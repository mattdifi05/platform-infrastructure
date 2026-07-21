import { lstat, opendir } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";

export class ProjectDiskUsageError extends Error {
  constructor(message, code = "PROJECT_DISK_IO") {
    super(message);
    this.name = "ProjectDiskUsageError";
    this.code = code;
  }
}

export function createProjectDiskUsageReader(options = {}) {
  return new ProjectDiskUsageReader(options);
}

export class ProjectDiskUsageReader {
  constructor({
    ttlMs = 30_000,
    partialTtlMs = 5000,
    staleTtlMs = 300_000,
    maxCacheEntries = 512,
    maxConcurrency = 2,
    scan = scanProjectTree,
    scanOptions = {},
    now = () => Date.now(),
  } = {}) {
    this.ttlMs = boundedInteger(ttlMs, 1, 3_600_000, "cache TTL");
    this.partialTtlMs = boundedInteger(partialTtlMs, 1, 3_600_000, "partial cache TTL");
    this.staleTtlMs = boundedInteger(staleTtlMs, 1, 86_400_000, "stale cache TTL");
    this.maxCacheEntries = boundedInteger(maxCacheEntries, 1, 4096, "cache entries");
    this.maxConcurrency = boundedInteger(maxConcurrency, 1, 16, "scan concurrency");
    this.scan = scan;
    this.scanOptions = { ...scanOptions };
    this.now = now;
    this.cache = new Map();
    this.inflight = new Map();
    this.active = 0;
    this.queue = [];
  }

  async read(key, root) {
    const cacheKey = String(key || root);
    const now = this.now();
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      this.touch(cacheKey, cached);
      return structuredClone(cached.value);
    }
    if (this.inflight.has(cacheKey)) return structuredClone(await this.inflight.get(cacheKey));

    const pending = this.runLimited(async () => {
      try {
        const value = await this.scan(root, this.scanOptions);
        const ttl = value.complete === true ? this.ttlMs : this.partialTtlMs;
        this.store(cacheKey, value, this.now() + ttl);
        return value;
      } catch {
        const prior = this.cache.get(cacheKey);
        if (prior && prior.staleUntil > this.now()) {
          const stale = {
            ...prior.value,
            stale: true,
            reason: "refresh-error",
          };
          this.store(cacheKey, stale, this.now() + this.partialTtlMs, prior.staleUntil);
          return stale;
        }
        return unavailableUsage("scan-error");
      }
    });
    this.inflight.set(cacheKey, pending);
    try {
      return structuredClone(await pending);
    } finally {
      this.inflight.delete(cacheKey);
    }
  }

  runLimited(task) {
    return new Promise((resolve, reject) => {
      const run = async () => {
        this.active += 1;
        try {
          resolve(await task());
        } catch (error) {
          reject(error);
        } finally {
          this.active -= 1;
          this.queue.shift()?.();
        }
      };
      if (this.active < this.maxConcurrency) run();
      else this.queue.push(run);
    });
  }

  store(key, value, expiresAt, staleUntil = this.now() + this.staleTtlMs) {
    this.cache.delete(key);
    this.cache.set(key, { value: structuredClone(value), expiresAt, staleUntil });
    while (this.cache.size > this.maxCacheEntries) this.cache.delete(this.cache.keys().next().value);
  }

  touch(key, value) {
    this.cache.delete(key);
    this.cache.set(key, value);
  }
}

export async function scanProjectTree(root, options = {}) {
  const {
    maxDepth = 32,
    maxNodes = 50_000,
    maxBytes = 100 * 1024 * 1024 * 1024,
    timeoutMs = 1500,
    yieldEvery = 64,
    fsApi = { lstat, opendir },
    monotonicNow = () => performance.now(),
    measuredAt = () => new Date().toISOString(),
  } = options;
  const budgets = {
    maxDepth: boundedInteger(maxDepth, 0, 256, "tree depth"),
    maxNodes: boundedInteger(maxNodes, 1, 10_000_000, "tree nodes"),
    maxBytes: boundedInteger(maxBytes, 1, Number.MAX_SAFE_INTEGER, "tree bytes"),
    timeoutMs: boundedInteger(timeoutMs, 1, 60_000, "tree timeout"),
    yieldEvery: boundedInteger(yieldEvery, 1, 10_000, "tree yield interval"),
  };
  const started = monotonicNow();
  const state = { bytes: 0, files: 0, directories: 0, symlinks: 0, nodes: 0 };
  const stack = [{ path: path.resolve(root), depth: 0 }];

  while (stack.length) {
    if (expired(started, budgets.timeoutMs, monotonicNow)) return truncatedUsage(state, "timeout", measuredAt());
    const current = stack.pop();
    let stat;
    try {
      stat = await fsApi.lstat(current.path);
    } catch {
      return truncatedUsage(state, "io-error", measuredAt());
    }
    if (expired(started, budgets.timeoutMs, monotonicNow)) return truncatedUsage(state, "timeout", measuredAt());
    state.nodes += 1;
    state.bytes += finiteSize(stat.size);
    if (state.nodes > budgets.maxNodes) return truncatedUsage(state, "nodes", measuredAt());
    if (state.bytes > budgets.maxBytes) return truncatedUsage(state, "bytes", measuredAt());

    if (stat.isSymbolicLink()) {
      state.symlinks += 1;
    } else if (stat.isDirectory()) {
      state.directories += 1;
      if (current.depth >= budgets.maxDepth) return truncatedUsage(state, "depth", measuredAt());
      let directory;
      try {
        directory = await fsApi.opendir(current.path);
        for await (const entry of directory) {
          if (state.nodes + stack.length >= budgets.maxNodes) {
            return truncatedUsage(state, "nodes", measuredAt());
          }
          stack.push({ path: path.join(current.path, entry.name), depth: current.depth + 1 });
          if (expired(started, budgets.timeoutMs, monotonicNow)) return truncatedUsage(state, "timeout", measuredAt());
        }
      } catch {
        return truncatedUsage(state, "io-error", measuredAt());
      } finally {
        await directory?.close().catch(() => {});
      }
    } else {
      state.files += 1;
    }

    if (state.nodes % budgets.yieldEvery === 0) await yieldToEventLoop();
  }

  return {
    available: true,
    complete: true,
    truncated: false,
    stale: false,
    reason: "",
    ...state,
    measuredAt: measuredAt(),
  };
}

function truncatedUsage(state, reason, measuredAt) {
  return {
    available: true,
    complete: false,
    truncated: true,
    stale: false,
    reason,
    ...state,
    measuredAt,
  };
}

export function unavailableUsage(reason = "unavailable") {
  return {
    available: false,
    complete: false,
    truncated: false,
    stale: false,
    reason,
    bytes: 0,
    files: 0,
    directories: 0,
    symlinks: 0,
    nodes: 0,
    measuredAt: null,
  };
}

function expired(started, timeoutMs, now) {
  return now() - started >= timeoutMs;
}

function finiteSize(value) {
  const size = Number(value);
  if (!Number.isSafeInteger(size) || size < 0) throw new ProjectDiskUsageError("Filesystem returned an invalid size.");
  return size;
}

function boundedInteger(value, minimum, maximum, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ProjectDiskUsageError(`Invalid ${label} budget.`, "PROJECT_DISK_BUDGET");
  }
  return parsed;
}

function yieldToEventLoop() {
  return new Promise((resolve) => setImmediate(resolve));
}
