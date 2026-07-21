import { constants, existsSync } from "node:fs";
import { open, opendir } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { Worker } from "node:worker_threads";

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
    maxQueue = 32,
    maxInflight = 64,
    hardDeadlineMs = 2000,
    scan = scanProjectTreeInWorker,
    scanOptions = {},
    now = () => Date.now(),
  } = {}) {
    this.ttlMs = boundedInteger(ttlMs, 1, 3_600_000, "cache TTL");
    this.partialTtlMs = boundedInteger(partialTtlMs, 1, 3_600_000, "partial cache TTL");
    this.staleTtlMs = boundedInteger(staleTtlMs, 1, 86_400_000, "stale cache TTL");
    this.maxCacheEntries = boundedInteger(maxCacheEntries, 1, 4096, "cache entries");
    this.maxConcurrency = boundedInteger(maxConcurrency, 1, 16, "scan concurrency");
    this.maxQueue = boundedInteger(maxQueue, 0, 4096, "scan queue");
    this.maxInflight = boundedInteger(maxInflight, 1, 8192, "inflight scans");
    this.hardDeadlineMs = boundedInteger(hardDeadlineMs, 1, 60_000, "hard scan deadline");
    this.scan = scan;
    this.scanOptions = { ...scanOptions };
    this.now = now;
    this.cache = new Map();
    this.inflight = new Map();
    this.active = 0;
    this.queue = [];
  }

  async read(key, root, scanOverrides = {}) {
    const cacheKey = String(key || root);
    const now = this.now();
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      this.touch(cacheKey, cached);
      return structuredClone(cached.value);
    }
    if (this.inflight.has(cacheKey)) return structuredClone(await this.inflight.get(cacheKey));
    if (this.inflight.size >= this.maxInflight) return unavailableUsage("inflight-limit");

    const pending = this.withHardDeadline((signal) => this.runLimited(
      () => this.scan(root, { ...this.scanOptions, ...scanOverrides, signal }),
      signal,
    ))
      .then((value) => {
        const ttl = value.complete === true ? this.ttlMs : this.partialTtlMs;
        this.store(cacheKey, value, this.now() + ttl);
        return value;
      })
      .catch((error) => {
        const reason = scanFailureReason(error);
        const prior = this.cache.get(cacheKey);
        if (prior && prior.staleUntil > this.now()) {
          const stale = {
            ...prior.value,
            stale: true,
            reason: reason === "scan-error" ? "refresh-error" : `refresh-${reason}`,
          };
          this.store(cacheKey, stale, this.now() + this.partialTtlMs, prior.staleUntil);
          return stale;
        }
        return unavailableUsage(reason);
      });
    this.inflight.set(cacheKey, pending);
    try {
      return structuredClone(await pending);
    } finally {
      this.inflight.delete(cacheKey);
    }
  }

  runLimited(task, signal) {
    return new Promise((resolve, reject) => {
      let queued = false;
      let settled = false;
      const settle = (callback, value) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        callback(value);
      };
      const onAbort = () => {
        if (!queued) return;
        const index = this.queue.indexOf(entry);
        if (index >= 0) this.queue.splice(index, 1);
        queued = false;
        settle(reject, deadlineError(signal));
      };
      const run = async () => {
        queued = false;
        signal?.removeEventListener("abort", onAbort);
        if (signal?.aborted) {
          settle(reject, deadlineError(signal));
          this.drainQueue();
          return;
        }
        this.active += 1;
        try {
          settle(resolve, await raceWithSignal(Promise.resolve().then(task), signal));
        } catch (error) {
          settle(reject, error);
        } finally {
          this.active -= 1;
          this.drainQueue();
        }
      };
      const entry = { run };
      if (this.active < this.maxConcurrency) run();
      else if (this.queue.length >= this.maxQueue) {
        settle(reject, new ProjectDiskUsageError("Project disk scan queue is full.", "PROJECT_DISK_QUEUE"));
      } else {
        queued = true;
        this.queue.push(entry);
        signal?.addEventListener("abort", onAbort, { once: true });
      }
    });
  }

  drainQueue() {
    while (this.active < this.maxConcurrency && this.queue.length > 0) this.queue.shift().run();
  }

  withHardDeadline(task) {
    const controller = new AbortController();
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        const error = new ProjectDiskUsageError("Project disk scan exceeded its hard deadline.", "PROJECT_DISK_DEADLINE");
        controller.abort(error);
        reject(error);
      }, this.hardDeadlineMs);
    });
    return Promise.race([
      Promise.resolve().then(() => task(controller.signal)),
      timeout,
    ]).finally(() => clearTimeout(timer));
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

export function scanProjectTreeInWorker(root, options = {}) {
  const signal = options.signal;
  const worker = new Worker(new URL("./project-disk-usage-worker.mjs", import.meta.url), {
    workerData: {
      root,
      options: serializableScanOptions(options),
    },
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      worker.terminate().catch(() => {});
      callback(value);
    };
    const onAbort = () => finish(reject, deadlineError(signal));
    if (signal?.aborted) {
      onAbort();
      return;
    }
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.once("message", (message) => {
      if (message?.ok === true) {
        finish(resolve, message.value);
        return;
      }
      finish(reject, new ProjectDiskUsageError(
        String(message?.message || "Project disk scan worker failed safely."),
        String(message?.code || "PROJECT_DISK_WORKER"),
      ));
    });
    worker.once("error", () => finish(reject, new ProjectDiskUsageError(
      "Project disk scan worker failed safely.",
      "PROJECT_DISK_WORKER",
    )));
    worker.once("exit", (code) => {
      if (code !== 0) finish(reject, new ProjectDiskUsageError(
        "Project disk scan worker exited before completion.",
        "PROJECT_DISK_WORKER",
      ));
    });
  });
}

export async function scanProjectTree(root, options = {}) {
  const {
    maxDepth = 32,
    maxNodes = 50_000,
    maxBytes = 100 * 1024 * 1024 * 1024,
    timeoutMs = 1500,
    yieldEvery = 64,
    anchorRoot,
    descriptorApi = createLinuxProjectTreeDescriptorApi(),
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
  let rootHandle;
  try {
    rootHandle = await openAnchoredDirectory(root, anchorRoot, descriptorApi);
    const truncated = await visitDescriptor(rootHandle, 0, {
      budgets,
      descriptorApi,
      measuredAt,
      monotonicNow,
      started,
      state,
    });
    if (truncated) return truncated;
  } catch (error) {
    if (error instanceof ProjectDiskUsageError) throw error;
    return truncatedUsage(state, "io-error", measuredAt());
  } finally {
    await closeDescriptor(descriptorApi, rootHandle);
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

export function createLinuxProjectTreeDescriptorApi() {
  if (process.platform !== "linux" || !existsSync("/proc/self/fd")
    || !Number.isInteger(constants.O_DIRECTORY) || !Number.isInteger(constants.O_NOFOLLOW)) {
    throw new ProjectDiskUsageError(
      "Descriptor-anchored project traversal is unavailable on this platform.",
      "PROJECT_DISK_DESCRIPTOR",
    );
  }
  const baseFlags = constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK || 0);
  return {
    openAnchor: (anchor) => open(anchor, baseFlags | constants.O_DIRECTORY),
    openChild: (parent, name, { directory = false } = {}) => {
      assertDescriptorName(name);
      const childPath = `/proc/self/fd/${parent.fd}/${name}`;
      return open(childPath, baseFlags | (directory ? constants.O_DIRECTORY : 0));
    },
    stat: (handle) => handle.stat({ bigint: true }),
    entries: async function* entries(handle) {
      let directory;
      try {
        directory = await opendir(`/proc/self/fd/${handle.fd}`);
        for await (const entry of directory) {
          yield { name: entry.name, symbolicLink: entry.isSymbolicLink() };
        }
      } finally {
        await directory?.close().catch(() => {});
      }
    },
    close: (handle) => handle.close(),
  };
}

async function openAnchoredDirectory(root, anchorRoot, descriptorApi) {
  const requested = String(root || "");
  const anchor = String(anchorRoot || "");
  if (!path.isAbsolute(requested) || !path.isAbsolute(anchor)) {
    throw new ProjectDiskUsageError("Project disk scan requires an absolute descriptor anchor.", "PROJECT_DISK_DESCRIPTOR");
  }
  const resolvedRoot = path.resolve(requested);
  const resolvedAnchor = path.resolve(anchor);
  const relative = path.relative(resolvedAnchor, resolvedRoot);
  if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(`..${path.sep}`)) {
    throw new ProjectDiskUsageError("Project disk scan root leaves its descriptor anchor.", "PROJECT_DISK_DESCRIPTOR");
  }
  const parts = relative ? relative.split(path.sep) : [];
  let handle;
  try {
    handle = await descriptorApi.openAnchor(resolvedAnchor);
    for (const part of parts) {
      assertDescriptorName(part);
      const next = await descriptorApi.openChild(handle, part, { directory: true });
      await closeDescriptor(descriptorApi, handle);
      handle = next;
    }
    return handle;
  } catch (error) {
    await closeDescriptor(descriptorApi, handle);
    if (error instanceof ProjectDiskUsageError) throw error;
    throw new ProjectDiskUsageError("Project disk scan could not open its anchored root.", "PROJECT_DISK_DESCRIPTOR");
  }
}

async function visitDescriptor(handle, depth, context) {
  const { budgets, descriptorApi, measuredAt, monotonicNow, started, state } = context;
  if (expired(started, budgets.timeoutMs, monotonicNow)) return truncatedUsage(state, "timeout", measuredAt());
  let stat;
  try {
    stat = await descriptorApi.stat(handle);
  } catch {
    return truncatedUsage(state, "io-error", measuredAt());
  }
  if (expired(started, budgets.timeoutMs, monotonicNow)) return truncatedUsage(state, "timeout", measuredAt());
  state.nodes += 1;
  state.bytes += finiteSize(stat.size);
  if (state.nodes > budgets.maxNodes) return truncatedUsage(state, "nodes", measuredAt());
  if (!Number.isSafeInteger(state.bytes) || state.bytes > budgets.maxBytes) return truncatedUsage(state, "bytes", measuredAt());

  if (stat.isSymbolicLink()) {
    state.symlinks += 1;
  } else if (stat.isDirectory()) {
    state.directories += 1;
    if (depth >= budgets.maxDepth) return truncatedUsage(state, "depth", measuredAt());
    try {
      for await (const rawEntry of descriptorApi.entries(handle)) {
        if (expired(started, budgets.timeoutMs, monotonicNow)) return truncatedUsage(state, "timeout", measuredAt());
        const entry = descriptorEntry(rawEntry);
        if (state.nodes >= budgets.maxNodes) return truncatedUsage(state, "nodes", measuredAt());
        if (entry.symbolicLink) {
          state.nodes += 1;
          state.symlinks += 1;
          continue;
        }
        let child;
        try {
          child = await descriptorApi.openChild(handle, entry.name);
        } catch (error) {
          if (isSymlinkOpenError(error)) {
            state.nodes += 1;
            state.symlinks += 1;
            continue;
          }
          return truncatedUsage(state, "namespace-change", measuredAt());
        }
        try {
          const truncated = await visitDescriptor(child, depth + 1, context);
          if (truncated) return truncated;
        } finally {
          await closeDescriptor(descriptorApi, child);
        }
      }
    } catch {
      return truncatedUsage(state, "io-error", measuredAt());
    }
  } else {
    state.files += 1;
  }

  if (state.nodes % budgets.yieldEvery === 0) await yieldToEventLoop();
  return null;
}

function descriptorEntry(value) {
  const name = String(value?.name || "");
  assertDescriptorName(name);
  return { name, symbolicLink: value?.symbolicLink === true };
}

function assertDescriptorName(name) {
  if (!name || name === "." || name === ".." || name.includes("/") || name.includes("\0")) {
    throw new ProjectDiskUsageError("Filesystem returned an invalid directory entry.", "PROJECT_DISK_DESCRIPTOR");
  }
}

function isSymlinkOpenError(error) {
  return error?.code === "ELOOP" || error?.code === "EMLINK";
}

async function closeDescriptor(descriptorApi, handle) {
  if (!handle) return;
  await Promise.resolve(descriptorApi.close(handle)).catch(() => {});
}

function serializableScanOptions(options) {
  return Object.fromEntries([
    "anchorRoot",
    "maxDepth",
    "maxNodes",
    "maxBytes",
    "timeoutMs",
    "yieldEvery",
  ].filter((key) => options[key] !== undefined).map((key) => [key, options[key]]));
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

function scanFailureReason(error) {
  if (error?.code === "PROJECT_DISK_DEADLINE") return "hard-deadline";
  if (error?.code === "PROJECT_DISK_QUEUE") return "queue-limit";
  if (error?.code === "PROJECT_DISK_DESCRIPTOR") return "descriptor-unavailable";
  return "scan-error";
}

function raceWithSignal(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(deadlineError(signal));
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      callback(value);
    };
    const onAbort = () => finish(reject, deadlineError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
  });
}

function deadlineError(signal) {
  return signal?.reason instanceof Error
    ? signal.reason
    : new ProjectDiskUsageError("Project disk scan exceeded its hard deadline.", "PROJECT_DISK_DEADLINE");
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
