import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { Worker } from "node:worker_threads";

const SHA256 = /^[a-f0-9]{64}$/;

export class ProjectMetadataError extends Error {
  constructor(message, code = "PROJECT_METADATA_INVALID") {
    super(message);
    this.name = "ProjectMetadataError";
    this.code = code;
  }
}

export function createProjectMetadataReader(options = {}) {
  return new ProjectMetadataReader(options);
}

export class ProjectMetadataReader {
  constructor({
    maxBytes = 256 * 1024,
    maxDepth = 24,
    maxKeys = 4096,
    maxNodes = 8192,
    maxAliases = 256,
    maxArrayItems = 2048,
    parseTimeoutMs = 500,
    maxCacheEntries = 256,
    parser = parseInWorker,
  } = {}) {
    this.budgets = Object.freeze({
      maxDepth: boundedInteger(maxDepth, 1, 64, "metadata depth"),
      maxKeys: boundedInteger(maxKeys, 1, 100_000, "metadata key count"),
      maxNodes: boundedInteger(maxNodes, 1, 200_000, "metadata node count"),
      maxAliases: boundedInteger(maxAliases, 0, 10_000, "metadata alias count"),
      maxArrayItems: boundedInteger(maxArrayItems, 1, 100_000, "metadata array length"),
    });
    this.maxBytes = boundedInteger(maxBytes, 2, 1024 * 1024, "metadata byte size");
    this.parseTimeoutMs = boundedInteger(parseTimeoutMs, 1, 5000, "metadata parse timeout");
    this.maxCacheEntries = boundedInteger(maxCacheEntries, 1, 4096, "metadata cache size");
    this.parser = parser;
    this.cache = new Map();
  }

  async read(filePath, { expectedSha256 = "", trustedEpoch = "", expectedSizeBytes = null } = {}) {
    const expectedDigest = normalizeTrustedDigest(expectedSha256, "metadata content");
    const trustEpoch = normalizeTrustedDigest(trustedEpoch, "workload lock");
    if (Boolean(expectedDigest) !== Boolean(trustEpoch)) {
      throw new ProjectMetadataError("Signed project metadata requires both content and workload-lock digests.", "PROJECT_METADATA_TRUST");
    }
    const snapshot = await readStableRegularFile(filePath, this.maxBytes);
    const contentSha256 = createHash("sha256").update(snapshot.bytes).digest("hex");
    if (expectedDigest && contentSha256 !== expectedDigest) {
      throw new ProjectMetadataError("Project metadata does not match its verified digest.", "PROJECT_METADATA_TRUST");
    }
    if (expectedSizeBytes != null) {
      const expectedSize = Number(expectedSizeBytes);
      if (!Number.isSafeInteger(expectedSize) || expectedSize < 2 || expectedSize > this.maxBytes
        || snapshot.bytes.length !== expectedSize) {
        throw new ProjectMetadataError("Project metadata does not match its verified size.", "PROJECT_METADATA_TRUST");
      }
    }
    const cacheKey = expectedDigest
      ? `signed:${trustEpoch}:${expectedDigest}`
      : `local-bounded:${contentSha256}`;
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      this.cache.delete(cacheKey);
      this.cache.set(cacheKey, cached);
      return structuredClone(cached);
    }

    const parsed = await withTimeout(
      Promise.resolve().then(() => this.parser(snapshot.bytes.toString("utf8"), this.budgets, { timeoutMs: this.parseTimeoutMs })),
      this.parseTimeoutMs,
    );
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new ProjectMetadataError("Project metadata root must be an object.");
    }
    this.cache.set(cacheKey, structuredClone(parsed));
    while (this.cache.size > this.maxCacheEntries) this.cache.delete(this.cache.keys().next().value);
    return structuredClone(parsed);
  }
}

async function readStableRegularFile(filePath, maxBytes) {
  let before;
  try {
    before = await lstat(filePath, { bigint: true });
  } catch (error) {
    throw fileError(error, "Project metadata is unavailable.");
  }
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new ProjectMetadataError("Project metadata must be a regular non-symlink file.", "PROJECT_METADATA_FILE_TYPE");
  }
  if (before.size < 2n || before.size > BigInt(maxBytes)) {
    throw new ProjectMetadataError("Project metadata exceeds the configured byte budget.", "PROJECT_METADATA_SIZE");
  }

  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(before, opened) || !opened.isFile() || opened.size > BigInt(maxBytes)) {
      throw new ProjectMetadataError("Project metadata changed before it could be read.", "PROJECT_METADATA_CHANGED");
    }
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (offset !== bytes.length || !sameSnapshot(opened, after)) {
      throw new ProjectMetadataError("Project metadata changed while it was being read.", "PROJECT_METADATA_CHANGED");
    }
    return { bytes };
  } catch (error) {
    if (error instanceof ProjectMetadataError) throw error;
    throw fileError(error, "Project metadata could not be read safely.");
  } finally {
    await handle?.close().catch(() => {});
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSnapshot(left, right) {
  return sameIdentity(left, right)
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function fileError(error, fallback) {
  if (error?.code === "ELOOP") {
    return new ProjectMetadataError("Project metadata symlinks are forbidden.", "PROJECT_METADATA_FILE_TYPE");
  }
  return new ProjectMetadataError(fallback, "PROJECT_METADATA_IO");
}

function normalizeTrustedDigest(value, label) {
  const digest = String(value || "").trim().toLowerCase();
  if (digest && !SHA256.test(digest)) {
    throw new ProjectMetadataError(`Trusted ${label} digest is invalid.`, "PROJECT_METADATA_TRUST");
  }
  return digest;
}

function boundedInteger(value, minimum, maximum, label) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ProjectMetadataError(`Invalid ${label} budget.`, "PROJECT_METADATA_BUDGET");
  }
  return parsed;
}

function withTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ProjectMetadataError(
      "Project metadata parsing exceeded the configured time budget.",
      "PROJECT_METADATA_TIMEOUT",
    )), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function parseInWorker(text, budgets, { timeoutMs }) {
  const worker = new Worker(new URL("./project-metadata-worker.mjs", import.meta.url), {
    workerData: { text, budgets },
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => {
      worker.terminate().catch(() => {});
      finish(reject, new ProjectMetadataError(
        "Project metadata parsing exceeded the configured time budget.",
        "PROJECT_METADATA_TIMEOUT",
      ));
    }, timeoutMs);
    worker.once("message", (message) => {
      worker.terminate().catch(() => {});
      if (message?.ok === true) finish(resolve, message.value);
      else finish(reject, new ProjectMetadataError(
        String(message?.message || "Project metadata is invalid."),
        String(message?.code || "PROJECT_METADATA_INVALID"),
      ));
    });
    worker.once("error", () => finish(reject, new ProjectMetadataError(
      "Project metadata parser failed safely.",
      "PROJECT_METADATA_PARSER",
    )));
    worker.once("exit", (code) => {
      if (code !== 0) finish(reject, new ProjectMetadataError(
        "Project metadata parser exited before validation completed.",
        "PROJECT_METADATA_PARSER",
      ));
    });
  });
}
