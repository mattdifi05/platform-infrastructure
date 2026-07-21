import crypto from "node:crypto";
import fs from "node:fs";

const DEFAULT_MAX_BYTES = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_DURATION_MS = 30 * 60 * 1000;
const DEFAULT_CHUNK_BYTES = 1024 * 1024;

function positiveBound(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive safe integer.`);
  }
  return parsed;
}

function nonNegativeBound(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`);
  }
  return parsed;
}

function abortError(filePath) {
  const error = new Error(`Hashing cancelled for ${filePath}.`);
  error.name = "AbortError";
  return error;
}

function sameStableIdentity(left, right) {
  return right.size === left.size
    && right.mtimeMs === left.mtimeMs
    && right.ctimeMs === left.ctimeMs
    && right.dev === left.dev
    && right.ino === left.ino;
}

function hashOpenDescriptor(descriptor, before, filePath, options) {
  const { maxBytes, maxDurationMs, chunkBytes, signal, readChunk, onChunk } = options;
  const startedAt = Date.now();
  const hash = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(Math.min(chunkBytes, maxBytes));
  let bytesReadTotal = 0;
  while (bytesReadTotal < before.size) {
    if (signal?.aborted) throw abortError(filePath);
    if (Date.now() - startedAt >= maxDurationMs) {
      throw new Error(`Hashing deadline exceeded for ${filePath}.`);
    }
    const remaining = before.size - bytesReadTotal;
    const bytesRead = readChunk(descriptor, buffer, 0, Math.min(buffer.length, remaining), bytesReadTotal);
    if (bytesRead === 0) throw new Error(`File was truncated while hashing: ${filePath}`);
    bytesReadTotal += bytesRead;
    if (bytesReadTotal > maxBytes) {
      throw new Error(`File exceeds hash size limit while reading: ${filePath}`);
    }
    hash.update(buffer.subarray(0, bytesRead));
    onChunk?.({ bytesRead, bytesReadTotal, expectedSizeBytes: before.size });
  }
  const after = fs.fstatSync(descriptor);
  if (!sameStableIdentity(before, after)) throw new Error(`File changed while hashing: ${filePath}`);
  return { sha256: hash.digest("hex"), sizeBytes: bytesReadTotal };
}

export function openSha256FileBounded(filePath, options = {}) {
  const maxBytes = positiveBound(options.maxBytes ?? DEFAULT_MAX_BYTES, "maxBytes");
  const maxDurationMs = nonNegativeBound(options.maxDurationMs ?? DEFAULT_MAX_DURATION_MS, "maxDurationMs");
  const chunkBytes = positiveBound(options.chunkBytes ?? DEFAULT_CHUNK_BYTES, "chunkBytes");
  const signal = options.signal;
  const readChunk = options.readChunk ?? fs.readSync;
  const onChunk = options.onChunk;
  if (typeof readChunk !== "function") throw new Error("readChunk must be a function.");
  if (onChunk !== undefined && typeof onChunk !== "function") throw new Error("onChunk must be a function.");
  if (signal?.aborted) throw abortError(filePath);

  const pathStat = fs.lstatSync(filePath);
  if (pathStat.isSymbolicLink()) throw new Error(`Refusing to hash symbolic link: ${filePath}`);
  if (!pathStat.isFile()) throw new Error(`Refusing to hash non-regular file: ${filePath}`);
  if (pathStat.size > maxBytes) {
    throw new Error(`File exceeds hash size limit (${pathStat.size} > ${maxBytes} bytes): ${filePath}`);
  }

  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const before = fs.fstatSync(descriptor);
    if (!before.isFile()) throw new Error(`Refusing to hash non-regular file: ${filePath}`);
    if (before.dev !== pathStat.dev || before.ino !== pathStat.ino) {
      throw new Error(`File changed before hashing began: ${filePath}`);
    }
    if (before.size > maxBytes) {
      throw new Error(`File exceeds hash size limit (${before.size} > ${maxBytes} bytes): ${filePath}`);
    }

    const bounds = { maxBytes, maxDurationMs, chunkBytes, signal, readChunk, onChunk };
    const result = hashOpenDescriptor(descriptor, before, filePath, bounds);
    let closed = false;
    const assertOpen = () => {
      if (closed) throw new Error(`Hash descriptor is closed for ${filePath}.`);
    };
    return {
      ...result,
      descriptor,
      identity: { dev: before.dev, ino: before.ino, size: before.size, mtimeMs: before.mtimeMs, ctimeMs: before.ctimeMs },
      assertUnchanged() {
        assertOpen();
        if (!sameStableIdentity(before, fs.fstatSync(descriptor))) throw new Error(`File changed after hashing: ${filePath}`);
        return true;
      },
      assertPathIdentity(candidatePath = filePath) {
        assertOpen();
        const candidate = fs.lstatSync(candidatePath);
        const current = fs.fstatSync(descriptor);
        if (candidate.isSymbolicLink() || !candidate.isFile() || candidate.dev !== current.dev || candidate.ino !== current.ino) {
          throw new Error(`File path no longer references the hashed artifact: ${candidatePath}`);
        }
        return true;
      },
      rehash() {
        assertOpen();
        const current = fs.fstatSync(descriptor);
        if (!current.isFile() || current.size > maxBytes) throw new Error(`File is no longer a bounded regular artifact: ${filePath}`);
        return hashOpenDescriptor(descriptor, current, filePath, {
          maxBytes,
          maxDurationMs,
          chunkBytes,
          signal,
          readChunk: fs.readSync,
          onChunk: undefined,
        });
      },
      close() {
        if (closed) return;
        closed = true;
        fs.closeSync(descriptor);
      },
    };
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

export function sha256FileBounded(filePath, options = {}) {
  const opened = openSha256FileBounded(filePath, options);
  try {
    return { sha256: opened.sha256, sizeBytes: opened.sizeBytes };
  } finally {
    opened.close();
  }
}
