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

export function sha256FileBounded(filePath, options = {}) {
  const maxBytes = positiveBound(options.maxBytes ?? DEFAULT_MAX_BYTES, "maxBytes");
  const maxDurationMs = nonNegativeBound(options.maxDurationMs ?? DEFAULT_MAX_DURATION_MS, "maxDurationMs");
  const chunkBytes = positiveBound(options.chunkBytes ?? DEFAULT_CHUNK_BYTES, "chunkBytes");
  const startedAt = Date.now();
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

    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(chunkBytes, maxBytes));
    let bytesReadTotal = 0;
    while (bytesReadTotal < before.size) {
      if (signal?.aborted) throw abortError(filePath);
      if (Date.now() - startedAt >= maxDurationMs) {
        throw new Error(`Hashing deadline exceeded for ${filePath}.`);
      }
      const remaining = before.size - bytesReadTotal;
      const bytesRead = readChunk(descriptor, buffer, 0, Math.min(buffer.length, remaining), null);
      if (bytesRead === 0) throw new Error(`File was truncated while hashing: ${filePath}`);
      bytesReadTotal += bytesRead;
      if (bytesReadTotal > maxBytes) {
        throw new Error(`File exceeds hash size limit while reading: ${filePath}`);
      }
      hash.update(buffer.subarray(0, bytesRead));
      onChunk?.({ bytesRead, bytesReadTotal, expectedSizeBytes: before.size });
    }

    const after = fs.fstatSync(descriptor);
    if (
      after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
      || after.dev !== before.dev
      || after.ino !== before.ino
    ) {
      throw new Error(`File changed while hashing: ${filePath}`);
    }
    return { sha256: hash.digest("hex"), sizeBytes: bytesReadTotal };
  } finally {
    fs.closeSync(descriptor);
  }
}
