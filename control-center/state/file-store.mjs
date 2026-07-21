import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

export class StateStoreError extends Error {}
export class StateConflictError extends StateStoreError {}
export class StateValidationError extends StateStoreError {}

export function createFileStateStore(options) {
  return new FileStateStore(options);
}

export class FileStateStore {
  constructor({ datasets, lockTimeoutMs = 2000, staleLockMs = 30_000, now = () => Date.now() }) {
    this.datasets = new Map(Object.entries(datasets || {}).map(([name, definition]) => [name, normalizeDefinition(name, definition)]));
    this.lockTimeoutMs = lockTimeoutMs;
    this.staleLockMs = staleLockMs;
    this.now = now;
  }

  read(name, { strict = false } = {}) {
    const definition = this.definition(name);
    const raw = readRaw(definition.path);
    const hash = digest(raw);
    const metadata = readMetadata(definition.path);
    const revision = Number.isInteger(metadata?.revision) && metadata.revision >= 0 ? metadata.revision : 0;
    const externalDrift = Boolean(metadata && metadata.contentSha256 !== hash);
    try {
      const value = definition.kind === "jsonl"
        ? parseJsonLines(raw, strict)
        : raw ? JSON.parse(raw) : clone(definition.defaultValue);
      if (definition.kind === "jsonl") {
        for (const record of value) definition.validate?.(record);
      } else {
        definition.validate?.(value);
      }
      return { name, kind: definition.kind, value, revision, token: `${revision}:${hash}`, contentSha256: hash, exists: raw !== "", externalDrift };
    } catch (error) {
      if (strict) throw new StateValidationError(`${name} state is unreadable: ${error.message}`);
      return { name, kind: definition.kind, value: clone(definition.defaultValue), revision, token: `${revision}:${hash}`, contentSha256: hash, exists: raw !== "", externalDrift, invalid: true };
    }
  }

  readTail(name, {
    strict = false,
    maxRecords = 100,
    maxBytes = 4 * 1024 * 1024,
    maxRecordBytes,
  } = {}) {
    const definition = this.definition(name);
    if (definition.kind !== "jsonl") throw new StateValidationError(`${name} is not JSONL state.`);
    const recordLimit = boundedReadLimit(maxRecords, 1, 100_000, "tail record");
    const byteLimit = boundedReadLimit(maxBytes, 1, 64 * 1024 * 1024, "tail byte");
    const recordByteLimit = boundedReadLimit(maxRecordBytes ?? Math.min(256 * 1024, byteLimit), 1, byteLimit, "tail record byte");
    const raw = readRawTail(definition.path, byteLimit);
    const metadata = readMetadata(definition.path);
    const revision = Number.isInteger(metadata?.revision) && metadata.revision >= 0 ? metadata.revision : 0;
    const lines = boundedJsonLineBuffers(raw.buffer, raw.offset > 0);
    const selected = lines.slice(-recordLimit);
    const value = [];
    let parsedRecords = 0;
    let invalidRecords = 0;

    for (const line of selected) {
      try {
        if (line.byteLength > recordByteLimit) throw new Error(`record exceeds ${recordByteLimit} bytes`);
        parsedRecords += 1;
        const record = JSON.parse(line.toString("utf8"));
        definition.validate?.(record);
        value.push(record);
      } catch (error) {
        invalidRecords += 1;
        if (strict) throw new StateValidationError(`${name} tail is unreadable: ${error.message}`);
      }
    }

    return {
      name,
      kind: definition.kind,
      value,
      revision,
      exists: raw.exists,
      totalBytes: raw.totalBytes,
      bytesRead: raw.buffer.byteLength,
      parsedRecords,
      invalidRecords,
      truncated: raw.offset > 0 || lines.length > selected.length,
    };
  }

  write(name, value, { expectedToken } = {}) {
    const definition = this.definition(name);
    if (definition.kind !== "json") throw new StateValidationError(`${name} is append-only JSONL state.`);
    return this.withLock(definition.path, () => this.writeLocked(name, value, expectedToken));
  }

  update(name, mutate, { expectedToken } = {}) {
    const definition = this.definition(name);
    if (definition.kind !== "json") throw new StateValidationError(`${name} is append-only JSONL state.`);
    return this.withLock(definition.path, () => {
      const current = this.read(name, { strict: true });
      if (expectedToken && expectedToken !== current.token) throw new StateConflictError(`${name} changed after it was read.`);
      const next = mutate(clone(current.value), current);
      return this.writeLocked(name, next, current.token);
    });
  }

  append(name, value, { expectedToken } = {}) {
    const definition = this.definition(name);
    if (definition.kind !== "jsonl") throw new StateValidationError(`${name} is not JSONL state.`);
    return this.withLock(definition.path, () => {
      const current = this.read(name, { strict: true });
      if (expectedToken && expectedToken !== current.token) throw new StateConflictError(`${name} changed after it was read.`);
      definition.validate?.(value);
      mkdirSync(path.dirname(definition.path), { recursive: true, mode: 0o700 });
      const fd = openSync(definition.path, "a", 0o600);
      try {
        writeFileSync(fd, `${JSON.stringify(value)}\n`, "utf8");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      chmodSync(definition.path, 0o600);
      return this.writeMetadata(name, current.revision + 1);
    });
  }

  appendRetained(name, value, {
    maxRecords = 5000,
    maxBytes = 8 * 1024 * 1024,
    maxRecordBytes,
  } = {}) {
    const definition = this.definition(name);
    if (definition.kind !== "jsonl") throw new StateValidationError(`${name} is not JSONL state.`);
    const recordLimit = boundedReadLimit(maxRecords, 1, 100_000, "retention record");
    const byteLimit = boundedReadLimit(maxBytes, 1024, 64 * 1024 * 1024, "retention byte");
    const recordByteLimit = boundedReadLimit(maxRecordBytes ?? Math.min(256 * 1024, byteLimit), 1, byteLimit, "retention record byte");
    definition.validate?.(value);
    const encoded = JSON.stringify(value);
    const encodedBytes = Buffer.byteLength(encoded);
    if (encodedBytes > recordByteLimit || encodedBytes + 1 > byteLimit) {
      throw new StateValidationError(`${name} record exceeds its retained JSONL budget.`);
    }

    return this.withLock(definition.path, () => {
      const metadata = readMetadata(definition.path);
      const revision = Number.isInteger(metadata?.revision) && metadata.revision >= 0 ? metadata.revision : 0;
      const stat = lstatRegularFile(definition.path);
      const retentionMatches = metadata?.retention?.maxRecords === recordLimit
        && metadata?.retention?.maxBytes === byteLimit
        && metadata?.retention?.maxRecordBytes === recordByteLimit;
      const trackedCount = Number(metadata?.recordCount);
      const canAppend = stat
        && retentionMatches
        && Number.isSafeInteger(trackedCount)
        && trackedCount >= 0
        && trackedCount < recordLimit
        && metadata.contentBytes === stat.size
        && stat.size + encodedBytes + 1 <= byteLimit;
      let recordCount;

      if (canAppend) {
        const currentRaw = readRaw(definition.path);
        if (Buffer.byteLength(currentRaw) !== stat.size || digest(currentRaw) !== metadata.contentSha256) {
          throw new StateValidationError(`${name} retained state changed outside the state store.`);
        }
        appendPrivateJsonLine(definition.path, encoded, stat);
        recordCount = trackedCount + 1;
      } else {
        const retained = recordLimit === 1
          ? []
          : this.readTail(name, {
              strict: true,
              maxRecords: recordLimit - 1,
              maxBytes: byteLimit,
              maxRecordBytes: recordByteLimit,
            }).value;
        const lines = [...retained, value].map((record) => JSON.stringify(record));
        let totalBytes = lines.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0);
        while (lines.length > 1 && totalBytes > byteLimit) {
          totalBytes -= Buffer.byteLength(lines.shift()) + 1;
        }
        atomicWrite(definition.path, `${lines.join("\n")}\n`);
        recordCount = lines.length;
      }

      return this.writeMetadata(name, revision + 1, {
        readBack: false,
        recordCount,
        contentBytes: lstatSync(definition.path).size,
        retention: { maxRecords: recordLimit, maxBytes: byteLimit, maxRecordBytes: recordByteLimit },
      });
    });
  }

  exportSnapshot(names = [...this.datasets.keys()]) {
    const datasets = {};
    for (const name of names) {
      const record = this.read(name, { strict: true });
      datasets[name] = {
        kind: record.kind,
        value: record.value,
        valueSha256: valueDigest(record.value),
        sourceToken: record.token,
      };
    }
    return { schemaVersion: 1, generatedAt: new Date(this.now()).toISOString(), datasets };
  }

  planImport(snapshot) {
    if (snapshot?.schemaVersion !== 1 || !snapshot.datasets || typeof snapshot.datasets !== "object") {
      throw new StateValidationError("State snapshot schema is invalid.");
    }
    const changes = [];
    for (const [name, entry] of Object.entries(snapshot.datasets)) {
      const definition = this.definition(name);
      if (entry?.kind !== definition.kind || entry.valueSha256 !== valueDigest(entry.value)) {
        throw new StateValidationError(`State snapshot dataset is invalid: ${name}.`);
      }
      if (definition.kind === "jsonl") {
        if (!Array.isArray(entry.value)) throw new StateValidationError(`State snapshot JSONL dataset is invalid: ${name}.`);
        for (const record of entry.value) definition.validate?.(record);
      } else {
        definition.validate?.(entry.value);
      }
      const current = this.read(name, { strict: true });
      changes.push({ name, kind: definition.kind, fromToken: current.token, changed: valueDigest(current.value) !== entry.valueSha256 });
    }
    return { status: "planned", apply: false, datasetCount: changes.length, changedCount: changes.filter((item) => item.changed).length, changes };
  }

  importSnapshot(snapshot, { apply = false, confirm = "" } = {}) {
    const plan = this.planImport(snapshot);
    if (!apply) return plan;
    if (confirm !== "IMPORT-CONTROL-CENTER-STATE") throw new StateValidationError("State import requires explicit confirmation.");
    const rollback = this.exportSnapshot(Object.keys(snapshot.datasets));
    try {
      for (const [name, entry] of Object.entries(snapshot.datasets)) {
        if (entry.kind === "json") this.write(name, entry.value);
        else this.replaceJsonLines(name, entry.value);
      }
    } catch (error) {
      for (const [name, entry] of Object.entries(rollback.datasets)) {
        if (entry.kind === "json") this.write(name, entry.value);
        else this.replaceJsonLines(name, entry.value);
      }
      throw error;
    }
    return { ...plan, status: "applied", apply: true, rollback };
  }

  replaceJsonLines(name, records) {
    const definition = this.definition(name);
    if (definition.kind !== "jsonl" || !Array.isArray(records)) throw new StateValidationError(`${name} JSONL replacement is invalid.`);
    return this.withLock(definition.path, () => {
      for (const record of records) definition.validate?.(record);
      const current = this.read(name, { strict: true });
      atomicWrite(definition.path, records.map((record) => JSON.stringify(record)).join("\n") + (records.length ? "\n" : ""));
      return this.writeMetadata(name, current.revision + 1);
    });
  }

  writeLocked(name, value, expectedToken) {
    const definition = this.definition(name);
    const current = this.read(name, { strict: true });
    if (expectedToken && expectedToken !== current.token) throw new StateConflictError(`${name} changed after it was read.`);
    definition.validate?.(value);
    atomicWrite(definition.path, `${JSON.stringify(value, null, 2)}\n`);
    return this.writeMetadata(name, current.revision + 1);
  }

  writeMetadata(name, revision, { readBack = true, ...details } = {}) {
    const definition = this.definition(name);
    const raw = readRaw(definition.path);
    const metadata = { schemaVersion: 1, ...details, revision, contentSha256: digest(raw), updatedAt: new Date(this.now()).toISOString() };
    atomicWrite(metadataPath(definition.path), `${JSON.stringify(metadata, null, 2)}\n`);
    if (readBack) return this.read(name, { strict: true });
    return {
      name,
      kind: definition.kind,
      revision,
      token: `${revision}:${metadata.contentSha256}`,
      contentSha256: metadata.contentSha256,
      exists: raw !== "",
      ...details,
    };
  }

  withLock(filePath, callback) {
    const lockPath = `${filePath}.lock`;
    mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    const started = this.now();
    let fd;
    while (fd === undefined) {
      try {
        fd = openSync(lockPath, "wx", 0o600);
        writeFileSync(fd, `${JSON.stringify({ pid: process.pid, createdAt: new Date(this.now()).toISOString() })}\n`);
        fsyncSync(fd);
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        if (lockIsStale(lockPath, this.now(), this.staleLockMs)) {
          rmSync(lockPath, { force: true });
          continue;
        }
        if (this.now() - started >= this.lockTimeoutMs) throw new StateConflictError(`State lock timed out: ${path.basename(filePath)}.`);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      }
    }
    try {
      return callback();
    } finally {
      closeSync(fd);
      rmSync(lockPath, { force: true });
    }
  }

  definition(name) {
    const definition = this.datasets.get(name);
    if (!definition) throw new StateValidationError(`Unknown state dataset: ${name}.`);
    return definition;
  }
}

function normalizeDefinition(name, definition = {}) {
  const kind = definition.kind || "json";
  if (!["json", "jsonl"].includes(kind) || !definition.path) throw new StateValidationError(`Invalid state dataset definition: ${name}.`);
  return { ...definition, kind, defaultValue: definition.defaultValue ?? (kind === "jsonl" ? [] : {}) };
}

function atomicWrite(filePath, content) {
  mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  let fd;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeFileSync(fd, content, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, filePath);
    chmodSync(filePath, 0o600);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    rmSync(temporary, { force: true });
    throw error;
  }
}

function appendPrivateJsonLine(filePath, encoded, expectedStat) {
  const flags = constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW;
  const fd = openSync(filePath, flags);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== expectedStat.dev || opened.ino !== expectedStat.ino || opened.size !== expectedStat.size) {
      throw new StateValidationError(`Retained state changed before append: ${path.basename(filePath)}.`);
    }
    writeFileSync(fd, `${encoded}\n`, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(filePath, 0o600);
}

function lstatRegularFile(filePath) {
  try {
    const stat = lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || !Number.isSafeInteger(stat.size) || stat.size < 0) {
      throw new StateValidationError(`Retained state source is not a regular file: ${path.basename(filePath)}.`);
    }
    return stat;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function readRaw(filePath) {
  try { return readFileSync(filePath, "utf8"); } catch (error) { if (error.code === "ENOENT") return ""; throw error; }
}

function readRawTail(filePath, maxBytes) {
  let fd;
  try {
    fd = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (error.code === "ENOENT") return { buffer: Buffer.alloc(0), exists: false, offset: 0, totalBytes: 0 };
    throw error;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || !Number.isSafeInteger(stat.size) || stat.size < 0) {
      throw new StateValidationError(`State tail source is not a bounded regular file: ${path.basename(filePath)}.`);
    }
    const totalBytes = stat.size;
    const length = Math.min(totalBytes, maxBytes);
    const offset = totalBytes - length;
    const buffer = Buffer.allocUnsafe(length);
    let bytesRead = 0;
    while (bytesRead < length) {
      const count = readSync(fd, buffer, bytesRead, length - bytesRead, offset + bytesRead);
      if (count === 0) break;
      bytesRead += count;
    }
    if (bytesRead !== length) throw new StateValidationError(`State tail changed while it was being read: ${path.basename(filePath)}.`);
    return { buffer, exists: true, offset, totalBytes };
  } finally {
    closeSync(fd);
  }
}

function boundedJsonLineBuffers(buffer, discardLeadingFragment) {
  let start = 0;
  if (discardLeadingFragment) {
    const boundary = buffer.indexOf(0x0a);
    if (boundary < 0) return [];
    start = boundary + 1;
  }
  const lines = [];
  let lineStart = start;
  for (let index = start; index < buffer.length; index += 1) {
    if (buffer[index] !== 0x0a) continue;
    appendJsonLineBuffer(lines, buffer.subarray(lineStart, index));
    lineStart = index + 1;
  }
  if (lineStart < buffer.length) appendJsonLineBuffer(lines, buffer.subarray(lineStart));
  return lines;
}

function appendJsonLineBuffer(lines, line) {
  const normalized = line.at(-1) === 0x0d ? line.subarray(0, -1) : line;
  if (normalized.byteLength > 0) lines.push(normalized);
}

function readMetadata(filePath) {
  try { return JSON.parse(readFileSync(metadataPath(filePath), "utf8")); } catch { return null; }
}

function metadataPath(filePath) { return `${filePath}.state-meta.json`; }
function digest(value) { return createHash("sha256").update(value).digest("hex"); }
function valueDigest(value) { return digest(JSON.stringify(value)); }
function clone(value) { return structuredClone(value); }

function boundedReadLimit(value, minimum, maximum, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new StateValidationError(`Invalid ${label} limit.`);
  }
  return parsed;
}

function parseJsonLines(raw, strict) {
  const records = [];
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    try { records.push(JSON.parse(line)); } catch (error) { if (strict) throw error; }
  }
  return records;
}

function lockIsStale(lockPath, now, staleLockMs) {
  try { return now - statSync(lockPath).mtimeMs > staleLockMs; } catch { return false; }
}
