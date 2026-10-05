import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import { lstat, mkdir, open, readdir, link, rm } from "node:fs/promises";
import { join } from "node:path";
import { Transform } from "node:stream";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MACHINE = /^[a-f0-9]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const MEDIA = /^[a-z]+\/[a-z0-9.+-]+$/i;
export const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
export const MAX_ARCHIVE_ENTRIES = 2048;
export const MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024;
export const MAX_ARCHIVE_RATIO = 100;
const MANIFEST_VERSION = 1;
const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;

export class ArtifactStorageError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = "ArtifactStorageError";
    this.code = code;
    this.status = status;
  }
}

function fail(code, message, status = 400) { throw new ArtifactStorageError(code, message, status); }

function scope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || typeof value.ownerId !== "string" || !value.ownerId.trim() || value.ownerId.length > 256 || CONTROL.test(value.ownerId)
    || !MACHINE.test(String(value.machineId || "")) || !UUID.test(String(value.conversationId || ""))) {
    fail("INVALID_SCOPE", "Ambito artefatto non valido.");
  }
  return Object.freeze({ ownerId: value.ownerId, machineId: String(value.machineId).toLowerCase(), conversationId: String(value.conversationId).toLowerCase() });
}

function sameScope(left, right) { return left.ownerId === right.ownerId && left.machineId === right.machineId && left.conversationId === right.conversationId; }
function id(value, code = "INVALID_ARTIFACT_ID") {
  if (!UUID.test(String(value || ""))) fail(code, "Identificativo artefatto non valido.");
  return String(value).toLowerCase();
}
function name(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 180 || value === "." || value === ".."
    || value.includes("/") || value.includes("\\") || CONTROL.test(value)) fail("INVALID_ARTIFACT_NAME", "Nome artefatto non valido.");
  return value.trim();
}
function mediaType(value, fallback = "application/octet-stream") {
  const result = value == null ? fallback : String(value).toLowerCase().trim();
  if (!MEDIA.test(result) || result.length > 128) fail("INVALID_ARTIFACT_TYPE", "Tipo artefatto non valido.");
  return result;
}
function exactBytes(value, max = MAX_ARTIFACT_BYTES) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) fail("ARTIFACT_TOO_LARGE", "Artefatto troppo grande.", 413);
  return value;
}
function safeEntryName(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 160 || value.endsWith("/") || value.includes("\\") || CONTROL.test(value)) fail("INVALID_ARCHIVE_ENTRY", "Voce archivio non valida.");
  const result = value.trim();
  if (result.split("/").some(part => part === ".." || part === "" || part === ".")) fail("INVALID_ARCHIVE_ENTRY", "Voce archivio non valida.");
  // ZIP entries are allowed to be nested, but never absolute, drive-qualified,
  // or dot-segment paths. The archive is data and is never extracted by this service.
  if (result.startsWith("/") || /^[A-Za-z]:/.test(result)) fail("INVALID_ARCHIVE_ENTRY", "Voce archivio non valida.");
  return result;
}

function crcTable() {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let value = i;
    for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : value >>> 1;
    table[i] = value >>> 0;
  }
  return table;
}
const CRC_TABLE = crcTable();
function crcUpdate(crc, bytes) {
  let value = crc ^ 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

async function atomicJson(path, value) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync(); await handle.close(); handle = null;
    // A manifest is immutable.  A hard-link publish is atomic and cannot
    // replace an object created by another request with the same UUID.
    try { await link(temporary, path); }
    catch (error) { if (error?.code === "EEXIST") fail("ARTIFACT_EXISTS", "Artefatto già esistente.", 409); throw error; }
  } finally { await handle?.close().catch(() => {}); await rm(temporary, { force: true }).catch(() => {}); }
}

async function loadJson(path, maximum = MAX_MANIFEST_BYTES) {
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.nlink !== 1 || info.size < 2 || info.size > maximum) fail("ARTIFACT_CORRUPT", "Manifest artefatto non valido.", 503);
    const value = JSON.parse(await handle.readFile("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) fail("ARTIFACT_CORRUPT", "Manifest artefatto non valido.", 503);
    return value;
  } catch (error) {
    if (error?.code === "ENOENT") fail("ARTIFACT_NOT_FOUND", "Artefatto non trovato.", 404);
    if (error instanceof ArtifactStorageError) throw error;
    fail("ARTIFACT_CORRUPT", "Manifest artefatto non valido.", 503);
  } finally { await handle?.close().catch(() => {}); }
}

function sourceChunks(source) {
  if (Buffer.isBuffer(source)) return (async function* () { yield source; }());
  if (source instanceof Uint8Array) return (async function* () { yield Buffer.from(source); }());
  if (typeof source === "string") return (async function* () { yield Buffer.from(source, "utf8"); }());
  if (source && typeof source[Symbol.asyncIterator] === "function") return source;
  if (source && typeof source[Symbol.iterator] === "function") return (async function* () { for (const chunk of source) yield chunk; }());
  fail("INVALID_ARTIFACT_SOURCE", "Sorgente artefatto non valida.");
}

function normalizeChunk(chunk) {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk);
  fail("INVALID_ARTIFACT_SOURCE", "Sorgente artefatto non valida.");
}

function artifactResult(manifest) {
  return {
    id: manifest.id,
    name: manifest.name,
    kind: manifest.kind,
    mediaType: manifest.mediaType,
    size: manifest.byteSize,
    sha256: manifest.sha256,
    ...(Array.isArray(manifest.sourceRefs) && manifest.sourceRefs.length ? { sourceRefs: [...manifest.sourceRefs] } : {}),
    ...(manifest.kind === "archive" ? {
      entryCount: manifest.entryCount,
      totalUncompressedBytes: manifest.totalUncompressedBytes,
    } : {}),
    createdAt: manifest.createdAt,
  };
}

function validateManifest(value, expectedId) {
  if (value.version !== MANIFEST_VERSION || value.id !== expectedId || !["file", "archive"].includes(value.kind)) fail("ARTIFACT_CORRUPT", "Manifest artefatto non valido.", 503);
  const owned = scope(value.scope);
  const cleanName = name(value.name);
  const type = mediaType(value.mediaType);
  exactBytes(value.byteSize);
  if (!UUID.test(String(value.objectKey || "")) || !/^[a-f0-9]{64}$/.test(String(value.sha256 || "")) || !Number.isFinite(Date.parse(value.createdAt))) fail("ARTIFACT_CORRUPT", "Manifest artefatto non valido.", 503);
  if (value.sourceRefs !== undefined && (!Array.isArray(value.sourceRefs) || value.sourceRefs.length > 5 || value.sourceRefs.some(valueRef => !UUID.test(String(valueRef))))) fail("ARTIFACT_CORRUPT", "Manifest artefatto non valido.", 503);
  if (value.kind === "archive") {
    if (type !== "application/zip" || !Number.isSafeInteger(value.entryCount) || value.entryCount < 1 || value.entryCount > MAX_ARCHIVE_ENTRIES
      || !Number.isSafeInteger(value.totalUncompressedBytes) || value.totalUncompressedBytes < 1 || value.totalUncompressedBytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES
      || value.totalUncompressedBytes > value.byteSize * MAX_ARCHIVE_RATIO
      || !Array.isArray(value.entries) || value.entries.length !== value.entryCount) fail("ARTIFACT_CORRUPT", "Manifest archivio non valido.", 503);
    for (const entry of value.entries) {
      if (!entry || typeof entry !== "object" || !UUID.test(String(entry.id || "")) || safeEntryName(entry.name) !== entry.name
        || !["text", "image"].includes(entry.kind) || !MEDIA.test(String(entry.mediaType || ""))
        || !Number.isSafeInteger(entry.byteSize) || entry.byteSize < 1 || entry.byteSize > MAX_ARTIFACT_BYTES
        || entry.compressedSize !== entry.byteSize || !Number.isSafeInteger(entry.localOffset) || entry.localOffset < 0
        || !Number.isSafeInteger(entry.dataOffset) || entry.dataOffset <= entry.localOffset || !Number.isSafeInteger(entry.crc32) || entry.crc32 < 0) {
        fail("ARTIFACT_CORRUPT", "Manifest archivio non valido.", 503);
      }
    }
  }
  return { ...value, scope: owned, name: cleanName, mediaType: type };
}

const MAX_ARTIFACTS_PER_CONVERSATION = 64;
const MAX_ARTIFACTS_PER_OWNER = 256;
const MAX_ARTIFACT_BYTES_PER_CONVERSATION = 4 * 1024 * 1024 * 1024;
const MAX_ARTIFACT_BYTES_PER_OWNER = 8 * 1024 * 1024 * 1024;
const MAX_ARTIFACT_BYTES_GLOBAL = 16 * 1024 * 1024 * 1024;

export class ArtifactStorage {
  constructor({ root, now = () => Date.now() } = {}) {
    if (typeof root !== "string" || !root.startsWith("/") || root.includes("\0")) fail("INVALID_STORAGE_ROOT", "Percorso archivio artefatti non valido.");
    this.root = root; this.objects = join(root, "objects"); this.manifests = join(root, "manifests"); this.now = now; this.readyPromise = null; this.quotaTail = Promise.resolve();
  }
  async ready() {
    if (!this.readyPromise) this.readyPromise = (async () => {
      await mkdir(this.root, { recursive: true, mode: 0o700 }); await mkdir(this.objects, { recursive: true, mode: 0o700 }); await mkdir(this.manifests, { recursive: true, mode: 0o700 });
      for (const directory of [this.root, this.objects, this.manifests]) { const info = await lstat(directory); if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077)) fail("INSECURE_STORAGE", "Permessi archivio artefatti non sicuri.", 503); }
      await this.#cleanupOrphans();
      return true;
    })().catch(error => { this.readyPromise = null; throw error; });
    return this.readyPromise;
  }
  #objectPath(key) { return join(this.objects, id(key, "INVALID_OBJECT_KEY")); }
  #manifestPath(artifactId) { return join(this.manifests, `${id(artifactId)}.json`); }
  async #withQuotaLock(work) {
    const previous = this.quotaTail;
    let release;
    this.quotaTail = previous.catch(() => {}).then(() => new Promise(resolve => { release = resolve; }));
    await previous.catch(() => {});
    try { return await work(); } finally { release(); }
  }
  async #cleanupOrphans() {
    const referenced = new Set();
    for (const file of await readdir(this.manifests)) {
      if (!/^[0-9a-f-]{36}\.json$/i.test(file)) continue;
      // The writer uses the artifact UUID as its object key. Preserve that
      // object even when the corresponding manifest is corrupt: recovery may
      // fail closed, but it must not turn metadata damage into data deletion.
      referenced.add(file.slice(0, -5).toLowerCase());
      try {
        const value = await loadJson(join(this.manifests, file));
        if (value && typeof value.objectKey === "string" && UUID.test(value.objectKey)) referenced.add(value.objectKey.toLowerCase());
        else await rm(join(this.manifests, file), { force: true });
      } catch (error) {
        // Leave malformed manifests for the normal corruption path; startup
        // cleanup must never erase an object whose ownership is uncertain.
        if (error?.code === "ARTIFACT_NOT_FOUND") await rm(join(this.manifests, file), { force: true }).catch(() => {});
      }
    }
    for (const file of await readdir(this.objects)) {
      if (file.endsWith(".tmp") || (!UUID.test(file) && /^[0-9a-f-]+$/i.test(file))) { await rm(join(this.objects, file), { force: true }).catch(() => {}); continue; }
      if (UUID.test(file) && !referenced.has(file.toLowerCase())) await rm(join(this.objects, file), { force: true }).catch(() => {});
    }
  }
  async #assertQuota(owned, additionalBytes) {
    // list() intentionally omits scope from public metadata; use a bounded
    // manifest walk for ownership/account totals.
    let conversationCount = 0; let ownerCount = 0; let conversationBytes = 0; let ownerBytes = 0; let totalBytes = 0;
    for (const file of await readdir(this.manifests)) {
      if (!/^[0-9a-f-]{36}\.json$/i.test(file)) continue;
      try {
        const item = validateManifest(await loadJson(join(this.manifests, file)), file.slice(0, -5));
        totalBytes += item.byteSize;
        if (item.scope.ownerId !== owned.ownerId) continue;
        ownerCount += 1; ownerBytes += item.byteSize;
        if (sameScope(item.scope, owned)) { conversationCount += 1; conversationBytes += item.byteSize; }
      } catch (error) {
        if (error?.code !== "ARTIFACT_NOT_FOUND") throw error;
      }
    }
    if (conversationCount >= MAX_ARTIFACTS_PER_CONVERSATION || conversationBytes + additionalBytes > MAX_ARTIFACT_BYTES_PER_CONVERSATION
      || ownerCount >= MAX_ARTIFACTS_PER_OWNER || ownerBytes + additionalBytes > MAX_ARTIFACT_BYTES_PER_OWNER
      || totalBytes + additionalBytes > MAX_ARTIFACT_BYTES_GLOBAL) fail("ARTIFACT_QUOTA", "Quota artefatti superata.", 413);
  }
  async #writeSource(artifactId, source, maximum = MAX_ARTIFACT_BYTES, writer = null, signal = null) {
    const temporary = `${this.#objectPath(artifactId)}.${randomUUID()}.tmp`;
    let handle; let bytes = 0; let hash = createHash("sha256");
    try {
      handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW, 0o600);
      for await (const raw of sourceChunks(source)) {
        signal?.throwIfAborted?.();
        const chunk = normalizeChunk(raw); bytes += chunk.length;
        if (bytes > maximum) fail("ARTIFACT_TOO_LARGE", "Artefatto troppo grande.", 413);
        hash.update(chunk);
        let written = 0;
        while (written < chunk.length) {
          signal?.throwIfAborted?.();
          const result = await handle.write(chunk, written, chunk.length - written, null);
          written += result.bytesWritten;
          if (!result.bytesWritten) fail("ARTIFACT_WRITE_FAILED", "Scrittura artefatto incompleta.", 503);
        }
        if (writer) await writer(chunk, bytes);
      }
      if (!bytes) fail("EMPTY_ARTIFACT", "Artefatto vuoto.");
      signal?.throwIfAborted?.();
      await handle.sync(); await handle.close(); handle = null;
      try { await link(temporary, this.#objectPath(artifactId)); }
      catch (error) { if (error?.code === "EEXIST") fail("ARTIFACT_EXISTS", "Artefatto già esistente.", 409); throw error; }
      return { byteSize: bytes, sha256: hash.digest("hex") };
    } finally { await handle?.close().catch(() => {}); await rm(temporary, { force: true }).catch(() => {}); }
  }
  async createFile(scopeValue, { id: suppliedId = randomUUID(), name: suppliedName, filename, mediaType: suppliedType, source, signal } = {}) {
    await this.ready(); const owned = scope(scopeValue); const artifactId = id(suppliedId); const cleanName = name(suppliedName ?? filename); const type = mediaType(suppliedType);
    return this.#withQuotaLock(async () => {
      let result;
      try {
        result = await this.#writeSource(artifactId, source, MAX_ARTIFACT_BYTES, null, signal);
        await this.#assertQuota(owned, result.byteSize);
        const manifest = { version: MANIFEST_VERSION, id: artifactId, kind: "file", scope: owned, name: cleanName, mediaType: type, byteSize: result.byteSize, sha256: result.sha256, objectKey: artifactId, createdAt: new Date(this.now()).toISOString() };
        await atomicJson(this.#manifestPath(artifactId), manifest);
        return artifactResult(manifest);
      } catch (error) { if (error?.code !== "ARTIFACT_EXISTS") await rm(this.#objectPath(artifactId), { force: true }).catch(() => {}); throw error; }
    });
  }
  async createZip(scopeValue, { id: suppliedId = randomUUID(), name: suppliedName = "server-ai.zip", entries = [], sourceRefs = [], signal } = {}) {
    await this.ready(); const owned = scope(scopeValue); const artifactId = id(suppliedId); const cleanName = name(suppliedName); if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_ARCHIVE_ENTRIES) fail("INVALID_ARCHIVE", "Archivio non valido.");
    if (!Array.isArray(sourceRefs) || sourceRefs.length > 5 || sourceRefs.some(value => !UUID.test(String(value)))) fail("INVALID_ARCHIVE_SOURCES", "Riferimenti allegato non validi.");
    const normalizedSourceRefs = [...new Set(sourceRefs.map(value => String(value).toLowerCase()))];
    const normalized = []; const seen = new Set();
    for (const item of entries) {
      if (!item || typeof item !== "object" || Array.isArray(item)) fail("INVALID_ARCHIVE_ENTRY", "Voce archivio non valida.");
      const entryName = safeEntryName(item.name ?? item.filename); if (seen.has(entryName)) fail("DUPLICATE_ARCHIVE_ENTRY", "Voci archivio duplicate."); seen.add(entryName);
      normalized.push({ id: id(item.id || randomUUID()), name: entryName, mediaType: mediaType(item.mediaType, "application/octet-stream"), kind: item.kind === "image" ? "image" : "text", source: item.source });
    }
    const entriesMeta = []; let totalUncompressedBytes = 0; let offset = 0;
    return this.#withQuotaLock(async () => {
      const result = await this.#writeSource(artifactId, (async function* () {
      signal?.throwIfAborted?.();
      for (const item of normalized) {
        signal?.throwIfAborted?.(); const filename = Buffer.from(item.name, "utf8"); if (filename.length > 160) fail("INVALID_ARCHIVE_ENTRY", "Voce archivio non valida.");
        const header = Buffer.alloc(30 + filename.length); header.writeUInt32LE(0x04034b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(0x808, 6); header.writeUInt16LE(0, 8); header.writeUInt16LE(0, 26); header.writeUInt16LE(filename.length, 26); header.writeUInt16LE(0, 28); filename.copy(header, 30);
        yield header; const dataOffset = offset + header.length; offset += header.length; let entrySize = 0; let crc = 0;
        for await (const raw of sourceChunks(item.source)) { signal?.throwIfAborted?.(); const chunk = normalizeChunk(raw); entrySize += chunk.length; totalUncompressedBytes += chunk.length; if (entrySize > MAX_ARTIFACT_BYTES || totalUncompressedBytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES) fail("ARCHIVE_TOO_LARGE", "Archivio troppo grande.", 413); crc = crcUpdate(crc, chunk); yield chunk; offset += chunk.length; }
        if (!entrySize) fail("EMPTY_ARCHIVE_ENTRY", "Voce archivio vuota.");
        const descriptor = Buffer.alloc(16); descriptor.writeUInt32LE(0x08074b50, 0); descriptor.writeUInt32LE(crc >>> 0, 4); descriptor.writeUInt32LE(entrySize, 8); descriptor.writeUInt32LE(entrySize, 12); yield descriptor; offset += descriptor.length;
        entriesMeta.push({ id: item.id, name: item.name, kind: item.kind, mediaType: item.mediaType, byteSize: entrySize, compressedSize: entrySize, crc32: crc >>> 0, localOffset: dataOffset - header.length, dataOffset });
      }
      const centralOffset = offset; for (const item of entriesMeta) { signal?.throwIfAborted?.(); const filename = Buffer.from(item.name, "utf8"); const central = Buffer.alloc(46 + filename.length); central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x808, 8); central.writeUInt16LE(0, 10); central.writeUInt32LE(item.crc32, 16); central.writeUInt32LE(item.compressedSize, 20); central.writeUInt32LE(item.byteSize, 24); central.writeUInt16LE(filename.length, 28); central.writeUInt16LE(0, 30); central.writeUInt16LE(0, 32); central.writeUInt16LE(0, 34); central.writeUInt16LE(0, 36); central.writeUInt32LE(item.localOffset, 42); filename.copy(central, 46); yield central; offset += central.length; }
      const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entriesMeta.length, 8); end.writeUInt16LE(entriesMeta.length, 10); end.writeUInt32LE(offset - centralOffset, 12); end.writeUInt32LE(centralOffset, 16); yield end; offset += end.length;
      })(), MAX_ARTIFACT_BYTES, null, signal);
      try {
        await this.#assertQuota(owned, result.byteSize);
        const manifest = { version: MANIFEST_VERSION, id: artifactId, kind: "archive", scope: owned, name: cleanName, mediaType: "application/zip", byteSize: result.byteSize, sha256: result.sha256, objectKey: artifactId, entryCount: entriesMeta.length, totalUncompressedBytes, entries: entriesMeta, ...(normalizedSourceRefs.length ? { sourceRefs: normalizedSourceRefs } : {}), createdAt: new Date(this.now()).toISOString() };
        await atomicJson(this.#manifestPath(artifactId), manifest);
        return artifactResult(manifest);
      } catch (error) { if (error?.code !== "ARTIFACT_EXISTS") await rm(this.#objectPath(artifactId), { force: true }).catch(() => {}); throw error; }
    });
  }
  async #load(scopeValue, artifactId) {
    await this.ready();
    const owned = scope(scopeValue); const value = validateManifest(await loadJson(this.#manifestPath(artifactId)), id(artifactId)); if (!sameScope(value.scope, owned)) fail("ARTIFACT_NOT_FOUND", "Artefatto non trovato.", 404); return value;
  }
  async list(scopeValue) { await this.ready(); const owned = scope(scopeValue); const values = []; for (const file of await readdir(this.manifests)) { if (!/^[0-9a-f-]{36}\.json$/.test(file)) continue; try { const item = validateManifest(await loadJson(join(this.manifests, file)), file.slice(0, -5)); if (sameScope(item.scope, owned)) values.push(artifactResult(item)); } catch (error) { if (error.code !== "ARTIFACT_NOT_FOUND") throw error; } } return values.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id)); }
  async open(scopeValue, artifactId, { startByte = 0, endByte, signal } = {}) { await this.ready(); const item = await this.#load(scopeValue, artifactId); const info = await lstat(this.#objectPath(item.objectKey)); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== item.byteSize) fail("ARTIFACT_CORRUPT", "Artefatto non integro.", 503); if (!Number.isSafeInteger(startByte) || startByte < 0 || startByte >= item.byteSize || (endByte !== undefined && (!Number.isSafeInteger(endByte) || endByte < startByte || endByte >= item.byteSize))) fail("INVALID_RANGE", "Intervallo artefatto non valido."); const stream = createReadStream(this.#objectPath(item.objectKey), { flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW, start: startByte, end: endByte }); const abort = () => stream.destroy(new ArtifactStorageError("ARTIFACT_ABORTED", "Lettura annullata.", 499)); if (signal?.aborted) abort(); else signal?.addEventListener("abort", abort, { once: true }); stream.once("close", () => signal?.removeEventListener("abort", abort)); return { ...artifactResult(item), objectKey: item.objectKey, stream };
  }
  async listArchiveEntries(scopeValue, artifactId, { cursor = null, limit = MAX_ARCHIVE_ENTRIES, signal } = {}) {
    signal?.throwIfAborted?.();
    const item = await this.#load(scopeValue, artifactId); if (item.kind !== "archive") fail("NOT_AN_ARCHIVE", "Artefatto non archivio.", 415);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_ARCHIVE_ENTRIES) fail("INVALID_ARCHIVE_CURSOR", "Limite archivio non valido.");
    if (cursor != null) id(cursor, "INVALID_ARCHIVE_CURSOR");
    const cursorIndex = cursor == null ? -1 : item.entries.findIndex(entry => entry.id === String(cursor).toLowerCase());
    if (cursor != null && cursorIndex < 0) fail("INVALID_ARCHIVE_CURSOR", "Cursore archivio non valido.");
    const start = cursor == null ? 0 : cursorIndex + 1;
    const selected = item.entries.slice(start, start + limit).map(({ id: entryId, name: entryName, kind, mediaType: type, byteSize }) => ({ id: entryId, name: entryName, kind, mediaType: type, size: byteSize, byteSize, readable: kind === "text" }));
    // Keep the historical array return usable while exposing the paged shape
    // consumed by the scan/context adapters.
    Object.defineProperties(selected, { entryCount: { value: item.entryCount }, totalUncompressedBytes: { value: item.totalUncompressedBytes }, entries: { value: selected }, nextCursor: { value: start + selected.length < item.entries.length ? selected.at(-1)?.id || null : null } });
    return selected;
  }
  async openArchiveEntry(scopeValue, artifactId, entryId, { signal } = {}) {
    signal?.throwIfAborted?.();
    const item = await this.#load(scopeValue, artifactId); if (item.kind !== "archive") fail("NOT_AN_ARCHIVE", "Artefatto non archivio.", 415);
    const entry = item.entries.find(value => value.id === id(entryId)); if (!entry) fail("ARTIFACT_ENTRY_NOT_FOUND", "Voce archivio non trovata.", 404);
    const streamInfo = await this.open(scopeValue, artifactId, { startByte: entry.dataOffset, endByte: entry.dataOffset + entry.compressedSize - 1, signal });
    let bytes = 0; let crc = 0;
    const verifier = new Transform({ transform(chunk, encoding, callback) { bytes += chunk.length; crc = crcUpdate(crc, chunk); callback(null, chunk); }, flush(callback) { if (bytes !== entry.byteSize || crc !== entry.crc32) callback(new ArtifactStorageError("ARTIFACT_CORRUPT", "Voce archivio non integra.", 503)); else callback(); } });
    streamInfo.stream.once("error", error => verifier.destroy(error)); streamInfo.stream.pipe(verifier);
    const verified = new Promise((resolve, reject) => { verifier.once("finish", () => resolve(true)); verifier.once("error", reject); });
    return { entry: { id: entry.id, name: entry.name, kind: entry.kind, mediaType: entry.mediaType, size: entry.byteSize, byteSize: entry.byteSize, readable: entry.kind === "text" }, stream: verifier, verified };
  }
  async remove(scopeValue, artifactId) { await this.ready(); const item = await this.#load(scopeValue, artifactId); await rm(this.#objectPath(item.objectKey), { force: true }); await rm(this.#manifestPath(item.id), { force: true }); return true; }
  async removeConversation(scopeValue) { const items = await this.list(scopeValue); for (const item of items) await this.remove(scopeValue, item.id); return items.length; }
}

export function createArtifactStorage(options) { return new ArtifactStorage(options); }
