import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { constants as fsConstants, createReadStream, createWriteStream } from "node:fs";
import { copyFile, lstat, mkdir, open, readdir, rename, rm, statfs, writeFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { pipeline } from "node:stream/promises";
import {
  ATTACHMENT_CAPABILITIES,
  AttachmentError,
  classifyAttachmentFilename,
  isKnownBinaryAttachment,
  normalizeAttachmentFilename,
  normalizeAttachmentImageFile,
  documentMediaTypeForFilename,
  readMultipartAttachment,
} from "./attachments.mjs";
import { extractDocumentFile } from "./document-attachments.mjs";
import { redactAttachmentWindow } from "./attachment-redaction.mjs";
import { inspectZipFile, openZipEntry, ZIP_ATTACHMENT_LIMITS, ZipAttachmentError } from "./zip-attachments.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MACHINE_ID = /^[a-f0-9]{64}$/;
const INVALID_SCOPE_TEXT = /[\u0000-\u001f\u007f]/;
const DEFAULT_READ_BYTES = 12_288;
const REDACTION_LOOKAROUND_BYTES = 4096;
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_CLEANUP_MS = 60 * 60 * 1000;
const MANIFEST_VERSION = 1;
const MATERIALIZATION_VERSION = 1;
const ARCHIVE_ENTRY_ID = /^[a-f0-9]{24}$/;
const BAD_TEXT_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const DOCUMENT_EXTRACTION_RESERVATION_BYTES = ATTACHMENT_CAPABILITIES.maxDocumentExtractedBytes;

export class AttachmentStorageError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = "AttachmentStorageError";
    this.code = code;
    this.status = status;
  }
}

function fail(code, message, status = 400) { throw new AttachmentStorageError(code, message, status); }

function normalizeScope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(key => !["ownerId", "machineId", "conversationId"].includes(key))
      || typeof value.ownerId !== "string" || !value.ownerId.trim() || value.ownerId.length > 256 || INVALID_SCOPE_TEXT.test(value.ownerId)
      || !MACHINE_ID.test(String(value.machineId || ""))
      || !UUID.test(String(value.conversationId || "").toLowerCase())) {
    fail("INVALID_SCOPE", "Ambito del caricamento non valido.");
  }
  return Object.freeze({ ownerId: String(value.ownerId), machineId: String(value.machineId), conversationId: String(value.conversationId).toLowerCase() });
}

function sameScope(left, right) {
  return left.ownerId === right.ownerId && left.machineId === right.machineId && left.conversationId === right.conversationId;
}

function checkedId(value, code = "INVALID_UPLOAD_ID") {
  const id = String(value || "").toLowerCase();
  if (!UUID.test(id)) fail(code, "Identificativo del caricamento non valido.");
  return id;
}

function exactInteger(value, minimum, maximum, code, message) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code, message);
  return value;
}

function parseOffset(value) {
  const text = Array.isArray(value) ? "" : String(value ?? "");
  if (!/^(?:0|[1-9][0-9]{0,11})$/.test(text)) fail("INVALID_OFFSET", "Offset del caricamento non valido.");
  return exactInteger(Number(text), 0, ATTACHMENT_CAPABILITIES.maxFileBytes, "INVALID_OFFSET", "Offset del caricamento non valido.");
}

function publicError(error) {
  if (error instanceof AttachmentStorageError) return error;
  if (error instanceof AttachmentError) return new AttachmentStorageError(error.code, error.message, error.status);
  if (error instanceof ZipAttachmentError) return new AttachmentStorageError(error.code, error.message, error.status);
  return new AttachmentStorageError("STORAGE_FAILURE", "Archivio allegati non disponibile.", 503);
}

function mediaTypeForKind(kind) {
  if (kind === "text") return "text/plain";
  if (kind === "image") return "image/jpeg";
  if (kind === "archive") return "application/zip";
  if (kind === "document") return null;
  fail("STORAGE_CORRUPT", "Tipo allegato non valido.", 503);
}

async function atomicJson(path, value) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  let handle;
  try {
    handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close(); handle = null;
    await rename(temporary, path);
  } finally {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
  }
}

async function regularFile(path, { expectedSize } = {}) {
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const info = await handle.stat({ bigint: false });
    if (!info.isFile() || info.nlink !== 1 || (expectedSize !== undefined && info.size !== expectedSize)) {
      fail("STORAGE_CORRUPT", "Archivio allegati non integro.", 503);
    }
    return info;
  } finally { await handle.close(); }
}

async function boundedJson(path, maximum = 32 * 1024) {
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let text;
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.nlink !== 1 || info.size < 2 || info.size > maximum) fail("STORAGE_CORRUPT", "Metadati allegato non validi.", 503);
    text = await handle.readFile("utf8");
  } finally { await handle.close(); }
  let value;
  try { value = JSON.parse(text); } catch { fail("STORAGE_CORRUPT", "Metadati allegato non validi.", 503); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("STORAGE_CORRUPT", "Metadati allegato non validi.", 503);
  return value;
}

function validateManifest(value, expectedId) {
  const keys = ["byteSize", "createdAt", "filename", "id", "kind", "lastChunk", "offset", "result", "scope", "state", "updatedAt", "version"];
  const optionalKeys = ["reservedBytes"];
  if (Object.keys(value).some(key => !keys.includes(key) && !optionalKeys.includes(key))
      || Object.keys(value).filter(key => !optionalKeys.includes(key)).sort().join("\0") !== keys.sort().join("\0") || value.version !== MANIFEST_VERSION
      || value.id !== expectedId || !["uploading", "complete"].includes(value.state)) fail("STORAGE_CORRUPT", "Manifest del caricamento non valido.", 503);
  const scope = normalizeScope(value.scope);
  const filename = normalizeAttachmentFilename(value.filename);
  const { kind } = classifyAttachmentFilename(filename);
  if (kind !== value.kind) fail("STORAGE_CORRUPT", "Manifest del caricamento non valido.", 503);
  exactInteger(value.byteSize, 1, ATTACHMENT_CAPABILITIES.maxFileBytes, "STORAGE_CORRUPT", "Manifest del caricamento non valido.");
  const expectedReservation = value.byteSize + (value.kind === "document" ? DOCUMENT_EXTRACTION_RESERVATION_BYTES : 0);
  if (value.reservedBytes !== undefined) exactInteger(value.reservedBytes, value.byteSize, ATTACHMENT_CAPABILITIES.maxFileBytes + DOCUMENT_EXTRACTION_RESERVATION_BYTES, "STORAGE_CORRUPT", "Prenotazione manifest non valida.");
  if (value.reservedBytes !== undefined && value.reservedBytes !== expectedReservation) fail("STORAGE_CORRUPT", "Prenotazione manifest non valida.", 503);
  exactInteger(value.offset, 0, value.byteSize, "STORAGE_CORRUPT", "Manifest del caricamento non valido.");
  if (!Number.isFinite(Date.parse(value.createdAt)) || !Number.isFinite(Date.parse(value.updatedAt))) fail("STORAGE_CORRUPT", "Manifest del caricamento non valido.", 503);
  if (value.state === "uploading" && value.result !== null) fail("STORAGE_CORRUPT", "Manifest del caricamento non valido.", 503);
  if (value.state === "complete") {
    const resultKeys = ["byteSize", "filename", "height", "kind", "mediaType", "objectKey", "sha256", "text", "truncated", "width"]
      .concat(kind === "archive" ? ["archive"] : kind === "document" ? ["document"] : []);
    const result = value.result;
    if (value.offset !== value.byteSize || !result || typeof result !== "object" || Array.isArray(result)
        || Object.keys(result).sort().join("\0") !== resultKeys.sort().join("\0") || result.filename !== filename || result.kind !== kind
        || (kind !== "document" && result.mediaType !== mediaTypeForKind(kind)) || (kind === "document" && result.mediaType !== documentMediaTypeForFilename(filename)) || !UUID.test(String(result.objectKey || ""))
        || !Number.isSafeInteger(result.byteSize) || result.byteSize < 1 || result.byteSize > ATTACHMENT_CAPABILITIES.maxFileBytes
        || !/^[a-f0-9]{64}$/.test(String(result.sha256 || "")) || result.truncated !== false) {
      fail("STORAGE_CORRUPT", "Risultato allegato non valido.", 503);
    }
    if (kind === "text" && (typeof result.text !== "string" || Buffer.byteLength(result.text, "utf8") > 384 || result.width !== null || result.height !== null)) {
      fail("STORAGE_CORRUPT", "Risultato allegato non valido.", 503);
    }
    if (kind === "image" && (result.text !== null || !Number.isSafeInteger(result.width) || !Number.isSafeInteger(result.height)
        || result.width < 1 || result.height < 1 || result.width > 1600 || result.height > 1600 || result.byteSize > ATTACHMENT_CAPABILITIES.maxImageOutputBytes)) {
      fail("STORAGE_CORRUPT", "Risultato allegato non valido.", 503);
    }
    if (kind === "archive" && (result.text !== null || result.width !== null || result.height !== null
        || !result.archive || Object.keys(result.archive).sort().join("\0") !== "entryCount\0totalUncompressedBytes"
        || !Number.isSafeInteger(result.archive.entryCount) || result.archive.entryCount < 1 || result.archive.entryCount > ZIP_ATTACHMENT_LIMITS.maxEntries
        || !Number.isSafeInteger(result.archive.totalUncompressedBytes) || result.archive.totalUncompressedBytes < 0
        || result.archive.totalUncompressedBytes > ZIP_ATTACHMENT_LIMITS.maxTotalUncompressedBytes)) {
      fail("STORAGE_CORRUPT", "Risultato allegato non valido.", 503);
    }
    if (kind === "document" && ((result.text !== null && (typeof result.text !== "string" || Buffer.byteLength(result.text, "utf8") > 384)) || result.width !== null || result.height !== null || result.mediaType !== documentMediaTypeForFilename(filename)
        || !result.document || !Number.isSafeInteger(result.document.extractedBytes) || result.document.extractedBytes < 0
        || result.document.extractedBytes > ATTACHMENT_CAPABILITIES.maxDocumentExtractedBytes
        || !Number.isSafeInteger(result.document.sourceBytes) || result.document.sourceBytes !== value.byteSize
        || !result.document.coverage || !["complete", "partial", "image_only", "unsupported"].includes(result.document.coverage.state)
        || !Number.isSafeInteger(result.document.coverage.unitsRead) || !Number.isSafeInteger(result.document.coverage.unitsSkipped)
        || !Array.isArray(result.document.coverage.warnings))) {
      fail("STORAGE_CORRUPT", "Risultato allegato non valido.", 503);
    }
  }
  if (value.lastChunk !== null && (!value.lastChunk || !Number.isSafeInteger(value.lastChunk.offset) || !Number.isSafeInteger(value.lastChunk.byteSize)
      || !/^[a-f0-9]{64}$/.test(value.lastChunk.sha256))) fail("STORAGE_CORRUPT", "Manifest del caricamento non valido.", 503);
  return { ...value, scope, filename };
}

function validateObject(value, expectedKey) {
  const keys = ["byteSize", "createdAt", "filename", "kind", "mediaType", "objectKey", "scope", "sha256", "version"];
  const actualKeys = Object.keys(value); const optionalKeys = ["parentObjectKey", "documentMetadata"]; const allowedKeys = [...keys, ...optionalKeys];
  if (actualKeys.some(key => !allowedKeys.includes(key)) || actualKeys.filter(key => !optionalKeys.includes(key)).sort().join("\0") !== keys.sort().join("\0") || value.version !== MANIFEST_VERSION || value.objectKey !== expectedKey
      || !["text", "image", "archive", "document"].includes(value.kind) || !/^[a-f0-9]{64}$/.test(value.sha256)) fail("STORAGE_CORRUPT", "Metadati oggetto non validi.", 503);
  const scope = normalizeScope(value.scope);
  const filename = normalizeAttachmentFilename(value.filename);
  if (classifyAttachmentFilename(filename).kind !== value.kind && !(value.kind === "text" && value.parentObjectKey)) fail("STORAGE_CORRUPT", "Metadati oggetto non validi.", 503);
  exactInteger(value.byteSize, value.kind === "text" ? 0 : 1, ATTACHMENT_CAPABILITIES.maxFileBytes, "STORAGE_CORRUPT", "Metadati oggetto non validi.");
  if (!Number.isFinite(Date.parse(value.createdAt)) || (value.kind !== "document" && value.mediaType !== mediaTypeForKind(value.kind))
      || (value.kind === "document" && value.mediaType !== documentMediaTypeForFilename(filename))) {
    fail("STORAGE_CORRUPT", "Metadati oggetto non validi.", 503);
  }
  if (value.parentObjectKey != null) checkedId(value.parentObjectKey, "STORAGE_CORRUPT");
  if (value.documentMetadata != null && (value.kind !== "document" || typeof value.documentMetadata !== "object" || !Number.isSafeInteger(value.documentMetadata.extractedBytes)
      || value.documentMetadata.extractedBytes < 0 || value.documentMetadata.extractedBytes > ATTACHMENT_CAPABILITIES.maxDocumentExtractedBytes)) fail("STORAGE_CORRUPT", "Metadati documento non validi.", 503);
  return { ...value, scope, filename };
}

function checkedArchiveEntryId(value) {
  const id = String(value || "");
  if (!ARCHIVE_ENTRY_ID.test(id)) fail("ZIP_ENTRY_NOT_FOUND", "Voce ZIP non trovata.", 404);
  return id;
}

function validateMaterialization(value, parentObjectKey, entryIdValue) {
  const keys = ["byteSize", "createdAt", "entryId", "filename", "objectKey", "parentObjectKey", "scope", "sha256", "state", "updatedAt", "version"];
  const optionalKeys = ["document", "sourceByteSize", "reservedBytes"];
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).some(key => !keys.includes(key) && !optionalKeys.includes(key))
      || Object.keys(value).filter(key => !optionalKeys.includes(key)).sort().join("\0") !== keys.sort().join("\0")
      || value.version !== MATERIALIZATION_VERSION || value.parentObjectKey !== parentObjectKey || value.entryId !== entryIdValue
      || !["materializing", "complete"].includes(value.state) || !UUID.test(String(value.objectKey || ""))) {
    fail("STORAGE_CORRUPT", "Checkpoint della voce ZIP non valido.", 503);
  }
  const scope = normalizeScope(value.scope);
  const filename = normalizeAttachmentFilename(value.filename);
  const classified = classifyAttachmentFilename(filename);
  if (classified.kind !== "text" && classified.kind !== "document") fail("STORAGE_CORRUPT", "Checkpoint della voce ZIP non valido.", 503);
  exactInteger(value.byteSize, 0, ATTACHMENT_CAPABILITIES.maxFileBytes, "STORAGE_CORRUPT", "Checkpoint della voce ZIP non valido.");
  if (!Number.isFinite(Date.parse(value.createdAt)) || !Number.isFinite(Date.parse(value.updatedAt))
      || (value.state === "materializing" && value.sha256 !== null)
      || (value.state === "complete" && !/^[a-f0-9]{64}$/.test(String(value.sha256 || "")))) {
    fail("STORAGE_CORRUPT", "Checkpoint della voce ZIP non valido.", 503);
  }
  if (value.sourceByteSize !== undefined) exactInteger(value.sourceByteSize, 1, ATTACHMENT_CAPABILITIES.maxFileBytes, "STORAGE_CORRUPT", "Checkpoint della voce ZIP non valido.");
  if (value.reservedBytes !== undefined) exactInteger(value.reservedBytes, 0, ATTACHMENT_CAPABILITIES.maxFileBytes + DOCUMENT_EXTRACTION_RESERVATION_BYTES, "STORAGE_CORRUPT", "Checkpoint della voce ZIP non valido.");
  if (value.state === "materializing" && value.sourceByteSize !== undefined
      && value.reservedBytes !== value.sourceByteSize + DOCUMENT_EXTRACTION_RESERVATION_BYTES) fail("STORAGE_CORRUPT", "Prenotazione checkpoint ZIP non valida.", 503);
  if (value.document !== undefined && (!value.document || typeof value.document !== "object" || !Number.isSafeInteger(value.document.extractedBytes)
      || value.document.extractedBytes !== value.byteSize || !Number.isSafeInteger(value.document.sourceBytes)
      || value.document.sourceBytes !== value.sourceByteSize || !value.document.coverage
      || !["complete", "partial", "image_only", "unsupported"].includes(value.document.coverage.state))) {
    fail("STORAGE_CORRUPT", "Checkpoint della voce ZIP non valido.", 503);
  }
  return { ...value, scope, filename };
}

function createLockMap() {
  const tails = new Map();
  return async (key, task) => {
    const previous = tails.get(key) || Promise.resolve();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const tail = previous.catch(() => {}).then(() => gate);
    tails.set(key, tail);
    await previous.catch(() => {});
    try { return await task(); }
    finally { release(); if (tails.get(key) === tail) tails.delete(key); }
  };
}

export class AttachmentStorage {
  constructor({ root, now = () => Date.now(), cleanupIntervalMs = DEFAULT_CLEANUP_MS, partialTtlMs = DEFAULT_TTL_MS, documentExtractor = extractDocumentFile } = {}) {
    if (typeof root !== "string" || !root.startsWith("/") || root.includes("\0")) fail("INVALID_STORAGE_ROOT", "Percorso archivio allegati non valido.");
    this.root = root;
    this.uploadsDir = join(root, "uploads");
    this.stagingDir = join(root, "staging");
    this.objectsDir = join(root, "objects");
    this.archiveEntriesDir = join(root, "archive-entries");
    this.now = now;
    this.cleanupIntervalMs = exactInteger(cleanupIntervalMs, 1_000, DEFAULT_TTL_MS, "INVALID_STORAGE_CONFIG", "Configurazione archivio non valida.");
    this.partialTtlMs = exactInteger(partialTtlMs, 60_000, 7 * DEFAULT_TTL_MS, "INVALID_STORAGE_CONFIG", "Configurazione archivio non valida.");
    this.documentExtractor = documentExtractor;
    this.withUploadLock = createLockMap();
    this.withArchiveEntryLock = createLockMap();
    this.withGlobalLock = createLockMap();
    this.timer = null;
    this.readyPromise = null;
    this.closed = false;
  }

  async ready() {
    if (this.closed) fail("STORAGE_CLOSED", "Archivio allegati chiuso.", 503);
    if (!this.readyPromise) this.readyPromise = this.#ready().catch(error => { this.readyPromise = null; throw publicError(error); });
    return this.readyPromise;
  }

  async #ready() {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    for (const directory of [this.uploadsDir, this.stagingDir, this.objectsDir, this.archiveEntriesDir]) await mkdir(directory, { recursive: true, mode: 0o700 });
    for (const directory of [this.root, this.uploadsDir, this.stagingDir, this.objectsDir, this.archiveEntriesDir]) {
      const info = await lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) fail("INSECURE_STORAGE", "Permessi archivio allegati non sicuri.", 503);
    }
    for (const [directory, pattern] of [
      [this.uploadsDir, /^[0-9a-f-]{36}\.json\.[0-9a-f-]{36}\.tmp$/],
      [this.objectsDir, /^[0-9a-f-]{36}(?:\.json)?\.[0-9a-f-]{36}\.tmp$/],
      [this.objectsDir, /^\.[0-9a-f-]{36}\.document\.tmp(?:\.worker-[0-9a-f]{32}\.tmp)?$/],
      [this.archiveEntriesDir, /^[0-9a-f-]{36}-[a-f0-9]{24}\.json\.[0-9a-f-]{36}\.tmp$/],
      [this.stagingDir, /^[0-9a-f-]{36}\.archive-entry\.tmp(?:\.source)?$/],
      [this.stagingDir, /^\.[0-9a-f-]{36}\.document\.tmp(?:\.worker-[0-9a-f]{32}\.tmp)?$/],
    ]) {
      for (const name of await readdir(directory)) if (pattern.test(name)) await rm(join(directory, name), { force: true });
    }
    await this.#recoverIncompleteMaterializations();
    await this.cleanupExpired();
    if (!this.timer) {
      this.timer = setInterval(() => { this.cleanupExpired().catch(() => {}); }, this.cleanupIntervalMs);
      this.timer.unref?.();
    }
  }

  async close() { this.closed = true; if (this.timer) clearInterval(this.timer); this.timer = null; }

  #manifestPath(id) { return join(this.uploadsDir, `${checkedId(id)}.json`); }
  #stagePath(id) { return join(this.stagingDir, `${checkedId(id)}.part`); }
  #objectPath(key) { return join(this.objectsDir, checkedId(key, "INVALID_OBJECT_KEY")); }
  #objectMetaPath(key) { return join(this.objectsDir, `${checkedId(key, "INVALID_OBJECT_KEY")}.json`); }
  #materializationPath(parentObjectKey, entryIdValue) {
    return join(this.archiveEntriesDir, `${checkedId(parentObjectKey, "INVALID_OBJECT_KEY")}-${checkedArchiveEntryId(entryIdValue)}.json`);
  }
  #materializationStagePath(objectKey) { return join(this.stagingDir, `${checkedId(objectKey, "INVALID_OBJECT_KEY")}.archive-entry.tmp`); }

  async #loadManifest(id) {
    const normalized = checkedId(id);
    try { return validateManifest(await boundedJson(this.#manifestPath(normalized)), normalized); }
    catch (error) { if (error?.code === "ENOENT") fail("UPLOAD_NOT_FOUND", "Caricamento non trovato.", 404); throw error; }
  }

  async #loadObject(key) {
    const normalized = checkedId(key, "INVALID_OBJECT_KEY");
    try {
      const metadata = validateObject(await boundedJson(this.#objectMetaPath(normalized)), normalized);
      await regularFile(this.#objectPath(normalized), { expectedSize: metadata.byteSize });
      return metadata;
    } catch (error) { if (error?.code === "ENOENT") fail("OBJECT_NOT_FOUND", "Allegato non trovato.", 404); throw error; }
  }

  async #loadMaterialization(parentObjectKey, entryIdValue, { optional = false } = {}) {
    const parent = checkedId(parentObjectKey, "INVALID_OBJECT_KEY");
    const entryId = checkedArchiveEntryId(entryIdValue);
    try { return validateMaterialization(await boundedJson(this.#materializationPath(parent, entryId)), parent, entryId); }
    catch (error) {
      if (optional && error?.code === "ENOENT") return null;
      if (error?.code === "ENOENT") fail("ZIP_ENTRY_NOT_FOUND", "Voce ZIP non materializzata.", 404);
      throw error;
    }
  }

  async #allManifests() {
    const names = await readdir(this.uploadsDir);
    const values = [];
    for (const name of names) {
      if (/^[0-9a-f-]{36}\.json\.[0-9a-f-]{36}\.tmp$/.test(name)) continue;
      if (!/^[0-9a-f-]{36}\.json$/.test(name)) fail("STORAGE_CORRUPT", "File estraneo nell'archivio caricamenti.", 503);
      const id = name.slice(0, -5); values.push(validateManifest(await boundedJson(join(this.uploadsDir, name)), id));
    }
    return values;
  }

  async #allObjects() {
    const names = (await readdir(this.objectsDir)).filter(name => name.endsWith(".json"));
    const values = [];
    for (const name of names) {
      const key = name.slice(0, -5); const metadata = validateObject(await boundedJson(join(this.objectsDir, name)), key);
      await regularFile(this.#objectPath(key), { expectedSize: metadata.byteSize });
      values.push(metadata);
    }
    return values;
  }

  async #allMaterializations() {
    const names = await readdir(this.archiveEntriesDir);
    const values = [];
    for (const name of names) {
      if (/^[0-9a-f-]{36}-[a-f0-9]{24}\.json\.[0-9a-f-]{36}\.tmp$/.test(name)) continue;
      const match = /^([0-9a-f-]{36})-([a-f0-9]{24})\.json$/.exec(name);
      if (!match) fail("STORAGE_CORRUPT", "File estraneo nei checkpoint ZIP.", 503);
      values.push(validateMaterialization(await boundedJson(join(this.archiveEntriesDir, name)), match[1], match[2]));
    }
    return values;
  }

  async beginUpload(scopeValue, { filename: suppliedFilename, byteSize } = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue);
    const filename = normalizeAttachmentFilename(suppliedFilename);
    const { kind } = classifyAttachmentFilename(filename);
    if (!Number.isSafeInteger(byteSize) || byteSize < 1 || byteSize > ATTACHMENT_CAPABILITIES.maxFileBytes) {
      fail("FILE_TOO_LARGE", "Dimensione del file non consentita.", 413);
    }
    return this.withGlobalLock("quota", async () => {
      const [manifests, materializations, objects, disk] = await Promise.all([this.#allManifests(), this.#allMaterializations(), this.#allObjects(), statfs(this.root)]);
      const pending = manifests.filter(item => sameScope(item.scope, scope));
      if (pending.length >= ATTACHMENT_CAPABILITIES.maxPendingUploads) fail("TOO_MANY_PENDING_UPLOADS", "Troppi caricamenti in sospeso.", 409);
      const uploadingBytes = uploadingBytesFor(manifests);
      const materializingBytes = materializingBytesFor(materializations);
      const objectBytes = objects.reduce((sum, item) => sum + item.byteSize, 0);
      const ownerBytes = uploadingBytesFor(manifests, scope.ownerId) + materializingBytesFor(materializations, scope.ownerId)
        + objects.filter(item => item.scope.ownerId === scope.ownerId).reduce((sum, item) => sum + item.byteSize, 0);
      const conversationBytes = uploadingBytesFor(manifests, scope.ownerId, scope.machineId, scope.conversationId)
        + materializingBytesFor(materializations, scope.ownerId, scope.machineId, scope.conversationId)
        + objects.filter(item => sameScope(item.scope, scope)).reduce((sum, item) => sum + item.byteSize, 0);
      const reservation = byteSize + (kind === "document" ? DOCUMENT_EXTRACTION_RESERVATION_BYTES : 0);
      if (objectBytes + uploadingBytes + materializingBytes + reservation > ATTACHMENT_CAPABILITIES.globalQuotaBytes) fail("GLOBAL_QUOTA_EXCEEDED", "Spazio allegati esaurito.", 507);
      if (ownerBytes + reservation > ATTACHMENT_CAPABILITIES.ownerQuotaBytes) fail("OWNER_QUOTA_EXCEEDED", "Quota allegati dell'utente superata.", 413);
      if (conversationBytes + reservation > ATTACHMENT_CAPABILITIES.conversationQuotaBytes) fail("CONVERSATION_QUOTA_EXCEEDED", "Quota allegati della conversazione superata.", 413);
      const available = Number(disk.bavail) * Number(disk.bsize);
      if (!Number.isSafeInteger(available) || available - reservation < ATTACHMENT_CAPABILITIES.minFreeBytes) fail("INSUFFICIENT_STORAGE", "Spazio su disco insufficiente.", 507);
      const id = randomUUID();
      const now = new Date(this.now()).toISOString();
      const manifest = { version: MANIFEST_VERSION, id, state: "uploading", scope, filename, kind, byteSize, reservedBytes: reservation, offset: 0, createdAt: now, updatedAt: now, lastChunk: null, result: null };
      let handle;
      try {
        handle = await open(this.#stagePath(id), fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW, 0o600);
        await handle.close(); handle = null;
        await atomicJson(this.#manifestPath(id), manifest);
      } catch (error) {
        await handle?.close().catch(() => {});
        await rm(this.#stagePath(id), { force: true }).catch(() => {});
        await rm(this.#manifestPath(id), { force: true }).catch(() => {});
        throw publicError(error);
      }
      return { id, offset: 0, chunkBytes: ATTACHMENT_CAPABILITIES.chunkBytes, byteSize };
    });
  }

  async appendUpload(scopeValue, uploadId, req, { signal } = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue); const id = checkedId(uploadId);
    return this.withUploadLock(id, async () => {
      const manifest = await this.#loadManifest(id);
      if (!sameScope(manifest.scope, scope)) fail("UPLOAD_NOT_FOUND", "Caricamento non trovato.", 404);
      if (manifest.state !== "uploading") fail("UPLOAD_COMPLETE", "Caricamento già completato.", 409);
      if (signal?.aborted) fail("UPLOAD_ABORTED", "Caricamento annullato.", 499);
      const suppliedOffset = parseOffset(req?.headers?.["x-upload-offset"]);
      const upload = await readMultipartAttachment(req, { signal, maxFileBytes: ATTACHMENT_CAPABILITIES.chunkBytes });
      // `chunk.bin` is a fixed multipart transport name and is deliberately
      // not a user attachment filename (the normalizer rejects `.bin`).
      const transportFilename = upload.filename === "chunk.bin" ? "chunk.bin" : normalizeAttachmentFilename(upload.filename);
      // Resumable clients use a neutral multipart filename so a proxy/WAF
      // never has to inspect the user's original extension. The immutable
      // original filename remains the validated value captured at init.
      if (transportFilename !== manifest.filename && transportFilename !== "chunk.bin") {
        fail("FILENAME_MISMATCH", "Il nome del file non corrisponde.", 409);
      }
      if (upload.bytes.length < 1 || upload.bytes.length > ATTACHMENT_CAPABILITIES.chunkBytes || suppliedOffset + upload.bytes.length > manifest.byteSize) {
        fail("CHUNK_TOO_LARGE", "Blocco del caricamento non valido.", 413);
      }
      const stagePath = this.#stagePath(id);
      const stage = await regularFile(stagePath);
      if (stage.size < manifest.offset) fail("STORAGE_CORRUPT", "Caricamento incompleto non integro.", 503);
      if (stage.size > manifest.offset) {
        const repair = await open(stagePath, fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW);
        try { await repair.truncate(manifest.offset); } finally { await repair.close(); }
      }
      const digest = createHash("sha256").update(upload.bytes).digest("hex");
      if (suppliedOffset < manifest.offset) {
        if (suppliedOffset + upload.bytes.length > manifest.offset) fail("OFFSET_MISMATCH", "Offset del caricamento non corrispondente.", 409);
        const handle = await open(stagePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
        try {
          const existing = Buffer.allocUnsafe(upload.bytes.length);
          const { bytesRead } = await handle.read(existing, 0, existing.length, suppliedOffset);
          if (bytesRead !== existing.length || !timingSafeEqual(existing, upload.bytes)) fail("CHUNK_MISMATCH", "Il blocco ripetuto non corrisponde.", 409);
        } finally { await handle.close(); }
        return { id, offset: manifest.offset, byteSize: manifest.byteSize };
      }
      if (suppliedOffset !== manifest.offset) fail("OFFSET_MISMATCH", "Offset del caricamento non corrispondente.", 409);
      const handle = await open(stagePath, fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW);
      try {
        const { bytesWritten } = await handle.write(upload.bytes, 0, upload.bytes.length, suppliedOffset);
        if (bytesWritten !== upload.bytes.length) fail("STORAGE_FAILURE", "Scrittura del caricamento incompleta.", 503);
        await handle.sync();
      } finally { await handle.close(); }
      manifest.offset += upload.bytes.length;
      manifest.updatedAt = new Date(this.now()).toISOString();
      manifest.lastChunk = { offset: suppliedOffset, byteSize: upload.bytes.length, sha256: digest };
      await atomicJson(this.#manifestPath(id), manifest);
      return { id, offset: manifest.offset, byteSize: manifest.byteSize };
    }).catch(error => { throw publicError(error); });
  }

  async completeUpload(scopeValue, uploadId, { signal } = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue); const id = checkedId(uploadId);
    return this.withUploadLock(id, async () => {
      const manifest = await this.#loadManifest(id);
      if (!sameScope(manifest.scope, scope)) fail("UPLOAD_NOT_FOUND", "Caricamento non trovato.", 404);
      if (manifest.state === "complete") return this.#completedResult(manifest);
      if (manifest.offset !== manifest.byteSize) fail("UPLOAD_INCOMPLETE", "Caricamento incompleto.", 409);
      await regularFile(this.#stagePath(id), { expectedSize: manifest.byteSize });
      if (signal?.aborted) fail("UPLOAD_ABORTED", "Caricamento annullato.", 499);
      let normalized;
      try {
        normalized = manifest.kind === "image"
          ? await this.#completeImage(manifest, signal)
          : manifest.kind === "archive"
            ? await this.#completeArchive(manifest, signal)
            : manifest.kind === "document"
              ? await this.#completeDocument(manifest, signal)
            : await this.#completeText(manifest, signal);
        manifest.state = "complete";
        manifest.updatedAt = new Date(this.now()).toISOString();
        manifest.result = normalized;
        await atomicJson(this.#manifestPath(id), manifest);
      } catch (error) {
        if (normalized?.objectKey) await this.#removeObject(normalized.objectKey).catch(() => {});
        throw error;
      }
      await rm(this.#stagePath(id), { force: true });
      return this.#completedResult(manifest);
    }).catch(error => { throw publicError(error); });
  }

  async #completeImage(manifest, signal) {
    const normalized = await normalizeAttachmentImageFile({ filename: manifest.filename, path: this.#stagePath(manifest.id), byteSize: manifest.byteSize }, { signal });
    const objectKey = randomUUID();
    await this.#publishObject(objectKey, normalized.image, { ...normalized, scope: manifest.scope });
    return { kind: "image", filename: normalized.filename, mediaType: normalized.mediaType, byteSize: normalized.byteSize, sha256: normalized.sha256,
      objectKey, text: null, width: normalized.width, height: normalized.height, truncated: false };
  }

  async #completeText(manifest, signal) {
    const objectKey = randomUUID();
    const temporary = `${this.#objectPath(objectKey)}.${randomUUID()}.tmp`;
    try {
      const result = await validateTextFile(this.#stagePath(manifest.id), { signal });
      if (!result.byteSize) fail("EMPTY_FILE", "Il file è vuoto.");
      await copyFile(this.#stagePath(manifest.id), temporary, fsConstants.COPYFILE_EXCL);
      const copied = await open(temporary, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
      try { await copied.chmod(0o600); await copied.sync(); } finally { await copied.close(); }
      await rename(temporary, this.#objectPath(objectKey));
      await atomicJson(this.#objectMetaPath(objectKey), {
        version: MANIFEST_VERSION, objectKey, kind: "text", scope: manifest.scope, filename: manifest.filename,
        mediaType: "text/plain", byteSize: result.byteSize, sha256: result.sha256, createdAt: new Date(this.now()).toISOString(),
      });
      const preview = await this.readText(objectKey, { maxBytes: 384, signal });
      return { kind: "text", filename: manifest.filename, mediaType: "text/plain", byteSize: result.byteSize, sha256: result.sha256,
        objectKey, text: clampUtf8(preview.content, 384), width: null, height: null, truncated: false };
    } catch (error) {
      await rm(temporary, { force: true }).catch(() => {});
      await this.#removeObject(objectKey).catch(() => {});
      throw error;
    }
  }

  async #completeArchive(manifest, signal) {
    const archive = await inspectZipFile(this.#stagePath(manifest.id), { signal });
    const objectKey = randomUUID();
    const temporary = `${this.#objectPath(objectKey)}.${randomUUID()}.tmp`;
    try {
      const digest = await hashFile(this.#stagePath(manifest.id), { signal });
      await copyFile(this.#stagePath(manifest.id), temporary, fsConstants.COPYFILE_EXCL);
      const copied = await open(temporary, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
      try { await copied.chmod(0o600); await copied.sync(); } finally { await copied.close(); }
      await rename(temporary, this.#objectPath(objectKey));
      await atomicJson(this.#objectMetaPath(objectKey), {
        version: MANIFEST_VERSION, objectKey, kind: "archive", scope: manifest.scope, filename: manifest.filename,
        mediaType: "application/zip", byteSize: manifest.byteSize, sha256: digest, createdAt: new Date(this.now()).toISOString(),
      });
      return {
        kind: "archive", filename: manifest.filename, mediaType: "application/zip", byteSize: manifest.byteSize, sha256: digest,
        objectKey, text: null, width: null, height: null, truncated: false,
        archive: { entryCount: archive.entryCount, totalUncompressedBytes: archive.totalUncompressedBytes },
      };
    } catch (error) {
      await rm(temporary, { force: true }).catch(() => {});
      await this.#removeObject(objectKey).catch(() => {});
      throw error;
    }
  }

  async #completeDocument(manifest, signal) {
    if (typeof this.documentExtractor !== "function") fail("DOCUMENT_EXTRACTOR_UNAVAILABLE", "Lettore documenti non disponibile.", 503);
    const originalKey = randomUUID(); const extractedKey = randomUUID();
    const extractedPath = this.#objectPath(extractedKey);
    let originalPublished = false;
    try {
      const source = await regularFile(this.#stagePath(manifest.id), { expectedSize: manifest.byteSize });
      const extracted = await this.documentExtractor({
        inputPath: this.#stagePath(manifest.id), outputPath: extractedPath, filename: manifest.filename,
        mediaType: documentMediaTypeForFilename(manifest.filename), sourceBytes: source.size, signal,
        maxOutputBytes: ATTACHMENT_CAPABILITIES.maxDocumentExtractedBytes,
      });
      if (!extracted || !Number.isSafeInteger(extracted.sourceBytes) || extracted.sourceBytes !== manifest.byteSize
          || !Number.isSafeInteger(extracted.textBytes) || extracted.textBytes < 0 || extracted.textBytes > ATTACHMENT_CAPABILITIES.maxDocumentExtractedBytes
          || !extracted.coverage || !["complete", "partial", "image_only", "unsupported"].includes(extracted.coverage.state)) {
        fail("DOCUMENT_EXTRACTOR_INVALID", "Risultato del lettore documenti non valido.", 503);
      }
      await regularFile(extractedPath, { expectedSize: extracted.textBytes });
      const extractedDigest = await hashFile(extractedPath, { signal });
      const documentMetadata = { format: extracted.format, extractedBytes: extracted.textBytes, sourceBytes: extracted.sourceBytes,
        coverage: { state: extracted.coverage.state, unitsRead: extracted.coverage.unitsRead, unitsSkipped: extracted.coverage.unitsSkipped, warnings: [...extracted.coverage.warnings] } };
      await this.#publishCopiedObject(originalKey, this.#stagePath(manifest.id), {
        kind: "document", scope: manifest.scope, filename: manifest.filename, mediaType: documentMediaTypeForFilename(manifest.filename),
        byteSize: manifest.byteSize, sha256: await hashFile(this.#stagePath(manifest.id), { signal }), documentMetadata,
      });
      originalPublished = true;
      await this.#publishCopiedObject(extractedKey, extractedPath, {
        kind: "text", scope: manifest.scope, filename: "document-text.txt", mediaType: "text/plain",
        byteSize: extracted.textBytes, sha256: extractedDigest, parentObjectKey: originalKey,
      });
      const preview = extracted.textBytes > 0 ? await this.readText(extractedKey, { maxBytes: 384, signal }) : { content: "" };
      return { kind: "document", filename: manifest.filename, mediaType: documentMediaTypeForFilename(manifest.filename), byteSize: manifest.byteSize,
        sha256: await hashFile(this.#stagePath(manifest.id), { signal }), objectKey: originalKey, text: preview.content || null,
        width: null, height: null, truncated: false,
        document: documentMetadata };
    } catch (error) {
      await rm(extractedPath, { force: true }).catch(() => {});
      await this.#removeObjectFiles(extractedKey).catch(() => {});
      if (originalPublished) await this.#removeObjectFiles(originalKey).catch(() => {});
      throw error;
    }
  }

  async #publishObject(objectKey, bytes, normalized) {
    const path = this.#objectPath(objectKey);
    await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
    try {
      await atomicJson(this.#objectMetaPath(objectKey), {
        version: MANIFEST_VERSION, objectKey, kind: normalized.kind, scope: normalized.scope, filename: normalized.filename,
        mediaType: normalized.mediaType, byteSize: bytes.length, sha256: normalized.sha256, createdAt: new Date(this.now()).toISOString(),
      });
    } catch (error) { await rm(path, { force: true }); throw error; }
  }

  async #publishCopiedObject(objectKey, sourcePath, normalized) {
    const temporary = `${this.#objectPath(objectKey)}.${randomUUID()}.tmp`;
    try {
      await copyFile(sourcePath, temporary, fsConstants.COPYFILE_EXCL);
      const copied = await open(temporary, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
      try { await copied.chmod(0o600); await copied.sync(); } finally { await copied.close(); }
      await rename(temporary, this.#objectPath(objectKey));
      await atomicJson(this.#objectMetaPath(objectKey), {
        version: MANIFEST_VERSION, objectKey, kind: normalized.kind, scope: normalized.scope, filename: normalized.filename,
        mediaType: normalized.mediaType, byteSize: normalized.byteSize, sha256: normalized.sha256, createdAt: new Date(this.now()).toISOString(),
        ...(normalized.parentObjectKey ? { parentObjectKey: normalized.parentObjectKey } : {}),
        ...(normalized.documentMetadata ? { documentMetadata: normalized.documentMetadata } : {}),
      });
    } catch (error) { await rm(temporary, { force: true }).catch(() => {}); await this.#removeObjectFiles(objectKey).catch(() => {}); throw error; }
  }

  async #completedResult(manifest) {
    const result = manifest.result;
    if (!result || typeof result !== "object" || checkedId(result.objectKey, "STORAGE_CORRUPT") !== result.objectKey) fail("STORAGE_CORRUPT", "Risultato allegato non valido.", 503);
    const metadata = await this.#loadObject(result.objectKey);
    if (!sameScope(metadata.scope, manifest.scope) || metadata.kind !== manifest.kind || metadata.sha256 !== result.sha256) fail("STORAGE_CORRUPT", "Risultato allegato non integro.", 503);
    if (manifest.kind !== "image") return { ...result };
    const handle = await open(this.#objectPath(metadata.objectKey), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    try { return { ...result, objectKey: null, image: await handle.readFile() }; }
    finally { await handle.close(); }
  }

  async acknowledgeUpload(scopeValue, uploadId) {
    await this.ready(); const scope = normalizeScope(scopeValue); const id = checkedId(uploadId);
    return this.withUploadLock(id, async () => {
      const manifest = await this.#loadManifest(id);
      if (!sameScope(manifest.scope, scope)) fail("UPLOAD_NOT_FOUND", "Caricamento non trovato.", 404);
      if (manifest.state !== "complete") fail("UPLOAD_INCOMPLETE", "Caricamento incompleto.", 409);
      if (manifest.kind === "image") await this.#removeObject(manifest.result.objectKey);
      await rm(this.#manifestPath(id));
      await rm(this.#stagePath(id), { force: true });
    }).catch(error => { throw publicError(error); });
  }

  async abortUpload(scopeValue, uploadId) {
    await this.ready(); const scope = normalizeScope(scopeValue); const id = checkedId(uploadId);
    return this.withUploadLock(id, async () => {
      let manifest;
      try { manifest = await this.#loadManifest(id); } catch (error) { if (error.code === "UPLOAD_NOT_FOUND") return; throw error; }
      if (!sameScope(manifest.scope, scope)) fail("UPLOAD_NOT_FOUND", "Caricamento non trovato.", 404);
      if (manifest.result?.objectKey) await this.#removeObject(manifest.result.objectKey).catch(error => { if (error.code !== "OBJECT_NOT_FOUND") throw error; });
      await rm(this.#stagePath(id), { force: true });
      await rm(this.#manifestPath(id), { force: true });
    }).catch(error => { throw publicError(error); });
  }

  async removeObject(objectKey) {
    await this.ready(); const key = checkedId(objectKey, "INVALID_OBJECT_KEY");
    await this.#removeObject(key);
  }

  async #removeObject(key) {
    const materializations = await this.#allMaterializations();
    const childMapping = materializations.find(mapping => mapping.objectKey === key);
    const lockKey = childMapping?.parentObjectKey || key;
    return this.withArchiveEntryLock(lockKey, () => this.#removeObjectUnlocked(key));
  }

  async #removeObjectUnlocked(key, materializations = null) {
    const objects = await this.#allObjects();
    for (const object of objects) {
      if (object.parentObjectKey === key) await this.#removeObjectFiles(object.objectKey);
    }
    for (const mapping of materializations || await this.#allMaterializations()) {
      if (mapping.parentObjectKey === key) {
        await rm(this.#materializationStagePath(mapping.objectKey), { force: true });
        await rm(`${this.#materializationStagePath(mapping.objectKey)}.source`, { force: true });
        await this.#removeObjectFiles(mapping.objectKey);
        await rm(this.#materializationPath(mapping.parentObjectKey, mapping.entryId), { force: true });
      } else if (mapping.objectKey === key) {
        await rm(this.#materializationStagePath(mapping.objectKey), { force: true });
        await rm(`${this.#materializationStagePath(mapping.objectKey)}.source`, { force: true });
        await rm(this.#materializationPath(mapping.parentObjectKey, mapping.entryId), { force: true });
      }
    }
    await this.#removeObjectFiles(key);
  }

  async #removeObjectFiles(key) {
    await rm(this.#objectPath(key), { force: true });
    await rm(this.#objectMetaPath(key), { force: true });
  }

  async statObject(objectKey) {
    await this.ready(); const metadata = await this.#loadObject(objectKey);
    return { objectKey: metadata.objectKey, byteSize: metadata.byteSize, mediaType: metadata.mediaType, filename: metadata.filename, kind: metadata.kind };
  }

  async createReadStream(objectKey, { startByte = 0, endByte, signal } = {}) {
    const metadata = await this.#loadObject(objectKey);
    exactInteger(startByte, 0, metadata.byteSize, "INVALID_OFFSET", "Intervallo allegato non valido.");
    const inclusiveEnd = endByte === undefined ? metadata.byteSize - 1 : exactInteger(endByte, startByte, metadata.byteSize - 1, "INVALID_OFFSET", "Intervallo allegato non valido.");
    const stream = createReadStream(this.#objectPath(metadata.objectKey), { flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW, start: startByte, end: inclusiveEnd });
    const abort = () => stream.destroy(new AttachmentStorageError("UPLOAD_ABORTED", "Lettura annullata.", 499));
    if (signal?.aborted) abort(); else signal?.addEventListener("abort", abort, { once: true });
    stream.once("close", () => signal?.removeEventListener("abort", abort));
    return stream;
  }

  async openObject(objectKey, options = {}) {
    const metadata = await this.statObject(objectKey);
    return { ...metadata, stream: await this.createReadStream(objectKey, options) };
  }

  async readText(objectKey, { startByte = 0, maxBytes = DEFAULT_READ_BYTES, signal } = {}) {
    await this.ready(); const metadata = await this.#loadObject(objectKey);
    if (metadata.kind !== "text") fail("OBJECT_NOT_TEXT", "L'allegato non è testuale.", 415);
    exactInteger(startByte, 0, metadata.byteSize, "INVALID_OFFSET", "Intervallo allegato non valido.");
    exactInteger(maxBytes, 4, DEFAULT_READ_BYTES, "INVALID_READ_LIMIT", "Limite di lettura non valido.");
    if (signal?.aborted) fail("UPLOAD_ABORTED", "Lettura annullata.", 499);
    if (startByte === metadata.byteSize) return { content: "", startByte, endByte: startByte, nextByte: null, hasMore: false };
    const handle = await open(this.#objectPath(metadata.objectKey), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    try {
      if (startByte > 0) {
        const marker = Buffer.alloc(1); await handle.read(marker, 0, 1, startByte);
        if ((marker[0] & 0xc0) === 0x80) fail("INVALID_OFFSET", "L'offset deve iniziare su un carattere UTF-8.", 409);
      }
      let endByte = Math.min(metadata.byteSize, startByte + maxBytes);
      while (endByte > startByte && endByte < metadata.byteSize) {
        const marker = Buffer.alloc(1); await handle.read(marker, 0, 1, endByte);
        if ((marker[0] & 0xc0) !== 0x80) break;
        endByte -= 1;
      }
      if (endByte === startByte) fail("INVALID_READ_LIMIT", "Il limite non contiene un carattere UTF-8 completo.");
      const windowStart = Math.max(0, startByte - REDACTION_LOOKAROUND_BYTES);
      let alignedStart = windowStart;
      while (alignedStart < startByte) {
        const marker = Buffer.alloc(1); await handle.read(marker, 0, 1, alignedStart);
        if ((marker[0] & 0xc0) !== 0x80) break;
        alignedStart += 1;
      }
      let windowEnd = Math.min(metadata.byteSize, endByte + REDACTION_LOOKAROUND_BYTES);
      while (windowEnd > endByte && windowEnd < metadata.byteSize) {
        const marker = Buffer.alloc(1); await handle.read(marker, 0, 1, windowEnd);
        if ((marker[0] & 0xc0) !== 0x80) break;
        windowEnd -= 1;
      }
      const buffer = Buffer.allocUnsafe(windowEnd - alignedStart);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, alignedStart);
      if (bytesRead !== buffer.length) fail("STORAGE_CORRUPT", "Testo allegato non integro.", 503);
      const prefixBytes = startByte - alignedStart; const targetBytes = endByte - startByte;
      let prefix; let target; let suffix;
      try {
        prefix = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, prefixBytes));
        target = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(prefixBytes, prefixBytes + targetBytes));
        suffix = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(prefixBytes + targetBytes));
      } catch { fail("STORAGE_CORRUPT", "Testo allegato non valido.", 503); }
      const content = redactAttachmentWindow({ prefix, target, suffix }, { maxOutputBytes: maxBytes });
      if (signal?.aborted) fail("UPLOAD_ABORTED", "Lettura annullata.", 499);
      const hasMore = endByte < metadata.byteSize;
      return { content, startByte, endByte, nextByte: hasMore ? endByte : null, hasMore };
    } finally { await handle.close(); }
  }

  async readDocumentText(scopeValue, originalObjectKey, options = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue);
    const originalKey = checkedId(originalObjectKey, "INVALID_OBJECT_KEY");
    const original = await this.#loadObject(originalKey);
    if (!sameScope(original.scope, scope) || original.kind !== "document") fail("OBJECT_NOT_FOUND", "Documento non trovato.", 404);
    const extractedChildren = (await this.#allObjects()).filter(item => item.parentObjectKey === originalKey);
    if (!extractedChildren.length) {
      if (original.documentMetadata?.extractedBytes === 0) return { content: "", startByte: 0, endByte: 0, nextByte: null, hasMore: false };
      fail("STORAGE_CORRUPT", "Testo estratto non integro.", 503);
    }
    if (extractedChildren.length !== 1 || extractedChildren[0].kind !== "text" || !sameScope(extractedChildren[0].scope, scope)) fail("STORAGE_CORRUPT", "Testo estratto non integro.", 503);
    const extracted = extractedChildren[0];
    return this.readText(extracted.objectKey, options);
  }

  async listArchiveEntries(scopeValue, objectKey, { cursor = null, limit = 50, signal } = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue); const key = checkedId(objectKey, "INVALID_OBJECT_KEY");
    const metadata = await this.#loadObject(key);
    if (!sameScope(metadata.scope, scope)) fail("OBJECT_NOT_FOUND", "Allegato non trovato.", 404);
    if (metadata.kind !== "archive") fail("OBJECT_NOT_ARCHIVE", "L'allegato non è un archivio ZIP.", 415);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) fail("INVALID_ARCHIVE_LIMIT", "Limite archivio non valido.");
    const cursorText = cursor === null || cursor === "" ? "0" : String(cursor);
    if (!/^(?:0|[1-9][0-9]{0,3})$/.test(cursorText)) fail("INVALID_ARCHIVE_CURSOR", "Cursore archivio non valido.");
    const start = Number(cursorText);
    const archive = await inspectZipFile(this.#objectPath(key), { signal });
    if (archive.byteSize !== metadata.byteSize || start > archive.entries.length) fail("STORAGE_CORRUPT", "Archivio allegato non integro.", 503);
    const catalog = archive.entries.map(entry => publicArchiveEntry(entry)).filter(Boolean);
    if (start > catalog.length) fail("INVALID_ARCHIVE_CURSOR", "Cursore archivio non valido.");
    const entries = catalog.slice(start, start + limit);
    const next = start + entries.length;
    return {
      entries,
      nextCursor: next < catalog.length ? String(next) : null,
      entryCount: archive.entryCount,
      availableEntryCount: catalog.length,
      skippedEntryCount: archive.entryCount - catalog.length,
      totalUncompressedBytes: archive.totalUncompressedBytes,
    };
  }

  async openArchiveEntry(scopeValue, objectKey, entryId, { signal } = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue); const key = checkedId(objectKey, "INVALID_OBJECT_KEY");
    const metadata = await this.#loadObject(key);
    if (!sameScope(metadata.scope, scope)) fail("OBJECT_NOT_FOUND", "Allegato non trovato.", 404);
    if (metadata.kind !== "archive") fail("OBJECT_NOT_ARCHIVE", "L'allegato non è un archivio ZIP.", 415);
    const archive = await inspectZipFile(this.#objectPath(key), { signal });
    if (archive.byteSize !== metadata.byteSize) fail("STORAGE_CORRUPT", "Archivio allegato non integro.", 503);
    const internal = archive.entries.find(entry => entry.id === String(entryId || ""));
    if (!internal) fail("ZIP_ENTRY_NOT_FOUND", "Voce ZIP non trovata.", 404);
    const entry = publicArchiveEntry(internal);
    if (!entry || !["text", "document"].includes(entry.kind)) fail("ZIP_ENTRY_UNSUPPORTED", "Voce ZIP non testuale.", 415);
    try {
      const opened = openZipEntry(this.#objectPath(key), archive, internal.id, { signal, validateText: entry.kind === "text" });
      return { entry, stream: opened.stream, verified: opened.verified };
    } catch (error) { throw publicError(error); }
  }

  async materializeArchiveTextEntry(scopeValue, objectKey, entryIdValue, { signal } = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue);
    const parentObjectKey = checkedId(objectKey, "INVALID_OBJECT_KEY");
    const entryId = checkedArchiveEntryId(entryIdValue);
    return this.withArchiveEntryLock(parentObjectKey, async () => {
      const parent = await this.#loadObject(parentObjectKey);
      if (!sameScope(parent.scope, scope)) fail("OBJECT_NOT_FOUND", "Allegato non trovato.", 404);
      if (parent.kind !== "archive") fail("OBJECT_NOT_ARCHIVE", "L'allegato non è un archivio ZIP.", 415);

      let mapping = await this.#loadMaterialization(parentObjectKey, entryId, { optional: true });
      if (mapping?.state === "complete") return this.#materializedResult(mapping, scope);
      if (mapping) await this.#discardMaterialization(mapping);

      const archive = await inspectZipFile(this.#objectPath(parentObjectKey), { signal });
      if (archive.byteSize !== parent.byteSize) fail("STORAGE_CORRUPT", "Archivio allegato non integro.", 503);
      const internal = archive.entries.find(item => item.id === entryId);
      if (!internal) fail("ZIP_ENTRY_NOT_FOUND", "Voce ZIP non trovata.", 404);
      const entry = publicArchiveEntry(internal);
      if (!entry || !["text", "document"].includes(entry.kind)) fail("ZIP_ENTRY_UNSUPPORTED", "Voce ZIP non testuale.", 415);
      const filename = normalizeAttachmentFilename(posix.basename(entry.path));
      const isDocument = entry.kind === "document";
      const reservation = entry.byteSize + (isDocument ? DOCUMENT_EXTRACTION_RESERVATION_BYTES : 0);
      const objectKeyForEntry = randomUUID();
      const now = new Date(this.now()).toISOString();
      mapping = {
        version: MATERIALIZATION_VERSION,
        state: "materializing",
        parentObjectKey,
        entryId,
        objectKey: objectKeyForEntry,
        scope,
        filename,
        byteSize: isDocument ? 0 : entry.byteSize,
        reservedBytes: reservation,
        sha256: null,
        createdAt: now,
        updatedAt: now,
        ...(isDocument ? { sourceByteSize: entry.byteSize } : {}),
      };

      await this.withGlobalLock("quota", async () => {
        const [manifests, materializations, objects, disk] = await Promise.all([
          this.#allManifests(), this.#allMaterializations(), this.#allObjects(), statfs(this.root),
        ]);
        const uploadingBytes = uploadingBytesFor(manifests);
        const materializingBytes = materializingBytesFor(materializations);
        const objectBytes = objects.reduce((sum, item) => sum + item.byteSize, 0);
        const ownerBytes = uploadingBytesFor(manifests, scope.ownerId) + materializingBytesFor(materializations, scope.ownerId)
          + objects.filter(item => item.scope.ownerId === scope.ownerId).reduce((sum, item) => sum + item.byteSize, 0);
        const conversationBytes = uploadingBytesFor(manifests, scope.ownerId, scope.machineId, scope.conversationId)
          + materializingBytesFor(materializations, scope.ownerId, scope.machineId, scope.conversationId)
          + objects.filter(item => sameScope(item.scope, scope)).reduce((sum, item) => sum + item.byteSize, 0);
        if (objectBytes + uploadingBytes + materializingBytes + reservation > ATTACHMENT_CAPABILITIES.globalQuotaBytes) fail("GLOBAL_QUOTA_EXCEEDED", "Spazio allegati esaurito.", 507);
        if (ownerBytes + reservation > ATTACHMENT_CAPABILITIES.ownerQuotaBytes) fail("OWNER_QUOTA_EXCEEDED", "Quota allegati dell'utente superata.", 413);
        if (conversationBytes + reservation > ATTACHMENT_CAPABILITIES.conversationQuotaBytes) fail("CONVERSATION_QUOTA_EXCEEDED", "Quota allegati della conversazione superata.", 413);
        const available = Number(disk.bavail) * Number(disk.bsize);
        if (!Number.isSafeInteger(available) || available - reservation < ATTACHMENT_CAPABILITIES.minFreeBytes) fail("INSUFFICIENT_STORAGE", "Spazio su disco insufficiente.", 507);
        await atomicJson(this.#materializationPath(parentObjectKey, entryId), mapping);
      });

      const temporary = this.#materializationStagePath(objectKeyForEntry);
      try {
        if (signal?.aborted) fail("UPLOAD_ABORTED", "Lettura annullata.", 499);
        const opened = openZipEntry(this.#objectPath(parentObjectKey), archive, entryId, { signal, validateText: !isDocument });
        const sourceTemporary = isDocument ? `${temporary}.source` : temporary;
        const output = createWriteStream(sourceTemporary, { flags: fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW, mode: 0o600 });
        await Promise.all([pipeline(opened.stream, output, { signal }), opened.verified]);
        const temporaryInfo = await regularFile(sourceTemporary, { expectedSize: entry.byteSize });
        if (temporaryInfo.size !== entry.byteSize) fail("ZIP_INTEGRITY", "Voce ZIP non integra.", 415);
        let digest; let document = null; let extractedBytes = entry.byteSize;
        if (isDocument) {
          if (typeof this.documentExtractor !== "function") fail("DOCUMENT_EXTRACTOR_UNAVAILABLE", "Lettore documenti non disponibile.", 503);
          const extracted = await this.documentExtractor({ inputPath: sourceTemporary, outputPath: temporary, filename, mediaType: documentMediaTypeForFilename(filename), sourceBytes: entry.byteSize, signal,
            maxOutputBytes: ATTACHMENT_CAPABILITIES.maxDocumentExtractedBytes });
          if (!extracted || !Number.isSafeInteger(extracted.textBytes) || extracted.textBytes < 0 || extracted.textBytes > ATTACHMENT_CAPABILITIES.maxDocumentExtractedBytes
              || extracted.sourceBytes !== entry.byteSize || !extracted.coverage || !["complete", "partial", "image_only", "unsupported"].includes(extracted.coverage.state)) fail("DOCUMENT_EXTRACTOR_INVALID", "Risultato del lettore documenti non valido.", 503);
          extractedBytes = extracted.textBytes;
          document = { format: extracted.format, extractedBytes, sourceBytes: extracted.sourceBytes, coverage: extracted.coverage };
          await regularFile(temporary, { expectedSize: extractedBytes });
          await rm(sourceTemporary, { force: true });
        }
        digest = await hashFile(temporary, { signal });
        const durable = await open(temporary, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
        try { await durable.chmod(0o600); await durable.sync(); } finally { await durable.close(); }
        await rename(temporary, this.#objectPath(objectKeyForEntry));
        await atomicJson(this.#objectMetaPath(objectKeyForEntry), {
          version: MANIFEST_VERSION,
          objectKey: objectKeyForEntry,
          kind: "text",
          scope,
          filename: isDocument ? "document-text.txt" : filename,
          mediaType: "text/plain",
          byteSize: extractedBytes,
          sha256: digest,
          createdAt: new Date(this.now()).toISOString(),
        });
        mapping.state = "complete";
        mapping.sha256 = digest;
        mapping.byteSize = extractedBytes;
        if (document) mapping.document = document;
        mapping.updatedAt = new Date(this.now()).toISOString();
        await atomicJson(this.#materializationPath(parentObjectKey, entryId), mapping);
        return this.#materializedResult(mapping, scope);
      } catch (error) {
        await rm(temporary, { force: true }).catch(() => {});
        await rm(`${temporary}.source`, { force: true }).catch(() => {});
        await this.#removeObjectFiles(objectKeyForEntry).catch(() => {});
        await rm(this.#materializationPath(parentObjectKey, entryId), { force: true }).catch(() => {});
        throw publicError(error);
      }
    }).catch(error => { throw publicError(error); });
  }

  async readMaterializedArchiveText(scopeValue, parentObjectKeyValue, objectKeyValue, options = {}) {
    await this.ready();
    const scope = normalizeScope(scopeValue);
    const parentObjectKey = checkedId(parentObjectKeyValue, "INVALID_OBJECT_KEY");
    const objectKey = checkedId(objectKeyValue, "INVALID_OBJECT_KEY");
    return this.withArchiveEntryLock(parentObjectKey, async () => {
      const parent = await this.#loadObject(parentObjectKey);
      if (!sameScope(parent.scope, scope)) fail("OBJECT_NOT_FOUND", "Allegato non trovato.", 404);
      if (parent.kind !== "archive") fail("OBJECT_NOT_ARCHIVE", "L'allegato non è un archivio ZIP.", 415);
      const mapping = (await this.#allMaterializations()).find(item => item.parentObjectKey === parentObjectKey
        && item.objectKey === objectKey && item.state === "complete");
      if (!mapping || !sameScope(mapping.scope, scope)) fail("OBJECT_NOT_FOUND", "Voce ZIP non trovata.", 404);
      await this.#materializedResult(mapping, scope);
      return this.readText(objectKey, options);
    }).catch(error => { throw publicError(error); });
  }

  async #materializedResult(mapping, scope) {
    if (!sameScope(mapping.scope, scope)) fail("OBJECT_NOT_FOUND", "Allegato non trovato.", 404);
    const child = await this.#loadObject(mapping.objectKey);
    if (!sameScope(child.scope, scope) || child.kind !== "text" || child.byteSize !== mapping.byteSize || child.sha256 !== mapping.sha256) {
      fail("STORAGE_CORRUPT", "Voce ZIP materializzata non integra.", 503);
    }
    return {
      objectKey: child.objectKey,
      entryId: mapping.entryId,
      filename: mapping.filename,
      mediaType: mapping.document ? "text/plain" : child.mediaType,
      byteSize: child.byteSize,
      sha256: child.sha256,
      verified: true,
      ...(mapping.sourceByteSize ? { sourceByteSize: mapping.sourceByteSize } : {}),
      ...(mapping.document ? { document: mapping.document } : {}),
    };
  }

  async #discardMaterialization(mapping) {
    await rm(this.#materializationStagePath(mapping.objectKey), { force: true });
    await rm(`${this.#materializationStagePath(mapping.objectKey)}.source`, { force: true });
    await this.#removeObjectFiles(mapping.objectKey);
    await rm(this.#materializationPath(mapping.parentObjectKey, mapping.entryId), { force: true });
  }

  async #recoverIncompleteMaterializations() {
    for (const mapping of await this.#allMaterializations()) {
      if (mapping.state !== "materializing") continue;
      await this.withArchiveEntryLock(mapping.parentObjectKey, async () => {
        const current = await this.#loadMaterialization(mapping.parentObjectKey, mapping.entryId, { optional: true });
        if (current?.state === "materializing") await this.#discardMaterialization(current);
      });
    }
  }

  async cleanupExpired() {
    const threshold = this.now() - this.partialTtlMs;
    const manifests = await this.withGlobalLock("quota", () => this.#allManifests());
    for (const manifest of manifests) {
      if (manifest.state !== "uploading" || Date.parse(manifest.updatedAt) >= threshold) continue;
      await this.withUploadLock(manifest.id, async () => {
        const current = await this.#loadManifest(manifest.id).catch(error => error.code === "UPLOAD_NOT_FOUND" ? null : Promise.reject(error));
        if (!current || current.state !== "uploading" || Date.parse(current.updatedAt) >= threshold) return;
        await rm(this.#stagePath(current.id), { force: true });
        await rm(this.#manifestPath(current.id), { force: true });
      });
    }
    const materializations = await this.withGlobalLock("quota", () => this.#allMaterializations());
    for (const mapping of materializations) {
      if (mapping.state !== "materializing" || Date.parse(mapping.updatedAt) >= threshold) continue;
      await this.withArchiveEntryLock(mapping.parentObjectKey, async () => {
        const current = await this.#loadMaterialization(mapping.parentObjectKey, mapping.entryId, { optional: true });
        if (!current || current.state !== "materializing" || Date.parse(current.updatedAt) >= threshold) return;
        await this.#discardMaterialization(current);
      });
    }
  }
}

function publicArchiveEntry(entry) {
  const filename = posix.basename(entry.path);
  let classified;
  try {
    const normalized = normalizeAttachmentFilename(filename);
    classified = classifyAttachmentFilename(normalized);
  } catch (error) {
    if (!(error instanceof AttachmentError)) throw error;
    return null;
  }
  const mediaType = classified.kind === "text" ? "text/plain"
    : classified.kind === "image" ? "image/*"
      : classified.kind === "archive" ? "application/zip" : "application/octet-stream";
  return Object.freeze({
    id: entry.id,
    path: entry.path,
    kind: classified.kind,
    mediaType,
    byteSize: entry.byteSize,
    compressedBytes: entry.compressedBytes,
  });
}

function uploadingBytesFor(manifests, ownerId, machineId, conversationId) {
  return manifests.filter(item => item.state === "uploading" && (ownerId === undefined || item.scope.ownerId === ownerId)
    && (machineId === undefined || item.scope.machineId === machineId)
    && (conversationId === undefined || item.scope.conversationId === conversationId)).reduce((sum, item) => sum + uploadReservation(item), 0);
}

function uploadReservation(item) {
  return item.reservedBytes ?? (item.byteSize + (item.kind === "document" ? DOCUMENT_EXTRACTION_RESERVATION_BYTES : 0));
}

function materializingBytesFor(materializations, ownerId, machineId, conversationId) {
  return materializations.filter(item => item.state === "materializing" && (ownerId === undefined || item.scope.ownerId === ownerId)
    && (machineId === undefined || item.scope.machineId === machineId)
    && (conversationId === undefined || item.scope.conversationId === conversationId)).reduce((sum, item) => sum + (item.reservedBytes ?? (item.sourceByteSize ? item.sourceByteSize + DOCUMENT_EXTRACTION_RESERVATION_BYTES : item.byteSize)), 0);
}

function clampUtf8(value, maximum) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maximum) return value;
  let end = maximum;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

async function validateTextFile(path, { signal }) {
  const probeHandle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const probe = Buffer.alloc(16); const { bytesRead } = await probeHandle.read(probe, 0, probe.length, 0);
    if (isKnownBinaryAttachment(probe.subarray(0, bytesRead))) fail("TYPE_MISMATCH", "Il contenuto del file non corrisponde al tipo dichiarato.", 415);
  } finally { await probeHandle.close(); }
  const input = createReadStream(path, { flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW, highWaterMark: 64 * 1024 });
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const hash = createHash("sha256"); let bytes = 0; let first = true;
  try {
    for await (const chunk of input) {
      if (signal?.aborted) fail("UPLOAD_ABORTED", "Caricamento annullato.", 499);
      hash.update(chunk); bytes += chunk.length;
      let decoded;
      try { decoded = decoder.decode(chunk, { stream: true }); } catch { fail("INVALID_TEXT", "Il file non contiene testo UTF-8 valido.", 415); }
      if (first) { first = false; decoded = decoded.replace(/^\uFEFF/, ""); }
      if (BAD_TEXT_CONTROL.test(decoded)) fail("INVALID_TEXT", "Il file contiene dati binari non consentiti.", 415);
    }
    try { if (BAD_TEXT_CONTROL.test(decoder.decode())) fail("INVALID_TEXT", "Il file contiene dati binari non consentiti.", 415); }
    catch (error) { if (error instanceof AttachmentStorageError) throw error; fail("INVALID_TEXT", "Il file non contiene testo UTF-8 valido.", 415); }
    return { byteSize: bytes, sha256: hash.digest("hex") };
  } finally { input.destroy(); }
}

async function hashFile(path, { signal }) {
  const input = createReadStream(path, { flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW, highWaterMark: 64 * 1024 });
  const hash = createHash("sha256");
  try {
    for await (const chunk of input) {
      if (signal?.aborted) fail("UPLOAD_ABORTED", "Caricamento annullato.", 499);
      hash.update(chunk);
    }
    return hash.digest("hex");
  } finally { input.destroy(); }
}

export function createAttachmentStorage(options) { return new AttachmentStorage(options); }
