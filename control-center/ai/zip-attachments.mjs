import { createHash } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createInflateRaw } from "node:zlib";

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const DESCRIPTOR_SIGNATURE = 0x08074b50;
const MAX_EOCD_BYTES = 65_557;
const MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAX_ENTRIES = 2_048;
const MAX_RATIO = 100;
const MAX_PATH_BYTES = 1_024;
const ENCRYPTED_FLAGS = 0x0001 | 0x0040 | 0x2000;
const ALLOWED_FLAGS = 0x0006 | 0x0008 | 0x0800;
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/;
const BAD_TEXT_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const VERIFIED_MANIFESTS = new WeakSet();

export const ZIP_ATTACHMENT_LIMITS = Object.freeze({
  maxEntries: MAX_ENTRIES,
  maxCentralDirectoryBytes: MAX_CENTRAL_DIRECTORY_BYTES,
  maxEntryBytes: MAX_ENTRY_BYTES,
  maxTotalUncompressedBytes: MAX_TOTAL_BYTES,
  maxCompressionRatio: MAX_RATIO,
});

export class ZipAttachmentError extends Error {
  constructor(code, message, status = 415) {
    super(message);
    this.name = "ZipAttachmentError";
    this.code = code;
    this.status = status;
  }
}

function fail(code, message = "Archivio ZIP non valido.", status = 415) { throw new ZipAttachmentError(code, message, status); }

function checkedInteger(value, maximum, code = "INVALID_ZIP") {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(code);
  return value;
}

async function readExact(handle, length, position) {
  checkedInteger(length, MAX_CENTRAL_DIRECTORY_BYTES, "INVALID_ZIP");
  checkedInteger(position, MAX_ARCHIVE_BYTES, "INVALID_ZIP");
  const buffer = Buffer.allocUnsafe(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  if (bytesRead !== length) fail("TRUNCATED_ZIP");
  return buffer;
}

function hasZip64Extra(extra) {
  let offset = 0;
  while (offset < extra.length) {
    if (offset + 4 > extra.length) fail("INVALID_ZIP_EXTRA");
    const id = extra.readUInt16LE(offset);
    const length = extra.readUInt16LE(offset + 2);
    offset += 4;
    if (offset + length > extra.length) fail("INVALID_ZIP_EXTRA");
    if (id === 0x0001) return true;
    offset += length;
  }
  return false;
}

function decodeEntryPath(bytes, flags) {
  let value;
  if (flags & 0x0800) {
    try { value = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch { fail("INVALID_ZIP_PATH"); }
  } else {
    if ([...bytes].some(byte => byte > 0x7f)) fail("INVALID_ZIP_PATH_ENCODING");
    value = bytes.toString("ascii");
  }
  const normalized = value.normalize("NFC");
  if (!normalized || normalized !== value || Buffer.byteLength(normalized, "utf8") > MAX_PATH_BYTES || [...normalized].length > 512
      || normalized.startsWith("/") || normalized.startsWith("\\") || /^[A-Za-z]:/.test(normalized) || normalized.includes("\\")
      || CONTROL_OR_BIDI.test(normalized)) fail("INVALID_ZIP_PATH");
  const directory = normalized.endsWith("/");
  const components = normalized.split("/");
  if (directory) components.pop();
  if (!components.length || components.some(component => !component || component === "." || component === "..")) fail("INVALID_ZIP_PATH");
  return { path: normalized, directory };
}

function entryId(path, crc32, localHeaderOffset) {
  return createHash("sha256").update(path).update("\0").update(String(crc32)).update("\0").update(String(localHeaderOffset)).digest("hex").slice(0, 24);
}

function validateUnixType(versionMadeBy, externalAttributes, directory) {
  if ((versionMadeBy >>> 8) !== 3) return;
  const type = (externalAttributes >>> 16) & 0xf000;
  if (type === 0xa000) fail("ZIP_SYMLINK");
  if (type && type !== 0x8000 && type !== 0x4000) fail("ZIP_SPECIAL_FILE");
  if ((type === 0x4000) !== directory && type !== 0) fail("INVALID_ZIP_PATH");
}

async function descriptorEnd(handle, entry, dataEnd, centralOffset) {
  if (!(entry.flags & 0x0008)) return dataEnd;
  if (dataEnd + 12 > centralOffset) fail("TRUNCATED_ZIP");
  const probeLength = Math.min(16, centralOffset - dataEnd);
  const descriptor = await readExact(handle, probeLength, dataEnd);
  const matches = start => descriptor.length >= start + 12 && descriptor.readUInt32LE(start) === entry.crc32
    && descriptor.readUInt32LE(start + 4) === entry.compressedBytes && descriptor.readUInt32LE(start + 8) === entry.byteSize;
  if (descriptor.length >= 16 && descriptor.readUInt32LE(0) === DESCRIPTOR_SIGNATURE && matches(4)) return dataEnd + 16;
  if (matches(0)) return dataEnd + 12;
  fail("INVALID_ZIP_DESCRIPTOR");
}

async function validateLocalEntry(handle, entry, centralOffset) {
  if (entry.localHeaderOffset + 30 > centralOffset) fail("INVALID_ZIP_OFFSET");
  const local = await readExact(handle, 30, entry.localHeaderOffset);
  if (local.readUInt32LE(0) !== LOCAL_SIGNATURE) fail("INVALID_ZIP_LOCAL_HEADER");
  const flags = local.readUInt16LE(6);
  const method = local.readUInt16LE(8);
  const nameLength = local.readUInt16LE(26);
  const extraLength = local.readUInt16LE(28);
  if (flags !== entry.flags || method !== entry.method) fail("INVALID_ZIP_LOCAL_HEADER");
  const variable = await readExact(handle, nameLength + extraLength, entry.localHeaderOffset + 30);
  if (!variable.subarray(0, nameLength).equals(entry.nameBytes) || hasZip64Extra(variable.subarray(nameLength))) fail("INVALID_ZIP_LOCAL_HEADER");
  if (!(flags & 0x0008) && (local.readUInt32LE(14) !== entry.crc32 || local.readUInt32LE(18) !== entry.compressedBytes
      || local.readUInt32LE(22) !== entry.byteSize)) fail("INVALID_ZIP_LOCAL_HEADER");
  if ((flags & 0x0008) && (![0, entry.crc32].includes(local.readUInt32LE(14))
      || ![0, entry.compressedBytes].includes(local.readUInt32LE(18))
      || ![0, entry.byteSize].includes(local.readUInt32LE(22)))) fail("INVALID_ZIP_LOCAL_HEADER");
  const dataOffset = entry.localHeaderOffset + 30 + nameLength + extraLength;
  const dataEnd = dataOffset + entry.compressedBytes;
  if (!Number.isSafeInteger(dataEnd) || dataEnd > centralOffset) fail("INVALID_ZIP_OFFSET");
  const intervalEnd = await descriptorEnd(handle, entry, dataEnd, centralOffset);
  return { ...entry, dataOffset, intervalEnd };
}

export async function inspectZipFile(path, { signal } = {}) {
  if (signal?.aborted) fail("ZIP_ABORTED", "Lettura ZIP annullata.", 499);
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.nlink !== 1 || info.size < 22 || info.size > MAX_ARCHIVE_BYTES) fail("INVALID_ZIP_SIZE", "Dimensione ZIP non consentita.", 413);
    const tailLength = Math.min(info.size, MAX_EOCD_BYTES);
    const tailOffset = info.size - tailLength;
    const tail = await readExact(handle, tailLength, tailOffset);
    let eocdIndex = -1;
    for (let index = tail.length - 22; index >= 0; index -= 1) {
      if (tail.readUInt32LE(index) === EOCD_SIGNATURE && index + 22 + tail.readUInt16LE(index + 20) === tail.length) { eocdIndex = index; break; }
    }
    if (eocdIndex < 0) fail("INVALID_ZIP_EOCD");
    const disk = tail.readUInt16LE(eocdIndex + 4);
    const centralDisk = tail.readUInt16LE(eocdIndex + 6);
    const diskEntries = tail.readUInt16LE(eocdIndex + 8);
    const totalEntries = tail.readUInt16LE(eocdIndex + 10);
    const centralSize = tail.readUInt32LE(eocdIndex + 12);
    const centralOffset = tail.readUInt32LE(eocdIndex + 16);
    const eocdOffset = tailOffset + eocdIndex;
    if (disk || centralDisk || diskEntries !== totalEntries) fail("ZIP_MULTI_DISK");
    if (totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) fail("ZIP64_UNSUPPORTED");
    if (totalEntries < 1) fail("EMPTY_ZIP");
    if (totalEntries > MAX_ENTRIES) fail("ZIP_TOO_MANY_ENTRIES", "Lo ZIP contiene troppi file.", 413);
    if (centralSize < 46 || centralSize > MAX_CENTRAL_DIRECTORY_BYTES || centralOffset + centralSize !== eocdOffset) fail("INVALID_ZIP_DIRECTORY");
    const central = await readExact(handle, centralSize, centralOffset);
    const entries = [];
    const paths = new Set();
    const ids = new Set();
    let cursor = 0;
    let totalUncompressedBytes = 0;
    for (let index = 0; index < totalEntries; index += 1) {
      if (signal?.aborted) fail("ZIP_ABORTED", "Lettura ZIP annullata.", 499);
      if (cursor + 46 > central.length || central.readUInt32LE(cursor) !== CENTRAL_SIGNATURE) fail("INVALID_ZIP_DIRECTORY");
      const versionMadeBy = central.readUInt16LE(cursor + 4);
      const flags = central.readUInt16LE(cursor + 8);
      const method = central.readUInt16LE(cursor + 10);
      const crc32 = central.readUInt32LE(cursor + 16);
      const compressedBytes = central.readUInt32LE(cursor + 20);
      const byteSize = central.readUInt32LE(cursor + 24);
      const nameLength = central.readUInt16LE(cursor + 28);
      const extraLength = central.readUInt16LE(cursor + 30);
      const commentLength = central.readUInt16LE(cursor + 32);
      const diskStart = central.readUInt16LE(cursor + 34);
      const externalAttributes = central.readUInt32LE(cursor + 38);
      const localHeaderOffset = central.readUInt32LE(cursor + 42);
      const end = cursor + 46 + nameLength + extraLength + commentLength;
      if (!nameLength || end > central.length) fail("INVALID_ZIP_DIRECTORY");
      if (diskStart || [compressedBytes, byteSize, localHeaderOffset].includes(0xffffffff)) fail("ZIP64_UNSUPPORTED");
      if (flags & ENCRYPTED_FLAGS) fail("ZIP_ENCRYPTED");
      if (flags & ~ALLOWED_FLAGS || ![0, 8].includes(method) || (method === 0 && flags & 0x0006)) fail("ZIP_COMPRESSION_UNSUPPORTED");
      const nameBytes = Buffer.from(central.subarray(cursor + 46, cursor + 46 + nameLength));
      const extra = central.subarray(cursor + 46 + nameLength, cursor + 46 + nameLength + extraLength);
      if (hasZip64Extra(extra)) fail("ZIP64_UNSUPPORTED");
      const decoded = decodeEntryPath(nameBytes, flags);
      validateUnixType(versionMadeBy, externalAttributes, decoded.directory);
      if (paths.has(decoded.path)) fail("ZIP_DUPLICATE_PATH");
      paths.add(decoded.path);
      if (method === 0 && compressedBytes !== byteSize) fail("INVALID_ZIP_SIZE");
      if (byteSize > MAX_ENTRY_BYTES) fail("ZIP_ENTRY_TOO_LARGE", "Una voce ZIP supera il limite.", 413);
      if (!decoded.directory && byteSize > 0 && byteSize / Math.max(1, compressedBytes) > MAX_RATIO) fail("ZIP_BOMB", "Rapporto di compressione ZIP non consentito.", 413);
      totalUncompressedBytes += byteSize;
      if (!Number.isSafeInteger(totalUncompressedBytes) || totalUncompressedBytes > MAX_TOTAL_BYTES) fail("ZIP_BOMB", "Contenuto ZIP espanso troppo grande.", 413);
      const id = entryId(decoded.path, crc32, localHeaderOffset);
      if (ids.has(id)) fail("ZIP_DUPLICATE_ENTRY");
      ids.add(id);
      entries.push({ id, path: decoded.path, directory: decoded.directory, flags, method, crc32, compressedBytes, byteSize, localHeaderOffset, nameBytes });
      cursor = end;
    }
    if (cursor !== central.length) fail("INVALID_ZIP_DIRECTORY");
    const validated = [];
    for (const entry of entries) validated.push(await validateLocalEntry(handle, entry, centralOffset));
    const intervals = [...validated].sort((left, right) => left.localHeaderOffset - right.localHeaderOffset);
    for (let index = 1; index < intervals.length; index += 1) if (intervals[index].localHeaderOffset < intervals[index - 1].intervalEnd) fail("ZIP_OVERLAPPING_ENTRIES");
    const files = validated.filter(entry => !entry.directory);
    if (!files.length) fail("EMPTY_ZIP");
    const expandedBytes = files.reduce((sum, entry) => sum + entry.byteSize, 0);
    if (expandedBytes < 1) fail("EMPTY_ZIP", "Lo ZIP non contiene dati leggibili.");
    const manifest = Object.freeze({
      version: 1,
      byteSize: info.size,
      entryCount: files.length,
      totalUncompressedBytes: expandedBytes,
      entries: Object.freeze(files.map(({ nameBytes: _nameBytes, ...entry }) => Object.freeze(entry))),
    });
    VERIFIED_MANIFESTS.add(manifest);
    return manifest;
  } finally { await handle.close(); }
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value >>> 0;
  }
  return table;
})();

function updateCrc32(crc, chunk) {
  let value = crc;
  for (const byte of chunk) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return value >>> 0;
}

class ZipVerifier extends Transform {
  constructor(entry) { super(); this.entry = entry; this.bytes = 0; this.crc = 0xffffffff; }
  _transform(chunk, encoding, callback) {
    this.bytes += chunk.length;
    if (this.bytes > this.entry.byteSize) { callback(new ZipAttachmentError("ZIP_BOMB", "Voce ZIP oltre il limite.", 413)); return; }
    this.crc = updateCrc32(this.crc, chunk);
    callback(null, chunk);
  }
  _flush(callback) {
    const crc32 = (this.crc ^ 0xffffffff) >>> 0;
    if (this.bytes !== this.entry.byteSize || crc32 !== this.entry.crc32) { callback(new ZipAttachmentError("ZIP_INTEGRITY", "Voce ZIP non integra.")); return; }
    callback();
  }
}

class ZipTextVerifier extends Transform {
  constructor() { super(); this.decoder = new TextDecoder("utf-8", { fatal: true }); }
  _transform(chunk, encoding, callback) {
    try {
      if (BAD_TEXT_CONTROL.test(this.decoder.decode(chunk, { stream: true }))) fail("INVALID_ZIP_TEXT", "La voce ZIP non contiene testo valido.");
      callback(null, chunk);
    } catch (error) { callback(error instanceof ZipAttachmentError ? error : new ZipAttachmentError("INVALID_ZIP_TEXT", "La voce ZIP non contiene testo UTF-8 valido.")); }
  }
  _flush(callback) {
    try {
      if (BAD_TEXT_CONTROL.test(this.decoder.decode())) fail("INVALID_ZIP_TEXT", "La voce ZIP non contiene testo valido.");
      callback();
    } catch (error) { callback(error instanceof ZipAttachmentError ? error : new ZipAttachmentError("INVALID_ZIP_TEXT", "La voce ZIP non contiene testo UTF-8 valido.")); }
  }
}

export function openZipEntry(path, manifest, entryIdValue, { signal, validateText = false } = {}) {
  if (!VERIFIED_MANIFESTS.has(manifest)) fail("INVALID_ZIP_MANIFEST", "Manifest ZIP non valido.", 503);
  const id = String(entryIdValue || "");
  const entry = manifest.entries.find(item => item.id === id);
  if (!entry) fail("ZIP_ENTRY_NOT_FOUND", "Voce ZIP non trovata.", 404);
  if (signal?.aborted) fail("ZIP_ABORTED", "Lettura ZIP annullata.", 499);
  const source = entry.compressedBytes === 0
    ? Readable.from([])
    : createReadStream(path, { flags: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW, start: entry.dataOffset, end: entry.dataOffset + entry.compressedBytes - 1 });
  const verifier = new ZipVerifier(entry);
  const inflater = entry.method === 8 ? createInflateRaw() : null;
  const textVerifier = validateText ? new ZipTextVerifier() : null;
  const stages = [source, ...(inflater ? [inflater] : []), verifier, ...(textVerifier ? [textVerifier] : [])];
  const verified = pipeline(...stages, { signal }).then(() => {
    if (inflater && inflater.bytesWritten !== entry.compressedBytes) fail("ZIP_TRAILING_DATA", "Voce ZIP con dati compressi eccedenti.");
  });
  verified.catch(() => {});
  return { entry: { id: entry.id, path: entry.path, byteSize: entry.byteSize, compressedBytes: entry.compressedBytes }, stream: textVerifier || verifier, verified };
}
