import { randomUUID } from "node:crypto";
import { SERVER_AI_MODEL, SERVER_AI_MODEL_LABEL } from "./model.mjs";
import { normalizeAnalysisSummary } from "./analysis-summary.mjs";

export { SERVER_AI_MODEL };
export const CONVERSATION_MODES = Object.freeze(["auto", "fast", "deep"]);
export const RESOLVED_MODES = Object.freeze(["fast", "deep"]);
export const GENERATION_STATUSES = Object.freeze(["pending", "streaming", "completed", "aborted", "failed"]);

const MACHINE_ID_RE = /^[a-f0-9]{64}$/;
const PROJECT_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CURSOR_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}(?::?\d{2})?)$/;
const MEDIA_TYPE_RE = /^[a-z]+\/[a-z0-9.+-]+$/i;
const MAX_OWNER = 256;
const MAX_TITLE = 200;
const MAX_CONTENT = 120_000;
const MAX_SUMMARY = 16_384;
// The durable summary is deliberately smaller than the column/store limit: it
// has to coexist with tool definitions and the current request in the model
// context. Its byte cap is also applied on UTF-8 boundaries.
const MAX_CONTEXT_SUMMARY_BYTES = 7_800;
const MAX_CONTEXT_CHARS = 64 * 1024;
const MAX_CONTEXT_MESSAGE_BYTES = 16 * 1024;
const DEFAULT_CONTEXT_MESSAGE_LIMIT = 40;
const RECENT_CONTEXT_MESSAGES = 16;
const INITIAL_CONTEXT_MESSAGES = 4;
const RELEVANT_CONTEXT_MESSAGES = 5;
const COMMITMENT_CONTEXT_MESSAGES = 5;
const MAX_METADATA_BYTES = 16_384;
const MAX_LIST_LIMIT = 100;
const MAX_CURSOR_BYTES = 512;
export const MAX_ATTACHMENT_FILES_PER_TURN = 5;
export const MAX_ATTACHMENT_IMAGES_PER_TURN = 5;
export const MAX_PENDING_ATTACHMENTS = 8;
export const MAX_CONVERSATION_QUEUE = 10;
export const MAX_ATTACHMENT_BYTES_PER_FILE = 512 * 1024 * 1024;
export const MAX_ATTACHMENT_BYTES_PER_CONVERSATION = 4 * 1024 * 1024 * 1024;
export const MAX_ATTACHMENT_BYTES_PER_OWNER = 8 * 1024 * 1024 * 1024;
export const MAX_ATTACHMENT_TEXT_CONTEXT_BYTES = 1024 * 1024;
const MAX_INLINE_ATTACHMENT_TEXT_BYTES = 256 * 1024;
const MAX_ATTACHMENT_PREVIEW_BYTES = 384;

export class ConversationStoreError extends Error {
  constructor(message, status = 503) {
    super(message);
    this.name = "ConversationStoreError";
    this.status = status;
  }
}

export class ConversationNotFoundError extends ConversationStoreError {
  constructor() { super("Conversazione non trovata.", 404); }
}

function fail(message, status = 400) { throw new ConversationStoreError(message, status); }

function assertText(value, label, max) {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) fail(`${label} non valido.`);
  return value;
}

export function normalizeOwnerId(value) { return assertText(value, "Owner", MAX_OWNER); }
function ownerFrom(ownerId, subject) { return normalizeOwnerId(ownerId ?? subject); }

export function normalizeMachineId(value) {
  if (typeof value !== "string" || !MACHINE_ID_RE.test(value)) fail("Identità macchina non valida.");
  return value;
}

// `null` is the explicit general-server scope. A project is selected only by
// the server-owned registry, never by a filesystem path or a browser root.
export function normalizeProjectId(value, { allowNull = true } = {}) {
  if (allowNull && value == null) return null;
  if (typeof value !== "string" || !PROJECT_ID_RE.test(value)) fail("Progetto conversazione non valido.");
  return value;
}

export function normalizeConversationId(value) {
  if (typeof value !== "string" || !UUID_RE.test(value)) fail("Identificativo conversazione non valido.");
  return value;
}

function normalizeAttachmentIds(value, { allowEmpty = true } = {}) {
  if (value == null && allowEmpty) return [];
  if (!Array.isArray(value) || value.length > MAX_ATTACHMENT_FILES_PER_TURN) fail("Allegati non validi.");
  const ids = value.map(normalizeConversationId);
  if (new Set(ids).size !== ids.length) fail("Allegati duplicati.");
  return ids;
}

function attachmentMetadata(row) {
  const archive = row.archive || row.archive_metadata || row.archiveMetadata;
  const document = row.document || row.document_metadata || row.documentMetadata;
  return {
    id: row.id,
    name: row.filename || row.name,
    kind: row.kind,
    mediaType: row.media_type || row.mediaType,
    size: Number(row.size),
    ...(Number.isInteger(row.width) ? { width: row.width } : {}),
    ...(Number.isInteger(row.height) ? { height: row.height } : {}),
    ...(row.truncated === true ? { truncated: true } : {}),
    ...(row.kind === "archive" && archive && typeof archive === "object" ? { archive: { entryCount: Number(archive.entryCount), totalUncompressedBytes: Number(archive.totalUncompressedBytes) } } : {}),
    ...(row.kind === "document" && document && typeof document === "object" ? { document: {
      format: typeof document.format === "string" ? document.format : "unknown",
      extractedBytes: Number(document.extractedBytes ?? document.textBytes ?? 0),
      sourceBytes: Number(document.sourceBytes ?? row.size ?? 0),
      coverage: document.coverage && typeof document.coverage === "object" ? {
        state: document.coverage.state,
        unitsRead: Number(document.coverage.unitsRead || 0),
        unitsSkipped: Number(document.coverage.unitsSkipped || 0),
        warnings: Array.isArray(document.coverage.warnings) ? document.coverage.warnings.slice(0, 16) : [],
      } : { state: "unsupported", unitsRead: 0, unitsSkipped: 0, warnings: [] },
    } } : {}),
  };
}

export function artifactMetadata(row) {
  const meta = row.metadata && typeof row.metadata === "object" ? row.metadata : {};
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    mediaType: row.media_type || row.mediaType,
    size: Number(row.byte_size ?? row.byteSize ?? row.size),
    sha256: row.sha256,
    ...(Array.isArray(row.source_refs) ? { sourceRefs: row.source_refs } : Array.isArray(row.sourceRefs) ? { sourceRefs: [...row.sourceRefs] } : Array.isArray(meta.sourceRefs) ? { sourceRefs: meta.sourceRefs } : {}),
    ...(row.entry_count == null && row.entryCount == null && meta.entryCount == null ? {} : { entryCount: Number(row.entry_count ?? row.entryCount ?? meta.entryCount) }),
    ...(row.total_uncompressed_bytes == null && row.totalUncompressedBytes == null && meta.totalUncompressedBytes == null ? {} : { totalUncompressedBytes: Number(row.total_uncompressed_bytes ?? row.totalUncompressedBytes ?? meta.totalUncompressedBytes) }),
    createdAt: row.created_at || row.createdAt,
  };
}

function normalizeArtifactInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !UUID_RE.test(String(value.id || ""))) fail("Artefatto non valido.");
  const kind = value.kind === "file" || value.kind === "archive" ? value.kind : "";
  const name = typeof value.name === "string" && value.name.length > 0 && value.name.length <= 180 && !/[\\/\0\x01-\x1f\x7f]/.test(value.name) ? value.name : "";
  const mediaType = typeof value.mediaType === "string" && MEDIA_TYPE_RE.test(value.mediaType) ? value.mediaType.toLowerCase() : "";
  const byteSize = Number(value.size ?? value.byteSize);
  const sha256 = typeof value.sha256 === "string" && /^[a-f0-9]{64}$/i.test(value.sha256) ? value.sha256.toLowerCase() : "";
  const objectKey = value.objectKey == null ? String(value.id).toLowerCase() : value.objectKey;
  if (!kind || !name || !mediaType || !Number.isSafeInteger(byteSize) || byteSize < 1 || byteSize > 512 * 1024 * 1024 || !UUID_RE.test(String(objectKey)) || !sha256 || (kind === "archive" && mediaType !== "application/zip")) fail("Artefatto non valido.");
  const entryCount = kind === "archive" ? Number(value.entryCount) : null;
  const totalUncompressedBytes = kind === "archive" ? Number(value.totalUncompressedBytes) : null;
  if (kind === "archive" && (!Number.isSafeInteger(entryCount) || entryCount < 1 || entryCount > 2048 || !Number.isSafeInteger(totalUncompressedBytes) || totalUncompressedBytes < 1 || totalUncompressedBytes > 1024 * 1024 * 1024)) fail("Archivio non valido.");
  const sourceRefs = value.sourceRefs == null ? [] : [...new Set(Array.isArray(value.sourceRefs) ? value.sourceRefs.map(ref => String(ref).toLowerCase()).filter(ref => UUID_RE.test(ref)) : [])];
  if (sourceRefs.length > 5 || (value.sourceRefs != null && sourceRefs.length !== value.sourceRefs.length)) fail("Artefatto non valido.");
  return { id: String(value.id).toLowerCase(), kind, name, mediaType, byteSize, sha256, objectKey: String(objectKey).toLowerCase(), ...(sourceRefs.length ? { sourceRefs } : {}), ...(kind === "archive" ? { entryCount, totalUncompressedBytes } : {}) };
}

function normalizeAttachmentUpload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("Allegato non valido.");
  const kind = ["text", "image", "archive", "document"].includes(value.kind) ? value.kind : "";
  const filename = typeof value.filename === "string" && value.filename.trim() && Array.from(value.filename.trim()).length <= 180 && !/[\\/\0\x01-\x1f\x7f]/.test(value.filename) ? value.filename.trim() : "";
  const suppliedMediaType = typeof value.mediaType === "string" ? value.mediaType.toLowerCase().trim() : "";
  const mediaType = suppliedMediaType === "text/plain; charset=utf-8" ? "text/plain" : /^[a-z]+\/[a-z0-9.+-]+$/i.test(suppliedMediaType) && suppliedMediaType.length <= 128 ? suppliedMediaType : "";
  const declaredSize = Number(value.byteSize);
  const sha256 = typeof value.sha256 === "string" && /^[a-f0-9]{64}$/i.test(value.sha256) ? value.sha256.toLowerCase() : "";
  if (value.objectKey != null && (typeof value.objectKey !== "string" || !UUID_RE.test(value.objectKey))) fail("Riferimento allegato non valido.");
  const objectKey = value.objectKey == null ? null : value.objectKey.toLowerCase();
  const archive = kind === "archive" ? value.archive : null;
  if (!kind || !filename || !mediaType || !Number.isSafeInteger(declaredSize) || declaredSize < 1 || !sha256) fail("Allegato non valido.");
  const text = kind === "text" ? value.text : null;
  const image = kind === "image" ? value.image : null;
  if (kind === "text" && (typeof text !== "string" || image != null)) fail("Testo allegato non valido.");
  if (kind === "text" && objectKey && (declaredSize > MAX_ATTACHMENT_BYTES_PER_FILE || Buffer.byteLength(text) > MAX_ATTACHMENT_PREVIEW_BYTES)) fail("Testo allegato non valido.");
  if (kind === "text" && !objectKey && Buffer.byteLength(text) > MAX_INLINE_ATTACHMENT_TEXT_BYTES) fail("Testo allegato non valido.");
  if (kind === "image" && (objectKey || !Buffer.isBuffer(image) || image.length > 1024 * 1024 || text != null || declaredSize !== image.length)) fail("Immagine allegata non valida.");
  if (kind === "archive" && (mediaType !== "application/zip" || !objectKey || text != null || image != null || value.width != null || value.height != null
    || !archive || !Number.isSafeInteger(archive.entryCount) || archive.entryCount < 1 || archive.entryCount > 2048
    || !Number.isSafeInteger(archive.totalUncompressedBytes) || archive.totalUncompressedBytes < 1 || archive.totalUncompressedBytes > 1024 * 1024 * 1024)) fail("Archivio allegato non valido.");
  const document = kind === "document" ? value.document : null;
  if (kind === "document" && (!objectKey || text != null || image != null || value.width != null || value.height != null
    || !document || typeof document !== "object" || Array.isArray(document) || typeof document.format !== "string"
    || !Number.isSafeInteger(document.extractedBytes) || document.extractedBytes < 0 || document.extractedBytes > 16 * 1024 * 1024
    || !Number.isSafeInteger(document.sourceBytes) || document.sourceBytes < 1 || document.sourceBytes !== declaredSize
    || !document.coverage || !["complete", "partial", "image_only", "unsupported"].includes(document.coverage.state)
    || !Number.isSafeInteger(document.coverage.unitsRead) || document.coverage.unitsRead < 0
    || !Number.isSafeInteger(document.coverage.unitsSkipped) || document.coverage.unitsSkipped < 0
    || !Array.isArray(document.coverage.warnings) || document.coverage.warnings.length > 16
    || document.coverage.warnings.some(item => typeof item !== "string" || item.length > 512))) fail("Documento allegato non valido.");
  const width = kind === "image" && Number.isSafeInteger(value.width) && value.width > 0 && value.width <= 1600 ? value.width : null;
  const height = kind === "image" && Number.isSafeInteger(value.height) && value.height > 0 && value.height <= 1600 ? value.height : null;
  if (kind === "image" && (!width || !height)) fail("Dimensioni immagine non valide.");
  // Quotas apply to retained data after redaction/normalisation, never to a
  // client-declared pre-normalisation length.
  const size = kind === "text" && objectKey ? declaredSize : kind === "text" ? Buffer.byteLength(text) : kind === "image" ? image.length : declaredSize;
  if (size < 1 || size > MAX_ATTACHMENT_BYTES_PER_FILE) fail("Allegato non valido.");
  return { kind, filename, mediaType, size, sha256, objectKey, text: kind === "text" ? text : null, image: kind === "image" ? image : null, width: kind === "image" ? width : null, height: kind === "image" ? height : null, truncated: value.truncated === true,
    ...(kind === "archive" ? { archive: { entryCount: archive.entryCount, totalUncompressedBytes: archive.totalUncompressedBytes } } : {}),
    ...(kind === "document" ? { document: { format: document.format, extractedBytes: document.extractedBytes, sourceBytes: document.sourceBytes,
      coverage: { state: document.coverage.state, unitsRead: document.coverage.unitsRead, unitsSkipped: document.coverage.unitsSkipped, warnings: [...document.coverage.warnings] } } } : {}) };
}

function normalizeCursorTimestamp(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 || !CURSOR_TIMESTAMP_RE.test(value) || !Number.isFinite(Date.parse(value))) {
    fail("Cursore conversazioni non valido.");
  }
  return value;
}

export function encodeConversationCursor(updatedAt, id) {
  const timestamp = updatedAt instanceof Date ? updatedAt.toISOString() : updatedAt;
  const value = JSON.stringify({ updatedAt: normalizeCursorTimestamp(timestamp), id: normalizeConversationId(id) });
  const encoded = Buffer.from(value, "utf8").toString("base64url");
  if (encoded.length > MAX_CURSOR_BYTES) fail("Cursore conversazioni troppo grande.");
  return encoded;
}

export function decodeConversationCursor(cursor) {
  if (typeof cursor !== "string" || cursor.length === 0 || cursor.length > MAX_CURSOR_BYTES || !/^[A-Za-z0-9_-]+$/.test(cursor)) {
    fail("Cursore conversazioni non valido.");
  }
  let decoded;
  try {
    const bytes = Buffer.from(cursor, "base64url");
    if (bytes.length === 0 || bytes.toString("base64url") !== cursor) fail("Cursore conversazioni non valido.");
    decoded = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("Cursore conversazioni non valido.");
  }
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)
    || Object.keys(decoded).length !== 2 || !Object.hasOwn(decoded, "updatedAt") || !Object.hasOwn(decoded, "id")) {
    fail("Cursore conversazioni non valido.");
  }
  return { updatedAt: normalizeCursorTimestamp(decoded.updatedAt), id: normalizeConversationId(decoded.id) };
}

function normalizeListLimit(value, fallback = 50) {
  if (value == null) return fallback;
  if (typeof value !== "number" && typeof value !== "string") fail("Limite conversazioni non valido.");
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_LIST_LIMIT) fail("Limite conversazioni non valido.");
  return count;
}

export function normalizeMode(value, { allowNull = false } = {}) {
  if (allowNull && value == null) return null;
  if (!CONVERSATION_MODES.includes(value)) fail("Modalità conversazione non valida.");
  return value;
}

export function normalizeResolvedMode(value) {
  if (!RESOLVED_MODES.includes(value)) fail("Modalità risolta non valida.");
  return value;
}

export function normalizeGenerationStatus(value) {
  if (!GENERATION_STATUSES.includes(value)) fail("Stato generazione non valido.");
  return value;
}

export function normalizeContent(value) { return assertText(value, "Contenuto", MAX_CONTENT); }

export function normalizeQueueDelivery(value, { allowDefault = true } = {}) {
  if (value == null && allowDefault) return "queue";
  if (value !== "queue" && value !== "immediate") fail("Consegna messaggio non valida.");
  return value;
}

function normalizeRequestId(value) {
  if (!UUID_RE.test(String(value || ""))) fail("Identificativo richiesta non valido.");
  return String(value).toLowerCase();
}

function queueRow(row) {
  return {
    id: row.id, requestId: row.request_id, conversationId: row.conversation_id,
    message: row.message, requestedMode: row.requested_mode,
    attachmentIds: Array.isArray(row.attachment_ids) ? row.attachment_ids : [],
    delivery: row.delivery, status: row.status, position: Number(row.position || 0),
    turnId: row.turn_id || null, errorCode: row.error_code || row.errorCode || null, createdAt: row.created_at, startedAt: row.started_at || null,
  };
}

const BRIEF_AFFIRMATIONS = new Set(["sì", "si", "ok", "okay", "va bene", "procedi", "continua", "certo", "confermo", "fallo", "fai pure", "sì procedi", "si procedi", "si grazie", "sì grazie", "ok procedi", "ok grazie"]);

// A confirmation is deliberately narrow: it may continue only the immediately
// preceding completed user/assistant pair already owned by this conversation.
// It does not infer a new task, project, permission, or web request.
export function isBriefAffirmation(value) {
  if (typeof value !== "string" || Buffer.byteLength(value) > 80) return false;
  const normalized = value.trim().toLocaleLowerCase("it-IT").replace(/[.!?…]+$/u, "").replace(/[,;:]+/g, " ").replace(/\s+/g, " ");
  if (BRIEF_AFFIRMATIONS.has(normalized)) return true;
  // Natural confirmations may add only a courtesy, a request to proceed with
  // the already named check, or a language reminder. Any new task words fail
  // closed and require a fresh user request instead of inferred permissions.
  return /^(?:sì|si|ok|okay|certo|va bene)(?:\s+(?:procedi|continua|pure|grazie|con questo controllo|con il controllo|resta in italiano|in italiano|e))*$/u.test(normalized);
}

function continuationAnchor(messages, currentMessage) {
  if (!isBriefAffirmation(currentMessage) || !Array.isArray(messages) || messages.length < 2) return null;
  const assistant = messages.at(-1);
  const user = messages.at(-2);
  if (assistant?.role !== "assistant" || user?.role !== "user" || typeof user.content !== "string" || !user.content.trim()
    || typeof assistant.content !== "string" || !assistant.content.trim()) return null;
  // Consecutive confirmations are not a useful semantic query. Walk back to
  // the most recent substantive user topic, while the immediate pair remains
  // the only proposal the model may continue.
  const topic = [...messages.slice(0, -1)].reverse().find(item => item?.role === "user" && !isBriefAffirmation(item.content));
  if (!topic?.content?.trim()) return null;
  return Object.freeze({
    // Used only as a bounded semantic-retrieval topic. The full pair remains
    // in the trusted recent history sent to the model.
    query: topic.content.slice(0, 4096),
    resolvedMode: assistant.resolvedMode === "deep" ? "deep" : "fast",
  });
}

function utf8Prefix(value, maxBytes) {
  let used = 0; let result = "";
  for (const character of String(value || "")) {
    const size = Buffer.byteLength(character);
    if (used + size > maxBytes) break;
    result += character; used += size;
  }
  return result;
}

function utf8Suffix(value, maxBytes) {
  let used = 0; const characters = [];
  for (const character of Array.from(String(value || "")).reverse()) {
    const size = Buffer.byteLength(character);
    if (used + size > maxBytes) break;
    characters.push(character); used += size;
  }
  return characters.reverse().join("");
}

function clipContextContent(value, maxBytes = MAX_CONTEXT_MESSAGE_BYTES) {
  const text = String(value || "");
  if (Buffer.byteLength(text) <= maxBytes) return text;
  const marker = "\n[Messaggio precedente abbreviato per il limite di contesto]\n";
  const available = maxBytes - Buffer.byteLength(marker);
  if (available < 2) return utf8Prefix(text, maxBytes);
  const headBytes = Math.floor(available / 2);
  const tailBytes = available - headBytes;
  return `${utf8Prefix(text, headBytes)}${marker}${utf8Suffix(text, tailBytes)}`;
}

function clipContextContentAroundMatch(value, terms, maxBytes = MAX_CONTEXT_MESSAGE_BYTES) {
  const text = String(value || "");
  if (Buffer.byteLength(text) <= maxBytes) return text;
  const lower = text.toLocaleLowerCase("it-IT");
  const hit = (terms || []).map(term => lower.indexOf(term)).filter(index => index >= 0).sort((left, right) => left - right)[0];
  if (hit === undefined) return clipContextContent(text, maxBytes);
  const marker = "\n[Passaggio storico abbreviato attorno al termine rilevante]\n";
  const room = maxBytes - Buffer.byteLength(marker);
  if (room < 2) return utf8Prefix(text, maxBytes);
  const prefixRoom = Math.floor(room / 3);
  const before = utf8Suffix(text.slice(0, hit), prefixRoom);
  const after = utf8Prefix(text.slice(hit), room - Buffer.byteLength(before));
  return `${before}${marker}${after}`;
}

function boundedRecentContext(stored, current, messageLimit, charLimit, anchor) {
  // `stored` has already been selected across the complete conversation. Do
  // not slice it again here: doing so would silently discard a relevant old
  // constraint returned by the bounded SQL/in-memory selection.
  const terms = historySearchTerms(current);
  const entries = stored.slice(-(Math.max(0, messageLimit - 1))).map((item, index) => ({
    role: item.role,
    content: clipContextContentAroundMatch(item.content, terms),
    // SQL assigns 1 to initial/relevant items and 3 to ordinary recency. A
    // missing value keeps compatibility with older fixtures.
    contextPriority: Number.isInteger(item.contextPriority) ? item.contextPriority : 2,
    ordinal: Number.isFinite(Number(item.ordinal)) ? Number(item.ordinal) : index,
  }));
  const currentBytes = Buffer.byteLength(JSON.stringify({ role: "user", content: current }));
  const historyBudget = Math.max(0, charLimit - currentBytes);
  const contextBytes = () => Buffer.byteLength(JSON.stringify(entries));
  // Protect the immediate pair for every follow-up, not just confirmations.
  // The service additionally pins it during final prompt assembly.
  const protectedOrdinals = new Set(entries.slice(-2).map(item => item.ordinal));
  while (contextBytes() > historyBudget && entries.length > 0) {
    const candidates = entries.filter(item => !protectedOrdinals.has(item.ordinal));
    const removable = (candidates.length ? candidates : entries)
      .sort((left, right) => right.contextPriority - left.contextPriority || left.ordinal - right.ordinal)[0];
    const index = entries.indexOf(removable);
    if (index < 0) break;
    entries.splice(index, 1);
  }
  return [...entries.map(({ role, content }) => ({ role, content })), { role: "user", content: current }];
}

// Assistant output may legitimately be empty while a durable turn is pending,
// streaming, aborted, or failed. Preserve it verbatim: trimming would corrupt
// incremental Markdown/code output, while the existing byte cap bounds storage.
export function normalizeAssistantContent(value) {
  if (typeof value !== "string" || value.length > MAX_CONTENT) fail("Contenuto non valido.");
  return value;
}

function jsonBytes(value) { return Buffer.byteLength(JSON.stringify(value)); }

const FORBIDDEN_METADATA_KEY = /secret|password|token|authorization|cookie|credential|private|cipher|raw|body|html|page|prompt|think|thought|reasoning/i;
function scrubMetadata(value, depth = 0) {
  if (depth > 5) return "[depth limit]";
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.slice(0, 4096);
  if (Array.isArray(value)) return value.slice(0, 64).map(entry => scrubMetadata(entry, depth + 1));
  if (typeof value === "object") return Object.fromEntries(
    Object.entries(value).filter(([key]) => !FORBIDDEN_METADATA_KEY.test(key)).slice(0, 64)
      .map(([key, entry]) => [key, scrubMetadata(entry, depth + 1)]),
  );
  return null;
}

function safeJson(value, label, fallback) {
  if (value == null) return fallback;
  if (typeof value !== "object" || (label !== "Fonti" && Array.isArray(value)) || (label === "Fonti" && !Array.isArray(value))) fail(`${label} non valido.`);
  const clean = scrubMetadata(value);
  if (jsonBytes(clean) > MAX_METADATA_BYTES) fail(`${label} troppo grande.`);
  return clean;
}

export function normalizeMetadata(value = {}) { return safeJson(value, "Metadata", {}); }
export function normalizeSources(value = []) {
  if (!Array.isArray(value)) fail("Fonti non valide.");
  return value.slice(0, 24).flatMap(source => {
    if (!source || typeof source !== "object" || Array.isArray(source)) return [];
    if (source.type === "project") {
      const id = typeof source.id === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(source.id) ? source.id : "";
      const projectId = typeof source.projectId === "string" && PROJECT_ID_RE.test(source.projectId) ? source.projectId : "";
      const kind = ["file", "git", "database"].includes(source.kind) ? source.kind : "";
      const sha256 = typeof source.sha256 === "string" && /^[a-f0-9]{64}$/i.test(source.sha256) ? source.sha256.toLowerCase() : "";
      const path = typeof source.path === "string" && source.path.length <= 512 && !source.path.startsWith("/") && !source.path.includes("..") ? source.path : "";
      const startLine = Number.isInteger(source.startLine) && source.startLine > 0 && source.startLine <= 1_000_000 ? source.startLine : null;
      const endLine = Number.isInteger(source.endLine) && startLine && source.endLine >= startLine && source.endLine <= 1_000_000 ? source.endLine : null;
      if (!id || !projectId || !kind || !sha256 || (kind === "file" && (!path || !startLine || !endLine))) return [];
      const databaseId = kind === "database" && typeof source.databaseId === "string" && /^[a-z0-9][a-z0-9-]{0,95}$/.test(source.databaseId) ? source.databaseId : undefined;
      const dialect = databaseId && ["postgresql", "mariadb"].includes(source.dialect) ? source.dialect : undefined;
      const operation = databaseId && dialect && ["schema", "query", "explain"].includes(source.operation) ? source.operation : undefined;
      return [{ id, type: "project", projectId, kind, title: String(source.title || path || kind).slice(0, 300), path, startLine, endLine, sha256, ...(databaseId && dialect ? { databaseId, dialect, ...(operation ? { operation } : {}) } : {}) }];
    }
    let url;
    try { url = new URL(source.url); } catch { return []; }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.href.length > 2048) return [];
    if ([...url.searchParams.keys()].some(key => /password|passwd|token|secret|signature|credential|api[_-]?key|session|^(?:sig|key)$/i.test(key))) return [];
    const fetchedAt = typeof source.fetchedAt === "string" && Number.isFinite(Date.parse(source.fetchedAt)) ? source.fetchedAt : undefined;
    return [{ id: String(source.id || "").slice(0, 64), title: String(source.title || url.hostname).slice(0, 300), url: url.href, domain: url.hostname, ...(fetchedAt ? { fetchedAt } : {}) }];
  });
}
export function normalizeToolMetadata(value = {}) {
  const clean = safeJson(value, "Metadati tool", {});
  if (!clean || typeof clean !== "object" || Array.isArray(clean)) return {};
  // Durable activity records are server-generated summaries. Keep only their
  // public scalar fields; never let an accidental tool argument/result become
  // visible on a later page reload.
  if (Array.isArray(clean.tools)) {
    clean.tools = clean.tools.slice(0, 24).flatMap(tool => {
      if (!tool || typeof tool !== "object" || Array.isArray(tool)) return [];
      const name = typeof tool.name === "string" && /^[A-Za-z][A-Za-z0-9]{0,95}$/.test(tool.name) ? tool.name : "";
      const label = typeof tool.label === "string" ? tool.label.slice(0, 120) : "";
      const target = typeof tool.target === "string" ? tool.target.slice(0, 256) : "";
      const summary = typeof tool.summary === "string" ? tool.summary.slice(0, 256) : "";
      const outcome = tool.outcome === "success" || tool.outcome === "unavailable" ? tool.outcome : undefined;
      const resultCount = Number.isSafeInteger(tool.resultCount) && tool.resultCount >= 0 && tool.resultCount <= 10_000 ? tool.resultCount : undefined;
      if (!name) return [];
      return [{ name, ...(label ? { label } : {}), ...(target ? { target } : {}), ...(summary ? { summary } : {}), ...(outcome ? { outcome } : {}), ...(resultCount !== undefined ? { resultCount } : {}) }];
    });
  }
  if (Array.isArray(clean.summarySteps)) clean.summarySteps = [...new Set(clean.summarySteps
    .filter(step => typeof step === "string" && step.length > 0).map(step => step.slice(0, 240)))].slice(-8);
  if (Object.hasOwn(clean, "analysisSummary")) {
    clean.analysisSummary = normalizeAnalysisSummary(clean.analysisSummary, { truncate: true });
    if (!clean.analysisSummary) delete clean.analysisSummary;
  }
  if (typeof clean.state === "string" && !["queued", "preparing", "thinking", "tools", "summarizing", "responding"].includes(clean.state)) delete clean.state;
  return clean;
}

function normalizeTurnId(value) { return normalizeConversationId(value); }

export function deriveConversationTitle(content) {
  const clean = normalizeContent(content)
    .replace(/[`*_>#]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/[.!?]+$/, "");
  if (!clean) return "Nuova chat";
  if (clean.length <= MAX_TITLE) return clean;
  const words = clean.split(" ");
  let title = "";
  for (const word of words) {
    const next = title ? `${title} ${word}` : word;
    if (next.length > MAX_TITLE - 1) break;
    title = next;
  }
  return `${title || clean.slice(0, MAX_TITLE - 1)}…`;
}

export function normalizeTitle(value) {
  const title = assertText(value, "Titolo", MAX_TITLE).replace(/\s+/g, " ").trim();
  return title || "Nuova chat";
}

const SUMMARY_HEADERS = Object.freeze({
  goal: "[Obiettivo iniziale]",
  commitments: "[Vincoli e consensi]",
  matches: "[Passaggi rilevanti]",
  recent: "[Memoria recente]",
});
const SUMMARY_COMMITMENT = /\b(?:non|solo|sempre|mai|evita|mantieni|senza|deve|devono|voglio|consento|autorizzo|confermo|procedi|continua|puoi|fermati|annulla|interrompi|revoco|lascia perdere|correzione|cambio|cambia|invece)\b/iu;
const SUMMARY_REVOCATION = /(?:\b(?:fermati|annulla|interrompi|revoco|lascia perdere|correzione|cambio|cambia|invece)\b|\bnon\s+procedere\b)/iu;

function isScopedCommitment(value) {
  // One-word quick replies are scoped only to the immediately preceding
  // proposal. Keep them in durable history, but do not turn them into a
  // timeless authorization after the subject changes.
  return !isBriefAffirmation(value) && SUMMARY_COMMITMENT.test(value);
}

function summaryExcerpt(content, role) {
  const text = typeof content === "string" && content.length <= MAX_CONTENT ? content.trim() : normalizeContent(content);
  // Code, raw logs and fetched pages remain in the durable transcript. A
  // deterministic index records only the conversational intent/evidence.
  const withoutCode = text.replace(/```[\s\S]*?(?:```|$)/g, " [blocco codice nella cronologia] ");
  const lines = withoutCode.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const selected = [...lines.slice(0, 2), ...lines.slice(2).filter(line => /error|fatal|exception|causa|conclus|risultat|container|verifica|vincolo|consens|autorizz|https?:\/\//i.test(line)).slice(0, 3)];
  return clipContextContent(selected.join(" ").replace(/\s+/g, " ") || "(nessun contenuto)", role === "user" ? 560 : 720);
}

function parseSummary(previous) {
  const empty = { goal: "", commitments: [], matches: [], recent: [] };
  const value = typeof previous === "string" ? previous.trim() : "";
  if (!value) return empty;
  const sections = { ...empty };
  let target = null;
  for (const line of value.split(/\r?\n/)) {
    if (line === SUMMARY_HEADERS.goal) { target = "goal"; continue; }
    if (line === SUMMARY_HEADERS.commitments) { target = "commitments"; continue; }
    if (line === SUMMARY_HEADERS.matches) { target = "matches"; continue; }
    if (line === SUMMARY_HEADERS.recent) { target = "recent"; continue; }
    if (!target || !line.trim()) continue;
    if (target === "goal" && !sections.goal) sections.goal = line.replace(/^Utente:\s*/u, "").trim();
    else if (target === "commitments") sections.commitments.push(line);
    else if (target === "matches") sections.matches.push(line);
    else if (target === "recent") sections.recent.push(line);
  }
  // Migration-safe fallback for summaries written before the structured form.
  if (!sections.goal) {
    const old = value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const firstUser = old.find(line => /^Utente:/u.test(line));
    sections.goal = (firstUser || old[0] || "").replace(/^Utente:\s*/u, "");
    sections.recent = old.slice(-8);
  }
  return sections;
}

function uniqueTail(values, value, limit) {
  const clean = typeof value === "string" ? value.trim() : "";
  if (!clean) return values.slice(-limit);
  const normalized = clean.toLocaleLowerCase("it-IT");
  const withoutSame = values.filter(item => item.toLocaleLowerCase("it-IT") !== normalized);
  return [...withoutSame, clean].slice(-limit);
}

function formatSummary({ goal, commitments, matches = [], recent }, maxBytes = MAX_CONTEXT_SUMMARY_BYTES) {
  const sections = {
    goal: goal ? utf8Prefix(goal, 1_400) : "",
    commitments: commitments.slice(-10).map(item => utf8Prefix(item, 620)),
    matches: matches.slice(-6).map(item => utf8Prefix(item, 720)),
    recent: recent.slice(-10).map(item => utf8Prefix(item, 760)),
  };
  const render = () => [
    SUMMARY_HEADERS.goal,
    sections.goal ? `Utente: ${sections.goal}` : "(non ancora definito)",
    SUMMARY_HEADERS.commitments,
    ...(sections.commitments.length ? sections.commitments : ["(nessun vincolo o consenso sintetizzato)"]),
    SUMMARY_HEADERS.matches,
    ...(sections.matches.length ? sections.matches : ["(nessun passaggio storico selezionato per questa richiesta)"]),
    SUMMARY_HEADERS.recent,
    ...(sections.recent.length ? sections.recent : ["(nessun passaggio completato)"]),
  ].join("\n");
  // Prefer keeping the initial goal and the most recent relevant evidence.
  // Older routine entries are the first expendable material, never code/raw
  // tool output because those are not inserted into this summary at all.
  while (Buffer.byteLength(render()) > maxBytes && sections.recent.length > 1) sections.recent.shift();
  while (Buffer.byteLength(render()) > maxBytes && sections.matches.length > 1) sections.matches.shift();
  // `shift()` preserves the most recent correction/revocation, which takes
  // precedence over an older consent when only a compact summary fits.
  while (Buffer.byteLength(render()) > maxBytes && sections.commitments.length > 1) sections.commitments.shift();
  if (Buffer.byteLength(render()) > maxBytes) sections.goal = utf8Prefix(sections.goal, Math.max(96, Math.floor(maxBytes / 4)));
  return utf8Prefix(render(), maxBytes);
}

// Service-side prompt fitting must never use a generic prefix of this ordered
// document: that would keep an old goal while cutting a later correction. The
// helper is pure and UTF-8-safe so the service can invoke it repeatedly during
// its existing binary context-budget search.
function tailEntriesWithinBytes(entries, maxBytes) {
  const kept = [];
  let used = 0;
  for (const entry of [...entries].reverse()) {
    const bytes = Buffer.byteLength(entry);
    if (used + bytes <= maxBytes) { kept.push(entry); used += bytes; continue; }
    if (kept.length === 0 && maxBytes >= 96) kept.push(clipContextContent(entry, maxBytes));
    break;
  }
  return kept.reverse();
}

export function compactConversationSummary(value, maxBytes = MAX_CONTEXT_SUMMARY_BYTES) {
  const limit = Number.isSafeInteger(maxBytes) ? Math.max(0, Math.min(MAX_CONTEXT_SUMMARY_BYTES, maxBytes)) : MAX_CONTEXT_SUMMARY_BYTES;
  // Do not return a misleading fragment of the sectioned record. The service
  // treats an empty optional block as unavailable and keeps the real messages.
  if (limit < 320) return "";
  const sections = parseSummary(value);
  // Keep a balanced, explicit account even under the real 32-tool FAST
  // budget: initial goal, latest corrections/consents in chronological order,
  // query-selected remote evidence, then a small recent tail.
  const usable = Math.max(0, limit - 260);
  const compact = {
    goal: clipContextContent(sections.goal, Math.max(96, Math.floor(usable * 0.20))),
    commitments: tailEntriesWithinBytes(sections.commitments, Math.floor(usable * 0.40)),
    matches: tailEntriesWithinBytes(sections.matches, Math.floor(usable * 0.35)),
    recent: tailEntriesWithinBytes(sections.recent, Math.floor(usable * 0.05)),
  };
  return formatSummary(compact, limit);
}

export function appendDeterministicSummary(previous, { role, content, generationStatus = "completed" }) {
  if (role === "assistant" && generationStatus !== "completed") return typeof previous === "string" ? previous : "";
  const sections = parseSummary(previous);
  const excerpt = summaryExcerpt(content, role);
  const entry = `${role === "user" ? "Utente" : "Assistente"}: ${excerpt}`;
  if (role === "user" && !sections.goal) sections.goal = excerpt;
  if (role === "user" && SUMMARY_REVOCATION.test(excerpt)) {
    // Keep independent constraints: a lexical "non" or "cambia" cannot tell
    // us deterministically which prior rule it edits. The explicit, later
    // marker makes the correction authoritative without deleting unrelated
    // durable commitments.
    sections.commitments = uniqueTail(sections.commitments, `Utente: Revoca o correzione attuale (prevale solo sul punto pertinente): ${excerpt}`, 10);
  } else if (role === "user" && isScopedCommitment(excerpt)) {
    sections.commitments = uniqueTail(sections.commitments, entry, 10);
  }
  sections.recent = uniqueTail(sections.recent, entry, 10);
  return formatSummary(sections);
}

function summaryForContext(summary, stored, current) {
  const sections = parseSummary(summary);
  // Legacy rolling summaries may have already dropped the true first request.
  // The bounded initial rows are authoritative and restore it without a data
  // migration or an extra model call.
  if (!String(summary || "").includes(SUMMARY_HEADERS.goal)) {
    const firstUser = stored.find(item => item.role === "user" && item.content.trim());
    if (firstUser) sections.goal = summaryExcerpt(firstUser.content, "user");
  }
  const terms = historySearchTerms(current);
  if (!terms.length) return formatSummary(sections);
  const lastRevocationOrdinal = stored.filter(item => item.role === "user" && SUMMARY_REVOCATION.test(item.content)).at(-1)?.ordinal;
  const relevant = stored.map(item => ({
    item,
    score: terms.reduce((count, term) => count + (item.content.toLocaleLowerCase("it-IT").includes(term) ? 1 : 0), 0),
  })).filter(({ item, score }) => score > 0
    && !(lastRevocationOrdinal != null && item.role === "user" && isScopedCommitment(item.content) && Number(item.ordinal) < Number(lastRevocationOrdinal)))
    .sort((left, right) => right.score - left.score || Number(right.item.ordinal) - Number(left.item.ordinal))
    .slice(0, RELEVANT_CONTEXT_MESSAGES)
    .sort((left, right) => Number(left.item.ordinal) - Number(right.item.ordinal))
    .map(({ item }) => `${item.role === "user" ? "Utente" : "Assistente"}: ${summaryExcerpt(clipContextContentAroundMatch(item.content, terms, item.role === "user" ? 560 : 720), item.role)}`);
  sections.matches = [...new Set(relevant)].slice(-RELEVANT_CONTEXT_MESSAGES);
  return formatSummary(sections);
}

const HISTORY_STOP_WORDS = new Set([
  "anche", "ancora", "avere", "come", "con", "cosa", "dalla", "delle", "della", "dopo", "essere", "fare", "fatto", "grazie", "italiano", "nella", "nelle", "nello", "non", "per", "prima", "procedi", "questo", "quella", "quello", "resta", "risposta", "sulla", "sulle", "sullo", "tutto", "una", "uno", "user", "utente", "verifica", "voglio", "sono", "stato", "stesso", "continua", "controllo", "sì", "si", "ok",
]);

function historySearchTerms(value) {
  if (typeof value !== "string") return [];
  const terms = value.toLocaleLowerCase("it-IT").match(/[\p{L}\p{N}_./:-]{3,63}/gu) || [];
  return [...new Set(terms.filter(term => !HISTORY_STOP_WORDS.has(term)))].slice(0, 8);
}

function historySearchPatterns(value) {
  return historySearchTerms(value).map(term => `%${term.replace(/[\\_%]/g, "\\$&")}%`);
}

function isHistoricalCommitment(item) {
  return item?.role === "user" && typeof item.content === "string" && isScopedCommitment(item.content);
}

function selectHistoricalMessages(rows, currentMessage, { limit = DEFAULT_CONTEXT_MESSAGE_LIMIT } = {}) {
  const complete = rows.filter(item => item && ["user", "assistant"].includes(item.role) && typeof item.content === "string");
  const terms = historySearchTerms(currentMessage);
  const score = item => terms.reduce((count, term) => count + (item.content.toLocaleLowerCase("it-IT").includes(term) ? 1 : 0), 0);
  const selected = new Map();
  const add = (index, priority) => {
    const item = complete[index];
    if (!item) return;
    const existing = selected.get(index);
    selected.set(index, { ...item, contextPriority: Math.min(existing?.contextPriority ?? priority, priority) });
  };
  complete.slice(0, INITIAL_CONTEXT_MESSAGES).forEach((_, index) => add(index, 1));
  complete.slice(-RECENT_CONTEXT_MESSAGES).forEach((_, index) => add(Math.max(0, complete.length - RECENT_CONTEXT_MESSAGES) + index, 3));
  complete.filter(isHistoricalCommitment).slice(-COMMITMENT_CONTEXT_MESSAGES).forEach(item => add(complete.indexOf(item), 2));
  const relevant = complete.map((item, index) => ({ index, score: score(item) }))
    .filter(item => item.score > 0).sort((left, right) => right.score - left.score || right.index - left.index)
    .slice(0, RELEVANT_CONTEXT_MESSAGES);
  for (const item of relevant) {
    add(item.index - 1, 1); add(item.index, 1); add(item.index + 1, 1);
  }
  return [...selected.entries()].sort(([left], [right]) => left - right).map(([, item]) => item).slice(-limit);
}

function rowConversation(row) {
  return {
    id: row.id,
    ownerId: row.owner_id,
    machineId: row.machine_id,
    projectId: row.project_id || null,
    title: row.title,
    summary: row.summary || "",
    metadata: row.metadata || {},
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    archivedAt: row.archived_at || null,
  };
}

function rowMessage(row) {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    role: row.role,
    content: row.content,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    requestedMode: row.requested_mode || null,
    resolvedMode: row.resolved_mode || null,
    model: row.model || null,
    generationStatus: row.generation_status,
    sources: row.source_metadata || [],
    toolMetadata: row.tool_metadata || {},
  };
}

function ensureResult(result) {
  if (!result || !Array.isArray(result.rows)) throw new ConversationStoreError("Archivio conversazioni non disponibile.");
  return result;
}

export class PostgresConversationStore {
  constructor({ pool, clock = () => new Date(), contextMessageLimit = DEFAULT_CONTEXT_MESSAGE_LIMIT, contextCharLimit = MAX_CONTEXT_CHARS, attachmentStorage = null, artifactStorage = null } = {}) {
    if (!pool || typeof pool.query !== "function") throw new TypeError("Conversation store requires a PostgreSQL pool.");
    this.pool = pool;
    this.clock = clock;
    this.contextMessageLimit = Math.max(1, Math.min(DEFAULT_CONTEXT_MESSAGE_LIMIT, Number(contextMessageLimit) || DEFAULT_CONTEXT_MESSAGE_LIMIT));
    this.contextCharLimit = Math.max(4_000, Math.min(MAX_CONTEXT_CHARS, Number(contextCharLimit) || MAX_CONTEXT_CHARS));
    this.attachmentStorage = attachmentStorage;
    this.artifactStorage = artifactStorage;
  }

  async ready() {
    const result = ensureResult(await this.pool.query(
      `select to_regclass('server_ai.conversations') as conversations,
              to_regclass('server_ai.messages') as messages,
              to_regclass('server_ai.attachments') as attachments,
              to_regclass('server_ai.conversation_queue') as conversation_queue`,
    ));
    const row = result.rows[0] || {};
    if (!row.conversations || !row.messages || !row.attachments || !row.conversation_queue) throw new ConversationStoreError("Migration Server AI conversazioni non applicata.");
    if (this.artifactStorage) {
      if (typeof this.artifactStorage.ready === "function") await this.artifactStorage.ready();
      const artifacts = ensureResult(await this.pool.query("select to_regclass('server_ai.artifacts') as artifacts"));
      if (!artifacts.rows[0]?.artifacts) throw new ConversationStoreError("Migration Server AI artefatti non applicata.");
      await this.cleanupDeletedArtifacts();
    }
    await this.cleanupDeletedAttachmentObjects();
    return { ready: true };
  }

  async cleanupDeletedAttachmentObjects() {
    if (!this.attachmentStorage || typeof this.attachmentStorage.removeObject !== "function") return 0;
    let rows;
    try {
      rows = ensureResult(await this.pool.query(
        `select object_key from server_ai.attachments
          where deleted_at is not null and object_key is not null
          order by deleted_at asc limit 32`,
      )).rows;
    } catch { return 0; }
    let removed = 0;
    for (const row of rows) {
      if (!UUID_RE.test(row.object_key || "")) continue;
      try {
        await this.attachmentStorage.removeObject(row.object_key);
        await this.pool.query("update server_ai.attachments set object_key=null where object_key=$1 and deleted_at is not null", [row.object_key]);
        removed += 1;
      } catch {}
    }
    return removed;
  }

  async cleanupDeletedArtifacts() {
    if (!this.artifactStorage || typeof this.artifactStorage.remove !== "function") return 0;
    let rows;
    try {
      rows = ensureResult(await this.pool.query(
        `select id, object_key, owner_id, machine_id, conversation_id from server_ai.artifacts
          where deleted_at is not null and object_key is not null order by deleted_at asc limit 32`,
      )).rows;
    } catch { return 0; }
    let removed = 0;
    for (const row of rows) {
      try { await this.artifactStorage.remove({ ownerId: row.owner_id, machineId: row.machine_id, conversationId: row.conversation_id }, row.id); } catch {}
      try { await this.pool.query("update server_ai.artifacts set object_key=null where id=$1 and deleted_at is not null", [row.id]); removed += 1; } catch {}
    }
    return removed;
  }

  async withTransaction(fn) {
    const client = typeof this.pool.connect === "function" ? await this.pool.connect() : this.pool;
    const owned = client !== this.pool;
    try {
      if (typeof client.query !== "function") throw new ConversationStoreError("Client PostgreSQL non valido.");
      await client.query("begin");
      const value = await fn(client);
      await client.query("commit");
      return value;
    } catch (error) {
      try { await client.query("rollback"); } catch {}
      throw error;
    } finally {
      if (owned && typeof client.release === "function") client.release();
    }
  }

  async create({ ownerId, subject, machineId, projectId = null, title = "Nuova chat", metadata = {} }) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const project = normalizeProjectId(projectId);
    const cleanTitle = normalizeTitle(title);
    const safeMetadata = normalizeMetadata(metadata);
    const id = randomUUID();
    const result = ensureResult(await this.pool.query(
      `insert into server_ai.conversations
       (id, owner_id, machine_id, project_id, title, metadata)
       values ($1, $2, $3, $4, $5, $6::jsonb)
       returning id, owner_id, machine_id, project_id, title, summary, metadata, created_at, updated_at, archived_at`,
      [id, owner, machine, project, cleanTitle, JSON.stringify(safeMetadata)],
    ));
    return rowConversation(result.rows[0]);
  }

  async listPage({ ownerId, subject, machineId, limit = 50, cursor = null } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const count = normalizeListLimit(limit);
    const keyset = cursor == null ? null : decodeConversationCursor(cursor);
    const result = ensureResult(await this.pool.query(
      `select id, owner_id, machine_id, project_id, title, summary, metadata, created_at, updated_at, archived_at,
              updated_at::text as _conversation_cursor_updated_at
       from server_ai.conversations
       where owner_id=$1 and machine_id=$2 and deleted_at is null
         and ($3::timestamptz is null or updated_at < $3::timestamptz
           or (updated_at = $3::timestamptz and id < $4::uuid))
       order by updated_at desc, id desc limit $5`,
      [owner, machine, keyset?.updatedAt || null, keyset?.id || null, count + 1],
    ));
    const hasNext = result.rows.length > count;
    const rows = result.rows.slice(0, count);
    const last = rows.at(-1);
    return {
      conversations: rows.map(rowConversation),
      nextCursor: hasNext && last ? encodeConversationCursor(last._conversation_cursor_updated_at || last.updated_at, last.id) : null,
    };
  }

  async list(args = {}) {
    return (await this.listPage(args)).conversations;
  }

  async get({ ownerId, subject, machineId, conversationId, limit = 200, before = null } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const id = normalizeConversationId(conversationId);
    const conversationResult = ensureResult(await this.pool.query(
      `select id, owner_id, machine_id, project_id, title, summary, metadata, created_at, updated_at, archived_at
       from server_ai.conversations
       where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null`,
      [id, owner, machine],
    ));
    if (!conversationResult.rows[0]) return null;
    const messageLimit = Math.max(1, Math.min(200, Number(limit) || 200));
    if (before != null && !/^\d+$/.test(String(before))) fail("Cursore conversazione non valido.");
    const messageResult = ensureResult(await this.pool.query(
      `select m.id, m.conversation_id, m.role, m.content, m.created_at, m.updated_at,
              m.requested_mode, m.resolved_mode, m.model, m.generation_status,
              m.source_metadata, m.tool_metadata, m.ordinal
       from server_ai.messages m
       join server_ai.conversations c on c.id=m.conversation_id
       where m.conversation_id=$1 and c.id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null
       ${before == null ? "" : "and m.ordinal < $4"}
       order by m.ordinal desc limit $${before == null ? 4 : 5}`,
      before == null ? [id, owner, machine, messageLimit] : [id, owner, machine, String(before), messageLimit],
    ));
    const messages = [...messageResult.rows].reverse();
    const messageIds = messages.map(row => row.id);
    const attachmentResult = messageIds.length === 0 ? { rows: [] } : ensureResult(await this.pool.query(
      `select a.id, a.message_id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.archive_metadata, a.document_metadata
         from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
        where a.conversation_id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null
          and a.deleted_at is null and a.message_id = any($4::uuid[])
        order by a.created_at asc, a.id asc`, [id, owner, machine, messageIds],
    ));
    const attachmentsByMessage = new Map();
    for (const attachment of attachmentResult.rows) {
      const values = attachmentsByMessage.get(attachment.message_id) || [];
      values.push(attachmentMetadata(attachment)); attachmentsByMessage.set(attachment.message_id, values);
    }
    const artifactsByMessage = new Map();
    if (this.artifactStorage && messageIds.length) {
      const artifactResult = ensureResult(await this.pool.query(
        `select a.id, a.message_id, a.name, a.kind, a.media_type, a.byte_size, a.sha256, a.metadata, a.created_at
           from server_ai.artifacts a join server_ai.conversations c on c.id=a.conversation_id
          where a.conversation_id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null
            and a.deleted_at is null and a.message_id = any($4::uuid[])
          order by a.created_at asc, a.id asc`, [id, owner, machine, messageIds],
      ));
      for (const artifact of artifactResult.rows) {
        const values = artifactsByMessage.get(artifact.message_id) || [];
        values.push(artifactMetadata(artifact)); artifactsByMessage.set(artifact.message_id, values);
      }
    }
    const queue = await this.listQueue({ ownerId: owner, machineId: machine, conversationId: id });
    return {
      conversation: rowConversation(conversationResult.rows[0]),
      messages: messages.map(row => ({ ...rowMessage(row), attachments: attachmentsByMessage.get(row.id) || [], artifacts: artifactsByMessage.get(row.id) || [] })),
      queue,
      nextBefore: messageResult.rows.length === messageLimit ? String(messages[0].ordinal) : null,
    };
  }

  // A citation can belong to a message outside the paginated transcript. Keep
  // this lookup single-row and bind every part of its durable scope in SQL.
  async getMessage({ ownerId, subject, machineId, conversationId, messageId } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const message = normalizeConversationId(messageId);
    const result = ensureResult(await this.pool.query(
      `select c.id as conversation_id, c.owner_id, c.machine_id, c.project_id, c.title, c.summary, c.metadata, c.created_at as conversation_created_at, c.updated_at as conversation_updated_at, c.archived_at,
              m.id, m.role, m.content, m.created_at, m.updated_at, m.requested_mode, m.resolved_mode, m.model, m.generation_status, m.source_metadata, m.tool_metadata
       from server_ai.messages m
       join server_ai.conversations c on c.id=m.conversation_id
       where m.id=$1 and m.conversation_id=$2 and c.id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null
       limit 1`,
      [message, conversation, owner, machine],
    ));
    const row = result.rows[0];
    if (!row) return null;
    const attachments = ensureResult(await this.pool.query(
      `select a.id, a.message_id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.archive_metadata, a.document_metadata
         from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
        where a.message_id=$1 and a.conversation_id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null
        order by a.created_at asc, a.id asc`, [message, conversation, owner, machine],
    ));
    return {
      conversation: rowConversation({
        id: row.conversation_id, owner_id: row.owner_id, machine_id: row.machine_id, project_id: row.project_id,
        title: row.title, summary: row.summary, metadata: row.metadata, created_at: row.conversation_created_at,
        updated_at: row.conversation_updated_at, archived_at: row.archived_at,
      }),
      message: { ...rowMessage({ ...row, conversation_id: row.conversation_id }), attachments: attachments.rows.map(attachmentMetadata) },
    };
  }

  // Authorization covers the durable transcript, not just the current page:
  // a source cited by an old message stays private after assignment revocation.
  async getProjectIds({ ownerId, subject, machineId, conversationId } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const result = ensureResult(await this.pool.query(
      `with owned_conversation as (
         select id, project_id from server_ai.conversations
          where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null
       ), cited_projects as (
         select distinct source->>'projectId' as project_id
           from server_ai.messages m join owned_conversation c on c.id=m.conversation_id
           cross join lateral jsonb_array_elements(case when jsonb_typeof(m.source_metadata)='array' then m.source_metadata else '[]'::jsonb end) as source
          where source->>'type'='project'
       )
       select project_id from owned_conversation where project_id is not null
       union select project_id from cited_projects where project_id is not null
       limit 65`,
      [conversation, owner, machine],
    ));
    if (result.rows.length > 64) fail("Troppe fonti progetto nella conversazione.");
    return result.rows.map(row => normalizeProjectId(row.project_id, { allowNull: false }));
  }

  async rename({ ownerId, subject, machineId, conversationId, title } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const id = normalizeConversationId(conversationId);
    const cleanTitle = normalizeTitle(title);
    const result = ensureResult(await this.pool.query(
      `update server_ai.conversations
       set title=$1, updated_at=now()
       where id=$2 and owner_id=$3 and machine_id=$4 and deleted_at is null
       returning id, owner_id, machine_id, project_id, title, summary, metadata, created_at, updated_at, archived_at`,
      [cleanTitle, id, owner, machine],
    ));
    if (!result.rows[0]) return null;
    return rowConversation(result.rows[0]);
  }

  async delete({ ownerId, subject, machineId, conversationId } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const id = normalizeConversationId(conversationId);
    const removed = await this.withTransaction(async (client) => {
      const conversationResult = ensureResult(await client.query(
        `select id from server_ai.conversations
         where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`,
        [id, owner, machine],
      ));
      if (!conversationResult.rows[0]) return false;
      const active = ensureResult(await client.query(
        `select id from server_ai.messages m
         where m.conversation_id=$1 and m.role='assistant' and m.generation_status in ('pending','streaming')
           and exists (select 1 from server_ai.conversations c where c.id=m.conversation_id and c.id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null)
         limit 1`,
        [id, owner, machine],
      ));
      if (active.rows[0]) throw new ConversationStoreError("Conversazione in generazione.", 409);
      await client.query(`update server_ai.conversation_queue set status='cancelled',cancelled_at=now(),completed_at=now(),error_code='CONVERSATION_DELETED'
        where conversation_id=$1 and owner_id=$2 and machine_id=$3 and status='queued'`, [id, owner, machine]);
      const scrubbed = ensureResult(await client.query(
        `update server_ai.attachments set deleted_at=now(), text_content=null, image_data=null, archive_metadata=null, document_metadata=null, size=0
         where conversation_id=$1 and deleted_at is null returning object_key`, [id],
      ));
      const artifacts = this.artifactStorage ? ensureResult(await client.query(
        `update server_ai.artifacts set deleted_at=now(), byte_size=0
          where conversation_id=$1 and deleted_at is null returning object_key`, [id],
      )) : { rows: [] };
      const result = ensureResult(await client.query(
        `update server_ai.conversations set deleted_at=now(), updated_at=now()
         where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null
         returning id`,
        [id, owner, machine],
      ));
      return {
        deleted: result.rowCount === 1,
        objectKeys: scrubbed.rows.map(row => row.object_key).filter(value => UUID_RE.test(value || "")),
        artifactKeys: artifacts.rows.map(row => row.object_key).filter(value => UUID_RE.test(value || "")),
      };
    });
    if (removed.deleted) { await this.cleanupDeletedAttachmentObjects(); await this.cleanupDeletedArtifacts(); }
    return removed.deleted === true;
  }

  async appendMessage({ ownerId, subject, machineId, conversationId, role, content, requestedMode = null, resolvedMode = null, model = null, generationStatus = "completed", sources = [], toolMetadata = {} } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    if (!(["user", "assistant"].includes(role))) fail("Ruolo messaggio non valido.");
    if (typeof content !== "string" || content.length > MAX_CONTENT) fail("Contenuto non valido.");
    const text = content;
    const requested = normalizeMode(requestedMode, { allowNull: true });
    const resolved = resolvedMode == null ? null : normalizeResolvedMode(resolvedMode);
    const status = normalizeGenerationStatus(generationStatus);
    if (status === "pending") fail("Lo stato pending si crea solo con beginTurn.");
    const chosenModel = model == null ? null : assertText(model, "Modello", 128);
    if (chosenModel != null && chosenModel !== SERVER_AI_MODEL) fail("Modello non consentito.");
    if (role === "assistant" && chosenModel !== SERVER_AI_MODEL) fail(`Il messaggio assistant richiede ${SERVER_AI_MODEL_LABEL}.`);
    const safeSources = normalizeSources(sources);
    const safeTools = normalizeToolMetadata(toolMetadata);
    const messageId = randomUUID();
    return this.withTransaction(async (client) => {
      const ownerResult = ensureResult(await client.query(
        `select id, title, summary from server_ai.conversations
         where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`,
        [conversation, owner, machine],
      ));
      const current = ownerResult.rows[0];
      if (!current) return null;
      const insertResult = ensureResult(await client.query(
        `insert into server_ai.messages
         (id, conversation_id, role, content, requested_mode, resolved_mode, model, generation_status, source_metadata, tool_metadata)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb)
         returning id, conversation_id, role, content, created_at, updated_at, requested_mode, resolved_mode, model, generation_status, source_metadata, tool_metadata`,
        [messageId, conversation, role, text, requested, resolved, chosenModel, status, JSON.stringify(safeSources), JSON.stringify(safeTools)],
      ));
      const nextSummary = appendDeterministicSummary(current.summary, { role, content: text, generationStatus: status });
      const title = role === "user" && (!current.title || current.title === "Nuova chat") ? deriveConversationTitle(text) : current.title;
      await client.query(
        `update server_ai.conversations set summary=$1, title=$2, updated_at=now()
         where id=$3 and owner_id=$4 and machine_id=$5 and deleted_at is null`,
        [nextSummary, title, conversation, owner, machine],
      );
      return rowMessage(insertResult.rows[0]);
    });
  }

  async createAttachment({ ownerId, subject, machineId, conversationId, attachment, attachmentId = null } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const item = normalizeAttachmentUpload(attachment);
    const id = attachmentId == null ? randomUUID() : normalizeConversationId(attachmentId);
    return this.withTransaction(async (client) => {
      // A transaction-scoped owner lock makes the aggregate quota reliable
      // across concurrent tabs without holding a process-local mutex.
      await client.query("select pg_advisory_xact_lock(hashtextextended($1, 0))", [owner]);
      const current = ensureResult(await client.query(
        `select id from server_ai.conversations where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`,
        [conversation, owner, machine],
      ));
      if (!current.rows[0]) return null;
      const existing = ensureResult(await client.query(
        `select a.id, a.message_id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.sha256, a.object_key, a.archive_metadata, a.document_metadata
           from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
          where a.id=$1 and a.conversation_id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null limit 1`,
        [id, conversation, owner, machine],
      )).rows[0];
      if (existing) {
        if (existing.sha256 !== item.sha256 || existing.object_key !== item.objectKey) fail("Allegato non disponibile.", 409);
        return attachmentMetadata(existing);
      }
      const usage = ensureResult(await client.query(
        `select coalesce(sum(a.size) filter (where a.conversation_id=$2 and a.deleted_at is null),0)::bigint as conversation_bytes,
                coalesce(sum(a.size) filter (where a.deleted_at is null),0)::bigint as owner_bytes,
                count(*) filter (where a.conversation_id=$2 and a.deleted_at is null and a.message_id is null)::int as pending_count
           from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
          where c.owner_id=$1 and c.deleted_at is null`, [owner, conversation],
      )).rows[0] || {};
      if (Number(usage.pending_count || 0) >= MAX_PENDING_ATTACHMENTS) fail("Hai già troppi allegati in attesa.", 409);
      if (Number(usage.conversation_bytes || 0) + item.size > MAX_ATTACHMENT_BYTES_PER_CONVERSATION) fail("Limite allegati della conversazione superato.", 413);
      if (Number(usage.owner_bytes || 0) + item.size > MAX_ATTACHMENT_BYTES_PER_OWNER) fail("Limite allegati dell'account superato.", 413);
      const result = ensureResult(await client.query(
        `insert into server_ai.attachments
           (id, conversation_id, message_id, filename, kind, media_type, size, text_content, image_data, sha256, object_key, width, height, truncated, archive_metadata, document_metadata)
         values ($1,$2,null,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         on conflict (id) do nothing
         returning id, message_id, filename, kind, media_type, size, width, height, truncated, sha256, object_key, archive_metadata, document_metadata`,
        [id, conversation, item.filename, item.kind, item.mediaType, item.size, item.text, item.image, item.sha256, item.objectKey, item.width, item.height, item.truncated, item.archive ? JSON.stringify(item.archive) : null, item.document ? JSON.stringify(item.document) : null],
      ));
      if (result.rows[0]) return attachmentMetadata(result.rows[0]);
      // `completeUpload` is safely retryable: the storage upload ID is also
      // the database attachment ID, but only an identical scoped object may
      // be acknowledged a second time.
      const raced = ensureResult(await client.query(
        `select a.id, a.message_id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.sha256, a.object_key, a.archive_metadata, a.document_metadata
           from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
          where a.id=$1 and a.conversation_id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null limit 1`,
        [id, conversation, owner, machine],
      )).rows[0];
      if (!raced || raced.sha256 !== item.sha256 || raced.object_key !== item.objectKey) fail("Allegato non disponibile.", 409);
      return attachmentMetadata(raced);
    });
  }

  async listPendingAttachments({ ownerId, subject, machineId, conversationId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId);
    const result = ensureResult(await this.pool.query(
        `select a.id, a.message_id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.archive_metadata, a.document_metadata
         from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
        where a.conversation_id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null
          and a.deleted_at is null and a.message_id is null order by a.created_at asc, a.id asc`, [conversation, owner, machine],
    ));
    return result.rows.map(attachmentMetadata);
  }

  async getAttachmentMetadata({ ownerId, subject, machineId, conversationId, attachmentId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const attachment = normalizeConversationId(attachmentId);
    const result = ensureResult(await this.pool.query(
      `select a.id, a.message_id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.archive_metadata, a.document_metadata
         from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
        where a.id=$1 and a.conversation_id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null limit 1`,
      [attachment, conversation, owner, machine],
    ));
    return result.rows[0] ? attachmentMetadata(result.rows[0]) : null;
  }

  async readAttachment({ ownerId, subject, machineId, conversationId, attachmentId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const attachment = normalizeConversationId(attachmentId);
    const result = ensureResult(await this.pool.query(
      `select a.id, a.message_id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.archive_metadata, a.document_metadata, a.text_content, a.image_data, a.sha256, a.object_key
         from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
        where a.id=$1 and a.conversation_id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null limit 1`,
      [attachment, conversation, owner, machine],
    ));
    if (!result.rows[0]) return null;
    const row = result.rows[0];
    if (row.object_key) {
      if (!this.attachmentStorage || typeof this.attachmentStorage.openObject !== "function") throw new ConversationStoreError("Archivio allegati non disponibile.");
      const object = await this.attachmentStorage.openObject(row.object_key);
      const result = { ...attachmentMetadata(row), sha256: row.sha256, objectKey: row.object_key, text: row.text_content, stream: object.stream, byteSize: Number(row.size) };
      if (row.kind === "archive") {
        if (!row.archive_metadata || typeof this.attachmentStorage.listArchiveEntries !== "function" || typeof this.attachmentStorage.openArchiveEntry !== "function") throw new ConversationStoreError("Archivio ZIP non disponibile.");
        const archiveScope = { ownerId: owner, machineId: machine, conversationId: conversation }; const materialized = new Set();
        return { ...result, archive: row.archive_metadata, listArchiveEntries: (options = {}) => this.attachmentStorage.listArchiveEntries(archiveScope, row.object_key, options), openArchiveEntry: (entryId, options = {}) => this.attachmentStorage.openArchiveEntry(archiveScope, row.object_key, entryId, options), ...(typeof this.attachmentStorage.materializeArchiveTextEntry === "function" ? { materializeArchiveTextEntry: async (entryId, options = {}) => { const value = await this.attachmentStorage.materializeArchiveTextEntry(archiveScope, row.object_key, entryId, options); if (value?.objectKey) materialized.add(value.objectKey); return value; }, readMaterializedText: (objectKey, options = {}) => { if (!materialized.has(objectKey)) throw new ConversationStoreError("Voce archivio non disponibile.", 404); return this.attachmentStorage.readText(objectKey, options); } } : {}) };
      }
      if (row.kind === "document") {
        if (!row.document_metadata || typeof this.attachmentStorage.readDocumentText !== "function") throw new ConversationStoreError("Lettore documento non disponibile.");
        const documentScope = { ownerId: owner, machineId: machine, conversationId: conversation };
        return { ...result, document: row.document_metadata,
          readText: (options = {}) => this.attachmentStorage.readDocumentText(documentScope, row.object_key, options) };
      }
      return result;
    }
    return { ...attachmentMetadata(row), sha256: row.sha256, text: row.text_content, data: row.kind === "image" ? row.image_data : Buffer.from(String(row.text_content || ""), "utf8") };
  }

  async deletePendingAttachment({ ownerId, subject, machineId, conversationId, attachmentId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const attachment = normalizeConversationId(attachmentId);
    const deleted = await this.withTransaction(async (client) => {
      const result = ensureResult(await client.query(
        `update server_ai.attachments a set deleted_at=now(), text_content=null, image_data=null, archive_metadata=null, document_metadata=null, size=0
          where a.id=$1 and a.conversation_id=$2 and a.message_id is null and a.deleted_at is null
            and exists (select 1 from server_ai.conversations c where c.id=a.conversation_id and c.id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null)
            and not exists (select 1 from server_ai.conversation_queue q where q.conversation_id=a.conversation_id and q.status in ('queued','running') and a.id = any(q.attachment_ids))
          returning a.id, a.object_key`, [attachment, conversation, owner, machine],
      ));
      return result.rowCount === 1;
    });
    if (deleted) await this.cleanupDeletedAttachmentObjects();
    return deleted;
  }

  // Artifacts are created only by trusted server-side code after it has
  // written the object through ArtifactStorage. The browser receives only
  // bounded metadata and an opaque UUID.
  async createArtifact({ ownerId, subject, machineId, conversationId, messageId = null, artifact } = {}) {
    if (!this.artifactStorage) throw new ConversationStoreError("Archivio artefatti non disponibile.");
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId);
    const item = normalizeArtifactInput(artifact); const message = messageId == null ? null : normalizeConversationId(messageId);
    const metadata = JSON.stringify({ ...(item.entryCount ? { entryCount: item.entryCount, totalUncompressedBytes: item.totalUncompressedBytes } : {}), ...(item.sourceRefs?.length ? { sourceRefs: item.sourceRefs } : {}) });
    let persisted = false; let reused = false; let collision = false;
    try {
      const result = await this.withTransaction(async client => {
        const current = ensureResult(await client.query(
          `select id from server_ai.conversations where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`, [conversation, owner, machine],
        ));
        if (!current.rows[0]) return null;
        if (message) {
          const messageResult = ensureResult(await client.query(
            `select id from server_ai.messages where id=$1 and conversation_id=$2 and role='assistant'`, [message, conversation],
          ));
          if (!messageResult.rows[0]) return null;
        }
        if (item.sourceRefs?.length) {
          const refs = ensureResult(await client.query(
            `select a.id from server_ai.attachments a
               join server_ai.conversations c on c.id=a.conversation_id
              where a.id = any($1::uuid[]) and a.conversation_id=$2
                and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null`,
            [item.sourceRefs, conversation, owner, machine],
          ));
          if (refs.rows.length !== item.sourceRefs.length) fail("Riferimenti artefatto non disponibili.", 409);
        }
        const result = ensureResult(await client.query(
          `insert into server_ai.artifacts
             (id, conversation_id, message_id, owner_id, machine_id, name, kind, media_type, byte_size, sha256, object_key, metadata)
           values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
           on conflict (id) do nothing
           returning id, name, kind, media_type, byte_size, sha256, metadata, created_at`,
          [item.id, conversation, message, owner, machine, item.name, item.kind, item.mediaType, item.byteSize, item.sha256, item.objectKey, metadata],
        ));
        if (result.rows[0]) { persisted = true; return artifactMetadata(result.rows[0]); }
        collision = true;
        const existing = ensureResult(await client.query(
          `select id, name, kind, media_type, byte_size, sha256, metadata, created_at
             from server_ai.artifacts where id=$1 and conversation_id=$2 and owner_id=$3 and machine_id=$4 and deleted_at is null`, [item.id, conversation, owner, machine],
        ));
        if (!existing.rows[0] || existing.rows[0].sha256 !== item.sha256) fail("Artefatto già associato.", 409);
        reused = true;
        return artifactMetadata(existing.rows[0]);
      });
      if (!result && !persisted && !reused) {
        try { await this.artifactStorage.remove({ ownerId: owner, machineId: machine, conversationId: conversation }, item.id); } catch {}
      }
      return result;
    } catch (error) {
      // If the DB insert cannot commit, remove the newly published object so
      // an abandoned server result cannot consume private disk indefinitely.
      if (!persisted && !reused && !collision) try { await this.artifactStorage.remove({ ownerId: owner, machineId: machine, conversationId: conversation }, item.id); } catch {}
      throw error;
    }
  }

  async listArtifacts({ ownerId, subject, machineId, conversationId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId);
    const result = ensureResult(await this.pool.query(
      `select a.id, a.name, a.kind, a.media_type, a.byte_size, a.sha256, a.metadata, a.created_at
         from server_ai.artifacts a join server_ai.conversations c on c.id=a.conversation_id
        where a.conversation_id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null and a.deleted_at is null
        order by a.created_at asc, a.id asc limit 2048`, [conversation, owner, machine],
    ));
    return result.rows.map(artifactMetadata);
  }

  async readArtifact({ ownerId, subject, machineId, conversationId, artifactId } = {}) {
    if (!this.artifactStorage) throw new ConversationStoreError("Archivio artefatti non disponibile.");
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const artifact = normalizeConversationId(artifactId);
    const result = ensureResult(await this.pool.query(
      `select a.id, a.name, a.kind, a.media_type, a.byte_size, a.sha256, a.object_key, a.metadata, a.created_at
         from server_ai.artifacts a join server_ai.conversations c on c.id=a.conversation_id
        where a.id=$1 and a.conversation_id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null limit 1`, [artifact, conversation, owner, machine],
    ));
    const row = result.rows[0]; if (!row) return null;
    const object = await this.artifactStorage.open({ ownerId: owner, machineId: machine, conversationId: conversation }, row.object_key);
    return { ...artifactMetadata(row), objectKey: row.object_key, stream: object.stream, byteSize: Number(row.byte_size) };
  }

  async deleteArtifact({ ownerId, subject, machineId, conversationId, artifactId } = {}) {
    if (!this.artifactStorage) throw new ConversationStoreError("Archivio artefatti non disponibile.");
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const artifact = normalizeConversationId(artifactId);
    const result = ensureResult(await this.pool.query(
      `update server_ai.artifacts set deleted_at=now(), byte_size=0
        where id=$1 and conversation_id=$2 and owner_id=$3 and machine_id=$4 and deleted_at is null returning object_key`, [artifact, conversation, owner, machine],
    ));
    if (!result.rows[0]) return false;
    try {
      await this.artifactStorage.remove({ ownerId: owner, machineId: machine, conversationId: conversation }, artifact);
      await this.pool.query(
        `update server_ai.artifacts set object_key=null where id=$1 and conversation_id=$2 and owner_id=$3 and machine_id=$4 and deleted_at is not null`,
        [artifact, conversation, owner, machine],
      );
    } catch {}
    return true;
  }

  async enqueueQueue({ ownerId, subject, machineId, conversationId, requestId, message, requestedMode = "auto", attachmentIds = [], delivery = "queue" } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId);
    const request = normalizeRequestId(requestId); const text = normalizeContent(message); const mode = normalizeMode(requestedMode); const attachments = normalizeAttachmentIds(attachmentIds); const chosenDelivery = normalizeQueueDelivery(delivery, { allowDefault: false });
    return this.withTransaction(async (client) => {
      const owned = ensureResult(await client.query(`select id from server_ai.conversations where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`, [conversation, owner, machine]));
      if (!owned.rows[0]) return null;
      const existing = ensureResult(await client.query(`select * from server_ai.conversation_queue where conversation_id=$1 and request_id=$2 for update`, [conversation, request])).rows[0];
      if (existing) {
        if (existing.message !== text || existing.requested_mode !== mode || existing.delivery !== chosenDelivery || JSON.stringify(existing.attachment_ids || []) !== JSON.stringify(attachments)) fail("Richiesta già usata con dati diversi.", 409);
        return { ...queueRow(existing), idempotent: true, created: false };
      }
      const outstanding = ensureResult(await client.query(`select count(*)::int as count from server_ai.conversation_queue where conversation_id=$1 and status in ('queued','running')`, [conversation])).rows[0];
      if (Number(outstanding?.count || 0) >= MAX_CONVERSATION_QUEUE) fail("Coda conversazione piena.", 409);
      if (attachments.length) {
        const selected = ensureResult(await client.query(`select id from server_ai.attachments where conversation_id=$1 and id=any($2::uuid[]) and message_id is null and deleted_at is null for update`, [conversation, attachments]));
        if (selected.rows.length !== attachments.length) fail("Uno o più allegati non sono più disponibili.", 409);
        const reserved = ensureResult(await client.query(`select 1 from server_ai.conversation_queue where conversation_id=$1 and status in ('queued','running') and attachment_ids && $2::uuid[] limit 1`, [conversation, attachments]));
        if (reserved.rows[0]) fail("Uno o più allegati sono già in coda.", 409);
      }
      const next = ensureResult(await client.query(`select coalesce(max(ordinal),0)::bigint + 1 as ordinal from server_ai.conversation_queue where conversation_id=$1`, [conversation])).rows[0];
      const result = ensureResult(await client.query(`insert into server_ai.conversation_queue (id,owner_id,machine_id,conversation_id,request_id,ordinal,message,requested_mode,attachment_ids,delivery,priority,status)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[],$10,$11,'queued') returning *`, [randomUUID(), owner, machine, conversation, request, next.ordinal, text, mode, attachments, chosenDelivery, chosenDelivery === "immediate" ? 1 : 0]));
      return { ...queueRow(result.rows[0]), created: true };
    });
  }

  async listQueue({ ownerId, subject, machineId, conversationId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId);
    const result = ensureResult(await this.pool.query(`with active as (
        select q.*, row_number() over (order by q.priority desc, q.ordinal)::int as position
          from server_ai.conversation_queue q join server_ai.conversations c on c.id=q.conversation_id
         where q.conversation_id=$1 and q.owner_id=$2 and q.machine_id=$3 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null and q.status in ('queued','running')
      ), failed_unstarted as (
        select q.*, 0::int as position
          from server_ai.conversation_queue q join server_ai.conversations c on c.id=q.conversation_id
         where q.conversation_id=$1 and q.owner_id=$2 and q.machine_id=$3 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null and q.status='failed' and q.turn_id is null
         order by q.completed_at desc nulls last, q.ordinal desc limit 10
      ) select * from (select * from active union all select * from failed_unstarted) as combined
        order by case when status in ('queued','running') then 0 else 1 end, priority desc, ordinal asc`, [conversation, owner, machine]));
    return result.rows.map(queueRow);
  }

  async claimQueued({ ownerId, subject, machineId, conversationId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId);
    return this.withTransaction(async client => {
      const owned = ensureResult(await client.query(`select id from server_ai.conversations where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`, [conversation, owner, machine]));
      if (!owned.rows[0]) return null;
      const active = ensureResult(await client.query(`select 1 from server_ai.conversation_queue where conversation_id=$1 and status='running' limit 1 for update`, [conversation]));
      if (active.rows[0]) return null;
      const assistant = ensureResult(await client.query(`select 1 from server_ai.messages where conversation_id=$1 and role='assistant' and generation_status in ('pending','streaming') limit 1 for update`, [conversation]));
      if (assistant.rows[0]) return null;
      const next = ensureResult(await client.query(`select id from server_ai.conversation_queue where conversation_id=$1 and owner_id=$2 and machine_id=$3 and status='queued' order by priority desc, ordinal asc limit 1 for update skip locked`, [conversation, owner, machine]));
      if (!next.rows[0]) return null;
      const claimed = ensureResult(await client.query(`update server_ai.conversation_queue set status='running',started_at=now(),error_code=null where id=$1 and status='queued' returning *`, [next.rows[0].id]));
      return claimed.rows[0] ? queueRow(claimed.rows[0]) : null;
    });
  }

  async completeQueued({ ownerId, subject, machineId, conversationId, queueId, status = "completed", turnId = null, errorCode = null } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const queue = normalizeConversationId(queueId);
    if (!["completed", "failed", "cancelled"].includes(status)) fail("Stato coda non valido.");
    const turn = turnId == null ? null : normalizeConversationId(turnId);
    const code = errorCode == null ? null : typeof errorCode === "string" && /^[A-Z0-9_]{1,64}$/.test(errorCode) ? errorCode : fail("Errore coda non valido.");
    const result = ensureResult(await this.pool.query(`update server_ai.conversation_queue q set status=$1,turn_id=coalesce($2::uuid,turn_id),error_code=$3,completed_at=now(),cancelled_at=case when $1='cancelled' then now() else cancelled_at end
      where q.id=$4 and q.conversation_id=$5 and q.owner_id=$6 and q.machine_id=$7 and q.status in ('queued','running') and exists(select 1 from server_ai.conversations c where c.id=q.conversation_id and c.owner_id=$6 and c.machine_id=$7 and c.deleted_at is null) returning q.*`, [status, turn, code, queue, conversation, owner, machine]));
    return result.rows[0] ? queueRow(result.rows[0]) : null;
  }

  async cancelQueued({ ownerId, subject, machineId, conversationId, queueId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const queue = normalizeConversationId(queueId);
    const result = ensureResult(await this.pool.query(`update server_ai.conversation_queue q set status='cancelled',cancelled_at=now(),completed_at=now()
      where q.id=$1 and q.conversation_id=$2 and q.owner_id=$3 and q.machine_id=$4 and q.status='queued'
        and exists(select 1 from server_ai.conversations c where c.id=q.conversation_id and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null) returning q.*`, [queue, conversation, owner, machine]));
    return result.rows[0] ? queueRow(result.rows[0]) : null;
  }

  async recoverQueuedOnStartup({ machineIds } = {}) {
    if (!Array.isArray(machineIds) || machineIds.length === 0 || machineIds.length > 64) fail("Registry macchine non valido.");
    const machines = [...new Set(machineIds.map(normalizeMachineId))];
    const result = ensureResult(await this.pool.query(`update server_ai.conversation_queue q set status=case when q.turn_id is null then 'queued' else 'failed' end, started_at=null, completed_at=case when q.turn_id is null then null else now() end, error_code=case when q.turn_id is null then null else 'RESTART_INTERRUPTED' end where q.status='running' and q.machine_id=any($1::text[]) and exists(select 1 from server_ai.conversations c where c.id=q.conversation_id and c.owner_id=q.owner_id and c.machine_id=q.machine_id and c.deleted_at is null) returning q.id`, [machines]));
    return result.rowCount || 0;
  }

  async beginTurn({ ownerId, subject, machineId, conversationId, message, attachmentIds = [], requestedMode = "auto", resolvedMode, queueId = null } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const queue = queueId == null ? null : normalizeConversationId(queueId);
    const text = normalizeContent(message);
    const attachments = normalizeAttachmentIds(attachmentIds);
    const requested = normalizeMode(requestedMode);
    const resolved = resolvedMode == null ? (requested === "auto" ? "fast" : requested) : normalizeResolvedMode(resolvedMode);
    const turnId = randomUUID();
    const userId = randomUUID();
    const assistantId = randomUUID();
    return this.withTransaction(async (client) => {
      const conversationResult = ensureResult(await client.query(
        `select id, title, summary from server_ai.conversations
         where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`,
        [conversation, owner, machine],
      ));
      const current = conversationResult.rows[0];
      if (!current) return null;
      const active = ensureResult(await client.query(
        `select m.id from server_ai.messages m
         where m.conversation_id=$1 and m.role='assistant' and m.generation_status in ('pending','streaming')
           and exists (select 1 from server_ai.conversations c where c.id=m.conversation_id and c.id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null)
         limit 1`,
        [conversation, owner, machine],
      ));
      if (active.rows[0]) throw new ConversationStoreError("Conversazione già in generazione.", 409);
      if (attachments.filter(id => id).length > MAX_ATTACHMENT_FILES_PER_TURN) fail("Troppi allegati.");
      if (attachments.length && !queue) {
        const reserved = ensureResult(await client.query(`select 1 from server_ai.conversation_queue
          where conversation_id=$1 and status in ('queued','running') and attachment_ids && $2::uuid[] limit 1 for update`, [conversation, attachments]));
        if (reserved.rows[0]) fail("Uno o più allegati sono già riservati nella coda.", 409);
      }
      if (attachments.length) {
        const attachmentResult = ensureResult(await client.query(
          `select id, kind from server_ai.attachments a
            where a.conversation_id=$1 and a.id = any($2::uuid[]) and a.message_id is null and a.deleted_at is null
              and exists (select 1 from server_ai.conversations c where c.id=a.conversation_id and c.id=$1 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null)
            for update`, [conversation, attachments, owner, machine],
        ));
        if (attachmentResult.rows.length !== attachments.length) fail("Uno o più allegati non sono più disponibili.", 409);
        if (attachmentResult.rows.filter(row => row.kind === "image").length > MAX_ATTACHMENT_IMAGES_PER_TURN) fail("Puoi inviare al massimo cinque immagini per messaggio.");
      }
      const userResult = ensureResult(await client.query(
        `insert into server_ai.messages
         (id, conversation_id, turn_id, role, content, requested_mode, resolved_mode, model, generation_status, source_metadata, tool_metadata)
         values ($1,$2,$3,'user',$4,$5,$6,null,'completed','[]'::jsonb,'{}'::jsonb)
         returning id, conversation_id, role, content, created_at, updated_at, requested_mode, resolved_mode, model, generation_status, source_metadata, tool_metadata`,
        [userId, conversation, turnId, text, requested, resolved],
      ));
      const assistantResult = ensureResult(await client.query(
        `insert into server_ai.messages
         (id, conversation_id, turn_id, role, content, requested_mode, resolved_mode, model, generation_status, source_metadata, tool_metadata)
         values ($1,$2,$3,'assistant','',$4,$5,$6,'pending','[]'::jsonb,'{}'::jsonb)
         returning id, conversation_id, role, content, created_at, updated_at, requested_mode, resolved_mode, model, generation_status, source_metadata, tool_metadata`,
        [assistantId, conversation, turnId, requested, resolved, SERVER_AI_MODEL],
      ));
      if (queue) {
        const boundQueue = ensureResult(await client.query(`update server_ai.conversation_queue set turn_id=$1
          where id=$2 and conversation_id=$3 and owner_id=$4 and machine_id=$5 and status='running' and turn_id is null returning id`, [turnId, queue, conversation, owner, machine]));
        if (!boundQueue.rows[0]) throw new ConversationStoreError("Coda conversazione non disponibile.", 409);
      }
      if (attachments.length) {
        const bound = ensureResult(await client.query(
          `update server_ai.attachments a set message_id=$1
            where a.conversation_id=$2 and a.id = any($3::uuid[]) and a.message_id is null and a.deleted_at is null
              and exists (select 1 from server_ai.conversations c where c.id=a.conversation_id and c.id=$2 and c.owner_id=$4 and c.machine_id=$5 and c.deleted_at is null)
            returning a.id`, [userId, conversation, attachments, owner, machine],
        ));
        if (bound.rows.length !== attachments.length) fail("Uno o più allegati non sono più disponibili.", 409);
      }
      const title = (!current.title || current.title === "Nuova chat") ? deriveConversationTitle(text) : current.title;
      const nextSummary = appendDeterministicSummary(current.summary, { role: "user", content: text });
      await client.query(
        `update server_ai.conversations set summary=$1, title=$2, updated_at=now()
         where id=$3 and owner_id=$4 and machine_id=$5 and deleted_at is null`,
        [nextSummary, title, conversation, owner, machine],
      );
      const boundAttachments = attachments.length ? ensureResult(await client.query(
        `select id, message_id, filename, kind, media_type, size, width, height, truncated, archive_metadata, document_metadata from server_ai.attachments
          where conversation_id=$1 and message_id=$2 and deleted_at is null order by created_at asc, id asc`, [conversation, userId],
      )).rows.map(attachmentMetadata) : [];
      return { turnId, user: { ...rowMessage(userResult.rows[0]), attachments: boundAttachments }, assistant: rowMessage(assistantResult.rows[0]) };
    });
  }

  // Background attachment analysis may need a final assistant response after
  // the original user turn has already completed.  This creates only the
  // assistant half of a turn: the original user message remains the sole
  // visible request, and the durable marker makes retries/restarts idempotent.
  async beginAttachmentContinuation({ ownerId, subject, machineId, conversationId, userMessageId, requestId, requestedMode = "auto", scanId } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const user = normalizeConversationId(userMessageId);
    const request = normalizeRequestId(requestId);
    const scan = normalizeConversationId(scanId);
    const requested = normalizeMode(requestedMode);
    const resolved = requested === "auto" ? "fast" : requested;
    return this.withTransaction(async client => {
      const current = ensureResult(await client.query(`select id,summary from server_ai.conversations where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`, [conversation, owner, machine]));
      if (!current.rows[0]) return null;
      const existing = ensureResult(await client.query(`select id,conversation_id,role,content,created_at,updated_at,requested_mode,resolved_mode,model,generation_status,source_metadata,tool_metadata,turn_id from server_ai.messages where conversation_id=$1 and role='assistant' and tool_metadata->'autoContinuation'->>'requestId'=$2 order by created_at asc limit 1`, [conversation, request])).rows[0];
      if (existing && ["pending", "streaming", "completed"].includes(existing.generation_status)) return { turnId: existing.turn_id, user: null, assistant: rowMessage(existing), idempotent: true };
      const active = ensureResult(await client.query(`select id from server_ai.messages where conversation_id=$1 and role='assistant' and generation_status in ('pending','streaming') limit 1 for update`, [conversation]));
      if (active.rows[0]) return { blocked: true };
      if (existing && ["aborted", "failed"].includes(existing.generation_status)) {
        const reclaimed = ensureResult(await client.query(`update server_ai.messages set content='',generation_status='pending',updated_at=now() where id=$1 and conversation_id=$2 and role='assistant' and generation_status in ('aborted','failed') returning id,conversation_id,role,content,created_at,updated_at,requested_mode,resolved_mode,model,generation_status,source_metadata,tool_metadata,turn_id`, [existing.id, conversation]));
        if (reclaimed.rows[0]) return { turnId: reclaimed.rows[0].turn_id, user: null, assistant: rowMessage(reclaimed.rows[0]), reclaimed: true };
      }
      const original = ensureResult(await client.query(`select id from server_ai.messages where id=$1 and conversation_id=$2 and role='user' and generation_status='completed'`, [user, conversation])).rows[0];
      if (!original) return null;
      const turn = randomUUID(); const assistant = randomUUID();
      const metadata = JSON.stringify({ autoContinuation: { version: 1, requestId: request, scanId: scan, userMessageId: user } });
      const result = ensureResult(await client.query(`insert into server_ai.messages
        (id,conversation_id,turn_id,role,content,requested_mode,resolved_mode,model,generation_status,source_metadata,tool_metadata)
        values ($1,$2,$3,'assistant','',$4,$5,$6,'pending','[]'::jsonb,$7::jsonb)
        returning id,conversation_id,role,content,created_at,updated_at,requested_mode,resolved_mode,model,generation_status,source_metadata,tool_metadata`, [assistant, conversation, turn, requested, resolved, SERVER_AI_MODEL, metadata]));
      return { turnId: turn, user: null, assistant: rowMessage(result.rows[0]), idempotent: false };
    });
  }
  async hasAttachmentContinuation({ ownerId, subject, machineId, conversationId, requestId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const request = normalizeRequestId(requestId);
    const result = ensureResult(await this.pool.query(`select 1 from server_ai.messages m where m.conversation_id=$1 and m.role='assistant' and m.generation_status in ('pending','streaming','completed') and m.tool_metadata->'autoContinuation'->>'requestId'=$2 and exists(select 1 from server_ai.conversations c where c.id=m.conversation_id and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null) limit 1`, [conversation, request, owner, machine]));
    return Boolean(result.rows[0]);
  }
  async getAttachmentContinuation({ ownerId, subject, machineId, conversationId, requestId } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId); const request = normalizeRequestId(requestId);
    const result = ensureResult(await this.pool.query(`select m.id,m.turn_id,m.generation_status from server_ai.messages m join server_ai.conversations c on c.id=m.conversation_id where m.conversation_id=$1 and m.role='assistant' and m.tool_metadata->'autoContinuation'->>'requestId'=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null order by m.created_at asc limit 1`, [conversation, request, owner, machine]));
    const row = result.rows[0]; return row ? { assistantId: row.id, turnId: row.turn_id, generationStatus: row.generation_status } : null;
  }

  async finishTurn({ ownerId, subject, machineId, conversationId, turnId, content, generationStatus, resolvedMode, sources = [], toolMetadata = {} } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const turn = normalizeTurnId(turnId);
    if (typeof content !== "string" || content.length > MAX_CONTENT) fail("Contenuto non valido.");
    const text = content;
    const status = normalizeGenerationStatus(generationStatus);
    if (!["completed", "aborted", "failed"].includes(status)) fail("Lo stato terminale non è valido.");
    const resolved = normalizeResolvedMode(resolvedMode);
    const safeSources = normalizeSources(sources);
    const safeTools = normalizeToolMetadata(toolMetadata);
    return this.withTransaction(async (client) => {
      const current = ensureResult(await client.query(
        `select summary from server_ai.conversations
         where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null for update`,
        [conversation, owner, machine],
      ));
      if (!current.rows[0]) return null;
      const result = ensureResult(await client.query(
        `update server_ai.messages m set content=$1, generation_status=$2, resolved_mode=$3,
                source_metadata=$4::jsonb,
                tool_metadata=case when m.tool_metadata ? 'autoContinuation'
                  then jsonb_set($5::jsonb,'{autoContinuation}',m.tool_metadata->'autoContinuation',true)
                  else $5::jsonb end, updated_at=now()
         where m.conversation_id=$6 and m.turn_id=$7 and m.role='assistant'
           and exists (select 1 from server_ai.conversations c where c.id=m.conversation_id and c.id=$6 and c.owner_id=$8 and c.machine_id=$9 and c.deleted_at is null)
           and m.generation_status in ('pending','streaming')
         returning m.id, m.conversation_id, m.role, m.content, m.created_at, m.updated_at, m.requested_mode, m.resolved_mode, m.model, m.generation_status, m.source_metadata, m.tool_metadata`,
        [text, status, resolved, JSON.stringify(safeSources), JSON.stringify(safeTools), conversation, turn, owner, machine],
      ));
      if (!result.rows[0]) return null;
      const summary = appendDeterministicSummary(current.rows[0].summary, { role: "assistant", content: text, generationStatus: status });
      await client.query(
        `update server_ai.conversations set summary=$1, updated_at=now()
         where id=$2 and owner_id=$3 and machine_id=$4 and deleted_at is null`,
        [summary, conversation, owner, machine],
      );
      return rowMessage(result.rows[0]);
    });
  }

  async updateMessage({ ownerId, subject, machineId, conversationId, messageId, content, generationStatus, sources, toolMetadata } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const message = normalizeConversationId(messageId);
    const status = normalizeGenerationStatus(generationStatus);
    const values = [status, conversation, message, owner, machine];
    const sets = ["generation_status=$1", "updated_at=now()"];
    if (content !== undefined) { sets.push(`content=$${values.push(normalizeAssistantContent(content))}`); }
    if (sources !== undefined) { sets.push(`source_metadata=$${values.push(JSON.stringify(normalizeSources(sources)))}::jsonb`); }
    if (toolMetadata !== undefined) {
      const index = values.push(JSON.stringify(normalizeToolMetadata(toolMetadata)));
      sets.push(`tool_metadata=case when m.tool_metadata ? 'autoContinuation' then jsonb_set($${index}::jsonb,'{autoContinuation}',m.tool_metadata->'autoContinuation',true) else $${index}::jsonb end`);
    }
    const result = ensureResult(await this.pool.query(
      `update server_ai.messages m set ${sets.join(", ")}
       where m.conversation_id=$2 and m.id=$3 and m.role='assistant'
         and m.generation_status in ('pending','streaming')
         and exists (select 1 from server_ai.conversations c where c.id=m.conversation_id and c.id=$2 and c.owner_id=$4 and c.machine_id=$5 and c.deleted_at is null)
       returning m.id, m.conversation_id, m.role, m.content, m.created_at, m.updated_at, m.requested_mode, m.resolved_mode, m.model, m.generation_status, m.source_metadata, m.tool_metadata`,
      values,
    ));
    if (!result.rows[0]) return null;
    return rowMessage(result.rows[0]);
  }

  async recoverIncomplete({ ownerId, subject, machineId } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const result = ensureResult(await this.pool.query(
      `update server_ai.messages m set generation_status='aborted', updated_at=now()
       where m.generation_status in ('pending','streaming')
         and exists (select 1 from server_ai.conversations c where c.id=m.conversation_id and c.owner_id=$1 and c.machine_id=$2 and c.deleted_at is null)
       returning m.id`,
      [owner, machine],
    ));
    return result.rowCount;
  }

  // Internal startup-only recovery. The caller must pass the machine registry
  // identities; this method is never exposed as a user/API operation.
  async recoverOnStartup({ machineIds } = {}) {
    if (!Array.isArray(machineIds) || machineIds.length === 0 || machineIds.length > 64) fail("Registry macchine non valido.");
    const machines = [...new Set(machineIds.map(normalizeMachineId))];
    const result = ensureResult(await this.pool.query(
      `update server_ai.messages m set generation_status='aborted', updated_at=now()
       where m.generation_status in ('pending','streaming')
         and exists (select 1 from server_ai.conversations c where c.id=m.conversation_id and c.machine_id = any($1::text[]) and c.deleted_at is null)
       returning m.id`,
      [machines],
    ));
    return result.rowCount;
  }

  async buildContext({ ownerId, subject, machineId, conversationId, currentMessage } = {}) {
    const owner = ownerFrom(ownerId, subject);
    const machine = normalizeMachineId(machineId);
    const conversation = normalizeConversationId(conversationId);
    const current = normalizeContent(currentMessage);
    const patterns = historySearchPatterns(current);
    const result = ensureResult(await this.pool.query(
      `with owned_conversation as (
         select id, summary, project_id
           from server_ai.conversations
          where id=$1 and owner_id=$2 and machine_id=$3 and deleted_at is null
       ), scoped as not materialized (
         select m.role,
                case when m.role='assistant' and m.generation_status='aborted'
                  then '[Risposta interrotta, parziale]' || E'\n' || m.content
                  else m.content end as content,
                m.resolved_mode, m.ordinal,
                lag(m.ordinal) over (order by m.ordinal) as previous_ordinal,
                lead(m.ordinal) over (order by m.ordinal) as next_ordinal
           from server_ai.messages m join owned_conversation c on c.id=m.conversation_id
          where m.generation_status='completed'
             or (
               m.role='assistant' and m.generation_status='aborted'
               and octet_length(m.content) > 0
               and not exists (
                 select 1 from server_ai.messages later
                  where later.conversation_id=m.conversation_id
                    and later.role='assistant' and later.ordinal > m.ordinal
               )
             )
       ), initial as (
         select *, 1 as context_priority from scoped order by ordinal asc limit ${INITIAL_CONTEXT_MESSAGES}
       ), recent as (
         select *, 3 as context_priority from scoped order by ordinal desc limit ${RECENT_CONTEXT_MESSAGES}
       ), relevant as (
         select *, 1 as context_priority from scoped
          where cardinality($4::text[]) > 0 and exists (
            select 1 from unnest($4::text[]) as pattern(value)
             where lower(content) like pattern.value escape '\\'
          )
          order by (
            select count(*) from unnest($4::text[]) as pattern(value)
             where lower(content) like pattern.value escape '\\'
          ) desc, ordinal desc limit ${RELEVANT_CONTEXT_MESSAGES}
       ), related as (
         select s.*, 1 as context_priority from scoped s
          where exists (select 1 from relevant r where s.ordinal in (r.previous_ordinal, r.ordinal, r.next_ordinal))
       ), commitments as (
         select *, 2 as context_priority from scoped
          where role='user' and content ~* '(^|[^[:alnum:]_])(non|solo|sempre|mai|evita|mantieni|senza|deve|devono|voglio|consento|autorizzo|confermo|procedi|continua|puoi|fermati|annulla|interrompi|revoco|lascia perdere|correzione|cambio|cambia|invece)([^[:alnum:]_]|$)'
            and regexp_replace(regexp_replace(regexp_replace(lower(trim(content)), '[.!?…]+$', ''), '[,;:]+', ' ', 'g'), '[[:space:]]+', ' ', 'g') !~
              '^((sì|si|ok|okay|certo|va bene)( (procedi|continua|pure|grazie|con questo controllo|con il controllo|resta in italiano|in italiano|e))*|confermo|procedi|continua|fallo|fai pure)$'
          order by ordinal desc limit ${COMMITMENT_CONTEXT_MESSAGES}
       ), selected as (
         select distinct on (ordinal) role, content, resolved_mode, ordinal, context_priority
           from (select * from initial union all select * from recent union all select * from related union all select * from commitments) candidates
          order by ordinal, context_priority asc
       )
       select c.summary, c.project_id, (select count(*)::int from scoped) as completed_count,
              s.role, s.content, s.resolved_mode, s.ordinal, s.context_priority
         from owned_conversation c left join selected s on true
        order by s.ordinal asc`,
      [conversation, owner, machine, patterns],
    ));
    if (!result.rows.length) return null;
    const summary = result.rows[0].summary || "";
    const stored = result.rows.filter(row => row.role).map(row => ({
      role: row.role, content: row.content, resolvedMode: row.resolved_mode,
      ordinal: row.ordinal, contextPriority: Number(row.context_priority) || 2,
    }));
    const anchor = continuationAnchor(stored, current);
    const context = boundedRecentContext(stored, current, this.contextMessageLimit, this.contextCharLimit, anchor);
    return {
      messages: context, summary: summaryForContext(summary, stored, current),
      priorConversation: { turnCount: Math.floor(Number(result.rows[0].completed_count) / 2), hasSummary: Boolean(summary), hasUnresolvedQuestion: Boolean(anchor) },
      ...(anchor ? { continuationAnchor: anchor } : {}),
      projectId: normalizeProjectId(result.rows[0].project_id),
    };
  }

  async getAttachmentContext({ ownerId, subject, machineId, conversationId, currentAttachmentIds = null } = {}) {
    const owner = ownerFrom(ownerId, subject); const machine = normalizeMachineId(machineId); const conversation = normalizeConversationId(conversationId);
    const current = currentAttachmentIds == null ? null : normalizeAttachmentIds(currentAttachmentIds);
    const selectedIds = current?.length ? current : null;
    const groupResult = selectedIds ? { rows: [{ message_id: null }] } : ensureResult(await this.pool.query(
      `select a.message_id from server_ai.attachments a join server_ai.messages m on m.id=a.message_id join server_ai.conversations c on c.id=a.conversation_id
        where a.conversation_id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null and a.deleted_at is null and m.role='user'
        order by m.ordinal desc limit 1`, [conversation, owner, machine],
    ));
    if (!groupResult.rows[0]) return [];
    const result = ensureResult(await this.pool.query(
      `select a.id, a.filename, a.kind, a.media_type, a.size, a.width, a.height, a.truncated, a.archive_metadata, a.document_metadata, a.sha256, a.text_content, a.image_data, a.object_key
         from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id join server_ai.messages m on m.id=a.message_id and m.conversation_id=a.conversation_id
        where a.conversation_id=$1 and c.owner_id=$2 and c.machine_id=$3 and c.deleted_at is null and a.deleted_at is null
          and m.role='user' and ${selectedIds ? "a.id = any($4::uuid[])" : "a.message_id=$4::uuid"}
        order by a.created_at asc, a.id asc limit ${MAX_ATTACHMENT_FILES_PER_TURN}`,
      [conversation, owner, machine, selectedIds || groupResult.rows[0].message_id],
    ));
    if (selectedIds && result.rows.length !== selectedIds.length) return [];
    let textBytes = 0; let images = 0;
    return result.rows.flatMap(row => {
      if (row.kind === "archive") {
        if (!row.object_key || !row.archive_metadata || !this.attachmentStorage?.listArchiveEntries || !this.attachmentStorage?.openArchiveEntry) return [];
        const archiveScope = { ownerId: owner, machineId: machine, conversationId: conversation }; const materialized = new Set();
        return [{ ...attachmentMetadata(row), filename: row.filename, sha256: row.sha256, objectKey: row.object_key, byteSize: Number(row.size), text: null, archive: row.archive_metadata,
          listArchiveEntries: (options = {}) => this.attachmentStorage.listArchiveEntries(archiveScope, row.object_key, options),
          openArchiveEntry: (entryId, options = {}) => this.attachmentStorage.openArchiveEntry(archiveScope, row.object_key, entryId, options),
          ...(typeof this.attachmentStorage.materializeArchiveTextEntry === "function" ? { materializeArchiveTextEntry: async (entryId, options = {}) => { const value = await this.attachmentStorage.materializeArchiveTextEntry(archiveScope, row.object_key, entryId, options); if (value?.objectKey) materialized.add(value.objectKey); return value; }, readMaterializedText: (objectKey, options = {}) => { if (!materialized.has(objectKey)) throw new ConversationStoreError("Voce archivio non disponibile.", 404); return this.attachmentStorage.readText(objectKey, options); } } : {}),
        }];
      }
      if (row.kind === "document") {
        if (!row.object_key || !row.document_metadata || typeof this.attachmentStorage?.readDocumentText !== "function") return [];
        const documentScope = { ownerId: owner, machineId: machine, conversationId: conversation };
        return [{ ...attachmentMetadata(row), filename: row.filename, sha256: row.sha256, objectKey: row.object_key, byteSize: Number(row.size), text: row.text_content ?? "",
          document: row.document_metadata,
          readText: ({ startByte = 0, maxBytes = 12 * 1024, signal } = {}) => this.attachmentStorage.readDocumentText(documentScope, row.object_key, { startByte, maxBytes, signal }) }];
      }
      if (row.kind === "image") {
        if (++images > MAX_ATTACHMENT_IMAGES_PER_TURN || !Buffer.isBuffer(row.image_data)) return [];
        return [{ ...attachmentMetadata(row), filename: row.filename, sha256: row.sha256, image: row.image_data.toString("base64") }];
      }
      if (row.object_key) {
        if (!this.attachmentStorage || typeof this.attachmentStorage.readText !== "function") return [];
        return [{ ...attachmentMetadata(row), filename: row.filename, sha256: row.sha256, objectKey: row.object_key, byteSize: Number(row.size), text: row.text_content || "",
          readText: ({ startByte = 0, maxBytes = 12 * 1024, signal } = {}) => this.attachmentStorage.readText(row.object_key, { startByte, maxBytes, signal }) }];
      }
      const remaining = MAX_ATTACHMENT_TEXT_CONTEXT_BYTES - textBytes;
      if (remaining <= 0 || typeof row.text_content !== "string") return [];
      const text = utf8Prefix(row.text_content, remaining); textBytes += Buffer.byteLength(text);
      return [{ ...attachmentMetadata(row), filename: row.filename, sha256: row.sha256, text, truncated: row.truncated === true || text !== row.text_content }];
    });
  }

  remove(args) { return this.delete(args); }
  markStreaming(args) { return this.updateMessage({ ...args, generationStatus: "streaming" }); }
  context(args) { return this.buildContext(args); }
  recover(args) { return this.recoverIncomplete(args); }
}

export const createPostgresConversationStore = (options) => new PostgresConversationStore(options);

// HTTP fixtures may use this store, but production must always construct the
// PostgreSQL implementation above. Keeping the guard at the factory boundary
// prevents an accidental in-memory production deployment.
export function createMemoryConversationStore({ nodeEnvironment = process.env.NODE_ENV, attachmentStorage = null, artifactStorage = null } = {}) {
  if (String(nodeEnvironment).toLowerCase() !== "test") throw new Error("Il conversation store in memoria è consentito solo nei test.");
  return new MemoryConversationStore({ attachmentStorage, artifactStorage });
}

class MemoryConversationStore {
  constructor({ attachmentStorage = null, artifactStorage = null } = {}) { this.conversations = new Map(); this.messages = new Map(); this.attachments = new Map(); this.artifacts = new Map(); this.queue = new Map(); this.ordinal = 0; this.attachmentStorage = attachmentStorage; this.artifactStorage = artifactStorage; }
  scope(args) { return { owner: ownerFrom(args.ownerId, args.subject), machine: normalizeMachineId(args.machineId), project: normalizeProjectId(args.projectId) }; }
  own(args, conversationId) {
    const { owner, machine } = this.scope(args);
    const conversation = this.conversations.get(normalizeConversationId(conversationId));
    return conversation && conversation.ownerId === owner && conversation.machineId === machine && !conversation.deletedAt ? conversation : null;
  }
  async ready() { return { ready: true }; }
  async create(args = {}) {
    const { owner, machine, project } = this.scope(args);
    const id = randomUUID();
    const now = new Date().toISOString();
    const conversation = { id, ownerId: owner, machineId: machine, projectId: project, title: normalizeTitle(args.title || "Nuova chat"), summary: "", metadata: normalizeMetadata(args.metadata), createdAt: now, updatedAt: now, archivedAt: null, deletedAt: null };
    this.conversations.set(id, conversation); this.messages.set(id, []); this.attachments.set(id, []); this.artifacts.set(id, []); this.queue.set(id, []); return structuredClone(conversation);
  }
  async listPage(args = {}) {
    const { owner, machine } = this.scope(args);
    const count = normalizeListLimit(args.limit);
    const cursor = args.cursor == null ? null : decodeConversationCursor(args.cursor);
    const filtered = [...this.conversations.values()]
      .filter(item => item.ownerId === owner && item.machineId === machine && !item.deletedAt)
      .filter(item => !cursor || item.updatedAt < cursor.updatedAt || (item.updatedAt === cursor.updatedAt && item.id < cursor.id))
      .sort((a, b) => (a.updatedAt === b.updatedAt ? (a.id === b.id ? 0 : a.id > b.id ? -1 : 1) : a.updatedAt > b.updatedAt ? -1 : 1));
    const hasNext = filtered.length > count;
    const conversations = filtered.slice(0, count).map(item => structuredClone(item));
    const last = filtered[count - 1];
    return { conversations, nextCursor: hasNext && last ? encodeConversationCursor(last.updatedAt, last.id) : null };
  }
  async list(args = {}) {
    return (await this.listPage(args)).conversations;
  }
  async get(args = {}) {
    const conversation = this.own(args, args.conversationId);
    if (!conversation) return null;
    const all = this.messages.get(conversation.id) || [];
    const before = args.before == null ? null : Number(args.before);
    const filtered = all.filter(item => before == null || item.ordinal < before).sort((a, b) => a.ordinal - b.ordinal);
    const limit = Math.max(1, Math.min(200, Number(args.limit) || 200));
    const page = filtered.slice(-limit);
    const attachments = this.attachments.get(conversation.id) || [];
    const artifacts = this.artifacts.get(conversation.id) || [];
    return { conversation: structuredClone(conversation), messages: page.map(message => ({ ...structuredClone(message), attachments: attachments.filter(item => !item.deletedAt && item.messageId === message.id).map(attachmentMetadata), artifacts: artifacts.filter(item => !item.deletedAt && item.messageId === message.id).map(artifactMetadata) })), queue: await this.listQueue(args), nextBefore: filtered.length > limit ? String(page[0].ordinal) : null };
  }
  async getMessage(args = {}) {
    const conversation = this.own(args, args.conversationId);
    if (!conversation) return null;
    const messageId = normalizeConversationId(args.messageId);
    const message = (this.messages.get(conversation.id) || []).find(item => item.id === messageId);
    if (!message) return null;
    const attachments = (this.attachments.get(conversation.id) || []).filter(item => !item.deletedAt && item.messageId === message.id).map(attachmentMetadata);
    return { conversation: structuredClone(conversation), message: { ...structuredClone(message), attachments } };
  }
  async getProjectIds(args = {}) {
    const conversation = this.own(args, args.conversationId);
    if (!conversation) return null;
    const ids = new Set();
    if (conversation.projectId) ids.add(normalizeProjectId(conversation.projectId, { allowNull: false }));
    for (const message of this.messages.get(conversation.id) || []) {
      for (const source of Array.isArray(message.sources) ? message.sources : []) {
        if (source?.type === "project" && source.projectId) ids.add(normalizeProjectId(source.projectId, { allowNull: false }));
      }
    }
    if (ids.size > 64) fail("Troppe fonti progetto nella conversazione.");
    return [...ids];
  }
  async rename(args = {}) { const conversation = this.own(args, args.conversationId); if (!conversation) return null; conversation.title = normalizeTitle(args.title); conversation.updatedAt = new Date().toISOString(); return structuredClone(conversation); }
  async delete(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return false;
    if ((this.messages.get(conversation.id) || []).some(item => item.role === "assistant" && ["pending", "streaming"].includes(item.generationStatus))) throw new ConversationStoreError("Conversazione in generazione.", 409);
    const now = new Date().toISOString();
    for (const item of this.queue.get(conversation.id) || []) if (item.status === "queued") { item.status = "cancelled"; item.completedAt = now; item.errorCode = "CONVERSATION_DELETED"; }
    const deletedAttachments = [];
    for (const attachment of this.attachments.get(conversation.id) || []) if (!attachment.deletedAt) { attachment.deletedAt = now; attachment.text = null; attachment.image = null; attachment.archive = null; attachment.document = null; attachment.size = 0; deletedAttachments.push(attachment); }
    conversation.deletedAt = now;
    if (this.attachmentStorage?.removeObject) for (const attachment of deletedAttachments) if (attachment.objectKey) {
      try { await this.attachmentStorage.removeObject(attachment.objectKey); attachment.objectKey = null; } catch {}
    }
    const artifacts = this.artifacts.get(conversation.id) || [];
    for (const item of artifacts) if (!item.deletedAt) { item.deletedAt = now; if (this.artifactStorage?.remove) { try { await this.artifactStorage.remove({ ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id }, item.id); } catch {} } }
    return true;
  }
  async createArtifact(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation || !this.artifactStorage) {
      if (this.artifactStorage && args.conversationId) try { await this.artifactStorage.remove({ ownerId: args.ownerId ?? args.subject, machineId: args.machineId, conversationId: args.conversationId }, args.artifact?.id); } catch {}
      return null;
    }
    const item = normalizeArtifactInput(args.artifact); const messageId = args.messageId == null ? null : normalizeConversationId(args.messageId);
    if (messageId && !(this.messages.get(conversation.id) || []).some(message => message.id === messageId && message.role === "assistant")) { try { await this.artifactStorage.remove({ ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id }, item.id); } catch {} return null; }
    if (item.sourceRefs?.length) {
      const attachments = this.attachments.get(conversation.id) || [];
      if (item.sourceRefs.some(ref => !attachments.some(value => value.id === ref && !value.deletedAt))) {
        try { await this.artifactStorage.remove({ ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id }, item.id); } catch {}
        fail("Riferimenti artefatto non disponibili.", 409);
      }
    }
    const local = this.artifacts.get(conversation.id) || []; const existing = local.find(value => value.id === item.id && !value.deletedAt);
    if (existing) { if (existing.sha256 !== item.sha256) fail("Artefatto già associato.", 409); return artifactMetadata(existing); }
    const value = { ...item, conversationId: conversation.id, messageId, createdAt: new Date().toISOString(), deletedAt: null };
    local.push(value); this.artifacts.set(conversation.id, local); return artifactMetadata(value);
  }
  async listArtifacts(args = {}) { const conversation = this.own(args, args.conversationId); return conversation ? (this.artifacts.get(conversation.id) || []).filter(item => !item.deletedAt).map(artifactMetadata) : []; }
  async readArtifact(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation || !this.artifactStorage) return null; const artifact = normalizeConversationId(args.artifactId); const item = (this.artifacts.get(conversation.id) || []).find(value => value.id === artifact && !value.deletedAt); if (!item) return null;
    const object = await this.artifactStorage.open({ ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id }, item.objectKey); return { ...artifactMetadata(item), objectKey: item.objectKey, stream: object.stream, byteSize: item.byteSize };
  }
  async deleteArtifact(args = {}) { const conversation = this.own(args, args.conversationId); if (!conversation || !this.artifactStorage) return false; const artifact = normalizeConversationId(args.artifactId); const item = (this.artifacts.get(conversation.id) || []).find(value => value.id === artifact && !value.deletedAt); if (!item) return false; item.deletedAt = new Date().toISOString(); try { await this.artifactStorage.remove({ ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id }, item.id); item.objectKey = null; } catch {} return true; }
  async createAttachment(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const item = normalizeAttachmentUpload(args.attachment); const owner = conversation.ownerId;
    const id = args.attachmentId == null ? randomUUID() : normalizeConversationId(args.attachmentId);
    const local = this.attachments.get(conversation.id) || [];
    const duplicate = local.find(value => value.id === id && !value.deletedAt);
    if (duplicate) {
      if (duplicate.sha256 !== item.sha256 || duplicate.objectKey !== item.objectKey) fail("Allegato non disponibile.", 409);
      return attachmentMetadata(duplicate);
    }
    const all = [...this.attachments.values()].flat();
    const ownBytes = all.filter(value => !value.deletedAt && this.conversations.get(value.conversationId)?.ownerId === owner).reduce((sum, value) => sum + value.size, 0);
    if (local.filter(value => !value.deletedAt && !value.messageId).length >= MAX_PENDING_ATTACHMENTS) fail("Hai già troppi allegati in attesa.", 409);
    if (local.filter(value => !value.deletedAt).reduce((sum, value) => sum + value.size, 0) + item.size > MAX_ATTACHMENT_BYTES_PER_CONVERSATION) fail("Limite allegati della conversazione superato.", 413);
    if (ownBytes + item.size > MAX_ATTACHMENT_BYTES_PER_OWNER) fail("Limite allegati dell'account superato.", 413);
    const value = { id, conversationId: conversation.id, messageId: null, ...item, createdAt: new Date().toISOString(), deletedAt: null };
    local.push(value); this.attachments.set(conversation.id, local); return attachmentMetadata(value);
  }
  async listPendingAttachments(args = {}) { const conversation = this.own(args, args.conversationId); return conversation ? structuredClone((this.attachments.get(conversation.id) || []).filter(item => !item.deletedAt && !item.messageId).map(attachmentMetadata)) : []; }
  async getAttachmentMetadata(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const id = normalizeConversationId(args.attachmentId);
    const attachment = (this.attachments.get(conversation.id) || []).find(item => item.id === id && !item.deletedAt);
    return attachment ? attachmentMetadata(attachment) : null;
  }
  async readAttachment(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const id = normalizeConversationId(args.attachmentId); const item = (this.attachments.get(conversation.id) || []).find(value => value.id === id && !value.deletedAt);
    if (!item) return null;
    if (item.objectKey) {
      if (!this.attachmentStorage || typeof this.attachmentStorage.openObject !== "function") throw new ConversationStoreError("Archivio allegati non disponibile.");
      const object = await this.attachmentStorage.openObject(item.objectKey);
      const result = { ...attachmentMetadata(item), sha256: item.sha256, objectKey: item.objectKey, text: item.text, stream: object.stream, byteSize: item.size };
      if (item.kind === "archive") {
        if (!item.archive || !this.attachmentStorage.listArchiveEntries || !this.attachmentStorage.openArchiveEntry) throw new ConversationStoreError("Archivio ZIP non disponibile.");
        const archiveScope = { ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id }; const materialized = new Set();
        return { ...result, archive: item.archive, listArchiveEntries: (options = {}) => this.attachmentStorage.listArchiveEntries(archiveScope, item.objectKey, options), openArchiveEntry: (entryId, options = {}) => this.attachmentStorage.openArchiveEntry(archiveScope, item.objectKey, entryId, options), ...(this.attachmentStorage.materializeArchiveTextEntry ? { materializeArchiveTextEntry: async (entryId, options = {}) => { const value = await this.attachmentStorage.materializeArchiveTextEntry(archiveScope, item.objectKey, entryId, options); if (value?.objectKey) materialized.add(value.objectKey); return value; }, readMaterializedText: (objectKey, options = {}) => { if (!materialized.has(objectKey)) throw new ConversationStoreError("Voce archivio non disponibile.", 404); return this.attachmentStorage.readText(objectKey, options); } } : {}) };
      }
      if (item.kind === "document") {
        if (!item.document || typeof this.attachmentStorage.readDocumentText !== "function") throw new ConversationStoreError("Lettore documento non disponibile.");
        const documentScope = { ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id };
        return { ...result, document: item.document, readText: (options = {}) => this.attachmentStorage.readDocumentText(documentScope, item.objectKey, options) };
      }
      return result;
    }
    return { ...attachmentMetadata(item), sha256: item.sha256, text: item.text, data: item.kind === "image" ? Buffer.from(item.image) : Buffer.from(item.text || "", "utf8") };
  }
  async deletePendingAttachment(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return false;
    const id = normalizeConversationId(args.attachmentId); const item = (this.attachments.get(conversation.id) || []).find(value => value.id === id && !value.deletedAt && !value.messageId);
    if (!item || (this.queue.get(conversation.id) || []).some(value => ["queued", "running"].includes(value.status) && value.attachmentIds.includes(id))) return false;
    const objectKey = item.objectKey; item.deletedAt = new Date().toISOString(); item.text = null; item.image = null; item.archive = null; item.document = null; item.size = 0;
    if (objectKey && this.attachmentStorage?.removeObject) { try { await this.attachmentStorage.removeObject(objectKey); item.objectKey = null; } catch {} }
    return true;
  }
  async enqueueQueue(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const requestId = normalizeRequestId(args.requestId); const message = normalizeContent(args.message); const requestedMode = normalizeMode(args.requestedMode || "auto"); const attachmentIds = normalizeAttachmentIds(args.attachmentIds); const delivery = normalizeQueueDelivery(args.delivery, { allowDefault: false });
    const rows = this.queue.get(conversation.id) || []; const existing = rows.find(item => item.requestId === requestId);
    if (existing) {
      if (existing.message !== message || existing.requestedMode !== requestedMode || existing.delivery !== delivery || JSON.stringify(existing.attachmentIds) !== JSON.stringify(attachmentIds)) fail("Richiesta già usata con dati diversi.", 409);
      return { ...structuredClone(existing), idempotent: true, created: false };
    }
    if (rows.filter(item => ["queued", "running"].includes(item.status)).length >= MAX_CONVERSATION_QUEUE) fail("Coda conversazione piena.", 409);
    const pending = this.attachments.get(conversation.id) || [];
    if (attachmentIds.some(id => !pending.some(item => item.id === id && !item.deletedAt && !item.messageId))) fail("Uno o più allegati non sono più disponibili.", 409);
    if (attachmentIds.some(id => rows.some(item => ["queued", "running"].includes(item.status) && item.attachmentIds.includes(id)))) fail("Uno o più allegati sono già in coda.", 409);
    const ordinal = (rows.at(-1)?.ordinal || 0) + 1; const now = new Date().toISOString();
    const item = { id: randomUUID(), requestId, conversationId: conversation.id, message, requestedMode, attachmentIds, delivery, priority: delivery === "immediate" ? 1 : 0, status: "queued", ordinal, position: rows.filter(value => value.status === "queued").length + 1, turnId: null, createdAt: now, startedAt: null };
    rows.push(item); this.queue.set(conversation.id, rows); conversation.updatedAt = now; return { ...structuredClone(item), created: true };
  }
  async listQueue(args = {}) { const conversation = this.own(args, args.conversationId); if (!conversation) return []; const rows = this.queue.get(conversation.id) || []; const active = rows.filter(item => ["queued", "running"].includes(item.status)).sort((a, b) => b.priority - a.priority || a.ordinal - b.ordinal).map((item, index) => ({ ...item, position: index + 1 })); const failed = rows.filter(item => item.status === "failed" && !item.turnId).sort((a, b) => String(b.completedAt || "").localeCompare(String(a.completedAt || "")) || b.ordinal - a.ordinal).slice(0, 10).map(item => ({ ...item, position: 0 })); return structuredClone([...active, ...failed]); }
  async claimQueued(args = {}) { const conversation = this.own(args, args.conversationId); if (!conversation) return null; const rows = this.queue.get(conversation.id) || []; if (rows.some(item => item.status === "running") || (this.messages.get(conversation.id) || []).some(item => item.role === "assistant" && ["pending", "streaming"].includes(item.generationStatus))) return null; const item = rows.filter(value => value.status === "queued").sort((a, b) => b.priority - a.priority || a.ordinal - b.ordinal)[0]; if (!item) return null; item.status = "running"; item.startedAt = new Date().toISOString(); return structuredClone(item); }
  async completeQueued(args = {}) { const conversation = this.own(args, args.conversationId); if (!conversation) return null; const id = normalizeConversationId(args.queueId); const status = args.status; if (!["completed", "failed", "cancelled"].includes(status)) fail("Stato coda non valido."); const item = (this.queue.get(conversation.id) || []).find(value => value.id === id && ["queued", "running"].includes(value.status)); if (!item) return null; item.status = status; item.turnId = args.turnId == null ? item.turnId : normalizeConversationId(args.turnId); item.errorCode = args.errorCode || null; item.completedAt = new Date().toISOString(); return structuredClone(item); }
  async cancelQueued(args = {}) { const conversation = this.own(args, args.conversationId); if (!conversation) return null; const id = normalizeConversationId(args.queueId); const item = (this.queue.get(conversation.id) || []).find(value => value.id === id && value.status === "queued"); if (!item) return null; item.status = "cancelled"; item.completedAt = new Date().toISOString(); return structuredClone(item); }
  async recoverQueuedOnStartup({ machineIds } = {}) { const allowed = new Set((machineIds || []).map(normalizeMachineId)); let count = 0; for (const conversation of this.conversations.values()) if (!conversation.deletedAt && allowed.has(conversation.machineId)) for (const item of this.queue.get(conversation.id) || []) if (item.status === "running") { item.status = item.turnId ? "failed" : "queued"; item.startedAt = null; item.errorCode = item.turnId ? "RESTART_INTERRUPTED" : null; count += 1; } return count; }

  async beginTurn(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const queueId = args.queueId == null ? null : normalizeConversationId(args.queueId);
    const messages = this.messages.get(conversation.id) || [];
    if (messages.some(item => item.role === "assistant" && ["pending", "streaming"].includes(item.generationStatus))) throw new ConversationStoreError("Conversazione già in generazione.", 409);
    const attachmentIds = normalizeAttachmentIds(args.attachmentIds);
    if (!queueId && attachmentIds.some(id => (this.queue.get(conversation.id) || []).some(item => ["queued", "running"].includes(item.status) && item.attachmentIds.includes(id)))) fail("Uno o più allegati sono già riservati nella coda.", 409);
    const pending = this.attachments.get(conversation.id) || [];
    const selected = attachmentIds.map(id => pending.find(item => item.id === id && !item.deletedAt && !item.messageId));
    if (selected.some(item => !item)) fail("Uno o più allegati non sono più disponibili.", 409);
    if (selected.filter(item => item.kind === "image").length > MAX_ATTACHMENT_IMAGES_PER_TURN) fail("Puoi inviare al massimo cinque immagini per messaggio.");
    const requestedMode = normalizeMode(args.requestedMode || "auto");
    const resolvedMode = args.resolvedMode == null ? (requestedMode === "auto" ? "fast" : requestedMode) : normalizeResolvedMode(args.resolvedMode);
    const turnId = randomUUID(); const now = new Date().toISOString();
    const user = { id: randomUUID(), conversationId: conversation.id, role: "user", content: normalizeContent(args.message), createdAt: now, updatedAt: now, requestedMode, resolvedMode, model: null, generationStatus: "completed", sources: [], toolMetadata: {}, ordinal: ++this.ordinal };
    const assistant = { id: randomUUID(), conversationId: conversation.id, role: "assistant", content: "", createdAt: now, updatedAt: now, requestedMode, resolvedMode, model: SERVER_AI_MODEL, generationStatus: "pending", sources: [], toolMetadata: {}, ordinal: ++this.ordinal, turnId };
    if (queueId) { const queued = (this.queue.get(conversation.id) || []).find(item => item.id === queueId && item.status === "running" && !item.turnId); if (!queued) fail("Coda conversazione non disponibile.", 409); queued.turnId = turnId; }
    selected.forEach(item => { item.messageId = user.id; });
    messages.push(user, assistant); this.messages.set(conversation.id, messages); conversation.summary = appendDeterministicSummary(conversation.summary, user); if (conversation.title === "Nuova chat") conversation.title = deriveConversationTitle(user.content); conversation.updatedAt = now;
    return { turnId, user: { ...structuredClone(user), attachments: selected.map(attachmentMetadata) }, assistant: structuredClone(assistant) };
  }
  async beginAttachmentContinuation(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const userId = normalizeConversationId(args.userMessageId); const requestId = normalizeRequestId(args.requestId); const scanId = normalizeConversationId(args.scanId);
    const messages = this.messages.get(conversation.id) || [];
    const existing = messages.find(item => item.role === "assistant" && item.toolMetadata?.autoContinuation?.requestId === requestId);
    if (existing && ["pending", "streaming", "completed"].includes(existing.generationStatus)) return { turnId: existing.turnId || null, user: null, assistant: structuredClone(existing), idempotent: true };
    if (messages.some(item => item.role === "assistant" && ["pending", "streaming"].includes(item.generationStatus))) return { blocked: true };
    if (existing && ["aborted", "failed"].includes(existing.generationStatus)) { existing.content = ""; existing.generationStatus = "pending"; existing.updatedAt = new Date().toISOString(); return { turnId: existing.turnId || null, user: null, assistant: structuredClone(existing), reclaimed: true }; }
    const original = messages.find(item => item.id === userId && item.role === "user" && item.generationStatus === "completed");
    if (!original) return null;
    const requestedMode = normalizeMode(args.requestedMode || "auto"); const resolvedMode = requestedMode === "auto" ? "fast" : requestedMode; const now = new Date().toISOString(); const turnId = randomUUID();
    const assistant = { id: randomUUID(), conversationId: conversation.id, role: "assistant", content: "", createdAt: now, updatedAt: now, requestedMode, resolvedMode, model: SERVER_AI_MODEL, generationStatus: "pending", sources: [], toolMetadata: { autoContinuation: { version: 1, requestId, scanId, userMessageId: userId } }, ordinal: ++this.ordinal, turnId };
    messages.push(assistant); this.messages.set(conversation.id, messages); conversation.updatedAt = now;
    return { turnId, user: null, assistant: structuredClone(assistant), idempotent: false };
  }
  async hasAttachmentContinuation(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return false;
    const requestId = normalizeRequestId(args.requestId); return (this.messages.get(conversation.id) || []).some(item => item.role === "assistant" && ["pending", "streaming", "completed"].includes(item.generationStatus) && item.toolMetadata?.autoContinuation?.requestId === requestId);
  }
  async getAttachmentContinuation(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const requestId = normalizeRequestId(args.requestId); const message = (this.messages.get(conversation.id) || []).find(item => item.role === "assistant" && item.toolMetadata?.autoContinuation?.requestId === requestId);
    return message ? { assistantId: message.id, turnId: message.turnId || null, generationStatus: message.generationStatus } : null;
  }
  async updateMessage(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const message = (this.messages.get(conversation.id) || []).find(item => item.id === args.messageId && item.role === "assistant" && ["pending", "streaming"].includes(item.generationStatus));
    if (!message) return null;
    message.generationStatus = normalizeGenerationStatus(args.generationStatus); if (message.generationStatus === "pending") fail("Lo stato pending si crea solo con beginTurn.");
    if (args.content !== undefined) message.content = typeof args.content === "string" && args.content.length <= MAX_CONTENT ? args.content : normalizeContent(args.content);
    if (args.sources !== undefined) message.sources = normalizeSources(args.sources);
    if (args.toolMetadata !== undefined) message.toolMetadata = { ...normalizeToolMetadata(args.toolMetadata), ...(message.toolMetadata?.autoContinuation ? { autoContinuation: structuredClone(message.toolMetadata.autoContinuation) } : {}) };
    message.updatedAt = new Date().toISOString(); return structuredClone(message);
  }
  async finishTurn(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const message = (this.messages.get(conversation.id) || []).find(item => item.turnId === normalizeTurnId(args.turnId) && item.role === "assistant" && ["pending", "streaming"].includes(item.generationStatus));
    if (!message) return null;
    const status = normalizeGenerationStatus(args.generationStatus); if (!["completed", "aborted", "failed"].includes(status)) fail("Lo stato terminale non è valido.");
    message.content = typeof args.content === "string" && args.content.length <= MAX_CONTENT ? args.content : normalizeContent(args.content); message.generationStatus = status; message.resolvedMode = normalizeResolvedMode(args.resolvedMode); message.sources = normalizeSources(args.sources); message.toolMetadata = { ...normalizeToolMetadata(args.toolMetadata), ...(message.toolMetadata?.autoContinuation ? { autoContinuation: structuredClone(message.toolMetadata.autoContinuation) } : {}) }; message.updatedAt = new Date().toISOString(); conversation.summary = appendDeterministicSummary(conversation.summary, message); conversation.updatedAt = message.updatedAt; return structuredClone(message);
  }
  async buildContext(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return null;
    const current = normalizeContent(args.currentMessage);
    const allMessages = this.messages.get(conversation.id) || [];
    const latestAssistant = [...allMessages].reverse().find(item => item.role === "assistant");
    const partialAssistantId = latestAssistant?.generationStatus === "aborted" && typeof latestAssistant.content === "string" && latestAssistant.content.trim()
      ? latestAssistant.id : null;
    const complete = allMessages
      .filter(item => item.generationStatus === "completed" || item.id === partialAssistantId)
      .map(item => ({
        role: item.role,
        content: item.id === partialAssistantId ? `[Risposta interrotta, parziale]\n${item.content}` : item.content,
        resolvedMode: item.resolvedMode,
        ordinal: item.ordinal,
      }));
    const stored = selectHistoricalMessages(complete, current, { limit: DEFAULT_CONTEXT_MESSAGE_LIMIT });
    const anchor = continuationAnchor(stored, current);
    const context = boundedRecentContext(stored, current, DEFAULT_CONTEXT_MESSAGE_LIMIT, MAX_CONTEXT_CHARS, anchor);
    return { messages: context, summary: summaryForContext(conversation.summary, stored, current), priorConversation: { turnCount: Math.floor(complete.length / 2), hasSummary: Boolean(conversation.summary), hasUnresolvedQuestion: Boolean(anchor) }, ...(anchor ? { continuationAnchor: anchor } : {}), projectId: conversation.projectId || null };
  }
  async getAttachmentContext(args = {}) {
    const conversation = this.own(args, args.conversationId); if (!conversation) return [];
    const ids = args.currentAttachmentIds == null ? null : normalizeAttachmentIds(args.currentAttachmentIds);
    const selectedIds = ids?.length ? ids : null;
    const all = (this.attachments.get(conversation.id) || []).filter(item => !item.deletedAt && item.messageId);
    const latest = selectedIds ? all.filter(item => selectedIds.includes(item.id)) : (() => { const messageId = [...all].filter(item => item.messageId).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))[0]?.messageId; return messageId ? all.filter(item => item.messageId === messageId) : []; })();
    if (selectedIds && latest.length !== selectedIds.length) return [];
    let textBytes = 0; let images = 0;
    return latest.slice(0, MAX_ATTACHMENT_FILES_PER_TURN).flatMap(item => {
      if (item.kind === "archive") {
        if (!item.objectKey || !item.archive || !this.attachmentStorage?.listArchiveEntries || !this.attachmentStorage?.openArchiveEntry) return [];
        const archiveScope = { ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id }; const materialized = new Set();
        return [{ ...attachmentMetadata(item), filename: item.filename, sha256: item.sha256, objectKey: item.objectKey, byteSize: item.size, text: null, archive: item.archive,
          listArchiveEntries: (options = {}) => this.attachmentStorage.listArchiveEntries(archiveScope, item.objectKey, options), openArchiveEntry: (entryId, options = {}) => this.attachmentStorage.openArchiveEntry(archiveScope, item.objectKey, entryId, options),
          ...(this.attachmentStorage.materializeArchiveTextEntry ? { materializeArchiveTextEntry: async (entryId, options = {}) => { const value = await this.attachmentStorage.materializeArchiveTextEntry(archiveScope, item.objectKey, entryId, options); if (value?.objectKey) materialized.add(value.objectKey); return value; }, readMaterializedText: (objectKey, options = {}) => { if (!materialized.has(objectKey)) throw new ConversationStoreError("Voce archivio non disponibile.", 404); return this.attachmentStorage.readText(objectKey, options); } } : {}),
        }];
      }
      if (item.kind === "document") {
        if (!item.objectKey || !item.document || typeof this.attachmentStorage?.readDocumentText !== "function") return [];
        const documentScope = { ownerId: conversation.ownerId, machineId: conversation.machineId, conversationId: conversation.id };
        return [{ ...attachmentMetadata(item), filename: item.filename, sha256: item.sha256, objectKey: item.objectKey, byteSize: item.size, text: item.text ?? "",
          document: item.document,
          readText: ({ startByte = 0, maxBytes = 12 * 1024, signal } = {}) => this.attachmentStorage.readDocumentText(documentScope, item.objectKey, { startByte, maxBytes, signal }) }];
      }
      if (item.kind === "image") { if (++images > MAX_ATTACHMENT_IMAGES_PER_TURN) return []; return [{ ...attachmentMetadata(item), filename: item.filename, sha256: item.sha256, image: Buffer.from(item.image).toString("base64") }]; }
      if (item.objectKey) {
        if (!this.attachmentStorage || typeof this.attachmentStorage.readText !== "function") return [];
        return [{ ...attachmentMetadata(item), filename: item.filename, sha256: item.sha256, objectKey: item.objectKey, byteSize: item.size, text: item.text || "",
          readText: ({ startByte = 0, maxBytes = 12 * 1024, signal } = {}) => this.attachmentStorage.readText(item.objectKey, { startByte, maxBytes, signal }) }];
      }
      const text = utf8Prefix(item.text || "", Math.max(0, MAX_ATTACHMENT_TEXT_CONTEXT_BYTES - textBytes)); textBytes += Buffer.byteLength(text); return text ? [{ ...attachmentMetadata(item), filename: item.filename, sha256: item.sha256, text, truncated: item.truncated || text !== item.text }] : [];
    });
  }
  async recoverOnStartup({ machineIds } = {}) { const allowed = new Set(machineIds.map(normalizeMachineId)); let count = 0; for (const [id, conversation] of this.conversations) if (allowed.has(conversation.machineId)) for (const message of this.messages.get(id) || []) if (["pending", "streaming"].includes(message.generationStatus)) { message.generationStatus = "aborted"; count += 1; } return count; }
}
