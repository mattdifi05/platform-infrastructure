import { createHash } from "node:crypto";
import { extname } from "node:path";
import Busboy from "busboy";
import sharp from "sharp";
import { redactText } from "./web.mjs";
import { ZIP_ATTACHMENT_LIMITS } from "./zip-attachments.mjs";
import { DOCUMENT_EXTENSIONS, DOCUMENT_MEDIA_TYPES } from "./document-formats.mjs";

const LEGACY_MAX_TEXT_BYTES = 256 * 1024;
const LEGACY_MAX_IMAGE_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const UPLOAD_CHUNK_BYTES = 4 * 1024 * 1024;
const MAX_IMAGE_OUTPUT_BYTES = 1024 * 1024;
const MULTIPART_OVERHEAD_BYTES = 64 * 1024;
const MAX_IMAGE_PIXELS = 25_000_000;
const MAX_IMAGE_DIMENSION = 1600;
const MAX_FILENAME_BYTES = 240;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_IMAGE_JOBS = 2;
const MAX_IMAGE_WAITERS = 4;

const IMAGE_EXTENSIONS = Object.freeze([".avif", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"]);
const ARCHIVE_EXTENSIONS = Object.freeze([".zip"]);
const TEXT_EXTENSIONS = Object.freeze([
  ".astro", ".bash", ".bat", ".c", ".cc", ".cjs", ".clj", ".cljc", ".cljs", ".cmake", ".cmd",
  ".conf", ".cpp", ".cs", ".css", ".csv", ".cxx", ".dart", ".dockerfile", ".edn", ".env.example",
  ".erl", ".ex", ".exs", ".fs", ".fsx", ".gql", ".go", ".gradle", ".graphql", ".groovy", ".h",
  ".hcl", ".hpp", ".hrl", ".hs", ".htm", ".html", ".ini", ".ipynb", ".java", ".js", ".json",
  ".jsonl", ".jsx", ".kt", ".kts", ".less", ".lhs", ".lock", ".log", ".lua", ".m", ".markdown",
  ".md", ".mjs", ".mm", ".nim", ".pas", ".php", ".phtml", ".pl", ".pm", ".prisma", ".properties",
  ".proto", ".ps1", ".py", ".r", ".rb", ".rs", ".rst", ".sass", ".scala", ".scss", ".sh", ".sol",
  ".sql", ".svelte", ".sv", ".svg", ".swift", ".tex", ".text", ".tf", ".tfvars", ".toml", ".ts",
  ".tsv", ".tsx", ".txt", ".v", ".vb", ".vbs", ".vhd", ".vhdl", ".vue", ".xml", ".yaml", ".yml",
  ".zig", ".zsh",
]);
const TEXT_BASENAMES = new Set([
  "cmakelists.txt", "containerfile", "dockerfile", "gemfile", "license", "makefile", "rakefile", "readme",
  ".dockerignore", ".editorconfig", ".env.example", ".gitignore",
]);
const DENIED_BASENAME = /^(?:id_rsa|id_ed25519|authorized_keys|shadow|passwd|cookies\.txt|(?:credentials?|secrets?|passwords?|tokens?)(?:\.json|\.ya?ml|\.toml|\.ini|\.conf|\.txt))$/i;
const DENIED_EXTENSION = /\.(?:7z|a|apk|app|bin|bz2|class|db|dll|dmg|dmp|dump|exe|gz|heic|heif|iso|jar|key|lib|o|obj|p12|pfx|pem|rar|so|sqlite|sqlite3|tar|wasm|xz)$/i;
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/;
const BAD_TEXT_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const IMAGE_FORMAT_BY_EXTENSION = Object.freeze({
  ".avif": "heif", ".gif": "gif", ".jpeg": "jpeg", ".jpg": "jpeg", ".png": "png",
  ".tif": "tiff", ".tiff": "tiff", ".webp": "webp",
});

export const ATTACHMENT_CAPABILITIES = deepFreeze({
  maxFilesPerTurn: 5,
  maxImagesPerTurn: 5,
  maxTextBytes: MAX_FILE_BYTES,
  maxImageInputBytes: MAX_FILE_BYTES,
  maxFileBytes: MAX_FILE_BYTES,
  chunkBytes: UPLOAD_CHUNK_BYTES,
  maxPendingUploads: 8,
  conversationQuotaBytes: 4 * 1024 * 1024 * 1024,
  ownerQuotaBytes: 8 * 1024 * 1024 * 1024,
  globalQuotaBytes: 16 * 1024 * 1024 * 1024,
  minFreeBytes: 1024 * 1024 * 1024,
  legacyMultipartMaxTextBytes: LEGACY_MAX_TEXT_BYTES,
  legacyMultipartMaxImageInputBytes: LEGACY_MAX_IMAGE_INPUT_BYTES,
  maxImageOutputBytes: MAX_IMAGE_OUTPUT_BYTES,
  maxImagePixels: MAX_IMAGE_PIXELS,
  maxImageWidth: MAX_IMAGE_DIMENSION,
  maxImageHeight: MAX_IMAGE_DIMENSION,
  imageOutputMediaType: "image/jpeg",
  archiveExtensions: ARCHIVE_EXTENSIONS,
  maxArchiveEntries: ZIP_ATTACHMENT_LIMITS.maxEntries,
  maxArchiveEntryBytes: ZIP_ATTACHMENT_LIMITS.maxEntryBytes,
  maxArchiveExpandedBytes: ZIP_ATTACHMENT_LIMITS.maxTotalUncompressedBytes,
  maxArchiveCompressionRatio: ZIP_ATTACHMENT_LIMITS.maxCompressionRatio,
  imageExtensions: IMAGE_EXTENSIONS,
  documentExtensions: DOCUMENT_EXTENSIONS,
  documentMediaTypes: DOCUMENT_MEDIA_TYPES,
  maxDocumentExtractedBytes: 16 * 1024 * 1024,
  textExtensions: TEXT_EXTENSIONS,
  textBasenames: Object.freeze([...TEXT_BASENAMES]),
});

export class AttachmentError extends Error {
  constructor(code, message, status = 400, diagnostics = null) {
    super(message);
    this.name = "AttachmentError";
    this.code = code;
    this.status = status;
    if (diagnostics) this.diagnostics = Object.freeze({ ...diagnostics });
  }
}

function fail(code, message, status = 400) { throw new AttachmentError(code, message, status); }
function deepFreeze(value) {
  if (value && typeof value === "object") Object.values(value).forEach(deepFreeze);
  return Object.freeze(value);
}

export function attachmentCapabilities() { return ATTACHMENT_CAPABILITIES; }

export function normalizeAttachmentFilename(value) {
  if (typeof value !== "string") fail("INVALID_FILENAME", "Nome del file non valido.");
  const filename = value.normalize("NFC").trim();
  if (!filename || filename === "." || filename === ".." || [...filename].length > 180 || filename.includes("/") || filename.includes("\\")
      || CONTROL_OR_BIDI.test(filename) || Buffer.byteLength(filename, "utf8") > MAX_FILENAME_BYTES
      || DENIED_BASENAME.test(filename) || DENIED_EXTENSION.test(filename)) {
    fail("INVALID_FILENAME", "Nome del file non valido.");
  }
  const lower = filename.toLowerCase();
  if (lower === ".env" || (lower.startsWith(".") && !TEXT_BASENAMES.has(lower))) {
    fail("UNSUPPORTED_FILE", "Tipo di file non supportato.", 415);
  }
  return filename;
}

export function classifyAttachmentFilename(filename) {
  const lower = filename.toLowerCase();
  const special = [...TEXT_EXTENSIONS].find(extension => extension.includes(".") && lower.endsWith(extension));
  const extension = special || extname(lower);
  if (ARCHIVE_EXTENSIONS.includes(extension)) return { kind: "archive", extension };
  if (IMAGE_EXTENSIONS.includes(extension)) return { kind: "image", extension };
  if (DOCUMENT_EXTENSIONS.includes(extension)) return { kind: "document", extension, mediaType: DOCUMENT_MEDIA_TYPES[extension] };
  if (TEXT_EXTENSIONS.includes(extension) || TEXT_BASENAMES.has(lower) || TEXT_BASENAMES.has(lower.replace(/\.[^.]+$/, ""))) {
    return { kind: "text", extension };
  }
  fail("UNSUPPORTED_FILE", "Tipo di file non supportato.", 415);
}

export function documentMediaTypeForFilename(filename) {
  const normalized = normalizeAttachmentFilename(filename);
  const type = classifyAttachmentFilename(normalized);
  if (type.kind !== "document") fail("TYPE_MISMATCH", "Il file non è un documento supportato.", 415);
  return type.mediaType;
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }

export function isKnownBinaryAttachment(bytes) {
  if (bytes.length >= 4) {
    const first4 = bytes.subarray(0, 4).toString("hex");
    if (["7f454c46", "89504e47", "25504446", "504b0304", "504b0506", "504b0708", "4d5a9000", "7f454c46", "feedface", "feedfacf", "cafebabe", "23217f45"].includes(first4)) return true;
    if (["4d4d002a", "49492a00", "47494638", "1f8b0800", "28b52ffd"].includes(first4)) return true;
  }
  if (bytes.length >= 12 && bytes.subarray(0, 4).toString("ascii") === "RIFF" && bytes.subarray(8, 12).toString("ascii") === "WEBP") return true;
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return true;
  if (bytes.length >= 16 && bytes.subarray(4, 12).toString("ascii") === "ftypavif") return true;
  return false;
}

function normalizeText(filename, bytes) {
  if (bytes.length < 1) fail("EMPTY_FILE", "Il file è vuoto.");
  if (bytes.length > LEGACY_MAX_TEXT_BYTES) fail("TEXT_TOO_LARGE", "Il file di testo supera 256 KiB.", 413);
  if (isKnownBinaryAttachment(bytes)) fail("TYPE_MISMATCH", "Il contenuto del file non corrisponde al tipo dichiarato.", 415);
  const source = bytes.subarray(bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0);
  let decoded;
  try { decoded = new TextDecoder("utf-8", { fatal: true }).decode(source); }
  catch { fail("INVALID_TEXT", "Il file non contiene testo UTF-8 valido.", 415); }
  if (BAD_TEXT_CONTROL.test(decoded)) fail("INVALID_TEXT", "Il file contiene dati binari non consentiti.", 415);
  // Redaction can expand a short value to "[redatto]". Give it enough room
  // to avoid silent clipping, then enforce the byte limit on the final text.
  const text = redactText(decoded, LEGACY_MAX_TEXT_BYTES * 4);
  const safeBytes = Buffer.from(text, "utf8");
  if (!safeBytes.length) fail("EMPTY_FILE", "Il file è vuoto.");
  if (safeBytes.length > LEGACY_MAX_TEXT_BYTES) fail("TEXT_TOO_LARGE", "Il file di testo supera 256 KiB dopo la normalizzazione.", 413);
  return {
    kind: "text", filename, mediaType: "text/plain", byteSize: safeBytes.length,
    sha256: sha256(safeBytes), text, image: null, width: null, height: null, truncated: false,
  };
}

let activeImageJobs = 0;
const imageWaiters = [];

function acquireImageSlot(signal, deadline) {
  if (signal?.aborted) fail("UPLOAD_ABORTED", "Caricamento annullato.", 499);
  if (activeImageJobs < MAX_IMAGE_JOBS) { activeImageJobs += 1; return Promise.resolve(); }
  if (imageWaiters.length >= MAX_IMAGE_WAITERS) fail("IMAGE_BUSY", "Elaborazione immagini temporaneamente occupata.", 429);
  return new Promise((resolve, reject) => {
    const waiter = { resolve, reject, signal, abort: null, timer: null };
    waiter.abort = () => {
      const index = imageWaiters.indexOf(waiter);
      if (index >= 0) imageWaiters.splice(index, 1);
      clearTimeout(waiter.timer);
      reject(new AttachmentError("UPLOAD_ABORTED", "Caricamento annullato.", 499));
    };
    waiter.timer = setTimeout(() => {
      const index = imageWaiters.indexOf(waiter);
      if (index >= 0) imageWaiters.splice(index, 1);
      signal?.removeEventListener("abort", waiter.abort);
      reject(new AttachmentError("IMAGE_TIMEOUT", "Elaborazione immagine scaduta.", 408));
    }, remainingMs(deadline));
    signal?.addEventListener("abort", waiter.abort, { once: true });
    imageWaiters.push(waiter);
  });
}

function releaseImageSlot() {
  const next = imageWaiters.shift();
  if (next) {
    clearTimeout(next.timer);
    next.signal?.removeEventListener("abort", next.abort);
    next.resolve();
  } else {
    activeImageJobs = Math.max(0, activeImageJobs - 1);
  }
}

function remainingMs(deadline) { return Math.max(1, deadline - Date.now()); }

async function sharpDeadline(pipeline, promise, deadline, signal) {
  let timer;
  let abort;
  const interrupted = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new AttachmentError("IMAGE_TIMEOUT", "Elaborazione immagine scaduta.", 408)), remainingMs(deadline));
    abort = () => reject(new AttachmentError("UPLOAD_ABORTED", "Caricamento annullato.", 499));
    signal?.addEventListener("abort", abort, { once: true });
  });
  try { return await Promise.race([promise, interrupted]); }
  catch (error) { pipeline.destroy?.(); throw error; }
  finally { clearTimeout(timer); signal?.removeEventListener("abort", abort); }
}

function validateImageMetadata(metadata, extension) {
  const expected = IMAGE_FORMAT_BY_EXTENSION[extension];
  if (!expected || metadata.format !== expected || (extension === ".avif" && metadata.compression && metadata.compression !== "av1")) {
    fail("TYPE_MISMATCH", "Il contenuto dell'immagine non corrisponde all'estensione.", 415);
  }
  if (!Number.isSafeInteger(metadata.width) || !Number.isSafeInteger(metadata.height) || metadata.width < 1 || metadata.height < 1
      || metadata.width * metadata.height > MAX_IMAGE_PIXELS) {
    fail("IMAGE_DIMENSIONS", "Dimensioni immagine non consentite.", 413);
  }
}

async function renderJpeg(source, { dimension, quality, deadline, signal }) {
  const pipeline = sharp(source, { pages: 1, limitInputPixels: MAX_IMAGE_PIXELS, failOn: "error" })
    .autoOrient()
    .resize({ width: dimension, height: dimension, fit: "inside", withoutEnlargement: true })
    .flatten({ background: "#ffffff" })
    .jpeg({ quality, chromaSubsampling: "4:2:0" })
    .timeout({ seconds: Math.max(1, Math.ceil(remainingMs(deadline) / 1000)) });
  return sharpDeadline(pipeline, pipeline.toBuffer(), deadline, signal);
}

async function normalizeImage(filename, extension, source, { signal, timeoutMs, byteSize, maxInputBytes }) {
  if (byteSize < 1) fail("EMPTY_FILE", "Il file è vuoto.");
  if (byteSize > maxInputBytes) fail("IMAGE_TOO_LARGE", `L'immagine supera ${Math.floor(maxInputBytes / (1024 * 1024))} MiB.`, 413);
  const deadline = Date.now() + timeoutMs;
  await acquireImageSlot(signal, deadline);
  try {
    // Metadata parsing does not decode pixels. Read dimensions first so an
    // oversized image gets a precise limit error before any raster allocation.
    const probe = sharp(source, { pages: 1, limitInputPixels: false, failOn: "error" })
      .timeout({ seconds: Math.max(1, Math.ceil(remainingMs(deadline) / 1000)) });
    let metadata;
    try { metadata = await sharpDeadline(probe, probe.metadata(), deadline, signal); }
    catch (error) {
      if (error instanceof AttachmentError) throw error;
      fail("INVALID_IMAGE", "Immagine non valida o non decodificabile.", 415);
    }
    validateImageMetadata(metadata, extension);
    let image;
    for (const [dimension, quality] of [[1600, 85], [1600, 72], [1440, 70], [1280, 68], [1024, 65], [800, 60], [640, 55]]) {
      try { image = await renderJpeg(source, { dimension, quality, deadline, signal }); }
      catch (error) {
        if (error instanceof AttachmentError) throw error;
        fail("INVALID_IMAGE", "Immagine non valida o non decodificabile.", 415);
      }
      if (image.length <= MAX_IMAGE_OUTPUT_BYTES) break;
    }
    if (!image || image.length > MAX_IMAGE_OUTPUT_BYTES) fail("IMAGE_OUTPUT_TOO_LARGE", "Impossibile ridurre l'immagine entro il limite consentito.", 413);
    const normalizedProbe = sharp(image).timeout({ seconds: Math.max(1, Math.ceil(remainingMs(deadline) / 1000)) });
    const normalized = await sharpDeadline(normalizedProbe, normalizedProbe.metadata(), deadline, signal).catch(() => null);
    if (!normalized || normalized.format !== "jpeg" || !Number.isSafeInteger(normalized.width) || !Number.isSafeInteger(normalized.height)
        || normalized.width > MAX_IMAGE_DIMENSION || normalized.height > MAX_IMAGE_DIMENSION) {
      fail("INVALID_IMAGE_OUTPUT", "Normalizzazione immagine non riuscita.", 500);
    }
    return {
      kind: "image", filename, mediaType: "image/jpeg", byteSize: image.length,
      sha256: sha256(image), text: null, image, width: normalized.width, height: normalized.height, truncated: false,
    };
  } finally {
    releaseImageSlot();
  }
}

export async function normalizeAttachmentUpload(upload, { signal, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (!upload || typeof upload !== "object" || Array.isArray(upload) || !Buffer.isBuffer(upload.bytes)) {
    fail("INVALID_UPLOAD", "Caricamento non valido.");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) fail("INVALID_TIMEOUT", "Limite di tempo non valido.");
  const filename = normalizeAttachmentFilename(upload.filename);
  const type = classifyAttachmentFilename(filename);
  if (type.kind === "text") return normalizeText(filename, upload.bytes);
  if (type.kind === "archive") fail("ARCHIVE_REQUIRES_RESUMABLE", "Gli archivi ZIP richiedono il caricamento riprendibile.", 409);
  if (type.kind === "document") fail("DOCUMENT_REQUIRES_RESUMABLE", "I documenti richiedono il caricamento riprendibile.", 409);
  return normalizeImage(filename, type.extension, upload.bytes, {
    signal, timeoutMs, byteSize: upload.bytes.length, maxInputBytes: LEGACY_MAX_IMAGE_INPUT_BYTES,
  });
}

export async function normalizeAttachmentImageFile({ filename: value, path, byteSize }, { signal, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof path !== "string" || !Number.isSafeInteger(byteSize)) fail("INVALID_UPLOAD", "Caricamento non valido.");
  if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) fail("INVALID_TIMEOUT", "Limite di tempo non valido.");
  const filename = normalizeAttachmentFilename(value);
  const type = classifyAttachmentFilename(filename);
  if (type.kind !== "image") fail("TYPE_MISMATCH", "Il file non è un'immagine supportata.", 415);
  return normalizeImage(filename, type.extension, path, { signal, timeoutMs, byteSize, maxInputBytes: MAX_FILE_BYTES });
}

export function readMultipartAttachment(req, { signal, timeoutMs = DEFAULT_TIMEOUT_MS, maxFileBytes = LEGACY_MAX_IMAGE_INPUT_BYTES } = {}) {
  if (!req || typeof req.pipe !== "function" || String(req.method || "").toUpperCase() !== "POST") {
    return Promise.reject(new AttachmentError("INVALID_UPLOAD", "Caricamento non valido."));
  }
  const lengthText = String(req.headers?.["content-length"] || "");
  if (!/^\d{1,12}$/.test(lengthText)) return Promise.reject(new AttachmentError("LENGTH_REQUIRED", "Dimensione del caricamento richiesta.", 411));
  const length = Number(lengthText);
  const abortDetails = receivedBytes => ({
    receivedBytes,
    expectedBytes: Number.isSafeInteger(length) ? length : null,
    complete: req.complete === true,
    readableEnded: req.readableEnded === true,
  });
  const abortedError = receivedBytes => new AttachmentError("UPLOAD_ABORTED", "Caricamento annullato.", 499, abortDetails(receivedBytes));
  if (signal?.aborted || req.aborted === true) {
    const error = abortedError(0);
    console.warn(JSON.stringify({ event: "server_ai_attachment_upload_aborted", ...error.diagnostics }));
    return Promise.reject(error);
  }
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1 || maxFileBytes > MAX_FILE_BYTES) {
    return Promise.reject(new AttachmentError("INVALID_UPLOAD_LIMIT", "Limite del caricamento non valido."));
  }
  const maxMultipartBytes = maxFileBytes + MULTIPART_OVERHEAD_BYTES;
  if (!Number.isSafeInteger(length) || length < 1 || length > maxMultipartBytes) {
    return Promise.reject(new AttachmentError("UPLOAD_TOO_LARGE", "Caricamento troppo grande.", 413));
  }
  if (req.headers?.["transfer-encoding"]) return Promise.reject(new AttachmentError("INVALID_UPLOAD", "Codifica del caricamento non consentita."));
  if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) return Promise.reject(new AttachmentError("INVALID_TIMEOUT", "Limite di tempo non valido."));

  let parser;
  try {
    parser = Busboy({
      headers: req.headers,
      // Keep any client-supplied path markers visible so normalizeFilename()
      // rejects them instead of silently accepting Busboy's basename.
      preservePath: true,
      defParamCharset: "utf8",
      // Busboy emits *Limit when the configured count is reached, so allow it
      // to surface a second part and reject that part explicitly below.
      // One byte above the policy limit distinguishes an exact-size chunk
      // from Busboy's `limit` event, which fires when the configured count is
      // reached. The explicit byte counter below still rejects that byte.
      limits: { fileSize: maxFileBytes + 1, files: 2, fields: 1, parts: 2, headerPairs: 16, fieldNameSize: 32 },
    });
  } catch {
    return Promise.reject(new AttachmentError("INVALID_MULTIPART", "Formato multipart non valido."));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let failure = null;
    let seenFile = false;
    let received = 0;
    let fileResult = null;
    let filePromise = null;
    let abortReported = false;
    const abortSignal = signal;
    const safeError = error => error instanceof AttachmentError ? error : new AttachmentError("INVALID_MULTIPART", "Caricamento multipart non valido.");
    const remember = error => { if (!failure) failure = safeError(error); };
    const cleanup = () => {
      clearTimeout(timer);
      abortSignal?.removeEventListener("abort", onAbort);
      req.removeListener("aborted", onRequestAborted);
      req.removeListener("error", onRequestError);
      req.removeListener("data", onRequestData);
    };
    const finishReject = error => {
      if (settled) return;
      if (error?.code === "UPLOAD_ABORTED" && !abortReported) {
        abortReported = true;
        console.warn(JSON.stringify({ event: "server_ai_attachment_upload_aborted", ...(error.diagnostics || abortDetails(received)) }));
      }
      settled = true; cleanup(); reject(safeError(error));
    };
    const onAbort = () => {
      remember(abortedError(received));
      req.unpipe(parser); parser.destroy(); req.resume(); finishReject(failure);
    };
    const requestBodyIsComplete = () => req.complete === true
      && req.readableEnded === true
      && received === length;
    // Node may emit `aborted` after a reverse proxy has delivered the entire
    // declared body and the IncomingMessage has already ended. At that point
    // the multipart parser still owns a complete, bounded body, so let it
    // finish. An explicit caller abort remains authoritative through onAbort.
    const onRequestAborted = () => {
      if (requestBodyIsComplete()) return;
      finishReject(abortedError(received));
    };
    const onRequestError = () => finishReject(new AttachmentError("INVALID_MULTIPART", "Caricamento multipart interrotto."));
    const onRequestData = chunk => {
      received += chunk.length;
      if (received > maxMultipartBytes) {
        remember(new AttachmentError("UPLOAD_TOO_LARGE", "Caricamento troppo grande.", 413));
        req.unpipe(parser); parser.destroy(); req.resume(); finishReject(failure);
      }
    };
    const timer = setTimeout(() => {
      remember(new AttachmentError("UPLOAD_TIMEOUT", "Caricamento scaduto.", 408));
      req.unpipe(parser); parser.destroy(); req.resume(); finishReject(failure);
    }, timeoutMs);
    abortSignal?.addEventListener("abort", onAbort, { once: true });
    req.once("aborted", onRequestAborted);
    req.once("error", onRequestError);
    req.on("data", onRequestData);

    parser.on("file", (field, file, info) => {
      if (seenFile || field !== "file") remember(new AttachmentError("INVALID_MULTIPART", "È consentito un solo campo file."));
      seenFile = true;
      const chunks = [];
      let bytes = 0;
      let limited = false;
      file.on("limit", () => { limited = true; remember(new AttachmentError("UPLOAD_TOO_LARGE", "File troppo grande.", 413)); });
      file.on("data", chunk => { bytes += chunk.length; if (bytes <= maxFileBytes) chunks.push(chunk); else remember(new AttachmentError("UPLOAD_TOO_LARGE", "File troppo grande.", 413)); });
      file.on("error", () => remember(new AttachmentError("INVALID_MULTIPART", "File multipart non valido.")));
      filePromise = new Promise(fileResolve => file.on("end", () => {
        if (limited || file.truncated) remember(new AttachmentError("UPLOAD_TOO_LARGE", "File troppo grande.", 413));
        fileResult = { filename: info.filename, clientMediaType: String(info.mimeType || ""), bytes: Buffer.concat(chunks) };
        fileResolve();
      }));
      file.resume();
    });
    parser.on("field", () => remember(new AttachmentError("INVALID_MULTIPART", "I campi multipart aggiuntivi non sono consentiti.")));
    parser.on("filesLimit", () => remember(new AttachmentError("INVALID_MULTIPART", "È consentito un solo file.")));
    parser.on("fieldsLimit", () => remember(new AttachmentError("INVALID_MULTIPART", "I campi multipart aggiuntivi non sono consentiti.")));
    parser.on("partsLimit", () => remember(new AttachmentError("INVALID_MULTIPART", "È consentita una sola parte multipart.")));
    parser.on("error", error => {
      req.unpipe(parser);
      req.resume();
      finishReject(safeError(error));
    });
    parser.on("close", async () => {
      if (settled) return;
      try { if (filePromise) await filePromise; } catch { remember(new AttachmentError("INVALID_MULTIPART", "File multipart non valido.")); }
      if (received !== length) remember(abortedError(received));
      if (!seenFile || !fileResult) remember(new AttachmentError("FILE_REQUIRED", "Seleziona un file."));
      if (failure) { finishReject(failure); return; }
      settled = true; cleanup(); resolve(fileResult);
    });
    req.pipe(parser);
  });
}

export async function readAndNormalizeAttachment(req, options = {}) {
  const upload = await readMultipartAttachment(req, options);
  return normalizeAttachmentUpload(upload, options);
}
