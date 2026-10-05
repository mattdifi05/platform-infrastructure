import { createHash, randomUUID } from "node:crypto";
import { spawn as spawnChild } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inspectZipFile } from "./zip-attachments.mjs";
import { redactText } from "./web.mjs";
import { DOCUMENT_EXTENSIONS, DOCUMENT_FORMATS } from "./document-formats.mjs";

const MAX_SOURCE_BYTES = 512 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_WORKER_JSON_BYTES = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 90_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 90_000;
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/;
const WORKER_PATH = fileURLToPath(new URL("./document_extract_worker.py", import.meta.url));

export { DOCUMENT_EXTENSIONS };
const DOCUMENT_ERROR_MESSAGES = Object.freeze({
  DOCUMENT_ENCRYPTED: "Il documento è protetto da password o cifrato.",
  DOCUMENT_MALFORMED: "Il documento è danneggiato o non è leggibile.",
  DOCUMENT_XML_INVALID: "Il contenuto XML del documento non è valido.",
  DOCUMENT_UNSAFE_XML: "Il documento contiene XML non sicuro.",
  DOCUMENT_ZIP_STRUCTURE: "La struttura interna del documento non è valida.",
  DOCUMENT_ZIP_BOMB: "Il documento supera i limiti di espansione consentiti.",
  DOCUMENT_XML_LIMIT: "Il contenuto strutturato supera il limite consentito.",
  DOCUMENT_UNSUPPORTED: "Questo formato documento non è disponibile.",
  DOCUMENT_TIMEOUT: "Tempo di estrazione esaurito.",
  DOCUMENT_ABORTED: "Estrazione annullata.",
  DOCUMENT_RESOURCE_GUARD: "Il lettore documenti non è disponibile in sicurezza.",
  NETWORK_GUARD_UNAVAILABLE: "Il lettore documenti non è disponibile in sicurezza.",
  DOCUMENT_RESOURCE_LIMIT: "Il lettore ha raggiunto il limite di risorse.",
  DOCUMENT_WORKER_UNAVAILABLE: "Lettore documenti non disponibile.",
});

const DOCUMENT_WARNING_MESSAGES = Object.freeze({
  MACROS_NOT_EXECUTED: "Le macro del documento non sono state eseguite.",
  IMAGE_ONLY_PDF: "Il PDF non contiene testo selezionabile.",
  OCR_NOT_AVAILABLE: "Le immagini non sono state convertite in testo.",
  NO_EXTRACTABLE_TEXT: "Non è stato trovato testo estraibile.",
  EXTRACTED_TEXT_TRUNCATED: "Il testo estratto è stato troncato al limite consentito.",
  REDACTED_TEXT_TRUNCATED: "Il testo normalizzato è stato troncato al limite consentito.",
  EPUB_PARTS_SKIPPED: "Alcune sezioni EPUB non sono state lette.",
  VISUAL_CONTENT_NOT_ANALYZED: "Elementi visivi e impaginazione non sono stati analizzati.",
  CACHED_FORMULA_VALUES: "Sono stati letti solo i valori già calcolati delle formule.",
  SPREADSHEET_FORMATTING_NOT_RENDERED: "Date, formati numerici e stili del foglio non sono stati interpretati.",
  ODS_CELLS_NOT_RECONSTRUCTED: "Le celle e le righe ripetute ODS sono state lette come testo, senza ricostruire la tabella.",
  XLS_EMBEDDED_FEATURES_IGNORED: "Macro, immagini e oggetti incorporati XLS non sono stati analizzati.",
  XLS_CELL_LIMIT: "Il foglio di calcolo supera il limite di celle leggibili.",
  PDF_PAGES_WITHOUT_TEXT: "Alcune pagine PDF non contengono testo selezionabile.",
});

export const DOCUMENT_ATTACHMENT_LIMITS = Object.freeze({
  maxSourceBytes: MAX_SOURCE_BYTES,
  maxExtractedBytes: MAX_OUTPUT_BYTES,
  timeoutMs: DEFAULT_TIMEOUT_MS,
  maxConcurrentExtractions: 1,
  formats: DOCUMENT_EXTENSIONS,
});

export class DocumentAttachmentError extends Error {
  constructor(code, message = "Documento non elaborabile.", status = 415) {
    super(message);
    this.name = "DocumentAttachmentError";
    this.code = code;
    this.status = status;
  }
}

function fail(code, message = "Documento non elaborabile.", status = 415) { throw new DocumentAttachmentError(code, message, status); }
function safeInteger(value, maximum, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) fail("INVALID_DOCUMENT_LIMIT", `${name} non valido.`, 500);
  return value;
}
function normalizeFilename(value) {
  if (typeof value !== "string") fail("INVALID_FILENAME", "Nome del documento non valido.");
  const filename = value.normalize("NFC").trim();
  if (!filename || filename === "." || filename === ".." || filename.includes("/") || filename.includes("\\")
      || CONTROL_OR_BIDI.test(filename) || [...filename].length > 180 || Buffer.byteLength(filename, "utf8") > 240) {
    fail("INVALID_FILENAME", "Nome del documento non valido.");
  }
  return filename;
}

export function classifyDocumentFilename(value) {
  const filename = normalizeFilename(value);
  const extension = extname(filename).toLowerCase();
  const format = DOCUMENT_FORMATS[extension];
  if (!format) fail("UNSUPPORTED_DOCUMENT", "Formato documento non supportato.", 415);
  return Object.freeze({ kind: "document", filename, extension, format, macrosIgnored: /m$/i.test(extension) });
}

export function documentCapabilities() {
  return Object.freeze({
    extensions: DOCUMENT_EXTENSIONS,
    maxFileBytes: MAX_SOURCE_BYTES,
    maxExtractedBytes: MAX_OUTPUT_BYTES,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    staticExtractionOnly: true,
    macroExecution: false,
    ocr: false,
  });
}

async function readPrefix(path, length = 8) {
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.nlink !== 1) fail("INVALID_DOCUMENT_SOURCE", "Documento non disponibile.", 409);
    const buffer = Buffer.alloc(length); const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return { info, prefix: buffer.subarray(0, bytesRead) };
  } finally { await handle.close(); }
}

function assertFormatMagic(format, prefix) {
  if (format === "pdf" && !prefix.subarray(0, 5).equals(Buffer.from("%PDF-"))) fail("TYPE_MISMATCH", "Il contenuto non corrisponde al documento dichiarato.");
  if (["docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"].includes(format)
      && !prefix.subarray(0, 4).equals(Buffer.from("PK\x03\x04")) && !prefix.subarray(0, 4).equals(Buffer.from("PK\x05\x06"))) {
    fail("TYPE_MISMATCH", "Il contenuto non corrisponde al documento dichiarato.");
  }
  if (format === "rtf" && !prefix.subarray(0, 5).toString("ascii").toLowerCase().startsWith("{\\rtf")) fail("TYPE_MISMATCH", "Il contenuto non corrisponde al documento dichiarato.");
  if (["doc", "xls"].includes(format) && !prefix.subarray(0, 8).equals(Buffer.from([0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1]))) {
    fail("TYPE_MISMATCH", "Il contenuto non corrisponde al documento dichiarato.");
  }
}

function clipUtf8(value, maximum) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maximum) return value;
  let end = maximum;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

function statusFor(code) {
  if (code === "DOCUMENT_TIMEOUT") return 504;
  if (code === "DOCUMENT_ABORTED") return 499;
  if (code === "DOCUMENT_TOO_LARGE" || code === "DOCUMENT_OUTPUT_LIMIT") return 413;
  if (["DOCUMENT_WORKER_UNAVAILABLE", "DOCUMENT_QUEUE_FULL", "DOCUMENT_RESOURCE_GUARD", "NETWORK_GUARD_UNAVAILABLE", "DOCUMENT_RESOURCE_LIMIT"].includes(code)) return 503;
  return 415;
}

function parseWorkerFailure(text) {
  try {
    const value = JSON.parse(text);
    const code = typeof value?.code === "string" && /^[A-Z0-9_]{1,64}$/.test(value.code) ? value.code : "DOCUMENT_WORKER_FAILED";
    return new DocumentAttachmentError(code, DOCUMENT_ERROR_MESSAGES[code] || "Documento non elaborabile.", statusFor(code));
  } catch { return new DocumentAttachmentError("DOCUMENT_RESOURCE_LIMIT", DOCUMENT_ERROR_MESSAGES.DOCUMENT_RESOURCE_LIMIT, 503); }
}

function parseWorkerResult(text) {
  if (Buffer.byteLength(text, "utf8") > MAX_WORKER_JSON_BYTES) fail("DOCUMENT_WORKER_INVALID", "Risposta del lettore non valida.", 500);
  let value;
  try { value = JSON.parse(text); } catch { fail("DOCUMENT_WORKER_INVALID", "Risposta del lettore non valida.", 500); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("DOCUMENT_WORKER_INVALID", "Risposta del lettore non valida.", 500);
  if (value.ok !== true) {
    const code = typeof value.code === "string" && /^[A-Z0-9_]{1,64}$/.test(value.code) ? value.code : "DOCUMENT_WORKER_FAILED";
    fail(code, "Documento non elaborabile.", statusFor(code));
  }
  const coverage = value.coverage;
  if (typeof value.format !== "string" || !["complete", "partial", "image_only", "unsupported"].includes(coverage?.state)
      || !Number.isSafeInteger(coverage.unitsRead) || coverage.unitsRead < 0 || !Number.isSafeInteger(coverage.unitsSkipped) || coverage.unitsSkipped < 0
      || !Array.isArray(coverage.warnings) || coverage.warnings.length > 16 || coverage.warnings.some(item => typeof item !== "string" || !/^[A-Z0-9_]{1,64}$/.test(item))) {
    fail("DOCUMENT_WORKER_INVALID", "Risposta del lettore non valida.", 500);
  }
  return { format: value.format, coverage: Object.freeze({ state: coverage.state, unitsRead: coverage.unitsRead, unitsSkipped: coverage.unitsSkipped,
    warnings: Object.freeze([...new Set(coverage.warnings.map(code => DOCUMENT_WARNING_MESSAGES[code] || "Alcune parti del documento non sono state elaborate."))]) }) };
}

function spawnWorker({ inputPath, outputPath, format, deadline, signal, pythonPath, workerPath }) {
  return new Promise((resolve, reject) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return reject(new DocumentAttachmentError("DOCUMENT_TIMEOUT", "Tempo di estrazione esaurito.", 504));
    const child = spawnChild(pythonPath, ["-I", workerPath, "--input", inputPath, "--output", outputPath, "--format", format], {
      stdio: ["ignore", "pipe", "pipe"], env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" }, windowsHide: true,
      detached: process.platform !== "win32",
    });
    const chunks = []; let stdoutBytes = 0; let stderrBytes = 0; let settled = false; let stopping = null; let termination = null;
    const killGroup = signalName => {
      // `detached` makes the Python worker a POSIX process-group leader. The
      // worker can spawn pdftotext/antiword children which inherit its pipes;
      // target the whole group, never only ChildProcess.killed.
      try {
        if (Number.isSafeInteger(child.pid) && child.pid > 0) {
          if (process.platform === "win32") child.kill(signalName);
          else process.kill(-child.pid, signalName);
        }
      } catch {}
    };
    const stop = error => {
      if (termination) return termination;
      stopping = error;
      // Spawn errors have no child process group. Do not leave a grace timer
      // behind in that case.
      if (!Number.isSafeInteger(child.pid) || child.pid <= 0) {
        termination = Promise.resolve();
        return termination;
      }
      killGroup("SIGTERM");
      // Always issue SIGKILL after the bounded grace period. A native child
      // can ignore TERM even when the Python leader has already closed.
      termination = new Promise(done => setTimeout(() => { killGroup("SIGKILL"); done(); }, 500));
      return termination;
    };
    const timer = setTimeout(() => stop(new DocumentAttachmentError("DOCUMENT_TIMEOUT", "Tempo di estrazione esaurito.", 504)), remaining);
    const onAbort = () => stop(new DocumentAttachmentError("DOCUMENT_ABORTED", "Estrazione annullata.", 499));
    const finish = (error, result) => {
      if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener("abort", onAbort);
      if (error) reject(error); else resolve(result);
    };
    if (signal?.aborted) { stop(new DocumentAttachmentError("DOCUMENT_ABORTED", "Estrazione annullata.", 499)); }
    else signal?.addEventListener("abort", onAbort, { once: true });
    child.once("error", () => {
      void stop(new DocumentAttachmentError("DOCUMENT_WORKER_UNAVAILABLE", "Lettore documenti non disponibile.", 503)).then(() => {
        if (!Number.isSafeInteger(child.pid) || child.pid <= 0) finish(stopping);
      });
    });
    child.stdout.on("data", chunk => {
      if (stopping) return;
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_WORKER_JSON_BYTES) { stop(new DocumentAttachmentError("DOCUMENT_WORKER_INVALID", "Risposta del lettore non valida.", 500)); return; }
      chunks.push(chunk);
    });
    child.stderr.on("data", chunk => { stderrBytes += chunk.length; if (stderrBytes > 1024) stop(new DocumentAttachmentError("DOCUMENT_WORKER_INVALID", "Risposta del lettore non valida.", 500)); });
    child.once("close", code => {
      if (stopping) return void Promise.resolve(termination).then(() => finish(stopping));
      const stdout = Buffer.concat(chunks).toString("utf8");
      if (code !== 0) return finish(stdout ? parseWorkerFailure(stdout) : new DocumentAttachmentError("DOCUMENT_RESOURCE_LIMIT", DOCUMENT_ERROR_MESSAGES.DOCUMENT_RESOURCE_LIMIT, 503));
      try { finish(null, parseWorkerResult(stdout)); } catch (error) { finish(error); }
    });
  });
}
let active = false; const waiters = [];
async function acquire(signal, deadline) {
  if (!active) { active = true; return () => release(); }
  if (waiters.length >= 4) throw new DocumentAttachmentError("DOCUMENT_QUEUE_FULL", "Lettore documenti occupato.", 503);
  return new Promise((resolve, reject) => {
    let timer;
    const waiter = () => { clearTimeout(timer); active = true; signal?.removeEventListener("abort", abort); resolve(() => release()); };
    const abort = () => { clearTimeout(timer); const index = waiters.indexOf(waiter); if (index >= 0) waiters.splice(index, 1); reject(new DocumentAttachmentError("DOCUMENT_ABORTED", "Estrazione annullata.", 499)); };
    const expire = () => { const index = waiters.indexOf(waiter); if (index >= 0) waiters.splice(index, 1); signal?.removeEventListener("abort", abort); reject(new DocumentAttachmentError("DOCUMENT_TIMEOUT", "Tempo di estrazione esaurito.", 504)); };
    if (signal?.aborted) return abort();
    const remaining = deadline - Date.now(); if (remaining <= 0) return expire();
    waiters.push(waiter); timer = setTimeout(expire, remaining); signal?.addEventListener("abort", abort, { once: true });
  });
}
function release() { const next = waiters.shift(); if (next) next(); else active = false; }
/** Extracts text into a private, caller-owned path. No user-controlled path is ever returned. */
export async function extractDocumentFile({ inputPath, outputPath, filename, signal, timeoutMs = DEFAULT_TIMEOUT_MS, pythonPath = "/usr/bin/python3", workerPath = WORKER_PATH } = {}) {
  if (typeof inputPath !== "string" || !isAbsolute(inputPath) || typeof outputPath !== "string" || !isAbsolute(outputPath) || inputPath === outputPath) {
    fail("INVALID_DOCUMENT_PATH", "Percorso documento non valido.", 500);
  }
  const type = classifyDocumentFilename(filename);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) fail("INVALID_DOCUMENT_TIMEOUT", "Tempo di estrazione non valido.", 500);
  const { info, prefix } = await readPrefix(inputPath);
  if (info.size < 1 || info.size > MAX_SOURCE_BYTES) fail("DOCUMENT_TOO_LARGE", "Documento oltre il limite consentito.", 413);
  assertFormatMagic(type.format, prefix);
  if (!["pdf", "rtf", "doc", "xls", "ppt"].includes(type.format)) await inspectZipFile(inputPath, { signal });
  await access(workerPath, fsConstants.R_OK);
  const deadline = Date.now() + timeoutMs;
  const releaseSlot = await acquire(signal, deadline);
  const temporaryOutput = join(dirname(outputPath), `.${randomUUID()}.document.tmp`);
  try {
    const result = await spawnWorker({ inputPath, outputPath: temporaryOutput, format: type.format, deadline, signal, pythonPath, workerPath });
    const extracted = await readFile(temporaryOutput);
    const extractedTruncated = extracted.length > MAX_OUTPUT_BYTES;
    const rawText = clipUtf8(extracted.toString("utf8"), MAX_OUTPUT_BYTES);
    const redacted = redactText(rawText, MAX_OUTPUT_BYTES * 2).trim();
    const text = clipUtf8(redacted, MAX_OUTPUT_BYTES);
    const bytes = Buffer.from(text, "utf8");
    const redactionTruncated = bytes.length < Buffer.byteLength(redacted, "utf8");
    const coverage = (extractedTruncated || redactionTruncated) ? Object.freeze({ state: "partial", unitsRead: result.coverage.unitsRead, unitsSkipped: result.coverage.unitsSkipped,
      warnings: Object.freeze([...new Set([...result.coverage.warnings, ...(extractedTruncated ? ["Il testo estratto è stato troncato al limite consentito."] : []), ...(redactionTruncated ? ["Il testo normalizzato è stato troncato al limite consentito."] : [])])]) }) : result.coverage;
    await writeFile(temporaryOutput, bytes, { flag: "w", mode: 0o600 });
    await rename(temporaryOutput, outputPath);
    return Object.freeze({ kind: "document", format: result.format, textPath: outputPath, textBytes: bytes.length, sourceBytes: info.size,
      coverage, sha256: createHash("sha256").update(bytes).digest("hex") });
  } finally {
    releaseSlot(); await rm(temporaryOutput, { force: true }).catch(() => {});
  }
}
