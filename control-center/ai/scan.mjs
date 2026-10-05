import { createHash } from "node:crypto";
import { redactText } from "./web.mjs";

export const SCAN_WINDOW_BYTES = 12 * 1024;
export const SCAN_SLICE_MS = 20 * 60 * 1000;
export const SCAN_SEGMENT_SUMMARY_BYTES = 768;
export const SCAN_PUBLIC_SUMMARY_BYTES = 8 * 1024;
const CHECKPOINT_BYTES = 1024 * 1024;
const CHECKPOINT_MS = 1000;

export class AttachmentScanError extends Error {
  constructor(message, code = "ATTACHMENT_SCAN_FAILED") { super(message); this.name = "AttachmentScanError"; this.code = code; }
}

export function utf8Prefix(value, maxBytes) {
  let used = 0; let output = "";
  for (const char of String(value || "")) { const bytes = Buffer.byteLength(char); if (used + bytes > maxBytes) break; output += char; used += bytes; }
  return output;
}

export function scanPublicStatus(scan) {
  if (!scan || typeof scan !== "object") return null;
  const totalBytes = finite(scan.totalBytes); const processedBytes = finite(scan.processedBytes);
  return Object.freeze({
    id: String(scan.id || ""), attachmentId: String(scan.attachmentId || ""), filename: utf8Prefix(scan.filename || "", 360),
    kind: ["archive", "document"].includes(scan.kind) ? scan.kind : "text",
    status: ["queued", "running", "paused", "completed", "aborted", "failed"].includes(scan.status) ? scan.status : "failed",
    processedBytes, totalBytes, uniqueBytes: finite(scan.uniqueBytes), deduplicatedBytes: finite(scan.deduplicatedBytes),
    leafCount: finite(scan.leafCount), entryCount: finite(scan.entryCount), processedEntries: finite(scan.processedEntries), analyzedEntries: finite(scan.analyzedEntries), unsupportedEntries: finite(scan.unsupportedEntries), summary: utf8Prefix(redactText(scan.summary || "", SCAN_PUBLIC_SUMMARY_BYTES * 2), SCAN_PUBLIC_SUMMARY_BYTES),
    ...(scan.coverage && Object.keys(scan.coverage).length ? { coverage: publicScanCoverage(scan.coverage) } : {}),
    ...(scan.artifactId ? { artifactId: String(scan.artifactId) } : {}),
    ...(scan.error ? { error: publicError(scan.error) } : {}),
  });
}

function finite(value) { return Number.isSafeInteger(value) && value >= 0 ? value : 0; }
function publicScanCoverage(coverage) {
  const warnings = value => (Array.isArray(value) ? value : []).filter(item => typeof item === "string").slice(0, 12).map(item => utf8Prefix(redactText(item, 1024), 500));
  const result = {};
  if (coverage.document && typeof coverage.document === "object") {
    const document = coverage.document;
    result.document = { format: utf8Prefix(document.format || "", 24), extractedBytes: finite(document.extractedBytes), sourceBytes: finite(document.sourceBytes),
      coverage: { state: ["complete", "partial", "image_only", "unsupported"].includes(document.coverage?.state) ? document.coverage.state : "unsupported", unitsRead: finite(document.coverage?.unitsRead), unitsSkipped: finite(document.coverage?.unitsSkipped), warnings: warnings(document.coverage?.warnings) } };
  }
  if (coverage.sourceBytes !== undefined) result.sourceBytes = finite(coverage.sourceBytes);
  if (coverage.documentEntries !== undefined) result.documentEntries = finite(coverage.documentEntries);
  if (coverage.partialDocumentEntries !== undefined) result.partialDocumentEntries = finite(coverage.partialDocumentEntries);
  if (coverage.documentWarnings) result.documentWarnings = warnings(coverage.documentWarnings);
  return result;
}
function publicError(value) {
  if (!value || typeof value !== "object") return { code: "ATTACHMENT_SCAN_FAILED", message: "Analisi interrotta." };
  return { code: /^[A-Z0-9_]{1,64}$/.test(value.code || "") ? value.code : "ATTACHMENT_SCAN_FAILED", message: utf8Prefix(redactText(value.message || "Analisi interrotta.", 512), 256) || "Analisi interrotta." };
}

export function normalizeScanSummary(value, maxBytes = SCAN_SEGMENT_SUMMARY_BYTES) {
  if (typeof value !== "string") return null;
  const clean = utf8Prefix(redactText(value, maxBytes * 2).replace(/\s+/g, " ").trim(), maxBytes);
  return clean || null;
}

// This representation is lossless: it only replaces a consecutive run when
// the JSON form is smaller than the original UTF-8 source. It keeps a 512 MiB
// fixture with repeated characters from becoming tens of thousands of needless
// model-prefill tokens, while hashes and coverage still apply to the full text.
export function losslessLeafRepresentation(content) {
  const source = String(content ?? "");
  const chars = [...source];
  if (!chars.length) return null;
  const segments = []; let literal = "";
  const flush = () => { if (literal) { segments.push({ literal }); literal = ""; } };
  for (let index = 0; index < chars.length;) {
    const value = chars[index]; let end = index + 1;
    while (end < chars.length && chars[end] === value) end += 1;
    const count = end - index;
    if (count >= 8) { flush(); segments.push({ repeat: value, count }); }
    else literal += chars.slice(index, end).join("");
    index = end;
  }
  flush();
  const representation = { encoding: "lossless-rle-v1", segments };
  return Buffer.byteLength(JSON.stringify(representation), "utf8") < Buffer.byteLength(source, "utf8")
    ? representation : null;
}

export function rebuildLosslessLeafRepresentation(value) {
  if (!value || value.encoding !== "lossless-rle-v1" || !Array.isArray(value.segments)) return null;
  let output = "";
  for (const segment of value.segments) {
    if (typeof segment?.literal === "string") output += segment.literal;
    else if (typeof segment?.repeat === "string" && [...segment.repeat].length === 1 && Number.isSafeInteger(segment.count) && segment.count > 0 && segment.count <= SCAN_WINDOW_BYTES) output += segment.repeat.repeat(segment.count);
    else return null;
  }
  return output;
}

// The worker owns coverage semantics: the checkpoint advances only after a
// structured leaf summary succeeds or an exact hash points to a prior leaf.
export async function runTextScanSlice({ scan, attachment, store, summarizeLeaf, summarizeProgress, signal, now = () => Date.now(), sliceMs = SCAN_SLICE_MS, onProgress } = {}) {
  validateInputs(scan, attachment, store, summarizeLeaf);
  const startedAt = now(); const deadline = startedAt + normalizeSlice(sliceMs);
  let current = { ...scan, kind: attachment.kind === "document" ? "document" : "text", ...(attachment.document ? { coverage: { ...scan.coverage, sourceBytes: attachment.byteSize, document: attachment.document } } : {}) }; let lastCheckpointBytes = current.processedBytes || 0; let lastCheckpointAt = startedAt;
  const recent = await resumableRecent(store, current);
  try { while (current.nextByte < current.totalBytes) {
    signal?.throwIfAborted?.();
    if (now() >= deadline) return checkpoint(store, current, recent, summarizeProgress, onProgress, "queued", { allowSummary: false });
    const startByte = current.nextByte;
    const chunk = await attachment.readText({ startByte, maxBytes: SCAN_WINDOW_BYTES, signal });
    signal?.throwIfAborted?.();
    const normalized = normalizeChunk(chunk, startByte, current.totalBytes);
    const bytes = normalized.endByte - startByte;
    const digest = createHash("sha256").update(Buffer.from(normalized.content, "utf8")).digest("hex");
    // A crash can leave durable segments after the last scan checkpoint. Reuse
    // their exact classification so restart neither calls the model again nor
    // inserts an overlapping range or inflates unique/deduplicated counters.
    const replay = await store.findRecordedSegment?.(current.id, "", startByte, normalized.endByte, digest);
    let summary = null; let canonicalSegmentId = null; let status = replay?.classification || null;
    if (!status) {
      const canonical = await store.findCanonicalSegment(current.id, digest);
      status = "analyzed";
      if (canonical?.id && typeof canonical.summary === "string") {
        canonicalSegmentId = canonical.id; status = "duplicate";
      } else {
        summary = normalizeScanSummary(await summarizeLeaf({ attachment: scanAttachmentMeta(attachment), document: attachment.document, startByte, endByte: normalized.endByte, totalBytes: current.totalBytes, content: normalized.content, representation: losslessLeafRepresentation(normalized.content), signal }));
        signal?.throwIfAborted?.();
        if (!summary) throw new AttachmentScanError("Il riepilogo del blocco non è valido.", "ATTACHMENT_SCAN_SUMMARY_INVALID");
        recent.push(summary);
      }
    }
    const stored = replay || await store.recordSegment({ scanId: current.id, startByte, endByte: normalized.endByte, contentSha256: digest, canonicalSegmentId, summary, status });
    const classification = stored?.classification || status;
    if (replay && classification === "analyzed" && typeof replay.summary === "string") appendRecent(recent, replay.summary);
    if (!replay && classification !== status && summary) recent.pop();
    current = {
      ...current,
      nextByte: normalized.endByte,
      processedBytes: current.processedBytes + bytes,
      uniqueBytes: current.uniqueBytes + (classification === "analyzed" ? bytes : 0),
      deduplicatedBytes: current.deduplicatedBytes + (classification === "duplicate" ? bytes : 0),
      leafCount: current.leafCount + 1,
      uniqueLeafCount: current.uniqueLeafCount + (classification === "analyzed" ? 1 : 0),
    };
    const elapsed = now() - lastCheckpointAt;
    if (recent.length >= 8 || current.nextByte === current.totalBytes || current.processedBytes - lastCheckpointBytes >= CHECKPOINT_BYTES || elapsed >= CHECKPOINT_MS) {
      await checkpoint(store, current, recent, summarizeProgress, onProgress, current.nextByte === current.totalBytes ? "completed" : "running");
      lastCheckpointBytes = current.processedBytes; lastCheckpointAt = now();
    }
  }
  return scanPublicStatus(current);
  } catch (error) {
    // An abort is allowed to interrupt I/O/model work, never to roll verified
    // bytes back. Do not spend another model call composing a progress summary.
    if (signal?.aborted && current.processedBytes > (scan.processedBytes || 0)) {
      await checkpoint(store, current, recent, summarizeProgress, onProgress, "running", { allowSummary: false }).catch(() => {});
    }
    throw error;
  }
}

async function checkpoint(store, scan, recent, summarizeProgress, onProgress, status, { allowSummary = true } = {}) {
  let summary = scan.summary || "";
  // A periodic checkpoint records coverage only. Replaying old leaf summaries
  // would turn a 512 MiB repeated file into hundreds of identical model calls.
  // Persisted leaf summaries remain available for a later new-evidence/final
  // aggregation, but never cause a duplicate-only progress call themselves.
  // Do not discard newly verified leaf summaries at a metadata-only boundary.
  // Archive entries can be small: their aggregate is emitted at a genuine
  // summary checkpoint or completion, not lost between entries.
  const summaries = recent.slice();
  if (allowSummary && typeof summarizeProgress === "function" && (summaries.length || status === "completed")) {
    const kind = ["archive", "document"].includes(scan.kind) ? scan.kind : "text";
    const completed = status === "completed";
    const entryCount = Number.isSafeInteger(scan.entryCount) ? scan.entryCount : 0;
    const processedEntries = Number.isSafeInteger(scan.processedEntries) ? scan.processedEntries : 0;
    const unsupportedEntries = Number.isSafeInteger(scan.unsupportedEntries) ? scan.unsupportedEntries : 0;
    const candidate = normalizeScanSummary(await summarizeProgress({
      priorSummary: summary, recentLeafSummaries: summaries,
      processedBytes: scan.processedBytes, totalBytes: scan.totalBytes,
      kind, status, completed, ...(scan.coverage ? { coverage: publicScanCoverage(scan.coverage) } : {}),
      entryCount, processedEntries,
      analyzedEntries: Number.isSafeInteger(scan.analyzedEntries) ? scan.analyzedEntries : 0,
      unsupportedEntries,
      // An archive’s source-byte total includes policy-excluded entries. Its
      // catalog is complete when every entry was visited, even when the
      // readable-byte counter is necessarily smaller than the total.
      allCatalogEntriesChecked: kind === "archive" && completed && processedEntries >= entryCount,
    }), SCAN_PUBLIC_SUMMARY_BYTES);
    if (candidate) { summary = candidate; recent.splice(0, recent.length); }
  }
  scan.summary = summary;
  scan.status = status;
  const next = { ...scan };
  const saved = await store.checkpoint(next);
  const publicValue = scanPublicStatus(saved || next);
  await onProgress?.(publicValue);
  return publicValue;
}

async function resumableRecent(store, scan) {
  // A crash can happen after recordSegment but before the first coverage
  // checkpoint, leaving processedBytes at zero. Rehydrate persisted leaf
  // summaries once per durable slice; periodic checkpoints never replay them.
  if (scan?.summary || typeof store?.listRecentSummaries !== "function") return [];
  try {
    const rows = await store.listRecentSummaries(scan.id, { limit: 8 });
    const result = [];
    for (const item of Array.isArray(rows) ? rows : []) appendRecent(result, item);
    return result;
  } catch { return []; }
}
function appendRecent(recent, value) {
  const summary = normalizeScanSummary(value, SCAN_SEGMENT_SUMMARY_BYTES);
  if (!summary || recent.includes(summary)) return;
  recent.push(summary);
  if (recent.length > 8) recent.splice(0, recent.length - 8);
}

function normalizeChunk(chunk, startByte, totalBytes) {
  if (!chunk || typeof chunk.content !== "string" || !Number.isSafeInteger(chunk.endByte) || chunk.endByte <= startByte || chunk.endByte > totalBytes || Buffer.byteLength(chunk.content) > SCAN_WINDOW_BYTES) throw new AttachmentScanError("Lettura allegato non valida.", "ATTACHMENT_SCAN_READ_INVALID");
  if (chunk.nextByte !== null && chunk.nextByte !== undefined && chunk.nextByte !== chunk.endByte) throw new AttachmentScanError("Cursore allegato non valido.", "ATTACHMENT_SCAN_READ_INVALID");
  return chunk;
}
function validateInputs(scan, attachment, store, summarizeLeaf) {
  if (!scan || !attachment || typeof attachment.readText !== "function" || !store || typeof store.findCanonicalSegment !== "function" || typeof store.recordSegment !== "function" || typeof store.checkpoint !== "function" || typeof summarizeLeaf !== "function") throw new TypeError("Configurazione scansione allegato non valida.");
  if (!Number.isSafeInteger(scan.totalBytes) || scan.totalBytes < 1 || !Number.isSafeInteger(scan.nextByte) || scan.nextByte < 0 || scan.nextByte > scan.totalBytes) throw new AttachmentScanError("Stato scansione non valido.", "ATTACHMENT_SCAN_INVALID");
}
function normalizeSlice(value) { return Number.isSafeInteger(value) ? Math.max(1, Math.min(value, SCAN_SLICE_MS)) : SCAN_SLICE_MS; }
function scanAttachmentMeta(attachment) { return { id: attachment.id, filename: attachment.filename, sha256: attachment.sha256 }; }

// ZIP entries are already filtered by the private storage boundary. We retain
// the opaque entry cursor only; paths never become scan checkpoints. A source
// entry is counted only once its stream reaches EOF and storage verifies CRC.
export async function runArchiveScanSlice({ scan, attachment, store, summarizeLeaf, summarizeProgress, signal, now = () => Date.now(), sliceMs = SCAN_SLICE_MS, onProgress } = {}) {
  if (!scan || attachment?.kind !== "archive" || typeof attachment.listArchiveEntries !== "function" || typeof attachment.materializeArchiveTextEntry !== "function" || typeof attachment.readMaterializedText !== "function") throw new TypeError("Configurazione scansione archivio non valida.");
  const startedAt = now(); const deadline = startedAt + normalizeSlice(sliceMs);
  let current = { ...scan, kind: "archive" }; const recent = await resumableRecent(store, current);
  let lastCheckpointBytes = current.processedBytes || 0; let lastCheckpointAt = startedAt;
  const checkpointArchive = async (status, options = {}) => {
    const value = await checkpoint(store, current, recent, summarizeProgress, onProgress, status, options);
    lastCheckpointBytes = current.processedBytes || 0; lastCheckpointAt = now();
    return value;
  };
  const shouldCheckpoint = () => recent.length >= 8
    || (current.processedBytes || 0) - lastCheckpointBytes >= CHECKPOINT_BYTES
    || now() - lastCheckpointAt >= CHECKPOINT_MS;
  try { while (true) {
    signal?.throwIfAborted?.();
    if (now() >= deadline) return checkpointArchive("queued");
    const page = await attachment.listArchiveEntries({ cursor: current.nextCursor ?? undefined, limit: 100, signal });
    signal?.throwIfAborted?.();
    if (!page || !Array.isArray(page.entries) || page.entries.length > 100 || !Number.isSafeInteger(page.entryCount) || !Number.isSafeInteger(page.availableEntryCount) || !Number.isSafeInteger(page.skippedEntryCount)) throw new AttachmentScanError("Catalogo archivio non valido.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
    for (const entry of page.entries) {
      signal?.throwIfAborted?.();
      if (now() >= deadline) return checkpointArchive("queued");
      if (!entry || typeof entry.id !== "string" || !Number.isSafeInteger(entry.byteSize) || entry.byteSize < 0) throw new AttachmentScanError("Voce archivio non valida.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
      // If the current entry was durable only up to its prior checkpoint,
      // replay its materialized ranges even when a later segment already hit
      // EOF. This closes the record-before-checkpoint crash window.
      const isDocument = entry.kind === "document";
      if (isDocument && current.coverage?.documentCompletedEntryIds?.includes(entry.id)) continue;
      if (!isDocument && current.activeEntryId !== entry.id && await store.isArchiveEntryComplete?.(current.id, entry.id, entry.byteSize)) continue;
      let documentMaterialized = null; let documentFailure = null;
      if (isDocument) {
        try {
          documentMaterialized = await attachment.materializeArchiveTextEntry(entry.id, { signal });
          signal?.throwIfAborted?.();
          if (!documentMaterialized?.verified || !documentMaterialized.document || documentMaterialized.sourceByteSize !== entry.byteSize
            || !Number.isSafeInteger(documentMaterialized.byteSize) || documentMaterialized.byteSize < 0 || documentMaterialized.byteSize > 16 * 1024 * 1024) throw new AttachmentScanError("Documento ZIP non integro.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
          if (!documentMaterialized.byteSize) documentFailure = "Documento senza testo estraibile; immagini e scansioni richiedono OCR.";
        } catch (error) {
          signal?.throwIfAborted?.();
          // Only expected parser rejections can exclude a document. Storage,
          // scope, integrity and runtime failures must remain retryable errors.
          if (![413, 415].includes(error?.status) || !/^(?:DOCUMENT_|INVALID_DOCUMENT|TYPE_MISMATCH|UNSUPPORTED_DOCUMENT|ZIP_)/.test(error?.code || "")) throw error;
          documentFailure = "Documento non leggibile o oltre i limiti di estrazione; contenuto non analizzato.";
        }
      }
      if (!["text", "document"].includes(entry.kind) || documentFailure) {
        const boundary = { scanId: current.id, entryId: entry.id, byteSize: entry.byteSize, classification: "unsupported", summary: documentFailure || "Voce non testuale: catalogata ma non analizzata." };
        if (typeof store.recordArchiveEntryBoundary === "function") {
          const saved = await store.recordArchiveEntryBoundary(boundary);
          current = { ...current, processedEntries: saved.processedEntries, analyzedEntries: saved.analyzedEntries, unsupportedEntries: saved.unsupportedEntries, status: "running" };
          lastCheckpointBytes = current.processedBytes || 0; lastCheckpointAt = now(); await onProgress?.(scanPublicStatus(current));
        } else {
          await store.recordUnsupportedSegment?.({ ...boundary, startByte: 0 });
          current.processedEntries = (current.processedEntries || 0) + 1; current.unsupportedEntries = (current.unsupportedEntries || 0) + 1;
          await checkpointArchive("running", { allowSummary: false });
        }
        if (isDocument) {
          current.coverage = archiveDocumentCoverage(current.coverage, entry, documentMaterialized?.document, documentFailure);
          await checkpointArchive("running", { allowSummary: false });
        }
        continue;
      }
      if (entry.byteSize === 0) {
        const boundary = { scanId: current.id, entryId: entry.id, byteSize: 0, classification: "empty" };
        if (typeof store.recordArchiveEntryBoundary === "function") {
          const saved = await store.recordArchiveEntryBoundary(boundary);
          current = { ...current, processedEntries: saved.processedEntries, analyzedEntries: saved.analyzedEntries, unsupportedEntries: saved.unsupportedEntries, status: "running" };
          lastCheckpointBytes = current.processedBytes || 0; lastCheckpointAt = now(); await onProgress?.(scanPublicStatus(current));
        } else {
          await store.recordEmptyArchiveEntry?.({ scanId: current.id, entryId: entry.id });
          current = { ...current, processedEntries: (current.processedEntries || 0) + 1, analyzedEntries: (current.analyzedEntries || 0) + 1 };
          await checkpointArchive("running", { allowSummary: false });
        }
        continue;
      }
      let materialized;
      if (documentMaterialized) {
        materialized = documentMaterialized;
        if (current.activeEntryId !== entry.id) {
          current = { ...current, activeEntryId: entry.id, materializedObjectKey: materialized.objectKey, materializedNextByte: 0 };
          await checkpointArchive("running", { allowSummary: false });
        } else if (current.materializedObjectKey !== materialized.objectKey) throw new AttachmentScanError("Documento ZIP cambiato durante l’analisi.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
      } else if (current.activeEntryId === entry.id && typeof current.materializedObjectKey === "string" && current.materializedObjectKey) {
        materialized = { objectKey: current.materializedObjectKey, entryId: entry.id, byteSize: entry.byteSize, verified: true };
      } else {
        materialized = await attachment.materializeArchiveTextEntry(entry.id, { signal });
        signal?.throwIfAborted?.();
        if (!materialized || typeof materialized.objectKey !== "string" || !Number.isSafeInteger(materialized.byteSize) || materialized.byteSize < 1 || materialized.verified !== true) throw new AttachmentScanError("Voce archivio non disponibile.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
        current = { ...current, activeEntryId: entry.id, materializedObjectKey: materialized.objectKey, materializedNextByte: 0 };
        await checkpointArchive("running", { allowSummary: false });
      }
      if (!isDocument && materialized.byteSize !== entry.byteSize) throw new AttachmentScanError("Voce archivio non integra.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
      let offset = current.activeEntryId === entry.id ? current.materializedNextByte || 0 : 0;
      while (offset < materialized.byteSize) {
        signal?.throwIfAborted?.();
        if (now() >= deadline) return checkpointArchive("queued");
        const chunk = await attachment.readMaterializedText(materialized.objectKey, { startByte: offset, maxBytes: SCAN_WINDOW_BYTES, signal });
        signal?.throwIfAborted?.();
        if (!chunk || typeof chunk.content !== "string" || !Number.isSafeInteger(chunk.endByte) || chunk.endByte <= offset || chunk.endByte > materialized.byteSize || Buffer.byteLength(chunk.content) > SCAN_WINDOW_BYTES || (chunk.nextByte !== null && chunk.nextByte !== undefined && chunk.nextByte !== chunk.endByte)) throw new AttachmentScanError("Lettura voce archivio non valida.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
        current = await processArchiveLeaf({ current, content: chunk.content, entry, document: materialized.document, extractedBytes: materialized.byteSize, store, summarizeLeaf, attachment, signal, recent, startByte: offset, endByte: chunk.endByte });
        offset = chunk.endByte;
        current = { ...current, activeEntryId: entry.id, materializedObjectKey: materialized.objectKey, materializedNextByte: offset };
        if (shouldCheckpoint()) await checkpointArchive("running");
      }
      current = { ...current, processedEntries: (current.processedEntries || 0) + 1, analyzedEntries: (current.analyzedEntries || 0) + 1, activeEntryId: "", materializedObjectKey: null, materializedNextByte: 0 };
      if (isDocument) current.coverage = archiveDocumentCoverage(current.coverage, entry, materialized.document);
      // Persist the entry boundary: a restart rereads only a materialized
      // partial entry, while already complete entries are skipped by segments.
      await checkpointArchive("running", { allowSummary: false });
    }
    current.nextCursor = page.nextCursor ?? null;
    current.entryCount = page.entryCount; current.totalBytes = page.totalUncompressedBytes ?? current.totalBytes;
    // Policy-hidden entries have no path and no stream by design. Count them
    // as explicitly unsupported once the catalog is exhausted, never analyzed.
    if (!current.nextCursor) {
      const hiddenCount = page.skippedEntryCount || 0;
      const priorHiddenCount = current.coverage?.policyExcludedEntries || 0;
      current.processedEntries = page.entryCount;
      current.unsupportedEntries = Math.min(page.entryCount, (current.unsupportedEntries || 0) + Math.max(0, hiddenCount - priorHiddenCount));
      if (hiddenCount) current.coverage = { ...current.coverage, policyExcludedEntries: hiddenCount };
      return checkpointArchive("completed");
    }
  }
  } catch (error) {
    // Like text scans, preserve only already verified offsets when an explicit
    // stop/disable interrupts an archive read or model call.
    if (signal?.aborted && ((current.processedBytes || 0) > (scan.processedBytes || 0) || (current.processedEntries || 0) > (scan.processedEntries || 0))) {
      await checkpointArchive("running", { allowSummary: false }).catch(() => {});
    }
    throw error;
  }
}

function archiveDocumentCoverage(prior = {}, entry, document, failure = null) {
  const completed = prior.documentCompletedEntryIds || [];
  if (completed.includes(entry.id)) return prior;
  const warning = failure || (document?.coverage?.warnings || []).join(" ");
  const warnings = [...(prior.documentWarnings || [])];
  if (warning && warnings.length < 12) warnings.push(utf8Prefix(`${entry.path || "Documento ZIP"}: ${warning}`, 500));
  return { ...prior, documentEntries: (prior.documentEntries || 0) + 1,
    partialDocumentEntries: (prior.partialDocumentEntries || 0) + (failure || document?.coverage?.state !== "complete" ? 1 : 0),
    documentCompletedEntryIds: [...completed, entry.id], documentWarnings: warnings };
}

async function processArchiveLeaf({ current, content, entry, document, extractedBytes, store, summarizeLeaf, attachment, signal, recent, startByte, endByte }) {
  // Coverage belongs to the verified archive offsets, never to redacted text
  // length. Redaction can alter UTF-8 byte length while the source span remains
  // authoritative and resumable.
  const span = endByte - startByte;
  if (!Number.isSafeInteger(span) || span < 1) throw new AttachmentScanError("Intervallo voce archivio non valido.", "ATTACHMENT_SCAN_ARCHIVE_INVALID");
  // ZIP accounting uses source-file bytes. Document cursors and segment hashes
  // instead address extracted text. Proportional accounting sums exactly to
  // source size at text EOF without confusing the two coordinate systems.
  const bytes = document ? Math.floor(endByte * entry.byteSize / extractedBytes) - Math.floor(startByte * entry.byteSize / extractedBytes) : span;
  const leaf = Buffer.from(content, "utf8"); const digest = createHash("sha256").update(leaf).digest("hex");
  const replay = await store.findRecordedSegment?.(current.id, entry.id, startByte, endByte, digest);
  let summary = null; let canonicalSegmentId = null; let status = replay?.classification || null;
  if (!status) {
    const canonical = await store.findCanonicalSegment(current.id, digest);
    status = "analyzed";
    if (canonical?.id && typeof canonical.summary === "string") { status = "duplicate"; canonicalSegmentId = canonical.id; }
    else { summary = normalizeScanSummary(await summarizeLeaf({ attachment: scanAttachmentMeta(attachment), entryId: entry.id, entryPath: entry.path, document, startByte, endByte, totalBytes: document ? extractedBytes : current.totalBytes, content, representation: losslessLeafRepresentation(content), signal })); signal?.throwIfAborted?.(); if (!summary) throw new AttachmentScanError("Il riepilogo della voce ZIP non è valido.", "ATTACHMENT_SCAN_SUMMARY_INVALID"); recent.push(summary); }
  }
  const stored = replay || await store.recordSegment({ scanId: current.id, entryId: entry.id, startByte, endByte, contentSha256: digest, canonicalSegmentId, summary, status });
  const classification = stored?.classification || status;
  if (replay && classification === "analyzed" && typeof replay.summary === "string") appendRecent(recent, replay.summary);
  if (!replay && classification !== status && summary) recent.pop();
  return { ...current, processedBytes: (current.processedBytes || 0) + bytes, uniqueBytes: (current.uniqueBytes || 0) + (classification === "analyzed" ? bytes : 0), deduplicatedBytes: (current.deduplicatedBytes || 0) + (classification === "duplicate" ? bytes : 0), leafCount: (current.leafCount || 0) + 1, uniqueLeafCount: (current.uniqueLeafCount || 0) + (classification === "analyzed" ? 1 : 0) };
}
