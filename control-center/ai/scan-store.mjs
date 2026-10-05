import { randomUUID } from "node:crypto";
import { scanPublicStatus, SCAN_PUBLIC_SUMMARY_BYTES, utf8Prefix } from "./scan.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MACHINE = /^[a-f0-9]{64}$/;
const SHA = /^[a-f0-9]{64}$/;
const STATUSES = new Set(["queued", "running", "paused", "completed", "aborted", "failed"]);

export class AttachmentScanStoreError extends Error {
  constructor(message, status = 400) { super(message); this.name = "AttachmentScanStoreError"; this.status = status; }
}

function id(value, label = "Identificativo") { if (typeof value !== "string" || !UUID.test(value)) throw new AttachmentScanStoreError(`${label} non valido.`); return value.toLowerCase(); }
function machine(value) { if (typeof value !== "string" || !MACHINE.test(value)) throw new AttachmentScanStoreError("Macchina non valida."); return value; }
function owner(value) { if (typeof value !== "string" || !value.trim() || value.length > 256) throw new AttachmentScanStoreError("Owner non valido."); return value; }
function sha(value) { if (typeof value !== "string" || !SHA.test(value)) throw new AttachmentScanStoreError("Hash allegato non valido."); return value.toLowerCase(); }
function int(value, label, max = 536870912) { if (!Number.isSafeInteger(value) || value < 0 || value > max) throw new AttachmentScanStoreError(`${label} non valido.`); return value; }
function scope(args) { return { ownerId: owner(args.ownerId ?? args.subject), machineId: machine(args.machineId), conversationId: id(args.conversationId, "Conversazione") }; }
function mapRow(row) {
  if (!row) return null;
  return {
    id: row.id, ownerId: row.owner_id ?? row.ownerId, machineId: row.machine_id ?? row.machineId,
    conversationId: row.conversation_id ?? row.conversationId, attachmentId: row.attachment_id ?? row.attachmentId,
    attachmentSha256: row.attachment_sha256 ?? row.attachmentSha256,
    filename: row.filename || "", kind: row.kind || "text", totalBytes: Number(row.total_bytes ?? row.totalBytes), entryCount: Number(row.entry_count ?? row.entryCount ?? 0),
    processedEntries: Number(row.processed_entries ?? row.processedEntries ?? 0), analyzedEntries: Number(row.analyzed_entries ?? row.analyzedEntries ?? 0), unsupportedEntries: Number(row.unsupported_entries ?? row.unsupportedEntries ?? 0), nextCursor: row.next_cursor ?? row.nextCursor ?? null,
    activeEntryId: row.active_entry_id ?? row.activeEntryId ?? "", materializedObjectKey: row.materialized_object_key ?? row.materializedObjectKey ?? null, materializedNextByte: Number(row.materialized_next_byte ?? row.materializedNextByte ?? 0),
    status: row.status, nextByte: Number(row.next_byte ?? row.nextByte), processedBytes: Number(row.processed_bytes ?? row.processedBytes),
    uniqueBytes: Number(row.unique_bytes ?? row.uniqueBytes), deduplicatedBytes: Number(row.deduplicated_bytes ?? row.deduplicatedBytes),
    leafCount: Number(row.leaf_count ?? row.leafCount), uniqueLeafCount: Number(row.unique_leaf_count ?? row.uniqueLeafCount),
    coverage: row.coverage_metadata ?? row.coverage ?? {},
    summary: row.summary || "", error: row.error_code ? { code: row.error_code, message: "Analisi interrotta." } : null,
    createdAt: row.created_at ?? row.createdAt, updatedAt: row.updated_at ?? row.updatedAt,
  };
}
function publicRow(row) { return scanPublicStatus(mapRow(row)); }
function attachmentForScan(attachment) {
  if (!attachment || typeof attachment !== "object" || !["text", "archive", "document"].includes(attachment.kind) || typeof attachment.filename !== "string" || !sha(attachment.sha256)
    || !Number.isSafeInteger(attachment.byteSize) || attachment.byteSize < 1 || attachment.byteSize > 536870912) throw new AttachmentScanStoreError("Allegato non disponibile.", 409);
  if (attachment.kind === "document") {
    if (typeof attachment.readText !== "function" || !attachment.document || !Number.isSafeInteger(attachment.document.extractedBytes) || attachment.document.extractedBytes < 1 || attachment.document.extractedBytes > 16 * 1024 * 1024) throw new AttachmentScanStoreError("Il documento non contiene testo estraibile da analizzare. Per scansioni o immagini serve OCR.", 409);
    return { id: id(attachment.id, "Allegato"), kind: "document", filename: attachment.filename, sha256: attachment.sha256.toLowerCase(), byteSize: attachment.byteSize, totalBytes: attachment.document.extractedBytes, document: attachment.document, coverage: { sourceBytes: attachment.byteSize, document: attachment.document }, readText: attachment.readText };
  }
  if (attachment.kind === "text") {
    if (typeof attachment.readText !== "function") throw new AttachmentScanStoreError("Allegato testuale non disponibile.", 409);
    return { id: id(attachment.id, "Allegato"), kind: "text", filename: attachment.filename, sha256: attachment.sha256.toLowerCase(), byteSize: attachment.byteSize, totalBytes: attachment.byteSize, readText: attachment.readText };
  }
  if (!attachment.archive || !Number.isSafeInteger(attachment.archive.entryCount) || attachment.archive.entryCount < 1 || attachment.archive.entryCount > 2048 || !Number.isSafeInteger(attachment.archive.totalUncompressedBytes) || attachment.archive.totalUncompressedBytes < 1 || attachment.archive.totalUncompressedBytes > 1024 * 1024 * 1024 || typeof attachment.listArchiveEntries !== "function" || typeof attachment.materializeArchiveTextEntry !== "function" || typeof attachment.readMaterializedText !== "function") throw new AttachmentScanStoreError("Archivio non disponibile.", 409);
  return { id: id(attachment.id, "Allegato"), kind: "archive", filename: attachment.filename, sha256: attachment.sha256.toLowerCase(), byteSize: attachment.byteSize, totalBytes: attachment.archive.totalUncompressedBytes, entryCount: attachment.archive.entryCount, listArchiveEntries: attachment.listArchiveEntries, materializeArchiveTextEntry: attachment.materializeArchiveTextEntry, readMaterializedText: attachment.readMaterializedText };
}

export class PostgresAttachmentScanStore {
  constructor({ pool, attachmentStorage = null } = {}) {
    if (!pool || typeof pool.query !== "function") throw new TypeError("Attachment scan store requires a PostgreSQL pool.");
    this.pool = pool; this.attachmentStorage = attachmentStorage;
  }
  async ready() {
    const result = await this.pool.query("select to_regclass('server_ai.attachment_scans') as scans, to_regclass('server_ai.attachment_scan_segments') as segments");
    if (!result?.rows?.[0]?.scans || !result.rows[0].segments) throw new AttachmentScanStoreError("Migration Server AI scansioni non applicata.", 503);
    return { ready: true };
  }
  async createOrResume(args = {}) {
    const ownerScope = scope(args); const attachment = attachmentForScan(args.attachment);
    const query = `insert into server_ai.attachment_scans
      (id,owner_id,machine_id,conversation_id,attachment_id,attachment_sha256,kind,total_bytes,entry_count,status,coverage_metadata)
      select $1::uuid,$2::text,$3::text,$4::uuid,a.id,a.sha256,$6::text,$7::bigint,$8::integer,'queued',$12::jsonb
      from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
      where a.id=$5::uuid and a.conversation_id=$4::uuid and a.kind=$6::text and a.size=$9::bigint and a.sha256=$10::text
        and c.owner_id=$2::text and c.machine_id=$3::text and c.deleted_at is null and a.deleted_at is null
      on conflict (conversation_id,attachment_id,attachment_sha256) do update
        set status=case when server_ai.attachment_scans.status in ('aborted','failed','completed') then server_ai.attachment_scans.status else 'queued' end,
            error_code=null, updated_at=now()
      returning *, $11::text as filename`;
    const result = await this.pool.query(query, [randomUUID(), ownerScope.ownerId, ownerScope.machineId, ownerScope.conversationId, attachment.id, attachment.kind, attachment.totalBytes, attachment.entryCount || 0, attachment.byteSize, attachment.sha256, attachment.filename, JSON.stringify(attachment.coverage || {})]);
    if (!result?.rows?.[0]) throw new AttachmentScanStoreError("Allegato non disponibile.", 404);
    return publicRow(result.rows[0]);
  }
  // Records the server-owned continuation intent on the scan itself.  The
  // metadata is deliberately identifiers only; the original prompt remains
  // in the conversation and is reloaded through the scoped message store.
  async attachContinuation({ ownerId, subject, machineId, conversationId, scanId, userMessageId, requestId, requestedMode = "auto", role } = {}) {
    const s = scope({ ownerId, subject, machineId, conversationId }); const scan = id(scanId, "Scansione"); const user = id(userMessageId, "Messaggio"); const request = id(requestId, "Richiesta");
    if (!["auto", "fast", "deep"].includes(requestedMode) || !["owner", "admin", "viewer"].includes(role)) throw new AttachmentScanStoreError("Modalità continuazione non valida.");
    const result = await this.pool.query(`update server_ai.attachment_scans set coverage_metadata = jsonb_set(
      coalesce(coverage_metadata,'{}'::jsonb), '{autoReply}', $1::jsonb, true), updated_at=now()
      where id=$2 and owner_id=$3 and machine_id=$4 and conversation_id=$5 returning *`, [JSON.stringify({ version: 1, requestId: request, userMessageId: user, requestedMode, scanId: scan, role, state: "pending" }), scan, s.ownerId, s.machineId, s.conversationId]);
    return result.rows?.[0] ? mapRow(result.rows[0]) : null;
  }
  async listContinuations({ ownerId, subject, machineId, conversationId } = {}) {
    const s = scope({ ownerId, subject, machineId, conversationId });
    const result = await this.pool.query(`select id,status,coverage_metadata->'autoReply' as auto_reply from server_ai.attachment_scans where owner_id=$1 and machine_id=$2 and conversation_id=$3 and coverage_metadata ? 'autoReply'`, [s.ownerId, s.machineId, s.conversationId]);
    return (result.rows || []).flatMap(row => row.auto_reply && typeof row.auto_reply === "object" ? [{ scanId: row.id, status: row.status, ...row.auto_reply }] : []);
  }
  async setContinuationState({ ownerId, subject, machineId, conversationId, requestId, state } = {}) {
    const s = scope({ ownerId, subject, machineId, conversationId }); const request = id(requestId, "Richiesta");
    if (!["pending", "running", "completed", "failed", "cancelled"].includes(state)) throw new AttachmentScanStoreError("Stato continuazione non valido.");
    const allowedFrom = state === "running" ? ["pending"] : ["pending", "running"];
    const result = await this.pool.query(`update server_ai.attachment_scans set coverage_metadata=jsonb_set(coverage_metadata,'{autoReply,state}',$1::jsonb,true),updated_at=now() where owner_id=$2 and machine_id=$3 and conversation_id=$4 and coverage_metadata->'autoReply'->>'requestId'=$5 and coverage_metadata->'autoReply'->>'state'=any($6::text[]) returning id`, [JSON.stringify(state), s.ownerId, s.machineId, s.conversationId, request, allowedFrom]);
    return result.rowCount || 0;
  }
  async listPendingContinuationScopes({ machineId } = {}) {
    const m = machine(machineId);
    const result = await this.pool.query(`select distinct s.owner_id,s.machine_id,s.conversation_id,s.coverage_metadata->'autoReply'->>'role' as role
      from server_ai.attachment_scans s
      join server_ai.conversations c on c.id=s.conversation_id and c.owner_id=s.owner_id and c.machine_id=s.machine_id
      where s.machine_id=$1 and c.deleted_at is null and s.coverage_metadata->'autoReply'->>'state' in ('pending','running')
        and s.coverage_metadata->'autoReply'->>'role' in ('owner','admin','viewer')
      order by s.conversation_id limit 32`, [m]);
    return (result.rows || []).filter(row => ["owner", "admin", "viewer"].includes(row.role)).map(row => ({ ownerId: row.owner_id, machineId: row.machine_id, conversationId: row.conversation_id, role: row.role }));
  }
  async resume(args = {}) {
    const s = scope(args); const attachment = attachmentForScan(args.attachment);
    const result = await this.pool.query(`update server_ai.attachment_scans set status='queued',error_code=null,updated_at=now()
      where owner_id=$1 and machine_id=$2 and conversation_id=$3 and attachment_id=$4 and attachment_sha256=$5 and status in ('paused','aborted','failed') returning *`, [s.ownerId, s.machineId, s.conversationId, attachment.id, attachment.sha256]);
    if (result.rows?.[0]) return publicRow({ ...result.rows[0], filename: attachment.filename });
    return this.createOrResume({ ...args, attachment });
  }
  async resumeScan(args = {}) {
    const s = scope(args); const scanId = id(args.scanId, "Scansione");
    const result = await this.pool.query(`update server_ai.attachment_scans set status='queued',error_code=null,updated_at=now()
      where id=$1 and owner_id=$2 and machine_id=$3 and conversation_id=$4 and status in ('paused','aborted','failed') returning *`, [scanId, s.ownerId, s.machineId, s.conversationId]);
    return result.rows?.[0] ? publicRow(result.rows[0]) : null;
  }
  async get(args = {}) {
    const s = scope(args); const scanId = id(args.scanId, "Scansione");
    const result = await this.pool.query(`select s.*,a.filename from server_ai.attachment_scans s join server_ai.attachments a on a.id=s.attachment_id
      join server_ai.conversations c on c.id=s.conversation_id where s.id=$1 and s.owner_id=$2 and s.machine_id=$3 and s.conversation_id=$4 and c.deleted_at is null`, [scanId, s.ownerId, s.machineId, s.conversationId]);
    return result?.rows?.[0] ? publicRow(result.rows[0]) : null;
  }
  async list(args = {}) {
    const s = scope(args);
    const result = await this.pool.query(`select s.*,a.filename from server_ai.attachment_scans s join server_ai.attachments a on a.id=s.attachment_id
      join server_ai.conversations c on c.id=s.conversation_id where s.owner_id=$1 and s.machine_id=$2 and s.conversation_id=$3 and c.deleted_at is null order by s.updated_at desc limit 16`, [s.ownerId, s.machineId, s.conversationId]);
    return (result?.rows || []).map(publicRow);
  }
  async claimNext({ machineId } = {}) {
    const m = machine(machineId);
    const result = await this.withTransaction(async client => {
      const row = await client.query(`select s.*,a.filename from server_ai.attachment_scans s join server_ai.attachments a on a.id=s.attachment_id
        join server_ai.conversations c on c.id=s.conversation_id where s.machine_id=$1 and s.status in ('queued','paused') and c.deleted_at is null and a.deleted_at is null
        order by s.updated_at asc for update of s skip locked limit 1`, [m]);
      if (!row.rows?.[0]) return null;
      const updated = await client.query("update server_ai.attachment_scans set status='running',started_at=coalesce(started_at,now()),updated_at=now(),error_code=null where id=$1 returning *", [row.rows[0].id]);
      return { ...updated.rows[0], filename: row.rows[0].filename };
    });
    return result ? mapRow(result) : null;
  }
  async loadAttachment(scan, { signal } = {}) {
    const idValue = id(scan.attachmentId, "Allegato");
    const result = await this.pool.query(`select a.id,a.filename,a.kind,a.size,a.sha256,a.text_content,a.object_key,a.archive_metadata,a.document_metadata from server_ai.attachments a join server_ai.conversations c on c.id=a.conversation_id
      where a.id=$1 and a.conversation_id=$2 and c.owner_id=$3 and c.machine_id=$4 and c.deleted_at is null and a.deleted_at is null`, [idValue, scan.conversationId, scan.ownerId, scan.machineId]);
    const row = result?.rows?.[0];
    if (!row || row.kind !== scan.kind || row.sha256 !== scan.attachmentSha256 || (row.kind === "text" && Number(row.size) !== scan.totalBytes)) throw new AttachmentScanStoreError("Allegato non più disponibile.", 409);
    if (row.kind === "archive") {
      const archive = row.archive_metadata;
      if (!row.object_key || !archive || Number(archive.totalUncompressedBytes) !== scan.totalBytes || !Number.isSafeInteger(Number(archive.entryCount)) || Number(archive.entryCount) < 1 || Number(archive.entryCount) > 2048
        || !Number.isSafeInteger(Number(archive.totalUncompressedBytes)) || Number(archive.totalUncompressedBytes) < 1 || Number(archive.totalUncompressedBytes) > 1024 * 1024 * 1024
        || !this.attachmentStorage?.listArchiveEntries || !this.attachmentStorage?.materializeArchiveTextEntry || !this.attachmentStorage?.readMaterializedArchiveText) throw new AttachmentScanStoreError("Archivio non più disponibile.", 409);
      const archiveScope = { ownerId: scan.ownerId, machineId: scan.machineId, conversationId: scan.conversationId };
      return {
        id: row.id, kind: "archive", filename: row.filename, sha256: row.sha256, byteSize: Number(row.size),
        archive: { entryCount: Number(archive.entryCount), totalUncompressedBytes: Number(archive.totalUncompressedBytes) },
        listArchiveEntries: options => this.attachmentStorage.listArchiveEntries(archiveScope, row.object_key, options),
        materializeArchiveTextEntry: (entryId, options = {}) => this.attachmentStorage.materializeArchiveTextEntry(archiveScope, row.object_key, entryId, options),
        // The stored key is DB-owned output of materialization. Storage
        // reattests the parent→child mapping and full scope after a restart.
        readMaterializedText: (objectKey, options = {}) => this.attachmentStorage.readMaterializedArchiveText(archiveScope, row.object_key, objectKey, options),
      };
    }
    if (row.kind === "document") {
      const document = row.document_metadata;
      if (!row.object_key || !document || document.extractedBytes !== scan.totalBytes || !this.attachmentStorage?.readDocumentText) throw new AttachmentScanStoreError("Documento non più disponibile.", 409);
      const documentScope = { ownerId: scan.ownerId, machineId: scan.machineId, conversationId: scan.conversationId };
      return { id: row.id, kind: "document", filename: row.filename, sha256: row.sha256, byteSize: Number(row.size), document,
        readText: ({ startByte, maxBytes, signal: readSignal }) => this.attachmentStorage.readDocumentText(documentScope, row.object_key, { startByte, maxBytes, signal: readSignal || signal }) };
    }
    if (row.kind !== "text") throw new AttachmentScanStoreError("Allegato non più disponibile.", 409);
    if (row.object_key) {
      if (!this.attachmentStorage?.readText) throw new AttachmentScanStoreError("Archivio allegati non disponibile.", 503);
      return { id: row.id, filename: row.filename, sha256: row.sha256, byteSize: Number(row.size), readText: ({ startByte, maxBytes, signal: readSignal }) => this.attachmentStorage.readText(row.object_key, { startByte, maxBytes, signal: readSignal || signal }) };
    }
    const text = String(row.text_content || "");
    if (Buffer.byteLength(text, "utf8") !== Number(row.size)) throw new AttachmentScanStoreError("Allegato legacy non recuperabile integralmente.", 409);
    return { id: row.id, filename: row.filename, sha256: row.sha256, byteSize: Buffer.byteLength(text), readText: async ({ startByte, maxBytes }) => readInlineText(text, startByte, maxBytes) };
  }
  async findCanonicalSegment(scanId, contentSha256) {
    const result = await this.pool.query(`select id,summary from server_ai.attachment_scan_segments where scan_id=$1 and content_sha256=$2 and status='analyzed' order by created_at asc limit 1`, [id(scanId, "Scansione"), sha(contentSha256)]);
    return result?.rows?.[0] || null;
  }
  async findRecordedSegment(scanId, entryId = null, startByte, endByte, contentSha256) {
    const scan = id(scanId, "Scansione"); const start = int(startByte, "Offset", 1073741824); const end = int(endByte, "Offset", 1073741824); const digest = sha(contentSha256);
    if (end <= start) throw new AttachmentScanStoreError("Intervallo scansione non valido.");
    // A merged duplicate run may contain the exact retry range after restart.
    const result = await this.pool.query(`select id,status,canonical_segment_id,summary,start_byte,end_byte from server_ai.attachment_scan_segments
      where scan_id=$1 and entry_id=$2 and start_byte <= $3 and end_byte >= $4 and content_sha256=$5 and status in ('analyzed','duplicate')
      order by start_byte desc limit 1`, [scan, entryId || "", start, end, digest]);
    const row = result.rows?.[0];
    return row ? { id: row.id, classification: row.status, canonicalSegmentId: row.canonical_segment_id, summary: row.summary, startByte: Number(row.start_byte), endByte: Number(row.end_byte), replayed: true } : null;
  }
  async listRecentSummaries(scanId, { limit = 8 } = {}) {
    const bounded = Number.isInteger(limit) ? Math.max(1, Math.min(limit, 8)) : 8;
    const result = await this.pool.query(`select summary from server_ai.attachment_scan_segments
      where scan_id=$1 and status='analyzed' and summary is not null
      order by created_at desc, id desc limit $2`, [id(scanId, "Scansione"), bounded]);
    return (result.rows || []).map(row => row.summary).reverse();
  }
  async isArchiveEntryComplete(scanId, entryId, byteSize) {
    const result = await this.pool.query(`select exists(
      select 1 from server_ai.attachment_scan_segments
       where scan_id=$1 and entry_id=$2 and (status in ('unsupported','empty') or end_byte >= $3)
    ) as complete`, [id(scanId, "Scansione"), String(entryId || ""), int(byteSize, "Voce archivio", 1073741824)]);
    return result.rows?.[0]?.complete === true;
  }
  async recordArchiveEntryBoundary({ scanId, entryId, byteSize, classification, summary = null }) {
    const scan = id(scanId, "Scansione"); const entry = String(entryId || "").slice(0, 128); const bytes = int(byteSize, "Voce archivio", 1073741824);
    if (!entry || !["empty", "unsupported"].includes(classification) || (classification === "empty" && bytes !== 0)) throw new AttachmentScanStoreError("Voce archivio non valida.");
    const result = await this.withTransaction(async client => {
      const inserted = await client.query(`insert into server_ai.attachment_scan_segments(id,scan_id,entry_id,start_byte,end_byte,content_sha256,summary,status)
        values($1,$2,$3,0,$4,$5,$6,$7) on conflict (scan_id,entry_id,start_byte) do nothing returning id`, [randomUUID(), scan, entry, Math.max(1, bytes), "0".repeat(64), classification === "unsupported" ? utf8Prefix(summary || "Voce non supportata.", 768) : null, classification]);
      const row = await client.query(`update server_ai.attachment_scans set
          processed_entries=processed_entries+$2,
          analyzed_entries=analyzed_entries+$3,
          unsupported_entries=unsupported_entries+$4,
          updated_at=now()
        where id=$1 returning *`, [scan, inserted.rowCount ? 1 : 0, inserted.rowCount && classification === "empty" ? 1 : 0, inserted.rowCount && classification === "unsupported" ? 1 : 0]);
      if (!row.rows?.[0]) throw new AttachmentScanStoreError("Scansione non disponibile.", 404);
      return mapRow(row.rows[0]);
    });
    return result;
  }
  async recordSegment({ scanId, entryId = null, startByte, endByte, contentSha256, canonicalSegmentId = null, summary = null, status }) {
    const scan = id(scanId, "Scansione"); int(startByte, "Offset"); int(endByte, "Offset"); if (endByte <= startByte) throw new AttachmentScanStoreError("Intervallo scansione non valido.");
    if (!["analyzed", "duplicate"].includes(status)) throw new AttachmentScanStoreError("Stato segmento non valido.");
    const digest = sha(contentSha256); const canonical = canonicalSegmentId ? id(canonicalSegmentId, "Segmento") : null;
    const existing = await this.findRecordedSegment(scan, entryId || "", startByte, endByte, digest);
    if (existing && existing.startByte === startByte && existing.endByte === endByte) return existing;
    // Exact run-length compression applies only to adjacent duplicate leaves.
    if (status === "duplicate") {
      const merged = await this.pool.query(`update server_ai.attachment_scan_segments set end_byte=$5,unit_count=unit_count+1
        where id=(select id from server_ai.attachment_scan_segments where scan_id=$1 and entry_id=$2 and status='duplicate' and content_sha256=$3 and canonical_segment_id=$4 and end_byte=$6 order by start_byte desc limit 1)
        returning id,unit_count`, [scan, entryId || "", digest, canonical, endByte, startByte]);
      if (merged.rows?.[0]) return { id: merged.rows[0].id, unitCount: 1, merged: true, classification: "duplicate" };
    }
    const result = await this.pool.query(`insert into server_ai.attachment_scan_segments(id,scan_id,entry_id,start_byte,end_byte,content_sha256,canonical_segment_id,summary,status)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9) on conflict (scan_id,entry_id,start_byte) do nothing returning id,unit_count,status`, [randomUUID(), scan, entryId || "", startByte, endByte, digest, canonical, summary, status]);
    if (result.rows?.[0]) return { id: result.rows[0].id, unitCount: Number(result.rows[0].unit_count) || 1, classification: result.rows[0].status };
    const replay = await this.findRecordedSegment(scan, entryId || "", startByte, endByte, digest);
    if (replay && replay.startByte === startByte && replay.endByte === endByte) return replay;
    throw new AttachmentScanStoreError("Segmento scansione in conflitto.", 409);
  }
  async recordUnsupportedSegment({ scanId, entryId, startByte = 0, byteSize, summary }) {
    const scan = id(scanId, "Scansione"); const bytes = int(byteSize, "Voce archivio", 1073741824); const start = int(startByte, "Offset", 1073741824);
    const digest = "0".repeat(64);
    const result = await this.pool.query(`insert into server_ai.attachment_scan_segments(id,scan_id,entry_id,start_byte,end_byte,content_sha256,summary,status)
      values($1,$2,$3,$4,$5,$6,$7,'unsupported') on conflict (scan_id,entry_id,start_byte) do nothing returning id`, [randomUUID(), scan, String(entryId || "").slice(0, 128), start, start + Math.max(1, bytes), digest, utf8Prefix(summary || "Voce non supportata.", 768)]);
    return result.rows?.[0] || null;
  }
  async recordEmptyArchiveEntry({ scanId, entryId }) {
    const result = await this.pool.query(`insert into server_ai.attachment_scan_segments(id,scan_id,entry_id,start_byte,end_byte,content_sha256,status)
      values($1,$2,$3,0,1,$4,'empty') on conflict (scan_id,entry_id,start_byte) do nothing returning id`, [randomUUID(), id(scanId, "Scansione"), String(entryId || "").slice(0, 128), "0".repeat(64)]);
    return result.rows?.[0] || null;
  }
  async checkpoint(scan) {
    const status = STATUSES.has(scan.status) ? scan.status : "failed";
    const result = await this.pool.query(`update server_ai.attachment_scans set status=$2,next_byte=$3,processed_bytes=$4,unique_bytes=$5,deduplicated_bytes=$6,leaf_count=$7,unique_leaf_count=$8,summary=$9,next_cursor=$10,entry_count=$11,processed_entries=$12,analyzed_entries=$13,unsupported_entries=$14,active_entry_id=$15,materialized_object_key=$16,materialized_next_byte=$17,coverage_metadata=case when coverage_metadata ? 'autoReply' then jsonb_set($18::jsonb,'{autoReply}',coverage_metadata->'autoReply',true) else $18::jsonb-'autoReply' end,updated_at=now(),completed_at=case when $2='completed' then now() else completed_at end
      where id=$1 returning *`, [id(scan.id, "Scansione"), status, int(scan.nextByte, "Checkpoint", 1073741824), int(scan.processedBytes, "Copertura", 1073741824), int(scan.uniqueBytes, "Copertura", 1073741824), int(scan.deduplicatedBytes, "Copertura", 1073741824), int(scan.leafCount, "Blocchi", 2 ** 31 - 1), int(scan.uniqueLeafCount, "Blocchi", 2 ** 31 - 1), utf8Prefix(scan.summary || "", SCAN_PUBLIC_SUMMARY_BYTES), scan.nextCursor == null ? null : utf8Prefix(scan.nextCursor, 1024), int(scan.entryCount || 0, "Voci", 2048), int(scan.processedEntries || 0, "Voci", 2048), int(scan.analyzedEntries || 0, "Voci", 2048), int(scan.unsupportedEntries || 0, "Voci", 2048), String(scan.activeEntryId || ""), scan.materializedObjectKey || null, int(scan.materializedNextByte || 0, "Offset", 536870912), JSON.stringify(scan.coverage || {})]);
    const saved = mapRow(result.rows?.[0]);
    return saved ? { ...saved, filename: scan.filename || "" } : null;
  }
  async pause(scanId, reason = null) { return this.setTerminal(scanId, "paused", reason); }
  async abort(args = {}) { const s = scope(args); const scanId = id(args.scanId, "Scansione"); const result = await this.pool.query("update server_ai.attachment_scans set status='aborted',error_code='ATTACHMENT_SCAN_ABORTED',coverage_metadata=coverage_metadata-'autoReply',updated_at=now() where id=$1 and owner_id=$2 and machine_id=$3 and conversation_id=$4 returning *", [scanId, s.ownerId, s.machineId, s.conversationId]); return result.rows?.[0] ? mapRow(result.rows[0]) : null; }
  async abortClaimed(scanId, code = "ATTACHMENT_SCAN_ABORTED") { const result = await this.pool.query("update server_ai.attachment_scans set status='aborted',error_code=$2,coverage_metadata=coverage_metadata-'autoReply',updated_at=now() where id=$1 returning *", [id(scanId, "Scansione"), code]); return mapRow(result.rows?.[0]); }
  async fail(scanId, code = "ATTACHMENT_SCAN_FAILED") { return this.setTerminal(scanId, "failed", code); }
  async setTerminal(scanId, status, code = null) { const result = await this.pool.query("update server_ai.attachment_scans set status=$2,error_code=$3,updated_at=now() where id=$1 returning *", [id(scanId, "Scansione"), status, code]); return mapRow(result.rows?.[0]); }
  async setScoped(scanId, s, status, code = null) { const result = await this.pool.query("update server_ai.attachment_scans set status=$2,error_code=$3,updated_at=now() where id=$1 and owner_id=$4 and machine_id=$5 and conversation_id=$6 returning *", [id(scanId, "Scansione"), status, code, s.ownerId, s.machineId, s.conversationId]); return result.rows?.[0] ? publicRow(result.rows[0]) : null; }
  async abortConversation(args = {}) { const s = scope(args); await this.pool.query("update server_ai.attachment_scans set status=case when status in ('queued','running','paused') then 'aborted' else status end,error_code=case when status in ('queued','running','paused') then 'ATTACHMENT_SCAN_ABORTED' else error_code end,coverage_metadata=coverage_metadata-'autoReply',updated_at=now() where owner_id=$1 and machine_id=$2 and conversation_id=$3", [s.ownerId, s.machineId, s.conversationId]); }
  async recoverOnStartup({ machineId } = {}) { const m = machine(machineId); const result = await this.pool.query("update server_ai.attachment_scans set status='queued',error_code=null,updated_at=now() where machine_id=$1 and status='running' returning id", [m]); return result.rowCount || 0; }
  async withTransaction(fn) { const client = typeof this.pool.connect === "function" ? await this.pool.connect() : this.pool; const owned = client !== this.pool; try { await client.query("begin"); const value = await fn(client); await client.query("commit"); return value; } catch (error) { try { await client.query("rollback"); } catch {} throw error; } finally { if (owned) client.release?.(); } }
}

export function createMemoryAttachmentScanStore() { return new MemoryAttachmentScanStore(); }
class MemoryAttachmentScanStore {
  constructor() { this.scans = new Map(); this.segments = new Map(); }
  async ready() { return { ready: true }; }
  async createOrResume(args = {}) { const s = scope(args); const attachment = attachmentForScan(args.attachment); const prior = [...this.scans.values()].find(row => row.ownerId === s.ownerId && row.machineId === s.machineId && row.conversationId === s.conversationId && row.attachmentId === attachment.id && row.attachmentSha256 === attachment.sha256); if (prior) { if (!["completed", "aborted", "failed"].includes(prior.status)) prior.status = "queued"; return scanPublicStatus(prior); } const row = { id: randomUUID(), ...s, attachmentId: attachment.id, attachmentSha256: attachment.sha256, filename: attachment.filename, kind: attachment.kind, coverage: attachment.coverage || {}, totalBytes: attachment.totalBytes, entryCount: attachment.entryCount || 0, attachment, status: "queued", nextByte: 0, processedBytes: 0, uniqueBytes: 0, deduplicatedBytes: 0, leafCount: 0, uniqueLeafCount: 0, summary: "", error: null }; this.scans.set(row.id, row); this.segments.set(row.id, []); return scanPublicStatus(row); }
  async attachContinuation({ ownerId, subject, machineId, conversationId, scanId, userMessageId, requestId, requestedMode = "auto", role } = {}) {
    const s = scope({ ownerId, subject, machineId, conversationId }); const scan = id(scanId, "Scansione"); const user = id(userMessageId, "Messaggio"); const request = id(requestId, "Richiesta");
    if (!["auto", "fast", "deep"].includes(requestedMode) || !["owner", "admin", "viewer"].includes(role)) throw new AttachmentScanStoreError("Modalità continuazione non valida.");
    const row = this.scans.get(scan); if (!row || row.ownerId !== s.ownerId || row.machineId !== s.machineId || row.conversationId !== s.conversationId) return null;
    row.coverage = { ...(row.coverage || {}), autoReply: { version: 1, requestId: request, userMessageId: user, requestedMode, scanId: scan, role, state: "pending" } }; return { ...row };
  }
  async listContinuations({ ownerId, subject, machineId, conversationId } = {}) {
    const s = scope({ ownerId, subject, machineId, conversationId });
    return [...this.scans.values()].filter(row => row.ownerId === s.ownerId && row.machineId === s.machineId && row.conversationId === s.conversationId && row.coverage?.autoReply).map(row => ({ scanId: row.id, status: row.status, ...row.coverage.autoReply }));
  }
  async setContinuationState({ ownerId, subject, machineId, conversationId, requestId, state } = {}) {
    const s = scope({ ownerId, subject, machineId, conversationId }); const request = id(requestId, "Richiesta");
    if (!["pending", "running", "completed", "failed", "cancelled"].includes(state)) throw new AttachmentScanStoreError("Stato continuazione non valido.");
    const allowedFrom = state === "running" ? ["pending"] : ["pending", "running"];
    let count = 0;
    for (const row of this.scans.values()) if (row.ownerId === s.ownerId && row.machineId === s.machineId && row.conversationId === s.conversationId && row.coverage?.autoReply?.requestId === request && allowedFrom.includes(row.coverage.autoReply.state)) { row.coverage.autoReply.state = state; count += 1; }
    return count;
  }
  async listPendingContinuationScopes({ machineId } = {}) {
    const m = machine(machineId); const values = new Map(); for (const row of this.scans.values()) if (row.machineId === m && ["pending", "running"].includes(row.coverage?.autoReply?.state) && ["owner", "admin", "viewer"].includes(row.coverage.autoReply.role)) values.set(`${row.ownerId}\u0000${row.conversationId}`, { ownerId: row.ownerId, machineId: row.machineId, conversationId: row.conversationId, role: row.coverage.autoReply.role }); return [...values.values()];
  }
  async resume(args = {}) { const s = scope(args); const attachment = attachmentForScan(args.attachment); const row = [...this.scans.values()].find(item => item.ownerId === s.ownerId && item.machineId === s.machineId && item.conversationId === s.conversationId && item.attachmentId === attachment.id && item.attachmentSha256 === attachment.sha256); if (!row) return this.createOrResume({ ...args, attachment }); if (["paused", "aborted", "failed"].includes(row.status)) { row.status = "queued"; row.error = null; } return scanPublicStatus(row); }
  async resumeScan(args = {}) { const s = scope(args); const row = this.scans.get(id(args.scanId, "Scansione")); if (!row || row.ownerId !== s.ownerId || row.machineId !== s.machineId || row.conversationId !== s.conversationId || !["paused", "aborted", "failed"].includes(row.status)) return null; row.status = "queued"; row.error = null; return scanPublicStatus(row); }
  async get(args = {}) { const s = scope(args); const row = this.scans.get(id(args.scanId, "Scansione")); return row && row.ownerId === s.ownerId && row.machineId === s.machineId && row.conversationId === s.conversationId ? scanPublicStatus(row) : null; }
  async list(args = {}) { const s = scope(args); return [...this.scans.values()].filter(row => row.ownerId === s.ownerId && row.machineId === s.machineId && row.conversationId === s.conversationId).map(scanPublicStatus); }
  async claimNext({ machineId } = {}) { const m = machine(machineId); const row = [...this.scans.values()].find(item => item.machineId === m && ["queued", "paused"].includes(item.status)); if (!row) return null; row.status = "running"; return { ...row }; }
  async loadAttachment(scan) { if (!scan.attachment || (["text", "document"].includes(scan.attachment.kind) && !scan.attachment.readText) || (scan.attachment.kind === "archive" && (!scan.attachment.listArchiveEntries || !scan.attachment.materializeArchiveTextEntry || !scan.attachment.readMaterializedText))) throw new AttachmentScanStoreError("Allegato non disponibile.", 409); return scan.attachment; }
  async findCanonicalSegment(scanId, digest) { return (this.segments.get(id(scanId, "Scansione")) || []).find(item => item.contentSha256 === digest && item.status === "analyzed") || null; }
  async findRecordedSegment(scanId, entryId = null, startByte, endByte, digest) {
    const row = (this.segments.get(id(scanId, "Scansione")) || []).find(item => String(item.entryId || "") === String(entryId || "") && item.startByte <= startByte && item.endByte >= endByte && item.contentSha256 === digest && ["analyzed", "duplicate"].includes(item.status));
    return row ? { ...row, classification: row.status, replayed: true, startByte: row.startByte, endByte: row.endByte } : null;
  }
  async listRecentSummaries(scanId, { limit = 8 } = {}) { const bounded = Number.isInteger(limit) ? Math.max(1, Math.min(limit, 8)) : 8; return (this.segments.get(id(scanId, "Scansione")) || []).filter(item => item.status === "analyzed" && typeof item.summary === "string").slice(-bounded).map(item => item.summary); }
  async isArchiveEntryComplete(scanId, entryId, byteSize) { return (this.segments.get(id(scanId, "Scansione")) || []).some(item => item.entryId === entryId && (["unsupported", "empty"].includes(item.status) || item.endByte >= byteSize)); }
  async recordArchiveEntryBoundary({ scanId, entryId, byteSize, classification, summary = null }) {
    const scanIdValue = id(scanId, "Scansione"); const row = this.scans.get(scanIdValue); const items = this.segments.get(scanIdValue) || [];
    if (!row || !entryId || !["empty", "unsupported"].includes(classification) || (classification === "empty" && byteSize !== 0)) throw new AttachmentScanStoreError("Voce archivio non valida.");
    if (!items.some(item => item.entryId === entryId && item.startByte === 0)) {
      items.push({ id: randomUUID(), scanId: scanIdValue, entryId, startByte: 0, endByte: Math.max(1, byteSize), byteSize, contentSha256: "0".repeat(64), summary: classification === "unsupported" ? summary : null, status: classification, unitCount: 1 });
      row.processedEntries = (row.processedEntries || 0) + 1;
      row.analyzedEntries = (row.analyzedEntries || 0) + (classification === "empty" ? 1 : 0);
      row.unsupportedEntries = (row.unsupportedEntries || 0) + (classification === "unsupported" ? 1 : 0);
    }
    this.segments.set(scanIdValue, items); return { ...row };
  }
  async recordSegment(input) {
    const items = this.segments.get(id(input.scanId, "Scansione")) || [];
    const exact = items.find(item => String(item.entryId || "") === String(input.entryId || "") && item.startByte === input.startByte && item.endByte === input.endByte && item.contentSha256 === input.contentSha256 && ["analyzed", "duplicate"].includes(item.status));
    if (exact) return { ...exact, classification: exact.status, replayed: true };
    const previous = items.at(-1);
    if (input.status === "duplicate" && previous?.status === "duplicate" && previous.entryId === input.entryId && previous.contentSha256 === input.contentSha256 && previous.canonicalSegmentId === input.canonicalSegmentId && previous.endByte === input.startByte) { previous.endByte = input.endByte; previous.unitCount += 1; return { id: previous.id, unitCount: 1, merged: true, classification: "duplicate" }; }
    const row = { id: randomUUID(), ...input, unitCount: 1 }; items.push(row); this.segments.set(id(input.scanId, "Scansione"), items); return { ...row, classification: row.status };
  }
  async recordUnsupportedSegment(input) { const items = this.segments.get(id(input.scanId, "Scansione")) || []; const row = { id: randomUUID(), ...input, status: "unsupported", unitCount: 1 }; items.push(row); this.segments.set(id(input.scanId, "Scansione"), items); return row; }
  async recordEmptyArchiveEntry(input) { const items = this.segments.get(id(input.scanId, "Scansione")) || []; const row = { id: randomUUID(), ...input, startByte: 0, endByte: 1, status: "empty", unitCount: 1 }; items.push(row); this.segments.set(id(input.scanId, "Scansione"), items); return row; }
  async checkpoint(scan) {
    const target = this.scans.get(id(scan.id, "Scansione")); if (!target) return null;
    const currentMarker = target.coverage?.autoReply ? structuredClone(target.coverage.autoReply) : null;
    const incomingCoverage = { ...(scan.coverage || {}) };
    if (currentMarker) incomingCoverage.autoReply = currentMarker; else delete incomingCoverage.autoReply;
    Object.assign(target, { ...scan, coverage: incomingCoverage });
    return { ...target };
  }
  async pause(scanId, reason = null) { const row = this.scans.get(id(scanId, "Scansione")); if (row) { row.status = "paused"; row.error = reason ? { code: reason, message: "Analisi in pausa." } : null; } return row ? { ...row } : null; }
  async abort(args = {}) { const s = scope(args); const row = this.scans.get(id(args.scanId, "Scansione")); if (!row || row.ownerId !== s.ownerId || row.machineId !== s.machineId || row.conversationId !== s.conversationId) return null; row.status = "aborted"; row.error = { code: "ATTACHMENT_SCAN_ABORTED", message: "Analisi interrotta." }; if (row.coverage) delete row.coverage.autoReply; return scanPublicStatus(row); }
  async abortClaimed(scanId, code = "ATTACHMENT_SCAN_ABORTED") { const row = this.scans.get(id(scanId, "Scansione")); if (row) { row.status = "aborted"; row.error = { code, message: "Analisi interrotta." }; if (row.coverage) delete row.coverage.autoReply; } return row ? { ...row } : null; }
  async fail(scanId, code = "ATTACHMENT_SCAN_FAILED") { const row = this.scans.get(id(scanId, "Scansione")); if (row) { row.status = "failed"; row.error = { code, message: "Analisi interrotta." }; } return row ? { ...row } : null; }
  async recoverOnStartup({ machineId } = {}) { const m = machine(machineId); let count = 0; for (const row of this.scans.values()) if (row.machineId === m && row.status === "running") { row.status = "queued"; count += 1; } return count; }
  async abortConversation(args = {}) { const s = scope(args); for (const row of this.scans.values()) if (row.ownerId === s.ownerId && row.machineId === s.machineId && row.conversationId === s.conversationId) { if (["queued", "running", "paused"].includes(row.status)) { row.status = "aborted"; row.error = { code: "ATTACHMENT_SCAN_ABORTED", message: "Analisi interrotta." }; } if (row.coverage) delete row.coverage.autoReply; } }
}

function readInlineText(text, startByte, maxBytes) { const source = Buffer.from(text, "utf8"); if (!Number.isSafeInteger(startByte) || startByte < 0 || startByte >= source.length || !Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new AttachmentScanStoreError("Intervallo allegato non valido."); let endByte = Math.min(source.length, startByte + maxBytes); while (endByte < source.length && (source[endByte] & 0xc0) === 0x80) endByte -= 1; return { content: source.subarray(startByte, endByte).toString("utf8"), startByte, endByte, nextByte: endByte < source.length ? endByte : null, hasMore: endByte < source.length }; }
