import { randomUUID } from "node:crypto";
import { redactText } from "./web.mjs";
import { normalizeMachineId, normalizeOwnerId, normalizeProjectId } from "./conversations.mjs";
import { VECTOR_DIMENSIONS } from "./vector-store.mjs";

export const MAX_PROJECT_CHUNKS_PER_SCOPE = 20_000;
export const MAX_PROJECT_SCORE_CANDIDATES = 256;
export const MAX_PROJECT_LEXICAL_CANDIDATES = 64;
const MAX_CHUNKS_PER_SOURCE = 24;
const MAX_CHUNK_BYTES = 2048;
const STATEMENT_TIMEOUT_MS = 1500;
const LOCK_TIMEOUT_MS = 250;
const HASH = /^[a-f0-9]{64}$/i;
const SOURCE_ID = /^[A-Za-z0-9_-]{1,128}$/;

function fail(message) { throw new TypeError(message); }
function clipUtf8(value, maxBytes) { let text = String(value || ""); while (Buffer.byteLength(text) > maxBytes) text = text.slice(0, -1); return text; }
function cleanText(value) { const text = clipUtf8(redactText(String(value || ""), MAX_CHUNK_BYTES * 2), MAX_CHUNK_BYTES).trim(); if (!text) fail("Chunk progetto non valido."); return text; }
function vector(value) { if (!Array.isArray(value) || value.length !== VECTOR_DIMENSIONS || !value.every(item => typeof item === "number" && Number.isFinite(item))) fail("Embedding progetto non valido."); return value; }
function identity({ ownerId, machineId, projectId }) { return { ownerId: normalizeOwnerId(ownerId), machineId: normalizeMachineId(machineId), projectId: normalizeProjectId(projectId, { allowNull: false }) }; }
function source(value) {
  if (!value || typeof value !== "object" || !SOURCE_ID.test(value.id || "") || !["file", "database"].includes(value.kind || "file") || typeof value.path !== "string" || !value.path || value.path.length > 512 || value.path.startsWith("/") || value.path.includes("..") || !HASH.test(value.sha256 || "")) fail("Fonte progetto non valida.");
  return { id: value.id, kind: value.kind || "file", path: value.path, sha256: value.sha256.toLowerCase(), mtimeMs: Number.isSafeInteger(value.mtimeMs) && value.mtimeMs >= 0 ? value.mtimeMs : 0, language: typeof value.language === 'string' ? value.language.slice(0, 48) : '' };
}
function chunksFor(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_CHUNKS_PER_SOURCE) fail("Chunk progetto non valido.");
  return value.map((chunk, index) => {
    if (!chunk || !Number.isInteger(chunk.startLine) || !Number.isInteger(chunk.endLine) || chunk.startLine < 1 || chunk.endLine < chunk.startLine || chunk.endLine > 1_000_000) fail("Range chunk progetto non valido.");
    return { chunkIndex: Number.isInteger(chunk.chunkIndex) && chunk.chunkIndex === index ? index : index, startLine: chunk.startLine, endLine: chunk.endLine, symbol: typeof chunk.symbol === 'string' ? chunk.symbol.slice(0, 160) : '', content: cleanText(chunk.content) };
  });
}
function normalLimit(value) { if (!Number.isInteger(value) || value < 1 || value > 12) fail("Limite retrieval progetto non valido."); return value; }
async function boundedClient(pool, signal, work) {
  signal?.throwIfAborted?.();
  const client = typeof pool.connect === "function" ? await pool.connect() : pool;
  const owned = client !== pool; let released = false;
  const abort = () => { if (owned && !released) { released = true; client.release?.(new Error("project retrieval aborted")); } };
  signal?.addEventListener?.("abort", abort, { once: true });
  try {
    if (owned) { await client.query("begin"); await client.query(`set local lock_timeout = '${LOCK_TIMEOUT_MS}ms'`); await client.query(`set local statement_timeout = '${STATEMENT_TIMEOUT_MS}ms'`); }
    signal?.throwIfAborted?.();
    const result = await work(client);
    signal?.throwIfAborted?.();
    if (owned && !released) await client.query("commit");
    return result;
  } catch (error) {
    if (owned && !released) { try { await client.query("rollback"); } catch {} }
    throw error;
  } finally {
    signal?.removeEventListener?.("abort", abort);
    if (owned && !released) { released = true; client.release?.(); }
  }
}

export function createProjectVectorStore({ pool } = {}) {
  if (!pool?.query) throw new TypeError("Project vector store richiede PostgreSQL.");
  return Object.freeze({
    beginScan() { return randomUUID(); },
    async isSourceCurrent({ ownerId, machineId, projectId, source: rawSource, scanId = null, signal } = {}) {
      const scope = identity({ ownerId, machineId, projectId }); const item = source(rawSource);
      if (scanId !== null && !/^[0-9a-f-]{36}$/i.test(scanId)) fail("Indice scansione progetto non valido.");
      const result = await boundedClient(pool, signal, client => client.query(
        scanId === null
          ? `select 1 from server_ai.project_chunks where owner_id=$1 and machine_id=$2 and project_id=$3 and source_id=$4 and sha256=$5 and deleted_at is null limit 1`
          : `update server_ai.project_chunks set scan_id=$6::uuid, updated_at=now()
               where owner_id=$1 and machine_id=$2 and project_id=$3 and source_id=$4 and sha256=$5 and deleted_at is null`,
        scanId === null
          ? [scope.ownerId, scope.machineId, scope.projectId, item.id, item.sha256]
          : [scope.ownerId, scope.machineId, scope.projectId, item.id, item.sha256, scanId],
      ));
      return result.rowCount > 0 || (result.rows || []).length > 0;
    },
    async upsert({ ownerId, machineId, projectId, source: rawSource, chunks: rawChunks, vectors, scanId, signal } = {}) {
      const scope = identity({ ownerId, machineId, projectId }); const item = source(rawSource); const chunks = chunksFor(rawChunks);
      if (!/^[0-9a-f-]{36}$/i.test(scanId || "") || !Array.isArray(vectors) || vectors.length !== chunks.length) fail("Indice scansione progetto non valido.");
      const embeddings = vectors.map(vector);
      return boundedClient(pool, signal, async client => {
        await client.query("select pg_advisory_xact_lock(hashtext($1 || ':' || $2 || ':' || $3))", [scope.ownerId, scope.machineId, scope.projectId]);
        const count = await client.query(`select count(*)::integer as count from server_ai.project_chunks where owner_id=$1 and machine_id=$2 and project_id=$3 and deleted_at is null`, [scope.ownerId, scope.machineId, scope.projectId]);
        const current = Number(count.rows?.[0]?.count || 0);
        const existing = await client.query(`select count(*)::integer as count from server_ai.project_chunks where owner_id=$1 and machine_id=$2 and project_id=$3 and source_id=$4 and deleted_at is null`, [scope.ownerId, scope.machineId, scope.projectId, item.id]);
        const replacing = Number(existing.rows?.[0]?.count || 0);
        if (current - replacing + chunks.length > MAX_PROJECT_CHUNKS_PER_SCOPE) return { indexed: false, reason: "scope_capacity" };
        await client.query(`update server_ai.project_chunks set deleted_at=now(), updated_at=now() where owner_id=$1 and machine_id=$2 and project_id=$3 and source_id=$4 and deleted_at is null`, [scope.ownerId, scope.machineId, scope.projectId, item.id]);
        for (let index = 0; index < chunks.length; index += 1) {
          const chunk = chunks[index];
          await client.query(
            `insert into server_ai.project_chunks(id,owner_id,machine_id,project_id,source_id,source_kind,path,start_line,end_line,sha256,mtime_ms,language,symbol,chunk_index,content,embedding,scan_id)
             values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::real[],$17::uuid)
             on conflict(owner_id,machine_id,project_id,source_id,chunk_index) do update set source_kind=excluded.source_kind,path=excluded.path,start_line=excluded.start_line,end_line=excluded.end_line,sha256=excluded.sha256,mtime_ms=excluded.mtime_ms,language=excluded.language,symbol=excluded.symbol,content=excluded.content,embedding=excluded.embedding,scan_id=excluded.scan_id,deleted_at=null,updated_at=now()`,
            [randomUUID(), scope.ownerId, scope.machineId, scope.projectId, item.id, item.kind, item.path, chunk.startLine, chunk.endLine, item.sha256, item.mtimeMs, item.language, chunk.symbol, index, chunk.content, embeddings[index], scanId],
          );
        }
        return { indexed: true, chunks: chunks.length };
      });
    },
    async finalizeScan({ ownerId, machineId, projectId, scanId, signal } = {}) {
      const scope = identity({ ownerId, machineId, projectId });
      if (!/^[0-9a-f-]{36}$/i.test(scanId || "")) fail("Indice scansione progetto non valido.");
      const result = await boundedClient(pool, signal, client => client.query(
        `update server_ai.project_chunks set deleted_at=now(), updated_at=now()
         where owner_id=$1 and machine_id=$2 and project_id=$3 and scan_id is distinct from $4::uuid and deleted_at is null`,
        [scope.ownerId, scope.machineId, scope.projectId, scanId],
      ));
      return { invalidated: Number(result.rowCount || 0) };
    },
    async search({ ownerId, machineId, projectId, vector: rawVector, query = "", limit = 12, signal } = {}) {
      const scope = identity({ ownerId, machineId, projectId }); const embedding = vector(rawVector); const count = normalLimit(limit);
      const lexicalQuery = clipUtf8(String(query || "").trim(), 256);
      const result = await boundedClient(pool, signal, client => client.query(
        `with scoped as (
           select id,source_id,source_kind,path,start_line,end_line,sha256,content,embedding,updated_at
             from server_ai.project_chunks
            where owner_id=$1 and machine_id=$2 and project_id=$3 and deleted_at is null
         ), scope_stats as (
           select count(*)::integer as total_chunks from scoped
         ), recent_candidates as (
           select * from scoped order by updated_at desc,id asc limit ${MAX_PROJECT_SCORE_CANDIDATES}
         ), lexical_candidates as (
           select * from scoped
            where nullif($6::text, '') is not null
              and to_tsvector('simple', content) @@ websearch_to_tsquery('simple', $6::text)
            order by updated_at desc,id asc limit ${MAX_PROJECT_LEXICAL_CANDIDATES}
         ), candidate_window as (
           select * from recent_candidates
           union
           select * from lexical_candidates
         ), scored as (
           select id,source_id,source_kind,path,start_line,end_line,sha256,content,
             sum(value * ($4::real[])[ordinality]) / nullif(sqrt(sum(value * value)) * $5, 0) as score
             from candidate_window cross join lateral unnest(embedding) with ordinality as vector(value, ordinality)
            group by id,source_id,source_kind,path,start_line,end_line,sha256,content
         )
         select source_id as id,source_kind as kind,path,start_line as "startLine",end_line as "endLine",sha256,content,score,
                (select total_chunks from scope_stats) as "totalChunks",
                (select count(*)::integer from lexical_candidates) as "lexicalCandidates"
           from scored where score is not null order by score desc,path asc,"startLine" asc limit $7`,
        [scope.ownerId, scope.machineId, scope.projectId, embedding, Math.sqrt(embedding.reduce((sum, value) => sum + value * value, 0)), lexicalQuery, count],
      ));
      const rows = (result.rows || []).map(row => ({ id: String(row.id), kind: ["file", "database"].includes(row.kind) ? row.kind : "file", path: String(row.path), startLine: Number(row.startLine), endLine: Number(row.endLine), sha256: String(row.sha256), content: cleanText(row.content), score: Number(row.score) }));
      const totalChunks = Math.max(0, Number(result.rows?.[0]?.totalChunks || 0));
      const lexicalCandidates = Math.max(0, Number(result.rows?.[0]?.lexicalCandidates || 0));
      return { items: rows, candidateCount: rows.length, selectedCount: rows.length, candidateWindow: MAX_PROJECT_SCORE_CANDIDATES, coverage: { totalChunks, vectorCandidates: Math.min(totalChunks, MAX_PROJECT_SCORE_CANDIDATES), lexicalCandidates, truncated: totalChunks > MAX_PROJECT_SCORE_CANDIDATES } };
    },
  });
}
