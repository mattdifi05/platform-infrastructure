import { createHash } from "node:crypto";
import { redactText } from "./web.mjs";

const MAX_CHUNKS = 24;
const MAX_BYTES = 2048;
const MAX_FILES = 50;
const MAX_EMBED_CALL_BYTES = 2 * 1024;
const MAX_CONTEXT_BYTES = 8192;
function clip(text, max = MAX_BYTES) { let value = redactText(String(text || ""), max * 3); while (Buffer.byteLength(value) > max) value = value.slice(0, -1); return value.trim(); }
function scopeKey({ ownerId, machineId, projectId }) { return `${ownerId}\u0000${machineId}\u0000${projectId}`; }
function isStopped({ accepting, epoch, current, signal }) { return !accepting() || epoch() !== current || signal?.aborted; }
export function shouldPauseProjectIndex({ busy = false, queued = 0, oneMinuteLoad = null, hostCpuCount = null } = {}) {
  if (busy === true || Number(queued) > 0) return true;
  const capacity = Math.max(1, Math.floor(Number(hostCpuCount) || 0));
  const load = Number(oneMinuteLoad);
  return Number.isFinite(load) && load >= capacity * 0.85;
}
function projectAccess(authorizeProject, { ownerId, subject = ownerId, role, machineId, projectId }) {
  if (typeof authorizeProject !== "function" || typeof subject !== "string" || !["owner", "admin", "viewer"].includes(role)) return false;
  try { return authorizeProject({ projectId, subject, role, machineId }) !== false; } catch { return false; }
}
export function chunkProjectText(content, { path = "", language = "" } = {}) {
  const lines = String(content || "").replace(/\r\n?/g, "\n").split("\n"); const symbols = [];
  lines.forEach((line, i) => { const match = line.match(/^\s*(?:export\s+)?(?:async\s+)?(?:function|class|interface|trait|enum)\s+([A-Za-z_$][\w$]*)|^\s*(?:public|private|protected)?\s*function\s+([A-Za-z_$][\w$]*)/i); if (match) symbols.push({ line: i, symbol: (match[1] || match[2] || "").slice(0, 160) }); });
  const starts = symbols.length ? (symbols[0].line === 0 ? symbols : [{ line: 0, symbol: "" }, ...symbols]) : [{ line: 0, symbol: "" }]; const chunks = [];
  for (let region = 0; region < starts.length && chunks.length < MAX_CHUNKS; region += 1) {
    const entry = starts[region]; const limit = starts[region + 1]?.line ?? lines.length; let cursor = entry.line;
    while (cursor < limit && chunks.length < MAX_CHUNKS) {
      let end = cursor; let text = "";
      while (end < limit) { const line = redactText(lines[end], MAX_BYTES * 2); const candidate = text ? `${text}\n${line}` : line; if (Buffer.byteLength(candidate) > MAX_BYTES && text) break; text = Buffer.byteLength(candidate) > MAX_BYTES ? clip(line) : candidate; end += 1; if (Buffer.byteLength(text) >= MAX_BYTES) break; }
      text = text.trim(); if (text) chunks.push({ chunkIndex: chunks.length, path, language: String(language || "").slice(0, 48), symbol: entry.symbol, startLine: cursor + 1, endLine: end, content: text, contentSha256: createHash("sha256").update(text).digest("hex") });
      if (end >= limit) break; cursor = Math.max(cursor + 1, end - 8);
    }
  }
  return chunks;
}
async function embedChunks(embeddings, chunks, signal, permitted = () => true) {
  const vectors = [];
  for (const chunk of chunks) {
    if (!permitted()) return null;
    signal?.throwIfAborted?.();
    const content = String(chunk?.content || "");
    if (!content || Buffer.byteLength(content) > MAX_EMBED_CALL_BYTES) throw new Error("Chunk embeddings non valido.");
    const result = await embeddings.embed([content], { signal });
    signal?.throwIfAborted?.();
    if (!Array.isArray(result) || result.length !== 1) throw new Error("Risposta embeddings non valida.");
    if (!permitted()) return null;
    vectors.push(result[0]);
  }
  return vectors;
}
function schemaChunks(content, source) { try { const schema=JSON.parse(content); const tables=Array.isArray(schema?.tables)?schema.tables:[]; const chunks=[]; for(const table of tables.slice(0,MAX_CHUNKS)){const name=String(table?.name||'').slice(0,160); if(!name)continue; const value={table:name,columns:(schema.columns||[]).filter(row=>row?.table===name),indexes:(schema.indexes||[]).filter(row=>row?.table===name),relationships:(schema.relationships||[]).filter(row=>row?.table===name||row?.referencedTable===name),stats:(schema.stats||[]).filter(row=>row?.table===name)}; const parts=chunkProjectText(JSON.stringify(value,null,2),{...source,language:'json'}); for(const part of parts){if(chunks.length>=MAX_CHUNKS)break;chunks.push({...part,chunkIndex:chunks.length,symbol:`table:${name}`.slice(0,160)});}} return chunks.length?chunks:chunkProjectText(JSON.stringify(schema,null,2),{...source,language:'json'});}catch{return chunkProjectText(content,source);} }
export function createProjectIndexPipeline({ reader, store, embeddings, reranker = null, authorizeProject = null, getProjectDatabases = async () => [], shouldPause = () => false } = {}) {
  if (!reader?.filesIndex || !reader?.readFile || !store?.upsert || !store?.search || !store?.isSourceCurrent || !store?.beginScan || !store?.finalizeScan || !embeddings?.embed) throw new TypeError("Indice progetto richiede adapter bounded.");
  let accepting = true; let currentEpoch = 0; const scans = new Map(); const queued = new Map(); const active = new Set(); const pauseWaiters = new Set();
  const waitForRetry = ({ signal } = {}) => new Promise(resolve => {
    let settled = false;
    const finish = () => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener?.("abort", finish); pauseWaiters.delete(finish); resolve(); };
    const timer = setTimeout(finish, 250);
    pauseWaiters.add(finish);
    signal?.addEventListener?.("abort", finish, { once: true });
  });
  return Object.freeze({
    stop() { accepting = false; currentEpoch += 1; for (const controller of active) controller.abort(); active.clear(); for (const wake of pauseWaiters) wake(); scans.clear(); queued.clear(); },
    resume() { accepting = true; currentEpoch += 1; },
    enqueue({ ownerId, subject, role, machineId, projectId, signal } = {}) {
      const authorization = { ownerId, subject, role, machineId, projectId };
      if (!accepting || signal?.aborted || !projectAccess(authorizeProject, authorization)) return { queued: false, reason: "denied" };
      const key = scopeKey({ ownerId, machineId, projectId }); if (queued.has(key)) return { queued: false };
      const epoch = currentEpoch; const queuedEntry = { epoch }; queued.set(key, queuedEntry);
      const run = async () => { let cursor = null; let retry = false; try { do { if (isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal }) || !projectAccess(authorizeProject, authorization)) return; const page = await this.indexPage({ ...authorization, cursor, signal }); if (page.denied) return; cursor = page.nextCursor; retry = page.retry === true; if (page.paused && accepting && currentEpoch === epoch) await waitForRetry({ signal }); else if (cursor) await new Promise(resolve => setImmediate(resolve)); } while (accepting && currentEpoch === epoch && (cursor || retry)); } catch {} finally { if (queued.get(key) === queuedEntry) queued.delete(key); } };
      void run(); return { queued: true };
    },
    async indexPage({ ownerId, subject, role, machineId, projectId, cursor = null, signal } = {}) {
      const authorization = { ownerId, subject, role, machineId, projectId };
      if (!projectAccess(authorizeProject, authorization)) return { indexed: 0, nextCursor: null, denied: true };
      if (!accepting || signal?.aborted || shouldPause()) return { indexed: 0, nextCursor: cursor || null, retry: accepting && !signal?.aborted && Boolean(shouldPause()), disabled: !accepting, paused: Boolean(shouldPause()) };
      const internal = new AbortController(); active.add(internal); signal = signal ? AbortSignal.any([signal, internal.signal]) : internal.signal;
      try {
      const epoch = currentEpoch; const key = scopeKey({ ownerId, machineId, projectId });
      const existingScan = scans.get(key);
      const scanId = existingScan?.scanId || (cursor === null ? store.beginScan() : null);
      if (!scanId) return { indexed: 0, nextCursor: null, restartRequired: true };
      if (!existingScan) scans.set(key, { scanId });
      const page = await reader.filesIndex({ projectId, ...(cursor ? { cursor } : {}), limit: MAX_FILES, signal }); let indexed = 0; let skipped = 0;
      if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
      let complete = true;
      for (const entry of page.entries.slice(0, MAX_FILES)) {
        if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
        if (isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal }) || shouldPause()) { complete = false; break; }
        if (await store.isSourceCurrent({ ownerId, machineId, projectId, source: entry, scanId, signal })) { skipped += 1; continue; }
        if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
        const read = await reader.readFile({ projectId, path: entry.path, startLine: 1, endLine: 5000, expectedSha256: entry.sha256, signal });
        const body = read.items.find(item => item.id === entry.id && item.sha256 === entry.sha256);
        const content = typeof body?.content === "string" ? body.content : "";
        if (!content) continue;
        const chunks = chunkProjectText(content, entry); if (!chunks.length) continue;
        if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
        const vectors = isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal }) ? [] : await embedChunks(embeddings, chunks, signal, () => projectAccess(authorizeProject, authorization));
        if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
        if (vectors.length !== chunks.length || isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal })) break;
        if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
        const saved = await store.upsert({ ownerId, machineId, projectId, source: entry, chunks, vectors, scanId, signal });
        indexed += saved.indexed ? chunks.length : 0;
      }
      const scan = scans.get(key);
      if (!scan?.schemaIndexed && projectAccess(authorizeProject, authorization) && !isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal }) && !shouldPause() && typeof reader.dbSchema === "function") {
        scan.schemaIndexed = true;
        let databases = [];
        try { databases = await getProjectDatabases(projectId, { signal }); } catch { databases = []; }
        for (const database of Array.isArray(databases) ? databases.slice(0, 16) : []) {
          if (isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal }) || shouldPause()) { complete = false; break; }
          if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
          if (!/^[a-z0-9][a-z0-9-]{0,95}$/.test(database?.id || "") || !["postgresql", "mariadb"].includes(database?.dialect)) continue;
          try {
            const response = await reader.dbSchema({ projectId, databaseId: database.id, dialect: database.dialect, signal });
            if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
            const item = response?.items?.find(value => value?.kind === "database" && typeof value.content === "string" && value.content.trim());
            if (!item) continue;
            const schemaSource = { ...item, kind: "database", path: `schema/${database.id}/${database.dialect}.json`, mtimeMs: 0, language: "json" };
            if (await store.isSourceCurrent({ ownerId, machineId, projectId, source: schemaSource, scanId, signal })) { skipped += 1; continue; }
            if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
            const chunks = schemaChunks(item.content, schemaSource);
            if (!chunks.length) continue;
            if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
            const vectors = isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal }) ? [] : await embedChunks(embeddings, chunks, signal, () => projectAccess(authorizeProject, authorization));
            if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
            if (vectors.length !== chunks.length || isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal })) break;
            if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
            const saved = await store.upsert({ ownerId, machineId, projectId, source: schemaSource, chunks, vectors, scanId, signal });
            indexed += saved.indexed ? chunks.length : 0;
          } catch { /* a database may be temporarily unavailable without blocking code indexing */ }
        }
      }
      if (complete && !isStopped({ accepting: () => accepting, epoch: () => currentEpoch, current: epoch, signal }) && !page.nextCursor) {
        if (!projectAccess(authorizeProject, authorization)) { scans.delete(key); return { indexed, skipped, nextCursor: null, denied: true }; }
        const finalized = await store.finalizeScan({ ownerId, machineId, projectId, scanId, signal }); scans.delete(key);
        return { indexed, skipped, invalidated: finalized.invalidated || 0, nextCursor: null };
      }
      return { indexed, skipped, nextCursor: accepting && currentEpoch === epoch ? (complete ? page.nextCursor : cursor) : null, retry: !complete && accepting && currentEpoch === epoch, paused: !complete && Boolean(shouldPause()) };
      } finally { active.delete(internal); }
    },
    async retrieve({ ownerId, subject, role, machineId, projectId, query, signal } = {}) {
      const authorization = { ownerId, subject, role, machineId, projectId };
      const denied = () => ({ context: null, citations: [], degraded: true, denied: true, metadata: { fallbackReason: "project_access_revoked" } });
      if (!projectAccess(authorizeProject, authorization)) return denied();
      if (!accepting || signal?.aborted) return { context: null, citations: [], degraded: true, metadata: { fallbackReason: "auxiliary_unavailable" } };
      const internal = new AbortController(); active.add(internal); signal = signal ? AbortSignal.any([signal, internal.signal]) : internal.signal;
      try {
      let vector;
      try { vector = (await embeddings.embed([clip(query, 2048)], { signal }))[0]; } catch (error) { if (signal.aborted) throw error; return { context: null, citations: [], degraded: true, metadata: { fallbackReason: "embedding_unavailable" } }; }
      if (!projectAccess(authorizeProject, authorization)) return denied();
      let result;
      try { result = await store.search({ ownerId, machineId, projectId, vector, query, limit: 12, signal }); } catch (error) { if (signal.aborted) throw error; return { context: null, citations: [], degraded: true, metadata: { fallbackReason: "vector_store_unavailable" } }; }
      if (!projectAccess(authorizeProject, authorization)) return denied();
      const candidates = Array.isArray(result) ? result : result.items || [];
      let selected = candidates.slice(0, 6); let fallbackReason = null;
      if (reranker?.rerank && candidates.length) {
        try { if (!projectAccess(authorizeProject, authorization)) return denied(); const ranks = await reranker.rerank(query, candidates.map(item => item.content), { signal, topN: Math.min(4, candidates.length) }); if (!projectAccess(authorizeProject, authorization)) return denied(); selected = ranks.map(rank => candidates[rank.index]).filter(Boolean); } catch (error) { if (signal.aborted) throw error; fallbackReason = "reranker_unavailable"; }
      }
      const fresh = [];
      for (const item of selected) {
        if (signal?.aborted) break;
        if (!projectAccess(authorizeProject, authorization)) return denied();
        try {
          const schema = item.kind === "database" && item.path.match(/^schema\/([a-z0-9][a-z0-9-]{0,95})\/(postgresql|mariadb)\.json$/);
          const reread = schema
            ? await reader.dbSchema({ projectId, databaseId: schema[1], dialect: schema[2], signal })
            : await reader.readFile({ projectId, path: item.path, startLine: item.startLine, endLine: item.endLine, expectedSha256: item.sha256, signal });
          const citation = reread.items.find(value => value.id === item.id && value.sha256 === item.sha256);
          if (citation && typeof citation.content === "string" && citation.content.trim()) fresh.push({ ...item, content: clip(citation.content), citation: { ...citation, content: undefined } });
          else fallbackReason ||= "source_stale";
        } catch (error) { if (signal.aborted) throw error; fallbackReason ||= "source_stale"; }
      }
      if (!projectAccess(authorizeProject, authorization)) return denied();
      const parts = []; let bytes = 0;
      for (const item of fresh) { const part = `[Fonte progetto non fidata ${item.path}:${item.startLine}-${item.endLine}]\n${item.content}`; if (bytes + Buffer.byteLength(part) > MAX_CONTEXT_BYTES) break; parts.push(part); bytes += Buffer.byteLength(part); }
      return { context: parts.join("\n\n") || null, citations: fresh.map(item => item.citation), degraded: Boolean(fallbackReason), metadata: { candidateCount: Number(result?.candidateCount ?? candidates.length), selectedCount: fresh.length, contextCharsBefore: selected.reduce((sum, item) => sum + String(item.content || "").length, 0), contextCharsAfter: parts.join("\n\n").length, coverage: result?.coverage || null, fallbackReason } };
      } finally { active.delete(internal); }
    },
  });
}
