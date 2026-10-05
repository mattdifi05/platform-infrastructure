import { randomUUID } from "node:crypto";
import { redactText } from "./web.mjs";
import { normalizeConversationId, normalizeMachineId, normalizeOwnerId, normalizeProjectId } from "./conversations.mjs";

export const VECTOR_DIMENSIONS = 1024;
export const MAX_RETRIEVAL_CHUNK_BYTES = 2 * 1024;
export const MAX_RETRIEVAL_CHUNKS_PER_MESSAGE = 16;
export const MAX_RETRIEVAL_CANDIDATES = 12;
export const MAX_RETRIEVAL_CHUNKS_PER_SCOPE = 20_000;
export const MAX_BACKFILL_MESSAGES = 2;
const MAX_RETRIEVAL_MESSAGE_BYTES = MAX_RETRIEVAL_CHUNK_BYTES * MAX_RETRIEVAL_CHUNKS_PER_MESSAGE;
const RETRIEVAL_STATEMENT_TIMEOUT_MS = 1500;
const RETRIEVAL_LOCK_TIMEOUT_MS = 250;
const MAX_CURATED_RUNBOOK_CANDIDATES = 64;

function fail(message) { throw new TypeError(message); }
function finiteVector(value) {
  if (!Array.isArray(value) || value.length !== VECTOR_DIMENSIONS || !value.every(number => typeof number === "number" && Number.isFinite(number))) fail("Embedding non valido.");
  return value;
}
function clipUtf8(value, maxBytes) {
  if (Buffer.byteLength(value) <= maxBytes) return value;
  let end = Math.min(value.length, maxBytes);
  while (end > 0 && Buffer.byteLength(value.slice(0, end)) > maxBytes) end -= 1;
  return value.slice(0, end);
}
function boundedText(value, maxBytes = MAX_RETRIEVAL_CHUNK_BYTES) {
  const text = clipUtf8(redactText(String(value || ""), maxBytes * 4), maxBytes).trim();
  if (!text || Buffer.byteLength(text) > maxBytes) fail("Chunk retrieval non valido.");
  return text;
}

function takeUtf8(value, maxBytes) {
  const part = clipUtf8(value, maxBytes);
  return [part, value.slice(part.length)];
}

export function splitRetrievalChunks(content) {
  const words = boundedText(content, MAX_RETRIEVAL_MESSAGE_BYTES).split(/\s+/);
  const chunks = [];
  let current = "";
  for (const word of words) {
    let remaining = word;
    while (remaining && chunks.length < MAX_RETRIEVAL_CHUNKS_PER_MESSAGE) {
      const next = current ? `${current} ${remaining}` : remaining;
      if (Buffer.byteLength(next) <= MAX_RETRIEVAL_CHUNK_BYTES) { current = next; break; }
      if (current) { chunks.push(current); current = ""; continue; }
      const [part, rest] = takeUtf8(remaining, MAX_RETRIEVAL_CHUNK_BYTES);
      if (!part) break;
      chunks.push(part);
      remaining = rest;
    }
  }
  if (current && chunks.length < MAX_RETRIEVAL_CHUNKS_PER_MESSAGE) chunks.push(current);
  return chunks;
}
function scope({ ownerId, machineId, projectId = null, conversationId, messageId }) {
  return {
    ownerId: normalizeOwnerId(ownerId), machineId: normalizeMachineId(machineId), projectId: normalizeProjectId(projectId),
    conversationId: normalizeConversationId(conversationId), messageId: normalizeConversationId(messageId),
  };
}
function normalizeLimit(value) {
  if (!Number.isInteger(value) || value < 1 || value > MAX_RETRIEVAL_CANDIDATES) fail("Limite retrieval non valido.");
  return value;
}
function normalizeAuthorizedProjects(value) {
  if (value === undefined) return null;
  if (!Array.isArray(value) || value.length > 64) fail("Ambiti progetto autorizzati non validi.");
  return [...new Set(value.map(item => normalizeProjectId(item, { allowNull: false })))];
}

async function withBoundedRetrievalClient(pool, signal, work) {
  signal?.throwIfAborted?.();
  const client = typeof pool.connect === "function" ? await pool.connect() : pool;
  const ownsClient = client !== pool;
  let released = false;
  const abort = () => {
    // node-postgres cancels an in-flight query by discarding this dedicated
    // checkout. Never leave a cancelled cosine scan in the shared auth pool.
    if (ownsClient && !released) { released = true; client.release?.(new Error("retrieval aborted")); }
  };
  signal?.addEventListener?.("abort", abort, { once: true });
  try {
    if (ownsClient) {
      await client.query("begin");
      await client.query(`set local lock_timeout = '${RETRIEVAL_LOCK_TIMEOUT_MS}ms'`);
      await client.query(`set local statement_timeout = '${RETRIEVAL_STATEMENT_TIMEOUT_MS}ms'`);
    }
    signal?.throwIfAborted?.();
    const value = await work(client);
    signal?.throwIfAborted?.();
    if (ownsClient && !released) await client.query("commit");
    return value;
  } catch (error) {
    if (ownsClient && !released) { try { await client.query("rollback"); } catch {} }
    throw error;
  } finally {
    signal?.removeEventListener?.("abort", abort);
    if (ownsClient && !released) { released = true; client.release?.(); }
  }
}

export function createPostgresVectorStore({ pool } = {}) {
  if (!pool || typeof pool.query !== "function") throw new TypeError("Vector store richiede PostgreSQL.");
  return Object.freeze({
    async indexConversationMessage({ ownerId, machineId, projectId = null, conversationId, messageId, content, embeddings, signal } = {}) {
      signal?.throwIfAborted?.();
      const identity = scope({ ownerId, machineId, projectId, conversationId, messageId });
      const chunks = splitRetrievalChunks(content);
      if (!Array.isArray(embeddings) || embeddings.length !== chunks.length) fail("Embeddings chunk non validi.");
      const vectors = embeddings.map(finiteVector);
      const client = typeof pool.connect === "function" ? await pool.connect() : pool;
      const ownsClient = client !== pool;
      let released = false;
      const abort = () => { if (ownsClient && !released) { released = true; client.release?.(new Error("retrieval aborted")); } };
      signal?.addEventListener?.("abort", abort, { once: true });
      try {
        if (ownsClient) {
          await client.query("begin");
          await client.query(`set local lock_timeout = '${RETRIEVAL_LOCK_TIMEOUT_MS}ms'`);
          await client.query(`set local statement_timeout = '${RETRIEVAL_STATEMENT_TIMEOUT_MS}ms'`);
          // Serialize capacity checks for this private owner/machine scope.
          await client.query("select pg_advisory_xact_lock(hashtext($1 || ':' || $2))", [identity.ownerId, identity.machineId]);
        }
        signal?.throwIfAborted?.();
        const capacity = await client.query(
          `select count(*)::integer as count from server_ai.retrieval_chunks
           where scope_type='conversation' and owner_id=$1 and machine_id=$2 and project_id is not distinct from $3 and deleted_at is null`,
          [identity.ownerId, identity.machineId, identity.projectId],
        );
        signal?.throwIfAborted?.();
        const count = Number(capacity.rows?.[0]?.count || 0);
        if (count + chunks.length > MAX_RETRIEVAL_CHUNKS_PER_SCOPE) {
          if (ownsClient) await client.query("commit");
          return { indexed: false, reason: "scope_capacity", pendingChunks: chunks.length };
        }
        for (let index = 0; index < chunks.length; index += 1) {
          const inserted = await client.query(
          `with live_conversation as (
             select id, project_id from server_ai.conversations
              where id=$4 and owner_id=$2 and machine_id=$3 and project_id is not distinct from $5 and deleted_at is null
              for update
           )
           insert into server_ai.retrieval_chunks
             (id, scope_type, owner_id, machine_id, project_id, conversation_id, message_id, chunk_index, content, embedding)
           select $1,'conversation',$2,$3,project_id,$4,$6,$7,$8,$9::real[] from live_conversation
           on conflict (message_id, chunk_index) where scope_type='conversation' do update
             set content=excluded.content, embedding=excluded.embedding, deleted_at=null, updated_at=now()
             where exists (select 1 from server_ai.conversations c where c.id=excluded.conversation_id and c.owner_id=$2 and c.machine_id=$3 and c.project_id is not distinct from $5 and c.deleted_at is null)
           returning id`,
          [randomUUID(), identity.ownerId, identity.machineId, identity.conversationId, identity.projectId, identity.messageId, index, chunks[index], vectors[index]],
          );
          if (inserted.rowCount !== 1) {
            if (ownsClient) await client.query("commit");
            return { indexed: false, reason: "conversation_deleted" };
          }
        }
        if (ownsClient) await client.query("commit");
        return { indexed: true, chunks: chunks.length };
      } catch (error) {
        if (ownsClient) { try { await client.query("rollback"); } catch {} }
        throw error;
      } finally {
        signal?.removeEventListener?.("abort", abort);
        if (ownsClient && !released) { released = true; client.release?.(); }
      }
    },
    async search({ ownerId, machineId, projectId = null, embedding, limit = MAX_RETRIEVAL_CANDIDATES, authorizedProjectIds, signal } = {}) {
      const owner = normalizeOwnerId(ownerId);
      const machine = normalizeMachineId(machineId);
      const project = normalizeProjectId(projectId);
      const vector = finiteVector(embedding);
      const count = normalizeLimit(limit);
      const allowedProjects = normalizeAuthorizedProjects(authorizedProjectIds);
      const result = await withBoundedRetrievalClient(pool, signal, client => client.query(
        `with conversation_scoped as (
           select r.id, r.scope_type, r.conversation_id, r.content, r.embedding
           from server_ai.retrieval_chunks r
           join server_ai.conversations c on c.id=r.conversation_id
           where r.machine_id=$2 and r.deleted_at is null
             and r.scope_type='conversation' and r.owner_id=$1 and c.owner_id=$1 and c.machine_id=$2 and c.deleted_at is null
             and (
               ($7::text[] is null and r.project_id is not distinct from $3 and c.project_id is not distinct from $3)
               or ($7::text[] is not null and r.project_id is not distinct from c.project_id and (r.project_id is null or r.project_id = any($7::text[])))
             )
             and ($7::text[] is null or (
               (c.project_id is null or c.project_id = any($7::text[]))
               and not exists (
                 select 1 from server_ai.messages source_message
                 cross join lateral jsonb_array_elements(case when jsonb_typeof(source_message.source_metadata)='array' then source_message.source_metadata else '[]'::jsonb end) as source
                  where source_message.conversation_id=c.id
                    and source->>'type'='project'
                    and coalesce(source->>'projectId' = any($7::text[]), false) is not true
               )
             ))
         ), runbook_scoped as (
           select r.id, r.scope_type, r.conversation_id, r.content, r.embedding
           from server_ai.retrieval_chunks r
           where r.machine_id=$2 and r.project_id is not distinct from $3 and r.deleted_at is null
             and r.scope_type='runbook' and r.owner_id is null and r.curated=true
           order by r.updated_at desc, r.id asc limit ${MAX_CURATED_RUNBOOK_CANDIDATES}
         ), scoped as (
           select * from conversation_scoped union all select * from runbook_scoped
         ), scored as (
           select id, scope_type, conversation_id, content,
             sum(value * ($4::real[])[ordinality]) / nullif(sqrt(sum(value * value)) * $5, 0) as score
           from scoped cross join lateral unnest(embedding) with ordinality as vector(value, ordinality)
           group by id, scope_type, conversation_id, content
         )
         select id, scope_type, conversation_id, content, score from scored
         where score is not null order by score desc, id asc limit $6`,
        [owner, machine, project, vector, Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0)), count, allowedProjects],
      ));
      return (result.rows || []).map(row => ({ id: String(row.id), kind: row.scope_type === "runbook" ? "runbook" : "conversation", sourceConversationId: row.scope_type === "conversation" ? String(row.conversation_id || "") : null, content: boundedText(row.content) }));
    },
    async listUnindexedConversationMessages({ ownerId, machineId, projectId = null, limit = MAX_BACKFILL_MESSAGES } = {}) {
      const owner = normalizeOwnerId(ownerId);
      const machine = normalizeMachineId(machineId);
      const project = normalizeProjectId(projectId);
      if (!Number.isInteger(limit) || limit < 1 || limit > MAX_BACKFILL_MESSAGES) fail("Limite backfill retrieval non valido.");
      const result = await pool.query(
        `select m.id as message_id, m.conversation_id,
                substring(m.content from 1 for 8192) as content
           from server_ai.messages m
           join server_ai.conversations c on c.id=m.conversation_id
          where c.owner_id=$1 and c.machine_id=$2 and c.project_id is not distinct from $3 and c.deleted_at is null
            and m.role in ('user','assistant') and m.generation_status='completed'
            and m.content <> ''
            and not exists (
              select 1 from server_ai.retrieval_chunks r
               where r.scope_type='conversation' and r.message_id=m.id and r.project_id is not distinct from $3 and r.deleted_at is null
            )
          order by m.ordinal asc
          limit $4`,
        [owner, machine, project, limit],
      );
      return (result.rows || []).flatMap((row) => {
        try {
          return [{ ownerId: owner, machineId: machine, projectId: project, conversationId: normalizeConversationId(row.conversation_id), messageId: normalizeConversationId(row.message_id), content: boundedText(row.content, MAX_RETRIEVAL_MESSAGE_BYTES) }];
        } catch { return []; }
      });
    },
    async markConversationDeleted({ ownerId, machineId, projectId = null, conversationId } = {}) {
      const owner = normalizeOwnerId(ownerId);
      const machine = normalizeMachineId(machineId);
      const project = normalizeProjectId(projectId);
      const conversation = normalizeConversationId(conversationId);
      await pool.query(
        `update server_ai.retrieval_chunks r set deleted_at=now(), updated_at=now()
         where r.scope_type='conversation' and r.owner_id=$1 and r.machine_id=$2 and r.project_id is not distinct from $3 and r.conversation_id=$4 and r.deleted_at is null
           and exists (select 1 from server_ai.conversations c where c.id=$4 and c.owner_id=$1 and c.machine_id=$2 and c.project_id is not distinct from $3 and c.deleted_at is not null)`,
        [owner, machine, project, conversation],
      );
    },
  });
}
