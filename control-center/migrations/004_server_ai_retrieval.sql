begin;

-- pgvector is intentionally not a prerequisite. Embeddings are exact 1024D
-- real arrays; retrieval scans are bounded in application code and always
-- tenant-scoped before cosine scoring.
create table if not exists server_ai.retrieval_chunks (
  id uuid primary key,
  scope_type text not null check (scope_type in ('conversation', 'runbook')),
  owner_id text check (owner_id is null or length(owner_id) between 1 and 256),
  machine_id text not null check (machine_id ~ '^[a-f0-9]{64}$'),
  conversation_id uuid references server_ai.conversations(id) on delete cascade,
  message_id uuid references server_ai.messages(id) on delete cascade,
  runbook_key text check (runbook_key is null or length(runbook_key) between 1 and 160),
  curated boolean not null default false,
  chunk_index smallint not null check (chunk_index between 0 and 15),
  content text not null check (octet_length(content) between 1 and 2048),
  embedding real[] not null check (cardinality(embedding) = 1024),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  check (
    (scope_type = 'conversation' and owner_id is not null and conversation_id is not null and message_id is not null and runbook_key is null and curated = false)
    or (scope_type = 'runbook' and owner_id is null and conversation_id is null and message_id is null and runbook_key is not null and curated = true)
  )
);

create unique index if not exists retrieval_chunks_message_chunk_idx
  on server_ai.retrieval_chunks (message_id, chunk_index)
  where scope_type = 'conversation';
create unique index if not exists retrieval_chunks_runbook_chunk_idx
  on server_ai.retrieval_chunks (machine_id, runbook_key, chunk_index)
  where scope_type = 'runbook';
create index if not exists retrieval_chunks_conversation_scope_idx
  on server_ai.retrieval_chunks (owner_id, machine_id, created_at desc)
  where scope_type = 'conversation' and deleted_at is null;
create index if not exists retrieval_chunks_runbook_scope_idx
  on server_ai.retrieval_chunks (machine_id, runbook_key, created_at desc)
  where scope_type = 'runbook' and curated = true and deleted_at is null;

comment on table server_ai.retrieval_chunks is
  'Bounded, redacted, scope-filtered chunks for private conversation memory and operator-curated runbooks. No raw pages, tool results, or embeddings leave PostgreSQL.';

-- The runtime role receives DML only; migration ownership remains with the
-- operator. No public or cross-owner read path exists.
grant select, insert, update on table server_ai.retrieval_chunks to control_center_runtime;

commit;
