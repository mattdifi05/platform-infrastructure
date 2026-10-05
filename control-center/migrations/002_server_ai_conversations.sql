begin;

-- Additive, application-owned conversation storage.  This migration is run by
-- the operator as the database owner; the Control Center runtime receives DML
-- only and never receives schema-creation privileges.
create schema if not exists server_ai;

create table if not exists server_ai.conversations (
  id uuid primary key,
  owner_id text not null check (length(owner_id) between 1 and 256),
  machine_id text not null check (machine_id ~ '^[0-9a-f]{64}$'),
  title text not null check (length(title) between 1 and 200),
  summary text not null default '' check (length(summary) <= 16384),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  deleted_at timestamptz
);

create index if not exists conversations_owner_machine_updated_idx
  on server_ai.conversations (owner_id, machine_id, updated_at desc)
  where deleted_at is null;

create table if not exists server_ai.messages (
  id uuid primary key,
  conversation_id uuid not null references server_ai.conversations(id) on delete cascade,
  turn_id uuid,
  ordinal bigint generated always as identity,
  role text not null check (role in ('user', 'assistant')),
  content text not null check (length(content) <= 120000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  requested_mode text check (requested_mode is null or requested_mode in ('auto', 'fast', 'deep')),
  resolved_mode text check (resolved_mode is null or resolved_mode in ('fast', 'deep')),
  model text check (model is null or model = 'gemma4:26b'),
  generation_status text not null check (generation_status in ('pending', 'streaming', 'completed', 'aborted', 'failed')),
  source_metadata jsonb not null default '[]'::jsonb,
  tool_metadata jsonb not null default '{}'::jsonb
);

create index if not exists messages_conversation_created_idx
  on server_ai.messages (conversation_id, created_at, id);

create unique index if not exists messages_conversation_ordinal_idx
  on server_ai.messages (conversation_id, ordinal);

create unique index if not exists messages_one_active_turn_idx
  on server_ai.messages (conversation_id)
  where role = 'assistant' and generation_status in ('pending', 'streaming');

comment on schema server_ai is
  'Server AI conversation history and bounded generation metadata.';
comment on table server_ai.conversations is
  'Machine-scoped conversations owned by the authenticated Control Center subject.';
comment on table server_ai.messages is
  'Final user/assistant messages; private reasoning and raw tool/page payloads are never stored.';
comment on column server_ai.conversations.summary is
  'Deterministic bounded context summary; visible history remains in messages.';
comment on column server_ai.messages.source_metadata is
  'Bounded source descriptors only, never fetched page bodies or credentials.';
comment on column server_ai.messages.tool_metadata is
  'Bounded safe tool outcome metadata only, never raw tool payloads or secrets.';

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'control_center_runtime') then
    raise exception 'Required runtime role control_center_runtime does not exist';
  end if;
end
$$;

grant usage on schema server_ai to control_center_runtime;
grant usage, select on sequence server_ai.messages_ordinal_seq to control_center_runtime;
grant select, insert, update on table
  server_ai.conversations,
  server_ai.messages
to control_center_runtime;

commit;
