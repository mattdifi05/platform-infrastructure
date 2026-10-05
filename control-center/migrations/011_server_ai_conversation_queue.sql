begin;

create table if not exists server_ai.conversation_queue (
  id uuid primary key,
  owner_id text not null check (length(owner_id) between 1 and 256),
  machine_id text not null check (machine_id ~ '^[a-f0-9]{64}$'),
  conversation_id uuid not null,
  request_id uuid not null,
  ordinal bigint not null check (ordinal > 0),
  message text not null check (octet_length(message) between 1 and 16384),
  requested_mode text not null check (requested_mode in ('auto','fast','deep')),
  attachment_ids uuid[] not null default '{}'::uuid[] check (cardinality(attachment_ids) <= 5),
  delivery text not null check (delivery in ('queue','immediate')),
  priority smallint not null default 0 check (priority in (0,1)),
  status text not null default 'queued' check (status in ('queued','running','cancelled','completed','failed')),
  turn_id uuid,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  cancelled_at timestamptz,
  error_code text check (error_code is null or error_code ~ '^[A-Z0-9_]{1,64}$'),
  unique (conversation_id, request_id),
  unique (conversation_id, ordinal),
  foreign key (conversation_id, owner_id, machine_id)
    references server_ai.conversations (id, owner_id, machine_id)
);

create index if not exists conversation_queue_scope_idx
  on server_ai.conversation_queue (owner_id, machine_id, conversation_id, status, priority desc, ordinal);
create index if not exists conversation_queue_machine_status_idx
  on server_ai.conversation_queue (machine_id, status, created_at);

grant select, insert, update on table server_ai.conversation_queue to control_center_runtime;

commit;
