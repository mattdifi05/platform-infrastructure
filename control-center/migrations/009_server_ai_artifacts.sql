begin;

-- Archive uploads share the existing attachment object store.  The archive
-- manifest remains on disk; these bounded counters keep the SQL row useful to
-- the context and scan adapters without copying ZIP bytes into PostgreSQL.
alter table server_ai.attachments
  add column if not exists archive_metadata jsonb;

alter table server_ai.attachments
  drop constraint if exists attachments_check;

alter table server_ai.attachments
  add constraint attachments_check
    check (
      (deleted_at is not null and text_content is null and image_data is null and size = 0)
      or (deleted_at is null and kind='text' and image_data is null and text_content is not null
          and width is null and height is null and object_key is null and archive_metadata is null
          and octet_length(text_content)=size)
      or (deleted_at is null and kind='text' and image_data is null and text_content is not null
          and width is null and height is null and object_key is not null and archive_metadata is null
          and octet_length(text_content) <= 384 and octet_length(text_content) <= size)
      or (deleted_at is null and kind='image' and text_content is null and image_data is not null
          and object_key is null and archive_metadata is null and width is not null and height is not null
          and octet_length(image_data)=size)
      or (deleted_at is null and kind='archive' and media_type='application/zip'
          and text_content is null and image_data is null and width is null and height is null
          and object_key is not null and archive_metadata is not null and coalesce(jsonb_typeof(archive_metadata)='object', false)
          and archive_metadata ? 'entryCount' and archive_metadata ? 'totalUncompressedBytes'
          and coalesce(jsonb_typeof(archive_metadata->'entryCount')='number', false)
          and coalesce(jsonb_typeof(archive_metadata->'totalUncompressedBytes')='number', false)
          and archive_metadata->>'entryCount' ~ '^[0-9]+$'
          and archive_metadata->>'totalUncompressedBytes' ~ '^[0-9]+$'
          and (archive_metadata->>'entryCount')::bigint between 1 and 2048
          and (archive_metadata->>'totalUncompressedBytes')::bigint between 1 and 1073741824)
    );

alter table server_ai.attachments
  drop constraint if exists attachments_kind_check;

alter table server_ai.attachments
  add constraint attachments_kind_check check (kind in ('text','image','archive'));

-- Scope columns are repeated on generated rows for fast, explicit predicates.
-- These composite keys make that denormalized scope attestable by PostgreSQL;
-- the ordinary primary keys and foreign keys remain for compatibility.
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'conversations_id_owner_machine_key'
    and conrelid = 'server_ai.conversations'::regclass) then
    alter table server_ai.conversations add constraint conversations_id_owner_machine_key unique (id, owner_id, machine_id);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'messages_id_conversation_key'
    and conrelid = 'server_ai.messages'::regclass) then
    alter table server_ai.messages add constraint messages_id_conversation_key unique (id, conversation_id);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'attachments_id_conversation_key'
    and conrelid = 'server_ai.attachments'::regclass) then
    alter table server_ai.attachments add constraint attachments_id_conversation_key unique (id, conversation_id);
  end if;
end
$$;

-- Generated files are separate from user uploads.  They are always addressed
-- by an opaque UUID and remain private to the owning conversation.
create table if not exists server_ai.artifacts (
  id uuid primary key,
  conversation_id uuid not null references server_ai.conversations(id),
  message_id uuid references server_ai.messages(id),
  owner_id text not null check (length(owner_id) between 1 and 256),
  machine_id text not null check (machine_id ~ '^[0-9a-f]{64}$'),
  name text not null check (length(name) between 1 and 180 and position('/' in name)=0 and position(chr(92) in name)=0 and name !~ '[[:cntrl:]]'),
  kind text not null check (kind in ('file', 'archive')),
  media_type text not null check (media_type ~ '^[A-Za-z]+/[A-Za-z0-9.+-]+$' and length(media_type)<=128),
  byte_size integer not null check (byte_size between 0 and 536870912),
  sha256 text not null check (sha256 ~ '^[a-f0-9]{64}$'),
  object_key uuid unique,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  check ((kind = 'archive' and media_type = 'application/zip') or kind = 'file'),
  check (kind = 'file' or (
    metadata is not null and metadata ? 'entryCount' and metadata ? 'totalUncompressedBytes'
    and coalesce(jsonb_typeof(metadata->'entryCount')='number', false)
    and coalesce(jsonb_typeof(metadata->'totalUncompressedBytes')='number', false)
    and metadata->>'entryCount' ~ '^[0-9]+$'
    and metadata->>'totalUncompressedBytes' ~ '^[0-9]+$'
    and (metadata->>'entryCount')::bigint between 1 and 2048
    and (metadata->>'totalUncompressedBytes')::bigint between 1 and 1073741824
  )),
  check ((deleted_at is null and byte_size > 0 and object_key is not null) or (deleted_at is not null and byte_size = 0))
);

create index if not exists artifacts_conversation_created_idx
  on server_ai.artifacts(conversation_id, created_at, id)
  where deleted_at is null;
create index if not exists artifacts_message_visible_idx
  on server_ai.artifacts(conversation_id, message_id, created_at, id)
  where deleted_at is null and message_id is not null;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'artifacts_conversation_scope_fkey'
    and conrelid = 'server_ai.artifacts'::regclass) then
    alter table server_ai.artifacts add constraint artifacts_conversation_scope_fkey
      foreign key (conversation_id, owner_id, machine_id)
      references server_ai.conversations (id, owner_id, machine_id);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'artifacts_message_scope_fkey'
    and conrelid = 'server_ai.artifacts'::regclass) then
    alter table server_ai.artifacts add constraint artifacts_message_scope_fkey
      foreign key (message_id, conversation_id)
      references server_ai.messages (id, conversation_id);
  end if;
end
$$;

grant select, insert, update on table server_ai.artifacts to control_center_runtime;

commit;
