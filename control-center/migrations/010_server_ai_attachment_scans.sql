begin;

create table if not exists server_ai.attachment_scans (
  id uuid primary key,
  owner_id text not null check (length(owner_id) between 1 and 256),
  machine_id text not null check (machine_id ~ '^[a-f0-9]{64}$'),
  conversation_id uuid not null,
  attachment_id uuid not null,
  attachment_sha256 text not null check (attachment_sha256 ~ '^[a-f0-9]{64}$'),
  kind text not null default 'text' check (kind in ('text','archive')),
  total_bytes bigint not null check (total_bytes between 1 and 1073741824),
  entry_count integer not null default 0 check (entry_count between 0 and 2048),
  processed_entries integer not null default 0 check (processed_entries between 0 and entry_count),
  analyzed_entries integer not null default 0 check (analyzed_entries between 0 and entry_count),
  unsupported_entries integer not null default 0 check (unsupported_entries between 0 and entry_count),
  next_cursor text check (next_cursor is null or octet_length(next_cursor) <= 1024),
  active_entry_id text not null default '' check (active_entry_id = '' or active_entry_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  materialized_object_key uuid,
  materialized_next_byte bigint not null default 0 check (materialized_next_byte >= 0 and materialized_next_byte <= 536870912),
  status text not null default 'queued' check (status in ('queued','running','paused','completed','aborted','failed')),
  next_byte bigint not null default 0 check (next_byte between 0 and total_bytes),
  processed_bytes bigint not null default 0 check (processed_bytes between 0 and total_bytes),
  unique_bytes bigint not null default 0 check (unique_bytes between 0 and total_bytes),
  deduplicated_bytes bigint not null default 0 check (deduplicated_bytes between 0 and total_bytes),
  leaf_count integer not null default 0 check (leaf_count >= 0),
  unique_leaf_count integer not null default 0 check (unique_leaf_count >= 0),
  summary text not null default '' check (octet_length(summary) <= 8192),
  error_code text check (error_code is null or error_code ~ '^[A-Z0-9_]{1,64}$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  unique (conversation_id, attachment_id, attachment_sha256),
  foreign key (conversation_id, owner_id, machine_id)
    references server_ai.conversations (id, owner_id, machine_id),
  foreign key (attachment_id, conversation_id)
    references server_ai.attachments (id, conversation_id),
  check (processed_bytes = unique_bytes + deduplicated_bytes),
  check ((status <> 'completed') or (kind = 'text' and next_byte = total_bytes and processed_bytes = total_bytes) or (kind = 'archive' and processed_entries = entry_count))
);

create table if not exists server_ai.attachment_scan_segments (
  id uuid primary key,
  scan_id uuid not null references server_ai.attachment_scans(id) on delete cascade,
  entry_id text not null default '' check (entry_id = '' or entry_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  start_byte bigint not null check (start_byte >= 0),
  end_byte bigint not null check (end_byte > start_byte),
  content_sha256 text not null check (content_sha256 ~ '^[a-f0-9]{64}$'),
  canonical_segment_id uuid references server_ai.attachment_scan_segments(id),
  summary text check (summary is null or octet_length(summary) <= 768),
  unit_count integer not null default 1 check (unit_count >= 1),
  status text not null check (status in ('analyzed','duplicate','unsupported','empty')),
  created_at timestamptz not null default now(),
  unique (scan_id, entry_id, start_byte),
  check ((status = 'analyzed' and canonical_segment_id is null and summary is not null)
      or (status = 'duplicate' and canonical_segment_id is not null and summary is null)
      or (status = 'unsupported' and canonical_segment_id is null and summary is not null)
      or (status = 'empty' and canonical_segment_id is null and summary is null))
);

create index if not exists attachment_scans_scope_status_idx
  on server_ai.attachment_scans (owner_id, machine_id, status, updated_at desc);
create index if not exists attachment_scans_attachment_idx
  on server_ai.attachment_scans (conversation_id, attachment_id, updated_at desc);
create index if not exists attachment_scan_segments_lookup_idx
  on server_ai.attachment_scan_segments (scan_id, content_sha256, status, created_at asc);
create index if not exists attachment_scan_segments_range_idx
  on server_ai.attachment_scan_segments (scan_id, start_byte);

grant select, insert, update on table server_ai.attachment_scans, server_ai.attachment_scan_segments to control_center_runtime;

commit;
