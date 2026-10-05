begin;
create table if not exists server_ai.attachments (
 id uuid primary key,
 conversation_id uuid not null references server_ai.conversations(id),
 message_id uuid references server_ai.messages(id),
 filename text not null check(length(filename) between 1 and 180 and position('/' in filename)=0 and position(chr(92) in filename)=0 and filename !~ '[[:cntrl:]]'),
 kind text not null check(kind in ('text','image')),
 media_type text not null check(media_type ~ '^[A-Za-z]+/[A-Za-z0-9.+-]+$' and length(media_type)<=128),
 size integer not null check(size>=0 and size<=8388608),
 text_content text,
 image_data bytea,
 sha256 text not null check(sha256 ~ '^[a-f0-9]{64}$'),
 width integer check(width between 1 and 1600),
 height integer check(height between 1 and 1600),
 truncated boolean not null default false,
 created_at timestamptz not null default now(),
 deleted_at timestamptz,
 check ((deleted_at is not null and text_content is null and image_data is null and size=0)
     or (deleted_at is null and kind='text' and text_content is not null and image_data is null and width is null and height is null and octet_length(text_content)=size)
     or (deleted_at is null and kind='image' and text_content is null and image_data is not null and width is not null and height is not null and octet_length(image_data)=size))
);
create index if not exists attachments_conversation_pending_idx on server_ai.attachments(conversation_id, created_at, id) where deleted_at is null and message_id is null;
create index if not exists attachments_message_visible_idx on server_ai.attachments(conversation_id, message_id, created_at, id) where deleted_at is null and message_id is not null;
grant select, insert, update on table server_ai.attachments to control_center_runtime;
commit;
