begin;

alter table server_ai.attachments
  add column if not exists object_key uuid unique;

alter table server_ai.attachments
  drop constraint if exists attachments_size_check,
  drop constraint if exists attachments_check;

alter table server_ai.attachments
  add constraint attachments_size_check
    check(size >= 0 and size <= 536870912),
  add constraint attachments_check
    check (
      (deleted_at is not null and text_content is null and image_data is null and size = 0)
      or (deleted_at is null and kind = 'text' and image_data is null and text_content is not null
          and width is null and height is null and object_key is null and octet_length(text_content) = size)
      or (deleted_at is null and kind = 'text' and image_data is null and text_content is not null
          and width is null and height is null and object_key is not null
          and octet_length(text_content) <= 384 and octet_length(text_content) <= size)
      or (deleted_at is null and kind = 'image' and text_content is null and image_data is not null
          and object_key is null and width is not null and height is not null and octet_length(image_data) = size)
    );

create index if not exists attachments_object_cleanup_idx
  on server_ai.attachments (object_key)
  where deleted_at is not null and object_key is not null;

grant select, insert, update on table server_ai.attachments to control_center_runtime;

commit;
