begin;

-- A document keeps its original bytes in the private attachment object store;
-- this column contains only bounded, redacted extraction coverage metadata.
alter table server_ai.attachments
  add column if not exists document_metadata jsonb;

alter table server_ai.attachments
  drop constraint if exists attachments_kind_check,
  drop constraint if exists attachments_check;

alter table server_ai.attachments
  add constraint attachments_kind_check check (kind in ('text','image','archive','document')),
  add constraint attachments_check
    check (
      (deleted_at is not null and text_content is null and image_data is null and archive_metadata is null
        and document_metadata is null and size = 0)
      or (deleted_at is null and kind='text' and image_data is null and text_content is not null
        and width is null and height is null and object_key is null and archive_metadata is null and document_metadata is null
        and octet_length(text_content)=size)
      or (deleted_at is null and kind='text' and image_data is null and text_content is not null
        and width is null and height is null and object_key is not null and archive_metadata is null and document_metadata is null
        and octet_length(text_content) <= 384 and octet_length(text_content) <= size)
      or (deleted_at is null and kind='image' and text_content is null and image_data is not null
        and object_key is null and archive_metadata is null and document_metadata is null
        and width is not null and height is not null and octet_length(image_data)=size)
      or (deleted_at is null and kind='archive' and media_type='application/zip'
        and text_content is null and image_data is null and width is null and height is null
        and object_key is not null and archive_metadata is not null and document_metadata is null
        and coalesce(jsonb_typeof(archive_metadata)='object', false)
        and archive_metadata ? 'entryCount' and archive_metadata ? 'totalUncompressedBytes'
        and coalesce(jsonb_typeof(archive_metadata->'entryCount')='number', false)
        and coalesce(jsonb_typeof(archive_metadata->'totalUncompressedBytes')='number', false)
        and archive_metadata->>'entryCount' ~ '^[0-9]+$'
        and archive_metadata->>'totalUncompressedBytes' ~ '^[0-9]+$'
        and (archive_metadata->>'entryCount')::bigint between 1 and 2048
        and (archive_metadata->>'totalUncompressedBytes')::bigint between 1 and 1073741824)
      or (deleted_at is null and kind='document'
        and media_type in ('application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.ms-word.document.macroenabled.12',
          'application/vnd.openxmlformats-officedocument.wordprocessingml.template','application/vnd.ms-word.template.macroenabled.12',
          'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-excel.sheet.macroenabled.12',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.template','application/vnd.ms-excel.template.macroenabled.12',
          'application/vnd.openxmlformats-officedocument.presentationml.presentation','application/vnd.ms-powerpoint.presentation.macroenabled.12',
          'application/vnd.openxmlformats-officedocument.presentationml.template','application/vnd.ms-powerpoint.template.macroenabled.12',
          'application/vnd.openxmlformats-officedocument.presentationml.slideshow','application/vnd.ms-powerpoint.slideshow.macroenabled.12',
          'application/vnd.oasis.opendocument.text','application/vnd.oasis.opendocument.text-template',
          'application/vnd.oasis.opendocument.spreadsheet','application/vnd.oasis.opendocument.spreadsheet-template',
          'application/vnd.oasis.opendocument.presentation','application/vnd.oasis.opendocument.presentation-template',
          'application/rtf','application/epub+zip')
        and (text_content is null or octet_length(text_content) <= 384)
        and image_data is null and width is null and height is null and object_key is not null
        and archive_metadata is null and document_metadata is not null
        and octet_length(document_metadata::text) <= 8192
        and coalesce(jsonb_typeof(document_metadata)='object', false)
        and document_metadata ? 'format' and coalesce(jsonb_typeof(document_metadata->'format')='string', false)
        and octet_length(document_metadata->>'format') between 1 and 24
        and document_metadata ? 'extractedBytes' and document_metadata ? 'sourceBytes'
        and document_metadata ? 'coverage'
        and coalesce(jsonb_typeof(document_metadata->'extractedBytes')='number', false)
        and coalesce(jsonb_typeof(document_metadata->'sourceBytes')='number', false)
        and (document_metadata->>'extractedBytes') ~ '^[0-9]+$'
        and (document_metadata->>'sourceBytes') ~ '^[0-9]+$'
        and (document_metadata->>'extractedBytes')::bigint between 0 and 16777216
        and (document_metadata->>'sourceBytes')::bigint = size
        and coalesce(jsonb_typeof(document_metadata->'coverage')='object', false)
        and document_metadata->'coverage' ? 'state'
        and document_metadata->'coverage'->>'state' in ('complete','partial','image_only','unsupported')
        and coalesce(jsonb_typeof(document_metadata->'coverage'->'warnings')='array', false)
        and jsonb_array_length(document_metadata->'coverage'->'warnings') between 0 and 16
        and not jsonb_path_exists(document_metadata,
          '$.coverage.warnings[*] ? (@.type() != "string" || @ like_regex "^.{255}.{255}.{3}.*$" flag "s")')
        and coalesce(jsonb_typeof(document_metadata->'coverage'->'unitsRead')='number', false)
        and coalesce(jsonb_typeof(document_metadata->'coverage'->'unitsSkipped')='number', false)
        and (document_metadata->'coverage'->>'unitsRead') ~ '^[0-9]+$'
        and (document_metadata->'coverage'->>'unitsSkipped') ~ '^[0-9]+$'
        and (document_metadata->'coverage'->>'unitsRead')::bigint between 0 and 2147483647
        and (document_metadata->'coverage'->>'unitsSkipped')::bigint between 0 and 2147483647)
    );

alter table server_ai.attachment_scans
  add column if not exists coverage_metadata jsonb not null default '{}'::jsonb;

alter table server_ai.attachment_scans
  drop constraint if exists attachment_scans_kind_check,
  drop constraint if exists attachment_scans_coverage_metadata_check,
  drop constraint if exists attachment_scans_completed_check;

-- The original completion CHECK was unnamed in 010.  Remove only that exact
-- predicate on this table so a future migration can add the document branch.
do $$
declare
  constraint_name text;
begin
  for constraint_name in
    select conname from pg_constraint
    where conrelid = 'server_ai.attachment_scans'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) like '%status <> ''completed''%'
  loop
    execute format('alter table server_ai.attachment_scans drop constraint %I', constraint_name);
  end loop;
end
$$;

alter table server_ai.attachment_scans
  add constraint attachment_scans_kind_check check (kind in ('text','archive','document')),
  add constraint attachment_scans_coverage_metadata_check check (coverage_metadata is not null and jsonb_typeof(coverage_metadata) = 'object' and octet_length(coverage_metadata::text) <= 131072),
  add constraint attachment_scans_completed_check check (
    status <> 'completed'
    or (kind = 'text' and next_byte = total_bytes and processed_bytes = total_bytes)
    or (kind = 'archive' and processed_entries = entry_count)
    or (kind = 'document' and next_byte = total_bytes and processed_bytes = total_bytes)
  );

grant select, insert, update on table server_ai.attachments, server_ai.attachment_scans to control_center_runtime;
commit;
