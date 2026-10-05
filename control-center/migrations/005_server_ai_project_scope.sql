begin;

-- Project Intelligence is opt-in. Existing general-server conversations and
-- retrieval rows stay in the explicit NULL project scope.
alter table server_ai.conversations
  add column if not exists project_id text check (project_id is null or project_id ~ '^[a-z0-9][a-z0-9-]{0,63}$');

alter table server_ai.retrieval_chunks
  add column if not exists project_id text check (project_id is null or project_id ~ '^[a-z0-9][a-z0-9-]{0,63}$');

create index if not exists conversations_owner_machine_project_updated_idx
  on server_ai.conversations (owner_id, machine_id, project_id, updated_at desc, id desc)
  where deleted_at is null;

create index if not exists retrieval_chunks_owner_machine_project_scope_idx
  on server_ai.retrieval_chunks (owner_id, machine_id, project_id, scope_type, conversation_id)
  where deleted_at is null;

grant select, insert, update on table server_ai.conversations, server_ai.retrieval_chunks to control_center_runtime;

commit;
