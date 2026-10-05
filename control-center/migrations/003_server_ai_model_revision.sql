begin;

-- New generations use the reviewed Qwen release. Existing Gemma rows remain
-- readable and are intentionally retained in the check constraint.
alter table server_ai.messages
  drop constraint if exists messages_model_check;

alter table server_ai.messages
  add constraint messages_model_check
  check (model is null or model in ('gemma4:26b', 'qwen3.6:35b-a3b-q4_K_M'));

comment on column server_ai.messages.model is
  'Generation model; new turns use qwen3.6:35b-a3b-q4_K_M and legacy Gemma rows remain readable.';

commit;
