begin;

alter table server_ai.messages
  drop constraint if exists messages_model_check;

alter table server_ai.messages
  add constraint messages_model_check
  check (model is null or model in ('gemma4:26b', 'qwen3.6:35b-a3b-q4_K_M', 'gpt-6-luna'));

comment on column server_ai.messages.model is
  'Generation model; new turns use gpt-6-luna and legacy Gemma/Qwen rows remain readable.';

commit;
