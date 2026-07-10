begin;

alter table control_auth.oidc_transactions
  add column if not exists throttle_key_hash text
  check (throttle_key_hash is null or throttle_key_hash ~ '^[0-9a-f]{64}$');

alter table control_auth.sessions
  add column if not exists csrf_hash text not null default repeat('0', 64)
  check (csrf_hash ~ '^[0-9a-f]{64}$');

alter table control_auth.sessions
  add column if not exists policy_version text not null default '1';

create table if not exists control_auth.login_throttle (
  key_hash text primary key check (key_hash ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz not null,
  attempts integer not null check (attempts >= 0),
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);

create index if not exists login_throttle_cleanup_idx
  on control_auth.login_throttle (updated_at);

comment on table control_auth.login_throttle is
  'Shared bounded login-start throttle. Keys are hashes of the immediate network peer.';

commit;
