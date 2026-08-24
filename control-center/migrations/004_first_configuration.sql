begin;

create table if not exists control_auth.first_configuration (
  singleton boolean primary key default true check (singleton),
  state text not null check (state in (
    'FIRST_CONFIGURATION_REQUIRED',
    'ADMIN_CONFIRMED',
    'PASSKEY_ENROLLMENT_REQUIRED',
    'PASSKEYS_READY',
    'PASSKEY_LOGIN_REQUIRED',
    'PASSKEY_LOGOUT_VERIFICATION_REQUIRED',
    'PASSKEY_RELOGIN_REQUIRED',
    'FIRST_CONFIGURATION_FINALIZING',
    'FIRST_CONFIGURATION_COMPLETE'
  )),
  bootstrap_token_hash text not null check (bootstrap_token_hash ~ '^[0-9a-f]{64}$'),
  bootstrap_token_expires_at timestamptz not null,
  bootstrap_token_consumed_at timestamptz,
  admin_subject text not null default '',
  admin_username text not null default '',
  admin_email text not null default '',
  passkey_count integer not null default 0 check (passkey_count >= 0),
  passkey_independence_confirmed_at timestamptz,
  cutover_at timestamptz,
  passkey_login_verified_at timestamptz,
  logout_verified_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (bootstrap_token_expires_at > created_at)
);

create table if not exists control_auth.first_configuration_sessions (
  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),
  csrf_hash text not null check (csrf_hash ~ '^[0-9a-f]{64}$'),
  peer_hash text not null check (peer_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check (expires_at > created_at)
);

create index if not exists first_configuration_sessions_expiry_idx
  on control_auth.first_configuration_sessions (expires_at);

comment on table control_auth.first_configuration is
  'Persistent fail-closed state for the LOCAL_PRIVATE guided passkey onboarding transaction.';
comment on column control_auth.first_configuration.bootstrap_token_hash is
  'SHA-256 of the temporary out-of-band bootstrap token; raw bootstrap material is never persisted and all setup sessions are revoked at completion.';
comment on table control_auth.first_configuration_sessions is
  'Short-lived, peer-bound sessions restricted to first-configuration routes.';

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'control_center_runtime') then
    raise exception 'Required runtime role control_center_runtime does not exist';
  end if;
end
$$;

grant usage on schema control_auth to control_center_runtime;
grant select, insert, update, delete on table
  control_auth.oidc_transactions,
  control_auth.sessions,
  control_auth.login_throttle,
  control_auth.provider_event_tokens,
  control_auth.provider_revocations,
  control_auth.first_configuration,
  control_auth.first_configuration_sessions
to control_center_runtime;

commit;
