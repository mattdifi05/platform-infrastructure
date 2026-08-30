begin;

create schema if not exists control_auth;

create table if not exists control_auth.sessions (
  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),
  csrf_hash text not null check (csrf_hash ~ '^[0-9a-f]{64}$'),
  policy_version text not null default '1',
  subject text not null,
  email text not null default '',
  display_name text not null default '',
  role text not null check (role in ('viewer', 'admin', 'owner')),
  roles text[] not null default '{}',
  acr text not null default 'app-passkey',
  amr text[] not null default '{webauthn}',
  auth_time timestamptz not null,
  issuer text not null,
  oidc_session_id text not null default '',
  signing_key_id text not null default '',
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check (expires_at > created_at)
);

alter table control_auth.sessions
  add column if not exists csrf_hash text not null default repeat('0', 64)
  check (csrf_hash ~ '^[0-9a-f]{64}$');

alter table control_auth.sessions
  add column if not exists policy_version text not null default '1';

create index if not exists sessions_subject_active_idx
  on control_auth.sessions (subject, expires_at)
  where revoked_at is null;

create index if not exists sessions_expiry_idx
  on control_auth.sessions (expires_at);

create table if not exists control_auth.login_throttle (
  key_hash text primary key check (key_hash ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz not null,
  attempts integer not null check (attempts >= 0),
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);

create index if not exists login_throttle_cleanup_idx
  on control_auth.login_throttle (updated_at);

create table if not exists control_auth.passkeys (
  credential_id text primary key check (credential_id ~ '^[A-Za-z0-9_-]+$' and length(credential_id) between 1 and 1024),
  user_id text not null check (length(user_id) between 1 and 256),
  webauthn_user_id text not null check (length(webauthn_user_id) between 1 and 256),
  public_key bytea not null check (octet_length(public_key) > 0),
  counter bigint not null default 0 check (counter >= 0),
  transports text[] not null default '{}',
  device_type text not null default 'singleDevice' check (device_type in ('singleDevice', 'multiDevice')),
  backed_up boolean not null default false,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_used_at timestamptz,
  updated_at timestamptz not null default now(),
  check (expires_at > created_at)
);

create index if not exists passkeys_user_expiry_idx
  on control_auth.passkeys (user_id, expires_at);

create unique index if not exists passkeys_one_per_user_idx
  on control_auth.passkeys (user_id);

create table if not exists control_auth.webauthn_challenges (
  challenge_hash text primary key check (challenge_hash ~ '^[0-9a-f]{64}$'),
  challenge text not null check (challenge ~ '^[A-Za-z0-9_-]+$' and length(challenge) between 16 and 256),
  flow text not null check (flow in ('registration', 'authentication')),
  user_id text not null check (length(user_id) between 1 and 256),
  peer_hash text not null check (peer_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  check (expires_at > created_at and expires_at <= created_at + interval '1 day')
);

create index if not exists webauthn_challenges_expiry_idx
  on control_auth.webauthn_challenges (expires_at);

comment on schema control_auth is
  'Application-owned Control Center passkeys, sessions, challenges, and login throttles.';
comment on column control_auth.sessions.token_hash is
  'SHA-256 of the opaque browser token; the raw token is never persisted.';
comment on column control_auth.sessions.oidc_session_id is
  'Reserved empty compatibility column for databases created before application-owned passkeys.';
comment on column control_auth.sessions.signing_key_id is
  'Reserved empty compatibility column for databases created before application-owned passkeys.';
comment on table control_auth.passkeys is
  'Application-owned WebAuthn public credentials for the Control Center.';
comment on table control_auth.webauthn_challenges is
  'One-use, peer-bound WebAuthn challenges removed after consumption or expiry.';

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'control_center_runtime') then
    raise exception 'Required runtime role control_center_runtime does not exist';
  end if;
end
$$;

grant usage on schema control_auth to control_center_runtime;
grant select, insert, update, delete on table
  control_auth.sessions,
  control_auth.login_throttle,
  control_auth.passkeys,
  control_auth.webauthn_challenges
to control_center_runtime;

commit;
