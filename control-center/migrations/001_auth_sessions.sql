begin;

create schema if not exists control_auth;

create table if not exists control_auth.oidc_transactions (
  state_hash text primary key check (state_hash ~ '^[0-9a-f]{64}$'),
  nonce_hash text not null check (nonce_hash ~ '^[0-9a-f]{64}$'),
  code_verifier text not null check (length(code_verifier) between 43 and 128),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  check (expires_at > created_at)
);

create index if not exists oidc_transactions_expires_at_idx
  on control_auth.oidc_transactions (expires_at);

create table if not exists control_auth.sessions (
  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),
  subject text not null,
  email text not null default '',
  display_name text not null default '',
  role text not null check (role in ('viewer', 'admin', 'owner')),
  roles text[] not null default '{}',
  acr text not null,
  amr text[] not null default '{}',
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

create index if not exists sessions_subject_active_idx
  on control_auth.sessions (subject, expires_at)
  where revoked_at is null;

create index if not exists sessions_expiry_idx
  on control_auth.sessions (expires_at);

comment on schema control_auth is
  'Control Center OIDC transactions and revocable administrative sessions.';
comment on column control_auth.sessions.token_hash is
  'SHA-256 of the opaque browser token; the raw token is never persisted.';
comment on column control_auth.oidc_transactions.code_verifier is
  'Short-lived PKCE verifier, atomically deleted when the callback consumes the state.';

commit;
