begin;

create table if not exists control_auth.provider_event_tokens (
  issuer text not null,
  jti_hash text not null check (jti_hash ~ '^[0-9a-f]{64}$'),
  event_type text not null check (length(event_type) between 1 and 512),
  issued_at timestamptz not null,
  expires_at timestamptz not null,
  consumed_at timestamptz not null default now(),
  primary key (issuer, jti_hash),
  check (expires_at > issued_at)
);

create table if not exists control_auth.provider_revocations (
  issuer text not null,
  scope_type text not null check (scope_type in ('sid', 'subject')),
  scope_value text not null check (length(scope_value) between 1 and 1024),
  event_iat timestamptz not null,
  expires_at timestamptz not null,
  updated_at timestamptz not null default now(),
  primary key (issuer, scope_type, scope_value),
  check (expires_at > event_iat)
);

drop index if exists control_auth.sessions_subject_active_idx;

create index if not exists sessions_issuer_subject_active_idx
  on control_auth.sessions (issuer, subject, expires_at)
  where revoked_at is null;

create index if not exists sessions_issuer_sid_active_idx
  on control_auth.sessions (issuer, oidc_session_id, expires_at)
  where revoked_at is null and oidc_session_id <> '';

create index if not exists provider_event_tokens_expiry_idx
  on control_auth.provider_event_tokens (expires_at);

create index if not exists provider_revocations_expiry_idx
  on control_auth.provider_revocations (expires_at);

comment on table control_auth.provider_event_tokens is
  'Replay-protection receipts for validated OIDC logout and provider security event tokens.';

comment on table control_auth.provider_revocations is
  'Issuer-scoped sid and subject revocation watermarks checked during session creation.';

commit;
