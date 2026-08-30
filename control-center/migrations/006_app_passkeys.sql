begin;

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

comment on table control_auth.passkeys is
  'Application-owned WebAuthn credentials for the Control Center. Public keys are persisted as BYTEA; credentials expire according to the configured retention window.';
comment on table control_auth.webauthn_challenges is
  'One-use, peer-bound WebAuthn challenges. The challenge value is protocol material and is removed on successful consumption or expiry.';

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'control_center_runtime') then
    raise exception 'Required runtime role control_center_runtime does not exist';
  end if;
end
$$;

grant usage on schema control_auth to control_center_runtime;
grant select, insert, update, delete on table
  control_auth.passkeys,
  control_auth.webauthn_challenges
to control_center_runtime;

commit;
