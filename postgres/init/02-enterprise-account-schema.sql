\connect stexor_app

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS stexor_account;

DO $$
BEGIN
  CREATE TYPE stexor_account.account_risk_level AS ENUM ('low', 'medium', 'high', 'locked');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE stexor_account.session_status AS ENUM ('active', 'revoked', 'expired');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE stexor_account.otp_purpose AS ENUM ('login', 'signup', 'recovery');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE stexor_account.challenge_status AS ENUM ('pending', 'verified', 'consumed', 'expired', 'failed');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE stexor_account.audit_severity AS ENUM ('info', 'success', 'warning', 'critical');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE stexor_account.device_approval_status AS ENUM ('pending', 'approved', 'denied', 'expired');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE stexor_account.subscription_status AS ENUM ('active', 'trial', 'paused', 'cancelled', 'expired');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE stexor_account.email_delivery_status AS ENUM ('queued', 'sending', 'sent', 'failed', 'cancelled');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE OR REPLACE FUNCTION stexor_account.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TABLE IF NOT EXISTS stexor_account.accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id text UNIQUE NOT NULL,
  username citext UNIQUE NOT NULL,
  first_name text NOT NULL CHECK (length(trim(first_name)) BETWEEN 1 AND 80),
  last_name text NOT NULL CHECK (length(trim(last_name)) BETWEEN 1 AND 80),
  email citext UNIQUE NOT NULL,
  date_of_birth date NOT NULL,
  language text NOT NULL DEFAULT 'it-IT',
  country char(2) NOT NULL,
  avatar_initials text NOT NULL,
  risk_level stexor_account.account_risk_level NOT NULL DEFAULT 'low',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK (country = upper(country))
);

CREATE TABLE IF NOT EXISTS stexor_account.account_security_settings (
  account_id uuid PRIMARY KEY REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  passwordless_required boolean NOT NULL DEFAULT true,
  email_otp_enabled boolean NOT NULL DEFAULT true,
  totp_enabled boolean NOT NULL DEFAULT false,
  device_approval_enabled boolean NOT NULL DEFAULT true,
  backup_codes_remaining integer NOT NULL DEFAULT 0 CHECK (backup_codes_remaining >= 0),
  failed_login_attempts integer NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
  locked_until timestamptz,
  last_security_review_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stexor_account.passkeys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  credential_id text UNIQUE NOT NULL,
  public_key bytea NOT NULL,
  counter bigint NOT NULL DEFAULT 0 CHECK (counter >= 0),
  label text NOT NULL,
  device_type text NOT NULL DEFAULT 'unknown',
  backed_up boolean NOT NULL DEFAULT false,
  transports text[] NOT NULL DEFAULT ARRAY[]::text[],
  aaguid uuid,
  attestation_format text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS stexor_account.totp_secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  label text NOT NULL DEFAULT 'Google Authenticator',
  secret_encrypted bytea NOT NULL,
  algorithm text NOT NULL DEFAULT 'SHA1',
  digits integer NOT NULL DEFAULT 6 CHECK (digits BETWEEN 6 AND 8),
  period_seconds integer NOT NULL DEFAULT 30 CHECK (period_seconds BETWEEN 15 AND 120),
  verified_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (account_id, label)
);

CREATE TABLE IF NOT EXISTS stexor_account.email_otp_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  purpose stexor_account.otp_purpose NOT NULL,
  destination citext NOT NULL,
  code_hash text NOT NULL,
  status stexor_account.challenge_status NOT NULL DEFAULT 'pending',
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  ip_address inet,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stexor_account.backup_code_sets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS stexor_account.backup_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  set_id uuid NOT NULL REFERENCES stexor_account.backup_code_sets(id) ON DELETE CASCADE,
  code_hash text UNIQUE NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stexor_account.sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  device text NOT NULL,
  device_type text NOT NULL DEFAULT 'unknown' CHECK (device_type IN ('bot', 'desktop', 'mobile', 'tablet', 'unknown')),
  device_vendor text NOT NULL DEFAULT '',
  device_model text NOT NULL DEFAULT '',
  browser text NOT NULL,
  browser_name text NOT NULL DEFAULT '',
  browser_version text NOT NULL DEFAULT '',
  engine_name text NOT NULL DEFAULT '',
  engine_version text NOT NULL DEFAULT '',
  os_name text NOT NULL DEFAULT '',
  os_version text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT '',
  user_agent_hash text NOT NULL DEFAULT '',
  ip_address inet,
  ip_version text NOT NULL DEFAULT 'unknown' CHECK (ip_version IN ('IPv4', 'IPv6', 'unknown')),
  country char(2),
  region text NOT NULL DEFAULT '',
  city text,
  timezone text NOT NULL DEFAULT '',
  asn text NOT NULL DEFAULT '',
  isp text NOT NULL DEFAULT '',
  network_org text NOT NULL DEFAULT '',
  network_type text NOT NULL DEFAULT 'unknown' CHECK (network_type IN ('bluetooth', 'cellular', 'ethernet', 'mixed', 'none', 'other', 'unknown', 'wifi', 'wimax')),
  effective_network_type text NOT NULL DEFAULT '' CHECK (effective_network_type IN ('', 'slow-2g', '2g', '3g', '4g', 'unknown')),
  downlink_mbps numeric(9,3),
  rtt_ms integer,
  save_data boolean,
  screen_width integer,
  screen_height integer,
  screen_avail_width integer,
  screen_avail_height integer,
  viewport_width integer,
  viewport_height integer,
  device_pixel_ratio numeric(6,3),
  color_depth integer,
  pixel_depth integer,
  hardware_concurrency integer,
  device_memory_gb numeric(8,2),
  max_touch_points integer,
  cookies_enabled boolean,
  do_not_track text NOT NULL DEFAULT '',
  webdriver boolean,
  locale text NOT NULL DEFAULT '',
  languages text[] NOT NULL DEFAULT ARRAY[]::text[],
  platform text NOT NULL DEFAULT '',
  platform_version text NOT NULL DEFAULT '',
  architecture text NOT NULL DEFAULT '',
  bitness text NOT NULL DEFAULT '',
  client_hints_mobile boolean,
  color_scheme text NOT NULL DEFAULT 'unknown' CHECK (color_scheme IN ('dark', 'light', 'no-preference', 'unknown')),
  reduced_motion boolean,
  forced_colors boolean,
  trusted boolean NOT NULL DEFAULT false,
  current_session boolean NOT NULL DEFAULT false,
  auth_method text NOT NULL DEFAULT 'passkey',
  status stexor_account.session_status NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS stexor_account.device_approval_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  requesting_device text NOT NULL,
  ip_address inet,
  status stexor_account.device_approval_status NOT NULL DEFAULT 'pending',
  approvable_by_session_ids uuid[] NOT NULL DEFAULT ARRAY[]::uuid[],
  approved_by_session_id uuid REFERENCES stexor_account.sessions(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  denied_at timestamptz
);

CREATE TABLE IF NOT EXISTS stexor_account.audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid REFERENCES stexor_account.accounts(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  title text NOT NULL,
  detail text NOT NULL,
  severity stexor_account.audit_severity NOT NULL DEFAULT 'info',
  ip_address inet,
  device text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stexor_account.service_catalog (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text UNIQUE NOT NULL,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  active boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stexor_account.subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES stexor_account.accounts(id) ON DELETE CASCADE,
  service_id uuid NOT NULL REFERENCES stexor_account.service_catalog(id) ON DELETE RESTRICT,
  status stexor_account.subscription_status NOT NULL,
  plan text NOT NULL,
  renewal_date date,
  seats_used integer NOT NULL DEFAULT 1 CHECK (seats_used >= 0),
  seats_total integer NOT NULL DEFAULT 1 CHECK (seats_total >= 1),
  monthly_price_eur numeric(10,2) NOT NULL DEFAULT 0 CHECK (monthly_price_eur >= 0),
  compliance text NOT NULL DEFAULT 'ok',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (account_id, service_id)
);

CREATE TABLE IF NOT EXISTS stexor_account.email_delivery_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL DEFAULT 'disabled',
  from_email citext NOT NULL,
  reply_to citext,
  smtp_host text,
  smtp_port integer CHECK (smtp_port IS NULL OR smtp_port BETWEEN 1 AND 65535),
  smtp_secure boolean NOT NULL DEFAULT true,
  username_ref text,
  secret_ref text,
  credentials_managed_externally boolean NOT NULL DEFAULT true,
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (provider <> 'smtp' OR (smtp_host IS NOT NULL AND secret_ref IS NOT NULL))
);

ALTER TABLE stexor_account.email_delivery_settings
  DROP CONSTRAINT IF EXISTS email_delivery_settings_check;
ALTER TABLE stexor_account.email_delivery_settings
  DROP CONSTRAINT IF EXISTS email_delivery_settings_smtp_requires_host_and_secret;
ALTER TABLE stexor_account.email_delivery_settings
  ADD CONSTRAINT email_delivery_settings_smtp_requires_host_and_secret
  CHECK (provider <> 'smtp' OR (smtp_host IS NOT NULL AND secret_ref IS NOT NULL));

CREATE TABLE IF NOT EXISTS stexor_account.email_templates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  template_key text NOT NULL,
  locale text NOT NULL DEFAULT 'it-IT',
  subject text NOT NULL,
  body_text text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (template_key, locale)
);

CREATE TABLE IF NOT EXISTS stexor_account.email_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid REFERENCES stexor_account.accounts(id) ON DELETE SET NULL,
  to_email citext NOT NULL,
  purpose text NOT NULL,
  template_key text,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status stexor_account.email_delivery_status NOT NULL DEFAULT 'queued',
  provider_message_id text,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz,
  failed_at timestamptz,
  last_error text
);

CREATE INDEX IF NOT EXISTS idx_accounts_email ON stexor_account.accounts(email);
CREATE INDEX IF NOT EXISTS idx_accounts_username ON stexor_account.accounts(username);
CREATE INDEX IF NOT EXISTS idx_passkeys_account ON stexor_account.passkeys(account_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_email_otp_account_status ON stexor_account.email_otp_challenges(account_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_account_status ON stexor_account.sessions(account_id, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_approval_account_status ON stexor_account.device_approval_requests(account_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_account_created ON stexor_account.audit_events(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_outbox_status_next ON stexor_account.email_outbox(status, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS idx_subscriptions_account_status ON stexor_account.subscriptions(account_id, status);

DROP TRIGGER IF EXISTS trg_accounts_updated_at ON stexor_account.accounts;
CREATE TRIGGER trg_accounts_updated_at
BEFORE UPDATE ON stexor_account.accounts
FOR EACH ROW EXECUTE FUNCTION stexor_account.set_updated_at();

DROP TRIGGER IF EXISTS trg_security_updated_at ON stexor_account.account_security_settings;
CREATE TRIGGER trg_security_updated_at
BEFORE UPDATE ON stexor_account.account_security_settings
FOR EACH ROW EXECUTE FUNCTION stexor_account.set_updated_at();

DROP TRIGGER IF EXISTS trg_service_catalog_updated_at ON stexor_account.service_catalog;
CREATE TRIGGER trg_service_catalog_updated_at
BEFORE UPDATE ON stexor_account.service_catalog
FOR EACH ROW EXECUTE FUNCTION stexor_account.set_updated_at();

DROP TRIGGER IF EXISTS trg_subscriptions_updated_at ON stexor_account.subscriptions;
CREATE TRIGGER trg_subscriptions_updated_at
BEFORE UPDATE ON stexor_account.subscriptions
FOR EACH ROW EXECUTE FUNCTION stexor_account.set_updated_at();

DROP TRIGGER IF EXISTS trg_email_delivery_settings_updated_at ON stexor_account.email_delivery_settings;
CREATE TRIGGER trg_email_delivery_settings_updated_at
BEFORE UPDATE ON stexor_account.email_delivery_settings
FOR EACH ROW EXECUTE FUNCTION stexor_account.set_updated_at();

DROP TRIGGER IF EXISTS trg_email_templates_updated_at ON stexor_account.email_templates;
CREATE TRIGGER trg_email_templates_updated_at
BEFORE UPDATE ON stexor_account.email_templates
FOR EACH ROW EXECUTE FUNCTION stexor_account.set_updated_at();

INSERT INTO stexor_account.email_templates (template_key, locale, subject, body_text)
VALUES
  ('login_otp', 'it-IT', 'Il tuo codice di accesso', 'Il tuo codice OTP e {{code}}. Scade tra {{minutes}} minuti.'),
  ('recovery_otp', 'it-IT', 'Codice recupero account', 'Usa {{code}} per recuperare il tuo account.'),
  ('device_approval', 'it-IT', 'Nuova richiesta di accesso', 'Approva la richiesta da {{device}} solo se sei stato tu.')
ON CONFLICT (template_key, locale) DO UPDATE SET
  subject = EXCLUDED.subject,
  body_text = EXCLUDED.body_text,
  active = true;

DO $$
BEGIN
  CREATE ROLE stexor_app_account_rw NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE ROLE stexor_app_auth_rw NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE ROLE stexor_app_audit_rw NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

GRANT USAGE ON SCHEMA stexor_account TO stexor_app_account_rw, stexor_app_auth_rw, stexor_app_audit_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA stexor_account TO stexor_app_account_rw, stexor_app_auth_rw, stexor_app_audit_rw;

GRANT SELECT, INSERT, UPDATE ON
  stexor_account.accounts,
  stexor_account.account_roles,
  stexor_account.account_security_settings,
  stexor_account.subscriptions
TO stexor_app_account_rw;

GRANT SELECT ON
  stexor_account.service_catalog,
  stexor_account.security_policies
TO stexor_app_account_rw;

GRANT SELECT, INSERT, UPDATE ON
  stexor_account.passkeys,
  stexor_account.sessions,
  stexor_account.totp_secrets,
  stexor_account.backup_code_sets,
  stexor_account.backup_codes,
  stexor_account.device_approval_requests,
  stexor_account.email_otp_challenges
TO stexor_app_auth_rw;

GRANT SELECT, INSERT, UPDATE ON
  stexor_account.audit_events,
  stexor_account.email_outbox
TO stexor_app_audit_rw;

GRANT SELECT ON
  stexor_account.email_templates,
  stexor_account.email_delivery_settings
TO stexor_app_audit_rw;

ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_account GRANT SELECT, INSERT, UPDATE ON TABLES TO stexor_app_account_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_account GRANT USAGE, SELECT ON SEQUENCES TO stexor_app_account_rw;

GRANT stexor_app_account_rw TO stexor_app_user;
GRANT stexor_app_auth_rw TO stexor_app_user;
GRANT stexor_app_audit_rw TO stexor_app_user;

DO $$
BEGIN
  CREATE ROLE stexor_console_readonly NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

GRANT USAGE ON SCHEMA stexor_account TO stexor_console_readonly;
GRANT SELECT ON
  stexor_account.accounts,
  stexor_account.account_security_settings,
  stexor_account.sessions,
  stexor_account.device_approval_requests,
  stexor_account.audit_events,
  stexor_account.service_catalog,
  stexor_account.subscriptions,
  stexor_account.email_templates
TO stexor_console_readonly;

GRANT stexor_console_readonly TO stexor_app_user;
