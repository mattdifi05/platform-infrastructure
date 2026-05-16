\connect stexor_app

CREATE SCHEMA IF NOT EXISTS stexor_platform;

CREATE TABLE IF NOT EXISTS stexor_platform.schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now(),
  checksum text NOT NULL DEFAULT ''
);

WITH ranked_sessions AS (
  SELECT
    id,
    row_number() OVER (PARTITION BY account_id ORDER BY current_session DESC, last_seen_at DESC, created_at DESC) AS rank
  FROM stexor_account.sessions
  WHERE status = 'active'
)
UPDATE stexor_account.sessions session
SET current_session = false
FROM ranked_sessions ranked
WHERE session.id = ranked.id
  AND ranked.rank > 1
  AND session.current_session = true;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_one_current_active
  ON stexor_account.sessions(account_id)
  WHERE current_session = true AND status = 'active';

CREATE INDEX IF NOT EXISTS idx_backup_codes_active_lookup
  ON stexor_account.backup_codes(code_hash)
  WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_backup_code_sets_account_active
  ON stexor_account.backup_code_sets(account_id, created_at DESC)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_audit_events_type_created
  ON stexor_account.audit_events(event_type, created_at DESC);

ALTER TABLE stexor_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_expiry_after_creation;

ALTER TABLE stexor_account.sessions
  ADD CONSTRAINT sessions_expiry_after_creation
  CHECK (expires_at > created_at);

COMMENT ON SCHEMA stexor_account IS 'Stexor account, passwordless, sessions, audit and subscription data.';
COMMENT ON TABLE stexor_account.audit_events IS 'Append-only security and product audit trail.';
COMMENT ON TABLE stexor_account.sessions IS 'Trusted browser/device sessions backed by HttpOnly signed cookies.';
COMMENT ON TABLE stexor_account.backup_codes IS 'One-time recovery backup code hashes.';

GRANT USAGE ON SCHEMA stexor_platform TO stexor_app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA stexor_platform TO stexor_app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_platform GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO stexor_app_user;
