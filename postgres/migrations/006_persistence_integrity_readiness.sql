\connect stexor_app

BEGIN;

ALTER TABLE stexor_platform.schema_migrations
  ADD COLUMN IF NOT EXISTS applied_by text NOT NULL DEFAULT current_user,
  ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS stexor_platform.data_retention_policies (
  key text PRIMARY KEY,
  target_table regclass NOT NULL,
  retention_interval interval NOT NULL CHECK (retention_interval > interval '0 seconds'),
  action text NOT NULL CHECK (action IN ('retain', 'purge', 'archive', 'anonymize')),
  enabled boolean NOT NULL DEFAULT true,
  description text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stexor_platform.backup_restore_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  operation text NOT NULL CHECK (operation IN ('backup', 'restore', 'restore_test')),
  status text NOT NULL CHECK (status IN ('started', 'success', 'failed')),
  database_name text NOT NULL,
  artifact_path text,
  artifact_sha256 text CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[a-f0-9]{64}$'),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  duration_ms integer CHECK (duration_ms IS NULL OR duration_ms >= 0),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  CHECK ((status = 'started' AND finished_at IS NULL) OR (status <> 'started' AND finished_at IS NOT NULL)),
  CHECK (finished_at IS NULL OR finished_at >= started_at)
);

ALTER TABLE stexor_platform.backup_restore_runs
  DROP CONSTRAINT IF EXISTS backup_restore_runs_operation_known,
  ADD CONSTRAINT backup_restore_runs_operation_known CHECK (operation IN ('backup', 'restore', 'restore_test'));

ALTER TABLE stexor_platform.backup_restore_runs
  DROP CONSTRAINT IF EXISTS backup_restore_runs_status_known,
  ADD CONSTRAINT backup_restore_runs_status_known CHECK (status IN ('started', 'success', 'failed'));

ALTER TABLE stexor_platform.backup_restore_runs
  DROP CONSTRAINT IF EXISTS backup_restore_runs_artifact_sha256_format,
  ADD CONSTRAINT backup_restore_runs_artifact_sha256_format CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE stexor_platform.backup_restore_runs
  DROP CONSTRAINT IF EXISTS backup_restore_runs_duration_non_negative,
  ADD CONSTRAINT backup_restore_runs_duration_non_negative CHECK (duration_ms IS NULL OR duration_ms >= 0);

ALTER TABLE stexor_platform.backup_restore_runs
  DROP CONSTRAINT IF EXISTS backup_restore_runs_finished_status_coherent,
  ADD CONSTRAINT backup_restore_runs_finished_status_coherent CHECK (
    (status = 'started' AND finished_at IS NULL)
    OR (status <> 'started' AND finished_at IS NOT NULL)
  );

ALTER TABLE stexor_platform.backup_restore_runs
  DROP CONSTRAINT IF EXISTS backup_restore_runs_finished_after_started,
  ADD CONSTRAINT backup_restore_runs_finished_after_started CHECK (finished_at IS NULL OR finished_at >= started_at);

DROP TRIGGER IF EXISTS trg_data_retention_policies_updated_at ON stexor_platform.data_retention_policies;
CREATE TRIGGER trg_data_retention_policies_updated_at
BEFORE UPDATE ON stexor_platform.data_retention_policies
FOR EACH ROW EXECUTE FUNCTION stexor_account.set_updated_at();

ALTER TABLE stexor_account.accounts
  DROP CONSTRAINT IF EXISTS accounts_username_format,
  ADD CONSTRAINT accounts_username_format CHECK (username::text ~ '^[a-z0-9_][a-z0-9_.]{2,31}$');

ALTER TABLE stexor_account.accounts
  DROP CONSTRAINT IF EXISTS accounts_email_format,
  ADD CONSTRAINT accounts_email_format CHECK (
    position('@' in email::text) > 1
    AND position('.' in split_part(email::text, '@', 2)) > 1
  );

ALTER TABLE stexor_account.accounts
  DROP CONSTRAINT IF EXISTS accounts_language_format,
  ADD CONSTRAINT accounts_language_format CHECK (language ~ '^[a-z]{2}-[A-Z]{2}$');

ALTER TABLE stexor_account.accounts
  DROP CONSTRAINT IF EXISTS accounts_deleted_anonymized,
  ADD CONSTRAINT accounts_deleted_anonymized CHECK (
    deleted_at IS NULL
    OR email::text ~ '^deleted\+[0-9a-f-]+@deleted\.stexor\.local$'
  );

ALTER TABLE stexor_account.account_security_settings
  DROP CONSTRAINT IF EXISTS account_security_locked_after_creation,
  ADD CONSTRAINT account_security_locked_after_creation CHECK (locked_until IS NULL OR locked_until > created_at);

ALTER TABLE stexor_account.passkeys
  DROP CONSTRAINT IF EXISTS passkeys_device_type_known,
  ADD CONSTRAINT passkeys_device_type_known CHECK (device_type IN ('singleDevice', 'multiDevice', 'unknown'));

ALTER TABLE stexor_account.passkeys
  DROP CONSTRAINT IF EXISTS passkeys_label_not_blank,
  ADD CONSTRAINT passkeys_label_not_blank CHECK (length(trim(label)) BETWEEN 1 AND 120);

ALTER TABLE stexor_account.email_otp_challenges
  DROP CONSTRAINT IF EXISTS email_otp_expiry_after_creation,
  ADD CONSTRAINT email_otp_expiry_after_creation CHECK (expires_at > created_at);

ALTER TABLE stexor_account.email_otp_challenges
  DROP CONSTRAINT IF EXISTS email_otp_attempts_within_max,
  ADD CONSTRAINT email_otp_attempts_within_max CHECK (attempts <= max_attempts);

ALTER TABLE stexor_account.email_otp_challenges
  DROP CONSTRAINT IF EXISTS email_otp_consumed_after_creation,
  ADD CONSTRAINT email_otp_consumed_after_creation CHECK (consumed_at IS NULL OR consumed_at >= created_at);

ALTER TABLE stexor_account.backup_code_sets
  DROP CONSTRAINT IF EXISTS backup_code_sets_revoked_after_creation,
  ADD CONSTRAINT backup_code_sets_revoked_after_creation CHECK (revoked_at IS NULL OR revoked_at >= created_at);

ALTER TABLE stexor_account.backup_codes
  DROP CONSTRAINT IF EXISTS backup_codes_used_after_creation,
  ADD CONSTRAINT backup_codes_used_after_creation CHECK (used_at IS NULL OR used_at >= created_at);

ALTER TABLE stexor_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_current_requires_active,
  ADD CONSTRAINT sessions_current_requires_active CHECK (current_session = false OR status = 'active');

ALTER TABLE stexor_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_last_seen_after_creation,
  ADD CONSTRAINT sessions_last_seen_after_creation CHECK (last_seen_at >= created_at);

ALTER TABLE stexor_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_revoked_after_creation,
  ADD CONSTRAINT sessions_revoked_after_creation CHECK (revoked_at IS NULL OR revoked_at >= created_at);

ALTER TABLE stexor_account.device_approval_requests
  DROP CONSTRAINT IF EXISTS device_approval_expiry_after_creation,
  ADD CONSTRAINT device_approval_expiry_after_creation CHECK (expires_at > created_at);

ALTER TABLE stexor_account.device_approval_requests
  DROP CONSTRAINT IF EXISTS device_approval_terminal_timestamps,
  ADD CONSTRAINT device_approval_terminal_timestamps CHECK (
    (status <> 'approved' OR approved_at IS NOT NULL)
    AND (status <> 'denied' OR denied_at IS NOT NULL)
  );

ALTER TABLE stexor_account.subscriptions
  DROP CONSTRAINT IF EXISTS subscriptions_seats_within_total,
  ADD CONSTRAINT subscriptions_seats_within_total CHECK (seats_used <= seats_total);

ALTER TABLE stexor_account.email_outbox
  DROP CONSTRAINT IF EXISTS email_outbox_next_attempt_after_creation,
  ADD CONSTRAINT email_outbox_next_attempt_after_creation CHECK (next_attempt_at IS NULL OR next_attempt_at >= created_at);

WITH ranked_sets AS (
  SELECT
    id,
    row_number() OVER (PARTITION BY account_id ORDER BY created_at DESC, id DESC) AS rank
  FROM stexor_account.backup_code_sets
  WHERE revoked_at IS NULL
)
UPDATE stexor_account.backup_code_sets code_set
SET revoked_at = now()
FROM ranked_sets ranked
WHERE code_set.id = ranked.id
  AND ranked.rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_backup_code_sets_one_active
  ON stexor_account.backup_code_sets(account_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_active_expiry
  ON stexor_account.sessions(expires_at)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_email_otp_destination_purpose_created
  ON stexor_account.email_otp_challenges(destination, purpose, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_device_approval_pending_expiry
  ON stexor_account.device_approval_requests(expires_at)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_email_outbox_account_created
  ON stexor_account.email_outbox(account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_accounts_deleted_at
  ON stexor_account.accounts(deleted_at)
  WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_backup_restore_runs_operation_started
  ON stexor_platform.backup_restore_runs(operation, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_data_retention_policies_enabled
  ON stexor_platform.data_retention_policies(enabled, target_table);

CREATE OR REPLACE FUNCTION stexor_account.prevent_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_events_are_append_only';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_events_append_only ON stexor_account.audit_events;
CREATE TRIGGER trg_audit_events_append_only
BEFORE UPDATE OR DELETE ON stexor_account.audit_events
FOR EACH ROW EXECUTE FUNCTION stexor_account.prevent_audit_event_mutation();

DROP POLICY IF EXISTS audit_events_runtime_access ON stexor_account.audit_events;
DROP POLICY IF EXISTS audit_events_runtime_select ON stexor_account.audit_events;
DROP POLICY IF EXISTS audit_events_runtime_insert ON stexor_account.audit_events;
CREATE POLICY audit_events_runtime_select ON stexor_account.audit_events
  FOR SELECT TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'));
CREATE POLICY audit_events_runtime_insert ON stexor_account.audit_events
  FOR INSERT TO PUBLIC
  WITH CHECK (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'));

REVOKE UPDATE, DELETE ON stexor_account.audit_events FROM stexor_app_audit_rw;
REVOKE UPDATE, DELETE ON stexor_account.audit_events FROM stexor_app_user;
GRANT SELECT, INSERT ON stexor_account.audit_events TO stexor_app_audit_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_account REVOKE UPDATE, DELETE ON TABLES FROM stexor_app_audit_rw;

GRANT SELECT, INSERT, UPDATE ON
  stexor_platform.data_retention_policies,
  stexor_platform.backup_restore_runs
TO stexor_app_audit_rw;

INSERT INTO stexor_platform.data_retention_policies (key, target_table, retention_interval, action, enabled, description)
VALUES
  ('audit_events', 'stexor_account.audit_events'::regclass, interval '400 days', 'archive', true, 'Security audit is retained online for investigation and archived before purge.'),
  ('email_otp_challenges', 'stexor_account.email_otp_challenges'::regclass, interval '30 days', 'purge', true, 'Expired OTP challenges are short-lived operational security data.'),
  ('email_outbox', 'stexor_account.email_outbox'::regclass, interval '90 days', 'archive', true, 'Email delivery trace is retained for support and abuse review.'),
  ('revoked_sessions', 'stexor_account.sessions'::regclass, interval '180 days', 'archive', true, 'Revoked and expired sessions are retained for security review.'),
  ('deleted_accounts', 'stexor_account.accounts'::regclass, interval '30 days', 'anonymize', true, 'Soft-deleted accounts are anonymized before any irreversible purge.')
ON CONFLICT (key) DO UPDATE SET
  target_table = EXCLUDED.target_table,
  retention_interval = EXCLUDED.retention_interval,
  action = EXCLUDED.action,
  enabled = EXCLUDED.enabled,
  description = EXCLUDED.description,
  updated_at = now();

INSERT INTO stexor_account.security_policies (key, value, description)
VALUES
  (
    'data_retention',
    '{"onlinePolicies":["audit_events","email_otp_challenges","email_outbox","revoked_sessions","deleted_accounts"],"policyTable":"stexor_platform.data_retention_policies","requiresRestoreTestBeforePurge":true}'::jsonb,
    'Database retention policies are stored in PostgreSQL and must be checked before destructive maintenance.'
  ),
  (
    'backup_restore_readiness',
    '{"backupFormat":"pg_dump custom","checksum":"sha256","restoreTest":"required","runLog":"stexor_platform.backup_restore_runs"}'::jsonb,
    'Backup and restore runs are tracked with artifact checksum and restore-test status.'
  )
ON CONFLICT (key) DO UPDATE SET
  value = EXCLUDED.value,
  description = EXCLUDED.description,
  updated_at = now();

UPDATE stexor_account.security_policies
SET value = jsonb_set(
      jsonb_set(value, '{retentionPoliciesTable}', '"stexor_platform.data_retention_policies"'::jsonb, true),
      '{restoreRunLog}',
      '"stexor_platform.backup_restore_runs"'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'backup';

COMMENT ON TABLE stexor_platform.data_retention_policies IS 'Authoritative database retention policy table for operational data classes.';
COMMENT ON TABLE stexor_platform.backup_restore_runs IS 'Append-style log of PostgreSQL backup, restore and restore-test executions.';
COMMENT ON TRIGGER trg_audit_events_append_only ON stexor_account.audit_events IS 'Audit events are append-only; corrections must be represented by a new event.';

COMMIT;
