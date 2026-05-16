\connect stexor_app

BEGIN;

CREATE TABLE IF NOT EXISTS stexor_account.audit_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_event_id uuid NOT NULL REFERENCES stexor_account.audit_events(id) ON DELETE RESTRICT,
  external_event_id text NOT NULL,
  event_type text NOT NULL,
  severity stexor_account.audit_severity NOT NULL,
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE stexor_account.audit_outbox
  DROP CONSTRAINT IF EXISTS audit_outbox_status_known,
  ADD CONSTRAINT audit_outbox_status_known CHECK (status IN ('queued', 'processing', 'delivered', 'failed'));

ALTER TABLE stexor_account.audit_outbox
  DROP CONSTRAINT IF EXISTS audit_outbox_attempts_non_negative,
  ADD CONSTRAINT audit_outbox_attempts_non_negative CHECK (attempts >= 0);

ALTER TABLE stexor_account.audit_outbox
  DROP CONSTRAINT IF EXISTS audit_outbox_processed_status_coherent,
  ADD CONSTRAINT audit_outbox_processed_status_coherent CHECK (
    (processed_at IS NULL AND status <> 'delivered')
    OR (processed_at IS NOT NULL AND status = 'delivered')
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_outbox_audit_event
  ON stexor_account.audit_outbox(audit_event_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_outbox_external_event
  ON stexor_account.audit_outbox(external_event_id);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_status_next_attempt
  ON stexor_account.audit_outbox(status, next_attempt_at, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_type_created
  ON stexor_account.audit_outbox(event_type, created_at DESC);

ALTER TABLE stexor_account.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.audit_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_outbox_runtime_access ON stexor_account.audit_outbox;
CREATE POLICY audit_outbox_runtime_access ON stexor_account.audit_outbox
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'));

REVOKE ALL ON stexor_account.audit_outbox FROM PUBLIC;
REVOKE ALL ON stexor_account.audit_outbox FROM stexor_console_readonly;
GRANT SELECT, INSERT, UPDATE ON stexor_account.audit_outbox TO stexor_app_audit_rw;
REVOKE DELETE ON stexor_account.audit_outbox FROM stexor_app_audit_rw;

INSERT INTO stexor_platform.data_retention_policies (key, target_table, retention_interval, action, enabled, description)
VALUES
  ('audit_outbox', 'stexor_account.audit_outbox'::regclass, interval '90 days', 'archive', true, 'Durable audit dispatch queue is retained online until downstream delivery and investigation windows close.')
ON CONFLICT (key) DO UPDATE SET
  target_table = EXCLUDED.target_table,
  retention_interval = EXCLUDED.retention_interval,
  action = EXCLUDED.action,
  enabled = EXCLUDED.enabled,
  description = EXCLUDED.description,
  updated_at = now();

UPDATE stexor_account.security_policies
SET value = jsonb_set(
      value,
      '{deniedTables}',
      '["stexor_account.passkeys","stexor_account.totp_secrets","stexor_account.backup_codes","stexor_account.backup_code_sets","stexor_account.email_otp_challenges","stexor_account.email_delivery_settings","stexor_account.email_outbox","stexor_account.audit_outbox"]'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'db_console';

UPDATE stexor_account.security_policies
SET value = jsonb_set(
      jsonb_set(value, '{durableAuditOutbox}', 'true'::jsonb, true),
      '{auditOutboxTable}',
      '"stexor_account.audit_outbox"'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'app_runtime_db_privileges';

UPDATE stexor_account.security_policies
SET value = jsonb_set(
      value,
      '{onlinePolicies}',
      '["audit_events","audit_outbox","email_otp_challenges","email_outbox","revoked_sessions","deleted_accounts"]'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'data_retention';

COMMENT ON TABLE stexor_account.audit_outbox IS 'Durable queue for critical audit events that must survive process failure before external dispatch.';

COMMIT;
