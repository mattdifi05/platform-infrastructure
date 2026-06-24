\connect app_db

BEGIN;

CREATE TABLE IF NOT EXISTS app_account.audit_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  audit_event_id uuid NOT NULL REFERENCES app_account.audit_events(id) ON DELETE RESTRICT,
  external_event_id text NOT NULL,
  event_type text NOT NULL,
  severity app_account.audit_severity NOT NULL,
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE app_account.audit_outbox
  DROP CONSTRAINT IF EXISTS audit_outbox_status_known,
  ADD CONSTRAINT audit_outbox_status_known CHECK (status IN ('queued', 'processing', 'delivered', 'failed'));

ALTER TABLE app_account.audit_outbox
  DROP CONSTRAINT IF EXISTS audit_outbox_attempts_non_negative,
  ADD CONSTRAINT audit_outbox_attempts_non_negative CHECK (attempts >= 0);

ALTER TABLE app_account.audit_outbox
  DROP CONSTRAINT IF EXISTS audit_outbox_processed_status_coherent,
  ADD CONSTRAINT audit_outbox_processed_status_coherent CHECK (
    (processed_at IS NULL AND status <> 'delivered')
    OR (processed_at IS NOT NULL AND status = 'delivered')
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_outbox_audit_event
  ON app_account.audit_outbox(audit_event_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_outbox_external_event
  ON app_account.audit_outbox(external_event_id);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_status_next_attempt
  ON app_account.audit_outbox(status, next_attempt_at, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_type_created
  ON app_account.audit_outbox(event_type, created_at DESC);

ALTER TABLE app_account.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_account.audit_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_outbox_runtime_access ON app_account.audit_outbox;
CREATE POLICY audit_outbox_runtime_access ON app_account.audit_outbox
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'app_db_audit_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'app_db_audit_rw', 'member'));

REVOKE ALL ON app_account.audit_outbox FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON app_account.audit_outbox TO app_db_audit_rw;
REVOKE DELETE ON app_account.audit_outbox FROM app_db_audit_rw;

INSERT INTO platform_ops.data_retention_policies (key, target_table, retention_interval, action, enabled, description)
VALUES
  ('audit_outbox', 'app_account.audit_outbox'::regclass, interval '90 days', 'archive', true, 'Durable audit dispatch queue is retained online until downstream delivery and investigation windows close.')
ON CONFLICT (key) DO UPDATE SET
  target_table = EXCLUDED.target_table,
  retention_interval = EXCLUDED.retention_interval,
  action = EXCLUDED.action,
  enabled = EXCLUDED.enabled,
  description = EXCLUDED.description,
  updated_at = now();

UPDATE app_account.security_policies
SET value = jsonb_set(
      jsonb_set(value, '{durableAuditOutbox}', 'true'::jsonb, true),
      '{auditOutboxTable}',
      '"app_account.audit_outbox"'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'app_runtime_db_privileges';

UPDATE app_account.security_policies
SET value = jsonb_set(
      value,
      '{onlinePolicies}',
      '["audit_events","audit_outbox","email_otp_challenges","email_outbox","revoked_sessions","deleted_accounts"]'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'data_retention';

COMMENT ON TABLE app_account.audit_outbox IS 'Durable queue for critical audit events that must survive process failure before external dispatch.';

COMMIT;
