\connect app_db

BEGIN;

ALTER TABLE app_account.audit_outbox
  DROP CONSTRAINT IF EXISTS audit_outbox_status_known,
  ADD CONSTRAINT audit_outbox_status_known CHECK (status IN ('queued', 'processing', 'delivered', 'failed', 'dead'));

CREATE INDEX IF NOT EXISTS idx_audit_outbox_due_dispatch
  ON app_account.audit_outbox(next_attempt_at, created_at)
  WHERE status IN ('queued', 'failed', 'processing');

COMMENT ON COLUMN app_account.audit_outbox.status IS 'Delivery lifecycle: queued, processing lease, delivered, retryable failed, or terminal dead letter.';
COMMENT ON COLUMN app_account.audit_outbox.next_attempt_at IS 'Next eligible claim time. For processing rows this is also the worker lease expiry used for crash recovery.';
COMMENT ON COLUMN app_account.audit_outbox.attempts IS 'Number of worker delivery attempts claimed transactionally.';

UPDATE app_account.security_policies
SET value = jsonb_set(
      jsonb_set(value, '{durableAuditDispatcher}', 'true'::jsonb, true),
      '{auditOutboxDeadLetterStatus}',
      '"dead"'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'app_runtime_db_privileges';

COMMIT;
