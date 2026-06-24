\connect app_db

BEGIN;

DROP INDEX IF EXISTS app_account.idx_accounts_recovery_email;

ALTER TABLE app_account.accounts
  DROP COLUMN IF EXISTS recovery_email,
  DROP COLUMN IF EXISTS recovery_email_verified;

INSERT INTO app_account.security_policies (key, value, description)
VALUES (
  'recovery_email_removed',
  '{"removedColumns":["app_account.accounts.recovery_email","app_account.accounts.recovery_email_verified"],"primaryEmailOtpRecovery":true,"strongRecovery":["backup_codes"],"migration":"012_remove_recovery_email"}'::jsonb,
  'Separate recovery email storage is removed; recovery uses the verified primary email plus stronger recovery factors.'
)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    description = excluded.description,
    updated_at = now();

COMMIT;
