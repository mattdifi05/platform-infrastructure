\connect stexor_app

BEGIN;

DROP TABLE IF EXISTS stexor_account.totp_secrets;

ALTER TABLE stexor_account.account_security_settings
  DROP COLUMN IF EXISTS totp_enabled;

INSERT INTO stexor_account.security_policies (key, value, description)
VALUES (
  'totp_removed',
  '{"removedTables":["stexor_account.totp_secrets"],"removedColumns":["stexor_account.account_security_settings.totp_enabled"],"strongRecovery":["backup_codes"],"migration":"014_remove_totp"}'::jsonb,
  'TOTP recovery is removed; strong recovery is handled by backup codes and passkey reset flows.'
)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    description = excluded.description,
    updated_at = now();

COMMIT;
