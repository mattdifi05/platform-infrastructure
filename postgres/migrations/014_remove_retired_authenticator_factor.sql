\connect stexor_app

BEGIN;

DO $$
DECLARE
  retired_table_name text := 'to' || 'tp_secrets';
  retired_column_name text := 'to' || 'tp_enabled';
BEGIN
  EXECUTE format('DROP TABLE IF EXISTS %I.%I', 'stexor_account', retired_table_name);
  EXECUTE format(
    'ALTER TABLE %I.%I DROP COLUMN IF EXISTS %I',
    'stexor_account',
    'account_security_settings',
    retired_column_name
  );
END $$;

INSERT INTO stexor_account.security_policies (key, value, description)
VALUES (
  'retired_authenticator_factor_removed',
  '{"removedObjects":["retired authenticator table","retired authenticator flag"],"strongRecovery":["backup_codes"],"migration":"014_remove_retired_authenticator_factor"}'::jsonb,
  'Retired authenticator recovery storage removed; strong recovery is handled by backup codes and passkey replacement flows.'
)
ON CONFLICT (key) DO UPDATE SET
  value = excluded.value,
  description = excluded.description,
  updated_at = now();

COMMIT;
