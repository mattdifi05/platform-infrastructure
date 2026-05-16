\connect stexor_app

DO $$
BEGIN
  CREATE ROLE stexor_console_readonly NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

GRANT USAGE ON SCHEMA stexor_account TO stexor_console_readonly;
GRANT USAGE ON SCHEMA stexor_platform TO stexor_console_readonly;

GRANT SELECT ON
  stexor_account.accounts,
  stexor_account.account_roles,
  stexor_account.account_security_settings,
  stexor_account.passkeys,
  stexor_account.sessions,
  stexor_account.device_approval_requests,
  stexor_account.audit_events,
  stexor_account.service_catalog,
  stexor_account.subscriptions,
  stexor_account.email_templates,
  stexor_account.security_policies,
  stexor_platform.schema_migrations
TO stexor_console_readonly;

REVOKE ALL ON
  stexor_account.totp_secrets,
  stexor_account.backup_codes,
  stexor_account.backup_code_sets,
  stexor_account.email_otp_challenges,
  stexor_account.email_delivery_settings,
  stexor_account.email_outbox
FROM stexor_console_readonly;

GRANT stexor_console_readonly TO stexor_app_user;

UPDATE stexor_account.security_policies
SET value = jsonb_set(
      jsonb_set(
        jsonb_set(value, '{readRole}', '"stexor_console_readonly"'::jsonb, true),
        '{deniedTables}',
        '["stexor_account.totp_secrets","stexor_account.backup_codes","stexor_account.backup_code_sets","stexor_account.email_otp_challenges","stexor_account.email_delivery_settings","stexor_account.email_outbox"]'::jsonb,
        true
      ),
      '{bindGrantToIp}',
      'true'::jsonb,
      true
    ),
    updated_at = now()
WHERE key = 'db_console';
