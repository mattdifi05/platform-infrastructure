BEGIN;

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

REVOKE ALL ON ALL TABLES IN SCHEMA stexor_account FROM stexor_app_user;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA stexor_account FROM stexor_app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_account REVOKE ALL ON TABLES FROM stexor_app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_account REVOKE ALL ON SEQUENCES FROM stexor_app_user;

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

INSERT INTO stexor_account.security_policies (key, value, description)
VALUES (
  'app_runtime_db_privileges',
  '{"directBroadGrants":false,"deletePrivilege":false,"splitRoles":["stexor_app_account_rw","stexor_app_auth_rw","stexor_app_audit_rw","stexor_console_readonly"]}'::jsonb,
  'Application runtime database privileges are split by capability and exclude broad DELETE grants.'
)
ON CONFLICT (key) DO UPDATE SET
  value = EXCLUDED.value,
  description = EXCLUDED.description,
  updated_at = now();

COMMIT;
