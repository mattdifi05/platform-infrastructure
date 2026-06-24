BEGIN;

DO $$
BEGIN
  CREATE ROLE app_db_account_rw NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE ROLE app_db_auth_rw NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE ROLE app_db_audit_rw NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA app_account FROM app_user;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA app_account FROM app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_account REVOKE ALL ON TABLES FROM app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_account REVOKE ALL ON SEQUENCES FROM app_user;

GRANT USAGE ON SCHEMA app_account TO app_db_account_rw, app_db_auth_rw, app_db_audit_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app_account TO app_db_account_rw, app_db_auth_rw, app_db_audit_rw;

GRANT SELECT, INSERT, UPDATE ON
  app_account.accounts,
  app_account.account_roles,
  app_account.account_security_settings,
  app_account.subscriptions
TO app_db_account_rw;

GRANT SELECT ON
  app_account.service_catalog,
  app_account.security_policies
TO app_db_account_rw;

GRANT SELECT, INSERT, UPDATE ON
  app_account.passkeys,
  app_account.sessions,
  app_account.backup_code_sets,
  app_account.backup_codes,
  app_account.device_approval_requests,
  app_account.email_otp_challenges
TO app_db_auth_rw;

GRANT SELECT, INSERT, UPDATE ON
  app_account.audit_events,
  app_account.email_outbox
TO app_db_audit_rw;

GRANT SELECT ON
  app_account.email_templates,
  app_account.email_delivery_settings
TO app_db_audit_rw;

ALTER DEFAULT PRIVILEGES IN SCHEMA app_account GRANT SELECT, INSERT, UPDATE ON TABLES TO app_db_account_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_account GRANT USAGE, SELECT ON SEQUENCES TO app_db_account_rw;

GRANT app_db_account_rw TO app_user;
GRANT app_db_auth_rw TO app_user;
GRANT app_db_audit_rw TO app_user;

INSERT INTO app_account.security_policies (key, value, description)
VALUES (
  'app_runtime_db_privileges',
  '{"directBroadGrants":false,"deletePrivilege":false,"splitRoles":["app_db_account_rw","app_db_auth_rw","app_db_audit_rw"]}'::jsonb,
  'Application runtime database privileges are split by capability and exclude broad DELETE grants.'
)
ON CONFLICT (key) DO UPDATE SET
  value = EXCLUDED.value,
  description = EXCLUDED.description,
  updated_at = now();

COMMIT;
