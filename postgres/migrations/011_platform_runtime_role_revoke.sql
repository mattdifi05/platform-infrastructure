\connect stexor_app

BEGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA stexor_platform FROM
  PUBLIC,
  stexor_app_user,
  stexor_app_account_rw,
  stexor_app_auth_rw,
  stexor_app_audit_rw;

REVOKE ALL ON ALL SEQUENCES IN SCHEMA stexor_platform FROM
  PUBLIC,
  stexor_app_user,
  stexor_app_account_rw,
  stexor_app_auth_rw,
  stexor_app_audit_rw;

ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_platform REVOKE ALL ON TABLES FROM
  PUBLIC,
  stexor_app_user,
  stexor_app_account_rw,
  stexor_app_auth_rw,
  stexor_app_audit_rw;

ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_platform REVOKE ALL ON SEQUENCES FROM
  PUBLIC,
  stexor_app_user,
  stexor_app_account_rw,
  stexor_app_auth_rw,
  stexor_app_audit_rw;

GRANT USAGE ON SCHEMA stexor_platform TO stexor_app_user, stexor_console_readonly;

GRANT SELECT ON
  stexor_platform.schema_migrations,
  stexor_platform.data_retention_policies,
  stexor_platform.backup_restore_runs
TO stexor_app_user, stexor_console_readonly;

REVOKE INSERT, UPDATE, DELETE ON
  stexor_platform.schema_migrations,
  stexor_platform.data_retention_policies,
  stexor_platform.backup_restore_runs
FROM
  PUBLIC,
  stexor_app_user,
  stexor_app_account_rw,
  stexor_app_auth_rw,
  stexor_app_audit_rw,
  stexor_console_readonly;

INSERT INTO stexor_account.security_policies (key, value, description)
VALUES (
  'platform_runtime_role_revoke',
  '{"runtimeCanReadPlatformEvidence":true,"runtimeCanMutatePlatformEvidence":false,"revokesInheritedRuntimeRoles":true,"migration":"011_platform_runtime_role_revoke"}'::jsonb,
  'Runtime capability roles do not inherit mutation rights on platform migration, retention or backup/restore control tables.'
)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    description = excluded.description,
    updated_at = now();

COMMIT;
