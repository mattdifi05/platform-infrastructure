\connect app_db

BEGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA platform_ops FROM
  PUBLIC,
  app_user,
  app_db_account_rw,
  app_db_auth_rw,
  app_db_audit_rw;

REVOKE ALL ON ALL SEQUENCES IN SCHEMA platform_ops FROM
  PUBLIC,
  app_user,
  app_db_account_rw,
  app_db_auth_rw,
  app_db_audit_rw;

ALTER DEFAULT PRIVILEGES IN SCHEMA platform_ops REVOKE ALL ON TABLES FROM
  PUBLIC,
  app_user,
  app_db_account_rw,
  app_db_auth_rw,
  app_db_audit_rw;

ALTER DEFAULT PRIVILEGES IN SCHEMA platform_ops REVOKE ALL ON SEQUENCES FROM
  PUBLIC,
  app_user,
  app_db_account_rw,
  app_db_auth_rw,
  app_db_audit_rw;

GRANT USAGE ON SCHEMA platform_ops TO app_user;

GRANT SELECT ON
  platform_ops.schema_migrations,
  platform_ops.data_retention_policies,
  platform_ops.backup_restore_runs
TO app_user;

REVOKE INSERT, UPDATE, DELETE ON
  platform_ops.schema_migrations,
  platform_ops.data_retention_policies,
  platform_ops.backup_restore_runs
FROM
  PUBLIC,
  app_user,
  app_db_account_rw,
  app_db_auth_rw,
  app_db_audit_rw;

INSERT INTO app_account.security_policies (key, value, description)
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
