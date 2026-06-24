\connect app_db

BEGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA platform_ops FROM app_user;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA platform_ops FROM app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA platform_ops REVOKE ALL ON TABLES FROM app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA platform_ops REVOKE ALL ON SEQUENCES FROM app_user;

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
FROM app_user;

INSERT INTO app_account.security_policies (key, value, description)
VALUES (
  'platform_runtime_least_privilege',
  '{"runtimeCanReadPlatformEvidence":true,"runtimeCanMutatePlatformEvidence":false,"migration":"010_platform_runtime_least_privilege"}'::jsonb,
  'Runtime database user can read platform evidence but cannot mutate migration, retention or backup/restore control tables.'
)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    description = excluded.description,
    updated_at = now();

COMMIT;
