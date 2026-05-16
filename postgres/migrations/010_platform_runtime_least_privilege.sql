\connect stexor_app

BEGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA stexor_platform FROM stexor_app_user;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA stexor_platform FROM stexor_app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_platform REVOKE ALL ON TABLES FROM stexor_app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA stexor_platform REVOKE ALL ON SEQUENCES FROM stexor_app_user;

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
FROM stexor_app_user, stexor_console_readonly;

INSERT INTO stexor_account.security_policies (key, value, description)
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
