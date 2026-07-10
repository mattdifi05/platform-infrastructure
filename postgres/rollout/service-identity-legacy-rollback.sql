BEGIN;

DO $migration$
DECLARE
  account_schema text;
  ops_schema text;
BEGIN
  account_schema := CASE WHEN to_regnamespace('stexor_account') IS NOT NULL THEN 'stexor_account' ELSE 'app_account' END;
  ops_schema := CASE WHEN to_regnamespace('stexor_platform') IS NOT NULL THEN 'stexor_platform' ELSE 'platform_ops' END;

  IF to_regnamespace(account_schema) IS NULL OR to_regnamespace(ops_schema) IS NULL THEN
    RAISE EXCEPTION 'Expected account and operations schemas are missing';
  END IF;

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO app_user', current_database());
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO app_user', ops_schema);
  EXECUTE format('GRANT SELECT ON %I.schema_migrations, %I.data_retention_policies, %I.backup_restore_runs TO app_user', ops_schema, ops_schema, ops_schema);
  EXECUTE format(
    'INSERT INTO %I.security_policies (key, value, description) VALUES ($1, $2::jsonb, $3) ON CONFLICT (key) DO UPDATE SET value = excluded.value, description = excluded.description, updated_at = now()',
    account_schema
  ) USING
    'service_identity_least_privilege',
    '{"legacyRevoked":false,"rollbackActive":true,"tenancyBoundary":"service-role-not-account-rls"}',
    'Emergency rollback re-enabled the bounded legacy capability memberships; broad direct grants remain revoked.';
END
$migration$;

ALTER ROLE app_user LOGIN;
GRANT app_db_account_rw, app_db_auth_rw, app_db_audit_rw TO app_user;

COMMIT;
