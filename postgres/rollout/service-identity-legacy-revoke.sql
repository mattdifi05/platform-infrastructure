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
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    RAISE EXCEPTION 'Legacy app_user role is missing';
  END IF;

  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM app_user', account_schema);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM app_user', account_schema);
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM app_user', ops_schema);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM app_user', ops_schema);
  EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM app_user', account_schema);
  EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM app_user', ops_schema);

  EXECUTE format(
    'INSERT INTO %I.security_policies (key, value, description) VALUES ($1, $2::jsonb, $3) ON CONFLICT (key) DO UPDATE SET value = excluded.value, description = excluded.description, updated_at = now()',
    account_schema
  ) USING
    'service_identity_least_privilege',
    '{"backend":"app_backend_runtime","jobs":"app_worker_jobs_runtime","notifications":"app_worker_notifications_runtime","jobsTables":["audit_outbox","backup_restore_runs"],"legacyRevoked":true,"tenancyBoundary":"service-role-not-account-rls"}',
    'Dedicated service identities are active and the legacy union login is disabled.';
END
$migration$;

DO $revoke_legacy_memberships$
DECLARE
  granted_name text;
BEGIN
  FOREACH granted_name IN ARRAY ARRAY['app_db_account_rw', 'app_db_auth_rw', 'app_db_audit_rw', 'app_worker_jobs_rw'] LOOP
    IF EXISTS (
      SELECT 1
      FROM pg_auth_members membership
      JOIN pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
      WHERE member_role.rolname = 'app_user' AND granted_role.rolname = granted_name
    ) THEN
      EXECUTE format('REVOKE %I FROM app_user', granted_name);
    END IF;
  END LOOP;
END
$revoke_legacy_memberships$;
ALTER ROLE app_user NOLOGIN;

COMMIT;
