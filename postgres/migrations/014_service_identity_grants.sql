BEGIN;

DO $migration$
DECLARE
  account_schema text;
  ops_schema text;
BEGIN
  account_schema := CASE
    WHEN to_regnamespace('stexor_account') IS NOT NULL THEN 'stexor_account'
    WHEN to_regnamespace('app_account') IS NOT NULL THEN 'app_account'
    ELSE NULL
  END;
  ops_schema := CASE
    WHEN to_regnamespace('stexor_platform') IS NOT NULL THEN 'stexor_platform'
    WHEN to_regnamespace('platform_ops') IS NOT NULL THEN 'platform_ops'
    ELSE NULL
  END;

  IF account_schema IS NULL OR ops_schema IS NULL THEN
    RAISE EXCEPTION 'Expected account and operations schemas are missing';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_backend_runtime') THEN
    EXECUTE 'CREATE ROLE app_backend_runtime LOGIN';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_worker_jobs_rw') THEN
    EXECUTE 'CREATE ROLE app_worker_jobs_rw NOLOGIN';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_worker_jobs_runtime') THEN
    EXECUTE 'CREATE ROLE app_worker_jobs_runtime LOGIN';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_worker_notifications_runtime') THEN
    EXECUTE 'CREATE ROLE app_worker_notifications_runtime LOGIN';
  END IF;

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO app_backend_runtime, app_worker_jobs_runtime, app_worker_notifications_runtime', current_database());

  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM app_worker_jobs_rw, app_worker_jobs_runtime, app_worker_notifications_runtime', account_schema);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM app_worker_jobs_rw, app_worker_jobs_runtime, app_worker_notifications_runtime', account_schema);
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM app_worker_jobs_rw, app_worker_jobs_runtime, app_worker_notifications_runtime', ops_schema);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM app_worker_jobs_rw, app_worker_jobs_runtime, app_worker_notifications_runtime', ops_schema);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON TABLES FROM app_db_account_rw, app_db_auth_rw, app_db_audit_rw, app_worker_jobs_rw', account_schema);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON SEQUENCES FROM app_db_account_rw, app_db_auth_rw, app_db_audit_rw, app_worker_jobs_rw', account_schema);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON TABLES FROM app_backend_runtime, app_worker_jobs_runtime, app_worker_notifications_runtime', ops_schema);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON SEQUENCES FROM app_backend_runtime, app_worker_jobs_runtime, app_worker_notifications_runtime', ops_schema);

  EXECUTE format('GRANT USAGE ON SCHEMA %I TO app_worker_jobs_rw', account_schema);
  EXECUTE format('GRANT SELECT, UPDATE ON %I.audit_outbox TO app_worker_jobs_rw', account_schema);
  EXECUTE format('REVOKE INSERT, DELETE, TRUNCATE, REFERENCES, TRIGGER ON %I.audit_outbox FROM app_worker_jobs_rw', account_schema);
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO app_worker_jobs_rw', ops_schema);
  EXECUTE format('GRANT SELECT ON %I.backup_restore_runs TO app_worker_jobs_rw', ops_schema);
  EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON %I.backup_restore_runs FROM app_worker_jobs_rw', ops_schema);

  EXECUTE format('GRANT USAGE ON SCHEMA %I TO app_backend_runtime', ops_schema);
  EXECUTE format('GRANT SELECT ON %I.schema_migrations TO app_backend_runtime', ops_schema);
  EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON %I.schema_migrations FROM app_backend_runtime', ops_schema);

  EXECUTE format('DROP POLICY IF EXISTS audit_outbox_runtime_access ON %I.audit_outbox', account_schema);
  EXECUTE format(
    'CREATE POLICY audit_outbox_runtime_access ON %I.audit_outbox FOR ALL TO PUBLIC USING (pg_has_role(current_user, ''app_db_audit_rw'', ''member'') OR pg_has_role(current_user, ''app_worker_jobs_rw'', ''member'')) WITH CHECK (pg_has_role(current_user, ''app_db_audit_rw'', ''member'') OR pg_has_role(current_user, ''app_worker_jobs_rw'', ''member''))',
    account_schema
  );

  EXECUTE format(
    'INSERT INTO %I.security_policies (key, value, description) VALUES ($1, $2::jsonb, $3) ON CONFLICT (key) DO UPDATE SET value = excluded.value, description = excluded.description, updated_at = now()',
    account_schema
  ) USING
    'service_identity_least_privilege',
    '{"backend":"app_backend_runtime","jobs":"app_worker_jobs_runtime","notifications":"app_worker_notifications_runtime","jobsTables":["audit_outbox","backup_restore_runs"],"legacyRevoked":false,"tenancyBoundary":"service-role-not-account-rls"}',
    'Per-service runtime identities are granted before cutover. Account-level RLS is defense in depth, not a supported tenant boundary.';
END
$migration$;

ALTER ROLE app_backend_runtime WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE app_worker_jobs_rw WITH NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE app_worker_jobs_runtime WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE app_worker_notifications_runtime WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

ALTER ROLE app_backend_runtime SET search_path = pg_catalog;
ALTER ROLE app_backend_runtime SET statement_timeout = '5s';
ALTER ROLE app_backend_runtime SET idle_in_transaction_session_timeout = '15s';
ALTER ROLE app_worker_jobs_runtime SET search_path = pg_catalog;
ALTER ROLE app_worker_jobs_runtime SET statement_timeout = '5s';
ALTER ROLE app_worker_jobs_runtime SET idle_in_transaction_session_timeout = '15s';
ALTER ROLE app_worker_notifications_runtime SET search_path = pg_catalog;
ALTER ROLE app_worker_notifications_runtime SET statement_timeout = '5s';
ALTER ROLE app_worker_notifications_runtime SET idle_in_transaction_session_timeout = '15s';

GRANT app_db_account_rw, app_db_auth_rw, app_db_audit_rw TO app_backend_runtime;
GRANT app_worker_jobs_rw TO app_worker_jobs_runtime;

DO $revoke_unexpected_memberships$
DECLARE
  member_name text;
  granted_name text;
BEGIN
  FOREACH member_name IN ARRAY ARRAY['app_worker_jobs_runtime', 'app_worker_notifications_runtime'] LOOP
    FOREACH granted_name IN ARRAY ARRAY['app_db_account_rw', 'app_db_auth_rw', 'app_db_audit_rw'] LOOP
      IF EXISTS (
        SELECT 1
        FROM pg_auth_members membership
        JOIN pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
        WHERE member_role.rolname = member_name AND granted_role.rolname = granted_name
      ) THEN
        EXECUTE format('REVOKE %I FROM %I', granted_name, member_name);
      END IF;
    END LOOP;
  END LOOP;
  FOREACH member_name IN ARRAY ARRAY['app_backend_runtime', 'app_worker_notifications_runtime'] LOOP
    IF EXISTS (
      SELECT 1
      FROM pg_auth_members membership
      JOIN pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
      WHERE member_role.rolname = member_name AND granted_role.rolname = 'app_worker_jobs_rw'
    ) THEN
      EXECUTE format('REVOKE app_worker_jobs_rw FROM %I', member_name);
    END IF;
  END LOOP;
END
$revoke_unexpected_memberships$;

COMMIT;
