#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MODE=plan
CONTAINER=${POSTGRES_CONTAINER:-enterprise-postgres}
DATABASE=${APP_DB_NAME:-app_db}
RECOVERY_EVIDENCE=
CUTOVER_EVIDENCE=
CONFIRM=${CONFIRM:-}
SECRETS_DIR=${SECRETS_DIR:-$INFRA_ROOT/secrets}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE=${2:?missing mode}; shift 2 ;;
    --container) CONTAINER=${2:?missing container}; shift 2 ;;
    --database) DATABASE=${2:?missing database}; shift 2 ;;
    --recovery-evidence) RECOVERY_EVIDENCE=${2:?missing recovery evidence}; shift 2 ;;
    --cutover-evidence) CUTOVER_EVIDENCE=${2:?missing cutover evidence}; shift 2 ;;
    --secrets-dir) SECRETS_DIR=${2:?missing secrets dir}; shift 2 ;;
    --confirm) CONFIRM=${2:?missing confirmation}; shift 2 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

require_file() {
  [ -s "$1" ] || fail "Required evidence or secret file is missing"
}

psql_value() {
  docker exec "$CONTAINER" psql -U postgres -d "$DATABASE" -X -v ON_ERROR_STOP=1 -tAc "$1" | tr -d '[:space:]'
}

apply_sql() {
  local source=$1
  local target="/tmp/$(basename "$source").$$"
  docker cp "$source" "$CONTAINER:$target" >/dev/null
  if ! docker exec "$CONTAINER" psql -U postgres -d "$DATABASE" -X -v ON_ERROR_STOP=1 -f "$target" >/dev/null; then
    docker exec "$CONTAINER" rm -f "$target" >/dev/null 2>&1 || true
    return 1
  fi
  docker exec "$CONTAINER" rm -f "$target" >/dev/null
}

secret_line() {
  local file=$1
  require_file "$file"
  local value
  value=$(tr -d '\r\n' < "$file")
  printf '%s' "$value" | grep -Eq '^[A-Za-z0-9_-]{32,}$' || fail "Database password files must contain one generated base64url value"
  printf '%s' "$value"
}

prepare_passwords() {
  local backend jobs notifications
  backend=$(secret_line "$SECRETS_DIR/backend_db_password.txt")
  jobs=$(secret_line "$SECRETS_DIR/worker_jobs_db_password.txt")
  notifications=$(secret_line "$SECRETS_DIR/worker_notifications_db_password.txt")
  [ "$backend" != "$jobs" ] && [ "$backend" != "$notifications" ] && [ "$jobs" != "$notifications" ] || fail "Scoped database passwords must be distinct"
  {
    printf "ALTER ROLE app_backend_runtime PASSWORD '%s';\n" "$backend"
    printf "ALTER ROLE app_worker_jobs_runtime PASSWORD '%s';\n" "$jobs"
    printf "ALTER ROLE app_worker_notifications_runtime PASSWORD '%s';\n" "$notifications"
  } | docker exec -i "$CONTAINER" psql -U postgres -d "$DATABASE" -X -v ON_ERROR_STOP=1 >/dev/null
  unset backend jobs notifications
}

verify_grants() {
  [ "$(psql_value "select count(*) = 3 from pg_auth_members membership join pg_roles member_role on member_role.oid = membership.member join pg_roles granted_role on granted_role.oid = membership.roleid where member_role.rolname = 'app_backend_runtime' and granted_role.rolname in ('app_db_account_rw','app_db_auth_rw','app_db_audit_rw');")" = t ] || fail "Backend capability memberships are incomplete"
  [ "$(psql_value "select pg_has_role('app_worker_jobs_runtime','app_worker_jobs_rw','member');")" = t ] || fail "Jobs worker role membership is missing"
  [ "$(psql_value "select not pg_has_role('app_worker_jobs_runtime','app_db_account_rw','member') and not pg_has_role('app_worker_jobs_runtime','app_db_auth_rw','member') and not pg_has_role('app_worker_jobs_runtime','app_db_audit_rw','member');")" = t ] || fail "Jobs worker inherits a broad application capability"
  [ "$(psql_value "select not pg_has_role('app_worker_notifications_runtime','app_db_account_rw','member') and not pg_has_role('app_worker_notifications_runtime','app_db_auth_rw','member') and not pg_has_role('app_worker_notifications_runtime','app_db_audit_rw','member') and not pg_has_role('app_worker_notifications_runtime','app_worker_jobs_rw','member');")" = t ] || fail "Notification worker inherits a database capability"
  [ "$(psql_value "select not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication and not rolbypassrls from pg_roles where rolname = 'app_backend_runtime';")" = t ] || fail "Backend login has administrative PostgreSQL attributes"
  [ "$(psql_value "select not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication and not rolbypassrls from pg_roles where rolname = 'app_worker_jobs_runtime';")" = t ] || fail "Jobs login has administrative PostgreSQL attributes"
  [ "$(psql_value "select not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication and not rolbypassrls from pg_roles where rolname = 'app_worker_notifications_runtime';")" = t ] || fail "Notifications login has administrative PostgreSQL attributes"
}

case "$MODE" in
  plan)
    printf '%s\n' "Plan only: apply migration 014, materialize three distinct credentials, cut over backend/jobs/notifications, verify, then explicitly revoke app_user."
    printf '%s\n' "No database, secret or container was changed."
    ;;
  prepare)
    [ "$CONFIRM" = PREPARE-SERVICE-IDENTITIES ] || fail "Use --confirm PREPARE-SERVICE-IDENTITIES"
    require_file "$RECOVERY_EVIDENCE"
    [ "$(psql_value "select count(*) = 3 from pg_roles where rolname in ('app_backend_runtime','app_worker_jobs_runtime','app_worker_notifications_runtime');")" = t ] || fail "Apply migration 014 before preparing credentials"
    prepare_passwords
    verify_grants
    printf '%s\n' "Scoped database identities prepared; legacy app_user remains enabled for dual-credential cutover."
    ;;
  verify)
    verify_grants
    printf '%s\n' "Scoped database role and grant policy verified."
    ;;
  revoke)
    [ "$CONFIRM" = REVOKE-LEGACY-APP-USER ] || fail "Use --confirm REVOKE-LEGACY-APP-USER"
    require_file "$RECOVERY_EVIDENCE"
    require_file "$CUTOVER_EVIDENCE"
    verify_grants
    apply_sql "$INFRA_ROOT/postgres/rollout/service-identity-legacy-revoke.sql"
    [ "$(psql_value "select not rolcanlogin from pg_roles where rolname = 'app_user';")" = t ] || fail "Legacy app_user was not disabled"
    printf '%s\n' "Legacy app_user disabled after explicit cutover evidence."
    ;;
  rollback)
    [ "$CONFIRM" = ROLLBACK-LEGACY-APP-USER ] || fail "Use --confirm ROLLBACK-LEGACY-APP-USER"
    apply_sql "$INFRA_ROOT/postgres/rollout/service-identity-legacy-rollback.sql"
    [ "$(psql_value "select rolcanlogin from pg_roles where rolname = 'app_user';")" = t ] || fail "Legacy app_user rollback failed"
    printf '%s\n' "Bounded legacy capability memberships restored; direct broad grants were not restored."
    ;;
  *) fail "Mode must be plan, prepare, verify, revoke or rollback" ;;
esac
