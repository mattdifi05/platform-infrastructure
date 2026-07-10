#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
POSTGRES_IMAGE=${POSTGRES_IMAGE:-postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa}
MINIO_IMAGE=${MINIO_IMAGE:-quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e}
MINIO_MC_IMAGE=${MINIO_MC_IMAGE:-quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727}
stamp=$(date -u +%Y%m%d%H%M%S)-$$
network=t14-service-identity-$stamp
pg=t14-postgres-$stamp
pginit=t14-postgres-init-$stamp
minio=t14-minio-$stamp
work=$(mktemp -d)
chmod 700 "$work"

cleanup() {
  docker rm -f "$pg" "$pginit" "$minio" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

random_value() {
  openssl rand -base64 36 | tr -d '=+/\r\n' | cut -c1-40
}

pg_super=$(random_value)
backend_password=$(random_value)
jobs_password=$(random_value)
notifications_password=$(random_value)
legacy_password=$(random_value)
minio_root=$(random_value)
minio_access=T14$(random_value | cut -c1-16)
minio_secret=$(random_value)

docker network create "$network" >/dev/null

mkdir -p "$work/init-secrets"
for entry in \
  postgres_superuser_password:"$pg_super" \
  app_db_password:"$legacy_password" \
  keycloak_db_password:"$(random_value)" \
  backend_db_password:"$backend_password" \
  worker_jobs_db_password:"$jobs_password" \
  worker_notifications_db_password:"$notifications_password"; do
  name=${entry%%:*}
  value=${entry#*:}
  printf '%s\n' "$value" > "$work/init-secrets/$name"
  chmod 600 "$work/init-secrets/$name"
done
docker run -d --name "$pginit" --network "$network" \
  --tmpfs /var/lib/postgresql:rw,noexec,nosuid,nodev,size=512m \
  -v "$INFRA_ROOT/postgres/entrypoint-with-init-secrets.sh:/usr/local/bin/platform-postgres-entrypoint:ro" \
  -v "$INFRA_ROOT/postgres/init:/platform-postgres-init:ro" \
  -v "$work/init-secrets:/run/source-secrets:ro" \
  -e POSTGRES_PASSWORD_FILE=/run/source-secrets/postgres_superuser_password \
  -e APP_DB_NAME=app_db -e APP_DB_USER=app_user -e APP_DB_PASSWORD_FILE=/run/source-secrets/app_db_password \
  -e KEYCLOAK_DB_NAME=keycloak -e KEYCLOAK_DB_USER=keycloak -e KEYCLOAK_DB_PASSWORD_FILE=/run/source-secrets/keycloak_db_password \
  -e BACKEND_DB_USER=app_backend_runtime -e BACKEND_DB_PASSWORD_FILE=/run/source-secrets/backend_db_password \
  -e WORKER_JOBS_DB_USER=app_worker_jobs_runtime -e WORKER_JOBS_DB_PASSWORD_FILE=/run/source-secrets/worker_jobs_db_password \
  -e WORKER_NOTIFICATIONS_DB_USER=app_worker_notifications_runtime -e WORKER_NOTIFICATIONS_DB_PASSWORD_FILE=/run/source-secrets/worker_notifications_db_password \
  --entrypoint /usr/local/bin/platform-postgres-entrypoint "$POSTGRES_IMAGE" postgres >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$pginit" pg_isready -U postgres -d postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$pginit" pg_isready -U postgres -d postgres >/dev/null 2>&1 || { docker logs "$pginit" >&2; exit 1; }
[ "$(docker exec "$pginit" psql -U postgres -d postgres -X -tAc "select count(*) from pg_roles where rolname in ('app_backend_runtime','app_worker_jobs_runtime','app_worker_notifications_runtime');" | tr -d '[:space:]')" = 3 ] || { printf '%s\n' "Clean init did not create scoped PostgreSQL logins" >&2; exit 1; }
for migration in "$INFRA_ROOT"/postgres/migrations/*.sql; do
  target=/tmp/$(basename "$migration")
  docker cp "$migration" "$pginit:$target" >/dev/null
  if ! docker exec "$pginit" psql -U postgres -d app_db -X -v ON_ERROR_STOP=1 -f "$target" >/dev/null 2>>"$work/migrations.log"; then
    tail -n 80 "$work/migrations.log" >&2
    exit 1
  fi
done
[ "$(docker exec "$pginit" psql -U postgres -d app_db -X -tAc "select pg_has_role('app_backend_runtime','app_db_account_rw','member') and pg_has_role('app_worker_jobs_runtime','app_worker_jobs_rw','member') and not has_table_privilege('app_worker_jobs_runtime','app_account.accounts','select') and not has_table_privilege('app_worker_notifications_runtime','app_account.audit_outbox','select');" | tr -d '[:space:]')" = t ] || { printf '%s\n' "Clean migration sequence did not enforce scoped grants" >&2; exit 1; }
docker rm -f "$pginit" >/dev/null

docker run -d --name "$pg" --network "$network" --tmpfs /var/lib/postgresql:rw,noexec,nosuid,nodev,size=512m -e POSTGRES_PASSWORD="$pg_super" "$POSTGRES_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$pg" pg_isready -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$pg" pg_isready -U postgres >/dev/null 2>&1 || { printf '%s\n' "PostgreSQL sandbox did not become ready" >&2; exit 1; }

cat > "$work/seed.sql" <<'SQL'
CREATE ROLE app_db_account_rw NOLOGIN;
CREATE ROLE app_db_auth_rw NOLOGIN;
CREATE ROLE app_db_audit_rw NOLOGIN;
CREATE ROLE app_user LOGIN;
CREATE SCHEMA stexor_account;
CREATE SCHEMA stexor_platform;
CREATE TABLE stexor_account.accounts (id bigint PRIMARY KEY, value text);
CREATE TABLE stexor_account.sessions (id bigint PRIMARY KEY, value text);
CREATE TABLE stexor_account.audit_events (id bigint PRIMARY KEY, value text);
CREATE TABLE stexor_account.audit_outbox (id bigint PRIMARY KEY, status text NOT NULL);
CREATE TABLE stexor_account.security_policies (key text PRIMARY KEY, value jsonb NOT NULL, description text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE stexor_platform.schema_migrations (version text PRIMARY KEY);
CREATE TABLE stexor_platform.backup_restore_runs (id bigint PRIMARY KEY, status text);
GRANT USAGE ON SCHEMA stexor_account TO app_db_account_rw, app_db_auth_rw, app_db_audit_rw;
GRANT SELECT, INSERT, UPDATE ON stexor_account.accounts TO app_db_account_rw;
GRANT SELECT, INSERT, UPDATE ON stexor_account.sessions TO app_db_auth_rw;
GRANT SELECT, INSERT ON stexor_account.audit_events TO app_db_audit_rw;
GRANT SELECT, INSERT, UPDATE ON stexor_account.audit_outbox TO app_db_audit_rw;
ALTER TABLE stexor_account.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY accounts_runtime_access ON stexor_account.accounts FOR ALL TO PUBLIC USING (pg_has_role(current_user, 'app_db_account_rw', 'member')) WITH CHECK (pg_has_role(current_user, 'app_db_account_rw', 'member'));
ALTER TABLE stexor_account.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_runtime_access ON stexor_account.sessions FOR ALL TO PUBLIC USING (pg_has_role(current_user, 'app_db_auth_rw', 'member')) WITH CHECK (pg_has_role(current_user, 'app_db_auth_rw', 'member'));
ALTER TABLE stexor_account.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_runtime_access ON stexor_account.audit_events FOR SELECT TO PUBLIC USING (pg_has_role(current_user, 'app_db_audit_rw', 'member'));
CREATE POLICY audit_events_runtime_insert ON stexor_account.audit_events FOR INSERT TO PUBLIC WITH CHECK (pg_has_role(current_user, 'app_db_audit_rw', 'member'));
ALTER TABLE stexor_account.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.audit_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_outbox_runtime_access ON stexor_account.audit_outbox FOR ALL TO PUBLIC USING (pg_has_role(current_user, 'app_db_audit_rw', 'member')) WITH CHECK (pg_has_role(current_user, 'app_db_audit_rw', 'member'));
GRANT app_db_account_rw, app_db_auth_rw, app_db_audit_rw TO app_user;
GRANT ALL ON ALL TABLES IN SCHEMA stexor_account TO app_user;
INSERT INTO stexor_account.accounts VALUES (1, 'account');
INSERT INTO stexor_account.sessions VALUES (1, 'session');
INSERT INTO stexor_account.audit_events VALUES (1, 'audit');
INSERT INTO stexor_account.audit_outbox VALUES (1, 'queued');
INSERT INTO stexor_platform.schema_migrations VALUES ('001');
INSERT INTO stexor_platform.backup_restore_runs VALUES (1, 'success');
SQL
docker cp "$work/seed.sql" "$pg:/tmp/seed.sql" >/dev/null
docker exec "$pg" psql -U postgres -d postgres -X -v ON_ERROR_STOP=1 -f /tmp/seed.sql >/dev/null
docker cp "$INFRA_ROOT/postgres/migrations/014_service_identity_grants.sql" "$pg:/tmp/014.sql" >/dev/null
docker exec "$pg" psql -U postgres -d postgres -X -v ON_ERROR_STOP=1 -f /tmp/014.sql >/dev/null

{
  printf "ALTER ROLE app_backend_runtime PASSWORD '%s';\n" "$backend_password"
  printf "ALTER ROLE app_worker_jobs_runtime PASSWORD '%s';\n" "$jobs_password"
  printf "ALTER ROLE app_worker_notifications_runtime PASSWORD '%s';\n" "$notifications_password"
  printf "ALTER ROLE app_user PASSWORD '%s';\n" "$legacy_password"
} | docker exec -i "$pg" psql -U postgres -d postgres -X -v ON_ERROR_STOP=1 >/dev/null

set_pgpass() {
  local name=$1 value=$2
  printf '127.0.0.1:5432:postgres:%s:%s\n' "$name" "$value" | docker exec -i "$pg" sh -c "umask 077; cat > /tmp/pgpass-$name"
}
set_pgpass app_backend_runtime "$backend_password"
set_pgpass app_worker_jobs_runtime "$jobs_password"
set_pgpass app_worker_notifications_runtime "$notifications_password"
set_pgpass app_user "$legacy_password"

query_as() {
  local role=$1 sql=$2
  docker exec -e PGPASSFILE="/tmp/pgpass-$role" "$pg" psql -h 127.0.0.1 -U "$role" -d postgres -X -v ON_ERROR_STOP=1 -tAc "$sql" >/dev/null
}

expect_denied() {
  local role=$1 sql=$2
  if query_as "$role" "$sql" 2>/dev/null; then
    printf 'Expected denial for %s\n' "$role" >&2
    exit 1
  fi
}

query_as app_backend_runtime "select count(*) from stexor_account.accounts; select count(*) from stexor_account.sessions; select count(*) from stexor_account.audit_events; select count(*) from stexor_platform.schema_migrations;"
expect_denied app_backend_runtime "delete from stexor_account.accounts where id = -1"
expect_denied app_backend_runtime "update stexor_platform.schema_migrations set version = version"
query_as app_worker_jobs_runtime "update stexor_account.audit_outbox set status = 'processing' where id = 1; select count(*) from stexor_platform.backup_restore_runs;"
expect_denied app_worker_jobs_runtime "select count(*) from stexor_account.accounts"
expect_denied app_worker_jobs_runtime "select count(*) from stexor_account.audit_events"
expect_denied app_worker_jobs_runtime "insert into stexor_account.audit_outbox values (2, 'queued')"
expect_denied app_worker_jobs_runtime "update stexor_platform.backup_restore_runs set status = 'failed'"
query_as app_worker_notifications_runtime "select 1"
expect_denied app_worker_notifications_runtime "select count(*) from stexor_account.audit_outbox"
expect_denied app_worker_notifications_runtime "select count(*) from stexor_platform.backup_restore_runs"

docker cp "$INFRA_ROOT/postgres/rollout/service-identity-legacy-revoke.sql" "$pg:/tmp/revoke.sql" >/dev/null
docker exec "$pg" psql -U postgres -d postgres -X -v ON_ERROR_STOP=1 -f /tmp/revoke.sql >/dev/null
if query_as app_user "select 1" 2>/dev/null; then
  printf '%s\n' "Legacy app_user still accepts logins after revoke" >&2
  exit 1
fi
query_as app_backend_runtime "select count(*) from stexor_account.accounts"
query_as app_worker_jobs_runtime "select count(*) from stexor_account.audit_outbox"

docker run -d --name "$minio" --network "$network" --tmpfs /data:rw,noexec,nosuid,nodev,size=256m -e MINIO_ROOT_USER=minio_admin -e MINIO_ROOT_PASSWORD="$minio_root" "$MINIO_IMAGE" server /data --address :9000 >/dev/null
for _ in $(seq 1 60); do
  if docker run --rm --network "$network" "$MINIO_MC_IMAGE" alias set root "http://$minio:9000" minio_admin "$minio_root" >/dev/null 2>&1; then break; fi
  sleep 1
done
docker run --rm --network "$network" --entrypoint /bin/sh "$MINIO_MC_IMAGE" -ec "mc alias set root http://$minio:9000 minio_admin '$minio_root' >/dev/null; mc mb root/t14-bucket root/t14-other >/dev/null"
printf '%s\n' "$minio_root" > "$work/minio-root"
printf '%s\n' "$minio_access" > "$work/minio-access"
printf '%s\n' "$minio_secret" > "$work/minio-secret"
chmod 600 "$work/minio-root" "$work/minio-access" "$work/minio-secret"

run_minio_identity() {
  docker run --rm --network "$network" \
    --entrypoint /bin/sh \
    -v "$INFRA_ROOT/scripts/minio-service-identity.sh:/usr/local/bin/minio-service-identity:ro" \
    -v "$work/minio-root:/run/secrets/minio_root_password:ro" \
    -v "$work/minio-access:/run/secrets/minio_service_access_key:ro" \
    -v "$work/minio-secret:/run/secrets/minio_service_secret_key:ro" \
    -e MINIO_ENDPOINT="http://$minio:9000" -e MINIO_ROOT_USER=minio_admin \
    -e MINIO_BUCKET=t14-bucket -e MINIO_PREFIX=app-one/ -e MINIO_DENY_TEST_BUCKET=t14-other \
    "$@" "$MINIO_MC_IMAGE" /usr/local/bin/minio-service-identity
}
run_minio_identity -e MODE=apply -e CONFIRM=APPLY-MINIO-SERVICE-IDENTITY
run_minio_identity -e MODE=verify -e MINIO_VERIFY_WRITE=1
run_minio_identity -e MODE=revoke -e CONFIRM=REVOKE-MINIO-SERVICE-IDENTITY
if run_minio_identity -e MODE=verify >/dev/null 2>&1; then
  printf '%s\n' "Revoked MinIO service account still authenticates" >&2
  exit 1
fi

unset pg_super backend_password jobs_password notifications_password legacy_password minio_root minio_access minio_secret
printf '%s\n' "Service identity sandbox passed clean init, full migrations, PostgreSQL positive/negative grants, legacy revoke, MinIO prefix isolation, cross-bucket denial and admin denial."
