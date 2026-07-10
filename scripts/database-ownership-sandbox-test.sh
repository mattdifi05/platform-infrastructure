#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUN_ID="t04-db-ownership-$$"
NETWORK="$RUN_ID"
POSTGRES_CONTAINER="$RUN_ID-postgres"
MARIADB_CONTAINER="$RUN_ID-mariadb"
CONTROL_CONTAINER="$RUN_ID-control"
CONTROL_IMAGE="platform/control-center:$RUN_ID"
WORK_DIR=$(mktemp -d "/tmp/$RUN_ID.XXXXXX")
POSTGRES_IMAGE=${POSTGRES_IMAGE:-postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa}
MARIADB_IMAGE=${MARIADB_IMAGE:-mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b}
NODE_IMAGE=${NODE_IMAGE:-node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606}
POSTGRES_PASSWORD="t04-postgres-root-fixture"
MARIADB_PASSWORD="t04-mariadb-root-fixture"
CREATE_PASSWORD="t04-managed-create-fixture"
ROTATE_PASSWORD="t04-managed-rotate-fixture"
ATTEMPT_PASSWORD="t04-foreign-attempt-fixture"

cleanup() {
  docker rm -f "$CONTROL_CONTAINER" "$POSTGRES_CONTAINER" "$MARIADB_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker image rm "$CONTROL_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

for command in docker jq; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 127; }
done

mkdir -p "$WORK_DIR/projects/node-demo" "$WORK_DIR/state" "$WORK_DIR/secrets"
printf '%s\n' '{"name":"node-demo","private":true}' > "$WORK_DIR/projects/node-demo/package.json"
printf '%s\n' "$POSTGRES_PASSWORD" > "$WORK_DIR/secrets/postgres_superuser_password"
printf '%s\n' "$MARIADB_PASSWORD" > "$WORK_DIR/secrets/mariadb_root_password"
printf '%s\n' "v20260710000000=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" > "$WORK_DIR/secrets/vault.keys"
chmod 600 "$WORK_DIR/secrets"/*

docker network create "$NETWORK" >/dev/null
docker run -d --rm --name "$POSTGRES_CONTAINER" --network "$NETWORK" \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  "$POSTGRES_IMAGE" >/dev/null
docker run -d --rm --name "$MARIADB_CONTAINER" --network "$NETWORK" \
  -e MARIADB_ROOT_PASSWORD="$MARIADB_PASSWORD" \
  "$MARIADB_IMAGE" >/dev/null

wait_for_database() {
  container="$1"
  shift
  attempts=0
  until docker exec "$container" "$@" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 60 ] || { echo "$container did not become ready" >&2; exit 1; }
    sleep 1
  done
}

wait_for_database "$POSTGRES_CONTAINER" pg_isready -U postgres
wait_for_database "$MARIADB_CONTAINER" mariadb-admin -h 127.0.0.1 -uroot "-p$MARIADB_PASSWORD" ping --silent

docker build \
  --no-cache \
  --build-arg "NODE_IMAGE=$NODE_IMAGE" \
  -f "$ROOT/docker/control-center.Dockerfile" \
  -t "$CONTROL_IMAGE" \
  "$ROOT" >/dev/null

principal_for() {
  engine="$1"
  database="$2"
  docker run --rm --entrypoint node "$CONTROL_IMAGE" --input-type=module -e \
    "import { generatedDatabasePrincipal } from './database/ownership.mjs'; process.stdout.write(generatedDatabasePrincipal({projectId:'node-demo',engine:'$engine',databaseName:'$database'}));"
}

MARIADB_COLLISION_DB="node_demo_maria_collision"
POSTGRES_COLLISION_DB="node_demo_pg_collision"
MARIADB_COLLISION_PRINCIPAL=$(principal_for mariadb "$MARIADB_COLLISION_DB")
POSTGRES_COLLISION_PRINCIPAL=$(principal_for postgres "$POSTGRES_COLLISION_DB")

docker exec "$MARIADB_CONTAINER" mariadb -h 127.0.0.1 -uroot "-p$MARIADB_PASSWORD" -e \
  "CREATE USER '$MARIADB_COLLISION_PRINCIPAL'@'%' IDENTIFIED BY 'original-fixture'; GRANT SELECT ON *.* TO '$MARIADB_COLLISION_PRINCIPAL'@'%';"
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" psql -U postgres -v ON_ERROR_STOP=1 -q -c \
  "CREATE ROLE \"$POSTGRES_COLLISION_PRINCIPAL\" LOGIN PASSWORD 'original-fixture' CREATEROLE;"

docker run -d --name "$CONTROL_CONTAINER" --network "$NETWORK" \
  --user "$(id -u):$(id -g)" \
  -e NODE_ENV=test \
  -e CONTROL_CENTER_PORT=8080 \
  -e CONTROL_CENTER_BIND_HOST=127.0.0.1 \
  -e CONTROL_CENTER_ENV=local \
  -e CONTROL_CENTER_AUTH_MODE=test-disabled \
  -e CONTROL_CENTER_DATABASE_LIVE_APPLY=true \
  -e CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS=true \
  -e CONTROL_CENTER_DOCS_ROOT=/var/www/infra-docs \
  -e PROJECTS_ROOT=/var/www/projects \
  -e PROJECT_DATABASES_FILE=/var/www/project-state/databases.json \
  -e PROJECT_DATABASE_PRINCIPALS_FILE=/var/www/project-state/database-principals.json \
  -e PROJECT_VAULT_FILE=/var/www/project-state/secret-vault.json \
  -e CONTROL_CENTER_VAULT_KEY_FILE=/run/secrets/vault.keys \
  -e CONTROL_CENTER_MARIADB_HOST="$MARIADB_CONTAINER" \
  -e CONTROL_CENTER_MARIADB_ROOT_USER=root \
  -e CONTROL_CENTER_MARIADB_ROOT_PASSWORD_FILE=/run/secrets/mariadb_root_password \
  -e CONTROL_CENTER_POSTGRES_HOST="$POSTGRES_CONTAINER" \
  -e CONTROL_CENTER_POSTGRES_SUPERUSER=postgres \
  -e CONTROL_CENTER_POSTGRES_SUPERUSER_PASSWORD_FILE=/run/secrets/postgres_superuser_password \
  -e CONTROL_CENTER_HOST=portal.localhost.com \
  -e DOCS_HOST=docs.localhost.com \
  -e PROJECT_HOST_SUFFIX=.localhost.com \
  -v "$ROOT:/var/www/infra-docs:ro" \
  -v "$WORK_DIR/projects:/var/www/projects:ro" \
  -v "$WORK_DIR/state:/var/www/project-state" \
  -v "$WORK_DIR/secrets/postgres_superuser_password:/run/secrets/postgres_superuser_password:ro" \
  -v "$WORK_DIR/secrets/mariadb_root_password:/run/secrets/mariadb_root_password:ro" \
  -v "$WORK_DIR/secrets/vault.keys:/run/secrets/vault.keys:ro" \
  "$CONTROL_IMAGE" node server.mjs >/dev/null

BASE_URL="http://127.0.0.1:8080"
attempts=0
until docker exec "$CONTROL_CONTAINER" node -e "fetch('$BASE_URL/__health').then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))" >/dev/null 2>&1; do
  attempts=$((attempts + 1))
  [ "$attempts" -lt 60 ] || { docker logs "$CONTROL_CONTAINER" >&2; exit 1; }
  sleep 1
done

post_json() {
  route="$1"
  body="$2"
  expected="$3"
  response=$(docker exec -e REQUEST_URL="$BASE_URL$route" -e REQUEST_BODY="$body" "$CONTROL_CONTAINER" node --input-type=module -e \
    'const response = await fetch(process.env.REQUEST_URL, { method: "POST", headers: { "content-type": "application/json" }, body: process.env.REQUEST_BODY }); const body = await response.text(); process.stdout.write(JSON.stringify({ status: response.status, body }));')
  status=$(printf '%s' "$response" | jq -r '.status')
  printf '%s' "$response" | jq -r '.body' > "$WORK_DIR/response.json"
  [ "$status" = "$expected" ] || { cat "$WORK_DIR/response.json" >&2; echo "expected HTTP $expected, got $status" >&2; exit 1; }
}

create_payload() {
  engine="$1"
  database="$2"
  password="$3"
  jq -nc --arg engine "$engine" --arg name "$database" --arg password "$password" \
    '{projectId:"node-demo",engine:$engine,name:$name,password:$password,confirm:"CREATE-DATABASE"}'
}

post_json /control/databases "$(create_payload mariadb "$MARIADB_COLLISION_DB" "$ATTEMPT_PASSWORD")" 409
post_json /control/databases "$(create_payload postgres "$POSTGRES_COLLISION_DB" "$ATTEMPT_PASSWORD")" 409

docker exec "$MARIADB_CONTAINER" mariadb -h 127.0.0.1 -uroot "-p$MARIADB_PASSWORD" --batch --skip-column-names -e \
  "SHOW GRANTS FOR '$MARIADB_COLLISION_PRINCIPAL'@'%';" | grep -q 'SELECT ON \*\.\*'
docker exec "$MARIADB_CONTAINER" mariadb -h 127.0.0.1 -uroot "-p$MARIADB_PASSWORD" --batch --skip-column-names -e \
  "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='$MARIADB_COLLISION_DB';" | grep -qx 0
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" psql -U postgres -Atq -c \
  "SELECT rolcreaterole::text FROM pg_roles WHERE rolname='$POSTGRES_COLLISION_PRINCIPAL';" | grep -qx true
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" psql -U postgres -Atq -c \
  "SELECT COUNT(*) FROM pg_database WHERE datname='$POSTGRES_COLLISION_DB';" | grep -qx 0

MARIADB_DB="node_demo_maria_managed"
POSTGRES_DB="node_demo_pg_managed"
MARIADB_PRINCIPAL=$(principal_for mariadb "$MARIADB_DB")
POSTGRES_PRINCIPAL=$(principal_for postgres "$POSTGRES_DB")

post_json /control/databases "$(create_payload mariadb "$MARIADB_DB" "$CREATE_PASSWORD")" 202
MARIADB_ID=$(jq -r '.database.id' "$WORK_DIR/response.json")
post_json /control/databases "$(create_payload postgres "$POSTGRES_DB" "$CREATE_PASSWORD")" 202
POSTGRES_ID=$(jq -r '.database.id' "$WORK_DIR/response.json")

jq -e --arg id "$MARIADB_ID" --arg principal "$MARIADB_PRINCIPAL" '.bindings[$id].status == "active" and .bindings[$id].principalName == $principal' "$WORK_DIR/state/database-principals.json" >/dev/null
jq -e --arg id "$POSTGRES_ID" --arg principal "$POSTGRES_PRINCIPAL" '.bindings[$id].status == "active" and .bindings[$id].principalName == $principal' "$WORK_DIR/state/database-principals.json" >/dev/null

docker exec -e MYSQL_PWD="$CREATE_PASSWORD" "$MARIADB_CONTAINER" mariadb -h 127.0.0.1 -u "$MARIADB_PRINCIPAL" "$MARIADB_DB" -e 'SELECT 1' >/dev/null
docker exec -e PGPASSWORD="$CREATE_PASSWORD" "$POSTGRES_CONTAINER" psql -h 127.0.0.1 -U "$POSTGRES_PRINCIPAL" -d "$POSTGRES_DB" -Atq -c 'SELECT 1' | grep -qx 1

rotate_payload() {
  database_id="$1"
  password="$2"
  jq -nc --arg id "$database_id" --arg password "$password" \
    '{action:"credential",id:$id,projectId:"node-demo",password:$password,confirm:("ROTATE-DATABASE-CREDENTIAL:" + $id)}'
}

post_json /actions/database-command "$(rotate_payload "$MARIADB_ID" "$ROTATE_PASSWORD")" 202
post_json /actions/database-command "$(rotate_payload "$POSTGRES_ID" "$ROTATE_PASSWORD")" 202
docker exec -e MYSQL_PWD="$ROTATE_PASSWORD" "$MARIADB_CONTAINER" mariadb -h 127.0.0.1 -u "$MARIADB_PRINCIPAL" "$MARIADB_DB" -e 'SELECT 1' >/dev/null
docker exec -e PGPASSWORD="$ROTATE_PASSWORD" "$POSTGRES_CONTAINER" psql -h 127.0.0.1 -U "$POSTGRES_PRINCIPAL" -d "$POSTGRES_DB" -Atq -c 'SELECT 1' | grep -qx 1

cp "$WORK_DIR/state/database-principals.json" "$WORK_DIR/state/database-principals.good.json"
jq --arg id "$MARIADB_ID" '.bindings[$id].projectId = "foreign-app"' "$WORK_DIR/state/database-principals.json" > "$WORK_DIR/state/database-principals.tmp"
mv "$WORK_DIR/state/database-principals.tmp" "$WORK_DIR/state/database-principals.json"
post_json /actions/database-command "$(rotate_payload "$MARIADB_ID" "$ATTEMPT_PASSWORD")" 409
docker exec -e MYSQL_PWD="$ROTATE_PASSWORD" "$MARIADB_CONTAINER" mariadb -h 127.0.0.1 -u "$MARIADB_PRINCIPAL" "$MARIADB_DB" -e 'SELECT 1' >/dev/null
if docker exec -e MYSQL_PWD="$ATTEMPT_PASSWORD" "$MARIADB_CONTAINER" mariadb -h 127.0.0.1 -u "$MARIADB_PRINCIPAL" "$MARIADB_DB" -e 'SELECT 1' >/dev/null 2>&1; then
  echo "foreign ownership rotation unexpectedly changed the credential" >&2
  exit 1
fi

grep -q '"action":"database.create.apply"' "$WORK_DIR/state/audit.jsonl"
grep -q '"action":"database.credential.update.apply"' "$WORK_DIR/state/audit.jsonl"
if grep -E -q 't04-(managed|foreign|postgres|mariadb).*-fixture' "$WORK_DIR/state/databases.json" "$WORK_DIR/state/database-principals.json" "$WORK_DIR/state/audit.jsonl"; then
  echo "database plaintext leaked into metadata or audit state" >&2
  exit 1
fi

printf '%s\n' '{"status":"passed","engines":["mariadb","postgres"],"foreignPrincipalCollisionRejected":true,"exactBindingRotationPassed":true,"foreignBindingRotationRejected":true,"livePlatformDatabasesTouched":false}'
