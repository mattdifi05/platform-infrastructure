#!/bin/sh
set -eu

read_secret() {
  name=$1
  case "$name" in
    APP_DB_PASSWORD) file=${APP_DB_PASSWORD_FILE:-} ;;
    KEYCLOAK_DB_PASSWORD) file=${KEYCLOAK_DB_PASSWORD_FILE:-} ;;
    BACKEND_DB_PASSWORD) file=${BACKEND_DB_PASSWORD_FILE:-} ;;
    WORKER_JOBS_DB_PASSWORD) file=${WORKER_JOBS_DB_PASSWORD_FILE:-} ;;
    WORKER_NOTIFICATIONS_DB_PASSWORD) file=${WORKER_NOTIFICATIONS_DB_PASSWORD_FILE:-} ;;
    *) printf 'Unsupported init secret: %s\n' "$name" >&2; exit 1 ;;
  esac
  file_var="${name}_FILE"
  if [[ -z "$file" || ! -s "$file" ]]; then
    printf '%s\n' "$file_var must point to a readable Docker secret file." >&2
    exit 1
  fi
  tr -d '\r\n' < "$file"
}

APP_DB_PASSWORD="$(read_secret APP_DB_PASSWORD)"
KEYCLOAK_DB_PASSWORD="$(read_secret KEYCLOAK_DB_PASSWORD)"
BACKEND_DB_PASSWORD="$(read_secret BACKEND_DB_PASSWORD)"
WORKER_JOBS_DB_PASSWORD="$(read_secret WORKER_JOBS_DB_PASSWORD)"
WORKER_NOTIFICATIONS_DB_PASSWORD="$(read_secret WORKER_NOTIFICATIONS_DB_PASSWORD)"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname postgres \
  -v app_db="$APP_DB_NAME" \
  -v app_user="$APP_DB_USER" \
  -v app_password="$APP_DB_PASSWORD" \
  -v backend_user="${BACKEND_DB_USER:-app_backend_runtime}" \
  -v backend_password="$BACKEND_DB_PASSWORD" \
  -v worker_jobs_user="${WORKER_JOBS_DB_USER:-app_worker_jobs_runtime}" \
  -v worker_jobs_password="$WORKER_JOBS_DB_PASSWORD" \
  -v worker_notifications_user="${WORKER_NOTIFICATIONS_DB_USER:-app_worker_notifications_runtime}" \
  -v worker_notifications_password="$WORKER_NOTIFICATIONS_DB_PASSWORD" \
  -v keycloak_db="$KEYCLOAK_DB_NAME" \
  -v keycloak_user="$KEYCLOAK_DB_USER" \
  -v keycloak_password="$KEYCLOAK_DB_PASSWORD" <<'EOSQL'
CREATE USER :"app_user" WITH PASSWORD :'app_password';
CREATE DATABASE :"app_db" OWNER :"app_user";
GRANT ALL PRIVILEGES ON DATABASE :"app_db" TO :"app_user";

CREATE USER :"backend_user" WITH PASSWORD :'backend_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE USER :"worker_jobs_user" WITH PASSWORD :'worker_jobs_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE USER :"worker_notifications_user" WITH PASSWORD :'worker_notifications_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE :"app_db" TO :"backend_user", :"worker_jobs_user", :"worker_notifications_user";

CREATE USER :"keycloak_user" WITH PASSWORD :'keycloak_password';
CREATE DATABASE :"keycloak_db" OWNER :"keycloak_user";
GRANT ALL PRIVILEGES ON DATABASE :"keycloak_db" TO :"keycloak_user";
EOSQL
