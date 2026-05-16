#!/usr/bin/env bash
set -euo pipefail

read_secret() {
  local name="$1"
  local file_var="${name}_FILE"
  local value="${!name:-}"
  local file="${!file_var:-}"
  if [[ -n "$file" ]]; then
    value="$(<"$file")"
  fi
  printf '%s' "$value"
}

APP_DB_PASSWORD="$(read_secret APP_DB_PASSWORD)"
KEYCLOAK_DB_PASSWORD="$(read_secret KEYCLOAK_DB_PASSWORD)"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname postgres \
  -v app_db="$APP_DB_NAME" \
  -v app_user="$APP_DB_USER" \
  -v app_password="$APP_DB_PASSWORD" \
  -v keycloak_db="$KEYCLOAK_DB_NAME" \
  -v keycloak_user="$KEYCLOAK_DB_USER" \
  -v keycloak_password="$KEYCLOAK_DB_PASSWORD" <<'EOSQL'
CREATE USER :"app_user" WITH PASSWORD :'app_password';
CREATE DATABASE :"app_db" OWNER :"app_user";
GRANT ALL PRIVILEGES ON DATABASE :"app_db" TO :"app_user";

CREATE USER :"keycloak_user" WITH PASSWORD :'keycloak_password';
CREATE DATABASE :"keycloak_db" OWNER :"keycloak_user";
GRANT ALL PRIVILEGES ON DATABASE :"keycloak_db" TO :"keycloak_user";
EOSQL
