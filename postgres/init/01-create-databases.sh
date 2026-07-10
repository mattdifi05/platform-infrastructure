#!/bin/sh
set -eu

read_secret() {
  name=$1
  case "$name" in
    KEYCLOAK_DB_PASSWORD) file=${KEYCLOAK_DB_PASSWORD_FILE:-} ;;
    *) printf 'Unsupported init secret: %s\n' "$name" >&2; exit 1 ;;
  esac
  file_var="${name}_FILE"
  if [[ -z "$file" || ! -s "$file" ]]; then
    printf '%s\n' "$file_var must point to a readable Docker secret file." >&2
    exit 1
  fi
  tr -d '\r\n' < "$file"
}

KEYCLOAK_DB_PASSWORD="$(read_secret KEYCLOAK_DB_PASSWORD)"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname postgres \
  -v keycloak_db="$KEYCLOAK_DB_NAME" \
  -v keycloak_user="$KEYCLOAK_DB_USER" \
  -v keycloak_password="$KEYCLOAK_DB_PASSWORD" <<'EOSQL'
CREATE USER :"keycloak_user" WITH PASSWORD :'keycloak_password';
CREATE DATABASE :"keycloak_db" OWNER :"keycloak_user";
GRANT ALL PRIVILEGES ON DATABASE :"keycloak_db" TO :"keycloak_user";
EOSQL
