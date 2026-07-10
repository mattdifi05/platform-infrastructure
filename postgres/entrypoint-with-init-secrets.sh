#!/bin/sh
set -eu

[ "$(id -u)" = 0 ] || {
  printf '%s\n' "Platform PostgreSQL entrypoint must start as root to stage private init secrets." >&2
  exit 1
}

mkdir -p "${PGDATA:?PGDATA is required}"
chown postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

init_source=/platform-postgres-init
init_target=/docker-entrypoint-initdb.d
[ -d "$init_source" ] || {
  printf '%s\n' "PostgreSQL init source is missing." >&2
  exit 1
}
mkdir -p "$init_target"
chown postgres:postgres "$init_target"
chmod 700 "$init_target"
for source in "$init_source"/*; do
  [ -f "$source" ] || continue
  target="$init_target/$(basename "$source")"
  umask 077
  cat "$source" > "$target"
  chown postgres:postgres "$target"
  case "$target" in
    *.sh) chmod 500 "$target" ;;
    *) chmod 400 "$target" ;;
  esac
done

target_dir=/run/postgres-init-secrets
mkdir -p "$target_dir"
chown postgres:postgres "$target_dir"
chmod 700 "$target_dir"

copy_secret() {
  name=$1
  source=$2
  [ -n "$source" ] && [ -s "$source" ] || {
    printf '%s_FILE must point to a non-empty secret before PostgreSQL starts.\n' "$name" >&2
    exit 1
  }
  target="$target_dir/$(printf '%s' "$name" | tr 'A-Z' 'a-z')"
  umask 077
  tr -d '\r\n' < "$source" > "$target"
  chown postgres:postgres "$target"
  chmod 400 "$target"
  case "$name" in
    POSTGRES_PASSWORD) export POSTGRES_PASSWORD_FILE=$target ;;
    KEYCLOAK_DB_PASSWORD) export KEYCLOAK_DB_PASSWORD_FILE=$target ;;
    *) printf 'Unsupported PostgreSQL secret: %s\n' "$name" >&2; exit 1 ;;
  esac
}

copy_secret POSTGRES_PASSWORD "${POSTGRES_PASSWORD_FILE:-}"
copy_secret KEYCLOAK_DB_PASSWORD "${KEYCLOAK_DB_PASSWORD_FILE:-}"

exec docker-entrypoint.sh "$@"
