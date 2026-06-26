#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE="${1:-$ROOT_DIR/.env}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-platform_infra_vps}"

cd "$ROOT_DIR"

if [ ! -f "$ENV_FILE" ]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

get_env() {
  key="$1"
  value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); value=$0 } END { print value }' "$ENV_FILE")
  printf '%s' "$value"
}

require_env() {
  key="$1"
  value=$(get_env "$key")
  if [ -z "$value" ]; then
    echo "Missing required env: $key" >&2
    exit 1
  fi
  case "$value" in
    *localhost*|*example.com*|*your-domain*|*change_me*)
      echo "Env $key is still local/placeholder: $value" >&2
      exit 1
      ;;
  esac
}

for key in \
  CONTROL_CENTER_HOST DOCS_HOST CONTROL_CENTER_PUBLIC_URL DOCS_PUBLIC_URL \
  UI_PUBLIC_URL NEXT_PUBLIC_UI_URL \
  MAILER_FROM MAILER_REPLY_TO SMTP_HOST SMTP_USER \
  ALERT_EMAIL_TO PROJECTS_GATEWAY_EMAIL
do
  require_env "$key"
done

for secret in \
  postgres_superuser_password app_db_password keycloak_db_password redis_password keycloak_admin_password nats_password \
  minio_root_password grafana_admin_password session_secret session_signing_keys hash_pepper_keys database_url nats_url smtp_password \
  mariadb_root_password
do
  file="$ROOT_DIR/secrets/$secret.txt"
  if [ ! -s "$file" ]; then
    echo "Missing Docker secret file: $file" >&2
    exit 1
  fi
done

docker compose \
  --env-file "$ENV_FILE" \
  -p "$PROJECT_NAME" \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  config --quiet

if docker compose \
  --env-file "$ENV_FILE" \
  -p "$PROJECT_NAME" \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  config | grep -E 'image: .+:latest(@|$)' >/dev/null; then
  echo "Mutable :latest image found in rendered VPS config." >&2
  exit 1
fi

echo "VPS preflight passed."
