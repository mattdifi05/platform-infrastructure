#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${COMPOSE_ENV_FILE:-$ROOT_DIR/.env}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-platform_infra_vps}

case "$ENV_FILE" in
  /*) ;;
  *) ENV_FILE="$ROOT_DIR/$ENV_FILE" ;;
esac

if [ ! -f "$ENV_FILE" ]; then
  echo "Compose env file not found: $ENV_FILE" >&2
  exit 1
fi

cd "$ROOT_DIR"

exec docker compose \
  --env-file "$ENV_FILE" \
  -p "$PROJECT_NAME" \
  -f compose.yaml \
  -f compose.secrets.yaml \
  -f compose.waf.yaml \
  -f compose.vps.yaml \
  -f compose.vps-waf.yaml \
  -f compose.backup-scheduler.yaml \
  -f compose.build.yaml \
  -f compose.runtime.yaml \
  -f compose.networks.yaml \
  --profile backup \
  "$@"
