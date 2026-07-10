#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${COMPOSE_ENV_FILE:-$ROOT_DIR/.env.vps.example}
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-platform_infra_runtime_check}
OUTPUT=$(mktemp)

cleanup() {
  rm -f "$OUTPUT"
}
trap cleanup EXIT

cd "$ROOT_DIR"
COMPOSE_ENV_FILE="$ENV_FILE" COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
  sh ./scripts/compose-vps.sh config --format json > "$OUTPUT"

for service in local-registry backup-scheduler project-router control-center \
  php-anniversary php-fiplatform php-matthewdifilippo php-stream \
  php-workcalendar node-account node-ui; do
  jq -e --arg service "$service" '.services[$service] != null' "$OUTPUT" >/dev/null
done

jq -e '.services["local-registry"].image | test("^registry:3@sha256:[a-f0-9]{64}$")' "$OUTPUT" >/dev/null
jq -e '.volumes.enterprise_local_registry_data.name == "enterprise_local_registry_data"' "$OUTPUT" >/dev/null

if rg -n '\.tmp/(vps-runtime-override|compose\.worker-runtime-hotfix)\.yaml' \
  README.md RUNBOOK.md scripts/compose-vps.sh scripts/deploy-vps.sh \
  scripts/vps-preflight.sh scripts/vps-go-live.sh compose*.yaml >/dev/null; then
  echo "Tracked runtime still references an ignored .tmp overlay." >&2
  exit 1
fi

echo "Tracked VPS runtime config passed."
