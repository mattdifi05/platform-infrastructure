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
  bash ./scripts/compose-vps.sh config --format json > "$OUTPUT"

for service in local-registry backup-scheduler docker-operation-gateway project-router control-center \
  platform-alert-dispatcher postgres redis keycloak nats minio mariadb \
  traefik waf prometheus alertmanager grafana loki promtail node-exporter cadvisor; do
  jq -e --arg service "$service" '.services[$service] != null' "$OUTPUT" >/dev/null
done

if [ -n "${HOSTED_WORKLOAD_LOCK:-}" ]; then
  lock=$HOSTED_WORKLOAD_LOCK
  case "$lock" in /*) ;; *) lock="$ROOT_DIR/$lock" ;; esac
  sh "$ROOT_DIR/scripts/hosted-workload-lock.sh" "$lock" verify
  jq -r '.workloads[].services[].name' "$lock" | while IFS= read -r service; do
    [ -n "$service" ] || continue
    jq -e --arg service "$service" '.services[$service] != null' "$OUTPUT" >/dev/null
  done
fi

jq -e '.services["local-registry"].image | test("^registry:3@sha256:[a-f0-9]{64}$")' "$OUTPUT" >/dev/null
jq -e '.networks.platform_docker_control.internal == true' "$OUTPUT" >/dev/null
jq -e '.services["docker-operation-gateway"].ports == null and .services["docker-operation-gateway"].entrypoint == ["node", "/infra/scripts/docker-operation-gateway.mjs"]' "$OUTPUT" >/dev/null
jq -e '.services["backup-scheduler"].environment.PLATFORM_DOCKER_GATEWAY_URL == "http://docker-operation-gateway:8787" and (.services["backup-scheduler"].environment.DOCKER_HOST == null)' "$OUTPUT" >/dev/null
jq -e '[.services[] | select(any(.volumes[]?; .source == "/var/run/docker.sock")) | .container_name] == ["enterprise-docker-operation-gateway"]' "$OUTPUT" >/dev/null
jq -e '
  [.services["docker-operation-gateway"].secrets[].source] == ["backup_scheduler_docker_gateway_token"] and
  [.services["backup-scheduler"].secrets[].source] == ["backup_scheduler_docker_gateway_token"] and
  ([.services | to_entries[] | select(any(.value.secrets[]?; .source == "backup_scheduler_docker_gateway_token")) | .key] | sort) == ["backup-scheduler", "docker-operation-gateway"]
' "$OUTPUT" >/dev/null
jq -e '.volumes.enterprise_local_registry_data.name == "enterprise_local_registry_data"' "$OUTPUT" >/dev/null
jq -e '.volumes.enterprise_local_registry_data.external == true' "$OUTPUT" >/dev/null

if rg -n '\.tmp/(vps-runtime-override|compose\.worker-runtime-hotfix)\.yaml' \
  README.md RUNBOOK.md scripts/compose-vps.sh scripts/deploy-vps.sh \
  scripts/vps-preflight.sh scripts/vps-go-live.sh compose*.yaml >/dev/null; then
  echo "Tracked runtime still references an ignored .tmp overlay." >&2
  exit 1
fi

echo "Tracked VPS runtime config passed."
