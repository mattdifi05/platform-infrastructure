#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd -P)
[[ $# = 1 && $1 = --apply-empty-core ]] || {
  printf 'Usage: %s --apply-empty-core\n' "$0" >&2
  exit 64
}
[[ $(uname -s) = Linux && $(id -u) != 0 ]] || {
  echo 'Run on the VPS as the non-root deployment user.' >&2
  exit 1
}
[[ -f "$ROOT/.env" && -f "$ROOT/secrets/control_center_database_url.txt" ]] || {
  echo 'The private first installation must be completed first.' >&2
  exit 1
}
env_value() { sed -n "s/^$1=//p" "$ROOT/.env" | tail -n 1; }
[[ $(env_value HOSTED_WORKLOAD_MODE) = no-hosted \
   && -z $(env_value HOSTED_WORKLOAD_LOCK) \
   && -z $(env_value NODE_PROJECT_HOSTS) \
   && -z $(env_value NODE_PROJECT_UPSTREAMS) \
   && -z $(env_value NODE_PROJECT_COMMANDS) ]] || {
  echo 'The exact empty-host workload mode is required.' >&2
  exit 1
}
[[ -z $(find "$ROOT/../src" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
  echo 'The application source directory must remain empty.' >&2
  exit 1
}
source "$ROOT/deployment/host/empty-vps/empty-vps-host-ownership.sh"
check_empty_vps_host_ownership
# The legacy Compose contract marks MariaDB storage external to prevent an
# accidental replacement. On this explicitly empty first install, create it
# once and require our label on every later run.
if ! docker volume inspect enterprise_mariadb_data >/dev/null 2>&1; then
  docker volume create --label com.platform.empty-vps-first-install=true enterprise_mariadb_data >/dev/null
fi
[[ $(docker volume inspect enterprise_mariadb_data --format '{{index .Labels "com.platform.empty-vps-first-install"}}') = true ]] || {
  echo 'MariaDB volume is not the empty first-install volume.' >&2
  exit 1
}
cd "$ROOT"
export EMPTY_VPS_HOSTED_LOCK_SHA256=45a56612923c64022df1173ca11486445d20c5ef06aab7b02c960f85feea851b
[[ $(sha256sum "$ROOT/config/no-hosted-workloads.lock.json" | cut -d ' ' -f 1) = "$EMPTY_VPS_HOSTED_LOCK_SHA256" ]] || {
  echo 'Empty-host workload lock differs from the reviewed candidate.' >&2
  exit 1
}
chmod 0600 "$ROOT/config/no-hosted-workloads.lock.json"
COMPOSE=(docker compose --env-file "$ROOT/.env")
COMPOSE+=(-p platform_infra_vps
  -f compose.yaml -f compose.secrets.yaml -f compose.waf.yaml
  -f compose.vps.yaml -f compose.vps-waf.yaml
  -f compose.empty-vps-networks.yaml -f compose.empty-vps-first-install.yaml
  -f compose.empty-vps-qualified-databases.yaml)
CC_CONFIG_FILES=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' enterprise-control-center 2>/dev/null || true)
HOST_METRICS_ACTIVE=0
for overlay in \
  deployment/vps-backup/compose.control-center.yaml \
  deployment/cloudflare-dns/compose.control-center.yaml \
  deployment/host/empty-vps/compose.first-enrollment.yaml \
  deployment/host/empty-vps/compose.host-metrics.yaml; do
  case ",$CC_CONFIG_FILES," in
    *,"$ROOT/$overlay",*)
      [[ -f "$ROOT/$overlay" ]] || { echo "The active Control Center overlay is missing: $overlay" >&2; exit 1; }
      COMPOSE+=(-f "$overlay")
      if [[ "$overlay" = deployment/host/empty-vps/compose.host-metrics.yaml ]]; then
        HOST_METRICS_ACTIVE=1
      fi
      ;;
  esac
done
[[ -n $("${COMPOSE[@]}" ps -q control-center) ]] || {
  echo 'Control Center from the private first installation is absent.' >&2
  exit 1
}
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" up -d --build
runtime_services=(postgres redis control-center traefik waf waf-loopback-proxy
  mariadb nats keycloak project-router rustfs-backend rustfs-gateway
  platform-alert-dispatcher alertmanager prometheus grafana loki promtail)
if (( HOST_METRICS_ACTIVE )); then
  runtime_services+=(node-exporter)
fi
for attempt in {1..90}; do
  pending=0
  for service in "${runtime_services[@]}"; do
    cid=$("${COMPOSE[@]}" ps -q "$service")
    state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)
    [[ "$state" = healthy || "$state" = running ]] || pending=1
  done
  (( pending == 0 )) && break
  if (( attempt == 90 )); then
    for service in "${runtime_services[@]}"; do
      cid=$("${COMPOSE[@]}" ps -q "$service")
      state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)
      [[ "$state" = healthy || "$state" = running ]] || printf '%s: %s\n' "$service" "${state:-missing}" >&2
    done
    exit 1
  fi
  sleep 2
done
"${COMPOSE[@]}" ps
echo 'The empty-host platform core is healthy; hosted applications remain absent.'
echo 'Backup admission and public production go-live require separate real inputs.'
