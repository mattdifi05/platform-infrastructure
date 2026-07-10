#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=plan
DEPLOY_USER="${PLATFORM_DEPLOY_USER:-platform_infrastructure}"
REPO_ROOT="${PLATFORM_REPO_ROOT:-$ROOT_DIR}"
UNIT_NAME=platform-container-metrics.service
UNIT_FILE="/etc/systemd/system/$UNIT_NAME"
ENV_DIR=/etc/platform-infrastructure
ENV_FILE="$ENV_DIR/container-metrics.env"
INSTALL_DIR=/usr/local/libexec/platform-infrastructure
INSTALL_FILE="$INSTALL_DIR/container-metrics-collector"

usage() {
  cat <<'EOF'
Usage: install-container-metrics-collector.sh [--plan|--apply|--verify] [--deploy-user USER] [--repo-root PATH]

Installs a hardened host-side Docker metrics collector. Plan is the default.
The collector writes non-secret JSON for Control Center and Prometheus textfile
metrics for node-exporter; it never mounts the Docker socket into a container.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --deploy-user)
      shift
      DEPLOY_USER="${1:?Missing value for --deploy-user}"
      ;;
    --repo-root)
      shift
      REPO_ROOT="${1:?Missing value for --repo-root}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

case "$DEPLOY_USER" in
  ''|*[!A-Za-z0-9_.-]*)
    echo "Invalid deploy user" >&2
    exit 2
    ;;
esac
case "$REPO_ROOT" in
  /*) ;;
  *)
    echo "--repo-root must be an absolute path" >&2
    exit 2
    ;;
esac

STATE_DIR="$REPO_ROOT/projects-portal/state"
TEXTFILE_DIR="$STATE_DIR/node-exporter-textfile"
JSON_FILE="$STATE_DIR/docker-stats.json"
PROM_FILE="$TEXTFILE_DIR/platform-container.prom"
SOURCE_FILE="$ROOT_DIR/scripts/write-docker-stats-json.sh"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 command not found" >&2
    exit 1
  fi
}

verify_installation() {
  require_command systemctl
  require_command jq
  [ -x "$INSTALL_FILE" ] || { echo "$INSTALL_FILE is missing or not executable" >&2; exit 1; }
  [ -r "$ENV_FILE" ] || { echo "$ENV_FILE is missing or unreadable" >&2; exit 1; }
  systemctl is-active --quiet "$UNIT_NAME" || { echo "$UNIT_NAME is not active" >&2; exit 1; }
  [ -r "$JSON_FILE" ] || { echo "$JSON_FILE is missing" >&2; exit 1; }
  [ -r "$PROM_FILE" ] || { echo "$PROM_FILE is missing" >&2; exit 1; }
  jq -e '
    .schemaVersion == 2
    and .collector.healthy == true
    and .collector.observed == .collector.expectedRunning
    and (.capturedAtEpoch | type == "number")
    and ((now - .capturedAtEpoch) <= 15)
    and ([.containers[] | select(.cpuPercent == null or .memoryUsageBytes == null)] | length) == 0
  ' "$JSON_FILE" >/dev/null
  grep -q '^platform_container_metrics_collector_healthy 1$' "$PROM_FILE"
  grep -q '^platform_container_cpu_percent{' "$PROM_FILE"
  grep -q '^platform_container_memory_usage_bytes{' "$PROM_FILE"
  echo "$UNIT_NAME verified: fresh complete workload metrics are available."
}

if [ "$MODE" = verify ]; then
  verify_installation
  exit 0
fi

if [ ! -f "$SOURCE_FILE" ]; then
  echo "Collector source not found: $SOURCE_FILE" >&2
  exit 1
fi

if [ "$MODE" = plan ]; then
  cat <<EOF
Plan only; no host mutation executed.
- install $SOURCE_FILE as $INSTALL_FILE
- create $ENV_FILE without secrets
- create hardened $UNIT_FILE for user $DEPLOY_USER
- write JSON to $JSON_FILE
- write Prometheus textfile metrics to $PROM_FILE
- enable and start $UNIT_NAME
EOF
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "--apply requires root" >&2
  exit 1
fi

for command_name in docker jq systemctl install; do
  require_command "$command_name"
done
if ! id "$DEPLOY_USER" >/dev/null 2>&1; then
  echo "Deploy user does not exist: $DEPLOY_USER" >&2
  exit 1
fi
if ! getent group docker >/dev/null 2>&1; then
  echo "docker group does not exist" >&2
  exit 1
fi

install -d -m 0755 "$INSTALL_DIR" "$ENV_DIR"
install -d -m 0755 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$STATE_DIR" "$TEXTFILE_DIR"
install -m 0755 "$SOURCE_FILE" "$INSTALL_FILE"

cat > "$ENV_FILE" <<EOF
PROJECT_DOCKER_STATS_FILE=$JSON_FILE
PLATFORM_CONTAINER_METRICS_FILE=$PROM_FILE
PROJECT_DOCKER_STATS_INTERVAL_SECONDS=5
EOF
chmod 0644 "$ENV_FILE"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Platform truthful Docker workload metrics collector
Documentation=$REPO_ROOT/RUNBOOK.md
Requires=docker.service
After=docker.service

[Service]
Type=simple
User=$DEPLOY_USER
Group=$DEPLOY_USER
SupplementaryGroups=docker
EnvironmentFile=$ENV_FILE
ExecStartPre=/usr/bin/test -S /var/run/docker.sock
ExecStart=$INSTALL_FILE --watch
Restart=always
RestartSec=3s
TimeoutStopSec=15s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_FILE"

systemctl daemon-reload
systemctl enable --now "$UNIT_NAME"

attempt=0
while [ "$attempt" -lt 10 ]; do
  if verify_installation >/dev/null 2>&1; then
    verify_installation
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done

systemctl --no-pager --full status "$UNIT_NAME" >&2 || true
echo "$UNIT_NAME did not produce fresh complete metrics within 10 seconds" >&2
exit 1
