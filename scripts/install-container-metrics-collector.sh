#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=plan
SCOPE=system
DEPLOY_USER="${PLATFORM_DEPLOY_USER:-platform_infrastructure}"
REPO_ROOT="${PLATFORM_REPO_ROOT:-$ROOT_DIR}"
STATE_DIR_OVERRIDE="${PLATFORM_METRICS_STATE_DIR:-}"
UNIT_NAME=platform-container-metrics.service
UNIT_FILE="/etc/systemd/system/$UNIT_NAME"
ENV_DIR=/etc/platform-infrastructure
ENV_FILE="$ENV_DIR/container-metrics.env"
INSTALL_DIR=/usr/local/libexec/platform-infrastructure
INSTALL_FILE="$INSTALL_DIR/container-metrics-collector"
RUNNER_FILE="$INSTALL_DIR/container-metrics-cron-runner"
CRON_MARKER="# platform-container-metrics"

usage() {
  cat <<'EOF'
Usage: install-container-metrics-collector.sh [--plan|--apply|--verify] [--user-cron] [--deploy-user USER] [--repo-root PATH] [--state-dir PATH]

Installs a hardened host-side Docker metrics collector. Plan is the default.
The collector writes non-secret JSON for Control Center and Prometheus textfile
metrics for node-exporter; it never mounts the Docker socket into a container.
Use --user-cron on a LOCAL_PRIVATE host where the deploy user already has
Docker access but passwordless root installation is intentionally unavailable.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --user-cron) SCOPE=user-cron ;;
    --deploy-user)
      shift
      DEPLOY_USER="${1:?Missing value for --deploy-user}"
      ;;
    --repo-root)
      shift
      REPO_ROOT="${1:?Missing value for --repo-root}"
      ;;
    --state-dir)
      shift
      STATE_DIR_OVERRIDE="${1:?Missing value for --state-dir}"
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

if [ -n "$STATE_DIR_OVERRIDE" ]; then
  case "$STATE_DIR_OVERRIDE" in
    /*) ;;
    *) echo "--state-dir must be an absolute path" >&2; exit 2 ;;
  esac
fi

STATE_DIR="${STATE_DIR_OVERRIDE:-$REPO_ROOT/projects-portal/state}"
TEXTFILE_DIR="$STATE_DIR/node-exporter-textfile"
JSON_FILE="$STATE_DIR/docker-stats.json"
PROM_FILE="$TEXTFILE_DIR/platform-container.prom"
SOURCE_FILE="$ROOT_DIR/scripts/write-docker-stats-json.sh"

if [ "$SCOPE" = user-cron ]; then
  USER_CONFIG_ROOT="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure"
  INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/platform-infrastructure/bin"
  ENV_DIR="$USER_CONFIG_ROOT"
  ENV_FILE="$ENV_DIR/container-metrics.env"
  INSTALL_FILE="$INSTALL_DIR/container-metrics-collector"
  RUNNER_FILE="$INSTALL_DIR/container-metrics-cron-runner"
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 command not found" >&2
    exit 1
  fi
}

verify_installation() {
  require_command jq
  [ -x "$INSTALL_FILE" ] || { echo "$INSTALL_FILE is missing or not executable" >&2; exit 1; }
  [ -r "$ENV_FILE" ] || { echo "$ENV_FILE is missing or unreadable" >&2; exit 1; }
  if [ "$SCOPE" = user-cron ]; then
    require_command crontab
    [ -x "$RUNNER_FILE" ] || { echo "$RUNNER_FILE is missing or not executable" >&2; exit 1; }
    crontab -l 2>/dev/null | grep -F "$CRON_MARKER" >/dev/null \
      || { echo "container metrics cron entry is missing" >&2; exit 1; }
  else
    require_command systemctl
    systemctl is-active --quiet "$UNIT_NAME" || { echo "$UNIT_NAME is not active" >&2; exit 1; }
  fi
  [ -r "$JSON_FILE" ] || { echo "$JSON_FILE is missing" >&2; exit 1; }
  [ -r "$PROM_FILE" ] || { echo "$PROM_FILE is missing" >&2; exit 1; }
  jq -e '
    .schemaVersion == 2
    and .collector.healthy == true
    and .collector.observed == .collector.expectedRunning
    and (.capturedAtEpoch | type == "number")
    and ((now - .capturedAtEpoch) <= 30)
    and ([.containers[] | select(.cpuPercent == null or .memoryUsageBytes == null)] | length) == 0
  ' "$JSON_FILE" >/dev/null
  grep -q '^platform_container_metrics_collector_healthy 1$' "$PROM_FILE"
  grep -q '^platform_container_cpu_percent{' "$PROM_FILE"
  grep -q '^platform_container_memory_usage_bytes{' "$PROM_FILE"
  echo "platform container metrics verified: fresh complete workload metrics are available."
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
  if [ "$SCOPE" = user-cron ]; then
    cat <<EOF
Plan only; no host mutation executed.
- install $SOURCE_FILE as $INSTALL_FILE
- create $ENV_FILE without secrets
- install a bounded three-sample-per-minute user cron runner
- write JSON to $JSON_FILE
- write Prometheus textfile metrics to $PROM_FILE
EOF
    exit 0
  fi
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

if [ "$SCOPE" = user-cron ]; then
  for command_name in docker jq crontab install; do
    require_command "$command_name"
  done
  install -d -m 0700 "$INSTALL_DIR" "$ENV_DIR"
  install -d -m 0755 "$STATE_DIR" "$TEXTFILE_DIR"
  install -m 0755 "$SOURCE_FILE" "$INSTALL_FILE"
  cat > "$ENV_FILE" <<EOF
PROJECT_DOCKER_STATS_FILE=$JSON_FILE
PLATFORM_CONTAINER_METRICS_FILE=$PROM_FILE
PROJECT_DOCKER_STATS_INTERVAL_SECONDS=5
EOF
  chmod 0600 "$ENV_FILE"
  cat > "$RUNNER_FILE" <<EOF
#!/usr/bin/env sh
set -eu
PATH=/usr/local/bin:/usr/bin:/bin
. "$ENV_FILE"
export PROJECT_DOCKER_STATS_FILE PLATFORM_CONTAINER_METRICS_FILE PROJECT_DOCKER_STATS_INTERVAL_SECONDS
lock="$STATE_DIR/.container-metrics-cron.lock"
if ! mkdir "\$lock" 2>/dev/null; then exit 0; fi
trap 'rmdir "\$lock" 2>/dev/null || true' EXIT HUP INT TERM
"$INSTALL_FILE"
sleep 20
"$INSTALL_FILE"
sleep 20
"$INSTALL_FILE"
EOF
  chmod 0700 "$RUNNER_FILE"
  cron_tmp=$(mktemp "${TMPDIR:-/tmp}/platform-container-metrics-cron.XXXXXX")
  trap 'rm -f "$cron_tmp"' EXIT HUP INT TERM
  crontab -l 2>/dev/null | grep -Fv "$CRON_MARKER" > "$cron_tmp" || true
  printf '%s\n' "* * * * * $RUNNER_FILE >/dev/null 2>&1 $CRON_MARKER" >> "$cron_tmp"
  crontab "$cron_tmp"
  rm -f "$cron_tmp"
  trap - EXIT HUP INT TERM
  "$INSTALL_FILE"
  verify_installation
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
Documentation=file:$REPO_ROOT/RUNBOOK.md
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
while [ "$attempt" -lt 30 ]; do
  if verify_installation >/dev/null 2>&1; then
    verify_installation
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done

systemctl --no-pager --full status "$UNIT_NAME" >&2 || true
echo "$UNIT_NAME did not produce fresh complete metrics within 30 seconds" >&2
exit 1
