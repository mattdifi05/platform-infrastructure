#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=plan
REPO_ROOT="${PLATFORM_REPO_ROOT:-$ROOT_DIR}"
UNIT_NAME=platform-host-reliability.service
TIMER_NAME=platform-host-reliability.timer
UNIT_FILE="/etc/systemd/system/$UNIT_NAME"
TIMER_FILE="/etc/systemd/system/$TIMER_NAME"
INSTALL_DIR=/usr/local/libexec/platform-infrastructure
INSTALL_FILE="$INSTALL_DIR/host-reliability-collector"
STATE_DIR="$REPO_ROOT/projects-portal/state/node-exporter-textfile"
PROM_FILE="$STATE_DIR/platform-host-reliability.prom"
SOURCE_FILE="$ROOT_DIR/scripts/collect-host-reliability.sh"

usage() {
  cat <<'EOF'
Usage: install-host-reliability-collector.sh [--plan|--apply|--verify] [--repo-root PATH]

Plan is the default. Apply installs smartmontools and nvme-cli, a hardened
oneshot service and a one-minute timer. It does not configure networking,
upgrade packages, reboot the host or configure a UPS.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --repo-root) shift; REPO_ROOT="${1:?Missing value for --repo-root}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$REPO_ROOT" in /*) ;; *) echo "--repo-root must be absolute" >&2; exit 2 ;; esac
STATE_DIR="$REPO_ROOT/projects-portal/state/node-exporter-textfile"
PROM_FILE="$STATE_DIR/platform-host-reliability.prom"

verify_installation() {
  systemctl is-enabled --quiet "$TIMER_NAME"
  systemctl is-active --quiet "$TIMER_NAME"
  [ "$(systemctl show "$UNIT_NAME" -p Result --value)" = "success" ]
  [ "$(systemctl show "$UNIT_NAME" -p ExecMainStatus --value)" = "0" ]
  [ -x "$INSTALL_FILE" ]
  [ -r "$PROM_FILE" ]
  grep -q '^platform_host_reliability_collector_healthy 1$' "$PROM_FILE"
  grep -q '^platform_host_network_default_route 1$' "$PROM_FILE"
  grep -q '^platform_host_drive_count [1-9][0-9]*$' "$PROM_FILE"
  current=$(date -u +%s)
  captured=$(awk '$1=="platform_host_reliability_last_success_timestamp_seconds"{print $2;exit}' "$PROM_FILE")
  age=$((current - captured))
  [ "$age" -ge 0 ] && [ "$age" -le 180 ]
  echo "$UNIT_NAME verified: metrics age ${age}s."
}

if [ "$MODE" = verify ]; then
  verify_installation
  exit 0
fi

if [ "$MODE" = plan ]; then
  cat <<EOF
Plan only; no host mutation executed.
- install smartmontools and nvme-cli
- install $SOURCE_FILE as $INSTALL_FILE
- create $UNIT_FILE and $TIMER_FILE
- write non-secret node-exporter textfile metrics to $PROM_FILE every minute
- leave network, package upgrades, reboot and UPS configuration unchanged
EOF
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "--apply requires root" >&2; exit 1; }
for command_name in apt-get install systemctl; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name is required" >&2; exit 1; }
done
[ -f "$SOURCE_FILE" ] || { echo "Collector source missing: $SOURCE_FILE" >&2; exit 1; }

apt-get update
apt-get install -y smartmontools nvme-cli
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0755 "$STATE_DIR"
install -m 0755 "$SOURCE_FILE" "$INSTALL_FILE"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Platform host reliability metrics collector
Documentation=file:$REPO_ROOT/RUNBOOK.md
After=local-fs.target network-online.target docker.service

[Service]
Type=oneshot
ExecStart=$INSTALL_FILE
Environment=PLATFORM_HOST_RELIABILITY_FILE=$PROM_FILE
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

cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Collect Platform host reliability metrics every minute

[Timer]
OnBootSec=45s
OnUnitActiveSec=60s
AccuracySec=5s
Persistent=true
Unit=$UNIT_NAME

[Install]
WantedBy=timers.target
EOF

chmod 0644 "$UNIT_FILE" "$TIMER_FILE"
systemctl daemon-reload
systemctl enable --now "$TIMER_NAME"
systemctl start "$UNIT_NAME"
verify_installation
