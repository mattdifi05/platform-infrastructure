#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/platform-host-reliability-test.XXXXXX")
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$WORK_DIR/bin" "$WORK_DIR/sys/block/nvme0n1" "$WORK_DIR/sys/block/sda" "$WORK_DIR/dev" "$WORK_DIR/journal" "$WORK_DIR/out"
: > "$WORK_DIR/dev/nvme0n1"
: > "$WORK_DIR/dev/sda"
: > "$WORK_DIR/reboot-required"

cat > "$WORK_DIR/bin/ip" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'default via 192.0.2.1 dev eth0'
EOF
cat > "$WORK_DIR/bin/systemctl" <<'EOF'
#!/usr/bin/env sh
[ "${1:-}" = is-failed ] && exit 1
exit 0
EOF
cat > "$WORK_DIR/bin/apt" <<'EOF'
#!/usr/bin/env sh
cat <<OUT
Listing...
one/stable 2 amd64 [upgradable from: 1]
two/stable 2 amd64 [upgradable from: 1]
OUT
EOF
cat > "$WORK_DIR/bin/smartctl" <<'EOF'
#!/usr/bin/env sh
case "$*" in
  *nvme0n1*) printf '%s\n' '{"smart_status":{"passed":true},"temperature":{"current":41},"nvme_smart_health_information_log":{"percentage_used":3,"media_errors":0}}' ;;
  *) printf '%s\n' '{"smart_status":{"passed":true},"temperature":{"current":35}}' ;;
esac
EOF
cat > "$WORK_DIR/bin/upsc" <<'EOF'
#!/usr/bin/env sh
case "$*" in
  -l) echo platform-ups ;;
  *ups.status*) echo OL ;;
  *battery.charge*) echo 97 ;;
esac
EOF
chmod 0755 "$WORK_DIR/bin/"*

PATH="$WORK_DIR/bin:$PATH" \
PLATFORM_ALLOW_FAKE_BLOCK_DEVICES=true \
PLATFORM_SYS_BLOCK_ROOT="$WORK_DIR/sys/block" \
PLATFORM_DEV_ROOT="$WORK_DIR/dev" \
PLATFORM_JOURNAL_ROOT="$WORK_DIR/journal" \
PLATFORM_REBOOT_REQUIRED_FILE="$WORK_DIR/reboot-required" \
PLATFORM_HOST_RELIABILITY_FILE="$WORK_DIR/out/host.prom" \
  sh "$ROOT_DIR/scripts/collect-host-reliability.sh"

assert_metric() {
  grep -Fqx "$1" "$WORK_DIR/out/host.prom" || { echo "Missing metric: $1" >&2; exit 1; }
}
assert_metric 'platform_host_reliability_collector_healthy 1'
assert_metric 'platform_host_network_default_route 1'
assert_metric 'platform_host_upgradable_packages 2'
assert_metric 'platform_host_reboot_required 1'
assert_metric 'platform_host_drive_count 2'
assert_metric 'platform_host_drive_telemetry_count 2'
assert_metric 'platform_host_drive_healthy{device="nvme0n1"} 1'
assert_metric 'platform_host_drive_percentage_used{device="nvme0n1"} 3'
assert_metric 'platform_host_ups_configured 1'
assert_metric 'platform_host_ups_online 1'
assert_metric 'platform_host_ups_charge_percent 97'

PATH="$WORK_DIR/bin:$PATH" \
PLATFORM_DISABLE_DRIVE_TELEMETRY=true \
PLATFORM_DISABLE_UPS=true \
PLATFORM_ALLOW_FAKE_BLOCK_DEVICES=true \
PLATFORM_SYS_BLOCK_ROOT="$WORK_DIR/sys/block" \
PLATFORM_DEV_ROOT="$WORK_DIR/dev" \
PLATFORM_JOURNAL_ROOT="$WORK_DIR/missing-journal" \
PLATFORM_REBOOT_REQUIRED_FILE="$WORK_DIR/no-reboot" \
PLATFORM_HOST_RELIABILITY_FILE="$WORK_DIR/out/no-telemetry.prom" \
  sh "$ROOT_DIR/scripts/collect-host-reliability.sh"
grep -Fqx 'platform_host_drive_count 2' "$WORK_DIR/out/no-telemetry.prom"
grep -Fqx 'platform_host_drive_telemetry_count 0' "$WORK_DIR/out/no-telemetry.prom"
grep -Fqx 'platform_host_ups_configured 0' "$WORK_DIR/out/no-telemetry.prom"

mkdir -p "$WORK_DIR/bin-no-route"
cat > "$WORK_DIR/bin-no-route/ip" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
chmod 0755 "$WORK_DIR/bin-no-route/ip"
if PATH="$WORK_DIR/bin-no-route:$WORK_DIR/bin:$PATH" PLATFORM_SYS_BLOCK_ROOT="$WORK_DIR/sys/block" PLATFORM_DEV_ROOT="$WORK_DIR/dev" PLATFORM_ALLOW_FAKE_BLOCK_DEVICES=true PLATFORM_HOST_RELIABILITY_FILE="$WORK_DIR/out/no-route.prom" sh "$ROOT_DIR/scripts/collect-host-reliability.sh" >/dev/null 2>&1; then
  echo "Collector unexpectedly passed without a default route" >&2
  exit 1
fi

echo "Host reliability sandbox passed: network, patch, drive, I/O and UPS metrics are truthful."
