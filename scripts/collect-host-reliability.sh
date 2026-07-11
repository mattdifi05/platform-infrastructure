#!/usr/bin/env sh
set -eu

OUT_FILE="${PLATFORM_HOST_RELIABILITY_FILE:-/home/platform_infrastructure/platform-infrastructure/projects-portal/state/node-exporter-textfile/platform-host-reliability.prom}"
SYS_BLOCK_ROOT="${PLATFORM_SYS_BLOCK_ROOT:-/sys/block}"
DEV_ROOT="${PLATFORM_DEV_ROOT:-/dev}"
JOURNAL_ROOT="${PLATFORM_JOURNAL_ROOT:-/var/log/journal}"
REBOOT_REQUIRED_FILE="${PLATFORM_REBOOT_REQUIRED_FILE:-/var/run/reboot-required}"

OUT_DIR=$(dirname "$OUT_FILE")
mkdir -p "$OUT_DIR"
TMP_FILE=$(mktemp "$OUT_DIR/.platform-host-reliability.XXXXXX")
cleanup() {
  rm -f "$TMP_FILE"
}
trap cleanup EXIT HUP INT TERM

metric() {
  printf '%s\n' "$1" >> "$TMP_FILE"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

number_or_zero() {
  value=${1:-0}
  case "$value" in
    ''|*[!0-9.-]*) printf '0' ;;
    *) printf '%s' "$value" ;;
  esac
}

device_label() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

now=$(date -u +%s)
network_default_route=0
wait_online_failed=0
upgradable_packages=0
reboot_required=0
journal_bytes=0
io_some_avg10=0
io_full_avg10=0
collector_healthy=1

if command_exists ip && ip route show default 2>/dev/null | grep -q '^default '; then
  network_default_route=1
fi
if command_exists systemctl && systemctl is-failed --quiet systemd-networkd-wait-online.service 2>/dev/null; then
  wait_online_failed=1
fi
if command_exists apt; then
  upgradable_packages=$(apt list --upgradable 2>/dev/null | awk '/upgradable from:/{count++} END{print count+0}')
fi
if [ -e "$REBOOT_REQUIRED_FILE" ]; then
  reboot_required=1
fi
if command_exists du && [ -d "$JOURNAL_ROOT" ]; then
  journal_bytes=$(du -sb "$JOURNAL_ROOT" 2>/dev/null | awk 'NR==1{print $1+0}' || printf '0')
fi
if [ -r /proc/pressure/io ]; then
  io_some_avg10=$(awk '$1=="some" {for(i=2;i<=NF;i++) if($i ~ /^avg10=/){sub(/^avg10=/,"",$i); print $i; exit}}' /proc/pressure/io)
  io_full_avg10=$(awk '$1=="full" {for(i=2;i<=NF;i++) if($i ~ /^avg10=/){sub(/^avg10=/,"",$i); print $i; exit}}' /proc/pressure/io)
fi

metric '# HELP platform_host_reliability_collector_healthy Whether the host reliability collector completed.'
metric '# TYPE platform_host_reliability_collector_healthy gauge'
metric "platform_host_reliability_collector_healthy $collector_healthy"
metric '# HELP platform_host_reliability_last_success_timestamp_seconds Unix timestamp of the latest successful collection.'
metric '# TYPE platform_host_reliability_last_success_timestamp_seconds gauge'
metric "platform_host_reliability_last_success_timestamp_seconds $now"
metric '# HELP platform_host_network_default_route Whether the host has an active default route.'
metric '# TYPE platform_host_network_default_route gauge'
metric "platform_host_network_default_route $network_default_route"
metric '# HELP platform_host_wait_online_failed Whether systemd-networkd-wait-online is failed.'
metric '# TYPE platform_host_wait_online_failed gauge'
metric "platform_host_wait_online_failed $wait_online_failed"
metric '# HELP platform_host_upgradable_packages Number of packages currently upgradeable.'
metric '# TYPE platform_host_upgradable_packages gauge'
metric "platform_host_upgradable_packages $(number_or_zero "$upgradable_packages")"
metric '# HELP platform_host_reboot_required Whether the host requests a reboot.'
metric '# TYPE platform_host_reboot_required gauge'
metric "platform_host_reboot_required $reboot_required"
metric '# HELP platform_host_journal_bytes Bytes consumed by persistent systemd journals.'
metric '# TYPE platform_host_journal_bytes gauge'
metric "platform_host_journal_bytes $(number_or_zero "$journal_bytes")"
metric '# HELP platform_host_io_pressure_avg10 Ten-second Linux PSI I/O pressure average.'
metric '# TYPE platform_host_io_pressure_avg10 gauge'
metric "platform_host_io_pressure_avg10{mode=\"some\"} $(number_or_zero "$io_some_avg10")"
metric "platform_host_io_pressure_avg10{mode=\"full\"} $(number_or_zero "$io_full_avg10")"

drive_count=0
telemetry_count=0
for sys_device in "$SYS_BLOCK_ROOT"/nvme*n1 "$SYS_BLOCK_ROOT"/sd*; do
  [ -e "$sys_device" ] || continue
  device=$(basename "$sys_device")
  [ -b "$DEV_ROOT/$device" ] || [ "${PLATFORM_ALLOW_FAKE_BLOCK_DEVICES:-false}" = true ] || continue
  drive_count=$((drive_count + 1))
  label=$(device_label "$device")
  telemetry_available=0
  drive_healthy=0
  temperature=0
  percentage_used=0
  media_errors=0
  smart_json=""
  if [ "${PLATFORM_DISABLE_DRIVE_TELEMETRY:-false}" != true ] && command_exists smartctl && command_exists jq; then
    smart_json=$(smartctl -j -H -A "$DEV_ROOT/$device" 2>/dev/null || true)
    if [ -n "$smart_json" ] && printf '%s' "$smart_json" | jq -e 'type == "object"' >/dev/null 2>&1; then
      telemetry_available=1
      drive_healthy=$(printf '%s' "$smart_json" | jq -r 'if .smart_status.passed == true then 1 else 0 end')
      temperature=$(printf '%s' "$smart_json" | jq -r '.temperature.current // .nvme_smart_health_information_log.temperature // 0')
      percentage_used=$(printf '%s' "$smart_json" | jq -r '.nvme_smart_health_information_log.percentage_used // 0')
      media_errors=$(printf '%s' "$smart_json" | jq -r '.nvme_smart_health_information_log.media_errors // 0')
    fi
  elif [ "${PLATFORM_DISABLE_DRIVE_TELEMETRY:-false}" != true ] && printf '%s' "$device" | grep -q '^nvme' && command_exists nvme && command_exists jq; then
    smart_json=$(nvme smart-log -o json "$DEV_ROOT/$device" 2>/dev/null || true)
    if [ -n "$smart_json" ] && printf '%s' "$smart_json" | jq -e 'type == "object"' >/dev/null 2>&1; then
      telemetry_available=1
      critical_warning=$(printf '%s' "$smart_json" | jq -r '.critical_warning // 1')
      [ "$critical_warning" = 0 ] && drive_healthy=1
      temperature=$(printf '%s' "$smart_json" | jq -r '.temperature // 0')
      percentage_used=$(printf '%s' "$smart_json" | jq -r '.percentage_used // 0')
      media_errors=$(printf '%s' "$smart_json" | jq -r '.media_errors // 0')
    fi
  fi
  [ "$telemetry_available" -eq 1 ] && telemetry_count=$((telemetry_count + 1))
  metric "platform_host_drive_telemetry_available{device=\"$label\"} $telemetry_available"
  metric "platform_host_drive_healthy{device=\"$label\"} $drive_healthy"
  metric "platform_host_drive_temperature_celsius{device=\"$label\"} $(number_or_zero "$temperature")"
  metric "platform_host_drive_percentage_used{device=\"$label\"} $(number_or_zero "$percentage_used")"
  metric "platform_host_drive_media_errors_total{device=\"$label\"} $(number_or_zero "$media_errors")"
done
metric '# HELP platform_host_drive_count Number of physical NVMe/SATA block devices detected.'
metric '# TYPE platform_host_drive_count gauge'
metric "platform_host_drive_count $drive_count"
metric '# HELP platform_host_drive_telemetry_count Number of detected drives with readable health telemetry.'
metric '# TYPE platform_host_drive_telemetry_count gauge'
metric "platform_host_drive_telemetry_count $telemetry_count"

ups_configured=0
ups_online=0
ups_on_battery=0
ups_charge_percent=0
if [ "${PLATFORM_DISABLE_UPS:-false}" != true ] && command_exists upsc; then
  ups_name=$(upsc -l 2>/dev/null | sed -n '1p' || true)
  if [ -n "$ups_name" ]; then
    ups_configured=1
    ups_status=$(upsc "$ups_name" ups.status 2>/dev/null || true)
    ups_charge_percent=$(upsc "$ups_name" battery.charge 2>/dev/null || printf '0')
    printf '%s' "$ups_status" | grep -qw OL && ups_online=1
    printf '%s' "$ups_status" | grep -qw OB && ups_on_battery=1
  fi
fi
metric '# HELP platform_host_ups_configured Whether a UPS is available through NUT.'
metric '# TYPE platform_host_ups_configured gauge'
metric "platform_host_ups_configured $ups_configured"
metric '# HELP platform_host_ups_online Whether the UPS reports utility power online.'
metric '# TYPE platform_host_ups_online gauge'
metric "platform_host_ups_online $ups_online"
metric '# HELP platform_host_ups_on_battery Whether the UPS reports battery operation.'
metric '# TYPE platform_host_ups_on_battery gauge'
metric "platform_host_ups_on_battery $ups_on_battery"
metric '# HELP platform_host_ups_charge_percent UPS battery charge percentage.'
metric '# TYPE platform_host_ups_charge_percent gauge'
metric "platform_host_ups_charge_percent $(number_or_zero "$ups_charge_percent")"

chmod 0644 "$TMP_FILE"
mv -f "$TMP_FILE" "$OUT_FILE"
trap - EXIT HUP INT TERM

if [ "$network_default_route" -ne 1 ]; then
  exit 1
fi
