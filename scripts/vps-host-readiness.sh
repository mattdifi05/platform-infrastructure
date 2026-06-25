#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEFAULT_REPORT_DIR="$ROOT_DIR/reports/vps-host"
REPORT_DIR="${REPORT_DIR:-}"
MIN_ROOT_FREE_MB="${MIN_ROOT_FREE_MB:-10240}"
MIN_MEMORY_MB="${MIN_MEMORY_MB:-4096}"
EXPECTED_SSH_PORT="${SSH_PORT:-65002}"
ALLOW_FAILURES=0
DIAGNOSTIC=0

usage() {
  cat <<'EOF'
Usage: vps-host-readiness.sh [--enforce|--allow-failures|--diagnostic] [--ssh-port PORT]

Verify the VPS Ubuntu LTS host after Docker and hardening are installed.
Writes JSON and Markdown evidence under reports/vps-host/.

Options:
  --enforce          Fail when a required check fails. This is the default and
                     the only mode that should be used for production evidence.
  --allow-failures   Write evidence but return success even with failed checks.
  --diagnostic       Run from a disposable Linux container or non-VPS host and
                     write under reports/vps-host-diagnostics/ so production
                     go/no-go does not confuse diagnostics with VPS evidence.
  --ssh-port PORT    Expected SSH port after hardening. Default: 65002 or
                     SSH_PORT from the environment.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --enforce)
      ALLOW_FAILURES=0
      ;;
    --allow-failures)
      ALLOW_FAILURES=1
      ;;
    --diagnostic)
      DIAGNOSTIC=1
      ALLOW_FAILURES=1
      ;;
    --ssh-port)
      shift
      EXPECTED_SSH_PORT="${1:?Missing value for --ssh-port}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

case "$EXPECTED_SSH_PORT" in
  ''|*[!0-9]*)
    echo "Invalid --ssh-port value: $EXPECTED_SSH_PORT" >&2
    exit 1
    ;;
esac

if [ -z "$REPORT_DIR" ]; then
  if [ "$DIAGNOSTIC" -eq 1 ]; then
    REPORT_DIR="$ROOT_DIR/reports/vps-host-diagnostics"
  else
    REPORT_DIR="$DEFAULT_REPORT_DIR"
  fi
fi

mkdir -p "$REPORT_DIR"
STAMP=$(date -u +%Y%m%d%H%M%S)
ROWS_FILE=$(mktemp)
REPORT_PREFIX="vps-host-readiness"
if [ "$DIAGNOSTIC" -eq 1 ]; then
  REPORT_PREFIX="vps-host-readiness-diagnostic"
fi
JSON_REPORT="$REPORT_DIR/$REPORT_PREFIX-$STAMP.json"
MD_REPORT="$REPORT_DIR/$REPORT_PREFIX-$STAMP.md"

cleanup() {
  rm -f "$ROWS_FILE"
}
trap cleanup EXIT

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g'
}

add_check() {
  name="$1"
  required="$2"
  status="$3"
  detail="$4"
  printf '%s\t%s\t%s\t%s\n' "$name" "$required" "$status" "$detail" >> "$ROWS_FILE"
  printf '%s [%s]: %s\n' "$name" "$status" "$detail"
}

remediation_for_check() {
  case "$1" in
    ubuntu-lts)
      printf '%s' "Provision an Ubuntu LTS VPS image before running the production profile."
      ;;
    git-cli)
      printf '%s' "Install Git: sudo apt-get update && sudo apt-get install -y git."
      ;;
    docker-cli|docker-daemon|docker-compose-plugin)
      printf '%s' "Install Docker Engine and the Docker Compose plugin from the official Docker Ubuntu repository, then ensure the deploy user can reach the Docker daemon."
      ;;
    docker-daemon-hardening)
      printf '%s' "Run sudo sh ./scripts/vps-hardening-ubuntu.sh --apply. If /etc/docker/daemon.json already exists and is missing Platform keys, review /etc/docker/daemon.json.platform-template and rerun with --replace-docker-daemon-config to create a backup, write /etc/docker/daemon.json and restart Docker."
      ;;
    ufw-active|ufw-no-direct-internal-ports)
      printf '%s' "Run sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port <port>, then apply Cloudflare origin lock before removing generic 80/443 exposure."
      ;;
    ufw-ssh-port-allowed)
      printf '%s' "Allow the hardened SSH port with sudo ufw allow <port>/tcp, then rerun vps-host-readiness.sh --ssh-port <port> --enforce."
      ;;
    fail2ban-active|apparmor-active|auditd-active)
      printf '%s' "Install and enable the host security service with sudo sh ./scripts/vps-hardening-ubuntu.sh --apply."
      ;;
    ssh-password-auth-disabled|ssh-root-login-disabled|ssh-hardening)
      printf '%s' "Apply /etc/ssh/sshd_config.d/99-platform-hardening.conf with sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port <port>, then reload sshd after confirming key access."
      ;;
    ssh-port-expected)
      printf '%s' "Run sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port <port> --reload-sshd after verifying key access to that port."
      ;;
    unattended-upgrades)
      printf '%s' "Enable unattended security updates with sudo dpkg-reconfigure -f noninteractive unattended-upgrades or rerun the hardening script."
      ;;
    root-disk-free)
      printf '%s' "Increase VPS disk size or prune unused Docker images, volumes and logs before production deploy."
      ;;
    memory-total)
      printf '%s' "Use a larger VPS plan before production deploy."
      ;;
    time-sync)
      printf '%s' "Enable NTP with timedatectl/systemd-timesyncd or chrony, then rerun readiness."
      ;;
    host-runtime-minimalism)
      printf '%s' "Prefer container-only runtimes; remove host Node/PHP/build tools unless explicitly needed for operations."
      ;;
    *)
      printf '%s' "Review the failed check, apply the matching runbook section, then rerun scripts/vps-host-readiness.sh --ssh-port <port> --enforce on the VPS."
      ;;
  esac
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

write_effective_sshd_config() {
  output_file="$1"
  for candidate in "sshd" "/usr/sbin/sshd" "sudo -n sshd" "sudo -n /usr/sbin/sshd"; do
    # shellcheck disable=SC2086
    if $candidate -T >"$output_file" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

service_active() {
  service="$1"
  if command_exists systemctl; then
    systemctl is-active --quiet "$service"
  else
    service "$service" status >/dev/null 2>&1
  fi
}

os_release_value() {
  key="$1"
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' /etc/os-release | sed "s/^'//;s/'$//;s/^\"//;s/\"$//"
}

check_os() {
  if [ ! -r /etc/os-release ]; then
    add_check "ubuntu-lts" "yes" "failed" "/etc/os-release is not readable"
    return
  fi
  id_value=$(os_release_value ID)
  version_value=$(os_release_value VERSION)
  pretty_name=$(os_release_value PRETTY_NAME)
  if [ "$id_value" = "ubuntu" ] && printf '%s' "$version_value" | grep -qi 'lts'; then
    add_check "ubuntu-lts" "yes" "passed" "$pretty_name"
  else
    add_check "ubuntu-lts" "yes" "failed" "expected Ubuntu LTS, got ${pretty_name:-unknown}"
  fi
}

check_command() {
  name="$1"
  command_name="$2"
  version_args="${3:---version}"
  if command_exists "$command_name"; then
    version=$("$command_name" $version_args 2>/dev/null | head -n 1 || true)
    add_check "$name" "yes" "passed" "${version:-$command_name found}"
  else
    add_check "$name" "yes" "failed" "$command_name not found"
  fi
}

check_docker() {
  check_command "docker-cli" "docker" "--version"
  if command_exists docker && docker info >/dev/null 2>&1; then
    server_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
    add_check "docker-daemon" "yes" "passed" "Docker daemon reachable ${server_version:-}"
  else
    add_check "docker-daemon" "yes" "failed" "Docker daemon is not reachable by this user"
  fi
  if command_exists docker && docker compose version >/dev/null 2>&1; then
    compose_version=$(docker compose version 2>/dev/null | head -n 1 || true)
    add_check "docker-compose-plugin" "yes" "passed" "${compose_version:-docker compose available}"
  else
    add_check "docker-compose-plugin" "yes" "failed" "docker compose plugin unavailable"
  fi
}

check_docker_daemon_hardening() {
  daemon_file=/etc/docker/daemon.json
  if [ ! -r "$daemon_file" ]; then
    add_check "docker-daemon-hardening" "yes" "failed" "$daemon_file is missing or unreadable"
    return
  fi
  missing=""
  grep -q '"live-restore"[[:space:]]*:[[:space:]]*true' "$daemon_file" || missing="$missing live-restore"
  grep -q '"no-new-privileges"[[:space:]]*:[[:space:]]*true' "$daemon_file" || missing="$missing no-new-privileges"
  grep -q '"max-size"[[:space:]]*:[[:space:]]*"10m"' "$daemon_file" || missing="$missing log-max-size"
  grep -q '"max-file"[[:space:]]*:[[:space:]]*"5"' "$daemon_file" || missing="$missing log-max-file"
  if [ -z "$missing" ]; then
    add_check "docker-daemon-hardening" "yes" "passed" "$daemon_file contains Platform hardening keys"
  else
    add_check "docker-daemon-hardening" "yes" "failed" "missing:$missing"
  fi
}

check_ufw() {
  if ! command_exists ufw; then
    add_check "ufw-active" "yes" "failed" "ufw not installed"
    return
  fi
  if [ "$(id -u)" -eq 0 ]; then
    ufw_status=$(ufw status verbose 2>/dev/null || true)
  elif command_exists sudo && sudo -n true >/dev/null 2>&1; then
    ufw_status=$(sudo -n ufw status verbose 2>/dev/null || true)
  else
    ufw_status=$(ufw status verbose 2>/dev/null || true)
  fi
  if printf '%s\n' "$ufw_status" | grep -qi 'Status: active'; then
    add_check "ufw-active" "yes" "passed" "UFW is active"
  else
    add_check "ufw-active" "yes" "failed" "UFW is not active"
  fi
  if printf '%s\n' "$ufw_status" | grep -E '(^|[[:space:]])(3306|5432|6379|4222|8080|9000|9001|9090|9093|3000|3100)/tcp' >/dev/null; then
    add_check "ufw-no-direct-internal-ports" "yes" "failed" "internal service ports are exposed in UFW"
  else
    add_check "ufw-no-direct-internal-ports" "yes" "passed" "no database/cache/admin ports exposed"
  fi
  if printf '%s\n' "$ufw_status" | grep -E "^${EXPECTED_SSH_PORT}/tcp([[:space:]]|$).*ALLOW" >/dev/null; then
    add_check "ufw-ssh-port-allowed" "yes" "passed" "UFW allows ${EXPECTED_SSH_PORT}/tcp"
  else
    add_check "ufw-ssh-port-allowed" "yes" "failed" "UFW does not show ${EXPECTED_SSH_PORT}/tcp"
  fi
}

check_services() {
  for service in fail2ban apparmor auditd; do
    if service_active "$service"; then
      add_check "$service-active" "yes" "passed" "$service is active"
    else
      add_check "$service-active" "yes" "failed" "$service is not active"
    fi
  done
}

check_ssh_hardening() {
  effective=$(mktemp)
  if write_effective_sshd_config "$effective"; then
    if grep -qi '^passwordauthentication no' "$effective"; then
      add_check "ssh-password-auth-disabled" "yes" "passed" "PasswordAuthentication no"
    else
      add_check "ssh-password-auth-disabled" "yes" "failed" "PasswordAuthentication is not disabled"
    fi
    if grep -qi '^permitrootlogin no' "$effective"; then
      add_check "ssh-root-login-disabled" "yes" "passed" "PermitRootLogin no"
    else
      add_check "ssh-root-login-disabled" "yes" "failed" "PermitRootLogin is not disabled"
    fi
    if grep -qi "^port ${EXPECTED_SSH_PORT}$" "$effective"; then
      add_check "ssh-port-expected" "yes" "passed" "effective sshd port ${EXPECTED_SSH_PORT}"
    else
      effective_ports=$(awk 'tolower($1) == "port" { print $2 }' "$effective" | paste -sd, -)
      add_check "ssh-port-expected" "yes" "failed" "expected ${EXPECTED_SSH_PORT}, effective ${effective_ports:-unknown}"
    fi
    rm -f "$effective"
  elif [ -r /etc/ssh/sshd_config.d/99-platform-hardening.conf ]; then
    rm -f "$effective"
    config=/etc/ssh/sshd_config.d/99-platform-hardening.conf
    grep -qi '^PasswordAuthentication no' "$config" \
      && add_check "ssh-password-auth-disabled" "yes" "passed" "$config contains PasswordAuthentication no" \
      || add_check "ssh-password-auth-disabled" "yes" "failed" "$config does not disable password auth"
    grep -qi '^PermitRootLogin no' "$config" \
      && add_check "ssh-root-login-disabled" "yes" "passed" "$config contains PermitRootLogin no" \
      || add_check "ssh-root-login-disabled" "yes" "failed" "$config does not disable root login"
    grep -qi "^Port ${EXPECTED_SSH_PORT}$" "$config" \
      && add_check "ssh-port-expected" "yes" "passed" "$config contains Port ${EXPECTED_SSH_PORT}" \
      || add_check "ssh-port-expected" "yes" "failed" "$config does not set Port ${EXPECTED_SSH_PORT}"
  else
    rm -f "$effective"
    add_check "ssh-hardening" "yes" "failed" "cannot inspect sshd effective config or Platform hardening file"
  fi
}

check_unattended_upgrades() {
  if [ -r /etc/apt/apt.conf.d/20auto-upgrades ] \
    && grep -q 'Unattended-Upgrade.*"1"' /etc/apt/apt.conf.d/20auto-upgrades; then
    add_check "unattended-upgrades" "yes" "passed" "automatic security upgrades enabled"
  else
    add_check "unattended-upgrades" "yes" "failed" "automatic security upgrades not confirmed"
  fi
}

check_resources() {
  free_mb=$(df -Pm / | awk 'NR == 2 { print $4 }')
  if [ "${free_mb:-0}" -ge "$MIN_ROOT_FREE_MB" ]; then
    add_check "root-disk-free" "yes" "passed" "${free_mb}MB free on /"
  else
    add_check "root-disk-free" "yes" "failed" "${free_mb:-0}MB free on /, minimum ${MIN_ROOT_FREE_MB}MB"
  fi
  memory_mb=$(awk '/MemTotal/ { print int($2 / 1024) }' /proc/meminfo 2>/dev/null || echo 0)
  if [ "${memory_mb:-0}" -ge "$MIN_MEMORY_MB" ]; then
    add_check "memory-total" "yes" "passed" "${memory_mb}MB RAM"
  else
    add_check "memory-total" "yes" "failed" "${memory_mb:-0}MB RAM, minimum ${MIN_MEMORY_MB}MB"
  fi
}

check_time_sync() {
  if command_exists timedatectl && timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi '^yes$'; then
    add_check "time-sync" "yes" "passed" "NTP synchronized"
  elif service_active systemd-timesyncd || service_active chrony; then
    add_check "time-sync" "yes" "passed" "time sync service active"
  else
    add_check "time-sync" "yes" "failed" "NTP synchronization not confirmed"
  fi
}

check_unneeded_host_runtimes() {
  found=""
  for binary in node pnpm php composer npm yarn; do
    if command_exists "$binary"; then
      found="$found $binary"
    fi
  done
  if [ -z "$found" ]; then
    add_check "host-runtime-minimalism" "no" "passed" "no Node/PHP/build runtime found on host PATH"
  else
    add_check "host-runtime-minimalism" "no" "warning" "extra host runtimes found:$found"
  fi
}

write_reports() {
  generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  failed_required=$(awk -F '\t' '$2 == "yes" && $3 == "failed" { count++ } END { print count + 0 }' "$ROWS_FILE")
  warning_count=$(awk -F '\t' '$3 == "warning" { count++ } END { print count + 0 }' "$ROWS_FILE")

  {
    printf '{\n'
    printf '  "generatedAt": "%s",\n' "$(json_escape "$generated_at")"
    printf '  "mode": "%s",\n' "$([ "$DIAGNOSTIC" -eq 1 ] && printf diagnostic || printf production)"
    printf '  "productionEvidence": %s,\n' "$([ "$DIAGNOSTIC" -eq 1 ] && printf false || printf true)"
    printf '  "minimums": {\n'
    printf '    "rootFreeMb": %s,\n' "$MIN_ROOT_FREE_MB"
    printf '    "memoryMb": %s\n' "$MIN_MEMORY_MB"
    printf '  },\n'
    printf '  "expectedSshPort": "%s",\n' "$(json_escape "$EXPECTED_SSH_PORT")"
    printf '  "summary": {\n'
    printf '    "failedRequired": %s,\n' "$failed_required"
    printf '    "warnings": %s\n' "$warning_count"
    printf '  },\n'
    printf '  "checks": [\n'
    first=1
    while IFS='	' read -r name required status detail; do
      [ -n "$name" ] || continue
      remediation=$(remediation_for_check "$name")
      if [ "$first" -eq 0 ]; then
        printf ',\n'
      fi
      first=0
      printf '    { "name": "%s", "required": %s, "status": "%s", "detail": "%s", "remediation": "%s" }' \
        "$(json_escape "$name")" \
        "$([ "$required" = "yes" ] && printf true || printf false)" \
        "$(json_escape "$status")" \
        "$(json_escape "$detail")" \
        "$(json_escape "$remediation")"
    done < "$ROWS_FILE"
    printf '\n  ]\n'
    printf '}\n'
  } > "$JSON_REPORT"

  {
    printf '# Platform VPS Host Readiness\n\n'
    printf 'Generated at: %s\n\n' "$generated_at"
    printf 'Mode: %s\n\n' "$([ "$DIAGNOSTIC" -eq 1 ] && printf diagnostic || printf production)"
    printf 'Failed required checks: %s\n\n' "$failed_required"
    printf '| Check | Required | Status | Detail | Remediation |\n'
    printf '| --- | --- | --- | --- | --- |\n'
    while IFS='	' read -r name required status detail; do
      [ -n "$name" ] || continue
      remediation=$(remediation_for_check "$name")
      printf '| %s | %s | %s | %s | %s |\n' "$name" "$required" "$status" "$detail" "$remediation"
    done < "$ROWS_FILE"
  } > "$MD_REPORT"

  echo "VPS host readiness reports written to $JSON_REPORT and $MD_REPORT"
  if [ "$failed_required" -gt 0 ] && [ "$ALLOW_FAILURES" -ne 1 ]; then
    echo "VPS host readiness failed: $failed_required required check(s) failed." >&2
    exit 1
  fi
}

check_os
check_command "git-cli" "git" "--version"
check_docker
check_docker_daemon_hardening
check_ufw
check_services
check_ssh_hardening
check_unattended_upgrades
check_resources
check_time_sync
check_unneeded_host_runtimes
write_reports
