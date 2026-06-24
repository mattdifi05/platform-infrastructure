#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPORT_DIR="${REPORT_DIR:-$ROOT_DIR/reports/vps-hardening}"
APPLY=0
SSH_PORT="${SSH_PORT:-22}"
REPLACE_DOCKER_DAEMON_CONFIG=0
DOCKER_DAEMON_CONFIG_CHANGED=0
RELOAD_SSHD=0

usage() {
  cat <<'EOF'
Usage: vps-hardening-ubuntu.sh [--apply] [--ssh-port PORT] [--replace-docker-daemon-config] [--reload-sshd]

Harden an Ubuntu LTS VPS for the Platform single-node Docker profile.
Dry-run by default. Re-run with --apply after reviewing the actions.
Writes JSON and Markdown evidence under reports/vps-hardening/.

By default, apply mode writes a hardened /etc/docker/daemon.json only when the
file is absent or already contains the required Platform keys. If an existing
daemon config is missing required keys, review the generated template and rerun
with --replace-docker-daemon-config to back up and replace it.

Use --reload-sshd only after SSH key access and the target SSH port are verified.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply)
      APPLY=1
      ;;
    --ssh-port)
      shift
      SSH_PORT="${1:?Missing value for --ssh-port}"
      ;;
    --replace-docker-daemon-config)
      REPLACE_DOCKER_DAEMON_CONFIG=1
      ;;
    --reload-sshd)
      RELOAD_SSHD=1
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

mkdir -p "$REPORT_DIR"
STAMP=$(date -u +%Y%m%d%H%M%S)
ROWS_FILE=$(mktemp)
REPORT_PREFIX="vps-hardening-plan"
if [ "$APPLY" -eq 1 ]; then
  REPORT_PREFIX="vps-hardening-apply"
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

add_step() {
  name="$1"
  status="$2"
  action="$3"
  detail="$4"
  printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$action" "$detail" >> "$ROWS_FILE"
}

write_reports() {
  generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  failed_count=$(awk -F '\t' '$2 == "failed" { count++ } END { print count + 0 }' "$ROWS_FILE")
  if [ "$failed_count" -gt 0 ]; then
    status="failed"
  elif [ "$APPLY" -eq 1 ]; then
    status="applied"
  else
    status="planned"
  fi

  {
    printf '{\n'
    printf '  "generatedAt": "%s",\n' "$(json_escape "$generated_at")"
    printf '  "status": "%s",\n' "$status"
    printf '  "mode": "%s",\n' "$([ "$APPLY" -eq 1 ] && printf apply || printf plan)"
    printf '  "sshPort": "%s",\n' "$(json_escape "$SSH_PORT")"
    printf '  "options": {\n'
    printf '    "reloadSshd": %s,\n' "$([ "$RELOAD_SSHD" -eq 1 ] && printf true || printf false)"
    printf '    "replaceDockerDaemonConfig": %s\n' "$([ "$REPLACE_DOCKER_DAEMON_CONFIG" -eq 1 ] && printf true || printf false)"
    printf '  },\n'
    printf '  "report": {\n'
    printf '    "jsonPath": "%s",\n' "$(json_escape "$JSON_REPORT")"
    printf '    "markdownPath": "%s"\n' "$(json_escape "$MD_REPORT")"
    printf '  },\n'
    printf '  "steps": [\n'
    first=1
    while IFS='	' read -r name step_status action detail; do
      [ -n "$name" ] || continue
      if [ "$first" -eq 0 ]; then
        printf ',\n'
      fi
      first=0
      printf '    { "name": "%s", "status": "%s", "action": "%s", "detail": "%s" }' \
        "$(json_escape "$name")" \
        "$(json_escape "$step_status")" \
        "$(json_escape "$action")" \
        "$(json_escape "$detail")"
    done < "$ROWS_FILE"
    printf '\n  ]\n'
    printf '}\n'
  } > "$JSON_REPORT"

  {
    printf '# Platform VPS Hardening\n\n'
    printf 'Generated at: %s\n\n' "$generated_at"
    printf 'Status: %s\n\n' "$status"
    printf 'Mode: %s\n\n' "$([ "$APPLY" -eq 1 ] && printf apply || printf plan)"
    printf 'SSH port: %s\n\n' "$SSH_PORT"
    printf '| Step | Status | Action | Detail |\n'
    printf '| --- | --- | --- | --- |\n'
    while IFS='	' read -r name step_status action detail; do
      [ -n "$name" ] || continue
      printf '| %s | %s | `%s` | %s |\n' "$name" "$step_status" "$action" "$detail"
    done < "$ROWS_FILE"
  } > "$MD_REPORT"

  echo "VPS hardening reports written to $JSON_REPORT and $MD_REPORT"
}

fail_step() {
  name="$1"
  action="$2"
  detail="$3"
  add_step "$name" "failed" "$action" "$detail"
  write_reports
  exit 1
}

run() {
  action="$*"
  if [ "$APPLY" -eq 1 ]; then
    echo "+ $action"
    if "$@"; then
      add_step "command" "applied" "$action" "completed"
    else
      code="$?"
      fail_step "command" "$action" "exit code $code"
    fi
  else
    echo "DRY-RUN: $action"
    add_step "command" "planned" "$action" "not executed"
  fi
}

write_file() {
  path="$1"
  mode="$2"
  content="$3"
  if [ "$APPLY" -eq 1 ]; then
    tmp="$(mktemp)"
    printf '%s\n' "$content" > "$tmp"
    if install -m "$mode" "$tmp" "$path"; then
      add_step "write-file" "applied" "write $path" "mode $mode"
    else
      code="$?"
      rm -f "$tmp"
      fail_step "write-file" "write $path" "exit code $code"
    fi
    rm -f "$tmp"
    echo "+ wrote $path"
  else
    echo "DRY-RUN: write $path"
    printf '%s\n' "$content"
    add_step "write-file" "planned" "write $path" "mode $mode"
  fi
}

daemon_contains_hardening() {
  daemon_file="$1"
  [ -r "$daemon_file" ] || return 1
  grep -q '"live-restore"[[:space:]]*:[[:space:]]*true' "$daemon_file" || return 1
  grep -q '"no-new-privileges"[[:space:]]*:[[:space:]]*true' "$daemon_file" || return 1
  grep -q '"max-size"[[:space:]]*:[[:space:]]*"10m"' "$daemon_file" || return 1
  grep -q '"max-file"[[:space:]]*:[[:space:]]*"5"' "$daemon_file" || return 1
  return 0
}

restart_docker_if_changed() {
  [ "$DOCKER_DAEMON_CONFIG_CHANGED" -eq 1 ] || return 0
  if [ "$APPLY" -eq 0 ]; then
    add_step "command" "planned" "systemctl restart docker" "restart after daemon config update"
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files docker.service 2>/dev/null | grep -q '^docker\.service'; then
    run systemctl restart docker
  else
    add_step "command" "skipped" "systemctl restart docker" "docker.service not available; rerun readiness after Docker Engine is installed"
  fi
}

apply_docker_daemon_config() {
  daemon_path=/etc/docker/daemon.json
  backup_path="/etc/docker/daemon.json.platform-backup-$STAMP"
  if [ "$APPLY" -eq 0 ]; then
    if [ -f "$daemon_path" ]; then
      add_step "docker-daemon-config" "planned" "validate $daemon_path" "existing config will be checked; missing keys require --replace-docker-daemon-config"
    else
      add_step "docker-daemon-config" "planned" "write $daemon_path" "hardened config will be written because file is absent"
      DOCKER_DAEMON_CONFIG_CHANGED=1
    fi
    restart_docker_if_changed
    return 0
  fi

  if [ -r "$daemon_path" ] && daemon_contains_hardening "$daemon_path"; then
    add_step "docker-daemon-config" "applied" "validate $daemon_path" "already contains Platform hardening keys"
    return 0
  fi

  if [ -f "$daemon_path" ] && [ "$REPLACE_DOCKER_DAEMON_CONFIG" -ne 1 ]; then
    fail_step "docker-daemon-config" "write $daemon_path" "existing daemon config is missing Platform hardening keys; review /etc/docker/daemon.json.platform-template and rerun with --replace-docker-daemon-config"
  fi

  if [ -f "$daemon_path" ]; then
    run cp "$daemon_path" "$backup_path"
  fi
  write_file "$daemon_path" 0644 "$DOCKER_DAEMON_CONFIG"
  DOCKER_DAEMON_CONFIG_CHANGED=1
  if daemon_contains_hardening "$daemon_path"; then
    add_step "docker-daemon-config" "applied" "validate $daemon_path" "contains Platform hardening keys"
  else
    fail_step "docker-daemon-config" "validate $daemon_path" "required Platform hardening keys are still missing"
  fi
  restart_docker_if_changed
}

reload_sshd_if_requested() {
  if [ "$RELOAD_SSHD" -ne 1 ]; then
    add_step "ssh-service-reload" "skipped" "systemctl reload ssh" "enable with --reload-sshd after SSH key access and target port are verified"
    return 0
  fi
  if [ "$APPLY" -eq 0 ]; then
    add_step "ssh-config-validate" "planned" "sshd -t" "validate before reload"
    add_step "ssh-service-reload" "planned" "systemctl reload ssh" "reload after config validation"
    return 0
  fi
  if ! command -v sshd >/dev/null 2>&1; then
    fail_step "ssh-config-validate" "sshd -t" "sshd command not found"
  fi
  if sshd -t; then
    add_step "ssh-config-validate" "applied" "sshd -t" "configuration valid"
  else
    code="$?"
    fail_step "ssh-config-validate" "sshd -t" "exit code $code"
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    fail_step "ssh-service-reload" "systemctl reload ssh" "systemctl not found"
  fi
  if systemctl reload ssh >/dev/null 2>&1; then
    add_step "ssh-service-reload" "applied" "systemctl reload ssh" "completed"
  elif systemctl reload sshd >/dev/null 2>&1; then
    add_step "ssh-service-reload" "applied" "systemctl reload sshd" "completed"
  else
    fail_step "ssh-service-reload" "systemctl reload ssh/sshd" "reload failed"
  fi
}

if [ "$APPLY" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "Run as root on the VPS, for example: sudo $0 --apply" >&2
  fail_step "root-check" "id -u" "apply mode requires root"
fi

echo "==> Ubuntu package baseline"
run apt-get update
run apt-get install -y ca-certificates curl gnupg ufw fail2ban unattended-upgrades auditd apparmor apparmor-utils

echo "==> SSH hardening"
write_file /etc/ssh/sshd_config.d/99-platform-hardening.conf 0644 "Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2"

echo "==> Kernel network hardening"
write_file /etc/sysctl.d/99-platform-hardening.conf 0644 "net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0"
run sysctl --system

echo "==> Unattended security updates"
run dpkg-reconfigure -f noninteractive unattended-upgrades
write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 "APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";"

echo "==> UFW baseline"
run ufw default deny incoming
run ufw default allow outgoing
run ufw allow "${SSH_PORT}/tcp"
run ufw allow 80/tcp
run ufw allow 443/tcp
run ufw --force enable
reload_sshd_if_requested

echo "==> fail2ban baseline"
write_file /etc/fail2ban/jail.d/platform-sshd.conf 0644 "[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 5
findtime = 10m
bantime = 1h"
run systemctl enable --now fail2ban
run systemctl restart fail2ban

echo "==> Docker daemon hardening template"
if [ ! -d /etc/docker ]; then
  run mkdir -p /etc/docker
fi
DOCKER_DAEMON_CONFIG="{
  \"icc\": false,
  \"live-restore\": true,
  \"log-driver\": \"json-file\",
  \"log-opts\": {
    \"max-size\": \"10m\",
    \"max-file\": \"5\"
  },
  \"no-new-privileges\": true
}"
write_file /etc/docker/daemon.json.platform-template 0644 "$DOCKER_DAEMON_CONFIG"
apply_docker_daemon_config

echo "Docker daemon hardening is applied automatically when /etc/docker/daemon.json is absent or already compatible."
echo "If an existing daemon config blocks the report, review the template and rerun with --replace-docker-daemon-config."
write_reports
if [ "$APPLY" -eq 1 ]; then
  echo "VPS hardening apply complete. Review reports and rerun vps-host-readiness --enforce."
else
  echo "VPS hardening dry-run complete. Re-run with --apply to apply changes."
fi
