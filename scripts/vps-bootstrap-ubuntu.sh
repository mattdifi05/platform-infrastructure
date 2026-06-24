#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPORT_DIR="${REPORT_DIR:-$ROOT_DIR/reports/vps-bootstrap}"
APPLY=0
DEPLOY_USER="${DEPLOY_USER:-}"
UBUNTU_CODENAME="${UBUNTU_CODENAME:-}"

usage() {
  cat <<'EOF'
Usage: vps-bootstrap-ubuntu.sh [--apply] [--deploy-user USER] [--ubuntu-codename CODENAME]

Bootstrap a Hostinger Ubuntu LTS VPS with only the host dependencies Stexor
requires: Git, Docker Engine, Docker Buildx and the Docker Compose plugin.
Dry-run by default. Re-run with --apply after reviewing the report.
Writes JSON and Markdown evidence under reports/vps-bootstrap/.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply)
      APPLY=1
      ;;
    --deploy-user)
      shift
      DEPLOY_USER="${1:?Missing value for --deploy-user}"
      ;;
    --ubuntu-codename)
      shift
      UBUNTU_CODENAME="${1:?Missing value for --ubuntu-codename}"
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
REPORT_PREFIX="vps-bootstrap-plan"
if [ "$APPLY" -eq 1 ]; then
  REPORT_PREFIX="vps-bootstrap-apply"
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
    printf '  "ubuntuCodename": "%s",\n' "$(json_escape "$UBUNTU_CODENAME")"
    printf '  "deployUser": "%s",\n' "$(json_escape "$DEPLOY_USER")"
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
    printf '# Stexor VPS Bootstrap\n\n'
    printf 'Generated at: %s\n\n' "$generated_at"
    printf 'Status: %s\n\n' "$status"
    printf 'Mode: %s\n\n' "$([ "$APPLY" -eq 1 ] && printf apply || printf plan)"
    printf 'Ubuntu codename: %s\n\n' "$UBUNTU_CODENAME"
    printf 'Deploy user: %s\n\n' "${DEPLOY_USER:-n/a}"
    printf '| Step | Status | Action | Detail |\n'
    printf '| --- | --- | --- | --- |\n'
    while IFS='	' read -r name step_status action detail; do
      [ -n "$name" ] || continue
      printf '| %s | %s | `%s` | %s |\n' "$name" "$step_status" "$action" "$detail"
    done < "$ROWS_FILE"
  } > "$MD_REPORT"

  echo "VPS bootstrap reports written to $JSON_REPORT and $MD_REPORT"
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

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

os_release_value() {
  key="$1"
  if [ ! -r /etc/os-release ]; then
    return 0
  fi
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' /etc/os-release | sed "s/^'//;s/'$//;s/^\"//;s/\"$//"
}

detect_ubuntu_codename() {
  if [ -n "$UBUNTU_CODENAME" ]; then
    printf '%s' "$UBUNTU_CODENAME"
    return
  fi
  codename=$(os_release_value UBUNTU_CODENAME)
  if [ -z "$codename" ]; then
    codename=$(os_release_value VERSION_CODENAME)
  fi
  printf '%s' "$codename"
}

detect_arch() {
  if command_exists dpkg; then
    dpkg --print-architecture
  else
    printf '<dpkg-architecture>'
  fi
}

id_value=$(os_release_value ID)
pretty_name=$(os_release_value PRETTY_NAME)
UBUNTU_CODENAME=$(detect_ubuntu_codename)
ARCHITECTURE=$(detect_arch)

if [ "$APPLY" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  fail_step "root-check" "id -u" "apply mode requires root"
fi

if [ "$APPLY" -eq 1 ] && [ "$id_value" != "ubuntu" ]; then
  fail_step "ubuntu-check" "read /etc/os-release" "expected Ubuntu, got ${pretty_name:-unknown}"
fi

if [ "$APPLY" -eq 1 ] && [ -z "$UBUNTU_CODENAME" ]; then
  fail_step "ubuntu-codename" "read /etc/os-release" "cannot determine Ubuntu codename; pass --ubuntu-codename"
fi

if [ -z "$UBUNTU_CODENAME" ]; then
  UBUNTU_CODENAME="<ubuntu-codename>"
fi

echo "==> Ubuntu package baseline"
run apt-get update
run apt-get install -y ca-certificates curl git

echo "==> Docker official apt repository"
run install -m 0755 -d /etc/apt/keyrings
run curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
run chmod a+r /etc/apt/keyrings/docker.asc
write_file /etc/apt/sources.list.d/docker.sources 0644 "Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME}
Components: stable
Architectures: ${ARCHITECTURE}
Signed-By: /etc/apt/keyrings/docker.asc"

echo "==> Docker Engine and Compose plugin"
run apt-get update
run apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
run systemctl enable --now docker

if [ -n "$DEPLOY_USER" ]; then
  echo "==> Docker group access for deploy user"
  run usermod -aG docker "$DEPLOY_USER"
else
  add_step "deploy-user" "skipped" "usermod -aG docker <deploy-user>" "pass --deploy-user after reviewing least-privilege policy"
fi

echo "==> Verification commands"
run docker --version
run docker compose version
run git --version

write_reports
if [ "$APPLY" -eq 1 ]; then
  echo "VPS bootstrap apply complete. Log out/in if a deploy user was added to the docker group, then run vps-hardening and vps-host-readiness."
else
  echo "VPS bootstrap dry-run complete. Re-run with --apply on the Hostinger Ubuntu LTS VPS."
fi
