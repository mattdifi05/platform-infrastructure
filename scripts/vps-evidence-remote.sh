#!/usr/bin/env bash
set -euo pipefail

decode_field() {
  printf '%s' "$1" | base64 -d
}

remote_dir=$(decode_field "$PLATFORM_REMOTE_DIR_B64")
hardened_ssh_port=$(decode_field "$PLATFORM_HARDENED_SSH_PORT_B64")
run_bootstrap=$(decode_field "$PLATFORM_RUN_BOOTSTRAP_B64")
run_hardening=$(decode_field "$PLATFORM_RUN_HARDENING_B64")
reload_sshd=$(decode_field "$PLATFORM_RELOAD_SSHD_B64")
replace_docker_daemon_config=$(decode_field "$PLATFORM_REPLACE_DOCKER_DAEMON_CONFIG_B64")
deploy_user=$(decode_field "$PLATFORM_DEPLOY_USER_B64")

[[ "$remote_dir" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ "$remote_dir" != *"//"* ]] && [[ "/$remote_dir/" != *"/../"* ]]
[[ "$hardened_ssh_port" =~ ^[0-9]{1,5}$ ]] && (( hardened_ssh_port >= 1 && hardened_ssh_port <= 65535 ))
for value in "$run_bootstrap" "$run_hardening" "$reload_sshd" "$replace_docker_daemon_config"; do
  [[ "$value" == "true" || "$value" == "false" ]]
done
[[ -z "$deploy_user" || "$deploy_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]

cd -- "$remote_dir"
git fetch --all --prune
git checkout main
git pull --ff-only origin main

if [[ "$run_bootstrap" == "true" ]]; then
  bootstrap_args=(--apply)
  if [[ -n "$deploy_user" ]]; then
    bootstrap_args+=(--deploy-user "$deploy_user")
  fi
  sudo sh ./scripts/vps-bootstrap-ubuntu.sh "${bootstrap_args[@]}"
fi

if [[ "$run_hardening" == "true" ]]; then
  hardening_args=(--apply --ssh-port "$hardened_ssh_port")
  if [[ "$reload_sshd" == "true" ]]; then
    hardening_args+=(--reload-sshd)
  fi
  if [[ "$replace_docker_daemon_config" == "true" ]]; then
    hardening_args+=(--replace-docker-daemon-config)
  fi
  sudo sh ./scripts/vps-hardening-ubuntu.sh "${hardening_args[@]}"
fi

sudo sh ./scripts/vps-host-readiness.sh --ssh-port "$hardened_ssh_port" --enforce

tar_paths=()
for report_path in reports/vps-bootstrap reports/vps-hardening reports/vps-host; do
  if [[ -d "$report_path" ]]; then
    tar_paths+=("$report_path")
  fi
done
if (( ${#tar_paths[@]} == 0 )); then
  echo "No VPS evidence report directories were produced." >&2
  exit 1
fi
echo "__PLATFORM_VPS_EVIDENCE_TGZ_BEGIN__"
tar -czf - "${tar_paths[@]}" | base64 -w0
echo
echo "__PLATFORM_VPS_EVIDENCE_TGZ_END__"
