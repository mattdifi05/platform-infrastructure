#!/usr/bin/env bash
set -euo pipefail

echo "V1 brownfield existing-host path is STOP: remote caller values cannot replace the verified PRE-DEPLOY backup and authenticated provider gates." >&2
exit 78

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
workflow_sha=$(decode_field "$PLATFORM_WORKFLOW_SHA_B64")
workflow_tree=$(decode_field "$PLATFORM_WORKFLOW_TREE_B64")

[[ "$remote_dir" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ "$remote_dir" != *"//"* ]] && [[ "/$remote_dir/" != *"/../"* ]]
[[ "$hardened_ssh_port" =~ ^[0-9]{1,5}$ ]] && (( hardened_ssh_port >= 1 && hardened_ssh_port <= 65535 ))
for value in "$run_bootstrap" "$run_hardening" "$reload_sshd" "$replace_docker_daemon_config"; do
  [[ "$value" == "true" || "$value" == "false" ]]
done
[[ -z "$deploy_user" || "$deploy_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
[[ "$workflow_sha" =~ ^[a-f0-9]{40}$ ]]
[[ "$workflow_tree" =~ ^[a-f0-9]{40}$ ]]

git -C "$remote_dir" fetch --no-tags --prune origin "$workflow_sha"
actual_commit=$(git -C "$remote_dir" rev-parse --verify "$workflow_sha^{commit}")
actual_tree=$(git -C "$remote_dir" rev-parse --verify "$workflow_sha^{tree}")
[[ "$actual_commit" == "$workflow_sha" ]]
[[ "$actual_tree" == "$workflow_tree" ]]

checkout_parent=$(mktemp -d "${TMPDIR:-/tmp}/platform-vps-evidence.XXXXXX")
checkout_dir="$checkout_parent/checkout"
archive_path="$checkout_parent/vps-evidence.tgz"
cleanup() {
  cd /
  git -C "$remote_dir" worktree remove --force "$checkout_dir" >/dev/null 2>&1 || true
  rm -rf -- "$checkout_parent"
}
trap cleanup EXIT INT TERM

git -C "$remote_dir" worktree add --detach "$checkout_dir" "$workflow_sha"
cd -- "$checkout_dir"
[[ "$(git rev-parse --verify HEAD)" == "$workflow_sha" ]]
[[ "$(git rev-parse --verify HEAD^{tree})" == "$workflow_tree" ]]
if git symbolic-ref -q HEAD >/dev/null 2>&1; then
  echo "VPS evidence checkout is not detached." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "VPS evidence checkout is dirty before collection." >&2
  exit 1
fi

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

[[ "$(git rev-parse --verify HEAD)" == "$workflow_sha" ]]
[[ "$(git rev-parse --verify HEAD^{tree})" == "$workflow_tree" ]]
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "VPS evidence checkout is dirty after collection." >&2
  exit 1
fi

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

while IFS= read -r -d '' report_entry; do
  relative_entry=${report_entry#./}
  if [[ -L "$report_entry" ]] || [[ ! -f "$report_entry" && ! -d "$report_entry" ]]; then
    echo "VPS evidence contains a symlink or unsupported file type: $relative_entry" >&2
    exit 1
  fi
  if [[ ! "$relative_entry" =~ ^reports/(vps-bootstrap|vps-hardening|vps-host)(/[A-Za-z0-9._-]+)*$ ]]; then
    echo "VPS evidence contains an unsafe report path: $relative_entry" >&2
    exit 1
  fi
done < <(find "${tar_paths[@]}" -mindepth 0 -print0)

tar -czf "$archive_path" -- "${tar_paths[@]}"
archive_sha256=$(sha256sum "$archive_path" | awk '{print $1}')
[[ "$archive_sha256" =~ ^[a-f0-9]{64}$ ]]
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
receipt=$(printf '{"schema":"platform.vps-evidence-receipt/v1","generatedAt":"%s","workflowSha":"%s","gitTree":"%s","checkoutMode":"detached","cleanBefore":true,"cleanAfter":true,"archiveSha256":"%s"}' "$generated_at" "$workflow_sha" "$workflow_tree" "$archive_sha256")

echo "__PLATFORM_VPS_EVIDENCE_RECEIPT_BEGIN__"
printf '%s' "$receipt" | base64 -w0
echo
echo "__PLATFORM_VPS_EVIDENCE_RECEIPT_END__"
echo "__PLATFORM_VPS_EVIDENCE_TGZ_BEGIN__"
base64 -w0 "$archive_path"
echo
echo "__PLATFORM_VPS_EVIDENCE_TGZ_END__"
