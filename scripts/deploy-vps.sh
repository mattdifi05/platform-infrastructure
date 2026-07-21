#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
umask 077

REMOTE="${DEPLOY_REMOTE:-}"
REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/platform/platform-infrastructure}"
SSH_PORT="${DEPLOY_SSH_PORT:-22}"
SSH_KEY_PATH="${DEPLOY_SSH_KEY_PATH:-$HOME/.ssh/deploy_key}"
SSH_KNOWN_HOSTS_PATH="${DEPLOY_SSH_KNOWN_HOSTS_PATH:-$HOME/.ssh/known_hosts}"
BRANCH="${DEPLOY_BRANCH:-main}"
ENV_FILE="${DEPLOY_ENV_FILE:-.env}"
PROJECT_NAME="${DEPLOY_PROJECT_NAME:-platform_infra_vps}"
RELEASE_SHA="${DEPLOY_RELEASE_SHA:-}"
RELEASE_TREE="${DEPLOY_RELEASE_TREE:-}"
DEPLOY_REPO="${DEPLOY_REPO:-}"
ARTIFACT_RECEIPT="${DEPLOY_ARTIFACT_RECEIPT_PATH:-}"
ARTIFACT_RECEIPT_SHA256="${DEPLOY_ARTIFACT_RECEIPT_SHA256:-}"
ADMISSION_RECEIPT="${DEPLOY_ADMISSION_RECEIPT_PATH:-}"
ADMISSION_RECEIPT_SHA256="${DEPLOY_ADMISSION_RECEIPT_SHA256:-}"
ADMISSION_POLICY="$ROOT_DIR/governance/deployment-admission.json"
if [ -n "${DEPLOY_ADMISSION_POLICY_PATH:-}" ]; then
  [ "${PLATFORM_DEPLOY_TEST_MODE:-0}" = 1 ] || { echo "DEPLOY_ADMISSION_POLICY_PATH is test-only." >&2; exit 1; }
  ADMISSION_POLICY=$DEPLOY_ADMISSION_POLICY_PATH
fi

case "$REMOTE" in
  *@*) remote_user=${REMOTE%%@*}; remote_host=${REMOTE#*@} ;;
  *) echo "DEPLOY_REMOTE must be a simple user@hostname value." >&2; exit 1 ;;
esac
case "$remote_user" in [a-z_]*) ;; *) echo "DEPLOY_REMOTE contains an invalid user." >&2; exit 1 ;; esac
case "$remote_user" in *[!a-z0-9_-]* ) echo "DEPLOY_REMOTE contains an invalid user." >&2; exit 1 ;; esac
case "$remote_host" in [A-Za-z0-9]*) ;; *) echo "DEPLOY_REMOTE contains an invalid hostname." >&2; exit 1 ;; esac
case "$remote_host" in *[!A-Za-z0-9.-]*|*@*|*..*|*-|*. ) echo "DEPLOY_REMOTE contains an invalid hostname." >&2; exit 1 ;; esac
case "$REMOTE_DIR" in /*) ;; *) echo "DEPLOY_REMOTE_DIR must be absolute." >&2; exit 1 ;; esac
case "$REMOTE_DIR" in *[!A-Za-z0-9_./-]*|*//*|*/../*|*/..) echo "DEPLOY_REMOTE_DIR contains invalid syntax." >&2; exit 1 ;; esac
case "$SSH_PORT" in ''|*[!0-9]*) echo "DEPLOY_SSH_PORT must be numeric." >&2; exit 1 ;; esac
[ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] || { echo "DEPLOY_SSH_PORT must be between 1 and 65535." >&2; exit 1; }
case "$SSH_KNOWN_HOSTS_PATH" in /*) ;; *) echo "DEPLOY_SSH_KNOWN_HOSTS_PATH must be absolute." >&2; exit 1 ;; esac
[ -f "$SSH_KEY_PATH" ] && [ -r "$SSH_KEY_PATH" ] && [ -s "$SSH_KEY_PATH" ] && [ ! -L "$SSH_KEY_PATH" ] || {
  echo "DEPLOY_SSH_KEY_PATH must be a readable, non-empty dedicated private-key file, not a symlink." >&2
  exit 1
}
[ -f "$SSH_KNOWN_HOSTS_PATH" ] && [ -r "$SSH_KNOWN_HOSTS_PATH" ] && [ -s "$SSH_KNOWN_HOSTS_PATH" ] && [ ! -L "$SSH_KNOWN_HOSTS_PATH" ] || {
  echo "DEPLOY_SSH_KNOWN_HOSTS_PATH must be a readable, non-empty owner-approved regular file, not a symlink." >&2
  exit 1
}
request_dir=$(mktemp -d "${TMPDIR:-/tmp}/platform-deploy-request.XXXXXX")
trap 'rm -rf "$request_dir"' EXIT HUP INT TERM
stable_ssh_key="$request_dir/deploy_key"
stable_known_hosts="$request_dir/known_hosts"
cp "$SSH_KEY_PATH" "$stable_ssh_key"
cp "$SSH_KNOWN_HOSTS_PATH" "$stable_known_hosts"
chmod 600 "$stable_ssh_key" "$stable_known_hosts"
[ -s "$stable_ssh_key" ] && [ -s "$stable_known_hosts" ] || { echo "Stable SSH identity snapshot is incomplete." >&2; exit 1; }
SSH_KEY_PATH=$stable_ssh_key
SSH_KNOWN_HOSTS_PATH=$stable_known_hosts
case "$ENV_FILE" in [A-Za-z0-9._/-]* ) ;; *) echo "DEPLOY_ENV_FILE is invalid." >&2; exit 1 ;; esac
case "$ENV_FILE" in /*|*..*|*//*|*/ ) echo "DEPLOY_ENV_FILE must be a contained relative path." >&2; exit 1 ;; esac
case "$PROJECT_NAME" in [a-z0-9]* ) ;; *) echo "DEPLOY_PROJECT_NAME is invalid." >&2; exit 1 ;; esac
case "$PROJECT_NAME" in *[!a-z0-9_-]* ) echo "DEPLOY_PROJECT_NAME is invalid." >&2; exit 1 ;; esac
case "$DEPLOY_REPO" in [A-Za-z0-9_.-]*/[A-Za-z0-9_.-]* ) ;; *) echo "DEPLOY_REPO must be exact owner/name." >&2; exit 1 ;; esac
case "$RELEASE_SHA" in *[!a-f0-9]*|'') echo "DEPLOY_RELEASE_SHA must be a lowercase full Git SHA." >&2; exit 1 ;; esac
case "$RELEASE_TREE" in *[!a-f0-9]*|'') echo "DEPLOY_RELEASE_TREE must be a lowercase full Git tree SHA." >&2; exit 1 ;; esac
[ "${#RELEASE_SHA}" -eq 40 ] && [ "${#RELEASE_TREE}" -eq 40 ] || { echo "Release commit and tree SHA must each contain 40 characters." >&2; exit 1; }
CANONICAL_ORIGIN="https://github.com/${DEPLOY_REPO}.git"

require_gate_enabled() {
  [ "$2" = 1 ] || { echo "$1=1 is mandatory for the production deployment entrypoint." >&2; exit 1; }
}

run_waf_smoke=${DEPLOY_RUN_WAF_SMOKE:-}
run_infra_health=${DEPLOY_RUN_INFRA_HEALTH:-}
run_production_preflight=${DEPLOY_RUN_PRODUCTION_PREFLIGHT:-}
run_pre_go_live=${DEPLOY_RUN_PRE_GO_LIVE:-}
run_go_no_go=${DEPLOY_RUN_GO_NO_GO:-}
pre_go_live_production_preflight=${DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT:-}
pre_go_live_restore_drill=${DEPLOY_PRE_GO_LIVE_RESTORE_DRILL:-}
pre_go_live_offsite_restore_dry_run=${DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN:-}
pre_go_live_github_remote=${DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE:-}
require_gate_enabled DEPLOY_RUN_WAF_SMOKE "$run_waf_smoke"
require_gate_enabled DEPLOY_RUN_INFRA_HEALTH "$run_infra_health"
require_gate_enabled DEPLOY_RUN_PRODUCTION_PREFLIGHT "$run_production_preflight"
require_gate_enabled DEPLOY_RUN_PRE_GO_LIVE "$run_pre_go_live"
require_gate_enabled DEPLOY_RUN_GO_NO_GO "$run_go_no_go"
require_gate_enabled DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT "$pre_go_live_production_preflight"
require_gate_enabled DEPLOY_PRE_GO_LIVE_RESTORE_DRILL "$pre_go_live_restore_drill"
require_gate_enabled DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN "$pre_go_live_offsite_restore_dry_run"
require_gate_enabled DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE "$pre_go_live_github_remote"

case "$ARTIFACT_RECEIPT_SHA256:$ADMISSION_RECEIPT_SHA256" in *[!a-f0-9:]*|:*) echo "Both expected receipt SHA256 values are required and must be lowercase." >&2; exit 1 ;; esac
[ "${#ARTIFACT_RECEIPT_SHA256}" -eq 64 ] && [ "${#ADMISSION_RECEIPT_SHA256}" -eq 64 ] || { echo "Both expected receipt SHA256 values must be complete." >&2; exit 1; }
for receipt in "$ARTIFACT_RECEIPT" "$ADMISSION_RECEIPT"; do
  [ -f "$receipt" ] && [ -r "$receipt" ] && [ -s "$receipt" ] && [ ! -L "$receipt" ] || { echo "Deployment receipt input is missing, unreadable, empty, or a symlink." >&2; exit 1; }
done

head_sha=$(git -C "$ROOT_DIR" rev-parse HEAD)
tree_sha=$(git -C "$ROOT_DIR" rev-parse "${RELEASE_SHA}^{tree}")
[ "$head_sha" = "$RELEASE_SHA" ] && [ "$tree_sha" = "$RELEASE_TREE" ] || { echo "Local checkout is not the exact approved commit/tree." >&2; exit 1; }
[ -z "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=all)" ] || { echo "Local release checkout is dirty." >&2; exit 1; }

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

stable_artifact_receipt="$request_dir/artifact-verification.json"
stable_admission_receipt="$request_dir/trusted-deployment-admission.json"
cp "$ARTIFACT_RECEIPT" "$stable_artifact_receipt"
cp "$ADMISSION_RECEIPT" "$stable_admission_receipt"
chmod 600 "$stable_artifact_receipt" "$stable_admission_receipt"
[ "$(hash_file "$stable_artifact_receipt")" = "$ARTIFACT_RECEIPT_SHA256" ] || { echo "Artifact verification receipt SHA256 mismatch." >&2; exit 1; }
[ "$(hash_file "$stable_admission_receipt")" = "$ADMISSION_RECEIPT_SHA256" ] || { echo "Trusted deployment receipt SHA256 mismatch." >&2; exit 1; }
node "$SCRIPT_DIR/deployment-receipt-policy.mjs" \
  --policy "$ADMISSION_POLICY" \
  --artifactReceipt "$stable_artifact_receipt" \
  --artifactReceiptSha256 "$ARTIFACT_RECEIPT_SHA256" \
  --deploymentReceipt "$stable_admission_receipt" \
  --deploymentReceiptSha256 "$ADMISSION_RECEIPT_SHA256" \
  --repo "$DEPLOY_REPO" --commit "$RELEASE_SHA" --tree "$RELEASE_TREE" >/dev/null

encode() { printf '%s' "$1" | base64 | tr -d '\r\n'; }
encode_file() { base64 < "$1" | tr -d '\r\n'; }

node "$SCRIPT_DIR/pinned-ssh-host-key.mjs" verify \
  --remote "$REMOTE" \
  --port "$SSH_PORT" \
  --file "$SSH_KNOWN_HOSTS_PATH" >/dev/null || {
    echo "Pinned SSH host trust validation failed." >&2
    exit 1
  }

set -- -F /dev/null -i "$SSH_KEY_PATH" -p "$SSH_PORT" \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=$SSH_KNOWN_HOSTS_PATH" \
  -o GlobalKnownHostsFile=/dev/null \
  -o UpdateHostKeys=no

request_file="$request_dir/request.sh"
{
  printf "PLATFORM_REMOTE_DIR_B64='%s'\n" "$(encode "$REMOTE_DIR")"
  printf "PLATFORM_ENV_FILE_B64='%s'\n" "$(encode "$ENV_FILE")"
  printf "PLATFORM_PROJECT_NAME_B64='%s'\n" "$(encode "$PROJECT_NAME")"
  printf "PLATFORM_RELEASE_SHA_B64='%s'\n" "$(encode "$RELEASE_SHA")"
  printf "PLATFORM_RELEASE_TREE_B64='%s'\n" "$(encode "$RELEASE_TREE")"
  printf "PLATFORM_DEPLOY_REPO_B64='%s'\n" "$(encode "$DEPLOY_REPO")"
  printf "PLATFORM_CANONICAL_ORIGIN_B64='%s'\n" "$(encode "$CANONICAL_ORIGIN")"
  printf "PLATFORM_ARTIFACT_RECEIPT_SHA256_B64='%s'\n" "$(encode "$ARTIFACT_RECEIPT_SHA256")"
  printf "PLATFORM_ADMISSION_RECEIPT_SHA256_B64='%s'\n" "$(encode "$ADMISSION_RECEIPT_SHA256")"
  printf "PLATFORM_ARTIFACT_RECEIPT_B64='%s'\n" "$(encode_file "$stable_artifact_receipt")"
  printf "PLATFORM_ADMISSION_RECEIPT_B64='%s'\n" "$(encode_file "$stable_admission_receipt")"
  printf "PLATFORM_RUN_WAF_SMOKE_B64='%s'\n" "$(encode "$run_waf_smoke")"
  printf "PLATFORM_RUN_INFRA_HEALTH_B64='%s'\n" "$(encode "$run_infra_health")"
  printf "PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64='%s'\n" "$(encode "$run_production_preflight")"
  printf "PLATFORM_RUN_PRE_GO_LIVE_B64='%s'\n" "$(encode "$run_pre_go_live")"
  printf "PLATFORM_RUN_GO_NO_GO_B64='%s'\n" "$(encode "$run_go_no_go")"
  printf "PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64='%s'\n" "$(encode "$pre_go_live_production_preflight")"
  printf "PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64='%s'\n" "$(encode "$pre_go_live_restore_drill")"
  printf "PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64='%s'\n" "$(encode "$pre_go_live_offsite_restore_dry_run")"
  printf "PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64='%s'\n" "$(encode "$pre_go_live_github_remote")"
  cat "$SCRIPT_DIR/deploy-vps-remote.sh"
} > "$request_file"

ssh "$@" "$REMOTE" 'sh -s' < "$request_file"
