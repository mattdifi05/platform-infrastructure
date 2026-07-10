#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
umask 077

REMOTE="${DEPLOY_REMOTE:-}"
REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/platform/platform-infrastructure}"
SSH_PORT="${DEPLOY_SSH_PORT:-22}"
SSH_KEY_PATH="${DEPLOY_SSH_KEY_PATH:-$HOME/.ssh/deploy_key}"
BRANCH="${DEPLOY_BRANCH:-main}"
ENV_FILE="${DEPLOY_ENV_FILE:-.env}"
PROJECT_NAME="${DEPLOY_PROJECT_NAME:-platform_infra_vps}"

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

case "$SSH_PORT" in
  ''|*[!0-9]*)
    echo "DEPLOY_SSH_PORT must be numeric." >&2
    exit 1
    ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "DEPLOY_SSH_PORT must be between 1 and 65535." >&2
  exit 1
fi
case "$BRANCH" in [A-Za-z0-9]* ) ;; *) echo "DEPLOY_BRANCH is invalid." >&2; exit 1 ;; esac
case "$BRANCH" in *[!A-Za-z0-9._/-]*|*..*|*/ ) echo "DEPLOY_BRANCH is invalid." >&2; exit 1 ;; esac
case "$ENV_FILE" in [A-Za-z0-9._/-]* ) ;; *) echo "DEPLOY_ENV_FILE is invalid." >&2; exit 1 ;; esac
case "$ENV_FILE" in /*|*..*|*//*|*/ ) echo "DEPLOY_ENV_FILE must be a contained relative path." >&2; exit 1 ;; esac
case "$PROJECT_NAME" in [a-z0-9]* ) ;; *) echo "DEPLOY_PROJECT_NAME is invalid." >&2; exit 1 ;; esac
case "$PROJECT_NAME" in *[!a-z0-9_-]* ) echo "DEPLOY_PROJECT_NAME is invalid." >&2; exit 1 ;; esac

validate_bool() {
  case "$2" in 0|1) ;; *) echo "$1 must be 0 or 1." >&2; exit 1 ;; esac
}

run_waf_smoke=${DEPLOY_RUN_WAF_SMOKE:-1}
run_infra_health=${DEPLOY_RUN_INFRA_HEALTH:-1}
run_production_preflight=${DEPLOY_RUN_PRODUCTION_PREFLIGHT:-0}
run_pre_go_live=${DEPLOY_RUN_PRE_GO_LIVE:-0}
run_go_no_go=${DEPLOY_RUN_GO_NO_GO:-0}
pre_go_live_production_preflight=${DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT:-1}
pre_go_live_restore_drill=${DEPLOY_PRE_GO_LIVE_RESTORE_DRILL:-0}
pre_go_live_offsite_restore_dry_run=${DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN:-0}
pre_go_live_github_remote=${DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE:-0}
validate_bool DEPLOY_RUN_WAF_SMOKE "$run_waf_smoke"
validate_bool DEPLOY_RUN_INFRA_HEALTH "$run_infra_health"
validate_bool DEPLOY_RUN_PRODUCTION_PREFLIGHT "$run_production_preflight"
validate_bool DEPLOY_RUN_PRE_GO_LIVE "$run_pre_go_live"
validate_bool DEPLOY_RUN_GO_NO_GO "$run_go_no_go"
validate_bool DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT "$pre_go_live_production_preflight"
validate_bool DEPLOY_PRE_GO_LIVE_RESTORE_DRILL "$pre_go_live_restore_drill"
validate_bool DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN "$pre_go_live_offsite_restore_dry_run"
validate_bool DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE "$pre_go_live_github_remote"

deploy_repo=${DEPLOY_REPO:-}
case "$deploy_repo" in ""|[A-Za-z0-9_.-]*/[A-Za-z0-9_.-]* ) ;; *) echo "DEPLOY_REPO must be empty or owner/name." >&2; exit 1 ;; esac

encode() {
  printf '%s' "$1" | base64 | tr -d '\r\n'
}

set -- -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new
if [ -f "$SSH_KEY_PATH" ]; then
  set -- -i "$SSH_KEY_PATH" "$@"
fi

request_file=$(mktemp "${TMPDIR:-/tmp}/platform-deploy-request.XXXXXX")
trap 'rm -f "$request_file"' EXIT HUP INT TERM
{
  printf "PLATFORM_REMOTE_DIR_B64='%s'\n" "$(encode "$REMOTE_DIR")"
  printf "PLATFORM_BRANCH_B64='%s'\n" "$(encode "$BRANCH")"
  printf "PLATFORM_ENV_FILE_B64='%s'\n" "$(encode "$ENV_FILE")"
  printf "PLATFORM_PROJECT_NAME_B64='%s'\n" "$(encode "$PROJECT_NAME")"
  printf "PLATFORM_RUN_WAF_SMOKE_B64='%s'\n" "$(encode "$run_waf_smoke")"
  printf "PLATFORM_RUN_INFRA_HEALTH_B64='%s'\n" "$(encode "$run_infra_health")"
  printf "PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64='%s'\n" "$(encode "$run_production_preflight")"
  printf "PLATFORM_RUN_PRE_GO_LIVE_B64='%s'\n" "$(encode "$run_pre_go_live")"
  printf "PLATFORM_RUN_GO_NO_GO_B64='%s'\n" "$(encode "$run_go_no_go")"
  printf "PLATFORM_DEPLOY_REPO_B64='%s'\n" "$(encode "$deploy_repo")"
  printf "PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64='%s'\n" "$(encode "$pre_go_live_production_preflight")"
  printf "PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64='%s'\n" "$(encode "$pre_go_live_restore_drill")"
  printf "PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64='%s'\n" "$(encode "$pre_go_live_offsite_restore_dry_run")"
  printf "PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64='%s'\n" "$(encode "$pre_go_live_github_remote")"
  cat "$SCRIPT_DIR/deploy-vps-remote.sh"
} > "$request_file"

ssh "$@" "$REMOTE" 'sh -s' < "$request_file"
