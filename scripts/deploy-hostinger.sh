#!/usr/bin/env sh
set -eu

REMOTE="${DEPLOY_REMOTE:-}"
REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/stexor/stexor-platform-infrastructure}"
BRANCH="${DEPLOY_BRANCH:-main}"
ENV_FILE="${DEPLOY_ENV_FILE:-.env}"
PROJECT_NAME="${DEPLOY_PROJECT_NAME:-stexor_platform_vps}"

if [ -z "$REMOTE" ]; then
  echo "Set DEPLOY_REMOTE, for example DEPLOY_REMOTE=deploy@your-vps" >&2
  exit 1
fi

ssh "$REMOTE" sh -s -- \
  "$REMOTE_DIR" \
  "$BRANCH" \
  "$ENV_FILE" \
  "$PROJECT_NAME" \
  "${DEPLOY_RUN_WAF_SMOKE:-1}" \
  "${DEPLOY_RUN_INFRA_HEALTH:-1}" \
  "${DEPLOY_RUN_PRODUCTION_PREFLIGHT:-0}" \
  "${DEPLOY_RUN_PRE_GO_LIVE:-0}" \
  "${DEPLOY_RUN_GO_NO_GO:-0}" \
  "${DEPLOY_REPO:-}" \
  "${DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT:-1}" \
  "${DEPLOY_PRE_GO_LIVE_RESTORE_DRILL:-0}" \
  "${DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN:-0}" \
  "${DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE:-0}" <<'REMOTE_SCRIPT'
set -eu

remote_dir="$1"
branch="$2"
env_file="$3"
project_name="$4"
deploy_run_waf_smoke="$5"
deploy_run_infra_health="$6"
deploy_run_production_preflight="$7"
deploy_run_pre_go_live="$8"
deploy_run_go_no_go="$9"
shift 9
deploy_repo="$1"
deploy_pre_go_live_production_preflight="$2"
deploy_pre_go_live_restore_drill="$3"
deploy_pre_go_live_offsite_restore_dry_run="$4"
deploy_pre_go_live_github_remote="$5"

cd "$remote_dir"
git fetch --all --prune
git checkout "$branch"
git pull --ff-only origin "$branch"
sh ./scripts/hostinger-preflight.sh "$env_file"
docker compose --env-file "$env_file" -p "$project_name" \
    -f compose.yaml \
    -f compose.build.yaml \
    -f compose.secrets.yaml \
    -f compose.hostinger.yaml \
    -f compose.waf.yaml \
    -f compose.hostinger-waf.yaml \
    up -d --build --remove-orphans
DEPLOY_RUN_WAF_SMOKE="$deploy_run_waf_smoke" \
DEPLOY_RUN_INFRA_HEALTH="$deploy_run_infra_health" \
DEPLOY_RUN_PRODUCTION_PREFLIGHT="$deploy_run_production_preflight" \
DEPLOY_RUN_PRE_GO_LIVE="$deploy_run_pre_go_live" \
DEPLOY_RUN_GO_NO_GO="$deploy_run_go_no_go" \
DEPLOY_REPO="$deploy_repo" \
DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT="$deploy_pre_go_live_production_preflight" \
DEPLOY_PRE_GO_LIVE_RESTORE_DRILL="$deploy_pre_go_live_restore_drill" \
DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN="$deploy_pre_go_live_offsite_restore_dry_run" \
DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE="$deploy_pre_go_live_github_remote" \
  sh ./scripts/hostinger-postdeploy.sh "$env_file"
REMOTE_SCRIPT
