#!/usr/bin/env sh
set -eu

decode_field() {
  printf '%s' "$1" | base64 -d
}

remote_dir=$(decode_field "$PLATFORM_REMOTE_DIR_B64")
branch=$(decode_field "$PLATFORM_BRANCH_B64")
env_file=$(decode_field "$PLATFORM_ENV_FILE_B64")
project_name=$(decode_field "$PLATFORM_PROJECT_NAME_B64")
deploy_run_waf_smoke=$(decode_field "$PLATFORM_RUN_WAF_SMOKE_B64")
deploy_run_infra_health=$(decode_field "$PLATFORM_RUN_INFRA_HEALTH_B64")
deploy_run_production_preflight=$(decode_field "$PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64")
deploy_run_pre_go_live=$(decode_field "$PLATFORM_RUN_PRE_GO_LIVE_B64")
deploy_run_go_no_go=$(decode_field "$PLATFORM_RUN_GO_NO_GO_B64")
deploy_repo=$(decode_field "$PLATFORM_DEPLOY_REPO_B64")
deploy_pre_go_live_production_preflight=$(decode_field "$PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64")
deploy_pre_go_live_restore_drill=$(decode_field "$PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64")
deploy_pre_go_live_offsite_restore_dry_run=$(decode_field "$PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64")
deploy_pre_go_live_github_remote=$(decode_field "$PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64")

case "$remote_dir" in /*) ;; *) exit 64 ;; esac
case "$remote_dir" in *[!A-Za-z0-9_./-]*|*//*|*/../*|*/..) exit 64 ;; esac
case "$branch" in [A-Za-z0-9]* ) ;; *) exit 64 ;; esac
case "$branch" in *[!A-Za-z0-9._/-]*|*..*|*/ ) exit 64 ;; esac
case "$env_file" in [A-Za-z0-9._/-]* ) ;; *) exit 64 ;; esac
case "$env_file" in /*|*..*|*//*|*/ ) exit 64 ;; esac
case "$project_name" in [a-z0-9]* ) ;; *) exit 64 ;; esac
case "$project_name" in *[!a-z0-9_-]* ) exit 64 ;; esac
for value in \
  "$deploy_run_waf_smoke" \
  "$deploy_run_infra_health" \
  "$deploy_run_production_preflight" \
  "$deploy_run_pre_go_live" \
  "$deploy_run_go_no_go" \
  "$deploy_pre_go_live_production_preflight" \
  "$deploy_pre_go_live_restore_drill" \
  "$deploy_pre_go_live_offsite_restore_dry_run" \
  "$deploy_pre_go_live_github_remote"
do
  case "$value" in 0|1) ;; *) exit 64 ;; esac
done
case "$deploy_repo" in ""|[A-Za-z0-9_.-]*/[A-Za-z0-9_.-]* ) ;; *) exit 64 ;; esac

cd -- "$remote_dir"
git fetch --all --prune
git checkout "$branch"
git pull --ff-only origin "$branch"
sh ./scripts/vps-preflight.sh "$env_file"
sh ./scripts/prepare-vps-runtime.sh
COMPOSE_ENV_FILE="$env_file" COMPOSE_PROJECT_NAME="$project_name" \
  bash ./scripts/compose-vps.sh up -d --build --remove-orphans
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
  sh ./scripts/vps-postdeploy.sh "$env_file"
