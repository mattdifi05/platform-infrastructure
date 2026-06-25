#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE="${1:-$ROOT_DIR/.env}"

cd "$ROOT_DIR"

if [ ! -f "$ENV_FILE" ]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

get_env() {
  key="$1"
  value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); value=$0 } END { print value }' "$ENV_FILE")
  printf '%s' "$value"
}

env_or_default() {
  key="$1"
  fallback="$2"
  value=$(get_env "$key")
  if [ -n "$value" ]; then
    printf '%s' "$value"
  else
    printf '%s' "$fallback"
  fi
}

api_host=$(env_or_default API_HOST api.localhost.com)
ui_host=$(env_or_default UI_HOST ui.localhost.com)
account_host=$(env_or_default ACCOUNT_HOST account.localhost.com)
projects_host=$(env_or_default PROJECTS_HOST projects.localhost.com)
api_base="${DEPLOY_API_BASE:-$(env_or_default API_PUBLIC_URL "https://$api_host")}"
ui_base="${DEPLOY_UI_BASE:-$(env_or_default UI_PUBLIC_URL "https://$ui_host")}"
account_base="${DEPLOY_ACCOUNT_BASE:-$(env_or_default ACCOUNT_PUBLIC_URL "https://$account_host")}"
account_origin="${DEPLOY_ACCOUNT_ORIGIN:-$(env_or_default ACCOUNT_PUBLIC_URL "$account_base")}"
projects_base="${DEPLOY_PROJECTS_BASE:-$(env_or_default PROJECTS_PUBLIC_URL "https://$projects_host")}"
grafana_base="${DEPLOY_GRAFANA_BASE:-$(env_or_default GRAFANA_PUBLIC_URL "")}"
grafana_blocked="${DEPLOY_GRAFANA_BLOCKED:-0}"
admin_scheme="${DEPLOY_ADMIN_SCHEME:-}"
allow_http_no_hsts="${DEPLOY_ALLOW_HTTP_NO_HSTS:-0}"

if [ "${DEPLOY_RUN_WAF_SMOKE:-1}" = "1" ]; then
  sh ./scripts/waf-smoke.sh --apiBase "$api_base" --phpBase "$projects_base"
fi

if [ "${DEPLOY_RUN_RATE_LIMIT_EVIDENCE:-1}" = "1" ]; then
  sh ./scripts/rate-limit-evidence.sh
fi

if [ "${DEPLOY_RUN_AUDIT_LOG_EVIDENCE:-1}" = "1" ]; then
  sh ./scripts/audit-log-evidence.sh
fi

if [ "${DEPLOY_RUN_RETENTION_EVIDENCE:-1}" = "1" ]; then
  sh ./scripts/retention-evidence.sh
fi

if [ "${DEPLOY_RUN_INFRA_HEALTH:-1}" = "1" ]; then
  set -- --apiBase "$api_base" --uiBase "$ui_base" --accountBase "$account_base" --projectsBase "$projects_base"
  if [ -n "$grafana_base" ]; then
    set -- "$@" --grafanaBase "$grafana_base"
  fi
  if [ "$grafana_blocked" = "1" ] || [ "$grafana_blocked" = "true" ]; then
    set -- "$@" --grafanaBlocked true
  fi
  if [ -n "$admin_scheme" ]; then
    set -- "$@" --adminScheme "$admin_scheme"
  fi
  sh ./scripts/infra-health.sh "$@"
fi

if [ "${DEPLOY_RUN_PRODUCTION_PREFLIGHT:-0}" = "1" ]; then
  sh ./scripts/production-preflight.sh --envFile "$ENV_FILE"
fi

if [ "${DEPLOY_RUN_PRE_GO_LIVE:-0}" = "1" ]; then
  if [ -z "${DEPLOY_REPO:-}" ]; then
    echo "Set DEPLOY_REPO=OWNER/REPO before enabling DEPLOY_RUN_PRE_GO_LIVE=1." >&2
    exit 1
  fi
  set -- --repo "$DEPLOY_REPO" --includeRuntime
  if [ "${DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT:-1}" = "1" ]; then
    set -- "$@" --includeProductionPreflight
  fi
  if [ "${DEPLOY_PRE_GO_LIVE_RESTORE_DRILL:-0}" = "1" ]; then
    set -- "$@" --includeRestoreDrill
  fi
  if [ "${DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN:-0}" = "1" ]; then
    set -- "$@" --includeOffsiteRestoreDryRun
  fi
  if [ "${DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE:-0}" = "1" ]; then
    set -- "$@" --verifyGithubRemote
  fi
  set -- "$@" \
    --apiBase "$api_base" \
    --uiBase "$ui_base" \
    --accountBase "$account_base" \
    --projectsBase "$projects_base" \
    --phpBase "$projects_base" \
    --accountOrigin "$account_origin"
  if [ -n "$grafana_base" ]; then
    set -- "$@" --grafanaBase "$grafana_base"
  fi
  if [ "$grafana_blocked" = "1" ] || [ "$grafana_blocked" = "true" ]; then
    set -- "$@" --grafanaBlocked true
  fi
  if [ -n "$admin_scheme" ]; then
    set -- "$@" --adminScheme "$admin_scheme"
  fi
  if [ "$allow_http_no_hsts" = "1" ] || [ "$allow_http_no_hsts" = "true" ]; then
    set -- "$@" --allowHttpNoHsts
  fi
  sh ./scripts/pre-go-live-evidence.sh "$@"
fi

if [ "${DEPLOY_RUN_GO_NO_GO:-0}" = "1" ]; then
  sh ./scripts/secret-rotation-evidence.sh --enforce
  sh ./scripts/production-go-no-go.sh --enforce
  sh ./scripts/production-readiness-live.sh
fi

echo "VPS post-deploy checks completed."
