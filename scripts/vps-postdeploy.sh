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

docs_host=$(env_or_default DOCS_HOST docs.localhost.com)
admin_host=$(env_or_default CONTROL_CENTER_HOST "$(env_or_default ADMIN_HOST admin.localhost.com)")
ui_base="${DEPLOY_UI_BASE:-$(env_or_default DOCS_PUBLIC_URL "https://$docs_host")}"
api_base="${DEPLOY_API_BASE:-}"
account_base="${DEPLOY_ACCOUNT_BASE:-}"
account_origin="${DEPLOY_ACCOUNT_ORIGIN:-$account_base}"
admin_base="${DEPLOY_ADMIN_BASE:-${DEPLOY_PROJECTS_BASE:-$(env_or_default CONTROL_CENTER_PUBLIC_URL "https://$admin_host")}}"
grafana_base="${DEPLOY_GRAFANA_BASE:-$(env_or_default GRAFANA_PUBLIC_URL "")}"
grafana_blocked="${DEPLOY_GRAFANA_BLOCKED:-0}"
admin_scheme="${DEPLOY_ADMIN_SCHEME:-}"
allow_http_no_hsts="${DEPLOY_ALLOW_HTTP_NO_HSTS:-0}"

if [ "${DEPLOY_RUN_WAF_SMOKE:-1}" = "1" ]; then
  set -- --phpBase "$admin_base"
  if [ -n "$api_base" ]; then
    set -- "$@" --apiBase "$api_base"
  fi
  sh ./scripts/waf-smoke.sh "$@"
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
  set -- --uiBase "$ui_base" --adminBase "$admin_base"
  if [ -n "$api_base" ]; then
    set -- "$@" --apiBase "$api_base"
  fi
  if [ -n "$account_base" ]; then
    set -- "$@" --accountBase "$account_base"
  fi
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
    --uiBase "$ui_base" \
    --adminBase "$admin_base" \
    --phpBase "$admin_base"
  if [ -n "$api_base" ]; then
    set -- "$@" --apiBase "$api_base"
  fi
  if [ -n "$account_base" ]; then
    set -- "$@" --accountBase "$account_base"
  fi
  if [ -n "$account_origin" ]; then
    set -- "$@" --accountOrigin "$account_origin"
  fi
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
