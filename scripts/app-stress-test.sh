#!/usr/bin/env sh
set -eu

APP=""
URL=""
PROFILES="${APP_STRESS_PROFILES:-100,250,500,1000}"
DURATION_SECONDS="${APP_STRESS_DURATION_SECONDS:-60}"
PER_USER_RPS="${APP_STRESS_PER_USER_RPS:-0.5}"
MAX_CONCURRENCY="${APP_STRESS_MAX_CONCURRENCY:-1000}"
MAX_P95_MS="${APP_STRESS_MAX_P95_MS:-2500}"
CONFIRM_MAX_LOAD="false"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app)
      APP="${2:-}"
      shift 2
      ;;
    --url)
      URL="${2:-}"
      shift 2
      ;;
    --profiles)
      PROFILES="${2:-}"
      shift 2
      ;;
    --durationSeconds)
      DURATION_SECONDS="${2:-}"
      shift 2
      ;;
    --perUserRps)
      PER_USER_RPS="${2:-}"
      shift 2
      ;;
    --maxConcurrency)
      MAX_CONCURRENCY="${2:-}"
      shift 2
      ;;
    --maxP95Ms)
      MAX_P95_MS="${2:-}"
      shift 2
      ;;
    --confirm-max-load)
      CONFIRM_MAX_LOAD="true"
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage:
  sh ./scripts/app-stress-test.sh --app <slug> --url <https-url> --confirm-max-load

Runs a high-impact per-application load benchmark through scripts/infra-ops.sh.
The command intentionally requires --confirm-max-load.
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$APP" ]; then
  echo "--app is required" >&2
  exit 2
fi

if [ -z "$URL" ]; then
  echo "--url is required" >&2
  exit 2
fi

case "$URL" in
  http://*|https://*) ;;
  *)
    echo "--url must be an HTTP or HTTPS URL" >&2
    exit 2
    ;;
esac

if [ "$CONFIRM_MAX_LOAD" != "true" ]; then
  echo "Refusing to run max-load stress test without --confirm-max-load" >&2
  exit 2
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "==> App stress test"
echo "App: $APP"
echo "URL: $URL"
echo "Profiles: $PROFILES"
echo "Duration seconds: $DURATION_SECONDS"
echo "Per-user RPS: $PER_USER_RPS"
echo "Max concurrency: $MAX_CONCURRENCY"
echo "Max P95 ms: $MAX_P95_MS"

exec sh ./scripts/infra-ops.sh load-benchmark \
  --url "$URL" \
  --profiles "$PROFILES" \
  --durationSeconds "$DURATION_SECONDS" \
  --perUserRps "$PER_USER_RPS" \
  --maxConcurrency "$MAX_CONCURRENCY" \
  --maxP95Ms "$MAX_P95_MS"
