#!/usr/bin/env sh
set -eu
umask 077

case "$0" in
  */*) SCRIPT_PARENT="${0%/*}" ;;
  *) SCRIPT_PARENT=. ;;
esac
SCRIPT_DIR="$(CDPATH= cd -- "$SCRIPT_PARENT" && pwd)"
SCHEDULER_PATH="$SCRIPT_DIR/${0##*/}"
INFRA_ROOT="${PLATFORM_INFRA_ROOT:-$SCRIPT_DIR}"
CLIENT_PATH="$SCRIPT_DIR/docker-action-client.mjs"
LOG_DIR="${BACKUP_SCHEDULER_LOG_DIR:-/var/log/platform}"
CRON_FILE="${BACKUP_SCHEDULER_CRON_FILE:-/run/platform/backup-scheduler/crontabs/root}"
ENV_FILE="${BACKUP_SCHEDULER_ENV_FILE:-/run/platform/backup-scheduler/backup-scheduler.env}"
JOBS_DIR="${BACKUP_SCHEDULER_JOBS_DIR:-/var/www/project-state/backup-jobs}"
QUEUE_POLL_SECONDS="${BACKUP_SCHEDULER_QUEUE_POLL_SECONDS:-5}"
RESTORE_DRILL_WEEKDAY="${BACKUP_SCHEDULER_RESTORE_DRILL_WEEKDAY:-0}"

CATALOG_BACKUP_CRON="${BACKUP_SCHEDULER_CATALOG_CRON:-5 */8 * * *}"
FULL_RESTORE_DRILL_AT="${BACKUP_SCHEDULER_FULL_RESTORE_DRILL_AT:-04:45}"
RETENTION_CRON="${BACKUP_SCHEDULER_RETENTION_CRON:-50 */8 * * *}"
OFFSITE_BACKUP_CRON="${BACKUP_SCHEDULER_OFFSITE_CRON:-35 */8 * * *}"

ENABLE_OFFSITE="${BACKUP_SCHEDULER_ENABLE_OFFSITE:-false}"
ENABLE_RETENTION_APPLY="${BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY:-false}"
RUN_ON_START="${BACKUP_SCHEDULER_RUN_ON_START:-false}"
DRY_RUN="${BACKUP_SCHEDULER_DRY_RUN:-false}"

usage() {
  cat <<'EOF'
Usage: backup-scheduler.sh

Runs a container-local crond schedule for Platform backups and restore drills.
Configuration is through BACKUP_SCHEDULER_* environment variables.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

quote_shell_value() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

write_env_var() {
  name="$1"
  value="${2:-}"
  if [ -n "$value" ]; then
    case "$value" in
      *'
'*) echo "Refusing to write multiline scheduler env value: $name" >&2; exit 1 ;;
    esac
    printf '%s=%s\n' "$name" "$value" >> "$ENV_FILE"
  fi
}

valid_claimed_job_file_name() {
  file_name="${1:-}"
  case "$file_name" in
    *.json) job_id="${file_name%.json}" ;;
    *) return 1 ;;
  esac
  [ "$file_name" = "$job_id.json" ] || return 1
  [ "${#job_id}" -ge 16 ] && [ "${#job_id}" -le 128 ] || return 1
  case "$job_id" in
    [a-z0-9]*) ;;
    *) return 1 ;;
  esac
  case "$job_id" in
    *[!a-z0-9-]*) return 1 ;;
  esac
  return 0
}

queue_control() {
  node "$INFRA_ROOT/scripts/backup-queue-control.mjs" "$@" --jobsDir "$JOBS_DIR" --logDir "$LOG_DIR"
}

load_runtime_env() {
  if [ ! -f "$ENV_FILE" ]; then
    echo "Scheduler runtime env file not found: $ENV_FILE" >&2
    exit 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*) continue ;;
    esac
    name="${line%%=*}"
    value="${line#*=}"
    case "$name" in
      ""|*[!A-Za-z0-9_]*|[0-9]*)
        echo "Invalid scheduler env name in $ENV_FILE: $name" >&2
        exit 1
        ;;
    esac
    export "$name=$value"
  done < "$ENV_FILE"
}

prepare_runtime_env() {
  mkdir -p "$(dirname "$ENV_FILE")"
  : > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  write_env_var BACKUP_SCHEDULER_JOBS_DIR "$JOBS_DIR"
  write_env_var DOCKER_ACTION_BROKER_SOCKET "${DOCKER_ACTION_BROKER_SOCKET:-}"
  write_env_var DOCKER_ACTION_RUNTIME_INTENT_ID "${DOCKER_ACTION_RUNTIME_INTENT_ID:-}"
  write_env_var DOCKER_ACTION_ACTIVE_RECEIPT_SHA256 "${DOCKER_ACTION_ACTIVE_RECEIPT_SHA256:-}"
  write_env_var DOCKER_ACTION_COMBINED_RENDER_SHA256 "${DOCKER_ACTION_COMBINED_RENDER_SHA256:-}"
  write_env_var BACKUP_QUEUE_MAX_OUTSTANDING "${BACKUP_QUEUE_MAX_OUTSTANDING:-32}"
  write_env_var BACKUP_QUEUE_MAX_PER_PRINCIPAL "${BACKUP_QUEUE_MAX_PER_PRINCIPAL:-4}"
  write_env_var BACKUP_QUEUE_RATE_WINDOW_SECONDS "${BACKUP_QUEUE_RATE_WINDOW_SECONDS:-900}"
  write_env_var BACKUP_QUEUE_MAX_CONCURRENCY "${BACKUP_QUEUE_MAX_CONCURRENCY:-1}"
  write_env_var BACKUP_QUEUE_TERMINAL_MAX_PER_STATUS "${BACKUP_QUEUE_TERMINAL_MAX_PER_STATUS:-200}"
  write_env_var BACKUP_QUEUE_TERMINAL_MAX_AGE_DAYS "${BACKUP_QUEUE_TERMINAL_MAX_AGE_DAYS:-30}"
  write_env_var BACKUP_QUEUE_LEDGER_MAX_ENTRIES "${BACKUP_QUEUE_LEDGER_MAX_ENTRIES:-4096}"
  write_env_var BACKUP_QUEUE_MAX_SCAN_ENTRIES "${BACKUP_QUEUE_MAX_SCAN_ENTRIES:-4096}"
  write_env_var BACKUP_QUEUE_LOCK_TIMEOUT_MS "${BACKUP_QUEUE_LOCK_TIMEOUT_MS:-2000}"
}

cron_time() {
  value="$1"
  name="$2"
  hour="${value%:*}"
  minute="${value#*:}"
  case "$hour:$minute" in
    *[!0-9:]*|:*|*:|"") echo "Invalid $name: $value. Use HH:MM." >&2; exit 1 ;;
  esac
  if [ "$hour" -lt 0 ] || [ "$hour" -gt 23 ] || [ "$minute" -lt 0 ] || [ "$minute" -gt 59 ]; then
    echo "Invalid $name: $value. Use HH:MM." >&2
    exit 1
  fi
  printf '%s %s' "$minute" "$hour"
}

validate_cron_expression() {
  value="$1"
  name="$2"
  case "$value" in
    *'
'*) echo "Invalid $name: multiline cron expressions are not allowed." >&2; exit 1 ;;
  esac
  set -f
  set -- $value
  set +f
  if [ "$#" -ne 5 ]; then
    echo "Invalid $name: expected 5 cron fields." >&2
    exit 1
  fi
  for field in "$@"; do
    case "$field" in
      *[!0-9*/,:-]*) echo "Invalid $name field: $field" >&2; exit 1 ;;
    esac
  done
}

append_cron_expression() {
  expression="$1"
  name="$2"
  command_value="$3"
  validate_cron_expression "$expression" "$name"
  log_file="$LOG_DIR/$name.log"
  printf '%s cd %s && mkdir -p %s && %s >> %s 2>&1\n' \
    "$expression" "$(quote_shell_value "$INFRA_ROOT")" "$(quote_shell_value "$LOG_DIR")" "$command_value" "$(quote_shell_value "$log_file")" >> "$CRON_FILE"
}

append_weekly() {
  time_value="$1"
  name="$2"
  command_value="$3"
  schedule="$(cron_time "$time_value" "$name")"
  log_file="$LOG_DIR/$name.log"
  printf '%s * * %s cd %s && mkdir -p %s && %s >> %s 2>&1\n' \
    "$schedule" "$RESTORE_DRILL_WEEKDAY" "$(quote_shell_value "$INFRA_ROOT")" "$(quote_shell_value "$LOG_DIR")" "$command_value" "$(quote_shell_value "$log_file")" >> "$CRON_FILE"
}

node_ops() {
  printf '%s --run %s' "$(quote_shell_value "$SCHEDULER_PATH")" "$1"
}

process_backup_job() {
  running_file="$1"
  name="$(basename "$running_file")"
  job_id="${name%.json}"
  log_file="$LOG_DIR/manual-backup-$job_id.log"
  exit_code=0
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] executing claimed typed job $name" >> "$log_file"
  if node "$CLIENT_PATH" execute-backup-job --jobFileName "$name" >> "$log_file" 2>&1; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] completed claimed typed job $name" >> "$log_file"
  else
    exit_code=$?
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] claimed typed job $name returned exit $exit_code" >> "$log_file"
  fi
  if [ "$exit_code" -eq 74 ]; then
    queue_control mark-unknown \
      --jobId "$job_id" \
      --summary "manual-reconciliation required: Docker broker outcome is unknown after admission." \
      --exitCode 74
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] leaving $name in running for manual reconciliation" >> "$log_file"
  elif [ "$exit_code" -eq 0 ]; then
    queue_control finish --jobId "$job_id" --status done --summary "Job completato dal backup scheduler."
  else
    queue_control finish --jobId "$job_id" --status failed --summary "Job fallito nel backup scheduler." --exitCode "$exit_code"
  fi
}

process_backup_job_queue() {
  mkdir -p "$JOBS_DIR/queued" "$JOBS_DIR/running" "$JOBS_DIR/done" "$JOBS_DIR/failed"
  while true; do
    running_file=""
    if ! running_file="$(queue_control claim)"; then
      echo "Backup queue claim failed closed; retrying after $QUEUE_POLL_SECONDS seconds." >&2
      sleep "$QUEUE_POLL_SECONDS"
      continue
    fi
    if [ -n "$running_file" ]; then
      process_backup_job "$running_file"
    else
      sleep "$QUEUE_POLL_SECONDS"
    fi
  done
}

if [ "${1:-}" = "--run" ]; then
  shift
  if [ "$#" -lt 1 ]; then
    echo "Usage: backup-scheduler.sh --run <infra-ops-command>" >&2
    exit 1
  fi
  operation="$1"
  shift
  case "$operation" in
    execute-backup-job)
      if [ "$#" -ne 2 ] || [ "$1" != "--jobFileName" ] || ! valid_claimed_job_file_name "$2"; then
        echo "execute-backup-job accepts only --jobFileName <basename>" >&2
        exit 64
      fi
      ;;
    backup-platform-catalog|prune-manifest-backups-plan|prune-manifest-backups-apply|full-restore-drill|offsite-backup-restic)
      if [ "$#" -ne 0 ]; then
        echo "Typed scheduler operation $operation accepts no parameters" >&2
        exit 64
      fi
      ;;
    *) echo "Unsupported typed scheduler operation: $operation" >&2; exit 64 ;;
  esac
  if [ -f "$ENV_FILE" ]; then
    load_runtime_env
  fi
  exec node "$CLIENT_PATH" "$operation" "$@"
fi

mkdir -p "$LOG_DIR" "$(dirname "$CRON_FILE")" "$JOBS_DIR/queued" "$JOBS_DIR/running" "$JOBS_DIR/done" "$JOBS_DIR/failed"
chmod 700 "$LOG_DIR" "$JOBS_DIR" "$JOBS_DIR/queued" "$JOBS_DIR/running" "$JOBS_DIR/done" "$JOBS_DIR/failed"
prepare_runtime_env
: > "$CRON_FILE"

append_cron_expression "$CATALOG_BACKUP_CRON" "platform-catalog-backup" "$(node_ops backup-platform-catalog)"
if [ "$ENABLE_RETENTION_APPLY" = "true" ] || [ "$ENABLE_RETENTION_APPLY" = "1" ]; then
  append_cron_expression "$RETENTION_CRON" "platform-manifest-retention" "$(node_ops prune-manifest-backups-apply)"
else
  append_cron_expression "$RETENTION_CRON" "platform-manifest-retention-plan" "$(node_ops prune-manifest-backups-plan)"
fi
append_weekly "$FULL_RESTORE_DRILL_AT" "full-restore-drill" "$(node_ops full-restore-drill)"

if [ "$ENABLE_OFFSITE" = "true" ] || [ "$ENABLE_OFFSITE" = "1" ]; then
  append_cron_expression "$OFFSITE_BACKUP_CRON" "restic-offsite" "$(node_ops offsite-backup-restic)"
fi

echo "Installed Platform backup scheduler crontab:"
cat "$CRON_FILE"

if [ "$DRY_RUN" = "true" ] || [ "$DRY_RUN" = "1" ]; then
  exit 0
fi

if [ "$RUN_ON_START" = "true" ] || [ "$RUN_ON_START" = "1" ]; then
  cd "$INFRA_ROOT"
  node "$CLIENT_PATH" backup-platform-catalog
fi

process_backup_job_queue &

exec crond -f -l 8 -L "$LOG_DIR/backup-scheduler.log" -c "$(dirname "$CRON_FILE")"
