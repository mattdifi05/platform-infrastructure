#!/usr/bin/env sh
set -eu
umask 077

INFRA_ROOT="${PLATFORM_INFRA_ROOT:-/infra}"
INFRA_CONTAINER_ROOT="${PLATFORM_INFRA_CONTAINER_ROOT:-$INFRA_ROOT}"
SOURCE_ROOT="${PROJECT_SOURCE_ROOT:-/project}"
STATE_ROOT="${PROJECT_STATE_ROOT:-/var/www/project-state}"
INFRA_HOST_ROOT="${PLATFORM_INFRA_HOST_ROOT:-}"
SOURCE_HOST_ROOT="${PROJECT_SOURCE_HOST_ROOT:-}"
LOG_DIR="${BACKUP_SCHEDULER_LOG_DIR:-/var/log/platform}"
CRON_FILE="${BACKUP_SCHEDULER_CRON_FILE:-/etc/crontabs/root}"
ENV_FILE="${BACKUP_SCHEDULER_ENV_FILE:-/etc/platform/backup-scheduler.env}"
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
  write_env_var PLATFORM_INFRA_ROOT "$INFRA_ROOT"
  write_env_var PLATFORM_INFRA_CONTAINER_ROOT "$INFRA_CONTAINER_ROOT"
  write_env_var PLATFORM_INFRA_HOST_ROOT "$INFRA_HOST_ROOT"
  write_env_var PROJECT_SOURCE_ROOT "$SOURCE_ROOT"
  write_env_var PROJECT_SOURCE_HOST_ROOT "$SOURCE_HOST_ROOT"
  write_env_var PROJECT_STATE_ROOT "$STATE_ROOT"
  write_env_var PROJECT_DATABASES_FILE "${PROJECT_DATABASES_FILE:-$STATE_ROOT/databases.json}"
  write_env_var NODE_IMAGE "${NODE_IMAGE:-}"
  write_env_var BACKUP_SIGNING_KEYS_FILE "${BACKUP_SIGNING_KEYS_FILE:-}"
  write_env_var RESTIC_IMAGE "${RESTIC_IMAGE:-}"
  write_env_var RESTIC_REPOSITORY "${RESTIC_REPOSITORY:-}"
  write_env_var RESTIC_PASSWORD_FILE "${RESTIC_PASSWORD_FILE:-}"
  write_env_var RESTIC_KEEP_LAST "${RESTIC_KEEP_LAST:-}"
  write_env_var RESTIC_HOSTNAME "${RESTIC_HOSTNAME:-platform-infrastructure}"
  write_env_var RESTIC_REQUIRE_IMMUTABLE_IMAGE "${RESTIC_REQUIRE_IMMUTABLE_IMAGE:-true}"
  write_env_var RESTIC_MAX_REPOSITORY_BYTES "${RESTIC_MAX_REPOSITORY_BYTES:-}"
  write_env_var RCLONE_CONFIG "${RCLONE_CONFIG:-}"
  write_env_var KEYCLOAK_DB_NAME "${KEYCLOAK_DB_NAME:-keycloak}"
  write_env_var BACKUP_LOCAL_KEEP_LAST "${BACKUP_LOCAL_KEEP_LAST:-42}"
  write_env_var BACKUP_SCHEDULER_JOBS_DIR "$JOBS_DIR"
  write_env_var AWS_ACCESS_KEY_ID "${AWS_ACCESS_KEY_ID:-}"
  write_env_var AWS_SECRET_ACCESS_KEY "${AWS_SECRET_ACCESS_KEY:-}"
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
  printf 'node %s %s' "$(quote_shell_value "$INFRA_ROOT/scripts/docker-operation-client.mjs")" "$1"
}

job_json_value() {
  file="$1"
  expression="$2"
  node -e 'const fs=require("fs"); const [file, expression]=process.argv.slice(1); const job=JSON.parse(fs.readFileSync(file, "utf8")); const value=Function("job", `return ${expression}`)(job); process.stdout.write(value == null ? "" : String(value));' "$file" "$expression"
}

update_job_status() {
  file="$1"
  status="$2"
  summary="$3"
  exit_code="${4:-}"
  log_path="${5:-}"
  node -e '
const fs = require("fs");
const [file, status, summary, exitCode, logPath] = process.argv.slice(1);
const now = new Date().toISOString();
const job = JSON.parse(fs.readFileSync(file, "utf8"));
job.status = status;
job.updatedAt = now;
if (status === "running" && !job.startedAt) job.startedAt = now;
if (status === "done" || status === "failed") job.finishedAt = now;
job.resultSummary = summary;
if (exitCode) job.exitCode = Number(exitCode);
if (logPath) job.logPath = logPath;
const temporary = `${file}.tmp-${process.pid}-${Date.now()}`;
fs.writeFileSync(temporary, `${JSON.stringify(job, null, 2)}\n`, { mode: 0o600, flag: "wx" });
fs.renameSync(temporary, file);
' "$file" "$status" "$summary" "$exit_code" "$log_path"
}

process_backup_job() {
  queued_file="$1"
  name="$(basename "$queued_file")"
  mkdir -p "$JOBS_DIR/running" "$JOBS_DIR/done" "$JOBS_DIR/failed" "$LOG_DIR"
  running_file="$JOBS_DIR/running/$name"
  if ! mv "$queued_file" "$running_file" 2>/dev/null; then
    return 0
  fi
  job_id="$(job_json_value "$running_file" 'job.id || "unknown"')"
  log_file="$LOG_DIR/manual-backup-$job_id.log"
  update_job_status "$running_file" "running" "Job preso in carico dal backup scheduler." "" "$log_file"
  exit_code=0
  schema="$(job_json_value "$running_file" 'job.schema || ""')"
  operation="$(job_json_value "$running_file" 'job.operation || ""')"
  if [ "$schema" != "platform.backup-job/v1" ]; then
    exit_code=64
    echo "Rejected unsupported backup job schema for $job_id" >> "$log_file"
  elif [ "$operation" != "backup" ] && [ "$operation" != "restore-drill" ]; then
    exit_code=64
    echo "Rejected unsupported backup job operation for $job_id" >> "$log_file"
  else
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] executing typed $operation job $job_id" >> "$log_file"
    if node "$INFRA_ROOT/scripts/docker-operation-client.mjs" execute-backup-job --jobFileName "$name" >> "$log_file" 2>&1; then
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] completed typed job $job_id" >> "$log_file"
    else
      exit_code=$?
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] typed job $job_id failed with exit $exit_code" >> "$log_file"
    fi
  fi
  if [ "$exit_code" -eq 0 ]; then
    update_job_status "$running_file" "done" "Job completato dal backup scheduler." "" "$log_file"
    mv "$running_file" "$JOBS_DIR/done/$name"
  else
    update_job_status "$running_file" "failed" "Job fallito nel backup scheduler." "$exit_code" "$log_file"
    mv "$running_file" "$JOBS_DIR/failed/$name"
  fi
}

process_backup_job_queue() {
  mkdir -p "$JOBS_DIR/queued" "$JOBS_DIR/running" "$JOBS_DIR/done" "$JOBS_DIR/failed"
  while true; do
    queued_file="$(find "$JOBS_DIR/queued" -maxdepth 1 -type f -name '*.json' 2>/dev/null | sort | head -n 1 || true)"
    if [ -n "$queued_file" ]; then
      process_backup_job "$queued_file"
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
    backup-platform-catalog|prune-manifest-backups-plan|prune-manifest-backups-apply|full-restore-drill|offsite-backup-restic|execute-backup-job) ;;
    *) echo "Unsupported typed scheduler operation: $operation" >&2; exit 64 ;;
  esac
  exec node "$INFRA_ROOT/scripts/docker-operation-client.mjs" "$operation" "$@"
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
  node "$INFRA_ROOT/scripts/docker-operation-client.mjs" backup-platform-catalog
fi

process_backup_job_queue &

exec crond -f -l 8 -L "$LOG_DIR/backup-scheduler.log"
