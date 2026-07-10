#!/usr/bin/env sh
set -eu

INFRA_ROOT="${PLATFORM_INFRA_ROOT:-/infra}"
INFRA_CONTAINER_ROOT="${PLATFORM_INFRA_CONTAINER_ROOT:-$INFRA_ROOT}"
SOURCE_ROOT="${PROJECT_SOURCE_ROOT:-/project}"
INFRA_HOST_ROOT="${PLATFORM_INFRA_HOST_ROOT:-}"
SOURCE_HOST_ROOT="${PROJECT_SOURCE_HOST_ROOT:-}"
LOG_DIR="${BACKUP_SCHEDULER_LOG_DIR:-/var/log/platform}"
CRON_FILE="${BACKUP_SCHEDULER_CRON_FILE:-/etc/crontabs/root}"
ENV_FILE="${BACKUP_SCHEDULER_ENV_FILE:-/etc/platform/backup-scheduler.env}"
JOBS_DIR="${BACKUP_SCHEDULER_JOBS_DIR:-/var/www/project-state/backup-jobs}"
QUEUE_POLL_SECONDS="${BACKUP_SCHEDULER_QUEUE_POLL_SECONDS:-5}"
RESTORE_DRILL_WEEKDAY="${BACKUP_SCHEDULER_RESTORE_DRILL_WEEKDAY:-0}"

POSTGRES_BACKUP_AT="${BACKUP_SCHEDULER_POSTGRES_AT:-03:15}"
APPLICATIONS_BACKUP_AT="${BACKUP_SCHEDULER_APPLICATIONS_AT:-03:05}"
MARIADB_BACKUP_AT="${BACKUP_SCHEDULER_MARIADB_AT:-03:45}"
MINIO_BACKUP_AT="${BACKUP_SCHEDULER_MINIO_AT:-04:00}"
KEYCLOAK_BACKUP_AT="${BACKUP_SCHEDULER_KEYCLOAK_AT:-04:10}"
SECRET_MANAGER_BACKUP_AT="${BACKUP_SCHEDULER_SECRET_MANAGER_AT:-04:20}"
POSTGRES_BACKUP_CRON="${BACKUP_SCHEDULER_POSTGRES_CRON:-}"
APPLICATIONS_BACKUP_CRON="${BACKUP_SCHEDULER_APPLICATIONS_CRON:-5 */8 * * *}"
MARIADB_BACKUP_CRON="${BACKUP_SCHEDULER_MARIADB_CRON:-}"
MINIO_BACKUP_CRON="${BACKUP_SCHEDULER_MINIO_CRON:-}"
KEYCLOAK_BACKUP_CRON="${BACKUP_SCHEDULER_KEYCLOAK_CRON:-}"
SECRET_MANAGER_BACKUP_CRON="${BACKUP_SCHEDULER_SECRET_MANAGER_CRON:-}"
FULL_RESTORE_DRILL_AT="${BACKUP_SCHEDULER_FULL_RESTORE_DRILL_AT:-04:45}"
RETENTION_AT="${BACKUP_SCHEDULER_RETENTION_AT:-05:15}"
OFFSITE_BACKUP_AT="${BACKUP_SCHEDULER_OFFSITE_AT:-05:30}"
OFFSITE_BACKUP_CRON="${BACKUP_SCHEDULER_OFFSITE_CRON:-}"

ENABLE_OFFSITE="${BACKUP_SCHEDULER_ENABLE_OFFSITE:-false}"
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

detect_mount_source() {
  destination="$1"
  container_id="${HOSTNAME:-$(hostname)}"
  docker inspect "$container_id" --format "{{range .Mounts}}{{if eq .Destination \"$destination\"}}{{.Source}}{{end}}{{end}}" 2>/dev/null || true
}

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
  if [ -z "$INFRA_HOST_ROOT" ]; then
    INFRA_HOST_ROOT="$(detect_mount_source "$INFRA_CONTAINER_ROOT")"
  fi
  if [ -z "$SOURCE_HOST_ROOT" ]; then
    SOURCE_HOST_ROOT="$(detect_mount_source "$SOURCE_ROOT")"
  fi

  if [ -z "$INFRA_HOST_ROOT" ]; then
    echo "Unable to detect PLATFORM_INFRA_HOST_ROOT from the $INFRA_CONTAINER_ROOT mount. Set it explicitly before starting the backup scheduler." >&2
    exit 1
  fi
  if [ -z "$SOURCE_HOST_ROOT" ]; then
    echo "Warning: PROJECT_SOURCE_HOST_ROOT could not be detected from the $SOURCE_ROOT mount. Source-dependent ops will use container-local paths only." >&2
  fi

  mkdir -p "$(dirname "$ENV_FILE")"
  : > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  write_env_var PLATFORM_INFRA_ROOT "$INFRA_ROOT"
  write_env_var PLATFORM_INFRA_CONTAINER_ROOT "$INFRA_CONTAINER_ROOT"
  write_env_var PLATFORM_INFRA_HOST_ROOT "$INFRA_HOST_ROOT"
  write_env_var PROJECT_SOURCE_ROOT "$SOURCE_ROOT"
  write_env_var PROJECT_SOURCE_HOST_ROOT "$SOURCE_HOST_ROOT"
  write_env_var NODE_IMAGE "${NODE_IMAGE:-}"
  write_env_var BACKUP_SIGNING_KEYS_FILE "${BACKUP_SIGNING_KEYS_FILE:-}"
  write_env_var RESTIC_IMAGE "${RESTIC_IMAGE:-}"
  write_env_var RESTIC_REPOSITORY "${RESTIC_REPOSITORY:-}"
  write_env_var RESTIC_PASSWORD_FILE "${RESTIC_PASSWORD_FILE:-}"
  write_env_var RESTIC_KEEP_LAST "${RESTIC_KEEP_LAST:-}"
  write_env_var RESTIC_MAX_REPOSITORY_BYTES "${RESTIC_MAX_REPOSITORY_BYTES:-}"
  write_env_var RCLONE_CONFIG "${RCLONE_CONFIG:-}"
  write_env_var POSTGRES_BACKUP_DATABASE "${POSTGRES_BACKUP_DATABASE:-}"
  write_env_var POSTGRES_OPS_SCHEMA "${POSTGRES_OPS_SCHEMA:-}"
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

append_daily() {
  time_value="$1"
  name="$2"
  command_value="$3"
  schedule="$(cron_time "$time_value" "$name")"
  log_file="$LOG_DIR/$name.log"
  printf '%s * * * cd %s && mkdir -p %s && %s >> %s 2>&1\n' \
    "$schedule" "$(quote_shell_value "$INFRA_ROOT")" "$(quote_shell_value "$LOG_DIR")" "$command_value" "$(quote_shell_value "$log_file")" >> "$CRON_FILE"
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

append_scheduled() {
  cron_value="$1"
  time_value="$2"
  name="$3"
  command_value="$4"
  if [ -n "$cron_value" ]; then
    append_cron_expression "$cron_value" "$name" "$command_value"
  else
    append_daily "$time_value" "$name" "$command_value"
  fi
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
  printf 'BACKUP_SCHEDULER_ENV_FILE=%s sh %s --run %s' "$(quote_shell_value "$ENV_FILE")" "$(quote_shell_value "$INFRA_ROOT/scripts/backup-scheduler.sh")" "$1"
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
    if BACKUP_SCHEDULER_ENV_FILE="$ENV_FILE" sh "$INFRA_ROOT/scripts/backup-scheduler.sh" --run execute-backup-job --jobFile "$running_file" >> "$log_file" 2>&1; then
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
  load_runtime_env
  cd "$INFRA_ROOT"
  exec node "$INFRA_ROOT/scripts/infra-ops.mjs" "$@"
fi

mkdir -p "$LOG_DIR" "$(dirname "$CRON_FILE")" "$JOBS_DIR/queued" "$JOBS_DIR/running" "$JOBS_DIR/done" "$JOBS_DIR/failed"
prepare_runtime_env
: > "$CRON_FILE"

append_scheduled "$APPLICATIONS_BACKUP_CRON" "$APPLICATIONS_BACKUP_AT" "applications-backup" "$(node_ops backup-applications)"
append_scheduled "$POSTGRES_BACKUP_CRON" "$POSTGRES_BACKUP_AT" "postgres-backup" "$(node_ops backup-postgres)"
append_scheduled "$MARIADB_BACKUP_CRON" "$MARIADB_BACKUP_AT" "mariadb-backup" "$(node_ops backup-mariadb)"
append_scheduled "$MINIO_BACKUP_CRON" "$MINIO_BACKUP_AT" "minio-backup" "$(node_ops backup-minio)"
append_scheduled "$KEYCLOAK_BACKUP_CRON" "$KEYCLOAK_BACKUP_AT" "keycloak-backup" "$(node_ops backup-keycloak)"
append_scheduled "$SECRET_MANAGER_BACKUP_CRON" "$SECRET_MANAGER_BACKUP_AT" "secret-manager-backup" "$(node_ops backup-secret-manager-metadata)"
append_daily "$RETENTION_AT" "postgres-retention" "$(node_ops prune-postgres-backups)"
append_weekly "$FULL_RESTORE_DRILL_AT" "full-restore-drill" "$(node_ops full-restore-drill)"

if [ "$ENABLE_OFFSITE" = "true" ] || [ "$ENABLE_OFFSITE" = "1" ]; then
  if [ -n "$OFFSITE_BACKUP_CRON" ]; then
    append_cron_expression "$OFFSITE_BACKUP_CRON" "restic-offsite" "$(node_ops offsite-backup-restic)"
  else
    append_daily "$OFFSITE_BACKUP_AT" "restic-offsite" "$(node_ops offsite-backup-restic)"
  fi
fi

echo "Installed Platform backup scheduler crontab:"
cat "$CRON_FILE"

if [ "$DRY_RUN" = "true" ] || [ "$DRY_RUN" = "1" ]; then
  exit 0
fi

if [ "$RUN_ON_START" = "true" ] || [ "$RUN_ON_START" = "1" ]; then
  cd "$INFRA_ROOT"
  load_runtime_env
  node "$INFRA_ROOT/scripts/infra-ops.mjs" backup-applications
  node "$INFRA_ROOT/scripts/infra-ops.mjs" backup-postgres
  node "$INFRA_ROOT/scripts/infra-ops.mjs" backup-mariadb
  node "$INFRA_ROOT/scripts/infra-ops.mjs" backup-minio
  node "$INFRA_ROOT/scripts/infra-ops.mjs" backup-keycloak
  node "$INFRA_ROOT/scripts/infra-ops.mjs" backup-secret-manager-metadata
fi

process_backup_job_queue &

exec crond -f -l 8 -L "$LOG_DIR/backup-scheduler.log"
