#!/usr/bin/env sh
set -eu

CRON_ROOT="/opt/platform/platform-infrastructure"
BACKUP_AT="03:15"
MARIADB_BACKUP_AT="03:45"
MINIO_BACKUP_AT="04:00"
KEYCLOAK_BACKUP_AT="04:10"
SECRET_MANAGER_BACKUP_AT="04:20"
RESTIC_AT="04:45"
LOG_DIR="/var/log/platform"

usage() {
  cat <<'EOF'
Usage: install-offsite-backup-cron.sh [--cron-root PATH] [--backup-at HH:MM] [--mariadb-backup-at HH:MM] [--minio-backup-at HH:MM] [--keycloak-backup-at HH:MM] [--secret-manager-backup-at HH:MM] [--restic-at HH:MM]

Print crontab lines for local PostgreSQL/MariaDB/MinIO/Keycloak/Secret
Manager metadata backups plus encrypted Restic off-site upload. Review and
install with `crontab -e`.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cron-root) shift; CRON_ROOT="${1:?Missing --cron-root value}" ;;
    --backup-at) shift; BACKUP_AT="${1:?Missing --backup-at value}" ;;
    --mariadb-backup-at) shift; MARIADB_BACKUP_AT="${1:?Missing --mariadb-backup-at value}" ;;
    --minio-backup-at) shift; MINIO_BACKUP_AT="${1:?Missing --minio-backup-at value}" ;;
    --keycloak-backup-at) shift; KEYCLOAK_BACKUP_AT="${1:?Missing --keycloak-backup-at value}" ;;
    --secret-manager-backup-at) shift; SECRET_MANAGER_BACKUP_AT="${1:?Missing --secret-manager-backup-at value}" ;;
    --restic-at) shift; RESTIC_AT="${1:?Missing --restic-at value}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

cron_line() {
  time_value="$1"
  command_value="$2"
  minute="${time_value#*:}"
  hour="${time_value%:*}"
  printf '%s %s * * * cd %s && mkdir -p %s && %s\n' "$minute" "$hour" "$CRON_ROOT" "$LOG_DIR" "$command_value"
}

cat <<EOF
# Platform backup schedule. Requires RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE in $CRON_ROOT/.env or the system environment.
$(cron_line "$BACKUP_AT" 'sh ./scripts/backup-postgres.sh >> /var/log/platform/postgres-backup.log 2>&1')
$(cron_line "$MARIADB_BACKUP_AT" 'sh ./scripts/backup-mariadb.sh >> /var/log/platform/mariadb-backup.log 2>&1')
$(cron_line "$MINIO_BACKUP_AT" 'sh ./scripts/backup-minio.sh >> /var/log/platform/minio-backup.log 2>&1')
$(cron_line "$KEYCLOAK_BACKUP_AT" 'sh ./scripts/backup-keycloak.sh >> /var/log/platform/keycloak-backup.log 2>&1')
$(cron_line "$SECRET_MANAGER_BACKUP_AT" 'sh ./scripts/backup-secret-manager-metadata.sh >> /var/log/platform/secret-manager-backup.log 2>&1')
$(cron_line "$RESTIC_AT" '. ./.env >/dev/null 2>&1 || true; sh ./scripts/offsite-backup-restic.sh >> /var/log/platform/restic-offsite.log 2>&1')
EOF
