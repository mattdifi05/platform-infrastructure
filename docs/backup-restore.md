# Backup and Restore

Backup coverage includes:

- PostgreSQL.
- MariaDB.
- MinIO/storage.
- Keycloak.
- Secret Manager metadata.

## Scripts

- `scripts/backup-postgres.sh`
- `scripts/backup-mariadb.sh`
- `scripts/backup-minio.sh`
- `scripts/backup-keycloak.sh`
- `scripts/backup-secret-manager-metadata.sh`
- `scripts/full-restore-drill.sh`

## Restore tests

Restore tests prove backup usability. Production readiness requires restore evidence, not just backup file creation.

## Scheduler and retention

The backup scheduler and retention evidence scripts document recurring backup behavior and cleanup policy.

## Off-site

Off-site backup/restore is required for production go/no-go. Local-only backups are not enough.
