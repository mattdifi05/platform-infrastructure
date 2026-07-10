# Backup and Recovery Coverage

The production candidate uses one typed platform backup job every eight hours. A job is complete only when every exact resource has one signed artifact in the same `platform.backup-manifest/v1` document.

## Protected resources

| Resource class | Discovery | Artifact |
| --- | --- | --- |
| Application source | Every non-hidden application directory under `PROJECT_SOURCE_ROOT`, excluding declared tooling, dependency and build directories | Per-application signed tar archive |
| Application database | Every active exact engine/name binding in `PROJECT_DATABASES_FILE` | Per-database PostgreSQL custom dump or MariaDB compressed SQL dump |
| Platform database | `APP_DB_NAME` and `KEYCLOAK_DB_NAME` | Per-database PostgreSQL custom dump |
| Object storage | Complete MinIO data state | Signed tar archive |
| Identity configuration | Keycloak realm/client/role configuration | Signed tar archive; the Keycloak database is protected separately |
| Control Center state | State files, encrypted Vault state and protected credential files; job queue and temporary copies are excluded | Restricted signed tar archive |
| Secret Manager | Encrypted metadata store and audit metadata, without the local master key | Signed tar archive |

The Backup Signing keyring, Restic password, rclone provider credentials, Control Center Vault keyring and Secret Manager master key require separate protected escrow. They are deliberately not embedded in the backup set they unlock.

Redis, NATS and observability runtime state are rebuild-only. Their business-critical state must remain in a protected database or object store. The authoritative policy is `governance/backup-data-policy.json`.

## Schedule and retention

- `05 */8 * * *`: create the complete local platform catalog.
- `35 */8 * * *`: upload that exact manifest and all of its signed artifacts when off-site backup is enabled.
- `50 */8 * * *`: produce a local retention plan. Apply remains disabled until `BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY=true` is approved.
- Local and off-site retention keep 42 complete restore points, equivalent to 14 days at three points per day.
- The Restic snapshot identity is the stable `platform-infrastructure` hostname, never a container ID.
- Unmanifested or invalid legacy artifacts are never deleted by manifest retention.

Backup directories are mode `0700`; artifacts, sidecars, manifests and reports are mode `0600`. Scheduler logs use the persistent `platform_backup_scheduler_logs` volume.

## Safe verification

```sh
sh scripts/infra-ops.sh backup-coverage-matrix
node scripts/backup-coverage-sandbox-test.mjs
BACKUP_SCHEDULER_DRY_RUN=true sh scripts/backup-scheduler.sh
sh scripts/infra-ops.sh prune-manifest-backups
```

The last command is plan-only. Applying deletion requires `--confirmPruneManifestBackups` and an approved maintenance step.

## Activation gates

Do not enable the candidate scheduler on the live host until:

1. T15 supplies and attests a real digest-pinned Restic/rclone helper image.
2. T08 proves restore of a complete signed manifest on a clean disposable host.
3. External key escrow is verified without placing key material in Git or evidence reports.
4. A fresh complete catalog and off-site restore receipt pass before retention apply is enabled.

This design is HA-prepared but remains single-node. Backups do not make the runtime highly available.
