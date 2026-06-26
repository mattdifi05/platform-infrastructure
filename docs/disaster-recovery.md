# Disaster Recovery

Disaster recovery is measured by recoverability evidence.

## Terms

- RPO: maximum acceptable data loss.
- RTO: maximum acceptable recovery time.

## Local vs off-site

Local restore proves the backup format. Off-site restore proves survival outside the host.

## Restic

Restic support is used for off-site backup and restore drills where configured.

## Production requirements

Production go/no-go expects:

- `coverage.complete=true`.
- Restore drills for configured data stores.
- Off-site restore evidence.
- `--allowPartial` only for bootstrap or explicitly documented partial environments.
