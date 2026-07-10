# Platform Data Classification

This document classifies data handled by the platform infrastructure. Hosted
application datasets remain application-owned and must keep their own
classification when business logic, users or customer data are involved.

## Classification Levels

| Level | Meaning | Examples | Handling |
| --- | --- | --- | --- |
| Public | Safe to publish. | README, runbooks, non-sensitive diagrams. | May be committed to Git. |
| Internal | Operational metadata without secrets. | Container names, service health, non-secret reports. | Git or Control Center allowed. |
| Confidential | Sensitive operational metadata. | Admin audit events, provider metadata, backup inventory. | Restrict to operators; redact before sharing. |
| Secret | Authentication or cryptographic material. | Tokens, passwords, private keys, signing keys, KMS material. | Never commit; store in vault/secret manager or external KMS. |
| Restricted | Data that could expose users, customers or live payloads. | Database dumps, backup contents, personal data, live request bodies. | Keep encrypted, access logged, restore only under approved procedure. |

## Platform Data Inventory

| Data type | Classification | Primary location | Treatment |
| --- | --- | --- | --- |
| Compose files and docs | Public/Internal | Repository | Commit allowed after review. |
| Control Center project metadata | Internal/Confidential | `projects-portal/state/*.json` | No secrets; audit mutations. |
| Control Center audit and operations log | Confidential | `projects-portal/state/*.jsonl` | Append-only operational evidence; redact before export. |
| Docker secrets materialized files | Secret | `secrets/*.txt`, `/run/secrets/*` | Ignored by Git; rotate and verify. |
| Secret manager encrypted store | Secret | `secrets/infra-secret-manager-store.json` | Encrypted local vault; never print values. |
| PostgreSQL/MariaDB data volumes | Restricted | Docker volumes | No public access; backup and restore under runbook. |
| MinIO objects | Restricted | Docker volumes / MinIO data | Backup encrypted; no public admin surface. |
| Backup artifacts | Restricted | `backups/`, off-site Restic repository | Encrypt, sign where applicable, test restore, prune by policy. |
| Logs and metrics | Internal/Confidential | Loki, Prometheus, Docker logs | Bounded retention; redact sensitive fields. |
| Release evidence and SBOM | Internal | `reports/`, GitHub Actions artifacts | Publish only non-secret reports. |
| Provider tokens and API keys | Secret | Vault/external provider secret store | Never commit; use `*_FILE` or GitHub secrets. |

## Handling Rules

- Secret and Restricted data must not be committed to Git.
- Generated reports must be non-secret and must not contain token values,
  passwords, private keys, raw dumps or customer payloads.
- Backup contents are Restricted even when filenames are Internal metadata.
- Logs are treated as Confidential until redaction evidence is current.
- Public sharing requires review of the exact artifact, not the folder name.
- New data types must be classified before go-live evidence can be claimed.

## Retention And Review

- Logs and metrics: governed by `retention-evidence`.
- Backups: governed by backup scheduler, restore drills and prune reports.
- Admin audit: reviewed through `platform-admin-audit`.
- Secrets: reviewed through `secret-rotation-evidence` and secret scan.
- Review cadence: before production go-live, after adding a new platform service,
  and quarterly during production operation.
