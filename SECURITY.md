# Stexor Security Baseline

## Authentication and sessions

- Account sessions are signed server-side and stored in `HttpOnly`, `Secure`, `SameSite=Lax` cookies by default.
- Mutating API calls reject untrusted `Origin` headers and hostile Fetch Metadata.
- DB Console requires an allowlisted email, an enterprise role (`owner`, `admin`, `db_admin`) and a fresh passkey challenge.
- Passkeys are the preferred high-assurance factor.
- Redis stores only short-lived auth state; PostgreSQL remains the durable source of truth.
- Fastify rate limiting uses Redis when available, so limits remain consistent across backend replicas.

## Roles

- `owner`: full platform ownership.
- `admin`: operational administration.
- `db_admin`: database console administration.
- `developer`: build/deploy diagnostics.
- `billing`: services and subscription management.
- `viewer`: read-only baseline.

Roles are stored in `stexor_account.account_roles` and must not be trusted from the client.

## Secrets

- `.env` is local-only and ignored by Git.
- Local development and single-node Docker production can use the proprietary `stexor-secret-manager`.
- The manager keeps the canonical store encrypted under `secrets/stexor-secret-manager-store.json`, writes an audit log and materializes Docker secret files under `secrets/*.txt`.
- Local secret files and manager runtime files are ignored by Git and mounted as `/run/secrets/*`.
- Runtime code must prefer `*_FILE` values over raw secret environment variables.
- `SESSION_SECRET` must be random, long and rotated per environment.
- SMTP, DB, MinIO, NATS, Redis and Grafana secrets must be managed through `stexor-secret-manager` or a stronger external KMS before serious VPS usage.

## Database

- PostgreSQL is not public in production.
- DB Console write mode is disabled by default.
- Query execution is statement-time-limited and row-limited.
- DB Console activity is audit logged with query fingerprints.
- Console reads use `stexor_console_readonly`; sensitive tables stay denied.
- Operational logs are centralized in Loki/Promtail with shared application redaction in `@stexor/observability`; durable security events are stored in append-only audit tables and dispatched through the audit outbox.

## Required recurring checks

- Mandatory supply-chain gate: production CVE audit, CycloneDX SBOM and license policy.
- Container image scan.
- Backup restore test.
- Fault-injection tests for Redis degradation, PostgreSQL timeout and session races.
- Certificate expiry check.
- RBAC review.
- Audit log review for DB Console access.
- `sh ./scripts/enterprise-hardening-audit.sh`.
- `sh ./scripts/secret-scan.sh`.
- `sh ./scripts/stexor-secret-manager.sh verify`.
- `sh ./scripts/fault-injection-tests.sh`.
- `sh ./scripts/supply-chain-hygiene.sh`.
- `sh ./scripts/generate-sbom.sh`.
- `sh ./scripts/production-preflight.sh` before every VPS release.
- `sh ./scripts/load-smoke.sh` after every deploy.
- `sh ./scripts/access-review.sh` monthly.
- `sh ./scripts/offsite-backup-restic.sh` after PostgreSQL backup in production.
- `sh ./scripts/sign-images.sh` for immutable production images.
