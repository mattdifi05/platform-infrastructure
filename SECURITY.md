# Stexor Security Baseline

## Authentication and sessions

- Account sessions are signed server-side and stored in `HttpOnly`, `Secure`, `SameSite=Lax` cookies by default.
- Mutating API calls reject untrusted `Origin` headers and hostile Fetch Metadata.
- Passkeys are the preferred high-assurance factor.
- Redis stores only short-lived auth state; PostgreSQL remains the durable source of truth.
- Fastify rate limiting uses Redis when available, so limits remain consistent across backend replicas.

## Roles

- `owner`: full platform ownership.
- `admin`: operational administration.
- `developer`: build/deploy diagnostics.
- `billing`: services and subscription management.
- `viewer`: read-only baseline.

Roles are stored in `stexor_account.account_roles` and must not be trusted from the client.

## Secrets

- `.env` is local-only and ignored by Git.
- Local development and single-node Docker production can use the proprietary `stexor-secret-manager`.
- The manager keeps the canonical store encrypted under `secrets/stexor-secret-manager-store.json`, wraps records with the proprietary `stexor-local-kms` envelope layer, writes an audit log and materializes Docker secret files under `secrets/*.txt`.
- Local secret files and manager runtime files are ignored by Git and mounted as `/run/secrets/*`.
- Runtime code must consume secret material only through `*_FILE` values or approved managed secret references.
- `SESSION_SECRET` must be random, long and rotated per environment.
- SMTP, DB, MinIO, NATS, Redis, Grafana, projects gateway and Alertmanager webhook secrets must be managed through `stexor-secret-manager` or a stronger external KMS before serious VPS usage.

## Local control access

- `projects.localhost.com` is not a public app surface. It requires an email OTP before exposing project/admin links.
- Its persistent cookie is `HttpOnly`, `Secure`, `SameSite=Lax` and signed with `projects_gateway_signing_keys`.
- Rotate `projects_gateway_signing_keys` to revoke every local Projects Control session.

## Alert delivery

- Alertmanager webhooks require the bearer token from `/run/secrets/alertmanager_webhook_token`.
- Email alerts use SMTP credentials from Docker secrets and expose delivery/failure counters.
- Alert messages must contain summaries and labels only; do not include bearer tokens, cookies, passwords or OTP values in alert annotations.

## Database

- PostgreSQL is not public in production.
- Query execution is statement-time-limited and row-limited.
- Operational logs are centralized in Loki/Promtail with shared application redaction in `@stexor/observability`; durable security events are stored in append-only audit tables and dispatched through the audit outbox.

## Required recurring checks

- Mandatory supply-chain gate: production CVE audit, CycloneDX SBOM and license policy.
- Container image scan.
- Backup restore tests for PostgreSQL, MariaDB, MinIO, Keycloak configuration and Secret Manager metadata.
- Fault-injection tests for Redis degradation, PostgreSQL timeout and session races.
- Certificate expiry check.
- RBAC review.
- Audit log review.
- Renovate dependency dashboard review for application, infra, container and GitHub Actions updates.
- `sh ./scripts/enterprise-hardening-audit.sh`.
- `sh ./scripts/infra-health.sh`.
- `sh ./scripts/secret-scan.sh`.
- `sh ./scripts/stexor-secret-manager.sh verify`.
- `sh ./scripts/fault-injection-tests.sh`.
- `sh ./scripts/failure-tests.sh`.
- `sh ./scripts/failure-tests.sh --confirmServiceStop` in staging before major releases.
- `sh ./scripts/supply-chain-hygiene.sh`.
- `sh ./scripts/generate-sbom.sh`.
- `sh ./scripts/production-preflight.sh` before every VPS release.
- `sh ./scripts/load-smoke.sh` after every deploy.
- `sh ./scripts/load-benchmark.sh --profiles 50,100,500` before production cutover and after capacity changes.
- `sh ./scripts/access-review.sh` monthly.
- `sh ./scripts/offsite-backup-restic.sh` after the full local backup set in production.
- `sh ./scripts/rollback-release.sh` as a dry-run before every approved rollback.
- `sh ./scripts/sign-images.sh` for immutable production images.
