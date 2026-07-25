# Platform Security Baseline

## Vulnerability disclosure

Report suspected vulnerabilities privately through the repository Security Policy
or to the configured production security contact. Do not open public issues with
exploit details, credentials, personal data or live target output.

Disclosure process:

- acknowledgement target: 72 hours;
- initial severity triage target: 5 business days;
- accepted reports get an owner, remediation plan and non-secret tracking
  evidence;
- reporters are updated when the fix is deployed or when a compensating control
  is applied;
- public disclosure happens only after remediation, validation and operator
  approval;
- emergency reports involving active exploitation, credential exposure or data
  access are handled as incident-response events.

Allowed report content: affected platform component, environment, impact,
reproduction summary, timestamps, request IDs and sanitized evidence.

Never include secrets, tokens, private keys, real user data, backup contents,
database dumps or live exploitation output in public reports.

## Admin Control Plane

- Control Center access is fail-closed through Keycloak OIDC Authorization Code
  with PKCE and passkey-attested `acr`/`amr` claims. There is no production
  local-password path.
- Browser cookies contain opaque session identifiers with `HttpOnly`, `Secure`
  and `SameSite=Lax`; transactions and revocable sessions are server-side.
- Mutating Control Center API calls reject untrusted `Origin` headers and hostile
  Fetch Metadata.
- Cloudflare Access or equivalent provider MFA is required for production admin
  surfaces.
- Redis-backed rate limiting is an infrastructure capability; hosted app auth
  factors are app-owned and not platform go-live gates.

## Roles

- `owner`: full platform ownership.
- `admin`: operational administration.
- `developer`: build/deploy diagnostics.
- `billing`: services and subscription management.
- `viewer`: read-only baseline.

Infrastructure admin authorization is tracked through Control Center identity
metadata, Cloudflare Access policy evidence and platform-admin-audit reports.
Hosted application identities and account schemas are workload concerns and are
not platform go-live gates.

## Secrets

- `.env` is local-only and ignored by Git.
- Local development and single-node Docker production can use the proprietary `infra-secret-manager`.
- The manager keeps the canonical store encrypted under `secrets/infra-secret-manager-store.json`, wraps records with the proprietary `local-bucket-kms` envelope layer, writes an audit log and materializes Docker secret files under `secrets/*.txt`.
- The manager is also the local secret vault for arbitrary operational secrets such as provider tokens. Vault secret names are constrained to lowercase letters, numbers and underscores; commands print metadata and fingerprints only, never values.
- Local secret files and manager runtime files are ignored by Git and mounted as `/run/secrets/*`.
- Runtime code must consume secret material only through `*_FILE` values or approved managed secret references.
- Every platform secret must be random, scoped, rotated per environment and
  declared in the platform Secret Manager policy.
- SMTP, platform DB, MinIO, Redis, Grafana, admin OIDC and Alertmanager webhook
  secrets must be managed through `infra-secret-manager` or a stronger external
  KMS before serious VPS usage.
- Application secrets are declared by the external workload manifest. The core
  must not require, materialize or scan their values during a zero-workload
  render.

## Local control access

- `portal.localhost.com` is the local Infrastructure Portal host, not a public app surface. It requires the Control Center admin gate before exposing project/admin links.
- Its persistent cookie is opaque, `HttpOnly`, `Secure` and `SameSite=Lax`.
- Revoke sessions through the Control Center session store and Keycloak policy;
  do not add a local password or static cookie-verifier fallback.

## Alert delivery

- Alertmanager webhooks require the bearer token from `/run/secrets/alertmanager_webhook_token`.
- Email alerts use SMTP credentials from Docker secrets and expose delivery/failure counters.
- Alert messages must contain summaries and labels only; do not include bearer tokens, cookies, passwords or OTP values in alert annotations.

## Database

- PostgreSQL is not public in production.
- Query execution is statement-time-limited and row-limited.
- Operational logs are centralized in Loki/Promtail with platform redaction;
  Control Center administrative events use append-only JSONL evidence.
- Each hosted workload owns its schema and migration path. Its services use
  distinct PostgreSQL logins and must prove cross-table denial before legacy
  credentials are revoked.
- Application RLS is defense in depth, not a supported platform tenant boundary.
- Hosted workloads never receive MinIO root material. Use one service account
  per bucket/prefix and prove cross-prefix, cross-bucket and admin denial.

## Runtime isolation

- The VPS render must load `compose.runtime-isolation.yaml` last.
- Every service has CPU, memory, PID, file-descriptor and I/O controls.
- Hosted source mounts are exact and read-only; hosted workloads must not see
  the infrastructure tree, backups, Control Center state or Docker socket.
- Hosted manifests, Compose files, non-secret environments and migrations are
  hash-locked. A changed input fails closed before Compose activation.
- PHP runtime copies are ephemeral tmpfs and receive no shared gateway-signing
  or SMTP secret.
- Only the typed Docker operation gateway receives the raw socket. It has no
  host endpoint; its scheduler-specific credential is mounted only by the
  gateway and backup scheduler on their two-member internal control network.
- Raw socket recovery mode requires explicit approval and both recovery flags.

## Required recurring checks

- Mandatory supply-chain gate: production CVE audit, CycloneDX SBOM and license policy.
- Container image scan.
- Backup restore tests for PostgreSQL, MariaDB, MinIO, Keycloak configuration and Secret Manager metadata.
- Fault-injection tests for platform dependencies and bounded failure recovery.
- Certificate expiry check.
- RBAC review.
- Audit log review.
- Renovate dependency dashboard review for application, infra, container and GitHub Actions updates.
- `sh ./scripts/enterprise-hardening-audit.sh`.
- `sh ./scripts/infra-health.sh`.
- `sh ./scripts/secret-scan.sh`.
- `sh ./scripts/infra-secret-manager.sh verify`.
- `sh ./scripts/fault-injection-tests.sh`.
- `sh ./scripts/failure-tests.sh`.
- `sh ./scripts/failure-tests.sh --confirmServiceStop` in staging before major releases.
- `sh ./scripts/supply-chain-hygiene.sh`.
- `sh ./scripts/generate-sbom.sh`.
- `sh ./scripts/production-preflight.sh` before every VPS release.
- `sh ./scripts/load-smoke.sh` after every deploy.
- `sh ./scripts/load-benchmark.sh --profiles 50,100,500` before production cutover and after capacity changes.
- `sh ./scripts/platform-admin-audit.sh` monthly and after admin/provider changes.
- `sh ./scripts/offsite-backup-restic.sh` after the full local backup set in production.
- `sh ./scripts/rollback-release.sh` as a dry-run before every approved rollback.
- `sh ./scripts/sign-images.sh` for immutable production images.
- `node scripts/t16-policy.mjs` after every release workflow or GitHub governance change.
- Release admission must invoke the checksum-pinned GitHub verifier directly;
  unsigned SLSA, normalized `verified=true` reports and commit-check bypasses are
  forbidden.
- `sh ./scripts/runtime-isolation-check.sh --env-file=.env.vps.example` after every Compose/runtime change.
- `sh ./scripts/runtime-isolation-sandbox-test.sh` before limit changes.
- the non-privileged `testing-hygiene` CI job on the exact checkout; and
- a workload lock emitted through the configured trusted ops producer. The
  `infra-ops.sh` and `prepare-hosted-workloads.sh` paths may execute only after
  revalidating the exact provider receipt chain, clean checkout, digest and
  local image ID. The repository policy remains `EXTERNAL-PENDING`, so it
  cannot currently satisfy production admission.
