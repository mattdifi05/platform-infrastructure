# Platform Enterprise Runbook

## Incident triage

1. Check service health:

   ```sh
   sh ./scripts/compose-healthcheck-coverage.sh
   sh ./scripts/rate-limit-evidence.sh
   sh ./scripts/audit-log-evidence.sh
   sh ./scripts/retention-evidence.sh
   sh ./scripts/infra-health.sh
   docker ps --format "table {{.Names}}\t{{.Status}}" | grep enterprise-
   ```

`compose-healthcheck-coverage.sh` verifies the rendered local WAF, VPS WAF and backup-scheduler stacks have a healthcheck on every operational service and writes non-secret reports under `reports/healthchecks/`.
`rate-limit-evidence.sh` verifies edge/API rate-limit configuration and writes non-secret reports under `reports/rate-limits/`; it runs infra-only when the Platform app source is intentionally not mounted.
`audit-log-evidence.sh` verifies append-only audit events, durable outbox dispatch, alerts, dashboards and optional Platform source wiring, then writes non-secret reports under `reports/audit-logs/`.
`retention-evidence.sh` verifies bounded Docker logs, Loki/Promtail retention, Prometheus TSDB retention, Grafana log panels and optional Platform structured log redaction, then writes non-secret reports under `reports/retention/`.

The shell wrappers are container-first. On Linux they run the ops container with host networking so `*.localhost.com` resolves to the local edge. On Docker Desktop they map those hostnames to `host-gateway`; override `PLATFORM_LOCAL_HOST_TARGET` only if your Docker runtime exposes the host through a different address.

2. Check edge and API:

   ```sh
   sh ./scripts/enterprise-hardening-audit.sh
   sh ./scripts/security-smoke.sh
   sh ./scripts/waf-smoke.sh
   curl https://api.localhost.com/health
   ```

3. Read scoped logs:

   ```sh
   docker compose -p platform_infra_local logs -f traefik backend web postgres
   ```

4. Check database migrations:

   ```sh
   docker exec enterprise-postgres psql -U postgres -d app_db -c "select * from platform_ops.schema_migrations order by applied_at desc;"
   ```

## WAF operations

The WAF is the only container that should publish public HTTP/HTTPS ports when `compose.waf.yaml` is active. It terminates or receives edge traffic, runs OWASP CRS/ModSecurity, then forwards benign requests to internal Traefik.

Useful checks:

```sh
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "enterprise-waf|enterprise-traefik"
sh ./scripts/rate-limit-evidence.sh
sh ./scripts/waf-smoke.sh
docker logs --tail 200 enterprise-waf
```

Prometheus, Alertmanager and the Traefik dashboard are intentionally not routed to browser hostnames. Use Grafana for browser access to metrics/logs, and Docker exec or internal network probes for raw Prometheus/Alertmanager diagnostics.

Expected blocks:

```sh
curl -k -o /dev/null -s -w "%{http_code}\n" "https://api.localhost.com/health?x=<script>alert(1)</script>"
curl -k -o /dev/null -s -w "%{http_code}\n" "https://projects.localhost.com/.env"
```

Both should return `403`. If a real workflow is blocked, keep `WAF_BLOCKING_PARANOIA=2`, inspect the JSON audit event in `enterprise-waf`, then add the smallest possible exclusion to `waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` or `waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`. Raise to PL3/PL4 only after the audit log is clean for the affected apps.

## Feature Flags And Kill Switches

Treat every risky launch feature as disabled-by-default until it has an owner, rollback path and monitoring signal. Document the feature flag name, default value, owning service, production enablement window and emergency disable command in the release evidence pack. If a feature does not have a runtime flag yet, the approved kill switch is a release rollback through `rollback-release.sh` plus the smallest environment or routing change needed to remove public exposure.

## Alerting

Prometheus sends alerts to Alertmanager, and Alertmanager posts grouped alerts to the notification worker at `worker-notifications:3000/alerts/prometheus` with the shared bearer token from `/run/secrets/alertmanager_webhook_token`. The worker logs sanitized alert summaries into Loki and exposes delivery counters on `/metrics`.

Alert evidence:

```sh
sh ./scripts/alert-evidence.sh
sh ./scripts/alert-evidence.sh --sendTest
sh ./scripts/alert-evidence.sh --sendTest --requireEmailDelivery
```

The summary mode validates Alertmanager routing, bearer-token secrets, Prometheus delivery-failure alerts and notification-worker counters. `--sendTest` posts a synthetic Alertmanager payload to the running worker and checks webhook counters. Add `--requireEmailDelivery`, `--requireDiscordDelivery` or `--requireTelegramDelivery` only after those real provider channels are configured.

Key alerts:

```text
ServiceTargetDown
BackendRedisUnavailable
WorkerPostgresUnavailable
AuditOutboxDeadLetters
PostgresBackupStale
RestoreDrillStale
AlertmanagerDeliveryFailed
HostDiskUsageHigh
HostMemoryUsageHigh
HostCpuUsageHigh
ContainerCpuUsageHigh
ContainerMemoryUsageHigh
ContainerDisappeared
WafBlockSpike
```

Optional external forwarding:

```sh
ALERT_FORWARD_WEBHOOK_URL=https://hooks.example.invalid/platform-alerts
```

Keep the URL in the production secret manager if it embeds credentials.

Email delivery is enabled when `ALERT_EMAIL_TO`, `MAILER_FROM`, `SMTP_HOST`, `SMTP_USER` and `/run/secrets/smtp_password` are configured. Local default recipient is `admin@example.com`. Watch:

```promql
notification_alert_email_deliveries_total
notification_alert_email_failures_total
```

If email failures increase, check `docker logs enterprise-worker-notifications` for `prometheus_alert_email_failed`, then verify SMTP credentials through the secret manager rather than putting the password in `.env`.

Native Discord and Telegram alert channels are optional and disabled by default. Enable them only through mounted secret files:

```sh
ALERT_DISCORD_WEBHOOK_URL_FILE=/run/secrets/alert_discord_webhook_url
ALERT_TELEGRAM_BOT_TOKEN_FILE=/run/secrets/alert_telegram_bot_token
ALERT_TELEGRAM_CHAT_ID=123456789
```

The notification worker exposes:

```promql
notification_alert_discord_deliveries_total
notification_alert_discord_failures_total
notification_alert_telegram_deliveries_total
notification_alert_telegram_failures_total
```

Keep the Discord webhook URL and Telegram bot token in the production secret manager or provider KMS. Do not put them in `.env` or Git.

## External uptime monitoring

The provider-neutral manifest is `monitoring/external-uptime.example.json`. It covers the public web edge, API health, OIDC discovery and negative checks for admin hostnames that must stay blocked.

Validate the manifest before creating provider monitors:

```sh
sh ./scripts/external-uptime-check.sh --dryRun
```

The dry-run writes a diagnostic `reports/uptime/external-uptime-*.json` and
`.md` with `mode=dry-run` and `providerEvidence.verified=false`. Archive it as
manifest evidence only; production go/no-go still requires verified external
provider evidence.

After DNS/CDN/TLS are live, create equivalent monitors in Cloudflare Health
Checks, BetterStack or UptimeRobot with the same expected status codes, keyword
checks and latency budgets. Copy
`monitoring/external-uptime-provider.example.json` to a production-only evidence
file, fill the provider monitor ids, regions and a fresh `verifiedAt` timestamp,
plus provider-reported `lastStatusCode`, `lastLatencyMs` and `lastCheckedAt`
for every monitor. Validate the evidence file, then run the real probe from
outside the local network or from the VPS:

```sh
sh ./scripts/external-uptime-check.sh \
  --providerEvidence ./monitoring/external-uptime-provider.production.json \
  --validateProviderEvidenceOnly

sh ./scripts/external-uptime-check.sh \
  --envFile .env \
  --providerEvidence ./monitoring/external-uptime-provider.production.json \
  --requireProviderEvidence
```

Archive the JSON/Markdown report from `reports/uptime/`. The production
go/no-go gate rejects reports that only prove local HTTP reachability and do not
include verified external provider evidence with fresh provider-reported
results.

## Resilience drills

Run these before major releases and after infrastructure changes:

```sh
sh ./scripts/fault-injection-tests.sh
sh ./scripts/failure-tests.sh --confirmServiceStop --targets redis,postgres,minio,keycloak,backend,worker-notifications,worker-jobs,nats,waf
sh ./scripts/infra-ops.sh load-profile --durationSeconds 60 --targetRps 8 --concurrency 8 --maxP95Ms 1000
sh ./scripts/load-benchmark.sh --profiles 50,100,500 --durationSeconds 60 --perUserRps 0.2 --maxP95Ms 1000
sh ./scripts/load-benchmark.sh --profiles 50,100,500 --url https://api.example.com/health --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare
sh ./scripts/infra-ops.sh chaos-profile --confirmChaos
```

Acceptance criteria:

- Redis degradation does not bypass sensitive endpoint rate limits.
- PostgreSQL statement timeout cancels slow queries and rolls back cleanly.
- Audit outbox due/dead/failed metrics stay explainable after worker interruption.
- Backend p95 stays under the declared threshold for the selected profile.
- `failure-tests` writes a non-sensitive detection/recovery report under `reports/failure-tests/`.
- `load-benchmark` writes JSON/Markdown reports under `reports/load/`, including Docker CPU/RAM snapshots before and after each profile.
- The production `load-benchmark` run must target the public API URL, classify the target as public, record edge/CDN evidence and finish with `status=passed`. With Cloudflare enabled, use `--requireEdgeEvidence --expectedEdgeProvider cloudflare`; otherwise document the reviewed provider exception before go-live. Failed preflights or profiles still write diagnostic reports under `reports/load/`, but they do not satisfy production go/no-go.

The load profile uses a bounded synthetic `X-Forwarded-For` client pool by default so the performance probe does not collide with the security rate-limit budget consumed by smoke and E2E checks. Use `--preserveClientIp` when deliberately testing one-client throttling behavior.

If `AuditOutboxDeadLetters` fires, pause risky account operations, inspect `{job="docker",service="enterprise-worker-jobs"} |= "audit_outbox"`, fix the downstream sink, then replay only events whose `external_event_id` has not already been accepted by the sink.

If `BackendRedisUnavailable` fires, keep login, passkey, OTP and backup-code traffic under the degraded memory budget until Redis is healthy. Do not raise rate-limit ceilings during the incident.

## Centralized logs and audit

Promtail reads Docker JSON logs from `/var/lib/docker/containers` without Docker socket service discovery. Its pipeline unwraps Docker log entries, redacts common sensitive fields (`authorization`, `cookie`, `set-cookie`, `password`, `secret`, `token`, `otp`, passkey credentials and challenges), parses JSON app logs and labels them by `service` and `level`.

Primary operator queries:

```logql
{job="docker",service=~"enterprise-.+",level=~"warn|error"}
{job="docker",service="enterprise-backend"} |= "request failed"
{job="docker",service="enterprise-worker-jobs"} |= "audit_outbox"
```

Use Loki for operational logs and PostgreSQL `app_account.audit_events` plus `app_account.audit_outbox` for durable security/compliance events. Audit tables are append-only and RLS protected.
Run `sh ./scripts/audit-log-evidence.sh` before go-live and after audit/outbox changes; archive `reports/audit-logs/audit-log-evidence-*.json` with the release evidence.
Run `sh ./scripts/retention-evidence.sh` after log/metric retention changes and before go-live; archive `reports/retention/retention-evidence-*.json` with the release evidence.

## Backup

Manual backup:

```sh
sh ./scripts/backup-postgres.sh
sh ./scripts/backup-mariadb.sh
sh ./scripts/backup-minio.sh
sh ./scripts/backup-keycloak.sh
sh ./scripts/backup-secret-manager-metadata.sh
```

Daily Linux cron:

```sh
sh ./scripts/install-postgres-backup-cron.sh --cronRoot /opt/platform/platform-infrastructure --backupAt 03:15 --drillAt 04:15 --retentionAt 05:15 --drillWeekday 0
sh ./scripts/install-mariadb-backup-cron.sh --cronRoot /opt/platform/platform-infrastructure --backupAt 03:45 --drillAt 04:45 --drillWeekday 0
sh ./scripts/install-offsite-backup-cron.sh --cron-root /opt/platform/platform-infrastructure
```

The generated crontab covers PostgreSQL/MariaDB local database backups, weekly restore drills, daily PostgreSQL backup-artifact retention, MinIO/Keycloak/Secret Manager metadata backups, and encrypted Restic off-site upload.

Preferred VPS scheduler:

```sh
docker compose --env-file .env -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f compose.backup-scheduler.yaml \
  --profile backup \
  up -d backup-scheduler

docker logs enterprise-backup-scheduler
docker exec enterprise-backup-scheduler crontab -l
```

This keeps scheduling inside Docker. The host only needs Docker, Compose and Git. The scheduler autodetects Docker mount sources; set `PLATFORM_INFRA_HOST_ROOT` and `PROJECT_SOURCE_HOST_ROOT` only when the VPS uses nonstandard paths. Enable off-site upload with `BACKUP_SCHEDULER_ENABLE_OFFSITE=true` after `RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE` and provider credentials are valid. Scheduled jobs call `backup-scheduler.sh --run <command>` and parse the private runtime env file as data instead of sourcing it as shell code.

## Local secrets

```sh
sh ./scripts/infra-secret-manager.sh init
sh ./scripts/infra-secret-manager.sh verify
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local up -d
```

`infra-secret-manager` is the proprietary local secret manager. It encrypts the canonical store, writes an audit log and materializes `secrets/*.txt` only for Docker Compose. Use `--sanitizeEnv` on `init-local-secrets` only after you are committed to starting local with `compose.secrets.yaml`.

Useful operations:

```sh
sh ./scripts/infra-secret-manager.sh status
sh ./scripts/infra-secret-manager.sh kms-status
sh ./scripts/infra-secret-manager.sh kms-rotate
sh ./scripts/infra-secret-manager.sh rotate --name session_signing_keys
sh ./scripts/infra-secret-manager.sh rotate --name projects_gateway_signing_keys
sh ./scripts/infra-secret-manager.sh rotate --name backup_signing_keys
sh ./scripts/infra-secret-manager.sh rotate --name alertmanager_webhook_token
sh ./scripts/secret-rotation-evidence.sh --enforce
```

`secret-rotation-evidence.sh --enforce` validates the encrypted store, materialized Docker secret files, audit log, Platform Local KMS age and every secret `rotationDays` window without printing secret values. Archive `reports/secret-rotation/secret-rotation-evidence-*.json` outside Git before production go/no-go.

`projects.localhost.com` is the Node-based Stexor Control Center served by the `control-center` container. It stays separate from PHP Apache, reads project inventory from `PHP_PROJECTS_DIR`, stores local enable/disable, metadata update, archive and soft-delete state in `projects-portal/state/projects.json`, stores declarative application metadata in `projects-portal/state/applications.json`, stores declarative domain metadata in `projects-portal/state/domains.json`, stores declarative web spaces and quota metadata in `projects-portal/state/webspaces.json`, stores per-project resource limits in `projects-portal/state/resource-limits.json`, stores local security policy metadata in `projects-portal/state/security-policies.json`, stores local alert metadata in `projects-portal/state/alerts.json`, stores notification-channel metadata in `projects-portal/state/notification-channels.json`, stores provider connection metadata in `projects-portal/state/provider-connections.json`, stores local settings preferences in `projects-portal/state/settings.json`, appends sanitized local audit events to `projects-portal/state/audit.jsonl`, persists Operation/OperationStep records in `projects-portal/state/operations.jsonl`, stores deploy/rollback plans in `projects-portal/state/deployments.jsonl`, and stores backup/restore drill plans in `projects-portal/state/backups.jsonl`. `PHP_SOURCE_DIR` points at `php-runtime-root`, a neutral static Apache root; PHP Apache is only the runtime for PHP projects and does not own the Control Center UI or API. Production/provider operations are plan-only from this foundation unless an explicit adapter and confirmation gate are added. For staging/VPS set `CONTROL_CENTER_AUTH_REQUIRED=true` and set `CONTROL_CENTER_ADMIN_PASSWORD_SHA256` to the SHA-256 hash of the admin password; the session cookie is signed with the existing `projects_gateway_signing_keys` Docker secret and login success/failure is audited without storing passwords.
Advanced Mode exposes the requested enterprise skeleton areas, including Workers & Jobs, CI/CD & GitHub Governance, Logs/Alerts Advanced, Disaster Recovery, Release Evidence, Security Advanced and Billing / Plans. These surfaces remain plan/evidence-only until an explicit adapter performs apply plus verifyRemote.
The read-only Advanced API is available at `/control/advanced` and `/control/advanced/:section`; it exposes capabilities, guardrails and evidence metadata without live provider calls, Docker mutations or production evidence claims.
The backend adapter registry is available at `/control/adapters` and `/control/adapters/:id`; it covers Cloudflare, Traefik, Docker, GitHub, Prometheus, Loki, Alertmanager, Backup, Restore, MinIO, Database, Security and Go/No-Go. `/control/adapters/:id/plan` and `/verify` create audited plans, while `/apply` is rejected until an explicit live backend implementation, strong confirmation and verifyRemote are added.

## Restore test

Never trust a backup that has not been restored.

```sh
sh ./scripts/restore-test-postgres.sh --backupFile ./backups/postgres/app_db-YYYYMMDD-HHMMSS.dump
sh ./scripts/restore-test-mariadb.sh --backupFile ./backups/mariadb/mariadb-all-YYYYMMDD-HHMMSS.sql.gz
sh ./scripts/restore-test-minio.sh --backupFile ./backups/minio/minio-data-YYYYMMDD-HHMMSS.tar.gz
sh ./scripts/restore-test-keycloak.sh --backupFile ./backups/keycloak/keycloak-config-YYYYMMDD-HHMMSS.tar.gz
sh ./scripts/restore-test-secret-manager-metadata.sh --backupFile ./backups/secret-manager/secret-manager-metadata-YYYYMMDD-HHMMSS.tar.gz
```

Scheduled drill:

```sh
sh ./scripts/backup-restore-drill.sh
sh ./scripts/backup-restore-drill-mariadb.sh
sh ./scripts/backup-restore-drill-minio.sh
sh ./scripts/backup-restore-drill-keycloak.sh
sh ./scripts/backup-restore-drill-secret-manager-metadata.sh
sh ./scripts/full-restore-drill.sh
sh ./scripts/dr-evidence.sh
```

MariaDB restore tests import the signed compressed dump into a disposable MariaDB container and never write into the live `enterprise_mariadb_data` volume.
MinIO restore drills use a disposable Docker volume and container. Keycloak restore drills validate exported realm/client/role JSON without importing into the live server. Secret Manager metadata drills verify the encrypted store metadata and KMS status without packaging the local master key.
Each backup command writes a non-secret execution report under `reports/backups/` with status, duration, artifact path, size, SHA256 and signature key id. Review these reports after the first VPS backup window and after any failed scheduler run.
`full-restore-drill.sh` runs every local data-family drill, runs `infra-health`, and writes the measured restore timing report under `reports/restore-drills/`.
`dr-evidence.sh` summarizes RPO/RTO evidence across backup, local restore and off-site restore reports. Run it after every scheduled drill window; run `dr-evidence.sh --enforce` in staging/VPS so missing fresh backup reports, missing off-site restore reports or restore timings above the 60-minute RTO fail the release gate.

Backup artifact retention:

```sh
sh ./scripts/prune-postgres-backups.sh --dryRun
sh ./scripts/prune-postgres-backups.sh
```

Retention refuses to delete dump artifacts unless `platform_ops.backup_restore_runs` contains a recent successful `restore_test`.

## Off-site backup

```sh
export RESTIC_REPOSITORY="s3:s3.amazonaws.com/bucket/platform"
sh ./scripts/offsite-backup-restic.sh --passwordFile ./secrets/restic_password.txt
sh ./scripts/offsite-restore-drill-restic.sh --planOnly
sh ./scripts/offsite-restore-drill-restic.sh --dryRun --passwordFile ./secrets/restic_password.txt
sh ./scripts/offsite-restore-drill-restic.sh --passwordFile ./secrets/restic_password.txt
sh ./scripts/install-offsite-backup-cron.sh --cron-root /opt/platform/platform-infrastructure
```

Without `--backupFile`, the Restic command uploads the latest signed PostgreSQL, MariaDB, MinIO, Keycloak and Secret Manager metadata artifact. Missing artifact families fail the run so cron/alerts catch incomplete protection.

Off-site restore drill:

`offsite-restore-drill-restic.sh --planOnly` writes the expected execution plan without requiring remote credentials. `--dryRun` validates the remote Restic repository and selected snapshot without restoring files. The full command restores into `.tmp/ops`, stages only signed backup artifacts under `backups/offsite-restore-drills/`, runs the disposable restore-test commands for every data family, runs `infra-health`, and writes evidence under `reports/offsite-restore-drills/`. Use `--snapshot <id>` for a specific snapshot, `--families postgres,mariadb` for a scoped drill, `--allowPartial` only during bootstrap, and `--keepRestoredArtifacts` only when you need manual inspection.

Production go/no-go requires restore evidence from a remote Restic repository such as `s3:`, `b2:`, `azure:`, `gs:`, `sftp:`, `rest:` or `rclone:`. The endpoint must not resolve to localhost, the Docker network or private IP space. The accepted report must show `coverage.complete=true`: PostgreSQL, MariaDB, MinIO, Keycloak and Secret Manager metadata were restored and tested, `--allowPartial` was not used, and `infra-health` passed after the restore. A local filesystem repository or scoped family drill is useful for bootstrap rehearsal only.

For Cloudflare R2, use the S3-compatible Restic repository endpoint and keep
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the VPS secret environment or
root-only systemd/cron environment, not in Git.

## VPS hardening and Cloudflare

Run on a new VPS Ubuntu LTS VPS before public traffic:

```sh
sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user deploy
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 65002 --reload-sshd
sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce
sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply --ports "80"
```

`vps-bootstrap-ubuntu.sh` is dry-run by default and writes JSON/Markdown reports
under `reports/vps-bootstrap/`. In `--apply` mode it requires root, configures
Docker's official Ubuntu apt repository, installs Git, Docker Engine, Buildx and
the Docker Compose plugin, enables Docker and verifies `docker`, `docker compose`
and `git`. Use `--deploy-user <user>` only after reviewing Docker group access.

`vps-hardening-ubuntu.sh` is dry-run by default and writes JSON/Markdown reports
under `reports/vps-hardening/`. In `--apply` mode it requires root, applies SSH
hardening, sysctl, UFW, fail2ban, unattended upgrades, auditd/AppArmor and Docker
daemon hardening. If `/etc/docker/daemon.json` is absent, it writes the hardened
config and restarts Docker. If an existing daemon config is missing Platform keys,
the script fails until the generated template is reviewed and the command is
rerun with `--replace-docker-daemon-config`, which backs up the old file before
replacement. Use `--reload-sshd` only after key-based SSH access and the target
port are verified; it validates `sshd -t`, reloads `ssh`/`sshd` and records
`ssh-service-reload=applied`. Archive the apply report outside Git before
running readiness.

`vps-host-readiness.sh --ssh-port 65002 --enforce` writes `reports/vps-host/vps-host-readiness-*.json`
and `.md`. It should pass after Docker Engine, the Compose plugin, Git, UFW,
fail2ban, SSH hardening, unattended upgrades, auditd, AppArmor and Docker daemon
hardening are installed, and it also verifies the expected SSH port and matching
UFW allow rule. Every check includes remediation text in JSON and Markdown so a
failed report can be used as the host fix checklist. If Docker daemon hardening
fails, merge the reviewed
`/etc/docker/daemon.json.platform-template` into `/etc/docker/daemon.json`,
restart Docker in a maintenance window and rerun the readiness script.
Use `--diagnostic` only from disposable Linux containers or non-VPS hosts; it
writes to `reports/vps-host-diagnostics/` so diagnostic failures cannot satisfy
or pollute production VPS evidence.

Use `--ports "80 443"` only if Cloudflare connects to the origin over both
HTTP and HTTPS. After Cloudflare DNS is proxied and working, remove generic
public UFW web rules so the origin accepts web traffic only from Cloudflare IP
ranges.

Cloudflare zone code lives in `cloudflare/`. Keep `ssl=full_strict` as a manual
review item until the VPS origin certificate is valid for every proxied
hostname.

Cloudflare Access admin protection is versioned in `cloudflare/access-admin.example.json`.
Before live apply, replace placeholder domains, account id, identity provider ids and
admin emails. MFA is enforced by the configured Cloudflare Access identity provider;
the Platform manifest refuses live operations unless that intent is explicit.

```sh
sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.example.json
CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.production.json --apply
CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.production.json --verifyRemote
```

The apply path is additive-only. Existing Access applications are verified and left
untouched; mismatched existing applications fail the run so the operator can review
Cloudflare manually instead of weakening an admin surface by accident.

## Linux portability

Before copying the repository to Ubuntu, run:

```sh
sh ./scripts/linux-portability-check.sh
sh ./scripts/linux-portability-check.sh --fix
```

The check scans operational files for UTF-8 BOMs, CRLF line endings, Windows
absolute paths and PowerShell/cmd dependencies, then validates every shell
wrapper with Alpine `sh -n`. It writes JSON/Markdown evidence under
`reports/linux-portability/`. Use `--fix` only for mechanical BOM/CRLF
normalization; Windows path or PowerShell findings require a real code/doc
change.

## DAST

Run OWASP ZAP only against staging or a local disposable stack:

```sh
sh ./scripts/dast-zap-baseline.sh https://api-staging.example.com
```

Archive `security/dast/zap-baseline.html`, `.json` and `.xml` with the release
evidence. Treat high findings as release blockers.

## HA and managed secrets

Validate multi-node production overlays before deployment:

```sh
sh ./scripts/infra-ops.sh ha-config-check
sh ./scripts/infra-ops.sh managed-secrets-preflight
sh ./scripts/infra-ops.sh dr-readiness-check
```

Production secret values must come from the approved secret manager or KMS sync
into external Docker secrets. The app accepts `*_FILE` variables for
session signing, hash pepper, backup signing, database, Redis, NATS, SMTP and
service credentials.

## Production preflight

```sh
sh ./scripts/production-preflight.sh
```

This must pass before public traffic is exposed.

## Access review

Run monthly:

```sh
sh ./scripts/access-review.sh
```

## Production deploy

Release approval is mandatory before public traffic is changed. The approver
must verify the release SHA, immutable image digests, SBOM artifact, provenance
attestation, rollback target and the output of:

```sh
sh ./scripts/infra-ops.sh release-artifact-gate --requireProvenance
sh ./scripts/release-evidence.sh --requireProvenance --provenance ./release/provenance.json --previousImagesFile ./release/previous-images.json
sh ./scripts/infra-ops.sh governance-check
sh ./scripts/infra-ops.sh enterprise-10-check
```

The provenance artifact must be an in-toto statement, DSSE envelope or bundle
using SLSA v1 `predicateType`, must include `predicate.buildDefinition.buildType`,
must bind every release image digest as a subject, and must reference the release
commit. Use `--skipProvenanceCommitCheck` only for a documented provider-format
exception reviewed before approval.

Before the first production deploy, apply the branch protection policy from
`governance/github-branch-protection.json` to the live GitHub repository. The
commands are dry-run by default:

```sh
sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --dryRun
GITHUB_TOKEN=... sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --apply
GITHUB_TOKEN=... sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --verifyRemote
sh ./scripts/github-environments.sh --repo OWNER/REPO --dryRun
GITHUB_PRODUCTION_REVIEWERS=user:OWNER GITHUB_TOKEN=... sh ./scripts/github-environments.sh --repo OWNER/REPO --apply
GITHUB_TOKEN=... sh ./scripts/github-environments.sh --repo OWNER/REPO --verifyRemote
sh ./scripts/github-actions-config.sh --repo OWNER/REPO
GITHUB_TOKEN=... sh ./scripts/github-actions-config.sh --repo OWNER/REPO --verifyRemote
GITHUB_TOKEN=... sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote
```

The token must have repository administration permission. Do not keep the token
in `.env` or GitHub workflow logs. Required deployment reviewers and wait
timers depend on the repository visibility and GitHub plan; verify them in the
repository Environments UI after `--verifyRemote`.
The GitHub Actions runtime check only verifies secret presence and variable
formats: it expects staging variable `DAST_TARGET`, production secret
`DEPLOY_SSH_KEY`, production secret `EXTERNAL_UPTIME_PROVIDER_EVIDENCE_JSON`,
production secret `CLOUDFLARE_API_TOKEN`, and production variables
`DEPLOY_REMOTE`, `DEPLOY_REMOTE_DIR`, `DEPLOY_SSH_PORT`,
`VPS_HARDENED_SSH_PORT`, `PUBLIC_API_HEALTH_URL` plus `CLOUDFLARE_ACCOUNT_ID`.
It also expects production secret
`CLOUDFLARE_ACCESS_ADMIN_MANIFEST_JSON` for live Cloudflare Access verification.
Infrastructure CI intentionally does not checkout project
repositories; attach an application project with `PROJECT_SOURCE_DIR` only when
building application images. The run evidence command verifies that the remote
`enterprise-infra` workflow completed successfully on the exact release commit
and writes `reports/github-actions/github-actions-run-*.json`. The
`enterprise-infra-run-evidence` workflow runs automatically after completed
`enterprise-infra` pushes on `main`, verifies the completed run with
`--verifyRemote`, and uploads the same non-secret report artifact.
Run the manual `enterprise-live-evidence` workflow from the production
environment after DNS, Cloudflare, provider monitors and VPS evidence are ready;
it gathers external uptime, public Cloudflare load, Cloudflare Access, live
go/no-go and complete evidence bundle reports without deploying.
Run `enterprise-vps-evidence` from the same production environment to collect
VPS bootstrap, hardening and host readiness reports from VPS over SSH. It
requires `DEPLOY_SSH_KEY`, `DEPLOY_REMOTE`, `DEPLOY_SSH_PORT`,
`DEPLOY_REMOTE_DIR` and `VPS_HARDENED_SSH_PORT`; bootstrap/hardening only run
when the workflow inputs explicitly enable them and `confirm_mutating_vps=true`.
Archive the uploaded artifact with `reports/vps-*` outside Git.

Before changing public traffic, generate the consolidated go-live evidence pack:

```sh
sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO
GITHUB_TOKEN=... sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO --verifyGithubRemote
sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO --includeRuntime --includeRestoreDrill
sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO --includeRuntime --includeRestoreDrill --includeOffsiteRestoreDryRun
sh ./scripts/dr-evidence.sh --enforce
```

The first command is safe for local/repo evidence and writes
`reports/go-live/pre-go-live-evidence-*.json` plus `.md` with `status`,
`missingOptions` and `issues`. Use
`--includeRuntime` only against a running local/staging/VPS stack and
`--includeRestoreDrill` during the staging/VPS validation window.
The pre go-live pack also runs `release-evidence --planOnly` so missing release
manifest or rollback-target work stays visible before approval. Diagnostic
packs with `status=failed` are useful for remediation but do not satisfy
production go/no-go.

Run the repository coverage gate whenever files or workflow jobs are added:

```sh
sh ./scripts/infra-ops.sh repo-coverage-check
```

The report in `reports/repo-coverage/` proves every tracked file belongs to an
infrastructure category and that the GitHub Actions workflow still exercises the
required CI gates.

## Production go/no-go

Run the final production gate after the live VPS/provider checks have produced
their reports:

```sh
sh ./scripts/production-go-no-go.sh
sh ./scripts/production-go-no-go.sh --enforce
sh ./scripts/production-readiness-live.sh
```

The summary command writes `reports/go-no-go/production-go-no-go-*.json` and
`.md`. `--enforce` fails unless the latest evidence proves VPS bootstrap and
hardening apply reports, VPS host readiness, Cloudflare Access admin
`--verifyRemote`, successful remote GitHub Actions run evidence, secret
rotation evidence, DR/off-site restore, real alert delivery, external uptime,
public 50/100/500 load, release evidence with rollback/provenance and complete
pre-go-live evidence. Treat
`no-go` as a hard stop before public traffic changes. A `no-go` report carries a JSON
`remediation` array and a Markdown remediation checklist with the exact
follow-up commands and evidence expected for each failed gate.
`production-readiness-live.sh` then maps the 20-point production readiness
checklist to the latest `production-go-no-go` report and writes
`reports/production-readiness/production-readiness-*.json` plus `.md`.

After the final reports are generated, create a non-secret evidence archive:

```sh
sh ./scripts/evidence-bundle.sh
sh ./scripts/evidence-bundle-verify.sh --requireComplete
```

The bundle is written under `.tmp/evidence-bundles/` and includes operational
docs plus the latest JSON/Markdown reports for each evidence family. It refuses
to include `.env`, `secrets/`, backup artifacts, release artifacts and SBOM
directories; use `--allReports` only for a reviewed validation window where the
full report history is needed. The verify command rereads `manifest.json`,
checks every entry's size and SHA256, confirms the anti-secret policy and, with
`--requireComplete`, fails while any required evidence family is still missing.

1. Build versioned images:

   ```sh
   docker compose -f compose.yaml -f compose.build.yaml --env-file .env build
   ```

2. Push images to the registry configured in `.env`.
3. Run migrations on the target before exposing traffic:

   ```sh
   sh ./scripts/apply-postgres-migrations.sh
   ```

4. Start production:

   ```sh
   docker compose -f compose.yaml -f compose.prod.yaml --env-file .env -p enterprise_prod up -d
   ```

5. Run smoke checks against public domains.
6. Run the mandatory supply-chain gate, then archive the dependency SBOM:

   ```sh
   sh ./scripts/supply-chain-hygiene.sh
   sh ./scripts/generate-sbom.sh
   ```

7. Sign immutable images before deployment:

   ```sh
   sh ./scripts/sign-images.sh
   ```

8. Generate the release evidence pack and rollback target:

   ```sh
   sh ./scripts/release-evidence.sh \
     --requireProvenance \
     --provenance ./release/provenance.json \
     --previousImagesFile ./release/previous-images.json
   ```

     This writes JSON/Markdown evidence under `reports/release/` and rewrites
     `release/previous-images.json` from the approved rollback image refs. When
     previous images are present, the command also runs the non-destructive
     rollback dry-run, validates the rollback compose configuration and links the
     generated `reports/rollback/rollback-plan-*.json` in the release evidence.
     Failed validation still writes a diagnostic release report with `status=failed`
     and `issues`, but production go/no-go accepts only `status=passed`.
     For an initial deployment with no previous images, pass `--firstDeploy` and
     record that exception in the approval.

9. Record the deploy audit trail:

## VPS Prod-Like Deploy

Use this path when TLS and public certificates are terminated by VPS, Cloudflare, or another edge in front of the VPS.

1. Prepare `.env` from `.env.example` plus `.env.vps.example`.
2. Replace every `example.com`, `localhost` and placeholder value with the final host names.
3. Initialize Docker secret files:

   ```sh
   sh ./scripts/infra-secret-manager.sh init
   ```

4. Run the VPS preflight:

   ```sh
   sh ./scripts/vps-preflight.sh .env
   ```

   The preflight validates production env values, Docker secret files and the
   same VPS Compose file set used by deploy, including `compose.waf.yaml`
   and `compose.vps-waf.yaml`.

5. Start the single-node VPS stack:

   ```sh
   docker compose --env-file .env -p platform_infra_vps \
     -f compose.yaml \
     -f compose.build.yaml \
     -f compose.secrets.yaml \
     -f compose.vps.yaml \
     -f compose.waf.yaml \
     -f compose.vps-waf.yaml \
     up -d --build
   sh ./scripts/vps-postdeploy.sh .env
   ```

6. For remote deploys, `scripts/deploy-vps.sh` now calls
   `vps-postdeploy.sh` after `docker compose up`. By default the
   post-deploy step runs WAF smoke and `infra-health` against the public URLs
   loaded from `.env`. With `DEPLOY_RUN_GO_NO_GO=1`, it also enforces
   `production-go-no-go.sh --enforce` and `production-readiness-live.sh`.
   Enable the final evidence gates only when the external providers are
   configured:

   ```sh
   DEPLOY_RUN_PRE_GO_LIVE=1 \
   DEPLOY_RUN_GO_NO_GO=1 \
   DEPLOY_REPO=OWNER/REPO \
   sh ./scripts/deploy-vps.sh
   ```

   Use `DEPLOY_PRE_GO_LIVE_RESTORE_DRILL=1`,
   `DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN=1` and
   `DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE=1` during the staging/VPS validation
   window once Restic, GitHub and provider credentials are ready.

   For a repeatable same-host execution, generate a plan first and then run the
   live orchestrator:

   ```sh
   sh ./scripts/vps-go-live.sh --planOnly --repo OWNER/REPO
   sh ./scripts/vps-go-live.sh --confirmLive --repo OWNER/REPO --start-stack
   sh ./scripts/vps-go-live.sh --confirmLive --repo OWNER/REPO --bootstrap --apply-hardening --reload-sshd --full-evidence --start-stack
   sh ./scripts/vps-go-live.sh --confirmLive --repo OWNER/REPO --apply-hardening --reload-sshd --replace-docker-daemon-config --full-evidence --start-stack
   ```

   The orchestrator is plan-only by default. Live mode runs VPS readiness,
   VPS preflight, optional compose start, post-deploy smoke/health, final
   go/no-go and evidence bundle in order. On a fresh VPS add `--bootstrap` to
   install Git/Docker/Compose and `--apply-hardening` after SSH key access is
   verified. Use `--reload-sshd` after the target SSH port is reachable so the
   daemon actually enforces the hardened config. Use `--replace-docker-daemon-config` only after reviewing the
   generated Docker daemon template on a host that already has
   `/etc/docker/daemon.json`. The flow writes JSON/Markdown reports under
   `reports/vps-go-live/`. It does not source `.env`; the file is passed
   to the dedicated preflight/postdeploy commands.

7. Keep database/admin surfaces private. Do not publish phpMyAdmin, Grafana, Prometheus, Alertmanager, MinIO console or Traefik dashboard to public DNS.

8. Run DAST on staging before production deploy, then record the report path.

9. After deploy, record the audit trail:

   ```text
   release_sha=<git sha>
   approved_by=<reviewer>
   images=<digest-pinned image refs>
   sbom=<archived sbom artifact>
   provenance=<attestation artifact>
   rollback_target=<previous image refs>
   deployed_at=<utc timestamp>
   ```

## Rollback

1. Keep the previous image digests in the registry and in the deploy audit trail.
2. Prepare a rollback image file:

   ```json
   {
     "BACKEND_IMAGE": "registry.example.com/platform/backend@sha256:...",
     "WEB_IMAGE": "registry.example.com/platform/web@sha256:...",
     "WORKER_NOTIFICATIONS_IMAGE": "registry.example.com/platform/worker-notifications@sha256:...",
     "WORKER_JOBS_IMAGE": "registry.example.com/platform/worker-jobs@sha256:..."
   }
   ```

3. Dry-run the rollback. This validates compose and writes `reports/rollback/rollback-plan-*.json` and `.md`:

   ```sh
   sh ./scripts/rollback-release.sh --rollbackFile ./release/previous-images.json
   ```

4. Apply only after approval:

   ```sh
   sh ./scripts/rollback-release.sh --rollbackFile ./release/previous-images.json --confirmRollback
   ```

5. The apply path backs up `.env`, updates only the image variables, restarts selected app services and runs `infra-health`.
6. Do not roll back the database unless a restore plan has been tested.
7. Append rollback reason, operator and restored image digests to the deploy audit trail.
