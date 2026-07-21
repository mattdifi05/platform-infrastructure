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

The shell wrappers are container-first. They never mount the raw Docker socket
by default. On the VPS they use the persistent proxy through
`127.0.0.1:2376`; in CI/bootstrap they create and remove a digest-pinned
ephemeral proxy. The container runs with the SSH user's UID/GID. Raw socket
mode requires the explicit recovery flags documented in
`RUNTIME-ISOLATION.md`.

Terminology: **Infrastructure Portal** is the operator product surface,
**Control Center** is the Node service that serves it, and `portal.<domain>` is
the host. The core contains no application backend, frontend, business worker,
account schema or application migration. Those assets belong to an external
hosted workload and are not infrastructure go-live gates.

## Documentation map

Use `DOCUMENTATION-INDEX.md` as the entry point for repository documentation and
`INFRASTRUCTURE-DEEP-DIVE.md` for the complete infrastructure map. This runbook
is the operational procedure layer: when a command here conflicts with current
Compose/script state, verify the technical source and update the docs before
using the procedure for production evidence.

## Current reference server quick checks

For the current prod-like Ubuntu reference server, start with read-only checks:

```sh
ssh platform-infrastructure
cd /home/platform_infrastructure/platform-infrastructure

docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f compose.runtime.yaml \
  -f compose.networks.yaml \
  -f compose.runtime-isolation.yaml \
  ps

curl -skS --resolve portal.platform-infrastructure.com:443:127.0.0.1 \
  https://portal.platform-infrastructure.com/control/status

for path in /srv/platform-nvme /home/platform_infrastructure /var/lib/docker; do
  findmnt -no SOURCE,TARGET,FSTYPE,OPTIONS "$path"
done
df -h / /srv/platform-nvme /home/platform_infrastructure /var/lib/docker
```

Expected storage model: `/` remains on the OS disk, while
`/home/platform_infrastructure`, external application sources and
`/var/lib/docker` are backed by `/srv/platform-nvme`. Do not delete rollback
copies, Docker volumes or backup artifacts while investigating an incident.

For a Control Center-only rollout, back up the touched files, copy only those
files, test them in the repo path, then recreate only `control-center`:

```sh
docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f compose.runtime.yaml \
  -f compose.networks.yaml \
  -f compose.runtime-isolation.yaml \
  up -d --force-recreate control-center
```

Never use `docker compose down -v` as a troubleshooting shortcut. Volume
deletion is a separate destructive procedure and requires explicit approval,
verified backups and a rollback plan.

2. Check edge and API:

   ```sh
   sh ./scripts/enterprise-hardening-audit.sh
   sh ./scripts/security-smoke.sh
   sh ./scripts/waf-smoke.sh
   curl https://portal.localhost.com/__health
   ```

3. Read scoped logs:

   ```sh
   docker compose -p platform_infra_local logs -f traefik control-center project-router postgres platform-alert-dispatcher
   ```

4. Check platform database availability and backup evidence:

   ```sh
   sh ./scripts/infra-ops.sh backup-coverage-matrix
   sh ./scripts/dr-evidence.sh
   ```

Application migrations are checked and applied only from the owning workload
repository, in a separately approved maintenance step.

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
curl -k -o /dev/null -s -w "%{http_code}\n" "https://portal.localhost.com/?x=<script>alert(1)</script>"
curl -k -o /dev/null -s -w "%{http_code}\n" "https://portal.localhost.com/.env"
```

Both should return `403`. If a real workflow is blocked, keep `WAF_BLOCKING_PARANOIA=2`, inspect the JSON audit event in `enterprise-waf`, then add the smallest possible exclusion to `waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` or `waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`. Raise to PL3/PL4 only after the audit log is clean for the affected apps.

## Feature Flags And Kill Switches

Treat every risky launch feature as disabled-by-default until it has an owner, rollback path and monitoring signal. Document the feature flag name, default value, owning service, production enablement window and emergency disable command in the release evidence pack. If a feature does not have a runtime flag yet, the approved kill switch is a release rollback through `rollback-release.sh` plus the smallest environment or routing change needed to remove public exposure.

## Alerting

Prometheus sends alerts to Alertmanager, and Alertmanager posts grouped platform
alerts to `platform-alert-dispatcher:3000/alerts/prometheus` with the bearer
token from `/run/secrets/alertmanager_webhook_token`. The dispatcher is a core
service: it logs sanitized summaries, delivers email and an optional generic
forward webhook, and exposes platform delivery counters on `/metrics`.

Before the first deploy, set `ALERTMANAGER_SECRET_GID` to the numeric group used
by the Ubuntu platform operator. The token must be `0640` and owned by that
group. Check without mutation first; apply only in an approved maintenance
window:

```sh
sh ./scripts/alertmanager-secret-permissions.sh --gid "$(id -g)"
sh ./scripts/alertmanager-secret-permissions.sh \
  --gid "$(id -g)" \
  --apply \
  --confirm APPLY-ALERTMANAGER-SECRET-PERMISSIONS
```

`vps-preflight.sh` repeats the read-only permission check and blocks deployment
when mode or group do not match. Alertmanager health also fails when the token
is unreadable, even if `/-/ready` is green.

Alert evidence:

```sh
sh ./scripts/alert-evidence.sh
sh ./scripts/alert-evidence.sh --sendTest
sh ./scripts/alert-evidence.sh --sendTest --requireEmailDelivery
```

The summary mode validates Alertmanager routing, bearer-token secrets,
Prometheus delivery-failure alerts and dispatcher counters. `--sendTest`
submits a uniquely correlated alert to the Alertmanager API, waits for the
dispatcher counters and requires the exact receiver log receipt. It never
calls the webhook directly. Add `--requireEmailDelivery` or
`--requireForwardDelivery` only after that real channel is configured.

Key alerts:

```text
PlatformTargetDown
KeycloakPlatformLoginFailures
KeycloakPlatformAdminLocked
BackupStale
RestoreDrillStale
AlertDeliveryFailed
HostDiskUsageHigh
HostDiskUsageCritical
HostDiskWillFillSoon
HostReliabilityCollectorMissing
HostNetworkNotReady
HostUpdatesPending
HostRebootRequired
HostDriveTelemetryMissing
HostDriveUnhealthy
HostDriveMediaErrors
HostIoPressureHigh
HostJournalUsageHigh
HostUpsMissing
HostUpsOnBattery
HostUpsChargeLow
HostMemoryUsageHigh
HostCpuUsageHigh
ContainerCpuUsageHigh
ContainerMemoryUsageHigh
ContainerDisappeared
```

Optional external forwarding:

```sh
ALERT_FORWARD_WEBHOOK_URL_FILE=/run/secrets/alert_forward_webhook_url
```

Keep the URL in the production secret manager if it embeds credentials.

Email delivery is enabled when `ALERT_EMAIL_TO`, `MAILER_FROM`, `SMTP_HOST`,
`SMTP_USER` and `/run/secrets/smtp_password` are configured. Watch:

```promql
platform_alert_delivery_total{channel="email",result="success"}
platform_alert_delivery_total{channel="email",result="failed"}
platform_alert_delivery_total{channel="forward",result="success"}
platform_alert_delivery_total{channel="forward",result="failed"}
```

If delivery failures increase, inspect
`docker logs enterprise-platform-alert-dispatcher` for
`email_delivery_failed` or `forward_delivery_failed`, then verify the mounted
secret through the secret manager. Do not put SMTP passwords or credentialed
webhook URLs in `.env` or Git.

## Workload metrics and capacity

Per-container CPU, memory and effective cgroup limits come from the hardened
host collector documented in `WORKLOAD-METRICS.md`. cAdvisor remains a
compatibility scrape, but its `/healthz` alone is not accepted as workload
coverage evidence.

Before an approved rollout, validate without touching the live collector:

```sh
sh ./scripts/container-metrics-sandbox-test.sh
sudo sh ./scripts/install-container-metrics-collector.sh \
  --plan \
  --deploy-user platform_infrastructure \
  --repo-root /home/platform_infrastructure/platform-infrastructure
```

During the maintenance window, run the installer with `--apply`, recreate only
node-exporter, Prometheus and Control Center with the canonical overlays, then
run `--verify` and `vps-host-readiness.sh --enforce`. Never use
`docker compose down -v`.

The Control Center rejects snapshots older than
`CONTROL_CENTER_DOCKER_STATS_MAX_AGE_SECONDS` and preserves a real `0.000%` CPU
sample as measured zero. Effective limits are reported separately from planned
portal quota metadata. The T13 candidate now applies hard CPU/RAM/PID/FD/I/O
limits through `compose.runtime-isolation.yaml`; the old live containers remain
unlimited until an approved per-service rollout.

Validate the desired runtime without recreating live services:

```sh
sh ./scripts/runtime-isolation-check.sh --env-file=.env.vps.example
sh ./scripts/runtime-isolation-sandbox-test.sh
sh ./scripts/infra-ops.sh testing-hygiene
HOSTED_WORKLOAD_CATALOG=/path/hosted-workloads.json \
HOSTED_WORKLOAD_ROOT=/path/applications \
HOSTED_WORKLOAD_LOCK=/path/private/hosted-workloads.lock.json \
COMPOSE_ENV_FILE=.env.vps \
sh ./scripts/prepare-hosted-workloads.sh
```

The stress sandbox is capped at 0.25 CPU and 96 MiB. The hosted workload
preparation is non-mutating: it validates the external manifest and environment,
compares core/combined renders and writes a hash-locked contract. Follow
`RUNTIME-ISOLATION.md` for rollout and rollback.

## Service identities and storage policy

Application database identities, grants and rollout SQL are owned by the
external workload repository. The platform contract requires distinct
service credentials, denies MinIO root material to workloads and supports one
object-storage service account per bucket/prefix. See
`SERVICE-IDENTITY-AND-TENANCY.md`.

Safe verification does not touch live data:

```sh
sh ./scripts/infra-ops.sh testing-hygiene
sh ./scripts/runtime-isolation-check.sh --env-file=.env.vps.example
sh ./scripts/network-segmentation-check.sh --env-file=.env.vps.example
MODE=plan MINIO_BUCKET=example-app MINIO_PREFIX=runtime/ \
  sh scripts/minio-service-identity.sh
```

Never run application prepare/revoke during an ordinary platform deploy. The
approved sequence lives in the app runbook: fresh exact backup plus restore
test, app migration, scoped secret materialization, service-by-service recreate,
functional smoke, non-secret cutover evidence and explicit legacy revoke.
Rollback may restore only bounded capabilities, never broad grants or MinIO
root material.

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
for every monitor. Produce and attest that exact file in a dedicated GitHub
workflow. A self-authored `verified: true` field is rejected. Validate the
GitHub/Sigstore attestation, then run the real probe from outside the local
network or from the VPS:

```sh
PROVIDER_EVIDENCE_ARGS="--providerEvidenceAttestation online --providerEvidenceRepository OWNER/REPO --providerEvidenceWorkflow OWNER/REPO/.github/workflows/provider-evidence.yml --providerEvidenceSourceDigest FULL_GIT_SHA --providerEvidenceSourceRef refs/heads/main"

sh ./scripts/external-uptime-check.sh \
  --providerEvidence ./monitoring/external-uptime-provider.production.json \
  $PROVIDER_EVIDENCE_ARGS \
  --validateProviderEvidenceOnly

sh ./scripts/external-uptime-check.sh \
  --envFile .env \
  --providerEvidence ./monitoring/external-uptime-provider.production.json \
  $PROVIDER_EVIDENCE_ARGS \
  --requireProviderEvidence
```

Archive the JSON/Markdown report from `reports/uptime/`. The production
go/no-go gate rejects reports that only prove local HTTP reachability and do not
include cryptographically authenticated external provider evidence with fresh
provider-reported results.

Runtime candidate identity is a separate fail-closed gate:

```sh
sh ./scripts/functional-health-check.sh
sh ./scripts/infra-ops.sh runtime-fingerprint --envFile .env --project platform_infra_vps
```

The runtime fingerprint passes only when the worktree is clean and every
Compose service config hash matches exactly one running container. It reads no
container environment values.

## Resilience drills

Run these before major releases and after infrastructure changes:

```sh
sh ./scripts/fault-injection-tests.sh
sh ./scripts/failure-tests.sh --confirmServiceStop --targets redis,postgres,minio,keycloak,nats,waf,platform-alert-dispatcher,backup-scheduler
sh ./scripts/infra-ops.sh load-profile --durationSeconds 60 --targetRps 8 --concurrency 8 --maxP95Ms 1000
sh ./scripts/load-benchmark.sh --profiles 50,100,500 --durationSeconds 60 --perUserRps 0.2 --maxP95Ms 1000
sh ./scripts/load-benchmark.sh --profiles 50,100,500 --url https://api.example.com/health --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare
sh ./scripts/infra-ops.sh chaos-profile --confirmChaos
```

Acceptance criteria:

- Redis degradation does not bypass sensitive endpoint rate limits.
- PostgreSQL statement timeout cancels slow queries and rolls back cleanly.
- Platform alert delivery and backup scheduler failures remain observable.
- Control Center p95 stays under the declared threshold for the selected profile.
- `failure-tests` writes a non-sensitive detection/recovery report under `reports/failure-tests/`.
- `load-benchmark` writes JSON/Markdown reports under `reports/load/`, including Docker CPU/RAM snapshots before and after each profile.
- The production `load-benchmark` run must target the public API URL, classify the target as public, record edge/CDN evidence and finish with `status=passed`. With Cloudflare enabled, use `--requireEdgeEvidence --expectedEdgeProvider cloudflare`; otherwise document the reviewed provider exception before go-live. Failed preflights or profiles still write diagnostic reports under `reports/load/`, but they do not satisfy production go/no-go.

The load profile uses a bounded synthetic `X-Forwarded-For` client pool by default so the performance probe does not collide with the security rate-limit budget consumed by smoke and E2E checks. Use `--preserveClientIp` when deliberately testing one-client throttling behavior.

If `AlertDeliveryFailed` fires, inspect the platform dispatcher logs and
mounted channel credentials, repair the channel, then rerun the exact correlated
probe. Application outbox recovery belongs to the workload runbook.

## Centralized logs and audit

Promtail reads Docker JSON logs from `/var/lib/docker/containers` without Docker socket service discovery. Its pipeline unwraps Docker log entries, redacts common sensitive fields (`authorization`, `cookie`, `set-cookie`, `password`, `secret`, `token`, `otp`, passkey credentials and challenges), parses JSON app logs and labels them by `service` and `level`.

Primary operator queries:

```logql
{job="docker",service=~"enterprise-.+",level=~"warn|error"}
{job="docker",service="enterprise-control-center"} |= "error"
{job="docker",service="enterprise-platform-alert-dispatcher"} |= "delivery_failed"
```

Use Loki for operational logs and `platform-admin-audit` evidence for
infrastructure admin activity. Hosted application audit schemas are
workload-owned and must not be used as platform go-live evidence. Audit tables
for hosted apps may still be append-only and RLS protected, but they are
outside the hosting-infra gate.
The infrastructure evidence gate verifies the Control Center append-only
administrative audit and JSONL operational evidence. It does not inspect or
promote application audit tables.
Run `sh ./scripts/audit-log-evidence.sh` before go-live and after audit/outbox changes; archive `reports/audit-logs/audit-log-evidence-*.json` with the release evidence.
Run `sh ./scripts/retention-evidence.sh` after log/metric retention changes and before go-live; archive `reports/retention/retention-evidence-*.json` with the release evidence.

## Backup

La coverage completa di dati e retention e' descritta in
`BACKUP-RECOVERY-COVERAGE.md`. Ogni cancellazione database deve seguire
`DATABASE-DELETION-SAFETY.md`; non sono ammesse cancellazioni dirette prive di
manifest firmato, restore drill e receipt off-site freschi.

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

This keeps scheduling inside Docker. The host only needs Docker, Compose and Git. The scheduler uses `docker-socket-proxy` on the isolated `platform_docker_control` network and never mounts the raw socket. It autodetects Docker mount sources; set `PLATFORM_INFRA_HOST_ROOT` and `PROJECT_SOURCE_HOST_ROOT` only when the VPS uses nonstandard paths. Enable off-site upload with `BACKUP_SCHEDULER_ENABLE_OFFSITE=true` after `RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE` and provider credentials are valid. Scheduled jobs call `backup-scheduler.sh --run <command>` and parse the private runtime env file as data instead of sourcing it as shell code.

## Home VPS LAN evidence

Use explicit runtime overrides when the home VPS is reachable only over LAN
HTTP while production TLS is still provided by the future edge provider. Keep
the canonical platform hostnames in local DNS or `/etc/hosts`; do not introduce
temporary wildcard/IP hostnames into platform evidence. This keeps production
HTTPS checks intact and only changes the local evidence target:

```sh
DEPLOY_PORTAL_BASE=http://portal.platform-infrastructure.com \
DEPLOY_DOCS_BASE=http://docs.platform-infrastructure.com \
DEPLOY_APP_BASE=http://app.platform-infrastructure.com \
DEPLOY_API_BASE=http://api.platform-infrastructure.com \
DEPLOY_AUTH_BASE=http://auth.platform-infrastructure.com \
DEPLOY_AUTH_ORIGIN=https://auth.platform-infrastructure.com \
DEPLOY_GRAFANA_BASE=http://grafana.platform-infrastructure.com/login \
DEPLOY_GRAFANA_BLOCKED=1 \
DEPLOY_ADMIN_SCHEME=http \
DEPLOY_ALLOW_HTTP_NO_HSTS=1 \
DEPLOY_RUN_PRE_GO_LIVE=1 \
DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT=0 \
DEPLOY_REPO=OWNER/REPO \
sh ./scripts/vps-postdeploy.sh .env
```

## Local secrets

```sh
sh ./scripts/infra-secret-manager.sh init
sh ./scripts/infra-secret-manager.sh verify
docker compose -f compose.yaml -f compose.secrets.yaml --env-file .env -p platform_infra_local up -d
```

`infra-secret-manager` is the proprietary local secret manager and local secret vault. It encrypts the canonical store, writes an audit log and materializes `secrets/*.txt` only for Docker Compose. Use `--sanitizeEnv` on `init-local-secrets` only after you are committed to starting local with `compose.secrets.yaml`.

Useful operations:

```sh
sh ./scripts/infra-secret-manager.sh status
sh ./scripts/infra-secret-manager.sh kms-status
sh ./scripts/infra-secret-manager.sh migrate-metadata
sh ./scripts/infra-secret-manager.sh kms-rotate
sh ./scripts/infra-secret-manager.sh rotate --name session_signing_keys
sh ./scripts/infra-secret-manager.sh rotate --name projects_gateway_signing_keys
sh ./scripts/infra-secret-manager.sh rotate --name backup_signing_keys
sh ./scripts/infra-secret-manager.sh rotate --name alertmanager_webhook_token
printf '%s\n' "$TOKEN" | sh ./scripts/infra-secret-manager.sh set --name github_token --stdin --owner github --minLength 40
sh ./scripts/secret-rotation-evidence.sh --enforce
```

Unknown safe names passed to `set --name` become vault secrets with owner/rotation metadata. `status` and evidence reports print only metadata and fingerprints, never secret values. GitHub ops auto-load `secrets/github_token.txt` as `GITHUB_TOKEN` inside the ops container when present and no GitHub token is already exported.

`secret-rotation-evidence.sh --enforce` validates the encrypted store, materialized Docker secret files, audit log, Platform Local KMS age and every secret `rotationDays` window without printing secret values. Archive `reports/secret-rotation/secret-rotation-evidence-*.json` outside Git before production go/no-go.

`portal.localhost.com` is the Node-based Infrastructure Portal served by the `control-center` container. It stays separate from PHP Apache, is declared as the local Node project `@platform/control-center`, and uses a local Control Center visual system: components are declared in `control-center/components/ui/controlCenterUi.mjs`, `--cc-*` tokens live in `control-center/styles/control-center.css`, the stylesheet is served from `/assets/control-center/control-center.css`, and `/control/ui-package` exposes that local contract. Control Center is platform-first: Applications are metadata only, may be zero, and render `No applications attached.` when no external application is attached. Automatic hosted-project discovery is disabled by default with `CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS=false`; enable it only for explicit external manifests or mounted source inventories. Control Center exposes read-only Advanced Network topology from `/control/network`, read-only Advanced Monitoring topology from `/control/monitoring`, and stores local metadata/audit state in `projects-portal/state/`. `docs.localhost.com` is served by the same Node process but only renders whitelisted Markdown documentation from the repository. `PHP_SOURCE_DIR` points at `php-runtime-root`, a neutral static Apache root; PHP Apache is only a generic runtime and does not own the Control Center UI or API. Production/provider operations are plan-only from this foundation unless an explicit adapter and confirmation gate are added. Administrative access is fail-closed through Keycloak OIDC Authorization Code with PKCE and passkey-only `acr`/`amr` validation. Local passwords and SHA-256 verifiers are not supported. Apply `control-center/migrations/001_auth_sessions.sql` to the dedicated control-plane PostgreSQL database before startup, provide its URL only through `CONTROL_CENTER_AUTH_DATABASE_URL_FILE`, and enroll at least two independent passkeys before switching the live route.
`project-router` remains the shared internal entrypoint for optional PHP and Node application hosts, but Traefik no longer publishes wildcard project routes by default. `CONTROL_CENTER_HOST` forwards to the Node Control Center, `DOCS_HOST` forwards to the docs surface, and `PROJECTS_HOST` stays deprecated and empty. Node/PHP routing behavior remains covered by `project-router-tests` as an internal capability, not as production evidence for hosted applications.
Advanced Mode exposes the requested enterprise skeleton areas, including Workers & Jobs, CI/CD & GitHub Governance, Logs/Alerts Advanced, Disaster Recovery, Release Evidence, Security Advanced and Billing / Plans. These surfaces remain plan/evidence-only until an explicit adapter performs apply plus verifyRemote.
The read-only Advanced API is available at `/control/advanced` and `/control/advanced/:section`; it exposes capabilities, guardrails and evidence metadata without live provider calls, Docker mutations or production evidence claims. `/control/readiness` reads the read-only governance manifests, exposes a sanitized repository/live-proof readiness matrix and keeps production evidence false until real VPS/provider proof is verified.
The server-side adapter registry is available at `/control/adapters` and `/control/adapters/:id`; it covers Cloudflare, Traefik, Docker, GitHub, Prometheus, Loki, Alertmanager, Backup, Restore, MinIO, Database, Security and Go/No-Go. `/control/adapters/:id/plan` and `/verify` create audited plans, while `/apply` is rejected until an explicit live adapter implementation, strong confirmation and verifyRemote are added.

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

## Host reliability, storage and power

The host reliability collector exports default-route and wait-online state,
pending package count, reboot requirement, journal size, Linux I/O pressure,
SMART/NVMe health, temperature, wear and media errors, plus NUT UPS state. It
writes an atomic, non-secret node-exporter textfile every minute.

Validate before host mutation:

```sh
sh ./scripts/host-reliability-sandbox-test.sh
sudo sh ./scripts/install-host-reliability-collector.sh \
  --plan \
  --repo-root /home/platform_infrastructure/platform-infrastructure
sudo sh ./scripts/configure-host-wait-online.sh --plan --interface wlp3s0
```

Install and verify on the current reference server without changing Netplan,
DHCP, routes or SSH:

```sh
sudo sh ./scripts/install-host-reliability-collector.sh \
  --apply \
  --repo-root /home/platform_infrastructure/platform-infrastructure
sudo sh ./scripts/install-host-reliability-collector.sh \
  --verify \
  --repo-root /home/platform_infrastructure/platform-infrastructure
sudo sh ./scripts/configure-host-wait-online.sh --apply --interface wlp3s0
sudo sh ./scripts/configure-host-wait-online.sh --verify --interface wlp3s0
```

`configure-host-wait-online.sh` changes only the wait-online command and never
runs `netplan apply` or restarts `systemd-networkd`. Use `--remove` to delete
its drop-in. A deterministic production network still requires Ethernet or a
router DHCP reservation plus a console-backed reboot test; successful
wait-online on the current Wi-Fi lease does not close that requirement.

Node-exporter must mount the same textfile directory used by both host
collectors. Set `NODE_EXPORTER_TEXTFILE_DIR` only when the collector repository
path differs from the Compose project directory. Confirm the real scrape with:

```promql
platform_host_reliability_collector_healthy
platform_host_drive_telemetry_count
platform_container_metrics_collector_healthy
```

Do not run a broad `apt upgrade` or reboot during an unplanned SSH session.
Record pending packages, create a maintenance window, verify console or
out-of-band access, apply updates, reboot only when required, then repeat SSH,
route, mount, Docker, container health and Prometheus checks. Automatic reboot
remains disabled. UPS readiness requires supported physical hardware, NUT
visibility and a controlled on-battery/shutdown drill; never mark it passed
from configuration alone.

## VPS hardening and Cloudflare

Run on a new VPS Ubuntu LTS VPS before public traffic:

```sh
sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user deploy
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 65002 --reload-sshd
sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce
sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply --ports "80"
```

For the current home-VPS/LAN validation host, do not change the SSH port. Use
the same sequence with `--ssh-port 22` after confirming the existing key-based
session works:

```sh
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 22 --reload-sshd
sh ./scripts/vps-host-readiness.sh --ssh-port 22 --enforce
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

The SSH hardening fragment is written to
`/etc/ssh/sshd_config.d/01-platform-hardening.conf` so OpenSSH reads Platform
settings before cloud-init fragments such as `50-cloud-init.conf`. This matters
because the effective `sshd -T` output, not only the file contents, must show
`passwordauthentication no`.

`vps-host-readiness.sh --ssh-port 65002 --enforce` writes `reports/vps-host/vps-host-readiness-*.json`
and `.md`. It should pass after Docker Engine, the Compose plugin, Git, UFW,
fail2ban, SSH hardening, unattended upgrades, auditd, AppArmor and Docker daemon
hardening are installed, and it also verifies the expected SSH port and matching
UFW allow rule, both host collectors, deterministic network readiness and UPS
telemetry. Every check includes remediation text in JSON and Markdown so a
failed report can be used as the host fix checklist. If Docker daemon hardening
fails, merge the reviewed
`/etc/docker/daemon.json.platform-template` into `/etc/docker/daemon.json`,
restart Docker in a maintenance window and rerun the readiness script.
For the current home-VPS/LAN host, the accepted readiness command is
`vps-host-readiness.sh --ssh-port 22 --enforce` until a separate SSH-port change
is explicitly approved and tested.
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
Before live apply, replace placeholder domains, Cloudflare account id, identity provider ids and
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

Prima di eseguire DAST o costruire un'immagine candidata, verifica il lock
supply-chain e le fixture negative:

```sh
sh ./scripts/supply-chain-lock-check.sh
docker run --rm -v "$PWD:/work" -w /work node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606 \
  node --test scripts/supply-chain-policy.test.mjs
sh ./scripts/build-context-sandbox-test.sh
sh ./scripts/build-daemon-isolation-sandbox-test.sh
sh ./scripts/core-image-supply-chain-test.sh
sh ./scripts/helper-image-supply-chain-test.sh
sh ./scripts/verify-locked-images.sh
```

I digest e i commit ammessi sono in `governance/supply-chain-lock.json`.
L'aggiornamento di un tag non modifica automaticamente il lock: risolvi il
nuovo digest/SHA, verifica la sorgente, aggiorna insieme lock e consumer e
conserva l'evidence del run. Non ripristinare riferimenti tag-only.

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
sh ./scripts/platform-admin-audit.sh
```

## Production deploy

Release approval is mandatory before public traffic is changed. The approver
must verify the release SHA, immutable image digests, SBOM artifact, provenance
attestation, rollback target and the output of:

```sh
GITHUB_REF=refs/heads/main sh ./scripts/infra-ops.sh release-artifact-gate --requireProvenance --repo OWNER/REPO --sourceRef refs/heads/main
gh workflow run release-attestation.yml --repo OWNER/REPO --ref main
GITHUB_REF=refs/heads/main sh ./scripts/release-evidence.sh --requireProvenance --repo OWNER/REPO --sourceRef refs/heads/main --imageManifest .tmp/release-attestation/release-subjects.json --sbom reports/release/github-release-sbom-<run-id>.cdx.json --previousImagesFile ./release/previous-images.json
sh ./scripts/infra-ops.sh governance-check
sh ./scripts/infra-ops.sh enterprise-10-check
```

Loose local SLSA statements, unsigned DSSE-looking envelopes and normalized
verification JSON are not admission evidence. The gate invokes GitHub CLI
directly and requires exact repository, signer workflow, source/signer commit,
source ref, GitHub Actions issuer, SLSA v1 predicate, GitHub-hosted runner,
verified timestamp and subject digest. Offline use requires both
`--attestationBundle` and `--trustedRoot`. There is no commit-check bypass.
`release-attestation.yml` publishes a digest-pinned GHCR infra image, enables
BuildKit SBOM attestation and uploads non-sensitive audit receipts. See
`RELEASE-TRUST-AND-WORKFLOW-SECURITY.md`.

Before the first production deploy, apply the branch protection policy from
`governance/github-branch-protection.json` to the live GitHub repository. The
commands are dry-run by default:

```sh
sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --dryRun
GITHUB_TOKEN=... sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --apply
GITHUB_TOKEN=... sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --verifyRemote
sh ./scripts/github-environments.sh --repo OWNER/REPO --dryRun
GITHUB_TOKEN=... sh ./scripts/github-environments.sh --repo OWNER/REPO --apply
GITHUB_TOKEN=... sh ./scripts/github-environments.sh --repo OWNER/REPO --verifyRemote
sh ./scripts/github-actions-config.sh --repo OWNER/REPO
GITHUB_TOKEN=... sh ./scripts/github-actions-config.sh --repo OWNER/REPO --verifyRemote
GITHUB_TOKEN=... sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote
```

The token must have repository administration permission. Do not keep the token
in `.env` or GitHub workflow logs. Exact deployment reviewer IDs are versioned
in `governance/github-environments.json`; `--verifyRemote` rejects wrong,
missing or additional reviewers as well as weaker self-review/wait/branch rules.
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
`no-go` as a hard stop before public traffic changes. A `no-go` report carries
JSON `summary`, `blockingRequired`, `pendingRequired` and `remediation`
sections plus a Markdown remediation checklist. Local repository or runtime
problems remain `failed`; public DNS/HTTPS, Cloudflare, external uptime,
public load, off-site restore and live GitHub provenance remain
`pending-live-proof` or `pending-provider` until real provider evidence exists.
`pre-go-live-evidence` uses the same separation: local blockers go to `issues`,
while DNS/provider/GitHub requirements are listed in `pendingLiveProofs`.
`production-readiness-live.sh` then maps the 19-point infrastructure production readiness
checklist to the latest `production-go-no-go` report and writes
`reports/production-readiness/production-readiness-*.json` plus `.md`.

Control Center `Stato` is the operator view of this gate. A run executes every
selected catalog item through the typed executor. Each item is labelled as a
real `probe`, `evidence-validation` or `external-required`; evidence snapshots
are never presented as network probes. Ordered progress is persisted in
`status-run-events.jsonl` and exposed through
`/control/v1/status/events?runId=<id>`. Runs remain read-only and do not include
Control Center-only UI tests or hosted-application checks as production
blockers.

Control metadata uses the single-writer file store documented in
`control-center/CONTROL-CENTER-CORE.md`. Before any approved state conversion,
follow `control-center/STATE-STORE-MIGRATION.md`: export, plan, write a private
rollback snapshot, require the exact apply confirmation and verify the
versioned API. T19 did not run this migration or recreate the live service.

If `Stato` shows only pending live/provider proof, do not try to force those
items green on a LAN-only Ubuntu server. The following blockers require real
external evidence:

| Blocker | Required external proof |
| --- | --- |
| `pre-go-live-evidence-complete` | final pre-go-live evidence with production preflight, GitHub remote verification and required restore/off-site options |
| `github-actions-run-success` | successful remote `enterprise-infra` GitHub Actions run on the release commit |
| `disaster-recovery-rpo-rto-offsite` | remote off-site repository plus full-family restore drill evidence |
| `external-uptime-provider` | third-party/provider uptime checks against public hosts from outside the VPS/LAN |
| `public-load-benchmark` | benchmark against final public hosts through the public edge/CDN path |
| `release-evidence-and-rollback` | fresh release evidence, rollback and complete GitHub/Sigstore provenance |
| `cloudflare-access-admin-verified` | Cloudflare Access admin protection applied and verified remotely on the real zone |

A private Ubuntu server can be healthy and ready for parallel migration while
production remains `NO-GO`. That is correct until DNS, Cloudflare, GitHub,
public monitoring, public load and off-site restore evidence are real.

### T23 production candidate verdict

The candidate verified on 2026-07-11 remains `NO-GO`. The authoritative local
receipt is
`/home/platform_infrastructure/remediation-work/20260711T044751Z-t23-production-candidate`.
The clean candidate commit is `4c04042a6fabc42317e18896b949f16b35102c7a`.
Functional health passed 11/11, but the exact runtime fingerprint correctly
failed because the 24-service candidate core is not deployed over the 34-service
historical runtime. Do not copy a passing flag into the report. Deploy in an
approved maintenance window, then rerun the fingerprint from the deployed clean
checkout with the production `.env`.

The same verdict retains stale bootstrap/hardening evidence, UPS, complete
pre-go-live, rotation, off-site DR and real alert delivery as local/maintenance
blockers. GitHub run, authenticated external uptime, public load, signed
release/rollback and Cloudflare Access remain provider blockers. Run
`evidence-bundle-verify --requireComplete` only after every one of those proofs
is real.

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
   docker compose -f compose.yaml --env-file .env build
   ```

2. Push images to the registry configured in `.env`.
3. Run hosted-application migrations only if an external app runbook requires
   them. They are workload steps, not platform hosting go-live gates. For the
   infrastructure itself, validate managed database backup/restore evidence
   instead:

   ```sh
   sh ./scripts/backup-postgres.sh
   sh ./scripts/backup-mariadb.sh
   sh ./scripts/full-restore-drill.sh
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

8. Generate GitHub/Sigstore release attestation evidence, then the release
   evidence pack and rollback target:

   ```sh
   gh workflow run release-attestation.yml --repo mattdifi05/platform-infrastructure --ref main
   gh run watch --repo mattdifi05/platform-infrastructure
   gh run download --repo mattdifi05/platform-infrastructure --name github-sigstore-release-evidence --dir .tmp/github-sigstore-release-evidence
   sh ./scripts/release-evidence.sh \
     --requireProvenance \
     --repo mattdifi05/platform-infrastructure \
     --sourceRef refs/heads/main \
     --previousImagesFile ./release/previous-images.json
   ```

     This writes JSON/Markdown evidence under `reports/release/` and rewrites
     `release/previous-images.json` from the approved rollback image refs. When
     previous images are present, the command also runs the non-destructive
     rollback dry-run, validates the rollback compose configuration and links the
     generated `reports/rollback/rollback-plan-*.json` in the release evidence.
     Failed validation still writes a diagnostic release report with `status=failed`
     and `issues`, but production go/no-go accepts only `status=passed` with a
     fresh cryptographic GitHub/Sigstore verification bound to the release.
     For an initial deployment with no previous images, pass `--firstDeploy` and
     record that exception in the approval.

9. Record the deploy audit trail:

## Hosted Workload Preparation

The platform must render and pass its gates with zero hosted applications.
Before attaching an external workload, publish its digest-pinned images and
keep its manifest, Compose overlay, non-secret runtime environment and database
migrations in the application repository. Then prepare and verify the lock:

```sh
HOSTED_WORKLOAD_CATALOG=/path/hosted-workloads.json \
HOSTED_WORKLOAD_ROOT=/path/applications \
HOSTED_WORKLOAD_LOCK=/path/private/hosted-workloads.lock.json \
COMPOSE_ENV_FILE=.env \
sh ./scripts/prepare-hosted-workloads.sh

sh ./scripts/hosted-workload-lock.sh \
  /path/private/hosted-workloads.lock.json verify
```

Preparation does not start services or change a database. Review the generated
core and combined render evidence, take fresh backup/restore evidence, and apply
application migrations only through the application runbook with its explicit
confirmation gate. Activation or replacement of workload containers requires a
separate approved maintenance window. A changed manifest, image environment or
migration invalidates the lock and fails closed.

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
   provenance=<github-sigstore-attestation report paths>
   rollback_target=<previous image refs>
   deployed_at=<utc timestamp>
   ```

## Rollback

1. Keep the previous image digests in the registry and in the deploy audit trail.
2. Prepare a rollback image file:

   ```json
   {
     "APP_IMAGE": "registry.example.com/example-app/app@sha256:...",
     "WORKER_IMAGE": "registry.example.com/example-app/worker@sha256:..."
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
