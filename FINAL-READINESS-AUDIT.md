# Platform Final Readiness Audit

Scope: repository and local Docker Desktop evidence before VPS Ubuntu LTS VPS deployment.

Status: repo/local readiness is strong, but production readiness is not fully proven until the real VPS, Cloudflare zone, remote backup store, external monitoring and alert recipients are exercised.

## Modified Files

Infrastructure worktree:

```text
.env.example
.gitattributes
.gitignore
ENTERPRISE-10-PLAN.md
ENTERPRISE-MATURITY.md
README.md
RUNBOOK.md
SECURITY.md
compose.build.yaml
compose.backup-scheduler.yaml
compose.managed-secrets.yaml
compose.prod.yaml
compose.secrets.yaml
compose.yaml
docker/backend.Dockerfile
docker/web.Dockerfile
docker/worker.Dockerfile
governance/github-actions-runtime.json
governance/github-environments.json
governance/production-go-no-go.json
grafana/dashboards/enterprise-overview.json
keycloak/templates/platform-realm.example.json
prometheus/prometheus.yml
prometheus/rules/enterprise-alerts.yml
scripts/access-review.sh
scripts/account-integration-tests.sh
scripts/alert-evidence.sh
scripts/apply-postgres-migrations.sh
scripts/backup-postgres.sh
scripts/backup-restore-drill.sh
scripts/backup-scheduler.sh
scripts/certificate-expiry-check.sh
scripts/enterprise-hardening-audit.sh
scripts/fault-injection-tests.sh
scripts/generate-sbom.sh
scripts/init-local-secrets.sh
scripts/install-postgres-backup-cron.sh
scripts/load-smoke.sh
scripts/offsite-backup-restic.sh
scripts/offsite-restore-drill-restic.sh
scripts/production-preflight.sh
scripts/prune-postgres-backups.sh
scripts/restore-postgres.sh
scripts/restore-test-postgres.sh
scripts/secret-scan.sh
scripts/security-smoke.sh
scripts/sign-images.sh
scripts/static-security-check.sh
scripts/infra-ops.mjs
scripts/infra-secret-manager.mjs
scripts/infra-secret-manager.sh
scripts/supply-chain-hygiene.sh
scripts/validate-local-secrets.sh
secrets/README.md
traefik/dynamic/middlewares.yml
traefik/traefik.yml
.env.vps.example
.env.staging.example
.github/workflows/enterprise-infra.yml
READINESS-REPORT.md
VPS-PREDEPLOY-CHECKLIST.md
cloudflare/*
cloudflare/access-admin.example.json
compose.vps-waf.yaml
compose.vps.yaml
compose.staging.yaml
compose.waf.yaml
docker/ops.Dockerfile
keycloak/import/platform-realm.json
loki/rules/platform/waf-alerts.yml
monitoring/external-uptime.example.json
monitoring/external-uptime-provider.example.json
phpmyadmin/config.user.inc.php
renovate.json
scripts/backup-keycloak.sh
scripts/backup-mariadb.sh
scripts/backup-minio.sh
scripts/backup-restore-drill-keycloak.sh
scripts/backup-restore-drill-mariadb.sh
scripts/backup-restore-drill-minio.sh
scripts/backup-restore-drill-secret-manager-metadata.sh
scripts/backup-secret-manager-metadata.sh
scripts/cloudflare-access-admin.mjs
scripts/cloudflare-from-zero.mjs
scripts/cloudflare-access-admin.sh
scripts/cloudflare-from-zero.sh
scripts/cloudflare-origin-lock-ufw.sh
scripts/dast-zap-baseline.sh
scripts/deploy-vps.sh
scripts/dr-evidence.sh
scripts/evidence-bundle.sh
scripts/external-uptime-check.sh
scripts/failure-tests.sh
scripts/full-restore-drill.sh
scripts/github-actions-config.sh
scripts/github-branch-protection.sh
scripts/github-environments.sh
scripts/vps-go-live.sh
scripts/vps-postdeploy.sh
scripts/vps-preflight.sh
scripts/infra-health.sh
scripts/install-mariadb-backup-cron.sh
scripts/install-offsite-backup-cron.sh
scripts/linux-portability-check.sh
scripts/load-benchmark.sh
scripts/pre-go-live-evidence.sh
scripts/production-go-no-go.sh
scripts/release-artifact-gate.sh
scripts/release-evidence.sh
scripts/vps-host-readiness.sh
scripts/restore-test-keycloak.sh
scripts/restore-test-mariadb.sh
scripts/restore-test-minio.sh
scripts/restore-test-secret-manager-metadata.sh
scripts/rollback-release.sh
scripts/infra-ops.sh
scripts/vps-bootstrap-ubuntu.sh
scripts/vps-hardening-ubuntu.sh
scripts/waf-smoke.sh
traefik/traefik.edge-http.yml
waf/*
FINAL-READINESS-AUDIT.md
```

Application worktree:

```text
.gitattributes
.github/workflows/enterprise-ci.yml
README.md
apps/backend/package.json
apps/worker-notifications/package.json
apps/worker-notifications/src/server.test.ts
apps/worker-notifications/src/server.ts
docs/README.md
docs/account-center.md
docs/architecture.md
docs/configuration-reference.md
docs/local-docker.md
docs/maintainer-playbook.md
docs/operations-runbook.md
docs/production-cloudflare-vps.md
docs/runtime-flows.md
docs/security.md
docs/testing-quality-gates.md
package.json
packages/ui/docs/release-governance.md
pnpm-lock.yaml
renovate.json
scripts/dependency-hygiene.mjs
scripts/maintainability-hygiene.mjs
scripts/performance-hygiene.mjs
scripts/run-infra-ops.mjs
scripts/supply-chain-gate.mjs
scripts/testing-hygiene.mjs
scripts/ui-publish-dry-run.mjs
```

## New Components

- Dockerized ops runner: `docker/ops.Dockerfile` and `scripts/infra-ops.sh`.
- Dockerized backup scheduler: `compose.backup-scheduler.yaml` and `scripts/backup-scheduler.sh`.
- VPS overlays: `compose.vps.yaml`, `compose.vps-waf.yaml`, `.env.vps.example`.
- Staging overlay and environment: `compose.staging.yaml`, `.env.staging.example`.
- OWASP CRS WAF overlay and local/VPS WAF rule files under `waf/`.
- Backup/restore commands for MariaDB, MinIO, Keycloak config and Secret Manager metadata.
- Non-secret backup execution reports under ignored `reports/backups/`.
- Off-site Restic restore drill with `--planOnly`, `--dryRun`, disposable artifact staging and reports under `reports/offsite-restore-drills/`.
- DR evidence summary with backup freshness, average/P95 restore timing, RTO/RPO status and reports under `reports/dr/`.
- Full restore drill, failure tests, load benchmark and rollback report commands.
- Node-exporter and cAdvisor for host/container resource metrics.
- Loki WAF alert rules and expanded Grafana dashboard panels.
- Cloudflare from-zero/additive scripts, zone rule manifests and Cloudflare Access admin application manifest.
- GitHub branch protection dry-run/apply/verify command.
- GitHub staging/production environment dry-run/apply/verify command with production reviewer enforcement.
- GitHub Actions runtime secret/variable verification command.
- GitHub Actions run evidence command for successful remote workflow proof on the release commit.
- Secret rotation evidence command with non-secret reports for Secret Manager store coverage, materialized files, audit trail, KMS age and per-secret freshness.
- Healthcheck coverage command with rendered Compose reports for local WAF, VPS WAF and backup-scheduler stacks.
- Pre go-live evidence pack with JSON/Markdown reports under `reports/go-live/`.
- Production go/no-go evidence gate with JSON/Markdown reports under `reports/go-no-go/`.
- Live production readiness checklist with JSON/Markdown reports under `reports/production-readiness/`.
- Release evidence pack with digest validation, SBOM/provenance references, rollback target generation and reports under `reports/release/`.
- Evidence bundle verifier for manifest policy, SHA256 and completeness checks.
- VPS bootstrap script with plan/apply JSON/Markdown evidence under `reports/vps-bootstrap/`.
- VPS hardening script with plan/apply JSON/Markdown evidence under `reports/vps-hardening/`.
- VPS host readiness script with JSON/Markdown evidence under `reports/vps-host/`.
- Linux portability check with BOM/CRLF, Windows path, PowerShell dependency and Alpine shell syntax evidence under `reports/linux-portability/`.
- VPS hardening and Cloudflare origin-lock scripts.
- Renovate configs for infra and app.
- Application-side Dockerized infra launcher: `scripts/run-infra-ops.mjs`.
- Optional native Discord and Telegram alert forwarding in notification worker.
- Provider-neutral external uptime manifest and `external-uptime-check` command.
- External uptime dry-run reports with `mode=dry-run` and `providerEvidence.verified=false`, so manifest evidence can be archived without satisfying live provider gates.
- Alert evidence command with synthetic Alertmanager delivery test and optional email/Discord/Telegram delivery requirements.
- VPS post-deploy command with WAF smoke, `infra-health`, optional pre go-live evidence and optional final go/no-go enforcement.
- VPS go-live orchestrator with plan-only default and JSON/Markdown reports under `reports/vps-go-live/`.
- Non-secret evidence bundle command with manifest, SHA256 checksums and `.tar.gz` output under `.tmp/evidence-bundles/`.
- Final readiness report and VPS pre-deploy checklist.

## Tests Executed

Latest local evidence includes:

```text
node scripts/infra-ops.mjs static-security-check
docker run --rm -v D:/docker/platform-infrastructure:/infra:ro -w /infra alpine:3.22 sh -ec 'for file in scripts/*.sh; do sh -n "$file"; done'
docker run --rm -v D:/docker/platform-infrastructure:/infra -w /infra alpine:3.22 sh ./scripts/vps-host-readiness.sh --diagnostic
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.waf.yaml config --quiet
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.waf.yaml -f compose.backup-scheduler.yaml --profile backup config --quiet
docker compose --env-file .env.vps.example -p platform_infra_vps_ci -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.vps.yaml -f compose.waf.yaml -f compose.vps-waf.yaml config --quiet
docker compose --env-file .env.vps.example -p platform_infra_vps_ci -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.vps.yaml -f compose.waf.yaml -f compose.vps-waf.yaml -f compose.backup-scheduler.yaml --profile backup config --quiet
docker compose --env-file .env.staging.example -p platform_infra_staging_ci -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.vps.yaml -f compose.waf.yaml -f compose.vps-waf.yaml -f compose.staging.yaml config --quiet
docker compose --env-file .env -p enterprise_prod_ci -f compose.yaml -f compose.prod.yaml -f compose.managed-secrets.yaml config --quiet
docker build -f docker/ops.Dockerfile -t platform/ops:local .
docker run --rm -e BACKUP_SCHEDULER_DRY_RUN=true -v D:/docker/platform-infrastructure:/infra:ro --entrypoint sh platform/ops:local /infra/scripts/backup-scheduler.sh
docker run --rm -e BACKUP_SCHEDULER_DRY_RUN=true -e BACKUP_SCHEDULER_ENABLE_OFFSITE=true -v D:/docker/platform-infrastructure:/infra:ro --entrypoint sh platform/ops:local /infra/scripts/backup-scheduler.sh
sh ./scripts/infra-ops.sh external-uptime-check --dryRun
sh ./scripts/infra-ops.sh github-branch-protection --repo OWNER/REPO --branch main --dryRun
sh ./scripts/infra-ops.sh github-environments --repo OWNER/REPO --dryRun
sh ./scripts/infra-ops.sh github-actions-config --repo OWNER/REPO
sh ./scripts/infra-ops.sh pre-go-live-evidence --repo OWNER/REPO
node --check scripts/infra-ops.mjs
node scripts/infra-ops.mjs offsite-restore-drill-restic --planOnly
node scripts/infra-ops.mjs linux-portability-check
node scripts/infra-ops.mjs dr-evidence
node scripts/infra-ops.mjs alert-evidence
node scripts/infra-ops.mjs release-evidence --planOnly
node scripts/infra-ops.mjs governance-check
node scripts/infra-ops.mjs github-actions-config --repo mattdifi05/project-repository
node scripts/infra-ops.mjs pre-go-live-evidence --repo mattdifi05/project-repository
node scripts/infra-ops.mjs production-go-no-go
node scripts/infra-ops.mjs external-uptime-check --dryRun
node scripts/infra-ops.mjs evidence-bundle
node scripts/infra-ops.mjs github-environments --repo mattdifi05/project-repository --dryRun
node scripts/infra-ops.mjs github-environments --repo mattdifi05/project-repository --apply (expected fail-fast without GITHUB_PRODUCTION_REVIEWERS)
docker run --rm -v D:/docker/platform-infrastructure:/infra:ro -w /infra platform/ops:local github-environments --repo mattdifi05/project-repository --dryRun
docker run --rm -e PROJECT_SOURCE_ROOT=/project -v D:/docker/platform-infrastructure:/infra:ro -v D:/docker/project:/project:ro -w /infra platform/ops:local static-security-check
node scripts/infra-ops.mjs backup-secret-manager-metadata --outputDir backups/secret-manager/report-test --skipEvidence
scripts/run-infra-ops.mjs static-security-check
scripts/run-infra-ops.mjs infra-health
scripts/run-infra-ops.mjs enterprise-10-check
scripts/infra-ops.sh static-security-check through docker:29-cli
scripts/infra-ops.sh infra-health through docker:29-cli
scripts/infra-ops.sh enterprise-10-check through docker:29-cli
docker run --rm -v D:/docker/platform-infrastructure:/work:ro alpine:3.22 sh -ec 'sh -n /work/scripts/deploy-vps.sh && sh -n /work/scripts/vps-postdeploy.sh && sh -n /work/scripts/evidence-bundle.sh'
docker run --rm -v D:/docker/platform-infrastructure:/infra -w /infra alpine:3.22 sh ./scripts/vps-go-live.sh --planOnly --repo OWNER/REPO
node --import ./scripts/register-ts-extension-loader.mjs --test apps/worker-notifications/src/server.test.ts
full-restore-drill.sh
failure-tests.sh --confirmServiceStop --targets redis
load-benchmark.sh --quick --profiles 50,100,500 --requests 20 --maxConcurrency 8 --maxP95Ms 2000
rollback-release.sh dry-run
promtool check rules prometheus/rules/enterprise-alerts.yml
```

All commands listed above passed in the local evidence gathered during this hardening run.

## Problems Found And Fixed

- phpMyAdmin login/root-secret handling was inconsistent; local secrets now provide MariaDB root credentials through Docker secrets.
- Unprotected raw admin routes were too broad; Prometheus, Alertmanager and Traefik dashboard browser routes are now blocked or internal.
- WAF needed local phpMyAdmin tuning; CRS exclusions were narrowed to phpMyAdmin navigation parameters.
- Initial ops wrappers still assumed host Node; wrappers now use a Dockerized ops image.
- Dockerized ops runner initially failed local HTTPS health checks from inside containers; Linux host networking and local host aliases were added.
- Nested Docker path mapping initially failed for backup/SBOM flows; host/container source mappings were added.
- Managed-secret overlay missed MariaDB/phpMyAdmin secrets; they are now external Docker secrets.
- Secret rotation/freshness proof was only implicit through Secret Manager verify; `secret-rotation-evidence.sh --enforce` now writes a required go/no-go report under `reports/secret-rotation/`.
- WAF lacked a container-level healthcheck and the readiness checklist only proved generic healthcheck presence; WAF now has a healthcheck and `compose-healthcheck-coverage.sh` verifies every rendered service.
- Application CI and docs still referenced PowerShell or direct host-Node infra gates; they now use bash/containerized gates or `scripts/run-infra-ops.mjs`.
- Production go/no-go now requires a remote successful `enterprise-infra` workflow report for the release commit.
- Alerting had email/generic webhook only; optional native Discord and Telegram delivery with metrics was added.
- Uptime dry-run previously did not leave report evidence; it now writes diagnostic reports while keeping `providerEvidence.verified=false` so production go/no-go still requires a live provider.
- VPS deploy previously stopped after compose/WAF smoke; a post-deploy script now runs WAF smoke plus `infra-health` and can opt into pre go-live, go/no-go and live production readiness gates.
- VPS live execution previously required manually sequencing many commands; `vps-go-live.sh` now creates a plan-first orchestration report and can run the ordered live sequence with `--confirmLive`.
- VPS bootstrap was previously a manual VPS task; `vps-bootstrap-ubuntu.sh` now plans/applies Git, Docker Engine, Buildx and Compose plugin installation with evidence reports.
- VPS hardening previously printed dry-run/apply output only; it now writes plan/apply JSON and Markdown evidence reports.
- VPS preflight previously rendered only the base VPS overlay; it now renders the full VPS+WAF Compose stack used by deploy and scans that render for mutable `:latest` images.
- VPS post-deploy previously sourced `.env`; it now parses only the required public URL keys without executing the env file.
- VPS remote deploy previously interpolated deploy values inside one SSH shell string; it now passes values as positional arguments to a literal remote script.
- Backup scheduler cron jobs previously sourced the private scheduler env file; they now call `backup-scheduler.sh --run` and parse the env file without shell execution.
- VPS host readiness previously sourced `/etc/os-release`; it now parses that file as data before checking Ubuntu LTS status.
- Local disposable Linux VPS-readiness probes previously wrote failed reports into production evidence; `--diagnostic` now writes them under `reports/vps-host-diagnostics/` while real VPS checks use `--enforce`.
- Evidence reports previously had to be gathered manually; `evidence-bundle.sh` now creates a non-secret archive with a manifest and SHA256 checksums.
- Evidence bundles now have a verifier that rereads the manifest and fails on hash drift, policy violations or missing required live evidence.

## Requirement Status

| # | Area | Local status | VPS/provider status |
| ---: | --- | --- | --- |
| 1 | Backup automatici | Implemented for PostgreSQL, MariaDB, MinIO, Keycloak config and Secret Manager metadata, with Dockerized scheduler profile and execution reports. | Enable scheduler and off-site repository on VPS, then archive first reports outside Git. |
| 2 | Restore drill | Full and per-service local drills implemented and exercised; off-site Restic restore drill and DR evidence summaries now cover timing/RTO/RPO reporting. | Remote restore from the real off-site repository must be executed with live credentials and `dr-evidence --enforce` must pass. |
| 3 | Passkey/WebAuthn | App code, tests and PostgreSQL persistence exist; OTP fallback retained. | Browser validation on real production domains still required. |
| 4 | Protezione console | Raw Prometheus/Alertmanager/Traefik dashboard blocked; admin surfaces kept internal or authenticated. | Cloudflare Access/VPN/SSH tunnel must be configured on real zone/host. |
| 5 | Healthcheck completi | `infra-health` covers containers, endpoints, admin blocks and WAF blocks. | Must pass on VPS after deploy. |
| 6 | Alert reali | Prometheus/Alertmanager/email plus optional Discord/Telegram metrics implemented; alert evidence and external uptime dry-run reports added. | Real email/Discord/Telegram delivery and external monitoring provider checks must be tested. |
| 7 | Failure tests | Controlled failure tests implemented and Redis recovery exercised. | Full target matrix should run in staging/VPS window. |
| 8 | Rollback | Image/compose rollback dry-run, post-health command and release evidence rollback-target generation are implemented. | Real previous image set must be captured from the live registry per release. |
| 9 | CI/CD | GitHub workflows, compose gates, DAST job, branch-protection apply command, deployment environment approvals, runtime secret/var verification, release evidence plan, VPS deploy job, post-deploy checks and evidence bundle smoke are prepared. | Secrets, branch protection and deploy approvals must be enabled in GitHub. |
| 10 | Dependency management | Renovate configured for app/infra. | Dependency dashboard and production update cadence must be operated. |
| 11 | Log hygiene | Redaction, bounded logs, Loki retention and dashboards added. | Retention/capacity must be tuned on VPS disk size. |
| 12 | Runbook definitivo | README, RUNBOOK, SECURITY, readiness and VPS checklist updated. | Must be followed during first real deploy. |
| 13 | Security hardening | Secrets, rotation evidence, service healthcheck coverage, CSP, rate limits, WAF, headers, admin blocks and audit gates implemented. | Cloudflare and VPS hardening must be applied live. |
| 14 | Load test | 50/100/500 benchmark command and local quick run completed. | Public-path VPS load benchmark still required. |
| 15 | Production-like env | Local, staging, VPS and production overlays exist. | Real staging and production hosts must be exercised. |
| 16 | Remove Windows dependency | Host-critical ops moved to Linux containers; LF normalization configured. | Docker Desktop compatibility retained; VPS requires no Windows. |
| 17 | Container-first ops | Backup, restore, scheduler, health, load, SBOM and diagnostics run through ops containers. | Confirm on Ubuntu VPS after clone. |
| 18 | Ubuntu LTS compatibility | Compose renders, shell syntax checks and host-readiness script exist. | Real Ubuntu LTS run still required. |
| 19 | VPS prep | Hardening, host readiness, origin lock, deploy scripts, post-deploy checks and checklist exist. | Execute on the actual VPS. |
| 20 | Final report | This audit, `READINESS-REPORT.md`, `VPS-PREDEPLOY-CHECKLIST.md`, pre go-live evidence and evidence bundle command exist. | Update with real production evidence after go-live. |

## Readiness Scores

| Area | Score | Reason |
| --- | ---: | --- |
| Development | 9/10 | Local Docker stack, app launcher, health, WAF, secrets and gates are operational. |
| Staging | 8/10 | Staging overlay exists and renders; real staging host/domain remains untested. |
| Production | 7.5/10 | VPS overlays and hardening exist; real VPS deploy and provider wiring remain. |
| Security | 8.7/10 | WAF, CSP, rate limits, secrets, audit, admin blocks and smoke gates are present. |
| Observability | 8.5/10 | Metrics, logs, dashboards, alerts, email, Discord and Telegram hooks are wired locally. |
| Disaster Recovery | 8.5/10 | Local full restore drills pass and off-site restore automation exists; live Restic repository restore must still be proven. |
| Linux Portability | 9.5/10 | Dockerized ops runner, shell syntax checks, LF normalization and no Windows-critical ops. |

## Requires Real VPS Or External Provider

- VPS Ubuntu LTS host bootstrap apply report under `reports/vps-bootstrap/`.
- VPS Ubuntu LTS host hardening apply report under `reports/vps-hardening/`.
- Docker Engine, Compose plugin and Git installation on the actual VPS.
- VPS host readiness script passed on the actual VPS host under `reports/vps-host/`.
- Cloudflare DNS/CDN/WAF/Access setup on the real zone, including verified MFA-protected Access applications for admin hosts.
- Cloudflare origin lock applied after proxied DNS works.
- Real SMTP/email and optional Discord/Telegram delivery tests.
- External uptime monitoring provider enabled from `monitoring/external-uptime.example.json` and confirmed from outside the VPS network.
- Dockerized backup scheduler enabled on VPS, plus remote Restic repository credentials and `offsite-restore-drill-restic` dry-run/full restore evidence.
- Real staging deploy and production deploy.
- GitHub branch protection applied and verified on the live repository.
- GitHub deployment environments applied and verified with production reviewers.
- GitHub Actions secrets and variables verified on the live repository.
- Pre go-live evidence pack generated with runtime/restore evidence on the real target.
- Production go/no-go report generated with status `go`.
- Evidence bundle regenerated after `go` status and archived outside Git.
- Load benchmark against the public route.
- Registry digest pinning, image signing, provenance and `release-evidence` reports for the real release artifacts.
- HA beyond a single VPS if maximum enterprise availability is required.

## Final VPS Pre-Deploy Checklist

Use `VPS-PREDEPLOY-CHECKLIST.md` as the canonical checklist. Minimum go/no-go:

```text
1. Host bootstrap hardened.
2. VPS host readiness report passed and archived.
3. .env created from examples with no placeholders.
4. Secret manager initialized, verified and `secret-rotation-evidence.sh --enforce` archived.
5. VPS compose render passes.
6. Cloudflare DNS proxied, Access admin applications verified, and origin lock applied.
7. Dockerized backup scheduler enabled and backup execution reports reviewed.
8. Full local and remote restore drills pass.
9. Static security, infra health, security smoke and WAF smoke pass.
10. Failure tests pass in staging.
11. 50/100/500 load benchmark report archived.
12. External uptime provider monitors created and first green check archived.
13. Alert delivery reaches real recipients.
14. GitHub branch protection, deployment environments and Actions runtime config applied or verified.
15. Pre go-live evidence pack archived.
16. Production go/no-go report archived with status `go`.
17. Release evidence pack archived with rollback target and release image digests.
18. Evidence bundle archive generated, manifest reviewed, SHA256 recorded and stored outside Git.
```
