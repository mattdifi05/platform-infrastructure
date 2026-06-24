# Stexor Readiness Report

Current scope: repository and local Docker evidence before Hostinger VPS deployment.

## Readiness Scores

| Area | Score | Evidence |
| --- | ---: | --- |
| Development | 9/10 | Local stack, projects gateway, secret manager, WAF and health gates are operational. |
| Staging | 8/10 | Staging overlays and gates exist; a real staging host/domain still has to be exercised. |
| Production | 7.5/10 | Production/Hostinger overlays, preflight, rollback and release evidence tooling exist; real VPS deploy remains required. |
| Security | 8.5/10 | Secrets, WAF, rate limits, CSP, audit, passkeys, smoke tests and hardening scripts are in place. |
| Observability | 8.5/10 | Prometheus, Alertmanager, Loki, Promtail, Grafana dashboards, email alerts and alert evidence tooling are wired. |
| Disaster Recovery | 8.5/10 | Full local restore drills, off-site Restic restore automation with full-family coverage checks and rollback evidence tooling exist; live remote restore must be proven. |
| Linux Portability | 9.5/10 | Shell scripts, LF normalization, Dockerized ops runner and Linux syntax checks are present. |

## Completed In Repository

- Backup scripts for PostgreSQL, MariaDB, MinIO, Keycloak configuration and Secret Manager metadata.
- Non-secret JSON/Markdown execution reports for every backup family under ignored `reports/backups/`.
- Dockerized backup scheduler profile for daily backups, weekly restore drill and retention without host cron.
- Backup scheduler jobs parse the private runtime env file as data through `backup-scheduler.sh --run`, avoiding `source`/shell execution of scheduler env content.
- Restore tests and `full-restore-drill.sh` with timing reports.
- `dr-evidence.sh` summarizes backup freshness, average/P95 restore duration, RTO/RPO status and full-family off-site restore coverage under ignored `reports/dr/`.
- `infra-health.sh` with container, endpoint and WAF checks.
- `failure-tests.sh` with safe default and opt-in service stop/recovery probes.
- `load-benchmark.sh` for 50/100/500-user profiles with CPU/RAM snapshots plus public target and edge/CDN evidence for production runs.
- `rollback-release.sh` with dry-run plans, image validation and post-rollback health checks.
- `release-evidence.sh` with digest-pinned image validation, SBOM/provenance references, rollback target generation and ignored JSON/Markdown reports.
- Renovate configs for infrastructure and application dependencies.
- Hostinger, Cloudflare, WAF, staging, production and managed-secret runbook coverage.
- Cloudflare Access admin manifest and additive apply/verify command for MFA-protected admin applications.
- VPS bootstrap script installs Git, Docker Engine, Buildx and Docker Compose plugin from Docker's official Ubuntu apt repository with plan/apply JSON/Markdown reports under `reports/vps-bootstrap/`.
- Hostinger/Ubuntu host readiness script with JSON/Markdown evidence for Docker, Compose, Git, UFW, fail2ban and SSH/Docker hardening.
- VPS hardening script now writes plan/apply JSON/Markdown reports under `reports/vps-hardening/`, so host bootstrap changes can be archived with the readiness evidence.
- VPS host readiness parses `/etc/os-release` as data instead of sourcing it, so host metadata cannot execute shell content during checks.
- VPS readiness diagnostics from disposable Linux containers write under `reports/vps-host-diagnostics/`; only `--enforce` reports under `reports/vps-host/` count as production evidence.
- Containerized ops runner, so the VPS host does not need Node, pnpm or a JS toolchain.
- `linux-portability-check.sh` scans BOM/CRLF, Windows paths and PowerShell/cmd dependencies, validates shell wrappers with Alpine and writes reports under `reports/linux-portability/`.
- Local `enterprise-10-check` passes through the Dockerized ops runner.
- Infrastructure and application CI now use bash/containerized infra gates instead of PowerShell or direct host-Node infra policy commands.
- Alert delivery supports email plus optional native Discord and Telegram channels, each with delivery/failure metrics.
- `alert-evidence.sh` validates Alertmanager routing and can send a synthetic alert to prove webhook/email/Discord/Telegram delivery counters.
- The application repo exposes a cross-platform Dockerized infra-ops launcher, so `pnpm infra:health` and enterprise gates work from Docker Desktop without a local Unix shell.
- Provider-neutral external uptime manifest and `external-uptime-check` dry-run are wired into the infra gate; real provider monitors still need live DNS/CDN.
- `external-uptime-check --dryRun` now writes diagnostic JSON/Markdown under `reports/uptime/` with `providerEvidence.verified=false`, so manifest evidence can be archived without satisfying the production provider gate.
- GitHub branch protection policy has a containerized dry-run/apply/verify command; live enforcement still needs an admin token and repository access.
- GitHub deployment environments for staging/production are now versioned with dry-run/apply/verify, production reviewers and serialized deploys.
- GitHub Actions runtime secrets/vars are versioned and can be verified remotely without exposing secret values.
- Pre go-live evidence pack aggregates local gates, provider dry-runs and remaining VPS/provider proof into ignored JSON/Markdown reports.
- Off-site restore drill and release evidence plan are included in the pre go-live evidence flow.
- `production-go-no-go.sh` aggregates live evidence reports and writes ignored JSON/Markdown reports under `reports/go-no-go/`; `--enforce` blocks production if any required proof is missing.
- `production-go-no-go` reports include a remediation checklist for every failed required gate.
- `production-readiness-live.sh` maps the 20-point production-ready checklist to the latest live `production-go-no-go` evidence and writes `reports/production-readiness/`.
- `github-actions-run-evidence.sh --verifyRemote` proves the remote `enterprise-infra` workflow completed successfully on the release commit and writes `reports/github-actions/`.
- `hostinger-preflight.sh` validates the full Hostinger+WAF Compose render used by deploy, then `hostinger-postdeploy.sh` runs WAF smoke and `infra-health` after the VPS compose start, with opt-in pre go-live evidence, final `production-go-no-go` and live readiness flags.
- `evidence-bundle-verify.sh` rereads the final evidence bundle manifest, validates entry SHA256/size and can require every live evidence family before handoff.
- `hostinger-postdeploy.sh` parses only the required `.env` keys and does not source/execute the env file.
- `hostinger-go-live.sh` provides a plan-first VPS orchestration path for readiness, preflight, optional compose start, postdeploy, go/no-go and evidence bundle reports.
- `deploy-hostinger.sh` passes remote deploy values through SSH positional arguments and a literal remote script, avoiding shell-string interpolation for branch, path, env file and deploy flags.
- `evidence-bundle.sh` creates a non-secret `.tmp/evidence-bundles/stexor-evidence-bundle-*.tar.gz` with report/document manifests and SHA256 checksums.

## Requires Real VPS Or External Provider

- Off-site Restic repository credentials and full-family restore from remote storage with `coverage.complete=true`.
- Hostinger Ubuntu LTS bootstrap executed on the actual host with `reports/vps-bootstrap/vps-bootstrap-apply-*.json`.
- Hostinger Ubuntu LTS hardening executed on the actual host with `reports/vps-hardening/vps-hardening-apply-*.json`.
- VPS host readiness report generated on the actual Hostinger host with `reports/vps-host/vps-host-readiness-*.json`.
- Cloudflare DNS/CDN/WAF/Access configuration on the real zone, including `cloudflare-access-admin.sh --verifyRemote` evidence for admin applications.
- External uptime monitoring provider enabled and confirmed from outside the VPS network.
- Real staging deploy and production deploy.
- GitHub branch protection applied and verified on the live repository.
- GitHub staging/production environments applied and verified with production reviewers.
- GitHub Actions repository/environment secrets and variables verified on the live repository.
- Pre go-live evidence pack generated on the real VPS/staging path with runtime and restore-drill options.
- Release evidence pack generated with real registry image digests, provenance/signature artifacts and rollback target.
- Production go/no-go report generated with status `go`.
- Load benchmark against the VPS through the public Cloudflare/CDN traffic path with `--requirePublicTarget --requireEdgeEvidence`.
- Final evidence bundle generated after the status is `go` and stored outside Git.
- Admin access enforcement through Cloudflare Access, VPN or SSH tunnel.
- Multi-node HA or managed database/storage if the target is maximum enterprise availability.

## Pre-Deploy Command Set

```sh
sh ./scripts/stexor-secret-manager.sh verify
sh ./scripts/static-security-check.sh
sh ./scripts/linux-portability-check.sh
sh ./scripts/infra-health.sh
sh ./scripts/full-restore-drill.sh
sh ./scripts/dr-evidence.sh --enforce
sh ./scripts/alert-evidence.sh --sendTest --requireEmailDelivery
sh ./scripts/failure-tests.sh --confirmServiceStop
sh ./scripts/load-benchmark.sh --profiles 50,100,500 --url https://api.example.com/health --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare
sh ./scripts/production-preflight.sh
sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --dryRun
sh ./scripts/github-environments.sh --repo OWNER/REPO --dryRun
sh ./scripts/github-actions-config.sh --repo OWNER/REPO
sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO
sh ./scripts/release-evidence.sh --planOnly
GITHUB_TOKEN=... sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote
sh ./scripts/production-go-no-go.sh --enforce
sh ./scripts/production-readiness-live.sh
sh ./scripts/evidence-bundle.sh
sh ./scripts/evidence-bundle-verify.sh --requireComplete
```
