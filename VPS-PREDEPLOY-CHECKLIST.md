# Stexor VPS Pre-Deploy Checklist

Use this checklist on the Hostinger Ubuntu LTS VPS before exposing public traffic.

## Host Bootstrap

- [ ] Ubuntu LTS installed and updated.
- [ ] `sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user <deploy-user>` executed, installing Git, Docker Engine, Buildx and Docker Compose plugin from Docker's official Ubuntu apt repository.
- [ ] The JSON/Markdown report under `reports/vps-bootstrap/` was archived outside Git.
- [ ] Node, pnpm, PHP CLI and build toolchains are not required on the host.
- [ ] Non-root deploy user created and added to the `docker` group only if required.
- [ ] SSH key login verified.
- [ ] Password SSH login disabled.
- [ ] `sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 65002 --reload-sshd` executed after key access and the target SSH port were verified, including Docker daemon hardening, and the JSON/Markdown report under `reports/vps-hardening/` was archived outside Git. If an existing `/etc/docker/daemon.json` blocks the run, review the generated template and rerun with `--replace-docker-daemon-config`.
- [ ] `sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce` passed and the JSON/Markdown report under `reports/vps-host/`, including the expected SSH port, UFW allow rule and remediation guidance for every check, was archived outside Git.
- [ ] `sudo ufw status verbose` reviewed.
- [ ] fail2ban active.

## Repository And Environment

- [ ] App repository and `stexor-platform-infrastructure` cloned under `/opt/stexor`.
- [ ] `.env` created from `.env.example` and `.env.hostinger.example`.
- [ ] No `localhost`, `example.com`, `change_me` or placeholder production values remain.
- [ ] `sh ./scripts/stexor-secret-manager.sh init` executed.
- [ ] `sh ./scripts/stexor-secret-manager.sh verify` passed.
- [ ] `sh ./scripts/secret-rotation-evidence.sh --enforce` passed and the JSON/Markdown reports under `reports/secret-rotation/` were archived outside Git.
- [ ] `sh ./scripts/hostinger-preflight.sh .env` passed and rendered the full Hostinger+WAF Compose stack, including `compose.waf.yaml` and `compose.hostinger-waf.yaml`.
- [ ] `sh ./scripts/linux-portability-check.sh` passed and the JSON/Markdown report under `reports/linux-portability/` was archived outside Git.
- [ ] No mutable `:latest` image exists in the rendered Hostinger+WAF stack.
- [ ] `sh ./scripts/hostinger-go-live.sh --planOnly --repo OWNER/REPO --bootstrap --apply-hardening --reload-sshd` generated a reviewed JSON/Markdown plan under `reports/hostinger-go-live/`; if an existing Docker daemon config must be replaced, the reviewed plan includes `--replace-docker-daemon-config`.
- [ ] `sh ./scripts/hostinger-postdeploy.sh .env` passed after the first VPS compose start, including WAF smoke and `infra-health` against public URLs from `.env`.
- [ ] Remote deploy variables reviewed: `DEPLOY_RUN_PRE_GO_LIVE`, `DEPLOY_RUN_GO_NO_GO`, `DEPLOY_PRE_GO_LIVE_RESTORE_DRILL`, `DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN` and `DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE` are enabled only for the final evidence window.

## Cloudflare And Edge

- [ ] DNS records are proxied through Cloudflare.
- [ ] Origin IP is not exposed in public DNS records.
- [ ] Cloudflare WAF rules reviewed.
- [ ] Cloudflare cache rules reviewed for API/account paths.
- [ ] `sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.production.json` reviewed.
- [ ] `CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.production.json --apply` completed for admin hosts, or equivalent Cloudflare Access config is proven.
- [ ] `CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.production.json --verifyRemote` passed.
- [ ] Origin lock applied after proxying works: `sudo sh ./scripts/cloudflare-origin-lock-ufw.sh --apply --ports "80"`.
- [ ] TLS mode and origin certificate strategy confirmed.

## Data Protection

- [ ] `sh ./scripts/backup-postgres.sh` passed.
- [ ] `sh ./scripts/backup-mariadb.sh` passed.
- [ ] `sh ./scripts/backup-minio.sh` passed.
- [ ] `sh ./scripts/backup-keycloak.sh` passed.
- [ ] `sh ./scripts/backup-secret-manager-metadata.sh` passed.
- [ ] Backup execution reports under `reports/backups/` reviewed and archived outside Git.
- [ ] `sh ./scripts/full-restore-drill.sh` passed.
- [ ] `sh ./scripts/dr-evidence.sh --enforce` passed and the JSON/Markdown reports under `reports/dr/` were archived outside Git.
- [ ] `compose.backup-scheduler.yaml` enabled with `--profile backup` or an equivalent scheduler approved.
- [ ] `docker exec enterprise-backup-scheduler crontab -l` reviewed, if using the Dockerized scheduler.
- [ ] Restic repository configured outside Git.
- [ ] `sh ./scripts/offsite-backup-restic.sh` passed.
- [ ] `sh ./scripts/offsite-restore-drill-restic.sh --dryRun --passwordFile ./secrets/restic_password.txt` validated the off-site repository and snapshot.
- [ ] `sh ./scripts/offsite-restore-drill-restic.sh --passwordFile ./secrets/restic_password.txt` restored from the off-site repository into disposable paths and passed restore tests with `coverage.complete=true`.

## Release Gates

- [ ] `sh ./scripts/static-security-check.sh` passed.
- [ ] `sh ./scripts/compose-healthcheck-coverage.sh` passed and the JSON/Markdown reports under `reports/healthchecks/` were archived outside Git.
- [ ] `sh ./scripts/rate-limit-evidence.sh` passed and the JSON/Markdown reports under `reports/rate-limits/` were archived outside Git.
- [ ] `sh ./scripts/infra-health.sh` passed.
- [ ] `sh ./scripts/security-smoke.sh` passed.
- [ ] `sh ./scripts/waf-smoke.sh` passed.
- [ ] `sh ./scripts/alert-evidence.sh --sendTest --requireEmailDelivery` passed and the JSON/Markdown reports under `reports/alerts/` were archived outside Git.
- [ ] `sh ./scripts/external-uptime-check.sh --dryRun` passed and provider monitors were created from `monitoring/external-uptime.example.json`.
- [ ] `sh ./scripts/external-uptime-check.sh --providerEvidence ./monitoring/external-uptime-provider.production.json --validateProviderEvidenceOnly` passed and wrote `reports/uptime/` with real provider monitor ids, public URLs, regions, `lastStatusCode`, `lastLatencyMs`, `lastCheckedAt` and a fresh `verifiedAt`.
- [ ] `sh ./scripts/external-uptime-check.sh --envFile .env --providerEvidence ./monitoring/external-uptime-provider.production.json --requireProviderEvidence` passed with the same provider evidence plus a direct public probe.
- [ ] `sh ./scripts/failure-tests.sh --confirmServiceStop` passed in staging.
- [ ] `sh ./scripts/load-benchmark.sh --profiles 50,100,500 --url https://api.example.com/health --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare` completed with `status=passed`, classified the target as public, recorded edge evidence, and archived `reports/load/`.
- [ ] `sh ./scripts/production-preflight.sh` passed.
- [ ] `sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --dryRun` reviewed.
- [ ] `GITHUB_TOKEN=... sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --apply` and `--verifyRemote` completed, or equivalent branch protection is proven in GitHub.
- [ ] `sh ./scripts/github-environments.sh --repo OWNER/REPO --dryRun` reviewed.
- [ ] `GITHUB_PRODUCTION_REVIEWERS=user:OWNER GITHUB_TOKEN=... sh ./scripts/github-environments.sh --repo OWNER/REPO --apply` and `--verifyRemote` completed, or equivalent deployment approvals are proven in GitHub.
- [ ] `sh ./scripts/github-actions-config.sh --repo OWNER/REPO` reviewed.
- [ ] `GITHUB_TOKEN=... sh ./scripts/github-actions-config.sh --repo OWNER/REPO --verifyRemote` confirmed `DAST_TARGET`, `DEPLOY_SSH_KEY`, `DEPLOY_REMOTE` and `DEPLOY_REMOTE_DIR`.
- [ ] `GITHUB_TOKEN=... sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote` passed and `reports/github-actions/` was archived outside Git.
- [ ] `sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO --includeRuntime --includeRestoreDrill --includeOffsiteRestoreDryRun --includeProductionPreflight --verifyGithubRemote` passed with `status=passed` and the JSON/Markdown reports under `reports/go-live/` were archived outside Git.
- [ ] SBOM archived.
- [ ] `sh ./scripts/release-evidence.sh --requireProvenance --provenance ./release/provenance.json --previousImagesFile ./release/previous-images.json` passed with `status=passed`, validated SLSA v1 provenance subjects against every image digest and release commit, linked a validated `reports/rollback/rollback-plan-*.json`, and `reports/release/` plus `reports/rollback/` were archived outside Git.
- [ ] Image digests and rollback target recorded.
- [ ] `sh ./scripts/production-go-no-go.sh --enforce` passed and `reports/go-no-go/` was archived outside Git.
- [ ] If `production-go-no-go` returns `no-go`, every item in the report `remediation` checklist was completed and the gate was rerun until `status=go`.
- [ ] `sh ./scripts/production-readiness-live.sh` passed and `reports/production-readiness/` was archived outside Git.
- [ ] `sh ./scripts/evidence-bundle.sh` generated `.tmp/evidence-bundles/stexor-evidence-bundle-*.tar.gz`; `manifest.json` was reviewed and the archive was stored outside Git.
- [ ] `sh ./scripts/evidence-bundle-verify.sh --requireComplete` passed against the final evidence bundle.

## Admin Surfaces

- [ ] phpMyAdmin not enabled by default.
- [ ] Grafana, Prometheus, Alertmanager, MinIO console, Keycloak Admin and Traefik dashboard are not public.
- [ ] Admin access protected by Cloudflare Access, VPN, SSH tunnel or equivalent MFA-protected path, with `cloudflare-access-admin.sh --verifyRemote` evidence when Cloudflare Access is used.

## Go/No-Go

- [ ] External uptime monitoring delivered a real green check from outside the VPS network and the report contains verified provider evidence.
- [ ] Email alerts delivered to the real recipient.
- [ ] Optional Discord/Telegram alert channels configured through secret files and delivery metrics checked, if used.
- [ ] Disaster recovery procedure rehearsed.
- [ ] Deploy audit entry written.
- [ ] Rollback dry-run plan generated with `sh ./scripts/rollback-release.sh --rollbackFile ./release/previous-images.json`.
- [ ] Production go/no-go status is `go`.
