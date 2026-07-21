# Platform VPS Pre-Deploy Checklist

Use this checklist on the VPS Ubuntu LTS VPS before exposing public traffic.

## Host Bootstrap

- [ ] Ubuntu LTS installed and updated.
- [ ] `sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user <deploy-user>` executed, installing Git, jq, Docker Engine, Buildx and Docker Compose plugin from Docker's official Ubuntu apt repository.
- [ ] The JSON/Markdown report under `reports/vps-bootstrap/` was archived outside Git.
- [ ] Node, pnpm, PHP CLI and build toolchains are not required on the host.
- [ ] Non-root deploy user created and added to the `docker` group only if required.
- [ ] SSH key login verified.
- [ ] Password SSH login disabled.
- [ ] `sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 65002 --reload-sshd` executed after key access and the target SSH port were verified, including Docker daemon hardening, and the JSON/Markdown report under `reports/vps-hardening/` was archived outside Git. If an existing `/etc/docker/daemon.json` blocks the run, review the generated template and rerun with `--replace-docker-daemon-config`.
- [ ] `sudo sh ./scripts/vps-host-readiness.sh --ssh-port 65002 --enforce` passed and the JSON/Markdown report under `reports/vps-host/`, including the expected SSH port, UFW allow rule and remediation guidance for every check, was archived outside Git.
- [ ] GitHub Actions workflow `enterprise-vps-evidence` passed in the `production` environment; its verified receipt/provenance binds the archive to the exact workflow commit and Git tree, and the artifact was archived outside Git.
- [ ] `sudo ufw status verbose` reviewed.
- [ ] fail2ban active.
- [ ] `sh ./scripts/container-metrics-sandbox-test.sh` passed without touching the live Docker runtime.
- [ ] `sudo sh ./scripts/install-container-metrics-collector.sh --apply --deploy-user <deploy-user> --repo-root <absolute-repo-path>` completed in an approved maintenance window.
- [ ] `sudo sh ./scripts/install-container-metrics-collector.sh --verify --repo-root <absolute-repo-path>` passed, proving a fresh complete per-container snapshot and node-exporter textfile metrics.
- [ ] `sh ./scripts/host-reliability-sandbox-test.sh` passed.
- [ ] `sudo sh ./scripts/install-host-reliability-collector.sh --apply --repo-root <absolute-repo-path>` completed, followed by `--verify` with full SMART/NVMe coverage.
- [ ] Node-exporter uses the same `NODE_EXPORTER_TEXTFILE_DIR` as the host collectors; Prometheus reports the host and container collector series as fresh.
- [ ] `systemd-networkd-wait-online.service` passes for the production interface. Any drop-in was applied with `configure-host-wait-online.sh`, without `netplan apply` over SSH.
- [ ] Production addressing is deterministic through Ethernet/static configuration or a router DHCP reservation, and a console-backed reboot preserved SSH, route and Docker access.
- [ ] Pending package and reboot state recorded; controlled patch/reboot evidence proves SSH, NVMe mounts, Docker and all required containers healthy afterward.
- [ ] Supported UPS hardware is visible through NUT and a controlled on-battery/shutdown drill passed. Configuration without hardware is not evidence.

## Repository And Environment

- [ ] App repository and `platform-infrastructure` cloned under the reviewed
      server path. Recommended generic path is `/opt/platform`; the current
      reference server uses `/home/platform_infrastructure/platform-infrastructure`
      for the infra repo and `/home/platform_infrastructure/src` for external
      application sources. The external `src` path is not part of this
      repository.
- [ ] `.env` created from `.env.example` and `.env.vps.example`.
- [ ] No `localhost`, `example.com`, `change_me` or placeholder production values remain.
- [ ] `sh ./scripts/infra-secret-manager.sh init` executed.
- [ ] `sh ./scripts/infra-secret-manager.sh verify` passed.
- [ ] `sh ./scripts/secret-rotation-evidence.sh --enforce` passed and the JSON/Markdown reports under `reports/secret-rotation/` were archived outside Git.
- [ ] `sh ./scripts/vps-preflight.sh .env` passed and rendered the canonical VPS+WAF stack, including `compose.runtime.yaml` and `compose.networks.yaml` loaded last.
- [ ] The zero-workload core render passed independently and contains no application backend, frontend, worker, schema migration or application secret requirement.
- [ ] Each attached application has an external catalog entry, application-owned manifest and Compose overlay, digest-pinned images, ignored non-secret runtime environment and application-owned migration/rollback procedure.
- [ ] `sh ./scripts/prepare-hosted-workloads.sh` produced a `verified` lock with mode `0600`; core and combined render diffs contain only the declared workload services, routes, networks and secrets.
- [ ] `sh ./scripts/hosted-workload-lock.sh <lock-file> verify` passed immediately before the approved workload activation window.
- [ ] `sh ./scripts/network-segmentation-check.sh --envFile .env` passed and its non-secret report under `reports/network-segmentation/` was archived outside Git.
- [ ] `sh ./scripts/network-segmentation-sandbox-test.sh` passed, proving allowed ingress/data paths and denied router-to-DB, app-to-observability and cross-app paths.
- [ ] `sudo sh ./scripts/workload-egress-firewall.sh --plan --network-prefix "$PLATFORM_NETWORK_PREFIX"` was reviewed after candidate networks were created; apply/verify used the strong confirmation in an approved maintenance window before hosted workloads started.
- [ ] `sh ./scripts/linux-portability-check.sh` passed and the JSON/Markdown report under `reports/linux-portability/` was archived outside Git.
- [ ] No mutable `:latest` image exists in the rendered VPS+WAF stack.
- [ ] `sh ./scripts/vps-go-live.sh --planOnly --repo OWNER/REPO --bootstrap --apply-hardening --reload-sshd` generated a reviewed JSON/Markdown plan under `reports/vps-go-live/`; if an existing Docker daemon config must be replaced, the reviewed plan includes `--replace-docker-daemon-config`.
- [ ] `sh ./scripts/vps-postdeploy.sh .env` passed after the first VPS compose start, including WAF smoke and `infra-health` against public URLs from `.env`.
- [ ] Remote deploy variables reviewed: `DEPLOY_RUN_PRE_GO_LIVE`, `DEPLOY_RUN_GO_NO_GO`, `DEPLOY_PRE_GO_LIVE_RESTORE_DRILL`, `DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN` and `DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE` are enabled only for the final evidence window.

## Cloudflare And Edge

- [ ] DNS records are proxied through Cloudflare.
- [ ] Origin IP is not exposed in public DNS records.
- [ ] Cloudflare WAF rules reviewed.
- [ ] Cloudflare cache rules reviewed for platform admin/docs paths and any
      explicitly attached application/API/auth paths.
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
- [ ] `sh ./scripts/audit-log-evidence.sh` passed and the JSON/Markdown reports under `reports/audit-logs/` were archived outside Git.
- [ ] `sh ./scripts/retention-evidence.sh` passed and the JSON/Markdown reports under `reports/retention/` were archived outside Git.
- [ ] `sh ./scripts/infra-health.sh` passed.
- [ ] Prometheus exposes fresh `platform_container_cpu_percent`, `platform_container_memory_usage_bytes` and collector-health series for every container Docker reports as running; Grafana shows workload CPU/RAM and effective limit coverage.
- [ ] `sh ./scripts/security-smoke.sh` passed.
- [ ] `sh ./scripts/waf-smoke.sh` passed.
- [ ] `sh ./scripts/alert-evidence.sh --sendTest --requireEmailDelivery` passed and the JSON/Markdown reports under `reports/alerts/` were archived outside Git.
- [ ] `sh ./scripts/external-uptime-check.sh --dryRun` passed and provider monitors were created from `monitoring/external-uptime.example.json`.
- [ ] Provider uptime evidence was produced by a dedicated GitHub workflow and its exact SHA256 is covered by a GitHub/Sigstore attestation bound to the expected repository, workflow, commit and ref.
- [ ] `external-uptime-check --providerEvidence ... --providerEvidenceAttestation online --providerEvidenceRepository OWNER/REPO --providerEvidenceWorkflow OWNER/REPO/.github/workflows/provider-evidence.yml --providerEvidenceSourceDigest FULL_GIT_SHA --providerEvidenceSourceRef refs/heads/main --validateProviderEvidenceOnly` passed and wrote `reports/uptime/` with authenticated provider results.
- [ ] The same authenticated evidence arguments passed with `external-uptime-check --envFile .env ... --requireProviderEvidence` plus a direct public probe.
- [ ] `sh ./scripts/functional-health-check.sh` passed and the runtime fingerprint matched a clean deployed commit and every Compose service config hash.
- [ ] `sh ./scripts/failure-tests.sh --confirmServiceStop` passed in staging.
- [ ] The 50/100/500 public load benchmark completed with `status=passed` and authenticated provider evidence bound to its exact URL/request/status/current candidate; origin-controlled response headers were retained only as diagnostics, and `reports/load/` was archived.
- [ ] `sh ./scripts/production-preflight.sh` passed.
- [ ] `sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --dryRun` reviewed.
- [ ] `GITHUB_TOKEN=... sh ./scripts/github-branch-protection.sh --repo OWNER/REPO --branch main --apply` and `--verifyRemote` completed, or equivalent branch protection is proven in GitHub.
- [ ] `sh ./scripts/github-environments.sh --repo OWNER/REPO --dryRun` reviewed.
- [ ] `GITHUB_TOKEN=... sh ./scripts/github-environments.sh --repo OWNER/REPO --apply` and `--verifyRemote` completed; exact reviewer IDs, self-review, wait timer and branch policy match `governance/github-environments.json`.
- [ ] `sh ./scripts/github-actions-config.sh --repo OWNER/REPO` reviewed.
- [ ] `GITHUB_TOKEN=... sh ./scripts/github-actions-config.sh --repo OWNER/REPO --verifyRemote` confirmed `DAST_TARGET`, `DEPLOY_SSH_KEY`, `DEPLOY_REMOTE`, `DEPLOY_REMOTE_DIR`, `DEPLOY_SSH_PORT`, `VPS_HARDENED_SSH_PORT`, `PUBLIC_API_HEALTH_URL`, `CLOUDFLARE_ACCOUNT_ID`, `EXTERNAL_UPTIME_PROVIDER_EVIDENCE_JSON`, `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCESS_ADMIN_MANIFEST_JSON`.
- [ ] `GITHUB_TOKEN=... sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote` passed and `reports/github-actions/` was archived outside Git.
- [ ] `sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO --includeRuntime --includeRestoreDrill --includeOffsiteRestoreDryRun --includeProductionPreflight --verifyGithubRemote` passed with `status=passed` and the JSON/Markdown reports under `reports/go-live/` were archived outside Git.
- [ ] SBOM archived.
- [ ] `gh workflow run release-attestation.yml --repo OWNER/REPO --ref main` completed, and `GITHUB_REF=refs/heads/main sh ./scripts/release-evidence.sh --requireProvenance --repo OWNER/REPO --sourceRef refs/heads/main --imageManifest .tmp/release-attestation/release-subjects.json --sbom reports/release/github-release-sbom-<run-id>.cdx.json --previousImagesFile ./release/previous-images.json` passed with `status=passed`; the gate directly verified signer workflow, commit/ref, issuer, timestamp and every image digest, linked a validated `reports/rollback/rollback-plan-*.json`, and `reports/release/` plus `reports/rollback/` were archived outside Git.
- [ ] Image digests and rollback target recorded.
- [ ] An independent release owner approved a fresh `platform.evidence-trust-envelope/v1` for the exact candidate/report set and pinned its SHA-256 outside the reports tree.
- [ ] `sh ./scripts/production-go-no-go.sh --evidenceTrustEnvelope /secure/approved-evidence-envelope.json --evidenceTrustEnvelopeSha256 <owner-pinned-sha256> --enforce` passed and `reports/go-no-go/` was archived outside Git.
- [ ] If `production-go-no-go` returns `no-go`, every item in the report `remediation` checklist was completed and the gate was rerun until `status=go`.
- [ ] `sh ./scripts/production-readiness-live.sh` passed and `reports/production-readiness/` was archived outside Git.
- [ ] `sh ./scripts/evidence-bundle.sh` generated `.tmp/evidence-bundles/infra-evidence-bundle-*.tar.gz`; `manifest.json` was reviewed and the archive was stored outside Git.
- [ ] A release owner pinned the exact final bundle `manifest.json` SHA-256 outside the bundle and mutable reports tree.
- [ ] `sh ./scripts/evidence-bundle-verify.sh --ownerPinnedManifestSha256 <independently-approved-sha256> --requireComplete` passed against the final evidence bundle.
- [ ] GitHub Actions workflow `enterprise-live-evidence` passed in the `production` environment and its `enterprise-live-evidence` artifact was archived outside Git.

## Admin Surfaces

- [ ] phpMyAdmin not enabled by default.
- [ ] Grafana, Prometheus, Alertmanager, MinIO console, Keycloak Admin and Traefik dashboard are not public.
- [ ] Admin access protected by Cloudflare Access, VPN, SSH tunnel or equivalent MFA-protected path, with `cloudflare-access-admin.sh --verifyRemote` evidence when Cloudflare Access is used.

## Go/No-Go

- [ ] External uptime monitoring delivered a real green check from outside the VPS network and the report contains verified provider evidence.
- [ ] Email alerts delivered to the real recipient.
- [ ] Optional generic forward-webhook channel configured through a secret file and its delivery metric checked, if used.
- [ ] Disaster recovery procedure rehearsed.
- [ ] Deploy audit entry written.
- [ ] `sh ./scripts/platform-admin-audit.sh` output reviewed after the deploy/admin changes.
- [ ] Rollback dry-run plan generated with `sh ./scripts/rollback-release.sh --rollbackFile ./release/previous-images.json`.
- [ ] Production go/no-go status is `go`.

Local/LAN-only Ubuntu evidence is not enough for a final `go`. Domain DNS,
Cloudflare Access/WAF, external uptime provider, public load benchmark,
off-site restore and GitHub/release provenance must be proven against the real
external providers before closing the production gate.
