# Current Operating Model

Last docs alignment: 2026-06-29.

This file records the current non-secret operating model for the prod-like
Ubuntu server. It is intentionally practical: use it to orient deploy,
migration, troubleshooting and go/no-go work. For the full infrastructure map,
read `INFRASTRUCTURE-DEEP-DIVE.md`; for the document map, read
`DOCUMENTATION-INDEX.md`. Refresh the evidence before any real cutover because
container state, reports and provider evidence can change.

## Non-Negotiable Runtime Rules

- Runtime target is Ubuntu LTS with Docker Engine and the Docker Compose plugin.
- macOS and Windows are client machines only: Git, SSH, browser and editor.
- Do not run the platform runtime on Docker Desktop for production-like proof.
- Do not commit `.env`, `reports/`, `.tmp/`, dumps, backup artifacts, secrets or
  generated evidence bundles.
- Do not run `docker compose down -v` on a live or reference server.
- Do not delete Docker volumes, backup directories, secret material or provider
  configuration without a reviewed backup and explicit confirmation.
- Keep hosted application behavior out of platform go/no-go. `control-center/`
  is infrastructure; attached PHP/Node/Static applications are external
  workloads.

## Reference Server Layout

Current reference host access is through the SSH alias used by operators:

```sh
ssh platform-infrastructure
```

Current verified paths:

```text
/home/platform_infrastructure/platform-infrastructure   # infrastructure repo
/home/platform_infrastructure/src                       # external application sources, outside this repo
/srv/platform-nvme                                      # NVMe backing mount
/var/lib/docker                                         # Docker data root on NVMe
```

Storage layout verified on 2026-06-28:

```text
/                         HDD/root filesystem
/srv/platform-nvme         /dev/nvme0n1p1 ext4 rw,noatime
/home/platform_infrastructure -> /srv/platform-nvme/home/platform_infrastructure
/var/lib/docker             -> /srv/platform-nvme/docker
```

The HDD keeps the operating system. Active infrastructure data, project sources
and Docker data live on the NVMe mount. Treat the HDD copy/backups as rollback
material only when explicitly present and verified.

## Live Compose Profile

Current compose project:

```text
platform_infra_vps
```

Current overlay set:

```sh
docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  ps
```

`.tmp/vps-runtime-override.yaml` is a local runtime override, not a portable
tracked baseline. New servers should recreate the same intent through reviewed
environment/override files rather than copying stale absolute paths blindly.

Core platform services currently expected in the reference stack:

```text
alertmanager, backend, cadvisor, control-center, grafana, keycloak, local-dns,
loki, mariadb, minio, nats, node-exporter, phpmyadmin, phppgadmin, postgres,
project-router, prometheus, promtail, redis, traefik, waf, web, worker-jobs,
worker-notifications
```

Attached workload containers can also exist on the reference server, usually as
`php-*` or `node-*`. They are capacity/migration inputs, not platform core and
not public documentation evidence for hosted projects.

Current named volumes:

```text
enterprise_alertmanager_data
enterprise_grafana_data
enterprise_keycloak_data
enterprise_loki_data
enterprise_mariadb_data
enterprise_minio_data
enterprise_nats_data
enterprise_postgres_data
enterprise_prometheus_data
enterprise_redis_data
```

## Public And Internal Surfaces

Expected public browser surfaces for the platform are:

- `https://portal.platform-infrastructure.com`
- `https://docs.platform-infrastructure.com`

The WAF publishes HTTP/HTTPS on the host and forwards safe traffic to internal
Traefik. Traefik routes platform hosts to `control-center` and docs. Databases,
Redis, NATS, MinIO, Prometheus, Loki, Alertmanager, Grafana, phpMyAdmin,
phpPgAdmin and Traefik dashboard must not be public internet surfaces.

`project-router` is an internal routing capability for attached applications.
It is not the Control Center and it is not a public wildcard-router contract by
default. Hosted applications are external to this repository and must not be
counted as platform go-live evidence.

## Control Center Status Semantics

The `Stato` page is an operator surface, not a documentation page. It must show
only platform-infrastructure readiness and direct operator actions.

The `Avvia test reali` button is intentionally read-only. It runs current
platform checks from the Control Center container and stores the latest result
in `projects-portal/state/status-runs.jsonl` or the configured state path.

Current status-run check ids:

```text
portal-through-waf
waf-sensitive-file-block
go-no-go-report-readable
go-no-go-verdict
readiness-matrix-readable
```

Control Center-only tests such as local UI contract, simple/advanced mode,
internal `__health` and static asset checks are intentionally excluded from the
operator Status page. They belong in code tests, not in platform go/no-go.

## Current Go/No-Go State

Current live status as of 2026-06-29:

```text
platform-readiness=go for repo and current Ubuntu runtime evidence
enterprise-requirements=go for repository/tooling coverage
production-go-live=no-go pending external live proofs
statusRun.status=passed
statusRun.summary=4 passed, 0 failed, 0 pending, 1 no-go verdict
visible-status-page=164 checks, 100 OK, 0 to fix, 62 missing proofs
production-go-no-go.status=no-go
production-go-no-go.generatedAt=2026-06-29T01:44:09Z
production-go-no-go.summary=0 failed required checks, 7 required external/provider proofs pending
```

Current required blockers:

| Gate | Status | Why local Ubuntu alone cannot close it |
| --- | --- | --- |
| `pre-go-live-evidence-complete` | `pending-provider` | Needs final evidence options such as production preflight, off-site restore dry-run and GitHub remote verification. |
| `github-actions-run-success` | `pending-provider` | Needs a successful remote `enterprise-infra` GitHub Actions run on the release commit. |
| `disaster-recovery-rpo-rto-offsite` | `pending-provider` | Needs remote/off-site backup repository and restore evidence, not only local backup files. |
| `external-uptime-provider` | `pending-provider` | Needs an external uptime provider checking public hosts from outside the LAN/VPS. |
| `public-load-benchmark` | `pending-provider` | Needs benchmark against final public hosts through the public edge/CDN path. |
| `release-evidence-and-rollback` | `pending-provider` | Needs fresh release evidence, rollback and complete GitHub/Sigstore provenance for the release window. |
| `cloudflare-access-admin-verified` | `pending-provider` | Needs Cloudflare Access configured and verified remotely on the real zone. |

These are not server-local bugs. They are intentionally impossible to mark
`go` using only a private Ubuntu host on a LAN. A new clean server can be
runtime-ready while production remains `NO-GO` until domain, Cloudflare,
GitHub, public monitoring, public benchmark and off-site restore evidence are
real.

## Safe Deploy Commands

Run from the server repo path:

```sh
cd /home/platform_infrastructure/platform-infrastructure

docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  up -d --build
```

For a Control Center-only code/documentation rollout:

```sh
cd /home/platform_infrastructure/platform-infrastructure

docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  up -d --force-recreate control-center
```

Health and status checks:

```sh
docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  ps control-center traefik waf

curl -skS --resolve portal.platform-infrastructure.com:443:127.0.0.1 \
  https://portal.platform-infrastructure.com/control/status
```

## Migration Checklist To A New Server

1. Install Ubuntu LTS on the new host.
2. Verify SSH key access before changing SSH hardening.
3. Run `vps-bootstrap-ubuntu.sh --apply` to install Docker/Git/Compose.
4. Run host readiness in report mode, then enforce only after remediations.
5. Create the NVMe mount plan before copying data.
6. Prepare rollback backups of repo, external application sources and Docker
   volumes before first cutover attempt.
7. Clone/copy `platform-infrastructure` to the final server path.
8. Recreate `.env`, secret files and local runtime override from reviewed
   templates; do not copy stale secret values into Git.
9. Copy application sources into the external application root, outside this
   repo.
10. Start the stack with the same overlay intent and verify `ps`, WAF, Portal,
    docs and Status.
11. Run backup and restore drills before deleting rollback copies.
12. Keep the old server as reference until the new server has clean health,
    current backups, restore evidence and operator sign-off.

## Refresh Evidence

Use these commands to refresh this document before a real migration or go-live:

```sh
docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  config --services

docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  config --volumes

docker compose -p platform_infra_vps \
  -f compose.yaml \
  -f compose.build.yaml \
  -f compose.secrets.yaml \
  -f compose.vps.yaml \
  -f compose.waf.yaml \
  -f compose.vps-waf.yaml \
  -f .tmp/vps-runtime-override.yaml \
  ps

curl -skS --resolve portal.platform-infrastructure.com:443:127.0.0.1 \
  https://portal.platform-infrastructure.com/control/status

for path in /srv/platform-nvme /home/platform_infrastructure /var/lib/docker; do
  findmnt -no SOURCE,TARGET,FSTYPE,OPTIONS "$path"
done
df -h / /srv/platform-nvme /home/platform_infrastructure /var/lib/docker
```
