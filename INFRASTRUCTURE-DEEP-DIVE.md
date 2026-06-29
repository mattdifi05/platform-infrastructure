# Platform Infrastructure Deep Dive

Last verified: 2026-06-29.

This document maps the infrastructure repository only. Hosted application code
is intentionally out of scope. `control-center/` is in scope because it is the
infrastructure operator surface.

## Scope Boundary

Included:

- Docker Compose infrastructure and overlays.
- WAF, Traefik, local DNS and edge routing.
- Control Center, docs surface and platform state metadata.
- Project Router as a platform routing capability.
- Generic PHP Apache, Node and Static runtime capability.
- PostgreSQL, MariaDB, Redis, NATS, MinIO and Keycloak.
- Observability stack: Prometheus, node-exporter, cAdvisor, Grafana, Loki,
  Promtail and Alertmanager.
- Backup, restore, disaster recovery, evidence and go/no-go tooling.
- GitHub Actions, release evidence and provider manifests.

Excluded:

- Hosted application source code under the external projects root.
- Hosted application business behavior, login flows and user data semantics.
- Hosted application success as platform production evidence.

The platform may discover or route external projects, but those projects remain
attached workloads. They are not part of this repository's production readiness
unless a check explicitly validates the platform capability itself.

## Naming Contract

Use the names consistently:

- **Infrastructure Portal**: product/operator surface.
- **Control Center**: Node component that serves the Portal, docs and
  `/control/*` APIs.
- **`portal.<domain>`**: host for the Infrastructure Portal.
- **`docs.<domain>`**: host for documentation.
- **Admin identity plane**: platform capability for Control Center operators,
  Cloudflare Access, GitHub/VPS admin review and platform-admin-audit evidence.
  User-facing account/passkey flows belong to hosted applications.
- **`backend`, `web`, `worker-*`**: historical service ids for generic
  platform runtime/template containers. They are not hosted applications.
- **`php-*`, `node-*`, external app names**: attached workload containers when
  present on a specific server. Treat them as migration/capacity inputs, not as
  platform core.

## Architecture Summary

The stack is a single-node, prod-like, self-hosted Docker platform for Ubuntu
LTS. Docker runs only on the server. macOS and Windows are client machines for
Git, SSH, browser testing and editing.

Traffic path for the current VPS/WAF model:

```text
Browser / external checker
  -> Cloudflare or LAN DNS
  -> host port 80
  -> waf
  -> traefik
  -> control-center, docs or project-router
  -> internal services on enterprise_net
```

Data path:

```text
control-center / platform runtime
  -> PostgreSQL, MariaDB, Redis, NATS, MinIO, Keycloak
  -> Prometheus/Loki/Grafana/Alertmanager for evidence and operations
  -> reports/ and .tmp/ for ignored evidence artifacts
```

Current reference server paths:

```text
/home/platform_infrastructure/platform-infrastructure   infrastructure repo
/home/platform_infrastructure/src                       external application sources, outside repo
/srv/platform-nvme                                      active NVMe backing mount
/var/lib/docker                                         Docker data root on NVMe
```

The current reference host keeps the OS on the HDD and active platform data on
NVMe. Do not delete rollback material, Docker volumes, backups or secrets
without a separate approved destructive procedure.

## Compose Files

| File | Role |
| --- | --- |
| `compose.yaml` | Base local prod-like stack, internal network, named volumes, healthchecks, docs/portal Traefik routes. |
| `compose.build.yaml` | Builds historical `backend`, `web` and `worker-*` runtime/template images from local Dockerfiles when their source packages are present. |
| `compose.secrets.yaml` | Switches services to file-based Docker secrets under `/run/secrets/*`. |
| `compose.managed-secrets.yaml` | Same intent as secrets overlay, wired for the proprietary Infra Secret Manager materialized files. |
| `compose.waf.yaml` | Adds local OWASP ModSecurity CRS WAF, owns local HTTP/HTTPS ports, keeps Traefik internal. |
| `compose.vps.yaml` | Single-VPS profile: provider/CDN terminates TLS, Traefik receives HTTP, direct internal ports are reset. |
| `compose.vps-waf.yaml` | VPS WAF edge: WAF owns host HTTP and forwards trusted HTTPS semantics to Traefik. |
| `compose.prod.yaml` | Production image/profile overlay with digest-pinned image requirements and public TLS/ACME posture. |
| `compose.staging.yaml` | Removes fixed container names and renames volumes for isolated staging projects. |
| `compose.backup-scheduler.yaml` | Optional `backup` profile with the Dockerized ops runner as cron-style backup scheduler. |
| `compose.dr.yaml` | DR/PITR helper overlay, including PostgreSQL WAL archive volume. |
| `compose.ha.yaml` | HA readiness overlay for replica-capable services; requires real multi-node/provider design before use. |

Current reference server overlay order:

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

`.tmp/vps-runtime-override.yaml` is deployment-local evidence, not a portable
baseline. Recreate its intent on a new host after reviewing paths and mounts.

## Service Catalogue

The current reference server may show additional dedicated workload containers
such as `php-*` or `node-*` for attached applications. Those containers are
runtime attachments. They matter for capacity and migration planning, but they
are excluded from this infrastructure deep dive unless the question is about the
platform's ability to host them.

| Service | Layer | Role | Public by default | Persistent state |
| --- | --- | --- | --- | --- |
| `waf` | edge | OWASP CRS reverse proxy in front of Traefik. | Host HTTP/HTTPS depending on overlay. | No named volume. |
| `traefik` | edge | File-provider reverse proxy, no Docker socket. | Only through host/WAF entrypoints. | Dynamic route config only. |
| `control-center` | control plane | Infrastructure portal, docs renderer, readiness/status, metadata actions. | `portal.<domain>` and `docs.<domain>` through Traefik. | `projects-portal/state/*` bind mount. |
| `project-router` | hosting capability | Routes attached external PHP/Node/Static projects to dedicated upstreams. | Only via project routes when configured. | Reads project state/source metadata. |
| `php-apache` | hosting capability | Generic PHP Apache runtime for external PHP projects. | No direct public route by default. | External project source bind mount. |
| `backend` | generic runtime | Historical service id for a platform API/runtime template. Not a hosted app and not account proof. | Disabled Traefik labels by default. | PostgreSQL/Redis/NATS/MinIO. |
| `web` | generic runtime | Historical service id for a generic web/Next.js runtime template. Not a hosted app. | Disabled Traefik labels by default. | No named volume. |
| `worker-notifications` | worker | Platform notification worker for alerts and provider channels. | No. | PostgreSQL/Redis/NATS. |
| `worker-jobs` | worker | Platform background worker and audit outbox dispatcher. | No. | PostgreSQL/Redis/NATS/MinIO. |
| `postgres` | data | PostgreSQL managed by the platform for internal metadata, Keycloak DB and explicitly attached workload databases. | No. | `enterprise_postgres_data`. |
| `mariadb` | data | MariaDB for attached PHP workloads and phpMyAdmin. | No. | `enterprise_mariadb_data`. |
| `redis` | data/cache | Rate limits, cache/runtime state, worker heartbeat and optional attached workload use. | No. | `enterprise_redis_data`. |
| `nats` | messaging | NATS JetStream event bus. | No. | `enterprise_nats_data`. |
| `minio` | object storage | S3-compatible object storage. | No. | `enterprise_minio_data`. |
| `keycloak` | identity | Prepared OIDC/identity provider. | No public route in platform default/VPS. | `enterprise_keycloak_data`. |
| `prometheus` | observability | Metrics scrape and rules. | No. | `enterprise_prometheus_data`. |
| `node-exporter` | observability | Host metrics from read-only host mount. | No. | None. |
| `cadvisor` | observability | Container metrics from read-only Docker mounts. | No. | None. |
| `grafana` | observability | Metrics/log dashboards. | No public route unless explicitly protected. | `enterprise_grafana_data`. |
| `loki` | observability | Log storage and rule engine. | No. | `enterprise_loki_data`. |
| `promtail` | observability | Docker log collector with redaction pipeline. | No. | Reads Docker logs. |
| `alertmanager` | observability | Alert routing to notification worker. | No. | `enterprise_alertmanager_data`. |
| `phpmyadmin` | admin profile | MariaDB admin UI, enabled only with `admin` profile. | No durable public surface. | No named volume. |
| `phppgadmin` | admin profile | PostgreSQL admin UI, enabled only with `admin` profile. | No durable public surface. | No named volume. |
| `local-dns` | dns profile | CoreDNS for local wildcard resolution. | Internal/LAN only when enabled. | No named volume. |
| `backup-scheduler` | backup profile | Dockerized ops runner for scheduled backups/drills. | No. | Writes ignored reports/backups. |

## Network, Volumes And State

Network:

```text
enterprise_net
```

The network is external in `compose.yaml`. Create it before rendering/running
the base stack if Docker does not already have it:

```sh
docker network create enterprise_net
```

Named volumes:

```text
enterprise_mariadb_data
enterprise_postgres_data
enterprise_redis_data
enterprise_keycloak_data
enterprise_nats_data
enterprise_minio_data
enterprise_alertmanager_data
enterprise_grafana_data
enterprise_prometheus_data
enterprise_loki_data
enterprise_postgres_wal_archive
```

Important bind mounts:

- repo root mounted read-only into Control Center docs.
- `control-center/` mounted read-only into the Control Center container.
- `project-router/` mounted read-only into the Project Router container.
- external projects root mounted under `/var/www/projects`.
- `projects-portal/state/` mounted read/write for Control Center metadata.
- `/var/lib/docker/containers` read-only into Promtail.
- host root, Docker state and cgroups read-only into node-exporter/cAdvisor.

Do not remove volumes with `docker compose down -v` on a live/reference/VPS
server.

## Secrets

Secret values are out of scope for documentation. Only names and mount paths
should be documented.

Declared Docker secret names:

```text
postgres_superuser_password
app_db_password
keycloak_db_password
redis_password
keycloak_admin_password
nats_password
minio_root_password
mariadb_root_password
phpmyadmin_control_password
grafana_admin_password
session_secret
session_signing_keys
projects_gateway_signing_keys
hash_pepper_keys
backup_signing_keys
alertmanager_webhook_token
smtp_password
cloudflare_turnstile_secret_key
database_url
nats_url
```

Rules:

- runtime code consumes secrets through `*_FILE` env vars or `/run/secrets/*`;
- `.env`, `secrets/*.txt`, encrypted stores, backups and reports stay out of
  Git;
- `infra-secret-manager` may initialize, verify, rotate and materialize secret
  files, but documentation must never print secret values;
- production go/no-go requires fresh non-secret `secret-rotation-evidence`.

## Edge, WAF And DNS

Default local base:

- Traefik binds `127.0.0.1:80` and `127.0.0.1:443`.
- Traefik serves `portal.localhost.com` and `docs.localhost.com`.
- Databases, observability internals and admin consoles remain private.

Local WAF overlay:

- `compose.waf.yaml` removes Traefik host ports.
- `waf` binds local host HTTP/HTTPS and forwards to Traefik.
- OWASP CRS rules live under `waf/`.

VPS WAF overlay:

- provider/CDN owns public HTTPS;
- `waf` binds host HTTP and forwards to Traefik;
- Traefik uses `traefik.edge-http.yml`;
- `enterprise-edge-forwarded-https` tells upstream services the request is
  effectively HTTPS.

Current deployment-specific files:

- `dns/Corefile` and `dns/db.platform-infrastructure.com` provide local wildcard
  CoreDNS for `platform-infrastructure.com` on the LAN.
- `traefik/dynamic/admin-routes.yml` exposes admin DB UI routes for local/admin
  work.
- `traefik/dynamic/project-routes.yml` exposes wildcard project routing to
  `project-router`.

Treat those files as current deployment configuration. They are not proof that
public DNS, Cloudflare Access or Cloudflare WAF are complete.

## Control Center

`control-center/` is infrastructure code. It is a Docker-first Node service with
no npm runtime dependencies beyond Node itself.

Primary responsibilities:

- render the operator Portal and docs;
- expose `/control/*` JSON APIs;
- keep local metadata for Applications, domains, databases, storage, workers,
  deployments, backups, resources, security policies and provider connections;
- run read-only Status checks from the Control Center container;
- present production go/no-go evidence without changing providers;
- record audit and operation JSONL entries;
- broker admin database UI entrypoints without exposing secret values in docs.

Important state files:

```text
projects-portal/state/projects.json
projects-portal/state/applications.json
projects-portal/state/domains.json
projects-portal/state/databases.json
projects-portal/state/storage-buckets.json
projects-portal/state/resource-limits.json
projects-portal/state/security-policies.json
projects-portal/state/provider-connections.json
projects-portal/state/audit.jsonl
projects-portal/state/operations.jsonl
projects-portal/state/status-runs.jsonl
```

The Status action `/actions/status-check` is intentionally read-only. Current
platform check ids are:

```text
portal-through-waf
waf-sensitive-file-block
go-no-go-report-readable
go-no-go-verdict
readiness-matrix-readable
```

Control Center-only UI checks and hosted-application checks belong in tests or
project-specific validation, not platform go/no-go.

## Project Router And Runtime Capability

`project-router` is infrastructure because it routes attached applications. It
does not make the applications part of this repository.

Supported attached runtime types:

- `php`;
- `node`;
- `static`.

Discovery inputs:

- external projects root (`PROJECTS_ROOT` / `PHP_PROJECTS_DIR`);
- `.platform/project.json` or `platform.project.json` inside an attached
  project;
- `PROJECT_UPSTREAMS`, `PHP_PROJECT_UPSTREAMS`, `NODE_PROJECT_UPSTREAMS`,
  `STATIC_PROJECT_UPSTREAMS`;
- `NODE_PROJECT_HOSTS` and `PROJECT_HOST_SUFFIX`.

Rules:

- new project sources stay outside this repo;
- dedicated upstreams are required for Node/Static and for dedicated PHP app
  routing;
- shared runtime shortcuts are not production isolation proof;
- app databases/storage may be shown in Control Center metadata, but app data is
  not platform readiness evidence.

## Backup, Restore And DR

Backup families:

- PostgreSQL;
- MariaDB;
- MinIO;
- Keycloak configuration;
- Secret Manager metadata.

Important commands:

```sh
sh ./scripts/backup-postgres.sh
sh ./scripts/backup-mariadb.sh
sh ./scripts/backup-minio.sh
sh ./scripts/backup-keycloak.sh
sh ./scripts/backup-secret-manager-metadata.sh
sh ./scripts/full-restore-drill.sh
sh ./scripts/dr-evidence.sh --enforce
```

Production DR is not proven by local backup files alone. The go/no-go gate
requires remote/off-site restore evidence with full-family coverage.

## Readiness And Go/No-Go

Machine-readable policy:

- `governance/production-go-no-go.json`;
- `governance/production-readiness.json`;
- `governance/enterprise-requirements.json`.

Current required live/provider blockers:

```text
Platform readiness: GO for repository and current Ubuntu runtime evidence
Enterprise requirements: GO for repository/tooling coverage
Production go-live: NO-GO pending external live proofs
pre-go-live-evidence-complete
github-actions-run-success
disaster-recovery-rpo-rto-offsite
external-uptime-provider
public-load-benchmark
release-evidence-and-rollback
cloudflare-access-admin-verified
```

These blockers require real external evidence. A LAN-only Ubuntu server can be
healthy and migration-ready while production remains `NO-GO`.

Core commands:

```sh
sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO --includeRuntime
sh ./scripts/production-go-no-go.sh
sh ./scripts/production-go-no-go.sh --enforce
sh ./scripts/production-readiness-live.sh
sh ./scripts/evidence-bundle.sh
sh ./scripts/evidence-bundle-verify.sh --requireComplete
```

## GitHub Actions And Release Evidence

Workflow files:

```text
.github/workflows/enterprise-infra.yml
.github/workflows/enterprise-infra-run-evidence.yml
.github/workflows/enterprise-live-evidence.yml
.github/workflows/enterprise-vps-evidence.yml
.github/workflows/release-attestation.yml
```

The main workflow validates shell syntax, Control Center tests, Project Router
tests, Compose renders, healthcheck coverage, secret scan, static security,
release artifact dry-run, governance dry-runs, production go/no-go summary,
enterprise readiness and repository coverage.

Production release evidence requires real registry image digests, rollback
targets and GitHub/Sigstore provenance. Dry-run CI evidence is useful but does
not close the live production gate.

## Safe Deploy Commands

Reference server path:

```sh
cd /home/platform_infrastructure/platform-infrastructure
```

Full current reference stack:

```sh
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

Control Center-only rollout:

```sh
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

Read-only status checks:

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

curl -skS --resolve portal.platform-infrastructure.com:443:127.0.0.1 \
  https://portal.platform-infrastructure.com/control/status
```

Never use `docker compose down -v` as a troubleshooting shortcut.

## New Server Migration Checklist

1. Install Ubuntu LTS.
2. Verify SSH key access.
3. Run `vps-bootstrap-ubuntu.sh --apply`.
4. Run `vps-hardening-ubuntu.sh` only after SSH rollback access is confirmed.
5. Run `vps-host-readiness.sh --enforce`.
6. Prepare NVMe mount and Docker data-root plan.
7. Back up repo, state, external app sources, Docker volumes and secrets.
8. Copy/clone infrastructure repo to the final server path.
9. Recreate `.env`, Docker secrets and local runtime overrides from reviewed
   templates.
10. Start the stack with the reviewed VPS/WAF overlay order.
11. Verify WAF, Traefik, Portal, docs, Status API, observability and backups.
12. Run restore drills before deleting rollback copies.
13. Keep the old server as reference until the new server has current evidence
   and operator sign-off.

## Main Risks

- Treating hosted project checks as platform production evidence.
- Copying stale `.tmp` overrides or secrets to a new server without review.
- Exposing DB/admin/observability surfaces publicly.
- Deleting rollback data before restore evidence is current.
- Marking provider/live proof as `go` from a LAN-only host.
- Using shared runtime shortcuts as if they were dedicated production isolation.
- Depending on untracked deployment-specific DNS/Traefik files without making a
  reviewed migration plan.
