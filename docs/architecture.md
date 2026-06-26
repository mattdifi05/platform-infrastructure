# Architecture

Platform Infrastructure is single-node-first and production-like by default. It can run locally for development and on a Linux VPS for self-hosting, while keeping live provider proof separate from static repository checks.

## Goals

- Keep the repository infrastructure-only.
- Attach applications externally through manifests, images and evidence.
- Provide an Admin Control Center without embedding application code.
- Make operational readiness measurable through reports and gates.

## Core components

- WAF: OWASP CRS in front of Traefik for request filtering.
- Traefik: reverse proxy and route orchestration.
- Admin Control Center: Node control plane for inventory, docs, topology and evidence.
- project-router: internal project runtime router for PHP and Node metadata flows.
- PostgreSQL: platform and account-style relational storage.
- MariaDB: PHP project database compatibility.
- Redis: sessions, cache and rate-limit support.
- NATS: queue and worker messaging.
- Keycloak: identity provider integration.
- MinIO: S3-compatible object storage.
- Prometheus: metrics store.
- Loki and Promtail: log aggregation.
- Grafana: observability dashboards.
- Alertmanager: alert routing.
- worker-notifications: alert delivery and notification evidence.
- worker-jobs: background job runtime.
- ops runner: containerized execution wrapper for scripts and checks.
- backup scheduler: containerized scheduled backup orchestration.

## Trust boundaries

- Public edge: only explicitly routed hostnames.
- Admin plane: `admin.<domain>`, protected in non-local environments.
- Internal services: databases, storage admin, observability and queues.
- Provider plane: Cloudflare, GitHub and external uptime providers are accessed only by explicit scripts and evidence workflows.
- Evidence plane: generated reports and bundles are ignored by Git and archived outside the repository.

## Public surfaces

The conventional production naming model is:

- `app.<domain>` for the default public app.
- `admin.<domain>` for the Admin Control Center.
- `api.<domain>` for application/API traffic when routed.
- `auth.<domain>` for Keycloak/Auth when routed.
- `storage.<domain>` for MinIO console only when protected.
- `grafana.<domain>` for Grafana only when protected.

Minimal profiles may publish only `admin` and `docs`.

## Data stores

Databases and object storage are stateful Docker volumes. Do not rebuild from scratch with `down -v` unless the goal is data deletion. Backup and restore drills are the authoritative proof of recoverability.

## Evidence flow

Scripts write non-sensitive evidence under `reports/` and bundle final release/deployment evidence under `.tmp/evidence-bundles/`. Both paths are ignored by Git.

## Repository-ready, environment-ready, live-proof

- Repo-ready: static config, tests and gates pass.
- Environment-ready: VPS/bootstrap/hardening/health checks pass in the target environment.
- Live-proof: DNS, TLS, alert delivery, uptime provider, off-site restore and signed release evidence are verified against real services.
