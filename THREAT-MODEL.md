# Platform Threat Model

## Assets

- Control Center admin metadata, provider metadata and operation audit records.
- PostgreSQL/MariaDB service data and explicitly attached workload data.
- SMTP/provider credentials for infrastructure alerts.
- MinIO objects.
- Observability logs and metrics.

## Trust boundaries

- Browser to Traefik over HTTPS.
- Traefik to internal services on `enterprise_net`.
- Platform runtime templates and hosted workloads to PostgreSQL/Redis/NATS/MinIO.
- SMTP provider outside the infrastructure boundary.

## Primary threats

- Admin session theft: mitigated by `HttpOnly`, `Secure`, signed cookies and server-side session state.
- CSRF on Control Center mutating endpoints: mitigated by Origin checks and JSON APIs.
- Hosted workload enumeration: app-specific public auth flows are outside the infra gate and must be tested by the hosted app.
- Secret leakage: `.env` ignored; production should move to secret manager.
- Backup compromise: backups must be encrypted before offsite storage.
- Supply-chain drift: CI must run lockfile install, typecheck, build, audit and image scanning.

## Accepted local-development risks

- Local direct ports are bound to `127.0.0.1` for development convenience.
- `.env` exists locally and must not be copied to shared systems.
- Hosted workload compatibility paths may exist locally but are not platform go-live gates.

## Production non-negotiables

- Public exposure limited to Traefik `80/443`.
- No public PostgreSQL, Redis, NATS, Prometheus, Loki, MinIO admin or Traefik dashboard.
- Real DNS and Let's Encrypt certificates.
- Firewall denies everything except required ingress.
- Backup restore test before go-live.
