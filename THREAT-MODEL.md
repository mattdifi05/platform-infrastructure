# Platform Threat Model

## Assets

- Control Center admin metadata, provider metadata and operation audit records.
- PostgreSQL/MariaDB service data and explicitly attached workload data.
- SMTP/provider credentials for infrastructure alerts.
- MinIO objects.
- Observability logs and metrics.

## Trust boundaries

- Browser to Traefik over HTTPS.
- Traefik to platform routing and per-app ingress trust zones.
- Hosted workloads to only their dedicated ingress/data/egress networks.
- Backup scheduler to the Docker API proxy on an internal control network.
- Host ops runner to the same proxy through a loopback-only endpoint.
- SMTP provider outside the infrastructure boundary.

## Primary threats

- Admin session theft: mitigated by `HttpOnly`, `Secure`, signed cookies and server-side session state.
- CSRF on Control Center mutating endpoints: mitigated by Origin checks and JSON APIs.
- Hosted workload enumeration: app-specific public auth flows are outside the infra gate and must be tested by the hosted app.
- Secret leakage: `.env` ignored; production should move to secret manager.
- Backup compromise: backups must be encrypted before offsite storage.
- Supply-chain drift: CI must run lockfile install, typecheck, build, audit and image scanning.
- Hosted workload escape: exact read-only source mounts, read-only rootfs,
  per-app networks and no raw Docker socket constrain host and cross-app access.
- Node exhaustion: cgroup memory/CPU/PID/FD/I/O controls and higher control-plane
  CPU shares contain workload stress.

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
- Runtime-isolation policy, hosted startup sandbox and bounded cgroup stress
  must pass before recreating any hosted workload.
