# Stexor Threat Model

## Assets

- Account profile and recovery data.
- Passkey public credentials and counters.
- PostgreSQL application data.
- SMTP credentials and OTP delivery.
- MinIO objects.
- Observability logs and metrics.

## Trust boundaries

- Browser to Traefik over HTTPS.
- Traefik to internal services on `enterprise_net`.
- Backend to PostgreSQL/Redis/NATS/MinIO.
- SMTP provider outside the infrastructure boundary.

## Primary threats

- Session theft: mitigated by `HttpOnly`, `Secure`, signed cookies and server-side session state.
- CSRF on mutating endpoints: mitigated by Origin checks and JSON APIs.
- Account enumeration: UI should keep generic error copy; backend should continue avoiding detailed public errors.
- Secret leakage: `.env` ignored; production should move to secret manager.
- Backup compromise: backups must be encrypted before offsite storage.
- Supply-chain drift: CI must run lockfile install, typecheck, build, audit and image scanning.

## Accepted local-development risks

- Local direct ports are bound to `127.0.0.1` for development convenience.
- `.env` exists locally and must not be copied to shared systems.
- The custom account layer is active while Keycloak remains prepared for OIDC hardening.

## Production non-negotiables

- Public exposure limited to Traefik `80/443`.
- No public PostgreSQL, Redis, NATS, Prometheus, Loki, MinIO admin or Traefik dashboard.
- Real DNS and Let's Encrypt certificates.
- Firewall denies everything except required ingress.
- Backup restore test before go-live.
