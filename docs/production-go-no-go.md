# Production Go/No-Go

`production-go-no-go` is a hard gate. It should block production when evidence is missing or stale.

## Readiness levels

- Repo-ready: static checks pass.
- Environment-ready: target host passes bootstrap, hardening and health.
- Live-proof: external systems prove the deployment is reachable, monitored, recoverable and auditable.

## Required evidence

- VPS bootstrap.
- Host hardening.
- Host readiness.
- Cloudflare Access verify if Cloudflare is used.
- GitHub Actions run evidence.
- Secret rotation evidence.
- DR/off-site restore evidence.
- Real alert delivery.
- External uptime provider evidence.
- Public load benchmark.
- GitHub/Sigstore release evidence.
- Pre-go-live evidence.
- Evidence bundle.

## Home VPS note

A LAN/home VPS can be production-like, but it is not production-go until public DNS/TLS, monitoring, alerts, off-site backup and release evidence are verified.

## Remediation

Treat no-go as a stop. Fix the missing evidence, rerun the relevant scripts and regenerate the evidence bundle.
