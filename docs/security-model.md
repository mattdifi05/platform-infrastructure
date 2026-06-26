# Security Model

## Baseline

- Admin surfaces are gated and should not be public without protection.
- Secrets are managed through Docker secrets or secret manager material.
- WAF rules run before application traffic.
- Rate limiting is applied at the edge where configured.
- Logs are redacted.
- Backups can be signed/encrypted and verified.
- Supply-chain checks require digest-pinned images and SBOM/provenance.

## Sessions and auth

Local development can be relaxed. Staging and VPS profiles should require Admin Control Center auth and secure cookies.

## Secrets

Never commit:

- `.env`
- `secrets/*.txt`
- provider tokens
- backups
- dumps
- generated evidence reports

## Admin surfaces

Database consoles, storage consoles, Grafana, Prometheus, Alertmanager and Traefik dashboards should remain internal or protected by MFA/VPN/Access.

## Disclosure

See [Security Baseline](../SECURITY.md) for reporting and supported security expectations.
