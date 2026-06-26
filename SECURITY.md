# Security Baseline

## Vulnerability disclosure

Report suspected vulnerabilities privately to the project owner or configured production security contact. Do not open public issues with exploit details, credentials, personal data or live target output.

Every accepted report should receive:

- acknowledgement
- severity triage
- remediation owner
- fix or mitigation plan
- follow-up evidence after deployment

## Security posture

Platform Infrastructure assumes:

- applications are external to this repository
- secrets are never committed
- admin surfaces are protected
- databases and internal consoles are not public
- production claims require live evidence

## Authentication and sessions

- Admin Control Center auth should be enabled outside local quickstart.
- Session cookies should be `HttpOnly`, `Secure` and `SameSite=Lax`.
- Session signing material must come from Docker secrets or a stronger external secret system.
- Mutating APIs should reject untrusted origins and hostile Fetch Metadata.

## Roles

Use least privilege for all admin and operator access. Common role names are:

- `owner`
- `admin`
- `developer`
- `billing`
- `viewer`

Never trust roles supplied by the browser.

## Secrets

Never commit:

- `.env`
- `secrets/*.txt`
- provider tokens
- API keys
- database dumps
- backups
- generated reports
- generated SBOMs
- evidence bundles

Runtime code should consume secret material through `*_FILE` references, Docker secrets or approved external secret managers.

## Admin surfaces

The Admin Control Center uses `admin.<domain>`. It is not a public app surface.

Keep these internal or behind MFA/VPN/Access:

- PostgreSQL
- MariaDB
- Redis
- NATS
- MinIO console
- Grafana
- Prometheus
- Alertmanager
- Traefik dashboard
- phpMyAdmin

## Required recurring checks

- `sh ./scripts/infra-health.sh`
- `sh ./scripts/security-smoke.sh`
- `sh ./scripts/waf-smoke.sh`
- `sh ./scripts/secret-scan.sh`
- `sh ./scripts/infra-secret-manager.sh verify`
- `sh ./scripts/supply-chain-hygiene.sh`
- `sh ./scripts/generate-sbom.sh`
- `sh ./scripts/production-preflight.sh`
- `sh ./scripts/load-smoke.sh`
- `sh ./scripts/access-review.sh`
- backup and restore drills
- certificate expiry checks
- release evidence verification

## More detail

- [Security Model](docs/security-model.md)
- [Threat Model](THREAT-MODEL.md)
- [Production Go/No-Go](docs/production-go-no-go.md)
