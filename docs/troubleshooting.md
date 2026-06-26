# Troubleshooting

## Docker and Compose

- Run `docker compose config --quiet` in Linux/CI or a safe local environment.
- Use `docker compose -p platform_infra_local logs -f` for service logs.
- Avoid deleting volumes unless data loss is intended.

## Hostnames

If a hostname returns `404`, it is not routed in the active profile. Check `.env` and the rendered Traefik config.

## mkcert

Browser TLS warnings usually mean the local CA is not trusted.

## WAF 403

Check WAF logs before adding exclusions. Keep exclusions narrow.

## Control Center auth

For non-local environments, verify `CONTROL_CENTER_AUTH_REQUIRED` and `CONTROL_CENTER_ADMIN_PASSWORD_SHA256`.

## GitHub attestation

Attestation verification requires a real Actions run and the correct subject digest.

## Release evidence failed

Check for missing digest-pinned images, missing SBOM, missing rollback target or unsigned provenance.

## Backup/restore failed

Check storage credentials, target container health and available disk space. A backup without restore proof is incomplete.

## External uptime pending

Dry-run manifests are not provider evidence. Configure a real provider monitor and attach fresh status data.
