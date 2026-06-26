# Cloudflare

Cloudflare is optional. Local development does not require Cloudflare.

## Supported concerns

- DNS.
- CDN.
- WAF.
- Access applications for admin surfaces.
- Origin lock.
- Optional Cloudflare Tunnel if the environment chooses it.

## Dry-run vs apply

Dry-run scripts produce plans and evidence files without changing Cloudflare. Apply scripts require tokens, explicit confirmation and remote verification.

## Access

Cloudflare Access can protect admin surfaces such as Grafana, storage console or the Admin Control Center. Access policies should require an identity provider with MFA.

## Origin lock

Origin lock should restrict direct origin access when Cloudflare is the production edge.

## Evidence

Provider evidence should include remote IDs, policy status, timestamps and verification result. Do not store tokens in evidence.
