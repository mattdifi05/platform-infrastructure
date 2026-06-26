# Threat Model

This summary complements the root [Threat Model](../THREAT-MODEL.md).

## Assets

- Secrets and signing keys.
- Databases and object storage.
- Admin Control Center sessions.
- Release artifacts and provenance.
- Backup archives.
- Provider API access.

## Trust boundaries

- Public edge.
- Admin control plane.
- Internal Docker network.
- Provider APIs.
- Evidence/report storage.

## Main threats

- Secret leakage.
- Public exposure of admin/database tools.
- Supply-chain substitution.
- Backup failure or untested restore.
- WAF bypass or false positive operational outage.
- Provider drift between intended and live state.

## Mitigations

- Docker secrets and ignored local secret files.
- WAF and rate limiting.
- Digest-pinned images and SBOMs.
- GitHub/Sigstore attestations.
- Restore drills and off-site evidence.
- External uptime and alert delivery verification.

## Accepted local risks

Local development may use relaxed auth and local-only TLS. Production must not.
