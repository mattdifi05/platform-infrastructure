# Threat Model

## Scope

This threat model covers the infrastructure repository, local/VPS runtime, Admin Control Center, evidence generation, provider integration points and attached external application manifests.

Application source repositories have their own threat models.

## Assets

- Docker secret files and external secret references.
- Session signing keys and admin credentials.
- PostgreSQL and MariaDB data.
- Redis, NATS and MinIO data.
- Keycloak realm configuration.
- Backup archives and restore material.
- Release image digests, SBOMs and provenance.
- Provider tokens and remote configuration.
- Evidence reports and go/no-go decisions.

## Trust boundaries

- Browser to WAF/Traefik.
- Public app/API surfaces to internal services.
- Admin Control Center to internal metadata and ops plans.
- Docker network to databases, queues and storage.
- Ops runner to Docker socket and provider APIs.
- GitHub Actions to GHCR, attestations and artifacts.
- Off-site backup provider to restore drills.

## Primary threats

- Secret leakage through Git, logs, reports or artifacts.
- Accidental public exposure of admin/database surfaces.
- Session theft or privilege escalation.
- WAF bypass or unsafe WAF exclusion.
- Supply-chain substitution through mutable images.
- Missing rollback target during deployment failure.
- Backup corruption or untested restore.
- Provider drift between intended state and live state.
- False production readiness claims based on dry-run evidence.

## Mitigations

- `.gitignore` excludes `.env`, secrets, reports, backups and bundles.
- Docker secrets and `*_FILE` conventions keep secret values out of configs.
- Admin surfaces are internal or protected by explicit access controls.
- WAF, rate limit and security headers protect routed HTTP surfaces.
- Images should be digest-pinned.
- SBOM and GitHub/Sigstore attestations support release verification.
- Restore drills and off-site restore evidence prove recoverability.
- External uptime and alert evidence prove live monitoring.
- Production go/no-go fails when required evidence is missing.

## Accepted local risks

- Local development may use relaxed auth.
- Local TLS may rely on mkcert or browser trust overrides.
- Some services may exist as containers while not being publicly routed.
- Dry-run evidence is acceptable for development but not for production approval.

## Production non-negotiables

- No public database, queue, storage admin or observability admin surface without an access layer.
- Real DNS and TLS for public surfaces.
- Firewall and host hardening.
- External uptime provider evidence.
- Real alert delivery evidence.
- Off-site backup and restore evidence.
- Signed release evidence for production release subjects.
