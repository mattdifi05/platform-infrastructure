# Rollout Plan

## Universal pre-change gate

Before every live restart, recreate, migration, credential change, network change or mount change:

1. resolve exact application, runtime, image, DB, principal, volume, network, secret and dependency IDs from APPLICATION_RUNTIME_MAP.md;
2. record functional pre-state, DB connectivity, jobs, logs, metrics, disk and memory;
3. create and verify a fresh resource-specific local and off-site backup;
4. record commit, effective Compose hash, image digest, inspect subset, migration version and backup manifest;
5. define success, abort, timeout and rollback;
6. apply one atomic change;
7. run route, TLS, assets, auth, controlled DB read/write, job, storage, log and metric checks;
8. abort and roll back on the first failed application or data invariant.

## Waves

- Wave A: T00, T11 and baseline HA documentation.
- Wave B: T01-T03 administrative security.
- Wave C: T04-T08 data, backup and restore.
- Wave D: T09-T10 observability.
- Wave E: T12-T15 isolation and immutable builds.
- Wave F: T16-T17 release trust and public edge.
- Wave G: T18-T20 ownership, Control Center and frontend.
- Wave H: T21-T22 host/governance.
- Wave I: T23 production-candidate verification.

## Live rollout strategy

Prefer per-service or per-application sequential recreate, immutable image digests and immediate functional smoke. Never use `docker compose down -v`. Never prune volumes. Database migrations use dual credentials and keep the previous credential valid until post-change verification.

## Control Center authentication rollout gate

Do not recreate the live Control Center until the dedicated control-plane
database has the application-owned passkey schema and its current passkey and
session rows are backed up. Build from protected main, recreate only the
Control Center, then prove anonymous denial, exact host/origin enforcement,
one-passkey login, fresh-owner gating, logout revocation and one-day expiry.
Keycloak is outside this login path and must not be mutated by the rollout.
