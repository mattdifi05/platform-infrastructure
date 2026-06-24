# Enterprise Production Readiness Plan

This is the Codex 8-point plan for moving from a hardened Docker deployment to
an enterprise-grade production posture. The target is an enforceable checklist:
every item must map to a file, command, policy or recurring drill.

## 1. HA multi-node production

- Use `compose.ha.yaml` with `compose.prod.yaml` for stateless service replicas.
- Keep `backend`, `web`, `worker-notifications` and `worker-jobs` behind
  healthchecked load balancing and rolling updates.
- Stateful services must run on a managed or clustered tier before public
  high-availability claims are made.
- Gate: `sh scripts/stexor-ops.sh ha-config-check`.

## 2. Managed secrets and KMS

- Production can use `stexor-secret-manager` as the proprietary integrated
  manager for single-node Docker, materializing external Docker secrets from an
  encrypted audited store.
- Multi-node/high-compliance deployments may swap the materialization backend
  to a provider KMS while preserving the same `*_FILE` contract.
- Raw `SESSION_SECRET`, `SECRET_HASH_KEYS` and `BACKUP_SIGNING_KEYS` values
  must not be required in `.env` for production.
- Rotation uses active plus previous key rings, then removes previous keys after the
  observation window.
- Gate: `sh scripts/stexor-ops.sh managed-secrets-preflight`.

## 3. Supply chain enforcement

- Images must be immutable digest references.
- SBOM must be archived per release.
- Images must be signed with cosign and accompanied by provenance attestation.
- Admission must reject unsigned, mutable or provenance-missing workloads.
- Gate: `sh scripts/stexor-ops.sh release-artifact-gate`.

## 4. DR, PITR and RPO/RTO

- `compose.dr.yaml` enables PostgreSQL WAL archiving.
- Dumps and WAL archives must be encrypted and shipped off-site.
- Restore drills must run on a schedule and record success in
  `stexor_platform.backup_restore_runs`.
- RPO/RTO targets are declared in this plan and checked by gate.
- Gate: `sh scripts/stexor-ops.sh dr-readiness-check`.

Declared targets:

- RPO: 15 minutes maximum data loss for account database.
- RTO: 60 minutes to restore account database service.
- Restore drill cadence: weekly minimum.

## 5. Security test matrix

- Cover CSRF, CORS, CSP, recovery brute force, passkey requested-account
  isolation, backup code single-use, session revocation and privilege blocks.
- Gate: `sh scripts/stexor-ops.sh security-matrix`.

## 6. Load and chaos

- Keep smoke load in the default enterprise gate.
- Run opt-in destructive chaos against staging only: Redis unavailable,
  PostgreSQL interruption/failover, NATS unavailable and MinIO unavailable.
- Measure p95 and p99 against published SLO budgets.
- Gate: `sh scripts/stexor-ops.sh chaos-profile --confirmChaos`.

## 7. Cross-browser UX

- Browser coverage must include Chromium, Firefox and WebKit for public and
  security surfaces, plus mobile viewport coverage.
- Visual snapshots stay restricted to stable Chromium projects.
- Gate: `pnpm test:e2e`.

## 8. Governance

- Required checks must block protected branches.
- Releases require approval, signed artifacts, SBOM archive and rollback plan.
- Deploys must leave an audit trail.
- Gate: `sh scripts/stexor-ops.sh governance-check`.
