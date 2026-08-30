# Enterprise Production Readiness Plan

This is the Codex 8-point plan for moving from a hardened Docker deployment to
an enterprise-grade production posture. The target is an enforceable checklist:
every item must map to a file, command, policy or recurring drill.

## 1. HA multi-node production

- Use `compose.ha.yaml` with `compose.prod.yaml` for stateless service replicas.
- Keep stateless platform services behind healthchecked load balancing and
  rolling updates; hosted workload HA is declared by each external contract.
- Stateful services must run on a managed or clustered tier before public
  high-availability claims are made.
- Gate: `sh scripts/infra-ops.sh ha-config-check`.

## 2. Managed secrets and KMS

- Production can use `infra-secret-manager` as the proprietary integrated
  manager for single-node Docker, materializing external Docker secrets from an
  encrypted audited store.
- Multi-node/high-compliance deployments may swap the materialization backend
  to a provider KMS while preserving the same `*_FILE` contract.
- Raw Control Center application-auth, application identity-provider, provider
  and backup signing secrets must not be
  required in `.env` for production.
- Rotation uses active plus previous key rings, then removes previous keys after the
  observation window.
- Gate: `sh scripts/infra-ops.sh managed-secrets-preflight`.

## 3. Supply chain enforcement

- Images must be immutable digest references.
- SBOM must be archived per release.
- Images must be signed with cosign and accompanied by provenance attestation.
- Admission must reject unsigned, mutable or provenance-missing workloads.
- Gate: `sh scripts/infra-ops.sh release-artifact-gate`.

## 4. DR, PITR and RPO/RTO

- `compose.dr.yaml` enables PostgreSQL WAL archiving.
- Dumps and WAL archives must be encrypted and shipped off-site.
- Restore drills must run on a schedule and record success in
  `platform_ops.backup_restore_runs`.
- RPO/RTO targets are declared in this plan and checked by gate.
- Gate: `sh scripts/infra-ops.sh dr-readiness-check`.

Declared targets:

- RPO: 15 minutes maximum data loss for declared platform state.
- RTO: 60 minutes to restore the platform data services required by the catalog.
- Restore drill cadence: weekly minimum.

## 5. Security test matrix

- Cover Control Center CSRF/origin policy, WebAuthn verification, session
  revocation, WAF, secret boundaries and privilege blocks. Application
  auth flows remain workload-owned.
- Gate: `sh scripts/infra-ops.sh security-matrix`.

## 6. Load and chaos

- Keep smoke load in the default enterprise gate.
- Run opt-in destructive chaos against staging only: Redis unavailable,
  PostgreSQL interruption/failover, NATS unavailable and MinIO unavailable.
- Measure p95 and p99 against published SLO budgets.
- Gate: `sh scripts/infra-ops.sh chaos-profile --confirmChaos`.

## 7. Cross-browser UX

- Browser coverage must include Chromium, Firefox and WebKit for Portal, docs
  and platform security surfaces, plus mobile viewport coverage.
- Visual snapshots stay restricted to stable Chromium projects.
- Gate: `sh scripts/infra-ops.sh browser-e2e-tests`.

## 8. Governance

- Required checks must block protected branches.
- Releases require approval, signed artifacts, SBOM archive and rollback plan.
- Deploys must leave an audit trail.
- Gate: `sh scripts/infra-ops.sh governance-check`.
