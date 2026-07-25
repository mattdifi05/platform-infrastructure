# Governance Runbooks

Status: `LOCAL-SUPPORT-READY-EXTERNAL-PENDING`.

These are the versioned repository-side procedures bound by
`governance/runbook-catalog.json`. They specify safe ordering, preservation,
rollback, and evidence boundaries. They do not prove execution. Synthetic
fixtures exercise only the validator and are never gate-admissible.

For each required drill, an independent operator must use the exact catalog
hash and bound artifact bytes, preserve the prior state, verify rollback,
record authenticated evidence without secret values, and remain distinct from
accepted accountability subjects. That verification is
`GOVERNANCE-EXTERNAL` and GO-blocking.

## Operations

Catalog anchor: runbook:operations

1. Identify the exact repository commit, deployment identifier, host scope, and
   requested maintenance boundary.
2. Begin with the read-only checks in `RUNBOOK.md` under
   `Current reference server quick checks`; do not expand into provider or live
   mutation without separate authorization.
3. Preserve the exact configuration, state identifiers, and current evidence
   before any approved mutation.
4. Change only the approved component, verify its health and dependent
   boundaries, and append a non-secret audit receipt.
5. If an invariant or verification step fails, stop and restore only the
   bounded prior state. Do not use destructive volume removal as recovery.

## Incident

Catalog anchor: runbook:incident

1. Declare the affected scope and preserve logs, timestamps, deployment
   identity, configuration identity, and observable state before remediation.
2. Follow `RUNBOOK.md` under `Incident triage`; keep investigation read-only
   until a bounded response action is approved.
3. Contain the smallest proven boundary, retain evidence, and distinguish
   service restoration from root-cause closure.
4. Verify dependent services and security controls after containment.
5. Roll back the response action if it worsens impact or its closure check
   fails; never erase the original incident evidence.

## Provider

Catalog anchor: runbook:provider

1. Bind the request to the exact account, zone or repository, deployment, and
   approved provider manifest without recording credentials.
2. Use the provider-specific dry-run or read-only verification documented in
   `cloudflare/README.md` and `RUNBOOK.md` before any separately authorized
   apply.
3. Preserve the previous provider object identifiers and effective policy.
4. Verify remote state through the supported authenticated verifier and retain
   the returned non-secret receipt under independent custody.
5. On mismatch, stop; restore only the reviewed prior provider state using the
   provider's bounded rollback procedure. Local catalog validation never
   substitutes for remote proof.

## Rollout

Catalog anchor: runbook:rollout

1. Require the exact clean commit and tree, immutable image identities,
   deployment identifier, approved evidence set, and previous rollback target.
2. Execute every non-mutating admission gate before the first runtime,
   firewall, DNS, or provider mutation.
3. Follow `RUNBOOK.md` under `Production deploy` and `ROLLOUT_PLAN.md` only
   after the separate release authority has approved the change.
4. Verify the intended service set and security boundaries against the same
   immutable inputs.
5. If any required check fails, stop the rollout and invoke the bounded rollback
   procedure; do not continue in a partially admitted state.

## Rollback

Catalog anchor: runbook:rollback

1. Confirm the exact failed deployment, approved prior image and configuration
   identities, preservation receipt, and rollback authority.
2. Dry-run the bounded rollback described in `RUNBOOK.md` under `Rollback` and
   `ROLLBACK_PLAN.md`.
3. Restore only the components named in the approved rollback plan; database or
   data restoration remains a separate tested operation.
4. Verify health, security boundaries, deployment identity, and audit evidence
   after restoration.
5. If the prior state cannot be restored exactly, stop, preserve the new
   evidence, and escalate instead of improvising a broader destructive change.

## Backup

Catalog anchor: runbook:backup

1. Bind the backup request to the exact data families, deployment identity,
   retention policy, destination class, and encryption/signing policy.
2. Preserve current manifests and previous successful receipts before starting
   the procedure in `RUNBOOK.md` under `Backup` and `Off-site backup`.
3. Produce an immutable, signed manifest and verify destination custody without
   exposing backup contents or credentials.
4. Treat configuration, a plan, or a partial family set as rehearsal evidence,
   never as a complete off-site backup result.
5. On failure, retain the failed receipt and prior valid backup; do not delete
   older recovery points to make a new run appear successful.

## Restore

Catalog anchor: runbook:restore

1. Select an immutable backup by verified manifest and restore it only into an
   isolated destination that cannot overwrite the source state.
2. Follow `RUNBOOK.md` under `Restore test` and the off-site restore procedure
   for every required data family.
3. Verify restored content, service-level usability, preservation, and the
   bounded cleanup or rollback plan against the selected manifest.
4. Record the independent operator, timestamps, exact artifact identities, and
   non-secret test results.
5. A dry run, local-only source, partial family set, or test of the original
   live stack does not close restore readiness.

## Access recovery

Catalog anchor: runbook:access-recovery

1. Record the exact host, deployment, failed access path, last known-good
   identity configuration, and incident timestamp. Preserve audit and access
   evidence before changing authentication.
2. Require approved console, rescue, or break-glass custody and a distinct
   accountability approval. Never publish an admin surface or broadly enable
   password authentication to regain access.
3. Recover only the canonical operator identity or key through the approved
   secret/identity lifecycle. Keep credential values out of receipts and logs.
4. From a separate session, verify ordinary key-based host access, required
   MFA or edge access, authorization boundaries, service health, and revocation
   of temporary recovery access.
5. If verification fails, restore the preserved authentication configuration
   through the same console or rescue path and escalate. Closure requires an
   independent drill against the exact artifact; this document alone is not
   recovery proof.
