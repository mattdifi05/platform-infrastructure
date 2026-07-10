# Database deletion safety

This document defines the destructive database workflow used by the Infrastructure Portal. It applies only to platform-managed MariaDB and PostgreSQL resources with an exact active ownership binding.

## Safety invariants

A delete request is rejected unless all of the following are true:

- the caller is an authenticated owner with fresh passkey authentication;
- the exact database name is typed by the operator;
- the request carries a new idempotency key;
- a fresh signed backup manifest contains the exact database resource ID;
- the backup artifact size and SHA-256 match the manifest and sidecars;
- a fresh disposable restore drill passed for that exact manifest and resource;
- a fresh remote Restic snapshot receipt covers that exact manifest and resource;
- the registered database, project, engine, generated principal and live catalog ownership all match;
- the principal is active, platform-managed and non-privileged.

The default evidence window is 24 hours. It can be shortened or extended, up to seven days, with `CONTROL_CENTER_DATABASE_DELETE_EVIDENCE_MAX_AGE_SECONDS`.

## State machine

The persisted operation uses these states:

```text
evidence-verified -> approved -> executing -> database-dropped -> completed
                                  |                    |
                                  v                    v
                                failed        rollback-required
```

Request, approval and execution are separate owner actions. Every action repeats the exact typed-name check; approval and execution also recalculate the recovery-evidence fingerprint.

The database drop and principal cleanup are separate operations. `database-dropped` is persisted before any principal, credential or metadata cleanup. A failure before that checkpoint enters `failed` and may be approved again after investigation. A failure after that checkpoint enters terminal `rollback-required`; it is never retried automatically.

## Operator procedure

1. Run an exact database backup through the typed backup job pipeline.
2. Run a disposable restore drill for the same manifest and database resource.
3. Upload the complete signed platform manifest off-site and retain the generated snapshot receipt.
4. Open the application database view and request deletion by typing the exact database name.
5. Review the manifest, restore report, off-site snapshot and evidence fingerprint.
6. Approve the persisted operation in a separate action.
7. Execute only inside an approved maintenance window.
8. Verify the operation is `completed`, the database and generated principal are absent, application metadata is reconciled and platform health still passes.

Do not use direct SQL or remove portal metadata to bypass this workflow.

## Failure handling

For `failed`, verify that the database still exists, correct the pre-drop blocker, create fresh evidence if needed and approve the same operation only after review.

For `rollback-required`, stop. Do not execute the operation again. Preserve the operation file and audit log, verify whether the exact database was dropped, and choose one explicitly approved path:

- restore the exact signed artifact and rebind the application; or
- complete principal, credential and metadata reconciliation after confirming that deletion was intended.

The portal intentionally does not automate either post-drop path.

## Verification scope

The repository test suite covers invalid, stale, cross-resource and tampered evidence; state transitions; idempotency; exact ownership; privileged principals; and disabled live adapters.

`scripts/database-ownership-sandbox-test.sh` creates isolated MariaDB and PostgreSQL containers, performs real backups and disposable restores, then exercises the complete request, approval and execution workflow. It verifies that live platform database container identities remain unchanged.

This verification does not authorize or perform a live database deletion. Live activation requires a separate maintenance approval, current backup evidence and rollback plan.
