# Typed Backup Job and Manifest Contract

## Scope

T06 replaces Control Center command arrays and fuzzy artifact discovery with exact, versioned resource documents.

- Job schema: `platform.backup-job/v1`.
- Manifest schema: `platform.backup-manifest/v1`.
- Supported T06 resource kinds: application source and individual PostgreSQL/MariaDB databases.
- Restore mode: drill-only against disposable targets. This task does not apply a restore to live data.
- MinIO, identity, Vault/state, off-site publication, retention and automatic full coverage remain T07.

## Invariants

1. The Control Center selects resources from server-side project and database state.
2. Every resource has an exact immutable ID such as `source:<project-id>` or `database:<database-id>`.
3. Application jobs reject resources owned by another project.
4. Queue documents contain no shell command or caller-controlled executable argument.
5. The scheduler claims one regular JSON file and invokes only `execute-backup-job --jobFile <claimed-file>`.
6. The executor validates schema, operation, queue path and every resource before execution.
7. A successful backup produces exactly one artifact per declared resource.
8. The manifest records exact resource IDs, relative artifact paths, size, SHA-256 and artifact signing key ID.
9. The complete manifest is HMAC-SHA256 signed with the versioned backup signing keyring.
10. Restore drills verify the manifest HMAC, artifact checksum/signature and exact resource metadata before creating disposable targets.
11. Source restore drills reject absolute paths, parent traversal, foreign top-level directories and symlinks.
12. Existing unmanifested files are legacy artifacts and are not associated with applications by filename.

## Queue Lifecycle

The scheduler owns queue transitions:

```text
queued -> running -> done
                  -> failed
```

Job files are private mode `0600` and written atomically. Admission and scheduler transitions share the filesystem lock at `backup-jobs/.admission.lock`. A queued file is moved to `running` before the executor sees it. The executor writes the manifest/report references; the scheduler records the terminal state.

### Bounded privileged queue

`control-center/backup/queue-admission.mjs` is the only supported writer for a newly admitted privileged backup job. One locked transaction performs the active-work lookup, global depth check, per-principal sliding-window check, conservative admission-ledger reservation and durable job creation. Equivalent active work is keyed from the typed operation, exact scope, sorted resource IDs and restore manifest reference, without including the principal; two owners therefore cannot enqueue the same work concurrently.

The scheduler uses `scripts/backup-queue-control.mjs` for claims and terminal transitions. The same lock enforces a scheduler-wide running-job limit across future replicas. Cron and run-on-start platform backup/restore work reserves the same budget with an ownership-checked lease; while such a lease exists, new Control Center admissions fail closed. `done` and `failed` job documents and their exact owned `manual-backup-<job-id>.log` files have count and age retention bounds. Active jobs are never retention candidates. Audit and backup evidence records remain governed by their separate evidence-retention policy.

Default bounds are configurable with:

- `BACKUP_QUEUE_MAX_OUTSTANDING=32`;
- `BACKUP_QUEUE_MAX_PER_PRINCIPAL=4` per `BACKUP_QUEUE_RATE_WINDOW_SECONDS=900`;
- `BACKUP_QUEUE_MAX_CONCURRENCY=1`;
- `BACKUP_QUEUE_TERMINAL_MAX_PER_STATUS=200` and `BACKUP_QUEUE_TERMINAL_MAX_AGE_DAYS=30`;
- `BACKUP_QUEUE_LEDGER_MAX_ENTRIES=4096`, `BACKUP_QUEUE_MAX_SCAN_ENTRIES=4096`, and `BACKUP_QUEUE_LOCK_TIMEOUT_MS=2000`.

Invalid queue state, malformed ledger state, a non-regular queue file, an exhausted scan bound, or an unavailable lock all fail closed. An abandoned lock or scheduler lease is not automatically removed based only on age; an operator must first prove that no owner still holds it.

### FG-004/FG-043 integration order

Queue admission consumes only the immutable operation object returned by `control-center/auth/route-capabilities.mjs`. It does not accept raw URLs and contains no duplicate alias matcher. The required integration order is:

1. integrate commit `0145498196b90d1df867c4b1428dcefed03d3c6d` so authorization and dispatch share the canonical operation object;
2. pass that exact resolved object and the authenticated principal into `admitBackupJob()` at every `createBackupJob()` call site; and
3. remove the old direct `writePrivateJsonAtomic()` queue write.

Until step 2 is complete, the repository has the tested queue control and bounded scheduler lifecycle but the Control Center enqueue sink is not yet protected by FG-069 and must remain a production NO-GO. No path-based fallback is permitted.

## Manifest Import

The Control Center imports only complete `platform.backup-manifest/v1` documents under `backups/manifests/` whose digest matches and whose artifact metadata matches regular files below the backup root. Application inventory uses `scope.kind=application` plus exact `scope.id`; substring matching and aliases are not used.

The Control Center does not hold the HMAC key. A restore request remains untrusted until the ops executor verifies the HMAC with the backup keyring.

## Database Backup

The database action now queues a real one-resource job. PostgreSQL receives one exact `--database` target. MariaDB receives one validated database name and does not fall back to the global user-database set for a typed job.

The database principal, credential file and live database are not changed by backup execution.

## Evidence

Required verification for T06:

- unit tests for cross-project rejection, duplicate IDs, incomplete coverage, similar-name collision and legacy command rejection;
- source backup and restore sandbox with a tampered-manifest negative test;
- disposable PostgreSQL/MariaDB backup and restore sandbox with exact IDs and unchanged live container identities;
- Control Center API tests proving jobs expose resources and never commands;
- static security gate proving fuzzy matching and queue command execution are absent.

## Rollout Gate

Do not activate the new scheduler against live data during T06. T07 must first add complete platform state/storage coverage, stable Restic identity, full retention policy, persistent logs and off-site coverage. T05 then consumes a verified backup plus successful restore receipt before any database delete can become executable.
