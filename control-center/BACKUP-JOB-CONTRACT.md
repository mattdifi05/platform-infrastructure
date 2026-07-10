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

Job files are private mode `0600` and written atomically. A queued file is moved to `running` before the executor sees it. The executor writes the manifest/report references; the scheduler records the terminal state.

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
