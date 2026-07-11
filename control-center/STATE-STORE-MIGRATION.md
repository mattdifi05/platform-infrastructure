# Control Center State Store Migration

Status: candidate procedure only. It has been tested with synthetic data; it
has not been run against live state.

## Scope

The migration catalog covers non-secret Control Center metadata, audit and
operation JSONL, deployment/backup records, and Status run events. It does not
include Vault ciphertext, database destructive-operation state, database
principal bindings, database credential files, secrets, backups or volumes.

Snapshots can still contain operational metadata and must be stored outside
Git with mode `0600`.

## Preconditions

1. Obtain maintenance approval and put the Control Center in read-only mode or
   stop its only writer.
2. Create and verify the normal Control Center state backup and off-site copy.
3. Record the current image digest, commit and container identity.
4. Use a private rollback directory outside the repository.
5. Do not proceed if any source dataset fails strict parsing.

## Export And Plan

Run inside the candidate image or an equivalent pinned Node environment with
the same `PROJECT_*_FILE` variables as the target:

```sh
npm run state:migrate -- export /private/control-state-before.json
npm run state:migrate -- plan-import /private/control-state-before.json
```

`plan-import` never writes state. CLI output contains counts and paths, not
dataset values.

## Apply

Apply is intentionally unavailable without both the exact confirmation and a
rollback output path:

```sh
npm run state:migrate -- apply-import /private/control-state-candidate.json \
  --rollback /private/control-state-rollback.json \
  --confirm IMPORT-CONTROL-CENTER-STATE
```

The rollback snapshot is written before the first target write. Import validates
schema, dataset type and content digest, and restores the in-memory rollback
snapshot automatically if a write fails.

## Verify

After an approved apply:

1. verify `/__health`, `/control/v1/status` and one read-only endpoint per area;
2. verify every state file and sidecar is private and parseable;
3. verify audit/status append and optimistic stale-token rejection;
4. compare application, domain, backup and provider metadata counts;
5. preserve the migration report outside Git.

## Rollback

Keep the writer stopped and import the pre-apply rollback snapshot with the same
explicit confirmation, writing a second rollback file for the failed state.
Then restore the previous verified image. Never delete volumes and never use
`docker compose down -v`.
