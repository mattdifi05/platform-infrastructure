# Control Center Core

Status: candidate T19, verified in an isolated container, not deployed live.

## Boundaries

`control-center/server.mjs` remains the compatibility entrypoint, but critical
state and execution behavior is owned by modules:

| Area | Module | Contract |
| --- | --- | --- |
| Admin authentication | `auth/` | Application-owned SimpleWebAuthn passkey, PostgreSQL credential/session store, fail closed; OIDC is explicit compatibility mode |
| Backup jobs | `backup/contracts.mjs` | typed resources, signed manifests, exact ownership |
| Database operations | `database/` | principal ownership and destructive state machine |
| Vault crypto | `vault/keyring.mjs` | versioned key IDs and authenticated encryption |
| Control metadata | `state/catalog.mjs`, `state/file-store.mjs` | strict reads, atomic writes, locks and revisions |
| State migration | `state/migration.mjs` | export, plan, confirmed import and rollback snapshot |
| Status execution | `status/executor.mjs` | typed catalog, timeout, lifecycle events and redacted errors |
| Portal icons | `components/ui/controlIcons.mjs` | self-hosted Font Awesome paths shared by the active renderer |

The unused legacy renderer was removed. The active operations renderer, login
surface and documentation renderer remain behavior-tested.

## API Contract

`/control/v1/*` is the versioned API surface. Existing `/control/*` routes are
compatibility aliases for the same handlers during the strangler migration.
T20 may move the frontend to v1 route by route without a backend big-bang.

Status runs expose:

- `GET /control/v1/status` for the latest result and its complete lifecycle;
- `GET /control/v1/status/events?runId=<id>` for ordered progress events;
- execution modes `probe`, `evidence-validation` and `external-required`;
- a bounded timeout per check and redacted executor failures.

An evidence validation re-evaluates the current report-derived row. It is not
presented as a network probe. `external-required` remains pending when a real
domain, provider or approved operation is unavailable.

## State Store Decision

The current single-node candidate uses file store v2 as the selected metadata
store. It preserves existing JSON/JSONL formats while adding:

- strict malformed-state rejection;
- private `0600` atomic writes with fsync and rename;
- per-dataset lock files and stale-lock recovery;
- revision plus SHA-256 sidecars;
- optimistic tokens for stale-writer rejection;
- portable export/import snapshots with rollback.

This is a single-active-writer design, not HA. PostgreSQL remains the durable
store for authentication sessions. Moving all control metadata to PostgreSQL
requires an async repository conversion and multi-node decision; it must not be
claimed as complete by this candidate.

Database destructive state, principal ownership and Vault ciphertext keep
their specialized fail-closed stores. They are deliberately excluded from the
generic migration catalog and retain their own backup and migration gates.

## Activation Gate

No state migration or Control Center recreate was performed for T19. A future
rollout requires T01/T02 passkey activation, a fresh state backup, T08 recovery
evidence, a maintenance approval and the procedure in
`STATE-STORE-MIGRATION.md`.
