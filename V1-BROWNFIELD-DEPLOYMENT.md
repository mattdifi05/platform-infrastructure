# V1 Brownfield Deployment Contract

This document defines the only permitted path for deploying V1 onto a host that
already contains applications and persistent data. It is a safety contract, not
deployment authority and not production evidence.

## Current status

- Candidate under remediation: `30fb7d6ebbaf1734e4f7eabfb95a6444417b0ed0`.
- Live observation: `2026-08-09T04:14:07Z`.
- Live Docker inventory: 34 containers and 139 volumes.
- The point-in-time baseline is stored outside Git under
  `reports/preservation-baselines/live-server-20260809T041407Z.json`.
- The retained read-only transcript has multiple explicit evidence
  deficiencies, including three truncated volume filesystem identities,
  missing per-container config/creation bindings, missing database catalog
  hashes and incomplete host/network identity fields. The baseline is therefore
  intentionally `INCOMPLETE-NO-GO` and cannot authorize mutation; the canonical
  deficiency array in the ignored baseline is the source of truth.
- The captured mounts show direct Docker-socket authority in the legacy backup
  scheduler and host-parent authority in the legacy cAdvisor and node-exporter
  containers. Starting another raw-socket broker would therefore violate the
  singleton boundary on the observed host.
- All three provider gates remain `EXTERNAL-PENDING`; none is transitively bound
  to a canonical complete baseline or authoritative PRE-DEPLOY backup receipt.
- The user has recorded `USER-APPROVED` for the two-phase Hosted sequence below.
  This is scoped governance authorization for the V1 deployment path under the
  absolute application/database preservation contract. It is not provider
  evidence, a receipt, or permission to weaken any fail-closed gate.
- Phase A provider authorization and producer metadata are still absent. No
  server work may begin merely because the user-approved sequence is recorded.

No server mutation, backup, push, or deploy is permitted while any of those
conditions remains unresolved.

## Two permitted strategies

### Additive control plane (reference-only, currently blocked)

The local reference design uses the isolated Compose project
`platform_infra_v1_control`. Its exact mutation set is:

- `docker-action-activation-sidecar`;
- `docker-action-broker`.

The legacy project `platform_infra_vps` and every unknown resource are
preserved. The replacement set is empty. A collision at any candidate-owned
container, volume, bind, or project identity stops the operation before the
first mutation.

This reference is not an executable deployment path. The planner has no Docker
executor and its `apply` mode always stops. On the observed server the existing
direct and host-parent Docker authorities also make this strategy ineligible:
the broker may not be started until a fresh preflight proves that it will be
the sole raw Docker authority and its isolated volume/runtime contract is
provider-attested. A structural fixture PASS is never evidence of that live
condition.

### Intentional rebuild

A rebuild may replace container, network, volume, inode, or host identities,
but only after a target-root backup receipt proves complete recoverability for
every application. The receipt must bind:

- code and configuration needed for recovery;
- a consistent, verified database dump for every database;
- persistent named-volume, bind-mount, upload, and application-storage data;
- secret and configuration recovery references without embedding secret values;
- the complete application-to-database-to-storage mapping;
- checksums, sizes, ownership metadata, and a backup destination outside the
  filesystem or device that may be rebuilt;
- a baseline-bound sorted unique device-set digest and count covering Docker
  root, every checkout, every Compose config file, every volume and database
  directory, both bind lstat-source and canonical-target identities, every
  source root, and every secret-metadata path. A missing identity is `STOP`, and
  the backup device must be outside the complete set;
- an ordered restore plan and explicit code rollback/data rollback separation.

The point-in-time live baseline is not such a receipt. A locally fabricated or
self-asserted receipt never authorizes a rebuild.

The current rebuild path is also blocked: the real baseline is incomplete, no
new PRE-DEPLOY backup receipt exists, and the external provider identities are
unset. The verify-only backup validator can prove structural coverage but
returns only `REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE`; it cannot create a
dump, sign evidence, authorize teardown, or replace the required provider and
target-root signatures.

## Local controls are not deployment authority

- `scripts/live-preservation-baseline.mjs` validates and compares deny-only
  observations. The real ignored artifact records current gaps and returns
  `STOP` when completeness is required.
- `scripts/v1-predeploy-backup-receipt.mjs` verifies a supplied backup mapping;
  it has no dump, restore, signer, teardown, SSH, Docker, or network capability.
- `scripts/v1-brownfield-bootstrap.sh` is retained as an install-only test
  harness and read-only plan/verify helper. Production `--apply` terminates with
  `STOP`/exit 78 until the independently pinned Phase-B root installer exists;
  the test seam cannot run with UID 0 and accepts only byte-safe, already
  canonical fixture and checkpoint paths that remain below the fixture root.
  It cannot target or resolve through an alias to `/`. Its output remains
  `deploymentAuthorized=false` with provider gates `EXTERNAL-PENDING`.
- `scripts/v1-provider-gates.mjs` summarizes the exact missing external and
  transitive preservation/backup bindings. It cannot change a gate to READY or
  create evidence.

These controls may reject unsafe input. None may be composed into a local
substitute for provider or target-root evidence.

## User-approved two-phase order; provider evidence pending

The prior literal order remains structurally unsatisfiable because it demanded
an installed broker receipt before the backup required to authorize that
installation. It is superseded as the active user order by the exact sequence
below. The user approval is governance authorization only: it is not provider
evidence, does not satisfy any provider gate, does not populate a receipt, and
does not grant Phase A mutation authority.

1. **Phase A — read-only provider authorization.** Obtain an independently
   authenticated authorization bound to the exact package bytes, package-byte
   attestation, this two-phase order contract, and an independently distributed
   trust key. Bind the external producer repository, exact workflow path,
   immutable `job_workflow_sha` and `head_sha`, `refs/heads/main`,
   `workflow_dispatch`, run ID and attempt, protected environment, and approval
   evidence identity/digest. Phase A is read-only and must complete before live
   preflight.
2. **Live read-only preflight.** Reacquire the complete target inventory and
   identity without mutation. Every application, database, storage path, bind,
   volume, secret reference, Docker authority, and recovery dependency must be
   mapped. Any gap remains `STOP`.
3. **Verified PRE-DEPLOY backup.** Only after preflight PASS, create the complete
   target-root backup and verify its dumps, storage, configuration, recovery
   mapping, checksums, readability, and restore plan. Its backup root must be
   outside the complete source-device set and outside every destruction domain
   that may be rebuilt.
4. **Phase B — installation, receipt, and final admission.** Only after the fresh
   complete preflight and authoritative backup verify, install the exact attested
   package, obtain the target-root installation receipt, and obtain independent
   provider final admission bound to the same candidate, target, baseline, backup
   receipt, source-device proof, and Phase A authorization.
5. **Activation.** Activate only after Phase B and all three provider gates have
   independently authenticated PASS evidence. Code rollback and data rollback
   remain separate; no pre-deploy dump may overwrite later live writes
   automatically.

The provider has not supplied Phase A or Phase B evidence. Therefore the current
machine status remains `EXTERNAL-PENDING` with effect `STOP`: no live preflight,
backup, broker installation, push, activation, or deploy follows from the user
approval alone.

## Fail-closed conditions

Stop before mutation when any application, database, storage path, volume,
bind, upload directory, secret reference, or restore step is unmapped; when a
backup is absent, unreadable, same-device, incomplete, overwritten, or not
checksum-bound; when a provider gate or receipt cannot be authenticated; or
when the deployed SHA differs from the authorized clean candidate.

Commands or plans that use global teardown, prune, orphan removal, database
drop/reinitialization, or recursive ownership changes are never implicit. They
may not be derived merely from a Compose project label. Any destructive action
in an intentional rebuild must be an exact post-backup action in the reviewed
restore plan.

## External evidence still required

The closed machine-readable inventory is
`governance/v1-provider-gates.json`. In summary:

| Gate | Missing authoritative evidence | Local satisfaction |
| --- | --- | --- |
| Hosted preparation/provider conformance | Independent-provider acceptance of the user-approved two-phase order; authenticated Phase A producer metadata and read-only package authorization; post-backup installation receipt/final admission; complete canonical baseline; proof digest covering Docker root, all checkouts, all Compose configs, all volume/database directories, both bind identities, all source roots and secret-metadata paths, with backup outside the complete set; exact candidate/target identity and signatures; post-deploy rollback preservation | No |
| Deployment admission | Complete canonical baseline; authoritative backup receipt; the same exact all-checkout/config/volume/database/bind/source-root/secret-metadata device-set digest with no missing identity and backup outside the complete set; exact candidate/target identity; provider and target-root signatures/admissions; post-deploy rollback preservation; trusted verifier channel, immutable ops image, real staging probes, DAST countersignature and Sigstore bundle | No |
| Activation promotion/Sigstore | Complete canonical baseline; authoritative backup receipt; the same exact all-checkout/config/volume/database/bind/source-root/secret-metadata device-set digest with no missing identity and backup outside the complete set; exact candidate/target identity; provider and target-root signatures/admissions; post-deploy rollback preservation; independent promoter/custom root, seven-file artifact, Docker authorization, immutable CAS and root broker identities | No |

Local validators and fixtures may prepare consumers and prove rejection. They
must not create, sign, mint, or relabel this evidence as production proof.
