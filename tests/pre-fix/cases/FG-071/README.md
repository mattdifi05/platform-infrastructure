# Hosted GPU admission PoC

This offline PoC demonstrates canonical finding `CAN-209` against exact
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It needs a local Git checkout
containing that revision, but it never reads the checkout's working tree.

## What the result establishes

The probe imports the archived `validateRenderedWorkloads()` implementation
and supplies complete synthetic core, combined-render, and workload-lock
objects. It changes only the GPU request on an otherwise accepted hosted
service. The archived validator accepts and preserves all four cases:

- service-level `gpus: all`;
- a deploy reservation with GPU capability and `count: all`;
- a GPU-capability reservation with both count and device IDs omitted; and
- a reservation naming a synthetic, unapproved GPU device ID.

A no-GPU baseline is accepted. A separate negative control sets
`privileged: true` and must be rejected by the same archived validator. This
guards against mistaking a broken fixture or an unexecuted validator for a
successful demonstration.

The probe also verifies exact hashes for the contract, its tests, the runtime
isolation policy, the preparation script, and the Compose wrapper. Static
source tracing confirms that the repository renders the workload file before
validation and later appends verified workload files to the Compose command.
The PoC does not invoke that command.

## Evidence boundary

`admission=accepted` is an observed result from the archived JavaScript
validator. `field_preserved=true` means the synthetic combined-render object
still contains the exact request after validation. Those results do not prove
that a particular Docker or Compose version accepts, normalizes, or activates
the request on a GPU host.

Every GPU case is therefore labeled `runtime=NOT-TESTED`. The final `PENDING`
line keeps Compose normalization, device allocation, resource exhaustion, and
driver attack-surface effects explicitly unverified. No live deployment state
is inferred.

## Safety and cleanup

The wrapper verifies the exact commit and tree and exports clean snapshots
with `git archive`. The JavaScript entry point refuses direct invocation
against an arbitrary directory. It requires the wrapper's real temporary
root, an unpredictable ownership sentinel, and the matching token; the source
must be the exact non-symlink `source` child.

Before the positive run, the wrapper supplies an invalid token to a separate
guard snapshot. The probe must reject it, and a synthetic pre-existing file
must remain byte-for-byte unchanged. The positive probe hashes the complete
archived source before and after analysis and rejects any mutation.

No Docker or Compose process is started. The PoC does not enumerate or open a
GPU, connect to a device, access a network, inspect credentials, use SSH, or
contact live infrastructure. Cleanup removes only the unpredictable
top-level temporary archive after revalidating its wrapper sentinel. If
ownership validation fails, cleanup refuses deletion and reports the retained
path.

## Requirements

- Git
- Node.js 20 or newer
- POSIX `sh`, `tar`, `mktemp`, `grep`, and `cmp`

Docker, Docker Compose, NVIDIA tooling, and a GPU are deliberately not
required or invoked.

## Run

From this `poc` directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`SOURCE_REPO` has no default. Uncommitted changes are ignored because the
wrapper reads the pinned commit through Git's object database.

## Expected output

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 5 archived source hashes and admission-to-Compose source shapes
[SOURCE-TRACE] gpu_checks=absent contract_tests=absent runtime_policy=absent compose_executable_invoked=false
[CONTROL] bounded-no-gpu admission=accepted synthetic_render=true
[NEGATIVE-CONTROL] privileged admission=rejected archived_validator_executed=true
[VULNERABLE] service-gpus-all admission=accepted field_preserved=true semantic=all-devices-per-compose-spec runtime=NOT-TESTED
[VULNERABLE] deploy-count-all admission=accepted field_preserved=true semantic=all-matching-gpu-devices runtime=NOT-TESTED
[VULNERABLE] deploy-capability-only admission=accepted field_preserved=true semantic=all-matching-gpu-devices-when-count-and-ids-omitted runtime=NOT-TESTED
[VULNERABLE] deploy-unknown-device-id admission=accepted field_preserved=true semantic=unapproved-device-identity-not-checked runtime=NOT-TESTED
[+] summary gpu_request_variants_accepted=4 total=4 source_tree_unchanged=true
[PENDING] compose_normalization=NOT-TESTED gpu_allocation=NOT-TESTED resource_exhaustion=NOT-TESTED driver_attack_surface=NOT-TESTED
[+] no Docker, Compose, GPU, device, network, credential, SSH, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```
