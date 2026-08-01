# Required-check producer-binding PoC

This offline PoC demonstrates canonical finding `CAN-155` against exact
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It needs a local Git checkout
that contains the revision, but it never reads the checkout's working tree.

## Safety boundary

The shell wrapper verifies the commit and tree, exports clean source snapshots
with `git archive`, and passes only the positive snapshot to the probe. The
JavaScript entry point refuses direct invocation against an arbitrary
directory. It requires the wrapper's real temporary root, a random ownership
sentinel, the matching token, and the exact non-symlink `source` child.

Before the positive run, the wrapper deliberately supplies an invalid token to
a separate guard snapshot. The probe must reject, and a pre-existing synthetic
file must remain byte-for-byte unchanged. The positive probe hashes the entire
source snapshot before and after analysis and rejects mutation.

The PoC imports only the pure branch-protection comparison functions from the
pinned archive and supplies in-memory synthetic GitHub API response objects.
The producer IDs `1001` and `9001` are deliberate placeholders; they do not
identify real GitHub Apps. The probe does not run the operations CLI, call the
GitHub API, publish a status/check, create a pull request, merge a branch, read
a credential, use SSH or a network service, or access live infrastructure.

Cleanup removes only the unpredictable top-level archive after revalidating
the wrapper ownership sentinel. If the sentinel is missing or changed,
cleanup fails closed and prints the retained path for manual review.

## Requirements

- Git
- Node.js 20 or newer
- POSIX `sh`, `tar`, `mktemp`, `grep`, and `cmp`

## Run

From this `poc` directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`SOURCE_REPO` has no default. Uncommitted changes are ignored because the
wrapper reads the pinned objects with `git archive`.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 5 embedded vulnerable-source hashes
[+] policy required_contexts=4 producer_bindings=0 apply_payload=contexts-only
[CONTROL] approved-producer app_id=1001 tuple_mismatches=0 governance_mismatches=0 accepted=true
[VULNERABLE] unapproved-producer app_id=9001 tuple_mismatches=4 governance_mismatches=0 accepted=true
[VULNERABLE] any-producer app_id=-1 tuple_mismatches=4 governance_mismatches=0 accepted=true
[VULNERABLE] duplicate-context context=quality app_ids=1001,9001 tuple_mismatches=1 governance_mismatches=0 accepted=true
[CONTROL] missing-context governance_mismatches=1 rejected=true
[CONTROL] extra-context governance_mismatches=1 rejected=true
[+] summary vulnerable=3 controls=3 source_tree_unchanged=true
[+] no GitHub API, status/check publication, pull request, merge, credential, network, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

`accepted=true` means the original repository-governance comparator and its
throwing assertion accepted the synthetic branch-protection response. It does
not claim that GitHub accepted a forged check or merged a pull request; those
are deliberately unexecuted platform conditions.
