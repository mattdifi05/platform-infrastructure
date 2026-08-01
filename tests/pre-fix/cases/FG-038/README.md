# Hosted PID-namespace admission PoC

This offline PoC demonstrates canonical finding `CAN-093` against exact
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
that contains the revision, but it never reads files from the checkout's
working tree.

## Safety boundary

The shell wrapper verifies the commit and tree, exports clean source snapshots
with `git archive`, and passes only the positive snapshot to the policy probe.
The JavaScript entry point refuses direct invocation against an arbitrary
directory. It requires the wrapper's real temporary root, a random ownership
sentinel, and the matching token; the source must be the exact, non-symlink
`source` child of that root.

Before the positive run, the wrapper deliberately supplies an invalid token to
a separate guard snapshot. The probe must reject, and a pre-existing synthetic
file must remain byte-for-byte unchanged. The positive probe hashes the entire
snapshot before and after analysis and rejects any mutation.

The PoC does not invoke Docker or Docker Compose, start a container, join a
namespace, read `/proc`, inspect a secret, use SSH or a network service, or
contact live infrastructure. Its fixtures exist only in JavaScript memory.
Cleanup removes only the unpredictable top-level temporary archive after
revalidating the wrapper ownership sentinel. If the sentinel is missing or
changed, cleanup fails closed and prints the retained path for manual review.

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

`SOURCE_REPO` has no default. Supply a local checkout that contains the pinned
commit; uncommitted working-tree changes are ignored because the wrapper reads
the Git object database through `git archive`.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 6 embedded vulnerable-source hashes
[+] verified Control Center target has no explicit user and declares 5 secrets
[+] verified admitted workload files reach the Compose activation command
[VULNERABLE] service-pid-reference user=1000:1000 pid=service:control-center admission=accepted runtime=passed
[VULNERABLE] zero-padded-uid user=00:1000 pid=unset admission=accepted runtime=passed
[VULNERABLE] zero-padded-gid user=1000:00 pid=unset admission=accepted runtime=passed
[VULNERABLE] combined-root-and-pid user=00:00 pid=service:control-center admission=accepted runtime=passed
[+] summary vulnerable=4 total=4 source_tree_unchanged=true
[+] no Docker, Compose, namespace, procfs, secret, network, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The `VULNERABLE` result means both original policy functions accepted the
synthetic field set. It does not claim that a container runtime parsed the
identity or that a concrete `/proc` path was readable; those are deliberately
unexecuted runtime preconditions.
