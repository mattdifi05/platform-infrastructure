# Hosted memory and OOM admission PoC

This offline PoC demonstrates canonical findings `CAN-194` and `CAN-198`
against exact revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
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

The PoC does not invoke Docker or Docker Compose, start a container, allocate
pressure memory, consume swap, alter an OOM score, disable an OOM kill, read
host capacity, use SSH, contact a network service, or access live
infrastructure. Its Compose models exist only in JavaScript memory. Cleanup
removes only the unpredictable top-level temporary archive after revalidating
the wrapper ownership sentinel. If the sentinel is missing or changed, cleanup
fails closed and prints the retained path for manual review.

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
[+] verified 3 embedded vulnerable-source hashes
[+] verified admitted workload files reach the Compose activation command
[VULNERABLE] unlimited-swap memswap_limit=-1 oom_score_adj=unset oom_kill_disable=unset admission=accepted runtime=passed
[VULNERABLE] oom-priority-immunity memswap_limit=unset oom_score_adj=-1000 oom_kill_disable=unset admission=accepted runtime=passed
[VULNERABLE] oom-kill-immunity memswap_limit=unset oom_score_adj=unset oom_kill_disable=true admission=accepted runtime=passed
[VULNERABLE] combined-controls memswap_limit=-1 oom_score_adj=-1000 oom_kill_disable=true admission=accepted runtime=passed
[+] summary vulnerable=4 total=4 source_tree_unchanged=true
[+] no Docker, Compose, memory pressure, swap, OOM policy, network, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

A `VULNERABLE` result means both original policy functions accepted the
synthetic field set. It does not claim that the host has swap, that the kernel
entered an OOM path, or that every container backend applies every field;
those are deliberately unexecuted runtime preconditions.
