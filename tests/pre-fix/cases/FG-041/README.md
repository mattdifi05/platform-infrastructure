# Hosted workload logging-policy admission PoC

This offline PoC demonstrates canonical findings `CAN-141`, `CAN-195`, and
`CAN-216` against exact revision
`68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
that contains the revision, but it never reads source from that checkout's
working tree.

## Safety boundary

The shell wrapper verifies the commit and tree, exports clean source snapshots
with `git archive`, and passes only the positive snapshot to the policy probe.
The JavaScript entry point refuses direct invocation against an arbitrary
directory. It requires the wrapper's real temporary root, a random ownership
sentinel, and the matching token; the source must be the exact, non-symlink
`source` child of that root.

Before the positive run, the wrapper deliberately supplies an invalid token to
a separate guard snapshot. The probe must reject it, and a pre-existing
synthetic file must remain byte-for-byte unchanged. The positive probe hashes
the entire archived tree before and after analysis and rejects any mutation.

The PoC imports the archived admission validator and builds its Compose objects
only in memory. It does not invoke Docker or Docker Compose, start a container,
contact a daemon or network destination, emit logs, fill storage, use SSH, or
access live infrastructure. Cleanup removes only the unpredictable top-level
temporary archive after revalidating the wrapper ownership sentinel. If that
sentinel is missing or changed, cleanup fails closed and prints the retained
path for manual review.

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
commit. Uncommitted working-tree changes are ignored because the wrapper reads
the Git object database through `git archive`.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 5 archived source hashes and absent workload logging policy
[+] verified daemon default logging=json-file max-size=10m max-file=5
[+] verified combined render reaches admission and locked overlays reach Compose
[BASELINE] approved-local-json driver=json-file max-size=10m max-file=5 admission=accepted
[VULNERABLE] disabled-audit driver=none admission=accepted
[VULNERABLE] rotation-bound-extreme driver=json-file max-size=100g max-file=1000000 admission=accepted
[VULNERABLE] daemon-syslog-egress driver=syslog address=tcp://10.0.0.25:514 admission=accepted
[+] summary vulnerable=3 total=3 source_tree_unchanged=true
[+] no Docker, Compose, daemon, container, network, log emission, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

`VULNERABLE` means the original rendered-workload policy accepted the supplied
logging object and returned success. It does not mean the PoC started a
container, exercised a Docker logging driver, opened the syslog address, wrote
log data, or exhausted storage. Those runtime effects are deliberately not
executed by this safe source-level demonstration.
