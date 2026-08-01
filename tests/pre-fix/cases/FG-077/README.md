# Streaming backup-hash PoC

This offline PoC demonstrates canonical finding `CAN-236` against exact
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
containing those objects, but it never reads the checkout's working tree.

## Safety boundary

The wrapper verifies the commit and tree, exports source with `git archive`, and
creates an unpredictable wrapper-owned lab. The JavaScript probe refuses direct
invocation against arbitrary directories. It requires exact non-symlink source
and lab children, a random ownership sentinel, and the matching token.

A wrong-token preflight must fail without changing a pre-existing synthetic
file. Cleanup removes only the unpredictable top-level lab after revalidating
the wrapper sentinel's path, content, device, and inode. If ownership cannot be
proved, cleanup fails closed and retains the path.

The positive probe creates one deterministic 8 MiB synthetic artifact. It
extracts and executes the original pinned `sha256File()` in a VM with an
instrumented `fs.readFileSync`, proving that one read returns the complete
artifact. A fixed-control implementation hashes the same bytes in 64 KiB
chunks, with identical digest, explicit size/time limits, cancellation, and
file-stability checks.

The oversized control creates a 64 MiB sparse synthetic file but rejects it
against a 16 MiB policy before opening a stream; its contents are never read.
The cancellation control stops the bounded stream after its first chunk. The
PoC deliberately does not attempt an OOM or scheduler crash and does not read a
real backup, database, Docker daemon, credential, network service, live target,
or candidate working-tree file.

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

`SOURCE_REPO` has no default. Uncommitted changes are ignored because only the
pinned Git objects are archived.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source and synthetic lab verified
[+] verified 3 embedded vulnerable-source hashes
[+] source proof read_strategy=readFileSync sign_and_verify_reuse=true scheduler_mem_limit=512m
[VULNERABLE] whole_file_read calls=1 artifact_bytes=8388608 largest_read=8388608
[CONTROL] digest_parity vulnerable_vs_streaming_equal=true
[FIXED] bounded_stream artifact_bytes=8388608 chunk_bytes=65536 max_observed_chunk=65536 whole_file_buffer=false time_bound_configured=true
[CONTROL] oversized_sparse declared_bytes=67108864 max_bytes=16777216 rejected_before_stream=true
[CONTROL] cancellation chunks_before_abort=1 cancelled=true
[+] source_tree_unchanged=true synthetic_only=true
[+] no real backup, database, Docker daemon, credential, network, live target, or candidate working tree was read or changed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The 8 MiB read is a safe strategy probe, not an OOM reproduction. It proves the
original function asks `readFileSync` for one artifact-sized Buffer. The source
trace and 512 MiB scheduler limit establish why artifact growth can become an
availability problem; no claim is made about a specific live artifact size,
memory peak, crash threshold, or observed scheduler failure.
