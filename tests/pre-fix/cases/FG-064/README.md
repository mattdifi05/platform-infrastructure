# Safe application-backup argument-boundary probe

This package demonstrates the vulnerable source-to-argument boundary without
running an archive utility, invoking a payload command, opening a real backup,
starting a service, or using the network.

The probe performs four bounded checks:

1. It executes the pinned revision's isolated
   `safeApplicationBackupSlug()` function and proves that short, long, and
   position-sensitive option-shaped directory names normalize to accepted
   output slugs.
2. It verifies the exact directory enumerator and application-backup sink in
   `scripts/infra-ops.mjs`: the raw directory name is retained and placed
   after `-C` without an end-of-options marker.
3. It classifies the untrusted token under documented GNU command-line and
   file-list rules. A harmless response-list line, `--no-recursion`, is used
   only as model input; no parser process consumes it.
4. It proves sensitivity with three negative controls: inserting `--` changes
   every injected token from option to operand, a leading-dash guard rejects
   the same names while preserving an ordinary application, and fixture
   acquisition refuses a pre-existing target without changing it.

The wrapper accepts only a caller-supplied local Git repository. It verifies
commit `68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`, then materializes only three
exact Git blobs. Their SHA-256 digests are checked again by the probe. The
working checkout may contain unrelated changes because it is never used as the
source of truth.

The private temporary root is bound to an unpredictable 256-bit ownership
sentinel. Cleanup revalidates the root's physical location plus the sentinel's
path, type, token, device, and inode before removal. A separate pre-existing
control file must retain its listing, bytes, hash, device, and inode throughout
the run.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=../../repository
make run SOURCE_REPO=../../repository
```

`SOURCE_REPO` has no default. The commands require POSIX `sh`, local Git,
Node.js, `make`, `find`, and `shasum`; they require no container engine or
network access.

Representative output:

```text
[+] unwrapped direct invocation rejected
[+] materialized revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 blobs=3
[+] safety source-only argument analysis; no archive utility, backup path, payload command, service, or network operation
[+] candidate source_name=--files-from=fixture-list slug=files-from-fixture-list raw_name_preserved=true source_mount=read-only
[VULNERABLE] candidate_argv untrusted_token=--files-from=fixture-list classification=OPTION end_of_options_before_input=false
[VULNERABLE] documented_gnu_file_list line=--no-recursion classification=OPTION verbatim_control=NAME
[+] boundary variants short=OPTION long=OPTION positional=OPTION response_style=OPTION
[+] negative-control fixed_argv short=OPERAND long=OPERAND positional=OPERAND
[+] negative-control leading_dash_guard=REJECTED ordinary_name=ACCEPTED preexisting_target=REJECTED
[+] safety probe_child_processes=0 archive_utility_processes=0 payload_commands=0 real_backups_read=0 real_backups_written=0 services_started=0 network_attempts=0
[+] result=VULNERABLE_SOURCE_ARGUMENT_BOUNDARY
[+] wrapper post-check preexisting_control_survived=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_device_inode_verified=true
```

This is a source-boundary proof, not a claim about a live host or a particular
runtime archive implementation. It models the GNU behavior documented in the
report and deliberately leaves parser/version compatibility as an explicit
deployment prerequisite.

Normal completion, ordinary failure, and handled HUP, INT, or TERM all use the
same guarded cleanup. SIGKILL and power loss cannot be trapped and may leave a
`backup-tar-option-poc.*` directory under `TMPDIR` (or `/tmp`). Inspect its
`.backup-tar-option-owner-<64 lowercase hex characters>` sentinel before any
manual removal; never delete an unverified path.
