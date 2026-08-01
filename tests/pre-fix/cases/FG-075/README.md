# Safe protected-service network-set integrity probe

This package demonstrates an admission gap in the protected-service comparison
without invoking Compose, a container engine, a container, a network, a
service, or a live system.

The probe performs five bounded checks:

1. It imports the pinned revision's actual `validateRenderedWorkloads()`
   export from an exact Git blob and feeds it only synthetic JavaScript
   objects held in memory.
2. It verifies the vulnerable source structure: protected-service equality
   removes `networks`, and the subsequent network policy examines additions
   but never checks whether each required core membership remains.
3. It proves that removal, permitted-zone replacement, emptying, and
   alias-based substitution of a required network are all accepted by the
   candidate function.
4. It proves sensitivity with a synthetic fixed guard that rejects all four
   missing-set cases while allowing a baseline and a permitted addition. The
   candidate's existing non-network mutation and unauthorized-addition guards
   are also shown to reject their controls.
5. It verifies the source-only activation trace: workload files follow core
   files, separate core and combined JSON models are generated, and the same
   validator is called over those models. It does not run that activation path.

The wrapper accepts only a caller-supplied local Git repository. It verifies
commit `68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`, then materializes only four exact
Git blobs. Their SHA-256 digests are checked again by the probe. The working
checkout may contain unrelated changes because it is never used as the source
of truth.

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
[+] materialized revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 blobs=4
[+] safety source-model validation only; no Compose, container engine, container, network, service, or live operation
[+] source-trace protected_service=postgres required=platform_db_admin,platform_postgres comparison=networks-excluded policy=additions-only
[VULNERABLE] removal candidate=ACCEPTED fixed_guard=REJECTED missing=platform_postgres
[VULNERABLE] replacement candidate=ACCEPTED fixed_guard=REJECTED missing=platform_postgres
[VULNERABLE] emptying candidate=ACCEPTED fixed_guard=REJECTED missing=platform_db_admin,platform_postgres
[VULNERABLE] alias_substitution candidate=ACCEPTED fixed_guard=REJECTED missing=platform_postgres alias=platform_postgres
[+] negative-control baseline candidate=ACCEPTED fixed_guard=ACCEPTED required_set=preserved
[+] negative-control permitted_addition candidate=ACCEPTED fixed_guard=ACCEPTED required_set=preserved added=example_app_postgres
[+] closest-controls non_network_mutation=REJECTED unauthorized_network_addition=REJECTED
[+] safety probe_child_processes=0 compose_processes=0 container_processes=0 containers=0 networks=0 services=0 live_access=0 network_attempts=0
[+] result=VULNERABLE_PROTECTED_NETWORK_SET_INTEGRITY
[+] wrapper post-check preexisting_control_survived=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_device_inode_verified=true
```

The result is a source-model finding. It proves what the pinned candidate
accepts after rendering. It does not prove that a particular raw overlay form
is supported by an installed Compose version, that any accepted lock was
deployed, or that a live service ever lost a network.

Normal completion, ordinary failure, and handled HUP, INT, or TERM all use the
same guarded cleanup. SIGKILL and power loss cannot be trapped and may leave a
`protected-network-set-poc.*` directory under `TMPDIR` (or `/tmp`). Inspect its
`.network-set-owner-<64 lowercase hex characters>` sentinel before any manual
removal; never delete an unverified path.
