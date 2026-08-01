# Safe hosted-workload symlink containment PoC

This offline, source-pinned PoC demonstrates `CAN-172` using only synthetic
files and symlinks inside a wrapper-owned temporary directory. It does not use
Docker, open a network connection, invoke SSH, read a credential, start a
service, modify the source repository, or inspect a live environment.

The wrapper verifies commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`, then exports only the four source
files used by the proof. The probe verifies each SHA-256 digest and imports the
exact archived `resolveCatalog` implementation.

Inside the private fixture, the PoC creates valid synthetic manifest, Compose,
environment, and migration files outside the synthetic workload root. An
intermediate directory symlink makes their lexical paths appear contained. The
pinned resolver accepts and hashes all four physical outside files. Their final
components remain regular files, so the archived shell lock's final-component
`-L` guard cannot see the parent symlink.

Additional cases cover a two-hop cross-root chain and a directory replaced by
a symlink. A terminal-file symlink is included as a control: `stat` follows it,
but the shell's existing final-component check can see it. An all-regular,
physically contained workload passes both the current resolver and the
symlink-safe reference oracle.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected output includes:

```text
[+] unwrapped direct invocation rejected
[SOURCE] revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 files=4 provenance=git-archive
[VULNERABLE CAN-172] case=intermediate-symlink records=4 lexical_contained=true terminal_symlink=false physical_outside=true resolver=accepted
[CONTROL] case=terminal-symlink stat_follows=true shell_final_guard=reject fixed_oracle=reject
[VULNERABLE] case=cross-root-two-hop terminal_symlink=false physical_outside=true resolver=accepted fixed_oracle=reject
[NEGATIVE CONTROL] case=all-regular records=4 resolver=accepted fixed_oracle=accepted
[VULNERABLE] case=replaced-directory lexical_path_unchanged=true resolver=accepted physical_outside=true fixed_oracle=reject
[GUARD] unowned_cleanup_refused=true preexisting_sha256=<sha256>
[SAFE] network_attempts=0 credentials_read=0 docker_calls=0 services_started=0 live_mutations=0 source_mutations=0
[+] cleanup sentinel_owned_fixture_removed=true preexisting_marker_preserved=true
[+] result=VULNERABLE canonical_id=CAN-172
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The fixture has its own unpredictable ownership sentinel. Its cleanup routine
refuses a pre-existing sentinel-free directory and verifies that the marker's
device, inode, size, bytes, and hash survive. Outer cleanup independently
revalidates its physical path, parent-directory identity, directory identity,
sentinel identity, and 256-bit token. A mismatch refuses deletion and makes
 the run fail.

No cleanup is normally required. `SIGKILL` or power loss may leave a directory
named `symlink-containment.*` under `TMPDIR`; inspect its
`.symlink-containment-wrapper-owner` sentinel before removing it.
