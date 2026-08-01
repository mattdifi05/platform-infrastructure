# Safe restore-manifest coverage probe

This probe demonstrates that the vulnerable off-site restore coverage function
accepts five broad family successes without consuming a signed backup manifest
or comparing an exact resource inventory.

The wrapper archives the pinned vulnerable revision into `poc/.tmp`, verifies
its Git commit, tree, and embedded file hashes, and then executes the exact pure
discovery and coverage functions with a bounded synthetic inventory in memory.
It does not inspect a backup directory, invoke Restic, call a restore adapter,
start a service, read a secret, or use the network. The temporary archive is
removed automatically on success, failure, or interruption.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=../../repository
make run SOURCE_REPO=../../repository
```

`SOURCE_REPO` must name a local Git repository containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. The current checkout may point
elsewhere because the wrapper always archives the pinned commit.

Expected final lines include:

```text
[VULNERABLE] manifest_present=false exact_resources=10 family_specimens=5 coverage_complete=true
[+] negative-control missing_family=mariadb coverage_complete=false
[+] safety restore_calls=0 backup_files_read=0 secrets_read=0 services_started=0 network_attempts=0
[+] result=VULNERABLE
```

No manual cleanup is required. If execution is forcibly terminated before the
shell trap runs, remove only the local `poc/.tmp` directory.
