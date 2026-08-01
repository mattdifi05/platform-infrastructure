# Safe backup-signing trust-transition probe

This probe exercises the vulnerable `sign-existing-postgres-backups` command
against one synthetic, deliberately malformed `.dump` inside a disposable
archive of the pinned vulnerable revision. It demonstrates three states:

1. the unsigned file is rejected by the restore integrity gate;
2. the privileged migration command creates a checksum and valid HMAC sidecar
   without checking PostgreSQL structure or provenance, after which the same
   file passes the integrity gate and reaches the Docker-copy boundary; and
3. modification after signing is still rejected, confirming that the existing
   checksum/HMAC control works for byte integrity but not initial provenance.

The probe cannot be invoked against an arbitrary source directory. The wrapper
creates a private temporary root and an unpredictable 256-bit ownership
sentinel; the probe requires both, resolves every path physically, and proves
that the source archive is the exact `source` child of that root. It rejects a
pre-existing target before any fixture write, creates its unpredictable target
exclusively, and removes it only after revalidating the target and sentinel
device, inode, path, and token.

As a deterministic negative regression, the wrapper places a simulated
pre-existing backup in a separate target before starting the probe. The probe
attempts to claim that target, must reject it, and verifies that its directory
listing and bytes remain unchanged with no generated sidecars. The wrapper
checks the same digest again after the probe returns. That data is removed only
later as part of the wrapper-owned temporary archive, never by the fixture
cleanup routine.

The probe prepends a local fake `docker` executable to `PATH`. That executable
records the attempted arguments and deliberately fails. Real Docker is never
called, `pg_restore` is never executed, no service is started, and no network
request is made. Synthetic files, generated reports, and the deterministic
demonstration key live only inside the sentinel-owned archive.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=../../repository
make run SOURCE_REPO=../../repository
```

`SOURCE_REPO` must be a local Git repository containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. The current checkout may point at
another revision because the wrapper always archives the pinned commit.

Expected final output includes:

```text
[+] unwrapped direct invocation rejected
[+] negative-control preexisting_target_rejected=true backup_preserved=true sha256=04271d397d7c1fb9dd88a38935624796bde6f8d258b7e3b81044d44433416533
[+] confinement source_realpath_exact_child=true wrapper_sentinel_valid=true
[+] negative-control unsigned artifact rejected before Docker
[VULNERABLE] arbitrary_dump_signed=true sha256=1c48b667dbcdd588bd4fe62b009c4fc3073b3b646ebe3b39adc07b17b5cb9283
[VULNERABLE] signature_valid=true key_id=poc-v1 provenance_fields=0
[VULNERABLE] restore_integrity_gate=passed docker_cp_reached=true pg_restore_executed=false
[+] negative-control post-sign modification rejected before Docker
[+] cleanup sentinel_owned_fixture_removed=true preexisting_backup_still_present=true
[+] safety live_docker_calls=0 pg_restore_calls=0 services_started=0 network_attempts=0
[+] result=VULNERABLE
[+] wrapper post-check preexisting_backup_survived=true sha256=04271d397d7c1fb9dd88a38935624796bde6f8d258b7e3b81044d44433416533
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

No manual cleanup is required after a normal run. The wrapper deletes its root
only when the unpredictable ownership sentinel is still a regular file with
the expected path and token. If that validation fails, cleanup deliberately
refuses deletion and prints the exact temporary root for manual inspection.
Normal failures and handled HUP, INT, or TERM signals use the same check. A
SIGKILL or power loss cannot be trapped and may leave a directory beneath
`poc/.tmp`; inspect its ownership sentinel before removing it manually.
