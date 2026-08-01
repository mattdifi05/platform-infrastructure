# Safe hosted-provider binary-lock probe

This source-pinned probe demonstrates `CAN-103` without running Docker Compose,
Docker, a provider helper, a service, or a network request. It imports the real
hosted-workload contract from an archive of the vulnerable revision and proves
that:

1. an otherwise compliant rendered service accepts `provider` with absolute,
   traversal-shaped, and symlinked helper values;
2. the real resolver omits the provider helper and its symlink from the workload
   lock;
3. changing helper bytes and retargeting the symlink do not invalidate the real
   lock verifier; and
4. changing the listed primary Compose file is rejected, confirming that the
   probe exercises the intended lock rather than a mock.

The helper fixtures use mode 0600 and are never executable. The activation
sink is established only by pinned source assertions over the Compose and
remote-deploy wrappers.

The wrapper creates a private temporary root and an unpredictable 256-bit
ownership sentinel. The Node probe resolves the wrapper root, archived source,
and sentinel physically, requires the archive to be the exact `source` child,
and creates files only inside a token-bound fixture directory. Cleanup verifies
the directory and sentinel path, device, inode, file type, and token before
removing that fixture.

As a negative preservation regression, the wrapper creates a separate
pre-existing helper target before invoking the probe. Fixture acquisition must
reject it before any write. The probe preserves and rechecks its directory
listing, device, inode, bytes, and digest; the wrapper checks the digest again
after the probe exits. That pre-existing target is never removed by the fixture
cleanup routine.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=../../repository
make run SOURCE_REPO=../../repository
```

`SOURCE_REPO` has no default and must be a local Git repository containing
commit `68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. The current checkout may point at
another revision; the wrapper always archives the pinned commit.

Expected output includes:

```text
[+] unwrapped direct invocation rejected
[+] negative-control preexisting_target_rejected=true helper_preserved=true sha256=e6436dbefa873635700108e046806995abfcecd6a216338bf6625cabfb89744e
[+] negative-control mutable_image_rejected=true real_contract_gate_exercised=true
[VULNERABLE] provider_field_accepted=true absolute=true traversal=true symlink=true
[VULNERABLE] provider_helper_locked=false lock_records=6
[VULNERABLE] mutable_replacement_survives_lock=true before=394a9bf96a851bc75adda3c96cf3539411fa31639fec7b3dd9aff71512d143bd after=e0f62dd1643546cc3d55e2af49bf8c47351cb733598f2ebeffb04896a51b0db0
[+] negative-control listed_compose_mutation_rejected=true original_bytes_restored=true
[VULNERABLE] symlink_retarget_survives_lock=true
[+] safety helper_executable=false provider_processes_started=0 compose_calls=0 docker_calls=0 services_started=0 network_attempts=0
[+] result=VULNERABLE
[+] cleanup sentinel_owned_fixture_removed=true preexisting_helper_still_present=true
[+] wrapper post-check preexisting_helper_survived=true sha256=e6436dbefa873635700108e046806995abfcecd6a216338bf6625cabfb89744e
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

No manual cleanup is required after a normal run. Normal failures and handled
HUP, INT, or TERM use the same token-checked wrapper cleanup. A SIGKILL or power
failure cannot be trapped and may leave a directory under `poc/.tmp`; inspect
its `.hosted-provider-lock-owner-*` sentinel before removing it manually.
