# Safe project-router `volumes_from` probe

This source-pinned probe demonstrates `CAN-144` without invoking Docker or
Compose, creating a container or mount, reading a real project or credential,
starting a service, or using the network.

The probe:

1. imports and executes the vulnerable revision's real
   `validateRenderedWorkloads()` function;
2. submits an otherwise-compliant hosted service containing
   `volumes_from: [project-router:ro]` and confirms that validation accepts it;
3. executes the revision's secondary runtime-isolation policy and confirms that
   its direct-bind and project-state checks also pass because they inspect only
   `service.volumes`;
4. models the documented Compose inheritance operation over three synthetic,
   read-only project-router mounts and reads four harmless fixture markers;
5. proves that the existing direct-bind control rejects the equivalent direct
   mount;
6. proves that a synthetic fixed guard rejects service inheritance before
   activation while preserving an ordinary workload; and
7. rejects an unresolved inheritance target as a resolver control.

The wrapper requires a caller-supplied local Git repository. It verifies the
exact commit and tree, creates a private temporary root with an unpredictable
256-bit ownership sentinel, and archives the pinned source as that root's exact
physical `source` child. The analyzer verifies a SHA-256 digest for every source
file it uses.

All demonstration files are harmless markers written inside a token-bound
fixture. A separate pre-existing project-state file must be rejected as a probe
target and preserved byte-for-byte. Cleanup revalidates the owned fixture's
physical path, directory and sentinel device/inode, type, and token before
deletion; the wrapper verifies the pre-existing file again afterward.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=../../repository
make run SOURCE_REPO=../../repository
```

`SOURCE_REPO` has no default. It must be a local Git repository containing
commit `68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. The current checkout may differ;
the wrapper archives the pinned object directly.

Expected output includes:

```text
[+] unwrapped direct invocation rejected
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[VULNERABLE] CAN-144 candidate_validator=ACCEPTED volumes_from=project-router:ro direct_volumes=0 protected_service_unchanged=true
[+] secondary_policy direct_bind_check=passed project_state_target_check=passed inherited_mounts_inspected=false
[VULNERABLE] CAN-144 inherited_targets=/app,/var/www/project-state,/var/www/projects inherited_read_only=true readable_fixture_markers=4 peer_source_visible=true state_and_lock_visible=true
[+] negative-control candidate_direct_bind=REJECTED closest_control_active=true
[+] negative-control synthetic_fixed_guard volumes_from=REJECTED baseline_without_inheritance=ACCEPTED fail_closed_before_activation=true
[+] negative-control unknown_inheritance_target=REJECTED resolver_fail_closed=true
[+] safety docker_calls=0 compose_calls=0 containers_started=0 mounts_created=0 real_project_files_read=0 credentials_read=0 services_started=0 network_attempts=0
[+] result=VULNERABLE
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The inherited-mount resolver is a source-only model of the Compose operation;
it does not claim that a container was created. Readability of real files still
depends on host ownership and mode relative to the workload's chosen non-root
UID. The canonical fixture deliberately uses `:ro`, so it demonstrates a
confidentiality boundary violation rather than write access.

Normal completion, ordinary failures, and handled HUP, INT, or TERM use the
same token-checked cleanup. A SIGKILL or power failure cannot be trapped and may
leave a directory under `poc/.tmp`; inspect its
`.project-router-volumes-from-owner-*` sentinel before removing it manually.
