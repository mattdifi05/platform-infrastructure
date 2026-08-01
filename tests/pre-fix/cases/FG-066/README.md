# CAN-193 offline `env_file` boundary probe

This PoC demonstrates the admission gap without invoking Docker Compose and
without reading an existing environment or credential file. The wrapper
extracts four source files from the exact affected Git revision, verifies the
commit, tree, and source hashes, and imports the archived contract module.

The probe creates one private fixture under its wrapper-owned temporary
directory. The fixture contains a workload tree and a separate synthetic host
directory. Every environment value is an obvious `SYNTHETIC_CAN193_*` marker.
The read helper accepts only the two exact regular files created by the probe,
requires both their lexical and physical paths to remain inside that fixture,
and refuses all other paths. It never searches for `.env` files or reads the
repository's deployment environment.

## Requirements

- POSIX `sh`, `git`, `tar`, `stat`, and either `shasum` or `sha256sum`;
- Node.js with ECMAScript module and `structuredClone` support;
- a local Git object database containing commit
  `68cd05895b8d479ffb8167344282e7d922958bfc`.

No Docker daemon, Compose plugin, network connection, SSH access, credential,
or running service is required.

## Run

From this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`SOURCE_REPO` is used only for `git rev-parse` and `git archive`. Git runs with
an empty environment, isolated home directory, disabled hooks and replacement
objects, no prompting, and file-only protocol access. The working tree is not
read or modified.

The expected high-signal output is:

```text
[PASS] source proof declared env is locked, service env_file is unhandled, and combined Compose rendering precedes validation
[GUARD] unowned_cleanup_refused=true preexisting_sha256=...
[VULNERABLE CAN-193] case=absolute-external-env-file lock_recorded=false field_present=accepted post_render=accepted fixed_oracle=reject keys=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,CLOUDFLARE_API_KEY
[VULNERABLE] case=relative-traversal physical_outside_workload=true validator=accepted fixed_oracle=reject
[VULNERABLE] case=symlinked-contained-name physical_outside_workload=true validator=accepted fixed_oracle=reject
[CONTROL] case=blocked-terminal-name key=DATABASE_PASSWORD validator=reject
[NEGATIVE CONTROL] case=contained-locked-env-file record_kind=workload-environment validator=accepted fixed_oracle=accepted
[VULNERABLE] case=untracked-env-file-mutation lock_still_valid=true post_render=accepted bytes_changed=true
[RECEIPT] sha256=e5ccd68de23e6b94cdcc71d46bfaf0d617d11cfc18204c830882451d3f84a7f0 scope=wrapper-owned-synthetic-fixture
[SAFE] real_env_reads=0 credentials_read=0 docker_calls=0 network_attempts=0 services_started=0 live_mutations=0 source_mutations=0
[+] cleanup sentinel_owned_fixture_removed=true preexisting_marker_preserved=true
[+] result=VULNERABLE canonical_id=CAN-193
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The exact vulnerable contract performs two independent tasks in the probe:

1. `resolveCatalog()` records the workload's declared environment file but not
   the separate service-level `env_file` named in the locked Compose document.
2. `validateRenderedWorkloads()` accepts a hardened service after synthetic
   `env_file` values have been materialized into its rendered `environment`.

The suffix control proves that the real validator is active by showing that
`DATABASE_PASSWORD` is rejected. The negative control uses the workload's
contained, non-symlink, hash-locked `declared.env`; both the affected validator
and the proposed fixed-policy oracle accept it. Absolute, traversal, symlink,
and post-lock mutation cases are accepted by the affected flow and rejected by
the oracle where applicable.

## Safety and cleanup

The shell wrapper and Node fixture each have a separate ownership sentinel,
parent and device/inode identity checks, an expected direct-child path, and
fail-closed cleanup. The probe first attempts to apply its fixture cleanup
routine to an
unowned control directory and verifies that the marker is unchanged. It then
removes only its sentinel-owned fixture. The wrapper finally removes only its
own verified temporary root.

If ownership validation fails, cleanup is refused rather than broadening the
deletion target. Any retained temporary path is reported on standard error.

## Scope and limitation

This is a safe admission-contract PoC, not a Compose integration test. It uses
a strict, deterministic `KEY=value` materializer for one probe-created file to
model the documented service `env_file` transition, then executes the exact
candidate lock resolver and rendered-service validator. It does not claim to
independently reimplement every Compose parsing, interpolation, precedence, or
multi-file rule.

The source trace establishes that the platform passes workload overlays to
Compose for a combined render before invoking the contract validator. Docker's
Compose reference separately defines service `env_file` as a host file whose
variables are passed to the container. A full regression should therefore run
the fixed pre-render policy against a disposable Compose fixture, but this PoC
does not need or contact a Docker daemon. It makes no assertion about any live
deployment or the existence of a real credential-bearing file.
