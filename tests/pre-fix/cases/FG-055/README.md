# Hosted-workload NATS authorization PoC

This offline PoC demonstrates canonical finding `CAN-129` against exact
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
that contains the revision, but it never reads source from that checkout's
working tree.

## What it proves

The probe verifies seven exact source hashes and imports the archived hosted
workload validator. It constructs two otherwise valid workload services on
separate internal bus networks. The original validator accepts both networks
terminating at the same core NATS service.

The probe separately verifies that NATS starts with one command-line user and
password, while the server configuration defines JetStream but no accounts,
user permission maps, or system account. It then applies NATS's documented
authorization semantics to concrete own-workload, cross-workload, JetStream
administration, and system-subject examples.

`source_policy=allowed` means the pinned source has no account or per-user
subject rule that would deny the operation. The probe does not open a NATS
connection or claim that an application accepted a forged payload. The
`$SYS.>` line proves only that an explicit user-level deny is absent; because
the configuration has no system account, it does not claim that server system
events were emitted or received.

## Safety boundary

The shell wrapper verifies the commit and tree and exports two clean snapshots
with `git archive`. The JavaScript entry point refuses direct invocation
against an arbitrary directory. It requires the wrapper's real temporary root,
an unpredictable ownership sentinel, and the matching token; the source must
be the exact, non-symlink `source` child of that root.

Before the positive run, the wrapper deliberately supplies an invalid token to
a separate guard snapshot. The probe must reject it, and a pre-existing
synthetic file must remain byte-for-byte unchanged. The positive probe hashes
the entire archived tree before and after analysis and rejects any mutation.

The PoC does not invoke NATS, Docker, or Docker Compose; start a service or
container; open a socket; inspect credentials; use SSH; or access live
infrastructure. Cleanup removes only the unpredictable top-level temporary
archive after revalidating the wrapper ownership sentinel. If that sentinel is
missing or changed, cleanup fails closed and prints the retained path for
manual review.

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
[+] verified 7 archived source hashes and NATS authorization source shape
[+] verified NATS global_users=1 password_source=file accounts=0 permissions=0 jetstream=enabled
[+] verified workload policy maps every admitted bus zone to the shared NATS service
[+] admission workloads=2 isolated_bus_networks=2 shared_brokers=1 result=accepted
[BASELINE] own publish=alpha.events.created subscribe=alpha.events.> source_policy=allowed
[VULNERABLE] cross-subscribe actor=alpha target=beta.events.> source_policy=allowed
[VULNERABLE] cross-publish actor=alpha target=beta.jobs.execute source_policy=allowed
[VULNERABLE] jetstream-admin actor=alpha target=$JS.API.STREAM.DELETE.BETA source_policy=allowed runtime_effect=not-executed
[BOUNDARY] system-subject actor=alpha target=$SYS.> explicit_deny=absent runtime_events=not-asserted
[+] summary cross_workload_denials_missing=3 system_subject_deny_missing=true source_tree_unchanged=true
[+] external credential values and active tenancy were not inspected or asserted
[+] no NATS, Docker, Compose, daemon, container, network, credential, SSH, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

Active tenancy and credential distribution remain explicit prerequisites. The
source proves that the platform exposes only one NATS principal; it does not
prove that two currently deployed external workloads possess that credential.
