# Safe ops-bootstrap image-trust PoC

This source-pinned PoC executes the exact archived
`scripts/prepare-hosted-workloads.sh` and downstream lock/Compose consumers
without contacting a Docker daemon. A local command sink records both
`docker run` calls and models the code that an untrusted ops image would run.
It writes a synthetic privileged Compose file and a self-consistent verified
lock only inside the wrapper-owned temporary root.

Two offline resolution cases are exercised:

- the mutable default image is absent locally, so Docker's default `missing`
  policy would initiate an implicit pull; and
- the same mutable tag names an unverified local replacement.

The wrapper requires a Git repository containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and verifies tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. It exports only that revision
into a private temporary root, and the probe verifies exact source hashes
before invoking the archived scripts.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected evidence includes:

```text
[VULNERABLE implicit-pull] image=platform/ops:local run_count=2 pull_policy=missing implicit_pull=true forged_lock=verified downstream_compose_included=true
[VULNERABLE local-replacement] image=platform/ops:local run_count=2 image_verified=false forged_lock=verified downstream_compose_included=true
[FIXED ORACLE] exact_digest=accepted mutable_tag=rejected wrong_digest=rejected unverified_local=rejected implicit_pull=rejected
[PASS] negative preservation mismatched sentinel refused deletion and preserved existing data
[SAFE] docker_daemon_calls=0 network=0 pulls=0 containers=0 live_mutations=0 candidate_mutations=0
[+] result=VULNERABLE canonical_id=CAN-131
```

The `docker` sink never opens a socket or performs a pull. The mocked Compose
render returns static JSON, while the exact archived lock verifier checks the
mock image's output and the exact archived Compose wrapper incorporates the
attacker-authored `-f` path into its captured command. No generated Compose
configuration is executed. On macOS, the probe supplies a temporary `BASH_ENV`
implementation of the Bash 4+ `mapfile` builtin required by the archived
Compose wrapper; it does not edit the archived script, and the source hash is
rechecked after execution.

Every recursive cleanup target is a direct child of a verified real directory
and carries an unpredictable ownership sentinel. A negative preservation
regression presents a mismatched sentinel, verifies deletion is refused, and
verifies a foreign file remains unchanged before authorized cleanup. The outer
wrapper independently validates its sentinel before removing its private root.

No Docker daemon, registry, network, provider, public hostname, SSH target,
credential, secret, live service, or repository working-tree file is changed.
No manual cleanup is normally required. If sentinel validation fails, inspect
the printed temporary path before removing anything manually.
