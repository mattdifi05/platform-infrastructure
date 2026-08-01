# Safe project-route owner-binding PoC

This source-pinned PoC demonstrates two route-ownership failures in the
pre-fix project router:

- source owned by one workload can create an unregistered route whose upstream
  is a sibling workload's globally allowlisted service; and
- the same source can bind its legitimate service to an arbitrary hostname in
  the public project wildcard namespace.

The wrapper requires a Git repository containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and verifies tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. It exports that immutable
revision into a private temporary root. The probe checks exact source hashes,
copies synthetic project metadata and a version-1 workload lock into an owned
runtime directory, and executes the pinned request handler, discovery, lock,
and upstream-selection functions. It replaces only the final HTTP proxy sink
in the temporary import copy, so no socket or network request is created.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected evidence includes:

```text
[VULNERABLE CAN-145] source=attacker-workload host=rogue.platform-infrastructure.com selected_slug=rogue upstream=http://victim-app:8080/ sibling_owner=victim
[VULNERABLE CAN-150] source=attacker-workload host=unregistered.platform-infrastructure.com selected_slug=attacker upstream=http://attacker-app:8080/ signed_host=false
[FIXED ORACLE] sibling_upstream_claim=rejected arbitrary_wildcard_host=rejected exact_owner_tuple=accepted
[NEGATIVE CONTROL] host=missing.platform-infrastructure.com status=404 upstream=none
[SAFE] network_attempts=0 proxy_sink_intercepted=true source_mutations=0 live_mutations=0
[+] result=VULNERABLE canonical_ids=CAN-145,CAN-150
```

The probe mutates only the wrapper-owned temporary root. Realpath containment
and an unpredictable ownership sentinel guard every recursive removal. A
negative preservation regression presents the wrong sentinel, verifies that
cleanup is refused, and verifies that existing data remains unchanged before
authorized disposal. The wrapper independently validates its root sentinel
before cleanup.

No provider, DNS, public hostname, Docker daemon, SSH target, credential,
secret, repository working-tree file, or live service is used or changed.
No manual cleanup is normally required. If sentinel validation fails, inspect
the printed temporary path before removing anything manually.
