# Safe current-candidate evidence-binding PoC

This source-pinned PoC runs the exact archived production go/no-go evaluator
against synthetic, non-secret JSON evidence. It demonstrates that fresh release
and GitHub evidence for the immediately preceding commit, plus a runtime
fingerprint for that old or a third commit, can be accepted while the evaluator
is explicitly told that the current candidate is newer. It also supplies wrong
tree, repository, and workload-lock identities that the vulnerable consumer
ignores.

The wrapper requires a Git repository containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and verifies tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. It exports that immutable
revision into a private temporary root. The probe verifies exact source hashes,
creates the required reports only inside that archive, and intercepts every
external command name that could otherwise reach Git, Docker, SSH, a provider,
or the network.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected evidence includes:

```text
[VULNERABLE prior-commit] candidate=68cd05895b8d479ffb8167344282e7d922958bfc release=4c04042a6fabc42317e18896b949f16b35102c7a github=4c04042a6fabc42317e18896b949f16b35102c7a runtime=4c04042a6fabc42317e18896b949f16b35102c7a decision=go
[VULNERABLE mixed-identity] release=4c04042a6fabc42317e18896b949f16b35102c7a runtime=15a12a81fa32ef3f1165b23d078d72f1d8bfdc29 wrong_tree=true wrong_repository=true wrong_lock=true decision=go
[NEGATIVE CONTROL stale] targeted_evidence=expired decision=no-go
[FIXED ORACLE] exact=accepted prior_commit=rejected mixed_commit=rejected wrong_tree=rejected stale=rejected
[SAFE] evaluator_external_commands=0 network=0 Docker=0 SSH=0 secrets=0 live_mutations=0 repository_worktree_mutations=0
[+] result=VULNERABLE canonical_ids=CAN-224,CAN-225
```

The probe refuses a source archive that already contains `reports/`. It creates
that directory with an unpredictable ownership sentinel and removes it only
after exact sentinel and realpath checks. Every recursive cleanup is confined
to a direct child of a verified wrapper-owned directory. A negative preservation
regression deliberately supplies a mismatched sentinel, confirms deletion is
refused, and confirms a foreign file survives before authorized cleanup.

No provider, GitHub API, public hostname, Docker daemon, SSH target, credential,
secret, repository working-tree file, or live service is used or changed. No
manual cleanup is normally required. If sentinel validation fails, inspect the
printed temporary path before removing anything manually.
