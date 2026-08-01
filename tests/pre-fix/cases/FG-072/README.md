# Safe hosted stop-grace admission PoC

This source-pinned PoC demonstrates that the hosted-workload contract accepts
an attacker-selected `stop_grace_period` without invoking Docker or waiting for
the declared duration. It requires a Git repository containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc`, verifies tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`, and exports only that revision with
`git archive` into a private temporary root.

The probe performs four separate checks:

1. It verifies exact SHA-256 hashes for the contract, its regression suite,
   the render/verification wrapper, the Compose activation wrapper, and the
   go-live orchestrator.
2. It runs the exact archived contract regression suite in an empty,
   non-secret environment and confirms all existing tests still pass.
3. It imports the exact archived validator and submits an otherwise compliant
   rendered workload with `stop_grace_period` values of `24h` and `168h`. Both
   are accepted. A nearby `privileged: true` negative control is rejected,
   proving the target guard is active rather than bypassed wholesale.
4. It applies an illustrative bounded-override oracle that accepts an absent
   field as the platform default, accepts canonical seconds-only overrides from
   1 through 120 seconds, and rejects zero, excessive, compound, leading-zero,
   numeric, and null forms. The 120-second value is a PoC policy example, not a
   claim about the platform's final operational SLA.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected decisive output includes:

```text
[PASS] archived contract regression suite passed=15/15
[NEGATIVE CONTROL existing] privileged=true contract=REJECT
[VULNERABLE] field=stop_grace_period value=24h contract=ACCEPT declared_grace_seconds=86400 engine_wait=NOT_MEASURED
[VULNERABLE] field=stop_grace_period value=168h contract=ACCEPT declared_grace_seconds=604800 engine_wait=NOT_MEASURED
[VALIDATOR SURFACE] field=stop_grace_period value=030s contract=ACCEPT compose_normalization=NOT_TESTED engine_wait=NOT_MEASURED
[FIXED ORACLE] missing=accepted_platform_default safe_30s=accepted max_120s=accepted zero_0s=rejected over_121s=rejected extreme_24h=rejected week_168h=rejected noncanonical_030s=rejected compound_1m=rejected numeric=rejected
[SAFE] docker_cli=0 docker_daemon=0 containers=0 sleeps=0 timers=0 network=0 provider=0 token=0 live_mutations=0 source_mutations=0 working_tree_mutations=0
[+] result=VULNERABLE canonical_id=CAN-211
```

`declared_grace_seconds` is simple fixture arithmetic, not a measured runtime
delay. The probe does not run `docker compose config`, so the `030s` row proves
only that the repository validator has no duration-shape check; it does not
claim that every Compose version preserves that spelling. The standard `24h`
and `168h` cases are the decisive admission evidence. A complete post-fix
closure test must separately use a disposable Engine fixture whose process
ignores the initial stop signal and verify the observed stop remains within the
approved platform deadline.

The wrapper starts Node with an empty environment and supplies no Docker,
provider, SSH, credential, or token context. It does not call Docker, create a
container, sleep, set a timer, or contact the network. All temporary state is a
direct child of a verified private root. Recursive cleanup requires an
unpredictable ownership sentinel; a negative preservation regression supplies
the wrong sentinel, confirms deletion is refused and foreign data survives,
then authorizes removal. No manual cleanup is normally required. If ownership
validation fails, inspect the printed temporary path before removing anything.
