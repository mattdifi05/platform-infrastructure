# Safe Cloudflare Access policy-exactness PoC

This PoC demonstrates that the pre-fix Cloudflare Access verifier accepts both
an authorization-broadened expected policy and an untracked sibling bypass
policy. It uses only the synthetic API response document in `fixtures/`.
It never contacts Cloudflare or any other network endpoint.

The wrapper requires a Git repository containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and verifies its tree as
`70031b30316fbaecbb23249491d6ff4e364d65d5`. It exports that immutable
revision into a private wrapper-owned temporary root. The Node probe then
verifies the exact source-file digest, loads an instrumented copy of the pinned
verifier from a sentinel-owned runtime directory, and invokes the original
`verifyRemote` function with an in-process `fetch` substitute.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected evidence includes:

```text
[CONTROL] exact_policy=true target=verified exact_oracle=accepted
[VULNERABLE CAN-126] expected_selector_present=true duplicate=true extra_domain=true everyone=true target=verified exact_oracle=rejected
[VULNERABLE CAN-127] expected_policy_intact=true sibling_decision=bypass policy_count=2 target=verified exact_oracle=rejected
[NEGATIVE CONTROL] expected_selector_missing=true target=failed
[SAFE] provider_requests=0 synthetic_fetch_calls=8 source_mutations=0 live_mutations=0
[+] result=VULNERABLE canonical_ids=CAN-126,CAN-127
```

The probe checks temporary-root realpaths and ownership sentinels before every
recursive removal. Its negative preservation regression deliberately presents
a mismatched sentinel, confirms that cleanup is refused, and confirms that the
pre-existing marker remains unchanged before authorized disposal. The wrapper
also validates its own unpredictable sentinel before removing the outer
temporary root. No provider credential, real token, Docker daemon, SSH target,
live service, or repository working-tree file is read or changed.

No cleanup is normally required. If the wrapper reports that ownership
validation failed, inspect the printed temporary path and remove it only after
confirming that it is the wrapper-created directory.
