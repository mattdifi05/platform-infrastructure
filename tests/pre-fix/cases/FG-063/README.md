# Cryptographic admission verification PoC

This offline PoC demonstrates canonical finding `CAN-185` against exact
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It needs a local Git checkout
containing that revision, but it never reads the checkout's working tree.

## What the result means

The probe verifies seven exact source hashes and evaluates a small JavaScript
model of the four rules in the pinned Rego file. The model preserves Rego's
important undefined-reference behavior: directly comparing a missing object
key with `!=` does not make the deny rule succeed. The output labels every such
decision `simulator=source-model` because no OPA runtime is invoked.

The probe demonstrates three affected-policy outcomes:

- omitted verification annotations produce no verification denial;
- requester-supplied expected annotation strings produce no denial without any
  signature or provenance evidence; and
- signer, repository, and subject-digest context is ignored because the Rego
  policy never consumes such context.

Two negative controls show that the model still produces the source policy's
image and explicit-bad-annotation denials.

The archived repository also contains a separate release-verification module.
The probe imports only its argument builder and post-verifier parser. It checks
that repository, workflow, commit, ref, issuer, predicate, and digest bindings
are constructed and that a legacy `{verified: true}` object is rejected. This
is input validation and parsing, not cryptographic verification. The probe
does not call `verifyGithubAttestation()`, `/usr/local/bin/gh`, `cosign`, or any
other verifier.

## Safety boundary

The wrapper verifies the commit and tree and exports clean snapshots with
`git archive`. The JavaScript entry point refuses direct invocation against an
arbitrary directory. It requires the wrapper's real temporary root, an
unpredictable ownership sentinel, and the matching token; the source must be
the exact, non-symlink `source` child of that root.

Before the positive run, the wrapper supplies an invalid token to a separate
guard snapshot. The probe must reject it, and a synthetic pre-existing file
must remain byte-for-byte unchanged. The positive probe hashes the complete
archived source before and after analysis and rejects any mutation.

No OPA process, cryptographic verifier, Docker or Kubernetes component is
started. The PoC does not open a network connection, inspect credentials, use
SSH, submit an admission request, or access live infrastructure. Cleanup
removes only the unpredictable top-level temporary archive after revalidating
its physical path, parent and directory identities, and wrapper sentinel. If
ownership validation fails, cleanup refuses deletion and reports the retained
path.

## Requirements

- Git
- Node.js 20 or newer
- POSIX `sh`, `tar`, `mktemp`, `grep`, and `cmp`

OPA, `gh`, and `cosign` are deliberately not required or invoked.

## Run

From this `poc` directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`SOURCE_REPO` has no default. Uncommitted changes are ignored because the
wrapper reads the pinned commit through Git's object database.

## Expected output

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 7 archived source hashes and admission/release trust source shapes
[+] classified admission_policy=annotation-comparison release_policy_check=static-text
[+] classified release_attestation_path=external-cryptographic-verifier present=true invoked=false
[NEGATIVE-CONTROL] mutable-image deny=2 admitted=false simulator=source-model
[NEGATIVE-CONTROL] explicit-bad-annotations deny=2 admitted=false simulator=source-model
[VULNERABLE] missing-annotations deny=0 admitted=true rego_missing_reference=undefined simulator=source-model
[VULNERABLE] self-asserted-annotations deny=0 admitted=true cryptographic_evidence=absent simulator=source-model
[VULNERABLE] wrong-signer-repository-digest deny=0 admitted=true verification_context=ignored simulator=source-model
[PARSER-CONTROL] legacy_verified_boolean=rejected cryptographic_verification=false
[CRYPTO-BOUNDARY] verifier_args_bound=repository,workflow,source-digest,signer-digest,ref,issuer,predicate,subject-digest executable_invoked=false
[+] summary simulated_policy_bypasses=3 total=3 cryptographic_verifications_executed=0 source_tree_unchanged=true
[+] no OPA, verifier, cosign, Docker, Kubernetes, network, credential, SSH, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The source model demonstrates the vulnerable policy logic; it does not prove
that this Rego file is deployed or that a particular admission controller
interprets its result. Deployment and any earlier trusted annotation-producing
controller remain explicit external prerequisites.
