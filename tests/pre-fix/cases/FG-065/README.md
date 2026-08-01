# Safe release-subject claim-verification PoC

This PoC demonstrates an evidence-integrity boundary without contacting GitHub,
an OCI registry, or any other network service. It requires a Git repository that
contains commit `68cd05895b8d479ffb8167344282e7d922958bfc`, verifies tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`, and exports only that revision with
`git archive` into a private temporary root.

The test deliberately separates three different operations:

1. **Exact local parsing.** The probe extracts and executes the precise inline
   Node generator from `.github/workflows/release-attestation.yml`. Synthetic
   configured subjects are copied into the generated manifest and SBOM. This
   proves local claim inclusion only; it is not described as registry or
   attestation verification.
2. **Fail-closed verification controls.** The exact archived
   `scripts/release-trust.mjs` rejects self-authored JSON that lacks a
   `verificationResult`. Its real per-image verification function is then
   directed, through the repository's explicit test-mode hook, to a local
   verifier that always exits 86. Rejection proves the verification path fails
   closed. It does not synthesize a successful cryptographic verification.
3. **Fixed acceptance oracle.** A small policy oracle accepts only an exact
   approved repository and digest whose registry resolution, required platform,
   and provenance verification all match. It rejects nonexistent, mutable,
   wrong-repository, wrong-platform, and unattested cases.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected decisive evidence includes:

```text
[LOCAL PARSER VULNERABLE] configured_subjects=5 manifest_included=5 sbom_included=5 registry_queries=0 attestation_verifications=0
[LOCAL PARSER VULNERABLE] nonexistent_reserved_name=included mutable_with_fallback_digest=included wrong_repository=included platform_constraint=discarded unattested_flag=discarded
[NEGATIVE CONTROL self-asserted] local_json=rejected verificationResult=missing cryptographic_verification=false
[NEGATIVE CONTROL verifier] exact_release_verifier=invoked mock_exit=86 result=rejected network=0 token=0
[FIXED ORACLE] exact=accepted nonexistent=rejected mutable=rejected wrong_repository=rejected wrong_platform=rejected unattested=rejected
[SAFE] network=0 provider=0 token=0 registry=0 live_mutations=0 source_mutations=0 working_tree_mutations=0
[+] result=VULNERABLE canonical_id=CAN-192
```

The `.invalid` registry and attestation names are intentionally synthetic. The
wrong-platform and unattested flags are fixture facts that the local generator
discards; the PoC does not claim to have queried remote metadata. The exact
archived source separately contains a stronger deployment-admission control
that calls the per-image verifier when provenance is required, and the probe
prints that countercontrol rather than suppressing it.

The wrapper starts the probe with an empty environment and passes no credential
or token. The only child processes are local Node executions and a local
refusing verifier. Generated manifests, SBOMs, logs, and mock executables stay
inside the wrapper-owned temporary root. Both wrapper and probe require an
unpredictable ownership sentinel before recursive deletion. A negative cleanup
regression supplies the wrong sentinel, confirms deletion is refused and a
foreign file survives, then authorizes removal. No manual cleanup is normally
required; if ownership validation fails, inspect the printed temporary path
before removing anything manually.
