# FG-062 offline provider-MFA assurance PoC

This PoC validates the source-level assurance gap tracked as `CAN-177` at the
exact affected Git object. It does **not** contact Cloudflare or an identity
provider, read an API token, perform a browser login, inspect a real user, or
claim that the deployed identity provider currently permits weak
authentication.

Requirements are Node.js, Git, `tar`, and a checkout containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc`.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper resolves the supplied checkout to its physical path, verifies the
exact commit and tree, creates clean Git archives, records the archive hash,
and runs below an unpredictable ownership sentinel. The probe verifies source
hashes for the Cloudflare Access verifier, example manifest, go/no-go policy,
security policy, and production go/no-go implementation.

The probe extracts and executes the affected manifest normalizer, evidence
summary, Access application and policy builders, matching functions, and
`verifyRemote()` logic in an isolated JavaScript context. Provider API list
operations are replaced with synthetic app and policy objects; `fetch()` is a
fail-closed trap. The fixture demonstrates only that a matching login-method
selector is labelled `verified` without any MFA authentication-context input
or provider-assurance query. It is not a simulation of Cloudflare's or the
identity provider's real assurance state.

Negative controls show that the local parser rejects a literal `false`, while a
separate reference gate rejects that same manifest boolean as provider proof.
Because this offline package cannot authenticate an issuer, client, method,
authentication context, freshness window, or provider signature, its final MFA
decision remains `PENDING-PROVIDER`. Even a synthetic claim containing those
labels is not accepted as proof.

Before the positive source probe, a preservation guard plants a pre-existing
output directory. The probe refuses it and the wrapper verifies the bytes are
unchanged. Generated output is removed only after realpath, parent-directory,
device, inode, and sentinel-content checks. A failed ownership check preserves
the target.

Representative output:

```text
[GUARD] preexisting_output_rejected=true evidence_preserved=true source_mutations=0
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 archive_sha256=<archive SHA-256>
[+] safety exact source, synthetic API objects, no provider, token, network, browser, identity, or live assurance
[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true
[+] source hashes access_admin=true manifest=true go_no_go=true policy=true infra_ops=true
[SOURCE] manifest_boolean_required=true normalized_provider_evidence_fields=0 evidence_summary_mfa=true
[SOURCE] access_policy_requires_login_method_id=true access_policy_requires_mfa_context=false
[VULNERABLE] synthetic_app_policy_match=verified synthetic_access_list_calls=4 provider_assurance_inputs=0 provider_assurance_queries=0
[CONDITIONAL] weak_provider_path_required=true deployed_provider_state=NOT-TESTED
[NEGATIVE-CONTROL] local_false_rejected=true self_attestation_rejected=true unauthenticated_claim_accepted=false
[REFERENCE] fresh_authenticated_provider_receipt=false decision=pending-provider
[RECEIPT] generated_at=<UTC timestamp> sha256=<receipt SHA-256>
[+] safety live_provider_calls=0 network_calls=0 real_token_reads=0 browser_flows=0 identity_logins=0 live_mutations=0 source_mutations=0
[+] result=VULNERABLE-SOURCE-GAP live_provider_assurance=NOT-TESTED final_gate=PENDING-PROVIDER
[+] cleanup sentinel_owned_output_removed=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The supplied checkout is read only. All temporary data remains under the
wrapper-owned root. A source-level vulnerable result proves the verifier gap;
it does not convert the unresolved provider condition into a claim about live
MFA enforcement.
