# FG-052 offline release-admission ordering PoC

This PoC validates the source and ordering defects tracked as `CAN-133` and
`CAN-142` at the exact affected Git object. It does not use SSH, contact a Git
remote, start Docker, build an image, read credentials, or access a live host.

Requirements are Node.js, Git, `tar`, and a checkout containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc`.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper resolves the supplied checkout to its physical path, verifies the
exact commit and tree, creates a clean `git archive`, records the archive hash,
and runs the probe below an unpredictable ownership sentinel. The probe then
verifies SHA-256 fingerprints for the affected deploy client, exact remote
bootstrap, postdeployment path, pre-go-live wrapper, admission implementation,
and security policy.

For the vulnerable-path demonstration, the exact archived remote bootstrap is
executed with a fake local `git`. The fake branch update installs inert shell
payloads in a synthetic remote directory. The trace proves that the payload's
preflight and preparation scripts and the Compose-shaped sink run without any
admission call. No real Git transport, Compose binary, Docker daemon, network,
or production state is reachable from the fixture.

`trusted-admission-guard.sh` is a reference ordering harness, not a production
cryptographic verifier. It supplies two negative controls: a commit mismatch
must stop before payload execution, and a plan-only admission result must not
count as authorization. A positive ordering control shows that the synthetic
payload is reachable only after an enforcing admission stub returns success.

The probe writes a receipt containing a UTC timestamp, exact input identity,
archive hash, source hashes, pre/post snapshot hashes, trace hash, and control
results. The receipt is reread and hashed before cleanup. A separate cleanup
regression supplies a mismatched token and verifies that sentinel-protected
data is preserved. Recursive removal proceeds only after device, inode,
realpath, and sentinel-content checks; otherwise cleanup fails closed.

Representative output (hashes and timestamp vary only where indicated):

```text
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 archive_sha256=<archive SHA-256>
[+] safety local archive, synthetic branch, fake Git, no SSH, network, Docker, credentials, or live state
[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true
[+] source hashes deploy_client=true remote=true postdeploy=true pre_go_live=true infra_ops=true policy=true
[SOURCE] selected_branch_transmitted=true expected_commit_transmitted=false expected_tree_transmitted=false
[SOURCE] branch_pull_before_candidate_execution=true trusted_admission_before_execution=false
[SOURCE] pre_go_live_release_evidence_plan_only=true artifact_gate_inside_not_plan_only=true plan_step_recorded_pass_on_nonthrow=true
[GUARD] mismatched_cleanup_sentinel_refused=true evidence_preserved=true
[VULNERABLE] fetched_branch_payload_executed=true admission_calls_before_payload=0 compose_sink_reached=true
[NEGATIVE-CONTROL] identity_mismatch_rejected=true payload_executed=false
[NEGATIVE-CONTROL] plan_only_not_admitted=true payload_executed=false
[REFERENCE] enforced_admission_before_payload=true compose_sink_after_admission=true
[RECEIPT] generated_at=<UTC timestamp> sha256=<receipt SHA-256>
[SNAPSHOT] pre_sha256=<SHA-256> post_sha256=<SHA-256>
[+] safety ssh_calls=0 network_calls=0 docker_calls=0 credential_reads=0 live_mutations=0 source_mutations=0
[+] result=VULNERABLE
[+] cleanup sentinel_owned_fixture_removed=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The supplied checkout is read only. All generated files remain below the
wrapper-owned temporary root and are removed after successful verification.
If an ownership check fails, the wrapper prints the retained path rather than
recursively deleting an unverified target.
