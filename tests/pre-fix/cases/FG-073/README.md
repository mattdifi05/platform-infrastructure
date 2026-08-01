# Offline hosted-config provenance PoC

This PoC validates the source-level hosted-config gap tracked as `CAN-219` at
the exact affected Git commit and tree. It never reads a platform `.env` file,
secret, provider account, container, or live configuration. It does not invoke
Docker or Docker Compose, deploy a workload, create a config, mount a file, or
contact a network service.

Requirements are Node.js, Git, `tar`, and a checkout containing commit
`68cd05895b8d479ffb8167344282e7d922958bfc`.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper resolves the checkout to its physical path, verifies the exact
commit and tree, and creates a clean Git archive of that commit. Dirty
worktree files are not used. It hashes the archive and runs below a random
wrapper-ownership sentinel.

The probe verifies exact hashes for these source files:

- `scripts/hosted-workload-contract.mjs`;
- `scripts/compose-vps.sh`;
- `scripts/prepare-hosted-workloads.sh`;
- `scripts/hosted-workload-contract.test.mjs`.

It imports `validateWorkloadManifest()` and `validateRenderedWorkloads()` from
the archived candidate and exercises them with the same shape as the checked-in
test fixture. A direct sensitive service-environment value is rejected, and a
file-backed Docker secret that is not external is rejected. Those are the
candidate's closest effective controls.

The probe then adds two otherwise valid hosted config grants:

1. a service `configs` mount backed by a top-level `environment` config; and
2. a service `configs` mount backed by top-level `content` that already
   contains the synthetic materialized value.

Both are accepted because the validator does not inspect service config grants
or top-level config definitions. Every value is a conspicuous synthetic marker.
The probe does not read the real core environment.

An isolated semantic model separately demonstrates the documented transition
from a synthetic environment map or interpolation template to the same bytes
already supplied to the second validator fixture. The model is not Docker
Compose and is labelled accordingly. Actual Compose feature
support, interpolation, config creation, container mounting, and deployment are
all `NOT-EXECUTED`. The final result therefore remains conditional on a literal
sensitive value being present in the shared core environment and a compatible
Compose runtime being used.

The fixed reference gate rejects all environment-backed, inline-content,
external, out-of-root, symlinked, and hash-mismatched config definitions. It
accepts only a contained workload-owned regular file whose expected and actual
SHA-256 values match and whose provenance is immutable. The gate works on
synthetic descriptors and creates no real symlink or external file.

Before the source probe, a preservation guard plants a pre-existing output
directory. The probe must refuse it, and the wrapper verifies its bytes are
unchanged. Generated output is removed only after realpath, device, inode,
token, and sentinel-content checks. Failed ownership validation preserves the
target and fails closed.

Representative output:

```text
[GUARD] preexisting_output_rejected=true evidence_preserved=true source_mutations=0
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 archive_sha256=<archive SHA-256>
[SOURCE] core_env_supplied_to_compose=true service_configs_checked=false top_level_configs_checked=false
[CONTROL] direct_sensitive_service_environment=REJECTED non_external_service_secret=REJECTED
[VULNERABLE] environment_config_accepted=true rendered_content_config_accepted=true
[MODEL] synthetic_environment_to_config_bytes=true synthetic_content_interpolation_to_config_bytes=true runtime=NOT-EXECUTED
[FIXED-CONTROL] platform_variable=REJECTED literal_content=REJECTED external=REJECTED symlink=REJECTED mutable=REJECTED safe_hash_locked_file=ACCEPTED
[CONDITIONAL] literal_sensitive_core_value=NOT-TESTED compose_runtime_materialization=NOT-EXECUTED
[+] result=VULNERABLE-SOURCE-GAP-CONDITIONAL final_gate=PENDING-ENVIRONMENT-AND-RUNTIME
[+] safety core_env_reads=0 secret_reads=0 docker_calls=0 compose_calls=0 deployments=0 mounts=0 network_calls=0 source_mutations=0
[+] cleanup sentinel_owned_output_removed=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The receipt is written only inside the sentinel-owned temporary output,
validated, hashed, and removed. A source-level vulnerable result proves the
validator omission. It does not prove that a real platform secret is stored in
the core env or that the deployed Compose provider materialized the config.
