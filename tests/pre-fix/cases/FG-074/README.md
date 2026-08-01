# CAN-220 offline OCI runtime admission probe

This PoC tests the source-model admission boundary only. It imports the exact
hosted-workload contract and runtime-isolation policy from the affected Git
revision, adds a service-level `runtime` string to otherwise valid in-memory
models, and records whether each source control accepts the model.

It does **not** ask a Docker daemon which runtimes are registered, create a
container, execute an OCI runtime, or measure an isolation difference. A
source-model acceptance result is therefore not a runtime-exploitation result.

## Requirements

- POSIX `sh`, `git`, `tar`, `stat`, and either `shasum` or `sha256sum`;
- Node.js with ECMAScript module and `structuredClone` support;
- a local Git object database containing commit
  `68cd05895b8d479ffb8167344282e7d922958bfc`.

Docker, Compose, an OCI runtime, network access, SSH, credentials, and running
services are neither required nor contacted.

## Run

From this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies the exact commit and tree, then extracts five source files
with `git archive`. Git runs with an empty environment, isolated home, disabled
hooks and replacement objects, no prompting, and file-only protocol access.
The working tree is not read or changed.

Expected high-signal output is:

```text
[PASS] source proof hosted admission and runtime-isolation policy omit service.runtime while workload overlays reach Compose
[GUARD] unowned_cleanup_refused=true preexisting_sha256=...
[SOURCE-MODEL ACCEPTED CAN-220] case=alternate-short-name value=runsc hosted_contract=accepted isolation_policy=passed fixed_oracle=reject runtime_outcome=unresolved
[SOURCE-MODEL ACCEPTED CAN-220] case=qualified-alternate value=io.containerd.kata.v2 hosted_contract=accepted isolation_policy=passed fixed_oracle=reject runtime_outcome=unresolved
[SOURCE-MODEL ACCEPTED CAN-220] case=unknown-name value=can220-unregistered hosted_contract=accepted isolation_policy=passed fixed_oracle=reject runtime_outcome=unresolved
[SOURCE-MODEL ACCEPTED CAN-220] case=path-like value=/opt/can220/custom-runtime hosted_contract=accepted isolation_policy=passed fixed_oracle=reject runtime_outcome=unresolved
[SOURCE-MODEL ACCEPTED CAN-220] case=case-variant value=RUNC hosted_contract=accepted isolation_policy=passed fixed_oracle=reject runtime_outcome=unresolved
[CONTROL] case=privileged-service hosted_contract=reject
[CONTROL] case=root-workload isolation_policy=failed
[NEGATIVE CONTROL] case=runtime-unset hosted_contract=accepted isolation_policy=passed fixed_oracle=accepted
[NEGATIVE CONTROL] case=exact-default value=runc hosted_contract=accepted isolation_policy=passed fixed_oracle=accepted
[RUNTIME NOT TESTED] docker_calls=0 daemon_inventory_queries=0 containers_created=0 runtimes_executed=0 alternate_registered=unknown isolation_effect=unknown
[RECEIPT] sha256=c6c8b24c2b7629bfd4e1bcaeb22aa17879354f1be89183f10452511aea8d740e scope=source-model-only
[SAFE] docker_calls=0 daemon_queries=0 container_creates=0 runtime_execs=0 network_attempts=0 credentials_read=0 live_mutations=0 source_mutations=0
[+] cleanup sentinel_owned_fixture_removed=true preexisting_marker_preserved=true
[+] result=SOURCE_MODEL_ACCEPTED canonical_id=CAN-220 runtime_validation=NOT_TESTED
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

## What the cases mean

For every non-default value, both exact candidate functions accept the model:

- `validateRenderedWorkloads()` accepts the hosted service;
- `evaluateRuntimeIsolation()` returns `status: "passed"` when invoked on a
  complete synthetic model containing that hosted service;
- a proposed fixed oracle allowing only an omitted runtime or exact `runc`
  rejects the value.

The unknown, path-like, and case-variant cases are diagnostic source-model
tests. They are not claims that Docker accepts those values on a real host. An
unregistered or malformed runtime normally provides a deployment failure, not
an isolation bypass. The alternate short and qualified names are likewise not
claimed to be installed or weaker than the default.

The controls show that the imported checks are active: the hosted contract
rejects `privileged: true`, and the isolation policy fails a root workload. The
negative controls show that a missing `runtime` property and an exact explicit
`runc` value remain accepted under the chosen fixed-policy oracle.

## Safety and cleanup

The probe uses only in-memory Compose-like objects. Its sole writable fixture
contains an ownership sentinel used to test cleanup. Before removing that
fixture, the same cleanup routine is pointed at an unowned control directory;
the probe verifies that the control marker's identity, size, and hash remain
unchanged.

The Node fixture and shell wrapper use separate ownership tokens, expected
direct-child paths, device/inode identities, and non-symlink sentinels. Cleanup
is refused if ownership cannot be proven.

## Runtime boundary

Docker's Compose reference defines `runtime` as the runtime used for a
service's containers. Whether a specific value is usable depends on the Docker
Engine and containerd runtime inventory and configuration. Whether that runtime
weakens, strengthens, or preserves isolation is a second host-specific fact.

This PoC deliberately proves neither fact. A disposable-host integration test
for a fixed release should enumerate the approved daemon default, verify that
unapproved names are rejected before container creation, and then inspect the
created container's selected runtime. No such integration test is performed
here, and no live-runtime conclusion should be inferred.
