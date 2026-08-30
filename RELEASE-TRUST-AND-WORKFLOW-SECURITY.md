# Release Trust and Workflow Security

## Status

T16 implements the repository-side trust chain for a production release. It is
verified with local negative fixtures and a read-only cryptographic verification
against a public GitHub Artifact Attestation. Applying GitHub governance or
publishing/deploying a platform release remains a separate provider action.

## Trust boundary

Release admission never trusts a JSON field such as `verified: true`. The gate
invokes the image-owned `/usr/local/bin/gh attestation verify` process and binds:

- repository;
- exact signer workflow path;
- full source and signer commit SHA;
- full `refs/heads/*` or `refs/tags/*` source ref;
- GitHub Actions OIDC issuer;
- SLSA provenance v1 predicate;
- GitHub-hosted runner requirement;
- image or file subject SHA256;
- at least one verified transparency-log or timestamp witness.

The normalized JSON/Markdown report is an audit receipt, not a trust input. A
later release gate repeats cryptographic verification against the artifact.

## Online verification

The release workflow calls:

```sh
sh ./scripts/github-attestation-evidence.sh \
  --subject 'oci://ghcr.io/owner/image@sha256:<digest>' \
  --expectedSubjectDigest 'sha256:<digest>' \
  --repo owner/repository \
  --signerWorkflow owner/repository/.github/workflows/release-attestation.yml \
  --sourceDigest '<40-character-commit>' \
  --sourceRef refs/heads/main
```

The token is loaded from the GitHub workflow token or the managed token file.
It is never placed in CLI arguments or evidence.

## Offline verification

Offline verification is supported only with both provider bundle and current
trusted root:

```sh
sh ./scripts/release-artifact-gate.sh \
  --requireProvenance \
  --repo owner/repository \
  --sourceRef refs/heads/main \
  --attestationBundle /secure/path/sha256-digest.jsonl \
  --trustedRoot /secure/path/trusted_root.jsonl
```

A loose in-toto/SLSA statement, a DSSE-looking envelope without cryptographic
verification, a normalized `gh` report, or a commit-check bypass is rejected.

## GitHub governance

`governance/github-branch-protection.json` and
`governance/github-environments.json` are exact policy, not lower bounds. Remote
verification rejects missing or additional status checks, admin/review bypass,
weaker review settings, wrong deployment branch policy, wrong reviewer IDs and
additional reviewers. Production reviewer identities are public governance
metadata and are versioned by immutable GitHub numeric ID.

No provider state changes occur without explicit `--apply`. Use `--verifyRemote`
after the approved provider change and archive the non-secret result.

## Remote workflow input

`scripts/deploy-vps.sh` uses a fixed remote broker command. Every configurable
field is validated before SSH and no workflow input is appended to the remote
command string. The LOCAL_PRIVATE V1 path is separate and consumes the exact
protected-main source lock.

Production deploy admission is currently deny-all. The repository can verify
artifact attestations, but it has no authenticated external producer for
`platform-trusted-deployment-admission/v1`; governance therefore remains
`EXTERNAL-PENDING`. The deployment receipt JSON validator is only a structural
consumer and is not, by itself, producer authentication or a reason to mark the
gate READY.

The remote activation transaction also binds the authenticated release subject
to the exact rendered Compose service and running Docker image ID. It snapshots
the previous normalized Compose model before checkout, rejects persistent mount
or network drift, and uses bounded automatic rollback after the mutation
boundary. Rollback restores the previous UFW/runtime model with no build, pull,
volume deletion or project teardown and verifies the prior image and volume
identities plus the exact previous commit/tree and full running-service image
identity set; rollback failure remains a hard deployment failure. Production
evidence, remote-provider, DR/off-site, go/no-go, WAF and health gates are all
mandatory; omitted or zero-valued flags fail before SSH or remote mutation.
The GitHub production job also has exact, non-skippable dependencies on
enterprise readiness, protected-main release admission and the staging DAST
job. Job success alone is not DAST admission. Release admission must first
select exactly one owner-hash-pinned
`platform-trusted-staging-deployment/v1` receipt from the authenticated external
provider run. That receipt binds the exact repository commit/tree, the canonical
HTTPS staging origin, the artifact receipt, and the complete active runtime
image subject/image-ID set. The DAST job fetches the fixed release-identity
path without redirects, requires the probed bytes and runtime fingerprint to
match the provider receipt, scans only that canonical origin, and emits one
run-bound `platform-dast-verification/v1` receipt containing hashes for the
probe and all ZAP reports. The production job downloads and revalidates that
receipt, including its current workflow producer and freshness, before the
first deployment step. Wrong or stale commit/tree, target, image set, provider
producer, DAST producer, probe, report hash or receipt hash fails closed.

`governance/deployment-admission.json` intentionally leaves both the trusted
provider and canonical staging target `EXTERNAL-PENDING`. Repository fixtures
prove only the local consumer contract; they do not prove that staging was
deployed, probed or scanned. The repository policy also rejects `always()`,
continue-on-error and alternate deployment sinks that could bypass failed or
skipped prerequisites.

Both privileged SSH consumers require an owner-approved exact host:port pin and
a readable, non-symlink dedicated private-key file. They use `BatchMode=yes`,
`IdentitiesOnly=yes`, strict host checking, no global host database and no host
key update, so an ambient agent or default identity cannot become a fallback.

## Tool integrity

The ops image installs GitHub CLI 2.93.0 from an immutable release asset after
checking SHA256
`02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0`.
Changing the version requires updating the checksum, rebuilding the candidate,
rerunning T15/T16 policy tests and producing new cryptographic evidence.

## Verification

```sh
node scripts/release-trust.test.mjs
node --test scripts/dast-runtime-receipt-policy.test.mjs
node scripts/privileged-workflow-policy.test.mjs
node scripts/github-governance-policy.test.mjs
sh scripts/deploy-vps-input-test.sh
sh scripts/deploy-vps-order-test.sh
```

Provider verification for this repository still requires an approved
`release-attestation` run and exact remote branch/environment verification.
Those are T22/T23 live evidence, not grounds for claiming that T16 changed live
GitHub or deployed an image.
