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

`enterprise-vps-evidence.yml` and `scripts/deploy-vps.sh` use a fixed remote
command (`bash -s` or `sh -s`). Every configurable field is validated before
SSH, Base64-encoded into a generated script prelude, decoded and validated again
remotely, then passed through quoted arguments or Bash arrays. No workflow input
is appended to the SSH remote command string.

Production deploy admission is currently deny-all. The repository can verify
artifact attestations, but it has no authenticated external producer for
`platform-trusted-deployment-admission/v1`; governance therefore remains
`EXTERNAL-PENDING`. The deployment receipt JSON validator is only a structural
consumer and is not, by itself, producer authentication or a reason to mark the
gate READY.

## Tool integrity

The ops image installs GitHub CLI 2.93.0 from an immutable release asset after
checking SHA256
`02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0`.
Changing the version requires updating the checksum, rebuilding the candidate,
rerunning T15/T16 policy tests and producing new cryptographic evidence.

## Verification

```sh
node scripts/release-trust.test.mjs
node scripts/github-governance-policy.test.mjs
node scripts/vps-evidence-request.test.mjs
sh scripts/deploy-vps-input-test.sh
sh scripts/deploy-vps-order-test.sh
node scripts/t16-policy.mjs
```

Provider verification for this repository still requires an approved
`release-attestation` run and exact remote branch/environment verification.
Those are T22/T23 live evidence, not grounds for claiming that T16 changed live
GitHub or deployed an image.
