# Supply-chain Lock and Build Isolation

Cryptographic release admission, GitHub signer identity and workflow input
handling are defined in `RELEASE-TRUST-AND-WORKFLOW-SECURITY.md`. T15 pins the
bytes and build inputs; T16 proves who produced each release subject and rejects
unsigned or self-asserted evidence.

## Contract

`governance/supply-chain-lock.json` is the reviewed source of truth for
third-party GitHub Actions, container images and downloaded source archives.
Every GitHub Action uses a full commit SHA, every external image uses a
`sha256` digest and every downloaded archive is verified before extraction.

Local first-party build tags such as `platform/backend:local` are development
outputs, not release subjects. Production deployment still requires the
digest-addressed, attested release manifest enforced by the release gate.

## Required checks

```sh
sh ./scripts/supply-chain-lock-check.sh
docker run --rm -v "$PWD:/work" -w /work \
  node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606 \
  node --test scripts/supply-chain-policy.test.mjs
sh ./scripts/build-context-sandbox-test.sh
sh ./scripts/build-daemon-isolation-sandbox-test.sh
sh ./scripts/core-image-supply-chain-test.sh
sh ./scripts/php-runtime-supply-chain-test.sh
sh ./scripts/helper-image-supply-chain-test.sh
sh ./scripts/verify-locked-images.sh
```

The policy test mutates one dependency class at a time and must reject:

- a tag-only GitHub Action;
- a mutable Compose image;
- an Imagick checksum mismatch;
- a Docker socket regression in the browser runner;
- removal of secret/state exclusions from `.dockerignore`;
- drift between a workflow and the lock manifest.

The build-context sandbox uses a disposable scratch image to prove required
source is included while secrets, backup, reports, state and build output are
excluded. The daemon sandbox executes an npm lifecycle hook with no network,
capabilities or Docker socket. It must be unable to find or connect to the
daemon.

The PHP test builds but does not deploy the candidate image. It verifies
Imagick with the expected checksum, confirms errors are hidden from client
output and retained in server error output, then proves an incorrect checksum
stops the build.

## Update procedure

1. Resolve the immutable commit or registry digest from the official source.
2. Review release notes and the source diff from the previously locked value.
3. Update the consumer and lock manifest in the same commit.
4. Run all required checks and archive their non-secret output.
5. Build, attest and verify the first-party release image in T16.
6. Deploy only the approved digest in a separate maintenance window.

Rollback selects the last verified digest and matching lock manifest. It never
reverts to a mutable tag. T15 does not deploy images or restart live services.

## Boundaries

The infrastructure build context is covered here. The external application
monorepo context remains a T18 ownership task. Raw operational Docker socket
access used by the current scheduler/ops wrapper is a T13 isolation task and is
not treated as closed by the browser/build-runner fix.
