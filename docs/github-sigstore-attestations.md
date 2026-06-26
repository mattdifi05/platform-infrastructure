# GitHub/Sigstore Attestations

Release attestation is handled by GitHub Actions and GitHub Artifact Attestations/Sigstore.

## Workflow

See `.github/workflows/release-attestation.yml`.

Required permissions:

```yaml
contents: read
id-token: write
attestations: write
packages: write
```

`packages: write` is required when pushing images to GHCR.

## Flow

1. Build or pull release images.
2. Push images to GHCR if the workflow owns the image subject.
3. Capture the digest.
4. Generate or attach SBOM.
5. Run `actions/attest-build-provenance`.
6. Publish non-sensitive release evidence artifacts.

## Verification

```sh
gh attestation verify oci://ghcr.io/OWNER/IMAGE@sha256:... --repo OWNER/REPO
```

This does not require DNS, Cloudflare or a public VPS. It does require a real GitHub Actions run and real artifact or image subjects.

## Artifacts

Download the `github-sigstore-release-evidence` artifact from the workflow run and pass it to release evidence checks when required.
