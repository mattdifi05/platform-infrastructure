# Release Evidence

Release evidence proves that a deployable release is identifiable, reversible and supply-chain auditable.

## Script

```sh
sh ./scripts/release-evidence.sh \
  --imageManifest release/images.json \
  --sbom security/sbom/pnpm-sbom.json \
  --githubAttestation reports/release/github-attestation.json \
  --previousImagesFile release/previous-images.json
```

## Important flags

- `--imageManifest`: current release image subjects.
- `--sbom`: SBOM path.
- `--githubAttestation`: GitHub/Sigstore evidence.
- `--previousImagesFile`: rollback target.
- `--firstDeploy`: allowed only when there is no prior release.

## Provenance levels

- `local-provenance`: partial, useful for diagnostics.
- `github-signed-attestation`: complete for production release evidence.

Failed diagnostic reports do not satisfy production go/no-go.
