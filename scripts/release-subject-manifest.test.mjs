#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createVerifiedReleaseArtifacts } from "./release-subject-manifest.mjs";
import { resolveRegistryDescriptor } from "./release-registry-resolution.mjs";

const repository = "owner/repo";
const commitSha = "b".repeat(40);
const runtimeDigest = `sha256:${"c".repeat(64)}`;
const descriptor = {
  schemaVersion: 2,
  mediaType: "application/vnd.oci.image.index.v1+json",
  manifests: [
    { mediaType: "application/vnd.oci.image.manifest.v1+json", digest: runtimeDigest, size: 123, platform: { os: "linux", architecture: "amd64" } },
    {
      mediaType: "application/vnd.oci.image.manifest.v1+json", digest: `sha256:${"d".repeat(64)}`, size: 456,
      platform: { os: "unknown", architecture: "unknown" },
      annotations: { "vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": runtimeDigest },
    },
  ],
};
const registryDescriptorBytes = Buffer.from(JSON.stringify(descriptor));
const imageDigest = crypto.createHash("sha256").update(registryDescriptorBytes).digest("hex");
const image = `ghcr.io/owner/platform-infrastructure-php-apache@sha256:${imageDigest}`;
const entries = [{ key: "PHP_APACHE_IMAGE", image }];
const registryResolution = resolveRegistryDescriptor({
  image, descriptorBytes: registryDescriptorBytes, expectedPlatforms: ["linux/amd64"], resolvedAt: "2026-07-21T00:00:00Z",
});
const registryResolutionBytes = Buffer.from(`${JSON.stringify(registryResolution, null, 2)}\n`);
const registryResolutionSha256 = crypto.createHash("sha256").update(registryResolutionBytes).digest("hex");
const buildkitSbom = {
  "linux/amd64": {
    SPDX: {
      spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT", dataLicense: "CC0-1.0",
      documentNamespace: "https://example.invalid/spdx/release", creationInfo: { created: "2026-07-21T00:00:00Z" },
      packages: [{
        SPDXID: "SPDXRef-Package-openssl", name: "openssl", versionInfo: "3.0.0",
        externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:apk/alpine/openssl@3.0.0" }],
      }],
    },
  },
};
const buildkitSbomBytes = Buffer.from(`${JSON.stringify(buildkitSbom)}\n`);
const verification = {
  status: "passed", verified: true, completeness: "complete",
  repository, sourceDigest: commitSha, commitSha, commitShaMatched: true,
  provider: "github-artifact-attestations",
  signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`, sourceRef: "refs/heads/main",
  releaseImages: [image], attestations: [{
    status: "passed", verified: true, completeness: "complete", repository,
    signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`, sourceDigest: commitSha, sourceRef: "refs/heads/main",
    predicateType: "https://slsa.dev/provenance/v1", certOidcIssuer: "https://token.actions.githubusercontent.com",
    certificateFingerprints: ["f".repeat(64)], verifiedTimestampCount: 1,
    subjects: [{ name: "ghcr.io/owner/platform-infrastructure-php-apache", sha256: imageDigest }],
  }],
};

const artifact = createVerifiedReleaseArtifacts({
  entries, repository, commitSha, releaseName: "release", workflowRunId: "1", workflowRunUrl: "https://example.invalid/1",
  verification, buildkitSbom, buildkitSbomBytes, registryResolution, registryResolutionSha256, registryDescriptorBytes,
  expectedPlatforms: ["linux/amd64"], generatedAt: "2026-07-21T00:00:00.000Z", serialNumber: "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
});
assert.equal(artifact.manifest.source, "registry-resolved-cryptographically-verified-subjects");
assert.deepEqual(artifact.manifest.subjects.map((subject) => subject.image), [image]);
assert.deepEqual(artifact.manifest.subjects[0].platforms.map((entry) => entry.platform), ["linux/amd64"]);
assert.match(artifact.manifest.sbom.sha256, /^[a-f0-9]{64}$/);
assert.equal(artifact.sbom.components.filter((component) => component.type === "container").length, 1);
assert.equal(artifact.sbom.components.filter((component) => component.type === "library").length, 1);

const wrong = structuredClone(verification);
wrong.releaseImages = [`ghcr.io/attacker/app@sha256:${imageDigest}`];
assert.throws(() => createVerifiedReleaseArtifacts({
  entries, repository, commitSha, verification: wrong, buildkitSbom, buildkitSbomBytes,
  registryResolution, registryResolutionSha256, registryDescriptorBytes,
}), /subject set/);
process.stdout.write("release subject manifest tests passed 8/8\n");
