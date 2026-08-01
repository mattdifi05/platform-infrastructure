#!/usr/bin/env node
import assert from "node:assert/strict";
import { validatePinnedCycloneDxReleaseSchema, validatePlatformReleaseProfileOnly } from "./cyclonedx-schema-policy.mjs";
import {
  buildReleaseAdmissionReceipt,
  canonicalReleaseSubjects,
  validateAttestedReleaseManifest,
  validateCryptographicReleaseVerification,
  validateCycloneDxReleaseSbom,
} from "./release-artifact-policy.mjs";

const repository = "owner/repo";
const commitSha = "b".repeat(40);
const sourceArchiveSha256 = "0".repeat(64);
const image = `ghcr.io/owner/platform-infrastructure-php-apache@sha256:${"a".repeat(64)}`;
const subjects = canonicalReleaseSubjects([{ key: "PHP_APACHE_IMAGE", image }]);
const sbom = {
  $schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
  version: 1,
  metadata: {
    timestamp: "2026-07-21T00:00:00.000Z",
    component: { type: "application", name: "release", version: commitSha, purl: `pkg:github/${repository}@${commitSha}` },
    properties: [
      { name: "repository", value: repository },
      { name: "commitSha", value: commitSha },
      { name: "workflowRunId", value: "1" },
      { name: "sbom.source", value: "buildkit-attestation-spdx" },
      { name: "buildkitSbomSha256", value: "e".repeat(64) },
      { name: "buildkitPlatforms", value: "linux/amd64" },
      { name: "releaseSubjectCount", value: "1" },
      { name: "buildkitPackageCount", value: "1" },
    ],
  },
  components: [{
    type: "container",
    name: "ghcr.io/owner/platform-infrastructure-php-apache",
    version: `sha256:${"a".repeat(64)}`,
    hashes: [{ alg: "SHA-256", content: "a".repeat(64) }],
    purl: `pkg:oci/ghcr.io/owner/platform-infrastructure-php-apache@sha256:${"a".repeat(64)}`,
    properties: [{ name: "releaseSubjectKey", value: "PHP_APACHE_IMAGE" }],
  }, {
    type: "library",
    "bom-ref": `urn:buildkit-spdx:${"f".repeat(64)}`,
    name: "openssl",
    version: "3.0.0",
    purl: "pkg:apk/alpine/openssl@3.0.0",
    hashes: [{ alg: "SHA-256", content: "b".repeat(64) }],
    properties: [
      { name: "sbom.source", value: "buildkit-attestation-spdx" },
      { name: "buildkit.platform", value: "linux/amd64" },
      { name: "buildkit.spdxId", value: "SPDXRef-Package-openssl" },
      { name: "releaseSubjectImage", value: image },
    ],
  }],
};
const verification = {
  status: "passed",
  verified: true,
  completeness: "complete",
  provider: "github-artifact-attestations",
  repository,
  sourceDigest: commitSha,
  commitSha,
  commitShaMatched: true,
  signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`,
  sourceRef: "refs/heads/main",
  verifiedTimestampCount: 1,
  releaseImages: [image],
  attestations: [{
    status: "passed", verified: true, completeness: "complete", repository,
    signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`,
    sourceDigest: commitSha, sourceRef: "refs/heads/main",
    predicateType: "https://slsa.dev/provenance/v1",
    certOidcIssuer: "https://token.actions.githubusercontent.com",
    certificateFingerprints: ["9".repeat(64)], verifiedTimestampCount: 1,
    subjects: [{ name: "ghcr.io/owner/platform-infrastructure-php-apache", sha256: "a".repeat(64) }],
  }],
};
const registryResolution = {
  version: 2, kind: "platform-registry-subject-resolution/v2",
  status: "passed", image, rootDigest: `sha256:${"a".repeat(64)}`, descriptorSha256: "a".repeat(64),
  platforms: [{
    platform: "linux/amd64", digest: `sha256:${"c".repeat(64)}`, size: 123,
    mediaType: "application/vnd.oci.image.manifest.v1+json", imageId: `sha256:${"1".repeat(64)}`,
    configSize: 321, configMediaType: "application/vnd.oci.image.config.v1+json",
    manifestArtifactSha256: "2".repeat(64), manifestBase64: "e30=",
  }],
};
const resolvedPlatforms = [{
  platform: "linux/amd64",
  digest: `sha256:${"c".repeat(64)}`,
  size: 123,
  mediaType: "application/vnd.oci.image.manifest.v1+json",
  imageId: `sha256:${"1".repeat(64)}`,
  configSize: 321,
  configMediaType: "application/vnd.oci.image.config.v1+json",
  manifestArtifactSha256: "2".repeat(64),
}];
const manifest = {
  version: 3,
  source: "registry-resolved-cryptographically-verified-subjects",
  repository,
  commitSha,
  sbom: { schema: "http://cyclonedx.org/schema/bom-1.5.schema.json", sha256: "d".repeat(64), buildkitSha256: "e".repeat(64) },
  registryResolution: { sha256: "f".repeat(64), descriptorSha256: "c".repeat(64), descriptorArtifactSha256: "a".repeat(64), platforms: ["linux/amd64"] },
  subjects: subjects.map((subject) => ({
    ...subject,
    platforms: resolvedPlatforms.map(({ platform, digest: descriptorDigest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256 }) => ({
      platform, descriptorDigest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256,
    })),
  })),
};
const manifestValidationOptions = {
  subjects,
  repository,
  commitSha,
  sbomSha256: "d".repeat(64),
  buildkitSbomSha256: "e".repeat(64),
  registryResolutionSha256: "f".repeat(64),
  registryDescriptorSha256: "a".repeat(64),
  registryRootDescriptorSha256: "c".repeat(64),
  resolvedPlatforms,
};

let passed = 0;
function test(name, fn) { fn(); passed += 1; process.stdout.write(`ok ${passed} - ${name}\n`); }

test("accepts an exactly bound CycloneDX release SBOM", () => {
  const result = validateCycloneDxReleaseSbom(sbom, { subjects, repository, commitSha, buildkitSbomSha256: "e".repeat(64) });
  assert.equal(result.subjects.length, 1);
  assert.equal(result.dependencyCount, 1);
});
test("rejects SBOM with wrong repository binding", () => {
  const changed = structuredClone(sbom);
  changed.metadata.properties[0].value = "attacker/repo";
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /binding/);
});
test("rejects SBOM missing one release subject", () => {
  const changed = structuredClone(sbom);
  changed.components = changed.components.filter((component) => component.type !== "container");
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /missing one or more exact release subject/);
});
test("accepts dependency components beyond the exact release subject set", () => {
  assert.equal(validateCycloneDxReleaseSbom(sbom, { subjects, repository, commitSha }).dependencyCount, 1);
});
test("rejects an extra unapproved release subject component", () => {
  const changed = structuredClone(sbom);
  const extra = structuredClone(changed.components[0]);
  extra.name = "ghcr.io/attacker/app";
  extra.purl = `pkg:oci/ghcr.io/attacker/app@sha256:${"a".repeat(64)}`;
  extra.properties[0].value = "ATTACKER_IMAGE";
  changed.components.push(extra);
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /unexpected or duplicate/);
});
test("rejects an empty dependency inventory", () => {
  const changed = structuredClone(sbom);
  changed.components = changed.components.filter((component) => component.type === "container");
  changed.metadata.properties.find((property) => property.name === "buildkitPackageCount").value = "0";
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /dependency inventory is empty/);
});
test("rejects a mismatched raw BuildKit SBOM hash", () => {
  assert.throws(() => validateCycloneDxReleaseSbom(sbom, {
    subjects, repository, commitSha, buildkitSbomSha256: "d".repeat(64),
  }), /hash binding/);
});
test("rejects SBOM component with wrong digest", () => {
  const changed = structuredClone(sbom);
  changed.components[0].version = `sha256:${"c".repeat(64)}`;
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /exact image digest/);
});
test("accepts complete exact cryptographic verification", () => {
  assert.equal(validateCryptographicReleaseVerification(verification, { subjects, repository, commitSha }).subjects.length, 1);
});
test("rejects same digest under a different image name", () => {
  const changed = structuredClone(verification);
  changed.releaseImages = [`ghcr.io/attacker/app@sha256:${"a".repeat(64)}`];
  assert.throws(() => validateCryptographicReleaseVerification(changed, { subjects, repository, commitSha }), /subject set/);
});
test("rejects provenance from a different commit", () => {
  const changed = structuredClone(verification);
  changed.sourceDigest = "c".repeat(40);
  assert.throws(() => validateCryptographicReleaseVerification(changed, { subjects, repository, commitSha }), /repository and commit/);
});
test("builds a receipt bound to SBOM and verifier output", () => {
  const receipt = buildReleaseAdmissionReceipt({
    subjects, repository, commitSha, sourceArchiveSha256, sbomSha256: "d".repeat(64), verification, registryResolution,
    manifestVerification: verification.attestations[0], generatedAt: "2026-07-21T00:00:00.000Z",
  });
  assert.equal(receipt.status, "EXTERNAL-PENDING");
  assert.equal(receipt.artifactVerification, "passed");
  assert.equal(receipt.deploymentAdmission, "EXTERNAL-PENDING");
  assert.equal(receipt.sourceArchiveSha256, sourceArchiveSha256);
  assert.match(receipt.provenance.manifestVerificationFingerprint, /^[a-f0-9]{64}$/);
  assert.equal(receipt.generatedAt, "2026-07-21T00:00:00.000Z");
  assert.equal(receipt.subjectVerificationReceipts[0].attestationReference.subject, `oci://${image}`);
  assert.equal(receipt.subjectVerificationReceipts[0].registry.platforms[0].imageId, `sha256:${"1".repeat(64)}`);
});
test("rejects registry evidence without a platform config image ID", () => {
  const changed = structuredClone(registryResolution);
  delete changed.platforms[0].imageId;
  assert.throws(() => buildReleaseAdmissionReceipt({
    subjects, repository, commitSha, sourceArchiveSha256, sbomSha256: "d".repeat(64), verification,
    registryResolution: changed, manifestVerification: verification.attestations[0],
  }), /registry resolution/);
});
test("rejects a receipt without an exact source archive hash", () => {
  assert.throws(() => buildReleaseAdmissionReceipt({
    subjects, repository, commitSha, sbomSha256: "d".repeat(64), verification, registryResolution,
    manifestVerification: verification.attestations[0],
  }), /source archive SHA256/);
});
test("rejects an unapproved release subject key and repository", () => {
  assert.throws(() => validateCryptographicReleaseVerification(verification, {
    subjects: [{ key: "APP_IMAGE", image: `ghcr.io/owner/app@sha256:${"a".repeat(64)}` }], repository, commitSha,
  }), /approved OCI repository/);
});
test("accepts attested manifest with exact registry child platform descriptor", () => {
  assert.equal(validateAttestedReleaseManifest(manifest, manifestValidationOptions).subjects.length, 1);
});
test("rejects attested manifest with wrong child platform", () => {
  const changed = structuredClone(manifest);
  changed.subjects[0].platforms[0].platform = "linux/arm64";
  assert.throws(() => validateAttestedReleaseManifest(changed, manifestValidationOptions), /platform descriptors/);
});
test("attested manifest consumer rejects a different SBOM digest", () => {
  const changedManifest = {
    version: 3,
    source: "registry-resolved-cryptographically-verified-subjects",
    repository,
    commitSha,
    sbom: { schema: "http://cyclonedx.org/schema/bom-1.5.schema.json", sha256: "e".repeat(64), buildkitSha256: "a".repeat(64) },
    registryResolution: { sha256: "b".repeat(64), descriptorSha256: "d".repeat(64), descriptorArtifactSha256: "c".repeat(64), platforms: ["linux/amd64"] },
    subjects: subjects.map((subject) => ({ ...subject, platforms: [{ platform: "linux/amd64", descriptorDigest: `sha256:${"d".repeat(64)}`, size: 1, mediaType: "application/vnd.oci.image.manifest.v1+json" }] })),
  };
  assert.throws(() => validateAttestedReleaseManifest(changedManifest, {
    subjects,
    repository,
    commitSha,
    sbomSha256: "f".repeat(64),
    buildkitSbomSha256: "a".repeat(64),
    registryResolutionSha256: "b".repeat(64),
    registryDescriptorSha256: "c".repeat(64),
    registryRootDescriptorSha256: "d".repeat(64),
    resolvedPlatforms: [{ platform: "linux/amd64", digest: `sha256:${"d".repeat(64)}`, size: 1, mediaType: "application/vnd.oci.image.manifest.v1+json" }],
  }), /authenticate the exact SBOM/);
});
test("rejects an SBOM field outside the pinned strict schema", () => {
  const changed = structuredClone(sbom);
  changed.unreviewedExtension = true;
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /additional properties|unsupported property/);
});
test("rejects a malformed hash through pinned schema validation", () => {
  const changed = structuredClone(sbom);
  changed.components[0].hashes[0].content = "not-a-hash";
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /match pattern/);
});
test("official schema rejects a document that the custom profile alone accepts", () => {
  const changed = structuredClone(sbom);
  changed.serialNumber = `urn:uuid:${"0".repeat(36)}`;
  assert.equal(validatePlatformReleaseProfileOnly(changed), true);
  assert.throws(() => validatePinnedCycloneDxReleaseSchema(changed), /Official CycloneDX 1\.5.*pattern/);
});
process.stdout.write(`release artifact policy tests passed ${passed}/${passed}\n`);
