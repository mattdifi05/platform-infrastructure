#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  buildReleaseAdmissionReceipt,
  canonicalReleaseSubjects,
  validateCryptographicReleaseVerification,
  validateCycloneDxReleaseSbom,
} from "./release-artifact-policy.mjs";

const repository = "owner/repo";
const commitSha = "b".repeat(40);
const image = `ghcr.io/owner/app@sha256:${"a".repeat(64)}`;
const subjects = canonicalReleaseSubjects([{ key: "APP_IMAGE", image }]);
const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
  version: 1,
  metadata: {
    timestamp: "2026-07-21T00:00:00.000Z",
    component: { type: "application", name: "release", version: commitSha, purl: `pkg:github/${repository}@${commitSha}` },
    properties: [{ name: "repository", value: repository }, { name: "commitSha", value: commitSha }],
  },
  components: [{
    type: "container",
    name: "ghcr.io/owner/app",
    version: `sha256:${"a".repeat(64)}`,
    hashes: [{ alg: "SHA-256", content: "a".repeat(64) }],
    purl: `pkg:oci/ghcr.io/owner/app@sha256:${"a".repeat(64)}`,
    properties: [{ name: "releaseSubjectKey", value: "APP_IMAGE" }],
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
  attestations: [{}],
};

let passed = 0;
function test(name, fn) { fn(); passed += 1; process.stdout.write(`ok ${passed} - ${name}\n`); }

test("accepts an exactly bound CycloneDX release SBOM", () => {
  assert.equal(validateCycloneDxReleaseSbom(sbom, { subjects, repository, commitSha }).subjects.length, 1);
});
test("rejects SBOM with wrong repository binding", () => {
  const changed = structuredClone(sbom);
  changed.metadata.properties[0].value = "attacker/repo";
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /binding/);
});
test("rejects SBOM missing one release subject", () => {
  const changed = structuredClone(sbom);
  changed.components = [];
  assert.throws(() => validateCycloneDxReleaseSbom(changed, { subjects, repository, commitSha }), /exactly match/);
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
  const receipt = buildReleaseAdmissionReceipt({ subjects, repository, commitSha, sbomSha256: "d".repeat(64), verification });
  assert.equal(receipt.status, "passed");
  assert.equal(receipt.deploymentAdmission, "EXTERNAL-PENDING");
});
process.stdout.write(`release artifact policy tests passed ${passed}/${passed}\n`);
