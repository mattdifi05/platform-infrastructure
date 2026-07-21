#!/usr/bin/env node
import assert from "node:assert/strict";
import { createVerifiedReleaseArtifacts } from "./release-subject-manifest.mjs";

const repository = "owner/repo";
const commitSha = "b".repeat(40);
const image = `ghcr.io/owner/app@sha256:${"a".repeat(64)}`;
const entries = [{ key: "APP_IMAGE", image }];
const verification = {
  status: "passed", verified: true, completeness: "complete",
  repository, sourceDigest: commitSha, commitSha, commitShaMatched: true,
  releaseImages: [image], attestations: [{}],
};

const artifact = createVerifiedReleaseArtifacts({
  entries, repository, commitSha, releaseName: "release", workflowRunId: "1", workflowRunUrl: "https://example.invalid/1",
  verification, generatedAt: "2026-07-21T00:00:00.000Z", serialNumber: "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
});
assert.equal(artifact.manifest.source, "cryptographically-verified-subjects");
assert.deepEqual(artifact.manifest.subjects.map((subject) => subject.image), [image]);
assert.match(artifact.manifest.sbom.sha256, /^[a-f0-9]{64}$/);
assert.equal(artifact.sbom.components[0].name, "ghcr.io/owner/app");

const wrong = structuredClone(verification);
wrong.releaseImages = [`ghcr.io/attacker/app@sha256:${"a".repeat(64)}`];
assert.throws(() => createVerifiedReleaseArtifacts({ entries, repository, commitSha, verification: wrong }), /subject set/);
process.stdout.write("release subject manifest tests passed 5/5\n");
