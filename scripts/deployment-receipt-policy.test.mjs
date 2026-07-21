#!/usr/bin/env node
import assert from "node:assert/strict";
import { validateTrustedDeploymentReceipt } from "./deployment-receipt-policy.mjs";

const repository = "owner/repo";
const commitSha = "a".repeat(40);
const treeSha = "b".repeat(40);
const artifactReceiptSha256 = "c".repeat(64);
const manifestSha256 = "d".repeat(64);
const sbomSha256 = "e".repeat(64);
const generatedAt = "2026-07-21T00:00:00.000Z";
const image = `ghcr.io/owner/app@sha256:${"f".repeat(64)}`;
const policy = {
  status: "READY",
  trustedVerifierChannel: "external-admission-controller/prod",
  requiredReceiptKind: "platform-trusted-deployment-admission/v1",
  selfAssertedAnnotationsAccepted: false,
  trustedProducer: {
    repository: "owner/trusted-admission",
    workflowPath: ".github/workflows/produce-admission.yml",
    workflowSha: "4".repeat(40),
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
  },
};
const artifactReceipt = {
  version: 1,
  kind: "platform-release-artifact-verification/v1",
  status: "EXTERNAL-PENDING",
  artifactVerification: "passed",
  deploymentAdmission: "EXTERNAL-PENDING",
  usageScope: "artifact-verification-only",
  repository,
  commitSha,
  generatedAt,
  manifestSha256,
  sbomSha256,
  subjects: [{ key: "APP_IMAGE", image }],
  provenance: {
    verificationFingerprint: "1".repeat(64),
    manifestVerificationFingerprint: "2".repeat(64),
  },
};
const deploymentReceipt = {
  version: 1,
  kind: "platform-trusted-deployment-admission/v1",
  status: "READY",
  artifactVerification: "passed",
  deploymentAdmission: "READY",
  repository,
  commitSha,
  treeSha,
  artifactVerificationReceiptSha256: artifactReceiptSha256,
  manifestSha256,
  sbomSha256,
  generatedAt,
  decisionId: "decision:12345678",
  verifier: {
    channel: policy.trustedVerifierChannel,
    fingerprint: "3".repeat(64),
    selfAsserted: false,
    verifiedAt: generatedAt,
  },
  producer: {
    ...policy.trustedProducer,
    runId: "123456",
    runAttempt: 2,
  },
};
const options = {
  policy, repository, commitSha, treeSha, artifactReceiptSha256, artifactReceipt,
  providerRunId: "123456", providerRunAttempt: "2",
};

assert.equal(validateTrustedDeploymentReceipt(deploymentReceipt, options), deploymentReceipt);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, commitSha: "9".repeat(40) }, options), /repository\/commit\/tree/);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, artifactVerificationReceiptSha256: "8".repeat(64) }, options), /exact artifact/);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, verifier: { ...deploymentReceipt.verifier, channel: "self" } }, options), /configured external/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, { ...options, policy: { ...policy, status: "EXTERNAL-PENDING", trustedVerifierChannel: null } }), /EXTERNAL-PENDING/);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, manifestSha256: "7".repeat(64) }, options), /manifest and SBOM/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, producer: { ...deploymentReceipt.producer, workflowPath: ".github/workflows/attacker.yml" },
}, options), /producer identity/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, { ...options, providerRunAttempt: "1" }), /run identity/);

process.stdout.write("deployment receipt policy tests passed 8/8\n");
