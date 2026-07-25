#!/usr/bin/env node
import assert from "node:assert/strict";
import { validateTrustedDeploymentReceipt } from "./deployment-receipt-policy.mjs";
import { runtimeIntentSha256 } from "./runtime-intent-policy.mjs";

const repository = "owner/repo";
const commitSha = "a".repeat(40);
const treeSha = "b".repeat(40);
const artifactReceiptSha256 = "c".repeat(64);
const manifestSha256 = "d".repeat(64);
const sbomSha256 = "e".repeat(64);
const sourceArchiveSha256 = "0".repeat(64);
const generatedAt = "2026-07-21T00:00:00.000Z";
const image = `ghcr.io/owner/app@sha256:${"f".repeat(64)}`;
const policy = {
  status: "READY",
  trustedVerifierChannel: "external-admission-controller/prod",
  trustedOpsImageRepository: "ghcr.io/owner/platform-infrastructure-ops",
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
  sourceArchiveSha256,
  generatedAt,
  manifestSha256,
  sbomSha256,
  subjects: [{ key: "APP_IMAGE", image }],
  provenance: {
    verificationFingerprint: "1".repeat(64),
    manifestVerificationFingerprint: "2".repeat(64),
  },
};
const runtimeIntent = {
  version: 1,
  kind: "platform-runtime-intent/v1",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256,
  projectName: "platform_infra_vps",
  environmentSha256: "8".repeat(64),
  hostedWorkloadLockSha256: null,
  coreComposeSha256: "9".repeat(64),
  combinedComposeSha256: "0".repeat(64),
  services: [
    {
      service: "app",
      image,
      admission: { kind: "artifact-subject", subjectKey: "APP_IMAGE" },
      expectedLocalImageId: `sha256:${"8".repeat(64)}`,
    },
    {
      service: "backup-scheduler",
      image: `ghcr.io/owner/platform-infrastructure-ops@sha256:${"5".repeat(64)}`,
      admission: { kind: "ops-runner" },
      expectedLocalImageId: `sha256:${"6".repeat(64)}`,
    },
  ],
  targetServingServices: ["app"],
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
  sourceArchiveSha256,
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
  opsRunner: {
    image: `ghcr.io/owner/platform-infrastructure-ops@sha256:${"5".repeat(64)}`,
    imageId: `sha256:${"6".repeat(64)}`,
    verificationFingerprint: "7".repeat(64),
    providerAttested: true,
  },
  runtimeIntent,
  runtimeIntentSha256: runtimeIntentSha256(runtimeIntent),
};
const options = {
  policy, repository, commitSha, treeSha, artifactReceiptSha256, artifactReceipt,
  providerRunId: "123456", providerRunAttempt: "2",
};

assert.equal(validateTrustedDeploymentReceipt(deploymentReceipt, options), deploymentReceipt);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, commitSha: "9".repeat(40) }, options), /repository\/commit\/tree/);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, artifactVerificationReceiptSha256: "8".repeat(64) }, options), /exact artifact/);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, sourceArchiveSha256: "8".repeat(64) }, options), /exact source archive/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, { ...options, sourceArchiveSha256: "8".repeat(64) }), /exact source archive/);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, verifier: { ...deploymentReceipt.verifier, channel: "self" } }, options), /configured external/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, { ...options, policy: { ...policy, status: "EXTERNAL-PENDING", trustedVerifierChannel: null } }), /EXTERNAL-PENDING/);
assert.throws(() => validateTrustedDeploymentReceipt({ ...deploymentReceipt, manifestSha256: "7".repeat(64) }, options), /manifest and SBOM/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, producer: { ...deploymentReceipt.producer, workflowPath: ".github/workflows/attacker.yml" },
}, options), /producer identity/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, { ...options, providerRunAttempt: "1" }), /run identity/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, opsRunner: { ...deploymentReceipt.opsRunner, image: `ghcr.io/owner/attacker@sha256:${"5".repeat(64)}` },
}, options), /ops image/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, runtimeIntent: { ...runtimeIntent, environmentSha256: "7".repeat(64) },
}, options), /canonical runtime intent/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, runtimeIntent: { ...runtimeIntent, services: runtimeIntent.services.slice().reverse() },
}, options), /lexicographically sorted/);

process.stdout.write("deployment receipt policy tests passed 13/13\n");
