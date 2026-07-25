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
const consumerChallenge = {
  consumerRepository: repository,
  consumerRunId: "7654321",
  consumerRunAttempt: 1,
  consumerJob: "deploy-vps",
  challengeNonce: "9".repeat(64),
};
const generatedAt = "2026-07-21T00:00:00.000Z";
const image = `ghcr.io/owner/app@sha256:${"f".repeat(64)}`;
const schedulerImage = `ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:${"7".repeat(64)}`;
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
  subjects: [
    { key: "APP_IMAGE", image },
    { key: "PLATFORM_BACKUP_SCHEDULER_IMAGE", image: schedulerImage },
  ],
  subjectVerificationReceipts: [
    {
      key: "APP_IMAGE",
      image,
      registry: {
        rootDigest: `sha256:${"f".repeat(64)}`,
        descriptorSha256: "f".repeat(64),
        platforms: [{
          platform: "linux/amd64", digest: `sha256:${"1".repeat(64)}`, size: 100,
          imageId: `sha256:${"8".repeat(64)}`, configSize: 50,
          manifestArtifactSha256: "2".repeat(64),
        }],
      },
    },
    {
      key: "PLATFORM_BACKUP_SCHEDULER_IMAGE",
      image: schedulerImage,
      registry: {
        rootDigest: `sha256:${"7".repeat(64)}`,
        descriptorSha256: "7".repeat(64),
        platforms: [{
          platform: "linux/amd64", digest: `sha256:${"3".repeat(64)}`, size: 100,
          imageId: `sha256:${"6".repeat(64)}`, configSize: 50,
          manifestArtifactSha256: "4".repeat(64),
        }],
      },
    },
  ],
  provenance: {
    verificationFingerprint: "1".repeat(64),
    manifestVerificationFingerprint: "2".repeat(64),
  },
};
const persistentVolumes = [{
  name: "enterprise_local_registry_data",
  createdAt: "2026-07-21T00:00:00.000Z",
  driver: "local",
  scope: "local",
  options: {},
  labels: {
    "platform.infrastructure.managed": "true",
    "platform.infrastructure.purpose": "local-registry",
  },
  mountpoint: "/var/lib/docker/volumes/enterprise_local_registry_data/_data",
  owner: { uid: 0, gid: 0, mode: "0755" },
}];
const runtimeIntent = {
  version: 2,
  kind: "platform-runtime-intent/v2",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256,
  projectName: "platform_infra_vps",
  environmentSha256: "8".repeat(64),
  hostedWorkloadLockSha256: null,
  sourceRenderSha256: "9".repeat(64),
  combinedComposeSha256: "0".repeat(64),
  persistentVolumes,
  services: [
    {
      service: "app",
      image,
      admission: { kind: "artifact-subject", subjectKey: "APP_IMAGE" },
      expectedLocalImageId: `sha256:${"8".repeat(64)}`,
    },
    {
      service: "backup-scheduler",
      image: schedulerImage,
      admission: { kind: "artifact-subject", subjectKey: "PLATFORM_BACKUP_SCHEDULER_IMAGE" },
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
  consumerChallenge,
  opsRunner: {
    image: `ghcr.io/owner/platform-infrastructure-ops@sha256:${"5".repeat(64)}`,
    imageId: `sha256:${"6".repeat(64)}`,
    verificationFingerprint: "7".repeat(64),
    providerAttested: true,
  },
  runtimeIntent,
  runtimeIntentSha256: runtimeIntentSha256(runtimeIntent),
  deploymentTarget: {
    environment: "production",
    host: "vps.example.internal",
    projectName: "platform_infra_vps",
  },
  privilegedRuntime: {
    activationBroker: {
      path: "/usr/local/libexec/platform-activation-broker",
      version: 1,
      sha256: "a".repeat(64),
      providerAttested: true,
    },
    originFirewallHelper: {
      path: "/usr/local/libexec/platform-origin-firewall",
      version: 1,
      sha256: "b".repeat(64),
      providerAttested: true,
    },
    workloadEgressHelper: {
      path: "/usr/local/libexec/platform-workload-egress-firewall",
      version: 1,
      sha256: "c".repeat(64),
      providerAttested: true,
    },
  },
};
const options = {
  policy, repository, commitSha, treeSha, artifactReceiptSha256, artifactReceipt,
  providerRunId: "123456", providerRunAttempt: "2",
  targetHost: "vps.example.internal", environmentSha256: runtimeIntent.environmentSha256,
  consumerChallenge,
  runtimeIntentSha256: deploymentReceipt.runtimeIntentSha256,
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
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, {
  ...options,
  consumerChallenge: { ...consumerChallenge, consumerRunId: "7654322" },
}), /consumer challenge/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, {
  ...options,
  policy: { ...policy, trustedProducer: { ...policy.trustedProducer, repository } },
}), /independent/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, {
  ...options,
  runtimeIntentSha256: "f".repeat(64),
}), /runtime intent binding/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, opsRunner: { ...deploymentReceipt.opsRunner, image: `ghcr.io/owner/attacker@sha256:${"5".repeat(64)}` },
}, options), /ops image/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, runtimeIntent: { ...runtimeIntent, environmentSha256: "7".repeat(64) },
}, options), /canonical runtime intent/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, runtimeIntent: { ...runtimeIntent, services: runtimeIntent.services.slice().reverse() },
}, options), /lexicographically sorted/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt,
  runtimeIntent: {
    ...runtimeIntent,
    services: runtimeIntent.services.map((service) => service.service === "backup-scheduler"
      ? { ...service, expectedLocalImageId: `sha256:${"8".repeat(64)}` }
      : service),
  },
}, options), /platform image ID/);
const wrongArtifactImageId = structuredClone(artifactReceipt);
wrongArtifactImageId.subjectVerificationReceipts[1].registry.platforms[0].imageId = `sha256:${"8".repeat(64)}`;
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, {
  ...options,
  artifactReceipt: wrongArtifactImageId,
}), /platform image ID/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt, deploymentTarget: { ...deploymentReceipt.deploymentTarget, host: "attacker.example" },
}, options), /target host/);
assert.throws(() => validateTrustedDeploymentReceipt({
  ...deploymentReceipt,
  privilegedRuntime: {
    ...deploymentReceipt.privilegedRuntime,
    originFirewallHelper: { ...deploymentReceipt.privilegedRuntime.originFirewallHelper, path: "/tmp/helper" },
  },
}, options), /fixed provider-attested helper/);
assert.throws(() => validateTrustedDeploymentReceipt(deploymentReceipt, {
  ...options, environmentSha256: "0".repeat(64),
}), /environment hash/);

process.stdout.write("deployment receipt policy tests passed 21/21\n");
