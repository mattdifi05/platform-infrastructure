#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { buildActivationRequest, buildTrustedReleaseContext } from "./activation-request.mjs";
import { exactNoHostedLockBytes, validateActivationBundleManifest } from "./activation-bundle.mjs";
import { dastActivationChainSha256 } from "./dast-activation-authorization.mjs";
import { runtimeIntentSha256 } from "./runtime-intent-policy.mjs";

function artifact(document) {
  const bytes = Buffer.from(`${JSON.stringify(document)}\n`, "utf8");
  return {
    document,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    sizeBytes: bytes.length,
  };
}

const repository = "owner/repo";
const commitSha = "a".repeat(40);
const treeSha = "b".repeat(40);
const sourceArchiveSha256 = "c".repeat(64);
const appImage = `ghcr.io/owner/app@sha256:${"d".repeat(64)}`;
const schedulerImage = `ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:${"0".repeat(64)}`;
const schedulerImageId = `sha256:${"1".repeat(64)}`;
const opsImage = `ghcr.io/owner/platform-infrastructure-ops@sha256:${"e".repeat(64)}`;
const opsImageId = `sha256:${"f".repeat(64)}`;
const policyDocument = {
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
const policy = artifact(policyDocument);
const artifactReceiptDocument = {
  version: 1,
  kind: "platform-release-artifact-verification/v1",
  status: "EXTERNAL-PENDING",
  artifactVerification: "passed",
  deploymentAdmission: "EXTERNAL-PENDING",
  usageScope: "artifact-verification-only",
  repository,
  commitSha,
  sourceArchiveSha256,
  generatedAt: "2026-07-21T00:00:00.000Z",
  manifestSha256: "1".repeat(64),
  sbomSha256: "2".repeat(64),
  subjects: [
    { key: "APP_IMAGE", image: appImage },
    { key: "PLATFORM_BACKUP_SCHEDULER_IMAGE", image: schedulerImage },
  ],
  subjectVerificationReceipts: [
    { key: "APP_IMAGE", image: appImage, registry: {
      rootDigest: `sha256:${"d".repeat(64)}`, descriptorSha256: "d".repeat(64),
      platforms: [{ platform: "linux/amd64", digest: `sha256:${"2".repeat(64)}`, size: 100, imageId: `sha256:${"8".repeat(64)}`, configSize: 50, manifestArtifactSha256: "3".repeat(64) }],
    } },
    { key: "PLATFORM_BACKUP_SCHEDULER_IMAGE", image: schedulerImage, registry: {
      rootDigest: `sha256:${"0".repeat(64)}`, descriptorSha256: "0".repeat(64),
      platforms: [{ platform: "linux/amd64", digest: `sha256:${"4".repeat(64)}`, size: 100, imageId: schedulerImageId, configSize: 50, manifestArtifactSha256: "5".repeat(64) }],
    } },
  ],
  provenance: {
    verificationFingerprint: "3".repeat(64),
    manifestVerificationFingerprint: "4".repeat(64),
  },
};
const artifactReceipt = artifact(artifactReceiptDocument);
const runtimeIntent = {
  version: 2,
  kind: "platform-runtime-intent/v2",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256,
  projectName: "platform_infra_vps",
  environmentSha256: "5".repeat(64),
  hostedWorkloadLockSha256: null,
  sourceRenderSha256: "6".repeat(64),
  combinedComposeSha256: "7".repeat(64),
  persistentVolumes: [{
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
  }],
  services: [
    {
      service: "app",
      image: appImage,
      admission: { kind: "artifact-subject", subjectKey: "APP_IMAGE" },
      expectedLocalImageId: `sha256:${"8".repeat(64)}`,
    },
    {
      service: "backup-scheduler",
      image: schedulerImage,
      admission: { kind: "artifact-subject", subjectKey: "PLATFORM_BACKUP_SCHEDULER_IMAGE" },
      expectedLocalImageId: schedulerImageId,
    },
  ],
  targetServingServices: ["app"],
};
const deploymentReceiptDocument = {
  version: 1,
  kind: "platform-trusted-deployment-admission/v1",
  status: "READY",
  artifactVerification: "passed",
  deploymentAdmission: "READY",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256,
  artifactVerificationReceiptSha256: artifactReceipt.sha256,
  manifestSha256: artifactReceiptDocument.manifestSha256,
  sbomSha256: artifactReceiptDocument.sbomSha256,
  generatedAt: "2026-07-21T00:00:00.000Z",
  decisionId: "decision:12345678",
  verifier: {
    channel: policyDocument.trustedVerifierChannel,
    fingerprint: "9".repeat(64),
    selfAsserted: false,
    verifiedAt: "2026-07-21T00:00:00.000Z",
  },
  producer: {
    ...policyDocument.trustedProducer,
    runId: "123456",
    runAttempt: 2,
  },
  opsRunner: {
    image: opsImage,
    imageId: opsImageId,
    verificationFingerprint: "0".repeat(64),
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
const deploymentReceipt = artifact(deploymentReceiptDocument);
const providerMetadataDocument = {
  id: 123456,
  run_attempt: 2,
  repository: { full_name: policyDocument.trustedProducer.repository },
  head_repository: { full_name: policyDocument.trustedProducer.repository },
  path: policyDocument.trustedProducer.workflowPath,
  head_branch: "main",
  head_sha: policyDocument.trustedProducer.workflowSha,
  event: "workflow_dispatch",
  status: "completed",
  conclusion: "success",
};
const providerMetadata = artifact(providerMetadataDocument);
const dastProviderMetadataSha256 = "2".repeat(64);
const dastSigstoreBundleSha256 = "3".repeat(64);
const dastSigstoreSubject = `dast-provider-verification.json@sha256:${"4".repeat(64)}`;
const dastProviderReceiptDocument = {
  version: 1,
  kind: "platform-dast-verification/v1",
  status: "passed",
  repository,
  commitSha,
  treeSha,
  runtimeIntentSha256: deploymentReceiptDocument.runtimeIntentSha256,
  generatedAt: "2026-07-21T00:00:00.000Z",
  target: "https://staging.example.com",
  scanRequestSha256: "a".repeat(64),
  runtimeInventorySha256: "b".repeat(64),
  targetServingInventoryHash: "c".repeat(64),
  reportArtifact: {
    id: "456789",
    name: "dast-scan-request-789012-3",
    archiveSha256: "d".repeat(64),
    repository,
    runId: "789012",
    runAttempt: 3,
  },
  reportEvidenceSha256: "e".repeat(64),
  provider: {
    repository: "owner/trusted-admission",
    workflowPath: ".github/workflows/produce-admission.yml",
    workflowSha: "4".repeat(40),
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
    runId: "987654",
    runAttempt: 2,
    job: "dast-countersign",
  },
  consumerChallenge: {
    consumerRepository: repository,
    consumerRunId: "789012",
    consumerRunAttempt: 3,
    consumerJob: "deploy-vps",
    challengeNonce: "d".repeat(64),
  },
};
const dastProviderReceipt = artifact(dastProviderReceiptDocument);
const dastChain = {
  schema: "platform.docker-dast-chain/v2",
  repository,
  commitSha,
  treeSha,
  target: dastProviderReceiptDocument.target,
  runtimeIntentSha256: deploymentReceiptDocument.runtimeIntentSha256,
  runtimeInventorySha256: dastProviderReceiptDocument.runtimeInventorySha256,
  targetServingInventoryHash: dastProviderReceiptDocument.targetServingInventoryHash,
  consumerChallengeSha256: crypto.createHash("sha256")
    .update((await import("./runtime-intent-policy.mjs")).canonicalJson(dastProviderReceiptDocument.consumerChallenge))
    .digest("hex"),
  scanRequestSha256: dastProviderReceiptDocument.scanRequestSha256,
  providerReceiptSha256: dastProviderReceipt.sha256,
  providerMetadataSha256: dastProviderMetadataSha256,
  providerRunId: dastProviderReceiptDocument.provider.runId,
  providerRunAttempt: dastProviderReceiptDocument.provider.runAttempt,
  reportArtifactId: dastProviderReceiptDocument.reportArtifact.id,
  reportArtifactArchiveSha256: dastProviderReceiptDocument.reportArtifact.archiveSha256,
  reportEvidenceSha256: dastProviderReceiptDocument.reportEvidenceSha256,
  sigstoreBundleSha256: dastSigstoreBundleSha256,
  sigstoreSubject: dastSigstoreSubject,
  verdict: "pass",
};
const dastAuthorizationDocument = {
  schema: "platform-dast-activation-authorization/v1",
  status: "READY",
  consumerChallenge: structuredClone(dastProviderReceiptDocument.consumerChallenge),
  chain: dastChain,
  chainSha256: dastActivationChainSha256(dastChain),
  generatedAt: "2026-07-21T00:01:00.000Z",
};
const dastAuthorization = artifact(dastAuthorizationDocument);
const context = buildTrustedReleaseContext({
  deploymentReceipt: deploymentReceiptDocument,
  artifactReceiptSha256: artifactReceipt.sha256,
  deploymentReceiptSha256: deploymentReceipt.sha256,
  providerMetadataSha256: providerMetadata.sha256,
  dastProviderReceiptSha256: dastProviderReceipt.sha256,
  dastAuthorizationSha256: dastAuthorization.sha256,
  dastChainSha256: dastAuthorizationDocument.chainSha256,
  providerRunId: "123456",
  providerRunAttempt: 2,
  providerChallenge: dastProviderReceiptDocument.consumerChallenge.challengeNonce,
});
const contextSha256 = crypto.createHash("sha256")
  .update(JSON.stringify(context, Object.keys(context).sort()))
  .digest("hex");

// Use the policy's canonical hash through a provisional request context, rather
// than relying on JSON insertion order.
const provisionalContextSha256 = crypto.createHash("sha256")
  .update((await import("./runtime-intent-policy.mjs")).canonicalJson(context))
  .digest("hex");
const requestId = `activation:${deploymentReceipt.sha256}:${provisionalContextSha256}`;
const noHostedSha256 = crypto.createHash("sha256").update(exactNoHostedLockBytes()).digest("hex");
const entryHashes = {
  "artifact-verification.json": artifactReceipt.sha256,
  "combined-compose.json": runtimeIntent.combinedComposeSha256,
  "dast-activation-authorization.json": dastAuthorization.sha256,
  "dast-provider-verification.json": dastProviderReceipt.sha256,
  "environment.env": runtimeIntent.environmentSha256,
  "exact-source-archive.tar": runtimeIntent.sourceArchiveSha256,
  "hosted-workloads.lock.json": noHostedSha256,
  "source-compose.json": runtimeIntent.sourceRenderSha256,
  "trusted-deployment-admission.json": deploymentReceipt.sha256,
  "trusted-provider-run.json": providerMetadata.sha256,
};
const bundleManifestDocument = {
  schema: "platform-activation-bundle-manifest/v2",
  requestId,
  releaseContextSha256: provisionalContextSha256,
  runtimeIntentSha256: deploymentReceiptDocument.runtimeIntentSha256,
  entries: Object.keys(entryHashes).sort().map((name) => ({
    name,
    sha256: entryHashes[name],
    sizeBytes: 1,
  })),
};
const bundleManifest = artifact(bundleManifestDocument);
const bundleManifestSha256 = validateActivationBundleManifest(bundleManifestDocument, {
  requestId,
  releaseContextSha256: provisionalContextSha256,
  runtimeIntentSha256: deploymentReceiptDocument.runtimeIntentSha256,
  expectedEntryHashes: entryHashes,
}).sha256;
const base = {
  policy,
  artifactReceipt,
  artifactReceiptSha256: artifactReceipt.sha256,
  deploymentReceipt,
  deploymentReceiptSha256: deploymentReceipt.sha256,
  providerMetadata,
  providerMetadataSha256: providerMetadata.sha256,
  dastProviderReceipt,
  dastProviderReceiptSha256: dastProviderReceipt.sha256,
  dastAuthorization,
  dastAuthorizationSha256: dastAuthorization.sha256,
  dastProviderMetadataSha256,
  dastSigstoreBundleSha256,
  dastSigstoreSubject,
  bundleManifest,
  releaseBundleDescriptor: {
    schema: "platform-activation-bundle-descriptor/v2",
    sha256: "e".repeat(64),
    sizeBytes: 1024,
    manifestSha256: bundleManifestSha256,
  },
  dockerActivationEnvelope: {
    schema: "platform-docker-runtime-activation-envelope-descriptor/v1",
    sha256: "f".repeat(64),
    sizeBytes: 4096,
    payloadType: "application/vnd.platform.docker-runtime-activation.v2+json",
    runtimeIntentId: "runtime.production",
    generation: 7,
    dastAuthorizationSha256: dastAuthorization.sha256,
    dastChainSha256: dastAuthorizationDocument.chainSha256,
  },
  repository,
  commitSha,
  treeSha,
  targetHost: "vps.example.internal",
  environmentSha256: runtimeIntent.environmentSha256,
  providerRunId: "123456",
  providerRunAttempt: "2",
  consumerRunId: "789012",
  consumerRunAttempt: "3",
  sshPort: "22",
};

const request = buildActivationRequest(base);
assert.equal(request.schema, "platform-activation-request/v3");
assert.equal(request.releaseContext.schema, "platform-trusted-release-context/v3");
assert.equal(request.requestId, requestId);
assert.equal(request.releaseContext.releaseRoot, `/srv/platform-infrastructure/releases/${commitSha}-${sourceArchiveSha256}`);
assert.equal(request.releaseContext.stateRoot, `/srv/platform-infrastructure/release-states/${commitSha}-${sourceArchiveSha256}-${runtimeIntent.environmentSha256}`);
assert.deepEqual(request.releaseContext.subjects.map((entry) => entry.serviceName), ["app", "backup-scheduler"]);
assert.equal(request.releaseContext.subjects[1].imageReference, schedulerImage);
assert.equal(request.releaseContext.subjects[1].imageId, schedulerImageId);
assert.equal(request.releaseContext.runtimeIntentSha256, deploymentReceiptDocument.runtimeIntentSha256);
assert.equal(request.releaseContext.sourceRenderSha256, runtimeIntent.sourceRenderSha256);
assert.equal(request.releaseContext.combinedRenderSha256, runtimeIntent.combinedComposeSha256);
assert.equal(request.releaseContext.provider.challenge, dastProviderReceiptDocument.consumerChallenge.challengeNonce);
assert.equal(request.releaseContext.receipts.dastProviderSha256, dastProviderReceipt.sha256);
assert.equal(request.releaseContext.receipts.dastAuthorizationSha256, dastAuthorization.sha256);
assert.equal(request.releaseContext.dastChainSha256, dastAuthorizationDocument.chainSha256);
assert.match(request.releaseContextSha256, /^[a-f0-9]{64}$/);
assert.equal(request.releaseBundle.manifestSha256, bundleManifestSha256);
assert.equal(request.dockerActivationEnvelope.dastAuthorizationSha256, dastAuthorization.sha256);
assert.equal(request.dockerActivationEnvelope.dastChainSha256, dastAuthorizationDocument.chainSha256);
assert.notEqual(request.releaseBundle.sha256, request.dockerActivationEnvelope.sha256);
assert.notEqual(request.releaseContext.receipts.dastProviderSha256, request.releaseContext.receipts.dastAuthorizationSha256);
assert.notEqual(request.releaseContext.receipts.dastAuthorizationSha256, request.releaseContext.dastChainSha256);
assert.match(request.dockerRuntime.releaseId, /^release\.[a-f0-9]{64}$/);
assert.match(request.dockerRuntime.candidateId, /^candidate\.[a-f0-9]{64}$/);
assert.match(request.dockerRuntime.targetId, /^target\.[a-f0-9]{64}$/);
assert.match(request.dockerRuntime.treeSha256, /^[a-f0-9]{64}$/);
assert.ok(request.requestedOperations.indexOf("verify-persistent-volume-identity") < request.requestedOperations.indexOf("activate-runtime"));
assert.ok(request.requestedOperations.indexOf("apply-origin-firewall") < request.requestedOperations.indexOf("activate-runtime"));
assert.ok(request.requestedOperations.indexOf("apply-workload-egress") < request.requestedOperations.indexOf("activate-runtime"));
assert.equal(request.requestedOperations.at(-1), "rollback-on-failure");
assert.equal(Object.hasOwn(request, "artifacts"), false);
assert.ok(Buffer.byteLength(JSON.stringify(request)) < 1024 * 1024);
assert.throws(() => buildActivationRequest({ ...base, targetHost: "attacker.example" }), /target host/);
assert.throws(() => buildActivationRequest({ ...base, environmentSha256: "f".repeat(64) }), /environment hash/);
assert.throws(() => buildActivationRequest({
  ...base,
  dastProviderReceipt: artifact({ ...dastProviderReceiptDocument, runtimeIntentSha256: "0".repeat(64) }),
}), /input artifacts|runtime intent/);
assert.throws(() => buildActivationRequest({
  ...base,
  releaseBundleDescriptor: { ...base.releaseBundleDescriptor, manifestSha256: "0".repeat(64) },
}), /exact canonical manifest/);
assert.throws(() => buildActivationRequest({
  ...base,
  dockerActivationEnvelope: { ...base.dockerActivationEnvelope, sizeBytes: 3 * 1024 * 1024 },
}), /size/);
assert.throws(() => buildActivationRequest({
  ...base,
  dockerActivationEnvelope: {
    ...base.dockerActivationEnvelope,
    dastAuthorizationSha256: "9".repeat(64),
  },
}), /exact DAST authorization/);
assert.throws(() => buildActivationRequest({
  ...base,
  dockerActivationEnvelope: {
    ...base.dockerActivationEnvelope,
    dastChainSha256: "9".repeat(64),
  },
}), /canonical chain/);
assert.throws(() => buildActivationRequest({
  ...base,
  releaseBundleDescriptor: {
    ...base.releaseBundleDescriptor,
    schema: "platform-activation-bundle-descriptor/v1",
  },
}), /schema/);
assert.throws(() => buildActivationRequest({
  ...base,
  dockerActivationEnvelope: {
    ...base.dockerActivationEnvelope,
    payloadType: "application/vnd.platform.docker-runtime-activation.v1+json",
  },
}), /payload type/);
assert.throws(() => buildActivationRequest({
  ...base,
  releaseBundleDescriptor: {
    ...base.releaseBundleDescriptor,
    sha256: base.dockerActivationEnvelope.sha256,
  },
}), /digests must be distinct/);
const nonCanonicalProviderReceipt = artifact({
  ...dastProviderReceiptDocument,
  provider: { ...dastProviderReceiptDocument.provider, runId: "0987654" },
});
assert.throws(() => buildActivationRequest({
  ...base,
  dastProviderReceipt: nonCanonicalProviderReceipt,
  dastProviderReceiptSha256: nonCanonicalProviderReceipt.sha256,
}), /canonical positive numeric identifier/);
const nonCanonicalReportReceipt = artifact({
  ...dastProviderReceiptDocument,
  reportArtifact: { ...dastProviderReceiptDocument.reportArtifact, id: "0456789" },
});
assert.throws(() => buildActivationRequest({
  ...base,
  dastProviderReceipt: nonCanonicalReportReceipt,
  dastProviderReceiptSha256: nonCanonicalReportReceipt.sha256,
}), /canonical positive numeric identifier/);

assert.match(contextSha256, /^[a-f0-9]{64}$/);
process.stdout.write("activation request policy tests passed 43/43\n");
