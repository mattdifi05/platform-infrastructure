#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateActivationBundleManifest, exactNoHostedLockBytes } from "./activation-bundle.mjs";
import { validateDastActivationAuthorization } from "./dast-activation-authorization.mjs";
import { validateTrustedDeploymentReceipt } from "./deployment-receipt-policy.mjs";
import { canonicalJson, runtimeIntentSha256 } from "./runtime-intent-policy.mjs";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";
import { validateTrustedProviderRun } from "./trusted-provider-run-policy.mjs";

const REQUEST_MAX_BYTES = 1024 * 1024;
const DOCKER_ACTIVATION_ENVELOPE_MAX_BYTES = 2 * 1024 * 1024;
const DOCKER_ACTIVATION_PAYLOAD_TYPE = "application/vnd.platform.docker-runtime-activation.v2+json";

function invalid(message) {
  throw new Error(message);
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object.`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactSha256(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one lowercase SHA256.`);
  return text;
}

function exactPositiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum) {
    invalid(`${label} must be a bounded positive integer.`);
  }
  return number;
}

function exactDecimalId(value, label) {
  const text = String(value ?? "");
  if (!/^[1-9][0-9]*$/.test(text)) invalid(`${label} must be one canonical positive numeric identifier.`);
  const number = Number(text);
  if (!Number.isSafeInteger(number) || String(number) !== text) {
    invalid(`${label} must remain within the exact safe integer identity range.`);
  }
  return text;
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--")) invalid(`Invalid or missing value for ${key ?? "argument"}.`);
    if (Object.hasOwn(result, key.slice(2))) invalid(`Duplicate argument ${key}.`);
    result[key.slice(2)] = value;
  }
  return result;
}

function exactDastProviderBinding(receipt, {
  repository,
  commitSha,
  treeSha,
  runtimeIntentSha256,
  consumerRunId,
  consumerRunAttempt,
}) {
  if (
    receipt?.version !== 1
    || receipt?.kind !== "platform-dast-verification/v1"
    || receipt?.status !== "passed"
    || receipt.repository !== repository
    || receipt.commitSha !== commitSha
    || receipt.treeSha !== treeSha
    || receipt.runtimeIntentSha256 !== runtimeIntentSha256
  ) {
    invalid("Provider DAST receipt does not bind the exact candidate commit, tree and runtime intent.");
  }
  exactObject(receipt.consumerChallenge, "DAST consumer challenge", [
    "challengeNonce",
    "consumerJob",
    "consumerRepository",
    "consumerRunAttempt",
    "consumerRunId",
  ]);
  const challenge = receipt.consumerChallenge;
  if (
    challenge.consumerRepository !== repository
    || challenge.consumerJob !== "deploy-vps"
    || String(challenge.consumerRunId) !== String(exactPositiveInteger(consumerRunId, "consumer run ID"))
    || challenge.consumerRunAttempt !== exactPositiveInteger(consumerRunAttempt, "consumer run attempt")
  ) {
    invalid("DAST consumer challenge does not bind the exact current deploy-vps run.");
  }
  const consumerChallenge = {
    consumerRepository: repository,
    consumerRunId: String(challenge.consumerRunId),
    consumerRunAttempt: challenge.consumerRunAttempt,
    consumerJob: "deploy-vps",
    challengeNonce: exactSha256(challenge.challengeNonce, "DAST consumer challenge nonce"),
  };
  exactObject(receipt.reportArtifact, "Provider DAST report artifact", [
    "id",
    "name",
    "archiveSha256",
    "repository",
    "runId",
    "runAttempt",
  ]);
  exactObject(receipt.provider, "Provider DAST producer", [
    "event",
    "job",
    "repository",
    "runAttempt",
    "runId",
    "sourceRef",
    "workflowPath",
    "workflowSha",
  ]);
  return {
    repository: receipt.repository,
    commitSha: receipt.commitSha,
    treeSha: receipt.treeSha,
    target: receipt.target,
    runtimeIntentSha256: exactSha256(receipt.runtimeIntentSha256, "DAST runtime intent SHA256"),
    runtimeInventorySha256: exactSha256(receipt.runtimeInventorySha256, "DAST runtime inventory SHA256"),
    targetServingInventoryHash: exactSha256(
      receipt.targetServingInventoryHash,
      "DAST target-serving inventory SHA256",
    ),
    consumerChallenge,
    scanRequestSha256: exactSha256(receipt.scanRequestSha256, "DAST scan request SHA256"),
    providerRunId: exactDecimalId(receipt.provider.runId, "DAST provider run ID"),
    providerRunAttempt: exactPositiveInteger(receipt.provider.runAttempt, "DAST provider run attempt"),
    reportArtifactId: exactDecimalId(receipt.reportArtifact.id, "DAST report artifact ID"),
    reportArtifactArchiveSha256: exactSha256(
      receipt.reportArtifact.archiveSha256,
      "DAST report artifact archive SHA256",
    ),
    reportEvidenceSha256: exactSha256(receipt.reportEvidenceSha256, "DAST report evidence SHA256"),
  };
}

function exactReleaseBundleDescriptor(value) {
  exactObject(value, "Release bundle descriptor", [
    "schema",
    "sha256",
    "sizeBytes",
    "manifestSha256",
  ]);
  if (value.schema !== "platform-activation-bundle-descriptor/v2") {
    invalid("Release bundle descriptor schema is invalid.");
  }
  return {
    schema: value.schema,
    sha256: exactSha256(value.sha256, "release bundle SHA256"),
    sizeBytes: exactPositiveInteger(value.sizeBytes, "release bundle size", 384 * 1024 * 1024),
    manifestSha256: exactSha256(value.manifestSha256, "release bundle manifest SHA256"),
  };
}

function exactDockerActivationEnvelopeDescriptor(value) {
  exactObject(value, "Docker activation envelope descriptor", [
    "schema",
    "sha256",
    "sizeBytes",
    "payloadType",
    "runtimeIntentId",
    "generation",
    "dastAuthorizationSha256",
    "dastChainSha256",
  ]);
  if (value.schema !== "platform-docker-runtime-activation-envelope-descriptor/v1") {
    invalid("Docker activation envelope descriptor schema is invalid.");
  }
  if (value.payloadType !== DOCKER_ACTIVATION_PAYLOAD_TYPE) {
    invalid("Docker activation envelope payload type is invalid.");
  }
  const runtimeIntentId = String(value.runtimeIntentId ?? "");
  if (!/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(runtimeIntentId)) {
    invalid("Docker activation envelope runtime intent ID is invalid.");
  }
  return {
    schema: value.schema,
    sha256: exactSha256(value.sha256, "Docker activation envelope SHA256"),
    sizeBytes: exactPositiveInteger(
      value.sizeBytes,
      "Docker activation envelope size",
      DOCKER_ACTIVATION_ENVELOPE_MAX_BYTES,
    ),
    payloadType: value.payloadType,
    runtimeIntentId,
    generation: exactPositiveInteger(value.generation, "Docker activation generation"),
    dastAuthorizationSha256: exactSha256(
      value.dastAuthorizationSha256,
      "Docker activation DAST authorization SHA256",
    ),
    dastChainSha256: exactSha256(value.dastChainSha256, "Docker activation DAST chain SHA256"),
  };
}

function dockerLogicalIdentity(prefix, value) {
  return `${prefix}.${crypto.createHash("sha256")
    .update(`platform-docker-${prefix}/v1\0`, "utf8")
    .update(String(value), "utf8")
    .digest("hex")}`;
}

export function buildTrustedReleaseContext({
  deploymentReceipt,
  artifactReceiptSha256,
  deploymentReceiptSha256,
  providerMetadataSha256,
  dastProviderReceiptSha256,
  dastAuthorizationSha256,
  dastChainSha256,
  providerRunId,
  providerRunAttempt,
  providerChallenge,
}) {
  const intent = deploymentReceipt.runtimeIntent;
  const releaseId = `${intent.commitSha}-${intent.sourceArchiveSha256}`;
  const stateId = `${releaseId}-${intent.environmentSha256}`;
  const releaseRoot = `/srv/platform-infrastructure/releases/${releaseId}`;
  const stateRoot = `/srv/platform-infrastructure/release-states/${stateId}`;
  const subjects = intent.services.map((service) => ({
    serviceName: service.service,
    imageReference: service.image,
    imageId: service.expectedLocalImageId,
  })).sort((left, right) => left.serviceName.localeCompare(right.serviceName));
  return {
    schema: "platform-trusted-release-context/v3",
    repository: intent.repository,
    commitSha: intent.commitSha,
    treeSha: intent.treeSha,
    sourceArchiveSha256: intent.sourceArchiveSha256,
    releaseId,
    releaseRoot,
    stateId,
    stateRoot,
    environmentFile: `${stateRoot}/environment.env`,
    environmentSha256: intent.environmentSha256,
    projectName: intent.projectName,
    decisionId: deploymentReceipt.decisionId,
    provider: {
      metadataSha256: exactSha256(providerMetadataSha256, "provider metadata SHA256"),
      runId: String(exactPositiveInteger(providerRunId, "provider run ID")),
      attempt: exactPositiveInteger(providerRunAttempt, "provider run attempt"),
      challenge: exactSha256(providerChallenge, "provider challenge"),
    },
    receipts: {
      artifactSha256: exactSha256(artifactReceiptSha256, "artifact receipt SHA256"),
      deploymentSha256: exactSha256(deploymentReceiptSha256, "deployment receipt SHA256"),
      dastProviderSha256: exactSha256(dastProviderReceiptSha256, "provider DAST receipt SHA256"),
      dastAuthorizationSha256: exactSha256(dastAuthorizationSha256, "DAST authorization SHA256"),
    },
    dastChainSha256: exactSha256(dastChainSha256, "DAST chain SHA256"),
    runtimeIntentSha256: runtimeIntentSha256(intent),
    subjects,
    hostedLockSha256: intent.hostedWorkloadLockSha256,
    noHosted: intent.hostedWorkloadLockSha256 === null,
    sourceRenderSha256: intent.sourceRenderSha256,
    combinedRenderSha256: intent.combinedComposeSha256,
    persistentVolumes: intent.persistentVolumes,
  };
}

export function buildActivationRequest({
  policy,
  artifactReceipt,
  artifactReceiptSha256,
  deploymentReceipt,
  deploymentReceiptSha256,
  providerMetadata,
  providerMetadataSha256,
  dastProviderReceipt,
  dastProviderReceiptSha256,
  dastAuthorization,
  dastAuthorizationSha256,
  dastProviderMetadataSha256,
  dastSigstoreBundleSha256,
  dastSigstoreSubject,
  bundleManifest,
  releaseBundleDescriptor,
  dockerActivationEnvelope,
  repository,
  commitSha,
  treeSha,
  targetHost,
  environmentSha256,
  providerRunId,
  providerRunAttempt,
  consumerRunId,
  consumerRunAttempt,
  sshPort,
}) {
  validateTrustedProviderRun(providerMetadata.document, {
    policy: policy.document,
    runId: providerRunId,
    runAttempt: providerRunAttempt,
    deploymentReceipt: deploymentReceipt.document,
  });
  validateTrustedDeploymentReceipt(deploymentReceipt.document, {
    policy: policy.document,
    repository,
    commitSha,
    treeSha,
    artifactReceiptSha256,
    artifactReceipt: artifactReceipt.document,
    sourceArchiveSha256: artifactReceipt.document.sourceArchiveSha256,
    providerRunId,
    providerRunAttempt,
    targetHost,
    environmentSha256,
  });
  if (
    artifactReceipt.sha256 !== exactSha256(artifactReceiptSha256, "artifact receipt SHA256")
    || deploymentReceipt.sha256 !== exactSha256(deploymentReceiptSha256, "deployment receipt SHA256")
    || providerMetadata.sha256 !== exactSha256(providerMetadataSha256, "provider metadata SHA256")
    || dastProviderReceipt.sha256 !== exactSha256(dastProviderReceiptSha256, "provider DAST receipt SHA256")
    || dastAuthorization.sha256 !== exactSha256(dastAuthorizationSha256, "DAST authorization SHA256")
  ) {
    invalid("One or more activation input artifacts differ from their exact expected SHA256.");
  }
  const dastBinding = exactDastProviderBinding(dastProviderReceipt.document, {
    repository,
    commitSha,
    treeSha,
    runtimeIntentSha256: deploymentReceipt.document.runtimeIntentSha256,
    consumerRunId,
    consumerRunAttempt,
  });
  const intent = deploymentReceipt.document.runtimeIntent;
  validateDastActivationAuthorization(dastAuthorization.document, {
    ...dastBinding,
    providerReceiptSha256: dastProviderReceiptSha256,
    providerMetadataSha256: exactSha256(
      dastProviderMetadataSha256,
      "DAST provider metadata SHA256",
    ),
    sigstoreBundleSha256: exactSha256(dastSigstoreBundleSha256, "DAST Sigstore bundle SHA256"),
    sigstoreSubject: String(dastSigstoreSubject ?? ""),
  });
  const dastChainSha256 = exactSha256(
    dastAuthorization.document.chainSha256,
    "DAST authorization chain SHA256",
  );
  const port = exactPositiveInteger(sshPort, "SSH port", 65535);
  const context = buildTrustedReleaseContext({
    deploymentReceipt: deploymentReceipt.document,
    artifactReceiptSha256,
    deploymentReceiptSha256,
    providerMetadataSha256,
    dastProviderReceiptSha256,
    dastAuthorizationSha256,
    dastChainSha256,
    providerRunId,
    providerRunAttempt,
    providerChallenge: dastBinding.consumerChallenge.challengeNonce,
  });
  const contextSha256 = crypto.createHash("sha256").update(canonicalJson(context)).digest("hex");
  const requestId = `activation:${deploymentReceiptSha256}:${contextSha256}`;
  const expectedHostedLockSha256 = intent.hostedWorkloadLockSha256
    ?? crypto.createHash("sha256").update(exactNoHostedLockBytes()).digest("hex");
  const expectedEntryHashes = {
    "artifact-verification.json": artifactReceiptSha256,
    "combined-compose.json": intent.combinedComposeSha256,
    "dast-activation-authorization.json": dastAuthorizationSha256,
    "dast-provider-verification.json": dastProviderReceiptSha256,
    "environment.env": intent.environmentSha256,
    "exact-source-archive.tar": intent.sourceArchiveSha256,
    "hosted-workloads.lock.json": expectedHostedLockSha256,
    "source-compose.json": intent.sourceRenderSha256,
    "trusted-deployment-admission.json": deploymentReceiptSha256,
    "trusted-provider-run.json": providerMetadataSha256,
  };
  const manifestValidation = validateActivationBundleManifest(bundleManifest.document, {
    requestId,
    releaseContextSha256: contextSha256,
    runtimeIntentSha256: deploymentReceipt.document.runtimeIntentSha256,
    expectedEntryHashes,
  });
  const releaseBundle = exactReleaseBundleDescriptor(releaseBundleDescriptor);
  if (releaseBundle.manifestSha256 !== manifestValidation.sha256) {
    invalid("Release bundle descriptor does not bind the exact canonical manifest.");
  }
  const envelope = exactDockerActivationEnvelopeDescriptor(dockerActivationEnvelope);
  if (
    envelope.dastAuthorizationSha256 !== dastAuthorizationSha256
    || envelope.dastChainSha256 !== dastChainSha256
  ) {
    invalid("Docker activation envelope does not bind the exact DAST authorization and canonical chain.");
  }
  const semanticDigests = [
    releaseBundle.sha256,
    envelope.sha256,
    dastProviderReceiptSha256,
    dastAuthorizationSha256,
    dastChainSha256,
  ];
  if (new Set(semanticDigests).size !== semanticDigests.length) {
    invalid("Release bundle, activation envelope, provider receipt, authorization and chain digests must be distinct.");
  }
  const dockerRuntime = {
    releaseId: dockerLogicalIdentity("release", context.releaseId),
    candidateId: dockerLogicalIdentity("candidate", context.stateId),
    targetId: dockerLogicalIdentity("target", deploymentReceipt.document.deploymentTarget.host),
    treeSha256: crypto.createHash("sha256")
      .update("platform-git-tree-sha1/v1\0", "utf8")
      .update(context.treeSha, "utf8")
      .digest("hex"),
  };
  const request = {
    schema: "platform-activation-request/v3",
    requestId,
    deploymentTarget: deploymentReceipt.document.deploymentTarget,
    sshPort: port,
    releaseContext: context,
    releaseContextSha256: contextSha256,
    runtimeIntentSha256: deploymentReceipt.document.runtimeIntentSha256,
    privilegedRuntime: deploymentReceipt.document.privilegedRuntime,
    releaseBundle,
    dockerActivationEnvelope: envelope,
    dockerRuntime,
    requestedOperations: [
      "authenticate-request-and-provider-sidecar",
      "lock-global-activation",
      "verify-active-selector-cas",
      "open-and-verify-bundle-cas",
      "materialize-immutable-release",
      "verify-source-to-final-render",
      "pull-and-inspect-all-images",
      "verify-persistent-volume-identity",
      "apply-origin-firewall",
      "apply-workload-egress",
      "activate-runtime",
      "verify-runtime-inventory",
      "publish-selector-and-receipt",
      "rollback-on-failure",
    ],
  };
  const requestBytes = Buffer.from(canonicalJson(request), "utf8");
  if (requestBytes.length > REQUEST_MAX_BYTES) invalid("Activation request exceeds the broker stdin boundary.");
  return request;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const snapshots = [];
  try {
    const policy = snapshotJsonArtifact(options.policy, { label: "deployment admission policy", maxBytes: 1024 * 1024 });
    const artifactReceipt = snapshotJsonArtifact(options.artifactReceipt, { label: "artifact verification receipt", maxBytes: 16 * 1024 * 1024 });
    const deploymentReceipt = snapshotJsonArtifact(options.deploymentReceipt, { label: "trusted deployment receipt", maxBytes: 16 * 1024 * 1024 });
    const providerMetadata = snapshotJsonArtifact(options.providerMetadata, { label: "trusted provider metadata", maxBytes: 4 * 1024 * 1024 });
    const dastProviderReceipt = snapshotJsonArtifact(options.dastProviderReceipt, { label: "provider DAST receipt", maxBytes: 16 * 1024 * 1024 });
    const dastAuthorization = snapshotJsonArtifact(options.dastAuthorization, { label: "DAST activation authorization", maxBytes: 16 * 1024 * 1024 });
    const bundleManifest = snapshotJsonArtifact(options.bundleManifest, { label: "release bundle manifest", maxBytes: 64 * 1024 });
    snapshots.push(
      policy,
      artifactReceipt,
      deploymentReceipt,
      providerMetadata,
      dastProviderReceipt,
      dastAuthorization,
      bundleManifest,
    );
    const request = buildActivationRequest({
      policy,
      artifactReceipt,
      artifactReceiptSha256: options.artifactReceiptSha256,
      deploymentReceipt,
      deploymentReceiptSha256: options.deploymentReceiptSha256,
      providerMetadata,
      providerMetadataSha256: options.providerMetadataSha256,
      dastProviderReceipt,
      dastProviderReceiptSha256: options.dastProviderReceiptSha256,
      dastAuthorization,
      dastAuthorizationSha256: options.dastAuthorizationSha256,
      dastProviderMetadataSha256: options.dastProviderMetadataSha256,
      dastSigstoreBundleSha256: options.dastSigstoreBundleSha256,
      dastSigstoreSubject: options.dastSigstoreSubject,
      bundleManifest,
      releaseBundleDescriptor: {
        schema: "platform-activation-bundle-descriptor/v2",
        sha256: options.releaseBundleSha256,
        sizeBytes: Number(options.releaseBundleSizeBytes),
        manifestSha256: options.releaseBundleManifestSha256,
      },
      dockerActivationEnvelope: {
        schema: "platform-docker-runtime-activation-envelope-descriptor/v1",
        sha256: options.dockerActivationEnvelopeSha256,
        sizeBytes: Number(options.dockerActivationEnvelopeSizeBytes),
        payloadType: options.dockerActivationEnvelopePayloadType,
        runtimeIntentId: options.dockerActivationRuntimeIntentId,
        generation: Number(options.dockerActivationGeneration),
        dastAuthorizationSha256: options.dastAuthorizationSha256,
        dastChainSha256: options.dastChainSha256,
      },
      repository: options.repository,
      commitSha: options.commit,
      treeSha: options.tree,
      targetHost: options.targetHost,
      environmentSha256: options.environmentSha256,
      providerRunId: options.providerRunId,
      providerRunAttempt: options.providerRunAttempt,
      consumerRunId: options.consumerRunId,
      consumerRunAttempt: options.consumerRunAttempt,
      sshPort: options.sshPort,
    });
    const output = path.resolve(String(options.output ?? ""));
    if (!options.output) invalid("Activation request output path is required.");
    fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
    fs.writeFileSync(output, `${canonicalJson(request)}\n`, { flag: "wx", mode: 0o600 });
    process.stdout.write(`${JSON.stringify({
      requestId: request.requestId,
      releaseContextSha256: request.releaseContextSha256,
      releaseBundleSha256: request.releaseBundle.sha256,
      dockerActivationEnvelopeSha256: request.dockerActivationEnvelope.sha256,
    })}\n`);
  } finally {
    for (const snapshot of snapshots.reverse()) snapshot.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  });
}
