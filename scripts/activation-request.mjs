#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateActivationBundleManifest, exactNoHostedLockBytes } from "./activation-bundle.mjs";
import { validateDastAdmissionReceipt } from "./dast-admission-policy.mjs";
import { validateTrustedDeploymentReceipt } from "./deployment-receipt-policy.mjs";
import { canonicalJson, runtimeIntentSha256 } from "./runtime-intent-policy.mjs";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";
import { validateTrustedProviderRun } from "./trusted-provider-run-policy.mjs";

const REQUEST_MAX_BYTES = 1024 * 1024;
const ACTIVATION_ADMISSION_MAX_BYTES = 16 * 1024 * 1024;

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

function canonicalDastChallenge(receipt, {
  repository,
  commitSha,
  treeSha,
  runtimeIntentSha256,
  consumerRunId,
  consumerRunAttempt,
}) {
  validateDastAdmissionReceipt(receipt, {
    repository,
    commitSha,
    treeSha,
    runtimeIntentSha256,
    consumerRunId,
    consumerRunAttempt,
  });
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
  return {
    consumerRepository: repository,
    consumerRunId: String(challenge.consumerRunId),
    consumerRunAttempt: challenge.consumerRunAttempt,
    consumerJob: "deploy-vps",
    challengeNonce: exactSha256(challenge.challengeNonce, "DAST consumer challenge nonce"),
  };
}

function exactBundleDescriptor(value) {
  exactObject(value, "Activation bundle descriptor", [
    "schema",
    "sha256",
    "sizeBytes",
    "manifestSha256",
  ]);
  if (value.schema !== "platform-activation-bundle-descriptor/v1") {
    invalid("Activation bundle descriptor schema is invalid.");
  }
  return {
    schema: value.schema,
    sha256: exactSha256(value.sha256, "activation bundle SHA256"),
    sizeBytes: exactPositiveInteger(value.sizeBytes, "activation bundle size", 384 * 1024 * 1024),
    manifestSha256: exactSha256(value.manifestSha256, "activation bundle manifest SHA256"),
  };
}

function exactAdmissionDescriptor(value) {
  exactObject(value, "Activation admission descriptor", [
    "schema",
    "sha256",
    "sizeBytes",
  ]);
  if (value.schema !== "platform-activation-admission-descriptor/v1") {
    invalid("Activation admission descriptor schema is invalid.");
  }
  return {
    schema: value.schema,
    sha256: exactSha256(value.sha256, "activation admission sidecar SHA256"),
    sizeBytes: exactPositiveInteger(
      value.sizeBytes,
      "activation admission sidecar size",
      ACTIVATION_ADMISSION_MAX_BYTES,
    ),
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
  dastReceiptSha256,
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
    schema: "platform-trusted-release-context/v2",
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
      dastSha256: exactSha256(dastReceiptSha256, "DAST receipt SHA256"),
    },
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
  dastReceipt,
  dastReceiptSha256,
  bundleManifest,
  bundleDescriptor,
  activationAdmission,
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
    || dastReceipt.sha256 !== exactSha256(dastReceiptSha256, "DAST receipt SHA256")
  ) {
    invalid("One or more activation input artifacts differ from their exact expected SHA256.");
  }
  const challenge = canonicalDastChallenge(dastReceipt.document, {
    repository,
    commitSha,
    treeSha,
    runtimeIntentSha256: deploymentReceipt.document.runtimeIntentSha256,
    consumerRunId,
    consumerRunAttempt,
  });
  const intent = deploymentReceipt.document.runtimeIntent;
  if (
    dastReceipt.document.commitSha !== commitSha
    || dastReceipt.document.treeSha !== treeSha
    || dastReceipt.document.runtimeIntentSha256 !== deploymentReceipt.document.runtimeIntentSha256
  ) {
    invalid("DAST admission does not bind the exact candidate commit, tree and runtime intent.");
  }
  const port = exactPositiveInteger(sshPort, "SSH port", 65535);
  const context = buildTrustedReleaseContext({
    deploymentReceipt: deploymentReceipt.document,
    artifactReceiptSha256,
    deploymentReceiptSha256,
    providerMetadataSha256,
    dastReceiptSha256,
    providerRunId,
    providerRunAttempt,
    providerChallenge: challenge.challengeNonce,
  });
  const contextSha256 = crypto.createHash("sha256").update(canonicalJson(context)).digest("hex");
  const requestId = `activation:${deploymentReceiptSha256}:${contextSha256}`;
  const expectedHostedLockSha256 = intent.hostedWorkloadLockSha256
    ?? crypto.createHash("sha256").update(exactNoHostedLockBytes()).digest("hex");
  const expectedEntryHashes = {
    "artifact-verification.json": artifactReceiptSha256,
    "combined-compose.json": intent.combinedComposeSha256,
    "dast-admission.json": dastReceiptSha256,
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
  const bundle = exactBundleDescriptor(bundleDescriptor);
  if (bundle.manifestSha256 !== manifestValidation.sha256) {
    invalid("Activation bundle descriptor does not bind the exact canonical manifest.");
  }
  const admission = exactAdmissionDescriptor(activationAdmission);
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
    schema: "platform-activation-request/v2",
    requestId,
    deploymentTarget: deploymentReceipt.document.deploymentTarget,
    sshPort: port,
    releaseContext: context,
    releaseContextSha256: contextSha256,
    runtimeIntentSha256: deploymentReceipt.document.runtimeIntentSha256,
    privilegedRuntime: deploymentReceipt.document.privilegedRuntime,
    bundle,
    activationAdmission: admission,
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
    const dastReceipt = snapshotJsonArtifact(options.dastReceipt, { label: "DAST admission receipt", maxBytes: 16 * 1024 * 1024 });
    const bundleManifest = snapshotJsonArtifact(options.bundleManifest, { label: "activation bundle manifest", maxBytes: 64 * 1024 });
    snapshots.push(policy, artifactReceipt, deploymentReceipt, providerMetadata, dastReceipt, bundleManifest);
    const request = buildActivationRequest({
      policy,
      artifactReceipt,
      artifactReceiptSha256: options.artifactReceiptSha256,
      deploymentReceipt,
      deploymentReceiptSha256: options.deploymentReceiptSha256,
      providerMetadata,
      providerMetadataSha256: options.providerMetadataSha256,
      dastReceipt,
      dastReceiptSha256: options.dastReceiptSha256,
      bundleManifest,
      bundleDescriptor: {
        schema: "platform-activation-bundle-descriptor/v1",
        sha256: options.bundleSha256,
        sizeBytes: Number(options.bundleSizeBytes),
        manifestSha256: options.bundleManifestSha256,
      },
      activationAdmission: {
        schema: "platform-activation-admission-descriptor/v1",
        sha256: options.activationAdmissionSha256,
        sizeBytes: Number(options.activationAdmissionSizeBytes),
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
      bundleSha256: request.bundle.sha256,
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
