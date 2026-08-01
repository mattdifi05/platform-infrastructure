#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateActivationBundleManifest } from "./activation-bundle.mjs";
import { validateDastAdmissionReceipt } from "./dast-admission-policy.mjs";
import { verifyGithubAttestation } from "./release-trust.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";
import { snapshotFileArtifact, snapshotJsonArtifact } from "./stable-json-artifact.mjs";

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

function exactGitSha(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{40}$/.test(text)) invalid(`${label} must be one full Git SHA.`);
  return text;
}

function exactPositiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum) {
    invalid(`${label} must be one bounded positive integer.`);
  }
  return number;
}

function exactRepository(value, label = "repository") {
  const text = String(value ?? "");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(text)) invalid(`${label} is invalid.`);
  return text;
}

function validateReadyPolicy(policy) {
  exactObject(policy, "Activation promotion policy", [
    "version",
    "status",
    "requiredReceiptKind",
    "selfAssertedAnnotationsAccepted",
    "trustedRootSha256",
    "trustedProducer",
    "reason",
  ]);
  if (
    policy.version !== 1
    || policy.status !== "READY"
    || policy.requiredReceiptKind !== "platform-activation-promotion/v1"
    || policy.selfAssertedAnnotationsAccepted !== false
    || policy.reason !== null
  ) {
    invalid("Provider-side activation promotion remains EXTERNAL-PENDING.");
  }
  exactSha256(policy.trustedRootSha256, "promotion trusted root SHA256");
  const producer = exactObject(policy.trustedProducer, "Activation promotion producer policy", [
    "repository", "workflowPath", "workflowSha", "sourceRef", "event", "artifactName",
  ]);
  exactRepository(producer.repository, "promotion producer repository");
  if (
    !/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(String(producer.workflowPath ?? ""))
    || !/^refs\/heads\/[A-Za-z0-9._/-]+$/.test(String(producer.sourceRef ?? ""))
    || producer.event !== "workflow_dispatch"
    || producer.artifactName !== "platform-promoted-activation"
  ) {
    invalid("Activation promotion producer identity is invalid.");
  }
  exactGitSha(producer.workflowSha, "promotion producer workflow SHA");
  return policy;
}

export function projectProviderRunMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    invalid("Activation promoter API response must be an object.");
  }
  return {
    id: metadata.id,
    run_attempt: metadata.run_attempt,
    repository: { full_name: metadata.repository?.full_name },
    head_repository: { full_name: metadata.head_repository?.full_name },
    path: metadata.path,
    head_branch: metadata.head_branch,
    head_sha: metadata.head_sha,
    event: metadata.event,
    status: metadata.status,
    conclusion: metadata.conclusion,
  };
}

function validateProviderMetadata(metadata, policy, receipt, { runId, runAttempt }) {
  const projected = projectProviderRunMetadata(metadata);
  exactObject(projected, "Activation promoter run metadata projection", [
    "id", "run_attempt", "repository", "head_repository", "path", "head_branch", "head_sha", "event", "status", "conclusion",
  ]);
  exactObject(projected.repository, "Activation promoter repository", ["full_name"]);
  exactObject(projected.head_repository, "Activation promoter head repository", ["full_name"]);
  const expected = policy.trustedProducer;
  if (
    String(projected.id) !== String(exactPositiveInteger(runId, "promoter run ID"))
    || projected.run_attempt !== exactPositiveInteger(runAttempt, "promoter run attempt")
    || projected.repository.full_name !== expected.repository
    || projected.head_repository.full_name !== expected.repository
    || projected.path !== expected.workflowPath
    || `refs/heads/${projected.head_branch}` !== expected.sourceRef
    || projected.head_sha !== expected.workflowSha
    || projected.event !== expected.event
    || projected.status !== "completed"
    || projected.conclusion !== "success"
  ) {
    invalid("Activation promoter run metadata is not the exact successful trusted producer run.");
  }
  exactObject(receipt.producer, "Activation promotion receipt producer", [
    "repository", "workflowPath", "workflowSha", "sourceRef", "event", "runId", "runAttempt",
  ]);
  if (
    receipt.producer.repository !== expected.repository
    || receipt.producer.workflowPath !== expected.workflowPath
    || receipt.producer.workflowSha !== expected.workflowSha
    || receipt.producer.sourceRef !== expected.sourceRef
    || receipt.producer.event !== expected.event
    || String(receipt.producer.runId) !== String(runId)
    || receipt.producer.runAttempt !== Number(runAttempt)
  ) {
    invalid("Activation promotion receipt producer is mismatched.");
  }
}

function verifyPromotionAttestation({
  subject,
  expectedSubjectDigest,
  policy,
  admission,
  trustedRoot,
  verifyAttestation,
}) {
  const result = verifyAttestation({
    subject: subject.sourcePath,
    repository: policy.trustedProducer.repository,
    signerWorkflow: `${policy.trustedProducer.repository}/${policy.trustedProducer.workflowPath}`,
    sourceDigest: policy.trustedProducer.workflowSha,
    sourceRef: policy.trustedProducer.sourceRef,
    bundle: admission.sourcePath,
    trustedRoot: trustedRoot.sourcePath,
    expectedSubjectDigest,
  });
  if (
    result?.status !== "passed"
    || result?.verified !== true
    || result?.selfHostedRunnerDenied !== true
    || result?.offlineBundleVerified !== true
  ) {
    invalid("Activation promotion DSSE/Sigstore verification is incomplete or self-asserted.");
  }
  return result;
}

export function validateActivationPromotion({
  policy,
  receipt,
  providerMetadata,
  bundle,
  bundleManifest,
  admission,
  trustedRoot,
  dastReceipt,
  repository,
  consumerRunId,
  consumerRunAttempt,
  providerRunId,
  providerRunAttempt,
  verifyAttestation = verifyGithubAttestation,
}) {
  validateReadyPolicy(policy.document);
  if (trustedRoot.sha256 !== policy.document.trustedRootSha256) {
    invalid("Activation promotion trusted root differs from policy.");
  }
  exactObject(receipt.document, "Activation promotion receipt", [
    "schema",
    "status",
    "requestId",
    "releaseContextSha256",
    "runtimeIntentSha256",
    "dastReceiptSha256",
    "generatedAt",
    "consumer",
    "producer",
    "bundle",
    "cas",
  ]);
  const document = receipt.document;
  if (document.schema !== "platform-activation-promotion/v1" || document.status !== "READY") {
    invalid("Activation promotion receipt is not READY.");
  }
  if (!/^activation:[a-f0-9]{64}:[a-f0-9]{64}$/.test(String(document.requestId ?? ""))) {
    invalid("Activation promotion request ID is invalid.");
  }
  exactSha256(document.releaseContextSha256, "promotion release context SHA256");
  exactSha256(document.runtimeIntentSha256, "promotion runtime intent SHA256");
  exactSha256(document.dastReceiptSha256, "promotion DAST receipt SHA256");
  if (new Date(document.generatedAt).toISOString() !== document.generatedAt) {
    invalid("Activation promotion generatedAt is invalid.");
  }
  exactObject(document.consumer, "Activation promotion consumer", [
    "repository", "runId", "runAttempt", "job", "challengeNonce",
  ]);
  if (
    document.consumer.repository !== exactRepository(repository)
    || String(document.consumer.runId) !== String(exactPositiveInteger(consumerRunId, "consumer run ID"))
    || document.consumer.runAttempt !== exactPositiveInteger(consumerRunAttempt, "consumer run attempt")
    || document.consumer.job !== "deploy-vps"
    || document.consumer.challengeNonce !== dastReceipt.document.consumerChallenge.challengeNonce
  ) {
    invalid("Activation promotion does not bind the exact current consumer challenge.");
  }
  exactSha256(document.consumer.challengeNonce, "promotion consumer challenge nonce");
  validateDastAdmissionReceipt(dastReceipt.document, {
    repository,
    commitSha: dastReceipt.document.commitSha,
    treeSha: dastReceipt.document.treeSha,
    runtimeIntentSha256: document.runtimeIntentSha256,
    consumerRunId,
    consumerRunAttempt,
  });
  if (
    dastReceipt.sha256 !== document.dastReceiptSha256
    || dastReceipt.document.repository !== repository
    || dastReceipt.document.runtimeIntentSha256 !== document.runtimeIntentSha256
    || String(dastReceipt.document.consumerChallenge.consumerRunId) !== String(consumerRunId)
    || dastReceipt.document.consumerChallenge.consumerRunAttempt !== Number(consumerRunAttempt)
  ) {
    invalid("Activation promotion DAST handoff is mismatched.");
  }
  validateProviderMetadata(providerMetadata.document, policy.document, document, {
    runId: providerRunId,
    runAttempt: providerRunAttempt,
  });

  exactObject(document.bundle, "Promoted activation bundle", ["schema", "sha256", "sizeBytes", "manifestSha256"]);
  if (
    document.bundle.schema !== "platform-activation-bundle-descriptor/v1"
    || document.bundle.sha256 !== bundle.sha256
    || document.bundle.sizeBytes !== bundle.sizeBytes
  ) {
    invalid("Promoted activation bundle descriptor does not match exact artifact bytes.");
  }
  const manifest = validateActivationBundleManifest(bundleManifest.document, {
    requestId: document.requestId,
    releaseContextSha256: document.releaseContextSha256,
    runtimeIntentSha256: document.runtimeIntentSha256,
  });
  if (document.bundle.manifestSha256 !== manifest.sha256) {
    invalid("Promoted activation bundle manifest SHA256 is mismatched.");
  }
  exactObject(document.cas, "Activation CAS installation", [
    "schema", "bundleObject", "manifestObject", "installed", "immutable", "providerAttested",
  ]);
  if (
    document.cas.schema !== "platform-activation-cas-installation/v1"
    || document.cas.bundleObject !== `sha256/${bundle.sha256}`
    || document.cas.manifestObject !== `sha256/${manifest.sha256}`
    || document.cas.installed !== true
    || document.cas.immutable !== true
    || document.cas.providerAttested !== true
  ) {
    invalid("Activation CAS installation is not exact, immutable and provider-attested.");
  }
  if (admission.sizeBytes < 1 || admission.sizeBytes > 16 * 1024 * 1024) {
    invalid("Activation admission sidecar exceeds its size boundary.");
  }
  const bundleAttestation = verifyPromotionAttestation({
    subject: bundle,
    expectedSubjectDigest: bundle.sha256,
    policy: policy.document,
    admission,
    trustedRoot,
    verifyAttestation,
  });
  const receiptAttestation = verifyPromotionAttestation({
    subject: receipt,
    expectedSubjectDigest: receipt.sha256,
    policy: policy.document,
    admission,
    trustedRoot,
    verifyAttestation,
  });
  return {
    status: "READY",
    requestId: document.requestId,
    releaseContextSha256: document.releaseContextSha256,
    runtimeIntentSha256: document.runtimeIntentSha256,
    dastReceiptSha256: document.dastReceiptSha256,
    bundle: document.bundle,
    activationAdmission: {
      schema: "platform-activation-admission-descriptor/v1",
      sha256: admission.sha256,
      sizeBytes: admission.sizeBytes,
    },
    promotionReceiptSha256: receipt.sha256,
    attestationResultCount: bundleAttestation.resultCount + receiptAttestation.resultCount,
  };
}

function parseArgs(values) {
  const options = {};
  if (values.length % 2 !== 0) invalid("Activation promotion arguments are incomplete.");
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || Object.hasOwn(options, key.slice(2))) {
      invalid(`Invalid activation promotion argument ${key ?? "<missing>"}.`);
    }
    options[key.slice(2)] = value;
  }
  return options;
}

function canonicalWire(document) {
  return Buffer.from(`${canonicalJson(document)}\n`, "utf8");
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const snapshots = [];
  try {
    const policy = snapshotJsonArtifact(options.policy, { label: "activation promotion policy", maxBytes: 1024 * 1024 });
    const receipt = snapshotJsonArtifact(options.receipt, { label: "activation promotion receipt", maxBytes: 4 * 1024 * 1024 });
    const providerMetadata = snapshotJsonArtifact(options.providerMetadata, { label: "activation promoter metadata", maxBytes: 4 * 1024 * 1024 });
    const bundle = snapshotFileArtifact(options.bundle, { label: "promoted activation bundle", maxBytes: 384 * 1024 * 1024 });
    const bundleManifest = snapshotJsonArtifact(options.bundleManifest, { label: "activation bundle manifest", maxBytes: 64 * 1024 });
    const admission = snapshotFileArtifact(options.activationAdmission, { label: "activation admission sidecar", maxBytes: 16 * 1024 * 1024 });
    const trustedRoot = snapshotFileArtifact(options.trustedRoot, { label: "activation trusted root", maxBytes: 4 * 1024 * 1024 });
    const dastReceipt = snapshotJsonArtifact(options.dastReceipt, { label: "DAST receipt", maxBytes: 16 * 1024 * 1024 });
    snapshots.push(policy, receipt, providerMetadata, bundle, bundleManifest, admission, trustedRoot, dastReceipt);
    if (!fs.readFileSync(receipt.snapshotPath).equals(canonicalWire(receipt.document))) {
      invalid("Activation promotion receipt is not exact canonical JSON.");
    }
    const result = validateActivationPromotion({
      policy,
      receipt,
      providerMetadata,
      bundle,
      bundleManifest,
      admission,
      trustedRoot,
      dastReceipt,
      repository: options.repository,
      consumerRunId: options.consumerRunId,
      consumerRunAttempt: options.consumerRunAttempt,
      providerRunId: options.providerRunId,
      providerRunAttempt: options.providerRunAttempt,
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
  } finally {
    for (const snapshot of snapshots.reverse()) snapshot.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
