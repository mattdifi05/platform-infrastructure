#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalReleaseSubjects, exactGitSha, exactRepository, parseReleaseImage } from "./release-artifact-policy.mjs";
import { validateRuntimeIntent } from "./runtime-intent-policy.mjs";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";
import { trustedProducerConfiguration } from "./trusted-provider-run-policy.mjs";

function invalid(message) {
  throw new Error(message);
}

function exactSha256(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one lowercase SHA256.`);
  return text;
}

function exactTimestamp(value, label) {
  const text = String(value ?? "");
  if (!text || !Number.isFinite(Date.parse(text))) invalid(`${label} must be a valid timestamp.`);
  return text;
}

function exactPositiveInteger(value, label) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1) invalid(`${label} must be a positive integer.`);
  return number;
}

function exactClosedObject(value, label, expectedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expectedKeys].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

export function canonicalConsumerChallenge(value) {
  exactClosedObject(value, "Deploy consumer challenge", [
    "challengeNonce",
    "consumerJob",
    "consumerRepository",
    "consumerRunAttempt",
    "consumerRunId",
  ]);
  const challenge = {
    consumerRepository: exactRepository(value.consumerRepository),
    consumerRunId: String(value.consumerRunId ?? ""),
    consumerRunAttempt: exactPositiveInteger(value.consumerRunAttempt, "Deploy consumer run attempt"),
    consumerJob: String(value.consumerJob ?? ""),
    challengeNonce: exactSha256(value.challengeNonce, "Deploy consumer challenge nonce"),
  };
  if (!/^[1-9][0-9]*$/.test(challenge.consumerRunId) || challenge.consumerJob !== "deploy-vps") {
    invalid("Deploy consumer challenge must bind the exact current deploy-vps run identity.");
  }
  return challenge;
}

function consumerChallengeFromOptions(options) {
  const values = [
    options.consumerRepository,
    options.consumerRunId,
    options.consumerRunAttempt,
    options.consumerJob,
    options.challengeNonce,
  ];
  if (values.every((value) => value === undefined || value === null)) return null;
  if (values.some((value) => value === undefined || value === null)) {
    invalid("All deploy consumer challenge bindings are required together.");
  }
  return canonicalConsumerChallenge({
    consumerRepository: options.consumerRepository,
    consumerRunId: options.consumerRunId,
    consumerRunAttempt: options.consumerRunAttempt,
    consumerJob: options.consumerJob,
    challengeNonce: options.challengeNonce,
  });
}

function validatePrivilegedRuntime(runtime) {
  exactClosedObject(runtime, "Trusted privileged runtime", [
    "activationBroker",
    "originFirewallHelper",
    "workloadEgressHelper",
  ]);
  const expected = new Map([
    ["activationBroker", "/usr/local/libexec/platform-activation-broker"],
    ["originFirewallHelper", "/usr/local/libexec/platform-origin-firewall"],
    ["workloadEgressHelper", "/usr/local/libexec/platform-workload-egress-firewall"],
  ]);
  for (const [key, pathname] of expected) {
    const helper = exactClosedObject(runtime[key], `Trusted ${key}`, [
      "path",
      "version",
      "sha256",
      "providerAttested",
    ]);
    if (helper.path !== pathname || !/^[1-9][0-9]{0,8}$/.test(String(helper.version ?? ""))
      || !/^[a-f0-9]{64}$/.test(String(helper.sha256 ?? "")) || helper.providerAttested !== true) {
      invalid(`Trusted ${key} is not bound to the fixed provider-attested helper.`);
    }
  }
  if (new Set([...expected.keys()].map((key) => runtime[key].sha256)).size !== expected.size) {
    invalid("Trusted privileged runtime helper hashes must be distinct.");
  }
  return runtime;
}

function artifactPlatformImageIds(receipt, subjects) {
  if (!Array.isArray(receipt.subjectVerificationReceipts)
    || receipt.subjectVerificationReceipts.length !== subjects.length) {
    invalid("Artifact verification receipt must bind one platform image ID receipt per release subject.");
  }
  const byKey = new Map(receipt.subjectVerificationReceipts.map((entry) => [entry?.key, entry]));
  if (byKey.size !== subjects.length) invalid("Artifact platform image ID receipt keys must be exact and unique.");
  const bindings = {};
  for (const subject of subjects) {
    const entry = byKey.get(subject.key);
    const platforms = entry?.registry?.platforms;
    if (entry?.image !== subject.image
      || entry?.registry?.rootDigest !== subject.digest
      || entry?.registry?.descriptorSha256 !== subject.sha256
      || !Array.isArray(platforms) || platforms.length !== 1) {
      invalid(`Artifact platform image ID receipt is not bound to ${subject.key}.`);
    }
    const platform = platforms[0];
    if (platform?.platform !== "linux/amd64"
      || !/^sha256:[a-f0-9]{64}$/.test(String(platform?.digest ?? ""))
      || !/^sha256:[a-f0-9]{64}$/.test(String(platform?.imageId ?? ""))
      || platform.imageId === platform.digest
      || platform.imageId === subject.digest
      || !Number.isInteger(platform?.size) || platform.size < 1
      || !Number.isInteger(platform?.configSize) || platform.configSize < 1
      || !/^[a-f0-9]{64}$/.test(String(platform?.manifestArtifactSha256 ?? ""))) {
      invalid(`Artifact platform image ID receipt is invalid for ${subject.key}.`);
    }
    bindings[subject.key] = platform.imageId;
  }
  return bindings;
}

export function validateArtifactVerificationReceipt(receipt, { repository, commitSha }) {
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  if (receipt?.version !== 1 || receipt?.kind !== "platform-release-artifact-verification/v1") {
    invalid("Artifact verification receipt kind/version is invalid.");
  }
  if (
    receipt.status !== "EXTERNAL-PENDING"
    || receipt.artifactVerification !== "passed"
    || receipt.deploymentAdmission !== "EXTERNAL-PENDING"
    || receipt.usageScope !== "artifact-verification-only"
  ) {
    invalid("Artifact verification receipt must remain artifact-only and EXTERNAL-PENDING.");
  }
  if (receipt.repository !== expectedRepository || receipt.commitSha !== expectedCommit) {
    invalid("Artifact verification receipt repository/commit binding is mismatched.");
  }
  exactSha256(receipt.sourceArchiveSha256, "artifact receipt source archive SHA256");
  exactSha256(receipt.sbomSha256, "artifact receipt SBOM SHA256");
  exactSha256(receipt.manifestSha256, "artifact receipt manifest SHA256");
  exactSha256(receipt.provenance?.verificationFingerprint, "artifact receipt verification fingerprint");
  exactSha256(receipt.provenance?.manifestVerificationFingerprint, "artifact receipt manifest verification fingerprint");
  exactTimestamp(receipt.generatedAt, "artifact receipt generatedAt");
  const subjects = canonicalReleaseSubjects(receipt.subjects);
  artifactPlatformImageIds(receipt, subjects);
  return receipt;
}

export function validateTrustedDeploymentReceipt(receipt, {
  policy,
  repository,
  commitSha,
  treeSha,
  artifactReceiptSha256,
  artifactReceipt,
  sourceArchiveSha256 = null,
  providerRunId = null,
  providerRunAttempt = null,
  targetHost = null,
  environmentSha256 = null,
  consumerChallenge = null,
  runtimeIntentSha256 = null,
}) {
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  const expectedTree = exactGitSha(treeSha, "tree SHA");
  const expectedArtifactReceipt = exactSha256(artifactReceiptSha256, "artifact verification receipt SHA256");
  validateArtifactVerificationReceipt(artifactReceipt, { repository: expectedRepository, commitSha: expectedCommit });
  const expectedSourceArchive = sourceArchiveSha256 === null
    ? artifactReceipt.sourceArchiveSha256
    : exactSha256(sourceArchiveSha256, "expected source archive SHA256");
  if (
    policy?.status !== "READY"
    || typeof policy?.trustedVerifierChannel !== "string"
    || !policy.trustedVerifierChannel
    || policy.selfAssertedAnnotationsAccepted !== false
    || policy.requiredReceiptKind !== "platform-trusted-deployment-admission/v1"
  ) {
    invalid(`EXTERNAL-PENDING: ${policy?.reason ?? "trusted deployment verifier channel is not configured"}`);
  }
  const configuredProducer = trustedProducerConfiguration(policy);
  if (configuredProducer.repository === expectedRepository) {
    invalid("Trusted deployment producer must be independent from the candidate repository.");
  }
  const configuredOpsRepository = String(policy.trustedOpsImageRepository ?? "");
  if (!/^[a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z0-9._-]+)+$/.test(configuredOpsRepository)) {
    invalid("EXTERNAL-PENDING: trusted ops image repository is not configured");
  }
  if (receipt?.version !== 1 || receipt?.kind !== policy.requiredReceiptKind) invalid("Trusted deployment receipt kind/version is invalid.");
  if (receipt.status !== "READY" || receipt.artifactVerification !== "passed" || receipt.deploymentAdmission !== "READY") {
    invalid("Trusted deployment receipt is not READY.");
  }
  if (receipt.repository !== expectedRepository || receipt.commitSha !== expectedCommit || receipt.treeSha !== expectedTree) {
    invalid("Trusted deployment receipt repository/commit/tree binding is mismatched.");
  }
  if (receipt.artifactVerificationReceiptSha256 !== expectedArtifactReceipt) {
    invalid("Trusted deployment receipt does not bind the exact artifact verification receipt.");
  }
  if (
    artifactReceipt.sourceArchiveSha256 !== expectedSourceArchive
    || receipt.sourceArchiveSha256 !== expectedSourceArchive
  ) {
    invalid("Trusted deployment receipt does not bind the exact source archive.");
  }
  if (receipt.manifestSha256 !== artifactReceipt.manifestSha256 || receipt.sbomSha256 !== artifactReceipt.sbomSha256) {
    invalid("Trusted deployment receipt does not bind the admitted manifest and SBOM.");
  }
  if (
    receipt.verifier?.channel !== policy.trustedVerifierChannel
    || receipt.verifier?.selfAsserted !== false
  ) {
    invalid("Trusted deployment receipt is not from the configured external verifier channel.");
  }
  const producer = receipt.producer;
  if (
    producer?.repository !== configuredProducer.repository
    || producer?.workflowPath !== configuredProducer.workflowPath
    || producer?.workflowSha !== configuredProducer.workflowSha
    || producer?.sourceRef !== configuredProducer.sourceRef
    || producer?.event !== configuredProducer.event
    || !/^[1-9][0-9]*$/.test(String(producer?.runId ?? ""))
    || !Number.isInteger(producer?.runAttempt)
    || producer.runAttempt < 1
    || !/^[a-f0-9]{40}$/.test(String(producer?.workflowSha ?? ""))
  ) {
    invalid("Trusted deployment receipt producer identity is not bound to the configured workflow/repository/ref.");
  }
  if (
    (providerRunId !== null && String(producer.runId) !== String(providerRunId))
    || (providerRunAttempt !== null && String(producer.runAttempt) !== String(providerRunAttempt))
  ) {
    invalid("Trusted deployment receipt producer run identity is mismatched.");
  }
  if (consumerChallenge !== null) {
    const expectedChallenge = canonicalConsumerChallenge(consumerChallenge);
    const actualChallenge = canonicalConsumerChallenge(receipt.consumerChallenge);
    if (JSON.stringify(actualChallenge) !== JSON.stringify(expectedChallenge)) {
      invalid("Trusted deployment receipt does not bind the exact deploy consumer challenge.");
    }
  }
  const opsImage = parseReleaseImage(receipt.opsRunner?.image, "PLATFORM_OPS_IMAGE");
  if (
    opsImage.name !== configuredOpsRepository
    || receipt.opsRunner?.imageId !== `sha256:${String(receipt.opsRunner?.imageId ?? "").replace(/^sha256:/, "")}`
    || !/^sha256:[a-f0-9]{64}$/.test(String(receipt.opsRunner?.imageId ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(receipt.opsRunner?.verificationFingerprint ?? ""))
    || receipt.opsRunner?.providerAttested !== true
  ) {
    invalid("Trusted deployment receipt does not admit one exact provider-attested ops image digest and local image ID.");
  }
  const artifactSubjects = canonicalReleaseSubjects(artifactReceipt.subjects);
  const runtimeIntent = validateRuntimeIntent(receipt.runtimeIntent, {
    repository: expectedRepository,
    commitSha: expectedCommit,
    treeSha: expectedTree,
    sourceArchiveSha256: expectedSourceArchive,
    artifactSubjects,
    artifactPlatformImageIds: artifactPlatformImageIds(artifactReceipt, artifactSubjects),
    opsRunner: receipt.opsRunner,
  });
  if (receipt.runtimeIntentSha256 !== runtimeIntent.sha256) {
    invalid("Trusted deployment receipt does not authenticate the exact canonical runtime intent.");
  }
  if (runtimeIntentSha256 !== null
    && receipt.runtimeIntentSha256 !== exactSha256(runtimeIntentSha256, "expected runtime intent SHA256")) {
    invalid("Trusted deployment receipt runtime intent binding is mismatched.");
  }
  const target = exactClosedObject(receipt.deploymentTarget, "Trusted deployment target", [
    "environment",
    "host",
    "projectName",
  ]);
  if (target.environment !== "production") {
    invalid("Trusted deployment target environment is invalid.");
  }
  if (target.projectName !== receipt.runtimeIntent.projectName
    || !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(String(target.host ?? ""))) {
    invalid("Trusted deployment target host/project binding is invalid.");
  }
  if (targetHost !== null && String(target.host).toLowerCase() !== String(targetHost).toLowerCase()) {
    invalid("Trusted deployment target host is mismatched.");
  }
  if (environmentSha256 !== null && receipt.runtimeIntent.environmentSha256 !== exactSha256(environmentSha256, "expected environment SHA256")) {
    invalid("Trusted deployment runtime environment hash is mismatched.");
  }
  validatePrivilegedRuntime(receipt.privilegedRuntime);
  exactSha256(receipt.verifier?.fingerprint, "trusted verifier fingerprint");
  exactTimestamp(receipt.verifier?.verifiedAt, "trusted verifier verifiedAt");
  exactTimestamp(receipt.generatedAt, "trusted deployment receipt generatedAt");
  if (typeof receipt.decisionId !== "string" || !/^[A-Za-z0-9._:-]{8,200}$/.test(receipt.decisionId)) {
    invalid("Trusted deployment receipt decisionId is invalid.");
  }
  return receipt;
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--")) invalid(`Invalid or missing value for ${key ?? "argument"}.`);
    result[key.slice(2)] = value;
  }
  return result;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const artifacts = [];
  try {
    const policy = snapshotJsonArtifact(options.policy, { label: "deployment admission policy", maxBytes: 1024 * 1024 });
    const artifact = snapshotJsonArtifact(options.artifactReceipt, { label: "artifact verification receipt", maxBytes: 16 * 1024 * 1024 });
    const deployment = snapshotJsonArtifact(options.deploymentReceipt, { label: "trusted deployment receipt", maxBytes: 16 * 1024 * 1024 });
    artifacts.push(policy, artifact, deployment);
    if (artifact.sha256 !== exactSha256(options.artifactReceiptSha256, "expected artifact receipt SHA256")) invalid("Artifact verification receipt SHA256 mismatch.");
    if (deployment.sha256 !== exactSha256(options.deploymentReceiptSha256, "expected deployment receipt SHA256")) invalid("Trusted deployment receipt SHA256 mismatch.");
    validateTrustedDeploymentReceipt(deployment.document, {
      policy: policy.document,
      repository: options.repo,
      commitSha: options.commit,
      treeSha: options.tree,
      artifactReceiptSha256: artifact.sha256,
      artifactReceipt: artifact.document,
      sourceArchiveSha256: options.sourceArchiveSha256 ?? null,
      providerRunId: options.providerRunId ?? null,
      providerRunAttempt: options.providerRunAttempt ?? null,
      targetHost: options.targetHost ?? null,
      environmentSha256: options.environmentSha256 ?? null,
      consumerChallenge: consumerChallengeFromOptions(options),
      runtimeIntentSha256: options.runtimeIntentSha256 ?? null,
    });
    process.stdout.write(`${JSON.stringify({ status: "READY", repository: options.repo, commitSha: options.commit, treeSha: options.tree, sourceArchiveSha256: deployment.document.sourceArchiveSha256, artifactReceiptSha256: artifact.sha256, deploymentReceiptSha256: deployment.sha256, runtimeIntentSha256: deployment.document.runtimeIntentSha256 })}\n`);
  } finally {
    for (const artifact of artifacts.reverse()) artifact.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
