#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateActivationBundleManifest } from "./activation-bundle.mjs";
import { validateDastActivationAuthorization } from "./dast-activation-authorization.mjs";
import { verifyGithubAttestation } from "./release-trust.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";
import { snapshotFileArtifact, snapshotJsonArtifact } from "./stable-json-artifact.mjs";

const DOCKER_ACTIVATION_PAYLOAD_SCHEMA = "platform.docker-runtime-activation/v2";
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

function exactGitSha(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{40}$/.test(text)) invalid(`${label} must be one full Git SHA.`);
  return text;
}

function exactPositiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum || String(number) !== String(value)) {
    invalid(`${label} must be one bounded positive integer.`);
  }
  return number;
}

function exactDecimalId(value, label) {
  const text = String(value ?? "");
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(text) || !Number.isSafeInteger(Number(text)) || String(Number(text)) !== text) {
    invalid(`${label} must be one canonical positive numeric identifier.`);
  }
  return text;
}

function exactRepository(value, label = "repository") {
  const text = String(value ?? "");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(text)) invalid(`${label} is invalid.`);
  return text;
}

function exactTimestamp(value, label) {
  const text = String(value ?? "");
  const milliseconds = Date.parse(text);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== text) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  return text;
}

function exactTarget(value, label) {
  const text = String(value ?? "");
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    invalid(`${label} must be one canonical HTTPS origin.`);
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
    || parsed.origin !== text
  ) {
    invalid(`${label} must be one canonical HTTPS origin.`);
  }
  return text;
}

function exactBoundedText(value, label, maximum = 512) {
  const text = String(value ?? "");
  if (!text || text.length > maximum || text !== text.trim() || /[\0\r\n]/.test(text)) {
    invalid(`${label} is invalid.`);
  }
  return text;
}

function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function exactSnapshotPath(artifact, label) {
  const snapshotPath = String(artifact?.snapshotPath ?? "");
  if (!path.isAbsolute(snapshotPath) || snapshotPath === String(artifact?.sourcePath ?? "")) {
    invalid(`${label} must be verified through its immutable captured snapshot.`);
  }
  return snapshotPath;
}

function gitTreeSha256(treeSha) {
  return crypto.createHash("sha256")
    .update(`platform-git-tree-sha1/v1\0${exactGitSha(treeSha, "DAST tree SHA")}`)
    .digest("hex");
}

function canonicalConsumerChallenge(value, { repository, runId, runAttempt }) {
  exactObject(value, "DAST consumer challenge", [
    "consumerRepository", "consumerRunId", "consumerRunAttempt", "consumerJob", "challengeNonce",
  ]);
  const challenge = {
    consumerRepository: exactRepository(value.consumerRepository, "DAST consumer repository"),
    consumerRunId: exactDecimalId(value.consumerRunId, "DAST consumer run ID"),
    consumerRunAttempt: exactPositiveInteger(value.consumerRunAttempt, "DAST consumer run attempt"),
    consumerJob: exactBoundedText(value.consumerJob, "DAST consumer job", 128),
    challengeNonce: exactSha256(value.challengeNonce, "DAST consumer challenge nonce"),
  };
  if (
    challenge.consumerRepository !== repository
    || challenge.consumerRunId !== exactDecimalId(String(runId), "expected consumer run ID")
    || challenge.consumerRunAttempt !== exactPositiveInteger(runAttempt, "expected consumer run attempt")
    || challenge.consumerJob !== "deploy-vps"
  ) {
    invalid("DAST consumer challenge is not bound to the exact deploy consumer.");
  }
  return challenge;
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
    || policy.requiredReceiptKind !== "platform-activation-promotion/v2"
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
    || producer.sourceRef.includes("..")
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
  const receiptRunId = exactDecimalId(receipt.producer.runId, "promotion receipt producer run ID");
  const expectedRunId = exactDecimalId(String(runId), "expected promoter run ID");
  exactPositiveInteger(receipt.producer.runAttempt, "promotion receipt producer run attempt");
  if (
    receipt.producer.repository !== expected.repository
    || receipt.producer.workflowPath !== expected.workflowPath
    || receipt.producer.workflowSha !== expected.workflowSha
    || receipt.producer.sourceRef !== expected.sourceRef
    || receipt.producer.event !== expected.event
    || receiptRunId !== expectedRunId
    || receipt.producer.runAttempt !== Number(runAttempt)
  ) {
    invalid("Activation promotion receipt producer is mismatched.");
  }
}

function validateDastProviderMetadata(metadata, provider) {
  const projected = projectProviderRunMetadata(metadata);
  exactObject(projected.repository, "DAST provider repository", ["full_name"]);
  exactObject(projected.head_repository, "DAST provider head repository", ["full_name"]);
  const expectedBranch = String(provider.sourceRef).replace(/^refs\/heads\//, "");
  if (
    String(projected.id) !== provider.runId
    || projected.run_attempt !== provider.runAttempt
    || projected.repository.full_name !== provider.repository
    || projected.head_repository.full_name !== provider.repository
    || projected.path !== provider.workflowPath
    || projected.head_branch !== expectedBranch
    || projected.head_sha !== provider.workflowSha
    || projected.event !== provider.event
    || projected.status !== "completed"
    || projected.conclusion !== "success"
  ) {
    invalid("DAST provider metadata is not the exact successful countersign run.");
  }
}

function canonicalDastSemanticVerdict(value, label) {
  exactObject(value, label, ["alertCount", "highestRiskCode", "policy", "siteCount", "status"]);
  if (
    value.policy !== "zap-baseline-no-risk-alerts/v1"
    || value.status !== "passed"
    || !Number.isSafeInteger(value.siteCount)
    || value.siteCount < 1
    || value.alertCount !== 0
    || value.highestRiskCode !== 0
  ) {
    invalid(`${label} is not a strict zero-alert pass.`);
  }
  return {
    policy: value.policy,
    status: "passed",
    siteCount: value.siteCount,
    alertCount: 0,
    highestRiskCode: 0,
  };
}

function canonicalDastReportFile(value, format) {
  exactObject(value, `Raw provider DAST ${format} report`, ["bytes", "path", "sha256"]);
  if (value.path !== `zap-baseline.${format}`) {
    invalid(`Raw provider DAST ${format} report path is invalid.`);
  }
  const bytes = exactPositiveInteger(value.bytes, `Raw provider DAST ${format} report size`, 128 * 1024 * 1024);
  return {
    path: value.path,
    sha256: exactSha256(value.sha256, `Raw provider DAST ${format} report SHA256`),
    bytes,
  };
}

function canonicalDastReportEvidence(value, { artifactName }) {
  exactObject(value, "Raw provider DAST validated report evidence", [
    "artifactName", "engineImage", "files", "semanticVerdict",
  ]);
  if (value.artifactName !== artifactName) {
    invalid("Raw provider DAST report evidence is not bound to its artifact name.");
  }
  const engineImage = String(value.engineImage ?? "");
  if (!/^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$/.test(engineImage)) {
    invalid("Raw provider DAST engine image is not digest-pinned.");
  }
  exactObject(value.files, "Raw provider DAST report file inventory", ["html", "json", "xml"]);
  return {
    artifactName,
    engineImage,
    files: {
      json: canonicalDastReportFile(value.files.json, "json"),
      html: canonicalDastReportFile(value.files.html, "html"),
      xml: canonicalDastReportFile(value.files.xml, "xml"),
    },
    semanticVerdict: canonicalDastSemanticVerdict(
      value.semanticVerdict,
      "Raw provider DAST report semantic verdict",
    ),
  };
}

function validateRawDastProviderReceipt(artifact, {
  repository,
  consumerRunId,
  consumerRunAttempt,
  providerMetadata,
  providerAttestationBundle,
}) {
  const receipt = exactObject(artifact.document, "Raw rich provider DAST receipt", [
    "candidateProducer",
    "commitSha",
    "consumerChallenge",
    "generatedAt",
    "kind",
    "provider",
    "providerValidation",
    "reportArtifact",
    "reportEvidenceSha256",
    "repository",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "scanRequestSha256",
    "semanticVerdict",
    "status",
    "target",
    "targetServingInventoryHash",
    "targetServingServices",
    "treeSha",
    "validatedReportEvidence",
    "version",
  ]);
  if (receipt.version !== 1 || receipt.kind !== "platform-dast-verification/v1" || receipt.status !== "passed") {
    invalid("Raw provider DAST receipt kind/version/status is invalid.");
  }
  if (receipt.repository !== exactRepository(repository) || receipt.repository !== exactRepository(receipt.repository)) {
    invalid("Raw provider DAST repository is mismatched.");
  }
  exactGitSha(receipt.commitSha, "raw provider DAST commit SHA");
  exactGitSha(receipt.treeSha, "raw provider DAST tree SHA");
  exactTarget(receipt.target, "raw provider DAST target");
  const challenge = canonicalConsumerChallenge(receipt.consumerChallenge, {
    repository,
    runId: consumerRunId,
    runAttempt: consumerRunAttempt,
  });
  for (const [field, label] of [
    ["runtimeIntentSha256", "raw provider DAST runtime intent SHA256"],
    ["runtimeInventorySha256", "raw provider DAST runtime inventory SHA256"],
    ["targetServingInventoryHash", "raw provider DAST target-serving inventory hash"],
    ["scanRequestSha256", "raw provider DAST scan request SHA256"],
    ["reportEvidenceSha256", "raw provider DAST report evidence SHA256"],
  ]) exactSha256(receipt[field], label);
  if (
    !Array.isArray(receipt.targetServingServices)
    || receipt.targetServingServices.length < 1
    || receipt.targetServingServices.some((service) => !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(String(service)))
    || new Set(receipt.targetServingServices).size !== receipt.targetServingServices.length
    || JSON.stringify(receipt.targetServingServices) !== JSON.stringify([...receipt.targetServingServices].sort())
  ) {
    invalid("Raw provider DAST target-serving services are invalid.");
  }
  const reportArtifact = exactObject(receipt.reportArtifact, "Raw provider DAST report artifact", [
    "id", "name", "archiveSha256", "repository", "runAttempt", "runId",
  ]);
  exactDecimalId(reportArtifact.id, "DAST report artifact ID");
  exactBoundedText(reportArtifact.name, "DAST report artifact name", 512);
  exactSha256(reportArtifact.archiveSha256, "DAST report artifact archive SHA256");
  if (
    reportArtifact.repository !== repository
    || reportArtifact.runId !== challenge.consumerRunId
    || reportArtifact.runAttempt !== challenge.consumerRunAttempt
  ) {
    invalid("Raw provider DAST report artifact is not run-bound.");
  }
  exactObject(receipt.providerValidation, "Raw provider DAST independent validation", [
    "independent", "parser", "status",
  ]);
  if (
    receipt.providerValidation.independent !== true
    || receipt.providerValidation.parser !== "platform-provider-zap-report-set/v1"
    || receipt.providerValidation.status !== "passed"
  ) {
    invalid("Raw provider DAST semantic validation is not an independent pass.");
  }
  const semanticVerdict = canonicalDastSemanticVerdict(
    receipt.semanticVerdict,
    "Raw provider DAST semantic verdict",
  );
  const reportEvidence = canonicalDastReportEvidence(receipt.validatedReportEvidence, {
    artifactName: reportArtifact.name,
  });
  if (
    canonicalJson(reportEvidence.semanticVerdict) !== canonicalJson(semanticVerdict)
    || crypto.createHash("sha256").update(JSON.stringify(reportEvidence)).digest("hex")
      !== receipt.reportEvidenceSha256
  ) {
    invalid("Raw provider DAST report evidence fingerprint or semantic verdict is inconsistent.");
  }
  const candidateProducer = exactObject(receipt.candidateProducer, "Raw candidate DAST producer", [
    "event", "job", "repository", "runAttempt", "runId", "sourceRef", "workflowPath", "workflowSha",
  ]);
  if (
    candidateProducer.repository !== repository
    || candidateProducer.workflowPath !== ".github/workflows/enterprise-infra.yml"
    || candidateProducer.workflowSha !== receipt.commitSha
    || candidateProducer.sourceRef !== "refs/heads/main"
    || candidateProducer.event !== "workflow_dispatch"
    || candidateProducer.runId !== challenge.consumerRunId
    || candidateProducer.runAttempt !== challenge.consumerRunAttempt
    || candidateProducer.job !== "dast-zap"
  ) {
    invalid("Raw candidate DAST producer is not bound to the exact candidate run.");
  }
  const provider = exactObject(receipt.provider, "Raw DAST provider", [
    "event", "job", "repository", "runAttempt", "runId", "sourceRef", "workflowPath", "workflowSha",
  ]);
  exactRepository(provider.repository, "DAST provider repository");
  if (
    provider.repository === repository
    || !/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(String(provider.workflowPath ?? ""))
    || !/^refs\/heads\/[A-Za-z0-9._/-]+$/.test(String(provider.sourceRef ?? ""))
    || provider.sourceRef.includes("..")
    || provider.event !== "workflow_dispatch"
    || provider.job !== "dast-countersign"
  ) {
    invalid("Raw DAST provider identity is not independent and exact.");
  }
  exactGitSha(provider.workflowSha, "DAST provider workflow SHA");
  exactDecimalId(provider.runId, "DAST provider run ID");
  exactPositiveInteger(provider.runAttempt, "DAST provider run attempt");
  validateDastProviderMetadata(providerMetadata.document, provider);
  exactTimestamp(receipt.generatedAt, "raw provider DAST generatedAt");
  const sigstoreSubject = `https://github.com/${provider.repository}/${provider.workflowPath}@${provider.sourceRef}`;
  return {
    challenge,
    expectedAuthorization: {
      repository,
      commitSha: receipt.commitSha,
      treeSha: receipt.treeSha,
      target: receipt.target,
      runtimeIntentSha256: receipt.runtimeIntentSha256,
      runtimeInventorySha256: receipt.runtimeInventorySha256,
      targetServingInventoryHash: receipt.targetServingInventoryHash,
      consumerChallenge: challenge,
      scanRequestSha256: receipt.scanRequestSha256,
      providerReceiptSha256: exactSha256(artifact.sha256, "raw provider DAST artifact SHA256"),
      providerMetadataSha256: exactSha256(providerMetadata.sha256, "DAST provider metadata SHA256"),
      providerRunId: provider.runId,
      providerRunAttempt: provider.runAttempt,
      reportArtifactId: reportArtifact.id,
      reportArtifactArchiveSha256: reportArtifact.archiveSha256,
      reportEvidenceSha256: receipt.reportEvidenceSha256,
      sigstoreBundleSha256: exactSha256(
        providerAttestationBundle.sha256,
        "DAST provider Sigstore bundle SHA256",
      ),
      sigstoreSubject,
    },
  };
}

function strictBase64(value, label) {
  const text = String(value ?? "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text) || text.length < 4) {
    invalid(`${label} is not canonical base64.`);
  }
  const bytes = Buffer.from(text, "base64");
  if (bytes.toString("base64") !== text) invalid(`${label} is not canonical base64.`);
  return bytes;
}

function validateDockerActivationEnvelope(artifact, {
  descriptor,
  authorization,
  authorizationSha256,
  releaseBundleSha256,
  releaseBundleManifestSha256,
  treeSha,
}) {
  if (!Buffer.isBuffer(artifact.bytes)) invalid("Docker activation envelope exact bytes are unavailable.");
  let envelope;
  try {
    envelope = JSON.parse(artifact.bytes.toString("utf8"));
  } catch {
    invalid("Docker activation envelope is not JSON.");
  }
  if (!artifact.bytes.equals(Buffer.from(`${canonicalJson(envelope)}\n`))) {
    invalid("Docker activation envelope is not exact canonical JSON.");
  }
  exactObject(envelope, "Docker activation DSSE envelope", ["payload", "payloadType", "signatures"]);
  if (
    envelope.payloadType !== DOCKER_ACTIVATION_PAYLOAD_TYPE
    || !Array.isArray(envelope.signatures)
    || envelope.signatures.length !== 1
  ) {
    invalid("Docker activation DSSE payload type or signature count is invalid.");
  }
  const signature = exactObject(envelope.signatures[0], "Docker activation DSSE signature", ["keyid", "sig"]);
  exactSha256(signature.keyid, "Docker activation DSSE key ID");
  strictBase64(signature.sig, "Docker activation DSSE signature");
  const payloadBytes = strictBase64(envelope.payload, "Docker activation DSSE payload");
  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    invalid("Docker activation DSSE payload is not JSON.");
  }
  if (!payloadBytes.equals(Buffer.from(canonicalJson(payload)))) {
    invalid("Docker activation DSSE payload is not exact canonical JSON.");
  }
  exactObject(payload, "Docker activation payload", [
    "activationId",
    "candidateId",
    "combinedRenderSha256",
    "dast",
    "dastAuthorizationSha256",
    "environment",
    "expiresAt",
    "generation",
    "issuedAt",
    "issuer",
    "nonce",
    "notBefore",
    "previousActiveSha256",
    "releaseBundleManifestSha256",
    "releaseBundleSha256",
    "releaseId",
    "requestId",
    "runtimeIntentId",
    "schema",
    "sourceRenderSha256",
    "subject",
    "targetId",
    "treeSha256",
  ]);
  if (payload.schema !== DOCKER_ACTIVATION_PAYLOAD_SCHEMA) {
    invalid("Docker activation payload schema is invalid.");
  }
  const runtimeIntentId = exactBoundedText(payload.runtimeIntentId, "Docker activation runtime intent ID", 128);
  if (!/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(runtimeIntentId)) {
    invalid("Docker activation runtime intent ID is invalid.");
  }
  const generation = exactPositiveInteger(payload.generation, "Docker activation generation");
  const expectedTreeSha256 = gitTreeSha256(treeSha);
  if (
    payload.releaseBundleSha256 !== releaseBundleSha256
    || payload.releaseBundleManifestSha256 !== releaseBundleManifestSha256
    || payload.dastAuthorizationSha256 !== authorizationSha256
    || payload.treeSha256 !== expectedTreeSha256
    || canonicalJson(payload.dast) !== canonicalJson(authorization.chain)
    || sha256Canonical(payload.dast) !== authorization.chainSha256
  ) {
    invalid("Docker activation envelope release/authorization/DAST projection is mismatched.");
  }
  if (
    descriptor.payloadType !== envelope.payloadType
    || descriptor.runtimeIntentId !== runtimeIntentId
    || descriptor.generation !== generation
    || descriptor.dastAuthorizationSha256 !== authorizationSha256
    || descriptor.dastChainSha256 !== authorization.chainSha256
  ) {
    invalid("Docker activation envelope descriptor is mismatched.");
  }
  return { payload, runtimeIntentId, generation };
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
    subject: exactSnapshotPath(subject, "Activation promotion subject"),
    repository: policy.trustedProducer.repository,
    signerWorkflow: `${policy.trustedProducer.repository}/${policy.trustedProducer.workflowPath}`,
    sourceDigest: policy.trustedProducer.workflowSha,
    sourceRef: policy.trustedProducer.sourceRef,
    bundle: exactSnapshotPath(admission, "Activation admission sidecar"),
    trustedRoot: exactSnapshotPath(trustedRoot, "Activation trusted root"),
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
  exactPositiveInteger(result.resultCount, "activation promotion attestation result count");
  return result;
}

export function validateActivationPromotion({
  policy,
  receipt,
  providerMetadata,
  releaseBundle,
  releaseBundleManifest,
  dockerActivationEnvelope,
  activationAdmission,
  trustedRoot,
  dastAuthorization,
  dastProviderReceipt,
  dastProviderMetadata,
  dastProviderAttestationBundle,
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
  const expectedRepository = exactRepository(repository);
  const dast = validateRawDastProviderReceipt(dastProviderReceipt, {
    repository: expectedRepository,
    consumerRunId,
    consumerRunAttempt,
    providerMetadata: dastProviderMetadata,
    providerAttestationBundle: dastProviderAttestationBundle,
  });
  const authorization = validateDastActivationAuthorization(
    dastAuthorization.document,
    dast.expectedAuthorization,
  );

  exactObject(receipt.document, "Activation promotion receipt", [
    "schema",
    "status",
    "requestId",
    "releaseContextSha256",
    "runtimeIntentSha256",
    "dastProviderReceiptSha256",
    "dastAuthorizationSha256",
    "dastChainSha256",
    "generatedAt",
    "consumer",
    "producer",
    "releaseBundle",
    "dockerActivationEnvelope",
    "cas",
  ]);
  const document = receipt.document;
  if (document.schema !== "platform-activation-promotion/v2" || document.status !== "READY") {
    invalid("Activation promotion receipt is not READY v2.");
  }
  const requestIdMatch = String(document.requestId ?? "").match(
    /^activation:([a-f0-9]{64}):([a-f0-9]{64})$/,
  );
  if (!requestIdMatch || requestIdMatch[2] !== document.releaseContextSha256) {
    invalid("Activation promotion request ID is invalid.");
  }
  exactSha256(document.releaseContextSha256, "promotion release context SHA256");
  exactSha256(document.runtimeIntentSha256, "promotion runtime intent SHA256");
  exactSha256(document.dastProviderReceiptSha256, "promotion raw DAST provider receipt SHA256");
  exactSha256(document.dastAuthorizationSha256, "promotion DAST authorization SHA256");
  exactSha256(document.dastChainSha256, "promotion DAST chain SHA256");
  const promotedAt = Date.parse(exactTimestamp(document.generatedAt, "activation promotion generatedAt"));
  if (
    promotedAt < Date.parse(exactTimestamp(dastProviderReceipt.document.generatedAt, "raw provider DAST generatedAt"))
    || promotedAt < Date.parse(exactTimestamp(authorization.generatedAt, "DAST authorization generatedAt"))
  ) {
    invalid("Activation promotion predates its DAST authorization chain.");
  }
  exactObject(document.consumer, "Activation promotion consumer", [
    "repository", "runId", "runAttempt", "job", "challengeNonce",
  ]);
  const receiptConsumerRunId = exactDecimalId(document.consumer.runId, "promotion consumer run ID");
  if (
    document.consumer.repository !== expectedRepository
    || receiptConsumerRunId !== dast.challenge.consumerRunId
    || receiptConsumerRunId !== exactDecimalId(String(consumerRunId), "expected consumer run ID")
    || document.consumer.runAttempt !== exactPositiveInteger(consumerRunAttempt, "consumer run attempt")
    || document.consumer.job !== "deploy-vps"
    || document.consumer.challengeNonce !== dast.challenge.challengeNonce
  ) {
    invalid("Activation promotion does not bind the exact current consumer challenge.");
  }
  exactSha256(document.consumer.challengeNonce, "promotion consumer challenge nonce");
  if (
    document.runtimeIntentSha256 !== dastProviderReceipt.document.runtimeIntentSha256
    || document.dastProviderReceiptSha256 !== dastProviderReceipt.sha256
    || document.dastAuthorizationSha256 !== dastAuthorization.sha256
    || document.dastChainSha256 !== authorization.chainSha256
    || authorization.chain.providerReceiptSha256 !== dastProviderReceipt.sha256
  ) {
    invalid("Activation promotion DAST authorization handoff is mismatched.");
  }
  validateProviderMetadata(providerMetadata.document, policy.document, document, {
    runId: providerRunId,
    runAttempt: providerRunAttempt,
  });

  const releaseDescriptor = exactObject(document.releaseBundle, "Promoted release activation bundle", [
    "schema", "sha256", "sizeBytes", "manifestSha256",
  ]);
  if (
    releaseDescriptor.schema !== "platform-activation-bundle-descriptor/v2"
    || releaseDescriptor.sha256 !== releaseBundle.sha256
    || releaseDescriptor.sizeBytes !== releaseBundle.sizeBytes
  ) {
    invalid("Promoted release activation bundle descriptor does not match exact artifact bytes.");
  }
  const manifest = validateActivationBundleManifest(releaseBundleManifest.document, {
    requestId: document.requestId,
    releaseContextSha256: document.releaseContextSha256,
    runtimeIntentSha256: document.runtimeIntentSha256,
    expectedEntryHashes: {
      "dast-activation-authorization.json": dastAuthorization.sha256,
      "dast-provider-verification.json": dastProviderReceipt.sha256,
      "trusted-deployment-admission.json": requestIdMatch[1],
    },
  });
  if (releaseDescriptor.manifestSha256 !== manifest.sha256) {
    invalid("Promoted release activation bundle manifest SHA256 is mismatched.");
  }

  const envelopeDescriptor = exactObject(
    document.dockerActivationEnvelope,
    "Promoted Docker activation envelope",
    [
      "schema",
      "sha256",
      "sizeBytes",
      "payloadType",
      "runtimeIntentId",
      "generation",
      "dastAuthorizationSha256",
      "dastChainSha256",
    ],
  );
  if (
    envelopeDescriptor.schema !== "platform-docker-runtime-activation-envelope-descriptor/v1"
    || envelopeDescriptor.sha256 !== dockerActivationEnvelope.sha256
    || envelopeDescriptor.sizeBytes !== dockerActivationEnvelope.sizeBytes
  ) {
    invalid("Promoted Docker activation envelope descriptor does not match exact artifact bytes.");
  }
  validateDockerActivationEnvelope(dockerActivationEnvelope, {
    descriptor: envelopeDescriptor,
    authorization,
    authorizationSha256: dastAuthorization.sha256,
    releaseBundleSha256: releaseBundle.sha256,
    releaseBundleManifestSha256: manifest.sha256,
    treeSha: dastProviderReceipt.document.treeSha,
  });

  exactObject(document.cas, "Activation CAS installation", [
    "schema",
    "releaseBundleObject",
    "releaseBundleManifestObject",
    "dockerActivationEnvelopeObject",
    "dastAuthorizationObject",
    "installed",
    "immutable",
    "providerAttested",
  ]);
  if (
    document.cas.schema !== "platform-activation-cas-installation/v2"
    || document.cas.releaseBundleObject !== `sha256/${releaseBundle.sha256}`
    || document.cas.releaseBundleManifestObject !== `sha256/${manifest.sha256}`
    || document.cas.dockerActivationEnvelopeObject !== `sha256/${dockerActivationEnvelope.sha256}`
    || document.cas.dastAuthorizationObject !== `sha256/${dastAuthorization.sha256}`
    || document.cas.installed !== true
    || document.cas.immutable !== true
    || document.cas.providerAttested !== true
  ) {
    invalid("Activation CAS v2 installation is not exact, immutable and provider-attested.");
  }
  const separatedDigests = [
    releaseBundle.sha256,
    dockerActivationEnvelope.sha256,
    dastProviderReceipt.sha256,
    dastAuthorization.sha256,
    authorization.chainSha256,
  ];
  if (new Set(separatedDigests).size !== separatedDigests.length) {
    invalid("Release bundle, Docker envelope, raw DAST receipt, authorization and DAST chain digests must remain distinct.");
  }
  if (activationAdmission.sizeBytes < 1 || activationAdmission.sizeBytes > 16 * 1024 * 1024) {
    invalid("Activation admission sidecar exceeds its size boundary.");
  }
  const attestations = [dastAuthorization, releaseBundle, dockerActivationEnvelope, receipt].map((subject) => (
    verifyPromotionAttestation({
      subject,
      expectedSubjectDigest: subject.sha256,
      policy: policy.document,
      admission: activationAdmission,
      trustedRoot,
      verifyAttestation,
    })
  ));
  return {
    status: "READY",
    requestId: document.requestId,
    releaseContextSha256: document.releaseContextSha256,
    runtimeIntentSha256: document.runtimeIntentSha256,
    dastProviderReceiptSha256: document.dastProviderReceiptSha256,
    dastAuthorizationSha256: document.dastAuthorizationSha256,
    dastChainSha256: document.dastChainSha256,
    releaseBundle: document.releaseBundle,
    dockerActivationEnvelope: document.dockerActivationEnvelope,
    activationAdmission: {
      schema: "platform-activation-admission-descriptor/v1",
      sha256: activationAdmission.sha256,
      sizeBytes: activationAdmission.sizeBytes,
    },
    promotionReceiptSha256: receipt.sha256,
    attestationResultCount: attestations.reduce((sum, result) => sum + result.resultCount, 0),
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

function assertCanonicalSnapshot(artifact, label) {
  if (!fs.readFileSync(artifact.snapshotPath).equals(canonicalWire(artifact.document))) {
    invalid(`${label} is not exact canonical JSON.`);
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const snapshots = [];
  try {
    const policy = snapshotJsonArtifact(options.policy, { label: "activation promotion policy", maxBytes: 1024 * 1024 });
    const receipt = snapshotJsonArtifact(options.receipt, { label: "activation promotion receipt", maxBytes: 4 * 1024 * 1024 });
    const providerMetadata = snapshotJsonArtifact(options.providerMetadata, { label: "activation promoter metadata", maxBytes: 4 * 1024 * 1024 });
    const releaseBundle = snapshotFileArtifact(options.releaseBundle, { label: "promoted release activation bundle", maxBytes: 384 * 1024 * 1024 });
    const releaseBundleManifest = snapshotJsonArtifact(options.releaseBundleManifest, { label: "release activation bundle manifest", maxBytes: 64 * 1024 });
    const dockerActivationEnvelope = snapshotFileArtifact(options.dockerActivationEnvelope, { label: "Docker activation envelope", maxBytes: 16 * 1024 * 1024 });
    const activationAdmission = snapshotFileArtifact(options.activationAdmission, { label: "activation admission sidecar", maxBytes: 16 * 1024 * 1024 });
    const trustedRoot = snapshotFileArtifact(options.trustedRoot, { label: "activation trusted root", maxBytes: 4 * 1024 * 1024 });
    const dastAuthorization = snapshotJsonArtifact(options.dastAuthorization, { label: "DAST activation authorization", maxBytes: 16 * 1024 * 1024 });
    const dastProviderReceipt = snapshotJsonArtifact(options.dastProviderReceipt, { label: "raw rich provider DAST receipt", maxBytes: 16 * 1024 * 1024 });
    const dastProviderMetadata = snapshotJsonArtifact(options.dastProviderMetadata, { label: "DAST provider metadata", maxBytes: 4 * 1024 * 1024 });
    const dastProviderAttestationBundle = snapshotFileArtifact(options.dastProviderAttestationBundle, { label: "DAST provider Sigstore bundle", maxBytes: 16 * 1024 * 1024 });
    snapshots.push(
      policy,
      receipt,
      providerMetadata,
      releaseBundle,
      releaseBundleManifest,
      dockerActivationEnvelope,
      activationAdmission,
      trustedRoot,
      dastAuthorization,
      dastProviderReceipt,
      dastProviderMetadata,
      dastProviderAttestationBundle,
    );
    assertCanonicalSnapshot(receipt, "Activation promotion receipt");
    assertCanonicalSnapshot(releaseBundleManifest, "Release activation bundle manifest");
    assertCanonicalSnapshot(dastAuthorization, "DAST activation authorization");
    assertCanonicalSnapshot(dastProviderReceipt, "Raw rich provider DAST receipt");
    const result = validateActivationPromotion({
      policy,
      receipt,
      providerMetadata,
      releaseBundle,
      releaseBundleManifest,
      dockerActivationEnvelope,
      activationAdmission,
      trustedRoot,
      dastAuthorization,
      dastProviderReceipt,
      dastProviderMetadata,
      dastProviderAttestationBundle,
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
