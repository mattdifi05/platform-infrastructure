#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, runtimeIntentSha256, validateRuntimeIntent } from "./runtime-intent-policy.mjs";
import { snapshotFileArtifact } from "./stable-json-artifact.mjs";

export const CONFORMANCE_KIND = "platform-hosted-preparation-provider-conformance/v1";
export const AUTHORIZATION_KIND = "platform-hosted-preparation-authorization/v1";
export const RECEIPT_KIND = "platform-hosted-preparation-receipt/v1";

const AUTHORIZATION_PAYLOAD_TYPE = "application/vnd.platform.hosted-preparation-authorization.v1+json";
const RECEIPT_PAYLOAD_TYPE = "application/vnd.platform.hosted-preparation-receipt.v1+json";
const REQUIRED_DAG = Object.freeze([
  "provider-signed-preparation-authorization/v1",
  "target-root-signed-preparation-receipt/v1",
  "provider-final-deployment-admission/v1",
]);
const REQUIRED_INVARIANT = Object.freeze([
  "authorization-has-no-final-output-bindings",
  "receipt-binds-the-exact-authorization-envelope",
  "final-admission-binds-the-exact-receipt-output-projection",
  "candidate-cannot-mint-authoritative-evidence",
]);
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$/;
const MAX_JSON_BYTES = 16 * 1024 * 1024;

function invalid(message) {
  throw new Error(message);
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactArray(value, expected, label) {
  if (!Array.isArray(value) || canonicalJson(value) !== canonicalJson(expected)) {
    invalid(`${label} is not the exact versioned sequence.`);
  }
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) invalid(`${label} must be one lowercase SHA256.`);
  return value;
}

function exactGitSha(value, label) {
  if (typeof value !== "string" || !GIT_SHA.test(value)) invalid(`${label} must be one full lowercase Git SHA.`);
  return value;
}

function exactRepository(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)) {
    invalid(`${label} must use exact owner/name syntax.`);
  }
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string") invalid(`${label} must be one canonical UTC timestamp.`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  return { value, milliseconds };
}

function exactSafeInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) invalid(`${label} must be a safe integer >= ${minimum}.`);
  return value;
}

function exactDecimal(value, label, positive = false) {
  const expression = positive ? POSITIVE_DECIMAL : DECIMAL;
  if (typeof value !== "string" || !expression.test(value)) invalid(`${label} must be one canonical decimal string.`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < (positive ? 1 : 0) || String(number) !== value) {
    invalid(`${label} exceeds the canonical safe integer range.`);
  }
  return value;
}

function exactAbsolutePath(value, label) {
  if (typeof value !== "string" || !/^\/[A-Za-z0-9._/-]+$/.test(value)
      || value.includes("//") || value.split("/").some((part) => part === "." || part === "..")
      || path.posix.normalize(value) !== value) {
    invalid(`${label} must be one normalized absolute path.`);
  }
  return value;
}

function exactHost(value, label) {
  if (typeof value !== "string" || !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(value)) {
    invalid(`${label} is invalid.`);
  }
  return value;
}

function exactImage(value, label) {
  if (typeof value !== "string" || !/^[a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$/.test(value)) {
    invalid(`${label} must be one immutable digest reference.`);
  }
  return value;
}

function exactImageId(value, label) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) {
    invalid(`${label} must be one exact local image ID.`);
  }
  return value;
}

function exactPublicKey(publicKeyPem, expectedKeyId, label) {
  if (typeof publicKeyPem !== "string"
      || !publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n")
      || !publicKeyPem.endsWith("-----END PUBLIC KEY-----\n")) {
    invalid(`${label} must use exact canonical SPKI public key PEM.`);
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch {
    invalid(`${label} must use exact canonical SPKI public key PEM.`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") invalid(`${label} must use an Ed25519 public key.`);
  const canonicalPem = publicKey.export({ type: "spki", format: "pem" });
  if (typeof canonicalPem !== "string" || canonicalPem !== publicKeyPem) {
    invalid(`${label} must use exact canonical SPKI public key PEM.`);
  }
  const keyId = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  if (keyId !== exactSha256(expectedKeyId, `${label} key ID`)) invalid(`${label} key ID does not match its public key.`);
  return publicKey;
}

function exactProducer(value, label, expected = null) {
  exactObject(value, label, [
    "event", "repository", "runAttempt", "runId", "sourceRef", "workflowPath", "workflowSha",
  ]);
  const producer = {
    repository: exactRepository(value.repository, `${label} repository`),
    workflowPath: value.workflowPath,
    workflowSha: exactGitSha(value.workflowSha, `${label} workflow SHA`),
    sourceRef: value.sourceRef,
    event: value.event,
    runId: exactDecimal(value.runId, `${label} run ID`, true),
    runAttempt: exactSafeInteger(value.runAttempt, `${label} run attempt`, 1),
  };
  if (!/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(producer.workflowPath)
      || producer.sourceRef !== "refs/heads/main" || producer.event !== "workflow_dispatch") {
    invalid(`${label} workflow path/ref/event is invalid.`);
  }
  if (expected !== null && ["repository", "workflowPath", "workflowSha", "sourceRef", "event"]
    .some((key) => producer[key] !== expected[key])) {
    invalid(`${label} differs from the configured independent provider.`);
  }
  return producer;
}

function exactConsumerChallenge(value, label) {
  exactObject(value, label, [
    "challengeNonce", "consumerJob", "consumerRepository", "consumerRunAttempt", "consumerRunId",
  ]);
  const challenge = {
    consumerRepository: exactRepository(value.consumerRepository, `${label} repository`),
    consumerRunId: exactDecimal(value.consumerRunId, `${label} run ID`, true),
    consumerRunAttempt: exactSafeInteger(value.consumerRunAttempt, `${label} run attempt`, 1),
    consumerJob: value.consumerJob,
    challengeNonce: exactSha256(value.challengeNonce, `${label} nonce`),
  };
  if (challenge.consumerJob !== "deploy-vps") invalid(`${label} must bind the deploy-vps consumer job.`);
  return challenge;
}

function exactTarget(value, label, requiredProjectName) {
  exactObject(value, label, [
    "deploymentGid", "deploymentUid", "dockerDaemonId", "environment", "host", "projectName", "sshHostKeySha256",
  ]);
  if (value.environment !== "production" || value.projectName !== requiredProjectName
      || typeof value.dockerDaemonId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(value.dockerDaemonId)) {
    invalid(`${label} environment/project/daemon identity is invalid.`);
  }
  exactHost(value.host, `${label} host`);
  exactSha256(value.sshHostKeySha256, `${label} SSH host-key SHA256`);
  exactSafeInteger(value.deploymentUid, `${label} deployment UID`, 1);
  exactSafeInteger(value.deploymentGid, `${label} deployment GID`, 1);
  return value;
}

function exactReleaseIdentity(value, label, identity) {
  exactObject(value, label, [
    "environmentFile", "environmentSha256", "releaseId", "releaseRoot", "stateId", "stateRoot",
  ]);
  const environmentSha256 = exactSha256(value.environmentSha256, `${label} environment SHA256`);
  const releaseId = `${identity.commitSha}-${identity.sourceArchiveSha256}`;
  const stateId = `${releaseId}-${environmentSha256}`;
  const releaseRoot = `/srv/platform-infrastructure/releases/${releaseId}`;
  const stateRoot = `/srv/platform-infrastructure/release-states/${stateId}`;
  if (value.releaseId !== releaseId || value.stateId !== stateId || value.releaseRoot !== releaseRoot
      || value.stateRoot !== stateRoot || value.environmentFile !== `${stateRoot}/environment.env`) {
    invalid(`${label} is not the exact deterministic target-local release/state identity.`);
  }
  return value;
}

function exactEnvironmentAuthority(value, label, target) {
  exactObject(value, label, ["gid", "mode", "nlink", "uid"]);
  if (value.uid !== 0 || value.gid !== target.deploymentGid || value.mode !== 0o640 || value.nlink !== 1) {
    invalid(`${label} must be root-owned, deployment-group readable, mode 0640 and singly linked.`);
  }
  return value;
}

function exactOpsRunner(value, label) {
  exactObject(value, label, ["image", "imageId", "providerAttested", "verificationFingerprint"]);
  exactImage(value.image, `${label} image`);
  exactImageId(value.imageId, `${label} image ID`);
  exactSha256(value.verificationFingerprint, `${label} verification fingerprint`);
  if (value.providerAttested !== true) invalid(`${label} must be provider-attested.`);
  return value;
}

function exactBroker(value, label, expected) {
  exactObject(value, label, ["path", "providerAttested", "sha256", "version"]);
  exactAbsolutePath(value.path, `${label} path`);
  exactSafeInteger(value.version, `${label} version`, 1);
  exactSha256(value.sha256, `${label} SHA256`);
  if (value.path !== "/usr/local/libexec/platform-hosted-preparation-broker"
      || value.providerAttested !== true || canonicalJson(value) !== canonicalJson(expected)) {
    invalid(`${label} is not the fixed provider-attested preparation broker.`);
  }
  return value;
}

function strictBase64(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    invalid(`${label} is not strict base64.`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) invalid(`${label} is not canonical base64.`);
  return bytes;
}

function dssePae(payloadType, payload) {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, "ascii"),
    type,
    Buffer.from(` ${payload.length} `, "ascii"),
    payload,
  ]);
}

function exactArtifact(artifact, label) {
  if (!artifact || !Buffer.isBuffer(artifact.bytes) || artifact.bytes.length < 2 || artifact.bytes.length > MAX_JSON_BYTES) {
    invalid(`${label} must be one explicitly supplied bounded artifact.`);
  }
  let document;
  try {
    const text = artifact.bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(artifact.bytes)) invalid(`${label} must be valid UTF-8.`);
    document = JSON.parse(text);
  } catch (error) {
    invalid(`${label} is invalid JSON: ${String(error?.message ?? error)}`);
  }
  if (!artifact.bytes.equals(Buffer.from(`${canonicalJson(document)}\n`, "utf8"))) {
    invalid(`${label} must use exact canonical JSON bytes.`);
  }
  return {
    bytes: artifact.bytes,
    document,
    sha256: crypto.createHash("sha256").update(artifact.bytes).digest("hex"),
  };
}

function verifyEnvelope(artifactValue, { label, payloadType, publicKey, keyId }) {
  const artifact = exactArtifact(artifactValue, label);
  const envelope = exactObject(artifact.document, `${label} DSSE envelope`, ["payload", "payloadType", "signatures"]);
  if (envelope.payloadType !== payloadType || !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    invalid(`${label} DSSE payload type or signature count is invalid.`);
  }
  const signature = exactObject(envelope.signatures[0], `${label} DSSE signature`, ["keyid", "sig"]);
  if (signature.keyid !== keyId) invalid(`${label} DSSE key ID is not authorized.`);
  const payloadBytes = strictBase64(envelope.payload, `${label} DSSE payload`);
  const signatureBytes = strictBase64(signature.sig, `${label} DSSE signature`);
  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    invalid(`${label} DSSE payload is not JSON.`);
  }
  if (!payloadBytes.equals(Buffer.from(canonicalJson(payload), "utf8"))) {
    invalid(`${label} DSSE payload is not exact canonical JSON.`);
  }
  if (!crypto.verify(null, dssePae(payloadType, payloadBytes), publicKey, signatureBytes)) {
    invalid(`${label} DSSE signature is invalid.`);
  }
  return { ...artifact, payload };
}

export function validateHostedPreparationConformanceContract(contract, { requireReady = true } = {}) {
  exactObject(contract, "Hosted preparation conformance contract", [
    "authorization", "dag", "kind", "preparationBroker", "providerInvariant", "reason", "receipt",
    "requiredFinalAdmissionKind", "requiredProjectName", "requiredRuntimeIntentKind", "selfAssertedEvidenceAccepted",
    "status", "trustedProducer", "version",
  ]);
  if (contract.version !== 1 || contract.kind !== CONFORMANCE_KIND
      || contract.selfAssertedEvidenceAccepted !== false
      || contract.requiredProjectName !== "platform_infra_vps"
      || contract.requiredFinalAdmissionKind !== "platform-trusted-deployment-admission/v1"
      || contract.requiredRuntimeIntentKind !== "platform-runtime-intent/v2") {
    invalid("Hosted preparation conformance contract identity is invalid.");
  }
  exactArray(contract.dag, REQUIRED_DAG, "Hosted preparation provider DAG");
  exactArray(contract.providerInvariant, REQUIRED_INVARIANT, "Hosted preparation provider invariant");
  exactObject(contract.authorization, "Hosted preparation authorization policy", [
    "maxLifetimeSeconds", "payloadType", "providerKeyId", "providerPublicKeyPem",
  ]);
  exactObject(contract.receipt, "Hosted preparation receipt policy", ["maxLifetimeSeconds", "payloadType"]);
  exactObject(contract.trustedProducer, "Hosted preparation trusted producer", [
    "event", "repository", "sourceRef", "workflowPath", "workflowSha",
  ]);
  exactObject(contract.preparationBroker, "Hosted preparation broker policy", [
    "path", "providerAttested", "sha256", "version",
  ]);
  if (contract.authorization.payloadType !== AUTHORIZATION_PAYLOAD_TYPE
      || contract.receipt.payloadType !== RECEIPT_PAYLOAD_TYPE
      || !Number.isSafeInteger(contract.authorization.maxLifetimeSeconds)
      || contract.authorization.maxLifetimeSeconds < 1 || contract.authorization.maxLifetimeSeconds > 900
      || !Number.isSafeInteger(contract.receipt.maxLifetimeSeconds)
      || contract.receipt.maxLifetimeSeconds < 1 || contract.receipt.maxLifetimeSeconds > 14400
      || typeof contract.reason !== "string" || contract.reason.length < 1) {
    invalid("Hosted preparation conformance policy bounds are invalid.");
  }
  if (contract.status === "EXTERNAL-PENDING") {
    if (contract.authorization.providerKeyId !== null || contract.authorization.providerPublicKeyPem !== null
        || Object.values(contract.trustedProducer).some((value) => value !== null)
        || contract.preparationBroker.version !== null || contract.preparationBroker.sha256 !== null
        || contract.preparationBroker.path !== "/usr/local/libexec/platform-hosted-preparation-broker"
        || contract.preparationBroker.providerAttested !== true) {
      invalid("EXTERNAL-PENDING hosted preparation contract must not contain self-asserted provider evidence.");
    }
    if (requireReady) invalid(`EXTERNAL-PENDING: ${contract.reason}`);
    return { status: contract.status };
  }
  if (contract.status !== "READY") invalid("Hosted preparation conformance status is invalid.");
  const trustedProducer = {
    repository: exactRepository(contract.trustedProducer.repository, "configured provider repository"),
    workflowPath: contract.trustedProducer.workflowPath,
    workflowSha: exactGitSha(contract.trustedProducer.workflowSha, "configured provider workflow SHA"),
    sourceRef: contract.trustedProducer.sourceRef,
    event: contract.trustedProducer.event,
  };
  if (!/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(trustedProducer.workflowPath)
      || trustedProducer.sourceRef !== "refs/heads/main" || trustedProducer.event !== "workflow_dispatch") {
    invalid("Configured hosted preparation producer identity is invalid.");
  }
  const providerPublicKey = exactPublicKey(
    contract.authorization.providerPublicKeyPem,
    contract.authorization.providerKeyId,
    "hosted preparation provider",
  );
  exactBroker(contract.preparationBroker, "Configured hosted preparation broker", contract.preparationBroker);
  return { ...contract, trustedProducer, providerPublicKey };
}

function validateAuthorization(payload, contract, now) {
  exactObject(payload, "Hosted preparation authorization", [
    "artifactVerificationReceiptSha256", "authorizationId", "consumerChallenge", "deploymentTarget", "environmentAuthority",
    "expiresAt", "issuedAt", "kind", "nonce", "notBefore", "operation", "opsRunner", "preparationBroker",
    "producer", "receiptSigner", "releaseIdentity", "repository", "sourceArchiveSha256", "status", "treeSha",
    "commitSha", "version",
  ]);
  if (payload.version !== 1 || payload.kind !== AUTHORIZATION_KIND || payload.status !== "AUTHORIZED"
      || payload.operation !== "prepare-hosted-workloads-v1" || typeof payload.authorizationId !== "string"
      || !IDENTIFIER.test(payload.authorizationId) || typeof payload.nonce !== "string" || !NONCE.test(payload.nonce)) {
    invalid("Hosted preparation authorization identity/status/operation is invalid.");
  }
  const identity = {
    repository: exactRepository(payload.repository, "authorization repository"),
    commitSha: exactGitSha(payload.commitSha, "authorization commit SHA"),
    treeSha: exactGitSha(payload.treeSha, "authorization tree SHA"),
    sourceArchiveSha256: exactSha256(payload.sourceArchiveSha256, "authorization source archive SHA256"),
  };
  exactSha256(payload.artifactVerificationReceiptSha256, "authorization artifact receipt SHA256");
  const target = exactTarget(payload.deploymentTarget, "authorization target", contract.requiredProjectName);
  const releaseIdentity = exactReleaseIdentity(payload.releaseIdentity, "authorization release identity", identity);
  exactEnvironmentAuthority(payload.environmentAuthority, "authorization environment authority", target);
  exactOpsRunner(payload.opsRunner, "authorization ops runner");
  exactBroker(payload.preparationBroker, "authorization preparation broker", contract.preparationBroker);
  const producer = exactProducer(payload.producer, "authorization producer", contract.trustedProducer);
  const challenge = exactConsumerChallenge(payload.consumerChallenge, "authorization consumer challenge");
  if (producer.repository === identity.repository || challenge.consumerRepository !== identity.repository) {
    invalid("Hosted preparation authorization is not independent from and bound to the candidate repository.");
  }
  const receiptSigner = exactObject(payload.receiptSigner, "authorization receipt signer", ["algorithm", "keyId", "publicKeyPem"]);
  if (receiptSigner.algorithm !== "ed25519") invalid("Authorization receipt signer algorithm is invalid.");
  const receiptPublicKey = exactPublicKey(receiptSigner.publicKeyPem, receiptSigner.keyId, "target-root receipt signer");
  const issuedAt = exactTimestamp(payload.issuedAt, "authorization issuedAt");
  const notBefore = exactTimestamp(payload.notBefore, "authorization notBefore");
  const expiresAt = exactTimestamp(payload.expiresAt, "authorization expiresAt");
  if (issuedAt.milliseconds > notBefore.milliseconds || expiresAt.milliseconds <= notBefore.milliseconds
      || expiresAt.milliseconds - issuedAt.milliseconds > contract.authorization.maxLifetimeSeconds * 1000
      || now < notBefore.milliseconds || now > expiresAt.milliseconds) {
    invalid("Hosted preparation authorization time window is invalid or inactive.");
  }
  return { payload, identity, target, releaseIdentity, producer, challenge, receiptPublicKey, issuedAt, notBefore, expiresAt };
}

function exactFileIdentity(value, label) {
  exactObject(value, label, ["device", "gid", "inode", "mode", "nlink", "path", "sha256", "size", "uid"]);
  exactAbsolutePath(value.path, `${label} path`);
  exactDecimal(value.device, `${label} device`);
  exactDecimal(value.inode, `${label} inode`, true);
  exactSafeInteger(value.uid, `${label} UID`);
  exactSafeInteger(value.gid, `${label} GID`);
  exactSafeInteger(value.mode, `${label} mode`);
  exactSafeInteger(value.nlink, `${label} nlink`, 1);
  exactSafeInteger(value.size, `${label} size`, 1);
  exactSha256(value.sha256, `${label} SHA256`);
  return value;
}

function exactDirectoryIdentity(value, label) {
  exactObject(value, label, ["device", "gid", "inode", "mode", "nlink", "uid"]);
  exactDecimal(value.device, `${label} device`);
  exactDecimal(value.inode, `${label} inode`, true);
  exactSafeInteger(value.uid, `${label} UID`);
  exactSafeInteger(value.gid, `${label} GID`);
  exactSafeInteger(value.mode, `${label} mode`);
  exactSafeInteger(value.nlink, `${label} nlink`, 1);
  return value;
}

function isStrictDescendant(candidate, root) {
  return candidate.startsWith(`${root}/`) && candidate !== root;
}

function validateReceipt(payload, authorization, authorizationSha256, contract, now) {
  exactObject(payload, "Hosted preparation receipt", [
    "artifactVerificationReceiptSha256", "authorizationEnvelopeSha256", "authorizationId", "combinedComposeSha256",
    "commitSha", "deploymentTarget", "environmentAfter", "environmentBefore", "expiresAt", "kind", "lock",
    "nonMutationProof", "nonce", "opsRunner", "preparationBroker", "preparedAt", "releaseIdentity", "repository",
    "snapshot", "sourceArchiveSha256", "sourceRenderSha256", "status", "treeSha", "version",
  ]);
  if (payload.version !== 1 || payload.kind !== RECEIPT_KIND || payload.status !== "PREPARED"
      || payload.authorizationEnvelopeSha256 !== authorizationSha256
      || payload.authorizationId !== authorization.payload.authorizationId || payload.nonce !== authorization.payload.nonce) {
    invalid("Hosted preparation receipt does not bind the exact preliminary authorization.");
  }
  for (const key of ["repository", "commitSha", "treeSha", "sourceArchiveSha256", "artifactVerificationReceiptSha256"] ) {
    if (payload[key] !== authorization.payload[key]) invalid(`Hosted preparation receipt ${key} differs from authorization.`);
  }
  if (canonicalJson(payload.deploymentTarget) !== canonicalJson(authorization.payload.deploymentTarget)
      || canonicalJson(payload.releaseIdentity) !== canonicalJson(authorization.payload.releaseIdentity)
      || canonicalJson(payload.opsRunner) !== canonicalJson(authorization.payload.opsRunner)
      || canonicalJson(payload.preparationBroker) !== canonicalJson(authorization.payload.preparationBroker)) {
    invalid("Hosted preparation receipt target/release/ops/broker projection differs from authorization.");
  }
  const before = exactFileIdentity(payload.environmentBefore, "preparation environment before");
  const after = exactFileIdentity(payload.environmentAfter, "preparation environment after");
  if (canonicalJson(before) !== canonicalJson(after)
      || before.path !== authorization.releaseIdentity.environmentFile
      || before.sha256 !== authorization.releaseIdentity.environmentSha256
      || before.uid !== authorization.payload.environmentAuthority.uid
      || before.gid !== authorization.payload.environmentAuthority.gid
      || before.mode !== authorization.payload.environmentAuthority.mode
      || before.nlink !== authorization.payload.environmentAuthority.nlink) {
    invalid("Preparation environment identity or bytes changed across PREPARE.");
  }
  const lock = exactObject(payload.lock, "preparation lock", [
    "combinedRenderSha256", "coreRenderSha256", "device", "gid", "inode", "mode", "nlink", "path", "sha256",
    "size", "state", "uid", "validatorVersion", "version",
  ]);
  exactAbsolutePath(lock.path, "preparation lock path");
  if (!isStrictDescendant(lock.path, authorization.releaseIdentity.stateRoot)
      || path.posix.basename(lock.path) !== "hosted-workloads.lock.json"
      || lock.version !== 4 || lock.validatorVersion !== "hosted-contract-v4" || lock.state !== "verified"
      || lock.uid !== authorization.target.deploymentUid || lock.gid !== authorization.target.deploymentGid
      || lock.mode !== 0o600 || lock.nlink !== 1) {
    invalid("Preparation lock is not the exact verified target-local Hosted v4 object.");
  }
  exactDecimal(lock.device, "preparation lock device");
  exactDecimal(lock.inode, "preparation lock inode", true);
  exactSafeInteger(lock.size, "preparation lock size", 1);
  exactSha256(lock.sha256, "preparation lock SHA256");
  exactSha256(lock.coreRenderSha256, "preparation lock core render SHA256");
  exactSha256(lock.combinedRenderSha256, "preparation lock combined render SHA256");
  if (payload.sourceRenderSha256 !== lock.coreRenderSha256
      || payload.combinedComposeSha256 !== lock.combinedRenderSha256
      || payload.sourceRenderSha256 === payload.combinedComposeSha256) {
    invalid("Preparation receipt render projection differs from the verified lock.");
  }
  const snapshot = exactObject(payload.snapshot, "preparation snapshot", [
    "durability", "generationIdentity", "generationPath", "parentIdentity", "parentPath", "rootIdentity", "rootPath",
  ]);
  for (const key of ["parentPath", "rootPath", "generationPath"]) exactAbsolutePath(snapshot[key], `snapshot ${key}`);
  if (!isStrictDescendant(snapshot.parentPath, authorization.releaseIdentity.stateRoot)
      || snapshot.parentPath !== path.posix.dirname(lock.path)
      || snapshot.rootPath !== `${snapshot.parentPath}/snapshots`
      || path.posix.dirname(snapshot.generationPath) !== snapshot.rootPath) {
    invalid("Preparation snapshot paths are not the exact lock-local target paths.");
  }
  const parentIdentity = exactDirectoryIdentity(snapshot.parentIdentity, "snapshot parent identity");
  const rootIdentity = exactDirectoryIdentity(snapshot.rootIdentity, "snapshot root identity");
  const generationIdentity = exactDirectoryIdentity(snapshot.generationIdentity, "snapshot generation identity");
  if ([parentIdentity, rootIdentity, generationIdentity].some((identity) =>
    identity.uid !== authorization.target.deploymentUid || identity.gid !== authorization.target.deploymentGid)
      || parentIdentity.mode !== 0o700 || rootIdentity.mode !== 0o700 || generationIdentity.mode !== 0o500) {
    invalid("Preparation snapshot identities are not deployment-owned and immutable.");
  }
  exactObject(snapshot.durability, "preparation snapshot durability", [
    "filesFsynced", "generationDirectoryFsynced", "rootDirectoryFsynced", "version",
  ]);
  if (snapshot.durability.version !== 1 || snapshot.durability.filesFsynced !== true
      || snapshot.durability.generationDirectoryFsynced !== true || snapshot.durability.rootDirectoryFsynced !== true) {
    invalid("Preparation snapshot has no complete durability proof.");
  }
  const nonMutation = exactObject(payload.nonMutationProof, "preparation non-mutation proof", [
    "activeSelectorAfterSha256", "activeSelectorBeforeSha256", "firewallStateAfterSha256", "firewallStateBeforeSha256",
    "runtimeInventoryAfterSha256", "runtimeInventoryBeforeSha256",
  ]);
  for (const key of Object.keys(nonMutation)) exactSha256(nonMutation[key], `preparation ${key}`);
  for (const pair of [
    ["activeSelectorBeforeSha256", "activeSelectorAfterSha256"],
    ["runtimeInventoryBeforeSha256", "runtimeInventoryAfterSha256"],
    ["firewallStateBeforeSha256", "firewallStateAfterSha256"],
  ]) {
    if (nonMutation[pair[0]] !== nonMutation[pair[1]]) invalid("Preparation changed protected runtime state.");
  }
  const preparedAt = exactTimestamp(payload.preparedAt, "preparation preparedAt");
  const expiresAt = exactTimestamp(payload.expiresAt, "preparation receipt expiresAt");
  if (preparedAt.milliseconds < authorization.notBefore.milliseconds
      || preparedAt.milliseconds > authorization.expiresAt.milliseconds
      || expiresAt.milliseconds <= preparedAt.milliseconds
      || expiresAt.milliseconds - preparedAt.milliseconds > contract.receipt.maxLifetimeSeconds * 1000
      || now < preparedAt.milliseconds || now > expiresAt.milliseconds) {
    invalid("Hosted preparation receipt time window is invalid or inactive.");
  }
  return { payload, lock, preparedAt, expiresAt };
}

function validateRuntimeIntentProjection(intent, receipt, requiredKind) {
  if (!intent || typeof intent !== "object" || !Array.isArray(intent.services)) {
    invalid("Final runtime intent is absent or malformed.");
  }
  // This reconstructs only the subject projection needed by the existing full
  // v2 structural validator. External artifact authentication remains the job
  // of the existing deployment-receipt gate; this result is non-authoritative.
  const artifactSubjectServices = intent.services.filter((service) => service?.admission?.kind === "artifact-subject");
  const artifactSubjects = artifactSubjectServices.map((service) => ({
    key: service.admission.subjectKey,
    image: service.image,
  }));
  const artifactPlatformImageIds = Object.fromEntries(artifactSubjectServices.map((service) => [
    service.admission.subjectKey,
    service.expectedLocalImageId,
  ]));
  validateRuntimeIntent(intent, {
    repository: receipt.payload.repository,
    commitSha: receipt.payload.commitSha,
    treeSha: receipt.payload.treeSha,
    sourceArchiveSha256: receipt.payload.sourceArchiveSha256,
    artifactSubjects,
    artifactPlatformImageIds,
    opsRunner: receipt.payload.opsRunner,
    projectName: receipt.payload.deploymentTarget.projectName,
    environmentSha256: receipt.payload.releaseIdentity.environmentSha256,
  });
  if (intent.version !== 2 || intent.kind !== requiredKind
      || intent.environmentSha256 !== receipt.payload.releaseIdentity.environmentSha256
      || intent.hostedWorkloadLockSha256 !== receipt.lock.sha256
      || intent.sourceRenderSha256 !== receipt.payload.sourceRenderSha256
      || intent.combinedComposeSha256 !== receipt.payload.combinedComposeSha256) {
    invalid("Final runtime intent does not bind the exact preparation receipt output projection.");
  }
  return intent;
}

function validateFinalAdmission(document, artifactSha256, authorization, receipt, contract, now) {
  exactObject(document, "Final deployment admission", [
    "artifactVerification", "artifactVerificationReceiptSha256", "commitSha", "consumerChallenge", "decisionId",
    "deploymentAdmission", "deploymentTarget", "generatedAt", "kind", "manifestSha256", "opsRunner", "privilegedRuntime",
    "producer", "repository", "runtimeIntent", "runtimeIntentSha256", "sbomSha256", "sourceArchiveSha256", "status",
    "treeSha", "verifier", "version",
  ]);
  if (document.version !== 1 || document.kind !== contract.requiredFinalAdmissionKind || document.status !== "READY"
      || document.artifactVerification !== "passed" || document.deploymentAdmission !== "READY") {
    invalid("Final deployment admission kind/version/status is invalid.");
  }
  for (const key of ["repository", "commitSha", "treeSha", "sourceArchiveSha256", "artifactVerificationReceiptSha256"]) {
    if (document[key] !== receipt.payload[key]) invalid(`Final deployment admission ${key} differs from preparation receipt.`);
  }
  exactSha256(document.manifestSha256, "final admission manifest SHA256");
  exactSha256(document.sbomSha256, "final admission SBOM SHA256");
  if (typeof document.decisionId !== "string" || !IDENTIFIER.test(document.decisionId)) invalid("Final admission decision ID is invalid.");
  const finalTarget = exactObject(document.deploymentTarget, "Final deployment target", ["environment", "host", "projectName"]);
  if (finalTarget.environment !== receipt.payload.deploymentTarget.environment
      || finalTarget.host !== receipt.payload.deploymentTarget.host
      || finalTarget.projectName !== receipt.payload.deploymentTarget.projectName) {
    invalid("Final deployment target differs from preparation target.");
  }
  if (canonicalJson(document.opsRunner) !== canonicalJson(receipt.payload.opsRunner)) {
    invalid("Final deployment ops runner differs from preparation authority.");
  }
  const producer = exactProducer(document.producer, "final admission producer", contract.trustedProducer);
  if (canonicalJson(producer) !== canonicalJson(authorization.producer)) {
    invalid("Final admission was not emitted by the same authenticated provider run as authorization.");
  }
  const challenge = exactConsumerChallenge(document.consumerChallenge, "final admission consumer challenge");
  if (canonicalJson(challenge) !== canonicalJson(authorization.challenge)) {
    invalid("Final admission consumer challenge differs from preliminary authorization.");
  }
  exactObject(document.verifier, "Final admission verifier", ["channel", "fingerprint", "selfAsserted", "verifiedAt"]);
  if (typeof document.verifier.channel !== "string" || document.verifier.channel.length < 1
      || document.verifier.selfAsserted !== false) {
    invalid("Final deployment admission verifier is self-asserted or unconfigured.");
  }
  exactSha256(document.verifier.fingerprint, "final admission verifier fingerprint");
  exactTimestamp(document.verifier.verifiedAt, "final admission verifiedAt");
  const generatedAt = exactTimestamp(document.generatedAt, "final admission generatedAt");
  if (generatedAt.milliseconds < receipt.preparedAt.milliseconds
      || generatedAt.milliseconds > receipt.expiresAt.milliseconds
      || generatedAt.milliseconds > now) {
    invalid("Final deployment admission was not emitted after PREPARE within receipt validity.");
  }
  const intent = validateRuntimeIntentProjection(document.runtimeIntent, receipt, contract.requiredRuntimeIntentKind);
  if (document.runtimeIntentSha256 !== runtimeIntentSha256(intent)) {
    invalid("Final deployment admission does not authenticate its exact runtime intent.");
  }
  exactObject(document.privilegedRuntime, "Final privileged runtime", [
    "activationBroker", "originFirewallHelper", "workloadEgressHelper",
  ]);
  for (const [name, pathname] of [
    ["activationBroker", "/usr/local/libexec/platform-activation-broker"],
    ["originFirewallHelper", "/usr/local/libexec/platform-origin-firewall"],
    ["workloadEgressHelper", "/usr/local/libexec/platform-workload-egress-firewall"],
  ]) {
    const helper = exactObject(document.privilegedRuntime[name], `Final ${name}`, ["path", "providerAttested", "sha256", "version"]);
    if (helper.path !== pathname || helper.providerAttested !== true || !Number.isSafeInteger(helper.version) || helper.version < 1) {
      invalid(`Final ${name} is invalid.`);
    }
    exactSha256(helper.sha256, `Final ${name} SHA256`);
  }
  return { document, sha256: artifactSha256 };
}

export function validateHostedPreparationProviderConformance({
  contract: contractDocument,
  authorizationArtifact,
  receiptArtifact,
  deploymentReceiptArtifact,
  now = Date.now(),
}) {
  if (!authorizationArtifact || !receiptArtifact || !deploymentReceiptArtifact) {
    invalid("Exact authorization, preparation receipt, and final deployment admission artifacts must be explicitly supplied.");
  }
  const contract = validateHostedPreparationConformanceContract(contractDocument, { requireReady: true });
  const authorizationEnvelope = verifyEnvelope(authorizationArtifact, {
    label: "provider preparation authorization",
    payloadType: contract.authorization.payloadType,
    publicKey: contract.providerPublicKey,
    keyId: contract.authorization.providerKeyId,
  });
  const authorization = validateAuthorization(authorizationEnvelope.payload, contract, now);
  const receiptEnvelope = verifyEnvelope(receiptArtifact, {
    label: "target-root preparation receipt",
    payloadType: contract.receipt.payloadType,
    publicKey: authorization.receiptPublicKey,
    keyId: authorization.payload.receiptSigner.keyId,
  });
  const receipt = validateReceipt(receiptEnvelope.payload, authorization, authorizationEnvelope.sha256, contract, now);
  const deploymentReceipt = exactArtifact(deploymentReceiptArtifact, "final deployment admission");
  validateFinalAdmission(deploymentReceipt.document, deploymentReceipt.sha256, authorization, receipt, contract, now);
  return Object.freeze({
    schema: "platform-hosted-preparation-provider-conformance-validation/v1",
    status: "STRUCTURALLY_CONSISTENT_NON_AUTHORITATIVE",
    authoritativeEvidence: false,
    authorizationEnvelopeSha256: authorizationEnvelope.sha256,
    preparationReceiptEnvelopeSha256: receiptEnvelope.sha256,
    finalDeploymentAdmissionSha256: deploymentReceipt.sha256,
  });
}

function parseArgs(values) {
  if (values.length !== 8) invalid("Usage: hosted-preparation-provider-conformance.mjs --contract FILE --authorization FILE --receipt FILE --deploymentReceipt FILE");
  const options = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || Object.hasOwn(options, key.slice(2))) {
      invalid("Hosted preparation conformance arguments are invalid or duplicated.");
    }
    options[key.slice(2)] = value;
  }
  exactObject(options, "Hosted preparation conformance arguments", ["authorization", "contract", "deploymentReceipt", "receipt"]);
  return options;
}

function captureJsonArtifact(filename, label) {
  const captured = snapshotFileArtifact(filename, { label, maxBytes: MAX_JSON_BYTES });
  return { ...captured, bytes: fs.readFileSync(captured.snapshotPath) };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const artifacts = [];
  try {
    const contractArtifact = captureJsonArtifact(options.contract, "hosted preparation conformance contract");
    const authorizationArtifact = captureJsonArtifact(options.authorization, "provider preparation authorization");
    const receiptArtifact = captureJsonArtifact(options.receipt, "target-root preparation receipt");
    const deploymentReceiptArtifact = captureJsonArtifact(options.deploymentReceipt, "final deployment admission");
    artifacts.push(contractArtifact, authorizationArtifact, receiptArtifact, deploymentReceiptArtifact);
    const contract = exactArtifact(contractArtifact, "hosted preparation conformance contract").document;
    const result = validateHostedPreparationProviderConformance({
      contract,
      authorizationArtifact,
      receiptArtifact,
      deploymentReceiptArtifact,
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
  } finally {
    for (const artifact of artifacts.reverse()) artifact.cleanup();
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
