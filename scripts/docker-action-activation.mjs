import crypto from "node:crypto";

import { canonicalJson } from "./docker-action-contract.mjs";

export const ACTIVATION_POLICY_SCHEMA = "platform.docker-runtime-activation-policy/v1";
export const ACTIVATION_PAYLOAD_SCHEMA = "platform.docker-runtime-activation/v2";
export const ACTIVATION_PAYLOAD_TYPE = "application/vnd.platform.docker-runtime-activation.v2+json";
export const DAST_CHAIN_SCHEMA = "platform.docker-dast-chain/v2";

const SHA256 = /^[a-f0-9]{64}$/;
const LOGICAL_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const MAX_ACTIVATION_LIFETIME_MS = 15 * 60_000;

export function normalizeActivationPolicy(value) {
  const policy = plainObject(value, "activation policy");
  exactKeys(policy, [
    "dastSigstoreSubject",
    "environment",
    "issuer",
    "keyId",
    "publicKeyPem",
    "schema",
    "status",
    "subject",
    "targetId",
  ], "activation policy");
  if (policy.schema !== ACTIVATION_POLICY_SCHEMA || policy.status !== "active") {
    fail(503, "provider/admin activation policy is external-pending");
  }
  for (const [name, value] of [
    ["issuer", policy.issuer],
    ["subject", policy.subject],
    ["dastSigstoreSubject", policy.dastSigstoreSubject],
    ["environment", policy.environment],
    ["targetId", policy.targetId],
  ]) {
    if (typeof value !== "string" || value.length < 1 || value.length > 512 || /[\0\r\n]/.test(value)) {
      fail(500, `activation policy ${name} is invalid`);
    }
  }
  if (!SHA256.test(String(policy.keyId ?? ""))) fail(500, "activation policy key ID is invalid");
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(policy.publicKeyPem);
  } catch {
    fail(500, "activation policy public key is invalid");
  }
  if (publicKey.asymmetricKeyType !== "ed25519") fail(500, "activation policy requires an Ed25519 root");
  const actualKeyId = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  if (!constantEqual(actualKeyId, policy.keyId)) fail(500, "activation policy root does not match its pinned key ID");
  return Object.freeze({ ...policy, publicKey });
}

export function verifyActivationEnvelope(rawEnvelope, policyValue, expected, { now = Date.now() } = {}) {
  const policy = policyValue?.publicKey ? policyValue : normalizeActivationPolicy(policyValue);
  const bytes = Buffer.isBuffer(rawEnvelope) ? rawEnvelope : Buffer.from(String(rawEnvelope ?? ""));
  let envelope;
  try {
    envelope = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(403, "activation envelope is not JSON");
  }
  if (!constantEqual(bytes, Buffer.from(`${canonicalJson(envelope)}\n`))) {
    fail(403, "activation envelope is not exact canonical JSON");
  }
  exactKeys(plainObject(envelope, "activation envelope"), ["payload", "payloadType", "signatures"], "activation envelope");
  if (envelope.payloadType !== ACTIVATION_PAYLOAD_TYPE || !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    fail(403, "activation envelope type or signature count is invalid");
  }
  const signature = plainObject(envelope.signatures[0], "activation signature");
  exactKeys(signature, ["keyid", "sig"], "activation signature");
  if (!constantEqual(String(signature.keyid ?? ""), policy.keyId)) fail(403, "activation signature key ID is not policy approved");
  const payloadBytes = strictBase64(String(envelope.payload ?? ""), "activation payload");
  const signatureBytes = strictBase64(String(signature.sig ?? ""), "activation signature");
  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    fail(403, "activation payload is not JSON");
  }
  if (!constantEqual(payloadBytes, Buffer.from(canonicalJson(payload)))) {
    fail(403, "activation payload is not exact canonical JSON");
  }
  const pae = dssePae(envelope.payloadType, payloadBytes);
  if (!crypto.verify(null, pae, policy.publicKey, signatureBytes)) fail(403, "activation DSSE signature is invalid");

  const normalized = normalizeActivationPayload(payload, policy, { now });
  bindExpected(normalized, expected);
  const envelopeSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  if (!constantEqual(envelopeSha256, String(expected?.activationEnvelopeSha256 ?? ""))) {
    fail(403, "activation CAS digest does not match the trusted context");
  }
  const dastChainSha256 = crypto.createHash("sha256").update(canonicalJson(normalized.dast)).digest("hex");
  const typedDigests = [
    envelopeSha256,
    normalized.releaseBundleSha256,
    normalized.dast.providerReceiptSha256,
    normalized.dastAuthorizationSha256,
    dastChainSha256,
    normalized.releaseBundleManifestSha256,
    normalized.treeSha256,
  ];
  if (new Set(typedDigests).size !== typedDigests.length) {
    fail(403, "activation typed digest identities collide");
  }
  return Object.freeze({ ...normalized, dastChainSha256, envelopeSha256 });
}

export function createActivationEnvelope(payload, privateKey, keyId) {
  const payloadBytes = Buffer.from(canonicalJson(payload));
  const signature = crypto.sign(null, dssePae(ACTIVATION_PAYLOAD_TYPE, payloadBytes), privateKey);
  const envelope = {
    payloadType: ACTIVATION_PAYLOAD_TYPE,
    payload: payloadBytes.toString("base64"),
    signatures: [{ keyid: keyId, sig: signature.toString("base64") }],
  };
  return Buffer.from(`${canonicalJson(envelope)}\n`);
}

function normalizeActivationPayload(value, policy, { now }) {
  const payload = plainObject(value, "activation payload");
  exactKeys(payload, [
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
    "releaseId",
    "releaseBundleManifestSha256",
    "releaseBundleSha256",
    "requestId",
    "runtimeIntentId",
    "schema",
    "sourceRenderSha256",
    "subject",
    "targetId",
    "treeSha256",
  ], "activation payload");
  if (payload.schema !== ACTIVATION_PAYLOAD_SCHEMA) fail(403, "activation payload schema is invalid");
  for (const [name, value] of [
    ["activationId", payload.activationId],
    ["candidateId", payload.candidateId],
    ["releaseId", payload.releaseId],
    ["runtimeIntentId", payload.runtimeIntentId],
  ]) {
    if (!LOGICAL_ID.test(String(value ?? ""))) fail(403, `activation ${name} is invalid`);
  }
  if (!Number.isSafeInteger(payload.generation) || payload.generation < 1) fail(403, "activation generation is invalid");
  if (!UUID_V4.test(String(payload.requestId ?? "")) || !NONCE.test(String(payload.nonce ?? ""))) {
    fail(403, "activation request identity is invalid");
  }
  for (const name of [
    "sourceRenderSha256",
    "combinedRenderSha256",
    "previousActiveSha256",
    "releaseBundleSha256",
    "releaseBundleManifestSha256",
    "dastAuthorizationSha256",
    "treeSha256",
  ]) {
    if (!SHA256.test(String(payload[name] ?? ""))) fail(403, `activation ${name} is invalid`);
  }
  if (payload.issuer !== policy.issuer || payload.subject !== policy.subject
    || payload.environment !== policy.environment || payload.targetId !== policy.targetId) {
    fail(403, "activation issuer, subject, environment or target is not policy approved");
  }
  const issuedAt = Date.parse(String(payload.issuedAt ?? ""));
  const notBefore = Date.parse(String(payload.notBefore ?? ""));
  const expiresAt = Date.parse(String(payload.expiresAt ?? ""));
  if (![issuedAt, notBefore, expiresAt].every(Number.isFinite) || issuedAt > notBefore || expiresAt <= notBefore
    || expiresAt - issuedAt > MAX_ACTIVATION_LIFETIME_MS || now < notBefore || now > expiresAt) {
    fail(403, "activation time window is invalid");
  }

  const dast = plainObject(payload.dast, "activation DAST chain");
  exactKeys(dast, [
    "commitSha",
    "consumerChallengeSha256",
    "providerMetadataSha256",
    "providerReceiptSha256",
    "providerRunId",
    "providerRunAttempt",
    "reportArtifactArchiveSha256",
    "reportArtifactId",
    "reportEvidenceSha256",
    "repository",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "scanRequestSha256",
    "schema",
    "sigstoreBundleSha256",
    "sigstoreSubject",
    "target",
    "targetServingInventoryHash",
    "treeSha",
    "verdict",
  ], "activation DAST chain");
  if (dast.schema !== DAST_CHAIN_SCHEMA) fail(403, "activation DAST chain schema is invalid");
  for (const name of [
    "consumerChallengeSha256",
    "providerMetadataSha256",
    "providerReceiptSha256",
    "reportArtifactArchiveSha256",
    "reportEvidenceSha256",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "scanRequestSha256",
    "sigstoreBundleSha256",
    "targetServingInventoryHash",
  ]) {
    if (!SHA256.test(String(dast[name] ?? ""))) fail(403, `activation DAST ${name} is invalid`);
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(dast.repository ?? ""))
    || !/^[a-f0-9]{40}$/.test(String(dast.commitSha ?? ""))
    || !/^[a-f0-9]{40}$/.test(String(dast.treeSha ?? ""))) {
    fail(403, "activation DAST repository, commit or tree is invalid");
  }
  let target;
  try {
    target = new URL(String(dast.target ?? ""));
  } catch {
    fail(403, "activation DAST target is invalid");
  }
  if (target.protocol !== "https:" || target.username || target.password || target.search
    || target.hash || target.pathname !== "/" || dast.target !== target.origin) {
    fail(403, "activation DAST target is invalid");
  }
  if (!isPositiveDecimalString(dast.providerRunId)
    || !Number.isSafeInteger(dast.providerRunAttempt) || dast.providerRunAttempt < 1
    || !isPositiveDecimalString(dast.reportArtifactId)
    || dast.verdict !== "pass"
    || dast.sigstoreSubject !== policy.dastSigstoreSubject) {
    fail(403, "activation DAST provider run, report artifact, verdict or Sigstore subject is invalid");
  }
  const derivedTreeSha256 = crypto.createHash("sha256")
    .update("platform-git-tree-sha1/v1\0", "utf8")
    .update(dast.treeSha, "utf8")
    .digest("hex");
  if (!constantEqual(payload.treeSha256, derivedTreeSha256)) {
    fail(403, "activation tree SHA256 is not derived from the DAST Git tree");
  }
  return Object.freeze({ ...payload, dast: Object.freeze({ ...dast }) });
}

function isPositiveDecimalString(value) {
  const text = String(value ?? "");
  const number = Number(text);
  return /^[1-9][0-9]*$/.test(text) && Number.isSafeInteger(number) && number >= 1
    && String(number) === text;
}

function bindExpected(payload, expected) {
  const dastChainSha256 = crypto.createHash("sha256").update(canonicalJson(payload.dast)).digest("hex");
  const expectedValues = {
    candidateId: expected?.candidateId,
    combinedRenderSha256: expected?.combinedRenderSha256,
    dastChainSha256: expected?.dastChainSha256,
    environment: expected?.environment,
    generation: expected?.generation,
    releaseId: expected?.releaseId,
    runtimeIntentId: expected?.runtimeIntentId,
    sourceRenderSha256: expected?.sourceRenderSha256,
    targetId: expected?.targetId,
    treeSha256: expected?.treeSha256,
  };
  for (const [name, value] of Object.entries(expectedValues)) {
    const actual = name === "dastChainSha256" ? dastChainSha256 : payload[name];
    if (typeof value === "number" ? actual !== value : !constantEqual(String(actual ?? ""), String(value ?? ""))) {
      fail(403, `activation ${name} does not match the trusted runtime context`);
    }
  }
  for (const name of [
    "dastAuthorizationSha256",
    "releaseBundleManifestSha256",
    "releaseBundleSha256",
  ]) {
    if (Object.hasOwn(expected ?? {}, name)
      && !constantEqual(String(payload[name] ?? ""), String(expected[name] ?? ""))) {
      fail(403, `activation ${name} does not match the trusted release context`);
    }
  }
}

function dssePae(payloadType, payload) {
  const type = Buffer.from(payloadType);
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `),
    type,
    Buffer.from(` ${payload.length} `),
    payload,
  ]);
}

function strictBase64(value, label) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) || value.length < 4) {
    fail(403, `${label} base64 is invalid`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) fail(403, `${label} base64 is non-canonical`);
  return bytes;
}

function plainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(403, `${label} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    fail(403, `${label} contains unsupported or missing fields`);
  }
}

function constantEqual(left, right) {
  const actual = Buffer.isBuffer(left) ? left : Buffer.from(String(left ?? ""));
  const expected = Buffer.isBuffer(right) ? right : Buffer.from(String(right ?? ""));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function fail(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  throw error;
}
