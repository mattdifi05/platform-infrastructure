#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PACKAGE_PAYLOAD_TYPE = 'application/vnd.platform.v1.phase-a.package-attestation.v1+json';
export const AUTHORIZATION_PAYLOAD_TYPE = 'application/vnd.platform.v1.phase-a.read-only-authorization.v1+json';
export const PERMITTED_OPERATIONS = Object.freeze(['READ_ONLY_LIVE_PREFLIGHT']);
export const FORBIDDEN_OPERATIONS = Object.freeze([
  'CREATE_BACKUP', 'QUIESCE', 'INSTALL', 'DOCKER', 'FIREWALL', 'ACTIVATE', 'RESTORE',
]);

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/;
const ROLE_KEYS = Object.freeze([
  'algorithm', 'keyId', 'producer', 'publicKeySpkiPem', 'role',
]);
const PRODUCER_KEYS = Object.freeze([
  'approvalApproverIdentity', 'approvalDecision', 'approvalEvidenceIdentity',
  'approvalEvidenceIssuedAt', 'approvalEvidenceSha256', 'eventName', 'headSha',
  'jobName', 'jobWorkflowSha', 'protectedEnvironment', 'ref', 'repository',
  'repositoryId', 'repositoryOwnerId', 'runAttempt', 'runId', 'workflowPath',
]);
const FUTURE_ROLE_KEYS = Object.freeze([
  'activationGate', 'activationTargetRoot', 'admissionController', 'backupAuthority',
  'deploymentGate', 'hostedGate', 'phaseBInstaller', 'sourceTargetCustodian',
]);
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function invalid(message) {
  throw new Error(message);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) invalid('Canonical JSON accepts only plain JSON objects.');
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  if (value === null || typeof value === 'string' || typeof value === 'boolean'
      || (typeof value === 'number' && Number.isFinite(value))) return value;
  invalid('Canonical JSON contains an unsupported value.');
}

function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactArray(value, expected, label) {
  if (!Array.isArray(value) || canonicalJson(value) !== canonicalJson(expected)) {
    invalid(`${label} is not the exact closed sequence.`);
  }
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) invalid(`${label} must be one lowercase SHA256.`);
  return value;
}

function exactGitSha(value, label) {
  if (typeof value !== 'string' || !GIT_SHA.test(value)) invalid(`${label} must be one full lowercase Git SHA.`);
  return value;
}

function exactRepository(value, label) {
  if (typeof value !== 'string' || !/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(value)
      || value !== value.toLowerCase()) {
    invalid(`${label} must use canonical lowercase owner/name syntax.`);
  }
  return value;
}

function exactDecimal(value, label, { positive = false } = {}) {
  const expression = positive ? POSITIVE_DECIMAL : DECIMAL;
  if (typeof value !== 'string' || !expression.test(value)) invalid(`${label} must be one canonical decimal string.`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || String(number) !== value) invalid(`${label} exceeds the safe canonical range.`);
  return value;
}

function exactInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) invalid(`${label} must be an integer >= ${minimum}.`);
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== 'string') invalid(`${label} must be a canonical UTC timestamp.`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(`${label} must be a canonical UTC timestamp.`);
  }
  return { value, milliseconds };
}

function exactIdentifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) invalid(`${label} is invalid.`);
  return value;
}

function exactAbsolutePath(value, label) {
  if (typeof value !== 'string' || !/^\/[A-Za-z0-9._/-]+$/.test(value)
      || value.includes('//') || value.split('/').some((part) => part === '.' || part === '..')
      || path.posix.normalize(value) !== value) {
    invalid(`${label} must be one normalized absolute path.`);
  }
  return value;
}

function exactWorkflowPath(value, label) {
  if (typeof value !== 'string' || !/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(value)) {
    invalid(`${label} is invalid.`);
  }
  return value;
}

function exactNonce(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) invalid(`${label} is not a 256-bit base64url nonce.`);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) invalid(`${label} is not a canonical 256-bit base64url nonce.`);
  return value;
}

function exactPublicKey(publicKeyPem, expectedKeyId, label) {
  if (typeof publicKeyPem !== 'string'
      || !publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n')
      || !publicKeyPem.endsWith('-----END PUBLIC KEY-----\n')) {
    invalid(`${label} must use canonical SPKI public-key PEM.`);
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch {
    invalid(`${label} must use canonical SPKI public-key PEM.`);
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') invalid(`${label} must be an Ed25519 public key.`);
  const canonicalPem = publicKey.export({ type: 'spki', format: 'pem' });
  if (canonicalPem !== publicKeyPem) invalid(`${label} SPKI PEM is not canonical.`);
  const keyId = crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  if (keyId !== exactSha256(expectedKeyId, `${label} key ID`)) invalid(`${label} key ID does not match SHA256(SPKI DER).`);
  return publicKey;
}

function pendingProducer() {
  return Object.fromEntries(PRODUCER_KEYS.map((key) => [key, null]));
}

function exactProducer(value, label) {
  exactObject(value, label, PRODUCER_KEYS);
  const producer = {
    repository: exactRepository(value.repository, `${label} repository`),
    repositoryId: exactDecimal(value.repositoryId, `${label} repository ID`, { positive: true }),
    repositoryOwnerId: exactDecimal(value.repositoryOwnerId, `${label} repository owner ID`, { positive: true }),
    workflowPath: exactWorkflowPath(value.workflowPath, `${label} workflow path`),
    jobWorkflowSha: exactGitSha(value.jobWorkflowSha, `${label} job workflow SHA`),
    headSha: exactGitSha(value.headSha, `${label} head SHA`),
    ref: value.ref,
    eventName: value.eventName,
    runId: exactDecimal(value.runId, `${label} run ID`, { positive: true }),
    runAttempt: exactInteger(value.runAttempt, `${label} run attempt`, 1),
    jobName: exactIdentifier(value.jobName, `${label} job name`),
    protectedEnvironment: exactIdentifier(value.protectedEnvironment, `${label} protected environment`),
    approvalDecision: value.approvalDecision,
    approvalApproverIdentity: exactIdentifier(value.approvalApproverIdentity, `${label} approval approver`),
    approvalEvidenceIdentity: exactIdentifier(value.approvalEvidenceIdentity, `${label} approval evidence identity`),
    approvalEvidenceSha256: exactSha256(value.approvalEvidenceSha256, `${label} approval evidence SHA256`),
    approvalEvidenceIssuedAt: exactTimestamp(value.approvalEvidenceIssuedAt, `${label} approval evidence timestamp`).value,
  };
  if (producer.ref !== 'refs/heads/main' || producer.eventName !== 'workflow_dispatch'
      || producer.approvalDecision !== 'APPROVED'
      || !producer.approvalEvidenceIdentity.endsWith(`:${producer.runId}:${producer.runAttempt}`)) {
    invalid(`${label} main/dispatch/protected approval binding is invalid.`);
  }
  return producer;
}

function exactRole(value, label, expectedRole) {
  exactObject(value, label, ROLE_KEYS);
  if (value.role !== expectedRole || value.algorithm !== 'Ed25519') invalid(`${label} role/algorithm is invalid.`);
  const producer = exactProducer(value.producer, `${label} producer`);
  const publicKey = exactPublicKey(value.publicKeySpkiPem, value.keyId, label);
  return { ...value, producer, publicKey };
}

function validatePendingRole(value, label, role) {
  exactObject(value, label, ROLE_KEYS);
  if (value.role !== role || value.algorithm !== 'Ed25519' || value.keyId !== null || value.publicKeySpkiPem !== null) {
    invalid(`EXTERNAL-PENDING ${label} must not contain a trust key.`);
  }
  exactObject(value.producer, `${label} producer`, PRODUCER_KEYS);
  if (canonicalJson(value.producer) !== canonicalJson(pendingProducer())) {
    invalid(`EXTERNAL-PENDING ${label} producer trust bindings must remain null.`);
  }
}

export function validateV1PhaseAPolicy(policy, { requireReady = true } = {}) {
  exactObject(policy, 'Phase A policy', [
    'authorization', 'authoritativeEvidence', 'candidate', 'futureRoleKeyIds', 'localTemplate',
    'packageAttestation', 'packageAttestor', 'phaseAAuthorizationProvider', 'reason',
    'replayLedgerStatus', 'schema', 'selfAssertedEvidenceAccepted', 'status',
    'trustAnchorProvenance', 'twoPhaseOrderContract', 'version',
  ]);
  if (policy.schema !== 'platform.v1-phase-a-authorization-policy/v1' || policy.version !== 1
      || policy.authoritativeEvidence !== false || policy.selfAssertedEvidenceAccepted !== false
      || policy.replayLedgerStatus !== 'EXTERNAL_PENDING'
      || typeof policy.reason !== 'string' || policy.reason.length < 20) {
    invalid('Phase A policy identity or fail-closed evidence state is invalid.');
  }
  exactObject(policy.packageAttestation, 'Phase A package-attestation policy', ['maxLifetimeSeconds', 'payloadType']);
  exactObject(policy.authorization, 'Phase A authorization policy', [
    'forbiddenOperations', 'maxLifetimeSeconds', 'payloadType', 'permittedOperations',
  ]);
  if (policy.packageAttestation.payloadType !== PACKAGE_PAYLOAD_TYPE
      || policy.authorization.payloadType !== AUTHORIZATION_PAYLOAD_TYPE
      || policy.packageAttestation.payloadType === policy.authorization.payloadType
      || !Number.isSafeInteger(policy.packageAttestation.maxLifetimeSeconds)
      || policy.packageAttestation.maxLifetimeSeconds < 1 || policy.packageAttestation.maxLifetimeSeconds > 900
      || !Number.isSafeInteger(policy.authorization.maxLifetimeSeconds)
      || policy.authorization.maxLifetimeSeconds < 1 || policy.authorization.maxLifetimeSeconds > 600) {
    invalid('Phase A payload domains or lifetime policy are invalid.');
  }
  exactArray(policy.authorization.permittedOperations, PERMITTED_OPERATIONS, 'Phase A permitted operations');
  exactArray(policy.authorization.forbiddenOperations, FORBIDDEN_OPERATIONS, 'Phase A forbidden operations');
  exactObject(policy.twoPhaseOrderContract, 'Phase A two-phase order contract', ['id', 'sha256']);
  exactObject(policy.futureRoleKeyIds, 'Phase A future-role key IDs', FUTURE_ROLE_KEYS);
  exactObject(policy.candidate, 'Phase A policy candidate', [
    'clean', 'commitSha', 'packageManifestSha256', 'packageSha256', 'repository',
    'repositoryId', 'repositoryOwnerId', 'sourceArchiveSha256', 'treeSha',
  ]);

  if (policy.status === 'EXTERNAL-PENDING') {
    if (policy.localTemplate !== true || policy.trustAnchorProvenance !== 'NOT_CONFIGURED'
        || Object.values(policy.candidate).some((value) => value !== null)
        || policy.twoPhaseOrderContract.id !== null || policy.twoPhaseOrderContract.sha256 !== null
        || Object.values(policy.futureRoleKeyIds).some((value) => value !== null)) {
      invalid('EXTERNAL-PENDING Phase A template trust bindings must remain null and non-authoritative.');
    }
    validatePendingRole(policy.packageAttestor, 'package attestor', 'packageAttestor');
    validatePendingRole(policy.phaseAAuthorizationProvider, 'authorization provider', 'phaseAAuthorizationProvider');
    if (requireReady) invalid(`EXTERNAL-PENDING: ${policy.reason}`);
    return Object.freeze({ status: 'EXTERNAL-PENDING' });
  }

  if (policy.status !== 'READY' || policy.localTemplate !== false
      || policy.trustAnchorProvenance !== 'CALLER-SUPPLIED-NON-AUTHORITATIVE') {
    invalid('Phase A verifier accepts only an explicitly supplied external READY policy in caller-anchored non-authoritative mode.');
  }
  exactIdentifier(policy.twoPhaseOrderContract.id, 'Phase A two-phase order contract ID');
  exactSha256(policy.twoPhaseOrderContract.sha256, 'Phase A two-phase order contract SHA256');
  const candidate = exactCandidate(policy.candidate, 'Phase A policy candidate');
  const packageAttestor = exactRole(policy.packageAttestor, 'Phase A package attestor', 'packageAttestor');
  const authorizationProvider = exactRole(
    policy.phaseAAuthorizationProvider, 'Phase A authorization provider', 'phaseAAuthorizationProvider',
  );
  const futureKeyIds = FUTURE_ROLE_KEYS.map((role) => exactSha256(policy.futureRoleKeyIds[role], `Phase A ${role} key ID`));
  const allKeyIds = [packageAttestor.keyId, authorizationProvider.keyId, ...futureKeyIds];
  if (new Set(allKeyIds).size !== allKeyIds.length
      || packageAttestor.producer.workflowPath === authorizationProvider.producer.workflowPath
      || canonicalJson(packageAttestor.producer) === canonicalJson(authorizationProvider.producer)) {
    invalid('Phase A package, authorization, and future role keys/producers must be separated.');
  }
  return Object.freeze({ ...policy, candidate, packageAttestor, authorizationProvider });
}

function exactArtifact(artifact, label) {
  if (!artifact || !Buffer.isBuffer(artifact.bytes) || artifact.bytes.length < 3
      || artifact.bytes.length > MAX_ARTIFACT_BYTES) {
    invalid(`${label} must be an explicitly supplied bounded artifact.`);
  }
  let document;
  try {
    const text = utf8Decoder.decode(artifact.bytes);
    document = JSON.parse(text);
  } catch (error) {
    invalid(`${label} is not valid UTF-8 JSON: ${String(error?.message ?? error)}`);
  }
  if (!artifact.bytes.equals(Buffer.from(`${canonicalJson(document)}\n`, 'utf8'))) {
    invalid(`${label} must use exact canonical JSON bytes with one LF.`);
  }
  return Object.freeze({
    bytes: artifact.bytes,
    document,
    sha256: crypto.createHash('sha256').update(artifact.bytes).digest('hex'),
  });
}

function strictBase64(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    invalid(`${label} is not strict base64.`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) invalid(`${label} is not canonical base64.`);
  return bytes;
}

function dssePae(payloadType, payloadBytes) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'ascii'), type,
    Buffer.from(` ${payloadBytes.length} `, 'ascii'), payloadBytes,
  ]);
}

function verifyEnvelope(artifactValue, { label, payloadType, publicKey, keyId }) {
  const artifact = exactArtifact(artifactValue, label);
  const envelope = exactObject(artifact.document, `${label} DSSE envelope`, ['payload', 'payloadType', 'signatures']);
  if (envelope.payloadType !== payloadType || !Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    invalid(`${label} DSSE payload type or signature count is invalid.`);
  }
  const signature = exactObject(envelope.signatures[0], `${label} DSSE signature`, ['keyid', 'sig']);
  if (signature.keyid !== keyId) invalid(`${label} DSSE key role is not authorized.`);
  const payloadBytes = strictBase64(envelope.payload, `${label} DSSE payload`);
  const signatureBytes = strictBase64(signature.sig, `${label} DSSE signature`);
  let payload;
  try {
    payload = JSON.parse(utf8Decoder.decode(payloadBytes));
  } catch {
    invalid(`${label} DSSE payload is not valid UTF-8 JSON.`);
  }
  if (!payloadBytes.equals(Buffer.from(canonicalJson(payload), 'utf8'))) {
    invalid(`${label} DSSE payload is not exact canonical JSON.`);
  }
  if (!crypto.verify(null, dssePae(payloadType, payloadBytes), publicKey, signatureBytes)) {
    invalid(`${label} DSSE signature is invalid.`);
  }
  return Object.freeze({ ...artifact, payload });
}

function exactCandidate(value, label) {
  exactObject(value, label, [
    'clean', 'commitSha', 'packageManifestSha256', 'packageSha256', 'repository',
    'repositoryId', 'repositoryOwnerId', 'sourceArchiveSha256', 'treeSha',
  ]);
  const candidate = {
    repository: exactRepository(value.repository, `${label} repository`),
    repositoryId: exactDecimal(value.repositoryId, `${label} repository ID`, { positive: true }),
    repositoryOwnerId: exactDecimal(value.repositoryOwnerId, `${label} repository owner ID`, { positive: true }),
    commitSha: exactGitSha(value.commitSha, `${label} commit SHA`),
    treeSha: exactGitSha(value.treeSha, `${label} tree SHA`),
    clean: value.clean,
    sourceArchiveSha256: exactSha256(value.sourceArchiveSha256, `${label} source archive SHA256`),
    packageSha256: exactSha256(value.packageSha256, `${label} package SHA256`),
    packageManifestSha256: exactSha256(value.packageManifestSha256, `${label} package manifest SHA256`),
  };
  if (candidate.clean !== true) invalid(`${label} must bind a clean candidate.`);
  return candidate;
}

function exactEndpoint(value, label) {
  if (typeof value !== 'string') invalid(`${label} is invalid.`);
  let url;
  try { url = new URL(value); } catch { invalid(`${label} is invalid.`); }
  if (url.protocol !== 'ssh:' || !url.username || url.password || !url.hostname || !url.port
      || url.pathname !== '' || url.search || url.hash || url.toString() !== value) invalid(`${label} is invalid.`);
  return { value, hostname: url.hostname };
}

function exactTarget(value, label) {
  exactObject(value, label, [
    'deploymentGid', 'deploymentUid', 'dockerDaemonId', 'endpoint', 'hostname',
    'machineIdentitySha256', 'rootFilesystemIdentitySha256', 'sshHostKeySha256', 'targetRoot',
  ]);
  const endpoint = exactEndpoint(value.endpoint, `${label} endpoint`);
  const target = {
    endpoint: endpoint.value,
    hostname: value.hostname,
    targetRoot: exactAbsolutePath(value.targetRoot, `${label} root`),
    sshHostKeySha256: exactSha256(value.sshHostKeySha256, `${label} SSH host-key SHA256`),
    dockerDaemonId: exactIdentifier(value.dockerDaemonId, `${label} Docker daemon ID`),
    machineIdentitySha256: exactSha256(value.machineIdentitySha256, `${label} machine identity SHA256`),
    rootFilesystemIdentitySha256: exactSha256(value.rootFilesystemIdentitySha256, `${label} root filesystem identity SHA256`),
    deploymentUid: exactInteger(value.deploymentUid, `${label} deployment UID`, 1),
    deploymentGid: exactInteger(value.deploymentGid, `${label} deployment GID`, 1),
  };
  if (target.hostname !== endpoint.hostname) invalid(`${label} hostname does not match its SSH endpoint.`);
  return target;
}

function exactChallenge(value, label, now) {
  exactObject(value, label, [
    'consumerJob', 'consumerJobWorkflowSha', 'consumerRepository', 'consumerRunAttempt',
    'consumerRunId', 'consumerWorkflowPath', 'expiresAt', 'issuedAt', 'nonce', 'replayDomain',
  ]);
  const issuedAt = exactTimestamp(value.issuedAt, `${label} issued-at`);
  const expiresAt = exactTimestamp(value.expiresAt, `${label} expires-at`);
  const challenge = {
    consumerRepository: exactRepository(value.consumerRepository, `${label} repository`),
    consumerWorkflowPath: exactWorkflowPath(value.consumerWorkflowPath, `${label} workflow path`),
    consumerJobWorkflowSha: exactGitSha(value.consumerJobWorkflowSha, `${label} job workflow SHA`),
    consumerJob: exactIdentifier(value.consumerJob, `${label} job`),
    consumerRunId: exactDecimal(value.consumerRunId, `${label} run ID`, { positive: true }),
    consumerRunAttempt: exactInteger(value.consumerRunAttempt, `${label} run attempt`, 1),
    nonce: exactNonce(value.nonce, `${label} nonce`),
    replayDomain: value.replayDomain,
    issuedAt: issuedAt.value,
    expiresAt: expiresAt.value,
  };
  if (challenge.replayDomain !== 'phase-a-read-only-preflight/platform-infrastructure/v1'
      || expiresAt.milliseconds <= issuedAt.milliseconds
      || expiresAt.milliseconds - issuedAt.milliseconds > 15 * 60 * 1000
      || now < issuedAt.milliseconds || now >= expiresAt.milliseconds) {
    invalid(`${label} freshness or replay domain is invalid.`);
  }
  return challenge;
}

function exactOrder(value, label) {
  exactObject(value, label, ['id', 'sha256']);
  return { id: exactIdentifier(value.id, `${label} ID`), sha256: exactSha256(value.sha256, `${label} SHA256`) };
}

function exactTimes(payload, label, maxLifetimeSeconds, now) {
  const issuedAt = exactTimestamp(payload.issuedAt, `${label} issued-at`);
  const notBefore = exactTimestamp(payload.notBefore, `${label} not-before`);
  const expiresAt = exactTimestamp(payload.expiresAt, `${label} expires-at`);
  if (notBefore.value !== issuedAt.value || expiresAt.milliseconds <= issuedAt.milliseconds
      || expiresAt.milliseconds - issuedAt.milliseconds > maxLifetimeSeconds * 1000
      || now < notBefore.milliseconds || now >= expiresAt.milliseconds) {
    invalid(`${label} lifetime, freshness, or canonical ordering is invalid.`);
  }
  return { issuedAt, expiresAt };
}

function exactContext(payload, label, expected, now) {
  const candidate = exactCandidate(payload.candidate, `${label} candidate`);
  const target = exactTarget(payload.target, `${label} target`);
  const challenge = exactChallenge(payload.consumerChallenge, `${label} consumer challenge`, now);
  const order = exactOrder(payload.twoPhaseOrderContract, `${label} two-phase order contract`);
  for (const [actual, wanted, binding] of [
    [candidate, expected.candidate, 'candidate'], [target, expected.target, 'target'],
    [challenge, expected.consumerChallenge, 'consumer challenge'],
    [order, expected.twoPhaseOrderContract, 'two-phase order contract'],
  ]) {
    if (canonicalJson(actual) !== canonicalJson(wanted)) invalid(`${label} ${binding} differs from the exact expected input.`);
  }
  return { candidate, target, challenge, order };
}

function validatePackagePayload(payload, policy, expected, now) {
  exactObject(payload, 'Phase A package attestation', [
    'attestationId', 'candidate', 'consumerChallenge', 'expiresAt', 'issuedAt', 'notBefore',
    'producer', 'replayLedgerStatus', 'role', 'schema', 'status', 'target',
    'twoPhaseOrderContract', 'version',
  ]);
  if (payload.schema !== 'platform.v1-phase-a-package-attestation/v1' || payload.version !== 1
      || payload.status !== 'PACKAGE-ATTESTED' || payload.role !== 'packageAttestor'
      || payload.replayLedgerStatus !== 'EXTERNAL_PENDING') invalid('Phase A package attestation identity/status/role/replay state is invalid.');
  exactIdentifier(payload.attestationId, 'Phase A package attestation ID');
  const producer = exactProducer(payload.producer, 'Phase A package-attestation producer');
  if (canonicalJson(producer) !== canonicalJson(policy.packageAttestor.producer)) {
    invalid('Phase A package-attestation producer differs from policy.');
  }
  const times = exactTimes(payload, 'Phase A package attestation', policy.packageAttestation.maxLifetimeSeconds, now);
  const context = exactContext(payload, 'Phase A package attestation', expected, now);
  const approval = exactTimestamp(producer.approvalEvidenceIssuedAt, 'Phase A package approval timestamp');
  const challengeIssuedAt = exactTimestamp(context.challenge.issuedAt, 'Phase A package challenge timestamp');
  if (approval.milliseconds < challengeIssuedAt.milliseconds || approval.milliseconds > times.issuedAt.milliseconds) {
    invalid('Phase A package approval must follow the challenge and precede production.');
  }
  return { payload, producer, times, context };
}

function validateAuthorizationPayload(payload, policy, expected, packageEnvelope, packageValue, now) {
  exactObject(payload, 'Phase A read-only authorization', [
    'authorizationId', 'candidate', 'consumerChallenge', 'expiresAt', 'forbiddenOperations',
    'issuedAt', 'mutationAuthority', 'notBefore', 'packageAttestationEnvelopeSha256',
    'permittedOperations', 'producer', 'readOnly', 'replayLedgerStatus', 'role', 'schema',
    'status', 'target', 'twoPhaseOrderContract', 'version',
  ]);
  if (payload.schema !== 'platform.v1-phase-a-read-only-authorization/v1' || payload.version !== 1
      || payload.status !== 'READ-ONLY-AUTHORIZED' || payload.role !== 'phaseAAuthorizationProvider'
      || payload.replayLedgerStatus !== 'EXTERNAL_PENDING' || payload.readOnly !== true
      || payload.mutationAuthority !== false) invalid('Phase A authorization identity/status/read-only/replay state is invalid.');
  exactIdentifier(payload.authorizationId, 'Phase A authorization ID');
  exactSha256(payload.packageAttestationEnvelopeSha256, 'Phase A package envelope SHA256');
  if (payload.packageAttestationEnvelopeSha256 !== packageEnvelope.sha256) {
    invalid('Phase A authorization does not reference the exact package-attestation envelope.');
  }
  exactArray(payload.permittedOperations, PERMITTED_OPERATIONS, 'Phase A authorized operations');
  exactArray(payload.forbiddenOperations, FORBIDDEN_OPERATIONS, 'Phase A forbidden operations');
  const producer = exactProducer(payload.producer, 'Phase A authorization producer');
  if (canonicalJson(producer) !== canonicalJson(policy.authorizationProvider.producer)) {
    invalid('Phase A authorization producer differs from policy.');
  }
  const times = exactTimes(payload, 'Phase A read-only authorization', policy.authorization.maxLifetimeSeconds, now);
  const context = exactContext(payload, 'Phase A authorization', expected, now);
  const approval = exactTimestamp(producer.approvalEvidenceIssuedAt, 'Phase A authorization approval timestamp');
  const challengeIssuedAt = exactTimestamp(context.challenge.issuedAt, 'Phase A authorization challenge timestamp');
  if (approval.milliseconds < challengeIssuedAt.milliseconds || approval.milliseconds > times.issuedAt.milliseconds
      || times.issuedAt.milliseconds < packageValue.times.issuedAt.milliseconds
      || times.issuedAt.milliseconds > packageValue.times.expiresAt.milliseconds) {
    invalid('Phase A authorization approval or package-before-authorization order is invalid.');
  }
  if (canonicalJson(context) !== canonicalJson(packageValue.context)) {
    invalid('Phase A authorization context differs from its package attestation.');
  }
  return { payload, producer, times, context };
}

function validateExpected(expected, now) {
  exactObject(expected, 'Phase A expected inputs', [
    'authorizationProviderKeyId', 'candidate', 'consumerChallenge', 'packageAttestorKeyId',
    'policySha256', 'target', 'twoPhaseOrderContract',
  ]);
  const normalized = {
    policySha256: exactSha256(expected.policySha256, 'expected Phase A policy SHA256'),
    packageAttestorKeyId: exactSha256(expected.packageAttestorKeyId, 'expected package-attestor key ID'),
    authorizationProviderKeyId: exactSha256(expected.authorizationProviderKeyId, 'expected authorization-provider key ID'),
    candidate: exactCandidate(expected.candidate, 'expected Phase A candidate'),
    target: exactTarget(expected.target, 'expected Phase A target'),
    consumerChallenge: exactChallenge(expected.consumerChallenge, 'expected Phase A consumer challenge', now),
    twoPhaseOrderContract: exactOrder(expected.twoPhaseOrderContract, 'expected Phase A two-phase order contract'),
  };
  if (normalized.packageAttestorKeyId === normalized.authorizationProviderKeyId) {
    invalid('Expected Phase A package and authorization key roles must be distinct.');
  }
  return normalized;
}

export function verifyV1PhaseAAuthorization({
  policyArtifact,
  packageAttestationArtifact,
  authorizationArtifact,
  expected,
  now = Date.now(),
}) {
  if (!Number.isFinite(now)) invalid('Phase A verification clock is invalid.');
  const expectedInput = validateExpected(expected, now);
  const policyValue = exactArtifact(policyArtifact, 'Phase A policy');
  if (policyValue.sha256 !== expectedInput.policySha256) invalid('Phase A policy SHA256 differs from the caller-supplied binding.');
  const policy = validateV1PhaseAPolicy(policyValue.document, { requireReady: true });
  if (policy.packageAttestor.keyId !== expectedInput.packageAttestorKeyId
      || policy.authorizationProvider.keyId !== expectedInput.authorizationProviderKeyId) {
    invalid('Phase A policy key IDs differ from the caller-supplied role bindings.');
  }
  if (policy.packageAttestor.producer.repository === expectedInput.candidate.repository
      || policy.authorizationProvider.producer.repository === expectedInput.candidate.repository
      || policy.packageAttestor.producer.repository.toLowerCase() === expectedInput.candidate.repository.toLowerCase()
      || policy.authorizationProvider.producer.repository.toLowerCase() === expectedInput.candidate.repository.toLowerCase()
      || policy.packageAttestor.producer.repositoryId === expectedInput.candidate.repositoryId
      || policy.authorizationProvider.producer.repositoryId === expectedInput.candidate.repositoryId
      || policy.packageAttestor.producer.repositoryOwnerId === expectedInput.candidate.repositoryOwnerId
      || policy.authorizationProvider.producer.repositoryOwnerId === expectedInput.candidate.repositoryOwnerId) {
    invalid('Phase A provider repository slug, immutable repository ID, and owner ID must be independent from the candidate.');
  }
  if (canonicalJson(policy.candidate) !== canonicalJson(expectedInput.candidate)) {
    invalid('Phase A policy binds a different exact candidate identity.');
  }
  if (canonicalJson(policy.twoPhaseOrderContract) !== canonicalJson(expectedInput.twoPhaseOrderContract)) {
    invalid('Phase A policy binds a different two-phase order contract.');
  }

  const packageEnvelope = verifyEnvelope(packageAttestationArtifact, {
    label: 'Phase A package attestation', payloadType: PACKAGE_PAYLOAD_TYPE,
    publicKey: policy.packageAttestor.publicKey, keyId: policy.packageAttestor.keyId,
  });
  const packageValue = validatePackagePayload(packageEnvelope.payload, policy, expectedInput, now);
  const authorizationEnvelope = verifyEnvelope(authorizationArtifact, {
    label: 'Phase A read-only authorization', payloadType: AUTHORIZATION_PAYLOAD_TYPE,
    publicKey: policy.authorizationProvider.publicKey, keyId: policy.authorizationProvider.keyId,
  });
  validateAuthorizationPayload(
    authorizationEnvelope.payload, policy, expectedInput, packageEnvelope, packageValue, now,
  );
  if (authorizationEnvelope.sha256 === packageEnvelope.sha256) invalid('Phase A DSSE envelopes are not distinct.');

  return deepFreeze({
    schema: 'platform.v1-phase-a-verification/v1',
    status: 'SIGNATURE_VERIFIED_NON_AUTHORITATIVE',
    authoritativeEvidence: false,
    callerSuppliedTrustAnchors: true,
    readOnlyLivePreflightOnly: true,
    localMutationAuthority: false,
    deploymentAuthorized: false,
    replayLedgerStatus: 'EXTERNAL_PENDING',
    packageMaterializationStatus: 'EXTERNAL_PENDING',
    packageMaterializationVerified: false,
    policySha256: policyValue.sha256,
    packageAttestationEnvelopeSha256: packageEnvelope.sha256,
    authorizationEnvelopeSha256: authorizationEnvelope.sha256,
    candidate: expectedInput.candidate,
    target: expectedInput.target,
    consumerChallengeSha256: crypto.createHash('sha256').update(canonicalJson(expectedInput.consumerChallenge)).digest('hex'),
    permittedOperations: PERMITTED_OPERATIONS,
    forbiddenOperations: FORBIDDEN_OPERATIONS,
  });
}

const CLI_KEYS = Object.freeze([
  'authorization', 'expected-authorization-provider-key-id', 'expected-candidate-commit-sha',
  'expected-candidate-repository', 'expected-candidate-repository-id',
  'expected-candidate-repository-owner-id', 'expected-candidate-tree-sha', 'expected-challenge-expires-at',
  'expected-challenge-issued-at', 'expected-challenge-nonce', 'expected-challenge-replay-domain',
  'expected-consumer-job', 'expected-consumer-job-workflow-sha', 'expected-consumer-repository',
  'expected-consumer-run-attempt', 'expected-consumer-run-id', 'expected-consumer-workflow-path',
  'expected-deployment-gid', 'expected-deployment-uid', 'expected-docker-daemon-id',
  'expected-machine-identity-sha256', 'expected-package-attestor-key-id',
  'expected-package-manifest-sha256', 'expected-package-sha256', 'expected-policy-sha256',
  'expected-root-filesystem-identity-sha256', 'expected-source-archive-sha256',
  'expected-ssh-host-key-sha256', 'expected-target-endpoint', 'expected-target-hostname',
  'expected-target-root', 'expected-two-phase-contract-id', 'expected-two-phase-contract-sha256',
  'package-attestation', 'policy',
]);

function usage() {
  return `Usage: v1-phase-a-authorization.mjs ${CLI_KEYS.map((key) => `--${key} VALUE`).join(' ')}`;
}

function parseArgs(values) {
  if (values.length !== CLI_KEYS.length * 2) invalid(usage());
  const options = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (typeof flag !== 'string' || !flag.startsWith('--') || typeof value !== 'string'
        || !value || value.startsWith('--') || Object.hasOwn(options, flag.slice(2))) invalid(usage());
    options[flag.slice(2)] = value;
  }
  if (canonicalJson(Object.keys(options).sort()) !== canonicalJson([...CLI_KEYS].sort())) invalid(usage());
  return options;
}

function readBoundedDescriptor(descriptor, boundaryBytes, label) {
  const chunks = [];
  let totalBytes = 0;
  while (totalBytes < boundaryBytes) {
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, boundaryBytes - totalBytes));
    const bytesRead = fs.readSync(descriptor, chunk, 0, chunk.length, null);
    if (bytesRead === 0) return Buffer.concat(chunks, totalBytes);
    chunks.push(chunk.subarray(0, bytesRead));
    totalBytes += bytesRead;
  }
  invalid(`${label} grew beyond the accepted size boundary while it was read.`);
}

function snapshotFile(filename, label) {
  const pathname = path.resolve(String(filename ?? ''));
  let initial;
  try { initial = fs.lstatSync(pathname, { bigint: true }); } catch (error) {
    invalid(`${label} safe capture failed: ${String(error?.message ?? error)}`);
  }
  if (!initial.isFile() || initial.isSymbolicLink() || initial.nlink !== 1n
      || initial.size < 3n || initial.size > BigInt(MAX_ARTIFACT_BYTES)) {
    invalid(`${label} must be one bounded regular non-symlink singly linked file.`);
  }
  if (typeof fs.constants.O_NOFOLLOW !== 'number') invalid(`${label} O_NOFOLLOW is unavailable.`);
  let descriptor;
  try {
    descriptor = fs.openSync(pathname, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.dev !== initial.dev || before.ino !== initial.ino
        || before.size !== initial.size || before.mtimeNs !== initial.mtimeNs || before.ctimeNs !== initial.ctimeNs) {
      invalid(`${label} changed before safe capture.`);
    }
    const bytes = readBoundedDescriptor(descriptor, MAX_ARTIFACT_BYTES + 1, label);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const finalPath = fs.lstatSync(pathname, { bigint: true });
    if (BigInt(bytes.length) !== before.size || !after.isFile() || after.nlink !== 1n
        || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
        || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs
        || finalPath.dev !== before.dev || finalPath.ino !== before.ino || finalPath.size !== before.size
        || finalPath.mtimeNs !== before.mtimeNs || finalPath.ctimeNs !== before.ctimeNs) {
      invalid(`${label} changed during safe capture.`);
    }
    return Object.freeze({ bytes });
  } catch (error) {
    invalid(`${label} safe O_NOFOLLOW capture failed: ${String(error?.message ?? error)}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function expectedFromOptions(options) {
  const parseCliInteger = (value, label) => {
    if (!/^(?:0|[1-9][0-9]*)$/.test(value)) invalid(`${label} must be a canonical integer.`);
    const number = Number(value);
    if (!Number.isSafeInteger(number)) invalid(`${label} exceeds the safe range.`);
    return number;
  };
  return {
    policySha256: options['expected-policy-sha256'],
    packageAttestorKeyId: options['expected-package-attestor-key-id'],
    authorizationProviderKeyId: options['expected-authorization-provider-key-id'],
    candidate: {
      repository: options['expected-candidate-repository'],
      repositoryId: options['expected-candidate-repository-id'],
      repositoryOwnerId: options['expected-candidate-repository-owner-id'],
      commitSha: options['expected-candidate-commit-sha'],
      treeSha: options['expected-candidate-tree-sha'],
      clean: true,
      sourceArchiveSha256: options['expected-source-archive-sha256'],
      packageSha256: options['expected-package-sha256'],
      packageManifestSha256: options['expected-package-manifest-sha256'],
    },
    target: {
      endpoint: options['expected-target-endpoint'],
      hostname: options['expected-target-hostname'],
      targetRoot: options['expected-target-root'],
      sshHostKeySha256: options['expected-ssh-host-key-sha256'],
      dockerDaemonId: options['expected-docker-daemon-id'],
      machineIdentitySha256: options['expected-machine-identity-sha256'],
      rootFilesystemIdentitySha256: options['expected-root-filesystem-identity-sha256'],
      deploymentUid: parseCliInteger(options['expected-deployment-uid'], 'expected deployment UID'),
      deploymentGid: parseCliInteger(options['expected-deployment-gid'], 'expected deployment GID'),
    },
    twoPhaseOrderContract: {
      id: options['expected-two-phase-contract-id'], sha256: options['expected-two-phase-contract-sha256'],
    },
    consumerChallenge: {
      consumerRepository: options['expected-consumer-repository'],
      consumerWorkflowPath: options['expected-consumer-workflow-path'],
      consumerJobWorkflowSha: options['expected-consumer-job-workflow-sha'],
      consumerJob: options['expected-consumer-job'],
      consumerRunId: options['expected-consumer-run-id'],
      consumerRunAttempt: parseCliInteger(options['expected-consumer-run-attempt'], 'expected consumer run attempt'),
      nonce: options['expected-challenge-nonce'],
      replayDomain: options['expected-challenge-replay-domain'],
      issuedAt: options['expected-challenge-issued-at'],
      expiresAt: options['expected-challenge-expires-at'],
    },
  };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const result = verifyV1PhaseAAuthorization({
    policyArtifact: snapshotFile(options.policy, 'Phase A policy'),
    packageAttestationArtifact: snapshotFile(options['package-attestation'], 'Phase A package attestation'),
    authorizationArtifact: snapshotFile(options.authorization, 'Phase A authorization'),
    expected: expectedFromOptions(options),
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
