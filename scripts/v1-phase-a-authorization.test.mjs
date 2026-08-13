import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import * as phaseA from './v1-phase-a-authorization.mjs';

const scriptsDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptsDirectory, '..');
const scriptPath = path.join(scriptsDirectory, 'v1-phase-a-authorization.mjs');
const templatePath = path.join(repositoryRoot, 'governance', 'v1-phase-a-authorization.json');
const PACKAGE_PAYLOAD_TYPE = 'application/vnd.platform.v1.phase-a.package-attestation.v1+json';
const AUTHORIZATION_PAYLOAD_TYPE = 'application/vnd.platform.v1.phase-a.read-only-authorization.v1+json';
const PERMITTED_OPERATIONS = Object.freeze(['READ_ONLY_LIVE_PREFLIGHT']);
const FORBIDDEN_OPERATIONS = Object.freeze([
  'CREATE_BACKUP', 'QUIESCE', 'INSTALL', 'DOCKER', 'FIREWALL', 'ACTIVATE', 'RESTORE',
]);

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function sha(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function keyId(publicKey) {
  return sha(publicKey.export({ type: 'spki', format: 'der' }));
}

function publicPem(publicKey) {
  return publicKey.export({ type: 'spki', format: 'pem' });
}

function pae(payloadType, payloadBytes) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'ascii'), type,
    Buffer.from(` ${payloadBytes.length} `, 'ascii'), payloadBytes,
  ]);
}

function envelope(payload, payloadType, privateKey, signerKeyId) {
  const payloadBytes = Buffer.from(canonicalJson(payload), 'utf8');
  const document = {
    payload: payloadBytes.toString('base64'),
    payloadType,
    signatures: [{ keyid: signerKeyId, sig: crypto.sign(null, pae(payloadType, payloadBytes), privateKey).toString('base64') }],
  };
  const bytes = Buffer.from(`${canonicalJson(document)}\n`, 'utf8');
  return { bytes, document, sha256: sha(bytes) };
}

function envelopeFromPayloadBytes(payloadBytes, payloadType, privateKey, signerKeyId, { rawJsonSignature = false } = {}) {
  const document = {
    payload: payloadBytes.toString('base64'),
    payloadType,
    signatures: [{
      keyid: signerKeyId,
      sig: crypto.sign(null, rawJsonSignature ? payloadBytes : pae(payloadType, payloadBytes), privateKey).toString('base64'),
    }],
  };
  const bytes = Buffer.from(`${canonicalJson(document)}\n`, 'utf8');
  return { bytes, document, sha256: sha(bytes) };
}

const packageKeys = crypto.generateKeyPairSync('ed25519');
const authorizationKeys = crypto.generateKeyPairSync('ed25519');
const wrongKeys = crypto.generateKeyPairSync('ed25519');
const futureKeyIds = Object.freeze({
  backupAuthority: sha('future-backup-authority'),
  sourceTargetCustodian: sha('future-source-target-custodian'),
  phaseBInstaller: sha('future-phase-b-installer'),
  hostedGate: sha('future-hosted-gate'),
  deploymentGate: sha('future-deployment-gate'),
  activationGate: sha('future-activation-gate'),
  admissionController: sha('future-admission-controller'),
  activationTargetRoot: sha('future-activation-target-root'),
});
const packageProducer = Object.freeze({
  repository: 'independent-provider/phase-a',
  repositoryId: '120001',
  repositoryOwnerId: '1200',
  workflowPath: '.github/workflows/attest-package.yml',
  jobWorkflowSha: '1'.repeat(40),
  headSha: '2'.repeat(40),
  ref: 'refs/heads/main',
  eventName: 'workflow_dispatch',
  runId: '4815162342',
  runAttempt: 1,
  jobName: 'attest-v1-package',
  protectedEnvironment: 'v1-phase-a-package',
  approvalDecision: 'APPROVED',
  approvalApproverIdentity: 'github-user-id:70001',
  approvalEvidenceIdentity: 'provider-approval:package:4815162342:1',
  approvalEvidenceSha256: sha('package-approval-evidence'),
  approvalEvidenceIssuedAt: '2026-08-09T09:59:45.000Z',
});
const authorizationProducer = Object.freeze({
  repository: 'independent-provider/phase-a',
  repositoryId: '120001',
  repositoryOwnerId: '1200',
  workflowPath: '.github/workflows/authorize-read-only.yml',
  jobWorkflowSha: '3'.repeat(40),
  headSha: '4'.repeat(40),
  ref: 'refs/heads/main',
  eventName: 'workflow_dispatch',
  runId: '4815162343',
  runAttempt: 2,
  jobName: 'authorize-v1-read-only',
  protectedEnvironment: 'v1-phase-a-authorization',
  approvalDecision: 'APPROVED',
  approvalApproverIdentity: 'github-user-id:70002',
  approvalEvidenceIdentity: 'provider-approval:authorization:4815162343:2',
  approvalEvidenceSha256: sha('authorization-approval-evidence'),
  approvalEvidenceIssuedAt: '2026-08-09T10:00:30.000Z',
});

function readyPolicy() {
  return {
    schema: 'platform.v1-phase-a-authorization-policy/v1',
    version: 1,
    status: 'READY',
    reason: 'Independent provider policy supplied to a verify-only local consumer.',
    selfAssertedEvidenceAccepted: false,
    localTemplate: false,
    authoritativeEvidence: false,
    trustAnchorProvenance: 'CALLER-SUPPLIED-NON-AUTHORITATIVE',
    replayLedgerStatus: 'EXTERNAL_PENDING',
    candidate: structuredClone(candidate),
    twoPhaseOrderContract: { id: 'platform-v1-hosted-two-phase-order/v1', sha256: sha('two-phase-order-contract') },
    packageAttestor: {
      role: 'packageAttestor', algorithm: 'Ed25519', keyId: keyId(packageKeys.publicKey),
      publicKeySpkiPem: publicPem(packageKeys.publicKey), producer: structuredClone(packageProducer),
    },
    phaseAAuthorizationProvider: {
      role: 'phaseAAuthorizationProvider', algorithm: 'Ed25519', keyId: keyId(authorizationKeys.publicKey),
      publicKeySpkiPem: publicPem(authorizationKeys.publicKey), producer: structuredClone(authorizationProducer),
    },
    futureRoleKeyIds: structuredClone(futureKeyIds),
    packageAttestation: { payloadType: PACKAGE_PAYLOAD_TYPE, maxLifetimeSeconds: 600 },
    authorization: {
      payloadType: AUTHORIZATION_PAYLOAD_TYPE,
      maxLifetimeSeconds: 300,
      permittedOperations: PERMITTED_OPERATIONS,
      forbiddenOperations: FORBIDDEN_OPERATIONS,
    },
  };
}

const candidate = Object.freeze({
  repository: 'candidate-owner/platform-infrastructure',
  repositoryId: '220001',
  repositoryOwnerId: '2200',
  commitSha: 'a'.repeat(40),
  treeSha: 'b'.repeat(40),
  clean: true,
  sourceArchiveSha256: sha('exact-source-archive-bytes'),
  packageSha256: sha('exact-phase-a-package-bytes'),
  packageManifestSha256: sha('exact-phase-a-package-manifest'),
});
const target = Object.freeze({
  endpoint: 'ssh://deploy@platform.example.test:22',
  hostname: 'platform.example.test',
  targetRoot: '/srv/platform-infrastructure',
  sshHostKeySha256: sha('canonical-ssh-host-key-blob'),
  dockerDaemonId: 'T23-DOCKER-DAEMON-20260809',
  machineIdentitySha256: sha('target-machine-identity'),
  rootFilesystemIdentitySha256: sha('target-root-filesystem-device-identity'),
  deploymentUid: 1000,
  deploymentGid: 1000,
});
const consumerChallenge = Object.freeze({
  consumerRepository: candidate.repository,
  consumerWorkflowPath: '.github/workflows/enterprise-infra.yml',
  consumerJobWorkflowSha: 'e'.repeat(40),
  consumerJob: 'phase-a-read-only-preflight',
  consumerRunId: '9007199254740000',
  consumerRunAttempt: 3,
  nonce: Buffer.alloc(32, 7).toString('base64url'),
  replayDomain: 'phase-a-read-only-preflight/platform-infrastructure/v1',
  issuedAt: '2026-08-09T09:59:30.000Z',
  expiresAt: '2026-08-09T10:08:00.000Z',
});

function packagePayload(policy = readyPolicy()) {
  return {
    schema: 'platform.v1-phase-a-package-attestation/v1', version: 1,
    status: 'PACKAGE-ATTESTED', role: 'packageAttestor',
    attestationId: `phase-a-package-${sha('package-id')}`,
    producer: policy.packageAttestor.producer,
    candidate: structuredClone(candidate), target: structuredClone(target), consumerChallenge: structuredClone(consumerChallenge),
    twoPhaseOrderContract: structuredClone(policy.twoPhaseOrderContract),
    issuedAt: '2026-08-09T10:00:00.000Z', notBefore: '2026-08-09T10:00:00.000Z', expiresAt: '2026-08-09T10:10:00.000Z',
    replayLedgerStatus: 'EXTERNAL_PENDING',
  };
}

function authorizationPayload(policy, packageEnvelopeSha256) {
  return {
    schema: 'platform.v1-phase-a-read-only-authorization/v1', version: 1,
    status: 'READ-ONLY-AUTHORIZED', role: 'phaseAAuthorizationProvider',
    authorizationId: `phase-a-authorization-${sha('authorization-id')}`,
    producer: policy.phaseAAuthorizationProvider.producer,
    candidate: structuredClone(candidate), target: structuredClone(target), consumerChallenge: structuredClone(consumerChallenge),
    twoPhaseOrderContract: structuredClone(policy.twoPhaseOrderContract),
    packageAttestationEnvelopeSha256: packageEnvelopeSha256,
    issuedAt: '2026-08-09T10:01:00.000Z', notBefore: '2026-08-09T10:01:00.000Z', expiresAt: '2026-08-09T10:06:00.000Z',
    replayLedgerStatus: 'EXTERNAL_PENDING',
    readOnly: true, mutationAuthority: false,
    permittedOperations: [...PERMITTED_OPERATIONS],
    forbiddenOperations: [...FORBIDDEN_OPERATIONS],
  };
}

function fixture() {
  const policy = readyPolicy();
  const policyBytes = Buffer.from(`${canonicalJson(policy)}\n`, 'utf8');
  const packageArtifact = envelope(packagePayload(policy), PACKAGE_PAYLOAD_TYPE, packageKeys.privateKey, policy.packageAttestor.keyId);
  const authorizationArtifact = envelope(
    authorizationPayload(policy, packageArtifact.sha256), AUTHORIZATION_PAYLOAD_TYPE,
    authorizationKeys.privateKey, policy.phaseAAuthorizationProvider.keyId,
  );
  const expected = {
    policySha256: sha(policyBytes),
    packageAttestorKeyId: policy.packageAttestor.keyId,
    authorizationProviderKeyId: policy.phaseAAuthorizationProvider.keyId,
    candidate: structuredClone(candidate),
    target: structuredClone(target),
    twoPhaseOrderContract: structuredClone(policy.twoPhaseOrderContract),
    consumerChallenge: structuredClone(consumerChallenge),
  };
  return { policy, policyArtifact: { bytes: policyBytes }, packageArtifact, authorizationArtifact, expected };
}

function verify(value = fixture(), now = Date.parse('2026-08-09T10:02:00.000Z')) {
  return phaseA.verifyV1PhaseAAuthorization({
    policyArtifact: value.policyArtifact,
    packageAttestationArtifact: value.packageArtifact,
    authorizationArtifact: value.authorizationArtifact,
    expected: value.expected,
    now,
  });
}

function resignPackage(value, payload = value.packageArtifact.payload ?? packagePayload(value.policy), privateKey = packageKeys.privateKey, signer = value.policy.packageAttestor.keyId) {
  value.packageArtifact = envelope(payload, PACKAGE_PAYLOAD_TYPE, privateKey, signer);
  return value;
}

function resignAuthorization(value, mutator = () => {}, privateKey = authorizationKeys.privateKey, signer = value.policy.phaseAAuthorizationProvider.keyId) {
  const payload = authorizationPayload(value.policy, value.packageArtifact.sha256);
  mutator(payload);
  value.authorizationArtifact = envelope(payload, AUTHORIZATION_PAYLOAD_TYPE, privateKey, signer);
  return value;
}

test('local policy template is closed EXTERNAL-PENDING and cannot verify as READY', () => {
  const template = JSON.parse(fs.readFileSync(templatePath, 'utf8'));
  assert.deepEqual(phaseA.validateV1PhaseAPolicy(template, { requireReady: false }), { status: 'EXTERNAL-PENDING' });
  assert.equal(template.authoritativeEvidence, false);
  assert.equal(template.localTemplate, true);
  assert.equal(template.replayLedgerStatus, 'EXTERNAL_PENDING');
  assert.ok(Object.values(template.candidate).every((value) => value === null));
  for (const role of [template.packageAttestor, template.phaseAAuthorizationProvider]) {
    assert.equal(role.keyId, null);
    assert.equal(role.publicKeySpkiPem, null);
    assert.ok(Object.values(role.producer).every((value) => value === null));
  }
  assert.ok(Object.values(template.futureRoleKeyIds).every((value) => value === null));
  assert.throws(() => phaseA.validateV1PhaseAPolicy(template), /EXTERNAL-PENDING/);
});

test('two distinct valid DSSE envelopes verify, but output is explicitly non-authoritative and read-only only', () => {
  const result = verify();
  assert.equal(result.schema, 'platform.v1-phase-a-verification/v1');
  assert.equal(result.status, 'SIGNATURE_VERIFIED_NON_AUTHORITATIVE');
  assert.equal(result.authoritativeEvidence, false);
  assert.equal(result.callerSuppliedTrustAnchors, true);
  assert.equal(result.readOnlyLivePreflightOnly, true);
  assert.equal(result.localMutationAuthority, false);
  assert.equal(result.deploymentAuthorized, false);
  assert.equal(result.replayLedgerStatus, 'EXTERNAL_PENDING');
  assert.equal(result.packageMaterializationStatus, 'EXTERNAL_PENDING');
  assert.equal(result.packageMaterializationVerified, false);
  assert.equal(result.candidate.repositoryId, candidate.repositoryId);
  assert.equal(result.candidate.repositoryOwnerId, candidate.repositoryOwnerId);
  assert.deepEqual(result.permittedOperations, PERMITTED_OPERATIONS);
  assert.deepEqual(result.forbiddenOperations, FORBIDDEN_OPERATIONS);
  assert.notEqual(result.packageAttestationEnvelopeSha256, result.authorizationEnvelopeSha256);
  assert.doesNotMatch(canonicalJson(result), /(?:\"status\":\"(?:READY|ADMITTED|AUTHORIZED)\"|mutationAuthority\":true|deploymentAuthorized\":true)/);
});

test('caller-selected self-consistent READY policy can prove signatures but can never claim authority', () => {
  const result = verify(fixture());
  assert.deepEqual(
    { status: result.status, authoritativeEvidence: result.authoritativeEvidence, localMutationAuthority: result.localMutationAuthority, deploymentAuthorized: result.deploymentAuthorized },
    { status: 'SIGNATURE_VERIFIED_NON_AUTHORITATIVE', authoritativeEvidence: false, localMutationAuthority: false, deploymentAuthorized: false },
  );
});

test('READY policy requires exact caller bindings and independent, canonical, role-separated Ed25519 keys', () => {
  const cases = [
    ['policy hash', (v) => { v.expected.policySha256 = sha('wrong'); }],
    ['package key', (v) => { v.expected.packageAttestorKeyId = sha('wrong'); }],
    ['authorization key', (v) => { v.expected.authorizationProviderKeyId = sha('wrong'); }],
    ['candidate-independent provider slug', (v) => { v.policy.packageAttestor.producer.repository = candidate.repository; }],
    ['candidate-independent provider casefolded slug', (v) => { v.policy.packageAttestor.producer.repository = candidate.repository.toUpperCase(); }],
    ['candidate-independent provider repository ID', (v) => { v.policy.packageAttestor.producer.repositoryId = candidate.repositoryId; }],
    ['candidate-independent provider owner ID', (v) => { v.policy.phaseAAuthorizationProvider.producer.repositoryOwnerId = candidate.repositoryOwnerId; }],
    ['role key reuse', (v) => { v.policy.phaseAAuthorizationProvider.keyId = v.policy.packageAttestor.keyId; v.policy.phaseAAuthorizationProvider.publicKeySpkiPem = v.policy.packageAttestor.publicKeySpkiPem; }],
    ['future role key reuse', (v) => { v.policy.futureRoleKeyIds.deploymentGate = v.policy.packageAttestor.keyId; }],
    ['private key PEM', (v) => { v.policy.packageAttestor.publicKeySpkiPem = packageKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }); }],
    ['noncanonical PEM', (v) => { v.policy.packageAttestor.publicKeySpkiPem = `\n${v.policy.packageAttestor.publicKeySpkiPem}`; }],
  ];
  for (const [label, mutate] of cases) {
    const value = fixture(); mutate(value);
    value.policyArtifact.bytes = Buffer.from(`${canonicalJson(value.policy)}\n`);
    if (label !== 'policy hash') value.expected.policySha256 = sha(value.policyArtifact.bytes);
    assert.throws(() => verify(value), undefined, label);
  }
});

test('candidate and provider repository slugs are canonical lowercase and immutable repository/owner IDs are mandatory', () => {
  const cases = [
    (v) => { v.expected.candidate.repository = 'Candidate-Owner/platform-infrastructure'; },
    (v) => { v.expected.candidate.repositoryId = '220002'; },
    (v) => { v.expected.candidate.repositoryOwnerId = '2201'; },
    (v) => { v.policy.packageAttestor.producer.repository = 'Independent-Provider/phase-a'; },
    (v) => { delete v.expected.candidate.repositoryId; },
    (v) => { v.expected.candidate.repositoryOwnerId = '0900'; },
  ];
  for (const mutate of cases) {
    const value = fixture(); mutate(value);
    value.policyArtifact.bytes = Buffer.from(`${canonicalJson(value.policy)}\n`);
    value.expected.policySha256 = sha(value.policyArtifact.bytes);
    assert.throws(() => verify(value), /repository|owner|candidate|schema|canonical|decimal/i);
  }
});

test('future role key IDs use the exact canonical eight-role set and all ten core keys are pairwise distinct', () => {
  assert.deepEqual(Object.keys(readyPolicy().futureRoleKeyIds).sort(), [
    'activationGate', 'activationTargetRoot', 'admissionController', 'backupAuthority',
    'deploymentGate', 'hostedGate', 'phaseBInstaller', 'sourceTargetCustodian',
  ]);
  const cases = [
    (p) => { delete p.futureRoleKeyIds.backupAuthority; },
    (p) => { p.futureRoleKeyIds.legacyTargetRootReceipt = sha('legacy'); },
    (p) => { p.futureRoleKeyIds.hostedGate = p.futureRoleKeyIds.deploymentGate; },
    (p) => { p.futureRoleKeyIds.phaseBInstaller = p.packageAttestor.keyId; },
    (p) => { p.futureRoleKeyIds.activationTargetRoot = p.phaseAAuthorizationProvider.keyId; },
  ];
  for (const mutate of cases) {
    const value = fixture(); mutate(value.policy);
    value.policyArtifact.bytes = Buffer.from(`${canonicalJson(value.policy)}\n`);
    value.expected.policySha256 = sha(value.policyArtifact.bytes);
    assert.throws(() => verify(value), /future|role|key|schema|separated/i);
  }
});

test('producer workflow, immutable SHAs, main ref, dispatch, run/attempt/job, protected environment and approval evidence are exact', () => {
  const mutations = [
    (p) => { p.producer.workflowPath = '.github/workflows/other.yml'; },
    (p) => { p.producer.jobWorkflowSha = '5'.repeat(40); },
    (p) => { p.producer.headSha = '6'.repeat(40); },
    (p) => { p.producer.ref = 'refs/heads/feature'; },
    (p) => { p.producer.eventName = 'push'; },
    (p) => { p.producer.runId = '4815169999'; },
    (p) => { p.producer.runAttempt = 3; },
    (p) => { p.producer.jobName = 'wrong-job'; },
    (p) => { p.producer.protectedEnvironment = 'unprotected'; },
    (p) => { p.producer.repositoryId = '120002'; },
    (p) => { p.producer.repositoryOwnerId = '1201'; },
    (p) => { p.producer.approvalDecision = 'REJECTED'; },
    (p) => { p.producer.approvalApproverIdentity = 'github-user-id:79999'; },
    (p) => { p.producer.approvalEvidenceIdentity = 'provider-approval:other:1:1'; },
    (p) => { p.producer.approvalEvidenceSha256 = sha('wrong approval'); },
    (p) => { p.producer.approvalEvidenceIssuedAt = '2026-08-09T09:58:00.000Z'; },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    const payload = packagePayload(value.policy); mutate(payload);
    resignPackage(value, payload);
    resignAuthorization(value);
    assert.throws(() => verify(value), /producer|approval|policy|workflow|provider/i);
  }
});

test('candidate, target, order contract, package-envelope and external challenge bindings reject cross-context and replay attempts', () => {
  const fields = [
    ['candidate repository', (p) => { p.candidate.repository = 'other/candidate'; }],
    ['candidate repository ID', (p) => { p.candidate.repositoryId = '220002'; }],
    ['candidate repository owner ID', (p) => { p.candidate.repositoryOwnerId = '2201'; }],
    ['commit', (p) => { p.candidate.commitSha = 'c'.repeat(40); }],
    ['tree', (p) => { p.candidate.treeSha = 'd'.repeat(40); }],
    ['dirty', (p) => { p.candidate.clean = false; }],
    ['archive', (p) => { p.candidate.sourceArchiveSha256 = sha('other archive'); }],
    ['package', (p) => { p.candidate.packageSha256 = sha('other package'); }],
    ['manifest', (p) => { p.candidate.packageManifestSha256 = sha('other manifest'); }],
    ['endpoint', (p) => { p.target.endpoint = 'ssh://deploy@other.example.test:22'; }],
    ['hostname', (p) => { p.target.hostname = 'other.example.test'; }],
    ['root', (p) => { p.target.targetRoot = '/srv/other'; }],
    ['host key', (p) => { p.target.sshHostKeySha256 = sha('other host key'); }],
    ['daemon', (p) => { p.target.dockerDaemonId = 'OTHER-DAEMON'; }],
    ['machine identity', (p) => { p.target.machineIdentitySha256 = sha('other target'); }],
    ['root filesystem', (p) => { p.target.rootFilesystemIdentitySha256 = sha('other root fs'); }],
    ['deployment UID', (p) => { p.target.deploymentUid = 0; }],
    ['order ID', (p) => { p.twoPhaseOrderContract.id = 'wrong-order/v1'; }],
    ['order SHA', (p) => { p.twoPhaseOrderContract.sha256 = sha('wrong order'); }],
    ['consumer run', (p) => { p.consumerChallenge.consumerRunId = '44'; }],
    ['consumer workflow revision', (p) => { p.consumerChallenge.consumerJobWorkflowSha = 'f'.repeat(40); }],
    ['replay domain', (p) => { p.consumerChallenge.replayDomain = 'other-domain/v1'; }],
    ['nonce replay/cross consumer', (p) => { p.consumerChallenge.nonce = Buffer.alloc(32, 8).toString('base64url'); }],
  ];
  for (const [label, mutate] of fields) {
    const value = fixture(); resignAuthorization(value, mutate);
    assert.throws(() => verify(value), undefined, label);
  }
  const wrongPackageReference = fixture();
  resignAuthorization(wrongPackageReference, (p) => { p.packageAttestationEnvelopeSha256 = sha('another envelope'); });
  assert.throws(() => verify(wrongPackageReference), /package/i);
});

test('package attestation rejects the same cross-candidate, target, order and challenge substitutions symmetrically', () => {
  const mutations = [
    (p) => { p.candidate.commitSha = 'c'.repeat(40); },
    (p) => { p.candidate.repositoryId = '220002'; },
    (p) => { p.candidate.repositoryOwnerId = '2201'; },
    (p) => { p.candidate.packageManifestSha256 = sha('substituted manifest'); },
    (p) => { p.target.machineIdentitySha256 = sha('substituted machine'); },
    (p) => { p.target.rootFilesystemIdentitySha256 = sha('substituted root fs'); },
    (p) => { p.twoPhaseOrderContract.sha256 = sha('substituted order'); },
    (p) => { p.consumerChallenge.consumerJobWorkflowSha = 'f'.repeat(40); },
    (p) => { p.consumerChallenge.nonce = Buffer.alloc(32, 9).toString('base64url'); },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    const payload = packagePayload(value.policy); mutate(payload);
    resignPackage(value, payload);
    resignAuthorization(value);
    assert.throws(() => verify(value), /candidate|target|order|challenge|expected|context/i);
  }
});

test('authorization producer is independently pinned, approved after challenge, and cannot reuse package provenance', () => {
  for (const mutate of [
    (p) => { p.producer = structuredClone(packageProducer); },
    (p) => { p.producer.jobWorkflowSha = '8'.repeat(40); },
    (p) => { p.producer.runAttempt = 9; },
    (p) => { p.producer.approvalDecision = 'REJECTED'; },
    (p) => { p.producer.approvalEvidenceIssuedAt = '2026-08-09T09:59:00.000Z'; },
    (p) => { p.producer.approvalEvidenceIssuedAt = '2026-08-09T10:01:30.000Z'; },
  ]) {
    const value = fixture(); resignAuthorization(value, mutate);
    assert.throws(() => verify(value), /producer|approval|challenge|policy/i);
  }
});

test('operation scope cannot authorize backup, quiesce, install, Docker, firewall, activation or restore', () => {
  for (const mutate of [
    (p) => { p.readOnly = false; },
    (p) => { p.mutationAuthority = true; },
    (p) => { p.permittedOperations.push('CREATE_BACKUP'); },
    (p) => { p.permittedOperations = ['CREATE_VERIFIED_PREDEPLOY_BACKUP']; },
    (p) => { p.forbiddenOperations = p.forbiddenOperations.filter((x) => x !== 'DOCKER'); },
    (p) => { p.status = 'AUTHORIZED'; },
    (p) => { p.replayLedgerStatus = 'CLOSED'; },
  ]) {
    const value = fixture(); resignAuthorization(value, mutate);
    assert.throws(() => verify(value), /authorization|operation|read-only|replay|schema|status/i);
  }
});

test('signature domain, payload type, key role, canonical JSON, strict base64 and envelope schema confusion are rejected', () => {
  const wrongSignature = fixture();
  resignAuthorization(wrongSignature, () => {}, wrongKeys.privateKey, keyId(wrongKeys.publicKey));
  assert.throws(() => verify(wrongSignature), /key|signature/i);

  const roleConfusion = fixture();
  roleConfusion.authorizationArtifact = envelope(
    authorizationPayload(roleConfusion.policy, roleConfusion.packageArtifact.sha256), AUTHORIZATION_PAYLOAD_TYPE,
    packageKeys.privateKey, roleConfusion.policy.packageAttestor.keyId,
  );
  assert.throws(() => verify(roleConfusion), /key|signature/i);

  const typeConfusion = fixture();
  typeConfusion.authorizationArtifact.document.payloadType = PACKAGE_PAYLOAD_TYPE;
  typeConfusion.authorizationArtifact.bytes = Buffer.from(`${canonicalJson(typeConfusion.authorizationArtifact.document)}\n`);
  assert.throws(() => verify(typeConfusion), /payload type/i);

  const noncanonical = fixture();
  noncanonical.authorizationArtifact.bytes = Buffer.from(` ${noncanonical.authorizationArtifact.bytes}`);
  assert.throws(() => verify(noncanonical), /canonical/i);

  const badBase64 = fixture();
  badBase64.authorizationArtifact.document.payload += '=';
  badBase64.authorizationArtifact.bytes = Buffer.from(`${canonicalJson(badBase64.authorizationArtifact.document)}\n`);
  assert.throws(() => verify(badBase64), /base64/i);

  const extra = fixture();
  extra.authorizationArtifact.document.signatures[0].role = 'phaseAAuthorizationProvider';
  extra.authorizationArtifact.bytes = Buffer.from(`${canonicalJson(extra.authorizationArtifact.document)}\n`);
  assert.throws(() => verify(extra), /closed schema/i);
});

test('package DSSE rejects wrong key/type, malformed signature, noncanonical or duplicate-key payloads, and raw-JSON signatures', () => {
  const wrongKey = fixture();
  wrongKey.packageArtifact = envelope(packagePayload(wrongKey.policy), PACKAGE_PAYLOAD_TYPE, wrongKeys.privateKey, keyId(wrongKeys.publicKey));
  resignAuthorization(wrongKey);
  assert.throws(() => verify(wrongKey), /key|signature/i);

  const wrongType = fixture();
  wrongType.packageArtifact.document.payloadType = AUTHORIZATION_PAYLOAD_TYPE;
  wrongType.packageArtifact.bytes = Buffer.from(`${canonicalJson(wrongType.packageArtifact.document)}\n`);
  assert.throws(() => verify(wrongType), /payload type/i);

  const malformedSignature = fixture();
  malformedSignature.packageArtifact.document.signatures[0].sig += '=';
  malformedSignature.packageArtifact.bytes = Buffer.from(`${canonicalJson(malformedSignature.packageArtifact.document)}\n`);
  assert.throws(() => verify(malformedSignature), /base64/i);

  const packageDocument = packagePayload(readyPolicy());
  const noncanonical = fixture();
  noncanonical.packageArtifact = envelopeFromPayloadBytes(
    Buffer.from(` ${canonicalJson(packageDocument)}`), PACKAGE_PAYLOAD_TYPE,
    packageKeys.privateKey, noncanonical.policy.packageAttestor.keyId,
  );
  resignAuthorization(noncanonical);
  assert.throws(() => verify(noncanonical), /canonical/i);

  const duplicate = fixture();
  const canonical = canonicalJson(packageDocument);
  duplicate.packageArtifact = envelopeFromPayloadBytes(
    Buffer.from(`{\"schema\":\"attacker-duplicate\",${canonical.slice(1)}`), PACKAGE_PAYLOAD_TYPE,
    packageKeys.privateKey, duplicate.policy.packageAttestor.keyId,
  );
  resignAuthorization(duplicate);
  assert.throws(() => verify(duplicate), /canonical/i);

  const rawJson = fixture();
  const payloadBytes = Buffer.from(canonicalJson(packagePayload(rawJson.policy)));
  rawJson.packageArtifact = envelopeFromPayloadBytes(
    payloadBytes, PACKAGE_PAYLOAD_TYPE, packageKeys.privateKey, rawJson.policy.packageAttestor.keyId,
    { rawJsonSignature: true },
  );
  resignAuthorization(rawJson);
  assert.throws(() => verify(rawJson), /signature/i);
});

test('boolean/integer coercion, unsafe integers and unknown payload fields never cross validation', () => {
  const cases = [
    (v) => { v.expected.target.deploymentUid = true; },
    (v) => { v.expected.consumerChallenge.consumerRunAttempt = 1.5; },
    (v) => { v.expected.consumerChallenge.consumerRunId = '9007199254740992'; },
    (v) => { v.policy.packageAttestation.maxLifetimeSeconds = true; },
    (v) => { v.policy.packageAttestor.producer.runAttempt = true; },
    (v) => {
      const payload = authorizationPayload(v.policy, v.packageArtifact.sha256);
      payload.version = true;
      v.authorizationArtifact = envelope(payload, AUTHORIZATION_PAYLOAD_TYPE, authorizationKeys.privateKey, v.policy.phaseAAuthorizationProvider.keyId);
    },
    (v) => {
      const payload = authorizationPayload(v.policy, v.packageArtifact.sha256);
      payload.untrusted = false;
      v.authorizationArtifact = envelope(payload, AUTHORIZATION_PAYLOAD_TYPE, authorizationKeys.privateKey, v.policy.phaseAAuthorizationProvider.keyId);
    },
  ];
  for (const mutate of cases) {
    const value = fixture(); mutate(value);
    value.policyArtifact.bytes = Buffer.from(`${canonicalJson(value.policy)}\n`);
    value.expected.policySha256 = sha(value.policyArtifact.bytes);
    assert.throws(() => verify(value), /integer|safe|policy|schema|version|range|identity|status/i);
  }
});

test('canonical UTC lifetime, freshness and package-before-authorization ordering are fail-closed', () => {
  const mutations = [
    (p) => { p.issuedAt = '2026-08-09T10:01:00Z'; },
    (p) => { p.notBefore = '2026-08-09T10:03:00.000Z'; },
    (p) => { p.expiresAt = '2026-08-09T10:07:00.000Z'; },
    (p) => { p.issuedAt = '2026-08-09T09:59:00.000Z'; p.notBefore = p.issuedAt; },
    (p) => { p.expiresAt = '2026-08-09T10:00:30.000Z'; },
  ];
  for (const mutate of mutations) {
    const value = fixture(); resignAuthorization(value, mutate);
    assert.throws(() => verify(value), /time|fresh|expired|order|lifetime|timestamp/i);
  }
  assert.throws(() => verify(fixture(), Date.parse('2026-08-09T10:07:00.001Z')), /expired|fresh/i);
  assert.throws(() => verify(fixture(), Date.parse('2026-08-09T10:06:00.000Z')), /expired|fresh/i);
});

function cliArgs(files, expected) {
  return [
    '--policy', files.policy,
    '--package-attestation', files.package,
    '--authorization', files.authorization,
    '--expected-policy-sha256', expected.policySha256,
    '--expected-package-attestor-key-id', expected.packageAttestorKeyId,
    '--expected-authorization-provider-key-id', expected.authorizationProviderKeyId,
    '--expected-candidate-repository', expected.candidate.repository,
    '--expected-candidate-repository-id', expected.candidate.repositoryId,
    '--expected-candidate-repository-owner-id', expected.candidate.repositoryOwnerId,
    '--expected-candidate-commit-sha', expected.candidate.commitSha,
    '--expected-candidate-tree-sha', expected.candidate.treeSha,
    '--expected-source-archive-sha256', expected.candidate.sourceArchiveSha256,
    '--expected-package-sha256', expected.candidate.packageSha256,
    '--expected-package-manifest-sha256', expected.candidate.packageManifestSha256,
    '--expected-two-phase-contract-id', expected.twoPhaseOrderContract.id,
    '--expected-two-phase-contract-sha256', expected.twoPhaseOrderContract.sha256,
    '--expected-consumer-repository', expected.consumerChallenge.consumerRepository,
    '--expected-consumer-workflow-path', expected.consumerChallenge.consumerWorkflowPath,
    '--expected-consumer-job-workflow-sha', expected.consumerChallenge.consumerJobWorkflowSha,
    '--expected-consumer-job', expected.consumerChallenge.consumerJob,
    '--expected-consumer-run-id', expected.consumerChallenge.consumerRunId,
    '--expected-consumer-run-attempt', String(expected.consumerChallenge.consumerRunAttempt),
    '--expected-challenge-nonce', expected.consumerChallenge.nonce,
    '--expected-challenge-replay-domain', expected.consumerChallenge.replayDomain,
    '--expected-challenge-issued-at', expected.consumerChallenge.issuedAt,
    '--expected-challenge-expires-at', expected.consumerChallenge.expiresAt,
    '--expected-target-endpoint', expected.target.endpoint,
    '--expected-target-hostname', expected.target.hostname,
    '--expected-target-root', expected.target.targetRoot,
    '--expected-ssh-host-key-sha256', expected.target.sshHostKeySha256,
    '--expected-docker-daemon-id', expected.target.dockerDaemonId,
    '--expected-machine-identity-sha256', expected.target.machineIdentitySha256,
    '--expected-root-filesystem-identity-sha256', expected.target.rootFilesystemIdentitySha256,
    '--expected-deployment-uid', String(expected.target.deploymentUid),
    '--expected-deployment-gid', String(expected.target.deploymentGid),
  ];
}

test('CLI is explicit verify-only, safely reads O_NOFOLLOW bounded artifacts, and emits no signed or minted artifact', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-a-cli-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const value = fixture();
  const clock = Date.now();
  const iso = (offset) => new Date(clock + offset).toISOString();
  value.policy.packageAttestor.producer.approvalEvidenceIssuedAt = iso(-90_000);
  value.policy.phaseAAuthorizationProvider.producer.approvalEvidenceIssuedAt = iso(-45_000);
  value.policyArtifact.bytes = Buffer.from(`${canonicalJson(value.policy)}\n`);
  value.expected.policySha256 = sha(value.policyArtifact.bytes);
  value.expected.consumerChallenge = {
    ...structuredClone(consumerChallenge), issuedAt: iso(-120_000), expiresAt: iso(480_000),
  };
  const packageDocument = packagePayload(value.policy);
  packageDocument.consumerChallenge = structuredClone(value.expected.consumerChallenge);
  packageDocument.issuedAt = iso(-60_000);
  packageDocument.notBefore = packageDocument.issuedAt;
  packageDocument.expiresAt = iso(540_000);
  value.packageArtifact = envelope(
    packageDocument, PACKAGE_PAYLOAD_TYPE, packageKeys.privateKey, value.policy.packageAttestor.keyId,
  );
  const authorizationDocument = authorizationPayload(value.policy, value.packageArtifact.sha256);
  authorizationDocument.consumerChallenge = structuredClone(value.expected.consumerChallenge);
  authorizationDocument.issuedAt = iso(-30_000);
  authorizationDocument.notBefore = authorizationDocument.issuedAt;
  authorizationDocument.expiresAt = iso(270_000);
  value.authorizationArtifact = envelope(
    authorizationDocument, AUTHORIZATION_PAYLOAD_TYPE,
    authorizationKeys.privateKey, value.policy.phaseAAuthorizationProvider.keyId,
  );
  const files = {
    policy: path.join(directory, 'policy.json'), package: path.join(directory, 'package.json'), authorization: path.join(directory, 'authorization.json'),
  };
  fs.writeFileSync(files.policy, value.policyArtifact.bytes);
  fs.writeFileSync(files.package, value.packageArtifact.bytes);
  fs.writeFileSync(files.authorization, value.authorizationArtifact.bytes);
  const before = fs.readdirSync(directory).sort();
  const output = execFileSync(process.execPath, [scriptPath, ...cliArgs(files, value.expected)], {
    cwd: repositoryRoot, encoding: 'utf8', env: { PATH: process.env.PATH, LANG: 'C', LC_ALL: 'C' },
  });
  assert.equal(JSON.parse(output).status, 'SIGNATURE_VERIFIED_NON_AUTHORITATIVE');
  assert.deepEqual(fs.readdirSync(directory).sort(), before);

  const symlink = path.join(directory, 'policy-link.json');
  fs.symlinkSync(files.policy, symlink);
  const symlinkResult = spawnSync(process.execPath, [scriptPath, ...cliArgs({ ...files, policy: symlink }, value.expected)], { cwd: repositoryRoot, encoding: 'utf8' });
  assert.notEqual(symlinkResult.status, 0);
  assert.match(symlinkResult.stderr, /symlink|O_NOFOLLOW|regular|capture/i);

  for (const key of ['policy', 'package', 'authorization']) {
    const linked = path.join(directory, `${key}-hardlink.json`);
    fs.linkSync(files[key], linked);
    const result = spawnSync(process.execPath, [scriptPath, ...cliArgs(files, value.expected)], { cwd: repositoryRoot, encoding: 'utf8' });
    assert.notEqual(result.status, 0, `${key} hardlink unexpectedly accepted`);
    assert.match(result.stderr, /linked|regular|capture/i);
    fs.unlinkSync(linked);
  }
});

test('CLI has no default/env path, no create/sign/mint/output/now/replay bypass and rejects missing, duplicate or unknown arguments', () => {
  for (const args of [
    [], ['--policy', templatePath], ['--create', 'x'], ['--sign', 'x'], ['--mint', 'x'], ['--output', 'x'], ['--now', '0'],
    ['--policy', templatePath, '--policy', templatePath], ['--unknown', 'x'],
  ]) {
    const result = spawnSync(process.execPath, [scriptPath, ...args], {
      cwd: repositoryRoot, encoding: 'utf8',
      env: { PATH: process.env.PATH, V1_PHASE_A_POLICY: templatePath, PHASE_A_BYPASS: '1', PHASE_A_READY: '1' },
    });
    assert.notEqual(result.status, 0, JSON.stringify(args));
    assert.match(result.stderr, /usage|argument|EXTERNAL-PENDING/i);
  }
  const exported = Object.keys(phaseA).sort();
  assert.ok(exported.every((name) => !/(?:create|sign|mint|write)/i.test(name)));
  const source = fs.readFileSync(scriptPath, 'utf8');
  assert.doesNotMatch(source, /fs\.(?:appendFile|createWriteStream|mkdir|rename|rm|unlink|writeFile)/);
  assert.doesNotMatch(source, /process\.env\.(?:V1_PHASE_A|PHASE_A)/);
  assert.doesNotMatch(source, /from ['\"]node:(?:child_process|http|https|net|tls)['\"]/);
  assert.doesNotMatch(source, /crypto\.sign\s*\(/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.match(source, /MAX_ARTIFACT_BYTES\s*\+\s*1/);
  assert.match(source, /fs\.readSync\s*\(/);
  assert.doesNotMatch(source, /fs\.readFileSync\s*\(\s*descriptor\s*\)/);
});
