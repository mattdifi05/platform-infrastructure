import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import * as providerGatesModule from './v1-provider-gates.mjs';
import { PERSISTENT_SOURCE_CLASSES } from './v1-predeploy-backup-receipt.mjs';

const scriptsDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptsDirectory, '..');
const policyPath = path.join(repositoryRoot, 'governance', 'v1-provider-gates.json');
const scriptPath = path.join(scriptsDirectory, 'v1-provider-gates.mjs');
const receiptVerifierPath = path.join(scriptsDirectory, 'v1-predeploy-backup-receipt.mjs');
const deploymentContractPath = path.join(repositoryRoot, 'V1-BROWNFIELD-DEPLOYMENT.md');
const HOSTED_TWO_PHASE_SEQUENCE = Object.freeze([
  'PHASE-A-READ-ONLY-PROVIDER-AUTHORIZATION',
  'LIVE-READ-ONLY-PREFLIGHT-PASS',
  'VERIFIED-PRE-DEPLOY-BACKUP-OUTSIDE-COMPLETE-SOURCE-DEVICE-SET',
  'PHASE-B-EXACT-ATTESTED-PACKAGE-INSTALLATION',
  'PHASE-B-TARGET-ROOT-INSTALLATION-RECEIPT',
  'PHASE-B-INDEPENDENT-PROVIDER-FINAL-ADMISSION',
  'ACTIVATION-AFTER-ALL-PROVIDER-GATES-PASS',
]);
const SEPARATE_DEVICE_REQUIREMENTS = Object.freeze({
  sourceClasses: Object.freeze([
    'DOCKER-ROOT-DIR',
    'ALL-CHECKOUTS',
    'ALL-COMPOSE-CONFIG-FILES',
    'ALL-VOLUME-AND-DATABASE-DIRECTORIES',
    'BIND-LSTAT-SOURCE-IDENTITIES',
    'BIND-CANONICAL-TARGET-IDENTITIES',
    'ALL-SOURCE-ROOTS',
    'ALL-SECRET-METADATA-PATHS',
  ]),
  sourceSetCanonicalization: 'SORTED-UNIQUE-FILESYSTEM-DEVICE-IDENTITIES',
  missingIdentityEffect: 'STOP',
  comparison: 'BACKUP-DEVICE-NOT-IN-CANONICAL-SOURCE-SET',
});
const TRANSITIVE_SAFETY_BINDING_FIELDS = Object.freeze({
  canonicalPreservationBaseline: Object.freeze(['artifactSha256', 'baselineId', 'complete', 'reason']),
  preDeployBackupReceipt: Object.freeze(['artifactSha256', 'authoritative', 'receiptId', 'reason']),
  candidateIdentity: Object.freeze(['commitSha', 'reason', 'treeSha']),
  targetIdentity: Object.freeze(['identity', 'reason', 'root']),
  separateDeviceProof: Object.freeze([
    'artifactSha256',
    'baselineArtifactSha256',
    'baselineId',
    'backupDeviceIdentity',
    'reason',
    'requirements',
    'sourceDeviceCount',
    'sourceDeviceIdentitiesComplete',
    'sourceDeviceSetSha256',
    'verifiedOutsideAllSources',
  ]),
  providerSignatureAdmission: Object.freeze([
    'admissionArtifactSha256',
    'admissionId',
    'reason',
    'signatureArtifactSha256',
    'signatureVerified',
    'signerIdentity',
  ]),
  targetRootSignatureAdmission: Object.freeze([
    'admissionArtifactSha256',
    'admissionId',
    'reason',
    'signatureArtifactSha256',
    'signatureVerified',
    'signerIdentity',
  ]),
  postDeployPreservationForDataRollback: Object.freeze([
    'artifactSha256',
    'baselineId',
    'candidateCommitSha',
    'dataRollbackAdmissionId',
    'preDeployReceiptId',
    'reason',
  ]),
});

function canonicalDocument() {
  return JSON.parse(fs.readFileSync(policyPath, 'utf8'));
}

function cloneDocument() {
  return structuredClone(canonicalDocument());
}

function expectRejected(mutator, pattern = /validation failed/) {
  const document = cloneDocument();
  mutator(document);
  assert.throws(() => providerGatesModule.validateV1ProviderGates(document), pattern);
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test('canonical provider-gate inventory validates and stays explicitly non-authoritative', () => {
  const document = canonicalDocument();
  assert.equal(providerGatesModule.validateV1ProviderGates(document), document);
  assert.deepEqual(Object.keys(document.gates), providerGatesModule.GATE_NAMES);

  const summary = providerGatesModule.summarizeV1ProviderGates(document);
  assert.equal(summary.status, 'EXTERNAL-PENDING');
  assert.equal(summary.authoritativeEvidence, false);
  assert.equal(summary.selfAssertedEvidenceAccepted, false);
  assert.equal(summary.canBeSatisfiedLocally, false);
  assert.equal(summary.hostedPreparationSequencingStatus, 'EXTERNAL-PENDING');
  assert.equal(summary.userOrderApprovalStatus, 'USER-APPROVED');
  assert.equal(summary.requiresUserOrderApproval, false);
  assert.equal(summary.literalOrderSatisfiable, false);
  assert.deepEqual(summary.orderedSequence, HOSTED_TWO_PHASE_SEQUENCE);
  assert.deepEqual(summary.gates.map(({ name }) => name), providerGatesModule.GATE_NAMES);
  assert.ok(summary.gates.every((gate) => gate.status === 'EXTERNAL-PENDING'));
  assert.ok(summary.gates.every((gate) => gate.localReadinessStatus === 'LOCAL-SCAFFOLDING-ONLY'));
  assert.ok(summary.gates.every((gate) => gate.transitiveSafetyBindingCount === 8));
  assert.ok(summary.gates.every((gate) => gate.canBeSatisfiedLocally === false));
});

test('module exports validation and summary only, never evidence creation, signing, or minting', () => {
  const exportedNames = Object.keys(providerGatesModule).sort();
  assert.deepEqual(exportedNames, ['GATE_NAMES', 'summarizeV1ProviderGates', 'validateV1ProviderGates']);
  assert.ok(exportedNames.every((name) => !/(?:create|sign|mint)/i.test(name)));
  const source = fs.readFileSync(scriptPath, 'utf8');
  for (const forbidden of [
    /fs\.(?:appendFile|createWriteStream|mkdir|rename|rm|unlink|writeFile)/,
    /from ['"]node:(?:child_process|crypto|http|https|net|tls)['"]/,
    /\bfetch\s*\(/,
  ]) assert.doesNotMatch(source, forbidden);
});

test('summary CLI reads the canonical inventory without changing its identity or content', () => {
  const beforeStat = fs.statSync(policyPath);
  const beforeHash = sha256(policyPath);
  const output = execFileSync(process.execPath, [scriptPath, '--summary', policyPath], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  });
  const afterStat = fs.statSync(policyPath);
  const afterHash = sha256(policyPath);

  assert.equal(afterHash, beforeHash);
  assert.equal(afterStat.dev, beforeStat.dev);
  assert.equal(afterStat.ino, beforeStat.ino);
  assert.equal(afterStat.size, beforeStat.size);
  assert.equal(afterStat.mtimeMs, beforeStat.mtimeMs);
  assert.deepEqual(JSON.parse(output), providerGatesModule.summarizeV1ProviderGates(canonicalDocument()));
});

test('CLI rejects every non-summary mode and never accepts an output path', () => {
  for (const args of [[], ['--output', 'receipt.json'], ['--summary'], ['--summary', policyPath, '--output', 'x']]) {
    const result = spawnSync(process.execPath, [scriptPath, ...args], {
      cwd: repositoryRoot,
      encoding: 'utf8',
    });
    assert.notEqual(result.status, 0, `unexpected success for ${JSON.stringify(args)}`);
    assert.match(result.stderr, /usage:/);
  }
});

test('READY, partial, authoritative, locally satisfiable, and self-asserted states are rejected', () => {
  expectRejected((document) => { document.status = 'READY'; }, /READY and partial states are forbidden/);
  expectRejected((document) => { document.gates.deploymentAdmission.status = 'READY'; }, /READY and partial states are forbidden/);
  expectRejected((document) => { document.gates.deploymentAdmission.status = 'PARTIALLY-READY'; }, /READY and partial states are forbidden/);
  expectRejected((document) => { document.authoritativeEvidence = true; }, /authoritativeEvidence must be false/);
  expectRejected((document) => { document.canBeSatisfiedLocally = true; }, /canBeSatisfiedLocally must be false/);
  expectRejected((document) => { document.selfAssertedEvidenceAccepted = true; }, /selfAssertedEvidenceAccepted must be false/);
  expectRejected((document) => { document.gates.activationPromotionSigstore.selfAssertedEvidenceAccepted = true; }, /selfAssertedEvidenceAccepted must be false/);
});

test('fake receipts, keys, workflows, and placeholders cannot turn null external bindings into evidence', () => {
  expectRejected((document) => {
    document.gates.hostedPreparationProviderConformance.externalBindings.targetRootPreparationReceipt.sha256 = 'a'.repeat(64);
  }, /must remain null/);
  expectRejected((document) => {
    document.gates.activationPromotionSigstore.externalBindings.dockerAuthorizationKey.identity = 'provider-key-1';
  }, /must remain null/);
  expectRejected((document) => {
    document.gates.hostedPreparationProviderConformance.externalBindings.providerSigningKey.identity = 'TODO';
  }, /must remain null/);
  expectRejected((document) => {
    document.gates.deploymentAdmission.externalBindings.providerWorkflow.identity = 'org/provider/.github/workflows/admit.yml@main';
  }, /must remain null/);
  expectRejected((document) => {
    document.gates.deploymentAdmission.externalBindings.providerWorkflow.sha256 = 'b'.repeat(64);
  }, /must remain null/);
});

test('omitted gates, evidence, gaps, bindings, and reasons fail the closed schema', () => {
  expectRejected((document) => { delete document.gates.deploymentAdmission; }, /must contain exactly/);
  expectRejected((document) => { document.gates.deploymentAdmission.externalEvidenceRequired.pop(); }, /closed ordered list/);
  expectRejected((document) => { document.gates.hostedPreparationProviderConformance.localReadiness.gaps.shift(); }, /closed ordered list/);
  expectRejected((document) => {
    delete document.gates.activationPromotionSigstore.externalBindings.customTrustedRoot.sha256;
  }, /must contain exactly/);
  expectRejected((document) => { delete document.gates.hostedPreparationProviderConformance.reason; }, /must contain exactly/);
});

test('cross-gate evidence or binding confusion is rejected', () => {
  expectRejected((document) => {
    const hostedEvidence = document.gates.hostedPreparationProviderConformance.externalEvidenceRequired;
    document.gates.hostedPreparationProviderConformance.externalEvidenceRequired = document.gates.deploymentAdmission.externalEvidenceRequired;
    document.gates.deploymentAdmission.externalEvidenceRequired = hostedEvidence;
  }, /closed ordered list/);
  expectRejected((document) => {
    document.gates.deploymentAdmission.externalBindings = structuredClone(
      document.gates.activationPromotionSigstore.externalBindings,
    );
  }, /must contain exactly/);
  expectRejected((document) => {
    document.gates.hostedPreparationProviderConformance.transitiveSafetyBindings = structuredClone(
      document.gates.deploymentAdmission.transitiveSafetyBindings,
    );
  }, /concrete non-placeholder V1 reason/);
  expectRejected((document) => {
    document.gates.activationPromotionSigstore.transitiveSafetyBindings.separateDeviceProof = structuredClone(
      document.gates.hostedPreparationProviderConformance.transitiveSafetyBindings.separateDeviceProof,
    );
  }, /concrete non-placeholder V1 reason/);
});

test('unknown fields and rewritten local claims are rejected', () => {
  expectRejected((document) => { document.generatedReceipt = 'self-asserted'; }, /must contain exactly/);
  expectRejected((document) => {
    document.gates.deploymentAdmission.localReadiness.status = 'READY';
  }, /LOCAL-SCAFFOLDING-ONLY/);
  expectRejected((document) => {
    document.gates.activationPromotionSigstore.localReadiness.safePreparations.push('Mint an attestation locally.');
  }, /closed ordered list/);
  expectRejected((document) => {
    document.gates.hostedPreparationProviderConformance.externalBindings.providerWorkflow.reason = 'TODO';
  }, /concrete non-placeholder/);
});

test('every external gate exposes the exact closed transitive preservation and recovery chain', () => {
  const document = canonicalDocument();
  for (const gateName of providerGatesModule.GATE_NAMES) {
    const bindings = document.gates[gateName].transitiveSafetyBindings;
    assert.ok(bindings, `${gateName} is missing transitiveSafetyBindings`);
    assert.deepEqual(Object.keys(bindings).sort(), Object.keys(TRANSITIVE_SAFETY_BINDING_FIELDS).sort());
    for (const [bindingName, expectedFields] of Object.entries(TRANSITIVE_SAFETY_BINDING_FIELDS)) {
      const binding = bindings[bindingName];
      assert.deepEqual(Object.keys(binding).sort(), [...expectedFields].sort(), `${gateName}.${bindingName}`);
      assert.equal(typeof binding.reason, 'string', `${gateName}.${bindingName}.reason`);
      for (const [field, value] of Object.entries(binding)) {
        if (field === 'requirements') {
          assert.deepEqual(value, SEPARATE_DEVICE_REQUIREMENTS, `${gateName}.${bindingName}.${field}`);
        } else if (field !== 'reason') {
          assert.equal(value, null, `${gateName}.${bindingName}.${field}`);
        }
      }
    }
  }
});

test('no future gate chain can omit the canonical baseline or authoritative PRE-DEPLOY backup receipt', () => {
  for (const gateName of providerGatesModule.GATE_NAMES) {
    for (const bindingName of ['canonicalPreservationBaseline', 'preDeployBackupReceipt']) {
      const document = cloneDocument();
      const bindings = document.gates[gateName].transitiveSafetyBindings;
      assert.ok(bindings, `${gateName} is missing transitiveSafetyBindings`);
      delete bindings[bindingName];
      assert.throws(
        () => providerGatesModule.validateV1ProviderGates(document),
        /transitiveSafetyBindings.*must contain exactly/,
        `${gateName} accepted a chain without ${bindingName}`,
      );
    }
  }
});

test('every transitive safety binding and exact field is mandatory in every gate', () => {
  for (const gateName of providerGatesModule.GATE_NAMES) {
    for (const [bindingName, fields] of Object.entries(TRANSITIVE_SAFETY_BINDING_FIELDS)) {
      const missingBinding = cloneDocument();
      delete missingBinding.gates[gateName].transitiveSafetyBindings[bindingName];
      assert.throws(
        () => providerGatesModule.validateV1ProviderGates(missingBinding),
        /must contain exactly/,
        `${gateName} accepted omission of ${bindingName}`,
      );
      for (const field of fields) {
        const document = cloneDocument();
        delete document.gates[gateName].transitiveSafetyBindings[bindingName][field];
        assert.throws(
          () => providerGatesModule.validateV1ProviderGates(document),
          /must contain exactly/,
          `${gateName}.${bindingName} accepted omission of ${field}`,
        );
      }
    }
  }
});

test('partial, placeholder, and locally fabricated transitive bindings stay fail-closed', () => {
  const mutations = [
    ['hostedPreparationProviderConformance', 'canonicalPreservationBaseline', 'complete', true],
    ['deploymentAdmission', 'preDeployBackupReceipt', 'artifactSha256', 'a'.repeat(64)],
    ['deploymentAdmission', 'candidateIdentity', 'commitSha', 'b'.repeat(40)],
    ['activationPromotionSigstore', 'targetIdentity', 'root', '/'],
    ['activationPromotionSigstore', 'separateDeviceProof', 'sourceDeviceSetSha256', 'c'.repeat(64)],
    ['activationPromotionSigstore', 'separateDeviceProof', 'sourceDeviceCount', 1],
    ['activationPromotionSigstore', 'separateDeviceProof', 'sourceDeviceIdentitiesComplete', true],
    ['activationPromotionSigstore', 'separateDeviceProof', 'backupDeviceIdentity', '2049'],
    ['activationPromotionSigstore', 'separateDeviceProof', 'verifiedOutsideAllSources', true],
    ['activationPromotionSigstore', 'providerSignatureAdmission', 'signatureVerified', true],
    ['activationPromotionSigstore', 'targetRootSignatureAdmission', 'admissionId', 'target-admission-1'],
    ['activationPromotionSigstore', 'postDeployPreservationForDataRollback', 'baselineId', 'postdeploy-1'],
  ];
  for (const [gateName, bindingName, field, value] of mutations) {
    const document = cloneDocument();
    const bindings = document.gates[gateName].transitiveSafetyBindings;
    assert.ok(bindings, `${gateName} is missing transitiveSafetyBindings`);
    bindings[bindingName][field] = value;
    assert.throws(
      () => providerGatesModule.validateV1ProviderGates(document),
      /must remain null until authoritative external evidence is supplied/,
      `${gateName}.${bindingName}.${field} accepted a partial or fabricated binding`,
    );
  }
  expectRejected((document) => {
    document.gates.deploymentAdmission
      .transitiveSafetyBindings.canonicalPreservationBaseline.reason = 'TODO';
  }, /concrete non-placeholder V1 reason/);
});

test('separate-device proof covers the canonical complete destruction-domain source set', () => {
  const document = canonicalDocument();
  for (const gateName of providerGatesModule.GATE_NAMES) {
    const proof = document.gates[gateName].transitiveSafetyBindings.separateDeviceProof;
    assert.deepEqual(proof.requirements, SEPARATE_DEVICE_REQUIREMENTS);
    for (const field of [
      'artifactSha256',
      'baselineArtifactSha256',
      'baselineId',
      'sourceDeviceSetSha256',
      'sourceDeviceCount',
      'sourceDeviceIdentitiesComplete',
      'backupDeviceIdentity',
      'verifiedOutsideAllSources',
    ]) assert.equal(proof[field], null, `${gateName}.separateDeviceProof.${field}`);
  }
});

test('provider source-device classes stay in exact parity with receipt device observation sites', () => {
  const source = fs.readFileSync(receiptVerifierPath, 'utf8');
  assert.deepEqual(
    PERSISTENT_SOURCE_CLASSES,
    SEPARATE_DEVICE_REQUIREMENTS.sourceClasses,
    'provider source classes drifted from the canonical receipt source-set export',
  );
  const derivationSection = source.match(
    /function derivePersistentSourceSetFromValidatedBaseline\(baseline\) \{[\s\S]*?(?=\nexport function derivePersistentSourceSet)/,
  )?.[0] ?? '';
  assert.notEqual(derivationSection, '', 'canonical persistent-source derivation is missing');
  for (const sourceClass of PERSISTENT_SOURCE_CLASSES) {
    assert.match(derivationSection, new RegExp(`"${sourceClass}"`), `${sourceClass} is not observed canonically`);
  }
  assert.match(
    source,
    /const persistentSourceSet = derivePersistentSourceSetFromValidatedBaseline\(baseline\);[\s\S]*?new Set\(persistentSourceSet\.sourceDeviceIdentities\)/,
    'backup device exclusion must consume the shared canonical persistent-source set',
  );
});

test('target-only, incomplete-identity, non-canonical, and same-source device semantics fail closed', () => {
  const mutations = [
    ['sourceClasses', ['TARGET-CHECKOUT']],
    ['sourceClasses', SEPARATE_DEVICE_REQUIREMENTS.sourceClasses.slice(1)],
    ['sourceSetCanonicalization', 'UNSORTED-DEVICE-LIST'],
    ['missingIdentityEffect', 'ALLOW'],
    ['comparison', 'BACKUP-DEVICE-DIFFERS-FROM-TARGET-ONLY'],
    ['comparison', 'BACKUP-DEVICE-MAY-EQUAL-A-NON-TARGET-SOURCE'],
  ];
  for (const gateName of providerGatesModule.GATE_NAMES) {
    for (const requirement of Object.keys(SEPARATE_DEVICE_REQUIREMENTS)) {
      const missingRequirement = cloneDocument();
      delete missingRequirement.gates[gateName]
        .transitiveSafetyBindings.separateDeviceProof.requirements[requirement];
      assert.throws(
        () => providerGatesModule.validateV1ProviderGates(missingRequirement),
        /separateDeviceProof\.requirements.*must contain exactly/,
        `${gateName} accepted omission of ${requirement}`,
      );
    }
    for (const [field, value] of mutations) {
      const document = cloneDocument();
      document.gates[gateName]
        .transitiveSafetyBindings.separateDeviceProof.requirements[field] = value;
      assert.throws(
        () => providerGatesModule.validateV1ProviderGates(document),
        /separateDeviceProof\.requirements/,
        `${gateName} accepted unsafe ${field} semantics`,
      );
    }
  }
});

test('Hosted sequencing records only the user-approved two-phase order while provider evidence stays pending', () => {
  const document = canonicalDocument();
  const sequencing = document.hostedPreparationSequencing;
  assert.ok(sequencing, 'hostedPreparationSequencing is missing');
  assert.deepEqual(Object.keys(sequencing).sort(), [
    'authoritativeEvidence',
    'canBeSatisfiedLocally',
    'effect',
    'literalOrderSatisfiable',
    'orderedSequence',
    'phases',
    'reason',
    'requiresUserOrderApproval',
    'status',
    'userOrderApprovalStatus',
  ]);
  assert.equal(sequencing.status, 'EXTERNAL-PENDING');
  assert.equal(sequencing.authoritativeEvidence, false);
  assert.equal(sequencing.canBeSatisfiedLocally, false);
  assert.equal(sequencing.effect, 'STOP');
  assert.equal(sequencing.literalOrderSatisfiable, false);
  assert.equal(sequencing.userOrderApprovalStatus, 'USER-APPROVED');
  assert.equal(sequencing.requiresUserOrderApproval, false);
  assert.deepEqual(sequencing.orderedSequence, HOSTED_TWO_PHASE_SEQUENCE);
  assert.equal(typeof sequencing.reason, 'string');
  assert.deepEqual(Object.keys(sequencing.phases), [
    'preMutationProviderAuthorization',
    'postBackupTargetInstallationReceipt',
  ]);
  const beforeMutation = sequencing.phases.preMutationProviderAuthorization;
  assert.equal(beforeMutation.status, 'EXTERNAL-PENDING');
  assert.equal(beforeMutation.external, true);
  assert.equal(beforeMutation.readOnly, true);
  assert.equal(beforeMutation.mustCompleteBeforeLivePreflight, true);
  assert.equal(beforeMutation.mutationAuthority, false);
  assert.ok(Object.values(beforeMutation.bindings).every((value) => value === null));
  assert.deepEqual(Object.keys(beforeMutation.providerProducerMetadata).sort(), [
    'bindings',
    'external',
    'requiredEventName',
    'requiredRef',
    'requiresProtectedEnvironment',
  ]);
  assert.equal(beforeMutation.providerProducerMetadata.external, true);
  assert.equal(beforeMutation.providerProducerMetadata.requiredRef, 'refs/heads/main');
  assert.equal(beforeMutation.providerProducerMetadata.requiredEventName, 'workflow_dispatch');
  assert.equal(beforeMutation.providerProducerMetadata.requiresProtectedEnvironment, true);
  assert.deepEqual(Object.keys(beforeMutation.providerProducerMetadata.bindings).sort(), [
    'approvalEvidenceIdentity',
    'approvalEvidenceSha256',
    'eventName',
    'headSha',
    'jobWorkflowSha',
    'protectedEnvironment',
    'ref',
    'repository',
    'runAttempt',
    'runId',
    'workflowPath',
  ]);
  assert.ok(Object.values(beforeMutation.providerProducerMetadata.bindings).every((value) => value === null));
  const afterBackup = sequencing.phases.postBackupTargetInstallationReceipt;
  assert.equal(afterBackup.status, 'EXTERNAL-PENDING');
  assert.equal(afterBackup.external, true);
  assert.equal(afterBackup.requiresFreshCompleteLivePreflightPass, true);
  assert.equal(afterBackup.requiresVerifiedPreDeployBackup, true);
  assert.equal(afterBackup.requiresBackupRootOutsideCompleteBaselineSourceDeviceSet, true);
  assert.equal(afterBackup.mustCompleteBeforeActivation, true);
  assert.equal(afterBackup.mutationAuthority, false);
  assert.ok(Object.values(afterBackup.bindings).every((value) => value === null));
});

test('Hosted sequencing cannot become READY, skip backup, authorize mutation, or self-fill evidence', () => {
  const mutations = [
    [(d) => { d.hostedPreparationSequencing.userOrderApprovalStatus = 'READY'; }, /userOrderApprovalStatus/],
    [(d) => { d.hostedPreparationSequencing.requiresUserOrderApproval = true; }, /requiresUserOrderApproval/],
    [(d) => { d.hostedPreparationSequencing.literalOrderSatisfiable = true; }, /literalOrderSatisfiable/],
    [(d) => { d.hostedPreparationSequencing.status = 'READY'; }, /EXTERNAL-PENDING/],
    [(d) => { d.hostedPreparationSequencing.effect = 'CONTINUE'; }, /effect/],
    [(d) => { d.hostedPreparationSequencing.canBeSatisfiedLocally = true; }, /locally satisfiable/],
    [(d) => { d.hostedPreparationSequencing.reason = null; }, /reason/],
    [(d) => { d.hostedPreparationSequencing.orderedSequence.reverse(); }, /orderedSequence/],
    [(d) => { d.hostedPreparationSequencing.orderedSequence.splice(2, 1); }, /orderedSequence/],
    [(d) => { d.hostedPreparationSequencing.orderedSequence[1] = d.hostedPreparationSequencing.orderedSequence[0]; }, /orderedSequence/],
    [(d) => { delete d.hostedPreparationSequencing.phases.preMutationProviderAuthorization; }, /must contain exactly/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.status = 'READY'; }, /EXTERNAL-PENDING/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.external = false; }, /external/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.readOnly = false; }, /readOnly/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.mustCompleteBeforeLivePreflight = false; }, /mustCompleteBeforeLivePreflight/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.mutationAuthority = true; }, /mutationAuthority/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.bindings.packageBytesSha256 = 'd'.repeat(64); }, /must remain null/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.bindings.twoPhaseOrderContractSha256 = 'd'.repeat(64); }, /must remain null/],
    [(d) => { delete d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.bindings.trustKeySha256; }, /must contain exactly/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.external = false; }, /providerProducerMetadata\.external/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.requiredRef = 'refs/heads/dev'; }, /requiredRef/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.requiredEventName = 'push'; }, /requiredEventName/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.requiresProtectedEnvironment = false; }, /requiresProtectedEnvironment/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.bindings.repository = 'provider/repo'; }, /must remain null/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.bindings.ref = 'refs/heads/main'; }, /must remain null/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.bindings.eventName = 'workflow_dispatch'; }, /must remain null/],
    [(d) => { d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.bindings.approvalEvidenceSha256 = 'e'.repeat(64); }, /must remain null/],
    [(d) => { delete d.hostedPreparationSequencing.phases.preMutationProviderAuthorization.providerProducerMetadata.bindings.runAttempt; }, /must contain exactly/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.status = 'READY'; }, /EXTERNAL-PENDING/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.external = false; }, /external/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.requiresFreshCompleteLivePreflightPass = false; }, /requiresFreshCompleteLivePreflightPass/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.requiresVerifiedPreDeployBackup = false; }, /requiresVerifiedPreDeployBackup/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.requiresBackupRootOutsideCompleteBaselineSourceDeviceSet = false; }, /requiresBackupRootOutsideCompleteBaselineSourceDeviceSet/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.mustCompleteBeforeActivation = false; }, /mustCompleteBeforeActivation/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.mutationAuthority = true; }, /mutationAuthority/],
    [(d) => { d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.bindings.finalAdmissionId = 'local-final'; }, /must remain null/],
    [(d) => { delete d.hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt.bindings.preDeployReceiptId; }, /must contain exactly/],
  ];
  for (const [mutate, pattern] of mutations) expectRejected(mutate, pattern);
});

test('every Phase A producer metadata field remains externally supplied and null', () => {
  const fields = Object.keys(
    canonicalDocument()
      .hostedPreparationSequencing
      .phases
      .preMutationProviderAuthorization
      .providerProducerMetadata
      .bindings,
  );
  assert.deepEqual(fields.sort(), [
    'approvalEvidenceIdentity',
    'approvalEvidenceSha256',
    'eventName',
    'headSha',
    'jobWorkflowSha',
    'protectedEnvironment',
    'ref',
    'repository',
    'runAttempt',
    'runId',
    'workflowPath',
  ]);
  for (const field of fields) {
    expectRejected((document) => {
      document
        .hostedPreparationSequencing
        .phases
        .preMutationProviderAuthorization
        .providerProducerMetadata
        .bindings[field] = `local-${field}`;
    }, new RegExp(`providerProducerMetadata\\.bindings\\.${field} must remain null`));
  }
});

test('deployment contract records scoped user approval without relabeling it as provider evidence', () => {
  const source = fs.readFileSync(deploymentContractPath, 'utf8');
  assert.match(source, /USER-APPROVED/);
  assert.match(source, /governance authorization only/i);
  assert.match(source, /not provider\s+evidence/i);
  assert.match(source, /Phase A[\s\S]*live read-only preflight[\s\S]*outside the complete source-device set[\s\S]*Phase B[\s\S]*activation/i);
  assert.match(source, /all three provider gates remain `EXTERNAL-PENDING`/i);
});
