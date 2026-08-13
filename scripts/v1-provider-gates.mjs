import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const EXTERNAL_PENDING = 'EXTERNAL-PENDING';
const LOCAL_SCAFFOLDING_ONLY = 'LOCAL-SCAFFOLDING-ONLY';
const USER_APPROVED = 'USER-APPROVED';
const MAX_INPUT_BYTES = 1024 * 1024;

export const GATE_NAMES = Object.freeze([
  'hostedPreparationProviderConformance',
  'deploymentAdmission',
  'activationPromotionSigstore',
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

const HOSTED_TWO_PHASE_SEQUENCE = Object.freeze([
  'PHASE-A-READ-ONLY-PROVIDER-AUTHORIZATION',
  'LIVE-READ-ONLY-PREFLIGHT-PASS',
  'VERIFIED-PRE-DEPLOY-BACKUP-OUTSIDE-COMPLETE-SOURCE-DEVICE-SET',
  'PHASE-B-EXACT-ATTESTED-PACKAGE-INSTALLATION',
  'PHASE-B-TARGET-ROOT-INSTALLATION-RECEIPT',
  'PHASE-B-INDEPENDENT-PROVIDER-FINAL-ADMISSION',
  'ACTIVATION-AFTER-ALL-PROVIDER-GATES-PASS',
]);

const HOSTED_PREPARATION_SEQUENCING = Object.freeze({
  status: EXTERNAL_PENDING,
  authoritativeEvidence: false,
  canBeSatisfiedLocally: false,
  effect: 'STOP',
  literalOrderSatisfiable: false,
  userOrderApprovalStatus: USER_APPROVED,
  requiresUserOrderApproval: false,
  orderedSequence: HOSTED_TWO_PHASE_SEQUENCE,
  reason: 'The user approved the two-phase Hosted order, superseding the unsatisfiable literal order. This governance authorization is not provider evidence; Phase A authorization and every authoritative external binding remain absent, so server work remains STOP.',
  phases: Object.freeze({
    preMutationProviderAuthorization: Object.freeze({
      status: EXTERNAL_PENDING,
      external: true,
      readOnly: true,
      mustCompleteBeforeLivePreflight: true,
      mutationAuthority: false,
      reason: 'No external read-only pre-mutation provider authorization binds the exact package bytes, package attestation, and independently distributed trust key.',
      bindings: Object.freeze({
        authorizationArtifactSha256: null,
        authorizationId: null,
        packageAttestationArtifactSha256: null,
        packageBytesSha256: null,
        twoPhaseOrderContractId: null,
        twoPhaseOrderContractSha256: null,
        trustKeyIdentity: null,
        trustKeySha256: null,
      }),
      providerProducerMetadata: Object.freeze({
        external: true,
        requiredRef: 'refs/heads/main',
        requiredEventName: 'workflow_dispatch',
        requiresProtectedEnvironment: true,
        bindings: Object.freeze({
          repository: null,
          workflowPath: null,
          jobWorkflowSha: null,
          headSha: null,
          ref: null,
          eventName: null,
          runId: null,
          runAttempt: null,
          protectedEnvironment: null,
          approvalEvidenceIdentity: null,
          approvalEvidenceSha256: null,
        }),
      }),
    }),
    postBackupTargetInstallationReceipt: Object.freeze({
      status: EXTERNAL_PENDING,
      external: true,
      requiresFreshCompleteLivePreflightPass: true,
      requiresVerifiedPreDeployBackup: true,
      requiresBackupRootOutsideCompleteBaselineSourceDeviceSet: true,
      mustCompleteBeforeActivation: true,
      mutationAuthority: false,
      reason: 'No post-backup target installation receipt and final provider admission bind the verified PRE-DEPLOY backup before activation.',
      bindings: Object.freeze({
        preDeployReceiptArtifactSha256: null,
        preDeployReceiptId: null,
        targetInstallationReceiptArtifactSha256: null,
        targetInstallationReceiptId: null,
        finalAdmissionArtifactSha256: null,
        finalAdmissionId: null,
      }),
    }),
  }),
});

function transitiveSafetyBindings(phaseName) {
  return Object.freeze({
    canonicalPreservationBaseline: Object.freeze({
      artifactSha256: null,
      baselineId: null,
      complete: null,
      reason: `No canonical complete preservation baseline artifact SHA-256 and baselineId are bound transitively to the ${phaseName} gate.`,
    }),
    preDeployBackupReceipt: Object.freeze({
      artifactSha256: null,
      authoritative: null,
      receiptId: null,
      reason: `No authoritative PRE-DEPLOY backup receipt artifact SHA-256 and receiptId are bound transitively to the ${phaseName} gate.`,
    }),
    candidateIdentity: Object.freeze({
      commitSha: null,
      treeSha: null,
      reason: `No exact candidate commit and tree SHA are bound transitively to the ${phaseName} gate.`,
    }),
    targetIdentity: Object.freeze({
      root: null,
      identity: null,
      reason: `No real target root and independently observed target identity are bound transitively to the ${phaseName} gate.`,
    }),
    separateDeviceProof: Object.freeze({
      artifactSha256: null,
      baselineArtifactSha256: null,
      baselineId: null,
      backupDeviceIdentity: null,
      sourceDeviceCount: null,
      sourceDeviceIdentitiesComplete: null,
      sourceDeviceSetSha256: null,
      verifiedOutsideAllSources: null,
      requirements: SEPARATE_DEVICE_REQUIREMENTS,
      reason: `No proof artifact binds the complete canonical baseline-derived destruction-domain source-device set and verifies the backup device is outside every source for the ${phaseName} gate.`,
    }),
    providerSignatureAdmission: Object.freeze({
      admissionArtifactSha256: null,
      admissionId: null,
      signatureArtifactSha256: null,
      signatureVerified: null,
      signerIdentity: null,
      reason: `No provider signature and admission artifact, signer identity, and admission identity are bound transitively to the ${phaseName} gate.`,
    }),
    targetRootSignatureAdmission: Object.freeze({
      admissionArtifactSha256: null,
      admissionId: null,
      signatureArtifactSha256: null,
      signatureVerified: null,
      signerIdentity: null,
      reason: `No target-root signature and admission artifact, signer identity, and admission identity are bound transitively to the ${phaseName} gate.`,
    }),
    postDeployPreservationForDataRollback: Object.freeze({
      artifactSha256: null,
      baselineId: null,
      candidateCommitSha: null,
      dataRollbackAdmissionId: null,
      preDeployReceiptId: null,
      reason: `No post-deploy preservation artifact is bound to the candidate and PRE-DEPLOY receipt for a separately admitted data rollback in the ${phaseName} gate.`,
    }),
  });
}

const CONTRACTS = Object.freeze({
  hostedPreparationProviderConformance: Object.freeze({
    reason: 'No independent hosted-preparation producer, provider verification key, target-root receipt, or final provider admission is bound to this candidate.',
    safePreparations: Object.freeze([
      'Keep the hosted-preparation authorization, receipt, and final-admission consumers fail-closed.',
      'Implement and test the fixed root-owned broker contract without creating provider evidence.',
      'Wire production workflow consumers only after their external trust bindings are configured.',
    ]),
    gaps: Object.freeze([
      'The V1 repository does not contain a provider-owned producer that is independent from the candidate repository.',
      'The fixed root-owned hosted-preparation broker has no provider-attested installed identity or digest.',
      'No production workflow consumes a real authorization, target-root preparation receipt, and final-admission triple.',
      'The existing local conformance result is structural and non-authoritative.',
      'No canonical complete preservation baseline or authoritative PRE-DEPLOY backup receipt is bound transitively to this gate.',
      'No exact candidate and target identity chain, complete all-source separate-device proof, provider and target-root signature/admission chain, or post-deploy data-rollback preservation binding exists.',
      'The superseded literal Hosted order is circular; the user-approved two-phase sequence remains stopped because no authentic Phase A provider authorization or producer metadata is bound.',
    ]),
    externalBindings: Object.freeze({
      providerSigningKey: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'An independent provider-controlled Ed25519 verification key has not been delivered or pinned.',
      }),
      providerWorkflow: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'The provider repository, workflow path, and immutable workflow revision have not been selected and attested.',
      }),
      rootOwnedPreparationBroker: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'The required path is /usr/local/libexec/platform-hosted-preparation-broker, but its installed provider-attested identity and digest are unavailable.',
      }),
      authorizationEnvelope: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No provider-signed hosted-preparation authorization has been issued for the candidate and real target.',
      }),
      targetRootPreparationReceipt: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No target-root execution receipt with a preservation and nonmutation result exists.',
      }),
      finalDeploymentAdmission: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No independent provider final admission binds the candidate to the hosted-preparation receipt.',
      }),
    }),
    transitiveSafetyBindings: transitiveSafetyBindings('hosted preparation/provider conformance'),
    externalEvidenceRequired: Object.freeze([
      'Canonical complete preservation baseline artifact SHA-256 and baselineId, exact candidate commit and tree, and real target root and identity, all transitively bound to this gate.',
      'Authoritative target-root PRE-DEPLOY backup receipt artifact SHA-256 and receiptId; a baseline-bound proof artifact carrying the sorted unique source-device set SHA-256 and count for Docker root, every checkout, every Compose config file, all volume and database directories, bind lstat source and canonical target identities, all source roots, and all secret-metadata paths, with every identity present and the backup device verified outside all sources; provider and target-root signatures and admissions; and post-deploy preservation binding before any data rollback.',
      'Phase A provider-controlled repository, exact workflow path, immutable job_workflow_sha and head_sha, refs/heads/main, workflow_dispatch, run ID and attempt, protected environment, and independently authenticated approval-evidence identity and digest.',
      'Provider Ed25519 public-key identity and independently distributed key digest.',
      'Provider-signed authorization bound to the exact candidate commit and tree, real target identity, freshness window, and nonce.',
      'Provider-attested installed identity, version, ownership, mode, and SHA-256 digest of /usr/local/libexec/platform-hosted-preparation-broker.',
      'Target-root preparation receipt bound to the authorization and containing preservation and nonmutation results.',
      'Independent provider final deployment admission bound to the same candidate, target, authorization, and preparation receipt.',
      'External read-only pre-mutation provider authorization bound to exact package bytes, package-byte attestation, the user-approved two-phase order-contract identity and digest, and an independently distributed trust key.',
      'Post-backup target installation receipt and final provider admission bound to the verified PRE-DEPLOY backup and completed before activation.',
    ]),
    userInterventionRequired: Object.freeze([
      'Obtain independent-provider acceptance of the user-approved two-phase order through authenticated Phase A producer metadata and authorization; the recorded user approval is not provider evidence.',
      'Authorize a fresh complete read-only target inventory and separate-device PRE-DEPLOY backup, then return their independently authenticated identities, digests, signatures, and admissions through the trusted provider channel.',
      'Establish or select the independent provider repository and protected workflow, then approve its immutable workflow identity.',
      'Provision the provider verification key and fixed root-owned broker through the trusted provider channel.',
      'Authorize the provider workflow to inspect the real target and return the signed authorization, target-root receipt, and final admission without copying local assertions into those artifacts.',
    ]),
  }),
  deploymentAdmission: Object.freeze({
    reason: 'No trusted provider channel, immutable operations image, canonical staging execution, DAST receipt, or Sigstore admission bundle is bound to this candidate.',
    safePreparations: Object.freeze([
      'Keep deployment-admission, staging-runtime, and DAST consumers fail-closed.',
      'Validate schemas and cross-artifact subject bindings without producing deployment receipts.',
      'Wire the consumer workflow after the real provider channel, image digest, staging target, and trust identities are configured.',
    ]),
    gaps: Object.freeze([
      'Trusted verifier-channel and immutable operations-image identities are not configured.',
      'No independent provider producer workflow and immutable workflow revision are bound.',
      'No canonical HTTPS staging target has produced a real deployment receipt or runtime probe.',
      'No provider DAST countersignature or GitHub and Sigstore bundle exists for this candidate.',
      'No canonical complete preservation baseline or authoritative PRE-DEPLOY backup receipt is bound transitively to this gate.',
      'No exact candidate and target identity chain, complete all-source separate-device proof, provider and target-root signature/admission chain, or post-deploy data-rollback preservation binding exists.',
    ]),
    externalBindings: Object.freeze({
      trustedVerifierChannel: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'The independently administered verifier channel and its immutable trust identity are not configured.',
      }),
      trustedOperationsImage: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No approved provider operations image repository and immutable image digest are pinned.',
      }),
      providerWorkflow: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'The deployment-admission producer repository, workflow path, and immutable workflow revision are absent.',
      }),
      canonicalStagingTarget: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'A real canonical HTTPS staging target has not been selected and attested.',
      }),
      deploymentAdmissionReceipt: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No provider-signed deployment admission binds the candidate, policy fingerprint, target, freshness, and nonce.',
      }),
      stagingDeploymentReceipt: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No actual staging deployment receipt and runtime-probe result exists.',
      }),
      dastProviderReceipt: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No independent provider receipt countersigns DAST execution against the staging deployment.',
      }),
      dastSigstoreBundle: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No GitHub and Sigstore identity bundle attests the required DAST subject.',
      }),
    }),
    transitiveSafetyBindings: transitiveSafetyBindings('deployment admission'),
    externalEvidenceRequired: Object.freeze([
      'Canonical complete preservation baseline artifact SHA-256 and baselineId, exact candidate commit and tree, and real target root and identity, all transitively bound to this gate.',
      'Authoritative target-root PRE-DEPLOY backup receipt artifact SHA-256 and receiptId; a baseline-bound proof artifact carrying the sorted unique source-device set SHA-256 and count for Docker root, every checkout, every Compose config file, all volume and database directories, bind lstat source and canonical target identities, all source roots, and all secret-metadata paths, with every identity present and the backup device verified outside all sources; provider and target-root signatures and admissions; and post-deploy preservation binding before any data rollback.',
      'Independent provider repository, workflow path, immutable workflow revision, run identity, event, source revision, and protected environment identity.',
      'Trusted verifier-channel identity and immutable provider operations-image repository, digest, and helper identity.',
      'Provider-signed deployment admission bound to the exact candidate commit and tree, policy fingerprint, staging target, freshness window, and nonce.',
      'Actual deployment receipt from the canonical HTTPS staging target, including immutable deployed image identities and runtime-probe results.',
      'ZAP machine-readable reports plus an independent provider DAST receipt bound to the staging deployment receipt and exact candidate.',
      'GitHub and Sigstore verification bundle whose issuer, subject, workflow, repository, revision, and protected environment match the configured trust policy.',
    ]),
    userInterventionRequired: Object.freeze([
      'Authorize a fresh complete read-only target inventory and separate-device PRE-DEPLOY backup, then return their independently authenticated identities, digests, signatures, and admissions through the trusted provider channel.',
      'Configure the independently administered verifier channel, protected provider workflow and environment, and immutable operations-image identities outside the candidate repository.',
      'Select and authorize the canonical HTTPS staging target and allow the provider workflow to perform the real staging deployment, runtime probes, and DAST run.',
      'Return the provider-signed deployment admission, staging receipt, ZAP reports, DAST countersignature, and GitHub and Sigstore bundle through the trusted channel.',
    ]),
  }),
  activationPromotionSigstore: Object.freeze({
    reason: 'No independent promoter, custom trusted root, promoted seven-file artifact, immutable provider CAS proof, or signed activation authorization is bound to this candidate.',
    safePreparations: Object.freeze([
      'Keep promotion, release-bundle, and activation-authorization consumers fail-closed.',
      'Implement and test broker and sidecar contracts without generating promotion or activation evidence.',
      'Wire activation only after independent promoter, trusted-root, Sigstore, and Docker authorization identities are configured.',
    ]),
    gaps: Object.freeze([
      'No independent promoter repository, workflow revision, protected environment, or custom trusted root is bound.',
      'The Docker activation policy remains deny-all because no real issuer, subject, target, DAST subject, or Ed25519 key is configured.',
      'No real seven-file promoted artifact or immutable provider content-addressed materialization proof exists.',
      'The root activation broker and provider materialization sidecar have no provider-attested production identities or digests.',
      'No canonical complete preservation baseline or authoritative PRE-DEPLOY backup receipt is bound transitively to this gate.',
      'No exact candidate and target identity chain, complete all-source separate-device proof, provider and target-root signature/admission chain, or post-deploy data-rollback preservation binding exists.',
    ]),
    externalBindings: Object.freeze({
      customTrustedRoot: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'The independent promotion trust root and its immutable digest have not been provisioned.',
      }),
      promoterWorkflow: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'The independent promoter repository, fixed workflow path, immutable revision, and protected environment are absent.',
      }),
      promotedSevenFileArtifact: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No provider-produced fixed-name seven-file promotion artifact is available.',
      }),
      promotionReceipt: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No promotion receipt binds the candidate, prior admissions, target, artifact members, and digests.',
      }),
      activationAdmissionBundle: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No activation-admission GitHub and Sigstore bundle has been produced under the custom trusted root.',
      }),
      releaseBundle: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No promoted release bundle binds all required subjects and upstream receipts.',
      }),
      dockerAuthorizationKey: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No real Docker activation Ed25519 verification key and policy identity have been provisioned.',
      }),
      dockerActivationEnvelope: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No provider-signed activation envelope binds issuer, subject, environment, target, DAST subject, freshness, and nonce.',
      }),
      providerContentAddressedMaterialization: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'No immutable provider content-addressed materialization and proof exist for the promoted artifact.',
      }),
      rootActivationBroker: Object.freeze({
        identity: null,
        sha256: null,
        reason: 'The root activation broker and provider sidecar do not have independently attested production identities and digests.',
      }),
    }),
    transitiveSafetyBindings: transitiveSafetyBindings('activation promotion/Sigstore'),
    externalEvidenceRequired: Object.freeze([
      'Canonical complete preservation baseline artifact SHA-256 and baselineId, exact candidate commit and tree, and real target root and identity, all transitively bound to this gate.',
      'Authoritative target-root PRE-DEPLOY backup receipt artifact SHA-256 and receiptId; a baseline-bound proof artifact carrying the sorted unique source-device set SHA-256 and count for Docker root, every checkout, every Compose config file, all volume and database directories, bind lstat source and canonical target identities, all source roots, and all secret-metadata paths, with every identity present and the backup device verified outside all sources; provider and target-root signatures and admissions; and post-deploy preservation binding before any data rollback.',
      'Independent promoter repository, fixed workflow identity, immutable workflow revision, run identity, protected environment, source revision, and custom trusted-root digest.',
      'Fixed-name seven-file promoted artifact containing the exact required members and no extras, with independently attested SHA-256 digests.',
      'Promotion receipt bound to the exact candidate, target, deployment admission, staging receipt, DAST receipt, artifact members, and artifact digests.',
      'GitHub and Sigstore attestations verified under the custom trusted root and bound to the configured issuer, subject, workflow, repository, revision, and environment.',
      'Immutable provider content-addressed materialization proof for the promoted artifact and release bundle.',
      'Provider-signed Docker activation authorization bound to the configured Ed25519 key, issuer, subject, environment, target, DAST Sigstore subject, freshness window, and nonce.',
      'Provider-attested installed identities, ownership, modes, versions, and SHA-256 digests for the root activation broker and materialization sidecar.',
    ]),
    userInterventionRequired: Object.freeze([
      'Authorize a fresh complete read-only target inventory and separate-device PRE-DEPLOY backup, then return their independently authenticated identities, digests, signatures, and admissions through the trusted provider channel.',
      'Establish or select the independent promoter repository, protected environment, fixed workflow, and custom trusted root, then approve their immutable identities.',
      'Provision the real Docker activation verification key, deny-by-default policy bindings, root broker, and provider materialization sidecar through the trusted provider channel.',
      'Authorize the external promotion run and return the seven-file artifact, promotion receipt, activation-admission bundle, release bundle, and immutable materialization proof.',
      'Authorize activation only after the independent provider artifacts verify against the exact clean candidate and real target.',
    ]),
  }),
});

const TOP_LEVEL_KEYS = Object.freeze([
  'schema',
  'version',
  'status',
  'authoritativeEvidence',
  'selfAssertedEvidenceAccepted',
  'canBeSatisfiedLocally',
  'reason',
  'hostedPreparationSequencing',
  'gates',
]);

const GATE_KEYS = Object.freeze([
  'status',
  'authoritativeEvidence',
  'selfAssertedEvidenceAccepted',
  'canBeSatisfiedLocally',
  'reason',
  'localReadiness',
  'externalBindings',
  'transitiveSafetyBindings',
  'externalEvidenceRequired',
  'userInterventionRequired',
]);

const PLACEHOLDER_PATTERN = /\b(?:todo|tbd|placeholder|unknown|fake|dummy|example|n\/a)\b/i;

function fail(message) {
  throw new Error(`v1 provider gates validation failed: ${message}`);
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
}

function assertExactKeys(value, expectedKeys, label) {
  assertPlainObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} must contain exactly: ${expected.join(', ')}`);
  }
}

function assertExactArray(value, expected, label) {
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`);
  }
  if (value.length !== expected.length || value.some((entry, index) => entry !== expected[index])) {
    fail(`${label} is a closed ordered list and does not match the V1 contract`);
  }
}

function assertReason(value, expected, label) {
  if (value !== expected || value.trim().length < 24 || PLACEHOLDER_PATTERN.test(value)) {
    fail(`${label} must be the concrete non-placeholder V1 reason`);
  }
}

function validateExternalBindings(actual, expected, gateName) {
  assertExactKeys(actual, Object.keys(expected), `${gateName}.externalBindings`);
  for (const bindingName of Object.keys(expected)) {
    const label = `${gateName}.externalBindings.${bindingName}`;
    const binding = actual[bindingName];
    const expectedBinding = expected[bindingName];
    assertExactKeys(binding, ['identity', 'sha256', 'reason'], label);
    if (binding.identity !== null || binding.sha256 !== null) {
      fail(`${label} identity and sha256 must remain null until authoritative external evidence is supplied`);
    }
    assertReason(binding.reason, expectedBinding.reason, `${label}.reason`);
  }
}

function validateTransitiveSafetyBindings(actual, expected, gateName) {
  const bindingsLabel = `${gateName}.transitiveSafetyBindings`;
  assertExactKeys(actual, Object.keys(expected), bindingsLabel);
  for (const bindingName of Object.keys(expected)) {
    const label = `${bindingsLabel}.${bindingName}`;
    const binding = actual[bindingName];
    const expectedBinding = expected[bindingName];
    assertExactKeys(binding, Object.keys(expectedBinding), label);
    for (const [field, value] of Object.entries(binding)) {
      if (field === 'requirements') {
        const expectedRequirements = expectedBinding.requirements;
        assertExactKeys(value, Object.keys(expectedRequirements), `${label}.requirements`);
        assertExactArray(
          value.sourceClasses,
          expectedRequirements.sourceClasses,
          `${label}.requirements.sourceClasses`,
        );
        for (const requirement of ['sourceSetCanonicalization', 'missingIdentityEffect', 'comparison']) {
          if (value[requirement] !== expectedRequirements[requirement]) {
            fail(`${label}.requirements.${requirement} does not match the fail-closed V1 contract`);
          }
        }
      } else if (field !== 'reason' && value !== null) {
        fail(`${label}.${field} must remain null until authoritative external evidence is supplied`);
      }
    }
    assertReason(binding.reason, expectedBinding.reason, `${label}.reason`);
  }
}

function validatePendingBindings(actual, expected, label) {
  assertExactKeys(actual, Object.keys(expected), label);
  for (const field of Object.keys(expected)) {
    if (actual[field] !== null) {
      fail(`${label}.${field} must remain null until authoritative external evidence is supplied`);
    }
  }
}

function validateHostedPreparationSequencing(actual) {
  const expected = HOSTED_PREPARATION_SEQUENCING;
  assertExactKeys(actual, Object.keys(expected), 'hostedPreparationSequencing');
  if (actual.status !== EXTERNAL_PENDING) {
    fail('hostedPreparationSequencing.status must be EXTERNAL-PENDING');
  }
  if (actual.authoritativeEvidence !== false || actual.canBeSatisfiedLocally !== false) {
    fail('hostedPreparationSequencing cannot be authoritative or locally satisfiable');
  }
  if (actual.effect !== 'STOP') fail('hostedPreparationSequencing.effect must be STOP');
  if (actual.literalOrderSatisfiable !== false) {
    fail('hostedPreparationSequencing.literalOrderSatisfiable must remain false');
  }
  if (actual.userOrderApprovalStatus !== USER_APPROVED) {
    fail('hostedPreparationSequencing.userOrderApprovalStatus must be USER-APPROVED');
  }
  if (actual.requiresUserOrderApproval !== false) {
    fail('hostedPreparationSequencing.requiresUserOrderApproval must remain false after recorded user approval');
  }
  assertExactArray(
    actual.orderedSequence,
    HOSTED_TWO_PHASE_SEQUENCE,
    'hostedPreparationSequencing.orderedSequence',
  );
  assertReason(actual.reason, expected.reason, 'hostedPreparationSequencing.reason');
  assertExactKeys(actual.phases, Object.keys(expected.phases), 'hostedPreparationSequencing.phases');

  const beforeMutation = actual.phases.preMutationProviderAuthorization;
  const expectedBeforeMutation = expected.phases.preMutationProviderAuthorization;
  assertExactKeys(beforeMutation, Object.keys(expectedBeforeMutation), 'hostedPreparationSequencing.phases.preMutationProviderAuthorization');
  if (beforeMutation.status !== EXTERNAL_PENDING) fail('preMutationProviderAuthorization.status must be EXTERNAL-PENDING');
  if (beforeMutation.external !== true) fail('preMutationProviderAuthorization.external must be true');
  if (beforeMutation.readOnly !== true) fail('preMutationProviderAuthorization.readOnly must be true');
  if (beforeMutation.mustCompleteBeforeLivePreflight !== true) {
    fail('preMutationProviderAuthorization.mustCompleteBeforeLivePreflight must be true');
  }
  if (beforeMutation.mutationAuthority !== false) fail('preMutationProviderAuthorization.mutationAuthority must be false');
  assertReason(beforeMutation.reason, expectedBeforeMutation.reason, 'preMutationProviderAuthorization.reason');
  validatePendingBindings(
    beforeMutation.bindings,
    expectedBeforeMutation.bindings,
    'preMutationProviderAuthorization.bindings',
  );
  const producer = beforeMutation.providerProducerMetadata;
  const expectedProducer = expectedBeforeMutation.providerProducerMetadata;
  assertExactKeys(producer, Object.keys(expectedProducer), 'preMutationProviderAuthorization.providerProducerMetadata');
  if (producer.external !== true) {
    fail('preMutationProviderAuthorization.providerProducerMetadata.external must be true');
  }
  if (producer.requiredRef !== 'refs/heads/main') {
    fail('preMutationProviderAuthorization.providerProducerMetadata.requiredRef must be refs/heads/main');
  }
  if (producer.requiredEventName !== 'workflow_dispatch') {
    fail('preMutationProviderAuthorization.providerProducerMetadata.requiredEventName must be workflow_dispatch');
  }
  if (producer.requiresProtectedEnvironment !== true) {
    fail('preMutationProviderAuthorization.providerProducerMetadata.requiresProtectedEnvironment must be true');
  }
  validatePendingBindings(
    producer.bindings,
    expectedProducer.bindings,
    'preMutationProviderAuthorization.providerProducerMetadata.bindings',
  );

  const afterBackup = actual.phases.postBackupTargetInstallationReceipt;
  const expectedAfterBackup = expected.phases.postBackupTargetInstallationReceipt;
  assertExactKeys(afterBackup, Object.keys(expectedAfterBackup), 'hostedPreparationSequencing.phases.postBackupTargetInstallationReceipt');
  if (afterBackup.status !== EXTERNAL_PENDING) fail('postBackupTargetInstallationReceipt.status must be EXTERNAL-PENDING');
  if (afterBackup.external !== true) fail('postBackupTargetInstallationReceipt.external must be true');
  if (afterBackup.requiresFreshCompleteLivePreflightPass !== true) {
    fail('postBackupTargetInstallationReceipt.requiresFreshCompleteLivePreflightPass must be true');
  }
  if (afterBackup.requiresVerifiedPreDeployBackup !== true) {
    fail('postBackupTargetInstallationReceipt.requiresVerifiedPreDeployBackup must be true');
  }
  if (afterBackup.requiresBackupRootOutsideCompleteBaselineSourceDeviceSet !== true) {
    fail('postBackupTargetInstallationReceipt.requiresBackupRootOutsideCompleteBaselineSourceDeviceSet must be true');
  }
  if (afterBackup.mustCompleteBeforeActivation !== true) {
    fail('postBackupTargetInstallationReceipt.mustCompleteBeforeActivation must be true');
  }
  if (afterBackup.mutationAuthority !== false) {
    fail('postBackupTargetInstallationReceipt.mutationAuthority must be false');
  }
  assertReason(afterBackup.reason, expectedAfterBackup.reason, 'postBackupTargetInstallationReceipt.reason');
  validatePendingBindings(
    afterBackup.bindings,
    expectedAfterBackup.bindings,
    'postBackupTargetInstallationReceipt.bindings',
  );
}

function validateGate(gate, contract, gateName) {
  assertExactKeys(gate, GATE_KEYS, `gates.${gateName}`);
  if (gate.status !== EXTERNAL_PENDING) {
    fail(`gates.${gateName}.status must be EXTERNAL-PENDING; READY and partial states are forbidden`);
  }
  if (gate.authoritativeEvidence !== false) {
    fail(`gates.${gateName}.authoritativeEvidence must be false`);
  }
  if (gate.selfAssertedEvidenceAccepted !== false) {
    fail(`gates.${gateName}.selfAssertedEvidenceAccepted must be false`);
  }
  if (gate.canBeSatisfiedLocally !== false) {
    fail(`gates.${gateName}.canBeSatisfiedLocally must be false`);
  }
  assertReason(gate.reason, contract.reason, `gates.${gateName}.reason`);

  assertExactKeys(gate.localReadiness, ['status', 'safePreparations', 'gaps'], `gates.${gateName}.localReadiness`);
  if (gate.localReadiness.status !== LOCAL_SCAFFOLDING_ONLY) {
    fail(`gates.${gateName}.localReadiness.status must be LOCAL-SCAFFOLDING-ONLY`);
  }
  assertExactArray(
    gate.localReadiness.safePreparations,
    contract.safePreparations,
    `gates.${gateName}.localReadiness.safePreparations`,
  );
  assertExactArray(gate.localReadiness.gaps, contract.gaps, `gates.${gateName}.localReadiness.gaps`);
  validateExternalBindings(gate.externalBindings, contract.externalBindings, `gates.${gateName}`);
  validateTransitiveSafetyBindings(
    gate.transitiveSafetyBindings,
    contract.transitiveSafetyBindings,
    `gates.${gateName}`,
  );
  assertExactArray(
    gate.externalEvidenceRequired,
    contract.externalEvidenceRequired,
    `gates.${gateName}.externalEvidenceRequired`,
  );
  assertExactArray(
    gate.userInterventionRequired,
    contract.userInterventionRequired,
    `gates.${gateName}.userInterventionRequired`,
  );
}

export function validateV1ProviderGates(document) {
  assertExactKeys(document, TOP_LEVEL_KEYS, 'document');
  if (document.schema !== 'platform-v1-provider-gates/v1') {
    fail('schema must be platform-v1-provider-gates/v1');
  }
  if (document.version !== 1) {
    fail('version must be 1');
  }
  if (document.status !== EXTERNAL_PENDING) {
    fail('top-level status must be EXTERNAL-PENDING; READY and partial states are forbidden');
  }
  if (document.authoritativeEvidence !== false) {
    fail('top-level authoritativeEvidence must be false');
  }
  if (document.selfAssertedEvidenceAccepted !== false) {
    fail('top-level selfAssertedEvidenceAccepted must be false');
  }
  if (document.canBeSatisfiedLocally !== false) {
    fail('top-level canBeSatisfiedLocally must be false');
  }
  assertReason(
    document.reason,
    'The V1 candidate can prepare fail-closed consumers locally, but only independent provider workflows and the real target can produce the authoritative evidence required by these gates.',
    'document.reason',
  );

  validateHostedPreparationSequencing(document.hostedPreparationSequencing);

  assertExactKeys(document.gates, GATE_NAMES, 'document.gates');
  for (const gateName of GATE_NAMES) {
    validateGate(document.gates[gateName], CONTRACTS[gateName], gateName);
  }

  return document;
}

export function summarizeV1ProviderGates(document) {
  validateV1ProviderGates(document);
  return {
    schema: 'platform-v1-provider-gates-summary/v1',
    status: EXTERNAL_PENDING,
    authoritativeEvidence: false,
    selfAssertedEvidenceAccepted: false,
    canBeSatisfiedLocally: false,
    hostedPreparationSequencingStatus: document.hostedPreparationSequencing.status,
    userOrderApprovalStatus: document.hostedPreparationSequencing.userOrderApprovalStatus,
    requiresUserOrderApproval: document.hostedPreparationSequencing.requiresUserOrderApproval,
    literalOrderSatisfiable: document.hostedPreparationSequencing.literalOrderSatisfiable,
    orderedSequence: [...document.hostedPreparationSequencing.orderedSequence],
    gates: GATE_NAMES.map((name) => ({
      name,
      status: document.gates[name].status,
      localReadinessStatus: document.gates[name].localReadiness.status,
      gapCount: document.gates[name].localReadiness.gaps.length,
      transitiveSafetyBindingCount: Object.keys(document.gates[name].transitiveSafetyBindings).length,
      externalEvidenceRequiredCount: document.gates[name].externalEvidenceRequired.length,
      userInterventionRequiredCount: document.gates[name].userInterventionRequired.length,
      canBeSatisfiedLocally: false,
    })),
  };
}

function readJsonReadOnly(inputPath) {
  const absolutePath = path.resolve(inputPath);
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  let descriptor;
  try {
    descriptor = fs.openSync(absolutePath, flags);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1) {
      fail('summary input must be a singly linked regular file');
    }
    if (before.size <= 0 || before.size > MAX_INPUT_BYTES) {
      fail(`summary input must be between 1 and ${MAX_INPUT_BYTES} bytes`);
    }
    const source = fs.readFileSync(descriptor, 'utf8');
    const after = fs.fstatSync(descriptor);
    if (
      before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
    ) {
      fail('summary input changed while it was read');
    }
    try {
      return JSON.parse(source);
    } catch {
      fail('summary input is not valid JSON');
    }
  } finally {
    if (descriptor !== undefined) {
      fs.closeSync(descriptor);
    }
  }
}

function runCli(argv) {
  if (argv.length !== 2 || argv[0] !== '--summary' || argv[1].startsWith('-')) {
    throw new Error('usage: node scripts/v1-provider-gates.mjs --summary <governance-json>');
  }
  const document = readJsonReadOnly(argv[1]);
  process.stdout.write(`${JSON.stringify(summarizeV1ProviderGates(document), null, 2)}\n`);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
