import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  BACKUP_PAYLOAD_TYPE,
  FORBIDDEN_OPERATIONS,
  PERMITTED_OPERATIONS,
  PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
  PHASE_A_PACKAGE_PAYLOAD_TYPE,
  PHASE_B_PREINSTALL_PAYLOAD_TYPE,
  PHASE_B_REPLAY_DOMAIN,
  ROLE_NAMES,
  canonicalJson,
  validateInstallPlanV2,
  validatePreinstallTuple,
  verifyV1PhaseBPreinstallAuthorization,
} from "./v1-phase-b-preinstall-authorization.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.dirname(HERE);
const MODULE = path.join(HERE, "v1-phase-b-preinstall-authorization.mjs");
const CORE_MODULE = path.join(HERE, "v1-brownfield-admission.mjs");
const PHASE_A_MODULE = path.join(HERE, "v1-phase-a-authorization.mjs");
const TEMPLATE = path.join(REPO, "governance", "v1-phase-b-preinstall-authorization.json");
const COMMON_SCHEMA = path.join(
  REPO,
  "governance",
  "schemas",
  "v1-brownfield-common-tuple.schema.json",
);
const POLICY_SCHEMA = path.join(
  REPO,
  "governance",
  "schemas",
  "v1-phase-b-preinstall-policy.schema.json",
);
const INSTALL_PLAN_SCHEMA = path.join(
  REPO,
  "governance",
  "schemas",
  "v1-phase-b-install-plan-v2.schema.json",
);
const AUTHORIZATION_SCHEMA = path.join(
  REPO,
  "governance",
  "schemas",
  "v1-phase-b-preinstall-authorization.schema.json",
);
const SCHEMAS = [
  INSTALL_PLAN_SCHEMA,
  POLICY_SCHEMA,
  AUTHORIZATION_SCHEMA,
];
const require = createRequire(path.join(REPO, "vendor", "json-schema", "package.json"));
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

function h(value) {
  return crypto.createHash("sha256")
    .update(Buffer.isBuffer(value) ? value : String(value))
    .digest("hex");
}

function shaCanonical(value) {
  return h(canonicalJson(value));
}

function nonce(label) {
  return crypto.createHash("sha256").update(label).digest().toString("base64url");
}

function at(now, offset) {
  return new Date(now + offset).toISOString();
}

function canonicalArtifact(document) {
  const bytes = Buffer.from(canonicalJson(document) + "\n", "utf8");
  return { bytes, sha256: h(bytes) };
}

function fingerprint(publicKey) {
  return h(publicKey.export({ type: "spki", format: "der" }));
}

function pae(payloadType, payloadBytes) {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from("DSSEv1 " + String(type.length) + " ", "ascii"),
    type,
    Buffer.from(" " + String(payloadBytes.length) + " ", "ascii"),
    payloadBytes,
  ]);
}

function envelope(payloadType, payload, signers) {
  const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
  const signingBytes = pae(payloadType, payloadBytes);
  return canonicalArtifact({
    payloadType,
    payload: payloadBytes.toString("base64"),
    signatures: signers.map((signer) => ({
      keyid: signer.keyId,
      sig: crypto.sign(null, signingBytes, signer.privateKey).toString("base64"),
    })),
  });
}

function externalConstraints(role, index) {
  return {
    type: "EXTERNAL-CI",
    role,
    repository: "independent-provider/" + role.toLowerCase(),
    repositoryId: String(700000 + index),
    repositoryOwnerId: String(7000 + index),
    workflowPath: ".github/workflows/" + role + ".yml",
    jobWorkflowSha: String((index % 8) + 1).repeat(40),
    ref: "refs/heads/main",
    eventName: "workflow_dispatch",
    jobName: "produce-" + role,
    protectedEnvironment: "v1-" + role,
  };
}

function targetConstraints(role, target) {
  return {
    type: "TARGET-ROOT",
    role,
    endpoint: target.endpoint,
    targetId: target.targetId,
    machineIdentitySha256: target.machineId,
    rootAbsenceReceiptSha256: target.rootAbsenceReceiptSha256,
    rootFilesystemIdentitySha256: target.rootFilesystemIdentitySha256,
    rootIdentitySha256: target.rootIdentity === null
      ? null
      : shaCanonical(target.rootIdentity),
    rootParentIdentitySha256: shaCanonical(target.rootParentIdentity),
    rootState: target.rootState,
    targetRoot: target.root,
  };
}

function externalProducer(role, constraints, index, approvalAt) {
  return {
    ...constraints,
    headSha: String(((index + 2) % 8) + 1).repeat(40),
    runId: String(800000 + index),
    runAttempt: 1,
    approvalDecision: "APPROVED",
    approvalApproverIdentity: "github-user-id:" + String(9000 + index),
    approvalEvidenceIdentity:
      "provider-approval:" + role + ":" + String(800000 + index) + ":1",
    approvalEvidenceSha256: h(role + "-approval"),
    approvalEvidenceIssuedAt: approvalAt,
  };
}

function phaseAProducer(producer) {
  const { type: _type, role: _role, ...phaseA } = producer;
  return phaseA;
}

function targetRootProducer(role, target, atTime) {
  return {
    type: "TARGET-ROOT",
    role,
    targetId: target.targetId,
    machineId: target.machineId,
    endpoint: target.endpoint,
    root: target.root,
    rootState: target.rootState,
    rootAbsenceReceiptSha256: target.rootAbsenceReceiptSha256,
    rootFilesystemIdentitySha256: target.rootFilesystemIdentitySha256,
    rootParentIdentitySha256: shaCanonical(target.rootParentIdentity),
    rootIdentitySha256: target.rootIdentity === null
      ? null
      : shaCanonical(target.rootIdentity),
    attestationIdentity: "target-root-attestation:" + role,
    attestationArtifactSha256: h(role + "-target-attestation"),
    attestedAt: atTime,
  };
}

function target(targetKind) {
  const activation = targetKind === "activation";
  const root = activation
    ? "/srv/platform-infrastructure"
    : "/home/deploy/platform-infrastructure";
  return {
    targetId: "production-" + targetKind + "-target:platform-001",
    machineId: h("machine-identity"),
    environment: "production",
    endpoint: "ssh://deploy@platform.example.test:22",
    host: "platform.example.test",
    root,
    sshHostKeySha256: h("ssh-host-key"),
    rootFilesystemIdentitySha256: h("root-filesystem-identity"),
    dockerDaemonId: "docker-daemon:production-001",
    deploymentUid: 1001,
    deploymentGid: 1001,
    rootState: activation ? "ABSENT_PROVEN" : "EXISTING_EXACT",
    rootParentPath: path.posix.dirname(root),
    rootParentIdentity: {
      deviceIdentity: activation
        ? "device:destination-filesystem"
        : "device:source-filesystem",
      filesystemUuid: activation
        ? h("destination-filesystem-uuid")
        : h("source-filesystem-uuid"),
      inode: activation ? "4102" : "256",
      mountId: activation ? "7006" : "250",
      uid: 0,
      gid: 0,
      mode: "0755",
      nlink: 2,
    },
    rootAbsenceReceiptSha256: activation
      ? h("negative-lookup:/srv/platform-infrastructure")
      : null,
    rootIdentity: activation ? null : {
      deviceIdentity: "device:source-root",
      filesystemUuid: h("source-root-filesystem-uuid"),
      inode: "512",
      mountId: "5012",
      uid: 0,
      gid: 0,
      mode: "0755",
      nlink: 2,
    },
  };
}

function binary(pathname, label) {
  const name = path.posix.basename(pathname);
  return {
    disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
    gid: 0,
    mode: "0555",
    name,
    nlink: 1,
    packageMember: "bin/" + name,
    path: pathname,
    sha256: h(label),
    sizeBytes: 4096 + label.length,
    uid: 0,
    version: 1,
  };
}

function observedParents(requirements, prefix) {
  return requirements.map((parent, index) => ({
    path: parent.path,
    deviceIdentity: "device:" + prefix + "-filesystem",
    filesystemUuid: h(prefix + "-filesystem-uuid"),
    inode: String(4096 + index),
    mountId: String(prefix === "source-cas" ? 6000 + index : 7000 + index),
    uid: 0,
    gid: 0,
    mode: "0755",
    nlink: 2,
    symlink: false,
    writableByNonRoot: false,
  }));
}

function materializationTargets(plan) {
  const directory = (pathname) => ({
    disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
    gid: 0,
    kind: "DIRECTORY",
    mode: "0755",
    nlink: null,
    path: pathname,
    sha256: null,
    sizeBytes: null,
    uid: 0,
  });
  const file = (identity, kind = "REGULAR_FILE") => ({
    disposition: identity.disposition,
    gid: identity.gid,
    kind,
    mode: identity.mode,
    nlink: identity.nlink,
    path: identity.path,
    sha256: identity.sha256,
    sizeBytes: identity.sizeBytes,
    uid: identity.uid,
  });
  const casRoot = plan.materializationPolicy.casRoot;
  return [
    directory("/var/lib/platform-infrastructure"),
    directory("/var/lib/platform-infrastructure/v1-package-cas"),
    directory("/var/lib/platform-infrastructure/v1-package-cas/sha256"),
    directory(casRoot),
    directory("/var/lib/platform-infrastructure/v1-install-receipts"),
    directory("/var/lib/platform-infrastructure/v1-install-receipts/sha256"),
    directory("/var/lib/platform-infrastructure/v1-phase-b-ledger"),
    {
      disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
      gid: 0,
      kind: "REGULAR_FILE",
      mode: "0444",
      nlink: 1,
      path: casRoot + "/package.bin",
      sha256: plan.packageBytesSha256,
      sizeBytes: plan.packageBytesSizeBytes,
      uid: 0,
    },
    {
      disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
      gid: 0,
      kind: "REGULAR_FILE",
      mode: "0444",
      nlink: 1,
      path: casRoot + "/manifest.json",
      sha256: plan.packageManifestSha256,
      sizeBytes: plan.packageManifestSizeBytes,
      uid: 0,
    },
    ...plan.directories.map((entry) => directory(entry.path)),
    file(plan.broker, "EXECUTABLE"),
    file(plan.verifier, "EXECUTABLE"),
    ...plan.helpers.map((entry) => file(entry, "EXECUTABLE")),
    file(plan.privilegePolicy, "SUDOERS_POLICY"),
  ];
}

function materializationAnchor(pathname) {
  if (pathname.startsWith("/var/lib/")) return "/var/lib";
  if (pathname.startsWith("/srv/")) return "/srv";
  if (pathname.startsWith("/usr/local/libexec/")) return "/usr/local/libexec";
  if (pathname.startsWith("/etc/sudoers.d/")) return "/etc/sudoers.d";
  throw new Error("missing fixture anchor for " + pathname);
}

function materializationPreconditions(targets, ancestry, verifiedAt) {
  const parents = [...ancestry.sourceParents, ...ancestry.destinationParents];
  return targets.map((targetValue) => {
    const anchorPath = materializationAnchor(targetValue.path);
    const anchor = parents.find((entry) => entry.path === anchorPath);
    return {
      path: targetValue.path,
      state: "ABSENT_PROVEN",
      anchorPath,
      anchorIdentitySha256: shaCanonical(anchor),
      relativePath: path.posix.relative(anchorPath, targetValue.path),
      negativeLookupReceiptSha256: h("negative-lookup:" + targetValue.path),
      openat2ResolveBeneathNoSymlinks: true,
      openat2ResolveNoXdev: true,
      verifiedAt,
    };
  });
}

function resourceObservation(plan, ancestry, preconditions, observedAt) {
  const parents = [...ancestry.sourceParents, ...ancestry.destinationParents];
  const devices = new Map();
  for (let index = 0; index < plan.materializationTargets.length; index += 1) {
    const targetValue = plan.materializationTargets[index];
    const precondition = preconditions[index];
    const parent = precondition.state === "EXISTING_EXACT"
      ? precondition.identity
      : parents.find((entry) => entry.path === precondition.anchorPath);
    const key = parent.deviceIdentity + ":" + parent.filesystemUuid;
    if (!devices.has(key)) devices.set(key, {
      deviceIdentity: parent.deviceIdentity,
      filesystemUuid: parent.filesystemUuid,
      mountIds: [],
      plannedWriteBytes: 0,
      plannedCreatedInodes: 0,
    });
    const device = devices.get(key);
    if (!device.mountIds.includes(parent.mountId)) device.mountIds.push(parent.mountId);
    device.plannedWriteBytes += targetValue.sizeBytes ?? 4096;
    device.plannedCreatedInodes += 1;
  }
  const varParent = parents.find((entry) => entry.path === "/var/lib");
  const varDevice = devices.get(
    varParent.deviceIdentity + ":" + varParent.filesystemUuid,
  );
  if (!varDevice.mountIds.includes(varParent.mountId)) {
    varDevice.mountIds.push(varParent.mountId);
  }
  varDevice.plannedWriteBytes += plan.resourceBudget.maxJournalBytes;
  varDevice.plannedCreatedInodes += 3;
  return {
    schema: "platform.v1-pre-mutation-resource-observation/v1",
    devices: [...devices.values()].map((device) => ({
      ...device,
      mountIds: device.mountIds.sort((left, right) => Number(left) - Number(right)),
      freeBytes: 4 * 1024 * 1024 * 1024,
      freeInodes: 1_000_000,
      requiredFreeBytesAfter: plan.resourceBudget.requiredFreeBytesAfter,
      requiredFreeInodesAfter: plan.resourceBudget.requiredFreeInodesAfter,
    })),
    receiptSha256: h("pre-mutation-resource-observation-receipt"),
    observedAt,
  };
}

function buildFixture({ now = Date.now() } = {}) {
  const candidate = {
    repository: "example/platform-infrastructure",
    repositoryId: "424242",
    repositoryOwnerId: "4242",
    commitSha: "3".repeat(40),
    treeSha: "4".repeat(40),
    clean: true,
    sourceArchiveSha256: h("source-archive"),
    packageSha256: h("package-bytes"),
    packageManifestSha256: h("package-manifest-v2"),
  };
  const sourceTarget = target("source");
  const activationTarget = target("activation");
  const phaseATarget = {
    endpoint: activationTarget.endpoint,
    hostname: activationTarget.host,
    targetRoot: activationTarget.root,
    sshHostKeySha256: activationTarget.sshHostKeySha256,
    dockerDaemonId: activationTarget.dockerDaemonId,
    machineIdentitySha256: activationTarget.machineId,
    rootFilesystemIdentitySha256:
      activationTarget.rootFilesystemIdentitySha256,
    deploymentUid: activationTarget.deploymentUid,
    deploymentGid: activationTarget.deploymentGid,
  };
  const keys = {};
  for (const role of ROLE_NAMES) {
    const pair = crypto.generateKeyPairSync("ed25519");
    keys[role] = { ...pair, keyId: fingerprint(pair.publicKey) };
  }
  const constraints = {};
  ROLE_NAMES.forEach((role, index) => {
    if (role === "sourceTargetCustodian") {
      constraints[role] = targetConstraints(role, sourceTarget);
    } else if (role === "activationTargetRoot") {
      constraints[role] = targetConstraints(role, activationTarget);
    } else {
      constraints[role] = externalConstraints(role, index + 1);
    }
  });

  const times = {
    phaseAChallenge: at(now, -720000),
    phaseAChallengeExpires: at(now, -60000),
    packageApproval: at(now, -700000),
    packageIssued: at(now, -680000),
    packageExpires: at(now, -80000),
    authApproval: at(now, -650000),
    authIssued: at(now, -620000),
    authVerified: at(now, -610000),
    authExpires: at(now, -300000),
    baselineStarted: at(now, -590000),
    baselineCompleted: at(now, -500000),
    baselineVerified: at(now, -450000),
    backupStarted: at(now, -440000),
    snapshotCaptured: at(now, -420000),
    snapshotVerified: at(now, -400000),
    backupCompleted: at(now, -380000),
    backupVerified: at(now, -360000),
    structuralVerified: at(now, -340000),
    retrievalStarted: at(now, -335000),
    retrievalCompleted: at(now, -330000),
    retrievalVerified: at(now, -325000),
    restoreStarted: at(now, -320000),
    restoreVerified: at(now, -310000),
    databaseVerified: at(now, -300000),
    sourceAttested: at(now, -290000),
    backupApproval: at(now, -280000),
    backupIssued: at(now, -270000),
    backupExpires: at(now, 600000),
    phaseBChallenge: at(now, -240000),
    phaseBChallengeExpires: at(now, 300000),
    phaseBApproval: at(now, -120000),
    activationAttested: at(now, -60000),
    phaseBIssued: at(now, -30000),
    phaseBExpires: at(now, 270000),
  };
  const producers = {};
  ROLE_NAMES.forEach((role, index) => {
    if (role === "sourceTargetCustodian") {
      producers[role] = targetRootProducer(
        role,
        sourceTarget,
        times.sourceAttested,
      );
    } else if (role === "activationTargetRoot") {
      producers[role] = targetRootProducer(
        role,
        activationTarget,
        times.activationAttested,
      );
    } else {
      let approvalAt = times.phaseBApproval;
      if (role === "packageAttestor") approvalAt = times.packageApproval;
      if (role === "phaseAAuthorizationProvider") {
        approvalAt = times.authApproval;
      }
      if (role === "backupAuthority") approvalAt = times.backupApproval;
      producers[role] = externalProducer(
        role,
        constraints[role],
        index + 1,
        approvalAt,
      );
    }
  });

  const policy = {
    schema: "platform.v1-phase-b-preinstall-policy/v1",
    version: 1,
    status: "READY",
    externallyManaged: true,
    localTemplate: false,
    selfAssertedEvidenceAccepted: false,
    authoritativeEvidence: false,
    localMutationAuthority: false,
    trustAnchorProvenance: "CALLER-SUPPLIED-NON-AUTHORITATIVE",
    reason:
      "Independent role keys and static producer constraints supplied through a caller-selected verification channel.",
    payloadTypes: {
      phaseAPackageAttestation: PHASE_A_PACKAGE_PAYLOAD_TYPE,
      phaseAAuthorization: PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
      backupAttestation: BACKUP_PAYLOAD_TYPE,
      phaseBPreinstallAuthorization: PHASE_B_PREINSTALL_PAYLOAD_TYPE,
    },
    freshness: {
      maxLifetimeSeconds: 900,
      maxClockSkewSeconds: 60,
      maxBackupEvidenceAgeSeconds: 14400,
      maxBaselineToBackupLagSeconds: 14400,
    },
    replayDomain: PHASE_B_REPLAY_DOMAIN,
    backupTrustPolicySha256: h("backup-trust-policy"),
    installPlanSchema: "platform.v1-phase-b-install-plan/v2",
    installPlanSchemaSha256: h("phase-b-install-plan-v2-schema"),
    roles: Object.fromEntries(ROLE_NAMES.map((role) => [role, {
      role,
      algorithm: "Ed25519",
      keyId: keys[role].keyId,
      publicKeySpkiPem: keys[role].publicKey.export({
        type: "spki",
        format: "pem",
      }),
      producerConstraints: constraints[role],
    }])),
  };
  const policyArtifact = canonicalArtifact(policy);
  const order = {
    id: "platform-v1-hosted-two-phase-order/v1",
    sha256: h("two-phase-order-contract"),
  };
  const futureRoleKeyIds = {
    backupAuthority: keys.backupAuthority.keyId,
    sourceTargetCustodian: keys.sourceTargetCustodian.keyId,
    phaseBInstaller: keys.phaseBInstaller.keyId,
    hostedGate: keys.hostedGate.keyId,
    deploymentGate: keys.deploymentGate.keyId,
    activationGate: keys.activationGate.keyId,
    admissionController: keys.admissionController.keyId,
    activationTargetRoot: keys.activationTargetRoot.keyId,
  };
  const phaseAPolicy = {
    schema: "platform.v1-phase-a-authorization-policy/v1",
    version: 1,
    status: "READY",
    reason:
      "Independent Phase-A provider roots supplied to the verify-only historical verifier.",
    selfAssertedEvidenceAccepted: false,
    localTemplate: false,
    authoritativeEvidence: false,
    trustAnchorProvenance: "CALLER-SUPPLIED-NON-AUTHORITATIVE",
    replayLedgerStatus: "EXTERNAL_PENDING",
    candidate: structuredClone(candidate),
    twoPhaseOrderContract: structuredClone(order),
    packageAttestor: {
      role: "packageAttestor",
      algorithm: "Ed25519",
      keyId: keys.packageAttestor.keyId,
      publicKeySpkiPem: keys.packageAttestor.publicKey.export({
        type: "spki",
        format: "pem",
      }),
      producer: phaseAProducer(producers.packageAttestor),
    },
    phaseAAuthorizationProvider: {
      role: "phaseAAuthorizationProvider",
      algorithm: "Ed25519",
      keyId: keys.phaseAAuthorizationProvider.keyId,
      publicKeySpkiPem: keys.phaseAAuthorizationProvider.publicKey.export({
        type: "spki",
        format: "pem",
      }),
      producer: phaseAProducer(producers.phaseAAuthorizationProvider),
    },
    futureRoleKeyIds,
    packageAttestation: {
      payloadType: PHASE_A_PACKAGE_PAYLOAD_TYPE,
      maxLifetimeSeconds: 900,
    },
    authorization: {
      payloadType: PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
      maxLifetimeSeconds: 600,
      permittedOperations: ["READ_ONLY_LIVE_PREFLIGHT"],
      forbiddenOperations: [
        "CREATE_BACKUP",
        "QUIESCE",
        "INSTALL",
        "DOCKER",
        "FIREWALL",
        "ACTIVATE",
        "RESTORE",
      ],
    },
  };
  const phaseAPolicyArtifact = canonicalArtifact(phaseAPolicy);
  const phaseAChallenge = {
    consumerRepository: "independent-consumer/preflight",
    consumerWorkflowPath: ".github/workflows/phase-a.yml",
    consumerJobWorkflowSha: "9".repeat(40),
    consumerJob: "verify-phase-a",
    consumerRunId: "98765001",
    consumerRunAttempt: 1,
    nonce: nonce("phase-a"),
    replayDomain: "phase-a-read-only-preflight/platform-infrastructure/v1",
    issuedAt: times.phaseAChallenge,
    expiresAt: times.phaseAChallengeExpires,
  };
  const phaseAPackagePayload = {
    schema: "platform.v1-phase-a-package-attestation/v1",
    version: 1,
    status: "PACKAGE-ATTESTED",
    role: "packageAttestor",
    replayLedgerStatus: "EXTERNAL_PENDING",
    attestationId: "phase-a-package-attestation:001",
    issuedAt: times.packageIssued,
    notBefore: times.packageIssued,
    expiresAt: times.packageExpires,
    producer: phaseAProducer(producers.packageAttestor),
    candidate,
    target: phaseATarget,
    twoPhaseOrderContract: order,
    consumerChallenge: phaseAChallenge,
  };
  const phaseAPackageArtifact = envelope(
    PHASE_A_PACKAGE_PAYLOAD_TYPE,
    phaseAPackagePayload,
    [keys.packageAttestor],
  );
  const phaseAAuthorizationPayload = {
    schema: "platform.v1-phase-a-read-only-authorization/v1",
    version: 1,
    status: "READ-ONLY-AUTHORIZED",
    role: "phaseAAuthorizationProvider",
    replayLedgerStatus: "EXTERNAL_PENDING",
    authorizationId: "phase-a-read-only-authorization:001",
    issuedAt: times.authIssued,
    notBefore: times.authIssued,
    expiresAt: times.authExpires,
    producer: phaseAProducer(producers.phaseAAuthorizationProvider),
    candidate,
    target: phaseATarget,
    twoPhaseOrderContract: order,
    consumerChallenge: phaseAChallenge,
    packageAttestationEnvelopeSha256: phaseAPackageArtifact.sha256,
    permittedOperations: ["READ_ONLY_LIVE_PREFLIGHT"],
    forbiddenOperations: [
      "CREATE_BACKUP",
      "QUIESCE",
      "INSTALL",
      "DOCKER",
      "FIREWALL",
      "ACTIVATE",
      "RESTORE",
    ],
    readOnly: true,
    mutationAuthority: false,
  };
  const phaseAAuthorizationArtifact = envelope(
    PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
    phaseAAuthorizationPayload,
    [keys.phaseAAuthorizationProvider],
  );

  const sudoersContent =
    "deploy ALL=(root) NOPASSWD: /usr/local/libexec/platform-activation-broker activate\n";
  const installPlan = {
    plannedReceiptId: "install-receipt:" + h("planned-install-receipt"),
    packageBytesSha256: candidate.packageSha256,
    packageBytesSizeBytes: 1_048_576,
    packageAttestationEnvelopeSha256: phaseAPackageArtifact.sha256,
    packageManifestSha256: candidate.packageManifestSha256,
    packageManifestSizeBytes: 8192,
    broker: binary(
      "/usr/local/libexec/platform-activation-broker",
      "broker-binary",
    ),
    verifier: binary(
      "/usr/local/libexec/platform-v1-brownfield-admission",
      "admission-verifier",
    ),
    helpers: [
      binary(
        "/usr/local/libexec/platform-hosted-preparation-broker",
        "hosted-helper",
      ),
      binary(
        "/usr/local/libexec/platform-origin-firewall",
        "origin-firewall-helper",
      ),
      binary(
        "/usr/local/libexec/platform-workload-egress-firewall",
        "workload-egress-firewall-helper",
      ),
    ],
    directories: [
      "/srv/platform-infrastructure",
      "/srv/platform-infrastructure/releases",
      "/srv/platform-infrastructure/release-states",
    ].map((pathname) => ({
      path: pathname,
      uid: 0,
      gid: 0,
      mode: "0755",
      disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
    })),
    privilegePolicy: {
      path: "/etc/sudoers.d/platform-activation-broker",
      content: sudoersContent,
      contentEncoding: "UTF-8",
      sha256: h(sudoersContent),
      uid: 0,
      gid: 0,
      mode: "0440",
      nlink: 1,
      packageMember: "etc/sudoers.d/platform-activation-broker",
      sizeBytes: Buffer.byteLength(sudoersContent, "utf8"),
      disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
      principalName: "deploy",
      principalUid: 1001,
      principalGid: 1001,
      principalPreexistingRequired: true,
      principalAccountIdentityReceiptSha256:
        h("activation-broker-account-identity-receipt"),
      allowedSupplementaryGroups: [],
      dockerGroupMembershipAllowed: false,
      dockerSocketAccessAllowed: false,
      rootEquivalentCapabilitiesAllowed: false,
      unrestrictedSudoAllowed: false,
      effectiveSudoPolicyProfile: "ACTIVATION-BROKER-ACTIVATE-ONLY/V1",
      permittedInvocation:
        "/usr/local/libexec/platform-activation-broker activate",
      argumentPolicy: "EXACT-NO-WILDCARDS",
      contentProfile: "ACTIVATION-BROKER-ACTIVATE-ONLY/V1",
      setenvAllowed: false,
      shellAllowed: false,
      parentPath: "/etc/sudoers.d",
      parentUid: 0,
      parentGid: 0,
      parentMode: "0755",
      parentWritableByNonRoot: false,
      providerPrevalidated: true,
      providerValidationReceiptSha256:
        h("provider-sudoers-validation-receipt"),
      validatorPath: "/usr/sbin/visudo",
      validatorSha256: h("pinned-visudo-binary"),
    },
    installerBootstrap: {
      path: "/usr/local/libexec/platform-v1-bootstrap-installer",
      version: 2,
      sha256: h("bootstrap-installer"),
      executionIdentitySha256: h("bootstrap-execution-identity"),
      trustPolicySha256: policyArtifact.sha256,
      phaseBInstallerFingerprintSha256: keys.phaseBInstaller.keyId,
      activationTargetRootFingerprintSha256:
        keys.activationTargetRoot.keyId,
      independentlyPinned: true,
      uid: 0,
      gid: 0,
      mode: "0555",
      nlink: 1,
    },
    materializationPolicy: {
      schema: "platform.v1-package-materialization-plan/v1",
      casRoot:
        "/var/lib/platform-infrastructure/v1-package-cas/sha256/" +
        candidate.packageSha256,
      descriptorRelativeMembersOnly: true,
      destinationParents: [
        "/",
        "/usr",
        "/usr/local",
        "/usr/local/libexec",
        "/etc",
        "/etc/sudoers.d",
        "/srv",
      ].map((pathname) => ({
        path: pathname,
        uid: 0,
        gid: 0,
        mode: "0755",
        descriptorRelativeRequired: true,
        noSymlinkRequired: true,
        nonWritableByNonRootRequired: true,
      })),
      sourceParents: ["/", "/var", "/var/lib"].map((pathname) => ({
        path: pathname,
        uid: 0,
        gid: 0,
        mode: "0755",
        descriptorRelativeRequired: true,
        noSymlinkRequired: true,
        nonWritableByNonRootRequired: true,
      })),
      manifestMemberParityRequired: true,
      openatNoFollowRequired: true,
      regularRootOwnedNlinkOneLeafRequired: true,
      rootOwnedNonWritableAncestryRequired: true,
    },
  };
  installPlan.materializationTargets = materializationTargets(installPlan);
  const packageMembers = [
    installPlan.broker,
    installPlan.verifier,
    ...installPlan.helpers,
    installPlan.privilegePolicy,
  ];
  const packageMemberBytesTotal = packageMembers.reduce(
    (total, member) => total + member.sizeBytes,
    0,
  );
  const maxCasBytes =
    installPlan.packageBytesSizeBytes + installPlan.packageManifestSizeBytes;
  const maxJournalBytes = 1024 * 1024;
  installPlan.resourceBudget = {
    schema: "platform.v1-install-resource-budget/v1",
    packageMemberCount: packageMembers.length,
    packageMemberBytesTotal,
    maxCasBytes,
    maxDestinationBytes: packageMemberBytesTotal,
    maxJournalBytes,
    maxTotalWriteBytes:
      maxCasBytes +
      packageMemberBytesTotal +
      installPlan.materializationTargets.filter(
        (targetValue) => targetValue.kind === "DIRECTORY",
      ).length * 4096 +
      maxJournalBytes,
    maxCreatedInodes: installPlan.materializationTargets.length + 3,
    hardTotalWriteCeilingBytes: 64 * 1024 * 1024,
    requiredFreeBytesAfter: 1024 * 1024 * 1024,
    requiredFreeInodesAfter: 10_000,
  };

  const backupSetId = h("backup-set");
  const backupManifestSha256 = h("backup-manifest");
  const backupArtifactSetSha256 = h("backup-artifact-set");
  const protectedArtifactSetSha256 = h("protected-artifact-set");
  const protectedArtifactCount = 173;
  const databaseSetSha256 = h("database-set");
  const databaseCount = 17;
  const retrievalReceiptArtifactSha256 = h("retrieval-receipt");
  const retrievedBytesSha256 = h("retrieved-backup-bytes");
  const restoreDrillArtifactSha256 = h("restore-drill");
  const offHostRetrieval = {
    backupSetId,
    backupManifestSha256,
    backupArtifactSetSha256,
    protectedArtifactSetSha256,
    protectedArtifactCount,
    retrievedBytesSha256,
    providerIdentity: "provider:offhost-backup-primary",
    retrievalReceiptArtifactSha256,
    retrievalStartedAt: times.retrievalStarted,
    retrievalCompletedAt: times.retrievalCompleted,
    lastVerifiedAt: times.retrievalVerified,
    verified: true,
  };
  const restoreDrill = {
    backupSetId,
    backupManifestSha256,
    backupArtifactSetSha256,
    expectedArtifactCount: protectedArtifactCount,
    restoredArtifactCount: protectedArtifactCount,
    restoredArtifactSetSha256: protectedArtifactSetSha256,
    manifestParity: true,
    restoredBytesSha256: retrievedBytesSha256,
    retrievalReceiptArtifactSha256,
    restoreDrillArtifactSha256,
    startedAt: times.restoreStarted,
    verifiedAt: times.restoreVerified,
    isolated: true,
    verified: true,
  };
  const databaseConsistency = {
    backupSetId,
    backupManifestSha256,
    backupArtifactSetSha256,
    expectedDatabaseCount: databaseCount,
    verifiedDatabaseCount: databaseCount,
    databaseSetSha256,
    databaseCatalogSha256: h("database-catalog"),
    restoredBytesSha256: retrievedBytesSha256,
    retrievalReceiptArtifactSha256,
    restoreDrillArtifactSha256,
    verificationArtifactSha256: h("database-consistency"),
    verifiedAt: times.databaseVerified,
    databasesConsistent: true,
  };
  const writeConsistency = {
    mode: "POINT_IN_TIME_SNAPSHOT",
    snapshotReceiptArtifactSha256: h("snapshot-receipt"),
    sourceWriteWatermarkSha256: h("source-write-watermark"),
    capturedAt: times.snapshotCaptured,
    verifiedAt: times.snapshotVerified,
    applicationDataMutationAuthority: false,
    continuedLiveWritesPreserved: true,
  };
  const tuple = {
    schema: "platform.v1-brownfield-preinstall-tuple/v1",
    transactionId: h("transaction"),
    candidate: {
      repository: candidate.repository,
      repositoryId: candidate.repositoryId,
      repositoryOwnerId: candidate.repositoryOwnerId,
      commitSha: candidate.commitSha,
      treeSha: candidate.treeSha,
      sourceArchiveSha256: candidate.sourceArchiveSha256,
    },
    strategy: "ADDITIVE",
    sourceTarget,
    activationTarget,
    identityTransition: null,
    phaseA: {
      authorizationEnvelopeSha256: phaseAAuthorizationArtifact.sha256,
      authorizedCandidate: structuredClone(candidate),
      authorizedCandidateSha256: shaCanonical(candidate),
      authorizedTarget: structuredClone(phaseATarget),
      authorizedTargetSha256: shaCanonical(phaseATarget),
      authorizationId: phaseAAuthorizationPayload.authorizationId,
      nonce: phaseAChallenge.nonce,
      orderContractId: order.id,
      orderContractSha256: order.sha256,
      scope: "READ_ONLY_LIVE_PREFLIGHT",
      issuedAt: times.authIssued,
      verifiedAt: times.authVerified,
      expiresAt: times.authExpires,
      policySha256: phaseAPolicyArtifact.sha256,
      verificationReceiptSha256: h("phase-a-verification-receipt"),
      packageAttestationEnvelopeSha256: phaseAPackageArtifact.sha256,
      packageAttestationId: phaseAPackagePayload.attestationId,
      packageAttestorKeyId: keys.packageAttestor.keyId,
      packagePayloadType: PHASE_A_PACKAGE_PAYLOAD_TYPE,
      authorizationPayloadType: PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
      authorizationProviderKeyId: keys.phaseAAuthorizationProvider.keyId,
      candidateClean: true,
      consumerChallengeSha256: shaCanonical(phaseAChallenge),
      futureRoleKeyIds,
      packageSha256: candidate.packageSha256,
      packageManifestSha256: candidate.packageManifestSha256,
      replayLedgerStatus: "EXTERNAL_PENDING",
    },
    baseline: {
      artifactSha256: h("baseline-artifact"),
      baselineId: h("baseline-id"),
      schema: "platform.live-preservation-baseline/v1",
      version: 1,
      classification: "COMPLETE-PRESERVATION-BASELINE",
      complete: true,
      deficiencies: [],
      sourceDeviceSetSha256: h("source-device-set"),
      sourceDeviceCount: 11,
      sourceDeviceIdentitiesComplete: true,
      protectedArtifactSetSha256,
      protectedArtifactCount,
      databaseSetSha256,
      databaseCount,
      captureStartedAt: times.baselineStarted,
      captureCompletedAt: times.baselineCompleted,
      verifiedAt: times.baselineVerified,
    },
    structuralBackupReceipt: {
      artifactSha256: h("structural-backup-receipt"),
      receiptId: h("structural-backup-receipt-id"),
      backupSetId,
      backupManifestSha256,
      backupArtifactSetSha256,
      protectedArtifactSetSha256,
      protectedArtifactCount,
      databaseSetSha256,
      databaseCount,
      schema: "platform.v1-predeploy-backup-receipt/v1",
      status: "REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE",
      authoritative: false,
      verifiedAt: times.structuralVerified,
    },
    authoritativeBackupAttestation: {
      evidenceArtifactSha256: h("authoritative-backup-evidence"),
      attestationId: h("authoritative-backup-attestation-id"),
      backupSetId,
      backupManifestSha256,
      backupArtifactSetSha256,
      protectedArtifactSetSha256,
      protectedArtifactCount,
      databaseSetSha256,
      databaseCount,
      offHost: true,
      sourceDeviceSetExcluded: true,
      captureStartedAt: times.backupStarted,
      captureCompletedAt: times.backupCompleted,
      verifiedAt: times.backupVerified,
      backupRootPath: "/mnt/offhost/platform-backup/transaction",
      backupDeviceIdentity: "device:offhost-backup-001",
      offHostRetrieval,
      restoreDrill,
      databaseConsistency,
      writeConsistency,
      backupTrustPolicySha256: policy.backupTrustPolicySha256,
      attestationIssuedAt: times.backupIssued,
      attestationExpiresAt: times.backupExpires,
    },
    installPlan,
    rollbackPolicy: {
      artifactSha256: h("rollback-policy"),
      policyId: h("rollback-policy-id"),
      codeRollbackAllowed: true,
      dataRollbackAuthority: false,
      requiresPostDeployPreservation: true,
      preserveNewWrites: true,
    },
  };
  const tupleSha256 = shaCanonical(tuple);
  const backupEvidence = {
    evidenceArtifactSha256:
      tuple.authoritativeBackupAttestation.evidenceArtifactSha256,
    structuralReceiptArtifactSha256:
      tuple.structuralBackupReceipt.artifactSha256,
    structuralReceiptId: tuple.structuralBackupReceipt.receiptId,
    structuralReceiptVerifiedAt: tuple.structuralBackupReceipt.verifiedAt,
    sourceDeviceSetSha256: tuple.baseline.sourceDeviceSetSha256,
    backupDeviceIdentity:
      tuple.authoritativeBackupAttestation.backupDeviceIdentity,
    backupSetId,
    backupManifestSha256,
    backupArtifactSetSha256,
    protectedArtifactSetSha256,
    protectedArtifactCount,
    databaseSetSha256,
    databaseCount,
    captureStartedAt: times.backupStarted,
    captureCompletedAt: times.backupCompleted,
    verifiedAt: times.backupVerified,
    offHost: true,
    sourceDeviceSetExcluded: true,
    offHostRetrieval,
    restoreDrill,
    databaseConsistency,
    writeConsistency,
    dataRollbackAuthority: false,
  };
  const backupPayload = {
    schema: "platform.v1-authoritative-backup-attestation/v1",
    attestationId: tuple.authoritativeBackupAttestation.attestationId,
    issuedAt: times.backupIssued,
    expiresAt: times.backupExpires,
    preinstallTuple: tuple,
    preinstallTupleSha256: tupleSha256,
    backupTrustPolicySha256: policy.backupTrustPolicySha256,
    producers: {
      backupAuthority: producers.backupAuthority,
      sourceTargetCustodian: producers.sourceTargetCustodian,
    },
    evidence: backupEvidence,
  };
  const backupAttestationArtifact = envelope(
    BACKUP_PAYLOAD_TYPE,
    backupPayload,
    [keys.backupAuthority, keys.sourceTargetCustodian],
  );

  const phaseBChallenge = {
    challengeId: h("phase-b-challenge-id"),
    consumerRepository: "independent-consumer/phase-b",
    consumerWorkflowPath: ".github/workflows/phase-b.yml",
    consumerJobWorkflowSha: "a".repeat(40),
    consumerJob: "verify-phase-b-preinstall",
    consumerRunId: "98765002",
    consumerRunAttempt: 1,
    nonce: nonce("phase-b"),
    replayDomain: PHASE_B_REPLAY_DOMAIN,
    issuedAt: times.phaseBChallenge,
    expiresAt: times.phaseBChallengeExpires,
    maxAgeSeconds: 600,
  };
  const preMutationAncestryVerification = {
    sourceParents: observedParents(
      installPlan.materializationPolicy.sourceParents,
      "source-cas",
    ),
    destinationParents: observedParents(
      installPlan.materializationPolicy.destinationParents,
      "destination",
    ),
    materializationPolicySha256:
      shaCanonical(installPlan.materializationPolicy),
    verificationReceiptSha256:
      h("pre-mutation-ancestry-verification-receipt"),
    verifiedAt: times.activationAttested,
  };
  preMutationAncestryVerification.destinationParents[0] =
    structuredClone(preMutationAncestryVerification.sourceParents[0]);
  const targetPreconditions = materializationPreconditions(
    installPlan.materializationTargets,
    preMutationAncestryVerification,
    times.activationAttested,
  );
  const resource = resourceObservation(
    installPlan,
    preMutationAncestryVerification,
    targetPreconditions,
    times.activationAttested,
  );
  const phaseBAuthorizationId = "phase-b-preinstall-authorization:001";
  const ledgerEntryKeySha256 = h([
    "phase-b-ledger-v1",
    phaseBAuthorizationId,
    phaseBChallenge.nonce,
    tuple.transactionId,
    policyArtifact.sha256,
    tupleSha256,
  ].join("\0"));
  const ledgerParent =
    preMutationAncestryVerification.sourceParents[2];
  const claimObjectPath =
    "/var/lib/.platform-v1-phase-b-claim-" + ledgerEntryKeySha256;
  const replayClaimPrecondition = {
    schema: "platform.v1-phase-b-replay-claim-precondition/v1",
    authorizationId: phaseBAuthorizationId,
    nonce: phaseBChallenge.nonce,
    policySha256: policyArtifact.sha256,
    preinstallTupleSha256: tupleSha256,
    ledgerEntryKeySha256,
    ledgerParentPath: "/var/lib",
    ledgerParentIdentitySha256: shaCanonical(ledgerParent),
    ledgerAncestrySha256: shaCanonical(
      preMutationAncestryVerification.sourceParents.slice(0, 3),
    ),
    claimObjectPath,
    claimNegativeLookupReceiptSha256:
      h("phase-b-claim-negative-lookup-receipt"),
    atomicCreateExclusiveRequired: true,
    claimFileFsyncRequired: true,
    claimParentFsyncRequired: true,
    openat2ResolveBeneathNoSymlinks: true,
    openat2ResolveNoXdev: true,
    verifiedAt: times.activationAttested,
  };
  const receiptObjectKeySha256 = h([
    "install-receipt-v1",
    installPlan.plannedReceiptId,
    tuple.transactionId,
  ].join("\0"));
  const phaseBPayload = {
    schema: "platform.v1-phase-b-preinstall-authorization/v1",
    version: 1,
    authorizationId: phaseBAuthorizationId,
    transactionId: tuple.transactionId,
    issuedAt: times.phaseBIssued,
    notBefore: times.phaseBIssued,
    expiresAt: times.phaseBExpires,
    policySha256: policyArtifact.sha256,
    preinstallTuple: tuple,
    preinstallTupleSha256: tupleSha256,
    installPlanSha256: shaCanonical(installPlan),
    installerBootstrapSha256: shaCanonical(installPlan.installerBootstrap),
    operationScope: {
      permitted: [...PERMITTED_OPERATIONS],
      forbidden: [...FORBIDDEN_OPERATIONS],
    },
    preMutationAncestryVerification,
    materializationPreconditions: targetPreconditions,
    materializationTargetPlanSha256:
      shaCanonical(installPlan.materializationTargets),
    packageInputObservation: {
      schema: "platform.v1-authenticated-package-input-observation/v1",
      transport: "AUTHENTICATED_READ_ONLY_FD",
      pathAccepted: false,
      readOnly: true,
      sealedAgainstMutation: true,
      packageBytesSha256: installPlan.packageBytesSha256,
      packageBytesSizeBytes: installPlan.packageBytesSizeBytes,
      manifestSha256: installPlan.packageManifestSha256,
      manifestSizeBytes: installPlan.packageManifestSizeBytes,
      descriptorIdentityReceiptSha256:
        h("package-input-descriptor-identity-receipt"),
      verifiedAt: times.activationAttested,
    },
    principalAccountObservation: {
      principalName: installPlan.privilegePolicy.principalName,
      principalUid: installPlan.privilegePolicy.principalUid,
      principalGid: installPlan.privilegePolicy.principalGid,
      accountLookupReceiptSha256:
        installPlan.privilegePolicy.principalAccountIdentityReceiptSha256,
      passwdEntryReceiptSha256:
        h("deployment-account-passwd-entry-receipt"),
      groupMembershipReceiptSha256:
        h("deployment-account-group-membership-receipt"),
      dockerSocketAclReceiptSha256:
        h("deployment-account-docker-socket-acl-receipt"),
      dockerSocketIdentity: {
        path: "/run/docker.sock",
        fileType: "SOCKET",
        symlink: false,
        descriptorNoFollow: true,
        nlink: 1,
        daemonId: activationTarget.dockerDaemonId,
        discoveredEndpoints: ["unix:///run/docker.sock"],
        principalAccessibleEndpoints: [],
        accessibleEndpointCount: 0,
        dockerHostEnvironmentAccepted: false,
        tcpEndpointsAccessible: false,
        parentAncestry: ["/", "/run"].map((pathname, index) => ({
          path: pathname,
          deviceIdentity: "device:docker-runtime-filesystem",
          filesystemUuid: h("docker-runtime-filesystem-uuid"),
          inode: String(90100 + index),
          mountId: "9010",
          uid: 0,
          gid: 0,
          mode: "0755",
          nlink: 2,
          symlink: false,
          writableByNonRoot: false,
        })),
        deviceIdentity: "device:docker-runtime-filesystem",
        filesystemUuid: h("docker-runtime-filesystem-uuid"),
        inode: "90001",
        mountId: "9010",
        uid: 0,
        gid: 999,
        mode: "0660",
        principalEffectiveAccess: false,
        aclArtifactSha256:
          h("deployment-account-docker-socket-acl-receipt"),
        ancestryVerificationReceiptSha256:
          h("docker-socket-ancestry-verification-receipt"),
        daemonProbeReceiptSha256: h("docker-daemon-id-probe-receipt"),
        descriptorIdentityReceiptSha256:
          h("docker-socket-descriptor-identity-receipt"),
        endpointEnumerationReceiptSha256:
          h("docker-endpoint-enumeration-receipt"),
      },
      capabilityReceiptSha256:
        h("deployment-account-capability-receipt"),
      effectiveSudoReceiptSha256:
        h("deployment-account-effective-sudo-receipt"),
      supplementaryGroups: [],
      dockerGroupMembership: false,
      dockerSocketAccess: false,
      rootEquivalentCapabilities: false,
      unrestrictedSudo: false,
      effectiveSudoCommands: [],
      preexisting: true,
      useraddForbidden: true,
      groupaddForbidden: true,
      verifiedAt: times.activationAttested,
    },
    resourceObservation: resource,
    replayClaimPrecondition,
    authoritativeBackup: {
      envelopeSha256: backupAttestationArtifact.sha256,
      payloadSha256: h(canonicalJson(backupPayload)),
      payloadType: BACKUP_PAYLOAD_TYPE,
      attestationId: backupPayload.attestationId,
      backupSetId,
      backupTrustPolicySha256: policy.backupTrustPolicySha256,
      backupAuthorityKeyId: keys.backupAuthority.keyId,
      sourceTargetCustodianKeyId: keys.sourceTargetCustodian.keyId,
      issuedAt: times.backupIssued,
      expiresAt: times.backupExpires,
    },
    consumerChallenge: phaseBChallenge,
    replayRequirements: {
      schema: "platform.v1-phase-b-replay-requirements/v1",
      ledgerId: "platform-v1-phase-b-installer-ledger",
      claimParentPath: "/var/lib",
      claimParentIdentitySha256:
        replayClaimPrecondition.ledgerParentIdentitySha256,
      claimAncestrySha256: replayClaimPrecondition.ledgerAncestrySha256,
      replayKeySha256: ledgerEntryKeySha256,
      claimObjectPath,
      claimNegativeLookupReceiptSha256:
        replayClaimPrecondition.claimNegativeLookupReceiptSha256,
      journalStorePath:
        "/var/lib/platform-infrastructure/v1-phase-b-ledger",
      journalRecordPath:
        "/var/lib/platform-infrastructure/v1-phase-b-ledger/" +
        ledgerEntryKeySha256 +
        ".json",
      receiptStorePath:
        "/var/lib/platform-infrastructure/v1-install-receipts/sha256",
      receiptObjectKeySha256,
      receiptObjectPath:
        "/var/lib/platform-infrastructure/v1-install-receipts/sha256/" +
        receiptObjectKeySha256 +
        ".json",
      priorState: "ABSENT_PROVEN",
      consumeBeforeFirstNonClaimMutation: true,
      atomicCreateExclusiveRequired: true,
      claimFileFsyncRequired: true,
      claimParentFsyncRequired: true,
      journalCreatedExclusiveRequired: true,
      receiptCreatedExclusiveRequired: true,
      failureStateTerminal: true,
      status: "EXTERNAL_PENDING",
    },
    producers: {
      phaseBInstaller: producers.phaseBInstaller,
      activationTargetRoot: producers.activationTargetRoot,
    },
    decision: "AUTHORIZE_EXACT_PREINSTALL_ONLY",
    installationAuthority: true,
    deploymentAuthority: false,
    activationAuthority: false,
    dataRollbackAuthority: false,
  };
  const authorizationArtifact = envelope(
    PHASE_B_PREINSTALL_PAYLOAD_TYPE,
    phaseBPayload,
    [keys.phaseBInstaller, keys.activationTargetRoot],
  );
  const expected = {
    schema: "platform.v1-phase-b-preinstall-expected/v1",
    policySha256: policyArtifact.sha256,
    phaseAPolicySha256: phaseAPolicyArtifact.sha256,
    phaseAPackageEnvelopeSha256: phaseAPackageArtifact.sha256,
    phaseAAuthorizationEnvelopeSha256: phaseAAuthorizationArtifact.sha256,
    backupAttestationEnvelopeSha256: backupAttestationArtifact.sha256,
    phaseBPreinstallEnvelopeSha256: authorizationArtifact.sha256,
    installPlanSchemaSha256: policy.installPlanSchemaSha256,
    roleKeyIds: Object.fromEntries(
      ROLE_NAMES.map((role) => [role, keys[role].keyId]),
    ),
    preinstallTupleSha256: tupleSha256,
    transactionId: tuple.transactionId,
    authorizationId: phaseBPayload.authorizationId,
    challengeNonce: phaseBChallenge.nonce,
  };
  return {
    now,
    keys,
    constraints,
    producers,
    policy,
    policyArtifact,
    phaseAPolicy,
    phaseAPolicyArtifact,
    phaseAPackagePayload,
    phaseAPackageArtifact,
    phaseAAuthorizationPayload,
    phaseAAuthorizationArtifact,
    tuple,
    backupPayload,
    backupAttestationArtifact,
    phaseBPayload,
    authorizationArtifact,
    expected,
  };
}

function signCurrentPhaseB(fixture) {
  fixture.authorizationArtifact = envelope(
    PHASE_B_PREINSTALL_PAYLOAD_TYPE,
    fixture.phaseBPayload,
    [fixture.keys.phaseBInstaller, fixture.keys.activationTargetRoot],
  );
  fixture.expected.phaseBPreinstallEnvelopeSha256 =
    fixture.authorizationArtifact.sha256;
}

function resignPhaseB(fixture) {
  fixture.phaseBPayload.installPlanSha256 = shaCanonical(
    fixture.phaseBPayload.preinstallTuple.installPlan,
  );
  fixture.phaseBPayload.installerBootstrapSha256 = shaCanonical(
    fixture.phaseBPayload.preinstallTuple.installPlan.installerBootstrap,
  );
  fixture.phaseBPayload.preMutationAncestryVerification
    .materializationPolicySha256 = shaCanonical(
      fixture.phaseBPayload.preinstallTuple.installPlan.materializationPolicy,
    );
  fixture.phaseBPayload.materializationTargetPlanSha256 = shaCanonical(
    fixture.phaseBPayload.preinstallTuple.installPlan.materializationTargets,
  );
  signCurrentPhaseB(fixture);
}

function rebindReplay(fixture) {
  const payload = fixture.phaseBPayload;
  const tupleSha256 = payload.preinstallTupleSha256;
  const replayKeySha256 = h([
    "phase-b-ledger-v1",
    payload.authorizationId,
    payload.consumerChallenge.nonce,
    payload.transactionId,
    payload.policySha256,
    tupleSha256,
  ].join("\0"));
  const claimObjectPath =
    "/var/lib/.platform-v1-phase-b-claim-" + replayKeySha256;
  Object.assign(payload.replayClaimPrecondition, {
    authorizationId: payload.authorizationId,
    nonce: payload.consumerChallenge.nonce,
    policySha256: payload.policySha256,
    preinstallTupleSha256: tupleSha256,
    ledgerEntryKeySha256: replayKeySha256,
    claimObjectPath,
  });
  Object.assign(payload.replayRequirements, {
    claimParentPath: payload.replayClaimPrecondition.ledgerParentPath,
    claimParentIdentitySha256:
      payload.replayClaimPrecondition.ledgerParentIdentitySha256,
    claimAncestrySha256:
      payload.replayClaimPrecondition.ledgerAncestrySha256,
    replayKeySha256,
    claimObjectPath,
    claimNegativeLookupReceiptSha256:
      payload.replayClaimPrecondition.claimNegativeLookupReceiptSha256,
    journalRecordPath:
      "/var/lib/platform-infrastructure/v1-phase-b-ledger/" +
      replayKeySha256 +
      ".json",
  });
}

function synchronizeBackupProjection(fixture) {
  const tuple = fixture.phaseBPayload.preinstallTuple;
  const evidence = fixture.backupPayload.evidence;
  const attestation = tuple.authoritativeBackupAttestation;
  const structural = tuple.structuralBackupReceipt;
  Object.assign(evidence, {
    evidenceArtifactSha256: attestation.evidenceArtifactSha256,
    structuralReceiptArtifactSha256: structural.artifactSha256,
    structuralReceiptId: structural.receiptId,
    structuralReceiptVerifiedAt: structural.verifiedAt,
    sourceDeviceSetSha256: tuple.baseline.sourceDeviceSetSha256,
    backupDeviceIdentity: attestation.backupDeviceIdentity,
    backupSetId: attestation.backupSetId,
    backupManifestSha256: attestation.backupManifestSha256,
    backupArtifactSetSha256: attestation.backupArtifactSetSha256,
    protectedArtifactSetSha256: attestation.protectedArtifactSetSha256,
    protectedArtifactCount: attestation.protectedArtifactCount,
    databaseSetSha256: attestation.databaseSetSha256,
    databaseCount: attestation.databaseCount,
    captureStartedAt: attestation.captureStartedAt,
    captureCompletedAt: attestation.captureCompletedAt,
    verifiedAt: attestation.verifiedAt,
    offHost: attestation.offHost,
    sourceDeviceSetExcluded: attestation.sourceDeviceSetExcluded,
    offHostRetrieval: attestation.offHostRetrieval,
    restoreDrill: attestation.restoreDrill,
    databaseConsistency: attestation.databaseConsistency,
    writeConsistency: attestation.writeConsistency,
    dataRollbackAuthority: false,
  });
}

function resignBackupAndPhaseB(fixture) {
  fixture.phaseBPayload.preinstallTupleSha256 = shaCanonical(
    fixture.phaseBPayload.preinstallTuple,
  );
  fixture.expected.preinstallTupleSha256 =
    fixture.phaseBPayload.preinstallTupleSha256;
  fixture.backupPayload.preinstallTupleSha256 =
    fixture.phaseBPayload.preinstallTupleSha256;
  fixture.backupPayload.preinstallTuple =
    fixture.phaseBPayload.preinstallTuple;
  synchronizeBackupProjection(fixture);
  fixture.backupAttestationArtifact = envelope(
    BACKUP_PAYLOAD_TYPE,
    fixture.backupPayload,
    [fixture.keys.backupAuthority, fixture.keys.sourceTargetCustodian],
  );
  fixture.phaseBPayload.authoritativeBackup.envelopeSha256 =
    fixture.backupAttestationArtifact.sha256;
  fixture.phaseBPayload.authoritativeBackup.payloadSha256 =
    h(canonicalJson(fixture.backupPayload));
  fixture.phaseBPayload.authoritativeBackup.issuedAt =
    fixture.backupPayload.issuedAt;
  fixture.phaseBPayload.authoritativeBackup.expiresAt =
    fixture.backupPayload.expiresAt;
  fixture.expected.backupAttestationEnvelopeSha256 =
    fixture.backupAttestationArtifact.sha256;
  rebindReplay(fixture);
  resignPhaseB(fixture);
}

function verify(fixture) {
  return verifyV1PhaseBPreinstallAuthorization({
    policyArtifact: fixture.policyArtifact,
    phaseAPolicyArtifact: fixture.phaseAPolicyArtifact,
    phaseAPackageArtifact: fixture.phaseAPackageArtifact,
    phaseAAuthorizationArtifact: fixture.phaseAAuthorizationArtifact,
    backupAttestationArtifact: fixture.backupAttestationArtifact,
    authorizationArtifact: fixture.authorizationArtifact,
    expected: fixture.expected,
    now: fixture.now,
  });
}

function resignRawBackup(fixture) {
  fixture.backupAttestationArtifact = envelope(
    BACKUP_PAYLOAD_TYPE,
    fixture.backupPayload,
    [fixture.keys.backupAuthority, fixture.keys.sourceTargetCustodian],
  );
  fixture.phaseBPayload.authoritativeBackup.envelopeSha256 =
    fixture.backupAttestationArtifact.sha256;
  fixture.phaseBPayload.authoritativeBackup.payloadSha256 =
    h(canonicalJson(fixture.backupPayload));
  fixture.phaseBPayload.authoritativeBackup.issuedAt =
    fixture.backupPayload.issuedAt;
  fixture.phaseBPayload.authoritativeBackup.expiresAt =
    fixture.backupPayload.expiresAt;
  fixture.expected.backupAttestationEnvelopeSha256 =
    fixture.backupAttestationArtifact.sha256;
  resignPhaseB(fixture);
}

function materializeCliFixture(fixture, directory) {
  const artifacts = {
    authorization: fixture.authorizationArtifact.bytes,
    "backup-attestation": fixture.backupAttestationArtifact.bytes,
    expected: canonicalArtifact(fixture.expected).bytes,
    "phase-a-authorization": fixture.phaseAAuthorizationArtifact.bytes,
    "phase-a-package-attestation": fixture.phaseAPackageArtifact.bytes,
    "phase-a-policy": fixture.phaseAPolicyArtifact.bytes,
    policy: fixture.policyArtifact.bytes,
  };
  const paths = {};
  for (const [name, bytes] of Object.entries(artifacts)) {
    const pathname = path.join(directory, name + ".json");
    fs.writeFileSync(pathname, bytes, { mode: 0o600, flag: "wx" });
    paths[name] = pathname;
  }
  return paths;
}

function cliArgs(paths) {
  return [
    MODULE,
    "--authorization", paths.authorization,
    "--backup-attestation", paths["backup-attestation"],
    "--expected", paths.expected,
    "--phase-a-authorization", paths["phase-a-authorization"],
    "--phase-a-package-attestation", paths["phase-a-package-attestation"],
    "--phase-a-policy", paths["phase-a-policy"],
    "--policy", paths.policy,
  ];
}

test("valid independently signed artifacts remain verify-only and STOP", () => {
  const fixture = buildFixture();
  const result = verify(fixture);
  assert.equal(result.status, "SIGNATURE_VERIFIED_NON_AUTHORITATIVE");
  assert.equal(result.effect, "STOP");
  assert.equal(result.authoritativeEvidence, false);
  assert.equal(result.localMutationAuthority, false);
  assert.equal(result.installationAuthorized, false);
  assert.equal(result.deploymentAuthorized, false);
  assert.equal(result.activationAuthorized, false);
  assert.equal(result.dataRollbackAuthorized, false);
  assert.equal(result.replayLedgerStatus, "EXTERNAL_PENDING");
  assert.equal(result.replayVerified, false);
  assert.equal(result.packageMaterializationStatus, "EXTERNAL_PENDING");
  assert.equal(result.packageMaterializationVerified, false);
  for (const field of [
    "rawBaselineVerificationStatus",
    "rawBackupReceiptVerificationStatus",
    "sourceSetRecomputationStatus",
    "offHostSourceDeviceExclusionVerificationStatus",
    "restoredCoverageRecomputationStatus",
    "databaseCoverageRecomputationStatus",
    "protectedPathOverlapVerificationStatus",
    "packageArchiveFormatVerificationStatus",
    "packageManifestMemberExtractionVerificationStatus",
    "replayArtifactByteSchemaVerificationStatus",
    "consumerChallengeAuthorityStatus",
    "expectedBindingsAuthorityStatus",
  ]) {
    assert.equal(result[field], "EXTERNAL_ROOT_CONSUMER_REQUIRED", field);
  }
  for (const field of [
    "rawBaselineReopened",
    "rawStructuralBackupReceiptReopened",
    "sourceDeviceSetRecomputed",
    "offHostSourceDeviceExclusionRecomputed",
    "restoredCoverageRecomputed",
    "databaseCoverageRecomputed",
    "protectedPathSetRecomputed",
    "allInstallWritesDisjointFromProtectedPaths",
    "packageArchiveFormatVerified",
    "packageManifestMembersRecomputed",
    "replayClaimBytesSchemaVerified",
    "replayJournalBytesSchemaVerified",
    "installExecutionReceiptBytesSchemaVerified",
    "consumerChallengeAuthorityVerified",
    "expectedBindingsAuthorityVerified",
    "stdoutAuthority",
    "liveAuthorization",
    "mutationAuthority",
  ]) {
    assert.equal(result[field], false, field);
  }
  assert.equal(result.trustedNativeLauncherRequired, true);
  assert.equal(
    result.sourceDeviceSetSha256,
    fixture.tuple.baseline.sourceDeviceSetSha256,
  );
  assert.equal(result.sourceDeviceCount, fixture.tuple.baseline.sourceDeviceCount);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.permittedOperations), true);
  assert.deepEqual(result.permittedOperations, PERMITTED_OPERATIONS);
  assert.deepEqual(result.forbiddenOperations, FORBIDDEN_OPERATIONS);
});

test("install-plan/v2 and preinstall tuple validate through the exported boundary", () => {
  const fixture = buildFixture();
  const installPlan = validateInstallPlanV2(fixture.tuple.installPlan);
  assert.deepEqual(installPlan, fixture.tuple.installPlan);
  assert.equal(Object.isFrozen(installPlan), true);
  assert.deepEqual(validatePreinstallTuple(fixture.tuple), fixture.tuple);
});

test("future install receipt fields cannot enter or alter PREINSTALL bytes", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.preinstallTuple.installReceipt = {
    artifactSha256: h("future-install-receipt"),
  };
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /exact closed schema/);
});

test("future final challenge and provider gates cannot enter the PREINSTALL payload", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.finalChallenge = { nonce: nonce("future") };
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /exact closed schema/);
});

test("raw Phase-A package envelope substitution is rejected", () => {
  const fixture = buildFixture();
  const substituted = h("substituted-envelope");
  fixture.phaseBPayload.preinstallTuple.phaseA
    .packageAttestationEnvelopeSha256 = substituted;
  fixture.phaseBPayload.preinstallTuple.installPlan
    .packageAttestationEnvelopeSha256 = substituted;
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /exact raw Phase-A artifacts/);
});

test("raw Phase-A authorization context divergence is rejected", () => {
  const fixture = buildFixture();
  fixture.phaseAAuthorizationPayload.candidate.treeSha = "5".repeat(40);
  fixture.phaseAAuthorizationArtifact = envelope(
    PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
    fixture.phaseAAuthorizationPayload,
    [fixture.keys.phaseAAuthorizationProvider],
  );
  assert.throws(() => verify(fixture), /do not share one exact context/);
});

test("raw backup envelope substitution is rejected", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.authoritativeBackup.envelopeSha256 =
    h("substituted-backup");
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /exact raw backup envelope/);
});

test("one backup signature cannot satisfy the dual-role contract", () => {
  const fixture = buildFixture();
  fixture.backupAttestationArtifact = envelope(
    BACKUP_PAYLOAD_TYPE,
    fixture.backupPayload,
    [fixture.keys.backupAuthority],
  );
  assert.throws(() => verify(fixture), /exactly 2 entries/);
});

test("swapped Phase-B signer roles are rejected", () => {
  const fixture = buildFixture();
  fixture.authorizationArtifact = envelope(
    PHASE_B_PREINSTALL_PAYLOAD_TYPE,
    fixture.phaseBPayload,
    [fixture.keys.activationTargetRoot, fixture.keys.phaseBInstaller],
  );
  assert.throws(() => verify(fixture), /signature role\/order is invalid/);
});

test("cross-contract role-key reuse is rejected before signatures", () => {
  const fixture = buildFixture();
  fixture.expected.roleKeyIds.phaseBInstaller =
    fixture.expected.roleKeyIds.packageAttestor;
  assert.throws(() => verify(fixture), /pairwise distinct/);
});

test("private-key PEM cannot be imported as a policy root", () => {
  const fixture = buildFixture();
  fixture.policy.roles.phaseBInstaller.publicKeySpkiPem =
    fixture.keys.phaseBInstaller.privateKey.export({
      type: "pkcs8",
      format: "pem",
    });
  fixture.policyArtifact = canonicalArtifact(fixture.policy);
  fixture.expected.policySha256 = fixture.policyArtifact.sha256;
  assert.throws(() => verify(fixture), /SPKI public-key PEM/);
});

test("candidate-controlled provider repository is rejected", () => {
  const fixture = buildFixture();
  fixture.policy.roles.phaseBInstaller.producerConstraints.repositoryId =
    fixture.phaseBPayload.preinstallTuple.candidate.repositoryId;
  fixture.phaseBPayload.producers.phaseBInstaller.repositoryId =
    fixture.phaseBPayload.preinstallTuple.candidate.repositoryId;
  fixture.policyArtifact = canonicalArtifact(fixture.policy);
  fixture.expected.policySha256 = fixture.policyArtifact.sha256;
  fixture.phaseBPayload.policySha256 = fixture.policyArtifact.sha256;
  fixture.phaseBPayload.preinstallTuple.installPlan.installerBootstrap
    .trustPolicySha256 = fixture.policyArtifact.sha256;
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /candidate-repository controlled/);
});

test("six future external authorities are independent by repository identity", () => {
  for (const field of ["repository", "repositoryId", "repositoryOwnerId"]) {
    const fixture = buildFixture();
    fixture.policy.roles.deploymentGate.producerConstraints[field] =
      fixture.policy.roles.hostedGate.producerConstraints[field];
    fixture.policyArtifact = canonicalArtifact(fixture.policy);
    fixture.expected.policySha256 = fixture.policyArtifact.sha256;
    assert.throws(
      () => verify(fixture),
      /future authority .* must be pairwise distinct/i,
      field,
    );
  }
});

test("typed install artifact hash reuse is rejected", () => {
  const fixture = buildFixture();
  const installPlan = fixture.phaseBPayload.preinstallTuple.installPlan;
  installPlan.broker.sha256 = installPlan.verifier.sha256;
  installPlan.materializationTargets.find((targetValue) =>
    targetValue.path === installPlan.broker.path).sha256 =
      installPlan.verifier.sha256;
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /artifact hashes.*pairwise distinct/i);
});

test("package/manifest candidate mismatch is rejected", () => {
  const fixture = buildFixture();
  const changed = h("different-package");
  fixture.phaseBPayload.preinstallTuple.installPlan.packageBytesSha256 = changed;
  fixture.phaseBPayload.preinstallTuple.installPlan.materializationPolicy.casRoot =
    "/var/lib/platform-infrastructure/v1-package-cas/sha256/" + changed;
  fixture.phaseBPayload.preinstallTuple.installPlan.materializationPolicy
    .sourceParents.at(-1).path =
      fixture.phaseBPayload.preinstallTuple.installPlan.materializationPolicy.casRoot;
  resignBackupAndPhaseB(fixture);
  assert.throws(
    () => verify(fixture),
    /Install plan package bytes.*differ from Phase A/,
  );
});

test("bootstrap trust policy cannot differ from Phase-B policy", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.preinstallTuple.installPlan.installerBootstrap
    .trustPolicySha256 = h("different-trust-policy");
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /trust-policy\/schema pins diverge/);
});

test("bootstrap cannot lose its independent preexisting pin", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.preinstallTuple.installPlan.installerBootstrap
    .independentlyPinned = false;
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /bootstrap identity is invalid|independently pinned/);
});

test("pre-mutation observation cannot claim a local runtime recheck", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.preMutationAncestryVerification.runtimeRecheckStatus =
    "VERIFIED";
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /exact closed schema/);
});

test("all seven canonical Phase-B evidence projections are signed and mandatory", () => {
  const evidenceKeys = [
    "materializationPreconditions",
    "materializationTargetPlanSha256",
    "packageInputObservation",
    "preMutationAncestryVerification",
    "principalAccountObservation",
    "replayClaimPrecondition",
    "resourceObservation",
  ];
  for (const key of evidenceKeys) {
    const fixture = buildFixture();
    delete fixture.phaseBPayload[key];
    signCurrentPhaseB(fixture);
    assert.throws(() => verify(fixture), /exact closed schema/, key);
  }
});

test("signed ancestry cannot alias the preserved source root filesystem object", () => {
  const fixture = buildFixture();
  const ancestry = fixture.phaseBPayload.preMutationAncestryVerification;
  const alias = ancestry.destinationParents.find((entry) =>
    entry.path === "/usr/local/libexec");
  const sourceIdentity = fixture.phaseBPayload.preinstallTuple.sourceTarget
    .rootIdentity;
  Object.assign(alias, {
    deviceIdentity: sourceIdentity.deviceIdentity,
    filesystemUuid: sourceIdentity.filesystemUuid,
    inode: sourceIdentity.inode,
  });
  for (const precondition of fixture.phaseBPayload.materializationPreconditions) {
    if (precondition.anchorPath === alias.path) {
      precondition.anchorIdentitySha256 = shaCanonical(alias);
    }
  }
  fixture.phaseBPayload.resourceObservation = resourceObservation(
    fixture.phaseBPayload.preinstallTuple.installPlan,
    ancestry,
    fixture.phaseBPayload.materializationPreconditions,
    ancestry.verifiedAt,
  );
  resignPhaseB(fixture);
  assert.throws(
    () => verify(fixture),
    /filesystem object graph exposes one filesystem object at multiple paths/,
  );
});

test("ADDITIVE source and activation roots must be distinct and non-nested", () => {
  for (const sourceRoot of [
    "/srv/platform-infrastructure",
    "/srv/platform-infrastructure/legacy",
  ]) {
    const fixture = buildFixture();
    fixture.phaseBPayload.preinstallTuple.sourceTarget.root = sourceRoot;
    fixture.phaseBPayload.preinstallTuple.sourceTarget.rootParentPath =
      path.posix.dirname(sourceRoot);
    resignBackupAndPhaseB(fixture);
    assert.throws(
      () => verify(fixture),
      /non-destructive ADDITIVE|distinct non-overlapping activation root/i,
      sourceRoot,
    );
  }
});

test("resource observations bind free bytes, free inodes, and mount identities", () => {
  for (const mutation of [
    (device) => {
      device.freeBytes = device.plannedWriteBytes + device.requiredFreeBytesAfter - 1;
    },
    (device) => {
      device.freeInodes =
        device.plannedCreatedInodes + device.requiredFreeInodesAfter - 1;
    },
    (device) => {
      device.mountIds = ["999999"];
    },
  ]) {
    const fixture = buildFixture();
    mutation(fixture.phaseBPayload.resourceObservation.devices[0]);
    resignPhaseB(fixture);
    assert.throws(
      () => verify(fixture),
      /resource observation|free bytes|free inodes|mount/i,
    );
  }
});

test("target ancestry/no-follow requirements are closed and mandatory", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.preinstallTuple.installPlan.materializationPolicy
    .openatNoFollowRequired = false;
  resignBackupAndPhaseB(fixture);
  assert.throws(
    () => verify(fixture),
    /derived fixed CAS root and descriptor-relative no-follow policy/,
  );
});

test("Phase-B nonce cannot reuse Phase-A nonce", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.consumerChallenge.nonce =
    fixture.phaseBPayload.preinstallTuple.phaseA.nonce;
  fixture.expected.challengeNonce =
    fixture.phaseBPayload.consumerChallenge.nonce;
  rebindReplay(fixture);
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /replay identifiers must be distinct/);
});

test("replay requirements cannot claim local consumption", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.replayRequirements.status = "CONSUMED";
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /fail-closed one-shot replay contract/);
});

test("baseline verification after Phase-A expiry is rejected", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.preinstallTuple.baseline.verifiedAt =
    at(Date.parse(fixture.phaseBPayload.preinstallTuple.phaseA.expiresAt), 1000);
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /Preinstall causal timestamps violate/);
});

test("stale Phase-B authorization is rejected", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.issuedAt = at(fixture.now, -600000);
  fixture.phaseBPayload.notBefore = fixture.phaseBPayload.issuedAt;
  fixture.phaseBPayload.expiresAt = at(fixture.now, -300000);
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /freshness are invalid/);
});

test("expired backup cannot authorize installation", () => {
  const fixture = buildFixture();
  fixture.backupPayload.expiresAt = at(fixture.now, -1);
  fixture.phaseBPayload.authoritativeBackup.expiresAt =
    fixture.backupPayload.expiresAt;
  fixture.backupAttestationArtifact = envelope(
    BACKUP_PAYLOAD_TYPE,
    fixture.backupPayload,
    [fixture.keys.backupAuthority, fixture.keys.sourceTargetCustodian],
  );
  fixture.phaseBPayload.authoritativeBackup.envelopeSha256 =
    fixture.backupAttestationArtifact.sha256;
  fixture.phaseBPayload.authoritativeBackup.payloadSha256 =
    h(canonicalJson(fixture.backupPayload));
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /freshness are invalid/);
});

test("authorization expiry cannot exceed the consumer challenge expiry", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.consumerChallenge.expiresAt = at(fixture.now, 200000);
  fixture.phaseBPayload.expiresAt = at(fixture.now, 201000);
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /freshness are invalid/);
});

test("an expired consumer challenge fails even while authorization is unexpired", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.consumerChallenge.expiresAt = at(fixture.now, -1);
  fixture.phaseBPayload.expiresAt = at(fixture.now, 10000);
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /freshness are invalid/);
});

test("authorization expiry cannot exceed the authoritative backup expiry", () => {
  const fixture = buildFixture();
  const backupExpiry = at(fixture.now, 200000);
  fixture.backupPayload.expiresAt = backupExpiry;
  fixture.phaseBPayload.preinstallTuple.authoritativeBackupAttestation
    .attestationExpiresAt = backupExpiry;
  fixture.phaseBPayload.expiresAt = at(fixture.now, 201000);
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /freshness are invalid/);
});

test("signed observations are contained between challenge issue and authorization issue", () => {
  const beforeChallenge = buildFixture();
  beforeChallenge.phaseBPayload.packageInputObservation.verifiedAt = at(
    Date.parse(beforeChallenge.phaseBPayload.consumerChallenge.issuedAt),
    -1,
  );
  resignPhaseB(beforeChallenge);
  assert.throws(() => verify(beforeChallenge), /freshness are invalid/);

  const afterAuthorization = buildFixture();
  afterAuthorization.phaseBPayload.resourceObservation.observedAt = at(
    Date.parse(afterAuthorization.phaseBPayload.issuedAt),
    1,
  );
  resignPhaseB(afterAuthorization);
  assert.throws(() => verify(afterAuthorization), /freshness are invalid/);
});

test("authoritative backup issuance must not follow challenge issuance", () => {
  const fixture = buildFixture();
  const issuedAfterChallenge = at(
    Date.parse(fixture.phaseBPayload.consumerChallenge.issuedAt),
    1,
  );
  fixture.backupPayload.issuedAt = issuedAfterChallenge;
  fixture.phaseBPayload.preinstallTuple.authoritativeBackupAttestation
    .attestationIssuedAt = issuedAfterChallenge;
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /freshness are invalid/);
});

test("challenge, authorization, and backup expiry boundaries are half-open", () => {
  for (const expiry of [
    (fixture) => fixture.phaseBPayload.consumerChallenge.expiresAt,
    (fixture) => fixture.phaseBPayload.expiresAt,
    (fixture) => fixture.phaseBPayload.authoritativeBackup.expiresAt,
  ]) {
    const fixture = buildFixture();
    fixture.now = Date.parse(expiry(fixture));
    assert.throws(() => verify(fixture), /freshness are invalid/);
  }
});

test("structural receipt remains non-authoritative", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.preinstallTuple.structuralBackupReceipt.authoritative =
    true;
  resignBackupAndPhaseB(fixture);
  assert.throws(() => verify(fixture), /explicitly non-authoritative/);
});

test("backup evidence cannot grant data rollback authority", () => {
  const fixture = buildFixture();
  fixture.backupPayload.evidence.dataRollbackAuthority = true;
  fixture.backupAttestationArtifact = envelope(
    BACKUP_PAYLOAD_TYPE,
    fixture.backupPayload,
    [fixture.keys.backupAuthority, fixture.keys.sourceTargetCustodian],
  );
  fixture.phaseBPayload.authoritativeBackup.envelopeSha256 =
    fixture.backupAttestationArtifact.sha256;
  fixture.phaseBPayload.authoritativeBackup.payloadSha256 =
    h(canonicalJson(fixture.backupPayload));
  fixture.expected.backupAttestationEnvelopeSha256 =
    fixture.backupAttestationArtifact.sha256;
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /no data rollback|canonical preinstall backup binding/);
});

test("raw backup coverage set and count fields are mandatory", () => {
  for (const field of [
    "protectedArtifactSetSha256",
    "protectedArtifactCount",
    "databaseSetSha256",
    "databaseCount",
  ]) {
    const fixture = buildFixture();
    delete fixture.backupPayload.evidence[field];
    resignRawBackup(fixture);
    assert.throws(
      () => verify(fixture),
      /authoritative backup (?:payload )?evidence.*exact closed schema/i,
      field,
    );
  }
});

test("retrieval, restore, and database coverage digests cannot diverge", () => {
  for (const mutate of [
    (fixture) => {
      fixture.phaseBPayload.preinstallTuple.authoritativeBackupAttestation
        .offHostRetrieval.protectedArtifactSetSha256 = h("divergent-retrieval-set");
    },
    (fixture) => {
      fixture.phaseBPayload.preinstallTuple.authoritativeBackupAttestation
        .restoreDrill.restoredArtifactCount += 1;
    },
    (fixture) => {
      fixture.phaseBPayload.preinstallTuple.authoritativeBackupAttestation
        .databaseConsistency.databaseSetSha256 = h("divergent-database-set");
    },
  ]) {
    const fixture = buildFixture();
    mutate(fixture);
    resignBackupAndPhaseB(fixture);
    assert.throws(
      () => verify(fixture),
      /retrieval|restore|database|coverage|canonical preinstall backup/i,
    );
  }
});

test("operation scope cannot add Docker, replace, prune, or teardown permission", () => {
  const fixture = buildFixture();
  fixture.phaseBPayload.operationScope.permitted.push("DOCKER_OPERATION");
  resignPhaseB(fixture);
  assert.throws(() => verify(fixture), /exact closed sequence/);
});

test("schemas and deny-only template are parseable and closed to authority", () => {
  for (const schemaPath of SCHEMAS) {
    const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  }
  const pending = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  assert.equal(pending.status, "EXTERNAL-PENDING");
  assert.equal(pending.authoritativeEvidence, false);
  assert.equal(pending.localMutationAuthority, false);
  assert.equal(pending.trustAnchorProvenance, "NOT_CONFIGURED");
  for (const role of ROLE_NAMES) {
    assert.equal(pending.roles[role].keyId, null);
    assert.equal(pending.roles[role].publicKeySpkiPem, null);
    assert.equal(pending.roles[role].producerConstraints, null);
  }
});

test("strict Ajv closure accepts the real policy, plan, payload, and STOP output", () => {
  const fixture = buildFixture();
  const result = verify(fixture);
  const commonSchema = JSON.parse(fs.readFileSync(COMMON_SCHEMA, "utf8"));
  const policySchema = JSON.parse(fs.readFileSync(POLICY_SCHEMA, "utf8"));
  const installPlanSchema = JSON.parse(
    fs.readFileSync(INSTALL_PLAN_SCHEMA, "utf8"),
  );
  const authorizationSchema = JSON.parse(
    fs.readFileSync(AUTHORIZATION_SCHEMA, "utf8"),
  );

  const policyAjv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: true,
  });
  addFormats(policyAjv);
  const validatePolicySchema = policyAjv.compile(policySchema);
  assert.equal(
    validatePolicySchema(fixture.policy),
    true,
    JSON.stringify(validatePolicySchema.errors),
  );
  const pendingPolicy = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  assert.equal(
    validatePolicySchema(pendingPolicy),
    true,
    JSON.stringify(validatePolicySchema.errors),
  );

  const closureAjv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: true,
  });
  addFormats(closureAjv);
  closureAjv.addSchema(commonSchema);
  const validateInstallPlanSchema = closureAjv.compile(installPlanSchema);
  closureAjv.addSchema(authorizationSchema);
  const validateAuthorizationSchema = closureAjv.getSchema(
    authorizationSchema.$id,
  );
  const validateOutputSchema = closureAjv.getSchema(
    authorizationSchema.$id + "#/$defs/verificationOutput",
  );
  assert.equal(
    validateInstallPlanSchema(fixture.tuple.installPlan),
    true,
    JSON.stringify(validateInstallPlanSchema.errors),
  );
  assert.equal(
    validateAuthorizationSchema(fixture.phaseBPayload),
    true,
    JSON.stringify(validateAuthorizationSchema.errors),
  );
  assert.equal(
    validateOutputSchema(result),
    true,
    JSON.stringify(validateOutputSchema.errors),
  );
  assert.deepEqual(
    [...authorizationSchema.$defs.verificationOutput.required].sort(),
    Object.keys(authorizationSchema.$defs.verificationOutput.properties).sort(),
  );
  assert.deepEqual(
    Object.keys(result).sort(),
    [...authorizationSchema.$defs.verificationOutput.required].sort(),
  );

  const missingOutput = structuredClone(result);
  delete missingOutput.rawBaselineReopened;
  assert.equal(validateOutputSchema(missingOutput), false);
  const changedAuthority = structuredClone(result);
  changedAuthority.mutationAuthority = true;
  assert.equal(validateOutputSchema(changedAuthority), false);
  const addedOutput = structuredClone(result);
  addedOutput.futureAuthority = true;
  assert.equal(validateOutputSchema(addedOutput), false);

  const swappedPolicy = structuredClone(fixture.policy);
  [
    swappedPolicy.roles.hostedGate,
    swappedPolicy.roles.deploymentGate,
  ] = [
    swappedPolicy.roles.deploymentGate,
    swappedPolicy.roles.hostedGate,
  ];
  assert.equal(validatePolicySchema(swappedPolicy), false);
  const missingEvidence = structuredClone(fixture.phaseBPayload);
  delete missingEvidence.resourceObservation;
  assert.equal(validateAuthorizationSchema(missingEvidence), false);
});

test("policy and challenge schema primitives match runtime canonical bounds", () => {
  const commonSchema = JSON.parse(fs.readFileSync(COMMON_SCHEMA, "utf8"));
  const policySchema = JSON.parse(fs.readFileSync(POLICY_SCHEMA, "utf8"));
  const authorizationSchema = JSON.parse(
    fs.readFileSync(AUTHORIZATION_SCHEMA, "utf8"),
  );
  const policyAjv = new Ajv2020({ allErrors: true, strict: true });
  const validatePolicySchema = policyAjv.compile(policySchema);
  const closureAjv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(closureAjv);
  closureAjv.addSchema(commonSchema);
  const validateAuthorizationSchema = closureAjv.compile(authorizationSchema);

  const unsafePolicy = buildFixture().policy;
  unsafePolicy.roles.hostedGate.producerConstraints.repositoryId =
    "9007199254740992";
  assert.equal(validatePolicySchema(unsafePolicy), false);
  for (const badEndpoint of [
    "ssh://deploy@Platform.example.test:70000",
    "ssh://deploy@localhost:22",
    "ssh://deploy@" + "a.".repeat(160) + "test:22",
  ]) {
    const badEndpointPolicy = buildFixture().policy;
    badEndpointPolicy.roles.activationTargetRoot.producerConstraints.endpoint =
      badEndpoint;
    assert.equal(validatePolicySchema(badEndpointPolicy), false, badEndpoint);
  }
  for (const badRoot of [
    "/",
    "/srv/",
    "/srv//platform-infrastructure",
    "/" + "a".repeat(4096),
  ]) {
    const badRootPolicy = buildFixture().policy;
    badRootPolicy.roles.activationTargetRoot.producerConstraints.targetRoot =
      badRoot;
    assert.equal(validatePolicySchema(badRootPolicy), false, badRoot);
  }

  const badChallenge = buildFixture().phaseBPayload;
  badChallenge.consumerChallenge.consumerRepository =
    "Independent-consumer/phase-b";
  assert.equal(validateAuthorizationSchema(badChallenge), false);
  const badJob = buildFixture().phaseBPayload;
  badJob.consumerChallenge.consumerJob = "consumer/job";
  assert.equal(validateAuthorizationSchema(badJob), false);
});

test("runtime rejects every target-root spelling excluded by the policy schema", () => {
  for (const badRoot of ["/", "/srv/", "/" + "a".repeat(4096)]) {
    const fixture = buildFixture();
    fixture.policy.roles.activationTargetRoot.producerConstraints.targetRoot =
      badRoot;
    fixture.policyArtifact = canonicalArtifact(fixture.policy);
    fixture.expected.policySha256 = fixture.policyArtifact.sha256;
    assert.throws(
      () => verify(fixture),
      /constrained root must be one normalized absolute path/,
      badRoot.slice(0, 80),
    );
  }
});

test("runtime rejects endpoint spellings excluded by the policy schema", () => {
  for (const badEndpoint of [
    "ssh://deploy@localhost:22",
    "ssh://deploy@" + "a.".repeat(160) + "test:22",
  ]) {
    const fixture = buildFixture();
    fixture.policy.roles.activationTargetRoot.producerConstraints.endpoint =
      badEndpoint;
    fixture.policyArtifact = canonicalArtifact(fixture.policy);
    fixture.expected.policySha256 = fixture.policyArtifact.sha256;
    assert.throws(
      () => verify(fixture),
      /canonical ssh:\/\/user@host:port identity/,
    );
  }
});

test("Phase-B consumes exactly the brownfield core preinstall tuple namespace", () => {
  const fixture = buildFixture();
  assert.equal(
    fixture.tuple.schema,
    "platform.v1-brownfield-preinstall-tuple/v1",
  );
  assert.deepEqual(validatePreinstallTuple(fixture.tuple), fixture.tuple);
});

test("Phase-B is byte-pinned to the frozen Phase-A and canonical core accept sets", () => {
  assert.equal(
    h(fs.readFileSync(PHASE_A_MODULE)),
    "dd4dbeba8a0baaa4e8e8cefeac0cf0712afd7edef39e0ed8ca14d99865c837c8",
  );
  assert.equal(
    h(fs.readFileSync(CORE_MODULE)),
    "11d1a252d90eccd3561fd19675a9c2b7646cd9df1ba9b16f85b57f406c2cd9a8",
  );
  assert.equal(
    h(fs.readFileSync(COMMON_SCHEMA)),
    "10fcc60e9a60ada1e675021d1cb415c0e287e89fbba28bbfb57bb2941a26922e",
  );
});

test("Phase-B delegates once to each canonical core validator without local accept-set copies", () => {
  const source = fs.readFileSync(MODULE, "utf8");
  assert.equal(
    (source.match(/validateV1BrownfieldInstallPlan\(value\)/g) ?? []).length,
    1,
  );
  assert.equal(
    (source.match(/validateV1BrownfieldPreinstallTuple\(value\)/g) ?? []).length,
    1,
  );
  assert.equal(
    (source.match(/validateV1BrownfieldPhaseBPreinstallEvidence\(/g) ?? []).length,
    1,
  );
  assert.doesNotMatch(source, /validateInstallPlanV2Legacy|exact fixed source CAS ancestry policy/);
  assert.doesNotMatch(
    source,
    /INSTALL_(?:BINARY_PATHS|BINARY_NAMES|DIRECTORY_PATHS)|validatePhaseAPackagePayload|validatePhaseAAuthorizationPayload/,
  );
});

test("replay claim, journal, receipt, and package CAS paths are fixed derivations", () => {
  const fixture = buildFixture();
  const payload = fixture.phaseBPayload;
  const replayKey = payload.replayClaimPrecondition.ledgerEntryKeySha256;
  const receiptKey = payload.replayRequirements.receiptObjectKeySha256;
  assert.equal(
    payload.replayClaimPrecondition.claimObjectPath,
    "/var/lib/.platform-v1-phase-b-claim-" + replayKey,
  );
  assert.equal(
    payload.replayRequirements.journalRecordPath,
    "/var/lib/platform-infrastructure/v1-phase-b-ledger/" + replayKey + ".json",
  );
  assert.equal(
    payload.replayRequirements.receiptObjectPath,
    "/var/lib/platform-infrastructure/v1-install-receipts/sha256/" +
      receiptKey +
      ".json",
  );
  assert.equal(
    payload.preinstallTuple.installPlan.materializationPolicy.casRoot,
    "/var/lib/platform-infrastructure/v1-package-cas/sha256/" +
      payload.preinstallTuple.installPlan.packageBytesSha256,
  );
});

test("module exposes no signing, minting, apply, output-file, force, or live execution CLI", () => {
  const source = fs.readFileSync(MODULE, "utf8");
  assert.doesNotMatch(source, /createPrivateKey|generateKeyPair|crypto\.sign/);
  assert.doesNotMatch(source, /--(?:force|apply|sign|mint|output|ready|skip)/);
  assert.doesNotMatch(source, /node:child_process|\b(?:spawn|execFile|execSync|fork)\s*\(/);
  assert.match(source, /SIGNATURE_VERIFIED_NON_AUTHORITATIVE/);
  assert.match(source, /installationAuthorized:\s*false/);
  assert.match(source, /effect:\s*"STOP"/);
  assert.match(
    source,
    /fs\.constants\.O_RDONLY\s*\|\s*fs\.constants\.O_NOFOLLOW\s*\|\s*fs\.constants\.O_NONBLOCK/,
  );
  assert.match(source, /const before = fs\.fstatSync\(descriptor/);
  assert.match(source, /process\.exitCode = 78/);
});

test("valid CLI emits immutable STOP evidence and exits non-authoritatively with 78", () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "platform-v1-phase-b-cli-"),
  );
  try {
    const fixture = buildFixture();
    const paths = materializeCliFixture(fixture, directory);
    const namesBefore = fs.readdirSync(directory).sort();
    const hashesBefore = Object.fromEntries(
      namesBefore.map((name) => [
        name,
        h(fs.readFileSync(path.join(directory, name))),
      ]),
    );
    const child = spawnSync(process.execPath, cliArgs(paths), {
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(child.error, undefined);
    assert.equal(child.signal, null);
    assert.equal(child.status, 78);
    assert.equal(child.stderr, "");
    const output = JSON.parse(child.stdout);
    assert.equal(output.effect, "STOP");
    assert.equal(output.stdoutAuthority, false);
    assert.equal(output.liveAuthorization, false);
    assert.equal(output.mutationAuthority, false);
    assert.equal(output.installationAuthorized, false);
    assert.deepEqual(fs.readdirSync(directory).sort(), namesBefore);
    for (const [name, digest] of Object.entries(hashesBefore)) {
      assert.equal(h(fs.readFileSync(path.join(directory, name))), digest);
    }
  } finally {
    fs.rmSync(directory, { force: true, recursive: true });
  }
});

test("CLI safe capture rejects FIFOs without blocking", () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "platform-v1-phase-b-fifo-"),
  );
  try {
    const fifo = path.join(directory, "artifact.fifo");
    const mkfifo = spawnSync("mkfifo", [fifo], {
      encoding: "utf8",
      timeout: 2000,
    });
    assert.equal(mkfifo.status, 0, mkfifo.stderr);
    const paths = Object.fromEntries([
      "authorization",
      "backup-attestation",
      "expected",
      "phase-a-authorization",
      "phase-a-package-attestation",
      "phase-a-policy",
      "policy",
    ].map((name) => [name, fifo]));
    const child = spawnSync(process.execPath, cliArgs(paths), {
      encoding: "utf8",
      timeout: 2000,
    });
    assert.equal(child.error, undefined);
    assert.equal(child.signal, null);
    assert.equal(child.status, 1);
    assert.match(child.stderr, /bounded regular non-symlink singly linked file/);
  } finally {
    fs.rmSync(directory, { force: true, recursive: true });
  }
});

test("CLI rejects BOM and noncanonical caller-binding bytes", () => {
  for (const encode of [
    (value) => Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      canonicalArtifact(value).bytes,
    ]),
    (value) => Buffer.from(JSON.stringify(value, null, 2) + "\n", "utf8"),
  ]) {
    const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "platform-v1-phase-b-canonical-"),
    );
    try {
      const fixture = buildFixture();
      const paths = materializeCliFixture(fixture, directory);
      fs.writeFileSync(paths.expected, encode(fixture.expected));
      const child = spawnSync(process.execPath, cliArgs(paths), {
        encoding: "utf8",
        timeout: 5000,
      });
      assert.equal(child.error, undefined);
      assert.equal(child.status, 1);
      assert.match(child.stderr, /BOM|exact canonical JSON bytes/);
    } finally {
      fs.rmSync(directory, { force: true, recursive: true });
    }
  }
});
