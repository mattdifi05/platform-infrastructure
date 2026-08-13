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
  GATE_ORDER,
  PAYLOAD_TYPES,
  ROLE_NAMES,
  validateV1BrownfieldInstallPlan,
  validateV1BrownfieldPhaseBPreinstallEvidence,
  validateV1BrownfieldPreinstallTuple,
  verifyV1BrownfieldAdmission,
} from "./v1-brownfield-admission.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const SCRIPT = path.join(HERE, "v1-brownfield-admission.mjs");
const PENDING_POLICY = path.join(ROOT, "governance", "v1-brownfield-admission-policy.json");
const SCHEMA_DIRECTORY = path.join(ROOT, "governance", "schemas");
const MAX_BYTES = 4 * 1024 * 1024;
const require = createRequire(path.join(ROOT, "vendor", "json-schema", "package.json"));
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

function h(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function domainSha(domain, ...values) {
  return h([domain, ...values].join("\0"));
}

function fingerprint(publicKey) {
  return crypto.createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function pae(payloadType, payloadBytes) {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, "ascii"),
    type,
    Buffer.from(` ${payloadBytes.length} `, "ascii"),
    payloadBytes,
  ]);
}

function canonicalArtifact(document) {
  const bytes = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
  return { bytes, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
}

function envelope(payloadType, payload, signers) {
  const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
  return canonicalArtifact({
    payload: payloadBytes.toString("base64"),
    payloadType,
    signatures: signers.map(({ keyId, privateKey }) => ({
      keyid: keyId,
      sig: crypto.sign(null, pae(payloadType, payloadBytes), privateKey).toString("base64"),
    })),
  });
}

function target(prefix, targetKind) {
  const activation = targetKind === "activation";
  const root = activation ? "/srv/platform-infrastructure" : "/home/deploy/platform-infrastructure";
  const rootParentPath = path.posix.dirname(root);
  return {
    targetId: `${prefix}-${targetKind}-production-target`,
    machineId: h(`${prefix}-machine-id`),
    environment: "production",
    host: `${prefix}.example.test`,
    endpoint: `ssh://deploy@${prefix}.example.test:22`,
    root,
    sshHostKeySha256: h(`${prefix}-host-key`),
    rootFilesystemIdentitySha256: h(`${prefix}-root-filesystem-identity`),
    dockerDaemonId: `${prefix}-daemon-001`,
    deploymentUid: 1001,
    deploymentGid: 1001,
    rootState: activation ? "ABSENT_PROVEN" : "EXISTING_EXACT",
    rootAbsenceReceiptSha256: activation ? h("negative-lookup:/srv/platform-infrastructure") : null,
    rootIdentity: activation ? null : {
      deviceIdentity: `device:${prefix}-source-root-001`,
      filesystemUuid: h(`${prefix}-source-filesystem-uuid`),
      inode: "512",
      mountId: "5012",
      uid: 0,
      gid: 0,
      mode: "0755",
      nlink: 2,
    },
    rootParentPath,
    rootParentIdentity: {
      deviceIdentity: activation ? "device:destination-filesystem" : `device:${prefix}-root-001`,
      filesystemUuid: activation ? h("destination-filesystem-uuid") : h(`${prefix}-filesystem-uuid`),
      inode: activation ? "4102" : "256",
      mountId: activation ? "7006" : "250",
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
    packageMember: `bin/${name}`,
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
    deviceIdentity: `device:${prefix}-filesystem`,
    filesystemUuid: h(`${prefix}-filesystem-uuid`),
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
    disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT", gid: 0, kind: "DIRECTORY", mode: "0755",
    nlink: null, path: pathname, sha256: null, sizeBytes: null, uid: 0,
  });
  const file = (identity, kind = "REGULAR_FILE") => ({
    disposition: identity.disposition, gid: identity.gid, kind, mode: identity.mode, nlink: identity.nlink,
    path: identity.path, sha256: identity.sha256, sizeBytes: identity.sizeBytes, uid: identity.uid,
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
      disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT", gid: 0, kind: "REGULAR_FILE", mode: "0444", nlink: 1,
      path: `${casRoot}/package.bin`, sha256: plan.packageBytesSha256, sizeBytes: plan.packageBytesSizeBytes, uid: 0,
    },
    {
      disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT", gid: 0, kind: "REGULAR_FILE", mode: "0444", nlink: 1,
      path: `${casRoot}/manifest.json`, sha256: plan.packageManifestSha256, sizeBytes: plan.packageManifestSizeBytes, uid: 0,
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
  throw new Error(`missing fixture anchor for ${pathname}`);
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
      anchorIdentitySha256: h(canonicalJson(anchor)),
      relativePath: path.posix.relative(anchorPath, targetValue.path),
      negativeLookupReceiptSha256: h(`negative-lookup:${targetValue.path}`),
      openat2ResolveBeneathNoSymlinks: true,
      openat2ResolveNoXdev: true,
      verifiedAt,
    };
  });
}

function existingMaterializationPrecondition(targetValue, index, ancestry, verifiedAt) {
  const anchorPath = materializationAnchor(targetValue.path);
  const anchor = [...ancestry.sourceParents, ...ancestry.destinationParents]
    .find((entry) => entry.path === anchorPath);
  return {
    path: targetValue.path,
    state: "EXISTING_EXACT",
    anchorPath,
    anchorIdentitySha256: h(canonicalJson(anchor)),
    relativePath: path.posix.relative(anchorPath, targetValue.path),
    openat2ResolveBeneathNoSymlinks: true,
    openat2ResolveNoXdev: true,
    identity: materializedIdentity(targetValue, index),
    verifiedAt,
  };
}

function markBrokerExistingExact(fixture) {
  const tuple = fixture.policy.expectedTuple;
  const targets = tuple.preinstallTuple.installPlan.materializationTargets;
  const index = targets.findIndex((entry) => entry.path === "/usr/local/libexec/platform-activation-broker");
  const precondition = existingMaterializationPrecondition(
    targets[index],
    index,
    tuple.phaseBPreInstallAuthorization.preMutationAncestryVerification,
    tuple.phaseBPreInstallAuthorization.preMutationAncestryVerification.verifiedAt,
  );
  tuple.phaseBPreInstallAuthorization.materializationPreconditions[index] = precondition;
  const outcome = tuple.installReceipt.materializationTargetOutcomes[index];
  outcome.state = "PREEXISTING_EXACT_UNCHANGED";
  outcome.preconditionSha256 = h(canonicalJson(precondition));
  outcome.identity = structuredClone(precondition.identity);
  outcome.identity.identityReceiptSha256 = h(`postinstall-existing-identity:${outcome.path}`);
  return { outcome, precondition };
}

function materializedIdentity(targetValue, index) {
  const mountId = targetValue.path.startsWith("/var/lib/") ? "6002"
    : targetValue.path.startsWith("/srv/") ? "7006"
      : targetValue.path.startsWith("/usr/local/libexec/") ? "7003" : "7005";
  return {
    path: targetValue.path,
    kind: targetValue.kind,
    fileType: targetValue.kind === "DIRECTORY" ? "DIRECTORY" : "REGULAR_FILE",
    symlink: false,
    descriptorNoFollow: true,
    identityReceiptSha256: h(`materialized-identity:${targetValue.path}`),
    deviceIdentity: targetValue.path.startsWith("/var/lib/") ? "device:source-cas-filesystem" : "device:destination-filesystem",
    filesystemUuid: targetValue.path.startsWith("/var/lib/")
      ? h("source-cas-filesystem-uuid") : h("destination-filesystem-uuid"),
    inode: String(20_000 + index),
    mountId,
    uid: targetValue.uid,
    gid: targetValue.gid,
    mode: targetValue.mode,
    nlink: targetValue.nlink ?? 2,
    sha256: targetValue.sha256,
    sizeBytes: targetValue.sizeBytes,
  };
}

function materializationOutcomes(targets, preconditions, transactionId, verifiedAt) {
  const outcomes = targets.map((targetValue, index) => ({
    path: targetValue.path,
    state: preconditions[index].state === "ABSENT_PROVEN"
      ? "CREATED_BY_TRANSACTION" : "PREEXISTING_EXACT_UNCHANGED",
    identity: materializedIdentity(targetValue, index),
    preconditionSha256: h(canonicalJson(preconditions[index])),
    transactionId,
    noReplacement: true,
    verifiedAt,
  }));
  for (let index = 0; index < targets.length; index += 1) {
    if (targets[index].kind !== "DIRECTORY") continue;
    const createdDirectChildren = targets.filter((candidate, childIndex) => (
      candidate.kind === "DIRECTORY" && preconditions[childIndex].state === "ABSENT_PROVEN"
        && path.posix.dirname(candidate.path) === targets[index].path
    )).length;
    outcomes[index].identity.nlink = preconditions[index].state === "ABSENT_PROVEN"
      ? 2 + createdDirectChildren
      : preconditions[index].identity.nlink + createdDirectChildren;
  }
  return outcomes;
}

function postInstallAncestry(preMutation, targets, preconditions) {
  const result = structuredClone(preMutation);
  for (let index = 0; index < targets.length; index += 1) {
    if (targets[index].kind !== "DIRECTORY" || preconditions[index].state !== "ABSENT_PROVEN") continue;
    const directParent = path.posix.dirname(targets[index].path);
    for (const parents of [result.sourceParents, result.destinationParents]) {
      const parent = parents.find((entry) => entry.path === directParent);
      if (parent !== undefined) parent.nlink += 1;
    }
  }
  result.verificationReceiptSha256 = h("post-install-ancestry-verification-receipt");
  return result;
}

function fixtureResourceObservation(plan, ancestry, observedAt) {
  const parents = [...ancestry.sourceParents, ...ancestry.destinationParents];
  const devices = new Map();
  for (const targetValue of plan.materializationTargets) {
    const anchorPath = materializationAnchor(targetValue.path);
    const parent = parents.find((entry) => entry.path === anchorPath);
    const key = `${parent.deviceIdentity}:${parent.filesystemUuid}`;
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
  const varDevice = devices.get(`${varParent.deviceIdentity}:${varParent.filesystemUuid}`);
  if (!varDevice.mountIds.includes(varParent.mountId)) varDevice.mountIds.push(varParent.mountId);
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

function fixtureResourceOutcome(observation, verifiedAt) {
  return {
    devices: observation.devices.map((device, index) => ({
      deviceIdentity: device.deviceIdentity,
      filesystemUuid: device.filesystemUuid,
      mountIds: device.mountIds,
      plannedWriteBytes: device.plannedWriteBytes,
      plannedCreatedInodes: device.plannedCreatedInodes,
      actualWrittenBytes: device.plannedWriteBytes,
      actualCreatedInodes: device.plannedCreatedInodes,
      freeBytes: device.freeBytes - device.plannedWriteBytes,
      freeInodes: device.freeInodes - device.plannedCreatedInodes,
      requiredFreeBytesAfter: device.requiredFreeBytesAfter,
      requiredFreeInodesAfter: device.requiredFreeInodesAfter,
      installerAccountingReceiptSha256: h(`installer-resource-accounting:${index}`),
    })),
    preMutationObservationReceiptSha256: observation.receiptSha256,
    receiptSha256: h("post-install-resource-outcome-receipt"),
    verifiedAt,
  };
}

function preinstallTuple(now = Date.now(), keys = null) {
  const phaseAIssuedAt = new Date(now - 10_800_000).toISOString();
  const phaseAVerifiedAt = new Date(now - 10_740_000).toISOString();
  const phaseAExpiresAt = new Date(now - 10_200_000).toISOString();
  const baselineCaptureStartedAt = new Date(now - 10_700_000).toISOString();
  const baselineCaptureCompletedAt = new Date(now - 10_300_000).toISOString();
  const baselineVerifiedAt = new Date(now - 10_250_000).toISOString();
  const backupCaptureStartedAt = new Date(now - 800_000).toISOString();
  const backupCaptureCompletedAt = new Date(now - 600_000).toISOString();
  const backupVerifiedAt = new Date(now - 570_000).toISOString();
  const structuralReceiptVerifiedAt = new Date(now - 540_000).toISOString();
  const retrievalStartedAt = new Date(now - 530_000).toISOString();
  const retrievalCompletedAt = new Date(now - 520_000).toISOString();
  const retrievalVerifiedAt = new Date(now - 510_000).toISOString();
  const restoreStartedAt = new Date(now - 500_000).toISOString();
  const restoreVerifiedAt = new Date(now - 480_000).toISOString();
  const databaseVerifiedAt = new Date(now - 470_000).toISOString();
  const sudoersContent = "deploy ALL=(root) NOPASSWD: /usr/local/libexec/platform-activation-broker activate\n";
  const sourceTarget = target("server", "source");
  const activationTarget = target("server", "activation");
  const phaseAAuthorizedCandidate = {
    repository: "example/platform-infrastructure",
    repositoryId: "123456789",
    repositoryOwnerId: "1234567",
    commitSha: "3".repeat(40),
    treeSha: "4".repeat(40),
    clean: true,
    sourceArchiveSha256: h("source-archive"),
    packageSha256: h("phase-a-package-bytes"),
    packageManifestSha256: h("phase-a-package-manifest"),
  };
  const phaseAAuthorizedTarget = {
    endpoint: activationTarget.endpoint,
    hostname: activationTarget.host,
    targetRoot: activationTarget.root,
    sshHostKeySha256: activationTarget.sshHostKeySha256,
    dockerDaemonId: activationTarget.dockerDaemonId,
    machineIdentitySha256: activationTarget.machineId,
    rootFilesystemIdentitySha256: activationTarget.rootFilesystemIdentitySha256,
    deploymentUid: activationTarget.deploymentUid,
    deploymentGid: activationTarget.deploymentGid,
  };
  const tuple = {
    schema: "platform.v1-brownfield-preinstall-tuple/v1",
    transactionId: h("transaction"),
    candidate: {
      repository: "example/platform-infrastructure",
      repositoryId: "123456789",
      repositoryOwnerId: "1234567",
      commitSha: "3".repeat(40),
      treeSha: "4".repeat(40),
      sourceArchiveSha256: h("source-archive"),
    },
    strategy: "ADDITIVE",
    sourceTarget,
    activationTarget,
    identityTransition: null,
    phaseA: {
      authorizationEnvelopeSha256: h("phase-a-envelope"),
      authorizedCandidate: phaseAAuthorizedCandidate,
      authorizedCandidateSha256: h(canonicalJson(phaseAAuthorizedCandidate)),
      authorizedTarget: phaseAAuthorizedTarget,
      authorizedTargetSha256: h(canonicalJson(phaseAAuthorizedTarget)),
      authorizationId: `phase-a-authorization-${h("phase-a-id")}`,
      nonce: Buffer.alloc(32, 7).toString("base64url"),
      orderContractId: "platform-v1-hosted-two-phase-order/v1",
      orderContractSha256: h("two-phase-order-sha"),
      scope: "READ_ONLY_LIVE_PREFLIGHT",
      issuedAt: phaseAIssuedAt,
      verifiedAt: phaseAVerifiedAt,
      expiresAt: phaseAExpiresAt,
      policySha256: h("phase-a-policy"),
      verificationReceiptSha256: h("phase-a-verification-receipt"),
      packageAttestationEnvelopeSha256: h("phase-a-package-envelope"),
      packageAttestationId: `phase-a-package-${h("phase-a-package-id")}`,
      packageAttestorKeyId: keys.phaseAPackageAttestor.fingerprintSha256,
      packagePayloadType: "application/vnd.platform.v1.phase-a.package-attestation.v1+json",
      authorizationPayloadType: "application/vnd.platform.v1.phase-a.read-only-authorization.v1+json",
      authorizationProviderKeyId: keys.phaseAAuthorizationProvider.fingerprintSha256,
      candidateClean: true,
      consumerChallengeSha256: h("phase-a-consumer-challenge"),
      futureRoleKeyIds: {
        backupAuthority: keys.backupAuthority.fingerprintSha256,
        sourceTargetCustodian: keys.sourceTargetCustodian.fingerprintSha256,
        phaseBInstaller: keys.phaseBInstaller.fingerprintSha256,
        hostedGate: keys.hostedGate.fingerprintSha256,
        deploymentGate: keys.deploymentGate.fingerprintSha256,
        activationGate: keys.activationGate.fingerprintSha256,
        admissionController: keys.admissionController.fingerprintSha256,
        activationTargetRoot: keys.activationTargetRoot.fingerprintSha256,
      },
      packageSha256: h("phase-a-package-bytes"),
      packageManifestSha256: h("phase-a-package-manifest"),
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
      protectedArtifactSetSha256: h("protected-artifact-set"),
      protectedArtifactCount: 173,
      databaseSetSha256: h("database-set"),
      databaseCount: 17,
      captureStartedAt: baselineCaptureStartedAt,
      captureCompletedAt: baselineCaptureCompletedAt,
      verifiedAt: baselineVerifiedAt,
    },
    structuralBackupReceipt: {
      artifactSha256: h("structural-backup-receipt"),
      receiptId: h("structural-backup-receipt-id"),
      backupSetId: h("backup-set-id"),
      backupManifestSha256: h("backup-manifest"),
      backupArtifactSetSha256: h("backup-artifact-set"),
      protectedArtifactSetSha256: h("protected-artifact-set"),
      protectedArtifactCount: 173,
      databaseSetSha256: h("database-set"),
      databaseCount: 17,
      schema: "platform.v1-predeploy-backup-receipt/v1",
      status: "REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE",
      authoritative: false,
      verifiedAt: structuralReceiptVerifiedAt,
    },
    authoritativeBackupAttestation: {
      evidenceArtifactSha256: h("authoritative-backup-evidence"),
      attestationId: h("authoritative-backup-attestation-id"),
      backupSetId: h("backup-set-id"),
      backupManifestSha256: h("backup-manifest"),
      backupArtifactSetSha256: h("backup-artifact-set"),
      protectedArtifactSetSha256: h("protected-artifact-set"),
      protectedArtifactCount: 173,
      databaseSetSha256: h("database-set"),
      databaseCount: 17,
      offHost: true,
      sourceDeviceSetExcluded: true,
      captureStartedAt: backupCaptureStartedAt,
      captureCompletedAt: backupCaptureCompletedAt,
      verifiedAt: backupVerifiedAt,
      backupRootPath: "/mnt/offhost/platform-backup/transaction",
      backupDeviceIdentity: "device:offhost-backup-001",
      offHostRetrieval: {
        backupSetId: h("backup-set-id"),
        backupManifestSha256: h("backup-manifest"),
        backupArtifactSetSha256: h("backup-artifact-set"),
        protectedArtifactSetSha256: h("protected-artifact-set"),
        protectedArtifactCount: 173,
        retrievedBytesSha256: h("retrieved-backup-bytes"),
        providerIdentity: "provider:offhost-backup-primary",
        retrievalReceiptArtifactSha256: h("offhost-retrieval-receipt"),
        retrievalStartedAt,
        retrievalCompletedAt,
        lastVerifiedAt: retrievalVerifiedAt,
        verified: true,
      },
      restoreDrill: {
        backupSetId: h("backup-set-id"),
        backupManifestSha256: h("backup-manifest"),
        backupArtifactSetSha256: h("backup-artifact-set"),
        expectedArtifactCount: 173,
        restoredArtifactCount: 173,
        restoredArtifactSetSha256: h("protected-artifact-set"),
        manifestParity: true,
        restoredBytesSha256: h("retrieved-backup-bytes"),
        retrievalReceiptArtifactSha256: h("offhost-retrieval-receipt"),
        restoreDrillArtifactSha256: h("restore-drill"),
        startedAt: restoreStartedAt,
        verifiedAt: restoreVerifiedAt,
        isolated: true,
        verified: true,
      },
      databaseConsistency: {
        backupSetId: h("backup-set-id"),
        backupManifestSha256: h("backup-manifest"),
        backupArtifactSetSha256: h("backup-artifact-set"),
        expectedDatabaseCount: 17,
        verifiedDatabaseCount: 17,
        databaseSetSha256: h("database-set"),
        databaseCatalogSha256: h("database-catalog"),
        restoredBytesSha256: h("retrieved-backup-bytes"),
        retrievalReceiptArtifactSha256: h("offhost-retrieval-receipt"),
        restoreDrillArtifactSha256: h("restore-drill"),
        verificationArtifactSha256: h("database-consistency"),
        verifiedAt: databaseVerifiedAt,
        databasesConsistent: true,
      },
      writeConsistency: {
        mode: "POINT_IN_TIME_SNAPSHOT",
        snapshotReceiptArtifactSha256: h("point-in-time-snapshot-receipt"),
        sourceWriteWatermarkSha256: h("source-write-watermark"),
        capturedAt: new Date(now - 700_000).toISOString(),
        verifiedAt: new Date(now - 650_000).toISOString(),
        applicationDataMutationAuthority: false,
        continuedLiveWritesPreserved: true,
      },
      backupTrustPolicySha256: h("backup-trust-policy"),
      attestationIssuedAt: new Date(now - 450_000).toISOString(),
      attestationExpiresAt: new Date(now + 450_000).toISOString(),
    },
    installPlan: {
      plannedReceiptId: `install-receipt:${h("install-receipt-id")}`,
      packageBytesSha256: h("phase-a-package-bytes"),
      packageBytesSizeBytes: 1_048_576,
      packageAttestationEnvelopeSha256: h("phase-a-package-envelope"),
      packageManifestSha256: h("phase-a-package-manifest"),
      packageManifestSizeBytes: 8192,
      broker: binary("/usr/local/libexec/platform-activation-broker", "broker-binary"),
      verifier: binary("/usr/local/libexec/platform-v1-brownfield-admission", "admission-verifier"),
      helpers: [
        binary("/usr/local/libexec/platform-hosted-preparation-broker", "hosted-helper"),
        binary("/usr/local/libexec/platform-origin-firewall", "origin-firewall-helper"),
        binary("/usr/local/libexec/platform-workload-egress-firewall", "workload-egress-firewall-helper"),
      ],
      directories: [
        "/srv/platform-infrastructure",
        "/srv/platform-infrastructure/releases",
        "/srv/platform-infrastructure/release-states",
      ].map((pathname) => ({
        path: pathname, uid: 0, gid: 0, mode: "0755",
        disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
      })),
      privilegePolicy: {
        path: "/etc/sudoers.d/platform-activation-broker",
        content: sudoersContent,
        contentEncoding: "UTF-8",
        sha256: h(sudoersContent), uid: 0, gid: 0, mode: "0440", nlink: 1,
        packageMember: "etc/sudoers.d/platform-activation-broker",
        sizeBytes: Buffer.byteLength(sudoersContent, "utf8"),
        disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT",
        principalName: "deploy",
        principalUid: 1001,
        principalGid: 1001,
        principalPreexistingRequired: true,
        principalAccountIdentityReceiptSha256: h("activation-broker-account-identity-receipt"),
        allowedSupplementaryGroups: [],
        dockerGroupMembershipAllowed: false,
        dockerSocketAccessAllowed: false,
        rootEquivalentCapabilitiesAllowed: false,
        unrestrictedSudoAllowed: false,
        effectiveSudoPolicyProfile: "ACTIVATION-BROKER-ACTIVATE-ONLY/V1",
        permittedInvocation: "/usr/local/libexec/platform-activation-broker activate",
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
        providerValidationReceiptSha256: h("provider-sudoers-validation-receipt"),
        validatorPath: "/usr/sbin/visudo",
        validatorSha256: h("pinned-visudo-binary"),
      },
      installerBootstrap: {
        path: "/usr/local/libexec/platform-v1-bootstrap-installer",
        version: 2,
        sha256: h("bootstrap-installer"),
        executionIdentitySha256: h("bootstrap-execution-identity"),
        trustPolicySha256: h("bootstrap-trust-policy"),
        phaseBInstallerFingerprintSha256: keys.phaseBInstaller.fingerprintSha256,
        activationTargetRootFingerprintSha256: keys.activationTargetRoot.fingerprintSha256,
        independentlyPinned: true,
        uid: 0, gid: 0, mode: "0555", nlink: 1,
      },
      materializationPolicy: {
        schema: "platform.v1-package-materialization-plan/v1",
        casRoot: `/var/lib/platform-infrastructure/v1-package-cas/sha256/${h("phase-a-package-bytes")}`,
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
        sourceParents: [
          "/",
          "/var",
          "/var/lib",
        ].map((pathname) => ({
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
    },
    rollbackPolicy: {
      artifactSha256: h("rollback-policy"),
      policyId: h("rollback-policy-id"),
      codeRollbackAllowed: true,
      dataRollbackAuthority: false,
      requiresPostDeployPreservation: true,
      preserveNewWrites: true,
    },
  };
  tuple.installPlan.materializationTargets = materializationTargets(tuple.installPlan);
  const members = [
    tuple.installPlan.broker, tuple.installPlan.verifier, ...tuple.installPlan.helpers, tuple.installPlan.privilegePolicy,
  ];
  const packageMemberBytesTotal = members.reduce((total, member) => total + member.sizeBytes, 0);
  const maxCasBytes = tuple.installPlan.packageBytesSizeBytes + tuple.installPlan.packageManifestSizeBytes;
  const maxJournalBytes = 1024 * 1024;
  tuple.installPlan.resourceBudget = {
    schema: "platform.v1-install-resource-budget/v1",
    packageMemberCount: members.length,
    packageMemberBytesTotal,
    maxCasBytes,
    maxDestinationBytes: packageMemberBytesTotal,
    maxJournalBytes,
    maxTotalWriteBytes: maxCasBytes + packageMemberBytesTotal
      + tuple.installPlan.materializationTargets.filter((targetValue) => targetValue.kind === "DIRECTORY").length * 4096
      + maxJournalBytes,
    maxCreatedInodes: tuple.installPlan.materializationTargets.length + 3,
    hardTotalWriteCeilingBytes: 64 * 1024 * 1024,
    requiredFreeBytesAfter: 1024 * 1024 * 1024,
    requiredFreeInodesAfter: 10_000,
  };
  return tuple;
}

function finalTuple(preinstall, backupEnvelopeSha256, keys, now = Date.now()) {
  const phaseBIssuedAt = new Date(now - 420_000).toISOString();
  const ancestryPreVerifiedAt = new Date(now - 435_000).toISOString();
  const phaseBVerifiedAt = new Date(now - 390_000).toISOString();
  const phaseBExpiresAt = new Date(now + 180_000).toISOString();
  const claimCreatedAt = new Date(now - 380_000).toISOString();
  const ledgerConsumedAt = new Date(now - 370_000).toISOString();
  const firstWriteAt = new Date(now - 360_000).toISOString();
  const journalRecordWrittenAt = new Date(now - 350_000).toISOString();
  const privilegeVerifiedAt = new Date(now - 330_000).toISOString();
  const receiptWrittenAt = new Date(now - 310_000).toISOString();
  const installedAt = new Date(now - 300_000).toISOString();
  const challengeIssuedAt = new Date(now - 30_000).toISOString();
  const challengeExpiresAt = new Date(now + 570_000).toISOString();
  const preinstallTupleSha256 = h(canonicalJson(preinstall));
  const installPlanSha256 = h(canonicalJson(preinstall.installPlan));
  const phaseBInstallerProducer = externalProducer(
    "phaseBInstaller", 6, null, new Date(Date.parse(phaseBIssuedAt) - 30_000).toISOString(),
  );
  const phaseBTargetProducer = targetRootProducer(
    "activationTargetRoot", preinstall.activationTarget, null, phaseBIssuedAt,
  );
  const preMutationAncestryVerification = {
    materializationPolicySha256: h(canonicalJson(preinstall.installPlan.materializationPolicy)),
    sourceParents: observedParents(preinstall.installPlan.materializationPolicy.sourceParents, "source-cas"),
    destinationParents: observedParents(preinstall.installPlan.materializationPolicy.destinationParents, "destination"),
    verificationReceiptSha256: h("pre-mutation-ancestry-verification-receipt"),
    verifiedAt: ancestryPreVerifiedAt,
  };
  preMutationAncestryVerification.destinationParents[0]
    = structuredClone(preMutationAncestryVerification.sourceParents[0]);
  const targetPreconditions = materializationPreconditions(
    preinstall.installPlan.materializationTargets,
    preMutationAncestryVerification,
    ancestryPreVerifiedAt,
  );
  const resourceObservation = fixtureResourceObservation(
    preinstall.installPlan,
    preMutationAncestryVerification,
    ancestryPreVerifiedAt,
  );
  const phaseBAuthorizationId = `phase-b-install-${h("phase-b-authorization-id")}`;
  const phaseBNonce = Buffer.alloc(32, 8).toString("base64url");
  const ledgerEntryKey = domainSha(
    "phase-b-ledger-v1", phaseBAuthorizationId, phaseBNonce, preinstall.transactionId,
    preinstall.installPlan.installerBootstrap.trustPolicySha256, preinstallTupleSha256,
  );
  const ledgerParent = preMutationAncestryVerification.sourceParents[2];
  const claimObjectPath = `/var/lib/.platform-v1-phase-b-claim-${ledgerEntryKey}`;
  const replayClaimPrecondition = {
    schema: "platform.v1-phase-b-replay-claim-precondition/v1",
    authorizationId: phaseBAuthorizationId,
    nonce: phaseBNonce,
    policySha256: preinstall.installPlan.installerBootstrap.trustPolicySha256,
    preinstallTupleSha256,
    ledgerEntryKeySha256: ledgerEntryKey,
    ledgerParentPath: "/var/lib",
    ledgerParentIdentitySha256: h(canonicalJson(ledgerParent)),
    ledgerAncestrySha256: h(canonicalJson(preMutationAncestryVerification.sourceParents.slice(0, 3))),
    claimObjectPath,
    claimNegativeLookupReceiptSha256: h("phase-b-claim-negative-lookup-receipt"),
    atomicCreateExclusiveRequired: true,
    claimFileFsyncRequired: true,
    claimParentFsyncRequired: true,
    openat2ResolveBeneathNoSymlinks: true,
    openat2ResolveNoXdev: true,
    verifiedAt: ancestryPreVerifiedAt,
  };
  const phaseB = {
    authorizationEnvelopeSha256: h("phase-b-authorization-envelope"),
    authorizationId: phaseBAuthorizationId,
    payloadType: "application/vnd.platform.v1.phase-b.preinstall-authorization.v1+json",
    scope: "INSTALL_PINNED_V1_CONTROL_PLANE_ONLY",
    policySha256: preinstall.installPlan.installerBootstrap.trustPolicySha256,
    verificationReceiptSha256: h("phase-b-verification-receipt"),
    nonce: phaseBNonce,
    replayLedgerStatus: "EXTERNAL_PENDING",
    issuedAt: phaseBIssuedAt,
    verifiedAt: phaseBVerifiedAt,
    expiresAt: phaseBExpiresAt,
    preinstallTupleSha256,
    backupAttestationEnvelopeSha256: backupEnvelopeSha256,
    installPlanSha256,
    materializationTargetPlanSha256: h(canonicalJson(preinstall.installPlan.materializationTargets)),
    installerBootstrapSha256: h(canonicalJson(preinstall.installPlan.installerBootstrap)),
    operationScope: {
      permitted: [
        "MATERIALIZE_PINNED_PACKAGE_TO_CAS",
        "INSTALL_PINNED_V1_CONTROL_PLANE",
        "VERIFY_INSTALLED_V1_CONTROL_PLANE",
      ],
      forbidden: [
        "APP_DATA_MUTATION", "APP_OR_DB_QUIESCE", "CHOWN_EXISTING", "DATABASE_OPERATION", "DOCKER_OPERATION",
        "FIREWALL_OPERATION", "REMOVE_EXISTING", "REPLACE_EXISTING", "RESTORE_OPERATION", "SYSTEMD_OPERATION",
      ],
    },
    preMutationAncestryVerification,
    materializationPreconditions: targetPreconditions,
    packageInputObservation: {
      schema: "platform.v1-authenticated-package-input-observation/v1",
      transport: "AUTHENTICATED_READ_ONLY_FD",
      pathAccepted: false,
      readOnly: true,
      sealedAgainstMutation: true,
      packageBytesSha256: preinstall.installPlan.packageBytesSha256,
      packageBytesSizeBytes: preinstall.installPlan.packageBytesSizeBytes,
      manifestSha256: preinstall.installPlan.packageManifestSha256,
      manifestSizeBytes: preinstall.installPlan.packageManifestSizeBytes,
      descriptorIdentityReceiptSha256: h("package-input-descriptor-identity-receipt"),
      verifiedAt: ancestryPreVerifiedAt,
    },
    principalAccountObservation: {
      principalName: preinstall.installPlan.privilegePolicy.principalName,
      principalUid: preinstall.installPlan.privilegePolicy.principalUid,
      principalGid: preinstall.installPlan.privilegePolicy.principalGid,
      accountLookupReceiptSha256: preinstall.installPlan.privilegePolicy.principalAccountIdentityReceiptSha256,
      passwdEntryReceiptSha256: h("deployment-account-passwd-entry-receipt"),
      groupMembershipReceiptSha256: h("deployment-account-group-membership-receipt"),
      dockerSocketAclReceiptSha256: h("deployment-account-docker-socket-acl-receipt"),
      dockerSocketIdentity: {
        path: "/run/docker.sock",
        fileType: "SOCKET",
        symlink: false,
        descriptorNoFollow: true,
        nlink: 1,
        daemonId: preinstall.activationTarget.dockerDaemonId,
        discoveredEndpoints: ["unix:///run/docker.sock"],
        principalAccessibleEndpoints: [],
        accessibleEndpointCount: 0,
        dockerHostEnvironmentAccepted: false,
        tcpEndpointsAccessible: false,
        parentAncestry: ["/", "/run"].map((pathname, index) => ({
          path: pathname,
          deviceIdentity: "device:docker-runtime-filesystem",
          filesystemUuid: h("docker-runtime-filesystem-uuid"),
          inode: String(90_100 + index),
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
        aclArtifactSha256: h("deployment-account-docker-socket-acl-receipt"),
        ancestryVerificationReceiptSha256: h("docker-socket-ancestry-verification-receipt"),
        daemonProbeReceiptSha256: h("docker-daemon-id-probe-receipt"),
        descriptorIdentityReceiptSha256: h("docker-socket-descriptor-identity-receipt"),
        endpointEnumerationReceiptSha256: h("docker-endpoint-enumeration-receipt"),
      },
      capabilityReceiptSha256: h("deployment-account-capability-receipt"),
      effectiveSudoReceiptSha256: h("deployment-account-effective-sudo-receipt"),
      supplementaryGroups: [],
      dockerGroupMembership: false,
      dockerSocketAccess: false,
      rootEquivalentCapabilities: false,
      unrestrictedSudo: false,
      effectiveSudoCommands: [],
      preexisting: true,
      useraddForbidden: true,
      groupaddForbidden: true,
      verifiedAt: ancestryPreVerifiedAt,
    },
    resourceObservation,
    replayClaimPrecondition,
    phaseBInstallerFingerprintSha256: keys.phaseBInstaller.fingerprintSha256,
    activationTargetRootFingerprintSha256: keys.activationTargetRoot.fingerprintSha256,
    phaseBInstallerProducer,
    activationTargetRootProducer: phaseBTargetProducer,
  };
  const targetOutcomes = materializationOutcomes(
    preinstall.installPlan.materializationTargets,
    targetPreconditions,
    preinstall.transactionId,
    privilegeVerifiedAt,
  );
  const resourceOutcome = fixtureResourceOutcome(resourceObservation, privilegeVerifiedAt);
  const receiptObjectKey = domainSha("install-receipt-v1", preinstall.installPlan.plannedReceiptId, preinstall.transactionId);
  const journalRecordPath = `/var/lib/platform-infrastructure/v1-phase-b-ledger/${ledgerEntryKey}.json`;
  const receiptObjectPath = `/var/lib/platform-infrastructure/v1-install-receipts/sha256/${receiptObjectKey}.json`;
  const claimArtifactSha256 = h("phase-b-ledger-claim-artifact");
  const journalArtifactSha256 = h("phase-b-ledger-journal-artifact");
  const receiptArtifactSha256 = h("bootstrap-installer-execution-receipt");
  const claimSizeBytes = 4096;
  const journalRecordSizeBytes = 8192;
  const receiptSizeBytes = 8192;
  const preReceiptResourceDevice = resourceOutcome.devices.find((device) => (
    device.deviceIdentity === ledgerParent.deviceIdentity
      && device.filesystemUuid === ledgerParent.filesystemUuid
  ));
  preReceiptResourceDevice.actualWrittenBytes -= receiptSizeBytes;
  preReceiptResourceDevice.actualCreatedInodes -= 1;
  preReceiptResourceDevice.freeBytes += receiptSizeBytes;
  preReceiptResourceDevice.freeInodes += 1;
  const ledgerLeafIdentity = (pathname, kind, sha256, sizeBytes, index) => materializedIdentity({
    path: pathname, kind, uid: 0, gid: 0, mode: "0400", nlink: 1, sha256, sizeBytes,
  }, index);
  const activationRootOutcome = targetOutcomes.find((entry) => entry.path === preinstall.activationTarget.root);
  const activationTargetPostinstall = {
    ...structuredClone(preinstall.activationTarget),
    rootState: "EXISTING_EXACT",
    rootAbsenceReceiptSha256: null,
    rootIdentity: {
      deviceIdentity: activationRootOutcome.identity.deviceIdentity,
      filesystemUuid: activationRootOutcome.identity.filesystemUuid,
      inode: activationRootOutcome.identity.inode,
      mountId: activationRootOutcome.identity.mountId,
      uid: activationRootOutcome.identity.uid,
      gid: activationRootOutcome.identity.gid,
      mode: activationRootOutcome.identity.mode,
      nlink: activationRootOutcome.identity.nlink,
    },
  };
  const ancestryPostinstall = postInstallAncestry(
    phaseB.preMutationAncestryVerification,
    preinstall.installPlan.materializationTargets,
    phaseB.materializationPreconditions,
  );
  ancestryPostinstall.verifiedAt = privilegeVerifiedAt;
  const postRootParent = ancestryPostinstall.destinationParents
    .find((entry) => entry.path === activationTargetPostinstall.rootParentPath);
  activationTargetPostinstall.rootParentIdentity = {
    deviceIdentity: postRootParent.deviceIdentity,
    filesystemUuid: postRootParent.filesystemUuid,
    inode: postRootParent.inode,
    mountId: postRootParent.mountId,
    uid: postRootParent.uid,
    gid: postRootParent.gid,
    mode: postRootParent.mode,
    nlink: postRootParent.nlink,
  };
  const postinstallPrincipalAuthorityObservation = structuredClone(phaseB.principalAccountObservation);
  postinstallPrincipalAuthorityObservation.accountLookupReceiptSha256 = h("postinstall-account-lookup-receipt");
  postinstallPrincipalAuthorityObservation.passwdEntryReceiptSha256 = h("postinstall-passwd-entry-receipt");
  postinstallPrincipalAuthorityObservation.groupMembershipReceiptSha256 = h("postinstall-group-membership-receipt");
  postinstallPrincipalAuthorityObservation.dockerSocketAclReceiptSha256 = h("postinstall-docker-socket-acl-receipt");
  postinstallPrincipalAuthorityObservation.capabilityReceiptSha256 = h("postinstall-capability-receipt");
  postinstallPrincipalAuthorityObservation.effectiveSudoReceiptSha256 = h("postinstall-effective-sudo-receipt");
  postinstallPrincipalAuthorityObservation.dockerSocketIdentity.aclArtifactSha256
    = postinstallPrincipalAuthorityObservation.dockerSocketAclReceiptSha256;
  postinstallPrincipalAuthorityObservation.dockerSocketIdentity.ancestryVerificationReceiptSha256
    = h("postinstall-docker-socket-ancestry-verification-receipt");
  postinstallPrincipalAuthorityObservation.dockerSocketIdentity.daemonProbeReceiptSha256
    = h("postinstall-docker-daemon-id-probe-receipt");
  postinstallPrincipalAuthorityObservation.dockerSocketIdentity.descriptorIdentityReceiptSha256
    = h("postinstall-docker-socket-descriptor-identity-receipt");
  postinstallPrincipalAuthorityObservation.dockerSocketIdentity.endpointEnumerationReceiptSha256
    = h("postinstall-docker-endpoint-enumeration-receipt");
  postinstallPrincipalAuthorityObservation.effectiveSudoCommands
    = [preinstall.installPlan.privilegePolicy.permittedInvocation];
  postinstallPrincipalAuthorityObservation.verifiedAt = privilegeVerifiedAt;
  const installReceipt = {
    activationTargetPostinstall,
    artifactHashScope: "EXTERNAL-INSTALL-JOURNAL-BYTES",
    artifactSha256: h("install-receipt-artifact"),
    selfHash: false,
    receiptId: preinstall.installPlan.plannedReceiptId,
    installedAt,
    phaseBAuthorizationEnvelopeSha256: phaseB.authorizationEnvelopeSha256,
    phaseBAuthorizationId: phaseB.authorizationId,
    installPlanSha256,
    packageBytesSha256: preinstall.installPlan.packageBytesSha256,
    packageBytesSizeBytes: preinstall.installPlan.packageBytesSizeBytes,
    packageAttestationEnvelopeSha256: preinstall.installPlan.packageAttestationEnvelopeSha256,
    packageManifestSha256: preinstall.installPlan.packageManifestSha256,
    packageManifestSizeBytes: preinstall.installPlan.packageManifestSizeBytes,
    materializationReceiptSha256: h("install-materialization-receipt"),
    materializationPolicy: preinstall.installPlan.materializationPolicy,
    materializationTargets: preinstall.installPlan.materializationTargets,
    materializationTargetOutcomes: targetOutcomes,
    preMutationAncestryVerificationSha256: h(canonicalJson(phaseB.preMutationAncestryVerification)),
    postInstallAncestryVerification: ancestryPostinstall,
    resourceOutcome,
    installerBootstrap: preinstall.installPlan.installerBootstrap,
    installerBootstrapExecutionReceiptSha256: h("bootstrap-installer-execution-receipt"),
    phaseBLedgerConsumption: {
      schema: "platform.v1-phase-b-replay-ledger-consumption/v1",
      ledgerId: "platform-v1-phase-b-installer-ledger",
      ledgerParentPath: "/var/lib",
      claimObjectPath,
      firstWritePath: claimObjectPath,
      journalRecordPath,
      receiptStorePath: "/var/lib/platform-infrastructure/v1-install-receipts/sha256",
      ledgerParentIdentitySha256: h(canonicalJson(phaseB.preMutationAncestryVerification.sourceParents[2])),
      ledgerAncestrySha256: h(canonicalJson(phaseB.preMutationAncestryVerification.sourceParents.slice(0, 3))),
      authorizationEnvelopeSha256: phaseB.authorizationEnvelopeSha256,
      authorizationId: phaseB.authorizationId,
      nonce: phaseB.nonce,
      ledgerEntryKeySha256: ledgerEntryKey,
      receiptObjectKeySha256: receiptObjectKey,
      receiptObjectPath,
      claimId: `phase-b-claim:${ledgerEntryKey}`,
      claimArtifactSha256,
      journalArtifactSha256,
      receiptArtifactSha256,
      claimSizeBytes,
      journalRecordSizeBytes,
      receiptSizeBytes,
      claimNegativeLookupReceiptSha256: replayClaimPrecondition.claimNegativeLookupReceiptSha256,
      journalNegativeLookupReceiptSha256: h("phase-b-journal-negative-lookup-receipt"),
      receiptNegativeLookupReceiptSha256: h("phase-b-receipt-negative-lookup-receipt"),
      claimObjectIdentity: ledgerLeafIdentity(claimObjectPath, "REPLAY_CLAIM", claimArtifactSha256, claimSizeBytes, 30_001),
      journalObjectIdentity: ledgerLeafIdentity(journalRecordPath, "LEDGER_RECORD", journalArtifactSha256, journalRecordSizeBytes, 30_002),
      receiptObjectIdentity: ledgerLeafIdentity(receiptObjectPath, "INSTALL_RECEIPT", receiptArtifactSha256, receiptSizeBytes, 30_003),
      journalParentIdentitySha256: h(canonicalJson(targetOutcomes.find(
        (outcome) => outcome.path === "/var/lib/platform-infrastructure/v1-phase-b-ledger",
      ).identity)),
      receiptParentIdentitySha256: h(canonicalJson(targetOutcomes.find(
        (outcome) => outcome.path === "/var/lib/platform-infrastructure/v1-install-receipts/sha256",
      ).identity)),
      state: "CONSUMED_BEFORE_FIRST_NON_CLAIM_MUTATION",
      claimCreatedAt,
      consumedAt: ledgerConsumedAt,
      firstNonClaimMutationAt: firstWriteAt,
      journalRecordWrittenAt,
      receiptWrittenAt,
      atomicCreateExclusive: true,
      claimDurablyCommitted: true,
      claimFileFsyncCompleted: true,
      claimParentFsyncCompleted: true,
      journalRecordCreatedExclusive: true,
      journalRecordFsyncCompleted: true,
      receiptCreatedExclusive: true,
      receiptFsyncCompleted: true,
      failureTerminal: true,
      replayRejected: true,
    },
    directories: preinstall.installPlan.directories,
    privilegePolicy: preinstall.installPlan.privilegePolicy,
    privilegePolicyTargetVerification: {
      policySha256: preinstall.installPlan.privilegePolicy.sha256,
      phaseBPrincipalAccountObservationSha256: h(canonicalJson(phaseB.principalAccountObservation)),
      stagedBytesSha256: preinstall.installPlan.privilegePolicy.sha256,
      effectiveBytesSha256: preinstall.installPlan.privilegePolicy.sha256,
      principalName: preinstall.installPlan.privilegePolicy.principalName,
      principalUid: preinstall.installPlan.privilegePolicy.principalUid,
      principalGid: preinstall.installPlan.privilegePolicy.principalGid,
      principalAccountIdentityReceiptSha256: postinstallPrincipalAuthorityObservation.accountLookupReceiptSha256,
      postinstallPrincipalAuthorityObservation,
      validatorPath: preinstall.installPlan.privilegePolicy.validatorPath,
      validatorSha256: preinstall.installPlan.privilegePolicy.validatorSha256,
      verificationReceiptSha256: h("target-visudo-verification-receipt"),
      verified: true,
      verifiedAt: privilegeVerifiedAt,
    },
    broker: preinstall.installPlan.broker,
    verifier: preinstall.installPlan.verifier,
    helpers: preinstall.installPlan.helpers,
  };
  return {
    schema: "platform.v1-brownfield-common-tuple/v1",
    transactionId: preinstall.transactionId,
    preinstallTuple: preinstall,
    preinstallTupleSha256,
    backupAttestationEnvelopeSha256: backupEnvelopeSha256,
    phaseBPreInstallAuthorization: phaseB,
    installReceipt,
    ciChallenge: {
      challengeId: h("ci-challenge-id"), nonce: Buffer.alloc(32, 9).toString("base64url"),
      issuedAt: challengeIssuedAt, expiresAt: challengeExpiresAt, maxAgeSeconds: 600,
      repository: "independent-provider/admissioncontroller",
      workflowPath: ".github/workflows/admissionController.yml", workflowSha: "6".repeat(40),
      job: "produce-admissionController", ref: "refs/heads/main", eventName: "workflow_dispatch",
      protectedEnvironment: "v1-admissionController", repositoryId: "700005", repositoryOwnerId: "7005",
      runId: "800005", runAttempt: 1,
    },
  };
}

const LEGACY = Object.freeze({
  HOSTED: Object.freeze({
    hostedPreparationAuthorizationSha256: h("legacy-hosted-authorization"),
    hostedPreparationReceiptSha256: h("legacy-hosted-receipt"),
    hostedFinalDeploymentAdmissionSha256: h("legacy-hosted-final"),
  }),
  DEPLOYMENT: Object.freeze({
    deploymentAdmissionSha256: h("legacy-deployment-admission"),
    stagingRuntimeReceiptSha256: h("legacy-staging-runtime"),
    dastReceiptSha256: h("legacy-dast-receipt"),
  }),
  ACTIVATION: Object.freeze({
    activationPromotionSha256: h("legacy-activation-promotion"),
    sigstoreBundleSha256: h("legacy-sigstore-bundle"),
    dockerAuthorizationSha256: h("legacy-docker-authorization"),
  }),
});

function externalProducer(role, index, commonTuple = null, approvalEvidenceIssuedAt = null) {
  const finalApprovalOffsets = {
    hostedGate: 3_000,
    deploymentGate: 7_000,
    activationGate: 11_000,
    admissionController: 15_000,
  };
  return {
    type: "EXTERNAL-CI",
    role,
    repository: `independent-provider/${role.toLowerCase()}`,
    repositoryId: String(700000 + index),
    repositoryOwnerId: String(7000 + index),
    workflowPath: `.github/workflows/${role}.yml`,
    jobWorkflowSha: String(index + 1).repeat(40),
    headSha: String(index + 2).repeat(40),
    ref: "refs/heads/main",
    eventName: "workflow_dispatch",
    runId: String(800000 + index),
    runAttempt: 1,
    jobName: `produce-${role}`,
    protectedEnvironment: `v1-${role}`,
    approvalDecision: "APPROVED",
    approvalApproverIdentity: `github-user-id:${9000 + index}`,
    approvalEvidenceIdentity: `provider-approval:${role}:${800000 + index}:1`,
    approvalEvidenceSha256: h(`${role}-approval-evidence`),
    approvalEvidenceIssuedAt: approvalEvidenceIssuedAt ?? new Date(
      Date.parse(commonTuple.ciChallenge.issuedAt) + finalApprovalOffsets[role],
    ).toISOString(),
  };
}

function targetRootProducer(role, targetValue, commonTuple = null, attestedAt = null) {
  const exactAttestedAt = attestedAt ?? (role === "sourceTargetCustodian"
    ? commonTuple.preinstallTuple.structuralBackupReceipt.verifiedAt
    : new Date(Date.parse(commonTuple.ciChallenge.issuedAt) + 14_000).toISOString());
  return {
    type: "TARGET-ROOT",
    role,
    targetId: targetValue.targetId,
    machineId: targetValue.machineId,
    endpoint: targetValue.endpoint,
    root: targetValue.root,
    rootState: targetValue.rootState,
    rootAbsenceReceiptSha256: targetValue.rootAbsenceReceiptSha256,
    rootFilesystemIdentitySha256: targetValue.rootFilesystemIdentitySha256,
    rootParentIdentitySha256: h(canonicalJson(targetValue.rootParentIdentity)),
    rootIdentitySha256: targetValue.rootIdentity === null ? null : h(canonicalJson(targetValue.rootIdentity)),
    attestationIdentity: `target-root-attestation:${role}:${h(exactAttestedAt)}`,
    attestationArtifactSha256: h(`${role}-target-root-attestation:${exactAttestedAt}`),
    attestedAt: exactAttestedAt,
  };
}

function producers(commonTuple, backupProducers) {
  const preinstall = commonTuple.preinstallTuple;
  return {
    backupAuthority: backupProducers.backupAuthority,
    sourceTargetCustodian: backupProducers.sourceTargetCustodian,
    hostedGate: externalProducer("hostedGate", 2, commonTuple),
    deploymentGate: externalProducer("deploymentGate", 3, commonTuple),
    activationGate: externalProducer("activationGate", 4, commonTuple),
    admissionController: externalProducer("admissionController", 5, commonTuple),
    activationTargetRoot: targetRootProducer("activationTargetRoot", commonTuple.installReceipt.activationTargetPostinstall, commonTuple),
    phaseBInstaller: commonTuple.phaseBPreInstallAuthorization.phaseBInstallerProducer,
  };
}

function predecessorFor(gate, gatePayloads, gates, keys) {
  const index = GATE_ORDER.indexOf(gate);
  if (index === 0) return null;
  const priorGate = GATE_ORDER[index - 1];
  const role = `${priorGate.toLowerCase()}Gate`;
  return {
    admissionId: gatePayloads[priorGate].admissionId,
    envelopeSha256: gates[priorGate].sha256,
    gate: priorGate,
    payloadSha256: h(canonicalJson(gatePayloads[priorGate])),
    payloadType: PAYLOAD_TYPES.gates[priorGate],
    role,
    rootKeyFingerprintSha256: keys[role].fingerprintSha256,
  };
}

function finalStageIssuedAt(commonTuple, stage) {
  const offsets = { HOSTED: 4_000, DEPLOYMENT: 8_000, ACTIVATION: 12_000, AGGREGATE: 16_000 };
  return new Date(Date.parse(commonTuple.ciChallenge.issuedAt) + offsets[stage]).toISOString();
}

function buildFixture({ now = Date.now() } = {}) {
  const keys = Object.fromEntries(ROLE_NAMES.map((role) => {
    const pair = crypto.generateKeyPairSync("ed25519");
    const keyFingerprint = fingerprint(pair.publicKey);
    return [role, {
      ...pair,
      keyId: keyFingerprint,
      fingerprintSha256: keyFingerprint,
      publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    }];
  }));
  for (const role of ["phaseAPackageAttestor", "phaseAAuthorizationProvider"]) {
    const pair = crypto.generateKeyPairSync("ed25519");
    const keyFingerprint = fingerprint(pair.publicKey);
    keys[role] = {
      ...pair,
      keyId: keyFingerprint,
      fingerprintSha256: keyFingerprint,
      publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    };
  }
  const preinstall = preinstallTuple(now, keys);
  const backupProducers = {
    backupAuthority: externalProducer(
      "backupAuthority", 1, null,
      new Date(Date.parse(preinstall.authoritativeBackupAttestation.attestationIssuedAt) - 10_000).toISOString(),
    ),
    sourceTargetCustodian: targetRootProducer(
      "sourceTargetCustodian", preinstall.sourceTarget, null,
      preinstall.authoritativeBackupAttestation.databaseConsistency.verifiedAt,
    ),
  };
  const preinstallTupleSha256 = h(canonicalJson(preinstall));
  const backupPayload = {
    schema: "platform.v1-authoritative-backup-attestation/v1",
    attestationId: preinstall.authoritativeBackupAttestation.attestationId,
    issuedAt: preinstall.authoritativeBackupAttestation.attestationIssuedAt,
    expiresAt: preinstall.authoritativeBackupAttestation.attestationExpiresAt,
    preinstallTuple: preinstall,
    preinstallTupleSha256,
    backupTrustPolicySha256: preinstall.authoritativeBackupAttestation.backupTrustPolicySha256,
    producers: backupProducers,
    evidence: {
      evidenceArtifactSha256: preinstall.authoritativeBackupAttestation.evidenceArtifactSha256,
      structuralReceiptArtifactSha256: preinstall.structuralBackupReceipt.artifactSha256,
      structuralReceiptId: preinstall.structuralBackupReceipt.receiptId,
      structuralReceiptVerifiedAt: preinstall.structuralBackupReceipt.verifiedAt,
      sourceDeviceSetSha256: preinstall.baseline.sourceDeviceSetSha256,
      backupDeviceIdentity: preinstall.authoritativeBackupAttestation.backupDeviceIdentity,
      backupSetId: preinstall.authoritativeBackupAttestation.backupSetId,
      backupManifestSha256: preinstall.authoritativeBackupAttestation.backupManifestSha256,
      backupArtifactSetSha256: preinstall.authoritativeBackupAttestation.backupArtifactSetSha256,
      protectedArtifactSetSha256: preinstall.authoritativeBackupAttestation.protectedArtifactSetSha256,
      protectedArtifactCount: preinstall.authoritativeBackupAttestation.protectedArtifactCount,
      databaseSetSha256: preinstall.authoritativeBackupAttestation.databaseSetSha256,
      databaseCount: preinstall.authoritativeBackupAttestation.databaseCount,
      captureStartedAt: preinstall.authoritativeBackupAttestation.captureStartedAt,
      captureCompletedAt: preinstall.authoritativeBackupAttestation.captureCompletedAt,
      verifiedAt: preinstall.authoritativeBackupAttestation.verifiedAt,
      offHost: true, sourceDeviceSetExcluded: true,
      offHostRetrieval: preinstall.authoritativeBackupAttestation.offHostRetrieval,
      restoreDrill: preinstall.authoritativeBackupAttestation.restoreDrill,
      databaseConsistency: preinstall.authoritativeBackupAttestation.databaseConsistency,
      writeConsistency: preinstall.authoritativeBackupAttestation.writeConsistency,
      dataRollbackAuthority: false,
    },
  };
  const backup = envelope(PAYLOAD_TYPES.backupAttestation, backupPayload, [
    keys.backupAuthority,
    keys.sourceTargetCustodian,
  ]);
  const commonTuple = finalTuple(preinstall, backup.sha256, keys, now);
  const roleProducers = producers(commonTuple, backupProducers);
  const policy = {
    schema: "platform.v1-brownfield-admission-policy/v1",
    version: 1,
    status: "READY",
    externallyManaged: true,
    selfAssertedEvidenceAccepted: false,
    localMutationAuthority: false,
    reason: "Independent verifier roots and exact transaction tuple delivered through the trusted control channel.",
    freshness: {
      maxLifetimeSeconds: 900,
      maxClockSkewSeconds: 60,
      maxBackupEvidenceAgeSeconds: 1800,
      maxBaselineToBackupLagSeconds: 10800,
    },
    payloadTypes: structuredClone(PAYLOAD_TYPES),
    roots: Object.fromEntries(ROLE_NAMES.map((role) => [role, {
      keyId: keys[role].keyId,
      fingerprintSha256: keys[role].fingerprintSha256,
      publicKeyPem: keys[role].publicKeyPem,
    }])),
    producers: roleProducers,
    expectedPreinstallTuple: preinstall,
    expectedTuple: commonTuple,
    legacyArtifactHashes: structuredClone(LEGACY),
  };
  const policyArtifact = canonicalArtifact(policy);
  const tupleSha256 = h(canonicalJson(commonTuple));

  const gatePayloads = {};
  const gates = {};
  for (const gate of GATE_ORDER) {
    gatePayloads[gate] = {
      schema: "platform.v1-brownfield-gate-admission/v1",
      gate,
      admissionId: h(`${gate}-admission-id`),
      issuedAt: finalStageIssuedAt(commonTuple, gate),
      expiresAt: commonTuple.ciChallenge.expiresAt,
      tuple: commonTuple,
      tupleSha256,
      policySha256: policyArtifact.sha256,
      producer: roleProducers[`${gate.toLowerCase()}Gate`],
      backupAttestationEnvelopeSha256: backup.sha256,
      decision: "PASS",
      externalEvidence: true,
      dataRollbackAuthority: false,
      legacyArtifactHashes: structuredClone(LEGACY[gate]),
      predecessor: predecessorFor(gate, gatePayloads, gates, keys),
    };
    gates[gate] = envelope(PAYLOAD_TYPES.gates[gate], gatePayloads[gate], [keys[`${gate.toLowerCase()}Gate`]]);
  }

  const aggregatePayload = {
    schema: "platform.v1-brownfield-admission/v1",
    admissionId: h("aggregate-admission-id"),
    issuedAt: finalStageIssuedAt(commonTuple, "AGGREGATE"),
    expiresAt: commonTuple.ciChallenge.expiresAt,
    tuple: commonTuple,
    tupleSha256,
    policySha256: policyArtifact.sha256,
    producers: {
      admissionController: roleProducers.admissionController,
      activationTargetRoot: roleProducers.activationTargetRoot,
    },
    backupAttestationEnvelopeSha256: backup.sha256,
    gates: GATE_ORDER.map((gate) => ({
      gate,
      admissionId: gatePayloads[gate].admissionId,
      envelopeSha256: gates[gate].sha256,
      payloadSha256: h(canonicalJson(gatePayloads[gate])),
      legacyArtifactSetSha256: h(canonicalJson(LEGACY[gate])),
      role: `${gate.toLowerCase()}Gate`,
      payloadType: PAYLOAD_TYPES.gates[gate],
      rootKeyFingerprintSha256: keys[`${gate.toLowerCase()}Gate`].fingerprintSha256,
    })),
    decision: "PASS",
    dataRollbackAuthority: false,
  };
  const aggregate = envelope(PAYLOAD_TYPES.aggregate, aggregatePayload, [
    keys.admissionController,
    keys.activationTargetRoot,
  ]);
  return {
    now,
    keys,
    policy,
    policyArtifact,
    backupPayload,
    backup,
    gatePayloads,
    gates,
    aggregatePayload,
    aggregate,
    expectedKeyFingerprints: Object.fromEntries(ROLE_NAMES.map((role) => [role, keys[role].fingerprintSha256])),
  };
}

function verify(fixture) {
  return verifyV1BrownfieldAdmission({
    policyArtifact: fixture.policyArtifact,
    expectedPolicySha256: fixture.policyArtifact.sha256,
    expectedKeyFingerprints: fixture.expectedKeyFingerprints,
    backupAttestationArtifact: fixture.backup,
    gateArtifacts: fixture.gates,
    aggregateArtifact: fixture.aggregate,
    now: fixture.now,
  });
}

function rebindPhaseBLedger(commonTuple) {
  const phaseB = commonTuple.phaseBPreInstallAuthorization;
  const receipt = commonTuple.installReceipt;
  const ledger = receipt.phaseBLedgerConsumption;
  const replayClaim = phaseB.replayClaimPrecondition;
  const ledgerEntryKey = domainSha(
    "phase-b-ledger-v1", phaseB.authorizationId, phaseB.nonce, commonTuple.transactionId,
    phaseB.policySha256, phaseB.preinstallTupleSha256,
  );
  const receiptObjectKey = domainSha("install-receipt-v1", receipt.receiptId, commonTuple.transactionId);
  const oldClaimObjectPath = ledger.claimObjectPath;
  const oldJournalRecordPath = ledger.journalRecordPath;
  const oldReceiptObjectPath = ledger.receiptObjectPath;
  replayClaim.authorizationId = phaseB.authorizationId;
  replayClaim.nonce = phaseB.nonce;
  replayClaim.policySha256 = phaseB.policySha256;
  replayClaim.preinstallTupleSha256 = phaseB.preinstallTupleSha256;
  replayClaim.ledgerEntryKeySha256 = ledgerEntryKey;
  replayClaim.claimObjectPath = `/var/lib/.platform-v1-phase-b-claim-${ledgerEntryKey}`;
  ledger.authorizationEnvelopeSha256 = phaseB.authorizationEnvelopeSha256;
  ledger.authorizationId = phaseB.authorizationId;
  ledger.nonce = phaseB.nonce;
  ledger.ledgerEntryKeySha256 = ledgerEntryKey;
  ledger.claimObjectPath = replayClaim.claimObjectPath;
  ledger.claimId = `phase-b-claim:${ledgerEntryKey}`;
  if (ledger.firstWritePath === oldClaimObjectPath) ledger.firstWritePath = ledger.claimObjectPath;
  ledger.journalRecordPath = `/var/lib/platform-infrastructure/v1-phase-b-ledger/${ledgerEntryKey}.json`;
  ledger.receiptObjectKeySha256 = receiptObjectKey;
  ledger.receiptObjectPath = `${ledger.receiptStorePath}/${receiptObjectKey}.json`;
  if (ledger.claimObjectIdentity.path === oldClaimObjectPath) ledger.claimObjectIdentity.path = ledger.claimObjectPath;
  ledger.claimObjectIdentity.identityReceiptSha256 = h(`materialized-identity:${ledger.claimObjectPath}`);
  if (ledger.journalObjectIdentity.path === oldJournalRecordPath) ledger.journalObjectIdentity.path = ledger.journalRecordPath;
  ledger.journalObjectIdentity.identityReceiptSha256 = h(`materialized-identity:${ledger.journalRecordPath}`);
  if (ledger.receiptObjectIdentity.path === oldReceiptObjectPath) ledger.receiptObjectIdentity.path = ledger.receiptObjectPath;
  ledger.receiptObjectIdentity.identityReceiptSha256 = h(`materialized-identity:${ledger.receiptObjectPath}`);
}

function resignAll(fixture) {
  const tuples = new Set([
    fixture.policy.expectedTuple,
    ...GATE_ORDER.map((gate) => fixture.gatePayloads[gate].tuple),
    fixture.aggregatePayload.tuple,
  ]);
  fixture.backupPayload.preinstallTupleSha256 = h(canonicalJson(fixture.backupPayload.preinstallTuple));
  fixture.backup = envelope(PAYLOAD_TYPES.backupAttestation, fixture.backupPayload, [
    fixture.keys.backupAuthority,
    fixture.keys.sourceTargetCustodian,
  ]);
  for (const tuple of tuples) {
    tuple.backupAttestationEnvelopeSha256 = fixture.backup.sha256;
    tuple.phaseBPreInstallAuthorization.backupAttestationEnvelopeSha256 = fixture.backup.sha256;
    rebindPhaseBLedger(tuple);
  }
  fixture.policyArtifact = canonicalArtifact(fixture.policy);
  for (const gate of GATE_ORDER) {
    fixture.gatePayloads[gate].backupAttestationEnvelopeSha256 = fixture.backup.sha256;
    fixture.gatePayloads[gate].policySha256 = fixture.policyArtifact.sha256;
    fixture.gatePayloads[gate].tupleSha256 = h(canonicalJson(fixture.gatePayloads[gate].tuple));
    fixture.gatePayloads[gate].predecessor = predecessorFor(
      gate, fixture.gatePayloads, fixture.gates, fixture.keys,
    );
    fixture.gates[gate] = envelope(PAYLOAD_TYPES.gates[gate], fixture.gatePayloads[gate], [
      fixture.keys[`${gate.toLowerCase()}Gate`],
    ]);
  }
  fixture.aggregatePayload.backupAttestationEnvelopeSha256 = fixture.backup.sha256;
  fixture.aggregatePayload.policySha256 = fixture.policyArtifact.sha256;
  fixture.aggregatePayload.tupleSha256 = h(canonicalJson(fixture.aggregatePayload.tuple));
  fixture.aggregatePayload.gates = GATE_ORDER.map((gate) => ({
    gate,
    admissionId: fixture.gatePayloads[gate].admissionId,
    envelopeSha256: fixture.gates[gate].sha256,
    payloadSha256: h(canonicalJson(fixture.gatePayloads[gate])),
    legacyArtifactSetSha256: h(canonicalJson(fixture.policy.legacyArtifactHashes[gate])),
    role: `${gate.toLowerCase()}Gate`,
    payloadType: PAYLOAD_TYPES.gates[gate],
    rootKeyFingerprintSha256: fixture.keys[`${gate.toLowerCase()}Gate`].fingerprintSha256,
  }));
  fixture.aggregate = envelope(PAYLOAD_TYPES.aggregate, fixture.aggregatePayload, [
    fixture.keys.admissionController,
    fixture.keys.activationTargetRoot,
  ]);
}

function replaceTuple(fixture, commonTuple) {
  fixture.policy.expectedTuple = commonTuple;
  for (const gate of GATE_ORDER) fixture.gatePayloads[gate].tuple = commonTuple;
  fixture.aggregatePayload.tuple = commonTuple;
}

function replacePreinstallTuple(fixture, preinstall) {
  fixture.policy.expectedPreinstallTuple = preinstall;
  fixture.backupPayload.preinstallTuple = preinstall;
}

function replaceEveryPreinstallTuple(fixture, preinstall) {
  replacePreinstallTuple(fixture, preinstall);
  const commonTuple = structuredClone(fixture.policy.expectedTuple);
  const preinstallTupleSha256 = h(canonicalJson(preinstall));
  commonTuple.preinstallTuple = preinstall;
  commonTuple.preinstallTupleSha256 = preinstallTupleSha256;
  commonTuple.phaseBPreInstallAuthorization.preinstallTupleSha256 = preinstallTupleSha256;
  replaceTuple(fixture, commonTuple);
}

function rebindSourceTargetCustodian(fixture) {
  const previous = fixture.policy.producers.sourceTargetCustodian;
  const producer = targetRootProducer(
    "sourceTargetCustodian",
    fixture.policy.expectedPreinstallTuple.sourceTarget,
    null,
    previous.attestedAt,
  );
  fixture.policy.producers.sourceTargetCustodian = producer;
  fixture.backupPayload.producers.sourceTargetCustodian = producer;
}

test("the supplied signed tranche verifies locally while Phase A and replay enforcement remain external", () => {
  const result = verify(buildFixture());
  assert.equal(result.schema, "platform.v1-brownfield-admission-validation/v1");
  assert.equal(result.status, "LOCAL-VERIFIED-NON-AUTHORITATIVE");
  assert.equal(result.authoritative, false);
  assert.equal(result.chainComplete, false);
  assert.equal(Object.isFrozen(result), true);
  assert.throws(() => { result.chainComplete = true; }, TypeError);
  assert.equal(result.phaseAVerificationStatus, "EXTERNAL-PENDING");
  assert.equal(result.phaseBPreinstallVerificationStatus, "EXTERNAL-PENDING");
  assert.equal(result.replayEnforcementStatus, "EXTERNAL-BROKER-REQUIRED");
  assert.equal(result.runtimeBootstrapTrustStatus, "EXTERNAL-PENDING");
  assert.equal(result.rawBaselineVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.rawBackupReceiptVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.sourceSetRecomputationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.offHostSourceDeviceExclusionVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.restoredCoverageRecomputationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.databaseCoverageRecomputationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.rawBaselineReopened, false);
  assert.equal(result.rawStructuralBackupReceiptReopened, false);
  assert.equal(result.sourceDeviceSetRecomputed, false);
  assert.equal(result.offHostSourceDeviceExclusionRecomputed, false);
  assert.equal(result.restoredCoverageRecomputed, false);
  assert.equal(result.databaseCoverageRecomputed, false);
  assert.equal(result.protectedPathOverlapVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.packageArchiveFormatVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.packageManifestMemberExtractionVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.replayArtifactByteSchemaVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.consumerChallengeAuthorityStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.expectedBindingsAuthorityStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.throws(() => { result.consumerChallengeAuthorityStatus = "PASS"; }, TypeError);
  assert.throws(() => { result.expectedBindingsAuthorityStatus = "PASS"; }, TypeError);
  assert.equal(result.protectedPathSetRecomputed, false);
  assert.equal(result.allInstallWritesDisjointFromProtectedPaths, false);
  assert.equal(result.packageArchiveFormatVerified, false);
  assert.equal(result.packageManifestMembersRecomputed, false);
  assert.equal(result.replayClaimBytesSchemaVerified, false);
  assert.equal(result.replayJournalBytesSchemaVerified, false);
  assert.equal(result.installExecutionReceiptBytesSchemaVerified, false);
  assert.equal(result.consumerChallengeAuthorityVerified, false);
  assert.equal(result.expectedBindingsAuthorityVerified, false);
  assert.equal(result.trustedNativeLauncherRequired, true);
  assert.equal(result.stdoutAuthority, false);
  assert.equal(result.liveAuthorization, false);
  assert.equal(result.mutationAuthority, false);
  assert.equal(result.localMutationAuthority, false);
  assert.deepEqual(result.gates, GATE_ORDER);
  assert.doesNotMatch(canonicalJson(result), /(?:ADMITTED|APPROVED)/);
});

test("the repository policy is EXTERNAL-PENDING and cannot admit anything", () => {
  const fixture = buildFixture();
  const bytes = fs.readFileSync(PENDING_POLICY);
  fixture.policyArtifact = { bytes, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
  assert.throws(() => verify(fixture), /EXTERNAL-PENDING/);
});

test("policy bytes and every role fingerprint require independent caller pins", () => {
  const fixture = buildFixture();
  assert.throws(() => verifyV1BrownfieldAdmission({
    policyArtifact: fixture.policyArtifact,
    expectedPolicySha256: h("wrong-policy"),
    expectedKeyFingerprints: fixture.expectedKeyFingerprints,
    backupAttestationArtifact: fixture.backup,
    gateArtifacts: fixture.gates,
    aggregateArtifact: fixture.aggregate,
    now: fixture.now,
  }), /policy SHA256.*trusted caller/i);
  const missing = { ...fixture.expectedKeyFingerprints };
  delete missing.activationTargetRoot;
  assert.throws(() => verifyV1BrownfieldAdmission({
    policyArtifact: fixture.policyArtifact,
    expectedPolicySha256: fixture.policyArtifact.sha256,
    expectedKeyFingerprints: missing,
    backupAttestationArtifact: fixture.backup,
    gateArtifacts: fixture.gates,
    aggregateArtifact: fixture.aggregate,
    now: fixture.now,
  }), /fingerprint.*exact closed schema|fingerprint.*exact.*roles/i);
});

test("all eight role keys are pairwise distinct and roles cannot be swapped", () => {
  const fixture = buildFixture();
  fixture.policy.roots.activationTargetRoot = structuredClone(fixture.policy.roots.admissionController);
  fixture.expectedKeyFingerprints.activationTargetRoot = fixture.expectedKeyFingerprints.admissionController;
  fixture.policyArtifact = canonicalArtifact(fixture.policy);
  assert.throws(() => verify(fixture), /pairwise distinct/i);

  const swapped = buildFixture();
  swapped.backup = envelope(PAYLOAD_TYPES.backupAttestation, swapped.backupPayload, [
    swapped.keys.sourceTargetCustodian,
    swapped.keys.backupAuthority,
  ]);
  assert.throws(() => verify(swapped), /backupAuthority.*key|authorized key.*backupAuthority/i);
});

test("backup requires both signatures, the exact payload type, off-host proof and restore proof", () => {
  const missing = buildFixture();
  missing.backup = envelope(PAYLOAD_TYPES.backupAttestation, missing.backupPayload, [missing.keys.backupAuthority]);
  assert.throws(() => verify(missing), /signature count/i);

  const wrongType = buildFixture();
  wrongType.backup = envelope("application/json", wrongType.backupPayload, [
    wrongType.keys.backupAuthority,
    wrongType.keys.sourceTargetCustodian,
  ]);
  assert.throws(() => verify(wrongType), /payload type/i);

  const notOffHost = buildFixture();
  notOffHost.backupPayload.evidence.offHost = false;
  resignAll(notOffHost);
  assert.throws(() => verify(notOffHost), /off-host|offHost/i);

  const noRestore = buildFixture();
  noRestore.backupPayload.evidence.restoreDrill.verified = false;
  resignAll(noRestore);
  assert.throws(() => verify(noRestore), /restore/i);
});

test("baseline, backup, restored storage and database coverage counts and sets are exact", () => {
  const partialStorage = buildFixture();
  partialStorage.policy.expectedPreinstallTuple.authoritativeBackupAttestation
    .restoreDrill.restoredArtifactCount -= 1;
  resignAll(partialStorage);
  assert.throws(() => verify(partialStorage), /restored.*artifact.*coverage|manifest parity/i);

  const partialDatabase = buildFixture();
  partialDatabase.policy.expectedPreinstallTuple.authoritativeBackupAttestation
    .databaseConsistency.verifiedDatabaseCount -= 1;
  resignAll(partialDatabase);
  assert.throws(() => verify(partialDatabase), /database.*coverage|database count/i);

  const driftedSet = buildFixture();
  driftedSet.policy.expectedPreinstallTuple.structuralBackupReceipt.protectedArtifactSetSha256
    = h("partial-protected-artifact-set");
  resignAll(driftedSet);
  assert.throws(() => verify(driftedSet), /coverage|protected artifact set/i);
});

test("strict canonical DSSE rejects malformed base64, noncanonical payload and private-key PEM policy roots", () => {
  const badBase64 = buildFixture();
  const document = JSON.parse(badBase64.backup.bytes);
  document.signatures[0].sig = `${document.signatures[0].sig} `;
  badBase64.backup = canonicalArtifact(document);
  assert.throws(() => verify(badBase64), /base64|signature/i);

  const noncanonical = buildFixture();
  const outer = JSON.parse(noncanonical.backup.bytes);
  const payload = JSON.parse(Buffer.from(outer.payload, "base64").toString("utf8"));
  const pretty = Buffer.from(JSON.stringify(payload, null, 2), "utf8");
  outer.payload = pretty.toString("base64");
  outer.signatures = [noncanonical.keys.backupAuthority, noncanonical.keys.sourceTargetCustodian].map((key) => ({
    keyid: key.keyId,
    sig: crypto.sign(null, pae(PAYLOAD_TYPES.backupAttestation, pretty), key.privateKey).toString("base64"),
  }));
  noncanonical.backup = canonicalArtifact(outer);
  assert.throws(() => verify(noncanonical), /canonical JSON/i);

  const privatePem = buildFixture();
  privatePem.policy.roots.hostedGate.publicKeyPem = privatePem.keys.hostedGate.privateKey.export({ type: "pkcs8", format: "pem" });
  privatePem.policyArtifact = canonicalArtifact(privatePem.policy);
  assert.throws(() => verify(privatePem), /SPKI public key PEM/i);
});

test("every artifact must carry the policy's byte-exact common tuple", () => {
  const fixture = buildFixture();
  fixture.gatePayloads.DEPLOYMENT.tuple = structuredClone(fixture.gatePayloads.DEPLOYMENT.tuple);
  fixture.gatePayloads.DEPLOYMENT.tuple.installReceipt.artifactSha256 = h("gate-only-install-receipt-artifact");
  resignAll(fixture);
  assert.throws(() => verify(fixture), /common tuple/i);
});

test("wrong candidate, target, order, baseline and backup bindings fail even when re-signed", () => {
  for (const mutate of [
    (value) => { value.candidate.treeSha = "7".repeat(40); },
    (value) => { value.activationTarget.root = "/srv/other"; },
    (value) => { value.phaseA.orderContractSha256 = h("wrong-order"); },
    (value) => { value.baseline.complete = false; },
    (value) => { value.authoritativeBackupAttestation.evidenceArtifactSha256 = h("wrong-backup"); },
  ]) {
    const fixture = buildFixture();
    fixture.backupPayload.preinstallTuple = structuredClone(fixture.backupPayload.preinstallTuple);
    mutate(fixture.backupPayload.preinstallTuple);
    resignAll(fixture);
    assert.throws(
      () => verify(fixture),
      /common tuple|preinstall tuple|baseline.*complete|ADDITIVE|Phase A authorized candidate|activation target root\/parent identity/i,
    );
  }
});

test("gate names, role-specific payload types, exact order and all envelope/payload hashes are bound", () => {
  const swapped = buildFixture();
  swapped.gatePayloads.HOSTED.gate = "DEPLOYMENT";
  resignAll(swapped);
  assert.throws(() => verify(swapped), /gate identity/i);

  const order = buildFixture();
  order.aggregatePayload.gates.reverse();
  order.aggregate = envelope(PAYLOAD_TYPES.aggregate, order.aggregatePayload, [
    order.keys.admissionController,
    order.keys.activationTargetRoot,
  ]);
  assert.throws(() => verify(order), /gate order/i);

  const hashDrift = buildFixture();
  hashDrift.aggregatePayload.gates[0].payloadSha256 = h("wrong-payload");
  hashDrift.aggregate = envelope(PAYLOAD_TYPES.aggregate, hashDrift.aggregatePayload, [
    hashDrift.keys.admissionController,
    hashDrift.keys.activationTargetRoot,
  ]);
  assert.throws(() => verify(hashDrift), /payload SHA256/i);
});

test("missing, extra and duplicate gate/admission identities fail closed", () => {
  const missing = buildFixture();
  delete missing.gates.ACTIVATION;
  assert.throws(() => verify(missing), /gate artifacts.*exact closed schema/i);

  const extra = buildFixture();
  extra.gates.EXTRA = extra.gates.HOSTED;
  assert.throws(() => verify(extra), /gate artifacts.*exact closed schema/i);

  const duplicate = buildFixture();
  duplicate.gatePayloads.DEPLOYMENT.admissionId = duplicate.gatePayloads.HOSTED.admissionId;
  resignAll(duplicate);
  assert.throws(() => verify(duplicate), /duplicate.*identifier|identifiers.*distinct/i);
});

test("legacy gate hashes cannot be omitted, moved, or replaced", () => {
  const fixture = buildFixture();
  fixture.gatePayloads.HOSTED.legacyArtifactHashes = structuredClone(LEGACY.DEPLOYMENT);
  resignAll(fixture);
  assert.throws(() => verify(fixture), /legacy artifact hashes/i);

  const collision = buildFixture();
  collision.policy.legacyArtifactHashes.DEPLOYMENT.dastReceiptSha256
    = collision.policy.legacyArtifactHashes.HOSTED.hostedPreparationReceiptSha256;
  resignAll(collision);
  assert.throws(() => verify(collision), /Nine role-specific legacy gate evidence artifacts.*distinct/i);
});

test("boolean/integer coercion and data rollback authority are rejected", () => {
  const bool = buildFixture();
  bool.backupPayload.evidence.offHost = 1;
  resignAll(bool);
  assert.throws(() => verify(bool), /off-host|offHost/i);

  const integer = buildFixture();
  integer.policy.expectedTuple.ciChallenge.runAttempt = "1";
  integer.policyArtifact = canonicalArtifact(integer.policy);
  assert.throws(() => verify(integer), /run attempt.*integer/i);

  const rollback = buildFixture();
  rollback.aggregatePayload.dataRollbackAuthority = true;
  rollback.aggregate = envelope(PAYLOAD_TYPES.aggregate, rollback.aggregatePayload, [
    rollback.keys.admissionController,
    rollback.keys.activationTargetRoot,
  ]);
  assert.throws(() => verify(rollback), /data rollback authority/i);
});

test("freshness is bound to the CI challenge and stale artifacts are rejected", () => {
  const stale = buildFixture({ now: Date.parse("2030-01-01T00:00:00.000Z") });
  stale.now = Date.parse("2030-01-01T01:00:00.000Z");
  assert.throws(() => verify(stale), /expired|freshness/i);

  const drift = buildFixture();
  drift.aggregatePayload.expiresAt = new Date(drift.now + 300_000).toISOString();
  drift.aggregate = envelope(PAYLOAD_TYPES.aggregate, drift.aggregatePayload, [
    drift.keys.admissionController,
    drift.keys.activationTargetRoot,
  ]);
  assert.throws(() => verify(drift), /freshness|CI challenge/i);
});

test("Phase A may precede final admission by hours, but every causal edge is monotonic", () => {
  const valid = buildFixture();
  assert.ok(Date.parse(valid.policy.expectedTuple.ciChallenge.issuedAt)
    - Date.parse(valid.policy.expectedTuple.preinstallTuple.phaseA.expiresAt) > 2 * 60 * 60 * 1000);
  assert.equal(verify(valid).status, "LOCAL-VERIFIED-NON-AUTHORITATIVE");

  const preinstallEdges = [
    ["baseline", "captureStartedAt", "phaseA", "issuedAt"],
    ["baseline", "captureCompletedAt", "baseline", "captureStartedAt"],
    ["authoritativeBackupAttestation", "captureStartedAt", "baseline", "captureCompletedAt"],
  ];
  for (const [leftObject, leftKey, rightObject, rightKey] of preinstallEdges) {
    const fixture = buildFixture();
    const changed = structuredClone(fixture.backupPayload.preinstallTuple);
    changed[leftObject][leftKey] = new Date(Date.parse(changed[rightObject][rightKey]) - 1_000).toISOString();
    fixture.backupPayload.preinstallTuple = changed;
    resignAll(fixture);
    assert.throws(() => verify(fixture), /causal timestamps|freshness|preinstall tuple/i);
  }
  const finalOrder = buildFixture();
  const changedFinal = structuredClone(finalOrder.policy.expectedTuple);
  changedFinal.installReceipt.installedAt = new Date(
    Date.parse(changedFinal.phaseBPreInstallAuthorization.verifiedAt) - 1_000,
  ).toISOString();
  replaceTuple(finalOrder, changedFinal);
  resignAll(finalOrder);
  assert.throws(() => verify(finalOrder), /causal timestamps|resource outcome.*after installation/i);
});

test("protected-environment and target-root producer provenance is exact and causal", () => {
  const approval = buildFixture();
  approval.gatePayloads.HOSTED.producer = structuredClone(approval.gatePayloads.HOSTED.producer);
  approval.gatePayloads.HOSTED.producer.approvalDecision = "DENIED";
  resignAll(approval);
  assert.throws(() => verify(approval), /approval decision|producer differs/i);

  const run = buildFixture();
  run.gatePayloads.DEPLOYMENT.producer = structuredClone(run.gatePayloads.DEPLOYMENT.producer);
  run.gatePayloads.DEPLOYMENT.producer.runId = "999999";
  resignAll(run);
  assert.throws(() => verify(run), /approval evidence identity|producer differs from policy/i);

  const targetRoot = buildFixture();
  targetRoot.aggregatePayload.producers.activationTargetRoot = structuredClone(
    targetRoot.aggregatePayload.producers.activationTargetRoot,
  );
  targetRoot.aggregatePayload.producers.activationTargetRoot.machineId = h("wrong-target-machine");
  resignAll(targetRoot);
  assert.throws(() => verify(targetRoot), /target-root producer.*target identity/i);
});

test("final challenge causally encloses protected approvals and ordered stage issuance", () => {
  const preChallenge = buildFixture();
  const beforeChallenge = new Date(
    Date.parse(preChallenge.policy.expectedTuple.ciChallenge.issuedAt) - 1_000,
  ).toISOString();
  preChallenge.policy.producers.hostedGate.approvalEvidenceIssuedAt = beforeChallenge;
  preChallenge.gatePayloads.HOSTED.producer.approvalEvidenceIssuedAt = beforeChallenge;
  resignAll(preChallenge);
  assert.throws(() => verify(preChallenge), /approval.*challenge|causal.*stage/i);

  const issuedBeforeApproval = buildFixture();
  issuedBeforeApproval.gatePayloads.HOSTED.issuedAt = new Date(
    Date.parse(issuedBeforeApproval.policy.producers.hostedGate.approvalEvidenceIssuedAt) - 1_000,
  ).toISOString();
  resignAll(issuedBeforeApproval);
  assert.throws(() => verify(issuedBeforeApproval), /approval.*issuance|causal.*stage/i);

  const reversedStages = buildFixture();
  const challengeAt = Date.parse(reversedStages.policy.expectedTuple.ciChallenge.issuedAt);
  reversedStages.gatePayloads.HOSTED.issuedAt = new Date(challengeAt + 10_000).toISOString();
  reversedStages.gatePayloads.DEPLOYMENT.issuedAt = new Date(challengeAt + 9_000).toISOString();
  resignAll(reversedStages);
  assert.throws(() => verify(reversedStages), /predecessor.*issued|stage order/i);

  const expiryEscapesChallenge = buildFixture();
  expiryEscapesChallenge.gatePayloads.ACTIVATION.expiresAt = new Date(
    Date.parse(expiryEscapesChallenge.policy.expectedTuple.ciChallenge.expiresAt) + 1_000,
  ).toISOString();
  resignAll(expiryEscapesChallenge);
  assert.throws(() => verify(expiryEscapesChallenge), /challenge window|expiry/i);

  const targetRootBeforeChallenge = buildFixture();
  const earlyTargetAttestation = new Date(
    Date.parse(targetRootBeforeChallenge.policy.expectedTuple.ciChallenge.issuedAt) - 1_000,
  ).toISOString();
  targetRootBeforeChallenge.policy.producers.activationTargetRoot.attestedAt = earlyTargetAttestation;
  targetRootBeforeChallenge.aggregatePayload.producers.activationTargetRoot.attestedAt = earlyTargetAttestation;
  resignAll(targetRootBeforeChallenge);
  assert.throws(() => verify(targetRootBeforeChallenge), /target-root attestation time.*causal/i);

  const lateReplayPrecondition = buildFixture();
  lateReplayPrecondition.policy.expectedTuple.phaseBPreInstallAuthorization
    .replayClaimPrecondition.verifiedAt = new Date(
      Date.parse(lateReplayPrecondition.policy.expectedTuple.phaseBPreInstallAuthorization.issuedAt) + 1_000,
    ).toISOString();
  resignAll(lateReplayPrecondition);
  assert.throws(() => verify(lateReplayPrecondition), /causal timestamps/i);
});

test("each gate role and the aggregate dual-signature set are closed", () => {
  const wrongGateRole = buildFixture();
  wrongGateRole.gates.HOSTED = envelope(PAYLOAD_TYPES.gates.HOSTED, wrongGateRole.gatePayloads.HOSTED, [
    wrongGateRole.keys.deploymentGate,
  ]);
  assert.throws(() => verify(wrongGateRole), /hostedGate.*authorized key/i);

  const missingAggregateRole = buildFixture();
  missingAggregateRole.aggregate = envelope(PAYLOAD_TYPES.aggregate, missingAggregateRole.aggregatePayload, [
    missingAggregateRole.keys.admissionController,
  ]);
  assert.throws(() => verify(missingAggregateRole), /signature count/i);

  const extraAggregateRole = buildFixture();
  extraAggregateRole.aggregate = envelope(PAYLOAD_TYPES.aggregate, extraAggregateRole.aggregatePayload, [
    extraAggregateRole.keys.admissionController,
    extraAggregateRole.keys.activationTargetRoot,
    extraAggregateRole.keys.backupAuthority,
  ]);
  assert.throws(() => verify(extraAggregateRole), /signature count/i);
});

test("outer canonical bytes and DSSE PAE are independently enforced", () => {
  const outer = buildFixture();
  outer.backup = {
    bytes: Buffer.from(`${JSON.stringify(JSON.parse(outer.backup.bytes), null, 2)}\n`, "utf8"),
  };
  assert.throws(() => verify(outer), /canonical JSON bytes/i);

  const wrongPae = buildFixture();
  const payloadBytes = Buffer.from(canonicalJson(wrongPae.backupPayload), "utf8");
  wrongPae.backup = canonicalArtifact({
    payload: payloadBytes.toString("base64"),
    payloadType: PAYLOAD_TYPES.backupAttestation,
    signatures: [wrongPae.keys.backupAuthority, wrongPae.keys.sourceTargetCustodian].map((key) => ({
      keyid: key.keyId,
      sig: crypto.sign(null, payloadBytes, key.privateKey).toString("base64"),
    })),
  });
  assert.throws(() => verify(wrongPae), /DSSE signature is invalid/i);
});

test("root ownership and exact helper set are closed while rebuild authority is rejected", () => {
  const uid = buildFixture();
  uid.policy.expectedTuple.preinstallTuple.activationTarget.rootParentIdentity.uid = true;
  uid.policyArtifact = canonicalArtifact(uid.policy);
  assert.throws(() => verify(uid), /UID.*integer|root identity/i);

  const helper = buildFixture();
  const changedHelpers = structuredClone(helper.policy.expectedTuple);
  changedHelpers.preinstallTuple.installPlan.helpers.pop();
  replaceTuple(helper, changedHelpers);
  resignAll(helper);
  assert.throws(() => verify(helper), /exact fixed V1 helper set/i);

  const transition = buildFixture();
  const changedTransition = structuredClone(transition.policy.expectedTuple);
  changedTransition.preinstallTuple.strategy = "INTENTIONAL-REBUILD";
  replaceTuple(transition, changedTransition);
  resignAll(transition);
  assert.throws(() => verify(transition), /ADDITIVE only|rebuild\/destruction/i);

  const wholeHostSource = buildFixture();
  const wholeHostPreinstall = structuredClone(wholeHostSource.policy.expectedPreinstallTuple);
  wholeHostPreinstall.sourceTarget.root = "/";
  wholeHostPreinstall.sourceTarget.rootParentPath = "/";
  replaceEveryPreinstallTuple(wholeHostSource, wholeHostPreinstall);
  resignAll(wholeHostSource);
  assert.throws(() => verify(wholeHostSource), /non-overlapping activation root|overlap.*preserved source/i);

  for (const sourceRoot of ["/var", "/usr/local", "/etc", "/var/", "/usr/local/", "/etc/"]) {
    const overlap = buildFixture();
    const overlapPreinstall = structuredClone(overlap.policy.expectedPreinstallTuple);
    overlapPreinstall.sourceTarget.root = sourceRoot;
    overlapPreinstall.sourceTarget.rootParentPath = path.posix.dirname(sourceRoot);
    replaceEveryPreinstallTuple(overlap, overlapPreinstall);
    resignAll(overlap);
    assert.throws(() => verify(overlap), /normalized absolute path|overlap.*preserved source/i);
  }

  const sibling = buildFixture();
  const siblingPreinstall = structuredClone(sibling.policy.expectedPreinstallTuple);
  siblingPreinstall.sourceTarget.root = "/var/lib/app-data";
  siblingPreinstall.sourceTarget.rootParentPath = "/var/lib";
  const observedVarLib = sibling.policy.expectedTuple.phaseBPreInstallAuthorization
    .preMutationAncestryVerification.sourceParents[2];
  siblingPreinstall.sourceTarget.rootParentIdentity = {
    deviceIdentity: observedVarLib.deviceIdentity,
    filesystemUuid: observedVarLib.filesystemUuid,
    gid: observedVarLib.gid,
    inode: observedVarLib.inode,
    mode: observedVarLib.mode,
    mountId: observedVarLib.mountId,
    nlink: observedVarLib.nlink,
    uid: observedVarLib.uid,
  };
  replaceEveryPreinstallTuple(sibling, siblingPreinstall);
  rebindSourceTargetCustodian(sibling);
  resignAll(sibling);
  assert.equal(verify(sibling).status, "LOCAL-VERIFIED-NON-AUTHORITATIVE");
});

test("PREINSTALL bytes are independent of all future fields and reject future-field injection", () => {
  const fixture = buildFixture();
  const beforeBytes = Buffer.from(fixture.backup.bytes);
  const beforeSha256 = fixture.backup.sha256;
  const futureJob = "verify-brownfield-admission-v2";
  fixture.policy.expectedTuple.ciChallenge.job = futureJob;
  fixture.policy.producers.admissionController.jobName = futureJob;
  fixture.aggregatePayload.producers.admissionController.jobName = futureJob;
  resignAll(fixture);
  assert.equal(fixture.backup.sha256, beforeSha256);
  assert.deepEqual(fixture.backup.bytes, beforeBytes);
  assert.equal(verify(fixture).status, "LOCAL-VERIFIED-NON-AUTHORITATIVE");

  for (const [field, value] of [
    ["finalPolicySha256", h("future-final-policy")],
    ["installReceipt", {}],
    ["finalCiChallenge", {}],
  ]) {
    const injected = buildFixture();
    injected.backupPayload.preinstallTuple[field] = value;
    resignAll(injected);
    assert.throws(() => verify(injected), /preinstall tuple.*exact closed schema/i);
  }
});

test("the exported PREINSTALL validator returns a frozen canonical snapshot for Phase B convergence", () => {
  const fixture = buildFixture();
  const input = fixture.policy.expectedPreinstallTuple;
  const snapshot = validateV1BrownfieldPreinstallTuple(input);
  assert.deepEqual(snapshot, input);
  assert.notEqual(snapshot, input);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.installPlan), true);
  assert.throws(() => { snapshot.strategy = "ADDITIVE"; }, TypeError);
});

test("the exported install-plan validator is the single frozen Phase B accept-set", () => {
  const plan = buildFixture().policy.expectedPreinstallTuple.installPlan;
  const snapshot = validateV1BrownfieldInstallPlan(plan);
  assert.equal(canonicalJson(snapshot), canonicalJson(plan));
  assert.notEqual(snapshot, plan);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.resourceBudget), true);

  const unsafe = structuredClone(plan);
  unsafe.broker.mode = "0755";
  assert.throws(() => validateV1BrownfieldInstallPlan(unsafe), /root-owned|mode 0555/i);
});

test("the exported Phase B evidence validator is the single frozen pre-mutation accept-set", () => {
  const fixture = buildFixture();
  const tuple = fixture.policy.expectedTuple;
  const phaseB = tuple.phaseBPreInstallAuthorization;
  const evidence = {
    materializationPreconditions: phaseB.materializationPreconditions,
    materializationTargetPlanSha256: phaseB.materializationTargetPlanSha256,
    packageInputObservation: phaseB.packageInputObservation,
    preMutationAncestryVerification: phaseB.preMutationAncestryVerification,
    principalAccountObservation: phaseB.principalAccountObservation,
    replayClaimPrecondition: phaseB.replayClaimPrecondition,
    resourceObservation: phaseB.resourceObservation,
  };
  const snapshot = validateV1BrownfieldPhaseBPreinstallEvidence(evidence, tuple.preinstallTuple);
  assert.equal(canonicalJson(snapshot), canonicalJson(evidence));
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.principalAccountObservation.dockerSocketIdentity), true);

  const drift = structuredClone(evidence);
  drift.materializationTargetPlanSha256 = h("wrong-target-plan");
  assert.throws(
    () => validateV1BrownfieldPhaseBPreinstallEvidence(drift, tuple.preinstallTuple),
    /exact canonical materialization target plan/i,
  );
});

test("Phase A package bytes, attestation envelope and manifest cannot be substituted in plan or receipt", () => {
  for (const [field, replacement] of [
    ["packageBytesSha256", h("substituted-package")],
    ["packageAttestationEnvelopeSha256", h("substituted-package-attestation")],
    ["packageManifestSha256", h("substituted-package-manifest")],
  ]) {
    const planned = buildFixture();
    planned.policy.expectedPreinstallTuple.installPlan[field] = replacement;
    resignAll(planned);
    assert.throws(() => verify(planned), /Install plan package bytes, attestation envelope, and manifest differ from Phase A/i);

    const installed = buildFixture();
    installed.policy.expectedTuple.installReceipt[field] = replacement;
    resignAll(installed);
    assert.throws(() => verify(installed), /Actual install receipt differs from Phase A|pinned install plan/i);
  }
});

test("Phase A raw candidate and target bridges reject self-consistent cross-shape substitution", () => {
  const candidate = buildFixture();
  candidate.policy.expectedPreinstallTuple.phaseA.authorizedCandidate.commitSha = "8".repeat(40);
  candidate.policy.expectedPreinstallTuple.phaseA.authorizedCandidateSha256 = h(canonicalJson(
    candidate.policy.expectedPreinstallTuple.phaseA.authorizedCandidate,
  ));
  resignAll(candidate);
  assert.throws(() => verify(candidate), /Phase A authorized candidate/i);

  const targetValue = buildFixture();
  targetValue.policy.expectedPreinstallTuple.phaseA.authorizedTarget.hostname = "other.example.test";
  targetValue.policy.expectedPreinstallTuple.phaseA.authorizedTargetSha256 = h(canonicalJson(
    targetValue.policy.expectedPreinstallTuple.phaseA.authorizedTarget,
  ));
  resignAll(targetValue);
  assert.throws(() => verify(targetValue), /Phase A authorized target/i);
});

test("Phase B scope, bootstrap trust policy, cross-phase nonces and typed artifacts are closed", () => {
  const scope = buildFixture();
  scope.policy.expectedTuple.phaseBPreInstallAuthorization.operationScope.permitted.push("DOCKER_OPERATION");
  resignAll(scope);
  assert.throws(() => verify(scope), /operation scope/i);

  const policy = buildFixture();
  policy.policy.expectedTuple.phaseBPreInstallAuthorization.policySha256 = h("wrong-phase-b-policy");
  resignAll(policy);
  assert.throws(() => verify(policy), /Phase B preinstall authorization.*bindings/i);

  for (const nonceSource of ["phaseA", "ciChallenge"]) {
    const replay = buildFixture();
    replay.policy.expectedTuple.phaseBPreInstallAuthorization.nonce = nonceSource === "phaseA"
      ? replay.policy.expectedPreinstallTuple.phaseA.nonce
      : replay.policy.expectedTuple.ciChallenge.nonce;
    resignAll(replay);
    assert.throws(() => verify(replay), /nonces.*distinct/i);
  }

  const collision = buildFixture();
  collision.policy.expectedTuple.installReceipt.materializationReceiptSha256
    = collision.policy.expectedPreinstallTuple.baseline.artifactSha256;
  resignAll(collision);
  assert.throws(() => verify(collision), /typed artifact hashes.*distinct/i);
});

test("the exact V2 materialization, privilege handoff, directory order and bootstrap identities are enforced", () => {
  for (const mutate of [
    (tuple) => { tuple.installPlan.broker.mode = "0755"; },
    (tuple) => { tuple.installPlan.broker.packageMember = "bin/other"; },
    (tuple) => { tuple.installPlan.broker.sizeBytes = true; },
    (tuple) => { tuple.installPlan.broker.disposition = "REPLACE"; },
    (tuple) => { tuple.installPlan.directories.reverse(); },
    (tuple) => { tuple.installPlan.materializationPolicy.casRoot = "/tmp/caller-selected"; },
    (tuple) => { tuple.installPlan.materializationPolicy.openatNoFollowRequired = false; },
    (tuple) => { tuple.installPlan.materializationPolicy.destinationParents[0].noSymlinkRequired = false; },
    (tuple) => { tuple.installPlan.materializationPolicy.destinationParents.pop(); },
    (tuple) => { tuple.installPlan.materializationPolicy.destinationParents.reverse(); },
    (tuple) => { tuple.installPlan.installerBootstrap.independentlyPinned = false; },
  ]) {
    const fixture = buildFixture();
    mutate(fixture.policy.expectedPreinstallTuple);
    resignAll(fixture);
    assert.throws(() => verify(fixture), /0555|package member|size|disposition|directories|materialization|bootstrap|Destination parents/i);
  }

  for (const mutate of [
    (policy) => { policy.mode = "0644"; },
    (policy) => { policy.permittedInvocation = "/bin/sh"; },
    (policy) => { policy.argumentPolicy = "*"; },
    (policy) => { policy.setenvAllowed = true; },
    (policy) => { policy.parentWritableByNonRoot = true; },
  ]) {
    const fixture = buildFixture();
    mutate(fixture.policy.expectedPreinstallTuple.installPlan.privilegePolicy);
    resignAll(fixture);
    assert.throws(() => verify(fixture), /privilege policy|sudoers/i);
  }

  const targetProof = buildFixture();
  targetProof.policy.expectedTuple.installReceipt.privilegePolicyTargetVerification.verified = false;
  resignAll(targetProof);
  assert.throws(() => verify(targetProof), /target privilege-policy proof/i);

  const parentProof = buildFixture();
  parentProof.policy.expectedTuple.installReceipt.postInstallAncestryVerification.destinationParents[0].symlink = true;
  resignAll(parentProof);
  assert.throws(() => verify(parentProof), /post-install ancestry verification/i);

  const writableAncestor = buildFixture();
  writableAncestor.policy.expectedTuple.installReceipt.postInstallAncestryVerification.destinationParents[1].writableByNonRoot = true;
  resignAll(writableAncestor);
  assert.throws(() => verify(writableAncestor), /post-install ancestry verification/i);
});

test("first-install CAS and namespace hierarchies cannot be pre-staged or adopted", () => {
  for (const select of [
    (tuple) => tuple.preinstallTuple.installPlan.materializationPolicy.casRoot,
    (tuple) => `${tuple.preinstallTuple.installPlan.materializationPolicy.casRoot}/package.bin`,
    () => "/var/lib/platform-infrastructure",
    () => "/srv/platform-infrastructure/releases",
  ]) {
    const fixture = buildFixture();
    const tuple = fixture.policy.expectedTuple;
    const targetPath = select(tuple);
    const index = tuple.preinstallTuple.installPlan.materializationTargets
      .findIndex((entry) => entry.path === targetPath);
    tuple.phaseBPreInstallAuthorization.materializationPreconditions[index]
      = existingMaterializationPrecondition(
        tuple.preinstallTuple.installPlan.materializationTargets[index],
        index,
        tuple.phaseBPreInstallAuthorization.preMutationAncestryVerification,
        tuple.phaseBPreInstallAuthorization.preMutationAncestryVerification.verifiedAt,
      );
    resignAll(fixture);
    assert.throws(() => verify(fixture), /pre-stage|hierarchy.*ABSENT|first-install/i);
  }
});

test("an authorized non-namespace EXISTING_EXACT leaf is accepted only with an unchanged post identity", () => {
  const accepted = buildFixture();
  markBrokerExistingExact(accepted);
  resignAll(accepted);
  assert.equal(verify(accepted).status, "LOCAL-VERIFIED-NON-AUTHORITATIVE");

  const drifted = buildFixture();
  const { outcome } = markBrokerExistingExact(drifted);
  outcome.identity.inode = "59999";
  resignAll(drifted);
  assert.throws(() => verify(drifted), /preexisting materialization target identity changed/i);
});

test("source and destination ancestry share one root and targets cannot cross a mount", () => {
  const splitRoot = buildFixture();
  splitRoot.policy.expectedTuple.phaseBPreInstallAuthorization
    .preMutationAncestryVerification.destinationParents[0].inode = "99999";
  resignAll(splitRoot);
  assert.throws(() => verify(splitRoot), /same path.*identity|shared ancestry/i);

  const foreignLeaf = buildFixture();
  const tuple = foreignLeaf.policy.expectedTuple;
  const outcome = tuple.installReceipt.materializationTargetOutcomes.find(
    (entry) => entry.path.endsWith("/package.bin"),
  );
  outcome.identity.deviceIdentity = "device:foreign-mounted-alias";
  outcome.identity.filesystemUuid = h("foreign-mounted-alias");
  outcome.identity.mountId = "88888";
  resignAll(foreignLeaf);
  assert.throws(() => verify(foreignLeaf), /parent mount|filesystem|NO_XDEV/i);

  const noXdev = buildFixture();
  noXdev.policy.expectedTuple.phaseBPreInstallAuthorization
    .materializationPreconditions[0].openat2ResolveNoXdev = false;
  resignAll(noXdev);
  assert.throws(() => verify(noXdev), /NO_XDEV|mount boundary/i);

  const bindAlias = buildFixture();
  const preAncestry = bindAlias.policy.expectedTuple.phaseBPreInstallAuthorization
    .preMutationAncestryVerification;
  const postAncestry = bindAlias.policy.expectedTuple.installReceipt.postInstallAncestryVerification;
  const sourceVar = preAncestry.sourceParents.find((entry) => entry.path === "/var");
  const destinationSrv = preAncestry.destinationParents.find((entry) => entry.path === "/srv");
  for (const key of ["deviceIdentity", "filesystemUuid", "inode"]) sourceVar[key] = destinationSrv[key];
  assert.notEqual(sourceVar.mountId, destinationSrv.mountId);
  Object.assign(postAncestry.sourceParents.find((entry) => entry.path === "/var"), sourceVar);
  const ledgerAncestrySha256 = h(canonicalJson(preAncestry.sourceParents));
  bindAlias.policy.expectedTuple.phaseBPreInstallAuthorization
    .replayClaimPrecondition.ledgerAncestrySha256 = ledgerAncestrySha256;
  bindAlias.policy.expectedTuple.installReceipt.phaseBLedgerConsumption
    .ledgerAncestrySha256 = ledgerAncestrySha256;
  bindAlias.policy.expectedTuple.installReceipt.preMutationAncestryVerificationSha256
    = h(canonicalJson(preAncestry));
  resignAll(bindAlias);
  assert.throws(() => verify(bindAlias), /aliases one filesystem object|bind.*alias/i);

  const outcomeParentAlias = buildFixture();
  const aliasTuple = outcomeParentAlias.policy.expectedTuple;
  const varLibParent = aliasTuple.phaseBPreInstallAuthorization
    .preMutationAncestryVerification.sourceParents.find((entry) => entry.path === "/var/lib");
  aliasTuple.installReceipt.materializationTargetOutcomes
    .find((outcome) => outcome.path.endsWith("/package.bin")).identity.inode = varLibParent.inode;
  resignAll(outcomeParentAlias);
  assert.throws(() => verify(outcomeParentAlias), /filesystem object.*multiple paths|object alias/i);
});

test("the Phase B preinstall subverifier rejects a preserved source root aliased to write ancestry", () => {
  const fixture = buildFixture();
  const preinstall = fixture.policy.expectedPreinstallTuple;
  const phaseB = fixture.policy.expectedTuple.phaseBPreInstallAuthorization;
  const evidence = Object.fromEntries([
    "materializationPreconditions",
    "materializationTargetPlanSha256",
    "packageInputObservation",
    "preMutationAncestryVerification",
    "principalAccountObservation",
    "replayClaimPrecondition",
    "resourceObservation",
  ].map((key) => [key, structuredClone(phaseB[key])]));
  const destinationRootParent = evidence.preMutationAncestryVerification.destinationParents
    .find((entry) => entry.path === "/usr/local/libexec");
  assert.ok(destinationRootParent);
  for (const key of ["deviceIdentity", "filesystemUuid", "inode"]) {
    destinationRootParent[key] = preinstall.sourceTarget.rootIdentity[key];
  }
  assert.notEqual(destinationRootParent.mountId, preinstall.sourceTarget.rootIdentity.mountId);
  for (const precondition of evidence.materializationPreconditions) {
    if (precondition.anchorPath === destinationRootParent.path) {
      precondition.anchorIdentitySha256 = h(canonicalJson(destinationRootParent));
    }
  }
  evidence.resourceObservation = fixtureResourceObservation(
    preinstall.installPlan,
    evidence.preMutationAncestryVerification,
    evidence.preMutationAncestryVerification.verifiedAt,
  );
  assert.throws(
    () => validateV1BrownfieldPhaseBPreinstallEvidence(evidence, preinstall),
    /filesystem object.*multiple paths|object alias/i,
  );
});

test("created and preexisting directory link identities are derived from exact children", () => {
  const fixture = buildFixture();
  const root = fixture.policy.expectedTuple.installReceipt.materializationTargetOutcomes.find(
    (entry) => entry.path === "/srv/platform-infrastructure",
  );
  root.identity.nlink -= 1;
  resignAll(fixture);
  assert.throws(() => verify(fixture), /directory link count|child nlink/i);
});

test("first-install principal authority is empty before sudoers and broker-only after install", () => {
  const preexistingAuthority = buildFixture();
  preexistingAuthority.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation
    .effectiveSudoCommands = [preexistingAuthority.policy.expectedPreinstallTuple.installPlan.privilegePolicy.permittedInvocation];
  resignAll(preexistingAuthority);
  assert.throws(() => verify(preexistingAuthority), /unprivileged preexisting deployment account/i);

  const dockerGroup = buildFixture();
  dockerGroup.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation.dockerGroupMembership = true;
  dockerGroup.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation.supplementaryGroups = ["docker"];
  resignAll(dockerGroup);
  assert.throws(() => verify(dockerGroup), /unprivileged preexisting deployment account/i);

  const broadPostinstallSudo = buildFixture();
  broadPostinstallSudo.policy.expectedTuple.installReceipt.privilegePolicyTargetVerification
    .postinstallPrincipalAuthorityObservation.unrestrictedSudo = true;
  resignAll(broadPostinstallSudo);
  assert.throws(() => verify(broadPostinstallSudo), /unprivileged preexisting deployment account/i);

  const socketAccess = buildFixture();
  socketAccess.policy.expectedTuple.installReceipt.privilegePolicyTargetVerification
    .postinstallPrincipalAuthorityObservation.dockerSocketIdentity.principalEffectiveAccess = true;
  resignAll(socketAccess);
  assert.throws(() => verify(socketAccess), /Docker socket observation/i);

  const wrongDaemon = buildFixture();
  wrongDaemon.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation
    .dockerSocketIdentity.daemonId = "other-daemon";
  resignAll(wrongDaemon);
  assert.throws(() => verify(wrongDaemon), /Docker socket observation/i);

  const alternateEndpoint = buildFixture();
  alternateEndpoint.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation
    .dockerSocketIdentity.discoveredEndpoints.push("tcp://127.0.0.1:2375");
  resignAll(alternateEndpoint);
  assert.throws(() => verify(alternateEndpoint), /Docker socket observation/i);

  const symlinkedRun = buildFixture();
  symlinkedRun.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation
    .dockerSocketIdentity.parentAncestry[1].symlink = true;
  resignAll(symlinkedRun);
  assert.throws(() => verify(symlinkedRun), /socket parent ancestry/i);

  const hardlinkedSocket = buildFixture();
  hardlinkedSocket.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation
    .dockerSocketIdentity.nlink = 2;
  resignAll(hardlinkedSocket);
  assert.throws(() => verify(hardlinkedSocket), /Docker socket observation/i);

  const followedSocket = buildFixture();
  followedSocket.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation
    .dockerSocketIdentity.descriptorNoFollow = false;
  resignAll(followedSocket);
  assert.throws(() => verify(followedSocket), /Docker socket observation/i);

  const worldWritableSocket = buildFixture();
  for (const socket of [
    worldWritableSocket.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation.dockerSocketIdentity,
    worldWritableSocket.policy.expectedTuple.installReceipt.privilegePolicyTargetVerification
      .postinstallPrincipalAuthorityObservation.dockerSocketIdentity,
  ]) socket.mode = "0666";
  resignAll(worldWritableSocket);
  assert.throws(() => verify(worldWritableSocket), /POSIX|Docker socket observation/i);

  const primaryGroupSocket = buildFixture();
  const principalGid = primaryGroupSocket.policy.expectedTuple.preinstallTuple.activationTarget.deploymentGid;
  for (const socket of [
    primaryGroupSocket.policy.expectedTuple.phaseBPreInstallAuthorization.principalAccountObservation.dockerSocketIdentity,
    primaryGroupSocket.policy.expectedTuple.installReceipt.privilegePolicyTargetVerification
      .postinstallPrincipalAuthorityObservation.dockerSocketIdentity,
  ]) socket.gid = principalGid;
  resignAll(primaryGroupSocket);
  assert.throws(() => verify(primaryGroupSocket), /POSIX|Docker socket observation/i);
});

test("resource budget rejects installer overrun while preserving unrelated brownfield writes", () => {
  const zeroAccounting = buildFixture();
  for (const device of zeroAccounting.policy.expectedTuple.installReceipt.resourceOutcome.devices) {
    device.actualWrittenBytes = 0;
    device.actualCreatedInodes = 0;
  }
  resignAll(zeroAccounting);
  assert.throws(() => verify(zeroAccounting), /mandatory.*accounting|created.*lower bound/i);

  const overrun = buildFixture();
  overrun.policy.expectedTuple.installReceipt.resourceOutcome.devices[0].actualWrittenBytes
    = overrun.policy.expectedTuple.installReceipt.resourceOutcome.devices[0].plannedWriteBytes + 1;
  resignAll(overrun);
  assert.throws(() => verify(overrun), /accounted consumption|exact plan|receipt write\/inode budget/i);

  const concurrentWrites = buildFixture();
  concurrentWrites.policy.expectedTuple.installReceipt.resourceOutcome.devices[0].freeBytes -= 1024 * 1024;
  resignAll(concurrentWrites);
  assert.equal(verify(concurrentWrites).status, "LOCAL-VERIFIED-NON-AUTHORITATIVE");

  const receiptReserve = buildFixture();
  const ledger = receiptReserve.policy.expectedTuple.installReceipt.phaseBLedgerConsumption;
  const receiptDevice = receiptReserve.policy.expectedTuple.installReceipt.resourceOutcome.devices.find((device) => (
    device.deviceIdentity === ledger.receiptObjectIdentity.deviceIdentity
      && device.filesystemUuid === ledger.receiptObjectIdentity.filesystemUuid
  ));
  receiptDevice.freeBytes = receiptDevice.requiredFreeBytesAfter + ledger.receiptSizeBytes - 1;
  resignAll(receiptReserve);
  assert.throws(() => verify(receiptReserve), /reserve.*final.*receipt/i);

  const unreservedReceipt = buildFixture();
  const unreservedLedger = unreservedReceipt.policy.expectedTuple.installReceipt.phaseBLedgerConsumption;
  const unreservedDevice = unreservedReceipt.policy.expectedTuple.installReceipt.resourceOutcome.devices.find((device) => (
    device.deviceIdentity === unreservedLedger.receiptObjectIdentity.deviceIdentity
      && device.filesystemUuid === unreservedLedger.receiptObjectIdentity.filesystemUuid
  ));
  unreservedDevice.actualWrittenBytes = unreservedDevice.plannedWriteBytes;
  unreservedDevice.actualCreatedInodes = unreservedDevice.plannedCreatedInodes;
  resignAll(unreservedReceipt);
  assert.throws(() => verify(unreservedReceipt), /receipt.*write budget|receipt.*inode budget/i);

  const mountSetDrift = buildFixture();
  const destinationFilesystem = mountSetDrift.policy.expectedTuple.phaseBPreInstallAuthorization
    .resourceObservation.devices.find((device) => device.mountIds.length > 1);
  destinationFilesystem.mountIds.pop();
  resignAll(mountSetDrift);
  assert.throws(() => verify(mountSetDrift), /per-device aggregate|resource observation/i);

  const outcomeMountSetDrift = buildFixture();
  outcomeMountSetDrift.policy.expectedTuple.installReceipt.resourceOutcome.devices.at(-1).mountIds = ["99999"];
  resignAll(outcomeMountSetDrift);
  assert.throws(() => verify(outcomeMountSetDrift), /device identity|resource outcome/i);
});

test("replay claim, ledger record and receipt leaves are exact O_EXCL no-follow identities", () => {
  for (const [mutate, expression] of [
    [(ledger) => { ledger.firstWritePath = ledger.journalRecordPath; }, /first write|replay ledger/i],
    [(ledger) => { ledger.journalObjectIdentity.symlink = true; }, /ledger record identity|materialization target identity/i],
    [(ledger) => { ledger.receiptObjectIdentity.nlink = 2; }, /receipt object identity|materialization target identity/i],
    [(ledger) => { ledger.claimObjectIdentity.uid = 1; }, /claim object identity|materialization target identity/i],
  ]) {
    const fixture = buildFixture();
    mutate(fixture.policy.expectedTuple.installReceipt.phaseBLedgerConsumption);
    resignAll(fixture);
    assert.throws(() => verify(fixture), expression);
  }


  const substitutedAbsenceProof = buildFixture();
  substitutedAbsenceProof.policy.expectedTuple.installReceipt.phaseBLedgerConsumption
    .claimNegativeLookupReceiptSha256 = h("substituted-claim-absence-proof");
  resignAll(substitutedAbsenceProof);
  assert.throws(() => verify(substitutedAbsenceProof), /pre-authorized.*claim|claim precondition/i);

  const ledgerLeafAlias = buildFixture();
  const aliasedLedger = ledgerLeafAlias.policy.expectedTuple.installReceipt.phaseBLedgerConsumption;
  aliasedLedger.journalObjectIdentity.inode = aliasedLedger.claimObjectIdentity.inode;
  resignAll(ledgerLeafAlias);
  assert.throws(() => verify(ledgerLeafAlias), /ledger.*filesystem object identities.*distinct|object alias/i);

  const materializationAlias = buildFixture();
  const aliasReceipt = materializationAlias.policy.expectedTuple.installReceipt;
  const casPackage = aliasReceipt.materializationTargetOutcomes.find((outcome) => outcome.path.endsWith("/package.bin"));
  aliasReceipt.phaseBLedgerConsumption.claimObjectIdentity.inode = casPackage.identity.inode;
  resignAll(materializationAlias);
  assert.throws(() => verify(materializationAlias), /ledger.*filesystem object identities.*distinct|object alias/i);
});

test("post-install activation root and typed receipts cannot drift or alias", () => {
  const staleParent = buildFixture();
  staleParent.policy.expectedTuple.installReceipt.activationTargetPostinstall.rootParentIdentity.nlink -= 1;
  resignAll(staleParent);
  assert.throws(() => verify(staleParent), /Post-install activation target/i);

  const rootFilesystem = buildFixture();
  rootFilesystem.policy.expectedTuple.installReceipt.activationTargetPostinstall.rootFilesystemIdentitySha256 = h("drifted-root-fs");
  resignAll(rootFilesystem);
  assert.throws(() => verify(rootFilesystem), /Post-install activation target/i);

  const receiptAlias = buildFixture();
  receiptAlias.policy.expectedTuple.phaseBPreInstallAuthorization.packageInputObservation.descriptorIdentityReceiptSha256
    = receiptAlias.policy.expectedTuple.phaseBPreInstallAuthorization.resourceObservation.receiptSha256;
  resignAll(receiptAlias);
  assert.throws(() => verify(receiptAlias), /typed artifact hashes.*distinct/i);
});

test("post-install evidence follows its exact materialization and precedes the final execution receipt", () => {
  const sudoersBeforeOutcome = buildFixture();
  const tuple = sudoersBeforeOutcome.policy.expectedTuple;
  const sudoersOutcome = tuple.installReceipt.materializationTargetOutcomes.find(
    (outcome) => outcome.path === tuple.installReceipt.privilegePolicy.path,
  );
  sudoersOutcome.verifiedAt = new Date(
    Date.parse(tuple.installReceipt.privilegePolicyTargetVerification.verifiedAt) + 1_000,
  ).toISOString();
  resignAll(sudoersBeforeOutcome);
  assert.throws(() => verify(sudoersBeforeOutcome), /causal timestamps/i);

  const receiptBeforeFinalChecks = buildFixture();
  receiptBeforeFinalChecks.policy.expectedTuple.installReceipt.phaseBLedgerConsumption.receiptWrittenAt = new Date(
    Date.parse(receiptBeforeFinalChecks.policy.expectedTuple.installReceipt.resourceOutcome.verifiedAt) - 1_000,
  ).toISOString();
  resignAll(receiptBeforeFinalChecks);
  assert.throws(() => verify(receiptBeforeFinalChecks), /causal timestamps/i);
});

test("Phase A signer keys remain distinct from all eight core roots and future-role mapping is exact", () => {
  const reused = buildFixture();
  reused.policy.expectedPreinstallTuple.phaseA.packageAttestorKeyId = reused.keys.hostedGate.keyId;
  const preinstallSha256 = h(canonicalJson(reused.policy.expectedPreinstallTuple));
  reused.policy.expectedTuple.preinstallTupleSha256 = preinstallSha256;
  reused.policy.expectedTuple.phaseBPreInstallAuthorization.preinstallTupleSha256 = preinstallSha256;
  resignAll(reused);
  assert.throws(() => verify(reused), /Phase A signer and core role keys.*distinct/i);

  const mapping = buildFixture();
  mapping.policy.expectedPreinstallTuple.phaseA.futureRoleKeyIds.deploymentGate
    = mapping.keys.activationGate.keyId;
  const mappingSha256 = h(canonicalJson(mapping.policy.expectedPreinstallTuple));
  mapping.policy.expectedTuple.preinstallTupleSha256 = mappingSha256;
  mapping.policy.expectedTuple.phaseBPreInstallAuthorization.preinstallTupleSha256 = mappingSha256;
  resignAll(mapping);
  assert.throws(() => verify(mapping), /future-role key IDs|pairwise distinct/i);
});

test("external producers use role/run-bound approvals and independent workflow, run and evidence domains", () => {
  const identity = buildFixture();
  identity.policy.producers.hostedGate.approvalEvidenceIdentity = "provider-approval:hostedGate:OTHER:9";
  resignAll(identity);
  assert.throws(() => verify(identity), /approval evidence identity.*exact role, run ID, and run attempt/i);

  const reused = buildFixture();
  const hosted = reused.policy.producers.hostedGate;
  const deployment = {
    ...structuredClone(hosted),
    role: "deploymentGate",
    approvalEvidenceIdentity: `provider-approval:deploymentGate:${hosted.runId}:${hosted.runAttempt}`,
  };
  reused.policy.producers.deploymentGate = deployment;
  reused.gatePayloads.DEPLOYMENT.producer = deployment;
  resignAll(reused);
  assert.throws(() => verify(reused), /producer repository identities|producer workflow identities|producer run\/job identities|approval evidence artifacts/i);
});

test("repository and workflow identities obey the exact schema length bounds", () => {
  const repository = buildFixture();
  const preinstall = structuredClone(repository.policy.expectedPreinstallTuple);
  const oversizedRepository = `a/${"b".repeat(255)}`;
  assert.equal(oversizedRepository.length, 257);
  preinstall.candidate.repository = oversizedRepository;
  preinstall.phaseA.authorizedCandidate.repository = oversizedRepository;
  preinstall.phaseA.authorizedCandidateSha256 = h(canonicalJson(preinstall.phaseA.authorizedCandidate));
  replaceEveryPreinstallTuple(repository, preinstall);
  resignAll(repository);
  assert.throws(() => verify(repository), /repository.*canonical|repository.*length/i);

  const workflow = buildFixture();
  const workflowPrefix = ".github/workflows/";
  const workflowSuffix = ".yml";
  const oversizedWorkflowPath = `${workflowPrefix}${"a".repeat(257 - workflowPrefix.length - workflowSuffix.length)}${workflowSuffix}`;
  assert.equal(oversizedWorkflowPath.length, 257);
  workflow.policy.producers.hostedGate.workflowPath = oversizedWorkflowPath;
  workflow.gatePayloads.HOSTED.producer.workflowPath = oversizedWorkflowPath;
  resignAll(workflow);
  assert.throws(() => verify(workflow), /workflow path.*canonical|workflow path.*length/i);
});

test("the final challenge is the exact independent admission-controller run identity", () => {
  for (const mutate of [
    (fixture) => {
      const candidate = fixture.policy.expectedPreinstallTuple.candidate;
      Object.assign(fixture.policy.expectedTuple.ciChallenge, {
        repository: candidate.repository,
        repositoryId: candidate.repositoryId,
        repositoryOwnerId: candidate.repositoryOwnerId,
      });
    },
    (fixture) => { fixture.policy.expectedTuple.ciChallenge.repository = "INDEPENDENT-PROVIDER/ADMISSIONCONTROLLER"; },
    (fixture) => {
      fixture.policy.expectedTuple.ciChallenge.runId = fixture.policy.producers.hostedGate.runId;
    },
  ]) {
    const fixture = buildFixture();
    mutate(fixture);
    resignAll(fixture);
    assert.throws(() => verify(fixture), /challenge.*repository|admission-controller.*identity|candidate-controlled/i);
  }
});

test("target-root attestation identities are stage-distinct", () => {
  const fixture = buildFixture();
  fixture.policy.producers.activationTargetRoot.attestationIdentity
    = fixture.policy.expectedTuple.phaseBPreInstallAuthorization.activationTargetRootProducer.attestationIdentity;
  fixture.aggregatePayload.producers.activationTargetRoot.attestationIdentity
    = fixture.policy.producers.activationTargetRoot.attestationIdentity;
  resignAll(fixture);
  assert.throws(() => verify(fixture), /attestation identities.*distinct|stage-distinct/i);
});

test("DEPLOYMENT and ACTIVATION cryptographically bind their exact predecessor gate", () => {
  const deployment = buildFixture();
  deployment.gatePayloads.DEPLOYMENT.predecessor.envelopeSha256 = h("wrong-hosted-envelope");
  deployment.gates.DEPLOYMENT = envelope(PAYLOAD_TYPES.gates.DEPLOYMENT, deployment.gatePayloads.DEPLOYMENT, [
    deployment.keys.deploymentGate,
  ]);
  assert.throws(() => verify(deployment), /DEPLOYMENT predecessor.*exact HOSTED/i);

  const activation = buildFixture();
  activation.gatePayloads.ACTIVATION.predecessor = structuredClone(activation.gatePayloads.DEPLOYMENT.predecessor);
  activation.gates.ACTIVATION = envelope(PAYLOAD_TYPES.gates.ACTIVATION, activation.gatePayloads.ACTIVATION, [
    activation.keys.activationGate,
  ]);
  assert.throws(() => verify(activation), /ACTIVATION predecessor.*exact DEPLOYMENT/i);
});

function setBackupExpiry(fixture, expiresAt) {
  fixture.policy.expectedPreinstallTuple.authoritativeBackupAttestation.attestationExpiresAt = expiresAt;
  fixture.backupPayload.expiresAt = expiresAt;
  const preinstallTupleSha256 = h(canonicalJson(fixture.policy.expectedPreinstallTuple));
  fixture.backupPayload.preinstallTupleSha256 = preinstallTupleSha256;
  fixture.policy.expectedTuple.preinstallTupleSha256 = preinstallTupleSha256;
  fixture.policy.expectedTuple.phaseBPreInstallAuthorization.preinstallTupleSha256 = preinstallTupleSha256;
  fixture.backup = envelope(PAYLOAD_TYPES.backupAttestation, fixture.backupPayload, [
    fixture.keys.backupAuthority,
    fixture.keys.sourceTargetCustodian,
  ]);
  fixture.policy.expectedTuple.backupAttestationEnvelopeSha256 = fixture.backup.sha256;
  fixture.policy.expectedTuple.phaseBPreInstallAuthorization.backupAttestationEnvelopeSha256 = fixture.backup.sha256;
  resignAll(fixture);
}

test("final challenge and aggregate verification remain inside authoritative backup recoverability", () => {
  const challengeAfterExpiry = buildFixture();
  setBackupExpiry(challengeAfterExpiry, new Date(challengeAfterExpiry.now - 60_000).toISOString());
  assert.throws(() => verify(challengeAfterExpiry), /causal timestamps|backup.*expired/i);

  const verificationAfterExpiry = buildFixture();
  setBackupExpiry(verificationAfterExpiry, new Date(verificationAfterExpiry.now - 1_000).toISOString());
  assert.throws(() => verify(verificationAfterExpiry), /backup recoverability expired/i);
});

test("JSON schemas mirror the runtime PREINSTALL and FINAL closed shapes", () => {
  const fixture = buildFixture();
  const common = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIRECTORY, "v1-brownfield-common-tuple.schema.json"), "utf8"));
  const backup = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIRECTORY, "v1-authoritative-backup-attestation.schema.json"), "utf8"));
  const gate = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIRECTORY, "v1-brownfield-gate-admission.schema.json"), "utf8"));
  const aggregate = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIRECTORY, "v1-brownfield-admission.schema.json"), "utf8"));
  const closed = (schemaValue, sample) => {
    assert.equal(schemaValue.additionalProperties, false);
    assert.deepEqual([...schemaValue.required].sort(), Object.keys(sample).sort());
    assert.deepEqual(Object.keys(schemaValue.properties).sort(), Object.keys(sample).sort());
  };
  const recursivelyClosed = (value, label = "schema") => {
    if (Array.isArray(value)) {
      value.forEach((entry, index) => recursivelyClosed(entry, `${label}[${index}]`));
      return;
    }
    if (value === null || typeof value !== "object") return;
    const constraintOnlyObject = /(?:\.allOf\[\d+\]|\.(?:if|then|else))$/.test(label);
    if (value.type === "object" && !constraintOnlyObject) {
      assert.equal(value.additionalProperties, false, `${label} must reject unknown properties`);
      assert.deepEqual(
        [...(value.required ?? [])].sort(),
        Object.keys(value.properties ?? {}).sort(),
        `${label} required/properties drift`,
      );
    }
    for (const [key, entry] of Object.entries(value)) recursivelyClosed(entry, `${label}.${key}`);
  };
  recursivelyClosed(common, "common");
  recursivelyClosed(backup, "backup");
  recursivelyClosed(gate, "gate");
  recursivelyClosed(aggregate, "aggregate");
  closed(common.$defs.preinstallTuple, fixture.policy.expectedPreinstallTuple);
  closed(common.$defs.commonTuple, fixture.policy.expectedTuple);
  closed(common.$defs.phaseA, fixture.policy.expectedPreinstallTuple.phaseA);
  closed(common.$defs.installPlan, fixture.policy.expectedPreinstallTuple.installPlan);
  closed(common.$defs.binaryIdentity, fixture.policy.expectedPreinstallTuple.installPlan.broker);
  closed(common.$defs.privilegePolicy, fixture.policy.expectedPreinstallTuple.installPlan.privilegePolicy);
  closed(common.$defs.materializationPolicy, fixture.policy.expectedPreinstallTuple.installPlan.materializationPolicy);
  closed(common.$defs.phaseBPreInstallAuthorization, fixture.policy.expectedTuple.phaseBPreInstallAuthorization);
  closed(common.$defs.baseline, fixture.policy.expectedPreinstallTuple.baseline);
  closed(common.$defs.structuralBackupReceipt, fixture.policy.expectedPreinstallTuple.structuralBackupReceipt);
  closed(
    common.$defs.authoritativeBackupBinding,
    fixture.policy.expectedPreinstallTuple.authoritativeBackupAttestation,
  );
  closed(
    common.$defs.offHostRetrieval,
    fixture.policy.expectedPreinstallTuple.authoritativeBackupAttestation.offHostRetrieval,
  );
  closed(common.$defs.restoreDrill, fixture.policy.expectedPreinstallTuple.authoritativeBackupAttestation.restoreDrill);
  closed(
    common.$defs.databaseConsistency,
    fixture.policy.expectedPreinstallTuple.authoritativeBackupAttestation.databaseConsistency,
  );
  closed(
    common.$defs.replayClaimPrecondition,
    fixture.policy.expectedTuple.phaseBPreInstallAuthorization.replayClaimPrecondition,
  );
  closed(
    common.$defs.resourceObservationDevice,
    fixture.policy.expectedTuple.phaseBPreInstallAuthorization.resourceObservation.devices[0],
  );
  closed(
    common.$defs.resourceOutcomeDevice,
    fixture.policy.expectedTuple.installReceipt.resourceOutcome.devices[0],
  );
  closed(
    common.$defs.materializedIdentity,
    fixture.policy.expectedTuple.installReceipt.materializationTargetOutcomes[0].identity,
  );
  closed(backup.properties.evidence, fixture.backupPayload.evidence);
  closed(common.$defs.installReceipt, fixture.policy.expectedTuple.installReceipt);
  closed(common.$defs.ciChallenge, fixture.policy.expectedTuple.ciChallenge);
  closed(backup, fixture.backupPayload);
  closed(gate, fixture.gatePayloads.HOSTED);
  closed(aggregate, fixture.aggregatePayload);
  const noncePattern = new RegExp(common.$defs.nonce.pattern);
  assert.equal(noncePattern.test(fixture.policy.expectedPreinstallTuple.phaseA.nonce), true);
  assert.equal(noncePattern.test(`${"A".repeat(42)}B`), false);
  assert.equal(common.$defs.binaryIdentity.properties.mode.const, "0555");
  assert.equal(common.$defs.binaryIdentity.properties.nlink.const, 1);
  assert.equal(common.$defs.preinstallTuple.properties.installReceipt, undefined);
  assert.equal(backup.properties.finalPolicySha256, undefined);
  assert.ok(gate.required.includes("predecessor"));
  assert.equal(new RegExp(common.$defs.sshEndpoint.pattern).test("ssh://deploy@host.example.test:65535"), true);
  assert.equal(new RegExp(common.$defs.sshEndpoint.pattern).test("ssh://deploy@host.example.test:65536"), false);
  assert.equal(new RegExp(common.$defs.timestamp.pattern).test("2026-13-40T25:61:61.000Z"), false);
  assert.equal(new RegExp(common.$defs.timestamp.pattern).test("2024-02-29T23:59:59.999Z"), true);
  assert.equal(new RegExp(common.$defs.timestamp.pattern).test("2025-02-29T00:00:00.000Z"), false);
  assert.equal(
    common.$defs.phaseBPreInstallAuthorization.properties.phaseBInstallerProducer
      .allOf[1].properties.role.const,
    "phaseBInstaller",
  );
  assert.deepEqual(
    common.$defs.phaseBPreInstallAuthorization.properties.activationTargetRootProducer
      .allOf[1].properties,
    { role: { const: "activationTargetRoot" }, rootState: { const: "ABSENT_PROVEN" } },
  );
  assert.equal(
    backup.properties.producers.properties.sourceTargetCustodian.allOf[1].properties.rootState.const,
    "EXISTING_EXACT",
  );
  assert.equal(
    aggregate.properties.producers.properties.activationTargetRoot.allOf[1].properties.rootState.const,
    "EXISTING_EXACT",
  );
  assert.equal(
    common.$defs.postinstallPrincipalAccountObservation.allOf[1]
      .properties.effectiveSudoCommands.minItems,
    1,
  );

  const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: true });
  addFormats(ajv);
  for (const schemaValue of [common, backup, gate, aggregate]) ajv.addSchema(schemaValue);
  const validator = (identifier) => {
    const compiled = ajv.getSchema(identifier);
    assert.ok(compiled, `missing compiled schema ${identifier}`);
    return compiled;
  };
  const validatePreinstall = validator(`${common.$id}#/$defs/preinstallTuple`);
  const validateCommon = validator(`${common.$id}#/$defs/commonTuple`);
  const validateBackup = validator(backup.$id);
  const validateGate = validator(gate.$id);
  const validateAggregate = validator(aggregate.$id);
  const accepts = (compiled, sample, label) => {
    assert.equal(compiled(sample), true, `${label}: ${ajv.errorsText(compiled.errors)}`);
  };
  const rejects = (compiled, sample, label) => {
    assert.equal(compiled(sample), false, `${label} was accepted by the static schema`);
  };

  accepts(validatePreinstall, fixture.policy.expectedPreinstallTuple, "PREINSTALL fixture");
  accepts(validateCommon, fixture.policy.expectedTuple, "FINAL common tuple fixture");
  accepts(validateBackup, fixture.backupPayload, "backup fixture");
  for (const gateName of GATE_ORDER) accepts(validateGate, fixture.gatePayloads[gateName], `${gateName} fixture`);
  accepts(validateAggregate, fixture.aggregatePayload, "aggregate fixture");
  const existingExact = buildFixture();
  markBrokerExistingExact(existingExact);
  accepts(validateCommon, existingExact.policy.expectedTuple, "EXISTING_EXACT common tuple fixture");

  const missingCoverage = structuredClone(fixture.backupPayload);
  delete missingCoverage.evidence.protectedArtifactSetSha256;
  rejects(validateBackup, missingCoverage, "backup missing protected coverage");
  const missingReplayClaim = structuredClone(fixture.policy.expectedTuple);
  delete missingReplayClaim.phaseBPreInstallAuthorization.replayClaimPrecondition;
  rejects(validateCommon, missingReplayClaim, "FINAL tuple missing replay precondition");
  const missingMountSet = structuredClone(fixture.policy.expectedTuple);
  delete missingMountSet.phaseBPreInstallAuthorization.resourceObservation.devices[0].mountIds;
  rejects(validateCommon, missingMountSet, "FINAL tuple missing resource mount set");
  const swappedPhaseBRole = structuredClone(fixture.policy.expectedTuple);
  swappedPhaseBRole.phaseBPreInstallAuthorization.phaseBInstallerProducer.role = "hostedGate";
  rejects(validateCommon, swappedPhaseBRole, "Phase B producer role swap");
  const wrongPhaseBRootState = structuredClone(fixture.policy.expectedTuple);
  wrongPhaseBRootState.phaseBPreInstallAuthorization.activationTargetRootProducer.rootState = "EXISTING_EXACT";
  rejects(validateCommon, wrongPhaseBRootState, "Phase B target-root state swap");
  const emptyPostinstallSudo = structuredClone(fixture.policy.expectedTuple);
  emptyPostinstallSudo.installReceipt.privilegePolicyTargetVerification
    .postinstallPrincipalAuthorityObservation.effectiveSudoCommands = [];
  rejects(validateCommon, emptyPostinstallSudo, "empty post-install effective sudo command set");
  const wrongExecutableMode = structuredClone(fixture.policy.expectedTuple);
  wrongExecutableMode.installReceipt.materializationTargetOutcomes
    .find((entry) => entry.identity.kind === "EXECUTABLE").identity.mode = "0755";
  rejects(validateCommon, wrongExecutableMode, "non-canonical executable mode");
  const invalidTimestamp = structuredClone(fixture.policy.expectedTuple);
  invalidTimestamp.ciChallenge.issuedAt = "2025-02-29T00:00:00.000Z";
  rejects(validateCommon, invalidTimestamp, "invalid calendar timestamp");
  const invalidEndpoint = structuredClone(fixture.policy.expectedPreinstallTuple);
  invalidEndpoint.activationTarget.endpoint = "ssh://deploy@activation.example.test:65536";
  rejects(validatePreinstall, invalidEndpoint, "out-of-range SSH port");
  const oversizedRepository = structuredClone(fixture.policy.expectedPreinstallTuple);
  oversizedRepository.candidate.repository = `a/${"b".repeat(255)}`;
  rejects(validatePreinstall, oversizedRepository, "oversized candidate repository");
  const oversizedWorkflow = structuredClone(fixture.gatePayloads.HOSTED);
  oversizedWorkflow.producer.workflowPath = `.github/workflows/${"a".repeat(235)}.yml`;
  assert.equal(oversizedWorkflow.producer.workflowPath.length, 257);
  rejects(validateGate, oversizedWorkflow, "oversized producer workflow path");
});

function writeFixture(directory, fixture) {
  const files = {
    policy: path.join(directory, "policy.json"),
    backup: path.join(directory, "backup.json"),
    hosted: path.join(directory, "hosted.json"),
    deployment: path.join(directory, "deployment.json"),
    activation: path.join(directory, "activation.json"),
    aggregate: path.join(directory, "aggregate.json"),
  };
  fs.writeFileSync(files.policy, fixture.policyArtifact.bytes);
  fs.writeFileSync(files.backup, fixture.backup.bytes);
  fs.writeFileSync(files.hosted, fixture.gates.HOSTED.bytes);
  fs.writeFileSync(files.deployment, fixture.gates.DEPLOYMENT.bytes);
  fs.writeFileSync(files.activation, fixture.gates.ACTIVATION.bytes);
  fs.writeFileSync(files.aggregate, fixture.aggregate.bytes);
  return files;
}

function cliArgs(files, fixture) {
  const args = [
    SCRIPT,
    "--policy", files.policy,
    "--backup-attestation", files.backup,
    "--hosted-gate", files.hosted,
    "--deployment-gate", files.deployment,
    "--activation-gate", files.activation,
    "--aggregate", files.aggregate,
    "--expected-policy-sha256", fixture.policyArtifact.sha256,
  ];
  for (const role of ROLE_NAMES) args.push("--expected-key-fingerprint", `${role}=${fixture.expectedKeyFingerprints[role]}`);
  return args;
}

test("CLI accepts only all explicit inputs and prints one non-authoritative result", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "v1-admission-test-"));
  try {
    const fixture = buildFixture();
    const files = writeFixture(directory, fixture);
    const result = spawnSync(process.execPath, cliArgs(files, fixture), {
      cwd: ROOT,
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: directory },
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.status, "LOCAL-VERIFIED-NON-AUTHORITATIVE");
    assert.equal(output.localMutationAuthority, false);
    assert.equal(output.runtimeBootstrapTrustStatus, "EXTERNAL-PENDING");
    assert.equal(output.trustedNativeLauncherRequired, true);
    assert.equal(output.stdoutAuthority, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CLI has no application-level defaults, environment-selected artifact paths, sign/mint/write/output modes or duplicate flags", () => {
  const attempts = [
    [],
    ["--policy", PENDING_POLICY],
    ["--sign", "x"],
    ["--mint", "x"],
    ["--create", "x"],
    ["--output", "x"],
    ["--policy", PENDING_POLICY, "--policy", PENDING_POLICY],
  ];
  for (const args of attempts) {
    const result = spawnSync(process.execPath, [SCRIPT, ...args], {
      cwd: ROOT,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        V1_ADMISSION_POLICY: "/tmp/fake-ready-policy.json",
        V1_ADMISSION_BYPASS: "READY",
      },
    });
    assert.notEqual(result.status, 0, JSON.stringify(args));
    assert.match(result.stderr, /Usage:|arguments/i);
  }
});

test("CLI O_NOFOLLOW reads reject symlinks and bounded artifacts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "v1-admission-test-"));
  try {
    const fixture = buildFixture();
    const files = writeFixture(directory, fixture);
    const link = path.join(directory, "policy-link.json");
    fs.symlinkSync(files.policy, link);
    files.policy = link;
    const symlink = spawnSync(process.execPath, cliArgs(files, fixture), { cwd: ROOT, encoding: "utf8" });
    assert.notEqual(symlink.status, 0);
    assert.match(symlink.stderr, /symlink|safely|O_NOFOLLOW/i);

    fs.unlinkSync(link);
    fs.writeFileSync(link, Buffer.alloc(MAX_BYTES + 1, 0x61));
    files.policy = link;
    const oversized = spawnSync(process.execPath, cliArgs(files, fixture), { cwd: ROOT, encoding: "utf8" });
    assert.notEqual(oversized.status, 0);
    assert.match(oversized.stderr, /size|bounded/i);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CLI snapshot reads reject hard-linked artifacts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "v1-admission-hardlink-test-"));
  try {
    const fixture = buildFixture();
    const files = writeFixture(directory, fixture);
    const hardlink = path.join(directory, "policy-hardlink.json");
    fs.linkSync(files.policy, hardlink);
    files.policy = hardlink;
    const result = spawnSync(process.execPath, cliArgs(files, fixture), { cwd: ROOT, encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /bounded regular-file|captured safely/i);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("implementation is verify-only and has no evidence writer or signing primitive", async () => {
  const source = fs.readFileSync(SCRIPT, "utf8");
  assert.doesNotMatch(source, /\b(?:createSign|generateKeyPair|privateKey|crypto\.sign|\bsign\s*\()/);
  assert.doesNotMatch(source, /fs\.(?:appendFile|createWriteStream|mkdir|rename|rm|unlink|writeFile)/);
  assert.doesNotMatch(source, /from ["']node:(?:child_process|http|https|net|tls)["']/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /process\.env/);
  for (const name of Object.keys(await import("./v1-brownfield-admission.mjs"))) {
    assert.doesNotMatch(name, /(?:create|mint|sign|write|authorize)/i);
  }
});
