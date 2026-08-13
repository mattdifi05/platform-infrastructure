#!/usr/bin/env node
/**
 * Verify-only V1 brownfield scheduler cutover contract.
 *
 * This module validates that a descriptive cutover plan is closed and binds the
 * preservation, backup, provider, legacy-container and queue identities needed
 * by a future independently trusted root executor. It does not authenticate the
 * caller-supplied external artifacts, execute the plan, access a container
 * engine, sign evidence, or grant mutation/data-rollback authority.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  sha256Canonical,
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";

export const CUTOVER_SCHEMA = "platform.v1-brownfield-scheduler-cutover-plan/v1";

export const EXTERNAL_EVIDENCE_HASH_FIELDS = Object.freeze([
  "brownfieldPolicySha256",
  "phaseAPackageAttestationEnvelopeSha256",
  "phaseAAuthorizationEnvelopeSha256",
  "authoritativeBackupAttestationEnvelopeSha256",
  "phaseBPreinstallAuthorizationEnvelopeSha256",
  "targetInstallationReceiptArtifactSha256",
  "hostedGateEnvelopeSha256",
  "deploymentGateEnvelopeSha256",
  "activationGateEnvelopeSha256",
  "aggregateAdmissionEnvelopeSha256",
]);

export const LEGACY_CONTAINER_REQUIREMENTS = deepFreeze([
  {
    name: "enterprise-control-center",
    project: "platform_infra_vps",
    service: "control-center",
    authorityKind: "NONE",
    disposition: "RECREATE-WITH-SHARED-QUEUE",
  },
  {
    name: "enterprise-backup-scheduler",
    project: "platform_infra_vps",
    service: "backup-scheduler",
    authorityKind: "RAW-DOCKER-SOCKET",
    disposition: "REPLACE-WITH-SOCKETLESS-SCHEDULER",
  },
  {
    name: "enterprise-cadvisor",
    project: "platform_infra_vps",
    service: "cadvisor",
    authorityKind: "HOST-PARENT",
    disposition: "REMOVE-CONTAINER-PRESERVE-RECOVERY",
  },
  {
    name: "enterprise-node-exporter",
    project: null,
    service: "node-exporter",
    authorityKind: "HOST-PARENT",
    disposition: "REMOVE-CONTAINER-PRESERVE-RECOVERY",
  },
]);

export const CUTOVER_STAGE_ORDER = Object.freeze([
  "acquire-root-activation-lock",
  "revalidate-baseline-backup-admission-and-container-cas",
  "scan-and-project-all-baseline-container-authorities",
  "stop-control-center-queue-admission",
  "prove-no-backup-job-or-lease-in-flight",
  "stop-exact-legacy-backup-scheduler",
  "stop-exact-legacy-host-parent-authorities",
  "remove-exact-legacy-authority-containers-preserve-storage",
  "prove-zero-raw-or-host-parent-authority",
  "create-empty-canonical-queue-volume",
  "copy-queue-source-read-only",
  "verify-queue-copy-and-source-unchanged",
  "start-final-docker-action-activation-sidecar",
  "start-final-docker-action-broker",
  "verify-broker-is-sole-raw-authority",
  "start-final-socketless-backup-scheduler",
  "recreate-control-center-with-shared-queue",
  "verify-application-database-storage-preservation",
  "publish-cutover-receipt",
]);

export const PROPOSED_MUTATION_TARGETS = Object.freeze([
  "container:enterprise-backup-scheduler",
  "container:enterprise-cadvisor",
  "container:enterprise-control-center",
  "container:enterprise-docker-action-activation-sidecar",
  "container:enterprise-docker-action-broker",
  "container:enterprise-node-exporter",
  "volume:platform_infra_vps_backup_scheduler_jobs",
  "volume:platform_infra_vps_backup_scheduler_logs",
  "volume:platform_infra_vps_docker_action_activation_cas",
  "volume:platform_infra_vps_docker_action_broker_socket",
  "volume:platform_infra_vps_docker_action_broker_state",
]);

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_OBJECT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MODE = /^0[0-7]{3}$/;
const RAW_DOCKER_SOURCES = new Set(["/var/run/docker.sock", "/run/docker.sock"]);
const HOST_PARENT_SOURCES = new Set([
  "/",
  "/dev",
  "/proc",
  "/run",
  "/sys",
  "/var/run",
  "/var/lib/docker",
]);
const MAX_PLAN_BYTES = 4 * 1024 * 1024;
const MAX_BASELINE_BYTES = 64 * 1024 * 1024;
const CANONICAL_TARGET_ROOT = "/srv/platform-infrastructure";

const PLAN_KEYS = Object.freeze([
  "schema",
  "planId",
  "scope",
  "evidenceClass",
  "synthetic",
  "verifyOnly",
  "candidateRepositoryControlled",
  "baseline",
  "candidate",
  "target",
  "authoritativeBackup",
  "externalEvidence",
  "legacyContainers",
  "queueMigration",
  "stagedOrder",
  "safety",
  "rollback",
]);

function invalid(message) {
  throw new Error(message);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const entry of Object.values(value)) deepFreeze(entry);
  }
  return value;
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalid(`${label} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactSha256(value, label) {
  const normalized = String(value ?? "");
  if (!SHA256.test(normalized)) invalid(`${label} must be one lowercase SHA256.`);
  return normalized;
}

function exactGitObject(value, label) {
  const normalized = String(value ?? "");
  if (!GIT_OBJECT.test(normalized)) invalid(`${label} must be one exact Git object ID.`);
  return normalized;
}

function exactTimestamp(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  return milliseconds;
}

function exactCanonicalAbsolute(value, label) {
  if (typeof value !== "string" || value.includes("\0") || !path.posix.isAbsolute(value)
      || path.posix.normalize(value) !== value || (value.length > 1 && value.endsWith("/"))) {
    invalid(`${label} must be one canonical absolute path.`);
  }
  return value;
}

function exactNonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    invalid(`${label} must be one bounded non-negative integer.`);
  }
  return value;
}

function exactPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    invalid(`${label} must be one bounded positive integer.`);
  }
  return value;
}

function exactMode(value, label) {
  const normalized = String(value ?? "");
  if (!MODE.test(normalized)) invalid(`${label} must be one canonical four-digit mode.`);
  return normalized;
}

function sameArray(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function requirePairwiseDistinct(values, label) {
  if (new Set(values).size !== values.length) invalid(`${label} must be pairwise distinct.`);
}

function validatePlanIdentity(plan) {
  exactObject(plan, "Cutover plan", PLAN_KEYS);
  if (plan.schema !== CUTOVER_SCHEMA
      || plan.scope !== "platform-infrastructure"
      || plan.verifyOnly !== true
      || plan.candidateRepositoryControlled !== true
      || typeof plan.synthetic !== "boolean") {
    invalid("Cutover plan identity or verify-only boundary is invalid.");
  }
  const expectedEvidenceClass = plan.synthetic
    ? "SYNTHETIC-TEST"
    : "EXTERNAL-BROWNFIELD-CUTOVER-PLAN";
  if (plan.evidenceClass !== expectedEvidenceClass) {
    invalid("Cutover plan evidence class does not match its synthetic state.");
  }
  exactSha256(plan.planId, "Cutover plan ID");
  const payload = structuredClone(plan);
  delete payload.planId;
  if (plan.planId !== sha256Canonical(payload)) {
    invalid("Cutover plan ID does not match the canonical closed plan payload.");
  }
}

function validateCompleteBaseline(baseline) {
  try {
    validateLivePreservationBaseline(baseline, { requireComplete: true });
  } catch (error) {
    invalid(`Canonical complete preservation baseline rejected: ${String(error?.message ?? error)}`);
  }
  if (baseline.schema !== "platform.live-preservation-baseline/v1"
      || baseline.scope !== "platform-infrastructure"
      || baseline.complete !== true
      || baseline.status !== "COMPLETE-PRESERVATION-BASELINE"
      || baseline.gateAdmissible !== false
      || baseline.mutationAuthority !== false
      || baseline.effect !== "DENY-ONLY"
      || !Array.isArray(baseline.deficiencies)
      || baseline.deficiencies.length !== 0) {
    invalid("A canonical COMPLETE deny-only preservation baseline is required.");
  }
  return baseline;
}

function validateBaselineBinding(plan, baseline, baselineArtifactSha256) {
  const binding = exactObject(plan.baseline, "Cutover baseline binding", [
    "schema",
    "baselineId",
    "artifactSha256",
    "completedAt",
    "dockerDaemonId",
  ]);
  const suppliedArtifactSha256 = exactSha256(
    baselineArtifactSha256,
    "Supplied baseline artifact SHA256",
  );
  exactSha256(binding.baselineId, "Cutover baseline ID");
  exactSha256(binding.artifactSha256, "Cutover baseline artifact SHA256");
  exactTimestamp(binding.completedAt, "Cutover baseline completion time");
  if (binding.schema !== baseline.schema
      || binding.baselineId !== baseline.baselineId
      || binding.artifactSha256 !== suppliedArtifactSha256
      || binding.completedAt !== baseline.capturedAt.completedAt
      || binding.dockerDaemonId !== baseline.host.dockerDaemonId) {
    invalid("Cutover baseline artifact SHA256 or canonical identity is mismatched.");
  }
  if (plan.synthetic !== baseline.synthetic
      || (plan.evidenceClass === "SYNTHETIC-TEST") !== (baseline.evidenceClass === "SYNTHETIC-TEST")) {
    invalid("Cutover plan and baseline evidence classes do not match.");
  }
  return binding;
}

function validateCandidate(candidate) {
  exactObject(candidate, "Cutover candidate", [
    "repository",
    "commit",
    "tree",
    "sourceArchiveSha256",
    "combinedRenderSha256",
  ]);
  if (!REPOSITORY.test(String(candidate.repository ?? ""))) {
    invalid("Cutover candidate repository is invalid.");
  }
  exactGitObject(candidate.commit, "Cutover candidate commit");
  exactGitObject(candidate.tree, "Cutover candidate tree");
  exactSha256(candidate.sourceArchiveSha256, "Cutover candidate source archive SHA256");
  exactSha256(candidate.combinedRenderSha256, "Cutover candidate combined render SHA256");
  if (candidate.commit === candidate.tree
      || candidate.sourceArchiveSha256 === candidate.combinedRenderSha256) {
    invalid("Cutover candidate semantic identities must be distinct.");
  }
  return candidate;
}

function validateTarget(target, baseline) {
  exactObject(target, "Cutover target", [
    "root",
    "hostname",
    "machineIdSha256",
    "sshHostKeySha256",
    "dockerDaemonId",
  ]);
  exactCanonicalAbsolute(target.root, "Cutover target root");
  if (target.root !== CANONICAL_TARGET_ROOT) {
    invalid(`Cutover canonical target root must be ${CANONICAL_TARGET_ROOT}.`);
  }
  exactSha256(target.machineIdSha256, "Cutover target machine identity");
  exactSha256(target.sshHostKeySha256, "Cutover target SSH host-key identity");
  if (typeof target.hostname !== "string" || !target.hostname
      || typeof target.dockerDaemonId !== "string" || !target.dockerDaemonId
      || target.hostname !== baseline.host.hostname
      || target.machineIdSha256 !== baseline.host.machineIdSha256
      || target.sshHostKeySha256 !== baseline.host.sshHostKeySha256
      || target.dockerDaemonId !== baseline.host.dockerDaemonId) {
    invalid("Cutover target identity does not exactly match the complete baseline host.");
  }
  return target;
}

function validateExternalEvidence(externalEvidence) {
  exactObject(
    externalEvidence,
    "Cutover externalEvidence",
    EXTERNAL_EVIDENCE_HASH_FIELDS,
  );
  const hashes = EXTERNAL_EVIDENCE_HASH_FIELDS.map((field) => (
    exactSha256(externalEvidence[field], `External evidence ${field}`)
  ));
  requirePairwiseDistinct(hashes, "Cutover external evidence hashes");
  return externalEvidence;
}

function validateAuthoritativeBackup(backup, { baselineBinding, candidate, target, externalEvidence }) {
  exactObject(backup, "Authoritative backup binding", [
    "schema",
    "authority",
    "receiptId",
    "receiptArtifactSha256",
    "attestationEnvelopeSha256",
    "evidenceArtifactSha256",
    "restoreVerificationArtifactSha256",
    "baselineId",
    "baselineArtifactSha256",
    "candidateRepository",
    "candidateCommit",
    "candidateTree",
    "targetRoot",
    "sourceDeviceSetSha256",
    "sourceDeviceCount",
    "backupDeviceIdentitySha256",
    "verifiedOutsideAllSourceDevices",
    "completeApplicationCoverage",
    "completeDatabaseCoverage",
    "completeStorageCoverage",
    "consistentDatabaseCaptures",
    "readable",
    "restorePlanVerified",
  ]);
  if (backup.schema !== "platform.v1-authoritative-backup-binding/v1"
      || backup.authority !== "EXTERNAL-TARGET-ROOT-AND-PROVIDER") {
    invalid("Authoritative backup binding identity is invalid.");
  }
  const semanticHashes = [
    exactSha256(backup.receiptId, "Authoritative backup receipt ID"),
    exactSha256(backup.receiptArtifactSha256, "Authoritative backup receipt artifact SHA256"),
    exactSha256(backup.attestationEnvelopeSha256, "Authoritative backup attestation envelope SHA256"),
    exactSha256(backup.evidenceArtifactSha256, "Authoritative backup evidence artifact SHA256"),
    exactSha256(backup.restoreVerificationArtifactSha256, "Authoritative backup restore verification SHA256"),
    exactSha256(backup.sourceDeviceSetSha256, "Authoritative backup source-device-set SHA256"),
    exactSha256(backup.backupDeviceIdentitySha256, "Authoritative backup device identity SHA256"),
  ];
  requirePairwiseDistinct(semanticHashes, "Authoritative backup semantic hashes");
  exactPositiveInteger(backup.sourceDeviceCount, "Authoritative backup source-device count");
  if (backup.baselineId !== baselineBinding.baselineId
      || backup.baselineArtifactSha256 !== baselineBinding.artifactSha256) {
    invalid("Authoritative backup baseline binding is mismatched.");
  }
  if (backup.candidateRepository !== candidate.repository
      || backup.candidateCommit !== candidate.commit
      || backup.candidateTree !== candidate.tree) {
    invalid("Authoritative backup candidate does not match the cutover candidate.");
  }
  if (backup.targetRoot !== target.root) {
    invalid("Authoritative backup target root does not match the cutover target.");
  }
  if (backup.attestationEnvelopeSha256
      !== externalEvidence.authoritativeBackupAttestationEnvelopeSha256) {
    invalid("Authoritative backup attestation does not match external evidence.");
  }
  for (const field of [
    "verifiedOutsideAllSourceDevices",
    "completeApplicationCoverage",
    "completeDatabaseCoverage",
    "completeStorageCoverage",
    "consistentDatabaseCaptures",
    "readable",
    "restorePlanVerified",
  ]) {
    if (backup[field] !== true) {
      invalid(`Authoritative backup claim ${field} must be present for external authentication.`);
    }
  }
  return backup;
}

function baselineContainerIndex(baseline) {
  const index = new Map();
  for (const container of baseline.containers) {
    if (index.has(container.name)) invalid(`Complete baseline has duplicate container ${container.name}.`);
    index.set(container.name, container);
  }
  return index;
}

function baselineBindIndex(baseline) {
  const index = new Map();
  for (const binding of baseline.bindMounts) {
    if (index.has(binding.source)) {
      invalid(`Global authority scan has ambiguous bind source ${binding.source}.`);
    }
    index.set(binding.source, binding);
  }
  return index;
}

function looksLikeDockerSocket(source) {
  return RAW_DOCKER_SOURCES.has(source) || source.endsWith("/docker.sock");
}

function isHostAuthorityPath(source, dockerRoot) {
  const hostTrees = ["/dev", "/proc", "/run", "/sys", "/var/run"];
  if (source === "/" || hostTrees.some((root) => (
    source === root || source.startsWith(`${root}/`)
  ))) {
    return true;
  }
  return source === dockerRoot
    || source.startsWith(`${dockerRoot}/`)
    || dockerRoot.startsWith(`${source}/`);
}

function observedAuthority(container, baseline, bindIndex) {
  const kinds = new Set();
  const authorityBindings = new Map();
  const dockerRoot = baseline.host.dockerRootDir;
  for (const mount of container.mounts ?? []) {
    if (mount.kind !== "bind") continue;
    const binding = bindIndex.get(mount.sourceRef);
    if (!binding) {
      invalid(
        `Global authority scan cannot map bind ${mount.sourceRef} for ${container.name}; `
          + "the resource must be PRESERVE+STOP.",
      );
    }
    const observedSources = [mount.sourceRef, binding.source, binding.canonicalPath];
    const dockerSocketPath = [...observedSources, mount.destination]
      .some(looksLikeDockerSocket);
    const lstatSocket = binding.lstatIdentity?.type === "socket";
    const targetSocket = binding.targetIdentity?.type === "socket";
    const exactSocketEvidence = binding.classification === "SOCKET"
      && lstatSocket
      && targetSocket;
    let kind = null;
    if (dockerSocketPath && exactSocketEvidence) {
      kind = "RAW-DOCKER-SOCKET";
    } else if (dockerSocketPath
        || binding.classification === "SOCKET"
        || lstatSocket
        || targetSocket) {
      kind = "UNKNOWN-SOCKET-AUTHORITY";
    } else if (binding.classification === "UNKNOWN-PRESERVE") {
      kind = "UNKNOWN-BIND-AUTHORITY";
    } else {
      if (binding.classification === "HOST-API"
          || observedSources.some((source) => HOST_PARENT_SOURCES.has(source))
          || observedSources.some((source) => isHostAuthorityPath(source, dockerRoot))) {
        kind = "HOST-PARENT";
      }
    }
    if (kind) {
      kinds.add(kind);
      authorityBindings.set(binding.source, binding);
    }
  }
  const exactAuthorityBindings = [...authorityBindings.values()]
    .sort((left, right) => left.source.localeCompare(right.source));
  return {
    kinds: [...kinds].sort((left, right) => left.localeCompare(right)),
    authorityBindingsSha256: sha256Canonical(exactAuthorityBindings),
  };
}

function assertObservedAuthority(container, requirement, baseline, bindIndex) {
  const { kinds } = observedAuthority(container, baseline, bindIndex);
  const bindSources = (container.mounts ?? [])
    .filter((mount) => mount.kind === "bind")
    .map((mount) => mount.sourceRef);
  if (requirement.authorityKind === "RAW-DOCKER-SOCKET"
      && (!kinds.includes("RAW-DOCKER-SOCKET")
        || !bindSources.some((source) => RAW_DOCKER_SOURCES.has(source)))) {
    invalid(`Legacy container ${requirement.name} lacks its baseline raw-socket authority.`);
  }
  if (requirement.authorityKind === "HOST-PARENT"
      && !kinds.includes("HOST-PARENT")) {
    invalid(`Legacy container ${requirement.name} lacks its baseline host-parent authority.`);
  }
  if (requirement.authorityKind === "NONE"
      && kinds.length !== 0) {
    invalid(`Legacy container ${requirement.name} unexpectedly has raw host authority.`);
  }
}

function validateLegacyContainers(bindings, baseline) {
  if (!Array.isArray(bindings)
      || bindings.length !== LEGACY_CONTAINER_REQUIREMENTS.length
      || !bindings.every((binding, index) => binding?.name === LEGACY_CONTAINER_REQUIREMENTS[index].name)) {
    invalid("Legacy container set and order must be exact.");
  }
  const containerIndex = baselineContainerIndex(baseline);
  const bindIndex = baselineBindIndex(baseline);
  const recoveryHashes = [];
  for (const [index, binding] of bindings.entries()) {
    const requirement = LEGACY_CONTAINER_REQUIREMENTS[index];
    exactObject(binding, `Legacy container ${requirement.name} binding`, [
      "name",
      "service",
      "project",
      "authorityKind",
      "disposition",
      "containerId",
      "imageRef",
      "imageId",
      "configHash",
      "createdAt",
      "expectedState",
      "expectedHealth",
      "mountsSha256",
      "recoveryArtifactSha256",
    ]);
    const container = containerIndex.get(requirement.name);
    if (!container) invalid(`Complete baseline is missing legacy container ${requirement.name}.`);
    exactSha256(binding.containerId, `Legacy container ${requirement.name} ID`);
    exactSha256(String(binding.imageId ?? "").replace(/^sha256:/, ""), `Legacy container ${requirement.name} image ID`);
    exactSha256(binding.configHash, `Legacy container ${requirement.name} config hash`);
    exactTimestamp(binding.createdAt, `Legacy container ${requirement.name} creation time`);
    exactSha256(binding.mountsSha256, `Legacy container ${requirement.name} mounts SHA256`);
    recoveryHashes.push(exactSha256(
      binding.recoveryArtifactSha256,
      `Legacy container ${requirement.name} recovery artifact SHA256`,
    ));
    if (binding.service !== requirement.service
        || binding.project !== requirement.project
        || binding.authorityKind !== requirement.authorityKind
        || binding.disposition !== requirement.disposition
        || container.service !== requirement.service
        || container.project !== requirement.project
        || binding.project !== container.project
        || binding.containerId !== container.id
        || binding.imageRef !== container.imageRef
        || binding.imageId !== container.imageId
        || binding.configHash !== container.configHash
        || binding.createdAt !== container.createdAt
        || binding.expectedState !== "running"
        || binding.expectedState !== container.state
        || binding.expectedHealth !== "healthy"
        || binding.expectedHealth !== container.health
        || binding.mountsSha256 !== sha256Canonical(container.mounts)) {
      invalid(`Legacy container ${requirement.name} CAS does not match the complete baseline.`);
    }
    assertObservedAuthority(container, requirement, baseline, bindIndex);
  }
  requirePairwiseDistinct(recoveryHashes, "Legacy container recovery artifact hashes");
  return bindings;
}

function validateGlobalAuthorityProjection(bindings, baseline) {
  const requirements = new Map(
    LEGACY_CONTAINER_REQUIREMENTS
      .filter(({ authorityKind }) => authorityKind !== "NONE")
      .map((requirement) => [requirement.name, requirement]),
  );
  const bindingIndex = new Map(bindings.map((binding) => [binding.name, binding]));
  const bindIndex = baselineBindIndex(baseline);
  const authorityContainers = [];
  for (const container of baseline.containers) {
    const { kinds: authorityKinds, authorityBindingsSha256 } = observedAuthority(
      container,
      baseline,
      bindIndex,
    );
    if (authorityKinds.length === 0) continue;
    const requirement = requirements.get(container.name);
    const binding = bindingIndex.get(container.name);
    if (!requirement
        || !binding
        || container.service !== requirement.service
        || container.project !== requirement.project
        || authorityKinds.length !== 1
        || authorityKinds[0] !== requirement.authorityKind) {
      invalid(
        `Unknown or foreign raw Docker or host-parent authority on ${container.name}; `
          + "the resource must be PRESERVE+STOP.",
      );
    }
    const mountsSha256 = sha256Canonical(container.mounts);
    if (binding.mountsSha256 !== mountsSha256
        || binding.containerId !== container.id
        || binding.configHash !== container.configHash) {
      invalid(`Global authority projection CAS does not match ${container.name}.`);
    }
    authorityContainers.push({
      name: container.name,
      service: container.service,
      project: container.project,
      authorityKind: requirement.authorityKind,
      containerCasSha256: sha256Canonical(container),
      mountsSha256,
      authorityBindingsSha256,
    });
  }
  const expectedNames = [...requirements.keys()].sort((left, right) => left.localeCompare(right));
  authorityContainers.sort((left, right) => left.name.localeCompare(right.name));
  if (!sameArray(authorityContainers.map(({ name }) => name), expectedNames)) {
    invalid("Global authority projection is incomplete; unknown resources are PRESERVE+STOP.");
  }
  return deepFreeze({
    schema: "platform.v1-brownfield-global-authority-projection/v1",
    baselineId: baseline.baselineId,
    baselineContainersSha256: sha256Canonical(baseline.containers),
    scannedContainerCount: baseline.containers.length,
    authorityContainers,
    unknownAuthorityCount: 0,
    foreignAuthorityCount: 0,
    unknownAuthorityDisposition: "PRESERVE+STOP",
    foreignAuthorityDisposition: "PRESERVE+STOP",
  });
}

function validateQueueMigration(queueMigration, baseline) {
  exactObject(queueMigration, "Queue migration", [
    "schema",
    "observationArtifactSha256",
    "source",
    "destination",
    "transfer",
  ]);
  if (queueMigration.schema !== "platform.v1-brownfield-scheduler-queue-migration/v1") {
    invalid("Queue migration schema is invalid.");
  }
  exactSha256(queueMigration.observationArtifactSha256, "Queue observation artifact SHA256");
  const source = exactObject(queueMigration.source, "Queue migration source", [
    "path",
    "parentBindSource",
    "contentTreeSha256",
    "metadataManifestSha256",
    "aclSha256",
    "xattrSha256",
    "entryCount",
    "totalBytes",
    "uid",
    "gid",
    "mode",
  ]);
  const destination = exactObject(queueMigration.destination, "Queue migration destination", [
    "volumeName",
    "initialState",
    "expectedContentTreeSha256",
    "expectedMetadataManifestSha256",
    "expectedAclSha256",
    "expectedXattrSha256",
    "expectedEntryCount",
    "expectedTotalBytes",
    "uid",
    "gid",
    "mode",
  ]);
  const transfer = exactObject(queueMigration.transfer, "Queue migration transfer", [
    "sourceReadOnly",
    "sourcePreserved",
    "contentRewriteAllowed",
    "symlinksAllowed",
    "specialFilesAllowed",
    "networkMode",
    "dockerSocketMounted",
    "ownershipTransform",
  ]);

  exactCanonicalAbsolute(source.parentBindSource, "Queue source parent bind");
  exactCanonicalAbsolute(source.path, "Queue source path");
  if (source.path !== path.posix.join(source.parentBindSource, "backup-jobs")) {
    invalid("Queue source must be the exact backup-jobs child of its observed parent bind.");
  }
  const parentBind = baseline.bindMounts.find((binding) => (
    binding.source === source.parentBindSource
      && binding.canonicalPath === source.parentBindSource
  ));
  if (!parentBind || parentBind.classification !== "APPLICATION-DATA") {
    invalid("Queue source parent must be one observed application-data bind.");
  }
  for (const containerName of ["enterprise-control-center", "enterprise-backup-scheduler"]) {
    const consumer = parentBind.consumers.find((entry) => (
      entry.containerName === containerName
        && entry.destination === "/var/www/project-state"
        && entry.readOnly === false
    ));
    if (!consumer) invalid(`Queue parent bind lacks exact legacy consumer ${containerName}.`);
  }
  exactSha256(source.contentTreeSha256, "Queue source content tree SHA256");
  exactSha256(source.metadataManifestSha256, "Queue source metadata manifest SHA256");
  exactSha256(source.aclSha256, "Queue source ACL manifest SHA256");
  exactSha256(source.xattrSha256, "Queue source xattr manifest SHA256");
  if (source.contentTreeSha256 === source.metadataManifestSha256) {
    invalid("Queue content and metadata digests must be distinct.");
  }
  exactNonNegativeInteger(source.entryCount, "Queue source entry count");
  exactNonNegativeInteger(source.totalBytes, "Queue source total bytes");
  exactNonNegativeInteger(source.uid, "Queue source owner UID");
  exactNonNegativeInteger(source.gid, "Queue source owner GID");
  exactMode(source.mode, "Queue source mode");

  if (destination.volumeName !== "platform_infra_vps_backup_scheduler_jobs"
      || destination.initialState !== "ABSENT-OR-EMPTY-CANDIDATE-OWNED") {
    invalid("Queue migration destination is not the canonical queue volume in an empty state.");
  }
  exactSha256(destination.expectedContentTreeSha256, "Queue destination content tree SHA256");
  exactSha256(
    destination.expectedMetadataManifestSha256,
    "Queue destination metadata manifest SHA256",
  );
  exactSha256(destination.expectedAclSha256, "Queue destination ACL manifest SHA256");
  exactSha256(destination.expectedXattrSha256, "Queue destination xattr manifest SHA256");
  exactNonNegativeInteger(destination.expectedEntryCount, "Queue destination entry count");
  exactNonNegativeInteger(destination.expectedTotalBytes, "Queue destination total bytes");
  exactNonNegativeInteger(destination.uid, "Queue destination owner UID");
  exactNonNegativeInteger(destination.gid, "Queue destination owner GID");
  exactMode(destination.mode, "Queue destination mode");
  if (destination.expectedContentTreeSha256 !== source.contentTreeSha256) {
    invalid("Queue source and destination content tree digest must match.");
  }
  if (destination.expectedEntryCount !== source.entryCount) {
    invalid("Queue source and destination entry count must match.");
  }
  if (destination.expectedTotalBytes !== source.totalBytes) {
    invalid("Queue source and destination total bytes must match.");
  }
  if (destination.expectedMetadataManifestSha256 !== source.metadataManifestSha256
      || destination.expectedAclSha256 !== source.aclSha256
      || destination.expectedXattrSha256 !== source.xattrSha256
      || destination.uid !== source.uid
      || destination.gid !== source.gid
      || destination.mode !== source.mode) {
    invalid(
      "Queue source and destination metadata, ownership, mode, ACL, and xattr digests must match.",
    );
  }
  if (transfer.sourceReadOnly !== true
      || transfer.sourcePreserved !== true
      || transfer.contentRewriteAllowed !== false
      || transfer.symlinksAllowed !== false
      || transfer.specialFilesAllowed !== false
      || transfer.networkMode !== "none"
      || transfer.dockerSocketMounted !== false
      || transfer.ownershipTransform !== "NONE-PRESERVE-EXACT") {
    invalid("Queue transfer boundary is widened or destructive.");
  }
  return queueMigration;
}

function validateStagedOrder(stagedOrder) {
  if (!sameArray(stagedOrder, CUTOVER_STAGE_ORDER)) {
    invalid("Cutover must use the exact deny-only staged order.");
  }
  return stagedOrder;
}

function validateSafety(safety) {
  exactObject(safety, "Cutover preservation safety policy", [
    "unknownResources",
    "foreignResourceMutationAllowed",
    "globalTeardownAllowed",
    "removeOrphansAllowed",
    "pruneAllowed",
    "databaseMutationAllowed",
    "persistentStorageDeletionAllowed",
    "sourceQueueMutationAllowed",
    "rawAuthorityOverlapAllowed",
    "proposedMutationTargets",
  ]);
  if (safety.unknownResources !== "PRESERVE"
      || safety.foreignResourceMutationAllowed !== false
      || safety.globalTeardownAllowed !== false
      || safety.removeOrphansAllowed !== false
      || safety.pruneAllowed !== false
      || safety.databaseMutationAllowed !== false
      || safety.persistentStorageDeletionAllowed !== false
      || safety.sourceQueueMutationAllowed !== false
      || safety.rawAuthorityOverlapAllowed !== false) {
    invalid("Cutover preservation safety policy is widened.");
  }
  if (!sameArray(safety.proposedMutationTargets, PROPOSED_MUTATION_TARGETS)) {
    invalid("Cutover proposed mutation targets are widened, missing, or reordered.");
  }
  return safety;
}

function validateRollback(rollback) {
  exactObject(rollback, "Cutover rollback policy", [
    "codeRollbackPlanArtifactSha256",
    "legacyRecoveryBundleSha256",
    "preservePostCutoverState",
    "automaticDatabaseRestore",
    "automaticQueueOverwrite",
    "dataRollbackAuthorized",
    "requireSeparateDataRollbackAdmission",
    "brokerMustStopBeforeLegacyAuthorityRestore",
  ]);
  const codeRollbackPlanArtifactSha256 = exactSha256(
    rollback.codeRollbackPlanArtifactSha256,
    "Code rollback plan artifact SHA256",
  );
  const legacyRecoveryBundleSha256 = exactSha256(
    rollback.legacyRecoveryBundleSha256,
    "Legacy recovery bundle SHA256",
  );
  if (codeRollbackPlanArtifactSha256 === legacyRecoveryBundleSha256
      || rollback.preservePostCutoverState !== true
      || rollback.automaticDatabaseRestore !== false
      || rollback.automaticQueueOverwrite !== false
      || rollback.dataRollbackAuthorized !== false
      || rollback.requireSeparateDataRollbackAdmission !== true
      || rollback.brokerMustStopBeforeLegacyAuthorityRestore !== true) {
    invalid("Cutover rollback policy permits unsafe or implicit data rollback.");
  }
  return rollback;
}

export function verifyV1BrownfieldSchedulerCutover({
  plan,
  baseline,
  baselineArtifactSha256,
} = {}) {
  validatePlanIdentity(plan);
  validateCompleteBaseline(baseline);
  const baselineBinding = validateBaselineBinding(plan, baseline, baselineArtifactSha256);
  const candidate = validateCandidate(plan.candidate);
  const target = validateTarget(plan.target, baseline);
  const externalEvidence = validateExternalEvidence(plan.externalEvidence);
  const authoritativeBackup = validateAuthoritativeBackup(plan.authoritativeBackup, {
    baselineBinding,
    candidate,
    target,
    externalEvidence,
  });
  const legacyContainers = validateLegacyContainers(plan.legacyContainers, baseline);
  const globalAuthorityProjection = validateGlobalAuthorityProjection(legacyContainers, baseline);
  validateQueueMigration(plan.queueMigration, baseline);
  validateStagedOrder(plan.stagedOrder);
  validateSafety(plan.safety);
  validateRollback(plan.rollback);

  return deepFreeze({
    schema: "platform.v1-brownfield-scheduler-cutover-validation/v1",
    status: "LOCAL-NOT-AUTHORIZED",
    externalStatus: "EXTERNAL-PENDING",
    referenceOnly: true,
    structuralBindingsValidated: true,
    authoritativeEvidenceVerified: false,
    callerSuppliedEvidenceHashes: true,
    baselineAuthenticationStatus: "CALLER-SUPPLIED-HASH-STRUCTURE-VALIDATED",
    authoritativeBackupAuthenticationStatus: "EXTERNAL-PENDING",
    providerAdmissionAuthenticationStatus: "EXTERNAL-PENDING",
    rootExecutionAndReplayStatus: "EXTERNAL-PENDING",
    executionAuthorized: false,
    mutationAuthority: false,
    localMutationAuthority: false,
    dataRollbackAuthorized: false,
    dockerExecutor: false,
    unknownResources: "PRESERVE",
    planId: plan.planId,
    baselineId: baselineBinding.baselineId,
    baselineArtifactSha256: baselineBinding.artifactSha256,
    authoritativeBackupReceiptId: authoritativeBackup.receiptId,
    authoritativeBackupAttestationEnvelopeSha256:
      authoritativeBackup.attestationEnvelopeSha256,
    externalEvidenceHashes: structuredClone(externalEvidence),
    proposedStagedOrder: [...CUTOVER_STAGE_ORDER],
    proposedMutationTargets: [...PROPOSED_MUTATION_TARGETS],
    globalAuthorityProjection,
    blockingConditions: [
      "authoritative-backup-authentication: EXTERNAL-PENDING",
      "provider-admission-authentication: EXTERNAL-PENDING",
      "root-executor-and-replay-enforcement: EXTERNAL-PENDING",
      "verify-only contract has no mutation executor or authority",
    ],
    actions: [],
  });
}

function readBoundedJson(filename, label, maximumBytes) {
  const absolute = path.resolve(String(filename ?? ""));
  const noFollow = fs.constants.O_NOFOLLOW;
  if (!filename || typeof noFollow !== "number") {
    invalid(`${label} cannot be opened through the protected read boundary.`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.size < 2 || before.size > maximumBytes) {
      invalid(`${label} must be one singly linked bounded regular JSON file.`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    for (const field of ["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"]) {
      if (before[field] !== after[field]) invalid(`${label} changed while it was read.`);
    }
    if (bytes.length !== before.size) invalid(`${label} byte count changed while it was read.`);
    let document;
    try {
      document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      invalid(`${label} is not valid UTF-8 JSON.`);
    }
    return {
      document,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseCli(argv) {
  if (argv.length !== 7
      || argv[0] !== "verify"
      || argv[1] !== "--plan"
      || argv[3] !== "--baseline"
      || argv[5] !== "--expected-baseline-sha256"
      || [argv[2], argv[4], argv[6]].some((value) => !value || value.startsWith("-"))) {
    invalid("usage: v1-brownfield-scheduler-cutover.mjs verify --plan FILE --baseline FILE --expected-baseline-sha256 SHA256");
  }
  return {
    planPath: argv[2],
    baselinePath: argv[4],
    expectedBaselineSha256: exactSha256(argv[6], "Expected baseline artifact SHA256"),
  };
}

function runCli(argv) {
  const options = parseCli(argv);
  const planArtifact = readBoundedJson(options.planPath, "Cutover plan", MAX_PLAN_BYTES);
  const baselineArtifact = readBoundedJson(
    options.baselinePath,
    "Preservation baseline",
    MAX_BASELINE_BYTES,
  );
  if (baselineArtifact.sha256 !== options.expectedBaselineSha256) {
    invalid("Expected baseline artifact SHA256 does not match the protected baseline bytes.");
  }
  return verifyV1BrownfieldSchedulerCutover({
    plan: planArtifact.document,
    baseline: baselineArtifact.document,
    baselineArtifactSha256: baselineArtifact.sha256,
  });
}

const invoked = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  try {
    process.stdout.write(`${JSON.stringify(runCli(process.argv.slice(2)), null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      schema: "platform.v1-brownfield-scheduler-cutover-validation-error/v1",
      status: "LOCAL-NOT-AUTHORIZED",
      externalStatus: "EXTERNAL-PENDING",
      referenceOnly: true,
      structuralBindingsValidated: false,
      authoritativeEvidenceVerified: false,
      executionAuthorized: false,
      mutationAuthority: false,
      dataRollbackAuthorized: false,
      dockerExecutor: false,
      error: String(error?.message ?? error),
      actions: [],
    }, null, 2)}\n`);
  }
  process.exitCode = 78;
}
