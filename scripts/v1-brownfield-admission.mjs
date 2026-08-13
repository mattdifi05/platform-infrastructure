#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./runtime-intent-policy.mjs";

export const GATE_ORDER = Object.freeze(["HOSTED", "DEPLOYMENT", "ACTIVATION"]);
export const ROLE_NAMES = Object.freeze([
  "backupAuthority",
  "sourceTargetCustodian",
  "hostedGate",
  "deploymentGate",
  "activationGate",
  "admissionController",
  "activationTargetRoot",
  "phaseBInstaller",
]);
export const PAYLOAD_TYPES = Object.freeze({
  backupAttestation: "application/vnd.platform.v1-authoritative-backup-attestation.v1+json",
  gates: Object.freeze({
    HOSTED: "application/vnd.platform.v1-brownfield-gate-admission.hosted.v1+json",
    DEPLOYMENT: "application/vnd.platform.v1-brownfield-gate-admission.deployment.v1+json",
    ACTIVATION: "application/vnd.platform.v1-brownfield-gate-admission.activation.v1+json",
  }),
  aggregate: "application/vnd.platform.v1-brownfield-admission.v1+json",
});

const POLICY_SCHEMA = "platform.v1-brownfield-admission-policy/v1";
const TUPLE_SCHEMA = "platform.v1-brownfield-common-tuple/v1";
const BACKUP_SCHEMA = "platform.v1-authoritative-backup-attestation/v1";
const GATE_SCHEMA = "platform.v1-brownfield-gate-admission/v1";
const AGGREGATE_SCHEMA = "platform.v1-brownfield-admission/v1";
const VALIDATION_SCHEMA = "platform.v1-brownfield-admission-validation/v1";
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const OPAQUE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/;
const ROLE_BY_GATE = Object.freeze({ HOSTED: "hostedGate", DEPLOYMENT: "deploymentGate", ACTIVATION: "activationGate" });
const LEGACY_KEYS = Object.freeze({
  HOSTED: Object.freeze([
    "hostedFinalDeploymentAdmissionSha256",
    "hostedPreparationAuthorizationSha256",
    "hostedPreparationReceiptSha256",
  ]),
  DEPLOYMENT: Object.freeze([
    "dastReceiptSha256",
    "deploymentAdmissionSha256",
    "stagingRuntimeReceiptSha256",
  ]),
  ACTIVATION: Object.freeze([
    "activationPromotionSha256",
    "dockerAuthorizationSha256",
    "sigstoreBundleSha256",
  ]),
});
const REQUIRED_HELPER_PATHS = Object.freeze([
  "/usr/local/libexec/platform-hosted-preparation-broker",
  "/usr/local/libexec/platform-origin-firewall",
  "/usr/local/libexec/platform-workload-egress-firewall",
]);
const REQUIRED_DIRECTORY_PATHS = Object.freeze([
  "/srv/platform-infrastructure",
  "/srv/platform-infrastructure/releases",
  "/srv/platform-infrastructure/release-states",
]);
const REQUIRED_TARGET_PARENT_PATHS = Object.freeze([
  "/",
  "/usr",
  "/usr/local",
  "/usr/local/libexec",
  "/etc",
  "/etc/sudoers.d",
  "/srv",
]);
const sourceParentPaths = (packageBytesSha256) => Object.freeze([
  "/",
  "/var",
  "/var/lib",
]);
const PHASE_B_PERMITTED = Object.freeze([
  "MATERIALIZE_PINNED_PACKAGE_TO_CAS",
  "INSTALL_PINNED_V1_CONTROL_PLANE",
  "VERIFY_INSTALLED_V1_CONTROL_PLANE",
]);
const PHASE_B_FORBIDDEN = Object.freeze([
  "APP_DATA_MUTATION", "APP_OR_DB_QUIESCE", "CHOWN_EXISTING", "DATABASE_OPERATION", "DOCKER_OPERATION",
  "FIREWALL_OPERATION", "REMOVE_EXISTING", "REPLACE_EXISTING", "RESTORE_OPERATION", "SYSTEMD_OPERATION",
]);
export const PHASE_B_OPERATION_SCOPE = Object.freeze({
  permitted: PHASE_B_PERMITTED,
  forbidden: PHASE_B_FORBIDDEN,
});

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

function exactArray(value, label, { min = 0 } = {}) {
  if (!Array.isArray(value) || value.length < min) invalid(`${label} must be an array with at least ${min} entries.`);
  return value;
}

function exactString(value, label, expression = IDENTIFIER) {
  if (typeof value !== "string" || !expression.test(value)) invalid(`${label} is not canonical.`);
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) invalid(`${label} must be one lowercase SHA256.`);
  return value;
}

function exactNonce(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    invalid(`${label} must be one canonical 32-byte base64url nonce.`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) {
    invalid(`${label} must be one canonical 32-byte base64url nonce.`);
  }
  return value;
}

function pathIsWithin(childPath, parentPath) {
  return parentPath === "/" ? childPath.startsWith("/") : childPath === parentPath || childPath.startsWith(`${parentPath}/`);
}

function pathsOverlap(leftPath, rightPath) {
  return pathIsWithin(leftPath, rightPath) || pathIsWithin(rightPath, leftPath);
}

function exactGitSha(value, label) {
  if (typeof value !== "string" || !GIT_SHA.test(value)) invalid(`${label} must be one full lowercase Git SHA.`);
  return value;
}

function exactInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${label} must be an exact safe integer in range.`);
  }
  return value;
}

function exactDecimal(value, label, positive = false) {
  const expression = positive ? POSITIVE_DECIMAL : DECIMAL;
  if (typeof value !== "string" || !expression.test(value)) invalid(`${label} must be one canonical decimal string.`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || String(number) !== value || (positive && number < 1)) {
    invalid(`${label} exceeds the accepted exact integer range.`);
  }
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  return { value, milliseconds };
}

function exactPath(value, label) {
  if (typeof value !== "string" || !/^\/(?:[A-Za-z0-9._/-]+)?$/.test(value)
      || value.includes("//") || value.split("/").some((part) => part === "." || part === "..")
      || (value !== "/" && value.endsWith("/")) || Buffer.byteLength(value, "utf8") > 4096
      || path.posix.normalize(value) !== value) {
    invalid(`${label} must be one normalized absolute path.`);
  }
  return value;
}

function exactRepository(value, label) {
  if (typeof value !== "string" || value.length < 3 || value.length > 256) {
    invalid(`${label} is not canonical or exceeds the exact repository length bound.`);
  }
  return exactString(value, label, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
}

function exactWorkflowPath(value, label) {
  if (typeof value !== "string" || value.length > 256) {
    invalid(`${label} is not canonical or exceeds the exact workflow path length bound.`);
  }
  return exactString(value, label, /^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/);
}

function exactHost(value, label) {
  return exactString(value, label, /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/);
}

function shaCanonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function assertDistinct(values, label) {
  if (new Set(values).size !== values.length) invalid(`${label} must be pairwise distinct.`);
}

function assertNoCrossPathFilesystemObjectAliases(observations, label) {
  const firstPathByObject = new Map();
  for (const observation of observations) {
    const objectKey = canonicalJson([
      observation.deviceIdentity,
      observation.filesystemUuid,
      observation.inode,
    ]);
    const firstPath = firstPathByObject.get(objectKey);
    if (firstPath !== undefined && firstPath !== observation.path) {
      invalid(`${label} exposes one filesystem object at multiple paths (object alias).`);
    }
    if (firstPath === undefined) firstPathByObject.set(objectKey, observation.path);
  }
}

function exactFilesystemIdentity(value, label) {
  exactObject(value, label, ["deviceIdentity", "filesystemUuid", "gid", "inode", "mode", "mountId", "nlink", "uid"]);
  exactString(value.deviceIdentity, `${label} device identity`);
  exactSha256(value.filesystemUuid, `${label} filesystem UUID`);
  exactDecimal(value.inode, `${label} inode`, true);
  exactDecimal(value.mountId, `${label} mount ID`, true);
  exactInteger(value.uid, `${label} UID`);
  exactInteger(value.gid, `${label} GID`);
  exactString(value.mode, `${label} mode`, /^0[0-7]{3}$/);
  exactInteger(value.nlink, `${label} link count`, 1);
  return value;
}

function filesystemIdentityProjection(value) {
  return {
    deviceIdentity: value.deviceIdentity,
    filesystemUuid: value.filesystemUuid,
    gid: value.gid,
    inode: value.inode,
    mountId: value.mountId,
    mode: value.mode,
    nlink: value.nlink,
    uid: value.uid,
  };
}

function exactTarget(value, label, { activation = false, postinstall = false } = {}) {
  exactObject(value, label, [
    "deploymentGid", "deploymentUid", "dockerDaemonId", "endpoint", "environment", "host", "machineId",
    "root", "rootAbsenceReceiptSha256", "rootIdentity", "rootParentIdentity", "rootParentPath", "rootState",
    "rootFilesystemIdentitySha256", "sshHostKeySha256", "targetId",
  ]);
  exactString(value.targetId, `${label} target ID`);
  exactSha256(value.machineId, `${label} machine ID`);
  if (value.environment !== "production") invalid(`${label} environment must be production.`);
  exactHost(value.host, `${label} host`);
  if (value.host !== value.host.toLowerCase()) invalid(`${label} host must be canonical lowercase DNS.`);
  const endpoint = /^ssh:\/\/([a-z_][a-z0-9_-]{0,31})@([^/:?#]+):([1-9][0-9]{0,4})$/.exec(value.endpoint);
  if (endpoint === null || endpoint[2] !== value.host || Number(endpoint[3]) > 65535) {
    invalid(`${label} endpoint must be one canonical ssh://user@host:port identity matching the target host.`);
  }
  exactPath(value.root, `${label} root`);
  exactPath(value.rootParentPath, `${label} root parent`);
  if (value.rootParentPath !== path.posix.dirname(value.root)
      || (activation && value.root !== "/srv/platform-infrastructure")) {
    invalid(`${label} root/parent identity is invalid for the fixed V1 activation root.`);
  }
  exactSha256(value.sshHostKeySha256, `${label} SSH host-key SHA256`);
  exactSha256(value.rootFilesystemIdentitySha256, `${label} root filesystem identity SHA256`);
  exactString(value.dockerDaemonId, `${label} Docker daemon ID`);
  exactInteger(value.deploymentUid, `${label} deployment UID`, 1);
  exactInteger(value.deploymentGid, `${label} deployment GID`, 1);
  exactFilesystemIdentity(value.rootParentIdentity, `${label} root parent identity`);
  if (activation && (value.rootParentIdentity.uid !== 0 || value.rootParentIdentity.gid !== 0
      || value.rootParentIdentity.mode !== "0755")) {
    invalid(`${label} root parent identity must be root-owned, root-grouped, and mode 0755.`);
  }
  if (value.rootState === "ABSENT_PROVEN") {
    if (postinstall) invalid(`${label} must carry the exact materialized post-install root identity.`);
    if (!activation) invalid(`${label} preserved source root cannot be absent.`);
    if (value.rootIdentity !== null) invalid(`${label} absent root cannot fabricate a leaf identity.`);
    exactSha256(value.rootAbsenceReceiptSha256, `${label} root absence receipt SHA256`);
  } else if (value.rootState === "EXISTING_EXACT") {
    if (activation && !postinstall) {
      invalid(`${label} must be ABSENT_PROVEN for first-install V1 admission; an existing namespace requires a separate authenticated resume contract.`);
    }
    if (value.rootAbsenceReceiptSha256 !== null) invalid(`${label} existing root cannot carry an absence receipt.`);
    exactFilesystemIdentity(value.rootIdentity, `${label} root identity`);
    if (activation && (value.rootIdentity.uid !== 0 || value.rootIdentity.gid !== 0 || value.rootIdentity.mode !== "0755")) {
      invalid(`${label} root identity must be root-owned, root-grouped, and mode 0755.`);
    }
  } else {
    invalid(`${label} root state must be ABSENT_PROVEN or EXISTING_EXACT.`);
  }
  return value;
}

function phaseAAuthorizedTargetProjection(activationTarget) {
  return {
    deploymentGid: activationTarget.deploymentGid,
    deploymentUid: activationTarget.deploymentUid,
    dockerDaemonId: activationTarget.dockerDaemonId,
    endpoint: activationTarget.endpoint,
    hostname: activationTarget.host,
    machineIdentitySha256: activationTarget.machineId,
    rootFilesystemIdentitySha256: activationTarget.rootFilesystemIdentitySha256,
    sshHostKeySha256: activationTarget.sshHostKeySha256,
    targetRoot: activationTarget.root,
  };
}

function phaseAAuthorizedCandidateProjection(candidate, phaseA) {
  return {
    clean: phaseA.candidateClean,
    commitSha: candidate.commitSha,
    packageManifestSha256: phaseA.packageManifestSha256,
    packageSha256: phaseA.packageSha256,
    repository: candidate.repository,
    repositoryId: candidate.repositoryId,
    repositoryOwnerId: candidate.repositoryOwnerId,
    sourceArchiveSha256: candidate.sourceArchiveSha256,
    treeSha: candidate.treeSha,
  };
}

function exactBinaryIdentity(value, label, requiredPath = null) {
  exactObject(value, label, [
    "disposition", "gid", "mode", "name", "nlink", "packageMember", "path", "sha256", "sizeBytes", "uid", "version",
  ]);
  exactPath(value.path, `${label} path`);
  if (requiredPath !== null && value.path !== requiredPath) invalid(`${label} path is not the fixed authorized path.`);
  const name = path.posix.basename(value.path);
  if (value.name !== name || value.packageMember !== `bin/${name}`
      || value.disposition !== "CREATE_IF_ABSENT_OR_REQUIRE_EXACT") {
    invalid(`${label} name, canonical package member, or non-replacement disposition is invalid.`);
  }
  exactInteger(value.version, `${label} version`, 1);
  exactInteger(value.sizeBytes, `${label} size`, 1, 16 * 1024 * 1024);
  exactSha256(value.sha256, `${label} SHA256`);
  exactInteger(value.uid, `${label} UID`);
  exactInteger(value.gid, `${label} GID`);
  exactInteger(value.nlink, `${label} link count`, 1);
  exactString(value.mode, `${label} mode`, /^0[0-7]{3}$/);
  if (value.uid !== 0 || value.gid !== 0 || value.mode !== "0555" || value.nlink !== 1) {
    invalid(`${label} must be root-owned, root-grouped, singly linked, and mode 0555.`);
  }
  return value;
}

function exactDirectoryPlan(value, index) {
  exactObject(value, `planned directory ${index}`, ["disposition", "gid", "mode", "path", "uid"]);
  if (value.path !== REQUIRED_DIRECTORY_PATHS[index] || value.uid !== 0 || value.gid !== 0
      || value.mode !== "0755" || value.disposition !== "CREATE_IF_ABSENT_OR_REQUIRE_EXACT") {
    invalid("Planned directories must be the exact root-owned V2 set with non-replacement disposition.");
  }
  return value;
}

function exactPrivilegePolicy(value) {
  exactObject(value, "activation privilege policy", [
    "allowedSupplementaryGroups", "argumentPolicy", "content", "contentEncoding", "contentProfile", "disposition",
    "dockerGroupMembershipAllowed", "dockerSocketAccessAllowed", "effectiveSudoPolicyProfile", "gid", "mode", "nlink", "parentGid",
    "parentMode", "parentPath", "parentUid", "parentWritableByNonRoot", "packageMember", "path", "permittedInvocation",
    "principalAccountIdentityReceiptSha256", "principalGid", "principalName", "principalPreexistingRequired", "principalUid", "providerPrevalidated",
    "providerValidationReceiptSha256", "rootEquivalentCapabilitiesAllowed", "setenvAllowed", "sha256", "shellAllowed",
    "sizeBytes", "uid", "unrestrictedSudoAllowed", "validatorPath",
    "validatorSha256",
  ]);
  exactString(value.principalName, "activation privilege principal name", /^[a-z_][a-z0-9_-]{0,31}$/);
  const expectedContent = `${value.principalName} ALL=(root) NOPASSWD: /usr/local/libexec/platform-activation-broker activate\n`;
  if (value.path !== "/etc/sudoers.d/platform-activation-broker" || value.uid !== 0 || value.gid !== 0
      || value.mode !== "0440" || value.nlink !== 1
      || value.permittedInvocation !== "/usr/local/libexec/platform-activation-broker activate"
      || value.argumentPolicy !== "EXACT-NO-WILDCARDS" || value.contentProfile !== "ACTIVATION-BROKER-ACTIVATE-ONLY/V1"
      || value.contentEncoding !== "UTF-8" || value.content !== expectedContent
      || value.setenvAllowed !== false || value.shellAllowed !== false || value.parentPath !== "/etc/sudoers.d"
      || value.parentUid !== 0 || value.parentGid !== 0 || value.parentMode !== "0755"
      || value.parentWritableByNonRoot !== false || value.providerPrevalidated !== true
      || value.packageMember !== "etc/sudoers.d/platform-activation-broker"
      || value.disposition !== "CREATE_IF_ABSENT_OR_REQUIRE_EXACT" || value.validatorPath !== "/usr/sbin/visudo"
      || !canonicalEqual(value.allowedSupplementaryGroups, []) || value.dockerGroupMembershipAllowed !== false
      || value.dockerSocketAccessAllowed !== false || value.rootEquivalentCapabilitiesAllowed !== false
      || value.unrestrictedSudoAllowed !== false
      || value.effectiveSudoPolicyProfile !== "ACTIVATION-BROKER-ACTIVATE-ONLY/V1") {
    invalid("Activation privilege policy is not the exact provider-prevalidated, closed, no-wildcard/no-SETENV sudoers plan.");
  }
  exactInteger(value.principalUid, "activation privilege principal UID", 1);
  exactInteger(value.principalGid, "activation privilege principal GID", 1);
  if (value.principalPreexistingRequired !== true) invalid("Activation privilege principal must preexist; account creation is forbidden.");
  exactInteger(value.sizeBytes, "activation privilege policy size", 1);
  exactSha256(value.sha256, "activation privilege policy SHA256");
  exactSha256(value.principalAccountIdentityReceiptSha256, "activation privilege principal identity receipt SHA256");
  exactSha256(value.providerValidationReceiptSha256, "provider privilege-policy validation receipt SHA256");
  exactSha256(value.validatorSha256, "pinned visudo binary SHA256");
  if (value.sizeBytes !== Buffer.byteLength(value.content, "utf8")
      || value.sha256 !== crypto.createHash("sha256").update(value.content, "utf8").digest("hex")) {
    invalid("Activation privilege policy size/hash does not match the exact canonical content bytes.");
  }
  return value;
}

function exactPrivilegePolicyTargetVerification(value, policyValue, expectedDockerDaemonId) {
  exactObject(value, "target privilege-policy verification", [
    "effectiveBytesSha256", "phaseBPrincipalAccountObservationSha256", "policySha256", "principalAccountIdentityReceiptSha256", "principalGid", "principalName",
    "postinstallPrincipalAuthorityObservation", "principalUid", "stagedBytesSha256", "validatorPath", "validatorSha256",
    "verificationReceiptSha256", "verified", "verifiedAt",
  ]);
  if (value.policySha256 !== policyValue.sha256 || value.stagedBytesSha256 !== policyValue.sha256
      || value.effectiveBytesSha256 !== policyValue.sha256 || value.validatorPath !== policyValue.validatorPath
      || value.validatorSha256 !== policyValue.validatorSha256 || value.principalName !== policyValue.principalName
      || value.principalUid !== policyValue.principalUid || value.principalGid !== policyValue.principalGid
      || value.principalAccountIdentityReceiptSha256 !== value.postinstallPrincipalAuthorityObservation?.accountLookupReceiptSha256
      || value.verified !== true) {
    invalid("Target privilege-policy proof does not verify the exact planned policy with fixed visudo.");
  }
  exactSha256(value.verificationReceiptSha256, "target visudo verification receipt SHA256");
  exactSha256(value.phaseBPrincipalAccountObservationSha256, "target Phase B principal observation SHA256");
  exactPrincipalAccountObservation(
    value.postinstallPrincipalAuthorityObservation,
    policyValue,
    [policyValue.permittedInvocation],
    {
      expectedDockerDaemonId,
      label: "post-install deployment-account authority observation",
      requirePolicyAccountReceipt: false,
    },
  );
  if (value.postinstallPrincipalAuthorityObservation.verifiedAt !== value.verifiedAt) {
    invalid("Post-install deployment-account authority was not rechecked with the target privilege policy.");
  }
  exactTimestamp(value.verifiedAt, "target visudo verification time");
  return value;
}

function exactInstallerBootstrap(value) {
  exactObject(value, "preexisting installer bootstrap", [
    "activationTargetRootFingerprintSha256", "executionIdentitySha256", "gid", "independentlyPinned", "mode",
    "nlink", "path", "phaseBInstallerFingerprintSha256", "sha256", "trustPolicySha256", "uid", "version",
  ]);
  if (value.path !== "/usr/local/libexec/platform-v1-bootstrap-installer" || value.version !== 2
      || value.uid !== 0 || value.gid !== 0 || value.mode !== "0555" || value.nlink !== 1
      || value.independentlyPinned !== true) {
    invalid("Preexisting one-shot installer bootstrap identity is invalid.");
  }
  for (const key of [
    "activationTargetRootFingerprintSha256", "executionIdentitySha256", "phaseBInstallerFingerprintSha256",
    "sha256", "trustPolicySha256",
  ]) exactSha256(value[key], `installer bootstrap ${key}`);
  if (value.activationTargetRootFingerprintSha256 === value.phaseBInstallerFingerprintSha256) {
    invalid("Installer bootstrap trust roots must be distinct.");
  }
  return value;
}

function exactMaterializationPolicy(value, packageBytesSha256) {
  exactObject(value, "package materialization policy", [
    "casRoot", "descriptorRelativeMembersOnly", "destinationParents", "manifestMemberParityRequired", "openatNoFollowRequired",
    "regularRootOwnedNlinkOneLeafRequired", "rootOwnedNonWritableAncestryRequired", "schema", "sourceParents",
  ]);
  const expectedRoot = `/var/lib/platform-infrastructure/v1-package-cas/sha256/${packageBytesSha256}`;
  if (value.schema !== "platform.v1-package-materialization-plan/v1" || value.casRoot !== expectedRoot
      || value.descriptorRelativeMembersOnly !== true || value.manifestMemberParityRequired !== true
      || value.openatNoFollowRequired !== true || value.regularRootOwnedNlinkOneLeafRequired !== true
      || value.rootOwnedNonWritableAncestryRequired !== true) {
    invalid("Package materialization must use the derived fixed CAS root and descriptor-relative no-follow policy.");
  }
  const validateParentRequirements = (parents, paths, label) => {
    if (!Array.isArray(parents) || parents.length !== paths.length) {
      invalid(`Package materialization requires the exact fixed ${label} ancestry policy.`);
    }
    parents.forEach((parent, index) => {
      exactObject(parent, `${label} parent ${index}`, [
      "descriptorRelativeRequired", "gid", "mode", "noSymlinkRequired", "nonWritableByNonRootRequired", "path", "uid",
      ]);
      if (parent.path !== paths[index] || parent.uid !== 0 || parent.gid !== 0
          || parent.mode !== "0755" || parent.descriptorRelativeRequired !== true
          || parent.noSymlinkRequired !== true || parent.nonWritableByNonRootRequired !== true) {
        invalid(`${label} parents must be the exact root-owned, non-writable, no-symlink fixed set.`);
      }
    });
  };
  validateParentRequirements(value.sourceParents, sourceParentPaths(packageBytesSha256), "source CAS");
  validateParentRequirements(value.destinationParents, REQUIRED_TARGET_PARENT_PATHS, "destination");
  return value;
}

function deriveMaterializationTargets(installPlan) {
  const directory = (targetPath) => ({
    disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT", gid: 0, kind: "DIRECTORY", mode: "0755",
    nlink: null, path: targetPath, sha256: null, sizeBytes: null, uid: 0,
  });
  const file = (identity, kind = "REGULAR_FILE") => ({
    disposition: identity.disposition, gid: identity.gid, kind, mode: identity.mode, nlink: identity.nlink,
    path: identity.path, sha256: identity.sha256, sizeBytes: identity.sizeBytes, uid: identity.uid,
  });
  const casRoot = installPlan.materializationPolicy.casRoot;
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
      path: `${casRoot}/package.bin`, sha256: installPlan.packageBytesSha256,
      sizeBytes: installPlan.packageBytesSizeBytes, uid: 0,
    },
    {
      disposition: "CREATE_IF_ABSENT_OR_REQUIRE_EXACT", gid: 0, kind: "REGULAR_FILE", mode: "0444", nlink: 1,
      path: `${casRoot}/manifest.json`, sha256: installPlan.packageManifestSha256,
      sizeBytes: installPlan.packageManifestSizeBytes, uid: 0,
    },
    ...installPlan.directories.map((entry) => directory(entry.path)),
    file(installPlan.broker, "EXECUTABLE"),
    file(installPlan.verifier, "EXECUTABLE"),
    ...installPlan.helpers.map((entry) => file(entry, "EXECUTABLE")),
    file(installPlan.privilegePolicy, "SUDOERS_POLICY"),
  ];
}

function exactMaterializationTargets(value, installPlan) {
  if (!Array.isArray(value) || !canonicalEqual(value, deriveMaterializationTargets(installPlan))) {
    invalid("Materialization targets are not the exact closed CAS, directory, executable, and sudoers plan.");
  }
  value.forEach((target, index) => {
    exactObject(target, `materialization target ${index}`, [
      "disposition", "gid", "kind", "mode", "nlink", "path", "sha256", "sizeBytes", "uid",
    ]);
    exactPath(target.path, `materialization target ${index} path`);
    if (target.disposition !== "CREATE_IF_ABSENT_OR_REQUIRE_EXACT" || target.uid !== 0 || target.gid !== 0) {
      invalid("Materialization target permits replacement or non-root ownership.");
    }
  });
  return value;
}

function exactPackageInputObservation(value, installPlan) {
  exactObject(value, "authenticated package input observation", [
    "descriptorIdentityReceiptSha256", "manifestSha256", "manifestSizeBytes", "packageBytesSha256",
    "packageBytesSizeBytes", "pathAccepted", "readOnly", "schema", "sealedAgainstMutation", "transport", "verifiedAt",
  ]);
  if (value.schema !== "platform.v1-authenticated-package-input-observation/v1"
      || value.transport !== "AUTHENTICATED_READ_ONLY_FD" || value.pathAccepted !== false
      || value.readOnly !== true || value.sealedAgainstMutation !== true
      || value.packageBytesSha256 !== installPlan.packageBytesSha256
      || value.packageBytesSizeBytes !== installPlan.packageBytesSizeBytes
      || value.manifestSha256 !== installPlan.packageManifestSha256
      || value.manifestSizeBytes !== installPlan.packageManifestSizeBytes) {
    invalid("Phase B package input is not one authenticated, sealed, pathless FD with exact package/manifest bytes.");
  }
  exactSha256(value.descriptorIdentityReceiptSha256, "package input descriptor identity receipt SHA256");
  exactTimestamp(value.verifiedAt, "package input verification time");
  return value;
}

function exactDockerSocketIdentity(value, expectedDockerDaemonId, principalUid, principalGid) {
  exactObject(value, "Docker socket authority observation", [
    "accessibleEndpointCount", "aclArtifactSha256", "ancestryVerificationReceiptSha256", "daemonId",
    "daemonProbeReceiptSha256", "descriptorIdentityReceiptSha256", "descriptorNoFollow", "deviceIdentity", "discoveredEndpoints",
    "dockerHostEnvironmentAccepted", "endpointEnumerationReceiptSha256", "fileType", "filesystemUuid", "gid",
    "inode", "mode", "mountId", "nlink", "parentAncestry", "path", "principalAccessibleEndpoints", "principalEffectiveAccess",
    "symlink", "tcpEndpointsAccessible", "uid",
  ]);
  if (value.path !== "/run/docker.sock" || value.fileType !== "SOCKET" || value.symlink !== false
      || value.descriptorNoFollow !== true || value.nlink !== 1
      || value.uid !== 0 || value.principalEffectiveAccess !== false || value.daemonId !== expectedDockerDaemonId
      || !canonicalEqual(value.discoveredEndpoints, ["unix:///run/docker.sock"])
      || !canonicalEqual(value.principalAccessibleEndpoints, []) || value.accessibleEndpointCount !== 0
      || value.dockerHostEnvironmentAccepted !== false || value.tcpEndpointsAccessible !== false) {
    invalid("Docker socket observation does not prove one no-follow root-owned socket inaccessible to the deploy principal.");
  }
  if (!Array.isArray(value.parentAncestry) || value.parentAncestry.length !== 2) {
    invalid("Docker socket observation lacks exact / and /run ancestry.");
  }
  value.parentAncestry.forEach((entry, index) => {
    exactObject(entry, `Docker socket parent ancestry ${index}`, [
      "deviceIdentity", "filesystemUuid", "gid", "inode", "mode", "mountId", "nlink", "path", "symlink", "uid",
      "writableByNonRoot",
    ]);
    if (entry.path !== ["/", "/run"][index] || entry.uid !== 0 || entry.gid !== 0 || entry.mode !== "0755"
        || entry.symlink !== false || entry.writableByNonRoot !== false) {
      invalid("Docker socket parent ancestry is not the exact root-owned no-symlink / to /run chain.");
    }
    exactString(entry.deviceIdentity, `Docker socket parent ancestry ${index} device identity`);
    exactSha256(entry.filesystemUuid, `Docker socket parent ancestry ${index} filesystem UUID`);
    exactDecimal(entry.inode, `Docker socket parent ancestry ${index} inode`, true);
    exactDecimal(entry.mountId, `Docker socket parent ancestry ${index} mount ID`, true);
    exactInteger(entry.nlink, `Docker socket parent ancestry ${index} link count`, 1);
  });
  exactString(value.deviceIdentity, "Docker socket device identity");
  exactSha256(value.filesystemUuid, "Docker socket filesystem UUID");
  exactDecimal(value.inode, "Docker socket inode", true);
  exactDecimal(value.mountId, "Docker socket mount ID", true);
  exactInteger(value.nlink, "Docker socket link count", 1);
  exactInteger(value.uid, "Docker socket UID");
  exactInteger(value.gid, "Docker socket GID");
  exactString(value.mode, "Docker socket mode", /^0[0-7]{3}$/);
  const mode = Number.parseInt(value.mode, 8);
  const effectiveBits = principalUid === value.uid ? (mode >> 6) & 7
    : principalGid === value.gid ? (mode >> 3) & 7 : mode & 7;
  if ((effectiveBits & 6) !== 0 || value.mountId !== value.parentAncestry[1].mountId) {
    invalid("Docker socket observation contradicts POSIX access or crosses the observed /run mount.");
  }
  exactSha256(value.aclArtifactSha256, "Docker socket ACL artifact SHA256");
  exactSha256(value.ancestryVerificationReceiptSha256, "Docker socket ancestry verification receipt SHA256");
  exactSha256(value.daemonProbeReceiptSha256, "Docker daemon-ID probe receipt SHA256");
  exactSha256(value.descriptorIdentityReceiptSha256, "Docker socket descriptor identity receipt SHA256");
  exactSha256(value.endpointEnumerationReceiptSha256, "Docker endpoint enumeration receipt SHA256");
  return value;
}

function exactPrincipalAccountObservation(
  value,
  privilegePolicy,
  expectedEffectiveSudoCommands,
  {
    expectedDockerDaemonId,
    label = "preexisting deployment-account observation",
    requirePolicyAccountReceipt = true,
  } = {},
) {
  exactObject(value, label, [
    "accountLookupReceiptSha256", "capabilityReceiptSha256", "dockerGroupMembership", "dockerSocketAccess",
    "dockerSocketAclReceiptSha256", "dockerSocketIdentity", "effectiveSudoCommands", "effectiveSudoReceiptSha256", "groupMembershipReceiptSha256",
    "groupaddForbidden", "passwdEntryReceiptSha256", "preexisting", "principalGid", "principalName", "principalUid",
    "rootEquivalentCapabilities", "supplementaryGroups", "unrestrictedSudo", "useraddForbidden", "verifiedAt",
  ]);
  if (value.principalName !== privilegePolicy.principalName || value.principalUid !== privilegePolicy.principalUid
      || value.principalGid !== privilegePolicy.principalGid || value.preexisting !== true
      || value.useraddForbidden !== true || value.groupaddForbidden !== true
      || (requirePolicyAccountReceipt
        && value.accountLookupReceiptSha256 !== privilegePolicy.principalAccountIdentityReceiptSha256)
      || !canonicalEqual(value.supplementaryGroups, privilegePolicy.allowedSupplementaryGroups)
      || value.dockerGroupMembership !== false || value.dockerSocketAccess !== false
      || value.rootEquivalentCapabilities !== false || value.unrestrictedSudo !== false
      || !canonicalEqual(value.effectiveSudoCommands, expectedEffectiveSudoCommands)) {
    invalid("Phase B does not prove one unprivileged preexisting deployment account constrained to the exact broker command.");
  }
  for (const key of [
    "accountLookupReceiptSha256", "capabilityReceiptSha256", "dockerSocketAclReceiptSha256",
    "effectiveSudoReceiptSha256", "groupMembershipReceiptSha256", "passwdEntryReceiptSha256",
  ]) exactSha256(value[key], `deployment account ${key}`);
  exactDockerSocketIdentity(
    value.dockerSocketIdentity,
    expectedDockerDaemonId,
    value.principalUid,
    value.principalGid,
  );
  if (value.dockerSocketAclReceiptSha256 !== value.dockerSocketIdentity.aclArtifactSha256) {
    invalid("Deployment-account Docker ACL receipt does not bind the exact observed socket ACL bytes.");
  }
  assertDistinct([
    value.accountLookupReceiptSha256, value.capabilityReceiptSha256, value.dockerSocketAclReceiptSha256,
    value.effectiveSudoReceiptSha256, value.groupMembershipReceiptSha256, value.passwdEntryReceiptSha256,
  ], "Deployment-account authority evidence receipts");
  exactTimestamp(value.verifiedAt, "deployment account lookup verification time");
  return value;
}

function exactMaterializedIdentity(value, target, label) {
  exactObject(value, label, [
    "descriptorNoFollow", "deviceIdentity", "fileType", "filesystemUuid", "gid", "identityReceiptSha256", "inode",
    "kind", "mode", "mountId", "nlink", "path", "sha256", "sizeBytes", "symlink", "uid",
  ]);
  exactString(value.deviceIdentity, `${label} device identity`);
  exactSha256(value.filesystemUuid, `${label} filesystem UUID`);
  exactDecimal(value.inode, `${label} inode`, true);
  exactDecimal(value.mountId, `${label} mount ID`, true);
  exactInteger(value.nlink, `${label} link count`, 1);
  exactSha256(value.identityReceiptSha256, `${label} descriptor identity receipt SHA256`);
  if (value.path !== target.path || value.kind !== target.kind || value.uid !== target.uid || value.gid !== target.gid
      || value.mode !== target.mode || (target.nlink === null ? value.nlink < 1 : value.nlink !== target.nlink)
      || value.fileType !== (target.kind === "DIRECTORY" ? "DIRECTORY" : "REGULAR_FILE")
      || value.symlink !== false || value.descriptorNoFollow !== true
      || value.sha256 !== target.sha256 || value.sizeBytes !== target.sizeBytes) {
    invalid(`${label} differs from the exact materialization target identity.`);
  }
  return value;
}

function materializationAnchor(pathname) {
  if (pathname.startsWith("/var/lib/")) return "/var/lib";
  if (pathname.startsWith("/srv/")) return "/srv";
  if (pathname.startsWith("/usr/local/libexec/")) return "/usr/local/libexec";
  if (pathname.startsWith("/etc/sudoers.d/")) return "/etc/sudoers.d";
  invalid("Materialization target lacks one fixed trusted ancestry anchor.");
}

function findObservedParent(ancestry, anchorPath) {
  const all = [...ancestry.sourceParents, ...ancestry.destinationParents];
  const matches = all.filter((entry) => entry.path === anchorPath);
  if (matches.length < 1 || !matches.every((entry) => canonicalEqual(entry, matches[0]))) {
    invalid("Materialization ancestry does not provide one exact trusted anchor identity.");
  }
  return matches[0];
}

function exactMaterializationPreconditions(value, targets, ancestry) {
  if (!Array.isArray(value) || value.length !== targets.length) {
    invalid("Phase B requires one exact precondition for every materialization target.");
  }
  value.forEach((condition, index) => {
    const target = targets[index];
    const anchorPath = materializationAnchor(target.path);
    const anchor = findObservedParent(ancestry, anchorPath);
    const relativePath = path.posix.relative(anchorPath, target.path);
    if (condition?.state === "ABSENT_PROVEN") {
      exactObject(condition, `absent materialization precondition ${index}`, [
        "anchorIdentitySha256", "anchorPath", "negativeLookupReceiptSha256", "openat2ResolveBeneathNoSymlinks",
        "openat2ResolveNoXdev", "path", "relativePath", "state", "verifiedAt",
      ]);
      if (condition.path !== target.path || condition.anchorPath !== anchorPath
          || condition.anchorIdentitySha256 !== shaCanonical(anchor) || condition.relativePath !== relativePath
          || relativePath.startsWith("../") || path.posix.isAbsolute(relativePath)
          || condition.openat2ResolveBeneathNoSymlinks !== true || condition.openat2ResolveNoXdev !== true) {
        invalid("Absent materialization target is not proven below the exact trusted parent FD with BENEATH/NO_XDEV.");
      }
      exactSha256(condition.negativeLookupReceiptSha256, `absent materialization precondition ${index} receipt SHA256`);
      exactTimestamp(condition.verifiedAt, `absent materialization precondition ${index} time`);
    } else if (condition?.state === "EXISTING_EXACT") {
      exactObject(condition, `existing materialization precondition ${index}`, [
        "anchorIdentitySha256", "anchorPath", "identity", "openat2ResolveBeneathNoSymlinks",
        "openat2ResolveNoXdev", "path", "relativePath", "state", "verifiedAt",
      ]);
      if (condition.path !== target.path || condition.anchorPath !== anchorPath
          || condition.anchorIdentitySha256 !== shaCanonical(anchor) || condition.relativePath !== relativePath
          || relativePath.startsWith("../") || path.posix.isAbsolute(relativePath)
          || condition.openat2ResolveBeneathNoSymlinks !== true || condition.openat2ResolveNoXdev !== true) {
        invalid("Existing materialization target is not descriptor-relative below its exact NO_XDEV anchor.");
      }
      exactMaterializedIdentity(condition.identity, target, `existing materialization precondition ${index} identity`);
      if (condition.identity.deviceIdentity !== anchor.deviceIdentity
          || condition.identity.filesystemUuid !== anchor.filesystemUuid
          || condition.identity.mountId !== anchor.mountId) {
        invalid("Existing materialization target crosses a mount boundary below its trusted anchor.");
      }
      exactTimestamp(condition.verifiedAt, `existing materialization precondition ${index} time`);
    } else {
      invalid("Materialization precondition state must be ABSENT_PROVEN or EXISTING_EXACT.");
    }
  });
  for (let index = 0; index < targets.length; index += 1) {
    for (let ancestorIndex = 0; ancestorIndex < targets.length; ancestorIndex += 1) {
      if (index === ancestorIndex || !pathIsWithin(targets[index].path, targets[ancestorIndex].path)) continue;
      if (value[ancestorIndex].state === "ABSENT_PROVEN" && value[index].state !== "ABSENT_PROVEN") {
        invalid("First-install target hierarchy below an absent ancestor must remain entirely ABSENT_PROVEN.");
      }
    }
  }
  const requiredAbsentRoots = [
    "/var/lib/platform-infrastructure",
    targets.find((target) => target.path.includes("/v1-package-cas/sha256/") && target.kind === "DIRECTORY")?.path,
    "/srv/platform-infrastructure",
  ].filter(Boolean);
  for (const requiredPath of requiredAbsentRoots) {
    const targetIndex = targets.findIndex((target) => target.path === requiredPath);
    if (targetIndex < 0 || value[targetIndex].state !== "ABSENT_PROVEN") {
      invalid("First-install CAS and control-plane namespaces cannot be pre-staged or adopted.");
    }
  }
  assertDistinct(
    value.filter((condition) => condition.state === "ABSENT_PROVEN")
      .map((condition) => condition.negativeLookupReceiptSha256),
    "Per-target absence proof receipts",
  );
  return value;
}

function exactMaterializationOutcomes(value, targets, preconditions, transactionId, ancestry) {
  if (!Array.isArray(value) || value.length !== targets.length) {
    invalid("Install receipt requires one exact outcome for every materialization target.");
  }
  value.forEach((outcome, index) => {
    exactObject(outcome, `materialization outcome ${index}`, [
      "identity", "noReplacement", "path", "preconditionSha256", "state", "transactionId", "verifiedAt",
    ]);
    const precondition = preconditions[index];
    const target = targets[index];
    const expectedState = precondition.state === "ABSENT_PROVEN"
      ? "CREATED_BY_TRANSACTION" : "PREEXISTING_EXACT_UNCHANGED";
    if (outcome.path !== target.path || outcome.state !== expectedState
        || outcome.preconditionSha256 !== shaCanonical(precondition) || outcome.transactionId !== transactionId
        || outcome.noReplacement !== true) {
      invalid("Materialization outcome does not preserve the exact absent/existing precondition without replacement.");
    }
    exactMaterializedIdentity(outcome.identity, target, `materialization outcome ${index} identity`);
    const anchor = findObservedParent(ancestry, materializationAnchor(target.path));
    if (outcome.identity.deviceIdentity !== anchor.deviceIdentity
        || outcome.identity.filesystemUuid !== anchor.filesystemUuid
        || outcome.identity.mountId !== anchor.mountId) {
      invalid("Materialization outcome crosses its exact parent mount/filesystem despite NO_XDEV.");
    }
    const createdDirectDirectoryChildren = targets.filter((candidate, childIndex) => (
      candidate.kind === "DIRECTORY" && preconditions[childIndex].state === "ABSENT_PROVEN"
        && path.posix.dirname(candidate.path) === target.path
    )).length;
    if (target.kind === "DIRECTORY") {
      const expectedNlink = precondition.state === "EXISTING_EXACT"
        ? precondition.identity.nlink + createdDirectDirectoryChildren
        : 2 + createdDirectDirectoryChildren;
      if (outcome.identity.nlink !== expectedNlink) {
        invalid("Materialized directory link count does not match its exact created child nlink delta.");
      }
    }
    if (precondition.state === "EXISTING_EXACT") {
      const childNlinkDelta = target.kind === "DIRECTORY" ? createdDirectDirectoryChildren : 0;
      const stableKeys = [
        "deviceIdentity", "fileType", "filesystemUuid", "gid", "inode", "kind", "mode", "path", "sha256", "sizeBytes", "symlink", "uid",
      ];
      if (stableKeys.some((key) => !canonicalEqual(outcome.identity[key], precondition.identity[key]))
          || outcome.identity.nlink !== precondition.identity.nlink + childNlinkDelta
          || outcome.identity.identityReceiptSha256 === precondition.identity.identityReceiptSha256) {
        invalid("Preexisting materialization target identity changed, reused a stale receipt, or has the wrong child nlink delta.");
      }
    }
    exactTimestamp(outcome.verifiedAt, `materialization outcome ${index} time`);
  });
  assertDistinct(
    value.map((outcome) => `${outcome.identity.deviceIdentity}:${outcome.identity.filesystemUuid}:${outcome.identity.inode}`),
    "Materialization outcome filesystem object identities",
  );
  assertDistinct(value.map((outcome) => outcome.identity.identityReceiptSha256), "Materialization outcome identity receipts");
  return value;
}

function expectedPostInstallParentIdentities(preMutation, targets, preconditions) {
  const expected = {
    sourceParents: structuredClone(preMutation.sourceParents),
    destinationParents: structuredClone(preMutation.destinationParents),
  };
  for (let index = 0; index < targets.length; index += 1) {
    if (targets[index].kind !== "DIRECTORY" || preconditions[index].state !== "ABSENT_PROVEN") continue;
    const directParent = path.posix.dirname(targets[index].path);
    for (const parents of [expected.sourceParents, expected.destinationParents]) {
      const parent = parents.find((entry) => entry.path === directParent);
      if (parent !== undefined) parent.nlink += 1;
    }
  }
  return expected;
}

function safeIntegerSum(values, label) {
  let total = 0;
  for (const value of values) {
    exactInteger(value, `${label} member`, 0);
    if (value > Number.MAX_SAFE_INTEGER - total) invalid(`${label} overflows the exact safe-integer domain.`);
    total += value;
  }
  return total;
}

function exactResourceBudget(value, installPlan) {
  exactObject(value, "install resource budget", [
    "hardTotalWriteCeilingBytes", "maxCasBytes", "maxCreatedInodes", "maxDestinationBytes", "maxJournalBytes",
    "maxTotalWriteBytes", "packageMemberBytesTotal", "packageMemberCount", "requiredFreeBytesAfter",
    "requiredFreeInodesAfter", "schema",
  ]);
  const packageMembers = [installPlan.broker, installPlan.verifier, ...installPlan.helpers, installPlan.privilegePolicy];
  const packageMemberBytesTotal = safeIntegerSum(packageMembers.map((entry) => entry.sizeBytes), "package member byte sum");
  const maxCasBytes = safeIntegerSum(
    [installPlan.packageBytesSizeBytes, installPlan.packageManifestSizeBytes], "CAS byte sum",
  );
  const directoryMetadataBytes = installPlan.materializationTargets
    .filter((target) => target.kind === "DIRECTORY").length * 4096;
  const maxTotalWriteBytes = safeIntegerSum(
    [maxCasBytes, packageMemberBytesTotal, directoryMetadataBytes, value.maxJournalBytes], "total planned write bytes",
  );
  if (value.schema !== "platform.v1-install-resource-budget/v1"
      || value.packageMemberCount !== packageMembers.length
      || value.packageMemberBytesTotal !== packageMemberBytesTotal
      || value.maxCasBytes !== maxCasBytes || value.maxDestinationBytes !== packageMemberBytesTotal
      || value.maxTotalWriteBytes !== maxTotalWriteBytes
      || value.maxCreatedInodes !== installPlan.materializationTargets.length + 3
      || value.hardTotalWriteCeilingBytes !== 64 * 1024 * 1024
      || value.maxTotalWriteBytes > value.hardTotalWriteCeilingBytes
      || value.requiredFreeBytesAfter !== 1024 * 1024 * 1024
      || value.requiredFreeInodesAfter !== 10_000) {
    invalid("Install resource budget does not exactly bind package/member sums, inode count, reserve, and hard ceiling.");
  }
  exactInteger(value.maxJournalBytes, "resource budget journal bytes", 1, 4 * 1024 * 1024);
  for (const key of [
    "hardTotalWriteCeilingBytes", "maxCasBytes", "maxCreatedInodes", "maxDestinationBytes", "maxTotalWriteBytes",
    "packageMemberBytesTotal", "packageMemberCount", "requiredFreeBytesAfter", "requiredFreeInodesAfter",
  ]) exactInteger(value[key], `resource budget ${key}`, 1);
  return value;
}

function exactInstallPlan(value) {
  exactObject(value, "preinstall plan", [
    "broker", "directories", "helpers", "installerBootstrap", "materializationPolicy", "materializationTargets",
    "packageAttestationEnvelopeSha256", "packageBytesSha256", "packageBytesSizeBytes", "packageManifestSha256",
    "packageManifestSizeBytes", "plannedReceiptId", "privilegePolicy", "resourceBudget", "verifier",
  ]);
  for (const key of ["packageAttestationEnvelopeSha256", "packageBytesSha256", "packageManifestSha256"]) {
    exactSha256(value[key], `install plan ${key}`);
  }
  exactInteger(value.packageBytesSizeBytes, "install plan package byte size", 1, MAX_ARTIFACT_BYTES);
  exactInteger(value.packageManifestSizeBytes, "install plan package manifest size", 1, MAX_ARTIFACT_BYTES);
  exactString(value.plannedReceiptId, "planned install receipt ID", OPAQUE_IDENTIFIER);
  exactBinaryIdentity(value.broker, "activation broker", "/usr/local/libexec/platform-activation-broker");
  exactBinaryIdentity(value.verifier, "brownfield admission verifier", "/usr/local/libexec/platform-v1-brownfield-admission");
  exactArray(value.helpers, "install plan helpers", { min: 1 });
  const helperPaths = value.helpers.map((helper, index) => exactBinaryIdentity(helper, `install helper ${index}`).path);
  if (!canonicalEqual(helperPaths, REQUIRED_HELPER_PATHS)) {
    invalid("Install helper paths must be the exact fixed V1 helper set and order.");
  }
  assertDistinct([value.broker.path, value.verifier.path, ...helperPaths], "Planned executable paths");
  if (!Array.isArray(value.directories) || value.directories.length !== REQUIRED_DIRECTORY_PATHS.length) {
    invalid("Install plan requires the exact three-directory set.");
  }
  value.directories.forEach(exactDirectoryPlan);
  exactPrivilegePolicy(value.privilegePolicy);
  exactInstallerBootstrap(value.installerBootstrap);
  exactMaterializationPolicy(value.materializationPolicy, value.packageBytesSha256);
  exactMaterializationTargets(value.materializationTargets, value);
  exactResourceBudget(value.resourceBudget, value);
  return value;
}

export function validateV1BrownfieldInstallPlan(value) {
  const snapshot = JSON.parse(canonicalJson(value));
  exactInstallPlan(snapshot);
  return deepFreezeJson(snapshot);
}

function plannedResourcesByDevice(installPlan, ancestry, preconditions) {
  const devices = new Map();
  for (let index = 0; index < installPlan.materializationTargets.length; index += 1) {
    const target = installPlan.materializationTargets[index];
    const parent = preconditions[index].state === "EXISTING_EXACT"
      ? preconditions[index].identity : findObservedParent(ancestry, materializationAnchor(target.path));
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
    device.plannedWriteBytes = safeIntegerSum(
      [device.plannedWriteBytes, target.sizeBytes ?? 4096], "per-device planned write bytes",
    );
    device.plannedCreatedInodes += 1;
  }
  const varParent = findObservedParent(ancestry, "/var/lib");
  const varKey = `${varParent.deviceIdentity}:${varParent.filesystemUuid}`;
  const varDevice = devices.get(varKey);
  if (!varDevice.mountIds.includes(varParent.mountId)) varDevice.mountIds.push(varParent.mountId);
  varDevice.plannedWriteBytes = safeIntegerSum(
    [varDevice.plannedWriteBytes, installPlan.resourceBudget.maxJournalBytes], "per-device journal write bytes",
  );
  varDevice.plannedCreatedInodes += 3;
  for (const device of devices.values()) device.mountIds.sort((left, right) => Number(left) - Number(right));
  return [...devices.values()];
}

function exactResourceObservation(value, installPlan, ancestry, preconditions) {
  exactObject(value, "pre-mutation resource observation", ["devices", "observedAt", "receiptSha256", "schema"]);
  if (value.schema !== "platform.v1-pre-mutation-resource-observation/v1") {
    invalid("Pre-mutation resource observation schema is invalid.");
  }
  const expected = plannedResourcesByDevice(installPlan, ancestry, preconditions);
  if (!Array.isArray(value.devices) || value.devices.length !== expected.length) {
    invalid("Pre-mutation resource observation does not cover every distinct target device.");
  }
  value.devices.forEach((device, index) => {
    exactObject(device, `pre-mutation resource device ${index}`, [
      "deviceIdentity", "filesystemUuid", "freeBytes", "freeInodes", "mountIds", "plannedCreatedInodes", "plannedWriteBytes",
      "requiredFreeBytesAfter", "requiredFreeInodesAfter",
    ]);
    const planned = expected[index];
    if (device.deviceIdentity !== planned.deviceIdentity || device.filesystemUuid !== planned.filesystemUuid
        || !canonicalEqual(device.mountIds, planned.mountIds)
        || device.plannedWriteBytes !== planned.plannedWriteBytes
        || device.plannedCreatedInodes !== planned.plannedCreatedInodes
        || device.requiredFreeBytesAfter !== installPlan.resourceBudget.requiredFreeBytesAfter
        || device.requiredFreeInodesAfter !== installPlan.resourceBudget.requiredFreeInodesAfter) {
      invalid("Pre-mutation resource observation does not bind exact per-device aggregate writes and reserves.");
    }
    exactInteger(device.freeBytes, `pre-mutation resource device ${index} free bytes`, 0);
    exactInteger(device.freeInodes, `pre-mutation resource device ${index} free inodes`, 0);
    if (device.freeBytes - device.plannedWriteBytes < device.requiredFreeBytesAfter
        || device.freeInodes - device.plannedCreatedInodes < device.requiredFreeInodesAfter) {
      invalid("Pre-mutation resource observation lacks the required post-install disk/inode reserve.");
    }
  });
  exactSha256(value.receiptSha256, "pre-mutation resource receipt SHA256");
  exactTimestamp(value.observedAt, "pre-mutation resource observation time");
  return value;
}

function mandatoryAccountedResources(materializationOutcomes, ledger) {
  const resources = new Map();
  const add = (identity, sizeBytes, label) => {
    const key = `${identity.deviceIdentity}:${identity.filesystemUuid}`;
    if (!resources.has(key)) resources.set(key, { createdInodes: 0, writtenBytes: 0 });
    const resource = resources.get(key);
    resource.writtenBytes = safeIntegerSum([resource.writtenBytes, sizeBytes], `${label} mandatory byte sum`);
    resource.createdInodes += 1;
  };
  for (const outcome of materializationOutcomes) {
    if (outcome.state === "CREATED_BY_TRANSACTION") {
      add(outcome.identity, outcome.identity.sizeBytes ?? 4096, "created materialization target");
    }
  }
  add(ledger.claimObjectIdentity, ledger.claimSizeBytes, "Phase B claim");
  add(ledger.journalObjectIdentity, ledger.journalRecordSizeBytes, "Phase B journal");
  return resources;
}

function exactResourceOutcome(value, observation, installedAt, materializationOutcomes, ledger) {
  exactObject(value, "post-install resource outcome", [
    "devices", "preMutationObservationReceiptSha256", "receiptSha256", "verifiedAt",
  ]);
  if (value.preMutationObservationReceiptSha256 !== observation.receiptSha256) {
    invalid("Post-install resource outcome does not bind the exact pre-mutation resource observation.");
  }
  if (!Array.isArray(value.devices) || value.devices.length !== observation.devices.length) {
    invalid("Post-install resource outcome does not cover every observed target device.");
  }
  const mandatory = mandatoryAccountedResources(materializationOutcomes, ledger);
  const observedKeys = new Set();
  value.devices.forEach((device, index) => {
    exactObject(device, `post-install resource device ${index}`, [
      "actualCreatedInodes", "actualWrittenBytes", "deviceIdentity", "filesystemUuid", "freeBytes", "freeInodes", "mountIds",
      "installerAccountingReceiptSha256", "plannedCreatedInodes", "plannedWriteBytes", "requiredFreeBytesAfter",
      "requiredFreeInodesAfter",
    ]);
    const before = observation.devices[index];
    const key = `${device.deviceIdentity}:${device.filesystemUuid}`;
    const minimum = mandatory.get(key) ?? { createdInodes: 0, writtenBytes: 0 };
    observedKeys.add(key);
    if (device.deviceIdentity !== before.deviceIdentity || device.filesystemUuid !== before.filesystemUuid
        || !canonicalEqual(device.mountIds, before.mountIds)
        || device.plannedWriteBytes !== before.plannedWriteBytes
        || device.plannedCreatedInodes !== before.plannedCreatedInodes
        || device.requiredFreeBytesAfter !== before.requiredFreeBytesAfter
        || device.requiredFreeInodesAfter !== before.requiredFreeInodesAfter
        || !Number.isSafeInteger(device.freeBytes) || !Number.isSafeInteger(device.freeInodes)
        || !Number.isSafeInteger(device.actualWrittenBytes) || device.actualWrittenBytes < 0
        || !Number.isSafeInteger(device.actualCreatedInodes) || device.actualCreatedInodes < 0
        || device.actualWrittenBytes < minimum.writtenBytes
        || device.actualCreatedInodes < minimum.createdInodes
        || device.actualWrittenBytes > before.plannedWriteBytes
        || device.actualCreatedInodes > before.plannedCreatedInodes
        || device.freeBytes < device.requiredFreeBytesAfter || device.freeInodes < device.requiredFreeInodesAfter) {
      invalid("Post-install resource outcome violates the exact plan, mandatory created-object accounting lower bound, device identity, or required reserve.");
    }
    exactSha256(device.installerAccountingReceiptSha256, `post-install resource device ${index} accounting receipt SHA256`);
  });
  assertDistinct(
    value.devices.map((device) => device.installerAccountingReceiptSha256),
    "Per-device installer resource-accounting receipts",
  );
  if ([...mandatory.keys()].some((key) => !observedKeys.has(key))) {
    invalid("Post-install resource outcome omits a filesystem with mandatory created-object accounting.");
  }
  exactSha256(value.preMutationObservationReceiptSha256, "post-install resource observation binding SHA256");
  exactSha256(value.receiptSha256, "post-install resource receipt SHA256");
  const verifiedAt = exactTimestamp(value.verifiedAt, "post-install resource verification time").milliseconds;
  if (verifiedAt > installedAt) invalid("Post-install resource outcome was verified after installation completion.");
  return value;
}

function exactAncestryVerification(value, materializationPolicy, label) {
  exactObject(value, label, [
    "destinationParents", "materializationPolicySha256", "sourceParents", "verificationReceiptSha256", "verifiedAt",
  ]);
  if (value.materializationPolicySha256 !== shaCanonical(materializationPolicy)) {
    invalid(`${label} does not bind the exact materialization policy.`);
  }
  const validateParents = (parents, paths, ancestryLabel) => {
    if (!Array.isArray(parents) || parents.length !== paths.length) {
      invalid(`${label} does not contain the exact ${ancestryLabel} ancestry.`);
    }
    parents.forEach((parent, index) => {
      exactObject(parent, `${label} ${ancestryLabel} parent ${index}`, [
        "deviceIdentity", "filesystemUuid", "gid", "inode", "mode", "mountId", "nlink", "path", "symlink", "uid", "writableByNonRoot",
      ]);
      exactString(parent.deviceIdentity, `${label} ${ancestryLabel} parent ${index} device identity`);
      exactSha256(parent.filesystemUuid, `${label} ${ancestryLabel} parent ${index} filesystem UUID`);
      exactDecimal(parent.inode, `${label} ${ancestryLabel} parent ${index} inode`, true);
      exactDecimal(parent.mountId, `${label} ${ancestryLabel} parent ${index} mount ID`, true);
      exactInteger(parent.nlink, `${label} ${ancestryLabel} parent ${index} link count`, 1);
      if (parent.path !== paths[index] || parent.uid !== 0 || parent.gid !== 0
          || parent.mode !== "0755" || parent.symlink !== false || parent.writableByNonRoot !== false) {
        invalid(`${label} does not prove exact root-owned, non-writable, no-symlink ${ancestryLabel} identities.`);
      }
    });
  };
  validateParents(value.sourceParents, sourceParentPaths(materializationPolicy.casRoot.split("/").at(-1)), "source CAS");
  validateParents(value.destinationParents, REQUIRED_TARGET_PARENT_PATHS, "destination");
  const observations = [...value.sourceParents, ...value.destinationParents];
  for (let index = 0; index < observations.length; index += 1) {
    for (let otherIndex = index + 1; otherIndex < observations.length; otherIndex += 1) {
      const left = observations[index];
      const right = observations[otherIndex];
      if (left.path === right.path && !canonicalEqual(left, right)) {
        invalid(`${label} gives the same path incompatible shared ancestry identities.`);
      }
      if (left.path !== right.path
          && left.deviceIdentity === right.deviceIdentity
          && left.filesystemUuid === right.filesystemUuid
          && left.inode === right.inode) {
        invalid(`${label} aliases one filesystem object at multiple trusted ancestry paths.`);
      }
    }
  }
  exactSha256(value.verificationReceiptSha256, `${label} receipt SHA256`);
  exactTimestamp(value.verifiedAt, `${label} time`);
  return value;
}

function domainSeparatedSha256(domain, ...values) {
  return crypto.createHash("sha256").update([domain, ...values].join("\0"), "utf8").digest("hex");
}

function exactReplayClaimPrecondition(value, preinstall, ancestry) {
  exactObject(value, "Phase B replay claim precondition", [
    "atomicCreateExclusiveRequired", "authorizationId", "claimFileFsyncRequired",
    "claimNegativeLookupReceiptSha256", "claimObjectPath", "claimParentFsyncRequired",
    "ledgerAncestrySha256", "ledgerEntryKeySha256", "ledgerParentIdentitySha256", "ledgerParentPath",
    "nonce", "openat2ResolveBeneathNoSymlinks", "openat2ResolveNoXdev", "policySha256",
    "preinstallTupleSha256", "schema", "verifiedAt",
  ]);
  const ledgerParentIndex = ancestry.sourceParents.findIndex((parent) => parent.path === "/var/lib");
  const ledgerParent = ancestry.sourceParents[ledgerParentIndex];
  exactString(value.authorizationId, "Phase B replay claim authorization ID", OPAQUE_IDENTIFIER);
  exactNonce(value.nonce, "Phase B replay claim nonce");
  const expectedPreinstallSha256 = shaCanonical(preinstall);
  const expectedEntryKey = domainSeparatedSha256(
    "phase-b-ledger-v1", value.authorizationId, value.nonce, preinstall.transactionId,
    value.policySha256, value.preinstallTupleSha256,
  );
  if (value.schema !== "platform.v1-phase-b-replay-claim-precondition/v1"
      || value.policySha256 !== preinstall.installPlan.installerBootstrap.trustPolicySha256
      || value.preinstallTupleSha256 !== expectedPreinstallSha256
      || value.ledgerEntryKeySha256 !== expectedEntryKey
      || value.ledgerParentPath !== "/var/lib" || ledgerParentIndex !== 2
      || value.ledgerParentIdentitySha256 !== shaCanonical(ledgerParent)
      || value.ledgerAncestrySha256 !== shaCanonical(ancestry.sourceParents.slice(0, ledgerParentIndex + 1))
      || value.claimObjectPath !== `/var/lib/.platform-v1-phase-b-claim-${expectedEntryKey}`
      || value.atomicCreateExclusiveRequired !== true || value.claimFileFsyncRequired !== true
      || value.claimParentFsyncRequired !== true || value.openat2ResolveBeneathNoSymlinks !== true
      || value.openat2ResolveNoXdev !== true) {
    invalid("Phase B replay claim precondition does not pre-authorize one atomic NO_XDEV /var/lib claim.");
  }
  for (const key of [
    "claimNegativeLookupReceiptSha256", "ledgerAncestrySha256", "ledgerEntryKeySha256",
    "ledgerParentIdentitySha256", "policySha256", "preinstallTupleSha256",
  ]) exactSha256(value[key], `Phase B replay claim ${key}`);
  exactTimestamp(value.verifiedAt, "Phase B replay claim precondition verification time");
  return value;
}

function exactPhaseBLedgerConsumption(value, phaseB, transactionId, receiptId, installPlan, materializationOutcomes) {
  exactObject(value, "Phase B replay-ledger consumption", [
    "atomicCreateExclusive", "authorizationEnvelopeSha256", "authorizationId", "claimArtifactSha256", "claimCreatedAt",
    "claimDurablyCommitted", "claimFileFsyncCompleted", "claimId", "claimNegativeLookupReceiptSha256",
    "claimObjectIdentity", "claimObjectPath", "claimParentFsyncCompleted", "claimSizeBytes", "consumedAt",
    "failureTerminal", "firstNonClaimMutationAt", "firstWritePath", "journalArtifactSha256",
    "journalNegativeLookupReceiptSha256", "journalObjectIdentity", "journalParentIdentitySha256",
    "journalRecordCreatedExclusive", "journalRecordFsyncCompleted", "journalRecordPath", "journalRecordSizeBytes",
    "journalRecordWrittenAt",
    "ledgerAncestrySha256", "ledgerEntryKeySha256", "ledgerId", "ledgerParentIdentitySha256", "ledgerParentPath",
    "nonce", "receiptArtifactSha256", "receiptCreatedExclusive", "receiptFsyncCompleted",
    "receiptNegativeLookupReceiptSha256", "receiptObjectIdentity", "receiptObjectKeySha256", "receiptObjectPath",
    "receiptParentIdentitySha256", "receiptSizeBytes", "receiptStorePath", "receiptWrittenAt", "replayRejected",
    "schema", "state",
  ]);
  const ledgerParentIndex = phaseB.preMutationAncestryVerification.sourceParents
    .findIndex((parent) => parent.path === "/var/lib");
  const ledgerParent = phaseB.preMutationAncestryVerification.sourceParents[ledgerParentIndex];
  const ledgerEntryKey = domainSeparatedSha256(
    "phase-b-ledger-v1", phaseB.authorizationId, phaseB.nonce, transactionId,
    phaseB.policySha256, phaseB.preinstallTupleSha256,
  );
  const receiptObjectKey = domainSeparatedSha256("install-receipt-v1", receiptId, transactionId);
  const journalRecordPath = `/var/lib/platform-infrastructure/v1-phase-b-ledger/${ledgerEntryKey}.json`;
  const receiptObjectPath = `/var/lib/platform-infrastructure/v1-install-receipts/sha256/${receiptObjectKey}.json`;
  const journalParent = materializationOutcomes.find(
    (outcome) => outcome.path === "/var/lib/platform-infrastructure/v1-phase-b-ledger",
  );
  const receiptParent = materializationOutcomes.find(
    (outcome) => outcome.path === "/var/lib/platform-infrastructure/v1-install-receipts/sha256",
  );
  if (value.claimObjectPath !== phaseB.replayClaimPrecondition.claimObjectPath
      || value.claimNegativeLookupReceiptSha256
        !== phaseB.replayClaimPrecondition.claimNegativeLookupReceiptSha256
      || value.ledgerParentIdentitySha256
        !== phaseB.replayClaimPrecondition.ledgerParentIdentitySha256
      || value.ledgerAncestrySha256 !== phaseB.replayClaimPrecondition.ledgerAncestrySha256) {
    invalid("Phase B replay ledger does not consume its exact pre-authorized claim precondition.");
  }
  if (value.schema !== "platform.v1-phase-b-replay-ledger-consumption/v1"
      || value.ledgerId !== "platform-v1-phase-b-installer-ledger"
      || value.ledgerParentPath !== "/var/lib"
      || value.claimObjectPath !== `/var/lib/.platform-v1-phase-b-claim-${ledgerEntryKey}`
      || value.firstWritePath !== value.claimObjectPath
      || value.journalRecordPath !== journalRecordPath
      || value.receiptStorePath !== "/var/lib/platform-infrastructure/v1-install-receipts/sha256"
      || ledgerParentIndex !== 2 || value.ledgerParentIdentitySha256 !== shaCanonical(ledgerParent)
      || value.ledgerAncestrySha256 !== shaCanonical(
        phaseB.preMutationAncestryVerification.sourceParents.slice(0, ledgerParentIndex + 1),
      )
      || value.authorizationEnvelopeSha256 !== phaseB.authorizationEnvelopeSha256
      || value.authorizationId !== phaseB.authorizationId || value.nonce !== phaseB.nonce
      || value.ledgerEntryKeySha256 !== ledgerEntryKey
      || value.receiptObjectKeySha256 !== receiptObjectKey || value.receiptObjectPath !== receiptObjectPath
      || journalParent === undefined || receiptParent === undefined
      || value.journalParentIdentitySha256 !== shaCanonical(journalParent.identity)
      || value.receiptParentIdentitySha256 !== shaCanonical(receiptParent.identity)
      || value.state !== "CONSUMED_BEFORE_FIRST_NON_CLAIM_MUTATION"
      || value.atomicCreateExclusive !== true || value.claimDurablyCommitted !== true
      || value.claimFileFsyncCompleted !== true || value.claimParentFsyncCompleted !== true
      || value.journalRecordCreatedExclusive !== true || value.journalRecordFsyncCompleted !== true
      || value.receiptCreatedExclusive !== true || value.receiptFsyncCompleted !== true
      || value.failureTerminal !== true || value.replayRejected !== true) {
    invalid("Phase B replay ledger does not prove a fixed, fsynced, failure-terminal consume before first write.");
  }
  exactString(value.claimId, "Phase B replay-ledger claim ID", IDENTIFIER);
  if (value.claimId !== `phase-b-claim:${ledgerEntryKey}`) {
    invalid("Phase B replay-ledger claim ID is not derived from the pre-authorized ledger entry key.");
  }
  for (const key of [
    "authorizationEnvelopeSha256", "claimArtifactSha256", "claimNegativeLookupReceiptSha256",
    "journalArtifactSha256", "journalNegativeLookupReceiptSha256", "journalParentIdentitySha256",
    "ledgerAncestrySha256", "ledgerEntryKeySha256", "ledgerParentIdentitySha256", "receiptArtifactSha256",
    "receiptNegativeLookupReceiptSha256", "receiptObjectKeySha256", "receiptParentIdentitySha256",
  ]) exactSha256(value[key], `Phase B replay-ledger ${key}`);
  for (const key of ["claimSizeBytes", "journalRecordSizeBytes", "receiptSizeBytes"]) {
    exactInteger(value[key], `Phase B replay-ledger ${key}`, 1, installPlan.resourceBudget.maxJournalBytes);
  }
  if (safeIntegerSum(
    [value.claimSizeBytes, value.journalRecordSizeBytes, value.receiptSizeBytes],
    "Phase B ledger metadata byte sum",
  ) > installPlan.resourceBudget.maxJournalBytes) {
    invalid("Phase B ledger claim, record, and receipt bytes exceed the exact metadata write budget.");
  }
  const claimTarget = {
    path: value.claimObjectPath, kind: "REPLAY_CLAIM", uid: 0, gid: 0, mode: "0400", nlink: 1,
    sha256: value.claimArtifactSha256, sizeBytes: value.claimSizeBytes,
  };
  const journalTarget = {
    path: value.journalRecordPath, kind: "LEDGER_RECORD", uid: 0, gid: 0, mode: "0400", nlink: 1,
    sha256: value.journalArtifactSha256, sizeBytes: value.journalRecordSizeBytes,
  };
  const receiptTarget = {
    path: value.receiptObjectPath, kind: "INSTALL_RECEIPT", uid: 0, gid: 0, mode: "0400", nlink: 1,
    sha256: value.receiptArtifactSha256, sizeBytes: value.receiptSizeBytes,
  };
  exactMaterializedIdentity(value.claimObjectIdentity, claimTarget, "Phase B replay claim object identity");
  exactMaterializedIdentity(value.journalObjectIdentity, journalTarget, "Phase B ledger record identity");
  exactMaterializedIdentity(value.receiptObjectIdentity, receiptTarget, "Phase B receipt object identity");
  if (value.claimObjectIdentity.deviceIdentity !== ledgerParent.deviceIdentity
      || value.claimObjectIdentity.filesystemUuid !== ledgerParent.filesystemUuid
      || value.claimObjectIdentity.mountId !== ledgerParent.mountId
      || value.journalObjectIdentity.deviceIdentity !== journalParent.identity.deviceIdentity
      || value.journalObjectIdentity.filesystemUuid !== journalParent.identity.filesystemUuid
      || value.journalObjectIdentity.mountId !== journalParent.identity.mountId
      || value.receiptObjectIdentity.deviceIdentity !== receiptParent.identity.deviceIdentity
      || value.receiptObjectIdentity.filesystemUuid !== receiptParent.identity.filesystemUuid
      || value.receiptObjectIdentity.mountId !== receiptParent.identity.mountId) {
    invalid("Phase B ledger leaf identities are not on their exact trusted parent filesystems.");
  }
  assertDistinct([
    value.claimNegativeLookupReceiptSha256, value.journalNegativeLookupReceiptSha256,
    value.receiptNegativeLookupReceiptSha256,
  ], "Phase B ledger leaf absence receipts");
  assertDistinct([
    value.claimObjectIdentity.identityReceiptSha256, value.journalObjectIdentity.identityReceiptSha256,
    value.receiptObjectIdentity.identityReceiptSha256,
  ], "Phase B ledger leaf identity receipts");
  exactString(value.authorizationId, "Phase B replay-ledger authorization ID", OPAQUE_IDENTIFIER);
  exactNonce(value.nonce, "Phase B replay-ledger nonce");
  const claimCreatedAt = exactTimestamp(value.claimCreatedAt, "Phase B replay claim creation time").milliseconds;
  const consumedAt = exactTimestamp(value.consumedAt, "Phase B replay-ledger consume time").milliseconds;
  const journalWrittenAt = exactTimestamp(value.journalRecordWrittenAt, "Phase B ledger record write time").milliseconds;
  const receiptWrittenAt = exactTimestamp(value.receiptWrittenAt, "Phase B receipt object write time").milliseconds;
  const firstMutationAt = exactTimestamp(
    value.firstNonClaimMutationAt, "Phase B first non-claim mutation time",
  ).milliseconds;
  if (claimCreatedAt > consumedAt || consumedAt >= firstMutationAt
      || firstMutationAt > journalWrittenAt || journalWrittenAt > receiptWrittenAt) {
    invalid("Phase B claim must be the first write and be durably consumed before every non-claim mutation.");
  }
  return { claimCreatedAt, consumedAt, firstMutationAt, journalWrittenAt, receiptWrittenAt };
}

function preinstallTypedArtifactHashes(value) {
  const backup = value.authoritativeBackupAttestation;
  return [
    value.phaseA.authorizationEnvelopeSha256, value.phaseA.consumerChallengeSha256,
    value.phaseA.orderContractSha256, value.phaseA.packageAttestationEnvelopeSha256,
    value.phaseA.packageSha256, value.phaseA.packageManifestSha256, value.phaseA.policySha256,
    value.phaseA.verificationReceiptSha256, value.baseline.artifactSha256, value.baseline.sourceDeviceSetSha256,
    value.baseline.protectedArtifactSetSha256, value.baseline.databaseSetSha256,
    value.structuralBackupReceipt.artifactSha256, value.structuralBackupReceipt.backupManifestSha256,
    value.structuralBackupReceipt.backupArtifactSetSha256, backup.backupTrustPolicySha256, backup.evidenceArtifactSha256,
    backup.offHostRetrieval.retrievedBytesSha256, backup.offHostRetrieval.retrievalReceiptArtifactSha256,
    backup.restoreDrill.restoreDrillArtifactSha256, backup.databaseConsistency.verificationArtifactSha256,
    backup.databaseConsistency.databaseCatalogSha256,
    backup.writeConsistency.snapshotReceiptArtifactSha256, backup.writeConsistency.sourceWriteWatermarkSha256,
    ...(value.identityTransition === null ? [] : [value.identityTransition.artifactSha256]),
    value.installPlan.broker.sha256, value.installPlan.verifier.sha256,
    ...value.installPlan.helpers.map((helper) => helper.sha256),
    value.installPlan.privilegePolicy.sha256, value.installPlan.privilegePolicy.principalAccountIdentityReceiptSha256,
    value.installPlan.privilegePolicy.providerValidationReceiptSha256, value.installPlan.privilegePolicy.validatorSha256,
    value.installPlan.installerBootstrap.sha256, value.installPlan.installerBootstrap.executionIdentitySha256,
    value.installPlan.installerBootstrap.trustPolicySha256, value.rollbackPolicy.artifactSha256,
  ];
}

function validatePreinstallTuple(value) {
  exactObject(value, "preinstall tuple", [
    "activationTarget", "authoritativeBackupAttestation", "baseline", "candidate",
    "identityTransition", "installPlan", "phaseA", "rollbackPolicy", "schema", "sourceTarget", "strategy",
    "structuralBackupReceipt", "transactionId",
  ]);
  if (value.schema !== "platform.v1-brownfield-preinstall-tuple/v1") invalid("Preinstall tuple schema is invalid.");
  exactSha256(value.transactionId, "preinstall tuple transaction ID");

  exactObject(value.candidate, "common tuple candidate", [
    "commitSha", "repository", "repositoryId", "repositoryOwnerId", "sourceArchiveSha256", "treeSha",
  ]);
  exactRepository(value.candidate.repository, "candidate repository");
  if (value.candidate.repository !== value.candidate.repository.toLowerCase()) {
    invalid("Candidate repository slug must be canonical lowercase owner/name.");
  }
  exactDecimal(value.candidate.repositoryId, "candidate repository ID", true);
  exactDecimal(value.candidate.repositoryOwnerId, "candidate repository owner ID", true);
  exactGitSha(value.candidate.commitSha, "candidate commit SHA");
  exactGitSha(value.candidate.treeSha, "candidate tree SHA");
  exactSha256(value.candidate.sourceArchiveSha256, "candidate source archive SHA256");
  if (value.strategy !== "ADDITIVE") {
    invalid("This V1 admission tranche authorizes ADDITIVE only; rebuild/destruction requires a separate target-restore admission.");
  }
  exactTarget(value.sourceTarget, "source target");
  exactTarget(value.activationTarget, "activation target", { activation: true });
  if (value.strategy === "ADDITIVE") {
    const preservedHostKeys = [
      "deploymentGid", "deploymentUid", "dockerDaemonId", "endpoint", "environment", "host", "machineId",
      "rootFilesystemIdentitySha256", "sshHostKeySha256",
    ];
    if (value.identityTransition !== null
        || preservedHostKeys.some((key) => value.sourceTarget[key] !== value.activationTarget[key])
        || pathsOverlap(value.sourceTarget.root, value.activationTarget.root)) {
      invalid("ADDITIVE strategy requires the same host authority and a distinct non-overlapping activation root without rebuild authority.");
    }
  }

  exactObject(value.phaseA, "common tuple Phase A binding", [
    "authorizationEnvelopeSha256", "authorizationId", "authorizationPayloadType", "authorizationProviderKeyId",
    "authorizedCandidate", "authorizedCandidateSha256", "authorizedTarget", "authorizedTargetSha256",
    "candidateClean", "consumerChallengeSha256",
    "expiresAt", "futureRoleKeyIds", "issuedAt", "nonce",
    "orderContractId", "orderContractSha256", "packageAttestationEnvelopeSha256", "packageAttestationId", "packageAttestorKeyId",
    "packageManifestSha256", "packagePayloadType", "packageSha256", "policySha256", "replayLedgerStatus", "scope",
    "verificationReceiptSha256", "verifiedAt",
  ]);
  for (const key of [
    "authorizationEnvelopeSha256", "authorizationProviderKeyId", "authorizedCandidateSha256", "authorizedTargetSha256",
    "orderContractSha256", "packageAttestationEnvelopeSha256",
    "consumerChallengeSha256", "packageManifestSha256", "packageSha256", "policySha256", "verificationReceiptSha256",
    "packageAttestorKeyId",
  ]) exactSha256(value.phaseA[key], `Phase A ${key}`);
  const expectedPhaseATarget = phaseAAuthorizedTargetProjection(value.activationTarget);
  exactObject(value.phaseA.authorizedTarget, "Phase A exact authorized target", [
    "deploymentGid", "deploymentUid", "dockerDaemonId", "endpoint", "hostname", "machineIdentitySha256",
    "rootFilesystemIdentitySha256", "sshHostKeySha256", "targetRoot",
  ]);
  if (!canonicalEqual(value.phaseA.authorizedTarget, expectedPhaseATarget)
      || value.phaseA.authorizedTargetSha256 !== shaCanonical(value.phaseA.authorizedTarget)) {
    invalid("Phase A authorized target does not bind the exact frozen raw target bytes and activation host/root projection.");
  }
  const expectedPhaseACandidate = phaseAAuthorizedCandidateProjection(value.candidate, value.phaseA);
  exactObject(value.phaseA.authorizedCandidate, "Phase A exact authorized candidate", [
    "clean", "commitSha", "packageManifestSha256", "packageSha256", "repository", "repositoryId",
    "repositoryOwnerId", "sourceArchiveSha256", "treeSha",
  ]);
  if (!canonicalEqual(value.phaseA.authorizedCandidate, expectedPhaseACandidate)
      || value.phaseA.authorizedCandidateSha256 !== shaCanonical(value.phaseA.authorizedCandidate)) {
    invalid("Phase A authorized candidate does not bind the exact frozen raw candidate bytes and core projection.");
  }
  if (value.phaseA.packageAttestorKeyId === value.phaseA.authorizationProviderKeyId) {
    invalid("Phase A package-attestor and authorization-provider keys must be distinct.");
  }
  if (value.phaseA.candidateClean !== true) invalid("Phase A binding must preserve the verified clean-candidate state.");
  exactObject(value.phaseA.futureRoleKeyIds, "Phase A future-role key IDs", [
    "activationGate", "activationTargetRoot", "admissionController", "backupAuthority", "deploymentGate",
    "hostedGate", "phaseBInstaller", "sourceTargetCustodian",
  ]);
  for (const [role, keyId] of Object.entries(value.phaseA.futureRoleKeyIds)) {
    exactSha256(keyId, `Phase A ${role} future-role key ID`);
  }
  assertDistinct(Object.values(value.phaseA.futureRoleKeyIds), "Phase A future-role key IDs");
  exactNonce(value.phaseA.nonce, "Phase A nonce");
  exactString(value.phaseA.authorizationId, "Phase A authorization ID", OPAQUE_IDENTIFIER);
  exactString(value.phaseA.packageAttestationId, "Phase A package attestation ID", OPAQUE_IDENTIFIER);
  exactString(value.phaseA.orderContractId, "Phase A order contract ID", OPAQUE_IDENTIFIER);
  if (value.phaseA.scope !== "READ_ONLY_LIVE_PREFLIGHT"
      || value.phaseA.packagePayloadType !== "application/vnd.platform.v1.phase-a.package-attestation.v1+json"
      || value.phaseA.authorizationPayloadType !== "application/vnd.platform.v1.phase-a.read-only-authorization.v1+json"
      || value.phaseA.replayLedgerStatus !== "EXTERNAL_PENDING") {
    invalid("Phase A scope, payload domains, or external replay status is invalid.");
  }
  exactTimestamp(value.phaseA.issuedAt, "Phase A issue time");
  exactTimestamp(value.phaseA.verifiedAt, "Phase A verification time");
  exactTimestamp(value.phaseA.expiresAt, "Phase A expiry time");

  exactObject(value.baseline, "common tuple baseline", [
    "artifactSha256", "baselineId", "captureCompletedAt", "captureStartedAt", "classification", "complete",
    "databaseCount", "databaseSetSha256", "deficiencies", "protectedArtifactCount", "protectedArtifactSetSha256",
    "schema", "sourceDeviceCount", "sourceDeviceIdentitiesComplete", "sourceDeviceSetSha256",
    "verifiedAt", "version",
  ]);
  if (value.baseline.schema !== "platform.live-preservation-baseline/v1" || value.baseline.version !== 1
      || value.baseline.classification !== "COMPLETE-PRESERVATION-BASELINE") {
    invalid("Baseline identity/classification is invalid.");
  }
  exactSha256(value.baseline.artifactSha256, "baseline artifact SHA256");
  exactSha256(value.baseline.baselineId, "baseline ID");
  if (value.baseline.complete !== true || !Array.isArray(value.baseline.deficiencies)
      || value.baseline.deficiencies.length !== 0 || value.baseline.sourceDeviceIdentitiesComplete !== true) {
    invalid("Baseline must be complete with no deficiencies and a complete source-device set.");
  }
  exactSha256(value.baseline.sourceDeviceSetSha256, "baseline source-device-set SHA256");
  exactInteger(value.baseline.sourceDeviceCount, "baseline source-device count", 1);
  exactSha256(value.baseline.protectedArtifactSetSha256, "baseline protected-artifact-set SHA256");
  exactInteger(value.baseline.protectedArtifactCount, "baseline protected-artifact count", 1);
  exactSha256(value.baseline.databaseSetSha256, "baseline database-set SHA256");
  exactInteger(value.baseline.databaseCount, "baseline database count", 1);
  exactTimestamp(value.baseline.captureStartedAt, "baseline capture start");
  exactTimestamp(value.baseline.captureCompletedAt, "baseline capture completion");
  exactTimestamp(value.baseline.verifiedAt, "baseline verification time");

  exactObject(value.structuralBackupReceipt, "structural backup receipt binding", [
    "artifactSha256", "authoritative", "backupArtifactSetSha256", "backupManifestSha256", "backupSetId",
    "databaseCount", "databaseSetSha256", "protectedArtifactCount", "protectedArtifactSetSha256",
    "receiptId", "schema", "status", "verifiedAt",
  ]);
  for (const key of [
    "artifactSha256", "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "databaseSetSha256",
    "protectedArtifactSetSha256", "receiptId",
  ]) {
    exactSha256(value.structuralBackupReceipt[key], `structural backup receipt ${key}`);
  }
  exactInteger(value.structuralBackupReceipt.protectedArtifactCount, "structural protected-artifact count", 1);
  exactInteger(value.structuralBackupReceipt.databaseCount, "structural database count", 1);
  exactTimestamp(value.structuralBackupReceipt.verifiedAt, "structural backup receipt verification time");
  if (value.structuralBackupReceipt.schema !== "platform.v1-predeploy-backup-receipt/v1"
      || value.structuralBackupReceipt.status !== "REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE"
      || value.structuralBackupReceipt.authoritative !== false) {
    invalid("Structural backup receipt must remain explicitly non-authoritative.");
  }

  const backup = exactObject(value.authoritativeBackupAttestation, "authoritative backup binding", [
    "attestationExpiresAt", "attestationId", "attestationIssuedAt", "backupDeviceIdentity", "backupRootPath",
    "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "backupTrustPolicySha256", "databaseConsistency",
    "databaseCount", "databaseSetSha256", "protectedArtifactCount", "protectedArtifactSetSha256",
    "evidenceArtifactSha256", "offHost", "offHostRetrieval", "captureCompletedAt", "captureStartedAt", "restoreDrill",
    "sourceDeviceSetExcluded", "verifiedAt", "writeConsistency",
  ]);
  for (const key of [
    "attestationId", "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "databaseSetSha256",
    "evidenceArtifactSha256", "protectedArtifactSetSha256",
  ]) {
    exactSha256(backup[key], `authoritative backup ${key}`);
  }
  exactInteger(backup.protectedArtifactCount, "authoritative backup protected-artifact count", 1);
  exactInteger(backup.databaseCount, "authoritative backup database count", 1);
  exactSha256(backup.backupTrustPolicySha256, "authoritative backup trust policy SHA256");
  exactTimestamp(backup.attestationIssuedAt, "backup attestation issue time");
  exactTimestamp(backup.attestationExpiresAt, "backup attestation expiry time");
  exactPath(backup.backupRootPath, "authoritative backup root path");
  exactString(backup.backupDeviceIdentity, "authoritative backup device identity");
  if (backup.offHost !== true || backup.sourceDeviceSetExcluded !== true) {
    invalid("Authoritative backup must prove off-host source-device exclusion.");
  }
  exactTimestamp(backup.captureStartedAt, "authoritative backup capture start");
  exactTimestamp(backup.captureCompletedAt, "authoritative backup capture completion");
  exactTimestamp(backup.verifiedAt, "authoritative backup verification time");
  exactObject(backup.offHostRetrieval, "authoritative backup off-host retrieval", [
    "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "lastVerifiedAt", "providerIdentity",
    "protectedArtifactCount", "protectedArtifactSetSha256", "retrievalCompletedAt",
    "retrievalReceiptArtifactSha256", "retrievalStartedAt", "retrievedBytesSha256", "verified",
  ]);
  for (const key of [
    "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "protectedArtifactSetSha256",
    "retrievalReceiptArtifactSha256", "retrievedBytesSha256",
  ]) {
    exactSha256(backup.offHostRetrieval[key], `off-host retrieval ${key}`);
  }
  exactInteger(backup.offHostRetrieval.protectedArtifactCount, "off-host protected-artifact count", 1);
  exactString(backup.offHostRetrieval.providerIdentity, "off-host provider identity");
  exactTimestamp(backup.offHostRetrieval.retrievalStartedAt, "off-host retrieval start time");
  exactTimestamp(backup.offHostRetrieval.retrievalCompletedAt, "off-host retrieval completion time");
  exactTimestamp(backup.offHostRetrieval.lastVerifiedAt, "off-host retrieval last verification time");
  if (backup.offHostRetrieval.verified !== true) invalid("Off-host retrieval proof is not verified.");

  exactObject(backup.restoreDrill, "authoritative backup isolated restore drill", [
    "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "expectedArtifactCount", "isolated",
    "manifestParity", "restoredArtifactCount", "restoredArtifactSetSha256", "restoredBytesSha256",
    "restoreDrillArtifactSha256", "retrievalReceiptArtifactSha256", "startedAt", "verified", "verifiedAt",
  ]);
  for (const key of [
    "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "restoredArtifactSetSha256", "restoredBytesSha256",
    "restoreDrillArtifactSha256", "retrievalReceiptArtifactSha256",
  ]) exactSha256(backup.restoreDrill[key], `isolated restore drill ${key}`);
  exactInteger(backup.restoreDrill.expectedArtifactCount, "restore expected artifact count", 1);
  exactInteger(backup.restoreDrill.restoredArtifactCount, "restore actual artifact count", 1);
  exactTimestamp(backup.restoreDrill.startedAt, "isolated restore drill start time");
  exactTimestamp(backup.restoreDrill.verifiedAt, "isolated restore drill verification time");
  if (backup.restoreDrill.isolated !== true || backup.restoreDrill.verified !== true
      || backup.restoreDrill.manifestParity !== true) {
    invalid("Authoritative backup restore drill must be isolated and verified.");
  }

  exactObject(backup.databaseConsistency, "authoritative backup database consistency", [
    "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "databaseCatalogSha256", "databaseSetSha256",
    "databasesConsistent", "expectedDatabaseCount", "restoredBytesSha256",
    "restoreDrillArtifactSha256", "retrievalReceiptArtifactSha256", "verificationArtifactSha256", "verifiedAt",
    "verifiedDatabaseCount",
  ]);
  for (const key of [
    "backupArtifactSetSha256", "backupManifestSha256", "backupSetId", "databaseCatalogSha256", "databaseSetSha256",
    "restoredBytesSha256",
    "restoreDrillArtifactSha256", "retrievalReceiptArtifactSha256", "verificationArtifactSha256",
  ]) exactSha256(backup.databaseConsistency[key], `database consistency ${key}`);
  exactInteger(backup.databaseConsistency.expectedDatabaseCount, "expected database count", 1);
  exactInteger(backup.databaseConsistency.verifiedDatabaseCount, "verified database count", 1);
  exactTimestamp(backup.databaseConsistency.verifiedAt, "database consistency verification time");
  if (backup.databaseConsistency.databasesConsistent !== true) {
    invalid("Authoritative backup database consistency proof is not PASS.");
  }

  exactObject(backup.writeConsistency, "authoritative backup write consistency", [
    "applicationDataMutationAuthority", "capturedAt", "continuedLiveWritesPreserved", "mode",
    "snapshotReceiptArtifactSha256", "sourceWriteWatermarkSha256", "verifiedAt",
  ]);
  exactSha256(backup.writeConsistency.snapshotReceiptArtifactSha256, "write-consistency snapshot receipt SHA256");
  exactSha256(backup.writeConsistency.sourceWriteWatermarkSha256, "write-consistency source watermark SHA256");
  exactTimestamp(backup.writeConsistency.capturedAt, "write-consistency snapshot time");
  exactTimestamp(backup.writeConsistency.verifiedAt, "write-consistency verification time");
  if (backup.writeConsistency.mode !== "POINT_IN_TIME_SNAPSHOT"
      || backup.writeConsistency.applicationDataMutationAuthority !== false
      || backup.writeConsistency.continuedLiveWritesPreserved !== true) {
    invalid("ADDITIVE admission requires a consistent point-in-time backup while preserving all continued live writes.");
  }
  const bindingKeys = ["backupSetId", "backupManifestSha256", "backupArtifactSetSha256"];
  for (const key of bindingKeys) {
    if (backup[key] !== value.structuralBackupReceipt[key]
        || backup.offHostRetrieval[key] !== backup[key]
        || backup.restoreDrill[key] !== backup[key]
        || backup.databaseConsistency[key] !== backup[key]) {
      invalid("Backup receipt, retrieval, isolated restore, and database proof do not bind one exact backup set and manifest.");
    }
  }
  if (value.baseline.protectedArtifactSetSha256 !== value.structuralBackupReceipt.protectedArtifactSetSha256
      || value.baseline.protectedArtifactSetSha256 !== backup.protectedArtifactSetSha256
      || value.baseline.protectedArtifactSetSha256 !== backup.offHostRetrieval.protectedArtifactSetSha256
      || value.baseline.protectedArtifactSetSha256 !== backup.restoreDrill.restoredArtifactSetSha256
      || value.baseline.protectedArtifactCount !== value.structuralBackupReceipt.protectedArtifactCount
      || value.baseline.protectedArtifactCount !== backup.protectedArtifactCount
      || value.baseline.protectedArtifactCount !== backup.offHostRetrieval.protectedArtifactCount
      || value.baseline.protectedArtifactCount !== backup.restoreDrill.expectedArtifactCount
      || value.baseline.protectedArtifactCount !== backup.restoreDrill.restoredArtifactCount
      || value.baseline.databaseSetSha256 !== value.structuralBackupReceipt.databaseSetSha256
      || value.baseline.databaseSetSha256 !== backup.databaseSetSha256
      || value.baseline.databaseSetSha256 !== backup.databaseConsistency.databaseSetSha256
      || value.baseline.databaseCount !== value.structuralBackupReceipt.databaseCount
      || value.baseline.databaseCount !== backup.databaseCount
      || value.baseline.databaseCount !== backup.databaseConsistency.expectedDatabaseCount
      || value.baseline.databaseCount !== backup.databaseConsistency.verifiedDatabaseCount) {
    invalid("Baseline, backup, restored artifact, and database coverage sets/counts are not exact.");
  }
  if (backup.restoreDrill.restoredBytesSha256 !== backup.offHostRetrieval.retrievedBytesSha256
      || backup.restoreDrill.retrievalReceiptArtifactSha256 !== backup.offHostRetrieval.retrievalReceiptArtifactSha256
      || backup.databaseConsistency.restoredBytesSha256 !== backup.offHostRetrieval.retrievedBytesSha256
      || backup.databaseConsistency.retrievalReceiptArtifactSha256 !== backup.offHostRetrieval.retrievalReceiptArtifactSha256
      || backup.databaseConsistency.restoreDrillArtifactSha256 !== backup.restoreDrill.restoreDrillArtifactSha256) {
    invalid("Isolated restore and database validation did not consume the exact off-host retrieved backup bytes.");
  }
  const protectedTargetDevices = [value.sourceTarget, value.activationTarget].flatMap((target) => [
    target.rootParentIdentity.deviceIdentity,
    ...(target.rootIdentity === null ? [] : [target.rootIdentity.deviceIdentity]),
  ]);
  if (protectedTargetDevices.includes(backup.backupDeviceIdentity)) {
    invalid("Backup device must be outside source and activation target root devices.");
  }

  if (value.installPlan.packageBytesSha256 !== value.phaseA.packageSha256
      || value.installPlan.packageAttestationEnvelopeSha256 !== value.phaseA.packageAttestationEnvelopeSha256
      || value.installPlan.packageManifestSha256 !== value.phaseA.packageManifestSha256) {
    invalid("Install plan package bytes, attestation envelope, and manifest differ from Phase A.");
  }
  exactInstallPlan(value.installPlan);
  if (value.installPlan.materializationTargets.some((target) => pathsOverlap(value.sourceTarget.root, target.path))) {
    invalid("ADDITIVE install writes overlap the preserved source application root.");
  }
  const activationUser = /^ssh:\/\/([^@]+)@/.exec(value.activationTarget.endpoint)?.[1];
  if (value.installPlan.privilegePolicy.principalName !== activationUser
      || value.installPlan.privilegePolicy.principalUid !== value.activationTarget.deploymentUid
      || value.installPlan.privilegePolicy.principalGid !== value.activationTarget.deploymentGid) {
    invalid("Sudoers principal must be the exact preexisting activation SSH/deployment account; account creation is forbidden.");
  }

  exactObject(value.rollbackPolicy, "rollback policy binding", [
    "artifactSha256", "codeRollbackAllowed", "dataRollbackAuthority", "policyId",
    "preserveNewWrites", "requiresPostDeployPreservation",
  ]);
  exactSha256(value.rollbackPolicy.artifactSha256, "rollback policy artifact SHA256");
  exactSha256(value.rollbackPolicy.policyId, "rollback policy ID");
  if (value.rollbackPolicy.codeRollbackAllowed !== true || value.rollbackPolicy.dataRollbackAuthority !== false
      || value.rollbackPolicy.requiresPostDeployPreservation !== true || value.rollbackPolicy.preserveNewWrites !== true) {
    invalid("Rollback policy cannot grant data rollback authority or discard new writes.");
  }

  const phaseAIssued = exactTimestamp(value.phaseA.issuedAt, "Phase A issue time").milliseconds;
  const phaseAVerified = exactTimestamp(value.phaseA.verifiedAt, "Phase A verification time").milliseconds;
  const phaseAExpires = exactTimestamp(value.phaseA.expiresAt, "Phase A expiry time").milliseconds;
  const baselineStart = exactTimestamp(value.baseline.captureStartedAt, "baseline capture start").milliseconds;
  const baselineEnd = exactTimestamp(value.baseline.captureCompletedAt, "baseline capture completion").milliseconds;
  const baselineVerified = exactTimestamp(value.baseline.verifiedAt, "baseline verification time").milliseconds;
  const backupStart = exactTimestamp(backup.captureStartedAt, "backup capture start").milliseconds;
  const backupEnd = exactTimestamp(backup.captureCompletedAt, "backup capture completion").milliseconds;
  const backupVerified = exactTimestamp(backup.verifiedAt, "backup verification time").milliseconds;
  const structuralReceiptVerified = exactTimestamp(
    value.structuralBackupReceipt.verifiedAt, "structural backup receipt verification time",
  ).milliseconds;
  const retrievalStarted = exactTimestamp(backup.offHostRetrieval.retrievalStartedAt, "off-host retrieval start time").milliseconds;
  const retrievalCompleted = exactTimestamp(backup.offHostRetrieval.retrievalCompletedAt, "off-host retrieval completion time").milliseconds;
  const retrievalVerified = exactTimestamp(backup.offHostRetrieval.lastVerifiedAt, "off-host retrieval verification time").milliseconds;
  const restoreStarted = exactTimestamp(backup.restoreDrill.startedAt, "restore drill start time").milliseconds;
  const restoreVerified = exactTimestamp(backup.restoreDrill.verifiedAt, "restore verification time").milliseconds;
  const databaseVerified = exactTimestamp(backup.databaseConsistency.verifiedAt, "database verification time").milliseconds;
  const snapshotCapturedAt = exactTimestamp(backup.writeConsistency.capturedAt, "write-consistency snapshot time").milliseconds;
  const snapshotVerifiedAt = exactTimestamp(backup.writeConsistency.verifiedAt, "write-consistency verification time").milliseconds;
  const attestationIssued = exactTimestamp(backup.attestationIssuedAt, "backup attestation issue time").milliseconds;
  const attestationExpires = exactTimestamp(backup.attestationExpiresAt, "backup attestation expiry time").milliseconds;
  if (!(phaseAIssued <= phaseAVerified && phaseAVerified <= phaseAExpires
      && phaseAVerified <= baselineStart && baselineStart <= phaseAExpires
      && baselineStart <= baselineEnd && baselineEnd <= baselineVerified && baselineVerified <= phaseAExpires
      && baselineVerified <= backupStart && backupStart <= snapshotCapturedAt && snapshotCapturedAt <= snapshotVerifiedAt
      && snapshotVerifiedAt <= backupEnd && backupEnd <= backupVerified
      && backupVerified <= structuralReceiptVerified && structuralReceiptVerified <= retrievalStarted
      && retrievalStarted <= retrievalCompleted && retrievalCompleted <= retrievalVerified
      && retrievalVerified <= restoreStarted && restoreStarted <= restoreVerified
      && restoreVerified <= databaseVerified && databaseVerified <= attestationIssued
      && attestationIssued < attestationExpires)) {
    invalid("Preinstall causal timestamps violate Phase A, preflight, quiesce, backup, retrieval, isolated restore, database, or attestation order.");
  }

  const identifiers = [
    value.transactionId,
    ...(value.identityTransition === null ? [] : [value.identityTransition.transitionId]),
    value.phaseA.authorizationId,
    value.phaseA.nonce,
    value.phaseA.orderContractId,
    value.phaseA.packageAttestationId,
    value.baseline.baselineId,
    value.structuralBackupReceipt.receiptId,
    backup.attestationId,
    backup.backupSetId,
    value.installPlan.plannedReceiptId,
    value.rollbackPolicy.policyId,
  ];
  assertDistinct(identifiers, "Common tuple replay identifiers");
  assertDistinct(preinstallTypedArtifactHashes(value), "Preinstall typed artifact hashes");
  return value;
}

function deepFreezeJson(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreezeJson(child);
    Object.freeze(value);
  }
  return value;
}

export function validateV1BrownfieldPreinstallTuple(value) {
  const snapshot = JSON.parse(canonicalJson(value));
  validatePreinstallTuple(snapshot);
  return deepFreezeJson(snapshot);
}

const PHASE_B_EVIDENCE_KEYS = Object.freeze([
  "materializationPreconditions",
  "materializationTargetPlanSha256",
  "packageInputObservation",
  "preMutationAncestryVerification",
  "principalAccountObservation",
  "replayClaimPrecondition",
  "resourceObservation",
]);

function phaseBPreinstallEvidenceProjection(value) {
  return Object.fromEntries(PHASE_B_EVIDENCE_KEYS.map((key) => [key, value[key]]));
}

function exactPhaseBPreinstallEvidence(value, preinstall) {
  exactObject(value, "Phase B preinstall evidence", PHASE_B_EVIDENCE_KEYS);
  exactSha256(value.materializationTargetPlanSha256, "Phase B materialization target plan SHA256");
  if (value.materializationTargetPlanSha256 !== shaCanonical(preinstall.installPlan.materializationTargets)) {
    invalid("Phase B evidence does not bind the exact canonical materialization target plan.");
  }
  exactAncestryVerification(
    value.preMutationAncestryVerification,
    preinstall.installPlan.materializationPolicy,
    "Phase B pre-mutation ancestry verification",
  );
  const targetFilesystemObjectObservations = [
    preinstall.sourceTarget,
    preinstall.activationTarget,
  ].flatMap((target) => [
    { ...target.rootParentIdentity, path: target.rootParentPath },
    ...(target.rootIdentity === null ? [] : [{ ...target.rootIdentity, path: target.root }]),
  ]);
  const preinstallFilesystemObjectObservations = [
    ...value.preMutationAncestryVerification.sourceParents,
    ...value.preMutationAncestryVerification.destinationParents,
    ...targetFilesystemObjectObservations,
  ];
  assertNoCrossPathFilesystemObjectAliases(
    preinstallFilesystemObjectObservations,
    "Phase B preinstall filesystem object graph",
  );
  exactPackageInputObservation(value.packageInputObservation, preinstall.installPlan);
  const materializationPreconditions = exactMaterializationPreconditions(
    value.materializationPreconditions,
    preinstall.installPlan.materializationTargets,
    value.preMutationAncestryVerification,
  );
  assertNoCrossPathFilesystemObjectAliases([
    ...preinstallFilesystemObjectObservations,
    ...materializationPreconditions.flatMap((condition) => (
      condition.state === "EXISTING_EXACT" ? [condition.identity] : []
    )),
  ], "Phase B preinstall filesystem object graph");
  const privilegeTargetIndex = preinstall.installPlan.materializationTargets
    .findIndex((target) => target.path === preinstall.installPlan.privilegePolicy.path);
  const privilegePrecondition = materializationPreconditions[privilegeTargetIndex];
  if (privilegeTargetIndex < 0 || privilegePrecondition === undefined) {
    invalid("Phase B lacks the exact sudoers materialization precondition.");
  }
  exactPrincipalAccountObservation(
    value.principalAccountObservation,
    preinstall.installPlan.privilegePolicy,
    privilegePrecondition.state === "ABSENT_PROVEN" ? [] : [preinstall.installPlan.privilegePolicy.permittedInvocation],
    { expectedDockerDaemonId: preinstall.activationTarget.dockerDaemonId },
  );
  exactResourceObservation(
    value.resourceObservation,
    preinstall.installPlan,
    value.preMutationAncestryVerification,
    materializationPreconditions,
  );
  exactReplayClaimPrecondition(
    value.replayClaimPrecondition,
    preinstall,
    value.preMutationAncestryVerification,
  );
  const activationRootTargetIndex = preinstall.installPlan.materializationTargets
    .findIndex((target) => target.path === preinstall.activationTarget.root);
  const activationRootCondition = value.materializationPreconditions[activationRootTargetIndex];
  const observedSrv = value.preMutationAncestryVerification.destinationParents
    .find((parent) => parent.path === preinstall.activationTarget.rootParentPath);
  if (activationRootTargetIndex < 0 || observedSrv === undefined
      || !canonicalEqual(filesystemIdentityProjection(observedSrv), preinstall.activationTarget.rootParentIdentity)) {
    invalid("Activation target root parent identity differs from the exact Phase B /srv observation.");
  }
  if (preinstall.activationTarget.rootState !== "ABSENT_PROVEN"
      || activationRootCondition.state !== "ABSENT_PROVEN"
      || activationRootCondition.negativeLookupReceiptSha256 !== preinstall.activationTarget.rootAbsenceReceiptSha256
      || activationRootCondition.anchorIdentitySha256 !== shaCanonical(observedSrv)) {
    invalid("Activation target ABSENT proof differs from its exact materialization precondition.");
  }
  const observedSourceParent = [
    ...value.preMutationAncestryVerification.sourceParents,
    ...value.preMutationAncestryVerification.destinationParents,
  ].find((parent) => parent.path === preinstall.sourceTarget.rootParentPath);
  if (observedSourceParent !== undefined
      && !canonicalEqual(filesystemIdentityProjection(observedSourceParent), preinstall.sourceTarget.rootParentIdentity)) {
    invalid("Preserved source root parent differs from the exact shared Phase B ancestry identity.");
  }
  return value;
}

export function validateV1BrownfieldPhaseBPreinstallEvidence(value, preinstallTuple) {
  const preinstallSnapshot = JSON.parse(canonicalJson(preinstallTuple));
  const evidenceSnapshot = JSON.parse(canonicalJson(value));
  validatePreinstallTuple(preinstallSnapshot);
  exactPhaseBPreinstallEvidence(evidenceSnapshot, preinstallSnapshot);
  return deepFreezeJson(evidenceSnapshot);
}

function validateCommonTuple(value) {
  exactObject(value, "final common tuple", [
    "backupAttestationEnvelopeSha256", "ciChallenge", "installReceipt", "phaseBPreInstallAuthorization",
    "preinstallTuple", "preinstallTupleSha256", "schema", "transactionId",
  ]);
  if (value.schema !== TUPLE_SCHEMA) invalid("Final common tuple schema is invalid.");
  const preinstall = validatePreinstallTuple(value.preinstallTuple);
  if (value.transactionId !== preinstall.transactionId
      || value.preinstallTupleSha256 !== shaCanonical(preinstall)) {
    invalid("Final common tuple does not bind the exact preinstall tuple and transaction.");
  }
  exactSha256(value.backupAttestationEnvelopeSha256, "final backup attestation envelope SHA256");
  const phaseB = exactObject(value.phaseBPreInstallAuthorization, "Phase B preinstall authorization binding", [
    "activationTargetRootFingerprintSha256", "activationTargetRootProducer", "authorizationEnvelopeSha256",
    "authorizationId", "backupAttestationEnvelopeSha256", "expiresAt", "installPlanSha256", "issuedAt", "nonce",
    "installerBootstrapSha256", "operationScope", "payloadType", "phaseBInstallerFingerprintSha256", "phaseBInstallerProducer", "policySha256",
    "materializationPreconditions", "materializationTargetPlanSha256", "packageInputObservation",
    "preMutationAncestryVerification",
    "principalAccountObservation", "replayClaimPrecondition", "resourceObservation",
    "preinstallTupleSha256", "replayLedgerStatus", "scope", "verificationReceiptSha256", "verifiedAt",
  ]);
  for (const key of [
    "activationTargetRootFingerprintSha256", "authorizationEnvelopeSha256", "backupAttestationEnvelopeSha256",
    "installPlanSha256", "installerBootstrapSha256", "materializationTargetPlanSha256",
    "phaseBInstallerFingerprintSha256", "policySha256",
    "preinstallTupleSha256", "verificationReceiptSha256",
  ]) exactSha256(phaseB[key], `Phase B ${key}`);
  exactNonce(phaseB.nonce, "Phase B nonce");
  exactString(phaseB.authorizationId, "Phase B authorization ID", OPAQUE_IDENTIFIER);
  if (phaseB.payloadType !== "application/vnd.platform.v1.phase-b.preinstall-authorization.v1+json"
      || phaseB.scope !== "INSTALL_PINNED_V1_CONTROL_PLANE_ONLY"
      || phaseB.replayLedgerStatus !== "EXTERNAL_PENDING"
      || phaseB.preinstallTupleSha256 !== value.preinstallTupleSha256
      || phaseB.backupAttestationEnvelopeSha256 !== value.backupAttestationEnvelopeSha256
      || phaseB.installPlanSha256 !== shaCanonical(preinstall.installPlan)
      || phaseB.materializationTargetPlanSha256 !== shaCanonical(preinstall.installPlan.materializationTargets)
      || phaseB.installerBootstrapSha256 !== shaCanonical(preinstall.installPlan.installerBootstrap)
      || phaseB.policySha256 !== preinstall.installPlan.installerBootstrap.trustPolicySha256) {
    invalid("Phase B preinstall authorization scope or exact preinstall bindings are invalid.");
  }
  exactTimestamp(phaseB.issuedAt, "Phase B issue time");
  exactTimestamp(phaseB.verifiedAt, "Phase B verification time");
  exactTimestamp(phaseB.expiresAt, "Phase B expiry time");
  exactObject(phaseB.operationScope, "Phase B operation scope", ["forbidden", "permitted"]);
  if (!canonicalEqual(phaseB.operationScope, PHASE_B_OPERATION_SCOPE)) {
    invalid("Phase B operation scope is not the exact install/verify-only closed set.");
  }
  exactPhaseBPreinstallEvidence(phaseBPreinstallEvidenceProjection(phaseB), preinstall);
  if (phaseB.replayClaimPrecondition.authorizationId !== phaseB.authorizationId
      || phaseB.replayClaimPrecondition.nonce !== phaseB.nonce
      || phaseB.replayClaimPrecondition.policySha256 !== phaseB.policySha256
      || phaseB.replayClaimPrecondition.preinstallTupleSha256 !== phaseB.preinstallTupleSha256) {
    invalid("Phase B authorization does not bind its exact pre-authorized replay claim.");
  }

  const receipt = exactObject(value.installReceipt, "actual install receipt", [
    "activationTargetPostinstall", "artifactHashScope", "artifactSha256", "broker", "directories", "helpers", "installPlanSha256", "installedAt", "installerBootstrap",
    "installerBootstrapExecutionReceiptSha256", "materializationPolicy", "materializationReceiptSha256",
    "materializationTargetOutcomes", "materializationTargets",
    "packageAttestationEnvelopeSha256", "packageBytesSha256", "packageBytesSizeBytes", "packageManifestSha256",
    "packageManifestSizeBytes",
    "phaseBAuthorizationEnvelopeSha256", "phaseBAuthorizationId", "phaseBLedgerConsumption",
    "postInstallAncestryVerification", "preMutationAncestryVerificationSha256", "privilegePolicy",
    "privilegePolicyTargetVerification", "receiptId", "resourceOutcome", "selfHash", "verifier",
  ]);
  for (const key of [
    "artifactSha256", "installPlanSha256", "installerBootstrapExecutionReceiptSha256", "materializationReceiptSha256", "packageAttestationEnvelopeSha256",
    "packageBytesSha256", "packageManifestSha256", "phaseBAuthorizationEnvelopeSha256", "preMutationAncestryVerificationSha256",
  ]) exactSha256(receipt[key], `install receipt ${key}`);
  exactString(receipt.receiptId, "install receipt ID", OPAQUE_IDENTIFIER);
  exactInteger(receipt.packageBytesSizeBytes, "install receipt package byte size", 1, MAX_ARTIFACT_BYTES);
  exactInteger(receipt.packageManifestSizeBytes, "install receipt package manifest size", 1, MAX_ARTIFACT_BYTES);
  exactString(receipt.phaseBAuthorizationId, "install receipt Phase B authorization ID", OPAQUE_IDENTIFIER);
  if (receipt.artifactHashScope !== "EXTERNAL-INSTALL-JOURNAL-BYTES" || receipt.selfHash !== false
      || receipt.receiptId !== preinstall.installPlan.plannedReceiptId
      || receipt.phaseBAuthorizationEnvelopeSha256 !== phaseB.authorizationEnvelopeSha256
      || receipt.phaseBAuthorizationId !== phaseB.authorizationId
      || receipt.preMutationAncestryVerificationSha256 !== shaCanonical(phaseB.preMutationAncestryVerification)
      || receipt.installPlanSha256 !== shaCanonical(preinstall.installPlan)
      || receipt.packageBytesSha256 !== preinstall.installPlan.packageBytesSha256
      || receipt.packageBytesSizeBytes !== preinstall.installPlan.packageBytesSizeBytes
      || receipt.packageAttestationEnvelopeSha256 !== preinstall.installPlan.packageAttestationEnvelopeSha256
      || receipt.packageManifestSha256 !== preinstall.installPlan.packageManifestSha256
      || receipt.packageManifestSizeBytes !== preinstall.installPlan.packageManifestSizeBytes
      || !canonicalEqual(receipt.broker, preinstall.installPlan.broker)
      || !canonicalEqual(receipt.verifier, preinstall.installPlan.verifier)
      || !canonicalEqual(receipt.helpers, preinstall.installPlan.helpers)
      || !canonicalEqual(receipt.directories, preinstall.installPlan.directories)
      || !canonicalEqual(receipt.privilegePolicy, preinstall.installPlan.privilegePolicy)
      || !canonicalEqual(receipt.materializationPolicy, preinstall.installPlan.materializationPolicy)
      || !canonicalEqual(receipt.materializationTargets, preinstall.installPlan.materializationTargets)
      || !canonicalEqual(receipt.installerBootstrap, preinstall.installPlan.installerBootstrap)) {
    invalid("Actual install receipt differs from Phase A, the pinned install plan, or Phase B authorization.");
  }
  exactBinaryIdentity(receipt.broker, "installed activation broker", "/usr/local/libexec/platform-activation-broker");
  exactBinaryIdentity(receipt.verifier, "installed brownfield admission verifier", "/usr/local/libexec/platform-v1-brownfield-admission");
  const installedHelperPaths = exactArray(receipt.helpers, "installed helpers", { min: 3 })
    .map((helper, index) => exactBinaryIdentity(helper, `installed helper ${index}`).path);
  if (!canonicalEqual(installedHelperPaths, REQUIRED_HELPER_PATHS)) invalid("Installed helpers differ from the exact V2 plan.");
  receipt.directories.forEach(exactDirectoryPlan);
  exactPrivilegePolicy(receipt.privilegePolicy);
  exactPrivilegePolicyTargetVerification(
    receipt.privilegePolicyTargetVerification,
    receipt.privilegePolicy,
    preinstall.activationTarget.dockerDaemonId,
  );
  if (receipt.privilegePolicyTargetVerification.phaseBPrincipalAccountObservationSha256
      !== shaCanonical(phaseB.principalAccountObservation)) {
    invalid("Target privilege-policy proof does not bind the exact Phase B preexisting account observation.");
  }
  const postinstallPrincipal = receipt.privilegePolicyTargetVerification.postinstallPrincipalAuthorityObservation;
  const stablePrincipalKeys = [
    "dockerGroupMembership", "dockerSocketAccess", "effectiveSudoCommands", "groupaddForbidden", "preexisting",
    "principalGid", "principalName", "principalUid", "rootEquivalentCapabilities", "supplementaryGroups",
    "unrestrictedSudo", "useraddForbidden",
  ];
  const stableSocketKeys = [
    "accessibleEndpointCount", "daemonId", "descriptorNoFollow", "deviceIdentity", "discoveredEndpoints", "dockerHostEnvironmentAccepted",
    "fileType", "filesystemUuid", "gid", "inode", "mode", "mountId", "nlink", "parentAncestry", "path", "principalAccessibleEndpoints",
    "principalEffectiveAccess", "symlink", "tcpEndpointsAccessible", "uid",
  ];
  if (stablePrincipalKeys.some((key) => key === "effectiveSudoCommands"
    ? !canonicalEqual(postinstallPrincipal[key], [receipt.privilegePolicy.permittedInvocation])
    : !canonicalEqual(postinstallPrincipal[key], phaseB.principalAccountObservation[key]))
      || stableSocketKeys.some((key) => !canonicalEqual(
        postinstallPrincipal.dockerSocketIdentity[key], phaseB.principalAccountObservation.dockerSocketIdentity[key],
      ))) {
    invalid("Post-install principal or Docker-socket authority differs from the exact safe Phase B observation.");
  }
  const principalEvidenceReceipts = (observation) => [
    observation.accountLookupReceiptSha256,
    observation.capabilityReceiptSha256,
    observation.dockerSocketAclReceiptSha256,
    observation.dockerSocketIdentity.ancestryVerificationReceiptSha256,
    observation.dockerSocketIdentity.daemonProbeReceiptSha256,
    observation.dockerSocketIdentity.descriptorIdentityReceiptSha256,
    observation.dockerSocketIdentity.endpointEnumerationReceiptSha256,
    observation.effectiveSudoReceiptSha256,
    observation.groupMembershipReceiptSha256,
    observation.passwdEntryReceiptSha256,
  ];
  assertDistinct([
    ...principalEvidenceReceipts(phaseB.principalAccountObservation),
    ...principalEvidenceReceipts(postinstallPrincipal),
  ], "Pre/post deployment-principal authority evidence receipts");
  exactInstallerBootstrap(receipt.installerBootstrap);
  exactMaterializationPolicy(receipt.materializationPolicy, receipt.packageBytesSha256);
  exactMaterializationTargets(receipt.materializationTargets, preinstall.installPlan);
  exactAncestryVerification(
    receipt.postInstallAncestryVerification,
    receipt.materializationPolicy,
    "post-install ancestry verification",
  );
  const expectedPostParents = expectedPostInstallParentIdentities(
    phaseB.preMutationAncestryVerification,
    preinstall.installPlan.materializationTargets,
    phaseB.materializationPreconditions,
  );
  if (!canonicalEqual(receipt.postInstallAncestryVerification.sourceParents, expectedPostParents.sourceParents)
      || !canonicalEqual(receipt.postInstallAncestryVerification.destinationParents, expectedPostParents.destinationParents)) {
    invalid("Source CAS or destination ancestry identity changed across installation.");
  }
  const materializationOutcomes = exactMaterializationOutcomes(
    receipt.materializationTargetOutcomes,
    preinstall.installPlan.materializationTargets,
    phaseB.materializationPreconditions,
    value.transactionId,
    phaseB.preMutationAncestryVerification,
  );
  const ledgerTimes = exactPhaseBLedgerConsumption(
    receipt.phaseBLedgerConsumption,
    phaseB,
    value.transactionId,
    receipt.receiptId,
    preinstall.installPlan,
    materializationOutcomes,
  );
  for (const dynamicWritePath of [
    receipt.phaseBLedgerConsumption.claimObjectPath,
    receipt.phaseBLedgerConsumption.journalRecordPath,
    receipt.phaseBLedgerConsumption.receiptObjectPath,
  ]) {
    if (pathsOverlap(preinstall.sourceTarget.root, dynamicWritePath)) {
      invalid("ADDITIVE ledger or receipt writes overlap the preserved source application root.");
    }
  }
  const receiptResourceDevice = receipt.resourceOutcome.devices.find((device) => (
    device.deviceIdentity === receipt.phaseBLedgerConsumption.receiptObjectIdentity.deviceIdentity
      && device.filesystemUuid === receipt.phaseBLedgerConsumption.receiptObjectIdentity.filesystemUuid
      && device.mountIds.includes(receipt.phaseBLedgerConsumption.receiptObjectIdentity.mountId)
  ));
  if (receiptResourceDevice === undefined
      || receiptResourceDevice.actualWrittenBytes + receipt.phaseBLedgerConsumption.receiptSizeBytes
        > receiptResourceDevice.plannedWriteBytes
      || receiptResourceDevice.actualCreatedInodes + 1 > receiptResourceDevice.plannedCreatedInodes
      || receiptResourceDevice.freeBytes - receipt.phaseBLedgerConsumption.receiptSizeBytes
        < receiptResourceDevice.requiredFreeBytesAfter
      || receiptResourceDevice.freeInodes - 1 < receiptResourceDevice.requiredFreeInodesAfter) {
    invalid("Post-install resource reserve or receipt write/inode budget does not cover the final fsynced receipt-object mutation.");
  }
  exactTarget(receipt.activationTargetPostinstall, "post-install activation target", { activation: true, postinstall: true });
  const initialActivationTarget = preinstall.activationTarget;
  const stableTargetKeys = [
    "deploymentGid", "deploymentUid", "dockerDaemonId", "endpoint", "environment", "host", "machineId",
    "root", "rootFilesystemIdentitySha256", "rootParentPath", "sshHostKeySha256", "targetId",
  ];
  const expectedActivationRootParent = expectedPostParents.destinationParents
    .find((entry) => entry.path === initialActivationTarget.rootParentPath);
  const rootOutcome = receipt.materializationTargetOutcomes.find((entry) => entry.path === initialActivationTarget.root);
  const outcomeRootIdentity = rootOutcome === undefined ? null : {
    deviceIdentity: rootOutcome.identity.deviceIdentity,
    filesystemUuid: rootOutcome.identity.filesystemUuid,
    gid: rootOutcome.identity.gid,
    inode: rootOutcome.identity.inode,
    mountId: rootOutcome.identity.mountId,
    mode: rootOutcome.identity.mode,
    nlink: rootOutcome.identity.nlink,
    uid: rootOutcome.identity.uid,
  };
  if (stableTargetKeys.some((key) => !canonicalEqual(receipt.activationTargetPostinstall[key], initialActivationTarget[key]))
      || expectedActivationRootParent === undefined
      || !canonicalEqual(
        receipt.activationTargetPostinstall.rootParentIdentity,
        filesystemIdentityProjection(expectedActivationRootParent),
      )
      || receipt.activationTargetPostinstall.rootState !== "EXISTING_EXACT"
      || receipt.activationTargetPostinstall.rootAbsenceReceiptSha256 !== null
      || rootOutcome === undefined || !canonicalEqual(receipt.activationTargetPostinstall.rootIdentity, outcomeRootIdentity)) {
    invalid("Post-install activation target does not prove the exact authorized absent/existing root materialization outcome.");
  }
  const targetFilesystemObjectObservations = [
    preinstall.sourceTarget,
    preinstall.activationTarget,
    receipt.activationTargetPostinstall,
  ].flatMap((target) => [
    { ...target.rootParentIdentity, path: target.rootParentPath },
    ...(target.rootIdentity === null ? [] : [{ ...target.rootIdentity, path: target.root }]),
  ]);
  assertNoCrossPathFilesystemObjectAliases([
    ...phaseB.preMutationAncestryVerification.sourceParents,
    ...phaseB.preMutationAncestryVerification.destinationParents,
    ...receipt.postInstallAncestryVerification.sourceParents,
    ...receipt.postInstallAncestryVerification.destinationParents,
    ...phaseB.materializationPreconditions.flatMap((condition) => (
      condition.state === "EXISTING_EXACT" ? [condition.identity] : []
    )),
    ...materializationOutcomes.map((outcome) => outcome.identity),
    receipt.phaseBLedgerConsumption.claimObjectIdentity,
    receipt.phaseBLedgerConsumption.journalObjectIdentity,
    receipt.phaseBLedgerConsumption.receiptObjectIdentity,
    ...targetFilesystemObjectObservations,
  ], "Final filesystem object graph");
  if (receipt.installerBootstrapExecutionReceiptSha256 !== receipt.phaseBLedgerConsumption.receiptArtifactSha256) {
    invalid("Installer execution receipt does not bind the exact Phase B ledger-consumption receipt.");
  }
  exactTimestamp(receipt.installedAt, "installation time");

  const challenge = exactObject(value.ciChallenge, "final CI challenge", [
    "challengeId", "eventName", "expiresAt", "issuedAt", "job", "maxAgeSeconds", "nonce",
    "protectedEnvironment", "ref", "repository", "repositoryId", "repositoryOwnerId", "runAttempt", "runId",
    "workflowPath", "workflowSha",
  ]);
  exactSha256(challenge.challengeId, "CI challenge ID");
  exactNonce(challenge.nonce, "CI challenge nonce");
  exactTimestamp(challenge.issuedAt, "CI challenge issue time");
  exactTimestamp(challenge.expiresAt, "CI challenge expiry time");
  exactInteger(challenge.maxAgeSeconds, "CI challenge max age", 1, 3600);
  exactRepository(challenge.repository, "CI challenge repository");
  if (challenge.repository !== challenge.repository.toLowerCase()
      || challenge.repository === preinstall.candidate.repository
      || challenge.repositoryId === preinstall.candidate.repositoryId
      || challenge.repositoryOwnerId === preinstall.candidate.repositoryOwnerId) {
    invalid("CI challenge repository identity is non-canonical or candidate-controlled.");
  }
  exactWorkflowPath(challenge.workflowPath, "CI challenge workflow path");
  exactGitSha(challenge.workflowSha, "CI challenge workflow SHA");
  exactString(challenge.job, "CI challenge job", /^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/);
  if (challenge.ref !== "refs/heads/main" || challenge.eventName !== "workflow_dispatch") {
    invalid("CI challenge ref/event identity is invalid.");
  }
  exactString(challenge.protectedEnvironment, "CI challenge protected environment");
  exactDecimal(challenge.repositoryId, "CI challenge repository ID", true);
  exactDecimal(challenge.repositoryOwnerId, "CI challenge repository owner ID", true);
  exactDecimal(challenge.runId, "CI challenge run ID", true);
  exactInteger(challenge.runAttempt, "CI challenge run attempt", 1);

  const backupIssued = exactTimestamp(
    preinstall.authoritativeBackupAttestation.attestationIssuedAt, "backup attestation issue time",
  ).milliseconds;
  const backupExpires = exactTimestamp(
    preinstall.authoritativeBackupAttestation.attestationExpiresAt, "backup attestation expiry time",
  ).milliseconds;
  const phaseBIssued = exactTimestamp(phaseB.issuedAt, "Phase B issue time").milliseconds;
  const phaseBVerified = exactTimestamp(phaseB.verifiedAt, "Phase B verification time").milliseconds;
  const phaseBExpires = exactTimestamp(phaseB.expiresAt, "Phase B expiry time").milliseconds;
  const ancestryPreVerifiedAt = exactTimestamp(
    phaseB.preMutationAncestryVerification.verifiedAt, "Phase B pre-mutation ancestry verification time",
  ).milliseconds;
  const phaseBPreconditionTimes = [
    ancestryPreVerifiedAt,
    exactTimestamp(phaseB.packageInputObservation.verifiedAt, "package input verification time").milliseconds,
    exactTimestamp(phaseB.principalAccountObservation.verifiedAt, "principal account verification time").milliseconds,
    exactTimestamp(
      phaseB.replayClaimPrecondition.verifiedAt, "replay claim precondition verification time",
    ).milliseconds,
    exactTimestamp(phaseB.resourceObservation.observedAt, "resource observation time").milliseconds,
    ...phaseB.materializationPreconditions.map((condition, index) => exactTimestamp(
      condition.verifiedAt, `materialization precondition ${index} verification time`,
    ).milliseconds),
  ];
  const installedAt = exactTimestamp(receipt.installedAt, "installation time").milliseconds;
  exactResourceOutcome(
    receipt.resourceOutcome,
    phaseB.resourceObservation,
    installedAt,
    materializationOutcomes,
    receipt.phaseBLedgerConsumption,
  );
  const privilegeVerifiedAt = exactTimestamp(
    receipt.privilegePolicyTargetVerification.verifiedAt, "target visudo verification time",
  ).milliseconds;
  const ancestryPostVerifiedAt = exactTimestamp(
    receipt.postInstallAncestryVerification.verifiedAt, "post-install ancestry verification time",
  ).milliseconds;
  const resourceOutcomeVerifiedAt = exactTimestamp(
    receipt.resourceOutcome.verifiedAt, "post-install resource outcome time",
  ).milliseconds;
  const challengeIssued = exactTimestamp(challenge.issuedAt, "CI challenge issue time").milliseconds;
  const challengeExpires = exactTimestamp(challenge.expiresAt, "CI challenge expiry time").milliseconds;
  const materializationOutcomeTimes = receipt.materializationTargetOutcomes.map((outcome, index) => exactTimestamp(
    outcome.verifiedAt, `materialization outcome ${index} verification time`,
  ).milliseconds);
  const privilegeOutcomeIndex = receipt.materializationTargetOutcomes
    .findIndex((outcome) => outcome.path === receipt.privilegePolicy.path);
  const privilegeOutcomeTime = privilegeOutcomeIndex < 0 ? Number.POSITIVE_INFINITY
    : materializationOutcomeTimes[privilegeOutcomeIndex];
  const finalMaterializationOutcomeTime = Math.max(...materializationOutcomeTimes);
  if (!(phaseBPreconditionTimes.every((time) => backupIssued <= time && time <= phaseBIssued)
      && phaseBIssued <= backupExpires
      && phaseBIssued <= phaseBVerified && phaseBVerified <= phaseBExpires
      && phaseBVerified <= ledgerTimes.claimCreatedAt && ledgerTimes.claimCreatedAt <= ledgerTimes.consumedAt
      && ledgerTimes.firstMutationAt <= privilegeVerifiedAt
      && ledgerTimes.firstMutationAt <= ancestryPostVerifiedAt
      && materializationOutcomeTimes.every((time) => ledgerTimes.firstMutationAt <= time && time <= installedAt)
      && ledgerTimes.journalWrittenAt <= ledgerTimes.receiptWrittenAt
      && ledgerTimes.receiptWrittenAt <= installedAt
      && ledgerTimes.firstMutationAt <= resourceOutcomeVerifiedAt && resourceOutcomeVerifiedAt <= installedAt
      && ledgerTimes.journalWrittenAt <= resourceOutcomeVerifiedAt
      && privilegeVerifiedAt <= installedAt && ancestryPostVerifiedAt <= installedAt
      && privilegeOutcomeTime <= privilegeVerifiedAt
      && finalMaterializationOutcomeTime <= ancestryPostVerifiedAt
      && finalMaterializationOutcomeTime <= resourceOutcomeVerifiedAt
      && privilegeVerifiedAt <= ledgerTimes.receiptWrittenAt
      && ancestryPostVerifiedAt <= ledgerTimes.receiptWrittenAt
      && resourceOutcomeVerifiedAt <= ledgerTimes.receiptWrittenAt
      && installedAt <= phaseBExpires && installedAt <= backupExpires
      && installedAt <= challengeIssued && challengeIssued <= backupExpires && challengeIssued < challengeExpires)) {
    invalid("Final causal timestamps violate backup, Phase B, install, or final challenge order.");
  }
  assertDistinct([
    phaseB.authorizationId, receipt.receiptId, receipt.artifactSha256, receipt.materializationReceiptSha256,
    challenge.challengeId, challenge.nonce,
  ], "Final tuple replay identifiers");
  assertDistinct([
    preinstall.phaseA.nonce, phaseB.nonce, challenge.nonce,
  ], "Phase A, Phase B, and final CI challenge nonces");
  const phaseBPreconditionReceipts = phaseB.materializationPreconditions.map((condition) => (
    condition.state === "ABSENT_PROVEN"
      ? condition.negativeLookupReceiptSha256 : condition.identity.identityReceiptSha256
  ));
  const outcomeIdentityReceipts = receipt.materializationTargetOutcomes
    .map((outcome) => outcome.identity.identityReceiptSha256);
  const ledger = receipt.phaseBLedgerConsumption;
  assertDistinct([
    ...preinstallTypedArtifactHashes(preinstall),
    value.backupAttestationEnvelopeSha256,
    phaseB.authorizationEnvelopeSha256,
    phaseB.verificationReceiptSha256,
    receipt.artifactSha256,
    receipt.materializationReceiptSha256,
    receipt.installerBootstrapExecutionReceiptSha256,
    receipt.privilegePolicyTargetVerification.verificationReceiptSha256,
    phaseB.preMutationAncestryVerification.verificationReceiptSha256,
    receipt.postInstallAncestryVerification.verificationReceiptSha256,
    receipt.phaseBLedgerConsumption.claimArtifactSha256,
    receipt.phaseBLedgerConsumption.journalArtifactSha256,
    phaseB.packageInputObservation.descriptorIdentityReceiptSha256,
    ...principalEvidenceReceipts(phaseB.principalAccountObservation).slice(1),
    phaseB.resourceObservation.receiptSha256,
    ...phaseBPreconditionReceipts,
    ...outcomeIdentityReceipts,
    receipt.resourceOutcome.receiptSha256,
    ...receipt.resourceOutcome.devices.map((device) => device.installerAccountingReceiptSha256),
    ...principalEvidenceReceipts(postinstallPrincipal),
    ledger.claimNegativeLookupReceiptSha256,
    ledger.journalNegativeLookupReceiptSha256,
    ledger.receiptNegativeLookupReceiptSha256,
    ledger.claimObjectIdentity.identityReceiptSha256,
    ledger.journalObjectIdentity.identityReceiptSha256,
    ledger.receiptObjectIdentity.identityReceiptSha256,
  ], "Final typed artifact hashes");
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

function exactArtifact(artifactValue, label) {
  if (!artifactValue || !Buffer.isBuffer(artifactValue.bytes)
      || artifactValue.bytes.length < 2 || artifactValue.bytes.length > MAX_ARTIFACT_BYTES) {
    invalid(`${label} must be one explicitly supplied bounded artifact.`);
  }
  let document;
  try {
    const text = artifactValue.bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(artifactValue.bytes) || text.startsWith("\uFEFF")) {
      invalid(`${label} must be exact UTF-8 without a BOM.`);
    }
    document = JSON.parse(text);
  } catch (error) {
    invalid(`${label} is invalid JSON: ${String(error?.message ?? error)}`);
  }
  const canonicalBytes = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
  if (!canonicalBytes.equals(artifactValue.bytes)) invalid(`${label} must use exact canonical JSON bytes.`);
  const sha256 = crypto.createHash("sha256").update(artifactValue.bytes).digest("hex");
  if (artifactValue.sha256 !== undefined && artifactValue.sha256 !== sha256) {
    invalid(`${label} declared SHA256 does not match its bytes.`);
  }
  return { bytes: artifactValue.bytes, document, sha256 };
}

function exactPublicRoot(value, role, expectedFingerprint) {
  exactObject(value, `${role} policy root`, ["fingerprintSha256", "keyId", "publicKeyPem"]);
  exactSha256(value.keyId, `${role} key ID`);
  exactSha256(value.fingerprintSha256, `${role} fingerprint`);
  if (value.fingerprintSha256 !== expectedFingerprint) {
    invalid(`${role} fingerprint differs from the mandatory trusted caller pin.`);
  }
  if (typeof value.publicKeyPem !== "string"
      || !value.publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n")
      || !value.publicKeyPem.endsWith("-----END PUBLIC KEY-----\n")) {
    invalid(`${role} root must be exact canonical SPKI public key PEM.`);
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(value.publicKeyPem);
  } catch {
    invalid(`${role} root must be exact canonical SPKI public key PEM.`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") invalid(`${role} root must be an Ed25519 public key.`);
  const canonicalPem = publicKey.export({ type: "spki", format: "pem" });
  if (canonicalPem !== value.publicKeyPem) invalid(`${role} root must be exact canonical SPKI public key PEM.`);
  const fingerprintSha256 = crypto.createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  if (fingerprintSha256 !== value.fingerprintSha256 || value.keyId !== fingerprintSha256) {
    invalid(`${role} key ID/public key/fingerprint binding is invalid.`);
  }
  return { role, keyId: value.keyId, fingerprintSha256, publicKey };
}

function exactLegacyHashes(value, gate, expected = null) {
  exactObject(value, `${gate} legacy artifact hashes`, LEGACY_KEYS[gate]);
  for (const key of LEGACY_KEYS[gate]) exactSha256(value[key], `${gate} legacy ${key}`);
  if (expected !== null && !canonicalEqual(value, expected)) invalid(`${gate} legacy artifact hashes differ from policy.`);
  return value;
}

function exactProducer(value, role, expectedTuple) {
  const preinstall = expectedTuple.preinstallTuple;
  if (role === "sourceTargetCustodian" || role === "activationTargetRoot") {
    exactObject(value, `${role} producer`, [
      "attestationArtifactSha256", "attestationIdentity", "attestedAt", "endpoint", "machineId", "role", "root",
      "rootAbsenceReceiptSha256", "rootFilesystemIdentitySha256", "rootIdentitySha256", "rootParentIdentitySha256",
      "rootState", "targetId", "type",
    ]);
    const target = role === "sourceTargetCustodian"
      ? preinstall.sourceTarget : expectedTuple.installReceipt.activationTargetPostinstall;
    if (value.type !== "TARGET-ROOT" || value.role !== role || value.targetId !== target.targetId
        || value.machineId !== target.machineId || value.endpoint !== target.endpoint || value.root !== target.root
        || value.rootState !== target.rootState || value.rootAbsenceReceiptSha256 !== target.rootAbsenceReceiptSha256
        || value.rootFilesystemIdentitySha256 !== target.rootFilesystemIdentitySha256
        || value.rootParentIdentitySha256 !== shaCanonical(target.rootParentIdentity)
        || value.rootIdentitySha256 !== (target.rootIdentity === null ? null : shaCanonical(target.rootIdentity))) {
      invalid(`${role} target-root producer differs from the exact target identity.`);
    }
    exactString(value.attestationIdentity, `${role} attestation identity`);
    exactSha256(value.attestationArtifactSha256, `${role} attestation artifact SHA256`);
    const attestedAt = exactTimestamp(value.attestedAt, `${role} attestation time`).milliseconds;
    const earliest = role === "sourceTargetCustodian"
      ? exactTimestamp(preinstall.authoritativeBackupAttestation.databaseConsistency.verifiedAt, "database consistency verification time").milliseconds
      : exactTimestamp(expectedTuple.ciChallenge.issuedAt, "CI challenge issue time").milliseconds;
    const latest = role === "sourceTargetCustodian"
      ? exactTimestamp(preinstall.authoritativeBackupAttestation.attestationIssuedAt, "backup attestation issue time").milliseconds
      : exactTimestamp(expectedTuple.ciChallenge.expiresAt, "CI challenge expiry time").milliseconds;
    if (attestedAt < earliest || attestedAt > latest) invalid(`${role} target-root attestation time is not causal.`);
    return value;
  }
  exactObject(value, `${role} producer`, [
    "approvalApproverIdentity", "approvalDecision", "approvalEvidenceIdentity", "approvalEvidenceIssuedAt",
    "approvalEvidenceSha256", "eventName", "headSha", "jobName",
    "jobWorkflowSha", "protectedEnvironment", "ref", "repository", "repositoryId", "repositoryOwnerId",
    "role", "runAttempt", "runId", "type", "workflowPath",
  ]);
  exactRepository(value.repository, `${role} producer repository`);
  exactDecimal(value.repositoryId, `${role} producer repository ID`, true);
  exactDecimal(value.repositoryOwnerId, `${role} producer repository owner ID`, true);
  if (value.repository !== value.repository.toLowerCase()
      || value.type !== "EXTERNAL-CI" || value.role !== role || value.ref !== "refs/heads/main"
      || value.eventName !== "workflow_dispatch"
      || value.repository.toLowerCase() === preinstall.candidate.repository.toLowerCase()
      || value.repositoryId === preinstall.candidate.repositoryId
      || value.repositoryOwnerId === preinstall.candidate.repositoryOwnerId) {
    invalid(`${role} producer identity/ref/event is invalid or candidate-controlled.`);
  }
  exactWorkflowPath(value.workflowPath, `${role} producer workflow path`);
  exactGitSha(value.jobWorkflowSha, `${role} producer job workflow SHA`);
  exactGitSha(value.headSha, `${role} producer head SHA`);
  exactDecimal(value.runId, `${role} producer run ID`, true);
  exactInteger(value.runAttempt, `${role} producer run attempt`, 1);
  exactString(value.jobName, `${role} producer job name`, /^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/);
  exactString(value.protectedEnvironment, `${role} protected environment`);
  if (value.approvalDecision !== "APPROVED") invalid(`${role} protected-environment approval decision is invalid.`);
  exactString(value.approvalApproverIdentity, `${role} approval approver identity`);
  exactString(value.approvalEvidenceIdentity, `${role} approval evidence identity`);
  exactSha256(value.approvalEvidenceSha256, `${role} approval evidence SHA256`);
  if (value.approvalEvidenceIdentity !== `provider-approval:${role}:${value.runId}:${value.runAttempt}`) {
    invalid(`${role} approval evidence identity does not bind its exact role, run ID, and run attempt.`);
  }
  const approvalIssued = exactTimestamp(value.approvalEvidenceIssuedAt, `${role} approval evidence issue time`).milliseconds;
  let earliest;
  let latest;
  if (role === "backupAuthority") {
    earliest = exactTimestamp(preinstall.authoritativeBackupAttestation.databaseConsistency.verifiedAt, "database consistency verification time").milliseconds;
    latest = exactTimestamp(preinstall.authoritativeBackupAttestation.attestationIssuedAt, "backup attestation issue time").milliseconds;
  } else if (role === "phaseBInstaller") {
    earliest = exactTimestamp(preinstall.authoritativeBackupAttestation.attestationIssuedAt, "backup attestation issue time").milliseconds;
    latest = exactTimestamp(expectedTuple.phaseBPreInstallAuthorization.issuedAt, "Phase B issue time").milliseconds;
  } else {
    earliest = exactTimestamp(expectedTuple.ciChallenge.issuedAt, "CI challenge issue time").milliseconds;
    latest = exactTimestamp(expectedTuple.ciChallenge.expiresAt, "CI challenge expiry time").milliseconds;
  }
  if (approvalIssued < earliest || approvalIssued > latest) {
    invalid(`${role} approval evidence is not causal to its signed stage.`);
  }
  return value;
}

function exactPhaseBTargetRootProducer(value, expectedTuple) {
  exactObject(value, "Phase B activation-target-root producer", [
    "attestationArtifactSha256", "attestationIdentity", "attestedAt", "endpoint", "machineId", "role", "root",
    "rootAbsenceReceiptSha256", "rootFilesystemIdentitySha256", "rootIdentitySha256", "rootParentIdentitySha256",
    "rootState", "targetId", "type",
  ]);
  const target = expectedTuple.preinstallTuple.activationTarget;
  if (value.type !== "TARGET-ROOT" || value.role !== "activationTargetRoot"
      || value.targetId !== target.targetId || value.machineId !== target.machineId
      || value.endpoint !== target.endpoint || value.root !== target.root
      || value.rootState !== target.rootState || value.rootAbsenceReceiptSha256 !== target.rootAbsenceReceiptSha256
      || value.rootFilesystemIdentitySha256 !== target.rootFilesystemIdentitySha256
      || value.rootParentIdentitySha256 !== shaCanonical(target.rootParentIdentity)
      || value.rootIdentitySha256 !== (target.rootIdentity === null ? null : shaCanonical(target.rootIdentity))) {
    invalid("Phase B target-root producer differs from activation target identity.");
  }
  exactString(value.attestationIdentity, "Phase B target-root attestation identity");
  exactSha256(value.attestationArtifactSha256, "Phase B target-root attestation artifact SHA256");
  const attestedAt = exactTimestamp(value.attestedAt, "Phase B target-root attestation time").milliseconds;
  const backupIssued = exactTimestamp(
    expectedTuple.preinstallTuple.authoritativeBackupAttestation.attestationIssuedAt,
    "backup attestation issue time",
  ).milliseconds;
  const phaseBIssued = exactTimestamp(expectedTuple.phaseBPreInstallAuthorization.issuedAt, "Phase B issue time").milliseconds;
  if (attestedAt < backupIssued || attestedAt > phaseBIssued) invalid("Phase B target-root attestation time is not causal.");
  return value;
}

function validatePolicy(policyArtifact, expectedPolicySha256, expectedKeyFingerprints) {
  const artifact = exactArtifact(policyArtifact, "V1 brownfield admission policy");
  if (artifact.sha256 !== exactSha256(expectedPolicySha256, "expected policy SHA256")) {
    invalid("Admission policy SHA256 differs from the mandatory trusted caller pin.");
  }
  exactObject(expectedKeyFingerprints, "trusted caller key fingerprints", ROLE_NAMES);
  const callerFingerprints = ROLE_NAMES.map((role) => exactSha256(
    expectedKeyFingerprints[role], `${role} trusted caller fingerprint`,
  ));
  assertDistinct(callerFingerprints, "Trusted caller root fingerprints");

  const policy = exactObject(artifact.document, "V1 brownfield admission policy", [
    "expectedPreinstallTuple", "expectedTuple", "externallyManaged", "freshness", "legacyArtifactHashes", "localMutationAuthority",
    "payloadTypes", "producers", "reason", "roots", "schema", "selfAssertedEvidenceAccepted", "status", "version",
  ]);
  if (policy.schema !== POLICY_SCHEMA || policy.version !== 1 || policy.externallyManaged !== true
      || policy.selfAssertedEvidenceAccepted !== false || policy.localMutationAuthority !== false
      || typeof policy.reason !== "string" || policy.reason.length < 20) {
    invalid("V1 brownfield admission policy identity or authority boundary is invalid.");
  }
  exactObject(policy.freshness, "admission policy freshness", [
    "maxBackupEvidenceAgeSeconds", "maxBaselineToBackupLagSeconds", "maxClockSkewSeconds", "maxLifetimeSeconds",
  ]);
  exactInteger(policy.freshness.maxLifetimeSeconds, "policy maximum lifetime", 1, 3600);
  exactInteger(policy.freshness.maxClockSkewSeconds, "policy maximum clock skew", 0, 300);
  exactInteger(policy.freshness.maxBackupEvidenceAgeSeconds, "policy maximum backup evidence age", 1, 14400);
  exactInteger(policy.freshness.maxBaselineToBackupLagSeconds, "policy maximum baseline-to-backup lag", 1, 14400);
  if (!canonicalEqual(policy.payloadTypes, PAYLOAD_TYPES)) invalid("Admission policy payload types are invalid.");
  exactObject(policy.roots, "admission policy roots", ROLE_NAMES);

  if (policy.status === "EXTERNAL-PENDING") {
    for (const role of ROLE_NAMES) {
      exactObject(policy.roots[role], `${role} pending root`, ["fingerprintSha256", "keyId", "publicKeyPem"]);
      if (Object.values(policy.roots[role]).some((entry) => entry !== null)) {
        invalid("EXTERNAL-PENDING policy cannot contain self-asserted roots.");
      }
    }
    exactObject(policy.producers, "pending admission policy producers", ROLE_NAMES);
    if (Object.values(policy.producers).some((entry) => entry !== null)
        || policy.expectedPreinstallTuple !== null || policy.expectedTuple !== null || policy.legacyArtifactHashes !== null) {
      invalid("EXTERNAL-PENDING policy cannot contain self-asserted transaction evidence.");
    }
    invalid(`EXTERNAL-PENDING: ${policy.reason}`);
  }
  if (policy.status !== "READY") invalid("Admission policy status must be READY or EXTERNAL-PENDING.");
  const roots = {};
  for (const role of ROLE_NAMES) roots[role] = exactPublicRoot(policy.roots[role], role, expectedKeyFingerprints[role]);
  assertDistinct(ROLE_NAMES.map((role) => roots[role].fingerprintSha256), "Admission policy role keys");
  validatePreinstallTuple(policy.expectedPreinstallTuple);
  validateCommonTuple(policy.expectedTuple);
  if (!canonicalEqual(policy.expectedTuple.preinstallTuple, policy.expectedPreinstallTuple)) {
    invalid("Final policy tuple does not embed the exact policy preinstall tuple.");
  }
  const backup = policy.expectedPreinstallTuple.authoritativeBackupAttestation;
  const attestationIssued = exactTimestamp(backup.attestationIssuedAt, "backup attestation issue time").milliseconds;
  const evidenceTimes = [
    exactTimestamp(backup.captureStartedAt, "backup capture start time").milliseconds,
    exactTimestamp(backup.captureCompletedAt, "backup capture completion time").milliseconds,
    exactTimestamp(backup.verifiedAt, "backup verification time").milliseconds,
    exactTimestamp(backup.writeConsistency.capturedAt, "point-in-time snapshot time").milliseconds,
    exactTimestamp(backup.writeConsistency.verifiedAt, "point-in-time snapshot verification time").milliseconds,
    exactTimestamp(policy.expectedPreinstallTuple.structuralBackupReceipt.verifiedAt, "structural receipt verification time").milliseconds,
    exactTimestamp(backup.offHostRetrieval.lastVerifiedAt, "off-host retrieval verification time").milliseconds,
    exactTimestamp(backup.restoreDrill.verifiedAt, "restore drill verification time").milliseconds,
    exactTimestamp(backup.databaseConsistency.verifiedAt, "database consistency verification time").milliseconds,
  ];
  const maximumEvidenceAge = policy.freshness.maxBackupEvidenceAgeSeconds * 1000;
  const baselineStarted = exactTimestamp(
    policy.expectedPreinstallTuple.baseline.captureStartedAt, "baseline capture start time",
  ).milliseconds;
  const backupStarted = exactTimestamp(backup.captureStartedAt, "backup capture start time").milliseconds;
  if (backupStarted - baselineStarted > policy.freshness.maxBaselineToBackupLagSeconds * 1000
      || evidenceTimes.some((time) => attestationIssued - time > maximumEvidenceAge)
      || exactTimestamp(policy.expectedTuple.installReceipt.installedAt, "installation time").milliseconds
        - evidenceTimes[0] > maximumEvidenceAge
      || exactTimestamp(policy.expectedTuple.ciChallenge.issuedAt, "final challenge issue time").milliseconds
        - evidenceTimes[0] > maximumEvidenceAge) {
    invalid("Backup evidence is too old for this PRE-DEPLOY install/final admission policy.");
  }
  exactObject(policy.producers, "admission policy producers", ROLE_NAMES);
  for (const role of ROLE_NAMES) exactProducer(policy.producers[role], role, policy.expectedTuple);
  const externalRoles = [
    "backupAuthority", "hostedGate", "deploymentGate", "activationGate", "admissionController", "phaseBInstaller",
  ];
  assertDistinct(
    externalRoles.map((role) => policy.producers[role].repository.toLowerCase()),
    "External producer repository identities",
  );
  assertDistinct(
    externalRoles.map((role) => policy.producers[role].repositoryId),
    "External producer repository IDs",
  );
  assertDistinct(
    externalRoles.map((role) => policy.producers[role].repositoryOwnerId),
    "External producer repository owner IDs",
  );
  assertDistinct(
    externalRoles.map((role) => `${policy.producers[role].repository.toLowerCase()}@${policy.producers[role].workflowPath}`),
    "External producer workflow identities",
  );
  assertDistinct(
    externalRoles.map((role) => `${policy.producers[role].repositoryId}:${policy.producers[role].runId}:${policy.producers[role].runAttempt}:${policy.producers[role].jobName}`),
    "External producer run/job identities",
  );
  assertDistinct(externalRoles.map((role) => policy.producers[role].runId), "External producer run IDs");
  assertDistinct(
    externalRoles.map((role) => policy.producers[role].approvalEvidenceSha256),
    "External producer approval evidence artifacts",
  );
  exactObject(policy.legacyArtifactHashes, "policy legacy artifact hashes", GATE_ORDER);
  for (const gate of GATE_ORDER) exactLegacyHashes(policy.legacyArtifactHashes[gate], gate);
  const legacyEvidenceHashes = GATE_ORDER.flatMap((gate) => Object.values(policy.legacyArtifactHashes[gate]));
  assertDistinct(legacyEvidenceHashes, "Nine role-specific legacy gate evidence artifacts");
  exactPhaseBTargetRootProducer(
    policy.expectedTuple.phaseBPreInstallAuthorization.activationTargetRootProducer,
    policy.expectedTuple,
  );
  const challenge = policy.expectedTuple.ciChallenge;
  const controller = policy.producers.admissionController;
  if (challenge.repository !== controller.repository || challenge.repositoryId !== controller.repositoryId
      || challenge.repositoryOwnerId !== controller.repositoryOwnerId
      || challenge.workflowPath !== controller.workflowPath || challenge.workflowSha !== controller.jobWorkflowSha
      || challenge.job !== controller.jobName || challenge.ref !== controller.ref
      || challenge.eventName !== controller.eventName || challenge.protectedEnvironment !== controller.protectedEnvironment
      || challenge.runId !== controller.runId || challenge.runAttempt !== controller.runAttempt) {
    invalid("Final CI challenge does not bind the exact independent admission-controller run identity.");
  }
  if (policy.expectedTuple.phaseBPreInstallAuthorization.phaseBInstallerFingerprintSha256
        !== roots.phaseBInstaller.fingerprintSha256
      || policy.expectedTuple.phaseBPreInstallAuthorization.activationTargetRootFingerprintSha256
        !== roots.activationTargetRoot.fingerprintSha256
      || !canonicalEqual(
        policy.expectedTuple.phaseBPreInstallAuthorization.phaseBInstallerProducer,
        policy.producers.phaseBInstaller,
      )) {
    invalid("Phase B installer/target-root roots or producer differ from the caller-pinned final policy.");
  }
  const expectedPhaseAFutureRoleKeyIds = {
    backupAuthority: roots.backupAuthority.keyId,
    sourceTargetCustodian: roots.sourceTargetCustodian.keyId,
    phaseBInstaller: roots.phaseBInstaller.keyId,
    hostedGate: roots.hostedGate.keyId,
    deploymentGate: roots.deploymentGate.keyId,
    activationGate: roots.activationGate.keyId,
    admissionController: roots.admissionController.keyId,
    activationTargetRoot: roots.activationTargetRoot.keyId,
  };
  if (!canonicalEqual(policy.expectedPreinstallTuple.phaseA.futureRoleKeyIds, expectedPhaseAFutureRoleKeyIds)) {
    invalid("Phase A future-role key IDs do not map exactly to the caller-pinned core roles.");
  }
  assertDistinct([
    ...ROLE_NAMES.map((role) => roots[role].keyId),
    policy.expectedPreinstallTuple.phaseA.packageAttestorKeyId,
    policy.expectedPreinstallTuple.phaseA.authorizationProviderKeyId,
  ], "Phase A signer and core role keys");
  const bootstrap = policy.expectedPreinstallTuple.installPlan.installerBootstrap;
  if (bootstrap.phaseBInstallerFingerprintSha256 !== roots.phaseBInstaller.fingerprintSha256
      || bootstrap.activationTargetRootFingerprintSha256 !== roots.activationTargetRoot.fingerprintSha256) {
    invalid("Preexisting installer bootstrap trust roots differ from caller pins.");
  }
  assertDistinct([
    policy.producers.sourceTargetCustodian.attestationArtifactSha256,
    policy.producers.activationTargetRoot.attestationArtifactSha256,
    policy.expectedTuple.phaseBPreInstallAuthorization.activationTargetRootProducer.attestationArtifactSha256,
  ], "Target-root producer attestation artifacts");
  assertDistinct([
    policy.producers.sourceTargetCustodian.attestationIdentity,
    policy.expectedTuple.phaseBPreInstallAuthorization.activationTargetRootProducer.attestationIdentity,
    policy.producers.activationTargetRoot.attestationIdentity,
  ], "Target-root stage attestation identities");
  const tuple = policy.expectedTuple;
  assertDistinct([
    ...preinstallTypedArtifactHashes(policy.expectedPreinstallTuple),
    tuple.backupAttestationEnvelopeSha256,
    tuple.phaseBPreInstallAuthorization.authorizationEnvelopeSha256,
    tuple.phaseBPreInstallAuthorization.verificationReceiptSha256,
    tuple.installReceipt.artifactSha256,
    tuple.installReceipt.materializationReceiptSha256,
    tuple.installReceipt.installerBootstrapExecutionReceiptSha256,
    tuple.installReceipt.privilegePolicyTargetVerification.verificationReceiptSha256,
    tuple.phaseBPreInstallAuthorization.preMutationAncestryVerification.verificationReceiptSha256,
    tuple.installReceipt.postInstallAncestryVerification.verificationReceiptSha256,
    tuple.installReceipt.phaseBLedgerConsumption.claimArtifactSha256,
    tuple.installReceipt.phaseBLedgerConsumption.journalArtifactSha256,
    ...externalRoles.map((role) => policy.producers[role].approvalEvidenceSha256),
    policy.producers.sourceTargetCustodian.attestationArtifactSha256,
    policy.producers.activationTargetRoot.attestationArtifactSha256,
    tuple.phaseBPreInstallAuthorization.activationTargetRootProducer.attestationArtifactSha256,
    ...legacyEvidenceHashes,
  ], "Admission typed evidence and legacy artifact hashes");
  return { artifact, policy, roots };
}

function verifyEnvelope(artifactValue, { label, payloadType, roles, roots }) {
  const artifact = exactArtifact(artifactValue, label);
  const envelope = exactObject(artifact.document, `${label} DSSE envelope`, ["payload", "payloadType", "signatures"]);
  if (envelope.payloadType !== payloadType) invalid(`${label} DSSE payload type is invalid.`);
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== roles.length) {
    invalid(`${label} DSSE signature count is invalid.`);
  }
  const payloadBytes = strictBase64(envelope.payload, `${label} DSSE payload`);
  let payload;
  try {
    const text = payloadBytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(payloadBytes) || text.startsWith("\uFEFF")) invalid("payload is not exact UTF-8");
    payload = JSON.parse(text);
  } catch (error) {
    invalid(`${label} DSSE payload is not JSON: ${String(error?.message ?? error)}`);
  }
  if (!payloadBytes.equals(Buffer.from(canonicalJson(payload), "utf8"))) {
    invalid(`${label} DSSE payload is not exact canonical JSON.`);
  }
  for (let index = 0; index < roles.length; index += 1) {
    const role = roles[index];
    const signature = exactObject(envelope.signatures[index], `${label} ${role} DSSE signature`, ["keyid", "sig"]);
    if (signature.keyid !== roots[role].keyId) invalid(`${label} ${role} signature does not use the authorized key.`);
    const signatureBytes = strictBase64(signature.sig, `${label} ${role} DSSE signature`);
    if (signatureBytes.length !== 64
        || !crypto.verify(null, dssePae(payloadType, payloadBytes), roots[role].publicKey, signatureBytes)) {
      invalid(`${label} ${role} DSSE signature is invalid.`);
    }
  }
  return { ...artifact, payload, payloadSha256: crypto.createHash("sha256").update(payloadBytes).digest("hex") };
}

function validateFreshness(payload, tuple, policy, now, label) {
  const issued = exactTimestamp(payload.issuedAt, `${label} issue time`);
  const expires = exactTimestamp(payload.expiresAt, `${label} expiry time`);
  const challengeIssued = exactTimestamp(tuple.ciChallenge.issuedAt, "CI challenge issue time").milliseconds;
  const challengeExpires = exactTimestamp(tuple.ciChallenge.expiresAt, "CI challenge expiry time").milliseconds;
  if (issued.milliseconds < challengeIssued || issued.milliseconds >= challengeExpires
      || expires.milliseconds !== challengeExpires) {
    invalid(`${label} freshness escapes the exact enclosing post-install CI challenge window.`);
  }
  const lifetime = expires.milliseconds - issued.milliseconds;
  if (lifetime < 1 || lifetime > tuple.ciChallenge.maxAgeSeconds * 1000
      || lifetime > policy.freshness.maxLifetimeSeconds * 1000) {
    invalid(`${label} freshness lifetime exceeds policy.`);
  }
  const skew = policy.freshness.maxClockSkewSeconds * 1000;
  if (now < issued.milliseconds - skew || now > expires.milliseconds + skew) {
    invalid(`${label} freshness is expired or not yet valid.`);
  }
}

function exactTupleBinding(payload, policy, label) {
  validateCommonTuple(payload.tuple);
  const tupleSha256 = shaCanonical(payload.tuple);
  if (payload.tupleSha256 !== tupleSha256) invalid(`${label} tuple SHA256 is invalid.`);
  if (!canonicalEqual(payload.tuple, policy.expectedTuple)) invalid(`${label} common tuple differs from policy.`);
  return payload.tuple;
}

function validateBackupPayload(verified, policyState) {
  const payload = exactObject(verified.payload, "authoritative backup attestation payload", [
    "attestationId", "backupTrustPolicySha256", "evidence", "expiresAt", "issuedAt", "preinstallTuple",
    "preinstallTupleSha256", "producers", "schema",
  ]);
  if (payload.schema !== BACKUP_SCHEMA) {
    invalid("Authoritative backup attestation schema is invalid.");
  }
  const tuple = validatePreinstallTuple(payload.preinstallTuple);
  if (payload.preinstallTupleSha256 !== shaCanonical(tuple)
      || !canonicalEqual(tuple, policyState.policy.expectedPreinstallTuple)) {
    invalid("Authoritative backup attestation preinstall tuple differs from final policy.");
  }
  if (payload.attestationId !== tuple.authoritativeBackupAttestation.attestationId
      || payload.backupTrustPolicySha256 !== tuple.authoritativeBackupAttestation.backupTrustPolicySha256
      || payload.issuedAt !== tuple.authoritativeBackupAttestation.attestationIssuedAt
      || payload.expiresAt !== tuple.authoritativeBackupAttestation.attestationExpiresAt) {
    invalid("Authoritative backup attestation identity, trust policy, or preinstall window is invalid.");
  }
  const lifetime = exactTimestamp(payload.expiresAt, "backup attestation expiry time").milliseconds
    - exactTimestamp(payload.issuedAt, "backup attestation issue time").milliseconds;
  if (lifetime < 1 || lifetime > policyState.policy.freshness.maxLifetimeSeconds * 1000) {
    invalid("Authoritative backup attestation lifetime exceeds policy.");
  }
  exactObject(payload.producers, "authoritative backup producers", ["backupAuthority", "sourceTargetCustodian"]);
  for (const role of ["backupAuthority", "sourceTargetCustodian"]) {
    exactProducer(payload.producers[role], role, policyState.policy.expectedTuple);
    if (!canonicalEqual(payload.producers[role], policyState.policy.producers[role])) {
      invalid(`Authoritative backup ${role} producer differs from policy.`);
    }
  }
  if (exactTimestamp(payload.producers.sourceTargetCustodian.attestedAt, "source target custodian attestation time").milliseconds
      > exactTimestamp(payload.producers.backupAuthority.approvalEvidenceIssuedAt, "backup authority approval time").milliseconds) {
    invalid("Backup authority approval must follow the exact source-custodian restore/database attestation.");
  }
  const evidence = exactObject(payload.evidence, "authoritative backup evidence", [
    "backupArtifactSetSha256", "backupDeviceIdentity", "backupManifestSha256", "backupSetId", "dataRollbackAuthority",
    "databaseConsistency", "databaseCount", "databaseSetSha256", "evidenceArtifactSha256", "offHost", "offHostRetrieval", "captureCompletedAt",
    "captureStartedAt", "restoreDrill",
    "protectedArtifactCount", "protectedArtifactSetSha256", "sourceDeviceSetExcluded", "sourceDeviceSetSha256", "verifiedAt",
    "structuralReceiptArtifactSha256", "structuralReceiptId", "structuralReceiptVerifiedAt", "writeConsistency",
  ]);
  const expected = tuple.authoritativeBackupAttestation;
  const exactBindings = {
    evidenceArtifactSha256: expected.evidenceArtifactSha256,
    structuralReceiptArtifactSha256: tuple.structuralBackupReceipt.artifactSha256,
    structuralReceiptId: tuple.structuralBackupReceipt.receiptId,
    structuralReceiptVerifiedAt: tuple.structuralBackupReceipt.verifiedAt,
    sourceDeviceSetSha256: tuple.baseline.sourceDeviceSetSha256,
    backupDeviceIdentity: expected.backupDeviceIdentity,
    backupSetId: expected.backupSetId,
    backupManifestSha256: expected.backupManifestSha256,
    backupArtifactSetSha256: expected.backupArtifactSetSha256,
    protectedArtifactSetSha256: expected.protectedArtifactSetSha256,
    protectedArtifactCount: expected.protectedArtifactCount,
    databaseSetSha256: expected.databaseSetSha256,
    databaseCount: expected.databaseCount,
    captureStartedAt: expected.captureStartedAt,
    captureCompletedAt: expected.captureCompletedAt,
    verifiedAt: expected.verifiedAt,
    offHost: true,
    sourceDeviceSetExcluded: true,
    offHostRetrieval: expected.offHostRetrieval,
    restoreDrill: expected.restoreDrill,
    databaseConsistency: expected.databaseConsistency,
    writeConsistency: expected.writeConsistency,
    dataRollbackAuthority: false,
  };
  if (!canonicalEqual(evidence, exactBindings)) {
    invalid("Authoritative backup evidence lacks exact off-host, database consistency, restore, or no-data-rollback bindings.");
  }
  if (expected.evidenceArtifactSha256 === verified.sha256) {
    invalid("Underlying backup evidence cannot self-reference the backup DSSE envelope.");
  }
  return { ...verified, payload, tuple };
}

function validateGatePayload(verified, gate, policyState, backup, priorGates, now) {
  const payload = exactObject(verified.payload, `${gate} gate admission payload`, [
    "admissionId", "backupAttestationEnvelopeSha256", "dataRollbackAuthority", "decision", "expiresAt",
    "externalEvidence", "gate", "issuedAt", "legacyArtifactHashes", "policySha256", "predecessor", "producer", "schema", "tuple", "tupleSha256",
  ]);
  if (payload.schema !== GATE_SCHEMA || payload.gate !== gate) invalid(`${gate} gate identity is invalid.`);
  if (payload.policySha256 !== policyState.artifact.sha256) invalid(`${gate} gate policy SHA256 is invalid.`);
  exactSha256(payload.admissionId, `${gate} admission ID`);
  const tuple = exactTupleBinding(payload, policyState.policy, `${gate} gate`);
  validateFreshness(payload, tuple, policyState.policy, now, `${gate} gate`);
  if (payload.backupAttestationEnvelopeSha256 !== backup.sha256
      || tuple.backupAttestationEnvelopeSha256 !== backup.sha256) {
    invalid(`${gate} gate backup attestation envelope SHA256 is invalid.`);
  }
  if (payload.decision !== "PASS" || payload.externalEvidence !== true || payload.dataRollbackAuthority !== false) {
    invalid(`${gate} gate decision cannot grant data rollback authority and requires external PASS evidence.`);
  }
  const role = ROLE_BY_GATE[gate];
  exactProducer(payload.producer, role, tuple);
  if (!canonicalEqual(payload.producer, policyState.policy.producers[role])) {
    invalid(`${gate} gate producer differs from policy.`);
  }
  const approvalIssuedAt = exactTimestamp(
    payload.producer.approvalEvidenceIssuedAt, `${gate} protected approval time`,
  ).milliseconds;
  const gateIssuedAt = exactTimestamp(payload.issuedAt, `${gate} gate issue time`).milliseconds;
  if (approvalIssuedAt > gateIssuedAt) invalid(`${gate} approval does not precede its causal gate issuance.`);
  const gateIndex = GATE_ORDER.indexOf(gate);
  if (gateIndex === 0) {
    if (payload.predecessor !== null) invalid("HOSTED gate must have no predecessor.");
  } else {
    const priorGate = GATE_ORDER[gateIndex - 1];
    const prior = priorGates[priorGate];
    const predecessor = exactObject(payload.predecessor, `${gate} predecessor`, [
      "admissionId", "envelopeSha256", "gate", "payloadSha256", "payloadType", "role", "rootKeyFingerprintSha256",
    ]);
    const priorRole = ROLE_BY_GATE[priorGate];
    if (predecessor.gate !== priorGate || predecessor.admissionId !== prior.payload.admissionId
        || predecessor.envelopeSha256 !== prior.sha256 || predecessor.payloadSha256 !== prior.payloadSha256
        || predecessor.payloadType !== PAYLOAD_TYPES.gates[priorGate] || predecessor.role !== priorRole
        || predecessor.rootKeyFingerprintSha256 !== policyState.roots[priorRole].fingerprintSha256) {
      invalid(`${gate} predecessor does not bind the exact ${priorGate} gate envelope and payload.`);
    }
    const priorIssuedAt = exactTimestamp(prior.payload.issuedAt, `${priorGate} gate issue time`).milliseconds;
    if (priorIssuedAt > approvalIssuedAt || priorIssuedAt > gateIssuedAt) {
      invalid(`${gate} stage order precedes its exact predecessor gate issuance.`);
    }
  }
  exactLegacyHashes(payload.legacyArtifactHashes, gate, policyState.policy.legacyArtifactHashes[gate]);
  return { ...verified, payload, tuple };
}

function validateAggregatePayload(verified, policyState, backup, gates, now) {
  const payload = exactObject(verified.payload, "aggregate admission payload", [
    "admissionId", "backupAttestationEnvelopeSha256", "dataRollbackAuthority", "decision", "expiresAt",
    "gates", "issuedAt", "policySha256", "producers", "schema", "tuple", "tupleSha256",
  ]);
  if (payload.schema !== AGGREGATE_SCHEMA || payload.policySha256 !== policyState.artifact.sha256) {
    invalid("Aggregate admission schema/policy binding is invalid.");
  }
  exactSha256(payload.admissionId, "aggregate admission ID");
  const tuple = exactTupleBinding(payload, policyState.policy, "aggregate admission");
  validateFreshness(payload, tuple, policyState.policy, now, "aggregate admission");
  const backupExpires = exactTimestamp(
    tuple.preinstallTuple.authoritativeBackupAttestation.attestationExpiresAt,
    "authoritative backup attestation expiry time",
  ).milliseconds;
  const backupCaptureCompleted = exactTimestamp(
    tuple.preinstallTuple.authoritativeBackupAttestation.captureCompletedAt,
    "authoritative backup capture completion time",
  ).milliseconds;
  if (now >= backupExpires) {
    invalid("Aggregate verification occurred after authoritative backup recoverability expired.");
  }
  if (now - backupCaptureCompleted > policyState.policy.freshness.maxBackupEvidenceAgeSeconds * 1000) {
    invalid("Aggregate verification occurred after fresh PRE-DEPLOY backup evidence aged out.");
  }
  if (payload.backupAttestationEnvelopeSha256 !== backup.sha256
      || tuple.backupAttestationEnvelopeSha256 !== backup.sha256) {
    invalid("Aggregate backup attestation envelope SHA256 is invalid.");
  }
  if (payload.decision !== "PASS" || payload.dataRollbackAuthority !== false) {
    invalid("Aggregate decision must be PASS without data rollback authority.");
  }
  exactObject(payload.producers, "aggregate producers", ["activationTargetRoot", "admissionController"]);
  for (const role of ["admissionController", "activationTargetRoot"]) {
    exactProducer(payload.producers[role], role, tuple);
    if (!canonicalEqual(payload.producers[role], policyState.policy.producers[role])) {
      invalid(`Aggregate ${role} producer differs from policy.`);
    }
  }
  const aggregateIssuedAt = exactTimestamp(payload.issuedAt, "aggregate issue time").milliseconds;
  const controllerApprovalAt = exactTimestamp(
    payload.producers.admissionController.approvalEvidenceIssuedAt, "admission-controller approval time",
  ).milliseconds;
  const targetAttestedAt = exactTimestamp(
    payload.producers.activationTargetRoot.attestedAt, "activation-target-root attestation time",
  ).milliseconds;
  const activationGateIssuedAt = exactTimestamp(
    gates.ACTIVATION.payload.issuedAt, "ACTIVATION gate issue time",
  ).milliseconds;
  if (activationGateIssuedAt > controllerApprovalAt || controllerApprovalAt > aggregateIssuedAt
      || targetAttestedAt > aggregateIssuedAt) {
    invalid("Aggregate causal stage order does not follow activation, approval, and target-root attestation.");
  }
  if (!Array.isArray(payload.gates) || payload.gates.length !== GATE_ORDER.length
      || payload.gates.some((entry, index) => entry?.gate !== GATE_ORDER[index])) {
    invalid("Aggregate gate order is not the fixed HOSTED, DEPLOYMENT, ACTIVATION sequence.");
  }
  for (let index = 0; index < GATE_ORDER.length; index += 1) {
    const gate = GATE_ORDER[index];
    const entry = exactObject(payload.gates[index], `aggregate ${gate} gate reference`, [
      "admissionId", "envelopeSha256", "gate", "legacyArtifactSetSha256", "payloadSha256", "payloadType",
      "role", "rootKeyFingerprintSha256",
    ]);
    const role = ROLE_BY_GATE[gate];
    if (entry.admissionId !== gates[gate].payload.admissionId || entry.envelopeSha256 !== gates[gate].sha256
        || entry.payloadSha256 !== gates[gate].payloadSha256) {
      invalid(`Aggregate ${gate} envelope or payload SHA256 binding is invalid.`);
    }
    if (entry.legacyArtifactSetSha256 !== shaCanonical(policyState.policy.legacyArtifactHashes[gate])) {
      invalid(`Aggregate ${gate} legacy artifact set SHA256 is invalid.`);
    }
    if (entry.role !== role || entry.payloadType !== PAYLOAD_TYPES.gates[gate]
        || entry.rootKeyFingerprintSha256 !== policyState.roots[role].fingerprintSha256) {
      invalid(`Aggregate ${gate} role, payload type, or root fingerprint binding is invalid.`);
    }
  }
  const identifiers = [
    tuple.transactionId,
    ...(tuple.preinstallTuple.identityTransition === null ? [] : [tuple.preinstallTuple.identityTransition.transitionId]),
    tuple.preinstallTuple.phaseA.authorizationId,
    tuple.preinstallTuple.phaseA.packageAttestationId,
    tuple.preinstallTuple.phaseA.nonce,
    tuple.preinstallTuple.phaseA.orderContractId,
    tuple.preinstallTuple.baseline.baselineId,
    tuple.preinstallTuple.structuralBackupReceipt.receiptId,
    tuple.preinstallTuple.authoritativeBackupAttestation.attestationId,
    tuple.preinstallTuple.authoritativeBackupAttestation.backupSetId,
    tuple.phaseBPreInstallAuthorization.authorizationId,
    tuple.phaseBPreInstallAuthorization.nonce,
    tuple.installReceipt.phaseBLedgerConsumption.claimId,
    tuple.installReceipt.phaseBLedgerConsumption.ledgerEntryKeySha256,
    tuple.installReceipt.phaseBLedgerConsumption.receiptObjectKeySha256,
    tuple.installReceipt.receiptId,
    tuple.preinstallTuple.rollbackPolicy.policyId,
    tuple.ciChallenge.challengeId,
    tuple.ciChallenge.nonce,
    ...GATE_ORDER.map((gate) => gates[gate].payload.admissionId),
    payload.admissionId,
  ];
  assertDistinct(identifiers, "Admission chain identifiers");
  const envelopeHashes = [backup.sha256, ...GATE_ORDER.map((gate) => gates[gate].sha256), verified.sha256];
  assertDistinct(envelopeHashes, "Admission envelope hashes");
  if (envelopeHashes.includes(tuple.preinstallTuple.authoritativeBackupAttestation.evidenceArtifactSha256)) {
    invalid("Underlying backup evidence hash cannot point to an admission DSSE envelope.");
  }
  return { ...verified, payload, tuple };
}

export function verifyV1BrownfieldAdmission({
  policyArtifact,
  expectedPolicySha256,
  expectedKeyFingerprints,
  backupAttestationArtifact,
  gateArtifacts,
  aggregateArtifact,
  now = Date.now(),
}) {
  exactInteger(now, "verification clock", 0);
  const policyState = validatePolicy(policyArtifact, expectedPolicySha256, expectedKeyFingerprints);
  exactObject(gateArtifacts, "gate artifacts", GATE_ORDER);
  const backupEnvelope = verifyEnvelope(backupAttestationArtifact, {
    label: "authoritative backup attestation",
    payloadType: PAYLOAD_TYPES.backupAttestation,
    roles: ["backupAuthority", "sourceTargetCustodian"],
    roots: policyState.roots,
  });
  const backup = validateBackupPayload(backupEnvelope, policyState);
  const gates = {};
  for (const gate of GATE_ORDER) {
    const gateEnvelope = verifyEnvelope(gateArtifacts[gate], {
      label: `${gate} gate admission`,
      payloadType: PAYLOAD_TYPES.gates[gate],
      roles: [ROLE_BY_GATE[gate]],
      roots: policyState.roots,
    });
    gates[gate] = validateGatePayload(gateEnvelope, gate, policyState, backup, gates, now);
  }
  const aggregateEnvelope = verifyEnvelope(aggregateArtifact, {
    label: "aggregate admission",
    payloadType: PAYLOAD_TYPES.aggregate,
    roles: ["admissionController", "activationTargetRoot"],
    roots: policyState.roots,
  });
  const aggregate = validateAggregatePayload(aggregateEnvelope, policyState, backup, gates, now);

  return Object.freeze({
    schema: VALIDATION_SCHEMA,
    status: "LOCAL-VERIFIED-NON-AUTHORITATIVE",
    authoritative: false,
    chainComplete: false,
    phaseAVerificationStatus: "EXTERNAL-PENDING",
    phaseBPreinstallVerificationStatus: "EXTERNAL-PENDING",
    replayEnforcementStatus: "EXTERNAL-BROKER-REQUIRED",
    runtimeBootstrapTrustStatus: "EXTERNAL-PENDING",
    rawBaselineVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    rawBackupReceiptVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    sourceSetRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    offHostSourceDeviceExclusionVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    restoredCoverageRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    databaseCoverageRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    protectedPathOverlapVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    packageArchiveFormatVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    packageManifestMemberExtractionVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    replayArtifactByteSchemaVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    consumerChallengeAuthorityStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    expectedBindingsAuthorityStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    rawBaselineReopened: false,
    rawStructuralBackupReceiptReopened: false,
    sourceDeviceSetRecomputed: false,
    offHostSourceDeviceExclusionRecomputed: false,
    restoredCoverageRecomputed: false,
    databaseCoverageRecomputed: false,
    protectedPathSetRecomputed: false,
    allInstallWritesDisjointFromProtectedPaths: false,
    packageArchiveFormatVerified: false,
    packageManifestMembersRecomputed: false,
    replayClaimBytesSchemaVerified: false,
    replayJournalBytesSchemaVerified: false,
    installExecutionReceiptBytesSchemaVerified: false,
    consumerChallengeAuthorityVerified: false,
    expectedBindingsAuthorityVerified: false,
    trustedNativeLauncherRequired: true,
    stdoutAuthority: false,
    liveAuthorization: false,
    mutationAuthority: false,
    localMutationAuthority: false,
    policySha256: policyState.artifact.sha256,
    transactionId: aggregate.tuple.transactionId,
    tupleSha256: shaCanonical(aggregate.tuple),
    backupAttestationEnvelopeSha256: backup.sha256,
    gateEnvelopeSha256: Object.freeze(Object.fromEntries(GATE_ORDER.map((gate) => [gate, gates[gate].sha256]))),
    aggregateEnvelopeSha256: aggregate.sha256,
    gates: GATE_ORDER,
  });
}

function captureArtifact(filename, label) {
  if (typeof filename !== "string" || filename.length === 0) invalid(`${label} path is missing.`);
  const resolved = path.resolve(filename);
  let descriptor;
  try {
    const beforePath = fs.lstatSync(resolved, { bigint: true });
    if (beforePath.isSymbolicLink()) invalid(`${label} path is a symlink and cannot be captured safely.`);
    if (!beforePath.isFile()) invalid(`${label} path must be a regular file.`);
    if (typeof fs.constants.O_NOFOLLOW !== "number" || fs.constants.O_NOFOLLOW === 0) {
      invalid(`${label} cannot be captured without O_NOFOLLOW.`);
    }
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 2n || before.size > BigInt(MAX_ARTIFACT_BYTES)) {
      invalid(`${label} violates the bounded regular-file size requirement.`);
    }
    if (before.dev !== beforePath.dev || before.ino !== beforePath.ino) invalid(`${label} path identity changed before capture.`);
    const bounded = Buffer.allocUnsafe(Number(before.size) + 1);
    let offset = 0;
    while (offset < bounded.length) {
      const count = fs.readSync(descriptor, bounded, offset, bounded.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    if (offset > Number(before.size)) invalid(`${label} grew beyond its bounded snapshot while captured.`);
    const bytes = bounded.subarray(0, offset);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(resolved, { bigint: true });
    if (BigInt(bytes.length) !== before.size || before.dev !== after.dev || before.ino !== after.ino
        || before.nlink !== after.nlink || after.nlink !== 1n
        || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
        || afterPath.isSymbolicLink() || afterPath.dev !== before.dev || afterPath.ino !== before.ino
        || afterPath.nlink !== 1n || afterPath.size !== before.size
        || afterPath.mtimeNs !== before.mtimeNs || afterPath.ctimeNs !== before.ctimeNs) {
      invalid(`${label} changed while captured.`);
    }
    return { bytes, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
  } catch (error) {
    invalid(`${label} could not be captured safely: ${String(error?.message ?? error)}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function usage() {
  return `Usage: v1-brownfield-admission.mjs --policy FILE --backup-attestation FILE --hosted-gate FILE --deployment-gate FILE --activation-gate FILE --aggregate FILE --expected-policy-sha256 SHA256 --expected-key-fingerprint ROLE=SHA256 (exactly ${ROLE_NAMES.length} roles)`;
}

function parseArgs(values) {
  const options = {};
  const fingerprints = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (typeof key !== "string" || !key.startsWith("--") || typeof value !== "string" || value.length === 0
        || value.startsWith("--")) invalid(usage());
    const name = key.slice(2);
    if (name === "expected-key-fingerprint") {
      const separator = value.indexOf("=");
      const role = value.slice(0, separator);
      const digest = value.slice(separator + 1);
      if (separator < 1 || !ROLE_NAMES.includes(role) || Object.hasOwn(fingerprints, role)) invalid(usage());
      fingerprints[role] = exactSha256(digest, `${role} CLI fingerprint`);
    } else {
      if (!new Set([
        "policy", "backup-attestation", "hosted-gate", "deployment-gate", "activation-gate", "aggregate",
        "expected-policy-sha256",
      ]).has(name) || Object.hasOwn(options, name)) invalid(usage());
      options[name] = value;
    }
  }
  exactObject(options, "V1 brownfield admission arguments", [
    "activation-gate", "aggregate", "backup-attestation", "deployment-gate", "expected-policy-sha256",
    "hosted-gate", "policy",
  ]);
  exactObject(fingerprints, "V1 brownfield admission caller fingerprints", ROLE_NAMES);
  return { options, fingerprints };
}

function main() {
  // JavaScript cannot establish trust before Node processes NODE_OPTIONS or loader hooks.
  // Production must use a fixed, root-owned native launcher with a scrubbed environment and
  // reverify artifacts/results out of process; stdout from this local verifier is never authority.
  const { options, fingerprints } = parseArgs(process.argv.slice(2));
  const result = verifyV1BrownfieldAdmission({
    policyArtifact: captureArtifact(options.policy, "V1 brownfield admission policy"),
    expectedPolicySha256: options["expected-policy-sha256"],
    expectedKeyFingerprints: fingerprints,
    backupAttestationArtifact: captureArtifact(options["backup-attestation"], "authoritative backup attestation"),
    gateArtifacts: {
      HOSTED: captureArtifact(options["hosted-gate"], "HOSTED gate admission"),
      DEPLOYMENT: captureArtifact(options["deployment-gate"], "DEPLOYMENT gate admission"),
      ACTIVATION: captureArtifact(options["activation-gate"], "ACTIVATION gate admission"),
    },
    aggregateArtifact: captureArtifact(options.aggregate, "aggregate admission"),
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
