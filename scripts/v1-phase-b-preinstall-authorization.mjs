#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AUTHORIZATION_PAYLOAD_TYPE as PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
  FORBIDDEN_OPERATIONS as PHASE_A_FORBIDDEN_OPERATIONS,
  PACKAGE_PAYLOAD_TYPE as PHASE_A_PACKAGE_PAYLOAD_TYPE,
  PERMITTED_OPERATIONS as PHASE_A_PERMITTED_OPERATIONS,
  validateV1PhaseAPolicy,
  verifyV1PhaseAAuthorization,
} from "./v1-phase-a-authorization.mjs";
import {
  PHASE_B_OPERATION_SCOPE,
  validateV1BrownfieldInstallPlan,
  validateV1BrownfieldPhaseBPreinstallEvidence,
  validateV1BrownfieldPreinstallTuple,
} from "./v1-brownfield-admission.mjs";

export {
  PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
  PHASE_A_PACKAGE_PAYLOAD_TYPE,
};
export const BACKUP_PAYLOAD_TYPE =
  "application/vnd.platform.v1-authoritative-backup-attestation.v1+json";
export const PHASE_B_PREINSTALL_PAYLOAD_TYPE =
  "application/vnd.platform.v1.phase-b.preinstall-authorization.v1+json";
export const PHASE_B_REPLAY_DOMAIN =
  "phase-b-exact-preinstall/platform-infrastructure/v1";

export const ROLE_NAMES = Object.freeze([
  "packageAttestor",
  "phaseAAuthorizationProvider",
  "backupAuthority",
  "sourceTargetCustodian",
  "phaseBInstaller",
  "hostedGate",
  "deploymentGate",
  "activationGate",
  "admissionController",
  "activationTargetRoot",
]);

export const PHASE_B_SIGNER_ROLES = Object.freeze([
  "phaseBInstaller",
  "activationTargetRoot",
]);

export const PERMITTED_OPERATIONS = PHASE_B_OPERATION_SCOPE.permitted;
export const FORBIDDEN_OPERATIONS = PHASE_B_OPERATION_SCOPE.forbidden;

const POLICY_SCHEMA = "platform.v1-phase-b-preinstall-policy/v1";
const EXPECTED_SCHEMA = "platform.v1-phase-b-preinstall-expected/v1";
const PREINSTALL_TUPLE_SCHEMA = "platform.v1-brownfield-preinstall-tuple/v1";
const INSTALL_PLAN_SCHEMA = "platform.v1-phase-b-install-plan/v2";
const AUTHORIZATION_SCHEMA = "platform.v1-phase-b-preinstall-authorization/v1";
const BACKUP_SCHEMA = "platform.v1-authoritative-backup-attestation/v1";
const VALIDATION_SCHEMA = "platform.v1-phase-b-preinstall-verification/v1";
const EXTERNAL_ROOT_CONSUMER_REQUIRED =
  "EXTERNAL_ROOT_CONSUMER_REQUIRED";
const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const OPAQUE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const EXTERNAL_ROLES = new Set([
  "packageAttestor",
  "phaseAAuthorizationProvider",
  "backupAuthority",
  "phaseBInstaller",
  "hostedGate",
  "deploymentGate",
  "activationGate",
  "admissionController",
]);
const FUTURE_EXTERNAL_AUTHORITY_ROLES = Object.freeze([
  "backupAuthority",
  "hostedGate",
  "deploymentGate",
  "activationGate",
  "admissionController",
  "phaseBInstaller",
]);
const TARGET_ROLES = new Set([
  "sourceTargetCustodian",
  "activationTargetRoot",
]);
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

function invalid(message) {
  throw new Error(message);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      invalid("Canonical JSON accepts only plain JSON objects.");
    }
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, stable(value[key])]),
    );
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  invalid("Canonical JSON contains an unsupported value.");
}

export function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function canonicalEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function shaBytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function shaCanonical(value) {
  return shaBytes(Buffer.from(canonicalJson(value), "utf8"));
}

function domainSeparatedSha256(domain, ...values) {
  return shaBytes(Buffer.from([domain, ...values].join("\0"), "utf8"));
}

function exactObject(value, label, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !canonicalEqual(Object.keys(value).sort(), [...keys].sort())
  ) {
    invalid(label + " does not use the exact closed schema.");
  }
  return value;
}

function exactArray(value, expected, label) {
  if (!Array.isArray(value) || !canonicalEqual(value, expected)) {
    invalid(label + " is not the exact closed sequence.");
  }
  return value;
}

function exactArrayLength(value, length, label) {
  if (!Array.isArray(value) || value.length !== length) {
    invalid(label + " must contain exactly " + String(length) + " entries.");
  }
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    invalid(label + " must be one lowercase SHA256.");
  }
  return value;
}

function exactGitSha(value, label) {
  if (typeof value !== "string" || !GIT_SHA.test(value)) {
    invalid(label + " must be one full lowercase Git SHA.");
  }
  return value;
}

function exactIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    invalid(label + " is not a canonical identifier.");
  }
  return value;
}

function exactOpaqueIdentifier(value, label) {
  if (typeof value !== "string" || !OPAQUE_IDENTIFIER.test(value)) {
    invalid(label + " is not a canonical opaque identifier.");
  }
  return value;
}

function exactJobName(value, label) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$/.test(value)
  ) {
    invalid(label + " is not a canonical job name.");
  }
  return value;
}

function exactRepository(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 3 ||
    value.length > 256 ||
    value !== value.toLowerCase() ||
    !/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(value)
  ) {
    invalid(label + " must use exact owner/name syntax.");
  }
  return value;
}

function exactWorkflowPath(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 22 ||
    value.length > 256 ||
    !/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(value)
  ) {
    invalid(label + " is not a canonical workflow path.");
  }
  return value;
}

function exactDecimal(value, label, { positive = false } = {}) {
  const expression = positive ? POSITIVE_DECIMAL : DECIMAL;
  if (typeof value !== "string" || !expression.test(value)) {
    invalid(label + " must be one canonical decimal string.");
  }
  const number = Number(value);
  if (
    !Number.isSafeInteger(number) ||
    String(number) !== value ||
    (positive && number < 1)
  ) {
    invalid(label + " exceeds the accepted exact integer range.");
  }
  return value;
}

function exactInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    invalid(label + " must be an exact safe integer in range.");
  }
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string") {
    invalid(label + " must be one canonical UTC timestamp.");
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(label + " must be one canonical UTC timestamp.");
  }
  return { value, milliseconds };
}

function exactAbsolutePath(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 2 ||
    value.length > 4096 ||
    !/^\/(?:(?!\.{1,2}(?:\/|$))[A-Za-z0-9._-]+)(?:\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9._-]+)*$/.test(value) ||
    path.posix.normalize(value) !== value
  ) {
    invalid(label + " must be one normalized absolute path.");
  }
  return value;
}

function pathsOverlap(left, right) {
  return left === right ||
    left.startsWith(right + "/") ||
    right.startsWith(left + "/");
}

function exactSshEndpoint(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 10 ||
    value.length > 320 ||
    !/^ssh:\/\/[a-z_][a-z0-9_-]{0,31}@(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$/.test(value)
  ) {
    invalid(label + " is not one canonical ssh://user@host:port identity.");
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    invalid(label + " is invalid.");
  }
  if (
    url.protocol !== "ssh:" ||
    !/^[a-z_][a-z0-9_-]{0,31}$/.test(url.username) ||
    url.password ||
    !url.hostname ||
    url.hostname !== url.hostname.toLowerCase() ||
    !url.port ||
    Number(url.port) > 65535 ||
    url.pathname !== "" ||
    url.search ||
    url.hash ||
    url.toString() !== value
  ) {
    invalid(label + " is not one canonical ssh://user@host:port identity.");
  }
  return url;
}

function exactNonce(value, label) {
  if (typeof value !== "string" || !NONCE.test(value)) {
    invalid(label + " must be one canonical 256-bit base64url nonce.");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) {
    invalid(label + " must be one canonical 256-bit base64url nonce.");
  }
  return value;
}

function assertDistinct(values, label) {
  if (new Set(values).size !== values.length) {
    invalid(label + " must be pairwise distinct.");
  }
}

function strictBase64(value, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    invalid(label + " is not strict base64.");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    invalid(label + " is not canonical base64.");
  }
  return bytes;
}

function dssePae(payloadType, payloadBytes) {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from("DSSEv1 " + String(type.length) + " ", "ascii"),
    type,
    Buffer.from(" " + String(payloadBytes.length) + " ", "ascii"),
    payloadBytes,
  ]);
}

function exactArtifact(artifactValue, label) {
  if (
    !artifactValue ||
    !Buffer.isBuffer(artifactValue.bytes) ||
    artifactValue.bytes.length < 3 ||
    artifactValue.bytes.length > MAX_ARTIFACT_BYTES
  ) {
    invalid(label + " must be one explicitly supplied bounded artifact.");
  }
  let document;
  try {
    const text = utf8Decoder.decode(artifactValue.bytes);
    if (text.startsWith("\uFEFF")) invalid(label + " must not contain a BOM.");
    document = JSON.parse(text);
  } catch (error) {
    invalid(label + " is invalid UTF-8 JSON: " + String(error?.message ?? error));
  }
  const canonicalBytes = Buffer.from(canonicalJson(document) + "\n", "utf8");
  if (!canonicalBytes.equals(artifactValue.bytes)) {
    invalid(label + " must use exact canonical JSON bytes with one LF.");
  }
  return Object.freeze({
    bytes: artifactValue.bytes,
    document,
    sha256: shaBytes(artifactValue.bytes),
  });
}

function exactPublicRoot(value, role, expectedKeyId) {
  exactObject(value, role + " policy root", [
    "algorithm",
    "keyId",
    "producerConstraints",
    "publicKeySpkiPem",
    "role",
  ]);
  if (value.role !== role || value.algorithm !== "Ed25519") {
    invalid(role + " policy role or algorithm is invalid.");
  }
  if (
    typeof value.publicKeySpkiPem !== "string" ||
    !value.publicKeySpkiPem.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !value.publicKeySpkiPem.endsWith("-----END PUBLIC KEY-----\n") ||
    value.publicKeySpkiPem.includes("PRIVATE KEY")
  ) {
    invalid(role + " root must be exact canonical SPKI public-key PEM.");
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(value.publicKeySpkiPem);
  } catch {
    invalid(role + " root must be exact canonical SPKI public-key PEM.");
  }
  if (publicKey.asymmetricKeyType !== "ed25519") {
    invalid(role + " root must be an Ed25519 public key.");
  }
  const canonicalPem = publicKey.export({ type: "spki", format: "pem" });
  if (canonicalPem !== value.publicKeySpkiPem) {
    invalid(role + " root SPKI PEM is not canonical.");
  }
  const keyId = shaBytes(publicKey.export({ type: "spki", format: "der" }));
  if (
    value.keyId !== keyId ||
    exactSha256(expectedKeyId, role + " expected key ID") !== keyId
  ) {
    invalid(role + " key ID/public key/caller binding is invalid.");
  }
  validateProducerConstraints(value.producerConstraints, role);
  return Object.freeze({ ...value, publicKey });
}

function validateProducerConstraints(value, role) {
  if (EXTERNAL_ROLES.has(role)) {
    exactObject(value, role + " external producer constraints", [
      "eventName",
      "jobName",
      "jobWorkflowSha",
      "protectedEnvironment",
      "ref",
      "repository",
      "repositoryId",
      "repositoryOwnerId",
      "role",
      "type",
      "workflowPath",
    ]);
    if (
      value.type !== "EXTERNAL-CI" ||
      value.role !== role ||
      value.ref !== "refs/heads/main" ||
      value.eventName !== "workflow_dispatch"
    ) {
      invalid(role + " producer constraints have the wrong trust domain.");
    }
    exactRepository(value.repository, role + " constraint repository");
    exactDecimal(value.repositoryId, role + " constraint repository ID", { positive: true });
    exactDecimal(value.repositoryOwnerId, role + " constraint repository owner ID", { positive: true });
    exactWorkflowPath(value.workflowPath, role + " constraint workflow path");
    exactGitSha(value.jobWorkflowSha, role + " constraint workflow SHA");
    exactJobName(value.jobName, role + " constraint job");
    exactIdentifier(
      value.protectedEnvironment,
      role + " constraint protected environment",
    );
    return value;
  }
  if (TARGET_ROLES.has(role)) {
    exactObject(value, role + " target-root constraints", [
      "endpoint",
      "machineIdentitySha256",
      "role",
      "rootAbsenceReceiptSha256",
      "rootFilesystemIdentitySha256",
      "rootIdentitySha256",
      "rootParentIdentitySha256",
      "rootState",
      "targetId",
      "targetRoot",
      "type",
    ]);
    if (value.type !== "TARGET-ROOT" || value.role !== role) {
      invalid(role + " target-root constraint role is invalid.");
    }
    exactSshEndpoint(value.endpoint, role + " constrained endpoint");
    exactSha256(value.machineIdentitySha256, role + " constrained machine identity");
    exactSha256(value.rootFilesystemIdentitySha256, role + " constrained root identity");
    exactSha256(value.rootParentIdentitySha256, role + " constrained root-parent identity");
    if (value.rootState === "ABSENT_PROVEN") {
      exactSha256(value.rootAbsenceReceiptSha256, role + " constrained root absence receipt");
      if (value.rootIdentitySha256 !== null) {
        invalid(role + " absent constrained root cannot have a leaf identity.");
      }
    } else if (value.rootState === "EXISTING_EXACT") {
      if (value.rootAbsenceReceiptSha256 !== null) {
        invalid(role + " existing constrained root cannot have an absence receipt.");
      }
      exactSha256(value.rootIdentitySha256, role + " constrained root identity");
    } else {
      invalid(role + " constrained root state is invalid.");
    }
    exactIdentifier(value.targetId, role + " constrained target ID");
    exactAbsolutePath(value.targetRoot, role + " constrained root");
    return value;
  }
  invalid("Unknown policy role " + role + ".");
}

function exactExternalProducer(
  value,
  role,
  constraints,
) {
  exactObject(value, role + " producer", [
    "approvalApproverIdentity",
    "approvalDecision",
    "approvalEvidenceIdentity",
    "approvalEvidenceIssuedAt",
    "approvalEvidenceSha256",
    "eventName",
    "headSha",
    "jobName",
    "jobWorkflowSha",
    "protectedEnvironment",
    "ref",
    "repository",
    "repositoryId",
    "repositoryOwnerId",
    "role",
    "runAttempt",
    "runId",
    "type",
    "workflowPath",
  ]);
  if (
    value.type !== "EXTERNAL-CI" ||
    value.role !== role ||
    value.approvalDecision !== "APPROVED"
  ) {
    invalid(role + " external producer authority is invalid.");
  }
  const stableProjection = {
    type: value.type,
    role: value.role,
    repository: value.repository,
    repositoryId: value.repositoryId,
    repositoryOwnerId: value.repositoryOwnerId,
    workflowPath: value.workflowPath,
    jobWorkflowSha: value.jobWorkflowSha,
    ref: value.ref,
    eventName: value.eventName,
    jobName: value.jobName,
    protectedEnvironment: value.protectedEnvironment,
  };
  if (!canonicalEqual(stableProjection, constraints)) {
    invalid(role + " producer differs from the independently pinned constraints.");
  }
  exactGitSha(value.headSha, role + " producer head SHA");
  exactDecimal(value.runId, role + " producer run ID", { positive: true });
  exactInteger(value.runAttempt, role + " producer run attempt", 1);
  exactIdentifier(value.approvalApproverIdentity, role + " approver identity");
  exactIdentifier(value.approvalEvidenceIdentity, role + " approval identity");
  exactSha256(value.approvalEvidenceSha256, role + " approval SHA256");
  exactTimestamp(value.approvalEvidenceIssuedAt, role + " approval timestamp");
  const expectedApprovalIdentity =
    "provider-approval:" + role + ":" + value.runId + ":" +
    String(value.runAttempt);
  if (value.approvalEvidenceIdentity !== expectedApprovalIdentity) {
    invalid(role + " approval evidence does not bind the run and attempt.");
  }
  return value;
}

function exactTargetRootProducer(value, role, constraints) {
  exactObject(value, role + " producer", [
    "attestationArtifactSha256",
    "attestationIdentity",
    "attestedAt",
    "endpoint",
    "machineId",
    "role",
    "root",
    "rootAbsenceReceiptSha256",
    "rootFilesystemIdentitySha256",
    "rootIdentitySha256",
    "rootParentIdentitySha256",
    "rootState",
    "targetId",
    "type",
  ]);
  const stableProjection = {
    type: value.type,
    role: value.role,
    endpoint: value.endpoint,
    machineIdentitySha256: value.machineId,
    rootAbsenceReceiptSha256: value.rootAbsenceReceiptSha256,
    rootFilesystemIdentitySha256: value.rootFilesystemIdentitySha256,
    rootIdentitySha256: value.rootIdentitySha256,
    rootParentIdentitySha256: value.rootParentIdentitySha256,
    rootState: value.rootState,
    targetId: value.targetId,
    targetRoot: value.root,
  };
  if (!canonicalEqual(stableProjection, constraints)) {
    invalid(role + " producer differs from the independently pinned target.");
  }
  exactIdentifier(value.attestationIdentity, role + " attestation identity");
  exactSha256(value.attestationArtifactSha256, role + " attestation artifact");
  exactTimestamp(value.attestedAt, role + " attestation time");
  return value;
}

function targetConstraintProjection(target, role) {
  return {
    type: "TARGET-ROOT",
    role,
    endpoint: target.endpoint,
    machineIdentitySha256: target.machineId,
    rootAbsenceReceiptSha256: target.rootAbsenceReceiptSha256,
    rootFilesystemIdentitySha256: target.rootFilesystemIdentitySha256,
    rootIdentitySha256: target.rootIdentity === null
      ? null
      : shaCanonical(target.rootIdentity),
    rootParentIdentitySha256: shaCanonical(target.rootParentIdentity),
    rootState: target.rootState,
    targetId: target.targetId,
    targetRoot: target.root,
  };
}

function exactProducer(value, role, root) {
  if (EXTERNAL_ROLES.has(role)) {
    return exactExternalProducer(value, role, root.producerConstraints);
  }
  return exactTargetRootProducer(value, role, root.producerConstraints);
}

function pendingRole(value, role) {
  exactObject(value, role + " pending role", [
    "algorithm",
    "keyId",
    "producerConstraints",
    "publicKeySpkiPem",
    "role",
  ]);
  if (
    value.role !== role ||
    value.algorithm !== "Ed25519" ||
    value.keyId !== null ||
    value.publicKeySpkiPem !== null ||
    value.producerConstraints !== null
  ) {
    invalid("EXTERNAL-PENDING " + role + " must contain no trust material.");
  }
}

function validatePolicy(policyArtifact, expected) {
  const artifact = exactArtifact(policyArtifact, "Phase-B PREINSTALL policy");
  if (artifact.sha256 !== exactSha256(expected.policySha256, "expected policy SHA256")) {
    invalid("Phase-B policy SHA256 differs from the caller-supplied pin.");
  }
  const policy = exactObject(artifact.document, "Phase-B PREINSTALL policy", [
    "authoritativeEvidence",
    "backupTrustPolicySha256",
    "externallyManaged",
    "freshness",
    "installPlanSchema",
    "installPlanSchemaSha256",
    "localMutationAuthority",
    "localTemplate",
    "payloadTypes",
    "reason",
    "replayDomain",
    "roles",
    "schema",
    "selfAssertedEvidenceAccepted",
    "status",
    "trustAnchorProvenance",
    "version",
  ]);
  if (
    policy.schema !== POLICY_SCHEMA ||
    policy.version !== 1 ||
    policy.externallyManaged !== true ||
    policy.selfAssertedEvidenceAccepted !== false ||
    policy.authoritativeEvidence !== false ||
    policy.localMutationAuthority !== false ||
    typeof policy.reason !== "string" ||
    policy.reason.length < 20
  ) {
    invalid("Phase-B policy identity or authority boundary is invalid.");
  }
  exactObject(policy.payloadTypes, "Phase-B payload types", [
    "backupAttestation",
    "phaseAAuthorization",
    "phaseAPackageAttestation",
    "phaseBPreinstallAuthorization",
  ]);
  if (
    policy.payloadTypes.phaseAPackageAttestation !== PHASE_A_PACKAGE_PAYLOAD_TYPE ||
    policy.payloadTypes.phaseAAuthorization !== PHASE_A_AUTHORIZATION_PAYLOAD_TYPE ||
    policy.payloadTypes.backupAttestation !== BACKUP_PAYLOAD_TYPE ||
    policy.payloadTypes.phaseBPreinstallAuthorization !== PHASE_B_PREINSTALL_PAYLOAD_TYPE
  ) {
    invalid("Phase-B policy payload domains are invalid.");
  }
  exactObject(policy.freshness, "Phase-B policy freshness", [
    "maxBackupEvidenceAgeSeconds",
    "maxBaselineToBackupLagSeconds",
    "maxClockSkewSeconds",
    "maxLifetimeSeconds",
  ]);
  exactInteger(policy.freshness.maxLifetimeSeconds, "Phase-B maximum lifetime", 1, 900);
  exactInteger(policy.freshness.maxClockSkewSeconds, "Phase-B clock skew", 0, 300);
  exactInteger(policy.freshness.maxBackupEvidenceAgeSeconds,
    "Phase-B maximum backup evidence age", 1, 14400);
  exactInteger(policy.freshness.maxBaselineToBackupLagSeconds,
    "Phase-B maximum baseline-to-backup lag", 1, 14400);
  if (
    policy.replayDomain !== PHASE_B_REPLAY_DOMAIN ||
    policy.installPlanSchema !== INSTALL_PLAN_SCHEMA
  ) {
    invalid("Phase-B replay or install-plan domain is invalid.");
  }
  exactObject(policy.roles, "Phase-B policy role map", ROLE_NAMES);

  if (policy.status === "EXTERNAL-PENDING") {
    if (
      policy.localTemplate !== true ||
      policy.trustAnchorProvenance !== "NOT_CONFIGURED" ||
      policy.backupTrustPolicySha256 !== null ||
      policy.installPlanSchemaSha256 !== null
    ) {
      invalid("EXTERNAL-PENDING Phase-B policy must not contain trust bindings.");
    }
    for (const role of ROLE_NAMES) pendingRole(policy.roles[role], role);
    invalid("EXTERNAL-PENDING: " + policy.reason);
  }
  if (
    policy.status !== "READY" ||
    policy.localTemplate !== false ||
    policy.trustAnchorProvenance !== "CALLER-SUPPLIED-NON-AUTHORITATIVE"
  ) {
    invalid("Phase-B verifier accepts only external READY policy in caller-anchored non-authoritative mode.");
  }
  exactSha256(policy.backupTrustPolicySha256, "backup trust policy SHA256");
  exactSha256(policy.installPlanSchemaSha256, "install-plan schema SHA256");
  exactObject(expected.roleKeyIds, "expected role key IDs", ROLE_NAMES);
  const roots = {};
  for (const role of ROLE_NAMES) {
    roots[role] = exactPublicRoot(
      policy.roles[role],
      role,
      expected.roleKeyIds[role],
    );
  }
  assertDistinct(ROLE_NAMES.map((role) => roots[role].keyId), "Phase-B cross-contract role keys");
  const futureAuthorityConstraints = FUTURE_EXTERNAL_AUTHORITY_ROLES.map(
    (role) => roots[role].producerConstraints,
  );
  assertDistinct(
    futureAuthorityConstraints.map((constraints) =>
      constraints.repository.toLowerCase()),
    "Phase-B future authority repositories",
  );
  assertDistinct(
    futureAuthorityConstraints.map((constraints) => constraints.repositoryId),
    "Phase-B future authority repository IDs",
  );
  assertDistinct(
    futureAuthorityConstraints.map((constraints) =>
      constraints.repositoryOwnerId),
    "Phase-B future authority repository owner IDs",
  );
  return Object.freeze({ artifact, policy, roots });
}

function validatePhaseAPolicyArtifact(
  phaseAPolicyArtifact,
  expected,
  phaseBPolicyValue,
) {
  const artifact = exactArtifact(
    phaseAPolicyArtifact,
    "raw Phase-A policy",
  );
  if (
    artifact.sha256 !==
      exactSha256(expected.phaseAPolicySha256, "expected Phase-A policy SHA256")
  ) {
    invalid("Raw Phase-A policy SHA256 differs from the caller-supplied pin.");
  }
  const policy = validateV1PhaseAPolicy(artifact.document, {
    requireReady: true,
  });
  if (
    policy.packageAttestor.keyId !==
      phaseBPolicyValue.roots.packageAttestor.keyId ||
    policy.authorizationProvider.keyId !==
      phaseBPolicyValue.roots.phaseAAuthorizationProvider.keyId
  ) {
    invalid("Raw Phase-A policy signer roots differ from the Phase-B role map.");
  }
  const phaseAConstraintProjection = (producer, role) => ({
    type: "EXTERNAL-CI",
    role,
    repository: producer.repository,
    repositoryId: producer.repositoryId,
    repositoryOwnerId: producer.repositoryOwnerId,
    workflowPath: producer.workflowPath,
    jobWorkflowSha: producer.jobWorkflowSha,
    ref: producer.ref,
    eventName: producer.eventName,
    jobName: producer.jobName,
    protectedEnvironment: producer.protectedEnvironment,
  });
  if (
    !canonicalEqual(
      phaseAConstraintProjection(
        policy.packageAttestor.producer,
        "packageAttestor",
      ),
      phaseBPolicyValue.roots.packageAttestor.producerConstraints,
    ) ||
    !canonicalEqual(
      phaseAConstraintProjection(
        policy.authorizationProvider.producer,
        "phaseAAuthorizationProvider",
      ),
      phaseBPolicyValue.roots.phaseAAuthorizationProvider.producerConstraints,
    )
  ) {
    invalid("Raw Phase-A producer constraints differ from the Phase-B role map.");
  }
  const futureMap = {
    backupAuthority: phaseBPolicyValue.roots.backupAuthority.keyId,
    sourceTargetCustodian:
      phaseBPolicyValue.roots.sourceTargetCustodian.keyId,
    phaseBInstaller: phaseBPolicyValue.roots.phaseBInstaller.keyId,
    hostedGate: phaseBPolicyValue.roots.hostedGate.keyId,
    deploymentGate: phaseBPolicyValue.roots.deploymentGate.keyId,
    activationGate: phaseBPolicyValue.roots.activationGate.keyId,
    admissionController: phaseBPolicyValue.roots.admissionController.keyId,
    activationTargetRoot:
      phaseBPolicyValue.roots.activationTargetRoot.keyId,
  };
  if (!canonicalEqual(policy.futureRoleKeyIds, futureMap)) {
    invalid("Raw Phase-A future-role key aliases differ from the exact Phase-B role map.");
  }
  return Object.freeze({ artifact, policy, futureMap });
}

function verifyEnvelope(artifactValue, {
  label,
  payloadType,
  signers,
}) {
  const artifact = exactArtifact(artifactValue, label);
  const envelope = exactObject(artifact.document, label + " DSSE envelope", [
    "payload",
    "payloadType",
    "signatures",
  ]);
  if (envelope.payloadType !== payloadType) {
    invalid(label + " payload type is invalid.");
  }
  exactArrayLength(envelope.signatures, signers.length, label + " signatures");
  const payloadBytes = strictBase64(envelope.payload, label + " payload");
  let payload;
  try {
    payload = JSON.parse(utf8Decoder.decode(payloadBytes));
  } catch {
    invalid(label + " payload is invalid UTF-8 JSON.");
  }
  if (!payloadBytes.equals(Buffer.from(canonicalJson(payload), "utf8"))) {
    invalid(label + " payload must be exact canonical JSON without a trailing LF.");
  }
  const pae = dssePae(payloadType, payloadBytes);
  const keyIds = [];
  for (let index = 0; index < signers.length; index += 1) {
    const signature = exactObject(
      envelope.signatures[index],
      label + " signature " + String(index),
      ["keyid", "sig"],
    );
    const signer = signers[index];
    if (signature.keyid !== signer.keyId) {
      invalid(label + " signature role/order is invalid.");
    }
    const signatureBytes = strictBase64(signature.sig, label + " signature");
    if (!crypto.verify(null, pae, signer.publicKey, signatureBytes)) {
      invalid(label + " signature verification failed.");
    }
    keyIds.push(signature.keyid);
  }
  assertDistinct(keyIds, label + " signer key IDs");
  return Object.freeze({
    artifact,
    envelope,
    payload,
    payloadBytes,
    payloadSha256: shaBytes(payloadBytes),
  });
}




function exactBackupEvidence(value, label) {
  exactObject(value, label, [
    "backupArtifactSetSha256",
    "backupDeviceIdentity",
    "backupManifestSha256",
    "backupSetId",
    "captureCompletedAt",
    "captureStartedAt",
    "databaseCount",
    "databaseConsistency",
    "databaseSetSha256",
    "dataRollbackAuthority",
    "evidenceArtifactSha256",
    "offHost",
    "offHostRetrieval",
    "protectedArtifactCount",
    "protectedArtifactSetSha256",
    "restoreDrill",
    "sourceDeviceSetExcluded",
    "sourceDeviceSetSha256",
    "structuralReceiptArtifactSha256",
    "structuralReceiptId",
    "structuralReceiptVerifiedAt",
    "verifiedAt",
    "writeConsistency",
  ]);
  for (const key of [
    "backupArtifactSetSha256",
    "backupManifestSha256",
    "backupSetId",
    "databaseSetSha256",
    "evidenceArtifactSha256",
    "protectedArtifactSetSha256",
    "sourceDeviceSetSha256",
    "structuralReceiptArtifactSha256",
    "structuralReceiptId",
  ]) {
    exactSha256(value[key], label + " " + key);
  }
  exactIdentifier(value.backupDeviceIdentity, label + " backup device identity");
  exactInteger(value.protectedArtifactCount,
    label + " protected artifact count", 1);
  exactInteger(value.databaseCount, label + " database count", 1);
  if (
    value.offHost !== true ||
    value.sourceDeviceSetExcluded !== true ||
    value.dataRollbackAuthority !== false
  ) {
    invalid(label + " does not prove off-host source-device exclusion and no data rollback.");
  }
  exactTimestamp(value.captureStartedAt, label + " capture start");
  exactTimestamp(value.captureCompletedAt, label + " capture completion");
  exactTimestamp(value.verifiedAt, label + " verification time");
  exactTimestamp(
    value.structuralReceiptVerifiedAt,
    label + " structural receipt verification time",
  );
  for (const nested of [
    "offHostRetrieval", "restoreDrill", "databaseConsistency", "writeConsistency",
  ]) {
    if (!value[nested] || typeof value[nested] !== "object" ||
        Array.isArray(value[nested])) invalid(label + " " + nested + " is invalid.");
  }
  return value;
}


export function validateInstallPlanV2(value) {
  return validateV1BrownfieldInstallPlan(value);
}


export function validatePreinstallTuple(value) {
  const tuple = validateV1BrownfieldPreinstallTuple(value);
  if (tuple.schema !== PREINSTALL_TUPLE_SCHEMA) {
    invalid("Phase-B preinstall tuple schema is not the canonical brownfield schema.");
  }
  return tuple;
}

function validateBackupPayload(
  payload,
  roots,
  tuple,
  tupleSha256,
  backupTrustPolicySha256,
  freshness,
  now,
) {
  exactObject(payload, "authoritative backup payload", [
    "attestationId",
    "backupTrustPolicySha256",
    "evidence",
    "expiresAt",
    "issuedAt",
    "preinstallTuple",
    "preinstallTupleSha256",
    "producers",
    "schema",
  ]);
  if (payload.schema !== BACKUP_SCHEMA) {
    invalid("Authoritative backup payload schema is invalid.");
  }
  exactSha256(payload.attestationId, "authoritative backup attestation ID");
  exactSha256(payload.preinstallTupleSha256, "backup preinstall-tuple SHA256");
  exactSha256(payload.backupTrustPolicySha256, "backup trust-policy SHA256");
  const embeddedTuple = validatePreinstallTuple(payload.preinstallTuple);
  if (
    payload.preinstallTupleSha256 !== tupleSha256 ||
    payload.preinstallTupleSha256 !== shaCanonical(embeddedTuple) ||
    !canonicalEqual(embeddedTuple, tuple) ||
    payload.backupTrustPolicySha256 !== backupTrustPolicySha256
  ) {
    invalid("Authoritative backup payload binds a different canonical tuple or trust policy.");
  }
  exactObject(payload.producers, "authoritative backup producers", [
    "backupAuthority",
    "sourceTargetCustodian",
  ]);
  exactExternalProducer(
    payload.producers.backupAuthority,
    "backupAuthority",
    roots.backupAuthority.producerConstraints,
  );
  exactRawBackupTargetProducer(
    payload.producers.sourceTargetCustodian,
    "sourceTargetCustodian",
    roots.sourceTargetCustodian,
    tuple.sourceTarget,
  );
  const backup = tuple.authoritativeBackupAttestation;
  const expectedEvidence = {
    evidenceArtifactSha256: backup.evidenceArtifactSha256,
    structuralReceiptArtifactSha256:
      tuple.structuralBackupReceipt.artifactSha256,
    structuralReceiptId: tuple.structuralBackupReceipt.receiptId,
    structuralReceiptVerifiedAt: tuple.structuralBackupReceipt.verifiedAt,
    sourceDeviceSetSha256: tuple.baseline.sourceDeviceSetSha256,
    backupDeviceIdentity: backup.backupDeviceIdentity,
    backupSetId: backup.backupSetId,
    backupManifestSha256: backup.backupManifestSha256,
    backupArtifactSetSha256: backup.backupArtifactSetSha256,
    protectedArtifactSetSha256: backup.protectedArtifactSetSha256,
    protectedArtifactCount: backup.protectedArtifactCount,
    databaseSetSha256: backup.databaseSetSha256,
    databaseCount: backup.databaseCount,
    captureStartedAt: backup.captureStartedAt,
    captureCompletedAt: backup.captureCompletedAt,
    verifiedAt: backup.verifiedAt,
    offHost: true,
    sourceDeviceSetExcluded: true,
    offHostRetrieval: backup.offHostRetrieval,
    restoreDrill: backup.restoreDrill,
    databaseConsistency: backup.databaseConsistency,
    writeConsistency: backup.writeConsistency,
    dataRollbackAuthority: false,
  };
  exactBackupEvidence(payload.evidence, "authoritative backup payload evidence");
  if (
    !canonicalEqual(payload.evidence, expectedEvidence) ||
    payload.attestationId !== backup.attestationId ||
    payload.issuedAt !== backup.attestationIssuedAt ||
    payload.expiresAt !== backup.attestationExpiresAt ||
    payload.backupTrustPolicySha256 !== backup.backupTrustPolicySha256
  ) {
    invalid("Authoritative backup payload differs from the canonical preinstall backup binding.");
  }
  const issued = exactTimestamp(payload.issuedAt, "authoritative backup issue time");
  const expires = exactTimestamp(payload.expiresAt, "authoritative backup expiry");
  const databaseVerified = exactTimestamp(
    backup.databaseConsistency.verifiedAt,
    "database consistency verification",
  );
  const sourceAttested = exactTimestamp(
    payload.producers.sourceTargetCustodian.attestedAt,
    "source-target custody attestation",
  );
  const backupApproval = exactTimestamp(
    payload.producers.backupAuthority.approvalEvidenceIssuedAt,
    "backup authority approval",
  );
  const backupStarted = exactTimestamp(
    backup.captureStartedAt,
    "authoritative backup capture start",
  );
  const evidenceTimes = [
    backup.captureStartedAt,
    backup.captureCompletedAt,
    backup.verifiedAt,
    backup.writeConsistency.capturedAt,
    backup.writeConsistency.verifiedAt,
    tuple.structuralBackupReceipt.verifiedAt,
    backup.offHostRetrieval.lastVerifiedAt,
    backup.restoreDrill.verifiedAt,
    backup.databaseConsistency.verifiedAt,
  ].map((value, index) => exactTimestamp(
    value,
    "authoritative backup evidence time " + String(index),
  ).milliseconds);
  const baselineStarted = exactTimestamp(
    tuple.baseline.captureStartedAt,
    "baseline capture start",
  );
  const maximumEvidenceAge = freshness.maxBackupEvidenceAgeSeconds * 1000;
  if (
    expires.milliseconds <= issued.milliseconds ||
    expires.milliseconds - issued.milliseconds >
      freshness.maxLifetimeSeconds * 1000 ||
    evidenceTimes.some((time) =>
      issued.milliseconds - time > maximumEvidenceAge ||
      now - time > maximumEvidenceAge) ||
    backupStarted.milliseconds - baselineStarted.milliseconds >
      freshness.maxBaselineToBackupLagSeconds * 1000 ||
    sourceAttested.milliseconds < databaseVerified.milliseconds ||
    sourceAttested.milliseconds > issued.milliseconds ||
    backupApproval.milliseconds < sourceAttested.milliseconds ||
    backupApproval.milliseconds > issued.milliseconds
  ) {
    invalid("Authoritative backup signing timestamps are not causal.");
  }
  return payload;
}

function exactRawBackupTargetProducer(value, role, root, sourceTarget) {
  exactObject(value, role + " raw-backup producer", [
    "attestationArtifactSha256",
    "attestationIdentity",
    "attestedAt",
    "endpoint",
    "machineId",
    "role",
    "root",
    "rootAbsenceReceiptSha256",
    "rootFilesystemIdentitySha256",
    "rootIdentitySha256",
    "rootParentIdentitySha256",
    "rootState",
    "targetId",
    "type",
  ]);
  const constraints = root.producerConstraints;
  if (
    value.type !== "TARGET-ROOT" ||
    value.role !== role ||
    value.targetId !== constraints.targetId ||
    value.machineId !== constraints.machineIdentitySha256 ||
    value.endpoint !== constraints.endpoint ||
    value.root !== constraints.targetRoot ||
    value.rootState !== constraints.rootState ||
    value.rootAbsenceReceiptSha256 !== constraints.rootAbsenceReceiptSha256 ||
    value.rootFilesystemIdentitySha256 !==
      constraints.rootFilesystemIdentitySha256 ||
    value.rootParentIdentitySha256 !== constraints.rootParentIdentitySha256 ||
    value.rootIdentitySha256 !== constraints.rootIdentitySha256
  ) {
    invalid(role + " raw-backup producer differs from pinned target constraints.");
  }
  if (
    sourceTarget.targetId !== value.targetId ||
    sourceTarget.machineId !== value.machineId ||
    sourceTarget.endpoint !== value.endpoint ||
    sourceTarget.root !== value.root ||
    sourceTarget.rootState !== value.rootState ||
    sourceTarget.rootAbsenceReceiptSha256 !== value.rootAbsenceReceiptSha256 ||
    sourceTarget.rootFilesystemIdentitySha256 !==
      value.rootFilesystemIdentitySha256 ||
    shaCanonical(sourceTarget.rootParentIdentity) !==
      value.rootParentIdentitySha256 ||
    (sourceTarget.rootIdentity === null
      ? value.rootIdentitySha256 !== null
      : shaCanonical(sourceTarget.rootIdentity) !== value.rootIdentitySha256)
  ) {
    invalid(role + " raw-backup producer differs from the Phase-B source target.");
  }
  exactIdentifier(value.attestationIdentity, role + " attestation identity");
  exactSha256(value.attestationArtifactSha256, role + " attestation artifact");
  exactTimestamp(value.attestedAt, role + " attestation time");
  return value;
}

function exactBackupRef(value, label) {
  exactObject(value, label, [
    "attestationId",
    "backupAuthorityKeyId",
    "backupSetId",
    "backupTrustPolicySha256",
    "envelopeSha256",
    "expiresAt",
    "issuedAt",
    "payloadSha256",
    "payloadType",
    "sourceTargetCustodianKeyId",
  ]);
  for (const key of [
    "attestationId",
    "backupAuthorityKeyId",
    "backupSetId",
    "backupTrustPolicySha256",
    "envelopeSha256",
    "payloadSha256",
    "sourceTargetCustodianKeyId",
  ]) {
    exactSha256(value[key], label + " " + key);
  }
  if (value.payloadType !== BACKUP_PAYLOAD_TYPE) {
    invalid(label + " payload type is invalid.");
  }
  exactTimestamp(value.issuedAt, label + " issue time");
  exactTimestamp(value.expiresAt, label + " expiry");
  return value;
}

function exactPhaseBChallenge(value, label) {
  exactObject(value, label, [
    "challengeId",
    "consumerJob",
    "consumerJobWorkflowSha",
    "consumerRepository",
    "consumerRunAttempt",
    "consumerRunId",
    "consumerWorkflowPath",
    "expiresAt",
    "issuedAt",
    "maxAgeSeconds",
    "nonce",
    "replayDomain",
  ]);
  exactSha256(value.challengeId, label + " ID");
  exactRepository(value.consumerRepository, label + " consumer repository");
  exactWorkflowPath(value.consumerWorkflowPath, label + " consumer workflow");
  exactGitSha(value.consumerJobWorkflowSha, label + " consumer workflow SHA");
  exactJobName(value.consumerJob, label + " consumer job");
  exactDecimal(value.consumerRunId, label + " consumer run ID", { positive: true });
  exactInteger(value.consumerRunAttempt, label + " consumer run attempt", 1);
  exactNonce(value.nonce, label + " nonce");
  if (value.replayDomain !== PHASE_B_REPLAY_DOMAIN) {
    invalid(label + " replay domain is invalid.");
  }
  exactInteger(value.maxAgeSeconds, label + " max age", 1, 900);
  const issued = exactTimestamp(value.issuedAt, label + " issue time");
  const expires = exactTimestamp(value.expiresAt, label + " expiry");
  if (
    expires.milliseconds <= issued.milliseconds ||
    expires.milliseconds - issued.milliseconds >
      value.maxAgeSeconds * 1000
  ) {
    invalid(label + " lifetime is invalid.");
  }
  return value;
}

function exactReplayRequirements(value, label, payload) {
  exactObject(value, label, [
    "atomicCreateExclusiveRequired",
    "claimAncestrySha256",
    "claimFileFsyncRequired",
    "claimNegativeLookupReceiptSha256",
    "claimObjectPath",
    "claimParentFsyncRequired",
    "claimParentIdentitySha256",
    "claimParentPath",
    "consumeBeforeFirstNonClaimMutation",
    "failureStateTerminal",
    "journalCreatedExclusiveRequired",
    "journalRecordPath",
    "journalStorePath",
    "ledgerId",
    "priorState",
    "receiptCreatedExclusiveRequired",
    "receiptObjectKeySha256",
    "receiptObjectPath",
    "receiptStorePath",
    "replayKeySha256",
    "schema",
    "status",
  ]);
  const replayKeySha256 = domainSeparatedSha256(
    "phase-b-ledger-v1",
    payload.authorizationId,
    payload.consumerChallenge.nonce,
    payload.transactionId,
    payload.policySha256,
    payload.preinstallTupleSha256,
  );
  const receiptObjectKeySha256 = domainSeparatedSha256(
    "install-receipt-v1",
    payload.preinstallTuple.installPlan.plannedReceiptId,
    payload.transactionId,
  );
  const claimParent = payload.preMutationAncestryVerification.sourceParents
    .find((entry) => entry.path === "/var/lib");
  const claimAncestry = payload.preMutationAncestryVerification.sourceParents
    .slice(0, 3);
  if (
    value.schema !== "platform.v1-phase-b-replay-requirements/v1" ||
    value.ledgerId !== "platform-v1-phase-b-installer-ledger" ||
    value.claimParentPath !== "/var/lib" ||
    claimParent === undefined ||
    value.claimParentIdentitySha256 !== shaCanonical(claimParent) ||
    value.claimAncestrySha256 !== shaCanonical(claimAncestry) ||
    value.replayKeySha256 !== replayKeySha256 ||
    value.claimObjectPath !==
      "/var/lib/.platform-v1-phase-b-claim-" + replayKeySha256 ||
    value.journalStorePath !==
      "/var/lib/platform-infrastructure/v1-phase-b-ledger" ||
    value.journalRecordPath !==
      value.journalStorePath + "/" + replayKeySha256 + ".json" ||
    value.receiptStorePath !==
      "/var/lib/platform-infrastructure/v1-install-receipts/sha256" ||
    value.receiptObjectKeySha256 !== receiptObjectKeySha256 ||
    value.receiptObjectPath !==
      value.receiptStorePath + "/" + receiptObjectKeySha256 + ".json"
  ) invalid(label + " does not use exact domain-separated replay/receipt object paths under the preexisting /var/lib anchor.");
  exactSha256(value.replayKeySha256, label + " replay key SHA256");
  exactSha256(value.receiptObjectKeySha256, label + " receipt object key SHA256");
  exactSha256(value.claimParentIdentitySha256, label + " claim parent identity");
  exactSha256(value.claimAncestrySha256, label + " claim ancestry");
  exactSha256(value.claimNegativeLookupReceiptSha256,
    label + " claim negative lookup receipt");
  for (const key of [
    "claimObjectPath", "claimParentPath", "journalRecordPath",
    "journalStorePath", "receiptObjectPath", "receiptStorePath",
  ]) exactAbsolutePath(value[key], label + " " + key);
  if (
    value.priorState !== "ABSENT_PROVEN" ||
    value.consumeBeforeFirstNonClaimMutation !== true ||
    value.atomicCreateExclusiveRequired !== true ||
    value.claimFileFsyncRequired !== true ||
    value.claimParentFsyncRequired !== true ||
    value.journalCreatedExclusiveRequired !== true ||
    value.receiptCreatedExclusiveRequired !== true ||
    value.failureStateTerminal !== true ||
    value.status !== "EXTERNAL_PENDING"
  ) {
    invalid(label + " is not a fail-closed one-shot replay contract.");
  }
  return value;
}

function phaseBPreinstallEvidenceProjection(payload) {
  return {
    materializationPreconditions: payload.materializationPreconditions,
    materializationTargetPlanSha256: payload.materializationTargetPlanSha256,
    packageInputObservation: payload.packageInputObservation,
    preMutationAncestryVerification:
      payload.preMutationAncestryVerification,
    principalAccountObservation: payload.principalAccountObservation,
    replayClaimPrecondition: payload.replayClaimPrecondition,
    resourceObservation: payload.resourceObservation,
  };
}

function validatePhaseBPayload(payload, policyValue, expected, now) {
  exactObject(payload, "Phase-B PREINSTALL authorization payload", [
    "activationAuthority",
    "authoritativeBackup",
    "authorizationId",
    "consumerChallenge",
    "dataRollbackAuthority",
    "decision",
    "deploymentAuthority",
    "expiresAt",
    "installPlanSha256",
    "installationAuthority",
    "installerBootstrapSha256",
    "issuedAt",
    "materializationPreconditions",
    "materializationTargetPlanSha256",
    "notBefore",
    "operationScope",
    "packageInputObservation",
    "policySha256",
    "preMutationAncestryVerification",
    "preinstallTuple",
    "preinstallTupleSha256",
    "principalAccountObservation",
    "producers",
    "replayClaimPrecondition",
    "replayRequirements",
    "resourceObservation",
    "schema",
    "transactionId",
    "version",
  ]);
  if (
    payload.schema !== AUTHORIZATION_SCHEMA ||
    payload.version !== 1 ||
    payload.decision !== "AUTHORIZE_EXACT_PREINSTALL_ONLY" ||
    payload.installationAuthority !== true ||
    payload.deploymentAuthority !== false ||
    payload.activationAuthority !== false ||
    payload.dataRollbackAuthority !== false
  ) {
    invalid("Phase-B PREINSTALL decision or authority scope is invalid.");
  }
  exactOpaqueIdentifier(payload.authorizationId, "Phase-B authorization ID");
  exactSha256(payload.transactionId, "Phase-B transaction ID");
  exactSha256(payload.policySha256, "Phase-B authorization policy SHA256");
  if (
    payload.policySha256 !== policyValue.artifact.sha256 ||
    payload.policySha256 !== expected.policySha256
  ) {
    invalid("Phase-B authorization policy binding is invalid.");
  }
  validatePreinstallTuple(payload.preinstallTuple);
  validateInstallPlanV2(payload.preinstallTuple.installPlan);
  const sourceTarget = payload.preinstallTuple.sourceTarget;
  const activationTarget = payload.preinstallTuple.activationTarget;
  const additiveHostKeys = [
    "deploymentGid", "deploymentUid", "dockerDaemonId", "endpoint",
    "environment", "host", "machineId", "rootFilesystemIdentitySha256",
    "sshHostKeySha256",
  ];
  if (
    payload.preinstallTuple.strategy !== "ADDITIVE" ||
    payload.preinstallTuple.identityTransition !== null ||
    additiveHostKeys.some((key) => sourceTarget[key] !== activationTarget[key]) ||
    sourceTarget.root === activationTarget.root ||
    sourceTarget.root.startsWith(activationTarget.root + "/") ||
    activationTarget.root.startsWith(sourceTarget.root + "/")
  ) {
    invalid("Phase-B PREINSTALL accepts only the non-destructive ADDITIVE tranche.");
  }
  if (
    !canonicalEqual(
      policyValue.roots.sourceTargetCustodian.producerConstraints,
      targetConstraintProjection(sourceTarget, "sourceTargetCustodian"),
    ) ||
    !canonicalEqual(
      policyValue.roots.activationTargetRoot.producerConstraints,
      targetConstraintProjection(activationTarget, "activationTargetRoot"),
    )
  ) {
    invalid("Phase-B target-root policy constraints differ from the exact ADDITIVE source/activation targets.");
  }
  exactSha256(payload.preinstallTupleSha256, "Phase-B preinstall-tuple SHA256");
  exactSha256(payload.installPlanSha256, "Phase-B install-plan SHA256");
  exactSha256(payload.installerBootstrapSha256, "Phase-B installer-bootstrap SHA256");
  if (
    payload.preinstallTupleSha256 !== shaCanonical(payload.preinstallTuple) ||
    payload.preinstallTupleSha256 !== expected.preinstallTupleSha256 ||
    payload.transactionId !== payload.preinstallTuple.transactionId ||
    payload.transactionId !== expected.transactionId
  ) {
    invalid("Phase-B preinstall tuple/transaction binding is invalid.");
  }
  if (
    payload.preinstallTuple.installPlan.installerBootstrap.trustPolicySha256 !==
      payload.policySha256 ||
    payload.preinstallTuple.installPlan.installerBootstrap.phaseBInstallerFingerprintSha256 !==
      policyValue.roots.phaseBInstaller.keyId ||
    payload.preinstallTuple.installPlan.installerBootstrap.activationTargetRootFingerprintSha256 !==
      policyValue.roots.activationTargetRoot.keyId ||
    payload.installPlanSha256 !== shaCanonical(payload.preinstallTuple.installPlan) ||
    payload.installerBootstrapSha256 !==
      shaCanonical(payload.preinstallTuple.installPlan.installerBootstrap) ||
    policyValue.policy.installPlanSchemaSha256 !==
      expected.installPlanSchemaSha256
  ) {
    invalid("Phase-B bootstrap and install-plan trust-policy/schema pins diverge.");
  }
  exactBackupRef(payload.authoritativeBackup, "Phase-B authoritative backup reference");
  exactObject(payload.operationScope, "Phase-B operation scope", [
    "forbidden",
    "permitted",
  ]);
  exactArray(payload.operationScope.permitted, PERMITTED_OPERATIONS,
    "Phase-B permitted operations");
  exactArray(payload.operationScope.forbidden, FORBIDDEN_OPERATIONS,
    "Phase-B forbidden operations");
  exactPhaseBChallenge(payload.consumerChallenge, "Phase-B consumer challenge");
  validateV1BrownfieldPhaseBPreinstallEvidence(
    phaseBPreinstallEvidenceProjection(payload),
    payload.preinstallTuple,
  );
  exactReplayRequirements(
    payload.replayRequirements,
    "Phase-B replay requirements",
    payload,
  );
  const replayClaim = payload.replayClaimPrecondition;
  const replayRequirements = payload.replayRequirements;
  if (
    replayRequirements.replayKeySha256 !==
      replayClaim.ledgerEntryKeySha256 ||
    replayRequirements.claimParentPath !== replayClaim.ledgerParentPath ||
    replayRequirements.claimParentIdentitySha256 !==
      replayClaim.ledgerParentIdentitySha256 ||
    replayRequirements.claimAncestrySha256 !==
      replayClaim.ledgerAncestrySha256 ||
    replayRequirements.claimObjectPath !== replayClaim.claimObjectPath ||
    replayRequirements.claimNegativeLookupReceiptSha256 !==
      replayClaim.claimNegativeLookupReceiptSha256 ||
    replayRequirements.atomicCreateExclusiveRequired !==
      replayClaim.atomicCreateExclusiveRequired ||
    replayRequirements.claimFileFsyncRequired !==
      replayClaim.claimFileFsyncRequired ||
    replayRequirements.claimParentFsyncRequired !==
      replayClaim.claimParentFsyncRequired
  ) {
    invalid("Phase-B replay requirements do not bind the canonical atomic claim precondition.");
  }
  const dynamicMutationPaths = [
    replayRequirements.claimObjectPath,
    replayRequirements.journalStorePath,
    replayRequirements.journalRecordPath,
    replayRequirements.receiptStorePath,
    replayRequirements.receiptObjectPath,
  ];
  if (dynamicMutationPaths.some((pathname) =>
    pathsOverlap(sourceTarget.root, pathname))) {
    invalid("Phase-B dynamic replay paths overlap the preserved source root.");
  }
  exactObject(payload.producers, "Phase-B authorization producers", [
    "activationTargetRoot",
    "phaseBInstaller",
  ]);
  exactProducer(
    payload.producers.phaseBInstaller,
    "phaseBInstaller",
    policyValue.roots.phaseBInstaller,
  );
  exactProducer(
    payload.producers.activationTargetRoot,
    "activationTargetRoot",
    policyValue.roots.activationTargetRoot,
  );
  if (
    payload.authorizationId !== expected.authorizationId ||
    payload.consumerChallenge.nonce !== expected.challengeNonce
  ) {
    invalid("Phase-B authorization ID or challenge nonce differs from the caller binding.");
  }
  const issued = exactTimestamp(payload.issuedAt, "Phase-B authorization issue time");
  const notBefore = exactTimestamp(payload.notBefore, "Phase-B authorization not-before");
  const expires = exactTimestamp(payload.expiresAt, "Phase-B authorization expiry");
  const challengeIssued = exactTimestamp(
    payload.consumerChallenge.issuedAt,
    "Phase-B challenge issue time",
  );
  const challengeExpires = exactTimestamp(
    payload.consumerChallenge.expiresAt,
    "Phase-B challenge expiry",
  );
  const backupIssued = exactTimestamp(
    payload.authoritativeBackup.issuedAt,
    "authoritative backup issue time",
  );
  const backupExpires = exactTimestamp(
    payload.authoritativeBackup.expiresAt,
    "authoritative backup expiry",
  );
  const installerApproval = exactTimestamp(
    payload.producers.phaseBInstaller.approvalEvidenceIssuedAt,
    "Phase-B installer approval",
  );
  const targetAttested = exactTimestamp(
    payload.producers.activationTargetRoot.attestedAt,
    "activation-target-root attestation",
  );
  const filesystemObserved = exactTimestamp(
    payload.preMutationAncestryVerification.verifiedAt,
    "Phase-B pre-mutation filesystem observation",
  );
  const signedObservationTimes = [
    installerApproval,
    targetAttested,
    filesystemObserved,
    exactTimestamp(payload.packageInputObservation.verifiedAt,
      "Phase-B package-input observation"),
    exactTimestamp(payload.principalAccountObservation.verifiedAt,
      "Phase-B principal/account observation"),
    exactTimestamp(payload.resourceObservation.observedAt,
      "Phase-B resource observation"),
    exactTimestamp(payload.replayClaimPrecondition.verifiedAt,
      "Phase-B replay-claim precondition observation"),
    ...payload.materializationPreconditions.map((precondition, index) =>
      exactTimestamp(precondition.verifiedAt,
        "Phase-B materialization precondition " + String(index))),
  ];
  const maxLifetime =
    policyValue.policy.freshness.maxLifetimeSeconds * 1000;
  const skew = policyValue.policy.freshness.maxClockSkewSeconds * 1000;
  if (
    issued.value !== notBefore.value ||
    expires.milliseconds <= issued.milliseconds ||
    expires.milliseconds - issued.milliseconds > maxLifetime ||
    backupIssued.milliseconds > challengeIssued.milliseconds ||
    signedObservationTimes.some((observation) =>
      observation.milliseconds < challengeIssued.milliseconds ||
      observation.milliseconds > issued.milliseconds) ||
    filesystemObserved.milliseconds !== targetAttested.milliseconds ||
    installerApproval.milliseconds > targetAttested.milliseconds ||
    issued.milliseconds > challengeExpires.milliseconds ||
    expires.milliseconds > challengeExpires.milliseconds ||
    expires.milliseconds > backupExpires.milliseconds ||
    now >= challengeExpires.milliseconds ||
    now >= backupExpires.milliseconds ||
    now >= expires.milliseconds ||
    now + skew < issued.milliseconds ||
    now + skew < challengeIssued.milliseconds
  ) {
    invalid("Phase-B backup/challenge/approval/target/authorization timestamps or freshness are invalid.");
  }
  if (
    payload.consumerChallenge.nonce ===
      payload.preinstallTuple.phaseA.nonce ||
    payload.consumerChallenge.challengeId ===
      payload.preinstallTuple.transactionId
  ) {
    invalid("Phase-B replay identifiers must be distinct from Phase-A and transaction identities.");
  }
  return payload;
}

function validateExpected(expected) {
  exactObject(expected, "Phase-B expected caller bindings", [
    "authorizationId",
    "backupAttestationEnvelopeSha256",
    "challengeNonce",
    "installPlanSchemaSha256",
    "phaseAAuthorizationEnvelopeSha256",
    "phaseAPackageEnvelopeSha256",
    "phaseAPolicySha256",
    "phaseBPreinstallEnvelopeSha256",
    "policySha256",
    "preinstallTupleSha256",
    "roleKeyIds",
    "schema",
    "transactionId",
  ]);
  if (expected.schema !== EXPECTED_SCHEMA) {
    invalid("Phase-B expected caller binding schema is invalid.");
  }
  exactOpaqueIdentifier(expected.authorizationId, "expected Phase-B authorization ID");
  exactNonce(expected.challengeNonce, "expected Phase-B challenge nonce");
  exactSha256(expected.installPlanSchemaSha256, "expected install-plan schema SHA256");
  exactSha256(expected.phaseAPolicySha256, "expected Phase-A policy SHA256");
  exactSha256(expected.phaseAPackageEnvelopeSha256,
    "expected Phase-A package envelope SHA256");
  exactSha256(expected.phaseAAuthorizationEnvelopeSha256,
    "expected Phase-A authorization envelope SHA256");
  exactSha256(expected.backupAttestationEnvelopeSha256,
    "expected authoritative backup envelope SHA256");
  exactSha256(expected.phaseBPreinstallEnvelopeSha256,
    "expected Phase-B PREINSTALL envelope SHA256");
  exactSha256(expected.policySha256, "expected Phase-B policy SHA256");
  exactSha256(expected.preinstallTupleSha256, "expected Phase-B tuple SHA256");
  exactSha256(expected.transactionId, "expected Phase-B transaction ID");
  exactObject(expected.roleKeyIds, "expected Phase-B role key map", ROLE_NAMES);
  const keys = ROLE_NAMES.map((role) =>
    exactSha256(expected.roleKeyIds[role], "expected " + role + " key ID")
  );
  assertDistinct(keys, "expected cross-contract role keys");
  return expected;
}

export function verifyV1PhaseBPreinstallAuthorization({
  policyArtifact,
  phaseAPolicyArtifact,
  phaseAPackageArtifact,
  phaseAAuthorizationArtifact,
  backupAttestationArtifact,
  authorizationArtifact,
  expected,
  now = Date.now(),
}) {
  if (!Number.isFinite(now)) invalid("Phase-B verification clock is invalid.");
  const expectedValue = validateExpected(expected);
  const policyValue = validatePolicy(policyArtifact, expectedValue);
  const phaseAPolicyValue = validatePhaseAPolicyArtifact(
    phaseAPolicyArtifact,
    expectedValue,
    policyValue,
  );

  const phaseAPackage = verifyEnvelope(phaseAPackageArtifact, {
    label: "Phase-A package attestation",
    payloadType: PHASE_A_PACKAGE_PAYLOAD_TYPE,
    signers: [policyValue.roots.packageAttestor],
  });
  const phaseAAuthorization = verifyEnvelope(phaseAAuthorizationArtifact, {
    label: "Phase-A read-only authorization",
    payloadType: PHASE_A_AUTHORIZATION_PAYLOAD_TYPE,
    signers: [policyValue.roots.phaseAAuthorizationProvider],
  });
  if (
    phaseAAuthorization.payload.packageAttestationEnvelopeSha256 !==
      phaseAPackage.artifact.sha256 ||
    !canonicalEqual(
      phaseAAuthorization.payload.candidate,
      phaseAPackage.payload.candidate,
    ) ||
    !canonicalEqual(
      phaseAAuthorization.payload.target,
      phaseAPackage.payload.target,
    ) ||
    !canonicalEqual(
      phaseAAuthorization.payload.twoPhaseOrderContract,
      phaseAPackage.payload.twoPhaseOrderContract,
    ) ||
    !canonicalEqual(
      phaseAAuthorization.payload.consumerChallenge,
      phaseAPackage.payload.consumerChallenge,
    )
  ) {
    invalid("Phase-A package and authorization raw envelopes do not share one exact context.");
  }
  if (
    phaseAPackage.artifact.sha256 !==
      expectedValue.phaseAPackageEnvelopeSha256 ||
    phaseAAuthorization.artifact.sha256 !==
      expectedValue.phaseAAuthorizationEnvelopeSha256
  ) {
    invalid("Raw Phase-A envelope SHA256 differs from the caller-supplied pins.");
  }
  const phaseB = verifyEnvelope(authorizationArtifact, {
    label: "Phase-B PREINSTALL authorization",
    payloadType: PHASE_B_PREINSTALL_PAYLOAD_TYPE,
    signers: [
      policyValue.roots.phaseBInstaller,
      policyValue.roots.activationTargetRoot,
    ],
  });
  validatePhaseBPayload(phaseB.payload, policyValue, expectedValue, now);
  if (phaseB.artifact.sha256 !== expectedValue.phaseBPreinstallEnvelopeSha256) {
    invalid("Phase-B PREINSTALL envelope SHA256 differs from the caller-supplied pin.");
  }
  const tuple = phaseB.payload.preinstallTuple;
  const phaseAVerification = verifyV1PhaseAAuthorization({
    policyArtifact: phaseAPolicyArtifact,
    packageAttestationArtifact: phaseAPackageArtifact,
    authorizationArtifact: phaseAAuthorizationArtifact,
    expected: {
      policySha256: phaseAPolicyValue.artifact.sha256,
      packageAttestorKeyId: policyValue.roots.packageAttestor.keyId,
      authorizationProviderKeyId:
        policyValue.roots.phaseAAuthorizationProvider.keyId,
      candidate: phaseAPackage.payload.candidate,
      target: phaseAPackage.payload.target,
      consumerChallenge: phaseAPackage.payload.consumerChallenge,
      twoPhaseOrderContract: phaseAPackage.payload.twoPhaseOrderContract,
    },
    now: Date.parse(tuple.phaseA.verifiedAt),
  });
  const expectedPhaseAVerification = {
    schema: "platform.v1-phase-a-verification/v1",
    status: "SIGNATURE_VERIFIED_NON_AUTHORITATIVE",
    authoritativeEvidence: false,
    callerSuppliedTrustAnchors: true,
    readOnlyLivePreflightOnly: true,
    localMutationAuthority: false,
    deploymentAuthorized: false,
    replayLedgerStatus: "EXTERNAL_PENDING",
    packageMaterializationStatus: "EXTERNAL_PENDING",
    packageMaterializationVerified: false,
    policySha256: phaseAPolicyValue.artifact.sha256,
    packageAttestationEnvelopeSha256: phaseAPackage.artifact.sha256,
    authorizationEnvelopeSha256: phaseAAuthorization.artifact.sha256,
    candidate: phaseAPackage.payload.candidate,
    target: phaseAPackage.payload.target,
    consumerChallengeSha256:
      shaCanonical(phaseAPackage.payload.consumerChallenge),
    permittedOperations: PHASE_A_PERMITTED_OPERATIONS,
    forbiddenOperations: PHASE_A_FORBIDDEN_OPERATIONS,
  };
  if (!canonicalEqual(phaseAVerification, expectedPhaseAVerification)) {
    invalid("Raw Phase-A verifier did not return its historical fail-closed verified state.");
  }

  if (
    tuple.phaseA.policySha256 !== phaseAPolicyValue.artifact.sha256 ||
    tuple.phaseA.packageAttestationEnvelopeSha256 !==
      phaseAPackage.artifact.sha256 ||
    tuple.phaseA.packageAttestationId !==
      phaseAPackage.payload.attestationId ||
    tuple.phaseA.packageAttestorKeyId !==
      policyValue.roots.packageAttestor.keyId ||
    tuple.phaseA.authorizationEnvelopeSha256 !==
      phaseAAuthorization.artifact.sha256 ||
    tuple.phaseA.authorizationId !==
      phaseAAuthorization.payload.authorizationId ||
    tuple.phaseA.authorizationProviderKeyId !==
      policyValue.roots.phaseAAuthorizationProvider.keyId ||
    tuple.phaseA.packagePayloadType !== PHASE_A_PACKAGE_PAYLOAD_TYPE ||
    tuple.phaseA.authorizationPayloadType !==
      PHASE_A_AUTHORIZATION_PAYLOAD_TYPE ||
    tuple.phaseA.scope !== "READ_ONLY_LIVE_PREFLIGHT" ||
    tuple.phaseA.candidateClean !== true ||
    tuple.phaseA.packageSha256 !==
      phaseAAuthorization.payload.candidate.packageSha256 ||
    tuple.phaseA.packageManifestSha256 !==
      phaseAAuthorization.payload.candidate.packageManifestSha256 ||
    tuple.phaseA.issuedAt !== phaseAAuthorization.payload.issuedAt ||
    tuple.phaseA.expiresAt !== phaseAAuthorization.payload.expiresAt ||
    tuple.phaseA.orderContractId !==
      phaseAAuthorization.payload.twoPhaseOrderContract.id ||
    tuple.phaseA.orderContractSha256 !==
      phaseAAuthorization.payload.twoPhaseOrderContract.sha256 ||
    tuple.phaseA.consumerChallengeSha256 !==
      shaCanonical(phaseAAuthorization.payload.consumerChallenge) ||
    tuple.phaseA.nonce !== phaseAAuthorization.payload.consumerChallenge.nonce ||
    !canonicalEqual(tuple.phaseA.futureRoleKeyIds,
      phaseAPolicyValue.futureMap) ||
    !canonicalEqual(
      tuple.phaseA.authorizedCandidate,
      phaseAAuthorization.payload.candidate,
    ) ||
    tuple.phaseA.authorizedCandidateSha256 !==
      shaCanonical(phaseAAuthorization.payload.candidate) ||
    !canonicalEqual(
      tuple.phaseA.authorizedTarget,
      phaseAAuthorization.payload.target,
    ) ||
    tuple.phaseA.authorizedTargetSha256 !==
      shaCanonical(phaseAAuthorization.payload.target) ||
    !canonicalEqual(tuple.candidate, {
      repository: phaseAAuthorization.payload.candidate.repository,
      repositoryId: phaseAAuthorization.payload.candidate.repositoryId,
      repositoryOwnerId:
        phaseAAuthorization.payload.candidate.repositoryOwnerId,
      commitSha: phaseAAuthorization.payload.candidate.commitSha,
      treeSha: phaseAAuthorization.payload.candidate.treeSha,
      sourceArchiveSha256:
        phaseAAuthorization.payload.candidate.sourceArchiveSha256,
    }) ||
    tuple.activationTarget.host !== phaseAAuthorization.payload.target.hostname ||
    tuple.activationTarget.endpoint !== phaseAAuthorization.payload.target.endpoint ||
    tuple.activationTarget.root !== phaseAAuthorization.payload.target.targetRoot ||
    tuple.activationTarget.sshHostKeySha256 !==
      phaseAAuthorization.payload.target.sshHostKeySha256 ||
    tuple.activationTarget.dockerDaemonId !==
      phaseAAuthorization.payload.target.dockerDaemonId ||
    tuple.activationTarget.machineId !==
      phaseAAuthorization.payload.target.machineIdentitySha256 ||
    tuple.activationTarget.rootFilesystemIdentitySha256 !==
      phaseAAuthorization.payload.target.rootFilesystemIdentitySha256 ||
    tuple.activationTarget.deploymentUid !==
      phaseAAuthorization.payload.target.deploymentUid ||
    tuple.activationTarget.deploymentGid !==
      phaseAAuthorization.payload.target.deploymentGid
  ) {
    invalid("Phase-B tuple does not bind the exact raw Phase-A artifacts.");
  }
  const providerConstraints = [...EXTERNAL_ROLES].map((role) =>
    policyValue.roots[role].producerConstraints);
  if (providerConstraints.some((producer) =>
    producer.repository.toLowerCase() === tuple.candidate.repository ||
    producer.repositoryId === tuple.candidate.repositoryId ||
    producer.repositoryOwnerId === tuple.candidate.repositoryOwnerId)) {
    invalid("Independent provider roles cannot be candidate-repository controlled.");
  }

  const backup = verifyEnvelope(backupAttestationArtifact, {
    label: "authoritative backup attestation",
    payloadType: BACKUP_PAYLOAD_TYPE,
    signers: [
      policyValue.roots.backupAuthority,
      policyValue.roots.sourceTargetCustodian,
    ],
  });
  if (backup.artifact.sha256 !== expectedValue.backupAttestationEnvelopeSha256) {
    invalid("Raw backup envelope SHA256 differs from the caller-supplied pin.");
  }
  validateBackupPayload(
    backup.payload,
    policyValue.roots,
    tuple,
    phaseB.payload.preinstallTupleSha256,
    policyValue.policy.backupTrustPolicySha256,
    policyValue.policy.freshness,
    now,
  );
  const backupRef = phaseB.payload.authoritativeBackup;
  if (
    backupRef.envelopeSha256 !== backup.artifact.sha256 ||
    backupRef.payloadSha256 !== backup.payloadSha256 ||
    backupRef.attestationId !== backup.payload.attestationId ||
    backupRef.backupSetId !==
      tuple.authoritativeBackupAttestation.backupSetId ||
    backupRef.backupTrustPolicySha256 !==
      policyValue.policy.backupTrustPolicySha256 ||
    backupRef.backupAuthorityKeyId !==
      policyValue.roots.backupAuthority.keyId ||
    backupRef.sourceTargetCustodianKeyId !==
      policyValue.roots.sourceTargetCustodian.keyId ||
    backupRef.issuedAt !== backup.payload.issuedAt ||
    backupRef.expiresAt !== backup.payload.expiresAt
  ) {
    invalid("Phase-B authorization does not bind the exact raw backup envelope.");
  }
  assertDistinct(
    [
      phaseAPackage.artifact.sha256,
      phaseAAuthorization.artifact.sha256,
      backup.artifact.sha256,
      phaseB.artifact.sha256,
    ],
    "Phase-A, backup, and Phase-B raw envelope hashes",
  );
  assertDistinct(
    [
      phaseAPackage.payload.attestationId,
      phaseAAuthorization.payload.authorizationId,
      tuple.transactionId,
      backup.payload.attestationId,
      tuple.authoritativeBackupAttestation.backupSetId,
      phaseB.payload.authorizationId,
      phaseB.payload.consumerChallenge.challengeId,
    ],
    "Phase-A, backup, transaction, and Phase-B replay identifiers",
  );
  const externalProducers = [
    phaseAPackage.payload.producer,
    phaseAAuthorization.payload.producer,
    backup.payload.producers.backupAuthority,
    phaseB.payload.producers.phaseBInstaller,
  ];
  assertDistinct(
    externalProducers.map((producer) => [
      producer.repository,
      producer.workflowPath,
      producer.runId,
      String(producer.runAttempt),
    ].join("|")),
    "package, Phase-A, backup, and Phase-B producer runs",
  );
  assertDistinct(
    externalProducers.map((producer) => producer.approvalEvidenceIdentity),
    "package, Phase-A, backup, and Phase-B approval identities",
  );

  return deepFreeze({
    schema: VALIDATION_SCHEMA,
    status: "SIGNATURE_VERIFIED_NON_AUTHORITATIVE",
    authoritativeEvidence: false,
    callerSuppliedTrustAnchors: true,
    localMutationAuthority: false,
    installationAuthorized: false,
    deploymentAuthorized: false,
    activationAuthorized: false,
    dataRollbackAuthorized: false,
    replayLedgerStatus: "EXTERNAL_PENDING",
    replayVerified: false,
    phaseAHistoricalReplayReceiptAuthenticationStatus: "EXTERNAL_PENDING",
    phaseAHistoricalReplayReceiptAuthenticated: false,
    packageMaterializationStatus: "EXTERNAL_PENDING",
    packageMaterializationVerified: false,
    rawBaselineVerificationStatus: EXTERNAL_ROOT_CONSUMER_REQUIRED,
    rawBackupReceiptVerificationStatus: EXTERNAL_ROOT_CONSUMER_REQUIRED,
    sourceSetRecomputationStatus: EXTERNAL_ROOT_CONSUMER_REQUIRED,
    offHostSourceDeviceExclusionVerificationStatus:
      EXTERNAL_ROOT_CONSUMER_REQUIRED,
    restoredCoverageRecomputationStatus: EXTERNAL_ROOT_CONSUMER_REQUIRED,
    databaseCoverageRecomputationStatus: EXTERNAL_ROOT_CONSUMER_REQUIRED,
    protectedPathOverlapVerificationStatus:
      EXTERNAL_ROOT_CONSUMER_REQUIRED,
    packageArchiveFormatVerificationStatus:
      EXTERNAL_ROOT_CONSUMER_REQUIRED,
    packageManifestMemberExtractionVerificationStatus:
      EXTERNAL_ROOT_CONSUMER_REQUIRED,
    replayArtifactByteSchemaVerificationStatus:
      EXTERNAL_ROOT_CONSUMER_REQUIRED,
    consumerChallengeAuthorityStatus: EXTERNAL_ROOT_CONSUMER_REQUIRED,
    expectedBindingsAuthorityStatus: EXTERNAL_ROOT_CONSUMER_REQUIRED,
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
    sourceDeviceSetSha256: tuple.baseline.sourceDeviceSetSha256,
    sourceDeviceCount: tuple.baseline.sourceDeviceCount,
    sourceDeviceIdentitiesComplete:
      tuple.baseline.sourceDeviceIdentitiesComplete,
    preMutationFilesystemObservationStatus:
      "SIGNATURE_BOUND_NON_AUTHORITATIVE",
    preMutationFilesystemObservationReceiptSha256:
      phaseB.payload.preMutationAncestryVerification.verificationReceiptSha256,
    preMutationFilesystemRuntimeRecheckStatus: "EXTERNAL_PENDING",
    preMutationFilesystemRuntimeRecheckVerified: false,
    runtimeBootstrapTrustStatus: "EXTERNAL_PENDING",
    runtimeBootstrapTrustVerified: false,
    effect: "STOP",
    policySha256: policyValue.artifact.sha256,
    preinstallTupleSha256: phaseB.payload.preinstallTupleSha256,
    phaseAPackageEnvelopeSha256: phaseAPackage.artifact.sha256,
    phaseAAuthorizationEnvelopeSha256:
      phaseAAuthorization.artifact.sha256,
    backupAttestationEnvelopeSha256: backup.artifact.sha256,
    phaseBPreinstallEnvelopeSha256: phaseB.artifact.sha256,
    transactionId: tuple.transactionId,
    authorizationId: phaseB.payload.authorizationId,
    permittedOperations: PERMITTED_OPERATIONS,
    forbiddenOperations: FORBIDDEN_OPERATIONS,
  });
}

const CLI_KEYS = Object.freeze([
  "authorization",
  "backup-attestation",
  "expected",
  "phase-a-authorization",
  "phase-a-package-attestation",
  "phase-a-policy",
  "policy",
]);

function usage() {
  return (
    "Usage: v1-phase-b-preinstall-authorization.mjs " +
    CLI_KEYS.map((key) => "--" + key + " FILE").join(" ")
  );
}

function parseArgs(values) {
  if (values.length !== CLI_KEYS.length * 2) invalid(usage());
  const options = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (
      typeof flag !== "string" ||
      !flag.startsWith("--") ||
      typeof value !== "string" ||
      !value ||
      value.startsWith("--") ||
      Object.hasOwn(options, flag.slice(2))
    ) {
      invalid(usage());
    }
    options[flag.slice(2)] = value;
  }
  if (!canonicalEqual(Object.keys(options).sort(), [...CLI_KEYS].sort())) {
    invalid(usage());
  }
  return options;
}

function readBoundedDescriptor(descriptor, boundaryBytes, label) {
  const chunks = [];
  let totalBytes = 0;
  while (totalBytes < boundaryBytes) {
    const chunk = Buffer.allocUnsafe(
      Math.min(64 * 1024, boundaryBytes - totalBytes),
    );
    const bytesRead = fs.readSync(descriptor, chunk, 0, chunk.length, null);
    if (bytesRead === 0) return Buffer.concat(chunks, totalBytes);
    chunks.push(chunk.subarray(0, bytesRead));
    totalBytes += bytesRead;
  }
  invalid(label + " grew beyond the accepted size boundary while it was read.");
}

function snapshotFile(filename, label) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) {
    invalid(label + " path must be explicitly absolute.");
  }
  const pathname = path.resolve(filename);
  if (pathname !== filename) invalid(label + " path must be canonical.");
  let initial;
  try {
    initial = fs.lstatSync(pathname, { bigint: true });
  } catch (error) {
    invalid(label + " safe capture failed: " + String(error?.message ?? error));
  }
  if (
    !initial.isFile() ||
    initial.isSymbolicLink() ||
    initial.nlink !== 1n ||
    initial.size < 3n ||
    initial.size > BigInt(MAX_ARTIFACT_BYTES)
  ) {
    invalid(label + " must be one bounded regular non-symlink singly linked file.");
  }
  if (
    typeof fs.constants.O_NOFOLLOW !== "number" ||
    typeof fs.constants.O_NONBLOCK !== "number"
  ) {
    invalid(label + " O_NOFOLLOW/O_NONBLOCK is unavailable.");
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      pathname,
      fs.constants.O_RDONLY |
        fs.constants.O_NOFOLLOW |
        fs.constants.O_NONBLOCK,
    );
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.dev !== initial.dev ||
      before.ino !== initial.ino ||
      before.size !== initial.size ||
      before.mtimeNs !== initial.mtimeNs ||
      before.ctimeNs !== initial.ctimeNs
    ) {
      invalid(label + " changed before safe capture.");
    }
    const bytes = readBoundedDescriptor(
      descriptor,
      MAX_ARTIFACT_BYTES + 1,
      label,
    );
    const after = fs.fstatSync(descriptor, { bigint: true });
    const finalPath = fs.lstatSync(pathname, { bigint: true });
    if (
      BigInt(bytes.length) !== before.size ||
      !after.isFile() ||
      after.nlink !== 1n ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs ||
      finalPath.dev !== before.dev ||
      finalPath.ino !== before.ino ||
      finalPath.size !== before.size ||
      finalPath.mtimeNs !== before.mtimeNs ||
      finalPath.ctimeNs !== before.ctimeNs
    ) {
      invalid(label + " changed during safe capture.");
    }
    return Object.freeze({ bytes });
  } catch (error) {
    invalid(label + " safe O_NOFOLLOW capture failed: " + String(error?.message ?? error));
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const expectedArtifact = exactArtifact(
    snapshotFile(options.expected, "Phase-B expected bindings"),
    "Phase-B expected bindings",
  );
  const result = verifyV1PhaseBPreinstallAuthorization({
    policyArtifact: snapshotFile(options.policy, "Phase-B policy"),
    phaseAPolicyArtifact: snapshotFile(
      options["phase-a-policy"],
      "Phase-A policy",
    ),
    phaseAPackageArtifact: snapshotFile(
      options["phase-a-package-attestation"],
      "Phase-A package attestation",
    ),
    phaseAAuthorizationArtifact: snapshotFile(
      options["phase-a-authorization"],
      "Phase-A read-only authorization",
    ),
    backupAttestationArtifact: snapshotFile(
      options["backup-attestation"],
      "authoritative backup attestation",
    ),
    authorizationArtifact: snapshotFile(
      options.authorization,
      "Phase-B PREINSTALL authorization",
    ),
    expected: expectedArtifact.document,
  });
  process.stdout.write(canonicalJson(result) + "\n");
  process.exitCode = 78;
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(String(error?.message ?? error) + "\n");
    process.exitCode = 1;
  }
}
