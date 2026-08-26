// Greenfield auth/bootstrap planner for V1 LOCAL_PRIVATE GREENFIELD.
//
// Offline planning/preflight ONLY: this module never contacts servers, Docker,
// or Keycloak. Every Docker-dependent check either fails closed (render
// unavailable -> violations) or is executor-injected (the returned CLI
// invocation for scripts/keycloak-passkey-reconcile.mjs is spawned by the
// operator, not by this module).
//
// Ground truth:
//   - control-center/first-configuration/config.mjs (mode required|disabled,
//     bootstrap token >=43 chars, keycloak client secret >=24 chars,
//     CONTROL_CENTER_MIN_PASSKEYS pinned bounded 2..2, flow
//     platform-passkey-browser, owner role owner, LOCAL_PRIVATE restriction)
//   - compose.local-private.yaml CONTROL_CENTER_FIRST_CONFIGURATION_* env
//     wiring + first-configuration secret files
//   - scripts/keycloak-passkey-reconcile.mjs (confirmations
//     RECONCILE-PLATFORM-PASSKEY-STAGED / BIND-PLATFORM-PASSKEY-BROWSER;
//     brownfield default container enterprise-keycloak -> greenfield
//     equivalent gf-keycloak)
//   - scripts/greenfield-namespace.mjs (gf- prefix authority)
//
// Secret VALUES are never read, printed, logged, exported, or embedded
// anywhere in this module, its outputs, or its receipts. Only sizes and
// caller-supplied digests cross this boundary.

import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  greenfieldContainerName,
  isBrownfieldOwnedPhysicalName,
} from "./greenfield-namespace.mjs";

export const SCHEMA = "platform.greenfield-auth-bootstrap/v1";

export const BOOTSTRAP_TOKEN_MIN_LENGTH = 43;
export const KEYCLOAK_CLIENT_SECRET_MIN_LENGTH = 24;

export const GF_CONTROL_CENTER_CONTAINER = greenfieldContainerName("control-center");
export const GF_KEYCLOAK_CONTAINER = greenfieldContainerName("keycloak");

// Greenfield physical secrets root (matches the greenfield secret projection
// target tree). First-configuration material must be declared in the render as
// files under this root.
export const GREENFIELD_SECRETS_ROOT = "/srv/platform-infrastructure/greenfield/secrets";

export const FIRST_CONFIGURATION_SECRET_LOGICAL_NAMES = Object.freeze([
  "control_center_first_configuration_bootstrap_token",
  "control_center_first_configuration_keycloak_client_secret",
]);

// Container-agnostic mirror of the compose.local-private.yaml
// control-center environment block (lines ~30-45). URL placeholders reference
// auth.<domain>; preflight accepts any non-empty value for these three keys.
export const FIRST_CONFIGURATION_REQUIRED_ENV = Object.freeze({
  CONTROL_CENTER_ENV: "local_private",
  CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "required",
  CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE:
    "/run/secrets/control_center_first_configuration_bootstrap_token",
  CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID: "platform-first-configuration",
  CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE:
    "/run/secrets/control_center_first_configuration_keycloak_client_secret",
  CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME: "admin",
  CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS:
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128",
  CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12,127.0.0.0/8,::1/128",
  CONTROL_CENTER_FIRST_CONFIGURATION_ACCOUNT_URL: "https://auth.<domain>/realms/platform/account/",
  CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_ENDPOINT:
    "https://auth.<domain>/realms/platform/protocol/openid-connect/token",
  CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_BASE_URL: "https://auth.<domain>/admin/realms/platform",
  CONTROL_CENTER_MIN_PASSKEYS: "2",
});

// Keys whose value may be any non-empty string (deployment-owned auth domain).
const URL_FLEXIBLE_ENV_KEYS = new Set([
  "CONTROL_CENTER_FIRST_CONFIGURATION_ACCOUNT_URL",
  "CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_ENDPOINT",
  "CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_BASE_URL",
]);

function fail(message) {
  throw new Error(`Greenfield auth bootstrap: ${message}`);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeEnvironment(rawEnvironment) {
  if (!rawEnvironment) return {};
  if (plainObject(rawEnvironment)) return { ...rawEnvironment };
  if (Array.isArray(rawEnvironment)) {
    const normalized = {};
    for (const entry of rawEnvironment) {
      if (typeof entry !== "string") continue;
      const separator = entry.indexOf("=");
      if (separator < 1) continue;
      normalized[entry.slice(0, separator)] = entry.slice(separator + 1);
    }
    return normalized;
  }
  return {};
}

function environmentViolations(environment, label) {
  const violations = [];
  for (const [key, expected] of Object.entries(FIRST_CONFIGURATION_REQUIRED_ENV)) {
    if (!Object.hasOwn(environment, key)) {
      violations.push(`${label}:env:missing:${key}`);
      continue;
    }
    const actual = environment[key];
    if (URL_FLEXIBLE_ENV_KEYS.has(key)) {
      if (typeof actual !== "string" || actual.trim().length === 0) {
        violations.push(`${label}:env:invalid-url:${key}`);
      }
      continue;
    }
    if (String(actual) !== expected) {
      violations.push(`${label}:env:value:${key}`);
    }
  }
  return violations;
}

function containerNameViolations(serviceDefinition, serviceName, expectedName) {
  const violations = [];
  const containerName = plainObject(serviceDefinition)
    ? serviceDefinition.container_name
    : undefined;
  if (typeof containerName !== "string" || containerName.length === 0) {
    violations.push(`${serviceName}:container-name:missing`);
    return violations;
  }
  if (isBrownfieldOwnedPhysicalName(containerName)) {
    violations.push(`${serviceName}:container-name:brownfield`);
  } else if (containerName !== expectedName) {
    violations.push(`${serviceName}:container-name:not-greenfield`);
  }
  return violations;
}

function secretDeclarationViolations(secretsBlock) {
  const violations = [];
  for (const logicalName of FIRST_CONFIGURATION_SECRET_LOGICAL_NAMES) {
    const declaration = plainObject(secretsBlock) ? secretsBlock[logicalName] : undefined;
    if (!plainObject(declaration) || typeof declaration.file !== "string") {
      violations.push(`secret:${logicalName}:undeclared`);
      continue;
    }
    if (!declaration.file.startsWith(`${GREENFIELD_SECRETS_ROOT}/`)) {
      violations.push(`secret:${logicalName}:file-outside-greenfield-root`);
    }
  }
  return violations;
}

function serviceSecretReferenceViolations(controlCenter) {
  const violations = [];
  const referenced = Array.isArray(controlCenter?.secrets) ? controlCenter.secrets : [];
  for (const logicalName of FIRST_CONFIGURATION_SECRET_LOGICAL_NAMES) {
    if (!referenced.includes(logicalName)) {
      violations.push(`service:control-center:secret-reference-missing:${logicalName}`);
    }
  }
  return violations;
}

function observationViolations(secretsObservation) {
  const violations = [];
  const observations = Array.isArray(secretsObservation) ? secretsObservation : [];
  const minimumLengths = new Map([
    ["control_center_first_configuration_bootstrap_token", BOOTSTRAP_TOKEN_MIN_LENGTH],
    ["control_center_first_configuration_keycloak_client_secret", KEYCLOAK_CLIENT_SECRET_MIN_LENGTH],
  ]);
  for (const logicalName of FIRST_CONFIGURATION_SECRET_LOGICAL_NAMES) {
    const record = observations.find((entry) => plainObject(entry) && entry.logicalName === logicalName);
    if (!record) {
      violations.push(`observation:${logicalName}:absent`);
      continue;
    }
    if (record.present !== true) {
      violations.push(`observation:${logicalName}:not-present`);
    }
    const minimum = minimumLengths.get(logicalName);
    if (typeof record.sizeBytes !== "number" || !Number.isSafeInteger(record.sizeBytes) || record.sizeBytes < 0) {
      violations.push(`observation:${logicalName}:size-missing`);
      continue;
    }
    if (record.sizeBytes < minimum) {
      violations.push(`observation:${logicalName}:size-undersized`);
    }
  }
  return violations;
}

// Fail-closed preflight for the greenfield Control Center First Configuration
// wiring. Empty violations array <=> ready. renderConfig may be null in
// offline unit contexts; every un-verifiable dimension then yields violations.
export function preflightAuthBootstrap({ renderConfig, secretsObservation } = {}) {
  const violations = [];

  if (!plainObject(renderConfig)) {
    violations.push("render:must-be-object");
  } else {
    const services = plainObject(renderConfig.services) ? renderConfig.services : {};

    const controlCenter = services["control-center"];
    if (!plainObject(controlCenter)) {
      violations.push("service:control-center:missing");
    } else {
      violations.push(...containerNameViolations(controlCenter, "control-center", GF_CONTROL_CENTER_CONTAINER));
      violations.push(...environmentViolations(normalizeEnvironment(controlCenter.environment), "control-center"));
      violations.push(...serviceSecretReferenceViolations(controlCenter));
    }

    const keycloak = services.keycloak;
    if (!plainObject(keycloak)) {
      violations.push("service:keycloak:missing");
    } else {
      violations.push(...containerNameViolations(keycloak, "keycloak", GF_KEYCLOAK_CONTAINER));
    }

    violations.push(...secretDeclarationViolations(renderConfig.secrets));
  }

  violations.push(...observationViolations(secretsObservation));

  return Object.freeze({
    schema: SCHEMA,
    ready: violations.length === 0,
    violations: Object.freeze(violations),
  });
}

const SEQUENCE_STEP_DEFS = Object.freeze([
  Object.freeze({
    stepId: "VERIFY_GREENFIELD_RENDER",
    kind: "automated",
    description:
      "Re-run preflightAuthBootstrap against the live greenfield render and confirm zero violations.",
    evidenceRequired: "preflight-violations-empty-report",
  }),
  Object.freeze({
    stepId: "WAIT_HEALTHY_GF_KEYCLOAK",
    kind: "automated",
    description: "Compose healthcheck reports gf-keycloak healthy.",
    evidenceRequired: "gf-keycloak-healthcheck-healthy-output",
  }),
  Object.freeze({
    stepId: "WAIT_HEALTHY_GF_CONTROL_CENTER",
    kind: "automated",
    description: "Compose healthcheck reports gf-control-center healthy.",
    evidenceRequired: "gf-control-center-healthcheck-healthy-output",
  }),
  Object.freeze({
    stepId: "STAGE_FIRST_CONFIGURATION_SECRETS",
    kind: "automated",
    description:
      "Declared compose secrets mount the bootstrap token and Keycloak client secret at /run/secrets inside gf-control-center.",
    evidenceRequired: "compose-secrets-stage-log",
  }),
  Object.freeze({
    stepId: "OPEN_FIRST_CONFIGURATION",
    kind: "automated",
    description: "First-configuration origin answers on the management LAN with mode=required active.",
    evidenceRequired: "first-configuration-open-response",
  }),
  Object.freeze({
    stepId: "ADMIN_CONFIRMED",
    kind: "automated",
    description: "Owner-role administrator identity confirmed at first login (admin username, realm platform).",
    evidenceRequired: "admin-first-login-audit-record",
  }),
  Object.freeze({
    stepId: "ENROLL_PASSKEY_1",
    kind: "human-gate",
    description:
      "Operator enrolls passkey 1 for the admin account through platform-passkey-browser. Checkpoint READY FOR 2 PASSKEYS.",
    evidenceRequired: "passkey-1-webauthn-enrollment-record",
  }),
  Object.freeze({
    stepId: "ENROLL_PASSKEY_2",
    kind: "human-gate",
    description:
      "Operator enrolls passkey 2 (independent authenticator) through platform-passkey-browser. Checkpoint READY FOR 2 PASSKEYS.",
    evidenceRequired: "passkey-2-webauthn-enrollment-record",
  }),
  Object.freeze({
    stepId: "PASSKEYS_READY",
    kind: "automated",
    description: "Keycloak readiness confirms CONTROL_CENTER_MIN_PASSKEYS=2 passkeys enrolled for the admin account.",
    evidenceRequired: "keycloak-passkey-count-2-readiness-line",
  }),
  Object.freeze({
    stepId: "LOGIN_VERIFICATION",
    kind: "automated",
    description: "Post-binding passkey-only browser login verified end to end.",
    evidenceRequired: "post-bind-login-transcript",
  }),
  Object.freeze({
    stepId: "LOGOUT_VERIFICATION",
    kind: "automated",
    description: "Backchannel/front-channel logout verified end to end.",
    evidenceRequired: "logout-verification-transcript",
  }),
  Object.freeze({
    stepId: "REVOCATION_CHECK",
    kind: "automated",
    description: "Revoked or unknown credentials are rejected by the bound browser flow.",
    evidenceRequired: "revocation-rejection-record",
  }),
  Object.freeze({
    stepId: "RESTART_PERSISTENCE_CHECK",
    kind: "automated",
    description: "Restarting gf-keycloak and gf-control-center preserves the flow binding and both passkeys.",
    evidenceRequired: "restart-persistence-record",
  }),
  Object.freeze({
    stepId: "BOOTSTRAP_CLOSURE",
    kind: "automated",
    description: "All prior evidence assembled; bootstrap closure receipt issued and first configuration closed.",
    evidenceRequired: "bootstrap-closure-receipt",
  }),
]);

export const AUTH_BOOTSTRAP_SEQUENCE_STEP_IDS = Object.freeze(
  SEQUENCE_STEP_DEFS.map((step) => step.stepId),
);

export const HUMAN_GATE_STEP_IDS = Object.freeze(
  SEQUENCE_STEP_DEFS.filter((step) => step.kind === "human-gate").map((step) => step.stepId),
);

// Ordered deterministic LIVE-phase sequence. Frozen; exactly two human gates
// (the passkey enrollments, checkpoint READY FOR 2 PASSKEYS).
export function buildAuthBootstrapSequence() {
  return Object.freeze(SEQUENCE_STEP_DEFS.map((step) => Object.freeze({ ...step })));
}

// Deterministic serialization (recursively key-sorted canonical JSON), so two
// builds serialize byte-for-byte identically. Consistent with the sibling
// greenfield-* modules.
export function serializeAuthBootstrapSequence(sequence) {
  return JSON.stringify(canonicalValue(sequence));
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

const RECONCILE_SCRIPT_PATH = resolve(join(dirname(fileURLToPath(import.meta.url)), "keycloak-passkey-reconcile.mjs"));

const RECONCILE_STAGE_CONTRACT = Object.freeze({
  staged: Object.freeze({
    action: "apply-staged",
    confirmation: "RECONCILE-PLATFORM-PASSKEY-STAGED",
    expectBinding: "staged",
  }),
  bind: Object.freeze({
    action: "bind",
    confirmation: "BIND-PLATFORM-PASSKEY-BROWSER",
    expectBinding: "cutover",
  }),
});

// Returns the EXACT CLI invocation for scripts/keycloak-passkey-reconcile.mjs
// against the greenfield runtime. The executor spawns argv with the returned
// env merged over process.env; this module itself never executes anything.
export function keycloakPasskeyReconcileInvocation({ stage } = {}) {
  const contract = plainObject(RECONCILE_STAGE_CONTRACT) ? RECONCILE_STAGE_CONTRACT[stage] : undefined;
  if (!contract) {
    throw new TypeError(`Unknown reconcile stage: ${String(stage)}; expected one of ${Object.keys(RECONCILE_STAGE_CONTRACT).join(", ")}.`);
  }
  return Object.freeze({
    argv: Object.freeze(["node", RECONCILE_SCRIPT_PATH]),
    env: Object.freeze({
      KEYCLOAK_CONTAINER: GF_KEYCLOAK_CONTAINER,
      KEYCLOAK_REALM: "platform",
      KEYCLOAK_PASSKEY_ACTION: contract.action,
      KEYCLOAK_PASSKEY_EXPECT_BINDING: contract.expectBinding,
      KEYCLOAK_PASSKEY_CONFIRM: contract.confirmation,
      CONTROL_CENTER_OIDC_CLIENT_ID: "platform-control-center",
      CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID: "platform-first-configuration",
      CONTROL_CENTER_MIN_PASSKEYS: "2",
      ...(stage === "bind" ? { KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED: "true" } : {}),
    }),
  });
}

function isValidUtcTimestamp(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed);
}

// Fail-closed closure receipt builder. NEVER accepts a run log in which a
// human gate is missing or unevidenced: skipping an enrollment gate can never
// produce BOOTSTRAP_CLOSED (prevents lockout-by-skipping).
export function bootstrapClosureReceipt({ sequenceRunLog } = {}) {
  if (!Array.isArray(sequenceRunLog)) {
    fail("sequenceRunLog must be an array of step records.");
  }

  const sequence = buildAuthBootstrapSequence();
  const recordsByStepId = new Map();
  for (const record of sequenceRunLog) {
    if (!plainObject(record) || typeof record.stepId !== "string" || record.stepId.length === 0) {
      throw new Error("Greenfield auth bootstrap: every run-log record needs a non-empty stepId.");
    }
    if (!recordsByStepId.has(record.stepId)) {
      recordsByStepId.set(record.stepId, []);
    }
    recordsByStepId.get(record.stepId).push(record);
  }

  const violations = [];
  let automatedEvidenceSatisfied = 0;
  let humanGatesRecorded = 0;

  for (const step of sequence) {
    const records = recordsByStepId.get(step.stepId) ?? [];
    recordsByStepId.delete(step.stepId);

    if (records.length > 1) {
      violations.push(`runlog:${step.stepId}:duplicate`);
      continue;
    }
    const record = records[0];

    if (step.kind === "automated") {
      const evidenceDigest = record?.evidenceDigest;
      if (typeof evidenceDigest !== "string" || evidenceDigest.trim().length === 0) {
        violations.push(`evidence:not-satisfied:${step.stepId}`);
        continue;
      }
      automatedEvidenceSatisfied += 1;
      continue;
    }

    const expectedPasskeyIndex = step.stepId.endsWith("_2") ? 2 : 1;
    if (!record) {
      violations.push(`human-gate:${step.stepId}:missing`);
      continue;
    }
    if (record.passkeyIndex !== expectedPasskeyIndex) {
      violations.push(`human-gate:${step.stepId}:passkey-index`);
    }
    if (!isValidUtcTimestamp(record.enrolledAtUtc)) {
      violations.push(`human-gate:${step.stepId}:enrolled-at-invalid`);
      continue;
    }
    humanGatesRecorded += 1;
  }

  for (const unknownStepId of [...recordsByStepId.keys()].sort()) {
    violations.push(`runlog:${unknownStepId}:unknown-step`);
  }

  const closed = violations.length === 0;
  return Object.freeze({
    schema: SCHEMA,
    status: closed ? "BOOTSTRAP_CLOSED" : "BOOTSTRAP_NOT_CLOSED",
    counts: Object.freeze({
      stepsTotal: sequence.length,
      automatedSteps: sequence.filter((step) => step.kind === "automated").length,
      automatedEvidenceSatisfied,
      humanGateSteps: sequence.filter((step) => step.kind === "human-gate").length,
      humanGatesRecorded,
      violations: violations.length,
    }),
    firstConfigurationState: closed ? "COMPLETE" : "INCOMPLETE",
    violations: Object.freeze(violations),
  });
}
