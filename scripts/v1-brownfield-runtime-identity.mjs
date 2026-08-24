#!/usr/bin/env node
/**
 * Verify-only bridge between the non-executable V1 staging namespace, the
 * scheduler cutover description, and the final production Compose identity.
 *
 * This module validates caller-supplied descriptions only. It does not render
 * Compose, inspect Docker, authenticate external observations, execute a
 * cutover, sign evidence, write state, or grant any authority.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const RUNTIME_IDENTITY_SCHEMA = "platform.v1-brownfield-runtime-identity/v1";
export const STAGING_PROJECT_NAME = "platform_infra_v1_control";
export const PRODUCTION_PROJECT_NAME = "platform_infra_vps";

const CANONICAL_UTC_TIMESTAMP =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]\.[0-9]{3}Z$/;

const CANONICAL_COMPOSE_FILE_PREFIX = deepFreeze([
  "compose.yaml",
  "compose.secrets.yaml",
  "compose.waf.yaml",
  "compose.vps.yaml",
  "compose.vps-waf.yaml",
  "compose.backup-scheduler.yaml",
  "compose.runtime.yaml",
  "compose.networks.yaml",
  "compose.runtime-isolation.yaml",
]);

export const CANONICAL_COMPOSE_FILE_ORDER = deepFreeze([
  ...CANONICAL_COMPOSE_FILE_PREFIX,
  "compose.runtime-identity.yaml",
]);

export const LOCAL_PRIVATE_CANONICAL_COMPOSE_FILE_ORDER = deepFreeze([
  ...CANONICAL_COMPOSE_FILE_PREFIX,
  "compose.local-private.yaml",
  "compose.runtime-identity.yaml",
]);

export const CANONICAL_COMPOSE_FILE_ORDERS = deepFreeze({
  VPS: CANONICAL_COMPOSE_FILE_ORDER,
  LOCAL_PRIVATE: LOCAL_PRIVATE_CANONICAL_COMPOSE_FILE_ORDER,
});

const STAGING_SOURCE_FILES = deepFreeze([
  "compose.v1-control-plane.yaml",
  "governance/v1-brownfield-control-plane.json",
  "scripts/v1-brownfield-control-plane-gate.mjs",
]);

const STAGING_SERVICE_NAMES = deepFreeze([
  "docker-action-activation-sidecar",
  "docker-action-broker",
]);

const STAGING_VOLUME_NAMES = deepFreeze([
  "backup_scheduler_jobs",
  "docker_action_activation_cas",
  "docker_action_broker_socket",
  "docker_action_broker_state",
]);

const CONTROL_CENTER_NETWORKS = deepFreeze([
  "platform_routing",
  "platform_db_admin",
  "platform_observability",
  "platform_egress",
]);

export const RUNTIME_SERVICES = deepFreeze([
  {
    service: "docker-action-activation-sidecar",
    containerName: "enterprise-docker-action-activation-sidecar",
    projectName: PRODUCTION_PROJECT_NAME,
    networkMode: "none",
    networkNames: [],
  },
  {
    service: "docker-action-broker",
    containerName: "enterprise-docker-action-broker",
    projectName: PRODUCTION_PROJECT_NAME,
    networkMode: "none",
    networkNames: [],
  },
  {
    service: "backup-scheduler",
    containerName: "enterprise-backup-scheduler",
    projectName: PRODUCTION_PROJECT_NAME,
    networkMode: "none",
    networkNames: [],
  },
  {
    service: "control-center",
    containerName: "enterprise-control-center",
    projectName: PRODUCTION_PROJECT_NAME,
    networkMode: "COMPOSE-NETWORKS",
    networkNames: CONTROL_CENTER_NETWORKS,
  },
]);

export const RUNTIME_VOLUMES = deepFreeze([
  {
    logicalName: "backup_scheduler_jobs",
    physicalName: "platform_infra_vps_backup_scheduler_jobs",
  },
  {
    logicalName: "backup_scheduler_logs",
    physicalName: "platform_infra_vps_backup_scheduler_logs",
  },
  {
    logicalName: "docker_action_activation_cas",
    physicalName: "platform_infra_vps_docker_action_activation_cas",
  },
  {
    logicalName: "docker_action_broker_socket",
    physicalName: "platform_infra_vps_docker_action_broker_socket",
  },
  {
    logicalName: "docker_action_broker_state",
    physicalName: "platform_infra_vps_docker_action_broker_state",
  },
]);

export const QUEUE_OWNERSHIP = deepFreeze([
  {
    service: "control-center",
    containerName: "enterprise-control-center",
    access: "RW",
    source: "backup_scheduler_jobs",
    target: "/var/www/project-state/backup-jobs",
  },
  {
    service: "backup-scheduler",
    containerName: "enterprise-backup-scheduler",
    access: "RW",
    source: "backup_scheduler_jobs",
    target: "/var/www/project-state/backup-jobs",
  },
  {
    service: "docker-action-broker",
    containerName: "enterprise-docker-action-broker",
    access: "RO",
    source: "backup_scheduler_jobs",
    target: "/run/platform/backup-jobs",
  },
]);

const PRODUCTION_SERVICE_NAMES = deepFreeze([
  "alertmanager",
  "backup-scheduler",
  "broker-auth-bootstrap",
  "control-center",
  "docker-action-activation-sidecar",
  "docker-action-broker",
  "grafana",
  "keycloak",
  "loki",
  "mariadb",
  "minio",
  "nats",
  "platform-alert-dispatcher",
  "postgres",
  "project-router",
  "prometheus",
  "promtail",
  "redis",
  "traefik",
  "waf",
]);

const PRODUCTION_NETWORK_NAMES = deepFreeze([
  "platform_bus",
  "platform_cache",
  "platform_db_admin",
  "platform_edge",
  "platform_egress",
  "platform_observability",
  "platform_postgres",
  "platform_routing",
  "platform_storage",
]);

export const PROTECTED_RESOURCE_MAP = deepFreeze({
  configs: ["enterprise_traefik_routes"],
  networks: PRODUCTION_NETWORK_NAMES,
  secrets: [
    "alertmanager_webhook_token",
    "control_center_database_url",
    "control_center_vault_keys",
    "docker_action_backup_catalog",
    "docker_action_backup_job_execute",
    "docker_action_backup_offsite_sync",
    "docker_action_backup_prune_apply",
    "docker_action_backup_prune_plan",
    "docker_action_evidence_runtime_snapshot",
    "docker_action_restore_drill_full",
    "docker_action_runtime_intent_trust_key",
    "grafana_admin_password",
    "keycloak_admin_password",
    "keycloak_db_password",
    "mariadb_root_password",
    "minio_root_password",
    "nats_password",
    "postgres_superuser_password",
    "projects_gateway_signing_keys",
    "redis_password",
    "smtp_password",
  ],
  services: PRODUCTION_SERVICE_NAMES,
  volumes: [
    "backup_scheduler_jobs",
    "backup_scheduler_logs",
    "docker_action_activation_cas",
    "docker_action_broker_socket",
    "docker_action_broker_state",
    "enterprise_alertmanager_data",
    "enterprise_grafana_data",
    "enterprise_keycloak_data",
    "enterprise_loki_data",
    "enterprise_mariadb_data",
    "enterprise_minio_data",
    "enterprise_nats_data",
    "enterprise_postgres_data",
    "enterprise_prometheus_data",
    "enterprise_redis_data",
    "nats_auth_config",
    "redis_auth_config",
  ],
});

export const LOCAL_PRIVATE_PROTECTED_RESOURCE_MAP = deepFreeze({
  ...PROTECTED_RESOURCE_MAP,
  secrets: [
    "alertmanager_webhook_token",
    "control_center_database_url",
    "control_center_first_configuration_bootstrap_token",
    "control_center_first_configuration_keycloak_client_secret",
    "control_center_vault_keys",
    "docker_action_backup_catalog",
    "docker_action_backup_job_execute",
    "docker_action_backup_offsite_sync",
    "docker_action_backup_prune_apply",
    "docker_action_backup_prune_plan",
    "docker_action_evidence_runtime_snapshot",
    "docker_action_restore_drill_full",
    "docker_action_runtime_intent_trust_key",
    "grafana_admin_password",
    "keycloak_admin_password",
    "keycloak_db_password",
    "mariadb_root_password",
    "minio_root_password",
    "nats_password",
    "postgres_superuser_password",
    "projects_gateway_signing_keys",
    "redis_password",
    "smtp_password",
  ],
});

export const PROTECTED_RESOURCE_MAPS = deepFreeze({
  VPS: PROTECTED_RESOURCE_MAP,
  LOCAL_PRIVATE: LOCAL_PRIVATE_PROTECTED_RESOURCE_MAP,
});

export const CURRENT_CONTRACTS = deepFreeze([
  {
    id: "v1-control-plane-staging",
    sourceFiles: [
      "compose.v1-control-plane.yaml",
      "governance/v1-brownfield-control-plane.json",
      "scripts/v1-brownfield-control-plane-gate.mjs",
    ],
    status: "MISMATCH-STOP",
    mismatches: [
      "STAGING-NAMESPACE-NON-EXECUTABLE",
      "STAGING-HAS-FOUR-NOT-FIVE-FINAL-VOLUMES",
      "STAGING-OMITS-FINAL-SCHEDULER-AND-CONTROL-CENTER",
    ],
  },
  {
    id: "scheduler-cutover",
    sourceFiles: ["scripts/v1-brownfield-scheduler-cutover.mjs"],
    status: "MISMATCH-STOP",
    mismatches: [
      "VERIFY-ONLY-DESCRIPTION-NOT-RUNTIME-OBSERVATION",
      "FINAL-CONTAINER-VOLUME-AND-RENDER-CAS-EXTERNAL-PENDING",
    ],
  },
  {
    id: "production-runtime-no-hosted",
    sourceFiles: [
      "scripts/compose-vps.sh",
      "compose.backup-scheduler.yaml",
      "compose.runtime-isolation.yaml",
      "config/no-hosted-workloads.lock.json",
    ],
    status: "MISMATCH-STOP",
    mismatches: [
      "CONTROL-CENTER-MISSING-CANONICAL-QUEUE-VOLUME-MOUNT",
      "RAW-FULL-RENDER-AND-RUNTIME-CAS-EXTERNAL-PENDING",
      "APPLICATION-DATA-PARENT-FIRST-CUTOVER-BINDING-EXTERNAL-PENDING",
    ],
  },
]);

const LEGACY_APPLICATION_DATA_PARENT =
  "/home/platform_infrastructure/platform-infrastructure/projects-portal/state";
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE_REFERENCE = /^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$/;
const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;

const DOCUMENT_KEYS = [
  "schema",
  "documentId",
  "scope",
  "evidenceClass",
  "synthetic",
  "verifyOnly",
  "status",
  "stagingBoundary",
  "schedulerBoundary",
  "productionBoundary",
  "currentContracts",
  "safety",
];

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

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function sameArray(left, right) {
  return Array.isArray(left)
    && left.length === right.length
    && left.every((entry, index) => entry === right[index]);
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    invalid(`${label} must be one lowercase SHA256.`);
  }
  return value;
}

function exactNullableSha256(value, label, pending) {
  if (pending) {
    if (value !== null) invalid(`EXTERNAL-PENDING template ${label} must remain null.`);
    return null;
  }
  return exactSha256(value, label);
}

function exactTimestamp(value, label) {
  if (typeof value !== "string" || !CANONICAL_UTC_TIMESTAMP.test(value)) {
    invalid(`${label} must be a canonical UTC timestamp.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(`${label} must be a canonical UTC timestamp.`);
  }
  return value;
}

function exactVolumeMountpoint(value, expected, label) {
  const escapedPhysicalName = expected.physicalName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `^/(?:(?!\\.{1,2}/)[^/\\u0000]+/)*volumes/${escapedPhysicalName}/_data$`,
    "u",
  );
  if (typeof value !== "string" || !pattern.test(value)) {
    invalid(`${label} does not match its canonical physical identity.`);
  }
  return value;
}

function exactAbsolutePath(value, label) {
  if (typeof value !== "string" || value.includes("\0") || !path.posix.isAbsolute(value)
      || path.posix.normalize(value) !== value || (value.length > 1 && value.endsWith("/"))) {
    invalid(`${label} must be one canonical absolute path.`);
  }
  return value;
}

export function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid("Canonical JSON numbers must be safe integers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    invalid("Canonical JSON accepts only plain JSON values.");
  }
  const keys = Object.keys(value).sort();
  if (keys.some((key) => value[key] === undefined)) {
    invalid("Canonical JSON cannot contain undefined values.");
  }
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function documentPayload(document) {
  const payload = structuredClone(document);
  delete payload.documentId;
  return payload;
}

export function sealRuntimeIdentityDocument(document) {
  exactObject(document, "Runtime identity document", DOCUMENT_KEYS);
  const sealed = structuredClone(document);
  sealed.documentId = sha256Canonical(documentPayload(sealed));
  return sealed;
}

function validateDocumentIdentity(document) {
  exactObject(document, "Runtime identity document", DOCUMENT_KEYS);
  if (document.schema !== RUNTIME_IDENTITY_SCHEMA
      || document.scope !== "platform-infrastructure"
      || document.verifyOnly !== true
      || typeof document.synthetic !== "boolean") {
    invalid("Runtime identity document identity or verify-only boundary is invalid.");
  }
  const pending = document.synthetic === false;
  if (pending) {
    if (document.evidenceClass !== "EXTERNAL-PENDING-TEMPLATE"
        || document.status !== "EXTERNAL-PENDING") {
      invalid("Non-synthetic runtime identity input must remain the EXTERNAL-PENDING template.");
    }
  } else if (document.evidenceClass !== "SYNTHETIC-TEST"
      || document.status !== "SYNTHETIC-COMPLETE-NOT-AUTHORIZED") {
    invalid("Synthetic runtime identity input has an invalid evidence class or status.");
  }
  exactSha256(document.documentId, "Runtime identity document ID");
  if (document.documentId !== sha256Canonical(documentPayload(document))) {
    invalid("Runtime identity document ID does not match its exact closed payload.");
  }
  return pending;
}

function validateStagingBoundary(boundary, pending) {
  exactObject(boundary, "Staging boundary", [
    "projectName",
    "disposition",
    "executionAuthorized",
    "sourceFiles",
    "sourceSetSha256",
    "serviceNames",
    "volumeNames",
  ]);
  if (boundary.projectName !== STAGING_PROJECT_NAME
      || boundary.projectName === PRODUCTION_PROJECT_NAME) {
    invalid("The staging namespace must remain distinct from the final production namespace.");
  }
  if (boundary.disposition !== "NON_EXECUTABLE" || boundary.executionAuthorized !== false) {
    invalid("The staging namespace is NON_EXECUTABLE and cannot carry execution authority.");
  }
  if (!sameArray(boundary.sourceFiles, STAGING_SOURCE_FILES)) {
    invalid("The staging source file set and order are invalid.");
  }
  if (!sameArray(boundary.serviceNames, STAGING_SERVICE_NAMES)) {
    invalid("The staging service set is invalid.");
  }
  if (!sameArray(boundary.volumeNames, STAGING_VOLUME_NAMES)) {
    invalid("The staging volume set is invalid.");
  }
  exactNullableSha256(boundary.sourceSetSha256, "staging source-set SHA256", pending);
}

function validateSchedulerBoundary(boundary, pending) {
  exactObject(boundary, "Scheduler boundary", [
    "contractSchema",
    "projectName",
    "disposition",
    "executionAuthorized",
    "dataRollbackAuthorized",
    "contractArtifactSha256",
    "identitySetSha256",
    "queueMigrationSha256",
    "applicationDataParentBindingSha256",
  ]);
  if (boundary.contractSchema !== "platform.v1-brownfield-scheduler-cutover-plan/v1"
      || boundary.projectName !== PRODUCTION_PROJECT_NAME
      || boundary.disposition !== "VERIFY_ONLY_STOP"
      || boundary.executionAuthorized !== false
      || boundary.dataRollbackAuthorized !== false) {
    invalid("Scheduler cutover boundary must remain verify-only, production-bound, and unauthorized.");
  }
  for (const [field, label] of [
    ["contractArtifactSha256", "scheduler contract artifact SHA256"],
    ["identitySetSha256", "scheduler identity-set SHA256"],
    ["queueMigrationSha256", "scheduler queue-migration SHA256"],
    ["applicationDataParentBindingSha256", "scheduler application-data parent binding SHA256"],
  ]) exactNullableSha256(boundary[field], label, pending);
}

function validateComposeIdentity(compose, pending) {
  exactObject(compose, "Production Compose identity", [
    "rawFullRenderBytesSha256",
    "fileOrder",
    "fileOrderSha256",
    "profiles",
    "profilesSha256",
    "environmentSha256",
    "projectName",
    "projectNameSha256",
    "serviceNames",
    "serviceSetSha256",
    "configSha256",
    "networkNames",
    "networksSha256",
    "attachmentsSha256",
    "resourceMap",
    "resourceMapSha256",
    "noHostedPolicyBytesSha256",
  ]);
  const composeVariant = Object.entries(CANONICAL_COMPOSE_FILE_ORDERS)
    .find(([, expectedOrder]) => sameArray(compose.fileOrder, expectedOrder))?.[0];
  if (composeVariant === undefined) {
    invalid("Production Compose file order is not one exact canonical VPS or LOCAL_PRIVATE wrapper order with runtime identity last.");
  }
  if (!sameArray(compose.profiles, ["backup"])) invalid("Production Compose profile set must be exactly backup.");
  if (compose.projectName !== PRODUCTION_PROJECT_NAME) invalid("Production project name is invalid.");
  if (!sameArray(compose.serviceNames, PRODUCTION_SERVICE_NAMES)) {
    invalid("Production service set does not match the no-hosted protected resource map.");
  }
  if (!sameArray(compose.networkNames, PRODUCTION_NETWORK_NAMES)) {
    invalid("Production network set does not match the no-hosted protected resource map.");
  }
  if (!sameJson(compose.resourceMap, PROTECTED_RESOURCE_MAPS[composeVariant])) {
    invalid("Production protected resource map does not match the full no-hosted policy mapping.");
  }

  for (const [field, label] of [
    ["rawFullRenderBytesSha256", "raw full render bytes SHA256"],
    ["fileOrderSha256", "Compose file order SHA256"],
    ["profilesSha256", "Compose profiles SHA256"],
    ["environmentSha256", "Compose environment SHA256"],
    ["projectNameSha256", "Compose project name SHA256"],
    ["serviceSetSha256", "Compose service set SHA256"],
    ["configSha256", "Compose config SHA256"],
    ["networksSha256", "Compose network set SHA256"],
    ["attachmentsSha256", "Compose attachments SHA256"],
    ["resourceMapSha256", "Compose resource map SHA256"],
    ["noHostedPolicyBytesSha256", "no-hosted policy bytes SHA256"],
  ]) exactNullableSha256(compose[field], label, pending);

  if (!pending) {
    if (compose.fileOrderSha256 !== sha256Canonical(compose.fileOrder)) {
      invalid("Compose file order SHA256 does not match the exact ordered file list.");
    }
    if (compose.profilesSha256 !== sha256Canonical(compose.profiles)) {
      invalid("Compose profiles SHA256 does not match the exact profile list.");
    }
    if (compose.projectNameSha256 !== sha256Canonical(compose.projectName)) {
      invalid("Compose project name SHA256 does not match the final namespace.");
    }
    if (compose.serviceSetSha256 !== sha256Canonical(compose.serviceNames)) {
      invalid("Compose service set SHA256 does not match the exact service set.");
    }
    if (compose.networksSha256 !== sha256Canonical(compose.networkNames)) {
      invalid("Compose network set SHA256 does not match the exact network set.");
    }
    if (compose.resourceMapSha256 !== sha256Canonical(compose.resourceMap)) {
      invalid("Compose resource map SHA256 does not match the exact protected resource map.");
    }
  }
}

const CONTAINER_KEYS = [
  "service",
  "containerName",
  "projectName",
  "networkMode",
  "networkNames",
  "containerId",
  "imageReference",
  "imageId",
  "configHash",
  "mountsSha256",
  "networkAttachmentsSha256",
  "inspectionArtifactSha256",
  "containerCasSha256",
];
const CONTAINER_OBSERVATION_KEYS = [
  "containerId",
  "imageReference",
  "imageId",
  "configHash",
  "mountsSha256",
  "networkAttachmentsSha256",
  "inspectionArtifactSha256",
  "containerCasSha256",
];

function validateContainers(containers, pending) {
  if (!Array.isArray(containers)
      || containers.length !== RUNTIME_SERVICES.length
      || !containers.every((entry, index) => entry?.service === RUNTIME_SERVICES[index].service)) {
    invalid("Final container identity set and order must be exact.");
  }
  for (const [index, container] of containers.entries()) {
    const expected = RUNTIME_SERVICES[index];
    exactObject(container, `Runtime container ${expected.service}`, CONTAINER_KEYS);
    if (container.service !== expected.service
        || container.containerName !== expected.containerName
        || container.projectName !== expected.projectName) {
      invalid(`Runtime container identity for ${expected.service} is invalid.`);
    }
    if (container.networkMode !== expected.networkMode) {
      invalid(`Runtime container ${expected.service} network mode is invalid.`);
    }
    if (!sameArray(container.networkNames, expected.networkNames)) {
      invalid(`Runtime container ${expected.service} network attachment expectation is invalid.`);
    }
    if (pending) {
      for (const field of CONTAINER_OBSERVATION_KEYS) {
        if (container[field] !== null) {
          invalid(`EXTERNAL-PENDING template container ${expected.service}.${field} must remain null.`);
        }
      }
      continue;
    }
    exactSha256(container.containerId, `Runtime container ${expected.service} ID`);
    if (typeof container.imageReference !== "string" || !IMAGE_REFERENCE.test(container.imageReference)) {
      invalid(`Runtime container ${expected.service} must use one digest-pinned image reference.`);
    }
    if (typeof container.imageId !== "string"
        || !/^sha256:[a-f0-9]{64}$/.test(container.imageId)) {
      invalid(`Runtime container ${expected.service} image ID is invalid.`);
    }
    for (const [field, label] of [
      ["configHash", "config hash"],
      ["mountsSha256", "mount set SHA256"],
      ["networkAttachmentsSha256", "network attachment SHA256"],
      ["inspectionArtifactSha256", "inspection artifact SHA256"],
      ["containerCasSha256", "container CAS SHA256"],
    ]) exactSha256(container[field], `Runtime container ${expected.service} ${label}`);
    const casPayload = structuredClone(container);
    casPayload.containerCasSha256 = null;
    if (container.containerCasSha256 !== sha256Canonical(casPayload)) {
      invalid(`Runtime container ${expected.service} container CAS does not match its exact identity.`);
    }
  }
}

const VOLUME_KEYS = [
  "logicalName",
  "physicalName",
  "driver",
  "scope",
  "options",
  "labels",
  "createdAt",
  "mountpoint",
  "inspectionArtifactSha256",
  "volumeCasSha256",
];
const VOLUME_OBSERVATION_KEYS = [
  "driver",
  "scope",
  "options",
  "labels",
  "createdAt",
  "mountpoint",
  "inspectionArtifactSha256",
  "volumeCasSha256",
];

function validateVolumeLabels(labels, expected) {
  exactObject(labels, `Runtime volume ${expected.logicalName} labels`, [
    "com.docker.compose.project",
    "com.docker.compose.version",
    "com.docker.compose.volume",
  ]);
  if (labels["com.docker.compose.project"] !== PRODUCTION_PROJECT_NAME
      || labels["com.docker.compose.volume"] !== expected.logicalName
      || typeof labels["com.docker.compose.version"] !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(labels["com.docker.compose.version"])) {
    invalid(`Runtime volume ${expected.logicalName} volume labels are invalid.`);
  }
}

function validateVolumes(volumes, pending) {
  if (!Array.isArray(volumes)
      || volumes.length !== RUNTIME_VOLUMES.length
      || !volumes.every((entry, index) => entry?.logicalName === RUNTIME_VOLUMES[index].logicalName)) {
    invalid("Final volume identity set and order must be exact.");
  }
  for (const [index, volume] of volumes.entries()) {
    const expected = RUNTIME_VOLUMES[index];
    exactObject(volume, `Runtime volume ${expected.logicalName}`, VOLUME_KEYS);
    if (volume.logicalName !== expected.logicalName
        || volume.physicalName !== expected.physicalName) {
      invalid(`Runtime volume identity for ${expected.logicalName} is invalid.`);
    }
    if (pending) {
      for (const field of VOLUME_OBSERVATION_KEYS) {
        if (volume[field] !== null) {
          invalid(`EXTERNAL-PENDING template volume ${expected.logicalName}.${field} must remain null.`);
        }
      }
      continue;
    }
    if (volume.driver !== "local") invalid(`Runtime volume ${expected.logicalName} driver must be local.`);
    if (volume.scope !== "local") invalid(`Runtime volume ${expected.logicalName} scope must be local.`);
    if (!volume.options || typeof volume.options !== "object" || Array.isArray(volume.options)
        || Object.keys(volume.options).length !== 0) {
      invalid(`Runtime volume ${expected.logicalName} options must be an exact empty object.`);
    }
    validateVolumeLabels(volume.labels, expected);
    exactTimestamp(volume.createdAt, `Runtime volume ${expected.logicalName} creation time`);
    exactVolumeMountpoint(
      volume.mountpoint,
      expected,
      `Runtime volume ${expected.logicalName} mountpoint`,
    );
    exactSha256(volume.inspectionArtifactSha256, `Runtime volume ${expected.logicalName} inspection artifact SHA256`);
    exactSha256(volume.volumeCasSha256, `Runtime volume ${expected.logicalName} volume CAS SHA256`);
    const casPayload = structuredClone(volume);
    casPayload.volumeCasSha256 = null;
    if (volume.volumeCasSha256 !== sha256Canonical(casPayload)) {
      invalid(`Runtime volume ${expected.logicalName} volume CAS does not match its exact identity.`);
    }
  }
}

function validateQueueOwnership(queue, pending) {
  exactObject(queue, "Queue ownership", [
    "logicalVolumeName",
    "parentAndChildScope",
    "owners",
    "extraParentOrChildReadWriteWriters",
    "completeParentAndChildWriterEnumeration",
    "observationArtifactSha256",
    "writerEnumerationSha256",
  ]);
  if (queue.logicalVolumeName !== "backup_scheduler_jobs"
      || queue.parentAndChildScope !== "EXACT-PARENT-AND-CHILD") {
    invalid("Queue ownership scope is invalid.");
  }
  if (!sameJson(queue.owners, QUEUE_OWNERSHIP)) invalid("Queue owner identity set and order must be exact.");
  if (!Array.isArray(queue.extraParentOrChildReadWriteWriters)
      || queue.extraParentOrChildReadWriteWriters.length !== 0) {
    invalid("Queue has an extra parent or child read-write writer; preserve and STOP.");
  }
  if (pending) {
    if (queue.completeParentAndChildWriterEnumeration !== null
        || queue.observationArtifactSha256 !== null
        || queue.writerEnumerationSha256 !== null) {
      invalid("EXTERNAL-PENDING template queue observation fields must remain null.");
    }
    return;
  }
  if (queue.completeParentAndChildWriterEnumeration !== true) {
    invalid("Queue requires a complete parent and child writer enumeration.");
  }
  exactSha256(queue.observationArtifactSha256, "Queue ownership observation artifact SHA256");
  exactSha256(queue.writerEnumerationSha256, "Queue writer enumeration SHA256");
  const expectedEnumeration = sha256Canonical({
    owners: queue.owners,
    extraParentOrChildReadWriteWriters: queue.extraParentOrChildReadWriteWriters,
  });
  if (queue.writerEnumerationSha256 !== expectedEnumeration) {
    invalid("Queue writer enumeration SHA256 does not match the complete owner projection.");
  }
}

const APPLICATION_ATTACHMENTS = deepFreeze([
  {
    service: "control-center",
    containerName: "enterprise-control-center",
    sourcePath: null,
    target: "/var/www/project-state",
    readOnly: false,
  },
  {
    service: "project-router",
    containerName: "enterprise-project-router",
    sourcePath: null,
    target: "/var/www/project-state",
    readOnly: true,
  },
]);

function validateApplicationDataParent(parent, pending) {
  exactObject(parent, "Application-data parent", [
    "classification",
    "sourcePath",
    "canonicalPath",
    "sourceIdentitySha256",
    "baselineBindingSha256",
    "consumerSetSha256",
    "observationArtifactSha256",
    "preservedForFirstCutover",
    "relocationAllowed",
    "finalAttachments",
  ]);
  if (parent.classification !== "APPLICATION-DATA") {
    invalid("The full parent bind must retain APPLICATION-DATA classification.");
  }
  if (parent.preservedForFirstCutover !== true) {
    invalid("The full APPLICATION-DATA parent must be preserved for the first cutover.");
  }
  if (parent.relocationAllowed !== false) {
    invalid("APPLICATION-DATA parent relocation is forbidden for the first cutover.");
  }
  if (!Array.isArray(parent.finalAttachments)
      || parent.finalAttachments.length !== APPLICATION_ATTACHMENTS.length
      || !parent.finalAttachments.every((entry, index) => (
        entry?.service === APPLICATION_ATTACHMENTS[index].service
      ))) {
    invalid("Application-data attachment set and order must be exact.");
  }
  for (const [index, attachment] of parent.finalAttachments.entries()) {
    const expected = APPLICATION_ATTACHMENTS[index];
    exactObject(attachment, `Application-data attachment ${expected.service}`, [
      "service", "containerName", "sourcePath", "target", "readOnly",
    ]);
    if (attachment.service !== expected.service
        || attachment.containerName !== expected.containerName
        || attachment.target !== expected.target
        || attachment.readOnly !== expected.readOnly) {
      invalid(`Application-data attachment ${expected.service} is invalid.`);
    }
  }
  if (pending) {
    for (const field of [
      "sourcePath",
      "canonicalPath",
      "sourceIdentitySha256",
      "baselineBindingSha256",
      "consumerSetSha256",
      "observationArtifactSha256",
    ]) {
      if (parent[field] !== null) {
        invalid(`EXTERNAL-PENDING template application-data ${field} must remain null.`);
      }
    }
    if (!parent.finalAttachments.every(({ sourcePath }) => sourcePath === null)) {
      invalid("EXTERNAL-PENDING template application-data attachment sources must remain null.");
    }
    return;
  }
  exactAbsolutePath(parent.sourcePath, "Observed application-data source path");
  exactAbsolutePath(parent.canonicalPath, "Observed application-data canonical path");
  if (parent.sourcePath !== LEGACY_APPLICATION_DATA_PARENT
      || parent.canonicalPath !== parent.sourcePath) {
    invalid("Application-data canonical path differs from the exact observed /home parent; silent relocation is forbidden.");
  }
  for (const [field, label] of [
    ["sourceIdentitySha256", "application-data source identity SHA256"],
    ["baselineBindingSha256", "application-data baseline binding SHA256"],
    ["consumerSetSha256", "application-data consumer set SHA256"],
    ["observationArtifactSha256", "application-data observation artifact SHA256"],
  ]) exactSha256(parent[field], label);
  if (!parent.finalAttachments.every(({ sourcePath }) => sourcePath === parent.sourcePath)) {
    invalid("Every final application-data attachment must retain the exact observed parent source.");
  }
}

function validateProductionBoundary(boundary, pending) {
  exactObject(boundary, "Production boundary", [
    "projectName",
    "compose",
    "containers",
    "volumes",
    "queueOwnership",
    "applicationDataParent",
  ]);
  if (boundary.projectName !== PRODUCTION_PROJECT_NAME) invalid("Final production project name is invalid.");
  validateComposeIdentity(boundary.compose, pending);
  validateContainers(boundary.containers, pending);
  validateVolumes(boundary.volumes, pending);
  validateQueueOwnership(boundary.queueOwnership, pending);
  validateApplicationDataParent(boundary.applicationDataParent, pending);
}

function validateCurrentContracts(contracts) {
  if (!Array.isArray(contracts)
      || contracts.length !== CURRENT_CONTRACTS.length
      || !contracts.every((entry, index) => entry?.id === CURRENT_CONTRACTS[index].id)) {
    invalid("Current contract set and order must be exact.");
  }
  for (const [index, contract] of contracts.entries()) {
    exactObject(contract, `Current contract ${CURRENT_CONTRACTS[index].id}`, [
      "id", "sourceFiles", "status", "mismatches",
    ]);
    if (contract.status !== "MISMATCH-STOP"
        || !Array.isArray(contract.mismatches)
        || contract.mismatches.length === 0) {
      invalid("Current contract mismatch/STOP projection must remain explicit and non-empty.");
    }
  }
  if (!sameJson(contracts, CURRENT_CONTRACTS)) {
    invalid("Current contract set and order or mismatch/STOP evidence differs from the canonical projection.");
  }
}

function validateSafety(safety) {
  exactObject(safety, "Runtime identity safety boundary", [
    "unknownResources",
    "preserveApplications",
    "preserveDatabases",
    "preservePersistentStorage",
    "deploymentAuthority",
    "executionAuthorized",
    "mutationAuthority",
    "executorAvailable",
    "dockerExecutor",
    "networkAuthority",
    "signingAuthority",
    "dataRollbackAuthorized",
    "actions",
  ]);
  if (safety.unknownResources !== "PRESERVE+STOP"
      || safety.preserveApplications !== true
      || safety.preserveDatabases !== true
      || safety.preservePersistentStorage !== true
      || safety.deploymentAuthority !== false
      || safety.executionAuthorized !== false
      || safety.mutationAuthority !== false
      || safety.executorAvailable !== false
      || safety.dockerExecutor !== false
      || safety.networkAuthority !== false
      || safety.signingAuthority !== false
      || safety.dataRollbackAuthorized !== false
      || !Array.isArray(safety.actions)
      || safety.actions.length !== 0) {
    invalid("Runtime identity safety boundary is widened or executable.");
  }
}

export function verifyV1BrownfieldRuntimeIdentity(document) {
  const pending = validateDocumentIdentity(document);
  validateStagingBoundary(document.stagingBoundary, pending);
  validateSchedulerBoundary(document.schedulerBoundary, pending);
  validateProductionBoundary(document.productionBoundary, pending);
  validateCurrentContracts(document.currentContracts);
  validateSafety(document.safety);

  return deepFreeze({
    schema: "platform.v1-brownfield-runtime-identity-validation/v1",
    status: "LOCAL-NOT-AUTHORIZED",
    externalStatus: pending ? "EXTERNAL-PENDING" : "SYNTHETIC-ONLY",
    referenceOnly: true,
    structuralBindingsValidated: true,
    syntheticBindingsComplete: !pending,
    observationBindingsComplete: false,
    externalEvidenceComplete: false,
    authoritativeEvidenceVerified: false,
    rawFullRenderVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    runtimeIdentityInspectionStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    applicationDataBaselineRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    queueWriterEnumerationRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    currentContractsConverged: false,
    currentContractStatus: "MISMATCH-STOP",
    mismatches: document.currentContracts.flatMap(({ id, mismatches }) => (
      mismatches.map((mismatch) => `${id}:${mismatch}`)
    )),
    stagingNamespaceExecutable: false,
    deploymentAuthority: false,
    executionAuthorized: false,
    mutationAuthority: false,
    localMutationAuthority: false,
    executorAvailable: false,
    dockerExecutor: false,
    networkAuthority: false,
    signingAuthority: false,
    dataRollbackAuthorized: false,
    actions: [],
    documentId: document.documentId,
  });
}

function readJsonDocument(inputPath) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      inputPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
  } catch (error) {
    invalid(`Runtime identity input is unavailable: ${String(error?.message ?? error)}`);
  }
  let bytes;
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n
        || before.size < 2n || before.size > BigInt(MAX_DOCUMENT_BYTES)) {
      invalid("Runtime identity input must be one bounded regular single-link JSON file.");
    }
    bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count === 0) invalid("Runtime identity input was truncated during its bounded read.");
      offset += count;
    }
    const trailing = Buffer.alloc(1);
    if (fs.readSync(descriptor, trailing, 0, 1, null) !== 0) {
      invalid("Runtime identity input grew beyond its bounded snapshot.");
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) {
      if (before[field] !== after[field]) {
        invalid("Runtime identity input identity changed during its bounded read.");
      }
    }
  } finally {
    fs.closeSync(descriptor);
  }
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    invalid("Runtime identity input is not valid JSON.");
  }
}

function main(argv) {
  if (argv.length !== 2 || argv[0] !== "verify") {
    process.stderr.write("Usage: v1-brownfield-runtime-identity.mjs verify <identity.json> (verify-only)\n");
    return 64;
  }
  try {
    const result = verifyV1BrownfieldRuntimeIdentity(readJsonDocument(argv[1]));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return 78;
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    return 78;
  }
}

const isCli = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli) process.exitCode = main(process.argv.slice(2));
