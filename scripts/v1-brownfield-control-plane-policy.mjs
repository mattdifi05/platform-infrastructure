import fs from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { pathToFileURL } from "node:url";

import {
  livePreservationBaselineSchema,
  sha256Canonical,
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";
import {
  CANDIDATE_EXPECTATIONS,
  inspectBrownfieldBaseline,
} from "./v1-brownfield-control-plane-gate.mjs";

const PROJECT_NAME = "platform_infra_v1_control";
const MUTATION_SERVICES = Object.freeze([
  "docker-action-activation-sidecar",
  "docker-action-broker",
]);
const PROJECT_VOLUMES = Object.freeze([
  "backup_scheduler_jobs",
  "docker_action_activation_cas",
  "docker_action_broker_socket",
  "docker_action_broker_state",
]);
const BROKER_SECRETS = Object.freeze([
  "docker_action_backup_catalog",
  "docker_action_backup_job_execute",
  "docker_action_backup_offsite_sync",
  "docker_action_backup_prune_apply",
  "docker_action_backup_prune_plan",
  "docker_action_evidence_runtime_snapshot",
  "docker_action_restore_drill_full",
  "docker_action_runtime_intent_trust_key",
]);

export const EXPECTED_BROWNFIELD_POLICY = Object.freeze({
  schemaVersion: "platform.v1-brownfield-control-plane/v1",
  status: "LOCAL-NOT-PREPARED",
  projectName: PROJECT_NAME,
  mutationServices: [...MUTATION_SERVICES],
  replaceableServices: [],
  preservedProjectNames: ["platform_infra_vps"],
  unknownResources: "PRESERVE",
  deploymentAuthority: false,
  rawBrokerEligibility: false,
  forbiddenOperations: [
    "down",
    "--remove-orphans",
    "prune",
    "project-wide stop/rm",
  ],
  preservation: {
    preserveAllExistingContainers: true,
    preserveAllExistingDatabases: true,
    preserveAllExistingVolumes: true,
    preserveAllExistingNamedVolumes: true,
    preserveAllExistingAnonymousVolumes: true,
    preserveAllExistingBindMounts: true,
    preserveAllExistingNetworks: true,
    minimumObservedVolumes: {
      total: 139,
      named: 12,
      anonymous: 127,
    },
  },
  localBlockers: [
    "canonical complete live baseline",
    "zero existing raw Docker socket owners",
    "zero existing host-parent authorities",
    "zero candidate bind source or target collisions",
    "real rendered Compose with root-owned bind and secret identities",
    "authenticated root executor",
    "all provider gates authenticated",
  ],
  providerGates: [
    {
      name: "Hosted preparation/provider conformance",
      status: "EXTERNAL-PENDING",
    },
    {
      name: "Deployment admission",
      status: "EXTERNAL-PENDING",
    },
    {
      name: "Activation promotion/Sigstore",
      status: "EXTERNAL-PENDING",
    },
  ],
  compose: {
    file: "compose.v1-control-plane.yaml",
    projectScopedVolumes: [...PROJECT_VOLUMES],
    networks: [],
  },
});

const EXPECTED_IMAGES = Object.freeze({
  "docker-action-activation-sidecar": "${PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY:?set provider/admin activation sidecar repository}@sha256:${PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256:?set provider/admin activation sidecar sha256}",
  "docker-action-broker": "${PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY:?set digest-pinned broker repository}@sha256:${PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256:?set broker image sha256}",
});

const EXPECTED_ENVIRONMENT = Object.freeze({
  "docker-action-activation-sidecar": {
    ACTIVATION_INBOX: "/run/platform/provider-activation/inbox",
    ACTIVATION_CAS: "/run/platform/docker-action-activation/by-bundle-sha256",
  },
  "docker-action-broker": {
    DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
    DOCKER_ACTION_RUNTIME_INTENT_FILE: "/run/platform/docker-action-trust/runtime-intent.json",
    DOCKER_ACTION_ACTIVE_RECEIPT_FILE: "/run/platform/docker-action-trust/active-receipt.json",
    DOCKER_ACTION_RUNTIME_INTENT_TRUST_KEY_FILE: "/run/secrets/docker_action_runtime_intent_trust_key",
  },
});

const EXPECTED_ENTRYPOINTS = Object.freeze({
  "docker-action-activation-sidecar": [
    "/opt/provider-activation/materialize-dsse-cas",
  ],
  "docker-action-broker": [
    "node",
    "/opt/platform-docker-broker/docker-action-broker.mjs",
  ],
});

const EXPECTED_PIDS_LIMIT = Object.freeze({
  "docker-action-activation-sidecar": "64",
  "docker-action-broker": "256",
});

const EXPECTED_RESTART = Object.freeze({
  "docker-action-activation-sidecar": "no",
  "docker-action-broker": "unless-stopped",
});

const EXPECTED_SERVICE_FIELDS = Object.freeze({
  "docker-action-activation-sidecar": [
    "cap_drop",
    "entrypoint",
    "environment",
    "image",
    "init",
    "network_mode",
    "pids_limit",
    "read_only",
    "restart",
    "security_opt",
    "user",
    "volumes",
  ],
  "docker-action-broker": [
    "cap_drop",
    "depends_on",
    "entrypoint",
    "environment",
    "healthcheck",
    "image",
    "init",
    "network_mode",
    "pids_limit",
    "read_only",
    "restart",
    "secrets",
    "security_opt",
    "user",
    "volumes",
  ],
});

const EXPECTED_MOUNTS = Object.freeze({
  "docker-action-activation-sidecar": [
    {
      type: "bind",
      source: "${DOCKER_ACTION_ACTIVATION_INBOX:?set provider/admin-owned activation inbox}",
      target: "/run/platform/provider-activation/inbox",
      readOnly: true,
      createHostPath: false,
    },
    {
      type: "volume",
      source: "docker_action_activation_cas",
      target: "/run/platform/docker-action-activation/by-bundle-sha256",
      readOnly: false,
      createHostPath: null,
    },
  ],
  "docker-action-broker": [
    {
      type: "bind",
      source: "/var/run/docker.sock",
      target: "/var/run/docker.sock",
      readOnly: true,
      createHostPath: false,
    },
    {
      type: "volume",
      source: "docker_action_broker_socket",
      target: "/run/platform/docker-action-broker",
      readOnly: false,
      createHostPath: null,
    },
    {
      type: "volume",
      source: "docker_action_broker_state",
      target: "/var/lib/platform/docker-action-broker",
      readOnly: false,
      createHostPath: null,
    },
    {
      type: "volume",
      source: "backup_scheduler_jobs",
      target: "/run/platform/backup-jobs",
      readOnly: true,
      createHostPath: null,
    },
    {
      type: "volume",
      source: "docker_action_activation_cas",
      target: "/run/platform/docker-action-activation/by-bundle-sha256",
      readOnly: true,
      createHostPath: null,
    },
    {
      type: "bind",
      source: "${DOCKER_ACTION_RUNTIME_INTENT_FILE:?set root-owned runtime intent}",
      target: "/run/platform/docker-action-trust/runtime-intent.json",
      readOnly: true,
      createHostPath: false,
    },
    {
      type: "bind",
      source: "${DOCKER_ACTION_ACTIVE_RECEIPT_FILE:?set root-owned active receipt}",
      target: "/run/platform/docker-action-trust/active-receipt.json",
      readOnly: true,
      createHostPath: false,
    },
  ],
});

const EXPECTED_SECRET_FILES = Object.freeze({
  docker_action_runtime_intent_trust_key: "${DOCKER_ACTION_RUNTIME_INTENT_TRUST_KEY_FILE:?set root-owned runtime-intent trust key file}",
  docker_action_backup_catalog: "${DOCKER_ACTION_BACKUP_CATALOG_FILE:?set root-owned backup catalog capability file}",
  docker_action_backup_job_execute: "${DOCKER_ACTION_BACKUP_JOB_EXECUTE_FILE:?set root-owned backup execution capability file}",
  docker_action_backup_prune_plan: "${DOCKER_ACTION_BACKUP_PRUNE_PLAN_FILE:?set root-owned backup prune-plan capability file}",
  docker_action_backup_prune_apply: "${DOCKER_ACTION_BACKUP_PRUNE_APPLY_FILE:?set root-owned backup prune-apply capability file}",
  docker_action_restore_drill_full: "${DOCKER_ACTION_RESTORE_DRILL_FULL_FILE:?set root-owned restore-drill capability file}",
  docker_action_backup_offsite_sync: "${DOCKER_ACTION_BACKUP_OFFSITE_SYNC_FILE:?set root-owned offsite-sync capability file}",
  docker_action_evidence_runtime_snapshot: "${DOCKER_ACTION_EVIDENCE_RUNTIME_SNAPSHOT_FILE:?set root-owned evidence capability file}",
});

/**
 * Validate the additive, observation-only brownfield source contract. Even a
 * structurally valid source remains LOCAL-NOT-PREPARED: the real render, root
 * identities, provider evidence and root executor are unavailable locally.
 */
export function evaluateBrownfieldControlPlane({ policy, composeText, liveBaseline }) {
  const failures = [];
  const baselineBefore = stableJson(liveBaseline);

  if (!isDeepStrictEqual(policy, EXPECTED_BROWNFIELD_POLICY)) {
    failures.push("policy-exact-contract: policy differs from the deny-only brownfield contract");
  }

  let compose;
  try {
    compose = parseBrownfieldControlPlaneCompose(composeText);
  } catch (error) {
    failures.push(`compose-parse: ${error.message}`);
  }
  if (compose) validateCompose(compose, failures);
  const liveInspection = validateLiveBaseline(liveBaseline, failures);

  const baselineAfter = stableJson(liveBaseline);
  const liveBaselineUnchanged = baselineBefore === baselineAfter;
  if (!liveBaselineUnchanged) {
    failures.push("baseline-observation-only: validator modified the supplied live baseline");
  }

  const blockingConditions = [
    "canonical-live-baseline: one complete canonical baseline using platform.live-preservation-baseline/v1 is required",
    "rendered compose: exact effective project, images and bind sources are not verified",
    "secret-input-identities: Compose secret file sources remain unresolved; root ownership, regular-file identity, mode and no-symlink checks are not observed",
    "provider-gates: Hosted preparation, deployment admission and activation promotion/Sigstore are EXTERNAL-PENDING",
    "root-executor: no authenticated local executor or raw-broker eligibility exists",
    ...(liveInspection?.authorityConflicts ?? []).map((entry) => `live-authority:${entry}`),
    ...(liveInspection?.namespaceCollisions ?? []).map((entry) => `namespace-collision:${entry}`),
    ...(liveInspection?.bindCollisions ?? []).map((entry) => `bind-collision:${entry}`),
  ].sort();

  return {
    ok: false,
    structurallyValid: failures.length === 0,
    status: "LOCAL-NOT-PREPARED",
    deploymentAuthorized: false,
    rawBrokerEligible: false,
    actions: [],
    mutationServices: [...MUTATION_SERVICES],
    replaceableServices: [],
    unknownResources: "PRESERVE",
    baselineSchema: livePreservationBaselineSchema,
    candidateEvidenceClass: CANDIDATE_EXPECTATIONS.evidenceClass,
    candidateExpectationsSha256: sha256Canonical(CANDIDATE_EXPECTATIONS),
    providerGates: EXPECTED_BROWNFIELD_POLICY.providerGates.map((gate) => ({ ...gate })),
    liveBaselineUnchanged,
    blockingConditions,
    failures,
  };
}

export function parseBrownfieldControlPlaneCompose(source) {
  if (typeof source !== "string" || source.trim() === "") {
    throw new Error("Compose source must be a non-empty string");
  }
  if (/\t/.test(source)) throw new Error("tabs are not permitted in the canonical Compose source");
  if (/^\s*(?:<<:|x-|include:|extends:)/m.test(source)) {
    throw new Error("Compose aliases, extension fields, includes, and extends are not admitted");
  }

  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const topLevel = mappingBlocks(lines, 0, 0, lines.length);
  const topLevelKeys = Object.keys(topLevel);
  const name = scalar(topLevel.name?.inline ?? "");
  const services = parseServiceMapping(lines, topLevel.services);
  const volumes = parseDeclarationMapping(lines, topLevel.volumes);
  const secrets = parseDeclarationMapping(lines, topLevel.secrets);
  const networks = parseDeclarationMapping(lines, topLevel.networks, { optional: true });
  const rawSocketOwners = Object.entries(services)
    .filter(([, service]) => service.mounts.some((mount) => (
      mount.source === "/var/run/docker.sock"
      || mount.target === "/var/run/docker.sock"
    )))
    .map(([service]) => service)
    .sort();

  return {
    name,
    topLevelKeys,
    services,
    volumes,
    secrets,
    networks,
    rawSocketOwners,
  };
}

function validateCompose(compose, failures) {
  exact("compose-top-level", [...compose.topLevelKeys].sort(), ["name", "secrets", "services", "volumes"], failures);
  same("compose-project-name", compose.name, PROJECT_NAME, failures);
  exact("compose-services", Object.keys(compose.services).sort(), [...MUTATION_SERVICES], failures);
  exact("compose-project-volumes", Object.keys(compose.volumes).sort(), [...PROJECT_VOLUMES], failures);
  exact("compose-no-networks", Object.keys(compose.networks).sort(), [], failures);
  exact("compose-raw-socket-owner", compose.rawSocketOwners, ["docker-action-broker"], failures);

  for (const volume of PROJECT_VOLUMES) {
    const declaration = compose.volumes[volume];
    if (!declaration || declaration.inline !== "{}" || Object.keys(declaration.attributes).length !== 0) {
      failures.push(`compose-private-volume-${volume}: volume must be an unaliased project-scoped declaration`);
    }
  }

  exact("compose-secret-declarations", Object.keys(compose.secrets).sort(), Object.keys(EXPECTED_SECRET_FILES).sort(), failures);
  for (const [name, expectedFile] of Object.entries(EXPECTED_SECRET_FILES)) {
    const declaration = compose.secrets[name];
    if (!declaration || declaration.inline !== "" || !isDeepStrictEqual(declaration.attributes, { file: expectedFile })) {
      failures.push(`compose-secret-source-${name}: secret source must be a required root-owned file input`);
    }
  }

  for (const serviceName of MUTATION_SERVICES) {
    const service = compose.services[serviceName];
    if (!service) continue;
    exact(`compose-fields-${serviceName}`, service.fieldNames, EXPECTED_SERVICE_FIELDS[serviceName], failures);
    same(`compose-image-${serviceName}`, service.image, EXPECTED_IMAGES[serviceName], failures);
    same(`compose-network-mode-${serviceName}`, service.networkMode, "none", failures);
    same(`compose-user-${serviceName}`, service.user, "0:0", failures);
    same(`compose-read-only-${serviceName}`, service.readOnly, "true", failures);
    same(`compose-init-${serviceName}`, service.init, "true", failures);
    same(`compose-pids-limit-${serviceName}`, service.pidsLimit, EXPECTED_PIDS_LIMIT[serviceName], failures);
    same(`compose-restart-${serviceName}`, service.restart, EXPECTED_RESTART[serviceName], failures);
    exact(`compose-cap-drop-${serviceName}`, service.capDrop, ["ALL"], failures);
    exact(`compose-security-opt-${serviceName}`, service.securityOpt, ["no-new-privileges:true"], failures);
    exact(`compose-entrypoint-${serviceName}`, service.entrypoint, EXPECTED_ENTRYPOINTS[serviceName], failures);
    exact(`compose-environment-${serviceName}`, service.environment, EXPECTED_ENVIRONMENT[serviceName], failures);
    exact(`compose-mounts-${serviceName}`, service.mounts, EXPECTED_MOUNTS[serviceName], failures);
    if (service.containerName !== undefined) {
      failures.push(`compose-container-name-${serviceName}: fixed container names are forbidden`);
    }
    if (service.hasNetworkField || service.hasPorts || service.hasExpose || service.hasBuild) {
      failures.push(`compose-host-private-${serviceName}: networks, ports, expose, and build are forbidden`);
    }
  }

  const sidecar = compose.services["docker-action-activation-sidecar"];
  const broker = compose.services["docker-action-broker"];
  if (sidecar) exact("compose-sidecar-secrets", sidecar.secretMounts, [], failures);
  if (broker) {
    exact("compose-broker-secrets", broker.secretMounts, BROKER_SECRETS.map((source) => ({
      source,
      target: source,
      uid: "0",
      gid: "0",
      mode: "256",
    })), failures);
    exact("compose-broker-healthcheck", broker.healthcheck, {
      test: [
        "CMD",
        "node",
        "/opt/platform-docker-broker/docker-action-readiness.mjs",
        "--require-trusted-activation",
      ],
      interval: "15s",
      timeout: "5s",
      retries: "5",
    }, failures);
    exact("compose-broker-sidecar-dependency", broker.dependsOn, {
      "docker-action-activation-sidecar": {
        condition: "service_completed_successfully",
      },
    }, failures);
  }
}

function validateLiveBaseline(baseline, failures) {
  let validation;
  try {
    if (!baseline || typeof baseline !== "object" || Array.isArray(baseline)
        || baseline.schema !== livePreservationBaselineSchema) {
      throw new Error(`PB01 requires canonical ${livePreservationBaselineSchema} evidence`);
    }

    validation = validateLivePreservationBaseline(baseline, { requireComplete: false });
  } catch (error) {
    failures.push(`canonical-live-baseline: ${String(error?.message ?? error)}`);
    return null;
  }

  const floor = EXPECTED_BROWNFIELD_POLICY.preservation.minimumObservedVolumes;
  const { volumes, namedVolumes, anonymousVolumes } = validation.summary;
  if (volumes < floor.total
      || namedVolumes < floor.named
      || anonymousVolumes < floor.anonymous) {
    failures.push(
      `live-volume-floor: observed total=${volumes}, named=${namedVolumes}, anonymous=${anonymousVolumes}; `
      + `required at least total=${floor.total}, named=${floor.named}, anonymous=${floor.anonymous}`,
    );
  }

  const inspection = inspectBrownfieldBaseline(baseline);
  failures.push(...inspection.authorityConflicts.map((entry) => `live-authority-conflict: ${entry}`));
  failures.push(...inspection.namespaceCollisions.map((entry) => `live-namespace-collision: ${entry}`));
  failures.push(...inspection.bindCollisions.map((entry) => `live-bind-collision: ${entry}`));
  try {
    validateLivePreservationBaseline(baseline, { requireComplete: true });
  } catch (error) {
    failures.push(`canonical-live-baseline-completeness: ${String(error?.message ?? error)}`);
  }
  return inspection;
}

function parseServiceMapping(lines, section) {
  if (!section) throw new Error("missing top-level services mapping");
  if (section.inline !== "") throw new Error("services must be a block mapping");
  const entries = mappingBlocks(lines, 2, section.start + 1, section.end);
  return Object.fromEntries(Object.entries(entries).map(([name, entry]) => [
    name,
    parseService(lines, entry),
  ]));
}

function parseService(lines, entry) {
  if (entry.inline !== "") throw new Error(`service ${entry.key} must be a block mapping`);
  const fields = mappingBlocks(lines, 4, entry.start + 1, entry.end);
  const fieldNames = Object.keys(fields).sort();
  const scalarField = (name) => fields[name] ? scalar(fields[name].inline) : undefined;
  return {
    fieldNames,
    image: scalarField("image"),
    networkMode: scalarField("network_mode"),
    user: scalarField("user"),
    readOnly: scalarField("read_only"),
    init: scalarField("init"),
    pidsLimit: scalarField("pids_limit"),
    restart: scalarField("restart"),
    containerName: scalarField("container_name"),
    hasNetworkField: Boolean(fields.networks),
    hasPorts: Boolean(fields.ports),
    hasExpose: Boolean(fields.expose),
    hasBuild: Boolean(fields.build),
    capDrop: listValues(lines, fields.cap_drop, 6),
    securityOpt: listValues(lines, fields.security_opt, 6),
    entrypoint: listValues(lines, fields.entrypoint, 6),
    environment: nestedMapping(lines, fields.environment, 6),
    mounts: parseMounts(lines, fields.volumes),
    secretMounts: parseSecretMounts(lines, fields.secrets),
    healthcheck: parseHealthcheck(lines, fields.healthcheck),
    dependsOn: parseDependsOn(lines, fields.depends_on),
  };
}

function parseMounts(lines, section) {
  if (!section) return [];
  if (section.inline !== "") throw new Error("service volumes must use block long syntax");
  const itemStarts = sequenceStarts(lines, section.start + 1, section.end, 6);
  return itemStarts.map(({ start, end, value }) => {
    const initial = mappingPair(value);
    if (!initial || initial.key !== "type") {
      return { invalid: true, raw: value };
    }
    const fieldBlocks = mappingBlocks(lines, 8, start + 1, end);
    const attributes = { [initial.key]: scalar(initial.value) };
    for (const [name, block] of Object.entries(fieldBlocks)) {
      attributes[name] = scalar(block.inline);
    }
    const expectedFields = attributes.type === "bind"
      ? ["bind", "read_only", "source", "target", "type"]
      : attributes.read_only === "true"
        ? ["read_only", "source", "target", "type"]
        : ["source", "target", "type"];
    const actualFields = Object.keys(attributes).sort();
    if (!isDeepStrictEqual(actualFields, expectedFields)) {
      throw new Error(`non-canonical mount fields: ${actualFields.join(",")}`);
    }
    const bindAttributes = fieldBlocks.bind
      ? nestedMapping(lines, fieldBlocks.bind, 10)
      : {};
    if (attributes.type === "bind"
        && !isDeepStrictEqual(bindAttributes, { create_host_path: "false" })) {
      throw new Error("bind mounts must set only create_host_path: false");
    }
    const createHostPathValue = bindAttributes.create_host_path ?? null;
    const createHostPath = createHostPathValue === "true"
      ? true
      : createHostPathValue === "false" ? false : null;
    return {
      type: attributes.type,
      source: attributes.source,
      target: attributes.target,
      readOnly: attributes.read_only === "true",
      createHostPath,
    };
  });
}

function parseSecretMounts(lines, section) {
  if (!section) return [];
  if (section.inline !== "") throw new Error("service secrets must use block long syntax");
  const starts = sequenceStarts(lines, section.start + 1, section.end, 6);
  return starts.map(({ start, end, value }) => {
    const pair = mappingPair(value);
    if (!pair || pair.key !== "source") throw new Error("service secrets must use source mappings");
    const fields = nestedMapping(lines, { key: "secret", inline: "", start, end }, 8);
    const mount = {
      source: scalar(pair.value),
      target: fields.target,
      uid: fields.uid,
      gid: fields.gid,
      mode: fields.mode,
    };
    if (!isDeepStrictEqual(Object.keys(fields).sort(), ["gid", "mode", "target", "uid"])) {
      throw new Error(`non-canonical secret fields for ${mount.source}`);
    }
    return mount;
  }).sort((left, right) => left.source.localeCompare(right.source));
}

function parseHealthcheck(lines, section) {
  if (!section) return {};
  const fields = mappingBlocks(lines, 6, section.start + 1, section.end);
  const fieldNames = Object.keys(fields).sort();
  if (!isDeepStrictEqual(fieldNames, ["interval", "retries", "test", "timeout"])) {
    throw new Error(`non-canonical healthcheck fields: ${fieldNames.join(",")}`);
  }
  return {
    test: listValues(lines, fields.test, 8),
    interval: fields.interval ? scalar(fields.interval.inline) : undefined,
    timeout: fields.timeout ? scalar(fields.timeout.inline) : undefined,
    retries: fields.retries ? scalar(fields.retries.inline) : undefined,
  };
}

function parseDependsOn(lines, section) {
  if (!section) return {};
  const dependencies = mappingBlocks(lines, 6, section.start + 1, section.end);
  return Object.fromEntries(Object.entries(dependencies).map(([name, dependency]) => [
    name,
    nestedMapping(lines, dependency, 8),
  ]));
}

function parseDeclarationMapping(lines, section, { optional = false } = {}) {
  if (!section) {
    if (optional) return {};
    throw new Error("missing required top-level declaration mapping");
  }
  if (section.inline !== "") throw new Error(`${section.key} must be a block mapping`);
  const entries = mappingBlocks(lines, 2, section.start + 1, section.end);
  return Object.fromEntries(Object.entries(entries).map(([name, entry]) => [
    name,
    {
      inline: scalar(entry.inline),
      attributes: entry.inline === "" ? nestedMapping(lines, entry, 4) : {},
    },
  ]));
}

function mappingBlocks(lines, indent, start, end) {
  const pattern = new RegExp(`^ {${indent}}([A-Za-z0-9_.-]+):(?:\\s*(.*))?$`);
  const starts = [];
  for (let index = start; index < end; index += 1) {
    const match = lines[index].match(pattern);
    if (match) {
      starts.push({ index, key: match[1], inline: match[2] ?? "" });
      continue;
    }
    const line = lines[index];
    const leadingSpaces = line.match(/^ */)[0].length;
    if (leadingSpaces === indent && line.trim() !== "" && !line.trimStart().startsWith("#")) {
      throw new Error(`unsupported or quoted mapping key at line ${index + 1}`);
    }
  }
  const result = {};
  for (let offset = 0; offset < starts.length; offset += 1) {
    const current = starts[offset];
    if (Object.hasOwn(result, current.key)) throw new Error(`duplicate mapping key ${current.key}`);
    result[current.key] = {
      key: current.key,
      inline: current.inline,
      start: current.index,
      end: starts[offset + 1]?.index ?? end,
    };
  }
  return result;
}

function nestedMapping(lines, section, indent) {
  if (!section) return {};
  if (section.inline !== "") throw new Error(`${section.key} must be a block mapping`);
  const blocks = mappingBlocks(lines, indent, section.start + 1, section.end);
  const result = {};
  for (const [key, block] of Object.entries(blocks)) {
    if (block.inline === "") throw new Error(`${section.key}.${key} must be a scalar`);
    result[key] = scalar(block.inline);
  }
  return result;
}

function listValues(lines, section, indent) {
  if (!section) return [];
  if (section.inline !== "") throw new Error(`${section.key} must be a block sequence`);
  return sequenceStarts(lines, section.start + 1, section.end, indent)
    .map(({ value }) => scalar(value));
}

function sequenceStarts(lines, start, end, indent) {
  const pattern = new RegExp(`^ {${indent}}-\\s*(.*)$`);
  const starts = [];
  for (let index = start; index < end; index += 1) {
    const match = lines[index].match(pattern);
    if (match) starts.push({ index, value: match[1] });
  }
  return starts.map((current, offset) => ({
    start: current.index,
    end: starts[offset + 1]?.index ?? end,
    value: current.value,
  }));
}

function mappingPair(value) {
  const match = String(value).match(/^([A-Za-z0-9_.-]+):(?:\s*(.*))?$/);
  return match ? { key: match[1], value: match[2] ?? "" } : null;
}

function scalar(value) {
  const source = String(value).trim();
  if ((source.startsWith('"') && source.endsWith('"'))
      || (source.startsWith("'") && source.endsWith("'"))) {
    return source.slice(1, -1);
  }
  return source;
}

function exact(id, actual, expected, failures) {
  if (!isDeepStrictEqual(actual, expected)) {
    failures.push(`${id}: expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  }
}

function same(id, actual, expected, failures) {
  if (actual !== expected) {
    failures.push(`${id}: expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  }
}

function stableJson(value) {
  try {
    return JSON.stringify(value, (_, candidate) => {
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return candidate;
      return Object.fromEntries(Object.entries(candidate).sort(([left], [right]) => left.localeCompare(right)));
    });
  } catch {
    return "<unserializable>";
  }
}

function parseArguments(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!["--policy", "--compose", "--baseline"].includes(name) || !value) {
      throw new Error("usage: v1-brownfield-control-plane-policy.mjs --policy FILE --compose FILE --baseline FILE");
    }
    args[name.slice(2)] = value;
  }
  if (!args.policy || !args.compose || !args.baseline) {
    throw new Error("policy, compose, and canonical read-only baseline paths are required");
  }
  return args;
}

function main() {
  const args = parseArguments(process.argv.slice(2));
  const policy = JSON.parse(fs.readFileSync(path.resolve(args.policy), "utf8"));
  const composeText = fs.readFileSync(path.resolve(args.compose), "utf8");
  const liveBaseline = JSON.parse(fs.readFileSync(path.resolve(args.baseline), "utf8"));
  const report = evaluateBrownfieldControlPlane({ policy, composeText, liveBaseline });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = 78;
}

if (process.argv[1]
    && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
