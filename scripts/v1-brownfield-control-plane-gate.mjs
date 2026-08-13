#!/usr/bin/env node
/**
 * Deny-only V1 brownfield reference gate.
 *
 * This module consumes the canonical read-only preservation baseline. It has no
 * Docker executor, no provider verifier and no mutation authority. Structural
 * expectations below are never observations and can never make the result
 * deployable. The CLI `apply` command is an unconditional fail-closed sentinel.
 */
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  compareLivePreservationBaseline,
  livePreservationBaselineSchema,
  sha256Canonical,
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";

export const CONTROL_PROJECT_NAME = "platform_infra_v1_control";
export const MUTATION_SERVICES = Object.freeze([
  "docker-action-activation-sidecar",
  "docker-action-broker",
]);
export const ACTIVATION_SCOPE = deepFreeze({
  mutationServices: [...MUTATION_SERVICES],
  replaceableServices: [],
  preservedProjectNames: ["platform_infra_vps"],
});

const CONTROL_VOLUME_NAMES = Object.freeze([
  "backup_scheduler_jobs",
  "docker_action_activation_cas",
  "docker_action_broker_socket",
  "docker_action_broker_state",
]);

const CONTROL_BIND_EXPECTATIONS = Object.freeze([
  {
    service: "docker-action-activation-sidecar",
    source: "/srv/platform-infrastructure/provider-activation/inbox",
    sourceVariable: "DOCKER_ACTION_ACTIVATION_INBOX",
    target: "/run/platform/provider-activation/inbox",
    readOnly: true,
  },
  {
    service: "docker-action-broker",
    source: "/srv/platform-infrastructure/platform-activation/active.json",
    sourceVariable: "DOCKER_ACTION_ACTIVE_RECEIPT_FILE",
    target: "/run/platform/docker-action-trust/active-receipt.json",
    readOnly: true,
  },
  {
    service: "docker-action-broker",
    source: "/srv/platform-infrastructure/platform-activation/runtime-intent.json",
    sourceVariable: "DOCKER_ACTION_RUNTIME_INTENT_FILE",
    target: "/run/platform/docker-action-trust/runtime-intent.json",
    readOnly: true,
  },
  {
    service: "docker-action-broker",
    source: "/var/run/docker.sock",
    sourceVariable: null,
    target: "/var/run/docker.sock",
    readOnly: true,
  },
]);

const CONTROL_SECRET_EXPECTATIONS = Object.freeze([
  ["DOCKER_ACTION_RUNTIME_INTENT_TRUST_KEY_FILE", "docker_action_runtime_intent_trust_key"],
  ["DOCKER_ACTION_BACKUP_CATALOG_FILE", "docker_action_backup_catalog"],
  ["DOCKER_ACTION_BACKUP_JOB_EXECUTE_FILE", "docker_action_backup_job_execute"],
  ["DOCKER_ACTION_BACKUP_PRUNE_PLAN_FILE", "docker_action_backup_prune_plan"],
  ["DOCKER_ACTION_BACKUP_PRUNE_APPLY_FILE", "docker_action_backup_prune_apply"],
  ["DOCKER_ACTION_RESTORE_DRILL_FULL_FILE", "docker_action_restore_drill_full"],
  ["DOCKER_ACTION_BACKUP_OFFSITE_SYNC_FILE", "docker_action_backup_offsite_sync"],
  ["DOCKER_ACTION_EVIDENCE_RUNTIME_SNAPSHOT_FILE", "docker_action_evidence_runtime_snapshot"],
].map(([sourceVariable, target]) => ({
  sourceVariable,
  target: `/run/secrets/${target}`,
  requiredObservedIdentity: "root-owned-single-regular-file",
})));

export const CANDIDATE_EXPECTATIONS = deepFreeze({
  schema: "platform.v1-brownfield-candidate-expectations/v1",
  evidenceClass: "STRUCTURAL-EXPECTATION-NOT-OBSERVATION",
  projectName: CONTROL_PROJECT_NAME,
  services: [
    {
      service: "docker-action-activation-sidecar",
      role: "provider-materializer",
      rawDockerSocket: false,
    },
    {
      service: "docker-action-broker",
      role: "prospective-raw-docker-authority",
      rawDockerSocket: true,
    },
  ],
  volumes: [...CONTROL_VOLUME_NAMES],
  networks: [],
  bindExpectations: CONTROL_BIND_EXPECTATIONS,
  secretExpectations: CONTROL_SECRET_EXPECTATIONS,
  imageInputs: [
    "PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY",
    "PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256",
    "PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY",
    "PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256",
  ],
});

// Backwards-compatible export name, now explicitly structural and identity-free.
export const REFERENCE_CANDIDATE_RESOURCES = CANDIDATE_EXPECTATIONS;

export const LOCAL_PROVIDER_POLICY = deepFreeze({
  schema: "platform-v1-brownfield-provider-policy/v1",
  status: "EXTERNAL-PENDING",
  providerControlled: true,
  locallySatisfiable: false,
  policySha256: null,
});

export const PROVIDER_GATES = deepFreeze([
  { name: "Hosted preparation/provider conformance", status: "EXTERNAL-PENDING" },
  { name: "Deployment admission", status: "EXTERNAL-PENDING" },
  { name: "Activation promotion/Sigstore", status: "EXTERNAL-PENDING" },
]);

const RAW_DOCKER_SOURCES = new Set(["/var/run/docker.sock", "/run/docker.sock"]);
const HOST_PARENT_SOURCES = new Set(["/", "/run", "/var/run", "/var/lib/docker"]);
const OBSERVED_VOLUME_FLOORS = Object.freeze({ total: 139, named: 12, anonymous: 127 });
const FIXED_LOCAL_BLOCKERS = Object.freeze([
  "rendered-compose: exact project, images, mounts and secret source identities are not verified by this source-only reference",
  "secret-input-identities: Compose secret file sources remain unresolved; root ownership, regular-file identity, mode and no-symlink checks are not observed",
  "provider-gates: Hosted preparation, deployment admission and activation promotion/Sigstore are EXTERNAL-PENDING",
  "root-executor: this local reference has no authenticated root executor or raw-broker eligibility",
]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const entry of Object.values(value)) deepFreeze(entry);
  }
  return value;
}

function canonicalEqual(left, right) {
  return sha256Canonical(left) === sha256Canonical(right);
}

function uniqueSorted(values) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function pathsOverlap(left, right) {
  if (left === right) return true;
  if (left === "/" || right === "/") return true;
  return left.startsWith(`${right}/`) || right.startsWith(`${left}/`);
}

function assertCanonicalBaseline(baseline, { requireComplete = false } = {}) {
  if (!baseline || typeof baseline !== "object" || Array.isArray(baseline)
      || baseline.schema !== livePreservationBaselineSchema) {
    throw new Error(`PB01 requires canonical ${livePreservationBaselineSchema} evidence.`);
  }
  return validateLivePreservationBaseline(baseline, { requireComplete });
}

function assertObservedVolumeFloor(summary) {
  if (summary.volumes < OBSERVED_VOLUME_FLOORS.total
      || summary.namedVolumes < OBSERVED_VOLUME_FLOORS.named
      || summary.anonymousVolumes < OBSERVED_VOLUME_FLOORS.anonymous) {
    throw new Error(
      `PB02 volume floor is incomplete: observed total=${summary.volumes}, named=${summary.namedVolumes}, `
      + `anonymous=${summary.anonymousVolumes}; require at least total=139, named=12, anonymous=127.`,
    );
  }
}

function expectedPhysicalContainerNames() {
  return MUTATION_SERVICES.map((service) => `${CONTROL_PROJECT_NAME}-${service}-1`);
}

function expectedPhysicalVolumeNames() {
  return CONTROL_VOLUME_NAMES.map((name) => `${CONTROL_PROJECT_NAME}_${name}`);
}

/**
 * Inspect one already validated canonical baseline for conflicts. The returned
 * strings are deny-only diagnostics, not an authorization or mutation plan.
 */
export function inspectBrownfieldBaseline(baseline) {
  const authorityConflicts = [];
  const namespaceCollisions = [];
  const bindCollisions = [];
  const containers = Array.isArray(baseline?.containers) ? baseline.containers : [];
  const binds = Array.isArray(baseline?.bindMounts) ? baseline.bindMounts : [];
  const projects = Array.isArray(baseline?.composeProjects) ? baseline.composeProjects : [];
  const volumes = Array.isArray(baseline?.volumes) ? baseline.volumes : [];
  const candidateContainerNames = new Set(expectedPhysicalContainerNames());
  const candidateVolumeNames = new Set(expectedPhysicalVolumeNames());
  const candidateSources = new Set(CONTROL_BIND_EXPECTATIONS.map(({ source }) => source));
  const candidateTargets = new Set([
    ...CONTROL_BIND_EXPECTATIONS.map(({ target }) => target),
    ...CONTROL_SECRET_EXPECTATIONS.map(({ target }) => target),
  ]);

  for (const project of projects) {
    if (project.name === CONTROL_PROJECT_NAME) namespaceCollisions.push(`compose-project:${project.name}`);
  }
  for (const container of containers) {
    if (container.project === CONTROL_PROJECT_NAME || candidateContainerNames.has(container.name)) {
      namespaceCollisions.push(`container:${container.name}`);
    }
    for (const mount of container.mounts ?? []) {
      if (mount.kind !== "bind") continue;
      if (RAW_DOCKER_SOURCES.has(mount.sourceRef)) {
        authorityConflicts.push(`raw-docker-socket:${container.name}:${mount.sourceRef}:${mount.destination}`);
      } else if (HOST_PARENT_SOURCES.has(mount.sourceRef)) {
        authorityConflicts.push(`host-parent-authority:${container.name}:${mount.sourceRef}:${mount.destination}`);
      }
    }
  }
  for (const volume of volumes) {
    if (candidateVolumeNames.has(volume.name)) namespaceCollisions.push(`volume:${volume.name}`);
  }
  for (const bind of binds) {
    const observedSources = uniqueSorted([bind.source, bind.canonicalPath]);
    for (const candidateSource of candidateSources) {
      for (const observedSource of observedSources) {
        if (pathsOverlap(observedSource, candidateSource)) {
          bindCollisions.push(
            `candidate-source:${bind.source}:${observedSource}:${candidateSource}`,
          );
        }
      }
    }
    for (const consumer of bind.consumers ?? []) {
      for (const candidateTarget of candidateTargets) {
        if (pathsOverlap(consumer.destination, candidateTarget)) {
          bindCollisions.push(
            `candidate-target:${consumer.containerName}:${consumer.destination}:${candidateTarget}`,
          );
        }
      }
    }
  }
  return {
    schema: "platform.v1-brownfield-baseline-inspection/v1",
    authorityConflicts: uniqueSorted(authorityConflicts),
    namespaceCollisions: uniqueSorted(namespaceCollisions),
    bindCollisions: uniqueSorted(bindCollisions),
    mutationAuthorized: false,
  };
}

export function planBrownfieldControlPlane({
  activationScope = ACTIVATION_SCOPE,
  preBaseline,
  candidateExpectations = CANDIDATE_EXPECTATIONS,
} = {}) {
  const blockingConditions = [...FIXED_LOCAL_BLOCKERS];
  let baselineId = null;
  let baselineSummary = null;
  let inspection = {
    authorityConflicts: [],
    namespaceCollisions: [],
    bindCollisions: [],
  };

  if (!canonicalEqual(activationScope, ACTIVATION_SCOPE)) {
    blockingConditions.push("activation-scope: exact additive scope was widened or changed");
  }
  if (!canonicalEqual(candidateExpectations, CANDIDATE_EXPECTATIONS)) {
    blockingConditions.push("candidate-expectations: structural scope was widened or rewritten");
  }
  let validation = null;
  try {
    validation = assertCanonicalBaseline(preBaseline);
  } catch (error) {
    blockingConditions.push(`canonical-baseline: ${String(error?.message ?? error)}`);
  }
  if (validation) {
    baselineId = validation.baselineId;
    baselineSummary = validation.summary;
    inspection = inspectBrownfieldBaseline(preBaseline);
    blockingConditions.push(...inspection.authorityConflicts.map((entry) => `live-authority:${entry}`));
    blockingConditions.push(...inspection.namespaceCollisions.map((entry) => `namespace-collision:${entry}`));
    blockingConditions.push(...inspection.bindCollisions.map((entry) => `bind-collision:${entry}`));
    try {
      assertObservedVolumeFloor(validation.summary);
    } catch (error) {
      blockingConditions.push(`canonical-baseline: ${String(error?.message ?? error)}`);
    }
    try {
      assertCanonicalBaseline(preBaseline, { requireComplete: true });
    } catch (error) {
      blockingConditions.push(`canonical-baseline-completeness: ${String(error?.message ?? error)}`);
    }
  }

  return {
    schema: "platform.v1-brownfield-reference-plan/v2",
    status: "LOCAL-NOT-PREPARED",
    referenceOnly: true,
    executionAuthorized: false,
    rawBrokerEligible: false,
    projectName: CONTROL_PROJECT_NAME,
    mutationServices: [...MUTATION_SERVICES],
    replaceableServices: [],
    unknownResources: "PRESERVE",
    baselineSchema: livePreservationBaselineSchema,
    baselineId,
    baselineSummary,
    candidateEvidenceClass: CANDIDATE_EXPECTATIONS.evidenceClass,
    candidateExpectationsSha256: sha256Canonical(CANDIDATE_EXPECTATIONS),
    providerGates: PROVIDER_GATES.map((gate) => ({ ...gate })),
    authorityConflicts: inspection.authorityConflicts,
    namespaceCollisions: inspection.namespaceCollisions,
    bindCollisions: inspection.bindCollisions,
    blockingConditions: uniqueSorted(blockingConditions),
    actions: [],
  };
}

export function comparePreservation({ preBaseline, postBaseline } = {}) {
  const comparison = compareLivePreservationBaseline(preBaseline, postBaseline);
  return {
    ...comparison,
    referenceOnly: true,
    executionAuthorized: false,
    mutationAuthorized: false,
    candidateAdditionsAdmitted: false,
  };
}

export function evaluateApplyPrerequisites({ preBaseline } = {}) {
  const plan = planBrownfieldControlPlane({ preBaseline });
  return {
    schema: "platform.v1-brownfield-apply-prerequisites/v2",
    status: "STOP",
    prerequisitesSatisfied: false,
    referenceOnly: true,
    executionAuthorized: false,
    rawBrokerEligible: false,
    providerGates: PROVIDER_GATES.map((gate) => ({ ...gate })),
    blockingConditions: uniqueSorted([
      ...plan.blockingConditions,
      "external-evidence: caller-supplied READY, authenticated or signed booleans are not provider verification",
    ]),
  };
}

function readBoundedJson(filename) {
  const absolute = path.resolve(filename);
  const details = fs.lstatSync(absolute);
  if (!details.isFile() || details.isSymbolicLink() || details.size < 2 || details.size > 64 * 1024 * 1024) {
    throw new Error("Reference input must be one bounded non-symlink regular file.");
  }
  return JSON.parse(fs.readFileSync(absolute, "utf8"));
}

function parseCli(arguments_) {
  const values = [...arguments_];
  const command = values[0] && !values[0].startsWith("-") ? values.shift() : "plan";
  if (!new Set(["verify", "plan", "apply"]).has(command)) {
    throw new Error("Usage: v1-brownfield-control-plane-gate.mjs [verify|plan|apply] --input FILE");
  }
  let input = null;
  while (values.length > 0) {
    const option = values.shift();
    if (option !== "--input" || input !== null || values.length === 0) {
      throw new Error("Only one --input FILE is accepted.");
    }
    input = values.shift();
  }
  return { command, input };
}

function applyStop() {
  return {
    schema: "platform.v1-brownfield-apply-stop/v1",
    status: "STOP",
    localStatus: "LOCAL-NOT-PREPARED",
    referenceOnly: true,
    executionAuthorized: false,
    rawBrokerEligible: false,
    providerGates: PROVIDER_GATES.map((gate) => ({ ...gate })),
    blockingConditions: [
      "local reference has no provider verifier, root executor or raw Docker eligibility",
    ],
    actions: [],
  };
}

function cli(arguments_) {
  const { command, input } = parseCli(arguments_);
  if (command === "apply") return applyStop();
  if (!input) throw new Error("--input FILE is required for plan or verify.");
  const document = readBoundedJson(input);
  const preBaseline = document?.preBaseline ?? document?.baseline ?? document;
  return planBrownfieldControlPlane({ preBaseline });
}

const invoked = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  try {
    const result = cli(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = 78;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      schema: "platform.v1-brownfield-reference-error/v1",
      status: "STOP",
      localStatus: "LOCAL-NOT-PREPARED",
      referenceOnly: true,
      executionAuthorized: false,
      error: String(error?.message ?? error),
    }, null, 2)}\n`);
    process.exitCode = 78;
  }
}
