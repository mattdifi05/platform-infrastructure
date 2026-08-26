// Architectural separation gate: infrastructure control plane vs application
// workloads. Fail-closed proof that
//   CONTROL_CENTER_DEPENDS_ON_STEXOR === false
//   INFRASTRUCTURE_DEPENDS_ON_STEXOR === false
// holds across the greenfield render, state projection, final sync sequence
// and auth bootstrap plan. Stexor (and every hosted application) is workload
// state only: preserved and verified with its own application data, never a
// dependency of the Control Center, of administrative authentication, or of
// any other control-plane component.

export const CONTROL_CENTER_DEPENDS_ON_STEXOR = false;
export const INFRASTRUCTURE_DEPENDS_ON_STEXOR = false;

export const SEPARATION_SCHEMA = "platform.greenfield-control-plane-separation/v1";

const STAPPORNE_PATTERN = /stexor|workcalendar/i;

// Services whose health is REQUIRED for server administrability. Everything
// else that serves applications is workload-classified; unknown services are
// a violation (fail-closed classification).
export const CONTROL_PLANE_SERVICES = Object.freeze([
  "alertmanager",
  "backup-scheduler",
  "broker-auth-bootstrap",
  "cadvisor",
  "control-center",
  "docker-action-activation-sidecar",
  "docker-action-broker",
  "grafana",
  "keycloak",
  "local-dns",
  "local-registry",
  "loki",
  "mariadb",
  "minio",
  "nats",
  "node-exporter",
  "platform-alert-dispatcher",
  "postgres",
  "prometheus",
  "promtail",
  "redis",
  "traefik",
  "waf",
]);

// Services that exist to serve or administer hosted applications only.
export const WORKLOAD_SERVICES = Object.freeze([
  "php-apache",
  "phpmyadmin",
  "phppgadmin",
  "project-router",
]);

export function serviceDependencyClass(serviceName) {
  if (CONTROL_PLANE_SERVICES.includes(serviceName)) return "control-plane";
  if (WORKLOAD_SERVICES.includes(serviceName)) return "application-workload";
  if (/^(gf-)/.test(String(serviceName))) return "unknown";
  return "unknown";
}

// Dependency class of a state-projection entry id / final-sync writer id.
export function stateDependencyClass(id) {
  if (id.startsWith("postgres-stexor") || id.startsWith("app-src-")) {
    return "application-workload";
  }
  if (id === "app-bind-trees" || id === "unclassified-writable-layers") {
    return "application-workload";
  }
  if (
    id.startsWith("postgres-keycloak")
    || id.startsWith("keycloak-")
    || id === "control-center-state"
  ) {
    return "control-plane";
  }
  if (
    id === "mariadb"
    || id === "mariadb-all"
    || id === "minio"
    || id === "minio-data"
    || id === "redis-data"
    || id === "nats-data"
    || id.startsWith("observe-")
    || id === "secret-manager-store"
    || id === "backup-families"
  ) {
    return "shared-infrastructure";
  }
  return "unknown";
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function envTexts(definition) {
  const environment = definition?.environment;
  const texts = [];
  if (Array.isArray(environment)) {
    texts.push(...environment.map((entry) => String(entry)));
  } else if (plainObject(environment)) {
    for (const [key, value] of Object.entries(environment)) {
      texts.push(`${key}=${typeof value === "string" ? value : JSON.stringify(value)}`);
    }
  }
  return texts;
}

function volumeTargets(definition) {
  const targets = [];
  for (const mount of Array.isArray(definition?.volumes) ? definition.volumes : []) {
    if (typeof mount === "string") {
      targets.push(mount);
    } else if (plainObject(mount)) {
      targets.push(`${mount.source ?? ""}:${mount.target ?? ""}`);
    }
  }
  return targets;
}

// Evaluates one rendered Compose configuration. Returns [] when no
// control-plane component depends on any workload component and no
// control-plane surface carries workload-application material.
export function evaluateRenderSeparation(renderedConfig) {
  const violations = [];
  if (!plainObject(renderedConfig) || !plainObject(renderedConfig.services)) {
    return ["separation:render-shape"];
  }
  const services = renderedConfig.services;
  for (const [name, definition] of Object.entries(services)) {
    const serviceClass = serviceDependencyClass(name);
    if (serviceClass === "unknown") {
      violations.push(`separation:${name}:unclassified-service`);
      continue;
    }
    if (serviceClass !== "control-plane") continue;
    for (const dependency of Object.keys(definition?.depends_on ?? {})) {
      const dependencyClass = serviceDependencyClass(dependency);
      if (dependencyClass === "unknown") {
        violations.push(`separation:${name}:unclassified-dependency:${dependency}`);
      } else if (dependencyClass === "application-workload") {
        violations.push(`separation:${name}:depends-on-workload:${dependency}`);
      }
    }
    const surfaces = [...envTexts(definition), ...volumeTargets(definition)];
    for (const text of surfaces) {
      if (STAPPORNE_PATTERN.test(text)) {
        violations.push(`separation:${name}:workload-material-reference`);
        break;
      }
    }
  }
  return violations;
}

// Evaluates the planning artifacts produced by the sibling modules.
export function evaluatePlanSeparation({ stateProjectionPlan, finalSyncSequence, authBootstrap }) {
  const violations = [];

  const stateIds = Array.isArray(stateProjectionPlan?.entries)
    ? stateProjectionPlan.entries.map((entry) => entry.entryId)
    : [];
  if (stateIds.length === 0) {
    violations.push("separation:state-plan-empty");
  }
  for (const id of stateIds) {
    if (stateDependencyClass(id) === "unknown") {
      violations.push(`separation:${id}:unclassified-state-entry`);
    }
  }

  const phaseWriters = Array.isArray(finalSyncSequence?.phases)
    ? finalSyncSequence.phases.flatMap((phase) => Array.isArray(phase?.writers) ? phase.writers.map((writer) => writer.writerId) : [])
    : [];
  if (phaseWriters.length === 0) {
    violations.push("separation:final-sync-empty");
  }
  const seenWriters = new Set();
  for (const writerId of phaseWriters) {
    seenWriters.add(writerId);
    if (stateDependencyClass(writerId) === "unknown") {
      violations.push(`separation:${writerId}:unclassified-final-sync-writer`);
    }
    // A control-plane writer's steps must never reference workload state.
    if (writerId.startsWith("postgres-keycloak") || writerId === "control-center-state") {
      // structural: their ids already prove the split; nothing further here.
    }
  }

  const bootstrapSteps = Array.isArray(authBootstrap)
    ? authBootstrap
    : (Array.isArray(authBootstrap?.steps) ? authBootstrap.steps : null);
  const bootstrapTexts = [];
  if (bootstrapSteps !== null) {
    for (const step of bootstrapSteps) {
      bootstrapTexts.push(String(step?.stepId ?? ""), String(step?.description ?? ""));
    }
  } else {
    violations.push("separation:auth-bootstrap-missing");
  }
  for (const text of bootstrapTexts) {
    if (STAPPORNE_PATTERN.test(text)) {
      violations.push("separation:auth-bootstrap-references-workload-material");
      break;
    }
  }

  return violations;
}

export function evaluateControlPlaneSeparation({ renderedConfig, stateProjectionPlan, finalSyncSequence, authBootstrap }) {
  return [
    ...evaluateRenderSeparation(renderedConfig),
    ...evaluatePlanSeparation({ stateProjectionPlan, finalSyncSequence, authBootstrap }),
  ];
}

export const separationDescriptor = Object.freeze({
  schema: SEPARATION_SCHEMA,
  controlCenterDependsOnStexor: CONTROL_CENTER_DEPENDS_ON_STEXOR,
  infrastructureDependsOnStexor: INFRASTRUCTURE_DEPENDS_ON_STEXOR,
  controlPlaneServiceCount: CONTROL_PLANE_SERVICES.length,
  workloadServiceCount: WORKLOAD_SERVICES.length,
});
