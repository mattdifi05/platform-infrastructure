// Greenfield namespace authority for V1 LOCAL_PRIVATE GREENFIELD.
// Single source of truth for every physical resource name owned by the
// greenfield runtime. Fail-closed: any collision against the frozen
// brownfield namespace (platform_infra_vps / enterprise-*) is a violation.

export const GREENFIELD_PROJECT_NAME = "platform_infra_greenfield";
export const BROWNFIELD_PROJECT_NAME = "platform_infra_vps";

export const GREENFIELD_CONTAINER_PREFIX = "gf-";
export const GREENFIELD_VOLUME_PREFIX = "greenfield_";
export const GREENFIELD_NETWORK_PREFIX = `${GREENFIELD_PROJECT_NAME}_`;
export const GREENFIELD_SECRET_PREFIX = `${GREENFIELD_PROJECT_NAME}_`;

// Host ports during the parallel phase must never collide with the frozen
// brownfield edge (80/443). CUTOVER topology takes over the canonical ports
// only after brownfield writers are quiesced and routing is switched.
export const GREENFIELD_TOPOLOGY_PARALLEL = "PARALLEL";
export const GREENFIELD_TOPOLOGY_CUTOVER = "CUTOVER";

const PARALLEL_EDGE_HTTP_BIND = "0.0.0.0:18080";
const PARALLEL_EDGE_HTTPS_BIND = "0.0.0.0:18443";
const CUTOVER_EDGE_HTTP_BIND = "0.0.0.0:80";
const CUTOVER_EDGE_HTTPS_BIND = "0.0.0.0:443";

export function greenfieldEdgeBinds(topology) {
  if (topology === GREENFIELD_TOPOLOGY_PARALLEL) {
    return { http: PARALLEL_EDGE_HTTP_BIND, https: PARALLEL_EDGE_HTTPS_BIND };
  }
  if (topology === GREENFIELD_TOPOLOGY_CUTOVER) {
    return { http: CUTOVER_EDGE_HTTP_BIND, https: CUTOVER_EDGE_HTTPS_BIND };
  }
  throw new TypeError(`Unknown greenfield topology: ${String(topology)}`);
}

// Logical data volumes owned by the greenfield project. Each maps to a fresh
// physical Docker volume named greenfield_<logical>. No external volumes are
// inherited from brownfield.
export const GREENFIELD_LOGICAL_VOLUMES = Object.freeze([
  "redis_auth_config",
  "nats_auth_config",
  "mariadb_data",
  "postgres_data",
  "redis_data",
  "keycloak_data",
  "nats_data",
  "minio_data",
  "alertmanager_data",
  "grafana_data",
  "prometheus_data",
  "loki_data",
  "local_registry_data",
  "backup_scheduler_jobs",
  "backup_scheduler_logs",
  "docker_action_activation_cas",
  "docker_action_broker_socket",
  "docker_action_broker_state",
]);

export const GREENFIELD_LOGICAL_NETWORKS = Object.freeze([
  "enterprise_net",
  "platform_edge",
  "platform_routing",
  "platform_db_admin",
  "platform_postgres",
  "platform_cache",
  "platform_bus",
  "platform_storage",
  "platform_observability",
  "platform_egress",
]);

export function greenfieldVolumeName(logicalName) {
  assertSafeLogicalName(logicalName);
  return `${GREENFIELD_VOLUME_PREFIX}${logicalName}`;
}

// Physical name for a base-topology volume key. Legacy enterprise_-prefixed
// keys are re-pointed; new keys must be clean.
export function greenfieldVolumePhysicalNameForKey(logicalKey) {
  if (typeof logicalKey !== "string" || !/^[a-z0-9][a-z0-9_-]*$/.test(logicalKey)) {
    throw new TypeError(`Invalid projected volume key: ${String(logicalKey)}`);
  }
  const legacy = logicalKey.startsWith("enterprise_");
  if (!legacy && (logicalKey.startsWith("enterprise") || logicalKey.includes("brownfield"))) {
    throw new TypeError(`Brownfield-flavoured volume key is not allowed in greenfield: ${logicalKey}`);
  }
  return `${GREENFIELD_VOLUME_PREFIX}${stripVolumePrefix(logicalKey)}`;
}

export function greenfieldNetworkName(logicalName) {
  assertSafeLogicalName(logicalName);
  return `${GREENFIELD_NETWORK_PREFIX}${logicalName}`;
}

// Physical name for a base-topology network key. Only enterprise_net is a
// sanctioned legacy key.
export function greenfieldNetworkPhysicalNameForKey(logicalKey) {
  assertProjectedLogicalName(logicalKey);
  return `${GREENFIELD_NETWORK_PREFIX}${logicalKey}`;
}

export function greenfieldContainerName(serviceName) {
  assertSafeLogicalName(serviceName);
  return `${GREENFIELD_CONTAINER_PREFIX}${serviceName}`;
}

export function greenfieldSecretPhysicalName(secretLogicalName) {
  assertSafeLogicalName(secretLogicalName);
  return `${GREENFIELD_SECRET_PREFIX}${secretLogicalName}`;
}

function assertSafeLogicalName(value) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9_-]*$/.test(value)) {
    throw new TypeError(`Invalid greenfield logical resource name: ${String(value)}`);
  }
  if (value.startsWith("enterprise") || value.includes("brownfield")) {
    throw new TypeError(`Brownfield-flavoured logical name is not allowed in greenfield: ${value}`);
  }
}

// Legacy logical keys inherited from the base compose topology. Their PHYSICAL
// names are always re-pointed into the greenfield namespace; the keys survive
// only so overlay merge semantics stay deterministic.
const SANCTIONED_LEGACY_LOGICAL_KEYS = Object.freeze(["enterprise_net"]);

function assertProjectedLogicalName(value) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9_-]*$/.test(value)) {
    throw new TypeError(`Invalid projected logical resource name: ${String(value)}`);
  }
  const sanctioned = SANCTIONED_LEGACY_LOGICAL_KEYS.includes(value);
  if (!sanctioned && (value.startsWith("enterprise") || value.includes("brownfield"))) {
    throw new TypeError(`Brownfield-flavoured logical name is not allowed in greenfield: ${value}`);
  }
}

// Core service set mirrors config/no-hosted-workloads.*.lock.json services.
export const GREENFIELD_CORE_SERVICES = Object.freeze([
  "alertmanager",
  "backup-scheduler",
  "broker-auth-bootstrap",
  "control-center",
  "docker-action-activation-sidecar",
  "docker-action-broker",
  "grafana",
  "keycloak",
  "local-dns",
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

// Services that exist outside the core lock set. They keep their profiles so
// READY_BUT_DISABLED stays disabled; names are still claimed to prevent any
// collision.
export const GREENFIELD_AUXILIARY_SERVICES = Object.freeze([
  "php-apache",
  "phpmyadmin",
  "phppgadmin",
  "node-exporter",
  "cadvisor",
  "local-registry",
]);

export const GREENFIELD_ALL_SERVICES = Object.freeze([
  ...GREENFIELD_CORE_SERVICES,
  ...GREENFIELD_AUXILIARY_SERVICES,
].sort());

// Physical names owned by the frozen brownfield runtime. Greenfield resources
// must never match or reference these.
export const BROWNFIELD_FORBIDDEN_PHYSICAL_NAMES = Object.freeze([
  BROWNFIELD_PROJECT_NAME,
  "enterprise_net",
  "enterprise_mariadb_data",
  "enterprise_local_registry_data",
]);

export function isBrownfieldOwnedPhysicalName(name) {
  if (typeof name !== "string" || name.length === 0) {
    return false;
  }
  if (BROWNFIELD_FORBIDDEN_PHYSICAL_NAMES.includes(name)) {
    return true;
  }
  if (name.startsWith("enterprise-")) {
    return true;
  }
  if (name.startsWith("enterprise_")) {
    return true;
  }
  if (name.startsWith(`${BROWNFIELD_PROJECT_NAME}_`)) {
    return true;
  }
  return false;
}

export function isGreenfieldOwnedPhysicalName(name) {
  if (typeof name !== "string" || name.length === 0) {
    return false;
  }
  return (
    name === GREENFIELD_PROJECT_NAME
    || name.startsWith(GREENFIELD_CONTAINER_PREFIX)
    || name.startsWith(GREENFIELD_VOLUME_PREFIX)
    || name.startsWith(GREENFIELD_NETWORK_PREFIX)
  );
}

// Validates a rendered Compose configuration (docker compose config JSON).
// Returns an array of violation strings; empty means the render lives fully
// inside the greenfield namespace.
export function evaluateGreenfieldNamespace(renderedConfig) {
  const violations = [];
  if (!renderedConfig || typeof renderedConfig !== "object" || Array.isArray(renderedConfig)) {
    return ["render:must-be-object"];
  }
  if (renderedConfig.name !== GREENFIELD_PROJECT_NAME) {
    violations.push("render:project-name");
  }

  const services = renderedConfig.services ?? {};
  for (const [service, definition] of Object.entries(services)) {
    if (!definition || typeof definition !== "object") {
      continue;
    }
    const containerName = definition.container_name;
    if (typeof containerName === "string") {
      if (isBrownfieldOwnedPhysicalName(containerName)) {
        violations.push(`service:${service}:container-name:brownfield`);
      } else if (containerName !== greenfieldContainerName(service)) {
        violations.push(`service:${service}:container-name:not-greenfield`);
      }
    } else {
      // Every greenfield service must pin an explicit container_name so no
      // implicit <project>-<service> name can drift or collide.
      violations.push(`service:${service}:container-name:missing`);
    }
    for (const networkLogical of Object.keys(definition.networks ?? {})) {
      // Service references use logical keys; isolation is enforced through the
      // top-level logical->physical mapping below.
      if (!Object.hasOwn(renderedConfig.networks ?? {}, networkLogical)) {
        violations.push(`service:${service}:network:undeclared:${networkLogical}`);
      }
    }
    for (const volumeRef of (definition.volumes ?? [])) {
      const entry = typeof volumeRef === "string"
        ? parseShortVolumeSyntax(volumeRef)
        : volumeRef;
      if (!entry || entry.type !== "volume") {
        continue;
      }
      const logicalSource = entry.source;
      if (typeof logicalSource !== "string" || !Object.hasOwn(renderedConfig.volumes ?? {}, logicalSource)) {
        violations.push(`service:${service}:volume:undeclared:${String(logicalSource)}`);
      }
    }
  }

  for (const [logical, declaration] of Object.entries(renderedConfig.networks ?? {})) {
    const physical = declaration?.name ?? null;
    if (physical === null) {
      violations.push(`network:${logical}:physical-name:missing`);
    } else if (isBrownfieldOwnedPhysicalName(physical)) {
      violations.push(`network:${logical}:physical-name:brownfield`);
    } else if (physical !== `${GREENFIELD_NETWORK_PREFIX}${logical}`) {
      violations.push(`network:${logical}:physical-name:not-greenfield`);
    }
  }

  for (const [logical, declaration] of Object.entries(renderedConfig.volumes ?? {})) {
    const physical = declaration?.name ?? null;
    if (physical === null) {
      violations.push(`volume:${logical}:physical-name:missing`);
    } else if (isBrownfieldOwnedPhysicalName(physical)) {
      violations.push(`volume:${logical}:physical-name:brownfield`);
    } else if (physical !== `${GREENFIELD_VOLUME_PREFIX}${stripVolumePrefix(logical)}`) {
      violations.push(`volume:${logical}:physical-name:not-greenfield`);
    }
  }

  // Configs must resolve to project-owned physical names and never be
  // external references into another runtime.
  for (const [logical, declaration] of Object.entries(renderedConfig.configs ?? {})) {
    if (declaration?.external === true) {
      violations.push(`config:${logical}:external`);
      continue;
    }
    const physical = typeof declaration?.name === "string" ? declaration.name : null;
    if (physical !== null && isBrownfieldOwnedPhysicalName(physical)) {
      violations.push(`config:${logical}:physical-name:brownfield`);
    }
  }

  // Secrets must be project-prefixed file-backed declarations; an external or
  // brownfield-owned secret name would silently re-import another runtime's
  // credential material.
  for (const [logical, declaration] of Object.entries(renderedConfig.secrets ?? {})) {
    if (declaration?.external === true) {
      violations.push(`secret:${logical}:external`);
      continue;
    }
    const physical = typeof declaration?.name === "string" ? declaration.name : "";
    const file = typeof declaration?.file === "string" ? declaration.file : "";
    const ownedName = physical.startsWith(GREENFIELD_SECRET_PREFIX);
    const ownedFile = file.includes("/secrets/") || file.endsWith(".txt");
    if (!ownedName && !ownedFile) {
      violations.push(`secret:${logical}:authority`);
    } else if (physical.length > 0 && isBrownfieldOwnedPhysicalName(physical)) {
      violations.push(`secret:${logical}:physical-name:brownfield`);
    }
  }

  return violations;
}

function stripVolumePrefix(logicalKey) {
  // Base compose uses enterprise_-prefixed keys for legacy data volumes; the
  // greenfield projection keeps those keys but re-points their physical names.
  return logicalKey.replace(/^enterprise_/, "");
}

function parseShortVolumeSyntax(raw) {
  const parts = String(raw).split(":");
  if (parts.length < 2 || parts.length > 3) {
    return null;
  }
  return { type: "volume", source: parts[0], target: parts[1] };
}

export const greenfieldNamespaceDescriptor = Object.freeze({
  schema: "platform.greenfield-namespace/v1",
  projectName: GREENFIELD_PROJECT_NAME,
  containerPrefix: GREENFIELD_CONTAINER_PREFIX,
  volumePrefix: GREENFIELD_VOLUME_PREFIX,
  networkPrefix: GREENFIELD_NETWORK_PREFIX,
  secretPrefix: GREENFIELD_SECRET_PREFIX,
  coreServiceCount: GREENFIELD_CORE_SERVICES.length,
  auxiliaryServiceCount: GREENFIELD_AUXILIARY_SERVICES.length,
});
