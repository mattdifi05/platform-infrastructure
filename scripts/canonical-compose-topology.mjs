import { createHash } from "node:crypto";
import path from "node:path";

function requiredIdentifier(value, label) {
  const clean = String(value ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(clean)) throw new Error(`Invalid ${label}.`);
  return clean;
}

function displayPath(root, filePath) {
  const relative = path.relative(root, filePath).replaceAll("\\", "/");
  return relative && !relative.startsWith("../") && relative !== ".." ? relative : filePath;
}

export function canonicalVpsTopologyPlan({ infraRoot, envFile, projectName = "platform_infra_vps", workloadLock = "" }) {
  const root = path.resolve(String(infraRoot ?? ""));
  const resolvedEnvFile = path.resolve(root, String(envFile ?? ""));
  const cleanProjectName = requiredIdentifier(projectName, "Compose project name");
  const rawLock = String(workloadLock ?? "").trim();
  const resolvedWorkloadLock = rawLock ? path.resolve(root, rawLock) : null;
  const wrapper = path.join(root, "scripts", "compose-vps.sh");
  return {
    source: "scripts/compose-vps.sh",
    root,
    envFile: resolvedEnvFile,
    envFileDisplay: displayPath(root, resolvedEnvFile),
    projectName: cleanProjectName,
    workloadLock: resolvedWorkloadLock,
    workloadLockDisplay: resolvedWorkloadLock ? displayPath(root, resolvedWorkloadLock) : null,
    command: {
      bin: "bash",
      args: [wrapper, "config", "--format", "json"],
      env: {
        COMPOSE_ENV_FILE: resolvedEnvFile,
        COMPOSE_PROJECT_NAME: cleanProjectName,
        HOSTED_WORKLOAD_LOCK: resolvedWorkloadLock ?? "",
        HOSTED_WORKLOAD_ALLOW_RESOLVED: "0",
      },
    },
  };
}

export function parseCanonicalVpsTopology(configText, plan, { workloadLockSha256 = null } = {}) {
  let config;
  try {
    config = JSON.parse(String(configText ?? ""));
  } catch {
    throw new Error("Canonical VPS Compose render was not valid JSON.");
  }
  if (!config || typeof config !== "object" || Array.isArray(config) || !config.services || !config.networks) {
    throw new Error("Canonical VPS Compose render must declare services and networks.");
  }
  const serviceNames = Object.keys(config.services).sort();
  const networkNames = Object.keys(config.networks).sort();
  if (!serviceNames.length || !networkNames.length) throw new Error("Canonical VPS Compose render is empty.");
  const hostedWorkloadIds = [...new Set(Object.values(config.services)
    .map((service) => String(service?.labels?.["com.platform.workload-id"] ?? "").trim())
    .filter(Boolean))].sort();
  const renderSha256 = createHash("sha256").update(String(configText)).digest("hex");
  return {
    config,
    evidence: {
      source: plan.source,
      projectName: plan.projectName,
      envFile: plan.envFileDisplay,
      workloadLock: plan.workloadLock ? {
        path: plan.workloadLockDisplay,
        sha256: workloadLockSha256,
        verifiedOnly: true,
      } : null,
      renderSha256,
      serviceNames,
      networkNames,
      hostedWorkloadIds,
    },
  };
}
