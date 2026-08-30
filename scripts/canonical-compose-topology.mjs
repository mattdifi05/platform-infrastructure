import { createHash } from "node:crypto";
import path from "node:path";

function requiredIdentifier(value, label) {
  const clean = String(value ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(clean)) throw new Error(`Invalid ${label}.`);
  return clean;
}

function requiredSha256(value, label) {
  const clean = String(value ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(clean)) throw new Error(`Invalid ${label}.`);
  return clean;
}

const NO_HOSTED_WORKLOAD_LOCKS = Object.freeze({
  VPS: Object.freeze({
    path: "config/no-hosted-workloads.lock.json",
    sha256: "70e476932a904d2f54d96cc9934d58111a411ad125c484a73966397d0935caf9",
  }),
  LOCAL_PRIVATE: Object.freeze({
    path: "config/no-hosted-workloads.local-private.lock.json",
    sha256: "6320478fbeac47ffe45a1470d171894094d0e4a21cd8a7a324d4d262f602e15e",
  }),
});

function displayPath(root, filePath) {
  const relative = path.relative(root, filePath).replaceAll("\\", "/");
  return relative && !relative.startsWith("../") && relative !== ".." ? relative : filePath;
}

export function canonicalVpsTopologyPlan({
  infraRoot,
  envFile,
  projectName = "platform_infra_vps",
  workloadLock = "",
  workloadMode,
  composeVariant = "VPS",
}) {
  const root = path.resolve(String(infraRoot ?? ""));
  const resolvedEnvFile = path.resolve(root, String(envFile ?? ""));
  const cleanProjectName = requiredIdentifier(projectName, "Compose project name");
  const rawLock = String(workloadLock ?? "").trim();
  const cleanWorkloadMode = String(workloadMode ?? "").trim();
  const cleanComposeVariant = String(composeVariant ?? "").trim();
  if (!Object.hasOwn(NO_HOSTED_WORKLOAD_LOCKS, cleanComposeVariant)) {
    throw new Error("Canonical VPS topology requires exact VPS or LOCAL_PRIVATE Compose variant.");
  }
  if (!new Set(["hosted", "no-hosted"]).has(cleanWorkloadMode)) {
    throw new Error("Canonical VPS topology requires exact hosted or no-hosted workload mode.");
  }
  if (cleanWorkloadMode === "hosted" && !rawLock) {
    throw new Error("Hosted workload lock is required for canonical VPS topology.");
  }
  if (cleanWorkloadMode === "no-hosted" && rawLock) {
    throw new Error("No-hosted canonical VPS topology forbids a Hosted workload lock.");
  }
  if (cleanComposeVariant === "LOCAL_PRIVATE" && cleanWorkloadMode !== "no-hosted") {
    throw new Error("LOCAL_PRIVATE Compose variant requires the canonical no-hosted runtime.");
  }
  const noHostedAuthority = NO_HOSTED_WORKLOAD_LOCKS[cleanComposeVariant];
  const resolvedWorkloadLock = cleanWorkloadMode === "hosted"
    ? path.resolve(root, rawLock)
    : path.join(root, noHostedAuthority.path);
  const wrapper = path.join(root, "scripts", "compose-vps.sh");
  const lockVerifier = path.join(root, "scripts", "hosted-workload-lock.sh");
  return {
    source: "scripts/compose-vps.sh",
    root,
    envFile: resolvedEnvFile,
    envFileDisplay: displayPath(root, resolvedEnvFile),
    projectName: cleanProjectName,
    composeVariant: cleanComposeVariant,
    workloadMode: cleanWorkloadMode,
    workloadLock: resolvedWorkloadLock,
    workloadLockDisplay: displayPath(root, resolvedWorkloadLock),
    expectedWorkloadLockSha256: cleanWorkloadMode === "no-hosted"
      ? noHostedAuthority.sha256
      : null,
    verification: cleanWorkloadMode === "hosted" ? {
      bin: "sh",
      args: [lockVerifier, resolvedWorkloadLock, "verify"],
      env: { HOSTED_WORKLOAD_ALLOW_RESOLVED: "0" },
    } : null,
    command: {
      bin: "bash",
      args: [wrapper, "config", "--format", "json"],
      env: {
        COMPOSE_ENV_FILE: resolvedEnvFile,
        COMPOSE_PROJECT_NAME: cleanProjectName,
        HOSTED_WORKLOAD_LOCK: cleanWorkloadMode === "hosted" ? resolvedWorkloadLock : "",
        HOSTED_WORKLOAD_MODE: cleanWorkloadMode,
        HOSTED_WORKLOAD_ALLOW_RESOLVED: "0",
        ...(cleanComposeVariant === "LOCAL_PRIVATE"
          ? { PLATFORM_COMPOSE_VARIANT: "LOCAL_PRIVATE" }
          : {}),
        ...(cleanWorkloadMode === "no-hosted"
          ? { HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: resolvedWorkloadLock }
          : {}),
      },
    },
  };
}

export function parseCanonicalVpsTopology(configText, plan, { workloadLockSha256 = null } = {}) {
  if (!plan?.workloadLock || !new Set(["hosted", "no-hosted"]).has(plan.workloadMode)) {
    throw new Error("Canonical VPS topology authority is incomplete.");
  }
  const lockSha256 = requiredSha256(workloadLockSha256, "workload authority lock SHA256");
  if (plan.expectedWorkloadLockSha256 && lockSha256 !== plan.expectedWorkloadLockSha256) {
    throw new Error("Canonical no-hosted workload lock SHA256 mismatch.");
  }
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
      workloadLock: {
        mode: plan.workloadMode,
        path: plan.workloadLockDisplay,
        sha256: lockSha256,
        verifiedOnly: true,
      },
      renderSha256,
      serviceNames,
      networkNames,
      hostedWorkloadIds,
    },
  };
}
