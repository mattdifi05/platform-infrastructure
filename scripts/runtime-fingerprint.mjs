import crypto from "node:crypto";

function text(value) {
  return String(value ?? "").trim();
}

function canonicalGitObject(value, label) {
  const sha = text(value).toLowerCase();
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(sha)) throw new Error(`${label} requires a full Git object ID.`);
  return sha;
}

function canonicalHash(value, label) {
  const hash = text(value).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error(`${label} requires a full SHA256 hash.`);
  return hash;
}

function canonicalImageId(value, label) {
  const imageId = text(value).toLowerCase();
  if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) throw new Error(`${label} requires an exact sha256 image ID.`);
  return imageId;
}

function canonicalDeploymentId(value) {
  const deploymentId = text(value);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(deploymentId)) {
    throw new Error("Runtime fingerprint requires an exact deployment ID.");
  }
  return deploymentId;
}

function canonicalCandidate(value) {
  if (value?.schema !== "platform.release-candidate/v1") {
    throw new Error("Runtime fingerprint requires a platform.release-candidate/v1 identity.");
  }
  const repository = text(value?.repository);
  const projectName = text(value?.projectName);
  if (!repository || /[\0\r\n]/.test(repository)) throw new Error("Runtime fingerprint candidate repository is required.");
  if (!projectName || /[\0\r\n]/.test(projectName)) throw new Error("Runtime fingerprint candidate project is required.");
  if (value?.clean !== true || value?.trusted !== true) throw new Error("Runtime fingerprint candidate must be clean and trusted.");
  return {
    schema: "platform.release-candidate/v1",
    id: canonicalHash(value?.id, "Runtime fingerprint candidate ID"),
    repository,
    commit: canonicalGitObject(value?.commit, "Runtime fingerprint commit"),
    tree: canonicalGitObject(value?.tree, "Runtime fingerprint tree"),
    clean: true,
    projectName,
    workloadLockSha256: canonicalHash(value?.workloadLockSha256, "Runtime fingerprint workload lock"),
    renderSha256: canonicalHash(value?.renderSha256, "Runtime fingerprint Compose render"),
    trusted: true,
  };
}

function canonicalTimestamp(value, label) {
  const timestamp = text(value);
  const milliseconds = Date.parse(timestamp);
  if (!timestamp || !Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== timestamp) {
    throw new Error(`${label} requires a canonical ISO timestamp.`);
  }
  return { timestamp, milliseconds };
}

function canonicalService(item) {
  const service = text(item?.service);
  const imageRef = text(item?.imageRef);
  const expectedState = text(item?.expectedState || "running").toLowerCase();
  if (!service) throw new Error("Runtime fingerprint service name is required.");
  if (!imageRef || /[\0\r\n]/.test(imageRef)) throw new Error(`Service ${service} requires an exact image reference.`);
  if (!new Set(["running", "completed"]).has(expectedState)) throw new Error(`Service ${service} has an invalid expected runtime state.`);
  return {
    service,
    configHash: canonicalHash(item?.configHash, `Service ${service} config`),
    imageId: canonicalImageId(item?.imageId, `Service ${service}`),
    imageRef,
    expectedState,
  };
}

function canonicalContainer(item) {
  const service = text(item?.service);
  const name = text(item?.name).replace(/^\//, "");
  if (!service || !name) throw new Error("Runtime fingerprint container name and service are required.");
  return {
    name,
    service,
    project: text(item?.project),
    configHash: text(item?.configHash).toLowerCase(),
    imageId: text(item?.imageId).toLowerCase(),
    imageRef: text(item?.imageRef),
    state: text(item?.state).toLowerCase(),
    exitCode: Number(item?.exitCode),
    health: text(item?.health || "none").toLowerCase(),
    startedAt: text(item?.startedAt),
    runtimeCommit: text(item?.runtimeCommit).toLowerCase(),
    runtimeTree: text(item?.runtimeTree).toLowerCase(),
    runtimeCandidateId: text(item?.runtimeCandidateId).toLowerCase(),
    runtimeDeploymentId: text(item?.runtimeDeploymentId),
    runtimeRenderSha256: text(item?.runtimeRenderSha256).toLowerCase(),
    runtimeWorkloadLockSha256: text(item?.runtimeWorkloadLockSha256).toLowerCase(),
  };
}

function assertUniqueServices(services, label) {
  const seen = new Set();
  for (const item of services) {
    if (seen.has(item.service)) throw new Error(`${label} contains duplicate service ${item.service}.`);
    seen.add(item.service);
  }
}

export function runtimeConfigurationSha256(services) {
  const config = [...services]
    .map((item) => ({ service: text(item?.service), configHash: text(item?.configHash).toLowerCase() }))
    .sort((left, right) => left.service.localeCompare(right.service));
  if (!config.length || config.some((item) => !item.service || !/^[a-f0-9]{64}$/.test(item.configHash))) {
    throw new Error("Runtime configuration digest requires exact service config hashes.");
  }
  assertUniqueServices(config, "Runtime configuration");
  return crypto.createHash("sha256").update(JSON.stringify(config)).digest("hex");
}

export function evaluateRuntimeFingerprint(expected, actual) {
  const candidate = canonicalCandidate(expected?.candidate);
  const expectedCommit = candidate.commit;
  const expectedTree = candidate.tree;
  const deploymentId = canonicalDeploymentId(expected?.deploymentId);
  const deploymentStarted = canonicalTimestamp(expected?.deploymentStartedAt, "Runtime fingerprint deployment start");
  const workloadLockSha256 = candidate.workloadLockSha256;
  const expectedProject = candidate.projectName;
  const actualProject = text(actual?.project);
  if (!expectedProject || !actualProject) throw new Error("Runtime fingerprint Compose project is required.");

  const services = (expected?.services ?? []).map(canonicalService).sort((a, b) => a.service.localeCompare(b.service));
  if (!services.length) throw new Error("Runtime fingerprint requires expected services.");
  assertUniqueServices(services, "Runtime fingerprint target");
  const expectedConfigurationSha256 = canonicalHash(expected?.serviceConfigSha256, "Runtime fingerprint service configuration");
  if (runtimeConfigurationSha256(services) !== expectedConfigurationSha256) {
    throw new Error("Runtime fingerprint target configuration digest does not match its service records.");
  }

  const containers = (actual?.containers ?? []).map(canonicalContainer).sort((a, b) => a.service.localeCompare(b.service) || a.name.localeCompare(b.name));
  const expectedNames = new Set(services.map((item) => item.service));
  const issues = [];

  if (text(actual?.checkoutCommit).toLowerCase() !== expectedCommit) issues.push("checkout-commit-mismatch");
  if (text(actual?.checkoutTree).toLowerCase() !== expectedTree) issues.push("checkout-tree-mismatch");
  if (actual?.clean !== true) issues.push("worktree-not-clean");
  if (expectedProject !== actualProject) issues.push(`project-mismatch:${actualProject}`);
  if (text(actual?.workloadLockSha256).toLowerCase() !== workloadLockSha256) issues.push("observed-workload-lock-mismatch");
  if (text(actual?.renderSha256).toLowerCase() !== candidate.renderSha256) issues.push("observed-render-mismatch");

  for (const expectedService of services) {
    const matches = containers.filter((container) => container.service === expectedService.service);
    if (matches.length !== 1) {
      issues.push(`${matches.length ? "duplicate" : "missing"}-service:${expectedService.service}`);
      continue;
    }
    const container = matches[0];
    if (container.project !== expectedProject) issues.push(`service-project-mismatch:${expectedService.service}`);
    if (container.configHash !== expectedService.configHash) issues.push(`config-hash-mismatch:${expectedService.service}`);
    if (container.imageRef !== expectedService.imageRef) issues.push(`image-ref-mismatch:${expectedService.service}`);
    if (container.imageId !== expectedService.imageId) issues.push(`image-id-mismatch:${expectedService.service}`);
    if (container.runtimeCommit !== expectedCommit) issues.push(`runtime-commit-mismatch:${expectedService.service}`);
    if (container.runtimeTree !== expectedTree) issues.push(`runtime-tree-mismatch:${expectedService.service}`);
    if (container.runtimeCandidateId !== candidate.id) issues.push(`runtime-candidate-mismatch:${expectedService.service}`);
    if (container.runtimeDeploymentId !== deploymentId) issues.push(`runtime-deployment-mismatch:${expectedService.service}`);
    if (container.runtimeRenderSha256 !== candidate.renderSha256) issues.push(`runtime-render-mismatch:${expectedService.service}`);
    if (container.runtimeWorkloadLockSha256 !== workloadLockSha256) issues.push(`runtime-workload-lock-mismatch:${expectedService.service}`);
    const startedAt = Date.parse(container.startedAt);
    if (!Number.isFinite(startedAt) || startedAt < deploymentStarted.milliseconds) issues.push(`container-predates-deployment:${expectedService.service}`);
    if (expectedService.expectedState === "running" && container.state !== "running") issues.push(`service-not-running:${expectedService.service}`);
    if (expectedService.expectedState === "completed" && (container.state !== "exited" || container.exitCode !== 0)) {
      issues.push(`service-not-completed:${expectedService.service}`);
    }
    if (expectedService.expectedState === "running" && container.health === "unhealthy") issues.push(`service-unhealthy:${expectedService.service}`);
  }
  for (const container of containers) {
    if (!expectedNames.has(container.service)) issues.push(`unexpected-service:${container.service}`);
  }

  let actualConfigurationSha256 = null;
  try {
    actualConfigurationSha256 = runtimeConfigurationSha256(containers);
  } catch {
    issues.push("observed-configuration-invalid");
  }
  if (actualConfigurationSha256 && actualConfigurationSha256 !== expectedConfigurationSha256) {
    issues.push("observed-configuration-mismatch");
  }

  const canonical = {
    expected: {
      candidate,
      deploymentId,
      deploymentStartedAt: deploymentStarted.timestamp,
      serviceConfigSha256: expectedConfigurationSha256,
      services,
    },
    actual: {
      checkoutCommit: text(actual?.checkoutCommit).toLowerCase(),
      checkoutTree: text(actual?.checkoutTree).toLowerCase(),
      clean: actual?.clean === true,
      project: actualProject,
      workloadLockSha256: text(actual?.workloadLockSha256).toLowerCase(),
      renderSha256: text(actual?.renderSha256).toLowerCase(),
      configurationSha256: actualConfigurationSha256,
      containers,
    },
  };
  return {
    status: issues.length ? "failed" : "passed",
    issues,
    expectedServiceCount: services.length,
    actualContainerCount: containers.length,
    fingerprint: crypto.createHash("sha256").update(JSON.stringify(canonical)).digest("hex"),
    ...canonical,
  };
}
