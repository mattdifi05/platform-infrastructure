import crypto from "node:crypto";

function text(value) {
  return String(value ?? "").trim();
}
function canonicalSha(value) {
  const sha = text(value).toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error("Runtime fingerprint requires a full Git commit SHA.");
  return sha;
}

function canonicalHash(value, label) {
  const hash = text(value).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error(`${label} requires a full SHA256 hash.`);
  return hash;
}

function canonicalService(item) {
  const service = text(item?.service);
  if (!service) throw new Error("Runtime fingerprint service name is required.");
  return { service, configHash: canonicalHash(item?.configHash, `Service ${service}`) };
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
    health: text(item?.health || "none").toLowerCase(),
  };
}

export function evaluateRuntimeFingerprint(expected, actual) {
  const expectedCommit = canonicalSha(expected?.commit);
  const actualCommit = canonicalSha(actual?.commit);
  const expectedProject = text(expected?.project);
  const actualProject = text(actual?.project);
  if (!expectedProject || !actualProject) throw new Error("Runtime fingerprint Compose project is required.");

  const services = (expected?.services ?? []).map(canonicalService).sort((a, b) => a.service.localeCompare(b.service));
  if (!services.length) throw new Error("Runtime fingerprint requires expected services.");
  const containers = (actual?.containers ?? []).map(canonicalContainer).sort((a, b) => a.service.localeCompare(b.service) || a.name.localeCompare(b.name));
  const expectedNames = new Set(services.map((item) => item.service));
  const issues = [];

  if (expectedCommit !== actualCommit) issues.push(`commit-mismatch:${actualCommit}`);
  if (actual?.clean !== true) issues.push("worktree-not-clean");
  if (expectedProject !== actualProject) issues.push(`project-mismatch:${actualProject}`);

  for (const expectedService of services) {
    const matches = containers.filter((container) => container.service === expectedService.service);
    if (matches.length !== 1) {
      issues.push(`${matches.length ? "duplicate" : "missing"}-service:${expectedService.service}`);
      continue;
    }
    const container = matches[0];
    if (container.project !== expectedProject) issues.push(`service-project-mismatch:${expectedService.service}`);
    if (container.configHash !== expectedService.configHash) issues.push(`config-hash-mismatch:${expectedService.service}`);
    if (!/^sha256:[a-f0-9]{64}$/.test(container.imageId)) issues.push(`image-id-missing:${expectedService.service}`);
    if (container.state !== "running") issues.push(`service-not-running:${expectedService.service}`);
    if (container.health === "unhealthy") issues.push(`service-unhealthy:${expectedService.service}`);
  }
  for (const container of containers) {
    if (!expectedNames.has(container.service)) issues.push(`unexpected-service:${container.service}`);
  }

  const canonical = {
    expected: { commit: expectedCommit, project: expectedProject, services },
    actual: { commit: actualCommit, clean: actual?.clean === true, project: actualProject, containers },
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
