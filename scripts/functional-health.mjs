import crypto from "node:crypto";

export function validateFunctionalHealthProbes(probes) {
  if (!Array.isArray(probes) || probes.length === 0) throw new Error("Functional health probes are required.");
  const seen = new Set();
  return probes.map((probe) => {
    const id = String(probe?.id || "").trim();
    const kind = String(probe?.kind || "http").trim();
    if (!id || seen.has(id)) throw new Error(`Invalid or duplicate functional health probe: ${id || "missing"}.`);
    if (!String(probe?.container || "").trim()) throw new Error(`Probe ${id} must name a container.`);
    if (!["http", "dns"].includes(kind)) throw new Error(`Probe ${id} must be HTTP or DNS, never process-only.`);
    if (kind === "http") {
      if (!Number.isInteger(probe.port) || probe.port <= 0) throw new Error(`Probe ${id} has an invalid port.`);
      if (!String(probe.path || "").startsWith("/")) throw new Error(`Probe ${id} has an invalid path.`);
      if (!Array.isArray(probe.expectedStatuses) || probe.expectedStatuses.length === 0) throw new Error(`Probe ${id} needs expected HTTP statuses.`);
    }
    if (kind === "dns" && !String(probe.query || "").trim()) throw new Error(`Probe ${id} needs a DNS query.`);
    seen.add(id);
    return { ...probe, id, kind };
  });
}

export function evaluateFunctionalHealth(probes, observations) {
  const catalog = validateFunctionalHealthProbes(probes);
  const byId = new Map((Array.isArray(observations) ? observations : []).map((item) => [item.id, item]));
  const checks = catalog.map((probe) => {
    const observation = byId.get(probe.id);
    let passed = Boolean(observation && !observation.error);
    if (passed && probe.kind === "http") {
      passed = probe.expectedStatuses.includes(Number(observation.status));
      if (passed && probe.bodyIncludes) passed = String(observation.body || "").includes(probe.bodyIncludes);
    }
    if (passed && probe.kind === "dns") passed = Array.isArray(observation.answers) && observation.answers.length > 0;
    return {
      id: probe.id,
      kind: probe.kind,
      container: probe.container,
      passed,
      status: observation?.status ?? null,
      latencyMs: Number(observation?.latencyMs ?? 0),
      error: observation?.error ? "probe-failed" : null,
    };
  });
  const canonical = JSON.stringify(checks.map(({ id, kind, container, passed, status }) => ({ id, kind, container, passed, status })));
  return {
    status: checks.every((check) => check.passed) ? "passed" : "failed",
    checks,
    fingerprint: crypto.createHash("sha256").update(canonical).digest("hex"),
  };
}
