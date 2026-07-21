import { createHash } from "node:crypto";

export const candidateIdentitySchema = "platform.release-candidate/v1";

function requiredHash(value, label, lengths = [64]) {
  const clean = String(value ?? "").trim().toLowerCase();
  if (!lengths.includes(clean.length) || !/^[a-f0-9]+$/.test(clean)) throw new Error(`Invalid ${label}.`);
  return clean;
}

function requiredProject(value) {
  const clean = String(value ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(clean)) throw new Error("Invalid candidate Compose project name.");
  return clean;
}

export function normalizeRepositoryIdentity(value) {
  let clean = String(value ?? "").trim();
  if (!clean || clean.length > 512 || /[\0\r\n]/.test(clean)) throw new Error("Candidate repository identity is required.");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(clean)) {
    let url;
    try {
      url = new URL(clean);
    } catch {
      throw new Error("Invalid candidate repository URL.");
    }
    clean = `${url.hostname}/${url.pathname.replace(/^\/+/, "")}`;
  } else {
    clean = clean.replace(/^[^@/]+@/, "");
    if (/^[^/:]+:.+/.test(clean)) clean = clean.replace(":", "/");
  }
  clean = clean.replace(/^\/+|\/+$/g, "").replace(/\.git$/i, "").replace(/\/{2,}/g, "/").toLowerCase();
  const parts = clean.split("/");
  if (parts.length < 2 || parts.some((part) => !part || part === "." || part === ".." || !/^[a-z0-9._-]+$/.test(part))) {
    throw new Error("Invalid candidate repository identity.");
  }
  return clean;
}

function canonicalCandidate(input) {
  const workloadLockSha256 = requiredHash(input.workloadLockSha256, "candidate workload lock SHA256");
  if (typeof input.clean !== "boolean") throw new Error("Candidate clean state must be explicit.");
  return {
    schema: candidateIdentitySchema,
    repository: normalizeRepositoryIdentity(input.repository),
    commit: requiredHash(input.commit, "candidate commit", [40, 64]),
    tree: requiredHash(input.tree, "candidate tree", [40, 64]),
    clean: input.clean,
    projectName: requiredProject(input.projectName),
    workloadLockSha256,
    renderSha256: requiredHash(input.renderSha256, "candidate render SHA256"),
  };
}

export function createCandidateIdentity(input) {
  const canonical = canonicalCandidate(input ?? {});
  const id = createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
  return { ...canonical, id, trusted: canonical.clean === true };
}

export function parseCandidateIdentity(input, { requireTrusted = false } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Candidate identity is missing.");
  if (input.schema !== candidateIdentitySchema) throw new Error("Unsupported candidate identity schema.");
  const parsed = createCandidateIdentity(input);
  if (String(input.id ?? "").toLowerCase() !== parsed.id) throw new Error("Candidate identity digest mismatch.");
  if (requireTrusted && !parsed.trusted) throw new Error("Candidate identity is not trusted because the worktree was dirty.");
  return parsed;
}

export function candidateIdentityMatches(expectedInput, actualInput, { requireTrusted = true } = {}) {
  try {
    const expected = parseCandidateIdentity(expectedInput, { requireTrusted });
    const actual = parseCandidateIdentity(actualInput, { requireTrusted });
    return expected.id === actual.id;
  } catch {
    return false;
  }
}

export function evaluateCandidateReportBinding(payload, currentCandidateInput, { kind, maxAgeHours, nowMs = Date.now() } = {}) {
  const issues = [];
  let current = null;
  try {
    current = parseCandidateIdentity(currentCandidateInput, { requireTrusted: true });
  } catch (error) {
    issues.push(`current-candidate:${String(error?.message ?? error)}`);
  }
  if (!current || !candidateIdentityMatches(current, payload?.candidate)) issues.push("candidate-identity-mismatch");
  if (payload?.candidateStable !== true || !candidateIdentityMatches(payload?.candidate, payload?.candidateEnd)) issues.push("candidate-changed-during-report");
  const generatedAt = Date.parse(String(payload?.generatedAt ?? ""));
  if (!Number.isFinite(generatedAt)) issues.push("invalid-generated-at");
  else {
    if (generatedAt > nowMs + 5 * 60 * 1000) issues.push("future-generated-at");
    if (Number.isFinite(Number(maxAgeHours)) && nowMs - generatedAt > Number(maxAgeHours) * 3600000) issues.push("stale-report");
  }
  if (current && kind === "release") {
    if (String(payload?.releaseSha ?? "").toLowerCase() !== current.commit) issues.push("release-commit-mismatch");
  }
  if (current && kind === "github-actions") {
    if (String(payload?.expectedSha ?? "").toLowerCase() !== current.commit) issues.push("github-commit-mismatch");
    try {
      if (normalizeRepositoryIdentity(payload?.repo) !== current.repository) issues.push("github-repository-mismatch");
    } catch {
      issues.push("github-repository-mismatch");
    }
  }
  if (current && kind === "runtime-fingerprint") {
    if (String(payload?.git?.commit ?? "").toLowerCase() !== current.commit) issues.push("runtime-commit-mismatch");
    if (String(payload?.git?.tree ?? "").toLowerCase() !== current.tree) issues.push("runtime-tree-mismatch");
    if (payload?.git?.dirty !== false) issues.push("runtime-worktree-not-clean");
  }
  return { passed: issues.length === 0, issues };
}
