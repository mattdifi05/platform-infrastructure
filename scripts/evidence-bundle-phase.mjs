import { candidateIdentityMatches, parseCandidateIdentity } from "./candidate-identity.mjs";

export const evidenceReportContextSchema = "platform.evidence-report-context/v1";
export const evidenceBundleManifestVersion = 2;
export const evidenceBundlePhaseNames = Object.freeze(["candidate-ci", "production-live"]);

const HASH = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const candidateCiRequiredLabels = Object.freeze([
  "healthcheck-coverage",
  "rate-limit-evidence",
  "audit-log-evidence",
  "retention-evidence",
]);

function cleanString(value) {
  const clean = String(value ?? "").trim();
  return clean || null;
}

function normalizedGit(git) {
  return {
    commit: cleanString(git?.commit)?.toLowerCase() ?? null,
    tree: cleanString(git?.tree)?.toLowerCase() ?? null,
    branch: cleanString(git?.branch),
    dirty: typeof git?.dirty === "boolean" ? git.dirty : null,
    repository: cleanString(git?.repository)?.toLowerCase() ?? null,
  };
}

export function normalizeEvidenceBundlePhase(value) {
  const phase = cleanString(value);
  if (!evidenceBundlePhaseNames.includes(phase)) {
    throw new Error(`Evidence bundle phase must be one of: ${evidenceBundlePhaseNames.join(", ")}.`);
  }
  return phase;
}

export function evidenceBundlePhasePolicy(phaseValue, { productionRequiredLabels = [] } = {}) {
  const phase = normalizeEvidenceBundlePhase(phaseValue);
  if (phase === "candidate-ci") {
    return {
      phase,
      authority: "candidate-only",
      requiresCandidate: false,
      requiresNotBefore: false,
      requiredLabels: [...candidateCiRequiredLabels],
    };
  }
  return {
    phase,
    authority: "production-live",
    requiresCandidate: true,
    requiresNotBefore: true,
    requiredLabels: [...new Set(productionRequiredLabels.map(String))].sort(),
  };
}

export function createEvidenceReportContext({ git, phase, command, env = {} }) {
  const normalizedPhase = cleanString(phase) ?? "unscoped";
  const github = {
    repository: cleanString(env.GITHUB_REPOSITORY)?.toLowerCase() ?? null,
    sha: cleanString(env.GITHUB_SHA)?.toLowerCase() ?? null,
    runId: cleanString(env.GITHUB_RUN_ID),
    runAttempt: cleanString(env.GITHUB_RUN_ATTEMPT),
    workflow: cleanString(env.GITHUB_WORKFLOW),
    job: cleanString(env.GITHUB_JOB),
  };
  return {
    schema: evidenceReportContextSchema,
    phase: normalizedPhase,
    command: cleanString(command),
    git: normalizedGit(git),
    github,
  };
}

function exactNonEmptyStringSet(leftInput, rightInput) {
  if (!Array.isArray(leftInput) || !Array.isArray(rightInput) || leftInput.length === 0 || rightInput.length === 0) return false;
  const clean = (values) => values.map((value) => cleanString(value)).filter(Boolean);
  const left = clean(leftInput);
  const right = clean(rightInput);
  if (left.length !== leftInput.length || right.length !== rightInput.length) return false;
  if (new Set(left).size !== left.length || new Set(right).size !== right.length) return false;
  return left.length === right.length && left.every((value) => right.includes(value));
}

export function evaluateOperationalEvidenceReport(label, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return ["offsite-restore-drill", "external-uptime"].includes(label)
      ? { passed: false, detail: "report payload is missing" }
      : null;
  }
  if (label === "offsite-restore-drill") {
    const requiredResourceIds = Array.isArray(payload.manifest?.resourceIds) ? payload.manifest.resourceIds : [];
    const successfulResourceIds = Array.isArray(payload.steps)
      ? payload.steps.filter((step) => step?.resourceId && step.status === "success").map((step) => step.resourceId)
      : [];
    const infraHealthOk = Array.isArray(payload.steps)
      && payload.steps.some((step) => step?.name === "infra-health" && step.status === "success");
    const exactResources = exactNonEmptyStringSet(requiredResourceIds, successfulResourceIds);
    const passed = payload.mode === "restore"
      && payload.status === "success"
      && payload.allowPartial !== true
      && payload.manifest?.signatureVerified === true
      && payload.exactSetVerified === true
      && payload.coverage?.complete === true
      && infraHealthOk
      && exactResources;
    return {
      passed,
      detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} signature=${payload.manifest?.signatureVerified ?? "missing"} exactSet=${payload.exactSetVerified ?? "missing"} coverage=${payload.coverage?.complete ?? "missing"} resources=${requiredResourceIds.length}`,
    };
  }
  if (label === "external-uptime") {
    const providerResults = Array.isArray(payload.providerEvidence?.results) ? payload.providerEvidence.results : [];
    const probeResults = Array.isArray(payload.results) ? payload.results : [];
    const providerNames = providerResults.filter((result) => result?.ok === true).map((result) => result.name);
    const probeNames = probeResults.filter((result) => result?.ok === true).map((result) => result.name);
    const coveredTargets = Array.isArray(payload.providerEvidence?.coveredTargets) ? payload.providerEvidence.coveredTargets : [];
    const exactProviderCoverage = exactNonEmptyStringSet(coveredTargets, providerNames)
      && exactNonEmptyStringSet(coveredTargets, probeNames)
      && Number(payload.providerEvidence?.monitorCount) === coveredTargets.length;
    const statusCompatible = payload.status === undefined || payload.status === "passed";
    const passed = payload.mode === "probe"
      && statusCompatible
      && payload.providerEvidence?.verified === true
      && payload.providerEvidence?.external === true
      && payload.providerEvidence?.authentication?.verified === true
      && providerResults.every((result) => result?.ok === true)
      && probeResults.every((result) => result?.ok === true)
      && exactProviderCoverage;
    return {
      passed,
      detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "producer-derived"} provider=${payload.providerEvidence?.verified ?? "missing"} external=${payload.providerEvidence?.external ?? "missing"} authenticated=${payload.providerEvidence?.authentication?.verified ?? "missing"} probes=${probeResults.length}`,
    };
  }
  return null;
}

function parseTime(value, label, issues) {
  const parsed = Date.parse(String(value ?? ""));
  if (!Number.isFinite(parsed)) {
    issues.push(`${label}: invalid timestamp`);
    return null;
  }
  return parsed;
}

function gitIssues(prefix, actualInput, expectedInput) {
  const issues = [];
  const actual = normalizedGit(actualInput);
  const expected = normalizedGit(expectedInput);
  if (!HASH.test(String(actual.commit ?? ""))) issues.push(`${prefix}: invalid git commit`);
  if (!HASH.test(String(actual.tree ?? ""))) issues.push(`${prefix}: invalid git tree`);
  if (actual.dirty !== false) issues.push(`${prefix}: git worktree is not clean`);
  if (expected.commit && actual.commit !== expected.commit) issues.push(`${prefix}: git commit mismatch`);
  if (expected.tree && actual.tree !== expected.tree) issues.push(`${prefix}: git tree mismatch`);
  if (expected.repository && actual.repository !== expected.repository) issues.push(`${prefix}: git repository mismatch`);
  return issues;
}

function validateReportBinding({ report, phase, sourceGit, candidate, notBeforeMs, nowMs, maxAgeHours }) {
  const issues = [];
  const prefix = `report ${report.label}`;
  const payload = report.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return [`${prefix}: payload is missing`];
  }
  const context = payload.evidenceContext;
  if (!context || context.schema !== evidenceReportContextSchema) {
    return [`${prefix}: evidence context is missing or unsupported`];
  }
  if (context.phase !== phase) issues.push(`${prefix}: phase mismatch (${context.phase ?? "missing"})`);
  issues.push(...gitIssues(prefix, context.git, sourceGit));
  if (context.github?.sha && String(context.github.sha).toLowerCase() !== String(sourceGit?.commit ?? "").toLowerCase()) {
    issues.push(`${prefix}: GitHub SHA mismatch`);
  }
  if (context.github?.repository && sourceGit?.repository) {
    const githubRepository = String(context.github.repository).toLowerCase();
    const sourceRepository = String(sourceGit.repository).toLowerCase();
    if (githubRepository !== sourceRepository && !sourceRepository.endsWith(`/${githubRepository}`)) {
      issues.push(`${prefix}: GitHub repository mismatch`);
    }
  }
  const generatedAtMs = parseTime(payload.generatedAt, `${prefix} generatedAt`, issues);
  if (generatedAtMs !== null) {
    if (generatedAtMs > nowMs + 5 * 60_000) issues.push(`${prefix}: future timestamp`);
    if (nowMs - generatedAtMs > maxAgeHours * 3_600_000) issues.push(`${prefix}: stale artifact`);
    if (notBeforeMs !== null && generatedAtMs < notBeforeMs) issues.push(`${prefix}: predates relevant phase event`);
  }
  if (candidate) {
    if (!payload.candidate) issues.push(`${prefix}: candidate is missing`);
    else if (!candidateIdentityMatches(candidate, payload.candidate)) issues.push(`${prefix}: candidate mismatch`);

    if (!payload.candidateEnd) issues.push(`${prefix}: ending candidate is missing`);
    else if (!candidateIdentityMatches(candidate, payload.candidateEnd)) issues.push(`${prefix}: ending candidate mismatch`);

    if (payload.candidateStable !== true) issues.push(`${prefix}: candidate stability proof is missing or false`);
  }
  return issues;
}

export function evaluateEvidenceBundlePhase({
  phase: phaseValue,
  expectedPhase,
  sourceGit,
  currentGit,
  candidate,
  missingRequiredEvidence = [],
  reports = [],
  productionRequiredLabels = [],
  requireComplete = false,
  notBefore,
  nowMs = Date.now(),
  maxAgeHours = 24,
  reportPasses = () => ({ passed: true, detail: "not-evaluated" }),
} = {}) {
  const issues = [];
  let policy = null;
  try {
    policy = evidenceBundlePhasePolicy(phaseValue, { productionRequiredLabels });
  } catch (error) {
    return { passed: false, complete: false, issues: [String(error?.message ?? error)], policy: null };
  }
  if (expectedPhase) {
    try {
      if (normalizeEvidenceBundlePhase(expectedPhase) !== policy.phase) issues.push(`bundle phase mismatch: expected ${expectedPhase}, found ${policy.phase}`);
    } catch (error) {
      issues.push(String(error?.message ?? error));
    }
  }
  issues.push(...gitIssues("bundle source", sourceGit, currentGit ?? sourceGit));
  if (currentGit) issues.push(...gitIssues("current verifier", currentGit, sourceGit));

  let parsedCandidate = null;
  if (policy.requiresCandidate) {
    try {
      parsedCandidate = parseCandidateIdentity(candidate, { requireTrusted: true });
      if (parsedCandidate.commit !== String(sourceGit?.commit ?? "").toLowerCase()) issues.push("bundle candidate commit mismatch");
      if (parsedCandidate.tree !== String(sourceGit?.tree ?? "").toLowerCase()) issues.push("bundle candidate tree mismatch");
    } catch (error) {
      issues.push(`bundle candidate: ${String(error?.message ?? error)}`);
    }
  } else if (candidate) {
    issues.push("candidate-ci bundle must not claim a production candidate identity");
  }

  let notBeforeMs = null;
  if (notBefore) notBeforeMs = parseTime(notBefore, "phase notBefore", issues);
  if (policy.requiresNotBefore && notBeforeMs === null) issues.push("production-live phase requires a valid notBefore event timestamp");
  const generatedNow = Number(nowMs);
  const ageLimit = Number(maxAgeHours);
  if (!Number.isFinite(generatedNow)) issues.push("invalid bundle evaluation time");
  if (!Number.isFinite(ageLimit) || ageLimit <= 0 || ageLimit > 168) issues.push("maxAgeHours must be between 0 and 168");

  const missingLabels = new Set(
    Array.isArray(missingRequiredEvidence)
      ? missingRequiredEvidence.map((item) => String(item?.label ?? ""))
      : [],
  );
  if (!Array.isArray(missingRequiredEvidence)) issues.push("missingRequiredEvidence must be an array");
  const reportsByLabel = new Map();
  for (const report of Array.isArray(reports) ? reports : []) {
    const label = String(report?.label ?? "");
    if (!reportsByLabel.has(label)) reportsByLabel.set(label, []);
    reportsByLabel.get(label).push(report);
  }

  if (requireComplete) {
    for (const label of policy.requiredLabels) {
      if (missingLabels.has(label)) issues.push(`required evidence is missing: ${label}`);
      const matches = reportsByLabel.get(label) ?? [];
      if (matches.length !== 1) {
        issues.push(`required report count must be exactly one for ${label}; found ${matches.length}`);
        continue;
      }
      const report = matches[0];
      issues.push(...validateReportBinding({
        report,
        phase: policy.phase,
        sourceGit,
        candidate: parsedCandidate,
        notBeforeMs,
        nowMs: generatedNow,
        maxAgeHours: ageLimit,
      }));
      const semantic = reportPasses(report.label, report.payload);
      if (!semantic?.passed) issues.push(`required report is phase-incompatible or not passing: ${label}; ${semantic?.detail ?? "no detail"}`);
    }
    for (const [label, matches] of reportsByLabel) {
      if (!policy.requiredLabels.includes(label)) {
        for (const report of matches) {
          issues.push(...validateReportBinding({
            report,
            phase: policy.phase,
            sourceGit,
            candidate: parsedCandidate,
            notBeforeMs,
            nowMs: generatedNow,
            maxAgeHours: ageLimit,
          }));
        }
      }
    }
  }

  const uniqueIssues = [...new Set(issues)];
  return {
    passed: uniqueIssues.length === 0,
    complete: requireComplete && uniqueIssues.length === 0,
    issues: uniqueIssues,
    policy,
    candidateId: parsedCandidate?.id ?? null,
    requiredLabels: policy.requiredLabels,
    reportLabels: [...reportsByLabel.keys()].filter(Boolean).sort(),
  };
}
