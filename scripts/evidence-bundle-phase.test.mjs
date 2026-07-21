#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { createCandidateIdentity } from "./candidate-identity.mjs";
import {
  createEvidenceReportContext,
  evaluateEvidenceBundlePhase,
  evidenceBundleManifestVersion,
} from "./evidence-bundle-phase.mjs";

const nowMs = Date.parse("2026-07-21T20:00:00.000Z");
const git = {
  commit: "1".repeat(40),
  tree: "2".repeat(40),
  branch: "main",
  dirty: false,
  repository: "github.com/example/platform-infrastructure",
};
const candidate = createCandidateIdentity({
  repository: git.repository,
  commit: git.commit,
  tree: git.tree,
  clean: true,
  projectName: "platform_infra_vps",
  workloadLockSha256: "3".repeat(64),
  renderSha256: "4".repeat(64),
});

function report(label, { phase = "candidate-ci", generatedAt = "2026-07-21T19:55:00.000Z", gitOverride = {}, payload = {} } = {}) {
  return {
    label,
    payload: {
      generatedAt,
      status: "passed",
      evidenceContext: createEvidenceReportContext({
        git: { ...git, ...gitOverride },
        phase,
        command: label,
        env: { GITHUB_SHA: gitOverride.commit ?? git.commit, GITHUB_REPOSITORY: "example/platform-infrastructure" },
      }),
      ...payload,
    },
  };
}

const candidateReports = [
  report("healthcheck-coverage"),
  report("rate-limit-evidence"),
  report("audit-log-evidence"),
  report("retention-evidence"),
];
const alwaysPasses = () => ({ passed: true, detail: "status=passed" });

test("manifest version is phase-aware and a complete ephemeral candidate bundle is accepted", () => {
  assert.equal(evidenceBundleManifestVersion, 2);
  const result = evaluateEvidenceBundlePhase({
    phase: "candidate-ci",
    expectedPhase: "candidate-ci",
    sourceGit: git,
    currentGit: git,
    reports: candidateReports,
    requireComplete: true,
    nowMs,
    reportPasses: alwaysPasses,
  });
  assert.equal(result.passed, true);
  assert.equal(result.complete, true);
  assert.equal(result.policy.authority, "candidate-only");
});

test("missing, stale, phase-incompatible, mismatched, dirty, and duplicate artifacts fail closed", () => {
  const cases = [
    { reports: candidateReports.slice(1), expected: /healthcheck-coverage/ },
    { reports: candidateReports.map((entry, index) => index === 0 ? report(entry.label, { generatedAt: "2026-07-19T00:00:00.000Z" }) : entry), expected: /stale artifact/ },
    { reports: candidateReports.map((entry, index) => index === 0 ? report(entry.label, { phase: "production-live" }) : entry), expected: /phase mismatch/ },
    { reports: candidateReports.map((entry, index) => index === 0 ? report(entry.label, { gitOverride: { tree: "a".repeat(40) } }) : entry), expected: /git tree mismatch/ },
    { reports: candidateReports.map((entry, index) => index === 0 ? report(entry.label, { gitOverride: { dirty: true } }) : entry), expected: /not clean/ },
    { reports: [...candidateReports, candidateReports[0]], expected: /exactly one/ },
  ];
  for (const fixture of cases) {
    const result = evaluateEvidenceBundlePhase({
      phase: "candidate-ci",
      sourceGit: git,
      currentGit: git,
      reports: fixture.reports,
      requireComplete: true,
      nowMs,
      reportPasses: alwaysPasses,
    });
    assert.equal(result.passed, false);
    assert.match(result.issues.join("\n"), fixture.expected);
  }
});

test("semantic report failures cannot be hidden by a complete manifest", () => {
  const result = evaluateEvidenceBundlePhase({
    phase: "candidate-ci",
    sourceGit: git,
    reports: candidateReports,
    requireComplete: true,
    nowMs,
    reportPasses: (label) => ({ passed: label !== "retention-evidence", detail: "mode=plan" }),
  });
  assert.match(result.issues.join("\n"), /phase-incompatible.*retention-evidence.*mode=plan/);
});

test("production bundles require one trusted candidate, a relevant event, and matching report bindings", () => {
  const labels = ["production-go-no-go", "runtime-fingerprint"];
  const productionReports = labels.map((label) => report(label, {
    phase: "production-live",
    payload: { candidate, candidateEnd: candidate, candidateStable: true },
  }));
  const accepted = evaluateEvidenceBundlePhase({
    phase: "production-live",
    expectedPhase: "production-live",
    sourceGit: git,
    currentGit: git,
    candidate,
    reports: productionReports,
    productionRequiredLabels: labels,
    requireComplete: true,
    notBefore: "2026-07-21T19:00:00.000Z",
    nowMs,
    reportPasses: alwaysPasses,
  });
  assert.equal(accepted.passed, true);
  assert.equal(accepted.candidateId, candidate.id);

  for (const mutation of [
    { candidate: null, notBefore: "2026-07-21T19:00:00.000Z", reports: productionReports, expected: /candidate/ },
    { candidate, notBefore: null, reports: productionReports, expected: /notBefore/ },
    { candidate, notBefore: "2026-07-21T19:56:00.000Z", reports: productionReports, expected: /predates/ },
    { candidate, notBefore: "2026-07-21T19:00:00.000Z", reports: productionReports.map((entry, index) => index === 0 ? report(entry.label, { phase: "production-live", payload: { candidate: createCandidateIdentity({ ...candidate, commit: "a".repeat(40) }) } }) : entry), expected: /candidate mismatch/ },
  ]) {
    const rejected = evaluateEvidenceBundlePhase({
      phase: "production-live",
      sourceGit: git,
      currentGit: git,
      candidate: mutation.candidate,
      reports: mutation.reports,
      productionRequiredLabels: labels,
      requireComplete: true,
      notBefore: mutation.notBefore,
      nowMs,
      reportPasses: alwaysPasses,
    });
    assert.equal(rejected.passed, false);
    assert.match(rejected.issues.join("\n"), mutation.expected);
  }
});

test("every production report requires exact start, end, and stable candidate bindings", () => {
  const labels = ["production-go-no-go"];
  const basePayload = { candidate, candidateEnd: candidate, candidateStable: true };
  const mutations = [
    { payload: { candidateEnd: candidate, candidateStable: true }, expected: /candidate is missing/ },
    { payload: { candidate, candidateStable: true }, expected: /ending candidate is missing/ },
    { payload: { candidate, candidateEnd: candidate }, expected: /candidate stability proof is missing or false/ },
    { payload: { candidate, candidateEnd: candidate, candidateStable: false }, expected: /candidate stability proof is missing or false/ },
    {
      payload: { ...basePayload, candidateEnd: createCandidateIdentity({ ...candidate, renderSha256: "a".repeat(64) }) },
      expected: /ending candidate mismatch/,
    },
  ];

  for (const mutation of mutations) {
    const result = evaluateEvidenceBundlePhase({
      phase: "production-live",
      sourceGit: git,
      currentGit: git,
      candidate,
      reports: [report(labels[0], { phase: "production-live", payload: mutation.payload })],
      productionRequiredLabels: labels,
      requireComplete: true,
      notBefore: "2026-07-21T19:00:00.000Z",
      nowMs,
      reportPasses: alwaysPasses,
    });
    assert.equal(result.passed, false);
    assert.match(result.issues.join("\n"), mutation.expected);
  }
});

test("candidate-ci manifests cannot be replayed as production-live authority", () => {
  const result = evaluateEvidenceBundlePhase({
    phase: "candidate-ci",
    expectedPhase: "production-live",
    sourceGit: git,
    reports: candidateReports,
    requireComplete: true,
    nowMs,
    reportPasses: alwaysPasses,
  });
  assert.match(result.issues.join("\n"), /bundle phase mismatch/);
});

test("report writer and ephemeral workflows enforce explicit phase contexts", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const source = fs.readFileSync(path.join(root, "scripts", "infra-ops.mjs"), "utf8");
  const candidateWorkflow = fs.readFileSync(path.join(root, ".github", "workflows", "enterprise-infra.yml"), "utf8");
  const liveWorkflow = fs.readFileSync(path.join(root, ".github", "workflows", "enterprise-live-evidence.yml"), "utf8");
  assert.match(source, /evidenceContext: createEvidenceReportContext/);
  assert.match(source, /manifest\.phase\?\.complete !== true/);
  assert.match(source, /currentGit: gitEvidence\(\)/);
  assert.match(candidateWorkflow, /EVIDENCE_REPORT_PHASE: candidate-ci/);
  assert.match(candidateWorkflow, /evidence-bundle --phase candidate-ci --strict --noArchive/);
  assert.match(candidateWorkflow, /evidence-bundle-verify --phase candidate-ci --requireComplete/);
  assert.match(liveWorkflow, /EVIDENCE_REPORT_PHASE: production-live/);
  assert.match(liveWorkflow, /evidence-bundle --phase production-live --strict --notBefore/);
  assert.match(liveWorkflow, /evidence-bundle-verify --phase production-live[\s\S]*--requireComplete/);
});
