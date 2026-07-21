#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { candidateIdentityMatches, createCandidateIdentity, evaluateCandidateReportBinding, normalizeRepositoryIdentity } from "./candidate-identity.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const nowMs = Date.parse("2026-07-21T12:00:00.000Z");
const base = {
  repository: "github.com/example/platform-infrastructure",
  commit: "1".repeat(40),
  tree: "2".repeat(40),
  clean: true,
  projectName: "platform_infra_vps",
  workloadLockSha256: "3".repeat(64),
  renderSha256: "4".repeat(64),
};
const candidate = createCandidateIdentity(base);

test("normalizes repository URLs without retaining credentials", () => {
  assert.equal(normalizeRepositoryIdentity("https://token@example.test/Owner/Repo.git"), "example.test/owner/repo");
  assert.equal(normalizeRepositoryIdentity("git@example.test:Owner/Repo.git"), "example.test/owner/repo");
});

test("exact clean candidate and reports are accepted", () => {
  const generatedAt = new Date(nowMs - 60_000).toISOString();
  const binding = { generatedAt, candidate, candidateEnd: candidate, candidateStable: true };
  assert.equal(candidate.trusted, true);
  assert.equal(evaluateCandidateReportBinding({ ...binding, releaseSha: base.commit }, candidate, { kind: "release", maxAgeHours: 24, nowMs }).passed, true);
  assert.equal(evaluateCandidateReportBinding({ ...binding, repo: base.repository, expectedSha: base.commit }, candidate, { kind: "github-actions", maxAgeHours: 24, nowMs }).passed, true);
  assert.equal(evaluateCandidateReportBinding({ ...binding, git: { commit: base.commit, tree: base.tree, dirty: false } }, candidate, { kind: "runtime-fingerprint", maxAgeHours: 24, nowMs }).passed, true);
});

test("prior commit, wrong tree, repository, workload lock, and render are rejected", () => {
  for (const mutation of [
    { commit: "a".repeat(40) },
    { tree: "b".repeat(40) },
    { repository: "github.com/example/other" },
    { workloadLockSha256: "c".repeat(64) },
    { renderSha256: "d".repeat(64) },
  ]) assert.equal(candidateIdentityMatches(candidate, createCandidateIdentity({ ...base, ...mutation })), false);
});

test("production candidate identity requires a non-null exact workload lock and render", () => {
  for (const workloadLockSha256 of [null, undefined, ""]) {
    assert.throws(
      () => createCandidateIdentity({ ...base, workloadLockSha256 }),
      /workload lock SHA256/,
    );
  }
  const source = readFileSync(path.join(repositoryRoot, "scripts", "infra-ops.mjs"), "utf8");
  const identity = source.slice(source.indexOf("function currentCandidateIdentity"), source.indexOf("function currentCandidateIdentityEvidence"));
  assert.match(identity, /workloadLockSha256: topology\.workloadLock\.sha256/);
  assert.doesNotMatch(identity, /workloadLock\?\.|\?\? null/);
});

test("mixed, stale, future, dirty, and digest-tampered reports fail closed", () => {
  const prior = createCandidateIdentity({ ...base, commit: "a".repeat(40) });
  const mixed = evaluateCandidateReportBinding({ generatedAt: new Date(nowMs - 60_000).toISOString(), candidate: prior, candidateEnd: prior, candidateStable: true, releaseSha: prior.commit }, candidate, { kind: "release", maxAgeHours: 24, nowMs });
  assert.match(mixed.issues.join(","), /candidate-identity-mismatch/);
  assert.match(evaluateCandidateReportBinding({ generatedAt: new Date(nowMs - 25 * 3600000).toISOString(), candidate, candidateEnd: candidate, candidateStable: true, releaseSha: candidate.commit }, candidate, { kind: "release", maxAgeHours: 24, nowMs }).issues.join(","), /stale-report/);
  assert.match(evaluateCandidateReportBinding({ generatedAt: new Date(nowMs + 10 * 60_000).toISOString(), candidate, candidateEnd: candidate, candidateStable: true, releaseSha: candidate.commit }, candidate, { kind: "release", maxAgeHours: 24, nowMs }).issues.join(","), /future-generated-at/);
  assert.match(evaluateCandidateReportBinding({ generatedAt: new Date(nowMs).toISOString(), candidate, candidateEnd: prior, candidateStable: false, releaseSha: candidate.commit }, candidate, { kind: "release", maxAgeHours: 24, nowMs }).issues.join(","), /candidate-changed-during-report/);
  assert.equal(candidateIdentityMatches(candidate, createCandidateIdentity({ ...base, clean: false })), false);
  assert.equal(candidateIdentityMatches(candidate, { ...candidate, tree: "f".repeat(40) }), false);
});

test("go/no-go consumers use candidate-bound report predicates", () => {
  const source = readFileSync(path.join(repositoryRoot, "scripts", "infra-ops.mjs"), "utf8");
  const goNoGo = source.slice(source.indexOf("async function productionGoNoGo"), source.indexOf("async function linuxPortabilityCheck"));
  assert.match(source, /evaluateCandidateReportBinding\(payload, currentCandidate/);
  assert.doesNotMatch(goNoGo, /releaseCommitShaCandidate\(\)/);
  assert.match(goNoGo, /candidateReportBinding\(payload, "release"/);
  assert.match(goNoGo, /candidateReportBinding\(payload, "github-actions"/);
  assert.match(goNoGo, /candidateReportBinding\(payload, "runtime-fingerprint"/);
  assert.match(goNoGo, /candidate-report-set-consistent/);
});
