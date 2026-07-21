import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseEvidenceTrustEnvelope, verifyTrustedEvidenceReports } from "./evidence-trust-envelope.mjs";

const nowMs = Date.parse("2026-07-21T12:00:00.000Z");
const candidateId = "a".repeat(64);

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function fixture() {
  const infraRoot = fs.mkdtempSync(path.join(os.tmpdir(), "evidence-trust-"));
  const reportPath = path.join(infraRoot, "reports", "healthchecks", "functional-health.json");
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  const reportBytes = Buffer.from(`${JSON.stringify({ generatedAt: "2026-07-21T11:59:00.000Z", status: "passed" }, null, 2)}\n`);
  fs.writeFileSync(reportPath, reportBytes);
  const envelope = {
    schema: "platform.evidence-trust-envelope/v1",
    generatedAt: "2026-07-21T12:00:00.000Z",
    candidateId,
    reports: [{
      path: "reports/healthchecks/functional-health.json",
      sha256: digest(reportBytes),
      sizeBytes: reportBytes.length,
      generatedAt: "2026-07-21T11:59:00.000Z",
      candidateId,
    }],
  };
  const envelopeBytes = Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`);
  const reportSelections = [{ filePath: reportPath, observedSha256: digest(reportBytes), observedSizeBytes: reportBytes.length }];
  return { infraRoot, reportPath, reportBytes, reportSelections, envelope, envelopeBytes, expectedEnvelopeSha256: digest(envelopeBytes) };
}

test("accepts an exact report set bound to one current candidate and owner-pinned envelope", () => {
  const value = fixture();
  try {
    const result = verifyTrustedEvidenceReports({ ...value, currentCandidateId: candidateId, nowMs });
    assert.equal(result.status, "passed");
    assert.equal(result.trustMode, "owner-pinned-sha256-envelope");
    assert.equal(result.reportCount, 1);
  } finally {
    fs.rmSync(value.infraRoot, { recursive: true, force: true });
  }
});

test("rejects unsigned, rewritten, coordinated, absent, and cross-candidate reports", () => {
  const value = fixture();
  try {
    assert.throws(() => verifyTrustedEvidenceReports({ ...value, expectedEnvelopeSha256: undefined, currentCandidateId: candidateId, nowMs }), /owner-pinned/i);
    fs.appendFileSync(value.reportPath, " ");
    assert.throws(() => verifyTrustedEvidenceReports({ ...value, currentCandidateId: candidateId, nowMs }), /size changed/);
    fs.writeFileSync(value.reportPath, value.reportBytes);
    assert.throws(() => verifyTrustedEvidenceReports({
      ...value,
      currentCandidateId: candidateId,
      reportSelections: [{ filePath: value.reportPath, observedSha256: "d".repeat(64), observedSizeBytes: value.reportBytes.length }],
      nowMs,
    }), /decision used report bytes/);
    const coordinatedEnvelope = { ...value.envelope, reports: [{ ...value.envelope.reports[0], sha256: "b".repeat(64) }] };
    const coordinatedBytes = Buffer.from(`${JSON.stringify(coordinatedEnvelope)}\n`);
    assert.throws(() => verifyTrustedEvidenceReports({ ...value, envelope: coordinatedEnvelope, envelopeBytes: coordinatedBytes, currentCandidateId: candidateId, nowMs }), /owner-pinned digest/);
    assert.throws(() => verifyTrustedEvidenceReports({ ...value, currentCandidateId: "c".repeat(64), nowMs }), /current candidate/);
    const otherPath = path.join(value.infraRoot, "reports", "healthchecks", "other.json");
    fs.writeFileSync(otherPath, value.reportBytes);
    assert.throws(() => verifyTrustedEvidenceReports({ ...value, currentCandidateId: candidateId, reportSelections: [{ filePath: otherPath, observedSha256: digest(value.reportBytes), observedSizeBytes: value.reportBytes.length }], nowMs }), /absent/);
  } finally {
    fs.rmSync(value.infraRoot, { recursive: true, force: true });
  }
});

test("rejects future and stale envelope or report timestamps", () => {
  const value = fixture();
  try {
    for (const mutation of [
      { generatedAt: "2026-07-21T12:06:00.000Z" },
      { generatedAt: "2026-07-19T12:00:00.000Z" },
    ]) {
      const envelope = { ...value.envelope, ...mutation };
      const envelopeBytes = Buffer.from(`${JSON.stringify(envelope)}\n`);
      assert.throws(() => parseEvidenceTrustEnvelope(envelope, { envelopeBytes, expectedEnvelopeSha256: digest(envelopeBytes), currentCandidateId: candidateId, nowMs, maxAgeHours: 24 }), /future|stale/);
    }
    const futureReportEnvelope = {
      ...value.envelope,
      reports: [{ ...value.envelope.reports[0], generatedAt: "2026-07-21T12:06:00.000Z" }],
    };
    const futureBytes = Buffer.from(`${JSON.stringify(futureReportEnvelope)}\n`);
    assert.throws(() => parseEvidenceTrustEnvelope(futureReportEnvelope, { envelopeBytes: futureBytes, expectedEnvelopeSha256: digest(futureBytes), currentCandidateId: candidateId, nowMs }), /future/);
  } finally {
    fs.rmSync(value.infraRoot, { recursive: true, force: true });
  }
});

test("production gate requires the external envelope and exposes external pending", () => {
  const source = fs.readFileSync(path.join(import.meta.dirname, "infra-ops.mjs"), "utf8");
  const body = source.slice(source.indexOf("async function productionGoNoGo"), source.indexOf("async function linuxPortabilityCheck"));
  assert.match(body, /verifyTrustedEvidenceReports/);
  assert.match(body, /EXTERNAL-PENDING/);
  assert.match(body, /evidence-report-authenticity/);
  assert.match(source, /future by more than/);
});
