import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const evidenceTrustEnvelopeSchema = "platform.evidence-trust-envelope/v1";

const SHA256 = /^[a-f0-9]{64}$/;
const MAX_FUTURE_SKEW_MS = 0;

function digestBytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeSha256(value, label) {
  const normalized = String(value ?? "").trim().toLowerCase().replace(/^sha256:/, "");
  if (!SHA256.test(normalized)) throw new Error(`${label} must be a complete SHA256 digest.`);
  return normalized;
}

function normalizeReportPath(value) {
  const normalized = String(value ?? "").replaceAll("\\", "/");
  if (!normalized.startsWith("reports/") || normalized.startsWith("/") || normalized.includes("../") || normalized.includes("\0")) {
    throw new Error(`Evidence trust envelope report path is invalid: ${normalized || "(empty)"}.`);
  }
  return normalized;
}

function parseTimestamp(value, label, nowMs) {
  const parsed = Date.parse(String(value ?? ""));
  if (!Number.isFinite(parsed)) throw new Error(`${label} is invalid.`);
  if (parsed > nowMs + MAX_FUTURE_SKEW_MS) throw new Error(`${label} is in the future.`);
  return parsed;
}

export function parseEvidenceTrustEnvelope(envelope, {
  envelopeBytes,
  expectedEnvelopeSha256,
  currentCandidateId,
  nowMs = Date.now(),
  maxAgeHours = 24,
} = {}) {
  if (!Buffer.isBuffer(envelopeBytes) && typeof envelopeBytes !== "string") {
    throw new Error("Evidence trust envelope bytes are required for external digest verification.");
  }
  const actualEnvelopeSha256 = digestBytes(envelopeBytes);
  const pinnedEnvelopeSha256 = normalizeSha256(expectedEnvelopeSha256, "Owner-pinned evidence trust envelope digest");
  if (actualEnvelopeSha256 !== pinnedEnvelopeSha256) {
    throw new Error("Evidence trust envelope does not match the owner-pinned digest.");
  }
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || envelope.schema !== evidenceTrustEnvelopeSchema) {
    throw new Error("Evidence trust envelope schema is invalid.");
  }
  const generatedAtMs = parseTimestamp(envelope.generatedAt, "Evidence trust envelope generatedAt", nowMs);
  if (!Number.isFinite(Number(maxAgeHours)) || Number(maxAgeHours) <= 0) {
    throw new Error("Evidence trust envelope max age must be positive.");
  }
  if (nowMs - generatedAtMs > Number(maxAgeHours) * 3600000) {
    throw new Error("Evidence trust envelope is stale.");
  }
  const candidateId = normalizeSha256(envelope.candidateId, "Evidence trust envelope candidate ID");
  if (candidateId !== normalizeSha256(currentCandidateId, "Current candidate ID")) {
    throw new Error("Evidence trust envelope is not bound to the current candidate.");
  }
  if (!Array.isArray(envelope.reports) || envelope.reports.length === 0) {
    throw new Error("Evidence trust envelope must contain reports.");
  }
  const reports = new Map();
  for (const raw of envelope.reports) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Evidence trust envelope contains a non-object report entry.");
    const reportPath = normalizeReportPath(raw.path);
    if (reports.has(reportPath)) throw new Error(`Evidence trust envelope contains duplicate report path: ${reportPath}.`);
    const generatedAtMsForReport = parseTimestamp(raw.generatedAt, `${reportPath} generatedAt`, nowMs);
    reports.set(reportPath, {
      path: reportPath,
      sha256: normalizeSha256(raw.sha256, `${reportPath} digest`),
      sizeBytes: Number(raw.sizeBytes),
      generatedAt: new Date(generatedAtMsForReport).toISOString(),
      candidateId: normalizeSha256(raw.candidateId, `${reportPath} candidate ID`),
    });
    if (!Number.isSafeInteger(Number(raw.sizeBytes)) || Number(raw.sizeBytes) <= 0) {
      throw new Error(`${reportPath} size is invalid.`);
    }
    if (reports.get(reportPath).candidateId !== candidateId) {
      throw new Error(`${reportPath} is not bound to the envelope candidate.`);
    }
  }
  return {
    schema: evidenceTrustEnvelopeSchema,
    generatedAt: new Date(generatedAtMs).toISOString(),
    candidateId,
    envelopeSha256: actualEnvelopeSha256,
    reports,
  };
}

export function verifyTrustedEvidenceReports({
  envelope,
  envelopeBytes,
  expectedEnvelopeSha256,
  currentCandidateId,
  infraRoot,
  reportSelections,
  nowMs = Date.now(),
  maxAgeHours = 24,
}) {
  const trusted = parseEvidenceTrustEnvelope(envelope, {
    envelopeBytes,
    expectedEnvelopeSha256,
    currentCandidateId,
    nowMs,
    maxAgeHours,
  });
  const root = path.resolve(infraRoot);
  const selections = (reportSelections ?? []).filter((selection) => selection?.filePath);
  const uniqueSelections = new Map(selections.map((selection) => [path.resolve(selection.filePath), selection]));
  if (uniqueSelections.size === 0) throw new Error("No production evidence reports were selected for trust verification.");
  const verified = [];
  for (const [reportPath, selection] of uniqueSelections) {
    const relativePath = path.relative(root, reportPath).replaceAll("\\", "/");
    const normalizedPath = normalizeReportPath(relativePath);
    const expected = trusted.reports.get(normalizedPath);
    if (!expected) throw new Error(`Selected production report is absent from the owner-pinned envelope: ${normalizedPath}.`);
    if (normalizeSha256(selection.observedSha256, `${normalizedPath} selected digest`) !== expected.sha256) {
      throw new Error(`Production decision used report bytes that differ from the owner-pinned envelope: ${normalizedPath}.`);
    }
    if (Number(selection.observedSizeBytes) !== expected.sizeBytes) {
      throw new Error(`Production decision used a report size that differs from the owner-pinned envelope: ${normalizedPath}.`);
    }
    const stat = fs.lstatSync(reportPath, { throwIfNoEntry: false });
    if (!stat?.isFile() || stat.isSymbolicLink()) throw new Error(`Selected production report is missing or not a regular file: ${normalizedPath}.`);
    if (stat.size !== expected.sizeBytes) throw new Error(`Selected production report size changed after external anchoring: ${normalizedPath}.`);
    const bytes = fs.readFileSync(reportPath);
    if (digestBytes(bytes) !== expected.sha256) throw new Error(`Selected production report digest changed after external anchoring: ${normalizedPath}.`);
    let payload;
    try {
      payload = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error(`Selected production report is not valid JSON: ${normalizedPath}.`);
    }
    const reportGeneratedAtMs = parseTimestamp(payload.generatedAt, `${normalizedPath} payload generatedAt`, nowMs);
    if (new Date(reportGeneratedAtMs).toISOString() !== expected.generatedAt) {
      throw new Error(`Selected production report timestamp differs from the owner-pinned envelope: ${normalizedPath}.`);
    }
    verified.push({ path: normalizedPath, sha256: expected.sha256, sizeBytes: expected.sizeBytes });
  }
  return {
    status: "passed",
    trustMode: "owner-pinned-sha256-envelope",
    candidateId: trusted.candidateId,
    envelopeSha256: trusted.envelopeSha256,
    reportCount: verified.length,
    reports: verified,
  };
}
