#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./runtime-intent-policy.mjs";
import { snapshotFileArtifact, snapshotJsonArtifact } from "./stable-json-artifact.mjs";

function invalid(message) {
  throw new Error(message);
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object.`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactSha256(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one lowercase SHA256.`);
  return text;
}

function exactGitSha(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{40}$/.test(text)) invalid(`${label} must be one full Git SHA.`);
  return text;
}

function exactPositiveInteger(value, label) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1) invalid(`${label} must be one positive integer.`);
  return number;
}

export function canonicalDastTarget(value, label = "DAST target") {
  const text = String(value ?? "");
  if (!text || text !== text.trim()) invalid(`${label} must be one canonical HTTPS URL without surrounding whitespace.`);
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    invalid(`${label} must be one valid HTTPS URL.`);
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || !parsed.hostname
  ) {
    invalid(`${label} must use HTTPS without credentials, query, or fragment.`);
  }
  return { url: parsed.href, origin: parsed.origin };
}

function reportedUrlOrigin(value, label) {
  const text = String(value ?? "");
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    invalid(`${label} is not one absolute URL.`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    invalid(`${label} is not one credential-free HTTPS URL.`);
  }
  return parsed.origin;
}

function validateReportedAuthorities(value, expectedOrigin, trail = "DAST report") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => validateReportedAuthorities(item, expectedOrigin, `${trail}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (/^(?:uri|url)$/i.test(key) && typeof child === "string") {
      if (reportedUrlOrigin(child, `${trail}.${key}`) !== expectedOrigin) {
        invalid(`${trail}.${key} crosses the admitted DAST target authority.`);
      }
    } else {
      validateReportedAuthorities(child, expectedOrigin, `${trail}.${key}`);
    }
  }
}

export function validateZapReportTarget(reportDocument, target) {
  if (!reportDocument || typeof reportDocument !== "object" || Array.isArray(reportDocument)) {
    invalid("ZAP report must be one JSON object.");
  }
  if (!Array.isArray(reportDocument.site) || reportDocument.site.length < 1) {
    invalid("ZAP report must contain at least one scanned site.");
  }
  for (const [index, site] of reportDocument.site.entries()) {
    if (!site || typeof site !== "object" || Array.isArray(site)) invalid(`ZAP site ${index} must be an object.`);
    const siteOrigin = reportedUrlOrigin(site["@name"], `ZAP site ${index} name`);
    let parsedName;
    try { parsedName = new URL(String(site["@name"])); } catch { invalid(`ZAP site ${index} name is invalid.`); }
    const expectedPort = parsedName.port || "443";
    if (
      siteOrigin !== target.origin
      || String(site["@host"] ?? "").toLowerCase() !== parsedName.hostname.toLowerCase()
      || String(site["@port"] ?? "") !== expectedPort
      || ![true, "true"].includes(site["@ssl"])
    ) {
      invalid(`ZAP site ${index} does not match the admitted HTTPS target authority.`);
    }
    validateReportedAuthorities(site, target.origin, `ZAP site ${index}`);
  }
  return reportDocument;
}

export function validateDastAdmissionReceipt(receipt, {
  repository,
  commitSha,
  treeSha,
  runtimeIntentSha256,
  consumerRunId,
  consumerRunAttempt,
  target = null,
  report = null,
} = {}) {
  exactObject(receipt, "DAST admission receipt", [
    "version",
    "kind",
    "status",
    "repository",
    "commitSha",
    "treeSha",
    "runtimeIntentSha256",
    "generatedAt",
    "target",
    "report",
    "consumerChallenge",
  ]);
  if (receipt.version !== 1 || receipt.kind !== "platform-dast-verification/v1" || receipt.status !== "passed") {
    invalid("DAST admission receipt is not one passed v1 receipt.");
  }
  if (
    receipt.repository !== repository
    || receipt.commitSha !== exactGitSha(commitSha, "expected DAST commit")
    || receipt.treeSha !== exactGitSha(treeSha, "expected DAST tree")
    || receipt.runtimeIntentSha256 !== exactSha256(runtimeIntentSha256, "expected runtime intent SHA256")
  ) {
    invalid("DAST admission receipt is not bound to the exact candidate.");
  }
  if (new Date(receipt.generatedAt).toISOString() !== receipt.generatedAt) {
    invalid("DAST admission generatedAt must be one canonical UTC timestamp.");
  }
  exactObject(receipt.target, "DAST target", ["url", "origin"]);
  const admittedTarget = canonicalDastTarget(receipt.target.url);
  if (canonicalJson(receipt.target) !== canonicalJson(admittedTarget)) invalid("DAST target is not canonical.");
  if (target) {
    const expectedTarget = canonicalDastTarget(target, "expected DAST target");
    if (canonicalJson(expectedTarget) !== canonicalJson(admittedTarget)) {
      invalid("DAST receipt is not bound to the exact requested target.");
    }
  }
  exactObject(receipt.report, "DAST report", ["name", "sha256", "sizeBytes"]);
  if (receipt.report.name !== "zap-baseline.json") invalid("DAST report name is not fixed.");
  exactSha256(receipt.report.sha256, "DAST report SHA256");
  exactPositiveInteger(receipt.report.sizeBytes, "DAST report size");
  if (report && (receipt.report.sha256 !== report.sha256 || receipt.report.sizeBytes !== report.sizeBytes)) {
    invalid("DAST receipt does not bind the exact captured report bytes.");
  }
  if (report?.document) validateZapReportTarget(report.document, admittedTarget);
  exactObject(receipt.consumerChallenge, "DAST consumer challenge", [
    "consumerRepository",
    "consumerRunId",
    "consumerRunAttempt",
    "consumerJob",
    "challengeNonce",
  ]);
  if (
    receipt.consumerChallenge.consumerRepository !== repository
    || String(receipt.consumerChallenge.consumerRunId) !== String(exactPositiveInteger(consumerRunId, "consumer run ID"))
    || receipt.consumerChallenge.consumerRunAttempt !== exactPositiveInteger(consumerRunAttempt, "consumer run attempt")
    || receipt.consumerChallenge.consumerJob !== "deploy-vps"
  ) {
    invalid("DAST consumer challenge is not bound to the exact deploy-vps run.");
  }
  exactSha256(receipt.consumerChallenge.challengeNonce, "DAST challenge nonce");
  return receipt;
}

export function buildDastAdmissionReceipt({
  repository,
  commitSha,
  treeSha,
  runtimeIntentSha256,
  consumerRunId,
  consumerRunAttempt,
  challengeNonce,
  target,
  report,
  generatedAt = new Date().toISOString(),
}) {
  const receipt = {
    version: 1,
    kind: "platform-dast-verification/v1",
    status: "passed",
    repository,
    commitSha,
    treeSha,
    runtimeIntentSha256,
    generatedAt,
    target: canonicalDastTarget(target),
    report: {
      name: "zap-baseline.json",
      sha256: report.sha256,
      sizeBytes: report.sizeBytes,
    },
    consumerChallenge: {
      consumerRepository: repository,
      consumerRunId: String(exactPositiveInteger(consumerRunId, "consumer run ID")),
      consumerRunAttempt: exactPositiveInteger(consumerRunAttempt, "consumer run attempt"),
      consumerJob: "deploy-vps",
      challengeNonce: exactSha256(challengeNonce, "DAST challenge nonce"),
    },
  };
  return validateDastAdmissionReceipt(receipt, {
    repository,
    commitSha,
    treeSha,
    runtimeIntentSha256,
    consumerRunId,
    consumerRunAttempt,
    target,
    report,
  });
}

function parseArgs(values) {
  const options = {};
  if (values.length % 2 !== 0) invalid("DAST admission arguments are incomplete.");
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || Object.hasOwn(options, key.slice(2))) {
      invalid(`Invalid DAST admission argument ${key ?? "<missing>"}.`);
    }
    options[key.slice(2)] = value;
  }
  return options;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const deployment = snapshotJsonArtifact(options.deploymentReceipt, {
    label: "trusted deployment receipt",
    maxBytes: 16 * 1024 * 1024,
  });
  const report = snapshotFileArtifact(options.report, { label: "DAST JSON report", maxBytes: 16 * 1024 * 1024 });
  try {
    const reportDocument = JSON.parse(fs.readFileSync(report.snapshotPath, "utf8"));
    const reportWithDocument = { ...report, document: reportDocument };
    const receipt = buildDastAdmissionReceipt({
      repository: options.repository,
      commitSha: options.commit,
      treeSha: options.tree,
      runtimeIntentSha256: deployment.document.runtimeIntentSha256,
      consumerRunId: options.consumerRunId,
      consumerRunAttempt: options.consumerRunAttempt,
      challengeNonce: options.challengeNonce,
      target: options.target,
      report: reportWithDocument,
    });
    const output = path.resolve(String(options.output ?? ""));
    if (!options.output) invalid("DAST admission output path is required.");
    fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
    fs.writeFileSync(output, `${canonicalJson(receipt)}\n`, { flag: "wx", mode: 0o600 });
    process.stdout.write(`${JSON.stringify({ status: "passed", receipt: output })}\n`);
  } finally {
    report.cleanup();
    deployment.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
