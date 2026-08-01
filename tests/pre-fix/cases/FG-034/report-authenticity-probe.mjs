#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const STALE_RELEASE_SHA = "a".repeat(40);
const EXPECTED_HASHES = new Map([
  ["governance/production-go-no-go.json", "b439dec1c3e5cc47d22c3f452991b5bd985464fca2fd4f7988b6222352fbc8ca"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
]);

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: report-authenticity-probe.mjs /path/to/archived/source");
}
const archiveRootInput = String(process.env.REPORT_AUTH_POC_TMP || "");
if (!archiveRootInput || !fs.statSync(archiveRootInput, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("the probe must be run through run-from-git-archive.sh");
}
const archiveRoot = fs.realpathSync(archiveRootInput);
if (fs.realpathSync(sourceRoot) !== path.join(archiveRoot, "source")) {
  throw new Error("the archived source must be the wrapper-owned source directory");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[PASS] exact pre-fix evaluator and production policy fingerprints verified");

const infraOps = fs.readFileSync(path.join(sourceRoot, "scripts/infra-ops.mjs"), "utf8");
const latestReportSource = sourceSlice(infraOps, "function latestJsonReport", "function reportAgeHours");
const freshnessSource = sourceSlice(infraOps, "function reportAgeHours", "function publicEvidenceUrl");
const goNoGoCheckSource = sourceSlice(infraOps, "function addGoNoGoCheck", "function goNoGoStatusCounts");

assert.match(latestReportSource, /payload\?\.generatedAt \? Date\.parse\(payload\.generatedAt\) : NaN/);
assert.match(latestReportSource, /Number\.isFinite\(generatedAt\) \? generatedAt : fs\.statSync\(filePath\)\.mtimeMs/);
assert.match(latestReportSource, /sort\(\(a, b\) => b\.timestamp - a\.timestamp\)/);
assert.match(freshnessSource, /return \(Date\.now\(\) - generatedAt\) \/ 3600000/);
assert.match(freshnessSource, /if \(ageHours > maxAgeHours\)/);
assert.doesNotMatch(freshnessSource, /ageHours\s*</);
assert.doesNotMatch(latestReportSource + freshnessSource + goNoGoCheckSource, /verifySignature|signatureValid|candidateCommit|candidateTree|sha256File/);
assert.match(goNoGoCheckSource, /reportPath: report\?\.filePath \?\? null/);
assert.match(goNoGoCheckSource, /generatedAt: report\?\.payload\?\.generatedAt \?\? null/);
console.log("[PASS] selector trusts payload.generatedAt and freshness has no future-skew rejection");
console.log("[PASS] consumed report metadata carries no signature, digest, or candidate identity binding");

const reportsRoot = path.join(sourceRoot, "reports");
const runtimeRoot = fs.mkdtempSync(path.join(archiveRoot, "report-auth-runtime-"));
const mockBin = path.join(runtimeRoot, "bin");
const externalCommandMarker = path.join(runtimeRoot, "external-command-used");
const cleanupSentinel = path.join(reportsRoot, ".report-auth-poc-owned");
const cleanupToken = crypto.randomBytes(32).toString("hex");
const futureAt = new Date(Date.now() + (10 * 365 * 24 * 3600000)).toISOString();
const currentAt = new Date().toISOString();
let completed = false;
let reportsCreatedByProbe = false;

try {
  assert.equal(
    fs.existsSync(reportsRoot),
    false,
    "refusing to run because the supplied source already contains a reports directory; use run-from-git-archive.sh",
  );
  fs.mkdirSync(reportsRoot, { mode: 0o700 });
  fs.writeFileSync(cleanupSentinel, cleanupToken, { encoding: "utf8", flag: "wx", mode: 0o600 });
  reportsCreatedByProbe = true;
  fs.mkdirSync(mockBin);
  for (const command of ["cosign", "curl", "docker", "gh", "git", "ssh"]) {
    writeExecutable(path.join(mockBin, command), `#!/bin/sh\nprintf '%s\\n' '${command}' >> "$REPORT_AUTH_EXTERNAL_MARKER"\nexit 97\n`);
  }

  writePassingFixtureReports({ reportsRoot, generatedAt: futureAt });

  const legitimateFunctionalPath = writeReport(reportsRoot, "healthchecks", "functional-health-legitimate.json", {
    generatedAt: currentAt,
    mode: "runtime",
    status: "failed",
    checks: [{ name: "legitimate-runtime-check", passed: false }],
  });
  const forgedFunctionalPath = writeReport(reportsRoot, "healthchecks", "functional-health-forged.json", {
    generatedAt: futureAt,
    mode: "runtime",
    status: "failed",
    checks: [{ name: "forged-runtime-check", passed: false }],
  });
  setOldMtime(forgedFunctionalPath);
  assert.ok(fs.statSync(legitimateFunctionalPath).mtimeMs > fs.statSync(forgedFunctionalPath).mtimeMs);

  const beforeHash = sha256File(forgedFunctionalPath);
  const baseline = runExactGoNoGo({ sourceRoot, mockBin, externalCommandMarker });
  assert.equal(baseline.status, 1, baseline.diagnostics);
  assert.match(baseline.stdout, /Production status: no-go/);
  const baselineDecision = latestDecision(reportsRoot);
  const baselineFunctional = checkByName(baselineDecision, "functional-health-runtime");
  assert.equal(baselineDecision.status, "no-go");
  assert.equal(baselineFunctional.status, "failed");
  assert.equal(path.basename(baselineFunctional.reportPath), path.basename(forgedFunctionalPath));
  console.log(`[BASELINE] decision=no-go selected=${path.basename(baselineFunctional.reportPath)} unsigned_status=failed`);

  writeReport(reportsRoot, "healthchecks", "functional-health-forged.json", {
    generatedAt: futureAt,
    mode: "runtime",
    status: "passed",
    checks: [{ name: "forged-runtime-check", passed: true }],
  });
  setOldMtime(forgedFunctionalPath);
  const afterHash = sha256File(forgedFunctionalPath);
  assert.notEqual(afterHash, beforeHash);
  assert.ok(fs.statSync(legitimateFunctionalPath).mtimeMs > fs.statSync(forgedFunctionalPath).mtimeMs);
  console.log(`[REWRITE] same_path=true signature_required=false sha_changed=${beforeHash.slice(0, 12)}->${afterHash.slice(0, 12)}`);

  const forged = runExactGoNoGo({ sourceRoot, mockBin, externalCommandMarker });
  assert.equal(forged.status, 0, forged.diagnostics);
  assert.match(forged.stdout, /Production status: go/);
  const forgedDecision = latestDecision(reportsRoot);
  const forgedFunctional = checkByName(forgedDecision, "functional-health-runtime");
  const releaseCheck = checkByName(forgedDecision, "release-evidence-and-rollback");
  assert.equal(forgedDecision.status, "go");
  assert.equal(forgedDecision.summary.blockingRequired, 0);
  assert.ok(forgedDecision.checks.filter((check) => check.required).every((check) => check.status === "passed"));
  assert.equal(path.basename(forgedFunctional.reportPath), path.basename(forgedFunctionalPath));
  assert.equal(forgedFunctional.generatedAt, futureAt);
  assert.match(forgedFunctional.detail, /fresh report age -/);
  assert.equal(releaseCheck.status, "passed");
  assert.notEqual(STALE_RELEASE_SHA, REVISION);

  const ageHours = (Date.now() - Date.parse(futureAt)) / 3600000;
  console.log(`[FUTURE] selected=${path.basename(forgedFunctional.reportPath)} age_hours=${ageHours.toFixed(1)} legitimate_mtime_newer=true accepted=true`);
  console.log(`[IDENTITY] current_commit=${REVISION} evidence_release_sha=${STALE_RELEASE_SHA} mismatch_accepted=true`);
  console.log(`[VULNERABLE] decision=go required=${forgedDecision.summary.required} blocking=${forgedDecision.summary.blockingRequired} unsigned_mutable_reports=true`);
  assert.equal(fs.existsSync(externalCommandMarker), false, "the evaluator unexpectedly invoked an external command");
  console.log("[SAFE] exact archived go/no-go evaluator used temporary JSON only; no external command, network, Docker, SSH, credential, or live-state access");
  completed = true;
} finally {
  let cleanupAuthorized = false;
  if (reportsCreatedByProbe) {
    try {
      cleanupAuthorized = fs.readFileSync(cleanupSentinel, "utf8") === cleanupToken;
    } catch {
      cleanupAuthorized = false;
    }
  }
  if (cleanupAuthorized) fs.rmSync(reportsRoot, { recursive: true });
  fs.rmSync(runtimeRoot, { recursive: true, force: true });
  if (reportsCreatedByProbe && !cleanupAuthorized && fs.existsSync(reportsRoot)) {
    throw new Error("refusing to remove reports because the PoC ownership sentinel is absent or changed");
  }
}

assert.equal(completed, true);
assert.equal(fs.existsSync(reportsRoot), false);
assert.equal(fs.existsSync(runtimeRoot), false);
console.log("[+] temporary reports and command guards removed");

function writePassingFixtureReports({ reportsRoot, generatedAt }) {
  writeReport(reportsRoot, "vps-bootstrap", "vps-bootstrap-apply-forged.json", {
    generatedAt,
    mode: "apply",
    status: "applied",
  });
  writeReport(reportsRoot, "vps-hardening", "vps-hardening-apply-forged.json", {
    generatedAt,
    mode: "apply",
    status: "applied",
    steps: [
      { name: "docker-daemon-config", status: "applied" },
      { name: "ssh-service-reload", status: "applied" },
    ],
  });
  writeReport(reportsRoot, "vps-host", "vps-host-readiness-forged.json", {
    generatedAt,
    mode: "production",
    status: "passed",
    productionEvidence: true,
    expectedSshPort: "22",
    summary: { failedRequired: 0 },
    checks: [{ name: "ssh-port-expected" }, { name: "ufw-ssh-port-allowed" }],
  });
  writeReport(reportsRoot, "go-live", "pre-go-live-evidence-forged.json", {
    generatedAt,
    status: "passed",
    options: {
      includeProductionPreflight: true,
      includeRuntime: true,
      includeRestoreDrill: true,
      includeOffsiteRestoreDryRun: true,
      verifyGithubRemote: true,
    },
    readinessMatrix: [],
    steps: [],
  });
  writeReport(reportsRoot, "runtime-fingerprint", "runtime-fingerprint-forged.json", {
    generatedAt,
    mode: "runtime-exact",
    status: "passed",
    git: { clean: true },
    fingerprint: "b".repeat(64),
  });
  writeReport(reportsRoot, "github-actions", "github-actions-run-forged.json", {
    generatedAt,
    mode: "verifyRemote",
    status: "passed",
    workflow: "enterprise-infra.yml",
    expectedSha: STALE_RELEASE_SHA,
    run: { status: "completed", conclusion: "success" },
  });
  writeReport(reportsRoot, "secret-rotation", "secret-rotation-evidence-forged.json", {
    generatedAt,
    mode: "evidence",
    status: "passed",
    verify: { status: "passed" },
    summary: { failedSecrets: 0, expiredSecrets: 0, missingMaterializedFiles: 0 },
    audit: { latestRotationEvent: { action: "forged-rotation" } },
  });
  writeReport(reportsRoot, "dr", "dr-evidence-forged.json", {
    generatedAt,
    status: "passed",
    rpoEvidence: { backupFamilies: [] },
    offsiteEvidence: {
      latestRestoreReport: "forged-restore.json",
      latestRestoreOffsite: true,
      latestRestoreCoverage: { complete: true },
    },
  });
  writeReport(reportsRoot, "alerts", "alert-evidence-forged.json", {
    generatedAt,
    mode: "send-test",
    status: "passed",
    requestedDelivery: { email: true },
  });
  writeReport(reportsRoot, "uptime", "external-uptime-forged.json", {
    generatedAt,
    status: "passed",
    providerEvidence: {
      provider: "forged-provider",
      verified: true,
      authentication: { verified: true, kind: "github-sigstore-cryptographic-attestation" },
    },
    results: [{ name: "public", url: "https://status.example.org/health", ok: true }],
  });
  writeReport(reportsRoot, "load", "load-benchmark-forged.json", {
    generatedAt,
    status: "passed",
    url: "https://benchmark.example.org/run",
    target: { public: true, edgeRequired: true, edge: { providerMatched: true, provider: "forged-edge" } },
    profiles: [50, 100, 500].map((users) => ({ users, metric: { errors: 0, p95: 10, maxP95Ms: 1000 } })),
  });
  writeReport(reportsRoot, "release", "release-evidence-forged.json", {
    generatedAt,
    mode: "evidence",
    status: "passed",
    releaseSha: STALE_RELEASE_SHA,
    git: { commit: STALE_RELEASE_SHA, dirty: false },
    rollback: { complete: true, firstDeploy: false, dryRun: { validated: true } },
    artifacts: { sbom: { path: "forged-sbom.json" } },
    attestations: {
      provenanceRequired: true,
      githubSigstore: {
        status: "passed",
        kind: "github-sigstore-cryptographic-attestation",
        verified: true,
        completeness: "complete",
        commitShaMatched: true,
        commitSha: STALE_RELEASE_SHA,
        verifiedTimestampCount: 1,
        attestationCount: 1,
      },
    },
  });
  writeReport(reportsRoot, "cloudflare-access", "cloudflare-access-admin-forged.json", {
    generatedAt,
    mode: "verifyRemote",
    status: "passed",
    applications: [{ name: "admin", result: "verified" }],
  });
}

function runExactGoNoGo({ sourceRoot, mockBin, externalCommandMarker }) {
  const result = spawnSync(process.execPath, [path.join(sourceRoot, "scripts/infra-ops.mjs"), "production-go-no-go", "--enforce"], {
    cwd: sourceRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${mockBin}${path.delimiter}${process.env.PATH ?? ""}`,
      PLATFORM_GIT_COMMIT: REVISION,
      PLATFORM_GIT_BRANCH: "main",
      PLATFORM_GIT_DIRTY: "0",
      REPORT_AUTH_EXTERNAL_MARKER: externalCommandMarker,
    },
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    diagnostics: `status=${result.status} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()}`,
  };
}

function latestDecision(reportsRoot) {
  const directory = path.join(reportsRoot, "go-no-go");
  const files = fs.readdirSync(directory).filter((name) => name.startsWith("production-go-no-go-") && name.endsWith(".json"));
  assert.ok(files.length > 0, "go/no-go evaluator did not write a decision report");
  const latest = files.map((name) => path.join(directory, name)).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
  return JSON.parse(fs.readFileSync(latest, "utf8"));
}

function checkByName(decision, name) {
  const check = decision.checks.find((entry) => entry.name === name);
  assert.ok(check, `missing go/no-go check: ${name}`);
  return check;
}

function writeReport(reportsRoot, directory, name, payload) {
  const targetDirectory = path.join(reportsRoot, directory);
  fs.mkdirSync(targetDirectory, { recursive: true });
  const target = path.join(targetDirectory, name);
  fs.writeFileSync(target, `${JSON.stringify(payload, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(target, 0o600);
  return target;
}

function setOldMtime(filePath) {
  const old = new Date("2000-01-01T00:00:00.000Z");
  fs.utimesSync(filePath, old, old);
}

function sourceSlice(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `missing source slice ${start} -> ${end}`);
  return source.slice(startIndex, endIndex);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function writeExecutable(filePath, contents) {
  fs.writeFileSync(filePath, contents, { mode: 0o700 });
}
