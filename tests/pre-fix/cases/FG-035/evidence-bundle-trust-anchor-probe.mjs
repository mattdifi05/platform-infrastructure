#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const EXPECTED_INFRA_OPS_SHA256 =
  "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b";

if (!process.argv[2]) {
  throw new Error("usage: evidence-bundle-trust-anchor-probe.mjs /path/to/archived/source");
}
const ownership = validateWrapperOwnedSource(process.argv[2]);
const sourceRoot = ownership.sourceRoot;
const wrapperTempRoot = ownership.wrapperTempRoot;
const reportsRoot = path.join(sourceRoot, "reports");
const mutableTempRoot = path.join(sourceRoot, ".tmp");
assertMutationTargetsAbsent([reportsRoot, mutableTempRoot]);
console.log("[PASS] wrapper-owned source boundary and absent mutation targets verified");

const infraOpsPath = path.join(sourceRoot, "scripts", "infra-ops.mjs");
assert.equal(
  sha256File(infraOpsPath),
  EXPECTED_INFRA_OPS_SHA256,
  "scripts/infra-ops.mjs is not the expected vulnerable source",
);
console.log("[PASS] exact vulnerable source fingerprint verified");

const infraOps = fs.readFileSync(infraOpsPath, "utf8");
const verifierSource = sourceSlice(
  infraOps,
  "async function evidenceBundleVerify()",
  "async function vpsPreflight()",
);
const entrySource = sourceSlice(
  infraOps,
  "function validateEvidenceBundleEntry",
  "function evidenceBundleReportPasses",
);

assert.match(verifierSource, /const manifest = readJsonFile\(manifestPath, manifestPath\)/);
assert.match(entrySource, /const actualHash = sha256File\(filePath\)/);
assert.match(entrySource, /String\(entry\.sha256 \?\? ""\)\.toLowerCase\(\) !== actualHash/);
assert.doesNotMatch(
  verifierSource,
  /crypto\.verify|verifySignature|trustedPublicKey|expectedManifestSha256|manifestAttestation/,
);
console.log("[PASS] manifest hashes have no external signature or pinned digest check");

const bundleRoot = path.join(mutableTempRoot, "evidence-bundles");
const goNoGoName = "production-go-no-go-poc.json";
writeRequiredReportFixtures(reportsRoot, goNoGoName);

const generated = runInfraOps(sourceRoot, [
  "evidence-bundle",
  "--noArchive",
  "--outputDir",
  bundleRoot,
]);
assert.equal(generated.status, 0, generated.diagnostics);

const bundleDir = latestBundleDirectory(bundleRoot);
const manifestPath = path.join(bundleDir, "manifest.json");
const manifestBefore = fs.readFileSync(manifestPath);
const bundledGoNoGoPath = path.join(
  bundleDir,
  "reports",
  "go-no-go",
  goNoGoName,
);

const baseline = runInfraOps(sourceRoot, [
  "evidence-bundle-verify",
  "--bundleDir",
  bundleDir,
  "--requireComplete",
]);
assert.notEqual(baseline.status, 0, "the no-go baseline unexpectedly verified");
const baselineReceipt = readJson(latestJsonFile(
  path.join(reportsRoot, "evidence-bundle-verify"),
  "evidence-bundle-verify-",
));
assert.equal(baselineReceipt.status, "failed");
assert.ok(
  baselineReceipt.issues.some((issue) =>
    issue.includes("required report is not passing: production-go-no-go")),
  `unexpected baseline issues: ${JSON.stringify(baselineReceipt.issues)}`,
);
assert.equal(fs.readFileSync(manifestPath).equals(manifestBefore), true);
console.log("[BASELINE] decision=no-go manifest_unchanged=true verifier=reject");

const report = readJson(bundledGoNoGoPath);
assert.equal(report.status, "no-go");
report.status = "go";
fs.writeFileSync(bundledGoNoGoPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

const manifest = readJson(manifestPath);
const relativeReportPath = `reports/go-no-go/${goNoGoName}`;
const entry = manifest.entries.find((candidate) => candidate.path === relativeReportPath);
assert.ok(entry, `missing manifest entry for ${relativeReportPath}`);
entry.sizeBytes = fs.statSync(bundledGoNoGoPath).size;
entry.sha256 = sha256File(bundledGoNoGoPath);
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
assert.equal(fs.readFileSync(manifestPath).equals(manifestBefore), false);
console.log("[TAMPER] decision=go report_sha_recomputed=true manifest_replaced=true");

const tampered = runInfraOps(sourceRoot, [
  "evidence-bundle-verify",
  "--bundleDir",
  bundleDir,
  "--requireComplete",
]);
assert.equal(tampered.status, 0, tampered.diagnostics);
assert.match(tampered.combined, /Evidence bundle verification passed\./);
console.log("[VULNERABLE] require_complete=true verifier=accept trust_anchor=none");
console.log("[SAFE] sentinel-owned temporary archive only; no pre-existing path deletion or live access");

function writeRequiredReportFixtures(root, productionGoNoGoName) {
  const passed = { generatedAt: "2026-07-11T00:00:00.000Z", status: "passed" };
  const fixtures = [
    ["go-no-go", productionGoNoGoName, { ...passed, status: "no-go" }],
    ["production-readiness", "production-readiness-poc.json", passed],
    ["github-actions", "github-actions-run-poc.json", {
      ...passed,
      mode: "verifyRemote",
      run: { conclusion: "success" },
    }],
    ["healthchecks", "healthcheck-coverage-poc.json", {
      ...passed,
      missingHealthchecks: [],
    }],
    ["healthchecks", "functional-health-poc.json", {
      ...passed,
      mode: "runtime",
      checks: [{ name: "offline-fixture", passed: true }],
    }],
    ["runtime-fingerprint", "runtime-fingerprint-poc.json", {
      ...passed,
      mode: "runtime-exact",
      git: { clean: true },
      fingerprint: "a".repeat(64),
    }],
    ["rate-limits", "rate-limit-evidence-poc.json", {
      ...passed,
      mode: "infra-only",
      summary: { failed: 0, infraChecksPassed: 4 },
    }],
    ["audit-logs", "audit-log-evidence-poc.json", {
      ...passed,
      mode: "infra-only",
      summary: { failed: 0, infraChecksPassed: 9 },
    }],
    ["retention", "retention-evidence-poc.json", {
      ...passed,
      mode: "infra-only",
      summary: { failed: 0, infraChecksPassed: 14 },
    }],
    ["secret-rotation", "secret-rotation-evidence-poc.json", {
      ...passed,
      mode: "evidence",
      verify: { status: "passed" },
      summary: {
        failedSecrets: 0,
        expiredSecrets: 0,
        missingMaterializedFiles: 0,
      },
    }],
    ["go-live", "pre-go-live-evidence-poc.json", passed],
    ["vps-host", "vps-host-readiness-poc.json", {
      ...passed,
      productionEvidence: true,
      summary: { failedRequired: 0 },
    }],
    ["dr", "dr-evidence-poc.json", passed],
    ["offsite-restore-drills", "offsite-restore-drill-poc.json", passed],
    ["uptime", "external-uptime-poc.json", passed],
    ["load", "load-benchmark-poc.json", passed],
    ["release", "release-evidence-poc.json", passed],
    ["rollback", "rollback-plan-poc.json", { ...passed, validated: true }],
    ["cloudflare-access", "cloudflare-access-admin-poc.json", passed],
    ["alerts", "alert-evidence-poc.json", passed],
    ["linux-portability", "linux-portability-poc.json", passed],
    ["vps-bootstrap", "vps-bootstrap-apply-poc.json", {
      ...passed,
      mode: "apply",
      status: "applied",
    }],
    ["vps-hardening", "vps-hardening-apply-poc.json", {
      ...passed,
      mode: "apply",
      status: "applied",
    }],
  ];

  for (const [directory, filename, payload] of fixtures) {
    const targetDirectory = path.join(root, directory);
    fs.mkdirSync(targetDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(targetDirectory, filename),
      `${JSON.stringify(payload, null, 2)}\n`,
      "utf8",
    );
  }
}

function runInfraOps(root, args) {
  const result = spawnSync(
    process.execPath,
    [path.join(root, "scripts", "infra-ops.mjs"), ...args],
    {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        CI: "true",
        GIT_CONFIG_NOSYSTEM: "1",
        HOME: path.join(wrapperTempRoot, "empty-home"),
      },
      timeout: 20_000,
    },
  );
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  return {
    status: result.status,
    combined: `${stdout}\n${stderr}`,
    diagnostics: `status=${result.status} signal=${result.signal ?? "none"}\nstdout:\n${stdout}\nstderr:\n${stderr}`,
  };
}

function latestBundleDirectory(root) {
  const names = fs.readdirSync(root)
    .filter((name) => name.startsWith("infra-evidence-bundle-"))
    .sort();
  assert.ok(names.length > 0, "evidence-bundle did not create a bundle directory");
  return path.join(root, names.at(-1));
}

function latestJsonFile(root, prefix) {
  const names = fs.readdirSync(root)
    .filter((name) => name.startsWith(prefix) && name.endsWith(".json"))
    .sort();
  assert.ok(names.length > 0, `missing JSON report in ${root}`);
  return path.join(root, names.at(-1));
}

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
}

function validateWrapperOwnedSource(sourceArgument) {
  const wrapperArgument = requiredEnvironment("REPORT_FG035_WRAPPER_TEMP_ROOT");
  const sentinelArgument = requiredEnvironment("REPORT_FG035_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("REPORT_FG035_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperArgument);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg035-(?:guard|run)\.[A-Za-z0-9]+$/,
    "wrapper temporary root does not have the expected mktemp name",
  );

  const requestedSource = path.resolve(sourceArgument);
  const sourceStat = fs.lstatSync(requestedSource, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(requestedSource);
  assert.equal(
    sourceReal,
    path.join(wrapperReal, "source"),
    "sourceRoot must be the exact wrapper-owned source child",
  );

  const sentinelPath = path.resolve(sentinelArgument);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg035-owner\.[A-Za-z0-9]+$/);
  const sentinelToken = path.basename(sentinelReal).slice(".fg035-owner.".length);
  assert.equal(ownershipToken, sentinelToken, "ownership token does not match sentinel name");
  assert.equal(
    fs.readFileSync(sentinelReal, "utf8"),
    `FG035-OWNER:${ownershipToken}\n`,
    "ownership sentinel content is invalid",
  );

  return { sourceRoot: sourceReal, wrapperTempRoot: wrapperReal };
}

function assertMutationTargetsAbsent(targets) {
  for (const target of targets) {
    if (fs.lstatSync(target, { throwIfNoEntry: false }) !== undefined) {
      throw new Error(`refusing to mutate pre-existing target path: ${path.basename(target)}`);
    }
  }
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke this probe through run-from-git-archive.sh`);
  }
  return value;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

assert.equal(REVISION.length, 40);
