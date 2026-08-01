#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const PRIOR_COMMIT = "4c04042a6fabc42317e18896b949f16b35102c7a";
const PRIOR_TREE = "4c7699a8565801af64a225b238a3c92865159f87";
const THIRD_COMMIT = "15a12a81fa32ef3f1165b23d078d72f1d8bfdc29";
const THIRD_TREE = "d966a284e246c8c5571ad3123154f39e213b9ca3";
const CURRENT_REPOSITORY = "example/platform-infrastructure";
const PRIOR_REPOSITORY = "example/previous-platform";
const CURRENT_WORKLOAD_LOCK = "1".repeat(64);
const PRIOR_WORKLOAD_LOCK = "9".repeat(64);
const EXPECTED_HASHES = new Map([
  ["governance/production-go-no-go.json", "b439dec1c3e5cc47d22c3f452991b5bd985464fca2fd4f7988b6222352fbc8ca"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["scripts/runtime-fingerprint.mjs", "bb5216a6f2caf3b00ea306a2ee43feabb1e4907a6ed0a1a62a8423d9088af319"],
]);

const sourceArgument = String(process.argv[2] || "");
const tmpArgument = String(process.env.EVIDENCE_BINDING_POC_TMP_ROOT || "");
const ownerToken = String(process.env.EVIDENCE_BINDING_POC_OWNER_TOKEN || "");
if (!sourceArgument || !tmpArgument || !ownerToken) {
  throw new Error("run this probe through run-from-git-archive.sh");
}

const tmpRoot = verifiedRealDirectory(tmpArgument, "wrapper temporary root");
const sourceRoot = verifiedRealDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(tmpRoot, "source"), "source must be the exact wrapper-owned source child");
assert.match(ownerToken, /^[a-f0-9]{64}$/, "invalid wrapper ownership token");
const rootOwnerFile = path.join(tmpRoot, ".evidence-candidate-binding-poc-owner");
assertRegularFile(rootOwnerFile, "wrapper ownership sentinel");
assert.equal(fs.readFileSync(rootOwnerFile, "utf8"), ownerToken, "wrapper ownership sentinel mismatch");

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  const target = path.join(sourceRoot, relativePath);
  assertRegularFile(target, `pinned source ${relativePath}`);
  assert.equal(sha256File(target), expectedHash, `${relativePath} is not the expected vulnerable source`);
}
console.log(`[PASS] exact pre-fix evaluator revision=${REVISION} tree=${TREE}`);

const infraOpsPath = path.join(sourceRoot, "scripts", "infra-ops.mjs");
const runtimeFingerprintPath = path.join(sourceRoot, "scripts", "runtime-fingerprint.mjs");
const infraOpsSource = fs.readFileSync(infraOpsPath, "utf8");
const runtimeFingerprintSource = fs.readFileSync(runtimeFingerprintPath, "utf8");
const releaseCandidateSource = sourceSlice(
  infraOpsSource,
  "function releaseCommitShaCandidate()",
  "async function collectEvidenceStep",
);
const reportPassSource = sourceSlice(
  infraOpsSource,
  "function evidenceBundleReportPasses",
  "async function evidenceBundle()",
);
const runtimeConsumerSource = sourceSlice(
  infraOpsSource,
  "  const runtimeFingerprintReport =",
  "  const infraHealthReport =",
);
const githubConsumerSource = sourceSlice(
  infraOpsSource,
  "  const expectedWorkflow =",
  "  const latestSecretRotationReport =",
);
const releaseConsumerSource = sourceSlice(
  infraOpsSource,
  "  const latestReleaseReport =",
  "  const latestCloudflareAccessReport =",
);

assert.match(releaseCandidateSource, /latestJsonReport\("release", "release-evidence-", \(payload\) => payload\.mode === "evidence"\)/);
assert.match(releaseCandidateSource, /release\?\.payload\?\.releaseSha \?\? release\?\.payload\?\.git\?\.commit/);
assert.doesNotMatch(releaseCandidateSource, /gitEvidence\(\)/);
assert.match(githubConsumerSource, /releaseCommitShaCandidate\(\) \?\? gitEvidence\(\)\.commit/);
assert.match(githubConsumerSource, /payload\.expectedSha \?\? ""\)\.toLowerCase\(\) === String\(releaseSha\)\.toLowerCase\(\)/);
assert.doesNotMatch(githubConsumerSource, /candidateTree|workloadLock|currentRepository/);
assert.match(reportPassSource, /spec\.label === "runtime-fingerprint"/);
assert.match(reportPassSource, /payload\.mode === "runtime-exact" && payload\.status === "passed" && payload\.git\?\.clean === true/);
assert.match(runtimeConsumerSource, /runtimeFingerprintFresh\.fresh && runtimeFingerprintResult\.passed/);
assert.doesNotMatch(runtimeConsumerSource, /git\.commit|expected\.commit|actual\.commit|gitEvidence|candidateTree|repository|workloadLock/);
assert.match(runtimeFingerprintSource, /if \(expectedCommit !== actualCommit\) issues\.push/);
assert.doesNotMatch(releaseConsumerSource, /gitEvidence|candidateTree|repository|workloadLock/);
console.log("[PASS] source proof release/GitHub share a report-selected SHA instead of the current candidate SHA");
console.log("[PASS] source proof runtime producer compares commits internally but go/no-go discards those commit fields");

const reportsRoot = path.join(sourceRoot, "reports");
const runtimeRoot = path.join(tmpRoot, "runtime");
const negativeRoot = path.join(tmpRoot, "negative-preservation");
const mockBin = path.join(runtimeRoot, "bin");
const externalCommandMarker = path.join(runtimeRoot, "external-command-used");
let reportsOwned = false;
let runtimeOwned = false;
let completed = false;

try {
  assert.equal(fs.existsSync(reportsRoot), false, "refusing an archive that already contains reports/");
  runNegativePreservationRegression(negativeRoot, ownerToken, tmpRoot);

  createOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
  runtimeOwned = true;
  fs.mkdirSync(mockBin, { mode: 0o700 });
  for (const command of ["cosign", "curl", "docker", "gh", "git", "ssh"]) {
    writeExecutable(
      path.join(mockBin, command),
      "#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$EVIDENCE_BINDING_EXTERNAL_MARKER\"\nexit 97\n",
    );
  }

  createOwnedDirectory(reportsRoot, ownerToken, sourceRoot);
  reportsOwned = true;
  const freshAt = new Date().toISOString();
  writeCommonPassingReports({ reportsRoot, generatedAt: freshAt });

  const priorIdentity = {
    commit: PRIOR_COMMIT,
    tree: PRIOR_TREE,
    repository: PRIOR_REPOSITORY,
    workloadLockSha256: PRIOR_WORKLOAD_LOCK,
  };
  writeIdentityReports({
    reportsRoot,
    generatedAt: freshAt,
    releaseCommit: PRIOR_COMMIT,
    runtimeCommit: PRIOR_COMMIT,
    identity: priorIdentity,
  });
  const priorRun = runExactGoNoGo({ sourceRoot, mockBin, externalCommandMarker });
  assert.equal(priorRun.status, 0, priorRun.diagnostics);
  assert.match(priorRun.stdout, /Production status: go/);
  const priorDecision = latestDecision(reportsRoot);
  assertGateAcceptedTargetedEvidence(priorDecision);
  assert.notEqual(PRIOR_COMMIT, REVISION);
  assert.notEqual(PRIOR_TREE, TREE);
  console.log(`[VULNERABLE prior-commit] candidate=${REVISION} release=${PRIOR_COMMIT} github=${PRIOR_COMMIT} runtime=${PRIOR_COMMIT} decision=go`);

  writeIdentityReports({
    reportsRoot,
    generatedAt: freshAt,
    releaseCommit: PRIOR_COMMIT,
    runtimeCommit: THIRD_COMMIT,
    identity: { ...priorIdentity, commit: THIRD_COMMIT, tree: THIRD_TREE },
  });
  const mixedRun = runExactGoNoGo({ sourceRoot, mockBin, externalCommandMarker });
  assert.equal(mixedRun.status, 0, mixedRun.diagnostics);
  assert.match(mixedRun.stdout, /Production status: go/);
  const mixedDecision = latestDecision(reportsRoot);
  assertGateAcceptedTargetedEvidence(mixedDecision);
  const mixedRuntimePayload = readJson(path.join(reportsRoot, "runtime-fingerprint", "runtime-fingerprint-poc.json"));
  assert.equal(mixedRuntimePayload.git.commit, THIRD_COMMIT);
  assert.notEqual(mixedRuntimePayload.git.commit, PRIOR_COMMIT);
  assert.notEqual(mixedRuntimePayload.git.tree, TREE);
  assert.notEqual(mixedRuntimePayload.git.repository, CURRENT_REPOSITORY);
  assert.notEqual(mixedRuntimePayload.git.workloadLockSha256, CURRENT_WORKLOAD_LOCK);
  console.log(`[VULNERABLE mixed-identity] release=${PRIOR_COMMIT} runtime=${THIRD_COMMIT} wrong_tree=true wrong_repository=true wrong_lock=true decision=go`);

  const staleAt = "2000-01-01T00:00:00.000Z";
  writeIdentityReports({
    reportsRoot,
    generatedAt: staleAt,
    releaseCommit: PRIOR_COMMIT,
    runtimeCommit: PRIOR_COMMIT,
    identity: priorIdentity,
  });
  const staleRun = runExactGoNoGo({ sourceRoot, mockBin, externalCommandMarker });
  assert.equal(staleRun.status, 1, staleRun.diagnostics);
  assert.match(staleRun.stdout, /Production status: no-go/);
  const staleDecision = latestDecision(reportsRoot);
  assert.equal(staleDecision.status, "no-go");
  for (const name of ["runtime-fingerprint-exact", "github-actions-run-success", "release-evidence-and-rollback"]) {
    assert.notEqual(checkByName(staleDecision, name).status, "passed", `${name} unexpectedly accepted expired evidence`);
  }
  console.log("[NEGATIVE CONTROL stale] targeted_evidence=expired decision=no-go");

  exerciseFixedOracle({ freshAt, staleAt, priorIdentity });

  assert.equal(fs.existsSync(externalCommandMarker), false, "the evaluator unexpectedly invoked an external command");
  for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
    assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} changed during the probe`);
  }
  console.log("[SAFE] evaluator_external_commands=0 network=0 Docker=0 SSH=0 secrets=0 live_mutations=0 repository_worktree_mutations=0");
  console.log("[+] result=VULNERABLE canonical_ids=CAN-224,CAN-225");
  completed = true;
} finally {
  let cleanupFailure = null;
  if (reportsOwned && fs.existsSync(reportsRoot)) {
    try {
      removeOwnedDirectory(reportsRoot, ownerToken, sourceRoot);
    } catch (error) {
      cleanupFailure = error;
    }
  }
  if (runtimeOwned && fs.existsSync(runtimeRoot)) {
    try {
      removeOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
    } catch (error) {
      cleanupFailure ??= error;
    }
  }
  if (cleanupFailure) throw cleanupFailure;
}

assert.equal(completed, true);
assert.equal(fs.existsSync(reportsRoot), false);
assert.equal(fs.existsSync(runtimeRoot), false);
console.log("[+] sentinel-authorized temporary cleanup complete; wrapper root remains trap-owned");

function writeCommonPassingReports({ reportsRoot: root, generatedAt }) {
  writeReport(root, "vps-bootstrap", "vps-bootstrap-apply-poc.json", {
    generatedAt,
    mode: "apply",
    status: "applied",
  });
  writeReport(root, "vps-hardening", "vps-hardening-apply-poc.json", {
    generatedAt,
    mode: "apply",
    status: "applied",
    steps: [
      { name: "docker-daemon-config", status: "applied" },
      { name: "ssh-service-reload", status: "applied" },
    ],
  });
  writeReport(root, "vps-host", "vps-host-readiness-poc.json", {
    generatedAt,
    mode: "production",
    status: "passed",
    productionEvidence: true,
    expectedSshPort: "22",
    summary: { failedRequired: 0 },
    checks: [{ name: "ssh-port-expected" }, { name: "ufw-ssh-port-allowed" }],
  });
  writeReport(root, "go-live", "pre-go-live-evidence-poc.json", {
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
  writeReport(root, "healthchecks", "functional-health-poc.json", {
    generatedAt,
    mode: "runtime",
    status: "passed",
    checks: [{ name: "synthetic-runtime-check", passed: true }],
  });
  writeReport(root, "secret-rotation", "secret-rotation-evidence-poc.json", {
    generatedAt,
    mode: "evidence",
    status: "passed",
    verify: { status: "passed" },
    summary: { failedSecrets: 0, expiredSecrets: 0, missingMaterializedFiles: 0 },
    audit: { latestRotationEvent: { action: "synthetic-rotation" } },
  });
  writeReport(root, "dr", "dr-evidence-poc.json", {
    generatedAt,
    status: "passed",
    rpoEvidence: { backupFamilies: [] },
    offsiteEvidence: {
      latestRestoreReport: "synthetic-restore.json",
      latestRestoreOffsite: true,
      latestRestoreCoverage: { complete: true },
    },
  });
  writeReport(root, "alerts", "alert-evidence-poc.json", {
    generatedAt,
    mode: "send-test",
    status: "passed",
    requestedDelivery: { email: true },
  });
  writeReport(root, "uptime", "external-uptime-poc.json", {
    generatedAt,
    status: "passed",
    providerEvidence: {
      provider: "synthetic-provider",
      verified: true,
      authentication: { verified: true, kind: "github-sigstore-cryptographic-attestation" },
    },
    results: [{ name: "public", url: "https://status.example.org/health", ok: true }],
  });
  writeReport(root, "load", "load-benchmark-poc.json", {
    generatedAt,
    status: "passed",
    url: "https://benchmark.example.org/run",
    target: {
      public: true,
      edgeRequired: true,
      edge: { providerMatched: true, provider: "synthetic-edge" },
    },
    profiles: [50, 100, 500].map((users) => ({ users, metric: { errors: 0, p95: 10, maxP95Ms: 1000 } })),
  });
  writeReport(root, "cloudflare-access", "cloudflare-access-admin-poc.json", {
    generatedAt,
    mode: "verifyRemote",
    status: "passed",
    applications: [{ name: "admin", result: "verified" }],
  });
}

function writeIdentityReports({ reportsRoot: root, generatedAt, releaseCommit, runtimeCommit, identity }) {
  const releaseIdentity = { ...identity, commit: releaseCommit };
  const runtimeIdentity = { ...identity, commit: runtimeCommit };
  writeReport(root, "runtime-fingerprint", "runtime-fingerprint-poc.json", {
    generatedAt,
    mode: "runtime-exact",
    status: "passed",
    git: {
      commit: runtimeCommit,
      tree: runtimeIdentity.tree,
      repository: runtimeIdentity.repository,
      workloadLockSha256: runtimeIdentity.workloadLockSha256,
      clean: true,
    },
    expected: { commit: runtimeCommit, project: "platform_infra_vps", services: [] },
    actual: { commit: runtimeCommit, clean: true, project: "platform_infra_vps", containers: [] },
    fingerprint: "b".repeat(64),
    candidate: runtimeIdentity,
  });
  writeReport(root, "github-actions", "github-actions-run-poc.json", {
    generatedAt,
    mode: "verifyRemote",
    status: "passed",
    repo: releaseIdentity.repository,
    workflow: "enterprise-infra.yml",
    expectedSha: releaseCommit,
    run: { status: "completed", conclusion: "success" },
    candidate: releaseIdentity,
  });
  writeReport(root, "release", "release-evidence-poc.json", {
    generatedAt,
    mode: "evidence",
    status: "passed",
    releaseSha: releaseCommit,
    repository: releaseIdentity.repository,
    workloadLockSha256: releaseIdentity.workloadLockSha256,
    git: { commit: releaseCommit, tree: releaseIdentity.tree, dirty: false },
    rollback: { complete: true, firstDeploy: false, dryRun: { validated: true } },
    artifacts: { sbom: { path: "synthetic-sbom.json" } },
    attestations: {
      provenanceRequired: true,
      githubSigstore: {
        status: "passed",
        kind: "github-sigstore-cryptographic-attestation",
        verified: true,
        completeness: "complete",
        commitShaMatched: true,
        commitSha: releaseCommit,
        verifiedTimestampCount: 1,
        attestationCount: 1,
      },
    },
    candidate: releaseIdentity,
  });
}

function runExactGoNoGo({ sourceRoot: root, mockBin: bin, externalCommandMarker: marker }) {
  const result = spawnSync(
    process.execPath,
    [path.join(root, "scripts", "infra-ops.mjs"), "production-go-no-go", "--enforce"],
    {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ""}`,
        PLATFORM_GIT_COMMIT: REVISION,
        PLATFORM_GIT_BRANCH: "main",
        PLATFORM_GIT_DIRTY: "0",
        EVIDENCE_BINDING_EXTERNAL_MARKER: marker,
        GITHUB_TOKEN: "",
        GH_TOKEN: "",
        SSH_AUTH_SOCK: "",
      },
    },
  );
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    diagnostics: `status=${result.status} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()}`,
  };
}

function assertGateAcceptedTargetedEvidence(decision) {
  assert.equal(decision.status, "go");
  assert.equal(decision.summary.blockingRequired, 0);
  for (const name of ["runtime-fingerprint-exact", "github-actions-run-success", "release-evidence-and-rollback"]) {
    assert.equal(checkByName(decision, name).status, "passed", `${name} did not pass`);
  }
}

function exerciseFixedOracle({ freshAt, staleAt, priorIdentity }) {
  const currentIdentity = {
    commit: REVISION,
    tree: TREE,
    repository: CURRENT_REPOSITORY,
    workloadLockSha256: CURRENT_WORKLOAD_LOCK,
  };
  const exact = evidenceSet(currentIdentity, freshAt);
  const prior = evidenceSet(priorIdentity, freshAt);
  const mixed = evidenceSet(currentIdentity, freshAt);
  mixed.runtime.candidate = { ...currentIdentity, commit: THIRD_COMMIT, tree: THIRD_TREE };
  const wrongTree = evidenceSet({ ...currentIdentity, tree: PRIOR_TREE }, freshAt);
  const stale = evidenceSet(currentIdentity, staleAt);

  assert.equal(candidateBindingOracle(currentIdentity, exact), true);
  assert.equal(candidateBindingOracle(currentIdentity, prior), false);
  assert.equal(candidateBindingOracle(currentIdentity, mixed), false);
  assert.equal(candidateBindingOracle(currentIdentity, wrongTree), false);
  assert.equal(candidateBindingOracle(currentIdentity, stale), false);
  console.log("[FIXED ORACLE] exact=accepted prior_commit=rejected mixed_commit=rejected wrong_tree=rejected stale=rejected");
}

function evidenceSet(identity, generatedAt) {
  return Object.fromEntries(
    ["release", "github", "runtime"].map((name) => [name, { generatedAt, candidate: { ...identity } }]),
  );
}

function candidateBindingOracle(candidate, evidence) {
  const keys = ["commit", "tree", "repository", "workloadLockSha256"];
  const now = Date.now();
  for (const record of Object.values(evidence)) {
    const generatedAt = Date.parse(record.generatedAt);
    const ageMs = now - generatedAt;
    if (!Number.isFinite(generatedAt) || ageMs < 0 || ageMs > 24 * 3600000) return false;
    if (keys.some((key) => record.candidate?.[key] !== candidate[key])) return false;
  }
  return true;
}

function latestDecision(root) {
  const directory = path.join(root, "go-no-go");
  const files = fs.readdirSync(directory)
    .filter((name) => name.startsWith("production-go-no-go-") && name.endsWith(".json"))
    .map((name) => path.join(directory, name));
  assert.ok(files.length > 0, "go/no-go evaluator did not write a decision report");
  const reports = files.map((filePath) => ({ filePath, payload: readJson(filePath) }));
  reports.sort((left, right) => Date.parse(right.payload.generatedAt) - Date.parse(left.payload.generatedAt));
  return reports[0].payload;
}

function checkByName(decision, name) {
  const check = decision.checks.find((entry) => entry.name === name);
  assert.ok(check, `missing go/no-go check: ${name}`);
  return check;
}

function writeReport(root, directory, name, payload) {
  const targetDirectory = path.join(root, directory);
  fs.mkdirSync(targetDirectory, { recursive: true, mode: 0o700 });
  const target = path.join(targetDirectory, name);
  fs.writeFileSync(target, `${JSON.stringify(payload, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(target, 0o600);
  return target;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function runNegativePreservationRegression(directory, token, parent) {
  fs.mkdirSync(directory, { mode: 0o700 });
  const foreignToken = `${token.slice(0, -1)}${token.endsWith("0") ? "1" : "0"}`;
  const ownerFile = path.join(directory, ".poc-owner");
  const preserveFile = path.join(directory, "preserve-me.txt");
  fs.writeFileSync(ownerFile, foreignToken, { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(preserveFile, "must-survive-refused-cleanup\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  assert.throws(() => removeOwnedDirectory(directory, token, parent), /ownership sentinel mismatch/);
  assert.equal(fs.readFileSync(preserveFile, "utf8"), "must-survive-refused-cleanup\n");
  fs.writeFileSync(ownerFile, token, { encoding: "utf8", flag: "w", mode: 0o600 });
  removeOwnedDirectory(directory, token, parent);
  assert.equal(fs.existsSync(directory), false);
  console.log("[PASS] negative preservation mismatched sentinel refused deletion and preserved existing data");
}

function createOwnedDirectory(directory, token, parent) {
  const parentReal = verifiedRealDirectory(parent, "owned-directory parent");
  assert.equal(path.dirname(path.resolve(directory)), parentReal, "owned directory must be a direct child of its verified parent");
  fs.mkdirSync(directory, { mode: 0o700 });
  const ownerFile = path.join(directory, ".poc-owner");
  fs.writeFileSync(ownerFile, token, { encoding: "utf8", flag: "wx", mode: 0o600 });
}

function removeOwnedDirectory(directory, token, parent) {
  const parentReal = verifiedRealDirectory(parent, "cleanup parent");
  assert.equal(path.dirname(path.resolve(directory)), parentReal, "cleanup target must be a direct child of its verified parent");
  const stats = fs.lstatSync(directory, { throwIfNoEntry: false });
  assert.ok(stats?.isDirectory() && !stats.isSymbolicLink(), "cleanup target must be a real directory");
  assert.equal(fs.realpathSync(directory), path.resolve(directory), "cleanup target realpath mismatch");
  const ownerFile = path.join(directory, ".poc-owner");
  assertRegularFile(ownerFile, "cleanup ownership sentinel");
  assert.equal(fs.readFileSync(ownerFile, "utf8"), token, "ownership sentinel mismatch");
  fs.rmSync(directory, { recursive: true });
}

function verifiedRealDirectory(input, label) {
  const resolved = path.resolve(input);
  const stats = fs.lstatSync(resolved, { throwIfNoEntry: false });
  assert.ok(stats?.isDirectory() && !stats.isSymbolicLink(), `${label} must be a real directory`);
  const real = fs.realpathSync(resolved);
  assert.equal(real, resolved, `${label} realpath mismatch`);
  return real;
}

function assertRegularFile(filePath, label) {
  const stats = fs.lstatSync(filePath, { throwIfNoEntry: false });
  assert.ok(stats?.isFile() && !stats.isSymbolicLink(), `${label} must be a regular file`);
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
  fs.writeFileSync(filePath, contents, { encoding: "utf8", flag: "wx", mode: 0o700 });
}
