#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_HASHES = new Map([
  ["scripts/deploy-vps.sh", "ee572ce2164fa620c59eb63cecc5d75db02f58d9e664bf923400b5315ef75245"],
  ["scripts/deploy-vps-remote.sh", "e7460e9db36765e6078d778d8a5388d54a78ee4620ddb70f2f7a19187f937804"],
  ["scripts/vps-postdeploy.sh", "e88fa132b375d110933e473a0dc80f10ebe06ab37eb8741ba2a8139a06da7963"],
  ["scripts/pre-go-live-evidence.sh", "6b0b5511873700cb443a1a6bfbfe2f3a78b86a2f58c8b0d796810b6d4ae87242"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["SECURITY.md", "b72a0abd090dfa15832d5af3e389edeee50cf5128cbd515e7c74b6a72f4d9cb3"],
]);

const [sourceArgument, wrapperArgument, sentinelArgument] = process.argv.slice(2);
if (!sourceArgument || !wrapperArgument || !sentinelArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned archive");
}

const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const wrapperRoot = exactPhysicalDirectory(wrapperArgument, "wrapper root");
const sourceRoot = exactPhysicalDirectory(sourceArgument, "source archive");
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source archive must be the exact wrapper child");

const sentinelPath = path.resolve(sentinelArgument);
const sentinelStat = fs.lstatSync(sentinelPath);
assert.equal(sentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(sentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel is a symbolic link");
assert.equal(fs.realpathSync(sentinelPath), sentinelPath, "wrapper ownership sentinel must use its physical path");
assert.equal(path.dirname(sentinelPath), wrapperRoot, "wrapper ownership sentinel escaped the wrapper root");
const sentinelMatch = path.basename(sentinelPath).match(/^\.fg052-wrapper-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(sentinelPath, "utf8"),
  `fg052-release-admission:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} is not the expected source`);
}

const clientSource = readSource("scripts/deploy-vps.sh");
const remoteSource = readSource("scripts/deploy-vps-remote.sh");
const postdeploySource = readSource("scripts/vps-postdeploy.sh");
const preGoLiveWrapper = readSource("scripts/pre-go-live-evidence.sh");
const infraOpsSource = readSource("scripts/infra-ops.mjs");
const securityPolicy = readSource("SECURITY.md");

assert.match(clientSource, /BRANCH="\$\{DEPLOY_BRANCH:-main\}"/);
assert.match(clientSource, /PLATFORM_BRANCH_B64/);
assert.doesNotMatch(clientSource, /PLATFORM_EXPECTED_(?:COMMIT|TREE)_B64/);
assertOrdered(remoteSource, [
  "git fetch --all --prune",
  "git checkout \"$branch\"",
  "git pull --ff-only origin \"$branch\"",
  "sh ./scripts/vps-preflight.sh \"$env_file\"",
  "sh ./scripts/prepare-vps-runtime.sh",
  "bash ./scripts/compose-vps.sh up -d --build --remove-orphans",
]);
const firstCandidateExecution = remoteSource.indexOf("sh ./scripts/vps-preflight.sh");
const remotePrefix = remoteSource.slice(0, firstCandidateExecution);
assert.doesNotMatch(remotePrefix, /rev-parse|release-artifact|attestation|provenance|EXPECTED_COMMIT|EXPECTED_TREE/);
assert.match(postdeploySource, /sh \.\/scripts\/pre-go-live-evidence\.sh "\$@"/);
assert.match(preGoLiveWrapper, /pre-go-live-evidence/);
assert.match(securityPolicy, /Release admission must invoke the checksum-pinned GitHub verifier directly/);

const preGoLiveFunction = sliceBetweenFunctions(
  infraOpsSource,
  "async function preGoLiveEvidence()",
  "function productionGoNoGoPolicy()",
);
const releaseEvidenceFunction = sliceBetweenFunctions(
  infraOpsSource,
  "async function releaseEvidence(options = {})",
  "async function githubAttestationEvidence()",
);
const collectEvidenceFunction = sliceBetweenFunctions(
  infraOpsSource,
  "async function collectEvidenceStep(steps, { name, category, required = true, fn })",
  "function skipEvidenceStep",
);
const readinessFunction = sliceBetweenFunctions(
  infraOpsSource,
  "function buildPreGoLiveReadinessMatrix({ steps, options, repo })",
  "async function preGoLiveEvidence()",
);
assert.match(preGoLiveFunction, /releaseEvidence\(\{ planOnly: true \}\)/);
const enforcementBlock = sliceBetweenFunctions(
  releaseEvidenceFunction,
  "if (!planOnly) {",
  "const sbom = planOnly",
);
assert.match(enforcementBlock, /releaseArtifactGate\(\{/);
assert.doesNotMatch(
  releaseEvidenceFunction.slice(0, releaseEvidenceFunction.indexOf("if (!planOnly)")),
  /releaseArtifactGate\(/,
);
assert.match(collectEvidenceFunction, /await fn\(\);[\s\S]*status: "passed"/);
assert.match(readinessFunction, /"release-evidence-plan"/);
assert.match(releaseEvidenceFunction, /status: planOnly \? "plan"/);

console.log("[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true");
console.log("[+] source hashes deploy_client=true remote=true postdeploy=true pre_go_live=true infra_ops=true policy=true");
console.log("[SOURCE] selected_branch_transmitted=true expected_commit_transmitted=false expected_tree_transmitted=false");
console.log("[SOURCE] branch_pull_before_candidate_execution=true trusted_admission_before_execution=false");
console.log("[SOURCE] pre_go_live_release_evidence_plan_only=true artifact_gate_inside_not_plan_only=true plan_step_recorded_pass_on_nonthrow=true");

const cleanupGuardRoot = path.join(wrapperRoot, "cleanup-guard");
const cleanupGuard = claimOwnedDirectory(cleanupGuardRoot, wrapperRoot, ownerToken, "cleanup-guard");
const preservedPath = path.join(cleanupGuardRoot, "preserve.txt");
fs.writeFileSync(preservedPath, "pre-existing evidence must survive rejected cleanup\n", { mode: 0o600, flag: "wx" });
assert.throws(
  () => cleanupOwnedDirectory(cleanupGuard, "0".repeat(64)),
  /cleanup ownership token mismatch/,
);
assert.equal(fs.readFileSync(preservedPath, "utf8"), "pre-existing evidence must survive rejected cleanup\n");
console.log("[GUARD] mismatched_cleanup_sentinel_refused=true evidence_preserved=true");
cleanupOwnedDirectory(cleanupGuard, ownerToken);

const fixtureRoot = path.join(wrapperRoot, "release-admission-fixture");
const fixtureOwnership = claimOwnedDirectory(fixtureRoot, wrapperRoot, ownerToken, "fixture");
let receiptHash = null;

try {
  const vulnerable = prepareScenario(fixtureRoot, "vulnerable-exact-remote");
  const preSnapshot = snapshotScenario(vulnerable);
  const vulnerableResult = spawnSync("/bin/sh", [path.join(sourceRoot, "scripts/deploy-vps-remote.sh")], {
    cwd: vulnerable.root,
    encoding: "utf8",
    env: remoteEnvironment(vulnerable),
  });
  assert.equal(vulnerableResult.status, 0, diagnostics("vulnerable", vulnerableResult, vulnerable.traceFile));
  const vulnerableTrace = readTrace(vulnerable.traceFile);
  assertOrdered(vulnerableTrace.join("\n"), [
    "git:fetch --all --prune",
    "git:checkout main",
    "git:pull --ff-only origin main",
    "payload:vps-preflight",
    "payload:prepare-vps-runtime",
    "sink:compose up -d --build --remove-orphans",
    "payload:vps-postdeploy",
  ]);
  assert.equal(vulnerableTrace.some((line) => line.startsWith("admission:")), false);
  assert.equal(fs.readFileSync(vulnerable.markerFile, "utf8"), "synthetic branch payload executed\n");
  const postSnapshot = snapshotScenario(vulnerable);

  console.log("[VULNERABLE] fetched_branch_payload_executed=true admission_calls_before_payload=0 compose_sink_reached=true");

  const identityMismatch = prepareScenario(fixtureRoot, "negative-identity-mismatch", {
    syntheticCommit: "1".repeat(40),
    syntheticTree: TREE,
  });
  const mismatchResult = runGuard(identityMismatch, "enforce");
  assert.equal(mismatchResult.status, 65, diagnostics("identity-mismatch", mismatchResult, identityMismatch.traceFile));
  assert.equal(fs.existsSync(identityMismatch.markerFile), false);
  assert.match(readTrace(identityMismatch.traceFile).join("\n"), /guard:identity-rejected/);
  console.log("[NEGATIVE-CONTROL] identity_mismatch_rejected=true payload_executed=false");

  const planOnly = prepareScenario(fixtureRoot, "negative-plan-only", {
    syntheticCommit: REVISION,
    syntheticTree: TREE,
  });
  const planResult = runGuard(planOnly, "plan");
  assert.equal(planResult.status, 66, diagnostics("plan-only", planResult, planOnly.traceFile));
  assert.equal(fs.existsSync(planOnly.markerFile), false);
  const planTrace = readTrace(planOnly.traceFile);
  assert.match(planTrace.join("\n"), /admission:mode=plan/);
  assert.equal(planTrace.some((line) => line === "guard:admission-passed"), false);
  console.log("[NEGATIVE-CONTROL] plan_only_not_admitted=true payload_executed=false");

  const enforced = prepareScenario(fixtureRoot, "positive-enforced", {
    syntheticCommit: REVISION,
    syntheticTree: TREE,
  });
  const enforcedResult = runGuard(enforced, "enforce");
  assert.equal(enforcedResult.status, 0, diagnostics("enforced", enforcedResult, enforced.traceFile));
  assert.equal(fs.readFileSync(enforced.markerFile, "utf8"), "synthetic branch payload executed\n");
  assertOrdered(readTrace(enforced.traceFile).join("\n"), [
    "guard:identity commit=",
    "admission:mode=enforce",
    "admission:pass",
    "guard:admission-passed",
    "payload:vps-preflight",
    "sink:compose up -d --build --remove-orphans",
  ]);
  console.log("[REFERENCE] enforced_admission_before_payload=true compose_sink_after_admission=true");

  const generatedAt = new Date().toISOString();
  const receipt = {
    schema: "release-admission-order-poc/v1",
    generatedAt,
    input: {
      revision: REVISION,
      tree: TREE,
      archiveSha256: process.env.FG052_ARCHIVE_SHA256 ?? null,
    },
    sourceHashes: Object.fromEntries(EXPECTED_HASHES),
    snapshots: { pre: preSnapshot, post: postSnapshot },
    vulnerableTraceSha256: sha256(Buffer.from(`${vulnerableTrace.join("\n")}\n`, "utf8")),
    controls: {
      identityMismatchRejected: true,
      planOnlyNotAdmitted: true,
      enforcedAdmissionBeforePayload: true,
    },
    result: "VULNERABLE",
  };
  const receiptPath = path.join(fixtureRoot, "receipt.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  assert.deepEqual(JSON.parse(fs.readFileSync(receiptPath, "utf8")), receipt);
  receiptHash = sha256File(receiptPath);
  console.log(`[RECEIPT] generated_at=${generatedAt} sha256=${receiptHash}`);
  console.log(`[SNAPSHOT] pre_sha256=${preSnapshot.sha256} post_sha256=${postSnapshot.sha256}`);
  console.log("[+] safety ssh_calls=0 network_calls=0 docker_calls=0 credential_reads=0 live_mutations=0 source_mutations=0");
  console.log("[+] result=VULNERABLE");
} finally {
  cleanupOwnedDirectory(fixtureOwnership, ownerToken);
}

assert.match(receiptHash ?? "", /^[a-f0-9]{64}$/);
assert.equal(fs.existsSync(fixtureRoot), false, "sentinel-owned fixture was not removed");
console.log("[+] cleanup sentinel_owned_fixture_removed=true");

function prepareScenario(parent, label, options = {}) {
  const root = path.join(parent, label);
  fs.mkdirSync(root, { mode: 0o700 });
  const remoteRoot = path.join(root, "remote");
  const scriptsRoot = path.join(remoteRoot, "scripts");
  const payloadRoot = path.join(root, "payload");
  const mockBin = path.join(root, "bin");
  fs.mkdirSync(scriptsRoot, { recursive: true, mode: 0o700 });
  fs.mkdirSync(payloadRoot, { mode: 0o700 });
  fs.mkdirSync(mockBin, { mode: 0o700 });
  fs.writeFileSync(path.join(remoteRoot, ".env"), "SYNTHETIC_FIXTURE=1\n", { mode: 0o600 });

  const failClosedBaseline = "#!/bin/sh\nprintf '%s\\n' 'unexpected baseline script execution' >&2\nexit 98\n";
  for (const name of ["vps-preflight.sh", "prepare-vps-runtime.sh", "compose-vps.sh", "vps-postdeploy.sh"]) {
    writeExecutable(path.join(scriptsRoot, name), failClosedBaseline);
  }

  writeExecutable(path.join(payloadRoot, "vps-preflight.sh"), `#!/bin/sh
set -eu
printf '%s\\n' 'payload:vps-preflight' >> "$TRACE_FILE"
printf '%s\\n' 'synthetic branch payload executed' > "$ATTACK_MARKER"
`);
  writeExecutable(path.join(payloadRoot, "prepare-vps-runtime.sh"), `#!/bin/sh
set -eu
printf '%s\\n' 'payload:prepare-vps-runtime' >> "$TRACE_FILE"
`);
  writeExecutable(path.join(payloadRoot, "compose-vps.sh"), `#!/bin/sh
set -eu
printf 'sink:compose %s\\n' "$*" >> "$TRACE_FILE"
`);
  writeExecutable(path.join(payloadRoot, "vps-postdeploy.sh"), `#!/bin/sh
set -eu
printf '%s\\n' 'payload:vps-postdeploy' >> "$TRACE_FILE"
`);

  const traceFile = path.join(root, "trace.log");
  const markerFile = path.join(root, "attacker-executed.marker");
  fs.writeFileSync(traceFile, "", { mode: 0o600 });
  const syntheticCommit = options.syntheticCommit ?? "1".repeat(40);
  const syntheticTree = options.syntheticTree ?? "2".repeat(40);

  writeExecutable(path.join(mockBin, "git"), `#!/bin/sh
set -eu
printf 'git:%s\\n' "$*" >> "$TRACE_FILE"
case "$1" in
  fetch|checkout) ;;
  pull)
    for name in vps-preflight.sh prepare-vps-runtime.sh compose-vps.sh vps-postdeploy.sh; do
      cp "$PAYLOAD_ROOT/$name" "$REMOTE_ROOT/scripts/$name"
      chmod 700 "$REMOTE_ROOT/scripts/$name"
    done
    ;;
  rev-parse)
    case "$*" in
      *HEAD*tree*) printf '%s\\n' "$SYNTHETIC_TREE" ;;
      *) printf '%s\\n' "$SYNTHETIC_COMMIT" ;;
    esac
    ;;
  *) exit 97 ;;
esac
`);

  const trustedAdmission = path.join(root, "trusted-admission-stub.sh");
  writeExecutable(trustedAdmission, `#!/bin/sh
set -eu
printf 'admission:mode=%s args=%s\\n' "$ADMISSION_MODE" "$*" >> "$TRACE_FILE"
if [ "$ADMISSION_MODE" = plan ]; then
  printf '%s\\n' 'admission:plan-rejected' >> "$TRACE_FILE"
  exit 66
fi
printf '%s\\n' 'admission:pass' >> "$TRACE_FILE"
`);

  return {
    label,
    root,
    remoteRoot,
    payloadRoot,
    mockBin,
    traceFile,
    markerFile,
    trustedAdmission,
    syntheticCommit,
    syntheticTree,
  };
}

function remoteEnvironment(scenario) {
  return {
    ...baseScenarioEnvironment(scenario),
    PLATFORM_REMOTE_DIR_B64: encodeField(scenario.remoteRoot),
    PLATFORM_BRANCH_B64: encodeField("main"),
    PLATFORM_ENV_FILE_B64: encodeField(".env"),
    PLATFORM_PROJECT_NAME_B64: encodeField("release_admission_poc"),
    PLATFORM_RUN_WAF_SMOKE_B64: encodeField("0"),
    PLATFORM_RUN_INFRA_HEALTH_B64: encodeField("0"),
    PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64: encodeField("0"),
    PLATFORM_RUN_PRE_GO_LIVE_B64: encodeField("0"),
    PLATFORM_RUN_GO_NO_GO_B64: encodeField("0"),
    PLATFORM_DEPLOY_REPO_B64: encodeField("owner/repository"),
    PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64: encodeField("0"),
    PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64: encodeField("0"),
    PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64: encodeField("0"),
    PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64: encodeField("0"),
  };
}

function runGuard(scenario, admissionMode) {
  return spawnSync("/bin/sh", [path.join(scriptRoot, "trusted-admission-guard.sh")], {
    cwd: scenario.root,
    encoding: "utf8",
    env: {
      ...baseScenarioEnvironment(scenario),
      REMOTE_ROOT: scenario.remoteRoot,
      BRANCH: "main",
      EXPECTED_COMMIT: REVISION,
      EXPECTED_TREE: TREE,
      TRUSTED_ADMISSION: scenario.trustedAdmission,
      ADMISSION_MODE: admissionMode,
    },
  });
}

function baseScenarioEnvironment(scenario) {
  return {
    HOME: scenario.root,
    LANG: "C",
    LC_ALL: "C",
    PATH: `${scenario.mockBin}${path.delimiter}/usr/bin:/bin`,
    TRACE_FILE: scenario.traceFile,
    ATTACK_MARKER: scenario.markerFile,
    PAYLOAD_ROOT: scenario.payloadRoot,
    REMOTE_ROOT: scenario.remoteRoot,
    SYNTHETIC_COMMIT: scenario.syntheticCommit,
    SYNTHETIC_TREE: scenario.syntheticTree,
  };
}

function snapshotScenario(scenario) {
  const state = {
    markerExists: fs.existsSync(scenario.markerFile),
    traceSha256: sha256File(scenario.traceFile),
    scriptHashes: Object.fromEntries(
      ["vps-preflight.sh", "prepare-vps-runtime.sh", "compose-vps.sh", "vps-postdeploy.sh"]
        .map((name) => [name, sha256File(path.join(scenario.remoteRoot, "scripts", name))]),
    ),
  };
  return { ...state, sha256: sha256(Buffer.from(JSON.stringify(state), "utf8")) };
}

function exactPhysicalDirectory(argument, label) {
  const resolved = path.resolve(argument);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  const physical = fs.realpathSync(resolved);
  assert.equal(physical, resolved, `${label} argument must be its exact physical path`);
  return physical;
}

function sliceBetweenFunctions(source, signature, nextSignature) {
  const start = source.indexOf(signature);
  const end = source.indexOf(nextSignature, start + signature.length);
  assert.ok(start >= 0, `missing source fragment: ${signature}`);
  assert.ok(end > start, `missing source boundary: ${nextSignature}`);
  assert.equal(source.indexOf(signature, start + signature.length), -1, `ambiguous source fragment: ${signature}`);
  return source.slice(start, end);
}

function assertOrdered(source, fragments) {
  let cursor = -1;
  for (const fragment of fragments) {
    const next = source.indexOf(fragment, cursor + 1);
    assert.ok(next > cursor, `missing or out-of-order fragment: ${fragment}`);
    cursor = next;
  }
}

function encodeField(value) {
  return Buffer.from(value, "utf8").toString("base64");
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function readTrace(traceFile) {
  return fs.readFileSync(traceFile, "utf8").split("\n").filter(Boolean);
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function writeExecutable(filePath, contents) {
  fs.writeFileSync(filePath, contents, { mode: 0o700, flag: "wx" });
}

function claimOwnedDirectory(targetPath, expectedParent, token, label) {
  assert.equal(path.dirname(targetPath), expectedParent, `${label} target escaped its expected parent`);
  assert.equal(fs.existsSync(targetPath), false, `${label} target already exists`);
  fs.mkdirSync(targetPath, { mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true);
  assert.equal(targetStat.isSymbolicLink(), false);
  assert.equal(fs.realpathSync(targetPath), targetPath);
  const ownershipSentinel = path.join(targetPath, `.fg052-inner-owner-${token}`);
  fs.writeFileSync(ownershipSentinel, `fg052-inner:${token}\n`, { mode: 0o600, flag: "wx" });
  const sentinelStatInner = fs.lstatSync(ownershipSentinel);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    ownershipSentinel,
    sentinelDevice: sentinelStatInner.dev,
    sentinelInode: sentinelStatInner.ino,
    token,
  };
}

function cleanupOwnedDirectory(ownership, suppliedToken) {
  assert.equal(suppliedToken, ownership.token, "cleanup ownership token mismatch");
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through target symlink");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  const cleanupSentinelStat = fs.lstatSync(ownership.ownershipSentinel);
  assert.equal(cleanupSentinelStat.isFile(), true, "cleanup sentinel is not a regular file");
  assert.equal(cleanupSentinelStat.isSymbolicLink(), false, "cleanup sentinel is a symbolic link");
  assert.equal(cleanupSentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(cleanupSentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.ownershipSentinel, "utf8"),
    `fg052-inner:${suppliedToken}\n`,
    "cleanup sentinel content changed",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}

function diagnostics(label, result, traceFile) {
  const trace = fs.existsSync(traceFile) ? readTrace(traceFile).join("|") : "missing";
  return `scenario=${label} status=${result.status} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()} trace=${trace}`;
}
