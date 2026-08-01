#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const MUTABLE_IMAGE = "platform/ops:local";
const APPROVED_DIGEST = `sha256:${"a".repeat(64)}`;
const APPROVED_IMAGE = `registry.example.invalid/platform/ops@${APPROVED_DIGEST}`;
const APPROVED_FINGERPRINT = "f".repeat(64);
const PROBE_PATH = fileURLToPath(import.meta.url);
const EXPECTED_HASHES = new Map([
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/hosted-workload-lock.sh", "f87317c017f541796f4144442a07c3c98e0b280aafb11396bd64852571390674"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/infra-ops.sh", "9e97cba91e877c34066c57509655a55f8bf67dab632d0a1e507242fdc8fb8901"],
]);

if (process.argv[2] === "--mock-docker") {
  mockDockerMain(process.argv.slice(3));
  process.exit(0);
}
if (process.argv[2] === "--mock-bash") {
  mockBashMain(process.argv.slice(3));
  process.exit(0);
}

const sourceArgument = String(process.argv[2] || "");
const tmpArgument = String(process.env.OPS_IMAGE_POC_TMP_ROOT || "");
const ownerToken = String(process.env.OPS_IMAGE_POC_OWNER_TOKEN || "");
if (!sourceArgument || !tmpArgument || !ownerToken) {
  throw new Error("run this probe through run-from-git-archive.sh");
}

const tmpRoot = verifiedRealDirectory(tmpArgument, "wrapper temporary root");
const sourceRoot = verifiedRealDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(tmpRoot, "source"), "source must be the exact wrapper-owned source child");
assert.match(ownerToken, /^[a-f0-9]{64}$/, "invalid wrapper ownership token");
const rootOwnerFile = path.join(tmpRoot, ".ops-bootstrap-image-trust-poc-owner");
assertRegularFile(rootOwnerFile, "wrapper ownership sentinel");
assert.equal(fs.readFileSync(rootOwnerFile, "utf8"), ownerToken, "wrapper ownership sentinel mismatch");

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  const target = path.join(sourceRoot, relativePath);
  assertRegularFile(target, `pinned source ${relativePath}`);
  assert.equal(sha256File(target), expectedHash, `${relativePath} is not the expected vulnerable source`);
}
console.log(`[PASS] exact pre-fix sources revision=${REVISION} tree=${TREE}`);

const preparePath = path.join(sourceRoot, "scripts", "prepare-hosted-workloads.sh");
const lockPath = path.join(sourceRoot, "scripts", "hosted-workload-lock.sh");
const composePath = path.join(sourceRoot, "scripts", "compose-vps.sh");
const infraOpsPath = path.join(sourceRoot, "scripts", "infra-ops.sh");
const prepareSource = fs.readFileSync(preparePath, "utf8");
const lockSource = fs.readFileSync(lockPath, "utf8");
const composeSource = fs.readFileSync(composePath, "utf8");
const infraOpsSource = fs.readFileSync(infraOpsPath, "utf8");

assert.match(prepareSource, /OPS_IMAGE=\$\{PLATFORM_OPS_IMAGE:-platform\/ops:local\}/);
assert.equal((prepareSource.match(/docker run/g) || []).length, 2, "expected exactly two vulnerable docker run sites");
assert.doesNotMatch(prepareSource, /--pull(?:=|\s)/);
assert.doesNotMatch(prepareSource, /docker image inspect|OPS_SOURCE_FINGERPRINT|cosign|@sha256:/);
assert.match(prepareSource, /-v "\$\(dirname "\$OUTPUT"\):\$\(dirname "\$OUTPUT"\)"/);
assert.match(lockSource, /expected=\$\(jq -r "\.files\[\$index\]\.sha256" "\$LOCK"\)/);
assert.match(lockSource, /actual=\$\(sha256sum "\$file"/);
assert.match(composeSource, /compose\+=\(-f "\$workload_file"\)/);
assert.match(infraOpsSource, /OPS_SOURCE_FINGERPRINT=\$\(/);
assert.match(infraOpsSource, /CURRENT_OPS_FINGERPRINT=\$\(docker image inspect/);
assert.match(infraOpsSource, /docker build[\s\S]*-t "\$OPS_IMAGE"/);
console.log("[PASS] source proof mutable default reaches two runs without digest, verification, or --pull=never");
console.log("[PASS] source proof writable output and self-authored hashes flow into downstream Compose -f arguments");

const runtimeRoot = path.join(tmpRoot, "runtime");
const negativeRoot = path.join(tmpRoot, "negative-preservation");
let runtimeOwned = false;
let completed = false;

try {
  runNegativePreservationRegression(negativeRoot, ownerToken, tmpRoot);
  createOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
  runtimeOwned = true;

  const mockBin = path.join(runtimeRoot, "bin");
  fs.mkdirSync(mockBin, { mode: 0o700 });
  writeExecutable(
    path.join(mockBin, "docker"),
    "#!/bin/sh\nexec \"$OPS_IMAGE_POC_NODE\" \"$OPS_IMAGE_POC_PROBE\" --mock-docker \"$@\"\n",
  );
  writeExecutable(
    path.join(mockBin, "bash"),
    "#!/bin/sh\nexec \"$OPS_IMAGE_POC_NODE\" \"$OPS_IMAGE_POC_PROBE\" --mock-bash \"$@\"\n",
  );
  writeExecutable(
    path.join(mockBin, "stat"),
    "#!/bin/sh\nif [ \"${1:-}\" = -c ] && [ \"${2:-}\" = %a ]; then printf '%s\\n' 600; exit 0; fi\nprintf '%s\\n' unexpected-stat-invocation > \"$OPS_IMAGE_POC_UNEXPECTED_MARKER\"\nexit 97\n",
  );

  const implicit = runScenario({
    name: "implicit-pull",
    localPresent: false,
    runtimeRoot,
    mockBin,
    sourceRoot,
    preparePath,
    composePath,
  });
  assert.equal(implicit.runRecords.length, 2);
  assert.ok(implicit.runRecords.every((record) => record.image === MUTABLE_IMAGE));
  assert.ok(implicit.runRecords.every((record) => record.pullPolicy === "missing"));
  assert.ok(implicit.runRecords.every((record) => record.implicitPull === true));
  assert.ok(implicit.runRecords.every((record) => record.networkNone === true));
  assert.equal(implicit.forgedLock.state, "verified");
  assert.equal(implicit.downstreamIncluded, true);
  console.log(`[VULNERABLE implicit-pull] image=${MUTABLE_IMAGE} run_count=2 pull_policy=missing implicit_pull=true forged_lock=verified downstream_compose_included=true`);

  const replacement = runScenario({
    name: "local-replacement",
    localPresent: true,
    runtimeRoot,
    mockBin,
    sourceRoot,
    preparePath,
    composePath,
  });
  assert.equal(replacement.runRecords.length, 2);
  assert.ok(replacement.runRecords.every((record) => record.image === MUTABLE_IMAGE));
  assert.ok(replacement.runRecords.every((record) => record.pullPolicy === "missing"));
  assert.ok(replacement.runRecords.every((record) => record.implicitPull === false));
  assert.equal(replacement.forgedLock.state, "verified");
  assert.equal(replacement.downstreamIncluded, true);
  console.log(`[VULNERABLE local-replacement] image=${MUTABLE_IMAGE} run_count=2 image_verified=false forged_lock=verified downstream_compose_included=true`);

  exerciseFixedOracle();

  for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
    assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} changed during the probe`);
  }
  assert.equal(fs.existsSync(path.join(sourceRoot, "reports")), false, "probe unexpectedly created archived-source reports");
  console.log("[SAFE] docker_daemon_calls=0 network=0 pulls=0 containers=0 live_mutations=0 candidate_mutations=0");
  console.log("[+] result=VULNERABLE canonical_id=CAN-131");
  completed = true;
} finally {
  if (runtimeOwned && fs.existsSync(runtimeRoot)) {
    removeOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
  }
}

assert.equal(completed, true);
assert.equal(fs.existsSync(runtimeRoot), false);
console.log("[+] sentinel-authorized temporary cleanup complete; wrapper root remains trap-owned");

function runScenario({ name, localPresent, runtimeRoot: root, mockBin, sourceRoot: source, preparePath: prepare, composePath: compose }) {
  const scenarioRoot = path.join(root, "scenarios", name);
  const home = path.join(scenarioRoot, "home");
  const workloadRoot = path.join(scenarioRoot, "workloads");
  const outputRoot = path.join(scenarioRoot, "output");
  const targetTmp = path.join(scenarioRoot, "target-tmp");
  const envFile = path.join(scenarioRoot, "compose.env");
  const catalog = path.join(scenarioRoot, "catalog.json");
  const bashEnv = path.join(scenarioRoot, "bash-compat.sh");
  const lockOutput = path.join(outputRoot, "hosted-workloads.lock.json");
  const dockerLog = path.join(scenarioRoot, "docker.jsonl");
  const bashLog = path.join(scenarioRoot, "bash.jsonl");
  const unexpectedMarker = path.join(scenarioRoot, "unexpected-command");
  for (const directory of [scenarioRoot, home, workloadRoot, outputRoot, targetTmp]) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(envFile, "# synthetic non-secret environment\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(catalog, '{"version":1,"workloads":[]}\n', { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(
    bashEnv,
    [
      "mapfile() {",
      "  if [ \"${1:-}\" = -t ]; then shift; fi",
      "  local target=${1:-} line index=0",
      "  case \"$target\" in ''|*[!A-Za-z0-9_]*) return 97 ;; esac",
      "  eval \"$target=()\"",
      "  while IFS= read -r line; do",
      "    eval \"$target[$index]=\\$line\"",
      "    index=$((index + 1))",
      "  done",
      "}",
      "",
    ].join("\n"),
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );

  const environment = {
    PATH: `${mockBin}:/usr/bin:/bin:/usr/sbin:/sbin`,
    HOME: home,
    LANG: "C",
    LC_ALL: "C",
    NODE_OPTIONS: "",
    BASH_ENV: bashEnv,
    TMPDIR: targetTmp,
    COMPOSE_ENV_FILE: envFile,
    COMPOSE_PROJECT_NAME: "poc_platform",
    HOSTED_WORKLOAD_CATALOG: catalog,
    HOSTED_WORKLOAD_ROOT: workloadRoot,
    HOSTED_WORKLOAD_LOCK: lockOutput,
    OPS_IMAGE_POC_NODE: process.execPath,
    OPS_IMAGE_POC_PROBE: PROBE_PATH,
    OPS_IMAGE_POC_SCENARIO: name,
    OPS_IMAGE_POC_LOCAL_PRESENT: localPresent ? "1" : "0",
    OPS_IMAGE_POC_DOCKER_LOG: dockerLog,
    OPS_IMAGE_POC_BASH_LOG: bashLog,
    OPS_IMAGE_POC_UNEXPECTED_MARKER: unexpectedMarker,
    OPS_IMAGE_POC_CORE_ENV: envFile,
    OPS_IMAGE_POC_PROJECT: "poc_platform",
  };

  const prepareResult = spawnSync("/bin/bash", [prepare], {
    cwd: source,
    encoding: "utf8",
    env: environment,
  });
  assert.equal(
    prepareResult.status,
    0,
    `prepare scenario=${name} status=${prepareResult.status} stdout=${prepareResult.stdout.trim()} stderr=${prepareResult.stderr.trim()}`,
  );
  assert.match(prepareResult.stdout, /Verified hosted workload lock:/);
  assert.equal(fs.existsSync(unexpectedMarker), false, `unexpected command in scenario ${name}`);
  assert.equal(fs.readdirSync(targetTmp).length, 0, `target temporary directory was not cleaned in scenario ${name}`);

  const firstRecords = readJsonLines(dockerLog);
  const runRecords = firstRecords.filter((record) => record.kind === "run");
  assert.equal(runRecords.length, 2, `scenario ${name} did not reach both docker run sites`);
  assert.ok(runRecords.every((record) => record.hasExplicitPull === false));
  assert.ok(runRecords.every((record) => record.userSpecified === true));
  assert.equal(runRecords.find((record) => record.operation === "verify-render")?.writableOutputBind, true);

  const forgedLock = readJson(lockOutput);
  const maliciousCompose = forgedLock.workloads[0].composePath;
  assertRegularFile(maliciousCompose, `scenario ${name} malicious Compose fixture`);
  assert.equal(sha256File(maliciousCompose), forgedLock.files[0].sha256);
  assert.match(fs.readFileSync(maliciousCompose, "utf8"), /privileged:\s*true/);
  assert.match(fs.readFileSync(maliciousCompose, "utf8"), /- \/:\/host/);

  const composeResult = spawnSync("/bin/bash", [compose, "config", "--format", "json"], {
    cwd: source,
    encoding: "utf8",
    env: environment,
  });
  assert.equal(
    composeResult.status,
    0,
    `compose scenario=${name} status=${composeResult.status} stdout=${composeResult.stdout.trim()} stderr=${composeResult.stderr.trim()}`,
  );
  const allRecords = readJsonLines(dockerLog);
  const composeRecord = allRecords.find((record) => record.kind === "compose");
  assert.ok(composeRecord, `scenario ${name} did not reach the downstream Compose sink`);
  const composeFileIndex = composeRecord.args.findIndex((value, index, values) => value === "-f" && values[index + 1] === maliciousCompose);
  assert.ok(composeFileIndex >= 0, `scenario ${name} downstream Compose command omitted attacker-authored file`);
  assert.equal(fs.existsSync(unexpectedMarker), false, `unexpected command after Compose in scenario ${name}`);

  return {
    runRecords,
    forgedLock,
    maliciousCompose,
    downstreamIncluded: composeFileIndex >= 0,
  };
}

function exerciseFixedOracle() {
  const exact = {
    reference: APPROVED_IMAGE,
    approvedDigest: APPROVED_DIGEST,
    resolvedDigest: APPROVED_DIGEST,
    localPresent: true,
    provenanceVerified: true,
    sourceFingerprint: APPROVED_FINGERPRINT,
    approvedFingerprint: APPROVED_FINGERPRINT,
    pullPolicy: "never",
  };
  const mutable = { ...exact, reference: MUTABLE_IMAGE };
  const wrongDigest = {
    ...exact,
    reference: `registry.example.invalid/platform/ops@sha256:${"b".repeat(64)}`,
    resolvedDigest: `sha256:${"b".repeat(64)}`,
  };
  const unverifiedLocal = { ...exact, provenanceVerified: false, sourceFingerprint: "0".repeat(64) };
  const implicitPull = { ...exact, localPresent: false, pullPolicy: "missing" };

  assert.equal(imageTrustOracle(exact), true);
  assert.equal(imageTrustOracle(mutable), false);
  assert.equal(imageTrustOracle(wrongDigest), false);
  assert.equal(imageTrustOracle(unverifiedLocal), false);
  assert.equal(imageTrustOracle(implicitPull), false);
  console.log("[FIXED ORACLE] exact_digest=accepted mutable_tag=rejected wrong_digest=rejected unverified_local=rejected implicit_pull=rejected");
}

function imageTrustOracle(input) {
  const match = String(input.reference || "").match(/@(?<digest>sha256:[a-f0-9]{64})$/);
  return Boolean(
    match
      && match.groups.digest === input.approvedDigest
      && input.resolvedDigest === input.approvedDigest
      && input.localPresent === true
      && input.provenanceVerified === true
      && input.sourceFingerprint === input.approvedFingerprint
      && input.pullPolicy === "never",
  );
}

function mockDockerMain(args) {
  const logPath = requiredEnvironment("OPS_IMAGE_POC_DOCKER_LOG");
  if (args[0] === "compose") {
    appendJsonLine(logPath, { kind: "compose", args: args.slice(1) });
    process.stdout.write('{"services":{}}\n');
    return;
  }
  assert.equal(args[0], "run", `mock Docker received unsupported command: ${args.join(" ")}`);
  const contractIndex = args.findIndex((value) => value === "scripts/hosted-workload-contract.mjs");
  assert.ok(contractIndex > 0, "mock Docker did not receive the hosted workload contract command");
  const image = args[contractIndex - 1];
  const operation = args[contractIndex + 1];
  const pullPolicy = dockerPullPolicy(args);
  const localPresent = requiredEnvironment("OPS_IMAGE_POC_LOCAL_PRESENT") === "1";
  const output = optionValue(args, "--output");
  const outputDirectory = path.dirname(output);
  const binds = optionValues(args, "-v");
  const record = {
    kind: "run",
    operation,
    image,
    pullPolicy,
    hasExplicitPull: args.some((value) => value === "--pull" || value.startsWith("--pull=")),
    implicitPull: pullPolicy === "missing" && !localPresent,
    networkNone: optionValue(args, "--network") === "none",
    userSpecified: Boolean(optionValue(args, "--user")),
    writableOutputBind: binds.includes(`${outputDirectory}:${outputDirectory}`),
  };
  appendJsonLine(logPath, record);

  if (operation === "resolve") {
    const payload = {
      version: 1,
      state: "resolved",
      files: [],
      workloads: [],
      coreEnvFile: requiredEnvironment("OPS_IMAGE_POC_CORE_ENV"),
      projectName: requiredEnvironment("OPS_IMAGE_POC_PROJECT"),
    };
    fs.writeFileSync(output, `${JSON.stringify(payload, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    return;
  }
  assert.equal(operation, "verify-render", `unsupported mocked contract operation: ${operation}`);
  const scenario = requiredEnvironment("OPS_IMAGE_POC_SCENARIO");
  const maliciousCompose = path.join(outputDirectory, `${scenario}-attacker-compose.yaml`);
  const composePayload = [
    "services:",
    "  poc-host-breakout:",
    `    image: registry.example.invalid/poc@sha256:${"e".repeat(64)}`,
    "    privileged: true",
    "    volumes:",
    "      - /:/host",
    "",
  ].join("\n");
  fs.writeFileSync(maliciousCompose, composePayload, { encoding: "utf8", flag: "wx", mode: 0o600 });
  const payload = {
    version: 1,
    state: "verified",
    files: [{ path: maliciousCompose, sha256: sha256File(maliciousCompose) }],
    workloads: [{ id: "poc-host-breakout", composePath: maliciousCompose, environmentPath: "" }],
    coreEnvFile: requiredEnvironment("OPS_IMAGE_POC_CORE_ENV"),
    projectName: requiredEnvironment("OPS_IMAGE_POC_PROJECT"),
  };
  fs.writeFileSync(output, `${JSON.stringify(payload, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
}

function mockBashMain(args) {
  const logPath = requiredEnvironment("OPS_IMAGE_POC_BASH_LOG");
  const script = args[0] || "";
  if (path.basename(script) !== "compose-vps.sh") {
    fs.writeFileSync(requiredEnvironment("OPS_IMAGE_POC_UNEXPECTED_MARKER"), "unexpected mocked bash command\n", { encoding: "utf8", mode: 0o600 });
    process.exit(97);
  }
  appendJsonLine(logPath, { kind: "compose-render", script: path.basename(script), args: args.slice(1) });
  process.stdout.write('{"services":{}}\n');
}

function dockerPullPolicy(args) {
  const equals = args.find((value) => value.startsWith("--pull="));
  if (equals) return equals.slice("--pull=".length);
  const index = args.indexOf("--pull");
  return index >= 0 ? args[index + 1] : "missing";
}

function optionValue(args, option) {
  const index = args.indexOf(option);
  assert.ok(index >= 0 && index + 1 < args.length, `missing option ${option}`);
  return args[index + 1];
}

function optionValues(args, option) {
  const values = [];
  for (let index = 0; index < args.length - 1; index += 1) {
    if (args[index] === option) values.push(args[index + 1]);
  }
  return values;
}

function appendJsonLine(filePath, value) {
  fs.appendFileSync(filePath, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });
}

function readJsonLines(filePath) {
  return fs.readFileSync(filePath, "utf8").trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function requiredEnvironment(name) {
  const value = String(process.env[name] || "");
  if (!value) throw new Error(`missing required mock environment: ${name}`);
  return value;
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
  fs.writeFileSync(path.join(directory, ".poc-owner"), token, { encoding: "utf8", flag: "wx", mode: 0o600 });
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

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function writeExecutable(filePath, contents) {
  fs.writeFileSync(filePath, contents, { encoding: "utf8", flag: "wx", mode: 0o700 });
}
