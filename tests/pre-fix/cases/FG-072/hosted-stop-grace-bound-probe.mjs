#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const CANONICAL_ID = "CAN-211";
const OWNER_SENTINEL = ".hosted-stop-grace-bound-runtime-owner";
const MAX_ORACLE_SECONDS = 120;
const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/vps-go-live.sh", "89d824edac428b30673f855f90e7d4710fb784f100c2dab95054a417435bc258"],
]);

const sourceArgument = String(process.argv[2] || "");
const tmpArgument = String(process.env.STOP_GRACE_POC_TMP_ROOT || "");
const ownerToken = String(process.env.STOP_GRACE_POC_OWNER_TOKEN || "");
if (!sourceArgument || !tmpArgument || !ownerToken) {
  throw new Error("run this probe through run-from-git-archive.sh");
}

const tmpRoot = verifiedRealDirectory(tmpArgument, "wrapper temporary root");
const sourceRoot = verifiedRealDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(tmpRoot, "source"), "source must be the exact wrapper-owned source child");
assert.match(ownerToken, /^[a-f0-9]{64}$/, "invalid wrapper ownership token");
const wrapperOwner = path.join(tmpRoot, ".hosted-stop-grace-bound-poc-owner");
assertRegularFile(wrapperOwner, "wrapper ownership sentinel");
assert.equal(fs.readFileSync(wrapperOwner, "utf8"), ownerToken, "wrapper ownership sentinel mismatch");
assertNoSensitiveEnvironment(process.env);
const sourceTreeBefore = directoryDigest(sourceRoot);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  const target = path.join(sourceRoot, relativePath);
  assertRegularFile(target, `pinned source ${relativePath}`);
  assert.equal(sha256File(target), expectedHash, `${relativePath} is not the expected vulnerable source`);
}
console.log(`[PASS] exact pre-fix sources revision=${REVISION} tree=${TREE}`);

const contractPath = path.join(sourceRoot, "scripts", "hosted-workload-contract.mjs");
const contractTestPath = path.join(sourceRoot, "scripts", "hosted-workload-contract.test.mjs");
const preparePath = path.join(sourceRoot, "scripts", "prepare-hosted-workloads.sh");
const composePath = path.join(sourceRoot, "scripts", "compose-vps.sh");
const goLivePath = path.join(sourceRoot, "scripts", "vps-go-live.sh");
const contractSource = fs.readFileSync(contractPath, "utf8");
const contractTestSource = fs.readFileSync(contractTestPath, "utf8");
const prepareSource = fs.readFileSync(preparePath, "utf8");
const composeSource = fs.readFileSync(composePath, "utf8");
const goLiveSource = fs.readFileSync(goLivePath, "utf8");

const serviceGuard = sliceBetween(
  contractSource,
  "function assertWorkloadService({ serviceDefinition, manifestService, manifest, combined }) {\n",
  "\n}\n\nexport function validateRenderedWorkloads",
  "workload service guard",
);
assert.match(serviceGuard, /serviceDefinition\.privileged/);
assert.match(serviceGuard, /assertResourceLimits\(name, serviceDefinition\)/);
assert.match(serviceGuard, /assertVolumes\(name, serviceDefinition, manifest\.id\)/);
assert.doesNotMatch(serviceGuard, /stop_grace_period|stop_signal/);
assert.match(contractSource, /assertWorkloadService\(\{ serviceDefinition: rendered, manifestService: item\.service, manifest: item\.workload, combined \}\);/);
assert.doesNotMatch(contractTestSource, /stop_grace_period/);
assert.match(prepareSource, /compose-vps\.sh" config --format json > "\$combined_render"/);
assert.match(prepareSource, /hosted-workload-contract\.mjs verify-render/);
assert.match(composeSource, /compose\+=\(-f "\$workload_file"\)/);
assert.match(composeSource, /exec "\$\{compose\[@\]\}" --profile backup "\$@"/);
assert.match(goLiveSource, /compose-vps\.sh up -d --build --remove-orphans/);
console.log("[PASS] source proof rendered workload fields pass the partial guard, remain in the locked Compose file, and reach normal compose up activation");

const runtimeRoot = path.join(tmpRoot, "runtime");
const negativeRoot = path.join(tmpRoot, "negative-preservation");
let runtimeOwned = false;
let completed = false;

try {
  runNegativePreservationRegression(negativeRoot, ownerToken, tmpRoot);
  createOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
  runtimeOwned = true;

  runArchivedRegressionSuite({ contractTestPath, runtimeRoot });
  const contract = await import(`${pathToFileURL(contractPath).href}?poc=${crypto.randomUUID()}`);
  runFocusedAdmissionProbe(contract);
  exerciseFixedOracle();

  for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
    assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} changed during the probe`);
  }
  assert.equal(directoryDigest(sourceRoot), sourceTreeBefore, "archived source tree changed during the probe");
  assert.equal(fs.existsSync(path.join(sourceRoot, "reports")), false, "probe unexpectedly created archived-source reports");
  console.log("[SAFE] docker_cli=0 docker_daemon=0 containers=0 sleeps=0 timers=0 network=0 provider=0 token=0 live_mutations=0 source_mutations=0 working_tree_mutations=0");
  console.log(`[+] result=VULNERABLE canonical_id=${CANONICAL_ID}`);
  completed = true;
} finally {
  if (runtimeOwned && fs.existsSync(runtimeRoot)) {
    removeOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
  }
}

assert.equal(completed, true);
assert.equal(fs.existsSync(runtimeRoot), false);
console.log("[+] sentinel-authorized temporary cleanup complete; wrapper root remains trap-owned");

function runArchivedRegressionSuite({ contractTestPath: testPath, runtimeRoot: root }) {
  const home = path.join(root, "regression-home");
  const targetTmp = path.join(root, "regression-tmp");
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(targetTmp, { mode: 0o700 });
  const environment = {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    HOME: home,
    TMPDIR: targetTmp,
    LANG: "C",
    LC_ALL: "C",
    NODE_OPTIONS: "",
  };
  assertNoSensitiveEnvironment(environment);
  const result = spawnSync(process.execPath, [testPath], {
    cwd: path.dirname(testPath),
    encoding: "utf8",
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.error, undefined, `archived regression suite failed to start: ${result.error?.message || "unknown"}`);
  assert.equal(result.status, 0, `archived regression suite status=${result.status} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()}`);
  const summary = result.stdout.match(/hosted workload contract tests passed (\d+)\/(\d+)/);
  assert.ok(summary, "archived regression suite summary missing");
  assert.equal(summary[1], summary[2], "archived regression suite did not fully pass");
  assert.ok(Number(summary[1]) >= 15, "unexpectedly small archived regression suite");
  console.log(`[PASS] archived contract regression suite passed=${summary[1]}/${summary[2]}`);
}

function runFocusedAdmissionProbe({ validateRenderedWorkloads, validateWorkloadManifest }) {
  const baseline = fixture(validateWorkloadManifest);
  assert.doesNotThrow(() => validateRenderedWorkloads(baseline));

  const privileged = fixture(validateWorkloadManifest);
  privileged.combined.services["example-app-worker"].privileged = true;
  assert.throws(() => validateRenderedWorkloads(privileged), /host-level privilege/);
  console.log("[NEGATIVE CONTROL existing] privileged=true contract=REJECT");

  for (const testCase of [
    { value: "30s", declaredSeconds: 30, label: "ordinary" },
    { value: "24h", declaredSeconds: 86400, label: "day" },
    { value: "168h", declaredSeconds: 604800, label: "week" },
  ]) {
    const input = fixture(validateWorkloadManifest);
    input.combined.services["example-app-worker"].stop_grace_period = testCase.value;
    const result = validateRenderedWorkloads(input);
    assert.deepEqual(result.routes, []);
    assert.equal(input.combined.services["example-app-worker"].stop_grace_period, testCase.value);
    if (testCase.label !== "ordinary") {
      console.log(`[VULNERABLE] field=stop_grace_period value=${testCase.value} contract=ACCEPT declared_grace_seconds=${testCase.declaredSeconds} engine_wait=NOT_MEASURED`);
    }
  }

  const syntheticNoncanonical = fixture(validateWorkloadManifest);
  syntheticNoncanonical.combined.services["example-app-worker"].stop_grace_period = "030s";
  assert.doesNotThrow(() => validateRenderedWorkloads(syntheticNoncanonical));
  console.log("[VALIDATOR SURFACE] field=stop_grace_period value=030s contract=ACCEPT compose_normalization=NOT_TESTED engine_wait=NOT_MEASURED");
}

function fixture(validateWorkloadManifest) {
  const digest = "a".repeat(64);
  const manifest = validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    secrets: [],
    services: [{ name: "example-app-worker", role: "worker" }],
  });
  const service = {
    image: `registry.example/example/app@sha256:${digest}`,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    pids_limit: 128,
    cpu_shares: 256,
    blkio_config: { weight: 300 },
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    cpus: 0.5,
    mem_limit: String(256 * 1024 * 1024),
    mem_reservation: String(64 * 1024 * 1024),
    healthcheck: { test: ["CMD", "node", "healthcheck.mjs"] },
    networks: { example_app_bus: null },
    labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "worker" },
  };
  const coreRouter = {
    image: `registry.example/router@sha256:${digest}`,
    networks: { platform_routing: null },
  };
  const core = {
    services: { "project-router": coreRouter },
    networks: { platform_routing: { internal: true } },
  };
  const combined = {
    services: {
      "project-router": structuredClone(coreRouter),
      "example-app-worker": service,
    },
    networks: {
      platform_routing: { internal: true },
      example_app_bus: { internal: true },
    },
  };
  return { core, combined, lock: { workloads: [manifest] } };
}

function exerciseFixedOracle() {
  assert.equal(fixedOracle(undefined), 10);
  assert.equal(fixedOracle("30s"), 30);
  assert.equal(fixedOracle("120s"), 120);
  for (const value of ["0s", "121s", "24h", "168h", "030s", "1m", 30, null]) {
    assert.equal(fixedOracle(value), null, `fixed oracle unexpectedly accepted ${String(value)}`);
  }
  console.log("[FIXED ORACLE] missing=accepted_platform_default safe_30s=accepted max_120s=accepted zero_0s=rejected over_121s=rejected extreme_24h=rejected week_168h=rejected noncanonical_030s=rejected compound_1m=rejected numeric=rejected");
}

function fixedOracle(value) {
  if (value === undefined) return 10;
  if (typeof value !== "string" || !/^[1-9][0-9]{0,2}s$/.test(value)) return null;
  const seconds = Number(value.slice(0, -1));
  return seconds >= 1 && seconds <= MAX_ORACLE_SECONDS ? seconds : null;
}

function runNegativePreservationRegression(directory, ownerToken, parent) {
  assertDirectChild(directory, parent, "negative preservation directory");
  fs.mkdirSync(directory, { mode: 0o700 });
  const ownerFile = path.join(directory, OWNER_SENTINEL);
  const foreignFile = path.join(directory, "foreign-data");
  fs.writeFileSync(ownerFile, "0".repeat(64), { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(foreignFile, "preserve-me\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  assert.throws(() => removeOwnedDirectory(directory, ownerToken, parent), /ownership sentinel mismatch/);
  assert.equal(fs.readFileSync(foreignFile, "utf8"), "preserve-me\n");
  fs.writeFileSync(ownerFile, ownerToken, { encoding: "utf8", flag: "w", mode: 0o600 });
  removeOwnedDirectory(directory, ownerToken, parent);
  assert.equal(fs.existsSync(directory), false);
  console.log("[PASS] negative preservation mismatched sentinel refused deletion and preserved existing data");
}

function createOwnedDirectory(directory, ownerToken, parent) {
  assertDirectChild(directory, parent, "owned runtime directory");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.writeFileSync(path.join(directory, OWNER_SENTINEL), ownerToken, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

function removeOwnedDirectory(directory, ownerToken, parent) {
  assertDirectChild(directory, parent, "cleanup directory");
  const stat = fs.lstatSync(directory);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), "cleanup target must be a real directory");
  assert.equal(fs.realpathSync(directory), directory, "cleanup target physical path mismatch");
  const ownerFile = path.join(directory, OWNER_SENTINEL);
  assertRegularFile(ownerFile, "cleanup ownership sentinel");
  assert.equal(fs.readFileSync(ownerFile, "utf8"), ownerToken, "cleanup ownership sentinel mismatch");
  fs.rmSync(directory, { recursive: true, force: false });
}

function assertDirectChild(child, parent, label) {
  assert.equal(path.dirname(child), parent, `${label} is not a direct child of its trusted parent`);
  assert.equal(path.resolve(child), child, `${label} is not absolute and normalized`);
}

function assertNoSensitiveEnvironment(environment) {
  const populated = [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "SSH_AUTH_SOCK",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
  ].filter((key) => String(environment[key] || "").length > 0);
  assert.deepEqual(populated, [], `sensitive or live environment unexpectedly populated: ${populated.join(",")}`);
}

function sliceBetween(source, startMarker, endMarker, label) {
  const start = source.indexOf(startMarker);
  assert.ok(start >= 0, `${label} start marker missing`);
  const contentStart = start + startMarker.length;
  const end = source.indexOf(endMarker, contentStart);
  assert.ok(end >= 0, `${label} end marker missing`);
  assert.equal(source.indexOf(startMarker, contentStart), -1, `${label} start marker is ambiguous`);
  return source.slice(contentStart, end);
}

function verifiedRealDirectory(value, label) {
  const resolved = path.resolve(value);
  const stat = fs.lstatSync(resolved);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), `${label} must be a real directory`);
  assert.equal(fs.realpathSync(resolved), resolved, `${label} physical path mismatch`);
  return resolved;
}

function assertRegularFile(filePath, label) {
  const stat = fs.lstatSync(filePath);
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular non-symlink file`);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function directoryDigest(root) {
  const digest = crypto.createHash("sha256");
  visit(root, "");
  return digest.digest("hex");

  function visit(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      digest.update(`L\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    if (stat.isDirectory()) {
      digest.update(`D\0${relative}\0${stat.mode & 0o7777}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        visit(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    assert.equal(stat.isFile(), true, `unsupported archived source entry: ${relative}`);
    digest.update(`F\0${relative}\0${stat.mode & 0o7777}\0`);
    digest.update(fs.readFileSync(current));
    digest.update("\0");
  }
}
