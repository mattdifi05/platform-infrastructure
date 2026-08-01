#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_SOURCES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["scripts/runtime-isolation-policy.test.mjs", "555eeafa5c15ed44a30b37140b537ad7424be19bb55fe697cda8cd46cb0043ea"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);

function fail(message) {
  throw new Error(message);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

function identity(filePath) {
  const stat = fs.lstatSync(filePath);
  return `${stat.dev}:${stat.ino}`;
}

function regularFileNoLink(filePath, label) {
  const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  requireCondition(Boolean(stat), `${label} is missing`);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular non-symlink file`);
  return stat;
}

function functionSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  requireCondition(start >= 0 && end > start, `source markers are missing: ${startMarker}`);
  return source.slice(start, end);
}

function verifySourceProof(sourceRoot) {
  const sourceHashes = {};
  for (const [relativePath, expectedHash] of EXPECTED_SOURCES) {
    const fullPath = path.join(sourceRoot, relativePath);
    regularFileNoLink(fullPath, relativePath);
    const actualHash = sha256File(fullPath);
    requireCondition(actualHash === expectedHash, `source hash mismatch for ${relativePath}`);
    sourceHashes[relativePath] = actualHash;
    process.stdout.write(`[SOURCE] path=${relativePath} sha256=${actualHash}\n`);
  }

  const contract = fs.readFileSync(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs"), "utf8");
  const contractTest = fs.readFileSync(path.join(sourceRoot, "scripts/hosted-workload-contract.test.mjs"), "utf8");
  const isolation = fs.readFileSync(path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs"), "utf8");
  const isolationTest = fs.readFileSync(path.join(sourceRoot, "scripts/runtime-isolation-policy.test.mjs"), "utf8");
  const compose = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");

  const serviceGuard = functionSlice(contract, "function assertWorkloadService", "export function validateRenderedWorkloads");
  const renderedValidator = functionSlice(contract, "export function validateRenderedWorkloads", "export function verifyLockFiles");
  const isolationEvaluator = functionSlice(isolation, "export function evaluateRuntimeIsolation", "function object");

  requireCondition(serviceGuard.includes("serviceDefinition.privileged"), "hosted service privilege guard is absent");
  requireCondition(serviceGuard.includes("assertResourceLimits(name, serviceDefinition)"), "hosted resource guard is absent");
  requireCondition(!/\bserviceDefinition(?:\?\.)?\.runtime\b/.test(serviceGuard), "hosted service guard unexpectedly checks runtime");
  requireCondition(renderedValidator.includes("assertWorkloadService"), "rendered workload validator does not reach service guard");
  requireCondition(isolationEvaluator.includes("workload-no-bind-mounts"), "runtime-isolation workload checks are absent");
  requireCondition(!/\bservice(?:\?\.)?\.runtime\b/.test(isolationEvaluator), "runtime-isolation policy unexpectedly checks runtime");
  requireCondition(!/\bruntime\s*:/.test(contractTest), "upstream hosted test unexpectedly covers a runtime field");
  requireCondition(!/\bruntime\s*:/.test(isolationTest), "upstream isolation test unexpectedly covers a runtime field");

  const workloadOverlay = compose.indexOf('compose+=(-f "$workload_file")');
  const composeExec = compose.indexOf('exec "${compose[@]}" --profile backup "$@"');
  requireCondition(workloadOverlay >= 0 && composeExec > workloadOverlay, "workload overlay does not reach Compose execution");

  process.stdout.write(`[SOURCE] revision=${REVISION} tree=${TREE} files=${EXPECTED_SOURCES.size} provenance=git-archive\n`);
  process.stdout.write("[PASS] source proof hosted admission and runtime-isolation policy omit service.runtime while workload overlays reach Compose\n");
  return sourceHashes;
}

function fixedRuntimeOracle(service) {
  if (!Object.hasOwn(service, "runtime")) return { mode: "daemon-default", value: null };
  requireCondition(typeof service.runtime === "string", "fixed oracle rejects non-string runtime");
  requireCondition(service.runtime === "runc", "fixed oracle permits only exact platform default runtime runc");
  return { mode: "explicit-platform-default", value: "runc" };
}

function fixedOracleRejects(service) {
  try {
    fixedRuntimeOracle(service);
    return false;
  } catch {
    return true;
  }
}

function expectContractReject(validateRenderedWorkloads, input, pattern) {
  try {
    validateRenderedWorkloads(input);
  } catch (error) {
    requireCondition(pattern.test(String(error.message)), `unexpected contract rejection: ${error.message}`);
    return String(error.message);
  }
  fail("hosted contract unexpectedly accepted control mutation");
}

function contractFixture(validateWorkloadManifest, runtimeValue) {
  const digest = "a".repeat(64);
  const manifest = validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    secrets: [],
    migrationRoots: [],
    services: [{ name: "example-app-web", role: "web", routes: [{ slug: "example", port: 3000 }] }],
  });
  const core = {
    services: {
      "project-router": {
        image: `registry.example/router@sha256:${digest}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
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
    networks: { example_app_ingress: null },
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "web",
    },
    environment: {},
  };
  if (runtimeValue !== undefined) service.runtime = runtimeValue;
  const combined = {
    services: {
      "project-router": {
        ...structuredClone(core.services["project-router"]),
        networks: { platform_routing: null, example_app_ingress: null },
      },
      "example-app-web": service,
    },
    networks: {
      platform_routing: { internal: true },
      example_app_ingress: { internal: true },
    },
  };
  return { core, combined, lock: { workloads: [manifest] } };
}

function bounded(overrides = {}) {
  return {
    cpus: 0.5,
    cpu_shares: 256,
    mem_limit: 128 * 1024 * 1024,
    mem_reservation: 32 * 1024 * 1024,
    pids_limit: 128,
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    blkio_config: { weight: 300 },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    ...overrides,
  };
}

function isolationFixture(runtimeValue) {
  const services = {};
  services["example-app-web"] = bounded({
    read_only: true,
    user: "1000:1000",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
    networks: { example_app_ingress: null },
  });
  if (runtimeValue !== undefined) services["example-app-web"].runtime = runtimeValue;
  services["control-center"] = bounded({ read_only: true, cpu_shares: 1024, volumes: [], networks: {} });
  services["project-router"] = bounded({
    read_only: true,
    volumes: [
      { type: "bind", source: "/srv/apps", target: "/var/www/projects", read_only: true },
      { type: "bind", source: "/srv/state", target: "/var/www/project-state", read_only: true },
    ],
    networks: {},
  });
  services["platform-alert-dispatcher"] = bounded({ read_only: true, networks: {} });
  services["backup-scheduler"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    environment: { DOCKER_HOST: "tcp://docker-socket-proxy:2375", DOCKER_API_VERSION: "1.51" },
    volumes: [],
    networks: { platform_docker_control: null },
  });
  services["docker-socket-proxy"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    image: `ghcr.io/tecnativa/docker-socket-proxy:v0.4.2@sha256:${"a".repeat(64)}`,
    environment: Object.fromEntries(["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"].map((key) => [key, "0"])),
    ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
    volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
    networks: { platform_docker_control: null },
  });
  services.postgres = bounded({ networks: {} });
  return { services, networks: { platform_docker_control: { internal: true } } };
}

function cleanupOwnedFixture(target, ownership) {
  if (target !== ownership.root) return false;
  const stat = fs.lstatSync(target, { throwIfNoEntry: false });
  if (!stat?.isDirectory() || stat.isSymbolicLink() || identity(target) !== ownership.rootIdentity) return false;
  const sentinel = path.join(target, ".can220-probe-owner");
  const sentinelStat = fs.lstatSync(sentinel, { throwIfNoEntry: false });
  if (!sentinelStat?.isFile() || sentinelStat.isSymbolicLink()) return false;
  if (identity(sentinel) !== ownership.sentinelIdentity) return false;
  if (fs.readFileSync(sentinel, "utf8") !== `can220-probe:${ownership.token}\n`) return false;
  fs.rmSync(target, { recursive: true });
  return !fs.existsSync(target);
}

async function main() {
  const [sourceInput, wrapperInput, sentinelInput, ownerToken, extra] = process.argv.slice(2);
  requireCondition(Boolean(sourceInput && wrapperInput && sentinelInput && ownerToken) && extra === undefined, "probe requires its source-pinned wrapper");
  requireCondition(/^[a-f0-9]{64}$/.test(ownerToken), "invalid wrapper ownership token");

  const wrapperRoot = fs.realpathSync(wrapperInput);
  const sourceRoot = fs.realpathSync(sourceInput);
  requireCondition(sourceRoot === path.join(wrapperRoot, "source"), "source archive is outside the wrapper root");
  requireCondition(sentinelInput === path.join(wrapperRoot, ".oci-runtime-admission-wrapper-owner"), "unexpected wrapper sentinel path");
  regularFileNoLink(sentinelInput, "wrapper ownership sentinel");
  requireCondition(fs.readFileSync(sentinelInput, "utf8") === `oci-runtime-admission:${ownerToken}\n`, "wrapper ownership sentinel mismatch");

  const sourceHashes = verifySourceProof(sourceRoot);
  const contractPath = path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
  const isolationPath = path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs");
  const contract = await import(`${pathToFileURL(contractPath).href}?can220=${REVISION}`);
  const isolation = await import(`${pathToFileURL(isolationPath).href}?can220=${REVISION}`);
  const { validateRenderedWorkloads, validateWorkloadManifest } = contract;
  const { evaluateRuntimeIsolation } = isolation;
  requireCondition(typeof validateRenderedWorkloads === "function", "exact hosted validator export is unavailable");
  requireCondition(typeof validateWorkloadManifest === "function", "exact manifest validator export is unavailable");
  requireCondition(typeof evaluateRuntimeIsolation === "function", "exact isolation policy export is unavailable");

  const guardRoot = path.join(wrapperRoot, "preexisting-cleanup-control");
  fs.mkdirSync(guardRoot, { mode: 0o700 });
  const guardMarker = path.join(guardRoot, "preserve.marker");
  fs.writeFileSync(guardMarker, "PRESERVE-CAN220\n", { mode: 0o600 });
  const guardBefore = {
    identity: identity(guardMarker),
    size: fs.lstatSync(guardMarker).size,
    sha256: sha256File(guardMarker),
  };

  const fixtureRoot = path.join(wrapperRoot, "can220-owned-fixture");
  requireCondition(!fs.existsSync(fixtureRoot), "owned fixture path already exists");
  fs.mkdirSync(fixtureRoot, { mode: 0o700 });
  const fixtureSentinel = path.join(fixtureRoot, ".can220-probe-owner");
  fs.writeFileSync(fixtureSentinel, `can220-probe:${ownerToken}\n`, { mode: 0o600 });
  const ownership = {
    root: fixtureRoot,
    rootIdentity: identity(fixtureRoot),
    sentinelIdentity: identity(fixtureSentinel),
    token: ownerToken,
  };

  const refusedUnownedCleanup = !cleanupOwnedFixture(guardRoot, ownership);
  const guardAfter = {
    identity: identity(guardMarker),
    size: fs.lstatSync(guardMarker).size,
    sha256: sha256File(guardMarker),
  };
  requireCondition(refusedUnownedCleanup && JSON.stringify(guardBefore) === JSON.stringify(guardAfter), "cleanup guard changed the unowned marker");
  process.stdout.write(`[GUARD] unowned_cleanup_refused=true preexisting_sha256=${guardAfter.sha256}\n`);

  let completed = false;
  try {
    const cases = [
      { id: "alternate-short-name", value: "runsc" },
      { id: "qualified-alternate", value: "io.containerd.kata.v2" },
      { id: "unknown-name", value: "can220-unregistered" },
      { id: "path-like", value: "/opt/can220/custom-runtime" },
      { id: "case-variant", value: "RUNC" },
    ];
    const results = [];
    for (const item of cases) {
      const contractModel = contractFixture(validateWorkloadManifest, item.value);
      validateRenderedWorkloads(contractModel);
      const isolationReport = evaluateRuntimeIsolation(isolationFixture(item.value));
      requireCondition(isolationReport.status === "passed", `isolation policy rejected ${item.id}: ${isolationReport.failures.join(";")}`);
      const oracleRejected = fixedOracleRejects({ runtime: item.value });
      requireCondition(oracleRejected, `fixed oracle accepted ${item.id}`);
      results.push({ id: item.id, value: item.value, contractAccepted: true, isolationPassed: true, fixedRejected: true });
      process.stdout.write(`[SOURCE-MODEL ACCEPTED CAN-220] case=${item.id} value=${item.value} hosted_contract=accepted isolation_policy=passed fixed_oracle=reject runtime_outcome=unresolved\n`);
    }

    const privilegedControl = contractFixture(validateWorkloadManifest, undefined);
    privilegedControl.combined.services["example-app-web"].privileged = true;
    expectContractReject(validateRenderedWorkloads, privilegedControl, /host-level privilege/);
    process.stdout.write("[CONTROL] case=privileged-service hosted_contract=reject\n");

    const rootControl = isolationFixture(undefined);
    rootControl.services["example-app-web"].user = "0:0";
    const rootReport = evaluateRuntimeIsolation(rootControl);
    requireCondition(rootReport.status === "failed" && rootReport.failures.some((item) => item.includes("workload-non-root-example-app-web")), "isolation policy did not reject root workload control");
    process.stdout.write("[CONTROL] case=root-workload isolation_policy=failed\n");

    const unsetContract = contractFixture(validateWorkloadManifest, undefined);
    validateRenderedWorkloads(unsetContract);
    const unsetIsolation = evaluateRuntimeIsolation(isolationFixture(undefined));
    requireCondition(unsetIsolation.status === "passed", "unset runtime negative control failed isolation policy");
    const unsetOracle = fixedRuntimeOracle(unsetContract.combined.services["example-app-web"]);
    requireCondition(unsetOracle.mode === "daemon-default", "unset runtime negative control failed fixed oracle");
    process.stdout.write("[NEGATIVE CONTROL] case=runtime-unset hosted_contract=accepted isolation_policy=passed fixed_oracle=accepted\n");

    const defaultContract = contractFixture(validateWorkloadManifest, "runc");
    validateRenderedWorkloads(defaultContract);
    const defaultIsolation = evaluateRuntimeIsolation(isolationFixture("runc"));
    requireCondition(defaultIsolation.status === "passed", "exact default runtime failed isolation policy");
    const defaultOracle = fixedRuntimeOracle(defaultContract.combined.services["example-app-web"]);
    requireCondition(defaultOracle.mode === "explicit-platform-default", "exact default runtime failed fixed oracle");
    process.stdout.write("[NEGATIVE CONTROL] case=exact-default value=runc hosted_contract=accepted isolation_policy=passed fixed_oracle=accepted\n");

    process.stdout.write("[RUNTIME NOT TESTED] docker_calls=0 daemon_inventory_queries=0 containers_created=0 runtimes_executed=0 alternate_registered=unknown isolation_effect=unknown\n");
    const receipt = {
      revision: REVISION,
      tree: TREE,
      sourceHashes,
      sourceProof: {
        hostedRuntimeCheckAbsent: true,
        isolationRuntimeCheckAbsent: true,
        workloadOverlayReachesCompose: true,
      },
      sourceModelCases: results,
      controls: {
        privilegedRejected: true,
        rootRejected: true,
        unsetAccepted: true,
        exactDefaultAccepted: true,
      },
      runtimeBoundary: {
        dockerCalls: 0,
        daemonInventoryQueries: 0,
        containersCreated: 0,
        runtimesExecuted: 0,
        alternateRegistered: "unknown",
        isolationEffect: "unknown",
      },
      safety: {
        networkAttempts: 0,
        credentialReads: 0,
        liveMutations: 0,
        sourceMutations: 0,
      },
    };
    process.stdout.write(`[RECEIPT] sha256=${sha256Bytes(JSON.stringify(receipt))} scope=source-model-only\n`);
    process.stdout.write("[SAFE] docker_calls=0 daemon_queries=0 container_creates=0 runtime_execs=0 network_attempts=0 credentials_read=0 live_mutations=0 source_mutations=0\n");
    completed = true;
  } finally {
    const removed = cleanupOwnedFixture(fixtureRoot, ownership);
    requireCondition(removed, "owned fixture cleanup or sentinel validation failed");
    requireCondition(fs.existsSync(guardMarker) && JSON.stringify(guardBefore) === JSON.stringify({
      identity: identity(guardMarker),
      size: fs.lstatSync(guardMarker).size,
      sha256: sha256File(guardMarker),
    }), "preexisting guard marker changed during probe cleanup");
    process.stdout.write("[+] cleanup sentinel_owned_fixture_removed=true preexisting_marker_preserved=true\n");
  }

  requireCondition(completed, "probe did not complete");
  process.stdout.write("[+] result=SOURCE_MODEL_ACCEPTED canonical_id=CAN-220 runtime_validation=NOT_TESTED\n");
}

main().catch((error) => {
  process.stderr.write(`[!] ${error.message}\n`);
  process.exitCode = 1;
});
