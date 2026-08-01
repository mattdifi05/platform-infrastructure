#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const CORE_FILES = [
  "compose.yaml",
  "compose.secrets.yaml",
  "compose.waf.yaml",
  "compose.vps.yaml",
  "compose.vps-waf.yaml",
  "compose.backup-scheduler.yaml",
  "compose.runtime.yaml",
  "compose.networks.yaml",
  "compose.runtime-isolation.yaml",
];
const SOURCE_HASHES = new Map([
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["scripts/network-segmentation-policy.mjs", "bc21ac9f6b01630925743dd9f226a07476f45aa56fc9c174edce38fd65312636"],
]);

if (!process.argv[2]) {
  throw new Error("usage: evidence-render-deployment-equivalence-probe.mjs /path/to/archived/source");
}

const sourceRoot = validateWrapperOwnedSource(process.argv[2]);
assert.equal(fs.existsSync(path.join(sourceRoot, ".git")), false, "source must be a Git archive without .git metadata");

for (const [relativePath, expected] of SOURCE_HASHES) {
  const actual = sha256File(path.join(sourceRoot, relativePath));
  assert.equal(actual, expected, `${relativePath} is not the expected pre-fix source`);
}
console.log(`[PASS] exact pre-fix source fingerprints verified revision=${REVISION} tree=${TREE}`);

const infraOps = fs.readFileSync(path.join(sourceRoot, "scripts", "infra-ops.mjs"), "utf8");
const composeVps = fs.readFileSync(path.join(sourceRoot, "scripts", "compose-vps.sh"), "utf8");
const networkCaller = sourceSlice(
  infraOps,
  "async function networkSegmentationCheck()",
  "async function runtimeIsolationCheck()",
);
const runtimeCaller = sourceSlice(
  infraOps,
  "async function runtimeIsolationCheck()",
  "async function faultInjectionTests()",
);
const networkFiles = composeFiles(networkCaller);
const runtimeFiles = composeFiles(runtimeCaller);

assert.deepEqual(networkFiles, CORE_FILES);
assert.deepEqual(runtimeFiles, CORE_FILES);
for (const caller of [networkCaller, runtimeCaller]) {
  assert.doesNotMatch(caller, /HOSTED_WORKLOAD_LOCK|hosted-workload-lock\.sh|compose-vps\.sh/);
}
assert.match(composeVps, /HOSTED_WORKLOAD_LOCK/);
assert.match(composeVps, /hosted-workload-lock\.sh[\s\S]*compose-files/);
assert.match(composeVps, /compose\+=\(-f "\$workload_file"\)/);
console.log(`[PASS] evidence callers render core_files=${CORE_FILES.length} hosted_lock_resolved=false`);
console.log("[PASS] deployment wrapper resolves hosted env files and Compose overlays from the verified lock");

const runtimeModule = await import(pathToFileURL(path.join(sourceRoot, "scripts", "runtime-isolation-policy.mjs")));
const networkModule = await import(pathToFileURL(path.join(sourceRoot, "scripts", "network-segmentation-policy.mjs")));
const contractModule = await import(pathToFileURL(path.join(sourceRoot, "scripts", "hosted-workload-contract.mjs")));
const evaluateRuntimeIsolation = runtimeModule.evaluateRuntimeIsolation;
const evaluateNetworkSegmentation = networkModule.evaluateNetworkSegmentation;
const validateRenderedWorkloads = contractModule.validateRenderedWorkloads;

const core = passingCoreConfig();
const baselineRuntime = evaluateRuntimeIsolation(structuredClone(core));
const baselineNetwork = evaluateNetworkSegmentation(structuredClone(core));
assert.equal(baselineRuntime.status, "passed", baselineRuntime.failures.join("\n"));
assert.equal(baselineNetwork.status, "passed", baselineNetwork.failures.join("\n"));
assert.equal(baselineRuntime.summary.hostedWorkloads, 0);
assert.equal(baselineNetwork.summary.hostedWorkloads, 0);
console.log(`[BASELINE] core_only runtime=${baselineRuntime.status} network=${baselineNetwork.status} hosted=0`);

const direct = structuredClone(core);
direct.services["evil-api"] = service({
  labels: {
    "com.platform.workload-id": "evil",
    "com.platform.workload-role": "api",
  },
  networks: ["platform_docker_control"],
  read_only: false,
  user: "root",
  security_opt: [],
  cap_drop: [],
  cap_add: ["SYS_ADMIN"],
  volumes: [{
    type: "bind",
    source: "/var/run/docker.sock",
    target: "/var/run/docker.sock",
    read_only: false,
  }],
});
const directRuntime = evaluateRuntimeIsolation(structuredClone(direct));
const directNetwork = evaluateNetworkSegmentation(structuredClone(direct));
assert.equal(directRuntime.status, "failed");
assert.equal(directNetwork.status, "failed");
assert.equal(directRuntime.summary.hostedWorkloads, 1);
assert.equal(directNetwork.summary.hostedWorkloads, 1);
assert.ok(directRuntime.failures.some((failure) => failure.startsWith("workload-deny-mount-var-run-docker-sock-evil-api:")));
assert.ok(directNetwork.failures.some((failure) => failure.startsWith("deny-evil-api-docker-socket-proxy:")));
console.log(`[EXACT-DIRECT] runtime=${directRuntime.status} network=${directNetwork.status} hosted=1 docker_control_exposed=true`);
console.log("[VULNERABLE] both evidence commands can retain the passing core-only result because the hostile overlay is absent from their render");

const alias = structuredClone(core);
const protectedPhysicalName = alias.networks.platform_docker_control.name;
alias.networks.evil_egress = {
  external: true,
  internal: false,
  enable_ipv6: false,
  name: protectedPhysicalName,
};
alias.services["evil-api"] = service({
  labels: {
    "com.platform.workload-id": "evil",
    "com.platform.workload-role": "api",
  },
  networks: ["evil_egress"],
  read_only: true,
  user: "10001:10001",
  security_opt: ["no-new-privileges:true"],
  cap_drop: ["ALL"],
  cap_add: [],
  volumes: [],
});
const aliasRuntime = evaluateRuntimeIsolation(structuredClone(alias));
const aliasNetwork = evaluateNetworkSegmentation(structuredClone(alias));
const aliasContract = validateRenderedWorkloads({
  core: structuredClone(core),
  combined: structuredClone(alias),
  lock: {
    workloads: [{
      id: "evil",
      secrets: [],
      services: [{ name: "evil-api", role: "api", routes: [] }],
    }],
  },
});
assert.equal(aliasRuntime.status, "passed", aliasRuntime.failures.join("\n"));
assert.equal(aliasNetwork.status, "passed", aliasNetwork.failures.join("\n"));
assert.deepEqual(aliasContract.routes, []);
assert.equal(aliasRuntime.summary.hostedWorkloads, 1);
assert.equal(aliasNetwork.summary.hostedWorkloads, 1);
assert.equal(alias.networks.evil_egress.name, alias.networks.platform_docker_control.name);
console.log(`[ALIAS] contract=accepted runtime=${aliasRuntime.status} network=${aliasNetwork.status} hosted=1 physical_name_collision=true`);
console.log("[VULNERABLE] network policy validates logical ownership but does not reject a workload network that aliases a protected physical network");
console.log("[SAFE] read-only policy evaluation inside a sentinel-owned Git archive; no Docker, network, SSH, credentials, or live target");

function passingCoreConfig() {
  const networks = Object.fromEntries([
    "platform_edge",
    "platform_routing",
    "platform_db_admin",
    "platform_postgres",
    "platform_cache",
    "platform_bus",
    "platform_storage",
    "platform_observability",
    "platform_docker_control",
  ].map((name) => [name, { internal: true, name: `platform_infra_vps_${name}` }]));
  networks.platform_egress = {
    internal: false,
    enable_ipv6: false,
    name: "platform_infra_vps_platform_egress",
  };

  const services = {
    waf: service({ networks: ["platform_edge"] }),
    traefik: service({ networks: ["platform_edge", "platform_routing"] }),
    "project-router": service({
      networks: ["platform_routing"],
      environment: {
        PROJECT_ROUTER_WORKLOAD_LOCK_FILE: "/var/www/project-state/hosted-workloads.lock.json",
      },
      volumes: [
        { type: "bind", source: "./src", target: "/var/www/projects", read_only: true },
        { type: "bind", source: "./state", target: "/var/www/project-state", read_only: true },
      ],
    }),
    "control-center": service({ networks: ["platform_routing", "platform_db_admin"] }),
    postgres: service({ networks: ["platform_db_admin", "platform_postgres"] }),
    mariadb: service({ networks: ["platform_db_admin"] }),
    redis: service({ networks: ["platform_cache"] }),
    nats: service({ networks: ["platform_bus"] }),
    minio: service({ networks: ["platform_storage"] }),
    keycloak: service({ networks: ["platform_routing"] }),
    prometheus: service({ networks: ["platform_observability"] }),
    loki: service({ networks: ["platform_observability"] }),
    alertmanager: service({ networks: ["platform_observability"] }),
    "platform-alert-dispatcher": service({ networks: ["platform_observability"] }),
    "backup-scheduler": service({
      networks: ["platform_docker_control"],
      environment: {
        DOCKER_HOST: "tcp://docker-socket-proxy:2375",
        DOCKER_API_VERSION: "1.51",
      },
    }),
    "docker-socket-proxy": service({
      networks: ["platform_docker_control"],
      image: `socket-proxy@sha256:${"a".repeat(64)}`,
      environment: Object.fromEntries([
        "AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES",
        "SESSION", "SWARM", "SYSTEM", "TASKS",
      ].map((name) => [name, "0"])),
      ports: [{ host_ip: "127.0.0.1", target: 2375, published: 2376 }],
      volumes: [{
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        read_only: true,
      }],
    }),
    phppgadmin: service({
      networks: ["platform_db_admin", "platform_routing"],
      image: `phppgadmin@sha256:${"b".repeat(64)}`,
    }),
  };
  return { services, networks };
}

function service(overrides = {}) {
  const result = {
    cpus: 0.25,
    mem_limit: 64 * 1024 * 1024,
    mem_reservation: 32 * 1024 * 1024,
    pids_limit: 64,
    ulimits: { nofile: { soft: 1024, hard: 2048 } },
    blkio_config: { weight: 100 },
    cpu_shares: 128,
    read_only: true,
    networks: [],
    volumes: [],
    environment: {},
    labels: {},
    image: `example/fixture@sha256:${"c".repeat(64)}`,
    init: true,
    restart: "unless-stopped",
    healthcheck: { test: ["CMD", "true"] },
    ...overrides,
  };
  if (Array.isArray(result.networks)) {
    result.networks = Object.fromEntries(result.networks.map((name) => [name, null]));
  }
  return result;
}

function composeFiles(functionSource) {
  const match = functionSource.match(/const composeFiles = \[([\s\S]*?)\];/);
  assert.ok(match, "missing local composeFiles array");
  return [...match[1].matchAll(/"([^"]+\.ya?ml)"/g)].map((item) => item[1]);
}

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
}

function validateWrapperOwnedSource(sourceArgument) {
  const wrapperArgument = requiredEnvironment("REPORT_FG047_WRAPPER_TEMP_ROOT");
  const sentinelArgument = requiredEnvironment("REPORT_FG047_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("REPORT_FG047_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperArgument);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(path.basename(wrapperReal), /^fg047-run\.[A-Za-z0-9]+$/);

  const requestedSource = path.resolve(sourceArgument);
  const sourceStat = fs.lstatSync(requestedSource, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(requestedSource);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned archive child");

  const sentinelPath = path.resolve(sentinelArgument);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg047-owner\.[A-Za-z0-9]+$/);
  const sentinelToken = path.basename(sentinelReal).slice(".fg047-owner.".length);
  assert.equal(ownershipToken, sentinelToken, "ownership token does not match sentinel name");
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), `FG047-OWNER:${ownershipToken}\n`);
  return sourceReal;
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke this probe through run-from-git-archive.sh`);
  }
  return value;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}
