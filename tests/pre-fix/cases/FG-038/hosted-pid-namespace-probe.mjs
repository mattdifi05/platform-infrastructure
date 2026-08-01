#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["compose.yaml", "ed630eee1be8350142493307c2647aa98ce67324c93c127a9370a19a24a9d6c7"],
  ["compose.secrets.yaml", "52897c0e6f650f360b673fff67a1dac1fe312f8c9ec8843890686ad62b4a6c60"],
  ["docker/control-center.Dockerfile", "efe5133f910f39c15a3c0ea83f7f027743157975216059cab2dbc46202cb0740"],
]);

const CASES = [
  {
    name: "service-pid-reference",
    user: "1000:1000",
    pid: "service:control-center",
  },
  {
    name: "zero-padded-uid",
    user: "00:1000",
  },
  {
    name: "zero-padded-gid",
    user: "1000:00",
  },
  {
    name: "combined-root-and-pid",
    user: "00:00",
    pid: "service:control-center",
  },
];

const sourceArgument = process.argv[2];
if (!sourceArgument) {
  throw new Error("usage: hosted-pid-namespace-probe.mjs WRAPPER_OWNED_SOURCE");
}

const {
  sourceRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedSource(sourceArgument);
const treeBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source boundary verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  const target = path.join(sourceRoot, relativePath);
  assert.equal(sha256File(target), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const composeSource = fs.readFileSync(path.join(sourceRoot, "compose.yaml"), "utf8");
const controlCenterBlock = sourceSlice(composeSource, "  control-center:\n", "\n  project-router:\n");
assert.doesNotMatch(controlCenterBlock, /^\s+user\s*:/m, "Control Center unexpectedly has a service-level user override");
const secretNames = [
  "projects_gateway_signing_keys",
  "control_center_vault_keys",
  "control_center_database_url",
  "mariadb_root_password",
  "postgres_superuser_password",
];
for (const name of secretNames) {
  assert.match(controlCenterBlock, new RegExp(`^\\s+- ${name}$`, "m"), `Control Center secret ${name} is missing`);
}

const dockerfile = fs.readFileSync(path.join(sourceRoot, "docker/control-center.Dockerfile"), "utf8");
assert.doesNotMatch(dockerfile, /^\s*USER(?:\s|$)/im, "Control Center Dockerfile unexpectedly selects a user");
console.log(`[+] verified Control Center target has no explicit user and declares ${secretNames.length} secrets`);

const activationScript = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
assert.match(
  activationScript,
  /compose\+=\(-f "\$workload_file"\)/,
  "activation must append each admitted workload file to the Compose command",
);
assert.match(
  activationScript,
  /exec "\$\{compose\[@\]\}" --profile backup "\$@"/,
  "activation must execute the composed command",
);
console.log("[+] verified admitted workload files reach the Compose activation command");

const contractUrl = pathToFileURL(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs")).href;
const runtimeUrl = pathToFileURL(path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs")).href;
const { validateRenderedWorkloads } = await import(contractUrl);
const { evaluateRuntimeIsolation } = await import(runtimeUrl);

let vulnerable = 0;
for (const testCase of CASES) {
  const admission = admissionResult(testCase, validateRenderedWorkloads);
  const runtime = runtimeResult(testCase, evaluateRuntimeIsolation);
  const pidLabel = testCase.pid ?? "unset";

  if (testCase.user.startsWith("00")) {
    assert.equal(Number.parseInt(testCase.user.split(":")[0], 10), 0);
  }
  if (testCase.user.endsWith(":00")) {
    assert.equal(Number.parseInt(testCase.user.split(":")[1], 10), 0);
  }

  if (admission.accepted && runtime.accepted) {
    vulnerable += 1;
    console.log(
      `[VULNERABLE] ${testCase.name} user=${testCase.user} pid=${pidLabel} admission=accepted runtime=passed`,
    );
    continue;
  }

  if (admission.error) console.error(`[UNEXPECTED] ${testCase.name} admission detail: ${admission.error}`);
  if (runtime.error) console.error(`[UNEXPECTED] ${testCase.name} runtime detail: ${runtime.error}`);
}

assert.equal(vulnerable, CASES.length, "the pinned vulnerable revision did not accept every tested variant");
assert.equal(directoryDigest(sourceRoot), treeBefore, "the source snapshot changed during the read-only probe");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the probe");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the probe");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the probe");
console.log(`[+] summary vulnerable=${vulnerable} total=${CASES.length} source_tree_unchanged=true`);
console.log("[+] no Docker, Compose, namespace, procfs, secret, network, or live target was accessed");

function admissionResult(testCase, validate) {
  const core = {
    services: {
      "control-center": {
        image: "platform/control-center:synthetic",
        secrets: [
          "projects_gateway_signing_keys",
          "control_center_vault_keys",
          "control_center_database_url",
          "mariadb_root_password",
          "postgres_superuser_password",
        ],
      },
      "project-router": {
        image: `registry.example/platform/router@sha256:${"b".repeat(64)}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
  const combined = structuredClone(core);
  combined.services["project-router"].networks.probe_app_ingress = null;
  const service = hostedService(testCase);
  combined.services["probe-app-web"] = service;
  combined.networks.probe_app_ingress = { internal: true };
  const lock = {
    workloads: [{
      id: "probe-app",
      secrets: [],
      services: [{ name: "probe-app-web", role: "web", routes: [{ slug: "probe", port: 3000 }] }],
    }],
  };

  try {
    validate({ core, combined, lock });
    return { accepted: true };
  } catch (error) {
    return { accepted: false, error: error.message };
  }
}

function runtimeResult(testCase, evaluate) {
  const config = runtimeFixture();
  const service = config.services["probe-app-web"];
  service.user = testCase.user;
  if (testCase.pid !== undefined) service.pid = testCase.pid;
  const result = evaluate(config);
  return {
    accepted: result.status === "passed",
    error: result.failures.join("; "),
  };
}

function hostedService(testCase) {
  const service = {
    image: `registry.example/workloads/probe@sha256:${"a".repeat(64)}`,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: testCase.user,
    pids_limit: 128,
    cpu_shares: 256,
    blkio_config: { weight: 300 },
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    cpus: 0.5,
    mem_limit: 256 * 1024 * 1024,
    mem_reservation: 64 * 1024 * 1024,
    healthcheck: { test: ["CMD", "true"] },
    networks: { probe_app_ingress: null },
    labels: {
      "com.platform.workload-id": "probe-app",
      "com.platform.workload-role": "web",
    },
  };
  if (testCase.pid !== undefined) service.pid = testCase.pid;
  return service;
}

function runtimeFixture() {
  const services = {
    "probe-app-web": bounded({
      read_only: true,
      user: "1000:1000",
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      labels: {
        "com.platform.workload-id": "probe-app",
        "com.platform.workload-role": "web",
      },
      networks: { probe_app_ingress: null },
    }),
    "control-center": bounded({
      read_only: true,
      secrets: [
        "projects_gateway_signing_keys",
        "control_center_vault_keys",
        "control_center_database_url",
        "mariadb_root_password",
        "postgres_superuser_password",
      ],
    }),
    "project-router": bounded({
      read_only: true,
      volumes: [
        { type: "bind", source: "/synthetic/projects", target: "/var/www/projects", read_only: true },
        { type: "bind", source: "/synthetic/state", target: "/var/www/project-state", read_only: true },
      ],
    }),
    "platform-alert-dispatcher": bounded({ read_only: true }),
    "backup-scheduler": bounded({
      read_only: true,
      cpu_shares: 1024,
      environment: {
        DOCKER_HOST: "tcp://docker-socket-proxy:2375",
        DOCKER_API_VERSION: "1.51",
      },
      networks: { platform_docker_control: null },
    }),
    "docker-socket-proxy": bounded({
      read_only: true,
      cpu_shares: 1024,
      image: `registry.example/platform/socket-proxy@sha256:${"c".repeat(64)}`,
      environment: Object.fromEntries(
        ["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"]
          .map((key) => [key, "0"]),
      ),
      ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
      volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
      networks: { platform_docker_control: null },
    }),
  };

  return {
    services,
    networks: { platform_docker_control: { internal: true } },
  };
}

function bounded(overrides = {}) {
  return {
    image: `registry.example/platform/component@sha256:${"d".repeat(64)}`,
    cpus: 0.1,
    cpu_shares: 256,
    mem_limit: 64 * 1024 * 1024,
    mem_reservation: 16 * 1024 * 1024,
    pids_limit: 64,
    ulimits: { nofile: { soft: 4096, hard: 4096 } },
    blkio_config: { weight: 300 },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    ...overrides,
  };
}

function validateWrapperOwnedSource(sourceInput) {
  const wrapperInput = requiredEnvironment("FG038_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG038_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG038_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg038-(?:guard|run)\.[A-Za-z0-9]+$/,
    "wrapper temporary root does not have the expected mktemp name",
  );

  const sourcePath = path.resolve(sourceInput);
  const sourceStat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(sourcePath);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned source child");

  const sentinelPath = path.resolve(sentinelInput);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside the wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg038-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg038-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG038-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  return {
    sourceRoot: sourceReal,
    sentinelPath: sentinelReal,
    sentinelText,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
  };
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke through run-from-git-archive.sh`);
  }
  return value;
}

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker.trim()}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker.trim()}`);
  return source.slice(start, end);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function directoryDigest(root) {
  const digest = crypto.createHash("sha256");
  walk(root, "");
  return digest.digest("hex");

  function walk(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      digest.update(`L\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    if (stat.isDirectory()) {
      digest.update(`D\0${relative}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        walk(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    assert.equal(stat.isFile(), true, `unsupported archived entry: ${relative}`);
    digest.update(`F\0${relative}\0`);
    digest.update(fs.readFileSync(current));
    digest.update("\0");
  }
}
