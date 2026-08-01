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
]);

const CASES = [
  {
    name: "unlimited-swap",
    fields: { memswap_limit: -1 },
  },
  {
    name: "oom-priority-immunity",
    fields: { oom_score_adj: -1000 },
  },
  {
    name: "oom-kill-immunity",
    fields: { oom_kill_disable: true },
  },
  {
    name: "combined-controls",
    fields: {
      memswap_limit: -1,
      oom_score_adj: -1000,
      oom_kill_disable: true,
    },
  },
];

const sourceArgument = process.argv[2];
if (!sourceArgument) {
  throw new Error("usage: hosted-memory-oom-probe.mjs WRAPPER_OWNED_SOURCE");
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
  const labels = fieldLabels(testCase.fields);

  if (admission.accepted && runtime.accepted) {
    vulnerable += 1;
    console.log(
      `[VULNERABLE] ${testCase.name} ${labels} admission=accepted runtime=passed`,
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
console.log("[+] no Docker, Compose, memory pressure, swap, OOM policy, network, or live target was accessed");

function admissionResult(testCase, validate) {
  const core = {
    services: {
      "control-center": {
        image: "platform/control-center:synthetic",
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
  combined.services["probe-app-web"] = hostedService(testCase.fields);
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
  Object.assign(config.services["probe-app-web"], testCase.fields);
  const result = evaluate(config);
  return {
    accepted: result.status === "passed",
    error: result.failures.join("; "),
  };
}

function hostedService(fields) {
  return {
    image: `registry.example/workloads/probe@sha256:${"a".repeat(64)}`,
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
    mem_limit: 256 * 1024 * 1024,
    mem_reservation: 64 * 1024 * 1024,
    healthcheck: { test: ["CMD", "true"] },
    networks: { probe_app_ingress: null },
    labels: {
      "com.platform.workload-id": "probe-app",
      "com.platform.workload-role": "web",
    },
    ...fields,
  };
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
    "control-center": bounded({ read_only: true }),
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

function fieldLabels(fields) {
  return [
    `memswap_limit=${fields.memswap_limit ?? "unset"}`,
    `oom_score_adj=${fields.oom_score_adj ?? "unset"}`,
    `oom_kill_disable=${fields.oom_kill_disable ?? "unset"}`,
  ].join(" ");
}

function validateWrapperOwnedSource(sourceInput) {
  const wrapperInput = requiredEnvironment("FG046_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG046_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG046_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg046-(?:guard|run)\.[A-Za-z0-9]+$/,
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
  assert.match(path.basename(sentinelReal), /^\.fg046-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg046-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG046-OWNER:${ownershipToken}\n`;
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
