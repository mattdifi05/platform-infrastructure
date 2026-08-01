#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const AFFECTED_REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);
const COUNTS = [1, 62, 63, 1000];
const PER_REPLICA = Object.freeze({
  memoryBytes: 128 * 1024 * 1024,
  reservationBytes: 32 * 1024 * 1024,
  cpus: 0.5,
  pids: 128,
  nofile: 8192,
  ioWeight: 300,
});
const WORKLOAD_MEMORY_BUDGET = 8_000 * 1024 * 1024;

const args = parseArgs(process.argv.slice(2));
const sourceRoot = path.resolve(required(args["source-root"], "--source-root"));
const revision = String(args.revision || "unknown");
const expectation = String(args.expect || "vulnerable");
if (!["vulnerable", "fixed", "either"].includes(expectation)) {
  throw new Error(`--expect must be vulnerable, fixed, or either; received ${expectation}`);
}

verifySourceArchive(sourceRoot, revision, expectation);

const contractPath = path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
const runtimePath = path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs");
const activationText = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
assert.match(
  activationText,
  /compose\+=\(-f "\$workload_file"\)/,
  "activation must preserve an admitted workload Compose file",
);

const { validateRenderedWorkloads, validateWorkloadManifest } = await import(pathToFileURL(contractPath));
const { evaluateRuntimeIsolation } = await import(pathToFileURL(runtimePath));

const observations = [];
for (const syntax of ["service.scale", "deploy.replicas"]) {
  for (const count of COUNTS) {
    const contractInput = contractFixture(validateWorkloadManifest, syntax, count);
    let contractAccepted = true;
    let contractError = "";
    try {
      validateRenderedWorkloads(contractInput);
    } catch (error) {
      contractAccepted = false;
      contractError = firstLine(error.message);
    }

    let runtimePassed = false;
    let accountedBytes = 0;
    let runtimeError = "";
    try {
      const report = evaluateRuntimeIsolation(runtimeFixture(syntax, count));
      runtimePassed = report.status === "passed";
      accountedBytes = reportedWorkloadMemory(report);
      runtimeError = report.failures.join("; ");
    } catch (error) {
      runtimeError = firstLine(error.message);
    }

    observations.push({
      syntax,
      count,
      contractAccepted,
      contractError,
      runtimePassed,
      runtimeError,
      accountedBytes,
      effectiveBytes: PER_REPLICA.memoryBytes * count,
    });
  }
}

printResults(observations, revision);
const vulnerable = observations
  .filter(({ count }) => count >= 63)
  .every(({ contractAccepted, runtimePassed, accountedBytes }) => (
    contractAccepted && runtimePassed && accountedBytes === PER_REPLICA.memoryBytes
  ));
const fixed = observations
  .filter(({ count }) => count >= 63)
  .every(({ contractAccepted, runtimePassed }) => !contractAccepted || !runtimePassed);

if (expectation === "vulnerable") {
  assert.equal(vulnerable, true, "expected both scaling syntaxes to bypass aggregate admission");
} else if (expectation === "fixed") {
  assert.equal(fixed, true, "expected every above-budget replica case to be rejected by contract or runtime admission");
}

if (vulnerable) {
  process.stdout.write("\n[VULNERABLE] Both replica syntaxes pass admission above the 8,000 MiB workload budget.\n");
} else if (fixed) {
  process.stdout.write("\n[FIXED] Every above-budget replica case is rejected by contract or runtime admission.\n");
} else {
  process.stdout.write("\n[MIXED] Replica handling differs by syntax or threshold; inspect the rows above.\n");
}

function verifySourceArchive(root, selectedRevision, selectedExpectation) {
  const observed = [];
  for (const [relative, expected] of EXPECTED_HASHES) {
    const file = path.join(root, relative);
    const actual = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    observed.push({ relative, actual, expected });
  }

  if (selectedExpectation === "vulnerable") {
    assert.equal(selectedRevision, AFFECTED_REVISION, `vulnerable expectation requires revision ${AFFECTED_REVISION}`);
    for (const item of observed) {
      assert.equal(item.actual, item.expected, `unexpected source digest for ${item.relative}`);
    }
    process.stdout.write(`[+] clean archive source digests match affected revision ${selectedRevision}\n`);
  } else {
    process.stdout.write(`[+] evaluating clean archive revision ${selectedRevision}\n`);
  }
}

function contractFixture(validateManifest, syntax, count) {
  const digest = "a".repeat(64);
  const manifest = validateManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    secrets: [],
    services: [{ name: "example-app-web", role: "web", routes: [] }],
  });
  const service = bounded({
    image: `registry.example/example/app@sha256:${digest}`,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    healthcheck: { test: ["CMD", "node", "healthcheck.mjs"] },
    labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
    networks: { example_app_bus: null },
  });
  applyReplicaSyntax(service, syntax, count);
  const core = {
    services: { "project-router": { image: `registry.example/router@sha256:${digest}`, networks: { platform_routing: null } } },
    networks: { platform_routing: { internal: true } },
  };
  const combined = {
    services: {
      "project-router": structuredClone(core.services["project-router"]),
      "example-app-web": service,
    },
    networks: {
      platform_routing: { internal: true },
      example_app_bus: { internal: true },
    },
  };
  return { core, combined, lock: { workloads: [manifest] } };
}

function runtimeFixture(syntax, count) {
  const services = {};
  services["example-app-web"] = bounded({
    read_only: true,
    user: "1000:1000",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
    networks: { example_app_ingress: null },
  });
  applyReplicaSyntax(services["example-app-web"], syntax, count);
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
    environment: Object.fromEntries(
      ["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"]
        .map((key) => [key, "0"]),
    ),
    ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
    volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
    networks: { platform_docker_control: null },
  });
  services.postgres = bounded({ networks: {} });
  return { services, networks: { platform_docker_control: { internal: true } } };
}

function bounded(overrides = {}) {
  return {
    cpus: PER_REPLICA.cpus,
    cpu_shares: 256,
    mem_limit: PER_REPLICA.memoryBytes,
    mem_reservation: PER_REPLICA.reservationBytes,
    pids_limit: PER_REPLICA.pids,
    ulimits: { nofile: { soft: PER_REPLICA.nofile, hard: PER_REPLICA.nofile } },
    blkio_config: { weight: PER_REPLICA.ioWeight },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    ...overrides,
  };
}

function applyReplicaSyntax(service, syntax, count) {
  if (syntax === "service.scale") service.scale = count;
  else service.deploy = { replicas: count };
}

function reportedWorkloadMemory(report) {
  const check = report.checks.find(({ id }) => id === "workload-memory-bounded");
  const match = String(check?.detail || "").match(/workloadMemory=(\d+)/);
  return match ? Number(match[1]) : 0;
}

function printResults(rows, selectedRevision) {
  process.stdout.write(`\nRevision: ${selectedRevision}\n`);
  process.stdout.write(`Per replica: 128 MiB, 0.5 CPU, 128 PIDs, nofile 8192, I/O weight 300\n`);
  process.stdout.write(`Workload memory ceiling: ${WORKLOAD_MEMORY_BUDGET / 1024 / 1024} MiB\n\n`);
  process.stdout.write("syntax             count contract runtime accountedMiB effectiveMiB effectiveCPU effectivePIDs\n");
  process.stdout.write("------------------ ----- -------- ------- ------------ ------------ ------------ -------------\n");
  for (const row of rows) {
    process.stdout.write([
      row.syntax.padEnd(18),
      String(row.count).padStart(5),
      (row.contractAccepted ? "ACCEPT" : "REJECT").padStart(8),
      (row.runtimePassed ? "PASS" : "FAIL").padStart(7),
      String(row.accountedBytes / 1024 / 1024).padStart(12),
      String(row.effectiveBytes / 1024 / 1024).padStart(12),
      String(PER_REPLICA.cpus * row.count).padStart(12),
      String(PER_REPLICA.pids * row.count).padStart(13),
    ].join(" ") + "\n");
    if (!row.contractAccepted) process.stdout.write(`  contract: ${row.contractError}\n`);
    if (!row.runtimePassed && row.runtimeError) process.stdout.write(`  runtime: ${firstLine(row.runtimeError)}\n`);
  }
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    if (!values[index].startsWith("--")) continue;
    parsed[values[index].slice(2)] = values[index + 1] && !values[index + 1].startsWith("--")
      ? values[++index]
      : true;
  }
  return parsed;
}

function required(value, flag) {
  if (!value || value === true) throw new Error(`${flag} is required`);
  return String(value);
}

function firstLine(value) {
  return String(value || "").split("\n", 1)[0];
}
