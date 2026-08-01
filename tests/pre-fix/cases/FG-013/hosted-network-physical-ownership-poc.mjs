#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

function fail(message) {
  process.stderr.write("[FAIL] " + message + "\n");
  process.exit(1);
}

function pass(message) {
  process.stdout.write("[PASS] " + message + "\n");
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--source-root" && argv[index + 1]) {
      parsed.sourceRoot = argv[++index];
      continue;
    }
    fail("usage: node hosted-network-physical-ownership-poc.mjs --source-root PATH");
  }
  if (!parsed.sourceRoot) {
    fail("--source-root is required");
  }
  return parsed;
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function hardenedService(logicalNetwork) {
  const digest = "a".repeat(64);
  return {
    image: "registry.example/example/app@sha256:" + digest,
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
    networks: { [logicalNetwork]: null },
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "worker",
    },
  };
}

function renderedFixture(logicalNetwork, networkDefinition) {
  return {
    services: {
      "example-app-worker": hardenedService(logicalNetwork),
    },
    networks: {
      [logicalNetwork]: structuredClone(networkDefinition),
    },
  };
}

function expectRejected(validateRenderedWorkloads, input, pattern) {
  assert.throws(
    () => validateRenderedWorkloads(input),
    pattern,
  );
}

const { sourceRoot: sourceRootArgument } = parseArgs(process.argv.slice(2));
const sourceRoot = path.resolve(sourceRootArgument);
const expectedHashes = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
]);

try {
  for (const [relativePath, expectedHash] of expectedHashes) {
    const filePath = path.join(sourceRoot, relativePath);
    assert.equal(
      sha256(filePath),
      expectedHash,
      relativePath + " does not match the exact pre-fix source",
    );
  }
  pass("exact pre-fix source fingerprints verified");

  const testPath = path.join(sourceRoot, "scripts/hosted-workload-contract.test.mjs");
  const suite = spawnSync(process.execPath, [testPath], {
    cwd: sourceRoot,
    encoding: "utf8",
    env: {
      HOME: process.env.HOME || "",
      PATH: process.env.PATH || "",
      NODE_NO_WARNINGS: "1",
    },
  });
  assert.equal(
    suite.status,
    0,
    "repository tests failed:\n" + (suite.stderr || suite.stdout || "no output"),
  );
  assert.match(suite.stdout, /hosted workload contract tests passed 15\/15/);
  pass("repository hosted-workload tests pass 15/15");

  const contractPath = path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
  const contract = await import(pathToFileURL(contractPath).href);
  const manifest = contract.validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    services: [
      { name: "example-app-worker", role: "worker" },
    ],
  });
  const lock = { workloads: [manifest] };
  const core = { services: {}, networks: {} };

  const baseline = renderedFixture("example_app_egress", {});
  assert.deepEqual(
    contract.validateRenderedWorkloads({ core, combined: baseline, lock }),
    { routes: [] },
  );
  pass("dedicated workload egress baseline is accepted");

  const directLogicalUse = renderedFixture(
    "platform_docker_control",
    {
      external: true,
      name: "platform_infra_vps_platform_docker_control",
    },
  );
  expectRejected(
    contract.validateRenderedWorkloads,
    { core, combined: directLogicalUse, lock },
    /uses unauthorized network platform_docker_control/,
  );
  pass("direct logical Docker-control key is rejected");

  const nonEgressAlias = renderedFixture(
    "example_app_ingress",
    {
      external: true,
      name: "platform_infra_vps_platform_docker_control",
    },
  );
  expectRejected(
    contract.validateRenderedWorkloads,
    { core, combined: nonEgressAlias, lock },
    /must be internal/,
  );
  pass("non-egress external alias shape is rejected");

  const acceptedAlias = renderedFixture(
    "example_app_egress",
    {
      external: true,
      name: "platform_infra_vps_platform_docker_control",
    },
  );
  assert.deepEqual(
    contract.validateRenderedWorkloads({ core, combined: acceptedAlias, lock }),
    { routes: [] },
  );
  pass("workload-prefixed egress alias to protected physical network is accepted");

  const contractText = fs.readFileSync(contractPath, "utf8");
  const wrapperText = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
  const runtimeText = fs.readFileSync(path.join(sourceRoot, "compose.runtime-isolation.yaml"), "utf8");
  const runtimeNameTemplate =
    "name: $" + "{COMPOSE_PROJECT_NAME:-platform_infra}_platform_docker_control";
  const wrapperDefault =
    "PROJECT_NAME=$" + "{COMPOSE_PROJECT_NAME:-platform_infra_vps}";

  assert.equal(contractText.includes("network?.external"), false);
  assert.equal(contractText.includes("network?.name"), false);
  assert.ok(wrapperText.includes(wrapperDefault));
  assert.ok(wrapperText.includes("compose+=(-f \"$workload_file\")"));
  assert.ok(runtimeText.includes(runtimeNameTemplate));
  assert.ok(runtimeText.includes("AUTH: \"0\""));
  assert.ok(runtimeText.includes("POST: \"1\""));
  assert.ok(runtimeText.includes("EXEC: \"1\""));
  assert.ok(runtimeText.includes("- \"2375\""));
  assert.ok(runtimeText.includes("- platform_docker_control"));
  pass("protected network and socket-proxy sink are present in frozen source");

  process.stdout.write(
    "[SAFE] no Compose, Docker, network, socket, HTTP, or deployment action attempted\n",
  );
} catch (error) {
  fail(error.stack || error.message);
}
