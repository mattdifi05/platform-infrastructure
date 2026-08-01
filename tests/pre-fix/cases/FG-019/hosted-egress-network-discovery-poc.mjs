#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
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
  let sourceRoot = "";
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--source-root" && argv[index + 1]) {
      sourceRoot = argv[++index];
      continue;
    }
    fail("usage: node hosted-egress-network-discovery-poc.mjs --source-root PATH");
  }
  if (!sourceRoot) fail("--source-root is required");
  return path.resolve(sourceRoot);
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function hardenedWorker(workloadId, logicalNetwork) {
  return {
    image: "registry.example/workload/app@sha256:" + "a".repeat(64),
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
      "com.platform.workload-id": workloadId,
      "com.platform.workload-role": "worker",
    },
  };
}

function validateEgressFixture(contract, workloadId) {
  const logicalNetwork = workloadId.replaceAll("-", "_") + "_egress";
  const serviceName = workloadId + "-worker";
  const manifest = contract.validateWorkloadManifest({
    version: 1,
    id: workloadId,
    composeFile: "compose.platform.yaml",
    services: [{ name: serviceName, role: "worker" }],
  });
  const core = { services: {}, networks: {} };
  const combined = {
    services: {
      [serviceName]: hardenedWorker(workloadId, logicalNetwork),
    },
    networks: {
      [logicalNetwork]: {},
    },
  };
  assert.deepEqual(
    contract.validateRenderedWorkloads({
      core,
      combined,
      lock: { workloads: [manifest] },
    }),
    { routes: [] },
  );
  return logicalNetwork;
}

const sourceRoot = parseArgs(process.argv.slice(2));
const expectedHashes = new Map([
  ["scripts/workload-egress-firewall.sh", "813217f31244cd909ad55cbe546452afbf5e47d74efd3508e666cfcb67d79a85"],
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["NETWORK-SEGMENTATION.md", "d4bb9839c3f2c95dff584ad5668971ba108e406618b472c55034e4f2bc26d62d"],
  ["config/project-manifest.example.json", "ddda464baa5d838c928938959e4bfe36de60e8a5814333f6495a0f6e0093be6f"],
]);

let temporaryRoot = "";
try {
  for (const [relativePath, expectedHash] of expectedHashes) {
    assert.equal(
      sha256(path.join(sourceRoot, relativePath)),
      expectedHash,
      relativePath + " does not match the exact pre-fix source",
    );
  }
  pass("exact pre-fix source fingerprints verified");

  const contractTests = spawnSync(
    process.execPath,
    [path.join(sourceRoot, "scripts/hosted-workload-contract.test.mjs")],
    {
      cwd: sourceRoot,
      encoding: "utf8",
      env: {
        HOME: process.env.HOME || "",
        PATH: process.env.PATH || "",
        NODE_NO_WARNINGS: "1",
      },
    },
  );
  assert.equal(
    contractTests.status,
    0,
    "repository tests failed:\n" +
      (contractTests.stderr || contractTests.stdout || "no output"),
  );
  assert.match(
    contractTests.stdout,
    /hosted workload contract tests passed 15\/15/,
  );
  pass("repository hosted-workload tests pass 15/15");

  const contractPath = path.join(
    sourceRoot,
    "scripts/hosted-workload-contract.mjs",
  );
  const contract = await import(pathToFileURL(contractPath).href);
  const stexorNetwork = validateEgressFixture(contract, "stexor");
  const exampleNetwork = validateEgressFixture(contract, "example-app");
  assert.equal(stexorNetwork, "stexor_egress");
  assert.equal(exampleNetwork, "example_app_egress");
  pass("valid stexor and example-app egress networks pass admission");

  const firewallPath = path.join(
    sourceRoot,
    "scripts/workload-egress-firewall.sh",
  );
  const firewallText = fs.readFileSync(firewallPath, "utf8");
  const vulnerablePattern =
    "\"$" + "{NETWORK_PREFIX}\"_app_*_egress)";
  assert.ok(firewallText.includes(vulnerablePattern));
  assert.ok(
    firewallText.includes("if [ ! -s \"$SUBNET_FILE\" ]; then"),
  );
  assert.ok(
    firewallText.includes("iptables -w -A \"$CHAIN\" -s \"$subnet\""),
  );

  temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "fg019-egress-discovery-"),
  );
  const fakeBin = path.join(temporaryRoot, "bin");
  const dockerLog = path.join(temporaryRoot, "docker.log");
  const iptablesLog = path.join(temporaryRoot, "iptables.log");
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(dockerLog, "");
  fs.writeFileSync(iptablesLog, "");

  const fakeDocker = [
    "#!/bin/sh",
    "set -eu",
    "printf '%s\\n' \"$*\" >> \"$FAKE_DOCKER_LOG\"",
    "if [ \"$1\" = network ] && [ \"$2\" = ls ]; then",
    "  printf '%s\\n' \\",
    "    platform_infra_vps_app_demo_egress \\",
    "    platform_infra_vps_stexor_egress \\",
    "    platform_infra_vps_example_app_egress",
    "  exit 0",
    "fi",
    "if [ \"$1\" = network ] && [ \"$2\" = inspect ]; then",
    "  case \"$3\" in",
    "    platform_infra_vps_app_demo_egress)",
    "      printf '%s\\n' 172.28.10.0/24",
    "      ;;",
    "    platform_infra_vps_stexor_egress)",
    "      printf '%s\\n' 172.28.20.0/24",
    "      ;;",
    "    platform_infra_vps_example_app_egress)",
    "      printf '%s\\n' 172.28.30.0/24",
    "      ;;",
    "    *)",
    "      exit 92",
    "      ;;",
    "  esac",
    "  exit 0",
    "fi",
    "exit 91",
  ].join("\n") + "\n";

  const fakeIptables = [
    "#!/bin/sh",
    "printf '%s\\n' \"$*\" >> \"$FAKE_IPTABLES_LOG\"",
    "exit 97",
  ].join("\n") + "\n";

  const scratchMktemp = [
    "#!/bin/sh",
    "set -eu",
    "[ \"$#\" -eq 0 ] || { printf '%s\\n' 'unexpected mktemp arguments' >&2; exit 93; }",
    "exec /usr/bin/mktemp \"${TMPDIR:?}/fg019-firewall-subnets.XXXXXXXX\"",
  ].join("\n") + "\n";

  fs.writeFileSync(path.join(fakeBin, "docker"), fakeDocker, { mode: 0o755 });
  fs.writeFileSync(
    path.join(fakeBin, "iptables"),
    fakeIptables,
    { mode: 0o755 },
  );
  fs.writeFileSync(path.join(fakeBin, "mktemp"), scratchMktemp, { mode: 0o755 });

  const plan = spawnSync(
    "/bin/sh",
    [
      firewallPath,
      "--plan",
      "--network-prefix",
      "platform_infra_vps",
    ],
    {
      cwd: temporaryRoot,
      encoding: "utf8",
      env: {
        FAKE_DOCKER_LOG: dockerLog,
        FAKE_IPTABLES_LOG: iptablesLog,
        LANG: "C",
        PATH: fakeBin + ":/usr/bin:/bin",
        TMPDIR: temporaryRoot,
      },
    },
  );
  assert.equal(
    plan.status,
    0,
    "firewall plan failed:\n" +
      (plan.stderr || plan.stdout || "no output"),
  );
  assert.match(plan.stdout, /Mode: plan; no firewall mutation executed\./);
  assert.match(plan.stdout, /Workload source: 172\.28\.10\.0\/24/);
  assert.doesNotMatch(plan.stdout, /172\.28\.20\.0\/24/);
  assert.doesNotMatch(plan.stdout, /172\.28\.30\.0\/24/);

  const dockerCalls = fs.readFileSync(dockerLog, "utf8");
  assert.match(dockerCalls, /network ls --format/);
  assert.match(
    dockerCalls,
    /network inspect platform_infra_vps_app_demo_egress --format/,
  );
  assert.doesNotMatch(
    dockerCalls,
    /network inspect platform_infra_vps_stexor_egress/,
  );
  assert.doesNotMatch(
    dockerCalls,
    /network inspect platform_infra_vps_example_app_egress/,
  );
  assert.equal(fs.readFileSync(iptablesLog, "utf8"), "");

  pass("exact discovery glob inspects only app_demo egress");
  pass("valid stexor and example-app physical networks are ignored");
  pass("partial discovery succeeds instead of reporting omitted networks");
  pass("firewall plan tracks 172.28.10.0/24 but not 172.28.20.0/24 or 172.28.30.0/24");
  process.stdout.write(
    "[SAFE] fake Docker shim only; no Engine, network, iptables, HTTP, or live-state action attempted\n",
  );
} catch (error) {
  process.stderr.write("[FAIL] " + (error.stack || error.message) + "\n");
  process.exitCode = 1;
} finally {
  if (temporaryRoot) {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
