#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_SOURCE_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/vps-hardening-ubuntu.sh", "c8edddfe1a1cb5da1499e4e35cc390b8dd14d7240a71321544709941bad62388"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);

function fail(message) {
  throw new Error(message);
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function snapshotTree(root) {
  const digest = crypto.createHash("sha256");

  function visit(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isDirectory()) {
      digest.update(`directory\0${relative}\0${stat.mode & 0o7777}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        visit(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    if (stat.isFile()) {
      const data = fs.readFileSync(current);
      digest.update(`file\0${relative}\0${stat.mode & 0o7777}\0${data.length}\0`);
      digest.update(data);
      digest.update("\0");
      return;
    }
    if (stat.isSymbolicLink()) {
      digest.update(`symlink\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    fail(`unsupported archived source entry: ${relative}`);
  }

  visit(root, "");
  return digest.digest("hex");
}

function verifyBoundary(sourceArgument) {
  const wrapperRootInput = process.env.FG041_WRAPPER_TEMP_ROOT;
  const sentinelInput = process.env.FG041_OWNERSHIP_SENTINEL;
  const token = process.env.FG041_OWNERSHIP_TOKEN;
  if (!wrapperRootInput || !sentinelInput || !token) {
    fail("wrapper ownership environment is required; direct invocation is refused");
  }
  if (!/^[A-Za-z0-9]+$/.test(token)) fail("ownership token has invalid syntax");

  const wrapperRoot = path.resolve(wrapperRootInput);
  const source = path.resolve(sourceArgument);
  const sentinel = path.resolve(sentinelInput);
  const rootStat = fs.lstatSync(wrapperRoot);
  const sourceStat = fs.lstatSync(source);
  const sentinelStat = fs.lstatSync(sentinel);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("wrapper root must be a real directory");
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) fail("source must be a real directory");
  if (!sentinelStat.isFile() || sentinelStat.isSymbolicLink()) fail("ownership sentinel must be a regular file");

  const realRoot = fs.realpathSync(wrapperRoot);
  const realSource = fs.realpathSync(source);
  const realSentinel = fs.realpathSync(sentinel);
  if (realSource !== path.join(realRoot, "source")) fail("source is not the wrapper-owned source child");
  if (path.dirname(realSentinel) !== realRoot) fail("ownership sentinel is outside the wrapper root");
  if (path.basename(realSentinel) !== `.fg041-owner.${token}`) {
    fail("ownership token does not match sentinel name");
  }
  if (fs.readFileSync(realSentinel, "utf8") !== `FG041-OWNER:${token}\n`) {
    fail("ownership sentinel content is invalid");
  }
  return realSource;
}

function readSource(sourceRoot, relative) {
  const file = path.join(sourceRoot, relative);
  const data = fs.readFileSync(file);
  const expected = EXPECTED_SOURCE_HASHES.get(relative);
  assert.equal(sha256(data), expected, `unexpected archived source hash for ${relative}`);
  return data.toString("utf8");
}

function verifySourceShape(sourceRoot) {
  const contract = readSource(sourceRoot, "scripts/hosted-workload-contract.mjs");
  const contractTest = readSource(sourceRoot, "scripts/hosted-workload-contract.test.mjs");
  const hardening = readSource(sourceRoot, "scripts/vps-hardening-ubuntu.sh");
  const prepare = readSource(sourceRoot, "scripts/prepare-hosted-workloads.sh");
  const compose = readSource(sourceRoot, "scripts/compose-vps.sh");

  const serviceStart = contract.indexOf("function assertWorkloadService(");
  const serviceEnd = contract.indexOf("export function validateRenderedWorkloads", serviceStart);
  assert.ok(serviceStart >= 0 && serviceEnd > serviceStart, "workload service policy function is missing");
  const servicePolicy = contract.slice(serviceStart, serviceEnd);
  assert.doesNotMatch(servicePolicy, /\blogging\b/, "pre-fix service policy unexpectedly checks logging");
  assert.match(contract, /assertWorkloadService\(\{ serviceDefinition: rendered,/);
  assert.doesNotMatch(contractTest, /\blogging\b/i, "pre-fix regression suite unexpectedly covers logging");

  assert.ok(hardening.includes('\\"log-driver\\": \\"json-file\\"'));
  assert.ok(hardening.includes('\\"max-size\\": \\"10m\\"'));
  assert.ok(hardening.includes('\\"max-file\\": \\"5\\"'));

  const combinedRender = prepare.indexOf('HOSTED_WORKLOAD_LOCK="$resolved"');
  const verifyRender = prepare.indexOf("verify-render", combinedRender);
  assert.ok(combinedRender >= 0 && verifyRender > combinedRender, "combined render does not reach verification");
  assert.ok(compose.includes('compose+=(-f "$workload_file")'));
  assert.ok(compose.includes('exec "${compose[@]}" --profile backup "$@"'));

  return path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
}

function createFixture(validateWorkloadManifest, logging) {
  const digest = "a".repeat(64);
  const manifest = validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    services: [
      { name: "example-app-web", role: "web", routes: [{ slug: "example", port: 3000 }] },
    ],
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
    networks: { example_app_ingress: null },
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "web",
    },
    logging: structuredClone(logging),
  };
  const core = {
    services: {
      "project-router": {
        image: `registry.example/router@sha256:${digest}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
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

async function main() {
  if (process.argv.length !== 3) fail("usage: hosted-logging-policy-probe.mjs ARCHIVED_SOURCE");
  const sourceRoot = verifyBoundary(process.argv[2]);
  process.stdout.write("[+] wrapper-owned source boundary verified\n");
  const before = snapshotTree(sourceRoot);
  const contractPath = verifySourceShape(sourceRoot);
  process.stdout.write("[+] verified 5 archived source hashes and absent workload logging policy\n");
  process.stdout.write("[+] verified daemon default logging=json-file max-size=10m max-file=5\n");
  process.stdout.write("[+] verified combined render reaches admission and locked overlays reach Compose\n");

  const moduleUrl = `${pathToFileURL(contractPath).href}?revision=${REVISION}&tree=${TREE}`;
  const { validateRenderedWorkloads, validateWorkloadManifest } = await import(moduleUrl);
  assert.equal(typeof validateRenderedWorkloads, "function");
  assert.equal(typeof validateWorkloadManifest, "function");

  function accepted(label, logging, detail) {
    const fixture = createFixture(validateWorkloadManifest, logging);
    const originalLogging = structuredClone(fixture.combined.services["example-app-web"].logging);
    const result = validateRenderedWorkloads(fixture);
    assert.deepEqual(result.routes, [
      {
        workloadId: "example-app",
        slug: "example",
        service: "example-app-web",
        port: 3000,
        upstream: "http://example-app-web:3000",
      },
    ]);
    assert.deepEqual(fixture.combined.services["example-app-web"].logging, originalLogging);
    process.stdout.write(`${label} ${detail} admission=accepted\n`);
  }

  accepted(
    "[BASELINE]",
    { driver: "json-file", options: { "max-size": "10m", "max-file": "5" } },
    "approved-local-json driver=json-file max-size=10m max-file=5",
  );
  accepted("[VULNERABLE]", { driver: "none" }, "disabled-audit driver=none");
  accepted(
    "[VULNERABLE]",
    { driver: "json-file", options: { "max-size": "100g", "max-file": "1000000" } },
    "rotation-bound-extreme driver=json-file max-size=100g max-file=1000000",
  );
  accepted(
    "[VULNERABLE]",
    { driver: "syslog", options: { "syslog-address": "tcp://10.0.0.25:514" } },
    "daemon-syslog-egress driver=syslog address=tcp://10.0.0.25:514",
  );

  const after = snapshotTree(sourceRoot);
  assert.equal(after, before, "archived source tree changed during the probe");
  process.stdout.write("[+] summary vulnerable=3 total=3 source_tree_unchanged=true\n");
  process.stdout.write("[+] no Docker, Compose, daemon, container, network, log emission, or live target was accessed\n");
}

main().catch((error) => {
  process.stderr.write(`error: ${error.message}\n`);
  process.exitCode = 1;
});
