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
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);

const GPU_CASES = [
  {
    name: "service-gpus-all",
    semantic: "all-devices-per-compose-spec",
    apply(service) {
      service.gpus = "all";
    },
  },
  {
    name: "deploy-count-all",
    semantic: "all-matching-gpu-devices",
    apply(service) {
      service.deploy = {
        resources: {
          reservations: {
            devices: [{ capabilities: ["gpu"], count: "all" }],
          },
        },
      };
    },
  },
  {
    name: "deploy-capability-only",
    semantic: "all-matching-gpu-devices-when-count-and-ids-omitted",
    apply(service) {
      service.deploy = {
        resources: {
          reservations: {
            devices: [{ capabilities: ["gpu"] }],
          },
        },
      };
    },
  },
  {
    name: "deploy-unknown-device-id",
    semantic: "unapproved-device-identity-not-checked",
    apply(service) {
      service.deploy = {
        resources: {
          reservations: {
            devices: [{
              capabilities: ["gpu"],
              driver: "nvidia",
              device_ids: ["GPU-SYNTHETIC-UNAPPROVED"],
            }],
          },
        },
      };
    },
  },
];

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
  const wrapperRootInput = process.env.FG071_WRAPPER_TEMP_ROOT;
  const sentinelInput = process.env.FG071_OWNERSHIP_SENTINEL;
  const token = process.env.FG071_OWNERSHIP_TOKEN;
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
  if (path.basename(realSentinel) !== `.fg071-owner.${token}`) {
    fail("ownership token does not match sentinel name");
  }
  if (fs.readFileSync(realSentinel, "utf8") !== `FG071-OWNER:${token}\n`) {
    fail("ownership sentinel content is invalid");
  }
  return realSource;
}

function readSource(sourceRoot, relative) {
  const file = path.join(sourceRoot, relative);
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`source path is not a regular file: ${relative}`);
  const data = fs.readFileSync(file);
  assert.equal(sha256(data), EXPECTED_SOURCE_HASHES.get(relative), `unexpected archived source hash for ${relative}`);
  return data.toString("utf8");
}

function verifySourceShape(sourceRoot) {
  const contract = readSource(sourceRoot, "scripts/hosted-workload-contract.mjs");
  const contractTests = readSource(sourceRoot, "scripts/hosted-workload-contract.test.mjs");
  const runtimePolicy = readSource(sourceRoot, "scripts/runtime-isolation-policy.mjs");
  const prepare = readSource(sourceRoot, "scripts/prepare-hosted-workloads.sh");
  const compose = readSource(sourceRoot, "scripts/compose-vps.sh");

  assert.match(contract, /function assertWorkloadService\(/);
  assert.match(contract, /export function validateRenderedWorkloads\(/);
  assert.doesNotMatch(contract, /\bgpus?\b|device_ids|reservations\?\.devices|reservations\.devices/i);
  assert.doesNotMatch(contractTests, /\bgpus?\b|device_ids/i);
  assert.doesNotMatch(runtimePolicy, /\bgpus?\b|device_ids|reservations\?\.devices|reservations\.devices/i);
  assert.match(prepare, /HOSTED_WORKLOAD_LOCK="\$resolved" HOSTED_WORKLOAD_ALLOW_RESOLVED=1[\s\S]*compose-vps\.sh" config --format json > "\$combined_render"/);
  assert.match(prepare, /hosted-workload-contract\.mjs verify-render[\s\S]*--combinedRender "\$combined_render"/);
  assert.match(compose, /mapfile -t workload_files[\s\S]*hosted-workload-lock\.sh" "\$workload_lock" compose-files[\s\S]*compose\+=\(-f "\$workload_file"\)/);
  assert.match(compose, /exec "\$\{compose\[@\]\}" --profile backup "\$@"/);

  return path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
}

function baseService() {
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
    networks: { probe_app_bus: null },
    labels: {
      "com.platform.workload-id": "probe-app",
      "com.platform.workload-role": "worker",
    },
  };
}

function fixture(apply = () => {}) {
  const service = baseService();
  apply(service);
  return {
    core: { services: {}, networks: {} },
    combined: {
      services: { "probe-app-worker": service },
      networks: { probe_app_bus: { internal: true } },
    },
    lock: {
      workloads: [{
        id: "probe-app",
        secrets: [],
        services: [{ name: "probe-app-worker", role: "worker", routes: [] }],
      }],
    },
  };
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
}

async function main() {
  if (process.argv.length !== 3) fail("usage: hosted-gpu-admission-probe.mjs ARCHIVED_SOURCE");
  const sourceRoot = verifyBoundary(process.argv[2]);
  process.stdout.write("[+] wrapper-owned source boundary verified\n");
  const sourceBefore = snapshotTree(sourceRoot);
  const contractPath = verifySourceShape(sourceRoot);
  process.stdout.write("[+] verified 5 archived source hashes and admission-to-Compose source shapes\n");
  process.stdout.write("[SOURCE-TRACE] gpu_checks=absent contract_tests=absent runtime_policy=absent compose_executable_invoked=false\n");

  const moduleUrl = `${pathToFileURL(contractPath).href}?revision=${REVISION}&tree=${TREE}`;
  const { validateRenderedWorkloads } = await import(moduleUrl);

  const baseline = fixture();
  const baselineResult = validateRenderedWorkloads(baseline);
  assert.deepEqual(baselineResult, { routes: [] });
  process.stdout.write("[CONTROL] bounded-no-gpu admission=accepted synthetic_render=true\n");

  const privileged = fixture((service) => {
    service.privileged = true;
  });
  assert.throws(() => validateRenderedWorkloads(privileged), /host-level privilege/);
  process.stdout.write("[NEGATIVE-CONTROL] privileged admission=rejected archived_validator_executed=true\n");

  let accepted = 0;
  for (const testCase of GPU_CASES) {
    const input = fixture(testCase.apply);
    const before = stable(structuredClone(input.combined));
    const result = validateRenderedWorkloads(input);
    assert.deepEqual(result, { routes: [] });
    assert.deepEqual(stable(input.combined), before, `${testCase.name} render changed during validation`);
    accepted += 1;
    process.stdout.write(
      `[VULNERABLE] ${testCase.name} admission=accepted field_preserved=true semantic=${testCase.semantic} runtime=NOT-TESTED\n`,
    );
  }

  assert.equal(accepted, GPU_CASES.length);
  const sourceAfter = snapshotTree(sourceRoot);
  assert.equal(sourceAfter, sourceBefore, "archived source tree changed during the probe");
  process.stdout.write(`[+] summary gpu_request_variants_accepted=${accepted} total=${GPU_CASES.length} source_tree_unchanged=true\n`);
  process.stdout.write("[PENDING] compose_normalization=NOT-TESTED gpu_allocation=NOT-TESTED resource_exhaustion=NOT-TESTED driver_attack_surface=NOT-TESTED\n");
  process.stdout.write("[+] no Docker, Compose, GPU, device, network, credential, SSH, or live target was accessed\n");
}

main().catch((error) => {
  process.stderr.write(`error: ${error.message}\n`);
  process.exitCode = 1;
});
