#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [snapshotRoot, commit, tree] = process.argv.slice(2);
if (!snapshotRoot || !commit || !tree) {
  process.stderr.write("usage: node probe.mjs SNAPSHOT_ROOT COMMIT TREE\n");
  process.exit(2);
}

const contractPath = path.join(snapshotRoot, "scripts", "hosted-workload-contract.mjs");
const {
  resolveCatalog,
  validateRenderedWorkloads,
  verifyLockFiles,
} = await import(pathToFileURL(contractPath).href);

const digest = "a".repeat(64);
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-config-fixture-"));

try {
  const workloadRoot = path.join(tempRoot, "workloads");
  const workloadDir = path.join(workloadRoot, "demo-app");
  const outsideDir = path.join(tempRoot, "outside");
  fs.mkdirSync(workloadDir, { recursive: true });
  fs.mkdirSync(outsideDir, { recursive: true });

  const hostReadableSource = path.join(outsideDir, "host-readable-sentinel.txt");
  const mutableSource = path.join(outsideDir, "mutable-sentinel.txt");
  const symlinkSource = path.join(workloadDir, "config-link.txt");
  fs.writeFileSync(hostReadableSource, "synthetic-host-readable-sentinel-v1\n", { mode: 0o644 });
  fs.writeFileSync(mutableSource, "synthetic-mutable-sentinel-v1\n", { mode: 0o644 });
  fs.symlinkSync(path.relative(workloadDir, hostReadableSource), symlinkSource);
  fs.accessSync(hostReadableSource, fs.constants.R_OK);

  const manifestPath = path.join(workloadDir, "workload.json");
  const composePath = path.join(workloadDir, "compose.platform.yaml");
  const environmentPath = path.join(workloadDir, "workload.env");
  const catalogPath = path.join(tempRoot, "catalog.json");
  const coreEnvPath = path.join(tempRoot, "core.env");
  const coreComposePath = path.join(tempRoot, "core.yaml");

  fs.writeFileSync(manifestPath, `${JSON.stringify({
    version: 1,
    id: "demo-app",
    composeFile: "compose.platform.yaml",
    services: [{ name: "demo-app-web", role: "web" }],
    secrets: [],
    migrationRoots: [],
  }, null, 2)}\n`);
  fs.writeFileSync(composePath, `services:\n  demo-app-web:\n    configs:\n      - source: demo-app-readable\n        target: /run/configs/readable\nconfigs:\n  demo-app-readable:\n    file: ${hostReadableSource}\n`);
  fs.writeFileSync(environmentPath, "DEMO_APP_PUBLIC_MODE=probe\n");
  fs.writeFileSync(catalogPath, `${JSON.stringify({
    version: 1,
    workloads: [{
      manifest: "demo-app/workload.json",
      environmentFile: "demo-app/workload.env",
    }],
  }, null, 2)}\n`);
  fs.writeFileSync(coreEnvPath, "PLATFORM_PUBLIC_MODE=probe\n");
  fs.writeFileSync(coreComposePath, "services: {}\n");

  const lock = resolveCatalog({
    catalogPath,
    workloadRoot,
    coreEnvFile: coreEnvPath,
    coreFiles: [coreComposePath],
    projectName: "hosted_config_probe",
  });

  const manifest = lock.workloads[0];
  const core = {
    services: {
      "project-router": {
        image: `registry.example/router@sha256:${digest}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };

  const baseService = {
    image: `registry.example/demo/app@sha256:${digest}`,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    pids_limit: 64,
    cpu_shares: 128,
    blkio_config: { weight: 100 },
    ulimits: { nofile: { soft: 4096, hard: 4096 } },
    cpus: 0.25,
    mem_limit: String(128 * 1024 * 1024),
    mem_reservation: String(32 * 1024 * 1024),
    healthcheck: { test: ["CMD", "true"] },
    networks: { demo_app_ingress: null },
    labels: {
      "com.platform.workload-id": "demo-app",
      "com.platform.workload-role": "web",
    },
  };

  function combinedFor(source) {
    return {
      services: {
        "project-router": {
          ...structuredClone(core.services["project-router"]),
          networks: { platform_routing: null, demo_app_ingress: null },
        },
        "demo-app-web": {
          ...structuredClone(baseService),
          configs: [{
            source: "demo-app-readable",
            target: "/run/configs/readable",
            mode: 0o444,
          }],
        },
      },
      networks: {
        platform_routing: { internal: true },
        demo_app_ingress: { internal: true },
      },
      configs: {
        "demo-app-readable": { file: source },
      },
    };
  }

  const cases = [
    ["absolute", hostReadableSource],
    ["traversal", "../../outside/host-readable-sentinel.txt"],
    ["symlink", symlinkSource],
    ["mutable", mutableSource],
  ];

  const accepted = [];
  for (const [label, source] of cases) {
    validateRenderedWorkloads({ core, combined: combinedFor(source), lock });
    accepted.push(label);
    process.stdout.write(`[+] ${label} config source: ACCEPTED\n`);
  }

  assert.equal(path.isAbsolute(cases[0][1]), true);
  assert.equal(cases[1][1].split(path.sep).includes(".."), true);
  assert.equal(fs.lstatSync(symlinkSource).isSymbolicLink(), true);
  assert.equal(fs.realpathSync(symlinkSource), fs.realpathSync(hostReadableSource));

  const recordedPaths = new Set(lock.files.map((record) => path.resolve(record.path)));
  assert.equal(recordedPaths.has(path.resolve(hostReadableSource)), false);
  assert.equal(recordedPaths.has(path.resolve(mutableSource)), false);
  process.stdout.write("[+] pointed-to config bytes in workload lock: NO\n");

  const beforeHash = sha256(mutableSource);
  fs.writeFileSync(mutableSource, "synthetic-mutable-sentinel-v2\n", { mode: 0o644 });
  const afterHash = sha256(mutableSource);
  assert.notEqual(beforeHash, afterHash);

  verifyLockFiles(lock);
  validateRenderedWorkloads({ core, combined: combinedFor(mutableSource), lock });
  process.stdout.write("[+] config bytes changed after lock resolution: YES\n");
  process.stdout.write("[+] workload lock verification after config mutation: ACCEPTED\n");
  process.stdout.write("[+] deployment-readable synthetic source: YES\n");

  assert.deepEqual(accepted, ["absolute", "traversal", "symlink", "mutable"]);
  process.stdout.write(`[+] revision: ${commit}\n`);
  process.stdout.write(`[+] tree: ${tree}\n`);
  process.stdout.write("[+] result: VULNERABLE\n");
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

