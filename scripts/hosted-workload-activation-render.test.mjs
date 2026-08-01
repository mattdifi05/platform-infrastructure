#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  resolveCatalog,
  verifyActivationRender,
  verifyLockFiles,
  verifyRawPolicyReceipt,
} from "./hosted-workload-contract.mjs";

const digest = "a".repeat(64);
const sourcePolicy = path.join(import.meta.dirname, "hosted-workload-source-policy.rb");
const contract = path.join(import.meta.dirname, "hosted-workload-contract.mjs");

test("read-only activation render verification binds both SHAs and final secret semantics", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-render-")));
  try {
    const fixture = verifiedRenderFixture(root);
    const lockBefore = fs.readFileSync(fixture.lockPath);
    const verified = spawnSync(process.execPath, [
      contract,
      "verify-activation-render",
      "--lock", fixture.lockPath,
      "--coreRender", fixture.coreRenderPath,
      "--combinedRender", fixture.combinedRenderPath,
    ], { encoding: "utf8" });
    assert.equal(verified.status, 0, verified.stderr);
    assert.equal(verifyActivationRender(fixture), true);
    assert.deepEqual(fs.readFileSync(fixture.lockPath), lockBefore);

    fs.appendFileSync(fixture.combinedRenderPath, "\n");
    assert.throws(
      () => verifyActivationRender(fixture),
      /combined render does not match the SHA-256 pinned/,
    );

    const combined = fixture.combined;
    combined.services["billing-web"].environment.BILLING_TOKEN_FILE = "/run/secrets/ungranted-secret";
    writeJson(fixture.combinedRenderPath, combined);
    const forgedLock = JSON.parse(fs.readFileSync(fixture.lockPath, "utf8"));
    forgedLock.combinedRenderSha256 = sha256(fs.readFileSync(fixture.combinedRenderPath));
    writeJson(fixture.lockPath, forgedLock);
    assert.throws(
      () => verifyActivationRender(fixture),
      /secret file.*ungranted secret target/i,
    );
  } finally {
    removeFixtureTree(root);
  }
});

test("verified lock and activation render reject a re-pinned undeclared worker route", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-route-lineage-")));
  try {
    const fixture = verifiedRenderFixture(root);
    const forged = JSON.parse(fs.readFileSync(fixture.lockPath, "utf8"));
    forged.routes = [{
      owner: "billing",
      workloadId: "billing",
      slug: "admin",
      aliases: [],
      canonicalHost: "admin.example.com",
      hosts: ["admin.example.com"],
      service: "billing-worker",
      port: 9999,
      upstream: "http://billing-worker:9999",
    }];
    writeJson(fixture.lockPath, forged);
    fs.chmodSync(fixture.lockPath, 0o600);

    assert.throws(() => verifyLockFiles(forged), /canonical route|route lineage/i);
    assert.throws(() => verifyRawPolicyReceipt(forged), /canonical route|route lineage/i);
    assert.throws(() => verifyActivationRender(fixture), /canonical route|route lineage/i);
  } finally {
    removeFixtureTree(root);
  }
});

function verifiedRenderFixture(root) {
  const workloadRoot = path.join(root, "workloads");
  const appRoot = path.join(workloadRoot, "billing");
  fs.mkdirSync(appRoot, { recursive: true });
  fs.writeFileSync(path.join(appRoot, "manifest.json"), JSON.stringify({
    version: 1,
    id: "billing",
    composeFile: "compose.yaml",
    secrets: ["billing-api-key"],
    services: [{
      name: "billing-web",
      role: "web",
      routes: [{ slug: "billing", host: "billing.example.com", port: 3000 }],
    }, {
      name: "billing-worker",
      role: "worker",
      routes: [],
    }],
  }));
  fs.writeFileSync(path.join(appRoot, "compose.yaml"), [
    "services:",
    "  billing-web:",
    "    security_opt:",
    "      - no-new-privileges:true",
    "    secrets:",
    "      - source: billing-api-key",
    "        target: billing-api-key",
    "    networks:",
    "      billing_ingress:",
    "  billing-worker:",
    "    security_opt:",
    "      - no-new-privileges:true",
    "    networks:",
    "      billing_ingress:",
    "  project-router:",
    "    networks:",
    "      billing_ingress:",
    "secrets:",
    "  billing-api-key:",
    "    external: true",
    "    name: fixture_billing-api-key",
    "networks:",
    "  billing_ingress:",
    "    internal: true",
    "",
  ].join("\n"));
  fs.writeFileSync(path.join(appRoot, "workload.env"), "BILLING_THEME=dark\n");
  const catalogPath = path.join(root, "catalog.json");
  const coreEnvFile = path.join(root, "core.env");
  const coreFile = path.join(root, "compose.core.yaml");
  const lockPath = path.join(root, "hosted-workloads.lock.json");
  fs.writeFileSync(catalogPath, JSON.stringify({
    version: 1,
    workloads: [{ manifest: "billing/manifest.json", environmentFile: "billing/workload.env" }],
  }));
  fs.writeFileSync(coreEnvFile, "CORE_VALUE=fixture\n", { mode: 0o600 });
  fs.chmodSync(coreEnvFile, 0o600);
  fs.writeFileSync(coreFile, [
    "services:",
    "  project-router: {}",
    "networks:",
    "  platform_routing: {}",
    "",
  ].join("\n"));
  const lock = resolveCatalog({
    catalogPath,
    workloadRoot,
    coreEnvFile,
    coreFiles: [coreFile],
    projectName: "fixture",
    snapshotRoot: path.join(root, "snapshots"),
    activationLockPath: lockPath,
  });
  writeJson(lockPath, lock);
  fs.chmodSync(lockPath, 0o600);
  const rawPolicy = spawnSync("ruby", [sourcePolicy, "--lock", lockPath], { encoding: "utf8" });
  assert.equal(rawPolicy.status, 0, rawPolicy.stderr);

  const core = {
    services: {
      "project-router": {
        image: `example.invalid/router@sha256:${digest}`,
        networks: { platform_routing: null },
        volumes: [{
          type: "bind",
          source: lockPath,
          target: "/run/platform/hosted-workloads.lock.json",
          read_only: true,
        }],
      },
    },
    networks: { platform_routing: { internal: true } },
  };
  const combined = {
    services: {
      "project-router": {
        ...structuredClone(core.services["project-router"]),
        networks: { platform_routing: null, billing_ingress: null },
      },
      "billing-web": {
        image: `example.invalid/billing@sha256:${digest}`,
        read_only: true,
        init: true,
        restart: "no",
        security_opt: ["no-new-privileges:true"],
        cap_drop: ["ALL"],
        user: "1000:1000",
        logging: { driver: "local", options: { "max-size": "10m", "max-file": "3" } },
        pids_limit: 128,
        cpu_shares: 256,
        blkio_config: { weight: 300 },
        ulimits: { nofile: { soft: 8192, hard: 8192 } },
        cpus: 0.5,
        mem_limit: String(256 * 1024 * 1024),
        memswap_limit: String(256 * 1024 * 1024),
        mem_reservation: String(64 * 1024 * 1024),
        healthcheck: { test: ["CMD", "true"] },
        environment: { BILLING_TOKEN_FILE: "/run/secrets/billing-api-key" },
        secrets: [{ source: "billing-api-key", target: "billing-api-key" }],
        networks: { billing_ingress: null },
        labels: {
          "com.platform.workload-id": "billing",
          "com.platform.workload-role": "web",
        },
      },
      "billing-worker": {
        image: `example.invalid/billing@sha256:${digest}`,
        read_only: true,
        init: true,
        restart: "no",
        security_opt: ["no-new-privileges:true"],
        cap_drop: ["ALL"],
        user: "1000:1000",
        logging: { driver: "local", options: { "max-size": "10m", "max-file": "3" } },
        pids_limit: 128,
        cpu_shares: 256,
        blkio_config: { weight: 300 },
        ulimits: { nofile: { soft: 8192, hard: 8192 } },
        cpus: 0.5,
        mem_limit: String(256 * 1024 * 1024),
        memswap_limit: String(256 * 1024 * 1024),
        mem_reservation: String(64 * 1024 * 1024),
        healthcheck: { test: ["CMD", "true"] },
        environment: {},
        secrets: [],
        volumes: [],
        networks: { billing_ingress: null },
        labels: {
          "com.platform.workload-id": "billing",
          "com.platform.workload-role": "worker",
        },
      },
    },
    networks: {
      platform_routing: { internal: true },
      billing_ingress: { internal: true, name: "fixture_billing_ingress" },
    },
    secrets: {
      "billing-api-key": { external: true, name: "fixture_billing-api-key" },
    },
  };
  const coreRenderPath = path.join(root, "core-render.json");
  const combinedRenderPath = path.join(root, "combined-render.json");
  writeJson(coreRenderPath, core);
  writeJson(combinedRenderPath, combined);
  const verified = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  verified.state = "verified";
  verified.coreRenderSha256 = sha256(fs.readFileSync(coreRenderPath));
  verified.combinedRenderSha256 = sha256(fs.readFileSync(combinedRenderPath));
  verified.routes = [{
    owner: "billing",
    workloadId: "billing",
    slug: "billing",
    aliases: [],
    canonicalHost: "billing.example.com",
    hosts: ["billing.example.com"],
    service: "billing-web",
    port: 3000,
    upstream: "http://billing-web:3000",
  }];
  writeJson(lockPath, verified);
  fs.chmodSync(lockPath, 0o600);
  return { lockPath, coreRenderPath, combinedRenderPath, combined };
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function removeFixtureTree(root) {
  if (!fs.existsSync(root)) return;
  const makeWritable = (target) => {
    const stat = fs.lstatSync(target);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return;
    fs.chmodSync(target, 0o700);
    for (const entry of fs.readdirSync(target)) makeWritable(path.join(target, entry));
  };
  makeWritable(root);
  fs.rmSync(root, { recursive: true, force: true });
}
