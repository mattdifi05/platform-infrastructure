#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { resolveCatalog } from "./hosted-workload-contract.mjs";

const digest = "a".repeat(64);
const policyScript = path.join(import.meta.dirname, "hosted-workload-source-policy.rb");
const lockScript = path.join(import.meta.dirname, "hosted-workload-lock.sh");

test("shell lock consumer preserves exact non-colliding and single-owner identities", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-shell-positive-")));
  try {
    const nonColliding = createResolvedLock(path.join(root, "non-colliding"), [
      { id: "billing", serviceName: "billing-web" },
      { id: "billingapi", serviceName: "billingapi-web" },
    ]);
    const nonCollidingBundle = validateRawAndReadBundle(nonColliding.lockPath);
    assert.deepEqual(nonCollidingBundle.workloadIds, ["billing", "billingapi"]);
    assert.deepEqual(
      Object.keys(nonCollidingBundle.protectedResourceNames).sort(),
      ["configs", "networks", "secrets", "services", "volumes"],
    );
    assert.deepEqual(
      nonCollidingBundle.protectedResourceNames,
      JSON.parse(fs.readFileSync(nonColliding.lockPath, "utf8")).rawPolicyReceipt.protectedResourceNames,
    );

    const singleOwner = createResolvedLock(path.join(root, "single-owner"), [{
      id: "billing",
      serviceName: "billing-api-web",
      secretName: "billing-api-key",
      volumeName: "billing_api_data",
    }]);
    const singleOwnerBundle = validateRawAndReadBundle(singleOwner.lockPath);
    assert.deepEqual(singleOwnerBundle.workloadIds, ["billing"]);
    assert.deepEqual(singleOwnerBundle.serviceRecords, [{
      workloadId: "billing",
      serviceName: "billing-api-web",
    }]);
  } finally {
    removeFixtureTree(root);
  }
});

test("shell lock consumer rejects a schema- and digest-coherent nested-id forgery", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-shell-forged-")));
  try {
    const fixture = createResolvedLock(root, [
      { id: "billing", serviceName: "billing-web" },
      { id: "billingapi", serviceName: "billingapi-web" },
    ]);
    validateRawAndReadBundle(fixture.lockPath);
    forgeNestedIdentity(fixture.lockPath, "billingapi", "billing-api");

    const forged = JSON.parse(fs.readFileSync(fixture.lockPath, "utf8"));
    assert.deepEqual(forged.workloads.map((workload) => workload.id), ["billing", "billing-api"]);
    assert.equal(
      forged.rawPolicySha256,
      sha256(Buffer.from(JSON.stringify(stable(forged.rawPolicyReceipt)))),
    );
    assert.equal(forged.rawPolicyWorkloadContentSha256, forged.workloadContentSha256);
    assert.deepEqual(
      Object.keys(forged.rawPolicyReceipt.protectedResourceNames).sort(),
      ["configs", "networks", "secrets", "services", "volumes"],
    );

    const rejected = spawnSync("/bin/sh", [lockScript, fixture.lockPath, "verify"], {
      encoding: "utf8",
      env: { ...process.env, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
    });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /canonical ownership is invalid/);
  } finally {
    removeFixtureTree(root);
  }
});

test("shell verify and activation bundle reject digest-coherent foreign resource owners", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-shell-owner-forged-")));
  try {
    const fixture = createResolvedLock(root, [
      {
        id: "billing",
        serviceName: "billing-web",
        secretName: "billing-api-key",
        volumeName: "billing_data",
      },
      { id: "billingapi", serviceName: "billingapi-web" },
    ]);
    validateRawAndReadBundle(fixture.lockPath);
    forgeForeignOwnedResources(fixture.lockPath);

    const forged = JSON.parse(fs.readFileSync(fixture.lockPath, "utf8"));
    const billing = forged.rawPolicyReceipt.workloads.find((item) => item.workloadId === "billing");
    assert.deepEqual(billing.serviceNames, ["billingapi-stolen-web"]);
    assert.deepEqual(billing.secretNames, ["billingapi-api-key"]);
    assert.deepEqual(billing.volumeNames, ["billingapi_data"]);
    assert.equal(
      forged.rawPolicySha256,
      sha256(Buffer.from(JSON.stringify(stable(forged.rawPolicyReceipt)))),
    );
    assert.equal(forged.rawPolicyWorkloadContentSha256, forged.workloadContentSha256);

    for (const command of ["verify", "activation-bundle"]) {
      const rejected = spawnSync("/bin/sh", [lockScript, fixture.lockPath, command], {
        encoding: "utf8",
        env: { ...process.env, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
      });
      assert.notEqual(rejected.status, 0, `${command} accepted foreign resource owners`);
      assert.match(rejected.stderr, /canonical ownership is invalid/);
    }
  } finally {
    removeFixtureTree(root);
  }
});

function createResolvedLock(root, workloads) {
  fs.mkdirSync(root, { recursive: true });
  fs.chmodSync(root, 0o700);
  const workloadRoot = path.join(root, "workloads");
  const catalogEntries = [];
  for (const workload of workloads) {
    const appRoot = path.join(workloadRoot, workload.id);
    fs.mkdirSync(appRoot, { recursive: true });
    fs.writeFileSync(path.join(appRoot, "manifest.json"), JSON.stringify({
      version: 1,
      id: workload.id,
      composeFile: "compose.yaml",
      secrets: workload.secretName ? [workload.secretName] : [],
      services: [{ name: workload.serviceName, role: "web" }],
    }));
    const serviceLines = [
      "services:",
      `  ${workload.serviceName}:`,
      `    image: example.invalid/${workload.id}@sha256:${digest}`,
      "    security_opt:",
      "      - no-new-privileges:true",
    ];
    if (workload.secretName) {
      serviceLines.push("    secrets:", `      - ${workload.secretName}`);
    }
    if (workload.volumeName) {
      serviceLines.push(
        "    volumes:",
        "      - type: volume",
        `        source: ${workload.volumeName}`,
        "        target: /data",
      );
    }
    if (workload.secretName) {
      serviceLines.push(
        "secrets:",
        `  ${workload.secretName}:`,
        "    external: true",
        `    name: fixture_${workload.secretName}`,
      );
    }
    if (workload.volumeName) {
      serviceLines.push("volumes:", `  ${workload.volumeName}: {}`);
    }
    fs.writeFileSync(path.join(appRoot, "compose.yaml"), `${serviceLines.join("\n")}\n`);
    const environmentPrefix = workload.id.toUpperCase().replaceAll("-", "_");
    fs.writeFileSync(path.join(appRoot, "workload.env"), `${environmentPrefix}_THEME=dark\n`);
    catalogEntries.push({
      manifest: `${workload.id}/manifest.json`,
      environmentFile: `${workload.id}/workload.env`,
    });
  }
  const catalogPath = path.join(root, "catalog.json");
  const coreEnvFile = path.join(root, "core.env");
  const coreFile = path.join(root, "compose.core.yaml");
  const lockPath = path.join(root, "hosted-workloads.lock.json");
  fs.writeFileSync(catalogPath, JSON.stringify({ version: 1, workloads: catalogEntries }));
  fs.writeFileSync(coreEnvFile, "CORE_VALUE=fixture\n", { mode: 0o600 });
  fs.chmodSync(coreEnvFile, 0o600);
  fs.writeFileSync(coreFile, [
    "services:",
    "  core-service: {}",
    "networks:",
    "  platform_routing: {}",
    "secrets:",
    "  platform-secret: {}",
    "volumes:",
    "  platform_data: {}",
    "configs:",
    "  platform_config: {}",
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
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(lockPath, 0o600);
  return { lockPath };
}

function validateRawAndReadBundle(lockPath) {
  const rawPolicy = spawnSync("ruby", [policyScript, "--lock", lockPath], { encoding: "utf8" });
  assert.equal(rawPolicy.status, 0, rawPolicy.stderr);
  const verify = spawnSync("/bin/sh", [lockScript, lockPath, "verify"], {
    encoding: "utf8",
    env: { ...process.env, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
  });
  assert.equal(verify.status, 0, verify.stderr);
  const bundle = spawnSync("/bin/sh", [lockScript, lockPath, "activation-bundle"], {
    encoding: "utf8",
    env: { ...process.env, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
  });
  assert.equal(bundle.status, 0, bundle.stderr);
  return JSON.parse(bundle.stdout);
}

function forgeNestedIdentity(lockPath, oldId, newId) {
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  const workload = lock.workloads.find((item) => item.id === oldId);
  assert.ok(workload);
  const oldServiceName = workload.services[0].name;
  const newServiceName = oldServiceName.replace(oldId, newId);
  workload.id = newId;
  workload.services[0].name = newServiceName;
  for (const record of workload.files) record.workloadId = newId;
  for (const record of lock.files) {
    if (record.workloadId === oldId) record.workloadId = newId;
  }

  fs.chmodSync(lock.snapshotGeneration, 0o700);
  const manifestRecord = lock.files.find((record) => record.kind === "workload-manifest" && record.workloadId === newId);
  const composeRecord = lock.files.find((record) => record.kind === "workload-compose" && record.workloadId === newId);
  const environmentRecord = lock.files.find((record) => record.kind === "workload-environment" && record.workloadId === newId);
  const manifest = JSON.parse(fs.readFileSync(manifestRecord.path, "utf8"));
  manifest.id = newId;
  manifest.services[0].name = newServiceName;
  rewriteSnapshotRecord(lock, workload, manifestRecord, Buffer.from(JSON.stringify(manifest)));
  rewriteSnapshotRecord(
    lock,
    workload,
    composeRecord,
    Buffer.from(fs.readFileSync(composeRecord.path, "utf8").replaceAll(oldServiceName, newServiceName)),
  );
  rewriteSnapshotRecord(
    lock,
    workload,
    environmentRecord,
    Buffer.from(fs.readFileSync(environmentRecord.path, "utf8").replaceAll(
      oldId.toUpperCase().replaceAll("-", "_"),
      newId.toUpperCase().replaceAll("-", "_"),
    )),
  );
  fs.chmodSync(lock.snapshotGeneration, 0o500);

  lock.workloadContentSha256 = workloadContentSha256(lock.files);
  lock.rawPolicyWorkloadContentSha256 = lock.workloadContentSha256;
  lock.rawPolicyReceipt.workloadContentSha256 = lock.workloadContentSha256;
  const receipt = lock.rawPolicyReceipt.workloads.find((item) => item.workloadId === oldId);
  receipt.workloadId = newId;
  receipt.serviceNames = [newServiceName];
  receipt.composeSha256 = composeRecord.sha256;
  lock.rawPolicyReceipt.workloads.sort((left, right) => left.workloadId.localeCompare(right.workloadId));
  lock.rawPolicySha256 = sha256(Buffer.from(JSON.stringify(stable(lock.rawPolicyReceipt))));
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(lockPath, 0o600);
}

function forgeForeignOwnedResources(lockPath) {
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  const workload = lock.workloads.find((item) => item.id === "billing");
  assert.ok(workload);
  const replacements = [
    ["billing-web", "billingapi-stolen-web"],
    ["billing-api-key", "billingapi-api-key"],
    ["billing_data", "billingapi_data"],
  ];
  workload.services[0].name = replacements[0][1];
  workload.secrets = [replacements[1][1]];

  fs.chmodSync(lock.snapshotGeneration, 0o700);
  const manifestRecord = lock.files.find((record) => record.kind === "workload-manifest" && record.workloadId === workload.id);
  const composeRecord = lock.files.find((record) => record.kind === "workload-compose" && record.workloadId === workload.id);
  const manifest = JSON.parse(fs.readFileSync(manifestRecord.path, "utf8"));
  manifest.services[0].name = replacements[0][1];
  manifest.secrets = [replacements[1][1]];
  rewriteSnapshotRecord(lock, workload, manifestRecord, Buffer.from(JSON.stringify(manifest)));
  let compose = fs.readFileSync(composeRecord.path, "utf8");
  for (const [before, after] of replacements) compose = compose.replaceAll(before, after);
  rewriteSnapshotRecord(lock, workload, composeRecord, Buffer.from(compose));
  fs.chmodSync(lock.snapshotGeneration, 0o500);

  lock.workloadContentSha256 = workloadContentSha256(lock.files);
  lock.rawPolicyWorkloadContentSha256 = lock.workloadContentSha256;
  lock.rawPolicyReceipt.workloadContentSha256 = lock.workloadContentSha256;
  const receipt = lock.rawPolicyReceipt.workloads.find((item) => item.workloadId === workload.id);
  receipt.serviceNames = [replacements[0][1]];
  receipt.secretNames = [replacements[1][1]];
  receipt.volumeNames = [replacements[2][1]];
  receipt.composeSha256 = composeRecord.sha256;
  lock.rawPolicySha256 = sha256(Buffer.from(JSON.stringify(stable(lock.rawPolicyReceipt))));
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(lockPath, 0o600);
}

function rewriteSnapshotRecord(lock, workload, record, bytes) {
  fs.chmodSync(record.path, 0o600);
  fs.writeFileSync(record.path, bytes);
  fs.chmodSync(record.path, 0o400);
  const digest = sha256(bytes);
  for (const candidate of [
    ...lock.files.filter((item) => item.path === record.path),
    ...workload.files.filter((item) => item.path === record.path),
  ]) {
    candidate.sha256 = digest;
    candidate.sizeBytes = bytes.length;
  }
}

function workloadContentSha256(records) {
  const content = records
    .filter((record) => record.snapshot === true)
    .map(({ kind, sourcePath, sha256: digestValue, sizeBytes, workloadId = null }) => ({
      kind,
      sourcePath,
      sha256: digestValue,
      sizeBytes,
      workloadId,
    }))
    .sort((left, right) => `${left.workloadId}:${left.kind}:${left.sourcePath}`
      .localeCompare(`${right.workloadId}:${right.kind}:${right.sourcePath}`));
  return sha256(Buffer.from(JSON.stringify(stable(content))));
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
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
