#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const [snapshotRoot, commit, tree] = process.argv.slice(2);
if (!snapshotRoot || !commit || !tree) {
  process.stderr.write("usage: node probe.mjs SNAPSHOT_ROOT COMMIT TREE\n");
  process.exit(2);
}

const lockScript = path.join(snapshotRoot, "scripts", "hosted-workload-lock.sh");
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-lock-fixture-"));

try {
  const workloadDir = path.join(tempRoot, "workload");
  fs.mkdirSync(workloadDir, { recursive: true });
  const composePath = path.join(workloadDir, "compose.platform.yaml");
  const replacementPath = path.join(workloadDir, "replacement.yaml");
  const symlinkTarget = path.join(workloadDir, "symlink-target.yaml");
  const lockPath = path.join(tempRoot, "hosted-workloads.lock.json");

  const approved = fixedPayload("APPROVED_LOCKED_BYTES", false);
  const unverified = fixedPayload("UNVERIFIED_ACTIVATION_BYTES", true);
  assert.equal(approved.length, unverified.length);
  fs.writeFileSync(symlinkTarget, unverified, { mode: 0o600 });

  const lock = {
    version: 1,
    state: "verified",
    files: [{
      kind: "workload-compose",
      path: composePath,
      sha256: sha256(approved),
      sizeBytes: approved.length,
    }],
    workloads: [{
      id: "demo-app",
      composePath,
      environmentPath: path.join(workloadDir, "workload.env"),
    }],
    coreEnvFile: path.join(tempRoot, "core.env"),
    projectName: "hosted_lock_probe",
  };
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(lockPath, 0o600);

  const commandEnvironment = verifierEnvironment(tempRoot);

  function resetApprovedFile() {
    fs.rmSync(composePath, { force: true });
    fs.writeFileSync(composePath, approved, { mode: 0o600 });
    fs.chmodSync(composePath, 0o600);
    assert.equal(sha256(fs.readFileSync(composePath)), lock.files[0].sha256);
    assert.equal(fs.lstatSync(composePath).isSymbolicLink(), false);
  }

  function invokeVerifier(command) {
    return spawnSync("sh", [lockScript, lockPath, command], {
      encoding: "utf8",
      env: commandEnvironment,
    });
  }

  function runScenario(label, swap, inspect) {
    resetApprovedFile();
    const before = fs.statSync(composePath);
    const checked = invokeVerifier("compose-files");
    assert.equal(checked.status, 0, checked.stderr);
    const emittedPath = checked.stdout.trim();
    assert.equal(emittedPath, composePath);

    swap();
    inspect(before);

    const reopened = fs.readFileSync(emittedPath);
    assert.equal(reopened.includes(Buffer.from("UNVERIFIED_ACTIVATION_BYTES")), true);
    assert.notEqual(sha256(reopened), lock.files[0].sha256);

    const afterUseVerification = invokeVerifier("verify");
    assert.notEqual(afterUseVerification.status, 0);
    process.stdout.write(`[+] ${label}: verified path reopened with unverified bytes\n`);
    process.stdout.write(`[+] ${label}: a later verification rejects the swapped source\n`);
  }

  runScenario(
    "in-place mutation",
    () => fs.writeFileSync(composePath, unverified),
    (before) => {
      const after = fs.statSync(composePath);
      assert.equal(after.ino, before.ino);
      assert.equal(after.size, before.size);
    },
  );

  runScenario(
    "atomic replacement",
    () => {
      fs.writeFileSync(replacementPath, unverified, { mode: 0o600 });
      fs.renameSync(replacementPath, composePath);
    },
    (before) => {
      const after = fs.statSync(composePath);
      assert.notEqual(after.ino, before.ino);
      assert.equal(after.size, before.size);
    },
  );

  runScenario(
    "symlink swap",
    () => {
      fs.unlinkSync(composePath);
      fs.symlinkSync(symlinkTarget, composePath);
    },
    () => assert.equal(fs.lstatSync(composePath).isSymbolicLink(), true),
  );

  process.stdout.write(`[+] revision: ${commit}\n`);
  process.stdout.write(`[+] tree: ${tree}\n`);
  process.stdout.write("[+] Docker/Compose invoked: NO\n");
  process.stdout.write("[+] result: VULNERABLE\n");
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

function fixedPayload(marker, hostile) {
  const source = hostile
    ? `# ${marker}\nservices:\n  demo-app-web:\n    image: example.invalid/demo@sha256:${"b".repeat(64)}\n    privileged: true\n`
    : `# ${marker}\nservices:\n  demo-app-web:\n    image: example.invalid/demo@sha256:${"a".repeat(64)}\n    read_only: true\n`;
  const size = 512;
  const buffer = Buffer.alloc(size, 0x20);
  const encoded = Buffer.from(source);
  assert.ok(encoded.length < size - 1);
  encoded.copy(buffer);
  buffer[size - 1] = 0x0a;
  return buffer;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function verifierEnvironment(root) {
  if (process.platform !== "darwin") return { ...process.env };
  const shimDirectory = path.join(root, "compat-bin");
  const statShim = path.join(shimDirectory, "stat");
  fs.mkdirSync(shimDirectory, { recursive: true });
  fs.writeFileSync(statShim, `#!/bin/sh\nif [ "$1" = "-c" ] && [ "$2" = "%a" ]; then\n  shift 2\n  exec /usr/bin/stat -f '%Lp' "$@"\nfi\nexec /usr/bin/stat "$@"\n`, { mode: 0o700 });
  fs.chmodSync(statShim, 0o700);
  return { ...process.env, PATH: `${shimDirectory}:${process.env.PATH ?? ""}` };
}

