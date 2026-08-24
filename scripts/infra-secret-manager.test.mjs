import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { assertNoPlaintextFingerprints } from "./secret-store-metadata.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const manager = path.join(here, "infra-secret-manager.mjs");

test("migrates plaintext-derived fingerprints and preserves timestamps without an oracle", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "secret-manager-metadata-"));
  const storePath = path.join(root, "store.json");
  const masterKeyPath = path.join(root, "master.key");
  const auditLogPath = path.join(root, "audit.jsonl");
  const valueFile = path.join(root, "value.txt");
  const baseArgs = ["--secretsDir", root, "--store", storePath, "--masterKey", masterKeyPath, "--auditLog", auditLogPath];
  const run = (command, args = [], expectSuccess = true) => {
    const result = spawnSync(process.execPath, [manager, command, ...baseArgs, ...args], { encoding: "utf8" });
    if (expectSuccess) assert.equal(result.status, 0, result.stderr);
    else assert.notEqual(result.status, 0, "command unexpectedly succeeded");
    return result;
  };
  try {
    run("init");
    fs.writeFileSync(valueFile, "0000\n", { mode: 0o600 });
    run("set", ["--name", "test_pin", "--valueFile", valueFile, "--minLength", "1"]);
    let store = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assertNoPlaintextFingerprints(store);
    const firstCiphertext = store.secrets.test_pin.encryption.ciphertext;
    store.secrets.test_pin.updatedAt = "2000-01-01T00:00:00.000Z";
    fs.writeFileSync(storePath, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 });

    run("set", ["--name", "test_pin", "--valueFile", valueFile, "--minLength", "1"]);
    store = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assert.equal(store.secrets.test_pin.updatedAt, "2000-01-01T00:00:00.000Z");
    assert.notEqual(store.secrets.test_pin.encryption.ciphertext, firstCiphertext);
    assertNoPlaintextFingerprints(store);
    const offlineOracle = crypto.createHash("sha256").update("0000").digest("hex").slice(0, 16);
    assert.equal(fs.readFileSync(storePath, "utf8").includes(offlineOracle), false);

    store.secrets.test_pin.fingerprint = offlineOracle;
    fs.writeFileSync(storePath, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 });
    assert.throws(() => assertNoPlaintextFingerprints(store, "metadata backup"), /before verification or export/);
    assert.match(run("verify", [], false).stderr, /migrate-metadata/);
    run("migrate-metadata");
    run("verify");
    const migrated = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assertNoPlaintextFingerprints(migrated);
    const status = run("status").stdout;
    assert.doesNotMatch(status, /fingerprint/i);
    assert.equal(status.includes(offlineOracle), false);

    fs.writeFileSync(valueFile, "0001\n", { mode: 0o600 });
    run("set", ["--name", "test_pin", "--valueFile", valueFile, "--minLength", "1"]);
    const rotated = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assert.notEqual(rotated.secrets.test_pin.updatedAt, "2000-01-01T00:00:00.000Z");
    assertNoPlaintextFingerprints(rotated);

    const infraOpsSource = fs.readFileSync(path.join(here, "infra-ops.mjs"), "utf8");
    assert.match(infraOpsSource, /assertNoPlaintextFingerprints\([^;]+"secret manager metadata backup"\)/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("preserves the existing app_db_password brownfield 0640 contract without making it core-required", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "secret-manager-app-db-mode-"));
  const storePath = path.join(root, "store.json");
  const masterKeyPath = path.join(root, "master.key");
  const auditLogPath = path.join(root, "audit.jsonl");
  const valueFile = path.join(root, "value.txt");
  const baseArgs = ["--secretsDir", root, "--store", storePath, "--masterKey", masterKeyPath, "--auditLog", auditLogPath];
  const run = (command, args = [], expectSuccess = true) => {
    const result = spawnSync(process.execPath, [manager, command, ...baseArgs, ...args], { encoding: "utf8" });
    if (expectSuccess) assert.equal(result.status, 0, result.stderr);
    else assert.notEqual(result.status, 0, "command unexpectedly succeeded");
    return result;
  };
  try {
    run("init");
    assert.equal(fs.existsSync(path.join(root, "app_db_password.txt")), false);
    fs.writeFileSync(valueFile, "brownfield_app_password_fixture_0123456789\n", { mode: 0o600 });
    run("set", ["--name", "app_db_password", "--valueFile", valueFile]);
    const materialized = path.join(root, "app_db_password.txt");
    assert.equal(fs.statSync(materialized).mode & 0o777, 0o640);
    const beforeBytes = fs.readFileSync(materialized);
    const before = fs.statSync(materialized);

    fs.chmodSync(materialized, 0o600);
    assert.match(run("verify", [], false).stderr, /mode mismatch.*app_db_password/i);
    fs.chmodSync(materialized, 0o640);
    run("init");
    run("verify");

    const after = fs.statSync(materialized);
    assert.deepEqual(fs.readFileSync(materialized), beforeBytes);
    assert.equal(after.ino, before.ino);
    assert.equal(after.uid, before.uid);
    assert.equal(after.gid, before.gid);
    assert.equal(after.mode & 0o777, 0o640);
    assert.equal(Object.hasOwn(JSON.parse(fs.readFileSync(storePath, "utf8")).secrets, "app_db_password"), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("read-only metadata probes never append persistent audit state, including on failure", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "secret-manager-read-only-"));
  const storePath = path.join(root, "store.json");
  const masterKeyPath = path.join(root, "master.key");
  const auditLogPath = path.join(root, "audit.jsonl");
  const baseArgs = ["--secretsDir", root, "--store", storePath, "--masterKey", masterKeyPath, "--auditLog", auditLogPath];
  const run = (command, args = []) => spawnSync(
    process.execPath,
    [manager, command, ...baseArgs, ...args],
    { encoding: "utf8" },
  );
  try {
    assert.equal(run("init").status, 0);
    const before = fs.readFileSync(auditLogPath);
    const fixed = new Date("2020-01-01T00:00:00.000Z");
    fs.utimesSync(auditLogPath, fixed, fixed);
    const beforeMtimeMs = fs.statSync(auditLogPath).mtimeMs;

    for (const command of ["status", "kms-status"]) {
      const result = run(command, ["--readOnly", "true"]);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(fs.readFileSync(auditLogPath), before);
      assert.equal(fs.statSync(auditLogPath).mtimeMs, beforeMtimeMs);
    }

    fs.renameSync(storePath, `${storePath}.unavailable`);
    for (const command of ["status", "kms-status"]) {
      const result = run(command, ["--readOnly", "true"]);
      assert.notEqual(result.status, 0, "missing-store read-only probe unexpectedly succeeded");
      assert.deepEqual(fs.readFileSync(auditLogPath), before);
      assert.equal(fs.statSync(auditLogPath).mtimeMs, beforeMtimeMs);
    }

    const rejected = run("verify", ["--readOnly", "true"]);
    assert.notEqual(rejected.status, 0, "mutating/audited command accepted --readOnly");
    assert.notDeepEqual(fs.readFileSync(auditLogPath), before);

    const infraOpsSource = fs.readFileSync(path.join(here, "infra-ops.mjs"), "utf8");
    assert.match(infraOpsSource, /\["--secretsDir", secretsRoot, "--readOnly", "true"\]/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("legacy raw backup signing material cannot cross the candidate-manager keyring guard", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "secret-manager-raw-keyring-"));
  const valueFile = path.join(root, "value.txt");
  const baseArgs = [
    "--secretsDir", root,
    "--store", path.join(root, "store.json"),
    "--masterKey", path.join(root, "master.key"),
    "--auditLog", path.join(root, "audit.jsonl"),
  ];
  const run = (command, args = []) => spawnSync(
    process.execPath,
    [manager, command, ...baseArgs, ...args],
    { encoding: "utf8" },
  );
  try {
    assert.equal(run("init").status, 0);
    fs.writeFileSync(valueFile, `${"r".repeat(64)}\n`, { mode: 0o600 });
    const rejected = run("set", ["--name", "backup_signing_keys", "--valueFile", valueFile]);
    assert.notEqual(rejected.status, 0, "raw signing material unexpectedly crossed the manager guard");
    assert.match(rejected.stderr, /Invalid keyring secret: backup_signing_keys/);
    assert.equal(run("verify").status, 0, "failed raw adoption changed the admitted manager state");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
