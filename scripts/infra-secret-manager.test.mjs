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
