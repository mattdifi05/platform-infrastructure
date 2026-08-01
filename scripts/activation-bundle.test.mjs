#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ACTIVATION_BUNDLE_ENTRY_LIMITS,
  ACTIVATION_BUNDLE_MAGIC,
  buildActivationBundle,
  exactNoHostedLockBytes,
  validateActivationBundleManifest,
} from "./activation-bundle.mjs";

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "activation-bundle-test."));
try {
  const names = Object.keys(ACTIVATION_BUNDLE_ENTRY_LIMITS).sort();
  const entryPaths = {};
  const expectedEntryHashes = {};
  for (const name of names) {
    const bytes = name === "hosted-workloads.lock.json"
      ? exactNoHostedLockBytes()
      : Buffer.from(`${name}\n`, "utf8");
    const filename = path.join(temporary, name);
    fs.writeFileSync(filename, bytes, { flag: "wx", mode: 0o600 });
    entryPaths[name] = filename;
    expectedEntryHashes[name] = crypto.createHash("sha256").update(bytes).digest("hex");
  }
  const deploymentReceiptSha256 = "a".repeat(64);
  const releaseContextSha256 = "b".repeat(64);
  const requestId = `activation:${deploymentReceiptSha256}:${releaseContextSha256}`;
  const runtimeIntentSha256 = "c".repeat(64);
  const outputPath = path.join(temporary, "activation.bundle");
  const manifestOutputPath = path.join(temporary, "manifest.json");
  const result = buildActivationBundle({
    outputPath,
    manifestOutputPath,
    requestId,
    releaseContextSha256,
    runtimeIntentSha256,
    entryPaths,
    expectedEntryHashes,
  });

  assert.equal(result.schema, "platform-activation-bundle-descriptor/v1");
  assert.match(result.sha256, /^[a-f0-9]{64}$/);
  assert.match(result.manifestSha256, /^[a-f0-9]{64}$/);
  assert.equal(result.sizeBytes, fs.statSync(outputPath).size);
  assert.deepEqual(result.manifest.entries.map(({ name }) => name), names);
  assert.equal(
    crypto.createHash("sha256").update(fs.readFileSync(outputPath)).digest("hex"),
    result.sha256,
  );
  const bundle = fs.readFileSync(outputPath);
  assert.ok(bundle.subarray(0, ACTIVATION_BUNDLE_MAGIC.length).equals(ACTIVATION_BUNDLE_MAGIC));
  const manifestLength = Number(bundle.readBigUInt64BE(ACTIVATION_BUNDLE_MAGIC.length));
  const manifestStart = ACTIVATION_BUNDLE_MAGIC.length + 8;
  assert.equal(
    bundle.subarray(manifestStart, manifestStart + manifestLength).toString("utf8"),
    JSON.stringify(JSON.parse(fs.readFileSync(manifestOutputPath, "utf8"))),
  );
  assert.equal(
    validateActivationBundleManifest(result.manifest, {
      requestId,
      releaseContextSha256,
      runtimeIntentSha256,
      expectedEntryHashes,
    }).sha256,
    result.manifestSha256,
  );

  assert.throws(() => validateActivationBundleManifest({
    ...result.manifest,
    entries: result.manifest.entries.slice().reverse(),
  }), /sorted fixed names/);
  assert.throws(() => validateActivationBundleManifest({
    ...result.manifest,
    entries: result.manifest.entries.map((entry) => (
      entry.name === "environment.env" ? { ...entry, sha256: "d".repeat(64) } : entry
    )),
  }, { expectedEntryHashes }), /hash-bound/);
  assert.throws(() => buildActivationBundle({
    outputPath: path.join(temporary, "missing.bundle"),
    manifestOutputPath: path.join(temporary, "missing.json"),
    requestId,
    releaseContextSha256,
    runtimeIntentSha256,
    entryPaths: Object.fromEntries(Object.entries(entryPaths).slice(1)),
  }), /exact fixed entry set/);
  assert.throws(() => buildActivationBundle({
    outputPath: path.join(temporary, "tampered.bundle"),
    manifestOutputPath: path.join(temporary, "tampered.json"),
    requestId,
    releaseContextSha256,
    runtimeIntentSha256,
    entryPaths,
    expectedEntryHashes: { "environment.env": "e".repeat(64) },
  }), /differs from its admitted SHA256/);

  process.stdout.write("activation bundle tests passed 14/14\n");
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
