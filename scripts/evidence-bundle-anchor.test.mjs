import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyClosedWorldBundleFiles, verifyOwnerPinnedBundleManifest } from "./evidence-bundle-anchor.mjs";

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("accepts exact manifest bytes against an independent owner pin", () => {
  const manifestBytes = Buffer.from('{"version":1,"entries":[]}\n');
  assert.deepEqual(verifyOwnerPinnedBundleManifest({ manifestBytes, expectedManifestSha256: digest(manifestBytes) }), {
    status: "passed",
    trustMode: "owner-pinned-manifest-sha256",
    manifestSha256: digest(manifestBytes),
  });
});

test("rejects missing pin, wrong trust anchor, and coordinated manifest rewrites", () => {
  const manifestBytes = Buffer.from('{"version":1,"entries":[{"path":"report.json","sha256":"a"}]}\n');
  const pinned = digest(manifestBytes);
  assert.throws(() => verifyOwnerPinnedBundleManifest({ manifestBytes }), /independently owner-pinned/);
  assert.throws(() => verifyOwnerPinnedBundleManifest({ manifestBytes, expectedManifestSha256: "b".repeat(64) }), /does not match/);
  const coordinatedRewrite = Buffer.from('{"version":1,"entries":[{"path":"report.json","sha256":"c"}]}\n');
  assert.throws(() => verifyOwnerPinnedBundleManifest({ manifestBytes: coordinatedRewrite, expectedManifestSha256: pinned }), /does not match/);
});

test("bundle verifier never accepts its internal manifest as a trust anchor", () => {
  const source = fs.readFileSync(path.join(import.meta.dirname, "infra-ops.mjs"), "utf8");
  const body = source.slice(source.indexOf("async function evidenceBundleVerify"), source.indexOf("async function vpsPreflight"));
  assert.match(body, /verifyOwnerPinnedBundleManifest/);
  assert.match(body, /verifyClosedWorldBundleFiles/);
  assert.match(body, /EXTERNAL-PENDING/);
  assert.doesNotMatch(body, /manifest\.(?:sha256|digest).*expectedManifest/i);
});

test("closed-world verification rejects an unlisted secret payload added after bundle creation", (t) => {
  const bundleDir = fs.mkdtempSync(path.join(os.tmpdir(), "evidence-bundle-closed-world-"));
  t.after(() => fs.rmSync(bundleDir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(bundleDir, "reports"));
  fs.writeFileSync(path.join(bundleDir, "manifest.json"), "{}\n");
  fs.writeFileSync(path.join(bundleDir, "manifest.md"), "# manifest\n");
  fs.writeFileSync(path.join(bundleDir, "summary.json"), "{}\n");
  fs.writeFileSync(path.join(bundleDir, "reports", "safe.json"), "{}\n");
  const expected = ["reports/safe.json"];
  assert.deepEqual(verifyClosedWorldBundleFiles({ bundleDir, manifestEntryPaths: expected }), {
    status: "passed",
    fileCount: 4,
    directoryCount: 1,
  });
  fs.writeFileSync(path.join(bundleDir, "unlisted-secret.txt"), "synthetic-secret-canary\n");
  assert.throws(
    () => verifyClosedWorldBundleFiles({ bundleDir, manifestEntryPaths: expected }),
    /unexpected bundle path: unlisted-secret\.txt/,
  );
});
