import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createBackupJobDocument, createBackupManifestDocument } from "../control-center/backup/contracts.mjs";
import { evaluateOffsiteRestoreCoverage, offsiteManifestTags, validateOffsiteRestoreSet } from "./offsite-restore-contract.mjs";

const resources = [
  { id: "source:alpha", externalId: "alpha", kind: "source", projectId: "alpha", name: "alpha", sourceDirectory: "alpha" },
  { id: "database:alpha-db", externalId: "alpha-db", kind: "database", projectId: "alpha", name: "alpha_db", engine: "postgres" },
  { id: "platform-state:control-center-state", externalId: "control-center-state", kind: "platform-state", projectId: "platform", name: "control-center-state" },
];
const job = createBackupJobDocument({ id: "job-1", operation: "backup", scope: { kind: "platform", id: "platform" }, resources, requestedBy: "test", environment: "test" });
const unsigned = createBackupManifestDocument({
  id: "manifest-1",
  job,
  artifacts: resources.map((resource, index) => ({ id: `artifact-${index}`, resourceId: resource.id, path: `family/artifact-${index}.dump`, sha256: String(index + 1).repeat(64), sizeBytes: 10 + index, signatureKeyId: "test-key" })),
});
const manifest = { ...unsigned, signature: { algorithm: "HMAC-SHA256", keyId: "test-key", digest: "d".repeat(64), value: "signature" } };
const manifestPath = "/backups/manifests/manifest-1.json";
const exactPaths = [manifestPath, ...manifest.artifacts.flatMap((artifact) => [`/backups/${artifact.path}`, `/backups/${artifact.path}.sha256`, `/backups/${artifact.path}.sig.json`])];
const tags = offsiteManifestTags(manifest);

test("accepts the exact signed manifest resource and artifact set", () => {
  const result = validateOffsiteRestoreSet({ manifest, snapshotPaths: exactPaths, restoredPaths: [...exactPaths].reverse(), snapshotTags: tags });
  assert.deepEqual(result.resourceIds, resources.map((resource) => resource.id));
  assert.equal(result.expectedPaths.length, exactPaths.length);
});

test("rejects missing, extra, substituted, duplicate, unsigned, and wrong-tag sets", () => {
  assert.throws(() => validateOffsiteRestoreSet({ manifest, snapshotPaths: exactPaths.slice(1), restoredPaths: exactPaths, snapshotTags: tags }), /exactly one backup manifest/);
  assert.throws(() => validateOffsiteRestoreSet({ manifest, snapshotPaths: [...exactPaths, "/backups/extra.dump"], restoredPaths: exactPaths, snapshotTags: tags }), /extra=/);
  assert.throws(() => validateOffsiteRestoreSet({ manifest, snapshotPaths: exactPaths, restoredPaths: [...exactPaths.slice(0, -1), "/backups/substitute.sig.json"], snapshotTags: tags }), /missing=.*extra=/);
  assert.throws(() => validateOffsiteRestoreSet({ manifest, snapshotPaths: [...exactPaths, exactPaths[0]], restoredPaths: exactPaths, snapshotTags: tags }), /duplicate/);
  assert.throws(() => validateOffsiteRestoreSet({ manifest: unsigned, snapshotPaths: exactPaths, restoredPaths: exactPaths, snapshotTags: tags }), /unsigned/);
  assert.throws(() => validateOffsiteRestoreSet({ manifest, snapshotPaths: exactPaths, restoredPaths: exactPaths, snapshotTags: [`platform-manifest-id=wrong`, tags[1]] }), /do not match/);
});

test("rejects a manifest whose artifact belongs to the wrong resource", () => {
  const wrong = { ...manifest, artifacts: [{ ...manifest.artifacts[0], resourceId: "database:foreign" }, ...manifest.artifacts.slice(1)] };
  assert.throws(() => validateOffsiteRestoreSet({ manifest: wrong, snapshotPaths: exactPaths, restoredPaths: exactPaths, snapshotTags: tags }), /undeclared resource/);
});

test("off-site implementation restores every typed resource and disables partial family discovery", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const source = fs.readFileSync(path.join(here, "infra-ops.mjs"), "utf8");
  assert.match(source, /offsiteManifestTags\(manifest\)/);
  assert.match(source, /validateOffsiteRestoreSet\(\{/);
  assert.match(source, /for \(const resource of stagedManifest\.resources\)/);
  assert.match(source, /executeTypedRestoreResource\(resource, artifact, \{ backupRoot: stagingRoot \}\)/);
  assert.match(source, /Partial off-site restore cannot produce trustworthy coverage and is disabled/);
  assert.doesNotMatch(source, /discoverRestoredBackupArtifacts/);
});

test("coverage is fail-closed unless every resource, exact set, signature, and health proof pass", () => {
  const payload = {
    mode: "restore",
    status: "success",
    allowPartial: false,
    exactSetVerified: true,
    manifest: { signatureVerified: true, resourceIds: ["source:alpha", "database:alpha-db"] },
    steps: [
      { resourceId: "source:alpha", status: "success" },
      { resourceId: "database:alpha-db", status: "success" },
      { name: "infra-health", status: "success" },
    ],
  };
  assert.equal(evaluateOffsiteRestoreCoverage(payload).complete, true);
  for (const mutation of [
    { exactSetVerified: false },
    { manifest: { ...payload.manifest, signatureVerified: false } },
    { allowPartial: true },
    { steps: payload.steps.slice(0, 2) },
    { steps: [payload.steps[0], payload.steps[2]] },
  ]) assert.equal(evaluateOffsiteRestoreCoverage({ ...payload, ...mutation }).complete, false);
});
