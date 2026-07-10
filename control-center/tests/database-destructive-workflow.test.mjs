import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import {
  backupDocumentDigest,
  backupResourceId,
  createBackupJobDocument,
  createBackupManifestDocument,
} from "../backup/contracts.mjs";
import {
  createDatabaseDeleteOperation,
  databaseDeleteConfirmation,
  findDatabaseDeleteRestorePoint,
  transitionDatabaseDeleteOperation,
} from "../database/destructive-workflow.mjs";

const database = {
  id: "demo-mariadb-demo-app",
  projectId: "demo",
  engine: "mariadb",
  name: "demo_app",
  ownerRole: "pi_m_demo_123456789abc",
  principalBindingId: "demo-mariadb-demo-app",
  credentialFile: "/var/www/project-state/database-credentials/demo-mariadb-demo-app.txt",
};

function fixture({ ageMs = 60_000, wrongOffsiteResource = false } = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), "platform-t05-delete-"));
  const backupRoot = path.join(root, "backups");
  const reportsRoot = path.join(root, "reports");
  const artifactDirectory = path.join(backupRoot, "mariadb", "demo");
  const manifestDirectory = path.join(backupRoot, "manifests");
  const restoreDirectory = path.join(reportsRoot, "backup-jobs");
  const offsiteDirectory = path.join(reportsRoot, "offsite-backups");
  for (const directory of [artifactDirectory, manifestDirectory, restoreDirectory, offsiteDirectory]) mkdirSync(directory, { recursive: true });
  const now = new Date("2026-07-10T12:00:00.000Z");
  const createdAt = new Date(now.getTime() - ageMs).toISOString();
  const resourceId = backupResourceId("database", database.id);
  const resource = { id: resourceId, externalId: database.id, kind: "database", projectId: database.projectId, name: database.name, engine: database.engine };
  const artifactPath = path.join(artifactDirectory, "demo.sql.gz");
  writeFileSync(artifactPath, "fixture database backup\n", { mode: 0o600 });
  const hash = createHash("sha256").update(readFileSync(artifactPath)).digest("hex");
  writeFileSync(`${artifactPath}.sha256`, `${hash}  demo.sql.gz\n`, { mode: 0o600 });
  writeFileSync(`${artifactPath}.sig.json`, `${JSON.stringify({ algorithm: "HMAC-SHA256", keyId: "fixture-v1", hash, signature: "fixture-signature" })}\n`, { mode: 0o600 });
  const job = createBackupJobDocument({ id: "delete-fixture-backup", operation: "backup", scope: { kind: "application", id: database.projectId }, resources: [resource], requestedBy: "fixture", environment: "sandbox", createdAt });
  const unsigned = createBackupManifestDocument({
    id: "manifest-delete-fixture",
    job: { ...job, status: "done" },
    artifacts: [{ id: `artifact-${hash.slice(0, 12)}`, resourceId, path: path.relative(backupRoot, artifactPath).replaceAll("\\", "/"), sha256: hash, sizeBytes: Buffer.byteLength("fixture database backup\n"), signatureKeyId: "fixture-v1" }],
    createdAt,
  });
  const manifest = {
    ...unsigned,
    signature: { algorithm: "HMAC-SHA256", keyId: "fixture-v1", digest: backupDocumentDigest(unsigned), value: "fixture-signature-value" },
  };
  const manifestPath = path.join(manifestDirectory, "manifest-delete-fixture.json");
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  const relativeManifest = "manifests/manifest-delete-fixture.json";
  const restoreFinishedAt = new Date(Date.parse(createdAt) + 10_000).toISOString();
  writeFileSync(path.join(restoreDirectory, "restore.json"), `${JSON.stringify({
    status: "passed",
    operation: "restore-drill",
    jobId: "delete-fixture-restore",
    manifestPath: relativeManifest,
    resourceIds: [resourceId],
    results: [{ resourceId, status: "passed" }],
    liveDataChanged: false,
    finishedAt: restoreFinishedAt,
  }, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(path.join(offsiteDirectory, "offsite.json"), `${JSON.stringify({
    schema: "platform.offsite-backup-receipt/v1",
    status: "passed",
    manifestId: manifest.id,
    manifestPath: relativeManifest,
    manifestDigest: manifest.signature.digest,
    resourceIds: [wrongOffsiteResource ? "database:foreign" : resourceId],
    snapshotId: "snapshot-fixture-123",
    hostname: "platform-infrastructure",
    repositoryOffsite: true,
    finishedAt: new Date(Date.parse(createdAt) + 20_000).toISOString(),
  }, null, 2)}\n`, { mode: 0o600 });
  return { root, backupRoot, reportsRoot, now, artifactPath };
}

test("database delete evidence requires exact fresh backup, restore and off-site receipt", () => {
  const readyFixture = fixture();
  const wrongFixture = fixture({ wrongOffsiteResource: true });
  const staleFixture = fixture({ ageMs: 48 * 60 * 60 * 1000 });
  try {
    const ready = findDatabaseDeleteRestorePoint({ database, backupRoot: readyFixture.backupRoot, reportsRoot: readyFixture.reportsRoot, now: readyFixture.now, maxAgeMs: 24 * 60 * 60 * 1000 });
    assert.equal(ready.ready, true);
    assert.equal(ready.evidence.resourceId, `database:${database.id}`);
    assert.equal(ready.evidence.offsiteReceipt.snapshotId, "snapshot-fixture-123");
    assert.equal(ready.evidence.manifest.artifactSha256.length, 64);

    const wrong = findDatabaseDeleteRestorePoint({ database, backupRoot: wrongFixture.backupRoot, reportsRoot: wrongFixture.reportsRoot, now: wrongFixture.now, maxAgeMs: 24 * 60 * 60 * 1000 });
    assert.equal(wrong.ready, false);
    assert.deepEqual(wrong.blockers, ["fresh-exact-offsite-receipt-missing"]);

    const stale = findDatabaseDeleteRestorePoint({ database, backupRoot: staleFixture.backupRoot, reportsRoot: staleFixture.reportsRoot, now: staleFixture.now, maxAgeMs: 24 * 60 * 60 * 1000 });
    assert.equal(stale.ready, false);
    assert.ok(stale.blockers.includes("fresh-exact-backup-manifest-missing"));

    const artifactSize = readFileSync(readyFixture.artifactPath).length;
    writeFileSync(readyFixture.artifactPath, Buffer.alloc(artifactSize, "x"), { mode: 0o600 });
    const tampered = findDatabaseDeleteRestorePoint({ database, backupRoot: readyFixture.backupRoot, reportsRoot: readyFixture.reportsRoot, now: readyFixture.now, maxAgeMs: 24 * 60 * 60 * 1000 });
    assert.equal(tampered.ready, false);
    assert.ok(tampered.blockers.includes("fresh-exact-backup-manifest-missing"));
  } finally {
    for (const item of [readyFixture, wrongFixture, staleFixture]) rmSync(item.root, { recursive: true, force: true });
  }
});

test("database delete state machine is explicit, idempotent at terminal states and fail-closed", () => {
  const evidenceFixture = fixture();
  try {
    const restorePoint = findDatabaseDeleteRestorePoint({ database, backupRoot: evidenceFixture.backupRoot, reportsRoot: evidenceFixture.reportsRoot, now: evidenceFixture.now });
    let operation = createDatabaseDeleteOperation({ id: "delete-operation-1", database, evidence: restorePoint.evidence, idempotencyKey: "request-1", requestedBy: "owner@example.test", now: evidenceFixture.now });
    assert.equal(operation.status, "evidence-verified");
    operation = transitionDatabaseDeleteOperation(operation, "approved", { approvedBy: "owner@example.test" }, evidenceFixture.now);
    assert.equal(operation.status, "approved");
    operation = transitionDatabaseDeleteOperation(operation, "executing", {}, evidenceFixture.now);
    assert.equal(operation.execution.attempts, 1);
    assert.throws(() => transitionDatabaseDeleteOperation(operation, "completed", {}, evidenceFixture.now), /Invalid database delete transition/);
    operation = transitionDatabaseDeleteOperation(operation, "database-dropped", {}, evidenceFixture.now);
    operation = transitionDatabaseDeleteOperation(operation, "rollback-required", { failure: "fixture cleanup failure" }, evidenceFixture.now);
    assert.equal(operation.status, "rollback-required");
    assert.throws(() => transitionDatabaseDeleteOperation(operation, "executing", {}, evidenceFixture.now), /Invalid database delete transition/);
    assert.equal(databaseDeleteConfirmation(database, "REQUEST"), `REQUEST-DATABASE-DELETE:${database.id}`);
    assert.equal(databaseDeleteConfirmation(database, "EXECUTE", operation.id), `EXECUTE-DATABASE-DELETE:${operation.id}`);
  } finally {
    rmSync(evidenceFixture.root, { recursive: true, force: true });
  }
});
