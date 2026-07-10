import assert from "node:assert/strict";
import test from "node:test";
import {
  BACKUP_JOB_SCHEMA,
  BACKUP_MANIFEST_SCHEMA,
  backupDocumentDigest,
  backupResourceId,
  createBackupJobDocument,
  createBackupManifestDocument,
  manifestArtifactForResource,
  manifestResourcesForProject,
  parseBackupJobDocument,
  parseBackupManifestDocument,
} from "../backup/contracts.mjs";

const sourceResource = (projectId) => ({
  id: backupResourceId("source", projectId),
  externalId: projectId,
  kind: "source",
  projectId,
  name: projectId,
  sourceDirectory: projectId,
});

const databaseResource = (projectId, externalId, name, engine = "postgres") => ({
  id: backupResourceId("database", externalId),
  externalId,
  kind: "database",
  projectId,
  name,
  engine,
});

function job(resources, projectId = "stream") {
  return createBackupJobDocument({
    id: "job-20260710-001",
    operation: "backup",
    scope: { kind: "application", id: projectId },
    resources,
    requestedBy: "operator@example.test",
    environment: "sandbox",
    createdAt: "2026-07-10T10:00:00.000Z",
  });
}

function artifact(resourceId, suffix) {
  return {
    id: `artifact-${suffix}`,
    resourceId,
    path: `postgres/${suffix}.dump`,
    sha256: "a".repeat(64),
    sizeBytes: 4096,
    signatureKeyId: "backup-key-2026-01",
  };
}

test("typed job rejects cross-project and duplicate resources", () => {
  assert.throws(() => job([sourceResource("streaming")]), /another project/);
  assert.throws(() => job([sourceResource("stream"), sourceResource("stream")]), /Duplicate backup resource ID/);
});

test("typed job rejects caller-controlled commands and unsafe restore paths", () => {
  const document = job([sourceResource("stream")]);
  assert.equal(document.schema, BACKUP_JOB_SCHEMA);
  assert.equal("commands" in document, false);
  assert.throws(() => createBackupJobDocument({
    ...document,
    operation: "restore-drill",
    sourceManifestPath: "../foreign.json",
  }), /Invalid source manifest path|under manifests/);
});

test("manifest requires exact one-to-one resource coverage", () => {
  const resources = [
    sourceResource("stream"),
    databaseResource("stream", "stream-postgres", "stream"),
  ];
  const document = job(resources);
  const incomplete = createBackupManifestDocument({
    id: "manifest-stream-incomplete",
    job: document,
    artifacts: [artifact(resources[0].id, "source")],
  });
  assert.equal(incomplete.coverage.complete, false);
  assert.throws(() => parseBackupManifestDocument({
    ...incomplete,
    signature: {
      algorithm: "HMAC-SHA256",
      keyId: "backup-key-2026-01",
      digest: backupDocumentDigest(incomplete),
      value: "c2lnbmF0dXJl",
    },
  }), /coverage is incomplete/);

  const manifest = createBackupManifestDocument({
    id: "manifest-stream-complete",
    job: document,
    artifacts: [artifact(resources[0].id, "source"), artifact(resources[1].id, "database")],
    createdAt: "2026-07-10T10:05:00.000Z",
  });
  assert.equal(manifest.schema, BACKUP_MANIFEST_SCHEMA);
  assert.equal(manifest.coverage.complete, true);
  assert.deepEqual(manifest.coverage.missingResourceIds, []);
});

test("similarly named projects never match by substring", () => {
  const resource = databaseResource("stream", "stream-postgres", "stream");
  const document = job([resource]);
  const base = createBackupManifestDocument({
    id: "manifest-stream-exact",
    job: document,
    artifacts: [artifact(resource.id, "stream")],
    createdAt: "2026-07-10T10:05:00.000Z",
  });
  const digest = backupDocumentDigest(base);
  const signed = {
    ...base,
    signature: {
      algorithm: "HMAC-SHA256",
      keyId: "backup-key-2026-01",
      digest,
      value: "c2lnbmF0dXJl",
    },
  };
  assert.equal(manifestResourcesForProject(signed, "stream").length, 1);
  assert.equal(manifestResourcesForProject(signed, "streaming").length, 0);
  assert.equal(manifestArtifactForResource(signed, resource.id)?.path, "postgres/stream.dump");
});

test("manifest import rejects undeclared artifacts and tampered metadata", () => {
  const resource = databaseResource("stream", "stream-postgres", "stream");
  const document = job([resource]);
  assert.throws(() => createBackupManifestDocument({
    id: "manifest-stream-foreign",
    job: document,
    artifacts: [artifact("database:workcalendar", "foreign")],
  }), /undeclared resource/);

  const manifest = createBackupManifestDocument({
    id: "manifest-stream-valid",
    job: document,
    artifacts: [artifact(resource.id, "stream")],
    createdAt: "2026-07-10T10:05:00.000Z",
  });
  const signed = {
    ...manifest,
    signature: {
      algorithm: "HMAC-SHA256",
      keyId: "backup-key-2026-01",
      digest: backupDocumentDigest(manifest),
      value: "c2lnbmF0dXJl",
    },
  };
  assert.equal(parseBackupManifestDocument(signed).signature.digest, backupDocumentDigest(manifest));
  assert.throws(() => parseBackupManifestDocument({ ...signed, schema: "legacy/v0" }), /Unsupported backup manifest schema/);
});

test("job parser rejects legacy global command queues", () => {
  assert.throws(() => parseBackupJobDocument({
    schema: BACKUP_JOB_SCHEMA,
    id: "legacy-global-job",
    action: "backup",
    scope: "app-stream",
    commands: [{ command: "backup-postgres" }],
    status: "queued",
  }), /Invalid backup operation/);
});
