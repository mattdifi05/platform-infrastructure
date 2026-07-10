#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  backupDocumentDigest,
  backupResourceId,
  createBackupJobDocument,
  createBackupManifestDocument,
} from "../backup/contracts.mjs";

const root = path.resolve(process.env.FIXTURE_ROOT || "/fixture");
const backupRoot = path.join(root, "backups");
const reportsRoot = path.join(root, "reports");
const projectId = "node-demo";
const createdAt = new Date(Date.now() - 30_000).toISOString();
const keyId = "sandbox-delete-v1";

const specifications = [
  {
    id: process.env.MARIADB_ID,
    engine: "mariadb",
    name: process.env.MARIADB_DATABASE,
    artifactPath: path.join("mariadb", `${process.env.MARIADB_ID}.sql.gz`),
  },
  {
    id: process.env.POSTGRES_ID,
    engine: "postgres",
    name: process.env.POSTGRES_DATABASE,
    artifactPath: path.join("postgres", `${process.env.POSTGRES_ID}.dump`),
  },
];

const resources = [];
const artifacts = [];
for (const [index, specification] of specifications.entries()) {
  if (!specification.id || !specification.name) throw new Error("Database evidence fixture identity is incomplete.");
  const resourceId = backupResourceId("database", specification.id);
  const resource = {
    id: resourceId,
    externalId: specification.id,
    kind: "database",
    projectId,
    name: specification.name,
    engine: specification.engine,
  };
  const artifactFile = path.join(backupRoot, specification.artifactPath);
  const bytes = readFileSync(artifactFile);
  const hash = createHash("sha256").update(bytes).digest("hex");
  writeFileSync(`${artifactFile}.sha256`, `${hash}  ${path.basename(artifactFile)}\n`, { mode: 0o600 });
  writeFileSync(`${artifactFile}.sig.json`, `${JSON.stringify({ algorithm: "HMAC-SHA256", keyId, hash, signature: "sandbox-delete-signature" })}\n`, { mode: 0o600 });
  resources.push(resource);
  artifacts.push({
    id: `artifact-delete-${index}-${hash.slice(0, 12)}`,
    resourceId,
    path: specification.artifactPath.replaceAll("\\", "/"),
    sha256: hash,
    sizeBytes: bytes.length,
    signatureKeyId: keyId,
  });
}

const job = createBackupJobDocument({
  id: "sandbox-delete-backup",
  operation: "backup",
  scope: { kind: "application", id: projectId },
  resources,
  requestedBy: "sandbox-delete-test",
  environment: "sandbox",
  createdAt,
});
const unsigned = createBackupManifestDocument({ id: "manifest-sandbox-delete", job, artifacts, createdAt });
const manifest = {
  ...unsigned,
  signature: {
    algorithm: "HMAC-SHA256",
    keyId,
    digest: backupDocumentDigest(unsigned),
    value: "c2FuZGJveC1kZWxldGUtc2lnbmF0dXJl",
  },
};
const manifestPath = "manifests/manifest-sandbox-delete.json";
mkdirSync(path.join(backupRoot, "manifests"), { recursive: true, mode: 0o700 });
mkdirSync(path.join(reportsRoot, "backup-jobs"), { recursive: true, mode: 0o700 });
mkdirSync(path.join(reportsRoot, "offsite-backups"), { recursive: true, mode: 0o700 });
writeFileSync(path.join(backupRoot, manifestPath), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
const resourceIds = resources.map((resource) => resource.id);
writeFileSync(path.join(reportsRoot, "backup-jobs", "restore-sandbox-delete.json"), `${JSON.stringify({
  status: "passed",
  operation: "restore-drill",
  jobId: "sandbox-delete-restore",
  manifestPath,
  resourceIds,
  results: resourceIds.map((resourceId) => ({ resourceId, status: "passed" })),
  liveDataChanged: false,
  finishedAt: new Date(Date.parse(createdAt) + 10_000).toISOString(),
}, null, 2)}\n`, { mode: 0o600 });
writeFileSync(path.join(reportsRoot, "offsite-backups", "offsite-sandbox-delete.json"), `${JSON.stringify({
  schema: "platform.offsite-backup-receipt/v1",
  status: "passed",
  manifestId: manifest.id,
  manifestPath,
  manifestDigest: manifest.signature.digest,
  resourceIds,
  snapshotId: "sandbox-delete-snapshot",
  hostname: "platform-infrastructure",
  repositoryOffsite: true,
  finishedAt: new Date(Date.parse(createdAt) + 20_000).toISOString(),
}, null, 2)}\n`, { mode: 0o600 });

process.stdout.write(`${JSON.stringify({ status: "passed", manifestId: manifest.id, resourceIds })}\n`);
