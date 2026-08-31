#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { publishBackupArtifact } from "./backup-artifact-publication.mjs";

const artifactA = Buffer.from("immutable-backup-artifact-A\n".repeat(128));
const artifactB = Buffer.from("swapped-backup-artifact-B\n".repeat(128));

function signatureFactory({ artifactName, sha256 }) {
  return {
    keyId: "synthetic-key",
    document: {
      version: 1,
      algorithm: "HMAC-SHA256",
      keyId: "synthetic-key",
      artifact: artifactName,
      sha256,
      signature: crypto.createHash("sha256").update(`synthetic:${artifactName}:${sha256}`).digest("base64url"),
      signedAt: "2026-07-22T00:00:00.000Z",
    },
  };
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "backup-publication-"));
  const stagingPath = path.join(root, ".database.dump.staging-synthetic");
  const publishedPath = path.join(root, "database.dump");
  fs.writeFileSync(stagingPath, artifactA, { mode: 0o600 });
  return { root, stagingPath, publishedPath };
}

test("publishes and reports the exact bytes held by the immutable artifact descriptor", () => {
  const paths = fixture();
  let publication;
  try {
    publication = publishBackupArtifact({ ...paths, createSignature: signatureFactory });
    const report = { artifactSha256: publication.hash, artifactSizeBytes: publication.sizeBytes };
    publication.assertCurrent();
    assert.deepEqual(fs.readFileSync(paths.publishedPath), artifactA);
    assert.equal(report.artifactSha256, crypto.createHash("sha256").update(artifactA).digest("hex"));
    assert.equal(report.artifactSizeBytes, artifactA.length);
    assert.match(fs.readFileSync(`${paths.publishedPath}.sha256`, "utf8"), new RegExp(`^${report.artifactSha256}  database\\.dump\\n$`));
    assert.equal(JSON.parse(fs.readFileSync(`${paths.publishedPath}.sig.json`, "utf8")).sha256, report.artifactSha256);
  } finally {
    publication?.close();
    fs.rmSync(paths.root, { recursive: true, force: true });
  }
});

test("dump A to B swap after checksum staging is rejected before signing or reporting", () => {
  const paths = fixture();
  const movedA = path.join(paths.root, "moved-A.dump");
  let signed = false;
  let reported = false;
  try {
    assert.throws(() => publishBackupArtifact({
      ...paths,
      createSignature(input) {
        signed = true;
        return signatureFactory(input);
      },
      onChecksumStaged() {
        fs.renameSync(paths.stagingPath, movedA);
        fs.writeFileSync(paths.stagingPath, artifactB, { mode: 0o600 });
      },
      onPublished() {
        reported = true;
      },
    }), /staging artifact changed/i);
    assert.equal(signed, false);
    assert.equal(reported, false);
    assert.equal(fs.existsSync(paths.publishedPath), false);
    assert.equal(fs.existsSync(`${paths.publishedPath}.sha256`), false);
    assert.equal(fs.existsSync(`${paths.publishedPath}.sig.json`), false);
  } finally {
    fs.rmSync(paths.root, { recursive: true, force: true });
  }
});

test("a published-path swap cannot be promoted to a success report", () => {
  const paths = fixture();
  const movedA = path.join(paths.root, "published-A.dump");
  let publication;
  let reported = false;
  try {
    publication = publishBackupArtifact({ ...paths, createSignature: signatureFactory });
    fs.renameSync(paths.publishedPath, movedA);
    fs.writeFileSync(paths.publishedPath, artifactB, { mode: 0o400 });
    assert.throws(() => {
      publication.assertCurrent();
      reported = true;
    }, /published artifact changed/i);
    assert.equal(reported, false);
  } finally {
    publication?.close();
    fs.rmSync(paths.root, { recursive: true, force: true });
  }
});

test("an explicitly admitted private staging directory publishes by immutable cross-directory links", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "backup-publication-private-"));
  const stagingDirectory = path.join(root, "broker-only-staging");
  const publishedDirectory = path.join(root, "shared-backups");
  fs.mkdirSync(stagingDirectory, { mode: 0o700 });
  fs.mkdirSync(publishedDirectory, { mode: 0o700 });
  const stagingPath = path.join(stagingDirectory, ".database.dump.staging-synthetic");
  const publishedPath = path.join(publishedDirectory, "database.dump");
  fs.writeFileSync(stagingPath, artifactA, { mode: 0o600 });
  let publication;
  try {
    assert.throws(() => publishBackupArtifact({ stagingPath, publishedPath, createSignature: signatureFactory }), /explicitly admitted/i);
    publication = publishBackupArtifact({
      stagingPath,
      publishedPath,
      allowSeparateStagingDirectory: true,
      createSignature: signatureFactory,
    });
    publication.assertCurrent();
    assert.deepEqual(fs.readFileSync(publishedPath), artifactA);
    assert.equal(fs.readdirSync(stagingDirectory).length, 0);
  } finally {
    publication?.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("all first-party backup producers stage before publishing and retain leases through reports", () => {
  const source = fs.readFileSync(path.resolve(import.meta.dirname, "infra-ops.mjs"), "utf8");
  const ranges = [
    ["async function backupPostgres", "function applicationSourceBackupExcludes"],
    ["async function backupApplications", "function controlCenterStateRoot"],
    ["async function backupControlCenterState", "function restoreTestControlCenterState"],
    ["async function backupMariadb", "async function restoreTestMariadb"],
    ["async function backupMinio", "async function restoreTestMinio"],
    ["async function backupKeycloakConfig", "async function restoreTestKeycloakConfig"],
    ["async function backupSecretManagerMetadata", "async function restoreTestSecretManagerMetadata"],
  ];
  for (const [start, end] of ranges) {
    const body = source.slice(source.indexOf(start), source.indexOf(end));
    assert.match(body, /backupArtifactStagingPath/, `${start} must create a private staging path`);
    assert.match(body, /publishBackupArtifact/, `${start} must publish through an artifact lease`);
    assert.doesNotMatch(body, /sha256File\(hostPath\)|signBackupArtifact\(hostPath/, `${start} must not close and reopen the published path`);
  }
  const evidenceHelper = source.slice(source.indexOf("function publishBackupArtifactWithEvidence"), source.indexOf("function hostPathForContainerMount"));
  assert.match(evidenceHelper, /onPublished[\s\S]*writeBackupExecutionReport[\s\S]*publication\.assertCurrent\(\)/);
  const postgres = source.slice(source.indexOf("async function backupPostgres"), source.indexOf("function applicationSourceBackupExcludes"));
  assert.match(postgres, /onPublished[\s\S]*writeBackupExecutionReport[\s\S]*publication\.assertCurrent\(\)/);
  const applications = source.slice(source.indexOf("async function backupApplications"), source.indexOf("function controlCenterStateRoot"));
  assert.match(applications, /writeJsonReport[\s\S]*writeMarkdownReport[\s\S]*publication\.assertCurrent\(\)/);
  assert.doesNotMatch(source, /function writeBackupIntegritySidecars/);
});
