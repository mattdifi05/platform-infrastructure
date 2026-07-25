#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { backupResourceId, createBackupJobDocument } from "../control-center/backup/contracts.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const sandboxRoot = mkdtempSync(path.join(os.tmpdir(), "platform-t07-coverage-"));
const replicaRoot = path.join(sandboxRoot, "infra");
const sourceRoot = path.join(sandboxRoot, "source");
const stateRoot = path.join(sandboxRoot, "state");
const jobsRoot = path.join(sandboxRoot, "jobs");
const keyFile = path.join(sandboxRoot, "backup-signing-keys.txt");

function runOps(args, expectSuccess = true, envOverrides = {}) {
  const result = spawnSync(process.execPath, [path.join(replicaRoot, "scripts", "infra-ops.mjs"), ...args], {
    cwd: replicaRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PROJECT_SOURCE_ROOT: sourceRoot,
      PROJECT_STATE_ROOT: stateRoot,
      PROJECT_DATABASES_FILE: path.join(stateRoot, "databases.json"),
      BACKUP_SCHEDULER_JOBS_DIR: jobsRoot,
      BACKUP_SIGNING_KEYS_FILE: keyFile,
      KEYCLOAK_DB_NAME: "keycloak",
      ...envOverrides,
    },
  });
  if (expectSuccess && result.status !== 0) throw new Error(result.stderr || result.stdout || "sandbox command failed");
  if (!expectSuccess && result.status === 0) throw new Error("sandbox command unexpectedly passed");
  return result;
}

function latestJson(directory) {
  return readdirSync(directory).filter((name) => name.endsWith(".json")).sort().at(-1);
}

function writeRunningJob(id) {
  const resource = {
    id: backupResourceId("source", "alpha"),
    externalId: "alpha",
    kind: "source",
    projectId: "alpha",
    name: "alpha",
    sourceDirectory: "alpha",
  };
  const job = createBackupJobDocument({
    id,
    operation: "backup",
    scope: { kind: "platform", id: "platform" },
    resources: [resource],
    requestedBy: "retention-sandbox",
    environment: "sandbox",
  });
  const runningDir = path.join(jobsRoot, "running");
  mkdirSync(runningDir, { recursive: true, mode: 0o700 });
  const jobFile = path.join(runningDir, `${id}.json`);
  writeFileSync(jobFile, `${JSON.stringify({ ...job, status: "running" }, null, 2)}\n`, { mode: 0o600 });
  return jobFile;
}

function writeJobDocument(job) {
  const runningDir = path.join(jobsRoot, "running");
  mkdirSync(runningDir, { recursive: true, mode: 0o700 });
  const jobFile = path.join(runningDir, `${job.id}.json`);
  writeFileSync(jobFile, `${JSON.stringify({ ...job, status: "running" }, null, 2)}\n`, { mode: 0o600 });
  return jobFile;
}

try {
  mkdirSync(path.join(replicaRoot, "scripts"), { recursive: true });
  mkdirSync(path.join(replicaRoot, "control-center", "backup"), { recursive: true });
  mkdirSync(path.join(replicaRoot, "governance"), { recursive: true });
  cpSync(path.join(repositoryRoot, "scripts", "infra-ops.mjs"), path.join(replicaRoot, "scripts", "infra-ops.mjs"));
  for (const moduleName of [
    "network-segmentation-policy.mjs",
    "runtime-isolation-policy.mjs",
    "supply-chain-policy.mjs",
    "functional-health.mjs",
    "runtime-fingerprint.mjs",
    "provider-evidence-auth.mjs",
    "github-governance-policy.mjs",
    "release-trust.mjs",
    "bounded-file-hash.mjs",
    "backup-artifact-publication.mjs",
    "command-safety.mjs",
    "restic-secret-transport.mjs",
    "safe-tar-path.mjs",
    "secret-store-metadata.mjs",
    "backup-import-policy.mjs",
    "postgres-restore-sandbox.mjs",
    "offsite-restore-contract.mjs",
    "canonical-compose-topology.mjs",
    "candidate-identity.mjs",
    "evidence-trust-envelope.mjs",
    "evidence-bundle-anchor.mjs",
    "evidence-bundle-phase.mjs",
    "edge-provider-evidence.mjs",
    "admin-access-inventory.mjs",
    "provider-mfa-assurance.mjs",
  ]) cpSync(path.join(repositoryRoot, "scripts", moduleName), path.join(replicaRoot, "scripts", moduleName));
  cpSync(path.join(repositoryRoot, "control-center", "backup", "contracts.mjs"), path.join(replicaRoot, "control-center", "backup", "contracts.mjs"));
  cpSync(path.join(repositoryRoot, "governance", "backup-data-policy.json"), path.join(replicaRoot, "governance", "backup-data-policy.json"));

  for (const application of ["alpha", "beta", "docs", ".hidden"]) {
    mkdirSync(path.join(sourceRoot, application), { recursive: true });
    writeFileSync(path.join(sourceRoot, application, "index.txt"), `${application}\n`);
  }
  mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(stateRoot, "databases.json"), `${JSON.stringify({
    alphaMaria: { id: "alpha-mariadb-alpha", projectId: "alpha", engine: "mariadb", name: "alpha" },
    betaPostgres: { id: "beta-postgres-beta", projectId: "beta", engine: "postgres", name: "beta" },
    deleted: { id: "old", projectId: "alpha", engine: "mariadb", name: "old", status: "deleted" },
  }, null, 2)}\n`, { mode: 0o600 });
  for (const [name, content] of [
    ["projects.json", "{}\n"],
    ["secret-vault.json", '{"version":2,"items":{}}\n'],
    ["operations.jsonl", '{"event":"fixture"}\n'],
    ["audit.jsonl", '{"event":"fixture"}\n'],
  ]) writeFileSync(path.join(stateRoot, name), content, { mode: 0o600 });
  writeFileSync(keyFile, `sandbox-v1=${randomBytes(48).toString("base64url")}\n`, { mode: 0o600 });

  runOps(["backup-coverage-matrix"]);
  const coverageDir = path.join(replicaRoot, "reports", "backup-coverage");
  const coverage = JSON.parse(readFileSync(path.join(coverageDir, latestJson(coverageDir)), "utf8"));
  const expectedIds = [
    "source:alpha",
    "source:beta",
    "database:alpha-mariadb-alpha",
    "database:beta-postgres-beta",
    "database:platform-postgres-keycloak",
    "platform-state:minio-data",
    "platform-state:keycloak-config",
    "platform-state:control-center-state",
    "platform-state:secret-manager-metadata",
  ];
  if (coverage.status !== "passed" || coverage.resourceCount !== expectedIds.length) throw new Error("Coverage matrix count is incomplete.");
  for (const id of expectedIds) if (!coverage.resourceIds.includes(id)) throw new Error(`Coverage matrix is missing ${id}.`);
  if (coverage.resourceIds.some((id) => id.includes("docs") || id.includes("hidden"))) throw new Error("Tooling or hidden source escaped into the application catalog.");

  const stateResource = {
    id: backupResourceId("platform-state", "control-center-state"),
    externalId: "control-center-state",
    kind: "platform-state",
    projectId: "platform",
    name: "control-center-state",
  };
  const stateBackup = createBackupJobDocument({
    id: "control-center-state-backup",
    operation: "backup",
    scope: { kind: "platform", id: "platform" },
    resources: [stateResource],
    requestedBy: "state-sandbox",
    environment: "sandbox",
  });
  const stateBackupFile = writeJobDocument(stateBackup);
  runOps(["execute-backup-job", "--jobFile", stateBackupFile]);
  const completedStateBackup = JSON.parse(readFileSync(stateBackupFile, "utf8"));
  const stateRestore = createBackupJobDocument({
    id: "control-center-state-restore",
    operation: "restore-drill",
    scope: { kind: "platform", id: "platform" },
    resources: [stateResource],
    requestedBy: "state-sandbox",
    environment: "sandbox",
    sourceManifestPath: completedStateBackup.manifestPath,
  });
  const stateRestoreFile = writeJobDocument(stateRestore);
  runOps(["execute-backup-job", "--jobFile", stateRestoreFile]);
  const completedStateRestore = JSON.parse(readFileSync(stateRestoreFile, "utf8"));
  const stateRestoreReport = JSON.parse(readFileSync(path.join(replicaRoot, completedStateRestore.reportPaths[0]), "utf8"));
  if (stateRestoreReport.status !== "passed" || stateRestoreReport.results[0]?.liveStateChanged !== false) throw new Error("Control Center state restore drill is incomplete or touched live state.");

  for (let index = 1; index <= 3; index += 1) {
    runOps(["execute-backup-job", "--jobFile", writeRunningJob(`retention-platform-${index}`)]);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1100);
  }
  const legacyFile = path.join(replicaRoot, "backups", "legacy-unmanifested.txt");
  writeFileSync(legacyFile, "must remain\n", { mode: 0o600 });
  runOps(["prune-manifest-backups", "--keepLast", "2"]);
  const retentionDir = path.join(replicaRoot, "reports", "backup-retention");
  const plan = JSON.parse(readFileSync(path.join(retentionDir, latestJson(retentionDir)), "utf8"));
  if (plan.mode !== "plan" || plan.completeManifestCount !== 4 || plan.expiredManifestIds.length !== 2) throw new Error("Retention plan is not manifest-bound.");
  if (readdirSync(path.join(replicaRoot, "backups", "manifests")).filter((name) => name.endsWith(".json")).length !== 4) throw new Error("Retention plan deleted files.");
  runOps(["prune-manifest-backups", "--keepLast", "2", "--confirmPruneManifestBackups"]);
  if (readdirSync(path.join(replicaRoot, "backups", "manifests")).filter((name) => name.endsWith(".json")).length !== 2) throw new Error("Retention apply did not keep exactly two manifests.");
  if (!existsSync(legacyFile)) throw new Error("Retention deleted an unmanifested legacy artifact.");

  const partialUpload = runOps(["offsite-backup-restic", "--allowPartial"], false);
  if (!`${partialUpload.stderr}\n${partialUpload.stdout}`.includes("partial off-site uploads are not supported")) throw new Error("Partial off-site upload did not fail closed.");
  const resticPasswordFile = path.join(sandboxRoot, "restic-password.txt");
  writeFileSync(resticPasswordFile, `${randomBytes(32).toString("base64url")}\n`, { mode: 0o600 });
  const mutableImage = runOps(["offsite-backup-restic"], false, {
    RESTIC_REPOSITORY: "s3:https://backup.invalid/platform-fixture",
    RESTIC_PASSWORD_FILE: resticPasswordFile,
    RESTIC_IMAGE: `registry.invalid/restic-rclone@sha256:${"0".repeat(64)}`,
    RESTIC_REQUIRE_IMMUTABLE_IMAGE: "true",
  });
  if (!`${mutableImage.stderr}\n${mutableImage.stdout}`.includes("RESTIC_IMAGE must be pinned by digest")) throw new Error("Placeholder Restic image digest did not fail closed.");

  const privateDirectories = [path.join(replicaRoot, "backups"), path.join(replicaRoot, "backups", "manifests")];
  for (const directory of privateDirectories) chmodSync(directory, statSync(directory).mode & 0o777);
  if (privateDirectories.some((directory) => (statSync(directory).mode & 0o077) !== 0)) throw new Error("Backup directory permissions are broader than 0700.");

  process.stdout.write(`${JSON.stringify({
    status: "passed",
    exactResourceCount: coverage.resourceCount,
    sourceDiscoveryExcludedTooling: true,
    controlCenterStateRestoreSandboxPassed: true,
    completeManifestRetention: true,
    unmanifestedArtifactsDeleted: false,
    privateModes: true,
    partialOffsiteRejected: true,
    placeholderResticImageRejected: true,
  })}\n`);
} finally {
  rmSync(sandboxRoot, { recursive: true, force: true });
}
