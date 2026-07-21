#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  backupResourceId,
  createBackupJobDocument,
} from "../control-center/backup/contracts.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sandboxRoot = mkdtempSync(path.join(os.tmpdir(), "platform-t06-backup-"));
const replicaRoot = path.join(sandboxRoot, "infra");
const sourceRoot = path.join(sandboxRoot, "source");
const jobsRoot = path.join(sandboxRoot, "jobs");
const keyFile = path.join(sandboxRoot, "backup-signing-keys.txt");
const resource = {
  id: backupResourceId("source", "fixture-app"),
  externalId: "fixture-app",
  kind: "source",
  projectId: "fixture-app",
  name: "fixture-app",
  sourceDirectory: "fixture-app",
};

function sha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function writeRunningJob(job) {
  const runningDir = path.join(jobsRoot, "running");
  mkdirSync(runningDir, { recursive: true, mode: 0o700 });
  const filePath = path.join(runningDir, `${job.id}.json`);
  writeFileSync(filePath, `${JSON.stringify({ ...job, status: "running" }, null, 2)}\n`, { mode: 0o600 });
  return filePath;
}

function runExecutor(jobFile, expectSuccess = true) {
  const result = spawnSync(process.execPath, [path.join(replicaRoot, "scripts", "infra-ops.mjs"), "execute-backup-job", "--jobFile", jobFile], {
    cwd: replicaRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PROJECT_SOURCE_ROOT: sourceRoot,
      BACKUP_SCHEDULER_JOBS_DIR: jobsRoot,
      BACKUP_SIGNING_KEYS_FILE: keyFile,
    },
  });
  if (expectSuccess && result.status !== 0) throw new Error(result.stderr || result.stdout || "typed executor failed");
  if (!expectSuccess && result.status === 0) throw new Error("tampered manifest was accepted");
  return result;
}

try {
  mkdirSync(path.join(replicaRoot, "scripts"), { recursive: true });
  mkdirSync(path.join(replicaRoot, "control-center", "backup"), { recursive: true });
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
    "edge-provider-evidence.mjs",
  ]) cpSync(path.join(repositoryRoot, "scripts", moduleName), path.join(replicaRoot, "scripts", moduleName));
  cpSync(path.join(repositoryRoot, "control-center", "backup", "contracts.mjs"), path.join(replicaRoot, "control-center", "backup", "contracts.mjs"));
  mkdirSync(path.join(sourceRoot, "fixture-app", "src"), { recursive: true });
  const sourceFile = path.join(sourceRoot, "fixture-app", "src", "index.js");
  writeFileSync(sourceFile, "export const fixture = true;\n");
  const sourceHashBefore = sha256(sourceFile);
  writeFileSync(keyFile, `sandbox-v1=${randomBytes(48).toString("base64url")}\n`, { mode: 0o600 });

  const backupJob = createBackupJobDocument({
    id: "sandbox-backup-job",
    operation: "backup",
    scope: { kind: "application", id: "fixture-app" },
    resources: [resource],
    requestedBy: "sandbox-test",
    environment: "sandbox",
  });
  const backupJobFile = writeRunningJob(backupJob);
  runExecutor(backupJobFile);
  const completedBackupJob = JSON.parse(readFileSync(backupJobFile, "utf8"));
  if (!completedBackupJob.manifestPath) throw new Error("backup job did not record a manifest path");
  const manifestFile = path.join(replicaRoot, "backups", completedBackupJob.manifestPath);
  const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
  if (manifest.coverage?.complete !== true || manifest.resources?.[0]?.id !== resource.id || !manifest.signature?.value) {
    throw new Error("backup manifest is incomplete or unsigned");
  }
  const artifactFile = path.join(replicaRoot, "backups", manifest.artifacts[0].path);
  if (!existsSync(artifactFile) || sha256(artifactFile) !== manifest.artifacts[0].sha256) throw new Error("backup artifact integrity mismatch");

  const restoreJob = createBackupJobDocument({
    id: "sandbox-restore-job",
    operation: "restore-drill",
    scope: { kind: "application", id: "fixture-app" },
    resources: [resource],
    requestedBy: "sandbox-test",
    environment: "sandbox",
    sourceManifestPath: completedBackupJob.manifestPath,
  });
  const restoreJobFile = writeRunningJob(restoreJob);
  runExecutor(restoreJobFile);
  const completedRestoreJob = JSON.parse(readFileSync(restoreJobFile, "utf8"));
  const restoreReport = JSON.parse(readFileSync(path.join(replicaRoot, completedRestoreJob.reportPaths[0]), "utf8"));
  if (restoreReport.status !== "passed" || restoreReport.liveDataChanged !== false || sha256(sourceFile) !== sourceHashBefore) {
    throw new Error("restore drill changed live source or did not pass");
  }

  const tampered = { ...manifest, signature: { ...manifest.signature, value: `${manifest.signature.value}x` } };
  writeFileSync(manifestFile, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
  const rejectedJob = createBackupJobDocument({
    id: "sandbox-tamper-job",
    operation: "restore-drill",
    scope: { kind: "application", id: "fixture-app" },
    resources: [resource],
    requestedBy: "sandbox-test",
    environment: "sandbox",
    sourceManifestPath: completedBackupJob.manifestPath,
  });
  runExecutor(writeRunningJob(rejectedJob), false);

  process.stdout.write(`${JSON.stringify({
    status: "passed",
    exactResourceId: resource.id,
    manifestSigned: true,
    restoreSandboxPassed: true,
    tamperedManifestRejected: true,
    liveDataChanged: false,
  })}\n`);
} finally {
  rmSync(sandboxRoot, { recursive: true, force: true });
}
