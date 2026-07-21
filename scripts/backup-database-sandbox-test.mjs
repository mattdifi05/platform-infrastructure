#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import {
  backupResourceId,
  createBackupJobDocument,
} from "../control-center/backup/contracts.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const sandboxRoot = "/sandbox";
const hostRoot = String(process.env.SANDBOX_HOST_ROOT || "").trim();
if (!hostRoot.startsWith("/")) throw new Error("SANDBOX_HOST_ROOT must be an absolute host path.");
const replicaRoot = path.join(sandboxRoot, "infra");
const jobsRoot = path.join(sandboxRoot, "jobs");
const keyFile = path.join(sandboxRoot, "backup-signing-keys.txt");
const mariaSecretFile = path.join(sandboxRoot, "mariadb-root-password.txt");
const suffix = `${process.pid}-${Date.now()}`;
const postgresContainer = `platform-t06-postgres-${suffix}`;
const mariadbContainer = `platform-t06-mariadb-${suffix}`;
const postgresImage = "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa";
const mariadbImage = "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b";
const postgresDatabase = "fixture_postgres";
const mariadbDatabase = "fixture_mariadb";
const postgresPassword = randomBytes(24).toString("base64url");
const mariadbPassword = randomBytes(24).toString("base64url");

const resources = [
  {
    id: backupResourceId("database", "fixture-postgres"),
    externalId: "fixture-postgres",
    kind: "database",
    projectId: "fixture-app",
    name: postgresDatabase,
    engine: "postgres",
  },
  {
    id: backupResourceId("database", "fixture-mariadb"),
    externalId: "fixture-mariadb",
    kind: "database",
    projectId: "fixture-app",
    name: mariadbDatabase,
    engine: "mariadb",
  },
];

function docker(args, { allowFailure = false } = {}) {
  const result = spawnSync("docker", args, { encoding: "utf8" });
  if (!allowFailure && result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "unknown error")
      .replaceAll(postgresPassword, "[redacted]")
      .replaceAll(mariadbPassword, "[redacted]")
      .replace(/-p[^\s"']+/g, "-p[redacted]")
      .trim()
      .slice(0, 300);
    throw new Error(`Disposable database sandbox command failed: ${detail}`);
  }
  return result;
}

function waitFor(container, command) {
  for (let attempt = 0; attempt < 90; attempt += 1) {
    if (docker(["exec", container, ...command], { allowFailure: true }).status === 0) return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  throw new Error("Disposable database did not become ready.");
}

function writeRunningJob(job) {
  const directory = path.join(jobsRoot, "running");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const filePath = path.join(directory, `${job.id}.json`);
  writeFileSync(filePath, `${JSON.stringify({ ...job, status: "running" }, null, 2)}\n`, { mode: 0o600 });
  return filePath;
}

function runExecutor(jobFile, expectSuccess = true) {
  const result = spawnSync(process.execPath, [path.join(replicaRoot, "scripts", "infra-ops.mjs"), "execute-backup-job", "--jobFile", jobFile, "--skipEvidence"], {
    cwd: replicaRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      BACKUP_SCHEDULER_JOBS_DIR: jobsRoot,
      BACKUP_SIGNING_KEYS_FILE: keyFile,
      BACKUP_POSTGRES_CONTAINER: postgresContainer,
      BACKUP_MARIADB_CONTAINER: mariadbContainer,
      PLATFORM_INFRA_CONTAINER_ROOT: replicaRoot,
      PLATFORM_INFRA_HOST_ROOT: path.join(hostRoot, "infra"),
    },
  });
  if (expectSuccess && result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "unknown error")
      .replaceAll(postgresPassword, "[redacted]")
      .replaceAll(mariadbPassword, "[redacted]")
      .replace(/(?:POSTGRES_PASSWORD|MARIADB_ROOT_PASSWORD)=[^\s]+/g, (match) => `${match.split("=")[0]}=[redacted]`)
      .replace(/restore_[A-Za-z0-9_-]+/g, "restore_[redacted]")
      .trim()
      .slice(-800);
    throw new Error(`Typed database executor failed: ${detail}`);
  }
  if (!expectSuccess && result.status === 0) throw new Error("Typed database executor accepted a tampered manifest.");
}

function fileSha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

const liveIdsBefore = {
  postgres: docker(["inspect", "--format", "{{.Id}}", "enterprise-postgres"], { allowFailure: true }).stdout.trim(),
  mariadb: docker(["inspect", "--format", "{{.Id}}", "mariadb"], { allowFailure: true }).stdout.trim(),
};

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
  ]) cpSync(path.join(repositoryRoot, "scripts", moduleName), path.join(replicaRoot, "scripts", moduleName));
  cpSync(path.join(repositoryRoot, "control-center", "backup", "contracts.mjs"), path.join(replicaRoot, "control-center", "backup", "contracts.mjs"));
  writeFileSync(keyFile, `sandbox-v1=${randomBytes(48).toString("base64url")}\n`, { mode: 0o600 });
  writeFileSync(mariaSecretFile, `${mariadbPassword}\n`, { mode: 0o600 });

  docker(["run", "-d", "--name", postgresContainer, "--network", "none", "-e", `POSTGRES_PASSWORD=${postgresPassword}`, "-e", `POSTGRES_DB=${postgresDatabase}`, postgresImage]);
  docker(["run", "-d", "--name", mariadbContainer, "--network", "none", "-e", `MARIADB_ROOT_PASSWORD=${mariadbPassword}`, "--mount", `type=bind,source=${path.join(hostRoot, "mariadb-root-password.txt")},target=/run/secrets/mariadb_root_password,readonly`, mariadbImage]);
  waitFor(postgresContainer, ["pg_isready", "-U", "postgres", "-d", postgresDatabase]);
  waitFor(mariadbContainer, ["sh", "-ec", 'test "$(mariadb -N -uroot -p"$(cat /run/secrets/mariadb_root_password)" -e "select 1" 2>/dev/null)" = "1"']);
  docker(["exec", postgresContainer, "psql", "-U", "postgres", "-d", postgresDatabase, "-v", "ON_ERROR_STOP=1", "-c", "create table fixture_rows(id integer primary key, payload text not null); insert into fixture_rows values (1, 'postgres-fixture');"]);
  docker(["exec", mariadbContainer, "sh", "-ec", `mariadb -uroot -p"$(cat /run/secrets/mariadb_root_password)" -e "create database ${mariadbDatabase}; create table ${mariadbDatabase}.fixture_rows(id int primary key, payload varchar(64) not null); insert into ${mariadbDatabase}.fixture_rows values (1, 'mariadb-fixture');"`]);

  const backupJob = createBackupJobDocument({
    id: "sandbox-database-backup",
    operation: "backup",
    scope: { kind: "application", id: "fixture-app" },
    resources,
    requestedBy: "sandbox-test",
    environment: "sandbox",
  });
  const backupJobFile = writeRunningJob(backupJob);
  runExecutor(backupJobFile);
  const completedBackup = JSON.parse(readFileSync(backupJobFile, "utf8"));
  const manifestFile = path.join(replicaRoot, "backups", completedBackup.manifestPath);
  const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
  if (manifest.coverage?.complete !== true || manifest.artifacts?.length !== 2 || !manifest.signature?.value) throw new Error("Database backup manifest incomplete.");
  for (const artifact of manifest.artifacts) {
    const artifactPath = path.join(replicaRoot, "backups", artifact.path);
    if (!existsSync(artifactPath) || fileSha256(artifactPath) !== artifact.sha256) throw new Error("Database artifact integrity mismatch.");
  }

  const restoreJob = createBackupJobDocument({
    id: "sandbox-database-restore",
    operation: "restore-drill",
    scope: { kind: "application", id: "fixture-app" },
    resources,
    requestedBy: "sandbox-test",
    environment: "sandbox",
    sourceManifestPath: completedBackup.manifestPath,
  });
  const restoreJobFile = writeRunningJob(restoreJob);
  runExecutor(restoreJobFile);
  const completedRestore = JSON.parse(readFileSync(restoreJobFile, "utf8"));
  const restoreReport = JSON.parse(readFileSync(path.join(replicaRoot, completedRestore.reportPaths[0]), "utf8"));
  if (restoreReport.status !== "passed" || restoreReport.liveDataChanged !== false || restoreReport.results.length !== 2) throw new Error("Database restore drill incomplete.");

  writeFileSync(manifestFile, `${JSON.stringify({ ...manifest, signature: { ...manifest.signature, value: `${manifest.signature.value}x` } }, null, 2)}\n`, { mode: 0o600 });
  const rejectedJob = createBackupJobDocument({
    id: "sandbox-database-tamper",
    operation: "restore-drill",
    scope: { kind: "application", id: "fixture-app" },
    resources,
    requestedBy: "sandbox-test",
    environment: "sandbox",
    sourceManifestPath: completedBackup.manifestPath,
  });
  runExecutor(writeRunningJob(rejectedJob), false);

  const liveIdsAfter = {
    postgres: docker(["inspect", "--format", "{{.Id}}", "enterprise-postgres"], { allowFailure: true }).stdout.trim(),
    mariadb: docker(["inspect", "--format", "{{.Id}}", "mariadb"], { allowFailure: true }).stdout.trim(),
  };
  if (JSON.stringify(liveIdsBefore) !== JSON.stringify(liveIdsAfter)) throw new Error("Live database container identity changed during sandbox test.");
  process.stdout.write(`${JSON.stringify({
    status: "passed",
    engines: ["postgres", "mariadb"],
    exactResources: resources.map((resource) => resource.id),
    backupManifestComplete: true,
    restoreSandboxPassed: true,
    tamperedManifestRejected: true,
    liveDatabaseContainersChanged: false,
  })}\n`);
} finally {
  docker(["rm", "-f", postgresContainer], { allowFailure: true });
  docker(["rm", "-f", mariadbContainer], { allowFailure: true });
}
