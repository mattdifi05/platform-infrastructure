import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createBackupJobDocument } from "../backup/contracts.mjs";
import {
  BackupQueueAdmissionError,
  acquireBackupSchedulerLease,
  admitBackupJob,
  claimNextBackupJob,
  finishBackupJob,
  pruneBackupQueue,
  releaseBackupSchedulerLease,
} from "../backup/queue-admission.mjs";
import {
  BackupQueueOperationError,
  listBackupQueueOperationIds,
  requireCanonicalBackupQueueOperation,
} from "../backup/queue-operation-adapter.mjs";

const BASE_TIME = Date.parse("2026-07-21T20:00:00.000Z");
const raceWorker = path.join(import.meta.dirname, "fixtures", "backup-queue-race-worker.mjs");
const claimRaceWorker = path.join(import.meta.dirname, "fixtures", "backup-queue-claim-race-worker.mjs");
const queueCli = path.resolve(import.meta.dirname, "..", "..", "scripts", "backup-queue-control.mjs");

function operation(operationId = "backup.run", control = true) {
  return Object.freeze({
    method: "POST",
    operationId,
    capability: "owner:fresh",
    canonicalPath: operationId === "legacy.backup" ? "/actions/backup-command" : operationId === "database.backup" ? "/control/databases/db-one/backup" : "/control/backups/run",
    classified: true,
    control,
    parameters: Object.freeze(operationId === "database.backup" ? { databaseId: "db-one" } : {}),
  });
}

function resource(suffix) {
  return {
    id: `platform-state:${suffix}`,
    externalId: suffix,
    kind: "platform-state",
    projectId: "platform",
    name: suffix,
  };
}

function job(id, principal, suffix = id, jobOperation = "backup", createdAt = BASE_TIME) {
  return createBackupJobDocument({
    id,
    operation: jobOperation,
    scope: { kind: "platform", id: "platform" },
    resources: [resource(suffix)],
    requestedBy: principal,
    environment: "test",
    createdAt: new Date(createdAt).toISOString(),
    ...(jobOperation === "restore-drill" ? { sourceManifestPath: `manifests/${suffix}.json` } : {}),
  });
}

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "fg069-queue-test-"));
  const jobsDir = path.join(root, "jobs");
  const logDir = path.join(root, "logs");
  mkdirSync(logDir, { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, jobsDir, logDir };
}

function policy(overrides = {}) {
  return {
    maxOutstanding: 8,
    maxPerPrincipal: 8,
    principalWindowMs: 60_000,
    maxConcurrency: 1,
    maxTerminalPerStatus: 8,
    terminalMaxAgeMs: 120_000,
    maxLedgerEntries: 64,
    maxScanEntries: 128,
    lockTimeoutMs: 2000,
    ...overrides,
  };
}

function rejectedCode(fn, code, ErrorType = BackupQueueAdmissionError) {
  assert.throws(fn, (error) => error instanceof ErrorType && error.code === code);
}

test("registry adapter accepts canonical aliases by operation identity and fails closed", () => {
  assert.deepEqual(listBackupQueueOperationIds(), ["backup.run", "database.backup", "legacy.backup"]);
  // FG-004/043 resolves /control and /control/v1 aliases to this same frozen
  // canonical identity; FG-069 never receives or re-matches their raw paths.
  for (const alias of ["/control/backups/run", "/control/v1/backups/run"]) {
    const admitted = requireCanonicalBackupQueueOperation(operation("backup.run", true), "backup");
    assert.equal(admitted.operationId, "backup.run", alias);
  }
  for (const alias of ["/control/databases/db-one/backup", "/control/v1/databases/db-one/backup"]) {
    const admitted = requireCanonicalBackupQueueOperation(operation("database.backup", true), "backup");
    assert.equal(admitted.operationId, "database.backup", alias);
  }
  assert.equal(requireCanonicalBackupQueueOperation(operation("legacy.backup", false), "restore-drill").jobOperation, "restore-drill");

  rejectedCode(() => requireCanonicalBackupQueueOperation({ ...operation() }, "backup"), "operation_not_canonical", BackupQueueOperationError);
  rejectedCode(() => requireCanonicalBackupQueueOperation(Object.freeze({ ...operation(), classified: false }), "backup"), "operation_not_privileged", BackupQueueOperationError);
  rejectedCode(() => requireCanonicalBackupQueueOperation(Object.freeze({ ...operation(), capability: "admin" }), "backup"), "operation_not_privileged", BackupQueueOperationError);
  rejectedCode(() => requireCanonicalBackupQueueOperation(Object.freeze({ ...operation(), operationId: "default.mutation" }), "backup"), "operation_not_admitted", BackupQueueOperationError);
  rejectedCode(() => requireCanonicalBackupQueueOperation(operation("backup.run", true), "restore-drill"), "job_operation_mismatch", BackupQueueOperationError);
});

test("active deduplication spans API aliases and principals", (t) => {
  const { jobsDir } = fixture(t);
  const firstPrincipal = "owner-a@example.test";
  admitBackupJob({ jobsDir, operation: operation(), principal: firstPrincipal, job: job("job-alias-a", firstPrincipal, "catalog"), policy: policy(), now: BASE_TIME });
  rejectedCode(
    () => admitBackupJob({ jobsDir, operation: operation(), principal: firstPrincipal, job: job("job-alias-b", firstPrincipal, "catalog"), policy: policy(), now: BASE_TIME }),
    "duplicate_active",
  );
  const secondPrincipal = "owner-b@example.test";
  rejectedCode(
    () => admitBackupJob({ jobsDir, operation: operation(), principal: secondPrincipal, job: job("job-cross-principal", secondPrincipal, "catalog"), policy: policy(), now: BASE_TIME }),
    "duplicate_active",
  );
  assert.equal(readdirSync(path.join(jobsDir, "queued")).filter((name) => name.endsWith(".json")).length, 1);
});

test("global depth and per-principal rate reject without writing jobs", (t) => {
  const fullFixture = fixture(t);
  const owner = "owner-depth@example.test";
  const fullPolicy = policy({ maxOutstanding: 2 });
  admitBackupJob({ jobsDir: fullFixture.jobsDir, operation: operation(), principal: owner, job: job("job-depth-a", owner, "depth-a"), policy: fullPolicy, now: BASE_TIME });
  admitBackupJob({ jobsDir: fullFixture.jobsDir, operation: operation(), principal: owner, job: job("job-depth-b", owner, "depth-b"), policy: fullPolicy, now: BASE_TIME });
  rejectedCode(() => admitBackupJob({ jobsDir: fullFixture.jobsDir, operation: operation(), principal: owner, job: job("job-depth-c", owner, "depth-c"), policy: fullPolicy, now: BASE_TIME }), "queue_full");
  assert.equal(readdirSync(path.join(fullFixture.jobsDir, "queued")).filter((name) => name.endsWith(".json")).length, 2);

  const rateFixture = fixture(t);
  const ratePolicy = policy({ maxPerPrincipal: 2 });
  admitBackupJob({ jobsDir: rateFixture.jobsDir, operation: operation(), principal: owner, job: job("job-rate-a", owner, "rate-a"), policy: ratePolicy, now: BASE_TIME });
  admitBackupJob({ jobsDir: rateFixture.jobsDir, operation: operation(), principal: owner, job: job("job-rate-b", owner, "rate-b"), policy: ratePolicy, now: BASE_TIME });
  rejectedCode(() => admitBackupJob({ jobsDir: rateFixture.jobsDir, operation: operation(), principal: owner, job: job("job-rate-c", owner, "rate-c"), policy: ratePolicy, now: BASE_TIME }), "principal_rate_limited");
  admitBackupJob({ jobsDir: rateFixture.jobsDir, operation: operation(), principal: owner, job: job("job-rate-after-window", owner, "rate-d", "backup", BASE_TIME + 61_000), policy: ratePolicy, now: BASE_TIME + 61_000 });
  assert.equal(readdirSync(path.join(rateFixture.jobsDir, "queued")).filter((name) => name.endsWith(".json")).length, 3);
});

test("scheduler concurrency is global and completion releases active work", (t) => {
  const { jobsDir, logDir } = fixture(t);
  const owner = "owner-completion@example.test";
  const bounded = policy({ maxConcurrency: 1 });
  admitBackupJob({ jobsDir, logDir, operation: operation(), principal: owner, job: job("job-complete-a", owner, "complete-a"), policy: bounded, now: BASE_TIME });
  admitBackupJob({ jobsDir, logDir, operation: operation(), principal: owner, job: job("job-complete-b", owner, "complete-b"), policy: bounded, now: BASE_TIME });
  const first = claimNextBackupJob({ jobsDir, logDir, policy: bounded, now: BASE_TIME + 1000 });
  assert.equal(first.claimed, true);
  assert.equal(claimNextBackupJob({ jobsDir, logDir, policy: bounded, now: BASE_TIME + 2000 }).reason, "concurrency_full");
  finishBackupJob({ jobsDir, logDir, jobId: first.job.id, status: "done", summary: "complete", policy: bounded, now: BASE_TIME + 3000 });
  assert.equal(claimNextBackupJob({ jobsDir, logDir, policy: bounded, now: BASE_TIME + 4000 }).claimed, true);

  const retryFixture = fixture(t);
  admitBackupJob({ jobsDir: retryFixture.jobsDir, logDir: retryFixture.logDir, operation: operation(), principal: owner, job: job("job-retry-a", owner, "same-work"), policy: bounded, now: BASE_TIME });
  const claimed = claimNextBackupJob({ jobsDir: retryFixture.jobsDir, logDir: retryFixture.logDir, policy: bounded, now: BASE_TIME + 1000 });
  finishBackupJob({ jobsDir: retryFixture.jobsDir, logDir: retryFixture.logDir, jobId: claimed.job.id, status: "done", summary: "complete", policy: bounded, now: BASE_TIME + 2000 });
  const retry = admitBackupJob({ jobsDir: retryFixture.jobsDir, logDir: retryFixture.logDir, operation: operation(), principal: owner, job: job("job-retry-b", owner, "same-work", "backup", BASE_TIME + 3000), policy: bounded, now: BASE_TIME + 3000 });
  assert.equal(retry.admitted, true);
  rejectedCode(
    () => admitBackupJob({ jobsDir: retryFixture.jobsDir, logDir: retryFixture.logDir, operation: operation(), principal: owner, job: job("job-retry-a", owner, "different-work", "backup", BASE_TIME + 4000), policy: bounded, now: BASE_TIME + 4000 }),
    "job_id_conflict",
  );
});

test("scheduled work reserves the same global execution budget", (t) => {
  const { jobsDir, logDir } = fixture(t);
  const bounded = policy({ maxConcurrency: 1 });
  const lease = acquireBackupSchedulerLease({ jobsDir, logDir, kind: "backup-platform-catalog", policy: bounded, now: BASE_TIME });
  assert.equal(lease.acquired, true);
  assert.equal(acquireBackupSchedulerLease({ jobsDir, logDir, kind: "full-restore-drill", policy: bounded, now: BASE_TIME }).reason, "concurrency_full");
  assert.equal(claimNextBackupJob({ jobsDir, logDir, policy: bounded, now: BASE_TIME }).reason, "concurrency_full");
  const principal = "owner-lease@example.test";
  rejectedCode(() => admitBackupJob({ jobsDir, logDir, operation: operation(), principal, job: job("job-lease-blocked", principal, "lease"), policy: bounded, now: BASE_TIME }), "scheduler_reserved");
  const wrongHandle = `${lease.handle.slice(0, -1)}${lease.handle.endsWith("0") ? "1" : "0"}`;
  rejectedCode(() => releaseBackupSchedulerLease({ jobsDir, handle: wrongHandle, policy: bounded }), "scheduler_lease_owner_mismatch");
  assert.equal(releaseBackupSchedulerLease({ jobsDir, handle: lease.handle, policy: bounded }).released, true);
  assert.equal(admitBackupJob({ jobsDir, logDir, operation: operation(), principal, job: job("job-lease-admitted", principal, "lease"), policy: bounded, now: BASE_TIME }).admitted, true);
});

test("terminal job and owned log retention are count and age bounded", (t) => {
  const { jobsDir, logDir } = fixture(t);
  const bounded = policy({ maxTerminalPerStatus: 2, terminalMaxAgeMs: 60_000 });
  for (let index = 0; index < 5; index += 1) {
    const principal = `owner-retention-${index}@example.test`;
    const createdAt = BASE_TIME + index * 1000;
    admitBackupJob({ jobsDir, logDir, operation: operation(), principal, job: job(`job-retention-${index}`, principal, `retention-${index}`, "backup", createdAt), policy: bounded, now: createdAt });
    const claimed = claimNextBackupJob({ jobsDir, logDir, policy: bounded, now: createdAt + 100 });
    writeFileSync(claimed.logPath, "bounded log\n", { mode: 0o600, flag: "wx" });
    finishBackupJob({ jobsDir, logDir, jobId: claimed.job.id, status: "done", summary: "complete", policy: bounded, now: createdAt + 200 });
  }
  assert.equal(readdirSync(path.join(jobsDir, "done")).filter((name) => name.endsWith(".json")).length, 2);
  assert.equal(readdirSync(logDir).filter((name) => name.endsWith(".log")).length, 2);
  const removed = pruneBackupQueue({ jobsDir, logDir, policy: bounded, now: BASE_TIME + 70_000 });
  assert.equal(removed.length, 2);
  assert.equal(readdirSync(path.join(jobsDir, "done")).filter((name) => name.endsWith(".json")).length, 0);
  assert.equal(readdirSync(logDir).filter((name) => name.endsWith(".log")).length, 0);
});

test("malformed durable state fails closed without creating a job", (t) => {
  const { jobsDir } = fixture(t);
  mkdirSync(path.join(jobsDir, "queued"), { recursive: true });
  writeFileSync(path.join(jobsDir, "queued", "corrupt.json"), "{not-json\n", { mode: 0o600 });
  const principal = "owner-corrupt@example.test";
  rejectedCode(() => admitBackupJob({ jobsDir, operation: operation(), principal, job: job("job-must-not-exist", principal, "valid"), policy: policy(), now: BASE_TIME }), "queue_entry_invalid");
  assert.equal(existsSync(path.join(jobsDir, "queued", "job-must-not-exist.json")), false);
});

test("scheduler CLI claims and finishes through the shared queue boundary", (t) => {
  const { jobsDir, logDir } = fixture(t);
  const principal = "owner-cli@example.test";
  admitBackupJob({ jobsDir, logDir, operation: operation(), principal, job: job("job-cli", principal, "cli"), policy: policy(), now: BASE_TIME });
  const env = {
    ...process.env,
    BACKUP_QUEUE_MAX_OUTSTANDING: "8",
    BACKUP_QUEUE_MAX_PER_PRINCIPAL: "8",
    BACKUP_QUEUE_RATE_WINDOW_SECONDS: "60",
    BACKUP_QUEUE_MAX_CONCURRENCY: "1",
  };
  const claimed = spawnSync(process.execPath, [queueCli, "claim", "--jobsDir", jobsDir, "--logDir", logDir], { encoding: "utf8", env });
  assert.equal(claimed.status, 0, claimed.stderr);
  assert.equal(claimed.stdout.trim(), path.join(jobsDir, "running", "job-cli.json"));
  const finished = spawnSync(process.execPath, [queueCli, "finish", "--jobId", "job-cli", "--status", "done", "--summary", "complete", "--jobsDir", jobsDir, "--logDir", logDir], { encoding: "utf8", env });
  assert.equal(finished.status, 0, finished.stderr);
  assert.equal(existsSync(path.join(jobsDir, "done", "job-cli.json")), true);
  assert.equal(existsSync(path.join(jobsDir, "running", "job-cli.json")), false);

  const leased = spawnSync(process.execPath, [queueCli, "acquire-lease", "--kind", "backup-platform-catalog", "--jobsDir", jobsDir, "--logDir", logDir], { encoding: "utf8", env });
  assert.equal(leased.status, 0, leased.stderr);
  assert.match(leased.stdout.trim(), /^lease-[a-f0-9]{32}\.[a-f0-9]{48}$/);
  const released = spawnSync(process.execPath, [queueCli, "release-lease", "--handle", leased.stdout.trim(), "--jobsDir", jobsDir, "--logDir", logDir], { encoding: "utf8", env });
  assert.equal(released.status, 0, released.stderr);
});

test("simultaneous equivalent admissions create exactly one durable job", async (t) => {
  const { root, jobsDir } = fixture(t);
  const readyDir = path.join(root, "ready");
  const barrierPath = path.join(root, "go");
  mkdirSync(readyDir, { mode: 0o700 });
  const children = Array.from({ length: 8 }, (_, index) => spawn(process.execPath, [raceWorker, jobsDir, readyDir, barrierPath, String(index)], {
    stdio: ["ignore", "pipe", "pipe"],
  }));
  await waitUntil(() => readdirSync(readyDir).filter((name) => name.endsWith(".ready")).length === children.length, 5000);
  writeFileSync(barrierPath, "go\n", { flag: "wx" });
  const results = await Promise.all(children.map(childResult));
  assert.equal(results.filter((result) => result.admitted).length, 1, JSON.stringify(results));
  assert.equal(results.filter((result) => result.code === "duplicate_active").length, 7, JSON.stringify(results));
  assert.equal(readdirSync(path.join(jobsDir, "queued")).filter((name) => name.endsWith(".json")).length, 1);
});

test("simultaneous schedulers share one durable concurrency budget", async (t) => {
  const { root, jobsDir, logDir } = fixture(t);
  const readyDir = path.join(root, "claim-ready");
  const barrierPath = path.join(root, "claim-go");
  mkdirSync(readyDir, { mode: 0o700 });
  for (let index = 0; index < 4; index += 1) {
    const principal = `owner-claim-${index}@example.test`;
    admitBackupJob({
      jobsDir,
      logDir,
      operation: operation(),
      principal,
      job: job(`job-claim-${index}`, principal, `claim-${index}`, "backup", BASE_TIME + index),
      policy: policy(),
      now: BASE_TIME + index,
    });
  }
  const children = Array.from({ length: 6 }, () => spawn(process.execPath, [claimRaceWorker, jobsDir, logDir, readyDir, barrierPath], {
    stdio: ["ignore", "pipe", "pipe"],
  }));
  await waitUntil(() => readdirSync(readyDir).filter((name) => name.endsWith(".ready")).length === children.length, 5000);
  writeFileSync(barrierPath, "go\n", { flag: "wx" });
  const results = await Promise.all(children.map(childResult));
  assert.equal(results.filter((result) => result.claimed).length, 1, JSON.stringify(results));
  assert.equal(results.filter((result) => result.reason === "concurrency_full").length, 5, JSON.stringify(results));
  assert.equal(readdirSync(path.join(jobsDir, "running")).filter((name) => name.endsWith(".json")).length, 1);
  assert.equal(readdirSync(path.join(jobsDir, "queued")).filter((name) => name.endsWith(".json")).length, 3);
});

async function waitUntil(predicate, timeoutMs) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > timeoutMs) throw new Error("Timed out waiting for race workers.");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function childResult(child) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== 0) return reject(new Error(`race worker exited ${code}: ${stderr}`));
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(new Error(`invalid race output: ${stdout} ${stderr}`, { cause: error })); }
    });
  });
}
