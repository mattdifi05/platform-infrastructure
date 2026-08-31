import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { parseBackupJobDocument } from "./contracts.mjs";
import { requireCanonicalBackupQueueOperation } from "./queue-operation-adapter.mjs";

const STATUS_NAMES = Object.freeze(["queued", "running", "done", "failed"]);
const TERMINAL_STATUS_NAMES = Object.freeze(["done", "failed"]);
const LEDGER_SCHEMA = "platform.backup-queue-admissions/v1";
const LEASE_SCHEMA = "platform.backup-scheduler-lease/v1";
const LOCK_DIRECTORY = ".admission.lock";
const LEDGER_FILE = ".admission-ledger.json";
const LEASE_DIRECTORY = ".scheduler-leases";
const waitArray = new Int32Array(new SharedArrayBuffer(4));

export class BackupQueueAdmissionError extends Error {
  constructor(code, message, status = 503, details = {}) {
    super(message);
    this.name = "BackupQueueAdmissionError";
    this.code = code;
    this.status = status;
    this.details = Object.freeze({ ...details });
  }
}

export function backupQueueSharedIdentityFromEnvironment(env = process.env) {
  const rawUid = String(env?.BACKUP_QUEUE_SHARED_UID ?? "").trim();
  const rawGid = String(env?.BACKUP_QUEUE_SHARED_GID ?? "").trim();
  if (!rawUid && !rawGid) return null;
  if (!rawUid || !rawGid) {
    throw admissionError("queue_shared_identity_invalid", "Backup queue shared UID and GID must be configured together.", 503);
  }
  if (!/^[1-9][0-9]*$/.test(rawUid) || !/^[1-9][0-9]*$/.test(rawGid)) {
    throw admissionError("queue_shared_identity_invalid", "Backup queue shared UID and GID must be positive decimal identifiers.", 503);
  }
  const uid = Number(rawUid);
  const gid = Number(rawGid);
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid) || uid > 0x7fffffff || gid > 0x7fffffff) {
    throw admissionError("queue_shared_identity_invalid", "Backup queue shared UID or GID is outside the supported range.", 503);
  }
  return Object.freeze({ uid, gid });
}

export function applyBackupQueueFileOwnership(descriptor, identity = backupQueueSharedIdentityFromEnvironment()) {
  if (!identity) return;
  const effectiveUid = typeof process.geteuid === "function" ? process.geteuid() : process.getuid();
  const effectiveGid = typeof process.getegid === "function" ? process.getegid() : process.getgid();
  const before = fstatSync(descriptor);
  if (!before.isFile() || before.nlink !== 1) {
    throw admissionError("queue_shared_identity_unavailable", "Backup queue ownership handoff requires one regular file.", 503);
  }
  if (effectiveUid === 0) {
    if (!((before.uid === 0 && before.gid === 0)
      || (before.uid === identity.uid && before.gid === identity.gid))) {
      throw admissionError("queue_shared_identity_unavailable", "Backup queue file has a foreign pre-handoff owner.", 503);
    }
    fchownSync(descriptor, identity.uid, identity.gid);
  } else if (effectiveUid !== identity.uid || effectiveGid !== identity.gid) {
    throw admissionError("queue_shared_identity_unavailable", "Process identity cannot materialize the configured backup queue owner.", 503);
  }
  fchmodSync(descriptor, 0o600);
  const stat = fstatSync(descriptor);
  if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== identity.uid || stat.gid !== identity.gid
    || (stat.mode & 0o777) !== 0o600) {
    throw admissionError("queue_shared_identity_unavailable", "Backup queue file ownership or mode handoff failed.", 503);
  }
}

export function ensureBackupQueueDirectoryOwnership(directory, identity = backupQueueSharedIdentityFromEnvironment()) {
  if (!identity) return;
  let descriptor;
  try {
    descriptor = openSync(
      directory,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    const before = fstatSync(descriptor);
    if (!before.isDirectory()) {
      throw admissionError("queue_path_invalid", "Backup queue paths must be real directories.", 503);
    }
    const effectiveUid = typeof process.geteuid === "function" ? process.geteuid() : process.getuid();
    const effectiveGid = typeof process.getegid === "function" ? process.getegid() : process.getgid();
    if (before.uid !== identity.uid || before.gid !== identity.gid) {
      if (effectiveUid !== 0) {
        throw admissionError("queue_shared_identity_unavailable", "Backup queue directory is not owned by the configured shared identity.", 503);
      }
      if (before.uid !== 0 || before.gid !== 0) {
        throw admissionError("queue_shared_identity_unavailable", "Backup queue directory has a foreign pre-handoff owner.", 503);
      }
      fchownSync(descriptor, identity.uid, identity.gid);
    } else if (effectiveUid !== 0 && (effectiveUid !== identity.uid || effectiveGid !== identity.gid)) {
      throw admissionError("queue_shared_identity_unavailable", "Process identity cannot use the configured backup queue owner.", 503);
    }
    fchmodSync(descriptor, 0o700);
    fsyncSync(descriptor);
    const after = fstatSync(descriptor);
    const namespace = lstatSync(directory);
    if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino
      || namespace.isSymbolicLink() || !namespace.isDirectory()
      || namespace.dev !== after.dev || namespace.ino !== after.ino
      || after.uid !== identity.uid || after.gid !== identity.gid || (after.mode & 0o777) !== 0o700) {
      throw admissionError("queue_shared_identity_unavailable", "Backup queue directory ownership, mode or namespace handoff failed.", 503);
    }
  } catch (error) {
    if (error instanceof BackupQueueAdmissionError) throw error;
    throw admissionError("queue_path_invalid", "Backup queue path could not be opened without following links.", 503, { cause: error?.code || "error" });
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function backupQueuePolicyFromEnvironment(env = process.env) {
  return normalizeBackupQueuePolicy({
    maxOutstanding: env.BACKUP_QUEUE_MAX_OUTSTANDING,
    maxPerPrincipal: env.BACKUP_QUEUE_MAX_PER_PRINCIPAL,
    principalWindowMs: seconds(env.BACKUP_QUEUE_RATE_WINDOW_SECONDS),
    maxConcurrency: env.BACKUP_QUEUE_MAX_CONCURRENCY,
    maxTerminalPerStatus: env.BACKUP_QUEUE_TERMINAL_MAX_PER_STATUS,
    terminalMaxAgeMs: days(env.BACKUP_QUEUE_TERMINAL_MAX_AGE_DAYS),
    maxLedgerEntries: env.BACKUP_QUEUE_LEDGER_MAX_ENTRIES,
    maxScanEntries: env.BACKUP_QUEUE_MAX_SCAN_ENTRIES,
    lockTimeoutMs: env.BACKUP_QUEUE_LOCK_TIMEOUT_MS,
  });
}

export function normalizeBackupQueuePolicy(input = {}) {
  const policy = Object.freeze({
    maxOutstanding: boundedInteger(input.maxOutstanding, 32, 1, 1024, "max outstanding jobs"),
    maxPerPrincipal: boundedInteger(input.maxPerPrincipal, 4, 1, 256, "per-principal admissions"),
    principalWindowMs: boundedInteger(input.principalWindowMs, 15 * 60 * 1000, 1000, 7 * 24 * 60 * 60 * 1000, "principal rate window"),
    maxConcurrency: boundedInteger(input.maxConcurrency, 1, 1, 64, "scheduler concurrency"),
    maxTerminalPerStatus: boundedInteger(input.maxTerminalPerStatus, 200, 1, 10000, "terminal retention count"),
    terminalMaxAgeMs: boundedInteger(input.terminalMaxAgeMs, 30 * 24 * 60 * 60 * 1000, 60 * 1000, 365 * 24 * 60 * 60 * 1000, "terminal retention age"),
    maxLedgerEntries: boundedInteger(input.maxLedgerEntries, 4096, 16, 100000, "admission ledger entries"),
    maxScanEntries: boundedInteger(input.maxScanEntries, 4096, 32, 100000, "queue scan entries"),
    lockTimeoutMs: boundedInteger(input.lockTimeoutMs, 2000, 0, 30000, "queue lock timeout"),
  });
  if (policy.maxConcurrency > policy.maxOutstanding) {
    throw new Error("Scheduler concurrency cannot exceed the global outstanding-job limit.");
  }
  return policy;
}

export function canonicalBackupActiveKey(jobInput) {
  const job = parseBackupJobDocument(jobInput);
  const identity = {
    operation: job.operation,
    scope: job.scope,
    resourceIds: job.resources.map((resource) => resource.id).sort(),
    sourceManifestPath: job.sourceManifestPath || "",
  };
  return createHash("sha256").update(JSON.stringify(identity)).digest("hex");
}

export function admitBackupJob({
  jobsDir,
  logDir = "",
  operation,
  principal,
  job: jobInput,
  policy: policyInput = {},
  now = Date.now(),
}) {
  const policy = normalizeBackupQueuePolicy(policyInput);
  const normalizedPrincipal = requirePrincipal(principal);
  const job = parseBackupJobDocument(jobInput);
  requireCanonicalBackupQueueOperation(operation, job.operation);
  if (job.status !== "queued") throw admissionError("invalid_job_status", "Only queued backup jobs can be admitted.", 422);
  if (job.requestedBy !== normalizedPrincipal) {
    throw admissionError("principal_mismatch", "Authenticated principal does not match the durable job requester.", 403);
  }
  const root = prepareQueueRoot(jobsDir);
  return withQueueLock(root, policy, () => {
    const timestamp = timestampMs(now);
    const pruned = pruneTerminalJobsUnlocked(root, logDir, policy, timestamp);
    const snapshot = readQueueSnapshot(root, policy);
    if (snapshot.leases.length > 0) {
      throw admissionError("scheduler_reserved", "A privileged scheduled operation holds the global execution budget.", 503, { leases: snapshot.leases.length });
    }
    const activeKey = canonicalBackupActiveKey(job);
    const duplicate = [...snapshot.queued, ...snapshot.running]
      .find((entry) => entry.activeKey === activeKey);
    if (duplicate) {
      throw admissionError("duplicate_active", "Equivalent privileged backup work is already queued or running.", 409, { existingJobId: duplicate.job.id });
    }
    const idConflict = STATUS_NAMES.flatMap((status) => snapshot[status]).find((entry) => entry.job.id === job.id);
    if (idConflict) throw admissionError("job_id_conflict", "Backup job identifier already exists in the durable lifecycle.", 409);
    const outstanding = snapshot.queued.length + snapshot.running.length + snapshot.leases.length;
    if (outstanding >= policy.maxOutstanding) {
      throw admissionError("queue_full", "Privileged backup queue capacity is exhausted.", 503, { outstanding, limit: policy.maxOutstanding });
    }
    const ledger = readAdmissionLedger(root, policy, timestamp);
    const principalAdmissions = ledger.events.filter((event) => event.principal === normalizedPrincipal);
    if (principalAdmissions.length >= policy.maxPerPrincipal) {
      throw admissionError("principal_rate_limited", "Principal backup admission rate is exhausted.", 429, { limit: policy.maxPerPrincipal, windowMs: policy.principalWindowMs });
    }
    if (ledger.events.length >= policy.maxLedgerEntries) {
      throw admissionError("admission_ledger_full", "Backup admission ledger reached its fail-closed bound.", 503);
    }
    const queuedPath = queueFilePath(root, "queued", job.id);
    if (existsSync(queuedPath)) throw admissionError("job_id_conflict", "Backup job identifier already exists.", 409);

    const event = Object.freeze({
      admittedAt: new Date(timestamp).toISOString(),
      principal: normalizedPrincipal,
      jobId: job.id,
      activeKey,
      routeOperationId: operation.operationId,
    });
    const nextLedger = { schema: LEDGER_SCHEMA, events: [...ledger.events, event] };
    writeJsonAtomic(path.join(root, LEDGER_FILE), nextLedger);
    try {
      writeJsonExclusiveAtomic(queuedPath, job);
    } catch (error) {
      // Roll back when possible. A crash before this point can leave only a
      // conservative rate reservation, which fails closed rather than
      // undercounting an admission.
      try {
        writeJsonAtomic(path.join(root, LEDGER_FILE), ledger);
      } catch {
        // Preserve the original persistence failure and the conservative slot.
      }
      throw admissionError("job_persist_failed", "Backup job could not be persisted atomically.", 503, { cause: error?.code || error?.name || "error" });
    }
    return Object.freeze({
      admitted: true,
      job,
      activeKey,
      outstanding: outstanding + 1,
      pruned: Object.freeze(pruned),
    });
  });
}

export function claimNextBackupJob({ jobsDir, logDir = "", policy: policyInput = {}, now = Date.now() }) {
  const policy = normalizeBackupQueuePolicy(policyInput);
  const root = prepareQueueRoot(jobsDir);
  return withQueueLock(root, policy, () => {
    const timestamp = timestampMs(now);
    const pruned = pruneTerminalJobsUnlocked(root, logDir, policy, timestamp);
    const snapshot = readQueueSnapshot(root, policy);
    const executing = snapshot.running.length + snapshot.leases.length;
    if (executing >= policy.maxConcurrency) {
      return Object.freeze({ claimed: false, reason: "concurrency_full", running: snapshot.running.length, leases: snapshot.leases.length, limit: policy.maxConcurrency, pruned: Object.freeze(pruned) });
    }
    const next = snapshot.queued
      .sort((left, right) => left.job.createdAt.localeCompare(right.job.createdAt) || left.name.localeCompare(right.name))[0];
    if (!next) return Object.freeze({ claimed: false, reason: "queue_empty", running: snapshot.running.length, pruned: Object.freeze(pruned) });

    const runningPath = queueFilePath(root, "running", next.job.id);
    if (existsSync(runningPath)) throw admissionError("job_id_conflict", "Running job identifier already exists.", 503);
    renameSync(next.path, runningPath);
    const startedAt = new Date(timestamp).toISOString();
    const logPath = logDir ? safeJobLogPath(logDir, next.job.id) : "";
    const runningJob = {
      ...next.raw,
      status: "running",
      updatedAt: startedAt,
      startedAt: next.raw.startedAt || startedAt,
      resultSummary: "Job claimed within the scheduler concurrency budget.",
      ...(logPath ? { logPath } : {}),
    };
    try {
      writeJsonAtomic(runningPath, runningJob);
    } catch (error) {
      try { renameSync(runningPath, next.path); } catch { /* fail closed on the stranded transition */ }
      throw admissionError("claim_persist_failed", "Claimed backup job state could not be persisted.", 503, { cause: error?.code || error?.name || "error" });
    }
    return Object.freeze({ claimed: true, job: parseBackupJobDocument(runningJob), runningPath, logPath, pruned: Object.freeze(pruned) });
  });
}

export function acquireBackupSchedulerLease({ jobsDir, logDir = "", kind, policy: policyInput = {}, now = Date.now() }) {
  const policy = normalizeBackupQueuePolicy(policyInput);
  const root = prepareQueueRoot(jobsDir);
  const normalizedKind = requireLeaseKind(kind);
  return withQueueLock(root, policy, () => {
    const timestamp = timestampMs(now);
    const pruned = pruneTerminalJobsUnlocked(root, logDir, policy, timestamp);
    const snapshot = readQueueSnapshot(root, policy);
    const executing = snapshot.running.length + snapshot.leases.length;
    if (executing >= policy.maxConcurrency) {
      return Object.freeze({ acquired: false, reason: "concurrency_full", running: snapshot.running.length, leases: snapshot.leases.length, limit: policy.maxConcurrency, pruned: Object.freeze(pruned) });
    }
    const id = `lease-${randomBytes(16).toString("hex")}`;
    const token = randomBytes(24).toString("hex");
    const lease = Object.freeze({ schema: LEASE_SCHEMA, id, token, kind: normalizedKind, pid: process.pid, createdAt: new Date(timestamp).toISOString() });
    writeJsonExclusiveAtomic(path.join(root, LEASE_DIRECTORY, `${id}.json`), lease);
    return Object.freeze({ acquired: true, handle: `${id}.${token}`, kind: normalizedKind, pruned: Object.freeze(pruned) });
  });
}

export function releaseBackupSchedulerLease({ jobsDir, handle, policy: policyInput = {} }) {
  const policy = normalizeBackupQueuePolicy(policyInput);
  const root = prepareQueueRoot(jobsDir);
  const parsed = parseLeaseHandle(handle);
  return withQueueLock(root, policy, () => {
    const leasePath = path.join(root, LEASE_DIRECTORY, `${parsed.id}.json`);
    const lease = readSchedulerLease(leasePath);
    if (!lease || lease.token !== parsed.token) throw admissionError("scheduler_lease_owner_mismatch", "Scheduler lease ownership could not be verified.", 503);
    unlinkSync(leasePath);
    fsyncDirectory(path.dirname(leasePath));
    return Object.freeze({ released: true, kind: lease.kind });
  });
}

export function finishBackupJob({
  jobsDir,
  logDir = "",
  jobId,
  status,
  summary,
  exitCode = null,
  policy: policyInput = {},
  now = Date.now(),
}) {
  const policy = normalizeBackupQueuePolicy(policyInput);
  const root = prepareQueueRoot(jobsDir);
  const normalizedId = requireJobId(jobId);
  const terminalStatus = String(status || "");
  if (!TERMINAL_STATUS_NAMES.includes(terminalStatus)) throw admissionError("invalid_terminal_status", "Backup job terminal status must be done or failed.", 422);
  return withQueueLock(root, policy, () => {
    const runningPath = queueFilePath(root, "running", normalizedId);
    const entry = readQueueEntry(runningPath, "running");
    if (!entry) throw admissionError("running_job_missing", "Running backup job was not found.", 409);
    const finishedAt = new Date(timestampMs(now)).toISOString();
    const terminalPath = queueFilePath(root, terminalStatus, normalizedId);
    if (existsSync(terminalPath)) throw admissionError("job_id_conflict", "Terminal job identifier already exists.", 503);
    const terminalJob = {
      ...entry.raw,
      status: terminalStatus,
      updatedAt: finishedAt,
      finishedAt,
      resultSummary: String(summary || (terminalStatus === "done" ? "Job completed." : "Job failed.")).slice(0, 500),
    };
    if (exitCode === null || exitCode === "") delete terminalJob.exitCode;
    else terminalJob.exitCode = boundedInteger(exitCode, 1, 0, 255, "job exit code");
    writeJsonAtomic(runningPath, terminalJob);
    renameSync(runningPath, terminalPath);
    const pruned = pruneTerminalJobsUnlocked(root, logDir, policy, timestampMs(now));
    return Object.freeze({ finished: true, job: parseBackupJobDocument(terminalJob), terminalPath, pruned: Object.freeze(pruned) });
  });
}

export function markBackupJobOutcomeUnknown({
  jobsDir,
  jobId,
  summary,
  exitCode = 74,
  policy: policyInput = {},
  now = Date.now(),
}) {
  const policy = normalizeBackupQueuePolicy(policyInput);
  const root = prepareQueueRoot(jobsDir);
  const normalizedId = requireJobId(jobId);
  const normalizedExitCode = boundedInteger(exitCode, 74, 74, 74, "unknown-outcome exit code");
  const normalizedSummary = String(summary || "").trim().slice(0, 500);
  if (!/manual-reconciliation/i.test(normalizedSummary)) {
    throw admissionError(
      "invalid_unknown_summary",
      "Unknown backup outcomes must explicitly require manual-reconciliation.",
      422,
    );
  }
  return withQueueLock(root, policy, () => {
    const runningPath = queueFilePath(root, "running", normalizedId);
    const entry = readQueueEntry(runningPath, "running");
    if (!entry) throw admissionError("running_job_missing", "Running backup job was not found.", 409);
    const unknownJob = {
      ...entry.raw,
      status: "running",
      updatedAt: new Date(timestampMs(now)).toISOString(),
      finishedAt: null,
      resultSummary: normalizedSummary,
      exitCode: normalizedExitCode,
    };
    delete unknownJob.logPath;
    writeJsonAtomic(runningPath, unknownJob);
    return Object.freeze({
      marked: true,
      exitCode: normalizedExitCode,
      job: Object.freeze({ ...parseBackupJobDocument(unknownJob), exitCode: normalizedExitCode }),
      runningPath,
    });
  });
}

export function pruneBackupQueue({ jobsDir, logDir = "", policy: policyInput = {}, now = Date.now() }) {
  const policy = normalizeBackupQueuePolicy(policyInput);
  const root = prepareQueueRoot(jobsDir);
  return withQueueLock(root, policy, () => Object.freeze(pruneTerminalJobsUnlocked(root, logDir, policy, timestampMs(now))));
}

function withQueueLock(root, policy, action) {
  const lockPath = path.join(root, LOCK_DIRECTORY);
  const token = randomBytes(24).toString("hex");
  const startedAt = Date.now();
  while (true) {
    try {
      mkdirSync(lockPath, { mode: 0o700 });
      ensureBackupQueueDirectoryOwnership(lockPath);
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw admissionError("queue_lock_failed", "Backup queue lock could not be created.", 503, { cause: error?.code || "error" });
      let lockStat;
      try { lockStat = lstatSync(lockPath); } catch { continue; }
      if (!lockStat.isDirectory() || lockStat.isSymbolicLink()) throw admissionError("queue_lock_invalid", "Backup queue lock path is not a real directory.", 503);
      if (Date.now() - startedAt >= policy.lockTimeoutMs) throw admissionError("queue_busy", "Backup queue admission lock is busy.", 503);
      Atomics.wait(waitArray, 0, 0, 10);
    }
  }
  const ownerPath = path.join(lockPath, "owner.json");
  try {
    const identity = backupQueueSharedIdentityFromEnvironment();
    const ownerDescriptor = openSync(ownerPath, "wx", 0o600);
    try {
      writeFileSync(ownerDescriptor, `${JSON.stringify({ token, pid: process.pid, createdAt: new Date().toISOString() })}\n`, "utf8");
      applyBackupQueueFileOwnership(ownerDescriptor, identity);
      fsyncSync(ownerDescriptor);
    } finally {
      closeSync(ownerDescriptor);
    }
    return action();
  } finally {
    try {
      const owner = JSON.parse(readFileSync(ownerPath, "utf8"));
      if (owner.token !== token) throw new Error("lock owner mismatch");
      unlinkSync(ownerPath);
      rmdirSync(lockPath);
    } catch (error) {
      throw admissionError("queue_lock_release_failed", "Backup queue lock ownership could not be released safely.", 503, { cause: error?.code || error?.name || "error" });
    }
  }
}

function prepareQueueRoot(jobsDir) {
  const root = path.resolve(String(jobsDir || ""));
  if (!String(jobsDir || "").trim()) throw admissionError("queue_root_missing", "Backup queue root is required.", 503);
  ensureRealDirectory(root);
  for (const status of STATUS_NAMES) ensureRealDirectory(path.join(root, status));
  ensureRealDirectory(path.join(root, LEASE_DIRECTORY));
  return root;
}

function ensureRealDirectory(directory) {
  const identity = backupQueueSharedIdentityFromEnvironment();
  if (!existsSync(directory)) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw admissionError("queue_path_invalid", "Backup queue paths must be real directories.", 503);
  ensureBackupQueueDirectoryOwnership(directory, identity);
}

function readQueueSnapshot(root, policy) {
  const snapshot = { queued: [], running: [], done: [], failed: [], leases: [] };
  let seen = 0;
  for (const status of STATUS_NAMES) {
    const directory = path.join(root, status);
    const names = readdirSync(directory).filter((name) => name.endsWith(".json")).sort();
    seen += names.length;
    if (seen > policy.maxScanEntries) throw admissionError("queue_scan_bound", "Backup queue inventory exceeds its fail-closed scan bound.", 503);
    snapshot[status] = names.map((name) => {
      const entry = readQueueEntry(path.join(directory, name), status);
      if (!entry) throw admissionError("queue_entry_missing", "Backup queue entry changed during locked inventory.", 503);
      return entry;
    });
  }
  snapshot.leases = readSchedulerLeases(root, policy);
  seen += snapshot.leases.length;
  if (seen > policy.maxScanEntries) throw admissionError("queue_scan_bound", "Backup queue inventory exceeds its fail-closed scan bound.", 503);
  return snapshot;
}

function readSchedulerLeases(root, policy) {
  const directory = path.join(root, LEASE_DIRECTORY);
  const names = readdirSync(directory).filter((name) => name.endsWith(".json")).sort();
  if (names.length > policy.maxScanEntries) throw admissionError("queue_scan_bound", "Scheduler lease inventory exceeds its fail-closed scan bound.", 503);
  return names.map((name) => {
    const lease = readSchedulerLease(path.join(directory, name));
    if (!lease || name !== `${lease.id}.json`) throw admissionError("scheduler_lease_invalid", "Scheduler lease filename does not match its immutable identifier.", 503);
    return lease;
  });
}

function readSchedulerLease(filePath) {
  if (!existsSync(filePath)) return null;
  const stat = lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw admissionError("scheduler_lease_invalid", "Scheduler leases must be regular files.", 503);
  let source;
  try { source = JSON.parse(readFileSync(filePath, "utf8")); } catch { throw admissionError("scheduler_lease_invalid", "Scheduler lease is invalid JSON.", 503); }
  if (source?.schema !== LEASE_SCHEMA) throw admissionError("scheduler_lease_invalid", "Scheduler lease schema is invalid.", 503);
  const id = String(source.id || "");
  const token = String(source.token || "");
  const kind = requireLeaseKind(source.kind);
  const createdAt = new Date(source.createdAt);
  if (!/^lease-[a-f0-9]{32}$/.test(id) || !/^[a-f0-9]{48}$/.test(token) || !Number.isFinite(createdAt.getTime()) || !Number.isSafeInteger(source.pid) || source.pid < 1) {
    throw admissionError("scheduler_lease_invalid", "Scheduler lease identity is invalid.", 503);
  }
  return Object.freeze({ schema: LEASE_SCHEMA, id, token, kind, pid: source.pid, createdAt: createdAt.toISOString() });
}

function readQueueEntry(filePath, expectedStatus) {
  if (!existsSync(filePath)) return null;
  const stat = lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw admissionError("queue_entry_invalid", "Backup queue entries must be regular files.", 503);
  let raw;
  let job;
  try {
    raw = JSON.parse(readFileSync(filePath, "utf8"));
    job = parseBackupJobDocument(raw);
  } catch (error) {
    throw admissionError("queue_entry_invalid", "Backup queue contains an invalid job document.", 503, { cause: error?.message || "invalid JSON" });
  }
  if (job.status !== expectedStatus) throw admissionError("queue_state_mismatch", "Backup job status does not match its queue directory.", 503, { jobId: job.id, expectedStatus, actualStatus: job.status });
  if (path.basename(filePath) !== `${job.id}.json`) throw admissionError("queue_filename_mismatch", "Backup job filename does not match its immutable identifier.", 503);
  return { name: path.basename(filePath), path: filePath, raw, job, activeKey: canonicalBackupActiveKey(job) };
}

function readAdmissionLedger(root, policy, now) {
  const ledgerPath = path.join(root, LEDGER_FILE);
  if (!existsSync(ledgerPath)) return { schema: LEDGER_SCHEMA, events: [] };
  let source;
  try { source = JSON.parse(readFileSync(ledgerPath, "utf8")); } catch { throw admissionError("admission_ledger_invalid", "Backup admission ledger is invalid JSON.", 503); }
  if (source?.schema !== LEDGER_SCHEMA || !Array.isArray(source.events)) throw admissionError("admission_ledger_invalid", "Backup admission ledger schema is invalid.", 503);
  if (source.events.length > policy.maxLedgerEntries) throw admissionError("admission_ledger_full", "Backup admission ledger exceeds its fail-closed bound.", 503);
  const events = source.events.map(validateLedgerEvent)
    .filter((event) => now - new Date(event.admittedAt).getTime() < policy.principalWindowMs);
  const compacted = { schema: LEDGER_SCHEMA, events };
  if (events.length !== source.events.length) writeJsonAtomic(ledgerPath, compacted);
  return compacted;
}

function validateLedgerEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) throw admissionError("admission_ledger_invalid", "Backup admission ledger contains an invalid event.", 503);
  const admittedAt = new Date(event.admittedAt);
  if (!Number.isFinite(admittedAt.getTime())) throw admissionError("admission_ledger_invalid", "Backup admission ledger contains an invalid timestamp.", 503);
  const principal = requirePrincipal(event.principal);
  const jobId = requireJobId(event.jobId);
  if (!/^[a-f0-9]{64}$/.test(String(event.activeKey || ""))) throw admissionError("admission_ledger_invalid", "Backup admission ledger contains an invalid active key.", 503);
  if (!/^[a-z][a-z0-9.-]{1,79}$/.test(String(event.routeOperationId || ""))) throw admissionError("admission_ledger_invalid", "Backup admission ledger contains an invalid route operation.", 503);
  return Object.freeze({ admittedAt: admittedAt.toISOString(), principal, jobId, activeKey: event.activeKey, routeOperationId: event.routeOperationId });
}

function pruneTerminalJobsUnlocked(root, logDir, policy, now) {
  const removed = [];
  for (const status of TERMINAL_STATUS_NAMES) {
    const directory = path.join(root, status);
    const names = readdirSync(directory).filter((name) => name.endsWith(".json"));
    if (names.length > policy.maxScanEntries) throw admissionError("queue_scan_bound", "Terminal queue inventory exceeds its fail-closed scan bound.", 503);
    const entries = names.map((name) => readQueueEntry(path.join(directory, name), status));
    entries.sort((left, right) => terminalTime(right.job) - terminalTime(left.job) || right.name.localeCompare(left.name));
    const remove = entries.filter((entry, index) => now - terminalTime(entry.job) > policy.terminalMaxAgeMs || index >= policy.maxTerminalPerStatus);
    for (const entry of remove) {
      const candidateLog = entry.raw.logPath;
      const ownedLog = candidateLog && logDir ? ownedJobLogPath(logDir, entry.job.id, candidateLog) : "";
      unlinkSync(entry.path);
      if (ownedLog) unlinkSync(ownedLog);
      removed.push(Object.freeze({ status, jobId: entry.job.id }));
    }
  }
  return removed;
}

function ownedJobLogPath(logDir, jobId, candidate) {
  const expected = safeJobLogPath(logDir, jobId);
  if (path.resolve(String(candidate)) !== expected || !existsSync(expected)) return "";
  const stat = lstatSync(expected);
  if (!stat.isFile() || stat.isSymbolicLink()) throw admissionError("job_log_invalid", "Terminal job log is not a regular owned file.", 503);
  return expected;
}

function safeJobLogPath(logDir, jobId) {
  const root = path.resolve(String(logDir || ""));
  if (!String(logDir || "").trim()) throw admissionError("log_root_missing", "Backup scheduler log root is required.", 503);
  ensureRealDirectory(root);
  return path.join(root, `manual-backup-${requireJobId(jobId)}.log`);
}

function queueFilePath(root, status, jobId) {
  if (!STATUS_NAMES.includes(status)) throw admissionError("invalid_queue_status", "Invalid backup queue status directory.", 503);
  return path.join(root, status, `${requireJobId(jobId)}.json`);
}

function writeJsonExclusiveAtomic(filePath, value) {
  if (existsSync(filePath)) throw admissionError("job_id_conflict", "Backup queue target already exists.", 409);
  writeJsonAtomic(filePath, value, true);
}

function writeJsonAtomic(filePath, value, exclusiveTarget = false) {
  const directory = path.dirname(filePath);
  const identity = backupQueueSharedIdentityFromEnvironment();
  const temporary = path.join(directory, `.${path.basename(filePath)}.tmp-${process.pid}-${randomBytes(12).toString("hex")}`);
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    applyBackupQueueFileOwnership(descriptor, identity);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    if (exclusiveTarget && existsSync(filePath)) throw admissionError("job_id_conflict", "Backup queue target already exists.", 409);
    renameSync(temporary, filePath);
    fsyncDirectory(directory);
  } catch (error) {
    if (descriptor !== undefined) try { closeSync(descriptor); } catch { /* retain original error */ }
    if (existsSync(temporary)) try { unlinkSync(temporary); } catch { /* retain original error */ }
    throw error;
  }
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = openSync(directory, "r");
    fsyncSync(descriptor);
  } catch {
    // Some filesystems reject directory fsync. The file itself is still synced.
  } finally {
    if (descriptor !== undefined) try { closeSync(descriptor); } catch { /* no-op */ }
  }
}

function terminalTime(job) {
  const value = new Date(job.finishedAt || job.updatedAt || job.createdAt).getTime();
  if (!Number.isFinite(value)) throw admissionError("queue_entry_invalid", "Terminal job has an invalid lifecycle timestamp.", 503);
  return value;
}

function requirePrincipal(value) {
  const principal = String(value || "").trim();
  if (!principal || principal.length > 200 || !/^[A-Za-z0-9@._:+/-]+$/.test(principal)) {
    throw admissionError("principal_invalid", "Authenticated backup principal is invalid.", 403);
  }
  return principal;
}

function requireJobId(value) {
  const jobId = String(value || "").trim();
  if (!/^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/.test(jobId)) throw admissionError("job_id_invalid", "Backup job identifier is invalid.", 422);
  return jobId;
}

function requireLeaseKind(value) {
  const kind = String(value || "").trim();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(kind)) throw admissionError("scheduler_lease_invalid", "Scheduler lease kind is invalid.", 422);
  return kind;
}

function parseLeaseHandle(value) {
  const match = /^(lease-[a-f0-9]{32})\.([a-f0-9]{48})$/.exec(String(value || ""));
  if (!match) throw admissionError("scheduler_lease_owner_mismatch", "Scheduler lease handle is invalid.", 503);
  return Object.freeze({ id: match[1], token: match[2] });
}

function timestampMs(value) {
  const result = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isFinite(result) || result < 0) throw new Error("Invalid queue clock value.");
  return result;
}

function boundedInteger(value, fallback, minimum, maximum, label) {
  const candidate = value === undefined || value === null || value === "" ? fallback : Number(value);
  if (!Number.isSafeInteger(candidate) || candidate < minimum || candidate > maximum) throw new Error(`Invalid ${label}.`);
  return candidate;
}

function seconds(value) {
  if (value === undefined || value === null || value === "") return undefined;
  return Number(value) * 1000;
}

function days(value) {
  if (value === undefined || value === null || value === "") return undefined;
  return Number(value) * 24 * 60 * 60 * 1000;
}

function admissionError(code, message, status = 503, details = {}) {
  return new BackupQueueAdmissionError(code, message, status, details);
}
