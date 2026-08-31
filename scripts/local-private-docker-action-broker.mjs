#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

import {
  ACTIONS,
  MAX_REQUEST_BYTES,
  RESPONSE_SCHEMA,
  RESULT_SCHEMA,
  canonicalJson,
  normalizeActionRequest,
  sha256,
  signActionResponse,
} from "./docker-action-contract.mjs";
import { defaultClaimedJobPolicy, readClaimedBackupJob } from "./docker-action-client.mjs";
import {
  LOCAL_PRIVATE_ALLOWED_ACTIONS,
  readCanonicalAdmission,
  verifyAdmissionDocument,
} from "./local-private-backup-admission.mjs";

const DEFAULT_SOCKET = "/run/platform/docker-action-broker/broker.sock";
const DEFAULT_STATE_DIR = "/var/lib/platform/docker-action-broker";
const DEFAULT_ADMISSION = "/run/platform/docker-action-broker/client/admission.json";
const DEFAULT_CAPABILITY_DIR = "/run/platform/docker-action-broker/client";
const DEFAULT_PUBLIC_KEY = "/opt/platform-infrastructure/policy/local-private-backup-admission.pub.pem";
const DEFAULT_RENDER = "/run/platform/local-private-input/combined-render.yaml";
const DEFAULT_SIGNING_KEY = "/run/platform/local-private-input/backup_signing_keys";
const DEFAULT_JOBS_ROOT = "/var/www/project-state/backup-jobs";
const DEFAULT_INFRA_OPS = "/opt/platform-infrastructure/scripts/infra-ops.mjs";
const ACTIVE_LOCK = "active-operation.json";
const TERMINAL_RECEIPT_SCHEMA = "platform.local-private-broker-terminal/v1";
const MAX_TERMINAL_RECEIPTS = 4096;
const MAX_RESPONSE_OUTPUT = 64 * 1024;
const OPERATION_TIMEOUT_MS = 4 * 60 * 60_000;
const SERVICE_UID = process.getuid();
const SERVICE_GID = process.getgid();

function brokerError(statusCode, errorCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.errorCode = errorCode;
  return error;
}

function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== SERVICE_UID || stat.gid !== SERVICE_GID
    || (stat.mode & 0o777) !== 0o700) throw new Error(`private broker directory rejected: ${directory}`);
}

function readProtectedBytes(file, { maximumBytes = 4096, minimumBytes = 32 } = {}) {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.uid !== SERVICE_UID || before.gid !== SERVICE_GID
      || (before.mode & 0o077) !== 0 || (before.mode & 0o400) === 0
      || before.size < minimumBytes || before.size > maximumBytes) {
      throw new Error(`protected broker input rejected: ${file}`);
    }
    const first = Buffer.alloc(before.size);
    const second = Buffer.alloc(before.size);
    if (fs.readSync(descriptor, first, 0, first.length, 0) !== first.length
      || fs.readSync(descriptor, second, 0, second.length, 0) !== second.length) {
      throw new Error(`protected broker input changed: ${file}`);
    }
    const after = fs.fstatSync(descriptor);
    if (!["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"]
      .every((field) => Object.is(before[field], after[field]))
      || !crypto.timingSafeEqual(first, second)) throw new Error(`protected broker input changed: ${file}`);
    return first;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function writeExclusiveCanonical(file, value) {
  const descriptor = fs.openSync(file, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, Buffer.from(`${canonicalJson(value)}\n`));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  syncDirectory(path.dirname(file));
}

function writeExclusiveBytes(file, bytes) {
  const descriptor = fs.openSync(file, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  syncDirectory(path.dirname(file));
}

function syncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function readCanonicalState(file) {
  const bytes = readProtectedBytes(file, { minimumBytes: 2, maximumBytes: 64 * 1024 });
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) throw new Error(`broker state is not canonical JSON: ${file}`);
  return value;
}

function replaceCanonical(file, value) {
  const temporary = `${file}.${process.pid}-${crypto.randomBytes(8).toString("hex")}.tmp`;
  writeExclusiveCanonical(temporary, value);
  fs.renameSync(temporary, file);
  syncDirectory(path.dirname(file));
}

function replaceProtectedBytes(file, expected, replacement) {
  const current = readProtectedBytes(file, { minimumBytes: 2, maximumBytes: 64 * 1024 });
  if (current.length !== expected.length || !crypto.timingSafeEqual(current, expected)) {
    throw new Error("protected rclone configuration changed before refresh commit");
  }
  const parent = path.dirname(file);
  const parentStat = fs.lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()
    || parentStat.uid !== SERVICE_UID || parentStat.gid !== SERVICE_GID
    || (parentStat.mode & 0o022) !== 0) {
    throw new Error("rclone configuration parent directory is not private");
  }
  const temporary = path.join(parent, `.rclone-refresh-${process.pid}-${crypto.randomBytes(8).toString("hex")}.tmp`);
  writeExclusiveBytes(temporary, replacement);
  fs.renameSync(temporary, file);
  syncDirectory(parent);
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

function rcloneTokenRecord(bytes) {
  const text = decodeUtf8(bytes, "rclone configuration");
  const lines = text.split("\n");
  let section = "";
  let record = null;
  for (let index = 0; index < lines.length; index += 1) {
    const sectionMatch = lines[index].match(/^\s*\[([^\]]+)]\s*$/);
    if (sectionMatch) {
      section = sectionMatch[1];
      continue;
    }
    const tokenMatch = lines[index].match(/^(\s*token\s*=\s*)(\{.*})(\s*)$/);
    if (!tokenMatch) continue;
    if (section !== "platform-onedrive" || record) {
      throw new Error("rclone token must exist exactly once in platform-onedrive");
    }
    let token;
    try { token = JSON.parse(tokenMatch[2]); } catch { throw new Error("rclone token JSON is invalid"); }
    if (!token || typeof token !== "object" || Array.isArray(token)
      || Object.getPrototypeOf(token) !== Object.prototype) {
      throw new Error("rclone token JSON must be a plain object");
    }
    record = { index, lines, prefix: tokenMatch[1], suffix: tokenMatch[3], text, token };
  }
  if (!record) throw new Error("platform-onedrive rclone token is missing");
  return record;
}

export function validateRcloneTokenRefresh(beforeBytes, afterBytes) {
  const before = rcloneTokenRecord(beforeBytes);
  const after = rcloneTokenRecord(afterBytes);
  const beforeRedacted = [...before.lines];
  const afterRedacted = [...after.lines];
  beforeRedacted[before.index] = `${before.prefix}<oauth-token>${before.suffix}`;
  afterRedacted[after.index] = `${after.prefix}<oauth-token>${after.suffix}`;
  if (beforeRedacted.join("\n") !== afterRedacted.join("\n")) {
    throw new Error("rclone refresh attempted to modify configuration outside the OAuth token");
  }
  const beforeKeys = Object.keys(before.token).sort();
  const afterKeys = Object.keys(after.token).sort();
  if (canonicalJson(beforeKeys) !== canonicalJson(afterKeys)) {
    throw new Error("rclone refresh changed the OAuth token schema");
  }
  const mutable = new Set(["access_token", "expiry", "expires_in", "refresh_token"]);
  for (const key of beforeKeys) {
    if (!mutable.has(key) && canonicalJson(before.token[key]) !== canonicalJson(after.token[key])) {
      throw new Error(`rclone refresh changed immutable OAuth field ${key}`);
    }
  }
  for (const key of ["access_token", "refresh_token"]) {
    if (typeof after.token[key] !== "string" || after.token[key].length < 16 || after.token[key].length > 16 * 1024) {
      throw new Error(`rclone refreshed ${key} is invalid`);
    }
  }
  if (typeof after.token.expiry !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(after.token.expiry)
    || !Number.isFinite(Date.parse(after.token.expiry))) {
    throw new Error("rclone refreshed expiry is invalid");
  }
  return Buffer.from(after.text);
}

function stageRcloneRefresh(originalFile, stateDir) {
  const directory = path.join(stateDir, "rclone-refresh");
  ensurePrivateDirectory(directory);
  if (fs.readdirSync(directory).length !== 0) {
    const error = brokerError(503, "OPERATION_RECONCILIATION_REQUIRED", "a prior rclone refresh requires reconciliation");
    error.preserveOperation = true;
    throw error;
  }
  const original = readProtectedBytes(originalFile, { minimumBytes: 2, maximumBytes: 64 * 1024 });
  const stagedFile = path.join(directory, "rclone.conf");
  writeExclusiveBytes(stagedFile, original);
  return Object.freeze({
    stagedFile,
    commit() {
      try {
        const staged = readProtectedBytes(stagedFile, { minimumBytes: 2, maximumBytes: 64 * 1024 });
        const replacement = validateRcloneTokenRefresh(original, staged);
        replaceProtectedBytes(originalFile, original, replacement);
        fs.unlinkSync(stagedFile);
        syncDirectory(directory);
      } catch (cause) {
        const error = brokerError(503, "RCLONE_REFRESH_RECONCILIATION_REQUIRED", "rclone OAuth refresh requires reconciliation");
        error.cause = cause;
        error.preserveOperation = true;
        throw error;
      }
    },
  });
}

function capabilityPath(capabilityDir, action) {
  return path.join(capabilityDir, ACTIONS[action].capabilityFile.split("/").at(-1));
}

export function loadLocalPrivateTrust(environment = process.env, now = Date.now()) {
  const admissionFile = environment.DOCKER_ACTION_LOCAL_ADMISSION_FILE || DEFAULT_ADMISSION;
  const capabilityDir = environment.DOCKER_ACTION_LOCAL_CAPABILITY_DIR || DEFAULT_CAPABILITY_DIR;
  const renderFile = environment.DOCKER_ACTION_LOCAL_RENDER_FILE || DEFAULT_RENDER;
  const signingKeyFile = environment.BACKUP_SIGNING_KEYS_FILE || DEFAULT_SIGNING_KEY;
  const capabilityFiles = Object.fromEntries(LOCAL_PRIVATE_ALLOWED_ACTIONS.map(
    (action) => [action, capabilityPath(capabilityDir, action)],
  ));
  for (const file of [admissionFile, renderFile, signingKeyFile, ...Object.values(capabilityFiles)]) {
    readProtectedBytes(file, {
      maximumBytes: file === admissionFile ? 64 * 1024 : file === renderFile ? 16 * 1024 * 1024 : 4 * 1024,
      minimumBytes: file === renderFile ? 2 : 32,
    });
  }
  const verified = verifyAdmissionDocument(readCanonicalAdmission(admissionFile), {
    backupSigningKeyFile: signingKeyFile,
    capabilityFiles,
    now,
    publicKeyPem: fs.readFileSync(environment.DOCKER_ACTION_LOCAL_PUBLIC_KEY_FILE || DEFAULT_PUBLIC_KEY),
    renderFile,
  });
  const offsiteFiles = Object.freeze({
    rcloneConfig: verified.payload.resources.offsite.rcloneConfigPath,
    resticPassword: verified.payload.resources.offsite.resticPasswordPath,
  });
  readProtectedBytes(offsiteFiles.rcloneConfig, { maximumBytes: 64 * 1024, minimumBytes: 2 });
  readProtectedBytes(offsiteFiles.resticPassword);
  return Object.freeze({
    activation: null,
    capabilityFiles: Object.freeze(capabilityFiles),
    document: verified.document,
    intent: Object.freeze({
      activationBundleSha256: sha256(canonicalJson(verified.document)),
      allowedActions: Object.freeze([...verified.payload.allowedActions]),
      candidateId: verified.payload.candidateId,
      combinedRenderSha256: verified.payload.combinedRenderSha256,
      dastChainSha256: "0".repeat(64),
      environment: verified.payload.environment,
      generation: verified.payload.generation,
      intentId: verified.payload.admissionId,
      releaseId: verified.payload.releaseId,
      targetId: verified.payload.targetId,
    }),
    offsiteFiles,
    receipt: verified.payload,
    receiptDigest: verified.receiptDigest,
  });
}

export function admitGeneration(stateDir, trusted) {
  const file = path.join(stateDir, "active-admission.json");
  const admissionSha256 = sha256(canonicalJson(trusted.document));
  const next = { admissionSha256, generation: trusted.intent.generation };
  if (!fs.existsSync(file)) {
    if (next.generation !== 1 || trusted.receipt.previousAdmissionSha256 !== "0".repeat(64)) {
      throw brokerError(409, "ADMISSION_GENESIS_REJECTED", "local admission has no valid generation-one genesis");
    }
    writeExclusiveCanonical(file, next);
    return;
  }
  const current = readCanonicalState(file);
  if (current.generation === next.generation && current.admissionSha256 === next.admissionSha256) return;
  if (!Number.isSafeInteger(current.generation) || !/^[a-f0-9]{64}$/.test(String(current.admissionSha256 ?? ""))
    || next.generation !== current.generation + 1
    || trusted.receipt.previousAdmissionSha256 !== current.admissionSha256) {
    throw brokerError(409, "ADMISSION_TRANSITION_REJECTED", "local admission rollback, gap or substitution rejected");
  }
  replaceCanonical(file, next);
}

function inspectedContainerImageId(container) {
  const value = execFileSync("docker", ["inspect", "--format", "{{.Image}}", container], {
    encoding: "utf8",
    maxBuffer: 4096,
    timeout: 10_000,
  }).trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) throw new Error(`container image identity rejected: ${container}`);
  return value;
}

function inspectedImageId(image) {
  const value = execFileSync("docker", ["image", "inspect", "--format", "{{.Id}}", image], {
    encoding: "utf8",
    maxBuffer: 4096,
    timeout: 10_000,
  }).trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) throw new Error(`image identity rejected: ${image}`);
  return value;
}

export function verifyRuntimeImages(trusted, { requireRestic = false, requireScheduler = false } = {}) {
  const ownContainer = String(process.env.HOSTNAME ?? "").trim();
  if (!/^[a-f0-9]{12,64}$/.test(ownContainer)
    || inspectedContainerImageId(ownContainer) !== trusted.receipt.brokerImageId) {
    throw brokerError(403, "BROKER_IMAGE_SUBSTITUTION_REJECTED", "broker runtime image differs from signed admission");
  }
  if (requireScheduler
    && inspectedContainerImageId("gf-backup-scheduler") !== trusted.receipt.schedulerImageId) {
    throw brokerError(403, "SCHEDULER_IMAGE_SUBSTITUTION_REJECTED", "scheduler runtime image differs from signed admission");
  }
  if (requireRestic
    && inspectedImageId(trusted.receipt.resources.offsite.resticImageId)
      !== trusted.receipt.resources.offsite.resticImageId) {
    throw brokerError(403, "RESTIC_IMAGE_SUBSTITUTION_REJECTED", "Restic helper image differs from signed admission");
  }
}

function purgeReplay(replayDir, now) {
  const names = fs.readdirSync(replayDir);
  if (names.length > 4096) throw brokerError(503, "REPLAY_CAPACITY_EXHAUSTED", "broker replay capacity exhausted");
  for (const name of names) {
    if (!/^[a-f0-9]{64}$/.test(name)) throw new Error("unexpected replay ledger entry");
    const file = path.join(replayDir, name);
    const entry = readCanonicalState(file);
    if (!Number.isFinite(Date.parse(String(entry.expiresAt ?? "")))) throw new Error("invalid replay expiry");
    if (Date.parse(entry.expiresAt) < now) {
      fs.unlinkSync(file);
      syncDirectory(replayDir);
    }
  }
}

export function consumeReplay(stateDir, request, now) {
  const replayDir = path.join(stateDir, "replay");
  ensurePrivateDirectory(replayDir);
  purgeReplay(replayDir, now);
  const id = sha256(`${request.requestId}\0${request.nonce}`);
  try {
    writeExclusiveCanonical(path.join(replayDir, id), { expiresAt: new Date(now + 24 * 60 * 60_000).toISOString() });
  } catch (error) {
    if (error?.code === "EEXIST") throw brokerError(409, "REQUEST_REPLAY_REJECTED", "request replay rejected");
    throw error;
  }
}

export function acquireOperation(stateDir, request) {
  const terminalDir = path.join(stateDir, "terminal");
  ensurePrivateDirectory(terminalDir);
  const terminalNames = fs.readdirSync(terminalDir);
  if (terminalNames.length >= MAX_TERMINAL_RECEIPTS
    || terminalNames.some((name) => !/^[a-f0-9]{64}\.json$/.test(name))) {
    throw brokerError(503, "TERMINAL_RECEIPT_CAPACITY_EXHAUSTED", "broker terminal receipt capacity requires reconciliation");
  }
  const file = path.join(stateDir, ACTIVE_LOCK);
  const requestSha256 = sha256(canonicalJson(request));
  const terminalFile = path.join(terminalDir, `${requestSha256}.json`);
  try {
    writeExclusiveCanonical(file, {
      action: request.action,
      admittedAt: new Date().toISOString(),
      requestId: request.requestId,
      requestSha256,
      terminalFile: path.relative(stateDir, terminalFile),
    });
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw brokerError(409, "OPERATION_RECONCILIATION_REQUIRED", "a prior Docker action is active or requires reconciliation");
    }
    throw error;
  }
  let terminalRecorded = false;
  return Object.freeze({
    recordTerminal(response) {
      writeExclusiveCanonical(terminalFile, {
        recordedAt: new Date().toISOString(),
        request: {
          action: request.action,
          parameters: request.parameters ?? {},
        },
        requestId: request.requestId,
        requestSha256,
        response,
        schema: TERMINAL_RECEIPT_SCHEMA,
      });
      terminalRecorded = true;
    },
    release() {
      if (!terminalRecorded) throw new Error("active operation has no durable terminal receipt");
      const state = readCanonicalState(file);
      if (state.requestId !== request.requestId || state.requestSha256 !== requestSha256) {
        throw new Error("active operation lock identity changed");
      }
      fs.unlinkSync(file);
      syncDirectory(stateDir);
    },
  });
}

export async function runFixedOperation(action, parameters, {
  jobsRoot, infraOps, signal, stateDir, trusted,
} = {}) {
  const args = [infraOps];
  let outputSchema;
  let phaseId;
  if (action === "backup.catalog") {
    args.push("backup-platform-catalog");
    outputSchema = "platform.backup-catalog/v1";
    phaseId = "catalog.capture";
  } else if (action === "backup.job.execute") {
    const claimed = await readClaimedBackupJob(parameters.jobFileName, defaultClaimedJobPolicy({
      BACKUP_SCHEDULER_JOBS_DIR: jobsRoot,
      DOCKER_ACTION_LOCAL_ADMISSION_FILE: process.env.DOCKER_ACTION_LOCAL_ADMISSION_FILE || DEFAULT_ADMISSION,
    }));
    if (canonicalJson(claimed) !== canonicalJson(parameters)) {
      throw brokerError(409, "CLAIMED_JOB_CHANGED", "claimed job identity changed after client admission");
    }
    if (parameters.jobOperation !== "backup") {
      throw brokerError(403, "RESTORE_JOB_NOT_ALLOWED", "LOCAL_PRIVATE queue execution is restricted to backup jobs");
    }
    args.push("execute-backup-job", "--jobFile", path.join(jobsRoot, "running", parameters.jobFileName));
    outputSchema = "platform.backup-job-result/v1";
    phaseId = "job.backup.capture";
  } else if (action === "backup.offsite.sync") {
    args.push("offsite-backup-restic");
    outputSchema = "platform.offsite-backup-receipt/v1";
    phaseId = "offsite.sync";
  } else {
    throw brokerError(403, "ACTION_NOT_ALLOWED", "action is outside the LOCAL_PRIVATE backup surface");
  }

  const childEnvironment = { ...process.env };
  let stagedRclone = null;
  delete childEnvironment.NODE_OPTIONS;
  delete childEnvironment.NODE_PATH;
  if (action === "backup.offsite.sync") {
    stagedRclone = stageRcloneRefresh(trusted.offsiteFiles.rcloneConfig, stateDir);
    childEnvironment.HOME = "/tmp";
    childEnvironment.XDG_CACHE_HOME = "/tmp/.cache";
    childEnvironment.PLATFORM_CLOSED_HOST_PATH_MAPPINGS = "1";
    childEnvironment.RCLONE_CONFIG = stagedRclone.stagedFile;
    childEnvironment.RCLONE_CONFIG_WRITABLE = "1";
    childEnvironment.RESTIC_DOCKER_USER = `${SERVICE_UID}:${SERVICE_GID}`;
    childEnvironment.RESTIC_HOSTNAME = "platform-infrastructure";
    childEnvironment.RESTIC_IMAGE = trusted.receipt.resources.offsite.resticImageId;
    childEnvironment.RESTIC_PASSWORD_FILE = trusted.offsiteFiles.resticPassword;
    childEnvironment.RESTIC_REPOSITORY = trusted.receipt.resources.offsite.repository;
    childEnvironment.RESTIC_REQUIRE_IMMUTABLE_IMAGE = "true";
  }
  let execution;
  try {
    execution = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, args, {
      env: childEnvironment,
      stdio: ["ignore", "pipe", "pipe"],
    });
      let output = Buffer.alloc(0);
      let killedForOutput = false;
      const collect = (chunk) => {
        output = Buffer.concat([output, chunk]);
        if (output.length > MAX_RESPONSE_OUTPUT) {
          killedForOutput = true;
          child.kill("SIGTERM");
        }
      };
      child.stdout.on("data", collect);
      child.stderr.on("data", collect);
      child.once("error", reject);
      child.once("close", (code, childSignal) => {
        if (killedForOutput || childSignal || signal.aborted) {
          const error = brokerError(503, "OPERATION_RECONCILIATION_REQUIRED", "backup operation outcome requires reconciliation");
          error.preserveOperation = true;
          reject(error);
        } else if (code !== 0) reject(brokerError(502, "BACKUP_OPERATION_FAILED", `backup operation failed with exit ${code ?? "unknown"}`));
        else resolve({ code });
      });
      signal.addEventListener("abort", () => child.kill("SIGTERM"), { once: true });
    });
  } finally {
    if (stagedRclone) stagedRclone.commit();
  }
  const operationOutput = {
    executedAt: new Date().toISOString(),
    schema: outputSchema,
    status: "completed",
    ...(parameters.jobId ? { jobId: parameters.jobId, jobOperation: parameters.jobOperation } : {}),
  };
  return {
    action,
    job: action === "backup.job.execute" ? parameters : null,
    phases: [{
      output: operationOutput,
      outputSchema,
      outputSha256: sha256(canonicalJson(operationOutput)),
      phaseId,
      status: "completed",
    }],
    schema: RESULT_SCHEMA,
    status: execution.code === 0 ? "completed" : "failed",
  };
}

function signedResponse(request, capabilityKey, { error, result }) {
  const normalizedResult = result ?? null;
  return signActionResponse({
    action: request.action,
    errorCode: error ? String(error.errorCode || "BROKER_OPERATION_REJECTED") : null,
    requestId: request.requestId,
    requestSha256: sha256(canonicalJson(request)),
    result: normalizedResult,
    resultSha256: sha256(canonicalJson(normalizedResult)),
    schema: RESPONSE_SCHEMA,
    status: error ? "rejected" : "completed",
    statusCode: error ? Number(error.statusCode || 500) : 200,
  }, capabilityKey);
}

async function handleRequest(frame, environment, now = Date.now()) {
  if (!Buffer.isBuffer(frame) || frame.length < 2 || frame.length > MAX_REQUEST_BYTES) {
    throw brokerError(413, "REQUEST_SIZE_REJECTED", "request size rejected");
  }
  const request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame));
  if (!frame.equals(Buffer.from(canonicalJson(request)))) throw brokerError(400, "REQUEST_CANONICALIZATION_REJECTED", "request is not canonical JSON");
  if (!LOCAL_PRIVATE_ALLOWED_ACTIONS.includes(request.action)) throw brokerError(403, "ACTION_NOT_ALLOWED", "action is outside the LOCAL_PRIVATE backup surface");
  const stateDir = environment.DOCKER_ACTION_BROKER_STATE_DIR || DEFAULT_STATE_DIR;
  ensurePrivateDirectory(stateDir);
  const trusted = loadLocalPrivateTrust(environment, now);
  verifyRuntimeImages(trusted, {
    requireRestic: request.action === "backup.offsite.sync",
    requireScheduler: true,
  });
  admitGeneration(stateDir, trusted);
  const capabilityKey = readProtectedBytes(trusted.capabilityFiles[request.action]);
  normalizeActionRequest(request, trusted, capabilityKey, { now });
  consumeReplay(stateDir, request, now);
  const operation = acquireOperation(stateDir, request);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), OPERATION_TIMEOUT_MS);
  try {
    const result = await runFixedOperation(request.action, request.parameters, {
      infraOps: environment.LOCAL_PRIVATE_INFRA_OPS_FILE || DEFAULT_INFRA_OPS,
      jobsRoot: environment.BACKUP_SCHEDULER_JOBS_DIR || DEFAULT_JOBS_ROOT,
      signal: controller.signal,
      stateDir,
      trusted,
    });
    return { body: signedResponse(request, capabilityKey, { result }), operation };
  } catch (error) {
    if (error?.preserveOperation) throw error;
    return { body: signedResponse(request, capabilityKey, { error }), operation };
  } finally {
    clearTimeout(timeout);
  }
}

export function createLocalPrivateBackupBroker({
  environment = process.env,
  requestHandler = handleRequest,
} = {}) {
  return net.createServer({ allowHalfOpen: true }, (connection) => {
    const chunks = [];
    let length = 0;
    let ended = false;
    connection.on("data", (chunk) => {
      length += chunk.length;
      if (length > MAX_REQUEST_BYTES + 1) connection.destroy();
      else chunks.push(chunk);
    });
    connection.once("end", async () => {
      if (ended) return;
      ended = true;
      try {
        const wire = Buffer.concat(chunks, length);
        if (wire.at(-1) !== 0x0a || wire.subarray(0, -1).includes(0x0a)) throw new Error("request frame delimiter rejected");
        const handled = await requestHandler(wire.subarray(0, -1), environment);
        handled.operation.recordTerminal(handled.body);
        handled.operation.release();
        connection.end(Buffer.from(`${canonicalJson(handled.body)}\n`));
      } catch (error) {
        process.stderr.write(`${error.message ?? error}\n`);
        connection.destroy();
      }
    });
  });
}

export function assertBrokerStateReady(stateDir, now = Date.now()) {
  const active = path.join(stateDir, ACTIVE_LOCK);
  if (!fs.existsSync(active)) return;
  const state = readCanonicalState(active);
  const admittedAt = Date.parse(String(state.admittedAt ?? ""));
  if (!Number.isFinite(admittedAt) || now < admittedAt || now - admittedAt > OPERATION_TIMEOUT_MS + 5 * 60_000) {
    throw new Error("broker operation requires reconciliation");
  }
}

async function main() {
  const socketPath = process.env.DOCKER_ACTION_BROKER_SOCKET || DEFAULT_SOCKET;
  const stateDir = process.env.DOCKER_ACTION_BROKER_STATE_DIR || DEFAULT_STATE_DIR;
  ensurePrivateDirectory(stateDir);
  if (fs.existsSync(path.join(stateDir, ACTIVE_LOCK))) {
    throw new Error("an unresolved LOCAL_PRIVATE broker operation requires reconciliation");
  }
  const trusted = loadLocalPrivateTrust(process.env);
  verifyRuntimeImages(trusted);
  ensurePrivateDirectory(path.dirname(socketPath));
  const existing = fs.lstatSync(socketPath, { throwIfNoEntry: false });
  if (existing) {
    if (!existing.isSocket() || existing.isSymbolicLink()) throw new Error("refusing to replace a non-socket broker path");
    fs.unlinkSync(socketPath);
  }
  const server = createLocalPrivateBackupBroker();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      fs.chmodSync(socketPath, 0o660);
      resolve();
    });
  });
  const stop = () => server.close(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message ?? error}\n`);
    process.exitCode = 1;
  });
}
