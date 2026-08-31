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
import {
  localPrivateBackupChildBindings,
  readLocalPrivateRenderBinding,
} from "./local-private-backup-docker-policy.mjs";
import {
  backupDocumentDigest,
  parseBackupManifestDocument,
} from "../control-center/backup/contracts.mjs";

const DEFAULT_SOCKET = "/run/platform/docker-action-broker/broker.sock";
const DEFAULT_STATE_DIR = "/var/lib/platform/docker-action-broker";
const DEFAULT_ADMISSION = "/run/platform/docker-action-broker/client/admission.json";
const DEFAULT_CAPABILITY_DIR = "/run/platform/docker-action-broker/client";
const DEFAULT_PUBLIC_KEY = "/opt/platform-infrastructure/policy/local-private-backup-admission.pub.pem";
const DEFAULT_RENDER = "/run/platform/local-private-input/combined-render.yaml";
const DEFAULT_SIGNING_KEY = "/run/platform/local-private-input/backup_signing_keys";
const DEFAULT_JOBS_ROOT = "/var/lib/platform-backup-data/backup-jobs";
const DEFAULT_INFRA_OPS = "/opt/platform-infrastructure/scripts/infra-ops.mjs";
const DEFAULT_OFFSITE_RESTORE_PROOF = "/opt/platform-infrastructure/scripts/local-private-offsite-restore-drill.mjs";
const DEFAULT_DATA_ROOT = "/var/lib/platform-backup-data";
const ACTIVE_LOCK = "active-operation.json";
const ACTIVE_OPERATION_SCHEMA = "platform.local-private-broker-active-operation/v2";
const TERMINAL_RECEIPT_SCHEMA = "platform.local-private-broker-terminal/v1";
const OFFSITE_RECONCILIATION_SCHEMA = "platform.local-private-offsite-reconciliation/v1";
const OFFSITE_RESTORE_RECONCILIATION_SCHEMA = "platform.local-private-offsite-restore-reconciliation/v1";
const OFFSITE_RESTORE_RCLONE_RECONCILIATION_SCHEMA = "platform.local-private-offsite-restore-rclone-reconciliation/v1";
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
  const schemaWithoutOptionalLifetime = (keys) => keys.filter((key) => key !== "expires_in");
  if (canonicalJson(schemaWithoutOptionalLifetime(beforeKeys))
    !== canonicalJson(schemaWithoutOptionalLifetime(afterKeys))) {
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
  if (Object.hasOwn(after.token, "expires_in")
    && (!Number.isSafeInteger(after.token.expires_in)
      || after.token.expires_in < 1
      || after.token.expires_in > 31 * 24 * 60 * 60)) {
    throw new Error("rclone refreshed expires_in is invalid");
  }
  return Buffer.from(after.text);
}

function exactRecord(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    throw new Error(`${label} fields are invalid`);
  }
  return value;
}

function exactIsoTime(value, label) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))
    || new Date(Date.parse(value)).toISOString() !== value) {
    throw new Error(`${label} is not an exact ISO timestamp`);
  }
  return Date.parse(value);
}

function validateActiveOperationRecord(active, { action, now = Date.now() } = {}) {
  exactRecord(active, [
    "action", "admittedAt", "request", "requestId", "requestSha256", "schema", "terminalFile",
  ], "active operation");
  const admittedAt = exactIsoTime(active.admittedAt, "active operation admittedAt");
  if (active.schema !== ACTIVE_OPERATION_SCHEMA
    || (action && active.action !== action)
    || active.request?.action !== active.action
    || active.request?.requestId !== active.requestId
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(active.requestId ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(active.requestSha256 ?? ""))
    || active.requestSha256 !== sha256(canonicalJson(active.request))
    || active.terminalFile !== `terminal/${active.requestSha256}.json`
    || admittedAt > now + 30_000) {
    throw new Error("active operation identity is invalid");
  }
  return active;
}

function protectedJson(file, { maximumBytes = 2 * 1024 * 1024 } = {}) {
  const bytes = readProtectedBytes(file, { minimumBytes: 2, maximumBytes });
  return {
    bytes,
    value: JSON.parse(decodeUtf8(bytes, file)),
  };
}

function exactProtectedChild(root, ...segments) {
  const canonicalRoot = fs.realpathSync(root);
  const candidate = path.join(canonicalRoot, ...segments);
  const parent = fs.realpathSync(path.dirname(candidate));
  if (parent !== canonicalRoot && !parent.startsWith(`${canonicalRoot}${path.sep}`)) {
    throw new Error("protected evidence path escaped its fixed root");
  }
  return path.join(parent, path.basename(candidate));
}

export function backupSigningKeyMap(bytes) {
  const text = decodeUtf8(bytes, "backup signing keyring").trim();
  const entries = text.split(",").map((entry) => entry.trim()).filter(Boolean);
  const keys = new Map();
  for (const entry of entries) {
    const separator = entry.indexOf("=");
    const id = separator > 0 ? entry.slice(0, separator).trim() : "";
    const secret = separator > 0 ? entry.slice(separator + 1).trim() : "";
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(id)
      || secret.length < 48 || secret.length > 16 * 1024 || keys.has(id)) {
      throw new Error("backup signing keyring is invalid");
    }
    keys.set(id, secret);
  }
  if (!keys.size) throw new Error("backup signing keyring is empty");
  return keys;
}

export function verifyOffsiteManifest(file, signingKeyFile) {
  const { bytes, value } = protectedJson(file, { maximumBytes: 16 * 1024 * 1024 });
  const manifest = parseBackupManifestDocument(value);
  if (!manifest.signature || manifest.signature.algorithm !== "HMAC-SHA256") {
    throw new Error("off-site manifest signature is missing or unsupported");
  }
  const digest = backupDocumentDigest(manifest);
  if (manifest.signature.digest !== digest) throw new Error("off-site manifest digest is invalid");
  const keys = backupSigningKeyMap(readProtectedBytes(signingKeyFile, {
    minimumBytes: 48,
    maximumBytes: 64 * 1024,
  }));
  const secret = keys.get(manifest.signature.keyId);
  const expected = secret
    ? crypto.createHmac("sha256", secret)
      .update(`platform-backup-manifest-v1\n${manifest.id}\n${digest}\n`)
      .digest("base64url")
    : "";
  const supplied = String(manifest.signature.value ?? "");
  if (!secret || supplied.length !== expected.length
    || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    throw new Error("off-site manifest signature verification failed");
  }
  return { fileSha256: sha256(bytes), manifest };
}

function validateCompletedOffsiteReceipt(receipt, active, manifest, {
  expectedManifestDigest,
  expectedSnapshotId,
} = {}) {
  exactRecord(receipt, [
    "artifactCount", "credentialsExposed", "durationMs", "evidenceContext", "finishedAt",
    "generatedAt", "hostname", "manifestDigest", "manifestId", "manifestPath",
    "repositoryHost", "repositoryMaxBytes", "repositoryOffsite", "repositorySizeBytes",
    "repositoryType", "resourceIds", "schema", "snapshotId", "startedAt", "status", "tag",
  ], "off-site backup receipt");
  if (receipt.schema !== "platform.offsite-backup-receipt/v1" || receipt.status !== "passed"
    || receipt.hostname !== "platform-infrastructure" || receipt.tag !== "platform-backups"
    || receipt.repositoryType !== "rclone" || receipt.repositoryHost !== null
    || receipt.repositoryOffsite !== true || receipt.credentialsExposed !== false) {
    throw new Error("off-site backup receipt identity or status is invalid");
  }
  const admittedAt = exactIsoTime(active.admittedAt, "active operation admittedAt");
  const startedAt = exactIsoTime(receipt.startedAt, "off-site receipt startedAt");
  const finishedAt = exactIsoTime(receipt.finishedAt, "off-site receipt finishedAt");
  if (receipt.generatedAt !== receipt.finishedAt
    || startedAt < admittedAt || startedAt - admittedAt > 30_000
    || finishedAt < startedAt || finishedAt - startedAt !== receipt.durationMs
    || receipt.durationMs < 1 || receipt.durationMs > OPERATION_TIMEOUT_MS) {
    throw new Error("off-site backup receipt timing is invalid");
  }
  if (!/^[a-f0-9]{64}$/.test(String(receipt.snapshotId ?? ""))
    || receipt.snapshotId !== expectedSnapshotId
    || !/^[a-f0-9]{64}$/.test(String(receipt.manifestDigest ?? ""))
    || receipt.manifestDigest !== expectedManifestDigest
    || receipt.manifestDigest !== manifest.signature.digest
    || receipt.manifestId !== manifest.id
    || receipt.manifestPath !== `manifests/${manifest.id}.json`) {
    throw new Error("off-site backup receipt snapshot or manifest binding is invalid");
  }
  const resourceIds = manifest.resources.map((resource) => resource.id);
  if (canonicalJson(receipt.resourceIds) !== canonicalJson(resourceIds)
    || receipt.artifactCount !== manifest.artifacts.length
    || !Number.isSafeInteger(receipt.artifactCount) || receipt.artifactCount < 1
    || !Number.isSafeInteger(receipt.repositorySizeBytes) || receipt.repositorySizeBytes < 1
    || !Number.isSafeInteger(receipt.repositoryMaxBytes)
    || receipt.repositoryMaxBytes < receipt.repositorySizeBytes) {
    throw new Error("off-site backup receipt coverage or repository bounds are invalid");
  }
}

function completedOffsiteResponse(active, receipt, capabilityKey) {
  const output = {
    executedAt: receipt.finishedAt,
    schema: "platform.offsite-backup-receipt/v1",
    status: "completed",
  };
  const result = {
    action: active.action,
    job: null,
    phases: [{
      output,
      outputSchema: output.schema,
      outputSha256: sha256(canonicalJson(output)),
      phaseId: "offsite.sync",
      status: "completed",
    }],
    schema: RESULT_SCHEMA,
    status: "completed",
  };
  return signActionResponse({
    action: active.action,
    errorCode: null,
    requestId: active.requestId,
    requestSha256: active.requestSha256,
    result,
    resultSha256: sha256(canonicalJson(result)),
    schema: RESPONSE_SCHEMA,
    status: "completed",
    statusCode: 200,
  }, capabilityKey);
}

export function reconcileCompletedOffsiteOperation({
  backupsRoot,
  capabilityKey,
  expectedManifestDigest,
  expectedOriginalRcloneSha256,
  expectedSnapshotId,
  rcloneConfigFile,
  receiptFileName,
  reportsRoot,
  signingKeyFile,
  stateDir,
  trusted,
  now = Date.now(),
} = {}) {
  if (!/^[a-f0-9]{64}$/.test(String(expectedManifestDigest ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(expectedOriginalRcloneSha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(expectedSnapshotId ?? ""))
    || !/^offsite-backup-\d{14}-[a-f0-9]{6}\.json$/.test(String(receiptFileName ?? ""))) {
    throw new Error("off-site reconciliation evidence selectors are invalid");
  }
  const activeFile = path.join(stateDir, ACTIVE_LOCK);
  const active = readCanonicalState(activeFile);
  validateActiveOperationRecord(active, { action: "backup.offsite.sync", now });

  const currentAdmission = readCanonicalState(path.join(stateDir, "active-admission.json"));
  exactRecord(currentAdmission, ["admissionSha256", "generation"], "active admission state");
  const candidateAdmission = trusted?.document ? {
    admissionSha256: sha256(canonicalJson(trusted.document)),
    generation: trusted.intent?.generation,
  } : null;
  const previousAdmission = candidateAdmission ? {
    admissionSha256: trusted.receipt?.previousAdmissionSha256,
    generation: candidateAdmission.generation - 1,
  } : null;
  if (!candidateAdmission || !previousAdmission
    || trusted.intent?.activationBundleSha256 !== candidateAdmission.admissionSha256
    || !Number.isSafeInteger(candidateAdmission.generation) || candidateAdmission.generation < 2
    || !/^[a-f0-9]{64}$/.test(String(candidateAdmission.admissionSha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(previousAdmission.admissionSha256 ?? ""))
    || (canonicalJson(currentAdmission) !== canonicalJson(previousAdmission)
      && canonicalJson(currentAdmission) !== canonicalJson(candidateAdmission))) {
    throw new Error("off-site reconciliation admission does not extend the active generation");
  }

  const reportFile = exactProtectedChild(reportsRoot, receiptFileName);
  const { bytes: reportBytes, value: receipt } = protectedJson(reportFile);
  if (!/^manifest-[a-z0-9][a-z0-9-]{15,127}$/.test(String(receipt?.manifestId ?? ""))
    || receipt?.manifestPath !== `manifests/${receipt.manifestId}.json`) {
    throw new Error("off-site receipt manifest identity is invalid");
  }
  const manifestFile = exactProtectedChild(backupsRoot, "manifests", `${receipt.manifestId}.json`);
  if (path.basename(manifestFile) !== path.basename(String(receipt?.manifestPath ?? ""))) {
    throw new Error("off-site receipt manifest path is not exact");
  }
  const { fileSha256: manifestFileSha256, manifest } = verifyOffsiteManifest(manifestFile, signingKeyFile);
  validateCompletedOffsiteReceipt(receipt, active, manifest, {
    expectedManifestDigest,
    expectedSnapshotId,
  });

  const refreshDir = path.join(stateDir, "rclone-refresh");
  ensurePrivateDirectory(refreshDir);
  const stagedFile = path.join(refreshDir, "rclone.conf");
  const refreshNames = fs.readdirSync(refreshDir).sort();
  if (canonicalJson(refreshNames) !== canonicalJson(["rclone.conf"])
    && canonicalJson(refreshNames) !== canonicalJson([])) {
    throw new Error("rclone refresh staging contains unexpected entries");
  }
  const reconciliationDir = path.join(stateDir, "reconciliation");
  const journalFile = path.join(reconciliationDir, `${active.requestSha256}.json`);
  const terminalFile = path.join(stateDir, active.terminalFile);

  const existingJournal = fs.existsSync(journalFile) ? readCanonicalState(journalFile) : null;
  const canonicalBytes = readProtectedBytes(rcloneConfigFile, { minimumBytes: 2, maximumBytes: 64 * 1024 });
  const stagedBytes = fs.existsSync(stagedFile)
    ? readProtectedBytes(stagedFile, { minimumBytes: 2, maximumBytes: 64 * 1024 })
    : null;
  let beforeSha256;
  let afterSha256;
  if (existingJournal) {
    exactRecord(existingJournal, [
      "active", "admission", "createdAt", "manifest", "rclone", "receipt", "schema", "snapshotId", "terminal",
    ], "off-site reconciliation journal");
    beforeSha256 = existingJournal.rclone?.beforeSha256;
    afterSha256 = existingJournal.rclone?.afterSha256;
  } else {
    if (!stagedBytes) throw new Error("staged rclone refresh is missing");
    const replacement = validateRcloneTokenRefresh(canonicalBytes, stagedBytes);
    beforeSha256 = sha256(canonicalBytes);
    afterSha256 = sha256(replacement);
    if (beforeSha256 !== expectedOriginalRcloneSha256) {
      throw new Error("canonical rclone configuration differs from the operator-confirmed pre-operation digest");
    }
    if (beforeSha256 === afterSha256) throw new Error("staged rclone refresh did not change the OAuth token");
  }
  if (!/^[a-f0-9]{64}$/.test(String(beforeSha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(afterSha256 ?? ""))) {
    throw new Error("off-site reconciliation rclone digests are invalid");
  }
  if (beforeSha256 !== expectedOriginalRcloneSha256) {
    throw new Error("off-site reconciliation original rclone digest is invalid");
  }
  if (stagedBytes && sha256(stagedBytes) !== afterSha256) {
    throw new Error("staged rclone refresh differs from the reconciliation journal");
  }

  const reconciliationAt = existingJournal?.createdAt ?? new Date(now).toISOString();
  exactIsoTime(reconciliationAt, "off-site reconciliation createdAt");
  const response = completedOffsiteResponse(active, receipt, capabilityKey);
  const terminal = {
    recordedAt: reconciliationAt,
    request: active.request,
    requestId: active.requestId,
    requestSha256: active.requestSha256,
    response,
    schema: TERMINAL_RECEIPT_SCHEMA,
  };
  const journal = {
    active,
    admission: { from: previousAdmission, to: candidateAdmission },
    createdAt: reconciliationAt,
    manifest: {
      digest: manifest.signature.digest,
      fileSha256: manifestFileSha256,
      id: manifest.id,
    },
    rclone: { afterSha256, beforeSha256 },
    receipt: { fileName: receiptFileName, fileSha256: sha256(reportBytes) },
    schema: OFFSITE_RECONCILIATION_SCHEMA,
    snapshotId: receipt.snapshotId,
    terminal,
  };
  if (existingJournal) {
    if (canonicalJson(existingJournal) !== canonicalJson(journal)) {
      throw new Error("off-site reconciliation journal evidence changed");
    }
  } else {
    ensurePrivateDirectory(reconciliationDir);
    writeExclusiveCanonical(journalFile, journal);
  }

  admitGeneration(stateDir, trusted);
  if (canonicalJson(readCanonicalState(path.join(stateDir, "active-admission.json")))
    !== canonicalJson(candidateAdmission)) {
    throw new Error("off-site reconciliation admission transition was not durable");
  }

  const currentSha256 = sha256(canonicalBytes);
  if (currentSha256 === beforeSha256) {
    if (!stagedBytes) throw new Error("staged rclone refresh disappeared before commit");
    const replacement = validateRcloneTokenRefresh(canonicalBytes, stagedBytes);
    if (sha256(replacement) !== afterSha256) throw new Error("validated rclone refresh digest changed");
    replaceProtectedBytes(rcloneConfigFile, canonicalBytes, replacement);
  } else if (currentSha256 !== afterSha256) {
    throw new Error("canonical rclone configuration is neither pre- nor post-reconciliation");
  }

  ensurePrivateDirectory(path.dirname(terminalFile));
  if (fs.existsSync(terminalFile)) {
    if (canonicalJson(readCanonicalState(terminalFile)) !== canonicalJson(terminal)) {
      throw new Error("off-site reconciliation terminal receipt changed");
    }
  } else {
    writeExclusiveCanonical(terminalFile, terminal);
  }
  if (fs.existsSync(stagedFile)) {
    if (sha256(readProtectedBytes(stagedFile, { minimumBytes: 2, maximumBytes: 64 * 1024 })) !== afterSha256) {
      throw new Error("staged rclone refresh changed before cleanup");
    }
    fs.unlinkSync(stagedFile);
    syncDirectory(refreshDir);
  }
  if (canonicalJson(readCanonicalState(activeFile)) !== canonicalJson(active)) {
    throw new Error("active operation changed before reconciliation release");
  }
  fs.unlinkSync(activeFile);
  syncDirectory(stateDir);
  return Object.freeze({
    manifestDigest: manifest.signature.digest,
    requestId: active.requestId,
    requestSha256: active.requestSha256,
    snapshotId: receipt.snapshotId,
    status: "reconciled",
  });
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
  if (Object.keys(environment).some((key) => key.startsWith("PLATFORM_LOCAL_PRIVATE_BACKUP_"))) {
    throw new Error("broker runtime must not inherit child-only LOCAL_PRIVATE authority markers");
  }
  const renderBinding = readLocalPrivateRenderBinding(renderFile);
  for (const [key, value] of Object.entries(renderBinding.brokerEnvironment)) {
    if (environment[key] !== value) throw new Error(`broker runtime differs from canonical render: ${key}`);
  }
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
    renderBinding,
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

export function verifyRuntimeEgressNetwork(trusted) {
  const expected = trusted.renderBinding.egressNetwork;
  const values = JSON.parse(execFileSync("docker", ["network", "inspect", expected], {
    encoding: "utf8",
    maxBuffer: 64 * 1024,
    timeout: 10_000,
  }));
  const network = Array.isArray(values) && values.length === 1 ? values[0] : null;
  if (!network || network.Name !== expected || network.Driver !== "bridge"
    || network.Internal !== false || network.EnableIPv6 !== false
    || network.Labels?.["com.platform.trust-zone"] !== "trusted-platform-egress") {
    throw brokerError(403, "EGRESS_NETWORK_SUBSTITUTION_REJECTED", "off-site egress network differs from signed render");
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
      request,
      requestId: request.requestId,
      requestSha256,
      schema: ACTIVE_OPERATION_SCHEMA,
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
        request,
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
  jobsRoot, infraOps, requestSha256, restoreProof = DEFAULT_OFFSITE_RESTORE_PROOF, signal, stateDir, trusted,
} = {}) {
  const args = [infraOps];
  let command;
  let phasePlan;
  if (action === "backup.catalog") {
    args.push("backup-platform-catalog");
    command = "backup-platform-catalog";
    phasePlan = [["catalog.capture", "platform.backup-catalog/v1"]];
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
    command = "execute-backup-job";
    phasePlan = [["job.backup.capture", "platform.backup-job-result/v1"]];
  } else if (action === "restore.offsite.proof") {
    args[0] = restoreProof;
    command = "restore-offsite-proof";
    phasePlan = [["offsite.restore", "platform.offsite-restore-proof/v1"]];
  } else if (action === "backup.offsite.sync") {
    args.push("offsite-backup-restic");
    command = "offsite-backup-restic";
    phasePlan = [["offsite.sync", "platform.offsite-backup-receipt/v1"]];
  } else {
    throw brokerError(403, "ACTION_NOT_ALLOWED", "action is outside the LOCAL_PRIVATE backup surface");
  }

  const childEnvironment = { ...process.env };
  let stagedRclone = null;
  delete childEnvironment.NODE_OPTIONS;
  delete childEnvironment.NODE_PATH;
  for (const key of Object.keys(childEnvironment)) {
    if (key.startsWith("PLATFORM_LOCAL_PRIVATE_BACKUP_")) delete childEnvironment[key];
  }
  if (["backup.offsite.sync", "restore.offsite.proof"].includes(action)) {
    stagedRclone = stageRcloneRefresh(trusted.offsiteFiles.rcloneConfig, stateDir);
    childEnvironment.HOME = "/tmp";
    childEnvironment.XDG_CACHE_HOME = "/tmp/.cache";
    childEnvironment.PLATFORM_CLOSED_HOST_PATH_MAPPINGS = "1";
    childEnvironment.RCLONE_CONFIG = stagedRclone.stagedFile;
    childEnvironment.RCLONE_CONFIG_WRITABLE = "1";
    childEnvironment.RESTIC_DOCKER_USER = `${SERVICE_UID}:${SERVICE_GID}`;
    childEnvironment.RESTIC_IMAGE = trusted.receipt.resources.offsite.resticImageId;
    childEnvironment.RESTIC_PASSWORD_FILE = trusted.offsiteFiles.resticPassword;
    childEnvironment.RESTIC_REPOSITORY = trusted.receipt.resources.offsite.repository;
    childEnvironment.RESTIC_REQUIRE_IMMUTABLE_IMAGE = "true";
    if (action === "backup.offsite.sync") {
      childEnvironment.RESTIC_HOSTNAME = "platform-infrastructure";
    } else {
      const restore = trusted.receipt.resources.offsite.restore;
      childEnvironment.LOCAL_PRIVATE_RESTORE_MANIFEST_DIGEST = restore.manifestDigest;
      childEnvironment.LOCAL_PRIVATE_RESTORE_MANIFEST_ID = restore.manifestId;
      childEnvironment.LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_NAME = restore.receiptFileName;
      childEnvironment.LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_SHA256 = restore.receiptFileSha256;
      childEnvironment.LOCAL_PRIVATE_RESTORE_SNAPSHOT_ID = restore.snapshotId;
    }
  }
  Object.assign(childEnvironment, localPrivateBackupChildBindings({
    action,
    command,
    egressNetwork: trusted.renderBinding.egressNetwork,
    jobSha256: action === "backup.job.execute" ? parameters.jobSha256 : "-",
    requestSha256,
    trusted,
  }));
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
        else resolve({ code, output });
      });
      signal.addEventListener("abort", () => child.kill("SIGTERM"), { once: true });
    });
  } finally {
    if (stagedRclone) stagedRclone.commit();
  }
  let restoreSummary = null;
  if (action === "restore.offsite.proof") {
    const outputText = new TextDecoder("utf-8", { fatal: true }).decode(execution.output).trim();
    const parsed = JSON.parse(outputText);
    const restore = trusted.receipt.resources.offsite.restore;
    const exactKeys = [
      "artifactCount", "artifactSignaturesVerified", "exactSetVerified", "manifestDigest",
      "manifestId", "manifestSignatureVerified", "receiptFile", "receiptFileSha256",
      "resourceCount", "restoredBytes", "restorePayloadRemoved", "schema", "snapshotId",
      "status",
    ];
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
      || canonicalJson(Object.keys(parsed).sort()) !== canonicalJson(exactKeys.sort())
      || outputText !== canonicalJson(parsed)
      || parsed.schema !== "platform.offsite-restore-proof/v1"
      || parsed.status !== "passed" || parsed.exactSetVerified !== true
      || parsed.manifestSignatureVerified !== true
      || parsed.artifactSignaturesVerified !== true
      || parsed.restorePayloadRemoved !== true
      || parsed.snapshotId !== restore.snapshotId
      || parsed.manifestId !== restore.manifestId
      || parsed.manifestDigest !== restore.manifestDigest
      || parsed.receiptFile !== restore.receiptFileName
      || parsed.receiptFileSha256 !== restore.receiptFileSha256
      || !Number.isSafeInteger(parsed.artifactCount) || parsed.artifactCount < 1
      || !Number.isSafeInteger(parsed.resourceCount) || parsed.resourceCount < 1
      || !Number.isSafeInteger(parsed.restoredBytes) || parsed.restoredBytes < 1) {
      throw new Error("LOCAL_PRIVATE off-site restore result is invalid");
    }
    restoreSummary = parsed;
  }
  const phases = phasePlan.map(([phaseId, outputSchema]) => {
    const operationOutput = action === "restore.offsite.proof"
      ? {
        artifactCount: restoreSummary.artifactCount,
        artifactSignaturesVerified: true,
        exactSetVerified: true,
        executedAt: new Date().toISOString(),
        manifestDigest: restoreSummary.manifestDigest,
        manifestId: restoreSummary.manifestId,
        manifestSignatureVerified: true,
        receiptFile: restoreSummary.receiptFile,
        receiptFileSha256: restoreSummary.receiptFileSha256,
        resourceCount: restoreSummary.resourceCount,
        restoredBytes: restoreSummary.restoredBytes,
        restorePayloadRemoved: true,
        schema: outputSchema,
        snapshotId: restoreSummary.snapshotId,
        status: "completed",
      }
      : {
        executedAt: new Date().toISOString(),
        schema: outputSchema,
        status: "completed",
        ...(parameters.jobId ? { jobId: parameters.jobId, jobOperation: parameters.jobOperation } : {}),
      };
    return {
      output: operationOutput,
      outputSchema,
      outputSha256: sha256(canonicalJson(operationOutput)),
      phaseId,
      status: "completed",
    };
  });
  return {
    action,
    job: action === "backup.job.execute" ? parameters : null,
    phases,
    schema: RESULT_SCHEMA,
    status: execution.code === 0 ? "completed" : "failed",
  };
}

function restoreReconciliationChildEnvironment({ environment, requestSha256, stateDir, trusted }) {
  const childEnvironment = { ...environment };
  delete childEnvironment.NODE_OPTIONS;
  delete childEnvironment.NODE_PATH;
  for (const key of Object.keys(childEnvironment)) {
    if (key.startsWith("PLATFORM_LOCAL_PRIVATE_BACKUP_")) delete childEnvironment[key];
  }
  const restore = trusted.receipt.resources.offsite.restore;
  Object.assign(childEnvironment, {
    HOME: "/tmp",
    XDG_CACHE_HOME: "/tmp/.cache",
    PLATFORM_CLOSED_HOST_PATH_MAPPINGS: "1",
    RCLONE_CONFIG: path.join(stateDir, "rclone-refresh", "rclone.conf"),
    RCLONE_CONFIG_WRITABLE: "1",
    RESTIC_DOCKER_USER: `${SERVICE_UID}:${SERVICE_GID}`,
    RESTIC_IMAGE: trusted.receipt.resources.offsite.resticImageId,
    RESTIC_PASSWORD_FILE: trusted.offsiteFiles.resticPassword,
    RESTIC_REPOSITORY: trusted.receipt.resources.offsite.repository,
    RESTIC_REQUIRE_IMMUTABLE_IMAGE: "true",
    LOCAL_PRIVATE_RESTORE_MANIFEST_DIGEST: restore.manifestDigest,
    LOCAL_PRIVATE_RESTORE_MANIFEST_ID: restore.manifestId,
    LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_NAME: restore.receiptFileName,
    LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_SHA256: restore.receiptFileSha256,
    LOCAL_PRIVATE_RESTORE_SNAPSHOT_ID: restore.snapshotId,
  }, localPrivateBackupChildBindings({
    action: "restore.offsite.proof",
    command: "restore-offsite-proof",
    egressNetwork: trusted.renderBinding.egressNetwork,
    requestSha256,
    trusted,
  }));
  return childEnvironment;
}

async function runRestoreReconciliationCleanup({
  environment = process.env,
  requestSha256,
  restoreProof = DEFAULT_OFFSITE_RESTORE_PROOF,
  stateDir,
  trusted,
} = {}) {
  const childEnvironment = restoreReconciliationChildEnvironment({
    environment,
    requestSha256,
    stateDir,
    trusted,
  });
  const execution = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [restoreProof, "reconcile-interrupted"], {
      env: childEnvironment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = Buffer.alloc(0);
    let oversized = false;
    child.stdout.on("data", (chunk) => {
      output = Buffer.concat([output, chunk]);
      if (output.length > MAX_RESPONSE_OUTPUT) {
        oversized = true;
        child.kill("SIGTERM");
      }
    });
    child.stderr.on("data", (chunk) => {
      output = Buffer.concat([output, chunk]);
      if (output.length > MAX_RESPONSE_OUTPUT) {
        oversized = true;
        child.kill("SIGTERM");
      }
    });
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (oversized || signal || code !== 0) {
        reject(new Error(`off-site restore cleanup failed (${signal ?? code ?? "unknown"})`));
      } else resolve(output);
    });
  });
  const outputText = decodeUtf8(execution, "off-site restore cleanup output").trim();
  const result = JSON.parse(outputText);
  exactRecord(result, [
    "helperContainersAbsent", "requestSha256", "restorePayloadRemoved", "rcloneStagingPreserved", "schema", "status",
  ], "off-site restore cleanup result");
  if (outputText !== canonicalJson(result)
    || result.schema !== "platform.offsite-restore-cleanup/v1"
    || result.status !== "completed" || result.requestSha256 !== requestSha256
    || result.helperContainersAbsent !== true || result.restorePayloadRemoved !== true
    || result.rcloneStagingPreserved !== true) {
    throw new Error("off-site restore cleanup result is invalid");
  }
  return result;
}

function reconcileInterruptedRestoreRclone({ active, createdAt, stateDir, trusted }) {
  const refreshDir = path.join(stateDir, "rclone-refresh");
  ensurePrivateDirectory(refreshDir);
  const stagedFile = path.join(refreshDir, "rclone.conf");
  const names = fs.readdirSync(refreshDir).sort();
  if (canonicalJson(names) !== canonicalJson([])
    && canonicalJson(names) !== canonicalJson(["rclone.conf"])) {
    throw new Error("off-site restore rclone staging contains unexpected entries");
  }
  const journalFile = path.join(stateDir, "reconciliation", `${active.requestSha256}.rclone.json`);
  const existing = fs.existsSync(journalFile) ? readCanonicalState(journalFile) : null;
  const canonicalBytes = readProtectedBytes(trusted.offsiteFiles.rcloneConfig, {
    minimumBytes: 2,
    maximumBytes: 64 * 1024,
  });
  const stagedBytes = fs.existsSync(stagedFile)
    ? readProtectedBytes(stagedFile, { minimumBytes: 2, maximumBytes: 64 * 1024 })
    : null;
  let journal;
  if (existing) {
    exactRecord(existing, ["createdAt", "requestSha256", "rclone", "schema"], "off-site restore rclone reconciliation");
    exactRecord(existing.rclone, ["afterSha256", "beforeSha256", "mode"], "off-site restore rclone reconciliation state");
    if (existing.schema !== OFFSITE_RESTORE_RCLONE_RECONCILIATION_SCHEMA
      || existing.createdAt !== createdAt || existing.requestSha256 !== active.requestSha256
      || !["absent", "refreshed", "unchanged"].includes(existing.rclone.mode)
      || !/^[a-f0-9]{64}$/.test(String(existing.rclone.beforeSha256 ?? ""))
      || !/^[a-f0-9]{64}$/.test(String(existing.rclone.afterSha256 ?? ""))
      || (existing.rclone.mode === "refreshed"
        ? existing.rclone.beforeSha256 === existing.rclone.afterSha256
        : existing.rclone.beforeSha256 !== existing.rclone.afterSha256)) {
      throw new Error("off-site restore rclone reconciliation journal is invalid");
    }
    journal = existing;
  } else {
    const beforeSha256 = sha256(canonicalBytes);
    const replacement = stagedBytes ? validateRcloneTokenRefresh(canonicalBytes, stagedBytes) : null;
    const afterSha256 = replacement ? sha256(replacement) : beforeSha256;
    journal = {
      createdAt,
      requestSha256: active.requestSha256,
      rclone: {
        afterSha256,
        beforeSha256,
        mode: stagedBytes ? (afterSha256 === beforeSha256 ? "unchanged" : "refreshed") : "absent",
      },
      schema: OFFSITE_RESTORE_RCLONE_RECONCILIATION_SCHEMA,
    };
    writeExclusiveCanonical(journalFile, journal);
  }

  const { afterSha256, beforeSha256, mode } = journal.rclone;
  const currentSha256 = sha256(canonicalBytes);
  if (stagedBytes && sha256(stagedBytes) !== afterSha256) {
    throw new Error("off-site restore staged rclone configuration differs from its reconciliation journal");
  }
  if (mode === "absent" && stagedBytes) {
    throw new Error("off-site restore rclone staging appeared after an absent reconciliation record");
  }
  if (currentSha256 === beforeSha256 && mode === "refreshed") {
    if (!stagedBytes) throw new Error("off-site restore refreshed rclone staging disappeared before commit");
    const replacement = validateRcloneTokenRefresh(canonicalBytes, stagedBytes);
    if (sha256(replacement) !== afterSha256) throw new Error("off-site restore refreshed rclone digest changed");
    replaceProtectedBytes(trusted.offsiteFiles.rcloneConfig, canonicalBytes, replacement);
  } else if (currentSha256 !== afterSha256) {
    throw new Error("canonical rclone configuration is neither pre- nor post-restore reconciliation");
  }
  const committed = readProtectedBytes(trusted.offsiteFiles.rcloneConfig, {
    minimumBytes: 2,
    maximumBytes: 64 * 1024,
  });
  if (sha256(committed) !== afterSha256) {
    throw new Error("off-site restore rclone refresh commit is not durable");
  }
  if (fs.existsSync(stagedFile)) {
    if (sha256(readProtectedBytes(stagedFile, { minimumBytes: 2, maximumBytes: 64 * 1024 })) !== afterSha256) {
      throw new Error("off-site restore rclone staging changed before cleanup");
    }
    fs.unlinkSync(stagedFile);
    syncDirectory(refreshDir);
  }
  return journal;
}

export async function reconcileInterruptedOffsiteRestoreProof({
  capabilityKey,
  cleanup = runRestoreReconciliationCleanup,
  dataRoot = DEFAULT_DATA_ROOT,
  environment = process.env,
  now = Date.now(),
  restoreProof = DEFAULT_OFFSITE_RESTORE_PROOF,
  stateDir,
  trusted,
} = {}) {
  const activeFile = path.join(stateDir, ACTIVE_LOCK);
  const active = validateActiveOperationRecord(readCanonicalState(activeFile), {
    action: "restore.offsite.proof",
    now,
  });
  const admittedAt = Date.parse(active.admittedAt);
  normalizeActionRequest(active.request, trusted, capabilityKey, { now: admittedAt });
  if (canonicalJson(active.request.parameters) !== canonicalJson({})) {
    throw new Error("active off-site restore parameters are not empty");
  }
  const currentAdmission = readCanonicalState(path.join(stateDir, "active-admission.json"));
  const expectedAdmission = {
    admissionSha256: sha256(canonicalJson(trusted.document)),
    generation: trusted.intent.generation,
  };
  exactRecord(currentAdmission, ["admissionSha256", "generation"], "active admission state");
  if (canonicalJson(currentAdmission) !== canonicalJson(expectedAdmission)) {
    throw new Error("active off-site restore admission differs from the loaded signed admission");
  }

  const reconciliationDir = path.join(stateDir, "reconciliation");
  const journalFile = path.join(reconciliationDir, `${active.requestSha256}.json`);
  const terminalFile = path.join(stateDir, active.terminalFile);
  const existingJournal = fs.existsSync(journalFile) ? readCanonicalState(journalFile) : null;
  const createdAt = existingJournal?.createdAt ?? new Date(now).toISOString();
  exactIsoTime(createdAt, "off-site restore reconciliation createdAt");
  const interrupted = brokerError(
    503,
    "OFFSITE_RESTORE_PROOF_INTERRUPTED",
    "off-site restore proof was interrupted and its isolated resources were reconciled",
  );
  const response = signedResponse(active.request, capabilityKey, { error: interrupted });
  const terminal = {
    recordedAt: createdAt,
    request: active.request,
    requestId: active.requestId,
    requestSha256: active.requestSha256,
    response,
    schema: TERMINAL_RECEIPT_SCHEMA,
  };
  const journal = {
    active,
    createdAt,
    plannedCleanup: {
      helperContainers: [
        `gf-restic-restore-${active.requestSha256.slice(0, 12)}`,
        `gf-restic-snapshots-${active.requestSha256.slice(0, 12)}`,
      ].sort(),
      rcloneStagingFile: path.join(stateDir, "rclone-refresh", "rclone.conf"),
      rcloneRefreshJournal: path.join(stateDir, "reconciliation", `${active.requestSha256}.rclone.json`),
      scratchRoot: path.join(dataRoot, ".offsite-restore-proof", active.requestSha256),
    },
    schema: OFFSITE_RESTORE_RECONCILIATION_SCHEMA,
    terminal,
  };
  if (existingJournal) {
    if (canonicalJson(existingJournal) !== canonicalJson(journal)) {
      throw new Error("off-site restore reconciliation journal changed");
    }
  } else {
    ensurePrivateDirectory(reconciliationDir);
    writeExclusiveCanonical(journalFile, journal);
  }

  await cleanup({ environment, requestSha256: active.requestSha256, restoreProof, stateDir, trusted });
  reconcileInterruptedRestoreRclone({ active, createdAt, stateDir, trusted });
  ensurePrivateDirectory(path.dirname(terminalFile));
  if (fs.existsSync(terminalFile)) {
    if (canonicalJson(readCanonicalState(terminalFile)) !== canonicalJson(terminal)) {
      throw new Error("off-site restore reconciliation terminal receipt changed");
    }
  } else {
    writeExclusiveCanonical(terminalFile, terminal);
  }
  if (canonicalJson(readCanonicalState(activeFile)) !== canonicalJson(active)) {
    throw new Error("active off-site restore changed before reconciliation release");
  }
  fs.unlinkSync(activeFile);
  syncDirectory(stateDir);
  return Object.freeze({
    requestId: active.requestId,
    requestSha256: active.requestSha256,
    status: "reconciled",
  });
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
    requireRestic: ["backup.offsite.sync", "restore.offsite.proof"].includes(request.action),
    requireScheduler: true,
  });
  if (["backup.offsite.sync", "restore.offsite.proof"].includes(request.action)) verifyRuntimeEgressNetwork(trusted);
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
      requestSha256: sha256(canonicalJson(request)),
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

function parseOffsiteReconciliationArgs(tokens) {
  const values = {};
  const allowed = new Set(["manifest-digest", "original-rclone-sha256", "report", "snapshot"]);
  for (let index = 0; index < tokens.length; index += 2) {
    const option = tokens[index];
    const value = tokens[index + 1];
    const name = typeof option === "string" && option.startsWith("--") ? option.slice(2) : "";
    if (!allowed.has(name) || !value || value.startsWith("--") || Object.hasOwn(values, name)) {
      throw new Error("reconcile-offsite-refresh requires exact report, snapshot, manifest and original-rclone digest options");
    }
    values[name] = value;
  }
  if (tokens.length !== 8 || Object.keys(values).length !== allowed.size) {
    throw new Error("reconcile-offsite-refresh requires exact report, snapshot, manifest and original-rclone digest options");
  }
  return values;
}

async function main() {
  if (process.argv[2] === "reconcile-offsite-refresh") {
    const args = parseOffsiteReconciliationArgs(process.argv.slice(3));
    const stateDir = process.env.DOCKER_ACTION_BROKER_STATE_DIR || DEFAULT_STATE_DIR;
    const dataRoot = process.env.PLATFORM_DATA_ROOT || DEFAULT_DATA_ROOT;
    ensurePrivateDirectory(stateDir);
    const trusted = loadLocalPrivateTrust(process.env);
    verifyRuntimeImages(trusted, { requireRestic: true, requireScheduler: true });
    verifyRuntimeEgressNetwork(trusted);
    const result = reconcileCompletedOffsiteOperation({
      backupsRoot: path.join(dataRoot, "backups"),
      capabilityKey: readProtectedBytes(trusted.capabilityFiles["backup.offsite.sync"]),
      expectedManifestDigest: args["manifest-digest"],
      expectedOriginalRcloneSha256: args["original-rclone-sha256"],
      expectedSnapshotId: args.snapshot,
      rcloneConfigFile: trusted.offsiteFiles.rcloneConfig,
      receiptFileName: args.report,
      reportsRoot: path.join(dataRoot, "reports", "offsite-backups"),
      signingKeyFile: process.env.BACKUP_SIGNING_KEYS_FILE || DEFAULT_SIGNING_KEY,
      stateDir,
      trusted,
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
    return;
  }
  if (process.argv[2] === "reconcile-offsite-restore-proof") {
    if (process.argv.length !== 3) {
      throw new Error("reconcile-offsite-restore-proof accepts no selectors or arguments");
    }
    const stateDir = process.env.DOCKER_ACTION_BROKER_STATE_DIR || DEFAULT_STATE_DIR;
    const dataRoot = process.env.PLATFORM_DATA_ROOT || DEFAULT_DATA_ROOT;
    ensurePrivateDirectory(stateDir);
    const active = readCanonicalState(path.join(stateDir, ACTIVE_LOCK));
    const trusted = loadLocalPrivateTrust(process.env, exactIsoTime(
      active.admittedAt,
      "active operation admittedAt",
    ));
    verifyRuntimeImages(trusted);
    const result = await reconcileInterruptedOffsiteRestoreProof({
      capabilityKey: readProtectedBytes(trusted.capabilityFiles["restore.offsite.proof"]),
      dataRoot,
      stateDir,
      trusted,
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
    return;
  }
  if (process.argv.length > 2) throw new Error("unsupported LOCAL_PRIVATE broker command");
  const socketPath = process.env.DOCKER_ACTION_BROKER_SOCKET || DEFAULT_SOCKET;
  const stateDir = process.env.DOCKER_ACTION_BROKER_STATE_DIR || DEFAULT_STATE_DIR;
  ensurePrivateDirectory(stateDir);
  let trusted;
  if (fs.existsSync(path.join(stateDir, ACTIVE_LOCK))) {
    const active = readCanonicalState(path.join(stateDir, ACTIVE_LOCK));
    if (active?.action !== "restore.offsite.proof") {
      throw new Error("an unresolved LOCAL_PRIVATE broker operation requires reconciliation");
    }
    trusted = loadLocalPrivateTrust(process.env, exactIsoTime(active.admittedAt, "active operation admittedAt"));
    verifyRuntimeImages(trusted);
    await reconcileInterruptedOffsiteRestoreProof({
      capabilityKey: readProtectedBytes(trusted.capabilityFiles["restore.offsite.proof"]),
      dataRoot: process.env.PLATFORM_DATA_ROOT || DEFAULT_DATA_ROOT,
      stateDir,
      trusted,
    });
  }
  trusted = loadLocalPrivateTrust(process.env);
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
