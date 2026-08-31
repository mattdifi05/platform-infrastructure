#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  ACTIONS,
  CLI_ACTIONS,
  LOCAL_PRIVATE_ACTIONS,
  MAX_REQUEST_BYTES,
  REQUEST_SCHEMA,
  canonicalJson,
  normalizeActionResponse,
  signActionRequest,
} from "./docker-action-contract.mjs";
import {
  LOCAL_PRIVATE_ALLOWED_ACTIONS,
  readCanonicalAdmission,
  verifyAdmissionDocument,
} from "./local-private-backup-admission.mjs";

const DEFAULT_SOCKET = "/run/platform/docker-action-broker/broker.sock";
const DEFAULT_BACKUP_JOBS_ROOT = "/var/www/project-state/backup-jobs";
const BACKUP_JOB_SCHEMA = "platform.backup-job/v1";
const MAX_CLAIMED_JOB_BYTES = 128 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
// The production broker admits a four-hour operation window. Keep one bounded
// minute after that window for its signed terminal response to reach the client.
export const DEFAULT_RESPONSE_DEADLINE_MS = (4 * 60 * 60_000) + 60_000;
export const UNKNOWN_AFTER_ADMISSION = "UNKNOWN_AFTER_ADMISSION";
export const UNKNOWN_AFTER_ADMISSION_EXIT_CODE = 74;
const MAX_RESPONSE_DEADLINE_MS = (24 * 60 * 60_000) + 60_000;
const CLAIMED_JOB_METADATA_FIELDS = Object.freeze([
  "dev",
  "ino",
  "size",
  "mtimeMs",
  "ctimeMs",
  "mode",
  "uid",
  "gid",
  "nlink",
]);

export function buildClientRequest(command, args, options = {}) {
  const action = resolveClientAction(command, { localPrivate: options.localPrivate === true });
  if (action === "backup.job.execute") {
    throw new Error("execute-backup-job requires runClientCommand with --jobFileName <basename>");
  }
  return buildSignedClientRequest(action, parseFixedActionParameters(args), options);
}

function buildSignedClientRequest(action, parameters, {
  runtimeIntentId,
  activeReceiptSha256,
  combinedRenderSha256,
  capabilityKey,
  now = Date.now(),
  requestId,
  nonce,
} = {}) {
  const contract = ACTIONS[action];
  if (!contract) throw new Error(`Unsupported Docker action: ${action || "(empty)"}`);
  const issuedAt = new Date(now);
  const request = {
    schema: REQUEST_SCHEMA,
    requestId: requestId ?? crypto.randomUUID(),
    nonce: nonce ?? crypto.randomBytes(32).toString("base64url"),
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 30_000).toISOString(),
    runtimeIntentId: String(runtimeIntentId ?? ""),
    activeReceiptSha256: String(activeReceiptSha256 ?? ""),
    combinedRenderSha256: String(combinedRenderSha256 ?? ""),
    capabilityId: contract.capabilityId,
    action,
    parameters,
  };
  return JSON.parse(canonicalJson(signActionRequest(request, capabilityKey)));
}

export class DockerActionOutcomeUnknownError extends Error {
  constructor(request, requestWire, cause) {
    const original = cause instanceof Error
      ? cause
      : new Error(String(cause ?? "Docker action broker response was lost"));
    super(`${UNKNOWN_AFTER_ADMISSION}: ${original.message}`, { cause: original });
    this.name = "DockerActionOutcomeUnknownError";
    this.action = String(request?.action ?? "");
    this.code = UNKNOWN_AFTER_ADMISSION;
    this.outcome = UNKNOWN_AFTER_ADMISSION;
    this.requestFrameSent = true;
    this.requestId = String(request?.requestId ?? "");
    this.requestSha256 = crypto.createHash("sha256").update(requestWire).digest("hex");
    this.retrySafe = false;
  }
}

export async function sendActionRequest(
  request,
  socketPath = DEFAULT_SOCKET,
  capabilityKey,
  { responseTimeoutMs = DEFAULT_RESPONSE_DEADLINE_MS } = {},
) {
  const requestWire = canonicalJson(request);
  if (Buffer.byteLength(requestWire) > MAX_REQUEST_BYTES) {
    throw new Error("Docker action broker request is oversized");
  }
  if (!Number.isSafeInteger(responseTimeoutMs) || responseTimeoutMs < 1
    || responseTimeoutMs > MAX_RESPONSE_DEADLINE_MS) {
    throw new TypeError("Docker action broker response deadline is invalid");
  }
  const frame = Buffer.from(`${requestWire}\n`);
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    const chunks = [];
    let length = 0;
    let requestFrameSent = false;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(requestFrameSent && !(error instanceof DockerActionOutcomeUnknownError)
        ? new DockerActionOutcomeUnknownError(request, requestWire, error)
        : error);
    };
    socket.setTimeout(responseTimeoutMs, () => {
      socket.destroy(new Error("Docker action broker response deadline elapsed"));
    });
    socket.once("connect", () => {
      try {
        socket.end(frame);
        requestFrameSent = true;
      } catch (error) {
        fail(error);
        socket.destroy();
      }
    });
    socket.on("data", (chunk) => {
      length += chunk.length;
      if (length > MAX_RESPONSE_BYTES) return socket.destroy(new Error("Docker action broker response is oversized"));
      chunks.push(chunk);
    });
    socket.once("error", fail);
    socket.once("close", () => {
      if (!settled) fail(new Error("Docker action broker connection closed without a terminal response"));
    });
    socket.once("end", () => {
      if (settled) return;
      try {
        const bytes = Buffer.concat(chunks, length);
        if (bytes.length < 2 || bytes.at(-1) !== 0x0a || bytes.subarray(0, -1).includes(0x0a)) {
          throw new Error("Docker action broker response wire frame or delimiter is malformed");
        }
        const payload = bytes.subarray(0, -1);
        let response;
        try {
          response = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
        } catch {
          throw new Error("Docker action broker response is malformed JSON");
        }
        if (!payload.equals(Buffer.from(canonicalJson(response)))) {
          throw new Error("Docker action broker response wire is not canonical JSON");
        }
        const normalized = normalizeActionResponse(response, request, capabilityKey);
        settled = true;
        resolve(normalized);
      } catch (error) {
        fail(error);
      }
    });
  });
}

export function defaultClaimedJobPolicy(environment = process.env) {
  const configuredRoot = environment?.BACKUP_SCHEDULER_JOBS_DIR;
  const jobsRoot = typeof configuredRoot === "string" && configuredRoot.length > 0
    ? configuredRoot
    : DEFAULT_BACKUP_JOBS_ROOT;
  const localPrivateIdentity = typeof environment?.DOCKER_ACTION_LOCAL_ADMISSION_FILE === "string"
    && environment.DOCKER_ACTION_LOCAL_ADMISSION_FILE.length > 0;
  return Object.freeze({
    expectedGid: localPrivateIdentity ? process.getgid() : 0,
    expectedUid: localPrivateIdentity ? process.getuid() : 0,
    maximumBytes: MAX_CLAIMED_JOB_BYTES,
    trustedRoot: path.join(jobsRoot, "running"),
  });
}

export async function readClaimedBackupJob(fileName, {
  expectedGid = 0,
  expectedUid = 0,
  fileSystem = fs,
  maximumBytes = MAX_CLAIMED_JOB_BYTES,
  trustedRoot,
} = {}) {
  if (typeof fileName !== "string") {
    throw new TypeError("Claimed job filename must be a primitive string basename");
  }
  if (!fileName || fileName.includes("\0") || path.basename(fileName) !== fileName) {
    throw new TypeError("Claimed job filename must be an exact leaf basename");
  }
  if (typeof trustedRoot !== "string" || !path.isAbsolute(trustedRoot)
    || trustedRoot.includes("\0") || path.resolve(trustedRoot) !== trustedRoot
    || path.normalize(trustedRoot) !== trustedRoot) {
    throw new TypeError("Claimed job trusted root must be an exact canonical path");
  }
  if (!isUnixIdentity(expectedUid) || !isUnixIdentity(expectedGid)
    || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1
    || maximumBytes > MAX_CLAIMED_JOB_BYTES) {
    throw new TypeError("Claimed job owner or bounded-size policy is invalid");
  }
  if (!fileSystem || typeof fileSystem !== "object"
    || !["closeSync", "fstatSync", "lstatSync", "openSync", "readSync"]
      .every((method) => typeof fileSystem[method] === "function")
    || !Number.isInteger(fileSystem.constants?.O_RDONLY)
    || !Number.isInteger(fileSystem.constants?.O_NOFOLLOW)
    || fileSystem.constants.O_NOFOLLOW === 0) {
    throw new TypeError("Claimed job reader requires a no-follow filesystem interface");
  }

  const rootStat = fileSystem.lstatSync(trustedRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()
    || statInteger(rootStat.uid) !== expectedUid || statInteger(rootStat.gid) !== expectedGid
    || (statInteger(rootStat.mode) & 0o777) !== 0o700) {
    throw new Error("Claimed job trusted root ownership, symlink state or permissions are unsafe");
  }

  const file = path.join(trustedRoot, fileName);
  if (path.dirname(file) !== trustedRoot || path.basename(file) !== fileName) {
    throw new Error("Claimed job filename is not an exact leaf basename");
  }
  const leafStat = fileSystem.lstatSync(file);
  assertClaimedJobFileStat(leafStat, { expectedGid, expectedUid, maximumBytes });

  let descriptor;
  let bytes;
  try {
    descriptor = fileSystem.openSync(
      file,
      fileSystem.constants.O_RDONLY | fileSystem.constants.O_NOFOLLOW,
    );
    const before = fileSystem.fstatSync(descriptor);
    assertClaimedJobFileStat(before, { expectedGid, expectedUid, maximumBytes });
    if (!sameClaimedJobMetadata(leafStat, before)) {
      throw new Error("Claimed job leaf metadata changed before its protected read");
    }
    const size = statInteger(before.size);
    const first = readClaimedJobDescriptor(fileSystem, descriptor, size);
    const second = readClaimedJobDescriptor(fileSystem, descriptor, size);
    const after = fileSystem.fstatSync(descriptor);
    if (!sameClaimedJobMetadata(before, after)) {
      throw new Error("Claimed job descriptor metadata changed while being read");
    }
    if (first.length !== second.length || !crypto.timingSafeEqual(first, second)) {
      throw new Error("Claimed job content changed between stable descriptor reads");
    }
    bytes = first;
  } finally {
    if (descriptor !== undefined) fileSystem.closeSync(descriptor);
  }

  let document;
  try {
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("Claimed job JSON is malformed");
  }
  assertClaimedJobDocument(document, fileName);
  return Object.freeze({
    jobFileName: fileName,
    jobId: document.id,
    jobOperation: document.operation,
    jobSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  });
}

export async function runClientCommand(command, args, options = {}) {
  const action = resolveClientAction(command, { localPrivate: options.localPrivate === true });
  let parameters;
  if (action === "backup.job.execute") {
    if (!Array.isArray(args) || args.length !== 2 || args[0] !== "--jobFileName") {
      throw new Error("execute-backup-job accepts only --jobFileName <basename>");
    }
    parameters = await readClaimedBackupJob(
      args[1],
      options.claimedJobPolicy ?? defaultClaimedJobPolicy(),
    );
  } else {
    parameters = parseFixedActionParameters(args);
  }
  const request = buildSignedClientRequest(action, parameters, options);
  return sendActionRequest(
    request,
    options.socketPath ?? DEFAULT_SOCKET,
    options.capabilityKey,
    { responseTimeoutMs: options.responseTimeoutMs ?? DEFAULT_RESPONSE_DEADLINE_MS },
  );
}

function resolveClientAction(command, { localPrivate = false } = {}) {
  const action = typeof command === "string" ? CLI_ACTIONS[command] : undefined;
  if (!action || !ACTIONS[action]
    || (Object.hasOwn(LOCAL_PRIVATE_ACTIONS, action) && !localPrivate)) {
    throw new Error(`Unsupported Docker action command: ${command || "(empty)"}`);
  }
  return action;
}

function parseFixedActionParameters(args) {
  if (!Array.isArray(args)) throw new TypeError("Docker action arguments must be an array");
  if (args.length) throw new Error("This fixed action accepts no parameters");
  return Object.freeze({});
}

function assertClaimedJobFileStat(stat, { expectedGid, expectedUid, maximumBytes }) {
  const size = statInteger(stat?.size);
  if (!stat || typeof stat.isFile !== "function" || !stat.isFile()
    || typeof stat.isSymbolicLink !== "function" || stat.isSymbolicLink()
    || statInteger(stat.nlink) !== 1
    || statInteger(stat.uid) !== expectedUid || statInteger(stat.gid) !== expectedGid
    || (statInteger(stat.mode) & 0o777) !== 0o600
    || size < 1 || size > maximumBytes || !hasStableClaimedJobTimestamps(stat)) {
    throw new Error("Claimed job file metadata, owner, mode, link count or size is invalid");
  }
}

function readClaimedJobDescriptor(fileSystem, descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = fileSystem.readSync(
      descriptor,
      bytes,
      offset,
      size - offset,
      offset,
    );
    if (!Number.isInteger(count) || count < 1 || count > size - offset) {
      throw new Error("Claimed job changed before a complete descriptor read");
    }
    offset += count;
  }
  return bytes;
}

function sameClaimedJobMetadata(before, after) {
  try {
    return CLAIMED_JOB_METADATA_FIELDS.every((field) => {
      const left = ["mtimeMs", "ctimeMs"].includes(field)
        ? before[field]
        : statInteger(before[field]);
      const right = ["mtimeMs", "ctimeMs"].includes(field)
        ? after[field]
        : statInteger(after[field]);
      return Object.is(left, right);
    }) && before.isFile() === after.isFile();
  } catch {
    return false;
  }
}

function hasStableClaimedJobTimestamps(stat) {
  return ["mtimeMs", "ctimeMs"].every(
    (field) => typeof stat[field] === "number" && Number.isFinite(stat[field]),
  );
}

function statInteger(value) {
  const number = typeof value === "bigint" ? Number(value) : value;
  return Number.isSafeInteger(number) ? number : Number.NaN;
}

function isUnixIdentity(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff;
}

function assertClaimedJobDocument(document, fileName) {
  const requiredKeys = [
    "createdAt",
    "environment",
    "finishedAt",
    "id",
    "operation",
    "reportPaths",
    "requestedBy",
    "resources",
    "resultSummary",
    "schema",
    "scope",
    "startedAt",
    "status",
    "updatedAt",
  ];
  if (!isPlainRecord(document)
    || !hasExactKeys(document, requiredKeys, ["logPath", "manifestPath", "sourceManifestPath"])) {
    throw new Error("Claimed job document fields are invalid");
  }
  if (document.schema !== BACKUP_JOB_SCHEMA) throw new Error("Backup job schema is invalid");
  if (typeof document.id !== "string") throw new TypeError("Claimed job ID must be a primitive string");
  if (!/^[a-z0-9][a-z0-9-]{15,127}$/.test(document.id)) throw new Error("Claimed job ID is invalid");
  if (fileName !== `${document.id}.json`) {
    throw new Error("Claimed job filename does not exactly match its job ID identity");
  }
  if (typeof document.operation !== "string") {
    throw new TypeError("Claimed job operation must be a primitive string");
  }
  if (!["backup", "restore-drill"].includes(document.operation)) {
    throw new Error("Claimed job operation is not a supported backup operation");
  }
  if (document.status !== "running") throw new Error("Claimed job status must be running");
  if (!isExactText(document.requestedBy, /^[A-Za-z0-9@._:+/-]+$/, 200)
    || !isExactText(document.environment, /^[a-z0-9-]+$/, 32)
    || !isExactIsoTime(document.createdAt) || !isExactIsoTime(document.updatedAt)
    || !isNullableExactIsoTime(document.startedAt) || !isNullableExactIsoTime(document.finishedAt)
    || typeof document.resultSummary !== "string" || document.resultSummary.length > 500
    || !Array.isArray(document.reportPaths) || document.reportPaths.length > 32
    || document.reportPaths.some((candidate) => !isExactRelativeBackupPath(candidate))) {
    throw new Error("Claimed job startedAt or other typed timestamps and fields are invalid");
  }
  if (!isPlainRecord(document.scope)
    || !hasExactKeys(document.scope, ["id", "kind"])
    || !["application", "platform"].includes(document.scope.kind)
    || (document.scope.kind === "platform"
      ? document.scope.id !== "platform"
      : !isProjectIdentifier(document.scope.id))) {
    throw new Error("Claimed job scope is invalid");
  }
  if (!Array.isArray(document.resources) || document.resources.length < 1
    || document.resources.length > 256) {
    throw new Error("Claimed job backup resources must be a non-empty bounded array");
  }
  const resourceIds = new Set();
  for (const resource of document.resources) {
    assertClaimedJobResource(resource, document.scope);
    if (resourceIds.has(resource.id)) throw new Error("Claimed job contains a duplicate resource");
    resourceIds.add(resource.id);
  }
  if (document.operation === "restore-drill") {
    if (!isExactRelativeBackupPath(document.sourceManifestPath)
      || !document.sourceManifestPath.startsWith("manifests/")) {
      throw new Error("Claimed restore job source manifest is invalid");
    }
  } else if (Object.hasOwn(document, "sourceManifestPath")) {
    throw new Error("Claimed backup job contains a restore source manifest");
  }
  if (Object.hasOwn(document, "manifestPath")
    && !isExactRelativeBackupPath(document.manifestPath)) {
    throw new Error("Claimed job manifest path is invalid");
  }
  if (Object.hasOwn(document, "logPath")
    && (typeof document.logPath !== "string" || !path.isAbsolute(document.logPath)
      || path.basename(document.logPath) !== `manual-backup-${document.id}.log`)) {
    throw new Error("Claimed job log path is invalid");
  }
}

function assertClaimedJobResource(resource, scope) {
  if (!isPlainRecord(resource) || typeof resource.kind !== "string") {
    throw new Error("Claimed job resource identity is invalid");
  }
  const kindKeys = {
    database: ["engine", "externalId", "id", "kind", "name", "projectId"],
    source: ["externalId", "id", "kind", "name", "projectId", "sourceDirectory"],
    storage: ["externalId", "id", "kind", "name", "projectId"],
    "platform-state": ["externalId", "id", "kind", "name", "projectId"],
  }[resource.kind];
  if (!kindKeys || !hasExactKeys(resource, kindKeys)
    || !isGeneralIdentifier(resource.externalId)
    || resource.id !== `${resource.kind}:${resource.externalId}`
    || !isProjectIdentifier(resource.projectId)
    || !isExactText(resource.name, /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/, 128)
    || (scope.kind === "application" && resource.projectId !== scope.id)
    || (resource.kind === "platform-state" && resource.projectId !== "platform")
    || (resource.kind === "database" && !["postgres", "mariadb"].includes(resource.engine))
    || (resource.kind === "source"
      && !isExactText(resource.sourceDirectory, /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/, 128))) {
    throw new Error("Claimed job resource identity is invalid");
  }
}

function isPlainRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, required, optional = []) {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && keys.every((key) => allowed.has(key))
    && keys.length >= required.length
    && keys.length <= required.length + optional.length;
}

function isGeneralIdentifier(value) {
  return isExactText(value, /^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/, 160);
}

function isProjectIdentifier(value) {
  return isExactText(value, /^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/, 80);
}

function isExactText(value, pattern, maximumLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maximumLength
    && value.trim() === value && pattern.test(value);
}

function isExactIsoTime(value) {
  if (typeof value !== "string") return false;
  const time = new Date(value);
  return Number.isFinite(time.getTime()) && time.toISOString() === value;
}

function isNullableExactIsoTime(value) {
  return value === null || isExactIsoTime(value);
}

function isExactRelativeBackupPath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 512
    && value.trim() === value && !value.includes("\0") && !value.includes("\\")
    && !value.startsWith("/")
    && value.split("/").every((part) => part && part !== "." && part !== "..");
}

export function protectedCapability(file, {
  expectedUid = 0,
  expectedGid = 0,
  parentRoot = "/",
} = {}) {
  const resolved = path.resolve(file);
  assertProtectedParentChain(path.dirname(resolved), { expectedUid, expectedGid, parentRoot });
  let descriptor;
  try {
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.uid !== expectedUid || before.gid !== expectedGid
      || before.size < 32 || before.size > 4096 || (before.mode & 0o077) !== 0 || (before.mode & 0o400) === 0) {
      throw new Error("Docker action capability ownership, links, permissions or size are invalid");
    }
    const first = readDescriptor(descriptor, before.size);
    const second = readDescriptor(descriptor, before.size);
    const after = fs.fstatSync(descriptor);
    if (!["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"]
      .every((field) => before[field] === after[field])
      || first.length !== second.length || !crypto.timingSafeEqual(first, second)) {
      throw new Error("Docker action capability changed while being read");
    }
    return first;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function assertProtectedParentChain(directory, { expectedUid, expectedGid, parentRoot }) {
  let current = path.resolve(directory);
  const stop = path.resolve(parentRoot);
  const prefix = stop === path.parse(stop).root ? stop : `${stop}${path.sep}`;
  if (current !== stop && !current.startsWith(prefix)) {
    throw new Error("Docker action capability parent escaped its trusted root");
  }
  while (true) {
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedUid || stat.gid !== expectedGid
      || (stat.mode & 0o022) !== 0) {
      throw new Error("Docker action capability parent directory is unsafe");
    }
    if (current === stop) break;
    const parent = path.dirname(current);
    if (parent === current) throw new Error("Docker action capability parent did not reach its trusted root");
    current = parent;
  }
}

function readDescriptor(descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = fs.readSync(descriptor, bytes, offset, size - offset, offset);
    if (count === 0) break;
    offset += count;
  }
  if (offset !== size) throw new Error("Docker action capability changed while being read");
  return bytes;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const localAdmissionFile = process.env.DOCKER_ACTION_LOCAL_ADMISSION_FILE;
  const localCapabilityDir = process.env.DOCKER_ACTION_LOCAL_CAPABILITY_DIR;
  const action = resolveClientAction(command, { localPrivate: Boolean(localAdmissionFile) });
  const contract = ACTIONS[action];
  const capabilityFile = localAdmissionFile && localCapabilityDir
    ? path.join(localCapabilityDir, path.basename(contract.capabilityFile))
    : contract.capabilityFile;
  const capabilityKey = protectedCapability(capabilityFile, localAdmissionFile ? {
    expectedGid: process.getgid(),
    expectedUid: process.getuid(),
    parentRoot: localCapabilityDir,
  } : undefined);
  let runtimeIntentId = process.env.DOCKER_ACTION_RUNTIME_INTENT_ID;
  let activeReceiptSha256 = process.env.DOCKER_ACTION_ACTIVE_RECEIPT_SHA256;
  let combinedRenderSha256 = process.env.DOCKER_ACTION_COMBINED_RENDER_SHA256;
  if (localAdmissionFile) {
    if (!localCapabilityDir || !process.env.DOCKER_ACTION_LOCAL_PUBLIC_KEY_FILE) {
      throw new Error("LOCAL_PRIVATE client admission paths are incomplete");
    }
    const capabilityFiles = Object.fromEntries(LOCAL_PRIVATE_ALLOWED_ACTIONS.map((localAction) => [
      localAction,
      path.join(localCapabilityDir, path.basename(ACTIONS[localAction].capabilityFile)),
    ]));
    const verified = verifyAdmissionDocument(readCanonicalAdmission(localAdmissionFile), {
      capabilityFiles,
      publicKeyPem: fs.readFileSync(process.env.DOCKER_ACTION_LOCAL_PUBLIC_KEY_FILE),
    });
    if (!verified.payload.allowedActions.includes(action)) {
      throw new Error(`LOCAL_PRIVATE admission does not allow ${action}`);
    }
    runtimeIntentId = verified.payload.admissionId;
    activeReceiptSha256 = verified.receiptDigest;
    combinedRenderSha256 = verified.payload.combinedRenderSha256;
  }
  const response = await runClientCommand(command, args, {
    runtimeIntentId,
    activeReceiptSha256,
    combinedRenderSha256,
    capabilityKey,
    claimedJobPolicy: defaultClaimedJobPolicy(process.env),
    localPrivate: Boolean(localAdmissionFile),
    socketPath: process.env.DOCKER_ACTION_BROKER_SOCKET || DEFAULT_SOCKET,
  });
  process.stdout.write(`${canonicalJson(response)}\n`);
  if (response.statusCode !== 200 || response.status !== "completed") process.exitCode = 77;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    if (error instanceof DockerActionOutcomeUnknownError) {
      process.stderr.write(`${canonicalJson({
        action: error.action,
        outcome: error.outcome,
        requestId: error.requestId,
        requestSha256: error.requestSha256,
        retrySafe: error.retrySafe,
      })}\n`);
      process.exitCode = UNKNOWN_AFTER_ADMISSION_EXIT_CODE;
      return;
    }
    process.stderr.write(`${error.message ?? error}\n`);
    process.exitCode = 1;
  });
}
