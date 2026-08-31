#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson, sha256 } from "./docker-action-contract.mjs";

export const LOCAL_PRIVATE_ADMISSION_SCHEMA = "platform.local-private-backup-admission/v1";
export const LOCAL_PRIVATE_ALLOWED_ACTIONS = Object.freeze([
  "backup.catalog",
  "backup.job.execute",
  "backup.offsite.sync",
]);
const SHA256 = /^[a-f0-9]{64}$/;
const SHA1 = /^[a-f0-9]{40}$/;
const LOGICAL_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const MAX_DOCUMENT_BYTES = 64 * 1024;
const MAX_LIFETIME_MS = 31 * 24 * 60 * 60_000;
const CLOCK_SKEW_MS = 30_000;
const CAPABILITY_BINDINGS = Object.freeze({
  "capability.backup.catalog": "/run/secrets/docker_action_backup_catalog",
  "capability.backup.job.execute": "/run/secrets/docker_action_backup_job_execute",
  "capability.backup.offsite.sync": "/run/secrets/docker_action_backup_offsite_sync",
});
const LOCAL_PRIVATE_RESTIC_REPOSITORY = "rclone:platform-onedrive:platform-infrastructure/restic";
const LOCAL_PRIVATE_RESTIC_PASSWORD_PATH = "/run/platform/critical/restic_password.txt";
const LOCAL_PRIVATE_RCLONE_CONFIG_PATH = "/run/platform/critical/rclone/rclone.conf";
const LOCAL_PRIVATE_BACKUP_JOBS_ROOT = "/var/lib/platform-backup-data/backup-jobs";

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, required, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(`${label} must be a plain object`);
  }
  const keys = Object.keys(value).sort();
  const expected = [...required].sort();
  if (canonicalJson(keys) !== canonicalJson(expected)) fail(`${label} fields are invalid`);
}

function exactTime(value, label) {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) {
    fail(`${label} is not an exact ISO timestamp`);
  }
  return Date.parse(value);
}

export function fileSha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function publicKeyId(publicKey) {
  const key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  const der = key.export({ format: "der", type: "spki" });
  return `ed25519-${sha256(der).slice(0, 24)}`;
}

function signedBytes(payload) {
  return Buffer.from(`${LOCAL_PRIVATE_ADMISSION_SCHEMA}\0${canonicalJson(payload)}`);
}

export function createAdmissionPayload({
  backupSigningKeySha256,
  brokerImageId,
  catalogCapabilitySha256,
  combinedRenderSha256,
  expiresAt,
  generation = 1,
  issuedAt,
  jobCapabilitySha256,
  offsiteCapabilitySha256,
  previousAdmissionSha256 = "0".repeat(64),
  releaseCommitSha1,
  resticImageId,
  resticRepository = LOCAL_PRIVATE_RESTIC_REPOSITORY,
  sourceRenderSha256 = combinedRenderSha256,
  schedulerImageId,
  targetId = "dell-192-168-1-202",
  treeSha256,
} = {}) {
  const short = String(releaseCommitSha1 ?? "").slice(0, 12);
  const resources = {
    backupResources: {
      "control-center.backup-queue": {
        authority: "local-private-backup-only-service-queue",
        brokerRoot: `${LOCAL_PRIVATE_BACKUP_JOBS_ROOT}/running`,
      },
    },
    capabilityFiles: {
      "capability.backup.catalog": {
        brokerPath: CAPABILITY_BINDINGS["capability.backup.catalog"],
        sha256: catalogCapabilitySha256,
      },
      "capability.backup.job.execute": {
        brokerPath: CAPABILITY_BINDINGS["capability.backup.job.execute"],
        sha256: jobCapabilitySha256,
      },
      "capability.backup.offsite.sync": {
        brokerPath: CAPABILITY_BINDINGS["capability.backup.offsite.sync"],
        sha256: offsiteCapabilitySha256,
      },
    },
    offsite: {
      rcloneConfigPath: LOCAL_PRIVATE_RCLONE_CONFIG_PATH,
      repository: resticRepository,
      resticImageId,
      resticPasswordPath: LOCAL_PRIVATE_RESTIC_PASSWORD_PATH,
    },
  };
  return {
    admissionId: `local-private-backup-${short}`,
    allowedActions: [...LOCAL_PRIVATE_ALLOWED_ACTIONS],
    backupSigningKey: {
      brokerPath: "/run/platform/local-private-input/backup_signing_keys",
      sha256: backupSigningKeySha256,
    },
    candidateId: `dell-${short}`,
    brokerImageId,
    combinedRenderSha256,
    environment: "local-private",
    expiresAt,
    generation,
    issuedAt,
    previousAdmissionSha256,
    releaseCommitSha1,
    releaseId: `v1-1-${short}`,
    resources,
    sourceRenderSha256,
    schedulerImageId,
    targetId,
    treeSha256,
  };
}

export function signAdmission(payload, privateKeyPem) {
  const publicKey = crypto.createPublicKey(privateKeyPem);
  return {
    schema: LOCAL_PRIVATE_ADMISSION_SCHEMA,
    payload,
    signature: {
      algorithm: "Ed25519",
      keyId: publicKeyId(publicKey),
      value: crypto.sign(null, signedBytes(payload), privateKeyPem).toString("base64"),
    },
  };
}

export function verifyAdmissionDocument(document, {
  backupSigningKeyFile,
  capabilityFiles,
  now = Date.now(),
  publicKeyPem,
  renderFile,
} = {}) {
  exactKeys(document, ["payload", "schema", "signature"], "admission document");
  if (document.schema !== LOCAL_PRIVATE_ADMISSION_SCHEMA) fail("unsupported local-private admission schema");
  exactKeys(document.signature, ["algorithm", "keyId", "value"], "admission signature");
  if (document.signature.algorithm !== "Ed25519") fail("unsupported admission signature algorithm");
  const publicKey = publicKeyPem?.type === "public" ? publicKeyPem : crypto.createPublicKey(publicKeyPem);
  if (document.signature.keyId !== publicKeyId(publicKey)) fail("admission signing key identity mismatch");
  let signature;
  try {
    signature = Buffer.from(document.signature.value, "base64");
  } catch {
    fail("admission signature encoding is invalid");
  }
  if (signature.toString("base64") !== document.signature.value) fail("admission signature encoding is invalid");
  if (signature.length !== 64 || !crypto.verify(null, signedBytes(document.payload), publicKey, signature)) {
    fail("local-private admission signature rejected");
  }

  const payload = document.payload;
  exactKeys(payload, [
    "admissionId", "allowedActions", "backupSigningKey", "brokerImageId", "candidateId",
    "combinedRenderSha256", "environment", "expiresAt", "generation", "issuedAt",
    "previousAdmissionSha256", "releaseCommitSha1", "releaseId", "resources",
    "schedulerImageId", "sourceRenderSha256", "targetId", "treeSha256",
  ], "admission payload");
  for (const [name, value] of [
    ["admissionId", payload.admissionId], ["candidateId", payload.candidateId],
    ["environment", payload.environment], ["releaseId", payload.releaseId], ["targetId", payload.targetId],
  ]) if (typeof value !== "string" || !LOGICAL_ID.test(value)) fail(`admission ${name} is invalid`);
  if (payload.environment !== "local-private" || payload.targetId !== "dell-192-168-1-202") {
    fail("admission environment or target is not the Dell LOCAL_PRIVATE runtime");
  }
  if (!Number.isSafeInteger(payload.generation) || payload.generation < 1) fail("admission generation is invalid");
  if (!SHA1.test(String(payload.releaseCommitSha1 ?? ""))) fail("admission release commit is invalid");
  for (const [name, value] of [["brokerImageId", payload.brokerImageId], ["schedulerImageId", payload.schedulerImageId]]) {
    if (!/^sha256:[a-f0-9]{64}$/.test(String(value ?? "")) || value === `sha256:${"0".repeat(64)}`) {
      fail(`admission ${name} is invalid`);
    }
  }
  for (const [name, value] of [
    ["combinedRenderSha256", payload.combinedRenderSha256],
    ["previousAdmissionSha256", payload.previousAdmissionSha256],
    ["sourceRenderSha256", payload.sourceRenderSha256],
    ["treeSha256", payload.treeSha256],
  ]) if (!SHA256.test(String(value ?? ""))) fail(`admission ${name} is invalid`);
  if (canonicalJson(payload.allowedActions) !== canonicalJson(LOCAL_PRIVATE_ALLOWED_ACTIONS)) {
    fail("admission action set is not the fixed LOCAL_PRIVATE backup surface");
  }
  const issuedAt = exactTime(payload.issuedAt, "admission issuedAt");
  const expiresAt = exactTime(payload.expiresAt, "admission expiresAt");
  if (!Number.isFinite(now) || expiresAt <= issuedAt || expiresAt - issuedAt > MAX_LIFETIME_MS
    || now < issuedAt - CLOCK_SKEW_MS || now > expiresAt) {
    fail("admission validity window rejected");
  }

  exactKeys(payload.backupSigningKey, ["brokerPath", "sha256"], "backup signing key binding");
  if (payload.backupSigningKey.brokerPath !== "/run/platform/local-private-input/backup_signing_keys"
    || !SHA256.test(String(payload.backupSigningKey.sha256 ?? ""))) {
    fail("backup signing key binding is invalid");
  }
  exactKeys(payload.resources, ["backupResources", "capabilityFiles", "offsite"], "admission resources");
  exactKeys(payload.resources.backupResources, ["control-center.backup-queue"], "backup resource admission");
  exactKeys(payload.resources.backupResources["control-center.backup-queue"], ["authority", "brokerRoot"], "backup queue admission");
  if (payload.resources.backupResources["control-center.backup-queue"].authority !== "local-private-backup-only-service-queue"
    || payload.resources.backupResources["control-center.backup-queue"].brokerRoot !== `${LOCAL_PRIVATE_BACKUP_JOBS_ROOT}/running`) {
    fail("backup queue admission is invalid");
  }
  exactKeys(payload.resources.capabilityFiles, Object.keys(CAPABILITY_BINDINGS), "capability bindings");
  for (const [id, brokerPath] of Object.entries(CAPABILITY_BINDINGS)) {
    const binding = payload.resources.capabilityFiles[id];
    exactKeys(binding, ["brokerPath", "sha256"], `capability binding ${id}`);
    if (binding.brokerPath !== brokerPath || !SHA256.test(String(binding.sha256 ?? ""))) {
      fail(`capability binding ${id} is invalid`);
    }
  }
  exactKeys(payload.resources.offsite, [
    "rcloneConfigPath", "repository", "resticImageId", "resticPasswordPath",
  ], "offsite admission");
  if (payload.resources.offsite.repository !== LOCAL_PRIVATE_RESTIC_REPOSITORY
    || payload.resources.offsite.resticPasswordPath !== LOCAL_PRIVATE_RESTIC_PASSWORD_PATH
    || payload.resources.offsite.rcloneConfigPath !== LOCAL_PRIVATE_RCLONE_CONFIG_PATH
    || !/^sha256:[a-f0-9]{64}$/.test(String(payload.resources.offsite.resticImageId ?? ""))
    || payload.resources.offsite.resticImageId === `sha256:${"0".repeat(64)}`) {
    fail("offsite admission is invalid");
  }

  if (renderFile && fileSha256(renderFile) !== payload.combinedRenderSha256) fail("runtime render hash differs from signed admission");
  if (backupSigningKeyFile && fileSha256(backupSigningKeyFile) !== payload.backupSigningKey.sha256) {
    fail("backup signing key hash differs from signed admission");
  }
  if (capabilityFiles) {
    for (const [action, file] of Object.entries(capabilityFiles)) {
      const binding = payload.resources.capabilityFiles[`capability.${action}`];
      if (!binding || fileSha256(file) !== binding.sha256) fail(`capability hash differs for ${action}`);
    }
  }
  return Object.freeze({
    document: Object.freeze(document),
    payload: Object.freeze(payload),
    receiptDigest: sha256(canonicalJson(payload)),
  });
}

export function readCanonicalAdmission(file) {
  const bytes = fs.readFileSync(file);
  if (bytes.length < 2 || bytes.length > MAX_DOCUMENT_BYTES) fail("admission file size is invalid");
  const document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!bytes.equals(Buffer.from(`${canonicalJson(document)}\n`))) fail("admission file is not canonical JSON");
  return document;
}

function parseArgs(tokens) {
  const parsed = { _: [] };
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("--")) parsed._.push(token);
    else {
      const name = token.slice(2);
      const value = tokens[index + 1];
      if (!value || value.startsWith("--")) fail(`missing value for --${name}`);
      parsed[name] = value;
      index += 1;
    }
  }
  return parsed;
}

function writePrivateCanonical(file, value) {
  const parent = path.dirname(path.resolve(file));
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  fs.chmodSync(parent, 0o700);
  const descriptor = fs.openSync(file, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, Buffer.from(`${canonicalJson(value)}\n`));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];
  if (command === "create") {
    const issuedAt = args.issuedAt ?? new Date().toISOString();
    const expiresAt = args.expiresAt ?? new Date(Date.parse(issuedAt) + 30 * 24 * 60 * 60_000).toISOString();
    const payload = createAdmissionPayload({
      backupSigningKeySha256: fileSha256(args.backupSigningKey),
      brokerImageId: args.brokerImageId,
      catalogCapabilitySha256: fileSha256(args.catalogCapability),
      combinedRenderSha256: fileSha256(args.renderFile),
      expiresAt,
      generation: Number(args.generation ?? 1),
      issuedAt,
      jobCapabilitySha256: fileSha256(args.jobCapability),
      offsiteCapabilitySha256: fileSha256(args.offsiteCapability),
      previousAdmissionSha256: args.previousAdmissionSha256,
      releaseCommitSha1: args.releaseCommit,
      resticImageId: args.resticImageId,
      schedulerImageId: args.schedulerImageId,
      treeSha256: args.treeSha256,
    });
    const document = signAdmission(payload, fs.readFileSync(args.privateKey));
    writePrivateCanonical(args.output, document);
    process.stdout.write(`${canonicalJson({ admissionSha256: fileSha256(args.output), keyId: document.signature.keyId, status: "created" })}\n`);
    return;
  }
  if (command === "verify") {
    const document = readCanonicalAdmission(args.admission);
    const verified = verifyAdmissionDocument(document, {
      backupSigningKeyFile: args.backupSigningKey,
      capabilityFiles: args.catalogCapability && args.jobCapability && args.offsiteCapability ? {
        "backup.catalog": args.catalogCapability,
        "backup.job.execute": args.jobCapability,
        "backup.offsite.sync": args.offsiteCapability,
      } : undefined,
      publicKeyPem: fs.readFileSync(args.publicKey),
      renderFile: args.renderFile,
    });
    process.stdout.write(`${canonicalJson({ admissionId: verified.payload.admissionId, receiptDigest: verified.receiptDigest, status: "verified" })}\n`);
    return;
  }
  fail("usage: local-private-backup-admission.mjs create|verify [options]");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message ?? error}\n`);
    process.exitCode = 1;
  });
}
