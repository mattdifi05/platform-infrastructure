import { createHash } from "node:crypto";
import { closeSync, existsSync, lstatSync, openSync, readFileSync, readSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import {
  backupDocumentDigest,
  backupResourceId,
  parseBackupManifestDocument,
} from "../backup/contracts.mjs";

export const DATABASE_DELETE_OPERATION_SCHEMA = "platform.database-delete-operation/v1";

const statuses = new Set([
  "evidence-verified",
  "approved",
  "executing",
  "database-dropped",
  "completed",
  "failed",
  "rollback-required",
]);

const transitions = new Map([
  ["evidence-verified", new Set(["approved"])],
  ["approved", new Set(["executing"])],
  ["executing", new Set(["database-dropped", "failed"])],
  ["database-dropped", new Set(["completed", "rollback-required"])],
  ["failed", new Set(["approved"])],
]);

function requiredText(value, label, pattern = /^[A-Za-z0-9@._:+/-]+$/, maxLength = 256) {
  const clean = String(value ?? "").trim();
  if (!clean || clean.length > maxLength || !pattern.test(clean)) throw new Error(`Invalid ${label}.`);
  return clean;
}

function identifier(value, label = "identifier") {
  return requiredText(value, label, /^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/, 160);
}

function isoDate(value, label) {
  const date = new Date(value);
  if (!value || !Number.isFinite(date.getTime())) throw new Error(`Invalid ${label}.`);
  return date.toISOString();
}

function regularFiles(directory, limit = 1000) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .slice(0, limit)
    .map((name) => path.join(directory, name))
    .filter((filePath) => {
      const stat = lstatSync(filePath);
      return stat.isFile() && !stat.isSymbolicLink();
    });
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function fileSha256(filePath) {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const descriptor = openSync(filePath, "r");
  try {
    let bytesRead = 0;
    do {
      bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
  } finally {
    closeSync(descriptor);
  }
  return hash.digest("hex");
}

function freshTimestamp(value, nowMs, maxAgeMs, notBeforeMs = 0) {
  const timestamp = Date.parse(value || "");
  return Number.isFinite(timestamp) && timestamp >= notBeforeMs && timestamp <= nowMs && nowMs - timestamp <= maxAgeMs;
}

function exactDatabase(database) {
  const id = identifier(database?.id, "database id");
  const engine = requiredText(database?.engine, "database engine", /^(mariadb|postgres)$/, 16);
  const name = requiredText(database?.name, "database name", /^[a-z][a-z0-9_]{0,62}$/, 63);
  const projectId = requiredText(database?.projectId, "project id", /^[a-z0-9](?:[a-z0-9-]{0,62})$/, 63);
  return { id, engine, name, projectId, resourceId: backupResourceId("database", id) };
}

function validateArtifactSidecars(root, artifact) {
  const artifactPath = path.resolve(root, artifact.path);
  if (!artifactPath.startsWith(`${root}${path.sep}`) || !existsSync(artifactPath)) return null;
  const artifactStat = lstatSync(artifactPath);
  if (!artifactStat.isFile() || artifactStat.isSymbolicLink() || artifactStat.size !== artifact.sizeBytes) return null;
  const checksumPath = `${artifactPath}.sha256`;
  const signaturePath = `${artifactPath}.sig.json`;
  if (!existsSync(checksumPath) || !existsSync(signaturePath)) return null;
  if ([checksumPath, signaturePath].some((filePath) => {
    const stat = lstatSync(filePath);
    return !stat.isFile() || stat.isSymbolicLink();
  })) return null;
  const checksum = String(readFileSync(checksumPath, "ascii")).trim().split(/\s+/)[0] || "";
  const signature = readJson(signaturePath);
  if (checksum !== artifact.sha256
    || fileSha256(artifactPath) !== artifact.sha256
    || signature.algorithm !== "HMAC-SHA256"
    || signature.hash !== artifact.sha256
    || signature.keyId !== artifact.signatureKeyId
    || !String(signature.signature || "")) return null;
  return { artifactPath, checksumPath, signaturePath };
}

function verifiedManifestCandidates(backupRoot, database, nowMs, maxAgeMs) {
  const root = path.resolve(backupRoot);
  const manifestDirectory = path.join(root, "manifests");
  const candidates = [];
  for (const manifestFile of regularFiles(manifestDirectory)) {
    try {
      const manifest = parseBackupManifestDocument(readJson(manifestFile));
      if (!manifest.signature || manifest.signature.digest !== backupDocumentDigest(manifest)) continue;
      if (!freshTimestamp(manifest.createdAt, nowMs, maxAgeMs)) continue;
      const artifact = manifest.artifacts.find((item) => item.resourceId === database.resourceId);
      const resource = manifest.resources.find((item) => item.id === database.resourceId);
      if (!artifact || !resource || resource.engine !== database.engine || resource.name !== database.name) continue;
      if (!validateArtifactSidecars(root, artifact)) continue;
      candidates.push({
        manifest,
        manifestPath: path.relative(root, manifestFile).replaceAll("\\", "/"),
        manifestFile,
        artifact,
      });
    } catch {
      // Invalid or incomplete candidates do not satisfy a destructive gate.
    }
  }
  return candidates.sort((left, right) => String(right.manifest.createdAt).localeCompare(String(left.manifest.createdAt)) || right.manifest.id.localeCompare(left.manifest.id));
}

function matchingRestoreReport(reportsRoot, database, candidate, nowMs, maxAgeMs) {
  const directory = path.join(path.resolve(reportsRoot), "backup-jobs");
  const manifestTime = Date.parse(candidate.manifest.createdAt);
  for (const reportFile of regularFiles(directory).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)) {
    try {
      const report = readJson(reportFile);
      if (report.status !== "passed" || report.operation !== "restore-drill" || report.liveDataChanged !== false) continue;
      if (report.manifestPath !== candidate.manifestPath || !Array.isArray(report.resourceIds) || !report.resourceIds.includes(database.resourceId)) continue;
      if (!Array.isArray(report.results) || !report.results.some((result) => result.resourceId === database.resourceId && result.status === "passed")) continue;
      if (!freshTimestamp(report.finishedAt, nowMs, maxAgeMs, manifestTime)) continue;
      return {
        path: path.relative(path.resolve(reportsRoot), reportFile).replaceAll("\\", "/"),
        sha256: fileSha256(reportFile),
        finishedAt: new Date(report.finishedAt).toISOString(),
        jobId: identifier(report.jobId, "restore job id"),
      };
    } catch {
      // Continue to an older valid receipt.
    }
  }
  return null;
}

function matchingOffsiteReceipt(reportsRoot, database, candidate, nowMs, maxAgeMs) {
  const directory = path.join(path.resolve(reportsRoot), "offsite-backups");
  const manifestTime = Date.parse(candidate.manifest.createdAt);
  for (const receiptFile of regularFiles(directory).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)) {
    try {
      const receipt = readJson(receiptFile);
      if (receipt.schema !== "platform.offsite-backup-receipt/v1" || receipt.status !== "passed" || receipt.repositoryOffsite !== true) continue;
      if (receipt.manifestId !== candidate.manifest.id || receipt.manifestPath !== candidate.manifestPath || receipt.manifestDigest !== candidate.manifest.signature.digest) continue;
      if (!Array.isArray(receipt.resourceIds) || !receipt.resourceIds.includes(database.resourceId) || !String(receipt.snapshotId || "")) continue;
      if (!freshTimestamp(receipt.finishedAt, nowMs, maxAgeMs, manifestTime)) continue;
      return {
        path: path.relative(path.resolve(reportsRoot), receiptFile).replaceAll("\\", "/"),
        sha256: fileSha256(receiptFile),
        finishedAt: new Date(receipt.finishedAt).toISOString(),
        snapshotId: requiredText(receipt.snapshotId, "snapshot id", /^[A-Za-z0-9._:-]+$/, 160),
        hostname: requiredText(receipt.hostname, "Restic hostname", /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/, 64),
      };
    } catch {
      // Continue to an older valid receipt.
    }
  }
  return null;
}

export function findDatabaseDeleteRestorePoint({ database: input, backupRoot, reportsRoot, now = new Date(), maxAgeMs = 24 * 60 * 60 * 1000 }) {
  const database = exactDatabase(input);
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs) || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 60_000) throw new Error("Invalid database delete evidence window.");
  const manifests = verifiedManifestCandidates(backupRoot, database, nowMs, maxAgeMs);
  const blockers = new Set();
  if (!manifests.length) blockers.add("fresh-exact-backup-manifest-missing");
  for (const candidate of manifests) {
    const restoreReport = matchingRestoreReport(reportsRoot, database, candidate, nowMs, maxAgeMs);
    const offsiteReceipt = matchingOffsiteReceipt(reportsRoot, database, candidate, nowMs, maxAgeMs);
    if (!restoreReport) blockers.add("fresh-exact-restore-drill-missing");
    if (!offsiteReceipt) blockers.add("fresh-exact-offsite-receipt-missing");
    if (!restoreReport || !offsiteReceipt) continue;
    const evidence = {
      resourceId: database.resourceId,
      manifest: {
        id: candidate.manifest.id,
        path: candidate.manifestPath,
        digest: candidate.manifest.signature.digest,
        createdAt: new Date(candidate.manifest.createdAt).toISOString(),
        artifactSha256: candidate.artifact.sha256,
        artifactSizeBytes: candidate.artifact.sizeBytes,
      },
      restoreReport,
      offsiteReceipt,
      verifiedAt: new Date(nowMs).toISOString(),
      maxAgeMs,
    };
    return { ready: true, blockers: [], evidence: { ...evidence, fingerprint: databaseDeleteEvidenceFingerprint(evidence) } };
  }
  return { ready: false, blockers: [...blockers], evidence: null };
}

export function databaseDeleteEvidenceFingerprint(evidence) {
  return createHash("sha256").update(JSON.stringify({
    resourceId: evidence.resourceId,
    manifest: evidence.manifest,
    restoreReport: evidence.restoreReport,
    offsiteReceipt: evidence.offsiteReceipt,
    maxAgeMs: evidence.maxAgeMs,
  })).digest("hex");
}

export function createDatabaseDeleteOperation({ id, database: input, evidence, idempotencyKey, requestedBy, now = new Date() }) {
  const database = exactDatabase(input);
  if (!evidence || evidence.resourceId !== database.resourceId || evidence.fingerprint !== databaseDeleteEvidenceFingerprint(evidence)) {
    throw new Error("Database delete evidence does not match the exact resource.");
  }
  const timestamp = new Date(now).toISOString();
  return {
    schema: DATABASE_DELETE_OPERATION_SCHEMA,
    id: identifier(id, "operation id"),
    database: {
      id: database.id,
      projectId: database.projectId,
      engine: database.engine,
      name: database.name,
      ownerRole: requiredText(input.ownerRole, "database owner", /^[a-z][a-z0-9_]{0,62}$/, 63),
      principalBindingId: identifier(input.principalBindingId || input.id, "principal binding id"),
      credentialFile: input.credentialFile ? requiredText(input.credentialFile, "credential file", /^\/[A-Za-z0-9._/-]+$/, 512) : "",
    },
    resourceId: database.resourceId,
    status: "evidence-verified",
    idempotencyKey: requiredText(idempotencyKey, "idempotency key", /^[A-Za-z0-9._:-]+$/, 160),
    requestedBy: requiredText(requestedBy, "requester"),
    requestedAt: timestamp,
    evidence,
    evidenceFingerprint: evidence.fingerprint,
    approval: null,
    execution: { attempts: 0, startedAt: null, databaseDroppedAt: null, completedAt: null, failure: "" },
    updatedAt: timestamp,
  };
}

export function parseDatabaseDeleteOperation(input) {
  if (!input || input.schema !== DATABASE_DELETE_OPERATION_SCHEMA || !statuses.has(input.status)) throw new Error("Invalid database delete operation.");
  const operation = createDatabaseDeleteOperation({
    id: input.id,
    database: input.database,
    evidence: input.evidence,
    idempotencyKey: input.idempotencyKey,
    requestedBy: input.requestedBy,
    now: input.requestedAt,
  });
  return {
    ...operation,
    status: input.status,
    approval: input.approval ? {
      approvedBy: requiredText(input.approval.approvedBy, "approver"),
      approvedAt: isoDate(input.approval.approvedAt, "approval timestamp"),
    } : null,
    execution: {
      attempts: Number.isSafeInteger(input.execution?.attempts) && input.execution.attempts >= 0 ? input.execution.attempts : 0,
      startedAt: input.execution?.startedAt ? isoDate(input.execution.startedAt, "execution timestamp") : null,
      databaseDroppedAt: input.execution?.databaseDroppedAt ? isoDate(input.execution.databaseDroppedAt, "database drop timestamp") : null,
      completedAt: input.execution?.completedAt ? isoDate(input.execution.completedAt, "completion timestamp") : null,
      failure: String(input.execution?.failure || "").slice(0, 500),
    },
    updatedAt: isoDate(input.updatedAt || input.requestedAt, "operation update timestamp"),
  };
}

export function transitionDatabaseDeleteOperation(input, nextStatus, details = {}, now = new Date()) {
  const operation = parseDatabaseDeleteOperation(input);
  const next = requiredText(nextStatus, "database delete status", /^[a-z-]+$/, 32);
  if (operation.status === next && new Set(["approved", "completed"]).has(next)) return operation;
  if (!transitions.get(operation.status)?.has(next)) throw new Error(`Invalid database delete transition: ${operation.status} -> ${next}`);
  const timestamp = new Date(now).toISOString();
  const updated = { ...operation, status: next, updatedAt: timestamp };
  if (next === "approved") {
    updated.approval = { approvedBy: requiredText(details.approvedBy, "approver"), approvedAt: timestamp };
  }
  if (next === "executing") {
    updated.execution = { ...operation.execution, attempts: operation.execution.attempts + 1, startedAt: timestamp, failure: "" };
  }
  if (next === "database-dropped") updated.execution = { ...operation.execution, databaseDroppedAt: timestamp };
  if (next === "completed") updated.execution = { ...operation.execution, completedAt: timestamp, failure: "" };
  if (next === "failed" || next === "rollback-required") updated.execution = { ...operation.execution, failure: String(details.failure || "operation failed").slice(0, 500) };
  return updated;
}

export function databaseDeleteConfirmation(database, phase, operationId = "") {
  const exact = exactDatabase(database);
  const action = requiredText(phase, "delete phase", /^(REQUEST|APPROVE|EXECUTE)$/, 16);
  const suffix = action === "REQUEST" ? exact.id : identifier(operationId, "operation id");
  return `${action}-DATABASE-DELETE:${suffix}`;
}
