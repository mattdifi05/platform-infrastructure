import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";

const SHA256 = /^[a-f0-9]{64}$/;
export const VERIFIED_WORKLOAD_LOCK_VERSION = 2;
export const VERIFIED_WORKLOAD_VALIDATOR_VERSION = "hosted-contract-v2";

export function validateVerifiedWorkloadLock(lock) {
  if (lock?.version !== VERIFIED_WORKLOAD_LOCK_VERSION
    || lock?.validatorVersion !== VERIFIED_WORKLOAD_VALIDATOR_VERSION
    || lock?.state !== "verified") {
    throw new Error("Hosted workload lock policy/version is not verified.");
  }
  if (!Array.isArray(lock.routes) || !Array.isArray(lock.workloads) || !Array.isArray(lock.files) || lock.files.length === 0) {
    throw new Error("Hosted workload lock inventory is incomplete.");
  }
  const expectedContentDigest = workloadContentDigest(lock.files);
  if (!SHA256.test(String(lock.workloadContentSha256 || "")) || lock.workloadContentSha256 !== expectedContentDigest) {
    throw new Error("Hosted workload lock content digest is invalid.");
  }

  const root = verifiedDirectory(lock.snapshotRoot, lock.snapshotRootIdentity, 0o700, "snapshot root");
  const generation = verifiedDirectory(lock.snapshotGeneration, lock.snapshotGenerationIdentity, 0o500, "snapshot generation");
  if (path.dirname(generation) !== root) throw new Error("Hosted workload snapshot generation leaves its verified root.");
  const effectiveUid = typeof process.getuid === "function" ? String(process.getuid()) : String(lock.snapshotRootIdentity?.uid);
  if (String(lock.snapshotRootIdentity?.uid) !== effectiveUid || String(lock.snapshotGenerationIdentity?.uid) !== effectiveUid) {
    throw new Error("Hosted workload snapshot is not owned by the deployment identity.");
  }

  const projectMetadataByWorkload = new Map();
  const projectMetadataBySource = new Map();
  for (const record of lock.files) {
    if (!record || typeof record !== "object" || Array.isArray(record)
      || !SHA256.test(String(record.sha256 || ""))
      || !Number.isSafeInteger(Number(record.sizeBytes)) || Number(record.sizeBytes) < 0) {
      throw new Error("Hosted workload lock file record is invalid.");
    }
    if (record.snapshot === true) verifySnapshotRecord(record, generation, lock.snapshotGenerationIdentity);
    if (record.kind !== "project-metadata") continue;
    const workloadId = String(record.workloadId || "");
    const sourcePath = String(record.sourcePath || "");
    if (!workloadId || !path.isAbsolute(sourcePath) || projectMetadataByWorkload.has(workloadId)
      || projectMetadataBySource.has(path.resolve(sourcePath))) {
      throw new Error("Hosted workload project metadata record is ambiguous.");
    }
    const normalized = {
      workloadId,
      sourcePath: path.resolve(sourcePath),
      path: path.resolve(String(record.path || "")),
      sha256: String(record.sha256),
      sizeBytes: Number(record.sizeBytes),
    };
    projectMetadataByWorkload.set(workloadId, normalized);
    projectMetadataBySource.set(normalized.sourcePath, normalized);
  }

  const workloadIds = new Set();
  const boundMetadata = new Set();
  for (const workload of lock.workloads) {
    const workloadId = String(workload?.id || "");
    if (!workloadId || workloadIds.has(workloadId)) throw new Error("Hosted workload identity is invalid or duplicated.");
    workloadIds.add(workloadId);
    const sourcePath = workload.projectMetadataSourcePath == null ? "" : String(workload.projectMetadataSourcePath);
    const snapshotPath = workload.projectMetadataPath == null ? "" : String(workload.projectMetadataPath);
    if (Boolean(sourcePath) !== Boolean(snapshotPath)) throw new Error("Hosted workload project metadata pointer is incomplete.");
    if (!sourcePath) {
      if (projectMetadataByWorkload.has(workloadId)) throw new Error("Hosted workload metadata record lacks a workload pointer.");
      continue;
    }
    const record = projectMetadataByWorkload.get(workloadId);
    if (!record || record.sourcePath !== path.resolve(sourcePath) || record.path !== path.resolve(snapshotPath)) {
      throw new Error("Hosted workload project metadata pointer does not match its snapshot record.");
    }
    boundMetadata.add(workloadId);
  }
  if (boundMetadata.size !== projectMetadataByWorkload.size) {
    throw new Error("Hosted workload project metadata record is not bound to exactly one workload.");
  }
  for (const route of lock.routes) {
    if (!workloadIds.has(String(route?.workloadId || ""))) throw new Error("Hosted workload route references an unknown workload.");
  }

  return {
    trustedEpoch: lock.workloadContentSha256,
    projectMetadata: projectMetadataBySource,
  };
}

export function workloadContentDigest(records) {
  const content = records
    .filter((record) => record?.snapshot === true)
    .map(({ kind, sourcePath, sha256, sizeBytes, workloadId = null }) => ({ kind, sourcePath, sha256, sizeBytes, workloadId }))
    .sort((left, right) => `${left.workloadId}:${left.kind}:${left.sourcePath}`.localeCompare(`${right.workloadId}:${right.kind}:${right.sourcePath}`));
  return createHash("sha256").update(JSON.stringify(stable(content))).digest("hex");
}

function verifiedDirectory(value, expectedIdentity, expectedMode, label) {
  const requested = String(value || "");
  if (!path.isAbsolute(requested)) throw new Error(`Hosted workload ${label} path is invalid.`);
  const stat = lstatSync(requested, { bigint: true, throwIfNoEntry: false });
  if (!stat?.isDirectory() || stat.isSymbolicLink() || Number(stat.mode & 0o777n) !== expectedMode) {
    throw new Error(`Hosted workload ${label} is not immutable.`);
  }
  const physical = realpathSync.native(requested);
  if (!sameIdentity(stat, expectedIdentity)) throw new Error(`Hosted workload ${label} identity changed.`);
  return physical;
}

function verifySnapshotRecord(record, generation, generationIdentity) {
  const recordPath = String(record.path || "");
  if (!path.isAbsolute(recordPath)) {
    throw new Error("Hosted workload snapshot record leaves its generation.");
  }
  const stat = lstatSync(recordPath, { bigint: true, throwIfNoEntry: false });
  const physicalPath = stat?.isFile() && !stat.isSymbolicLink() ? realpathSync.native(recordPath) : "";
  if (!physicalPath || path.dirname(physicalPath) !== generation) {
    throw new Error("Hosted workload snapshot record leaves its generation.");
  }
  if (!stat?.isFile() || stat.isSymbolicLink() || Number(stat.mode & 0o777n) !== 0o400
    || !sameIdentity(stat, {
      device: record.snapshotDevice,
      inode: record.snapshotInode,
      uid: record.snapshotUid,
      mode: 0o400,
    })
    || String(record.snapshotUid) !== String(generationIdentity?.uid)
    || Number(stat.size) !== Number(record.sizeBytes)) {
    throw new Error("Hosted workload snapshot record identity changed.");
  }
}

function sameIdentity(stat, expected) {
  return String(stat.dev) === String(expected?.device)
    && String(stat.ino) === String(expected?.inode)
    && String(stat.uid) === String(expected?.uid)
    && Number(stat.mode & 0o777n) === Number(expected?.mode);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
}
