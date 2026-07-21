import crypto from "node:crypto";
import fs from "node:fs";

const SHA256 = /^[a-f0-9]{64}$/;
const SOURCE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$/;
const MAX_PROVENANCE_BYTES = 1024 * 1024;

export function backupImportConfirmation({ sha256, sourceSystem, sourceId }) {
  return `IMPORT:${sha256}:${sourceSystem}:${sourceId}`;
}

export function readBackupImportProvenance({ filePath, maxBytes = MAX_PROVENANCE_BYTES, onBytesCaptured } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_PROVENANCE_BYTES) {
    throw new Error("Backup import provenance size bound is invalid.");
  }
  let fd = null;
  try {
    const before = fs.lstatSync(filePath, { throwIfNoEntry: false });
    if (!before?.isFile() || before.isSymbolicLink() || before.size <= 0 || before.size > maxBytes) {
      throw new Error("Backup import provenance must be a bounded regular non-symlink file.");
    }
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error("Backup import provenance changed before capture.");
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) throw new Error("Backup import provenance was truncated during capture.");
      offset += count;
    }
    const finished = fs.fstatSync(fd);
    if (finished.dev !== opened.dev || finished.ino !== opened.ino || finished.size !== opened.size || finished.mtimeMs !== opened.mtimeMs) {
      throw new Error("Backup import provenance changed during capture.");
    }
    if (typeof onBytesCaptured === "function") onBytesCaptured();
    let provenance;
    try {
      provenance = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new Error("Backup import provenance JSON is invalid.");
    }
    return {
      provenance,
      provenanceSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      provenanceSizeBytes: bytes.length,
    };
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

export function validateBackupImportProvenance({
  artifactName,
  artifactSha256,
  artifactSizeBytes,
  provenance,
  provenanceSha256,
  pinnedProvenanceSha256,
  expectedSourceSystem,
  expectedSourceId,
  confirmation,
  now = Date.now(),
}) {
  if (!SHA256.test(String(artifactSha256 ?? ""))) throw new Error("Backup import artifact SHA-256 is invalid.");
  if (!Number.isSafeInteger(artifactSizeBytes) || artifactSizeBytes <= 0) throw new Error("Backup import artifact size is invalid.");
  if (!SHA256.test(String(pinnedProvenanceSha256 ?? "")) || provenanceSha256 !== pinnedProvenanceSha256) {
    throw new Error("Backup import provenance does not match the owner-pinned digest.");
  }
  if (provenance?.schema !== "platform.backup-import-provenance/v1") throw new Error("Backup import provenance schema is invalid.");
  if (provenance.artifact?.fileName !== artifactName) throw new Error("Backup import provenance artifact name mismatch.");
  if (provenance.artifact?.sha256 !== artifactSha256) throw new Error("Backup import provenance artifact digest mismatch.");
  if (provenance.artifact?.sizeBytes !== artifactSizeBytes) throw new Error("Backup import provenance artifact size mismatch.");
  const sourceSystem = String(provenance.source?.system ?? "");
  const sourceId = String(provenance.source?.resourceId ?? "");
  if (!SOURCE.test(sourceSystem) || !SOURCE.test(sourceId)) throw new Error("Backup import provenance source identity is invalid.");
  if (sourceSystem !== expectedSourceSystem || sourceId !== expectedSourceId) throw new Error("Backup import provenance source identity mismatch.");
  const createdAt = Date.parse(provenance.createdAt);
  if (!Number.isFinite(createdAt) || createdAt > now + 5 * 60 * 1000) throw new Error("Backup import provenance timestamp is invalid or in the future.");
  const expectedConfirmation = backupImportConfirmation({ sha256: artifactSha256, sourceSystem, sourceId });
  if (confirmation !== expectedConfirmation) throw new Error(`Backup import requires exact confirmation: ${expectedConfirmation}`);
  return { sourceSystem, sourceId, createdAt: new Date(createdAt).toISOString(), provenanceSha256 };
}
