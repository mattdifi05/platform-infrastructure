const SHA256 = /^[a-f0-9]{64}$/;
const SOURCE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$/;

export function backupImportConfirmation({ sha256, sourceSystem, sourceId }) {
  return `IMPORT:${sha256}:${sourceSystem}:${sourceId}`;
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

