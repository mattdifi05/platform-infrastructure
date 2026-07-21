import { parseBackupManifestDocument } from "../control-center/backup/contracts.mjs";

export const manifestIdTagPrefix = "platform-manifest-id=";
export const manifestDigestTagPrefix = "platform-manifest-digest=";

function normalizedSnapshotPaths(values, label) {
  if (!Array.isArray(values) || values.length === 0) throw new Error(`${label} must be a non-empty array.`);
  const normalized = values.map((value) => {
    const raw = String(value ?? "").replaceAll("\\", "/");
    const absolute = `/${raw.replace(/^\/+/, "")}`;
    if (!absolute.startsWith("/backups/") || absolute.split("/").some((part) => part === "..")) {
      throw new Error(`${label} contains an unsafe or foreign path: ${raw}`);
    }
    return absolute;
  });
  if (new Set(normalized).size !== normalized.length) throw new Error(`${label} contains duplicate paths.`);
  return normalized.sort();
}

function oneTag(tags, prefix, label) {
  const matches = (tags ?? []).filter((tag) => String(tag).startsWith(prefix)).map((tag) => String(tag).slice(prefix.length));
  if (matches.length !== 1 || !matches[0]) throw new Error(`Restic snapshot must contain exactly one ${label} tag.`);
  return matches[0];
}

export function offsiteManifestTags(manifestInput) {
  const manifest = parseBackupManifestDocument(manifestInput);
  if (!manifest.signature) throw new Error("Off-site backup manifest must be signed.");
  return [`${manifestIdTagPrefix}${manifest.id}`, `${manifestDigestTagPrefix}${manifest.signature.digest}`];
}

export function locateSnapshotManifest({ snapshotPaths, snapshotTags }) {
  const normalizedSnapshotPaths = normalizedSnapshotPathsInternal(snapshotPaths);
  const manifestPaths = normalizedSnapshotPaths.filter((entry) => entry.startsWith("/backups/manifests/") && entry.endsWith(".json"));
  if (manifestPaths.length !== 1) throw new Error("Restic snapshot must contain exactly one backup manifest path.");
  const manifestId = oneTag(snapshotTags, manifestIdTagPrefix, "manifest identity");
  const manifestDigest = oneTag(snapshotTags, manifestDigestTagPrefix, "manifest digest");
  if (!/^[a-f0-9]{64}$/.test(manifestDigest)) throw new Error("Restic snapshot manifest digest tag is invalid.");
  return { manifestPath: manifestPaths[0], manifestId, manifestDigest, snapshotPaths: normalizedSnapshotPaths };
}

function normalizedSnapshotPathsInternal(paths) {
  return normalizedSnapshotPaths(paths, "Restic snapshot paths");
}

export function validateOffsiteRestoreSet({ manifest: manifestInput, snapshotPaths, restoredPaths, snapshotTags }) {
  const manifest = parseBackupManifestDocument(manifestInput);
  if (!manifest.signature) throw new Error("Off-site restore manifest is unsigned.");
  const located = locateSnapshotManifest({ snapshotPaths, snapshotTags });
  const normalizedSnapshot = located.snapshotPaths;
  const normalizedRestored = normalizedSnapshotPaths(restoredPaths, "Restored file paths");
  if (located.manifestId !== manifest.id || located.manifestDigest !== manifest.signature.digest) throw new Error("Restic snapshot manifest tags do not match the signed manifest.");
  const expected = [located.manifestPath];
  for (const artifact of manifest.artifacts) {
    const artifactPath = `/backups/${artifact.path}`;
    expected.push(artifactPath, `${artifactPath}.sha256`, `${artifactPath}.sig.json`);
  }
  const expectedPaths = [...new Set(expected)].sort();
  if (expectedPaths.length !== expected.length) throw new Error("Signed manifest resolves to duplicate restore paths.");
  const compare = (actual, label) => {
    const missing = expectedPaths.filter((entry) => !actual.includes(entry));
    const extra = actual.filter((entry) => !expectedPaths.includes(entry));
    if (missing.length || extra.length) throw new Error(`${label} is not the exact signed manifest set; missing=${missing.join(",") || "none"} extra=${extra.join(",") || "none"}.`);
  };
  compare(normalizedSnapshot, "Restic snapshot");
  compare(normalizedRestored, "Restored files");
  return {
    manifest,
    manifestPath: located.manifestPath,
    expectedPaths,
    resourceIds: manifest.resources.map((resource) => resource.id),
  };
}

export function evaluateOffsiteRestoreCoverage(payload = {}) {
  const requiredResourceIds = Array.isArray(payload.manifest?.resourceIds) ? payload.manifest.resourceIds : [];
  const successfulResourceIds = [...new Set((payload.steps ?? [])
    .filter((step) => step.resourceId && step.status === "success")
    .map((step) => step.resourceId))];
  const missingRequiredResourceIds = requiredResourceIds.filter((resourceId) => !successfulResourceIds.includes(resourceId));
  const infraHealthOk = (payload.steps ?? []).some((step) => step.name === "infra-health" && step.status === "success");
  const complete = payload.mode === "restore"
    && payload.status === "success"
    && payload.allowPartial !== true
    && payload.manifest?.signatureVerified === true
    && payload.exactSetVerified === true
    && requiredResourceIds.length > 0
    && missingRequiredResourceIds.length === 0
    && infraHealthOk;
  return {
    requiredResourceIds,
    successfulResourceIds,
    missingRequiredResourceIds,
    allowPartial: payload.allowPartial === true,
    manifestSignatureVerified: payload.manifest?.signatureVerified === true,
    exactSetVerified: payload.exactSetVerified === true,
    infraHealthOk,
    complete,
  };
}
