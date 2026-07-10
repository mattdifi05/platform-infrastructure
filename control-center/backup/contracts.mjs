import { createHash } from "node:crypto";

export const BACKUP_JOB_SCHEMA = "platform.backup-job/v1";
export const BACKUP_MANIFEST_SCHEMA = "platform.backup-manifest/v1";

const resourceKinds = new Set(["source", "database", "storage", "platform-state"]);
const databaseEngines = new Set(["postgres", "mariadb"]);
const operations = new Set(["backup", "restore-drill"]);

function requiredText(value, label, pattern, maxLength = 160) {
  const clean = String(value ?? "").trim();
  if (!clean || clean.length > maxLength || (pattern && !pattern.test(clean))) {
    throw new Error(`Invalid ${label}.`);
  }
  return clean;
}

function identifier(value, label = "identifier") {
  return requiredText(value, label, /^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/);
}

function projectIdentifier(value) {
  return requiredText(value, "projectId", /^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/, 80);
}

function resourceName(value) {
  return requiredText(value, "resource name", /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/, 128);
}

function relativeBackupPath(value, label = "backup path") {
  const clean = String(value ?? "").trim().replaceAll("\\", "/").replace(/^\/+/, "");
  if (!clean || clean.length > 512 || clean.includes("\0") || clean.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error(`Invalid ${label}.`);
  }
  return clean;
}

export function backupResourceId(kind, id) {
  const normalizedKind = requiredText(kind, "resource kind", /^[a-z-]+$/, 32);
  if (!resourceKinds.has(normalizedKind)) throw new Error("Unsupported backup resource kind.");
  return `${normalizedKind}:${identifier(id, "resource identity")}`;
}

export function normalizeBackupResource(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const kind = requiredText(source.kind, "resource kind", /^[a-z-]+$/, 32);
  if (!resourceKinds.has(kind)) throw new Error("Unsupported backup resource kind.");
  const projectId = kind === "platform-state" ? "platform" : projectIdentifier(source.projectId);
  const externalId = identifier(source.externalId ?? source.id?.split(":").slice(1).join(":"), "resource identity");
  const id = backupResourceId(kind, externalId);
  if (source.id && source.id !== id) throw new Error("Backup resource ID does not match its kind and external identity.");
  const resource = {
    id,
    externalId,
    kind,
    projectId,
    name: resourceName(source.name),
  };
  if (kind === "database") {
    const engine = requiredText(source.engine, "database engine", /^[a-z]+$/, 16);
    if (!databaseEngines.has(engine)) throw new Error("Unsupported database engine.");
    resource.engine = engine;
  }
  if (kind === "source") {
    resource.sourceDirectory = resourceName(source.sourceDirectory ?? source.name);
  }
  return Object.freeze(resource);
}

export function normalizeBackupResources(resources) {
  if (!Array.isArray(resources) || resources.length === 0 || resources.length > 256) {
    throw new Error("Backup resources must be a non-empty bounded array.");
  }
  const normalized = resources.map(normalizeBackupResource);
  const ids = new Set();
  for (const resource of normalized) {
    if (ids.has(resource.id)) throw new Error(`Duplicate backup resource ID: ${resource.id}`);
    ids.add(resource.id);
  }
  return normalized;
}

function normalizeScope(scope) {
  const source = scope && typeof scope === "object" && !Array.isArray(scope) ? scope : {};
  const kind = requiredText(source.kind, "scope kind", /^(application|platform)$/, 16);
  return {
    kind,
    id: kind === "application" ? projectIdentifier(source.id) : "platform",
  };
}

export function createBackupJobDocument({
  id,
  operation,
  scope,
  resources,
  requestedBy,
  environment,
  createdAt = new Date().toISOString(),
  sourceManifestPath = "",
}) {
  const normalizedOperation = requiredText(operation, "backup operation", /^[a-z-]+$/, 32);
  if (!operations.has(normalizedOperation)) throw new Error("Unsupported backup operation.");
  const normalizedResources = normalizeBackupResources(resources);
  const normalizedScope = normalizeScope(scope);
  if (normalizedScope.kind === "application" && normalizedResources.some((resource) => resource.projectId !== normalizedScope.id)) {
    throw new Error("Application job contains a resource owned by another project.");
  }
  const document = {
    schema: BACKUP_JOB_SCHEMA,
    id: identifier(id, "job id"),
    operation: normalizedOperation,
    scope: normalizedScope,
    resources: normalizedResources,
    requestedBy: requiredText(requestedBy || "control-center", "requester", /^[A-Za-z0-9@._:+/-]+$/, 200),
    environment: requiredText(environment || "local", "environment", /^[a-z0-9-]+$/, 32),
    status: "queued",
    createdAt: new Date(createdAt).toISOString(),
    updatedAt: new Date(createdAt).toISOString(),
    startedAt: null,
    finishedAt: null,
    resultSummary: "Queued for typed backup executor.",
    reportPaths: [],
  };
  if (normalizedOperation === "restore-drill") {
    document.sourceManifestPath = relativeBackupPath(sourceManifestPath, "source manifest path");
    if (!document.sourceManifestPath.startsWith("manifests/")) throw new Error("Restore source manifest must be under manifests/.");
  }
  return document;
}

export function parseBackupJobDocument(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  if (source.schema !== BACKUP_JOB_SCHEMA) throw new Error("Unsupported backup job schema.");
  const document = createBackupJobDocument(source);
  const allowedStatuses = new Set(["queued", "running", "done", "failed"]);
  if (!allowedStatuses.has(source.status)) throw new Error("Invalid backup job status.");
  return {
    ...document,
    status: source.status,
    updatedAt: new Date(source.updatedAt || source.createdAt).toISOString(),
    startedAt: source.startedAt ? new Date(source.startedAt).toISOString() : null,
    finishedAt: source.finishedAt ? new Date(source.finishedAt).toISOString() : null,
    resultSummary: String(source.resultSummary || document.resultSummary).slice(0, 500),
    reportPaths: Array.isArray(source.reportPaths) ? source.reportPaths.map((item) => relativeBackupPath(item, "report path")).slice(0, 32) : [],
    manifestPath: source.manifestPath ? relativeBackupPath(source.manifestPath, "manifest path") : undefined,
  };
}

function normalizeArtifact(input, resourceIds) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const resourceId = identifier(source.resourceId, "artifact resource ID");
  if (!resourceIds.has(resourceId)) throw new Error(`Artifact references undeclared resource: ${resourceId}`);
  const sha256 = requiredText(source.sha256, "artifact sha256", /^[a-f0-9]{64}$/, 64);
  const sizeBytes = Number(source.sizeBytes);
  if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 1) throw new Error("Invalid artifact size.");
  return {
    id: identifier(source.id, "artifact id"),
    resourceId,
    path: relativeBackupPath(source.path, "artifact path"),
    sha256,
    sizeBytes,
    signatureKeyId: identifier(source.signatureKeyId, "artifact signature key ID"),
  };
}

export function createBackupManifestDocument({ id, job, artifacts, createdAt = new Date().toISOString() }) {
  const normalizedJob = parseBackupJobDocument(job);
  if (normalizedJob.operation !== "backup") throw new Error("Only backup jobs can produce backup manifests.");
  const resourceIds = new Set(normalizedJob.resources.map((resource) => resource.id));
  const normalizedArtifacts = Array.isArray(artifacts) ? artifacts.map((artifact) => normalizeArtifact(artifact, resourceIds)) : [];
  const artifactResourceIds = new Set(normalizedArtifacts.map((artifact) => artifact.resourceId));
  const missingResourceIds = [...resourceIds].filter((resourceId) => !artifactResourceIds.has(resourceId));
  if (normalizedArtifacts.length !== artifactResourceIds.size) throw new Error("Every resource must map to exactly one artifact.");
  return {
    schema: BACKUP_MANIFEST_SCHEMA,
    id: identifier(id, "manifest id"),
    jobId: normalizedJob.id,
    operation: "backup",
    scope: normalizedJob.scope,
    resources: normalizedJob.resources,
    artifacts: normalizedArtifacts,
    coverage: {
      requiredResourceIds: [...resourceIds].sort(),
      artifactResourceIds: [...artifactResourceIds].sort(),
      missingResourceIds,
      complete: missingResourceIds.length === 0,
    },
    createdAt: new Date(createdAt).toISOString(),
  };
}

export function parseBackupManifestDocument(input, { requireComplete = true } = {}) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  if (source.schema !== BACKUP_MANIFEST_SCHEMA) throw new Error("Unsupported backup manifest schema.");
  const job = createBackupJobDocument({
    id: source.jobId,
    operation: "backup",
    scope: source.scope,
    resources: source.resources,
    requestedBy: "manifest-import",
    environment: "evidence",
    createdAt: source.createdAt,
  });
  const manifest = createBackupManifestDocument({ id: source.id, job, artifacts: source.artifacts, createdAt: source.createdAt });
  if (requireComplete && !manifest.coverage.complete) throw new Error("Backup manifest coverage is incomplete.");
  const signature = source.signature && typeof source.signature === "object" ? {
    algorithm: requiredText(source.signature.algorithm, "manifest signature algorithm", /^HMAC-SHA256$/, 32),
    keyId: identifier(source.signature.keyId, "manifest signature key ID"),
    digest: requiredText(source.signature.digest, "manifest digest", /^[a-f0-9]{64}$/, 64),
    value: requiredText(source.signature.value, "manifest signature", /^[A-Za-z0-9_-]+$/, 256),
  } : null;
  return { ...manifest, signature };
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).filter((key) => key !== "signature").sort().map((key) => [key, canonicalValue(value[key]) ]));
  }
  return value;
}

export function canonicalBackupDocument(document) {
  return JSON.stringify(canonicalValue(document));
}

export function backupDocumentDigest(document) {
  return createHash("sha256").update(canonicalBackupDocument(document)).digest("hex");
}

export function manifestResourcesForProject(manifestInput, projectId) {
  const manifest = parseBackupManifestDocument(manifestInput);
  const cleanProjectId = projectIdentifier(projectId);
  return manifest.resources.filter((resource) => resource.projectId === cleanProjectId);
}

export function manifestArtifactForResource(manifestInput, resourceId) {
  const manifest = parseBackupManifestDocument(manifestInput);
  const cleanResourceId = identifier(resourceId, "resource ID");
  return manifest.artifacts.find((artifact) => artifact.resourceId === cleanResourceId) || null;
}
