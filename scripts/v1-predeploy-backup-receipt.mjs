import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import {
  sha256Canonical,
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";

export const REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE =
  "REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(root, "vendor", "json-schema", "package.json"));
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");
const schema = JSON.parse(fs.readFileSync(
  path.join(root, "governance", "schemas", "v1-predeploy-backup-receipt.schema.json"),
  "utf8",
));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateSchema = ajv.compile(schema);
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_OBJECT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const MAX_INPUT_BYTES = 32 * 1024 * 1024;
const PHASES = Object.freeze(["CODE", "CONFIG", "STORAGE", "DATABASE", "SECRETS", "VERIFY"]);
const IMMUTABLE_ARTIFACT_MODES = new Set(["0400", "0440", "0444"]);
const MIN_SEMANTIC_ARTIFACT_BYTES = 128;
const EXTERNAL_ADMISSION_REFERENCE = /^external-admission-policy:\/\/[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:([a-f0-9]{64})$/;
const EXTERNAL_RECOVERY_REFERENCE = /^external-recovery-policy:\/\/[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:([a-f0-9]{64})$/;
const PROVIDER_IDENTITY_REFERENCE = /^provider-identity:\/\/[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:([a-f0-9]{64})$/;
const VERSIONED_PROVIDER_LOCATOR = /^provider-(config|secret):\/\/[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:([a-f0-9]{64})$/;
const PLACEHOLDER_REFERENCE = /(?:^|[._/-])(?:example|invalid|nonexistent|placeholder|unknown|pending)(?:[._/@-]|$)/i;
const DATABASE_CAPTURE = Object.freeze({
  POSTGRESQL: Object.freeze({ disposition: "LOGICAL-DUMP", format: "POSTGRESQL-CUSTOM", tool: "pg_dump", method: "ISOLATED-LOGICAL-RESTORE" }),
  MARIADB: Object.freeze({ disposition: "LOGICAL-DUMP", format: "MARIADB-SQL", tool: "mariadb-dump", method: "ISOLATED-LOGICAL-RESTORE" }),
  REDIS: Object.freeze({ disposition: "ENGINE-SNAPSHOT", format: "REDIS-RDB", tool: "redis-check-rdb", method: "ISOLATED-SNAPSHOT-RESTORE" }),
});
const ENGINE_GLOBAL_CAPTURE = Object.freeze({
  POSTGRESQL: Object.freeze({ format: "POSTGRESQL-GLOBAL-SQL", tool: "pg_dumpall" }),
  MARIADB: Object.freeze({ format: "MARIADB-SYSTEM-SQL", tool: "mariadb-dump" }),
  REDIS: Object.freeze({ format: "REDIS-RDB", tool: "redis-check-rdb" }),
});

export const PERSISTENT_SOURCE_CLASSES = Object.freeze([
  "DOCKER-ROOT-DIR",
  "ALL-CHECKOUTS",
  "ALL-COMPOSE-CONFIG-FILES",
  "ALL-VOLUME-AND-DATABASE-DIRECTORIES",
  "BIND-LSTAT-SOURCE-IDENTITIES",
  "BIND-CANONICAL-TARGET-IDENTITIES",
  "ALL-SOURCE-ROOTS",
  "ALL-SECRET-METADATA-PATHS",
]);

function fail(message) {
  throw new Error(message);
}

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object.`);
  }
  return value;
}

function array(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array.`);
  return value;
}

function indexUnique(items, key, label) {
  const result = new Map();
  for (const item of items) {
    const id = item?.[key];
    if (result.has(id)) fail(`${label} contains duplicate ${key} ${String(id)}.`);
    result.set(id, item);
  }
  return result;
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function assertExactSet(actual, expected, label) {
  const actualSorted = sorted(actual);
  const expectedSorted = sorted(expected);
  if (
    actualSorted.length !== expectedSorted.length
    || actualSorted.some((value, index) => value !== expectedSorted[index])
  ) {
    fail(`${label} must exactly cover the deny-only baseline.`);
  }
}

function assertCanonicalAbsolute(input, label) {
  if (
    typeof input !== "string"
    || !path.posix.isAbsolute(input)
    || path.posix.normalize(input) !== input
    || (input.length > 1 && input.endsWith("/"))
  ) {
    fail(`${label} must be an exact canonical absolute path.`);
  }
}

function isStrictDescendant(parentPath, candidatePath) {
  const relative = path.posix.relative(parentPath, candidatePath);
  return relative !== ""
    && relative !== ".."
    && !relative.startsWith("../")
    && !path.posix.isAbsolute(relative);
}

function assertTimestamp(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) fail(`${label} must be a valid UTC timestamp.`);
  return milliseconds;
}

function canonicalDevice(identity, label) {
  if (!identity || !/^(?:0|[1-9][0-9]*)$/.test(String(identity.device ?? ""))) {
    fail(`${label} must have an exact, unambiguous filesystem device identity.`);
  }
  return identity.device;
}

function validateEvidenceTime(value, label, freshness) {
  const milliseconds = assertTimestamp(value, label);
  if (
    milliseconds < freshness.notBefore
    || milliseconds > freshness.generatedAt
    || freshness.current - milliseconds > freshness.maxAgeMilliseconds
  ) {
    fail(`${label} is outside the receipt evidence window or maxAgeSeconds.`);
  }
  return milliseconds;
}

function validateFreshness(receipt) {
  const generatedAt = assertTimestamp(receipt.generatedAt, "generatedAt");
  const notBefore = assertTimestamp(receipt.freshness.notBefore, "freshness.notBefore");
  const expiresAt = assertTimestamp(receipt.freshness.expiresAt, "freshness.expiresAt");
  const current = Date.now();
  const maxAgeMilliseconds = receipt.freshness.maxAgeSeconds * 1000;

  if (notBefore > generatedAt || generatedAt > expiresAt) {
    fail("Receipt generatedAt must fall inside its freshness window.");
  }
  if (current < notBefore || current > expiresAt || current < generatedAt) {
    fail("Receipt is outside its freshness window.");
  }
  if (
    generatedAt - notBefore > maxAgeMilliseconds
    || current - notBefore > maxAgeMilliseconds
    || current - generatedAt > maxAgeMilliseconds
    || expiresAt - generatedAt > maxAgeMilliseconds
  ) {
    fail("Receipt freshness exceeds maxAgeSeconds.");
  }
  return { generatedAt, notBefore, expiresAt, current, maxAgeMilliseconds };
}

function sameFilesystemIdentity(left, right) {
  return ["type", "device", "inode", "uid", "gid", "mode", "nlink"]
    .every((field) => left?.[field] === right?.[field]);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function derivePersistentSourceSetFromValidatedBaseline(baseline) {
  const sources = [];
  const devices = new Set();
  const pathIdentities = new Map();
  const exactEntries = new Set();
  const observe = (sourceClass, sourcePath, identity, label) => {
    if (!PERSISTENT_SOURCE_CLASSES.includes(sourceClass)) {
      fail(`${label} uses an unclassified persistent-source observation.`);
    }
    assertCanonicalAbsolute(sourcePath, `${label} path`);
    const device = canonicalDevice(identity, label);
    const previous = pathIdentities.get(sourcePath);
    if (previous && !sameFilesystemIdentity(previous.identity, identity)) {
      fail(`Persistent source ${sourcePath} has ambiguous filesystem identities in the complete baseline.`);
    }
    pathIdentities.set(sourcePath, { identity, label });
    devices.add(device);
    const entry = { sourceClass, path: sourcePath, identity: structuredClone(identity) };
    const key = sha256Canonical(entry);
    if (!exactEntries.has(key)) {
      exactEntries.add(key);
      sources.push(entry);
    }
  };

  observe(
    "DOCKER-ROOT-DIR",
    baseline.host.dockerRootDir,
    baseline.host.dockerRootIdentity,
    "baseline.host.dockerRootIdentity",
  );
  baseline.checkouts.forEach((checkout, index) => observe(
    "ALL-CHECKOUTS",
    checkout.path,
    checkout.fsIdentity,
    `baseline.checkouts[${index}].fsIdentity`,
  ));
  baseline.composeProjects.forEach((project, projectIndex) => {
    project.configFiles.forEach((config, configIndex) => observe(
      "ALL-COMPOSE-CONFIG-FILES",
      config.path,
      config.fsIdentity,
      `baseline.composeProjects[${projectIndex}].configFiles[${configIndex}].fsIdentity`,
    ));
  });
  baseline.volumes.forEach((volume, index) => observe(
    "ALL-VOLUME-AND-DATABASE-DIRECTORIES",
    volume.mountpoint,
    volume.fsIdentity,
    `baseline.volumes[${index}].fsIdentity`,
  ));
  baseline.bindMounts.forEach((binding, index) => {
    observe(
      "BIND-LSTAT-SOURCE-IDENTITIES",
      binding.source,
      binding.lstatIdentity,
      `baseline.bindMounts[${index}].lstatIdentity`,
    );
    observe(
      "BIND-CANONICAL-TARGET-IDENTITIES",
      binding.canonicalPath,
      binding.targetIdentity,
      `baseline.bindMounts[${index}].targetIdentity`,
    );
  });
  baseline.sourceRoots.forEach((sourceRoot, index) => observe(
    "ALL-SOURCE-ROOTS",
    sourceRoot.path,
    sourceRoot.fsIdentity,
    `baseline.sourceRoots[${index}].fsIdentity`,
  ));
  baseline.secretMetadata.forEach((secret, index) => observe(
    "ALL-SECRET-METADATA-PATHS",
    secret.path,
    secret.fsIdentity,
    `baseline.secretMetadata[${index}].fsIdentity`,
  ));

  sources.sort((left, right) => {
    const leftKey = `${left.sourceClass}\0${left.path}\0${sha256Canonical(left.identity)}`;
    const rightKey = `${right.sourceClass}\0${right.path}\0${sha256Canonical(right.identity)}`;
    return leftKey === rightKey ? 0 : leftKey < rightKey ? -1 : 1;
  });
  const sourceDeviceIdentities = [...devices].sort();
  const sourcePaths = [...pathIdentities.entries()]
    .map(([sourcePath, observation]) => ({ path: sourcePath, identity: structuredClone(observation.identity) }))
    .sort((left, right) => (left.path === right.path ? 0 : left.path < right.path ? -1 : 1));
  return deepFreeze({
    schema: "platform.v1-persistent-source-set/v1",
    sourceClasses: [...PERSISTENT_SOURCE_CLASSES],
    sourceDeviceIdentities,
    sourceDeviceCount: sourceDeviceIdentities.length,
    sourceDeviceIdentitiesComplete: true,
    sourceDeviceSetSha256: sha256Canonical(sourceDeviceIdentities),
    sources,
    sourceObservationCount: sources.length,
    sourceObservationSetSha256: sha256Canonical(sources),
    sourcePaths,
    sourcePathCount: sourcePaths.length,
    sourcePathSetSha256: sha256Canonical(sourcePaths),
  });
}

export function derivePersistentSourceSet(baseline) {
  try {
    baseline = structuredClone(baseline);
  } catch (error) {
    fail(`Persistent-source baseline cannot be snapshotted: ${error instanceof Error ? error.message : String(error)}`);
  }
  record(baseline, "baseline");
  try {
    validateLivePreservationBaseline(baseline, { requireComplete: true });
  } catch (error) {
    fail(`Canonical deny-only baseline rejected: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (baseline.complete !== true || baseline.status !== "COMPLETE-PRESERVATION-BASELINE"
      || baseline.gateAdmissible !== false || baseline.mutationAuthority !== false
      || baseline.effect !== "DENY-ONLY" || baseline.deficiencies.length !== 0) {
    fail("Persistent sources require one complete deny-only baseline with no mutation authority.");
  }
  return derivePersistentSourceSetFromValidatedBaseline(baseline);
}

function validateDenyOnlyBaseline(baseline, baselineSha256, receiptBinding, targetBinding) {
  try {
    baseline = structuredClone(baseline);
  } catch (error) {
    fail(`Canonical deny-only baseline cannot be snapshotted: ${error instanceof Error ? error.message : String(error)}`);
  }
  record(baseline, "baseline");
  try {
    validateLivePreservationBaseline(baseline, { requireComplete: true });
  } catch (error) {
    fail(`Canonical deny-only baseline rejected: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (
    baseline.schema !== "platform.live-preservation-baseline/v1"
    || baseline.scope !== "platform-infrastructure"
    || baseline.complete !== true
    || baseline.status !== "COMPLETE-PRESERVATION-BASELINE"
    || baseline.gateAdmissible !== false
    || baseline.mutationAuthority !== false
    || baseline.effect !== "DENY-ONLY"
    || !Array.isArray(baseline.deficiencies)
    || baseline.deficiencies.length !== 0
  ) {
    fail("A complete deny-only baseline with no mutation authority is required.");
  }
  if (!SHA256.test(String(baselineSha256 ?? "")) || receiptBinding.artifactSha256 !== baselineSha256) {
    fail("Receipt baseline digest does not match the captured deny-only baseline artifact.");
  }
  if (
    receiptBinding.schema !== baseline.schema
    || receiptBinding.baselineId !== baseline.baselineId
    || receiptBinding.complete !== baseline.complete
    || receiptBinding.effect !== baseline.effect
  ) {
    fail("Receipt baseline identity does not match the deny-only baseline.");
  }

  const anchors = array(baseline.logicalRecoveryAnchors, "baseline.logicalRecoveryAnchors");
  const databases = array(baseline.databases, "baseline.databases");
  const volumes = array(baseline.volumes, "baseline.volumes");
  const bindMounts = array(baseline.bindMounts, "baseline.bindMounts");
  const sourceRoots = array(baseline.sourceRoots, "baseline.sourceRoots");
  const secretMetadata = array(baseline.secretMetadata, "baseline.secretMetadata");
  const checkouts = array(baseline.checkouts, "baseline.checkouts");
  if (anchors.length === 0) fail("The deny-only baseline has no application coverage.");

  const activeCheckouts = checkouts.filter((checkout) => checkout?.role === "ACTIVE-LIVE");
  if (
    activeCheckouts.length !== 1
    || activeCheckouts[0].path !== targetBinding.root
    || !sameFilesystemIdentity(activeCheckouts[0].fsIdentity, targetBinding.identity)
  ) {
    fail("Receipt target root and immutable identity must exactly match the baseline ACTIVE-LIVE checkout.");
  }

  const anchorIndex = indexUnique(anchors, "id", "Baseline applications");
  const containerIndex = indexUnique(array(baseline.containers, "baseline.containers"), "name", "Baseline containers");
  const databaseIndex = indexUnique(databases, "id", "Baseline databases");
  const volumeIndex = indexUnique(volumes, "name", "Baseline volumes");
  const sourceRootIndex = indexUnique(sourceRoots, "path", "Baseline source roots");
  const secretIndex = indexUnique(secretMetadata, "id", "Baseline secret metadata");
  const bindIndex = new Map();
  for (const binding of bindMounts) {
    const source = binding.source;
    if (!source || bindIndex.has(source)) fail(`Baseline bind storage contains duplicate source ${String(source)}.`);
    bindIndex.set(source, binding);
  }

  const persistentSourceSet = derivePersistentSourceSetFromValidatedBaseline(baseline);
  const persistentSourceDevices = new Set(persistentSourceSet.sourceDeviceIdentities);

  const mappedDatabaseIds = new Set();
  const mappedSecretIds = new Set();
  const mappedConfigPaths = new Set();
  for (const anchor of anchors) {
    for (const field of [
      "sourceRootRefs", "sourceBindRefs", "containerRefs", "databaseRefs", "storageRefs", "configRefs", "secretMetadataRefs",
    ]) {
      if (!Array.isArray(anchor[field])) fail(`Baseline application ${anchor.id} has invalid ${field} coverage.`);
      if (new Set(anchor[field]).size !== anchor[field].length) {
        fail(`Baseline application ${anchor.id} has duplicate ${field}.`);
      }
    }
    anchor.databaseRefs.forEach((id) => mappedDatabaseIds.add(id));
    anchor.secretMetadataRefs.forEach((id) => mappedSecretIds.add(id));
    anchor.configRefs.forEach((configPath) => mappedConfigPaths.add(configPath));
  }

  assertExactSet(mappedDatabaseIds, databaseIndex.keys(), "Baseline application database mapping");
  assertExactSet(mappedSecretIds, secretIndex.keys(), "Baseline application secret mapping");

  const persistentStorageIndex = new Map();
  for (const [name, volume] of volumeIndex) {
    persistentStorageIndex.set(name, {
      kind: volume.nameClass === "NAMED" ? "NAMED-VOLUME" : "ANONYMOUS-VOLUME",
      source: volume,
    });
  }
  for (const [source, binding] of bindIndex) {
    if (["APPLICATION-DATA", "SHARED-STORAGE"].includes(binding.classification)) {
      if (persistentStorageIndex.has(source)) fail(`Baseline storage identity ${source} is ambiguous.`);
      persistentStorageIndex.set(source, { kind: "BIND", source: binding });
    } else if (binding.classification === "UNKNOWN-PRESERVE") {
      fail(`Baseline bind ${source} is unknown and cannot be admitted for rebuild.`);
    } else if (binding.classification === "CONFIG" && !mappedConfigPaths.has(source)) {
      fail(`Baseline config bind ${source} is not mapped to an application recovery anchor.`);
    } else if (
      binding.classification === "SECRET-METADATA"
      && !secretMetadata.some((secret) => secret?.path === source)
    ) {
      fail(`Baseline secret-metadata bind ${source} has no value-free recovery identity.`);
    }
  }

  for (const anchor of anchors) {
    for (const storageId of anchor.storageRefs) {
      if (!persistentStorageIndex.has(storageId) && sourceRootIndex.has(storageId)) {
        persistentStorageIndex.set(storageId, { kind: "SOURCE-ROOT", source: sourceRootIndex.get(storageId) });
      }
    }
  }

  for (const anchor of anchors) {
    for (const databaseId of anchor.databaseRefs) {
      const database = databaseIndex.get(databaseId);
      if (!database) fail(`Baseline application ${anchor.id} references unmapped database ${databaseId}.`);
      for (const storageId of database.storageRefs) {
        if (!anchor.storageRefs.includes(storageId)) {
          fail(`Baseline application ${anchor.id} does not preserve database storage ${storageId}.`);
        }
      }
    }
    for (const storageId of anchor.storageRefs) {
      if (!persistentStorageIndex.has(storageId)) {
        fail(`Baseline application ${anchor.id} references unmapped persistent storage ${storageId}.`);
      }
    }
    for (const secretId of anchor.secretMetadataRefs) {
      const secret = secretIndex.get(secretId);
      if (!secret || secret.contentCaptured !== false || secret.valuesCaptured !== false) {
        fail(`Baseline application ${anchor.id} secret metadata ${secretId} is unsafe or unmapped.`);
      }
    }
  }

  const storageDatabaseRefs = new Map(
    [...persistentStorageIndex.keys()].map((storageId) => [storageId, new Set()]),
  );
  for (const database of databases) {
    for (const storageId of database.storageRefs) {
      if (storageDatabaseRefs.has(storageId)) storageDatabaseRefs.get(storageId).add(database.id);
    }
  }
  const storageApplicationRefs = new Map(
    [...persistentStorageIndex.keys()].map((storageId) => [storageId, new Set()]),
  );
  for (const anchor of anchors) {
    for (const storageId of anchor.storageRefs) {
      if (storageApplicationRefs.has(storageId)) storageApplicationRefs.get(storageId).add(anchor.id);
    }
  }

  return {
    anchorIndex,
    containerIndex,
    databaseIndex,
    persistentStorageIndex,
    persistentSourceSet,
    persistentSourceDevices,
    storageApplicationRefs,
    storageDatabaseRefs,
  };
}

function validateRootsAndArtifacts(receipt, baselineState, freshness) {
  const targetRoot = receipt.target.root;
  const backupRoot = receipt.backupRoot.path;
  assertCanonicalAbsolute(targetRoot, "target.root");
  assertCanonicalAbsolute(backupRoot, "backupRoot.path");
  if (
    targetRoot === backupRoot
    || isStrictDescendant(targetRoot, backupRoot)
    || isStrictDescendant(backupRoot, targetRoot)
  ) {
    fail("backupRoot must be outside and disjoint from the rebuild target.");
  }
  const backupDevice = canonicalDevice(receipt.backupRoot.identity, "backupRoot.identity");
  if (baselineState.persistentSourceDevices.has(backupDevice)) {
    fail("backupRoot device must differ from every persistent source device in the complete baseline.");
  }

  const artifactIndex = indexUnique(receipt.artifacts, "artifactId", "Artifacts");
  const paths = new Set();
  const identities = new Set();
  for (const artifact of receipt.artifacts) {
    assertCanonicalAbsolute(artifact.backupPath, `Artifact ${artifact.artifactId} backupPath`);
    if (!isStrictDescendant(backupRoot, artifact.backupPath)) {
      fail(`Artifact ${artifact.artifactId} must be inside backup root.`);
    }
    if (paths.has(artifact.backupPath)) fail(`Artifacts contain duplicate backupPath ${artifact.backupPath}.`);
    paths.add(artifact.backupPath);
    const identityKey = `${artifact.identity.device}:${artifact.identity.inode}`;
    if (identities.has(identityKey)) fail(`Artifacts contain duplicate immutable identity ${identityKey}.`);
    identities.add(identityKey);
    if (
      artifact.sizeBytes <= 0
      || artifact.identity.device !== receipt.backupRoot.identity.device
      || artifact.identity.type !== "regular-file"
      || artifact.identity.nlink !== 1
      || artifact.identityVerified !== true
      || !IMMUTABLE_ARTIFACT_MODES.has(artifact.identity.mode)
    ) {
      fail(`Artifact ${artifact.artifactId} lacks a verified immutable backup identity or non-zero size.`);
    }
    if (artifact.sourceRefsSha256 !== sha256Canonical(sorted(artifact.sourceRefs))) {
      fail(`Artifact ${artifact.artifactId} sourceRefsSha256 does not bind its exact original sources.`);
    }
    if (artifact.sizeBytes < MIN_SEMANTIC_ARTIFACT_BYTES) {
      fail(`Artifact ${artifact.artifactId} is below the minimum semantic size and remains opaque.`);
    }
    if (artifact.checksum.verified !== true || artifact.checksum.algorithm !== "SHA-256") {
      fail(`Artifact ${artifact.artifactId} checksum is not verified.`);
    }
    const capturedAt = validateEvidenceTime(artifact.capturedAt, `${artifact.artifactId} capturedAt`, freshness);
    const identityVerifiedAt = validateEvidenceTime(
      artifact.identityVerifiedAt,
      `${artifact.artifactId} identityVerifiedAt`,
      freshness,
    );
    const checksumAt = validateEvidenceTime(
      artifact.checksum.verifiedAt,
      `${artifact.artifactId} checksum verifiedAt`,
      freshness,
    );
    if (capturedAt > identityVerifiedAt || identityVerifiedAt > checksumAt) {
      fail(`Artifact ${artifact.artifactId} capture, immutable identity, and checksum evidence are not causal.`);
    }
    if (["CODE", "OCI-IMAGE", "CONFIG"].includes(artifact.kind)) {
      const materialization = artifact.materializationVerification;
      const expectedMethod = artifact.kind === "OCI-IMAGE"
        ? "ISOLATED-OCI-ARCHIVE-INSPECTION"
        : "ISOLATED-ARCHIVE-MATERIALIZATION";
      if (
        !materialization
        || materialization.verified !== true
        || materialization.method !== expectedMethod
        || materialization.artifactSha256 !== artifact.sha256
        || materialization.sourceRefsSha256 !== artifact.sourceRefsSha256
        || materialization.ownershipManifestSha256 !== artifact.ownershipManifestSha256
      ) {
        fail(`Artifact ${artifact.artifactId} lacks exact isolated materialization and ownership evidence.`);
      }
      const materializedAt = validateEvidenceTime(
        materialization.verifiedAt,
        `${artifact.artifactId} materialization verifiedAt`,
        freshness,
      );
      if (materializedAt < checksumAt) {
        fail(`Artifact ${artifact.artifactId} was materialized before its immutable checksum was verified.`);
      }
    } else if (artifact.materializationVerification !== null) {
      fail(`Artifact ${artifact.artifactId} has an unexpected generic materialization claim.`);
    }
  }
  return artifactIndex;
}

function engineRecoveryId(database) {
  return `engine-global:${database.engine.toLowerCase()}:${database.serverContainer}`;
}

function engineRegenerationMethod(database) {
  if (
    database.engine === "MARIADB"
    && ["information_schema", "performance_schema"].includes(database.name)
  ) {
    return "MARIADB-VIRTUAL-CATALOG-REGENERATION";
  }
  if (database.engine === "POSTGRESQL" && database.name === "template0") {
    return "POSTGRESQL-TEMPLATE0-INITDB";
  }
  return null;
}

function databaseCatalogManifest(databases) {
  return sha256Canonical(
    [...databases]
      .map((database) => ({ databaseId: database.id, catalogSha256: database.catalogSha256 }))
      .sort((left, right) => left.databaseId.localeCompare(right.databaseId)),
  );
}

function artifactChecksumTime(artifact, freshness) {
  return validateEvidenceTime(
    artifact.checksum.verifiedAt,
    `${artifact.artifactId} checksum verifiedAt`,
    freshness,
  );
}

function validateToolCompatibility(value, engineVersion, label, freshness) {
  if (
    !SHA256.test(String(value.toolSha256 ?? ""))
    || !value.serverCompatibility
    || value.serverCompatibility.verified !== true
    || value.serverCompatibility.serverEngineVersion !== engineVersion
  ) {
    fail(`${label} lacks immutable tool identity and verified server compatibility.`);
  }
  validateEvidenceTime(
    value.serverCompatibility.verifiedAt,
    `${label} server compatibility verifiedAt`,
    freshness,
  );
}

function strongEvidenceHash(value) {
  return SHA256.test(String(value ?? "")) && !/^([a-f0-9])\1{63}$/.test(value);
}

function validateRecoveryProviderBinding(reference, artifact, application, freshness) {
  const expectedLocatorKind = reference.kind === "CONFIG" ? "config" : "secret";
  const expectedProviderType = reference.kind === "CONFIG" ? "CONFIG-REGISTRY" : "SECRET-VAULT";
  const expectedMethod = reference.kind === "CONFIG"
    ? "ISOLATED-CONFIG-READINESS"
    : "METADATA-ONLY-SECRET-READINESS";
  const locatorMatch = reference.providerLocator.match(VERSIONED_PROVIDER_LOCATOR);
  const providerMatch = reference.providerIdentity.providerRef.match(PROVIDER_IDENTITY_REFERENCE);
  const admissionMatch = reference.externalAdmission.requirementRef.match(EXTERNAL_RECOVERY_REFERENCE);
  const retrieval = reference.retrievalVerification;
  if (
    !locatorMatch
    || locatorMatch[1] !== expectedLocatorKind
    || locatorMatch[2] !== reference.versionSha256
    || PLACEHOLDER_REFERENCE.test(reference.providerLocator)
    || !strongEvidenceHash(reference.versionSha256)
    || reference.providerIdentity.providerType !== expectedProviderType
    || !providerMatch
    || providerMatch[1] !== reference.providerIdentity.identitySha256
    || PLACEHOLDER_REFERENCE.test(reference.providerIdentity.providerRef)
    || !strongEvidenceHash(reference.providerIdentity.identitySha256)
    || retrieval.verified !== true
    || retrieval.method !== expectedMethod
    || retrieval.providerIdentitySha256 !== reference.providerIdentity.identitySha256
    || retrieval.versionSha256 !== reference.versionSha256
    || retrieval.valueRetrieved !== false
    || !strongEvidenceHash(retrieval.evidenceSha256)
    || !admissionMatch
    || admissionMatch[1] !== reference.externalAdmission.requirementSha256
    || !strongEvidenceHash(reference.externalAdmission.requirementSha256)
    || reference.externalAdmission.status !== "EXTERNAL-PENDING"
    || reference.externalAdmission.evidenceRef !== null
    || reference.externalAdmission.providerSignatureAccepted !== false
    || reference.externalAdmission.targetSignatureAccepted !== false
    || reference.externalAdmission.canAuthorizeLive !== false
  ) {
    fail(`Recovery reference ${reference.recoveryRefId} lacks an immutable provider, version, retrieval readiness, or external admission binding.`);
  }
  const retrievalAt = validateEvidenceTime(
    retrieval.verifiedAt,
    `${reference.recoveryRefId} retrieval verifiedAt`,
    freshness,
  );
  if (application.quiesce.required && retrievalAt < Date.parse(application.quiesce.evidence.completedAt)) {
    fail(`Recovery reference ${reference.recoveryRefId} readiness predates application quiesce completion.`);
  }
  if (reference.kind === "CONFIG") {
    if (
      !artifact
      || retrieval.artifactSha256 !== artifact.sha256
      || retrievalAt < Date.parse(artifact.materializationVerification.verifiedAt)
    ) {
      fail(`Config recovery reference ${reference.recoveryRefId} is not bound to its exact materialized artifact version.`);
    }
  } else if (artifact || retrieval.artifactSha256 !== null) {
    fail(`Secret recovery reference ${reference.recoveryRefId} must remain value-free and artifact-free.`);
  }
}

function validateReceiptCoverage(receipt, baselineState, artifactIndex, freshness) {
  const {
    anchorIndex,
    containerIndex,
    databaseIndex: baselineDatabases,
    persistentStorageIndex,
    storageApplicationRefs,
    storageDatabaseRefs,
  } = baselineState;
  const applicationIndex = indexUnique(receipt.applications, "applicationId", "Applications");
  const mappingIndex = indexUnique(receipt.mappings, "applicationId", "Mappings");
  const databaseIndex = indexUnique(receipt.databases, "databaseId", "Databases");
  const engineRecoveryIndex = indexUnique(receipt.engineRecoveries, "recoveryId", "Engine recoveries");
  const storageIndex = indexUnique(receipt.storage, "storageId", "Storage");
  const recoveryIndex = indexUnique(receipt.recoveryRefs, "recoveryRefId", "Recovery references");

  assertExactSet(applicationIndex.keys(), anchorIndex.keys(), "Application coverage");
  assertExactSet(mappingIndex.keys(), anchorIndex.keys(), "Application mapping coverage");
  assertExactSet(databaseIndex.keys(), baselineDatabases.keys(), "Database coverage");
  assertExactSet(storageIndex.keys(), persistentStorageIndex.keys(), "Persistent storage coverage");

  const expectedEngineRecoveries = new Map();
  for (const baselineDatabase of baselineDatabases.values()) {
    if (baselineDatabase.kind !== "SYSTEM" || engineRegenerationMethod(baselineDatabase)) continue;
    const recoveryId = engineRecoveryId(baselineDatabase);
    const group = expectedEngineRecoveries.get(recoveryId) ?? {
      engine: baselineDatabase.engine,
      engineVersion: baselineDatabase.engineVersion,
      serverContainer: baselineDatabase.serverContainer,
      databases: [],
    };
    if (
      group.engine !== baselineDatabase.engine
      || group.engineVersion !== baselineDatabase.engineVersion
      || group.serverContainer !== baselineDatabase.serverContainer
    ) {
      fail(`System databases for ${recoveryId} have ambiguous engine-global identities.`);
    }
    group.databases.push(baselineDatabase);
    expectedEngineRecoveries.set(recoveryId, group);
  }
  assertExactSet(engineRecoveryIndex.keys(), expectedEngineRecoveries.keys(), "Engine-global recovery coverage");

  const usedArtifacts = new Set();
  const usedRecoveryRefs = new Set();
  const usedEngineRecoveries = new Set();
  for (const [databaseId, baselineDatabase] of baselineDatabases) {
    const database = databaseIndex.get(databaseId);
    if (
      database.engine !== baselineDatabase.engine
      || database.engineVersion !== baselineDatabase.engineVersion
      || database.databaseKind !== baselineDatabase.kind
    ) {
      fail(`Database ${databaseId} engine, version, and kind must exactly match the baseline.`);
    }
    if (["APPLICATION", "PLATFORM", "RESTORE"].includes(baselineDatabase.kind)) {
      const capture = DATABASE_CAPTURE[baselineDatabase.engine];
      const expectedDisposition = baselineDatabase.kind === "RESTORE"
        ? "TRANSIENT-PRESERVED"
        : capture?.disposition;
      const artifact = artifactIndex.get(database.dumpArtifactRef);
      if (
        !capture
        || database.disposition !== expectedDisposition
        || database.engineRecoveryRef !== null
        || database.dumpFormat !== capture.format
        || database.tool !== capture.tool
        || typeof database.toolVersion !== "string"
        || database.consistencyMethod !== ({
          POSTGRESQL: "PG-MVCC-SNAPSHOT",
          MARIADB: "MARIADB-SINGLE-TRANSACTION",
          REDIS: "REDIS-BGSAVE-RDB",
        })[baselineDatabase.engine]
        || database.sourceCatalogSha256 !== baselineDatabase.catalogSha256
        || database.consistentDump !== true
        || database.checksumVerified !== true
        || database.regeneration !== null
        || !artifact
        || artifact.kind !== "DATABASE-DUMP"
        || artifact.sourceRefs.length !== 1
        || artifact.sourceRefs[0] !== databaseId
      ) {
        fail(`Database ${databaseId} lacks closed engine-aware dump and catalog semantics.`);
      }
      validateToolCompatibility(database, baselineDatabase.engineVersion, `Database ${databaseId}`, freshness);
      const verification = database.restoreVerification;
      if (
        !verification
        || verification.verified !== true
        || verification.method !== capture.method
        || verification.engine !== baselineDatabase.engine
        || verification.engineVersion !== baselineDatabase.engineVersion
        || verification.scope !== "SINGLE-DATABASE"
        || verification.databaseName !== baselineDatabase.name
        || verification.catalogSha256 !== baselineDatabase.catalogSha256
        || verification.artifactSha256 !== artifact.sha256
        || verification.ownershipManifestSha256 !== artifact.ownershipManifestSha256
      ) {
        fail(`Database ${databaseId} restore result is not bound to its exact dump, catalog, engine, and ownership manifest.`);
      }
      const restoredAt = validateEvidenceTime(
        verification.verifiedAt,
        `${databaseId} restore verifiedAt`,
        freshness,
      );
      if (restoredAt < artifactChecksumTime(artifact, freshness)) {
        fail(`Database ${databaseId} restore verification predates its immutable dump checksum.`);
      }
      usedArtifacts.add(artifact.artifactId);
    } else if (baselineDatabase.kind === "SYSTEM") {
      const regenerationMethod = engineRegenerationMethod(baselineDatabase);
      if (regenerationMethod) {
        const baselineContainer = containerIndex.get(baselineDatabase.serverContainer);
        const regeneration = database.regeneration;
        if (
          database.disposition !== "ENGINE-REGENERATED"
          || database.dumpArtifactRef !== null
          || database.engineRecoveryRef !== null
          || database.dumpFormat !== null
          || database.tool !== null
          || database.toolVersion !== null
          || database.toolSha256 !== null
          || database.serverCompatibility !== null
          || database.consistencyMethod !== null
          || database.sourceCatalogSha256 !== null
          || database.consistentDump !== null
          || database.checksumVerified !== null
          || database.quiesceRequired !== false
          || database.restoreVerification !== null
          || !regeneration
          || regeneration.basis !== "ENGINE-VIRTUAL-CATALOG-REGENERATION"
          || regeneration.method !== regenerationMethod
          || regeneration.engine !== baselineDatabase.engine
          || regeneration.engineVersion !== baselineDatabase.engineVersion
          || regeneration.serverContainer !== baselineDatabase.serverContainer
          || regeneration.imageRef !== baselineContainer?.imageRef
          || regeneration.imageId !== baselineContainer?.imageId
          || regeneration.catalogSha256 !== baselineDatabase.catalogSha256
        ) {
          fail(`Virtual system database ${databaseId} lacks exact engine regeneration semantics.`);
        }
        validateEvidenceTime(regeneration.verifiedAt, `${databaseId} regeneration verifiedAt`, freshness);
      } else {
        const recoveryId = engineRecoveryId(baselineDatabase);
        if (
          database.disposition !== "ENGINE-GLOBAL-RECOVERY"
          || database.dumpArtifactRef !== null
          || database.engineRecoveryRef !== recoveryId
          || database.dumpFormat !== null
          || database.tool !== null
          || database.toolVersion !== null
          || database.toolSha256 !== null
          || database.serverCompatibility !== null
          || database.consistencyMethod !== null
          || database.sourceCatalogSha256 !== null
          || database.consistentDump !== null
          || database.checksumVerified !== null
          || database.quiesceRequired !== false
          || database.restoreVerification !== null
          || database.regeneration !== null
        ) {
          fail(`System database ${databaseId} must use exact engine-global recovery without a standalone dump.`);
        }
        usedEngineRecoveries.add(recoveryId);
      }
    } else {
      fail(`Database ${databaseId} has no admissible kind-aware recovery disposition.`);
    }
  }

  for (const [recoveryId, expected] of expectedEngineRecoveries) {
    const recovery = engineRecoveryIndex.get(recoveryId);
    const artifact = recovery && artifactIndex.get(recovery.artifactRef);
    const expectedCapture = ENGINE_GLOBAL_CAPTURE[expected.engine];
    const expectedDatabaseRefs = expected.databases.map((database) => database.id);
    const expectedCatalogManifest = databaseCatalogManifest(expected.databases);
    const verification = recovery?.restoreVerification;
    if (
      !recovery
      || !expectedCapture
      || recovery.engine !== expected.engine
      || recovery.engineVersion !== expected.engineVersion
      || recovery.serverContainer !== expected.serverContainer
      || recovery.format !== expectedCapture.format
      || recovery.tool !== expectedCapture.tool
      || typeof recovery.toolVersion !== "string"
      || recovery.consistencyMethod !== ({
        POSTGRESQL: "PG-GLOBALS-CONSISTENT",
        MARIADB: "MARIADB-SYSTEM-CONSISTENT",
        REDIS: "REDIS-BGSAVE-RDB",
      })[expected.engine]
      || recovery.catalogManifestSha256 !== expectedCatalogManifest
      || recovery.checksumVerified !== true
      || !artifact
      || artifact.kind !== "DATABASE-GLOBAL"
      || verification?.verified !== true
      || verification.method !== "ISOLATED-ENGINE-GLOBAL-RESTORE"
      || verification.engine !== expected.engine
      || verification.engineVersion !== expected.engineVersion
      || verification.scope !== "ENGINE-GLOBAL"
      || verification.databaseName !== null
      || verification.catalogSha256 !== expectedCatalogManifest
      || verification.artifactSha256 !== artifact.sha256
      || verification.ownershipManifestSha256 !== artifact.ownershipManifestSha256
    ) {
      fail(`Engine-global recovery ${recoveryId} lacks exact system catalog and restore semantics.`);
    }
    validateToolCompatibility(recovery, expected.engineVersion, `Engine-global recovery ${recoveryId}`, freshness);
    assertExactSet(recovery.databaseRefs, expectedDatabaseRefs, `Engine-global recovery ${recoveryId} database coverage`);
    assertExactSet(artifact.sourceRefs, expectedDatabaseRefs, `Engine-global artifact ${recoveryId} source coverage`);
    const restoredAt = validateEvidenceTime(
      verification.verifiedAt,
      `${recoveryId} restore verifiedAt`,
      freshness,
    );
    if (restoredAt < artifactChecksumTime(artifact, freshness)) {
      fail(`Engine-global recovery ${recoveryId} predates its immutable artifact checksum.`);
    }
    usedArtifacts.add(artifact.artifactId);
  }
  assertExactSet(usedEngineRecoveries, engineRecoveryIndex.keys(), "Engine-global database references");

  for (const [storageId, baselineStorage] of persistentStorageIndex) {
    const storage = storageIndex.get(storageId);
    const artifact = storage && artifactIndex.get(storage.artifactRef);
    const kindMatches = ["NAMED-VOLUME", "ANONYMOUS-VOLUME", "SOURCE-ROOT"].includes(baselineStorage.kind)
      ? storage?.kind === baselineStorage.kind && artifact?.kind === baselineStorage.kind
      : ["BIND", "UPLOAD"].includes(storage?.kind) && artifact?.kind === storage?.kind;
    if (
      !storage
      || storage.sourceRef !== storageId
      || !artifact
      || !kindMatches
      || artifact.sourceRefs.length !== 1
      || artifact.sourceRefs[0] !== storageId
      || storage.checksumVerified !== true
      || storage.restoreVerification.verified !== true
      || storage.restoreVerification.method !== "ISOLATED-MATERIALIZATION"
      || storage.restoreVerification.artifactSha256 !== artifact.sha256
      || storage.restoreVerification.ownershipManifestSha256 !== artifact.ownershipManifestSha256
    ) {
      fail(`Storage ${storageId} lacks an exact checksum-verified backup and restore verification.`);
    }
    const expectedDatabaseDependencies = storageDatabaseRefs.get(storageId);
    const expectedApplicationDependencies = storageApplicationRefs.get(storageId);
    const expectedRecoveryRole = expectedDatabaseDependencies.size > 0
      ? "DATABASE-FALLBACK-ONLY"
      : "PRIMARY";
    if (storage.recoveryRole !== expectedRecoveryRole) {
      fail(`Storage ${storageId} must declare its exact primary or database-fallback recovery role.`);
    }
    assertExactSet(
      storage.dependencyDatabaseRefs,
      expectedDatabaseDependencies,
      `Storage ${storageId} database dependency closure`,
    );
    assertExactSet(
      storage.dependencyApplicationRefs,
      expectedApplicationDependencies,
      `Storage ${storageId} application dependency closure`,
    );
    const writableSource = baselineStorage.kind === "BIND"
      ? baselineStorage.source.consumers.some((consumer) => consumer.readOnly === false)
      : baselineStorage.kind === "SOURCE-ROOT"
        ? baselineStorage.source.mounted === true
        : baselineStorage.source.attachments.some((attachment) => attachment.readOnly === false);
    const expectedQuiesce = writableSource && storage.captureMode !== "FILESYSTEM-SNAPSHOT";
    if (
      !["QUIESCED-ARCHIVE", "FILESYSTEM-SNAPSHOT"].includes(storage.captureMode)
      || storage.quiesceRequired !== expectedQuiesce
    ) {
      fail(`Storage ${storageId} quiesce must derive from baseline writability or an explicit filesystem snapshot.`);
    }
    const restoredAt = validateEvidenceTime(
      storage.restoreVerification.verifiedAt,
      `${storageId} restore verifiedAt`,
      freshness,
    );
    if (restoredAt < artifactChecksumTime(artifact, freshness)) {
      fail(`Storage ${storageId} restore verification predates its immutable artifact checksum.`);
    }
    usedArtifacts.add(artifact.artifactId);
  }

  for (const [applicationId, anchor] of anchorIndex) {
    const application = applicationIndex.get(applicationId);
    const mapping = mappingIndex.get(applicationId);
    if (application.mappingState !== anchor.mappingState || mapping.mappingState !== anchor.mappingState) {
      fail(`Application ${applicationId} mappingState must exactly match the deny-only baseline.`);
    }
    assertExactSet(application.databaseRefs, anchor.databaseRefs, `Application ${applicationId} database coverage`);
    assertExactSet(application.storageRefs, anchor.storageRefs, `Application ${applicationId} storage coverage`);
    assertExactSet(mapping.databaseRefs, anchor.databaseRefs, `Application ${applicationId} mapping database coverage`);
    assertExactSet(mapping.storageRefs, anchor.storageRefs, `Application ${applicationId} mapping storage coverage`);

    const codeSources = [];
    for (const artifactId of application.codeArtifactRefs) {
      const artifact = artifactIndex.get(artifactId);
      if (!artifact || !["CODE", "OCI-IMAGE"].includes(artifact.kind)) {
        fail(`Application ${applicationId} code artifact ${artifactId} is invalid.`);
      }
      codeSources.push(...artifact.sourceRefs);
      usedArtifacts.add(artifactId);
    }
    const expectedCodeSources = new Set([
      ...anchor.sourceRootRefs,
      ...anchor.sourceBindRefs,
      ...anchor.containerRefs,
    ]);
    assertExactSet(codeSources, expectedCodeSources, `Application ${applicationId} code artifact coverage`);

    const imageIndex = indexUnique(application.containerImages, "containerRef", `Application ${applicationId} container images`);
    assertExactSet(imageIndex.keys(), anchor.containerRefs, `Application ${applicationId} container image coverage`);
    for (const containerRef of anchor.containerRefs) {
      const baselineContainer = containerIndex.get(containerRef);
      const image = imageIndex.get(containerRef);
      const artifact = image && artifactIndex.get(image.artifactRef);
      const verification = image?.materializationVerification;
      if (
        !baselineContainer
        || !baselineContainer.imageId
        || !image
        || image.imageRef !== baselineContainer.imageRef
        || image.imageId !== baselineContainer.imageId
        || image.archiveFormat !== "OCI-IMAGE-LAYOUT-V1"
        || !artifact
        || artifact.kind !== "OCI-IMAGE"
        || !application.codeArtifactRefs.includes(artifact.artifactId)
        || artifact.sourceRefs.length !== 1
        || artifact.sourceRefs[0] !== containerRef
        || verification?.verified !== true
        || verification.method !== "ISOLATED-OCI-ARCHIVE-INSPECTION"
        || verification.imageRef !== baselineContainer.imageRef
        || verification.imageId !== baselineContainer.imageId
        || verification.manifestSha256 !== image.manifestSha256
        || verification.artifactSha256 !== artifact.sha256
        || verification.ownershipManifestSha256 !== artifact.ownershipManifestSha256
      ) {
        fail(`Application ${applicationId} container ${containerRef} lacks exact OCI image identity and materialization evidence.`);
      }
      const materializedAt = validateEvidenceTime(
        verification.verifiedAt,
        `${applicationId}/${containerRef} OCI materialization verifiedAt`,
        freshness,
      );
      if (materializedAt < artifactChecksumTime(artifact, freshness)) {
        fail(`Application ${applicationId} container ${containerRef} OCI materialization predates its artifact checksum.`);
      }
    }

    const configSources = [];
    const configArtifactSources = new Set();
    for (const referenceId of application.configRecoveryRefs) {
      const reference = recoveryIndex.get(referenceId);
      const artifact = reference && artifactIndex.get(reference.artifactRef);
      if (
        !reference
        || reference.applicationId !== applicationId
        || reference.kind !== "CONFIG"
        || !reference.providerLocator.startsWith("provider-config://")
        || reference.valuesIncluded !== false
        || !artifact
        || artifact.kind !== "CONFIG"
        || !artifact.sourceRefs.includes(reference.sourceRef)
      ) {
        fail(`Application ${applicationId} config recovery reference ${referenceId} is invalid.`);
      }
      validateRecoveryProviderBinding(reference, artifact, application, freshness);
      configSources.push(reference.sourceRef);
      artifact.sourceRefs.forEach((sourceRef) => configArtifactSources.add(sourceRef));
      usedRecoveryRefs.add(referenceId);
      usedArtifacts.add(artifact.artifactId);
    }
    assertExactSet(configSources, anchor.configRefs, `Application ${applicationId} config recovery coverage`);
    assertExactSet(configArtifactSources, anchor.configRefs, `Application ${applicationId} config artifact coverage`);

    const secretSources = [];
    for (const referenceId of application.secretRecoveryRefs) {
      const reference = recoveryIndex.get(referenceId);
      if (
        !reference
        || reference.applicationId !== applicationId
        || reference.kind !== "SECRET"
        || !reference.providerLocator.startsWith("provider-secret://")
        || reference.artifactRef !== null
        || reference.valuesIncluded !== false
      ) {
        fail(`Application ${applicationId} secret recovery reference ${referenceId} is invalid.`);
      }
      validateRecoveryProviderBinding(reference, null, application, freshness);
      secretSources.push(reference.sourceRef);
      usedRecoveryRefs.add(referenceId);
    }
    assertExactSet(secretSources, anchor.secretMetadataRefs, `Application ${applicationId} secret recovery coverage`);

    const needsQuiesce = application.databaseRefs.some((id) => databaseIndex.get(id).quiesceRequired)
      || application.storageRefs.some((id) => storageIndex.get(id).quiesceRequired);
    if (application.quiesce.required !== needsQuiesce) {
      fail(`Application ${applicationId} quiesce requirement does not match its backup resources.`);
    }
    if (needsQuiesce) {
      const evidence = application.quiesce.evidence;
      if (!evidence || evidence.verified !== true) fail(`Application ${applicationId} is missing verified quiesce evidence.`);
      const startedAt = validateEvidenceTime(
        evidence.startedAt,
        `${applicationId} quiesce startedAt`,
        freshness,
      );
      const completedAt = validateEvidenceTime(
        evidence.completedAt,
        `${applicationId} quiesce completedAt`,
        freshness,
      );
      if (startedAt > completedAt) {
        fail(`Application ${applicationId} quiesce evidence has an invalid time window.`);
      }
      const quiescedArtifacts = [];
      for (const databaseId of application.databaseRefs) {
        const database = databaseIndex.get(databaseId);
        if (database.quiesceRequired && database.dumpArtifactRef) {
          quiescedArtifacts.push(artifactIndex.get(database.dumpArtifactRef));
        }
      }
      for (const storageId of application.storageRefs) {
        const storage = storageIndex.get(storageId);
        if (storage.quiesceRequired) quiescedArtifacts.push(artifactIndex.get(storage.artifactRef));
      }
      for (const artifact of quiescedArtifacts) {
        const capturedAt = validateEvidenceTime(
          artifact.capturedAt,
          `${artifact.artifactId} capturedAt`,
          freshness,
        );
        const checksumAt = artifactChecksumTime(artifact, freshness);
        if (capturedAt < startedAt || capturedAt > completedAt || checksumAt < completedAt) {
          fail(`Application ${applicationId} quiesce evidence is not causal for artifact ${artifact.artifactId}.`);
        }
      }
    } else if (application.quiesce.evidence !== null) {
      fail(`Application ${applicationId} has unexpected quiesce evidence.`);
    }

    for (const databaseId of application.databaseRefs) {
      for (const storageId of baselineDatabases.get(databaseId).storageRefs) {
        if (!application.storageRefs.includes(storageId)) {
          fail(`Application ${applicationId} mapping does not bind database ${databaseId} to storage ${storageId}.`);
        }
      }
    }
  }

  assertExactSet(usedRecoveryRefs, recoveryIndex.keys(), "Recovery reference coverage");
  assertExactSet(usedArtifacts, artifactIndex.keys(), "Backup artifact coverage");
  return { applicationIndex, databaseIndex, storageIndex };
}

function resourceOwners(applicationIndex, field) {
  const dependencies = new Map();
  for (const application of applicationIndex.values()) {
    for (const resourceId of application[field]) {
      const consumers = dependencies.get(resourceId) ?? [];
      consumers.push(application.applicationId);
      dependencies.set(resourceId, consumers);
    }
  }
  return new Map(
    [...dependencies].map(([resourceId, consumers]) => [resourceId, sorted(consumers)[0]]),
  );
}

function emptyStepProjection() {
  return {
    artifactRefs: [],
    databaseRefs: [],
    delegatedDatabaseRefs: [],
    storageRefs: [],
    fallbackStorageRefs: [],
    delegatedStorageRefs: [],
    recoveryRefs: [],
  };
}

function expectedStep(application, phase, databaseIndex, storageIndex, databaseOwners, storageOwners) {
  const projection = emptyStepProjection();
  switch (phase) {
    case "CODE": {
      projection.artifactRefs = application.codeArtifactRefs;
      return projection;
    }
    case "CONFIG": {
      projection.recoveryRefs = application.configRecoveryRefs;
      return projection;
    }
    case "STORAGE": {
      for (const storageId of application.storageRefs) {
        if (storageOwners.get(storageId) !== application.applicationId) {
          projection.delegatedStorageRefs.push(storageId);
        } else if (storageIndex.get(storageId).recoveryRole === "DATABASE-FALLBACK-ONLY") {
          projection.fallbackStorageRefs.push(storageId);
        } else {
          projection.storageRefs.push(storageId);
        }
      }
      return projection;
    }
    case "DATABASE": {
      for (const databaseId of application.databaseRefs) {
        if (databaseOwners.get(databaseId) !== application.applicationId) {
          projection.delegatedDatabaseRefs.push(databaseId);
        } else {
          projection.databaseRefs.push(databaseId);
        }
      }
      return projection;
    }
    case "SECRETS": {
      projection.recoveryRefs = application.secretRecoveryRefs;
      return projection;
    }
    case "VERIFY":
      return projection;
    default:
      fail(`Unsupported restore phase ${phase}.`);
  }
}

function validateRestorePlan(receipt, applicationIndex, databaseIndex, storageIndex) {
  const stepIndex = indexUnique(receipt.restorePlan, "stepId", "Restore plan");
  void stepIndex;
  receipt.restorePlan.forEach((step, index) => {
    if (step.order !== index + 1) fail("Restore plan order must be unique and contiguous from one.");
    if (!applicationIndex.has(step.applicationId)) fail(`Restore plan references unknown application ${step.applicationId}.`);
  });

  const databaseOwners = resourceOwners(applicationIndex, "databaseRefs");
  const storageOwners = resourceOwners(applicationIndex, "storageRefs");
  for (const [applicationId, application] of applicationIndex) {
    const steps = receipt.restorePlan.filter((step) => step.applicationId === applicationId);
    const expectedPhases = PHASES.filter((phase) => {
      if (phase === "CODE") return application.codeArtifactRefs.length > 0;
      if (phase === "CONFIG") return application.configRecoveryRefs.length > 0;
      if (phase === "STORAGE") return application.storageRefs.length > 0;
      if (phase === "DATABASE") return application.databaseRefs.length > 0;
      if (phase === "SECRETS") return application.secretRecoveryRefs.length > 0;
      return true;
    });
    if (steps.length !== expectedPhases.length) fail(`Restore plan for ${applicationId} is incomplete.`);
    for (let index = 0; index < expectedPhases.length; index += 1) {
      const step = steps[index];
      const phase = expectedPhases[index];
      if (step.phase !== phase) fail(`Restore plan for ${applicationId} has an invalid phase order.`);
      const expected = expectedStep(
        application,
        phase,
        databaseIndex,
        storageIndex,
        databaseOwners,
        storageOwners,
      );
      for (const field of [
        "artifactRefs",
        "databaseRefs",
        "delegatedDatabaseRefs",
        "storageRefs",
        "fallbackStorageRefs",
        "delegatedStorageRefs",
        "recoveryRefs",
      ]) {
        assertExactSet(step[field], expected[field], `Restore plan ${step.stepId} ${field}`);
      }
      if (step.destructiveMigration !== false) fail(`Restore plan ${step.stepId} contains a destructive migration.`);
    }
  }
  assertExactSet(
    receipt.restorePlan.flatMap((step) => step.databaseRefs),
    databaseIndex.keys(),
    "Restore plan single-owner database coverage",
  );
  assertExactSet(
    receipt.restorePlan.flatMap((step) => [...step.storageRefs, ...step.fallbackStorageRefs]),
    storageIndex.keys(),
    "Restore plan single-owner storage coverage",
  );
  const verifyOrder = new Map(
    receipt.restorePlan
      .filter((step) => step.phase === "VERIFY")
      .map((step) => [step.applicationId, step.order]),
  );
  const databaseOwnerOrder = new Map();
  const storageOwnerOrder = new Map();
  for (const step of receipt.restorePlan) {
    step.databaseRefs.forEach((databaseId) => databaseOwnerOrder.set(databaseId, step.order));
    [...step.storageRefs, ...step.fallbackStorageRefs]
      .forEach((storageId) => storageOwnerOrder.set(storageId, step.order));
  }
  for (const step of receipt.restorePlan) {
    for (const databaseId of step.delegatedDatabaseRefs) {
      if (databaseOwnerOrder.get(databaseId) >= verifyOrder.get(step.applicationId)) {
        fail(`Restore owner for delegated database ${databaseId} must run before ${step.applicationId} verification.`);
      }
    }
    for (const storageId of step.delegatedStorageRefs) {
      if (storageOwnerOrder.get(storageId) >= verifyOrder.get(step.applicationId)) {
        fail(`Restore owner for delegated storage ${storageId} must run before ${step.applicationId} verification.`);
      }
    }
  }
}

function validateRollback(receipt, applicationIndex, databaseIndex, storageIndex) {
  if (receipt.rollback.code.planId === receipt.rollback.data.planId) {
    fail("Rollback code and data plans must remain separate.");
  }
  const codeIndex = indexUnique(receipt.rollback.code.steps, "applicationId", "Code rollback");
  const dataIndex = indexUnique(receipt.rollback.data.steps, "applicationId", "Data rollback");
  indexUnique(receipt.rollback.code.steps, "stepId", "Code rollback");
  indexUnique(receipt.rollback.data.steps, "stepId", "Data rollback");
  const codeApplications = [...applicationIndex.values()]
    .filter((application) => application.codeArtifactRefs.length > 0 || application.configRecoveryRefs.length > 0)
    .map((application) => application.applicationId);
  const dataApplications = [...applicationIndex.values()]
    .filter((application) => application.databaseRefs.length > 0 || application.storageRefs.length > 0)
    .map((application) => application.applicationId);
  assertExactSet(codeIndex.keys(), codeApplications, "Code rollback application coverage");
  assertExactSet(dataIndex.keys(), dataApplications, "Data rollback application coverage");
  const databaseOwners = resourceOwners(applicationIndex, "databaseRefs");
  const storageOwners = resourceOwners(applicationIndex, "storageRefs");
  if (
    receipt.rollback.data.automatic !== false
    || receipt.rollback.data.requiresProviderTargetAdmission !== true
    || receipt.rollback.data.postDeployPreservationRequired !== true
  ) {
    fail("Data rollback must remain manual, externally admitted, and post-deploy preservation-gated.");
  }
  const admission = receipt.rollback.data.externalAdmission;
  const admissionMatch = admission.requirementRef.match(EXTERNAL_ADMISSION_REFERENCE);
  if (
    !admissionMatch
    || admissionMatch[1] !== admission.requirementSha256
    || admission.status !== "EXTERNAL-PENDING"
    || admission.evidenceRef !== null
    || admission.providerDurabilityAttestationRequired !== true
    || admission.targetMountAttestationRequired !== true
    || admission.providerSignatureAccepted !== false
    || admission.targetSignatureAccepted !== false
    || admission.canAuthorizeLive !== false
  ) {
    fail("Data rollback requires an immutable external provider-and-target admission policy that remains pending.");
  }
  receipt.rollback.code.steps.forEach((step, index) => {
    if (step.order !== index + 1) fail("Code rollback order must be contiguous from one.");
    const application = applicationIndex.get(step.applicationId);
    assertExactSet(step.artifactRefs, application.codeArtifactRefs, `Code rollback ${step.applicationId} artifact coverage`);
    assertExactSet(step.configRecoveryRefs, application.configRecoveryRefs, `Code rollback ${step.applicationId} config coverage`);
  });
  receipt.rollback.data.steps.forEach((step, index) => {
    if (step.order !== index + 1) fail("Data rollback order must be contiguous from one.");
    const application = applicationIndex.get(step.applicationId);
    const recoverableDatabases = application.databaseRefs
      .filter((databaseId) => databaseOwners.get(databaseId) === application.applicationId);
    const delegatedDatabases = application.databaseRefs
      .filter((databaseId) => databaseOwners.get(databaseId) !== application.applicationId);
    const primaryStorage = application.storageRefs.filter((storageId) => (
      storageOwners.get(storageId) === application.applicationId
      && storageIndex.get(storageId).recoveryRole === "PRIMARY"
    ));
    const fallbackStorage = application.storageRefs.filter((storageId) => (
      storageOwners.get(storageId) === application.applicationId
      && storageIndex.get(storageId).recoveryRole === "DATABASE-FALLBACK-ONLY"
    ));
    const delegatedStorage = application.storageRefs
      .filter((storageId) => storageOwners.get(storageId) !== application.applicationId);
    assertExactSet(step.databaseRefs, recoverableDatabases, `Data rollback ${step.applicationId} database coverage`);
    assertExactSet(step.delegatedDatabaseRefs, delegatedDatabases, `Data rollback ${step.applicationId} delegated database coverage`);
    assertExactSet(step.storageRefs, primaryStorage, `Data rollback ${step.applicationId} storage coverage`);
    assertExactSet(step.fallbackStorageRefs, fallbackStorage, `Data rollback ${step.applicationId} fallback storage coverage`);
    assertExactSet(step.delegatedStorageRefs, delegatedStorage, `Data rollback ${step.applicationId} delegated storage coverage`);
  });
  assertExactSet(
    receipt.rollback.data.steps.flatMap((step) => step.databaseRefs),
    databaseIndex.keys(),
    "Data rollback single-owner database coverage",
  );
  assertExactSet(
    receipt.rollback.data.steps.flatMap((step) => [...step.storageRefs, ...step.fallbackStorageRefs]),
    storageIndex.keys(),
    "Data rollback single-owner storage coverage",
  );
}

export function verifyV1PredeployBackupReceipt({
  receipt,
  baseline,
  baselineSha256,
  expectedTargetRoot,
  expectedCandidateCommit,
  expectedCandidateTree,
} = {}) {
  if (!validateSchema(receipt)) {
    const details = validateSchema.errors
      .slice(0, 5)
      .map((error) => `${error.instancePath || "/"} ${error.message}`)
      .join("; ");
    fail(`Receipt schema validation failed: ${details}.`);
  }
  const receiptPayload = structuredClone(receipt);
  delete receiptPayload.receiptId;
  if (receipt.receiptId !== sha256Canonical(receiptPayload)) {
    fail("Receipt receiptId does not match the canonical receipt payload.");
  }
  if (receipt.target.root !== expectedTargetRoot) {
    fail("Receipt target.root does not exactly match the expected rebuild target root.");
  }
  if (receipt.candidate.commit !== expectedCandidateCommit) {
    fail("Receipt candidate commit does not exactly match the expected candidate commit.");
  }
  if (receipt.candidate.tree !== expectedCandidateTree) {
    fail("Receipt candidate tree does not exactly match the expected candidate tree.");
  }
  if (
    receipt.synthetic !== baseline?.synthetic
    || (receipt.evidenceClass === "SYNTHETIC-TEST") !== (baseline?.evidenceClass === "SYNTHETIC-TEST")
  ) {
    fail("Receipt and deny-only baseline evidence classes do not match.");
  }
  const freshness = validateFreshness(receipt);
  const baselineState = validateDenyOnlyBaseline(
    baseline,
    baselineSha256,
    receipt.baseline,
    receipt.target,
  );
  const artifactIndex = validateRootsAndArtifacts(receipt, baselineState, freshness);
  const coverageState = validateReceiptCoverage(receipt, baselineState, artifactIndex, freshness);
  validateRestorePlan(
    receipt,
    coverageState.applicationIndex,
    coverageState.databaseIndex,
    coverageState.storageIndex,
  );
  validateRollback(
    receipt,
    coverageState.applicationIndex,
    coverageState.databaseIndex,
    coverageState.storageIndex,
  );

  return Object.freeze({
    status: REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE,
    authoritative: false,
    liveAuthorization: false,
    mutationAuthority: false,
  });
}

function readJsonReadOnly(inputPath, label) {
  const absolutePath = path.resolve(String(inputPath ?? ""));
  const noFollow = fs.constants.O_NOFOLLOW;
  if (!inputPath || typeof noFollow !== "number") fail(`${label} cannot be read safely.`);
  let descriptor;
  try {
    descriptor = fs.openSync(absolutePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > MAX_INPUT_BYTES) {
      fail(`${label} must be a singly linked regular JSON file within the size boundary.`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (
      bytes.length !== before.size
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ctimeMs !== after.ctimeMs
    ) {
      fail(`${label} changed while it was read.`);
    }
    let document;
    try {
      document = JSON.parse(bytes.toString("utf8").replace(/^\uFEFF/, ""));
    } catch {
      fail(`${label} is not valid JSON.`);
    }
    return {
      document,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function runCli(argv) {
  if (
    argv.length !== 11
    || argv[0] !== "--verify"
    || argv[1] !== "--receipt"
    || argv[3] !== "--baseline"
    || argv[5] !== "--target-root"
    || argv[7] !== "--candidate-commit"
    || argv[9] !== "--candidate-tree"
    || [argv[2], argv[4], argv[6], argv[8], argv[10]].some((value) => !value || value.startsWith("-"))
    || !GIT_OBJECT.test(argv[8])
    || !GIT_OBJECT.test(argv[10])
  ) {
    fail("usage: node scripts/v1-predeploy-backup-receipt.mjs --verify --receipt <receipt.json> --baseline <baseline.json> --target-root <absolute-path> --candidate-commit <git-object> --candidate-tree <git-object>");
  }
  const receiptArtifact = readJsonReadOnly(argv[2], "Receipt");
  const baselineArtifact = readJsonReadOnly(argv[4], "Baseline");
  const result = verifyV1PredeployBackupReceipt({
    receipt: receiptArtifact.document,
    baseline: baselineArtifact.document,
    baselineSha256: baselineArtifact.sha256,
    expectedTargetRoot: argv[6],
    expectedCandidateCommit: argv[8],
    expectedCandidateTree: argv[10],
  });
  process.stdout.write(`${result.status}\n`);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
