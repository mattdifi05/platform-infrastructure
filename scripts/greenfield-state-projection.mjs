// GREENFIELD STATE PROJECTION for V1 LOCAL_PRIVATE GREENFIELD.
// Deterministic, offline planning: PRESERVED brownfield state -> greenfield
// destinations. No side effects; pure data in -> frozen plan out.

import { isBrownfieldOwnedPhysicalName } from "./greenfield-namespace.mjs";

export const GREENFIELD_STATE_PROJECTION_SCHEMA = "platform.greenfield-state-projection/v1";

const SRC_TREE_KEY = "/home/platform_infrastructure/src";
const STATE_TREE_KEY = "/home/platform_infrastructure/platform-infrastructure/projects-portal/state";
const SECRETS_TREE_KEY = "/home/platform_infrastructure/platform-infrastructure/secrets";
const BACKUPS_TREE_KEY = "/home/platform_infrastructure/platform-infrastructure/backups";

// Documented greenfield bind root projected from the brownfield src tree;
// consumed by gf-php-apache / gf-project-router via PHP_PROJECTS_DIR.
export const GREENFIELD_PHP_PROJECTS_DIR = "/srv/platform_infra_greenfield/src";

const ENTRY_KINDS = Object.freeze([
  "postgres",
  "mariadb",
  "minio",
  "keycloak-config",
  "keycloak-data",
  "redis-data",
  "app-source-tree",
  "control-center-state",
  "secret-manager-store",
  "backup-family",
  "writable-layer",
]);

const CLASSIFICATIONS = Object.freeze(["PRESERVE", "PRESERVE_IF_STATEFUL", "OBSERVE"]);
const TARGET_KINDS = Object.freeze(["volume", "bind", "database"]);

const REQUIRED_ENTRY_FIELDS = Object.freeze([
  "entryId",
  "kind",
  "sourceIdentity",
  "classification",
  "backupMethod",
  "restoreMethod",
  "target",
  "ownership",
  "mode",
  "verificationMethod",
  "rollbackRelationship",
]);

const ROLLBACK_VOLUME_UNTOUCHED = "brownfield-volume-untouched";
const ROLLBACK_TREE_UNTOUCHED = "brownfield-tree-untouched";
const SHARED_ARCHIVE_ROOT_REF = "shared-read-only-archive-root";

function entry(fields) {
  return fields;
}

function postgresEntry(databaseName, extraMode) {
  return entry({
    entryId: `postgres-${databaseName}`,
    kind: "postgres",
    sourceIdentity: "volume:enterprise_postgres_data",
    classification: "PRESERVE",
    backupMethod: `pg_dump --format=custom per DB (${databaseName}) after writer quiesce`,
    restoreMethod: `pg_restore into gf-postgres database ${databaseName}`,
    target: { kind: "database", ref: `gf-postgres/${databaseName}` },
    ownership: "postgres:postgres (logical, container-local)",
    mode: extraMode,
    verificationMethod: "postgres row-count+checksum fingerprint",
    rollbackRelationship: ROLLBACK_VOLUME_UNTOUCHED,
  });
}

function appSourceTreeEntry(project) {
  return entry({
    entryId: `app-src-${project}`,
    kind: "app-source-tree",
    sourceIdentity: `tree:${SRC_TREE_KEY}/${project}`,
    classification: "PRESERVE",
    backupMethod: `rsync-style incremental archive of ${project} tree`,
    restoreMethod: `rsync-style materialize into greenfield PHP_PROJECTS_DIR bind (${GREENFIELD_PHP_PROJECTS_DIR}/${project})`,
    target: { kind: "bind", ref: `${GREENFIELD_PHP_PROJECTS_DIR}/${project}` },
    ownership: "uid 1000 / gid 1000 (platform_infrastructure)",
    mode: "preserve ownership+modes verbatim during projection",
    verificationMethod: "recursive tree digest + ownership/mode",
    rollbackRelationship: ROLLBACK_TREE_UNTOUCHED,
  });
}

export function buildStateProjectionPlan({ manifest, includeRedisState = true }) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new TypeError("manifest must be a parsed preservation-manifest object");
  }
  const trees = manifest.hostStateTrees;
  if (!trees || typeof trees !== "object") {
    throw new TypeError("manifest.hostStateTrees is required");
  }
  const srcTree = trees[SRC_TREE_KEY];
  if (!srcTree || !Array.isArray(srcTree.projects)) {
    throw new TypeError(`manifest.hostStateTrees["${SRC_TREE_KEY}"].projects is required`);
  }
  if (!trees[STATE_TREE_KEY]) {
    throw new TypeError(`manifest.hostStateTrees["${STATE_TREE_KEY}"] is required`);
  }

  const projects = [...new Set(srcTree.projects)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (const project of projects) {
    if (typeof project !== "string" || project.length === 0) {
      throw new TypeError("every src project name must be a non-empty string");
    }
  }

  const backupsTree = trees[BACKUPS_TREE_KEY];
  const backupsFamilies = Array.isArray(backupsTree?.families) ? backupsTree.families.length : null;
  const anonymousRaw = manifest.anonymousVolumesCountApprox;
  const anonymousLabel = Number.isFinite(Number(anonymousRaw))
    ? `approx-${Number(anonymousRaw)}`
    : "count-unmeasured";

  const collected = [];

  collected.push(
    postgresEntry("keycloak", "single-shot cutover restore before gf-keycloak first start"),
    postgresEntry("stexor", "single-shot cutover restore before any greenfield app start"),
    entry({
      entryId: "mariadb-all",
      kind: "mariadb",
      sourceIdentity: "volume:enterprise_mariadb_data",
      classification: "PRESERVE",
      backupMethod: "mariadb-dump --single-transaction --all user schemas",
      restoreMethod: "load SQL dump into gf-mariadb (all user schemas)",
      target: { kind: "database", ref: "gf-mariadb/user-schemas" },
      ownership: "mysql:mysql (logical, container-local)",
      mode: "single-shot cutover load before greenfield app start",
      verificationMethod: "mariadb schema/table-count+fingerprint",
      rollbackRelationship: ROLLBACK_VOLUME_UNTOUCHED,
    }),
    entry({
      entryId: "minio-data",
      kind: "minio",
      sourceIdentity: "volume:enterprise_minio_data",
      classification: "PRESERVE",
      backupMethod: "mc mirror export + tar of the data tree",
      restoreMethod: "mc mirror restore into greenfield_minio_data on gf-minio",
      target: { kind: "volume", ref: "greenfield_minio_data" },
      ownership: "gf-minio container user",
      mode: "single-shot cutover mirror before greenfield storage consumers start",
      verificationMethod: "bucket/object-count/size/checksum",
      rollbackRelationship: ROLLBACK_VOLUME_UNTOUCHED,
    }),
    entry({
      entryId: "keycloak-config",
      kind: "keycloak-config",
      sourceIdentity: "volume:enterprise_keycloak_data#realm-export",
      classification: "PRESERVE",
      backupMethod: "keycloak realm export (JSON) from enterprise-keycloak",
      restoreMethod: "gf-keycloak realm import (--import-realm) against gf-postgres/keycloak",
      target: { kind: "database", ref: "gf-postgres/keycloak" },
      ownership: "keycloak:keycloak (logical, container-local)",
      mode: "import once at cutover; never re-projected afterwards",
      verificationMethod: "realm/client/role-count parity vs exported JSON",
      rollbackRelationship: ROLLBACK_VOLUME_UNTOUCHED,
    }),
    entry({
      entryId: "keycloak-runtime-data",
      kind: "keycloak-data",
      sourceIdentity: "volume:enterprise_keycloak_data#runtime-data",
      classification: "PRESERVE",
      backupMethod: "tar copy of enterprise_keycloak_data contents + pg_dump custom of keycloak DB",
      restoreMethod: "extract into gf-keycloak data dir backed by greenfield_keycloak_data; DB covered by postgres-keycloak",
      target: { kind: "volume", ref: "greenfield_keycloak_data" },
      ownership: "gf-keycloak container user",
      mode: "copy-once at cutover while brownfield keycloak stays quiesced",
      verificationMethod: "file-count+sha256 tree digest vs source volume",
      rollbackRelationship: ROLLBACK_VOLUME_UNTOUCHED,
    }),
  );

  if (includeRedisState === true) {
    collected.push(
      entry({
        entryId: "redis-data",
        kind: "redis-data",
        sourceIdentity: "volume:enterprise_redis_data",
        classification: "PRESERVE_IF_STATEFUL",
        backupMethod: "RDB copy while replica-quiesced (SAVE then copy dump.rdb)",
        restoreMethod: "stage dump.rdb into gf-redis data dir before first start",
        target: { kind: "volume", ref: "greenfield_redis_data" },
        ownership: "gf-redis container user",
        mode: "included only when includeRedisState=true and manifest classifies the volume stateful",
        verificationMethod: "redis dbsize+sample-key-type fingerprint",
        rollbackRelationship: ROLLBACK_VOLUME_UNTOUCHED,
      }),
    );
  }

  for (const project of projects) {
    collected.push(appSourceTreeEntry(project));
  }

  collected.push(
    entry({
      entryId: "control-center-state",
      kind: "control-center-state",
      sourceIdentity: `tree:${STATE_TREE_KEY}`,
      classification: "PRESERVE",
      backupMethod: "rsync-style archive of projects-portal state tree (916K)",
      restoreMethod: "extract into gf-control-center bind /var/www/project-state",
      target: { kind: "bind", ref: "gf-control-center:/var/www/project-state" },
      ownership: "uid 1000 / gid 1000 (platform_infrastructure)",
      mode: "restore while single-writer state adapter is quiesced",
      verificationMethod: "per-file sha256 + mode",
      rollbackRelationship: ROLLBACK_TREE_UNTOUCHED,
    }),
    entry({
      entryId: "secret-manager-store",
      kind: "secret-manager-store",
      sourceIdentity: `tree:${SECRETS_TREE_KEY}`,
      classification: "OBSERVE",
      backupMethod: "metadata/digest inventory only; secret values never read or copied here",
      restoreMethod: "handled-by:greenfield-secret-projection",
      target: { kind: "bind", ref: "deferred:greenfield-secret-projection" },
      ownership: "root:platform_infrastructure 0600 (unchanged)",
      mode: "excluded from state projection; exclusion note emitted for audit trail",
      verificationMethod: "sha256 baseline parity (delegated to greenfield-secret-projection)",
      rollbackRelationship: ROLLBACK_TREE_UNTOUCHED,
    }),
    entry({
      entryId: "backup-families",
      kind: "backup-family",
      sourceIdentity: `tree:${BACKUPS_TREE_KEY}${backupsFamilies === null ? "" : ` (${backupsFamilies} families)`}`,
      classification: "PRESERVE",
      backupMethod: "none new; existing scheduler keeps writing families in place",
      restoreMethod: "none (in-place, greenfield reads same immutable archive root)",
      target: { kind: "bind", ref: SHARED_ARCHIVE_ROOT_REF },
      ownership: "root:platform_infrastructure (shared read-only archive root)",
      mode: "NOT projected into greenfield runtime; shared-read-only-archive-root",
      verificationMethod: "sha256sum -c per published artifact (.sha256 sidecars)",
      rollbackRelationship: "shared-immutable-archive-no-mutation",
    }),
    entry({
      entryId: "unclassified-writable-layers",
      kind: "writable-layer",
      sourceIdentity: `docker-anonymous-volumes:${anonymousLabel}`,
      classification: "OBSERVE",
      backupMethod: "none (observe-only until individually classified)",
      restoreMethod: "requires explicit manifest classification before restore",
      target: { kind: "bind", ref: "quarantine:unclassified-writable-layers" },
      ownership: "n/a (unclassified)",
      mode: "no anonymous/writable-layer volume is destroyed or reused until individually classified; projection refuses unknown volumes",
      verificationMethod: "docker volume inventory diff before/after projection (zero mutations)",
      rollbackRelationship: "n/a (observe-only)",
    }),
  );

  const entries = collected.sort((a, b) => (a.entryId < b.entryId ? -1 : a.entryId > b.entryId ? 1 : 0));
  const writersCoveredByFinalSync = finalSyncWriterRegistry().map((writer) => writer.writerId);

  const plan = {
    schema: GREENFIELD_STATE_PROJECTION_SCHEMA,
    ...(typeof manifest.manifestSha256 === "string" && manifest.manifestSha256.length > 0
      ? { generatedFromManifestSha256: manifest.manifestSha256 }
      : {}),
    entries,
    writersCoveredByFinalSync,
  };
  return deepFreeze(plan);
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return Object.freeze(value);
}

function sortCanonical(value) {
  if (Array.isArray(value)) {
    return value.map(sortCanonical);
  }
  if (value && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortCanonical(value[key]);
    }
    return sorted;
  }
  return value;
}

export function serializeProjectionPlan(plan) {
  return JSON.stringify(sortCanonical(plan), null, 2);
}

export function validateStateProjectionPlan(plan) {
  const violations = [];
  if (!plan || typeof plan !== "object" || Array.isArray(plan)) {
    return ["plan:must-be-object"];
  }
  if (plan.schema !== GREENFIELD_STATE_PROJECTION_SCHEMA) {
    violations.push("plan:schema:mismatch");
  }
  if (!Array.isArray(plan.entries)) {
    violations.push("plan:entries:must-be-array");
    return violations;
  }

  const seenEntryIds = new Set();
  let previousEntryId = null;
  for (const candidate of plan.entries) {
    if (!candidate || typeof candidate !== "object") {
      violations.push("entry:unknown:must-be-object");
      continue;
    }
    const id = typeof candidate.entryId === "string" && candidate.entryId.length > 0
      ? candidate.entryId
      : "unknown";

    if (seenEntryIds.has(id)) {
      violations.push(`entry:${id}:duplicate-entry-id`);
    }
    seenEntryIds.add(id);

    if (previousEntryId !== null && id < previousEntryId) {
      violations.push(`plan:entries:not-sorted-at:${id}`);
    }
    previousEntryId = id;

    for (const field of REQUIRED_ENTRY_FIELDS) {
      if (candidate[field] === undefined || candidate[field] === null || candidate[field] === "") {
        violations.push(`entry:${id}:missing-field:${field}`);
      }
    }
    if (!ENTRY_KINDS.includes(candidate.kind)) {
      violations.push(`entry:${id}:kind:invalid`);
    }
    if (!CLASSIFICATIONS.includes(candidate.classification)) {
      violations.push(`entry:${id}:classification:invalid`);
    }

    const target = candidate.target;
    if (!target || typeof target !== "object") {
      violations.push(`entry:${id}:target:missing`);
      continue;
    }
    if (!TARGET_KINDS.includes(target.kind)) {
      violations.push(`entry:${id}:target.kind:invalid`);
    }
    if (typeof target.ref !== "string" || target.ref.length === 0) {
      violations.push(`entry:${id}:target.ref:missing`);
      continue;
    }
    if (isBrownfieldOwnedPhysicalName(target.ref)) {
      violations.push(`entry:${id}:target.ref:brownfield-owned`);
    }
    if (target.kind === "volume" && !target.ref.startsWith("greenfield_")) {
      violations.push(`entry:${id}:target.ref:not-greenfield-volume`);
    }
  }
  return violations;
}

export function finalSyncWriterRegistry() {
  const registry = [
    {
      writerId: "postgres-stexor",
      steps: [
        "quiesce: pause stexor app writers (php-stexor pool + worker-jobs touching stexor schema); record pg WAL LSN marker",
        "capture: pg_dump --format=custom database stexor from enterprise_postgres_data",
        "verify: postgres row-count+checksum fingerprint matches pre-quiesce baseline (stexor)",
      ],
    },
    {
      writerId: "postgres-keycloak",
      steps: [
        "quiesce: disable enterprise-keycloak realm admin/token writes; record pg WAL LSN marker",
        "capture: pg_dump --format=custom database keycloak from enterprise_postgres_data",
        "verify: postgres row-count+checksum fingerprint matches pre-quiesce baseline (keycloak)",
      ],
    },
    {
      writerId: "mariadb",
      steps: [
        "quiesce: pause php-mariadb consumer writers; FLUSH TABLES WITH READ LOCK and record binlog position",
        "capture: mariadb-dump --single-transaction --all user schemas | gzip > mariadb-all snapshot",
        "verify: mariadb schema/table-count+fingerprint vs source",
      ],
    },
    {
      writerId: "minio",
      steps: [
        "quiesce: freeze bucket writes (mc admin service freeze or app-level S3 pause)",
        "capture: mc mirror enterprise_minio_data to staging tree then tar the staging tree",
        "verify: bucket/object-count/size/checksum vs source",
      ],
    },
    {
      writerId: "app-bind-trees",
      steps: [
        "quiesce: stop project file writers (php-fpm pools + node workers) across every src project",
        "capture: rsync-style archive of /home/platform_infrastructure/src/* per project into staged trees",
        "verify: recursive tree digest + ownership/mode parity per project",
      ],
    },
    {
      writerId: "control-center-state",
      steps: [
        "quiesce: pause single-writer state adapter (no JSONL appends, atomic-write lock held)",
        "capture: rsync-style archive of projects-portal/state tree",
        "verify: per-file sha256 + mode parity",
      ],
    },
  ];
  return deepFreeze(registry.map((writer) => ({ writerId: writer.writerId, steps: [...writer.steps] })));
}
