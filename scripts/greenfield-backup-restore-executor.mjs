// Greenfield backup/restore executor contracts for V1 LOCAL_PRIVATE GREENFIELD.
// Planning + fingerprint comparison is pure; execution paths fail closed
// without Docker. Receipts never carry raw command output (secret hygiene).

import { execFileSync } from "node:child_process";
import { assertNoSecretMaterialization } from "./greenfield-secret-projection.mjs";

export const SCHEMA = "platform.greenfield-backup-restore-executor/v1";

export const GREENFIELD_POSTGRES_CONTAINER = "gf-postgres";
export const GREENFIELD_MARIADB_CONTAINER = "gf-mariadb";
export const GREENFIELD_MINIO_CONTAINER = "gf-minio";
export const GREENFIELD_NATS_CONTAINER = "gf-nats";

// Frozen brownfield source containers for BACKUP_PRE capture. These names are
// read-only inputs for pre-cutover capture; nothing in this module ever
// writes to or mutates them.
export const BROWNFIELD_POSTGRES_CONTAINER = "enterprise-postgres";
export const BROWNFIELD_MARIADB_CONTAINER = "mariadb";
export const BROWNFIELD_MINIO_CONTAINER = "enterprise-minio";

const TIMESTAMP_PATTERN = "[0-9]{8}-[0-9]{6}";

export const CAPTURE_CONTRACTS = Object.freeze({
  "app-bind-trees": Object.freeze({
    container: null,
    commands: [
      "tar czf {outputDir}/app-state-{tree}-{ts}.tar.gz -C {treeRoot} .",
      "find {treeRoot} -type f -print0 | xargs -0 sha256sum > {outputDir}/tree-manifest.json",
    ],
    artifacts: ["app-state-{tree}-{ts}.tar.gz", "tree-manifest.json"],
  }),
  mariadb: Object.freeze({
    container: GREENFIELD_MARIADB_CONTAINER,
    commands: [
      "docker exec {container} sh -c 'export MYSQL_PWD=\"$(cat /run/secrets/mariadb_root_password)\"; mariadb-dump --single-transaction --routines --events --triggers --all-databases | gzip -9' > {outputDir}/mariadb-all-{ts}.sql.gz",
    ],
    artifacts: ["mariadb-all-{ts}.sql.gz"],
  }),
  minio: Object.freeze({
    container: GREENFIELD_MINIO_CONTAINER,
    commands: [
      "docker exec {container} tar czf - -C /data . > {outputDir}/minio-data-{ts}.tar.gz",
    ],
    artifacts: ["minio-data-{ts}.tar.gz"],
  }),
  "nats-data": Object.freeze({
    container: GREENFIELD_NATS_CONTAINER,
    commands: [
      "docker exec {container} tar czf - -C /data . > {outputDir}/nats-data-{ts}.tar.gz",
    ],
    artifacts: ["nats-data-{ts}.tar.gz"],
  }),
  "postgres-keycloak": Object.freeze({
    container: GREENFIELD_POSTGRES_CONTAINER,
    database: "keycloak",
    commands: [
      "docker exec {container} pg_dump --format=custom --no-owner --no-acl -U postgres -d keycloak > {outputDir}/keycloak-{ts}.dump",
    ],
    artifacts: ["keycloak-{ts}.dump"],
  }),
  "postgres-stexor": Object.freeze({
    container: GREENFIELD_POSTGRES_CONTAINER,
    database: "stexor",
    commands: [
      "docker exec {container} pg_dump --format=custom --no-owner --no-acl -U postgres -d stexor > {outputDir}/stexor-{ts}.dump",
    ],
    artifacts: ["stexor-{ts}.dump"],
  }),
  "control-center-state": Object.freeze({
    container: null,
    commands: [
      "tar czf {outputDir}/cc-state-{ts}.tar.gz -C {stateRoot} .",
      "find {stateRoot} -type f -print0 | xargs -0 sha256sum > {outputDir}/cc-tree-manifest.json",
    ],
    artifacts: ["cc-state-{ts}.tar.gz", "cc-tree-manifest.json"],
  }),
});

// Pre-cutover capture contracts executed against the frozen brownfield
// runtime (BACKUP_PRE transaction state). Same artifact naming and sidecar
// conventions as the platform backup families so the existing verification
// and retention tooling accepts them.
export const BROWNFIELD_PRE_CAPTURE_CONTRACTS = Object.freeze({
  "postgres-keycloak": Object.freeze({
    container: BROWNFIELD_POSTGRES_CONTAINER,
    database: "keycloak",
    commands: [
      "docker exec {container} pg_dump --format=custom --no-owner --no-acl -U postgres -d keycloak > {outputDir}/keycloak-{ts}.dump",
    ],
    artifacts: ["keycloak-{ts}.dump"],
  }),
  "postgres-stexor": Object.freeze({
    container: BROWNFIELD_POSTGRES_CONTAINER,
    database: "stexor",
    commands: [
      "docker exec {container} pg_dump --format=custom --no-owner --no-acl -U postgres -d stexor > {outputDir}/stexor-{ts}.dump",
    ],
    artifacts: ["stexor-{ts}.dump"],
  }),
  mariadb: Object.freeze({
    container: BROWNFIELD_MARIADB_CONTAINER,
    commands: [
      "docker exec {container} sh -c 'export MYSQL_PWD=\"$(cat /run/secrets/mariadb_root_password)\"; mariadb-dump --single-transaction --routines --events --triggers --all-databases | gzip -9' > {outputDir}/mariadb-all-{ts}.sql.gz",
    ],
    artifacts: ["mariadb-all-{ts}.sql.gz"],
  }),
  minio: Object.freeze({
    container: BROWNFIELD_MINIO_CONTAINER,
    commands: [
      "docker exec {container} tar czf - -C /data . > {outputDir}/minio-data-{ts}.tar.gz",
    ],
    artifacts: ["minio-data-{ts}.tar.gz"],
  }),
});

const VERIFICATION_CONTRACTS = Object.freeze({
  postgres: Object.freeze({ kind: "row-count-fingerprint", tablesMinimumPerDb: 5 }),
  mariadb: Object.freeze({ kind: "schema-table-fingerprint", minSchemas: 2 }),
  minio: Object.freeze({ kind: "object-count-checksum", objectCountMinimum: 1 }),
  "nats-data": Object.freeze({ kind: "nats-stream-fingerprint", streamCountMinimum: 0 }),
  tree: Object.freeze({ kind: "tree-digest", fileCountMinimum: 1 }),
});

function verificationForFamily(family) {
  if (family.startsWith("postgres-")) {
    return VERIFICATION_CONTRACTS.postgres;
  }
  if (family === "app-bind-trees" || family === "control-center-state") {
    return VERIFICATION_CONTRACTS.tree;
  }
  return VERIFICATION_CONTRACTS[family] ?? null;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const key of Object.keys(value)) {
      deepFreeze(value[key]);
    }
    Object.freeze(value);
  }
  return value;
}

export function buildCapturePlan({ families, outputRoot, runId, contracts = CAPTURE_CONTRACTS }) {
  const unknown = families.filter((family) => !Object.hasOwn(contracts, family));
  if (unknown.length > 0) {
    throw new TypeError(`Unknown capture families: ${unknown.join(", ")}`);
  }
  const entries = [...families].sort().map((family) => {
    const contract = contracts[family];
    return {
      family,
      runId,
      container: contract.container,
      outputRoot,
      commands: [...contract.commands],
      artifacts: contract.artifacts.map((name) => ({
        name,
        pattern: name.replaceAll("{ts}", TIMESTAMP_PATTERN).replaceAll("{tree}", "[a-z0-9-]+"),
        sidecars: ["sha256"],
      })),
      verification: verificationForFamily(family),
    };
  });
  return deepFreeze({ schema: SCHEMA, kind: "capture", outputRoot, runId, entries });
}

// Ownership normalization template for greenfield restores. pg_restore runs
// with --no-owner, so restored objects would otherwise be owned by the
// postgres superuser while the workload (e.g. keycloak) connects as a
// non-superuser role and fails with "permission denied for table
// databasechangelog". The DO block reassigns ownership of every table,
// sequence, view, materialized view, foreign table and function in all
// non-system schemas to the contract's ownerRole.
const OWNERSHIP_NORMALIZATION_SQL_TEMPLATE = Object.freeze(`
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT n.nspname AS schema_name, c.relname AS object_name, c.relkind
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_%'
  LOOP
    IF r.relkind = 'S' THEN
      EXECUTE format('ALTER SEQUENCE %I.%I OWNER TO {ownerRole}', r.schema_name, r.object_name);
    ELSE
      EXECUTE format('ALTER TABLE %I.%I OWNER TO {ownerRole}', r.schema_name, r.object_name);
    END IF;
  END LOOP;
  FOR r IN
    SELECT n.nspname AS schema_name, p.proname AS function_name,
           pg_get_function_identity_arguments(p.oid) AS identity_args
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE p.prokind = 'f'
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_%'
  LOOP
    EXECUTE format('ALTER FUNCTION %I.%I(%s) OWNER TO {ownerRole}', r.schema_name, r.function_name, r.identity_args);
  END LOOP;
END $$;
`);

const IDENTIFIER_PATTERN = /^[a-z_][a-z0-9_]{0,62}$/;

export function buildOwnershipNormalizationSql({ ownerRole }) {
  if (typeof ownerRole !== "string" || !IDENTIFIER_PATTERN.test(ownerRole)) {
    throw new TypeError(`invalid owner role identifier: ${ownerRole}`);
  }
  return OWNERSHIP_NORMALIZATION_SQL_TEMPLATE.trim().replaceAll("{ownerRole}", ownerRole);
}

// The normalization command is executed via `sh -c`, so the SQL body is shell
// double-quoted: every `$`, backtick, backslash and double quote must be
// escaped or the shell would expand e.g. $$ dollar-quoting into a PID.
function shellDoubleQuoted(value) {
  return `"${value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("$", "\\$")
    .replaceAll("`", "\\`")}"`;
}

export function buildOwnershipNormalizationCommand({ database, ownerRole }) {
  if (typeof database !== "string" || !IDENTIFIER_PATTERN.test(database)) {
    throw new TypeError(`invalid database identifier: ${database}`);
  }
  const sql = buildOwnershipNormalizationSql({ ownerRole }).replace(/\s+/g, " ").trim();
  return `docker exec ${GREENFIELD_POSTGRES_CONTAINER} psql -U postgres -d ${database} -c ${shellDoubleQuoted(sql)}`;
}

const RESTORE_COMMANDS = Object.freeze({
  "nats-data": Object.freeze({
    commands: [
      "docker exec gf-nats sh -c 'find /data -mindepth 1 -delete'",
      "cat {artifactPath} | docker exec -i gf-nats tar xzf - -C /data",
    ],
  }),
  mariadb: Object.freeze({
    commands: [
      "gunzip -c {artifactPath} | docker exec -i gf-mariadb sh -c 'mariadb -u root -p\"$(cat /run/secrets/mariadb_root_password)\"'",
    ],
  }),
  minio: Object.freeze({
    commands: [
      "docker exec gf-minio sh -c 'find /data -mindepth 1 -delete'",
      "cat {artifactPath} | docker exec -i gf-minio tar xzf - -C /data",
    ],
  }),
  tree: Object.freeze({
    commands: [
      "mkdir -p {targetPath} && tar xzf {artifactPath} -C {targetPath} --preserve-permissions",
    ],
  }),
  "postgres-keycloak": Object.freeze({
    database: "keycloak",
    // Keycloak (KC_DB_USER=keycloak) connects as this non-superuser role; the
    // restore must hand ownership of every object back to it.
    ownerRole: "keycloak",
    commands: [
      "docker exec -i gf-postgres pg_restore --clean --if-exists --no-owner --no-acl -U postgres -d keycloak < {artifactPath}",
    ],
  }),
  "postgres-stexor": Object.freeze({
    database: "stexor",
    // stexor may run as the superuser today; normalize to postgres so the
    // plan stays explicit even when no dedicated app principal exists yet.
    ownerRole: "postgres",
    commands: [
      `docker exec gf-postgres sh -ec 'exists="$(psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname = '\\''stexor'\\''")" || { echo "stexor database probe failed" >&2; exit 1; } ; case "$exists" in 1) ;; "") createdb -U postgres -O postgres stexor ;; *) echo "unexpected stexor database probe result" >&2; exit 1 ;; esac'`,
      "docker exec -i gf-postgres pg_restore --clean --if-exists --no-owner --no-acl -U postgres -d stexor < {artifactPath}",
    ],
  }),
});

function restoreFamilyKey(family) {
  if (Object.hasOwn(RESTORE_COMMANDS, family)) {
    return family;
  }
  if (family === "app-bind-trees" || family === "control-center-state") {
    return "tree";
  }
  throw new TypeError(`No restore contract for capture family: ${family}`);
}

export function buildRestorePlan({ captureReceipt }) {
  if (!captureReceipt || captureReceipt.kind !== "capture") {
    throw new TypeError("buildRestorePlan requires a capture plan receipt");
  }
  const entries = captureReceipt.entries.map((entry) => {
    const contract = RESTORE_COMMANDS[restoreFamilyKey(entry.family)];
    const commands = [...contract.commands];
    if (contract.ownerRole) {
      commands.push(
        buildOwnershipNormalizationCommand({ database: contract.database, ownerRole: contract.ownerRole }),
      );
    }
    return {
      family: entry.family,
      runId: captureReceipt.runId,
      targetKind: entry.family.startsWith("postgres-")
        ? "database"
        : (entry.family === "app-bind-trees" || entry.family === "control-center-state" ? "bind" : "volume"),
      ownerRole: contract.ownerRole ?? null,
      commands,
      artifacts: entry.artifacts.map((artifact) => artifact.name),
      verification: entry.verification,
    };
  });
  return deepFreeze({ schema: SCHEMA, kind: "restore", runId: captureReceipt.runId, entries });
}

export function compareFingerprints({ pre, post }) {
  if (!pre || !post || pre.family !== post.family) {
    return { status: "FAIL", deltas: [], reason: "fingerprint-family-mismatch" };
  }
  const postById = new Map(post.items.map((item) => [item.id, item]));
  const deltas = [];
  let structural = false;
  for (const item of pre.items) {
    const after = postById.get(item.id);
    if (!after) {
      deltas.push({ id: item.id, before: summarizeItem(item), after: null });
      structural = true;
      continue;
    }
    if (!itemEquals(item, after)) {
      deltas.push({ id: item.id, before: summarizeItem(item), after: summarizeItem(after) });
    }
  }
  for (const item of post.items) {
    if (!pre.items.some((candidate) => candidate.id === item.id)) {
      deltas.push({ id: item.id, before: null, after: summarizeItem(item) });
      structural = true;
    }
  }
  const status = deltas.length === 0 ? "MATCH" : (structural ? "FAIL" : "DELTA");
  return { status, deltas };
}

function itemEquals(a, b) {
  return a.count === b.count && a.digest === b.digest && a.size === b.size;
}

function summarizeItem(item) {
  const summary = { id: item.id };
  if (item.count !== undefined) summary.count = item.count;
  if (item.digest !== undefined) summary.digest = item.digest;
  if (item.size !== undefined) summary.size = item.size;
  return summary;
}

const DOCKER_INFO_TIMEOUT_MS = 3000;

export function dockerAvailability(options = {}) {
  if (options.dockerCheck) {
    return options.dockerCheck();
  }
  try {
    execFileSync("docker", ["info", "--format", "{{.ServerVersion}}"], {
      timeout: DOCKER_INFO_TIMEOUT_MS,
      stdio: "ignore",
    });
    return { available: true };
  } catch (error) {
    return { available: false, reason: `docker unavailable: ${error.code ?? error.message}` };
  }
}

const RECEIPT_ALLOWED_KEYS = new Set(["schema", "kind", "family", "runId", "exitCode", "artifactNames", "durationMs"]);

export function executeCaptureStep(step, options = {}) {
  return executeStep("capture", step, options);
}

export function executeRestoreStep(step, options = {}) {
  return executeStep("restore", step, options);
}

function executeStep(kind, step, options = {}) {
  const availability = dockerAvailability(options);
  if (!availability.available) {
    throw new Error(
      "greenfield executor requires Docker (CI runner or live phase); offline matrix uses plan/compare primitives",
    );
  }
  if (!step || typeof step.command !== "string") {
    throw new TypeError("executeStep requires a resolved command string");
  }
  const startedAt = Date.now();
  let exitCode = 0;
  try {
    execFileSync("sh", ["-c", step.command], { stdio: "ignore", timeout: options.timeoutMs ?? 3_600_000 });
  } catch (error) {
    exitCode = error.status ?? 1;
  }
  const receipt = {
    schema: SCHEMA,
    kind,
    family: step.family ?? null,
    runId: step.runId ?? null,
    exitCode,
    artifactNames: Array.isArray(step.artifactNames) ? [...step.artifactNames] : [],
    durationMs: Date.now() - startedAt,
  };
  for (const key of Object.keys(receipt)) {
    if (!RECEIPT_ALLOWED_KEYS.has(key)) {
      throw new TypeError(`receipt key not allowed: ${key}`);
    }
  }
  assertNoSecretMaterialization(JSON.stringify(receipt));
  if (exitCode !== 0) {
    const failure = new Error(`greenfield ${kind} step failed with exit code ${exitCode}`);
    failure.exitCode = exitCode;
    throw failure;
  }
  return Object.freeze(receipt);
}
