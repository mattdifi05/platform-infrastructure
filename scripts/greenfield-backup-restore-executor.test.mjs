import assert from "node:assert/strict";
import test from "node:test";
import {
  SCHEMA,
  CAPTURE_CONTRACTS,
  BROWNFIELD_PRE_CAPTURE_CONTRACTS,
  BROWNFIELD_POSTGRES_CONTAINER,
  BROWNFIELD_MARIADB_CONTAINER,
  BROWNFIELD_MINIO_CONTAINER,
  buildCapturePlan,
  buildRestorePlan,
  buildOwnershipNormalizationSql,
  buildOwnershipNormalizationCommand,
  compareFingerprints,
  dockerAvailability,
  executeCaptureStep,
  executeRestoreStep,
} from "./greenfield-backup-restore-executor.mjs";

const ALL_FAMILIES = Object.freeze([
  "postgres-stexor",
  "postgres-keycloak",
  "mariadb",
  "minio",
  "nats-data",
  "app-bind-trees",
  "control-center-state",
]);

test("capture contracts cover every family against greenfield containers", () => {
  assert.deepEqual(Object.keys(CAPTURE_CONTRACTS).sort(), [...ALL_FAMILIES].sort());
  assert.equal(CAPTURE_CONTRACTS["postgres-stexor"].container, "gf-postgres");
  assert.match(CAPTURE_CONTRACTS["postgres-stexor"].commands[0], /pg_dump --format=custom/);
  assert.equal(CAPTURE_CONTRACTS["postgres-keycloak"].database, "keycloak");
  assert.match(CAPTURE_CONTRACTS["postgres-keycloak"].commands[0], /-d keycloak/);
  assert.equal(CAPTURE_CONTRACTS.mariadb.container, "gf-mariadb");
  assert.match(CAPTURE_CONTRACTS.mariadb.commands[0], /mariadb-dump --single-transaction/);
  assert.match(CAPTURE_CONTRACTS.mariadb.commands[0], /\/run\/secrets\/mariadb_root_password/);
  assert.ok(!/\-p['"\s]*\$?\{?[A-Za-z_]*PASSWORD/.test(CAPTURE_CONTRACTS.mariadb.commands[0]), "no inline password argument");
  assert.equal(CAPTURE_CONTRACTS.minio.container, "gf-minio");
});

test("capture plan is deterministic and ordered", () => {
  const a = buildCapturePlan({ families: ALL_FAMILIES, outputRoot: "/tmp/x", runId: "run-1" });
  const b = buildCapturePlan({ families: ALL_FAMILIES, outputRoot: "/tmp/x", runId: "run-1" });
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  assert.deepEqual(a.entries.map((entry) => entry.family), [...ALL_FAMILIES].sort());
  for (const entry of a.entries) {
    if (entry.family.startsWith("postgres-")) {
      assert.equal(entry.container, "gf-postgres");
      assert.equal(entry.verification.kind, "row-count-fingerprint");
      assert.equal(entry.verification.tablesMinimumPerDb, 5);
    }
    if (entry.family === "nats-data") {
      assert.equal(entry.container, "gf-nats");
      assert.equal(entry.verification.kind, "nats-stream-fingerprint");
    }
    for (const artifact of entry.artifacts) {
      assert.equal(typeof artifact.pattern, "string");
      assert.ok(artifact.pattern.length > 0);
      assert.ok(artifact.sidecars.includes("sha256"));
    }
  }
});

test("capture plan rejects unknown families", () => {
  assert.throws(() => buildCapturePlan({ families: ["legacy-volume"], outputRoot: "/tmp", runId: "r" }), TypeError);
});

test("restore plan targets only greenfield resources", () => {
  const capture = buildCapturePlan({ families: ALL_FAMILIES, outputRoot: "/tmp/x", runId: "run-2" });
  const restore = buildRestorePlan({ captureReceipt: capture });
  const serialized = JSON.stringify(restore);
  assert.ok(!serialized.includes("enterprise_"), serialized);
  assert.ok(!serialized.includes("platform_infra_vps"));
  const pgRestore = restore.entries.find((entry) => entry.family === "postgres-stexor");
  assert.match(pgRestore.commands[0], /pg_restore --clean --if-exists/);
  assert.equal(pgRestore.targetKind, "database");
  assert.equal(restore.entries.find((entry) => entry.family === "minio").targetKind, "volume");
  assert.equal(restore.entries.find((entry) => entry.family === "control-center-state").targetKind, "bind");
  assert.throws(() => buildRestorePlan({ captureReceipt: { kind: "bogus" } }), TypeError);
});

test("restore plan normalizes object ownership for every postgres family", () => {
  const capture = buildCapturePlan({ families: ALL_FAMILIES, outputRoot: "/tmp/x", runId: "run-owner" });
  const restore = buildRestorePlan({ captureReceipt: capture });

  const keycloak = restore.entries.find((entry) => entry.family === "postgres-keycloak");
  const stexor = restore.entries.find((entry) => entry.family === "postgres-stexor");
  assert.equal(keycloak.ownerRole, "keycloak");
  assert.equal(stexor.ownerRole, "postgres");

  for (const [entry, database, expectedRole] of [
    [keycloak, "keycloak", "keycloak"],
    [stexor, "stexor", "postgres"],
  ]) {
    assert.equal(entry.commands.length, 2, `${entry.family} must pair pg_restore with ownership normalization`);
    assert.match(entry.commands[0], /pg_restore --clean --if-exists --no-owner --no-acl/);
    const normalization = entry.commands[1];
    assert.equal(normalization, buildOwnershipNormalizationCommand({ database, ownerRole: expectedRole }));
    assert.match(normalization, /^docker exec gf-postgres psql -U postgres -d /);
    assert.ok(normalization.includes(`-d ${database} `), normalization);
    assert.ok(normalization.includes(`OWNER TO ${expectedRole}`), normalization);
    assert.doesNotMatch(normalization, /\{ownerRole\}/, "owner role must be resolved at plan time");
  }

  for (const family of ["mariadb", "minio", "nats-data", "app-bind-trees", "control-center-state"]) {
    const entry = restore.entries.find((candidate) => candidate.family === family);
    assert.equal(entry.ownerRole, null, `${family} carries no owner metadata`);
    assert.ok(!entry.commands.some((command) => command.includes("OWNER TO")), family);
  }
});

test("ownership normalization SQL is a DO block over non-system schemas", () => {
  const sql = buildOwnershipNormalizationSql({ ownerRole: "keycloak" });
  assert.match(sql, /^DO \$\$/);
  assert.match(sql, /\bEND \$\$\;/);
  assert.match(sql, /FROM pg_class c\b/);
  assert.match(sql, /FROM pg_proc p\b/);
  assert.match(sql, /relkind IN \('r', 'p', 'v', 'm', 'f', 'S'\)/);
  assert.match(sql, /n\.nspname NOT IN \('pg_catalog', 'information_schema'\)/);
  assert.match(sql, /n\.nspname NOT LIKE 'pg\\_%'/);
  assert.match(sql, /ALTER SEQUENCE %I\.%I OWNER TO keycloak/);
  assert.match(sql, /ALTER TABLE %I\.%I OWNER TO keycloak/);
  assert.match(sql, /ALTER FUNCTION %I\.%I\(%s\) OWNER TO keycloak/);

  // Role and database identifiers are validated before interpolation.
  assert.throws(() => buildOwnershipNormalizationSql({ ownerRole: "role; DROP SCHEMA x" }), TypeError);
  assert.throws(() => buildOwnershipNormalizationSql({ ownerRole: "" }), TypeError);
  assert.throws(() => buildOwnershipNormalizationCommand({ database: "keycloak; DROP SCHEMA x", ownerRole: "keycloak" }), TypeError);

  const command = buildOwnershipNormalizationCommand({ database: "keycloak", ownerRole: "keycloak" });
  assert.match(command, /^docker exec gf-postgres psql -U postgres -d keycloak -c "/);
  assert.match(command, /"\s*$/, "SQL body must stay inside one double-quoted argument");
  assert.ok(command.includes("DO \\$\\$"), command.slice(0, 120));
  // Shell safety: no unescaped $ survives inside the quoted SQL body.
  assert.doesNotMatch(command, /[^\\]\$/, command);
});

function fingerprint(family, items) {
  return { family, items };
}

test("compareFingerprints classifies MATCH, DELTA and FAIL", () => {
  const pre = fingerprint("postgres-stexor", [
    { id: "public.users", count: 10 },
    { id: "public.sessions", count: 4 },
  ]);
  assert.equal(compareFingerprints({ pre, post: fingerprint("postgres-stexor", [
    { id: "public.users", count: 10 },
    { id: "public.sessions", count: 4 },
  ]) }).status, "MATCH");
  assert.equal(compareFingerprints({ pre, post: fingerprint("postgres-stexor", [
    { id: "public.users", count: 11 },
    { id: "public.sessions", count: 4 },
  ]) }).status, "DELTA");
  assert.equal(compareFingerprints({ pre, post: fingerprint("postgres-stexor", [
    { id: "public.users", count: 11 },
  ]) }).status, "FAIL");
  assert.equal(compareFingerprints({ pre, post: fingerprint("mariadb", pre.items) }).status, "FAIL");
});

test("executor steps fail closed without docker", () => {
  const availability = dockerAvailability({ dockerCheck: () => ({ available: false, reason: "none" }) });
  assert.equal(availability.available, false);
  assert.throws(
    () => executeCaptureStep({ command: "true" }, { dockerCheck: () => ({ available: false }) }),
    /greenfield executor requires Docker/,
  );
  assert.throws(
    () => executeRestoreStep({ command: "true" }, { dockerCheck: () => ({ available: false }) }),
    /greenfield executor requires Docker/,
  );
});

test("executor receipts carry only whitelisted keys and reject failures", () => {
  const receipt = executeCaptureStep(
    { command: "true", family: "minio", runId: "run-3", artifactNames: ["minio-data-x.tar.gz"] },
    { dockerCheck: () => ({ available: true }) },
  );
  assert.deepEqual(Object.keys(receipt).sort(), ["artifactNames", "durationMs", "exitCode", "family", "kind", "runId", "schema"]);
  assert.ok(!("stdout" in receipt) && !("stderr" in receipt));
  let failure;
  try {
    executeRestoreStep({ command: "exit 7", family: "mariadb" }, { dockerCheck: () => ({ available: true }) });
    assert.fail("expected restore step failure");
  } catch (error) {
    failure = error;
  }
  assert.equal(failure.exitCode, 7);
});

test("brownfield BACKUP_PRE contracts target frozen sources without mutation", () => {
  assert.deepEqual(Object.keys(BROWNFIELD_PRE_CAPTURE_CONTRACTS).sort(), [
    "mariadb", "minio", "postgres-keycloak", "postgres-stexor",
  ]);
  assert.equal(BROWNFIELD_POSTGRES_CONTAINER, "enterprise-postgres");
  assert.equal(BROWNFIELD_MARIADB_CONTAINER, "mariadb");
  assert.equal(BROWNFIELD_MINIO_CONTAINER, "enterprise-minio");

  const pre = buildCapturePlan({
    families: Object.keys(BROWNFIELD_PRE_CAPTURE_CONTRACTS),
    outputRoot: "/tmp/pre",
    runId: "run-pre",
    contracts: BROWNFIELD_PRE_CAPTURE_CONTRACTS,
  });
  const serialized = JSON.stringify(pre);
  assert.match(serialized, /enterprise-postgres/);
  assert.match(serialized, /pg_dump --format=custom/);
  assert.match(serialized, /mariadb-dump --single-transaction/);
  for (const entry of pre.entries) {
    for (const command of entry.commands) {
      // Capture commands must only read from the source containers and write
      // to stdout redirections; no exec with write flags into the sources.
      assert.ok(!command.includes("docker cp"), command);
      assert.ok(!command.includes(" rm "), command);
    }
  }

  // Greenfield capture contracts stay untouched by the parameter.
  const gf = buildCapturePlan({ families: ALL_FAMILIES, outputRoot: "/tmp/x", runId: "r" });
  assert.equal(JSON.parse(JSON.stringify(gf.entries[0])).family, ALL_FAMILIES.slice().sort()[0]);
});
