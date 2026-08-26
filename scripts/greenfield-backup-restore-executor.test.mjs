import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
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
  assert.match(pgRestore.commands[0], /psql.*SELECT 1 FROM pg_database WHERE datname/);
  assert.match(pgRestore.commands[0], /createdb/);
  assert.match(pgRestore.commands[0], /stexor/);
  assert.match(pgRestore.commands[1], /pg_restore --clean --if-exists/);
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

  for (const [entry, database, expectedRole, expectedCommandCount] of [
    [keycloak, "keycloak", "keycloak", 2],
    [stexor, "stexor", "postgres", 3],
  ]) {
    assert.equal(entry.commands.length, expectedCommandCount, `${entry.family} must have ${expectedCommandCount} commands`);
    if (entry.family === "postgres-stexor") {
      assert.match(entry.commands[0], /psql.*SELECT 1 FROM pg_database/);
      assert.match(entry.commands[0], /createdb/);
      assert.match(entry.commands[1], /pg_restore --clean --if-exists --no-owner --no-acl/);
      const normalization = entry.commands[2];
    } else {
      assert.match(entry.commands[0], /pg_restore --clean --if-exists --no-owner --no-acl/);
      const normalization = entry.commands[1];
    }
    const normalization = entry.commands[entry.commands.length - 1];
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

test("postgres-stexor restore plan ordering: ensure-db, pg_restore, normalization", () => {
  const capture = buildCapturePlan({ families: ["postgres-stexor"], outputRoot: "/tmp/x", runId: "r" });
  const restore = buildRestorePlan({ captureReceipt: capture });
  const entry = restore.entries.find((e) => e.family === "postgres-stexor");
  assert.equal(entry.commands.length, 3, "stexor must have 3 commands");
  assert.match(entry.commands[0], /psql.*SELECT 1 FROM pg_database/);
  assert.match(entry.commands[0], /createdb/);
  assert.match(entry.commands[1], /pg_restore --clean --if-exists --no-owner --no-acl/);
  assert.match(entry.commands[2], /OWNER TO postgres/);
  assert.equal(entry.ownerRole, "postgres");
});

test("postgres-stexor ensure-db command is idempotent: probe then conditionally create", () => {
  const capture = buildCapturePlan({ families: ["postgres-stexor"], outputRoot: "/tmp/x", runId: "r" });
  const restore = buildRestorePlan({ captureReceipt: capture });
  const ensureDb = restore.entries.find((e) => e.family === "postgres-stexor").commands[0];
  // Must probe pg_database
  assert.match(ensureDb, /SELECT 1 FROM pg_database WHERE datname/);
  // Must use createdb (not CREATE DATABASE) for conditional creation
  assert.match(ensureDb, /createdb/);
  // Must NOT use unconditional CREATE DATABASE
  assert.doesNotMatch(ensureDb, /CREATE DATABASE(?!.*IF NOT EXISTS)/, "must not use unconditional CREATE DATABASE");
  // Must NOT use CREATE DATABASE IF NOT EXISTS (invalid PostgreSQL)
  assert.doesNotMatch(ensureDb, /CREATE DATABASE IF NOT EXISTS/);
  // Must NOT use DROP DATABASE
  assert.doesNotMatch(ensureDb, /DROP DATABASE/);
  // Must use case statement for fail-closed branching
  assert.match(ensureDb, /case/);
  assert.match(ensureDb, /unexpected.*probe.*result/);
  // Must have ON_ERROR_STOP for fail-closed probe
  assert.match(ensureDb, /ON_ERROR_STOP=1/);
});

test("postgres-stexor ensure-db does not create when database already exists", () => {
  const capture = buildCapturePlan({ families: ["postgres-stexor"], outputRoot: "/tmp/x", runId: "r" });
  const restore = buildRestorePlan({ captureReceipt: capture });
  const ensureDb = restore.entries.find((e) => e.family === "postgres-stexor").commands[0];
  // The case 1) branch must be empty (no-op when database exists)
  const caseMatch = ensureDb.match(/1\)\s*(.*?)\s*;;\s*""\)/s);
  assert.ok(caseMatch, "must have a case 1) branch for existing database");
  const existingBranch = caseMatch[1].trim();
  assert.equal(existingBranch, "", "existing database branch must be empty (no-op)");
});

// ---------------------------------------------------------------------------
// Deterministic behavioural tests for the stexor ensure-database command.
// These execute the INNER shell logic directly (no Docker, no root, no live
// database) by substituting fake `psql` and `createdb` executables on PATH.
// ---------------------------------------------------------------------------

function buildEnsureDbCommand(ensureDbFull) {
  const marker = "sh -ec ";
  const idx = ensureDbFull.indexOf(marker);
  assert.ok(idx !== -1, `ensure-db command must contain "${marker}"`);
  const afterMarker = ensureDbFull.slice(idx + marker.length);
  const firstQuote = afterMarker.indexOf("'");
  assert.ok(firstQuote !== -1, "ensure-db command must have opening single quote");
  const lastQuote = afterMarker.lastIndexOf("'");
  assert.ok(lastQuote > firstQuote, "ensure-db command must have closing single quote");
  return afterMarker.slice(firstQuote + 1, lastQuote);
}

function runEnsureDbWithFakes(innerLogic, control) {
  const psqlStdout = control?.psqlStdout ?? "";
  const psqlExitCode = control?.psqlExitCode ?? 0;
  const createdbExitCode = control?.createdbExitCode ?? 0;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "stexor-ensure-db-"));
  const binDir = path.join(tmpDir, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const createdbCalls = path.join(tmpDir, "CREATEDB_CALLS");
  // psql stdout and exit status are independent controls so the probe-failure
  // path exercises a REAL nonzero psql exit, not merely unexpected stdout.
  fs.writeFileSync(
    path.join(binDir, "psql"),
    `#!/bin/sh\nprintf '%s' '${psqlStdout}'\nexit ${psqlExitCode}\n`,
    { mode: 0o755 },
  );
  // createdb records ONE line per invocation so call count is exact.
  fs.writeFileSync(
    path.join(binDir, "createdb"),
    `#!/bin/sh\nprintf '%s\\n' "$*" >> '${createdbCalls}'\nexit ${createdbExitCode}\n`,
    { mode: 0o755 },
  );
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  let exitCode = 0;
  try {
    execFileSync("sh", ["-ec", innerLogic], { env, stdio: "ignore" });
  } catch (error) {
    exitCode = error.status ?? 1;
  }
  let createdbCallCount = 0;
  let createdbArgs = "";
  try {
    createdbArgs = fs.readFileSync(createdbCalls, "utf8");
    createdbCallCount = createdbArgs.split("\n").filter((line) => line.trim().length > 0).length;
  } catch {
    createdbCallCount = 0;
    createdbArgs = "";
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
  return { exitCode, createdbCallCount, createdbArgs };
}

function getStexorEnsureDbCommand() {
  const capture = buildCapturePlan({ families: ["postgres-stexor"], outputRoot: "/tmp/x", runId: "r" });
  const restore = buildRestorePlan({ captureReceipt: capture });
  return restore.entries.find((e) => e.family === "postgres-stexor").commands[0];
}

// Test 1: MISSING DATABASE path – probe returns "", createdb invoked EXACTLY once
test("ensure-db MISSING DATABASE: probe empty, createdb invoked exactly once with stexor owned by postgres", () => {
  const ensureDb = getStexorEnsureDbCommand();
  const inner = buildEnsureDbCommand(ensureDb);
  const result = runEnsureDbWithFakes(inner, { psqlStdout: "", psqlExitCode: 0 });
  assert.equal(result.exitCode, 0, "must exit 0 when database is missing");
  assert.equal(result.createdbCallCount, 1, "createdb must be invoked exactly once");
  assert.ok(result.createdbArgs.includes("stexor"), "createdb must include stexor as target");
  assert.ok(result.createdbArgs.includes("-U postgres"), "createdb must run as postgres user");
  assert.ok(result.createdbArgs.includes("-O postgres"), "createdb owner must be postgres");
});

// Test 2: EXISTING DATABASE path – probe returns "1", createdb not invoked
test("ensure-db EXISTING DATABASE: probe returns 1, createdb not invoked", () => {
  const ensureDb = getStexorEnsureDbCommand();
  const inner = buildEnsureDbCommand(ensureDb);
  const result = runEnsureDbWithFakes(inner, { psqlStdout: "1", psqlExitCode: 0 });
  assert.equal(result.exitCode, 0, "must exit 0 when database already exists");
  assert.equal(result.createdbCallCount, 0, "createdb must not be invoked");
});

// Test 3: PROBE FAILURE – psql exits nonzero (REAL failure), createdb not invoked
test("ensure-db PROBE FAILURE: psql exits nonzero, createdb not invoked", () => {
  const ensureDb = getStexorEnsureDbCommand();
  const inner = buildEnsureDbCommand(ensureDb);
  const result = runEnsureDbWithFakes(inner, { psqlStdout: "", psqlExitCode: 1 });
  assert.ok(result.exitCode !== 0, "must exit nonzero when probe fails");
  assert.equal(result.createdbCallCount, 0, "createdb must not be invoked on probe failure");
});

// Test 4: CREATE FAILURE – probe returns empty but createdb exits nonzero
test("ensure-db CREATE FAILURE: createdb invoked once but fails, command exits nonzero", () => {
  const ensureDb = getStexorEnsureDbCommand();
  const inner = buildEnsureDbCommand(ensureDb);
  const result = runEnsureDbWithFakes(inner, { psqlStdout: "", psqlExitCode: 0, createdbExitCode: 1 });
  assert.ok(result.exitCode !== 0, "must exit nonzero when createdb fails");
  assert.equal(result.createdbCallCount, 1, "createdb must be invoked exactly once (even though it fails)");
  assert.ok(result.createdbArgs.includes("stexor"), "createdb must target stexor");
});

// Test 5: UNEXPECTED PROBE OUTPUT – psql outputs "garbage", createdb not invoked
test("ensure-db UNEXPECTED PROBE OUTPUT: psql outputs garbage, createdb not invoked", () => {
  const ensureDb = getStexorEnsureDbCommand();
  const inner = buildEnsureDbCommand(ensureDb);
  const result = runEnsureDbWithFakes(inner, { psqlStdout: "garbage", psqlExitCode: 0 });
  assert.ok(result.exitCode !== 0, "must exit nonzero on unexpected probe output");
  assert.equal(result.createdbCallCount, 0, "createdb must not be invoked on unexpected output");
});

// Test 6: Structural assertions on the full stexor restore entry
test("ensure-db structural assertions: command shape and ordering", () => {
  const ensureDb = getStexorEnsureDbCommand();
  const inner = buildEnsureDbCommand(ensureDb);

  // The extracted logic must be non-empty and contain the case/pattern structure
  assert.ok(inner.length > 0, "extracted inner logic must be non-empty");
  assert.match(inner, /case/);
  assert.match(inner, /1\)/);
  assert.match(inner, /""/);
  assert.match(inner, /\*\)/);
  assert.match(inner, /createdb/);
  assert.match(inner, /psql/);
  assert.match(inner, /ON_ERROR_STOP=1/);
  assert.match(inner, /database probe failed/);
  assert.match(inner, /unexpected.*probe.*result/);

  // commands[0] is the ensure-db shell command
  assert.match(ensureDb, /docker exec gf-postgres sh -ec/);
  // commands[1] is pg_restore
  const capture = buildCapturePlan({ families: ["postgres-stexor"], outputRoot: "/tmp/x", runId: "r" });
  const restore = buildRestorePlan({ captureReceipt: capture });
  const entry = restore.entries.find((e) => e.family === "postgres-stexor");
  assert.match(entry.commands[1], /pg_restore --clean --if-exists --no-owner --no-acl/);
  // commands[2] is ownership normalization
  assert.match(entry.commands[2], /OWNER TO postgres/);
  // ownerRole metadata
  assert.equal(entry.ownerRole, "postgres");
});
