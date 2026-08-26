import assert from "node:assert/strict";
import test from "node:test";
import {
  SCHEMA,
  CAPTURE_CONTRACTS,
  buildCapturePlan,
  buildRestorePlan,
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
