import assert from "node:assert/strict";
import test from "node:test";
import {
  GREENFIELD_STATE_PROJECTION_SCHEMA,
  buildStateProjectionPlan,
  serializeProjectionPlan,
  validateStateProjectionPlan,
  finalSyncWriterRegistry,
} from "./greenfield-state-projection.mjs";
import { isBrownfieldOwnedPhysicalName } from "./greenfield-namespace.mjs";

function preservationManifestFixture() {
  return {
    schema: "platform.v1-greenfield-preservation-manifest/v1",
    capturedAtUtc: "2026-08-25T21:15:00Z-2026-08-26T00:30:00Z",
    sourceHost: "platform-infrastructure (Ubuntu, ssh alias platform-infrastructure)",
    manifestSha256: `f`.repeat(64),
    brownfieldRuntime: {
      composeProject: "platform_infra_vps",
      containersTotal: 35,
      containersRunning: 34,
    },
    namedVolumesMeasured: {
      enterprise_postgres_data: "90M",
      enterprise_mariadb_data: "224M",
      enterprise_keycloak_data: "24K",
      enterprise_minio_data: "104K",
      enterprise_redis_data: "32M",
      enterprise_grafana_data: "1.6M",
      enterprise_prometheus_data: "507M",
      enterprise_loki_data: "39M",
      enterprise_alertmanager_data: "8.0K",
      enterprise_pgadmin_data: "384K",
      enterprise_local_registry_data: "367M",
      enterprise_nats_data: "NOT_MEASURED",
    },
    anonymousVolumesCountApprox: 135,
    networks: ["enterprise_net"],
    hostStateTrees: {
      "/home/platform_infrastructure/src": {
        size: "1.5G",
        projects: [
          "anniversary",
          "fiplatform",
          "fireport",
          "matthewdifilippo",
          "opstudents",
          "public",
          "stexor",
          "stream",
          "workcalendar",
        ],
        perProject: { stexor: "535M", opstudents: "394M", stream: "21M" },
      },
      "/home/platform_infrastructure/platform-infrastructure/projects-portal/state": {
        size: "916K",
        keyFiles: ["projects.json", "databases.json", "operations.jsonl", "audit.jsonl"],
      },
      "/home/platform_infrastructure/platform-infrastructure/secrets": {
        size: "220K",
        fileCount_txt: 37,
        storeJsonBytes: 19072,
      },
      "/home/platform_infrastructure/platform-infrastructure/backups": {
        apparentSize: "29G",
        families: [
          "applications/",
          "postgres/*.dump",
          "mariadb/*.sql.gz",
          "minio/*.tar.gz",
          "keycloak/*.tar.gz",
          "secret-manager/",
          "secret-manager-real/*.tar.gpg",
          "offsite-restore-drills/",
        ],
        schedulerActive: true,
      },
    },
    activeReceiptSha256: `a`.repeat(64),
  };
}

const EXPECTED_ENTRY_IDS = [
  "app-src-anniversary",
  "app-src-fiplatform",
  "app-src-fireport",
  "app-src-matthewdifilippo",
  "app-src-opstudents",
  "app-src-public",
  "app-src-stexor",
  "app-src-stream",
  "app-src-workcalendar",
  "backup-families",
  "control-center-state",
  "keycloak-config",
  "keycloak-runtime-data",
  "mariadb-all",
  "minio-data",
  "postgres-keycloak",
  "postgres-stexor",
  "redis-data",
  "secret-manager-store",
  "unclassified-writable-layers",
];

test("plan builds clean from a realistic preservation-manifest fixture", () => {
  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  assert.equal(plan.schema, GREENFIELD_STATE_PROJECTION_SCHEMA);
  assert.equal(plan.generatedFromManifestSha256, "f".repeat(64));
  assert.ok(Object.isFrozen(plan));
  for (const entry of plan.entries) {
    assert.ok(Object.isFrozen(entry), entry.entryId);
    assert.ok(Object.isFrozen(entry.target), entry.entryId);
  }
  assert.deepEqual(validateStateProjectionPlan(plan), []);
});

test("entry set matches the canonical mapping table and is deterministically ordered", () => {
  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  assert.deepEqual(plan.entries.map((entry) => entry.entryId), EXPECTED_ENTRY_IDS);
  const sorted = [...plan.entries.map((entry) => entry.entryId)].sort();
  assert.deepEqual(plan.entries.map((entry) => entry.entryId), sorted);

  const byId = new Map(plan.entries.map((entry) => [entry.entryId, entry]));
  assert.equal(byId.get("postgres-stexor").kind, "postgres");
  assert.equal(byId.get("postgres-stexor").classification, "PRESERVE");
  assert.equal(byId.get("postgres-stexor").sourceIdentity, "volume:enterprise_postgres_data");
  assert.deepEqual(byId.get("postgres-stexor").target, { kind: "database", ref: "gf-postgres/stexor" });
  assert.equal(byId.get("postgres-stexor").verificationMethod, "postgres row-count+checksum fingerprint");
  assert.deepEqual(byId.get("postgres-keycloak").target, { kind: "database", ref: "gf-postgres/keycloak" });
  assert.equal(byId.get("postgres-keycloak").rollbackRelationship, "brownfield-volume-untouched");

  assert.equal(byId.get("mariadb-all").kind, "mariadb");
  assert.match(byId.get("mariadb-all").backupMethod, /mariadb-dump --single-transaction/);
  assert.equal(byId.get("mariadb-all").verificationMethod, "mariadb schema/table-count+fingerprint");
  assert.equal(byId.get("mariadb-all").target.ref.startsWith("gf-mariadb"), true);

  assert.deepEqual(byId.get("minio-data").target, { kind: "volume", ref: "greenfield_minio_data" });
  assert.equal(byId.get("minio-data").verificationMethod, "bucket/object-count/size/checksum");

  assert.equal(byId.get("keycloak-config").kind, "keycloak-config");
  assert.deepEqual(byId.get("keycloak-config").target, { kind: "database", ref: "gf-postgres/keycloak" });
  assert.equal(byId.get("keycloak-runtime-data").kind, "keycloak-data");
  assert.deepEqual(byId.get("keycloak-runtime-data").target, { kind: "volume", ref: "greenfield_keycloak_data" });

  assert.equal(byId.get("redis-data").classification, "PRESERVE_IF_STATEFUL");
  assert.match(byId.get("redis-data").backupMethod, /replica-quiesced/);

  for (const project of ["stexor", "workcalendar", "fireport"]) {
    const entry = byId.get(`app-src-${project}`);
    assert.equal(entry.kind, "app-source-tree");
    assert.equal(entry.sourceIdentity, `tree:/home/platform_infrastructure/src/${project}`);
    assert.equal(entry.target.kind, "bind");
    assert.ok(entry.target.ref.endsWith(`/${project}`));
    assert.equal(entry.verificationMethod, "recursive tree digest + ownership/mode");
  }

  const controlCenter = byId.get("control-center-state");
  assert.equal(controlCenter.sourceIdentity, "tree:/home/platform_infrastructure/platform-infrastructure/projects-portal/state");
  assert.deepEqual(controlCenter.target, { kind: "bind", ref: "gf-control-center:/var/www/project-state" });
  assert.equal(controlCenter.verificationMethod, "per-file sha256 + mode");

  const secrets = byId.get("secret-manager-store");
  assert.equal(secrets.classification, "OBSERVE");
  assert.equal(secrets.restoreMethod, "handled-by:greenfield-secret-projection");

  const backups = byId.get("backup-families");
  assert.equal(backups.classification, "PRESERVE");
  assert.equal(backups.target.kind, "bind");
  assert.equal(backups.target.ref, "shared-read-only-archive-root");
  assert.equal(backups.restoreMethod, "none (in-place, greenfield reads same immutable archive root)");

  const writable = byId.get("unclassified-writable-layers");
  assert.equal(writable.kind, "writable-layer");
  assert.equal(writable.classification, "OBSERVE");
  assert.equal(writable.sourceIdentity, "docker-anonymous-volumes:approx-135");
  assert.match(writable.mode, /projection refuses unknown volumes/);
  assert.equal(writable.restoreMethod, "requires explicit manifest classification before restore");
});

test("serialization is byte-identical across repeated builds with stable ordering", () => {
  const manifest = preservationManifestFixture();
  const first = buildStateProjectionPlan({ manifest });
  const second = buildStateProjectionPlan({ manifest });
  const serializedFirst = serializeProjectionPlan(first);
  const serializedSecond = serializeProjectionPlan(second);
  assert.equal(serializedFirst, serializedSecond);
  assert.equal(serializeProjectionPlan(buildStateProjectionPlan({ manifest })), serializedFirst);
  assert.equal(JSON.parse(serializedFirst).entries.length, EXPECTED_ENTRY_IDS.length);
});

test("includeRedisState:false drops the redis projection entry; default keeps it flagged stateful", () => {
  const manifest = preservationManifestFixture();
  const withRedis = buildStateProjectionPlan({ manifest });
  const withoutRedis = buildStateProjectionPlan({ manifest, includeRedisState: false });
  assert.ok(withRedis.entries.some((entry) => entry.entryId === "redis-data"));
  assert.ok(!withoutRedis.entries.some((entry) => entry.entryId === "redis-data"));
  assert.equal(withoutRedis.entries.length, withRedis.entries.length - 1);
  assert.deepEqual(validateStateProjectionPlan(withoutRedis), []);
  const redisEntry = withRedis.entries.find((entry) => entry.entryId === "redis-data");
  assert.equal(redisEntry.classification, "PRESERVE_IF_STATEFUL");
});

test("negative: brownfield target refs are rejected by validation", () => {
  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  const poisoned = JSON.parse(serializeProjectionPlan(plan));
  poisoned.entries.find((entry) => entry.entryId === "minio-data").target.ref = "enterprise_postgres_data";
  const violations = validateStateProjectionPlan(poisoned);
  assert.ok(violations.length > 0);
  assert.ok(violations.includes("entry:minio-data:target.ref:brownfield-owned"));
  assert.ok(violations.includes("entry:minio-data:target.ref:not-greenfield-volume"));
});

test("negative: duplicate entryId fails validation", () => {
  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  const poisoned = JSON.parse(serializeProjectionPlan(plan));
  poisoned.entries.push({ ...poisoned.entries[0] });
  const violations = validateStateProjectionPlan(poisoned);
  assert.ok(violations.some((violation) => violation === `entry:${poisoned.entries[0].entryId}:duplicate-entry-id`));
});

test("negative: unknown classification fails validation", () => {
  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  const poisoned = JSON.parse(serializeProjectionPlan(plan));
  poisoned.entries.find((entry) => entry.entryId === "minio-data").classification = "MAYBE";
  const violations = validateStateProjectionPlan(poisoned);
  assert.ok(violations.includes("entry:minio-data:classification:invalid"));
});

test("negative: missing required fields fail validation", () => {
  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  const poisoned = JSON.parse(serializeProjectionPlan(plan));
  delete poisoned.entries.find((entry) => entry.entryId === "mariadb-all").rollbackRelationship;
  const violations = validateStateProjectionPlan(poisoned);
  assert.ok(violations.includes("entry:mariadb-all:missing-field:rollbackRelationship"));
});

test("namespace interplay: every volume-kind target ref is greenfield-owned", () => {
  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  const volumeEntries = plan.entries.filter((entry) => entry.target.kind === "volume");
  assert.ok(volumeEntries.length >= 3);
  for (const entry of volumeEntries) {
    assert.equal(isBrownfieldOwnedPhysicalName(entry.target.ref), false, `${entry.entryId}:${entry.target.ref}`);
    assert.ok(entry.target.ref.startsWith("greenfield_"), `${entry.entryId}:${entry.target.ref}`);
  }
  for (const entry of plan.entries) {
    assert.equal(isBrownfieldOwnedPhysicalName(entry.target.ref), false, entry.entryId);
  }
});

test("final-sync registry covers exactly the cutover writers with quiesce-before-capture steps", () => {
  const registry = finalSyncWriterRegistry();
  assert.deepEqual(
    registry.map((writer) => writer.writerId),
    ["postgres-stexor", "postgres-keycloak", "mariadb", "minio", "app-bind-trees", "control-center-state"],
  );
  const freshRegistry = finalSyncWriterRegistry();
  assert.notEqual(registry, freshRegistry);
  for (const writer of registry) {
    assert.equal(writer.steps.length, 3, writer.writerId);
    const phases = writer.steps.map((step) => step.split(":")[0]);
    assert.deepEqual(phases, ["quiesce", "capture", "verify"], writer.writerId);
    const quiesceIndex = writer.steps.findIndex((step) => step.startsWith("quiesce"));
    const captureIndex = writer.steps.findIndex((step) => step.startsWith("capture"));
    const verifyIndex = writer.steps.findIndex((step) => step.startsWith("verify"));
    assert.ok(quiesceIndex < captureIndex && captureIndex < verifyIndex, writer.writerId);
    for (const step of writer.steps) {
      assert.equal(typeof step, "string");
    }
  }

  const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  assert.deepEqual(
    plan.writersCoveredByFinalSync,
    registry.map((writer) => writer.writerId),
  );
  const coveredIds = new Set(plan.writersCoveredByFinalSync);
  assert.ok(coveredIds.has("postgres-stexor"));
  assert.ok(coveredIds.has("postgres-keycloak"));
  assert.ok(coveredIds.has("mariadb"));
  assert.ok(coveredIds.has("minio"));
  assert.ok(coveredIds.has("app-bind-trees"));
  assert.ok(coveredIds.has("control-center-state"));
});
