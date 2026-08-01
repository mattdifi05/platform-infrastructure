import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import * as contract from "./docker-action-contract.mjs";
import { createBrokerCore } from "./docker-action-broker.mjs";
import {
  ALL_ACTION_NAMES,
  ACTION_PROFILE_KEYS,
  ACTIVE_RECEIPT_KEYS,
  ACTIVE_RECEIPT_RESOURCE_KEYS,
  ACTIVE_RECEIPT_SCHEMA_V2,
  EVIDENCE_ACTION_NAMES,
  EXPECTED_ACTION_BINDINGS,
  EXPECTED_ACTION_PHASES,
  EXPECTED_CLAIMED_JOB_SOURCE_IDS,
  EXPECTED_EVIDENCE_RESULT_PHASE,
  EXPECTED_PHASE_PROFILES,
  FIXTURE_NOW,
  FIXTURE_TRUST_KEY,
  MAX_PHASE_OUTPUT_BYTES_V2,
  REQUEST_SCHEMA_V2,
  RESPONSE_SCHEMA_V2,
  RESULT_SCHEMA_V2,
  RUNTIME_INTENT_SCHEMA_V1,
  PHASE_PROFILE_KEYS,
  SCHEDULER_ACTION_NAMES,
  buildFixtureActionResultV2,
  buildFixtureSignedActionRequestV2,
  buildFixtureTrustedContextV2,
  buildFixtureUnsignedActionRequestV2,
  buildRawActiveReceiptV2,
  buildTrustedContextV2,
  canonicalFixtureJson,
  capabilityFileId,
  expectedActionPhases,
  expectedClaimedJobSourceId,
  expectedPhaseProfile,
  fixtureCapabilityKey,
  fixtureSha256,
  phaseDigest,
  profileDigest,
  resealActionProfiles,
} from "./docker-action-v2-fixtures.mjs";

const NOW = FIXTURE_NOW;
const TRUST_KEY = FIXTURE_TRUST_KEY;
const REQUEST_MAC_DOMAIN = `${REQUEST_SCHEMA_V2}\0`;
const RESPONSE_MAC_DOMAIN = `${RESPONSE_SCHEMA_V2}\0`;
const REQUEST_KEYS = Object.freeze([
  "action",
  "activeReceiptSha256",
  "capabilityId",
  "combinedRenderSha256",
  "expiresAt",
  "issuedAt",
  "mac",
  "nonce",
  "parameters",
  "requestId",
  "runtimeIntentId",
  "schema",
]);
const RESPONSE_KEYS = Object.freeze([
  "action",
  "errorCode",
  "mac",
  "requestId",
  "requestSha256",
  "result",
  "resultSha256",
  "schema",
  "status",
  "statusCode",
]);
const RESULT_KEYS = Object.freeze([
  "action",
  "job",
  "phases",
  "schema",
  "status",
]);
const RESULT_JOB_KEYS = Object.freeze([
  "jobFileName",
  "jobId",
  "jobOperation",
  "jobSha256",
]);
const RESULT_PHASE_KEYS = Object.freeze([
  "output",
  "outputSchema",
  "outputSha256",
  "phaseId",
  "status",
]);
const SERVICE_ENDPOINT_KEYS = Object.freeze([
  "backupResourceId",
  "engine",
  "endpointId",
  "host",
  "networkId",
  "port",
  "protocol",
  "purpose",
  "secretSetId",
  "targetContainerId",
  "tlsMode",
]);
const HELPER_PROFILE_KEYS = Object.freeze([
  "engine",
  "entrypoint",
  "imageId",
  "imageRef",
  "networkId",
  "operation",
  "outputMode",
  "resourceKind",
  "secretSetId",
  "helperProfileId",
]);
const EXPECTED_SERVICE_ENDPOINTS = Object.freeze({
  "capture.database.mariadb": Object.freeze({
    backupResourceId: "database:mariadb",
    engine: "mariadb",
    endpointId: "capture.database.mariadb",
    host: "mariadb",
    networkId: "platform_db_admin",
    port: 3306,
    protocol: "mariadb",
    purpose: "capture",
    secretSetId: "mariadb.capture.credentials",
    targetContainerId: "mariadb",
    tlsMode: "require",
  }),
  "capture.database.postgres": Object.freeze({
    backupResourceId: "database:postgres",
    engine: "postgres",
    endpointId: "capture.database.postgres",
    host: "postgres",
    networkId: "platform_db_admin",
    port: 5432,
    protocol: "postgresql",
    purpose: "capture",
    secretSetId: "postgres.capture.credentials",
    targetContainerId: "postgres",
    tlsMode: "require",
  }),
  "capture.storage.minio": Object.freeze({
    backupResourceId: "storage:minio",
    engine: "minio",
    endpointId: "capture.storage.minio",
    host: "minio",
    networkId: "platform_storage",
    port: 9000,
    protocol: "s3-http",
    purpose: "capture",
    secretSetId: "minio.capture.credentials",
    targetContainerId: "minio",
    tlsMode: "none",
  }),
  "offsite.repository": Object.freeze({
    backupResourceId: null,
    engine: "restic",
    endpointId: "offsite.repository",
    host: "backup.example.net",
    networkId: "platform_egress",
    port: 443,
    protocol: "restic-https",
    purpose: "offsite",
    secretSetId: "offsite.credentials",
    targetContainerId: null,
    tlsMode: "verify-full",
  }),
});
const POSTGRES_IMAGE_ID = `sha256:${"8".repeat(64)}`;
const POSTGRES_IMAGE_REF = "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa";
const MARIADB_IMAGE_ID = `sha256:${"9".repeat(64)}`;
const MARIADB_IMAGE_REF = "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b";
const MINIO_MC_IMAGE_ID = `sha256:${"a".repeat(64)}`;
const MINIO_MC_IMAGE_REF = "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727";
const MINIO_SERVER_IMAGE_ID = `sha256:${"b".repeat(64)}`;
const MINIO_SERVER_IMAGE_REF = "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e";
const RESTIC_IMAGE_ID = `sha256:${"c".repeat(64)}`;
const RESTIC_IMAGE_REF = "restic/restic:0.18.0@sha256:4cf4a61ef9786f4de53e9de8c8f5c040f33830eb0a10bf3d614410ee2fcb6120";
const EXPECTED_HELPER_PROFILES = Object.freeze({
  "helper.capture.mariadb": Object.freeze({
    engine: "mariadb",
    entrypoint: Object.freeze(["/usr/bin/mariadb-dump"]),
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "mariadb.capture.credentials",
    helperProfileId: "helper.capture.mariadb",
  }),
  "helper.capture.minio": Object.freeze({
    engine: "minio",
    entrypoint: Object.freeze(["/bin/sh"]),
    imageId: MINIO_MC_IMAGE_ID,
    imageRef: MINIO_MC_IMAGE_REF,
    networkId: "platform_storage",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "storage",
    secretSetId: "minio.capture.credentials",
    helperProfileId: "helper.capture.minio",
  }),
  "helper.capture.postgres": Object.freeze({
    engine: "postgres",
    entrypoint: Object.freeze(["/usr/local/bin/pg_dump"]),
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "postgres.capture.credentials",
    helperProfileId: "helper.capture.postgres",
  }),
  "helper.offsite.restic": Object.freeze({
    engine: "restic",
    entrypoint: Object.freeze(["/usr/bin/restic"]),
    imageId: RESTIC_IMAGE_ID,
    imageRef: RESTIC_IMAGE_REF,
    networkId: "platform_egress",
    operation: "offsite-sync",
    outputMode: "json",
    resourceKind: null,
    secretSetId: "offsite.credentials",
    helperProfileId: "helper.offsite.restic",
  }),
  "helper.restore.minio.restore": Object.freeze({
    engine: "minio",
    entrypoint: Object.freeze(["/usr/bin/mc"]),
    imageId: MINIO_MC_IMAGE_ID,
    imageRef: MINIO_MC_IMAGE_REF,
    networkId: null,
    operation: "restore",
    outputMode: "none",
    resourceKind: "storage",
    secretSetId: null,
    helperProfileId: "helper.restore.minio.restore",
  }),
  "helper.restore.minio.server": Object.freeze({
    engine: "minio",
    entrypoint: Object.freeze(["/usr/bin/minio"]),
    imageId: MINIO_SERVER_IMAGE_ID,
    imageRef: MINIO_SERVER_IMAGE_REF,
    networkId: null,
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "storage",
    secretSetId: null,
    helperProfileId: "helper.restore.minio.server",
  }),
  "helper.restore.minio.verify": Object.freeze({
    engine: "minio",
    entrypoint: Object.freeze(["/usr/bin/mc"]),
    imageId: MINIO_MC_IMAGE_ID,
    imageRef: MINIO_MC_IMAGE_REF,
    networkId: null,
    operation: "verify",
    outputMode: "json",
    resourceKind: "storage",
    secretSetId: null,
    helperProfileId: "helper.restore.minio.verify",
  }),
  "helper.restore.mariadb.restore": Object.freeze({
    engine: "mariadb",
    entrypoint: Object.freeze(["/usr/bin/mariadb"]),
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    networkId: null,
    operation: "restore",
    outputMode: "none",
    resourceKind: "database",
    secretSetId: null,
    helperProfileId: "helper.restore.mariadb.restore",
  }),
  "helper.restore.mariadb.server": Object.freeze({
    engine: "mariadb",
    entrypoint: Object.freeze(["/usr/local/bin/docker-entrypoint.sh"]),
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    networkId: null,
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "database",
    secretSetId: null,
    helperProfileId: "helper.restore.mariadb.server",
  }),
  "helper.restore.mariadb.verify": Object.freeze({
    engine: "mariadb",
    entrypoint: Object.freeze(["/usr/bin/mariadb"]),
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    networkId: null,
    operation: "verify",
    outputMode: "json",
    resourceKind: "database",
    secretSetId: null,
    helperProfileId: "helper.restore.mariadb.verify",
  }),
  "helper.restore.postgres.restore": Object.freeze({
    engine: "postgres",
    entrypoint: Object.freeze(["/usr/local/bin/pg_restore"]),
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    networkId: null,
    operation: "restore",
    outputMode: "none",
    resourceKind: "database",
    secretSetId: null,
    helperProfileId: "helper.restore.postgres.restore",
  }),
  "helper.restore.postgres.server": Object.freeze({
    engine: "postgres",
    entrypoint: Object.freeze(["/usr/local/bin/docker-entrypoint.sh"]),
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    networkId: null,
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "database",
    secretSetId: null,
    helperProfileId: "helper.restore.postgres.server",
  }),
  "helper.restore.postgres.verify": Object.freeze({
    engine: "postgres",
    entrypoint: Object.freeze(["/usr/local/bin/psql"]),
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    networkId: null,
    operation: "verify",
    outputMode: "json",
    resourceKind: "database",
    secretSetId: null,
    helperProfileId: "helper.restore.postgres.verify",
  }),
});
const EXPECTED_PHASE_ENDPOINT_HELPER_IDS = Object.freeze({
  "catalog.capture": Object.freeze({
    endpointIds: Object.freeze(["capture.database.mariadb", "capture.database.postgres", "capture.storage.minio"]),
    helperProfileIds: Object.freeze(["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"]),
  }),
  "job.backup.capture": Object.freeze({
    endpointIds: Object.freeze(["capture.database.mariadb", "capture.database.postgres", "capture.storage.minio"]),
    helperProfileIds: Object.freeze(["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"]),
  }),
  "job.restore.verify": Object.freeze({
    endpointIds: Object.freeze([]),
    helperProfileIds: Object.freeze([
      "helper.restore.mariadb.restore",
      "helper.restore.mariadb.server",
      "helper.restore.mariadb.verify",
      "helper.restore.minio.restore",
      "helper.restore.minio.server",
      "helper.restore.minio.verify",
      "helper.restore.postgres.restore",
      "helper.restore.postgres.server",
      "helper.restore.postgres.verify",
    ]),
  }),
  "offsite.sync": Object.freeze({
    endpointIds: Object.freeze(["offsite.repository"]),
    helperProfileIds: Object.freeze(["helper.offsite.restic"]),
  }),
  "prune.apply": Object.freeze({
    endpointIds: Object.freeze([]),
    helperProfileIds: Object.freeze([]),
  }),
  "prune.plan": Object.freeze({
    endpointIds: Object.freeze([]),
    helperProfileIds: Object.freeze([]),
  }),
  "restore.capture": Object.freeze({
    endpointIds: Object.freeze(["capture.database.mariadb", "capture.database.postgres", "capture.storage.minio"]),
    helperProfileIds: Object.freeze(["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"]),
  }),
  "restore.verify": Object.freeze({
    endpointIds: Object.freeze([]),
    helperProfileIds: Object.freeze([
      "helper.restore.mariadb.restore",
      "helper.restore.mariadb.server",
      "helper.restore.mariadb.verify",
      "helper.restore.minio.restore",
      "helper.restore.minio.server",
      "helper.restore.minio.verify",
      "helper.restore.postgres.restore",
      "helper.restore.postgres.server",
      "helper.restore.postgres.verify",
    ]),
  }),
});

test("RED v2: scheduler and runtime-evidence registries are disjoint, complete, modeled and uniquely bound", () => {
  assert.ok(
    contract.SCHEDULER_ACTIONS && typeof contract.SCHEDULER_ACTIONS === "object",
    "the product must export the six-action SCHEDULER_ACTIONS registry",
  );
  assert.ok(
    contract.EVIDENCE_ACTIONS && typeof contract.EVIDENCE_ACTIONS === "object",
    "the product must export the disjoint EVIDENCE_ACTIONS registry",
  );

  assert.deepEqual(Object.keys(contract.SCHEDULER_ACTIONS).sort(), [...SCHEDULER_ACTION_NAMES].sort());
  assert.deepEqual(Object.keys(contract.EVIDENCE_ACTIONS).sort(), [...EVIDENCE_ACTION_NAMES].sort());
  assert.deepEqual(
    Object.keys(contract.ACTIONS).sort(),
    [...SCHEDULER_ACTION_NAMES, ...EVIDENCE_ACTION_NAMES].sort(),
    "ACTIONS must be only the exact union of the two disjoint registries",
  );

  const entries = Object.entries(contract.ACTIONS);
  for (const [action, entry] of entries) {
    const expected = EXPECTED_ACTION_BINDINGS[action];
    assert.ok(expected, `${action} is not an approved action binding`);
    assert.equal(entry.modeled, true, `${action} must have an implemented fixed model`);
    assert.equal(entry.capabilityId, expected.capabilityId, `${action} capability identity`);
    assert.equal(entry.capabilityFile, expected.capabilityFile, `${action} capability path`);
    assert.equal(entry.profileId, expected.profileId, `${action} semantic profile identity`);
  }
  assertUnique(entries.map(([, entry]) => entry.capabilityId), "capabilityId");
  assertUnique(entries.map(([, entry]) => entry.capabilityFile), "capabilityFile");
  assertUnique(entries.map(([, entry]) => entry.profileId), "profileId");
});

test("RED v2: request schema has exact keys and rejects extensions", () => {
  assert.equal(contract.REQUEST_SCHEMA, REQUEST_SCHEMA_V2);
  const trusted = requestTrustedFixture("backup.catalog");
  const unsigned = contract.buildUnsignedRequest("backup.catalog", {}, trusted, {
    now: NOW,
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
  });
  const key = capabilityKey("backup.catalog");
  const signed = contract.signActionRequest(unsigned, key);

  assert.deepEqual(Object.keys(unsigned).sort(), REQUEST_KEYS.filter((key) => key !== "mac").sort());
  assert.deepEqual(Object.keys(signed).sort(), [...REQUEST_KEYS].sort());
  const admitted = contract.normalizeActionRequest(signed, trusted, key, { now: NOW });
  assert.equal(admitted.action, "backup.catalog");
  assert.equal(admitted.activeReceiptSha256, trusted.receiptDigest);
  assert.equal(admitted.capabilityId, contract.ACTIONS["backup.catalog"].capabilityId);
  assert.equal(admitted.combinedRenderSha256, trusted.receipt.combinedRenderSha256);
  assert.equal(admitted.nonce, signed.nonce);
  assert.deepEqual(admitted.parameters, {});
  assert.equal(admitted.requestId, signed.requestId);
  assert.equal(admitted.runtimeIntentId, trusted.intent.intentId);

  const injected = contract.signActionRequest({ ...unsigned, rawDockerArgs: ["run", "--privileged"] }, key);
  assert.throws(
    () => contract.normalizeActionRequest(injected, trusted, key, { now: NOW }),
    /unsupported or missing fields/,
  );
  assert.equal(unsigned.schema, REQUEST_SCHEMA_V2);
});

test("RED v2: request MAC is canonical and domain-separated", () => {
  const trusted = requestTrustedFixture("backup.catalog");
  const unsigned = buildFixtureUnsignedActionRequestV2("backup.catalog", {}, {
    index: 8,
    now: NOW,
    trustedContext: trusted,
  });
  const key = capabilityKey("backup.catalog");
  const signed = contract.signActionRequest(unsigned, key);
  const expectedMac = requestMac(unsigned, key);

  assert.equal(signed.mac, expectedMac);
  assert.equal(
    contract.signActionRequest(Object.fromEntries(Object.entries(unsigned).reverse()), key).mac,
    expectedMac,
    "property insertion order must not change the domain-separated request MAC",
  );
  assert.notEqual(
    expectedMac,
    crypto.createHmac("sha256", key).update(canonicalFixtureJson(unsigned)).digest("hex"),
    "v1-compatible bare canonical JSON must not authenticate as a v2 request",
  );
});

test("runtime intent v1 preserves its legacy bare-canonical MAC contract", () => {
  assert.equal(contract.RUNTIME_INTENT_SCHEMA, RUNTIME_INTENT_SCHEMA_V1);
  const unsigned = {
    schema: RUNTIME_INTENT_SCHEMA_V1,
    activeReceiptSha256: "a".repeat(64),
    activationBundleSha256: "b".repeat(64),
    allowedActions: ["backup.prune.plan"],
    candidateId: "candidate.v2",
    combinedRenderSha256: "c".repeat(64),
    dastChainSha256: "d".repeat(64),
    environment: "production",
    expiresAt: new Date(NOW + 30 * 60_000).toISOString(),
    generation: 2,
    intentId: "intent.release-v2",
    issuedAt: new Date(NOW - 30_000).toISOString(),
    releaseId: "release.v2",
    targetId: "platform.primary",
  };
  const signed = contract.signRuntimeIntent(unsigned, TRUST_KEY);
  const legacyMac = crypto
    .createHmac("sha256", TRUST_KEY)
    .update(canonicalFixtureJson(unsigned))
    .digest("hex");
  const schemaDomainMac = crypto
    .createHmac("sha256", TRUST_KEY)
    .update(`${RUNTIME_INTENT_SCHEMA_V1}\0`)
    .update(canonicalFixtureJson(unsigned))
    .digest("hex");

  assert.equal(signed.mac, legacyMac);
  assert.notEqual(
    signed.mac,
    schemaDomainMac,
    "the v1 intent compatibility MAC must not inherit the v2 request/response domain format",
  );
});

test("RED v2: request consumer admits the v2 domain control and rejects legacy or cross-domain MACs", async (t) => {
  const trusted = requestTrustedFixture("backup.catalog");
  const key = capabilityKey("backup.catalog");
  const unsigned = buildFixtureUnsignedActionRequestV2("backup.catalog", {}, {
    index: 9,
    now: NOW,
    trustedContext: trusted,
  });
  const valid = buildFixtureSignedActionRequestV2("backup.catalog", {}, {
    capabilityKey: key,
    index: 9,
    now: NOW,
    trustedContext: trusted,
  });
  const candidates = [
    [
      "bare legacy canonical JSON",
      {
        ...unsigned,
        mac: crypto
          .createHmac("sha256", key)
          .update(canonicalFixtureJson(unsigned))
          .digest("hex"),
      },
    ],
    [
      "response-domain MAC",
      {
        ...unsigned,
        mac: crypto
          .createHmac("sha256", key)
          .update(RESPONSE_MAC_DOMAIN)
          .update(canonicalFixtureJson(unsigned))
          .digest("hex"),
      },
    ],
  ];

  await t.test("positive v2 request-domain control reaches the consumer", (st) => {
    if (!requestConsumerV2Ready(st)) return;
    assert.deepEqual(
      contract.normalizeActionRequest(valid, trusted, key, { now: NOW }),
      admittedRequestShape(valid),
    );
  });
  for (const [label, candidate] of candidates) {
    await t.test(label, (st) => {
      if (!requestConsumerV2Ready(st)) return;
      assert.deepEqual(
        contract.normalizeActionRequest(valid, trusted, key, { now: NOW }),
        admittedRequestShape(valid),
        `${label} negative is meaningful only after the correct domain is admitted`,
      );
      assert.throws(
        () => contract.normalizeActionRequest(candidate, trusted, key, { now: NOW }),
        /authentication|mac/i,
        `${label} must reach and fail request authentication`,
      );
    });
  }
  const nestedActionCollisions = exactActionIdentityCollisions(valid.action);
  assert.deepEqual(
    nestedActionCollisions
      .filter(([, nestedAction]) => identityBlindEndsWithActionMutant(
        nestedAction,
        valid.action,
      ))
      .map(([label]) => label),
    ["authenticated expected-suffix action"],
    "the active identity-blind endsWith mutant must admit only the hostile expected-suffix collision",
  );
  for (const [label, nestedAction] of nestedActionCollisions) {
    await t.test(label, (st) => {
      if (!requestConsumerV2Ready(st)) return;
      const unsignedCandidate = {
        ...unsigned,
        action: nestedAction,
      };
      const candidate = {
        ...unsignedCandidate,
        mac: requestMac(unsignedCandidate, key),
      };
      assert.deepEqual(
        Object.keys(candidate).sort(),
        [...REQUEST_KEYS].sort(),
        `${label} must preserve the exact request wire schema`,
      );
      assert.equal(candidate.schema, REQUEST_SCHEMA_V2);
      assert.equal(
        candidate.mac,
        requestMac(omit(candidate, "mac"), key),
        `${label} must carry a valid independently recomputed request MAC`,
      );
      const error = captureThrownError(
        () => contract.normalizeActionRequest(candidate, trusted, key, { now: NOW }),
        /action|authorized|enabled|binding|identity/i,
        `${label} must fail only at exact canonical action binding`,
      );
      assert.doesNotMatch(
        error.message,
        /authentication|mac|schema|digest/i,
        `${label} must not be rejected for authentication, schema or digest`,
      );
    });
  }
  await t.test("authenticated path-nested action fails at action grammar", (st) => {
    const nestedAction = `${valid.action}/child`;
    const unsignedCandidate = {
      ...unsigned,
      action: nestedAction,
    };
    const candidate = {
      ...unsignedCandidate,
      mac: requestMac(unsignedCandidate, key),
    };
    assert.deepEqual(
      Object.keys(candidate).sort(),
      [...REQUEST_KEYS].sort(),
      "the path-nested action must preserve the exact signed request wire schema",
    );
    assert.equal(candidate.schema, REQUEST_SCHEMA_V2);
    assert.equal(candidate.activeReceiptSha256, valid.activeReceiptSha256);
    assert.equal(candidate.combinedRenderSha256, valid.combinedRenderSha256);
    assert.equal(candidate.runtimeIntentId, valid.runtimeIntentId);
    assert.equal(
      candidate.mac,
      requestMac(omit(candidate, "mac"), key),
      "the path-nested action must carry a valid independently recomputed request MAC",
    );
    assert.notEqual(
      candidate.mac,
      valid.mac,
      "the authenticated action mutation must alter the request MAC",
    );
    assert.notEqual(
      canonicalSignedRequestSha256(candidate),
      canonicalSignedRequestSha256(valid),
      "the authenticated action mutation must alter the complete signed-request digest",
    );
    assert.throws(
      () => assertActionGrammarFailure(
        () => grammarBlindExactRegistryLookupMutant(candidate),
        "the active grammar-blind exact-registry mutant",
      ),
      /must fail specifically at action grammar before registry lookup/i,
      "the grammar-specific consumer oracle must kill an exact registry lookup with no grammar gate",
    );

    if (!requestConsumerV2Ready(st)) return;
    assertActionGrammarFailure(
      () => contract.normalizeActionRequest(candidate, trusted, key, { now: NOW }),
      "the authenticated path-nested action",
    );
  });
});

test("RED v2: every capability is action-distinct and bound to the attested file bytes", async (t) => {
  const receipt = activeReceiptFixture();
  const keyDigests = [];
  for (const action of ALL_ACTION_NAMES) {
    const fileId = capabilityFileId(action);
    const key = capabilityKey(action);
    const file = receipt.resources.capabilityFiles[fileId];
    assert.ok(file, `${action} capability file is missing`);
    assert.equal(file.brokerPath, EXPECTED_ACTION_BINDINGS[action].capabilityFile);
    assert.equal(file.sha256, fixtureSha256(key), `${action} capability digest must bind its real bytes`);
    keyDigests.push(file.sha256);
  }
  assertUnique(keyDigests, "action capability key digest");

  const action = "backup.catalog";
  const trusted = requestTrustedFixture(action);
  const request = signedRequest(action, {}, trusted, 10);
  await t.test("positive exact action capability control", (st) => {
    if (!requestConsumerV2Ready(st)) return;
    assert.deepEqual(
      contract.normalizeActionRequest(
        request,
        trusted,
        capabilityKey(action),
        { now: NOW },
      ),
      admittedRequestShape(request),
    );
  });
  await t.test("different valid action capability", (st) => {
    if (!requestConsumerV2Ready(st)) return;
    assert.deepEqual(
      contract.normalizeActionRequest(
        request,
        trusted,
        capabilityKey(action),
        { now: NOW },
      ),
      admittedRequestShape(request),
      "cross-capability rejection is meaningful only after the exact capability is admitted",
    );
    assert.throws(
      () => contract.normalizeActionRequest(
        request,
        trusted,
        capabilityKey("backup.prune.plan"),
        { now: NOW },
      ),
      /capability|authentication|mac|digest/i,
      "a different action capability must not authenticate",
    );
  });

  await t.test("receipt capability digest does not match the loaded bytes", (st) => {
    if (!requestConsumerV2Ready(st)) return;
    assert.deepEqual(
      contract.normalizeActionRequest(
        request,
        trusted,
        capabilityKey(action),
        { now: NOW },
      ),
      admittedRequestShape(request),
      "digest substitution is meaningful only after the exact receipt and bytes are admitted",
    );
    const wrongDigestReceipt = activeReceiptFixture();
    wrongDigestReceipt.resources.capabilityFiles[capabilityFileId(action)].sha256 = "0".repeat(64);
    const wrongDigestTrusted = buildFixtureTrustedContextV2({
      allowedActions: [action],
      now: NOW,
      rawReceipt: wrongDigestReceipt,
    }).trusted;
    const wrongDigestRequest = signedRequest(action, {}, wrongDigestTrusted, 11);
    assert.throws(
      () => contract.normalizeActionRequest(
        wrongDigestRequest,
        wrongDigestTrusted,
        capabilityKey(action),
        { now: NOW },
      ),
      /capability.*(?:digest|sha)|digest.*capability/i,
      "the broker must compare loaded capability bytes with the signed receipt",
    );
  });
});

test("RED v2: typed job parameters preserve real identifiers and reject normalization or aliases", async (t) => {
  const trusted = requestTrustedFixture("backup.job.execute");
  const key = capabilityKey("backup.job.execute");
  const accepted = [
    {
      jobFileName: "0123456789abcdef.json",
      jobId: "0123456789abcdef",
      jobOperation: "backup",
      jobSha256: "1".repeat(64),
    },
    {
      jobFileName: "scheduled-platform-20260728-120000-a1b2c3.json",
      jobId: "scheduled-platform-20260728-120000-a1b2c3",
      jobOperation: "backup",
      jobSha256: "2".repeat(64),
    },
    {
      jobFileName: "job-0123456789abcdef.json",
      jobId: "job-0123456789abcdef",
      jobOperation: "restore-drill",
      jobSha256: "3".repeat(64),
    },
  ];

  for (const [index, parameters] of accepted.entries()) {
    await t.test(`accepted canonical job identity ${index + 1}`, (st) => {
      if (!requestConsumerV2Ready(st)) return;
      const request = signedRequest("backup.job.execute", parameters, trusted, index);
      const normalized = contract.normalizeActionRequest(request, trusted, key, { now: NOW });
      assert.deepEqual(Object.keys(normalized.parameters).sort(), [
        "jobFileName",
        "jobId",
        "jobOperation",
        "jobSha256",
      ]);
      assert.deepEqual(normalized.parameters, parameters, "admitted job identity must be byte-exact");
    });
  }

  const base = accepted[0];
  const invalid = [
    ["missing field", omit(base, "jobSha256")],
    ["extra alias field", { ...base, jobHash: base.jobSha256 }],
    ["leading whitespace", { ...base, jobId: ` ${base.jobId}` }],
    ["trailing whitespace", { ...base, jobId: `${base.jobId} ` }],
    ["case normalization", { ...base, jobId: base.jobId.toUpperCase() }],
    ["operation case", { ...base, jobOperation: "Backup" }],
    ["operation whitespace", { ...base, jobOperation: "backup " }],
    ["operation alias", { ...base, jobOperation: "restore" }],
    ["parent traversal", { ...base, jobFileName: `../${base.jobFileName}` }],
    ["nested traversal", { ...base, jobFileName: `queued/${base.jobFileName}` }],
    ["backslash traversal", { ...base, jobFileName: `queued\\${base.jobFileName}` }],
    ["filename case", { ...base, jobFileName: base.jobFileName.toUpperCase() }],
    ["filename alias", { ...base, jobFileName: "job-alias.json" }],
    ["digest case", { ...base, jobSha256: "A".repeat(64) }],
    ["digest whitespace", { ...base, jobSha256: `${base.jobSha256} ` }],
  ];
  for (const [index, [label, parameters]] of invalid.entries()) {
    await t.test(label, (st) => {
      if (!requestConsumerV2Ready(st)) return;
      const control = signedRequest("backup.job.execute", base, trusted, 100 + index);
      assert.deepEqual(
        contract.normalizeActionRequest(control, trusted, key, { now: NOW }),
        admittedRequestShape(control),
        `${label} negative is meaningful only after the exact job identity is admitted`,
      );
      const request = signedRequest("backup.job.execute", parameters, trusted, 200 + index);
      assert.throws(
        () => contract.normalizeActionRequest(request, trusted, key, { now: NOW }),
        /job|parameter|field|identity|operation|digest|file/i,
        label,
      );
    });
  }
});

test("RED v2: broker core emits the exact authenticated response wire contract", async (t) => {
  if (!requestConsumerV2Ready(t)) return;
  const parameters = {
    jobFileName: "0123456789abcdef.json",
    jobId: "0123456789abcdef",
    jobOperation: "backup",
    jobSha256: "1".repeat(64),
  };
  const trusted = requestTrustedFixture("backup.job.execute");
  const key = capabilityKey("backup.job.execute");
  const request = signedRequest("backup.job.execute", parameters, trusted, 30);
  const result = buildFixtureActionResultV2("backup.job.execute", parameters);
  const calls = {
    acquire: [],
    consume: [],
    engine: [],
  };
  let lease;
  const replayStore = {
    acquire(...args) {
      calls.acquire.push(args);
      const [observedRequest, observedTrusted] = args;
      lease = Object.freeze({
        lineage: Object.freeze({
          action: observedRequest.action,
          intentId: observedTrusted.intent.intentId,
          receiptDigest: observedTrusted.receiptDigest,
          request: structuredClone(observedRequest),
          requestId: observedRequest.requestId,
          requestSha256: fixtureSha256(canonicalFixtureJson(observedRequest)),
        }),
        preserve() {},
        recordWorker() {},
        release() {},
      });
      return lease;
    },
    admitActivation() {},
    admitTrustedContext() {},
    consume(...args) {
      calls.consume.push(args);
    },
  };
  const core = createBrokerCore({
    trustedContextProvider: async () => trusted,
    capabilityProvider: async () => key,
    engine: {
      async execute(...args) {
        calls.engine.push(args);
        return result;
      },
    },
    replayStore,
    now: () => NOW,
    operationTimeoutMs: 100,
  });

  const wire = await core.handle(Buffer.from(canonicalFixtureJson(request)));
  const response = wire.body;
  const requestSha256 = canonicalSignedRequestSha256(request);
  const requestIdOnlySha256 = fixtureSha256(request.requestId);
  const resultSha256 = fixtureSha256(canonicalFixtureJson(result));

  assert.notEqual(
    requestSha256,
    requestIdOnlySha256,
    "the response request digest must cover the complete signed request, not only requestId",
  );
  assert.equal(calls.consume.length, 1);
  assert.equal(calls.consume[0].length, 1);
  assertCompleteSignedRequestBoundary(
    calls.consume[0][0],
    request,
    "replayStore.consume request",
  );
  assert.equal(calls.acquire.length, 1);
  assert.equal(calls.acquire[0].length, 2);
  assertCompleteSignedRequestBoundary(
    calls.acquire[0][0],
    request,
    "replayStore.acquire request",
  );
  assert.strictEqual(
    calls.acquire[0][1],
    trusted,
    "replayStore.acquire must receive the exact trusted lineage admitted by the provider",
  );
  assertTrustedRequestLineage(lease.lineage, request, trusted, "lease");
  assert.equal(calls.engine.length, 1);
  assert.equal(calls.engine[0].length, 2);
  assert.equal(calls.engine[0][0], request.action);
  assertSemanticCoreContext(
    calls.engine[0][1],
    request,
    trusted,
    lease,
    "engine.execute context",
  );
  assert.equal(wire.statusCode, 200);
  assert.deepEqual(Object.keys(response).sort(), [...RESPONSE_KEYS].sort());
  assert.equal(response.schema, RESPONSE_SCHEMA_V2);
  assert.equal(response.status, "completed");
  assert.equal(response.statusCode, 200);
  assert.equal(response.errorCode, null);
  assert.equal(response.action, request.action);
  assert.equal(response.requestId, request.requestId);
  assert.equal(response.requestSha256, requestSha256);
  assert.equal(response.requestSha256, lease.lineage.requestSha256);
  assert.equal(response.requestSha256, calls.engine[0][1].requestSha256);
  assert.equal(response.resultSha256, resultSha256);
  assert.deepEqual(response.result, result);
  assertResponseBoundToSignedRequestAndResult(response, request);
  assert.equal(response.mac, responseMac(omit(response, "mac"), key));

  const truncated = admittedRequestShape(request);
  assert.throws(
    () => assertCompleteSignedRequestBoundary(
      truncated,
      request,
      "negative truncated request",
    ),
    /complete signed request/i,
    "the oracle must reject a normalized or truncated request at an internal boundary",
  );
  assert.throws(
    () => assertSemanticCoreContext(
      {
        ...calls.engine[0][1],
        requestSha256: requestIdOnlySha256,
      },
      request,
      trusted,
      lease,
      "negative requestId-only engine context",
    ),
    /canonical full signed request/i,
    "the oracle must reject a digest derived from requestId even when the response is otherwise valid",
  );
  assert.throws(
    () => assertSemanticCoreContext(
      {
        ...calls.engine[0][1],
        parameters: {},
      },
      request,
      trusted,
      lease,
      "negative truncated engine parameters",
    ),
    /exact request parameters/i,
    "the oracle must reject an engine context that drops typed request parameters",
  );
  assert.throws(
    () => assertTrustedRequestLineage(
      {
        ...lease.lineage,
        request: truncated,
        requestSha256: requestIdOnlySha256,
      },
      request,
      trusted,
      "negative truncated lease",
    ),
    /complete signed request/i,
    "the oracle must reject a lease lineage that discarded authenticated request fields",
  );
});

test("RED v2: evidence output is bounded before the broker releases its replay lease", async (t) => {
  await t.test("bounded evidence result reaches the authenticated consumer", async (st) => {
    if (!requestConsumerV2Ready(st)) return;
    if (!responseConsumerV2Ready(st)) return;
    const trusted = requestTrustedFixture("evidence.runtime.snapshot");
    const key = capabilityKey("evidence.runtime.snapshot");
    const request = signedRequest("evidence.runtime.snapshot", {}, trusted, 31);
    const result = buildFixtureActionResultV2("evidence.runtime.snapshot");
    const outputBytes = Buffer.byteLength(canonicalFixtureJson(result.phases[0].output));
    const harness = evidenceBrokerHarness({ key, result, trusted });

    assert.ok(outputBytes <= MAX_PHASE_OUTPUT_BYTES_V2);
    const wire = await harness.core.handle(Buffer.from(canonicalFixtureJson(request)));
    assert.equal(wire.statusCode, 200);
    assert.equal(harness.executeCount(), 1);
    assert.deepEqual(harness.leaseEvents, ["acquire", "release"]);
    assertResponseBoundToSignedRequestAndResult(wire.body, request);
  });

  await t.test("oversized evidence result is rejected and preserves the replay lease", async (st) => {
    if (!requestConsumerV2Ready(st)) return;
    if (!responseConsumerV2Ready(st)) return;
    const trusted = requestTrustedFixture("evidence.runtime.snapshot");
    const key = capabilityKey("evidence.runtime.snapshot");
    const request = signedRequest("evidence.runtime.snapshot", {}, trusted, 32);
    const bounded = buildFixtureActionResultV2("evidence.runtime.snapshot");
    const oversizedOutput = {
      ...bounded.phases[0].output,
      resources: {
        padding: "x".repeat(MAX_PHASE_OUTPUT_BYTES_V2),
      },
    };
    const result = {
      ...bounded,
      phases: [phaseResultWithResealedOutput(bounded.phases[0], oversizedOutput)],
    };
    const outputBytes = Buffer.byteLength(canonicalFixtureJson(oversizedOutput));
    const harness = evidenceBrokerHarness({ key, result, trusted });

    assert.ok(
      outputBytes > MAX_PHASE_OUTPUT_BYTES_V2,
      "the negative must cross the unchanged 4096-byte phase-output boundary",
    );
    await assert.rejects(
      () => harness.core.handle(Buffer.from(canonicalFixtureJson(request))),
      undefined,
      "an oversized evidence result must not reach the authenticated response consumer",
    );
    assert.equal(harness.executeCount(), 1);
    assert.deepEqual(
      harness.leaseEvents,
      ["acquire", "preserve"],
      "post-execution result rejection must fail closed without consuming the replay lease",
    );
  });
});

test("RED v2: response signing binds request and result digests and exact fields", () => {
  assert.equal(
    typeof contract.signActionResponse,
    "function",
    "the product must expose response signing for the v2 wire contract",
  );
  assert.equal(
    typeof contract.normalizeActionResponse,
    "function",
    "the client-visible contract must expose fail-closed response normalization",
  );

  const trusted = requestTrustedFixture("backup.prune.plan");
  const key = capabilityKey("backup.prune.plan");
  const request = signedRequest("backup.prune.plan", {}, trusted, 40);
  const result = buildFixtureActionResultV2("backup.prune.plan");
  const unsigned = {
    schema: RESPONSE_SCHEMA_V2,
    status: "completed",
    statusCode: 200,
    errorCode: null,
    action: request.action,
    requestId: request.requestId,
    requestSha256: canonicalSignedRequestSha256(request),
    result,
    resultSha256: fixtureSha256(canonicalFixtureJson(result)),
  };
  const response = contract.signActionResponse(unsigned, key);

  assert.deepEqual(Object.keys(response).sort(), [...RESPONSE_KEYS].sort());
  assert.equal(response.mac, responseMac(unsigned, key));
  assert.equal(
    contract.signActionResponse(Object.fromEntries(Object.entries(unsigned).reverse()), key).mac,
    response.mac,
    "property insertion order must not change the domain-separated response MAC",
  );
  assert.notEqual(
    response.mac,
    crypto.createHmac("sha256", key).update(canonicalFixtureJson(unsigned)).digest("hex"),
    "bare canonical JSON must not authenticate as a v2 response",
  );
  assert.deepEqual(
    contract.normalizeActionResponse(response, request, key),
    response,
  );
  assertResponseBoundToSignedRequestAndResult(response, request);

  const rejectedUnsigned = {
    schema: RESPONSE_SCHEMA_V2,
    status: "rejected",
    statusCode: 403,
    errorCode: "ACTION_REJECTED",
    action: request.action,
    requestId: request.requestId,
    requestSha256: canonicalSignedRequestSha256(request),
    result: null,
    resultSha256: fixtureSha256(canonicalFixtureJson(null)),
  };
  const rejected = contract.signActionResponse(rejectedUnsigned, key);
  assert.deepEqual(Object.keys(rejected).sort(), [...RESPONSE_KEYS].sort());
  assert.equal(rejected.mac, responseMac(rejectedUnsigned, key));
  assert.deepEqual(
    contract.normalizeActionResponse(rejected, request, key),
    rejected,
    "an admitted request rejection must be authenticated and bound to that exact request",
  );
  assertResponseBoundToSignedRequestAndResult(rejected, request);
  assert.throws(
    () => contract.normalizeActionResponse(
      { ...rejected, errorCode: "OTHER_REJECTION" },
      request,
      key,
    ),
    undefined,
    "an unauthenticated rejected response mutation must fail",
  );

  const exactIdentityMutations = [];
  const nestedActionCollisions = exactActionIdentityCollisions(request.action);
  assert.deepEqual(
    nestedActionCollisions
      .filter(([, nestedAction]) => identityBlindEndsWithActionMutant(
        nestedAction,
        request.action,
      ))
      .map(([label]) => label),
    ["authenticated expected-suffix action"],
    "the active response identity-blind endsWith mutant must admit only the hostile expected-suffix collision",
  );
  for (const [position, nestedAction] of nestedActionCollisions) {
    exactIdentityMutations.push(
      [`response action ${position}`, responseWithRecomputedSeals({
        ...unsigned,
        action: nestedAction,
      }, result), /action|binding|identity/i],
      [`result action ${position}`, responseWithRecomputedSeals(unsigned, {
        ...result,
        action: nestedAction,
      }), /action|result|binding|identity/i],
      [`response/result action ${position}`, responseWithRecomputedSeals({
        ...unsigned,
        action: nestedAction,
      }, {
        ...result,
        action: nestedAction,
      }), /action|result|binding|identity/i, identityBlindEndsWithActionMutant(
        nestedAction,
        request.action,
      )],
    );
  }
  const expectedPhaseId = result.phases[0].phaseId;
  for (const [position, nestedPhaseId] of [
    ["suffix", `${expectedPhaseId}.nested`],
    ["prefix", `nested.${expectedPhaseId}`],
  ]) {
    exactIdentityMutations.push(
      [`phase identity ${position}`, responseWithRecomputedSeals(unsigned, {
        ...result,
        phases: [{ ...result.phases[0], phaseId: nestedPhaseId }],
      }), /phase|plan|binding|identity/i],
    );
  }

  const signedMutations = [
    ["extra field", { ...unsigned, extension: "not-allowed" }],
    ["cross-action", { ...unsigned, action: "backup.catalog" }],
    ...exactIdentityMutations,
    ["cross-request ID", { ...unsigned, requestId: "123e4567-e89b-42d3-a456-426614174999" }],
    ["request digest", { ...unsigned, requestSha256: "0".repeat(64) }],
    ["requestId-only digest", {
      ...unsigned,
      requestSha256: fixtureSha256(request.requestId),
    }],
    ["result without matching digest", {
      ...unsigned,
      result: buildFixtureActionResultV2("backup.catalog"),
    }],
    ["result digest", { ...unsigned, resultSha256: "0".repeat(64) }],
    ["result action coherently rebound", responseWithResealedResult(unsigned, {
      ...result,
      action: "backup.catalog",
    })],
    ["result phase coherently rebound", responseWithResealedResult(unsigned, {
      ...result,
      phases: buildFixtureActionResultV2("backup.catalog").phases,
    })],
    ["result phase output schema coherently rebound", responseWithResealedResult(unsigned, {
      ...result,
      phases: [{
        ...result.phases[0],
        outputSchema: EXPECTED_PHASE_PROFILES["catalog.capture"].outputSchema,
      }],
    })],
    ["result extension", responseWithResealedResult(unsigned, {
      ...result,
      extension: "not-allowed",
    })],
    ["fixed action result gains job identity", responseWithResealedResult(unsigned, {
      ...result,
      job: {
        jobFileName: "0123456789abcdef.json",
        jobId: "0123456789abcdef",
        jobOperation: "backup",
        jobSha256: "1".repeat(64),
      },
    })],
    ["phase output without matching digest", responseWithResealedResult(unsigned, {
      ...result,
      phases: [{ ...result.phases[0], output: { arbitrary: "bytes" } }],
    })],
    ["phase output coherently rebound", responseWithResealedResult(unsigned, {
      ...result,
      phases: [{
        ...result.phases[0],
        output: buildFixtureActionResultV2("backup.catalog").phases[0].output,
        outputSha256: buildFixtureActionResultV2("backup.catalog").phases[0].outputSha256,
      }],
    })],
    ["phase result extension", responseWithResealedResult(unsigned, {
      ...result,
      phases: [{ ...result.phases[0], extension: "not-allowed" }],
    })],
    ["duplicate phase result", responseWithResealedResult(unsigned, {
      ...result,
      phases: [result.phases[0], result.phases[0]],
    })],
    ["missing phase result", responseWithResealedResult(unsigned, {
      ...result,
      phases: [],
    })],
    ["invalid worker output digest", responseWithResealedResult(unsigned, {
      ...result,
      phases: [{ ...result.phases[0], outputSha256: "A".repeat(64) }],
    })],
    ["oversized bounded worker output", responseWithResealedResult(unsigned, {
      ...result,
      phases: [phaseResultWithResealedOutput(result.phases[0], {
        ...result.phases[0].output,
        retainedManifestIds: Array.from(
          { length: 512 },
          (_, index) => `manifest:${String(index).padStart(4, "0")}`,
        ),
      })],
    })],
    ["completed response with an error code", { ...unsigned, errorCode: "ACTION_REJECTED" }],
    ["rejected response without an error code", {
      ...rejectedUnsigned,
      errorCode: null,
    }],
    ["rejected response with a success status", {
      ...rejectedUnsigned,
      statusCode: 200,
    }],
  ];
  for (const [
    label,
    mutation,
    exactIdentityError,
    identityBlindEndsWithAdmission,
  ] of signedMutations) {
    const candidate = { ...mutation, mac: responseMac(mutation, key) };
    if (!exactIdentityError) {
      assert.throws(
        () => contract.normalizeActionResponse(candidate, request, key),
        undefined,
        label,
      );
      continue;
    }
    assertAuthenticatedResponseEnvelope(candidate, key, label);
    if (identityBlindEndsWithAdmission) {
      assert.equal(
        candidate.action,
        candidate.result.action,
        `${label} must coherently bind the same hostile action in response and result`,
      );
      assert.notEqual(
        candidate.action,
        request.action,
        `${label} must remain an actually distinct hostile identity`,
      );
      assert.equal(
        identityBlindEndsWithActionMutant(candidate.action, request.action),
        true,
        `${label} must be admitted by the active identity-blind endsWith mutant`,
      );
    }
    const error = captureThrownError(
      () => contract.normalizeActionResponse(candidate, request, key),
      exactIdentityError,
      `${label} must fail only at exact canonical identity binding`,
    );
    assert.doesNotMatch(
      error.message,
      /authentication|mac|schema|digest/i,
      `${label} must not be rejected for authentication, schema or digest`,
    );
  }
  assert.throws(
    () => contract.normalizeActionResponse({ ...response, mac: "0".repeat(64) }, request, key),
    undefined,
    "MAC mutation",
  );
});

test("RED v2: response consumer admits the v2 domain control and rejects legacy or request-domain MACs", async (t) => {
  const trusted = requestTrustedFixture("backup.prune.plan");
  const key = capabilityKey("backup.prune.plan");
  const request = signedRequest("backup.prune.plan", {}, trusted, 41);
  const result = buildFixtureActionResultV2("backup.prune.plan");
  const unsigned = responseUnsigned(request, result);
  const valid = { ...unsigned, mac: responseMac(unsigned, key) };
  const candidates = [
    [
      "bare legacy canonical JSON",
      {
        ...unsigned,
        mac: crypto
          .createHmac("sha256", key)
          .update(canonicalFixtureJson(unsigned))
          .digest("hex"),
      },
    ],
    [
      "request-domain MAC",
      {
        ...unsigned,
        mac: crypto
          .createHmac("sha256", key)
          .update(REQUEST_MAC_DOMAIN)
          .update(canonicalFixtureJson(unsigned))
          .digest("hex"),
      },
    ],
  ];

  await t.test("positive v2 response-domain control reaches the consumer", (st) => {
    if (!responseConsumerV2Ready(st)) return;
    assert.deepEqual(contract.normalizeActionResponse(valid, request, key), valid);
    assertResponseBoundToSignedRequestAndResult(valid, request);
  });
  for (const [label, candidate] of candidates) {
    await t.test(label, (st) => {
      if (!responseConsumerV2Ready(st)) return;
      assert.deepEqual(
        contract.normalizeActionResponse(valid, request, key),
        valid,
        `${label} negative is meaningful only after the correct domain is admitted`,
      );
      assert.throws(
        () => contract.normalizeActionResponse(candidate, request, key),
        /authentication|mac/i,
        `${label} must reach and fail response authentication`,
      );
    });
  }
});

test("RED v2: typed job result is bound to the exact request operation, job identity and phase", async (t) => {
  const trusted = requestTrustedFixture("backup.job.execute");
  const key = capabilityKey("backup.job.execute");
  const parameters = {
    jobFileName: "0123456789abcdef.json",
    jobId: "0123456789abcdef",
    jobOperation: "backup",
    jobSha256: "1".repeat(64),
  };
  const request = signedRequest("backup.job.execute", parameters, trusted, 42);
  const result = buildFixtureActionResultV2("backup.job.execute", parameters);
  const validUnsigned = responseUnsigned(request, result);
  const valid = { ...validUnsigned, mac: responseMac(validUnsigned, key) };

  await t.test("positive exact job and phase control", (st) => {
    if (!responseConsumerV2Ready(st)) return;
    assert.deepEqual(contract.normalizeActionResponse(valid, request, key), valid);
    assertResponseBoundToSignedRequestAndResult(valid, request);
  });

  const restoreParameters = {
    ...parameters,
    jobOperation: "restore-drill",
    jobSha256: "3".repeat(64),
  };
  const reboundIdentityParameters = {
    ...parameters,
    jobFileName: "fedcba9876543210.json",
    jobId: "fedcba9876543210",
    jobSha256: "2".repeat(64),
  };
  const prefixedIdentityParameters = {
    ...parameters,
    jobId: `nested-${parameters.jobId}`,
    jobFileName: `nested-${parameters.jobId}.json`,
  };
  const suffixedIdentityParameters = {
    ...parameters,
    jobId: `${parameters.jobId}-nested`,
    jobFileName: `${parameters.jobId}-nested.json`,
  };
  const mutations = [
    ["valid operation and phase rebind", buildFixtureActionResultV2(
      "backup.job.execute",
      restoreParameters,
    ), restoreParameters],
    ["valid job identity rebind", buildFixtureActionResultV2(
      "backup.job.execute",
      reboundIdentityParameters,
    ), reboundIdentityParameters],
    ["valid phase rebind with original operation", {
      ...result,
      phases: buildFixtureActionResultV2("backup.job.execute", restoreParameters).phases,
    }],
    ["job identity prefix lookalike", resultWithCoherentJobIdentity(
      result,
      prefixedIdentityParameters,
    ), prefixedIdentityParameters],
    ["job identity suffix lookalike", resultWithCoherentJobIdentity(
      result,
      suffixedIdentityParameters,
    ), suffixedIdentityParameters],
  ];
  for (const [index, [label, mutatedResult, coherentParameters]] of mutations.entries()) {
    await t.test(label, (st) => {
      if (!responseConsumerV2Ready(st)) return;
      assert.deepEqual(
        contract.normalizeActionResponse(valid, request, key),
        valid,
        `${label} negative is meaningful only after the exact request-bound result is admitted`,
      );
      if (coherentParameters) {
        const coherentRequest = signedRequest(
          "backup.job.execute",
          coherentParameters,
          trusted,
          50 + index,
        );
        const coherentUnsigned = responseUnsigned(coherentRequest, mutatedResult);
        const coherentSealed = responseWithRecomputedSeals(coherentUnsigned, mutatedResult);
        const coherent = { ...coherentSealed, mac: responseMac(coherentSealed, key) };
        assertAuthenticatedResponseEnvelope(coherent, key, `${label} coherent control`);
        assert.deepEqual(
          contract.normalizeActionResponse(coherent, coherentRequest, key),
          coherent,
          `${label} must first be admitted as an internally coherent result for its own request`,
        );
        assertResponseBoundToSignedRequestAndResult(coherent, coherentRequest);
      }
      const candidateUnsigned = responseWithRecomputedSeals(validUnsigned, mutatedResult);
      const candidate = { ...candidateUnsigned, mac: responseMac(candidateUnsigned, key) };
      assertAuthenticatedResponseEnvelope(candidate, key, label);
      assert.equal(
        candidate.resultSha256,
        fixtureSha256(canonicalFixtureJson(candidate.result)),
        `${label} must reseal the internally coherent result before request binding is tested`,
      );
      const error = captureThrownError(
        () => contract.normalizeActionResponse(candidate, request, key),
        /result|job|operation|phase|identity|binding/i,
        `${label} must not authenticate a coherent valid-to-valid result rebind`,
      );
      if (label.includes("lookalike")) {
        assert.doesNotMatch(
          error.message,
          /authentication|mac|schema|digest/i,
          `${label} must fail only at exact job identity binding`,
        );
      }
    });
  }
});

test("RED v2: active receipt binds exact action plans to phase-scoped Docker authority", () => {
  const receipt = activeReceiptFixture();
  const normalized = contract.normalizeActiveReceipt(receipt, { now: NOW });

  assert.equal(contract.ACTIVE_RECEIPT_SCHEMA, ACTIVE_RECEIPT_SCHEMA_V2);
  assert.equal(normalized.schema, ACTIVE_RECEIPT_SCHEMA_V2);
  assert.deepEqual(Object.keys(receipt).sort(), [...ACTIVE_RECEIPT_KEYS].sort());
  assert.deepEqual(Object.keys(receipt.resources).sort(), [...ACTIVE_RECEIPT_RESOURCE_KEYS].sort());
  assert.deepEqual(
    Object.keys(receipt.resources.actionProfiles).sort(),
    [...SCHEDULER_ACTION_NAMES].sort(),
  );
  assert.deepEqual(
    Object.keys(receipt.resources.phaseProfiles).sort(),
    Object.keys(EXPECTED_PHASE_PROFILES).sort(),
  );

  for (const action of SCHEDULER_ACTION_NAMES) {
    const profile = receipt.resources.actionProfiles[action];
    const expected = expectedActionPhases(action);
    const capabilityId = capabilityFileId(action);
    assert.deepEqual(Object.keys(profile).sort(), [...ACTION_PROFILE_KEYS].sort(), action);
    assert.equal(profile.profileId, EXPECTED_ACTION_BINDINGS[action].profileId);
    assert.equal(profile.profileSha256, profileDigest(profile), `${action} profile digest`);
    assert.equal(profile.capabilityFileId, capabilityId);
    assert.equal(profile.claimedJobSourceId, expectedClaimedJobSourceId(action));
    assert.deepEqual(profile.jobOperations, expected.jobOperations);
    assert.deepEqual(profile.operationPhaseIds, expected.operationPhaseIds);
    assert.deepEqual(profile.phaseIds, expected.phaseIds);
    assert.ok(receipt.resources.capabilityFiles[capabilityId]);
    assert.equal(
      receipt.resources.capabilityFiles[capabilityId].sha256,
      fixtureSha256(fixtureCapabilityKey(action)),
    );
  }

  for (const [phaseId, profile] of Object.entries(receipt.resources.phaseProfiles)) {
    const expected = expectedPhaseProfile(phaseId);
    assert.deepEqual(Object.keys(profile).sort(), [...PHASE_PROFILE_KEYS].sort(), phaseId);
    assert.equal(profile.phaseId, phaseId);
    assert.equal(profile.phaseSha256, phaseDigest(profile), `${phaseId} digest`);
    for (const field of [
      "command",
      "endpointIds",
      "helperProfileIds",
      "mountIds",
      "mutationPolicy",
      "networkIds",
      "outputSchema",
      "scratchVolumeIds",
      "workerSecretSetIds",
      "writableSubpathIds",
    ]) {
      assert.deepEqual(profile[field], expected[field], `${phaseId}.${field}`);
    }
    assert.match(profile.workerImageId, /^sha256:[a-f0-9]{64}$/);
    assert.match(profile.workerImageRef, /@sha256:[a-f0-9]{64}$/);
    for (const mountId of profile.mountIds) assert.ok(receipt.resources.mounts[mountId], mountId);
    for (const networkId of profile.networkIds) assert.ok(receipt.resources.networks[networkId], networkId);
    for (const volumeId of profile.scratchVolumeIds) assert.ok(receipt.resources.volumes[volumeId], volumeId);
    for (const setId of profile.workerSecretSetIds) {
      assert.ok(receipt.resources.workerSecretSets[setId], setId);
      assert.equal(setId.startsWith("capability."), false);
    }
    for (const subpathId of profile.writableSubpathIds) {
      assert.ok(receipt.resources.writableSubpaths[subpathId], subpathId);
    }
    assert.equal(
      profile.mountIds.includes("backup.root.ro") && profile.mountIds.includes("backup.root.rw"),
      false,
      `${phaseId} cannot receive both backup-root alternatives`,
    );
  }

  assert.deepEqual(receipt.resources.phaseProfiles["job.restore.verify"].networkIds, []);
  assert.deepEqual(receipt.resources.phaseProfiles["restore.verify"].networkIds, []);
  assert.deepEqual(receipt.resources.phaseProfiles["offsite.sync"].networkIds, ["platform_egress"]);
  assert.equal(
    Object.entries(receipt.resources.phaseProfiles)
      .filter(([phaseId]) => phaseId !== "offsite.sync")
      .some(([, profile]) => profile.networkIds.includes("platform_egress")),
    false,
  );
  assert.equal(
    receipt.resources.volumes["jobs.queue"].engineName,
    "platform_infra_vps_backup_scheduler_jobs",
  );
  assert.equal(receipt.resources.claimedJobSources["jobs.running"].volumeId, "jobs.queue");
  assert.equal(receipt.resources.claimedJobSources["jobs.running"].brokerRoot, "/run/platform/backup-jobs/running");
  assert.equal(
    receipt.resources.claimedJobSources["jobs.running"].snapshotVolumeId,
    "broker.state",
  );
  assert.equal(
    receipt.resources.claimedJobSources["jobs.running"].snapshotContainerPath,
    "/run/platform/claimed-job/job.json",
  );
  assert.equal(
    receipt.resources.claimedJobSources["jobs.running"].snapshotVolumeSubpath,
    "claimed-jobs",
  );
  assert.equal(
    receipt.resources.volumes["broker.state"].engineName,
    "platform_infra_vps_docker_action_broker_state",
  );
  assert.equal(receipt.resources.writableSubpaths["backup.quarantine"].device, 42);
  assert.equal(receipt.resources.mounts["backup.root.rw"].device, 42);
  assert.equal(receipt.resources.volumes["backup.quarantine"], undefined);

  const invalid = [
    ["top-level extension", (value) => { value.extension = true; }],
    ["resources extension", (value) => { value.resources.extension = {}; }],
    ["missing capability map", (value) => { delete value.resources.capabilityFiles; }],
    ["missing scheduler action", (value) => { delete value.resources.actionProfiles["backup.catalog"]; }],
    ["evidence mixed into scheduler profiles", (value) => {
      value.resources.actionProfiles["evidence.runtime.snapshot"] =
        structuredClone(value.resources.actionProfiles["backup.catalog"]);
    }],
    ["action extension", (value) => {
      value.resources.actionProfiles["backup.catalog"].extension = true;
    }],
    ["action digest mismatch", (value) => {
      value.resources.actionProfiles["backup.catalog"].profileSha256 = "0".repeat(64);
    }, false],
    ["duplicate action profile identity", (value) => {
      value.resources.actionProfiles["backup.catalog"].profileId =
        value.resources.actionProfiles["backup.job.execute"].profileId;
    }],
    ["canonical phase plan substitution", (value) => {
      value.resources.actionProfiles["backup.catalog"].phaseIds = ["prune.plan"];
    }],
    ["fixed action gains operation", (value) => {
      value.resources.actionProfiles["backup.catalog"].jobOperations = ["backup"];
    }],
    ["job operation is duplicated", (value) => {
      value.resources.actionProfiles["backup.job.execute"].jobOperations = ["backup", "backup"];
    }],
    ["job operation mapping is missing", (value) => {
      delete value.resources.actionProfiles["backup.job.execute"].operationPhaseIds.backup;
    }],
    ["fixed action gains operation mapping", (value) => {
      value.resources.actionProfiles["backup.catalog"].operationPhaseIds = {
        backup: ["catalog.capture"],
      };
    }],
    ["job action gains fixed phase union", (value) => {
      value.resources.actionProfiles["backup.job.execute"].phaseIds = [
        "job.backup.capture",
        "job.restore.verify",
      ];
    }],
    ["dangling claimed source", (value) => {
      value.resources.actionProfiles["backup.job.execute"].claimedJobSourceId = "jobs.missing";
    }],
    ["fixed action gains claimed source", (value) => {
      value.resources.actionProfiles["backup.catalog"].claimedJobSourceId = "jobs.running";
    }],
    ["missing phase", (value) => { delete value.resources.phaseProfiles["prune.apply"]; }],
    ["phase extension", (value) => {
      value.resources.phaseProfiles["prune.plan"].extension = true;
    }],
    ["phase digest mismatch", (value) => {
      value.resources.phaseProfiles["prune.plan"].phaseSha256 = "0".repeat(64);
    }, false],
    ["phase ID substitution", (value) => {
      value.resources.phaseProfiles["prune.plan"].phaseId = "prune.apply";
    }],
    ["phase command substitution", (value) => {
      value.resources.phaseProfiles["restore.verify"].command = "restore-full";
    }],
    ["phase output schema substitution", (value) => {
      value.resources.phaseProfiles["restore.verify"].outputSchema = "platform.generic/v1";
    }],
    ["restore phase gains DB network", (value) => {
      value.resources.phaseProfiles["restore.verify"].networkIds = ["platform_db_admin"];
    }],
    ["non-offsite phase gains egress", (value) => {
      value.resources.phaseProfiles["catalog.capture"].networkIds = ["platform_egress"];
    }],
    ["offsite loses egress", (value) => {
      value.resources.phaseProfiles["offsite.sync"].networkIds = [];
    }],
    ["phase has duplicate network", (value) => {
      value.resources.phaseProfiles["catalog.capture"].networkIds = [
        "platform_db_admin",
        "platform_db_admin",
      ];
    }],
    ["phase has dangling mount", (value) => {
      value.resources.phaseProfiles["catalog.capture"].mountIds = ["missing.mount"];
    }],
    ["phase gains RO and RW backup roots", (value) => {
      value.resources.phaseProfiles["restore.verify"].mountIds = [
        "backup.root.ro",
        "backup.root.rw",
        "report.root.rw",
      ];
    }],
    ["phase has dangling secret set", (value) => {
      value.resources.phaseProfiles["offsite.sync"].workerSecretSetIds = ["missing.secret-set"];
    }],
    ["capability referenced as worker set", (value) => {
      value.resources.phaseProfiles["offsite.sync"].workerSecretSetIds = [
        "capability.backup.offsite.sync",
      ];
    }],
    ["phase has dangling scratch volume", (value) => {
      value.resources.phaseProfiles["restore.verify"].scratchVolumeIds = ["missing.volume"];
    }],
    ["phase has dangling writable subpath", (value) => {
      value.resources.phaseProfiles["prune.apply"].writableSubpathIds = ["missing.subpath"];
    }],
    ["quarantine leaves backup filesystem", (value) => {
      value.resources.writableSubpaths["backup.quarantine"].device = 99;
    }],
    ["quarantine uses RO parent", (value) => {
      value.resources.writableSubpaths["backup.quarantine"].mountId = "backup.root.ro";
    }],
    ["quarantine path traversal", (value) => {
      value.resources.writableSubpaths["backup.quarantine"].relativePath = "../quarantine";
    }],
    ["queue volume substitution", (value) => {
      value.resources.volumes["jobs.queue"].engineName = "attacker_queue";
    }],
    ["queue source points to other volume", (value) => {
      value.resources.claimedJobSources["jobs.running"].volumeId = "restore.scratch";
    }],
    ["queue root traversal", (value) => {
      value.resources.claimedJobSources["jobs.running"].brokerRoot =
        "/run/platform/backup-jobs/../queued";
    }],
    ["snapshot points to queue volume", (value) => {
      value.resources.claimedJobSources["jobs.running"].snapshotVolumeId = "jobs.queue";
    }],
    ["snapshot worker path substitution", (value) => {
      value.resources.claimedJobSources["jobs.running"].snapshotContainerPath =
        "/run/platform/claimed-job/../forged.json";
    }],
    ["snapshot volume subpath traversal", (value) => {
      value.resources.claimedJobSources["jobs.running"].snapshotVolumeSubpath =
        "../claimed-jobs";
    }],
    ["broker state volume substitution", (value) => {
      value.resources.volumes["broker.state"].engineName = "attacker_broker_state";
    }],
    ["queue is unbounded", (value) => {
      value.resources.claimedJobSources["jobs.running"].maximumBytes = Number.MAX_SAFE_INTEGER;
    }],
    ["missing evidence capability", (value) => {
      delete value.resources.capabilityFiles["capability.evidence.runtime.snapshot"];
    }],
    ["capability path substitution", (value) => {
      value.resources.capabilityFiles["capability.backup.catalog"].brokerPath =
        "/run/secrets/docker_action_backup_prune_plan";
    }],
    ["secret-set volume substitution", (value) => {
      value.resources.workerSecretSets["manifest.signing"].volumeId = "jobs.queue";
    }],
    ["secret-set path traversal", (value) => {
      value.resources.workerSecretSets["offsite.credentials"].files.password.relativePath = "../password";
    }],
    ["worker file extension", (value) => {
      value.resources.workerSecretSets["manifest.verification"].files.key.extension = true;
    }],
    ["network extension", (value) => {
      value.resources.networks.platform_egress.extension = true;
    }],
    ["volume extension", (value) => {
      value.resources.volumes["restore.scratch"].extension = true;
    }],
    ["backup root is not root-private", (value) => {
      value.resources.mounts["backup.root.ro"].mode = 0o755;
    }],
  ];
  for (const [label, mutate, reseal = true] of invalid) {
    const candidate = structuredClone(receipt);
    mutate(candidate);
    if (reseal) resealActionProfiles(candidate);
    assert.throws(
      () => contract.normalizeActiveReceipt(candidate, { now: NOW }),
      undefined,
      label,
    );
  }
});

test("RED v2: active receipt binds exact service endpoints and helper profiles to each phase", () => {
  const receipt = activeReceiptFixture();
  const normalized = contract.normalizeActiveReceipt(receipt, { now: NOW });

  assert.deepEqual(receipt.resources.serviceEndpoints, EXPECTED_SERVICE_ENDPOINTS);
  assert.deepEqual(receipt.resources.helperProfiles, EXPECTED_HELPER_PROFILES);
  for (const [endpointId, endpoint] of Object.entries(normalized.resources.serviceEndpoints)) {
    assert.deepEqual(Object.keys(endpoint).sort(), [...SERVICE_ENDPOINT_KEYS].sort(), endpointId);
    assert.equal(endpoint.endpointId, endpointId);
    assert.deepEqual(endpoint, EXPECTED_SERVICE_ENDPOINTS[endpointId]);
    assert.ok(normalized.resources.networks[endpoint.networkId], endpoint.networkId);
    if (endpoint.purpose === "capture") {
      assert.ok(normalized.resources.backupResources[endpoint.backupResourceId], endpoint.backupResourceId);
      assert.ok(normalized.resources.containers[endpoint.targetContainerId], endpoint.targetContainerId);
    } else {
      assert.equal(endpoint.backupResourceId, null);
      assert.equal(endpoint.targetContainerId, null);
    }
  }
  for (const [helperProfileId, helperProfile] of Object.entries(normalized.resources.helperProfiles)) {
    assert.deepEqual(Object.keys(helperProfile).sort(), [...HELPER_PROFILE_KEYS].sort(), helperProfileId);
    assert.equal(helperProfile.helperProfileId, helperProfileId);
    assert.deepEqual(helperProfile, EXPECTED_HELPER_PROFILES[helperProfileId]);
    assert.match(helperProfile.imageRef, /@sha256:[a-f0-9]{64}$/);
    assert.notEqual(helperProfile.imageRef.split("@").at(-1), helperProfile.imageId);
    assert.equal(Array.isArray(helperProfile.entrypoint), true);
    assert.equal(helperProfile.entrypoint.length, 1);
  }
  for (const [phaseId, profile] of Object.entries(normalized.resources.phaseProfiles)) {
    const expected = EXPECTED_PHASE_ENDPOINT_HELPER_IDS[phaseId];
    assert.deepEqual(profile.endpointIds, expected.endpointIds, `${phaseId}.endpointIds`);
    assert.deepEqual(profile.helperProfileIds, expected.helperProfileIds, `${phaseId}.helperProfileIds`);
    for (const endpointId of profile.endpointIds) {
      const endpoint = normalized.resources.serviceEndpoints[endpointId];
      assert.ok(endpoint, `${phaseId}/${endpointId}`);
      assert.ok(profile.networkIds.includes(endpoint.networkId), `${phaseId}/${endpoint.networkId}`);
    }
    for (const helperProfileId of profile.helperProfileIds) {
      assert.ok(normalized.resources.helperProfiles[helperProfileId], `${phaseId}/${helperProfileId}`);
    }
  }
});

test("RED v2: phase worker registry and config image digests are independent exact attestations", () => {
  const receipt = activeReceiptFixture();
  const profile = receipt.resources.phaseProfiles["catalog.capture"];
  assert.match(profile.workerImageRef, /@sha256:[a-f0-9]{64}$/);
  assert.match(profile.workerImageId, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(profile.workerImageRef.split("@").at(-1), profile.workerImageId);
  assert.doesNotThrow(() => contract.normalizeActiveReceipt(receipt, { now: NOW }));

  for (const [label, mutate] of [
    ["registry manifest digest", (value) => {
      value.resources.phaseProfiles["catalog.capture"].workerImageRef = "registry.example/platform/worker:latest";
    }],
    ["config image digest", (value) => {
      value.resources.phaseProfiles["catalog.capture"].workerImageId = "sha256:invalid";
    }],
  ]) {
    const candidate = structuredClone(receipt);
    mutate(candidate);
    resealActionProfiles(candidate);
    assert.throws(
      () => contract.normalizeActiveReceipt(candidate, { now: NOW }),
      /phase|worker image|digest|binding|invalid/i,
      label,
    );
  }
});

test("RED v2: endpoint and helper authority rejects canonical widening and coherent resealing", () => {
  const control = activeReceiptFixture();
  assert.doesNotThrow(() => contract.normalizeActiveReceipt(structuredClone(control), { now: NOW }));
  const cases = [
    ["missing endpoint", (value) => { delete value.resources.serviceEndpoints["capture.database.postgres"]; }],
    ["endpoint extension", (value) => { value.resources.serviceEndpoints["capture.database.postgres"].extension = true; }],
    ["endpoint key substitution", (value) => {
      value.resources.serviceEndpoints["capture.database.postgres"].endpointId = "capture.database.mariadb";
    }],
    ["endpoint resource substitution", (value) => {
      value.resources.serviceEndpoints["capture.database.postgres"].backupResourceId = "database:mariadb";
    }],
    ["endpoint target substitution", (value) => {
      value.resources.serviceEndpoints["capture.database.postgres"].targetContainerId = "mariadb";
    }],
    ["endpoint host widening", (value) => { value.resources.serviceEndpoints["capture.database.postgres"].host = "attacker"; }],
    ["endpoint port widening", (value) => { value.resources.serviceEndpoints["capture.database.postgres"].port = 15432; }],
    ["endpoint network widening", (value) => {
      value.resources.serviceEndpoints["capture.database.postgres"].networkId = "platform_egress";
    }],
    ["endpoint TLS downgrade", (value) => { value.resources.serviceEndpoints["capture.database.postgres"].tlsMode = "none"; }],
    ["endpoint engine widening", (value) => { value.resources.serviceEndpoints["capture.database.postgres"].engine = "mariadb"; }],
    ["endpoint secret widening", (value) => {
      value.resources.serviceEndpoints["capture.database.postgres"].secretSetId = "manifest.signing";
    }],
    ["offsite endpoint becomes local", (value) => {
      value.resources.serviceEndpoints["offsite.repository"].targetContainerId = "postgres";
    }],
    ["missing helper", (value) => { delete value.resources.helperProfiles["helper.capture.postgres"]; }],
    ["helper extension", (value) => { value.resources.helperProfiles["helper.capture.postgres"].extension = true; }],
    ["helper key substitution", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].helperProfileId = "helper.capture.mariadb";
    }],
    ["helper entrypoint widening", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].entrypoint = ["sh"];
    }],
    ["helper operation widening", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].operation = "restore";
    }],
    ["helper resource kind widening", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].resourceKind = "source";
    }],
    ["helper network widening", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].networkId = "platform_egress";
    }],
    ["helper secret widening", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].secretSetId = "offsite.credentials";
    }],
    ["helper output widening", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].outputMode = "json";
    }],
    ["helper image reference substitution", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].imageRef = MARIADB_IMAGE_REF;
    }],
    ["helper image ID invalid", (value) => {
      value.resources.helperProfiles["helper.capture.postgres"].imageId = "sha256:invalid";
    }],
    ["phase gains endpoint", (value) => {
      value.resources.phaseProfiles["prune.plan"].endpointIds = ["offsite.repository"];
    }],
    ["phase substitutes helper", (value) => {
      value.resources.phaseProfiles["job.backup.capture"].helperProfileIds = ["helper.offsite.restic"];
    }],
    ["phase overlaps worker and helper credentials", (value) => {
      value.resources.phaseProfiles["catalog.capture"].workerSecretSetIds = [
        "manifest.signing",
        "postgres.capture.credentials",
      ];
    }],
    ["phase endpoint loses owning network", (value) => {
      value.resources.phaseProfiles["catalog.capture"].networkIds = ["platform_storage"];
    }],
  ];
  for (const [label, mutate] of cases) {
    const candidate = structuredClone(control);
    mutate(candidate);
    resealActionProfiles(candidate);
    assert.throws(
      () => contract.normalizeActiveReceipt(candidate, { now: NOW }),
      /endpoint|helper|phase|network|authority|identity|binding|unsupported|missing|canonical/i,
      label,
    );
  }
});

test("RED v2: coherent valid-to-valid receipt rebinds cannot be accepted after exact resealing", async (t) => {
  const control = activeReceiptFixture();
  const cases = [
    ["action-key ownership", (value) => {
      const catalog = structuredClone(value.resources.actionProfiles["backup.catalog"]);
      const prune = structuredClone(value.resources.actionProfiles["backup.prune.plan"]);
      value.resources.actionProfiles["backup.catalog"] = prune;
      value.resources.actionProfiles["backup.prune.plan"] = catalog;
    }],
    ["canonical profile identity", (value) => {
      value.resources.actionProfiles["backup.catalog"].profileId =
        EXPECTED_ACTION_BINDINGS["backup.prune.plan"].profileId;
    }],
    ["phase-key ownership", (value) => {
      const catalog = structuredClone(value.resources.phaseProfiles["catalog.capture"]);
      const prune = structuredClone(value.resources.phaseProfiles["prune.plan"]);
      value.resources.phaseProfiles["catalog.capture"] = prune;
      value.resources.phaseProfiles["prune.plan"] = catalog;
    }],
    ["canonical capability ownership", (value) => {
      value.resources.actionProfiles["backup.catalog"].capabilityFileId =
        capabilityFileId("backup.prune.plan");
    }],
    ["canonical resource ownership", (value) => {
      const brokerState = structuredClone(value.resources.volumes["broker.state"]);
      const queue = structuredClone(value.resources.volumes["jobs.queue"]);
      value.resources.volumes["broker.state"] = queue;
      value.resources.volumes["jobs.queue"] = brokerState;
    }],
  ];

  for (const [label, mutate] of cases) {
    await t.test(label, (st) => {
      if (!activeReceiptV2Ready(st)) return;
      assert.doesNotThrow(
        () => contract.normalizeActiveReceipt(structuredClone(control), { now: NOW }),
        `${label} negative is meaningful only after the exact v2 control is admitted`,
      );
      const candidate = structuredClone(control);
      mutate(candidate);
      resealActionProfiles(candidate);
      assert.throws(
        () => contract.normalizeActiveReceipt(candidate, { now: NOW }),
        /action|profile|phase|capability|resource|volume|identity|binding/i,
        `${label} must reject a coherent reseal made from individually valid identities`,
      );
    });
  }
});

test("RED v2: signed runtime intent detects every Release-owned receipt reference mutation", async (t) => {
  const mutations = [
    ["coherent worker image substitution", (value) => {
      const profile = value.resources.phaseProfiles["catalog.capture"];
      const digest = alternateSha256(profile.workerImageId.slice("sha256:".length));
      profile.workerImageId = `sha256:${digest}`;
      profile.workerImageRef = profile.workerImageRef.replace(
        /sha256:[a-f0-9]{64}$/,
        `sha256:${digest}`,
      );
    }],
    ["capability file digest", (value) => {
      const file = value.resources.capabilityFiles["capability.backup.catalog"];
      file.sha256 = alternateSha256(file.sha256);
    }],
    ["worker verification file digest", (value) => {
      const file = value.resources.workerSecretSets["manifest.verification"].files.key;
      file.sha256 = alternateSha256(file.sha256);
    }],
    ["mount inode", (value) => { value.resources.mounts["backup.root.ro"].inode += 1; }],
    ["network identity", (value) => {
      const network = value.resources.networks.platform_egress;
      network.engineId = alternateSha256(network.engineId);
    }],
    ["volume options", (value) => {
      const volume = value.resources.volumes["restore.scratch"];
      volume.optionsSha256 = alternateSha256(volume.optionsSha256);
    }],
  ];
  for (const [label, mutate] of mutations) {
    await t.test(label, (st) => {
      if (!activeReceiptV2Ready(st)) return;
      const {
        intent,
        rawReceipt: receipt,
        receiptDigest,
        trusted,
      } = buildTrustedContextV2(contract, {
        allowedActions: SCHEDULER_ACTION_NAMES,
        now: NOW,
        trustKey: TRUST_KEY,
      });
      assert.match(intent.mac, /^[a-f0-9]{64}$/);
      assert.equal(trusted.receiptDigest, intent.activeReceiptSha256);
      assert.equal(trusted.receiptDigest, receiptDigest);
      assert.equal(
        fixtureSha256(canonicalFixtureJson(
          contract.normalizeActiveReceipt(structuredClone(receipt), { now: NOW }),
        )),
        receiptDigest,
        `${label} negative is meaningful only after the original receipt normalizes`,
      );
      assert.doesNotThrow(
        () => contract.normalizeTrustedContext(intent, receipt, TRUST_KEY, { now: NOW }),
        `${label} negative is meaningful only after the original signed lineage is admitted`,
      );

      const candidate = structuredClone(receipt);
      mutate(candidate);
      resealActionProfiles(candidate);
      const normalizedCandidate = contract.normalizeActiveReceipt(candidate, { now: NOW });
      const candidateDigest = fixtureSha256(canonicalFixtureJson(normalizedCandidate));
      assert.notEqual(candidateDigest, receiptDigest, `${label} must alter signed receipt lineage`);
      assert.throws(
        () => contract.normalizeTrustedContext(intent, candidate, TRUST_KEY, { now: NOW }),
        /receipt digest|does not match/i,
        `${label} must cross semantic receipt admission and fail only at signed intent lineage`,
      );
    });
  }
});

function requestTrustedFixture(action) {
  return buildFixtureTrustedContextV2({
    allowedActions: [action],
    now: NOW,
  }).trusted;
}

function signedRequest(action, parameters, trusted, index) {
  return buildFixtureSignedActionRequestV2(action, parameters, {
    capabilityKey: capabilityKey(action),
    index,
    now: NOW,
    trustedContext: trusted,
  });
}

function activeReceiptFixture() {
  return buildRawActiveReceiptV2({ now: NOW });
}

function responseMac(unsigned, key) {
  return crypto
    .createHmac("sha256", key)
    .update(RESPONSE_MAC_DOMAIN)
    .update(canonicalFixtureJson(unsigned))
    .digest("hex");
}

function responseUnsigned(request, result) {
  return {
    schema: RESPONSE_SCHEMA_V2,
    status: "completed",
    statusCode: 200,
    errorCode: null,
    action: request.action,
    requestId: request.requestId,
    requestSha256: canonicalSignedRequestSha256(request),
    result,
    resultSha256: fixtureSha256(canonicalFixtureJson(result)),
  };
}

function responseWithResealedResult(unsigned, result) {
  return {
    ...unsigned,
    result,
    resultSha256: fixtureSha256(canonicalFixtureJson(result)),
  };
}

function responseWithRecomputedSeals(unsigned, result) {
  const resealed = structuredClone(result);
  resealed.phases = resealed.phases.map(
    (phase) => phaseResultWithResealedOutput(phase, phase.output),
  );
  return responseWithResealedResult(unsigned, resealed);
}

function assertAuthenticatedResponseEnvelope(response, key, label) {
  assert.deepEqual(Object.keys(response).sort(), [...RESPONSE_KEYS].sort(), label);
  assert.equal(response.schema, RESPONSE_SCHEMA_V2, `${label} response schema`);
  assert.equal(response.result.schema, RESULT_SCHEMA_V2, `${label} result schema`);
  for (const phase of response.result.phases) {
    assert.equal(
      phase.outputSha256,
      fixtureSha256(canonicalFixtureJson(phase.output)),
      `${label} output digest`,
    );
  }
  assert.equal(
    response.resultSha256,
    fixtureSha256(canonicalFixtureJson(response.result)),
    `${label} result digest`,
  );
  assert.equal(
    response.mac,
    responseMac(omit(response, "mac"), key),
    `${label} must carry a valid independently recomputed response MAC`,
  );
}

function resultWithCoherentJobIdentity(result, parameters) {
  const mutated = structuredClone(result);
  mutated.job = structuredClone(parameters);
  mutated.phases = mutated.phases.map((phase) => {
    const output = {
      ...phase.output,
      jobId: parameters.jobId,
      jobOperation: parameters.jobOperation,
    };
    return phaseResultWithResealedOutput(phase, output);
  });
  return mutated;
}

function phaseResultWithResealedOutput(phaseResult, output) {
  return {
    ...phaseResult,
    output,
    outputSha256: fixtureSha256(canonicalFixtureJson(output)),
  };
}

function requestMac(unsigned, key) {
  return crypto
    .createHmac("sha256", key)
    .update(REQUEST_MAC_DOMAIN)
    .update(canonicalFixtureJson(unsigned))
    .digest("hex");
}

function exactActionIdentityCollisions(expectedAction) {
  return [
    ["authenticated expected-prefix dot action", `${expectedAction}.nested`],
    ["authenticated expected-suffix action", `nested.${expectedAction}`],
  ];
}

function identityBlindEndsWithActionMutant(candidateAction, expectedAction) {
  return candidateAction.endsWith(expectedAction);
}

function grammarBlindExactRegistryLookupMutant(request) {
  const action = String(request.action ?? "");
  if (!Object.hasOwn(EXPECTED_ACTION_BINDINGS, action)) {
    throw new Error("action is unknown to the exact registry");
  }
  return action;
}

function assertActionGrammarFailure(operation, label) {
  const error = captureThrownError(operation, undefined, `${label} must be rejected`);
  assert.match(
    error.message,
    /action.*(?:grammar|syntax|format|logical[ -]?id)/i,
    `${label} must fail specifically at action grammar before registry lookup`,
  );
  assert.doesNotMatch(
    error.message,
    /(?:registry|unknown|not authorized|not enabled|unsupported|binding|identity|authentication|mac|schema|digest)/i,
    `${label} must not be classified as a registry, identity, authentication or digest failure`,
  );
  return error;
}

function captureThrownError(operation, expected, message) {
  let captured;
  assert.throws(
    () => {
      try {
        operation();
      } catch (error) {
        captured = error;
        throw error;
      }
    },
    expected,
    message,
  );
  assert.ok(captured instanceof Error, `${message}: thrown Error was not captured`);
  return captured;
}

function canonicalSignedRequestSha256(request) {
  assert.deepEqual(
    Object.keys(request).sort(),
    [...REQUEST_KEYS].sort(),
    "requestSha256 requires the exact complete signed request",
  );
  assert.match(request.mac, /^[a-f0-9]{64}$/);
  return fixtureSha256(canonicalFixtureJson(request));
}

function assertCompleteSignedRequestBoundary(observed, expected, label) {
  assert.ok(
    observed
      && typeof observed === "object"
      && !Array.isArray(observed)
      && Object.getPrototypeOf(observed) === Object.prototype,
    `${label} must receive the complete signed request as a plain object`,
  );
  assert.deepEqual(
    Object.keys(observed).sort(),
    [...REQUEST_KEYS].sort(),
    `${label} must receive the complete signed request`,
  );
  assert.deepEqual(
    observed,
    expected,
    `${label} must preserve every authenticated request field byte-for-byte`,
  );
  const expectedSha256 = canonicalSignedRequestSha256(expected);
  assert.equal(
    canonicalSignedRequestSha256(observed),
    expectedSha256,
    `${label} must preserve sha256 of the canonical full signed request`,
  );
  assert.notEqual(
    expectedSha256,
    fixtureSha256(expected.requestId),
    `${label} must not collapse request identity to requestId`,
  );
  assert.deepEqual(
    observed.parameters,
    expected.parameters,
    `${label} must preserve the exact admitted parameters`,
  );
  return expectedSha256;
}

function assertTrustedRequestLineage(lineage, request, trusted, label) {
  assert.ok(lineage && typeof lineage === "object", `${label} lineage is missing`);
  const requestSha256 = assertCompleteSignedRequestBoundary(
    lineage.request,
    request,
    `${label} lineage request`,
  );
  assert.equal(lineage.action, request.action, `${label} action lineage`);
  assert.equal(lineage.requestId, request.requestId, `${label} requestId lineage`);
  assert.equal(
    lineage.requestSha256,
    requestSha256,
    `${label} must bind sha256 of the canonical full signed request`,
  );
  assert.notEqual(
    lineage.requestSha256,
    fixtureSha256(request.requestId),
    `${label} lineage must not use a requestId-only digest`,
  );
  assert.equal(lineage.intentId, trusted.intent.intentId, `${label} runtime intent lineage`);
  assert.equal(lineage.receiptDigest, trusted.receiptDigest, `${label} receipt lineage`);
  assert.equal(
    lineage.request.runtimeIntentId,
    trusted.intent.intentId,
    `${label} signed request must retain trusted intent identity`,
  );
  assert.equal(
    lineage.request.activeReceiptSha256,
    trusted.receiptDigest,
    `${label} signed request must retain trusted receipt identity`,
  );
}

function assertSemanticCoreContext(context, request, trusted, lease, label) {
  assert.ok(context && typeof context === "object", `${label} is missing`);
  assert.deepEqual(
    Object.keys(context).sort(),
    [
      "lease",
      "parameters",
      "request",
      "requestId",
      "requestSha256",
      "signal",
      "trusted",
    ],
    `${label} must expose the exact semantic request lineage`,
  );
  const requestSha256 = assertCompleteSignedRequestBoundary(
    context.request,
    request,
    `${label} request`,
  );
  assert.equal(context.requestId, request.requestId, `${label} requestId`);
  assert.equal(
    context.requestSha256,
    requestSha256,
    `${label} must bind sha256 of the canonical full signed request`,
  );
  assert.notEqual(
    context.requestSha256,
    fixtureSha256(request.requestId),
    `${label} must not use a requestId-only digest`,
  );
  assert.deepEqual(
    context.parameters,
    request.parameters,
    `${label} must carry the exact request parameters`,
  );
  assert.strictEqual(context.trusted, trusted, `${label} must carry the exact trusted context`);
  assert.strictEqual(context.lease, lease, `${label} must carry the acquired lease`);
  assertTrustedRequestLineage(context.lease.lineage, request, trusted, `${label} lease`);
  assert.ok(
    context.signal && typeof context.signal.aborted === "boolean",
    `${label} must carry an AbortSignal`,
  );
}

function assertResponseBoundToSignedRequestAndResult(response, request) {
  const requestSha256 = canonicalSignedRequestSha256(request);
  assert.equal(
    response.requestSha256,
    requestSha256,
    "response requestSha256 must bind the complete canonical signed request",
  );
  assert.notEqual(
    response.requestSha256,
    fixtureSha256(request.requestId),
    "requestId alone is not a request identity digest",
  );
  assert.equal(
    response.resultSha256,
    fixtureSha256(canonicalFixtureJson(response.result)),
    "response resultSha256 must bind the complete canonical result",
  );
  if (response.result !== null) assertResultBoundToRequest(response.result, request);
}

function evidenceBrokerHarness({ key, result, trusted }) {
  const leaseEvents = [];
  let executions = 0;
  const replayStore = {
    acquire() {
      leaseEvents.push("acquire");
      return {
        preserve() {
          leaseEvents.push("preserve");
        },
        recordWorker() {},
        release() {
          leaseEvents.push("release");
        },
      };
    },
    admitActivation() {},
    admitTrustedContext() {},
    consume() {},
  };
  const core = createBrokerCore({
    trustedContextProvider: async () => trusted,
    capabilityProvider: async () => key,
    engine: {
      async execute() {
        executions += 1;
        return structuredClone(result);
      },
    },
    replayStore,
    now: () => NOW,
    operationTimeoutMs: 100,
  });
  return {
    core,
    executeCount: () => executions,
    leaseEvents,
  };
}

function capabilityKey(action) {
  return fixtureCapabilityKey(action);
}

function admittedRequestShape(request) {
  return {
    action: request.action,
    capabilityId: request.capabilityId,
    parameters: structuredClone(request.parameters),
    requestId: request.requestId,
    nonce: request.nonce,
    runtimeIntentId: request.runtimeIntentId,
    activeReceiptSha256: request.activeReceiptSha256,
    combinedRenderSha256: request.combinedRenderSha256,
  };
}

function assertResultBoundToRequest(result, request) {
  assert.equal(result.schema, RESULT_SCHEMA_V2);
  assert.deepEqual(Object.keys(result).sort(), [...RESULT_KEYS].sort());
  assert.equal(result.action, request.action);
  assert.equal(result.status, "completed");
  const isEvidence = request.action === "evidence.runtime.snapshot";
  const plan = EXPECTED_ACTION_PHASES[request.action] ?? null;
  assert.ok(isEvidence || plan, `missing fixture action plan for ${request.action}`);
  const isJob = request.action === "backup.job.execute";
  if (isJob) {
    assert.deepEqual(Object.keys(result.job).sort(), [...RESULT_JOB_KEYS].sort());
    assert.deepEqual(result.job, request.parameters);
  } else {
    assert.equal(result.job, null);
  }
  const expectedPhaseIds = isEvidence
    ? [EXPECTED_EVIDENCE_RESULT_PHASE.phaseId]
    : isJob
      ? plan.operationPhaseIds[request.parameters.jobOperation]
      : plan.phaseIds;
  assert.ok(result.phases.length >= 1 && result.phases.length <= 2);
  assert.deepEqual(
    result.phases.map(({ phaseId }) => phaseId),
    expectedPhaseIds,
    "result phases must preserve the canonical request action/operation plan and order",
  );
  const expectedResult = buildFixtureActionResultV2(request.action, request.parameters);
  for (const [index, phaseResult] of result.phases.entries()) {
    assert.deepEqual(Object.keys(phaseResult).sort(), [...RESULT_PHASE_KEYS].sort());
    assert.equal(phaseResult.status, "completed");
    assert.equal(
      phaseResult.outputSchema,
      isEvidence
        ? EXPECTED_EVIDENCE_RESULT_PHASE.outputSchema
        : EXPECTED_PHASE_PROFILES[phaseResult.phaseId].outputSchema,
    );
    assert.deepEqual(
      phaseResult.output,
      expectedResult.phases[index].output,
      `${phaseResult.phaseId} output must be the bounded action-specific worker schema`,
    );
    assert.equal(
      phaseResult.outputSha256,
      fixtureSha256(canonicalFixtureJson(phaseResult.output)),
    );
    assert.ok(
      Buffer.byteLength(canonicalFixtureJson(phaseResult.output)) <= MAX_PHASE_OUTPUT_BYTES_V2,
      `${phaseResult.phaseId} output exceeds the bounded response contract`,
    );
  }
}

function requestConsumerV2Ready(t) {
  if (contract.REQUEST_SCHEMA === REQUEST_SCHEMA_V2) return true;
  t.todo("blocked until the product request schema reaches v2");
  return false;
}

function responseConsumerV2Ready(t) {
  if (typeof contract.normalizeActionResponse === "function") return true;
  t.todo("blocked until the product exports the v2 response consumer");
  return false;
}

function activeReceiptV2Ready(t) {
  if (contract.ACTIVE_RECEIPT_SCHEMA === ACTIVE_RECEIPT_SCHEMA_V2) return true;
  t.todo("blocked until the product active receipt schema reaches v2");
  return false;
}

function alternateSha256(value) {
  assert.match(value, /^[a-f0-9]{64}$/);
  return `${value[0] === "0" ? "1" : "0"}${value.slice(1)}`;
}

function omit(value, key) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

function assertUnique(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} values must be unique`);
}
