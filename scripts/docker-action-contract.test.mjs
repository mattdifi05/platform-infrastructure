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
  EXPECTED_PHASE_PROFILES,
  FIXTURE_NOW,
  FIXTURE_TRUST_KEY,
  REQUEST_SCHEMA_V2,
  RESPONSE_SCHEMA_V2,
  PHASE_PROFILE_KEYS,
  SCHEDULER_ACTION_NAMES,
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
  assert.equal(contract.REQUEST_SCHEMA, REQUEST_SCHEMA_V2);
  const trusted = requestTrustedFixture("backup.catalog");
  const unsigned = {
    ...contract.buildUnsignedRequest("backup.catalog", {}, trusted, {
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174000",
      nonce: "A".repeat(43),
    }),
    schema: REQUEST_SCHEMA_V2,
  };
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

test("RED v2: every capability is action-distinct and bound to the attested file bytes", () => {
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

  const wrongDigestReceipt = activeReceiptFixture();
  wrongDigestReceipt.resources.capabilityFiles[capabilityFileId(action)].sha256 = "0".repeat(64);
  const wrongDigestTrusted = buildTrustedContextV2(contract, {
    allowedActions: [action],
    now: NOW,
    rawReceipt: wrongDigestReceipt,
    trustKey: TRUST_KEY,
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

test("RED v2: typed job parameters preserve real identifiers and reject normalization or aliases", () => {
  assert.equal(contract.REQUEST_SCHEMA, REQUEST_SCHEMA_V2);
  assert.deepEqual(
    Object.keys(contract.SCHEDULER_ACTIONS ?? {}).sort(),
    [...SCHEDULER_ACTION_NAMES].sort(),
    "typed scheduler requests require the exact v2 scheduler registry",
  );
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
    const request = signedRequest("backup.job.execute", parameters, trusted, index);
    const normalized = contract.normalizeActionRequest(request, trusted, key, { now: NOW });
    assert.deepEqual(Object.keys(normalized.parameters).sort(), [
      "jobFileName",
      "jobId",
      "jobOperation",
      "jobSha256",
    ]);
    assert.deepEqual(normalized.parameters, parameters, "admitted job identity must be byte-exact");
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
  for (const [label, parameters] of invalid) {
    const request = signedRequest("backup.job.execute", parameters, trusted, 20);
    assert.throws(
      () => contract.normalizeActionRequest(request, trusted, key, { now: NOW }),
      undefined,
      label,
    );
  }
});

test("RED v2: broker core emits the exact authenticated response wire contract", async () => {
  const trusted = requestTrustedFixture("backup.prune.plan");
  const key = capabilityKey("backup.prune.plan");
  const request = signedRequest("backup.prune.plan", {}, trusted, 30);
  const result = { mode: "plan", mutationPerformed: false };
  const replayStore = {
    acquire() {
      return { preserve() {}, recordWorker() {}, release() {} };
    },
    admitActivation() {},
    admitTrustedContext() {},
    consume() {},
  };
  const core = createBrokerCore({
    trustedContextProvider: async () => trusted,
    capabilityProvider: async () => key,
    engine: { execute: async () => result },
    replayStore,
    now: () => NOW,
    operationTimeoutMs: 100,
  });

  const wire = await core.handle(Buffer.from(JSON.stringify(request)));
  const response = wire.body;
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const resultSha256 = fixtureSha256(canonicalFixtureJson(result));

  assert.equal(wire.statusCode, 200);
  assert.deepEqual(Object.keys(response).sort(), [...RESPONSE_KEYS].sort());
  assert.equal(response.schema, RESPONSE_SCHEMA_V2);
  assert.equal(response.status, "completed");
  assert.equal(response.statusCode, 200);
  assert.equal(response.errorCode, null);
  assert.equal(response.action, request.action);
  assert.equal(response.requestId, request.requestId);
  assert.equal(response.requestSha256, requestSha256);
  assert.equal(response.resultSha256, resultSha256);
  assert.deepEqual(response.result, result);
  assert.equal(response.mac, responseMac(omit(response, "mac"), key));
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
  const result = { mode: "plan", mutationPerformed: false };
  const unsigned = {
    schema: RESPONSE_SCHEMA_V2,
    status: "completed",
    statusCode: 200,
    errorCode: null,
    action: request.action,
    requestId: request.requestId,
    requestSha256: fixtureSha256(canonicalFixtureJson(request)),
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

  const rejectedUnsigned = {
    schema: RESPONSE_SCHEMA_V2,
    status: "rejected",
    statusCode: 403,
    errorCode: "ACTION_REJECTED",
    action: request.action,
    requestId: request.requestId,
    requestSha256: fixtureSha256(canonicalFixtureJson(request)),
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
  assert.throws(
    () => contract.normalizeActionResponse(
      { ...rejected, errorCode: "OTHER_REJECTION" },
      request,
      key,
    ),
    undefined,
    "an unauthenticated rejected response mutation must fail",
  );

  const signedMutations = [
    ["extra field", { ...unsigned, extension: "not-allowed" }],
    ["cross-action", { ...unsigned, action: "backup.catalog" }],
    ["cross-request ID", { ...unsigned, requestId: "123e4567-e89b-42d3-a456-426614174999" }],
    ["request digest", { ...unsigned, requestSha256: "0".repeat(64) }],
    ["result without matching digest", { ...unsigned, result: { mode: "apply", mutationPerformed: true } }],
    ["result digest", { ...unsigned, resultSha256: "0".repeat(64) }],
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
  for (const [label, mutation] of signedMutations) {
    const candidate = { ...mutation, mac: responseMac(mutation, key) };
    assert.throws(
      () => contract.normalizeActionResponse(candidate, request, key),
      undefined,
      label,
    );
  }
  assert.throws(
    () => contract.normalizeActionResponse({ ...response, mac: "0".repeat(64) }, request, key),
    undefined,
    "MAC mutation",
  );
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
    ["capability digest substitution", (value) => {
      value.resources.capabilityFiles["capability.backup.catalog"].sha256 = "9".repeat(64);
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
    ["network ID substitution", (value) => {
      value.resources.networks.platform_egress.engineId = "9".repeat(64);
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

test("RED v2: signed runtime intent detects every Release-owned receipt reference mutation", () => {
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

  const mutations = [
    ["coherent worker image substitution", (value) => {
      value.resources.phaseProfiles["catalog.capture"].workerImageId = `sha256:${"8".repeat(64)}`;
      value.resources.phaseProfiles["catalog.capture"].workerImageRef =
        `registry.example/platform/docker-action-substitute@sha256:${"8".repeat(64)}`;
    }],
    ["phase plan substitution", (value) => {
      value.resources.actionProfiles["backup.catalog"].phaseIds = ["prune.plan"];
    }],
    ["capability file digest", (value) => {
      value.resources.capabilityFiles["capability.backup.catalog"].sha256 = "9".repeat(64);
    }],
    ["worker verification file digest", (value) => {
      value.resources.workerSecretSets["manifest.verification"].files.key.sha256 = "8".repeat(64);
    }],
    ["mount inode", (value) => { value.resources.mounts["backup.root.ro"].inode += 1; }],
    ["network identity", (value) => {
      value.resources.networks.platform_egress.engineId = "9".repeat(64);
    }],
    ["volume options", (value) => {
      value.resources.volumes["restore.scratch"].optionsSha256 = "f".repeat(64);
    }],
    ["claimed queue identity", (value) => {
      value.resources.volumes["jobs.queue"].engineName = "attacker_queue";
    }],
    ["quarantine same-device binding", (value) => {
      value.resources.writableSubpaths["backup.quarantine"].device = 99;
    }],
  ];
  for (const [label, mutate] of mutations) {
    const candidate = structuredClone(receipt);
    mutate(candidate);
    resealActionProfiles(candidate);
    const normalizedCandidate = contract.normalizeActiveReceipt(candidate, { now: NOW });
    const candidateDigest = fixtureSha256(canonicalFixtureJson(normalizedCandidate));
    assert.notEqual(candidateDigest, receiptDigest, `${label} must alter signed receipt lineage`);
    assert.throws(
      () => contract.normalizeTrustedContext(intent, candidate, TRUST_KEY, { now: NOW }),
      /receipt digest|does not match/i,
      label,
    );
  }
});

function requestTrustedFixture(action) {
  return buildTrustedContextV2(contract, {
    allowedActions: [action],
    now: NOW,
    trustKey: TRUST_KEY,
  }).trusted;
}

function signedRequest(action, parameters, trusted, index) {
  const suffix = String(index).padStart(12, "0");
  const unsigned = contract.buildUnsignedRequest(action, parameters, trusted, {
    now: NOW,
    requestId: `123e4567-e89b-42d3-a456-${suffix}`,
    nonce: Buffer.alloc(32, index + 1).toString("base64url"),
  });
  return contract.signActionRequest(unsigned, capabilityKey(action));
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

function requestMac(unsigned, key) {
  return crypto
    .createHmac("sha256", key)
    .update(REQUEST_MAC_DOMAIN)
    .update(canonicalFixtureJson(unsigned))
    .digest("hex");
}

function capabilityKey(action) {
  return fixtureCapabilityKey(action);
}

function omit(value, key) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

function assertUnique(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} values must be unique`);
}
