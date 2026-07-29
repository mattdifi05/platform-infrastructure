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
  const trusted = requestTrustedFixture("backup.prune.plan");
  const key = capabilityKey("backup.prune.plan");
  const request = signedRequest("backup.prune.plan", {}, trusted, 30);
  const result = buildFixtureActionResultV2("backup.prune.plan");
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
  assertResultBoundToRequest(response.result, request);
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
  const result = buildFixtureActionResultV2("backup.prune.plan");
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
  assertResultBoundToRequest(response.result, request);

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
    assertResultBoundToRequest(valid.result, request);
  });

  const restoreParameters = {
    ...parameters,
    jobOperation: "restore-drill",
    jobSha256: "3".repeat(64),
  };
  const mutations = [
    ["valid operation and phase rebind", buildFixtureActionResultV2(
      "backup.job.execute",
      restoreParameters,
    )],
    ["valid job identity rebind", {
      ...result,
      job: {
        ...result.job,
        jobFileName: "job-0123456789abcdef.json",
        jobId: "job-0123456789abcdef",
      },
    }],
    ["valid phase rebind with original operation", {
      ...result,
      phases: buildFixtureActionResultV2("backup.job.execute", restoreParameters).phases,
    }],
  ];
  for (const [label, mutatedResult] of mutations) {
    await t.test(label, (st) => {
      if (!responseConsumerV2Ready(st)) return;
      assert.deepEqual(
        contract.normalizeActionResponse(valid, request, key),
        valid,
        `${label} negative is meaningful only after the exact request-bound result is admitted`,
      );
      const candidateUnsigned = responseWithResealedResult(validUnsigned, mutatedResult);
      const candidate = { ...candidateUnsigned, mac: responseMac(candidateUnsigned, key) };
      assert.throws(
        () => contract.normalizeActionResponse(candidate, request, key),
        /result|job|operation|phase/i,
        `${label} must not authenticate a coherent valid-to-valid result rebind`,
      );
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

test("RED v2: signed runtime intent detects every Release-owned receipt reference mutation", (t) => {
  if (!activeReceiptV2Ready(t)) return;
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
    requestSha256: fixtureSha256(canonicalFixtureJson(request)),
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

function omit(value, key) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

function assertUnique(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} values must be unique`);
}
