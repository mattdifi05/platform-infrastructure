import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { BACKUP_JOB_SCHEMA } from "../control-center/backup/contracts.mjs";
import * as broker from "./docker-action-broker.mjs";
import * as actionContract from "./docker-action-contract.mjs";
import * as client from "./docker-action-client.mjs";
import {
  buildFixtureActionResultV2,
  buildFixturePhaseOutputV2,
  buildFixtureSignedActionRequestV2,
  buildFixtureTrustedContextV2,
  buildFixtureVolumeInspect,
  fixtureCapabilityKey,
} from "./docker-action-v2-fixtures.mjs";

const {
  buildClientRequest,
  protectedCapability,
  sendActionRequest,
} = client;

const CAPABILITY = Buffer.alloc(32, 0x61);
const INTENT_ID = "intent.release-1";
const RECEIPT_SHA256 = "b".repeat(64);
const COMBINED_RENDER_SHA256 = "c".repeat(64);
const NOW = Date.parse("2026-07-28T12:00:00.000Z");
const REQUEST_SCHEMA_V2 = "platform.docker-action.request/v2";
const REQUEST_MAC_DOMAIN = `${REQUEST_SCHEMA_V2}\0`;
const RESPONSE_SCHEMA_V2 = "platform.docker-action.response/v2";
const RESPONSE_MAC_DOMAIN = `${RESPONSE_SCHEMA_V2}\0`;
const RESULT_SCHEMA_V2 = "platform.docker-action.result/v2";
const EVIDENCE_PSEUDO_PHASE_ID = "evidence.runtime.snapshot";
const EVIDENCE_OUTPUT_SCHEMA = "platform.docker-runtime-snapshot/v2";
const MAX_CLAIMED_JOB_BYTES = 128 * 1024;
const MAX_SIGNED_REQUEST_BYTES = 16 * 1024;
const MAX_EXECVE_STRING_BYTES = 128 * 1024;
const MAX_PHASE_OUTPUT_BYTES = 4096;
const SAFE_ACTION_IDENTITY = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOCKETLESS_PREIMPORT_GUARD_SYMBOL = Symbol.for(
  "platform-infrastructure.test.socketless-preimport-guard/v1",
);
const SOCKETLESS_SAFE_COHORT_NAMES = Object.freeze([
  ["RED v2: in-memory request producer", " rejects SAFE action affixes before every provider"].join(""),
  ["RED v2: in-memory response producer", " emits no success frame for identity-blind semantic results"].join(""),
  ["RED v2: in-memory core", " crosses the real semantic executor without UDS"].join(""),
]);
const SOCKETLESS_SAFE_COHORT_LABELS = Object.freeze([
  "in-memory request producer SAFE cohort",
  "in-memory response producer SAFE cohort",
  "in-memory semantic executor SAFE cohort",
]);
let socketlessPreimportTodoBodyMustRemainClosed = false;

test("client rejects raw argument injection before constructing a request", () => {
  const control = buildClientRequest("prune-manifest-backups-plan", [], {
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityKey: CAPABILITY,
  });
  assert.equal(control.action, "backup.prune.plan");
  assert.deepEqual(control.parameters, {});
  assert.throws(
    () => buildClientRequest("prune-manifest-backups-plan", ["--hostConfig", "{\"Privileged\":true}"], {
      runtimeIntentId: INTENT_ID,
      activeReceiptSha256: RECEIPT_SHA256,
      combinedRenderSha256: COMBINED_RENDER_SHA256,
      capabilityKey: CAPABILITY,
    }),
    /accepts no parameters/,
  );
  assert.throws(
    () => buildClientRequest("docker", ["run", "--privileged"], {
      runtimeIntentId: INTENT_ID,
      activeReceiptSha256: RECEIPT_SHA256,
      combinedRenderSha256: COMBINED_RENDER_SHA256,
      capabilityKey: CAPABILITY,
    }),
    /Unsupported Docker action command/,
  );
});

test("RED v2: real builder emits the exact fixed schema and domain-separated request MAC", () => {
  const request = buildClientRequest("prune-manifest-backups-plan", [], {
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityKey: CAPABILITY,
    now: Date.parse("2026-07-26T12:00:00.000Z"),
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
  });
  assert.equal(request.schema, REQUEST_SCHEMA_V2);
  assert.deepEqual(Object.keys(request).sort(), [
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
  assert.equal(request.action, "backup.prune.plan");
  assert.deepEqual(request.parameters, {});
  const unsigned = omit(request, "mac");
  assert.equal(request.mac, requestMac(unsigned));
  assert.notEqual(
    request.mac,
    legacyMac(unsigned),
    "a bare v1-compatible canonical JSON MAC must not authenticate a request/v2",
  );
  assert.notEqual(
    request.mac,
    domainMac(RESPONSE_MAC_DOMAIN, unsigned),
    "the response domain must not authenticate a request/v2",
  );
});

test("RED v2: real UDS consumer accepts canonical success and authenticated rejection responses", async (t) => {
  const request = wireRequest();
  assertManualRequestV2(request);
  const result = canonicalActionResultV2(request);
  assertCanonicalActionResultV2(result, request);
  const success = signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result,
  });
  const completed = await exchangeWithLocalBroker(request, success, {
    encodeResponse: canonicalJsonOracle,
  });
  assert.deepEqual(completed, success);

  await t.test("authenticated semantic rejection remains a trusted response", async () => {
    const rejected = signedResponse(request, {
      status: "rejected",
      statusCode: 403,
      errorCode: "ACTION_REJECTED",
      result: null,
    });
    const admitted = await exchangeWithLocalBroker(request, rejected, {
      encodeResponse: canonicalJsonOracle,
    });
    assert.deepEqual(admitted, rejected);
  });
});

test("RED v2: real UDS producer emits one bounded canonical request frame", async () => {
  const request = wireRequest();
  assertManualRequestV2(request);
  const result = canonicalActionResultV2(request);
  const response = signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result,
  });
  const exchange = await invokeWithLocalBroker(
    (socketPath) => sendActionRequest(request, socketPath, CAPABILITY),
    (received) => {
      assert.deepEqual(received, request);
      return response;
    },
    { encodeResponse: canonicalJsonOracle },
  );
  assert.equal(
    exchange.requestWire,
    canonicalJsonOracle(request),
    "the request wire itself, not merely its MAC input, must be canonical JSON",
  );
  assert.ok(
    Buffer.byteLength(exchange.requestWire) <= MAX_SIGNED_REQUEST_BYTES,
    "the exact signed request frame must stay inside the broker's 16 KiB admission bound",
  );
  assert.deepEqual(exchange.value, response);
});

test("RED v2: real UDS consumer rejects the complete authenticated response mutation matrix", async (t) => {
  const request = wireRequest();
  assertManualRequestV2(request);
  const result = canonicalActionResultV2(request);
  assertCanonicalActionResultV2(result, request);
  const valid = signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result,
  });
  const unsigned = omit(valid, "mac");
  const mutations = [
    [
      "schema",
      resignResponse({ ...unsigned, schema: "platform.docker-action.response/v1" }),
      /response schema/i,
    ],
    [
      "cross-action",
      resignResponse({ ...unsigned, action: "backup.catalog" }),
      /response action/i,
    ],
    [
      "cross-request ID",
      resignResponse({ ...unsigned, requestId: "123e4567-e89b-42d3-a456-426614174999" }),
      /response request.*id/i,
    ],
    [
      "request digest",
      resignResponse({ ...unsigned, requestSha256: "0".repeat(64) }),
      /response request.*(?:digest|sha)/i,
    ],
    [
      "result bytes without matching digest",
      resignResponse({
        ...unsigned,
        result: {
          ...result,
          phases: [{
            ...result.phases[0],
            output: {
              ...result.phases[0].output,
              resources: {
                substituted: {},
              },
            },
          }],
        },
      }),
      /response result.*(?:digest|sha)/i,
    ],
    [
      "phase output digest with coherent response digest",
      resignResponseWithResult(unsigned, {
        ...result,
        phases: [{
          ...result.phases[0],
          outputSha256: "0".repeat(64),
        }],
      }),
      /(?:phase|result).*output.*(?:digest|sha)|output.*(?:digest|sha)/i,
    ],
    [
      "result digest",
      resignResponse({ ...unsigned, resultSha256: "0".repeat(64) }),
      /response result.*(?:digest|sha)/i,
    ],
    [
      "exact-key extension",
      resignResponse({ ...unsigned, extension: "not-allowed" }),
      /response.*(?:field|key|extension)/i,
    ],
    [
      "MAC",
      { ...valid, mac: "0".repeat(64) },
      /response.*(?:authentication|mac)/i,
    ],
    [
      "bare legacy MAC",
      { ...unsigned, mac: legacyMac(unsigned) },
      /response.*(?:authentication|mac)/i,
    ],
    [
      "wrong-domain MAC",
      { ...unsigned, mac: domainMac(REQUEST_MAC_DOMAIN, unsigned) },
      /response.*(?:authentication|mac)/i,
    ],
    [
      "non-canonical wire",
      Object.fromEntries(Object.entries(valid).reverse()),
      /response.*(?:canonical|wire)/i,
      JSON.stringify,
    ],
  ];

  for (const [label, candidate, expectedError, encodeResponse = canonicalJsonOracle] of mutations) {
    await t.test(label, async () => {
      const control = await exchangeWithLocalBroker(request, valid, {
        encodeResponse: canonicalJsonOracle,
      });
      assert.deepEqual(control, valid, `${label} control must first reach and pass the real response consumer`);
      await assert.rejects(
        () => exchangeWithLocalBroker(request, candidate, {
          encodeResponse,
        }),
        expectedError,
        `${label} must be rejected by sendActionRequest after the local UDS exchange`,
      );
    });
  }
});

test("RED v2: real UDS consumer requires exactly one canonical response frame and one LF", async (t) => {
  const request = wireRequest();
  assertManualRequestV2(request);
  const result = canonicalActionResultV2(request);
  const valid = signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result,
  });
  const canonical = canonicalJsonOracle(valid);
  const control = await exchangeWithLocalBroker(request, valid, {
    responseFrame: () => `${canonical}\n`,
  });
  assert.deepEqual(control, valid);

  const invalidFrames = [
    ["missing LF", canonical],
    ["two valid response frames", `${canonical}\n${canonical}\n`],
    ["bytes after the only delimited frame", `${canonical}\ntrailing`],
    ["extra trailing LF", `${canonical}\n\n`],
    ["empty delimited frame", "\n"],
  ];
  for (const [label, frame] of invalidFrames) {
    await t.test(label, async () => {
      const positive = await exchangeWithLocalBroker(request, valid, {
        responseFrame: () => `${canonical}\n`,
      });
      assert.deepEqual(positive, valid, `${label} requires a real single-frame positive control`);
      await assert.rejects(
        () => exchangeWithLocalBroker(request, valid, {
          responseFrame: () => frame,
        }),
        /response.*(?:canonical|delimiter|frame|malformed|wire)/i,
        `${label} must be rejected only after reaching the real UDS response consumer`,
      );
    });
  }
});

test("test-only nested response fixture defeats a shallow canonicalizer with a valid MAC", () => {
  const request = wireRequest();
  const canonicalControl = canonicalValueOracle(signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result: canonicalActionResultV2(request),
  }));
  assert.equal(
    JSON.stringify(canonicalControl),
    canonicalJsonOracle(canonicalControl),
    "the independent positive control must already be recursively canonical",
  );
  const nestedNonCanonical = independentlySignedNestedNonCanonicalResponse(
    canonicalControl,
    CAPABILITY,
  );
  assertNestedNonCanonicalResponseFixture(
    nestedNonCanonical,
    canonicalControl,
    CAPABILITY,
  );
});

test("test-only raw response fixtures survive the exact vulnerable self-mutants", () => {
  const request = wireRequest();
  const canonicalControl = canonicalValueOracle(signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result: canonicalActionResultV2(request),
  }));
  const nestedNonCanonical = independentlySignedNestedNonCanonicalResponse(
    canonicalControl,
    CAPABILITY,
  );
  const nestedRawFrame = `${JSON.stringify(nestedNonCanonical)}\n`;
  assert.equal(
    shallowResponseWireMutantAccepts(nestedRawFrame),
    true,
    "the nested-order fixture must survive a validator that sorts only response-level keys",
  );
  assert.equal(
    nestedRawFrame,
    `${shallowCanonicalJsonOracle(nestedNonCanonical)}\n`,
  );
  assert.notEqual(
    nestedRawFrame,
    `${canonicalJsonOracle(nestedNonCanonical)}\n`,
  );

  const actionOnlyResult = canonicalValueOracle({
    ...canonicalControl.result,
    action: "backup.catalog",
  });
  const actionOnly = independentlySignedResponseWithResult(
    canonicalControl,
    actionOnlyResult,
    CAPABILITY,
  );
  assert.equal(
    digestAndMacOnlyResponseMutantAccepts(actionOnly, CAPABILITY),
    true,
    "the identity fixture must survive a validator that checks only result digest and response MAC",
  );
  assert.equal(
    outerPlanIdentityBlindMutantAccepts(actionOnly, canonicalControl, CAPABILITY),
    true,
    "the action-only fixture must survive an identity-blind validator driven by the outer plan",
  );

  const alternateResult = canonicalValueOracle(
    buildFixtureActionResultV2("backup.catalog"),
  );
  const fullyRebound = independentlySignedResponseWithResult(
    canonicalControl,
    alternateResult,
    CAPABILITY,
  );
  assert.equal(
    nestedPlanIdentityBlindMutantAccepts(fullyRebound, CAPABILITY),
    true,
    "the full-result fixture must survive an identity-blind validator driven by the nested plan",
  );
  assert.equal(fullyRebound.action, request.action);
  assert.equal(fullyRebound.result.action, "backup.catalog");
  assert.notEqual(fullyRebound.result.action, fullyRebound.action);
});

// Intentionally not TODO-gated: sendActionRequest is the already-exported
// consumer under test, and this raw frame must bypass every broker encoder.
test("RED v2: real UDS consumer rejects a raw top-level-canonical nested-noncanonical response", async () => {
  assert.equal(
    typeof sendActionRequest,
    "function",
    "the raw client consumer RED must stay active without broker or contract export gates",
  );
  const request = wireRequest();
  const canonicalControl = canonicalValueOracle(signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result: canonicalActionResultV2(request),
  }));
  const canonicalFrame = `${JSON.stringify(canonicalControl)}\n`;
  assert.equal(canonicalFrame, `${canonicalJsonOracle(canonicalControl)}\n`);
  const admitted = await exchangeWithLocalBroker(request, canonicalControl, {
    responseFrame: () => canonicalFrame,
  });
  assert.deepEqual(admitted, canonicalControl);

  const nestedNonCanonical = independentlySignedNestedNonCanonicalResponse(
    canonicalControl,
    CAPABILITY,
  );
  assertNestedNonCanonicalResponseFixture(
    nestedNonCanonical,
    canonicalControl,
    CAPABILITY,
  );
  const rawFrame = `${JSON.stringify(nestedNonCanonical)}\n`;
  assert.equal(
    rawFrame,
    `${shallowCanonicalJsonOracle(nestedNonCanonical)}\n`,
    "the hostile raw frame must pass the exact shallow-client mutant",
  );
  assert.notEqual(
    rawFrame,
    `${canonicalJsonOracle(nestedNonCanonical)}\n`,
    "the hostile raw frame must remain recursively non-canonical",
  );
  await assert.rejects(
    () => exchangeWithLocalBroker(request, nestedNonCanonical, {
      responseFrame: () => rawFrame,
    }),
    /response.*(?:canonical|wire)/i,
    "sendActionRequest must reject the direct raw frame after the real UDS exchange",
  );
});

// Also intentionally active: this semantic identity boundary uses only the
// existing sendActionRequest consumer and an independently signed raw frame.
test("RED v2: real UDS consumer binds result.action to response.action and request.action", async (t) => {
  assert.equal(
    typeof sendActionRequest,
    "function",
    "the nested identity RED must stay active without unrelated export gates",
  );
  const request = wireRequest();
  const canonicalControl = canonicalValueOracle(signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result: canonicalActionResultV2(request),
  }));
  assert.equal(canonicalControl.action, request.action);
  assert.equal(canonicalControl.result.action, canonicalControl.action);
  const admitted = await exchangeWithLocalBroker(request, canonicalControl, {
    responseFrame: () => `${JSON.stringify(canonicalControl)}\n`,
  });
  assert.deepEqual(admitted, canonicalControl);
  assert.equal(admitted.result.action, admitted.action);
  assert.equal(admitted.action, request.action);

  const actionOnlyResult = canonicalValueOracle({
    ...canonicalControl.result,
    action: "backup.catalog",
  });
  const fullyReboundResult = canonicalValueOracle(
    buildFixtureActionResultV2("backup.catalog"),
  );
  const mutations = [
    {
      label: "action-only rebind with the outer request phase plan",
      result: actionOnlyResult,
      selfMutantAccepts(candidate) {
        return outerPlanIdentityBlindMutantAccepts(
          candidate,
          canonicalControl,
          CAPABILITY,
        );
      },
    },
    {
      label: "fully coherent alternate nested action plan",
      result: fullyReboundResult,
      selfMutantAccepts(candidate) {
        return nestedPlanIdentityBlindMutantAccepts(candidate, CAPABILITY);
      },
    },
  ];

  for (const mutation of mutations) {
    await t.test(mutation.label, async () => {
      const candidate = independentlySignedResponseWithResult(
        canonicalControl,
        mutation.result,
        CAPABILITY,
      );
      assert.deepEqual(
        Object.fromEntries(
          Object.entries(candidate)
            .filter(([key]) => !["mac", "result", "resultSha256"].includes(key)),
        ),
        Object.fromEntries(
          Object.entries(canonicalControl)
            .filter(([key]) => !["mac", "result", "resultSha256"].includes(key)),
        ),
        "the mutation must preserve every outer response identity field",
      );
      assert.deepEqual(candidate.result, mutation.result);
      assert.equal(candidate.action, request.action);
      assert.equal(candidate.result.action, "backup.catalog");
      assert.notEqual(candidate.result.action, candidate.action);
      for (const phase of candidate.result.phases) {
        assert.equal(
          phase.outputSha256,
          sha256Bytes(canonicalJsonOracle(phase.output)),
          "the alternate result must retain independently valid phase output digests",
        );
      }
      assert.equal(
        candidate.resultSha256,
        sha256Bytes(canonicalJsonOracle(candidate.result)),
        "the hostile nested result must be coherently re-digested",
      );
      assert.equal(
        candidate.mac,
        domainMacWithKey(RESPONSE_MAC_DOMAIN, omit(candidate, "mac"), CAPABILITY),
        "the hostile response must be coherently re-MACed with the independent oracle",
      );
      assert.equal(
        mutation.selfMutantAccepts(candidate),
        true,
        "the fixture must survive its exact identity-blind validator mutant",
      );
      const rawFrame = `${JSON.stringify(candidate)}\n`;
      assert.equal(rawFrame, `${canonicalJsonOracle(candidate)}\n`);
      await assert.rejects(
        () => exchangeWithLocalBroker(request, candidate, {
          responseFrame: () => rawFrame,
        }),
        "the real client must reject a fully authenticated nested action divergence",
      );
    });
  }
});

test("test-only canonical identity-collision fixtures are fully re-digested and re-MACed", () => {
  const fixture = canonicalIdentityCollisionFixture();

  assert.equal(fixture.request.action, fixture.expectedAction);
  assert.equal(
    JSON.stringify(fixture.request),
    canonicalJsonOracle(fixture.request),
    "the independently signed request control must already be recursively canonical",
  );
  assert.equal(fixture.control.action, fixture.expectedAction);
  assert.equal(fixture.control.result.action, fixture.expectedAction);
  assert.equal(
    fixture.control.result.job.jobId,
    fixture.expectedJobId,
  );
  assert.equal(
    fixture.control.result.phases[0].phaseId,
    fixture.expectedPhaseId,
  );
  assertCanonicalIdentityResponseSeal(
    fixture.control,
    fixture.request,
    fixture.capabilityKey,
  );

  assert.deepEqual(
    fixture.mutations.map(({ label }) => label),
    [
      "action exact prefix plus dotted nested identity",
      "action dotted nested identity plus exact suffix",
      "job identity with the exact job as a prefix",
      "job identity with the exact job as a suffix",
      "phase identity with the exact phase as a prefix",
      "phase identity with the exact phase as a suffix",
    ],
    "the hostile fixture matrix must keep every independently required collision class active",
  );
  assert.deepEqual(
    fixture.mutations.map(({ boundary }) => boundary),
    [
      "exact-identity",
      "exact-identity",
      "exact-identity",
      "exact-identity",
      "exact-identity",
      "exact-identity",
    ],
    "the identity-collision matrix must contain only syntactically SAFE identities",
  );

  for (const mutation of fixture.mutations) {
    const {
      candidate,
      candidateIdentity,
      expectedIdentity,
      layer,
      relationship,
      syntaxPattern,
    } = mutation;
    assert.notEqual(
      candidateIdentity,
      expectedIdentity,
      `${mutation.label} must be a distinct canonical identity`,
    );
    if (relationship === "prefix") {
      assert.equal(
        candidateIdentity.startsWith(expectedIdentity),
        true,
        `${mutation.label} must survive a startsWith identity-blind consumer`,
      );
    } else {
      assert.equal(
        candidateIdentity.endsWith(expectedIdentity),
        true,
        `${mutation.label} must survive an endsWith identity-blind consumer`,
      );
    }
    if (syntaxPattern) {
      assert.match(
        candidateIdentity,
        syntaxPattern,
        `${mutation.label} must itself remain a syntactically valid ${layer} identity`,
      );
    }
    assert.equal(
      JSON.stringify(candidate),
      canonicalJsonOracle(candidate),
      `${mutation.label} must remain recursively canonical on the raw wire`,
    );
    assertCanonicalIdentityResponseSeal(
      candidate,
      fixture.request,
      fixture.capabilityKey,
    );
    assert.equal(
      affixIdentityBlindResponseMutantAccepts(
        candidate,
        fixture.control,
        fixture.request,
        mutation,
        fixture.capabilityKey,
      ),
      true,
      `${mutation.label} must survive a consumer that enforces every non-identity field but uses affix matching`,
    );
    assert.notEqual(
      candidate.resultSha256,
      fixture.control.resultSha256,
      `${mutation.label} must change the independently sealed result`,
    );
    assert.notEqual(
      candidate.mac,
      fixture.control.mac,
      `${mutation.label} must carry a fresh response MAC`,
    );
    if (layer === "job") {
      assert.equal(
        candidate.result.job.jobSha256,
        fixture.control.result.job.jobSha256,
        `${mutation.label} must preserve the exact claimed-byte digest`,
      );
      assert.notEqual(
        candidate.result.phases[0].outputSha256,
        fixture.control.result.phases[0].outputSha256,
        `${mutation.label} must also re-digest the changed worker output identity`,
      );
    } else if (layer === "phase") {
      assert.deepEqual(
        candidate.result.phases[0].output,
        fixture.control.result.phases[0].output,
        `${mutation.label} must isolate the phase identity without changing output semantics`,
      );
    } else {
      assert.deepEqual(
        candidate.result.phases,
        fixture.control.result.phases,
        `${mutation.label} must isolate the action identities without changing the phase plan`,
      );
    }
  }

  assert.deepEqual(
    fixture.control,
    fixture.producerControlSnapshot,
    "constructing hostile identities must not mutate the admitted producer control",
  );
});

test("test-only slash-child fixture is a grammar failure, not an exact-identity collision", () => {
  const fixture = slashChildActionGrammarFixture();
  assert.equal(
    fixture.mutation.candidateIdentity.startsWith(fixture.expectedAction),
    true,
    "the slash-child control must still survive a naive prefix matcher",
  );
  assert.doesNotMatch(
    fixture.mutation.candidateIdentity,
    SAFE_ACTION_IDENTITY,
    "slash-child belongs exclusively to the grammar-rejection boundary",
  );
  assertCanonicalIdentityResponseSeal(
    fixture.mutation.candidate,
    fixture.request,
    fixture.capabilityKey,
  );
  assert.equal(
    affixIdentityBlindResponseMutantAccepts(
      fixture.mutation.candidate,
      fixture.control,
      fixture.request,
      fixture.mutation,
      fixture.capabilityKey,
    ),
    true,
    "the grammar control must remain causal against the explicit prefix-blind mutant",
  );
});

// UDS cohort: intentionally separate from the socketless producer/semantic-
// core cohort below, and excluded from its focused NO-UDS execution.
test("RED v2: real UDS consumer rejects fully sealed SAFE action, job and phase affix collisions", async (t) => {
  const fixture = canonicalIdentityCollisionFixture();
  const admitted = await exchangeWithLocalBroker(
    fixture.request,
    fixture.control,
    {
      capabilityKey: fixture.capabilityKey,
      responseFrame: (response) => `${canonicalJsonOracle(response)}\n`,
    },
  );
  assert.deepEqual(
    admitted,
    fixture.control,
    "the exact producer control must reach and pass the real response consumer first",
  );

  for (const mutation of fixture.mutations) {
    await t.test(mutation.label, async () => {
      const controlSnapshot = structuredClone(fixture.control);
      await assert.rejects(
        () => exchangeWithLocalBroker(
          fixture.request,
          mutation.candidate,
          {
            capabilityKey: fixture.capabilityKey,
            responseFrame: (response) => `${canonicalJsonOracle(response)}\n`,
          },
        ),
        `${mutation.label} must be rejected after the real canonical response exchange`,
      );
      assert.deepEqual(
        fixture.control,
        controlSnapshot,
        `${mutation.label} rejection must not alter the admitted producer state`,
      );
    });
  }
});

// UDS cohort: grammar rejection stays independent from canonical identity
// equality and is likewise NOT_RUN by the focused socketless cohort.
test("RED v2: real UDS consumer rejects the fully sealed slash-child grammar control", async () => {
  const fixture = slashChildActionGrammarFixture();
  const admitted = await exchangeWithLocalBroker(
    fixture.request,
    fixture.control,
    {
      capabilityKey: fixture.capabilityKey,
      responseFrame: (response) => `${canonicalJsonOracle(response)}\n`,
    },
  );
  assert.deepEqual(admitted, fixture.control);
  await assert.rejects(
    () => exchangeWithLocalBroker(
      fixture.request,
      fixture.mutation.candidate,
      {
        capabilityKey: fixture.capabilityKey,
        responseFrame: (response) => `${canonicalJsonOracle(response)}\n`,
      },
    ),
    "the real response consumer must reject slash-child at its grammar boundary",
  );
});

testWhenProductionExports(
  [
    [actionContract, "normalizeActionResponse"],
    [broker, "encodeActionResponseFrame"],
  ],
  "RED v2: production response framing recursively canonicalizes nested signed values",
  async () => {
    const request = wireRequest();
    const canonicalControl = canonicalValueOracle(signedResponse(request, {
      status: "completed",
      statusCode: 200,
      errorCode: null,
      result: canonicalActionResultV2(request),
    }));
    const canonicalFrame = broker.encodeActionResponseFrame(canonicalControl);
    assertProductionResponseFrame(canonicalFrame, canonicalControl);
    const admittedControl = await exchangeWithLocalBroker(request, canonicalControl, {
      responseFrame: () => canonicalFrame,
    });
    assert.deepEqual(admittedControl, canonicalControl);

    const nestedNonCanonical = independentlySignedNestedNonCanonicalResponse(
      canonicalControl,
      CAPABILITY,
    );
    assertNestedNonCanonicalResponseFixture(
      nestedNonCanonical,
      canonicalControl,
      CAPABILITY,
    );

    const encoded = broker.encodeActionResponseFrame(nestedNonCanonical);
    assertProductionResponseFrame(encoded, nestedNonCanonical);
    const admitted = await exchangeWithLocalBroker(request, nestedNonCanonical, {
      responseFrame: () => encoded,
    });
    assert.deepEqual(admitted, nestedNonCanonical);
  },
);

test("test-only assembly gates do not depend on an unrelated semantic-executor export", () => {
  const contractModule = Object.freeze({
    normalizeActionResponse() {},
    signActionResponse() {},
  });
  const brokerModule = Object.freeze({
    encodeActionResponseFrame() {},
  });
  const clientModule = Object.freeze({
    defaultClaimedJobPolicy() {},
    readClaimedBackupJob() {},
    runClientCommand() {},
  });
  const requirementSets = [
    injectedAssemblyRequirements({ brokerModule, contractModule }),
    schedulerMainRequirements({ brokerModule, clientModule, contractModule }),
  ];
  for (const requirements of requirementSets) {
    assert.deepEqual(
      missingProductionExports(requirements),
      [],
      "a gate body must activate when every API it calls is present",
    );
    assert.equal(
      requirements.some(([, exportName]) => exportName === "createSemanticActionExecutor"),
      false,
      "an injected or scheduler assembly body must not become TODO because an unrelated export is absent",
    );
  }
  assert.deepEqual(
    missingProductionExports(
      semanticCoreRequirements({ brokerModule, contractModule }),
    ),
    ["createSemanticActionExecutor"],
    "the socketless semantic-core body must activate only when its real semantic executor exists",
  );
});

test("test-only semantic transport proxy rejects every method outside its exact whitelist", () => {
  const { trusted } = buildFixtureTrustedContextV2({
    allowedActions: ["backup.prune.plan"],
    now: NOW,
  });
  const oracle = exactPrunePlanTransportOracle({
    successRequestId: "123e4567-e89b-42d3-a456-426614174102",
    trusted,
  });
  assert.deepEqual(
    Object.keys(oracle.transport).sort(),
    [
      "createWorker",
      "deleteContainer",
      "inspectContainer",
      "inspectVolume",
      "logsContainer",
      "startContainer",
      "waitContainer",
    ],
  );
  assert.equal(Object.hasOwn(oracle.transport, "execute"), false);
  assert.equal(oracle.transport.execute, undefined);
  assert.throws(
    () => oracle.transport.inspectNetwork,
    /unexpected semantic transport method inspectNetwork/i,
  );
  assert.throws(
    () => oracle.transport.pullImage,
    /unexpected semantic transport method pullImage/i,
  );
  assert.deepEqual(oracle.calls, [], "wrong-method probes must not become admitted transport calls");
});

test("test-only producer, result and semantic-core helpers are permanently NO-UDS", () => {
  assert.equal(
    SAFE_ACTION_IDENTITY.source,
    "^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    "all socketless identity gates must share the one explicit SAFE grammar",
  );
  const source = [
    inMemoryBrokerCoreFixture,
    inMemoryCoreConnection,
    inMemorySemanticExecutorCoreFixture,
  ].map((value) => Function.prototype.toString.call(value)).join("\n");
  assertSocketlessSourceOracle(
    source,
    "the complete in-memory SAFE helper graph",
  );
  assert.match(
    source,
    /\bcreateBrokerCore\b/,
    "the socketless fixture must still cross the real production broker core",
  );
  assert.match(
    source,
    /\bencodeActionResponseFrame\b/,
    "the socketless connection must still cross the real production response encoder",
  );
  const completeTestSource = fs.readFileSync(fileURLToPath(import.meta.url), "utf8");
  assert.match(
    completeTestSource,
    /\nconst withSocketlessNetworkCapabilityTrap = \(\(\) => \{\n/,
    "the audited wrapper must be one exact const initialized by a closure IIFE",
  );
  for (const [index, testName] of SOCKETLESS_SAFE_COHORT_NAMES.entries()) {
    const testBodySource = socketlessSafeCohortBodySource(
      completeTestSource,
      testName,
    );
    assertSocketlessSourceOracle(
      testBodySource,
      `${testName} bounded SAFE body`,
    );
    assertSocketlessCohortCannotAttestWrapperLedger(
      testBodySource,
      `${testName} bounded SAFE body`,
    );
    assertDirectSocketlessWrapperArrow(
      testBodySource,
      SOCKETLESS_SAFE_COHORT_LABELS[index],
      `${testName} registered callback`,
    );
  }
});

test("test-only direct SAFE callback oracle rejects alias and fake-label wrappers", () => {
  const completeTestSource = fs.readFileSync(fileURLToPath(import.meta.url), "utf8");
  for (const [index, testName] of SOCKETLESS_SAFE_COHORT_NAMES.entries()) {
    const exactLabel = SOCKETLESS_SAFE_COHORT_LABELS[index];
    const bodySource = socketlessSafeCohortBodySource(completeTestSource, testName);
    assertDirectSocketlessWrapperArrow(bodySource, exactLabel, testName);

    const aliased = bodySource.replace(
      "withSocketlessNetworkCapabilityTrap(",
      "invokeSocketlessTrapAlias(",
    );
    assert.throws(
      () => assertDirectSocketlessWrapperArrow(aliased, exactLabel, `${testName} alias mutant`),
      /must start with a direct call to the const socketless wrapper and exact SAFE label/i,
    );

    const relabeled = bodySource.replace(`"${exactLabel}"`, `"${exactLabel}.forged"`);
    assert.throws(
      () => assertDirectSocketlessWrapperArrow(relabeled, exactLabel, `${testName} label mutant`),
      /must start with a direct call to the const socketless wrapper and exact SAFE label/i,
    );
  }
});

test("test-only NO-UDS oracle kills computed, aliased and builtin-module network mutants", async (t) => {
  await t.test("socketless positive fixture records exactly zero capability calls", async () => {
    await withSocketlessNetworkCapabilityTrap(
      "active socketless positive fixture",
      async () => {
        const value = await Promise.resolve({ status: "socketless" });
        assert.deepEqual(value, { status: "socketless" });
      },
    );
  });

  const mutants = [
    {
      blockedAttempt: "net.createServer",
      invoke() {
        return net["createServer"](() => {});
      },
      label: "bracket createServer",
      source: `function mutant() { return net["createServer"](() => {}); }`,
    },
    {
      blockedAttempt: "net.createServer",
      invoke() {
        const { createServer: openServer } = net;
        return openServer(() => {});
      },
      label: "destructured createServer alias",
      source: `function mutant() { const { createServer: openServer } = net; return openServer(() => {}); }`,
    },
    {
      blockedAttempt: "net.createServer",
      invoke() {
        const openServer = net.createServer;
        return openServer(() => {});
      },
      label: "property createServer alias",
      source: `function mutant() { const openServer = net.createServer; return openServer(() => {}); }`,
    },
    {
      blockedAttempt: "process.getBuiltinModule",
      invoke() {
        return process.getBuiltinModule("node:net").createServer(() => {});
      },
      label: "process builtin-module escape",
      source: `function mutant() { return process.getBuiltinModule("node:net").createServer(() => {}); }`,
    },
    {
      blockedAttempt: "net.createServer",
      invoke() {
        const method = ["create", "Server"].join("");
        return Reflect.get(net, method)(() => {});
      },
      label: "Reflect.get computed createServer",
      source: `function mutant() { return Reflect.get(net, ["create", "Server"].join(""))(() => {}); }`,
    },
  ];

  for (const mutant of mutants) {
    await t.test(mutant.label, async () => {
      assert.throws(
        () => assertSocketlessSourceOracle(mutant.source, mutant.label),
        /NO-UDS source oracle rejected/i,
        `${mutant.label} must be rejected statically before the SAFE body can run`,
      );
      await withSocketlessNetworkCapabilityTrap(
        `${mutant.label} runtime self-mutant`,
        async () => {
          assert.throws(
            () => mutant.invoke(),
            (error) => error?.code === "ERR_TEST_NO_UDS_CAPABILITY",
            `${mutant.label} must hit the causal runtime capability trap without opening a socket`,
          );
        },
        { expectedAttempts: [mutant.blockedAttempt] },
      );
    });
  }

  await t.test("every exported net callable and reachable connect/listen prototype", async () => {
    const callableNames = socketlessNetCallableNames();
    const originalServerPrototype = socketlessOriginalNetPrototype("Server");
    const expectedAttempts = [
      ...callableNames.map((name) => `net.${name}`),
      "net.Socket.prototype.connect",
      "net.Server.prototype.listen",
      "net.Socket.prototype.constructor",
    ];
    await withSocketlessNetworkCapabilityTrap(
      "complete node:net callable surface self-mutant",
      async () => {
        for (const name of callableNames) {
          assert.throws(
            () => Reflect.apply(net[name], undefined, []),
            (error) => error?.code === "ERR_TEST_NO_UDS_CAPABILITY",
            `node:net callable ${name} must be replaced by the runtime trap`,
          );
        }
        assert.throws(
          () => process.stdout.connect(),
          (error) => error?.code === "ERR_TEST_NO_UDS_CAPABILITY",
          "the reachable Socket prototype may not retain connect authority",
        );
        assert.throws(
          () => originalServerPrototype.listen(),
          (error) => error?.code === "ERR_TEST_NO_UDS_CAPABILITY",
          "the reachable Server prototype may not retain listen authority",
        );
        assert.throws(
          () => Reflect.construct(process.stdout.constructor, []),
          (error) => error?.code === "ERR_TEST_NO_UDS_CAPABILITY",
          "the reachable Socket prototype constructor may not create a socket",
        );
      },
      { expectedAttempts },
    );
  });
});

test("test-only fresh process behaviorally proves exact-once SAFE wrappers", async (t) => {
  const control = await runSocketlessGuardedSafeChild();
  assertSocketlessGuardedSafeChildEnvelope(control, "exact-once control");
  assertExactSocketlessWrapperLedger(control.report, "exact-once control");

  await t.test("wrapper bypass/deletion mutant records zero real invocations", async () => {
    const bypass = await runSocketlessGuardedSafeChild("bypass");
    assertSocketlessGuardedSafeChildEnvelope(bypass, "wrapper bypass mutant");
    assert.deepEqual(
      bypass.report.wrapperLedger.map(({ bodyEntries, entries, exits }) => ({
        bodyEntries,
        entries,
        exits,
      })),
      SOCKETLESS_SAFE_COHORT_LABELS.map(() => ({ bodyEntries: 1, entries: 0, exits: 0 })),
      "the bypass mutant must traverse the inner callback while producing zero wrapper entries",
    );
    assert.throws(
      () => assertExactSocketlessWrapperLedger(bypass.report, "wrapper bypass mutant"),
      /exactly one completed wrapper invocation/i,
    );
  });

  await t.test("aliased double-wrapper mutant records two real invocations", async () => {
    const duplicate = await runSocketlessGuardedSafeChild("double-alias");
    assertSocketlessGuardedSafeChildEnvelope(duplicate, "aliased double-wrapper mutant");
    assert.deepEqual(
      duplicate.report.wrapperLedger.map(({ bodyEntries, entries, exits }) => ({
        bodyEntries,
        entries,
        exits,
      })),
      SOCKETLESS_SAFE_COHORT_LABELS.map(() => ({ bodyEntries: 2, entries: 2, exits: 2 })),
      "the isolated alias mutant must cross the real wrapper twice for every exact SAFE label",
    );
    assert.throws(
      () => assertExactSocketlessWrapperLedger(duplicate.report, "aliased double-wrapper mutant"),
      /exactly one completed wrapper invocation/i,
    );
  });

  await t.test("computed global operation adds calls instead of forging the ledger", async () => {
    const forged = await runSocketlessGuardedSafeChild("computed-global");
    assertSocketlessGuardedSafeChildEnvelope(
      forged,
      "computed global-operation mutant",
    );
    assert.deepEqual(
      forged.report.wrapperLedger,
      SOCKETLESS_SAFE_COHORT_LABELS.map((label) => ({
        bodyEntries: 2,
        entries: 2,
        exits: 2,
        inFlight: 0,
        label,
      })),
      "a computed global call must add to, never forge or replace, the legitimate invocation",
    );
    assert.deepEqual(
      forged.report.wrapperExtraEvents,
      [],
      "an exact computed call is counted directly rather than mislabeled as a forgery",
    );
    assert.throws(
      () => assertExactSocketlessWrapperLedger(forged.report, "computed global-operation mutant"),
      /exactly one completed wrapper invocation/i,
      "the dynamic globalThis/Symbol/computed-property call must fail exact-once",
    );
  });

  await t.test("hostile second pre-import cannot prefill and silence the ledger", async () => {
    const stolen = await runSocketlessGuardedSafeChild("preimport-steal");
    assertSocketlessGuardedSafeChildEnvelope(stolen, "pre-import steal mutant");
    assert.deepEqual(
      stolen.report.wrapperLedger,
      SOCKETLESS_SAFE_COHORT_LABELS.map((label) => ({
        bodyEntries: 2,
        entries: 2,
        exits: 2,
        inFlight: 0,
        label,
      })),
      "hostile pre-import calls made under a patched Array.push must remain additive",
    );
    assert.throws(
      () => assertExactSocketlessWrapperLedger(stolen.report, "pre-import steal mutant"),
      /exactly one completed wrapper invocation/i,
    );
  });
});

testWhenProductionExports(
  injectedAssemblyRequirements(),
  "RED v2: real broker assembly signs and writes semantic success and rejection to the real client",
  async (t) => {
    const action = "backup.prune.plan";
    const command = "prune-manifest-backups-plan";
    const capabilityKey = fixtureCapabilityKey(action);
    const { trusted } = buildFixtureTrustedContextV2({
      allowedActions: [action],
      now: NOW,
    });
    const result = buildFixtureActionResultV2(action);
    const assembly = await realBrokerAssembly(t, {
      capabilityKey,
      outcomes: [
        { result },
        { rejection: "semantic policy rejected the admitted action" },
      ],
      trusted,
    });

    const successRequest = buildClientRequest(command, [], {
      runtimeIntentId: trusted.intent.intentId,
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      capabilityKey,
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174100",
      nonce: "B".repeat(43),
    });
    const completed = await sendActionRequest(
      successRequest,
      assembly.socketPath,
      capabilityKey,
    );
    assert.equal(completed.status, "completed");
    assert.equal(completed.statusCode, 200);
    assert.equal(completed.errorCode, null);
    assert.deepEqual(completed.result, result);

    const rejectionRequest = buildClientRequest(command, [], {
      runtimeIntentId: trusted.intent.intentId,
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      capabilityKey,
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174101",
      nonce: "C".repeat(43),
    });
    const rejected = await sendActionRequest(
      rejectionRequest,
      assembly.socketPath,
      capabilityKey,
    );
    assert.equal(rejected.status, "rejected");
    assert.equal(rejected.statusCode, 403);
    assert.equal(rejected.errorCode, "ACTION_REJECTED");
    assert.equal(rejected.result, null);

    assert.equal(assembly.semanticExecutorFactoryCalls, 1);
    assert.deepEqual(
      assembly.executedActions,
      [action, action],
      "both responses must traverse the semantic executor selected by the real assembly",
    );
    assert.deepEqual(assembly.replayEvents.slice(0, 2), ["recover", "activation"]);
    assert.equal(assembly.responseFrames.length, 2);
    assertProductionEncoderMatchesWrittenFrame(
      assembly.responseFrames[0],
      completed,
      "semantic success",
    );
    assertProductionEncoderMatchesWrittenFrame(
      assembly.responseFrames[1],
      rejected,
      "semantic rejection",
    );
  },
);

testWhenProductionExports(
  injectedAssemblyRequirements(),
  "RED v2: in-memory request producer rejects SAFE action affixes before every provider",
  async (t) => withSocketlessNetworkCapabilityTrap(
    "in-memory request producer SAFE cohort",
    async (executionGate) => {
    if (!executionGate.productionBodyAllowed) return;
    const expectedAction = "backup.prune.plan";
    const capabilityKey = fixtureCapabilityKey(expectedAction);
    const { trusted } = buildFixtureTrustedContextV2({
      allowedActions: [expectedAction],
      now: NOW,
    });
    const control = buildClientRequest("prune-manifest-backups-plan", [], {
      runtimeIntentId: trusted.intent.intentId,
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      capabilityKey,
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174104",
      nonce: "F".repeat(43),
    });
    assert.equal(control.action, expectedAction);
    assert.equal(
      control.mac,
      domainMacWithKey(
        REQUEST_MAC_DOMAIN,
        omit(control, "mac"),
        capabilityKey,
      ),
      "the exact request producer control must carry an independently verified request MAC",
    );

    const controlResult = buildFixtureActionResultV2(expectedAction);
    const coreFixture = await inMemoryBrokerCoreFixture({
      capabilityKey,
      outcomes: [{ result: controlResult }],
      trusted,
    });
    assert.equal(
      coreFixture.fixtureExecutorFactoryCalls,
      1,
      "the control must prove the fixture-owned executor factory is reachable",
    );
    assert.deepEqual(
      coreFixture.fixtureReplayEvents,
      ["recover"],
      "the fixture-owned replay double must be initialized before the production core",
    );
    assert.equal(coreFixture.capabilityProviderCalls, 0);
    assert.equal(coreFixture.trustedContextProviderCalls, 0);
    assert.deepEqual(coreFixture.executedActions, []);

    const controlExchange = await coreFixture.exchange(control);
    const admittedControl = consumeInMemoryAssemblyResponse(
      controlExchange,
      control,
      capabilityKey,
      "exact request producer success control",
    );
    assert.equal(admittedControl.status, "completed");
    assert.equal(admittedControl.statusCode, 200);
    assert.equal(admittedControl.errorCode, null);
    assert.deepEqual(admittedControl.result, controlResult);
    assert.equal(coreFixture.capabilityProviderCalls, 1);
    assert.equal(coreFixture.trustedContextProviderCalls, 1);
    assert.deepEqual(coreFixture.executedActions, [expectedAction]);
    assert.ok(
      coreFixture.fixtureReplayEvents.includes("consume"),
      "the exact request must prove that the fixture replay double crosses real core admission",
    );
    assert.equal(coreFixture.responseFrames.length, 1);
    assertProductionEncoderMatchesWrittenFrame(
      controlExchange.frame,
      admittedControl,
      "exact request producer success control",
    );
    assert.deepEqual(
      coreFixture.responseFrames[0],
      controlExchange.frame,
      "the in-memory connection must receive the exact frame observed at the production encoder boundary",
    );

    const baseline = {
      capabilityProviderCalls: coreFixture.capabilityProviderCalls,
      executedActions: [...coreFixture.executedActions],
      fixtureExecutorFactoryCalls: coreFixture.fixtureExecutorFactoryCalls,
      fixtureReplayEvents: [...coreFixture.fixtureReplayEvents],
      trustedContextProviderCalls: coreFixture.trustedContextProviderCalls,
    };
    const identityMutations = [
      {
        action: `${expectedAction}.nested`,
        boundary: "exact-identity",
        label: "exact prefix plus dotted nested identity",
        relationship: "prefix",
      },
      {
        action: `nested.${expectedAction}`,
        boundary: "exact-identity",
        label: "dotted nested identity plus exact suffix",
        relationship: "suffix",
      },
    ];

    async function assertPreProviderRejection(mutation) {
      await t.test(`${mutation.boundary}: ${mutation.label}`, async () => {
        const candidate = independentlyResignedRequest(
          control,
          { action: mutation.action },
          capabilityKey,
        );
        assert.equal(candidate.action, mutation.action);
        assert.equal(
          candidate.mac,
          domainMacWithKey(
            REQUEST_MAC_DOMAIN,
            omit(candidate, "mac"),
            capabilityKey,
          ),
          "the hostile action request must be coherently re-MACed before broker admission",
        );
        assert.equal(
          affixIdentityBlindRequestMutantAccepts(
            candidate,
            control,
            mutation,
            capabilityKey,
          ),
          true,
          "the request fixture must survive its exact affix-blind authorization mutant",
        );
        assert.match(
          candidate.action,
          SAFE_ACTION_IDENTITY,
          "the exact-identity collision must pass the shared SAFE grammar",
        );

        const outcome = await coreFixture.exchange(candidate).then(
          (value) => ({ kind: "response", value }),
          (error) => ({ error, kind: "error" }),
        );
        if (outcome.kind === "response") {
          assertProductionResponseFrame(
            outcome.value.frame,
            outcome.value.response,
          );
          assert.notEqual(
            `${outcome.value.response.status}:${outcome.value.response.statusCode}`,
            "completed:200",
            "a hostile action collision may not produce a completed response",
          );
          assert.equal(outcome.value.response.result ?? null, null);
        } else {
          assert.ok(
            outcome.error instanceof Error,
            "a fail-closed transport rejection must preserve an Error",
          );
        }

        assert.deepEqual(
          {
            capabilityProviderCalls: coreFixture.capabilityProviderCalls,
            executedActions: coreFixture.executedActions,
            fixtureExecutorFactoryCalls: coreFixture.fixtureExecutorFactoryCalls,
            fixtureReplayEvents: coreFixture.fixtureReplayEvents,
            trustedContextProviderCalls: coreFixture.trustedContextProviderCalls,
          },
          baseline,
          "an affix collision must not reach trust, capability, replay, or semantic execution side effects",
        );
      });
    }

    for (const mutation of identityMutations) {
      await assertPreProviderRejection(mutation);
    }

    await t.test("grammar: slash child fails specifically before every provider", async () => {
      const grammarMutation = {
        action: `${expectedAction}/child`,
        boundary: "grammar",
        label: "slash child",
        relationship: "prefix",
      };
      const candidate = independentlyResignedRequest(
        control,
        { action: grammarMutation.action },
        capabilityKey,
      );
      assert.equal(
        candidate.mac,
        domainMacWithKey(
          REQUEST_MAC_DOMAIN,
          omit(candidate, "mac"),
          capabilityKey,
        ),
        "the slash-child request must be coherently re-MACed before grammar admission",
      );
      assert.doesNotMatch(
        candidate.action,
        SAFE_ACTION_IDENTITY,
        "slash-child must remain isolated at the grammar boundary",
      );
      assert.equal(
        affixIdentityBlindRequestMutantAccepts(
          candidate,
          control,
          grammarMutation,
          capabilityKey,
        ),
        true,
        "the slash-child request must survive the explicit prefix-blind mutant",
      );

      const grammarCore = await inMemoryBrokerCoreFixture({
        capabilityKey,
        outcomes: [],
        trusted,
      });
      assert.equal(grammarCore.capabilityProviderCalls, 0);
      assert.equal(grammarCore.trustedContextProviderCalls, 0);
      assert.deepEqual(grammarCore.executedActions, []);
      const error = await grammarCore.exchange(candidate).then(
        () => assert.fail("slash-child must fail specifically at action grammar"),
        (rejection) => rejection,
      );
      assert.ok(error instanceof Error, "grammar rejection must preserve an Error");
      assert.match(
        error.message,
        /action.*(?:grammar|syntax|format|logical[ -]?id)/i,
        "slash-child must fail specifically at action grammar before registry lookup",
      );
      assert.doesNotMatch(
        error.message,
        /(?:registry|unknown|not authorized|not enabled|unsupported|binding|identity|authentication|mac|schema|digest)/i,
        "slash-child may not be misclassified as registry, identity, authentication or digest rejection",
      );
      assert.equal(grammarCore.capabilityProviderCalls, 0);
      assert.equal(grammarCore.trustedContextProviderCalls, 0);
      assert.deepEqual(grammarCore.executedActions, []);
      assert.deepEqual(
        grammarCore.fixtureReplayEvents,
        ["recover"],
        "grammar rejection must precede activation, trust, replay consume and lease acquisition",
      );
      assert.deepEqual(grammarCore.responseFrames, []);
    });
    },
  ),
);

testWhenProductionExports(
  injectedAssemblyRequirements(),
  "RED v2: in-memory response producer emits no success frame for identity-blind semantic results",
  async (t) => withSocketlessNetworkCapabilityTrap(
    "in-memory response producer SAFE cohort",
    async (executionGate) => {
    if (!executionGate.productionBodyAllowed) return;
    const seed = canonicalIdentityCollisionFixture();
    const { trusted } = buildFixtureTrustedContextV2({
      allowedActions: [seed.expectedAction],
      now: NOW,
    });
    const coreFixture = await inMemoryBrokerCoreFixture({
      capabilityKey: seed.capabilityKey,
      outcomes: [
        { result: seed.control.result },
        ...seed.mutations.map(({ candidate }) => ({
          result: candidate.result,
        })),
      ],
      trusted,
    });
    assert.equal(coreFixture.fixtureExecutorFactoryCalls, 1);
    assert.deepEqual(coreFixture.fixtureReplayEvents, ["recover"]);

    const controlExchange = await coreFixture.exchange(seed.request);
    const admittedControl = consumeInMemoryAssemblyResponse(
      controlExchange,
      seed.request,
      seed.capabilityKey,
      "exact semantic result success control",
    );
    assert.deepEqual(
      admittedControl,
      seed.control,
      "the positive baseline must cross the real core providers, fixture executor and production encoder intact",
    );
    assert.equal(coreFixture.capabilityProviderCalls, 1);
    assert.equal(coreFixture.trustedContextProviderCalls, 1);
    assert.deepEqual(coreFixture.executedActions, [seed.expectedAction]);
    assert.ok(coreFixture.fixtureReplayEvents.includes("consume"));
    assert.equal(coreFixture.responseFrames.length, 1);
    assert.deepEqual(coreFixture.responseFrames[0], controlExchange.frame);

    for (const [index, seedMutation] of seed.mutations.entries()) {
      await t.test(`${seedMutation.boundary}: ${seedMutation.label}`, async () => {
        const fixture = canonicalIdentityCollisionFixture({
          requestIndex: 80 + index,
        });
        const mutation = fixture.mutations[index];
        assert.equal(mutation.label, seedMutation.label);
        assert.equal(
          affixIdentityBlindResponseMutantAccepts(
            mutation.candidate,
            fixture.control,
            fixture.request,
            mutation,
            fixture.capabilityKey,
          ),
          true,
          "the hostile semantic result must first survive the exact identity-blind mutant",
        );

        const frameBaseline = coreFixture.responseFrames.length;
        const outcome = await coreFixture.exchange(fixture.request).then(
          (value) => ({ kind: "response", value }),
          (error) => ({ error, kind: "error" }),
        );
        if (outcome.kind === "response") {
          assert.notEqual(
            `${outcome.value.response.status}:${outcome.value.response.statusCode}`,
            "completed:200",
            "an identity-blind semantic result may not become a completed response",
          );
          assert.equal(
            outcome.value.response.result ?? null,
            null,
            "a fail-closed producer response may not expose the hostile semantic result",
          );
          assertProductionResponseFrame(
            outcome.value.frame,
            outcome.value.response,
          );
        } else {
          assert.ok(outcome.error instanceof Error);
        }

        const newFrames = coreFixture.responseFrames.slice(frameBaseline);
        for (const frame of newFrames) {
          const wire = frame.toString("utf8");
          assert.equal(wire.endsWith("\n"), true);
          assert.equal(wire.slice(0, -1).includes("\n"), false);
          const response = JSON.parse(wire.slice(0, -1));
          assertProductionEncoderMatchesWrittenFrame(
            frame,
            response,
            `${mutation.label} fail-closed producer frame`,
          );
          assert.notEqual(
            `${response.status}:${response.statusCode}`,
            "completed:200",
            `${mutation.label} must never reach a signed success frame`,
          );
          assert.equal(response.result, null);
        }
        assert.deepEqual(
          coreFixture.executedActions,
          Array(index + 2).fill(seed.expectedAction),
          "the semantic executor receives only the exact request action; the producer must reject its hostile result",
        );
      });
    }
    },
  ),
);

testWhenProductionExports(
  semanticCoreRequirements(),
  "RED v2: in-memory core crosses the real semantic executor without UDS",
  async () => withSocketlessNetworkCapabilityTrap(
    "in-memory semantic executor SAFE cohort",
    async (executionGate) => {
    if (!executionGate.productionBodyAllowed) return;
    const action = "backup.prune.plan";
    const command = "prune-manifest-backups-plan";
    const capabilityKey = fixtureCapabilityKey(action);
    const { trusted } = buildFixtureTrustedContextV2({
      allowedActions: [action],
      now: NOW,
    });
    const successRequest = buildClientRequest(command, [], {
      runtimeIntentId: trusted.intent.intentId,
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      capabilityKey,
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174102",
      nonce: "D".repeat(43),
    });
    const rejectionRequest = buildClientRequest(command, [], {
      runtimeIntentId: trusted.intent.intentId,
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      capabilityKey,
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174103",
      nonce: "E".repeat(43),
    });
    const coreFixture = await inMemorySemanticExecutorCoreFixture({
      capabilityKey,
      successRequestId: successRequest.requestId,
      trusted,
    });
    const successExchange = await coreFixture.exchange(successRequest);
    const completed = consumeInMemoryAssemblyResponse(
      successExchange,
      successRequest,
      capabilityKey,
      "semantic executor success",
    );
    assert.equal(completed.status, "completed");
    assert.equal(completed.statusCode, 200);
    assert.equal(completed.errorCode, null);
    assert.deepEqual(completed.result, buildFixtureActionResultV2(action));
    const rejectionExchange = await coreFixture.exchange(rejectionRequest);
    const rejected = consumeInMemoryAssemblyResponse(
      rejectionExchange,
      rejectionRequest,
      capabilityKey,
      "semantic executor rejection",
    );
    assert.equal(rejected.status, "rejected");
    assert.equal(rejected.statusCode, 403);
    assert.equal(rejected.errorCode, "ACTION_REJECTED");
    assert.equal(rejected.result, null);
    assert.equal(
      coreFixture.fixtureRecoveredExecutor,
      true,
      "the fixture-owned replay recovery must receive the real semantic executor",
    );
    assert.equal(
      coreFixture.fixtureSemanticExecutorCreations,
      1,
      "the fixture must construct the real semantic executor exactly once",
    );
    coreFixture.assertTransportComplete();
    assert.equal(
      Object.hasOwn(coreFixture.transport, "execute"),
      false,
      "the transport intentionally exposes no legacy engine execute shortcut",
    );
    assert.equal(coreFixture.transport.execute, undefined);
    assert.equal(coreFixture.capabilityProviderCalls, 2);
    assert.equal(coreFixture.trustedContextProviderCalls, 2);
    assert.deepEqual(
      coreFixture.fixtureReplayEvents.slice(0, 2),
      ["recover", "activation"],
      "the semantic-core baseline must cross the fixture replay double before execution",
    );
    assert.equal(coreFixture.responseFrames.length, 2);
    assertProductionEncoderMatchesWrittenFrame(
      successExchange.frame,
      completed,
      "semantic executor success",
    );
    assertProductionEncoderMatchesWrittenFrame(
      rejectionExchange.frame,
      rejected,
      "semantic executor rejection",
    );
    assert.deepEqual(coreFixture.responseFrames, [
      successExchange.frame,
      rejectionExchange.frame,
    ]);
    },
  ),
);

test("capability reader requires stable private ownership, parents and one link", async (t) => {
  for (const scenario of [
    {
      label: "group-readable mode",
      mutate({ capability }) {
        fs.chmodSync(capability, 0o440);
      },
    },
    {
      label: "second hardlink",
      mutate({ capability, directory }) {
        fs.linkSync(capability, path.join(directory, "second-link"));
      },
    },
  ]) {
    await t.test(scenario.label, () => {
      const fixture = capabilityFixture(t);
      const policy = {
        expectedUid: process.getuid(),
        expectedGid: process.getgid(),
        parentRoot: fixture.directory,
      };
      assert.deepEqual(protectedCapability(fixture.capability, policy), CAPABILITY);
      scenario.mutate(fixture);
      assert.throws(
        () => protectedCapability(fixture.capability, policy),
        /ownership, links, permissions or size/,
      );
    });
  }
});

test("test-only claimed fixture applies document mutations and raw bytes independently of production", (t) => {
  const raw = Buffer.from("{");
  const fixture = claimedJobFixture(t, {
    mutateDocument(document) {
      document.status = "queued";
      document.startedAt = null;
    },
    rawBytes: raw,
  });
  assert.equal(fixture.document.status, "queued");
  assert.equal(fixture.document.startedAt, null);
  assert.deepEqual(fixture.bytes, raw);
  assert.deepEqual(fs.readFileSync(fixture.file), raw);

  const generated = claimedJobFixture(t, {
    mutateDocument(document) {
      document.status = "done";
      document.finishedAt = "2026-07-28T12:01:00.000Z";
    },
  });
  const parsed = JSON.parse(fs.readFileSync(generated.file, "utf8"));
  assert.equal(parsed.status, "done");
  assert.equal(parsed.finishedAt, "2026-07-28T12:01:00.000Z");
});

test("test-only filesystem double independently observes O_NOFOLLOW, descriptor reads and same-size substitution", (t) => {
  const fixture = claimedJobFixture(t);
  const replacement = Buffer.from(
    fixture.bytes.toString("utf8").replace(
      '"requestedBy": "control-center"',
      '"requestedBy": "control-centes"',
    ),
  );
  assert.equal(replacement.length, fixture.bytes.length);

  const control = observedFilesystem(fixture);
  const descriptor = control.fileSystem.openSync(
    fixture.file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  const first = observedDescriptorRead(control.fileSystem, descriptor, fixture.bytes.length);
  const second = observedDescriptorRead(control.fileSystem, descriptor, fixture.bytes.length);
  control.fileSystem.closeSync(descriptor);
  assert.deepEqual(first, fixture.bytes);
  assert.deepEqual(second, fixture.bytes);
  assert.equal(control.state.protectedOpenCount, 1);
  assert.equal(control.state.allProtectedOpensNoFollow, true);
  assert.equal(control.state.completeDescriptorReads, 2);
  assert.equal(control.state.descriptorBytesRead, fixture.bytes.length * 2);
  assert.equal(control.state.pathReadAttempts, 0);

  const racing = observedFilesystem(fixture, {
    afterFirstCompleteRead() {
      fs.writeFileSync(fixture.file, replacement, { mode: 0o600 });
    },
  });
  const racingDescriptor = racing.fileSystem.openSync(
    fixture.file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  const before = observedDescriptorRead(racing.fileSystem, racingDescriptor, fixture.bytes.length);
  const after = observedDescriptorRead(racing.fileSystem, racingDescriptor, fixture.bytes.length);
  racing.fileSystem.closeSync(racingDescriptor);
  assert.deepEqual(before, fixture.bytes);
  assert.deepEqual(after, replacement);
  assert.equal(racing.state.completeDescriptorReads, 2);
  assert.equal(racing.state.firstCompleteReadObserved, true);
  assert.equal(racing.state.pathReadAttempts, 0);

  racing.fileSystem.readFileSync(fixture.file);
  assert.equal(racing.state.pathReadAttempts, 1, "the double must expose a pathname read");
});

test("test-only real-main preload is a narrow filesystem redirect, not a client bridge", async (t) => {
  const fixture = claimedJobFixture(t);
  const redirect = clientMainFsRedirectFixture(t, {
    capabilityKey: CAPABILITY,
    capabilityPath: actionContract.ACTIONS["backup.job.execute"].capabilityFile,
  });
  const source = fs.readFileSync(redirect.preloadFile, "utf8");
  assert.doesNotMatch(source, /docker-action-client|runClientCommand|sendActionRequest|node:net/);
  const checked = await collectChildProcess(
    process.execPath,
    ["--check", redirect.preloadFile],
    {
      cwd: REPOSITORY_ROOT,
      env: {
        PATH: path.dirname(process.execPath),
      },
    },
  );
  assert.equal(checked.code, 0, `${checked.stdout}\n${checked.stderr}`);
  assert.equal(checked.stdout, "");
  assert.equal(checked.stderr, "");
  const exercised = await collectChildProcess(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      [
        'import { protectedCapability } from "./scripts/docker-action-client.mjs";',
        "const value = protectedCapability(process.env.DOCKER_ACTION_TEST_CAPABILITY_PATH);",
        'if (!Buffer.isBuffer(value) || value.length !== 32) throw new Error("redirected capability was not read");',
      ].join("\n"),
    ],
    {
      cwd: REPOSITORY_ROOT,
      env: {
        DOCKER_ACTION_TEST_AUDIT_FILE: redirect.auditFile,
        DOCKER_ACTION_TEST_CAPABILITY_FILE: redirect.capabilityFile,
        DOCKER_ACTION_TEST_CAPABILITY_PATH: redirect.capabilityPath,
        DOCKER_ACTION_TEST_CLAIMED_FILE: fixture.file,
        DOCKER_ACTION_TEST_CLAIMED_ROOT: fixture.directory,
        DOCKER_ACTION_TEST_NOW: String(NOW),
        DOCKER_ACTION_TEST_RUN_ID: "preload-control",
        NODE_OPTIONS: `--require=${redirect.preloadFile}`,
        PATH: path.dirname(process.execPath),
      },
    },
  );
  assert.equal(exercised.code, 0, `${exercised.stdout}\n${exercised.stderr}`);
  assert.equal(exercised.stdout, "");
  assert.equal(exercised.stderr, "");
  assertProtectedMainReads(redirect.readAudit(), {
    capabilityBytes: CAPABILITY.length,
    capabilityRuns: ["preload-control"],
    claimedJobBytes: fixture.bytes.length,
    claimedJobRuns: [],
  });
  const fakeEntrypoint = await collectChildProcess(
    process.execPath,
    ["--eval", ""],
    {
      cwd: REPOSITORY_ROOT,
      env: {
        DOCKER_ACTION_TEST_AUDIT_FILE: redirect.auditFile,
        DOCKER_ACTION_TEST_CAPABILITY_FILE: redirect.capabilityFile,
        DOCKER_ACTION_TEST_CAPABILITY_PATH: redirect.capabilityPath,
        DOCKER_ACTION_TEST_CLAIMED_FILE: fixture.file,
        DOCKER_ACTION_TEST_CLAIMED_ROOT: fixture.directory,
        DOCKER_ACTION_TEST_EXPECTED_ARGS_JSON: JSON.stringify([
          "execute-backup-job",
          "--jobFileName",
          fixture.fileName,
        ]),
        DOCKER_ACTION_TEST_EXPECTED_ENTRYPOINT: path.join(
          REPOSITORY_ROOT,
          "scripts",
          "docker-action-client.mjs",
        ),
        DOCKER_ACTION_TEST_NOW: String(NOW),
        DOCKER_ACTION_TEST_REQUIRE_REAL_MAIN: "1",
        DOCKER_ACTION_TEST_RUN_ID: "fake-entrypoint",
        NODE_OPTIONS: `--require=${redirect.preloadFile}`,
        PATH: path.dirname(process.execPath),
      },
    },
  );
  assert.notEqual(fakeEntrypoint.code, 0, "the preload must fail closed on a replacement entrypoint");
  assert.equal(fakeEntrypoint.stdout, "");
  assert.match(fakeEntrypoint.stderr, /real client entrypoint or arguments mismatch/i);
  assert.throws(
    () => assertRealClientMainInvocation(redirect.readAudit(), {
      fileName: fixture.fileName,
      runId: "fake-entrypoint",
    }),
    /exact real client entrypoint/i,
    "the independent audit oracle must also reject the fake process",
  );
  assert.equal(fs.statSync(fixture.file).mode & 0o777, 0o600);
});

test("RED v2 API: real client exports the claimed-job reader boundary", () => {
  assert.equal(
    typeof client.readClaimedBackupJob,
    "function",
    "docker-action-client.mjs must export readClaimedBackupJob",
  );
});

test("RED v2 API: real client exports the testable CLI command boundary", () => {
  assert.equal(
    typeof client.runClientCommand,
    "function",
    "docker-action-client.mjs must export runClientCommand",
  );
});

test("RED v2 API: real client exports the root-owned default claimed-job policy", () => {
  assert.equal(
    typeof client.defaultClaimedJobPolicy,
    "function",
    "docker-action-client.mjs must export defaultClaimedJobPolicy so main's real queue boundary is testable",
  );
});

test("RED v2 API: real broker exports its canonical response frame encoder", () => {
  assert.equal(
    typeof broker.encodeActionResponseFrame,
    "function",
    "docker-action-broker.mjs must export encodeActionResponseFrame so the client is tested against production wire bytes",
  );
});

testWhenClientExports(
  ["defaultClaimedJobPolicy"],
  "RED v2: default claimed-job policy is the exact root-owned running queue boundary",
  () => {
    const jobsDirectory = "/var/lib/platform/test-only-backup-jobs";
    const policy = client.defaultClaimedJobPolicy({
      BACKUP_SCHEDULER_JOBS_DIR: jobsDirectory,
      DOCKER_ACTION_CLAIMED_JOB_GID: "501",
      DOCKER_ACTION_CLAIMED_JOB_MAXIMUM_BYTES: String(MAX_CLAIMED_JOB_BYTES * 4),
      DOCKER_ACTION_CLAIMED_JOB_UID: "501",
    });
    assert.deepEqual(Object.keys(policy).sort(), [
      "expectedGid",
      "expectedUid",
      "maximumBytes",
      "trustedRoot",
    ]);
    assert.deepEqual(policy, {
      expectedGid: 0,
      expectedUid: 0,
      maximumBytes: MAX_CLAIMED_JOB_BYTES,
      trustedRoot: path.join(jobsDirectory, "running"),
    });
    assert.deepEqual(
      client.defaultClaimedJobPolicy({}),
      {
        expectedGid: 0,
        expectedUid: 0,
        maximumBytes: MAX_CLAIMED_JOB_BYTES,
        trustedRoot: "/var/www/project-state/backup-jobs/running",
      },
      "an empty environment must retain the production queue default",
    );
  },
);

testWhenClientExports(
  ["readClaimedBackupJob", "runClientCommand"],
  "RED v2: real CLI command carries one claimed file through signed request and local UDS response",
  async (t) => {
  const accepted = [
    ["leading-zero hex identity", "0123456789abcdef", "backup"],
    ["scheduled identity", "scheduled-platform-20260728-120000-a1b2c3", "backup"],
    ["restore-drill identity", "job-0123456789abcdef", "restore-drill"],
  ];
  for (const [label, id, operation] of accepted) {
    await t.test(label, async (st) => {
      const fixture = claimedJobFixture(st, { id, operation });
      const readClaimedBackupJob = requireClaimedJobReader();
      const runClientCommand = requireClientCommandRunner();
      const policy = claimedJobPolicy(fixture);
      const expected = await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
      const exchange = await invokeValidCliControl(runClientCommand, fixture, {
        policy,
      });
      const request = exchange.request;
      const unsigned = omit(request, "mac");
      const result = canonicalActionResultV2(request);

      assert.equal(request.schema, REQUEST_SCHEMA_V2);
      assert.deepEqual(Object.keys(request).sort(), [
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
      assert.equal(request.action, "backup.job.execute");
      assert.deepEqual(request.parameters, expected, "the CLI must preserve the claimed identity byte-for-byte");
      assert.equal(request.parameters.jobFileName, `${id}.json`);
      assert.equal(request.parameters.jobId, id);
      assert.equal(request.parameters.jobOperation, operation);
      assert.equal(request.mac, requestMac(unsigned));
      assert.deepEqual(exchange.value, signedResponse(request, {
        status: "completed",
        statusCode: 200,
        errorCode: null,
        result,
      }));
    });
  }
  },
);

testWhenProductionExports(
  schedulerMainRequirements(),
  "RED v2: scheduler executes the real client main through the real broker assembly",
  async (t) => {
    const fixture = claimedJobFixture(t);
    const expected = await assertValidClaimedJobControl(
      requireClaimedJobReader(),
      fixture,
    );
    const action = "backup.job.execute";
    const capabilityKey = fixtureCapabilityKey(action);
    const { trusted } = buildFixtureTrustedContextV2({
      allowedActions: [action],
      now: NOW,
    });
    const result = buildFixtureActionResultV2(action, expected);
    const assembly = await realBrokerAssembly(t, {
      capabilityKey,
      now: () => NOW,
      outcomes: [
        { result },
        { rejection: "semantic policy rejected the admitted claimed job" },
      ],
      trusted,
    });
    const redirect = clientMainFsRedirectFixture(t, {
      capabilityKey,
      capabilityPath: actionContract.ACTIONS[action].capabilityFile,
    });

    const completed = await invokeSchedulerRealMain(fixture, assembly.socketPath, redirect, {
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      runtimeIntentId: trusted.intent.intentId,
    }, "completed");
    assert.equal(completed.code, 0, `${completed.stdout}\n${completed.stderr}`);
    assert.equal(completed.stderr, "");
    assertSingleJsonLine(completed.stdout, "completed scheduler/client main output");
    const completedResponse = JSON.parse(completed.stdout);
    assert.equal(
      completed.stdout,
      `${canonicalJsonOracle(completedResponse)}\n`,
      "the real client main must emit exactly one canonical completed response frame",
    );
    assert.equal(completedResponse.status, "completed");
    assert.equal(completedResponse.statusCode, 200);
    assert.deepEqual(completedResponse.result, result);

    const rejected = await invokeSchedulerRealMain(fixture, assembly.socketPath, redirect, {
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      runtimeIntentId: trusted.intent.intentId,
    }, "rejected");
    assert.equal(rejected.code, 77, `${rejected.stdout}\n${rejected.stderr}`);
    assert.equal(rejected.stderr, "");
    assertSingleJsonLine(rejected.stdout, "rejected scheduler/client main output");
    const rejectedResponse = JSON.parse(rejected.stdout);
    assert.equal(
      rejected.stdout,
      `${canonicalJsonOracle(rejectedResponse)}\n`,
      "the real client main must emit exactly one canonical rejected response frame",
    );
    assert.equal(rejectedResponse.status, "rejected");
    assert.equal(rejectedResponse.statusCode, 403);
    assert.equal(rejectedResponse.errorCode, "ACTION_REJECTED");
    assert.equal(rejectedResponse.result, null);

    assertProtectedMainReads(redirect.readAudit(), {
      capabilityBytes: capabilityKey.length,
      capabilityRuns: ["completed", "rejected"],
      claimedJobBytes: fixture.bytes.length,
      claimedJobRuns: ["completed", "rejected"],
    });

    fs.chmodSync(redirect.capabilityFile, 0o440);
    const exposedCapability = await invokeSchedulerRealMain(
      fixture,
      assembly.socketPath,
      redirect,
      {
        activeReceiptSha256: trusted.receiptDigest,
        combinedRenderSha256: trusted.receipt.combinedRenderSha256,
        runtimeIntentId: trusted.intent.intentId,
      },
      "exposed-capability",
    );
    assert.equal(exposedCapability.code, 1, `${exposedCapability.stdout}\n${exposedCapability.stderr}`);
    assert.equal(exposedCapability.stdout, "");
    assert.match(
      exposedCapability.stderr,
      /capability.*(?:ownership|link|mode|permission|protected|size)/i,
    );

    fs.chmodSync(redirect.capabilityFile, 0o400);
    fs.chmodSync(fixture.file, 0o640);
    const exposedClaimedJob = await invokeSchedulerRealMain(
      fixture,
      assembly.socketPath,
      redirect,
      {
        activeReceiptSha256: trusted.receiptDigest,
        combinedRenderSha256: trusted.receipt.combinedRenderSha256,
        runtimeIntentId: trusted.intent.intentId,
      },
      "exposed-claimed-job",
    );
    assert.equal(exposedClaimedJob.code, 1, `${exposedClaimedJob.stdout}\n${exposedClaimedJob.stderr}`);
    assert.equal(exposedClaimedJob.stdout, "");
    assert.match(
      exposedClaimedJob.stderr,
      /claimed job.*(?:metadata|mode|owner|permission|protected)/i,
    );

    assert.deepEqual(assembly.executedActions, [action, action]);
    assert.deepEqual(assembly.executedParameters, [expected, expected]);
    assert.equal(assembly.responseFrames.length, 2);
    assertProductionEncoderMatchesWrittenFrame(
      assembly.responseFrames[0],
      completedResponse,
      "scheduler completed response",
    );
    assertProductionEncoderMatchesWrittenFrame(
      assembly.responseFrames[1],
      rejectedResponse,
      "scheduler rejected response",
    );
  },
);

testWhenClientExports(
  ["readClaimedBackupJob", "runClientCommand"],
  "RED v2: exact protected snapshot bound never transports raw job bytes in a request-sized or execve field",
  async (t) => {
  const fixture = claimedJobFixture(t, {
    rawBytes(document) {
      return exactBoundJsonBytes(document, MAX_CLAIMED_JOB_BYTES);
    },
  });
  assert.equal(fixture.bytes.length, MAX_CLAIMED_JOB_BYTES);
  assert.equal(claimedJobPolicy(fixture).maximumBytes, MAX_CLAIMED_JOB_BYTES);

  const readClaimedBackupJob = requireClaimedJobReader();
  const runClientCommand = requireClientCommandRunner();
  const expected = await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
  const exchange = await invokeValidCliControl(runClientCommand, fixture, {
    policy: claimedJobPolicy(fixture),
  });
  const requestWire = canonicalJsonOracle(exchange.request);
  const base64 = fixture.bytes.toString("base64");
  const base64url = fixture.bytes.toString("base64url");

  assert.deepEqual(exchange.request.parameters, expected);
  assert.deepEqual(Object.keys(exchange.request.parameters).sort(), [
    "jobFileName",
    "jobId",
    "jobOperation",
    "jobSha256",
  ]);
  assert.equal(Buffer.byteLength(requestWire), requestWire.length);
  assert.ok(Buffer.byteLength(requestWire) <= MAX_SIGNED_REQUEST_BYTES);
  assert.ok(Buffer.byteLength(base64) > MAX_EXECVE_STRING_BYTES);
  assert.ok(Buffer.byteLength(base64url) > MAX_EXECVE_STRING_BYTES);
  assert.equal(requestWire.includes(base64), false, "raw claimed bytes must not be base64 request material");
  assert.equal(requestWire.includes(base64url), false, "raw claimed bytes must not be base64url request material");
  assert.equal(
    Object.keys(exchange.request.parameters).some((key) => /(?:bytes|base64|document|payload)/i.test(key)),
    false,
    "the signed request must carry metadata only; worker delivery belongs to a protected file",
  );
  for (const value of jsonStrings(exchange.request)) {
    assert.ok(
      Buffer.byteLength(value) < MAX_EXECVE_STRING_BYTES,
      "no request field may rely on a string larger than Linux's per-string execve limit",
    );
  }
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: claimed reader preserves real IDs, operation and raw-file digest without normalization",
  async (t) => {
  const accepted = [
    ["16-hex backup", "0123456789abcdef", "backup"],
    ["scheduled platform backup", "scheduled-platform-20260728-120000-a1b2c3", "backup"],
    ["job restore drill", "job-0123456789abcdef", "restore-drill"],
  ];

  for (const [label, id, operation] of accepted) {
    await t.test(label, async (st) => {
      const fixture = claimedJobFixture(st, { id, operation });
      const readClaimedBackupJob = requireClaimedJobReader();
      const first = await readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture));
      assert.deepEqual(first, {
        jobFileName: `${id}.json`,
        jobId: id,
        jobOperation: operation,
        jobSha256: sha256Bytes(fixture.bytes),
      });

      const compactBytes = Buffer.from(`${JSON.stringify(fixture.document)}\n`);
      assert.notDeepEqual(compactBytes, fixture.bytes);
      fs.writeFileSync(fixture.file, compactBytes, { mode: 0o600 });
      const second = await readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture));
      assert.equal(second.jobSha256, sha256Bytes(compactBytes));
      assert.notEqual(second.jobSha256, first.jobSha256);
      assert.equal(second.jobId, id);
      assert.equal(second.jobOperation, operation);
    });
  }
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: claimed reader admits only a bounded valid running backup-contract document",
  async (t) => {
  const invalid = [
    {
      label: "malformed JSON",
      rawBytes: Buffer.from("{"),
      expected: /claimed job.*(?:json|malformed|parse)/i,
    },
    {
      label: "oversized document",
      rawBytes: Buffer.alloc(MAX_CLAIMED_JOB_BYTES + 1, 0x61),
      expected: /claimed job.*(?:oversize|size|bounded)/i,
    },
    {
      label: "wrong schema",
      mutate(document) {
        document.schema = "platform.backup-job/v0";
      },
      expected: /backup job schema|claimed job.*schema/i,
    },
    {
      label: "queued document is not a claimed running job",
      mutate(document) {
        document.status = "queued";
        document.startedAt = null;
      },
      expected: /claimed job.*(?:running|status)/i,
    },
    {
      label: "terminal document is not a claimed running job",
      mutate(document) {
        document.status = "done";
        document.finishedAt = "2026-07-28T12:01:00.000Z";
      },
      expected: /claimed job.*(?:running|status)/i,
    },
    {
      label: "empty resources",
      mutate(document) {
        document.resources = [];
      },
      expected: /backup resources|claimed job.*resource/i,
    },
    {
      label: "malformed resource identity",
      mutate(document) {
        document.resources[0].id = "platform-state:other";
      },
      expected: /resource id|resource identity|claimed job.*resource/i,
    },
    {
      label: "restore drill missing source manifest",
      operation: "restore-drill",
      mutate(document) {
        delete document.sourceManifestPath;
      },
      expected: /restore.*manifest|source manifest/i,
    },
    {
      label: "restore drill manifest traversal",
      operation: "restore-drill",
      mutate(document) {
        document.sourceManifestPath = "../manifests/source.json";
      },
      expected: /restore.*manifest|source manifest|backup path/i,
    },
    {
      label: "restore drill absolute manifest",
      operation: "restore-drill",
      mutate(document) {
        document.sourceManifestPath = "/manifests/source.json";
      },
      expected: /restore.*manifest|source manifest|backup path/i,
    },
  ];

  for (const scenario of invalid) {
    await t.test(scenario.label, async (st) => {
      const readClaimedBackupJob = requireClaimedJobReader();
      const control = claimedJobFixture(st, {
        operation: scenario.operation ?? "backup",
      });
      await assertValidClaimedJobControl(readClaimedBackupJob, control);

      const fixture = claimedJobFixture(st, {
        operation: scenario.operation ?? "backup",
        mutateDocument: scenario.mutate,
        rawBytes: scenario.rawBytes,
      });
      await assert.rejects(
        async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
        scenario.expected,
      );
    });
  }
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: claimed reader enforces trusted root, basename and exact protected-file stat",
  async (t) => {
  await t.test("parent traversal is rejected as a basename violation", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
    await assert.rejects(
      async () => readClaimedBackupJob(`../${fixture.fileName}`, claimedJobPolicy(fixture)),
      /claimed job (?:basename|filename)/i,
    );
  });

  await t.test("basename must equal the byte-exact job ID plus .json", async (st) => {
    const readClaimedBackupJob = requireClaimedJobReader();
    const control = claimedJobFixture(st);
    await assertValidClaimedJobControl(readClaimedBackupJob, control);
    const fixture = claimedJobFixture(st, {
      id: "0123456789abcdef",
      fileName: "job-0123456789abcdef.json",
    });
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job (?:basename|filename).*(?:id|identity)|job id.*(?:basename|filename)/i,
    );
  });

  await t.test("a second hardlink is rejected", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
    fs.linkSync(fixture.file, path.join(fixture.root, "second-link.json"));
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:link|stat|metadata)/i,
    );
  });

  await t.test("mode must be exactly private 0600", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
    fs.chmodSync(fixture.file, 0o640);
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:mode|permission|stat|metadata)/i,
    );
  });

  await t.test("owner is checked without coercion", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, {
        ...claimedJobPolicy(fixture),
        expectedUid: process.getuid() + 1,
      }),
      /claimed job.*(?:owner|ownership|stat|metadata)/i,
    );
  });

  await t.test("leaf symlink is rejected", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
    const outside = path.join(fixture.directory, "outside.json");
    fs.renameSync(fixture.file, outside);
    fs.symlinkSync(outside, fixture.file);
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:symlink|nofollow|regular|stat|metadata)/i,
    );
  });

  await t.test("trusted root itself cannot be a symlink", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
    const linkedRoot = path.join(fixture.directory, "linked-running");
    fs.symlinkSync(fixture.root, linkedRoot);
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, {
        ...claimedJobPolicy(fixture),
        trustedRoot: linkedRoot,
      }),
      /claimed job.*(?:root|parent|symlink)/i,
    );
  });

  await t.test("trusted root cannot be group writable", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assertValidClaimedJobControl(readClaimedBackupJob, fixture);
    fs.chmodSync(fixture.root, 0o770);
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:root|parent|permission)/i,
    );
  });
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: injected filesystem proves descriptor-only O_NOFOLLOW admission",
  async (t) => {
  const fixture = claimedJobFixture(t);
  const readClaimedBackupJob = requireClaimedJobReader();
  const observed = observedFilesystem(fixture);
  const parameters = await readClaimedBackupJob(fixture.fileName, {
    ...claimedJobPolicy(fixture),
    fileSystem: observed.fileSystem,
  });
  assert.equal(parameters.jobSha256, sha256Bytes(fixture.bytes));
  assert.equal(observed.state.protectedOpenCount > 0, true, "the injected filesystem must observe a protected open");
  assert.equal(observed.state.allProtectedOpensNoFollow, true, "every claimed-file open must carry O_NOFOLLOW");
  assert.equal(observed.state.pathReadAttempts, 0, "claimed bytes must never be read by pathname");
  assert.equal(
    observed.state.completeDescriptorReads >= 2,
    true,
    "admission must compare two complete reads from protected descriptor(s)",
  );
  assert.equal(
    observed.state.descriptorBytesRead >= fixture.bytes.length * 2,
    true,
    "both stable reads must come from protected descriptor(s)",
  );
  assert.equal(
    observed.state.protectedFstatCount >= 2,
    true,
    "the protected descriptor must be fstat'ed before and after its stable reads",
  );
  assert.equal(
    observed.state.fstatBeforeFirstCompleteRead,
    true,
    "the first complete descriptor read must be preceded by protected metadata",
  );
  assert.equal(
    observed.state.fstatAfterSecondCompleteRead,
    true,
    "the second complete descriptor read must be followed by protected metadata",
  );
  assert.deepEqual(
    Object.keys(observed.state.protectedFstatSnapshots[0]).sort(),
    ["ctimeMs", "dev", "gid", "ino", "mode", "mtimeMs", "nlink", "size", "uid"],
    "the harness must expose the complete protected metadata comparison surface",
  );
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: injected filesystem exposes a same-size race between stable descriptor reads",
  async (t) => {
  const fixture = claimedJobFixture(t);
  const readClaimedBackupJob = requireClaimedJobReader();
  const replacement = Buffer.from(
    fixture.bytes.toString("utf8").replace(
      '"requestedBy": "control-center"',
      '"requestedBy": "control-centes"',
    ),
  );
  assert.equal(replacement.length, fixture.bytes.length);
  assert.notDeepEqual(replacement, fixture.bytes);

  const control = observedFilesystem(fixture);
  await readClaimedBackupJob(fixture.fileName, {
    ...claimedJobPolicy(fixture),
    fileSystem: control.fileSystem,
  });
  assert.equal(control.state.completeDescriptorReads >= 2, true);
  assert.equal(control.state.pathReadAttempts, 0);

  const observed = observedFilesystem(fixture, {
    afterFirstCompleteRead() {
      fs.writeFileSync(fixture.file, replacement, { mode: 0o600 });
    },
    freezeProtectedStats: true,
  });
  await assert.rejects(
    async () => readClaimedBackupJob(fixture.fileName, {
      ...claimedJobPolicy(fixture),
      fileSystem: observed.fileSystem,
    }),
    /claimed job.*(?:changed|stable|race|read)/i,
  );
  assert.equal(observed.state.firstCompleteReadObserved, true, "the harness must race after one complete descriptor read");
  assert.equal(observed.state.protectedOpenCount > 0, true);
  assert.equal(observed.state.allProtectedOpensNoFollow, true);
  assert.equal(observed.state.pathReadAttempts, 0, "a pathname pre-read cannot satisfy stable descriptor admission");
  assert.equal(
    observed.state.completeDescriptorReads >= 2,
    true,
    "the race must be detected only after the consumer performs its second complete descriptor read",
  );
  assert.deepEqual(
    observed.state.protectedFstatSnapshots[0],
    observed.state.protectedFstatSnapshots.at(-1),
    "the content race freezes every protected stat field so only the two real descriptor buffers expose it",
  );
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: metadata-only races are rejected after two identical descriptor reads",
  async (t) => {
    const fixture = claimedJobFixture(t);
    const readClaimedBackupJob = requireClaimedJobReader();
    const control = observedFilesystem(fixture);
    await readClaimedBackupJob(fixture.fileName, {
      ...claimedJobPolicy(fixture),
      fileSystem: control.fileSystem,
    });
    assert.equal(control.state.completeDescriptorReads >= 2, true);
    assert.equal(control.state.fstatBeforeFirstCompleteRead, true);
    assert.equal(control.state.fstatAfterSecondCompleteRead, true);

    const observed = observedFilesystem(fixture, {
      afterFirstCompleteRead() {
        fs.chmodSync(fixture.file, 0o400);
      },
    });
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, {
        ...claimedJobPolicy(fixture),
        fileSystem: observed.fileSystem,
      }),
      /claimed job.*(?:changed|metadata|mode|permission|race|stable)/i,
    );
    assert.equal(observed.state.completeDescriptorReads >= 2, true);
    assert.equal(observed.state.pathReadAttempts, 0);
    assert.equal(observed.state.fstatBeforeFirstCompleteRead, true);
    assert.equal(observed.state.fstatAfterSecondCompleteRead, true);
    assert.notDeepEqual(
      observed.state.protectedFstatSnapshots[0],
      observed.state.protectedFstatSnapshots.at(-1),
      "the independent metadata-only race must leave the two data buffers unchanged but alter protected stat",
    );
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: stable-read compares every security-relevant fstat field",
  async (t) => {
    const fields = ["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"];
    for (const field of fields) {
      await t.test(field, async (st) => {
        const fixture = claimedJobFixture(st);
        const readClaimedBackupJob = requireClaimedJobReader();
        const control = observedFilesystem(fixture);
        await readClaimedBackupJob(fixture.fileName, {
          ...claimedJobPolicy(fixture),
          fileSystem: control.fileSystem,
        });
        assert.equal(control.state.fstatAfterSecondCompleteRead, true);

        const observed = observedFilesystem(fixture, {
          afterSecondReadStatOverrides(stat) {
            return { [field]: stat[field] + 1 };
          },
        });
        await assert.rejects(
          async () => readClaimedBackupJob(fixture.fileName, {
            ...claimedJobPolicy(fixture),
            fileSystem: observed.fileSystem,
          }),
          /claimed job.*(?:changed|metadata|race|stable|stat|mode|owner|link|size)/i,
          `${field} substitution must be rejected after the positive stable-read control`,
        );
        assert.equal(observed.state.completeDescriptorReads >= 2, true);
        assert.equal(observed.state.fstatBeforeFirstCompleteRead, true);
        assert.equal(observed.state.fstatAfterSecondCompleteRead, true);
      });
    }
  },
);

testWhenClientExports(
  ["readClaimedBackupJob"],
  "RED v2: claimed document types admit zero coercion",
  async (t) => {
  const invalidDocuments = [
    {
      label: "numeric ID",
      fileName: "1234567890123456.json",
      mutate(document) {
        document.id = 1234567890123456;
      },
      expected: /job id.*string|claimed job.*id/i,
    },
    {
      label: "raw ID whitespace with a canonical filename",
      fileName: "0123456789abcdef.json",
      mutate(document) {
        document.id = " 0123456789abcdef ";
      },
      expected: /claimed job.*id|invalid job id/i,
    },
    {
      label: "array operation",
      mutate(document) {
        document.operation = ["backup"];
      },
      expected: /job operation.*string|claimed job.*operation/i,
    },
    {
      label: "uppercase ID",
      fileName: "0123456789ABCDEf.json",
      mutate(document) {
        document.id = "0123456789ABCDEf";
      },
      expected: /claimed job.*id|invalid job id/i,
    },
    {
      label: "operation case",
      mutate(document) {
        document.operation = "Backup";
      },
      expected: /claimed job.*operation|backup operation/i,
    },
    {
      label: "operation whitespace",
      mutate(document) {
        document.operation = "backup ";
      },
      expected: /claimed job.*operation|backup operation/i,
    },
    {
      label: "dot is outside the exact v2 job identity alphabet",
      id: "job.0123456789ab",
      expected: /claimed job.*id|invalid job id/i,
    },
    {
      label: "underscore is outside the exact v2 job identity alphabet",
      id: "job_0123456789ab",
      expected: /claimed job.*id|invalid job id/i,
    },
    {
      label: "colon is outside the exact v2 job identity alphabet",
      id: "job:0123456789ab",
      expected: /claimed job.*id|invalid job id/i,
    },
    {
      label: "job identity is shorter than sixteen bytes",
      id: "a".repeat(15),
      expected: /claimed job.*id|invalid job id/i,
    },
    {
      label: "job identity exceeds one hundred twenty eight bytes",
      id: "a".repeat(129),
      expected: /claimed job.*id|invalid job id/i,
    },
    {
      label: "numeric startedAt is not a primitive ISO timestamp",
      mutate(document) {
        document.startedAt = Date.parse("2026-07-28T12:00:00.000Z");
      },
      expected: /claimed job.*startedAt|startedAt.*(?:string|ISO|timestamp)/i,
    },
    {
      label: "non-canonical startedAt is not admitted by Date coercion",
      mutate(document) {
        document.startedAt = "2026-07-28 12:00:00Z";
      },
      expected: /claimed job.*startedAt|startedAt.*(?:ISO|timestamp)/i,
    },
    {
      label: "resource external identity whitespace is not trimmed",
      mutate(document) {
        document.resources[0].externalId = " catalog ";
      },
      expected: /claimed job.*resource|resource identity|externalId/i,
    },
    {
      label: "resource name array is not string-coerced",
      mutate(document) {
        document.resources[0].name = ["catalog"];
      },
      expected: /claimed job.*resource|resource name.*string/i,
    },
    {
      label: "restore manifest path array is not string-coerced",
      operation: "restore-drill",
      mutate(document) {
        document.sourceManifestPath = ["manifests/source.json"];
      },
      expected: /restore.*manifest|source manifest.*string|backup path/i,
    },
    {
      label: "restore manifest backslash is not normalized",
      operation: "restore-drill",
      mutate(document) {
        document.sourceManifestPath = "manifests\\source.json";
      },
      expected: /restore.*manifest|source manifest|backup path/i,
    },
    {
      label: "restore manifest whitespace is not trimmed",
      operation: "restore-drill",
      mutate(document) {
        document.sourceManifestPath = " manifests/source.json ";
      },
      expected: /restore.*manifest|source manifest|backup path/i,
    },
    {
      label: "restore manifest nested traversal is rejected before normalization",
      operation: "restore-drill",
      mutate(document) {
        document.sourceManifestPath = "manifests/../source.json";
      },
      expected: /restore.*manifest|source manifest|backup path/i,
    },
  ];
  for (const scenario of invalidDocuments) {
    await t.test(scenario.label, async (st) => {
      const readClaimedBackupJob = requireClaimedJobReader();
      const control = claimedJobFixture(st, {
        operation: scenario.operation ?? "backup",
      });
      await assertValidClaimedJobControl(readClaimedBackupJob, control);
      const fixture = claimedJobFixture(st, {
        id: scenario.id,
        operation: scenario.operation,
        fileName: scenario.fileName,
        mutateDocument: scenario.mutate,
      });
      await assert.rejects(
        async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
        scenario.expected,
      );
    });
  }
  },
);

testWhenClientExports(
  ["readClaimedBackupJob", "runClientCommand"],
  "RED v2: CLI adapter admits only one exact --jobFileName basename",
  async (t) => {
    const fixture = claimedJobFixture(t);
    const runClientCommand = requireClientCommandRunner();
    const options = {
      ...clientOptions(),
      claimedJobPolicy: claimedJobPolicy(fixture),
      socketPath: path.join(fixture.directory, "must-not-connect.sock"),
    };
    const invalidArguments = [
      [
        "direct metadata aliases",
        [
          "--jobFileName",
          fixture.fileName,
          "--jobId",
          fixture.document.id,
          "--jobOperation",
          fixture.document.operation,
          "--jobSha256",
          sha256Bytes(fixture.bytes),
        ],
        /execute-backup-job.*only --jobFileName|requires --jobFileName <basename>/i,
      ],
      [
        "filename option alias",
        ["--jobFile", fixture.fileName],
        /execute-backup-job.*--jobFileName/i,
      ],
      [
        "absolute path",
        ["--jobFileName", fixture.file],
        /claimed job (?:basename|filename)/i,
      ],
      [
        "boxed-string filename",
        ["--jobFileName", new String(fixture.fileName)],
        /claimed job (?:basename|filename).*string/i,
      ],
    ];
    for (const [label, args, expected] of invalidArguments) {
      await t.test(label, async () => {
        await invokeValidCliControl(runClientCommand, fixture, {
          policy: claimedJobPolicy(fixture),
        });
        await assert.rejects(
          async () => runClientCommand("execute-backup-job", args, options),
          expected,
          `${label} must be rejected only after the exact filename-only control passes`,
        );
      });
    }
  },
);

function socketlessSafeCohortBodySource(completeTestSource, testName) {
  assert.equal(typeof completeTestSource, "string");
  assert.ok(SOCKETLESS_SAFE_COHORT_NAMES.includes(testName));
  const marker = `"${testName}"`;
  const markerCount = completeTestSource.split(marker).length - 1;
  assert.equal(
    markerCount,
    1,
    `${testName} source marker must remain unique and reachable`,
  );
  const start = completeTestSource.indexOf(marker);
  const remainder = completeTestSource.slice(start + marker.length);
  const nextTest = /\n(?:test|testWhenClientExports|testWhenProductionExports)\s*\(/.exec(remainder);
  assert.ok(nextTest, `${testName} must retain a bounded source region`);
  return remainder.slice(0, nextTest.index);
}

function assertSocketlessCohortCannotAttestWrapperLedger(source, label) {
  for (const forbidden of [
    "SOCKETLESS_PREIMPORT_GUARD_SYMBOL",
    "Symbol",
    "global",
    "platform-infrastructure.test.socketless-preimport-guard/v1",
    "runWrapper",
    "socketlessPreimportTodoBodyMustRemainClosed",
    "wrapperExtraEvents",
    "wrapperLedger",
  ]) {
    assert.equal(
      source.includes(forbidden),
      false,
      `${label} may not access or self-attest the private wrapper ledger via ${forbidden}`,
    );
  }
}

function assertDirectSocketlessWrapperArrow(source, exactLabel, label) {
  const directPrefix = new RegExp(
    `^,\\s*async\\s*(?:\\([^)]*\\)|[A-Za-z_$][A-Za-z0-9_$]*)\\s*=>\\s*` +
      `withSocketlessNetworkCapabilityTrap\\(\\s*${escapeRegularExpression(JSON.stringify(exactLabel))}\\s*,\\s*` +
      "async\\s*\\(executionGate\\)\\s*=>\\s*\\{\\s*" +
      "if\\s*\\(!executionGate\\.productionBodyAllowed\\)\\s*return;",
    "u",
  );
  assert.match(
    source,
    directPrefix,
    `${label} must start with a direct call to the const socketless wrapper and exact SAFE label`,
  );
}

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function socketlessExpectedFreshGuardCapabilities() {
  return [
    ...socketlessNetCallableNames().map((name) => `net.${name}`),
    "net.Server.prototype.listen",
    "net.Socket.prototype.connect",
    "process.getBuiltinModule",
  ].sort((left, right) => left.localeCompare(right));
}

function parseTapTestSummary(stdout) {
  const summary = {};
  for (const name of ["fail", "pass", "tests", "todo"]) {
    const matches = [...stdout.matchAll(new RegExp(`^# ${name} (\\d+)$`, "gm"))];
    assert.equal(matches.length, 1, `TAP summary must contain exactly one ${name} counter`);
    summary[name] = Number(matches[0][1]);
  }
  return summary;
}

async function runSocketlessGuardedSafeChild(wrapperMutant = "control") {
  assert.ok(
    ["bypass", "computed-global", "control", "double-alias", "preimport-steal"].includes(
      wrapperMutant,
    ),
    `unknown socketless wrapper mutant ${wrapperMutant}`,
  );
  const guardUrl = `data:text/javascript;charset=utf-8,${encodeURIComponent(
    socketlessFreshProcessGuardSource(),
  )}`;
  const exactNamePattern = `^(?:${SOCKETLESS_SAFE_COHORT_NAMES
    .map(escapeRegularExpression)
    .join("|")})(?: \\[activates when .+ is exported\\])?$`;
  const childEnvironment = {
    ...process.env,
    DOCKER_ACTION_TEST_SOCKETLESS_WRAPPER_MUTANT: wrapperMutant,
  };
  delete childEnvironment.NODE_OPTIONS;
  delete childEnvironment.NODE_TEST_CONTEXT;
  const preloadArguments = [`--import=${guardUrl}`];
  if (["computed-global", "double-alias", "preimport-steal"].includes(wrapperMutant)) {
    const hostileUrl = `data:text/javascript;charset=utf-8,${encodeURIComponent(
      socketlessHostilePreimportSource(),
    )}`;
    preloadArguments.push(`--import=${hostileUrl}`);
  }
  const result = await collectChildProcess(
    process.execPath,
    [
      ...preloadArguments,
      "--test",
      "--test-reporter=tap",
      `--test-name-pattern=${exactNamePattern}`,
      fileURLToPath(import.meta.url),
    ],
    {
      cwd: REPOSITORY_ROOT,
      env: childEnvironment,
    },
  );
  const guardOutput = `${result.stdout}\n${result.stderr}`;
  const guardReports = [...guardOutput.matchAll(
    /^(?:# )?SOCKETLESS_PREIMPORT_GUARD_REPORT=(\{.*\})$/gm,
  )];
  assert.equal(
    guardReports.length,
    1,
    `the ${wrapperMutant} child must emit exactly one private-ledger report; output:\n${guardOutput}`,
  );
  return {
    ...result,
    report: JSON.parse(guardReports[0][1]),
    summary: parseTapTestSummary(result.stdout),
  };
}

function assertSocketlessGuardedSafeChildEnvelope(result, label) {
  assert.equal(
    result.code,
    0,
    `${label} child must exit cleanly\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.signal, null);
  assert.deepEqual(Object.keys(result.report).sort(), [
    "lockedCapabilities",
    "staleAliasBlocked",
    "transcript",
    "wrapperExtraEvents",
    "wrapperLedger",
  ]);
  assert.equal(
    result.report.staleAliasBlocked,
    true,
    `${label} must block a node:net alias captured after the imported module graph`,
  );
  assert.deepEqual(
    result.report.transcript,
    [],
    `${label} must leave exactly zero NO-network capability attempts`,
  );
  assert.deepEqual(
    result.report.lockedCapabilities,
    socketlessExpectedFreshGuardCapabilities(),
    `${label} must lock the complete node:net surface and builtin escape`,
  );
  assert.deepEqual(
    result.report.wrapperExtraEvents,
    [],
    `${label} may not contain an unknown-label or invalid-body wrapper event`,
  );
  assert.deepEqual(
    result.report.wrapperLedger.map(({ label: wrapperLabel }) => wrapperLabel),
    SOCKETLESS_SAFE_COHORT_LABELS,
    `${label} must report only the three exact SAFE labels`,
  );
  const expectedTodoCount = [
    injectedAssemblyRequirements(),
    injectedAssemblyRequirements(),
    semanticCoreRequirements(),
  ].filter((requirements) => missingProductionExports(requirements).length > 0).length;
  assert.deepEqual(
    result.summary,
    {
      fail: 0,
      pass: SOCKETLESS_SAFE_COHORT_NAMES.length - expectedTodoCount,
      tests: SOCKETLESS_SAFE_COHORT_NAMES.length,
      todo: expectedTodoCount,
    },
    `${label} must execute only the three SAFE patterns with the exact current RED TODO count`,
  );
  for (const testName of SOCKETLESS_SAFE_COHORT_NAMES) {
    const resultLinePattern = new RegExp(
      `^ok \\d+ - ${escapeRegularExpression(testName)}(?: \\[.*\\])?(?: # TODO(?: .*)?)?$`,
      "gm",
    );
    assert.equal(
      [...result.stdout.matchAll(resultLinePattern)].length,
      1,
      `${label} must select ${testName} exactly once without meta recursion`,
    );
  }
}

function assertExactSocketlessWrapperLedger(report, label) {
  const expected = SOCKETLESS_SAFE_COHORT_LABELS.map((wrapperLabel) => ({
    bodyEntries: 1,
    entries: 1,
    exits: 1,
    inFlight: 0,
    label: wrapperLabel,
  }));
  assert.deepEqual(
    report.wrapperLedger,
    expected,
    `${label} must attest exactly one completed wrapper invocation per SAFE label`,
  );
  assert.deepEqual(
    report.wrapperExtraEvents,
    [],
    `${label} must attest no extra wrapper event`,
  );
}

async function socketlessFreshProcessGuardMain() {
  const wrapperMode = process.env.DOCKER_ACTION_TEST_SOCKETLESS_WRAPPER_MUTANT;
  if (
    wrapperMode !== "bypass" &&
    wrapperMode !== "computed-global" &&
    wrapperMode !== "control" &&
    wrapperMode !== "double-alias" &&
    wrapperMode !== "preimport-steal"
  ) {
    throw new Error(`fresh-process guard rejected wrapper mode ${String(wrapperMode)}`);
  }
  const arraySlice = Function.prototype.call.bind(Array.prototype.slice);
  const arraySort = Function.prototype.call.bind(Array.prototype.sort);
  const objectCreate = Object.create;
  const objectDefineProperty = Object.defineProperty;
  const objectFreeze = Object.freeze;
  const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const reflectApply = Reflect.apply;
  const reflectGet = Reflect.get;
  const reflectOwnKeys = Reflect.ownKeys;
  const stringify = JSON.stringify;
  const stringFrom = String;
  const stringLocaleCompare = Function.prototype.call.bind(String.prototype.localeCompare);
  const openProductionBodyGate = objectFreeze({ productionBodyAllowed: true });
  const closedProductionBodyGate = objectFreeze({ productionBodyAllowed: false });
  const [
    { default: guardedNet },
    { syncBuiltinESMExports: synchronizeBuiltins },
    { writeSync },
  ] = await Promise.all([import("node:net"), import("node:module"), import("node:fs")]);
  void process.stdin;
  void process.stdout;
  void process.stderr;
  const attempts = [];
  let attemptCount = 0;
  const installations = [];
  let installationCount = 0;
  const exactWrapperLabels = [
    "in-memory request producer SAFE cohort",
    "in-memory response producer SAFE cohort",
    "in-memory semantic executor SAFE cohort",
  ];
  const privateWrapperLedger = [
    {
      bodyEntries: 0,
      entries: 0,
      exits: 0,
      inFlight: 0,
      label: exactWrapperLabels[0],
    },
    {
      bodyEntries: 0,
      entries: 0,
      exits: 0,
      inFlight: 0,
      label: exactWrapperLabels[1],
    },
    {
      bodyEntries: 0,
      entries: 0,
      exits: 0,
      inFlight: 0,
      label: exactWrapperLabels[2],
    },
  ];
  const wrapperExtraEvents = [];
  let wrapperExtraEventCount = 0;

  function addWrapperExtraEvent(event) {
    wrapperExtraEvents[wrapperExtraEventCount] = event;
    wrapperExtraEventCount += 1;
  }

  function wrapperState(label) {
    if (label === exactWrapperLabels[0]) return privateWrapperLedger[0];
    if (label === exactWrapperLabels[1]) return privateWrapperLedger[1];
    if (label === exactWrapperLabels[2]) return privateWrapperLedger[2];
    return undefined;
  }

  function blockedCapability(label) {
    return function preimportNoNetworkCapability() {
      attempts[attemptCount] = label;
      attemptCount += 1;
      const error = new Error(`fresh-process NO-network guard blocked ${label}`);
      error.code = "ERR_TEST_FRESH_NO_NETWORK_CAPABILITY";
      throw error;
    };
  }

  function install(target, property, label) {
    const descriptor = objectGetOwnPropertyDescriptor(target, property);
    if (!descriptor || descriptor.configurable !== true) {
      throw new Error(`fresh-process guard cannot lock ${label}`);
    }
    const blocker = blockedCapability(label);
    objectDefineProperty(target, property, {
      configurable: false,
      enumerable: descriptor.enumerable,
      value: blocker,
      writable: false,
    });
    installations[installationCount] = { blocker, label, property, target };
    installationCount += 1;
  }

  const originalSocketPrototype = guardedNet.Socket.prototype;
  const originalServerPrototype = guardedNet.Server.prototype;
  install(originalSocketPrototype, "connect", "net.Socket.prototype.connect");
  install(originalServerPrototype, "listen", "net.Server.prototype.listen");

  const callableNames = [];
  let callableNameCount = 0;
  for (const name of reflectOwnKeys(guardedNet)) {
    if (typeof name !== "string" || typeof reflectGet(guardedNet, name) !== "function") continue;
    callableNames[callableNameCount] = name;
    callableNameCount += 1;
  }
  arraySort(callableNames, (left, right) => stringLocaleCompare(left, right));
  for (let index = 0; index < callableNameCount; index += 1) {
    const name = callableNames[index];
    install(guardedNet, name, `net.${name}`);
  }
  install(process, "getBuiltinModule", "process.getBuiltinModule");
  synchronizeBuiltins();
  const synchronizedNetNamespace = await import("node:net");

  async function runWrapper(label, body, productionBodyAllowed) {
    const state = wrapperState(label);
    if (!state) {
      addWrapperExtraEvent(`unexpected-label:${stringFrom(label)}`);
      return undefined;
    }
    if (typeof body !== "function") {
      addWrapperExtraEvent(`invalid-body:${label}`);
      return undefined;
    }
    if (typeof productionBodyAllowed !== "boolean") {
      addWrapperExtraEvent(`invalid-production-body-gate:${label}`);
      productionBodyAllowed = false;
    }
    const initialAttemptCount = attemptCount;
    const invocationCount = 1;
    const countWrapperLifecycle = wrapperMode !== "bypass";
    const executionGate = productionBodyAllowed
      ? openProductionBodyGate
      : closedProductionBodyGate;
    let bodyError;
    let value;
    for (let invocation = 0; invocation < invocationCount; invocation += 1) {
      state.bodyEntries += 1;
      if (countWrapperLifecycle) {
        state.entries += 1;
        state.inFlight += 1;
      }
      try {
        value = await reflectApply(body, undefined, [executionGate]);
      } catch (error) {
        bodyError = error;
      } finally {
        if (countWrapperLifecycle) {
          state.exits += 1;
          state.inFlight -= 1;
        }
      }
      if (bodyError) break;
    }
    if (attemptCount !== initialAttemptCount) {
      const error = new Error(`SAFE wrapper ${label} attempted a NO-network capability`);
      error.code = "ERR_TEST_FRESH_NO_NETWORK_CAPABILITY";
      throw error;
    }
    if (bodyError) throw bodyError;
    return value;
  }

  objectFreeze(runWrapper);
  const guardFacade = objectCreate(null);
  objectDefineProperty(guardFacade, "runWrapper", {
    configurable: false,
    enumerable: true,
    value: runWrapper,
    writable: false,
  });
  objectFreeze(guardFacade);
  objectDefineProperty(
    globalThis,
    Symbol.for("platform-infrastructure.test.socketless-preimport-guard/v1"),
    {
      configurable: false,
      enumerable: false,
      value: guardFacade,
      writable: false,
    },
  );

  process.once("exit", () => {
    let staleAliasBlocked = false;
    let transcript = arraySlice(attempts, 0, attemptCount);
    try {
      if (attemptCount !== 0) {
        throw new Error(`SAFE cohorts attempted guarded capabilities: ${stringify(transcript)}`);
      }
      const staleAliasCapturedAfterModuleImport = synchronizedNetNamespace.createServer;
      try {
        reflectApply(staleAliasCapturedAfterModuleImport, undefined, []);
      } catch (error) {
        staleAliasBlocked = error?.code === "ERR_TEST_FRESH_NO_NETWORK_CAPABILITY";
      }
      if (!staleAliasBlocked) {
        throw new Error("the post-import node:net alias was not blocked");
      }
      if (
        attemptCount !== 1 ||
        attempts[0] !== "net.createServer"
      ) {
        throw new Error(
          `unexpected stale-alias transcript: ${stringify(arraySlice(attempts, 0, attemptCount))}`,
        );
      }
      attemptCount = 0;
      attempts.length = 0;
      transcript = [];
      for (let index = 0; index < installationCount; index += 1) {
        const installation = installations[index];
        const descriptor = objectGetOwnPropertyDescriptor(
          installation.target,
          installation.property,
        );
        if (
          descriptor?.configurable !== false ||
          descriptor?.writable !== false ||
          descriptor?.value !== installation.blocker
        ) {
          throw new Error(`guard lock drifted for ${installation.label}`);
        }
      }
    } catch (error) {
      process.exitCode = 1;
      transcript = arraySlice(attempts, 0, attemptCount);
    }
    const lockedCapabilities = [];
    for (let index = 0; index < installationCount; index += 1) {
      lockedCapabilities[index] = installations[index].label;
    }
    arraySort(lockedCapabilities, (left, right) => stringLocaleCompare(left, right));
    const report = {
      lockedCapabilities,
      staleAliasBlocked,
      transcript,
      wrapperExtraEvents: arraySlice(wrapperExtraEvents, 0, wrapperExtraEventCount),
      wrapperLedger: [
        {
          bodyEntries: privateWrapperLedger[0].bodyEntries,
          entries: privateWrapperLedger[0].entries,
          exits: privateWrapperLedger[0].exits,
          inFlight: privateWrapperLedger[0].inFlight,
          label: privateWrapperLedger[0].label,
        },
        {
          bodyEntries: privateWrapperLedger[1].bodyEntries,
          entries: privateWrapperLedger[1].entries,
          exits: privateWrapperLedger[1].exits,
          inFlight: privateWrapperLedger[1].inFlight,
          label: privateWrapperLedger[1].label,
        },
        {
          bodyEntries: privateWrapperLedger[2].bodyEntries,
          entries: privateWrapperLedger[2].entries,
          exits: privateWrapperLedger[2].exits,
          inFlight: privateWrapperLedger[2].inFlight,
          label: privateWrapperLedger[2].label,
        },
      ],
    };
    writeSync(2, `SOCKETLESS_PREIMPORT_GUARD_REPORT=${stringify(report)}\n`);
  });
}

function socketlessFreshProcessGuardSource() {
  return `await (${Function.prototype.toString.call(socketlessFreshProcessGuardMain)})();\n`;
}

async function socketlessHostilePreimportMain() {
  const wrapperMode = process.env.DOCKER_ACTION_TEST_SOCKETLESS_WRAPPER_MUTANT;
  if (
    wrapperMode !== "computed-global" &&
    wrapperMode !== "double-alias" &&
    wrapperMode !== "preimport-steal"
  ) return;
  const computedGuardIdentity = [
    "platform-infrastructure",
    "test",
    "socketless-preimport-guard/v1",
  ].join(".");
  const symbolFactory = Symbol[["f", "or"].join("")];
  const facade = globalThis[symbolFactory(computedGuardIdentity)];
  const computedOperation = facade[["run", "Wrapper"].join("")];
  const aliasedOperation = computedOperation;
  const exactLabels = [
    "in-memory request producer SAFE cohort",
    "in-memory response producer SAFE cohort",
    "in-memory semantic executor SAFE cohort",
  ];
  let originalPushDescriptor;
  let originalWrapperMode;
  if (wrapperMode === "preimport-steal") {
    originalPushDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "push");
    originalWrapperMode = process.env.DOCKER_ACTION_TEST_SOCKETLESS_WRAPPER_MUTANT;
    process.env.DOCKER_ACTION_TEST_SOCKETLESS_WRAPPER_MUTANT = "bypass";
    Object.defineProperty(Array.prototype, "push", {
      configurable: true,
      enumerable: originalPushDescriptor.enumerable,
      value() {
        return this.length;
      },
      writable: true,
    });
  }
  try {
    for (let index = 0; index < exactLabels.length; index += 1) {
      await aliasedOperation(exactLabels[index], function hostilePreimportBody() {}, false);
    }
  } finally {
    if (originalPushDescriptor) {
      Object.defineProperty(Array.prototype, "push", originalPushDescriptor);
      process.env.DOCKER_ACTION_TEST_SOCKETLESS_WRAPPER_MUTANT = originalWrapperMode;
    }
  }
}

function socketlessHostilePreimportSource() {
  return `await (${Function.prototype.toString.call(socketlessHostilePreimportMain)})();\n`;
}

function socketlessNetCallableEntries() {
  return Reflect.ownKeys(net)
    .filter((name) => typeof name === "string")
    .map((name) => {
      const descriptor = Object.getOwnPropertyDescriptor(net, name);
      assert.ok(descriptor, `node:net export ${name} must retain an own descriptor`);
      const value = Object.hasOwn(descriptor, "value")
        ? descriptor.value
        : descriptor.get?.call(net);
      return { descriptor, name, value };
    })
    .filter(({ value }) => typeof value === "function")
    .sort((left, right) => left.name.localeCompare(right.name));
}

function socketlessNetCallableNames() {
  return socketlessNetCallableEntries().map(({ name }) => name);
}

function socketlessOriginalNetPrototype(name) {
  const entry = socketlessNetCallableEntries().find((candidate) => candidate.name === name);
  assert.ok(entry, `node:net must expose callable ${name}`);
  assert.ok(entry.value.prototype && typeof entry.value.prototype === "object");
  return entry.value.prototype;
}

function socketlessForbiddenSourceTokens() {
  return [...new Set([
    ...socketlessNetCallableNames(),
    "createDockerActionBroker",
    "exchangeWithLocalBroker",
    "realBrokerAssembly",
    "realDefaultSemanticBrokerAssembly",
    "sendActionRequest",
    "socketPath",
    "node:net",
    "net",
    "listen",
    "getBuiltinModule",
    "process",
    "globalThis",
    "Reflect",
    "Proxy",
    "eval",
    "Function",
    "constructor",
    "fromCharCode",
    "fromCodePoint",
    "getOwnPropertyDescriptor",
    "ownKeys",
    "require",
    "module",
  ])].sort((left, right) => left.localeCompare(right));
}

function socketlessSourceTokenPattern(token) {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(token)) {
    return new RegExp(`(?:^|[^A-Za-z0-9_$])${escaped}(?:$|[^A-Za-z0-9_$])`, "m");
  }
  return new RegExp(escaped, "m");
}

function rejectSocketlessSource(label, reason) {
  const error = new Error(`NO-UDS source oracle rejected ${label}: ${reason}`);
  error.code = "ERR_TEST_NO_UDS_SOURCE";
  throw error;
}

function assertSocketlessSourceOracle(source, label) {
  if (typeof source !== "string" || source.length === 0) {
    rejectSocketlessSource(label, "source is absent");
  }
  const normalized = source.normalize("NFKC");
  if (normalized !== source) {
    rejectSocketlessSource(label, "Unicode normalization changes the audited source");
  }
  if (/\\(?:u\{?[0-9a-fA-F]|x[0-9a-fA-F]{2})/.test(source)) {
    rejectSocketlessSource(label, "escaped identifiers or property names are forbidden");
  }
  if (/[^\x09\x0a\x0d\x20-\x7e]/.test(source)) {
    rejectSocketlessSource(label, "non-ASCII source is forbidden");
  }
  for (const token of socketlessForbiddenSourceTokens()) {
    if (socketlessSourceTokenPattern(token).test(source)) {
      rejectSocketlessSource(label, `forbidden capability token ${JSON.stringify(token)}`);
    }
  }
  return source;
}

const withSocketlessNetworkCapabilityTrap = (() => {
  const capturedPreimportGuard = globalThis[SOCKETLESS_PREIMPORT_GUARD_SYMBOL];
  const capturedGuardOperation = capturedPreimportGuard?.runWrapper;
  const openProductionBodyGate = Object.freeze({ productionBodyAllowed: true });

  return async function exactSocketlessNetworkCapabilityTrap(
    label,
    body,
    { expectedAttempts = [] } = {},
  ) {
  assert.equal(typeof body, "function", `${label} body must be callable`);
  assert.ok(Array.isArray(expectedAttempts), `${label} expected-attempt transcript must be an array`);
  const preimportGuard = capturedPreimportGuard;
  if (preimportGuard !== undefined) {
    assert.equal(Object.isFrozen(preimportGuard), true);
    assert.deepEqual(
      Object.keys(preimportGuard).sort(),
      ["runWrapper"],
      `${label} guard facade must expose only one immutable wrapper operation`,
    );
    const operationDescriptor = Object.getOwnPropertyDescriptor(preimportGuard, "runWrapper");
    assert.equal(operationDescriptor?.configurable, false);
    assert.equal(operationDescriptor?.writable, false);
    assert.equal(operationDescriptor?.value, capturedGuardOperation);
    assert.equal(Object.isFrozen(capturedGuardOperation), true);
    assert.deepEqual(
      expectedAttempts,
      [],
      `${label} SAFE cohort may not declare expected network attempts under the pre-import guard`,
    );
    assert.ok(
      SOCKETLESS_SAFE_COHORT_LABELS.includes(label),
      `${label} must be one of the three exact SAFE wrapper identities`,
    );
    const productionBodyAllowed = !socketlessPreimportTodoBodyMustRemainClosed;
    return capturedGuardOperation(label, body, productionBodyAllowed);
  }
  const attempts = [];
  const callableEntries = socketlessNetCallableEntries();
  const patches = [];
  const patchedProperties = new WeakMap();

  function stagePatch(target, property, attemptLabel) {
    let properties = patchedProperties.get(target);
    if (!properties) {
      properties = new Set();
      patchedProperties.set(target, properties);
    }
    if (properties.has(property)) return;
    properties.add(property);
    const descriptor = Object.getOwnPropertyDescriptor(target, property);
    assert.ok(descriptor, `${label} trap target ${attemptLabel} must have an own descriptor`);
    assert.equal(
      descriptor.configurable,
      true,
      `${label} trap target ${attemptLabel} must be reversibly configurable`,
    );
    patches.push({ attemptLabel, descriptor, property, target });
  }

  for (const entry of callableEntries) {
    stagePatch(net, entry.name, `net.${entry.name}`);
  }
  const constructorPrototypes = new Set();
  for (const entry of callableEntries) {
    const prototype = entry.value.prototype;
    if (!prototype || typeof prototype !== "object" || constructorPrototypes.has(prototype)) continue;
    constructorPrototypes.add(prototype);
    if (Object.hasOwn(prototype, "constructor")) {
      stagePatch(prototype, "constructor", `net.${entry.name}.prototype.constructor`);
    }
  }
  stagePatch(
    socketlessOriginalNetPrototype("Socket"),
    "connect",
    "net.Socket.prototype.connect",
  );
  stagePatch(
    socketlessOriginalNetPrototype("Server"),
    "listen",
    "net.Server.prototype.listen",
  );
  stagePatch(process, "getBuiltinModule", "process.getBuiltinModule");

  function blockedCapability(attemptLabel) {
    return function noUdsRuntimeCapability() {
      attempts.push(attemptLabel);
      const error = new Error(`NO-UDS runtime capability blocked ${attemptLabel}`);
      error.code = "ERR_TEST_NO_UDS_CAPABILITY";
      throw error;
    };
  }

  let bodyError;
  let value;
  try {
    for (const patch of patches) {
      Object.defineProperty(patch.target, patch.property, {
        configurable: true,
        enumerable: patch.descriptor.enumerable,
        value: blockedCapability(patch.attemptLabel),
        writable: false,
      });
    }
    syncBuiltinESMExports();
    try {
      value = await body(openProductionBodyGate);
    } catch (error) {
      bodyError = error;
    }
  } finally {
    for (const patch of patches.toReversed()) {
      Object.defineProperty(
        patch.target,
        patch.property,
        patch.descriptor,
      );
    }
    syncBuiltinESMExports();
  }

  assert.deepEqual(
    attempts,
    expectedAttempts,
    `${label} must retain the exact NO-UDS capability-attempt transcript`,
  );
  if (bodyError) throw bodyError;
  return value;
  };
})();

function testWhenClientExports(exportNames, name, body) {
  const missing = exportNames.filter((exportName) => typeof client[exportName] !== "function");
  if (missing.length > 0) {
    return test.todo(`${name} [activates when ${missing.join(", ")} is exported]`);
  }
  return test(name, body);
}

function injectedAssemblyRequirements({
  brokerModule = broker,
  contractModule = actionContract,
} = {}) {
  return [
    [contractModule, "normalizeActionResponse"],
    [contractModule, "signActionResponse"],
    [brokerModule, "encodeActionResponseFrame"],
  ];
}

function semanticCoreRequirements(options = {}) {
  const {
    brokerModule = broker,
  } = options;
  return [
    ...injectedAssemblyRequirements(options),
    [brokerModule, "createSemanticActionExecutor"],
  ];
}

function schedulerMainRequirements({
  brokerModule = broker,
  clientModule = client,
  contractModule = actionContract,
} = {}) {
  return [
    [clientModule, "defaultClaimedJobPolicy"],
    [clientModule, "readClaimedBackupJob"],
    [clientModule, "runClientCommand"],
    ...injectedAssemblyRequirements({ brokerModule, contractModule }),
  ];
}

function missingProductionExports(requirements) {
  return requirements
    .filter(([module, exportName]) => typeof module[exportName] !== "function")
    .map(([, exportName]) => exportName);
}

function testWhenProductionExports(requirements, name, body) {
  const missing = missingProductionExports(requirements);
  const safeCohortIndex = SOCKETLESS_SAFE_COHORT_NAMES.indexOf(name);
  const preimportGuard = globalThis[SOCKETLESS_PREIMPORT_GUARD_SYMBOL];
  if (preimportGuard !== undefined && safeCohortIndex !== -1) {
    const registeredName = missing.length === 0
      ? name
      : `${name} [activates when ${missing.join(", ")} is exported]`;
    return test(registeredName, async (t) => {
      if (missing.length > 0) t.todo(`activates when ${missing.join(", ")} is exported`);
      const previousBodyGate = socketlessPreimportTodoBodyMustRemainClosed;
      socketlessPreimportTodoBodyMustRemainClosed = missing.length > 0;
      try {
        await body(t);
      } finally {
        socketlessPreimportTodoBodyMustRemainClosed = previousBodyGate;
      }
    });
  }
  if (missing.length > 0) {
    return test.todo(`${name} [activates when ${missing.join(", ")} is exported]`);
  }
  return test(name, body);
}

function requireClaimedJobReader() {
  assert.equal(
    typeof client.readClaimedBackupJob,
    "function",
    "docker-action-client.mjs must export readClaimedBackupJob; the claimed-file boundary belongs to the real client",
  );
  return client.readClaimedBackupJob;
}

function requireClientCommandRunner() {
  assert.equal(
    typeof client.runClientCommand,
    "function",
    "docker-action-client.mjs must export runClientCommand so the real CLI adapter is behaviorally testable",
  );
  return client.runClientCommand;
}

function clientOptions() {
  return {
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityKey: CAPABILITY,
    now: NOW,
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
  };
}

function claimedJobFixture(t, {
  id = "0123456789abcdef",
  operation = "backup",
  fileName = `${id}.json`,
  mutateDocument,
  rawBytes,
} = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-claimed-job-"));
  const root = path.join(directory, "running");
  fs.chmodSync(directory, 0o700);
  fs.mkdirSync(root, { mode: 0o700 });
  const document = backupJobDocument({ id, operation });
  if (mutateDocument !== undefined) {
    assert.equal(typeof mutateDocument, "function", "mutateDocument fixture hook must be callable");
    mutateDocument(document);
  }
  const selectedBytes = typeof rawBytes === "function" ? rawBytes(document) : rawBytes;
  const bytes = selectedBytes === undefined
    ? Buffer.from(`${JSON.stringify(document, null, 2)}\n`)
    : Buffer.from(selectedBytes);
  const file = path.join(root, fileName);
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return {
    bytes,
    directory,
    document,
    file,
    fileName,
    root,
  };
}

function backupJobDocument({ id, operation }) {
  const document = {
    schema: BACKUP_JOB_SCHEMA,
    id,
    operation,
    scope: {
      kind: "platform",
      id: "platform",
    },
    resources: [
      {
        id: "platform-state:catalog",
        externalId: "catalog",
        kind: "platform-state",
        projectId: "platform",
        name: "catalog",
      },
    ],
    requestedBy: "control-center",
    environment: "production",
    status: "running",
    createdAt: "2026-07-28T11:59:00.000Z",
    updatedAt: "2026-07-28T12:00:00.000Z",
    startedAt: "2026-07-28T12:00:00.000Z",
    finishedAt: null,
    resultSummary: "Claimed by the socketless scheduler.",
    reportPaths: [],
  };
  if (operation === "restore-drill") document.sourceManifestPath = "manifests/source.json";
  return document;
}

function claimedJobPolicy(fixture) {
  return {
    trustedRoot: fixture.root,
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
    maximumBytes: MAX_CLAIMED_JOB_BYTES,
  };
}

function capabilityFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-capability-"));
  fs.chmodSync(directory, 0o700);
  const capability = path.join(directory, "capability");
  fs.writeFileSync(capability, CAPABILITY, { mode: 0o400 });
  fs.chmodSync(capability, 0o400);
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return { capability, directory };
}

async function assertValidClaimedJobControl(readClaimedBackupJob, fixture) {
  const expected = {
    jobFileName: fixture.fileName,
    jobId: fixture.document.id,
    jobOperation: fixture.document.operation,
    jobSha256: sha256Bytes(fixture.bytes),
  };
  const actual = await readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture));
  assert.deepEqual(Object.keys(actual).sort(), [
    "jobFileName",
    "jobId",
    "jobOperation",
    "jobSha256",
  ]);
  assert.deepEqual(actual, expected);
  return expected;
}

function exactBoundJsonBytes(document, maximumBytes) {
  const json = Buffer.from(JSON.stringify(document));
  assert.ok(json.length + 1 <= maximumBytes, "base fixture must fit below the exact claimed-job bound");
  return Buffer.concat([
    json,
    Buffer.alloc(maximumBytes - json.length - 1, 0x20),
    Buffer.from("\n"),
  ]);
}

function* jsonStrings(value) {
  if (typeof value === "string") {
    yield value;
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) yield* jsonStrings(item);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) yield* jsonStrings(item);
  }
}

function observedFilesystem(fixture, {
  afterFirstCompleteRead,
  afterSecondReadStatOverrides,
  freezeProtectedStats = false,
} = {}) {
  const target = path.resolve(fixture.file);
  const descriptorState = new Map();
  let frozenProtectedStat;
  const state = {
    allProtectedOpensNoFollow: true,
    completeDescriptorReads: 0,
    descriptorBytesRead: 0,
    fstatAfterSecondCompleteRead: false,
    fstatBeforeFirstCompleteRead: false,
    firstCompleteReadObserved: false,
    pathReadAttempts: 0,
    protectedFstatCount: 0,
    protectedFstatSnapshots: [],
    protectedOpenCount: 0,
  };

  function isTarget(value) {
    return typeof value === "string" && path.resolve(value) === target;
  }

  function observeCompleteRead() {
    state.completeDescriptorReads += 1;
    if (state.completeDescriptorReads === 1) {
      state.firstCompleteReadObserved = true;
      afterFirstCompleteRead?.();
    }
  }

  function observeDescriptorBytes(descriptor, count, position) {
    const observed = descriptorState.get(descriptor);
    if (!observed || count <= 0) return;
    state.descriptorBytesRead += count;
    if (observed.completed && position === 0) {
      observed.completed = false;
      observed.covered = new Uint8Array(fixture.bytes.length);
      observed.coveredBytes = 0;
    }
    const start = Number.isInteger(position) && position >= 0
      ? position
      : observed.implicitPosition;
    const end = Math.min(start + count, fixture.bytes.length);
    for (let index = Math.max(0, start); index < end; index += 1) {
      if (observed.covered[index] === 0) {
        observed.covered[index] = 1;
        observed.coveredBytes += 1;
      }
    }
    observed.implicitPosition = start + count;
    if (!observed.completed && observed.coveredBytes === fixture.bytes.length) {
      observed.completed = true;
      observeCompleteRead();
    }
  }

  const overrides = {
    openSync(file, flags, ...args) {
      const descriptor = fs.openSync(file, flags, ...args);
      if (isTarget(file)) {
        state.protectedOpenCount += 1;
        const noFollow = fs.constants.O_NOFOLLOW ?? 0;
        state.allProtectedOpensNoFollow &&= (
          typeof flags === "number"
          && noFollow !== 0
          && (flags & noFollow) === noFollow
        );
        descriptorState.set(descriptor, {
          completed: false,
          covered: new Uint8Array(fixture.bytes.length),
          coveredBytes: 0,
          implicitPosition: 0,
        });
      }
      return descriptor;
    },
    readSync(descriptor, buffer, offset, length, position) {
      const count = fs.readSync(descriptor, buffer, offset, length, position);
      observeDescriptorBytes(descriptor, count, position);
      return count;
    },
    readFileSync(file, ...args) {
      if (typeof file !== "number" && isTarget(file)) state.pathReadAttempts += 1;
      const bytes = fs.readFileSync(file, ...args);
      if (typeof file === "number" && descriptorState.has(file)) {
        observeDescriptorBytes(file, Buffer.byteLength(bytes), 0);
      }
      return bytes;
    },
    fstatSync(descriptor, ...args) {
      const actual = fs.fstatSync(descriptor, ...args);
      if (!descriptorState.has(descriptor)) return actual;
      state.protectedFstatCount += 1;
      state.fstatBeforeFirstCompleteRead ||= state.completeDescriptorReads === 0;
      state.fstatAfterSecondCompleteRead ||= state.completeDescriptorReads >= 2;
      frozenProtectedStat ??= statMetadata(actual);
      let overridesForRead = freezeProtectedStats
        ? frozenProtectedStat
        : {};
      if (state.completeDescriptorReads >= 2 && afterSecondReadStatOverrides) {
        overridesForRead = {
          ...overridesForRead,
          ...afterSecondReadStatOverrides(actual),
        };
      }
      const observed = statWithOverrides(actual, overridesForRead);
      state.protectedFstatSnapshots.push(statMetadata(observed));
      return observed;
    },
    closeSync(descriptor) {
      descriptorState.delete(descriptor);
      return fs.closeSync(descriptor);
    },
  };
  const fileSystem = new Proxy(fs, {
    get(targetFs, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property];
      const value = Reflect.get(targetFs, property);
      return typeof value === "function" ? value.bind(targetFs) : value;
    },
  });
  return { fileSystem, state };
}

function statMetadata(stat) {
  return Object.fromEntries(
    ["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"]
      .map((field) => [field, stat[field]]),
  );
}

function statWithOverrides(stat, overrides) {
  return new Proxy(stat, {
    get(target, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property];
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function observedDescriptorRead(fileSystem, descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = fileSystem.readSync(
      descriptor,
      bytes,
      offset,
      size - offset,
      offset,
    );
    if (count === 0) break;
    offset += count;
  }
  assert.equal(offset, size, "the independent filesystem-double driver must complete its read");
  return bytes;
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function assertProductionResponseFrame(frame, response) {
  assert.ok(
    typeof frame === "string" || Buffer.isBuffer(frame),
    "the production response encoder must return exact string or Buffer wire bytes",
  );
  const bytes = Buffer.isBuffer(frame) ? frame : Buffer.from(frame);
  assert.deepEqual(
    bytes,
    Buffer.from(`${canonicalJsonOracle(response)}\n`),
    "the production broker encoder must emit exactly canonical JSON plus one LF",
  );
}

function assertProductionEncoderMatchesWrittenFrame(frame, response, label) {
  const reordered = Object.fromEntries(Object.entries(response).reverse());
  const legacyFrame = Buffer.from(`${JSON.stringify(reordered)}\n`);
  const canonicalFrame = Buffer.from(`${canonicalJsonOracle(response)}\n`);
  assert.notDeepEqual(
    legacyFrame,
    canonicalFrame,
    `${label} fixture must distinguish legacy JSON.stringify from canonical encoding`,
  );
  const encoded = broker.encodeActionResponseFrame(reordered);
  assertProductionResponseFrame(encoded, response);
  assert.deepEqual(
    Buffer.from(frame),
    Buffer.from(encoded),
    `${label} bytes written by the real broker must be the production encoder bytes`,
  );
}

function canonicalJsonOracle(value) {
  return JSON.stringify(canonicalValueOracle(value));
}

function shallowCanonicalJsonOracle(value) {
  assert.ok(
    value && typeof value === "object" && !Array.isArray(value),
    "shallow canonicalization oracle requires one object",
  );
  return JSON.stringify(
    Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])),
  );
}

function canonicalValueOracle(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalValueOracle);
  assert.ok(
    value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype,
    "canonical wire oracle accepts only plain JSON values",
  );
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalValueOracle(value[key])]),
  );
}

function wireRequest() {
  const unsigned = {
    schema: REQUEST_SCHEMA_V2,
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
    issuedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 30_000).toISOString(),
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityId: "evidence.runtime.snapshot.v2",
    action: "evidence.runtime.snapshot",
    parameters: {},
  };
  return {
    ...unsigned,
    mac: crypto
      .createHmac("sha256", CAPABILITY)
      .update(REQUEST_MAC_DOMAIN)
      .update(canonicalJsonOracle(unsigned))
      .digest("hex"),
  };
}

function requestMac(unsigned) {
  return domainMac(REQUEST_MAC_DOMAIN, unsigned);
}

function domainMac(domain, unsigned) {
  return domainMacWithKey(domain, unsigned, CAPABILITY);
}

function domainMacWithKey(domain, unsigned, capabilityKey) {
  return crypto
    .createHmac("sha256", capabilityKey)
    .update(domain)
    .update(canonicalJsonOracle(unsigned))
    .digest("hex");
}

function legacyMac(unsigned) {
  return crypto
    .createHmac("sha256", CAPABILITY)
    .update(canonicalJsonOracle(unsigned))
    .digest("hex");
}

function assertManualRequestV2(request) {
  assert.equal(request.schema, REQUEST_SCHEMA_V2);
  assert.deepEqual(Object.keys(request).sort(), [
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
  const unsigned = omit(request, "mac");
  assert.equal(request.mac, requestMac(unsigned));
  assert.notEqual(request.mac, legacyMac(unsigned));
  assert.notEqual(request.mac, domainMac(RESPONSE_MAC_DOMAIN, unsigned));
}

function canonicalActionResultV2(request) {
  const isClaimedJob = request.action === "backup.job.execute";
  let phaseId;
  let output;
  if (request.action === "evidence.runtime.snapshot") {
    // Broker-native evidence has no worker phase. The wire contract represents it
    // as this one explicit pseudo-phase so the inspected snapshot remains digest-bound.
    phaseId = EVIDENCE_PSEUDO_PHASE_ID;
    output = {
      schema: EVIDENCE_OUTPUT_SCHEMA,
      resources: {},
    };
  } else if (isClaimedJob && request.parameters.jobOperation === "backup") {
    phaseId = "job.backup.capture";
    output = canonicalJobWorkerOutput(request.parameters);
  } else if (isClaimedJob && request.parameters.jobOperation === "restore-drill") {
    phaseId = "job.restore.verify";
    output = canonicalJobWorkerOutput(request.parameters);
  } else {
    throw new TypeError(`client result fixture does not model action ${request.action}`);
  }
  const outputBytes = Buffer.from(canonicalJsonOracle(output));
  assert.ok(
    outputBytes.length <= MAX_PHASE_OUTPUT_BYTES,
    "the independent phase output fixture must stay inside the exact worker-output bound",
  );
  return {
    schema: RESULT_SCHEMA_V2,
    action: request.action,
    job: isClaimedJob
      ? {
          jobFileName: request.parameters.jobFileName,
          jobId: request.parameters.jobId,
          jobOperation: request.parameters.jobOperation,
          jobSha256: request.parameters.jobSha256,
        }
      : null,
    phases: [{
      output,
      outputSchema: output.schema,
      outputSha256: sha256Bytes(outputBytes),
      phaseId,
      status: "completed",
    }],
    status: "completed",
  };
}

function assertCanonicalActionResultV2(result, request) {
  assert.deepEqual(Object.keys(result).sort(), [
    "action",
    "job",
    "phases",
    "schema",
    "status",
  ]);
  assert.equal(result.schema, RESULT_SCHEMA_V2);
  assert.equal(result.action, request.action);
  assert.equal(result.status, "completed");
  if (request.action === "backup.job.execute") {
    assert.deepEqual(Object.keys(result.job).sort(), [
      "jobFileName",
      "jobId",
      "jobOperation",
      "jobSha256",
    ]);
    assert.deepEqual(result.job, request.parameters);
  } else {
    assert.equal(result.job, null);
  }
  assert.equal(result.phases.length, 1);
  assert.deepEqual(Object.keys(result.phases[0]).sort(), [
    "output",
    "outputSchema",
    "outputSha256",
    "phaseId",
    "status",
  ]);
  assert.equal(result.phases[0].status, "completed");
  assert.match(result.phases[0].outputSha256, /^[a-f0-9]{64}$/);
  assert.equal(result.phases[0].outputSchema, result.phases[0].output.schema);
  assert.equal(
    result.phases[0].outputSha256,
    sha256Bytes(canonicalJsonOracle(result.phases[0].output)),
  );
  assert.ok(
    Buffer.byteLength(canonicalJsonOracle(result.phases[0].output)) <= MAX_PHASE_OUTPUT_BYTES,
  );
  if (request.action === "evidence.runtime.snapshot") {
    assert.equal(result.phases[0].phaseId, EVIDENCE_PSEUDO_PHASE_ID);
    assert.equal(result.phases[0].outputSchema, EVIDENCE_OUTPUT_SCHEMA);
    assert.deepEqual(result.phases[0].output, {
      schema: EVIDENCE_OUTPUT_SCHEMA,
      resources: {},
    });
  } else if (request.parameters.jobOperation === "backup") {
    assert.equal(result.phases[0].phaseId, "job.backup.capture");
    assert.equal(result.phases[0].outputSchema, "platform.backup-job-result/v1");
    assert.deepEqual(result.phases[0].output, canonicalJobWorkerOutput(request.parameters));
  } else {
    assert.equal(result.phases[0].phaseId, "job.restore.verify");
    assert.equal(result.phases[0].outputSchema, "platform.backup-job-result/v1");
    assert.deepEqual(result.phases[0].output, canonicalJobWorkerOutput(request.parameters));
  }
}

function canonicalJobWorkerOutput(parameters) {
  return {
    schema: "platform.backup-job-result/v1",
    jobId: parameters.jobId,
    jobOperation: parameters.jobOperation,
    status: "passed",
    evidenceSha256: sha256Bytes(
      `test-only:backup-job-evidence:${parameters.jobId}:${parameters.jobOperation}`,
    ),
    mutationPerformed: true,
  };
}

function signedResponse(request, {
  status,
  statusCode,
  errorCode,
  result,
}) {
  return resignResponse({
    schema: RESPONSE_SCHEMA_V2,
    status,
    statusCode,
    errorCode,
    action: request.action,
    requestId: request.requestId,
    requestSha256: sha256Bytes(canonicalJsonOracle(request)),
    result,
    resultSha256: sha256Bytes(canonicalJsonOracle(result)),
  });
}

function resignResponse(unsigned) {
  return {
    ...unsigned,
    mac: domainMac(RESPONSE_MAC_DOMAIN, unsigned),
  };
}

function resignResponseWithResult(unsigned, result) {
  return resignResponse({
    ...unsigned,
    result,
    resultSha256: sha256Bytes(canonicalJsonOracle(result)),
  });
}

function independentlySignedResponseWithResult(response, result, capabilityKey) {
  const canonicalResponse = canonicalValueOracle(response);
  const canonicalResult = canonicalValueOracle(result);
  const unsigned = canonicalValueOracle({
    ...omit(canonicalResponse, "mac"),
    result: canonicalResult,
    resultSha256: sha256Bytes(canonicalJsonOracle(canonicalResult)),
  });
  return canonicalValueOracle({
    ...unsigned,
    mac: domainMacWithKey(RESPONSE_MAC_DOMAIN, unsigned, capabilityKey),
  });
}

function independentlyResignedRequest(request, changes, capabilityKey) {
  const unsigned = canonicalValueOracle({
    ...omit(canonicalValueOracle(request), "mac"),
    ...structuredClone(changes),
  });
  return canonicalValueOracle({
    ...unsigned,
    mac: domainMacWithKey(REQUEST_MAC_DOMAIN, unsigned, capabilityKey),
  });
}

function independentlySignedActionResponse(
  request,
  result,
  capabilityKey,
  {
    action = request.action,
  } = {},
) {
  const canonicalResult = canonicalValueOracle(result);
  const unsigned = canonicalValueOracle({
    schema: RESPONSE_SCHEMA_V2,
    status: "completed",
    statusCode: 200,
    errorCode: null,
    action,
    requestId: request.requestId,
    requestSha256: sha256Bytes(canonicalJsonOracle(request)),
    result: canonicalResult,
    resultSha256: sha256Bytes(canonicalJsonOracle(canonicalResult)),
  });
  return canonicalValueOracle({
    ...unsigned,
    mac: domainMacWithKey(RESPONSE_MAC_DOMAIN, unsigned, capabilityKey),
  });
}

function independentlyResealedIdentityResult(
  result,
  {
    action = result.action,
    job = result.job,
    phaseId = result.phases[0].phaseId,
    output = result.phases[0].output,
  } = {},
) {
  const canonicalOutput = canonicalValueOracle(output);
  const phase = canonicalValueOracle({
    ...result.phases[0],
    output: canonicalOutput,
    outputSha256: sha256Bytes(canonicalJsonOracle(canonicalOutput)),
    phaseId,
  });
  return canonicalValueOracle({
    ...result,
    action,
    job: structuredClone(job),
    phases: [phase],
  });
}

function canonicalIdentityCollisionFixture({
  requestIndex = 73,
} = {}) {
  const expectedAction = "backup.job.execute";
  const expectedJobId = "scheduled-platform-20260728-120000-a1b2c3";
  const parameters = {
    jobFileName: `${expectedJobId}.json`,
    jobId: expectedJobId,
    jobOperation: "backup",
    jobSha256: "1".repeat(64),
  };
  const { trusted } = buildFixtureTrustedContextV2({
    allowedActions: [expectedAction],
    now: NOW,
  });
  const capabilityKey = fixtureCapabilityKey(expectedAction);
  const request = canonicalValueOracle(buildFixtureSignedActionRequestV2(
    expectedAction,
    parameters,
    {
      capabilityKey,
      index: requestIndex,
      now: NOW,
      trustedContext: trusted,
    },
  ));
  const result = canonicalValueOracle(
    buildFixtureActionResultV2(expectedAction, parameters),
  );
  const expectedPhaseId = result.phases[0].phaseId;
  const control = independentlySignedActionResponse(
    request,
    result,
    capabilityKey,
  );
  const producerControlSnapshot = structuredClone(control);

  const actionMutations = [
    {
      boundary: "exact-identity",
      candidateIdentity: `${expectedAction}.nested`,
      label: "action exact prefix plus dotted nested identity",
      relationship: "prefix",
    },
    {
      boundary: "exact-identity",
      candidateIdentity: `nested.${expectedAction}`,
      label: "action dotted nested identity plus exact suffix",
      relationship: "suffix",
    },
  ].map(({ boundary, candidateIdentity, label, relationship }) => {
    const reboundResult = independentlyResealedIdentityResult(result, {
      action: candidateIdentity,
    });
    return {
      candidate: independentlySignedActionResponse(
        request,
        reboundResult,
        capabilityKey,
        { action: candidateIdentity },
      ),
      boundary,
      candidateIdentity,
      expectedIdentity: expectedAction,
      label,
      layer: "action",
      relationship,
      syntaxPattern: SAFE_ACTION_IDENTITY,
    };
  });

  const jobMutations = [
    {
      boundary: "exact-identity",
      candidateIdentity: `${expectedJobId}-child`,
      label: "job identity with the exact job as a prefix",
      relationship: "prefix",
    },
    {
      boundary: "exact-identity",
      candidateIdentity: `child-${expectedJobId}`,
      label: "job identity with the exact job as a suffix",
      relationship: "suffix",
    },
  ].map((mutation) => {
    const reboundResult = independentlyResealedIdentityResult(result, {
      job: {
        ...result.job,
        jobFileName: `${mutation.candidateIdentity}.json`,
        jobId: mutation.candidateIdentity,
      },
      output: {
        ...result.phases[0].output,
        jobId: mutation.candidateIdentity,
      },
    });
    return {
      ...mutation,
      candidate: independentlySignedActionResponse(
        request,
        reboundResult,
        capabilityKey,
      ),
      expectedIdentity: expectedJobId,
      layer: "job",
      syntaxPattern: /^[a-z0-9][a-z0-9-]{15,127}$/,
    };
  });

  const phaseMutations = [
    {
      boundary: "exact-identity",
      candidateIdentity: `${expectedPhaseId}.child`,
      label: "phase identity with the exact phase as a prefix",
      relationship: "prefix",
    },
    {
      boundary: "exact-identity",
      candidateIdentity: `child.${expectedPhaseId}`,
      label: "phase identity with the exact phase as a suffix",
      relationship: "suffix",
    },
  ].map((mutation) => {
    const reboundResult = independentlyResealedIdentityResult(result, {
      phaseId: mutation.candidateIdentity,
    });
    return {
      ...mutation,
      candidate: independentlySignedActionResponse(
        request,
        reboundResult,
        capabilityKey,
      ),
      expectedIdentity: expectedPhaseId,
      layer: "phase",
      syntaxPattern: /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/,
    };
  });

  return {
    capabilityKey,
    control,
    expectedAction,
    expectedJobId,
    expectedPhaseId,
    mutations: [
      ...actionMutations,
      ...jobMutations,
      ...phaseMutations,
    ],
    producerControlSnapshot,
    request,
  };
}

function slashChildActionGrammarFixture({
  requestIndex = 74,
} = {}) {
  const fixture = canonicalIdentityCollisionFixture({ requestIndex });
  const candidateIdentity = `${fixture.expectedAction}/child`;
  const reboundResult = independentlyResealedIdentityResult(
    fixture.control.result,
    { action: candidateIdentity },
  );
  return {
    capabilityKey: fixture.capabilityKey,
    control: fixture.control,
    expectedAction: fixture.expectedAction,
    mutation: {
      boundary: "grammar",
      candidate: independentlySignedActionResponse(
        fixture.request,
        reboundResult,
        fixture.capabilityKey,
        { action: candidateIdentity },
      ),
      candidateIdentity,
      expectedIdentity: fixture.expectedAction,
      label: "action exact prefix plus slash child",
      layer: "action",
      relationship: "prefix",
      syntaxPattern: null,
    },
    request: fixture.request,
  };
}

function assertCanonicalIdentityResponseSeal(response, request, capabilityKey) {
  assert.equal(
    request.mac,
    domainMacWithKey(
      REQUEST_MAC_DOMAIN,
      omit(request, "mac"),
      capabilityKey,
    ),
    "the complete hostile request fixture must retain an independent request-domain MAC",
  );
  assert.equal(
    response.requestSha256,
    sha256Bytes(canonicalJsonOracle(request)),
    "the response must bind the complete canonical signed request",
  );
  assert.notEqual(
    response.requestSha256,
    sha256Bytes(request.requestId),
    "the response request digest may not collapse to the shared request ID",
  );
  assert.equal(
    response.resultSha256,
    sha256Bytes(canonicalJsonOracle(response.result)),
    "the nested result must be independently re-digested",
  );
  for (const phase of response.result.phases) {
    assert.equal(
      phase.outputSha256,
      sha256Bytes(canonicalJsonOracle(phase.output)),
      `${phase.phaseId} output must be independently re-digested`,
    );
  }
  assert.equal(
    response.mac,
    domainMacWithKey(
      RESPONSE_MAC_DOMAIN,
      omit(response, "mac"),
      capabilityKey,
    ),
    "the complete hostile response must be independently re-MACed",
  );
}

function affixIdentityBlindResponseMutantAccepts(
  response,
  control,
  request,
  {
    candidateIdentity,
    expectedIdentity,
    layer,
    relationship,
  },
  capabilityKey,
) {
  if (JSON.stringify(response) !== canonicalJsonOracle(response)) return false;
  if (response.requestSha256 !== sha256Bytes(canonicalJsonOracle(request))) return false;
  if (response.resultSha256 !== sha256Bytes(canonicalJsonOracle(response.result))) return false;
  if (response.mac !== domainMacWithKey(
    RESPONSE_MAC_DOMAIN,
    omit(response, "mac"),
    capabilityKey,
  )) {
    return false;
  }
  if (response.result.phases.some((phase) => (
    phase.outputSha256 !== sha256Bytes(canonicalJsonOracle(phase.output))
  ))) {
    return false;
  }
  const affixMatches = relationship === "prefix"
    ? candidateIdentity.startsWith(expectedIdentity)
    : candidateIdentity.endsWith(expectedIdentity);
  if (!affixMatches || candidateIdentity === expectedIdentity) return false;

  const normalized = structuredClone(response);
  if (layer === "action") {
    if (normalized.action !== candidateIdentity
      || normalized.result.action !== candidateIdentity) {
      return false;
    }
    normalized.action = expectedIdentity;
    normalized.result.action = expectedIdentity;
  } else if (layer === "job") {
    const job = normalized.result.job;
    const output = normalized.result.phases[0]?.output;
    if (job?.jobId !== candidateIdentity
      || job.jobFileName !== `${candidateIdentity}.json`
      || output?.jobId !== candidateIdentity) {
      return false;
    }
    job.jobId = expectedIdentity;
    job.jobFileName = `${expectedIdentity}.json`;
    output.jobId = expectedIdentity;
    normalized.result.phases[0].outputSha256 =
      control.result.phases[0].outputSha256;
  } else if (layer === "phase") {
    if (normalized.result.phases[0]?.phaseId !== candidateIdentity) return false;
    normalized.result.phases[0].phaseId = expectedIdentity;
  } else {
    return false;
  }
  normalized.resultSha256 = control.resultSha256;
  normalized.mac = control.mac;
  return canonicalJsonOracle(normalized) === canonicalJsonOracle(control);
}

function affixIdentityBlindRequestMutantAccepts(
  request,
  control,
  {
    action,
    relationship,
  },
  capabilityKey,
) {
  if (JSON.stringify(request) !== canonicalJsonOracle(request)) return false;
  if (request.action !== action || request.action === control.action) return false;
  if (request.mac !== domainMacWithKey(
    REQUEST_MAC_DOMAIN,
    omit(request, "mac"),
    capabilityKey,
  )) {
    return false;
  }
  const affixMatches = relationship === "prefix"
    ? request.action.startsWith(control.action)
    : request.action.endsWith(control.action);
  if (!affixMatches) return false;
  const normalized = canonicalValueOracle({
    ...request,
    action: control.action,
    mac: control.mac,
  });
  return canonicalJsonOracle(normalized) === canonicalJsonOracle(control);
}

function independentlySignedNestedNonCanonicalResponse(response, capabilityKey) {
  const canonicalResponse = canonicalValueOracle(response);
  assert.ok(canonicalResponse.result, "nested-order fixture requires a completed result");
  assert.ok(
    canonicalResponse.result.phases?.[0]?.output,
    "nested-order fixture requires one worker output",
  );
  const reverseEntries = (value) => Object.fromEntries(Object.entries(value).reverse());
  const nestedResult = reverseEntries({
    ...canonicalResponse.result,
    phases: canonicalResponse.result.phases.map((phase, index) => (
      index === 0
        ? {
            ...phase,
            output: reverseEntries(phase.output),
          }
        : phase
    )),
  });
  const unsignedValues = {
    ...omit(canonicalResponse, "mac"),
    result: nestedResult,
    resultSha256: sha256Bytes(canonicalJsonOracle(nestedResult)),
  };
  const unsigned = Object.fromEntries(
    Object.keys(unsignedValues).sort().map((key) => [key, unsignedValues[key]]),
  );
  const complete = {
    ...unsigned,
    mac: domainMacWithKey(RESPONSE_MAC_DOMAIN, unsigned, capabilityKey),
  };
  return Object.fromEntries(
    Object.keys(complete).sort().map((key) => [key, complete[key]]),
  );
}

function assertNestedNonCanonicalResponseFixture(candidate, canonicalControl, capabilityKey) {
  assert.deepEqual(
    canonicalValueOracle(candidate),
    canonicalControl,
    "the hostile nested-order fixture must differ from its control only by insertion order",
  );
  assert.deepEqual(
    Object.keys(candidate),
    Object.keys(candidate).sort(),
    "the hostile fixture must keep the response's top-level insertion order canonical",
  );
  assert.deepEqual(
    Object.keys(candidate.result),
    [...Object.keys(canonicalControl.result)].reverse(),
    "the hostile fixture must reverse the nested result insertion order",
  );
  assert.deepEqual(
    Object.keys(candidate.result.phases[0].output),
    [...Object.keys(canonicalControl.result.phases[0].output)].reverse(),
    "the hostile fixture must independently reverse the nested worker output",
  );
  assert.equal(
    candidate.mac,
    domainMacWithKey(
      RESPONSE_MAC_DOMAIN,
      omit(candidate, "mac"),
      capabilityKey,
    ),
    "the hostile nested-order fixture must carry an independently valid response MAC",
  );
  assert.equal(
    candidate.resultSha256,
    sha256Bytes(canonicalJsonOracle(candidate.result)),
  );
  assert.equal(
    candidate.result.phases[0].outputSha256,
    sha256Bytes(canonicalJsonOracle(candidate.result.phases[0].output)),
    "the hostile nested output must retain its independently valid digest",
  );
  assert.equal(
    candidate.resultSha256,
    canonicalControl.resultSha256,
    "order-only result mutation must preserve the canonical result digest",
  );
  assert.equal(
    candidate.mac,
    canonicalControl.mac,
    "order-only response mutation must preserve the canonical response MAC",
  );
  assert.notEqual(
    shallowCanonicalJsonOracle(candidate),
    canonicalJsonOracle(candidate),
    "sorting only the top-level keys must fail this recursive canonicalization oracle",
  );
}

function shallowResponseWireMutantAccepts(frame) {
  if (typeof frame !== "string" || !frame.endsWith("\n")) return false;
  const wire = frame.slice(0, -1);
  if (wire.includes("\n")) return false;
  let parsed;
  try {
    parsed = JSON.parse(wire);
  } catch {
    return false;
  }
  return wire === shallowCanonicalJsonOracle(parsed);
}

function digestAndMacOnlyResponseMutantAccepts(response, capabilityKey) {
  if (!response?.result || typeof response.mac !== "string") return false;
  return response.resultSha256 === sha256Bytes(canonicalJsonOracle(response.result))
    && response.mac === domainMacWithKey(
      RESPONSE_MAC_DOMAIN,
      omit(response, "mac"),
      capabilityKey,
    );
}

function outerPlanIdentityBlindMutantAccepts(response, canonicalControl, capabilityKey) {
  if (!digestAndMacOnlyResponseMutantAccepts(response, capabilityKey)) return false;
  if (response.action !== canonicalControl.action) return false;
  const reboundResult = canonicalValueOracle({
    ...response.result,
    action: response.action,
  });
  return canonicalJsonOracle(reboundResult)
    === canonicalJsonOracle(canonicalControl.result);
}

function nestedPlanIdentityBlindMutantAccepts(response, capabilityKey) {
  if (!digestAndMacOnlyResponseMutantAccepts(response, capabilityKey)) return false;
  let expected;
  try {
    expected = canonicalValueOracle(
      buildFixtureActionResultV2(response.result.action),
    );
  } catch {
    return false;
  }
  return canonicalJsonOracle(response.result) === canonicalJsonOracle(expected);
}

function omit(value, key) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

async function exchangeWithLocalBroker(
  request,
  response,
  {
    capabilityKey = CAPABILITY,
    encodeResponse = JSON.stringify,
    responseFrame,
  } = {},
) {
  const exchange = await invokeWithLocalBroker(
    (socketPath) => sendActionRequest(request, socketPath, capabilityKey),
    (received) => {
      assert.deepEqual(received, request, "sendActionRequest must carry the exact request over the local UDS");
      return response;
    },
    { encodeResponse, responseFrame },
  );
  assert.deepEqual(exchange.request, request);
  return exchange.value;
}

async function invokeValidCliControl(
  runClientCommand,
  fixture,
  {
    policy = claimedJobPolicy(fixture),
  } = {},
) {
  return invokeWithLocalBroker(
    (socketPath) => runClientCommand(
      "execute-backup-job",
      ["--jobFileName", fixture.fileName],
      {
        ...clientOptions(),
        claimedJobPolicy: policy,
        socketPath,
      },
    ),
    (request) => {
      const result = canonicalActionResultV2(request);
      assertCanonicalActionResultV2(result, request);
      return signedResponse(request, {
        status: "completed",
        statusCode: 200,
        errorCode: null,
        result,
      });
    },
    { encodeResponse: canonicalJsonOracle },
  );
}

async function inMemoryBrokerCoreFixture({
  capabilityKey,
  now = () => NOW,
  outcomes,
  trusted,
}) {
  const responseFrames = [];
  const executedActions = [];
  const executedParameters = [];
  const fixtureReplayEvents = [];
  let capabilityProviderCalls = 0;
  let fixtureExecutorFactoryCalls = 0;
  let trustedContextProviderCalls = 0;
  let outcomeIndex = 0;
  const semanticExecutorOptions = Object.freeze({
    fixtureProbe: "client-in-memory-core",
  });
  const semanticExecutorFactory = (options) => {
    fixtureExecutorFactoryCalls += 1;
    assert.deepEqual(options, semanticExecutorOptions);
    return Object.freeze({
      async execute(action, { parameters }) {
        executedActions.push(action);
        executedParameters.push(structuredClone(parameters));
        const outcome = outcomes[outcomeIndex++];
        assert.ok(outcome, "the in-memory core fixture executed an unplanned semantic action");
        if (outcome.rejection) {
          const error = new Error(outcome.rejection);
          error.statusCode = 403;
          error.errorCode = "ACTION_REJECTED";
          error.semanticRejection = true;
          throw error;
        }
        return structuredClone(outcome.result);
      },
      async recoverLease() {
        throw new Error("the clean in-memory replay fixture must not recover a worker");
      },
    });
  };
  const semanticExecutor = semanticExecutorFactory(semanticExecutorOptions);
  const replayStore = {
    async recover(engine) {
      fixtureReplayEvents.push("recover");
      assert.equal(engine, semanticExecutor);
      return { status: "clean" };
    },
    admitActivation() {
      fixtureReplayEvents.push("activation");
    },
    admitTrustedContext() {
      fixtureReplayEvents.push("trusted");
    },
    consume() {
      fixtureReplayEvents.push("consume");
    },
    acquire(request, admittedTrusted) {
      fixtureReplayEvents.push("acquire");
      const lineage = Object.freeze({
        action: request.action,
        intentId: admittedTrusted.intent.intentId,
        receiptDigest: admittedTrusted.receiptDigest,
        request: structuredClone(request),
        requestId: request.requestId,
        requestSha256: sha256Bytes(canonicalJsonOracle(request)),
      });
      return Object.freeze({
        lineage,
        preserve() {
          fixtureReplayEvents.push("preserve");
        },
        recordEvent(event) {
          fixtureReplayEvents.push(`event:${String(event?.event ?? event?.type ?? "unknown")}`);
        },
        recordWorker() {},
        release() {
          fixtureReplayEvents.push("release");
        },
      });
    },
  };
  await replayStore.recover(semanticExecutor);
  const core = broker.createBrokerCore({
    trustedContextProvider: async () => {
      trustedContextProviderCalls += 1;
      return trusted;
    },
    capabilityProvider: async () => {
      capabilityProviderCalls += 1;
      return capabilityKey;
    },
    engine: semanticExecutor,
    replayStore,
    now,
    operationTimeoutMs: 100,
  });
  return {
    get capabilityProviderCalls() {
      return capabilityProviderCalls;
    },
    core,
    async exchange(request) {
      const exchange = await inMemoryCoreConnection(core, request);
      responseFrames.push(Buffer.from(exchange.frame));
      return exchange;
    },
    executedActions,
    executedParameters,
    get fixtureExecutorFactoryCalls() {
      return fixtureExecutorFactoryCalls;
    },
    fixtureReplayEvents,
    responseFrames,
    get trustedContextProviderCalls() {
      return trustedContextProviderCalls;
    },
  };
}

async function inMemoryCoreConnection(core, request) {
  assert.equal(
    JSON.stringify(request),
    canonicalJsonOracle(request),
    "the in-memory connection accepts only the exact canonical request object",
  );
  const requestFrame = Buffer.from(canonicalJsonOracle(request));
  assert.equal(
    requestFrame.includes(0x0a),
    false,
    "createBrokerCore receives the one frame payload without a transport delimiter",
  );
  const wire = await core.handle(requestFrame);
  assert.ok(wire && typeof wire === "object");
  assert.ok(wire.body && typeof wire.body === "object");
  assert.equal(
    wire.statusCode,
    wire.body.statusCode,
    "the in-memory connection must retain the core response status exactly",
  );
  const response = canonicalValueOracle(wire.body);
  const encoded = broker.encodeActionResponseFrame(response);
  const frame = Buffer.isBuffer(encoded)
    ? Buffer.from(encoded)
    : Buffer.from(encoded);
  assertProductionResponseFrame(frame, response);
  return Object.freeze({
    frame,
    requestFrame,
    response,
  });
}

function consumeInMemoryAssemblyResponse(
  exchange,
  request,
  capabilityKey,
  label,
) {
  assertProductionResponseFrame(exchange.frame, exchange.response);
  const admitted = actionContract.normalizeActionResponse(
    exchange.response,
    request,
    capabilityKey,
  );
  assert.deepEqual(
    admitted,
    exchange.response,
    `${label} must cross the real response consumer without normalization drift`,
  );
  assertProductionEncoderMatchesWrittenFrame(
    exchange.frame,
    admitted,
    label,
  );
  return admitted;
}

async function realBrokerAssembly(t, {
  capabilityKey,
  now = () => NOW,
  outcomes,
  trusted,
}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-real-assembly-"));
  fs.chmodSync(temporary, 0o700);
  const socketPath = path.join(temporary, "broker.sock");
  const stateDir = path.join(temporary, "state-must-remain-unmaterialized");
  const responseFrames = [];
  const executedActions = [];
  const executedParameters = [];
  const replayEvents = [];
  let capabilityProviderCalls = 0;
  let semanticExecutorFactoryCalls = 0;
  let trustedContextProviderCalls = 0;
  let outcomeIndex = 0;
  const semanticExecutorOptions = Object.freeze({
    assemblyProbe: "client-real-uds",
  });
  const semanticExecutor = Object.freeze({
    async execute(action, { parameters }) {
      executedActions.push(action);
      executedParameters.push(structuredClone(parameters));
      const outcome = outcomes[outcomeIndex++];
      assert.ok(outcome, "the real assembly executed an unplanned semantic action");
      if (outcome.rejection) {
        const error = new Error(outcome.rejection);
        error.statusCode = 403;
        error.errorCode = "ACTION_REJECTED";
        error.semanticRejection = true;
        throw error;
      }
      return structuredClone(outcome.result);
    },
    async recoverLease() {
      throw new Error("the clean replay fixture must not recover a worker");
    },
  });
  const replayStore = {
    async recover(engine) {
      replayEvents.push("recover");
      assert.equal(engine, semanticExecutor);
      return { status: "clean" };
    },
    admitActivation() {
      replayEvents.push("activation");
    },
    admitTrustedContext() {
      replayEvents.push("trusted");
    },
    consume() {
      replayEvents.push("consume");
    },
    acquire() {
      replayEvents.push("acquire");
      return {
        preserve() {
          replayEvents.push("preserve");
        },
        recordWorker() {},
        release() {
          replayEvents.push("release");
        },
      };
    },
  };
  const server = broker.createDockerActionBroker({
    socketPath,
    stateDir,
    trustedContextProvider: async () => {
      trustedContextProviderCalls += 1;
      return trusted;
    },
    capabilityProvider: async () => {
      capabilityProviderCalls += 1;
      return capabilityKey;
    },
    replayStore,
    semanticExecutorFactory(options) {
      semanticExecutorFactoryCalls += 1;
      assert.deepEqual(options, semanticExecutorOptions);
      return semanticExecutor;
    },
    semanticExecutorOptions,
    onResponseFrame(frame) {
      responseFrames.push(Buffer.from(frame));
    },
    now,
    operationTimeoutMs: 100,
  });
  t.after(async () => {
    if (server.listening) {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }
    fs.rmSync(temporary, { force: true, recursive: true });
  });
  await server.initialize();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  return {
    get capabilityProviderCalls() {
      return capabilityProviderCalls;
    },
    executedActions,
    executedParameters,
    get semanticExecutorFactoryCalls() {
      return semanticExecutorFactoryCalls;
    },
    replayEvents,
    responseFrames,
    socketPath,
    stateDir,
    get trustedContextProviderCalls() {
      return trustedContextProviderCalls;
    },
  };
}

function exactPrunePlanTransportOracle({ successRequestId, trusted }) {
  const action = "backup.prune.plan";
  const phaseId = "prune.plan";
  const volumeId = "worker.input.manifest-verification";
  const workerId = "2".repeat(64);
  const workerName = "platform-action-prune-plan-010101010101010101010101";
  const phase = trusted.receipt.resources.phaseProfiles[phaseId];
  const volume = trusted.receipt.resources.volumes[volumeId];
  const expectedBody = expectedPrunePlanWorkerBody({
    requestId: successRequestId,
    trusted,
  });
  const calls = [];
  let cleanupSignal;
  let created = false;
  let firstRequestSignal;
  let inspectVolumeCount = 0;
  let rejectionMethod;
  const rejection = Object.assign(
    new Error("semantic transport fixture rejected prune.plan preflight"),
    {
      errorCode: "ACTION_REJECTED",
      semanticRejection: true,
      statusCode: 403,
    },
  );

  function assertSignal(signal, label) {
    assert.equal(typeof signal?.aborted, "boolean", `${label} must receive an AbortSignal`);
    assert.equal(
      typeof signal?.addEventListener,
      "function",
      `${label} must receive a functional AbortSignal`,
    );
  }

  function assertFirstRequestSignal(signal, label) {
    assertSignal(signal, label);
    assert.equal(signal, firstRequestSignal, `${label} must retain the first request signal`);
  }

  const exactMethods = Object.freeze({
    async inspectVolume(name, signal) {
      assert.equal(arguments.length, 2, "inspectVolume exact argument count");
      assertSignal(signal, "inspectVolume");
      assert.equal(name, volume.engineName, "inspectVolume exact admitted engine name");
      inspectVolumeCount += 1;
      calls.push({ method: "inspectVolume", name, signal });
      if (inspectVolumeCount === 1) {
        firstRequestSignal = signal;
        return buildFixtureVolumeInspect(trusted.receipt, volumeId);
      }
      assert.equal(
        inspectVolumeCount,
        2,
        "the semantic-core fixture must not perform an unplanned volume inspection",
      );
      assert.notEqual(signal, firstRequestSignal, "the second request needs a fresh signal");
      assert.notEqual(signal, cleanupSignal, "a request must not reuse the cleanup signal");
      rejectionMethod = "inspectVolume#2";
      throw rejection;
    },

    async createWorker(name, body, signal) {
      assert.equal(arguments.length, 3, "createWorker exact argument count");
      assertFirstRequestSignal(signal, "createWorker");
      assert.equal(name, workerName, "createWorker exact deterministic worker name");
      assert.deepEqual(body, expectedBody, "createWorker exact independently derived body");
      created = true;
      calls.push({
        body: structuredClone(body),
        method: "createWorker",
        name,
        signal,
      });
      return { Id: workerId };
    },

    async inspectContainer(id, signal) {
      assert.equal(arguments.length, 2, "inspectContainer exact argument count");
      assertFirstRequestSignal(signal, "inspectContainer");
      assert.equal(created, true, "inspectContainer must follow the exact createWorker call");
      assert.equal(id, workerId, "inspectContainer exact worker ID");
      calls.push({ id, method: "inspectContainer", signal });
      return expectedPrunePlanWorkerInspect({
        body: expectedBody,
        id,
        name: workerName,
        trusted,
      });
    },

    async startContainer(id, signal) {
      assert.equal(arguments.length, 2, "startContainer exact argument count");
      assertFirstRequestSignal(signal, "startContainer");
      assert.equal(id, workerId, "startContainer exact worker ID");
      calls.push({ id, method: "startContainer", signal });
    },

    async waitContainer(id, signal) {
      assert.equal(arguments.length, 2, "waitContainer exact argument count");
      assertFirstRequestSignal(signal, "waitContainer");
      assert.equal(id, workerId, "waitContainer exact worker ID");
      calls.push({ id, method: "waitContainer", signal });
      return { StatusCode: 0 };
    },

    async logsContainer(id, signal) {
      assert.equal(arguments.length, 2, "logsContainer exact argument count");
      assertFirstRequestSignal(signal, "logsContainer");
      assert.equal(id, workerId, "logsContainer exact worker ID");
      calls.push({ id, method: "logsContainer", signal });
      return dockerStdoutFrame({
        schema: "platform.docker-worker.result/v2",
        requestId: successRequestId,
        action,
        phaseId,
        command: phase.command,
        job: null,
        status: "completed",
        output: buildFixturePhaseOutputV2(action, phaseId, {}),
      });
    },

    async deleteContainer(id, signal) {
      assert.equal(arguments.length, 2, "deleteContainer exact argument count");
      assertSignal(signal, "deleteContainer");
      assert.equal(id, workerId, "deleteContainer exact worker ID");
      assert.notEqual(signal, firstRequestSignal, "cleanup must use its own bounded signal");
      cleanupSignal = signal;
      calls.push({ id, method: "deleteContainer", signal });
    },
  });

  const transport = new Proxy(exactMethods, {
    get(target, property, receiver) {
      if (
        typeof property === "symbol"
        || property === "execute"
        || property === "then"
      ) {
        return Reflect.get(target, property, receiver);
      }
      if (!Object.hasOwn(target, property)) {
        throw new TypeError(`unexpected semantic transport method ${String(property)}`);
      }
      return Reflect.get(target, property, receiver);
    },
  });

  return Object.freeze({
    assertComplete() {
      assert.deepEqual(
        calls.map(({ method }) => method),
        [
          "inspectVolume",
          "createWorker",
          "inspectContainer",
          "startContainer",
          "waitContainer",
          "logsContainer",
          "deleteContainer",
          "inspectVolume",
        ],
        "the semantic transport fixture must follow the one exact method sequence",
      );
      assert.equal(
        rejectionMethod,
        "inspectVolume#2",
        "the unique semantic rejection must occur at the second exact preflight method",
      );
    },
    calls,
    transport,
  });
}

function expectedPrunePlanPhaseAuthority(receipt) {
  const action = "backup.prune.plan";
  const phaseId = "prune.plan";
  const phase = receipt.resources.phaseProfiles[phaseId];
  const workerSecretSets = Object.fromEntries(
    phase.workerSecretSetIds.map((id) => [
      id,
      structuredClone(receipt.resources.workerSecretSets[id]),
    ]),
  );
  const volumeIds = [
    ...phase.workerSecretSetIds.map(
      (id) => receipt.resources.workerSecretSets[id].volumeId,
    ),
    ...phase.scratchVolumeIds,
  ];
  return {
    schema: "platform.docker-worker.phase-authority/v2",
    action,
    actionProfile: structuredClone(receipt.resources.actionProfiles[action]),
    phaseProfile: structuredClone(phase),
    resources: {
      mounts: Object.fromEntries(
        phase.mountIds.map((id) => [
          id,
          structuredClone(receipt.resources.mounts[id]),
        ]),
      ),
      networks: Object.fromEntries(
        phase.networkIds.map((id) => [
          id,
          structuredClone(receipt.resources.networks[id]),
        ]),
      ),
      volumes: Object.fromEntries(
        [...new Set(volumeIds)].map((id) => [
          id,
          structuredClone(receipt.resources.volumes[id]),
        ]),
      ),
      workerSecretSets,
      writableSubpaths: Object.fromEntries(
        phase.writableSubpathIds.map((id) => [
          id,
          structuredClone(receipt.resources.writableSubpaths[id]),
        ]),
      ),
    },
  };
}

function expectedPrunePlanWorkerBody({ requestId, trusted }) {
  const action = "backup.prune.plan";
  const phaseId = "prune.plan";
  const receipt = trusted.receipt;
  const phase = receipt.resources.phaseProfiles[phaseId];
  const actionProfile = receipt.resources.actionProfiles[action];
  const authority = expectedPrunePlanPhaseAuthority(receipt);
  const verificationSet = receipt.resources.workerSecretSets["manifest.verification"];
  const verificationVolume = receipt.resources.volumes[verificationSet.volumeId];
  const binds = phase.mountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return `${mount.canonicalPath}:${mount.containerPath}:${mount.access}`;
  });
  return {
    Image: phase.workerImageRef,
    Entrypoint: [
      "node",
      "--import",
      "/opt/platform-docker-worker/docker-action-worker-runtime-guard.mjs",
      "/opt/platform-docker-worker/docker-action-worker.mjs",
    ],
    Cmd: [phase.command],
    Env: [
      "HOME=/tmp",
      "LANG=C.UTF-8",
      "NODE_ENV=production",
      `PLATFORM_DOCKER_ACTION=${action}`,
      `PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64=${Buffer.from(canonicalJsonOracle(authority)).toString("base64url")}`,
      `PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256=${sha256Bytes(canonicalJsonOracle(authority))}`,
      `PLATFORM_DOCKER_PHASE_ID=${phaseId}`,
      `PLATFORM_DOCKER_REQUEST_ID=${requestId}`,
    ],
    User: "0:0",
    WorkingDir: "/opt/platform-docker-worker",
    NetworkDisabled: true,
    AttachStdin: false,
    AttachStdout: false,
    AttachStderr: false,
    OpenStdin: false,
    StdinOnce: false,
    Tty: false,
    Labels: {
      "com.platform.active-receipt-sha256": trusted.receiptDigest,
      "com.platform.docker-action": action,
      "com.platform.docker-action-profile": actionProfile.profileId,
      "com.platform.docker-action-profile-sha256": actionProfile.profileSha256,
      "com.platform.docker-phase": phaseId,
      "com.platform.docker-phase-sha256": phase.phaseSha256,
      "com.platform.runtime-intent": trusted.intent.intentId,
    },
    HostConfig: {
      Annotations: null,
      AutoRemove: false,
      Binds: binds,
      BlkioDeviceReadBps: null,
      BlkioDeviceReadIOps: null,
      BlkioDeviceWriteBps: null,
      BlkioDeviceWriteIOps: null,
      BlkioWeight: 0,
      BlkioWeightDevice: null,
      CapAdd: [],
      CapDrop: ["ALL"],
      Cgroup: "",
      CgroupnsMode: "private",
      CgroupParent: "",
      ConsoleSize: [0, 0],
      CpuCount: 0,
      CpuPercent: 0,
      CpuPeriod: 0,
      CpuQuota: 0,
      CpuRealtimePeriod: 0,
      CpuRealtimeRuntime: 0,
      CpuShares: 0,
      CpusetCpus: "",
      CpusetMems: "",
      DeviceCgroupRules: [],
      Devices: [],
      DeviceRequests: [],
      DiskQuota: 0,
      Dns: [],
      DnsOptions: [],
      DnsSearch: [],
      ExtraHosts: [],
      GroupAdd: [],
      IOMaximumBandwidth: 0,
      IOMaximumIOps: 0,
      Init: false,
      IpcMode: "private",
      Isolation: "",
      KernelMemory: 0,
      KernelMemoryTCP: 0,
      Links: [],
      LogConfig: {
        Type: "json-file",
        Config: {
          "max-file": "1",
          "max-size": "1m",
        },
      },
      MaskedPaths: [
        "/proc/acpi",
        "/proc/asound",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/sys/devices/virtual/powercap",
        "/sys/firmware",
      ],
      Memory: 134217728,
      MemoryReservation: 0,
      MemorySwap: 134217728,
      MemorySwappiness: null,
      Mounts: [{
        Type: "volume",
        Source: verificationVolume.engineName,
        Target: verificationSet.containerRoot,
        ReadOnly: true,
        VolumeOptions: { NoCopy: true },
      }],
      NanoCpus: 250000000,
      NetworkMode: "none",
      OomKillDisable: false,
      OomScoreAdj: 0,
      PidMode: "",
      PidsLimit: 96,
      PortBindings: {},
      Privileged: false,
      PublishAllPorts: false,
      ReadonlyPaths: [
        "/proc/asound",
        "/proc/acpi",
        "/proc/interrupts",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/sys/firmware",
      ],
      ReadonlyRootfs: true,
      RestartPolicy: {
        Name: "no",
        MaximumRetryCount: 0,
      },
      Runtime: "runc",
      SecurityOpt: ["no-new-privileges:true"],
      ShmSize: 67108864,
      StorageOpt: {},
      Sysctls: {},
      Tmpfs: {
        "/tmp": "rw,noexec,nosuid,nodev,size=32m,mode=700",
      },
      Ulimits: [{
        Name: "nofile",
        Soft: 1024,
        Hard: 1024,
      }],
      UsernsMode: "",
      UTSMode: "",
      VolumeDriver: "",
      VolumesFrom: [],
    },
    NetworkingConfig: {
      EndpointsConfig: {},
    },
  };
}

function expectedPrunePlanWorkerInspect({ body, id, name, trusted }) {
  const receipt = trusted.receipt;
  const phase = receipt.resources.phaseProfiles["prune.plan"];
  const verificationSet = receipt.resources.workerSecretSets["manifest.verification"];
  const verificationVolume = receipt.resources.volumes[verificationSet.volumeId];
  const bindMounts = phase.mountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return {
      Type: "bind",
      Source: mount.canonicalPath,
      Destination: mount.containerPath,
      Mode: mount.access,
      RW: mount.access !== "ro",
      Propagation: "rprivate",
    };
  });
  return {
    Id: id,
    Name: `/${name}`,
    Image: phase.workerImageId,
    Config: {
      Image: body.Image,
      Entrypoint: body.Entrypoint,
      Cmd: body.Cmd,
      Env: body.Env,
      User: body.User,
      WorkingDir: body.WorkingDir,
      NetworkDisabled: body.NetworkDisabled,
      AttachStdin: false,
      AttachStdout: false,
      AttachStderr: false,
      OpenStdin: false,
      StdinOnce: false,
      Tty: false,
      Labels: body.Labels,
    },
    HostConfig: body.HostConfig,
    Mounts: [
      ...bindMounts,
      {
        Type: "volume",
        Name: verificationVolume.engineName,
        Source: `/var/lib/docker/volumes/${verificationVolume.engineName}/_data`,
        Destination: verificationSet.containerRoot,
        Driver: "local",
        Mode: "",
        RW: false,
        Propagation: "",
      },
    ],
    NetworkSettings: {
      Networks: {},
    },
  };
}

function dockerStdoutFrame(value) {
  const payload = Buffer.from(`${JSON.stringify(value)}\n`);
  const header = Buffer.alloc(8);
  header[0] = 1;
  header.writeUInt32BE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

async function inMemorySemanticExecutorCoreFixture({
  capabilityKey,
  successRequestId,
  trusted,
}) {
  const responseFrames = [];
  const fixtureReplayEvents = [];
  let capabilityProviderCalls = 0;
  let fixtureRecoveredExecutor = false;
  let fixtureSemanticExecutorCreations = 0;
  let trustedContextProviderCalls = 0;
  const transportOracle = exactPrunePlanTransportOracle({
    successRequestId,
    trusted,
  });
  const replayStore = {
    async recover(executor) {
      fixtureReplayEvents.push("recover");
      assert.equal(typeof executor?.execute, "function");
      assert.equal(typeof executor?.executePhase, "function");
      assert.equal(typeof executor?.recoverLease, "function");
      fixtureRecoveredExecutor = true;
      return { status: "clean" };
    },
    admitActivation() {
      fixtureReplayEvents.push("activation");
    },
    admitTrustedContext() {
      fixtureReplayEvents.push("trusted");
    },
    consume() {
      fixtureReplayEvents.push("consume");
    },
    acquire(request, admittedTrusted) {
      fixtureReplayEvents.push("acquire");
      return Object.freeze({
        lineage: Object.freeze({
          action: request.action,
          intentId: admittedTrusted.intent.intentId,
          receiptDigest: admittedTrusted.receiptDigest,
          request: structuredClone(request),
          requestId: request.requestId,
          requestSha256: sha256Bytes(canonicalJsonOracle(request)),
        }),
        preserve() {
          fixtureReplayEvents.push("preserve");
        },
        recordEvent(event) {
          fixtureReplayEvents.push(`event:${String(event?.event ?? event?.type ?? "unknown")}`);
        },
        recordWorker() {},
        release() {
          fixtureReplayEvents.push("release");
        },
      });
    },
  };
  const semanticExecutorOptions = Object.freeze({
    async claimedJobSnapshotProvider() {
      throw new Error("the prune-plan semantic-core fixture may not claim a queued job");
    },
    cleanupTimeoutMs: 100,
    randomBytes: () => Buffer.alloc(12, 1),
    snapshotFileStore: Object.freeze({
      cleanup() {
        throw new Error("the prune-plan semantic-core fixture may not clean a claimed-job snapshot");
      },
      async seal() {
        throw new Error("the prune-plan semantic-core fixture may not seal a claimed-job snapshot");
      },
    }),
    transport: transportOracle.transport,
  });
  fixtureSemanticExecutorCreations += 1;
  const semanticExecutor = broker.createSemanticActionExecutor(
    semanticExecutorOptions,
  );
  await replayStore.recover(semanticExecutor);
  const core = broker.createBrokerCore({
    trustedContextProvider: async () => {
      trustedContextProviderCalls += 1;
      return trusted;
    },
    capabilityProvider: async () => {
      capabilityProviderCalls += 1;
      return capabilityKey;
    },
    engine: semanticExecutor,
    replayStore,
    now: () => NOW,
    operationTimeoutMs: 100,
  });
  return {
    assertTransportComplete: transportOracle.assertComplete,
    get capabilityProviderCalls() {
      return capabilityProviderCalls;
    },
    core,
    async exchange(request) {
      const exchange = await inMemoryCoreConnection(core, request);
      responseFrames.push(Buffer.from(exchange.frame));
      return exchange;
    },
    get fixtureRecoveredExecutor() {
      return fixtureRecoveredExecutor;
    },
    fixtureReplayEvents,
    responseFrames,
    get fixtureSemanticExecutorCreations() {
      return fixtureSemanticExecutorCreations;
    },
    transport: transportOracle.transport,
    get trustedContextProviderCalls() {
      return trustedContextProviderCalls;
    },
  };
}

function clientMainFsRedirectFixture(t, {
  capabilityKey,
  capabilityPath,
}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-client-main-fs-"));
  fs.chmodSync(directory, 0o700);
  const auditFile = path.join(directory, "audit.jsonl");
  const capabilityFile = path.join(directory, "capability");
  const preloadFile = path.join(directory, "root-owned-fs-preload.cjs");
  fs.writeFileSync(auditFile, "", { mode: 0o600 });
  fs.writeFileSync(capabilityFile, capabilityKey, { mode: 0o400 });
  fs.chmodSync(capabilityFile, 0o400);
  fs.writeFileSync(
    preloadFile,
    [
      '"use strict";',
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const { syncBuiltinESMExports } = require("node:module");',
      "const original = {",
      "  appendFileSync: fs.appendFileSync.bind(fs),",
      "  closeSync: fs.closeSync.bind(fs),",
      "  fstatSync: fs.fstatSync.bind(fs),",
      "  lstatSync: fs.lstatSync.bind(fs),",
      "  openSync: fs.openSync.bind(fs),",
      "  readFileSync: fs.readFileSync.bind(fs),",
      "  readSync: fs.readSync.bind(fs),",
      "  realpathSync: fs.realpathSync.bind(fs),",
      "  statSync: fs.statSync.bind(fs),",
      "};",
      "const auditFile = process.env.DOCKER_ACTION_TEST_AUDIT_FILE;",
      "const capabilityFile = path.resolve(process.env.DOCKER_ACTION_TEST_CAPABILITY_FILE);",
      "const capabilityPath = path.resolve(process.env.DOCKER_ACTION_TEST_CAPABILITY_PATH);",
      "const claimedFile = path.resolve(process.env.DOCKER_ACTION_TEST_CLAIMED_FILE);",
      "const claimedRoot = path.resolve(process.env.DOCKER_ACTION_TEST_CLAIMED_ROOT);",
      "const runId = process.env.DOCKER_ACTION_TEST_RUN_ID;",
      "const fixedNow = Number(process.env.DOCKER_ACTION_TEST_NOW);",
      'if (!Number.isSafeInteger(fixedNow)) throw new Error("test-only fixed Date.now value is invalid");',
      "Date.now = () => fixedNow;",
      "const descriptors = new Map();",
      "const capabilityParents = new Set();",
      "for (let current = path.dirname(capabilityPath); current !== path.parse(current).root; current = path.dirname(current)) {",
      "  capabilityParents.add(current);",
      "}",
      "function resolved(value) {",
      '  return typeof value === "string" ? path.resolve(value) : null;',
      "}",
      "function inside(candidate, root) {",
      "  return candidate === root || candidate.startsWith(`${root}${path.sep}`);",
      "}",
      "function rootOwned(stat) {",
      "  return new Proxy(stat, {",
      "    get(target, property) {",
      '      if (property === "uid" || property === "gid") return 0;',
      "      const value = Reflect.get(target, property, target);",
      '      return typeof value === "function" ? value.bind(target) : value;',
      "    },",
      "  });",
      "}",
      "function audit(event) {",
      "  original.appendFileSync(auditFile, `${JSON.stringify({ ...event, runId })}\\n`);",
      "}",
      "const observedProcess = {",
      '  argv: [...process.argv],',
      '  event: "process",',
      "  execPath: process.execPath,",
      "  now: Date.now(),",
      "};",
      "audit(observedProcess);",
      'if (process.env.DOCKER_ACTION_TEST_REQUIRE_REAL_MAIN === "1") {',
      "  const expectedEntrypoint = process.env.DOCKER_ACTION_TEST_EXPECTED_ENTRYPOINT;",
      "  const expectedArgs = JSON.parse(process.env.DOCKER_ACTION_TEST_EXPECTED_ARGS_JSON);",
      "  if (process.argv[1] !== expectedEntrypoint",
      "      || JSON.stringify(process.argv.slice(2)) !== JSON.stringify(expectedArgs)) {",
      '    throw new Error("test-only real client entrypoint or arguments mismatch");',
      "  }",
      "}",
      "function protectedKind(candidate) {",
      '  if (candidate === capabilityPath) return "capability";',
      '  if (candidate === claimedFile) return "claimed-job";',
      "  return null;",
      "}",
      "fs.lstatSync = function testLstat(file, options) {",
      "  const candidate = resolved(file);",
      "  if (candidate === capabilityPath) return rootOwned(original.lstatSync(capabilityFile, options));",
      "  if (capabilityParents.has(candidate)) return rootOwned(original.lstatSync(path.parse(candidate).root, options));",
      "  if (candidate && inside(candidate, claimedRoot)) return rootOwned(original.lstatSync(file, options));",
      "  return original.lstatSync(file, options);",
      "};",
      "fs.statSync = function testStat(file, options) {",
      "  const candidate = resolved(file);",
      "  if (candidate === capabilityPath) return rootOwned(original.statSync(capabilityFile, options));",
      "  if (capabilityParents.has(candidate)) return rootOwned(original.statSync(path.parse(candidate).root, options));",
      "  if (candidate && inside(candidate, claimedRoot)) return rootOwned(original.statSync(file, options));",
      "  return original.statSync(file, options);",
      "};",
      "fs.realpathSync = function testRealpath(file, options) {",
      "  const candidate = resolved(file);",
      "  if (candidate === capabilityPath || capabilityParents.has(candidate)) return candidate;",
      "  return original.realpathSync(file, options);",
      "};",
      "fs.openSync = function testOpen(file, flags, mode) {",
      "  const candidate = resolved(file);",
      "  const kind = protectedKind(candidate);",
      "  const selected = candidate === capabilityPath ? capabilityFile : file;",
      "  const descriptor = original.openSync(selected, flags, mode);",
      "  if (kind) {",
      "    descriptors.set(descriptor, kind);",
      '    audit({ descriptor, event: "open", flags, kind, path: candidate });',
      "  }",
      "  return descriptor;",
      "};",
      "fs.fstatSync = function testFstat(descriptor, options) {",
      "  const stat = original.fstatSync(descriptor, options);",
      "  const kind = descriptors.get(descriptor);",
      "  if (!kind) return stat;",
      '  audit({ descriptor, event: "fstat", kind });',
      "  return rootOwned(stat);",
      "};",
      "fs.readSync = function testRead(...args) {",
      "  const bytesRead = original.readSync(...args);",
      "  const kind = descriptors.get(args[0]);",
      "  if (kind) {",
      '    const options = args[2] && typeof args[2] === "object" ? args[2] : null;',
      "    const position = options ? options.position : args[4];",
      "    const requested = options ? options.length : args[3];",
      '    audit({ bytesRead, descriptor: args[0], event: "read", kind, position, requested });',
      "  }",
      "  return bytesRead;",
      "};",
      "fs.readFileSync = function testReadFile(file, options) {",
      '  const descriptorKind = typeof file === "number" ? descriptors.get(file) : null;',
      "  const candidate = resolved(file);",
      "  const kind = descriptorKind || protectedKind(candidate);",
      '  if (kind) audit({ descriptor: typeof file === "number" ? file : null, event: "readFile", kind, path: candidate });',
      "  return original.readFileSync(candidate === capabilityPath ? capabilityFile : file, options);",
      "};",
      "fs.closeSync = function testClose(descriptor) {",
      "  const kind = descriptors.get(descriptor);",
      "  if (kind) {",
      '    audit({ descriptor, event: "close", kind });',
      "    descriptors.delete(descriptor);",
      "  }",
      "  return original.closeSync(descriptor);",
      "};",
      "syncBuiltinESMExports();",
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  fs.chmodSync(preloadFile, 0o600);
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return {
    auditFile,
    capabilityFile,
    capabilityPath,
    preloadFile,
    readAudit() {
      const value = fs.readFileSync(auditFile, "utf8");
      return value
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    },
  };
}

function assertProtectedMainReads(events, {
  capabilityBytes,
  capabilityRuns,
  claimedJobBytes,
  claimedJobRuns,
}) {
  for (const [kind, runs, expectedBytes] of [
    ["capability", capabilityRuns, capabilityBytes],
    ["claimed-job", claimedJobRuns, claimedJobBytes],
  ]) {
    for (const runId of runs) {
      const selected = events.filter((event) => event.kind === kind && event.runId === runId);
      const opens = selected.filter(({ event }) => event === "open");
      assert.equal(opens.length, 1, `${runId} must open ${kind} exactly once`);
      assert.equal(
        (opens[0].flags & fs.constants.O_NOFOLLOW) === fs.constants.O_NOFOLLOW,
        true,
        `${runId} must open ${kind} with O_NOFOLLOW`,
      );
      assert.equal(
        selected.some(({ event }) => event === "readFile"),
        false,
        `${runId} must not shortcut ${kind} through readFileSync`,
      );
      const reads = selected.filter(({ event }) => event === "read");
      assertTwoCompleteDescriptorReads(reads, expectedBytes, `${runId} ${kind}`);
      assert.ok(
        selected.filter(({ event }) => event === "fstat").length >= 2,
        `${runId} must bind ${kind} bytes to stable descriptor metadata`,
      );
      assert.equal(
        selected.filter(({ event }) => event === "close").length,
        1,
        `${runId} must close the one protected ${kind} descriptor`,
      );
    }
  }
}

function assertTwoCompleteDescriptorReads(reads, expectedBytes, label) {
  let pass = -1;
  let cursor = 0;
  for (const read of reads) {
    if (read.position === 0) {
      if (pass >= 0) {
        assert.equal(cursor, expectedBytes, `${label} descriptor pass was incomplete`);
      }
      pass += 1;
      cursor = 0;
    }
    assert.equal(
      read.position,
      cursor,
      `${label} descriptor reads must be explicit and contiguous`,
    );
    assert.ok(read.bytesRead > 0, `${label} descriptor read made no progress`);
    cursor += read.bytesRead;
    assert.ok(cursor <= expectedBytes, `${label} descriptor read exceeded the protected file`);
  }
  assert.equal(pass, 1, `${label} must have exactly two descriptor passes`);
  assert.equal(cursor, expectedBytes, `${label} final descriptor pass was incomplete`);
}

function assertRealClientMainInvocation(events, { fileName, runId }) {
  const selected = events.filter((event) => event.event === "process" && event.runId === runId);
  assert.equal(selected.length, 1, `${runId} must audit exactly one child process`);
  const [observed] = selected;
  const expectedEntrypoint = path.join(
    REPOSITORY_ROOT,
    "scripts",
    "docker-action-client.mjs",
  );
  assert.equal(
    observed.argv[1],
    expectedEntrypoint,
    `${runId} must execute the exact real client entrypoint`,
  );
  assert.equal(
    observed.execPath,
    process.execPath,
    `${runId} must execute the expected Node command`,
  );
  assert.deepEqual(
    observed.argv.slice(2),
    ["execute-backup-job", "--jobFileName", fileName],
    `${runId} must preserve the exact scheduler command and arguments`,
  );
  assert.equal(observed.now, NOW, `${runId} must share the one frozen clock`);
}

async function invokeSchedulerRealMain(
  fixture,
  socketPath,
  redirect,
  trustedEnvironment,
  runId,
) {
  const expectedEntrypoint = path.join(
    REPOSITORY_ROOT,
    "scripts",
    "docker-action-client.mjs",
  );
  const expectedArgs = ["execute-backup-job", "--jobFileName", fixture.fileName];
  const env = {
    BACKUP_SCHEDULER_JOBS_DIR: fixture.directory,
    DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: trustedEnvironment.activeReceiptSha256,
    DOCKER_ACTION_BROKER_SOCKET: socketPath,
    DOCKER_ACTION_COMBINED_RENDER_SHA256: trustedEnvironment.combinedRenderSha256,
    DOCKER_ACTION_RUNTIME_INTENT_ID: trustedEnvironment.runtimeIntentId,
    DOCKER_ACTION_TEST_AUDIT_FILE: redirect.auditFile,
    DOCKER_ACTION_TEST_CAPABILITY_FILE: redirect.capabilityFile,
    DOCKER_ACTION_TEST_CAPABILITY_PATH: redirect.capabilityPath,
    DOCKER_ACTION_TEST_CLAIMED_FILE: fixture.file,
    DOCKER_ACTION_TEST_CLAIMED_ROOT: fixture.directory,
    DOCKER_ACTION_TEST_EXPECTED_ARGS_JSON: JSON.stringify(expectedArgs),
    DOCKER_ACTION_TEST_EXPECTED_ENTRYPOINT: expectedEntrypoint,
    DOCKER_ACTION_TEST_NOW: String(NOW),
    DOCKER_ACTION_TEST_REQUIRE_REAL_MAIN: "1",
    DOCKER_ACTION_TEST_RUN_ID: runId,
    NODE_OPTIONS: `--require=${redirect.preloadFile}`,
    PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ""}`,
    PLATFORM_INFRA_ROOT: REPOSITORY_ROOT,
  };
  const result = await collectChildProcess(
    "/bin/sh",
    [
      path.join(REPOSITORY_ROOT, "scripts", "backup-scheduler.sh"),
      "--run",
      "execute-backup-job",
      "--jobFileName",
      fixture.fileName,
    ],
    {
      cwd: REPOSITORY_ROOT,
      env,
    },
  );
  assertRealClientMainInvocation(redirect.readAudit(), {
    fileName: fixture.fileName,
    runId,
  });
  return result;
}

function assertSingleJsonLine(value, label) {
  assert.equal(value.endsWith("\n"), true, `${label} must end in exactly one LF`);
  assert.equal(value.slice(0, -1).includes("\n"), false, `${label} must contain exactly one frame`);
  assert.doesNotThrow(() => JSON.parse(value.slice(0, -1)), `${label} must be one JSON document`);
}

function collectChildProcess(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...options,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout) > 1024 * 1024) child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (Buffer.byteLength(stderr) > 1024 * 1024) child.kill("SIGKILL");
    });
    child.once("error", reject);
    child.once("close", (code, signal) => {
      resolve({ code, signal, stderr, stdout });
    });
  });
}

async function invokeWithLocalBroker(
  invokeClient,
  responseForRequest,
  {
    encodeResponse = JSON.stringify,
    responseFrame,
  } = {},
) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-client-uds-"));
  fs.chmodSync(directory, 0o700);
  const socketPath = path.join(directory, "broker.sock");
  let receivedFrame;
  let receivedWire;
  let serverFailure;
  const server = net.createServer((connection) => {
    let bytes = "";
    connection.setEncoding("utf8");
    connection.on("data", (chunk) => {
      bytes += chunk;
    });
    connection.on("end", () => {
      try {
        assert.equal(bytes.endsWith("\n"), true, "the client request must end in one frame delimiter");
        const frames = bytes.slice(0, -1).split("\n");
        assert.equal(frames.length, 1, "the client must emit exactly one request frame");
        [receivedWire] = frames;
        receivedFrame = JSON.parse(frames[0]);
        const response = responseForRequest(receivedFrame);
        connection.end(
          responseFrame
            ? responseFrame(response)
            : `${encodeResponse(response)}\n`,
        );
      } catch (error) {
        serverFailure = error;
        connection.destroy(error);
      }
    });
    connection.on("error", (error) => {
      serverFailure ??= error;
    });
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });

  let value;
  let clientFailure;
  try {
    value = await invokeClient(socketPath);
  } catch (error) {
    clientFailure = error;
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(directory, { force: true, recursive: true });
  }

  if (serverFailure) throw serverFailure;
  if (clientFailure) throw clientFailure;
  assert.ok(receivedFrame, "the local UDS broker must observe exactly one request");
  return { request: receivedFrame, requestWire: receivedWire, value };
}
