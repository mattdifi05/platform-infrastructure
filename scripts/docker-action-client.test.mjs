import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
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
  buildFixtureTrustedContextV2,
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
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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

testWhenProductionExports(
  [
    [actionContract, "normalizeActionResponse"],
    [actionContract, "signActionResponse"],
    [broker, "encodeActionResponseFrame"],
  ],
  "RED v2: production broker encoder round-trips real core success and signed rejection through the real client",
  async () => {
    const action = "backup.prune.plan";
    const command = "prune-manifest-backups-plan";
    const capabilityKey = fixtureCapabilityKey(action);
    const { trusted } = buildFixtureTrustedContextV2({
      allowedActions: [action],
      now: NOW,
    });
    const request = buildClientRequest(command, [], {
      runtimeIntentId: trusted.intent.intentId,
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      capabilityKey,
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174100",
      nonce: "B".repeat(43),
    });
    const result = buildFixtureActionResultV2(action);
    const replayStore = {
      acquire() {
        return { preserve() {}, recordWorker() {}, release() {} };
      },
      admitActivation() {},
      admitTrustedContext() {},
      consume() {},
    };
    const core = broker.createBrokerCore({
      trustedContextProvider: async () => trusted,
      capabilityProvider: async () => capabilityKey,
      engine: { execute: async () => result },
      replayStore,
      now: () => NOW,
      operationTimeoutMs: 100,
    });
    const wire = await core.handle(Buffer.from(canonicalJsonOracle(request)));
    assert.equal(wire.statusCode, 200);
    const encodedSuccess = broker.encodeActionResponseFrame(wire.body);
    assertProductionResponseFrame(encodedSuccess, wire.body);
    const completed = await exchangeWithLocalBroker(request, wire.body, {
      capabilityKey,
      responseFrame: () => encodedSuccess,
    });
    assert.deepEqual(completed, wire.body);

    const rejectedUnsigned = {
      schema: RESPONSE_SCHEMA_V2,
      status: "rejected",
      statusCode: 403,
      errorCode: "ACTION_REJECTED",
      action: request.action,
      requestId: request.requestId,
      requestSha256: sha256Bytes(canonicalJsonOracle(request)),
      result: null,
      resultSha256: sha256Bytes(canonicalJsonOracle(null)),
    };
    const rejected = actionContract.signActionResponse(rejectedUnsigned, capabilityKey);
    const encodedRejection = broker.encodeActionResponseFrame(rejected);
    assertProductionResponseFrame(encodedRejection, rejected);
    const admittedRejection = await exchangeWithLocalBroker(request, rejected, {
      capabilityKey,
      responseFrame: () => encodedRejection,
    });
    assert.deepEqual(
      admittedRejection,
      rejected,
      "the production encoder and real client must preserve an authenticated semantic rejection",
    );
  },
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
  [
    [client, "readClaimedBackupJob"],
    [client, "runClientCommand"],
    [actionContract, "normalizeActionResponse"],
    [broker, "encodeActionResponseFrame"],
  ],
  "RED v2: scheduler filename reaches the real client module and real UDS response consumer",
  async (t) => {
    const fixture = claimedJobFixture(t);
    const expected = await assertValidClaimedJobControl(
      requireClaimedJobReader(),
      fixture,
    );
    const exchange = await invokeWithLocalBroker(
      (socketPath) => invokeSchedulerThroughRealClient(t, fixture, socketPath),
      (request) => {
        assert.equal(request.action, "backup.job.execute");
        assert.deepEqual(
          request.parameters,
          expected,
          "the scheduler-to-client bridge must preserve only the claimed filename-derived metadata",
        );
        return signedResponse(request, {
          status: "completed",
          statusCode: 200,
          errorCode: null,
          result: canonicalActionResultV2(request),
        });
      },
      {
        responseFrame(response) {
          return broker.encodeActionResponseFrame(response);
        },
      },
    );
    assert.equal(exchange.requestWire, canonicalJsonOracle(exchange.request));
    assert.deepEqual(
      exchange.value,
      signedResponse(exchange.request, {
        status: "completed",
        statusCode: 200,
        errorCode: null,
        result: canonicalActionResultV2(exchange.request),
      }),
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

function testWhenClientExports(exportNames, name, body) {
  const missing = exportNames.filter((exportName) => typeof client[exportName] !== "function");
  if (missing.length > 0) {
    return test.todo(`${name} [activates when ${missing.join(", ")} is exported]`);
  }
  return test(name, body);
}

function testWhenProductionExports(requirements, name, body) {
  const missing = requirements
    .filter(([module, exportName]) => typeof module[exportName] !== "function")
    .map(([, exportName]) => exportName);
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

function canonicalJsonOracle(value) {
  return JSON.stringify(canonicalValueOracle(value));
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
  return crypto
    .createHmac("sha256", CAPABILITY)
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

async function invokeSchedulerThroughRealClient(t, fixture, socketPath) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-scheduler-client-"));
  const bin = path.join(temporary, "bin");
  const bridge = path.join(temporary, "real-client-bridge.mjs");
  const nodeShim = path.join(bin, "node");
  fs.mkdirSync(bin, { mode: 0o700 });
  fs.writeFileSync(
    bridge,
    [
      'import { pathToFileURL } from "node:url";',
      "const [clientPath, command, ...args] = process.argv.slice(2);",
      "const client = await import(pathToFileURL(clientPath).href);",
      'if (typeof client.runClientCommand !== "function") throw new Error("real client command seam is unavailable");',
      'const options = JSON.parse(Buffer.from(process.env.SCHEDULER_CLIENT_OPTIONS_B64, "base64url").toString("utf8"));',
      'options.capabilityKey = Buffer.from(process.env.SCHEDULER_CLIENT_CAPABILITY_B64, "base64url");',
      "const response = await client.runClientCommand(command, args, options);",
      'process.stdout.write(`${JSON.stringify(response)}\\n`);',
      'if (response.statusCode !== 200 || response.status !== "completed") process.exitCode = 77;',
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  fs.writeFileSync(
    nodeShim,
    [
      "#!/bin/sh",
      'exec "$SCHEDULER_REAL_NODE" "$SCHEDULER_REAL_CLIENT_BRIDGE" "$@"',
      "",
    ].join("\n"),
    { mode: 0o700 },
  );
  t.after(() => fs.rmSync(temporary, { force: true, recursive: true }));

  const options = {
    ...clientOptions(),
    claimedJobPolicy: claimedJobPolicy(fixture),
    socketPath,
  };
  const outcome = await collectChildProcess(
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
      env: {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ""}`,
        PLATFORM_INFRA_ROOT: REPOSITORY_ROOT,
        SCHEDULER_CLIENT_CAPABILITY_B64: CAPABILITY.toString("base64url"),
        SCHEDULER_CLIENT_OPTIONS_B64: Buffer.from(JSON.stringify(options)).toString("base64url"),
        SCHEDULER_REAL_CLIENT_BRIDGE: bridge,
        SCHEDULER_REAL_NODE: process.execPath,
      },
    },
  );
  assert.equal(outcome.code, 0, `${outcome.stdout}\n${outcome.stderr}`);
  const lines = outcome.stdout.trim().split("\n").filter(Boolean);
  assert.equal(lines.length, 1, "the scheduler/client bridge must emit exactly one authenticated response");
  return JSON.parse(lines[0]);
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
