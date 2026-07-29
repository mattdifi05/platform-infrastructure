import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BACKUP_JOB_SCHEMA,
  createBackupJobDocument,
  parseBackupJobDocument,
} from "../control-center/backup/contracts.mjs";
import * as client from "./docker-action-client.mjs";

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

test("client signs only the fixed action schema and rejects raw argument injection", () => {
  const request = buildClientRequest("prune-manifest-backups-plan", [], {
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityKey: CAPABILITY,
    now: Date.parse("2026-07-26T12:00:00.000Z"),
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
  });
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

test("RED v2: real UDS consumer accepts canonical success and authenticated rejection responses", async (t) => {
  const request = buildClientRequest("runtime-docker-snapshot", [], clientOptions());
  assert.equal(request.schema, REQUEST_SCHEMA_V2, "positive UDS control must be a real request/v2");
  assert.equal(
    request.mac,
    requestMac(omit(request, "mac")),
    "positive UDS control must carry the domain-separated request/v2 MAC",
  );
  const success = signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result: { containers: [] },
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

test("RED v2: real UDS consumer rejects the complete authenticated response mutation matrix", async (t) => {
  const request = buildClientRequest("runtime-docker-snapshot", [], clientOptions());
  const result = { containers: [] };
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
      resignResponse({ ...unsigned, result: { containers: ["substituted"] } }),
      /response result.*(?:digest|sha)/i,
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
      "non-canonical wire",
      Object.fromEntries(Object.entries(valid).reverse()),
      /response.*(?:canonical|wire)/i,
      JSON.stringify,
    ],
  ];

  for (const [label, candidate, expectedError, encodeResponse = canonicalJsonOracle] of mutations) {
    await t.test(label, async () => {
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

test("capability reader requires stable private ownership, parents and one link", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-capability-"));
  const uid = process.getuid();
  const gid = process.getgid();
  fs.chmodSync(directory, 0o700);
  const capability = path.join(directory, "capability");
  fs.writeFileSync(capability, CAPABILITY, { mode: 0o400 });
  assert.deepEqual(
    protectedCapability(capability, { expectedUid: uid, expectedGid: gid, parentRoot: directory }),
    CAPABILITY,
  );

  fs.chmodSync(capability, 0o440);
  assert.throws(
    () => protectedCapability(capability, { expectedUid: uid, expectedGid: gid, parentRoot: directory }),
    /ownership, links, permissions or size/,
  );
  fs.chmodSync(capability, 0o400);
  fs.linkSync(capability, path.join(directory, "second-link"));
  assert.throws(
    () => protectedCapability(capability, { expectedUid: uid, expectedGid: gid, parentRoot: directory }),
    /ownership, links, permissions or size/,
  );
  fs.rmSync(directory, { force: true, recursive: true });
});

test("RED v2: real CLI command carries one claimed file through signed request and local UDS response", async (t) => {
  const fixture = claimedJobFixture(t, {
    id: "0123456789abcdef",
    operation: "backup",
  });
  const readClaimedBackupJob = requireClaimedJobReader();
  const runClientCommand = requireClientCommandRunner();
  const policy = claimedJobPolicy(fixture);
  const parameters = await readClaimedBackupJob(fixture.fileName, policy);
  const expected = {
    jobFileName: fixture.fileName,
    jobId: fixture.document.id,
    jobOperation: fixture.document.operation,
    jobSha256: sha256Bytes(fixture.bytes),
  };

  assert.deepEqual(Object.keys(parameters).sort(), [
    "jobFileName",
    "jobId",
    "jobOperation",
    "jobSha256",
  ]);
  assert.deepEqual(parameters, expected);

  const result = {
    accepted: true,
    jobId: fixture.document.id,
  };
  const exchange = await invokeWithLocalBroker(
    (socketPath) => runClientCommand(
      "execute-backup-job",
      ["--jobFileName", fixture.fileName],
      {
        ...clientOptions(),
        claimedJobPolicy: policy,
        socketPath,
      },
    ),
    (request) => signedResponse(request, {
      status: "completed",
      statusCode: 200,
      errorCode: null,
      result,
    }),
    { encodeResponse: canonicalJsonOracle },
  );
  const request = exchange.request;
  const unsigned = omit(request, "mac");
  const expectedMac = crypto
    .createHmac("sha256", CAPABILITY)
    .update(REQUEST_MAC_DOMAIN)
    .update(canonicalJsonOracle(unsigned))
    .digest("hex");

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
  assert.deepEqual(request.parameters, expected);
  assert.equal(request.mac, expectedMac);
  assert.deepEqual(exchange.value, signedResponse(request, {
    status: "completed",
    statusCode: 200,
    errorCode: null,
    result,
  }));
});

test("RED v2: claimed reader preserves real IDs, operation and raw-file digest without normalization", async (t) => {
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
});

test("RED v2: claimed reader admits only a bounded valid running backup-contract document", async (t) => {
  const invalid = [
    {
      label: "malformed JSON",
      rawBytes: Buffer.from("{"),
      expected: /claimed job.*(?:json|malformed|parse)/i,
    },
    {
      label: "oversized document",
      rawBytes: Buffer.alloc(5 * 1024 * 1024, 0x61),
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
      const fixture = claimedJobFixture(st, {
        operation: scenario.operation ?? "backup",
        mutateDocument: scenario.mutate,
        rawBytes: scenario.rawBytes,
      });
      const readClaimedBackupJob = requireClaimedJobReader();
      await assert.rejects(
        async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
        scenario.expected,
      );
    });
  }
});

test("RED v2: claimed reader enforces trusted root, basename and exact protected-file stat", async (t) => {
  await t.test("parent traversal is rejected as a basename violation", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assert.rejects(
      async () => readClaimedBackupJob(`../${fixture.fileName}`, claimedJobPolicy(fixture)),
      /claimed job (?:basename|filename)/i,
    );
  });

  await t.test("basename must equal the byte-exact job ID plus .json", async (st) => {
    const fixture = claimedJobFixture(st, {
      id: "0123456789abcdef",
      fileName: "job-0123456789abcdef.json",
    });
    const readClaimedBackupJob = requireClaimedJobReader();
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job (?:basename|filename).*(?:id|identity)|job id.*(?:basename|filename)/i,
    );
  });

  await t.test("a second hardlink is rejected", async (st) => {
    const fixture = claimedJobFixture(st);
    fs.linkSync(fixture.file, path.join(fixture.root, "second-link.json"));
    const readClaimedBackupJob = requireClaimedJobReader();
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:link|stat|metadata)/i,
    );
  });

  await t.test("mode must be exactly private 0600", async (st) => {
    const fixture = claimedJobFixture(st);
    fs.chmodSync(fixture.file, 0o640);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:mode|permission|stat|metadata)/i,
    );
  });

  await t.test("owner is checked without coercion", async (st) => {
    const fixture = claimedJobFixture(st);
    const readClaimedBackupJob = requireClaimedJobReader();
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
    const outside = path.join(fixture.directory, "outside.json");
    fs.renameSync(fixture.file, outside);
    fs.symlinkSync(outside, fixture.file);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:symlink|nofollow|regular|stat|metadata)/i,
    );
  });

  await t.test("trusted root itself cannot be a symlink", async (st) => {
    const fixture = claimedJobFixture(st);
    const linkedRoot = path.join(fixture.directory, "linked-running");
    fs.symlinkSync(fixture.root, linkedRoot);
    const readClaimedBackupJob = requireClaimedJobReader();
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
    fs.chmodSync(fixture.root, 0o770);
    const readClaimedBackupJob = requireClaimedJobReader();
    await assert.rejects(
      async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
      /claimed job.*(?:root|parent|permission)/i,
    );
  });
});

test("RED v2: injected filesystem proves descriptor-only O_NOFOLLOW admission", async (t) => {
  const fixture = claimedJobFixture(t);
  const readClaimedBackupJob = requireClaimedJobReader();
  const observed = observedFilesystem(fixture);
  await readClaimedBackupJob(fixture.fileName, {
    ...claimedJobPolicy(fixture),
    fileSystem: observed.fileSystem,
  });
  assert.equal(observed.state.protectedOpenCount > 0, true, "the injected filesystem must observe a protected open");
  assert.equal(observed.state.allProtectedOpensNoFollow, true, "every claimed-file open must carry O_NOFOLLOW");
  assert.equal(observed.state.pathReadAttempts, 0, "claimed bytes must never be read by pathname");
  assert.equal(observed.state.descriptorBytesRead >= fixture.bytes.length, true, "claimed bytes must come from a descriptor");
});

test("RED v2: injected filesystem exposes a same-size race between stable descriptor reads", async (t) => {
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
  const observed = observedFilesystem(fixture, {
    afterFirstCompleteRead() {
      fs.writeFileSync(fixture.file, replacement, { mode: 0o600 });
    },
  });
  await assert.rejects(
    async () => readClaimedBackupJob(fixture.fileName, {
      ...claimedJobPolicy(fixture),
      fileSystem: observed.fileSystem,
    }),
    /claimed job.*(?:changed|stable|race|read)/i,
  );
  assert.equal(observed.state.firstCompleteReadObserved, true, "the harness must race after one complete descriptor read");
  assert.equal(observed.state.pathReadAttempts, 0, "a pathname pre-read cannot satisfy stable descriptor admission");
});

test("RED v2: claimed document types and CLI surface admit zero coercion or metadata aliases", async (t) => {
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
  ];
  for (const scenario of invalidDocuments) {
    await t.test(scenario.label, async (st) => {
      const fixture = claimedJobFixture(st, {
        fileName: scenario.fileName,
        mutateDocument: scenario.mutate,
      });
      const readClaimedBackupJob = requireClaimedJobReader();
      await assert.rejects(
        async () => readClaimedBackupJob(fixture.fileName, claimedJobPolicy(fixture)),
        scenario.expected,
      );
    });
  }

  await t.test("only --jobFileName basename is accepted by the CLI adapter", async (st) => {
    const fixture = claimedJobFixture(st);
    const runClientCommand = requireClientCommandRunner();
    const options = {
      ...clientOptions(),
      claimedJobPolicy: claimedJobPolicy(fixture),
      socketPath: path.join(fixture.directory, "must-not-connect.sock"),
    };
    const directMetadata = [
      "--jobFileName",
      fixture.fileName,
      "--jobId",
      fixture.document.id,
      "--jobOperation",
      fixture.document.operation,
      "--jobSha256",
      sha256Bytes(fixture.bytes),
    ];
    await assert.rejects(
      async () => runClientCommand("execute-backup-job", directMetadata, options),
      /execute-backup-job.*only --jobFileName|requires --jobFileName <basename>/i,
    );
    await assert.rejects(
      async () => runClientCommand("execute-backup-job", ["--jobFile", fixture.fileName], options),
      /execute-backup-job.*--jobFileName/i,
    );
    await assert.rejects(
      async () => runClientCommand("execute-backup-job", ["--jobFileName", fixture.file], options),
      /claimed job (?:basename|filename)/i,
    );
    await assert.rejects(
      async () => runClientCommand("execute-backup-job", ["--jobFileName", new String(fixture.fileName)], options),
      /claimed job (?:basename|filename).*string/i,
    );
  });
});

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
} = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-claimed-job-"));
  const root = path.join(directory, "running");
  fs.chmodSync(directory, 0o700);
  fs.mkdirSync(root, { mode: 0o700 });
  const document = backupJobDocument({ id, operation });
  const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
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
  };
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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
  return crypto
    .createHmac("sha256", CAPABILITY)
    .update(REQUEST_MAC_DOMAIN)
    .update(canonicalJsonOracle(unsigned))
    .digest("hex");
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
    mac: crypto
      .createHmac("sha256", CAPABILITY)
      .update(RESPONSE_MAC_DOMAIN)
      .update(canonicalJsonOracle(unsigned))
      .digest("hex"),
  };
}

function omit(value, key) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

async function exchangeWithLocalBroker(
  request,
  response,
  { encodeResponse = JSON.stringify } = {},
) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-client-uds-"));
  fs.chmodSync(directory, 0o700);
  const socketPath = path.join(directory, "broker.sock");
  let receivedFrame;
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
        receivedFrame = JSON.parse(frames[0]);
        connection.end(`${encodeResponse(response)}\n`);
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
    value = await sendActionRequest(request, socketPath, CAPABILITY);
  } catch (error) {
    clientFailure = error;
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(directory, { force: true, recursive: true });
  }

  if (serverFailure) throw serverFailure;
  assert.deepEqual(receivedFrame, request, "sendActionRequest must carry the exact request over the local UDS");
  if (clientFailure) throw clientFailure;
  return value;
}
