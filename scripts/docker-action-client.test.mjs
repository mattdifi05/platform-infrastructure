import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import * as contract from "./docker-action-contract.mjs";
import {
  buildClientRequest,
  protectedCapability,
  sendActionRequest,
} from "./docker-action-client.mjs";

const CAPABILITY = Buffer.alloc(32, 0x61);
const INTENT_ID = "intent.release-1";
const RECEIPT_SHA256 = "b".repeat(64);
const COMBINED_RENDER_SHA256 = "c".repeat(64);
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

test("client uses a Unix frame boundary and receives one semantic response", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-client-"));
  const socketPath = path.join(directory, "broker.sock");
  let responseCount = 0;
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const server = net.createServer((connection) => {
    let bytes = "";
    connection.on("data", (chunk) => {
      bytes += chunk;
    });
    connection.on("end", () => {
      const frames = bytes.split("\n").filter(Boolean);
      assert.equal(frames.length, 1);
      const request = JSON.parse(frames[0]);
      assert.equal(request.action, "evidence.runtime.snapshot");
      const response = signedResponse(request, { containers: [] });
      if (responseCount++ === 1) response.mac = "0".repeat(64);
      connection.end(`${JSON.stringify(response)}\n`);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  t.after(() => server.close());
  const request = buildClientRequest("runtime-docker-snapshot", [], {
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityKey: CAPABILITY,
  });
  const response = await sendActionRequest(request, socketPath, CAPABILITY);
  assert.equal(response.statusCode, 200);
  assert.equal(response.status, "completed");
  assert.deepEqual(response.result, { containers: [] });
  await assert.rejects(
    () => sendActionRequest(request, socketPath, CAPABILITY),
    /authentication|MAC|response/i,
    "the real client consumer must reject a structurally valid response with a substituted MAC",
  );
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

test("RED v2: client emits the exact canonical request and preserves every typed job field byte-for-byte", () => {
  const parameters = {
    jobFileName: "0123456789abcdef.json",
    jobId: "0123456789abcdef",
    jobOperation: "backup",
    jobSha256: "d".repeat(64),
  };
  const request = buildClientRequest("execute-backup-job", jobArguments(parameters), {
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityKey: CAPABILITY,
    now: Date.parse("2026-07-28T12:00:00.000Z"),
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
  });
  const unsigned = Object.fromEntries(Object.entries(request).filter(([key]) => key !== "mac"));
  const expectedMac = crypto
    .createHmac("sha256", CAPABILITY)
    .update(REQUEST_MAC_DOMAIN)
    .update(contract.canonicalJson(unsigned))
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
  assert.deepEqual(Object.keys(request.parameters).sort(), [
    "jobFileName",
    "jobId",
    "jobOperation",
    "jobSha256",
  ]);
  assert.deepEqual(request.parameters, parameters);
  assert.equal(request.mac, expectedMac);
});

test("RED v2: client accepts real queue identities without trim/lowercase and rejects case, traversal, whitespace or aliases", () => {
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
  for (const parameters of accepted) {
    const request = buildClientRequest("execute-backup-job", jobArguments(parameters), clientOptions());
    assert.deepEqual(request.parameters, parameters);
  }

  const base = accepted[0];
  const invalidParameterSets = [
    { ...base, jobId: ` ${base.jobId}` },
    { ...base, jobId: `${base.jobId} ` },
    { ...base, jobId: base.jobId.toUpperCase() },
    { ...base, jobOperation: "Backup" },
    { ...base, jobOperation: "backup " },
    { ...base, jobOperation: "restore" },
    { ...base, jobFileName: `../${base.jobFileName}` },
    { ...base, jobFileName: `queued/${base.jobFileName}` },
    { ...base, jobFileName: `queued\\${base.jobFileName}` },
    { ...base, jobFileName: base.jobFileName.toUpperCase() },
    { ...base, jobFileName: "job-alias.json" },
    { ...base, jobSha256: "A".repeat(64) },
    { ...base, jobSha256: `${base.jobSha256} ` },
  ];
  for (const parameters of invalidParameterSets) {
    assert.throws(() => buildClientRequest("execute-backup-job", jobArguments(parameters), clientOptions()));
  }
  assert.throws(() => buildClientRequest(
    "execute-backup-job",
    [...jobArguments(base), "--jobHash", base.jobSha256],
    clientOptions(),
  ));
  assert.throws(() => buildClientRequest(
    "execute-backup-job",
    jobArguments(base).map((value) => value === "--jobId" ? "--jobID" : value),
    clientOptions(),
  ));
  assert.throws(() => buildClientRequest(
    "execute-backup-job",
    jobArguments(base).filter((value) => value !== "--jobSha256" && value !== base.jobSha256),
    clientOptions(),
  ));
});

function jobArguments(parameters) {
  return [
    "--jobFileName",
    parameters.jobFileName,
    "--jobId",
    parameters.jobId,
    "--jobOperation",
    parameters.jobOperation,
    "--jobSha256",
    parameters.jobSha256,
  ];
}

function clientOptions() {
  return {
    runtimeIntentId: INTENT_ID,
    activeReceiptSha256: RECEIPT_SHA256,
    combinedRenderSha256: COMBINED_RENDER_SHA256,
    capabilityKey: CAPABILITY,
    now: Date.parse("2026-07-28T12:00:00.000Z"),
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
  };
}

function signedResponse(request, result) {
  const unsigned = {
    schema: RESPONSE_SCHEMA_V2,
    status: "completed",
    statusCode: 200,
    errorCode: null,
    action: request.action,
    requestId: request.requestId,
    requestSha256: contract.sha256(contract.canonicalJson(request)),
    result,
    resultSha256: contract.sha256(contract.canonicalJson(result)),
  };
  return {
    ...unsigned,
    mac: crypto
      .createHmac("sha256", CAPABILITY)
      .update(RESPONSE_MAC_DOMAIN)
      .update(contract.canonicalJson(unsigned))
      .digest("hex"),
  };
}
