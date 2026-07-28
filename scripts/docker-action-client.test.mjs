import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildClientRequest,
  protectedCapability,
  sendActionRequest,
} from "./docker-action-client.mjs";

const CAPABILITY = Buffer.alloc(32, 0x61);
const INTENT_ID = "intent.release-1";
const RECEIPT_SHA256 = "b".repeat(64);
const COMBINED_RENDER_SHA256 = "c".repeat(64);

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
      connection.end(`${JSON.stringify({
        statusCode: 200,
        status: "completed",
        action: request.action,
        result: { containers: [] },
      })}\n`);
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
  const response = await sendActionRequest(request, socketPath);
  assert.equal(response.statusCode, 200);
  assert.equal(response.status, "completed");
  assert.deepEqual(response.result, { containers: [] });
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
