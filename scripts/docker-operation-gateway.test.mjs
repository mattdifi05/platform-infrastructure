import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  authenticatePrincipal,
  createDockerOperationGateway,
  normalizeOperationRequest,
  operationNames,
  snapshotJobFile,
  validateJobFilePath,
} from "./docker-operation-gateway.mjs";

const token = "t".repeat(48);

test("typed gateway exposes only fixed high-level operations", () => {
  assert.deepEqual(operationNames().sort(), [
    "backup-platform-catalog",
    "execute-backup-job",
    "full-restore-drill",
    "offsite-backup-restic",
    "prune-manifest-backups-apply",
    "prune-manifest-backups-plan",
  ]);
  const request = validRequest("backup-platform-catalog");
  assert.deepEqual(normalizeOperationRequest(request, { now: Date.parse(request.issuedAt) }).args, ["backup-platform-catalog"]);
  for (const operation of [
    "container-create",
    "container-exec",
    "image-pull",
    "network-create",
    "volume-create",
    "host-bind",
    "privileged-container",
    "device-mount",
    "cap-add",
    "host-network",
    "host-pid",
    "host-ipc",
    "/v1.51/containers/create",
  ]) {
    assert.throws(() => normalizeOperationRequest(validRequest(operation), { now: Date.now() }), /not authorized/);
  }
  assert.throws(() => normalizeOperationRequest({ ...request, dockerArgs: ["exec", "x", "sh"] }, { now: Date.parse(request.issuedAt) }), /unsupported fields/);
});

test("job file is contained to the fixed running queue", () => {
  const request = validRequest("execute-backup-job", { jobFileName: "job-123.json" });
  const normalized = normalizeOperationRequest(request, { now: Date.parse(request.issuedAt), jobsDir: "/state/jobs" });
  assert.deepEqual(normalized.args, ["execute-backup-job", "--jobFile", "/state/jobs/running/job-123.json"]);
  for (const jobFileName of ["../escape.json", "nested/job.json", "job.txt", "..json"]) {
    assert.throws(() => normalizeOperationRequest(validRequest("execute-backup-job", { jobFileName }), { now: Date.now() }), /invalid/);
  }
});

test("job file validation rejects symlinks and files outside the running queue", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-gateway-job-"));
  try {
    const running = path.join(root, "running");
    fs.mkdirSync(running);
    const job = path.join(running, "job.json");
    fs.writeFileSync(job, "{}\n");
    assert.equal(validateJobFilePath(job, root), job);
    const outside = path.join(root, "outside.json");
    fs.writeFileSync(outside, "{}\n");
    assert.throws(() => validateJobFilePath(outside, root), /regular file/);
    const link = path.join(running, "link.json");
    fs.symlinkSync(outside, link);
    assert.throws(() => validateJobFilePath(link, root), /regular file/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("job execution uses a private stable snapshot after source replacement", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-gateway-snapshot-"));
  try {
    const running = path.join(root, "running");
    const snapshots = path.join(root, "snapshots");
    fs.mkdirSync(running);
    fs.mkdirSync(snapshots);
    const source = path.join(running, "job.json");
    fs.writeFileSync(source, "{\"operation\":\"backup\"}\n");
    const snapshot = snapshotJobFile(source, root, snapshots);
    const replacement = path.join(root, "replacement.json");
    fs.writeFileSync(replacement, "{\"operation\":\"restore-drill\"}\n");
    fs.renameSync(replacement, source);
    assert.equal(fs.readFileSync(snapshot.path, "utf8"), "{\"operation\":\"backup\"}\n");
    assert.equal(fs.realpathSync.native(path.dirname(snapshot.path)), fs.realpathSync.native(snapshot.root));
    snapshot.cleanup();
    assert.equal(fs.existsSync(snapshot.root), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("principal credential comparison rejects missing, malformed and short credentials", () => {
  const credentials = { "backup-scheduler": token };
  assert.equal(authenticatePrincipal(`Bearer ${token}`, credentials), "backup-scheduler");
  assert.equal(authenticatePrincipal(token, credentials), "");
  assert.equal(authenticatePrincipal("Bearer wrong", credentials), "");
  assert.equal(authenticatePrincipal("Bearer short", { "backup-scheduler": "short" }), "");
});

test("HTTP boundary rejects raw Docker routes, replay and unsupported fields while allowing one legitimate operation", async (t) => {
  let calls = 0;
  const server = createDockerOperationGateway({ principalTokens: { "backup-scheduler": token }, runOperation: async () => { calls += 1; return { status: 0 }; } });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = validRequest("backup-platform-catalog");
  const raw = await fetch(`${base}/v1.51/containers/create`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  assert.equal(raw.status, 404);
  const missing = await post(base, request);
  assert.equal(missing.status, 401);
  assert.equal(calls, 0);
  const unauthorized = await post(base, request, "wrong".repeat(10));
  assert.equal(unauthorized.status, 401);
  assert.equal(calls, 0);
  const wrongPrincipal = await post(base, { ...request, principal: "control-center", requestId: crypto.randomUUID() }, token);
  assert.equal(wrongPrincipal.status, 403);
  assert.equal(calls, 0);
  const accepted = await post(base, request, token);
  assert.equal(accepted.status, 200);
  assert.equal(calls, 1);
  const replay = await post(base, request, token);
  assert.equal(replay.status, 409);
  assert.equal(calls, 1);
  const smuggled = await post(base, { ...validRequest("backup-platform-catalog"), parameters: { command: ["docker", "exec"] } }, token);
  assert.equal(smuggled.status, 400);
  assert.equal(calls, 1);
  for (const parameters of [
    { image: "attacker/image:latest" },
    { binds: ["/:/host"] },
    { privileged: true },
    { devices: ["/dev/sda"] },
    { capAdd: ["SYS_ADMIN"] },
    { networkMode: "host" },
    { pidMode: "host" },
    { ipcMode: "host" },
  ]) {
    const response = await post(base, { ...validRequest("backup-platform-catalog"), parameters }, token);
    assert.equal(response.status, 400);
  }
  assert.equal(calls, 1);
});

test("timeout keeps the gateway busy until the privileged operation actually exits", async (t) => {
  let calls = 0;
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const server = createDockerOperationGateway({
    principalTokens: { "backup-scheduler": token },
    operationTimeoutMs: 30,
    runOperation: async () => { calls += 1; return pending; },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const first = post(base, validRequest("backup-platform-catalog"), token);
  while (calls === 0) await new Promise((resolve) => setImmediate(resolve));
  const concurrent = await post(base, validRequest("full-restore-drill"), token);
  assert.equal(concurrent.status, 409);
  assert.equal((await first).status, 504);
  const stillBusy = await post(base, validRequest("full-restore-drill"), token);
  assert.equal(stillBusy.status, 409);
  release({ status: 0 });
  await new Promise((resolve) => setImmediate(resolve));
  const afterExit = await post(base, validRequest("full-restore-drill"), token);
  assert.equal(afterExit.status, 200);
  assert.equal(calls, 2);
});

function validRequest(operation, parameters = {}) {
  return { version: 1, principal: "backup-scheduler", requestId: crypto.randomUUID(), issuedAt: new Date().toISOString(), operation, parameters };
}

function post(base, body, bearer) {
  const headers = { "Content-Type": "application/json" };
  if (bearer !== undefined) headers.Authorization = `Bearer ${bearer}`;
  return fetch(`${base}/v1/operations`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}
