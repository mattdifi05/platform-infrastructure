import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { authorizeBearer, createDockerOperationGateway, normalizeOperationRequest, operationNames, validateJobFilePath } from "./docker-operation-gateway.mjs";

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
  for (const operation of ["container-create", "exec", "image-pull", "network-create", "volume-create", "/v1.51/containers/create"]) {
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

test("bearer comparison rejects missing, malformed and short credentials", () => {
  assert.equal(authorizeBearer(`Bearer ${token}`, token), true);
  assert.equal(authorizeBearer(token, token), false);
  assert.equal(authorizeBearer("Bearer wrong", token), false);
  assert.equal(authorizeBearer("Bearer short", "short"), false);
});

test("HTTP boundary rejects raw Docker routes, replay and unsupported fields while allowing one legitimate operation", async (t) => {
  let calls = 0;
  const server = createDockerOperationGateway({ token, runOperation: async () => { calls += 1; return { status: 0 }; } });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = validRequest("backup-platform-catalog");
  const raw = await fetch(`${base}/v1.51/containers/create`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  assert.equal(raw.status, 404);
  const unauthorized = await post(base, request, "wrong".repeat(10));
  assert.equal(unauthorized.status, 401);
  const accepted = await post(base, request, token);
  assert.equal(accepted.status, 200);
  assert.equal(calls, 1);
  const replay = await post(base, request, token);
  assert.equal(replay.status, 409);
  assert.equal(calls, 1);
  const smuggled = await post(base, { ...validRequest("backup-platform-catalog"), parameters: { command: ["docker", "exec"] } }, token);
  assert.equal(smuggled.status, 400);
  assert.equal(calls, 1);
});

function validRequest(operation, parameters = {}) {
  return { version: 1, requestId: crypto.randomUUID(), issuedAt: new Date().toISOString(), operation, parameters };
}

function post(base, body, bearer) {
  return fetch(`${base}/v1/operations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
