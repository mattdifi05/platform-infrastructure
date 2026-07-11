import assert from "node:assert/strict";
import test from "node:test";
import { evaluateRuntimeFingerprint } from "./runtime-fingerprint.mjs";

const commit = "a".repeat(40);
const hash = "b".repeat(64);
const imageId = `sha256:${"c".repeat(64)}`;
const expected = { commit, project: "platform", services: [{ service: "api", configHash: hash }] };
const actual = {
  commit,
  clean: true,
  project: "platform",
  containers: [{ name: "platform-api", service: "api", project: "platform", configHash: hash, imageId, imageRef: "example/api@sha256:digest", state: "running", health: "healthy" }],
};

test("exact commit, project and service hashes pass", () => {
  const result = evaluateRuntimeFingerprint(expected, actual);
  assert.equal(result.status, "passed");
  assert.deepEqual(result.issues, []);
  assert.match(result.fingerprint, /^[a-f0-9]{64}$/);
});

test("wrong commit fails closed", () => {
  assert.match(evaluateRuntimeFingerprint(expected, { ...actual, commit: "d".repeat(40) }).issues.join(","), /commit-mismatch/);
});

test("wrong config hash fails closed", () => {
  const containers = [{ ...actual.containers[0], configHash: "e".repeat(64) }];
  assert.match(evaluateRuntimeFingerprint(expected, { ...actual, containers }).issues.join(","), /config-hash-mismatch/);
});

test("missing and unexpected services fail closed", () => {
  const missing = evaluateRuntimeFingerprint(expected, { ...actual, containers: [] });
  assert.match(missing.issues.join(","), /missing-service/);
  const extra = evaluateRuntimeFingerprint(expected, { ...actual, containers: [...actual.containers, { ...actual.containers[0], name: "other", service: "other" }] });
  assert.match(extra.issues.join(","), /unexpected-service/);
});

test("dirty worktree and unhealthy runtime fail closed", () => {
  const result = evaluateRuntimeFingerprint(expected, { ...actual, clean: false, containers: [{ ...actual.containers[0], health: "unhealthy" }] });
  assert.match(result.issues.join(","), /worktree-not-clean/);
  assert.match(result.issues.join(","), /service-unhealthy/);
});
