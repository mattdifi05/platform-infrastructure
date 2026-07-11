import assert from "node:assert/strict";
import test from "node:test";
import { executeStatusChecks, StatusExecutorError, validateCatalog } from "./executor.mjs";

test("executor emits ordered progress for probe and evidence checks", async () => {
  const received = [];
  const result = await executeStatusChecks({
    runId: "run-one",
    delayMs: 0,
    onEvent: (event) => received.push(event),
    checks: [
      { id: "probe", category: "edge", executionMode: "probe", run: async () => ({ status: "passed", title: "Probe" }) },
      { id: "evidence", category: "backup", executionMode: "evidence-validation", run: () => ({ status: "pending-live-proof", title: "Evidence" }) },
    ],
  });
  assert.deepEqual(result.checks.map((item) => item.id), ["probe", "evidence"]);
  assert.deepEqual(received.map((event) => event.type), ["run-started", "check-started", "check-completed", "check-started", "check-completed", "run-completed"]);
  assert.deepEqual(received.map((event) => event.sequence), [1, 2, 3, 4, 5, 6]);
  assert.equal(result.checks[0].executionMode, "probe");
  assert.equal(result.checks[1].executionMode, "evidence-validation");
});

test("executor timeout fails closed without leaking the thrown error", async () => {
  const result = await executeStatusChecks({
    runId: "run-timeout",
    timeoutMs: 5,
    checks: [{ id: "slow", category: "runtime", executionMode: "probe", run: () => new Promise(() => {}) }],
  });
  assert.equal(result.checks[0].status, "failed");
  assert.equal(result.checks[0].errorCode, "STATUS_TIMEOUT");
  assert.doesNotMatch(JSON.stringify(result), /super-secret/);
});

test("catalog rejects duplicates, missing runners and unknown execution modes", () => {
  assert.throws(() => validateCatalog([{ id: "same", run() {} }, { id: "same", run() {} }]), StatusExecutorError);
  assert.throws(() => validateCatalog([{ id: "missing" }]), StatusExecutorError);
  assert.throws(() => validateCatalog([{ id: "bad", executionMode: "snapshot", run() {} }]), StatusExecutorError);
});
