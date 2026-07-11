import assert from "node:assert/strict";
import test from "node:test";
import { evaluateFunctionalHealth, validateFunctionalHealthProbes } from "./functional-health.mjs";

const probes = [
  { id: "ready", kind: "http", container: "service", port: 8080, path: "/ready", expectedStatuses: [200], bodyIncludes: "ready" },
  { id: "dns", kind: "dns", container: "dns", query: "portal.example.com" },
];

test("functional HTTP and DNS observations pass", () => {
  const result = evaluateFunctionalHealth(probes, [
    { id: "ready", status: 200, body: "ready", latencyMs: 3 },
    { id: "dns", answers: ["192.0.2.10"], latencyMs: 2 },
  ]);
  assert.equal(result.status, "passed");
  assert.match(result.fingerprint, /^[a-f0-9]{64}$/);
});

test("process alive without a functional response fails", () => {
  const result = evaluateFunctionalHealth(probes, [
    { id: "ready", status: 503, body: "starting", latencyMs: 1 },
    { id: "dns", answers: ["192.0.2.10"], latencyMs: 2 },
  ]);
  assert.equal(result.status, "failed");
  assert.equal(result.checks.find((check) => check.id === "ready").passed, false);
});

test("missing observation fails closed", () => {
  assert.equal(evaluateFunctionalHealth(probes, []).status, "failed");
});

test("process-only probes are rejected", () => {
  assert.throws(() => validateFunctionalHealthProbes([{ id: "version", kind: "process", container: "service" }]), /never process-only/);
});
