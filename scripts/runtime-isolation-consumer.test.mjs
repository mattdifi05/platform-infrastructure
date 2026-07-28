#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const source = fs.readFileSync(path.join(import.meta.dirname, "infra-ops.mjs"), "utf8");
const start = source.indexOf("async function runtimeIsolationCheck()");
const end = source.indexOf("\nasync function faultInjectionTests()", start);

assert.notEqual(start, -1, "runtimeIsolationCheck() is missing");
assert.notEqual(end, -1, "runtimeIsolationCheck() boundary is missing");

const runtimeIsolationConsumer = source.slice(start, end);
const composeVpsSource = fs.readFileSync(path.join(import.meta.dirname, "compose-vps.sh"), "utf8");

test("production runtime-isolation consumer binds the authoritative Hosted activation inventory", () => {
  assert.match(
    runtimeIsolationConsumer,
    /compose-vps\.sh/,
    "runtime-isolation-check bypasses the read-once VPS Compose/activation consumer",
  );
  assert.match(
    runtimeIsolationConsumer,
    /runtime-isolation-envelope/,
    "runtime-isolation-check does not request one semantic runtime-isolation envelope",
  );
  for (const field of ["config", "lockSha256", "projectName", "protectedResourceNames"]) {
    assert.match(
      runtimeIsolationConsumer,
      new RegExp(`\\b${field}\\b`),
      `runtime-isolation-check does not validate the closed envelope field ${field}`,
    );
  }
  assert.match(
    runtimeIsolationConsumer,
    /evaluateRuntimeIsolation\(\s*(?:runtimeIsolationEnvelope|envelope)\.config\s*,\s*\{[\s\S]*?projectName\s*:\s*(?:runtimeIsolationEnvelope|envelope)\.projectName[\s\S]*?protectedResourceNames\s*:\s*(?:runtimeIsolationEnvelope|envelope)\.protectedResourceNames[\s\S]*?\}\s*\)/,
    "runtime-isolation-check does not pass the envelope identity and inventory into the semantic runtime policy",
  );
  assert.doesNotMatch(
    runtimeIsolationConsumer,
    /protectedResourceNames\s*[:=][\s\S]{0,400}Object\.keys\(\s*config/,
    "runtime-isolation-check derives a protected-resource fallback from the rendered config",
  );
  assert.doesNotMatch(
    runtimeIsolationConsumer,
    /(?:readFileSync|readJsonFile|hosted-workload-lock\.sh)[\s\S]{0,200}HOSTED_WORKLOAD_LOCK|HOSTED_WORKLOAD_LOCK[\s\S]{0,200}(?:readFileSync|readJsonFile|hosted-workload-lock\.sh)/,
    "runtime-isolation-check re-reads the Hosted lock instead of consuming the read-once envelope",
  );
  assert.doesNotMatch(
    runtimeIsolationConsumer,
    /argv\.(?:protectedResourceNames|protectedResources|workloadLock)/,
    "runtime-isolation-check permits a CLI override of the authoritative envelope",
  );
});

test("VPS wrapper emits one closed envelope from the same read-once activation bundle", () => {
  assert.match(
    composeVpsSource,
    /runtime-isolation-envelope/,
    "compose-vps.sh has no exact semantic-envelope mode",
  );
  const activationReads = [...composeVpsSource.matchAll(
    /hosted-workload-lock\.sh["']?\s+"\$workload_lock"\s+activation-bundle/g,
  )];
  assert.equal(activationReads.length, 1, "compose-vps.sh must read the Hosted activation bundle exactly once");
  assert.match(
    composeVpsSource,
    /runtime-isolation-envelope[\s\S]*activation_bundle[\s\S]*projectName[\s\S]*lockSha256[\s\S]*protectedResourceNames[\s\S]*config/,
    "semantic-envelope mode is not assembled from the same activation bundle and Compose render",
  );
  assert.doesNotMatch(
    composeVpsSource,
    /protectedResourceNames\s*[:=][\s\S]{0,400}(?:keys|Object\.keys)\s*\([^)]*(?:config|render)/,
    "compose-vps.sh derives protected resources from the combined render",
  );
  assert.match(
    composeVpsSource,
    /(?:HOSTED_WORKLOAD_MODE|NO_HOSTED|--no-hosted)[\s\S]*no-hosted-workloads\.lock\.json/,
    "an empty lock is treated as no-hosted without an explicit mode and canonical core lock",
  );
});
