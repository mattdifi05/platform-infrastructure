#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const gatePath = path.join(import.meta.dirname, "hosted-workload-activation-gate.sh");
const gateSource = fs.readFileSync(gatePath, "utf8");
const functionStart = gateSource.indexOf("validate_bundle() {");
const functionEndMarker = "\n}\n\nverify_extension_records()";
const functionEnd = gateSource.indexOf(functionEndMarker, functionStart);
assert.notEqual(functionStart, -1, "validate_bundle() is missing");
assert.notEqual(functionEnd, -1, "validate_bundle() boundary is missing");
const validateBundleFunction = gateSource.slice(functionStart, functionEnd + 2);

test("activation bundle validator preserves exact non-colliding and single textual-child owners", () => {
  const nonColliding = validate(bundleFor(["billing", "billingapi"]));
  assert.equal(nonColliding.status, 0, nonColliding.stderr);
  const singleOwner = validate(bundleFor(["billing"], { billing: "billing-api-web" }));
  assert.equal(singleOwner.status, 0, singleOwner.stderr);
});

test("activation bundle validator rejects nested ids before any render consumer", () => {
  const result = validate(bundleFor(["billing", "billing-api"]));
  assert.notEqual(result.status, 0);
});

test("activation bundle validator rejects an exact network record claimed by another workload", () => {
  const forged = bundleFor(["billing", "billingapi"]);
  forged.platformExtensionRecords[0].networkNames = ["billingapi_ingress"];
  const result = validate(forged);
  assert.notEqual(result.status, 0);
});

test("activation bundle validator consumes the exact protected resource schema", () => {
  const forged = bundleFor(["billing"]);
  delete forged.protectedResourceNames.volumes;
  const result = validate(forged);
  assert.notEqual(result.status, 0);
});

test("activation bundle validator rejects the canonical one-character id drift", () => {
  const result = validate(bundleFor(["b"]));
  assert.notEqual(result.status, 0);
});

test("activation bundle validator leaves exact suffix room at the 61-byte workload-id limit", () => {
  const workloadId = `b${"a".repeat(60)}`;
  const result = validate(bundleFor([workloadId], { [workloadId]: `${workloadId}-x` }));
  assert.equal(result.status, 0, result.stderr);
});

test("activation bundle validator binds exact closed route records to exact service owners", () => {
  const valid = bundleFor(["billing"]);
  valid.routeRecords = [{
    workloadId: "billing",
    slug: "billing",
    serviceName: "billing-web",
    port: 3000,
    upstream: "http://billing-web:3000",
  }];
  assert.equal(validate(valid).status, 0);

  const mutations = [
    (route) => { route.workloadId = "billingapi"; },
    (route) => { route.slug = "Billing"; },
    (route) => { route.serviceName = "billing-worker"; },
    (route) => { route.port = 0; },
    (route) => { route.upstream = "http://billing-web:9999"; },
    (route) => { route.extra = true; },
  ];
  for (const mutate of mutations) {
    const forged = structuredClone(valid);
    mutate(forged.routeRecords[0]);
    assert.notEqual(validate(forged).status, 0, JSON.stringify(forged.routeRecords[0]));
  }
});

test("all Hosted shell bundle consumers use the exact workload-id regex", () => {
  for (const relativePath of [
    "hosted-workload-activation-gate.sh",
    "compose-vps.sh",
    "core-stack-activation-gate.sh",
    "hosted-workload-network-ownership.sh",
  ]) {
    const source = fs.readFileSync(path.join(import.meta.dirname, relativePath), "utf8");
    const workloadIdRegexLines = source.split("\n")
      .filter((line) => /workloadId|workloadIds/.test(line) && line.includes("test("));
    assert.equal(
      workloadIdRegexLines.some((line) => line.includes("^[a-z0-9][a-z0-9-]*$")),
      false,
      `${relativePath} still contains the permissive workload-id regex`,
    );
    assert.equal(
      workloadIdRegexLines.some((line) => line.includes("^[a-z][a-z0-9-]{1,60}$")),
      true,
      `${relativePath} has no exact 61-byte workload-id regex`,
    );
    assert.equal(
      workloadIdRegexLines.some((line) => line.includes("^[a-z][a-z0-9-]{1,62}$")),
      false,
      `${relativePath} still accepts workload ids longer than 61 bytes`,
    );
  }

  const lockSource = fs.readFileSync(path.join(import.meta.dirname, "hosted-workload-lock.sh"), "utf8");
  assert.match(
    lockSource,
    /all\(\$lock\.workloads\[\];\s*\(\.id\s*\|\s*type\s*==\s*"string"\s+and\s+test\("\^\[a-z\]\[a-z0-9-\]\{1,60\}\$"\)\)\)/,
    "hosted-workload-lock.sh has no exact 61-byte workload-id validator",
  );
});

function validate(bundle) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
PROJECT_NAME=platform_infra_vps
${validateBundleFunction}
validate_bundle "$1"
`,
    "activation-bundle-test",
    JSON.stringify(bundle),
  ], { encoding: "utf8" });
}

function bundleFor(workloadIds, serviceNames = {}) {
  const networkRecords = workloadIds.map((workloadId) => {
    const logicalName = `${workloadId.replaceAll("-", "_")}_ingress`;
    return {
      workloadId,
      logicalName,
      physicalName: `platform_infra_vps_${logicalName}`,
    };
  });
  const serviceRecords = workloadIds.map((workloadId) => ({
    workloadId,
    serviceName: serviceNames[workloadId] || `${workloadId}-web`,
  }));
  const platformExtensionRecords = workloadIds.map((workloadId) => ({
    workloadId,
    serviceName: "project-router",
    networkNames: [`${workloadId.replaceAll("-", "_")}_ingress`],
  }));
  return {
    version: 2,
    projectName: "platform_infra_vps",
    lockSha256: "a".repeat(64),
    coreRenderSha256: "b".repeat(64),
    combinedRenderSha256: "c".repeat(64),
    workloadIds: [...workloadIds].sort(),
    protectedNetworkNames: ["platform_routing"],
    protectedResourceNames: {
      configs: [],
      networks: ["platform_routing"],
      secrets: [],
      services: ["project-router"],
      volumes: [],
    },
    networkRecords: networkRecords.sort(compareRecords),
    serviceRecords: serviceRecords.sort(compareRecords),
    platformExtensionRecords: platformExtensionRecords.sort(compareRecords),
    routeRecords: [],
  };
}

function compareRecords(left, right) {
  const leftKey = `${left.workloadId}\0${left.serviceName || left.logicalName}`;
  const rightKey = `${right.workloadId}\0${right.serviceName || right.logicalName}`;
  return leftKey < rightKey ? -1 : (leftKey > rightKey ? 1 : 0);
}
