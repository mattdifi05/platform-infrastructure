#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { canonicalVpsTopologyPlan, parseCanonicalVpsTopology } from "./canonical-compose-topology.mjs";
import { evaluateNetworkSegmentation } from "./network-segmentation-policy.mjs";
import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");

test("canonical plan invokes the deployment wrapper with a verified workload lock", () => {
  const plan = canonicalVpsTopologyPlan({
    infraRoot: repositoryRoot,
    envFile: ".env.vps.example",
    projectName: "platform_policy_check",
    workloadLock: "private/workloads.lock.json",
  });
  assert.equal(plan.command.bin, "bash");
  assert.deepEqual(plan.command.args.slice(1), ["config", "--format", "json"]);
  assert.equal(plan.command.args[0], path.join(repositoryRoot, "scripts", "compose-vps.sh"));
  assert.equal(plan.command.env.COMPOSE_ENV_FILE, path.join(repositoryRoot, ".env.vps.example"));
  assert.equal(plan.command.env.HOSTED_WORKLOAD_LOCK, path.join(repositoryRoot, "private", "workloads.lock.json"));
  assert.equal(plan.command.env.HOSTED_WORKLOAD_ALLOW_RESOLVED, "0");
});

test("canonical evidence includes hostile overlay services and changes its render identity", () => {
  const plan = canonicalVpsTopologyPlan({ infraRoot: repositoryRoot, envFile: ".env.vps.example" });
  const base = { services: { traefik: { networks: { platform_edge: null } } }, networks: { platform_edge: { internal: true } } };
  const hostile = structuredClone(base);
  hostile.services["hostile-shell"] = {
    privileged: true,
    networks: { platform_edge: null },
    labels: { "com.platform.workload-id": "hostile" },
  };
  const baseEvidence = parseCanonicalVpsTopology(JSON.stringify(base), plan).evidence;
  const hostileEvidence = parseCanonicalVpsTopology(JSON.stringify(hostile), plan, { workloadLockSha256: "a".repeat(64) }).evidence;
  assert.ok(hostileEvidence.serviceNames.includes("hostile-shell"));
  assert.deepEqual(hostileEvidence.hostedWorkloadIds, ["hostile"]);
  assert.notEqual(hostileEvidence.renderSha256, baseEvidence.renderSha256);
});

test("hostile services in the canonical render reach both policy evaluators", () => {
  const plan = canonicalVpsTopologyPlan({ infraRoot: repositoryRoot, envFile: ".env.vps.example" });
  const hostile = {
    services: {
      "project-router": { networks: { platform_postgres: null } },
      postgres: { networks: { platform_postgres: null } },
      "hostile-shell": {
        privileged: true,
        networks: { platform_postgres: null },
        labels: { "com.platform.workload-id": "hostile", "com.platform.workload-role": "web" },
      },
    },
    networks: { platform_postgres: { internal: true } },
  };
  const { config } = parseCanonicalVpsTopology(JSON.stringify(hostile), plan);
  const network = evaluateNetworkSegmentation(config);
  const runtime = evaluateRuntimeIsolation(config);
  assert.equal(network.checks.find((check) => check.id === "deny-router-postgres")?.status, "failed");
  assert.equal(runtime.checks.find((check) => check.id === "resource-cpu-hostile-shell")?.status, "failed");
  assert.equal(runtime.checks.find((check) => check.id === "workload-no-bind-mounts-hostile-shell")?.status, "passed");
});

test("network and runtime checks consume only the canonical wrapper render", () => {
  const source = readFileSync(path.join(repositoryRoot, "scripts", "infra-ops.mjs"), "utf8");
  const networkBody = source.slice(source.indexOf("async function networkSegmentationCheck"), source.indexOf("async function runtimeIsolationCheck"));
  const runtimeBody = source.slice(source.indexOf("async function runtimeIsolationCheck"), source.indexOf("async function faultInjectionTests"));
  for (const body of [networkBody, runtimeBody]) {
    assert.match(body, /canonicalVpsTopologyRender/);
    assert.doesNotMatch(body, /output\("docker"|const composeFiles/);
  }
});

test("invalid or empty canonical renders fail closed", () => {
  const plan = canonicalVpsTopologyPlan({ infraRoot: repositoryRoot, envFile: ".env.vps.example" });
  assert.throws(() => parseCanonicalVpsTopology("not-json", plan), /not valid JSON/);
  assert.throws(() => parseCanonicalVpsTopology(JSON.stringify({ services: {}, networks: {} }), plan), /empty/);
  assert.throws(() => canonicalVpsTopologyPlan({ infraRoot: repositoryRoot, envFile: ".env", projectName: "prod;id" }), /project name/);
});
