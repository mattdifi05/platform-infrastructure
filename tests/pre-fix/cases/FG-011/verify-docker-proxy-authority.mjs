#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED = new Map([
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["scripts/runtime-isolation-policy.test.mjs", "555eeafa5c15ed44a30b37140b537ad7424be19bb55fe697cda8cd46cb0043ea"],
  ["scripts/runtime-isolation-sandbox-test.sh", "76d4736524d966619b07273d05bc11fafb708bd2ddc2237780f4bada6aabfb50"],
]);

const BROAD_FLAGS = [
  "ALLOW_START",
  "ALLOW_STOP",
  "ALLOW_RESTARTS",
  "CONTAINERS",
  "EXEC",
  "IMAGES",
  "NETWORKS",
  "POST",
  "VOLUMES",
];

const MUTATION_ROUTES = [
  ["container creation", "POST /v1.51/containers/create", ["CONTAINERS", "POST"]],
  ["container start", "POST /v1.51/containers/{id}/start", ["CONTAINERS", "POST", "ALLOW_START"]],
  ["exec creation", "POST /v1.51/containers/{id}/exec", ["EXEC", "POST"]],
  ["exec start", "POST /v1.51/exec/{id}/start", ["EXEC", "POST"]],
  ["image pull/create", "POST /v1.51/images/create", ["IMAGES", "POST"]],
  ["network creation", "POST /v1.51/networks/create", ["NETWORKS", "POST"]],
  ["volume creation", "POST /v1.51/volumes/create", ["VOLUMES", "POST"]],
];

main().catch((error) => {
  console.error(`[FAIL] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});

async function main() {
  const specimenRoot = path.resolve(process.argv[2] || ".");

  for (const [relativePath, expectedHash] of EXPECTED) {
    const content = await readFile(path.join(specimenRoot, relativePath));
    const actualHash = createHash("sha256").update(content).digest("hex");
    assert.equal(actualHash, expectedHash, `${relativePath} is not the affected pre-fix source`);
  }
  console.log("[PASS] exact pre-fix source fingerprints verified");

  const compose = await readFile(path.join(specimenRoot, "compose.runtime-isolation.yaml"), "utf8");
  const policySource = await readFile(path.join(specimenRoot, "scripts/runtime-isolation-policy.mjs"), "utf8");
  const sandboxSource = await readFile(path.join(specimenRoot, "scripts/runtime-isolation-sandbox-test.sh"), "utf8");

  const proxyBlock = between(compose, "  docker-socket-proxy:\n", "\n  traefik:");
  const schedulerBlock = between(compose, "  backup-scheduler:\n", "\nnetworks:");

  for (const flag of BROAD_FLAGS) {
    assert.match(proxyBlock, new RegExp(`\\n\\s+${flag}: "1"`), `${flag}=1 is absent from the proxy block`);
  }
  assert.ok(
    proxyBlock.includes('      - "127.0.0.1:${DOCKER_SOCKET_PROXY_PORT:-2376}:2375"'),
    "loopback publication is absent",
  );
  assert.ok(
    proxyBlock.includes("      - /var/run/docker.sock:/var/run/docker.sock:ro"),
    "raw Docker socket backend is absent",
  );
  assert.ok(
    schedulerBlock.includes("      DOCKER_HOST: tcp://docker-socket-proxy:2375"),
    "scheduler proxy endpoint is absent",
  );
  assert.ok(schedulerBlock.includes("      - platform_docker_control"), "scheduler control-network membership is absent");
  assert.doesNotMatch(proxyBlock, /(?:client[_-]?ca|mtls|client[_-]?cert|bearer|basic[_-]?auth)/i);

  const policyUrl = pathToFileURL(path.join(specimenRoot, "scripts/runtime-isolation-policy.mjs"));
  const { evaluateRuntimeIsolation } = await import(policyUrl.href);
  assert.equal(typeof evaluateRuntimeIsolation, "function", "pre-fix policy export is unavailable");

  const vulnerableConfig = fixture();
  const report = evaluateRuntimeIsolation(vulnerableConfig);
  assert.equal(report.status, "passed", report.failures.join("\n"));
  for (const id of [
    "raw-socket-single-owner",
    "socket-proxy-dangerous-sections-disabled",
    "socket-proxy-loopback-only",
    "scheduler-uses-proxy",
    "socket-network-internal",
    "socket-network-members",
  ]) {
    assert.equal(check(report, id).status, "passed", `${id} did not pass`);
  }
  console.log("[PASS] pre-fix runtime policy result: passed");

  for (const [, route, gates] of MUTATION_ROUTES) {
    assert.ok(gates.every((gate) => vulnerableConfig.services["docker-socket-proxy"].environment[gate] === "1"), `${route} gates are not all enabled`);
  }
  console.log("[PASS] host-loopback boundary is accepted with broad Docker mutation families");
  console.log("[PASS] scheduler boundary is accepted with the same unauthenticated authority");

  const publicBinding = clone(vulnerableConfig);
  publicBinding.services["docker-socket-proxy"].ports[0].host_ip = "0.0.0.0";
  assert.equal(check(evaluateRuntimeIsolation(publicBinding), "socket-proxy-loopback-only").status, "failed");

  const extraMember = clone(vulnerableConfig);
  extraMember.services["untrusted-client"] = bounded({
    read_only: true,
    networks: { platform_docker_control: null },
  });
  assert.equal(check(evaluateRuntimeIsolation(extraMember), "socket-network-members").status, "failed");
  console.log("[PASS] policy negative controls reject public binding and extra network membership");

  const disabledList = extractQuotedList(policySource, "disabledProxySections");
  for (const flag of ["CONTAINERS", "EXEC", "IMAGES", "NETWORKS", "POST", "VOLUMES"]) {
    assert.ok(!disabledList.includes(flag), `${flag} unexpectedly appears in the pre-fix deny list`);
  }
  for (const route of [
    "/v1.51/containers/create",
    "/v1.51/containers/{id}/exec",
    "/v1.51/exec/{id}/start",
    "/v1.51/images/create",
    "/v1.51/networks/create",
    "/v1.51/volumes/create",
  ]) {
    assert.ok(!sandboxSource.includes(route), `sandbox unexpectedly probes ${route}`);
  }
  console.log("[PASS] sandbox omits denial probes for decisive mutation routes");
  console.log("[SAFE] no network connection, Docker command, socket access, or state change was attempted");
}

function fixture() {
  const services = {};
  services["example-app-web"] = bounded({
    read_only: true,
    user: "1000:1000",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
    networks: { example_app_ingress: null },
  });
  services["control-center"] = bounded({ read_only: true, cpu_shares: 1024, volumes: [], networks: {} });
  services["project-router"] = bounded({
    read_only: true,
    volumes: [
      { type: "bind", source: "/srv/apps", target: "/var/www/projects", read_only: true },
      { type: "bind", source: "/srv/state", target: "/var/www/project-state", read_only: true },
    ],
    networks: {},
  });
  services["platform-alert-dispatcher"] = bounded({ read_only: true, networks: {} });
  services["backup-scheduler"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    environment: { DOCKER_HOST: "tcp://docker-socket-proxy:2375", DOCKER_API_VERSION: "1.51" },
    volumes: [],
    networks: { platform_docker_control: null },
  });
  services["docker-socket-proxy"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    image: `ghcr.io/tecnativa/docker-socket-proxy:v0.4.2@sha256:${"a".repeat(64)}`,
    environment: {
      ALLOW_START: "1",
      ALLOW_STOP: "1",
      ALLOW_RESTARTS: "1",
      AUTH: "0",
      BUILD: "0",
      COMMIT: "0",
      CONFIGS: "0",
      CONTAINERS: "1",
      EXEC: "1",
      IMAGES: "1",
      NETWORKS: "1",
      POST: "1",
      SECRETS: "0",
      SERVICES: "0",
      SESSION: "0",
      SWARM: "0",
      SYSTEM: "0",
      TASKS: "0",
      VOLUMES: "1",
    },
    ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
    volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
    networks: { platform_docker_control: null },
  });
  services.postgres = bounded({ networks: {} });
  return { services, networks: { platform_docker_control: { internal: true } } };
}

function bounded(overrides = {}) {
  return {
    cpus: 0.5,
    cpu_shares: 256,
    mem_limit: 128 * 1024 * 1024,
    mem_reservation: 32 * 1024 * 1024,
    pids_limit: 128,
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    blkio_config: { weight: 300 },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    ...overrides,
  };
}

function between(text, start, end) {
  const startIndex = text.indexOf(start);
  assert.notEqual(startIndex, -1, `missing source marker: ${start.trim()}`);
  const endIndex = text.indexOf(end, startIndex + start.length);
  assert.notEqual(endIndex, -1, `missing source marker: ${end.trim()}`);
  return text.slice(startIndex, endIndex);
}

function check(report, id) {
  const item = report.checks.find((entry) => entry.id === id);
  assert.ok(item, `missing policy check: ${id}`);
  return item;
}

function extractQuotedList(source, variableName) {
  const match = source.match(new RegExp(`const ${variableName} = \\[([^;]+)\\];`));
  assert.ok(match, `missing source list: ${variableName}`);
  return [...match[1].matchAll(/"([A-Z_]+)"/g)].map((item) => item[1]);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}
