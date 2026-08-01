#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: api-socket-admission-probe.mjs /path/to/archived/source");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 4 embedded vulnerable-source hashes");

const preparationScript = fs.readFileSync(path.join(sourceRoot, "scripts/prepare-hosted-workloads.sh"), "utf8");
assert.match(preparationScript, /compose-vps\.sh" config --format json > "\$combined_render"/);
assert.match(preparationScript, /hosted-workload-contract\.mjs verify-render/);

const activationScript = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
assert.match(activationScript, /compose\+=\(-f "\$workload_file"\)/);
assert.match(activationScript, /exec "\$\{compose\[@\]\}" --profile backup "\$@"/);
console.log("[+] verified rendered admission and workload activation data flow");

const contractUrl = pathToFileURL(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs")).href;
const runtimeUrl = pathToFileURL(path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs")).href;
const { validateRenderedWorkloads } = await import(contractUrl);
const { evaluateRuntimeIsolation } = await import(runtimeUrl);

const baselineAdmission = admissionResult(() => {});
const baselineRuntime = runtimeResult(() => {});
assert.equal(baselineAdmission.accepted, true, baselineAdmission.error);
assert.equal(baselineRuntime.passed, true, baselineRuntime.error);
console.log("[+] hardened-baseline admission=accepted runtime=passed");

const privilegedAdmission = admissionResult((service) => {
  service.privileged = true;
});
assert.equal(privilegedAdmission.accepted, false, "explicit privileged mode should be rejected");
assert.match(privilegedAdmission.error, /host-level privilege/);
console.log("[+] explicit-privileged admission=rejected");

const directSocket = (service) => {
  service.volumes = [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock" }];
};
const directSocketAdmission = admissionResult(directSocket);
const directSocketRuntime = runtimeResult(directSocket);
assert.equal(directSocketAdmission.accepted, false, "a direct Engine socket bind should be rejected");
assert.match(directSocketAdmission.error, /bind mounts are forbidden/);
assert.equal(directSocketRuntime.passed, false, "the runtime check should reject a direct Engine socket bind");
assert.match(directSocketRuntime.error, /workload-no-bind-mounts-probe-app-web/);
assert.deepEqual(directSocketRuntime.rawSocketOwners, ["docker-socket-proxy", "probe-app-web"]);
console.log("[+] direct-engine-socket-bind admission=rejected runtime=failed");

const apiSocket = (service) => {
  service.use_api_socket = true;
};
const apiSocketAdmission = admissionResult(apiSocket);
const apiSocketRuntime = runtimeResult(apiSocket);
assert.equal(apiSocketAdmission.accepted, true, apiSocketAdmission.error);
assert.equal(apiSocketAdmission.service.use_api_socket, true, "admission unexpectedly removed use_api_socket");
assert.equal(apiSocketRuntime.passed, true, apiSocketRuntime.error);
assert.deepEqual(apiSocketRuntime.rawSocketOwners, ["docker-socket-proxy"]);
console.log("[VULNERABLE] use-api-socket admission=accepted runtime=passed field-preserved=yes raw-socket-owners=docker-socket-proxy");

console.log("[+] no Docker or Compose process, daemon socket, credential store, or network service was accessed");
console.log("[+] result=VULNERABLE");

function admissionResult(apply) {
  const core = {
    services: {
      "project-router": {
        image: `registry.example/platform/router@sha256:${"b".repeat(64)}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
  const combined = structuredClone(core);
  combined.services["project-router"].networks.probe_app_ingress = null;
  const service = hostedService();
  apply(service);
  combined.services["probe-app-web"] = service;
  combined.networks.probe_app_ingress = { internal: true };
  const lock = {
    workloads: [{
      id: "probe-app",
      secrets: [],
      services: [{ name: "probe-app-web", role: "web", routes: [{ slug: "probe", port: 3000 }] }],
    }],
  };

  try {
    validateRenderedWorkloads({ core, combined, lock });
    return { accepted: true, service };
  } catch (error) {
    return { accepted: false, error: error.message, service };
  }
}

function runtimeResult(apply) {
  const config = runtimeFixture();
  apply(config.services["probe-app-web"]);
  const result = evaluateRuntimeIsolation(config);
  return {
    passed: result.status === "passed",
    error: result.failures.join("; "),
    rawSocketOwners: result.summary.rawSocketOwners,
  };
}

function hostedService() {
  return {
    image: `registry.example/workloads/probe@sha256:${"a".repeat(64)}`,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    pids_limit: 128,
    cpu_shares: 256,
    blkio_config: { weight: 300 },
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    cpus: 0.5,
    mem_limit: 256 * 1024 * 1024,
    mem_reservation: 64 * 1024 * 1024,
    healthcheck: { test: ["CMD", "true"] },
    networks: { probe_app_ingress: null },
    labels: {
      "com.platform.workload-id": "probe-app",
      "com.platform.workload-role": "web",
    },
  };
}

function runtimeFixture() {
  const services = {
    "probe-app-web": bounded({
      read_only: true,
      user: "1000:1000",
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      labels: {
        "com.platform.workload-id": "probe-app",
        "com.platform.workload-role": "web",
      },
      networks: { probe_app_ingress: null },
    }),
    "control-center": bounded({ read_only: true }),
    "project-router": bounded({
      read_only: true,
      volumes: [
        { type: "bind", source: "/synthetic/projects", target: "/var/www/projects", read_only: true },
        { type: "bind", source: "/synthetic/state", target: "/var/www/project-state", read_only: true },
      ],
    }),
    "platform-alert-dispatcher": bounded({ read_only: true }),
    "backup-scheduler": bounded({
      read_only: true,
      cpu_shares: 1024,
      environment: {
        DOCKER_HOST: "tcp://docker-socket-proxy:2375",
        DOCKER_API_VERSION: "1.51",
      },
      networks: { platform_docker_control: null },
    }),
    "docker-socket-proxy": bounded({
      read_only: true,
      cpu_shares: 1024,
      image: `registry.example/platform/socket-proxy@sha256:${"c".repeat(64)}`,
      environment: Object.fromEntries(
        ["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"]
          .map((key) => [key, "0"]),
      ),
      ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
      volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
      networks: { platform_docker_control: null },
    }),
  };

  return {
    services,
    networks: { platform_docker_control: { internal: true } },
  };
}

function bounded(overrides = {}) {
  return {
    image: `registry.example/platform/component@sha256:${"d".repeat(64)}`,
    cpus: 0.1,
    cpu_shares: 256,
    mem_limit: 64 * 1024 * 1024,
    mem_reservation: 16 * 1024 * 1024,
    pids_limit: 64,
    ulimits: { nofile: { soft: 4096, hard: 4096 } },
    blkio_config: { weight: 300 },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    ...overrides,
  };
}
