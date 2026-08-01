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

const CASES = [
  {
    name: "raw-block-rwm-with-group",
    apply(service) {
      service.devices = ["/dev/sda:/dev/xvda:rwm"];
      service.device_cgroup_rules = ["b 8:* rwm"];
      service.group_add = ["disk"];
    },
  },
  {
    name: "raw-character-rwm",
    apply(service) {
      service.devices = ["/dev/kvm:/dev/kvm:rwm"];
    },
  },
  {
    name: "standalone-device-cgroup-wildcard",
    apply(service) {
      service.device_cgroup_rules = ["a 7:* rmw"];
    },
  },
  {
    name: "cdi-device-selector",
    apply(service) {
      service.devices = ["vendor1.com/device=gpu"];
    },
  },
  {
    name: "service-gpus-all",
    apply(service) {
      service.gpus = "all";
    },
  },
  {
    name: "service-gpus-list",
    apply(service) {
      service.gpus = [{ driver: "synthetic", count: 1 }];
    },
  },
  {
    name: "deploy-device-by-id",
    apply(service) {
      service.deploy = {
        resources: {
          reservations: {
            devices: [{
              capabilities: ["gpu"],
              driver: "synthetic",
              device_ids: ["device-0"],
              options: { mode: "isolated" },
            }],
          },
        },
      };
    },
  },
  {
    name: "deploy-all-matching-devices",
    apply(service) {
      service.deploy = {
        resources: {
          reservations: {
            devices: [{ capabilities: ["tpu"], count: "all" }],
          },
        },
      };
    },
  },
  {
    name: "supplemental-device-group",
    apply(service) {
      service.group_add = ["44", "video"];
    },
  },
];

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: device-admission-probe.mjs /path/to/archived/source");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 4 embedded vulnerable-source hashes");

const activationScript = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
assert.match(
  activationScript,
  /compose\+=\(-f "\$workload_file"\)/,
  "activation must append each admitted workload file to the Compose command",
);
console.log("[+] verified admitted workload files reach the Compose activation command");

const contractUrl = pathToFileURL(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs")).href;
const runtimeUrl = pathToFileURL(path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs")).href;
const { validateRenderedWorkloads } = await import(contractUrl);
const { evaluateRuntimeIsolation } = await import(runtimeUrl);

let accepted = 0;
for (const testCase of CASES) {
  const admission = admissionResult(testCase.apply);
  const runtime = runtimeResult(testCase.apply);
  if (admission.accepted && runtime.accepted) {
    accepted += 1;
    console.log(`[VULNERABLE] ${testCase.name} admission=accepted runtime=passed`);
    continue;
  }

  console.error(
    `[UNEXPECTED] ${testCase.name} admission=${admission.accepted ? "accepted" : "rejected"} runtime=${runtime.accepted ? "passed" : "failed"}`,
  );
  if (admission.error) console.error(`  admission detail: ${admission.error}`);
  if (runtime.error) console.error(`  runtime detail: ${runtime.error}`);
}

console.log(`[+] summary vulnerable=${accepted} total=${CASES.length}`);
console.log("[+] no device was opened and no Docker or Compose process was invoked");
assert.equal(accepted, CASES.length, "the archived vulnerable revision did not accept every device-delegation variant");

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
    return { accepted: true };
  } catch (error) {
    return { accepted: false, error: error.message };
  }
}

function runtimeResult(apply) {
  const config = runtimeFixture();
  apply(config.services["probe-app-web"]);
  const result = evaluateRuntimeIsolation(config);
  return {
    accepted: result.status === "passed",
    error: result.failures.join("; "),
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
