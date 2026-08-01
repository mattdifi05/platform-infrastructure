#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const CASES = [
  ["CAN-002", "enterprise_postgres_data"],
  ["CAN-086", "enterprise_mariadb_data"],
  ["CAN-087", "enterprise_redis_data"],
  ["CAN-088", "enterprise_keycloak_data"],
  ["CAN-089", "enterprise_nats_data"],
  ["CAN-090", "enterprise_minio_data"],
  ["CAN-091", "peer_workload_data"],
  ["CAN-092", "enterprise_grafana_data"],
];

function usage() {
  process.stderr.write(
    "Usage: node volume-alias-probe.mjs --contract PATH " +
      "[--expect vulnerable|fixed]\n",
  );
}

function parseArgs(values) {
  const result = { expect: "vulnerable" };
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--contract") result.contract = values[++index];
    else if (value === "--expect") result.expect = values[++index];
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!result.contract) throw new Error("--contract is required");
  if (!new Set(["vulnerable", "fixed"]).has(result.expect)) {
    throw new Error("--expect must be vulnerable or fixed");
  }
  return result;
}

const digest = "a".repeat(64);
const manifest = {
  id: "example-app",
  services: [{ name: "example-app-web", role: "web", routes: [] }],
  secrets: [],
};
const lock = {
  projectName: "synthetic_project",
  workloads: [manifest],
};
const core = {
  services: {
    "project-router": {
      image: `registry.example/router@sha256:${digest}`,
      networks: { platform_routing: null },
    },
  },
  networks: { platform_routing: { internal: true } },
};

function combinedFixture(physicalName) {
  const logicalName = "example-app_data";
  return {
    services: {
      "project-router": structuredClone(core.services["project-router"]),
      "example-app-web": {
        image: `registry.example/example/app@sha256:${digest}`,
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
        mem_limit: String(256 * 1024 * 1024),
        mem_reservation: String(64 * 1024 * 1024),
        healthcheck: { test: ["CMD", "true"] },
        networks: { example_app_bus: null },
        labels: {
          "com.platform.workload-id": "example-app",
          "com.platform.workload-role": "web",
        },
        volumes: [
          {
            type: "volume",
            source: logicalName,
            target: "/mnt/synthetic-target",
          },
        ],
      },
    },
    networks: {
      platform_routing: { internal: true },
      example_app_bus: { internal: true },
    },
    volumes: {
      [logicalName]: {
        external: true,
        name: physicalName,
      },
    },
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const contractUrl = pathToFileURL(path.resolve(args.contract)).href;
  const module = await import(contractUrl);
  if (typeof module.validateRenderedWorkloads !== "function") {
    throw new Error("target module does not export validateRenderedWorkloads");
  }
  const validate = module.validateRenderedWorkloads;
  process.stdout.write("[+] loaded hosted-workload contract module\n");

  const bindFixture = combinedFixture("synthetic_unused");
  bindFixture.services["example-app-web"].volumes = [
    { type: "bind", source: "/synthetic", target: "/mnt/synthetic-target" },
  ];
  let bindRejected = false;
  try {
    validate({ core, combined: bindFixture, lock });
  } catch {
    bindRejected = true;
  }
  if (!bindRejected) throw new Error("negative control failed: direct bind was accepted");
  process.stdout.write("[+] negative control rejected a direct bind mount\n");

  let accepted = 0;
  let rejected = 0;
  for (const [candidateId, physicalName] of CASES) {
    try {
      validate({ core, combined: combinedFixture(physicalName), lock });
      accepted += 1;
      process.stdout.write(
        `[!] ${candidateId} accepted foreign physical volume ${physicalName}\n`,
      );
    } catch {
      rejected += 1;
      process.stdout.write(
        `[+] ${candidateId} rejected foreign physical volume ${physicalName}\n`,
      );
    }
  }

  if (args.expect === "vulnerable") {
    if (accepted !== CASES.length || rejected !== 0) {
      throw new Error(
        `vulnerable expectation failed: accepted=${accepted} rejected=${rejected}`,
      );
    }
    process.stdout.write(
      `[+] vulnerable expectation met: ${accepted}/${CASES.length} foreign aliases accepted\n`,
    );
  } else {
    if (rejected !== CASES.length || accepted !== 0) {
      throw new Error(
        `fixed expectation failed: accepted=${accepted} rejected=${rejected}`,
      );
    }
    process.stdout.write(
      `[+] fixed expectation met: ${rejected}/${CASES.length} foreign aliases rejected\n`,
    );
  }

  process.stdout.write(
    "[+] no Docker daemon, volume, network, or real data was accessed\n",
  );
}

try {
  await main();
} catch (error) {
  usage();
  process.stderr.write(`[-] ${error.message}\n`);
  process.exitCode = 1;
}
