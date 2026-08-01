#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const CANONICAL_IDS = Object.freeze(["CAN-008", "CAN-094", "CAN-104"]);
const digest = "a".repeat(64);

function usage() {
  process.stderr.write(
    "Usage: node probe.mjs --candidate-root <path> [--expect vulnerable|fixed]\n",
  );
}

function parseArgs(argv) {
  const parsed = { expect: "vulnerable" };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--candidate-root") parsed.candidateRoot = argv[++index];
    else if (value === "--expect") parsed.expect = argv[++index];
    else {
      usage();
      throw new Error(`unsupported argument: ${value}`);
    }
  }
  if (!parsed.candidateRoot) throw new Error("--candidate-root is required");
  if (!new Set(["vulnerable", "fixed"]).has(parsed.expect)) {
    throw new Error("--expect must be vulnerable or fixed");
  }
  return parsed;
}

function fixture() {
  const manifest = {
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    secrets: [],
    migrationRoots: [],
    services: [
      {
        name: "example-app-web",
        role: "web",
        routes: [{ slug: "example", port: 3000 }],
      },
    ],
  };

  const workloadService = {
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
    healthcheck: { test: ["CMD", "node", "healthcheck.mjs"] },
    networks: { example_app_ingress: null },
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "web",
    },
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

  const combined = {
    services: {
      "project-router": {
        ...structuredClone(core.services["project-router"]),
        networks: {
          platform_routing: null,
          example_app_ingress: null,
        },
      },
      "example-app-web": workloadService,
    },
    networks: {
      platform_routing: { internal: true },
      example_app_ingress: { internal: true },
    },
  };

  return { core, combined, lock: { workloads: [manifest] } };
}

function expectRejection(validate, label, mutate) {
  const input = fixture();
  mutate(input.combined.services["example-app-web"]);
  try {
    validate(input);
  } catch (error) {
    process.stdout.write(`[+] control ${label} rejected: ${error.message}\n`);
    return;
  }
  throw new Error(`negative control ${label} was unexpectedly accepted`);
}

function exercise(validate, testCase) {
  const input = fixture();
  testCase.mutate(input.combined.services["example-app-web"]);
  try {
    validate(input);
    process.stdout.write(
      `[VULNERABLE] ${testCase.id} ${testCase.field} accepted (${testCase.primitive})\n`,
    );
    return "accepted";
  } catch (error) {
    process.stdout.write(
      `[FIXED] ${testCase.id} ${testCase.field} rejected: ${error.message}\n`,
    );
    return "rejected";
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const modulePath = path.resolve(
    args.candidateRoot,
    "scripts",
    "hosted-workload-contract.mjs",
  );
  const target = await import(pathToFileURL(modulePath).href);
  if (typeof target.validateRenderedWorkloads !== "function") {
    throw new Error("target does not export validateRenderedWorkloads");
  }
  const validate = target.validateRenderedWorkloads;
  process.stdout.write("[+] loaded scripts/hosted-workload-contract.mjs\n");

  validate(fixture());
  process.stdout.write("[+] baseline hardened service accepted\n");

  expectRejection(validate, "top-level privileged=true", (service) => {
    service.privileged = true;
  });
  expectRejection(validate, "top-level user=root", (service) => {
    service.user = "root";
  });
  expectRejection(validate, "top-level mutable image", (service) => {
    service.image = "registry.example/example/app:latest";
  });

  const testCases = [
    {
      id: "CAN-008",
      field: "post_start",
      primitive: "root + privileged hook command",
      mutate(service) {
        service.post_start = [
          {
            command: ["/bin/sh", "-c", "printf can008"],
            user: "root",
            privileged: true,
          },
        ];
      },
    },
    {
      id: "CAN-094",
      field: "pre_stop",
      primitive: "root + privileged hook command",
      mutate(service) {
        service.pre_stop = [
          {
            command: ["/bin/sh", "-c", "printf can094"],
            user: "0:0",
            privileged: true,
          },
        ];
      },
    },
    {
      id: "CAN-104",
      field: "pre_start",
      primitive: "attacker image + root + privileged init",
      mutate(service) {
        service.pre_start = [
          {
            image: `registry.invalid/attacker/init@sha256:${"b".repeat(64)}`,
            command: ["/bin/sh", "-c", "printf can104"],
            user: "root",
            privileged: true,
          },
        ];
      },
    },
  ];

  const results = testCases.map((testCase) => exercise(validate, testCase));
  const expected = args.expect === "vulnerable" ? "accepted" : "rejected";
  const matching = results.filter((result) => result === expected).length;
  if (matching !== CANONICAL_IDS.length) {
    throw new Error(
      `expected ${CANONICAL_IDS.length} lifecycle variants to be ${expected}, observed ${matching}`,
    );
  }
  process.stdout.write(
    `[+] result: ${matching}/${CANONICAL_IDS.length} lifecycle variants ${expected} as expected\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`[-] ${error.message}\n`);
  process.exitCode = 1;
});
