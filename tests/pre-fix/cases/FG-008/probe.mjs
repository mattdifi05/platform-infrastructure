#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const digest = "a".repeat(64);
const EXPECTED_CASES = 4;

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
    services: [{ name: "example-app-worker", role: "worker", routes: [] }],
  };

  const core = {
    services: {
      traefik: {
        image: `registry.example/platform/traefik@sha256:${digest}`,
        configs: [
          {
            source: "enterprise_traefik_routes",
            target: "/etc/traefik/dynamic/routes.yml",
          },
        ],
        networks: { platform_routing: null },
      },
      postgres: {
        image: `registry.example/platform/postgres@sha256:${digest}`,
        secrets: [{ source: "postgres_superuser_password" }],
        volumes: [
          {
            type: "volume",
            source: "enterprise_postgres_data",
            target: "/var/lib/postgresql",
          },
        ],
        networks: { platform_postgres: null },
      },
      "docker-socket-proxy": {
        image: `registry.example/platform/socket-proxy@sha256:${digest}`,
        networks: { platform_docker_control: null },
      },
    },
    configs: {
      enterprise_traefik_routes: {
        content: "http:\n  routers:\n    enterprise-portal: {}\n",
      },
    },
    secrets: {
      postgres_superuser_password: {
        file: "./secrets/postgres_superuser_password.txt",
      },
    },
    volumes: {
      enterprise_postgres_data: { name: "enterprise_postgres_data" },
    },
    networks: {
      platform_routing: {
        name: "platform_infra_vps_routing",
        internal: true,
      },
      platform_postgres: {
        name: "platform_infra_vps_postgres",
        internal: true,
      },
      platform_docker_control: {
        name: "platform_infra_vps_docker_control",
        internal: true,
      },
    },
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
    logging: {
      driver: "local",
      options: { "max-size": "10m", "max-file": "3" },
    },
    healthcheck: { test: ["CMD", "node", "healthcheck.mjs"] },
    networks: { example_app_bus: null },
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "worker",
    },
  };

  const combined = structuredClone(core);
  combined.services["example-app-worker"] = workloadService;
  combined.networks.example_app_bus = {
    internal: true,
    name: "platform_test_example_app_bus",
  };
  return {
    core,
    combined,
    lock: { projectName: "platform_test", workloads: [manifest] },
  };
}

function expectReferenceRejection(validate, testCase) {
  const input = fixture();
  testCase.mutateReference(input.combined);
  try {
    validate(input);
  } catch (error) {
    process.stdout.write(
      `[+] control ${testCase.id} changed service reference rejected: ${error.message}\n`,
    );
    return;
  }
  throw new Error(`${testCase.id} changed service reference was unexpectedly accepted`);
}

function exerciseDefinitionReplacement(validate, testCase) {
  const input = fixture();
  testCase.mutateDefinition(input.combined);
  try {
    validate(input);
    process.stdout.write(
      `[VULNERABLE] ${testCase.id} ${testCase.resource} replacement accepted (${testCase.detail})\n`,
    );
    return "accepted";
  } catch (error) {
    process.stdout.write(
      `[FIXED] ${testCase.id} ${testCase.resource} replacement rejected: ${error.message}\n`,
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
  validate(fixture());
  process.stdout.write("[+] baseline protected core resources accepted\n");

  const testCases = [
    {
      id: "CAN-114",
      resource: "configs.enterprise_traefik_routes",
      detail: "routing content source changed",
      mutateReference(combined) {
        combined.services.traefik.configs[0].source = "attacker_routes";
      },
      mutateDefinition(combined) {
        combined.configs.enterprise_traefik_routes = {
          file: "./workloads/example-app/synthetic-routes.yml",
        };
      },
    },
    {
      id: "CAN-115",
      resource: "secrets.postgres_superuser_password",
      detail: "credential file source changed",
      mutateReference(combined) {
        combined.services.postgres.secrets[0].source = "attacker_secret";
      },
      mutateDefinition(combined) {
        combined.secrets.postgres_superuser_password = {
          file: "./workloads/example-app/synthetic-password.txt",
        };
      },
    },
    {
      id: "CAN-116",
      resource: "volumes.enterprise_postgres_data",
      detail: "engine volume identity changed",
      mutateReference(combined) {
        combined.services.postgres.volumes[0].source = "attacker_postgres_data";
      },
      mutateDefinition(combined) {
        combined.volumes.enterprise_postgres_data = {
          external: true,
          name: "attacker_postgres_data",
        };
      },
    },
    {
      id: "CAN-117",
      resource: "networks.platform_docker_control",
      detail: "internal trust zone redirected to external network",
      mutateReference(combined) {
        combined.services["docker-socket-proxy"].networks = {
          attacker_zone: null,
        };
      },
      mutateDefinition(combined) {
        combined.networks.platform_docker_control = {
          external: true,
          name: "attacker_zone",
        };
      },
    },
  ];

  for (const testCase of testCases) {
    expectReferenceRejection(validate, testCase);
  }
  const results = testCases.map((testCase) =>
    exerciseDefinitionReplacement(validate, testCase),
  );
  const expected = args.expect === "vulnerable" ? "accepted" : "rejected";
  const matching = results.filter((result) => result === expected).length;
  if (matching !== EXPECTED_CASES) {
    throw new Error(
      `expected ${EXPECTED_CASES} protected-resource replacements to be ${expected}, observed ${matching}`,
    );
  }
  process.stdout.write(
    `[+] result: ${matching}/${EXPECTED_CASES} protected-resource replacements ${expected} as expected\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`[-] ${error.message}\n`);
  process.exitCode = 1;
});
