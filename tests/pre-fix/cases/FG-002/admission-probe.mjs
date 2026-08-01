#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const CASES = [
  ["CAN-004", "docker-socket-proxy"],
  ["CAN-005", "backup-scheduler"],
  ["CAN-006", "postgres"],
  ["CAN-075", "cadvisor"],
  ["CAN-076", "node-exporter"],
  ["CAN-077", "control-center"],
  ["CAN-078", "mariadb"],
  ["CAN-079", "redis"],
  ["CAN-080", "keycloak"],
  ["CAN-081", "nats"],
  ["CAN-082", "minio"],
  ["CAN-083", "php-apache"],
];

const args = parseArgs(process.argv.slice(2));
const expected = args.expect ?? "vulnerable";
if (!new Set(["vulnerable", "fixed"]).has(expected)) {
  fail("--expect must be either vulnerable or fixed");
}

const rawSourceRoot = args["source-root"] ?? process.env.SOURCE_ROOT ?? "";
if (!rawSourceRoot) fail("--source-root or SOURCE_ROOT is required");
const sourceRoot = path.resolve(rawSourceRoot);
const contractUrl = pathToFileURL(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs")).href;
const runtimeUrl = pathToFileURL(path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs")).href;

const { validateRenderedWorkloads } = await import(contractUrl);
const { evaluateRuntimeIsolation } = await import(runtimeUrl);

let vulnerable = 0;
let fixed = 0;
let partial = 0;

for (const [candidateId, sourceService] of CASES) {
  const admissionAccepted = admissionAccepts(validateRenderedWorkloads, sourceService);
  const runtimeAccepted = runtimeAccepts(evaluateRuntimeIsolation, sourceService);

  if (admissionAccepted && runtimeAccepted) {
    vulnerable += 1;
    console.log(`[VULNERABLE] ${candidateId} source=${sourceService} admission=accepted runtime=accepted`);
  } else if (!admissionAccepted && !runtimeAccepted) {
    fixed += 1;
    console.log(`[FIXED] ${candidateId} source=${sourceService} admission=rejected runtime=rejected`);
  } else {
    partial += 1;
    console.log(
      `[PARTIAL] ${candidateId} source=${sourceService} admission=${admissionAccepted ? "accepted" : "rejected"} runtime=${runtimeAccepted ? "accepted" : "rejected"}`,
    );
  }
}

console.log(`[+] summary vulnerable=${vulnerable} fixed=${fixed} partial=${partial} total=${CASES.length}`);
console.log("[+] no containers, sockets, volumes, or host files were accessed");

if (expected === "vulnerable" && vulnerable === CASES.length) process.exit(0);
if (expected === "fixed" && fixed === CASES.length) process.exit(0);
process.exit(1);

function admissionAccepts(validateRenderedWorkloads, sourceService) {
  const digest = "a".repeat(64);
  const platformServices = Object.fromEntries(
    CASES.map(([, name]) => [name, { image: `registry.example/platform/${name}@sha256:${digest}`, volumes: sourceVolumes(name) }]),
  );
  platformServices["project-router"] = {
    image: `registry.example/platform/router@sha256:${digest}`,
    networks: { platform_routing: null },
  };

  const core = {
    services: platformServices,
    networks: { platform_routing: { internal: true } },
  };
  const workload = {
    image: `registry.example/workloads/probe@sha256:${digest}`,
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
    networks: { probe_app_ingress: null },
    labels: {
      "com.platform.workload-id": "probe-app",
      "com.platform.workload-role": "web",
    },
    volumes_from: [sourceService],
  };
  const combined = structuredClone(core);
  combined.services["project-router"].networks.probe_app_ingress = null;
  combined.services["probe-app-web"] = workload;
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
    return true;
  } catch {
    return false;
  }
}

function runtimeAccepts(evaluateRuntimeIsolation, sourceService) {
  const config = runtimeFixture();
  config.services["probe-app-web"].volumes_from = [sourceService];
  return evaluateRuntimeIsolation(config).status === "passed";
}

function runtimeFixture() {
  const services = {};
  services["probe-app-web"] = bounded({
    read_only: true,
    user: "1000:1000",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    labels: { "com.platform.workload-id": "probe-app", "com.platform.workload-role": "web" },
    networks: { probe_app_ingress: null },
  });
  services["control-center"] = bounded({
    read_only: true,
    volumes: sourceVolumes("control-center"),
  });
  services["project-router"] = bounded({
    read_only: true,
    volumes: [
      { type: "bind", source: "/synthetic/projects", target: "/var/www/projects", read_only: true },
      { type: "bind", source: "/synthetic/state", target: "/var/www/project-state", read_only: true },
    ],
  });
  services["platform-alert-dispatcher"] = bounded({ read_only: true });
  services["backup-scheduler"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    environment: { DOCKER_HOST: "tcp://docker-socket-proxy:2375", DOCKER_API_VERSION: "1.51" },
    volumes: sourceVolumes("backup-scheduler"),
    networks: { platform_docker_control: null },
  });
  services["docker-socket-proxy"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    image: `registry.example/platform/socket-proxy@sha256:${"b".repeat(64)}`,
    environment: Object.fromEntries(
      ["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"].map((key) => [key, "0"]),
    ),
    ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
    volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
    networks: { platform_docker_control: null },
  });

  for (const [, name] of CASES) {
    if (!services[name]) services[name] = bounded({ volumes: sourceVolumes(name) });
  }
  services.cadvisor.volumes = sourceVolumes("cadvisor");
  services["node-exporter"].volumes = sourceVolumes("node-exporter");
  services.postgres.volumes = sourceVolumes("postgres");
  services.mariadb.volumes = sourceVolumes("mariadb");
  services.redis.volumes = sourceVolumes("redis");
  services.keycloak.volumes = sourceVolumes("keycloak");
  services.nats.volumes = sourceVolumes("nats");
  services.minio.volumes = sourceVolumes("minio");
  services["php-apache"].volumes = sourceVolumes("php-apache");

  return { services, networks: { platform_docker_control: { internal: true } } };
}

function sourceVolumes(name) {
  const volume = (source, target, readOnly = false) => ({ type: "volume", source, target, read_only: readOnly });
  const bind = (source, target, readOnly = false) => ({ type: "bind", source, target, read_only: readOnly });
  const byService = {
    "docker-socket-proxy": [bind("/var/run/docker.sock", "/var/run/docker.sock", true)],
    "backup-scheduler": [bind("/synthetic/backups", "/infra/backups")],
    postgres: [volume("enterprise_postgres_data", "/var/lib/postgresql")],
    cadvisor: [bind("/var/run", "/var/run", true)],
    "node-exporter": [bind("/", "/host", true)],
    "control-center": [bind("/synthetic/state", "/var/www/project-state")],
    mariadb: [volume("enterprise_mariadb_data", "/var/lib/mysql")],
    redis: [volume("enterprise_redis_data", "/data")],
    keycloak: [volume("enterprise_keycloak_data", "/opt/keycloak/data")],
    nats: [volume("enterprise_nats_data", "/data")],
    minio: [volume("enterprise_minio_data", "/data")],
    "php-apache": [bind("/synthetic/projects", "/var/www/projects")],
  };
  return byService[name] ?? [];
}

function bounded(overrides = {}) {
  return {
    image: `registry.example/platform/component@sha256:${"c".repeat(64)}`,
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

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) fail(`unexpected argument: ${value}`);
    const key = value.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith("--")) fail(`missing value for ${value}`);
    result[key] = next;
    index += 1;
  }
  return result;
}

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(2);
}
