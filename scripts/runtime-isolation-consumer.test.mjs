#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

const source = fs.readFileSync(path.join(import.meta.dirname, "infra-ops.mjs"), "utf8");
const start = source.indexOf("async function runtimeIsolationCheck()");
const end = source.indexOf("\nasync function faultInjectionTests()", start);

assert.notEqual(start, -1, "runtimeIsolationCheck() is missing");
assert.notEqual(end, -1, "runtimeIsolationCheck() boundary is missing");

const runtimeIsolationConsumer = source.slice(start, end);
const composeVpsSource = fs.readFileSync(path.join(import.meta.dirname, "compose-vps.sh"), "utf8");
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const canonicalNoHostedLockPath = path.join(repositoryRoot, "config", "no-hosted-workloads.lock.json");
const protectedKinds = ["configs", "networks", "secrets", "services", "volumes"];
const expectedCoreInventory = {
  configs: ["enterprise_traefik_routes"],
  networks: [
    "enterprise_net",
    "platform_bus",
    "platform_cache",
    "platform_db_admin",
    "platform_docker_control",
    "platform_edge",
    "platform_egress",
    "platform_observability",
    "platform_postgres",
    "platform_routing",
    "platform_storage",
  ],
  secrets: [
    "alertmanager_webhook_token",
    "backup_signing_keys",
    "control_center_database_url",
    "control_center_vault_keys",
    "grafana_admin_password",
    "keycloak_admin_password",
    "keycloak_db_password",
    "mariadb_root_password",
    "minio_root_password",
    "nats_password",
    "phpmyadmin_control_password",
    "postgres_superuser_password",
    "projects_gateway_signing_keys",
    "redis_password",
    "smtp_password",
  ],
  services: [
    "alertmanager",
    "backup-scheduler",
    "cadvisor",
    "control-center",
    "docker-socket-proxy",
    "grafana",
    "keycloak",
    "local-dns",
    "local-registry",
    "loki",
    "mariadb",
    "minio",
    "nats",
    "node-exporter",
    "phpmyadmin",
    "phppgadmin",
    "platform-alert-dispatcher",
    "postgres",
    "project-router",
    "prometheus",
    "promtail",
    "redis",
    "traefik",
    "waf",
  ],
  volumes: [
    "backup_scheduler_logs",
    "enterprise_alertmanager_data",
    "enterprise_grafana_data",
    "enterprise_keycloak_data",
    "enterprise_local_registry_data",
    "enterprise_loki_data",
    "enterprise_mariadb_data",
    "enterprise_minio_data",
    "enterprise_nats_data",
    "enterprise_postgres_data",
    "enterprise_prometheus_data",
    "enterprise_redis_data",
  ],
};

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function cleanEnvironment(overrides = {}) {
  const environment = { ...process.env };
  for (const key of [
    "COMPOSE_ENV_FILE",
    "COMPOSE_PROJECT_NAME",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "HOSTED_WORKLOAD_ALLOW_RESOLVED",
    "HOSTED_WORKLOAD_LOCK",
    "HOSTED_WORKLOAD_MODE",
    "HOSTED_WORKLOAD_PREPARE_RESOLVED",
    "HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE",
    "PLATFORM_RUNTIME_CANDIDATE_ID",
    "PLATFORM_RUNTIME_COMMIT",
    "PLATFORM_RUNTIME_DEPLOYMENT_ID",
    "PLATFORM_RUNTIME_SOURCE_RENDER_SHA256",
    "PLATFORM_RUNTIME_TREE",
    "PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256",
    "QA6_ACTIVATION_BUNDLE_FILE",
    "QA6_DOCKER_ENV_CAPTURE",
    "QA6_DOCKER_MARKER",
    "QA6_DOCKER_OUTPUT_FILE",
    "QA6_SWAP_ENV_REPLACEMENT",
    "QA6_SWAP_ENV_TARGET",
    "QA6_SWAP_LOCK_REPLACEMENT",
    "QA6_SWAP_LOCK_TARGET",
  ]) {
    delete environment[key];
  }
  return { ...environment, ...overrides };
}

function writeExecutable(filePath, body) {
  fs.writeFileSync(filePath, body, { mode: 0o755 });
}

function copyRepositoryFile(root, relativePath) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(path.join(repositoryRoot, relativePath), target);
  return target;
}

function createConsumerSandbox() {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "runtime-consumer-qa6-")));
  const scripts = path.join(root, "scripts");
  const configDirectory = path.join(root, "config");
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(scripts, { recursive: true });
  fs.mkdirSync(configDirectory, { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  const composeVps = copyRepositoryFile(root, "scripts/compose-vps.sh");
  fs.chmodSync(composeVps, 0o755);
  const canonicalLock = copyRepositoryFile(root, "config/no-hosted-workloads.lock.json");
  const inventory = structuredClone(expectedCoreInventory);
  const trustedEnvironmentBytes =
    "HOSTED_WORKLOAD_LOCK=\nHOSTED_WORKLOAD_MODE=no-hosted\nCORE_VALUE=trusted\n";
  const environmentFile = path.join(root, "core.env");
  fs.writeFileSync(environmentFile, trustedEnvironmentBytes, { mode: 0o600 });
  fs.writeFileSync(path.join(root, ".env.vps.example"), trustedEnvironmentBytes, { mode: 0o600 });
  const workloadLock = path.join(root, "hosted.lock.json");
  fs.writeFileSync(workloadLock, "{}\n", { mode: 0o600 });
  const activationBundleFile = path.join(root, "activation-bundle.json");
  const dockerOutputFile = path.join(root, "docker-output.json");
  const dockerMarker = path.join(root, "docker-called");
  const dockerEnvironmentCapture = path.join(root, "docker-env.txt");
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
if [ -n "\${QA6_SWAP_LOCK_REPLACEMENT:-}" ]; then
  /bin/mv "$QA6_SWAP_LOCK_REPLACEMENT" "$QA6_SWAP_LOCK_TARGET"
fi
if [ -n "\${QA6_SWAP_ENV_REPLACEMENT:-}" ]; then
  /bin/mv "$QA6_SWAP_ENV_REPLACEMENT" "$QA6_SWAP_ENV_TARGET"
fi
: > "$QA6_DOCKER_MARKER"
expect_env=0
for argument in "$@"; do
  if [ "$expect_env" = 1 ]; then
    /bin/cat "$argument" > "$QA6_DOCKER_ENV_CAPTURE"
    expect_env=0
  elif [ "$argument" = "--env-file" ]; then
    expect_env=1
  fi
done
/bin/cat "$QA6_DOCKER_OUTPUT_FILE"
`);
  writeExecutable(path.join(scripts, "hosted-workload-lock.sh"), `#!/bin/sh
set -eu
case "\${2:-}" in
  activation-bundle) /bin/cat "$QA6_ACTIVATION_BUNDLE_FILE" ;;
  verify) exit 0 ;;
  *) exit 64 ;;
esac
`);
  const environment = cleanEnvironment({
    PATH: `${fakeBin}:${process.env.PATH}`,
    COMPOSE_ENV_FILE: environmentFile,
    COMPOSE_PROJECT_NAME: "platform_infra_vps",
    HOSTED_WORKLOAD_LOCK: "",
    HOSTED_WORKLOAD_MODE: "no-hosted",
    HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: "",
    QA6_ACTIVATION_BUNDLE_FILE: activationBundleFile,
    QA6_DOCKER_ENV_CAPTURE: dockerEnvironmentCapture,
    QA6_DOCKER_MARKER: dockerMarker,
    QA6_DOCKER_OUTPUT_FILE: dockerOutputFile,
  });
  return {
    root,
    scripts,
    composeVps,
    canonicalLock,
    inventory,
    environmentFile,
    workloadLock,
    activationBundleFile,
    dockerOutputFile,
    dockerMarker,
    dockerEnvironmentCapture,
    environment,
  };
}

function addInfraConsumer(sandbox) {
  for (const relativePath of [
    "scripts/infra-ops.mjs",
    "scripts/network-segmentation-policy.mjs",
    "scripts/runtime-isolation-policy.mjs",
    "scripts/supply-chain-policy.mjs",
    "scripts/functional-health.mjs",
    "scripts/runtime-fingerprint.mjs",
    "scripts/provider-evidence-auth.mjs",
    "scripts/github-governance-policy.mjs",
    "scripts/release-trust.mjs",
    "control-center/backup/contracts.mjs",
  ]) {
    copyRepositoryFile(sandbox.root, relativePath);
  }
  sandbox.infraOps = path.join(sandbox.scripts, "infra-ops.mjs");
  return sandbox;
}

function removeSandbox(sandbox) {
  fs.rmSync(sandbox.root, { recursive: true, force: true });
}

function runWrapper(sandbox, arguments_ = ["runtime-isolation-envelope"], overrides = {}) {
  return spawnSync("/bin/bash", [sandbox.composeVps, ...arguments_], {
    encoding: "utf8",
    env: cleanEnvironment({ ...sandbox.environment, ...overrides }),
  });
}

function runInfraConsumer(sandbox, extraArguments = []) {
  return runInfraArguments(sandbox, [
    "--env-file",
    sandbox.environmentFile,
    ...extraArguments,
  ]);
}

function runInfraArguments(sandbox, arguments_) {
  return spawnSync(process.execPath, [
    "--",
    sandbox.infraOps,
    "runtime-isolation-check",
    ...arguments_,
  ], {
    encoding: "utf8",
    env: cleanEnvironment(sandbox.environment),
  });
}

function boundedService(overrides = {}) {
  return {
    cpus: 0.5,
    cpu_shares: 256,
    mem_limit: 128 * 1024 * 1024,
    memswap_limit: 128 * 1024 * 1024,
    mem_reservation: 32 * 1024 * 1024,
    pids_limit: 128,
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    blkio_config: { weight: 300 },
    restart: "no",
    healthcheck: { test: ["CMD", "true"] },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    read_only: true,
    ...overrides,
  };
}

function coreRuntimeConfig(inventory, { hosted = false } = {}) {
  const fromNames = (names, definition) =>
    Object.fromEntries(names.map((name) => [name, definition(name)]));
  const config = {
    name: "platform_infra_vps",
    configs: fromNames(inventory.configs, () => ({ file: "/fixture/config" })),
    networks: fromNames(inventory.networks, () => ({ internal: true })),
    secrets: fromNames(inventory.secrets, (name) => ({ external: true, name: `platform_infra_vps_${name}` })),
    services: fromNames(inventory.services, () => boundedService()),
    volumes: fromNames(inventory.volumes, (name) => ({ name: `platform_infra_vps_${name}` })),
  };
  config.services["control-center"] = boundedService({ read_only: true, cpu_shares: 1024 });
  config.services["project-router"] = boundedService({
    volumes: [
      { type: "bind", source: "/srv/apps", target: "/var/www/projects", read_only: true },
      { type: "bind", source: "/srv/state", target: "/var/www/project-state", read_only: true },
    ],
  });
  config.services["platform-alert-dispatcher"] = boundedService();
  config.services["backup-scheduler"] = boundedService({
    cpu_shares: 1024,
    environment: {
      DOCKER_HOST: "tcp://docker-socket-proxy:2375",
      DOCKER_API_VERSION: "1.51",
    },
    networks: { platform_docker_control: null },
  });
  config.services["docker-socket-proxy"] = boundedService({
    cpu_shares: 1024,
    image: `ghcr.io/tecnativa/docker-socket-proxy:v0.4.2@sha256:${"a".repeat(64)}`,
    environment: Object.fromEntries(
      ["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"]
        .map((key) => [key, "0"]),
    ),
    ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
    volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
    networks: { platform_docker_control: null },
  });
  config.services.postgres = boundedService();
  config.networks.platform_docker_control = { internal: true };
  if (hosted) {
    config.services["example-app-web"] = boundedService({
      image: `example.invalid/example-app@sha256:${"a".repeat(64)}`,
      user: "1000:1000",
      init: true,
      logging: { driver: "local", options: { "max-size": "10m", "max-file": "3" } },
      security_opt: ["no-new-privileges:true"],
      cap_drop: ["ALL"],
      labels: {
        "com.platform.workload-id": "example-app",
        "com.platform.workload-role": "web",
      },
      networks: { example_app_ingress: null },
    });
    config.networks.example_app_ingress = {
      internal: true,
      name: "platform_infra_vps_example_app_ingress",
    };
  }
  return config;
}

function hostileCoreService(overrides = {}) {
  return boundedService({
    image: `attacker.invalid/hostile@sha256:${"f".repeat(64)}`,
    privileged: true,
    pid: "host",
    network_mode: "host",
    cap_add: ["SYS_ADMIN"],
    devices: ["/dev/null:/dev/qa7"],
    volumes: [{ type: "bind", source: "/", target: "/host" }],
    ...overrides,
  });
}

function coreAuthorityConfig() {
  const config = coreRuntimeConfig(expectedCoreInventory);
  for (const [serviceName, definition] of Object.entries(config.services)) {
    definition.image ||= `trusted.invalid/${serviceName}@sha256:${sha256(serviceName)}`;
  }
  return config;
}

function writeDockerOutput(sandbox, documents) {
  fs.writeFileSync(sandbox.dockerOutputFile, documents);
}

function installCountingRenderer(sandbox) {
  const renderCountFile = path.join(sandbox.root, "docker-render-count");
  fs.writeFileSync(renderCountFile, "0\n", { mode: 0o600 });
  writeExecutable(path.join(sandbox.root, "bin", "docker"), `#!/bin/sh
set -eu
count=0
if [ -f "$QA7_RENDER_COUNT_FILE" ]; then
  IFS= read -r count < "$QA7_RENDER_COUNT_FILE"
fi
count=$((count + 1))
printf '%s\\n' "$count" > "$QA7_RENDER_COUNT_FILE"
/bin/cat "$QA6_DOCKER_OUTPUT_FILE"
`);
  sandbox.environment.QA7_RENDER_COUNT_FILE = renderCountFile;
  return {
    count() {
      return Number.parseInt(fs.readFileSync(renderCountFile, "utf8").trim(), 10);
    },
    reset() {
      fs.writeFileSync(renderCountFile, "0\n", { mode: 0o600 });
    },
  };
}

function runCoreStackNoHostedScenario(config) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "core-stack-no-hosted-qa7-")));
  const fakeBin = path.join(root, "bin");
  const stateDirectory = path.join(root, "state");
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(stateDirectory);
  const gate = copyRepositoryFile(root, "scripts/core-stack-activation-gate.sh");
  const composeVps = copyRepositoryFile(root, "scripts/compose-vps.sh");
  copyRepositoryFile(root, "config/no-hosted-workloads.lock.json");
  fs.chmodSync(gate, 0o755);
  fs.chmodSync(composeVps, 0o755);

  const modelPath = path.join(root, "candidate-render.json");
  fs.writeFileSync(modelPath, `${JSON.stringify(config)}\n`, { mode: 0o600 });
  const extensionServices = new Set([
    "project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus",
  ]);
  const mutableServices = Object.keys(config.services)
    .filter((serviceName) => !extensionServices.has(serviceName))
    .sort();
  const idsPath = path.join(root, "container-ids");
  fs.writeFileSync(idsPath, `${mutableServices.map((serviceName) => `cid-${serviceName}`).join("\n")}\n`);
  const inspections = mutableServices.map((serviceName) => ({
    Config: {
      Labels: {
        "com.docker.compose.project": "platform_infra_vps",
        "com.docker.compose.service": serviceName,
      },
      Image: config.services[serviceName].image,
    },
    State: { Running: true },
  }));
  const inspectPath = path.join(root, "inspect.json");
  fs.writeFileSync(inspectPath, `${JSON.stringify(inspections)}\n`, { mode: 0o600 });

  writeExecutable(path.join(root, "scripts", "platform-activation-state.mjs"), `#!/usr/bin/env node
const expected = ["read", process.env.PLATFORM_ACTIVATION_STATE_DIR, "journal.json"];
if (JSON.stringify(process.argv.slice(2)) !== JSON.stringify(expected)) process.exit(64);
process.stdout.write(JSON.stringify({
  version: 2,
  state: "pending",
  transactionId: process.env.PLATFORM_ACTIVATION_TRANSACTION_ID,
  projectName: "platform_infra_vps",
  phase: "intent"
}));
`);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/bin/sh
set -eu
shift
exec "$@"
`);
  const engineLog = path.join(root, "fake-engine.log");
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$QA7_ENGINE_LOG"
if [ "\${1:-}" = "compose" ]; then
  /bin/cat "$QA7_RENDER_MODEL"
  exit 0
fi
if [ "\${1:-}" = "--host" ] && [ "\${3:-}" = "info" ]; then
  printf '%s\\n' "daemon-qa7"
  exit 0
fi
if [ "\${1:-}" = "--host" ] && [ "\${3:-}" = "compose" ]; then
  case " $* " in
    *" create "*) exit 0 ;;
    *" ps -aq "*)
      /bin/cat "$QA7_CONTAINER_IDS"
      exit 0
      ;;
  esac
fi
if [ "\${1:-}" = "--host" ] && [ "\${3:-}" = "start" ]; then
  exit 0
fi
if [ "\${1:-}" = "--host" ] && [ "\${3:-}" = "inspect" ]; then
  /bin/cat "$QA7_INSPECT_MODEL"
  exit 0
fi
printf '%s\\n' "UNEXPECTED_DOCKER_CALL $*" >> "$QA7_ENGINE_LOG"
exit 97
`);

  const environmentFile = path.join(root, "core.env");
  fs.writeFileSync(environmentFile, "CORE_VALUE=trusted\n", { mode: 0o600 });
  const result = spawnSync("/bin/bash", [
    gate,
    "--project-name", "platform_infra_vps",
    "--env-file", environmentFile,
    "--no-hosted-workloads",
    "--action", "activate",
    "--confirm", "ACTIVATE-CORE-STACK",
  ], {
    cwd: root,
    env: cleanEnvironment({
      PATH: `${fakeBin}:${process.env.PATH}`,
      PLATFORM_ACTIVATION_TRANSACTION_ID: "a".repeat(64),
      PLATFORM_ACTIVATION_EXPECTED_DAEMON_ID: "daemon-qa7",
      PLATFORM_ACTIVATION_STATE_DIR: stateDirectory,
      QA7_CONTAINER_IDS: idsPath,
      QA7_ENGINE_LOG: engineLog,
      QA7_INSPECT_MODEL: inspectPath,
      QA7_RENDER_MODEL: modelPath,
      TMPDIR: root,
    }),
    encoding: "utf8",
    timeout: 30_000,
  });
  const log = fs.existsSync(engineLog) ? fs.readFileSync(engineLog, "utf8") : "";
  return { root, result, log };
}

function activationBundle(sandbox, protectedResourceNames, combinedRenderBytes) {
  const coreEnvironmentPath = fs.realpathSync.native(sandbox.environmentFile);
  const stat = fs.statSync(coreEnvironmentPath);
  return {
    version: 2,
    lockSha256: sha256(fs.readFileSync(sandbox.workloadLock)),
    coreRenderSha256: "c".repeat(64),
    combinedRenderSha256: sha256(combinedRenderBytes),
    coreEnvFile: coreEnvironmentPath,
    coreEnvironmentRecord: {
      path: coreEnvironmentPath,
      sha256: sha256(fs.readFileSync(coreEnvironmentPath)),
      device: String(stat.dev),
      inode: String(stat.ino),
      uid: String(stat.uid),
      mode: stat.mode & 0o777,
    },
    projectName: "platform_infra_vps",
    workloadIds: ["example-app"],
    protectedNetworkNames: protectedResourceNames.networks,
    protectedResourceNames,
    networkRecords: [{
      workloadId: "example-app",
      logicalName: "example_app_ingress",
      physicalName: "platform_infra_vps_example_app_ingress",
    }],
    serviceRecords: [{ workloadId: "example-app", serviceName: "example-app-web" }],
    routeRecords: [],
    platformExtensionRecords: [],
    environmentRecords: [],
    composeRecords: [],
  };
}

function writeActivationBundle(sandbox, bundle) {
  fs.writeFileSync(sandbox.activationBundleFile, `${JSON.stringify(bundle)}\n`, { mode: 0o600 });
}

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
    "runtime-isolation-check derives protected-resource authority from the rendered config",
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

test("VPS wrapper derives a core-only envelope only in explicit canonical no-hosted mode", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-envelope-no-hosted-"));
  try {
    const envFile = path.join(root, "core.env");
    const fakeBin = path.join(root, "bin");
    const marker = path.join(root, "docker.args");
    const config = coreRuntimeConfig(expectedCoreInventory);
    fs.writeFileSync(envFile, "CORE_VALUE=fixture\n");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\n' "$*" > "$RUNTIME_ENVELOPE_DOCKER_MARKER"
printf '%s\n' "$RUNTIME_ENVELOPE_CONFIG"
`, { mode: 0o755 });
    const commonEnvironment = {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      COMPOSE_ENV_FILE: envFile,
      COMPOSE_PROJECT_NAME: "platform_infra_vps",
      HOSTED_WORKLOAD_LOCK: "",
      HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: "",
      RUNTIME_ENVELOPE_DOCKER_MARKER: marker,
      RUNTIME_ENVELOPE_CONFIG: JSON.stringify(config),
    };
    const implicit = spawnSync("/bin/bash", [
      path.join(import.meta.dirname, "compose-vps.sh"),
      "runtime-isolation-envelope",
    ], {
      encoding: "utf8",
      env: { ...commonEnvironment, HOSTED_WORKLOAD_MODE: "" },
    });
    assert.notEqual(implicit.status, 0);
    assert.match(implicit.stderr, /explicit HOSTED_WORKLOAD_MODE=no-hosted/);
    assert.equal(fs.existsSync(marker), false);

    const explicit = spawnSync("/bin/bash", [
      path.join(import.meta.dirname, "compose-vps.sh"),
      "runtime-isolation-envelope",
    ], {
      encoding: "utf8",
      env: { ...commonEnvironment, HOSTED_WORKLOAD_MODE: "no-hosted" },
    });
    assert.equal(explicit.status, 0, explicit.stderr);
    const envelope = JSON.parse(explicit.stdout);
    assert.deepEqual(Object.keys(envelope).sort(), [
      "config", "lockSha256", "projectName", "protectedResourceNames", "version",
    ]);
    assert.equal(envelope.version, 1);
    assert.equal(envelope.projectName, "platform_infra_vps");
    assert.deepEqual(envelope.config, config);
    assert.deepEqual(envelope.protectedResourceNames, expectedCoreInventory);
    const canonicalNoHostedLock = path.join(import.meta.dirname, "..", "config", "no-hosted-workloads.lock.json");
    assert.equal(
      envelope.lockSha256,
      crypto.createHash("sha256").update(fs.readFileSync(canonicalNoHostedLock)).digest("hex"),
    );
    assert.match(fs.readFileSync(marker, "utf8"), /--profile backup config --format json/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("QA6 Hosted envelope binds the exact descriptor render digest before runtime policy", () => {
  const sandbox = addInfraConsumer(createConsumerSandbox());
  try {
    const protectedResourceNames = structuredClone(expectedCoreInventory);
    const configA = coreRuntimeConfig(protectedResourceNames, { hosted: true });
    const configB = structuredClone(configA);
    configB.services["example-app-web"].image =
      `example.invalid/example-app@sha256:${"b".repeat(64)}`;
    const reorderedConfig = {
      volumes: configA.volumes,
      services: configA.services,
      secrets: configA.secrets,
      networks: configA.networks,
      configs: configA.configs,
      name: configA.name,
    };
    assert.deepEqual(reorderedConfig, configA);
    for (const [label, config] of [
      ["baseline", configA],
      ["image mutation", configB],
      ["semantic-equivalent byte mutation", reorderedConfig],
    ]) {
      const policy = evaluateRuntimeIsolation(config, {
        projectName: "platform_infra_vps",
        protectedResourceNames,
        protectedNetworkNames: protectedResourceNames.networks,
      });
      assert.equal(policy.status, "passed", `${label} must remain policy-valid: ${policy.failures.join("\n")}`);
    }
    const baselineBytes = `${JSON.stringify(configA)}\n`;
    fs.writeFileSync(
      sandbox.environmentFile,
      `HOSTED_WORKLOAD_LOCK=${sandbox.workloadLock}\nHOSTED_WORKLOAD_MODE=hosted\nCORE_VALUE=trusted\n`,
      { mode: 0o600 },
    );
    writeActivationBundle(
      sandbox,
      activationBundle(sandbox, protectedResourceNames, baselineBytes),
    );
    writeDockerOutput(sandbox, baselineBytes);
    const baseline = runInfraConsumer(sandbox);
    assert.equal(baseline.status, 0, baseline.stderr);

    const acceptedMutations = [];
    for (const [label, bytes] of [
      ["image mutation", `${JSON.stringify(configB)}\n`],
      ["semantic-equivalent whitespace/key-order mutation", `${JSON.stringify(reorderedConfig, null, 2)}\n`],
    ]) {
      assert.notEqual(bytes, baselineBytes, `${label} did not alter renderer bytes`);
      writeDockerOutput(sandbox, bytes);
      const substituted = runInfraConsumer(sandbox);
      if (substituted.status === 0) acceptedMutations.push(label);
    }
    assert.deepEqual(
      acceptedMutations,
      [],
      `combinedRenderSha256 accepted renderer substitutions: ${acceptedMutations.join(", ")}`,
    );
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA6 wrapper accepts exactly one JSON object and consumes that exact object", () => {
  const sandbox = createConsumerSandbox();
  try {
    const config = coreRuntimeConfig(sandbox.inventory);
    const baselineDocument = `${JSON.stringify(config)}\n`;
    writeDockerOutput(sandbox, baselineDocument);
    const baseline = runWrapper(sandbox);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.deepEqual(JSON.parse(baseline.stdout).config, config);

    const invalidStreams = new Map([
      ["zero documents", ""],
      ["two objects", `${JSON.stringify(config)}\n{}\n`],
      ["leading object", `{}\n${JSON.stringify(config)}\n`],
      ["leading scalar", `0\n${JSON.stringify(config)}\n`],
      ["trailing scalar", `${JSON.stringify(config)}\n0\n`],
      ["leading null", `null\n${JSON.stringify(config)}\n`],
      ["trailing array", `${JSON.stringify(config)}\n[]\n`],
    ]);
    const accepted = [];
    for (const [label, stream] of invalidStreams) {
      writeDockerOutput(sandbox, stream);
      const result = runWrapper(sandbox);
      if (result.status === 0) accepted.push(label);
    }
    assert.deepEqual(accepted, [], `wrapper accepted non-singleton JSON streams: ${accepted.join(", ")}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted compose-config validates and forwards one exact renderer byte stream", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    const config = coreAuthorityConfig();
    const baselineBytes = `${JSON.stringify(config, null, 2)}\n`;
    writeDockerOutput(sandbox, baselineBytes);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1, "baseline no-hosted config rendered more than once");
    assert.equal(baseline.stdout, baselineBytes, "validated no-hosted config bytes were not forwarded exactly");
    assert.equal(sha256(baseline.stdout), sha256(baselineBytes));
    const forwarded = JSON.parse(baseline.stdout);
    for (const kind of protectedKinds) {
      assert.deepEqual(
        Object.keys(forwarded[kind]).sort(),
        expectedCoreInventory[kind],
        `baseline ${kind} differs from canonical no-hosted authority`,
      );
    }

    const invalidStreams = new Map([
      ["zero documents", ""],
      ["two objects", `${JSON.stringify(config)}\n{}\n`],
      ["leading scalar", `0\n${JSON.stringify(config)}\n`],
      ["trailing scalar", `${JSON.stringify(config)}\n0\n`],
    ]);
    const accepted = [];
    for (const [label, bytes] of invalidStreams) {
      renderer.reset();
      writeDockerOutput(sandbox, bytes);
      const result = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second no-hosted render`);
      if (result.status === 0 || result.stdout.length > 0) {
        accepted.push({ label, status: result.status, stdoutBytes: result.stdout.length });
      }
    }
    assert.deepEqual(accepted, [], `no-hosted config accepted non-singleton JSON streams: ${JSON.stringify(accepted)}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted compose-config rejects extra and same-name hostile core authority", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    const extraService = coreAuthorityConfig();
    extraService.services["attacker-daemon"] = hostileCoreService();
    const sameNameMutation = coreAuthorityConfig();
    sameNameMutation.services.alertmanager = hostileCoreService({
      image: sameNameMutation.services.alertmanager.image,
    });
    assert.deepEqual(
      Object.keys(sameNameMutation.services).sort(),
      expectedCoreInventory.services,
      "same-name hostile fixture accidentally changed service inventory",
    );

    const accepted = [];
    for (const [label, config] of [
      ["extra attacker-daemon", extraService],
      ["same-name alertmanager mutation", sameNameMutation],
    ]) {
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const result = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second no-hosted render`);
      if (result.status === 0 || result.stdout.length > 0) {
        accepted.push({ label, status: result.status, stdoutBytes: result.stdout.length });
      } else {
        assert.match(
          result.stderr,
          /no-hosted|semantic|runtime|isolation|inventory|authority|resource|mismatch|forbidden/i,
          `${label} failed for an unrelated reason:\n${result.stderr}`,
        );
      }
    }
    assert.deepEqual(accepted, [], `no-hosted config forwarded hostile authority: ${JSON.stringify(accepted)}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 core activation rejects hostile no-hosted renders before create and start", () => {
  const extraService = coreAuthorityConfig();
  extraService.services["attacker-daemon"] = hostileCoreService();
  const sameNameMutation = coreAuthorityConfig();
  sameNameMutation.services.alertmanager = hostileCoreService({
    image: sameNameMutation.services.alertmanager.image,
  });
  const violations = [];
  for (const [label, config] of [
    ["extra attacker-daemon", extraService],
    ["same-name alertmanager mutation", sameNameMutation],
  ]) {
    const scenario = runCoreStackNoHostedScenario(config);
    try {
      const trace = scenario.log.trim().split("\n").filter(Boolean);
      const renderCalls = trace.filter((line) =>
        line.startsWith("compose ") && line.endsWith(" config --format json"));
      const createCalls = trace.filter((line) => /(?:^| )create(?: |$)/.test(line));
      const startCalls = trace.filter((line) =>
        /^--host unix:\/\/\/var\/run\/docker\.sock start(?: |$)/.test(line));
      assert.equal(renderCalls.length, 1, `${label} did not acquire exactly one renderer stream:\n${scenario.log}`);
      if (scenario.result.status === 0 || createCalls.length > 0 || startCalls.length > 0
          || /Core activation gate completed/.test(scenario.result.stdout)) {
        violations.push({
          label,
          status: scenario.result.status,
          createCalls,
          startCalls,
          completed: /Core activation gate completed/.test(scenario.result.stdout),
        });
      } else {
        assert.match(
          scenario.result.stderr,
          /no-hosted|semantic|runtime|isolation|inventory|authority|resource|mismatch|forbidden/i,
          `${label} was stopped for an unrelated reason:\n${scenario.result.stderr}`,
        );
      }
    } finally {
      fs.rmSync(scenario.root, { recursive: true, force: true });
    }
  }
  assert.deepEqual(
    violations,
    [],
    `hostile no-hosted render reached a core mutation sink: ${JSON.stringify(violations)}`,
  );
});

test("QA6 canonical no-hosted lock contains the exact authoritative core inventory", () => {
  const lock = JSON.parse(fs.readFileSync(canonicalNoHostedLockPath, "utf8"));
  assert.deepEqual(Object.keys(lock).sort(), [
    "brokerPolicySha256",
    "projectName",
    "protectedResourceNames",
    "routes",
    "state",
    "validatorVersion",
    "version",
    "workloads",
  ]);
  assert.equal(lock.projectName, "platform_infra_vps");
  assert.deepEqual(Object.keys(lock.protectedResourceNames).sort(), protectedKinds);
  assert.deepEqual(lock.protectedResourceNames, expectedCoreInventory);
  assert.deepEqual(
    Object.fromEntries(protectedKinds.map((kind) => [kind, lock.protectedResourceNames[kind].length])),
    { configs: 1, networks: 11, secrets: 15, services: 24, volumes: 12 },
  );
  assert.equal(lock.protectedResourceNames.services.includes("php-apache"), false);
  for (const kind of protectedKinds) {
    const names = lock.protectedResourceNames[kind];
    assert.deepEqual(names, [...new Set(names)].sort(), `${kind} inventory is not sorted/unique`);
  }
});

test("QA6 no-hosted exact inventory baseline passes end-to-end", () => {
  const sandbox = addInfraConsumer(createConsumerSandbox());
  try {
    const config = coreRuntimeConfig(expectedCoreInventory);
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
    const result = runInfraConsumer(sandbox);
    assert.equal(result.status, 0, result.stderr);
    const envelope = JSON.parse(
      runWrapper(sandbox).stdout,
    );
    assert.deepEqual(envelope.protectedResourceNames, expectedCoreInventory);
    assert.deepEqual(envelope.config, config);
    assert.equal(envelope.lockSha256, sha256(fs.readFileSync(sandbox.canonicalLock)));
  } finally {
    removeSandbox(sandbox);
  }
});

const candidateMissingNames = {
  configs: "enterprise_traefik_routes",
  networks: "enterprise_net",
  secrets: "alertmanager_webhook_token",
  services: "alertmanager",
  volumes: "backup_scheduler_logs",
};

for (const kind of protectedKinds) {
  test(`QA6 no-hosted rejects candidate missing one authoritative ${kind} entry`, () => {
    const sandbox = addInfraConsumer(createConsumerSandbox());
    try {
      const config = coreRuntimeConfig(expectedCoreInventory);
      delete config[kind][candidateMissingNames[kind]];
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const result = runInfraConsumer(sandbox);
      assert.notEqual(result.status, 0, `candidate missing ${kind} was auto-authorized`);
      assert.match(result.stderr, /inventory|protected|resource|authority|mismatch/i);
    } finally {
      removeSandbox(sandbox);
    }
  });
}

for (const kind of protectedKinds) {
  test(`QA6 no-hosted rejects candidate extra ${kind} before it becomes core authority`, () => {
    const sandbox = addInfraConsumer(createConsumerSandbox());
    try {
      const config = coreRuntimeConfig(expectedCoreInventory);
      if (kind === "configs") config.configs.attacker_config = { file: "/attacker/config" };
      if (kind === "networks") config.networks.attacker_network = { internal: false };
      if (kind === "secrets") config.secrets.attacker_secret = { file: "/attacker/secret" };
      if (kind === "volumes") config.volumes.attacker_volume = { name: "attacker_volume" };
      if (kind === "services") {
        config.services["attacker-daemon"] = boundedService({
          privileged: true,
          pid: "host",
          network_mode: "host",
          cap_add: ["SYS_ADMIN"],
          devices: ["/dev/null:/dev/attacker"],
          volumes: [{ type: "bind", source: "/", target: "/host" }],
        });
      }
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const result = runInfraConsumer(sandbox);
      assert.notEqual(result.status, 0, `candidate extra ${kind} was auto-authorized`);
      assert.match(result.stderr, /inventory|protected|resource|authority|mismatch/i);
    } finally {
      removeSandbox(sandbox);
    }
  });
}

function futureNoHostedLock() {
  return {
    ...JSON.parse(fs.readFileSync(canonicalNoHostedLockPath, "utf8")),
    projectName: "platform_infra_vps",
    protectedResourceNames: structuredClone(expectedCoreInventory),
  };
}

const lockInventoryMutations = [
  ...protectedKinds.map((kind) => [`missing-${kind}`, (lock) => {
    delete lock.protectedResourceNames[kind];
  }]),
  ...protectedKinds.map((kind) => [`minus-${kind}`, (lock) => {
    lock.protectedResourceNames[kind] = lock.protectedResourceNames[kind].slice(1);
  }]),
  ...protectedKinds.map((kind) => [`extra-${kind}`, (lock) => {
    lock.protectedResourceNames[kind] = [...lock.protectedResourceNames[kind], `attacker_${kind}`].sort();
  }]),
  ["duplicate", (lock) => {
    lock.protectedResourceNames.services = [
      lock.protectedResourceNames.services[0],
      ...lock.protectedResourceNames.services,
    ];
  }],
  ["unsorted", (lock) => {
    lock.protectedResourceNames.networks = [...lock.protectedResourceNames.networks].reverse();
  }],
  ["wrong-type", (lock) => {
    lock.protectedResourceNames.volumes = {};
  }],
  ["inventory-key-extra", (lock) => {
    lock.protectedResourceNames.images = [];
  }],
  ["top-level-key-extra", (lock) => {
    lock.attacker = true;
  }],
  ["project-name", (lock) => {
    lock.projectName = "attacker";
  }],
];

for (const [label, mutate] of lockInventoryMutations) {
  test(`QA6 no-hosted lock rejects ${label} before renderer`, () => {
    const sandbox = createConsumerSandbox();
    try {
      const lock = futureNoHostedLock();
      mutate(lock);
      fs.writeFileSync(sandbox.canonicalLock, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
      writeDockerOutput(sandbox, `${JSON.stringify(coreRuntimeConfig(expectedCoreInventory))}\n`);
      const result = runWrapper(sandbox);
      assert.notEqual(result.status, 0, `${label} lock inventory reached renderer`);
      assert.equal(fs.existsSync(sandbox.dockerMarker), false, `${label} lock inventory invoked Docker`);
    } finally {
      removeSandbox(sandbox);
    }
  });
}

test("QA6 no-hosted lock race preserves the initial authoritative snapshot or fails explicitly", () => {
  const sandbox = createConsumerSandbox();
  try {
    const originalLockBytes = fs.readFileSync(sandbox.canonicalLock);
    const initialLockSha256 = sha256(originalLockBytes);
    const config = coreRuntimeConfig(sandbox.inventory);
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);

    const baseline = runWrapper(sandbox);
    assert.equal(baseline.status, 0, baseline.stderr);
    const baselineEnvelope = JSON.parse(baseline.stdout);
    assert.equal(baselineEnvelope.lockSha256, initialLockSha256);
    assert.deepEqual(baselineEnvelope.protectedResourceNames, expectedCoreInventory);
    assert.deepEqual(baselineEnvelope.config, config);

    const foreignLock = path.join(sandbox.root, "foreign-no-hosted.lock.json");
    fs.writeFileSync(foreignLock, originalLockBytes, { mode: 0o600 });
    const foreign = runWrapper(sandbox, undefined, {
      HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: foreignLock,
    });
    assert.notEqual(foreign.status, 0, "copied no-hosted lock bypassed canonical path binding");

    fs.writeFileSync(sandbox.canonicalLock, "{}\n", { mode: 0o600 });
    const preTampered = runWrapper(sandbox);
    assert.notEqual(preTampered.status, 0, "pre-tampered canonical lock reached Docker");
    fs.writeFileSync(sandbox.canonicalLock, originalLockBytes, { mode: 0o600 });

    const replacement = path.join(sandbox.root, "replacement.lock.json");
    const replacementBytes = Buffer.from('{"attacker":true}\n');
    fs.writeFileSync(replacement, replacementBytes, { mode: 0o600 });
    const raced = runWrapper(sandbox, undefined, {
      QA6_SWAP_LOCK_REPLACEMENT: replacement,
      QA6_SWAP_LOCK_TARGET: sandbox.canonicalLock,
    });
    if (raced.status !== 0) {
      assert.match(
        raced.stderr,
        /(?:no-hosted|lock).*(?:changed|identity|snapshot|swap|digest|invalid|mismatch|tampered)|(?:changed|identity|snapshot|swap|digest|invalid|mismatch|tampered).*(?:no-hosted|lock)/i,
        `lock race failed for an unrelated reason:\n${raced.stderr}`,
      );
    } else {
      const racedEnvelope = JSON.parse(raced.stdout);
      assert.equal(racedEnvelope.lockSha256, initialLockSha256);
      assert.notEqual(racedEnvelope.lockSha256, sha256(replacementBytes));
      assert.deepEqual(racedEnvelope.protectedResourceNames, expectedCoreInventory);
      assert.deepEqual(racedEnvelope.config, config);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA6 no-hosted env bytes are stable from mode parse through Compose render", () => {
  const sandbox = createConsumerSandbox();
  try {
    const initialEnvironment = "HOSTED_WORKLOAD_LOCK=\nHOSTED_WORKLOAD_MODE=no-hosted\nCORE_VALUE=trusted\n";
    fs.writeFileSync(sandbox.environmentFile, initialEnvironment, { mode: 0o600 });
    const hostileEnvironment = path.join(sandbox.root, "hostile.env");
    fs.writeFileSync(
      hostileEnvironment,
      "HOSTED_WORKLOAD_LOCK=/attacker.lock\nHOSTED_WORKLOAD_MODE=hosted\nCORE_VALUE=hostile\n",
      { mode: 0o600 },
    );
    writeDockerOutput(sandbox, `${JSON.stringify(coreRuntimeConfig(sandbox.inventory))}\n`);
    const baseline = runWrapper(sandbox);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(fs.readFileSync(sandbox.dockerEnvironmentCapture, "utf8"), initialEnvironment);

    fs.rmSync(sandbox.dockerMarker, { force: true });
    fs.rmSync(sandbox.dockerEnvironmentCapture, { force: true });
    const raced = runWrapper(sandbox, undefined, {
      QA6_SWAP_ENV_REPLACEMENT: hostileEnvironment,
      QA6_SWAP_ENV_TARGET: sandbox.environmentFile,
    });
    const consumedBytes = fs.existsSync(sandbox.dockerEnvironmentCapture)
      ? fs.readFileSync(sandbox.dockerEnvironmentCapture, "utf8")
      : "";
    if (raced.status !== 0) {
      assert.match(
        raced.stderr,
        /(?:environment|env).*(?:changed|identity|snapshot|swap|digest|invalid|mismatch|tampered)|(?:changed|identity|snapshot|swap|digest|invalid|mismatch|tampered).*(?:environment|env)/i,
        `env race failed for an unrelated reason:\n${raced.stderr}`,
      );
    } else {
      assert.equal(consumedBytes, initialEnvironment, `Compose consumed swapped env bytes:\n${consumedBytes}`);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA6 PREPARE_RESOLVED accepts only exact hosted mode and forbids envelope", () => {
  const sandbox = createConsumerSandbox();
  try {
    writeDockerOutput(sandbox, `${JSON.stringify(coreRuntimeConfig(sandbox.inventory))}\n`);
    const prepareEnvironment = {
      HOSTED_WORKLOAD_LOCK: "",
      HOSTED_WORKLOAD_MODE: "hosted",
      HOSTED_WORKLOAD_PREPARE_RESOLVED: "1",
      HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: sandbox.workloadLock,
    };
    const positive = runWrapper(sandbox, ["config", "--format", "json"], prepareEnvironment);
    assert.equal(positive.status, 0, positive.stderr);
    fs.rmSync(sandbox.dockerMarker, { force: true });
    const envelope = runWrapper(sandbox, ["runtime-isolation-envelope"], prepareEnvironment);
    assert.notEqual(envelope.status, 0, "PREPARE_RESOLVED emitted a semantic envelope");
    assert.equal(fs.existsSync(sandbox.dockerMarker), false, "forbidden PREPARE envelope reached Docker");

    const acceptedModes = [];
    for (const mode of ["", "no-hosted", "evil", "HOSTED", " hosted", "hosted ", "No-hosted", "NO-HOSTED"]) {
      fs.rmSync(sandbox.dockerMarker, { force: true });
      const result = runWrapper(sandbox, ["config", "--format", "json"], {
        ...prepareEnvironment,
        HOSTED_WORKLOAD_MODE: mode,
      });
      if (result.status === 0 || fs.existsSync(sandbox.dockerMarker)) acceptedModes.push(mode);
    }
    assert.deepEqual(acceptedModes, [], `PREPARE accepted non-exact modes: ${JSON.stringify(acceptedModes)}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA6 infra runtime-isolation CLI closes argv before invoking the renderer", () => {
  const sandbox = addInfraConsumer(createConsumerSandbox());
  try {
    writeDockerOutput(sandbox, `${JSON.stringify(coreRuntimeConfig(sandbox.inventory))}\n`);
    for (const allowedArguments of [
      ["--env-file", sandbox.environmentFile],
      ["--envFile", sandbox.environmentFile],
      [`--env-file=${sandbox.environmentFile}`],
      [`--envFile=${sandbox.environmentFile}`],
    ]) {
      fs.rmSync(sandbox.dockerMarker, { force: true });
      const allowed = runInfraArguments(sandbox, allowedArguments);
      assert.equal(allowed.status, 0, allowed.stderr);
    }

    const accepted = [];
    for (const [label, arguments_] of [
      ["unknown split", ["--env-file", sandbox.environmentFile, "--foo", "attacker"]],
      ["unknown equals", ["--env-file", sandbox.environmentFile, "--foo=attacker"]],
      ["unknown flag", ["--env-file", sandbox.environmentFile, "--foo"]],
      ["positional", ["--env-file", sandbox.environmentFile, "attacker-positional"]],
      ["duplicate env-file", [
        "--env-file", sandbox.environmentFile,
        "--env-file", sandbox.environmentFile,
      ]],
      ["both aliases", [
        "--env-file", sandbox.environmentFile,
        "--envFile", sandbox.environmentFile,
      ]],
      ["empty env-file", ["--env-file="]],
      ["empty envFile", ["--envFile="]],
    ]) {
      fs.rmSync(sandbox.dockerMarker, { force: true });
      const result = runInfraArguments(sandbox, arguments_);
      const rendererInvoked = fs.existsSync(sandbox.dockerMarker);
      if (result.status === 0 || rendererInvoked) {
        accepted.push(label);
      } else {
        assert.match(
          result.stderr,
          /argument|argv|option|unknown|invalid|forbidden|duplicate|empty/i,
          `${label} failed before renderer for an unrelated reason:\n${result.stderr}`,
        );
      }
    }
    assert.deepEqual(accepted, [], `runtime-isolation-check accepted unknown argv: ${accepted.join(", ")}`);
  } finally {
    removeSandbox(sandbox);
  }
});
