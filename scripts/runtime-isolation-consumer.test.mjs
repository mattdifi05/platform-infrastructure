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
const canonicalNoHostedAuthorityPath = path.join(repositoryRoot, "config", "no-hosted-runtime-authority.json");
const protectedKinds = ["configs", "networks", "secrets", "services", "volumes"];
const fallbackCoreInventory = {
  configs: [],
  networks: ["platform_docker_control"],
  secrets: [],
  services: [
    "backup-scheduler",
    "control-center",
    "docker-socket-proxy",
    "platform-alert-dispatcher",
    "postgres",
    "project-router",
  ],
  volumes: [],
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

function authoritativeCoreInventory() {
  if (!fs.existsSync(canonicalNoHostedAuthorityPath)) return structuredClone(fallbackCoreInventory);
  const authority = JSON.parse(fs.readFileSync(canonicalNoHostedAuthorityPath, "utf8"));
  return structuredClone(authority.protectedResourceNames);
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
  const inventory = authoritativeCoreInventory();
  const authority = {
    version: 1,
    lockSha256: sha256(fs.readFileSync(canonicalLock)),
    projectName: "platform_infra_vps",
    protectedResourceNames: inventory,
  };
  const authorityFile = path.join(configDirectory, "no-hosted-runtime-authority.json");
  fs.writeFileSync(authorityFile, `${JSON.stringify(authority, null, 2)}\n`, { mode: 0o600 });
  const environmentFile = path.join(root, "core.env");
  fs.writeFileSync(environmentFile, "HOSTED_WORKLOAD_LOCK=\nHOSTED_WORKLOAD_MODE=no-hosted\nCORE_VALUE=trusted\n", { mode: 0o600 });
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
    authority,
    authorityFile,
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

function writeDockerOutput(sandbox, documents) {
  fs.writeFileSync(sandbox.dockerOutputFile, documents);
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
    "runtime-isolation-check derives a protected-resource fallback from the rendered config",
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
    const config = {
      name: "platform_infra_vps",
      configs: { core_config: {} },
      networks: { core_net: { name: "platform_infra_vps_core_net" } },
      secrets: { core_secret: { file: "/private/core-secret" } },
      services: { core: { image: "example.invalid/core@sha256:fixture" } },
      volumes: { core_volume: {} },
    };
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
    assert.deepEqual(envelope.protectedResourceNames, {
      configs: ["core_config"],
      networks: ["core_net"],
      secrets: ["core_secret"],
      services: ["core"],
      volumes: ["core_volume"],
    });
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
    const protectedResourceNames = structuredClone(fallbackCoreInventory);
    const configA = coreRuntimeConfig(protectedResourceNames, { hosted: true });
    const configB = structuredClone(configA);
    configB.services["example-app-web"].image =
      `example.invalid/example-app@sha256:${"b".repeat(64)}`;
    for (const [label, config] of [["baseline", configA], ["image mutation", configB]]) {
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

    writeDockerOutput(sandbox, `${JSON.stringify(configB)}\n`);
    const substituted = runInfraConsumer(sandbox);
    assert.notEqual(
      substituted.status,
      0,
      `combinedRenderSha256 accepted policy-valid renderer substitution:\n${substituted.stdout}\n${substituted.stderr}`,
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

test("QA6 canonical no-hosted authority is closed and digest-bound to the canonical lock", () => {
  assert.equal(
    fs.existsSync(canonicalNoHostedAuthorityPath),
    true,
    "missing config/no-hosted-runtime-authority.json",
  );
  const authority = JSON.parse(fs.readFileSync(canonicalNoHostedAuthorityPath, "utf8"));
  assert.deepEqual(Object.keys(authority).sort(), [
    "lockSha256", "projectName", "protectedResourceNames", "version",
  ]);
  assert.equal(authority.version, 1);
  assert.equal(authority.projectName, "platform_infra_vps");
  assert.equal(authority.lockSha256, sha256(fs.readFileSync(canonicalNoHostedLockPath)));
  assert.deepEqual(Object.keys(authority.protectedResourceNames).sort(), protectedKinds);
  for (const kind of protectedKinds) {
    const names = authority.protectedResourceNames[kind];
    assert.ok(Array.isArray(names), `${kind} inventory is not an array`);
    assert.deepEqual(names, [...new Set(names)].sort(), `${kind} inventory is not closed/sorted/unique`);
    assert.ok(names.every((name) => typeof name === "string" && name.length > 0));
  }
});

test("QA6 no-hosted authority rejects missing, extra, unsafe and tampered resource inventories", () => {
  const bypasses = [];
  const sandbox = addInfraConsumer(createConsumerSandbox());
  try {
    const config = coreRuntimeConfig(sandbox.inventory);
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);
    const baseline = runInfraConsumer(sandbox);
    assert.equal(baseline.status, 0, baseline.stderr);

    const removableService = sandbox.inventory.services.find((name) =>
      !["backup-scheduler", "control-center", "docker-socket-proxy", "platform-alert-dispatcher", "project-router"].includes(name));
    assert.ok(removableService, "fixture needs one non-special protected service");
    const missing = structuredClone(config);
    delete missing.services[removableService];
    writeDockerOutput(sandbox, `${JSON.stringify(missing)}\n`);
    const missingResult = runInfraConsumer(sandbox);

    const attacker = structuredClone(config);
    attacker.configs.attacker_config = { file: "/attacker/config" };
    attacker.networks.attacker_network = { internal: false };
    attacker.secrets.attacker_secret = { file: "/attacker/secret" };
    attacker.volumes.attacker_volume = { name: "attacker_volume" };
    attacker.services["attacker-daemon"] = boundedService({
      privileged: true,
      pid: "host",
      network_mode: "host",
      cap_add: ["SYS_ADMIN"],
      devices: ["/dev/null:/dev/attacker"],
      volumes: [{ type: "bind", source: "/", target: "/host" }],
    });
    writeDockerOutput(sandbox, `${JSON.stringify(attacker)}\n`);
    const attackerResult = runInfraConsumer(sandbox);

    if (missingResult.status === 0) bypasses.push("candidate-minus-authority");
    if (attackerResult.status === 0) bypasses.push("unsafe-candidate-extras");
  } finally {
    removeSandbox(sandbox);
  }

  for (const mutation of ["lockSha256", "protectedResourceNames"]) {
    const candidate = createConsumerSandbox();
    try {
      const config = coreRuntimeConfig(candidate.inventory);
      writeDockerOutput(candidate, `${JSON.stringify(config)}\n`);
      const authority = JSON.parse(fs.readFileSync(candidate.authorityFile, "utf8"));
      if (mutation === "lockSha256") {
        authority.lockSha256 = "f".repeat(64);
      } else {
        authority.protectedResourceNames.services = [
          ...authority.protectedResourceNames.services,
          "attacker-daemon",
        ].sort();
      }
      fs.writeFileSync(candidate.authorityFile, `${JSON.stringify(authority, null, 2)}\n`, { mode: 0o600 });
      const result = runWrapper(candidate);
      if (result.status === 0) bypasses.push(`authority-${mutation}`);
    } finally {
      removeSandbox(candidate);
    }
  }
  assert.deepEqual(
    bypasses,
    [],
    `no-hosted authority bypasses: ${bypasses.join(", ")}`,
  );
});

test("QA6 no-hosted lock swap after validation fails without emitting replacement SHA", () => {
  const sandbox = createConsumerSandbox();
  try {
    const originalLockBytes = fs.readFileSync(sandbox.canonicalLock);
    const config = coreRuntimeConfig(sandbox.inventory);
    writeDockerOutput(sandbox, `${JSON.stringify(config)}\n`);

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
    assert.notEqual(raced.status, 0, `canonical lock swap emitted an envelope:\n${raced.stdout}`);
    assert.doesNotMatch(raced.stdout, new RegExp(sha256(replacementBytes)));
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
    const result = runWrapper(sandbox, undefined, {
      QA6_SWAP_ENV_REPLACEMENT: hostileEnvironment,
      QA6_SWAP_ENV_TARGET: sandbox.environmentFile,
    });
    const consumedBytes = fs.existsSync(sandbox.dockerEnvironmentCapture)
      ? fs.readFileSync(sandbox.dockerEnvironmentCapture, "utf8")
      : "";
    assert.ok(
      result.status !== 0 || consumedBytes === initialEnvironment,
      `Compose consumed swapped env bytes:\n${consumedBytes}`,
    );
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
    for (const mode of ["evil", "HOSTED", " hosted", "hosted ", "No-hosted", "NO-HOSTED"]) {
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
    ]) {
      const allowed = runInfraArguments(sandbox, allowedArguments);
      assert.equal(allowed.status, 0, allowed.stderr);
    }

    const accepted = [];
    for (const arguments_ of [
      ["--env-file", sandbox.environmentFile, "--config", "/attacker/config.json"],
      ["--env-file", sandbox.environmentFile, "--protectedResourceNames", "{}"],
      ["--env-file", sandbox.environmentFile, "--workloadLock", "/attacker/lock.json"],
      ["--env-file", sandbox.environmentFile, "attacker-positional"],
    ]) {
      fs.rmSync(sandbox.dockerMarker, { force: true });
      const result = runInfraArguments(sandbox, arguments_);
      if (result.status === 0 || fs.existsSync(sandbox.dockerMarker)) accepted.push(arguments_.slice(2).join(" "));
    }
    assert.deepEqual(accepted, [], `runtime-isolation-check accepted unknown argv: ${accepted.join(", ")}`);
  } finally {
    removeSandbox(sandbox);
  }
});
