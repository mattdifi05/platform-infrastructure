#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  resolveCatalog,
  validateGlobalRouteOwnership,
  validateRenderedWorkloads,
  validateWorkloadEnvironmentText,
  validateWorkloadManifest,
  verifyLockFiles,
  verifyRawPolicyReceipt,
} from "./hosted-workload-contract.mjs";
import { brokerPolicySha256, expectedNatsPolicy, expectedRedisPolicy } from "./workload-broker-policy.mjs";

const digest = "a".repeat(64);
const manifest = validateWorkloadManifest({
  version: 1,
  id: "example-app",
  composeFile: "compose.platform.yaml",
  secrets: ["example-app-database-url"],
  migrationRoots: ["postgres/migrations"],
  services: [
    {
      name: "example-app-web",
      role: "web",
      routes: [{ slug: "example", host: "Example.Example.com.", aliases: ["example-alt"], port: 3000 }],
    },
    { name: "example-app-worker", role: "worker" },
  ],
});

const baseService = {
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
  labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
};

const core = {
  services: { "project-router": { image: `registry.example/router@sha256:${digest}`, networks: { platform_routing: null } } },
  networks: { platform_routing: { internal: true } },
};

function combinedFixture() {
  return {
    services: {
      "project-router": { ...core.services["project-router"], networks: { platform_routing: null, example_app_ingress: null } },
      "example-app-web": {
        ...structuredClone(baseService),
        secrets: [{ source: "example-app-database-url", target: "example-app-database-url" }],
        environment: { DATABASE_URL_FILE: "/run/secrets/example-app-database-url" },
      },
      "example-app-worker": {
        ...structuredClone(baseService),
        networks: { example_app_egress: null },
        labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "worker" },
      },
    },
    networks: { platform_routing: { internal: true }, example_app_ingress: { internal: true }, example_app_egress: { internal: false, enable_ipv6: false } },
    secrets: { "example-app-database-url": { external: true } },
  };
}

const lock = { workloads: [manifest], brokerPolicySha256: brokerPolicySha256([manifest]) };
let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}

test("exact hardened workload render passes", () => {
  assert.equal(manifest.version, 1);
  const result = validateRenderedWorkloads({ core, combined: combinedFixture(), lock });
  assert.deepEqual(result.routes, [{
    owner: "example-app",
    workloadId: "example-app",
    slug: "example",
    aliases: ["example-alt"],
    canonicalHost: "example.example.com",
    hosts: ["example.example.com", "example-alt.example.com"],
    service: "example-app-web",
    port: 3000,
    upstream: "http://example-app-web:3000",
  }]);
});
test("build context is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].build = { context: "." };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot build/);
});
test("mutable image is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].image = "registry.example/example/app:latest";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /digest-pinned/);
});
test("bind mount is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].volumes = [{ type: "bind", source: "/srv", target: "/app" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /bind mounts are forbidden/);
});
test("service volume inheritance is rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].volumes_from = ["postgres:rw"];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot inherit volumes/);
});
test("service lifecycle hooks are rejected after render", () => {
  for (const hook of ["post_start", "pre_start", "pre_stop"]) {
    const combined = combinedFixture();
    combined.services["example-app-web"][hook] = [{ command: "id" }];
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot define service lifecycle hooks/);
  }
});
test("service scaling is rejected after render", () => {
  for (const mutation of [
    (service) => { service.scale = 2; },
    (service) => { service.deploy = { replicas: 2 }; },
  ]) {
    const combined = combinedFixture();
    mutation(combined.services["example-app-web"]);
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot request service scaling/);
  }
});
test("host port is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].ports = [{ target: 3000, published: "3000" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /host ports/);
});
test("root user is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].user = "0:0";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /non-root/);
});
test("literal secret environment is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].environment.DATABASE_URL = "postgres://user:password@postgres/db";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /sensitive environment/);
});
test("file-backed secret must be external", () => {
  const combined = combinedFixture();
  combined.secrets["example-app-database-url"] = { file: "/tmp/secret" };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /must be external/);
});
test("file-backed configs and workload config grants are rejected after render", () => {
  const fileBacked = combinedFixture();
  fileBacked.configs = { host_data: { file: "/etc/hosts" } };
  assert.throws(() => validateRenderedWorkloads({ core, combined: fileBacked, lock }), /cannot use a host file source/);

  const granted = combinedFixture();
  granted.configs = { platform_config: { external: true } };
  granted.services["example-app-web"].configs = [{ source: "platform_config", target: "/run/config" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined: granted, lock }), /cannot mount platform or host-backed configs/);
});
test("platform service mutation is rejected", () => {
  const combined = combinedFixture();
  combined.services["project-router"].privileged = true;
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /changed protected platform service/);
});
test("protected top-level resources cannot be replaced or removed", () => {
  const protectedCore = structuredClone(core);
  protectedCore.configs = { traefik_dynamic: { file: "/private/traefik.yaml" } };
  protectedCore.secrets = { postgres_password: { external: true, name: "platform-postgres-password" } };
  protectedCore.volumes = { postgres_data: { name: "platform-postgres-data" } };
  protectedCore.networks.platform_db = { internal: true, name: "platform-db" };
  for (const [resourceType, resourceName, replacement] of [
    ["configs", "traefik_dynamic", { file: "/hostile/config" }],
    ["secrets", "postgres_password", { external: true, name: "hostile-secret" }],
    ["volumes", "postgres_data", { name: "hostile-volume" }],
    ["networks", "platform_db", { internal: false, name: "hostile-network" }],
  ]) {
    const combined = combinedFixture();
    combined.configs = structuredClone(protectedCore.configs);
    combined.secrets = { ...structuredClone(protectedCore.secrets), ...combined.secrets };
    combined.volumes = structuredClone(protectedCore.volumes);
    combined.networks = { ...structuredClone(protectedCore.networks), ...combined.networks };
    combined[resourceType][resourceName] = replacement;
    assert.throws(
      () => validateRenderedWorkloads({ core: protectedCore, combined, lock }),
      new RegExp(`changed protected ${resourceType} resource ${resourceName}`),
    );
    combined[resourceType][resourceName] = structuredClone(protectedCore[resourceType][resourceName]);
    delete combined[resourceType][resourceName];
    assert.throws(
      () => validateRenderedWorkloads({ core: protectedCore, combined, lock }),
      new RegExp(`removed protected ${resourceType} resource ${resourceName}`),
    );
  }
});
test("unauthorized platform network extension is rejected", () => {
  const combined = combinedFixture();
  combined.services["project-router"].networks.evil = null;
  combined.networks.evil = { internal: true };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /non-workload network/);
});
test("workload network cannot alias the Docker-control physical network", () => {
  for (const definition of [
    { external: true, name: "platform_infra_platform_docker_control" },
    { internal: true, name: "platform_infra_platform_docker_control" },
  ]) {
    const combined = combinedFixture();
    combined.networks.example_app_ingress = definition;
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock: { projectName: "fixture", workloads: [manifest] } }),
      /cannot alias foreign physical network/,
    );
  }
  const combined = combinedFixture();
  combined.networks.example_app_ingress.name = "fixture_example_app_ingress";
  assert.doesNotThrow(() => validateRenderedWorkloads({ core, combined, lock: { projectName: "fixture", workloads: [manifest] } }));
});
test("platform service can join only its assigned workload zone", () => {
  const combined = combinedFixture();
  combined.services["project-router"].networks.example_app_cache = null;
  combined.networks.example_app_cache = { internal: true };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot join workload example-app zone cache/);
});
test("deployment-private activation state has no non-router writable mount", () => {
  const privateLock = "/deployment-private/hosted-workloads.lock.json";
  const lockWithActivation = {
    workloads: [manifest],
    activationLockPath: privateLock,
    snapshotRoot: "/deployment-private/snapshots",
  };
  const coreWithLock = structuredClone(core);
  coreWithLock.services["project-router"].volumes = [{
    type: "bind",
    source: privateLock,
    target: "/run/platform/hosted-workloads.lock.json",
    read_only: true,
  }];
  const combined = combinedFixture();
  combined.services["project-router"].volumes = structuredClone(coreWithLock.services["project-router"].volumes);
  assert.doesNotThrow(() => validateRenderedWorkloads({ core: coreWithLock, combined, lock: lockWithActivation }));
  combined.services["project-router"].volumes[0].read_only = false;
  assert.throws(
    () => validateRenderedWorkloads({ core: coreWithLock, combined, lock: lockWithActivation }),
    /deployment-private hosted workload activation state|read-only activation-lock mount/,
  );
  combined.services["project-router"].volumes = structuredClone(coreWithLock.services["project-router"].volumes);
  combined.services["example-app-worker"].volumes = [{
    type: "bind",
    source: "/deployment-private",
    target: "/mnt/private",
    read_only: false,
  }];
  assert.throws(
    () => validateRenderedWorkloads({ core: coreWithLock, combined, lock: lockWithActivation }),
    /writable access to deployment-private/,
  );
});
test("route without dedicated router network is rejected", () => {
  const combined = combinedFixture();
  delete combined.services["project-router"].networks.example_app_ingress;
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /no dedicated network/);
});
test("undeclared service is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-shell"] = structuredClone(baseService);
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /exactly match/);
});

function brokerRenderFixture() {
  const services = [
    { name: "tenant-app-cache", role: "worker" },
    { name: "tenant-app-bus", role: "scheduled-worker" },
  ];
  const secrets = ["tenant-app-redis-password", "tenant-app-bus-nats-password"];
  const workload = validateWorkloadManifest({
    version: 1,
    id: "tenant-app",
    composeFile: "compose.yaml",
    services,
    secrets,
    brokers: {
      redis: expectedRedisPolicy("tenant-app"),
      nats: expectedNatsPolicy("tenant-app", [services[1]]),
    },
  });
  const brokerCore = {
    services: {
      redis: { image: "redis@sha256:fixed", command: ["fixed-redis-entrypoint"], secrets: ["redis_password"], networks: { platform_cache: null } },
      nats: { image: "nats@sha256:fixed", command: ["fixed-nats-entrypoint"], secrets: ["nats_password"], networks: { platform_bus: null } },
      "broker-auth-bootstrap": { image: "ops@sha256:fixed", command: ["fixed-broker-bootstrap"], secrets: ["redis_password", "nats_password"], network_mode: "none" },
    },
    networks: { platform_cache: { internal: true }, platform_bus: { internal: true } },
  };
  const cacheService = {
    ...structuredClone(baseService),
    networks: { tenant_app_cache: null },
    labels: { "com.platform.workload-id": "tenant-app", "com.platform.workload-role": "worker" },
    secrets: [{ source: "tenant-app-redis-password", target: "tenant-app-redis-password" }],
    environment: {
      REDIS_HOST: "redis",
      REDIS_PORT: "6379",
      REDIS_USERNAME: workload.brokers.redis.username,
      REDIS_PASSWORD_FILE: "/run/secrets/tenant-app-redis-password",
      REDIS_KEY_PREFIX: "tenant-app:",
      REDIS_CHANNEL_PREFIX: "tenant-app:",
    },
  };
  const natsUser = workload.brokers.nats.users[0];
  const busService = {
    ...structuredClone(baseService),
    networks: { tenant_app_bus: null },
    labels: { "com.platform.workload-id": "tenant-app", "com.platform.workload-role": "scheduled-worker" },
    secrets: [{ source: "tenant-app-bus-nats-password", target: "tenant-app-bus-nats-password" }],
    environment: {
      NATS_HOST: "nats",
      NATS_PORT: "4222",
      NATS_ACCOUNT: workload.brokers.nats.account,
      NATS_USERNAME: natsUser.username,
      NATS_PASSWORD_FILE: "/run/secrets/tenant-app-bus-nats-password",
      NATS_SUBJECT_PREFIX: natsUser.publish[0].slice(0, -1),
      NATS_QUEUE_GROUP: natsUser.queueGroups[0],
    },
  };
  const combined = {
    services: {
      redis: {
        ...structuredClone(brokerCore.services.redis),
        networks: { platform_cache: null, tenant_app_cache: null },
      },
      nats: {
        ...structuredClone(brokerCore.services.nats),
        networks: { platform_bus: null, tenant_app_bus: null },
      },
      "broker-auth-bootstrap": {
        ...structuredClone(brokerCore.services["broker-auth-bootstrap"]),
        secrets: ["redis_password", "nats_password", "tenant-app-redis-password", "tenant-app-bus-nats-password"],
      },
      "tenant-app-cache": cacheService,
      "tenant-app-bus": busService,
    },
    networks: {
      platform_cache: { internal: true },
      platform_bus: { internal: true },
      tenant_app_cache: { internal: true },
      tenant_app_bus: { internal: true },
    },
    secrets: {
      redis_password: { external: true },
      nats_password: { external: true },
      "tenant-app-redis-password": { external: true },
      "tenant-app-bus-nats-password": { external: true },
    },
  };
  return {
    core: brokerCore,
    combined,
    lock: { workloads: [workload], brokerPolicySha256: brokerPolicySha256([workload]) },
  };
}

test("rendered cache and bus consumers bind exact workload broker identities and core secret mounts", () => {
  const fixture = brokerRenderFixture();
  assert.deepEqual(validateRenderedWorkloads(fixture).routes, []);
});

test("rendered broker contract rejects missing identity fields, core secrets and broker command mutation", () => {
  const missingIdentity = brokerRenderFixture();
  delete missingIdentity.combined.services["tenant-app-bus"].environment.NATS_PASSWORD_FILE;
  assert.throws(() => validateRenderedWorkloads(missingIdentity), /NATS connection fields/);

  const missingCoreSecret = brokerRenderFixture();
  missingCoreSecret.combined.services["broker-auth-bootstrap"].secrets = ["redis_password", "nats_password", "tenant-app-bus-nats-password"];
  assert.throws(() => validateRenderedWorkloads(missingCoreSecret), /mount exactly/);

  const mutatedBroker = brokerRenderFixture();
  mutatedBroker.combined.services.nats.command = ["--user", "shared", "--pass", "shared"];
  assert.throws(() => validateRenderedWorkloads(mutatedBroker), /changed protected platform service/);
});
test("duplicate route is rejected at manifest boundary", () => {
  assert.throws(() => validateWorkloadManifest({
    version: 1,
    id: "duplicate-app",
    composeFile: "compose.yaml",
    services: [
      { name: "duplicate-app-one", role: "web", routes: [{ slug: "same", host: "same.example.com", port: 3000 }] },
      { name: "duplicate-app-two", role: "web", routes: [{ slug: "same", host: "same.example.com", port: 3000 }] },
    ],
  }), /Duplicate route/);
});

test("global route collisions are deterministic regardless of manifest order", () => {
  const alpha = validateWorkloadManifest({
    version: 1,
    id: "alpha-app",
    composeFile: "compose.yaml",
    services: [{
      name: "alpha-app-web",
      role: "web",
      routes: [{ slug: "alpha", host: "alpha.example.com", aliases: ["shared"], port: 3000 }],
    }],
  });
  const beta = validateWorkloadManifest({
    version: 1,
    id: "beta-app",
    composeFile: "compose.yaml",
    services: [{
      name: "beta-app-web",
      role: "web",
      routes: [{ slug: "shared", host: "shared.example.net", port: 3001 }],
    }],
  });
  const errors = [];
  for (const workloads of [[alpha, beta], [beta, alpha]]) {
    assert.throws(() => validateGlobalRouteOwnership(workloads), (error) => {
      errors.push(error.message);
      return /slug or alias 'shared'.*alpha-app.*beta-app/.test(error.message);
    });
  }
  assert.equal(errors[0], errors[1]);
});

test("canonical host ownership rejects reserved and normalized duplicates", () => {
  const alpha = validateWorkloadManifest({
    version: 1,
    id: "alpha-app",
    composeFile: "compose.yaml",
    services: [{ name: "alpha-app-web", role: "web", routes: [{ slug: "alpha", host: "ALPHA.example.com.", port: 3000 }] }],
  });
  assert.throws(
    () => validateGlobalRouteOwnership([alpha], { reservedHosts: ["alpha.example.com"] }),
    /host 'alpha\.example\.com'.*platform/,
  );
});

test("global upstream reuse is rejected even when hosts differ", () => {
  const workload = validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.yaml",
    services: [{
      name: "example-app-web",
      role: "web",
      routes: [
        { slug: "alpha", host: "alpha.example.com", port: 3000 },
        { slug: "beta", host: "beta.example.com", port: 3000 },
      ],
    }],
  });
  assert.throws(() => validateGlobalRouteOwnership([workload]), /upstream 'example-app-web:3000'/);
});

test("legacy hosted workload locks fail closed", () => {
  assert.throws(
    () => verifyLockFiles({ version: 1, state: "verified", files: [] }),
    /schema 2 and validator hosted-contract-v2/,
  );
});

test("raw policy receipt requires the exact current control set", () => {
  const rawPolicyReceipt = {
    policyVersion: "hosted-raw-v1",
    controls: ["deny-env-file", "deny-extends", "deny-file-configs", "deny-include", "deny-lifecycle-hooks", "deny-scaling", "deny-volumes-from"],
    workloadContentSha256: "a".repeat(64),
    workloads: [{
      workloadId: "example-app",
      composeSha256: "c".repeat(64),
      topLevelKeys: ["services"],
      serviceNames: ["example-app-web"],
    }],
  };
  const stable = (value) => {
    if (Array.isArray(value)) return value.map(stable);
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  };
  const receipt = {
    workloadContentSha256: "a".repeat(64),
    workloads: [{ id: "example-app", services: [{ name: "example-app-web" }] }],
    files: [{ kind: "workload-compose", workloadId: "example-app", sha256: "c".repeat(64) }],
    rawPolicyVersion: "hosted-raw-v1",
    rawPolicyWorkloadContentSha256: "a".repeat(64),
    rawPolicyReceipt,
    rawPolicySha256: crypto.createHash("sha256").update(JSON.stringify(stable(rawPolicyReceipt))).digest("hex"),
    rawPolicyControls: ["deny-env-file", "deny-extends", "deny-file-configs", "deny-include", "deny-lifecycle-hooks", "deny-scaling", "deny-volumes-from"],
  };
  assert.doesNotThrow(() => verifyRawPolicyReceipt(receipt));
  receipt.rawPolicyControls = ["deny-include"];
  assert.throws(() => verifyRawPolicyReceipt(receipt), /raw source policy receipt/);
  receipt.rawPolicyControls = ["deny-env-file", "deny-extends", "deny-file-configs", "deny-include", "deny-lifecycle-hooks", "deny-scaling", "deny-volumes-from"];
  receipt.rawPolicySha256 = "b".repeat(64);
  assert.throws(() => verifyRawPolicyReceipt(receipt), /raw source policy receipt/);
  receipt.rawPolicyReceipt.workloads[0].composeSha256 = "d".repeat(64);
  receipt.rawPolicySha256 = crypto.createHash("sha256").update(JSON.stringify(stable(receipt.rawPolicyReceipt))).digest("hex");
  assert.throws(() => verifyRawPolicyReceipt(receipt), /not bound/);
});

function catalogFixture(root, appRoot = path.join(root, "workloads", "example-app")) {
  fs.mkdirSync(appRoot, { recursive: true });
  fs.writeFileSync(path.join(appRoot, "manifest.json"), JSON.stringify({
    version: 1,
    id: "example-app",
    composeFile: "compose.yaml",
    services: [{ name: "example-app-web", role: "web" }],
  }));
  fs.writeFileSync(path.join(appRoot, "compose.yaml"), "services:\n  example-app-web: {}\n");
  fs.writeFileSync(path.join(appRoot, "workload.env"), "EXAMPLE_APP_THEME=dark\n");
  const catalogPath = path.join(root, "catalog.json");
  fs.writeFileSync(catalogPath, JSON.stringify({
    version: 1,
    workloads: [{ manifest: "example-app/manifest.json", environmentFile: "example-app/workload.env" }],
  }));
  const coreEnvFile = path.join(root, "core.env");
  const coreFile = path.join(root, "compose.core.yaml");
  fs.writeFileSync(coreEnvFile, "CORE_VALUE=fixture\n");
  fs.writeFileSync(coreFile, "services: {}\n");
  return { catalogPath, coreEnvFile, coreFile };
}

function removeFixtureTree(root) {
  if (!fs.existsSync(root)) return;
  const makeDirectoriesWritable = (directory) => {
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return;
    fs.chmodSync(directory, 0o700);
    for (const entry of fs.readdirSync(directory)) makeDirectoriesWritable(path.join(directory, entry));
  };
  makeDirectoriesWritable(root);
  fs.rmSync(root, { recursive: true, force: true });
}

function executablePath(name) {
  const result = spawnSync("/bin/sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : null;
}

test("workload resolver accepts an all-regular contained tree", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-contained-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const snapshotRoot = path.join(root, "snapshots");
    const result = resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture", snapshotRoot });
    assert.equal(result.workloads[0].manifestSourcePath, fs.realpathSync.native(path.join(workloadRoot, "example-app", "manifest.json")));
    assert.equal(path.dirname(result.workloads[0].manifestPath), result.snapshotGeneration);
    assert.equal(path.basename(result.snapshotGeneration), `content-${result.workloadContentSha256}`);
    assert.equal(result.snapshotRootIdentity.uid, String(process.getuid?.() ?? result.snapshotRootIdentity.uid));
    assert.equal(result.snapshotParentIdentity.mode, 0o700);
    assert.equal(result.snapshotRootIdentity.mode, 0o700);
    assert.equal(result.snapshotGenerationIdentity.mode, 0o500);
    assert.deepEqual(result.snapshotDurability, {
      version: 1,
      filesFsynced: true,
      generationDirectoryFsynced: true,
      rootDirectoryFsynced: true,
    });
    assert.match(result.workloadContentSha256, /^[a-f0-9]{64}$/);
    verifyLockFiles(result);
  } finally {
    removeFixtureTree(root);
  }
});

test("lock verification rejects missing, duplicate, and semantically tampered workload roles", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-role-binding-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const missing = structuredClone(lock);
    missing.files = missing.files.filter((record) => record.kind !== "workload-compose");
    missing.workloads[0].files = missing.workloads[0].files.filter((record) => record.kind !== "workload-compose");
    assert.throws(() => verifyLockFiles(missing), /exactly one workload-compose/);

    const duplicate = structuredClone(lock);
    duplicate.files.push(structuredClone(duplicate.files.find((record) => record.kind === "workload-compose")));
    duplicate.workloads[0].files.push(structuredClone(duplicate.workloads[0].files.find((record) => record.kind === "workload-compose")));
    assert.throws(() => verifyLockFiles(duplicate), /duplicate file paths/);

    const semantic = structuredClone(lock);
    semantic.workloads[0].services[0].role = "worker";
    assert.throws(() => verifyLockFiles(semantic), /semantic manifest fields differ/);
  } finally {
    removeFixtureTree(root);
  }
});

test("workload resolver rejects intermediate and terminal symlinks", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-symlink-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const outside = path.join(root, "outside-app");
    const snapshotRoot = path.join(root, "snapshots");
    fs.mkdirSync(workloadRoot, { recursive: true });
    const fixture = catalogFixture(root, outside);
    fs.symlinkSync(outside, path.join(workloadRoot, "example-app"), "dir");
    assert.throws(
      () => resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture", snapshotRoot }),
      /symlink component/,
    );
    fs.rmSync(path.join(workloadRoot, "example-app"));
    fs.mkdirSync(path.join(workloadRoot, "example-app"));
    fs.symlinkSync(path.join(outside, "manifest.json"), path.join(workloadRoot, "example-app", "manifest.json"));
    assert.throws(
      () => resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture", snapshotRoot }),
      /symlink component/,
    );
  } finally {
    removeFixtureTree(root);
  }
});

test("workload resolver rejects symlinked roots and root parents", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-root-link-")));
  try {
    const realParent = path.join(root, "real-parent");
    const workloadRoot = path.join(realParent, "workloads");
    const fixture = catalogFixture(root, path.join(workloadRoot, "example-app"));
    const linkedParent = path.join(root, "linked-parent");
    fs.symlinkSync(realParent, linkedParent, "dir");
    assert.throws(
      () => resolveCatalog({
        ...fixture,
        workloadRoot: path.join(linkedParent, "workloads"),
        coreFiles: [fixture.coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(root, "snapshots-one"),
      }),
      /symlink component/,
    );
    const realSnapshotParent = path.join(root, "real-snapshot-parent");
    fs.mkdirSync(realSnapshotParent);
    const linkedSnapshotParent = path.join(root, "linked-snapshot-parent");
    fs.symlinkSync(realSnapshotParent, linkedSnapshotParent, "dir");
    assert.throws(
      () => resolveCatalog({
        ...fixture,
        workloadRoot,
        coreFiles: [fixture.coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(linkedSnapshotParent, "snapshots"),
      }),
      /symlink component/,
    );
    assert.equal(fs.existsSync(path.join(realSnapshotParent, "snapshots")), false);
    const linkedRoot = path.join(root, "linked-workloads");
    fs.symlinkSync(workloadRoot, linkedRoot, "dir");
    assert.throws(
      () => resolveCatalog({
        ...fixture,
        workloadRoot: linkedRoot,
        coreFiles: [fixture.coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(root, "snapshots-two"),
      }),
      /symlink component/,
    );
  } finally {
    removeFixtureTree(root);
  }
});

test("snapshot capture rejects deterministic parent swaps before every workload file open", () => {
  for (const targetKind of ["workload-manifest", "workload-compose", "workload-environment"]) {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `hosted-open-race-${targetKind}-`)));
    try {
      const workloadRoot = path.join(root, "workloads");
      const fixture = catalogFixture(root);
      const appRoot = path.join(workloadRoot, "example-app");
      const outside = path.join(root, "outside-app");
      fs.cpSync(appRoot, outside, { recursive: true });
      let swapped = false;
      assert.throws(() => resolveCatalog({
        ...fixture,
        workloadRoot,
        coreFiles: [fixture.coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(root, "snapshots"),
        sourceAccessHook(_source, label) {
          if (swapped || label !== targetKind) return;
          swapped = true;
          fs.renameSync(appRoot, `${appRoot}.original`);
          fs.symlinkSync(outside, appRoot, "dir");
        },
      }), /symlink component|identity changed|physical root/);
      assert.equal(swapped, true);
    } finally {
      removeFixtureTree(root);
    }
  }
});

test("migration enumeration rejects a deterministic parent-directory swap", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-migration-race-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const appRoot = path.join(workloadRoot, "example-app");
    const manifestPath = path.join(appRoot, "manifest.json");
    const manifestDocument = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifestDocument.migrationRoots = ["postgres/migrations"];
    fs.writeFileSync(manifestPath, JSON.stringify(manifestDocument));
    const migrations = path.join(appRoot, "postgres", "migrations");
    fs.mkdirSync(migrations, { recursive: true });
    fs.writeFileSync(path.join(migrations, "001.sql"), "SELECT 1;\n");
    const outside = path.join(root, "outside-migrations");
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, "001.sql"), "SELECT 'hostile';\n");
    let swapped = false;
    assert.throws(() => resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
      sourceAccessHook(_source, label) {
        if (swapped || label !== "migration root") return;
        swapped = true;
        fs.renameSync(migrations, `${migrations}.original`);
        fs.symlinkSync(outside, migrations, "dir");
      },
    }), /symlink component|identity changed|physical root/);
    assert.equal(swapped, true);
  } finally {
    removeFixtureTree(root);
  }
});

test("activation paths remain bound to immutable snapshots after source replacement", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-snapshot-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const originalCompose = fs.readFileSync(lock.workloads[0].composePath, "utf8");
    fs.writeFileSync(lock.workloads[0].composeSourcePath, "services:\n  hostile:\n    privileged: true\n");
    const replacement = path.join(root, "replacement.yaml");
    fs.writeFileSync(replacement, "services:\n  replaced: {}\n");
    fs.renameSync(replacement, lock.workloads[0].composeSourcePath);
    fs.unlinkSync(lock.workloads[0].composeSourcePath);
    fs.symlinkSync(path.join(root, "hostile.yaml"), lock.workloads[0].composeSourcePath);
    fs.writeFileSync(path.join(root, "hostile.yaml"), "services:\n  linked:\n    privileged: true\n");
    assert.equal(fs.readFileSync(lock.workloads[0].composePath, "utf8"), originalCompose);
    assert.equal(verifyLockFiles(lock), true);
  } finally {
    removeFixtureTree(root);
  }
});

test("optional project metadata is exported as a verified workload-owned snapshot record", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-project-metadata-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const appRoot = path.join(workloadRoot, "example-app");
    const manifestPath = path.join(appRoot, "manifest.json");
    const manifestDocument = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifestDocument.projectMetadataFile = ".platform/project.json";
    fs.writeFileSync(manifestPath, JSON.stringify(manifestDocument));
    fs.mkdirSync(path.join(appRoot, ".platform"));
    fs.writeFileSync(path.join(appRoot, ".platform", "project.json"), '{"name":"Example"}\n');
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const record = lock.files.find((item) => item.kind === "project-metadata");
    assert.equal(record.workloadId, "example-app");
    assert.equal(record.path, lock.workloads[0].projectMetadataPath);
    assert.equal(record.sourcePath, lock.workloads[0].projectMetadataSourcePath);
    assert.match(record.sha256, /^[a-f0-9]{64}$/);
    fs.writeFileSync(record.sourcePath, '{"name":"Changed"}\n');
    assert.equal(verifyLockFiles(lock), true);
  } finally {
    removeFixtureTree(root);
  }
});

test("lock verification rejects snapshot parent and generation replacement", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-snapshot-parent-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const originalRoot = `${lock.snapshotRoot}.original`;
    fs.renameSync(lock.snapshotRoot, originalRoot);
    fs.symlinkSync(originalRoot, lock.snapshotRoot, "dir");
    assert.throws(() => verifyLockFiles(lock), /symlink component/);
    fs.unlinkSync(lock.snapshotRoot);
    fs.renameSync(originalRoot, lock.snapshotRoot);

    const originalGeneration = `${lock.snapshotGeneration}.original`;
    fs.renameSync(lock.snapshotGeneration, originalGeneration);
    fs.mkdirSync(lock.snapshotGeneration, { mode: 0o700 });
    fs.chmodSync(lock.snapshotGeneration, 0o500);
    assert.throws(() => verifyLockFiles(lock), /identity changed/);
  } finally {
    removeFixtureTree(root);
  }
});

test("compose-files CLI never emits a path not exactly bound to a compose snapshot record", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-pointer-tamper-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const lockPath = path.join(root, "lock.json");
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
    const rawPolicy = spawnSync("ruby", [path.join(import.meta.dirname, "hosted-workload-source-policy.rb"), "--lock", lockPath], { encoding: "utf8" });
    assert.equal(rawPolicy.status, 0, rawPolicy.stderr);
    const contractScript = path.join(import.meta.dirname, "hosted-workload-contract.mjs");
    const valid = spawnSync(process.execPath, [contractScript, "compose-files", "--lock", lockPath, "--allowResolved", "true"], { encoding: "utf8" });
    assert.equal(valid.status, 0, valid.stderr);
    assert.equal(valid.stdout.trim(), lock.workloads[0].composePath);

    const minimalBin = path.join(root, "minimal-bin");
    fs.mkdirSync(minimalBin);
    let realJq;
    for (const command of ["jq", "stat", "awk", "dirname", "id"]) {
      const executable = executablePath(command);
      assert.ok(executable, `${command} is required by the host lock reader test`);
      fs.symlinkSync(executable, path.join(minimalBin, command));
      if (command === "jq") realJq = executable;
    }
    const shaCommand = executablePath("sha256sum") ? "sha256sum" : "shasum";
    const shaExecutable = executablePath(shaCommand);
    assert.ok(shaExecutable, "a SHA-256 utility is required by the host lock reader test");
    fs.symlinkSync(shaExecutable, path.join(minimalBin, shaCommand));
    assert.equal(fs.existsSync(path.join(minimalBin, "node")), false);
    const shellReader = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), lockPath, "compose-files"], {
      encoding: "utf8",
      env: { PATH: minimalBin, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
    });
    assert.equal(shellReader.status, 0, shellReader.stderr);
    assert.equal(shellReader.stdout.trim(), lock.workloads[0].composePath);
    const verifiedActivation = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    verifiedActivation.state = "verified";
    fs.writeFileSync(verifiedActivation.activationLockPath, `${JSON.stringify(verifiedActivation, null, 2)}\n`, { mode: 0o600 });
    const finalShellReader = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), verifiedActivation.activationLockPath, "compose-files"], {
      encoding: "utf8",
      env: { PATH: minimalBin, HOSTED_WORKLOAD_ALLOW_RESOLVED: "0" },
    });
    assert.equal(finalShellReader.status, 0, finalShellReader.stderr);
    assert.equal(finalShellReader.stdout.trim(), lock.workloads[0].composePath);

    const hostilePath = path.join(root, "hostile.yaml");
    fs.writeFileSync(hostilePath, "services:\n  hostile:\n    privileged: true\n");
    const verifiedLockText = fs.readFileSync(lockPath, "utf8");
    const raceReplacementPath = path.join(root, "race-replacement.json");
    const raceReplacement = JSON.parse(verifiedLockText);
    raceReplacement.workloads[0].composePath = hostilePath;
    fs.writeFileSync(raceReplacementPath, `${JSON.stringify(raceReplacement, null, 2)}\n`, { mode: 0o600 });
    fs.unlinkSync(path.join(minimalBin, "jq"));
    fs.writeFileSync(path.join(minimalBin, "jq"), `#!/bin/sh
if [ "\${HOSTED_TEST_SWAP_ON_CONSUMER:-0}" = 1 ]; then
  case "$*" in
    *'.workloads[].composePath'*) /bin/mv "$HOSTED_TEST_REPLACEMENT" "$HOSTED_TEST_LOCK" ;;
  esac
fi
exec "$HOSTED_TEST_REAL_JQ" "$@"
`, { mode: 0o755 });
    const raced = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), lockPath, "compose-files"], {
      encoding: "utf8",
      env: {
        PATH: minimalBin,
        HOSTED_WORKLOAD_ALLOW_RESOLVED: "1",
        HOSTED_TEST_SWAP_ON_CONSUMER: "1",
        HOSTED_TEST_REPLACEMENT: raceReplacementPath,
        HOSTED_TEST_LOCK: lockPath,
        HOSTED_TEST_REAL_JQ: realJq,
      },
    });
    assert.notEqual(raced.status, 0);
    assert.doesNotMatch(raced.stdout, /hostile\.yaml/);
    assert.match(raced.stderr, /lock changed while being verified/i);
    fs.writeFileSync(lockPath, verifiedLockText, { mode: 0o600 });

    const tampered = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    tampered.workloads[0].composePath = hostilePath;
    fs.writeFileSync(lockPath, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
    const rejected = spawnSync(process.execPath, [contractScript, "compose-files", "--lock", lockPath, "--allowResolved", "true"], { encoding: "utf8" });
    assert.notEqual(rejected.status, 0);
    assert.doesNotMatch(rejected.stdout, /hostile\.yaml/);
    assert.match(rejected.stderr, /activation pointers are not exactly bound/);
    const shellRejected = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), lockPath, "compose-files"], {
      encoding: "utf8",
      env: { PATH: minimalBin, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
    });
    assert.notEqual(shellRejected.status, 0);
    assert.doesNotMatch(shellRejected.stdout, /hostile\.yaml/);
  } finally {
    removeFixtureTree(root);
  }
});

test("workload environment accepts only non-secret prefixed variables", () => {
  assert.deepEqual(
    validateWorkloadEnvironmentText("EXAMPLE_APP_IMAGE=registry.example/app@sha256:abc\nEXAMPLE_APP_SMTP_HOST=smtp.example.test\n", "example-app"),
    ["EXAMPLE_APP_IMAGE", "EXAMPLE_APP_SMTP_HOST"],
  );
  assert.throws(
    () => validateWorkloadEnvironmentText("EXAMPLE_APP_DATABASE_URL=postgres://user:password@postgres/db\n", "example-app"),
    /sensitive variable/,
  );
  assert.throws(
    () => validateWorkloadEnvironmentText("UNSCOPED_IMAGE=registry.example/app@sha256:abc\n", "example-app"),
    /EXAMPLE_APP_/,
  );
});

process.stdout.write(`hosted workload contract tests passed ${passed}/${passed}\n`);
