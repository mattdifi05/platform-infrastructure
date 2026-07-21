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
  logging: { driver: "local", options: { "max-size": "10m", "max-file": "3" } },
  pids_limit: 128,
  cpu_shares: 256,
  blkio_config: { weight: 300 },
  ulimits: { nofile: { soft: 8192, hard: 8192 } },
  cpus: 0.5,
  mem_limit: String(256 * 1024 * 1024),
  memswap_limit: String(256 * 1024 * 1024),
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
    networks: {
      platform_routing: { internal: true },
      example_app_ingress: { internal: true, name: "fixture_example_app_ingress" },
      example_app_egress: {
        internal: false,
        enable_ipv6: false,
        name: "fixture_example_app_egress",
      },
    },
    secrets: { "example-app-database-url": { external: true, name: "fixture_example-app-database-url" } },
  };
}

const lock = {
  projectName: "fixture",
  workloads: [manifest],
  brokerPolicySha256: brokerPolicySha256([manifest]),
};
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
test("workload volumes are bound to project-owned physical names", () => {
  const valid = combinedFixture();
  valid.volumes = { "example-app_data": { name: "fixture_example-app_data" } };
  valid.services["example-app-web"].volumes = [{ type: "volume", source: "example-app_data", target: "/data" }];
  assert.doesNotThrow(() => validateRenderedWorkloads({ core, combined: valid, lock: { ...lock, projectName: "fixture" } }));

  for (const definition of [
    { external: true, name: "foreign_data" },
    { name: "foreign_data" },
    {},
  ]) {
    const combined = combinedFixture();
    combined.volumes = { "example-app_data": definition };
    combined.services["example-app-web"].volumes = [{ type: "volume", source: "example-app_data", target: "/data" }];
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock: { ...lock, projectName: "fixture" } }),
      /must bind physical volume fixture_example-app_data/,
    );
  }
});
test("service volume inheritance is rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].volumes_from = ["postgres:rw"];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot inherit volumes/);

  const externalContainer = combinedFixture();
  externalContainer.services["example-app-web"].volumes_from = ["container:platform-postgres:rw"];
  assert.throws(() => validateRenderedWorkloads({ core, combined: externalContainer, lock }), /cannot inherit volumes/);
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
    (service) => { service.deploy = { mode: "global" }; },
  ]) {
    const combined = combinedFixture();
    mutation(combined.services["example-app-web"]);
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot request service scaling/);
  }
});
test("Compose wrapper rejects caller-controlled scaling flags before execution", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-cli-scale-")));
  try {
    const envFile = path.join(root, "core.env");
    const fakeBin = path.join(root, "bin");
    const marker = path.join(root, "docker-called");
    fs.writeFileSync(envFile, "CORE_VALUE=fixture\n");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh\nprintf called > "$HOSTED_TEST_DOCKER_MARKER"\n`, { mode: 0o755 });
    const result = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "up", "--scale", "example-app-web=100"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH}`,
        COMPOSE_ENV_FILE: envFile,
        HOSTED_TEST_DOCKER_MARKER: marker,
      },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /caller-controlled scaling is forbidden/i);
    assert.equal(fs.existsSync(marker), false);
  } finally {
    removeFixtureTree(root);
  }
});
test("host port is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].ports = [{ target: 3000, published: "3000" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /host ports/);
});
test("PID sharing and non-canonical workload users are rejected", () => {
  for (const user of ["0:0", "app:app", "1000", "1000:root"]) {
    const combined = combinedFixture();
    combined.services["example-app-web"].user = user;
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /canonical numeric non-root uid:gid/);
  }
  for (const pid of ["host", "service:postgres", "container:foreign"]) {
    const combined = combinedFixture();
    combined.services["example-app-web"].pid = pid;
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot share another PID namespace/);
  }
});
test("workload logging is local and rotation-bounded", () => {
  for (const logging of [
    undefined,
    { driver: "json-file", options: { "max-size": "10m", "max-file": "3" } },
    { driver: "local" },
    { driver: "local", options: { "max-size": "1g", "max-file": "99" } },
  ]) {
    const combined = combinedFixture();
    combined.services["example-app-web"].logging = logging;
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /must use local logging/);
  }
});
test("workload swap and OOM policy is fail-closed", () => {
  const swap = combinedFixture();
  swap.services["example-app-web"].memswap_limit = String(512 * 1024 * 1024);
  assert.throws(() => validateRenderedWorkloads({ core, combined: swap, lock }), /memswap_limit equal to mem_limit/);
  for (const field of ["oom_kill_disable", "oom_score_adj", "mem_swappiness"]) {
    const combined = combinedFixture();
    combined.services["example-app-web"][field] = field === "oom_kill_disable" ? true : 0;
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot override OOM or swappiness controls/);
  }
});
test("literal secret environment is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].environment.DATABASE_URL = "postgres://user:password@postgres/db";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /sensitive environment/);
});
test("secrets must bind workload-owned external physical names", () => {
  for (const definition of [
    { file: "/tmp/secret" },
    { external: true },
    { external: true, name: "foreign_database_url" },
  ]) {
    const combined = combinedFixture();
    combined.secrets["example-app-database-url"] = definition;
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /must bind workload-owned external secret/);
  }
});
test("file-backed configs and workload config grants are rejected after render", () => {
  const fileBacked = combinedFixture();
  fileBacked.configs = { host_data: { file: "/etc/hosts" } };
  assert.throws(() => validateRenderedWorkloads({ core, combined: fileBacked, lock }), /cannot use a host file source/);

  const granted = combinedFixture();
  granted.configs = { platform_config: { external: true } };
  granted.services["example-app-web"].configs = [{ source: "platform_config", target: "/run/config" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined: granted, lock }), /cannot mount platform or host-backed configs/);

  for (const definition of [{ content: "hostile" }, { environment: "HOST_SECRET" }]) {
    const combined = combinedFixture();
    combined.configs = { example_app_inline: definition };
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot use inline or host-environment content/);
  }
});
test("host device controls are rejected after render", () => {
  for (const mutation of [
    (service) => { service.devices = [{ source: "/dev/kvm", target: "/dev/kvm" }]; },
    (service) => { service.device_cgroup_rules = ["c 10:232 rwm"]; },
  ]) {
    const combined = combinedFixture();
    mutation(combined.services["example-app-web"]);
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot request host device access/);
  }
});
test("supplemental device groups are rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].group_add = ["video", "44"];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot add supplemental groups/);
});
test("local volume driver options are rejected after render", () => {
  const combined = combinedFixture();
  combined.volumes = {
    example_app_data: {
      driver: "local",
      driver_opts: { type: "none", o: "bind", device: "/srv/platform" },
    },
  };
  combined.services["example-app-web"].volumes = [{ type: "volume", source: "example_app_data", target: "/data" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot use local driver options/);
});
test("Compose API socket access is rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].use_api_socket = true;
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot use the Compose API socket/);
});
test("external service providers are rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].provider = { type: "hostile-provider", options: { command: "/host/tool" } };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot delegate execution to a provider/);
});
test("OCI runtime overrides are rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].runtime = "kata-runtime";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot override the OCI runtime/);
});
test("stop grace period overrides are rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].stop_grace_period = "24h";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot override the stop grace period/);
});
test("GPU and accelerator requests are rejected after render", () => {
  for (const mutation of [
    (service) => { service.gpus = "all"; },
    (service) => { service.device_requests = [{ capabilities: [["gpu"]] }]; },
    (service) => { service.deploy = { resources: { reservations: { devices: [{ driver: "nvidia", capabilities: ["gpu"] }] } } }; },
  ]) {
    const combined = combinedFixture();
    mutation(combined.services["example-app-web"]);
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot request GPU or accelerator access/);
  }
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
      () => validateRenderedWorkloads({
        core,
        combined,
        lock: {
          projectName: "fixture",
          workloads: [manifest],
          brokerPolicySha256: brokerPolicySha256([manifest]),
        },
      }),
      /cannot alias foreign physical network/,
    );
  }
  const combined = combinedFixture();
  combined.networks.example_app_ingress.name = "fixture_example_app_ingress";
  assert.doesNotThrow(() => validateRenderedWorkloads({
    core,
    combined,
    lock: {
      projectName: "fixture",
      workloads: [manifest],
      brokerPolicySha256: brokerPolicySha256([manifest]),
    },
  }));
  for (const attachment of [{ aliases: ["postgres"] }, { ipv4_address: "172.30.0.2" }, { gw_priority: 999 }]) {
    const aliased = combinedFixture();
    aliased.services["example-app-web"].networks.example_app_ingress = attachment;
    assert.throws(() => validateRenderedWorkloads({ core, combined: aliased, lock }), /cannot set aliases or address overrides/);
  }
});
test("workload networks reject every caller-controlled topology knob", () => {
  for (const mutate of [
    (network) => { network.internal = false; },
    (network) => { network.driver = "bridge"; },
    (network) => { network.driver_opts = { "com.docker.network.bridge.name": "host0" }; },
    (network) => { network.ipam = { config: [{ subnet: "172.30.0.0/16" }] }; },
    (network) => { network.attachable = true; },
    (network) => { network.labels = { "com.docker.compose.network": "platform_docker_control" }; },
    (network) => { network.enable_ipv4 = false; },
    (network) => { network.enable_ipv6 = true; },
  ]) {
    const combined = combinedFixture();
    mutate(combined.networks.example_app_ingress);
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock: { projectName: "fixture", workloads: [manifest] } }), /exact ingress topology/);
  }
  const egress = combinedFixture();
  egress.services["example-app-worker"].networks = { example_app_egress: null };
  delete egress.networks.example_app_bus;
  egress.networks.example_app_egress = { internal: false, name: "fixture_example_app_egress" };
  assert.doesNotThrow(() => validateRenderedWorkloads({ core, combined: egress, lock }));
});
test("platform service can join only its assigned workload zone", () => {
  const combined = combinedFixture();
  combined.services["project-router"].networks.example_app_cache = null;
  combined.networks.example_app_cache = { internal: true };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot join workload example-app zone cache/);
});
test("platform services preserve every original network attachment", () => {
  const removed = combinedFixture();
  delete removed.services["project-router"].networks.platform_routing;
  assert.throws(() => validateRenderedWorkloads({ core, combined: removed, lock }), /removed or changed protected network attachment/);

  const changed = combinedFixture();
  changed.services["project-router"].networks.platform_routing = { aliases: ["impersonate-router"] };
  assert.throws(() => validateRenderedWorkloads({ core, combined: changed, lock }), /removed or changed protected network attachment/);
});
test("deployment-private activation state has no non-router writable mount", () => {
  const privateLock = "/deployment-private/hosted-workloads.lock.json";
  const lockWithActivation = {
    projectName: "fixture",
    workloads: [manifest],
    brokerPolicySha256: brokerPolicySha256([manifest]),
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
      tenant_app_cache: { internal: true, name: "fixture_tenant_app_cache" },
      tenant_app_bus: { internal: true, name: "fixture_tenant_app_bus" },
    },
    secrets: {
      redis_password: { external: true },
      nats_password: { external: true },
      "tenant-app-redis-password": { external: true, name: "fixture_tenant-app-redis-password" },
      "tenant-app-bus-nats-password": { external: true, name: "fixture_tenant-app-bus-nats-password" },
    },
  };
  return {
    core: brokerCore,
    combined,
    lock: { projectName: "fixture", workloads: [workload], brokerPolicySha256: brokerPolicySha256([workload]) },
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
    controls: ["bind-bounded-local-logging", "bind-network-identity", "bind-network-topology", "bind-no-swap-oom-policy", "bind-owned-secret-aliases", "bind-owned-volumes", "bind-private-pid-numeric-user", "deny-api-socket", "deny-compose-interpolation", "deny-device-access", "deny-env-file", "deny-extends", "deny-file-configs", "deny-gpu-access", "deny-include", "deny-inline-configs", "deny-lifecycle-hooks", "deny-local-volume-options", "deny-providers", "deny-runtime-overrides", "deny-scaling", "deny-stop-grace-overrides", "deny-supplemental-groups", "deny-volumes-from"],
    workloadContentSha256: "a".repeat(64),
    workloads: [{
      workloadId: "example-app",
      composeSha256: "c".repeat(64),
      networkNames: [],
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
    rawPolicyControls: ["bind-bounded-local-logging", "bind-network-identity", "bind-network-topology", "bind-no-swap-oom-policy", "bind-owned-secret-aliases", "bind-owned-volumes", "bind-private-pid-numeric-user", "deny-api-socket", "deny-compose-interpolation", "deny-device-access", "deny-env-file", "deny-extends", "deny-file-configs", "deny-gpu-access", "deny-include", "deny-inline-configs", "deny-lifecycle-hooks", "deny-local-volume-options", "deny-providers", "deny-runtime-overrides", "deny-scaling", "deny-stop-grace-overrides", "deny-supplemental-groups", "deny-volumes-from"],
  };
  assert.doesNotThrow(() => verifyRawPolicyReceipt(receipt));
  receipt.rawPolicyControls = ["deny-include"];
  assert.throws(() => verifyRawPolicyReceipt(receipt), /raw source policy receipt/);
  receipt.rawPolicyControls = ["bind-bounded-local-logging", "bind-network-identity", "bind-network-topology", "bind-no-swap-oom-policy", "bind-owned-secret-aliases", "bind-owned-volumes", "bind-private-pid-numeric-user", "deny-api-socket", "deny-compose-interpolation", "deny-device-access", "deny-env-file", "deny-extends", "deny-file-configs", "deny-gpu-access", "deny-include", "deny-inline-configs", "deny-lifecycle-hooks", "deny-local-volume-options", "deny-providers", "deny-runtime-overrides", "deny-scaling", "deny-stop-grace-overrides", "deny-supplemental-groups", "deny-volumes-from"];
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
  fs.writeFileSync(path.join(appRoot, "compose.yaml"), "services:\n  example-app-web:\n    networks:\n      example_app_ingress:\nnetworks:\n  example_app_ingress:\n    internal: true\n");
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
    const repeated = resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture", snapshotRoot });
    assert.equal(repeated.snapshotGeneration, result.snapshotGeneration);
    verifyLockFiles(repeated);
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

test("descriptor-relative snapshot creation fails before a root symlink swap can write outside", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-root-create-race-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const snapshotRoot = path.join(root, "snapshots");
    const originalRoot = `${snapshotRoot}.original`;
    const outside = path.join(root, "outside");
    fs.mkdirSync(snapshotRoot, { mode: 0o700 });
    fs.mkdirSync(outside, { mode: 0o700 });
    let swapped = false;
    assert.throws(() => resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot,
      snapshotAccessHook(_snapshot, label) {
        if (swapped || label !== "before descriptor-relative snapshot create") return;
        swapped = true;
        fs.renameSync(snapshotRoot, originalRoot);
        fs.symlinkSync(outside, snapshotRoot, "dir");
      },
    }), /[Dd]escriptor-relative snapshot create failed|identity changed/);
    assert.equal(swapped, true);
    assert.deepEqual(fs.readdirSync(outside), []);
    fs.unlinkSync(snapshotRoot);
    fs.renameSync(originalRoot, snapshotRoot);
  } finally {
    removeFixtureTree(root);
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
    for (const command of ["jq", "stat", "awk", "dirname", "id", "mktemp", "chmod"]) {
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
    const shellReader = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), lockPath, "compose-records"], {
      encoding: "utf8",
      env: { PATH: minimalBin, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
    });
    assert.equal(shellReader.status, 0, shellReader.stderr);
    assert.equal(shellReader.stdout.trim().split("\t")[0], lock.workloads[0].composePath);
    const verifiedActivation = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    verifiedActivation.state = "verified";
    fs.writeFileSync(verifiedActivation.activationLockPath, `${JSON.stringify(verifiedActivation, null, 2)}\n`, { mode: 0o600 });
    const finalShellReader = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), verifiedActivation.activationLockPath, "compose-records"], {
      encoding: "utf8",
      env: { PATH: minimalBin, HOSTED_WORKLOAD_ALLOW_RESOLVED: "0" },
    });
    assert.equal(finalShellReader.status, 0, finalShellReader.stderr);
    assert.equal(finalShellReader.stdout.trim().split("\t")[0], lock.workloads[0].composePath);

    const hostilePath = path.join(root, "hostile.yaml");
    fs.writeFileSync(hostilePath, "services:\n  hostile:\n    privileged: true\n");
    const verifiedLockText = fs.readFileSync(lockPath, "utf8");
    const raceReplacementPath = path.join(root, "race-replacement.json");
    const raceReplacement = JSON.parse(verifiedLockText);
    raceReplacement.workloads[0].composePath = hostilePath;
    fs.writeFileSync(raceReplacementPath, `${JSON.stringify(raceReplacement, null, 2)}\n`, { mode: 0o600 });
    const raceOriginalPath = path.join(root, "race-original.json");
    fs.writeFileSync(raceOriginalPath, verifiedLockText, { mode: 0o600 });
    fs.unlinkSync(path.join(minimalBin, "jq"));
    fs.writeFileSync(path.join(minimalBin, "jq"), `#!/bin/sh
if [ -n "\${HOSTED_TEST_SWAP_MODE:-}" ]; then
  case "$*" in
    *'workload-compose'*'@tsv'*|*'.composeRecords'*'@tsv'*)
      for argument in "$@"; do
        case "$argument" in
          */hosted-workload-lock.*/lock.json)
            /bin/cp "$HOSTED_TEST_REPLACEMENT" "$argument"
            : > "$HOSTED_TEST_PRIVATE_LOCK_MARKER"
            ;;
        esac
      done
      case "$HOSTED_TEST_SWAP_MODE" in
        transient)
          /bin/cp "$HOSTED_TEST_REPLACEMENT" "$HOSTED_TEST_LOCK"
          "$HOSTED_TEST_REAL_JQ" "$@"
          status=$?
          /bin/cp "$HOSTED_TEST_ORIGINAL" "$HOSTED_TEST_LOCK"
          exit "$status"
          ;;
        replace) /bin/mv "$HOSTED_TEST_REPLACEMENT" "$HOSTED_TEST_LOCK" ;;
      esac
      ;;
  esac
fi
exec "$HOSTED_TEST_REAL_JQ" "$@"
`, { mode: 0o755 });
    const lockInode = fs.statSync(lockPath).ino;
    const transient = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), lockPath, "compose-records"], {
      encoding: "utf8",
      env: {
        PATH: minimalBin,
        HOSTED_WORKLOAD_ALLOW_RESOLVED: "1",
        HOSTED_TEST_SWAP_MODE: "transient",
        HOSTED_TEST_REPLACEMENT: raceReplacementPath,
        HOSTED_TEST_ORIGINAL: raceOriginalPath,
        HOSTED_TEST_LOCK: lockPath,
        HOSTED_TEST_REAL_JQ: realJq,
        HOSTED_TEST_PRIVATE_LOCK_MARKER: path.join(root, "private-lock-path-reopened"),
      },
    });
    assert.doesNotMatch(transient.stdout, /hostile\.yaml/);
    if (transient.status === 0) {
      assert.equal(transient.stdout.trim().split("\t")[0], lock.workloads[0].composePath);
    } else {
      assert.match(transient.stderr, /lock changed while being verified/i);
    }
    assert.equal(fs.statSync(lockPath).ino, lockInode);

    const raced = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), lockPath, "compose-records"], {
      encoding: "utf8",
      env: {
        PATH: minimalBin,
        HOSTED_WORKLOAD_ALLOW_RESOLVED: "1",
        HOSTED_TEST_SWAP_MODE: "replace",
        HOSTED_TEST_REPLACEMENT: raceReplacementPath,
        HOSTED_TEST_LOCK: lockPath,
        HOSTED_TEST_REAL_JQ: realJq,
        HOSTED_TEST_PRIVATE_LOCK_MARKER: path.join(root, "private-lock-path-reopened"),
      },
    });
    assert.doesNotMatch(raced.stdout, /hostile\.yaml/);
    if (raced.status === 0) {
      assert.equal(raced.stdout.trim().split("\t")[0], lock.workloads[0].composePath);
    } else {
      assert.match(raced.stderr, /lock changed while being (verified|snapshotted)/i);
    }
    assert.equal(fs.existsSync(path.join(root, "private-lock-path-reopened")), false);
    fs.writeFileSync(lockPath, verifiedLockText, { mode: 0o600 });

    const tampered = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    tampered.workloads[0].composePath = hostilePath;
    fs.writeFileSync(lockPath, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
    const rejected = spawnSync(process.execPath, [contractScript, "compose-files", "--lock", lockPath, "--allowResolved", "true"], { encoding: "utf8" });
    assert.notEqual(rejected.status, 0);
    assert.doesNotMatch(rejected.stdout, /hostile\.yaml/);
    assert.match(rejected.stderr, /activation pointers are not exactly bound/);
    const shellRejected = spawnSync("/bin/sh", [path.join(import.meta.dirname, "hosted-workload-lock.sh"), lockPath, "compose-records"], {
      encoding: "utf8",
      env: { PATH: minimalBin, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
    });
    assert.notEqual(shellRejected.status, 0);
    assert.doesNotMatch(shellRejected.stdout, /hostile\.yaml/);
  } finally {
    removeFixtureTree(root);
  }
});

test("compose wrapper uses one activation bundle and hands verified bytes through persistent descriptors", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-fd-handoff-")));
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

    const fakeBin = path.join(root, "fake-bin");
    const capture = path.join(root, "consumer-capture.txt");
    const originalGeneration = `${lock.snapshotGeneration}.original`;
    const composeBasename = path.basename(lock.workloads[0].composePath);
    const realJq = executablePath("jq");
    const shaCommand = executablePath("sha256sum") ? "sha256sum" : "shasum";
    const realSha = executablePath(shaCommand);
    assert.ok(realJq, "jq is required by the descriptor handoff race test");
    assert.ok(realSha, "a SHA-256 utility is required by the descriptor handoff race test");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/bash
set -euo pipefail
/bin/mv "$HOSTED_TEST_GENERATION" "$HOSTED_TEST_ORIGINAL_GENERATION"
/bin/mkdir -m 700 "$HOSTED_TEST_GENERATION"
printf 'services:\n  hostile:\n    privileged: true\n' > "$HOSTED_TEST_GENERATION/$HOSTED_TEST_COMPOSE_BASENAME"
/bin/chmod 400 "$HOSTED_TEST_GENERATION/$HOSTED_TEST_COMPOSE_BASENAME"
/bin/chmod 500 "$HOSTED_TEST_GENERATION"
: > "$HOSTED_TEST_CAPTURE"
for argument in "$@"; do
  case "$argument" in
    /dev/fd/*)
      printf '%s\n' "---$argument" >> "$HOSTED_TEST_CAPTURE"
      /bin/cat "$argument" >> "$HOSTED_TEST_CAPTURE"
      ;;
  esac
done
`, { mode: 0o755 });
    fs.writeFileSync(path.join(fakeBin, "sh"), `#!/bin/sh
count=0
if [ -f "$HOSTED_TEST_LOCK_READER_COUNT" ]; then
  IFS= read -r count < "$HOSTED_TEST_LOCK_READER_COUNT"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$HOSTED_TEST_LOCK_READER_COUNT"
exec /bin/sh "$@"
`, { mode: 0o755 });
    fs.writeFileSync(path.join(fakeBin, "jq"), `#!/bin/sh
if [ "\${HOSTED_TEST_QUERY_SWAP:-0}" = 1 ]; then
  case "$*" in
    *'workload-compose'*'@tsv'*|*'.composeRecords'*'@tsv'*)
      /bin/mv "$HOSTED_TEST_GENERATION" "$HOSTED_TEST_ORIGINAL_GENERATION"
      /bin/mkdir -m 700 "$HOSTED_TEST_GENERATION"
      printf 'services:\n  hostile:\n    privileged: true\n' > "$HOSTED_TEST_GENERATION/$HOSTED_TEST_COMPOSE_BASENAME"
      /bin/chmod 400 "$HOSTED_TEST_GENERATION/$HOSTED_TEST_COMPOSE_BASENAME"
      /bin/chmod 500 "$HOSTED_TEST_GENERATION"
      ;;
  esac
fi
exec "$HOSTED_TEST_REAL_JQ" "$@"
`, { mode: 0o755 });
    const sharedEnvironment = {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      COMPOSE_ENV_FILE: fixture.coreEnvFile,
      COMPOSE_PROJECT_NAME: "fixture",
      HOSTED_WORKLOAD_LOCK: lockPath,
      HOSTED_WORKLOAD_ALLOW_RESOLVED: "1",
      HOSTED_TEST_GENERATION: lock.snapshotGeneration,
      HOSTED_TEST_ORIGINAL_GENERATION: originalGeneration,
      HOSTED_TEST_COMPOSE_BASENAME: composeBasename,
      HOSTED_TEST_CAPTURE: capture,
      HOSTED_TEST_REAL_JQ: realJq,
      HOSTED_TEST_REAL_SHA: realSha,
      HOSTED_TEST_TMPDIR: root,
      HOSTED_TEST_HASH_RACE_MARKER: path.join(root, "hash-race-fired"),
      HOSTED_TEST_LOCK_READER_COUNT: path.join(root, "lock-reader-count"),
      TMPDIR: root,
    };
    const queryRace = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "config", "--format", "json"], {
      encoding: "utf8",
      env: { ...sharedEnvironment, HOSTED_TEST_QUERY_SWAP: "1" },
    });
    assert.notEqual(queryRace.status, 0);
    assert.match(queryRace.stderr, /handoff object (identity changed|could not be opened)/i);
    assert.equal(fs.existsSync(capture), false);
    assert.equal(fs.readFileSync(sharedEnvironment.HOSTED_TEST_LOCK_READER_COUNT, "utf8").trim(), "1");
    removeFixtureTree(lock.snapshotGeneration);
    fs.renameSync(originalGeneration, lock.snapshotGeneration);
    fs.unlinkSync(path.join(fakeBin, "jq"));
    fs.writeFileSync(sharedEnvironment.HOSTED_TEST_LOCK_READER_COUNT, "0\n");
    fs.writeFileSync(path.join(fakeBin, shaCommand), `#!/bin/sh
output=$("$HOSTED_TEST_REAL_SHA" "$@")
status=$?
target=
for argument in "$@"; do
  case "$argument" in
    "$HOSTED_TEST_TMPDIR"/hosted-compose-handoff.*/object-*) target=$argument ;;
  esac
done
if [ -z "$target" ]; then
  for candidate in "$HOSTED_TEST_TMPDIR"/hosted-compose-handoff.*/object-*; do
    [ -e "$candidate" ] || continue
    target=$candidate
    break
  done
fi
if [ -n "$target" ] && [ -e "$target" ]; then
  printf 'services:\n  hostile:\n    privileged: true\n' > "$target.replacement"
  /bin/mv "$target.replacement" "$target"
  : > "$HOSTED_TEST_HASH_RACE_MARKER"
fi
printf '%s\n' "$output"
exit "$status"
`, { mode: 0o755 });

    const consumer = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "config", "--format", "json"], {
      encoding: "utf8",
      env: sharedEnvironment,
    });
    assert.equal(consumer.status, 0, consumer.stderr);
    const consumed = fs.readFileSync(capture, "utf8");
    assert.match(consumed, /example-app-web/);
    assert.match(consumed, /EXAMPLE_APP_THEME=dark/);
    assert.doesNotMatch(consumed, /privileged: true/);
    assert.equal(fs.existsSync(sharedEnvironment.HOSTED_TEST_HASH_RACE_MARKER), false);
    assert.equal(fs.readFileSync(sharedEnvironment.HOSTED_TEST_LOCK_READER_COUNT, "utf8").trim(), "1");
    assert.notEqual(fs.statSync(lock.snapshotGeneration).ino, Number(lock.snapshotGenerationIdentity.inode));
  } finally {
    removeFixtureTree(root);
  }
});

test("Engine network ownership verifier binds exact physical names and Compose labels", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-network-owner-")));
  try {
    const fixture = catalogFixture(root);
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot: path.join(root, "workloads"),
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const lockPath = path.join(root, "lock.json");
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
    const rawPolicy = spawnSync("ruby", [path.join(import.meta.dirname, "hosted-workload-source-policy.rb"), "--lock", lockPath], { encoding: "utf8" });
    assert.equal(rawPolicy.status, 0, rawPolicy.stderr);

    const fakeBin = path.join(root, "fake-bin");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/bash
set -euo pipefail
if [[ "\${1:-}" == network && "\${2:-}" == inspect ]]; then
  case "\${HOSTED_TEST_NETWORK_MODE:-correct}" in
    correct) printf '[{"Name":"fixture_example_app_ingress","Labels":{"com.docker.compose.project":"fixture","com.docker.compose.network":"example_app_ingress"}}]\n' ;;
    wrong-project) printf '[{"Name":"fixture_example_app_ingress","Labels":{"com.docker.compose.project":"attacker","com.docker.compose.network":"example_app_ingress"}}]\n' ;;
    wrong-logical) printf '[{"Name":"fixture_example_app_ingress","Labels":{"com.docker.compose.project":"fixture","com.docker.compose.network":"platform_docker_control"}}]\n' ;;
    invalid-json) printf '{not-json\n' ;;
    duplicate) printf '[{"Name":"fixture_example_app_ingress","Labels":{"com.docker.compose.project":"fixture","com.docker.compose.network":"example_app_ingress"}},{"Name":"fixture_example_app_ingress","Labels":{"com.docker.compose.project":"fixture","com.docker.compose.network":"example_app_ingress"}}]\n' ;;
    missing|collision) exit 1 ;;
  esac
  exit 0
fi
if [[ "\${1:-}" == network && "\${2:-}" == ls ]]; then
  [[ "\${HOSTED_TEST_NETWORK_MODE:-}" != collision ]] || printf '%s\n' fixture_example_app_ingress
  exit 0
fi
exit 2
`, { mode: 0o755 });
    const verifier = path.join(import.meta.dirname, "hosted-workload-network-ownership.sh");
    const environment = {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      HOSTED_WORKLOAD_ALLOW_RESOLVED: "1",
    };
    const run = (mode, extra = []) => spawnSync("/bin/bash", [verifier, "--lock", lockPath, "--project-name", "fixture", ...extra], {
      encoding: "utf8",
      env: { ...environment, HOSTED_TEST_NETWORK_MODE: mode },
    });
    assert.equal(run("correct").status, 0);
    for (const mode of ["wrong-project", "wrong-logical", "invalid-json", "duplicate", "missing"]) {
      const rejected = run(mode);
      assert.notEqual(rejected.status, 0, `${mode} unexpectedly passed`);
      assert.match(rejected.stderr, /invalid Engine ownership|missing or cannot be inspected/);
    }
    assert.equal(run("missing", ["--allow-absent"]).status, 0);
    const collision = run("collision", ["--allow-absent"]);
    assert.notEqual(collision.status, 0);
    assert.match(collision.stderr, /exists but cannot be inspected/);
    const wrongProject = spawnSync("/bin/bash", [verifier, "--lock", lockPath, "--project-name", "attacker"], {
      encoding: "utf8",
      env: { ...environment, HOSTED_TEST_NETWORK_MODE: "correct" },
    });
    assert.notEqual(wrongProject.status, 0);
    assert.match(wrongProject.stderr, /ownership receipt is invalid/);
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
