#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
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
const currentRawPolicyControls = ["bind-bounded-dependencies", "bind-bounded-local-logging", "bind-closed-service-schema", "bind-exact-healthcheck", "bind-exact-security-opt", "bind-exact-ulimits", "bind-exact-volume-mounts", "bind-firewall-gated-restart", "bind-network-identity", "bind-network-topology", "bind-no-swap-oom-policy", "bind-owned-secret-aliases", "bind-owned-volume-driver", "bind-owned-volumes", "bind-platform-extension-records", "bind-private-pid-numeric-user", "deny-accelerator-environment", "deny-api-socket", "deny-compose-interpolation", "deny-deploy-controls", "deny-device-access", "deny-env-file", "deny-extends", "deny-file-configs", "deny-generic-resources", "deny-gpu-access", "deny-include", "deny-inline-configs", "deny-label-file", "deny-lifecycle-hooks", "deny-local-volume-options", "deny-providers", "deny-runtime-identity-labels", "deny-runtime-overrides", "deny-scaling", "deny-stop-grace-overrides", "deny-supplemental-groups", "deny-volumes-from"];
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
  restart: "no",
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
  rawPolicyReceipt: {
    protectedNetworkNames: ["platform_routing"],
    protectedResourceNames: {
      configs: [],
      networks: ["platform_routing"],
      secrets: [],
      services: ["project-router"],
      volumes: [],
    },
    workloads: [{
      workloadId: "example-app",
      platformExtensions: [{ serviceName: "project-router", networkNames: ["example_app_ingress"] }],
    }],
  },
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
test("named volumes cannot shadow protected targets or use nested mount controls", () => {
  for (const target of [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/infra",
    "/backups",
    "/mnt/host/root",
    "/var/www/project-state",
    "/var/www/infra-docs",
    "/run/platform/hosted-workloads.lock.json",
  ]) {
    const combined = combinedFixture();
    combined.volumes = { "example-app_data": { name: "fixture_example-app_data" } };
    combined.services["example-app-web"].volumes = [{
      type: "volume",
      source: "example-app_data",
      target,
    }];
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock }),
      /single closed \/data mount/,
    );
  }
  for (const extra of [
    { read_only: false },
    { volume: { nocopy: false } },
    { volume: { nocopy: false, subpath: "host" } },
    { consistency: "cached" },
  ]) {
    const combined = combinedFixture();
    combined.volumes = { "example-app_data": { name: "fixture_example-app_data" } };
    combined.services["example-app-web"].volumes = [{
      type: "volume",
      source: "example-app_data",
      target: "/data",
      ...extra,
    }];
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock }),
      /only workload-prefixed named volumes/,
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
test("Compose wrapper is render-only and canonical-project-bound in no-hosted mode", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-no-lock-mutation-"));
  try {
    const envFile = path.join(root, "core.env");
    const fakeBin = path.join(root, "bin");
    const marker = path.join(root, "docker-called");
    fs.writeFileSync(envFile, "CORE_VALUE=fixture\n");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh\nprintf called > "$HOSTED_TEST_DOCKER_MARKER"\n`, { mode: 0o755 });
    for (const extraEnvironment of [{}, { COMPOSE_PROJECT_NAME: "attacker" }]) {
      const result = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "up", "-d"], {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${fakeBin}:${process.env.PATH}`,
          COMPOSE_ENV_FILE: envFile,
          HOSTED_WORKLOAD_LOCK: "",
          HOSTED_TEST_DOCKER_MARKER: marker,
          ...extraEnvironment,
        },
      });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /render-only|canonical project/i);
      assert.equal(fs.existsSync(marker), false);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("Compose wrapper rejects a missing or non-canonical runtime lock source before render", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-runtime-lock-source-"));
  try {
    const envFile = path.join(root, "core.env");
    fs.writeFileSync(envFile, "CORE_VALUE=fixture\n");
    const missing = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "config", "--format", "json"], {
      encoding: "utf8",
      env: {
        ...process.env,
        COMPOSE_ENV_FILE: envFile,
        HOSTED_WORKLOAD_LOCK: "",
        HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: path.join(root, "missing.lock.json"),
      },
    });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /existing regular non-symlink file/);
    const foreign = path.join(root, "foreign.lock.json");
    fs.copyFileSync(path.join(import.meta.dirname, "..", "config", "no-hosted-workloads.lock.json"), foreign);
    const nonCanonical = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "config", "--format", "json"], {
      encoding: "utf8",
      env: {
        ...process.env,
        COMPOSE_ENV_FILE: envFile,
        HOSTED_WORKLOAD_LOCK: "",
        HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: foreign,
      },
    });
    assert.notEqual(nonCanonical.status, 0);
    assert.match(nonCanonical.stderr, /non-empty HOSTED_WORKLOAD_LOCK is required/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
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
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot override OOM or swappiness controls|unsupported Compose service fields/);
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
  assert.throws(
    () => validateRenderedWorkloads({ core, combined: fileBacked, lock }),
    /cannot use a host file source|cannot add, alias, replace, or remove top-level configs/,
  );

  const granted = combinedFixture();
  granted.configs = { platform_config: { external: true } };
  granted.services["example-app-web"].configs = [{ source: "platform_config", target: "/run/config" }];
  assert.throws(
    () => validateRenderedWorkloads({ core, combined: granted, lock }),
    /cannot mount platform or host-backed configs|cannot add, alias, replace, or remove top-level configs/,
  );

  for (const definition of [{ content: "hostile" }, { environment: "HOST_SECRET" }]) {
    const combined = combinedFixture();
    combined.configs = { example_app_inline: definition };
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock }),
      /cannot use inline or host-environment content|cannot add, alias, replace, or remove top-level configs/,
    );
  }
});
test("host device controls are rejected after render", () => {
  for (const mutation of [
    (service) => { service.devices = [{ source: "/dev/kvm", target: "/dev/kvm" }]; },
    (service) => { service.device_cgroup_rules = ["c 10:232 rwm"]; },
    (service) => { service.blkio_config.device_read_bps = [{ path: "/dev/sda", rate: "1mb" }]; },
  ]) {
    const combined = combinedFixture();
    mutation(combined.services["example-app-web"]);
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock }),
      /cannot request host device access|blkio_config must contain only the bounded global weight/,
    );
  }
});
test("host label files, ambient environment and deploy resource overrides are rejected after render", () => {
  for (const [mutation, message] of [
    [(service) => { service.label_file = "/tmp/attacker.labels"; }, /cannot load labels from a host file/],
    [(service) => { service.environment = { DATABASE_URL: null }; }, /explicit mapping with no ambient null values/],
    [(service) => { service.environment = ["DATABASE_URL"]; }, /explicit mapping with no ambient null values/],
    [(service) => { service.deploy = { resources: { limits: { cpus: "64", memory: "64G", pids: 999999 } } }; }, /cannot define deploy controls/],
  ]) {
    const combined = combinedFixture();
    mutation(combined.services["example-app-web"]);
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), message);
  }
});
test("supplemental device groups are rejected after render", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].group_add = ["video", "44"];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot add supplemental groups/);
});
test("local volume driver options are rejected after render", () => {
  for (const device of ["/", "/var/run", "/run/docker.sock", "/var/run/docker.sock"]) {
    const combined = combinedFixture();
    combined.volumes = {
      "example-app_data": {
        driver: "local",
        driver_opts: { type: "none", o: "bind", device },
      },
    };
    combined.services["example-app-web"].volumes = [{
      type: "volume",
      source: "example-app_data",
      target: "/data",
    }];
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot use local driver options/);
  }
});
test("top-level workload resources are closed to exact referenced volumes and signed secrets", () => {
  const unusedVolume = combinedFixture();
  unusedVolume.volumes = { "example-app_unused": { name: "fixture_example-app_unused" } };
  assert.throws(
    () => validateRenderedWorkloads({ core, combined: unusedVolume, lock }),
    /top-level volumes do not exactly match/,
  );

  const unusedSecret = combinedFixture();
  unusedSecret.secrets["example-app-unused"] = {
    external: true,
    name: "fixture_example-app-unused",
  };
  assert.throws(
    () => validateRenderedWorkloads({ core, combined: unusedSecret, lock }),
    /top-level secrets do not exactly match/,
  );

  const aliasedConfig = combinedFixture();
  aliasedConfig.configs = { attacker_trust_key: { external: true } };
  assert.throws(
    () => validateRenderedWorkloads({ core, combined: aliasedConfig, lock }),
    /cannot add, alias, replace, or remove top-level configs/,
  );
});
test("read-only volume syntax cannot smuggle a Docker socket or sensitive target", () => {
  for (const target of ["/run", "/var/run", "/proc", "/sys", "/dev", "/run/docker.sock", "/var/run/docker.sock"]) {
    const combined = combinedFixture();
    combined.volumes = { "example-app_data": { name: "fixture_example-app_data" } };
    combined.services["example-app-web"].volumes = [{
      type: "volume",
      source: "example-app_data",
      target,
      read_only: true,
    }];
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock }),
      /only workload-prefixed named volumes|single closed \/data mount/,
    );
  }
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
test("workloads cannot predeclare trusted runtime identity labels", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].labels["com.platform.runtime.candidate-id"] = "a".repeat(64);
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot predeclare trusted runtime identity labels/);
});
test("security_opt is the exact no-new-privileges singleton", () => {
  for (const securityOpt of [
    ["no-new-privileges:true", "seccomp=unconfined"],
    ["no-new-privileges:true", "apparmor=unconfined"],
    ["seccomp=unconfined"],
  ]) {
    const combined = combinedFixture();
    combined.services["example-app-web"].security_opt = securityOpt;
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock }),
      /security_opt must be exactly \[no-new-privileges:true\]/,
    );
  }
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
    (service) => { service.deploy = { resources: { reservations: { generic_resources: [{ discrete_resource_spec: { kind: "GPU", value: 1 } }] } } }; },
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
  const protectedLock = structuredClone(lock);
  protectedLock.rawPolicyReceipt.protectedNetworkNames = Object.keys(protectedCore.networks).sort();
  protectedLock.rawPolicyReceipt.protectedResourceNames = {
    configs: Object.keys(protectedCore.configs).sort(),
    networks: Object.keys(protectedCore.networks).sort(),
    secrets: Object.keys(protectedCore.secrets).sort(),
    services: Object.keys(protectedCore.services).sort(),
    volumes: Object.keys(protectedCore.volumes).sort(),
  };
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
      () => validateRenderedWorkloads({ core: protectedCore, combined, lock: protectedLock }),
      new RegExp(`changed protected ${resourceType} resource ${resourceName}`),
    );
    combined[resourceType][resourceName] = structuredClone(protectedCore[resourceType][resourceName]);
    delete combined[resourceType][resourceName];
    assert.throws(
      () => validateRenderedWorkloads({ core: protectedCore, combined, lock: protectedLock }),
      new RegExp(`removed protected ${resourceType} resource ${resourceName}`),
    );
  }
});
test("workload resources are logically and physically disjoint from protected core resources", () => {
  const enterpriseManifest = validateWorkloadManifest({
    version: 1,
    id: "enterprise",
    composeFile: "compose.yaml",
    secrets: [],
    migrationRoots: [],
    services: [{ name: "enterprise-web", role: "worker" }],
  });
  const protectedCore = {
    services: structuredClone(core.services),
    networks: structuredClone(core.networks),
    volumes: {
      enterprise_local_registry_data: {
        external: true,
        name: "enterprise_local_registry_data",
      },
    },
  };
  const combined = {
    services: {
      ...structuredClone(protectedCore.services),
      "enterprise-web": {
        ...structuredClone(baseService),
        labels: {
          "com.platform.workload-id": "enterprise",
          "com.platform.workload-role": "worker",
        },
        networks: { enterprise_ingress: null },
        volumes: [{
          type: "volume",
          source: "enterprise_local_registry_data",
          target: "/data",
        }],
      },
    },
    networks: {
      ...structuredClone(protectedCore.networks),
      enterprise_ingress: {
        internal: true,
        name: "fixture_enterprise_ingress",
      },
    },
    volumes: structuredClone(protectedCore.volumes),
  };
  const enterpriseLock = {
    projectName: "fixture",
    workloads: [enterpriseManifest],
    brokerPolicySha256: brokerPolicySha256([enterpriseManifest]),
    rawPolicyReceipt: {
      protectedNetworkNames: ["platform_routing"],
      protectedResourceNames: {
        configs: [],
        networks: ["platform_routing"],
        secrets: [],
        services: ["project-router"],
        volumes: ["enterprise_local_registry_data"],
      },
      workloads: [{
        workloadId: "enterprise",
        platformExtensions: [],
      }],
    },
  };
  assert.throws(
    () => validateRenderedWorkloads({ core: protectedCore, combined, lock: enterpriseLock }),
    /collides with a protected core volume/,
  );

  const physicalAliasCore = structuredClone(protectedCore);
  physicalAliasCore.volumes = { registry_data: { name: "fixture_enterprise_data" } };
  const physicalAlias = structuredClone(combined);
  physicalAlias.volumes = {
    registry_data: { name: "fixture_enterprise_data" },
    enterprise_data: { name: "fixture_enterprise_data" },
  };
  physicalAlias.services["enterprise-web"].volumes[0].source = "enterprise_data";
  const physicalAliasLock = structuredClone(enterpriseLock);
  physicalAliasLock.rawPolicyReceipt.protectedResourceNames.volumes = ["registry_data"];
  assert.throws(
    () => validateRenderedWorkloads({ core: physicalAliasCore, combined: physicalAlias, lock: physicalAliasLock }),
    /aliases protected physical resource/,
  );
});
test("signed but unreferenced workload networks are rejected", () => {
  const combined = combinedFixture();
  combined.networks.example_app_storage = {
    internal: true,
    name: "fixture_example_app_storage",
  };
  assert.throws(
    () => validateRenderedWorkloads({ core, combined, lock }),
    /networks must be exactly referenced/,
  );
});
test("unauthorized platform network extension is rejected", () => {
  const combined = combinedFixture();
  combined.services["project-router"].networks.evil = null;
  combined.networks.evil = { internal: true };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /non-workload network|signed workload service consumer/);
});
test("workload logical networks cannot collide with protected core networks", () => {
  const protectedDefinition = { internal: true, name: "fixture_platform_postgres", labels: { "com.platform.trust-zone": "postgres" } };
  const collisionCore = {
    services: { postgres: { image: `registry.example/postgres@sha256:${digest}`, networks: { platform_postgres: null } } },
    networks: { platform_postgres: protectedDefinition },
  };
  const platformManifest = {
    version: 1,
    id: "platform",
    composeFile: "compose.yaml",
    services: [{ name: "platform-web", role: "worker", routes: [] }],
    secrets: [],
    migrationRoots: [],
  };
  const collisionCombined = {
    services: {
      postgres: structuredClone(collisionCore.services.postgres),
      "platform-web": {
        ...structuredClone(baseService),
        networks: { platform_postgres: null },
        labels: { "com.platform.workload-id": "platform", "com.platform.workload-role": "worker" },
      },
    },
    networks: { platform_postgres: structuredClone(protectedDefinition) },
  };
  assert.throws(
    () => validateRenderedWorkloads({
      core: collisionCore,
      combined: collisionCombined,
      lock: {
        projectName: "fixture",
        workloads: [platformManifest],
        brokerPolicySha256: brokerPolicySha256([platformManifest]),
      },
    }),
    /cannot join protected core network platform_postgres/,
  );
});
test("workload network cannot alias the Docker-control physical network", () => {
  for (const definition of [
    { external: true, name: "platform_infra_platform_docker_control" },
    { internal: true, name: "platform_infra_platform_docker_control" },
  ]) {
    const combined = combinedFixture();
    combined.networks.example_app_ingress = definition;
    assert.throws(
      () => validateRenderedWorkloads({ core, combined, lock }),
      /cannot alias foreign physical network/,
    );
  }
  const combined = combinedFixture();
  combined.networks.example_app_ingress.name = "fixture_example_app_ingress";
  assert.doesNotThrow(() => validateRenderedWorkloads({ core, combined, lock }));
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
    assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /exact ingress topology/);
  }
  const egress = combinedFixture();
  egress.services["example-app-worker"].networks = { example_app_egress: null };
  delete egress.networks.example_app_bus;
  egress.networks.example_app_egress = { internal: false, enable_ipv6: false, name: "fixture_example_app_egress" };
  assert.doesNotThrow(() => validateRenderedWorkloads({ core, combined: egress, lock }));
});
test("platform service can join only its assigned workload zone", () => {
  const combined = combinedFixture();
  combined.services["project-router"].networks.example_app_cache = null;
  combined.services["example-app-worker"].networks.example_app_cache = null;
  combined.networks.example_app_cache = { internal: true, name: "fixture_example_app_cache" };
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
    rawPolicyReceipt: structuredClone(lock.rawPolicyReceipt),
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
  const missingRouteLock = structuredClone(lock);
  missingRouteLock.rawPolicyReceipt.workloads[0].platformExtensions = [];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock: missingRouteLock }), /no exact dedicated ingress network/);
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
    secrets: { redis_password: { external: true }, nats_password: { external: true } },
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
    lock: {
      projectName: "fixture",
      workloads: [workload],
      brokerPolicySha256: brokerPolicySha256([workload]),
      rawPolicyReceipt: {
        protectedNetworkNames: ["platform_bus", "platform_cache"],
        protectedResourceNames: {
          configs: [],
          networks: ["platform_bus", "platform_cache"],
          secrets: ["nats_password", "redis_password"],
          services: ["broker-auth-bootstrap", "nats", "redis"],
          volumes: [],
        },
        workloads: [{
          workloadId: "tenant-app",
          platformExtensions: [
            { serviceName: "nats", networkNames: ["tenant_app_bus"] },
            { serviceName: "redis", networkNames: ["tenant_app_cache"] },
          ],
        }],
      },
    },
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
    /schema 4 and validator hosted-contract-v4/,
  );
});

test("raw policy receipt requires the exact current control set", () => {
  const rawPolicyReceipt = {
    policyVersion: "hosted-raw-v3",
    controls: currentRawPolicyControls,
    protectedNetworkNames: [],
    protectedResourceNames: {
      configs: [],
      networks: [],
      secrets: [],
      services: [],
      volumes: [],
    },
    workloadContentSha256: "a".repeat(64),
    workloads: [{
      workloadId: "example-app",
      composeSha256: "c".repeat(64),
      configNames: [],
      networkNames: [],
      platformExtensions: [],
      secretNames: [],
      topLevelKeys: ["services"],
      serviceNames: ["example-app-web"],
      volumeNames: [],
    }],
  };
  const stable = (value) => {
    if (Array.isArray(value)) return value.map(stable);
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  };
  const receipt = {
    workloadContentSha256: "a".repeat(64),
    workloads: [{ id: "example-app", services: [{ name: "example-app-web" }], secrets: [] }],
    files: [{ kind: "workload-compose", workloadId: "example-app", sha256: "c".repeat(64) }],
    rawPolicyVersion: "hosted-raw-v3",
    rawPolicyWorkloadContentSha256: "a".repeat(64),
    rawPolicyReceipt,
    rawPolicySha256: crypto.createHash("sha256").update(JSON.stringify(stable(rawPolicyReceipt))).digest("hex"),
    rawPolicyControls: currentRawPolicyControls,
  };
  assert.doesNotThrow(() => verifyRawPolicyReceipt(receipt));
  receipt.rawPolicyControls = ["deny-include"];
  assert.throws(() => verifyRawPolicyReceipt(receipt), /raw source policy receipt/);
  receipt.rawPolicyControls = currentRawPolicyControls;
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
  fs.writeFileSync(path.join(appRoot, "compose.yaml"), "services:\n  example-app-web:\n    security_opt:\n      - no-new-privileges:true\n    networks:\n      example_app_ingress:\nnetworks:\n  example_app_ingress:\n    internal: true\n");
  fs.writeFileSync(path.join(appRoot, "workload.env"), "EXAMPLE_APP_THEME=dark\n");
  const catalogPath = path.join(root, "catalog.json");
  fs.writeFileSync(catalogPath, JSON.stringify({
    version: 1,
    workloads: [{ manifest: "example-app/manifest.json", environmentFile: "example-app/workload.env" }],
  }));
  const coreEnvFile = path.join(root, "core.env");
  const coreFile = path.join(root, "compose.core.yaml");
  fs.writeFileSync(coreEnvFile, "CORE_VALUE=fixture\n");
  fs.chmodSync(coreEnvFile, 0o600);
  fs.writeFileSync(coreFile, "services: {}\nnetworks:\n  platform_postgres: {}\n");
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

function promoteFixtureLock(lockPath) {
  const verified = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  assert.equal(verified.activationLockPath, lockPath);
  verified.state = "verified";
  verified.coreRenderSha256 = "c".repeat(64);
  verified.combinedRenderSha256 = "d".repeat(64);
  verified.routes = [];
  fs.writeFileSync(lockPath, `${JSON.stringify(verified, null, 2)}\n`, { mode: 0o600 });
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

test("workload resolver rejects prefix-colliding ids independent of secret declaration and catalog order", () => {
  for (const [label, parentSecrets, childSecrets, reversed] of [
    ["parent-only", ["billing-api-db-password"], [], false],
    ["child-only", [], ["billing-api-db-password"], false],
    ["both", ["billing-api-db-password"], ["billing-api-db-password"], false],
    ["reversed", [], ["billing-api-db-password"], true],
  ]) {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `hosted-prefix-${label}-`)));
    try {
      const workloadRoot = path.join(root, "workloads");
      for (const [id, secrets] of [["billing", parentSecrets], ["billing-api", childSecrets]]) {
        const appRoot = path.join(workloadRoot, id);
        fs.mkdirSync(appRoot, { recursive: true });
        fs.writeFileSync(path.join(appRoot, "manifest.json"), JSON.stringify({
          version: 1,
          id,
          composeFile: "compose.yaml",
          secrets,
          services: [{ name: `${id}-web`, role: "web" }],
        }));
        fs.writeFileSync(path.join(appRoot, "compose.yaml"), `services:\n  ${id}-web:\n    image: example.invalid/${id}@sha256:${digest}\n`);
        fs.writeFileSync(
          path.join(appRoot, "workload.env"),
          `${id.toUpperCase().replaceAll("-", "_")}_THEME=dark\n`,
        );
      }
      const entries = ["billing", "billing-api"].map((id) => ({
        manifest: `${id}/manifest.json`,
        environmentFile: `${id}/workload.env`,
      }));
      if (reversed) entries.reverse();
      const catalogPath = path.join(root, "catalog.json");
      const coreEnvFile = path.join(root, "core.env");
      const coreFile = path.join(root, "compose.core.yaml");
      fs.writeFileSync(catalogPath, JSON.stringify({ version: 1, workloads: entries }));
      fs.writeFileSync(coreEnvFile, "CORE_VALUE=fixture\n", { mode: 0o600 });
      fs.chmodSync(coreEnvFile, 0o600);
      fs.writeFileSync(coreFile, "services: {}\n");
      assert.throws(() => resolveCatalog({
        catalogPath,
        coreEnvFile,
        workloadRoot,
        coreFiles: [coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(root, "snapshots"),
      }), /Prefix-colliding workload ids billing and billing-api are forbidden|ambiguously declared/);
    } finally {
      removeFixtureTree(root);
    }
  }
});

test("resolver preserves billing plus billingapi and one billing textual child resource", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-prefix-positive-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const entries = [];
    for (const id of ["billing", "billingapi"]) {
      const appRoot = path.join(workloadRoot, id);
      fs.mkdirSync(appRoot, { recursive: true });
      fs.writeFileSync(path.join(appRoot, "manifest.json"), JSON.stringify({
        version: 1,
        id,
        composeFile: "compose.yaml",
        services: [{ name: `${id}-web`, role: "web" }],
      }));
      fs.writeFileSync(path.join(appRoot, "compose.yaml"), `services:\n  ${id}-web:\n    image: example.invalid/${id}@sha256:${digest}\n`);
      fs.writeFileSync(path.join(appRoot, "workload.env"), `${id.toUpperCase()}_THEME=dark\n`);
      entries.push({ manifest: `${id}/manifest.json`, environmentFile: `${id}/workload.env` });
    }
    const catalogPath = path.join(root, "catalog.json");
    const coreEnvFile = path.join(root, "core.env");
    const coreFile = path.join(root, "compose.core.yaml");
    fs.writeFileSync(catalogPath, JSON.stringify({ version: 1, workloads: entries }));
    fs.writeFileSync(coreEnvFile, "CORE_VALUE=fixture\n", { mode: 0o600 });
    fs.chmodSync(coreEnvFile, 0o600);
    fs.writeFileSync(coreFile, "services: {}\n");
    const resolved = resolveCatalog({
      catalogPath,
      coreEnvFile,
      workloadRoot,
      coreFiles: [coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    assert.deepEqual(resolved.workloads.map((workload) => workload.id), ["billing", "billingapi"]);

    assert.doesNotThrow(() => validateWorkloadManifest({
      version: 1,
      id: "billing",
      composeFile: "compose.yaml",
      secrets: ["billing-api-key"],
      services: [{ name: "billing-api-web", role: "web" }],
    }));
  } finally {
    removeFixtureTree(root);
  }
});

test("supplied or forged nested-id locks cannot assign child resources to the parent", () => {
  const forgedCore = {
    services: { "project-router": { networks: { platform_routing: null } } },
    networks: { platform_routing: { internal: true } },
  };
  for (const workloadIds of [
    ["billing", "billing-api"],
    ["billing-api", "billing"],
    ["billing-api-admin", "billing", "billing-api"],
  ]) {
    const childId = workloadIds.find((id) => id !== "billing" && id.startsWith("billing-"));
    const childService = `${childId}-web`;
    const childNetwork = `${childId.replaceAll("-", "_")}_ingress`;
    const childVolume = `${childId.replaceAll("-", "_")}_data`;
    const childSecret = `${childId}-api-key`;
    const parentService = {
      ...structuredClone(baseService),
      labels: { "com.platform.workload-id": "billing", "com.platform.workload-role": "web" },
      networks: { [childNetwork]: null },
      environment: {
        [`${childId.toUpperCase().replaceAll("-", "_")}_TOKEN_FILE`]: `/run/secrets/${childSecret}`,
      },
      secrets: [{ source: childSecret, target: childSecret }],
      volumes: [{ type: "volume", source: childVolume, target: "/data" }],
    };
    const forgedCombined = {
      services: {
        "project-router": {
          ...forgedCore.services["project-router"],
          networks: { platform_routing: null, [childNetwork]: null },
        },
        [childService]: parentService,
        ...Object.fromEntries(workloadIds
          .filter((id) => id !== "billing")
          .map((id) => [`${id}-worker`, {
            ...structuredClone(baseService),
            labels: { "com.platform.workload-id": id, "com.platform.workload-role": "worker" },
            networks: {},
          }])),
      },
      networks: {
        platform_routing: { internal: true },
        [childNetwork]: { internal: true, name: `fixture_${childNetwork}` },
      },
      secrets: { [childSecret]: { external: true, name: `fixture_${childSecret}` } },
      volumes: { [childVolume]: { name: `fixture_${childVolume}` } },
    };
    const forgedWorkloads = workloadIds.map((id) => ({
      version: 1,
      id,
      composeFile: "compose.yaml",
      projectMetadataFile: null,
      services: id === "billing"
        ? [{ name: childService, role: "web", routes: [{ slug: "billing", port: 3000 }] }]
        : [{ name: `${id}-worker`, role: "worker", routes: [] }],
      secrets: id === "billing" ? [childSecret] : [],
      migrationRoots: [],
    }));
    const forgedLock = {
      projectName: "fixture",
      workloads: forgedWorkloads,
      rawPolicyReceipt: {
        protectedNetworkNames: ["platform_routing"],
        protectedResourceNames: {
          configs: [],
          networks: ["platform_routing"],
          secrets: [],
          services: ["project-router"],
          volumes: [],
        },
        workloads: workloadIds.map((id) => ({
          workloadId: id,
          platformExtensions: id === "billing"
            ? [{ serviceName: "project-router", networkNames: [childNetwork] }]
            : [],
        })),
      },
    };
    assert.throws(
      () => validateRenderedWorkloads({ core: forgedCore, combined: forgedCombined, lock: forgedLock }),
      /Prefix-colliding workload ids/,
    );
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
      projectName: "platform_infra_vps",
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
      projectName: "platform_infra_vps",
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
    const bundleReader = spawnSync("/bin/sh", [
      path.join(import.meta.dirname, "hosted-workload-lock.sh"),
      lockPath,
      "activation-bundle",
    ], {
      encoding: "utf8",
      env: { PATH: minimalBin, HOSTED_WORKLOAD_ALLOW_RESOLVED: "1" },
    });
    assert.equal(bundleReader.status, 0, bundleReader.stderr);
    const activationBundle = JSON.parse(bundleReader.stdout);
    assert.deepEqual(
      activationBundle.protectedResourceNames,
      JSON.parse(fs.readFileSync(lockPath, "utf8")).rawPolicyReceipt.protectedResourceNames,
    );
    assert.deepEqual(
      Object.keys(activationBundle.protectedResourceNames).sort(),
      ["configs", "networks", "secrets", "services", "volumes"],
    );
    const verifiedActivation = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    verifiedActivation.state = "verified";
    verifiedActivation.coreRenderSha256 = "c".repeat(64);
    verifiedActivation.combinedRenderSha256 = "d".repeat(64);
    verifiedActivation.routes = [];
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
    const lockPath = path.join(root, "lock.json");
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "platform_infra_vps",
      snapshotRoot: path.join(root, "snapshots"),
      activationLockPath: lockPath,
    });
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
if [[ "\${HOSTED_TEST_NO_SWAP:-0}" != 1 ]]; then
  /bin/mv "$HOSTED_TEST_GENERATION" "$HOSTED_TEST_ORIGINAL_GENERATION"
  /bin/mkdir -m 700 "$HOSTED_TEST_GENERATION"
  printf 'services:\n  hostile:\n    privileged: true\n' > "$HOSTED_TEST_GENERATION/$HOSTED_TEST_COMPOSE_BASENAME"
  /bin/chmod 400 "$HOSTED_TEST_GENERATION/$HOSTED_TEST_COMPOSE_BASENAME"
  /bin/chmod 500 "$HOSTED_TEST_GENERATION"
fi
if [[ "\${HOSTED_TEST_CORE_ENV_SWAP:-0}" = 1 ]]; then
  printf 'CORE_VALUE=hostile\n' > "$HOSTED_TEST_CORE_ENV"
fi
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
      COMPOSE_PROJECT_NAME: "platform_infra_vps",
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
      HOSTED_TEST_CORE_ENV: fixture.coreEnvFile,
      PLATFORM_RUNTIME_CANDIDATE_ID: "a".repeat(64),
      PLATFORM_RUNTIME_COMMIT: "b".repeat(40),
      PLATFORM_RUNTIME_TREE: "c".repeat(40),
      PLATFORM_RUNTIME_DEPLOYMENT_ID: "deploy-20260721",
      PLATFORM_RUNTIME_SOURCE_RENDER_SHA256: "d".repeat(64),
      PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256: "e".repeat(64),
      TMPDIR: root,
    };
    const prepareConfig = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "config", "--format", "json"], {
      encoding: "utf8",
      env: { ...sharedEnvironment, HOSTED_WORKLOAD_PREPARE_RESOLVED: "1", HOSTED_TEST_NO_SWAP: "1" },
    });
    assert.equal(prepareConfig.status, 0, prepareConfig.stderr);
    assert.equal(fs.existsSync(capture), true);
    fs.unlinkSync(capture);
    fs.writeFileSync(sharedEnvironment.HOSTED_TEST_LOCK_READER_COUNT, "0\n");
    for (const arguments_ of [["up", "-d"], ["start"]]) {
      const prepareMutation = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), ...arguments_], {
        encoding: "utf8",
        env: { ...sharedEnvironment, HOSTED_WORKLOAD_PREPARE_RESOLVED: "1", HOSTED_TEST_NO_SWAP: "1" },
      });
      assert.notEqual(prepareMutation.status, 0);
      assert.match(prepareMutation.stderr, /limited to the exact prepare-time config render/i);
      assert.equal(fs.existsSync(capture), false);
    }
    const resolvedRejected = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "config", "--format", "json"], {
      encoding: "utf8",
      env: sharedEnvironment,
    });
    assert.notEqual(resolvedRejected.status, 0);
    assert.equal(fs.existsSync(capture), false);
    promoteFixtureLock(lockPath);
    fs.writeFileSync(sharedEnvironment.HOSTED_TEST_LOCK_READER_COUNT, "0\n");
    const queryRace = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), "config", "--format", "json"], {
      encoding: "utf8",
      env: { ...sharedEnvironment, HOSTED_TEST_QUERY_SWAP: "1" },
    });
    assert.notEqual(queryRace.status, 0);
    assert.match(queryRace.stderr, /handoff (?:object|path) (?:identity changed|could not be opened)/i);
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
      env: { ...sharedEnvironment, HOSTED_TEST_CORE_ENV_SWAP: "1" },
    });
    assert.equal(consumer.status, 0, consumer.stderr);
    const consumed = fs.readFileSync(capture, "utf8");
    assert.match(consumed, /example-app-web/);
    assert.match(consumed, /EXAMPLE_APP_THEME=dark/);
    assert.match(consumed, /CORE_VALUE=fixture/);
    assert.doesNotMatch(consumed, /CORE_VALUE=hostile/);
    assert.match(consumed, /"example-app-web"/);
    assert.match(consumed, /"com\.platform\.runtime\.candidate-id":"a{64}"/);
    assert.match(consumed, /"com\.platform\.runtime\.commit":"b{40}"/);
    assert.match(consumed, /"com\.platform\.runtime\.tree":"c{40}"/);
    assert.match(consumed, /"com\.platform\.runtime\.deployment-id":"deploy-20260721"/);
    assert.match(consumed, /"com\.platform\.runtime\.source-render-sha256":"d{64}"/);
    assert.match(consumed, /"com\.platform\.runtime\.workload-lock-sha256":"e{64}"/);
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
    const lockPath = path.join(root, "lock.json");
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot: path.join(root, "workloads"),
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
      activationLockPath: lockPath,
    });
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
    const rawPolicy = spawnSync("ruby", [path.join(import.meta.dirname, "hosted-workload-source-policy.rb"), "--lock", lockPath], { encoding: "utf8" });
    assert.equal(rawPolicy.status, 0, rawPolicy.stderr);

    const fakeBin = path.join(root, "fake-bin");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/bash
set -euo pipefail
if [[ "\${1:-}" == --host ]]; then shift 2; fi
if [[ "\${1:-}" == info ]]; then
  printf '%s\n' daemon-fixture
  exit 0
fi
if [[ "\${1:-}" == network && "\${2:-}" == inspect ]]; then
  base='{"Name":"fixture_example_app_ingress","Id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Driver":"bridge","Scope":"local","Internal":true,"Attachable":false,"Ingress":false,"EnableIPv6":false,"Options":{},"IPAM":{"Driver":"default","Options":null,"Config":[{"Subnet":"172.31.10.0/24","Gateway":"172.31.10.1"}]},"Containers":{},"Labels":{"com.docker.compose.project":"fixture","com.docker.compose.network":"example_app_ingress","com.docker.compose.version":"2.40.3"}}'
  case "\${HOSTED_TEST_NETWORK_MODE:-correct}" in
    correct) printf '[%s]\n' "$base" ;;
    wrong-project) printf '[%s]\n' "\${base/\\\"fixture\\\"/\\\"attacker\\\"}" ;;
    wrong-logical) printf '[%s]\n' "\${base/\\\"example_app_ingress\\\"/\\\"platform_docker_control\\\"}" ;;
    macvlan) printf '[%s]\n' "\${base/\\\"Driver\\\":\\\"bridge\\\"/\\\"Driver\\\":\\\"macvlan\\\"}" ;;
    attachable) printf '[%s]\n' "\${base/\\\"Attachable\\\":false/\\\"Attachable\\\":true}" ;;
    hostile-ipam) printf '[%s]\n' "\${base/\\\"Driver\\\":\\\"default\\\"/\\\"Driver\\\":\\\"evil\\\"}" ;;
    rogue-member) printf '[%s]\n' "\${base/\\\"Containers\\\":{}/\\\"Containers\\\":{\\\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\\":{\\\"Name\\\":\\\"rogue\\\",\\\"EndpointID\\\":\\\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\\",\\\"MacAddress\\\":\\\"02:42:ac:1f:0a:02\\\",\\\"IPv4Address\\\":\\\"172.31.10.2\\\\/24\\\",\\\"IPv6Address\\\":\\\"\\\"}}}" ;;
    invalid-json) printf '{not-json\n' ;;
    duplicate) printf '[%s,%s]\n' "$base" "$base" ;;
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
    const run = (mode, extra = []) => spawnSync("/bin/bash", [
      verifier,
      "--lock", lockPath,
      "--project-name", "fixture",
      "--expected-daemon-id", "daemon-fixture",
      ...extra,
    ], {
      encoding: "utf8",
      env: { ...environment, HOSTED_TEST_NETWORK_MODE: mode },
    });
    const resolvedRejected = run("correct");
    assert.notEqual(resolvedRejected.status, 0);
    promoteFixtureLock(lockPath);
    assert.equal(run("correct").status, 0);
    for (const mode of ["wrong-project", "wrong-logical", "macvlan", "attachable", "hostile-ipam", "rogue-member", "invalid-json", "duplicate", "missing"]) {
      const rejected = run(mode);
      assert.notEqual(rejected.status, 0, `${mode} unexpectedly passed`);
      assert.match(rejected.stderr, /invalid Engine ownership|missing or cannot be inspected/);
    }
    assert.equal(run("missing", ["--allow-absent"]).status, 0);
    const collision = run("collision", ["--allow-absent"]);
    assert.notEqual(collision.status, 0);
    assert.match(collision.stderr, /exists but cannot be inspected/);
    const wrongProject = spawnSync("/bin/bash", [
      verifier,
      "--lock", lockPath,
      "--project-name", "attacker",
      "--expected-daemon-id", "daemon-fixture",
    ], {
      encoding: "utf8",
      env: { ...environment, HOSTED_TEST_NETWORK_MODE: "correct" },
    });
    assert.notEqual(wrongProject.status, 0);
    assert.match(wrongProject.stderr, /ownership receipt is invalid/);
  } finally {
    removeFixtureTree(root);
  }
});

test("egress firewall consumes only the verified lock network inventory", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-egress-inventory-")));
  try {
    const fixture = catalogFixture(root);
    fs.writeFileSync(path.join(root, "workloads", "example-app", "compose.yaml"), "services:\n  example-app-web:\n    security_opt:\n      - no-new-privileges:true\n    networks:\n      example_app_egress:\nnetworks:\n  example_app_egress:\n    internal: false\n");
    const lockPath = path.join(root, "lock.json");
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot: path.join(root, "workloads"),
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
      activationLockPath: lockPath,
    });
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
    const rawPolicy = spawnSync("ruby", [path.join(import.meta.dirname, "hosted-workload-source-policy.rb"), "--lock", lockPath], { encoding: "utf8" });
    assert.equal(rawPolicy.status, 0, rawPolicy.stderr);
    const fakeBin = path.join(root, "fake-bin");
    const dockerLog = path.join(root, "docker.log");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\n' "$*" >> "$HOSTED_TEST_DOCKER_LOG"
if [ "\${1:-}" = --host ]; then shift 2; fi
if [ "\${1:-}" = info ]; then
  printf '%s\n' daemon-fixture
  exit 0
fi
[ "\${1:-}" = network ] && [ "\${2:-}" = inspect ] || exit 2
case "\${HOSTED_TEST_EGRESS_MODE:-correct}" in
  missing) exit 1 ;;
  wrong-label) project=attacker ;;
  *) project=fixture ;;
esac
printf '[{"Name":"fixture_example_app_egress","EnableIPv6":false,"Labels":{"com.docker.compose.project":"%s","com.docker.compose.network":"example_app_egress"},"IPAM":{"Config":[{"Subnet":"172.30.10.0/24"}]}}]\n' "$project"
`, { mode: 0o755 });
    fs.writeFileSync(path.join(fakeBin, "iptables"), `#!/bin/sh
case "$*" in
  *'-S DOCKER-USER'*)
    if [ "\${HOSTED_TEST_IPTABLES_MODE:-correct}" = preceding-accept ]; then
      printf '%s\n' '-A DOCKER-USER -j ACCEPT'
    fi
    printf '%s\n' '-A DOCKER-USER -j PLATFORM-WORKLOAD-EGRESS'
    ;;
  *'-S PLATFORM-WORKLOAD-EGRESS-NEW'*) exit 1 ;;
  *'-S PLATFORM-WORKLOAD-EGRESS'*)
    count=0
    while [ "$count" -lt 17 ]; do printf '%s\n' '-A PLATFORM-WORKLOAD-EGRESS -j RETURN'; count=$((count + 1)); done
    ;;
esac
exit 0
`, { mode: 0o755 });
    const environment = {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      HOSTED_WORKLOAD_ALLOW_RESOLVED: "1",
      HOSTED_TEST_DOCKER_LOG: dockerLog,
    };
    const firewall = path.join(import.meta.dirname, "workload-egress-firewall.sh");
    const run = (mode, extraEnvironment = {}) => spawnSync("/bin/sh", [
      firewall,
      mode,
      "--lock", lockPath,
      "--project-name", "fixture",
      "--expected-daemon-id", "daemon-fixture",
    ], {
      encoding: "utf8",
      env: { ...environment, ...extraEnvironment },
    });
    const resolvedRejected = run("--plan");
    assert.notEqual(resolvedRejected.status, 0);
    assert.equal(fs.existsSync(dockerLog), false);
    promoteFixtureLock(lockPath);
    const plan = run("--plan");
    assert.equal(plan.status, 0, plan.stderr);
    assert.match(plan.stdout, /Workload source: 172\.30\.10\.0\/24/);
    assert.deepEqual(fs.readFileSync(dockerLog, "utf8").trim().split("\n"), [
      "--host unix:///var/run/docker.sock info --format {{.ID}}",
      "--host unix:///var/run/docker.sock network inspect fixture_example_app_egress",
    ]);
    const callerPrefix = spawnSync("/bin/sh", [firewall, "--apply", "--network-prefix", "fixture"], {
      encoding: "utf8",
      env: environment,
    });
    assert.notEqual(callerPrefix.status, 0);
    assert.match(callerPrefix.stderr, /unknown option/i);
    fs.writeFileSync(dockerLog, "");
    const verified = run("--verify");
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stdout, /verified for 1 subnet/);
    const shadowed = run("--verify", { HOSTED_TEST_IPTABLES_MODE: "preceding-accept" });
    assert.notEqual(shadowed.status, 0);
    assert.match(shadowed.stderr, /must begin with exactly one direct workload egress jump/);
    for (const mode of ["wrong-label", "missing"]) {
      const rejected = run("--plan", { HOSTED_TEST_EGRESS_MODE: mode });
      assert.notEqual(rejected.status, 0);
      assert.match(rejected.stderr, /missing|identity\/IPAM is invalid/);
    }
  } finally {
    removeFixtureTree(root);
  }
});

function activationGateFixture(root) {
  const repository = path.join(root, "repository");
  const scripts = path.join(repository, "scripts");
  const config = path.join(repository, "config");
  const fixtures = path.join(repository, "fixtures");
  const releaseStates = path.join(root, "release-states");
  const activationCoordinator = path.join(root, "platform-activation");
  const fakeBin = path.join(root, "bin");
  const log = path.join(root, "trace.log");
  const dockerState = path.join(root, "docker-state.json");
  const firewallMarker = path.join(root, "firewall-verified");
  fs.mkdirSync(scripts, { recursive: true });
  fs.mkdirSync(config);
  fs.mkdirSync(fixtures);
  fs.mkdirSync(releaseStates);
  fs.mkdirSync(activationCoordinator, { mode: 0o700 });
  fs.chmodSync(activationCoordinator, 0o700);
  fs.mkdirSync(fakeBin);
  const copyExecutable = (name) => {
    fs.copyFileSync(path.join(import.meta.dirname, name), path.join(scripts, name));
    fs.chmodSync(path.join(scripts, name), 0o755);
  };
  for (const name of [
    "hosted-workload-activation-gate.sh",
    "core-stack-activation-gate.sh",
    "platform-activation-broker.py",
    "platform-activation-state.mjs",
    "compose-start-order.mjs",
  ]) {
    copyExecutable(name);
  }
  if (process.platform === "linux") {
    fs.writeFileSync(path.join(scripts, "platform-release-context.mjs"), `#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const [command, contextPath] = process.argv.slice(2);
if (command !== "read" || !path.isAbsolute(contextPath) || path.normalize(contextPath) !== contextPath) process.exit(1);
const details = fs.lstatSync(contextPath);
if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1 || (details.mode & 0o777) !== 0o640) process.exit(1);
const document = JSON.parse(fs.readFileSync(contextPath, "utf8"));
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const keys = [
  "schema", "repository", "commitSha", "treeSha", "sourceArchiveSha256",
  "releaseId", "releaseRoot", "stateId", "stateRoot", "environmentFile",
  "environmentSha256", "projectName", "decisionId", "provider", "receipts",
  "runtimeIntentSha256", "subjects", "hostedLockSha256", "noHosted",
  "coreRenderSha256", "combinedRenderSha256",
];
if (!exactKeys(document, keys)
    || document.schema !== "platform-trusted-release-context/v1"
    || document.projectName !== "platform_infra_vps"
    || path.join(document.stateRoot, "trusted-release-context.json") !== contextPath
    || path.basename(document.stateRoot) !== document.stateId
    || !Array.isArray(document.subjects) || document.subjects.length === 0
    || document.subjects.some((subject) => !exactKeys(subject, ["serviceName", "imageReference", "imageId"]))) process.exit(1);
const activationCoordinatorRoot = path.join(path.dirname(path.dirname(document.stateRoot)), "platform-activation");
process.stdout.write(JSON.stringify({ ...document, activationCoordinatorRoot }) + "\\n");
`, { mode: 0o755 });
  } else {
    copyExecutable("platform-release-context.mjs");
  }
  fs.copyFileSync(
    path.join(import.meta.dirname, "..", "config", "no-hosted-workloads.lock.json"),
    path.join(config, "no-hosted-workloads.lock.json"),
  );

  const envFile = path.join(repository, "fixture.env");
  const currentLock = path.join(fixtures, "current.lock.json");
  const previousLock = path.join(fixtures, "previous.lock.json");
  const otherLock = path.join(fixtures, "other.lock.json");
  const noHostedModel = path.join(fixtures, "no-hosted.model.json");
  const currentModel = path.join(fixtures, "current.model.json");
  const previousModel = path.join(fixtures, "previous.model.json");
  const otherModel = path.join(fixtures, "other.model.json");
  const extensionServices = ["project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus"];
  const baseServices = ["core-service", ...extensionServices].sort();
  const image = (name) => `example.invalid/${name}@sha256:${crypto.createHash("sha256").update(name).digest("hex")}`;
  const platformNetwork = "platform_routing";
  const baseModelValue = {
    services: Object.fromEntries(
      baseServices.map((name) => [name, {
        image: image(name),
        networks: { [platformNetwork]: null },
      }]),
    ),
    networks: {
      [platformNetwork]: {
        internal: true,
        name: "platform_infra_vps_platform_routing",
      },
    },
  };
  const model = (workloadId, serviceName) => {
    const networkName = `${workloadId.replaceAll("-", "_")}_private`;
    const services = structuredClone(baseModelValue.services);
    services.postgres.networks[networkName] = null;
    services[serviceName] = {
      image: image(serviceName),
      read_only: true,
      restart: "no",
      cap_drop: ["ALL"],
      labels: { "com.platform.workload-id": workloadId },
      networks: { [networkName]: null },
      depends_on: { postgres: { condition: "service_started" } },
    };
    return {
      services,
      networks: {
        ...structuredClone(baseModelValue.networks),
        [networkName]: {
          internal: true,
          name: `platform_infra_vps_${networkName}`,
        },
      },
    };
  };
  const currentModelValue = model("current-app", "current-app-web");
  const previousModelValue = model("previous-app", "previous-app-web");
  const otherModelValue = model("other-app", "other-app-web");
  const modelText = (value) => `${JSON.stringify(value)}\n`;
  const bundle = (workloadId, serviceName, lockByte, modelValue) => ({
    version: 2,
    projectName: "platform_infra_vps",
    lockSha256: lockByte.repeat(64),
    coreRenderSha256: crypto.createHash("sha256").update(modelText(baseModelValue)).digest("hex"),
    combinedRenderSha256: crypto.createHash("sha256").update(modelText(modelValue)).digest("hex"),
    workloadIds: [workloadId],
    protectedNetworkNames: [platformNetwork],
    protectedResourceNames: {
      configs: [],
      networks: [platformNetwork],
      secrets: [],
      services: baseServices,
      volumes: [],
    },
    networkRecords: [{
      workloadId,
      logicalName: `${workloadId.replaceAll("-", "_")}_private`,
      physicalName: `platform_infra_vps_${workloadId.replaceAll("-", "_")}_private`,
    }],
    serviceRecords: [{ workloadId, serviceName }],
    platformExtensionRecords: [{
      workloadId,
      serviceName: "postgres",
      networkNames: [`${workloadId.replaceAll("-", "_")}_private`],
    }],
    routeRecords: [],
  });
  fs.writeFileSync(envFile, `HOSTED_WORKLOAD_LOCK=${currentLock}\n`);
  fs.writeFileSync(currentLock, `${JSON.stringify(bundle("current-app", "current-app-web", "a", currentModelValue))}\n`, { mode: 0o600 });
  fs.writeFileSync(previousLock, `${JSON.stringify(bundle("previous-app", "previous-app-web", "b", previousModelValue))}\n`, { mode: 0o600 });
  fs.writeFileSync(otherLock, `${JSON.stringify(bundle("other-app", "other-app-web", "c", otherModelValue))}\n`, { mode: 0o600 });
  fs.writeFileSync(noHostedModel, modelText(baseModelValue));
  fs.writeFileSync(currentModel, modelText(currentModelValue));
  fs.writeFileSync(previousModel, modelText(previousModelValue));
  fs.writeFileSync(otherModel, modelText(otherModelValue));
  fs.writeFileSync(dockerState, `${JSON.stringify({ containers: {} })}\n`, { mode: 0o600 });

  const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
  const noHostedLock = path.join(config, "no-hosted-workloads.lock.json");
  const releaseContext = (stateId, modelValue, {
    noHosted,
    hostedLockSha256,
    suffix,
  }) => {
    const stateRoot = path.join(releaseStates, stateId);
    fs.mkdirSync(stateRoot, { mode: 0o700 });
    fs.chmodSync(stateRoot, 0o700);
    const contextPath = path.join(stateRoot, "trusted-release-context.json");
    const subjects = Object.entries(modelValue.services)
      .map(([serviceName, definition]) => ({
        serviceName,
        imageReference: definition.image,
        imageId: `sha256:${"d".repeat(64)}`,
      }))
      .sort((left, right) => left.serviceName.localeCompare(right.serviceName));
    const context = {
      schema: "platform-trusted-release-context/v1",
      repository: "example.invalid/platform-infrastructure",
      commitSha: "1".repeat(40),
      treeSha: "2".repeat(40),
      sourceArchiveSha256: "3".repeat(64),
      releaseId: `release-fixture-${suffix}`,
      releaseRoot: repository,
      stateId,
      stateRoot,
      environmentFile: envFile,
      environmentSha256: sha256(fs.readFileSync(envFile)),
      projectName: "platform_infra_vps",
      decisionId: `decision-fixture-${suffix}`,
      provider: {
        metadataSha256: "4".repeat(64),
        runId: `provider-run-${suffix}`,
        attempt: 1,
        challenge: "5".repeat(64),
      },
      receipts: {
        artifactSha256: "6".repeat(64),
        deploymentSha256: "7".repeat(64),
        dastSha256: "8".repeat(64),
      },
      runtimeIntentSha256: "9".repeat(64),
      subjects,
      hostedLockSha256,
      noHosted,
      coreRenderSha256: sha256(modelText(baseModelValue)),
      combinedRenderSha256: sha256(modelText(modelValue)),
    };
    fs.writeFileSync(contextPath, `${JSON.stringify(context)}\n`, { mode: 0o640 });
    fs.chmodSync(contextPath, 0o640);
    return { contextPath, stateRoot };
  };
  const currentRelease = releaseContext("state-fixture-hosted", currentModelValue, {
    noHosted: false,
    hostedLockSha256: "a".repeat(64),
    suffix: "hosted",
  });
  const nextRelease = releaseContext("state-fixture-hosted-next", currentModelValue, {
    noHosted: false,
    hostedLockSha256: "a".repeat(64),
    suffix: "hosted-next",
  });
  const noHostedRelease = releaseContext("state-fixture-zero", baseModelValue, {
    noHosted: true,
    hostedLockSha256: sha256(fs.readFileSync(noHostedLock)),
    suffix: "zero",
  });

  fs.writeFileSync(path.join(scripts, "hosted-workload-lock.sh"), `#!/bin/sh
printf 'lock:%s:%s\\n' "$1" "\${2:-}" >> "$HOSTED_TEST_TRACE"
cat "$1"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(scripts, "hosted-workload-contract.mjs"), `#!/usr/bin/env node
import fs from "node:fs";
const [command, ...args] = process.argv.slice(2);
const value = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : "";
};
const lock = value("--lock");
const core = value("--coreRender");
const combined = value("--combinedRender");
if (command !== "verify-activation-render"
    || ![lock, core, combined].every((file) => file && fs.statSync(file).isFile())) process.exit(1);
fs.appendFileSync(process.env.HOSTED_TEST_TRACE, \`semantic:\${lock}:\${core}:\${combined}\\n\`);
`, { mode: 0o755 });
  fs.writeFileSync(path.join(scripts, "compose-vps.sh"), `#!/bin/sh
printf 'render:%s:%s\\n' "\${HOSTED_WORKLOAD_LOCK:-}" "$*" >> "$HOSTED_TEST_TRACE"
case "\${HOSTED_WORKLOAD_LOCK:-}" in
  "$HOSTED_TEST_CURRENT_LOCK") cat "$HOSTED_TEST_CURRENT_MODEL" ;;
  "$HOSTED_TEST_PREVIOUS_LOCK") cat "$HOSTED_TEST_PREVIOUS_MODEL" ;;
  "$HOSTED_TEST_OTHER_LOCK") cat "$HOSTED_TEST_OTHER_MODEL" ;;
  "") cat "$HOSTED_TEST_NO_HOSTED_MODEL" ;;
  *) exit 81 ;;
esac
`, { mode: 0o755 });
  fs.writeFileSync(path.join(scripts, "hosted-workload-network-ownership.sh"), `#!/bin/sh
lock=
project=
daemon=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --lock) lock=$2; shift 2 ;;
    --project-name) project=$2; shift 2 ;;
    --expected-daemon-id) daemon=$2; shift 2 ;;
    *) shift ;;
  esac
done
test "$project" = platform_infra_vps
test "$daemon" = daemon-fixture
printf 'ownership:%s\\n' "$lock" >> "$HOSTED_TEST_TRACE"
exit 0
`, { mode: 0o755 });
  fs.writeFileSync(path.join(scripts, "workload-egress-firewall.sh"), `#!/bin/sh
mode=
lock=
project=
daemon=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --privilege-preflight|--apply|--verify|--rollback) mode=$1; shift ;;
    --lock) lock=$2; shift 2 ;;
    --project-name) project=$2; shift 2 ;;
    --expected-daemon-id) daemon=$2; shift 2 ;;
    *) shift ;;
  esac
done
test "$project" = platform_infra_vps
test "$daemon" = daemon-fixture
printf 'firewall:%s:%s\\n' "$mode" "$lock" >> "$HOSTED_TEST_TRACE"
if [ "$mode" = --verify ] && [ -n "$lock" ]; then
  : > "$HOSTED_TEST_FIREWALL_MARKER"
fi
if [ "\${HOSTED_TEST_PAUSE_AT:-}" = created ] && [ "$mode" = --apply ] && [ ! -e "$HOSTED_TEST_PAUSE_READY" ]; then
  printf 'created\\n' > "$HOSTED_TEST_PAUSE_READY"
  sleep 30
fi
exit 0
`, { mode: 0o755 });
  fs.writeFileSync(path.join(scripts, "vps-postdeploy.sh"), `#!/bin/sh
test "$1" = "$HOSTED_TEST_ENV_FILE"
printf 'postdeploy:%s\\n' "$1" >> "$HOSTED_TEST_TRACE"
if [ "\${HOSTED_TEST_PAUSE_AT:-}" = postdeploy ] && [ ! -e "$HOSTED_TEST_PAUSE_READY" ]; then
  printf 'postdeploy\\n' > "$HOSTED_TEST_PAUSE_READY"
  sleep 30
fi
test "\${HOSTED_TEST_FAIL_POSTDEPLOY:-0}" != 1
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "timeout"), `#!/bin/sh
shift
exec "$@"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "sudo"), `#!/bin/sh
[ "\${1:-}" != -n ] || shift
exec "$@"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "docker"), `#!/usr/bin/env node
const fs = require("node:fs");

const trace = process.env.HOSTED_TEST_TRACE;
const statePath = process.env.HOSTED_TEST_DOCKER_STATE;
const original = process.argv.slice(2);
fs.appendFileSync(trace, "docker:" + original.join(" ") + "\\n");
let args = [...original];
if (args[0] === "--host") args = args.slice(2);
const pauseAt = (point) => {
  if (process.env.HOSTED_TEST_PAUSE_AT !== point) return;
  if (fs.existsSync(process.env.HOSTED_TEST_PAUSE_READY)) return;
  fs.writeFileSync(process.env.HOSTED_TEST_PAUSE_READY, point + "\\n", { mode: 0o600 });
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30_000);
};
if (args[0] === "info") {
  if (process.env.PLATFORM_ACTIVATION_TRANSACTION_ID) pauseAt("intent");
  if (fs.existsSync(process.env.HOSTED_TEST_FIREWALL_MARKER || "")) pauseAt("firewall-active");
  process.stdout.write("daemon-fixture\\n");
  process.exit(0);
}
if (args[0] === "image" && args[1] === "inspect") {
  process.stdout.write("sha256:" + "d".repeat(64) + "\\n");
  process.exit(0);
}

const readState = () => JSON.parse(fs.readFileSync(statePath, "utf8"));
const writeState = (state) => fs.writeFileSync(statePath, JSON.stringify(state) + "\\n", { mode: 0o600 });
const state = readState();
const containers = state.containers;
const selectedIds = (values) => values.filter((value) => Object.hasOwn(containers, value));
const containerForService = (project, service) => Object.values(containers)
  .find((container) => container.project === project && container.service === service);

function inspection(container) {
  const definition = container.definition;
  const model = container.model;
  const labels = {
    "com.docker.compose.project": container.project,
    "com.docker.compose.service": container.service,
    "com.docker.compose.config-hash": "fixture-config-hash",
    ...(definition.labels || {}),
  };
  const environment = Array.isArray(definition.environment)
    ? definition.environment
    : Object.entries(definition.environment || {}).map(([key, value]) => key + "=" + value);
  const networkNames = Object.keys(definition.networks || {}).map((logical) =>
    (model.networks && model.networks[logical] && model.networks[logical].name)
      || container.project + "_" + logical);
  return {
    Id: container.id,
    Image: "sha256:" + "d".repeat(64),
    Config: {
      Image: definition.image,
      Env: environment,
      Labels: labels,
    },
    HostConfig: {
      RestartPolicy: { Name: definition.restart || "no" },
      ReadonlyRootfs: definition.read_only === true,
      Privileged: false,
      PidMode: "",
      CapDrop: definition.cap_drop || [],
    },
    State: {
      Running: container.running,
      Paused: false,
      Restarting: false,
      Status: container.running ? "running" : "exited",
    },
    NetworkSettings: {
      Networks: Object.fromEntries(networkNames.map((name) => [name, {}])),
    },
  };
}

if (args[0] === "compose") {
  const modelIndex = args.indexOf("-f");
  const projectIndex = args.indexOf("-p");
  const modelPath = args[modelIndex + 1];
  const project = args[projectIndex + 1];
  const model = JSON.parse(fs.readFileSync(modelPath, "utf8"));
  const commandIndex = args.findIndex((argument) => ["create", "stop", "ps"].includes(argument));
  const command = args[commandIndex];
  const requested = args.slice(commandIndex + 1).filter((argument) => Object.hasOwn(model.services, argument));
  const services = requested.length > 0 ? requested : Object.keys(model.services);
  if (command === "create") {
    pauseAt("quiesced");
    for (const service of services) {
      const existing = containerForService(project, service);
      const id = existing ? existing.id : "cid-" + service;
      containers[id] = {
        id,
        project,
        service,
        running: false,
        definition: model.services[service],
        model,
      };
    }
    writeState(state);
    process.exit(0);
  }
  if (command === "stop") {
    for (const service of services) {
      const container = containerForService(project, service);
      if (container) container.running = false;
    }
    writeState(state);
    process.exit(0);
  }
  if (command === "ps") {
    for (const service of services) {
      const container = containerForService(project, service);
      if (container) process.stdout.write(container.id + "\\n");
    }
    process.exit(0);
  }
}

if (args[0] === "start") {
  pauseAt("start");
  const ids = selectedIds(args.slice(1));
  const failingService = process.env.HOSTED_TEST_FAIL_SERVICE || "";
  if (ids.some((id) => containers[id].service === failingService)) process.exit(82);
  for (const id of ids) containers[id].running = true;
  writeState(state);
  process.stdout.write(ids.join("\\n") + (ids.length > 0 ? "\\n" : ""));
  process.exit(0);
}
if (args[0] === "stop") {
  const ids = selectedIds(args.slice(1));
  for (const id of ids) containers[id].running = false;
  writeState(state);
  process.stdout.write(ids.join("\\n") + (ids.length > 0 ? "\\n" : ""));
  process.exit(0);
}
if (args[0] === "rm") {
  const ids = selectedIds(args.slice(1));
  for (const id of ids) delete containers[id];
  writeState(state);
  process.stdout.write(ids.join("\\n") + (ids.length > 0 ? "\\n" : ""));
  process.exit(0);
}
if (args[0] === "ps") {
  const includeStopped = args.includes("-a") || args.includes("-aq");
  const values = Object.values(containers)
    .filter((container) => container.project === "platform_infra_vps")
    .filter((container) => includeStopped || container.running)
    .sort((left, right) => left.service.localeCompare(right.service));
  for (const container of values) process.stdout.write(container.id + "\\n");
  process.exit(0);
}
if (args[0] === "inspect") {
  process.stdout.write(JSON.stringify(selectedIds(args.slice(1)).map((id) => inspection(containers[id]))) + "\\n");
  process.exit(0);
}
process.exit(2);
`, { mode: 0o755 });

  const environment = {
    ...process.env,
    PATH: `${fakeBin}:${process.env.PATH}`,
    HOSTED_TEST_TRACE: log,
    HOSTED_TEST_DOCKER_STATE: dockerState,
    HOSTED_TEST_FIREWALL_MARKER: firewallMarker,
    HOSTED_TEST_ENV_FILE: envFile,
    HOSTED_TEST_CURRENT_LOCK: currentLock,
    HOSTED_TEST_PREVIOUS_LOCK: previousLock,
    HOSTED_TEST_OTHER_LOCK: otherLock,
    HOSTED_TEST_NO_HOSTED_MODEL: noHostedModel,
    HOSTED_TEST_CURRENT_MODEL: currentModel,
    HOSTED_TEST_PREVIOUS_MODEL: previousModel,
    HOSTED_TEST_OTHER_MODEL: otherModel,
    HOSTED_ACTIVATION_TIMEOUT_SECONDS: "5",
    HOSTED_VERIFY_TIMEOUT_SECONDS: "5",
    HOSTED_STOP_TIMEOUT_SECONDS: "5",
    CORE_ACTIVATION_TIMEOUT_SECONDS: "5",
    CORE_VERIFY_TIMEOUT_SECONDS: "5",
    CORE_STOP_TIMEOUT_SECONDS: "5",
  };
  return {
    repository,
    gate: path.join(scripts, "hosted-workload-activation-gate.sh"),
    envFile,
    state: activationCoordinator,
    noHostedState: activationCoordinator,
    currentReleaseContext: currentRelease.contextPath,
    nextReleaseContext: nextRelease.contextPath,
    noHostedReleaseContext: noHostedRelease.contextPath,
    dockerState,
    currentLock,
    previousLock,
    otherLock,
    noHostedModel,
    currentModel,
    baseServices,
    currentServices: [...baseServices, "current-app-web"].sort(),
    log,
    environment,
  };
}

function activationGateArguments(fixture, ...extra) {
  const releaseContext = extra.includes("--no-hosted-workloads")
    ? fixture.noHostedReleaseContext
    : fixture.currentReleaseContext;
  return [
    fixture.gate,
    "--project-name", "platform_infra_vps",
    "--env-file", fixture.envFile,
    "--release-context", releaseContext,
    ...extra,
    "--confirm", "ACTIVATE-HOSTED-WORKLOADS",
  ];
}

function activationGateArgumentsForContext(fixture, releaseContext, ...extra) {
  const arguments_ = activationGateArguments(fixture, ...extra);
  arguments_[arguments_.indexOf("--release-context") + 1] = releaseContext;
  return arguments_;
}

function interruptActivation(fixture, phase, signal = "SIGKILL", ...extra) {
  const ready = path.join(path.dirname(fixture.state), `pause-${phase}-${crypto.randomBytes(8).toString("hex")}`);
  const orchestrator = spawnSync(process.execPath, ["--input-type=module", "-e", `
import { spawn } from "node:child_process";
import fs from "node:fs";

const child = spawn("/bin/bash", JSON.parse(process.env.HOSTED_TEST_ACTIVATION_ARGS), {
  detached: true,
  env: process.env,
  stdio: ["ignore", "pipe", "pipe"],
});
let stdout = "";
let stderr = "";
child.stdout.setEncoding("utf8");
child.stderr.setEncoding("utf8");
child.stdout.on("data", (chunk) => { stdout += chunk; });
child.stderr.on("data", (chunk) => { stderr += chunk; });
const exitResult = new Promise((resolve) => {
  child.once("exit", (code, endedSignal) => resolve({ code, signal: endedSignal }));
});
const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const deadline = Date.now() + 8_000;
while (!fs.existsSync(process.env.HOSTED_TEST_PAUSE_READY)
    && child.exitCode === null && child.signalCode === null
    && Date.now() < deadline) await pause(20);
if (!fs.existsSync(process.env.HOSTED_TEST_PAUSE_READY)) {
  if (child.exitCode === null && child.signalCode === null) {
    try { process.kill(-child.pid, "SIGKILL"); } catch {}
  }
  await exitResult;
  process.stderr.write("activation did not reach requested pause\\n" + stdout + "\\n" + stderr);
  process.exit(2);
}
process.kill(-child.pid, process.env.HOSTED_TEST_INTERRUPT_SIGNAL);
const ended = await exitResult;
process.stdout.write(JSON.stringify({ ...ended, stdout, stderr }));
`], {
    encoding: "utf8",
    timeout: 15_000,
    env: {
      ...fixture.environment,
      HOSTED_TEST_ACTIVATION_ARGS: JSON.stringify(activationGateArguments(fixture, ...extra)),
      HOSTED_TEST_PAUSE_AT: phase,
      HOSTED_TEST_PAUSE_READY: ready,
      HOSTED_TEST_INTERRUPT_SIGNAL: signal,
    },
  });
  assert.equal(orchestrator.status, 0, `${orchestrator.stdout}\n${orchestrator.stderr}`);
  return JSON.parse(orchestrator.stdout);
}

test("Compose wrapper rejects late global overlays and hosted mutation bypasses", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-compose-cli-boundary-")));
  try {
    const envFile = path.join(root, "fixture.env");
    const marker = path.join(root, "docker.called");
    const fakeBin = path.join(root, "bin");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(envFile, "HOSTED_WORKLOAD_LOCK=/verified/current.lock.json\n");
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh\n: > "$HOSTED_TEST_DOCKER_MARKER"\nexit 0\n`, { mode: 0o755 });
    const candidates = [
      ["-f", "attacker.yaml", "config", "--format", "json"],
      ["-fattacker.yaml", "up", "-d"],
      ["--file=attacker.yaml", "config", "--format", "json"],
      ["--env-file=attacker.env", "config", "--format", "json"],
      ["-p", "attacker", "config", "--format", "json"],
      ["-pattacker", "up", "-d"],
      ["--project-name=attacker", "config", "--format", "json"],
      ["--project-directory=/tmp", "config", "--format", "json"],
      ["--profile=attacker", "config", "--format", "json"],
      ...["up", "create", "start", "restart", "run", "unpause", "watch"].map((command) => [command]),
    ];
    for (const arguments_ of candidates) {
      fs.rmSync(marker, { force: true });
      const result = spawnSync("/bin/bash", [path.join(import.meta.dirname, "compose-vps.sh"), ...arguments_], {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${fakeBin}:${process.env.PATH}`,
          COMPOSE_ENV_FILE: envFile,
          HOSTED_TEST_DOCKER_MARKER: marker,
        },
      });
      assert.notEqual(result.status, 0, `${arguments_.join(" ")} unexpectedly passed`);
      assert.match(result.stderr, /caller-controlled|exact internal config --format json|render-only/i);
      assert.equal(fs.existsSync(marker), false, `${arguments_.join(" ")} reached Docker`);
    }
  } finally {
    removeFixtureTree(root);
  }
});

test("activation gate requires an explicit lock and the canonical global project before mutation", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-empty-")));
  try {
    const fixture = activationGateFixture(root);
    const missing = spawnSync("/bin/bash", activationGateArguments(fixture), {
      encoding: "utf8",
      env: fixture.environment,
    });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /verified hosted workload lock is required/i);
    assert.equal(fs.existsSync(fixture.log), false);

    const wrongProject = spawnSync("/bin/bash", [
      fixture.gate,
      "--project-name", "fixture",
      "--env-file", fixture.envFile,
      "--release-context", fixture.currentReleaseContext,
      "--lock", fixture.currentLock,
      "--confirm", "ACTIVATE-HOSTED-WORKLOADS",
    ], {
      encoding: "utf8",
      env: fixture.environment,
    });
    assert.notEqual(wrongProject.status, 0);
    assert.match(wrongProject.stderr, /canonical project platform_infra_vps/i);
    assert.equal(fs.existsSync(fixture.log), false);

    for (const hostile of [
      ["--compose-file", fixture.currentModel],
      ["--project-directory", fixture.repository],
      ["--profile", "attacker"],
    ]) {
      const rejected = spawnSync("/bin/bash", activationGateArguments(
        fixture,
        "--lock", fixture.currentLock,
        ...hostile,
      ), {
        encoding: "utf8",
        env: fixture.environment,
      });
      assert.notEqual(rejected.status, 0);
      assert.equal(fs.existsSync(fixture.log), false);
    }
  } finally {
    removeFixtureTree(root);
  }
});

test("activation gate runs one canonical global transaction with core validation, firewall ordering and postdeploy", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-order-")));
  try {
    const fixture = activationGateFixture(root);
    const result = spawnSync("/bin/bash", activationGateArguments(
      fixture,
      "--lock", fixture.currentLock,
      "--run-postdeploy",
    ), {
      encoding: "utf8",
      env: { ...fixture.environment, HOSTED_WORKLOAD_LOCK: fixture.otherLock },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const trace = fs.readFileSync(fixture.log, "utf8").trim().split("\n");
    assert.ok(trace.includes(`render:${fixture.currentLock}:config --format json`));
    assert.equal(trace.some((line) => line.startsWith(`render:${fixture.otherLock}:`)), false);
    assert.ok(trace.some((line) => line === "render::config --format json"), "real core validation did not render the canonical core model");
    const createLine = trace.find((line) => /docker:.* compose .* create /.test(line));
    assert.ok(createLine, "global create was not reached");
    for (const service of fixture.currentServices) assert.match(createLine, new RegExp(`(?:^| )${service}(?: |$)`));
    const createIndex = trace.findIndex((line) => /docker:.* create /.test(line));
    const ownershipIndex = trace.findIndex((line) => line === `ownership:${fixture.currentLock}`);
    const applyIndex = trace.findIndex((line) => line === `firewall:--apply:${fixture.currentLock}`);
    const verifyIndex = trace.findIndex((line) => line === `firewall:--verify:${fixture.currentLock}`);
    const startIndex = trace.findIndex((line) => /docker:.* start /.test(line));
    const workloadStartIndex = trace.findIndex((line) => /docker:.* start .*cid-current-app-web(?: |$)/.test(line));
    const postdeployIndex = trace.findIndex((line) => line === `postdeploy:${fixture.envFile}`);
    assert.ok(
      createIndex >= 0
      && createIndex < ownershipIndex
      && ownershipIndex < applyIndex
      && applyIndex < verifyIndex
      && verifyIndex < startIndex
      && startIndex < workloadStartIndex
      && workloadStartIndex < postdeployIndex,
    );
    const active = JSON.parse(fs.readFileSync(path.join(fixture.state, "active.json"), "utf8"));
    assert.equal(active.projectName, "platform_infra_vps");
    assert.equal(active.state, "hosted");
    assert.deepEqual(active.serviceNames, fixture.currentServices);
  } finally {
    removeFixtureTree(root);
  }
});

test("activation gate rejects a rendered workload-labelled service not present in the verified lock", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-extra-service-")));
  try {
    const fixture = activationGateFixture(root);
    const model = JSON.parse(fs.readFileSync(fixture.currentModel, "utf8"));
    model.services["attacker-app-web"] = {
      image: "example.invalid/attacker@sha256:c",
      labels: { "com.platform.workload-id": "attacker-app" },
    };
    fs.writeFileSync(fixture.currentModel, `${JSON.stringify(model)}\n`);
    const result = spawnSync("/bin/bash", activationGateArguments(
      fixture,
      "--lock", fixture.currentLock,
    ), { encoding: "utf8", env: fixture.environment });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not exact for the verified hosted lock/i);
    const trace = fs.readFileSync(fixture.log, "utf8");
    assert.doesNotMatch(trace, /docker:.* compose .* create /);
  } finally {
    removeFixtureTree(root);
  }
});

test("activation gate rejects missing, empty, extra or wrong platform-extension crosswalk records", () => {
  const variants = [
    ["missing", (bundle) => { delete bundle.platformExtensionRecords; }],
    ["empty", (bundle) => { bundle.platformExtensionRecords = []; }],
    ["extra", (bundle) => {
      bundle.platformExtensionRecords.push({
        workloadId: "current-app",
        serviceName: "redis",
        networkNames: ["current_app_private"],
      });
    }],
    ["wrong-network", (bundle) => {
      bundle.platformExtensionRecords[0].networkNames = ["current_app_wrong"];
    }],
  ];
  for (const [name, mutate] of variants) {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `hosted-extension-${name}-`)));
    try {
      const fixture = activationGateFixture(root);
      const bundle = JSON.parse(fs.readFileSync(fixture.currentLock, "utf8"));
      mutate(bundle);
      fs.writeFileSync(fixture.currentLock, `${JSON.stringify(bundle)}\n`, { mode: 0o600 });
      const result = spawnSync("/bin/bash", activationGateArguments(
        fixture,
        "--lock", fixture.currentLock,
      ), { encoding: "utf8", env: fixture.environment });
      assert.notEqual(result.status, 0, `${name} extension records unexpectedly passed`);
      assert.match(
        result.stderr,
        /activation bundle is invalid|extension records do not exactly bind/i,
        `${name} did not fail at the signed extension boundary`,
      );
      const trace = fs.existsSync(fixture.log) ? fs.readFileSync(fixture.log, "utf8") : "";
      assert.doesNotMatch(trace, /docker:.* compose .* create /);
    } finally {
      removeFixtureTree(root);
    }
  }
});

test("SIGKILL at every activation boundary leaves a durable pending journal that can be recovered", () => {
  const phases = [
    ["intent", "intent", []],
    ["quiesced", "quiesced", []],
    ["created", "created", []],
    ["firewall-active", "firewall-active", []],
    ["start", "firewall-active", []],
    ["postdeploy", "runtime-verified", ["--run-postdeploy"]],
  ];
  for (const [pausePoint, expectedJournalPhase, extra] of phases) {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `hosted-kill-${pausePoint}-`)));
    try {
      const fixture = activationGateFixture(root);
      const interrupted = interruptActivation(
        fixture,
        pausePoint,
        "SIGKILL",
        "--lock", fixture.currentLock,
        ...extra,
      );
      assert.equal(interrupted.signal, "SIGKILL", `${pausePoint} did not receive SIGKILL`);
      const pending = JSON.parse(fs.readFileSync(path.join(fixture.state, "journal.json"), "utf8"));
      assert.equal(pending.version, 2);
      assert.equal(pending.state, "pending");
      assert.equal(pending.phase, expectedJournalPhase);
      assert.equal(pending.releaseId, "release-fixture-hosted");

      const recovered = spawnSync("/bin/bash", activationGateArguments(
        fixture,
        "--lock", fixture.currentLock,
        "--recover-pending",
      ), { encoding: "utf8", env: fixture.environment });
      assert.equal(recovered.status, 0, `${pausePoint}\n${recovered.stdout}\n${recovered.stderr}`);
      const journal = JSON.parse(fs.readFileSync(path.join(fixture.state, "journal.json"), "utf8"));
      const active = JSON.parse(fs.readFileSync(path.join(fixture.state, "active.json"), "utf8"));
      assert.equal(journal.state, "complete");
      assert.equal(journal.phase, "complete");
      assert.equal(active.state, "hosted");
      assert.deepEqual(active.serviceNames, fixture.currentServices);
    } finally {
      removeFixtureTree(root);
    }
  }
});

test("a new trusted release context can recover a pending transaction from the retained prior context", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-cross-release-recovery-")));
  try {
    const fixture = activationGateFixture(root);
    const interrupted = interruptActivation(
      fixture,
      "created",
      "SIGKILL",
      "--lock", fixture.currentLock,
    );
    assert.equal(interrupted.signal, "SIGKILL");
    const pending = JSON.parse(fs.readFileSync(path.join(fixture.state, "journal.json"), "utf8"));
    assert.equal(pending.releaseId, "release-fixture-hosted");
    const priorContextSha = pending.releaseContextSha256;

    const recovered = spawnSync("/bin/bash", activationGateArgumentsForContext(
      fixture,
      fixture.nextReleaseContext,
      "--lock", fixture.currentLock,
      "--recover-pending",
    ), { encoding: "utf8", env: fixture.environment });
    assert.equal(recovered.status, 0, `${recovered.stdout}\n${recovered.stderr}`);
    const active = JSON.parse(fs.readFileSync(path.join(fixture.state, "active.json"), "utf8"));
    assert.equal(active.releaseId, "release-fixture-hosted-next");
    assert.notEqual(active.releaseContextSha256, priorContextSha);
    assert.equal(active.state, "hosted");
    assert.deepEqual(active.serviceNames, fixture.currentServices);
  } finally {
    removeFixtureTree(root);
  }
});

test("SIGTERM during start runs the fail-closed rollback instead of leaving a pending transaction", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-term-start-")));
  try {
    const fixture = activationGateFixture(root);
    const interrupted = interruptActivation(
      fixture,
      "start",
      "SIGTERM",
      "--lock", fixture.currentLock,
    );
    assert.equal(interrupted.signal, null);
    assert.equal(interrupted.code, 71, `${interrupted.stdout}\n${interrupted.stderr}`);
    const journal = JSON.parse(fs.readFileSync(path.join(fixture.state, "journal.json"), "utf8"));
    assert.equal(journal.state, "complete");
    assert.equal(journal.phase, "complete");
    const docker = JSON.parse(fs.readFileSync(fixture.dockerState, "utf8"));
    for (const service of fixture.baseServices) {
      const container = Object.values(docker.containers).find((candidate) => candidate.service === service);
      assert.equal(container?.running, true, `${service} was not restored after SIGTERM`);
    }
  } finally {
    removeFixtureTree(root);
  }
});

test("activation failure restores the canonical no-hosted state by creating every fallback service", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-rollback-")));
  try {
    const fixture = activationGateFixture(root);
    const result = spawnSync("/bin/bash", activationGateArguments(
      fixture,
      "--lock", fixture.currentLock,
    ), {
      encoding: "utf8",
      env: { ...fixture.environment, HOSTED_TEST_FAIL_SERVICE: "current-app-web" },
    });
    assert.equal(result.status, 71, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /canonical no-hosted state was restored/i);
    const trace = fs.readFileSync(fixture.log, "utf8").trim().split("\n");
    const failedStartIndex = trace.findIndex((line) => /docker:.* start .*cid-current-app-web(?: |$)/.test(line));
    const rollbackIndex = trace.findIndex((line) => line === "firewall:--rollback:");
    const createLines = trace.filter((line) => /docker:.* compose .* create /.test(line));
    assert.ok(failedStartIndex >= 0 && rollbackIndex > failedStartIndex);
    assert.equal(createLines.length, 2);
    const fallbackCreate = createLines.at(-1);
    for (const service of fixture.baseServices) assert.match(fallbackCreate, new RegExp(`(?:^| )${service}(?: |$)`));
    assert.doesNotMatch(fallbackCreate, /(?:^| )current-app-web(?: |$)/);
    const docker = JSON.parse(fs.readFileSync(fixture.dockerState, "utf8"));
    for (const service of fixture.baseServices) {
      const container = Object.values(docker.containers).find((candidate) => candidate.service === service);
      assert.equal(container?.running, true, `${service} was not restored running`);
    }
  } finally {
    removeFixtureTree(root);
  }
});

test("hosted to explicit zero performs a real full-project transition and deactivates egress enforcement", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-zero-")));
  try {
    const fixture = activationGateFixture(root);
    const hosted = spawnSync("/bin/bash", activationGateArguments(
      fixture,
      "--lock", fixture.currentLock,
    ), { encoding: "utf8", env: fixture.environment });
    assert.equal(hosted.status, 0, `${hosted.stdout}\n${hosted.stderr}`);
    assert.equal(fixture.state, fixture.noHostedState);
    const hostedActive = JSON.parse(fs.readFileSync(path.join(fixture.state, "active.json"), "utf8"));
    assert.equal(hostedActive.state, "hosted");
    assert.equal(hostedActive.lockSha256, "a".repeat(64));
    assert.equal(hostedActive.releaseId, "release-fixture-hosted");

    fs.writeFileSync(fixture.log, "");
    const zero = spawnSync("/bin/bash", activationGateArguments(
      fixture,
      "--no-hosted-workloads",
      "--previous-lock", fixture.currentLock,
    ), { encoding: "utf8", env: fixture.environment });
    assert.equal(zero.status, 0, `${zero.stdout}\n${zero.stderr}`);
    const trace = fs.readFileSync(fixture.log, "utf8").trim().split("\n");
    const projectStopIndex = trace.findIndex((line) => /docker:.* stop --time 30 /.test(line));
    const removeIndex = trace.findIndex((line) => /docker:.* rm .*cid-current-app-web(?: |$)/.test(line));
    const createIndex = trace.findIndex((line) => /docker:.* compose .* create /.test(line));
    const deactivateIndex = trace.findIndex((line) => line === "firewall:--rollback:");
    const startIndex = trace.findIndex((line) => /docker:.* start /.test(line));
    assert.ok(
      projectStopIndex >= 0
      && projectStopIndex < removeIndex
      && removeIndex < createIndex
      && createIndex < deactivateIndex
      && deactivateIndex < startIndex,
    );
    const createLine = trace[createIndex];
    for (const service of fixture.baseServices) assert.match(createLine, new RegExp(`(?:^| )${service}(?: |$)`));
    assert.doesNotMatch(createLine, /(?:^| )current-app-web(?: |$)/);
    const docker = JSON.parse(fs.readFileSync(fixture.dockerState, "utf8"));
    assert.deepEqual(
      Object.values(docker.containers).map((container) => container.service).sort(),
      fixture.baseServices,
    );
    assert.ok(Object.values(docker.containers).every((container) => container.running));
    const active = JSON.parse(fs.readFileSync(path.join(fixture.noHostedState, "active.json"), "utf8"));
    assert.equal(active.state, "no-hosted");
    assert.equal(active.releaseId, "release-fixture-zero");
    assert.notEqual(active.releaseContextSha256, hostedActive.releaseContextSha256);
    assert.deepEqual(active.serviceNames, fixture.baseServices);
  } finally {
    removeFixtureTree(root);
  }
});

test("the shared activation mutex serializes different trusted release contexts", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-contention-")));
  let holder;
  try {
    const fixture = activationGateFixture(root);
    const mutex = path.join(fixture.state, "activation.lock");
    const ready = path.join(root, "mutex-ready");
    fs.writeFileSync(mutex, "", { mode: 0o600 });
    fs.chmodSync(mutex, 0o600);
    holder = spawn("python3", ["-c", `
import fcntl
import os
import sys
import time

descriptor = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(descriptor, fcntl.LOCK_EX)
with open(sys.argv[2], "x", encoding="utf-8"):
    pass
time.sleep(30)
`, mutex, ready], { stdio: "ignore" });
    const sleeper = new Int32Array(new SharedArrayBuffer(4));
    const deadline = Date.now() + 5_000;
    while (!fs.existsSync(ready) && Date.now() < deadline) Atomics.wait(sleeper, 0, 0, 20);
    assert.equal(fs.existsSync(ready), true, "mutex holder did not acquire the fixture lock");

    const result = spawnSync("/bin/bash", activationGateArguments(
      fixture,
      "--no-hosted-workloads",
    ), { encoding: "utf8", env: fixture.environment });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /another platform activation transaction holds the global mutex/i);
    const trace = fs.existsSync(fixture.log) ? fs.readFileSync(fixture.log, "utf8") : "";
    assert.doesNotMatch(trace, /docker:.* compose .* create /);
    assert.doesNotMatch(trace, /^firewall:/m);
  } finally {
    holder?.kill("SIGTERM");
    removeFixtureTree(root);
  }
});

test("activation mutex symlink cannot truncate its target or bypass the global lock", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-mutex-")));
  try {
    const fixture = activationGateFixture(root);
    const sentinel = path.join(root, "mutex-sentinel");
    const mutex = path.join(fixture.state, "activation.lock");
    fs.writeFileSync(sentinel, "do-not-truncate\n", { mode: 0o600 });
    fs.symlinkSync(sentinel, mutex);
    const result = spawnSync("/bin/bash", activationGateArguments(
      fixture,
      "--lock", fixture.currentLock,
    ), { encoding: "utf8", env: fixture.environment });
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /activation mutex (?:must be the stable, single deployment-owned mode-0600 regular file|could not be opened safely)/i,
    );
    assert.equal(fs.readFileSync(sentinel, "utf8"), "do-not-truncate\n");
    assert.equal(fs.lstatSync(mutex).isSymbolicLink(), true);
    const trace = fs.existsSync(fixture.log) ? fs.readFileSync(fixture.log, "utf8") : "";
    assert.doesNotMatch(trace, /docker:.* compose .* create /);
    assert.doesNotMatch(trace, /^firewall:/m);
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
