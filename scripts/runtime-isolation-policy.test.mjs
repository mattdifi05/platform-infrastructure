import assert from "node:assert/strict";
import test from "node:test";

import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

test("accepts bounded platform and external workload services", () => {
  const report = evaluateRuntimeIsolation(fixture(), { projectName: "fixture" });
  assert.equal(report.status, "passed", report.failures.join("\n"));
  assert.equal(report.summary.rawSocketOwners.join(","), "docker-operation-gateway");
  assert.equal(report.summary.hostedWorkloads, 1);
  assert.equal(report.checks.find((item) => item.id === "scheduler-has-no-docker-api")?.status, "passed");
  assert.equal(report.checks.find((item) => item.id === "socket-network-members")?.status, "passed");
  assert.equal(report.checks.find((item) => item.id === "docker-gateway-no-host-ports")?.status, "passed");
  assert.equal(report.checks.find((item) => item.id === "docker-gateway-principal-secret-exclusive")?.status, "passed");
});

test("rejects a workload raw socket, bind and broad host mount", () => {
  const config = fixture();
  config.services["example-app-web"].volumes.push(
    { type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock" },
    { type: "bind", source: "/srv/platform", target: "/mnt/host/platform" },
  );
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-bind-mounts-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-deny-mount-mnt-host-example-app-web/);
});

test("rejects PID sharing, non-numeric workload identity and added capabilities", () => {
  const config = fixture();
  config.services["example-app-web"].user = "app:app";
  config.services["example-app-web"].pid = "service:postgres";
  config.services["example-app-web"].cap_add = ["NET_ADMIN"];
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-numeric-user-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-private-pid-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-drop-all-capabilities-example-app-web/);
});

test("rejects unbounded or non-local workload logging at runtime", () => {
  for (const logging of [
    undefined,
    { driver: "json-file" },
    { driver: "local", options: { "max-size": "1g", "max-file": "99" } },
  ]) {
    const config = fixture();
    config.services["example-app-web"].logging = logging;
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-bounded-local-logging-example-app-web/);
  }
});

test("rejects workload swap and OOM overrides at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].memswap_limit = 512 * 1024 * 1024;
  config.services["example-app-web"].oom_score_adj = -1000;
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-swap-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-no-oom-overrides-example-app-web/);
});

test("rejects workload service volume inheritance independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].volumes_from = ["postgres:rw"];
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-volumes-from-example-app-web/);
});

test("rejects named-volume protected-target shadowing and nested mount controls", () => {
  for (const mount of [
    { type: "volume", source: "example-app_data", target: "/var/run/docker.sock" },
    { type: "volume", source: "example-app_data", target: "/run/platform/hosted-workloads.lock.json" },
    { type: "volume", source: "example-app_data", target: "/data", read_only: false },
    { type: "volume", source: "example-app_data", target: "/data", volume: { nocopy: false, subpath: "host" } },
  ]) {
    const config = fixture();
    config.volumes = { "example-app_data": { name: "fixture_example-app_data" } };
    config.services["example-app-web"].volumes = [mount];
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-exact-volume-mounts-example-app-web/);
  }
});

test("FG-057 countercheck rejects external-container volume inheritance", () => {
  const config = fixture();
  config.services["example-app-web"].volumes_from = ["container:platform-postgres:rw"];
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-external-container-volume-inheritance-example-app-web/);
});

test("rejects workload lifecycle hooks independently at runtime", () => {
  for (const hook of ["post_start", "pre_start", "pre_stop"]) {
    const config = fixture();
    config.services["example-app-web"][hook] = [{ command: "id" }];
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-no-lifecycle-hooks-example-app-web/);
  }
});

test("rejects both workload scaling controls independently at runtime", () => {
  for (const mutation of [
    (service) => { service.scale = 2; },
    (service) => { service.deploy = { replicas: 2 }; },
    (service) => { service.deploy = { mode: "global" }; },
  ]) {
    const config = fixture();
    mutation(config.services["example-app-web"]);
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-no-scaling-example-app-web/);
  }
});

test("rejects workload config grants independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].configs = [{ source: "platform-config", target: "/run/config" }];
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-configs-example-app-web/);
});

test("rejects workload inline and host-environment config definitions at runtime", () => {
  for (const definition of [{ content: "hostile" }, { environment: "HOST_SECRET" }]) {
    const config = fixture();
    config.configs = { example_app_inline: definition };
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-no-inline-config-definitions/);
  }
});

test("rejects workload host device controls independently at runtime", () => {
  for (const mutation of [
    (service) => { service.devices = [{ source: "/dev/kvm", target: "/dev/kvm" }]; },
    (service) => { service.device_cgroup_rules = ["c 10:232 rwm"]; },
    (service) => { service.blkio_config.device_write_iops = [{ path: "/dev/sda", rate: 1000 }]; },
  ]) {
    const config = fixture();
    mutation(config.services["example-app-web"]);
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-(no-device-access|bounded-global-blkio)-example-app-web/);
  }
});

test("rejects workload label files, ambient environment and deploy controls independently at runtime", () => {
  for (const [mutation, check] of [
    [(service) => { service.label_file = "/tmp/attacker.labels"; }, "workload-no-label-file"],
    [(service) => { service.environment = { DATABASE_URL: null }; }, "workload-explicit-environment"],
    [(service) => { service.environment = ["DATABASE_URL"]; }, "workload-explicit-environment"],
    [(service) => { service.deploy = { resources: { limits: { cpus: "64", memory: "64G", pids: 999999 } } }; }, "workload-no-deploy-controls"],
  ]) {
    const config = fixture();
    mutation(config.services["example-app-web"]);
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), new RegExp(`${check}-example-app-web`));
  }
});

test("rejects workload supplemental device groups independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].group_add = ["video", "44"];
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-supplemental-groups-example-app-web/);
});

test("rejects workload local volume driver options independently at runtime", () => {
  const config = fixture();
  config.volumes = {
    example_app_data: {
      driver: "local",
      driver_opts: { type: "none", o: "bind", device: "/srv/platform" },
    },
  };
  config.services["example-app-web"].volumes.push({ type: "volume", source: "example_app_data", target: "/data" });
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-local-volume-options-example-app-web/);
});

test("rejects external and foreign workload volume aliases at runtime", () => {
  for (const definition of [
    { external: true, name: "foreign_data" },
    { name: "foreign_data" },
    { name: "attacker_example-app_data" },
  ]) {
    const config = fixture();
    config.volumes = { "example-app_data": definition };
    config.services["example-app-web"].volumes.push({ type: "volume", source: "example-app_data", target: "/data" });
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-owned-volumes-example-app-web/);
  }
});

test("rejects foreign external secret aliases at runtime", () => {
  for (const definition of [
    { external: true },
    { external: true, name: "foreign_api_key" },
    { external: true, name: "attacker_example-app-api-key" },
  ]) {
    const config = fixture();
    config.secrets = { "example-app-api-key": definition };
    config.services["example-app-web"].secrets = [{ source: "example-app-api-key", target: "example-app-api-key" }];
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-owned-secrets-example-app-web/);
  }
});

test("rejects foreign workload networks and attachment aliases at runtime", () => {
  for (const mutation of [
    (config) => { config.networks.example_app_ingress.name = "attacker_example_app_ingress"; },
    (config) => { config.services["example-app-web"].networks.example_app_ingress = { aliases: ["postgres"] }; },
    (config) => { config.services["example-app-web"].networks.foreign_ingress = null; },
  ]) {
    const config = fixture();
    mutation(config);
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-network-identity-example-app-web/);
  }
  const missingExpectedProject = evaluateRuntimeIsolation(fixture());
  assert.equal(missingExpectedProject.status, "failed");
  assert.match(missingExpectedProject.failures.join("\n"), /workload-project-name-bound/);
  const spoofed = fixture();
  spoofed.name = "attacker";
  spoofed.networks.example_app_ingress.name = "attacker_example_app_ingress";
  const spoofedProject = evaluateRuntimeIsolation(spoofed, { projectName: "fixture" });
  assert.equal(spoofedProject.status, "failed");
  assert.match(spoofedProject.failures.join("\n"), /workload-project-name-bound|workload-network-identity/);
});

test("rejects workload network topology overrides at runtime", () => {
  for (const mutate of [
    (network) => { network.internal = false; },
    (network) => { network.driver = "bridge"; },
    (network) => { network.driver_opts = { "com.docker.network.bridge.name": "host0" }; },
    (network) => { network.ipam = { config: [{ subnet: "172.30.0.0/16" }] }; },
    (network) => { network.attachable = true; },
    (network) => { network.labels = { owner: "attacker" }; },
    (network) => { network.enable_ipv4 = false; },
    (network) => { network.enable_ipv6 = true; },
  ]) {
    const config = fixture();
    mutate(config.networks.example_app_ingress);
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-network-topology-example-app-web/);
  }
  const egress = fixture();
  egress.services["example-app-web"].networks = { example_app_egress: null };
  delete egress.networks.example_app_ingress;
  egress.networks.example_app_egress = { internal: false, name: "fixture_example_app_egress" };
  const accepted = evaluateRuntimeIsolation(egress, { projectName: "fixture" });
  assert.equal(accepted.status, "passed", accepted.failures.join("\n"));
});

test("rejects a workload identity that collides with a protected core network", () => {
  const config = fixture();
  const service = config.services["example-app-web"];
  delete config.services["example-app-web"];
  config.services["platform-web"] = {
    ...service,
    labels: { "com.platform.workload-id": "platform", "com.platform.workload-role": "web" },
    networks: { platform_postgres: null },
  };
  config.services.postgres.networks = { platform_postgres: null };
  delete config.networks.example_app_ingress;
  config.networks.platform_postgres = {
    internal: true,
    name: "fixture_platform_postgres",
    labels: { "com.platform.trust-zone": "postgres" },
  };
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture", protectedNetworkNames: ["platform_postgres"] });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-protected-network-platform-web/);
});

test("binds all six hosted workload runtime identity labels", () => {
  const expected = runtimeIdentityFixture();
  const accepted = fixture();
  Object.assign(accepted.services["example-app-web"].labels, expected);
  assert.equal(evaluateRuntimeIsolation(accepted, { projectName: "fixture", runtimeIdentity: expected }).status, "passed");
  for (const label of Object.keys(expected)) {
    const config = fixture();
    Object.assign(config.services["example-app-web"].labels, expected);
    config.services["example-app-web"].labels[label] = `wrong-${label}`;
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture", runtimeIdentity: expected });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-runtime-identity-example-app-web/);
  }
  const missing = fixture();
  Object.assign(missing.services["example-app-web"].labels, expected);
  delete missing.services["example-app-web"].labels["com.platform.runtime.tree"];
  assert.equal(evaluateRuntimeIsolation(missing, { projectName: "fixture", runtimeIdentity: expected }).status, "failed");

  const legacy = fixture();
  Object.assign(legacy.services["example-app-web"].labels, expected, {
    "com.platform.runtime.render-sha256": "f".repeat(64),
  });
  const legacyReport = evaluateRuntimeIsolation(legacy, { projectName: "fixture", runtimeIdentity: expected });
  assert.equal(legacyReport.status, "failed");
  assert.match(legacyReport.failures.join("\n"), /workload-runtime-identity-example-app-web/);
});

test("rejects workload Compose API socket access independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].use_api_socket = true;
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-api-socket-example-app-web/);
});

test("rejects workload external service providers independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].provider = { type: "hostile-provider", options: { command: "/host/tool" } };
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-provider-example-app-web/);
});

test("rejects workload OCI runtime overrides independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].runtime = "kata-runtime";
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-runtime-override-example-app-web/);
});

test("rejects workload stop grace period overrides independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].stop_grace_period = "24h";
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-stop-grace-override-example-app-web/);
});

test("rejects workload GPU and accelerator requests independently at runtime", () => {
  for (const mutation of [
    (service) => { service.gpus = "all"; },
    (service) => { service.device_requests = [{ capabilities: [["gpu"]] }]; },
    (service) => { service.deploy = { resources: { reservations: { devices: [{ driver: "nvidia", capabilities: ["gpu"] }] } } }; },
    (service) => { service.deploy = { resources: { reservations: { generic_resources: [{ discrete_resource_spec: { kind: "GPU", value: 1 } }] } } }; },
  ]) {
    const config = fixture();
    mutation(config.services["example-app-web"]);
    const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-no-accelerators-example-app-web/);
  }
});

test("rejects missing memory limits and budget overcommit", () => {
  const config = fixture();
  config.services["example-app-web"].mem_limit = 0;
  config.services.postgres.mem_limit = 99 * 1024 * 1024 * 1024;
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /resource-memory-example-app-web/);
  assert.match(report.failures.join("\n"), /resource-memory-admission/);
});

test("rejects security_opt entries that disable confinement", () => {
  const config = fixture();
  config.services["example-app-web"].security_opt = ["no-new-privileges:true", "seccomp=unconfined"];
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-exact-security-opt-example-app-web/);
});

test("rejects host-published gateways and extra Docker-control network members", () => {
  const config = fixture();
  config.services["docker-operation-gateway"].ports = ["0.0.0.0:8787:8787"];
  config.services["example-app-web"].networks.platform_docker_control = null;
  const report = evaluateRuntimeIsolation(config, { projectName: "fixture" });
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-gateway-no-host-ports/);
  assert.match(report.failures.join("\n"), /socket-network-members/);
});

test("rejects scheduler Docker API access and missing principal authentication", () => {
  const config = fixture();
  config.services["backup-scheduler"].environment.DOCKER_HOST = "tcp://docker-operation-gateway:2375";
  config.services["docker-operation-gateway"].secrets = [];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /scheduler-has-no-docker-api/);
  assert.match(report.failures.join("\n"), /docker-gateway-principal-auth/);
});

test("rejects mounting the scheduler principal credential into any third service", () => {
  const config = fixture();
  config.services["example-app-web"].secrets = ["backup_scheduler_docker_gateway_token"];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-gateway-principal-secret-exclusive/);
});

test("rejects a networked broker bootstrap or writable workload lock", () => {
  const config = fixture();
  config.services["broker-auth-bootstrap"].network_mode = "bridge";
  config.services["broker-auth-bootstrap"].volumes[0].read_only = false;
  config.services.nats.command.push("--user", "global", "--pass", "shared");
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /broker-bootstrap-no-network/);
  assert.match(report.failures.join("\n"), /broker-bootstrap-lock-read-only/);
  assert.match(report.failures.join("\n"), /nats-no-global-credential-flags/);
});

function fixture() {
  const services = {};
  services["example-app-web"] = bounded({
    read_only: true,
    user: "1000:1000",
    logging: { driver: "local", options: { "max-size": "10m", "max-file": "3" } },
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
    networks: { example_app_ingress: null },
  });
  services["control-center"] = bounded({ read_only: true, cpu_shares: 1024, volumes: [], networks: {} });
  services["project-router"] = bounded({
    read_only: true,
    volumes: [
      { type: "bind", source: "/srv/apps", target: "/var/www/projects", read_only: true },
      { type: "bind", source: "/srv/state", target: "/var/www/project-state", read_only: true },
    ],
    networks: {},
  });
  services["platform-alert-dispatcher"] = bounded({ read_only: true, networks: {} });
  services["broker-auth-bootstrap"] = bounded({
    read_only: true,
    network_mode: "none",
    cap_drop: ["ALL"],
    cap_add: ["CHOWN"],
    volumes: [
      { type: "bind", source: "/private/hosted.lock.json", target: "/run/platform/hosted-workloads.lock.json", read_only: true },
      { type: "volume", source: "redis_auth_config", target: "/out/redis", read_only: false },
      { type: "volume", source: "nats_auth_config", target: "/out/nats", read_only: false },
    ],
    networks: {},
  });
  services.redis = bounded({
    volumes: [{ type: "volume", source: "redis_auth_config", target: "/run/platform-broker", read_only: true }],
    networks: {},
  });
  services.nats = bounded({
    user: "1000:1000",
    entrypoint: ["/bin/sh", "-ec"],
    command: ["cd /run/platform-broker && sha256sum -c nats-server.conf.sha256 >/dev/null && exec /nats-server --config /run/platform-broker/nats-server.conf"],
    volumes: [{ type: "volume", source: "nats_auth_config", target: "/run/platform-broker", read_only: true }],
    networks: {},
  });
  services["backup-scheduler"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    environment: { PLATFORM_DOCKER_GATEWAY_URL: "http://docker-operation-gateway:8787", BACKUP_SCHEDULER_DOCKER_GATEWAY_TOKEN_FILE: "/run/secrets/backup_scheduler_docker_gateway_token" },
    secrets: ["backup_scheduler_docker_gateway_token"],
    volumes: [],
    networks: { platform_docker_control: null },
  });
  services["docker-operation-gateway"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    entrypoint: ["node", "/infra/scripts/docker-operation-gateway.mjs"],
    environment: { BACKUP_SCHEDULER_DOCKER_GATEWAY_TOKEN_FILE: "/run/secrets/backup_scheduler_docker_gateway_token" },
    secrets: ["backup_scheduler_docker_gateway_token"],
    volumes: [{ type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
    networks: { platform_docker_control: null },
  });
  services.postgres = bounded({ networks: {} });
  return {
    name: "fixture",
    services,
    networks: {
      platform_docker_control: { internal: true },
      example_app_ingress: { internal: true, name: "fixture_example_app_ingress" },
    },
  };
}

function runtimeIdentityFixture() {
  return {
    "com.platform.runtime.candidate-id": "a".repeat(64),
    "com.platform.runtime.commit": "b".repeat(40),
    "com.platform.runtime.tree": "c".repeat(40),
    "com.platform.runtime.deployment-id": "deploy-20260721",
    "com.platform.runtime.source-render-sha256": "d".repeat(64),
    "com.platform.runtime.workload-lock-sha256": "e".repeat(64),
  };
}

function bounded(overrides = {}) {
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
    ...overrides,
  };
}
