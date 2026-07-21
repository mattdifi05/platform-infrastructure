import assert from "node:assert/strict";
import test from "node:test";

import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

test("accepts bounded platform and external workload services", () => {
  const report = evaluateRuntimeIsolation(fixture());
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
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-bind-mounts-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-deny-mount-mnt-host-example-app-web/);
});

test("rejects root workload identity and added capabilities", () => {
  const config = fixture();
  config.services["example-app-web"].user = "0:0";
  config.services["example-app-web"].cap_add = ["NET_ADMIN"];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-non-root-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-drop-all-capabilities-example-app-web/);
});

test("rejects workload service volume inheritance independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].volumes_from = ["postgres:rw"];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-volumes-from-example-app-web/);
});

test("FG-057 countercheck rejects external-container volume inheritance", () => {
  const config = fixture();
  config.services["example-app-web"].volumes_from = ["container:platform-postgres:rw"];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-external-container-volume-inheritance-example-app-web/);
});

test("rejects workload lifecycle hooks independently at runtime", () => {
  for (const hook of ["post_start", "pre_start", "pre_stop"]) {
    const config = fixture();
    config.services["example-app-web"][hook] = [{ command: "id" }];
    const report = evaluateRuntimeIsolation(config);
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
    const report = evaluateRuntimeIsolation(config);
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-no-scaling-example-app-web/);
  }
});

test("rejects workload config grants independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].configs = [{ source: "platform-config", target: "/run/config" }];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-configs-example-app-web/);
});

test("rejects workload host device controls independently at runtime", () => {
  for (const mutation of [
    (service) => { service.devices = [{ source: "/dev/kvm", target: "/dev/kvm" }]; },
    (service) => { service.device_cgroup_rules = ["c 10:232 rwm"]; },
  ]) {
    const config = fixture();
    mutation(config.services["example-app-web"]);
    const report = evaluateRuntimeIsolation(config);
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-no-device-access-example-app-web/);
  }
});

test("rejects workload supplemental device groups independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].group_add = ["video", "44"];
  const report = evaluateRuntimeIsolation(config);
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
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-local-volume-options-example-app-web/);
});

test("rejects workload Compose API socket access independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].use_api_socket = true;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-api-socket-example-app-web/);
});

test("rejects workload external service providers independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].provider = { type: "hostile-provider", options: { command: "/host/tool" } };
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-provider-example-app-web/);
});

test("rejects workload OCI runtime overrides independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].runtime = "kata-runtime";
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-runtime-override-example-app-web/);
});

test("rejects workload stop grace period overrides independently at runtime", () => {
  const config = fixture();
  config.services["example-app-web"].stop_grace_period = "24h";
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-no-stop-grace-override-example-app-web/);
});

test("rejects workload GPU and accelerator requests independently at runtime", () => {
  for (const mutation of [
    (service) => { service.gpus = "all"; },
    (service) => { service.device_requests = [{ capabilities: [["gpu"]] }]; },
    (service) => { service.deploy = { resources: { reservations: { devices: [{ driver: "nvidia", capabilities: ["gpu"] }] } } }; },
  ]) {
    const config = fixture();
    mutation(config.services["example-app-web"]);
    const report = evaluateRuntimeIsolation(config);
    assert.equal(report.status, "failed");
    assert.match(report.failures.join("\n"), /workload-no-accelerators-example-app-web/);
  }
});

test("rejects missing memory limits and budget overcommit", () => {
  const config = fixture();
  config.services["example-app-web"].mem_limit = 0;
  config.services.postgres.mem_limit = 99 * 1024 * 1024 * 1024;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /resource-memory-example-app-web/);
  assert.match(report.failures.join("\n"), /resource-memory-admission/);
});

test("rejects host-published gateways and extra Docker-control network members", () => {
  const config = fixture();
  config.services["docker-operation-gateway"].ports = ["0.0.0.0:8787:8787"];
  config.services["example-app-web"].networks.platform_docker_control = null;
  const report = evaluateRuntimeIsolation(config);
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
  return { services, networks: { platform_docker_control: { internal: true } } };
}

function bounded(overrides = {}) {
  return {
    cpus: 0.5,
    cpu_shares: 256,
    mem_limit: 128 * 1024 * 1024,
    mem_reservation: 32 * 1024 * 1024,
    pids_limit: 128,
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    blkio_config: { weight: 300 },
    environment: {},
    secrets: [],
    volumes: [],
    networks: {},
    ...overrides,
  };
}
