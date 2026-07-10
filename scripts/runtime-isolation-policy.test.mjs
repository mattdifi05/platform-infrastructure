import assert from "node:assert/strict";
import test from "node:test";

import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

test("accepts bounded platform and external workload services", () => {
  const report = evaluateRuntimeIsolation(fixture());
  assert.equal(report.status, "passed", report.failures.join("\n"));
  assert.equal(report.summary.rawSocketOwners.join(","), "docker-socket-proxy");
  assert.equal(report.summary.hostedWorkloads, 1);
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

test("rejects missing memory limits and budget overcommit", () => {
  const config = fixture();
  config.services["example-app-web"].mem_limit = 0;
  config.services.postgres.mem_limit = 99 * 1024 * 1024 * 1024;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /resource-memory-example-app-web/);
  assert.match(report.failures.join("\n"), /resource-memory-admission/);
});

test("rejects mutable proxy images and extra socket-network members", () => {
  const config = fixture();
  config.services["docker-socket-proxy"].image = "ghcr.io/tecnativa/docker-socket-proxy:latest";
  config.services["docker-socket-proxy"].ports[0].host_ip = "0.0.0.0";
  config.services["example-app-web"].networks.platform_docker_control = null;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /socket-proxy-image-pinned/);
  assert.match(report.failures.join("\n"), /socket-proxy-loopback-only/);
  assert.match(report.failures.join("\n"), /socket-network-members/);
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
  services["backup-scheduler"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    environment: { DOCKER_HOST: "tcp://docker-socket-proxy:2375", DOCKER_API_VERSION: "1.51" },
    volumes: [],
    networks: { platform_docker_control: null },
  });
  services["docker-socket-proxy"] = bounded({
    read_only: true,
    cpu_shares: 1024,
    image: `ghcr.io/tecnativa/docker-socket-proxy:v0.4.2@sha256:${"a".repeat(64)}`,
    environment: Object.fromEntries(["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"].map((key) => [key, "0"])),
    ports: [{ host_ip: "127.0.0.1", published: "2376", target: 2375, protocol: "tcp" }],
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
