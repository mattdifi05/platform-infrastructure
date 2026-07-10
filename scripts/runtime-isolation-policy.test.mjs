import assert from "node:assert/strict";
import test from "node:test";

import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

test("accepts the bounded mount and socket model", () => {
  const report = evaluateRuntimeIsolation(fixture());
  assert.equal(report.status, "passed", report.failures.join("\n"));
  assert.equal(report.summary.rawSocketOwners.join(","), "docker-socket-proxy");
});

test("rejects a hosted raw socket and broad host mount", () => {
  const config = fixture();
  config.services["php-anniversary"].volumes.push(
    { source: "/var/run/docker.sock", target: "/var/run/docker.sock" },
    { source: "/srv/platform", target: "/mnt/host/d/docker" },
  );
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /app-no-docker-socket-php-anniversary/);
  assert.match(report.failures.join("\n"), /app-deny-mount-mnt-host-php-anniversary/);
});

test("rejects shared PHP admin secrets", () => {
  const config = fixture();
  config.services["php-stream"].secrets = [{ source: "smtp_password" }];
  config.services["php-stream"].environment.SMTP_PASSWORD_FILE = "/run/secrets/smtp_password";
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /php-no-admin-secrets-php-stream/);
  assert.match(report.failures.join("\n"), /php-no-shared-mail-or-gateway-php-stream/);
});

test("rejects missing memory limits and budget overcommit", () => {
  const config = fixture();
  config.services["node-ui"].mem_limit = 0;
  config.services.postgres.mem_limit = 99 * 1024 * 1024 * 1024;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /resource-memory-node-ui/);
  assert.match(report.failures.join("\n"), /resource-memory-admission/);
});

test("rejects mutable proxy images and extra socket-network members", () => {
  const config = fixture();
  config.services["docker-socket-proxy"].image = "ghcr.io/tecnativa/docker-socket-proxy:latest";
  config.services["docker-socket-proxy"].ports[0].host_ip = "0.0.0.0";
  config.services["node-ui"].networks.platform_docker_control = null;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /socket-proxy-image-pinned/);
  assert.match(report.failures.join("\n"), /socket-proxy-loopback-only/);
  assert.match(report.failures.join("\n"), /socket-network-members/);
});

function fixture() {
  const services = {};
  const appTargets = {
    "php-anniversary": "/opt/platform-source/anniversary",
    "php-fiplatform": "/opt/platform-source/fiplatform",
    "php-matthewdifilippo": "/opt/platform-source/matthewdifilippo",
    "php-stream": "/opt/platform-source/stream",
    "php-workcalendar": "/opt/platform-source/workcalendar",
    "node-account": "/workspace",
    "node-ui": "/workspace",
  };
  for (const [name, target] of Object.entries(appTargets)) {
    services[name] = bounded({
      read_only: true,
      environment: name.startsWith("node-") ? { NODE_PROJECT_INSTALL_COMMAND: "", NODE_PROJECT_BUILD_COMMAND: "" } : {},
      tmpfs: name.startsWith("php-") ? ["/var/www/projects:rw,size=128m"] : [],
      volumes: [{ source: `/srv/apps/${name}`, target, read_only: true }],
      networks: { app_ingress: null },
    });
  }
  for (const name of ["backend", "web", "worker-jobs", "worker-notifications"]) {
    services[name] = bounded({ read_only: true, volumes: [], networks: {} });
  }
  services["control-center"] = bounded({ read_only: true, cpu_shares: 1024, volumes: [], networks: {} });
  services["project-router"] = bounded({
    read_only: true,
    volumes: [
      { source: "/srv/apps", target: "/var/www/projects", read_only: true },
      { source: "/srv/state", target: "/var/www/project-state", read_only: true },
    ],
    networks: {},
  });
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
    volumes: [{ source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true }],
    networks: { platform_docker_control: null },
  });
  services.postgres = bounded({ volumes: [], networks: {} });
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
