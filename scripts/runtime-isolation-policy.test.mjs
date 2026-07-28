import assert from "node:assert/strict";
import test from "node:test";

import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

test("accepts the host-private immutable action broker boundary", () => {
  const report = evaluateRuntimeIsolation(fixture());
  assert.equal(report.status, "passed", report.failures.join("\n"));
  assert.equal(report.summary.rawSocketOwners.join(","), "docker-action-broker");
  assert.equal(report.summary.hostedWorkloads, 1);
  for (const id of [
    "docker-broker-immutable-image",
    "docker-broker-host-private",
    "docker-broker-exact-raw-socket",
    "docker-broker-socket-volume-not-aliased",
    "docker-broker-state-volume-not-aliased",
    "scheduler-uses-local-action-socket",
    "scheduler-has-no-docker-api",
  ]) {
    assert.equal(report.checks.find((item) => item.id === id)?.status, "passed", id);
  }
});

test("rejects workload raw socket, bind and broad host mounts", () => {
  const config = fixture();
  config.services["example-app-web"].volumes.push(
    { type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true },
    { type: "bind", source: "/srv/platform", target: "/mnt/host/platform", read_only: true },
  );
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /raw-socket-single-owner/);
  assert.match(report.failures.join("\n"), /workload-no-bind-mounts-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-deny-mount-mnt-host-example-app-web/);
});

test("rejects root workload identity, added capabilities and supplemental Docker group", () => {
  const config = fixture();
  config.services["example-app-web"].user = "0:0";
  config.services["example-app-web"].cap_add = ["NET_ADMIN"];
  config.services["example-app-web"].group_add = ["998"];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-non-root-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-drop-all-capabilities-example-app-web/);
  assert.match(report.failures.join("\n"), /workload-no-supplemental-groups-example-app-web/);
});

test("rejects a workload named-volume alias to a host path", () => {
  const config = fixture();
  config.volumes.example_data = {
    driver: "local",
    driver_opts: { type: "none", o: "bind", device: "/var/run" },
  };
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /workload-volume-no-host-alias-example-data-example-app-web/);
});

test("rejects broker socket and state volume alias substitution", () => {
  const external = fixture();
  external.volumes.docker_action_broker_socket = { external: true, name: "attacker_socket" };
  let report = evaluateRuntimeIsolation(external);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-socket-volume-not-aliased/);

  const driverOpts = fixture();
  driverOpts.volumes.docker_action_broker_state = {
    driver: "local",
    driver_opts: { type: "none", o: "bind", device: "/var/run" },
  };
  report = evaluateRuntimeIsolation(driverOpts);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-state-volume-not-aliased/);

  const activationCas = fixture();
  activationCas.volumes.docker_action_activation_cas = { external: true, name: "shared_cas" };
  report = evaluateRuntimeIsolation(activationCas);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-activation-cas-volume-not-aliased/);
});

test("rejects mutable, networked or candidate-mounted brokers", () => {
  const config = fixture();
  const broker = config.services["docker-action-broker"];
  broker.image = "platform/docker-action-broker:latest";
  broker.build = { context: "." };
  broker.network_mode = "bridge";
  broker.ports = ["0.0.0.0:2376:2376"];
  broker.environment.DOCKER_HOST = "tcp://evil:2376";
  broker.volumes.push({ type: "bind", source: ".", target: "/infra", read_only: true });
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-immutable-image/);
  assert.match(report.failures.join("\n"), /docker-broker-host-private/);
  assert.match(report.failures.join("\n"), /docker-broker-no-candidate-code/);
  assert.match(report.failures.join("\n"), /docker-broker-no-remote-host/);
  assert.match(report.failures.join("\n"), /docker-broker-exact-mount-targets/);
});

test("rejects broker and scheduler supplemental groups", () => {
  const config = fixture();
  config.services["docker-action-broker"].group_add = ["998"];
  config.services["backup-scheduler"].group_add = ["998"];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-no-supplemental-groups/);
  assert.match(report.failures.join("\n"), /scheduler-no-supplemental-groups/);
});

test("rejects a mutable, networked or Docker-bearing activation sidecar", () => {
  const config = fixture();
  const sidecar = config.services["docker-action-activation-sidecar"];
  sidecar.image = "provider/activation-sidecar:latest";
  sidecar.build = { context: "." };
  sidecar.network_mode = "bridge";
  sidecar.group_add = ["998"];
  sidecar.volumes.push({
    type: "bind",
    source: "/var/run/docker.sock",
    target: "/var/run/docker.sock",
    read_only: true,
  });
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /activation-sidecar-immutable-provider-image/);
  assert.match(report.failures.join("\n"), /activation-sidecar-host-private/);
  assert.match(report.failures.join("\n"), /activation-sidecar-minimum-authority/);
  assert.match(report.failures.join("\n"), /activation-sidecar-exact-mounts/);
  assert.match(report.failures.join("\n"), /activation-sidecar-no-docker-control/);
  assert.match(report.failures.join("\n"), /raw-socket-single-owner/);
});

test("rejects secret external/name substitution, third-party owners and weak mounts", () => {
  const config = fixture();
  config.secrets.docker_action_backup_prune_plan = {
    external: true,
    name: "shared_admin_token",
  };
  config.services["example-app-web"].secrets = [
    secret("docker_action_backup_prune_plan"),
  ];
  config.services["backup-scheduler"].secrets[0].mode = 0o444;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-secret-source-docker_action_backup_prune_plan/);
  assert.match(report.failures.join("\n"), /docker-broker-secret-owners-docker_action_backup_prune_plan/);
  assert.match(report.failures.join("\n"), /docker-broker-secret-mode-docker_action_backup_prune_plan-backup-scheduler/);
});

test("rejects scheduler Docker API, trust documents and aliased broker socket", () => {
  const config = fixture();
  const scheduler = config.services["backup-scheduler"];
  scheduler.environment.DOCKER_HOST = "unix:///var/run/docker.sock";
  scheduler.volumes.push({
    type: "bind",
    source: "/srv/platform/trust/runtime-intent.json",
    target: "/run/platform/docker-action-trust/runtime-intent.json",
    read_only: true,
  });
  scheduler.volumes[0].source = "attacker_socket";
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /scheduler-uses-local-action-socket/);
  assert.match(report.failures.join("\n"), /scheduler-has-no-docker-api/);
  assert.match(report.failures.join("\n"), /scheduler-no-trust-documents/);
});

test("rejects missing limits, budget overcommit and unsafe broker bootstrap", () => {
  const config = fixture();
  config.services["example-app-web"].mem_limit = 0;
  config.services.postgres.mem_limit = 99 * 1024 * 1024 * 1024;
  config.services["broker-auth-bootstrap"].network_mode = "bridge";
  config.services["broker-auth-bootstrap"].volumes[0].read_only = false;
  config.services.nats.command.push("--user", "global", "--pass", "shared");
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /resource-memory-example-app-web/);
  assert.match(report.failures.join("\n"), /resource-memory-admission/);
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
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "web",
    },
    volumes: [
      { type: "volume", source: "example_data", target: "/app/data", read_only: false },
    ],
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
    environment: {
      DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
      DOCKER_ACTION_RUNTIME_INTENT_ID: INTENT_ID,
      DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: "a".repeat(64),
      DOCKER_ACTION_COMBINED_RENDER_SHA256: "b".repeat(64),
    },
    secrets: [
      secret("docker_action_backup_prune_plan"),
      secret("docker_action_evidence_runtime_snapshot"),
    ],
    volumes: [
      { type: "volume", source: "docker_action_broker_socket", target: "/run/platform/docker-action-broker", read_only: true },
    ],
    networks: { platform_db_admin: null, platform_storage: null, platform_egress: null },
  });
  services["docker-action-activation-sidecar"] = bounded({
    image: `provider.example/platform/activation-sidecar@sha256:${"c".repeat(64)}`,
    read_only: true,
    user: "0:0",
    network_mode: "none",
    entrypoint: ["/opt/provider-activation/materialize-dsse-cas"],
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    volumes: [
      {
        type: "bind",
        source: "/srv/platform/provider-activation/inbox",
        target: "/run/platform/provider-activation/inbox",
        read_only: true,
      },
      {
        type: "volume",
        source: "docker_action_activation_cas",
        target: "/run/platform/docker-action-activation/by-bundle-sha256",
        read_only: false,
      },
    ],
    networks: {},
  });
  services["docker-action-broker"] = bounded({
    image: `platform/docker-action-broker@sha256:${"d".repeat(64)}`,
    read_only: true,
    cpu_shares: 1024,
    network_mode: "none",
    entrypoint: ["node", "/opt/platform-docker-broker/docker-action-broker.mjs"],
    environment: {
      DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
    },
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    secrets: [
      secret("docker_action_runtime_intent_trust_key"),
      secret("docker_action_backup_prune_plan"),
      secret("docker_action_evidence_runtime_snapshot"),
    ],
    volumes: [
      { type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true },
      { type: "volume", source: "docker_action_broker_socket", target: "/run/platform/docker-action-broker", read_only: false },
      { type: "volume", source: "docker_action_broker_state", target: "/var/lib/platform/docker-action-broker", read_only: false },
      { type: "volume", source: "docker_action_activation_cas", target: "/run/platform/docker-action-activation/by-bundle-sha256", read_only: true },
      { type: "bind", source: "/srv/platform/trust/runtime-intent.json", target: "/run/platform/docker-action-trust/runtime-intent.json", read_only: true },
      { type: "bind", source: "/srv/platform/trust/active-receipt.json", target: "/run/platform/docker-action-trust/active-receipt.json", read_only: true },
    ],
    networks: {},
  });
  services.postgres = bounded({ networks: {} });
  const secrets = Object.fromEntries([
    "docker_action_runtime_intent_trust_key",
    "docker_action_backup_prune_plan",
    "docker_action_evidence_runtime_snapshot",
  ].map((name) => [name, { file: `./secrets/${name}.txt` }]));
  return {
    services,
    networks: {
      platform_db_admin: { internal: true },
      platform_storage: { internal: true },
      platform_egress: {},
      example_app_ingress: { internal: true },
    },
    volumes: {
      docker_action_broker_socket: {},
      docker_action_broker_state: {},
      docker_action_activation_cas: {},
      example_data: {},
      redis_auth_config: {},
      nats_auth_config: {},
    },
    secrets,
  };
}

function secret(name) {
  return {
    source: name,
    target: name,
    uid: "0",
    gid: "0",
    mode: 0o400,
  };
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

const INTENT_ID = "intent.release-1";
