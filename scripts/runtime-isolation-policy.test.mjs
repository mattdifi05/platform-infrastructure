import assert from "node:assert/strict";
import test from "node:test";

import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

const CAPABILITY_SECRETS = [
  "docker_action_backup_catalog",
  "docker_action_backup_job_execute",
  "docker_action_backup_prune_plan",
  "docker_action_backup_prune_apply",
  "docker_action_restore_drill_full",
  "docker_action_backup_offsite_sync",
];
const EVIDENCE_SECRET = "docker_action_evidence_runtime_snapshot";
const TRUST_SECRET = "docker_action_runtime_intent_trust_key";

test("accepts the host-private immutable action broker boundary", () => {
  const report = evaluateRuntimeIsolation(fixture());
  for (const id of [
    "docker-broker-immutable-image",
    "docker-broker-host-private",
    "docker-broker-root-identity",
    "docker-broker-trust-aware-readiness",
    "docker-broker-exact-raw-socket",
    "docker-broker-socket-volume-not-aliased",
    "docker-broker-state-volume-not-aliased",
    "docker-broker-exact-capability-secrets",
    "docker-broker-claimed-job-queue-read-only",
    "docker-broker-claimed-job-queue-not-aliased",
    "scheduler-immutable-image",
    "scheduler-minimum-authority",
    "scheduler-host-private",
    "scheduler-exact-mount-targets",
    "scheduler-claimed-job-queue-read-write",
    "scheduler-writable-paths",
    "scheduler-exact-capability-secrets",
    "scheduler-uses-local-action-socket",
    "scheduler-has-no-docker-api",
  ]) {
    assert.equal(report.checks.find((item) => item.id === id)?.status, "passed", id);
  }
  assert.equal(report.status, "passed", report.failures.join("\n"));
  assert.equal(report.summary.rawSocketOwners.join(","), "docker-action-broker");
  assert.equal(report.summary.hostedWorkloads, 1);
});

test("the policy consumes a realistic Compose JSON render, not a source-only fixture shape", () => {
  const renderedJson = JSON.stringify(fixture());
  const parsedRender = JSON.parse(renderedJson);
  const report = evaluateRuntimeIsolation(parsedRender);

  assert.equal(report.status, "passed", report.failures.join("\n"));
  assert.deepEqual(report.summary.rawSocketOwners, ["docker-action-broker"]);

  parsedRender.services["node-exporter"].volumes = [
    {
      type: "bind",
      source: "/",
      target: "/host",
      read_only: true,
      bind: { create_host_path: true },
    },
  ];
  const widened = evaluateRuntimeIsolation(JSON.parse(JSON.stringify(parsedRender)));
  assert.equal(widened.checks.find((item) => item.id === "raw-socket-single-owner")?.status, "failed");
  assert.ok(widened.summary.rawSocketOwners.includes("node-exporter"));
});

test("the rendered policy follows volumes_from authority instead of trusting an empty local mount list", () => {
  const config = fixture();
  config.services.cadvisor.volumes_from = ["docker-action-broker:ro"];
  const report = evaluateRuntimeIsolation(JSON.parse(JSON.stringify(config)));
  assert.equal(report.checks.find((item) => item.id === "raw-socket-single-owner")?.status, "failed");
  assert.ok(report.summary.rawSocketOwners.includes("cadvisor"));
});

for (const serviceName of ["cadvisor", "node-exporter"]) {
  for (const source of ["/", "/run", "/var/run", "/run/docker.sock"]) {
    test(`rejects ${serviceName} raw socket exposing mount ${source}`, () => {
      const config = fixture();
      config.services[serviceName] = bounded({
        read_only: true,
        volumes: [
          { type: "bind", source, target: "/host-runtime", read_only: true },
        ],
        networks: { platform_observability: null },
      });
      const report = evaluateRuntimeIsolation(config);
      assert.equal(
        report.checks.find((item) => item.id === "raw-socket-single-owner")?.status,
        "failed",
        `${source} exposes /var/run/docker.sock even when mounted read-only`,
      );
      assert.ok(report.summary.rawSocketOwners.includes(serviceName), `${source} must make ${serviceName} a raw socket owner`);
    });
  }
}

for (const device of ["/", "/run", "/var/run"]) {
  test(`rejects cAdvisor named-volume alias ${device} to the raw socket`, () => {
    const config = fixture();
    config.services.cadvisor = bounded({
      read_only: true,
      volumes: [
        { type: "volume", source: "cadvisor_runtime", target: "/host-runtime", read_only: true },
      ],
      networks: { platform_observability: null },
    });
    config.volumes.cadvisor_runtime = {
      driver: "local",
      driver_opts: { type: "none", o: "bind,ro", device },
    };
    const report = evaluateRuntimeIsolation(config);
    assert.equal(
      report.checks.find((item) => item.id === "raw-socket-single-owner")?.status,
      "failed",
      "named-volume bind aliases must be resolved before raw socket ownership is decided",
    );
    assert.ok(report.summary.rawSocketOwners.includes("cadvisor"), "aliased cAdvisor mount must be reported as an owner");
  });
}

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

  const jobQueue = fixture();
  jobQueue.volumes.backup_scheduler_jobs = {
    driver: "local",
    driver_opts: { type: "none", o: "bind,ro", device: "/srv/shared/jobs" },
  };
  report = evaluateRuntimeIsolation(jobQueue);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-claimed-job-queue-not-aliased/);
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

test("rejects a broker without the explicit root identity required by its private state", () => {
  const config = fixture();
  delete config.services["docker-action-broker"].user;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "docker-broker-root-identity")?.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-root-identity/);
});

test("rejects broker readiness that proves only the UDS exists", () => {
  const config = fixture();
  config.services["docker-action-broker"].healthcheck = {
    test: ["CMD", "node", "-e", "const fs=require('node:fs');process.exit(fs.statSync('/run/platform/docker-action-broker/broker.sock').isSocket()?0:1)"],
  };
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "docker-broker-trust-aware-readiness")?.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-trust-aware-readiness/);
});

test("rejects readiness commands that merely contain trusted-looking words", () => {
  const config = fixture();
  config.services["docker-action-broker"].healthcheck = {
    test: ["CMD", "echo", "readiness trusted activation receipt"],
  };
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "docker-broker-trust-aware-readiness")?.status, "failed");
});

test("requires the exact readiness module command and mandatory trust argument", () => {
  for (const command of [
    ["CMD", "node", "/opt/platform-docker-broker/docker-action-readiness.mjs"],
    ["CMD", "node", "/opt/platform-docker-broker/docker-action-readiness.mjs", "--require-trusted-activation", "--allow-pending"],
    ["CMD", "node", "/tmp/docker-action-readiness.mjs", "--require-trusted-activation"],
    ["CMD-SHELL", "node /opt/platform-docker-broker/docker-action-readiness.mjs --require-trusted-activation"],
  ]) {
    const config = fixture();
    config.services["docker-action-broker"].healthcheck = { test: command };
    const report = evaluateRuntimeIsolation(config);
    assert.equal(
      report.checks.find((item) => item.id === "docker-broker-trust-aware-readiness")?.status,
      "failed",
      `healthcheck widening was accepted: ${JSON.stringify(command)}`,
    );
  }
});

test("rejects a mutable or generic scheduler image", () => {
  const config = fixture();
  const scheduler = config.services["backup-scheduler"];
  scheduler.image = "platform/ops:local";
  scheduler.build = { context: ".", dockerfile: "docker/ops.Dockerfile" };
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "scheduler-immutable-image")?.status, "failed");
  assert.match(report.failures.join("\n"), /scheduler-immutable-image/);
});

test("rejects scheduler Linux capability widening", () => {
  const config = fixture();
  const scheduler = config.services["backup-scheduler"];
  scheduler.cap_drop = [];
  scheduler.cap_add = ["NET_ADMIN"];
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "scheduler-minimum-authority")?.status, "failed");
  assert.match(report.failures.join("\n"), /scheduler-minimum-authority/);
});

test("rejects scheduler external egress", () => {
  const config = fixture();
  const scheduler = config.services["backup-scheduler"];
  scheduler.network_mode = "bridge";
  scheduler.networks = { platform_egress: null };
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "scheduler-host-private")?.status, "failed");
  assert.match(report.failures.join("\n"), /scheduler-host-private/);
});

test("rejects scheduler repository, backup, report, state or source mounts", () => {
  const config = fixture();
  config.services["backup-scheduler"].volumes.push(
    { type: "bind", source: ".", target: "/infra", read_only: true },
    { type: "bind", source: "./backups", target: "/infra/backups", read_only: false },
    { type: "bind", source: "./reports", target: "/infra/reports", read_only: false },
    { type: "bind", source: "./projects-portal/state", target: "/var/www/project-state", read_only: false },
    { type: "bind", source: "../src", target: "/project", read_only: true },
  );
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "scheduler-exact-mount-targets")?.status, "failed");
  assert.match(report.failures.join("\n"), /scheduler-exact-mount-targets/);
});

test("requires the private claimed-job queue read-write on scheduler and read-only on broker", () => {
  const schedulerReadOnly = fixture();
  schedulerReadOnly.services["backup-scheduler"].volumes
    .find((mount) => mount.source === "backup_scheduler_jobs").read_only = true;
  let report = evaluateRuntimeIsolation(schedulerReadOnly);
  assert.equal(report.checks.find((item) => item.id === "scheduler-claimed-job-queue-read-write")?.status, "failed");

  const brokerWritable = fixture();
  brokerWritable.services["docker-action-broker"].volumes
    .find((mount) => mount.source === "backup_scheduler_jobs").read_only = false;
  report = evaluateRuntimeIsolation(brokerWritable);
  assert.equal(report.checks.find((item) => item.id === "docker-broker-claimed-job-queue-read-only")?.status, "failed");

  const thirdParty = fixture();
  thirdParty.services["example-app-web"].volumes.push({
    type: "volume",
    source: "backup_scheduler_jobs",
    target: "/app/jobs",
    read_only: true,
  });
  report = evaluateRuntimeIsolation(thirdParty);
  assert.equal(report.checks.find((item) => item.id === "docker-broker-claimed-job-queue-not-aliased")?.status, "failed");

  for (const declaration of [
    { external: true, name: "platform_infra_vps_backup_scheduler_jobs" },
    { name: "shared_backup_scheduler_jobs" },
    { name: "${COMPOSE_PROJECT_NAME}_backup_scheduler_jobs" },
  ]) {
    const aliased = fixture();
    aliased.volumes.backup_scheduler_jobs = declaration;
    report = evaluateRuntimeIsolation(aliased);
    assert.equal(
      report.checks.find((item) => item.id === "docker-broker-claimed-job-queue-not-aliased")?.status,
      "failed",
      `claimed queue alias was accepted: ${JSON.stringify(declaration)}`,
    );
  }
});

test("rejects scheduler control files outside its exact hardened tmpfs", () => {
  const config = fixture();
  const scheduler = config.services["backup-scheduler"];
  scheduler.environment.BACKUP_SCHEDULER_CRON_FILE = "/tmp/root.cron";
  scheduler.environment.BACKUP_SCHEDULER_ENV_FILE = "/var/lib/platform/backup-scheduler.env";
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.checks.find((item) => item.id === "scheduler-writable-paths")?.status, "failed");
  assert.match(report.failures.join("\n"), /scheduler-writable-paths/);
});

test("rejects scheduler tmpfs without noexec/nosuid/nodev or with an unbounded size", () => {
  for (const tmpfs of [
    [
      "/tmp:rw,nosuid,nodev,size=64m",
      "/run/platform/backup-scheduler:rw,noexec,nosuid,nodev,size=8m",
    ],
    [
      "/tmp:rw,noexec,nosuid,nodev,size=1024m",
      "/run/platform/backup-scheduler:rw,noexec,nosuid,nodev,size=8m",
    ],
    [
      "/tmp:rw,noexec,nosuid,nodev,size=64m",
      "/run/platform/backup-scheduler:rw,noexec,nosuid,size=8m",
    ],
  ]) {
    const config = fixture();
    config.services["backup-scheduler"].tmpfs = tmpfs;
    const report = evaluateRuntimeIsolation(config);
    assert.equal(
      report.checks.find((item) => item.id === "scheduler-writable-paths")?.status,
      "failed",
      `unsafe tmpfs was accepted: ${JSON.stringify(tmpfs)}`,
    );
  }
});

test("rejects scheduler mount source, target, type and option widening", () => {
  for (const mutate of [
    (scheduler) => { scheduler.volumes.find((mount) => mount.target === "/var/log/platform").source = "shared_logs"; },
    (scheduler) => { scheduler.volumes.find((mount) => mount.target === "/run/platform/docker-action-broker").read_only = false; },
    (scheduler) => { scheduler.volumes.find((mount) => mount.source === "backup_scheduler_jobs").target = "/run/jobs"; },
    (scheduler) => { scheduler.volumes.find((mount) => mount.source === "backup_scheduler_jobs").type = "bind"; },
  ]) {
    const config = fixture();
    mutate(config.services["backup-scheduler"]);
    const report = evaluateRuntimeIsolation(config);
    assert.equal(report.checks.find((item) => item.id === "scheduler-exact-mount-targets")?.status, "failed");
  }
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
  config.services["backup-scheduler"].secrets
    .find((item) => item.source === "docker_action_backup_prune_plan").mode = 0o444;
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "failed");
  assert.match(report.failures.join("\n"), /docker-broker-secret-source-docker_action_backup_prune_plan/);
  assert.match(report.failures.join("\n"), /docker-broker-secret-owners-docker_action_backup_prune_plan/);
  assert.match(report.failures.join("\n"), /docker-broker-secret-mode-docker_action_backup_prune_plan-backup-scheduler/);
});

test("assigns exact root-owned capability and evidence secret ownership", () => {
  const report = evaluateRuntimeIsolation(fixture());
  for (const name of CAPABILITY_SECRETS) {
    assert.equal(
      report.checks.find((item) => item.id === `docker-broker-secret-owners-${name}`)?.status,
      "passed",
      `${name} must belong exactly to backup-scheduler and docker-action-broker`,
    );
    for (const owner of ["backup-scheduler", "docker-action-broker"]) {
      assert.equal(
        report.checks.find((item) => item.id === `docker-broker-secret-mode-${name}-${owner}`)?.status,
        "passed",
        `${name} must be mounted root:root 0400 by ${owner}`,
      );
    }
  }
  assert.equal(
    report.checks.find((item) => item.id === `docker-broker-secret-owners-${EVIDENCE_SECRET}`)?.status,
    "passed",
    "runtime snapshot evidence authority belongs only to docker-action-broker",
  );
});

test("requires all six scheduler capability secrets", () => {
  const missingCapability = fixture();
  missingCapability.services["backup-scheduler"].secrets = missingCapability.services["backup-scheduler"].secrets
    .filter((item) => item.source !== "docker_action_backup_catalog");
  const report = evaluateRuntimeIsolation(missingCapability);
  assert.equal(report.checks.find((item) => item.id === "scheduler-exact-capability-secrets")?.status, "failed");
  assert.equal(
    report.checks.find((item) => item.id === "docker-broker-secret-owners-docker_action_backup_catalog")?.status,
    "failed",
  );
});

test("excludes runtime snapshot evidence authority from the scheduler", () => {
  const evidenceWidening = fixture();
  evidenceWidening.services["backup-scheduler"].secrets.push(secret(EVIDENCE_SECRET));
  const report = evaluateRuntimeIsolation(evidenceWidening);
  assert.equal(report.checks.find((item) => item.id === "scheduler-exact-capability-secrets")?.status, "failed");
  assert.equal(
    report.checks.find((item) => item.id === `docker-broker-secret-owners-${EVIDENCE_SECRET}`)?.status,
    "failed",
    "runtime snapshot is evidence authority and must not be delegated to backup-scheduler",
  );
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
  scheduler.volumes
    .find((mount) => mount.target === "/run/platform/docker-action-broker").source = "attacker_socket";
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
  services["node-exporter"] = bounded({
    read_only: true,
    volumes: [
      { type: "volume", source: "node_exporter_textfiles", target: "/var/lib/node-exporter/textfile", read_only: true },
    ],
    networks: { platform_observability: null },
  });
  services.cadvisor = bounded({
    read_only: true,
    volumes: [],
    networks: { platform_observability: null },
  });
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
    image: `platform/backup-scheduler@sha256:${"e".repeat(64)}`,
    read_only: true,
    cpu_shares: 1024,
    network_mode: "none",
    entrypoint: ["/opt/platform-backup-scheduler/backup-scheduler.sh"],
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    environment: {
      DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
      DOCKER_ACTION_RUNTIME_INTENT_ID: INTENT_ID,
      DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: "a".repeat(64),
      DOCKER_ACTION_COMBINED_RENDER_SHA256: "b".repeat(64),
      BACKUP_SCHEDULER_JOBS_DIR: "/var/www/project-state/backup-jobs",
      BACKUP_SCHEDULER_LOG_DIR: "/var/log/platform",
      BACKUP_SCHEDULER_CRON_FILE: "/run/platform/backup-scheduler/crontabs/root",
      BACKUP_SCHEDULER_ENV_FILE: "/run/platform/backup-scheduler/backup-scheduler.env",
    },
    secrets: CAPABILITY_SECRETS.map(secret),
    volumes: [
      { type: "volume", source: "backup_scheduler_jobs", target: "/var/www/project-state/backup-jobs", read_only: false },
      { type: "volume", source: "backup_scheduler_logs", target: "/var/log/platform", read_only: false },
      { type: "volume", source: "docker_action_broker_socket", target: "/run/platform/docker-action-broker", read_only: true },
    ],
    tmpfs: [
      "/tmp:rw,noexec,nosuid,nodev,size=64m",
      "/run/platform/backup-scheduler:rw,noexec,nosuid,nodev,size=8m",
    ],
    networks: {},
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
    user: "0:0",
    cpu_shares: 1024,
    network_mode: "none",
    entrypoint: ["node", "/opt/platform-docker-broker/docker-action-broker.mjs"],
    environment: {
      DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
    },
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    secrets: [
      secret(TRUST_SECRET),
      ...CAPABILITY_SECRETS.map(secret),
      secret(EVIDENCE_SECRET),
    ],
    volumes: [
      { type: "bind", source: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: true },
      { type: "volume", source: "docker_action_broker_socket", target: "/run/platform/docker-action-broker", read_only: false },
      { type: "volume", source: "docker_action_broker_state", target: "/var/lib/platform/docker-action-broker", read_only: false },
      { type: "volume", source: "backup_scheduler_jobs", target: "/run/platform/backup-jobs", read_only: true },
      { type: "volume", source: "docker_action_activation_cas", target: "/run/platform/docker-action-activation/by-bundle-sha256", read_only: true },
      { type: "bind", source: "/srv/platform/trust/runtime-intent.json", target: "/run/platform/docker-action-trust/runtime-intent.json", read_only: true },
      { type: "bind", source: "/srv/platform/trust/active-receipt.json", target: "/run/platform/docker-action-trust/active-receipt.json", read_only: true },
    ],
    healthcheck: {
      test: [
        "CMD",
        "node",
        "/opt/platform-docker-broker/docker-action-readiness.mjs",
        "--require-trusted-activation",
      ],
    },
    networks: {},
  });
  services.postgres = bounded({ networks: {} });
  const secrets = Object.fromEntries([
    TRUST_SECRET,
    ...CAPABILITY_SECRETS,
    EVIDENCE_SECRET,
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
      backup_scheduler_jobs: { name: "platform_infra_vps_backup_scheduler_jobs" },
      backup_scheduler_logs: {},
      node_exporter_textfiles: {},
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
