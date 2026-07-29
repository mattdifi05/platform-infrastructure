import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
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
const CANDIDATE_PROJECT_PRIVATE_VOLUMES = [
  "backup_scheduler_logs",
  "enterprise_alertmanager_data",
  "enterprise_grafana_data",
  "enterprise_keycloak_data",
  "enterprise_local_registry_data",
  "enterprise_loki_data",
  "enterprise_mariadb_data",
  "enterprise_minio_data",
  "enterprise_nats_data",
  "enterprise_postgres_data",
  "enterprise_prometheus_data",
  "enterprise_redis_data",
  "nats_auth_config",
  "redis_auth_config",
];
const pinnedComposeSha256 = "32691ba1196d819fa68cbdc0aad9a5569e730a35ae40c6fdd8458110ecd69488";
const composeAvailability = findComposeCli();
const cachedCanonicalRenders = new Map();

test("canonical Compose policy rendering is available without a Docker Engine", () => {
  assert.equal(
    composeAvailability.available,
    true,
    `NOT_RUN: canonical docker compose config renderer unavailable: ${composeAvailability.reason}`,
  );
});

test("the test-only candidate overlay resolves to the intended authority boundary", (t) => {
  const config = canonicalComposeRenderOrSkip(t, "candidate");
  if (!config) return;
  assertRenderedPolicySurface(config);

  assert.deepEqual(renderedRawSocketOwners(config), ["docker-action-broker"]);
  assert.equal(config.volumes.backup_scheduler_jobs?.name, "platform_infra_vps_backup_scheduler_jobs");
  assert.equal(config.volumes.backup_scheduler_jobs?.external, undefined);
  assert.equal(config.volumes.backup_scheduler_jobs?.driver_opts, undefined);

  const broker = config.services["docker-action-broker"];
  const scheduler = config.services["backup-scheduler"];
  assert.equal(broker.user, "0:0");
  assert.deepEqual(broker.cap_drop, ["ALL"]);
  assert.deepEqual(broker.cap_add ?? [], []);
  assert.equal(broker.network_mode, "none");
  assert.deepEqual(Object.keys(broker.networks ?? {}), []);
  assert.deepEqual(broker.healthcheck.test, [
    "CMD",
    "node",
    "/opt/platform-docker-broker/docker-action-readiness.mjs",
    "--require-trusted-activation",
  ]);
  assert.deepEqual(
    broker.volumes.find((mount) => mount.source === "backup_scheduler_jobs"),
    {
      type: "volume",
      source: "backup_scheduler_jobs",
      target: "/run/platform/backup-jobs",
      read_only: true,
      volume: {},
    },
  );

  assert.equal(scheduler.user, "0:0");
  assert.deepEqual(scheduler.cap_drop, ["ALL"]);
  assert.deepEqual(scheduler.cap_add ?? [], []);
  assert.equal(scheduler.network_mode, "none");
  assert.deepEqual(Object.keys(scheduler.networks ?? {}), []);
  assert.equal(scheduler.build, undefined);
  assert.match(scheduler.image, /@sha256:[a-f0-9]{64}$/);
  assert.deepEqual(
    scheduler.volumes.find((mount) => mount.source === "backup_scheduler_jobs"),
    {
      type: "volume",
      source: "backup_scheduler_jobs",
      target: "/var/www/project-state/backup-jobs",
      volume: {},
    },
  );

  const brokerSecrets = secretNamesFromRender(broker);
  const schedulerSecrets = secretNamesFromRender(scheduler);
  assert.deepEqual(
    brokerSecrets,
    [...CAPABILITY_SECRETS, EVIDENCE_SECRET, TRUST_SECRET].sort(),
  );
  assert.deepEqual(schedulerSecrets, [...CAPABILITY_SECRETS].sort());
  assert.ok(!schedulerSecrets.includes(EVIDENCE_SECRET));
  assert.ok(!schedulerSecrets.includes(TRUST_SECRET));
});

test("the unmodified canonical source render itself satisfies the policy (real-current gate)", (t) => {
  const config = canonicalComposeRenderOrSkip(t, "current");
  if (!config) return;
  assertRenderedPolicySurface(config);
  const report = evaluateRuntimeIsolation(config);
  assert.equal(report.status, "passed", report.failures.join("\n"));
});

test("accepts the complete canonical Compose JSON render", (t) => {
  const config = canonicalComposeRenderOrSkip(t, "candidate");
  if (!config) return;
  assertRenderedPolicySurface(config);
  const report = evaluateRuntimeIsolation(config);

  assert.equal(report.status, "passed", report.failures.join("\n"));
  assert.deepEqual(report.summary.rawSocketOwners, ["docker-action-broker"]);
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
    assert.equal(checkStatus(report, id), "passed", id);
  }
});

test("the policy consumes user, capabilities, networks, secrets, tmpfs, volumes, volumes_from and healthcheck from the real render", (t) => {
  const admitted = admittedCandidatePolicyOrTodo(t);
  if (!admitted) return;
  const { config, report } = admitted;
  const broker = config.services["docker-action-broker"];
  const scheduler = config.services["backup-scheduler"];

  assert.equal(typeof broker.user, "string");
  assert.ok(Array.isArray(broker.cap_drop));
  assert.ok(broker.cap_add === undefined || Array.isArray(broker.cap_add));
  assert.ok(broker.network_mode === "none" || broker.networks !== undefined);
  assert.ok(Array.isArray(broker.secrets));
  assert.ok(Array.isArray(broker.tmpfs));
  assert.ok(Array.isArray(broker.volumes));
  assert.ok(broker.volumes_from === undefined || Array.isArray(broker.volumes_from));
  assert.ok(Array.isArray(broker.healthcheck?.test));

  assert.equal(typeof scheduler.user, "string");
  assert.ok(Array.isArray(scheduler.cap_drop));
  assert.ok(scheduler.cap_add === undefined || Array.isArray(scheduler.cap_add));
  assert.ok(scheduler.network_mode === "none" || scheduler.networks !== undefined);
  assert.ok(Array.isArray(scheduler.secrets));
  assert.ok(Array.isArray(scheduler.tmpfs));
  assert.ok(Array.isArray(scheduler.volumes));
  assert.ok(scheduler.volumes_from === undefined || Array.isArray(scheduler.volumes_from));
  assert.ok(Array.isArray(scheduler.healthcheck?.test));

  assert.equal(report.status, "passed", report.failures.join("\n"));
});

test("follows rendered volumes_from authority instead of trusting an empty local mount list", (t) => {
  assertMutationRejected(t, {
    checks: ["raw-socket-single-owner"],
    mutate(config) {
      config.services.cadvisor.volumes = [];
      config.services.cadvisor.volumes_from = ["docker-action-broker:ro"];
    },
  });
});

test("rejects an unprovable external container volumes_from authority", (t) => {
  assertMutationRejected(t, {
    checks: ["raw-socket-single-owner"],
    mutate(config) {
      config.services.cadvisor.volumes = [];
      config.services.cadvisor.volumes_from = ["container:untrusted-runtime:ro"];
    },
  });
});

test("accepts a project-private canonical local volume as a raw-authority positive control", (t) => {
  const baseline = rawAuthorityBaselineOrTodo(t);
  if (!baseline) return;
  baseline.services.cadvisor.volumes = [{
    type: "volume",
    source: "metrics_runtime",
    target: "/mnt/runtime",
    read_only: true,
    volume: {},
  }];
  baseline.volumes.metrics_runtime = {
    name: "platform_infra_vps_metrics_runtime",
    driver: "local",
  };

  assert.equal(renderedServiceOwnsRawSocket(baseline, "cadvisor"), false);
  assert.equal(
    checkStatus(evaluateRuntimeIsolation(baseline), "raw-socket-single-owner"),
    "passed",
    "a proven project-private canonical local volume must not be misclassified as raw Docker authority",
  );
});

test("accepts a canonical rendered named volume without classifying every named volume", (t) => {
  const baseline = rawAuthorityBaselineOrTodo(t);
  if (!baseline) return;
  baseline.services.cadvisor.volumes = [{
    type: "volume",
    source: "metrics_cache",
    target: "/mnt/runtime",
    read_only: true,
    volume: {},
  }];
  baseline.volumes.metrics_cache = {
    name: "platform_infra_vps_metrics_cache",
  };

  assert.equal(renderedServiceOwnsRawSocket(baseline, "cadvisor"), false);
  assert.equal(
    checkStatus(evaluateRuntimeIsolation(baseline), "raw-socket-single-owner"),
    "passed",
    "a canonical default-local rendered volume must remain distinct from unprovable volume authority",
  );
});

test("accepts internal volumes_from from a socketless service as a positive control", (t) => {
  const baseline = rawAuthorityBaselineOrTodo(t);
  if (!baseline) return;
  assert.equal(renderedServiceOwnsRawSocket(baseline, "node-exporter"), false);
  baseline.services.cadvisor.volumes = [];
  baseline.services.cadvisor.volumes_from = ["node-exporter:ro"];

  assert.equal(renderedServiceOwnsRawSocket(baseline, "cadvisor"), false);
  assert.equal(
    checkStatus(evaluateRuntimeIsolation(baseline), "raw-socket-single-owner"),
    "passed",
    "internal volumes_from must remain safe when its exact source service is socketless",
  );
});

for (const serviceName of ["cadvisor", "node-exporter"]) {
  for (const source of ["/", "/var", "/run", "/var/run", "/run/docker.sock"]) {
    test(`rejects ${serviceName} raw socket exposing mount ${source}`, (t) => {
      assertMutationRejected(t, {
        checks: ["raw-socket-single-owner"],
        mutate(config) {
          config.services[serviceName].volumes = [{
            type: "bind",
            source,
            target: "/host-runtime",
            read_only: true,
            bind: { create_host_path: true },
          }];
        },
      });
    });
  }
}

for (const device of ["/", "/var", "/run", "/var/run"]) {
  test(`rejects cAdvisor named-volume alias ${device} to the raw socket`, (t) => {
    assertMutationRejected(t, {
      checks: ["raw-socket-single-owner"],
      mutate(config) {
        config.services.cadvisor.volumes = [{
          type: "volume",
          source: "cadvisor_runtime",
          target: "/mnt/runtime",
          read_only: true,
        }];
        config.volumes.cadvisor_runtime = {
          name: "platform_infra_vps_cadvisor_runtime",
          driver: "local",
          driver_opts: { type: "none", o: "bind,ro", device },
        };
      },
    });
  });
}

for (const [label, volumeName, declaration] of [
  [
    "external volume",
    "external_runtime",
    { external: true, name: "platform_infra_vps_external_runtime" },
  ],
  [
    "non-canonical custom alias",
    "aliased_runtime",
    { name: "shared_runtime" },
  ],
  [
    "unprovable volume driver",
    "driver_runtime",
    { name: "platform_infra_vps_driver_runtime", driver: "untrusted.remote" },
  ],
]) {
  test(`rejects cAdvisor ${label} independently of its mount target`, (t) => {
    assertMutationRejected(t, {
      checks: ["raw-socket-single-owner"],
      mutate(config) {
        config.services.cadvisor.volumes = [{
          type: "volume",
          source: volumeName,
          target: "/mnt/runtime",
          read_only: true,
          volume: {},
        }];
        config.volumes[volumeName] = structuredClone(declaration);
      },
    });
  });
}

test("rejects an arbitrary service external volume at a neutral target", (t) => {
  assertMutationRejected(t, {
    checks: ["raw-socket-single-owner"],
    mutate(config) {
      config.services.postgres.volumes = [{
        type: "volume",
        source: "neutral_runtime",
        target: "/mnt/runtime",
        read_only: true,
        volume: {},
      }];
      config.volumes.neutral_runtime = {
        external: true,
        name: "platform_infra_vps_neutral_runtime",
      };
    },
  });
});

test("rejects an arbitrary service volume with no provable definition", (t) => {
  assertMutationRejected(t, {
    checks: ["raw-socket-single-owner"],
    mutate(config) {
      config.services.postgres.volumes = [{
        type: "volume",
        source: "undefined_runtime",
        target: "/mnt/runtime",
        read_only: true,
        volume: {},
      }];
      delete config.volumes.undefined_runtime;
    },
  });
});

test("rejects workload raw socket, bind and broad host mounts", (t) => {
  assertMutationRejected(t, {
    checks: [
      "raw-socket-single-owner",
      "workload-no-bind-mounts-example-app-web",
      "workload-deny-mount-mnt-host-example-app-web",
    ],
    mutate(config) {
      config.services["example-app-web"] = hostileWorkload({
        volumes: [
          {
            type: "bind",
            source: "/var/run/docker.sock",
            target: "/var/run/docker.sock",
            read_only: true,
          },
          {
            type: "bind",
            source: "/srv/platform",
            target: "/mnt/host/platform",
            read_only: true,
          },
        ],
      });
    },
  });
});

test("rejects root workload identity, added capabilities and supplemental Docker group", (t) => {
  assertMutationRejected(t, {
    checks: [
      "workload-non-root-example-app-web",
      "workload-drop-all-capabilities-example-app-web",
      "workload-no-supplemental-groups-example-app-web",
    ],
    mutate(config) {
      config.services["example-app-web"] = hostileWorkload({
        user: "0:0",
        cap_add: ["NET_ADMIN"],
        group_add: ["998"],
      });
    },
  });
});

test("rejects a workload named-volume alias to a host path", (t) => {
  assertMutationRejected(t, {
    checks: ["workload-volume-no-host-alias-example-data-example-app-web"],
    mutate(config) {
      config.services["example-app-web"] = hostileWorkload({
        volumes: [{
          type: "volume",
          source: "example_data",
          target: "/app/data",
          read_only: false,
        }],
      });
      config.volumes.example_data = {
        name: "platform_infra_vps_example_data",
        driver: "local",
        driver_opts: { type: "none", o: "bind", device: "/var/run" },
      };
    },
  });
});

for (const [label, volumeName, declaration, check] of [
  [
    "broker socket external substitution",
    "docker_action_broker_socket",
    { external: true, name: "attacker_socket" },
    "docker-broker-socket-volume-not-aliased",
  ],
  [
    "broker state host alias",
    "docker_action_broker_state",
    { name: "platform_infra_vps_docker_action_broker_state", driver: "local", driver_opts: { type: "none", o: "bind", device: "/var/run" } },
    "docker-broker-state-volume-not-aliased",
  ],
  [
    "activation CAS external substitution",
    "docker_action_activation_cas",
    { external: true, name: "shared_cas" },
    "docker-broker-activation-cas-volume-not-aliased",
  ],
  [
    "claimed job queue host alias",
    "backup_scheduler_jobs",
    { name: "platform_infra_vps_backup_scheduler_jobs", driver: "local", driver_opts: { type: "none", o: "bind,ro", device: "/srv/shared/jobs" } },
    "docker-broker-claimed-job-queue-not-aliased",
  ],
]) {
  test(`rejects ${label}`, (t) => {
    assertMutationRejected(t, {
      checks: [check],
      mutate(config) {
        config.volumes[volumeName] = structuredClone(declaration);
      },
    });
  });
}

test("rejects mutable, networked, remotely controlled or candidate-mounted brokers", (t) => {
  assertMutationRejected(t, {
    checks: [
      "docker-broker-immutable-image",
      "docker-broker-host-private",
      "docker-broker-no-candidate-code",
      "docker-broker-no-remote-host",
      "docker-broker-exact-mount-targets",
    ],
    mutate(config) {
      const broker = config.services["docker-action-broker"];
      broker.image = "platform/docker-action-broker:latest";
      broker.build = { context: "." };
      broker.network_mode = "bridge";
      broker.networks = { platform_egress: null };
      broker.ports = [{ target: 2376, published: "2376", protocol: "tcp", mode: "ingress" }];
      broker.environment.DOCKER_HOST = "tcp://evil.invalid:2376";
      broker.volumes.push({ type: "bind", source: root, target: "/infra", read_only: true });
    },
  });
});

test("rejects broker and scheduler supplemental groups", (t) => {
  assertMutationRejected(t, {
    checks: ["docker-broker-no-supplemental-groups", "scheduler-no-supplemental-groups"],
    mutate(config) {
      config.services["docker-action-broker"].group_add = ["998"];
      config.services["backup-scheduler"].group_add = ["998"];
    },
  });
});

test("rejects a broker without the explicit root identity required by its private state", (t) => {
  assertMutationRejected(t, {
    checks: ["docker-broker-root-identity"],
    mutate(config) {
      delete config.services["docker-action-broker"].user;
    },
  });
});

for (const command of [
  ["CMD", "node", "-e", "require('node:fs').statSync('/run/platform/docker-action-broker/broker.sock')"],
  ["CMD", "echo", "readiness trusted activation receipt"],
  ["CMD", "node", "/opt/platform-docker-broker/docker-action-readiness.mjs"],
  ["CMD", "node", "/opt/platform-docker-broker/docker-action-readiness.mjs", "--require-trusted-activation", "--allow-pending"],
  ["CMD", "node", "/tmp/docker-action-readiness.mjs", "--require-trusted-activation"],
  ["CMD-SHELL", "node /opt/platform-docker-broker/docker-action-readiness.mjs --require-trusted-activation"],
]) {
  test(`rejects widened broker readiness ${JSON.stringify(command)}`, (t) => {
    assertMutationRejected(t, {
      checks: ["docker-broker-trust-aware-readiness"],
      mutate(config) {
        config.services["docker-action-broker"].healthcheck.test = command;
      },
    });
  });
}

test("rejects a mutable or generic scheduler image", (t) => {
  assertMutationRejected(t, {
    checks: ["scheduler-immutable-image"],
    mutate(config) {
      const scheduler = config.services["backup-scheduler"];
      scheduler.image = "platform/ops:local";
      scheduler.build = { context: ".", dockerfile: "docker/ops.Dockerfile" };
    },
  });
});

test("rejects scheduler Linux capability widening", (t) => {
  assertMutationRejected(t, {
    checks: ["scheduler-minimum-authority"],
    mutate(config) {
      config.services["backup-scheduler"].cap_drop = [];
      config.services["backup-scheduler"].cap_add = ["NET_ADMIN"];
    },
  });
});

test("rejects scheduler external egress", (t) => {
  assertMutationRejected(t, {
    checks: ["scheduler-host-private"],
    mutate(config) {
      config.services["backup-scheduler"].network_mode = "bridge";
      config.services["backup-scheduler"].networks = { platform_egress: null };
    },
  });
});

test("rejects scheduler repository, backup, report, state or source mounts", (t) => {
  assertMutationRejected(t, {
    checks: ["scheduler-exact-mount-targets"],
    mutate(config) {
      config.services["backup-scheduler"].volumes.push(
        { type: "bind", source: root, target: "/infra", read_only: true },
        { type: "bind", source: path.join(root, "backups"), target: "/infra/backups", read_only: false },
        { type: "bind", source: path.join(root, "reports"), target: "/infra/reports", read_only: false },
        { type: "bind", source: path.join(root, "projects-portal/state"), target: "/var/www/project-state", read_only: false },
        { type: "bind", source: path.resolve(root, "../src"), target: "/project", read_only: true },
      );
    },
  });
});

for (const [label, check, mutate] of [
  [
    "scheduler queue read-only",
    "scheduler-claimed-job-queue-read-write",
    (config) => {
      config.services["backup-scheduler"].volumes
        .find((mount) => mount.source === "backup_scheduler_jobs").read_only = true;
    },
  ],
  [
    "broker queue writable",
    "docker-broker-claimed-job-queue-read-only",
    (config) => {
      config.services["docker-action-broker"].volumes
        .find((mount) => mount.source === "backup_scheduler_jobs").read_only = false;
    },
  ],
  [
    "third-party queue owner",
    "docker-broker-claimed-job-queue-not-aliased",
    (config) => {
      config.services["example-app-web"] = hostileWorkload({
        volumes: [{
          type: "volume",
          source: "backup_scheduler_jobs",
          target: "/app/jobs",
          read_only: true,
        }],
      });
    },
  ],
]) {
  test(`rejects ${label}`, (t) => {
    assertMutationRejected(t, { checks: [check], mutate });
  });
}

for (const declaration of [
  { external: true, name: "platform_infra_vps_backup_scheduler_jobs" },
  { name: "shared_backup_scheduler_jobs" },
  { name: "platform_infra_vps_docker_action_broker_state" },
]) {
  test(`rejects claimed queue alias ${JSON.stringify(declaration)}`, (t) => {
    assertMutationRejected(t, {
      checks: ["docker-broker-claimed-job-queue-not-aliased"],
      mutate(config) {
        config.volumes.backup_scheduler_jobs = structuredClone(declaration);
      },
    });
  });
}

test("rejects scheduler control files outside its exact hardened tmpfs", (t) => {
  assertMutationRejected(t, {
    checks: ["scheduler-writable-paths"],
    mutate(config) {
      const scheduler = config.services["backup-scheduler"];
      scheduler.environment.BACKUP_SCHEDULER_CRON_FILE = "/tmp/root.cron";
      scheduler.environment.BACKUP_SCHEDULER_ENV_FILE = "/var/lib/platform/backup-scheduler.env";
    },
  });
});

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
  test(`rejects unsafe scheduler tmpfs ${JSON.stringify(tmpfs)}`, (t) => {
    assertMutationRejected(t, {
      checks: ["scheduler-writable-paths"],
      mutate(config) {
        config.services["backup-scheduler"].tmpfs = structuredClone(tmpfs);
      },
    });
  });
}

for (const [label, mutate] of [
  [
    "log source",
    (scheduler) => {
      scheduler.volumes.find((mount) => mount.target === "/var/log/platform").source = "shared_logs";
    },
  ],
  [
    "broker UDS write access",
    (scheduler) => {
      scheduler.volumes.find((mount) => mount.target === "/run/platform/docker-action-broker").read_only = false;
    },
  ],
  [
    "queue target",
    (scheduler) => {
      scheduler.volumes.find((mount) => mount.source === "backup_scheduler_jobs").target = "/run/jobs";
    },
  ],
  [
    "queue type",
    (scheduler) => {
      scheduler.volumes.find((mount) => mount.source === "backup_scheduler_jobs").type = "bind";
    },
  ],
]) {
  test(`rejects scheduler mount widening: ${label}`, (t) => {
    assertMutationRejected(t, {
      checks: ["scheduler-exact-mount-targets"],
      mutate(config) {
        mutate(config.services["backup-scheduler"]);
      },
    });
  });
}

test("rejects a mutable, networked or Docker-bearing activation sidecar", (t) => {
  assertMutationRejected(t, {
    checks: [
      "activation-sidecar-immutable-provider-image",
      "activation-sidecar-host-private",
      "activation-sidecar-minimum-authority",
      "activation-sidecar-exact-mounts",
      "activation-sidecar-no-docker-control",
      "raw-socket-single-owner",
    ],
    mutate(config) {
      const sidecar = config.services["docker-action-activation-sidecar"];
      sidecar.image = "provider/activation-sidecar:latest";
      sidecar.build = { context: "." };
      sidecar.network_mode = "bridge";
      sidecar.networks = { platform_egress: null };
      sidecar.group_add = ["998"];
      sidecar.volumes.push({
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        read_only: true,
      });
    },
  });
});

test("rejects secret external/name substitution, third-party owners and weak mounts", (t) => {
  assertMutationRejected(t, {
    checks: [
      "docker-broker-secret-source-docker_action_backup_prune_plan",
      "docker-broker-secret-owners-docker_action_backup_prune_plan",
      "docker-broker-secret-mode-docker_action_backup_prune_plan-backup-scheduler",
    ],
    mutate(config) {
      config.secrets.docker_action_backup_prune_plan = {
        external: true,
        name: "shared_admin_token",
      };
      config.services["example-app-web"] = hostileWorkload({
        secrets: [secret("docker_action_backup_prune_plan")],
      });
      config.services["backup-scheduler"].secrets
        .find((item) => item.source === "docker_action_backup_prune_plan").mode = 0o444;
    },
  });
});

test("assigns exact root-owned capability, evidence and trust secret ownership", (t) => {
  const admitted = admittedCandidatePolicyOrTodo(t);
  if (!admitted) return;
  const { report } = admitted;

  for (const name of CAPABILITY_SECRETS) {
    assert.equal(checkStatus(report, `docker-broker-secret-owners-${name}`), "passed", name);
    for (const owner of ["backup-scheduler", "docker-action-broker"]) {
      assert.equal(checkStatus(report, `docker-broker-secret-mode-${name}-${owner}`), "passed", `${name}:${owner}`);
    }
  }
  assert.equal(checkStatus(report, `docker-broker-secret-owners-${EVIDENCE_SECRET}`), "passed");
  assert.equal(checkStatus(report, `docker-broker-secret-owners-${TRUST_SECRET}`), "passed");
});

test("requires all six scheduler capability secrets", (t) => {
  assertMutationRejected(t, {
    checks: [
      "scheduler-exact-capability-secrets",
      "docker-broker-secret-owners-docker_action_backup_catalog",
    ],
    mutate(config) {
      config.services["backup-scheduler"].secrets = config.services["backup-scheduler"].secrets
        .filter((item) => item.source !== "docker_action_backup_catalog");
    },
  });
});

test("excludes runtime snapshot evidence authority from the scheduler", (t) => {
  assertMutationRejected(t, {
    checks: [
      "scheduler-exact-capability-secrets",
      `docker-broker-secret-owners-${EVIDENCE_SECRET}`,
    ],
    mutate(config) {
      config.services["backup-scheduler"].secrets.push(secret(EVIDENCE_SECRET));
    },
  });
});

test("rejects scheduler Docker API, trust documents and aliased broker socket", (t) => {
  assertMutationRejected(t, {
    checks: [
      "scheduler-uses-local-action-socket",
      "scheduler-has-no-docker-api",
      "scheduler-no-trust-documents",
    ],
    mutate(config) {
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
    },
  });
});

test("rejects missing limits, budget overcommit and unsafe broker bootstrap", (t) => {
  assertMutationRejected(t, {
    checks: [
      "resource-memory-control-center",
      "resource-memory-admission",
      "broker-bootstrap-no-network",
      "broker-bootstrap-lock-read-only",
      "nats-no-global-credential-flags",
    ],
    mutate(config) {
      config.services["control-center"].mem_limit = 0;
      config.services.postgres.mem_limit = 99 * 1024 * 1024 * 1024;
      config.services["broker-auth-bootstrap"].network_mode = "bridge";
      config.services["broker-auth-bootstrap"].networks = { platform_egress: null };
      config.services["broker-auth-bootstrap"].volumes
        .find((mount) => mount.target === "/run/platform/hosted-workloads.lock.json").read_only = false;
      config.services.nats.command = [
        ...(config.services.nats.command ?? []),
        "--user",
        "global",
        "--pass",
        "shared",
      ];
    },
  });
});

test.todo("Package A/B runtime metrics continuity after removing cAdvisor/node-exporter host parents (NOT_RUN)");

function assertMutationRejected(t, { checks, mutate }) {
  const baseline = canonicalComposeRenderOrSkip(t, "candidate");
  if (!baseline) return;

  const baselineReport = evaluateRuntimeIsolation(baseline);
  if (checks.includes("raw-socket-single-owner")) {
    assert.deepEqual(
      renderedRawSocketOwners(baseline),
      ["docker-action-broker"],
      "raw-authority mutation baseline must independently prove one exact owner",
    );
  }
  const blockedTargets = checks
    .map((id) => ({ id, status: checkStatus(baselineReport, id) ?? "missing" }))
    .filter(({ status }) => status !== "passed");
  if (blockedTargets.length > 0) {
    t.todo(
      `blocked by candidate policy consumer RED: ${blockedTargets
        .map(({ id, status }) => `${id}=${status}`)
        .join(", ")}`,
    );
    return;
  }

  const candidate = structuredClone(baseline);
  mutate(candidate);
  if (checks.includes("raw-socket-single-owner")) {
    assert.notDeepEqual(
      renderedRawSocketOwners(candidate),
      ["docker-action-broker"],
      "raw-authority mutation must independently widen or make authority unprovable",
    );
  }
  const report = evaluateRuntimeIsolation(candidate);
  for (const id of checks) {
    assert.equal(
      checkStatus(report, id),
      "failed",
      `mutation did not reject at its intended consumer check: ${id}\n${report.failures.join("\n")}`,
    );
  }
}

function rawAuthorityBaselineOrTodo(t) {
  const baseline = canonicalComposeRenderOrSkip(t, "candidate");
  if (!baseline) return null;
  const report = evaluateRuntimeIsolation(baseline);
  const status = checkStatus(report, "raw-socket-single-owner");
  if (status !== "passed") {
    t.todo(`blocked by candidate policy consumer RED: raw-socket-single-owner=${status ?? "missing"}`);
    return null;
  }
  assert.deepEqual(renderedRawSocketOwners(baseline), ["docker-action-broker"]);
  return baseline;
}

function admittedCandidatePolicyOrTodo(t) {
  const config = canonicalComposeRenderOrSkip(t, "candidate");
  if (!config) return null;
  const report = evaluateRuntimeIsolation(config);
  if (report.status !== "passed") {
    const failedIds = report.checks
      .filter((item) => item.status === "failed")
      .map((item) => item.id);
    t.todo(`blocked by candidate policy consumer RED: ${failedIds.join(", ") || "status=failed"}`);
    return null;
  }
  return { config, report };
}

function checkStatus(report, id) {
  return report.checks.find((item) => item.id === id)?.status;
}

function canonicalComposeRenderOrSkip(t, variant = "candidate") {
  if (!composeAvailability.available) {
    t.skip(`NOT_RUN: canonical docker compose config renderer unavailable: ${composeAvailability.reason}`);
    return null;
  }
  return canonicalComposeRender(variant);
}

function canonicalComposeRender(variant) {
  assert.ok(["current", "candidate"].includes(variant), `unsupported Compose render variant ${variant}`);
  if (cachedCanonicalRenders.has(variant)) return structuredClone(cachedCanonicalRenders.get(variant));

  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "platform-policy-render-"));
  const envFile = path.join(temporaryRoot, "compose.env");
  const dockerConfig = path.join(temporaryRoot, "docker-config");
  const candidateOverlay = variant === "candidate"
    ? path.join(temporaryRoot, "candidate-runtime-isolation.yaml")
    : "";
  fs.mkdirSync(dockerConfig, { mode: 0o700 });
  fs.writeFileSync(envFile, deterministicComposeEnvironment(), { mode: 0o600 });
  if (candidateOverlay) {
    fs.writeFileSync(candidateOverlay, candidateRuntimeIsolationOverlay(), { mode: 0o600 });
  }
  const executionPath = prepareComposeExecutionPath(temporaryRoot, candidateOverlay);

  try {
    const result = spawnSync(
      "bash",
      [path.join(root, "scripts", "compose-vps.sh"), "config", "--format", "json"],
      {
        cwd: root,
        encoding: "utf8",
        env: {
          COMPOSE_ANSI: "never",
          COMPOSE_ENV_FILE: envFile,
          COMPOSE_PROJECT_NAME: "platform_infra_vps",
          DOCKER_CONFIG: dockerConfig,
          DOCKER_HOST: `unix://${path.join(temporaryRoot, "engine-must-not-exist.sock")}`,
          HOME: temporaryRoot,
          HOSTED_WORKLOAD_ALLOW_RESOLVED: "0",
          HOSTED_WORKLOAD_LOCK: "",
          LANG: "C",
          LC_ALL: "C",
          PATH: executionPath,
        },
        timeout: 30_000,
      },
    );
    const output = `${result.stdout || ""}\n${result.stderr || ""}`;
    assert.equal(
      result.status,
      0,
      `offline canonical docker compose config render failed (no Engine is permitted):\n${output}`,
    );
    assert.equal(result.signal, null, `offline Compose render terminated by ${result.signal}`);
    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch (error) {
      assert.fail(`docker compose config --format json returned invalid JSON: ${error.message}`);
    }
    assertRenderedPolicySurface(parsed);
    cachedCanonicalRenders.set(variant, parsed);
    return structuredClone(cachedCanonicalRenders.get(variant));
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function findComposeCli() {
  const searchPath = [
    process.env.PATH,
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications/Docker.app/Contents/Resources/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
  ].filter(Boolean).join(path.delimiter);

  const composeOverride = process.env.PLATFORM_TEST_DOCKER_COMPOSE_BIN;
  const bundledCompose = composeOverride
    || path.resolve(root, "../compose-runtime/docker-compose");
  if (fs.existsSync(bundledCompose) && fs.statSync(bundledCompose).isFile()) {
    const expectedSha256 = composeOverride
      ? String(process.env.PLATFORM_TEST_DOCKER_COMPOSE_SHA256 || "")
      : pinnedComposeSha256;
    if (!/^[a-f0-9]{64}$/.test(expectedSha256)) {
      return {
        available: false,
        path: searchPath,
        reason: "PLATFORM_TEST_DOCKER_COMPOSE_BIN requires PLATFORM_TEST_DOCKER_COMPOSE_SHA256",
      };
    }
    const sha256 = createHash("sha256").update(fs.readFileSync(bundledCompose)).digest("hex");
    if (sha256 !== expectedSha256) {
      return {
        available: false,
        path: searchPath,
        reason: `Compose SHA256 mismatch at ${bundledCompose}: expected ${expectedSha256}, got ${sha256}`,
      };
    }
    const probe = spawnSync(bundledCompose, ["version", "--short"], {
      encoding: "utf8",
      env: {
        DOCKER_HOST: "unix:///tmp/platform-compose-probe-engine-must-not-exist.sock",
        HOME: os.tmpdir(),
        LANG: "C",
        LC_ALL: "C",
        PATH: searchPath,
      },
      timeout: 10_000,
    });
    if (probe.status === 0) {
      return {
        available: true,
        path: searchPath,
        reason: "",
        standalone: bundledCompose,
      };
    }
    const detail = `${probe.stderr || probe.stdout || `status ${probe.status}`}`.trim();
    return {
      available: false,
      path: searchPath,
      reason: `bundled Compose at ${bundledCompose} failed its offline version probe: ${detail}`,
    };
  }

  return {
    available: false,
    path: searchPath,
    reason: "no SHA-pinned standalone Compose renderer is available; an unpinned docker compose plugin is not admissible",
  };
}

function prepareComposeExecutionPath(temporaryRoot, candidateOverlay) {
  const shimDir = path.join(temporaryRoot, "compose-shim");
  const shim = path.join(shimDir, "docker");
  fs.mkdirSync(shimDir, { mode: 0o700 });
  const delegate = composeAvailability.standalone
    ? `exec ${shellSingleQuote(composeAvailability.standalone)} "\${arguments[@]}"`
    : `exec ${shellSingleQuote(composeAvailability.docker)} compose "\${arguments[@]}"`;
  fs.writeFileSync(
    shim,
    [
      "#!/bin/bash",
      "set -euo pipefail",
      "[ \"$1\" = compose ] || exit 64",
      "shift",
      "arguments=()",
      "overlay_inserted=0",
      "for argument in \"$@\"; do",
      `  if [[ "$argument" == "--profile" && "$overlay_inserted" == 0 && -n ${shellSingleQuote(candidateOverlay)} ]]; then`,
      `    arguments+=("-f" ${shellSingleQuote(candidateOverlay)})`,
      "    overlay_inserted=1",
      "  fi",
      "  arguments+=(\"$argument\")",
      "done",
      `if [[ "$overlay_inserted" == 0 && -n ${shellSingleQuote(candidateOverlay)} ]]; then exit 65; fi`,
      delegate,
      "",
    ].join("\n"),
    { mode: 0o700 },
  );
  return [shimDir, composeAvailability.path].join(path.delimiter);
}

function shellSingleQuote(value) {
  return `'${String(value).replaceAll("'", `'\\''`)}'`;
}

function deterministicComposeEnvironment() {
  return [
    "ALERT_EMAIL_TO=alerts@example.invalid",
    "COMPOSE_PROJECT_NAME=platform_infra_vps",
    "DOMAIN=platform.example.invalid",
    "DOCKER_ACTION_ACTIVATION_INBOX=/srv/platform/provider-activation/inbox",
    "DOCKER_ACTION_ACTIVE_RECEIPT_FILE=/srv/platform/trust/active-receipt.json",
    `DOCKER_ACTION_ACTIVE_RECEIPT_SHA256=${"a".repeat(64)}`,
    `DOCKER_ACTION_COMBINED_RENDER_SHA256=${"b".repeat(64)}`,
    "DOCKER_ACTION_RUNTIME_INTENT_FILE=/srv/platform/trust/runtime-intent.json",
    "DOCKER_ACTION_RUNTIME_INTENT_ID=intent.offline-compose-v2",
    "HOSTED_WORKLOAD_LOCK=",
    "KC_BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/keycloak_admin_password",
    "KC_DB_PASSWORD_FILE=/run/secrets/keycloak_db_password",
    "MAILER_FROM=no-reply@example.invalid",
    "MAILER_REPLY_TO=no-reply@example.invalid",
    "MARIADB_ROOT_PASSWORD=offline-not-a-secret",
    "MINIO_ROOT_PASSWORD_FILE=/run/secrets/minio_root_password",
    "PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY=registry.example.invalid/platform/backup-scheduler",
    `PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256=${"e".repeat(64)}`,
    "PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY=registry.example.invalid/platform/docker-action-broker",
    `PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256=${"c".repeat(64)}`,
    "PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY=registry.example.invalid/platform/provider-activation",
    `PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256=${"d".repeat(64)}`,
    "POSTGRES_USER=postgres",
    "REDIS_PASSWORD_FILE=/run/secrets/redis_password",
    "REDIS_USERNAME=platform",
    "SMTP_HOST=smtp.example.invalid",
    "SMTP_USER=mailer",
    "",
  ].join("\n");
}

function candidateRuntimeIsolationOverlay() {
  const capabilitySecrets = CAPABILITY_SECRETS.map((name) => `      - source: ${name}
        target: ${name}
        uid: "0"
        gid: "0"
        mode: 256`).join("\n");
  const secretDeclarations = CAPABILITY_SECRETS.map((name) => `  ${name}:
    file: ./secrets/${name}.txt`).join("\n");
  const privateVolumeDeclarations = CANDIDATE_PROJECT_PRIVATE_VOLUMES
    .map((name) => `  ${name}: !override
    name: platform_infra_vps_${name}
    driver: local`)
    .join("\n");
  return `services:
  node-exporter:
    pid: !reset null
    command: !override
      - --collector.textfile.directory=/var/lib/node-exporter/textfile
    volumes: !override
      - \${NODE_EXPORTER_TEXTFILE_DIR:-./projects-portal/state/node-exporter-textfile}:/var/lib/node-exporter/textfile:ro

  cadvisor:
    command: !override
      - --docker_only=false
      - --store_container_labels=false
      - --housekeeping_interval=30s
    volumes: !reset []

  docker-action-broker:
    user: "0:0"
    read_only: true
    cap_drop: !override
      - ALL
    cap_add: !reset []
    group_add: !reset []
    network_mode: none
    networks: !reset []
    ports: !reset []
    expose: !reset []
    secrets: !override
      - source: ${TRUST_SECRET}
        target: ${TRUST_SECRET}
        uid: "0"
        gid: "0"
        mode: 256
${capabilitySecrets}
      - source: ${EVIDENCE_SECRET}
        target: ${EVIDENCE_SECRET}
        uid: "0"
        gid: "0"
        mode: 256
    volumes: !override
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - docker_action_broker_socket:/run/platform/docker-action-broker
      - docker_action_broker_state:/var/lib/platform/docker-action-broker
      - backup_scheduler_jobs:/run/platform/backup-jobs:ro
      - docker_action_activation_cas:/run/platform/docker-action-activation/by-bundle-sha256:ro
      - \${DOCKER_ACTION_RUNTIME_INTENT_FILE:?set root-owned runtime intent}:/run/platform/docker-action-trust/runtime-intent.json:ro
      - \${DOCKER_ACTION_ACTIVE_RECEIPT_FILE:?set root-owned active receipt}:/run/platform/docker-action-trust/active-receipt.json:ro
    tmpfs: !override
      - /tmp:rw,noexec,nosuid,nodev,size=64m
      - /root:rw,noexec,nosuid,nodev,size=16m
    healthcheck:
      test:
        - CMD
        - node
        - /opt/platform-docker-broker/docker-action-readiness.mjs
        - --require-trusted-activation
      interval: 15s
      timeout: 5s
      retries: 5

  backup-scheduler:
    image: \${PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY:?set scheduler repository}@sha256:\${PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256:?set scheduler sha256}
    build: !reset null
    user: "0:0"
    read_only: true
    entrypoint: !override
      - /opt/platform-backup-scheduler/backup-scheduler.sh
    command: !reset []
    cap_drop: !override
      - ALL
    cap_add: !reset []
    group_add: !reset []
    network_mode: none
    networks: !reset []
    ports: !reset []
    expose: !reset []
    environment: !override
      DOCKER_ACTION_BROKER_SOCKET: /run/platform/docker-action-broker/broker.sock
      DOCKER_ACTION_RUNTIME_INTENT_ID: \${DOCKER_ACTION_RUNTIME_INTENT_ID:?set admitted runtime intent id}
      DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: \${DOCKER_ACTION_ACTIVE_RECEIPT_SHA256:?set admitted active receipt sha256}
      DOCKER_ACTION_COMBINED_RENDER_SHA256: \${DOCKER_ACTION_COMBINED_RENDER_SHA256:?set exact final combined render sha256}
      BACKUP_SCHEDULER_JOBS_DIR: /var/www/project-state/backup-jobs
      BACKUP_SCHEDULER_LOG_DIR: /var/log/platform
      BACKUP_SCHEDULER_CRON_FILE: /run/platform/backup-scheduler/crontabs/root
      BACKUP_SCHEDULER_ENV_FILE: /run/platform/backup-scheduler/backup-scheduler.env
    secrets: !override
${capabilitySecrets}
    volumes: !override
      - backup_scheduler_jobs:/var/www/project-state/backup-jobs
      - backup_scheduler_logs:/var/log/platform
      - docker_action_broker_socket:/run/platform/docker-action-broker:ro
    tmpfs: !override
      - /tmp:rw,noexec,nosuid,nodev,size=64m
      - /run/platform/backup-scheduler:rw,noexec,nosuid,nodev,size=8m
    depends_on: !override
      docker-action-broker:
        condition: service_healthy
    healthcheck:
      test:
        - CMD-SHELL
        - test -s /run/platform/backup-scheduler/crontabs/root
      interval: 30s
      timeout: 5s
      retries: 5

volumes:
${privateVolumeDeclarations}
  backup_scheduler_jobs:

secrets:
${secretDeclarations}
  ${EVIDENCE_SECRET}:
    file: ./secrets/${EVIDENCE_SECRET}.txt
  ${TRUST_SECRET}:
    file: ./secrets/${TRUST_SECRET}.txt
`;
}

function assertRenderedPolicySurface(config) {
  assert.ok(config && typeof config === "object" && !Array.isArray(config), "Compose JSON render must be an object");
  for (const field of ["services", "networks", "volumes", "secrets"]) {
    assert.ok(
      config[field] && typeof config[field] === "object" && !Array.isArray(config[field]),
      `Compose JSON render must contain ${field}`,
    );
  }
  for (const name of ["docker-action-broker", "backup-scheduler"]) {
    const service = config.services[name];
    assert.ok(service && typeof service === "object", `canonical render is missing ${name}`);
    for (const field of ["cap_drop", "cap_add", "secrets", "tmpfs", "volumes", "volumes_from"]) {
      assert.ok(
        service[field] === undefined || Array.isArray(service[field]),
        `${name}.${field} has an unsupported normalized render shape`,
      );
    }
    assert.ok(
      service.networks === undefined || Array.isArray(service.networks) || typeof service.networks === "object",
      `${name}.networks shape is invalid`,
    );
    assert.ok(
      service.healthcheck === undefined || Array.isArray(service.healthcheck.test),
      `${name}.healthcheck.test shape is invalid`,
    );
    assert.ok(service.user === undefined || typeof service.user === "string", `${name}.user shape is invalid`);
  }
}

function renderedRawSocketOwners(config) {
  return Object.keys(config.services)
    .filter((name) => renderedServiceOwnsRawSocket(config, name))
    .sort();
}

function renderedServiceOwnsRawSocket(config, name, ancestry = new Set()) {
  if (ancestry.has(name)) throw new Error(`cyclic rendered volumes_from authority chain at ${name}`);
  const service = config.services[name];
  assert.ok(service, `unknown rendered service ${name}`);
  const next = new Set(ancestry).add(name);
  if ((service.volumes ?? []).some((mount) => {
    if (mount?.type !== "volume") return exposesDockerSocket(mount?.source);
    const volumeName = String(mount?.source || "");
    const declaration = config.volumes?.[volumeName];
    if (!declaration || declaration.external === true) return true;
    const canonicalName = `${String(config.name || "")}_${volumeName}`;
    if (!config.name || declaration.name !== canonicalName) return true;
    if (declaration.driver && declaration.driver !== "local") return true;
    if (declaration.driver_opts) {
      const device = declaration.driver_opts.device;
      return device ? exposesDockerSocket(device) : true;
    }
    return false;
  })) return true;
  return (service.volumes_from ?? []).some((rawReference) => {
    if (typeof rawReference === "string" && rawReference.startsWith("container:")) return true;
    const reference = typeof rawReference === "string"
      ? rawReference.split(":")[0]
      : String(rawReference?.source || rawReference?.service || "");
    if (!reference || reference.startsWith("container:")) return true;
    return renderedServiceOwnsRawSocket(config, reference, next);
  });
}

function exposesDockerSocket(source) {
  if (!String(source || "").startsWith("/")) return false;
  const observed = path.posix.normalize(source);
  const normalized = observed === "/run" || observed.startsWith("/run/")
    ? `/var${observed}`
    : observed;
  const clean = normalized === "/" ? "/" : normalized.replace(/\/+$/, "");
  return clean === "/var/run/docker.sock"
    || "/var/run/docker.sock".startsWith(clean === "/" ? "/" : `${clean}/`);
}

function secretNamesFromRender(service) {
  return (service.secrets ?? [])
    .map((entry) => typeof entry === "string" ? entry : String(entry?.source || ""))
    .sort();
}

function hostileWorkload(overrides = {}) {
  return {
    cpus: 0.5,
    cpu_shares: 256,
    mem_limit: 128 * 1024 * 1024,
    mem_reservation: 32 * 1024 * 1024,
    pids_limit: 128,
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    blkio_config: { weight: 300 },
    read_only: true,
    user: "1000:1000",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    environment: {},
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "web",
    },
    networks: { example_app_ingress: null },
    secrets: [],
    tmpfs: [],
    volumes: [],
    ...overrides,
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
