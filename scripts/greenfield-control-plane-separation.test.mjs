import assert from "node:assert/strict";
import test from "node:test";
import {
  CONTROL_CENTER_DEPENDS_ON_STEXOR,
  INFRASTRUCTURE_DEPENDS_ON_STEXOR,
  CONTROL_PLANE_SERVICES,
  WORKLOAD_SERVICES,
  evaluateControlPlaneSeparation,
  evaluateRenderSeparation,
  evaluatePlanSeparation,
  serviceDependencyClass,
  stateDependencyClass,
  separationDescriptor,
} from "./greenfield-control-plane-separation.mjs";
import { buildStateProjectionPlan } from "./greenfield-state-projection.mjs";
import { buildFinalSyncSequence } from "./greenfield-final-sync-plan.mjs";
import { buildAuthBootstrapSequence } from "./greenfield-auth-bootstrap.mjs";

function preservationManifestFixture() {
  return {
    hostStateTrees: {
      "/home/platform_infrastructure/src": {
        projects: ["stexor", "workcalendar", "public"],
      },
      "/home/platform_infrastructure/platform-infrastructure/projects-portal/state": { size: "916K" },
      "/home/platform_infrastructure/platform-infrastructure/secrets": { size: "220K" },
      "/home/platform_infrastructure/platform-infrastructure/backups": {
        families: ["a", "b"],
      },
    },
    anonymousVolumesCountApprox: 135,
  };
}

function renderFixture(overrides = {}) {
  const services = {
    "control-center": { depends_on: { keycloak: { condition: "service_healthy" }, postgres: {} } },
    keycloak: { depends_on: { postgres: { condition: "service_healthy" } } },
    postgres: {},
    redis: {},
    waf: { depends_on: { traefik: { condition: "service_healthy" } } },
    traefik: {},
    "php-apache": { depends_on: { mariadb: { condition: "service_healthy" } } },
    mariadb: {},
    "project-router": { depends_on: { "control-center": { condition: "service_healthy" } } },
  };
  for (const [service, patch] of Object.entries(overrides.services ?? {})) {
    services[service] = { ...(services[service] ?? {}), ...patch };
    if (patch === null) delete services[service];
  }
  return { name: "platform_infra_greenfield", services };
}

test("the exported architectural gates are hard-false constants", () => {
  assert.equal(CONTROL_CENTER_DEPENDS_ON_STEXOR, false);
  assert.equal(INFRASTRUCTURE_DEPENDS_ON_STEXOR, false);
  assert.equal(separationDescriptor.controlCenterDependsOnStexor, false);
  assert.equal(separationDescriptor.infrastructureDependsOnStexor, false);
});

test("classification splits control plane from application workloads", () => {
  assert.equal(serviceDependencyClass("control-center"), "control-plane");
  assert.equal(serviceDependencyClass("keycloak"), "control-plane");
  assert.equal(serviceDependencyClass("postgres"), "control-plane");
  assert.equal(serviceDependencyClass("php-apache"), "application-workload");
  assert.equal(serviceDependencyClass("project-router"), "application-workload");
  assert.equal(serviceDependencyClass("mystery-app"), "unknown");

  assert.equal(stateDependencyClass("postgres-stexor"), "application-workload");
  assert.equal(stateDependencyClass("app-src-stexor"), "application-workload");
  assert.equal(stateDependencyClass("app-src-workcalendar"), "application-workload");
  assert.equal(stateDependencyClass("postgres-keycloak"), "control-plane");
  assert.equal(stateDependencyClass("keycloak-runtime-data"), "control-plane");
  assert.equal(stateDependencyClass("control-center-state"), "control-plane");
  assert.equal(stateDependencyClass("mariadb-all"), "shared-infrastructure");
  assert.equal(stateDependencyClass("observe-prometheus-data"), "shared-infrastructure");
  assert.equal(stateDependencyClass("something-new"), "unknown");

  // No service may be both control plane and workload.
  for (const service of CONTROL_PLANE_SERVICES) {
    assert.ok(!WORKLOAD_SERVICES.includes(service), service);
  }
});

test("canonical greenfield render satisfies the separation invariant", () => {
  const violations = evaluateRenderSeparation(renderFixture());
  assert.deepEqual(violations, []);
});

test("any control-plane dependence on a workload is a fail-closed violation", () => {
  const stexorDependent = evaluateRenderSeparation(renderFixture({
    services: { "control-center": { depends_on: { "php-apache": { condition: "service_started" } } } },
  }));
  assert.deepEqual(stexorDependent, ["separation:control-center:depends-on-workload:php-apache"]);

  const keycloakDependent = evaluateRenderSeparation(renderFixture({
    services: { keycloak: { depends_on: { "project-router": {} } } },
  }));
  assert.deepEqual(keycloakDependent, ["separation:keycloak:depends-on-workload:project-router"]);

  const unknownService = evaluateRenderSeparation(renderFixture({
    services: { "brand-new-app": { image: "x@sha256:" + "0".repeat(64) } },
  }));
  assert.deepEqual(unknownService, ["separation:brand-new-app:unclassified-service"]);

  const unknownDependency = evaluateRenderSeparation(renderFixture({
    services: { traefik: { depends_on: { "mystery-sidecar": {} } } },
  }));
  assert.deepEqual(unknownDependency, ["separation:traefik:unclassified-dependency:mystery-sidecar"]);
});

test("control-plane surfaces must not carry workload application material", () => {
  const envLeak = evaluateRenderSeparation(renderFixture({
    services: { "control-center": { environment: { DATABASE_URL: "postgresql://postgres/stexor" } } },
  }));
  assert.deepEqual(envLeak, ["separation:control-center:workload-material-reference"]);

  const mountLeak = evaluateRenderSeparation(renderFixture({
    services: { keycloak: { volumes: ["/srv/stexor/state:/data:ro"] } },
  }));
  assert.deepEqual(mountLeak, ["separation:keycloak:workload-material-reference"]);

  // Workload-side references to their own applications stay allowed.
  assert.deepEqual(evaluateRenderSeparation(renderFixture({
    services: { "project-router": { environment: { ROUTE_TARGET: "stexor.internal" } } },
  })), []);
});

test("planning artifacts from the real modules satisfy the invariant", () => {
  const stateProjectionPlan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
  const finalSyncSequence = buildFinalSyncSequence();
  const authBootstrap = buildAuthBootstrapSequence();
  const violations = evaluateControlPlaneSeparation({
    renderedConfig: renderFixture(),
    stateProjectionPlan,
    finalSyncSequence,
    authBootstrap,
  });
  assert.deepEqual(violations, []);
});

test("plan-level hostiles fail closed", () => {
  const base = {
    stateProjectionPlan: buildStateProjectionPlan({ manifest: preservationManifestFixture() }),
    finalSyncSequence: buildFinalSyncSequence(),
    authBootstrap: buildAuthBootstrapSequence(),
  };

  const emptyState = evaluatePlanSeparation({ ...base, stateProjectionPlan: { entries: [] } });
  assert.ok(emptyState.includes("separation:state-plan-empty"));

  const unknownEntry = evaluatePlanSeparation({
    ...base,
    stateProjectionPlan: {
      entries: [...base.stateProjectionPlan.entries, { entryId: "mystery-state" }],
    },
  });
  assert.ok(unknownEntry.includes("separation:mystery-state:unclassified-state-entry"));

  const unknownWriter = evaluatePlanSeparation({
    ...base,
    finalSyncSequence: {
      phases: [{ phase: "FINAL_CAPTURE", writers: [{ writerId: "mystery-writer" }] }],
    },
  });
  assert.ok(unknownWriter.includes("separation:mystery-writer:unclassified-final-sync-writer"));

  const leakyBootstrap = evaluatePlanSeparation({
    ...base,
    authBootstrap: [
      ...base.authBootstrap,
      { stepId: "IMPORT_STEXOR_PASSKEY", description: "import existing stexor passkey into first configuration" },
    ],
  });
  assert.ok(leakyBootstrap.includes("separation:auth-bootstrap-references-workload-material"));

  const missingBootstrap = evaluatePlanSeparation({ ...base, authBootstrap: null });
  assert.ok(missingBootstrap.includes("separation:auth-bootstrap-missing"));
});
