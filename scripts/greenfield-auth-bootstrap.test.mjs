import assert from "node:assert/strict";
import test from "node:test";
import {
  SCHEMA,
  BOOTSTRAP_TOKEN_MIN_LENGTH,
  KEYCLOAK_CLIENT_SECRET_MIN_LENGTH,
  FIRST_CONFIGURATION_REQUIRED_ENV,
  FIRST_CONFIGURATION_SECRET_LOGICAL_NAMES,
  GF_CONTROL_CENTER_CONTAINER,
  GF_KEYCLOAK_CONTAINER,
  GREENFIELD_SECRETS_ROOT,
  AUTH_BOOTSTRAP_SEQUENCE_STEP_IDS,
  HUMAN_GATE_STEP_IDS,
  preflightAuthBootstrap,
  buildAuthBootstrapSequence,
  serializeAuthBootstrapSequence,
  keycloakPasskeyReconcileInvocation,
  bootstrapClosureReceipt,
} from "./greenfield-auth-bootstrap.mjs";

const TOKEN_LOGICAL = "control_center_first_configuration_bootstrap_token";
const CLIENT_SECRET_LOGICAL = "control_center_first_configuration_keycloak_client_secret";
const TOKEN_FILE = `${GREENFIELD_SECRETS_ROOT}/${TOKEN_LOGICAL}.txt`;
const CLIENT_SECRET_FILE = `${GREENFIELD_SECRETS_ROOT}/${CLIENT_SECRET_LOGICAL}.txt`;

const URL_ENV_KEYS = [
  "CONTROL_CENTER_FIRST_CONFIGURATION_ACCOUNT_URL",
  "CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_ENDPOINT",
  "CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_BASE_URL",
];

function fixtureEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(FIRST_CONFIGURATION_REQUIRED_ENV)) {
    environment[key] = URL_ENV_KEYS.includes(key) ? "https://auth.greenfield.example.com/fixture" : value;
  }
  return environment;
}

function fixtureRender(overrides = {}) {
  const render = {
    name: "platform_infra_greenfield",
    services: {
      "control-center": {
        container_name: "gf-control-center",
        environment: fixtureEnvironment(),
        secrets: [TOKEN_LOGICAL, CLIENT_SECRET_LOGICAL],
      },
      keycloak: {
        container_name: "gf-keycloak",
      },
    },
    secrets: {
      [TOKEN_LOGICAL]: { file: TOKEN_FILE },
      [CLIENT_SECRET_LOGICAL]: { file: CLIENT_SECRET_FILE },
    },
    ...overrides,
  };
  return render;
}

function happyObservation() {
  return [
    { logicalName: TOKEN_LOGICAL, sha256: "a".repeat(64), sizeBytes: 64, present: true },
    { logicalName: CLIENT_SECRET_LOGICAL, sha256: "b".repeat(64), sizeBytes: 48, present: true },
  ];
}

function mutateRender(base, mutator) {
  const clone = JSON.parse(JSON.stringify(base));
  mutator(clone);
  return clone;
}

test("required env map mirrors the compose first-configuration wiring, frozen", () => {
  assert.equal(Object.isFrozen(FIRST_CONFIGURATION_REQUIRED_ENV), true);
  assert.equal(FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_ENV, "local_private");
  assert.equal(FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_FIRST_CONFIGURATION_MODE, "required");
  assert.equal(
    FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE,
    "/run/secrets/control_center_first_configuration_bootstrap_token",
  );
  assert.equal(
    FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID,
    "platform-first-configuration",
  );
  assert.equal(
    FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE,
    "/run/secrets/control_center_first_configuration_keycloak_client_secret",
  );
  assert.equal(FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME, "admin");
  assert.equal(
    FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS,
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128",
  );
  assert.equal(
    FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS,
    "172.16.0.0/12,127.0.0.0/8,::1/128",
  );
  for (const key of URL_ENV_KEYS) {
    assert.match(FIRST_CONFIGURATION_REQUIRED_ENV[key], /^https:\/\/auth\./, key);
  }
  assert.equal(FIRST_CONFIGURATION_REQUIRED_ENV.CONTROL_CENTER_MIN_PASSKEYS, "2");
});

test("preflight happy case with hand-built greenfield render is violation-free", () => {
  const report = preflightAuthBootstrap({
    renderConfig: fixtureRender(),
    secretsObservation: happyObservation(),
  });
  assert.deepEqual(report.violations, []);
  assert.equal(report.ready, true);
  assert.equal(report.schema, SCHEMA);
});

test("preflight fails closed when the render is unavailable offline", () => {
  const report = preflightAuthBootstrap({ renderConfig: null, secretsObservation: happyObservation() });
  assert.equal(report.ready, false);
  assert.ok(report.violations.includes("render:must-be-object"));
});

test("preflight maps a missing env key to its specific violation id", () => {
  const render = mutateRender(fixtureRender(), (config) => {
    delete config.services["control-center"].environment.CONTROL_CENTER_MIN_PASSKEYS;
  });
  const report = preflightAuthBootstrap({ renderConfig: render, secretsObservation: happyObservation() });
  assert.equal(report.ready, false);
  assert.ok(report.violations.includes("control-center:env:missing:CONTROL_CENTER_MIN_PASSKEYS"));
});

test("preflight maps a wrong MODE value to its specific violation id", () => {
  const render = mutateRender(fixtureRender(), (config) => {
    config.services["control-center"].environment.CONTROL_CENTER_FIRST_CONFIGURATION_MODE = "disabled";
  });
  const report = preflightAuthBootstrap({ renderConfig: render, secretsObservation: happyObservation() });
  assert.equal(report.ready, false);
  assert.ok(report.violations.includes("control-center:env:value:CONTROL_CENTER_FIRST_CONFIGURATION_MODE"));
});

test("preflight rejects brownfield enterprise-* container names specifically", () => {
  const render = mutateRender(fixtureRender(), (config) => {
    config.services["control-center"].container_name = "enterprise-control-center";
    config.services.keycloak.container_name = "enterprise-keycloak";
  });
  const report = preflightAuthBootstrap({ renderConfig: render, secretsObservation: happyObservation() });
  assert.equal(report.ready, false);
  assert.ok(report.violations.includes("control-center:container-name:brownfield"));
  assert.ok(report.violations.includes("keycloak:container-name:brownfield"));
});

test("preflight rejects a missing secret declaration specifically", () => {
  const render = mutateRender(fixtureRender(), (config) => {
    delete config.secrets[TOKEN_LOGICAL];
  });
  const report = preflightAuthBootstrap({ renderConfig: render, secretsObservation: happyObservation() });
  assert.equal(report.ready, false);
  assert.ok(report.violations.includes(`secret:${TOKEN_LOGICAL}:undeclared`));
});

test("preflight rejects an undersized bootstrap token observation (<43)", () => {
  const observation = [
    { logicalName: TOKEN_LOGICAL, sizeBytes: BOOTSTRAP_TOKEN_MIN_LENGTH - 1, present: true },
    { logicalName: CLIENT_SECRET_LOGICAL, sizeBytes: KEYCLOAK_CLIENT_SECRET_MIN_LENGTH + 24, present: true },
  ];
  const report = preflightAuthBootstrap({ renderConfig: fixtureRender(), secretsObservation: observation });
  assert.equal(report.ready, false);
  assert.ok(report.violations.includes(`observation:${TOKEN_LOGICAL}:size-undersized`));
});

test("sequence is exactly the 14 ordered steps with two passkey human gates", () => {
  const sequence = buildAuthBootstrapSequence();
  assert.equal(sequence.length, 14);
  assert.deepEqual(sequence.map((step) => step.stepId), [
    "VERIFY_GREENFIELD_RENDER",
    "WAIT_HEALTHY_GF_KEYCLOAK",
    "WAIT_HEALTHY_GF_CONTROL_CENTER",
    "STAGE_FIRST_CONFIGURATION_SECRETS",
    "OPEN_FIRST_CONFIGURATION",
    "ADMIN_CONFIRMED",
    "ENROLL_PASSKEY_1",
    "ENROLL_PASSKEY_2",
    "PASSKEYS_READY",
    "LOGIN_VERIFICATION",
    "LOGOUT_VERIFICATION",
    "REVOCATION_CHECK",
    "RESTART_PERSISTENCE_CHECK",
    "BOOTSTRAP_CLOSURE",
  ]);
  assert.deepEqual(AUTH_BOOTSTRAP_SEQUENCE_STEP_IDS.slice(6, 8), ["ENROLL_PASSKEY_1", "ENROLL_PASSKEY_2"]);

  const humanGates = sequence.filter((step) => step.kind === "human-gate");
  assert.deepEqual(humanGates.map((step) => step.stepId), ["ENROLL_PASSKEY_1", "ENROLL_PASSKEY_2"]);
  assert.deepEqual(HUMAN_GATE_STEP_IDS, ["ENROLL_PASSKEY_1", "ENROLL_PASSKEY_2"]);
  for (const gate of humanGates) {
    assert.match(gate.description, /READY FOR 2 PASSKEYS/, gate.stepId);
  }
  for (const step of sequence) {
    assert.equal(["automated", "human-gate"].includes(step.kind), true, step.stepId);
    assert.equal(typeof step.description, "string");
    assert.equal(typeof step.evidenceRequired, "string");
    assert.notEqual(step.evidenceRequired, "");
    assert.equal(Object.isFrozen(step), true);
  }
  assert.equal(Object.isFrozen(sequence), true);
});

test("sequence serialization is deterministic canonical JSON", () => {
  const serializedOnce = serializeAuthBootstrapSequence(buildAuthBootstrapSequence());
  const serializedAgain = serializeAuthBootstrapSequence(buildAuthBootstrapSequence());
  assert.equal(serializedAgain, serializedOnce);

  // Key order is sorted recursively (canonical form), not insertion-ordered.
  const parsed = JSON.parse(serializedOnce);
  for (const step of parsed) {
    assert.deepEqual(Object.keys(step), ["description", "evidenceRequired", "kind", "stepId"]);
  }
});

test("reconcile invocation for stage staged targets gf-keycloak with staged confirmation", () => {
  const invocation = keycloakPasskeyReconcileInvocation({ stage: "staged" });
  assert.deepEqual(invocation.argv, [
    "node",
    new URL("../scripts/keycloak-passkey-reconcile.mjs", import.meta.url).pathname,
  ]);
  assert.equal(invocation.env.KEYCLOAK_CONTAINER, "gf-keycloak");
  assert.equal(invocation.env.KEYCLOAK_REALM, "platform");
  assert.equal(invocation.env.KEYCLOAK_PASSKEY_ACTION, "apply-staged");
  assert.equal(invocation.env.KEYCLOAK_PASSKEY_CONFIRM, "RECONCILE-PLATFORM-PASSKEY-STAGED");
});

test("reconcile invocation for stage bind carries bind confirmation", () => {
  const invocation = keycloakPasskeyReconcileInvocation({ stage: "bind" });
  assert.equal(invocation.argv[1].endsWith("/scripts/keycloak-passkey-reconcile.mjs"), true);
  assert.equal(invocation.env.KEYCLOAK_CONTAINER, "gf-keycloak");
  assert.equal(invocation.env.KEYCLOAK_PASSKEY_ACTION, "bind");
  assert.equal(invocation.env.KEYCLOAK_PASSKEY_CONFIRM, "BIND-PLATFORM-PASSKEY-BROWSER");
  assert.equal(invocation.env.KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED, "true");
});

test("reconcile invocation refuses unknown stages", () => {
  assert.throws(() => keycloakPasskeyReconcileInvocation({ stage: "rollback-browser" }), TypeError);
  assert.throws(() => keycloakPasskeyReconcileInvocation({}), TypeError);
});

function fullSequenceRunLog() {
  const log = [];
  let counter = 0;
  for (const step of buildAuthBootstrapSequence()) {
    if (step.kind === "human-gate") {
      log.push({
        stepId: step.stepId,
        passkeyIndex: step.stepId.endsWith("_2") ? 2 : 1,
        enrolledAtUtc: `2026-08-26T00:00:${String(counter++).padStart(2, "0")}Z`,
      });
      continue;
    }
    log.push({ stepId: step.stepId, evidenceDigest: (counter++ % 10 + "a").padEnd(64, "0") });
  }
  return log;
}

test("closure receipt closes on a complete run log", () => {
  const receipt = bootstrapClosureReceipt({ sequenceRunLog: fullSequenceRunLog() });
  assert.equal(receipt.status, "BOOTSTRAP_CLOSED");
  assert.equal(receipt.firstConfigurationState, "COMPLETE");
  assert.deepEqual(receipt.violations, []);
  assert.equal(receipt.counts.stepsTotal, 14);
  assert.equal(receipt.counts.automatedSteps, 12);
  assert.equal(receipt.counts.automatedEvidenceSatisfied, 12);
  assert.equal(receipt.counts.humanGateSteps, 2);
  assert.equal(receipt.counts.humanGatesRecorded, 2);
  assert.equal(receipt.counts.violations, 0);
});

test("closure receipt never closes when a passkey human gate is missing", () => {
  const incompleteLog = fullSequenceRunLog()
    .filter((record) => record.stepId !== "ENROLL_PASSKEY_2");
  const receipt = bootstrapClosureReceipt({ sequenceRunLog: incompleteLog });
  assert.notEqual(receipt.status, "BOOTSTRAP_CLOSED");
  assert.equal(receipt.firstConfigurationState, "INCOMPLETE");
  assert.notEqual(receipt.violations.length, 0);
  assert.ok(receipt.violations.includes("human-gate:ENROLL_PASSKEY_2:missing"));
});

test("closure receipt rejects fabricated empty evidence digests", () => {
  const fabricatedLog = fullSequenceRunLog().map((record) =>
    record.stepId === "VERIFY_GREENFIELD_RENDER" ? { ...record, evidenceDigest: "" } : record,
  );
  const receipt = bootstrapClosureReceipt({ sequenceRunLog: fabricatedLog });
  assert.notEqual(receipt.status, "BOOTSTRAP_CLOSED");
  assert.ok(receipt.violations.includes("evidence:not-satisfied:VERIFY_GREENFIELD_RENDER"));
});

test("no secret material ever appears in any serialized output", () => {
  const leakPatterns = [
    /-----BEGIN/i,
    /(?:password|passwd|pwd|token|secret)\s*=/i,
    /[A-Za-z0-9+/]{65,}={0,2}/,
  ];
  const outputs = [
    serializeAuthBootstrapSequence(buildAuthBootstrapSequence()),
    JSON.stringify(keycloakPasskeyReconcileInvocation({ stage: "staged" })),
    JSON.stringify(keycloakPasskeyReconcileInvocation({ stage: "bind" })),
    JSON.stringify(preflightAuthBootstrap({ renderConfig: fixtureRender(), secretsObservation: happyObservation() })),
    JSON.stringify(bootstrapClosureReceipt({ sequenceRunLog: fullSequenceRunLog() })),
  ];
  for (const output of outputs) {
    assert.doesNotMatch(output, /-----BEGIN/i);
    for (const pattern of leakPatterns) {
      assert.doesNotMatch(output, pattern);
    }
  }
});
