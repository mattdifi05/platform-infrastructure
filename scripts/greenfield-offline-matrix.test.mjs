// GREENFIELD OFFLINE MATRIX: end-to-end integration suite traversing the real
// cohort modules offline (renders only, zero container mutations, zero network).
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { evaluateGreenfieldNamespace, GREENFIELD_AUXILIARY_SERVICES, GREENFIELD_PROJECT_NAME } from "./greenfield-namespace.mjs";
import {
  evaluateControlPlaneSeparation,
  separationDescriptor,
  serviceDependencyClass,
} from "./greenfield-control-plane-separation.mjs";
import {
  buildStateProjectionPlan,
  finalSyncWriterRegistry,
  serializeProjectionPlan,
  validateStateProjectionPlan,
} from "./greenfield-state-projection.mjs";
import {
  buildSecretProjectionPlan,
  buildSecretReceipt,
  assertNoSecretMaterialization,
  verifyObservedSecretSet,
} from "./greenfield-secret-projection.mjs";
import {
  buildCapturePlan,
  buildRestorePlan,
  compareFingerprints,
  executeCaptureStep,
} from "./greenfield-backup-restore-executor.mjs";
import {
  buildFinalSyncSequence,
  serializeFinalSyncPlan,
  validateDeltaZero,
} from "./greenfield-final-sync-plan.mjs";
import {
  bootstrapClosureReceipt,
  buildAuthBootstrapSequence,
  GF_KEYCLOAK_CONTAINER,
  GREENFIELD_SECRETS_ROOT,
  HUMAN_GATE_STEP_IDS,
  keycloakPasskeyReconcileInvocation,
  preflightAuthBootstrap,
} from "./greenfield-auth-bootstrap.mjs";

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WRAPPER_PATH = path.join(ROOT_DIR, "scripts", "compose-greenfield.sh");
const POLICY_CLI_PATH = path.join(ROOT_DIR, "scripts", "greenfield-core-policy.mjs");
const GREENFIELD_LOCK_PATH = path.join(ROOT_DIR, "config", "no-hosted-workloads.greenfield.lock.json");
const LOCAL_PRIVATE_LOCK_PATH = path.join(ROOT_DIR, "config", "no-hosted-workloads.local-private.lock.json");
const TRANSACTION_SCRIPT_PATH = path.join(ROOT_DIR, "scripts", "v1-greenfield-transaction.py");
const WORKLOAD_BUILDER_PATH = path.join(ROOT_DIR, "scripts", "greenfield-workload-builder.sh");
const ENV_EXAMPLE_PATH = path.join(ROOT_DIR, ".env.example");
const COMPOSE_UNAVAILABLE_SKIP = "compose renderer unavailable on this host; exercised in CI";
const DIRTY_WORKTREE_SKIP = "worktree dirty; authoritative run happens post-commit/CI";

const startedAt = new Date().toISOString();
const tally = { pass: 0, fail: 0, skipped: 0 };

function matrixTest(name, options, body) {
  const normalized = typeof options === "function" ? {} : { ...(options ?? {}) };
  const fn = typeof options === "function" ? options : body;
  if (normalized.skip) {
    tally.skipped += 1;
    test(name, { skip: normalized.skip }, () => {});
    return;
  }
  test(name, normalized, async (t) => {
    try {
      await fn(t);
      tally.pass += 1;
    } catch (error) {
      tally.fail += 1;
      throw error;
    }
  });
}

const tempRoots = [];
function makeTempRoot(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempRoots.push(root);
  return root;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function deterministicDigest(seed) {
  return crypto.createHash("sha256").update(`platform-greenfield-offline-matrix:${seed}`).digest("hex");
}

function stripRepoEnvironment(environment) {
  const clean = {};
  for (const key of Object.keys(environment)) {
    if (!/^PLATFORM_|^GREENFIELD_|^COMPOSE_|^DOCKER_|^WAF_|^MARIADB_DATA_VOLUME|^HOSTED_WORKLOAD_/.test(key)) {
      clean[key] = environment[key];
    }
  }
  return clean;
}

function readDotenvMap(filePath) {
  const map = {};
  for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator < 1) continue;
    map[trimmed.slice(0, separator).trim()] = trimmed.slice(separator + 1).trim();
  }
  return map;
}

function overlayChainFromWrapper() {
  const source = fs.readFileSync(WRAPPER_PATH, "utf8");
  const chain = [];
  for (const match of source.matchAll(/-f (compose(?:\.[a-z0-9-]+)?\.yaml)/g)) {
    if (!chain.includes(match[1])) chain.push(match[1]);
  }
  const conditionalIdentityOverlay = chain.indexOf("compose.runtime-identity.yaml");
  if (conditionalIdentityOverlay >= 0) chain.splice(conditionalIdentityOverlay, 1);
  return chain.filter((overlay) => fs.existsSync(path.join(ROOT_DIR, overlay)));
}

function requiredInterpolationVariables() {
  const names = new Set();
  for (const overlay of overlayChainFromWrapper()) {
    const text = fs.readFileSync(path.join(ROOT_DIR, overlay), "utf8");
    for (const match of text.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*):\?/g)) {
      names.add(match[1]);
    }
  }
  return [...names].sort();
}

const DISABLING_PROFILES = new Set([
  "admin",
  "dns",
  "raw-host-metrics-disabled",
  "local-runtime-disabled",
  "legacy-shared-runtime-disabled",
]);

const FIRST_CONFIG_TOKEN_MIN = 43;
const FIRST_CONFIG_CLIENT_SECRET_MIN = 24;

function createComposeFixtureWorkspace() {
  const root = makeTempRoot("greenfield-matrix-fixture-");
  const secretsRoot = path.join(root, "secrets");
  const certsDir = path.join(root, "certs");
  const stateDir = path.join(root, "state");
  const projectsDir = path.join(root, "projects");
  const firstConfigDir = path.join(root, "first-configuration");
  for (const dir of [secretsRoot, certsDir, stateDir, projectsDir, firstConfigDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const localPrivateLock = JSON.parse(fs.readFileSync(LOCAL_PRIVATE_LOCK_PATH, "utf8"));
  for (const secretName of localPrivateLock.protectedResourceNames.secrets) {
    fs.writeFileSync(
      path.join(secretsRoot, `${secretName}.txt`),
      `ci-placeholder-${secretName}-00000000000000000000000000000000\n`,
      { mode: 0o600 },
    );
  }
  const tokenValue = `ci-placeholder-bootstrap-token-${"t".repeat(FIRST_CONFIG_TOKEN_MIN)}\n`;
  const clientSecretValue = `ci-placeholder-client-secret-${"k".repeat(FIRST_CONFIG_CLIENT_SECRET_MIN)}\n`;
  const tokenFile = path.join(firstConfigDir, "control_center_first_configuration_bootstrap_token.txt");
  const clientSecretFile = path.join(
    firstConfigDir,
    "control_center_first_configuration_keycloak_client_secret.txt",
  );
  fs.writeFileSync(tokenFile, tokenValue, { mode: 0o600 });
  fs.writeFileSync(clientSecretFile, clientSecretValue, { mode: 0o600 });
  for (const pem of ["local-cert.pem", "local-key.pem", "local-ca.pem"]) {
    fs.writeFileSync(path.join(certsDir, pem), `placeholder ${pem}; not certificate material\n`);
  }

  const env = readDotenvMap(ENV_EXAMPLE_PATH);
  delete env.WAF_HTTP_BIND;
  delete env.WAF_HTTPS_BIND;
  delete env.COMPOSE_PROJECT_NAME;
  const overrides = {
    MARIADB_DATA_VOLUME: "greenfield_mariadb_data",
    PLATFORM_NETWORK_PREFIX: GREENFIELD_PROJECT_NAME,
    PLATFORM_SECRETS_ROOT: secretsRoot,
    PLATFORM_CERTS_DIR: certsDir,
    PLATFORM_STATE_DIR: stateDir,
    PHP_PROJECTS_DIR: projectsDir,
    CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE: tokenFile,
    CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE: clientSecretFile,
    HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE: LOCAL_PRIVATE_LOCK_PATH,
    DOCKER_ACTION_RUNTIME_INTENT_FILE: "/srv/platform/trust/runtime-intent.json",
    DOCKER_ACTION_ACTIVE_RECEIPT_FILE: "/srv/platform/trust/active-receipt.json",
    DOCKER_ACTION_ACTIVATION_INBOX: "/srv/platform/provider-activation/inbox",
    DOCKER_ACTION_RUNTIME_INTENT_ID: "greenfield-offline-matrix-intent-0001",
    DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: deterministicDigest("docker-action-active-receipt"),
    DOCKER_ACTION_COMBINED_RENDER_SHA256: deterministicDigest("docker-action-combined-render"),
  };
  for (const imageVar of [
    "PHP_APACHE_IMAGE",
    "CONTROL_CENTER_IMAGE",
    "PROJECT_ROUTER_IMAGE",
    "PLATFORM_ALERT_DISPATCHER_IMAGE",
    "PLATFORM_OPS_IMAGE",
  ]) {
    overrides[imageVar] = `registry.invalid/platform/${imageVar.toLowerCase().replaceAll("_", "-")}@sha256:${deterministicDigest(`image:${imageVar}`)}`;
  }
  Object.assign(env, overrides);
  const provided = new Set(Object.keys(env));
  for (const name of requiredInterpolationVariables()) {
    if (provided.has(name) && env[name] !== "") continue;
    if (/_(FILE|SOURCE)$/.test(name)) {
      env[name] = `/srv/platform/trust/${name.toLowerCase().replaceAll("_", "-")}`;
    } else if (/_SHA256$/.test(name)) {
      env[name] = deterministicDigest(name);
    } else if (/_IMAGE_REPOSITORY$/.test(name)) {
      env[name] = `registry.invalid/platform/${name.toLowerCase().replaceAll("_", "-").replace(/-image-repository$/, "")}`;
    } else if (/_(DIR|ROOT|INBOX)$/.test(name)) {
      env[name] = path.join(root, "material", name.toLowerCase());
    } else {
      env[name] = `ci-placeholder-${name.toLowerCase().replaceAll("_", "-")}`;
    }
  }
  const envFile = path.join(root, "greenfield.env");
  fs.writeFileSync(
    envFile,
    `${Object.keys(env).sort().map((key) => `${key}=${env[key]}`).join("\n")}\n`,
    { mode: 0o600 },
  );
  const policyEnvFile = path.join(root, "environment-snapshot.env");
  fs.writeFileSync(policyEnvFile, `PLATFORM_SECRETS_ROOT=${secretsRoot}\n`, { mode: 0o600 });
  return {
    root,
    envFile,
    secretsRoot,
    certsDir,
    stateDir,
    projectsDir,
    tokenFile,
    clientSecretFile,
    policyEnvFile,
    requiredVariables: requiredInterpolationVariables(),
  };
}

function detectComposeCapability() {
  const pinned = process.env.PLATFORM_TEST_DOCKER_COMPOSE_BIN;
  if (pinned !== undefined && pinned !== "") {
    if (!path.isAbsolute(pinned) || !fs.existsSync(pinned) || !fs.statSync(pinned).isFile()) {
      return { available: false, reason: `PLATFORM_TEST_DOCKER_COMPOSE_BIN is not an absolute executable file: ${pinned}` };
    }
    return { available: true, command: [pinned], passthroughPin: true, source: "PLATFORM_TEST_DOCKER_COMPOSE_BIN" };
  }
  const probe = spawnSync("docker", ["compose", "version", "--short"], {
    encoding: "utf8",
    timeout: 15_000,
  });
  if (probe.status !== 0) {
    return { available: false, reason: "docker compose CLI plugin is unavailable on this host" };
  }
  const version = String(probe.stdout ?? "").trim();
  if (!/^v?5\.3\./.test(version)) {
    return { available: false, reason: `docker compose version ${version || "<unknown>"} is not the pinned 5.3.x renderer` };
  }
  return { available: true, command: ["docker", "compose"], passthroughPin: false, source: "docker compose plugin" };
}

function wrapperCallerEnvironment(fixture, topology) {
  const environment = stripRepoEnvironment(process.env);
  if (composeCapability.available && composeCapability.passthroughPin) {
    environment.PLATFORM_TEST_DOCKER_COMPOSE_BIN = process.env.PLATFORM_TEST_DOCKER_COMPOSE_BIN;
  }
  environment.COMPOSE_ENV_FILE = fixture.envFile;
  environment.GREENFIELD_TOPOLOGY = topology;
  environment.PLATFORM_SECRETS_ROOT = fixture.secretsRoot;
  environment.CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_SECRET_FILE = fixture.tokenFile;
  environment.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE = fixture.clientSecretFile;
  environment.PLATFORM_STATE_DIR = fixture.stateDir;
  environment.PHP_PROJECTS_DIR = fixture.projectsDir;
  environment.PLATFORM_CERTS_DIR = fixture.certsDir;
  environment.WAF_TLS_KEY_GID = "101";
  // Canonical broker trust-input mount strings (runtime-isolation policy pins
  // the /srv/platform/trust/ prefix); render-only, no files are created.
  environment.DOCKER_ACTION_RUNTIME_INTENT_FILE = "/srv/platform/trust/runtime-intent.json";
  environment.DOCKER_ACTION_ACTIVE_RECEIPT_FILE = "/srv/platform/trust/active-receipt.json";
  environment.DOCKER_ACTION_RUNTIME_INTENT_ID = `greenfield-matrix-intent-${topology.toLowerCase()}`;
  environment.DOCKER_ACTION_ACTIVE_RECEIPT_SHA256 = deterministicDigest(`receipt:${topology}`);
  return environment;
}

function runWrapperConfig(fixture, topology) {
  return spawnSync("bash", [WRAPPER_PATH, "config", "--format", "json"], {
    cwd: ROOT_DIR,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    timeout: 120_000,
    env: wrapperCallerEnvironment(fixture, topology),
  });
}

function runPolicyCli(renderPath, envSnapshotPath, lockPath, workspaceRoot) {
  return spawnSync(process.execPath, [
    POLICY_CLI_PATH,
    "--root",
    ROOT_DIR,
    "--lock",
    lockPath,
    "--config",
    renderPath,
    "--env",
    envSnapshotPath,
  ], {
    cwd: workspaceRoot ?? ROOT_DIR,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    timeout: 60_000,
  });
}

function parsePolicyViolations(result) {
  if (result.status === 0) return [];
  const stderr = String(result.stderr ?? "");
  const marker = "greenfield semantic authority rejected: ";
  const line = stderr.split(/\r?\n/).find((candidate) => candidate.startsWith(marker));
  if (!line) return null;
  return line.slice(marker.length).trim().split(",").filter((entry) => entry.length > 0);
}

const composeCapability = detectComposeCapability();

const renderState = {
  attempted: false,
  fixture: null,
  parallel: null,
  cutover: null,
  namespaceViolations: null,
  policyResult: null,
};

function loadRenderState() {
  if (renderState.attempted) return renderState;
  renderState.attempted = true;
  if (!composeCapability.available) return renderState;
  renderState.fixture = createComposeFixtureWorkspace();
  for (const topology of ["PARALLEL", "CUTOVER"]) {
    const wrapperResult = runWrapperConfig(renderState.fixture, topology);
    if (wrapperResult.status !== 0) {
      // No harness-side recovery exists on purpose: a wrapper defect must
      // fail the matrix loudly instead of being papered over by a
      // test-constructed substitute envelope.
      renderState[topology.toLowerCase()] = {
        ok: false,
        stage: "wrapper",
        status: wrapperResult.status,
        stderr: String(wrapperResult.stderr ?? ""),
      };
      continue;
    }
    let envelope;
    try {
      envelope = JSON.parse(wrapperResult.stdout);
    } catch (error) {
      renderState[topology.toLowerCase()] = {
        ok: false,
        stage: "wrapper-envelope-parse",
        status: wrapperResult.status,
        stderr: `canonical envelope is not one JSON document: ${error.message}`,
      };
      continue;
    }
    renderState[topology.toLowerCase()] = {
      ok: true,
      pipeline: "wrapper",
      envelope,
    };
  }
  if (renderState.parallel?.ok) {
    renderState.namespaceViolations = evaluateGreenfieldNamespace(
      renderState.parallel.envelope.config,
    );
    fs.writeFileSync(
      path.join(renderState.fixture.root, "render-PARALLEL.json"),
      `${JSON.stringify(renderState.parallel.envelope.config)}\n`,
      { mode: 0o600 },
    );
    renderState.policyResult = runPolicyCli(
      path.join(renderState.fixture.root, "render-PARALLEL.json"),
      renderState.fixture.policyEnvFile,
      GREENFIELD_LOCK_PATH,
    );
  }
  return renderState;
}

function requireHealthyParallelRender() {
  const state = loadRenderState();
  if (!state.parallel?.ok) {
    throw new Error(
      `canonical PARALLEL render failed at stage ${state.parallel?.stage ?? "unknown"} (exit ${state.parallel?.status ?? "?"}): ${state.parallel?.stderr ?? ""}`,
    );
  }
  return state;
}

function physicalNamesInRender(config) {
  const physical = [];
  for (const definition of Object.values(config.services ?? {})) {
    if (definition && typeof definition.container_name === "string") {
      physical.push(definition.container_name);
    }
  }
  for (const kind of ["configs", "networks", "secrets", "volumes"]) {
    for (const declaration of Object.values(config[kind] ?? {})) {
      if (declaration && typeof declaration.name === "string") {
        physical.push(declaration.name);
      }
    }
  }
  return physical;
}

function wafPublishedPorts(config) {
  const ports = config.services?.waf?.ports ?? [];
  return ports.map((port) => String(typeof port === "string" ? port : port.published ?? ""));
}

describe("A) RENDER TOPOLOGY (real Compose render, offline)", () => {
  matrixTest("wrapper refuses a caller-selected brownfield network prefix", () => {
    const environment = stripRepoEnvironment(process.env);
    environment.GREENFIELD_TOPOLOGY = "PARALLEL";
    environment.PLATFORM_NETWORK_PREFIX = "platform_infra_vps";
    const result = spawnSync("bash", [WRAPPER_PATH, "config", "--format", "json"], {
      cwd: ROOT_DIR,
      encoding: "utf8",
      timeout: 30_000,
      env: environment,
    });
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /PLATFORM_NETWORK_PREFIX/);
    assert.match(result.stderr, /platform_infra_greenfield/);
  });

  matrixTest("wrapper refuses a legacy brownfield MariaDB data volume", () => {
    const environment = stripRepoEnvironment(process.env);
    environment.GREENFIELD_TOPOLOGY = "PARALLEL";
    environment.MARIADB_DATA_VOLUME = "enterprise_mariadb_data";
    const result = spawnSync("bash", [WRAPPER_PATH, "config", "--format", "json"], {
      cwd: ROOT_DIR,
      encoding: "utf8",
      timeout: 30_000,
      env: environment,
    });
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /MARIADB_DATA_VOLUME/);
    assert.match(result.stderr, /greenfield_mariadb_data/);
  });

  matrixTest("hostile handcrafted render naming a brownfield container is rejected by the policy CLI", () => {
    const workspace = makeTempRoot("greenfield-matrix-hostile-");
    const hostile = {
      name: GREENFIELD_PROJECT_NAME,
      services: {
        postgres: { container_name: "enterprise-postgres" },
      },
      configs: {},
      networks: {},
      secrets: {},
      volumes: {},
    };
    const configPath = path.join(workspace, "hostile-render.json");
    const envPath = path.join(workspace, "environment.env");
    fs.writeFileSync(configPath, `${JSON.stringify(hostile)}\n`);
    fs.writeFileSync(envPath, `PLATFORM_SECRETS_ROOT=/srv/platform-infrastructure/greenfield/secrets\n`);
    const result = runPolicyCli(configPath, envPath, GREENFIELD_LOCK_PATH, workspace);
    assert.equal(result.status, 65, result.stderr);
    assert.match(result.stderr, /service:postgres:container-name:brownfield/);
  });

  const composeSkip = composeCapability.available ? false : COMPOSE_UNAVAILABLE_SKIP;

  matrixTest(
    "PARALLEL render projects the canonical greenfield envelope",
    { skip: composeSkip },
    () => {
      const state = requireHealthyParallelRender();
      const envelope = state.parallel.envelope;
      assert.equal(envelope.projectName, GREENFIELD_PROJECT_NAME);
      assert.equal(envelope.version, 1);
      assert.equal(envelope.topology, "PARALLEL");
      assert.equal(envelope.config.name, GREENFIELD_PROJECT_NAME);
      assert.equal(envelope.lockSha256, sha256File(GREENFIELD_LOCK_PATH));
      const services = envelope.config.services ?? {};
      assert.ok(Object.keys(services).length >= 20, "expected the active core service set");
      for (const [service, definition] of Object.entries(services)) {
        assert.match(
          String(definition.container_name),
          /^gf-/,
          `service ${service} container_name must live in the gf- namespace`,
        );
      }
      for (const physical of physicalNamesInRender(envelope.config)) {
        assert.doesNotMatch(
          physical,
          /^enterprise[-_]/,
          `brownfield physical name leaked into the greenfield render: ${physical}`,
        );
        assert.doesNotMatch(physical, /^platform_infra_vps_/);
      }
      for (const declaration of Object.values(envelope.config.networks ?? {})) {
        assert.match(
          String(declaration.name),
          /^platform_infra_greenfield_/,
          `network physical name escaped the greenfield project namespace: ${declaration.name}`,
        );
      }
      for (const [logical, declaration] of Object.entries(envelope.config.volumes ?? {})) {
        assert.match(
          String(declaration.name),
          /^greenfield_/,
          `volume ${logical} must project onto a greenfield_ physical volume`,
        );
        assert.notEqual(declaration.external, true);
      }
      const published = wafPublishedPorts(envelope.config);
      assert.ok(published.includes("18080"), `expected WAF http 18080, got ${published}`);
      assert.ok(published.includes("18443"), `expected WAF https 18443, got ${published}`);
      for (const auxiliary of GREENFIELD_AUXILIARY_SERVICES) {
        const definition = services[auxiliary];
        // The canonical LOCAL_PRIVATE render profile-prunes every auxiliary
        // service; their presence at all in the active render is a violation
        // (READY_BUT_DISABLED must stay disabled), pinned gf-* names are
        // additionally asserted by the namespace unit suite.
        assert.equal(
          definition,
          undefined,
          `auxiliary service ${auxiliary} must stay pruned from the active render`,
        );
      }
    },
  );

  const parallelState = composeCapability.available ? loadRenderState() : null;

  matrixTest(
    "evaluateGreenfieldNamespace accepts the canonical PARALLEL render",
    { skip: composeSkip },
    () => {
      const state = requireHealthyParallelRender();
      const violations = evaluateGreenfieldNamespace(state.parallel.envelope.config);
      assert.deepEqual(violations, []);
    },
  );

  matrixTest(
    "greenfield-core-policy CLI accepts the canonical PARALLEL render, lock and env snapshot",
    { skip: composeSkip },
    () => {
      const state = requireHealthyParallelRender();
      const result = runPolicyCli(
        path.join(state.fixture.root, "render-PARALLEL.json"),
        state.fixture.policyEnvFile,
        GREENFIELD_LOCK_PATH,
      );
      assert.equal(result.status, 0, result.stderr);
      const payload = JSON.parse(result.stdout);
      assert.deepEqual(payload.violations, []);
    },
  );

  matrixTest(
    "tampered core policy self-digest in the lock fails the policy CLI closed",
    { skip: composeSkip },
    () => {
      const state = requireHealthyParallelRender();
      const lock = JSON.parse(fs.readFileSync(GREENFIELD_LOCK_PATH, "utf8"));
      const flipped = lock.coreSemanticPolicy.sha256.startsWith("f")
        ? `0${lock.coreSemanticPolicy.sha256.slice(1)}`
        : `f${lock.coreSemanticPolicy.sha256.slice(1)}`;
      lock.coreSemanticPolicy.sha256 = flipped;
      const workspace = makeTempRoot("greenfield-matrix-tamperedlock-");
      const lockPath = path.join(workspace, "tampered.lock.json");
      const renderPath = path.join(workspace, "render.json");
      const envPath = path.join(workspace, "environment.env");
      fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
      fs.writeFileSync(renderPath, `${JSON.stringify(requireHealthyParallelRender().parallel.envelope.config)}\n`);
      fs.writeFileSync(envPath, `PLATFORM_SECRETS_ROOT=${state.fixture.secretsRoot}\n`);
      const result = runPolicyCli(renderPath, envPath, lockPath, workspace);
      assert.equal(result.status, 65, result.stderr);
      assert.match(result.stderr, /policy-binding/);
    },
  );

  matrixTest(
    "CUTOVER render takes over the canonical edge ports and diverges from PARALLEL",
    { skip: composeSkip },
    () => {
      const state = requireHealthyParallelRender();
      if (!state.cutover?.ok) {
        throw new Error(
          `canonical CUTOVER render failed at stage ${state.cutover?.stage ?? "unknown"} (exit ${state.cutover?.status ?? "?"}): ${state.cutover?.stderr ?? ""}`,
        );
      }
      const cutover = state.cutover.envelope;
      assert.equal(cutover.topology, "CUTOVER");
      assert.equal(cutover.projectName, GREENFIELD_PROJECT_NAME);
      const published = wafPublishedPorts(cutover.config);
      assert.ok(published.includes("80"), `expected WAF http 80 after cutover, got ${published}`);
      assert.ok(published.includes("443"), `expected WAF https 443 after cutover, got ${published}`);
      assert.notEqual(cutover.renderSha256, state.parallel.envelope.renderSha256);
      assert.notEqual(
        sha256Bytes(Buffer.from(`${JSON.stringify(cutover)}\n`)),
        sha256Bytes(Buffer.from(`${JSON.stringify(state.parallel.envelope)}\n`)),
      );
    },
  );
});

function preservationManifestFixture() {
  return {
    schema: "platform.v1-greenfield-preservation-manifest/v1",
    capturedAtUtc: "2026-08-25T21:15:00Z",
    sourceHost: "platform-infrastructure (Ubuntu)",
    manifestSha256: deterministicDigest("preservation-manifest"),
    brownfieldRuntime: {
      composeProject: "platform_infra_vps",
      containersTotal: 35,
      containersRunning: 34,
    },
    namedVolumesMeasured: {
      enterprise_postgres_data: "90M",
      enterprise_mariadb_data: "224M",
      enterprise_keycloak_data: "24K",
      enterprise_minio_data: "104K",
      enterprise_redis_data: "32M",
    },
    anonymousVolumesCountApprox: 135,
    networks: ["enterprise_net"],
    hostStateTrees: {
      "/home/platform_infrastructure/src": {
        size: "1.5G",
        projects: ["anniversary", "opstudents", "stexor", "stream"],
      },
      "/home/platform_infrastructure/platform-infrastructure/projects-portal/state": {
        size: "916K",
        keyFiles: ["projects.json", "operations.jsonl"],
      },
      "/home/platform_infrastructure/platform-infrastructure/secrets": {
        size: "220K",
        fileCount_txt: 37,
        storeJsonBytes: 19072,
      },
      "/home/platform_infrastructure/platform-infrastructure/backups": {
        apparentSize: "29G",
        families: ["postgres/*.dump", "mariadb/*.sql.gz", "minio/*.tar.gz"],
        schedulerActive: true,
      },
    },
    activeReceiptSha256: deterministicDigest("active-receipt"),
  };
}

describe("B) PROJECTIONS (pure planning authorities)", () => {
  matrixTest("state projection plan validates clean and serializes byte-stable", () => {
    const plan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
    assert.deepEqual(validateStateProjectionPlan(plan), []);
    const firstSerialization = serializeProjectionPlan(plan);
    const secondPlan = buildStateProjectionPlan({ manifest: preservationManifestFixture() });
    assert.equal(serializeProjectionPlan(secondPlan), firstSerialization);
    for (const entry of plan.entries) {
      if (entry.target.kind === "volume") {
        assert.match(entry.target.ref, /^greenfield_/, entry.entryId);
      }
      assert.doesNotMatch(entry.target.ref, /^enterprise[-_]/, entry.entryId);
    }
    const writerIds = plan.writersCoveredByFinalSync;
    assert.deepEqual([...writerIds].sort(), finalSyncWriterRegistry().map((writer) => writer.writerId).sort());
  });

  const secretPlan = buildSecretProjectionPlan({
    greenfieldSecretsRoot: GREENFIELD_SECRETS_ROOT,
  });

  function faithfulObservation() {
    const observed = [];
    for (const entry of secretPlan.entries) {
      observed.push({
        logicalName: entry.logicalName,
        sha256: entry.expectedSha256,
        sizeBytes: 128,
        mode: entry.requiredMode,
      });
    }
    for (const entry of secretPlan.additionalMaterial) {
      observed.push({
        logicalName: entry.logicalName,
        sha256: entry.expectedSha256 ?? deterministicDigest(`observed:${entry.logicalName}`),
        sizeBytes: typeof entry.sizeBytes === "number" ? entry.sizeBytes : 256,
        mode: entry.requiredMode,
      });
    }
    return observed.sort((left, right) => (left.logicalName < right.logicalName ? -1 : 1));
  }

  matrixTest("faithful secret observation verifies MATCH; hostiles fail closed", () => {
    const faithful = verifyObservedSecretSet({ plan: secretPlan, observed: faithfulObservation() });
    assert.equal(faithful.status, "MATCH");
    assert.deepEqual(faithful.violations, []);

    const missingOne = faithfulObservation();
    missingOne.splice(missingOne.findIndex((entry) => entry.logicalName === "smtp_password"), 1);
    const missingResult = verifyObservedSecretSet({ plan: secretPlan, observed: missingOne });
    assert.equal(missingResult.status, "FAIL");
    assert.ok(
      missingResult.violations.some((violation) => violation.entry === "smtp_password" && violation.reason === "missing"),
      JSON.stringify(missingResult.violations),
    );

    const withExtra = [...faithfulObservation(), { logicalName: "bogus_extra_material", sha256: deterministicDigest("bogus"), sizeBytes: 1, mode: null }];
    const extraResult = verifyObservedSecretSet({ plan: secretPlan, observed: withExtra });
    assert.equal(extraResult.status, "FAIL");
    assert.ok(extraResult.violations.some((violation) => violation.entry === "bogus_extra_material" && violation.reason === "extra"));

    const flipped = faithfulObservation();
    const flippedTarget = flipped.find((entry) => entry.logicalName === "redis_password");
    flippedTarget.sha256 = deterministicDigest("flipped-redis-password");
    const flippedResult = verifyObservedSecretSet({ plan: secretPlan, observed: flipped });
    assert.equal(flippedResult.status, "FAIL");
    assert.ok(flippedResult.violations.some((violation) => violation.entry === "redis_password" && violation.reason === "digest-altered"));
  });

  matrixTest("secret receipt carries metadata only and passes the leak guard", () => {
    const faithful = verifyObservedSecretSet({ plan: secretPlan, observed: faithfulObservation() });
    const receipt = buildSecretReceipt({
      plan: secretPlan,
      verifyResult: faithful,
      runId: "greenfield-offline-matrix-run-1",
    });
    assert.deepEqual(
      Object.keys(receipt).sort(),
      ["counts", "entries", "runId", "schema", "status"],
    );
    const serialized = JSON.stringify(receipt);
    assert.equal(assertNoSecretMaterialization(serialized), true, serialized);
    assert.doesNotMatch(serialized, /[A-Za-z0-9+/]{40,}/);
    for (const entry of receipt.entries) {
      assert.deepEqual(Object.keys(entry).sort(), ["logicalName", "mode", "sha256Matched"]);
      assert.equal(typeof entry.sha256Matched, "boolean");
    }
  });

  const ALL_FAMILIES = Object.freeze([
    "postgres-stexor",
    "postgres-keycloak",
    "mariadb",
    "minio",
    "app-bind-trees",
    "control-center-state",
  ]);

  matrixTest("backup/restore plans round-trip; fingerprints classify MATCH/DELTA/FAIL", () => {
    const capture = buildCapturePlan({
      families: [...ALL_FAMILIES],
      outputRoot: "/var/tmp/greenfield-matrix-captures",
      runId: "matrix-capture-1",
    });
    const restore = buildRestorePlan({ captureReceipt: capture });
    assert.equal(restore.kind, "restore");
    assert.equal(restore.runId, capture.runId);
    assert.deepEqual(
      restore.entries.map((entry) => entry.family),
      capture.entries.map((entry) => entry.family),
    );

    const fingerprint = (family, items) => ({ family, items });
    const pre = fingerprint("postgres-stexor", [{ id: "public.jobs", count: 3, digest: "aa", size: 12 }]);
    assert.equal(compareFingerprints({ pre, post: structuredClone(pre) }).status, "MATCH");
    const drifted = structuredClone(pre);
    drifted.items[0].count = 4;
    const delta = compareFingerprints({ pre, post: drifted });
    assert.equal(delta.status, "DELTA");
    assert.equal(delta.deltas.length, 1);
    const lost = structuredClone(pre);
    lost.items = [];
    const failure = compareFingerprints({ pre, post: lost });
    assert.equal(failure.status, "FAIL");
    assert.equal(compareFingerprints({ pre, post: { family: "other", items: [] } }).status, "FAIL");
  });

  matrixTest("capture step execution fails closed without Docker and receipts stay whitelisted", () => {
    assert.throws(
      () => executeCaptureStep(
        { family: "app-bind-trees", runId: "offline", command: "true", artifactNames: [] },
        { dockerCheck: () => ({ available: false, reason: "no engine in the offline matrix" }) },
      ),
      (error) => /requires Docker/.test(error.message),
    );
    const receipt = executeCaptureStep(
      { family: "app-bind-trees", runId: "offline-ok", command: "true", artifactNames: ["app-state-x.tar.gz"] },
      { dockerCheck: () => ({ available: true }) },
    );
    assert.deepEqual(
      Object.keys(receipt).every((key) => ["schema", "kind", "family", "runId", "exitCode", "artifactNames", "durationMs"].includes(key)),
      true,
    );
    assert.equal(receipt.exitCode, 0);
  });

  matrixTest("final sync sequence phases cover the registry writers deterministically", () => {
    const sequence = buildFinalSyncSequence();
    assert.deepEqual(
      sequence.phases.map((phase) => phase.phase),
      [
        "QUIESCE_WRITERS",
        "FINAL_CAPTURE",
        "VERIFY_CAPTURE",
        "RESTORE_FINAL",
        "VERIFY_DELTA",
        "RESUME_OR_CUTOVER",
      ],
    );
    const registryIds = finalSyncWriterRegistry().map((writer) => writer.writerId).sort();
    for (const phase of sequence.phases) {
      assert.deepEqual(phase.writers.map((writer) => writer.writerId).sort(), registryIds);
    }
    assert.deepEqual(validateDeltaZero({
      preCutoverFingerprints: [{ family: "mariadb", items: [{ id: "wp.posts", count: 9 }] }],
      postRestoreFingerprints: [{ family: "mariadb", items: [{ id: "wp.posts", count: 9 }] }],
    }), []);
    const violations = validateDeltaZero({
      preCutoverFingerprints: [{ family: "postgres-stexor", items: [{ id: "public.jobs", count: 3 }] }],
      postRestoreFingerprints: [{ family: "postgres-stexor", items: [{ id: "public.jobs", count: 4 }] }],
    });
    assert.equal(violations.length, 1);
    assert.equal(violations[0].writerId, "postgres-stexor");
    assert.equal(serializeFinalSyncPlan(sequence), serializeFinalSyncPlan(buildFinalSyncSequence()));
  });
});

const pythonProbe = spawnSync("python3", ["-c", "print('ok')"], { encoding: "utf8", timeout: 15_000 });
const pythonAvailable = pythonProbe.status === 0;
const PYTHON_SKIP = "python3 unavailable on this host";

const TRANSACTION_ENV_KEYS = {
  journal: "PLATFORM_GREENFIELD_TRANSACTION_JOURNAL",
  executor: "PLATFORM_GREENFIELD_STEP_EXECUTOR",
  commit: "PLATFORM_RUNTIME_CANDIDATE_COMMIT",
  tree: "PLATFORM_RUNTIME_CANDIDATE_TREE",
  fullRun: "PLATFORM_GREENFIELD_ALLOW_FULL_RUN",
  executorConfig: "PLATFORM_TEST_GREENFIELD_EXECUTOR_CONFIG",
};
const COMMIT_A = "a".repeat(40);
const TREE_A = "b".repeat(40);
const COMMIT_B = "c".repeat(40);
const TREE_B = "d".repeat(40);

function transactionFixture(t) {
  const root = makeTempRoot("greenfield-matrix-tx-");
  after(() => {
    try {
      const pidFile = path.join(root, "executor.pid");
      if (fs.existsSync(pidFile)) {
        process.kill(Number(fs.readFileSync(pidFile, "utf8")), "SIGKILL");
      }
    } catch {}
  });
  const journalDir = path.join(root, "transaction");
  const journal = path.join(journalDir, "journal.jsonl");
  const executorPath = path.join(root, "step-executor.cjs");
  const executorBody = `#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { raw += chunk; });
process.stdin.on("end", () => {
  const request = JSON.parse(raw);
  const configPath = process.env[${JSON.stringify(TRANSACTION_ENV_KEYS.executorConfig)}];
  const config = configPath ? JSON.parse(fs.readFileSync(configPath, "utf8")) : {};
  if (config.pidFile) {
    try { fs.writeFileSync(config.pidFile, String(process.pid)); } catch {}
  }
  const failStates = config.failStates || {};
  if (Object.prototype.hasOwnProperty.call(failStates, request.state)) {
    process.stderr.write("injected failure for " + request.state + "\\n");
    process.exit(failStates[request.state]);
  }
  if ((config.sleepStates || []).includes(request.state)) {
    setTimeout(() => process.exit(0), 120000);
    return;
  }
  process.stdout.write(JSON.stringify({ outputs: {
    note: request.state + "-ok",
    observedProject: String(request.context.project),
    observedAttempt: String(request.context.attempt),
  } }) + "\\n");
});
`;
  fs.writeFileSync(executorPath, executorBody, { mode: 0o755 });
  const configPath = path.join(root, "executor-config.json");
  fs.writeFileSync(configPath, "{}");
  return { root, journalDir, journal, executorPath, configPath };
}

function writeExecutorConfig(fixture_, config) {
  fs.writeFileSync(fixture_.configPath, JSON.stringify(config));
}

function runTransaction(fixture_, arguments_, extraEnvironment = {}, { includeExecutor = true } = {}) {
  const environment = stripRepoEnvironment(process.env);
  environment[TRANSACTION_ENV_KEYS.journal] = fixture_.journal;
  environment[TRANSACTION_ENV_KEYS.commit] = COMMIT_A;
  environment[TRANSACTION_ENV_KEYS.tree] = TREE_A;
  if (includeExecutor) {
    environment[TRANSACTION_ENV_KEYS.executor] = fixture_.executorPath;
    environment[TRANSACTION_ENV_KEYS.executorConfig] = fixture_.configPath;
  }
  Object.assign(environment, extraEnvironment);
  return spawnSync("python3", [TRANSACTION_SCRIPT_PATH, ...arguments_], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    timeout: 120_000,
    env: environment,
  });
}

function journalRecords(journalPath) {
  return fs.readFileSync(journalPath, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line));
}

describe("C) TRANSACTION (delegated state machine)", () => {
  matrixTest("source stays delegation-only and names its step-executor authority", () => {
    const source = fs.readFileSync(TRANSACTION_SCRIPT_PATH, "utf8");
    for (const forbidden of ["docker", "ssh ", "rm -rf", "prune", "enterprise-traefik"]) {
      assert.ok(!source.includes(forbidden), `transaction source must not contain "${forbidden}"`);
    }
    assert.ok(source.includes("PLATFORM_GREENFIELD_STEP_EXECUTOR"));
  });

  matrixTest(
    "PREPARE..READY_FOR_FINAL_SYNC chains receipts that verify-journal accepts",
    { skip: pythonAvailable ? false : PYTHON_SKIP },
    (t) => {
      const fx = transactionFixture(t);
      const result = runTransaction(fx, [
        "run",
        "--from",
        "PREPARE",
        "--stop-after",
        "READY_FOR_FINAL_SYNC",
      ]);
      assert.equal(result.status, 0, result.stderr);
      const summary = JSON.parse(result.stdout);
      assert.equal(summary.stopAfter, "READY_FOR_FINAL_SYNC");
      assert.equal(summary.pointOfNoReturnCrossed, false);
      assert.equal(summary.receivedCount, 9);

      const verified = runTransaction(fx, ["verify-journal"]);
      assert.equal(verified.status, 0, verified.stderr);
      const verdict = JSON.parse(verified.stdout);
      assert.equal(verdict.ok, true);
      assert.equal(verdict.records, 18);
      const records = journalRecords(fx.journal);
      assert.equal(records[0].prevRecordSha256, "0".repeat(64));
      assert.ok(records.every((record) => typeof record.prevRecordSha256 === "string"));
    },
  );

  matrixTest(
    "a crashed FINAL_CAPTURE is ambiguous for run (87) and recoverable via reconcile attempt 2",
    { skip: pythonAvailable ? false : PYTHON_SKIP },
    async (t) => {
      const fx = transactionFixture(t);
      writeExecutorConfig(fx, { sleepStates: ["FINAL_CAPTURE"], pidFile: path.join(fx.root, "executor.pid") });
      let prepared = runTransaction(fx, ["run", "--stop-after", "VERIFY"]);
      assert.equal(prepared.status, 0, prepared.stderr);

      const child = spawn("python3", [TRANSACTION_SCRIPT_PATH, "run", "--stop-after", "FINAL_CAPTURE"], {
        env: (() => {
          const environment = stripRepoEnvironment(process.env);
          environment[TRANSACTION_ENV_KEYS.journal] = fx.journal;
          environment[TRANSACTION_ENV_KEYS.commit] = COMMIT_A;
          environment[TRANSACTION_ENV_KEYS.tree] = TREE_A;
          environment[TRANSACTION_ENV_KEYS.executor] = fx.executorPath;
          environment[TRANSACTION_ENV_KEYS.executorConfig] = fx.configPath;
          return environment;
        })(),
        stdio: ["ignore", "ignore", "pipe"],
      });
      let crashStderr = "";
      child.stderr.on("data", (chunk) => {
        crashStderr += chunk;
      });
      const deadline = Date.now() + 20_000;
      let danglingVisible = false;
      while (Date.now() < deadline) {
        try {
          danglingVisible = journalRecords(fx.journal)
            .some((record) => record.state === "FINAL_CAPTURE" && record.status === "ENTERED");
        } catch {}
        if (danglingVisible) break;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
      }
      assert.ok(danglingVisible, `FINAL_CAPTURE never entered the journal: ${crashStderr}`);
      child.kill("SIGKILL");
      await new Promise((resolve) => child.once("exit", resolve));
      try {
        process.kill(Number(fs.readFileSync(path.join(fx.root, "executor.pid"), "utf8")), "SIGKILL");
      } catch {}

      const recordsBefore = journalRecords(fx.journal);
      assert.equal(recordsBefore[recordsBefore.length - 1].status, "ENTERED");
      assert.equal(fs.existsSync(path.join(fx.journalDir, "FINAL_CAPTURE-receipt.json")), false);

      const refused = runTransaction(fx, ["run", "--stop-after", "FINAL_CAPTURE"]);
      assert.equal(refused.status, 87, refused.stderr);
      assert.match(refused.stderr, /FINAL_CAPTURE/);
      assert.match(refused.stderr, /reconcile/);
      assert.equal(journalRecords(fx.journal).length, recordsBefore.length);

      writeExecutorConfig(fx, {});
      const recovered = runTransaction(fx, ["reconcile", "--stop-after", "FINAL_CAPTURE"]);
      assert.equal(recovered.status, 0, recovered.stderr);
      const receipt = JSON.parse(fs.readFileSync(path.join(fx.journalDir, "FINAL_CAPTURE-receipt.json"), "utf8"));
      assert.equal(receipt.outputs.attempt, "2");
      assertVerifiedJournal(fx);
    },
  );

  function assertVerifiedJournal(fx) {
    const verified = runTransaction(fx, ["verify-journal"]);
    assert.equal(verified.status, 0, verified.stderr);
    assert.equal(JSON.parse(verified.stdout).ok, true);
  }

  matrixTest(
    "full machine reaches sealed GO; post-seal mutations refuse 89 and rollback refuses 86",
    { skip: pythonAvailable ? false : PYTHON_SKIP },
    (t) => {
      const fx = transactionFixture(t);
      let result = runTransaction(fx, ["run", "--stop-after", "READY_FOR_FINAL_SYNC"]);
      assert.equal(result.status, 0, result.stderr);
      result = runTransaction(fx, ["run", "--stop-after", "GO"], {
        [TRANSACTION_ENV_KEYS.fullRun]: "1",
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).sealed, true);

      result = runTransaction(fx, ["rollback"]);
      assert.equal(result.status, 86, result.stderr);
      assert.match(result.stderr, /point of no return/i);
      result = runTransaction(fx, ["reconcile"]);
      assert.equal(result.status, 89, result.stderr);
      result = runTransaction(fx, ["run"]);
      assert.equal(result.status, 89, result.stderr);
      assert.match(result.stderr, /sealed/i);
      const records = journalRecords(fx.journal);
      const seal = records[records.length - 1];
      assert.equal(seal.state, "JOURNAL_SEALED");
      assert.equal(seal.status, "SEALED");
      assertVerifiedJournal(fx);
    },
  );

  matrixTest(
    "fresh journal stopped pre-CUTOVER rolls back cleanly and terminates ROLLED_BACK",
    { skip: pythonAvailable ? false : PYTHON_SKIP },
    (t) => {
      const fx = transactionFixture(t);
      let result = runTransaction(fx, ["run", "--stop-after", "POST"]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).pointOfNoReturnCrossed, false);

      result = runTransaction(fx, ["rollback"]);
      assert.equal(result.status, 0, result.stderr);
      const summary = JSON.parse(result.stdout);
      assert.equal(summary.rolledBack, true);
      assert.equal(summary.completedStates.length, 14);
      const status = JSON.parse(runTransaction(fx, ["status"]).stdout);
      assert.equal(status.terminalStatus, "ROLLED_BACK");
      assert.equal(status.rolledBack, true);

      result = runTransaction(fx, ["run"]);
      assert.equal(result.status, 85, result.stderr);
      assert.match(result.stderr, /ROLLED_BACK/);
      assertVerifiedJournal(fx);
    },
  );

  matrixTest(
    "resume with different candidate authority is refused as drift (88)",
    { skip: pythonAvailable ? false : PYTHON_SKIP },
    (t) => {
      const fx = transactionFixture(t);
      let result = runTransaction(fx, ["run", "--stop-after", "BUILD"]);
      assert.equal(result.status, 0, result.stderr);
      result = runTransaction(fx, ["run", "--stop-after", "BUILD"], {
        [TRANSACTION_ENV_KEYS.commit]: COMMIT_B,
        [TRANSACTION_ENV_KEYS.tree]: TREE_B,
      });
      assert.equal(result.status, 88, result.stderr);
      assert.match(result.stderr, /authority drift/i);
      result = runTransaction(fx, ["rollback"], {
        [TRANSACTION_ENV_KEYS.commit]: COMMIT_B,
        [TRANSACTION_ENV_KEYS.tree]: TREE_B,
      });
      assert.equal(result.status, 88, result.stderr);
      assertVerifiedJournal(fx);
    },
  );

  matrixTest(
    "byte-flipped journal fails verify-journal everywhere with 79",
    { skip: pythonAvailable ? false : PYTHON_SKIP },
    (t) => {
      const fx = transactionFixture(t);
      let result = runTransaction(fx, ["run", "--stop-after", "VERIFY"]);
      assert.equal(result.status, 0, result.stderr);
      const lines = fs.readFileSync(fx.journal, "utf8").split("\n");
      assert.ok(lines[4].includes('"seq":5'));
      lines[4] = lines[4].replace('"seq":5', '"seq":6');
      fs.writeFileSync(fx.journal, lines.join("\n"));
      result = runTransaction(fx, ["verify-journal"]);
      assert.equal(result.status, 79, result.stderr);
      result = runTransaction(fx, ["status"]);
      assert.equal(result.status, 79, result.stderr);
      result = runTransaction(fx, ["rollback"]);
      assert.equal(result.status, 79, result.stderr);
    },
  );
});

describe("D) WORKLOAD BUILDER (exact-main image factory)", () => {
  matrixTest("plan enumerates the eight Dockerfiles and both bash scripts parse", () => {
    const parsed = spawnSync("bash", [WORKLOAD_BUILDER_PATH, "plan"], {
      cwd: ROOT_DIR,
      encoding: "utf8",
      timeout: 15_000,
    });
    assert.equal(parsed.status, 0, parsed.stderr);
    const plan = JSON.parse(parsed.stdout);
    assert.equal(plan.length, 8);
    for (const entry of plan) {
      assert.equal(entry.dockerfile, `docker/${entry.name}.Dockerfile`);
      assert.ok(fs.existsSync(path.join(ROOT_DIR, entry.dockerfile)), entry.dockerfile);
    }
    for (const script of [WORKLOAD_BUILDER_PATH, WRAPPER_PATH]) {
      const syntax = spawnSync("bash", ["-n", script], { encoding: "utf8", timeout: 15_000 });
      assert.equal(syntax.status, 0, syntax.stderr);
    }
  });

  function gitWorktreeIsClean() {
    const status = spawnSync("git", ["status", "--porcelain"], {
      cwd: ROOT_DIR,
      encoding: "utf8",
      timeout: 30_000,
    });
    if (status.status !== 0) return { clean: false, available: false, detail: status.stderr };
    return { clean: String(status.stdout ?? "").trim() === "", available: true, detail: String(status.stdout ?? "") };
  }

  const gitProbe = spawnSync("git", ["--version"], { encoding: "utf8", timeout: 15_000 });
  const gitAvailable = gitProbe.status === 0;
  const worktree = gitAvailable ? gitWorktreeIsClean() : { clean: false, available: false, detail: "git unavailable" };
  const builderSkip = !gitAvailable
    ? "git unavailable on this host"
    : (!worktree.clean ? DIRTY_WORKTREE_SKIP : false);

  function extractHeadContext(destination) {
    const extract = spawnSync("bash", [WORKLOAD_BUILDER_PATH, "build-context", "HEAD", destination], {
      cwd: ROOT_DIR,
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(extract.status, 0, extract.stderr);
  }

  matrixTest(
    "audit-context accepts the exact-main build context",
    { skip: builderSkip },
    (t) => {
      const workspace = makeTempRoot("greenfield-matrix-builder-");
      const context = path.join(workspace, "context");
      extractHeadContext(context);
      const audit = spawnSync("bash", [WORKLOAD_BUILDER_PATH, "audit-context", context], {
        cwd: ROOT_DIR,
        encoding: "utf8",
        timeout: 60_000,
      });
      assert.equal(audit.status, 0, audit.stdout + audit.stderr);
    },
  );

  matrixTest(
    "audit-context rejects every injection class with exit 4",
    { skip: builderSkip },
    (t) => {
      const workspace = makeTempRoot("greenfield-matrix-builder-negatives-");
      const context = path.join(workspace, "context");
      extractHeadContext(context);
      const injections = [
        {
          label: "secrets/x.txt",
          apply: () => {
            fs.mkdirSync(path.join(context, "secrets"), { recursive: true });
            fs.writeFileSync(path.join(context, "secrets", "x.txt"), "leak\n");
          },
          remove: () => fs.unlinkSync(path.join(context, "secrets", "x.txt")),
        },
        {
          label: ".env",
          apply: () => fs.writeFileSync(path.join(context, ".env"), "SECRET=nope\n"),
          remove: () => fs.unlinkSync(path.join(context, ".env")),
        },
        {
          label: "symlink",
          apply: () => fs.symlinkSync("/etc/hostconfig", path.join(context, "dangerous-link")),
          remove: () => fs.unlinkSync(path.join(context, "dangerous-link")),
        },
        {
          label: "fifo",
          apply: () => {
            const created = spawnSync("mkfifo", [path.join(context, "dangerous-fifo")], { encoding: "utf8", timeout: 10_000 });
            assert.equal(created.status, 0, created.stderr);
          },
          remove: () => fs.unlinkSync(path.join(context, "dangerous-fifo")),
        },
        {
          label: "traefik/certs/key.pem",
          apply: () => {
            fs.mkdirSync(path.join(context, "traefik", "certs"), { recursive: true });
            fs.writeFileSync(path.join(context, "traefik", "certs", "key.pem"), "not a key\n");
          },
          remove: () => fs.unlinkSync(path.join(context, "traefik", "certs", "key.pem")),
        },
      ];
      for (const injection of injections) {
        injection.apply();
        const audit = spawnSync("bash", [WORKLOAD_BUILDER_PATH, "audit-context", context], {
          cwd: ROOT_DIR,
          encoding: "utf8",
          timeout: 60_000,
        });
        assert.equal(audit.status, 4, `${injection.label}: expected exit 4, got ${audit.status}`);
        injection.remove();
      }
      const restored = spawnSync("bash", [WORKLOAD_BUILDER_PATH, "audit-context", context], {
        cwd: ROOT_DIR,
        encoding: "utf8",
        timeout: 60_000,
      });
      assert.equal(restored.status, 0, restored.stdout + restored.stderr);
    },
  );

  matrixTest(
    "extracted compose.yaml bytes are bit-identical to git archive HEAD output",
    { skip: builderSkip },
    (t) => {
      const workspace = makeTempRoot("greenfield-matrix-archive-");
      const context = path.join(workspace, "context");
      extractHeadContext(context);
      const archive = spawnSync("git", ["archive", "--format=tar", "HEAD", "compose.yaml"], {
        cwd: ROOT_DIR,
        encoding: "buffer",
        maxBuffer: 32 * 1024 * 1024,
        timeout: 60_000,
      });
      assert.equal(archive.status, 0, archive.stderr);
      const extracted = spawnSync("tar", ["-xO"], {
        encoding: "buffer",
        maxBuffer: 32 * 1024 * 1024,
        timeout: 30_000,
        input: archive.stdout,
      });
      assert.equal(extracted.status, 0, extracted.stderr);
      assert.equal(
        sha256Bytes(extracted.stdout),
        sha256File(path.join(context, "compose.yaml")),
      );
    },
  );
});

describe("E) AUTH BOOTSTRAP (offline planner)", () => {
  const TOKEN_LOGICAL = "control_center_first_configuration_bootstrap_token";
  const CLIENT_SECRET_LOGICAL = "control_center_first_configuration_keycloak_client_secret";

  function happyRenderConfig() {
    const environment = {};
    for (const [key, value] of Object.entries({
      CONTROL_CENTER_ENV: "local_private",
      CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "required",
      CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE: "/run/secrets/control_center_first_configuration_bootstrap_token",
      CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID: "platform-first-configuration",
      CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE: "/run/secrets/control_center_first_configuration_keycloak_client_secret",
      CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME: "admin",
      CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128",
      CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12,127.0.0.0/8,::1/128",
      CONTROL_CENTER_FIRST_CONFIGURATION_ACCOUNT_URL: "https://auth.greenfield.matrix/realms/platform/account/",
      CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_ENDPOINT: "https://auth.greenfield.matrix/realms/platform/protocol/openid-connect/token",
      CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_BASE_URL: "https://auth.greenfield.matrix/admin/realms/platform",
      CONTROL_CENTER_MIN_PASSKEYS: "2",
    })) {
      environment[key] = value;
    }
    return {
      name: GREENFIELD_PROJECT_NAME,
      services: {
        "control-center": {
          container_name: "gf-control-center",
          environment,
          secrets: [TOKEN_LOGICAL, CLIENT_SECRET_LOGICAL],
        },
        keycloak: { container_name: GF_KEYCLOAK_CONTAINER },
      },
      secrets: {
        [TOKEN_LOGICAL]: { file: `${GREENFIELD_SECRETS_ROOT}/${TOKEN_LOGICAL}.txt` },
        [CLIENT_SECRET_LOGICAL]: { file: `${GREENFIELD_SECRETS_ROOT}/${CLIENT_SECRET_LOGICAL}.txt` },
      },
    };
  }

  function happyObservation() {
    return [
      { logicalName: TOKEN_LOGICAL, present: true, sizeBytes: 64 },
      { logicalName: CLIENT_SECRET_LOGICAL, present: true, sizeBytes: 32 },
    ];
  }

  matrixTest("preflight accepts the happy greenfield first-configuration fixture", () => {
    const report = preflightAuthBootstrap({
      renderConfig: happyRenderConfig(),
      secretsObservation: happyObservation(),
    });
    assert.deepEqual(report.violations, []);
    assert.equal(report.ready, true);
  });

  matrixTest("sequence carries exactly the two passkey enrollment human gates", () => {
    const sequence = buildAuthBootstrapSequence();
    const gates = sequence.filter((step) => step.kind === "human-gate");
    assert.deepEqual(gates.map((step) => step.stepId), HUMAN_GATE_STEP_IDS);
    assert.deepEqual(HUMAN_GATE_STEP_IDS, ["ENROLL_PASSKEY_1", "ENROLL_PASSKEY_2"]);
  });

  matrixTest("closure receipt fails closed without the second passkey gate", () => {
    const runLog = buildAuthBootstrapSequence()
      .filter((step) => step.stepId !== "ENROLL_PASSKEY_2")
      .map((step) => step.kind === "automated"
        ? { stepId: step.stepId, evidenceDigest: `evidence-${step.stepId}` }
        : {
          stepId: step.stepId,
          passkeyIndex: 1,
          enrolledAtUtc: "2026-08-26T00:00:00Z",
        });
    const receipt = bootstrapClosureReceipt({ sequenceRunLog: runLog });
    assert.equal(receipt.status, "BOOTSTRAP_NOT_CLOSED");
    assert.equal(receipt.firstConfigurationState, "INCOMPLETE");
    assert.ok(receipt.violations.includes("human-gate:ENROLL_PASSKEY_2:missing"), receipt.violations);
  });

  matrixTest("reconcile invocations target gf-keycloak for both stages", () => {
    for (const stage of ["staged", "bind"]) {
      const invocation = keycloakPasskeyReconcileInvocation({ stage });
      assert.equal(invocation.env.KEYCLOAK_CONTAINER, "gf-keycloak");
      assert.equal(invocation.env.KEYCLOAK_REALM, "platform");
    }
    const bind = keycloakPasskeyReconcileInvocation({ stage: "bind" });
    assert.equal(bind.env.KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED, "true");
  });
});

describe("F) CONTROL PLANE / WORKLOAD SEPARATION (architectural invariant)", () => {
  const composeSkip = composeCapability.available ? false : COMPOSE_UNAVAILABLE_SKIP;
  function separationStateFixture() {
    return {
      hostStateTrees: {
        "/home/platform_infrastructure/src": { projects: ["stexor", "workcalendar", "public"] },
        "/home/platform_infrastructure/platform-infrastructure/projects-portal/state": { size: "916K" },
        "/home/platform_infrastructure/platform-infrastructure/secrets": { size: "220K" },
        "/home/platform_infrastructure/platform-infrastructure/backups": { families: ["a"] },
      },
      anonymousVolumesCountApprox: 135,
    };
  }
  const stateProjectionPlan = buildStateProjectionPlan({ manifest: separationStateFixture() });
  const finalSyncSequence = buildFinalSyncSequence();
  const authBootstrap = buildAuthBootstrapSequence();

  matrixTest(
    "the exported gates are hard-false and every control-plane service is classified",
    () => {
      assert.deepEqual(separationDescriptor, {
        schema: "platform.greenfield-control-plane-separation/v1",
        controlCenterDependsOnStexor: false,
        infrastructureDependsOnStexor: false,
        controlPlaneServiceCount: separationDescriptor.controlPlaneServiceCount,
        workloadServiceCount: separationDescriptor.workloadServiceCount,
      });
      const renderedServices = composeCapability.available && loadRenderState().parallel?.ok
        ? Object.keys(loadRenderState().parallel.envelope.config.services)
        : [];
      for (const service of renderedServices) {
        assert.notEqual(
          serviceDependencyClass(service),
          "unknown",
          `rendered service ${service} must be classified control-plane or workload`,
        );
      }
    },
  );

  matrixTest(
    "the canonical render, state plan, final sync and auth bootstrap satisfy the separation invariant",
    { skip: composeSkip },
    () => {
      const state = requireHealthyParallelRender();
      const violations = evaluateControlPlaneSeparation({
        renderedConfig: state.parallel.envelope.config,
        stateProjectionPlan,
        finalSyncSequence,
        authBootstrap,
      });
      assert.deepEqual(violations, []);
    },
  );

  matrixTest(
    "wiring a workload dependency into the Control Center fails the gate closed",
    () => {
      const hostile = {
        name: GREENFIELD_PROJECT_NAME,
        services: {
          "control-center": {
            container_name: "gf-control-center",
            depends_on: { "php-apache": { condition: "service_healthy" } },
          },
          "php-apache": { container_name: "gf-php-apache" },
        },
      };
      assert.deepEqual(evaluateControlPlaneSeparation({
        renderedConfig: hostile,
        stateProjectionPlan,
        finalSyncSequence,
        authBootstrap,
      }), ["separation:control-center:depends-on-workload:php-apache"]);
    },
  );

  matrixTest(
    "the Stexor passkey stays application-workload state and never enters First Configuration",
    () => {
      for (const entry of stateProjectionPlan.entries) {
        if (entry.entryId === "postgres-stexor" || entry.entryId === "app-src-stexor") {
          assert.equal(entry.classification.startsWith("PRESERVE"), true, entry.entryId);
        }
      }
      const serializedBootstrap = JSON.stringify(authBootstrap);
      assert.ok(!/stexor/i.test(serializedBootstrap), serializedBootstrap);
      // First Configuration materials are exclusively Control Center/Keycloak.
      for (const step of authBootstrap) {
        if (step.kind === "human-gate") {
          assert.match(step.stepId, /ENROLL_PASSKEY_[12]$/, step.stepId);
        }
      }
    },
  );
});

after(() => {
  const outputPath = process.env.PLATFORM_GREENFIELD_MATRIX_OUT;
  if (outputPath) {
    const state = renderState.attempted ? renderState : null;
    const renderTopology = {};
    if (state?.parallel?.ok) renderTopology.parallelRenderSha = state.parallel.envelope.renderSha256;
    if (state?.cutover?.ok) renderTopology.cutoverRenderSha = state.cutover.envelope.renderSha256;
    const payload = {
      schema: "platform.greenfield-offline-matrix/v1",
      startedAt,
      finishedAt: new Date().toISOString(),
      counts: { ...tally },
      ...(Object.keys(renderTopology).length > 0 ? { renderTopology } : {}),
    };
    if (assertNoSecretMaterialization(JSON.stringify(payload))) {
      fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
      fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`);
    } else {
      console.warn("[greenfield-offline-matrix] evidence summary refused by the secret-materialization guard");
    }
  }
  for (const root of tempRoots) {
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 25 });
  }
});
