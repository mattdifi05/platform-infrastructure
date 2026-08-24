import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
const dockerSocketPath = "/var/run/docker.sock";
const pinnedComposeSha256 = "32691ba1196d819fa68cbdc0aad9a5569e730a35ae40c6fdd8458110ecd69488";
const composeAvailability = findComposeCli();
let cachedCanonicalRender;

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

test("the standard and LOCAL_PRIVATE canonical Compose orders are derived from compose-vps.sh", () => {
  const wrapper = read("scripts/compose-vps.sh");
  const files = canonicalComposeFiles(wrapper);

  assert.ok(files.length > 1, "compose-vps.sh must provide a non-empty ordered overlay set");
  assert.equal(files[0], "compose.yaml");
  assert.ok(files.includes("compose.backup-scheduler.yaml"));
  assert.equal(files.at(-1), "compose.runtime-isolation.yaml");
  for (const file of files) {
    assert.ok(fs.statSync(path.join(root, file)).isFile(), `canonical Compose overlay is missing: ${file}`);
  }
  assert.ok(fs.statSync(path.join(root, "compose.local-private.yaml")).isFile());
  const localPrivateAppend = wrapper.indexOf("compose+=(-f compose.local-private.yaml)");
  const runtimeIdentityAppend = wrapper.indexOf("compose+=(-f compose.runtime-identity.yaml)");
  assert.ok(localPrivateAppend > wrapper.indexOf("-f compose.runtime-isolation.yaml"));
  assert.ok(runtimeIdentityAppend > localPrivateAppend, "runtime identity must be last for LOCAL_PRIVATE");
});

test("unit support: the fail-closed parser handles short, long, override, reset and named host aliases", () => {
  const model = effectiveComposeModel([
    {
      label: "base.yaml",
      source: `services:
  shorty:
    volumes:
      - /var/run:/host/run:ro
  longy:
    volumes:
      - type: bind
        source: /run/docker.sock
        target: /host/docker.sock
        read_only: true
  aliasy:
    volumes:
      - host_runtime:/host/runtime:ro
volumes:
  host_runtime:
    driver: local
    driver_opts:
      type: none
      o: bind,ro
      device: /var/run
`,
    },
    {
      label: "last.yaml",
      source: `services:
  shorty:
    volumes: !override
      - type: volume
        source: safe_data
        target: /host/run
        read_only: true
  longy:
    volumes: !reset []
volumes:
  safe_data:
`,
    },
  ]);

  assert.deepEqual(
    rawSocketOwners(model),
    ["aliasy"],
    "override/reset must remove inherited authorities while a named-volume host alias remains visible",
  );
  assert.deepEqual(model.services.get("shorty").volumes, [{
    type: "volume",
    source: "safe_data",
    target: "/host/run",
    readOnly: true,
  }]);
  assert.deepEqual(model.services.get("longy").volumes, []);
  assert.equal(model.volumes.get("host_runtime").device, "/var/run");
});

test("unit support: the parser expands mount sources, follows volumes_from and resolves explicit volume aliases", () => {
  const model = effectiveComposeModel([
    {
      label: "expanded.yaml",
      source: `services:
  env-owner:
    volumes:
      - \${SOCKET_PARENT}:/host/runtime:ro
  default-owner:
    volumes:
      - \${UNSET_SOCKET_PARENT:-/run}:/host/default-runtime:ro
  inherited-owner:
    volumes_from:
      - env-owner:ro
  named-consumer:
    volumes:
      - project_runtime:/runtime:ro
volumes:
  project_runtime:
    name: \${COMPOSE_PROJECT_NAME}_runtime
  external_runtime:
    external: true
`,
    },
  ], {
    environment: {
      COMPOSE_PROJECT_NAME: "platform_infra_vps",
      SOCKET_PARENT: "/var/run",
    },
  });

  assert.deepEqual(rawSocketOwners(model), ["default-owner", "env-owner", "inherited-owner"]);
  assert.equal(model.volumes.get("project_runtime").name, "platform_infra_vps_runtime");
  assert.equal(model.volumes.get("external_runtime").external, "true");
  assert.equal(effectiveVolumeName(model, "project_runtime"), "platform_infra_vps_runtime");
  assert.throws(() => effectiveVolumeName(model, "external_runtime"), /is external/);
  assert.throws(
    () => exactPrivateVolumeName(model, "project_runtime"),
    /must not define external, name, driver or driver_opts aliases/,
  );
  assert.throws(
    () => exactPrivateVolumeName(model, "external_runtime"),
    /must not define external, name, driver or driver_opts aliases/,
  );

  const unresolved = effectiveComposeModel([{
    label: "unresolved.yaml",
    source: "services:\n  observer:\n    volumes:\n      - ${UNSET_SOCKET_PARENT}:/host/runtime:ro\n",
  }]);
  assert.throws(() => rawSocketOwners(unresolved), /unresolved Compose variable UNSET_SOCKET_PARENT/);

  assert.throws(
    () => effectiveComposeModel([{
      label: "external-volumes-from.yaml",
      source: "services:\n  observer:\n    volumes_from:\n      - container:untrusted-runtime:ro\n",
    }]),
    /unsupported external volumes_from/i,
  );
});

test("unit support: the parser rejects Compose volume constructs it cannot prove safe", () => {
  for (const [label, source] of [
    ["inline sequence", "services:\n  app:\n    volumes: [/var/run:/host/run:ro]\n"],
    ["inline mapping", "services:\n  app:\n    volumes:\n      - { type: bind, source: /var/run, target: /host/run }\n"],
    ["missing long target", "services:\n  app:\n    volumes:\n      - type: bind\n        source: /var/run\n"],
    ["unknown tag", "services:\n  app:\n    volumes: !replace\n      - /var/run:/host/run:ro\n"],
  ]) {
    assert.throws(
      () => effectiveComposeModel([{ label: `${label}.yaml`, source }]),
      /unsupported|requires both source and target/i,
      `${label} must fail closed`,
    );
  }
});

test("unit support: raw-authority classification is fail-closed with positive controls", () => {
  const config = {
    services: {
      safe: {
        volumes: [{
          type: "volume",
          source: "safe_runtime",
          target: "/host-runtime",
          read_only: true,
        }],
      },
      bindParent: {
        volumes: [{
          type: "bind",
          source: "/var",
          target: "/host-runtime",
          read_only: true,
        }],
      },
      externalVolume: {
        volumes: [{
          type: "volume",
          source: "external_runtime",
          target: "/host-runtime",
          read_only: true,
        }],
      },
      namedVolume: {
        volumes: [{
          type: "volume",
          source: "named_runtime",
          target: "/host-runtime",
          read_only: true,
        }],
      },
      internalInheritance: {
        volumes: [],
        volumes_from: ["safe:ro"],
      },
      externalInheritance: {
        volumes: [],
        volumes_from: ["container:untrusted-runtime:ro"],
      },
    },
    volumes: {
      safe_runtime: { name: "platform_infra_vps_safe_runtime" },
      external_runtime: { external: true, name: "untrusted_precreated_runtime" },
      named_runtime: { name: "untrusted_precreated_runtime" },
    },
  };

  assert.equal(renderedServiceOwnsRawSocket(config, "safe"), false);
  assert.equal(renderedServiceOwnsRawSocket(config, "internalInheritance"), false);
  for (const name of ["bindParent", "externalVolume", "namedVolume", "externalInheritance"]) {
    assert.equal(renderedServiceOwnsRawSocket(config, name), true, `${name} must remain unprovable/fail-closed`);
  }
});

test("canonical Compose rendering is available without a Docker Engine", () => {
  assert.equal(
    composeAvailability.available,
    true,
    `NOT_RUN: canonical docker compose config renderer unavailable: ${composeAvailability.reason}`,
  );
});

test("the effective canonical VPS JSON render has one raw Docker authority and no raw-host metrics profile", (t) => {
  const config = canonicalComposeRenderOrSkip(t);
  if (!config) return;
  assertRenderedPolicySurface(config);
  const owners = renderedRawSocketOwners(config);

  assert.deepEqual(
    owners,
    ["docker-action-broker"],
    `raw Docker socket owners include bind parents or named-volume aliases: ${owners.join(",") || "none"}`,
  );
  for (const metricsService of ["cadvisor", "node-exporter"]) {
    assert.equal(
      config.services?.[metricsService],
      undefined,
      `${metricsService} must remain absent unless the non-canonical raw-host-metrics-disabled profile is explicit`,
    );
  }
});

test.todo("Package A/B runtime metrics continuity after removing cAdvisor/node-exporter host parents (NOT_RUN)");

test("broker and scheduler share only the root-owned claimed-job queue boundary", (t) => {
  const config = canonicalComposeRenderOrSkip(t);
  if (!config) return;
  const owners = Object.entries(config.services ?? {})
    .filter(([, service]) => (service.volumes ?? []).some((mount) => mount.source === "backup_scheduler_jobs"))
    .map(([name, service]) => ({
      name,
      mounts: service.volumes
        .filter((mount) => mount.source === "backup_scheduler_jobs")
        .map(normalizeRenderedMount),
    }))
    .sort((left, right) => left.name.localeCompare(right.name));

  assertPrivateRenderedVolume(
    config,
    "backup_scheduler_jobs",
    "platform_infra_vps_backup_scheduler_jobs",
  );
  assert.deepEqual(
    owners,
    [
      {
        name: "backup-scheduler",
        mounts: [{
          type: "volume",
          source: "backup_scheduler_jobs",
          target: "/var/www/project-state/backup-jobs",
          readOnly: false,
        }],
      },
      {
        name: "docker-action-broker",
        mounts: [{
          type: "volume",
          source: "backup_scheduler_jobs",
          target: "/run/platform/backup-jobs",
          readOnly: true,
        }],
      },
    ],
    "scheduler claims queue entries read-write; broker stable-reads the same private volume read-only",
  );
});

test("the canonical broker healthcheck invokes mandatory behavioral readiness", (t) => {
  const config = canonicalComposeRenderOrSkip(t);
  if (!config) return;
  const broker = config.services?.["docker-action-broker"];
  assert.deepEqual(
    broker?.healthcheck?.test,
    [
      "CMD",
      "node",
      "/opt/platform-docker-broker/docker-action-readiness.mjs",
      "--require-trusted-activation",
    ],
    "the effective last-overlay healthcheck must invoke the behavioral readiness module with no optional bypass",
  );
});

test("the behavioral readiness module exists as a direct production boundary", () => {
  const modulePath = path.join(root, "scripts", "docker-action-readiness.mjs");
  assert.ok(fs.existsSync(modulePath), "missing behaviorally testable broker readiness module");
});

test("the behavioral readiness module is copied to the exact immutable image path", (t) => {
  const modulePath = readinessModuleOrTodo(t);
  if (!modulePath) return;
  assert.equal(
    dockerfileCopyTarget(
      read("docker/docker-action-broker.Dockerfile"),
      "scripts/docker-action-readiness.mjs",
    ),
    "/opt/platform-docker-broker/docker-action-readiness.mjs",
    "the healthcheck command must address the exact immutable module copied into the broker image",
  );
});

test("unit support: readiness evaluator rejects incoherent trusted activation state", async (t) => {
  const modulePath = readinessModuleOrTodo(t);
  if (!modulePath) return;
  const readiness = await import(`${pathToFileURL(modulePath).href}?test=${Date.now()}`);
  assert.equal(typeof readiness.evaluateBrokerReadiness, "function");

  const trusted = trustedReadinessInput();
  assert.deepEqual(readiness.evaluateBrokerReadiness(trusted), { ready: true, failures: [] });

  for (const [name, mutate] of [
    ["socket type", (value) => { value.socket.isSocket = false; }],
    ["intent trust", (value) => { value.runtimeIntent.trusted = false; }],
    ["receipt digest", (value) => { value.activeReceipt.sha256 = "f".repeat(64); }],
    ["activation status", (value) => { value.activation.status = "pending"; }],
    ["render tuple", (value) => { value.activeReceipt.document.combinedRenderSha256 = "e".repeat(64); }],
  ]) {
    const candidate = structuredClone(trusted);
    mutate(candidate);
    const result = readiness.evaluateBrokerReadiness(candidate);
    assert.equal(result?.ready, false, `${name} mutation must fail readiness`);
    assert.ok(Array.isArray(result?.failures) && result.failures.length > 0, `${name} must identify a failed invariant`);
  }
});

test("the true readiness CLI reads documents, stats the UDS and rejects tamper", async (t) => {
  const modulePath = readinessModuleOrTodo(t);
  if (!modulePath) return;

  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "platform-readiness-cli-"));
  const inputFile = path.join(temporaryRoot, "readiness-input.json");
  const socketPath = path.join(temporaryRoot, "broker.sock");
  let protocolResponse = `${JSON.stringify({
    error: "action grammar is invalid",
    schema: "platform.docker-action.response/v1",
    status: "rejected",
    statusCode: 403,
  })}\n`;
  const server = net.createServer((connection) => {
    const chunks = [];
    connection.on("data", (chunk) => chunks.push(chunk));
    connection.on("end", () => {
      const request = Buffer.concat(chunks).toString("utf8");
      if (request !== "{}\n") return connection.destroy();
      connection.end(protocolResponse);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });

  const runCli = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      "scripts/docker-action-readiness.mjs",
      "--require-trusted-activation",
    ], {
      cwd: root,
      env: {
        DOCKER_ACTION_BROKER_SOCKET: socketPath,
        DOCKER_ACTION_READINESS_INPUT_FILE: inputFile,
        DOCKER_ACTION_READINESS_TEST_ONLY: "1",
        HOME: temporaryRoot,
        LANG: "C",
        LC_ALL: "C",
        NODE_ENV: "test",
        PATH: process.env.PATH,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, 10_000);
    child.once("close", (status, signal) => {
      clearTimeout(timer);
      resolve({
        signal,
        status,
        stderr: `${stderr}${timedOut ? "readiness test command timed out\n" : ""}`,
        stdout,
      });
    });
  });

  try {
    const trusted = trustedReadinessInput();
    fs.writeFileSync(inputFile, `${JSON.stringify(trusted)}\n`, { mode: 0o600 });
    const valid = await runCli();
    assert.equal(valid.status, 0, `valid readiness CLI fixture rejected:\n${valid.stdout}\n${valid.stderr}`);

    protocolResponse = '{"status":"ok"}\n';
    const rejectedWrongProtocol = await runCli();
    assert.notEqual(
      rejectedWrongProtocol.status,
      0,
      "readiness CLI accepted a live non-broker listener with the wrong protocol response",
    );
    protocolResponse = `${JSON.stringify({
      error: "action grammar is invalid",
      schema: "platform.docker-action.response/v1",
      status: "rejected",
      statusCode: 403,
    })}\n`;

    const tampered = structuredClone(trusted);
    tampered.activeReceipt.document.combinedRenderSha256 = "e".repeat(64);
    fs.writeFileSync(inputFile, `${JSON.stringify(tampered)}\n`, { mode: 0o600 });
    const rejectedDocument = await runCli();
    assert.notEqual(
      rejectedDocument.status,
      0,
      "readiness CLI accepted a tampered on-disk active receipt document",
    );

    fs.writeFileSync(inputFile, `${JSON.stringify(trusted)}\n`, { mode: 0o600 });
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    fs.rmSync(socketPath, { force: true });
    const rejectedSocket = await runCli();
    assert.notEqual(
      rejectedSocket.status,
      0,
      "readiness CLI trusted fixture-reported socket state instead of statting the actual UDS",
    );

    const staleListener = spawn(process.execPath, [
      "-e",
      "const net=require('node:net');const server=net.createServer();server.listen(process.env.STALE_SOCKET_PATH,()=>process.stdout.write('ready\\n'));setInterval(()=>{},1<<30);",
    ], {
      env: { ...process.env, STALE_SOCKET_PATH: socketPath },
      stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise((resolve, reject) => {
      staleListener.once("error", reject);
      staleListener.once("exit", (code, signal) => reject(new Error(`stale listener exited early: ${code ?? signal}`)));
      staleListener.stdout.once("data", resolve);
    });
    staleListener.kill("SIGKILL");
    await new Promise((resolve) => staleListener.once("exit", resolve));
    assert.equal(fs.lstatSync(socketPath).isSocket(), true, "stale listener fixture did not leave a UDS inode");
    const rejectedStaleSocket = await runCli();
    assert.notEqual(
      rejectedStaleSocket.status,
      0,
      "readiness CLI accepted a stale Unix-socket inode without a serving broker",
    );
  } finally {
    if (server.listening) {
      await new Promise((resolve) => server.close(() => resolve()));
    }
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("infra-ops.sh remains an executable general host orchestrator", () => {
  const wrapperPath = path.join(root, "scripts", "infra-ops.sh");
  const mode = fs.statSync(wrapperPath).mode & 0o777;
  const result = spawnSync("sh", [wrapperPath, "help"], {
    cwd: root,
    encoding: "utf8",
    env: {
      HOME: os.tmpdir(),
      PATH: process.env.PATH,
    },
    timeout: 10_000,
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;

  assert.equal(mode, 0o755, `scripts/infra-ops.sh mode must remain 0755, got 0${mode.toString(8)}`);
  assert.equal(result.status, 0, output);
  for (const command of ["runtime-isolation-check", "backup-postgres", "vps-preflight"]) {
    assert.match(output, new RegExp(`(?:^|\\s)${command}(?:\\s|$)`), `general command missing from help: ${command}`);
  }
});

test("activation remains external-pending until Release materializes exact v2 values", () => {
  const policy = JSON.parse(read("policy/docker-action-activation-policy.json"));
  assert.equal(policy.status, "external-pending");
});

function readinessModuleOrTodo(t) {
  const modulePath = path.join(root, "scripts", "docker-action-readiness.mjs");
  if (!fs.existsSync(modulePath)) {
    t.todo("blocked by direct readiness module presence RED");
    return null;
  }
  return modulePath;
}

function canonicalComposeRenderOrSkip(t) {
  if (!composeAvailability.available) {
    t.skip(`NOT_RUN: canonical docker compose config renderer unavailable: ${composeAvailability.reason}`);
    return null;
  }
  return canonicalComposeRender();
}

function canonicalComposeRender() {
  if (cachedCanonicalRender) return structuredClone(cachedCanonicalRender);

  const temporaryRoot = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "platform-compose-render-")),
  );
  try {
    const workspaceRoot = path.join(temporaryRoot, "workspace");
    copyTrackedWorkspaceSnapshot(workspaceRoot);
    const envFile = path.join(workspaceRoot, ".env");
    const dockerConfig = path.join(temporaryRoot, "docker-config");
    fs.mkdirSync(dockerConfig, { mode: 0o700 });
    fs.writeFileSync(envFile, deterministicComposeEnvironment(), { flag: "wx", mode: 0o600 });
    fs.chmodSync(envFile, 0o600);
    prepareOfflineSecretFixtures(workspaceRoot);
    prepareOfflineFilesystemFixtures(workspaceRoot, temporaryRoot, envFile, dockerConfig);
    const executionPath = prepareComposeExecutionPath(temporaryRoot);

    const result = spawnSync(
      "bash",
      [path.join(workspaceRoot, "scripts", "compose-vps.sh"), "config", "--format", "json"],
      {
        cwd: workspaceRoot,
        encoding: "utf8",
        env: {
          COMPOSE_ANSI: "never",
          COMPOSE_PROJECT_NAME: "platform_infra_vps",
          DOCKER_CONFIG: dockerConfig,
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
    assert.ok(parsed && typeof parsed === "object" && !Array.isArray(parsed), "Compose JSON render must be an object");
    assert.ok(parsed.services && typeof parsed.services === "object", "Compose JSON render must contain services");
    cachedCanonicalRender = parsed;
    return structuredClone(cachedCanonicalRender);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function copyTrackedWorkspaceSnapshot(workspaceRoot) {
  fs.mkdirSync(workspaceRoot, { mode: 0o700 });
  const listed = spawnSync("git", ["ls-files", "-z"], {
    cwd: root,
    encoding: "utf8",
    env: {
      GIT_CONFIG_NOSYSTEM: "1",
      HOME: os.tmpdir(),
      LANG: "C",
      LC_ALL: "C",
      PATH: process.env.PATH,
    },
    maxBuffer: 10 * 1024 * 1024,
    timeout: 10_000,
  });
  assert.equal(listed.status, 0, `could not enumerate tracked Compose fixture inputs: ${listed.stderr}`);
  const trackedFiles = listed.stdout.split("\0").filter(Boolean);
  assert.ok(trackedFiles.length > 0, "tracked Compose fixture input set is empty");
  for (const relative of trackedFiles) {
    assert.ok(
      !path.isAbsolute(relative)
        && relative !== ".."
        && !relative.startsWith(`..${path.sep}`)
        && path.normalize(relative) === relative,
      `unsafe tracked fixture path: ${relative}`,
    );
    if (relative === "secrets" || relative.startsWith(`secrets${path.sep}`)) continue;
    const source = path.join(root, relative);
    const sourceStat = fs.lstatSync(source);
    assert.ok(sourceStat.isFile() && !sourceStat.isSymbolicLink(), `unsupported tracked fixture object: ${relative}`);
    const destination = path.join(workspaceRoot, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
    fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(destination, sourceStat.mode & 0o777);
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

function prepareComposeExecutionPath(temporaryRoot) {
  if (!composeAvailability.standalone) return composeAvailability.path;
  const shimDir = path.join(temporaryRoot, "compose-shim");
  const shim = path.join(shimDir, "docker");
  const materializedDir = path.join(temporaryRoot, "compose-inputs");
  fs.mkdirSync(shimDir, { mode: 0o700 });
  fs.mkdirSync(materializedDir, { mode: 0o700 });
  fs.writeFileSync(
    shim,
    [
      "#!/bin/bash",
      "set -euo pipefail",
      "[ \"$1\" = compose ] || exit 64",
      "shift",
      "arguments=()",
      "for argument in \"$@\"; do",
      "  case \"$argument\" in",
      "    /dev/fd/*)",
      `      materialized=$(mktemp ${shellSingleQuote(`${materializedDir}/input.XXXXXX`)})`,
      "      chmod 600 \"$materialized\"",
      "      /bin/cat -- \"$argument\" > \"$materialized\"",
      "      arguments+=(\"$materialized\")",
      "      ;;",
      "    *) arguments+=(\"$argument\") ;;",
      "  esac",
      "done",
      "argument_count=${#arguments[@]}",
      "(( argument_count >= 3 )) || exit 65",
      "[[ \"${arguments[$((argument_count - 3))]}\" == config ]] || exit 65",
      "[[ \"${arguments[$((argument_count - 2))]}\" == --format ]] || exit 65",
      "[[ \"${arguments[$((argument_count - 1))]}\" == json ]] || exit 65",
      `export DOCKER_HOST=${shellSingleQuote(`unix://${path.join(temporaryRoot, "engine-must-not-exist.sock")}`)}`,
      "unset DOCKER_CONTEXT",
      `exec ${shellSingleQuote(composeAvailability.standalone)} "\${arguments[@]}"`,
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
    "HOSTED_WORKLOAD_MODE=no-hosted",
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
    `PLATFORM_OPS_IMAGE=registry.example.invalid/platform/ops@sha256:${"f".repeat(64)}`,
    "POSTGRES_USER=postgres",
    "REDIS_PASSWORD_FILE=/run/secrets/redis_password",
    "REDIS_USERNAME=platform",
    "SMTP_HOST=smtp.example.invalid",
    "SMTP_USER=mailer",
    "",
  ].join("\n");
}

function prepareOfflineSecretFixtures(workspaceRoot) {
  const secretsDirectory = path.join(workspaceRoot, "secrets");
  fs.mkdirSync(secretsDirectory, { mode: 0o700 });
  fs.chmodSync(secretsDirectory, 0o700);
  const workspaceReal = fs.realpathSync.native(workspaceRoot);
  const secretsReal = fs.realpathSync.native(secretsDirectory);
  const secretsStat = fs.lstatSync(secretsDirectory);
  assert.equal(secretsReal, path.join(workspaceReal, "secrets"));
  assert.ok(secretsStat.isDirectory() && !secretsStat.isSymbolicLink());
  const secretNames = new Set();
  const copiedWrapper = fs.readFileSync(path.join(workspaceRoot, "scripts", "compose-vps.sh"), "utf8");
  for (const composeFile of canonicalComposeFiles(copiedWrapper)) {
    const source = fs.readFileSync(path.join(workspaceRoot, composeFile), "utf8");
    for (const match of source.matchAll(/(?:\$\{[A-Z0-9_]+:-)?\.\/secrets\/([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\})?/g)) {
      secretNames.add(match[1]);
    }
  }
  for (const secretName of secretNames) {
    const mode = secretName === "alertmanager_webhook_token.txt" ? 0o640 : 0o600;
    const secretFile = path.join(secretsDirectory, secretName);
    fs.writeFileSync(secretFile, "offline-test-fixture\n", { flag: "wx", mode });
    fs.chmodSync(secretFile, mode);
    const secretStat = fs.lstatSync(secretFile);
    assert.ok(secretStat.isFile() && !secretStat.isSymbolicLink() && secretStat.nlink === 1);
  }
}

const offlineDirectoryMountTargets = new Set([
  "/app",
  "/docker-entrypoint-initdb.d",
  "/etc/coredns",
  "/etc/grafana/provisioning",
  "/etc/mysql/conf.d",
  "/etc/mysql/ssl",
  "/etc/phpmyadmin/certs",
  "/etc/prometheus/rules",
  "/infra",
  "/infra/backups",
  "/infra/reports",
  "/loki/rules",
  "/opt/keycloak/data/import",
  "/platform-postgres-init",
  "/project",
  "/var/lib/grafana/dashboards",
  "/var/lib/node-exporter/textfile",
  "/var/www/infra-docs",
  "/var/www/project-state",
  "/var/www/projects",
]);

function prepareOfflineFilesystemFixtures(workspaceRoot, temporaryRoot, envFile, dockerConfig) {
  const copiedWrapper = fs.readFileSync(path.join(workspaceRoot, "scripts", "compose-vps.sh"), "utf8");
  const composeFiles = canonicalComposeFiles(copiedWrapper);
  const composeArguments = [
    "--env-file",
    envFile,
    "-p",
    "platform_infra_vps",
    ...composeFiles.flatMap((composeFile) => ["-f", composeFile]),
    "--profile",
    "backup",
    "config",
    "--format",
    "json",
  ];
  const rendered = spawnSync(composeAvailability.standalone, composeArguments, {
    cwd: workspaceRoot,
    encoding: "utf8",
    env: {
      COMPOSE_ANSI: "never",
      DOCKER_CONFIG: dockerConfig,
      DOCKER_HOST: `unix://${path.join(temporaryRoot, "preflight-engine-must-not-exist.sock")}`,
      HOME: temporaryRoot,
      LANG: "C",
      LC_ALL: "C",
      PATH: composeAvailability.path,
    },
    maxBuffer: 10 * 1024 * 1024,
    timeout: 30_000,
  });
  assert.equal(
    rendered.status,
    0,
    `offline filesystem-fixture Compose pre-render failed:\n${rendered.stdout}\n${rendered.stderr}`,
  );
  assert.equal(rendered.signal, null, `offline filesystem-fixture pre-render terminated by ${rendered.signal}`);
  let config;
  try {
    config = JSON.parse(rendered.stdout);
  } catch (error) {
    assert.fail(`offline filesystem-fixture pre-render returned invalid JSON: ${error.message}`);
  }
  materializeOfflineCanonicalSources(workspaceRoot, temporaryRoot, config);
}

function materializeOfflineCanonicalSources(workspaceRoot, temporaryRoot, config) {
  const workspaceReal = fs.realpathSync.native(workspaceRoot);
  const siblingSource = path.join(temporaryRoot, "src");
  fs.mkdirSync(siblingSource, { mode: 0o755 });
  const siblingReal = fs.realpathSync.native(siblingSource);
  assert.equal(siblingReal, siblingSource);

  for (const service of Object.values(config.services ?? {})) {
    for (const mount of service.volumes ?? []) {
      if (mount?.type !== "bind" || typeof mount.source !== "string") continue;
      const source = path.resolve(mount.source);
      const anchor = source === workspaceReal || source.startsWith(`${workspaceReal}${path.sep}`)
        ? workspaceReal
        : source === siblingReal || source.startsWith(`${siblingReal}${path.sep}`)
          ? siblingReal
          : "";
      if (!anchor) continue;
      if (source === anchor || offlineDirectoryMountTargets.has(mount.target)) {
        fs.mkdirSync(source, { recursive: true, mode: 0o755 });
        const sourceStat = fs.lstatSync(source);
        assert.ok(sourceStat.isDirectory() && !sourceStat.isSymbolicLink(), `unsafe fixture directory: ${source}`);
        assert.ok(fs.realpathSync.native(source) === source || fs.realpathSync.native(source).startsWith(`${anchor}${path.sep}`));
        continue;
      }
      if (mount.target === "/run/platform/hosted-workloads.lock.json" && fs.existsSync(source)) continue;
      fs.mkdirSync(path.dirname(source), { recursive: true, mode: 0o755 });
      const parentReal = fs.realpathSync.native(path.dirname(source));
      assert.ok(parentReal === anchor || parentReal.startsWith(`${anchor}${path.sep}`), `fixture parent escaped: ${source}`);
      if (fs.existsSync(source)) {
        const sourceStat = fs.lstatSync(source);
        assert.ok(sourceStat.isFile() && !sourceStat.isSymbolicLink(), `unsafe fixture file: ${source}`);
        continue;
      }
      const mode = mount.target === "/usr/local/bin/platform-postgres-entrypoint" ? 0o755 : 0o644;
      fs.writeFileSync(source, `offline-source:${mount.target}\n`, { flag: "wx", mode });
      fs.chmodSync(source, mode);
      const sourceStat = fs.lstatSync(source);
      assert.ok(sourceStat.isFile() && !sourceStat.isSymbolicLink() && sourceStat.nlink === 1);
    }
  }
}

function assertRenderedPolicySurface(config) {
  assert.ok(config.services && typeof config.services === "object" && !Array.isArray(config.services));
  assert.ok(config.volumes && typeof config.volumes === "object" && !Array.isArray(config.volumes));
  assert.ok(config.networks && typeof config.networks === "object" && !Array.isArray(config.networks));
  assert.ok(config.secrets && typeof config.secrets === "object" && !Array.isArray(config.secrets));
  for (const name of ["docker-action-broker", "backup-scheduler"]) {
    const service = config.services[name];
    assert.ok(service && typeof service === "object", `canonical render is missing ${name}`);
    for (const field of ["cap_drop", "cap_add", "secrets", "tmpfs", "volumes", "volumes_from"]) {
      assert.ok(
        service[field] === undefined || Array.isArray(service[field]),
        `${name}.${field} has an unsupported normalized Compose JSON shape`,
      );
    }
    assert.ok(
      service.healthcheck === undefined || Array.isArray(service.healthcheck.test),
      `${name}.healthcheck.test has an unsupported rendered shape`,
    );
    assert.ok(
      service.network_mode === "none" || service.networks === undefined
        || Array.isArray(service.networks) || typeof service.networks === "object",
      `${name}.networks has an unsupported rendered shape`,
    );
    assert.ok(service.user === undefined || typeof service.user === "string", `${name}.user has an unsupported rendered shape`);
  }
}

function renderedRawSocketOwners(config) {
  return Object.keys(config.services ?? {})
    .filter((name) => renderedServiceOwnsRawSocket(config, name))
    .sort();
}

function renderedServiceOwnsRawSocket(config, name, ancestry = new Set()) {
  if (ancestry.has(name)) throw new Error(`cyclic rendered volumes_from authority chain at ${name}`);
  const service = config.services?.[name];
  if (!service) throw new Error(`unknown rendered volumes_from service ${name}`);
  const next = new Set(ancestry).add(name);
  if ((service.volumes ?? []).some((mount) => {
    if (mount?.type !== "volume") return exposesDockerSocket(mount?.source);
    const volumeName = String(mount?.source || "");
    const declaration = config.volumes?.[volumeName];
    const targetCarriesHostAuthority = /(?:^|\/)(?:host(?:-runtime)?|rootfs)(?:\/|$)/.test(String(mount?.target || ""));
    if (!declaration || declaration.external === true) return targetCarriesHostAuthority;
    if (declaration.name && declaration.name !== `platform_infra_vps_${volumeName}`) return targetCarriesHostAuthority;
    if (declaration.driver && declaration.driver !== "local") return targetCarriesHostAuthority;
    if (declaration.driver_opts) {
      const device = declaration.driver_opts.device;
      return device ? exposesDockerSocket(device) : targetCarriesHostAuthority;
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

function normalizeRenderedMount(mount) {
  return {
    type: String(mount?.type || ""),
    source: String(mount?.source || ""),
    target: String(mount?.target || ""),
    readOnly: mount?.read_only === true,
  };
}

function assertPrivateRenderedVolume(config, name, exactName) {
  const declaration = config.volumes?.[name];
  assert.ok(declaration && typeof declaration === "object", `missing rendered named volume ${name}`);
  assert.equal(declaration.name, exactName, `rendered ${name} must have the exact project-private Engine name`);
  assert.notEqual(declaration.external, true, `${name} must not be external`);
  assert.ok(!declaration.driver || declaration.driver === "local", `${name} uses a non-local driver`);
  assert.equal(declaration.driver_opts, undefined, `${name} must not alias a host path through driver_opts`);
}

function canonicalComposeFiles(wrapper) {
  const blocks = [...wrapper.matchAll(/(?:^|\n)\s*compose\+=\(\s*\n([\s\S]*?)\n\s*\)/g)]
    .map((match) => match[1])
    .filter((body) => /(?:^|\n)\s*-f\s+/.test(body));
  assert.equal(blocks.length, 1, "compose-vps.sh must have one literal canonical -f overlay block");
  const tokens = shellWords(blocks[0], "scripts/compose-vps.sh canonical overlay block");
  const files = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index] === "-p") {
      const projectName = tokens[++index];
      if (!projectName || projectName !== "$PROJECT_NAME") {
        throw new Error(`unsupported canonical Compose project argument: ${projectName || "<missing>"}`);
      }
      continue;
    }
    if (tokens[index] !== "-f") {
      throw new Error(`unsupported token in canonical Compose overlay block: ${tokens[index]}`);
    }
    const file = tokens[++index];
    if (!file || file.startsWith("-") || file.includes("$") || path.isAbsolute(file) || path.normalize(file) !== file) {
      throw new Error(`unsupported canonical Compose overlay path: ${file || "<missing>"}`);
    }
    files.push(file);
  }
  return files;
}

function shellWords(source, label) {
  const words = [];
  let current = "";
  let quote = "";
  let escaped = false;
  for (const character of source) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = "";
      else current += character;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (/\s/.test(character)) {
      if (current) {
        words.push(current);
        current = "";
      }
      continue;
    }
    if (character === "#" && current === "") {
      throw new Error(`${label} contains an unsupported inline comment`);
    }
    current += character;
  }
  if (escaped || quote) throw new Error(`${label} contains an unterminated shell token`);
  if (current) words.push(current);
  return words;
}

function effectiveComposeModel(documents, options = {}) {
  const model = {
    environment: { ...(options.environment ?? {}) },
    services: new Map(),
    volumes: new Map(),
  };
  for (const document of documents) {
    const parsed = parseComposeDocument(document.source, document.label, model.environment);
    for (const [name, declaration] of parsed.volumes) {
      model.volumes.set(name, {
        ...(model.volumes.get(name) ?? {}),
        ...declaration,
      });
    }
    for (const [name, patch] of parsed.services) {
      const service = model.services.get(name) ?? {
        healthcheckTest: undefined,
        volumes: [],
        volumesFrom: [],
      };
      if (patch.volumeMode === "override" || patch.volumeMode === "reset") service.volumes = [];
      for (const mount of patch.volumes) {
        const prior = service.volumes.findIndex((item) => item.target === mount.target);
        if (prior === -1) service.volumes.push(mount);
        else service.volumes[prior] = mount;
      }
      if (patch.volumesFromPresent) {
        if (patch.volumesFromMode === "override" || patch.volumesFromMode === "reset") service.volumesFrom = [];
        service.volumesFrom.push(...patch.volumesFrom);
      }
      if (patch.healthcheckTest !== undefined) service.healthcheckTest = patch.healthcheckTest;
      model.services.set(name, service);
    }
  }
  return model;
}

function parseComposeDocument(source, label, environment) {
  if (source.includes("\t")) throw new Error(`${label}: tabs are unsupported`);
  const services = new Map();
  for (const [name, block] of sectionEntries(source, "services", label)) {
    services.set(name, parseServiceDefinition(block, `${label}:services.${name}`, environment));
  }
  const volumes = new Map();
  for (const [name, block, declaration] of sectionEntries(source, "volumes", label)) {
    volumes.set(name, parseNamedVolume(block, declaration, `${label}:volumes.${name}`, environment));
  }
  return { services, volumes };
}

function sectionEntries(source, section, label) {
  const lines = source.replaceAll("\r\n", "\n").split("\n");
  const start = lines.findIndex((line) => line === `${section}:`);
  if (start === -1) return [];
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^[^\s#][^:]*:\s*(?:#.*)?$/.test(lines[index])) {
      end = index;
      break;
    }
  }
  const entries = [];
  for (let index = start + 1; index < end;) {
    const line = lines[index];
    if (line.trim() === "" || line.trimStart().startsWith("#")) {
      index += 1;
      continue;
    }
    const marker = line.match(/^  ([A-Za-z0-9][A-Za-z0-9_.-]*):(.*)$/);
    if (!marker) throw new Error(`${label}:${index + 1}: unsupported ${section} entry`);
    let next = index + 1;
    while (next < end && !/^  [A-Za-z0-9][A-Za-z0-9_.-]*:/.test(lines[next])) next += 1;
    entries.push([marker[1], lines.slice(index + 1, next), marker[2].trim()]);
    index = next;
  }
  return entries;
}

function parseServiceDefinition(lines, label, environment) {
  const property = lines.findIndex((line) => /^    volumes:/.test(line));
  let volumeMode = "merge";
  let volumes = [];
  if (property !== -1) {
    const declaration = lines[property].slice(lines[property].indexOf(":") + 1).trim();
    if (declaration === "!override") volumeMode = "override";
    else if (declaration === "!reset []") volumeMode = "reset";
    else if (declaration !== "") throw new Error(`${label}: unsupported volumes declaration ${declaration}`);
    const body = indentedPropertyBody(lines, property, label, "volumes");
    if (volumeMode === "reset") {
      if (body.length > 0) throw new Error(`${label}: !reset [] cannot contain entries`);
    } else {
      volumes = parseMountList(body, label);
    }
  }

  const volumesFromProperty = lines.findIndex((line) => /^    volumes_from:/.test(line));
  const volumesFromPresent = volumesFromProperty !== -1;
  let volumesFromMode = "merge";
  let volumesFrom = [];
  if (volumesFromPresent) {
    const declaration = lines[volumesFromProperty].slice(lines[volumesFromProperty].indexOf(":") + 1).trim();
    if (declaration === "!override") volumesFromMode = "override";
    else if (declaration === "!reset []") volumesFromMode = "reset";
    else if (declaration !== "") throw new Error(`${label}: unsupported volumes_from declaration ${declaration}`);
    const body = indentedPropertyBody(lines, volumesFromProperty, label, "volumes_from");
    if (volumesFromMode === "reset") {
      if (body.length > 0) throw new Error(`${label}: !reset [] cannot contain volumes_from entries`);
    } else {
      volumesFrom = parseVolumesFrom(body, label);
    }
  }

  return {
    healthcheckTest: parseHealthcheckTest(lines, label, environment),
    volumeMode,
    volumes,
    volumesFrom,
    volumesFromMode,
    volumesFromPresent,
  };
}

function indentedPropertyBody(lines, property, label, name) {
  const body = [];
  for (let index = property + 1; index < lines.length; index += 1) {
    if (lines[index].trim() === "" || lines[index].trimStart().startsWith("#")) continue;
    if (/^    \S/.test(lines[index])) break;
    if (!/^ {6,}\S/.test(lines[index])) throw new Error(`${label}: unsupported ${name} indentation`);
    body.push(lines[index]);
  }
  return body;
}

function parseMountList(lines, label) {
  const mounts = [];
  for (let index = 0; index < lines.length;) {
    const marker = lines[index].match(/^      -\s+(.+?)\s*$/);
    if (!marker) throw new Error(`${label}: unsupported volume list item`);
    const head = marker[1];
    if (head.startsWith("{") || head.startsWith("[")) {
      throw new Error(`${label}: unsupported inline volume item`);
    }
    if (/^(?:type|source|target|read_only):(?:\s|$)/.test(head)) {
      const fields = new Map();
      setLongMountField(fields, head, label);
      index += 1;
      while (index < lines.length && /^ {8,}\S/.test(lines[index])) {
        const continuation = lines[index].trim();
        if (!/^(?:type|source|target|read_only):(?:\s|$)/.test(continuation)) {
          throw new Error(`${label}: unsupported long volume field ${continuation}`);
        }
        setLongMountField(fields, continuation, label);
        index += 1;
      }
      const source = fields.get("source");
      const target = fields.get("target");
      if (!source || !target) throw new Error(`${label}: long volume requires both source and target`);
      const type = fields.get("type") || inferMountType(source);
      if (!["bind", "volume"].includes(type)) throw new Error(`${label}: unsupported long volume type ${type}`);
      mounts.push({
        type,
        source,
        target,
        readOnly: fields.get("read_only") === "true",
      });
      continue;
    }
    const parts = splitComposeMount(unquote(head));
    if (parts.length < 2 || parts.length > 3 || !parts[0] || !parts[1]) {
      throw new Error(`${label}: unsupported short volume ${head}`);
    }
    mounts.push({
      type: inferMountType(parts[0]),
      source: parts[0],
      target: parts[1],
      readOnly: parts[2]?.split(",").includes("ro") ?? false,
    });
    index += 1;
  }
  return mounts;
}

function parseVolumesFrom(lines, label) {
  const references = [];
  for (const line of lines) {
    const marker = line.match(/^      -\s+(.+?)\s*$/);
    if (!marker) throw new Error(`${label}: unsupported volumes_from list item`);
    const value = unquote(marker[1]);
    if (value.startsWith("container:")) {
      throw new Error(`${label}: unsupported external volumes_from reference ${value}`);
    }
    const parts = value.split(":");
    if (parts.length > 2 || !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(parts[0])
      || (parts[1] && !["ro", "rw"].includes(parts[1]))) {
      throw new Error(`${label}: unsupported volumes_from reference ${value}`);
    }
    references.push({ service: parts[0], readOnly: parts[1] === "ro" });
  }
  return references;
}

function parseHealthcheckTest(lines, label, environment) {
  const property = lines.findIndex((line) => /^    healthcheck:/.test(line));
  if (property === -1) return undefined;
  const declaration = lines[property].slice(lines[property].indexOf(":") + 1).trim();
  if (declaration) throw new Error(`${label}: inline healthcheck is unsupported`);
  const body = indentedPropertyBody(lines, property, label, "healthcheck");
  const testIndex = body.findIndex((line) => /^      test:/.test(line));
  if (testIndex === -1) throw new Error(`${label}: healthcheck.test is required`);
  const raw = body[testIndex].slice(body[testIndex].indexOf(":") + 1).trim();
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`${label}: healthcheck.test inline value must be a JSON string array`);
    }
    if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((value) => typeof value !== "string")) {
      throw new Error(`${label}: healthcheck.test must be a non-empty string array`);
    }
    return parsed;
  }
  const result = [];
  for (let index = testIndex + 1; index < body.length; index += 1) {
    const marker = body[index].match(/^        -\s+(.+?)\s*$/);
    if (!marker) break;
    result.push(unquote(marker[1]));
  }
  if (result.length === 0) throw new Error(`${label}: healthcheck.test list is empty or unsupported`);
  return result;
}

function setLongMountField(fields, line, label) {
  const separator = line.indexOf(":");
  const key = line.slice(0, separator).trim();
  const raw = line.slice(separator + 1).trim();
  if (!raw) throw new Error(`${label}: unsupported nested long volume field ${key}`);
  if (fields.has(key)) throw new Error(`${label}: duplicate long volume field ${key}`);
  const value = unquote(raw);
  if (key === "read_only" && !["true", "false"].includes(value)) {
    throw new Error(`${label}: read_only must be true or false`);
  }
  fields.set(key, value);
}

function parseNamedVolume(lines, declaration, label, environment) {
  if (declaration === "{}" || declaration === "") {
    const result = {};
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
      const property = line.match(/^    ([A-Za-z_][A-Za-z0-9_-]*):(?:\s*(.*))?$/);
      if (!property) throw new Error(`${label}: unsupported named-volume property`);
      const [, key, raw = ""] = property;
      if (key === "driver_opts") {
        if (raw.trim()) throw new Error(`${label}: inline driver_opts are unsupported`);
        result.driver_opts = {};
        index += 1;
        while (index < lines.length && /^ {6,}\S/.test(lines[index])) {
          const option = lines[index].match(/^      ([A-Za-z_][A-Za-z0-9_-]*):\s*(.+?)\s*$/);
          if (!option) throw new Error(`${label}: unsupported driver_opts entry`);
          const value = expandComposeScalar(unquote(option[2]), environment);
          result.driver_opts[option[1]] = value;
          if (option[1] === "device") result.device = value;
          index += 1;
        }
        index -= 1;
      } else if (["driver", "name", "external"].includes(key)) {
        if (!raw.trim()) throw new Error(`${label}: missing value for ${key}`);
        result[key] = key === "external"
          ? unquote(raw)
          : expandComposeScalar(unquote(raw), environment);
      } else {
        throw new Error(`${label}: unsupported named-volume property ${key}`);
      }
    }
    return result;
  }
  throw new Error(`${label}: unsupported named-volume declaration ${declaration}`);
}

function splitComposeMount(value) {
  const parts = [];
  let start = 0;
  let interpolationDepth = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "$" && value[index + 1] === "{") {
      interpolationDepth += 1;
      index += 1;
      continue;
    }
    if (value[index] === "}" && interpolationDepth > 0) {
      interpolationDepth -= 1;
      continue;
    }
    if (value[index] === ":" && interpolationDepth === 0) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  if (interpolationDepth !== 0) throw new Error(`unsupported unterminated Compose interpolation: ${value}`);
  parts.push(value.slice(start));
  return parts;
}

function inferMountType(source) {
  return source.startsWith("/") || source.startsWith(".") || source.startsWith("${") ? "bind" : "volume";
}

function unquote(value) {
  const clean = String(value).trim();
  if ((clean.startsWith('"') && clean.endsWith('"')) || (clean.startsWith("'") && clean.endsWith("'"))) {
    return clean.slice(1, -1);
  }
  if (/^[\[{"'|>&*!]/.test(clean)) throw new Error(`unsupported YAML scalar: ${clean}`);
  return clean;
}

function rawSocketOwners(model) {
  return [...model.services.keys()].filter((name) => serviceOwnsRawSocket(model, name)).sort();
}

function serviceOwnsRawSocket(model, name, ancestry = new Set()) {
  if (ancestry.has(name)) throw new Error(`cyclic volumes_from authority chain at ${name}`);
  const service = model.services.get(name);
  if (!service) throw new Error(`unknown volumes_from service ${name}`);
  const next = new Set(ancestry).add(name);
  if ((service.volumes ?? []).some((mount) => {
    const rawSource = mount.type === "volume" ? model.volumes.get(mount.source)?.device : mount.source;
    const source = rawSource === undefined ? "" : expandComposeScalar(rawSource, model.environment);
    return exposesDockerSocket(source);
  })) return true;
  return (service.volumesFrom ?? []).some((reference) => serviceOwnsRawSocket(model, reference.service, next));
}

function exposesDockerSocket(source) {
  if (!String(source || "").startsWith("/")) return false;
  const observed = path.posix.normalize(source);
  const normalized = observed === "/run" || observed.startsWith("/run/")
    ? `/var${observed}`
    : observed;
  const withoutTrailingSlash = normalized === "/" ? "/" : normalized.replace(/\/+$/, "");
  return withoutTrailingSlash === dockerSocketPath
    || dockerSocketPath.startsWith(withoutTrailingSlash === "/" ? "/" : `${withoutTrailingSlash}/`);
}

function effectiveVolumeName(model, name) {
  const declaration = model.volumes.get(name);
  if (!declaration) throw new Error(`missing named volume ${name}`);
  if (declaration.external === "true" || declaration.external === true) {
    throw new Error(`named volume ${name} is external`);
  }
  if (declaration.name) return expandComposeScalar(declaration.name, model.environment);
  const projectName = expandComposeScalar("${COMPOSE_PROJECT_NAME}", model.environment);
  return `${projectName}_${name}`;
}

function exactPrivateVolumeName(model, name) {
  const declaration = model.volumes.get(name);
  if (!declaration) throw new Error(`missing named volume ${name}`);
  if (Object.keys(declaration).length !== 0) {
    throw new Error(`named volume ${name} must not define external, name, driver or driver_opts aliases`);
  }
  return effectiveVolumeName(model, name);
}

function expandComposeScalar(value, environment = {}) {
  let expanded = String(value);
  for (let pass = 0; pass < 8 && expanded.includes("${"); pass += 1) {
    expanded = expanded.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])(.*?))?\}/g, (_match, name, operator, fallback = "") => {
      const present = Object.hasOwn(environment, name);
      const actual = present ? String(environment[name]) : "";
      if (!operator) {
        if (!present) throw new Error(`unresolved Compose variable ${name}`);
        return actual;
      }
      if (operator === ":-") return present && actual !== "" ? actual : fallback;
      if (operator === "-") return present ? actual : fallback;
      if (operator === ":?") {
        if (!present || actual === "") throw new Error(`unresolved Compose variable ${name}: ${fallback}`);
        return actual;
      }
      if (operator === "?") {
        if (!present) throw new Error(`unresolved Compose variable ${name}: ${fallback}`);
        return actual;
      }
      throw new Error(`unsupported Compose expansion operator for ${name}`);
    });
  }
  if (expanded.includes("${")) throw new Error(`unsupported nested Compose interpolation: ${expanded}`);
  expanded = expanded.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_match, name) => {
    if (!Object.hasOwn(environment, name)) throw new Error(`unresolved Compose variable ${name}`);
    return String(environment[name]);
  });
  return expanded.replaceAll("$$", "$");
}

function dockerfileCopyTarget(source, repositoryPath) {
  const matches = [];
  for (const rawLine of source.replaceAll("\r\n", "\n").split("\n")) {
    const line = rawLine.trim();
    if (!/^COPY\s+/i.test(line)) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length === 3 && tokens[1] === repositoryPath) matches.push(tokens[2]);
  }
  assert.equal(matches.length, 1, `expected one COPY for ${repositoryPath}`);
  return matches[0];
}

function trustedReadinessInput() {
  const intentId = "intent.release-20260728";
  const combinedRenderSha256 = "a".repeat(64);
  const activeReceiptSha256 = "b".repeat(64);
  return {
    socket: {
      exists: true,
      isSocket: true,
      ownerUid: 0,
      ownerGid: 0,
    },
    runtimeIntent: {
      trusted: true,
      document: {
        schema: "platform.docker-runtime-intent/v1",
        intentId,
        combinedRenderSha256,
      },
    },
    activeReceipt: {
      trusted: true,
      sha256: activeReceiptSha256,
      document: {
        schema: "platform.docker-active-receipt/v2",
        intentId,
        combinedRenderSha256,
      },
    },
    activation: {
      trusted: true,
      status: "active",
      intentId,
      activeReceiptSha256,
      combinedRenderSha256,
    },
    expected: {
      intentId,
      activeReceiptSha256,
      combinedRenderSha256,
    },
  };
}
