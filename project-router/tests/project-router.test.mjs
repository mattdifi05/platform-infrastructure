import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { createServer as createTcpServer } from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { createProjectMetadataReader } from "../project-metadata.mjs";
import { validateVerifiedWorkloadLock, workloadContentDigest } from "../verified-workload-lock.mjs";
import {
  HOSTED_ROUTE_RAW_POLICY_CONTROLS,
  parseHostedRouteLock,
} from "../workload-route-lock.mjs";

const infraRoot = path.resolve(import.meta.dirname, "..", "..");
const testRoot = path.join(infraRoot, ".tmp", "project-router-tests", randomUUID());
const projectsRoot = path.join(testRoot, "projects");
const stateDir = path.join(testRoot, "state");
const stateFile = path.join(stateDir, "projects.json");
const workloadLockFile = path.join(stateDir, "hosted-workloads.lock.json");
const routerScript = path.join(infraRoot, "project-router", "server.mjs");

test("project-router proxies PHP, Node and Static projects only to dedicated upstreams", async (t) => {
  const verifiedLock = prepareFixture();
  const expectedWorkloadLockSha256 = createHash("sha256").update(readFileSync(workloadLockFile)).digest("hex");
  let phpRequestCount = 0;
  const phpServer = createServer((req, res) => {
    phpRequestCount += 1;
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end(`php-dedicated:${req.headers.host}:${req.url}`);
  });
  const nodeServer = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      runtime: "node-dedicated",
      host: req.headers.host,
      path: req.url,
    }));
  });
  const staticServer = createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end(`static-dedicated:${req.headers.host}:${req.url}`);
  });
  const controlServer = createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end(`control-center:${req.headers.host}:${req.url}`);
  });
  await listen(phpServer);
  await listen(nodeServer);
  await listen(staticServer);
  await listen(controlServer);

  const routerPort = await freePort();
  const child = spawn(process.execPath, [routerScript], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PROJECT_ROUTER_PORT: String(routerPort),
      PROJECT_ROUTER_UPSTREAM_TIMEOUT_MS: "100",
      PROJECTS_ROOT: projectsRoot,
      PROJECT_STATE_FILE: stateFile,
      PROJECT_ROUTER_WORKLOAD_LOCK_FILE: workloadLockFile,
      PROJECT_ROUTER_WORKLOAD_LOCK_MODE: "required",
      PROJECT_ROUTER_WORKLOAD_LOCK_SHA256: expectedWorkloadLockSha256,
      CONTROL_CENTER_HOST: "portal.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
      PHP_PROJECT_UPSTREAMS: `php-demo=http://127.0.0.1:${serverPort(phpServer)},fiplatform=http://127.0.0.1:${serverPort(phpServer)}`,
      NODE_PROJECT_UPSTREAMS: `node-demo=http://127.0.0.1:${serverPort(nodeServer)}`,
      STATIC_PROJECT_UPSTREAMS: `static-demo=http://127.0.0.1:${serverPort(staticServer)}`,
      PROJECT_UPSTREAMS: "legacy-php=http://fixture-app-web:3000",
      CONTROL_CENTER_UPSTREAM: `http://127.0.0.1:${serverPort(controlServer)}`,
      PROJECT_ROUTER_TEST_ALLOW_LOOPBACK: "true",
      PROJECT_ROUTER_TEST_ALLOW_LEGACY_DISCOVERY: "true",
      PROJECT_METADATA_MAX_BYTES: "4096",
      PROJECT_ROUTER_ALLOWED_UPSTREAMS: [
        `127.0.0.1:${serverPort(phpServer)}`,
        `127.0.0.1:${serverPort(nodeServer)}`,
        `127.0.0.1:${serverPort(staticServer)}`,
        `127.0.0.1:${serverPort(controlServer)}`,
      ].join(","),
      NODE_PROJECT_HOSTS: "node-demo=node-demo.localhost.com",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  t.after(async () => {
    await stopChild(child);
    chmodWritableSnapshot(path.join(stateDir, "verified-snapshots", "content-fixture"));
    await closeServer(phpServer);
    await closeServer(nodeServer);
    await closeServer(staticServer);
    await closeServer(controlServer);
    removeFixtureTree();
  });

  await waitForHealth(routerPort);

  const control = await httpGet(routerPort, "portal.localhost.com", "/");
  assert.equal(control.statusCode, 200);
  assert.match(control.body, /control-center:portal\.localhost\.com:\//);

  const php = await httpGet(routerPort, "php-demo.localhost.com", "/calendar?day=1");
  assert.equal(php.statusCode, 200);
  assert.equal(php.body, "php-dedicated:php-demo.localhost.com:/calendar?day=1");

  const fallbackPhp = await httpGet(routerPort, "legacy-php.localhost.com", "/fallback");
  assert.equal(fallbackPhp.statusCode, 503);
  assert.match(fallbackPhp.body, /PHP project has no dedicated upstream/);

  const fiplatform = await httpGet(routerPort, "fiplatform.localhost.com", "/");
  assert.equal(fiplatform.statusCode, 200);
  assert.equal(fiplatform.body, "php-dedicated:fiplatform.localhost.com:/");

  const fireportAlias = await httpGet(routerPort, "fireport.localhost.com", "/");
  assert.equal(fireportAlias.statusCode, 200);
  assert.equal(fireportAlias.body, "php-dedicated:fireport.localhost.com:/");

  writeFileSync(path.join(projectsRoot, "fiplatform", ".platform", "project.json"), `${JSON.stringify({
    projects: [{ slug: "fiplatform", name: "fiplatform", type: "php", aliases: ["attacker-alias"] }],
    type: "php",
  })}\n`);
  const signedAliasStillAvailable = await httpGet(routerPort, "fireport.localhost.com", "/signed-snapshot");
  assert.equal(signedAliasStillAvailable.statusCode, 200);
  const unsignedReplacement = await httpGet(routerPort, "attacker-alias.localhost.com", "/");
  assert.equal(unsignedReplacement.statusCode, 404);

  const nodeFirst = await httpGet(routerPort, "node-demo.localhost.com", "/api/ping");
  assert.equal(nodeFirst.statusCode, 200);
  const nodeFirstPayload = JSON.parse(nodeFirst.body);
  assert.equal(nodeFirstPayload.runtime, "node-dedicated");
  assert.equal(nodeFirstPayload.host, "node-demo.localhost.com");
  assert.equal(nodeFirstPayload.path, "/api/ping");

  const staticProject = await httpGet(routerPort, "static-demo.localhost.com", "/assets/app.css");
  assert.equal(staticProject.statusCode, 200);
  assert.equal(staticProject.body, "static-dedicated:static-demo.localhost.com:/assets/app.css");

  const phpStillAvailable = await httpGet(routerPort, "php-demo.localhost.com", "/after-node");
  assert.equal(phpStillAvailable.statusCode, 200);
  assert.equal(phpStillAvailable.body, "php-dedicated:php-demo.localhost.com:/after-node");

  const requestCountBeforeRedirect = phpRequestCount;
  const redirect = await httpGet(routerPort, "php-demo.localhost.com", "/redirect");
  assert.equal(redirect.statusCode, 302);
  assert.equal(redirect.headers.location, "http://169.254.169.254/latest/meta-data/");
  assert.equal(phpRequestCount, requestCountBeforeRedirect + 1);

  const absoluteTarget = await httpGet(routerPort, "php-demo.localhost.com", "//169.254.169.254/latest/meta-data/");
  assert.equal(absoluteTarget.statusCode, 400);
  assert.match(absoluteTarget.body, /invalid request target/);

  const metadataProject = await httpGet(routerPort, "metadata-demo.localhost.com", "/latest/meta-data/");
  assert.equal(metadataProject.statusCode, 404);
  assert.match(metadataProject.body, /Project not found/);

  const oversizedMetadata = await httpGet(routerPort, "oversized-demo.localhost.com", "/");
  assert.equal(oversizedMetadata.statusCode, 404);
  assert.match(oversizedMetadata.body, /Project not found/);

  const unsignedHostedClaim = await httpGet(routerPort, "unsigned-hosted-claim.localhost.com", "/");
  assert.equal(unsignedHostedClaim.statusCode, 404);
  assert.match(unsignedHostedClaim.body, /Project not found/);

  const legacyHostedClaim = await httpGet(routerPort, "legacy-php.localhost.com", "/");
  assert.equal(legacyHostedClaim.statusCode, 503);
  assert.match(legacyHostedClaim.body, /no dedicated upstream/);

  writeFileSync(stateFile, `${JSON.stringify({ projects: { "node-demo": { enabled: false } } }, null, 2)}\n`);
  const disabledNode = await httpGet(routerPort, "node-demo.localhost.com", "/api/ping");
  assert.equal(disabledNode.statusCode, 404);
  assert.match(disabledNode.body, /Project disabled/);

  writeFileSync(stateFile, `${JSON.stringify({ projects: { "node-demo": { enabled: true } } }, null, 2)}\n`);
  const nodeAfterEnable = await httpGet(routerPort, "node-demo.localhost.com", "/api/ping");
  assert.equal(nodeAfterEnable.statusCode, 200);
  const nodeAfterEnablePayload = JSON.parse(nodeAfterEnable.body);
  assert.equal(nodeAfterEnablePayload.runtime, "node-dedicated");
  assert.equal(nodeAfterEnablePayload.host, "node-demo.localhost.com");
  assert.equal(nodeAfterEnablePayload.path, "/api/ping");

  const missing = await httpGet(routerPort, "missing.localhost.com", "/");
  assert.equal(missing.statusCode, 404);
  assert.match(missing.body, /Project not found/);

  const lockedRoute = await httpGet(routerPort, "locked-demo.localhost.com", "/");
  assert.equal(lockedRoute.statusCode, 502);
  assert.match(lockedRoute.body, /upstream unavailable/);

  writeFileSync(workloadLockFile, `${JSON.stringify({
    version: 2,
    validatorVersion: "hosted-contract-v2",
    state: "verified",
    routes: [routeFixture({ service: "postgres", port: 5432 })],
  }, null, 2)}\n`);
  const forgedLockedRoute = await httpGet(routerPort, "locked-demo.localhost.com", "/");
  assert.equal(forgedLockedRoute.statusCode, 502);
  assert.match(forgedLockedRoute.body, /upstream unavailable/);

  writeFileSync(workloadLockFile, `${JSON.stringify({
    version: 2,
    validatorVersion: "hosted-contract-v2",
    state: "verified",
    routes: [routeFixture({ canonicalHost: "*.localhost.com", hosts: ["*.localhost.com"] })],
  }, null, 2)}\n`);
  const wildcardLockedRoute = await httpGet(routerPort, "locked-demo.localhost.com", "/");
  assert.equal(wildcardLockedRoute.statusCode, 502);
  assert.match(wildcardLockedRoute.body, /upstream unavailable/);

  writeFileSync(workloadLockFile, `${JSON.stringify(verifiedLock, null, 2)}\n`);
  const wildcardRequest = await httpGet(routerPort, "anything.example.invalid", "/");
  assert.equal(wildcardRequest.statusCode, 404);
  assert.match(wildcardRequest.body, /Project not found/);
  assert.equal(existsSync(path.join(projectsRoot, "php-demo", "public", "index.php")), true);
  assert.equal(stderr.includes("project-router error"), false);
  assert.equal(stderr.includes("169.254.169.254"), false);
  assert.match(stderr, /rejected project metadata for metadata-demo: PROJECT_METADATA_UNSIGNED/);
  assert.match(stderr, /rejected project metadata for oversized-demo: PROJECT_METADATA_UNSIGNED/);
});

test("project-router explicit lock-required mode rejects a missing lock and Compose enables it", async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "project-router-lock-required-"));
  const routerPort = await freePort();
  const missingLock = path.join(root, "missing.lock.json");
  const child = spawn(process.execPath, [path.join(infraRoot, "project-router", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PROJECT_ROUTER_PORT: String(routerPort),
      PROJECTS_ROOT: path.join(root, "projects"),
      PROJECT_STATE_FILE: path.join(root, "projects.json"),
      PROJECT_ROUTER_WORKLOAD_LOCK_FILE: missingLock,
      PROJECT_ROUTER_WORKLOAD_LOCK_MODE: "required",
      PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080",
      CONTROL_CENTER_UPSTREAM: "http://control-center:8080",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const result = await childOutputAndExit(child);
  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /Required hosted workload lock is unavailable/);
  rmSync(root, { recursive: true, force: true });

  const serverSource = readFileSync(path.join(infraRoot, "project-router", "server.mjs"), "utf8");
  const composeSource = readFileSync(path.join(infraRoot, "compose.yaml"), "utf8");
  assert.match(serverSource, /PROJECT_ROUTER_WORKLOAD_LOCK_MODE/);
  assert.doesNotMatch(serverSource, /process\.env\.NODE_ENV === "production"/);
  assert.match(composeSource, /PROJECT_ROUTER_WORKLOAD_LOCK_MODE:\s+required/);
});

test("project-router rejects IP and external-host upstream policy at production startup", async () => {
  for (const target of ["169.254.169.254:80", "example.com:80", "localhost:8080"]) {
    const routerPort = await freePort();
    const child = spawn(process.execPath, [routerScript], {
      cwd: infraRoot,
      env: {
        ...process.env,
        NODE_ENV: "production",
        PROJECT_ROUTER_WORKLOAD_LOCK_MODE: "optional",
        PROJECT_ROUTER_PORT: String(routerPort),
        PROJECT_ROUTER_ALLOWED_UPSTREAMS: target,
        CONTROL_CENTER_UPSTREAM: `http://${target}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stderr = await childOutputAndExit(child);
    assert.notEqual(stderr.code, 0);
    assert.doesNotMatch(stderr.stderr, /169\.254\.169\.254|example\.com|localhost:8080/);
  }
});

test("production routing ignores legacy discovery and environment maps", async (t) => {
  const root = path.join(infraRoot, ".tmp", "project-router-tests", randomUUID());
  const projects = path.join(root, "projects");
  const state = path.join(root, "state");
  mkdirSync(path.join(projects, "legacy-demo"), { recursive: true });
  mkdirSync(state, { recursive: true });
  writeFileSync(path.join(projects, "legacy-demo", "package.json"), "{}\n");
  writeFileSync(path.join(state, "projects.json"), "{\"projects\":{}}\n");
  const routerPort = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "project-router", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "production",
      PROJECT_ROUTER_PORT: String(routerPort),
      PROJECTS_ROOT: projects,
      PROJECT_STATE_FILE: path.join(state, "projects.json"),
      PROJECT_ROUTER_WORKLOAD_LOCK_FILE: path.join(state, "missing.lock.json"),
      PROJECT_ROUTER_WORKLOAD_LOCK_MODE: "optional",
      CONTROL_CENTER_HOST: "portal.localhost.com",
      CONTROL_CENTER_UPSTREAM: "http://control-center:8080",
      PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080,legacy-service:8080",
      NODE_PROJECT_UPSTREAMS: "legacy-demo=http://legacy-service:8080",
      PROJECT_ROUTER_TEST_ALLOW_LEGACY_DISCOVERY: "true",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(async () => {
    await stopChild(child);
    rmSync(root, { recursive: true, force: true });
  });
  await waitForHealth(routerPort);
  const response = await httpGet(routerPort, "legacy-demo.localhost.com", "/");
  assert.equal(response.statusCode, 404);
  assert.match(response.body, /Project not found/);
});

test("FG-042 production consumer rejects route-owner, sibling-upstream and wildcard substitutions", async (t) => {
  const substitutions = [
    ["route owner", { owner: "sibling-app" }],
    ["sibling upstream", { service: "sibling-app-web", upstream: "http://sibling-app-web:3000" }],
    ["wildcard hostname", { canonicalHost: "*.example.invalid", hosts: ["*.example.invalid"] }],
  ];

  for (const [label, override] of substitutions) {
    await t.test(label, async (t) => {
      const root = path.join(infraRoot, ".tmp", "project-router-tests", randomUUID());
      const lockFile = path.join(root, "hosted-workloads.lock.json");
      mkdirSync(root, { recursive: true });
      const verifiedLock = verifiedMetadataLockFixture(root);
      verifiedLock.routes = [routeFixture(override)];
      writeFileSync(lockFile, `${JSON.stringify(verifiedLock, null, 2)}\n`, { mode: 0o600 });
      chmodSync(lockFile, 0o600);

      const routerPort = await freePort();
      const child = spawn(process.execPath, [path.join(infraRoot, "project-router", "server.mjs")], {
        cwd: infraRoot,
        env: {
          ...process.env,
          NODE_ENV: "production",
          PROJECT_ROUTER_PORT: String(routerPort),
          PROJECT_ROUTER_WORKLOAD_LOCK_FILE: lockFile,
          PROJECT_ROUTER_WORKLOAD_LOCK_MODE: "required",
          PROJECT_ROUTER_WORKLOAD_LOCK_SHA256: sha256(readFileSync(lockFile)),
          CONTROL_CENTER_HOST: "portal.localhost.com",
          CONTROL_CENTER_UPSTREAM: "http://control-center:8080",
          PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080",
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      const result = await childOutputAndExit(child);
      assert.notEqual(result.code, 0);
      assert.doesNotMatch(result.stderr, /sibling-app|example\.invalid/);
      chmodWritableSnapshot(verifiedLock.snapshotGeneration);
      rmSync(root, { recursive: true, force: true });
    });
  }
});

test("project metadata budgets reject unsafe files before they can influence routing", async (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "project-metadata-budgets-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "project.json");
  const reader = createProjectMetadataReader({
    maxBytes: 256,
    maxDepth: 4,
    maxKeys: 8,
    maxNodes: 32,
    maxAliases: 2,
    maxArrayItems: 8,
    parseTimeoutMs: 1000,
  });

  writeFileSync(file, `${JSON.stringify({ type: "node", aliases: ["one", "two"] })}\n`);
  assert.deepEqual(await reader.read(file), { type: "node", aliases: ["one", "two"] });

  writeFileSync(file, JSON.stringify({ padding: "x".repeat(300) }));
  await assert.rejects(reader.read(file), (error) => error.code === "PROJECT_METADATA_SIZE");

  writeFileSync(file, JSON.stringify({ a: { b: { c: { d: { e: true } } } } }));
  await assert.rejects(reader.read(file), (error) => error.code === "PROJECT_METADATA_COMPLEXITY");

  writeFileSync(file, JSON.stringify(Object.fromEntries(Array.from({ length: 9 }, (_, index) => [`key${index}`, index]))));
  await assert.rejects(reader.read(file), (error) => error.code === "PROJECT_METADATA_COMPLEXITY");

  writeFileSync(file, JSON.stringify({ aliases: ["one", "two", "three"] }));
  await assert.rejects(reader.read(file), (error) => error.code === "PROJECT_METADATA_COMPLEXITY");

  const symlink = path.join(root, "linked.json");
  symlinkSync(file, symlink);
  await assert.rejects(reader.read(symlink), (error) => error.code === "PROJECT_METADATA_FILE_TYPE");
});

test("project metadata cache is content-addressed and bound to the verified lock digest", async (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "project-metadata-cache-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "project.json");
  let parses = 0;
  const reader = createProjectMetadataReader({
    parser: async (text) => {
      parses += 1;
      return JSON.parse(text);
    },
  });
  const first = `${JSON.stringify({ type: "node", aliases: ["one"] })}\n`;
  writeFileSync(file, first);
  const contentDigest = createHash("sha256").update(first).digest("hex");
  const firstEpoch = "a".repeat(64);
  await reader.read(file, { expectedSha256: contentDigest, expectedSizeBytes: Buffer.byteLength(first), trustedEpoch: firstEpoch });
  await reader.read(file, { expectedSha256: contentDigest, expectedSizeBytes: Buffer.byteLength(first), trustedEpoch: firstEpoch });
  assert.equal(parses, 1);
  await reader.read(file, { expectedSha256: contentDigest, expectedSizeBytes: Buffer.byteLength(first), trustedEpoch: "b".repeat(64) });
  assert.equal(parses, 2, "a new verified workload digest must invalidate metadata cache reuse");

  const originalTimes = statSync(file);
  const changed = first.replace("one", "two");
  writeFileSync(file, changed);
  utimesSync(file, originalTimes.atime, originalTimes.mtime);
  assert.equal(Buffer.byteLength(changed), Buffer.byteLength(first));
  await assert.rejects(
    reader.read(file, { expectedSha256: contentDigest, expectedSizeBytes: Buffer.byteLength(first), trustedEpoch: firstEpoch }),
    (error) => error.code === "PROJECT_METADATA_TRUST",
  );
  assert.equal(parses, 2, "digest mismatch must fail before parsing");

  await reader.read(file);
  assert.equal(parses, 3, "same-size and same-mtime replacement must not reuse the old local cache entry");
});

test("project metadata parse-time budget interrupts an unresponsive parser", async (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "project-metadata-timeout-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "project.json");
  writeFileSync(file, '{"type":"node"}\n');
  const reader = createProjectMetadataReader({
    parseTimeoutMs: 25,
    parser: () => new Promise(() => {}),
  });
  const started = Date.now();
  await assert.rejects(reader.read(file), (error) => error.code === "PROJECT_METADATA_TIMEOUT");
  assert.equal(Date.now() - started < 500, true);
});

test("project metadata trust rejects legacy locks, pointer tampering, and digest tampering", (t) => {
  const root = realpathSync.native(mkdtempSync(path.join(os.tmpdir(), "project-metadata-lock-")));
  t.after(() => {
    chmodWritableSnapshot(path.join(root, "snapshots", "content-fixture"));
    rmSync(root, { recursive: true, force: true });
  });
  const lock = verifiedMetadataLockFixture(root);
  assert.equal(validateVerifiedWorkloadLock(lock).projectMetadata.size, 1);

  const legacy = structuredClone(lock);
  legacy.version = 1;
  delete legacy.validatorVersion;
  assert.throws(() => validateVerifiedWorkloadLock(legacy), /policy\/version/);

  const pointerTamper = structuredClone(lock);
  pointerTamper.workloads[0].projectMetadataPath = path.join(lock.snapshotGeneration, "different.json");
  assert.throws(() => validateVerifiedWorkloadLock(pointerTamper), /pointer/);

  const digestTamper = structuredClone(lock);
  digestTamper.files[0].sha256 = "d".repeat(64);
  assert.throws(() => validateVerifiedWorkloadLock(digestTamper), /content digest/);
});

test("project-router fails startup when the activated lock digest is missing or wrong", async () => {
  for (const expectedSha256 of [undefined, "0".repeat(64)]) {
    prepareFixture();
    const routerPort = await freePort();
    const child = spawnFixtureRouter(routerPort, expectedSha256);
    const result = await childOutputAndExit(child);
    assert.notEqual(result.code, 0);
    assert.match(
      result.stderr,
      expectedSha256 === undefined
        ? /expected digest is missing/
        : /digest differs from the activated receipt/,
    );
    removeFixtureTree();
  }
});

test("project-router keeps the startup route snapshot frozen and rejects a replaced lock on restart", async (t) => {
  prepareFixture();
  const originalSha256 = lockSha256();
  const routerPort = await freePort();
  const child = spawnFixtureRouter(routerPort, originalSha256);
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  t.after(async () => {
    await stopChild(child);
    removeFixtureTree();
  });

  await waitForHealth(routerPort);
  const originalRoute = await httpGet(routerPort, "locked-demo.localhost.com", "/before-replacement");
  assert.equal(originalRoute.statusCode, 502);
  assert.match(stderr, /fixture-app-web:3000/);

  const replacement = JSON.parse(readFileSync(workloadLockFile, "utf8"));
  replacement.workloads[0].services = [{
    name: "fixture-app-alt",
    role: "web",
    routes: [manifestRouteFixture({ port: 3001 })],
  }];
  replacement.routes = [routeFixture({
    service: "fixture-app-alt",
    port: 3001,
    upstream: "http://fixture-app-alt:3001",
  })];
  writeLock(replacement);

  const healthAfterReplacement = await httpGet(routerPort, "portal.localhost.com", "/__health");
  assert.equal(healthAfterReplacement.statusCode, 500);
  assert.match(healthAfterReplacement.body, /internal proxy error/);

  const routeAfterReplacement = await httpGet(routerPort, "locked-demo.localhost.com", "/after-replacement");
  assert.equal(routeAfterReplacement.statusCode, 502);
  assert.match(stderr, /fixture-app-web:3000/);
  assert.doesNotMatch(stderr, /fixture-app-alt:3001/);

  await stopChild(child);
  const restartPort = await freePort();
  const restarted = spawnFixtureRouter(restartPort, originalSha256);
  const restartResult = await childOutputAndExit(restarted);
  assert.notEqual(restartResult.code, 0);
  assert.match(restartResult.stderr, /digest differs from the activated receipt/);
});

test("project-router hashes exact lock bytes, not a semantically equivalent JSON object", async () => {
  prepareFixture();
  const originalBytes = readFileSync(workloadLockFile);
  const originalObject = JSON.parse(originalBytes.toString("utf8"));
  const originalSha256 = sha256(originalBytes);
  const equivalentBytes = Buffer.from(JSON.stringify(originalObject), "utf8");
  assert.deepEqual(JSON.parse(equivalentBytes.toString("utf8")), originalObject);
  assert.notDeepEqual(equivalentBytes, originalBytes);
  writeFileSync(workloadLockFile, equivalentBytes);

  const routerPort = await freePort();
  const child = spawnFixtureRouter(routerPort, originalSha256);
  const result = await childOutputAndExit(child);
  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /digest differs from the activated receipt/);
  removeFixtureTree();
});

test("unsigned metadata and legacy mappings cannot claim a signed workload endpoint", async (t) => {
  prepareFixture();
  const routerPort = await freePort();
  const child = spawnFixtureRouter(routerPort, lockSha256(), {
    PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080,fixture-app-web:3000",
    PROJECT_UPSTREAMS: "legacy-php=http://fixture-app-web:3000",
  });
  t.after(async () => {
    await stopChild(child);
    removeFixtureTree();
  });

  await waitForHealth(routerPort);
  const metadataClaim = await httpGet(routerPort, "unsigned-hosted-claim.localhost.com", "/");
  assert.equal(metadataClaim.statusCode, 404);
  assert.match(metadataClaim.body, /Project not found/);

  const legacyClaim = await httpGet(routerPort, "legacy-php.localhost.com", "/");
  assert.equal(legacyClaim.statusCode, 503);
  assert.match(legacyClaim.body, /no dedicated upstream/);
});

test("canonical project slugs outrank aliases and aliases cannot claim signed routes", async (t) => {
  prepareFixture();
  const lockedProjectConfig = path.join(projectsRoot, "locked-demo", ".platform", "project.json");
  mkdirSync(path.dirname(lockedProjectConfig), { recursive: true });
  writeFileSync(lockedProjectConfig, `${JSON.stringify({
    type: "node",
    projects: [
      {
        slug: "alias-claim",
        type: "node",
        aliases: ["locked-demo"],
        upstream: "http://fixture-app-web:3000",
      },
      {
        slug: "locked-demo",
        type: "node",
      },
    ],
  }, null, 2)}\n`);
  writeFileSync(stateFile, `${JSON.stringify({
    projects: { "alias-claim": { enabled: false } },
  }, null, 2)}\n`);

  const routerPort = await freePort();
  const child = spawnFixtureRouter(routerPort, lockSha256(), {
    PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080,fixture-app-web:3000",
  });
  t.after(async () => {
    await stopChild(child);
    removeFixtureTree();
  });

  await waitForHealth(routerPort);
  const canonicalRoute = await httpGet(routerPort, "locked-demo.localhost.com", "/canonical");
  assert.equal(canonicalRoute.statusCode, 502);
  assert.match(canonicalRoute.body, /upstream unavailable/);

  writeFileSync(lockedProjectConfig, `${JSON.stringify({
    type: "node",
    projects: [{
      slug: "alias-claim",
      type: "node",
      aliases: ["locked-demo"],
      upstream: "http://fixture-app-web:3000",
    }],
  }, null, 2)}\n`);
  writeFileSync(stateFile, `${JSON.stringify({ projects: {} }, null, 2)}\n`);

  const aliasClaim = await httpGet(routerPort, "locked-demo.localhost.com", "/alias");
  assert.equal(aliasClaim.statusCode, 502);
  assert.match(aliasClaim.body, /upstream unavailable/);
});

test("forged nested-id route locks cannot assign a child service to its parent", () => {
  for (const workloadIds of [
    ["billing", "billing-api"],
    ["billing-api", "billing"],
    ["billing-api-admin", "billing", "billing-api"],
  ]) {
    const parentId = "billing";
    const childId = workloadIds.find((id) => id !== parentId && id.startsWith(`${parentId}-`));
    const forged = verifiedRouteLock();
    forged.workloads = workloadIds.map((id) => ({
      id,
      services: [{ name: id === parentId ? `${childId}-web` : `${id}-worker` }],
    }));
    forged.routes = [{
      workloadId: parentId,
      slug: "billing",
      service: `${childId}-web`,
      port: 3000,
      upstream: `http://${childId}-web:3000`,
    }];
    assert.throws(
      () => parseHostedRouteLock(forged),
      /prefix-colliding|prefix-disjoint|canonical owner|declarations are invalid/i,
    );
  }
});

test("project-router enforces the exact 61-byte workload-id boundary before route lineage", () => {
  const maximumId = `b${"a".repeat(60)}`;
  const valid = verifiedRouteLock();
  valid.workloads = [{
    id: maximumId,
    services: [{
      name: `${maximumId}-x`,
      role: "web",
      routes: [manifestRouteFixture({
        owner: maximumId,
        slug: "ok",
        canonicalHost: "ok.localhost.com",
        hosts: ["ok.localhost.com"],
      })],
    }],
  }];
  valid.routes = [routeFixture({
    owner: maximumId,
    workloadId: maximumId,
    slug: "ok",
    canonicalHost: "ok.localhost.com",
    hosts: ["ok.localhost.com"],
    service: `${maximumId}-x`,
    upstream: `http://${maximumId}-x:3000`,
  })];
  assert.equal(parseHostedRouteLock(valid).routes.get("ok"), `http://${maximumId}-x:3000`);

  for (const length of [62, 63, 64]) {
    const oversizedId = `b${"a".repeat(length - 1)}`;
    const forged = structuredClone(valid);
    forged.workloads[0].id = oversizedId;
    forged.workloads[0].services[0].name = `${oversizedId}-x`;
    forged.routes[0].workloadId = oversizedId;
    forged.routes[0].service = `${oversizedId}-x`;
    forged.routes[0].upstream = `http://${oversizedId}-x:3000`;
    assert.throws(
      () => parseHostedRouteLock(forged),
      /Hosted workload declarations are invalid/i,
      `${length}-byte workload id bypassed the project-router boundary`,
    );
  }
});

test("exact route owners preserve non-colliding and single-owner textual prefixes", () => {
  const nonColliding = verifiedRouteLock();
  nonColliding.workloads = [
    { id: "billing", services: [{ name: "billing-web", role: "worker", routes: [] }] },
    { id: "billingapi", services: [{ name: "billingapi-web", role: "web", routes: [manifestRouteFixture({
      owner: "billingapi",
      slug: "billingapi",
      canonicalHost: "billingapi.localhost.com",
      hosts: ["billingapi.localhost.com"],
    })] }] },
  ];
  nonColliding.routes = [routeFixture({
    owner: "billingapi",
    workloadId: "billingapi",
    slug: "billingapi",
    canonicalHost: "billingapi.localhost.com",
    hosts: ["billingapi.localhost.com"],
    service: "billingapi-web",
    upstream: "http://billingapi-web:3000",
  })];
  assert.equal(parseHostedRouteLock(nonColliding).routes.get("billingapi"), "http://billingapi-web:3000");

  const singleOwner = verifiedRouteLock();
  singleOwner.workloads = [{
    id: "billing",
    services: [{ name: "billing-api-web", role: "web", routes: [manifestRouteFixture({
      owner: "billing",
      slug: "billing",
      canonicalHost: "billing.localhost.com",
      hosts: ["billing.localhost.com"],
    })] }],
  }];
  singleOwner.routes = [routeFixture({
    owner: "billing",
    workloadId: "billing",
    slug: "billing",
    canonicalHost: "billing.localhost.com",
    hosts: ["billing.localhost.com"],
    service: "billing-api-web",
    upstream: "http://billing-api-web:3000",
  })];
  assert.equal(parseHostedRouteLock(singleOwner).routes.get("billing"), "http://billing-api-web:3000");

  const wrongExactOwner = structuredClone(nonColliding);
  wrongExactOwner.routes[0] = {
    ...wrongExactOwner.routes[0],
    owner: "billing",
    workloadId: "billing",
  };
  assert.throws(() => parseHostedRouteLock(wrongExactOwner), /verified lock contract/);

  const incompleteProtectedResources = structuredClone(nonColliding);
  delete incompleteProtectedResources.rawPolicyReceipt.protectedResourceNames.volumes;
  assert.throws(() => parseHostedRouteLock(incompleteProtectedResources), /policy\/render receipt is incomplete/);
});

test("project-router derives exact route lineage from declared api and web services", () => {
  const validWeb = verifiedRouteLock();
  assert.equal(parseHostedRouteLock(validWeb).routes.get("locked-demo"), "http://fixture-app-web:3000");

  const validApi = verifiedRouteLock();
  validApi.workloads[0].services[0].role = "api";
  assert.equal(parseHostedRouteLock(validApi).routes.get("locked-demo"), "http://fixture-app-web:3000");

  const workerForgery = verifiedRouteLock();
  workerForgery.workloads[0].services = [{
    name: "fixture-app-worker",
    role: "worker",
    routes: [],
  }];
  workerForgery.routes = [routeFixture({
    slug: "admin",
    canonicalHost: "admin.localhost.com",
    hosts: ["admin.localhost.com"],
    service: "fixture-app-worker",
    port: 9999,
    upstream: "http://fixture-app-worker:9999",
  })];
  assert.throws(() => parseHostedRouteLock(workerForgery), /canonical route|route lineage/i);

  for (const mutate of [
    (lock) => { lock.routes[0].workloadId = "FIXTURE-APP"; },
    (lock) => { lock.routes[0].slug = "Locked-demo"; },
    (lock) => { lock.routes[0].service = "FIXTURE-APP-WEB"; },
    (lock) => { lock.routes[0].service = "fixture-app-worker"; },
    (lock) => { lock.routes[0].port = 9999; lock.routes[0].upstream = "http://fixture-app-web:9999"; },
    (lock) => { lock.routes[0].upstream = "http://fixture-app-web:9999"; },
    (lock) => { lock.routes[0].extra = true; },
    (lock) => { lock.workloads[0].services[0].routes[0].extra = true; },
  ]) {
    const forged = verifiedRouteLock();
    mutate(forged);
    assert.throws(() => parseHostedRouteLock(forged), /canonical route|route lineage/i);
  }
});

function removeFixtureTree() {
  chmodWritableSnapshot(path.join(stateDir, "verified-snapshots", "content-fixture"));
  rmSync(testRoot, { recursive: true, force: true });
}

function prepareFixture() {
  removeFixtureTree();
  mkdirSync(path.join(projectsRoot, "php-demo", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "legacy-php", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "fiplatform", ".platform"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "fiplatform", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "node-demo"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "static-demo", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "metadata-demo", ".platform"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "oversized-demo", ".platform"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "unsigned-hosted-claim", ".platform"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "locked-demo"), { recursive: true });
  const snapshotRoot = path.join(stateDir, "verified-snapshots");
  const snapshotGeneration = path.join(snapshotRoot, "content-fixture");
  mkdirSync(snapshotGeneration, { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(path.join(projectsRoot, "php-demo", "public", "index.php"), "<?php echo 'php-demo';\n");
  writeFileSync(path.join(projectsRoot, "legacy-php", "public", "index.php"), "<?php echo 'legacy-php';\n");
  const fiplatformMetadata = `${JSON.stringify({
    projects: [
      {
        slug: "fiplatform",
        name: "fiplatform",
        type: "php",
        aliases: ["fireport"],
      },
    ],
    type: "php",
  }, null, 2)}\n`;
  const fiplatformMetadataSource = path.join(projectsRoot, "fiplatform", ".platform", "project.json");
  const fiplatformMetadataSnapshot = path.join(snapshotGeneration, "project-metadata.json");
  writeFileSync(fiplatformMetadataSource, fiplatformMetadata);
  writeFileSync(fiplatformMetadataSnapshot, fiplatformMetadata);
  chmodSync(fiplatformMetadataSnapshot, 0o400);
  chmodSync(snapshotGeneration, 0o500);
  chmodSync(snapshotRoot, 0o700);
  writeFileSync(path.join(projectsRoot, "fiplatform", "public", "index.php"), "<?php echo 'fiplatform';\n");
  writeFileSync(path.join(projectsRoot, "node-demo", "package.json"), `${JSON.stringify({ scripts: { start: "node server.mjs" } }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "static-demo", "public", "index.html"), "<!doctype html><title>static</title>\n");
  writeFileSync(path.join(projectsRoot, "metadata-demo", "package.json"), `${JSON.stringify({ scripts: { start: "node server.mjs" } }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "metadata-demo", ".platform", "project.json"), `${JSON.stringify({
    type: "node",
    upstream: "http://169.254.169.254:80",
  }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "oversized-demo", "package.json"), `${JSON.stringify({ scripts: { start: "node server.mjs" } }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "oversized-demo", ".platform", "project.json"), `${JSON.stringify({
    type: "node",
    padding: "x".repeat(8192),
  })}\n`);
  writeFileSync(path.join(projectsRoot, "unsigned-hosted-claim", "package.json"), `${JSON.stringify({ scripts: { start: "node server.mjs" } }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "unsigned-hosted-claim", ".platform", "project.json"), `${JSON.stringify({
    type: "node",
    upstream: "http://fixture-app-web:3000",
  }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "locked-demo", "package.json"), `${JSON.stringify({ scripts: { start: "node server.mjs" } }, null, 2)}\n`);
  writeFileSync(stateFile, `${JSON.stringify({ projects: {} }, null, 2)}\n`);
  const metadataStat = statSync(fiplatformMetadataSnapshot, { bigint: true });
  const snapshotRootStat = statSync(snapshotRoot, { bigint: true });
  const snapshotGenerationStat = statSync(snapshotGeneration, { bigint: true });
  const metadataRecord = {
    kind: "project-metadata",
    workloadId: "fixture-app",
    sourcePath: fiplatformMetadataSource,
    path: fiplatformMetadataSnapshot,
    sha256: createHash("sha256").update(fiplatformMetadata).digest("hex"),
    sizeBytes: Buffer.byteLength(fiplatformMetadata),
    snapshot: true,
    snapshotDevice: String(metadataStat.dev),
    snapshotInode: String(metadataStat.ino),
    snapshotUid: String(metadataStat.uid),
  };
  const workloadLock = {
    ...verifiedRouteLock(),
    snapshotRoot,
    snapshotGeneration,
    snapshotRootIdentity: statIdentity(snapshotRootStat),
    snapshotGenerationIdentity: statIdentity(snapshotGenerationStat),
    workloads: [{
      id: "fixture-app",
      services: [{ name: "fixture-app-web", role: "web", routes: [manifestRouteFixture()] }],
      projectMetadataSourcePath: fiplatformMetadataSource,
      projectMetadataPath: fiplatformMetadataSnapshot,
    }],
    files: [metadataRecord],
  };
  workloadLock.workloadContentSha256 = workloadContentDigest(workloadLock.files);
  writeFileSync(workloadLockFile, `${JSON.stringify(workloadLock, null, 2)}\n`, { mode: 0o600 });
  chmodSync(workloadLockFile, 0o600);
  return workloadLock;
}

function verifiedMetadataLockFixture(root) {
  const sourceRoot = path.join(root, "source");
  const snapshotRoot = path.join(root, "snapshots");
  const snapshotGeneration = path.join(snapshotRoot, "content-fixture");
  mkdirSync(sourceRoot, { recursive: true });
  mkdirSync(snapshotGeneration, { recursive: true });
  const sourcePath = path.join(sourceRoot, "project.json");
  const snapshotPath = path.join(snapshotGeneration, "project.json");
  const content = '{"type":"node"}\n';
  writeFileSync(sourcePath, content);
  writeFileSync(snapshotPath, content, { mode: 0o400 });
  chmodSync(snapshotPath, 0o400);
  chmodSync(snapshotGeneration, 0o500);
  chmodSync(snapshotRoot, 0o700);
  const fileStat = statSync(snapshotPath, { bigint: true });
  const record = {
    kind: "project-metadata",
    workloadId: "fixture-app",
    sourcePath,
    path: snapshotPath,
    sha256: createHash("sha256").update(content).digest("hex"),
    sizeBytes: Buffer.byteLength(content),
    snapshot: true,
    snapshotDevice: String(fileStat.dev),
    snapshotInode: String(fileStat.ino),
    snapshotUid: String(fileStat.uid),
  };
  const lock = {
    ...verifiedRouteLock(),
    state: "verified",
    snapshotRoot,
    snapshotGeneration,
    snapshotRootIdentity: statIdentity(statSync(snapshotRoot, { bigint: true })),
    snapshotGenerationIdentity: statIdentity(statSync(snapshotGeneration, { bigint: true })),
    workloads: [{
      id: "fixture-app",
      services: [{ name: "fixture-app-web", role: "web", routes: [manifestRouteFixture()] }],
      projectMetadataSourcePath: sourcePath,
      projectMetadataPath: snapshotPath,
    }],
    files: [record],
    routes: [routeFixture()],
  };
  lock.workloadContentSha256 = workloadContentDigest(lock.files);
  return lock;
}

function statIdentity(stat) {
  return {
    device: String(stat.dev),
    inode: String(stat.ino),
    uid: String(stat.uid),
    mode: Number(stat.mode & 0o777n),
  };
}

function chmodWritableSnapshot(snapshotGeneration) {
  try {
    chmodSync(snapshotGeneration, 0o700);
  } catch {
    // The fixture may have been removed before cleanup.
  }
}

function verifiedRouteLock() {
  return {
    version: 4,
    validatorVersion: "hosted-contract-v4",
    state: "verified",
    rawPolicyVersion: "hosted-raw-v3",
    rawPolicyControls: HOSTED_ROUTE_RAW_POLICY_CONTROLS,
    rawPolicyReceipt: {
      policyVersion: "hosted-raw-v3",
      controls: HOSTED_ROUTE_RAW_POLICY_CONTROLS,
      protectedNetworkNames: [],
      protectedResourceNames: {
        configs: [],
        networks: [],
        secrets: [],
        services: [],
        volumes: [],
      },
    },
    rawPolicySha256: "a".repeat(64),
    workloadContentSha256: "b".repeat(64),
    coreRenderSha256: "c".repeat(64),
    combinedRenderSha256: "d".repeat(64),
    workloads: [{
      id: "fixture-app",
      services: [{
        name: "fixture-app-web",
        role: "web",
        routes: [manifestRouteFixture()],
      }],
    }],
    routes: [routeFixture()],
  };
}

function routeFixture(overrides = {}) {
  return {
    owner: "fixture-app",
    workloadId: "fixture-app",
    slug: "locked-demo",
    aliases: [],
    canonicalHost: "locked-demo.localhost.com",
    hosts: ["locked-demo.localhost.com"],
    service: "fixture-app-web",
    port: 3000,
    upstream: "http://fixture-app-web:3000",
    ...overrides,
  };
}

function manifestRouteFixture(overrides = {}) {
  const route = routeFixture(overrides);
  return {
    owner: route.owner,
    slug: route.slug,
    aliases: route.aliases,
    canonicalHost: route.canonicalHost,
    hosts: route.hosts,
    port: route.port,
  };
}

function writeLock(lock) {
  writeFileSync(workloadLockFile, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
  chmodSync(workloadLockFile, 0o600);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function lockSha256() {
  return sha256(readFileSync(workloadLockFile));
}

function spawnFixtureRouter(routerPort, expectedSha256, extraEnv = {}) {
  const env = {
    ...process.env,
    NODE_ENV: "test",
    PROJECT_ROUTER_PORT: String(routerPort),
    PROJECT_ROUTER_UPSTREAM_TIMEOUT_MS: "100",
    PROJECTS_ROOT: projectsRoot,
    PROJECT_STATE_FILE: stateFile,
    PROJECT_ROUTER_WORKLOAD_LOCK_FILE: workloadLockFile,
    PROJECT_ROUTER_WORKLOAD_LOCK_MODE: "required",
    CONTROL_CENTER_HOST: "portal.localhost.com",
    PROJECT_HOST_SUFFIX: ".localhost.com",
    PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080",
    CONTROL_CENTER_UPSTREAM: "http://control-center:8080",
    PROJECT_ROUTER_TEST_ALLOW_LEGACY_DISCOVERY: "true",
    ...extraEnv,
  };
  delete env.PROJECT_ROUTER_WORKLOAD_LOCK_SHA256;
  if (expectedSha256 !== undefined) {
    env.PROJECT_ROUTER_WORKLOAD_LOCK_SHA256 = expectedSha256;
  }
  return spawn(process.execPath, [routerScript], {
    cwd: infraRoot,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createTcpServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function serverPort(server) {
  return server.address().port;
}

function childOutputAndExit(child, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Child did not fail closed before the test timeout."));
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolve({ code, stderr });
    });
  });
}

async function waitForHealth(port) {
  const started = Date.now();
  while (Date.now() - started < 10000) {
    try {
      const response = await httpGet(port, "portal.localhost.com", "/__health");
      if (response.statusCode === 200) return;
    } catch {
      // Keep probing until the router has bound its port.
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error("Timed out waiting for project-router health.");
}

function httpGet(port, host, requestPath) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: "127.0.0.1",
      port,
      path: requestPath,
      method: "GET",
      headers: { host },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function stopChild(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode) {
      resolve();
      return;
    }
    if (process.platform === "win32") {
      const killer = spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], { stdio: "ignore" });
      killer.once("exit", () => resolve());
      killer.once("error", () => {
        child.kill("SIGKILL");
        resolve();
      });
      return;
    }
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 3000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}
