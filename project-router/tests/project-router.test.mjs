import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { createServer as createTcpServer } from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { createProjectMetadataReader } from "../project-metadata.mjs";
import { validateVerifiedWorkloadLock, workloadContentDigest } from "../verified-workload-lock.mjs";

const infraRoot = path.resolve(import.meta.dirname, "..", "..");
const testRoot = path.join(infraRoot, ".tmp", "project-router-tests", randomUUID());
const projectsRoot = path.join(testRoot, "projects");
const stateDir = path.join(testRoot, "state");
const stateFile = path.join(stateDir, "projects.json");
const workloadLockFile = path.join(stateDir, "hosted-workloads.lock.json");

test("project-router proxies PHP, Node and Static projects only to dedicated upstreams", async (t) => {
  const verifiedLock = prepareFixture();
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
  const child = spawn(process.execPath, [path.join(infraRoot, "project-router", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PROJECT_ROUTER_PORT: String(routerPort),
      PROJECTS_ROOT: projectsRoot,
      PROJECT_STATE_FILE: stateFile,
      PROJECT_ROUTER_WORKLOAD_LOCK_FILE: workloadLockFile,
      CONTROL_CENTER_HOST: "portal.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
      PHP_PROJECT_UPSTREAMS: `php-demo=http://127.0.0.1:${serverPort(phpServer)},fiplatform=http://127.0.0.1:${serverPort(phpServer)}`,
      NODE_PROJECT_UPSTREAMS: `node-demo=http://127.0.0.1:${serverPort(nodeServer)}`,
      STATIC_PROJECT_UPSTREAMS: `static-demo=http://127.0.0.1:${serverPort(staticServer)}`,
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
    rmSync(testRoot, { recursive: true, force: true });
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
  assert.equal(metadataProject.statusCode, 503);
  assert.match(metadataProject.body, /no dedicated upstream/);

  const oversizedMetadata = await httpGet(routerPort, "oversized-demo.localhost.com", "/");
  assert.equal(oversizedMetadata.statusCode, 404);
  assert.match(oversizedMetadata.body, /Project not found/);

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
  assert.equal(forgedLockedRoute.statusCode, 500);
  assert.match(forgedLockedRoute.body, /internal proxy error/);

  writeFileSync(workloadLockFile, `${JSON.stringify({
    version: 2,
    validatorVersion: "hosted-contract-v2",
    state: "verified",
    routes: [routeFixture({ canonicalHost: "*.localhost.com", hosts: ["*.localhost.com"] })],
  }, null, 2)}\n`);
  const wildcardLockedRoute = await httpGet(routerPort, "locked-demo.localhost.com", "/");
  assert.equal(wildcardLockedRoute.statusCode, 500);
  assert.match(wildcardLockedRoute.body, /internal proxy error/);

  writeFileSync(workloadLockFile, `${JSON.stringify(verifiedLock, null, 2)}\n`);
  const wildcardRequest = await httpGet(routerPort, "anything.example.invalid", "/");
  assert.equal(wildcardRequest.statusCode, 404);
  assert.match(wildcardRequest.body, /Project not found/);

  assert.equal(existsSync(path.join(projectsRoot, "php-demo", "public", "index.php")), true);
  assert.equal(stderr.includes("project-router error"), false);
  assert.equal(stderr.includes("169.254.169.254"), false);
  assert.match(stderr, /service allowlist policy violation/);
  assert.match(stderr, /rejected project metadata for oversized-demo: PROJECT_METADATA_SIZE/);
});

test("project-router rejects IP and external-host upstream policy at production startup", async () => {
  for (const target of ["169.254.169.254:80", "example.com:80", "localhost:8080"]) {
    const routerPort = await freePort();
    const child = spawn(process.execPath, [path.join(infraRoot, "project-router", "server.mjs")], {
      cwd: infraRoot,
      env: {
        ...process.env,
        NODE_ENV: "production",
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
          CONTROL_CENTER_HOST: "portal.localhost.com",
          CONTROL_CENTER_UPSTREAM: "http://control-center:8080",
          PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080",
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString("utf8");
      });
      t.after(async () => {
        await stopChild(child);
        chmodWritableSnapshot(verifiedLock.snapshotGeneration);
        rmSync(root, { recursive: true, force: true });
      });

      await waitForHealth(routerPort);
      const response = await httpGet(routerPort, "locked-demo.localhost.com", "/");
      assert.equal(response.statusCode, 500);
      assert.match(response.body, /internal proxy error/);
      assert.match(stderr, /project-router request failed/);
      assert.doesNotMatch(stderr, /sibling-app|example\.invalid/);
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

function prepareFixture() {
  rmSync(testRoot, { recursive: true, force: true });
  mkdirSync(path.join(projectsRoot, "php-demo", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "legacy-php", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "fiplatform", ".platform"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "fiplatform", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "node-demo"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "static-demo", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "metadata-demo", ".platform"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "oversized-demo", ".platform"), { recursive: true });
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
    version: 2,
    validatorVersion: "hosted-contract-v2",
    state: "verified",
    snapshotRoot,
    snapshotGeneration,
    snapshotRootIdentity: statIdentity(statSync(snapshotRoot, { bigint: true })),
    snapshotGenerationIdentity: statIdentity(statSync(snapshotGeneration, { bigint: true })),
    workloads: [{ id: "fixture-app", projectMetadataSourcePath: sourcePath, projectMetadataPath: snapshotPath }],
    files: [record],
    routes: [{ workloadId: "fixture-app", slug: "fixture", service: "fixture-app-web", port: 3000, upstream: "http://fixture-app-web:3000" }],
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
    version: 2,
    validatorVersion: "hosted-contract-v2",
    state: "verified",
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

function childOutputAndExit(child) {
  return new Promise((resolve, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", reject);
    child.once("exit", (code) => resolve({ code, stderr }));
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
