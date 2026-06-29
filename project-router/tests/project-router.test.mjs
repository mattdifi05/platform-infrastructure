import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { createServer as createTcpServer } from "node:net";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

const infraRoot = path.resolve(import.meta.dirname, "..", "..");
const testRoot = path.join(infraRoot, ".tmp", "project-router-tests", randomUUID());
const projectsRoot = path.join(testRoot, "projects");
const stateDir = path.join(testRoot, "state");
const stateFile = path.join(stateDir, "projects.json");

test("project-router proxies PHP, Node and Static projects only to dedicated upstreams", async (t) => {
  prepareFixture();
  const phpServer = createServer((req, res) => {
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
      PROJECT_ROUTER_PORT: String(routerPort),
      PROJECTS_ROOT: projectsRoot,
      PROJECT_STATE_FILE: stateFile,
      CONTROL_CENTER_HOST: "portal.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
      PHP_PROJECT_UPSTREAMS: `php-demo=http://127.0.0.1:${serverPort(phpServer)},fiplatform=http://127.0.0.1:${serverPort(phpServer)}`,
      NODE_PROJECT_UPSTREAMS: `node-demo=http://127.0.0.1:${serverPort(nodeServer)}`,
      STATIC_PROJECT_UPSTREAMS: `static-demo=http://127.0.0.1:${serverPort(staticServer)}`,
      CONTROL_CENTER_UPSTREAM: `http://127.0.0.1:${serverPort(controlServer)}`,
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

  assert.equal(existsSync(path.join(projectsRoot, "php-demo", "public", "index.php")), true);
  assert.equal(stderr.includes("project-router error"), false);
});

function prepareFixture() {
  rmSync(testRoot, { recursive: true, force: true });
  mkdirSync(path.join(projectsRoot, "php-demo", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "legacy-php", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "fiplatform", ".platform"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "fiplatform", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "node-demo"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "static-demo", "public"), { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(path.join(projectsRoot, "php-demo", "public", "index.php"), "<?php echo 'php-demo';\n");
  writeFileSync(path.join(projectsRoot, "legacy-php", "public", "index.php"), "<?php echo 'legacy-php';\n");
  writeFileSync(path.join(projectsRoot, "fiplatform", ".platform", "project.json"), `${JSON.stringify({
    projects: [
      {
        slug: "fiplatform",
        name: "fiplatform",
        type: "php",
        aliases: ["fireport"],
      },
    ],
    type: "php",
  }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "fiplatform", "public", "index.php"), "<?php echo 'fiplatform';\n");
  writeFileSync(path.join(projectsRoot, "node-demo", "package.json"), `${JSON.stringify({ scripts: { start: "node server.mjs" } }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "static-demo", "public", "index.html"), "<!doctype html><title>static</title>\n");
  writeFileSync(stateFile, `${JSON.stringify({ projects: {} }, null, 2)}\n`);
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
