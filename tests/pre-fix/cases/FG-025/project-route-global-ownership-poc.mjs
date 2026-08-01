#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { isIP } from "node:net";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

function fail(message) {
  process.stderr.write("[FAIL] " + message + "\n");
  process.exit(1);
}

function pass(message) {
  process.stdout.write("[PASS] " + message + "\n");
}

function parseArgs(argv) {
  let sourceRoot = "";
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--source-root" && argv[index + 1]) {
      sourceRoot = argv[++index];
      continue;
    }
    fail("usage: node project-route-global-ownership-poc.mjs --source-root PATH");
  }
  if (!sourceRoot) fail("--source-root is required");
  return path.resolve(sourceRoot);
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function extractBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, "missing source marker: " + startMarker);
  assert.ok(end > start, "missing source marker: " + endMarker);
  return source.slice(start, end).trim();
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2) + "\n", {
    mode: 0o600,
  });
}

function writeProject(projectsRoot, directory, config) {
  const projectRoot = path.join(projectsRoot, directory);
  fs.mkdirSync(path.join(projectRoot, ".platform"), {
    recursive: true,
    mode: 0o700,
  });
  writeJson(path.join(projectRoot, "package.json"), {
    scripts: { start: "node server.mjs" },
  });
  writeJson(path.join(projectRoot, ".platform", "project.json"), config);
}

function route(workloadId, slug, service, port) {
  return {
    workloadId,
    slug,
    service,
    port,
    upstream: "http://" + service + ":" + port,
  };
}

function writeVerifiedLock(lockPath, routes) {
  writeJson(lockPath, { version: 1, state: "verified", routes });
}

function createContractFixture(root, contractModule) {
  const workloadRoot = path.join(root, "workloads");
  const coreEnvironment = path.join(root, "core.env");
  const coreCompose = path.join(root, "compose.core.json");
  const catalogPath = path.join(root, "catalog.json");
  fs.mkdirSync(workloadRoot, { recursive: true, mode: 0o700 });
  fs.writeFileSync(coreEnvironment, "DOMAIN=route.test\n", { mode: 0o600 });
  writeJson(coreCompose, { services: {} });

  const manifests = [
    {
      directory: "victim",
      environment: "VICTIM_APP_IMAGE=registry.example/victim@sha256:fixture\n",
      document: {
        version: 1,
        id: "victim-app",
        composeFile: "compose.json",
        services: [{
          name: "victim-app-web",
          role: "web",
          routes: [{ slug: "victim", port: 3000 }],
        }],
      },
    },
    {
      directory: "attacker",
      environment: "ATTACKER_APP_IMAGE=registry.example/attacker@sha256:fixture\n",
      document: {
        version: 1,
        id: "attacker-app",
        composeFile: "compose.json",
        services: [{
          name: "attacker-app-web",
          role: "web",
          routes: [{
            slug: "attacker",
            port: 4000,
            aliases: ["victim"],
            host: "victim.route.test",
            upstream: "http://attacker-app-web:4000",
          }],
        }],
      },
    },
  ];

  const catalog = { version: 1, workloads: [] };
  for (const fixture of manifests) {
    const directory = path.join(workloadRoot, fixture.directory);
    writeJson(path.join(directory, "manifest.json"), fixture.document);
    writeJson(path.join(directory, "compose.json"), { services: {} });
    fs.writeFileSync(path.join(directory, "workload.env"), fixture.environment, {
      mode: 0o600,
    });
    catalog.workloads.push({
      manifest: fixture.directory + "/manifest.json",
      environmentFile: fixture.directory + "/workload.env",
    });
  }
  writeJson(catalogPath, catalog);

  const resolved = contractModule.resolveCatalog({
    catalogPath,
    workloadRoot,
    coreEnvFile: coreEnvironment,
    coreFiles: [coreCompose],
    projectName: "route-ownership-poc",
  });
  assert.equal(resolved.state, "resolved");
  assert.deepEqual(
    resolved.workloads.map((workload) => workload.services[0].routes[0].slug),
    ["victim", "attacker"],
  );
  assert.deepEqual(
    resolved.workloads[1].services[0].routes[0],
    { slug: "attacker", port: 4000 },
  );
  assert.equal(
    resolved.files.some((record) => /(?:^|\/)project\.json$/.test(record.path)),
    false,
  );
  return resolved;
}

function createRouterHarness({
  serverText,
  projectsRoot,
  workloadLockFile,
  discoveryOrder,
}) {
  const routerCore = extractBetween(
    serverText,
    "function dedicatedUpstreamFor",
    "function isEnabled",
  );
  const projectSlugs = extractBetween(
    serverText,
    "function projectSlugs",
    "function readState",
  );
  const hostHelpers = extractBetween(
    serverText,
    "function slugFromHost",
    "function escapeHtml",
  );
  const selectionMatch = serverText.match(
    /const project = projects\.find\(\(item\) => item\.slug === slug \|\| item\.aliases\?\.includes\(slug\) \|\| normalizeHost\(item\.host\) === host\);/,
  );
  assert.ok(selectionMatch, "exact first-match selection expression is missing");

  const errors = [];
  const realRoot = path.resolve(projectsRoot);
  const rank = new Map(
    discoveryOrder.map((name, index) => [name, index]),
  );
  function orderedReaddirSync(target, options) {
    const entries = fs.readdirSync(target, options);
    if (path.resolve(target) !== realRoot || !options?.withFileTypes) {
      return entries;
    }
    return [...entries].sort((left, right) => {
      const leftRank = rank.get(left.name) ?? Number.MAX_SAFE_INTEGER;
      const rightRank = rank.get(right.name) ?? Number.MAX_SAFE_INTEGER;
      return leftRank - rightRank || left.name.localeCompare(right.name);
    });
  }

  const context = vm.createContext({
    URL,
    path,
    isIP,
    existsSync: fs.existsSync,
    readFileSync: fs.readFileSync,
    readdirSync: orderedReaddirSync,
    statSync: fs.statSync,
    console: {
      error(message) {
        errors.push(String(message));
      },
    },
    projectsRoot: realRoot,
    workloadLockFile: path.resolve(workloadLockFile),
    projectConfigNames: [".platform/project.json", "platform.project.json"],
    testLoopbackAllowed: false,
    allowedUpstreams: new Set(["control-center:8080"]),
    domain: "route.test",
    hostSuffix: ".route.test",
    nodeHosts: new Map(),
    projectUpstreams: new Map(),
    phpProjectUpstreams: new Map(),
    nodeUpstreams: new Map(),
    staticUpstreams: new Map(),
    workloadRouteCache: { key: "", routes: new Map(), allowed: new Set() },
  });
  const harnessSource = [
    routerCore,
    projectSlugs,
    hostHelpers,
    `globalThis.__resolveRoute = (requestedHost) => {
      const host = normalizeHost(requestedHost);
      const projects = discoverProjects();
      const slug = slugFromHost(host);
      ${selectionMatch[0]}
      const workloadRoutes = workloadRoutesFromLock();
      const upstream = project ? dedicatedUpstreamFor(project, workloadRoutes) : null;
      return {
        host,
        hostSlug: slug,
        discovery: projects.map((item) => ({
          slug: item.slug,
          aliases: [...(item.aliases || [])],
          host: normalizeHost(item.host),
          configuredUpstream: item.upstream || "",
        })),
        selected: project?.slug || "",
        upstream: upstream?.href || "",
      };
    };`,
  ].join("\n\n");
  vm.runInContext(harnessSource, context, {
    filename: "exact-project-route-functions.mjs",
  });
  return {
    resolveRoute(host) {
      const result = context.__resolveRoute(host);
      assert.deepEqual(errors, []);
      return result;
    },
  };
}

function createTwoProjectScenario(root, { attacker, victim, routes }) {
  const projectsRoot = path.join(root, "projects");
  const lockPath = path.join(root, "hosted-workloads.lock.json");
  writeProject(projectsRoot, "attacker-source", {
    projects: [{ name: "Attacker", type: "node", ...attacker }],
  });
  writeProject(projectsRoot, "victim-source", {
    projects: [{ name: "Victim", type: "node", ...victim }],
  });
  writeVerifiedLock(lockPath, routes);
  return { projectsRoot, lockPath };
}

function trace(label, first, second) {
  process.stdout.write(
    "[TRACE] " + label +
      " first=" + first.selected + "->" + first.upstream +
      " reversed=" + second.selected + "->" + second.upstream +
      "\n",
  );
}

const sourceRoot = parseArgs(process.argv.slice(2));
const expectedHashes = new Map([
  ["project-router/server.mjs", "7ace8ada6839a02abe80b723afa225b83b049789c3fe7e975a4755a32cde65e8"],
  ["project-router/tests/project-router.test.mjs", "a781be8929a064eaa3e1b84cf3e5c5ab9d89fda667e25d8234a1b25e3cc7f5e3"],
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["compose.yaml", "ed630eee1be8350142493307c2647aa98ce67324c93c127a9370a19a24a9d6c7"],
  ["compose.runtime.yaml", "b7b546bbb8587b54d39a0a53d22db4f020afcc707c33338eee264c4407d30505"],
  ["traefik/dynamic/project-routes.yml", "d3614e869d7ff64ab7ed8f54efbaea56666405d5fdcf4bef24095e1b6ee060e1"],
]);

let temporaryRoot = "";
try {
  for (const [relativePath, expectedHash] of expectedHashes) {
    assert.equal(
      sha256(path.join(sourceRoot, relativePath)),
      expectedHash,
      relativePath + " does not match the exact pre-fix source",
    );
  }
  pass("exact pre-fix source fingerprints verified");

  const contractTests = spawnSync(
    process.execPath,
    [path.join(sourceRoot, "scripts/hosted-workload-contract.test.mjs")],
    {
      cwd: sourceRoot,
      encoding: "utf8",
      env: {
        HOME: process.env.HOME || "",
        PATH: process.env.PATH || "",
        NODE_NO_WARNINGS: "1",
      },
    },
  );
  assert.equal(
    contractTests.status,
    0,
    "hosted-workload contract tests failed:\n" +
      (contractTests.stderr || contractTests.stdout || "no output"),
  );
  assert.match(contractTests.stdout, /contract tests passed 15\/15/);
  pass("repository hosted-workload contract tests pass 15/15");

  const serverPath = path.join(sourceRoot, "project-router/server.mjs");
  const contractPath = path.join(
    sourceRoot,
    "scripts/hosted-workload-contract.mjs",
  );
  const serverText = fs.readFileSync(serverPath, "utf8");
  const contractText = fs.readFileSync(contractPath, "utf8");
  const routerTestText = fs.readFileSync(
    path.join(sourceRoot, "project-router/tests/project-router.test.mjs"),
    "utf8",
  );
  const composeText = fs.readFileSync(path.join(sourceRoot, "compose.yaml"), "utf8");
  const runtimeComposeText = fs.readFileSync(
    path.join(sourceRoot, "compose.runtime.yaml"),
    "utf8",
  );
  const edgeRouteText = fs.readFileSync(
    path.join(sourceRoot, "traefik/dynamic/project-routes.yml"),
    "utf8",
  );

  assert.match(
    serverText,
    /for \(const entry of readdirSync\(projectsRoot, \{ withFileTypes: true \}\)\)/,
  );
  assert.ok(serverText.includes("if (!project || seen.has(project.slug)) continue;"));
  assert.ok(serverText.includes("seen.add(project.slug);"));
  assert.doesNotMatch(
    extractBetween(serverText, "function discoverProjects", "function configuredProjectEntries"),
    /seen\.add\(alias\)|hostOwners|aliasOwners|upstreamOwners/,
  );
  assert.ok(
    serverText.includes(
      "projects.find((item) => item.slug === slug || item.aliases?.includes(slug) || normalizeHost(item.host) === host)",
    ),
  );
  assert.match(
    extractBetween(contractText, "export function validateWorkloadManifest", "export function resolveCatalog"),
    /routeSlugs\.has\(route\.slug\)/,
  );
  assert.match(
    extractBetween(contractText, "export function resolveCatalog", "function objectWithoutNetworks"),
    /Duplicate global route/,
  );
  assert.doesNotMatch(contractText, /project\.json|route\.aliases|route\.host|upstreamOwners/);
  assert.match(routerTestText, /aliases: \["fireport"\]/);
  assert.doesNotMatch(routerTestText, /collision|reverse discovery/i);
  assert.match(
    composeText,
    /project-router:[\s\S]*?PROJECTS_ROOT: \/var\/www\/projects[\s\S]*?PHP_PROJECTS_DIR:-\.\.\/src}:\/var\/www\/projects/,
  );
  assert.match(
    edgeRouteText,
    /HostRegexp\(`\^\[a-z0-9-\]\+\\\.platform-infrastructure\\\.com\$`\)/,
  );
  assert.ok(edgeRouteText.includes("url: http://project-router:8080"));
  assert.ok(
    runtimeComposeText.includes(
      "./traefik/dynamic/project-routes.yml:/etc/traefik/dynamic/project-routes.yml:ro",
    ),
  );
  pass("first-match routing and slug-only ownership controls verified");

  const contractModule = await import(pathToFileURL(contractPath).href);
  temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "project-route-ownership-"),
  );
  createContractFixture(path.join(temporaryRoot, "contract"), contractModule);
  pass("two unique route slugs pass while alias, host, and upstream claims remain outside the contract");

  const standardRoutes = [
    route("victim-app", "victim", "victim-app-web", 3000),
    route("attacker-app", "attacker", "attacker-app-web", 4000),
  ];

  const aliasFixture = createTwoProjectScenario(
    path.join(temporaryRoot, "alias"),
    {
      attacker: {
        slug: "attacker",
        host: "attacker.route.test",
        aliases: ["victim"],
      },
      victim: { slug: "victim", host: "victim.route.test" },
      routes: standardRoutes,
    },
  );
  const aliasAttackerFirst = createRouterHarness({
    serverText,
    projectsRoot: aliasFixture.projectsRoot,
    workloadLockFile: aliasFixture.lockPath,
    discoveryOrder: ["attacker-source", "victim-source"],
  }).resolveRoute("Victim.Route.Test:443");
  const aliasVictimFirst = createRouterHarness({
    serverText,
    projectsRoot: aliasFixture.projectsRoot,
    workloadLockFile: aliasFixture.lockPath,
    discoveryOrder: ["victim-source", "attacker-source"],
  }).resolveRoute("Victim.Route.Test:443");
  assert.equal(aliasAttackerFirst.selected, "attacker");
  assert.equal(aliasAttackerFirst.upstream, "http://attacker-app-web:4000/");
  assert.equal(aliasVictimFirst.selected, "victim");
  assert.equal(aliasVictimFirst.upstream, "http://victim-app-web:3000/");
  assert.equal(aliasAttackerFirst.discovery.length, 2);
  assert.equal(aliasVictimFirst.discovery.length, 2);
  trace("alias_collision", aliasAttackerFirst, aliasVictimFirst);
  pass("reversing discovery order flips alias ownership and selected upstream");

  const hostFixture = createTwoProjectScenario(
    path.join(temporaryRoot, "host"),
    {
      attacker: { slug: "attacker", host: "shared.route.test" },
      victim: { slug: "victim", host: "shared.route.test" },
      routes: standardRoutes,
    },
  );
  const hostAttackerFirst = createRouterHarness({
    serverText,
    projectsRoot: hostFixture.projectsRoot,
    workloadLockFile: hostFixture.lockPath,
    discoveryOrder: ["attacker-source", "victim-source"],
  }).resolveRoute("shared.route.test");
  const hostVictimFirst = createRouterHarness({
    serverText,
    projectsRoot: hostFixture.projectsRoot,
    workloadLockFile: hostFixture.lockPath,
    discoveryOrder: ["victim-source", "attacker-source"],
  }).resolveRoute("shared.route.test");
  assert.equal(hostAttackerFirst.selected, "attacker");
  assert.equal(hostAttackerFirst.upstream, "http://attacker-app-web:4000/");
  assert.equal(hostVictimFirst.selected, "victim");
  assert.equal(hostVictimFirst.upstream, "http://victim-app-web:3000/");
  trace("host_collision", hostAttackerFirst, hostVictimFirst);
  pass("reversing discovery order flips explicit-host ownership and selected upstream");

  const upstreamFixture = createTwoProjectScenario(
    path.join(temporaryRoot, "upstream"),
    {
      attacker: {
        slug: "attacker",
        host: "attacker.route.test",
        upstream: "http://shared-app-web:8080",
      },
      victim: {
        slug: "victim",
        host: "victim.route.test",
        upstream: "http://shared-app-web:8080",
      },
      routes: [route("shared-app", "grant", "shared-app-web", 8080)],
    },
  );
  const upstreamHarness = createRouterHarness({
    serverText,
    projectsRoot: upstreamFixture.projectsRoot,
    workloadLockFile: upstreamFixture.lockPath,
    discoveryOrder: ["attacker-source", "victim-source"],
  });
  const attackerUpstream = upstreamHarness.resolveRoute("attacker.route.test");
  const victimUpstream = upstreamHarness.resolveRoute("victim.route.test");
  assert.equal(attackerUpstream.selected, "attacker");
  assert.equal(victimUpstream.selected, "victim");
  assert.equal(attackerUpstream.upstream, "http://shared-app-web:8080/");
  assert.equal(victimUpstream.upstream, "http://shared-app-web:8080/");
  process.stdout.write(
    "[TRACE] upstream_collision attacker=" + attackerUpstream.upstream +
      " victim=" + victimUpstream.upstream + "\n",
  );
  pass("two project identities can claim the same verified upstream identity");

  process.stdout.write(
    "[SAFE] exact functions, deterministic directory order, and temporary fixtures only; no listener, socket, network, container, or live-state access\n",
  );
} catch (error) {
  process.stderr.write("[FAIL] " + (error.stack || error.message) + "\n");
  process.exitCode = 1;
} finally {
  if (temporaryRoot) {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
