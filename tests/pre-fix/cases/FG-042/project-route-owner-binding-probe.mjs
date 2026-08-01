#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const ROUTER_SHA256 = "7ace8ada6839a02abe80b723afa225b83b049789c3fe7e975a4755a32cde65e8";
const TRAEFIK_SHA256 = "d3614e869d7ff64ab7ed8f54efbaea56666405d5fdcf4bef24095e1b6ee060e1";
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));

const sourceArgument = String(process.argv[2] || "");
const tmpArgument = String(process.env.PROJECT_ROUTE_POC_TMP_ROOT || "");
const ownerToken = String(process.env.PROJECT_ROUTE_POC_OWNER_TOKEN || "");
if (!sourceArgument || !tmpArgument || !ownerToken) {
  throw new Error("run this probe through run-from-git-archive.sh");
}

const tmpRoot = verifiedRealDirectory(tmpArgument, "wrapper temporary root");
const sourceRoot = verifiedRealDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(tmpRoot, "source"), "source must be the exact wrapper-owned source child");
assert.equal(ownerToken.length, 64, "invalid wrapper ownership token length");
const rootOwnerFile = path.join(tmpRoot, ".project-route-owner-poc-owner");
assertRegularFile(rootOwnerFile, "wrapper ownership sentinel");
assert.equal(fs.readFileSync(rootOwnerFile, "utf8"), ownerToken, "wrapper ownership sentinel mismatch");

const routerPath = path.join(sourceRoot, "project-router", "server.mjs");
const traefikPath = path.join(sourceRoot, "traefik", "dynamic", "project-routes.yml");
assertRegularFile(routerPath, "pinned project router");
assertRegularFile(traefikPath, "pinned wildcard ingress configuration");
assert.equal(sha256File(routerPath), ROUTER_SHA256, "unexpected project router bytes");
assert.equal(sha256File(traefikPath), TRAEFIK_SHA256, "unexpected wildcard ingress bytes");

const routerSource = fs.readFileSync(routerPath, "utf8");
const traefikSource = fs.readFileSync(traefikPath, "utf8");
const handlerSource = sourceSlice(routerSource, "const server = createServer", "function proxy");
const routeSource = sourceSlice(routerSource, "function dedicatedUpstreamFor", "function safeProxyPath");
const lockSource = sourceSlice(routerSource, "function workloadRoutesFromLock", "function validUpstreamHost");
const discoverySource = sourceSlice(routerSource, "function discoverProjects", "function projectAliases");

assert.match(handlerSource, /projects\.find\(\(item\) => item\.slug === slug \|\| item\.aliases\?\.includes\(slug\) \|\| normalizeHost\(item\.host\) === host\)/);
assert.match(routeSource, /mappedProjectValue\(workloadRoutes\.routes, project\)\s*\n\s*\|\| project\.upstream/);
assert.doesNotMatch(routeSource, /parentSlug|workloadId|owner/);
assert.match(lockSource, /allowed\.add\(`\$\{service\}:\$\{port\}`\)/);
assert.match(discoverySource, /host: stringValue\(item\.host\) \|\| nodeHosts\.get\(slug\) \|\| `\$\{slug\}\$\{hostSuffix\}`/);
assert.match(discoverySource, /const upstream = stringValue\(item\.upstream\) \|\| fallbackUpstream/);
assert.doesNotMatch(discoverySource, /hostOwners|ownedHost|signedRoute|routeTuple/);
assert.match(traefikSource, /HostRegexp\(`\^\[a-z0-9-\]\+\\\.platform-infrastructure\\\.com\$`\)/);
console.log(`[PASS] pinned routing sources revision=${REVISION} tree=${TREE}`);
console.log("[PASS] source proof mutable host/upstream metadata reaches wildcard routing through a global service allowlist");

const runtimeRoot = path.join(tmpRoot, "runtime");
const runtimeOwner = createOwnedDirectory(runtimeRoot, ownerToken);
const negativeRoot = path.join(tmpRoot, "negative-preservation");
const projectsRoot = path.join(runtimeRoot, "projects");
const lockFile = path.join(runtimeRoot, "hosted-workloads.lock.json");
const stateFile = path.join(runtimeRoot, "projects.json");
const modulePath = path.join(runtimeRoot, "pinned-project-router.mjs");
const environmentKeys = [
  "PROJECTS_ROOT",
  "PROJECT_STATE_FILE",
  "PROJECT_ROUTER_WORKLOAD_LOCK_FILE",
  "PROJECT_ROUTER_ALLOWED_UPSTREAMS",
  "CONTROL_CENTER_UPSTREAM",
  "DOMAIN",
  "LOCAL_DOMAIN",
  "ADMIN_HOST",
  "CONTROL_CENTER_HOST",
  "PROJECTS_HOST",
  "PROJECT_HOST_SUFFIX",
  "NODE_PROJECT_HOSTS",
  "PROJECT_UPSTREAMS",
  "PHP_PROJECT_UPSTREAMS",
  "NODE_PROJECT_UPSTREAMS",
  "STATIC_PROJECT_UPSTREAMS",
];
const originalEnvironment = new Map(environmentKeys.map((key) => [key, process.env[key]]));
let sourceHashAfter;

try {
  runNegativePreservationRegression(negativeRoot, ownerToken);
  writeRuntimeFixtures({ projectsRoot, lockFile, stateFile });

  Object.assign(process.env, {
    PROJECTS_ROOT: projectsRoot,
    PROJECT_STATE_FILE: stateFile,
    PROJECT_ROUTER_WORKLOAD_LOCK_FILE: lockFile,
    PROJECT_ROUTER_ALLOWED_UPSTREAMS: "control-center:8080",
    CONTROL_CENTER_UPSTREAM: "http://control-center:8080",
    DOMAIN: "platform-infrastructure.com",
    LOCAL_DOMAIN: "platform-infrastructure.com",
    ADMIN_HOST: "portal.platform-infrastructure.com",
    CONTROL_CENTER_HOST: "portal.platform-infrastructure.com",
    PROJECTS_HOST: "",
    PROJECT_HOST_SUFFIX: ".platform-infrastructure.com",
    NODE_PROJECT_HOSTS: "",
    PROJECT_UPSTREAMS: "",
    PHP_PROJECT_UPSTREAMS: "",
    NODE_PROJECT_UPSTREAMS: "",
    STATIC_PROJECT_UPSTREAMS: "",
  });

  const instrumented = instrumentForSafeImport(routerSource);
  assert.doesNotMatch(instrumented, /server\.listen\s*\(/);
  assert.doesNotMatch(instrumented, /httpRequest\s*\(/);
  fs.writeFileSync(modulePath, instrumented, { encoding: "utf8", flag: "wx", mode: 0o600 });
  const target = await import(`${pathToFileURL(modulePath).href}?revision=${REVISION}`);

  const projects = target.discoverProjects();
  assert.equal(projects.length, 3, `expected three synthetic project entries, received ${projects.length}`);
  const rogue = projectBySlug(projects, "rogue");
  const attacker = projectBySlug(projects, "attacker");
  const victim = projectBySlug(projects, "victim");
  assert.equal(rogue.parentSlug, "attacker-workload");
  assert.equal(attacker.parentSlug, "attacker-workload");
  assert.equal(victim.parentSlug, "victim-workload");

  const siblingResponse = responseRecorder();
  await target.routeRequest(requestFixture("rogue.platform-infrastructure.com"), siblingResponse);
  assert.equal(siblingResponse.statusCode, 204);
  assert.equal(siblingResponse.routeCapture?.projectHost, "rogue.platform-infrastructure.com");
  assert.equal(siblingResponse.routeCapture?.upstream, "http://victim-app:8080/");
  console.log("[VULNERABLE CAN-145] source=attacker-workload host=rogue.platform-infrastructure.com selected_slug=rogue upstream=http://victim-app:8080/ sibling_owner=victim");

  const arbitraryHostResponse = responseRecorder();
  await target.routeRequest(requestFixture("unregistered.platform-infrastructure.com"), arbitraryHostResponse);
  assert.equal(arbitraryHostResponse.statusCode, 204);
  assert.equal(arbitraryHostResponse.routeCapture?.upstream, "http://attacker-app:8080/");
  console.log("[VULNERABLE CAN-150] source=attacker-workload host=unregistered.platform-infrastructure.com selected_slug=attacker upstream=http://attacker-app:8080/ signed_host=false");

  const signedTuples = readFixture("signed-route-tuples.json");
  assert.throws(
    () => assertSignedRouteTuple({ sourceDirectory: "attacker-workload", project: rogue, upstream: siblingResponse.routeCapture.upstream, signedTuples }),
    /unregistered owner\/slug tuple/,
  );
  assert.throws(
    () => assertSignedRouteTuple({ sourceDirectory: "attacker-workload", project: attacker, upstream: arbitraryHostResponse.routeCapture.upstream, signedTuples }),
    /host is not bound/,
  );
  const victimUpstream = target.dedicatedUpstreamFor(victim, target.workloadRoutesFromLock());
  assert.ok(victimUpstream);
  assertSignedRouteTuple({ sourceDirectory: "victim-workload", project: victim, upstream: victimUpstream.href, signedTuples });
  console.log("[FIXED ORACLE] sibling_upstream_claim=rejected arbitrary_wildcard_host=rejected exact_owner_tuple=accepted");

  const missingResponse = responseRecorder();
  await target.routeRequest(requestFixture("missing.platform-infrastructure.com"), missingResponse);
  assert.equal(missingResponse.statusCode, 404);
  assert.equal(missingResponse.routeCapture, null);
  console.log("[NEGATIVE CONTROL] host=missing.platform-infrastructure.com status=404 upstream=none");

  sourceHashAfter = sha256File(routerPath);
  assert.equal(sourceHashAfter, ROUTER_SHA256, "probe changed the archived project router");
  assert.equal(fs.existsSync(path.join(sourceRoot, "reports")), false, "probe unexpectedly created source reports");
  console.log("[SAFE] network_attempts=0 proxy_sink_intercepted=true source_mutations=0 live_mutations=0");
  console.log("[+] result=VULNERABLE canonical_ids=CAN-145,CAN-150");
} finally {
  for (const [key, value] of originalEnvironment) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  if (fs.existsSync(runtimeRoot)) removeOwnedDirectory(runtimeRoot, runtimeOwner, tmpRoot);
}

assert.equal(sourceHashAfter, ROUTER_SHA256);
assert.equal(fs.existsSync(runtimeRoot), false);
console.log("[+] sentinel-authorized runtime cleanup complete; wrapper root remains trap-owned");

function writeRuntimeFixtures({ projectsRoot, lockFile, stateFile }) {
  const attackerConfig = path.join(projectsRoot, "attacker-workload", ".platform", "project.json");
  const victimConfig = path.join(projectsRoot, "victim-workload", ".platform", "project.json");
  fs.mkdirSync(path.dirname(attackerConfig), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.dirname(victimConfig), { recursive: true, mode: 0o700 });
  fs.copyFileSync(path.join(SCRIPT_DIR, "fixtures", "attacker-project.json"), attackerConfig, fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(path.join(SCRIPT_DIR, "fixtures", "victim-project.json"), victimConfig, fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(path.join(SCRIPT_DIR, "fixtures", "hosted-workloads.lock.json"), lockFile, fs.constants.COPYFILE_EXCL);
  fs.writeFileSync(stateFile, '{"projects":{}}\n', { encoding: "utf8", flag: "wx", mode: 0o600 });
}

function instrumentForSafeImport(source) {
  const handlerStartToken = "const server = createServer(async (req, res) => {";
  const handlerStart = source.indexOf(handlerStartToken);
  const listenStart = source.indexOf("\n\nserver.listen(", handlerStart);
  const proxyStart = source.indexOf("function proxy", listenStart);
  const dedicatedStart = source.indexOf("function dedicatedUpstreamFor", proxyStart);
  assert.ok(handlerStart >= 0 && listenStart > handlerStart && proxyStart > listenStart && dedicatedStart > proxyStart);

  let handler = source.slice(handlerStart, listenStart);
  handler = handler.replace(handlerStartToken, "async function routeRequest(req, res) {");
  assert.match(handler, /\n\}\);\s*$/);
  handler = handler.replace(/\n\}\);\s*$/, "\n}");

  const proxyStub = `function proxy(clientReq, clientRes, upstream) {
  clientRes.routeCapture = {
    projectHost: normalizeHost(clientReq.headers.host || ""),
    upstream: upstream.href,
  };
  clientRes.writeHead(204, { "x-poc-proxy-intercepted": "true" });
  clientRes.end("");
}`;

  return `${source.slice(0, handlerStart)}${handler}\n\n${proxyStub}\n\n${source.slice(dedicatedStart)}\nexport { routeRequest, discoverProjects, dedicatedUpstreamFor, workloadRoutesFromLock };\n`;
}

function requestFixture(host) {
  return {
    headers: { host },
    url: "/probe",
    method: "GET",
    pipe() {
      throw new Error("proxy request body must not be used by the intercepted sink");
    },
  };
}

function responseRecorder() {
  return {
    statusCode: null,
    headers: null,
    body: "",
    routeCapture: null,
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(body = "") {
      this.body += String(body);
    },
  };
}

function projectBySlug(projects, slug) {
  const project = projects.find((entry) => entry.slug === slug);
  assert.ok(project, `missing discovered project ${slug}`);
  return project;
}

function assertSignedRouteTuple({ sourceDirectory, project, upstream, signedTuples }) {
  assert.equal(signedTuples.version, 2);
  assert.equal(signedTuples.state, "verified");
  const tuple = signedTuples.tuples.find((entry) => (
    entry.sourceDirectory === sourceDirectory && entry.slug === project.slug
  ));
  if (!tuple) throw new Error(`unregistered owner/slug tuple: ${sourceDirectory}/${project.slug}`);
  if (project.host !== tuple.host) throw new Error(`host is not bound to owner/slug tuple: ${project.host}`);
  const actualAliases = [...(project.aliases || [])].sort();
  const expectedAliases = [...(tuple.aliases || [])].sort();
  assert.deepEqual(actualAliases, expectedAliases, "aliases are not bound to owner/slug tuple");
  assert.equal(upstream, new URL(`${tuple.upstream}/`).href, "upstream is not bound to owner/slug tuple");
}

function readFixture(name) {
  const fixturePath = path.join(SCRIPT_DIR, "fixtures", name);
  assertRegularFile(fixturePath, `fixture ${name}`);
  return JSON.parse(fs.readFileSync(fixturePath, "utf8"));
}

function runNegativePreservationRegression(directory, token) {
  fs.mkdirSync(directory, { mode: 0o700 });
  const foreignOwner = `${token.slice(0, -1)}${token.endsWith("0") ? "1" : "0"}`;
  const ownerFile = path.join(directory, ".poc-owner");
  const preserveFile = path.join(directory, "preserve-me.txt");
  fs.writeFileSync(ownerFile, foreignOwner, { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(preserveFile, "must-survive-refused-cleanup\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  assert.throws(() => removeOwnedDirectory(directory, token, tmpRoot), /ownership sentinel mismatch/);
  assert.equal(fs.readFileSync(preserveFile, "utf8"), "must-survive-refused-cleanup\n");
  fs.writeFileSync(ownerFile, token, { encoding: "utf8", flag: "w", mode: 0o600 });
  removeOwnedDirectory(directory, token, tmpRoot);
  assert.equal(fs.existsSync(directory), false);
  console.log("[PASS] negative preservation mismatched sentinel refused deletion and preserved existing data");
}

function createOwnedDirectory(directory, token) {
  assert.equal(path.dirname(directory), tmpRoot, "owned mutation directory must be a direct child of wrapper root");
  fs.mkdirSync(directory, { mode: 0o700 });
  const ownerFile = path.join(directory, ".poc-owner");
  fs.writeFileSync(ownerFile, token, { encoding: "utf8", flag: "wx", mode: 0o600 });
  return token;
}

function removeOwnedDirectory(directory, token, parent) {
  const parentReal = verifiedRealDirectory(parent, "cleanup parent");
  assert.equal(path.dirname(path.resolve(directory)), parentReal, "cleanup target must be a direct child of wrapper root");
  const stats = fs.lstatSync(directory, { throwIfNoEntry: false });
  assert.ok(stats?.isDirectory() && !stats.isSymbolicLink(), "cleanup target must be a real directory");
  assert.equal(fs.realpathSync(directory), path.resolve(directory), "cleanup target realpath mismatch");
  const ownerFile = path.join(directory, ".poc-owner");
  assertRegularFile(ownerFile, "cleanup ownership sentinel");
  assert.equal(fs.readFileSync(ownerFile, "utf8"), token, "ownership sentinel mismatch");
  fs.rmSync(directory, { recursive: true });
}

function verifiedRealDirectory(input, label) {
  const resolved = path.resolve(input);
  const stats = fs.lstatSync(resolved, { throwIfNoEntry: false });
  assert.ok(stats?.isDirectory() && !stats.isSymbolicLink(), `${label} must be a real directory`);
  const real = fs.realpathSync(resolved);
  assert.equal(real, resolved, `${label} realpath mismatch`);
  return real;
}

function assertRegularFile(filePath, label) {
  const stats = fs.lstatSync(filePath, { throwIfNoEntry: false });
  assert.ok(stats?.isFile() && !stats.isSymbolicLink(), `${label} must be a regular file`);
}

function sourceSlice(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `missing source slice ${start} -> ${end}`);
  return source.slice(startIndex, endIndex);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}
