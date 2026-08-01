#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { performance } from "node:perf_hooks";

const EXPECTED_HASHES = new Map([
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
]);
const CACHE_TTL_MS = 30_000;
const sourceRoot = path.resolve(process.argv[2] ?? "");

if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: project-tree-budget-probe.mjs /path/to/archived/source");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified exact server and runtime-isolation source hashes");

const serverSource = fs.readFileSync(path.join(sourceRoot, "control-center/server.mjs"), "utf8");
const isolationSource = fs.readFileSync(path.join(sourceRoot, "compose.runtime-isolation.yaml"), "utf8");
const readUsageSource = extractFunction(serverSource, "readProjectDiskUsage");
const directoryUsageSource = extractFunction(serverSource, "directoryUsage");

assert.match(serverSource, /const context = req\.method === "GET"/);
assert.match(serverSource, /await buildContext\(\{ projects, state \}\)/);
assert.match(serverSource, /const projectDisks = new Map\(projects\.map\(\(project\) => \[project\.slug, readProjectDiskUsage\(project\)\]\)\);/);
assert.match(readUsageSource, /const cached = projectDiskUsageCache\.get\(key\);/);
assert.match(readUsageSource, /const value = directoryUsage\(root\);\s+projectDiskUsageCache\.set/);
assert.match(directoryUsageSource, /while \(stack\.length\)/);
assert.match(directoryUsageSource, /lstatSync\(current\)/);
assert.match(directoryUsageSource, /readdirSync\(current\)/);
assert.doesNotMatch(directoryUsageSource, /max(?:Depth|Nodes|Files|Bytes|Time)|deadline|elapsed|truncated|stale/);
assert.match(isolationSource, /control-center:\s+[\s\S]*?cpus: 1\.00[\s\S]*?mem_limit: 512m/);
assert.match(isolationSource, /\$\{PHP_PROJECTS_DIR:-\.\.\/src\}:\/var\/www\/projects:ro/);

const temporaryParent = process.env.CONTROL_TREE_POC_TMP || os.tmpdir();
const fixtureRoot = fs.mkdtempSync(path.join(temporaryParent, "control-tree-fixtures-"));
let completed = false;

try {
  const fixtures = buildFixtures(fixtureRoot);

  const wide = runExactScenario("EXACT-WIDE", fixtures.wide);
  assert.equal(wide.result.files, fixtures.wideFiles);
  assert.equal(wide.result.directories, fixtures.wideDirectories);
  assert.equal(wide.ops.lstatCalls, fixtures.wideFiles + fixtures.wideDirectories);

  const deep = runExactScenario("EXACT-DEEP", fixtures.deep);
  assert.equal(deep.result.files, 1);
  assert.equal(deep.result.directories, fixtures.deepDirectories);
  assert.equal(deep.ops.lstatCalls, fixtures.deepDirectories + 1);

  const symlink = runExactScenario("EXACT-SYMLINK", fixtures.symlink, { symlinkPath: fixtures.symlinkPath });
  assert.equal(symlink.ops.symlinkReaddirCalls, 0);
  assert.equal(symlink.result.files, fixtures.symlinkRegularFiles + 1);

  const slow = runExactScenario("EXACT-SLOW", fixtures.slow, { delayMs: 1 });
  assert.equal(slow.result.files, fixtures.slowFiles);
  assert.ok(slow.wallMs >= 30, `slow fixture unexpectedly completed in ${slow.wallMs} ms`);

  for (const scenario of [wide, deep, symlink, slow]) {
    assert.equal(Object.hasOwn(scenario.result, "truncated"), false);
    assert.equal(Object.hasOwn(scenario.result, "stale"), false);
  }

  const cacheOps = instrumentFilesystem();
  const clock = { now: 1_000_000 };
  const cacheSets = [];
  class TrackingMap extends Map {
    set(key, value) {
      cacheSets.push(totalOperations(cacheOps));
      return super.set(key, value);
    }
  }
  const cache = new TrackingMap();
  const cacheHarness = exactHarness(cacheOps, clock, cache);
  const project = { slug: "synthetic-wide", root: fixtures.wide, filesAvailable: true, relativePath: "synthetic-wide" };
  cacheHarness.readProjectDiskUsage(project);
  const firstScanOps = totalOperations(cacheOps);
  const firstCacheSetAt = cacheSets[0];
  cacheHarness.readProjectDiskUsage(project);
  const cacheHitOps = totalOperations(cacheOps) - firstScanOps;
  clock.now += CACHE_TTL_MS + 1;
  cacheHarness.readProjectDiskUsage(project);
  const expiredScanOps = totalOperations(cacheOps) - firstScanOps;
  assert.equal(firstCacheSetAt, firstScanOps);
  assert.equal(cacheHitOps, 0);
  assert.equal(expiredScanOps, firstScanOps);
  console.log(
    `[CACHE] ttl_ms=${CACHE_TTL_MS} first_scan_ops=${firstScanOps} cache_set_after_ops=${firstCacheSetAt}`
    + ` cache_hit_ops=${cacheHitOps} expired_scan_ops=${expiredScanOps}`,
  );

  const boundedWide = boundedDirectoryUsage(fixtures.wide, {
    maxNodes: 128,
    maxDepth: 64,
    maxTimeMs: 1_000,
  });
  assert.equal(boundedWide.truncated, true);
  assert.equal(boundedWide.stale, false);
  assert.equal(boundedWide.reason, "node-budget");
  assert.equal(boundedWide.visitedNodes, 128);
  printReference("REFERENCE-WIDE", boundedWide);

  const boundedDeep = boundedDirectoryUsage(fixtures.deep, {
    maxNodes: 10_000,
    maxDepth: 16,
    maxTimeMs: 1_000,
  });
  assert.equal(boundedDeep.truncated, true);
  assert.equal(boundedDeep.stale, false);
  assert.equal(boundedDeep.reason, "depth-budget");
  printReference("REFERENCE-DEEP", boundedDeep);

  const boundedSymlink = boundedDirectoryUsage(fixtures.symlink, {
    maxNodes: 128,
    maxDepth: 16,
    maxTimeMs: 1_000,
    symlinkPath: fixtures.symlinkPath,
  });
  assert.equal(boundedSymlink.truncated, false);
  assert.equal(boundedSymlink.stale, false);
  assert.equal(boundedSymlink.symlinkReaddirCalls, 0);
  printReference("REFERENCE-SYMLINK", boundedSymlink);

  const lastKnownGood = { available: true, bytes: 12_345, files: 77, directories: 9 };
  const boundedSlow = boundedDirectoryUsage(fixtures.slow, {
    maxNodes: 10_000,
    maxDepth: 64,
    maxTimeMs: 8,
    delayMs: 1,
    lastKnownGood,
  });
  assert.equal(boundedSlow.truncated, true);
  assert.equal(boundedSlow.stale, true);
  assert.equal(boundedSlow.reason, "time-budget");
  assert.equal(boundedSlow.bytes, lastKnownGood.bytes);
  assert.ok(boundedSlow.visitedNodes < fixtures.slowFiles + 1);
  printReference("REFERENCE-SLOW", boundedSlow);

  console.log("[+] exact vulnerable traversal and bounded reference behavior reproduced with disposable synthetic trees");
  console.log("[+] no HTTP, listener, socket, network, container, service state, project mount, or secret was used");
  completed = true;
} finally {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
}

assert.equal(completed, true);
assert.equal(fs.existsSync(fixtureRoot), false);
console.log("[+] temporary fixture trees removed");

function buildFixtures(root) {
  const wide = path.join(root, "wide");
  const wideDirectoryCount = 20;
  const filesPerDirectory = 75;
  fs.mkdirSync(wide);
  for (let directory = 0; directory < wideDirectoryCount; directory += 1) {
    const branch = path.join(wide, `branch-${String(directory).padStart(2, "0")}`);
    fs.mkdirSync(branch);
    for (let file = 0; file < filesPerDirectory; file += 1) {
      fs.writeFileSync(path.join(branch, `file-${String(file).padStart(2, "0")}.txt`), "x");
    }
  }

  const deep = path.join(root, "deep");
  const deepLevels = 140;
  fs.mkdirSync(deep);
  let cursor = deep;
  for (let depth = 0; depth < deepLevels; depth += 1) {
    cursor = path.join(cursor, "d");
    fs.mkdirSync(cursor);
  }
  fs.writeFileSync(path.join(cursor, "leaf.txt"), "leaf");

  const symlink = path.join(root, "symlink");
  const symlinkTarget = path.join(symlink, "target");
  const symlinkPath = path.join(symlink, "loop");
  fs.mkdirSync(symlink);
  fs.mkdirSync(symlinkTarget);
  for (let index = 0; index < 3; index += 1) fs.writeFileSync(path.join(symlinkTarget, `file-${index}.txt`), "x");
  fs.symlinkSync(symlink, symlinkPath, "dir");

  const slow = path.join(root, "slow");
  const slowFiles = 80;
  fs.mkdirSync(slow);
  for (let index = 0; index < slowFiles; index += 1) fs.writeFileSync(path.join(slow, `file-${index}.txt`), "x");

  return {
    wide,
    wideFiles: wideDirectoryCount * filesPerDirectory,
    wideDirectories: wideDirectoryCount + 1,
    deep,
    deepDirectories: deepLevels + 1,
    symlink,
    symlinkPath,
    symlinkRegularFiles: 3,
    slow,
    slowFiles,
  };
}

function runExactScenario(label, root, options = {}) {
  const ops = instrumentFilesystem(options);
  const harness = exactHarness(ops, { now: 1_000_000 }, new Map());
  const startedAt = performance.now();
  const result = harness.directoryUsage(root);
  const wallMs = performance.now() - startedAt;
  console.log(
    `[${label}] lstat_calls=${ops.lstatCalls} readdir_calls=${ops.readdirCalls}`
    + ` files=${result.files} directories=${result.directories} wall_ms=${wallMs.toFixed(3)}`
    + ` truncated_field=${Object.hasOwn(result, "truncated") ? result.truncated : "absent"}`
    + ` stale_field=${Object.hasOwn(result, "stale") ? result.stale : "absent"}`,
  );
  return { result, ops, wallMs };
}

function exactHarness(ops, clock, cache) {
  return vm.runInNewContext(
    `${directoryUsageSource}\n\n${readUsageSource}\n\n({ directoryUsage, readProjectDiskUsage });`,
    {
      lstatSync: ops.lstatSync,
      readdirSync: ops.readdirSync,
      path,
      projectDiskUsageCache: cache,
      projectDiskUsageTtlMs: CACHE_TTL_MS,
      resolveProjectRoot(project) { return project.root; },
      Date: { now() { return clock.now; } },
    },
    { filename: "archived-project-tree-helpers.mjs" },
  );
}

function instrumentFilesystem({ delayMs = 0, symlinkPath = "" } = {}) {
  const sleeper = new Int32Array(new SharedArrayBuffer(4));
  const counters = {
    lstatCalls: 0,
    readdirCalls: 0,
    symlinkReaddirCalls: 0,
  };
  counters.lstatSync = (target) => {
    counters.lstatCalls += 1;
    if (delayMs > 0) Atomics.wait(sleeper, 0, 0, delayMs);
    return fs.lstatSync(target);
  };
  counters.readdirSync = (target) => {
    counters.readdirCalls += 1;
    if (path.resolve(target) === path.resolve(symlinkPath || path.join(fixtureRoot, "missing"))) counters.symlinkReaddirCalls += 1;
    if (delayMs > 0) Atomics.wait(sleeper, 0, 0, delayMs);
    return fs.readdirSync(target);
  };
  return counters;
}

function boundedDirectoryUsage(root, options) {
  const {
    maxNodes,
    maxDepth,
    maxTimeMs,
    delayMs = 0,
    lastKnownGood = null,
    symlinkPath = "",
  } = options;
  const ops = instrumentFilesystem({ delayMs, symlinkPath });
  const startedAt = performance.now();
  const stack = [{ target: root, depth: 0 }];
  let bytes = 0;
  let files = 0;
  let directories = 0;
  let visitedNodes = 0;

  while (stack.length) {
    if (performance.now() - startedAt >= maxTimeMs) return truncatedResult("time-budget");
    if (visitedNodes >= maxNodes) return truncatedResult("node-budget");
    const current = stack.pop();
    if (current.depth > maxDepth) return truncatedResult("depth-budget");
    let stat;
    try {
      stat = ops.lstatSync(current.target);
    } catch {
      continue;
    }
    visitedNodes += 1;
    bytes += Number(stat.size || 0);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      directories += 1;
      let entries = [];
      try {
        entries = ops.readdirSync(current.target);
      } catch {
        entries = [];
      }
      for (const entry of entries) stack.push({ target: path.join(current.target, entry), depth: current.depth + 1 });
    } else {
      files += 1;
    }
  }

  return {
    available: true,
    bytes,
    files,
    directories,
    visitedNodes,
    truncated: false,
    stale: false,
    reason: "complete",
    lstatCalls: ops.lstatCalls,
    readdirCalls: ops.readdirCalls,
    symlinkReaddirCalls: ops.symlinkReaddirCalls,
  };

  function truncatedResult(reason) {
    const partial = {
      available: true,
      bytes,
      files,
      directories,
    };
    return {
      ...(lastKnownGood || partial),
      visitedNodes,
      truncated: true,
      stale: Boolean(lastKnownGood),
      reason,
      lstatCalls: ops.lstatCalls,
      readdirCalls: ops.readdirCalls,
      symlinkReaddirCalls: ops.symlinkReaddirCalls,
    };
  }
}

function printReference(label, result) {
  console.log(
    `[${label}] visited_nodes=${result.visitedNodes} truncated=${result.truncated}`
    + ` stale=${result.stale} reason=${result.reason} symlink_readdir_calls=${result.symlinkReaddirCalls}`,
  );
}

function totalOperations(ops) {
  return ops.lstatCalls + ops.readdirCalls;
}

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `missing ${name} in archived source`);
  const open = source.indexOf("{", start);
  assert.ok(open >= 0, `missing opening brace for ${name}`);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`unterminated function ${name}`);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}
