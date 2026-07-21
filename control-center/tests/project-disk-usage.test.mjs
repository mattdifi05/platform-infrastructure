import assert from "node:assert/strict";
import { lstat, opendir } from "node:fs/promises";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  createProjectDiskUsageReader,
  scanProjectTree,
} from "../resources/project-disk-usage.mjs";

function fixture(t, prefix) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("project disk usage scans asynchronously without following symlinks", async (t) => {
  const root = fixture(t, "project-disk-safe-");
  const outside = fixture(t, "project-disk-outside-");
  mkdirSync(path.join(root, "nested"));
  writeFileSync(path.join(root, "root.txt"), "root");
  writeFileSync(path.join(root, "nested", "child.txt"), "child");
  writeFileSync(path.join(outside, "large.bin"), Buffer.alloc(1024 * 1024));
  symlinkSync(outside, path.join(root, "outside-link"));

  const result = await scanProjectTree(root, {
    maxDepth: 8,
    maxNodes: 100,
    maxBytes: 2 * 1024 * 1024,
    timeoutMs: 1000,
    yieldEvery: 1,
  });
  assert.equal(result.complete, true);
  assert.equal(result.truncated, false);
  assert.equal(result.stale, false);
  assert.equal(result.files, 2);
  assert.equal(result.directories, 2);
  assert.equal(result.symlinks, 1);
  assert.equal(result.bytes < 1024 * 1024, true, "the external symlink target must not be counted or traversed");
});

test("project disk usage returns explicit depth, node, byte, and time ceilings", async (t) => {
  const deep = fixture(t, "project-disk-deep-");
  mkdirSync(path.join(deep, "a", "b", "c"), { recursive: true });
  const depth = await scanProjectTree(deep, { maxDepth: 1, maxNodes: 100, maxBytes: 1024 * 1024, timeoutMs: 1000 });
  assert.equal(depth.complete, false);
  assert.equal(depth.truncated, true);
  assert.equal(depth.reason, "depth");

  const wide = fixture(t, "project-disk-wide-");
  for (let index = 0; index < 10; index += 1) writeFileSync(path.join(wide, `${index}.txt`), "x");
  const nodes = await scanProjectTree(wide, { maxDepth: 4, maxNodes: 3, maxBytes: 1024 * 1024, timeoutMs: 1000 });
  assert.equal(nodes.truncated, true);
  assert.equal(nodes.reason, "nodes");

  const byteRoot = fixture(t, "project-disk-bytes-");
  writeFileSync(path.join(byteRoot, "large.bin"), Buffer.alloc(4096));
  const bytes = await scanProjectTree(byteRoot, { maxDepth: 4, maxNodes: 100, maxBytes: 1024, timeoutMs: 1000 });
  assert.equal(bytes.truncated, true);
  assert.equal(bytes.reason, "bytes");

  const slowRoot = fixture(t, "project-disk-slow-");
  writeFileSync(path.join(slowRoot, "file.txt"), "slow");
  const timeout = await scanProjectTree(slowRoot, {
    maxDepth: 4,
    maxNodes: 100,
    maxBytes: 1024 * 1024,
    timeoutMs: 5,
    fsApi: {
      opendir,
      lstat: async (...args) => {
        await pause(10);
        return lstat(...args);
      },
    },
  });
  assert.equal(timeout.truncated, true);
  assert.equal(timeout.reason, "timeout");
});

test("wide scans yield to the event loop", async (t) => {
  const root = fixture(t, "project-disk-yield-");
  for (let index = 0; index < 300; index += 1) writeFileSync(path.join(root, `${index}.txt`), "x");
  let ticks = 0;
  let ticking = true;
  const tick = () => {
    ticks += 1;
    if (ticking) setImmediate(tick);
  };
  setImmediate(tick);
  const result = await scanProjectTree(root, {
    maxDepth: 4,
    maxNodes: 1000,
    maxBytes: 1024 * 1024,
    timeoutMs: 2000,
    yieldEvery: 1,
  });
  ticking = false;
  assert.equal(result.complete, true);
  assert.equal(ticks > 1, true);
});

test("disk usage reader coalesces scans, bounds concurrency, and serves explicit stale data", async () => {
  let clock = 0;
  let calls = 0;
  let active = 0;
  let maxActive = 0;
  let fail = false;
  const scan = async (root) => {
    calls += 1;
    active += 1;
    maxActive = Math.max(maxActive, active);
    await pause(10);
    active -= 1;
    if (fail) throw new Error("fixture failure");
    return exactUsage(root, clock);
  };
  const reader = createProjectDiskUsageReader({
    ttlMs: 10,
    partialTtlMs: 5,
    staleTtlMs: 100,
    maxConcurrency: 2,
    scan,
    now: () => clock,
  });

  const [first, duplicate] = await Promise.all([
    reader.read("same", "/same"),
    reader.read("same", "/same"),
  ]);
  assert.deepEqual(duplicate, first);
  assert.equal(calls, 1);

  await Promise.all(Array.from({ length: 5 }, (_, index) => reader.read(`key-${index}`, `/root-${index}`)));
  assert.equal(maxActive, 2);

  clock = 11;
  fail = true;
  const stale = await reader.read("same", "/same");
  assert.equal(stale.available, true);
  assert.equal(stale.stale, true);
  assert.equal(stale.reason, "refresh-error");
});

function exactUsage(root, timestamp) {
  return {
    available: true,
    complete: true,
    truncated: false,
    stale: false,
    reason: "",
    bytes: root.length,
    files: 1,
    directories: 1,
    symlinks: 0,
    nodes: 2,
    measuredAt: new Date(timestamp).toISOString(),
  };
}

function pause(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
