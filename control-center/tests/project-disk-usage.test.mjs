import assert from "node:assert/strict";
import { lstat, opendir } from "node:fs/promises";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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
    anchorRoot: root,
    descriptorApi: portableDescriptorApi(),
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
  const depth = await scanProjectTree(deep, {
    anchorRoot: deep,
    descriptorApi: portableDescriptorApi(),
    maxDepth: 1,
    maxNodes: 100,
    maxBytes: 1024 * 1024,
    timeoutMs: 1000,
  });
  assert.equal(depth.complete, false);
  assert.equal(depth.truncated, true);
  assert.equal(depth.reason, "depth");

  const wide = fixture(t, "project-disk-wide-");
  for (let index = 0; index < 10; index += 1) writeFileSync(path.join(wide, `${index}.txt`), "x");
  const nodes = await scanProjectTree(wide, {
    anchorRoot: wide,
    descriptorApi: portableDescriptorApi(),
    maxDepth: 4,
    maxNodes: 3,
    maxBytes: 1024 * 1024,
    timeoutMs: 1000,
  });
  assert.equal(nodes.truncated, true);
  assert.equal(nodes.reason, "nodes");

  const byteRoot = fixture(t, "project-disk-bytes-");
  writeFileSync(path.join(byteRoot, "large.bin"), Buffer.alloc(4096));
  const bytes = await scanProjectTree(byteRoot, {
    anchorRoot: byteRoot,
    descriptorApi: portableDescriptorApi(),
    maxDepth: 4,
    maxNodes: 100,
    maxBytes: 1024,
    timeoutMs: 1000,
  });
  assert.equal(bytes.truncated, true);
  assert.equal(bytes.reason, "bytes");

  const slowRoot = fixture(t, "project-disk-slow-");
  writeFileSync(path.join(slowRoot, "file.txt"), "slow");
  const timeout = await scanProjectTree(slowRoot, {
    anchorRoot: slowRoot,
    descriptorApi: portableDescriptorApi({ statDelayMs: 10 }),
    maxDepth: 4,
    maxNodes: 100,
    maxBytes: 1024 * 1024,
    timeoutMs: 5,
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
    anchorRoot: root,
    descriptorApi: portableDescriptorApi(),
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

test("disk usage reader enforces a hard deadline and bounds unique inflight and queued scans", async () => {
  const never = async () => new Promise(() => {});
  const inflightReader = createProjectDiskUsageReader({
    scan: never,
    maxConcurrency: 1,
    maxQueue: 1,
    maxInflight: 2,
    hardDeadlineMs: 25,
  });
  const started = Date.now();
  const first = inflightReader.read("first", "/first");
  const second = inflightReader.read("second", "/second");
  const rejectedInflight = await Promise.race([
    inflightReader.read("third", "/third"),
    pause(100).then(() => null),
  ]);
  assert.notEqual(rejectedInflight, null, "inflight overflow must reject immediately");
  assert.equal(rejectedInflight.reason, "inflight-limit");
  const settled = await Promise.race([
    Promise.all([first, second]),
    pause(250).then(() => null),
  ]);
  assert.notEqual(settled, null, "hard deadline must settle active and queued reads");
  assert.deepEqual(settled.map((entry) => entry.reason), ["hard-deadline", "hard-deadline"]);
  assert.equal(Date.now() - started < 225, true);
  assert.equal(inflightReader.inflight.size, 0);
  assert.equal(inflightReader.queue.length, 0);
  assert.equal(inflightReader.active, 0);

  const queueReader = createProjectDiskUsageReader({
    scan: never,
    maxConcurrency: 1,
    maxQueue: 1,
    maxInflight: 3,
    hardDeadlineMs: 25,
  });
  const active = queueReader.read("active", "/active");
  const queued = queueReader.read("queued", "/queued");
  const rejectedQueue = await Promise.race([
    queueReader.read("overflow", "/overflow"),
    pause(100).then(() => null),
  ]);
  assert.notEqual(rejectedQueue, null, "queue overflow must reject immediately");
  assert.equal(rejectedQueue.reason, "queue-limit");
  await Promise.all([active, queued]);
  assert.equal(queueReader.inflight.size, 0);
  assert.equal(queueReader.queue.length, 0);
  assert.equal(queueReader.active, 0);
});

test("production traversal is worker-isolated and descriptor-anchored without pathname reopen", () => {
  const source = readFileSync(path.join(import.meta.dirname, "..", "resources", "project-disk-usage.mjs"), "utf8");
  assert.match(source, /new Worker\(/);
  assert.match(source, /\/proc\/self\/fd\/\$\{parent\.fd\}/);
  assert.doesNotMatch(source, /lstat\(current\.path\)/);
  assert.doesNotMatch(source, /opendir\(current\.path\)/);
});

test("default worker scanner uses Linux descriptors and otherwise fails closed", async (t) => {
  const root = fixture(t, "project-disk-worker-");
  writeFileSync(path.join(root, "file.txt"), "worker");
  const reader = createProjectDiskUsageReader({ hardDeadlineMs: 1000 });
  const result = await reader.read("worker", root, { anchorRoot: root });
  if (process.platform === "linux") {
    assert.equal(result.complete, true);
    assert.equal(result.files, 1);
    assert.equal(result.reason, "");
  } else {
    assert.equal(result.available, false);
    assert.equal(result.reason, "descriptor-unavailable");
  }
});

test("descriptor traversal consumes an opened project generation after its namespace entry is swapped", async () => {
  const safeFile = memoryNode("file", 4);
  const safeProject = memoryNode("directory", 1, new Map([["safe.txt", safeFile]]));
  const outsideProject = memoryNode("directory", 1, new Map([["outside.bin", memoryNode("file", 1024 * 1024)]]));
  const anchor = memoryNode("directory", 1, new Map([["project", safeProject]]));
  let namespaceProject = safeProject;
  let swapped = false;
  const descriptorApi = {
    openAnchor: async (requested) => {
      assert.equal(requested, "/trusted");
      return { node: anchor };
    },
    openChild: async (parent, name) => {
      if (parent.node === anchor && name === "project") {
        const opened = namespaceProject;
        namespaceProject = outsideProject;
        swapped = true;
        return { node: opened };
      }
      const child = parent.node.children.get(name);
      if (!child) throw new Error("missing in-memory child");
      return { node: child };
    },
    stat: async ({ node }) => memoryStat(node),
    entries: async function* entries({ node }) {
      for (const [name, child] of node.children) {
        yield { name, symbolicLink: child.kind === "symlink" };
      }
    },
    close: async () => {},
  };

  const result = await scanProjectTree("/trusted/project", {
    anchorRoot: "/trusted",
    descriptorApi,
    maxDepth: 4,
    maxNodes: 10,
    maxBytes: 2 * 1024 * 1024,
    timeoutMs: 1000,
  });
  assert.equal(swapped, true);
  assert.equal(result.complete, true);
  assert.equal(result.files, 1);
  assert.equal(result.bytes < 1024 * 1024, true, "the replacement namespace target must never be reopened");
});

function portableDescriptorApi({ statDelayMs = 0 } = {}) {
  return {
    openAnchor: async (requested) => ({ path: requested }),
    openChild: async (parent, name) => ({ path: path.join(parent.path, name) }),
    stat: async (handle) => {
      if (statDelayMs > 0) await pause(statDelayMs);
      return lstat(handle.path);
    },
    entries: async function* entries(handle) {
      let directory;
      try {
        directory = await opendir(handle.path);
        for await (const entry of directory) {
          yield { name: entry.name, symbolicLink: entry.isSymbolicLink() };
        }
      } finally {
        await directory?.close().catch(() => {});
      }
    },
    close: async () => {},
  };
}

function memoryNode(kind, size, children = new Map()) {
  return { kind, size, children };
}

function memoryStat(node) {
  return {
    size: node.size,
    isDirectory: () => node.kind === "directory",
    isSymbolicLink: () => node.kind === "symlink",
  };
}

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
