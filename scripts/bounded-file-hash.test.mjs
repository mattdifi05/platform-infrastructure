import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { sha256FileBounded } from "./bounded-file-hash.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

test("streams a regular file into the expected digest", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bounded-hash-"));
  try {
    const filePath = path.join(root, "artifact.dump");
    const content = Buffer.from("backup-artifact\n".repeat(8192));
    fs.writeFileSync(filePath, content);
    const result = sha256FileBounded(filePath, { chunkBytes: 4096, maxBytes: content.length + 1 });
    assert.equal(result.sha256, crypto.createHash("sha256").update(content).digest("hex"));
    assert.equal(result.sizeBytes, content.length);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects an oversized sparse artifact before reading it", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bounded-hash-"));
  try {
    const filePath = path.join(root, "oversized.dump");
    fs.closeSync(fs.openSync(filePath, "w"));
    fs.truncateSync(filePath, 64 * 1024 * 1024);
    assert.throws(
      () => sha256FileBounded(filePath, { maxBytes: 1024 * 1024 }),
      /exceeds hash size limit/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects cancellation, deadlines, and symbolic links", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bounded-hash-"));
  try {
    const filePath = path.join(root, "artifact.dump");
    fs.writeFileSync(filePath, "content");
    const controller = new AbortController();
    controller.abort();
    assert.throws(() => sha256FileBounded(filePath, { signal: controller.signal }), { name: "AbortError" });
    assert.throws(() => sha256FileBounded(filePath, { maxDurationMs: 0 }), /deadline exceeded/);
    const linkPath = path.join(root, "artifact-link.dump");
    fs.symlinkSync(filePath, linkPath);
    assert.throws(() => sha256FileBounded(linkPath), /symbolic link/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("large sparse hashing stays within a bounded child-process RSS", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bounded-hash-rss-"));
  try {
    const filePath = path.join(root, "large.dump");
    fs.closeSync(fs.openSync(filePath, "w"));
    fs.truncateSync(filePath, 128 * 1024 * 1024);
    const modulePath = path.join(here, "bounded-file-hash.mjs");
    const script = [
      `import { sha256FileBounded } from ${JSON.stringify(modulePath)};`,
      `sha256FileBounded(${JSON.stringify(filePath)}, { maxBytes: 129 * 1024 * 1024, chunkBytes: 1024 * 1024 });`,
      "process.stdout.write(String(process.resourceUsage().maxRSS));",
    ].join("\n");
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });
    assert.equal(result.status, 0, result.stderr);
    const maxRssKiB = Number(result.stdout);
    assert.ok(Number.isFinite(maxRssKiB));
    assert.ok(maxRssKiB < 112 * 1024, `max RSS ${maxRssKiB} KiB exceeded the streaming bound`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects a file that grows while it is being hashed", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bounded-hash-growth-"));
  try {
    const filePath = path.join(root, "growing.dump");
    fs.writeFileSync(filePath, Buffer.alloc(8192, 1));
    let changed = false;
    assert.throws(() => sha256FileBounded(filePath, {
      chunkBytes: 1024,
      onChunk() {
        if (!changed) {
          changed = true;
          fs.appendFileSync(filePath, Buffer.from([2]));
        }
      },
    }), /changed while hashing/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects a file that is truncated while it is being hashed", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bounded-hash-truncate-"));
  try {
    const filePath = path.join(root, "truncated.dump");
    fs.writeFileSync(filePath, Buffer.alloc(8192, 1));
    let changed = false;
    assert.throws(() => sha256FileBounded(filePath, {
      chunkBytes: 1024,
      onChunk() {
        if (!changed) {
          changed = true;
          fs.truncateSync(filePath, 1);
        }
      },
    }), /truncated while hashing/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("propagates read errors and closes the opened descriptor", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bounded-hash-read-error-"));
  try {
    const filePath = path.join(root, "unreadable.dump");
    fs.writeFileSync(filePath, Buffer.alloc(4096, 1));
    assert.throws(() => sha256FileBounded(filePath, {
      readChunk() {
        const error = new Error("synthetic read failure");
        error.code = "EIO";
        throw error;
      },
    }), /synthetic read failure/);
    fs.renameSync(filePath, `${filePath}.closed`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
