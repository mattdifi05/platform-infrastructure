#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const EXPECTED_HASHES = new Map([
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
  ["compose.backup-scheduler.yaml", "cf2ad09cd02f3a04c512450f0c730ec6637ac86646d9037c0be118a12c95c748"],
]);

const FIXTURE_BYTES = 8 * 1024 * 1024;
const CHUNK_BYTES = 64 * 1024;
const MAX_BYTES = 16 * 1024 * 1024;
const SPARSE_BYTES = 64 * 1024 * 1024;
const sourceArgument = process.argv[2];
const labArgument = process.argv[3];
if (!sourceArgument || !labArgument) {
  throw new Error("usage: streaming-backup-hash-probe.mjs WRAPPER_OWNED_SOURCE WRAPPER_OWNED_LAB");
}

const {
  sourceRoot,
  labRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedPaths(sourceArgument, labArgument);
const sourceBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source and synthetic lab verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256FileSmall(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const infraOpsPath = path.join(sourceRoot, "scripts/infra-ops.mjs");
const isolationPath = path.join(sourceRoot, "compose.runtime-isolation.yaml");
const schedulerPath = path.join(sourceRoot, "compose.backup-scheduler.yaml");
const infraOpsSource = fs.readFileSync(infraOpsPath, "utf8");
const isolationSource = fs.readFileSync(isolationPath, "utf8");
const schedulerSource = fs.readFileSync(schedulerPath, "utf8");
const vulnerableFunctionSource = extractFunction(infraOpsSource, "sha256File");
assert.match(vulnerableFunctionSource, /hash\.update\(fs\.readFileSync\(filePath\)\)/);
assert.doesNotMatch(vulnerableFunctionSource, /createReadStream|highWaterMark|maxBytes|AbortSignal|signal/);
assert.match(infraOpsSource, /function signBackupArtifact\(filePath, hash = sha256File\(filePath\)\)/);
assert.match(infraOpsSource, /function verifyBackupArtifact\(filePath\)[\s\S]*?const hash = sha256File\(filePath\)/);
assert.ok((infraOpsSource.match(/sha256File\(/g) ?? []).length >= 10, "expected broad sha256File reuse");
assert.match(isolationSource, /backup-scheduler:[\s\S]*?mem_limit: 512m[\s\S]*?mem_reservation: 128m/);
assert.match(schedulerSource, /backup-scheduler:[\s\S]*?BACKUP_SIGNING_KEYS_FILE:/);
console.log("[+] source proof read_strategy=readFileSync sign_and_verify_reuse=true scheduler_mem_limit=512m");

const fixturePath = path.join(labRoot, "synthetic-artifact.bin");
writeDeterministicFixture(fixturePath, FIXTURE_BYTES);
assert.equal(fs.statSync(fixturePath).size, FIXTURE_BYTES);

let fullReadCalls = 0;
let largestRead = 0;
const instrumentedFs = {
  readFileSync(filePath) {
    assert.equal(fs.realpathSync(filePath), fs.realpathSync(fixturePath));
    const data = fs.readFileSync(filePath);
    fullReadCalls += 1;
    largestRead = Math.max(largestRead, data.length);
    return data;
  },
};
const vulnerableSha256File = vm.runInNewContext(
  `(${vulnerableFunctionSource})`,
  { crypto, fs: instrumentedFs },
  { filename: "pinned-sha256File.mjs" },
);
const vulnerableDigest = vulnerableSha256File(fixturePath);
assert.match(vulnerableDigest, /^[a-f0-9]{64}$/);
assert.equal(fullReadCalls, 1);
assert.equal(largestRead, FIXTURE_BYTES);
console.log(`[VULNERABLE] whole_file_read calls=${fullReadCalls} artifact_bytes=${FIXTURE_BYTES} largest_read=${largestRead}`);

const streaming = await sha256FileBounded(fixturePath, {
  maxBytes: MAX_BYTES,
  maxMs: 5000,
  chunkBytes: CHUNK_BYTES,
});
assert.equal(streaming.digest, vulnerableDigest);
assert.equal(streaming.totalBytes, FIXTURE_BYTES);
assert.equal(streaming.maxChunkBytes, CHUNK_BYTES);
console.log("[CONTROL] digest_parity vulnerable_vs_streaming_equal=true");
console.log(`[FIXED] bounded_stream artifact_bytes=${streaming.totalBytes} chunk_bytes=${CHUNK_BYTES} max_observed_chunk=${streaming.maxChunkBytes} whole_file_buffer=false time_bound_configured=true`);

const sparsePath = path.join(labRoot, "synthetic-oversized-sparse.bin");
const sparseFd = fs.openSync(sparsePath, "wx", 0o600);
try {
  fs.ftruncateSync(sparseFd, SPARSE_BYTES);
} finally {
  fs.closeSync(sparseFd);
}
assert.equal(fs.statSync(sparsePath).size, SPARSE_BYTES);
let oversizedStreamOpens = 0;
await assert.rejects(
  sha256FileBounded(sparsePath, {
    maxBytes: MAX_BYTES,
    maxMs: 5000,
    chunkBytes: CHUNK_BYTES,
    streamFactory(filePath, options) {
      oversizedStreamOpens += 1;
      return fs.createReadStream(filePath, options);
    },
  }),
  /artifact-size-limit/,
);
assert.equal(oversizedStreamOpens, 0);
console.log(`[CONTROL] oversized_sparse declared_bytes=${SPARSE_BYTES} max_bytes=${MAX_BYTES} rejected_before_stream=true`);

const cancellation = new AbortController();
let chunksBeforeAbort = 0;
await assert.rejects(
  sha256FileBounded(fixturePath, {
    maxBytes: MAX_BYTES,
    maxMs: 5000,
    chunkBytes: CHUNK_BYTES,
    signal: cancellation.signal,
    onChunk() {
      chunksBeforeAbort += 1;
      cancellation.abort(new Error("synthetic-cancel"));
    },
  }),
  /hash-cancelled/,
);
assert.equal(chunksBeforeAbort, 1);
console.log(`[CONTROL] cancellation chunks_before_abort=${chunksBeforeAbort} cancelled=true`);

assert.equal(directoryDigest(sourceRoot), sourceBefore, "the archived source changed during the probe");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the probe");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the probe");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the probe");
console.log("[+] source_tree_unchanged=true synthetic_only=true");
console.log("[+] no real backup, database, Docker daemon, credential, network, live target, or candidate working tree was read or changed");

async function sha256FileBounded(filePath, options) {
  const {
    maxBytes,
    maxMs,
    chunkBytes,
    signal = null,
    onChunk = null,
    streamFactory = (target, streamOptions) => fs.createReadStream(target, streamOptions),
  } = options;
  assert.ok(Number.isSafeInteger(maxBytes) && maxBytes > 0, "maxBytes must be a positive safe integer");
  assert.ok(Number.isSafeInteger(maxMs) && maxMs > 0, "maxMs must be a positive safe integer");
  assert.ok(Number.isSafeInteger(chunkBytes) && chunkBytes > 0 && chunkBytes <= maxBytes);

  const initial = fs.lstatSync(filePath);
  if (!initial.isFile() || initial.isSymbolicLink()) throw new Error("artifact-type-limit");
  if (initial.size > maxBytes) throw new Error("artifact-size-limit");
  if (signal?.aborted) throw new Error("hash-cancelled");

  const controller = new AbortController();
  const forwardAbort = () => controller.abort(signal?.reason ?? new Error("hash-cancelled"));
  signal?.addEventListener("abort", forwardAbort, { once: true });
  const timer = setTimeout(() => controller.abort(new Error("hash-time-limit")), maxMs);
  timer.unref?.();
  let totalBytes = 0;
  let maxChunkBytes = 0;
  const hash = crypto.createHash("sha256");
  try {
    const stream = streamFactory(filePath, {
      highWaterMark: chunkBytes,
      signal: controller.signal,
    });
    for await (const chunk of stream) {
      totalBytes += chunk.length;
      maxChunkBytes = Math.max(maxChunkBytes, chunk.length);
      if (totalBytes > maxBytes) {
        controller.abort(new Error("artifact-size-limit"));
        throw new Error("artifact-size-limit");
      }
      onChunk?.(chunk);
      hash.update(chunk);
    }
    if (signal?.aborted) throw new Error("hash-cancelled");
    const final = fs.lstatSync(filePath);
    if (final.dev !== initial.dev || final.ino !== initial.ino || final.size !== initial.size || final.mtimeMs !== initial.mtimeMs) {
      throw new Error("artifact-changed-during-hash");
    }
    return { digest: hash.digest("hex"), totalBytes, maxChunkBytes };
  } catch (error) {
    if (signal?.aborted) throw new Error("hash-cancelled");
    if (controller.signal.aborted && String(controller.signal.reason?.message ?? controller.signal.reason).includes("hash-time-limit")) {
      throw new Error("hash-time-limit");
    }
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", forwardAbort);
  }
}

function writeDeterministicFixture(filePath, size) {
  assert.ok(Number.isSafeInteger(size) && size > 0 && size <= MAX_BYTES);
  const block = Buffer.alloc(CHUNK_BYTES);
  for (let index = 0; index < block.length; index += 1) {
    block[index] = (index * 31 + 17) & 0xff;
  }
  const fd = fs.openSync(filePath, "wx", 0o600);
  try {
    let written = 0;
    while (written < size) {
      const length = Math.min(block.length, size - written);
      const count = fs.writeSync(fd, block, 0, length, written);
      assert.equal(count, length, "short synthetic fixture write");
      written += count;
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function extractFunction(source, name) {
  const marker = `function ${name}(`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing function ${name}`);
  const open = source.indexOf("{", start + marker.length);
  assert.notEqual(open, -1, `missing body for ${name}`);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  throw new Error(`unterminated function ${name}`);
}

function validateWrapperOwnedPaths(sourceInput, labInput) {
  const wrapperInput = requiredEnvironment("FG077_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG077_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG077_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(path.basename(wrapperReal), /^fg077-(?:guard|run)\.[A-Za-z0-9]+$/);

  const sourcePath = path.resolve(sourceInput);
  const sourceStat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(sourcePath);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned source child");

  const labPath = path.resolve(labInput);
  const labStat = fs.lstatSync(labPath, { throwIfNoEntry: false });
  assert.ok(labStat?.isDirectory(), "synthetic lab directory is missing");
  assert.equal(labStat.isSymbolicLink(), false, "synthetic lab must not be a symlink");
  const labReal = fs.realpathSync(labPath);
  assert.equal(labReal, path.join(wrapperReal, "lab"), "lab must be the exact wrapper-owned lab child");

  const sentinelPath = path.resolve(sentinelInput);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside the wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg077-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg077-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG077-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  return {
    sourceRoot: sourceReal,
    labRoot: labReal,
    sentinelPath: sentinelReal,
    sentinelText,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
  };
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke through run-from-git-archive.sh`);
  }
  return value;
}

function sha256FileSmall(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function directoryDigest(root) {
  const digest = crypto.createHash("sha256");
  walk(root, "");
  return digest.digest("hex");

  function walk(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      digest.update(`L\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    if (stat.isDirectory()) {
      digest.update(`D\0${relative}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        walk(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    assert.equal(stat.isFile(), true, `unsupported archived entry: ${relative}`);
    digest.update(`F\0${relative}\0`);
    digest.update(fs.readFileSync(current));
    digest.update("\0");
  }
}
