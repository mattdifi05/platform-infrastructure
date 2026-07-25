#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  extractSourceArchive,
  inspectSourceArchive,
  validateExactSourceArchive,
  validateExtractedSourceArchive,
  validateExtractedSourceTree,
} from "./source-archive-policy.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "source-archive-policy-test-"));
process.on("exit", () => {
  spawnSync("chmod", ["-R", "u+w", temporary]);
  fs.rmSync(temporary, { recursive: true, force: true });
});

function git(...args) {
  const result = spawnSync("git", ["-C", root, ...args], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function gitAt(repository, ...args) {
  const result = spawnSync("git", ["-C", repository, ...args], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function archive(name, umask) {
  const pathname = path.join(temporary, name);
  git("-c", `tar.umask=${umask}`, "archive", "--format=tar", `--output=${pathname}`, commitSha);
  return pathname;
}

function tarNumber(bytes) {
  return Number.parseInt(bytes.toString("ascii").replace(/\0.*$/su, "").trim() || "0", 8);
}

function firstRegular(bytes) {
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) throw new Error("fixture contains no regular tar entry");
    const size = tarNumber(header.subarray(124, 136));
    const type = String.fromCharCode(header[156] || 0x30);
    const span = 512 + Math.ceil(size / 512) * 512;
    if (type === "0") return { offset, size, span };
    offset += span;
  }
  throw new Error("fixture contains no regular tar entry");
}

function rewriteChecksum(bytes, offset) {
  bytes.fill(0x20, offset + 148, offset + 156);
  let checksum = 0;
  for (let index = 0; index < 512; index += 1) checksum += bytes[offset + index];
  const field = Buffer.from(`${checksum.toString(8).padStart(6, "0")}\0 `, "ascii");
  field.copy(bytes, offset + 148);
}

function writeMutation(name, mutate) {
  const bytes = Buffer.from(fs.readFileSync(defaultArchive));
  mutate(bytes);
  const pathname = path.join(temporary, name);
  fs.writeFileSync(pathname, bytes);
  return { pathname, sha256: sha256(bytes) };
}

const commitSha = git("rev-parse", "HEAD");
const treeSha = git("rev-parse", "HEAD^{tree}");
const defaultArchive = archive("default.tar", "0000");
const restrictiveArchive = archive("restrictive.tar", "0077");

const validated = validateExactSourceArchive({
  archivePath: defaultArchive,
  gitRoot: root,
  commitSha,
  treeSha,
  expectedSha256: sha256(fs.readFileSync(defaultArchive)),
});
assert.equal(validated.status, "passed");
assert.ok(validated.fileCount > 0);

assert.equal(validateExactSourceArchive({
  archivePath: restrictiveArchive,
  gitRoot: root,
  commitSha,
  treeSha,
  expectedSha256: sha256(fs.readFileSync(restrictiveArchive)),
}).status, "passed", "local tar.umask must not affect semantic source verification");
assert.notEqual(
  sha256(fs.readFileSync(defaultArchive)),
  sha256(fs.readFileSync(restrictiveArchive)),
  "restrictive tar.umask fixture must produce different serialized bytes",
);

assert.throws(() => inspectSourceArchive({
  archivePath: defaultArchive,
  expectedSha256: "0".repeat(64),
  commitSha,
}), /admitted SHA256/);

const contentMutation = writeMutation("content-mutation.tar", (bytes) => {
  const entry = firstRegular(bytes);
  bytes[entry.offset + 512] ^= 0xff;
});
assert.throws(() => validateExactSourceArchive({
  archivePath: contentMutation.pathname,
  gitRoot: root,
  commitSha,
  treeSha,
  expectedSha256: contentMutation.sha256,
}), /bytes differ from Git/);

const traversal = writeMutation("traversal.tar", (bytes) => {
  const entry = firstRegular(bytes);
  bytes.fill(0, entry.offset, entry.offset + 100);
  Buffer.from("../escape", "ascii").copy(bytes, entry.offset);
  bytes.fill(0, entry.offset + 345, entry.offset + 500);
  rewriteChecksum(bytes, entry.offset);
});
assert.throws(() => inspectSourceArchive({
  archivePath: traversal.pathname,
  expectedSha256: traversal.sha256,
  commitSha,
}), /unsafe path/);

const paxHeaderTraversal = writeMutation("pax-header-traversal.tar", (bytes) => {
  const entry = firstRegular(bytes);
  bytes.fill(0, entry.offset, entry.offset + 100);
  Buffer.from("../hidden-pax-header", "ascii").copy(bytes, entry.offset);
  bytes[entry.offset + 156] = "x".charCodeAt(0);
  rewriteChecksum(bytes, entry.offset);
});
assert.throws(() => inspectSourceArchive({
  archivePath: paxHeaderTraversal.pathname,
  expectedSha256: paxHeaderTraversal.sha256,
  commitSha,
}), /unsafe path/, "raw PAX header paths must be validated even when a path override could follow");

const invalidUtf8Path = writeMutation("invalid-utf8-path.tar", (bytes) => {
  const entry = firstRegular(bytes);
  bytes[entry.offset] = 0xff;
  rewriteChecksum(bytes, entry.offset);
});
assert.throws(() => inspectSourceArchive({
  archivePath: invalidUtf8Path.pathname,
  expectedSha256: invalidUtf8Path.sha256,
  commitSha,
}), /not valid UTF-8/);

const link = writeMutation("link.tar", (bytes) => {
  const entry = firstRegular(bytes);
  bytes[entry.offset + 156] = "2".charCodeAt(0);
  rewriteChecksum(bytes, entry.offset);
});
assert.throws(() => inspectSourceArchive({
  archivePath: link.pathname,
  expectedSha256: link.sha256,
  commitSha,
}), /forbidden tar entry type/);

const executableMismatch = writeMutation("executable-mismatch.tar", (bytes) => {
  const entry = firstRegular(bytes);
  Buffer.from("0000755\0", "ascii").copy(bytes, entry.offset + 100);
  rewriteChecksum(bytes, entry.offset);
});
assert.throws(() => validateExactSourceArchive({
  archivePath: executableMismatch.pathname,
  gitRoot: root,
  commitSha,
  treeSha,
  expectedSha256: executableMismatch.sha256,
}), /executable mode differs from Git/);

const defaultBytes = fs.readFileSync(defaultArchive);
const regular = firstRegular(defaultBytes);
let endOffset = regular.offset + regular.span;
while (endOffset + 512 <= defaultBytes.length && !defaultBytes.subarray(endOffset, endOffset + 512).every((byte) => byte === 0)) {
  const size = tarNumber(defaultBytes.subarray(endOffset + 124, endOffset + 136));
  endOffset += 512 + Math.ceil(size / 512) * 512;
}
const duplicateBytes = Buffer.concat([
  defaultBytes.subarray(0, endOffset),
  defaultBytes.subarray(regular.offset, regular.offset + regular.span),
  Buffer.alloc(1024),
]);
const duplicatePath = path.join(temporary, "duplicate.tar");
fs.writeFileSync(duplicatePath, duplicateBytes);
assert.throws(() => inspectSourceArchive({
  archivePath: duplicatePath,
  expectedSha256: sha256(duplicateBytes),
  commitSha,
}), /duplicate path/);

const extractedRoot = path.join(temporary, "extracted");
fs.mkdirSync(extractedRoot);
const extractResult = spawnSync("tar", ["-xf", defaultArchive, "-C", extractedRoot], { encoding: "utf8" });
assert.equal(extractResult.status, 0, extractResult.stderr);
assert.equal(validateExtractedSourceTree({
  rootPath: extractedRoot,
  gitRoot: root,
  commitSha,
  treeSha,
}).status, "passed");
fs.symlinkSync("/tmp", path.join(extractedRoot, "forbidden-link"));
assert.throws(() => validateExtractedSourceTree({
  rootPath: extractedRoot,
  gitRoot: root,
  commitSha,
  treeSha,
}), /forbidden filesystem type/);

fs.rmSync(path.join(extractedRoot, "forbidden-link"));
fs.chmodSync(extractedRoot, 0o777);
assert.throws(() => validateExtractedSourceTree({
  rootPath: extractedRoot,
  gitRoot: root,
  commitSha,
  treeSha,
  requireImmutableOwnership: true,
}), /canonical path|root-owned|non-canonical permissions/);

const policyExtractedRoot = path.join(temporary, "policy-extracted");
fs.mkdirSync(policyExtractedRoot);
assert.equal(extractSourceArchive({
  rootPath: policyExtractedRoot,
  archivePath: defaultArchive,
  expectedSha256: sha256(fs.readFileSync(defaultArchive)),
  commitSha,
}).status, "passed");
assert.equal(validateExtractedSourceArchive({
  rootPath: policyExtractedRoot,
  archivePath: defaultArchive,
  expectedSha256: sha256(fs.readFileSync(defaultArchive)),
  commitSha,
}).status, "passed");
const policyExtractedFile = path.join(policyExtractedRoot, validated.files?.[0] ?? inspectSourceArchive({
  archivePath: defaultArchive,
  commitSha,
}).files[0]);
fs.chmodSync(policyExtractedFile, 0o644);
fs.appendFileSync(policyExtractedFile, "tampered");
assert.throws(() => validateExtractedSourceArchive({
  rootPath: policyExtractedRoot,
  archivePath: defaultArchive,
  expectedSha256: sha256(fs.readFileSync(defaultArchive)),
  commitSha,
}), /bytes differ from the archive/);

const replaceRepository = path.join(temporary, "replace-repository");
const cloneResult = spawnSync("git", ["clone", "--quiet", "--no-hardlinks", root, replaceRepository], { encoding: "utf8" });
assert.equal(cloneResult.status, 0, cloneResult.stderr);
const replaceCommit = gitAt(replaceRepository, "rev-parse", "HEAD");
const replaceTree = gitAt(replaceRepository, "rev-parse", "HEAD^{tree}");
const replaceArchive = path.join(temporary, "replace.tar");
gitAt(replaceRepository, "-c", "tar.umask=0000", "archive", "--format=tar", `--output=${replaceArchive}`, replaceCommit);
const firstBlob = gitAt(replaceRepository, "ls-tree", "-r", "--format=%(objectname)", replaceCommit).split("\n")[0];
const replacement = spawnSync("git", ["-C", replaceRepository, "hash-object", "-w", "--stdin"], {
  encoding: "utf8",
  input: "attacker-controlled replacement bytes\n",
});
assert.equal(replacement.status, 0, replacement.stderr);
gitAt(replaceRepository, "replace", firstBlob, replacement.stdout.trim());
assert.throws(() => validateExactSourceArchive({
  archivePath: replaceArchive,
  gitRoot: replaceRepository,
  commitSha: replaceCommit,
  treeSha: replaceTree,
  expectedSha256: sha256(fs.readFileSync(replaceArchive)),
}), /replacement refs/);

process.stdout.write("source archive policy tests passed 17/17\n");
