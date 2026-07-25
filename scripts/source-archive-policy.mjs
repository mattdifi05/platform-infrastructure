#!/usr/bin/env node
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

function strictUtf8(bytes, label) {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    invalid(`${label} is not valid UTF-8.`);
  }
}

function snapshotFileArtifact(filePath, { label, maxBytes }) {
  const pathname = path.resolve(String(filePath ?? ""));
  const before = fs.lstatSync(pathname, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    invalid(`${label} must be one regular non-linked file.`);
  }
  if (before.size < 1n || before.size > BigInt(maxBytes)) {
    invalid(`${label} size is outside the accepted range.`);
  }
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const descriptor = fs.openSync(pathname, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (
      !opened.isFile()
      || opened.nlink !== 1n
      || opened.dev !== before.dev
      || opened.ino !== before.ino
      || opened.size !== before.size
    ) {
      invalid(`${label} changed while it was opened.`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (
      after.dev !== opened.dev
      || after.ino !== opened.ino
      || after.size !== opened.size
      || after.mtimeNs !== opened.mtimeNs
      || after.ctimeNs !== opened.ctimeNs
    ) {
      invalid(`${label} changed while it was read.`);
    }
    return {
      bytes,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      cleanup() {},
    };
  } finally {
    fs.closeSync(descriptor);
  }
}

function invalid(message) {
  throw new Error(message);
}

function exactGitSha(value, label) {
  const text = String(value ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(text)) invalid(`${label} must be one full lowercase Git SHA.`);
  return text;
}

function parseArgs(values) {
  const options = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) invalid(`Unexpected argument: ${value}`);
    const key = value.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith("--")) invalid(`Missing value for --${key}.`);
    options[key] = next;
    index += 1;
  }
  return options;
}

function runGit(gitRoot, args, { input = undefined, encoding = "buffer", maxBuffer = 512 * 1024 * 1024 } = {}) {
  const env = {
    PATH: process.env.PATH,
    HOME: "/nonexistent",
    LANG: "C",
    LC_ALL: "C",
    XDG_CONFIG_HOME: "/nonexistent",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
  };
  const result = spawnSync("git", ["--no-replace-objects", "-C", gitRoot, ...args], {
    input,
    encoding: encoding === "buffer" ? null : encoding,
    env,
    maxBuffer,
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) {
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString("utf8") : String(result.stderr ?? "");
    invalid(`Git source-archive verification failed: ${String(result.error?.message ?? stderr).trim() || args.join(" ")}`);
  }
  return result.stdout;
}

function tarString(bytes, label, { allowSpacePadding = false } = {}) {
  const nul = bytes.indexOf(0);
  if (
    nul !== -1
    && !bytes.subarray(nul).every((byte) => byte === 0 || (allowSpacePadding && byte === 0x20))
  ) {
    invalid(`${label} contains non-NUL bytes after its terminator.`);
  }
  return strictUtf8(bytes.subarray(0, nul === -1 ? bytes.length : nul), label);
}

function tarNumber(bytes, label) {
  if (bytes[0] & 0x80) invalid(`${label} uses an unsupported base-256 encoding.`);
  const value = tarString(bytes, label, { allowSpacePadding: true }).trim().replace(/\s+$/u, "");
  if (!value) return 0;
  if (!/^[0-7]+$/.test(value)) invalid(`${label} is not canonical octal.`);
  const number = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(number) || number < 0) invalid(`${label} is outside the accepted range.`);
  return number;
}

function tarPath(value) {
  const pathname = String(value ?? "").replace(/\/+$/u, "");
  if (
    !pathname
    || pathname.startsWith("/")
    || pathname.includes("\\")
    || /[\0\r\n]/u.test(pathname)
    || pathname.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    invalid(`Source archive contains unsafe path ${JSON.stringify(value)}.`);
  }
  return pathname;
}

function parsePax(bytes) {
  const fields = new Map();
  let offset = 0;
  while (offset < bytes.length) {
    const space = bytes.indexOf(0x20, offset);
    if (space < 0) invalid("Source archive contains a malformed PAX record length.");
    const lengthText = strictUtf8(bytes.subarray(offset, space), "PAX record length");
    if (!/^[1-9][0-9]*$/.test(lengthText)) invalid("Source archive contains a malformed PAX record length.");
    const length = Number(lengthText);
    const end = offset + length;
    if (!Number.isSafeInteger(length) || end > bytes.length || bytes[end - 1] !== 0x0a) {
      invalid("Source archive contains a truncated PAX record.");
    }
    const record = strictUtf8(bytes.subarray(space + 1, end - 1), "PAX record");
    const separator = record.indexOf("=");
    if (separator < 1) invalid("Source archive contains a malformed PAX record.");
    const key = record.slice(0, separator);
    const value = record.slice(separator + 1);
    if (fields.has(key)) invalid(`Source archive contains duplicate PAX field ${key}.`);
    fields.set(key, value);
    offset = end;
  }
  return fields;
}

function parseTar(bytes) {
  const files = new Map();
  const directories = new Set();
  const seenPaths = new Set();
  const globalPax = new Map();
  let pendingPax = null;
  let offset = 0;
  let ended = false;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      ended = true;
      break;
    }
    const recordedChecksum = tarNumber(header.subarray(148, 156), "tar header checksum");
    let computedChecksum = 0;
    for (let index = 0; index < 512; index += 1) {
      computedChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
    }
    if (computedChecksum !== recordedChecksum) invalid("Source archive contains an invalid tar header checksum.");
    const size = tarNumber(header.subarray(124, 136), "tar entry size");
    const mode = tarNumber(header.subarray(100, 108), "tar entry mode");
    const type = String.fromCharCode(header[156] || 0x30);
    if (!header.subarray(257, 263).equals(Buffer.from("ustar\0", "ascii")) || !header.subarray(263, 265).equals(Buffer.from("00", "ascii"))) {
      invalid("Source archive entry is not canonical POSIX ustar.");
    }
    if (header.subarray(157, 257).some((byte) => byte !== 0)) {
      invalid("Source archive entry contains a forbidden link target.");
    }
    const name = tarString(header.subarray(0, 100), "tar entry name");
    const prefix = tarString(header.subarray(345, 500), "tar entry prefix");
    const headerPath = prefix ? `${prefix}/${name}` : name;
    tarPath(headerPath);
    const contentStart = offset + 512;
    const contentEnd = contentStart + size;
    if (contentEnd > bytes.length) invalid("Source archive contains a truncated tar entry.");
    const content = bytes.subarray(contentStart, contentEnd);
    offset = contentStart + Math.ceil(size / 512) * 512;

    if (type === "g") {
      if (pendingPax) invalid("Source archive contains a global PAX header after a pending local PAX header.");
      const fields = parsePax(content);
      for (const [key, value] of fields) {
        if (key !== "comment") invalid(`Source archive contains unsupported global PAX field ${key}.`);
        if (globalPax.has(key)) invalid(`Source archive contains duplicate global PAX field ${key}.`);
        globalPax.set(key, value);
      }
      continue;
    }
    if (type === "x") {
      if (pendingPax) invalid("Source archive contains stacked local PAX headers.");
      pendingPax = parsePax(content);
      for (const key of pendingPax.keys()) {
        if (key !== "path") invalid(`Source archive contains unsupported local PAX field ${key}.`);
      }
      continue;
    }
    if (type !== "0" && type !== "5") {
      invalid(`Source archive contains forbidden tar entry type ${JSON.stringify(type)}.`);
    }
    const pathname = tarPath(pendingPax?.get("path") ?? headerPath);
    pendingPax = null;
    if (seenPaths.has(pathname)) invalid(`Source archive contains duplicate path ${pathname}.`);
    seenPaths.add(pathname);
    if ((mode & ~0o777) !== 0) invalid(`Source archive path ${pathname} contains special permission bits.`);
    if (type === "5") {
      if (size !== 0) invalid(`Source archive directory ${pathname} contains a payload.`);
      directories.add(pathname);
      continue;
    }
    files.set(pathname, {
      bytes: Buffer.from(content),
      executable: (mode & 0o111) !== 0,
    });
  }
  if (!ended || pendingPax) invalid("Source archive has no canonical end marker.");
  if (!bytes.subarray(offset).every((byte) => byte === 0)) invalid("Source archive contains trailing non-zero bytes.");
  return { files, directories, globalPax };
}

const persistentRuntimeBoundaries = [
  "reports",
  "backups",
  "release",
  ".tmp",
  "security/sbom",
  "security/dast",
  "projects-portal/state",
  "secrets",
  "traefik/acme",
  "traefik/certs",
];

function assertNoPersistentRuntimePaths(parsed) {
  for (const pathname of [...parsed.files.keys(), ...parsed.directories]) {
    if (persistentRuntimeBoundaries.some((boundary) => pathname === boundary || pathname.startsWith(`${boundary}/`))) {
      invalid(`Source archive crosses persistent runtime boundary ${pathname}.`);
    }
  }
}

export function inspectSourceArchive({ archivePath, expectedSha256 = null, commitSha = null }) {
  const snapshot = snapshotFileArtifact(archivePath, {
    label: "exact release source archive",
    maxBytes: 256 * 1024 * 1024,
  });
  try {
    if (expectedSha256 !== null && snapshot.sha256 !== String(expectedSha256)) {
      invalid("Source archive bytes do not match the admitted SHA256.");
    }
    const parsed = parseTar(snapshot.bytes);
    assertNoPersistentRuntimePaths(parsed);
    if (commitSha !== null && parsed.globalPax.get("comment") !== exactGitSha(commitSha, "commit SHA")) {
      invalid("Source archive global commit identity is missing or mismatched.");
    }
    return {
      status: "passed",
      sourceArchiveSha256: snapshot.sha256,
      fileCount: parsed.files.size,
      directoryCount: parsed.directories.size,
      files: [...parsed.files.keys()].sort(),
    };
  } finally {
    snapshot.cleanup();
  }
}

function parseTree(bytes) {
  const entries = [];
  for (const rawRecord of strictUtf8(bytes, "Git tree listing").split("\0").filter(Boolean)) {
    const separator = rawRecord.indexOf("\t");
    const metadata = rawRecord.slice(0, separator).split(" ");
    const pathname = rawRecord.slice(separator + 1);
    if (separator < 1 || metadata.length !== 3) invalid("Git tree listing is malformed.");
    entries.push({ mode: metadata[0], type: metadata[1], oid: metadata[2], path: tarPath(pathname) });
  }
  return entries;
}

function repositoryControlPath(gitRoot, value) {
  const text = String(value ?? "").trim();
  if (!text) invalid("Git repository control path is empty.");
  return path.isAbsolute(text) ? path.resolve(text) : path.resolve(gitRoot, text);
}

function assertClosedGitRepository(gitRoot) {
  const root = path.resolve(gitRoot);
  const commonDir = repositoryControlPath(
    root,
    runGit(root, ["rev-parse", "--path-format=absolute", "--git-common-dir"], { encoding: "utf8" }),
  );
  const gitDir = repositoryControlPath(
    root,
    runGit(root, ["rev-parse", "--path-format=absolute", "--git-dir"], { encoding: "utf8" }),
  );
  const replaceRefs = runGit(root, ["for-each-ref", "--format=%(refname)", "refs/replace"], { encoding: "utf8" }).trim();
  if (replaceRefs) invalid("Git source repository contains forbidden replacement refs.");
  if (runGit(root, ["rev-parse", "--is-shallow-repository"], { encoding: "utf8" }).trim() !== "false") {
    invalid("Git source repository must not be shallow.");
  }
  for (const forbiddenPath of [
    path.join(commonDir, "info", "grafts"),
    path.join(commonDir, "objects", "info", "alternates"),
    path.join(commonDir, "shallow"),
    path.join(gitDir, "shallow"),
  ]) {
    if (fs.existsSync(forbiddenPath)) {
      invalid(`Git source repository contains forbidden history/object indirection at ${forbiddenPath}.`);
    }
  }
}

function exportIgnoreMap(gitRoot, commitSha, paths) {
  if (paths.length === 0) return new Map();
  const output = runGit(
    gitRoot,
    ["check-attr", "-z", "--stdin", `--source=${commitSha}`, "export-ignore"],
    { input: Buffer.from(`${paths.join("\0")}\0`) },
  );
  const fields = output.toString("utf8").split("\0");
  if (fields.at(-1) === "") fields.pop();
  if (fields.length !== paths.length * 3) invalid("Git export-ignore attribute output is incomplete.");
  const result = new Map();
  for (let index = 0; index < fields.length; index += 3) {
    if (fields[index + 1] !== "export-ignore") invalid("Git export-ignore attribute output is malformed.");
    result.set(fields[index], !["unspecified", "unset", "false"].includes(fields[index + 2]));
  }
  return result;
}

function gitBlobMap(gitRoot, entries) {
  if (entries.length === 0) return new Map();
  const input = Buffer.from(`${entries.map((entry) => entry.oid).join("\n")}\n`);
  const output = runGit(gitRoot, ["cat-file", "--batch"], { input });
  const blobs = new Map();
  let offset = 0;
  for (const entry of entries) {
    const newline = output.indexOf(0x0a, offset);
    if (newline < 0) invalid("Git cat-file output is truncated.");
    const header = output.subarray(offset, newline).toString("ascii").split(" ");
    if (header.length !== 3 || header[0] !== entry.oid || header[1] !== "blob" || !/^[0-9]+$/.test(header[2])) {
      invalid(`Git cat-file output is malformed for ${entry.path}.`);
    }
    const size = Number(header[2]);
    const start = newline + 1;
    const end = start + size;
    if (!Number.isSafeInteger(size) || end >= output.length || output[end] !== 0x0a) {
      invalid(`Git blob output is truncated for ${entry.path}.`);
    }
    blobs.set(entry.path, Buffer.from(output.subarray(start, end)));
    offset = end + 1;
  }
  if (offset !== output.length) invalid("Git cat-file output contains unexpected trailing bytes.");
  return blobs;
}

function exactGitExport(gitRoot, commitSha, treeSha) {
  assertClosedGitRepository(gitRoot);
  const observedTree = runGit(gitRoot, ["rev-parse", `${commitSha}^{tree}`], { encoding: "utf8" }).trim();
  if (observedTree !== treeSha) invalid("Source archive commit does not resolve to the admitted Git tree.");
  const treeEntries = parseTree(runGit(gitRoot, ["ls-tree", "-r", "-t", "-z", commitSha]));
  for (const entry of treeEntries) {
    if (!["040000", "100644", "100755"].includes(entry.mode)) {
      invalid(`Git source tree contains forbidden mode ${entry.mode} at ${entry.path}.`);
    }
    if ((entry.mode === "040000") !== (entry.type === "tree")) {
      invalid(`Git source tree type is inconsistent at ${entry.path}.`);
    }
  }
  const attributes = exportIgnoreMap(gitRoot, commitSha, treeEntries.map((entry) => entry.path));
  const ignoredDirectories = new Set(treeEntries
    .filter((entry) => entry.mode === "040000" && attributes.get(entry.path))
    .map((entry) => entry.path));
  const ignored = (entry) => attributes.get(entry.path)
    || [...ignoredDirectories].some((directory) => entry.path.startsWith(`${directory}/`));
  const files = treeEntries.filter((entry) => entry.mode !== "040000" && !ignored(entry));
  const directories = new Set();
  for (const entry of files) {
    const segments = entry.path.split("/");
    for (let index = 1; index < segments.length; index += 1) {
      directories.add(segments.slice(0, index).join("/"));
    }
  }
  return { files, directories, blobs: gitBlobMap(gitRoot, files) };
}

export function validateExactSourceArchive({ archivePath, gitRoot, commitSha, treeSha, expectedSha256 = null }) {
  const expectedCommit = exactGitSha(commitSha, "commit SHA");
  const expectedTree = exactGitSha(treeSha, "tree SHA");
  const root = path.resolve(String(gitRoot ?? ""));
  const snapshot = snapshotFileArtifact(archivePath, {
    label: "exact release source archive",
    maxBytes: 256 * 1024 * 1024,
  });
  try {
    if (expectedSha256 !== null && snapshot.sha256 !== String(expectedSha256)) {
      invalid("Source archive bytes do not match the admitted SHA256.");
    }
    const parsed = parseTar(snapshot.bytes);
    assertNoPersistentRuntimePaths(parsed);
    if (parsed.globalPax.get("comment") !== expectedCommit) {
      invalid("Source archive global commit identity is missing or mismatched.");
    }
    const exported = exactGitExport(root, expectedCommit, expectedTree);
    const expectedFiles = exported.files;
    const expectedPaths = new Set(expectedFiles.map((entry) => entry.path));
    if (
      parsed.files.size !== expectedPaths.size
      || [...parsed.files.keys()].some((pathname) => !expectedPaths.has(pathname))
    ) {
      invalid("Source archive regular-file set differs from the exact exported Git tree.");
    }
    const expectedDirectories = exported.directories;
    if (
      parsed.directories.size !== expectedDirectories.size
      || [...parsed.directories].some((pathname) => !expectedDirectories.has(pathname))
    ) {
      invalid("Source archive directory set differs from the exact exported Git tree.");
    }
    for (const entry of expectedFiles) {
      const archived = parsed.files.get(entry.path);
      if (archived.executable !== (entry.mode === "100755")) {
        invalid(`Source archive executable mode differs from Git for ${entry.path}.`);
      }
      if (!archived.bytes.equals(exported.blobs.get(entry.path))) {
        invalid(`Source archive bytes differ from Git for ${entry.path}.`);
      }
    }
    return {
      status: "passed",
      commitSha: expectedCommit,
      treeSha: expectedTree,
      sourceArchiveSha256: snapshot.sha256,
      fileCount: expectedFiles.length,
      directoryCount: expectedDirectories.size,
      files: expectedFiles.map((entry) => entry.path).sort(),
    };
  } finally {
    snapshot.cleanup();
  }
}

function assertImmutableFilesystemEntry(stat, pathname, expectedMode, { directory = false } = {}) {
  if (stat.uid !== 0 || stat.gid !== 0) {
    invalid(`Immutable release path must be owned by root:root: ${pathname}.`);
  }
  if ((stat.mode & 0o7777) !== expectedMode) {
    invalid(`Immutable release path has non-canonical permissions at ${pathname}.`);
  }
  if (!directory && stat.nlink !== 1) {
    invalid(`Immutable release file must have exactly one link at ${pathname}.`);
  }
}

function assertTrustedAncestry(sourceRoot) {
  if (fs.realpathSync(sourceRoot) !== sourceRoot) {
    invalid("Immutable release root must have one canonical path without symlink aliases.");
  }
  const parsed = path.parse(sourceRoot);
  const relative = path.relative(parsed.root, sourceRoot);
  let cursor = parsed.root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    const stat = fs.lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      invalid(`Immutable release ancestry contains a non-directory or symlink at ${cursor}.`);
    }
    if (stat.uid !== 0 || stat.gid !== 0 || (stat.mode & 0o022) !== 0) {
      invalid(`Immutable release ancestry is not root-owned and non-writable at ${cursor}.`);
    }
  }
}

export function validateExtractedSourceTree({
  rootPath,
  gitRoot,
  commitSha,
  treeSha,
  requireImmutableOwnership = false,
}) {
  const expectedCommit = exactGitSha(commitSha, "commit SHA");
  const expectedTree = exactGitSha(treeSha, "tree SHA");
  const sourceRoot = path.resolve(String(rootPath ?? ""));
  const rootStat = fs.lstatSync(sourceRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) invalid("Extracted release root must be one real directory.");
  if (requireImmutableOwnership) {
    assertTrustedAncestry(sourceRoot);
    assertImmutableFilesystemEntry(rootStat, sourceRoot, 0o555, { directory: true });
  }
  const actualFiles = new Map();
  const actualDirectories = new Set();
  const walk = (directory, relativeRoot = "") => {
    for (const name of fs.readdirSync(directory)) {
      const relative = relativeRoot ? `${relativeRoot}/${name}` : name;
      tarPath(relative);
      const pathname = path.join(directory, name);
      const stat = fs.lstatSync(pathname);
      if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
        invalid(`Extracted release root contains forbidden filesystem type at ${relative}.`);
      }
      if (stat.isDirectory()) {
        if (requireImmutableOwnership) assertImmutableFilesystemEntry(stat, pathname, 0o555, { directory: true });
        actualDirectories.add(relative);
        walk(pathname, relative);
      } else {
        if (requireImmutableOwnership) {
          assertImmutableFilesystemEntry(stat, pathname, (stat.mode & 0o111) !== 0 ? 0o555 : 0o444);
        }
        actualFiles.set(relative, { pathname, executable: (stat.mode & 0o111) !== 0 });
      }
    }
  };
  walk(sourceRoot);
  const exported = exactGitExport(path.resolve(String(gitRoot ?? "")), expectedCommit, expectedTree);
  const expectedPaths = new Set(exported.files.map((entry) => entry.path));
  if (
    actualFiles.size !== expectedPaths.size
    || [...actualFiles.keys()].some((pathname) => !expectedPaths.has(pathname))
    || actualDirectories.size !== exported.directories.size
    || [...actualDirectories].some((pathname) => !exported.directories.has(pathname))
  ) {
    invalid("Extracted release root path set differs from the exact exported Git tree.");
  }
  for (const entry of exported.files) {
    const actual = actualFiles.get(entry.path);
    if (actual.executable !== (entry.mode === "100755")) {
      invalid(`Extracted release executable mode differs from Git for ${entry.path}.`);
    }
    if (!fs.readFileSync(actual.pathname).equals(exported.blobs.get(entry.path))) {
      invalid(`Extracted release bytes differ from Git for ${entry.path}.`);
    }
  }
  return {
    status: "passed",
    commitSha: expectedCommit,
    treeSha: expectedTree,
    fileCount: exported.files.length,
    directoryCount: exported.directories.size,
  };
}

function readExtractedTree(sourceRoot, { requireImmutableOwnership = false } = {}) {
  const rootStat = fs.lstatSync(sourceRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) invalid("Extracted release root must be one real directory.");
  if (requireImmutableOwnership) {
    assertTrustedAncestry(sourceRoot);
    assertImmutableFilesystemEntry(rootStat, sourceRoot, 0o555, { directory: true });
  }
  const files = new Map();
  const directories = new Set();
  const walk = (directory, relativeRoot = "") => {
    for (const name of fs.readdirSync(directory)) {
      const relative = relativeRoot ? `${relativeRoot}/${name}` : name;
      tarPath(relative);
      const pathname = path.join(directory, name);
      const before = fs.lstatSync(pathname);
      if (before.isSymbolicLink() || (!before.isDirectory() && !before.isFile())) {
        invalid(`Extracted release root contains forbidden filesystem type at ${relative}.`);
      }
      if (before.isDirectory()) {
        if (requireImmutableOwnership) assertImmutableFilesystemEntry(before, pathname, 0o555, { directory: true });
        directories.add(relative);
        walk(pathname, relative);
        continue;
      }
      if (requireImmutableOwnership) {
        assertImmutableFilesystemEntry(before, pathname, (before.mode & 0o111) !== 0 ? 0o555 : 0o444);
      }
      const noFollow = fs.constants.O_NOFOLLOW ?? 0;
      const descriptor = fs.openSync(pathname, fs.constants.O_RDONLY | noFollow);
      try {
        const opened = fs.fstatSync(descriptor);
        if (
          !opened.isFile()
          || opened.dev !== before.dev
          || opened.ino !== before.ino
          || opened.size !== before.size
        ) {
          invalid(`Extracted release file changed while opened at ${relative}.`);
        }
        const bytes = fs.readFileSync(descriptor);
        const after = fs.fstatSync(descriptor);
        if (
          after.dev !== opened.dev
          || after.ino !== opened.ino
          || after.size !== opened.size
          || after.mtimeMs !== opened.mtimeMs
          || after.ctimeMs !== opened.ctimeMs
        ) {
          invalid(`Extracted release file changed while read at ${relative}.`);
        }
        files.set(relative, { bytes, executable: (opened.mode & 0o111) !== 0 });
      } finally {
        fs.closeSync(descriptor);
      }
    }
  };
  walk(sourceRoot);
  return { files, directories };
}

export function validateExtractedSourceArchive({
  rootPath,
  archivePath,
  expectedSha256 = null,
  commitSha = null,
  requireImmutableOwnership = false,
}) {
  const sourceRoot = path.resolve(String(rootPath ?? ""));
  const snapshot = snapshotFileArtifact(archivePath, {
    label: "exact release source archive",
    maxBytes: 256 * 1024 * 1024,
  });
  try {
    if (expectedSha256 !== null && snapshot.sha256 !== String(expectedSha256)) {
      invalid("Source archive bytes do not match the admitted SHA256.");
    }
    const parsed = parseTar(snapshot.bytes);
    assertNoPersistentRuntimePaths(parsed);
    if (commitSha !== null && parsed.globalPax.get("comment") !== exactGitSha(commitSha, "commit SHA")) {
      invalid("Source archive global commit identity is missing or mismatched.");
    }
    const actual = readExtractedTree(sourceRoot, { requireImmutableOwnership });
    if (
      actual.files.size !== parsed.files.size
      || [...actual.files.keys()].some((pathname) => !parsed.files.has(pathname))
      || actual.directories.size !== parsed.directories.size
      || [...actual.directories].some((pathname) => !parsed.directories.has(pathname))
    ) {
      invalid("Extracted release root path set differs from the admitted source archive.");
    }
    for (const [pathname, archived] of parsed.files) {
      const file = actual.files.get(pathname);
      if (file.executable !== archived.executable) {
        invalid(`Extracted release executable mode differs from the archive for ${pathname}.`);
      }
      if (!file.bytes.equals(archived.bytes)) {
        invalid(`Extracted release bytes differ from the archive for ${pathname}.`);
      }
    }
    return {
      status: "passed",
      sourceArchiveSha256: snapshot.sha256,
      fileCount: parsed.files.size,
      directoryCount: parsed.directories.size,
      files: [...parsed.files.keys()].sort(),
    };
  } finally {
    snapshot.cleanup();
  }
}

export function extractSourceArchive({
  rootPath,
  archivePath,
  expectedSha256 = null,
  commitSha = null,
}) {
  const sourceRoot = path.resolve(String(rootPath ?? ""));
  const rootStat = fs.lstatSync(sourceRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || fs.readdirSync(sourceRoot).length !== 0) {
    invalid("Source archive extraction root must be one new empty real directory.");
  }
  const snapshot = snapshotFileArtifact(archivePath, {
    label: "exact release source archive",
    maxBytes: 256 * 1024 * 1024,
  });
  try {
    if (expectedSha256 !== null && snapshot.sha256 !== String(expectedSha256)) {
      invalid("Source archive bytes do not match the admitted SHA256.");
    }
    const parsed = parseTar(snapshot.bytes);
    assertNoPersistentRuntimePaths(parsed);
    if (commitSha !== null && parsed.globalPax.get("comment") !== exactGitSha(commitSha, "commit SHA")) {
      invalid("Source archive global commit identity is missing or mismatched.");
    }
    const directories = [...parsed.directories].sort((left, right) => {
      const depth = left.split("/").length - right.split("/").length;
      return depth || left.localeCompare(right);
    });
    for (const relative of directories) {
      fs.mkdirSync(path.join(sourceRoot, relative), { mode: 0o700 });
    }
    for (const [relative, archived] of [...parsed.files].sort(([left], [right]) => left.localeCompare(right))) {
      const pathname = path.join(sourceRoot, relative);
      const descriptor = fs.openSync(
        pathname,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW ?? 0),
        0o600,
      );
      try {
        fs.writeFileSync(descriptor, archived.bytes);
        fs.fsyncSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
      fs.chmodSync(pathname, archived.executable ? 0o555 : 0o444);
    }
    for (const relative of directories.reverse()) fs.chmodSync(path.join(sourceRoot, relative), 0o555);
    fs.chmodSync(sourceRoot, 0o555);
    return {
      status: "passed",
      sourceArchiveSha256: snapshot.sha256,
      fileCount: parsed.files.size,
      directoryCount: parsed.directories.size,
    };
  } finally {
    snapshot.cleanup();
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.inspectOnly === "true") {
    const result = inspectSourceArchive({
      archivePath: options.archive,
      expectedSha256: options.sha256 ?? null,
      commitSha: options.commit ?? null,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (options.extractRoot) {
    const result = extractSourceArchive({
      rootPath: options.extractRoot,
      archivePath: options.archive,
      expectedSha256: options.sha256 ?? null,
      commitSha: options.commit ?? null,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (options.extractedRoot) {
    const result = options.archive
      ? validateExtractedSourceArchive({
        rootPath: options.extractedRoot,
        archivePath: options.archive,
        expectedSha256: options.sha256 ?? null,
        commitSha: options.commit ?? null,
        requireImmutableOwnership: options.requireImmutableOwnership === "true",
      })
      : validateExtractedSourceTree({
        rootPath: options.extractedRoot,
        gitRoot: options.gitRoot ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
        commitSha: options.commit,
        treeSha: options.tree,
        requireImmutableOwnership: options.requireImmutableOwnership === "true",
      });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  const result = validateExactSourceArchive({
    archivePath: options.archive,
    gitRoot: options.gitRoot ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
    commitSha: options.commit,
    treeSha: options.tree,
    expectedSha256: options.sha256 ?? null,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
