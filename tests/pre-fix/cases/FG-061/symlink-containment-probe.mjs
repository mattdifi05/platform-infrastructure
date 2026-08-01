#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-lock.sh", "f87317c017f541796f4144442a07c3c98e0b280aafb11396bd64852571390674"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);

const [sourceArgument, wrapperArgument, sentinelArgument, ownerToken] = process.argv.slice(2);
if (!sourceArgument || !wrapperArgument || !sentinelArgument || !ownerToken) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh");
}

const wrapperRoot = verifiedPhysicalDirectory(wrapperArgument, "wrapper root");
const sourceRoot = verifiedPhysicalDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source must be the wrapper's exact source child");
assert.match(ownerToken, /^[0-9a-f]{64}$/, "invalid wrapper ownership token");
const wrapperSentinel = verifiedRegularFile(sentinelArgument, "wrapper ownership sentinel");
assert.equal(wrapperSentinel, path.join(wrapperRoot, ".symlink-containment-wrapper-owner"));
assert.equal(fs.readFileSync(wrapperSentinel, "utf8"), `symlink-containment:${ownerToken}\n`);

const sourceText = new Map();
for (const [relative, expected] of EXPECTED_HASHES) {
  const sourceFile = verifiedContainedFile(sourceRoot, relative);
  const bytes = fs.readFileSync(sourceFile);
  const actual = sha256(bytes);
  assert.equal(actual, expected, `unexpected bytes for ${relative}`);
  sourceText.set(relative, bytes.toString("utf8"));
  console.log(`[SOURCE] path=${relative} sha256=${actual}`);
}
console.log(`[SOURCE] revision=${REVISION} tree=${TREE} files=${sourceText.size} provenance=git-archive`);

const contractSource = sourceText.get("scripts/hosted-workload-contract.mjs");
const lockSource = sourceText.get("scripts/hosted-workload-lock.sh");
const prepareSource = sourceText.get("scripts/prepare-hosted-workloads.sh");
const composeSource = sourceText.get("scripts/compose-vps.sh");
assert.match(contractSource, /function resolveWithin\(root, value, label\)[\s\S]*path\.resolve\(resolvedRoot, text\)[\s\S]*return resolved;/);
assert.match(contractSource, /function fileRecord\(filePath, kind\)[\s\S]*fs\.statSync\(filePath[\s\S]*sha256File\(filePath\)/);
assert.doesNotMatch(sourceSlice(contractSource, "function resolveWithin", "function fileRecord"), /realpathSync|lstatSync|O_NOFOLLOW/);
assert.match(lockSource, /\[ -f "\$file" \] && \[ ! -L "\$file" \]/);
assert.doesNotMatch(lockSource, /realpath|readlink|find .*type l|namei/);
assert.match(prepareSource, /-v "\$WORKLOAD_ROOT:\$WORKLOAD_ROOT:ro"/);
assert.match(prepareSource, /hosted-workload-contract\.mjs resolve/);
assert.match(composeSource, /hosted-workload-lock\.sh[\s\S]*compose-files[\s\S]*compose\+=\(-f "\$workload_file"\)/);
console.log("[PASS] source proof lexical resolver, following stat/read, terminal-only shell guard, and activation path confirmed");

const contractPath = verifiedContainedFile(sourceRoot, "scripts/hosted-workload-contract.mjs");
const { resolveCatalog } = await import(`${pathToFileURL(contractPath).href}?revision=${REVISION}`);
assert.equal(typeof resolveCatalog, "function", "pinned resolver export is unavailable");

const preexisting = path.join(wrapperRoot, "preexisting-preservation-control");
fs.mkdirSync(preexisting, { mode: 0o700 });
const preexistingMarker = path.join(preexisting, "preserve-me.txt");
fs.writeFileSync(preexistingMarker, "preexisting-data-must-survive\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
const preexistingBefore = fileIdentityAndHash(preexistingMarker);
assert.throws(() => removeOwnedDirectory(preexisting, wrapperRoot, ownerToken), /ownership sentinel/);
assert.deepEqual(fileIdentityAndHash(preexistingMarker), preexistingBefore);
console.log(`[GUARD] unowned_cleanup_refused=true preexisting_sha256=${preexistingBefore.sha256}`);

const fixtureRoot = path.join(wrapperRoot, "owned-fixture");
const fixtureOwner = createOwnedDirectory(fixtureRoot, wrapperRoot, ownerToken);
let receiptHash;
try {
  const workloadRoot = path.join(fixtureRoot, "workloads");
  const outsideRoot = path.join(fixtureRoot, "outside-root");
  const bridgeRoot = path.join(fixtureRoot, "bridge-root");
  fs.mkdirSync(workloadRoot, { mode: 0o700 });
  fs.mkdirSync(outsideRoot, { mode: 0o700 });
  fs.mkdirSync(bridgeRoot, { mode: 0o700 });

  const coreEnv = path.join(fixtureRoot, "core.env");
  const coreCompose = path.join(fixtureRoot, "compose.core.yaml");
  fs.writeFileSync(coreEnv, "CORE_MODE=synthetic\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(coreCompose, "services: {}\n", { encoding: "utf8", flag: "wx", mode: 0o600 });

  const escapedApp = path.join(outsideRoot, "escape-app");
  writeWorkload(escapedApp, "escape-app");
  const intermediateLink = path.join(workloadRoot, "linked-app");
  fs.symlinkSync(path.relative(workloadRoot, escapedApp), intermediateLink, "dir");
  const escaped = resolveOne(resolveCatalog, fixtureRoot, workloadRoot, coreEnv, coreCompose, "linked-app", "escape-app");
  const escapedRecords = assertEscapedRecords(escaped, workloadRoot, escapedApp);
  console.log(`[VULNERABLE CAN-172] case=intermediate-symlink records=${escapedRecords.length} lexical_contained=true terminal_symlink=false physical_outside=true resolver=accepted`);
  for (const record of escapedRecords) {
    console.log(`[TRACE] kind=${record.kind} lexical=${path.relative(workloadRoot, record.path)} physical_root=outside sha256=${record.sha256}`);
  }

  const directTerminal = path.join(workloadRoot, "terminal-manifest.json");
  fs.symlinkSync(path.relative(workloadRoot, path.join(escapedApp, "manifest.json")), directTerminal, "file");
  assert.equal(fs.statSync(directTerminal).isFile(), true);
  assert.equal(fs.lstatSync(directTerminal).isSymbolicLink(), true);
  assert.throws(() => assertSymlinkSafe(workloadRoot, directTerminal), /symlink component/);
  console.log("[CONTROL] case=terminal-symlink stat_follows=true shell_final_guard=reject fixed_oracle=reject");

  const chainedBridge = path.join(bridgeRoot, "second-hop");
  fs.symlinkSync(path.relative(bridgeRoot, escapedApp), chainedBridge, "dir");
  const firstHop = path.join(workloadRoot, "chain-app");
  fs.symlinkSync(path.relative(workloadRoot, chainedBridge), firstHop, "dir");
  const chained = resolveOne(resolveCatalog, fixtureRoot, workloadRoot, coreEnv, coreCompose, "chain-app", "escape-app");
  assertEscapedRecords(chained, workloadRoot, escapedApp);
  assert.throws(() => assertSymlinkSafe(workloadRoot, path.join(firstHop, "compose.yaml")), /symlink component/);
  console.log("[VULNERABLE] case=cross-root-two-hop terminal_symlink=false physical_outside=true resolver=accepted fixed_oracle=reject");

  const safeApp = path.join(workloadRoot, "safe-app");
  writeWorkload(safeApp, "safe-app");
  const safe = resolveOne(resolveCatalog, fixtureRoot, workloadRoot, coreEnv, coreCompose, "safe-app", "safe-app");
  const safeRecords = safe.workloads[0].files;
  for (const record of safeRecords) {
    assertSymlinkSafe(workloadRoot, record.path);
    assert.equal(isPhysicallyWithin(workloadRoot, record.path), true);
  }
  console.log(`[NEGATIVE CONTROL] case=all-regular records=${safeRecords.length} resolver=accepted fixed_oracle=accepted`);

  const replacePath = path.join(workloadRoot, "replace-app");
  const outsideReplacement = path.join(outsideRoot, "replace-app");
  writeWorkload(replacePath, "replace-app");
  writeWorkload(outsideReplacement, "replace-app");
  const beforeReplacement = resolveOne(resolveCatalog, fixtureRoot, workloadRoot, coreEnv, coreCompose, "replace-app", "replace-app");
  for (const record of beforeReplacement.workloads[0].files) assertSymlinkSafe(workloadRoot, record.path);
  fs.renameSync(replacePath, path.join(workloadRoot, "replace-app-original"));
  fs.symlinkSync(path.relative(workloadRoot, outsideReplacement), replacePath, "dir");
  const afterReplacement = resolveOne(resolveCatalog, fixtureRoot, workloadRoot, coreEnv, coreCompose, "replace-app", "replace-app");
  assertEscapedRecords(afterReplacement, workloadRoot, outsideReplacement);
  assert.throws(() => assertSymlinkSafe(workloadRoot, path.join(replacePath, "manifest.json")), /symlink component/);
  console.log("[VULNERABLE] case=replaced-directory lexical_path_unchanged=true resolver=accepted physical_outside=true fixed_oracle=reject");

  const receipt = {
    schema: "symlink-containment-poc/v1",
    revision: REVISION,
    tree: TREE,
    sourceSha256: Object.fromEntries(EXPECTED_HASHES),
    vulnerableCases: ["intermediate", "cross-root-two-hop", "replaced-directory"],
    terminalControl: "visible-to-final-component-guard",
    safeControl: "all-regular-contained",
    escapedRecordKinds: escapedRecords.map((record) => record.kind).sort(),
    safety: {
      networkAttempts: 0,
      credentialsRead: 0,
      dockerCalls: 0,
      servicesStarted: 0,
      liveMutations: 0,
      sourceMutations: 0,
    },
  };
  const receiptFile = path.join(fixtureRoot, "offline-receipt.json");
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  receiptHash = sha256(fs.readFileSync(receiptFile));
  console.log(`[RECEIPT] sha256=${receiptHash} scope=wrapper-owned-synthetic-fixture`);
} finally {
  removeOwnedDirectory(fixtureRoot, wrapperRoot, fixtureOwner);
}

assert.equal(fs.existsSync(fixtureRoot), false, "sentinel-owned fixture survived cleanup");
assert.deepEqual(fileIdentityAndHash(preexistingMarker), preexistingBefore, "pre-existing marker changed");
for (const [relative, expected] of EXPECTED_HASHES) {
  assert.equal(sha256(fs.readFileSync(path.join(sourceRoot, relative))), expected, `source mutation detected: ${relative}`);
}
console.log("[SAFE] network_attempts=0 credentials_read=0 docker_calls=0 services_started=0 live_mutations=0 source_mutations=0");
console.log("[+] cleanup sentinel_owned_fixture_removed=true preexisting_marker_preserved=true");
console.log("[+] result=VULNERABLE canonical_id=CAN-172");

function resolveOne(resolveCatalogFn, fixtureRoot, workloadRoot, coreEnvFile, coreCompose, relativeDirectory, id) {
  const catalogPath = path.join(fixtureRoot, `catalog-${relativeDirectory.replaceAll("/", "-")}.json`);
  const catalog = {
    version: 1,
    workloads: [{
      manifest: `${relativeDirectory}/manifest.json`,
      environmentFile: `${relativeDirectory}/workload.env`,
    }],
  };
  fs.writeFileSync(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  const result = resolveCatalogFn({
    catalogPath,
    workloadRoot,
    coreEnvFile,
    coreFiles: [coreCompose],
    projectName: `poc-${id}`,
  });
  assert.equal(result.workloads.length, 1);
  assert.equal(result.workloads[0].id, id);
  return result;
}

function writeWorkload(directory, id) {
  fs.mkdirSync(path.join(directory, "migrations"), { recursive: true, mode: 0o700 });
  const manifest = {
    version: 1,
    id,
    composeFile: "compose.yaml",
    services: [{ name: `${id}-web`, role: "web", routes: [] }],
    secrets: [],
    migrationRoots: ["migrations"],
  };
  const prefix = id.toUpperCase().replaceAll("-", "_");
  fs.writeFileSync(path.join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "compose.yaml"), "services: {}\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "workload.env"), `${prefix}_MODE=synthetic\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "migrations", "001.sql"), "select 1;\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
}

function assertEscapedRecords(resolved, workloadRoot, expectedPhysicalRoot) {
  const records = resolved.workloads[0].files;
  assert.deepEqual(records.map((record) => record.kind).sort(), [
    "migration",
    "workload-compose",
    "workload-environment",
    "workload-manifest",
  ]);
  for (const record of records) {
    const lexical = path.resolve(record.path);
    assert.equal(lexical.startsWith(`${path.resolve(workloadRoot)}${path.sep}`), true, `${record.kind} is not lexically contained`);
    assert.equal(fs.lstatSync(record.path).isSymbolicLink(), false, `${record.kind} unexpectedly has a terminal symlink`);
    const physical = fs.realpathSync(record.path);
    assert.equal(physical.startsWith(`${fs.realpathSync(expectedPhysicalRoot)}${path.sep}`), true, `${record.kind} did not resolve outside`);
    assert.equal(record.sha256, sha256(fs.readFileSync(physical)), `${record.kind} hash is not the escaped file hash`);
    assert.equal(record.sizeBytes, fs.statSync(physical).size, `${record.kind} size is not the escaped file size`);
    assert.throws(() => assertSymlinkSafe(workloadRoot, record.path), /symlink component/);
  }
  return records;
}

function assertSymlinkSafe(root, candidate) {
  const rootPath = path.resolve(root);
  const candidatePath = path.resolve(candidate);
  assert.equal(candidatePath === rootPath || candidatePath.startsWith(`${rootPath}${path.sep}`), true, "lexical path escapes root");
  const relative = path.relative(rootPath, candidatePath);
  let cursor = rootPath;
  const rootStat = fs.lstatSync(rootPath);
  if (rootStat.isSymbolicLink()) throw new Error(`symlink component: ${rootPath}`);
  for (const component of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) throw new Error(`symlink component: ${cursor}`);
  }
  assert.equal(isPhysicallyWithin(rootPath, candidatePath), true, "physical path escapes root");
  return true;
}

function isPhysicallyWithin(root, candidate) {
  const rootReal = fs.realpathSync(root);
  const candidateReal = fs.realpathSync(candidate);
  return candidateReal === rootReal || candidateReal.startsWith(`${rootReal}${path.sep}`);
}

function sourceSlice(source, start, end) {
  const startOffset = source.indexOf(start);
  const endOffset = source.indexOf(end, startOffset + start.length);
  assert.notEqual(startOffset, -1, `missing source marker: ${start}`);
  assert.notEqual(endOffset, -1, `missing source marker: ${end}`);
  return source.slice(startOffset, endOffset);
}

function verifiedPhysicalDirectory(candidate, label) {
  const resolved = path.resolve(candidate);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} is a symbolic link`);
  assert.equal(fs.realpathSync(resolved), resolved, `${label} is not a physical path`);
  return resolved;
}

function verifiedRegularFile(candidate, label) {
  const resolved = path.resolve(candidate);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isFile(), true, `${label} is not a regular file`);
  assert.equal(stat.isSymbolicLink(), false, `${label} is a symbolic link`);
  return resolved;
}

function verifiedContainedFile(root, relative) {
  const candidate = path.resolve(root, relative);
  assert.equal(candidate.startsWith(`${root}${path.sep}`), true, `source path escaped archive: ${relative}`);
  verifiedRegularFile(candidate, relative);
  assert.equal(fs.realpathSync(candidate), candidate, `source file is not a physical path: ${relative}`);
  return candidate;
}

function createOwnedDirectory(directory, parent, token) {
  const resolved = path.resolve(directory);
  assert.equal(path.dirname(resolved), parent, "owned directory must be a direct wrapper child");
  assert.equal(fs.existsSync(resolved), false, "refusing pre-existing owned directory target");
  fs.mkdirSync(resolved, { mode: 0o700 });
  const sentinel = path.join(resolved, ".symlink-containment-owner");
  fs.writeFileSync(sentinel, `${token}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  return token;
}

function removeOwnedDirectory(directory, parent, token) {
  const resolved = path.resolve(directory);
  assert.equal(path.dirname(resolved), parent, "cleanup target is outside wrapper root");
  const directoryStat = fs.lstatSync(resolved);
  assert.equal(directoryStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(directoryStat.isSymbolicLink(), false, "cleanup target is a symlink");
  assert.equal(fs.realpathSync(resolved), resolved, "cleanup target is not a physical path");
  const sentinel = path.join(resolved, ".symlink-containment-owner");
  assert.equal(fs.existsSync(sentinel), true, "ownership sentinel is missing");
  const sentinelStat = fs.lstatSync(sentinel);
  assert.equal(sentinelStat.isFile(), true, "ownership sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel is a symlink");
  assert.equal(fs.readFileSync(sentinel, "utf8"), `${token}\n`, "ownership sentinel mismatch");
  fs.rmSync(resolved, { recursive: true, force: false });
  assert.equal(fs.existsSync(resolved), false, "owned directory survived cleanup");
}

function fileIdentityAndHash(file) {
  const stat = fs.lstatSync(file);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  return { device: stat.dev, inode: stat.ino, size: stat.size, sha256: sha256(fs.readFileSync(file)) };
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}
