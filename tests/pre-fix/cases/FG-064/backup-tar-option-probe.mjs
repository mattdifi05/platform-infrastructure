#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const EXPECTED_HASHES = new Map([
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["compose.backup-scheduler.yaml", "cf2ad09cd02f3a04c512450f0c730ec6637ac86646d9037c0be118a12c95c748"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
]);

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function isStrictChild(parent, child) {
  const relative = path.relative(parent, child);
  return Boolean(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function checkedRealDirectory(rawPath, label) {
  const unresolved = path.resolve(rawPath);
  const before = fs.lstatSync(unresolved);
  assert(before.isDirectory() && !before.isSymbolicLink(), `${label} must be a physical directory`);
  const physical = fs.realpathSync(unresolved);
  const after = fs.lstatSync(physical);
  assert(after.isDirectory() && !after.isSymbolicLink(), `${label} changed type during validation`);
  assert(before.dev === after.dev && before.ino === after.ino, `${label} changed identity during validation`);
  return physical;
}

function checkedRegularFile(filePath, label) {
  const entry = fs.lstatSync(filePath);
  assert(entry.isFile() && !entry.isSymbolicLink(), `${label} must be a physical regular file`);
  return fs.readFileSync(filePath);
}

function snapshotFlatDirectory(root) {
  const rootStat = fs.lstatSync(root);
  assert(rootStat.isDirectory() && !rootStat.isSymbolicLink(), "pre-existing target must remain a physical directory");
  const entries = fs.readdirSync(root).sort().map((name) => {
    const target = path.join(root, name);
    const stat = fs.lstatSync(target);
    assert(stat.isFile() && !stat.isSymbolicLink(), "pre-existing control may contain only physical regular files");
    const bytes = fs.readFileSync(target);
    return {
      name,
      dev: String(stat.dev),
      ino: String(stat.ino),
      mode: stat.mode,
      size: stat.size,
      hash: sha256(bytes),
    };
  });
  return JSON.stringify({
    dev: String(rootStat.dev),
    ino: String(rootStat.ino),
    mode: rootStat.mode,
    entries,
  });
}

function functionBlock(source, declaration, nextDeclaration) {
  const start = source.indexOf(declaration);
  assert(start >= 0, `missing source declaration: ${declaration}`);
  const end = source.indexOf(nextDeclaration, start + declaration.length);
  assert(end > start, `missing source boundary after: ${declaration}`);
  return source.slice(start, end);
}

function evaluatePinnedNormalizer(functionSource, input) {
  const context = {
    input,
    fail: (message) => {
      throw new Error(String(message));
    },
  };
  return vm.runInNewContext(
    `"use strict";\n${functionSource}\nsafeApplicationBackupSlug(input);`,
    context,
    { timeout: 50 },
  );
}

function classifyUntrustedToken(argv, index) {
  assert(index >= 0 && index < argv.length, "invalid modeled argument index");
  const value = argv[index];
  const terminator = argv.slice(0, index).lastIndexOf("--");
  if (terminator >= 0) return "OPERAND";
  return value.startsWith("-") && value !== "-" ? "OPTION" : "OPERAND";
}

function classifyFileListLine(line, verbatim = false) {
  if (verbatim) return "NAME";
  const trimmed = line.trim();
  return trimmed.startsWith("-") && trimmed !== "-" ? "OPTION" : "NAME";
}

function rejectLeadingDash(name) {
  if (!name || name.startsWith("-") || name === "." || name === ".." || name.includes("/") || name.includes("\\") || name.includes("\0")) {
    throw new Error("unsafe-source-name");
  }
  return name;
}

function claimFreshFixture(target, token) {
  if (fs.existsSync(target)) {
    const error = new Error("target-exists");
    error.code = "TARGET_EXISTS";
    throw error;
  }
  fs.mkdirSync(target, { mode: 0o700 });
  fs.writeFileSync(path.join(target, `.backup-tar-option-lab-owner-${token}`), `backup-tar-option-lab:${token}\n`, {
    encoding: "ascii",
    flag: "wx",
    mode: 0o600,
  });
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4) {
    console.error("usage: backup-tar-option-probe.mjs SOURCE_ROOT WRAPPER_ROOT OWNER_SENTINEL PREEXISTING_ROOT");
    return 2;
  }

  const [sourceArg, wrapperArg, ownerSentinelArg, preexistingArg] = args;
  const wrapperRoot = checkedRealDirectory(wrapperArg, "wrapper root");
  const sourceRoot = checkedRealDirectory(sourceArg, "source root");
  const preexistingRoot = checkedRealDirectory(preexistingArg, "pre-existing root");
  assert(isStrictChild(wrapperRoot, sourceRoot), "source root escaped wrapper root");
  assert(isStrictChild(wrapperRoot, preexistingRoot), "pre-existing root escaped wrapper root");

  const ownerSentinel = path.resolve(ownerSentinelArg);
  assert(path.dirname(ownerSentinel) === wrapperRoot, "owner sentinel escaped wrapper root");
  const sentinelName = path.basename(ownerSentinel);
  const tokenMatch = /^\.backup-tar-option-owner-([a-f0-9]{64})$/.exec(sentinelName);
  assert(tokenMatch, "invalid owner sentinel name");
  const token = tokenMatch[1];
  const sentinelBytes = checkedRegularFile(ownerSentinel, "owner sentinel");
  assert(sentinelBytes.equals(Buffer.from(`backup-tar-option:${token}\n`, "ascii")), "owner sentinel content mismatch");

  const loadedSources = new Map();
  for (const [relative, expected] of EXPECTED_HASHES) {
    const target = path.join(sourceRoot, relative);
    assert(isStrictChild(sourceRoot, path.resolve(target)), `source path escaped root: ${relative}`);
    const bytes = checkedRegularFile(target, relative);
    const actual = sha256(bytes);
    assert(actual === expected, `source hash mismatch for ${relative}: ${actual}`);
    loadedSources.set(relative, bytes.toString("utf8"));
  }

  const infraOps = loadedSources.get("scripts/infra-ops.mjs");
  const schedulerCompose = loadedSources.get("compose.backup-scheduler.yaml");
  const isolationCompose = loadedSources.get("compose.runtime-isolation.yaml");

  const normalizerSource = functionBlock(
    infraOps,
    "function safeApplicationBackupSlug(value) {",
    "function applicationSourceDirectories(options = {}) {",
  );
  const enumeratorSource = functionBlock(
    infraOps,
    "function applicationSourceDirectories(options = {}) {",
    "async function backupApplications(options = {}) {",
  );
  const backupSource = functionBlock(
    infraOps,
    "async function backupApplications(options = {}) {",
    "function controlCenterStateRoot() {",
  );

  assert(
    enumeratorSource.includes('.filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))'),
    "top-level directory filter changed",
  );
  assert(enumeratorSource.includes("const slug = safeApplicationBackupSlug(entry.name);"), "slug normalization trace changed");
  assert(enumeratorSource.includes("name: entry.name,"), "raw directory-name preservation trace changed");

  const sinkPattern = /run\("tar",\s*\["-czf",\s*hostPath,\s*\.\.\.excludeArgs,\s*"-C",\s*sourceRoot,\s*application\.name\]\);/;
  const sinkMatch = backupSource.match(sinkPattern);
  assert(sinkMatch, "application backup argument sink changed");
  assert(!sinkMatch[0].includes('"--"'), "candidate unexpectedly contains an option terminator at the sink");
  assert(/PROJECT_SOURCE_ROOT:\s*\/project/.test(schedulerCompose), "scheduler source-root binding changed");
  assert(/\$\{PROJECT_SOURCE_DIR:-\.\.\/src\}:\/project:ro/.test(schedulerCompose), "scheduler source mount changed");
  assert(/\$\{PROJECT_SOURCE_DIR:-\.\.\/src\}:\/project:ro/.test(isolationCompose), "isolated scheduler source mount changed");

  const preexistingBefore = snapshotFlatDirectory(preexistingRoot);
  let preexistingRejected = false;
  try {
    claimFreshFixture(preexistingRoot, token);
  } catch (error) {
    preexistingRejected = error?.code === "TARGET_EXISTS";
  }
  assert(preexistingRejected, "probe did not reject a pre-existing fixture target");
  assert(snapshotFlatDirectory(preexistingRoot) === preexistingBefore, "pre-existing target changed during refusal");

  const labRoot = path.join(wrapperRoot, `model-lab-${token.slice(0, 16)}`);
  assert(!fs.existsSync(labRoot), "owned model lab unexpectedly exists");
  claimFreshFixture(labRoot, token);

  const variants = [
    { kind: "short", name: "-Tfixture-list" },
    { kind: "long", name: "--files-from=fixture-list" },
    { kind: "positional", name: "-Cfixture-area" },
  ];
  const vulnerablePrefix = ["-czf", "<synthetic-output>", "--exclude", ".git", "-C", "<synthetic-source-root>"];
  const fixedPrefix = [...vulnerablePrefix, "--"];
  const results = variants.map((variant) => {
    const slug = evaluatePinnedNormalizer(normalizerSource, variant.name);
    const vulnerableArgv = [...vulnerablePrefix, variant.name];
    const fixedArgv = [...fixedPrefix, variant.name];
    return {
      ...variant,
      slug,
      vulnerable: classifyUntrustedToken(vulnerableArgv, vulnerableArgv.length - 1),
      fixed: classifyUntrustedToken(fixedArgv, fixedArgv.length - 1),
    };
  });
  assert(results.every((result) => result.slug && result.vulnerable === "OPTION" && result.fixed === "OPERAND"), "variant sensitivity failed");

  const canonicalName = "--files-from=fixture-list";
  const canonicalSlug = evaluatePinnedNormalizer(normalizerSource, canonicalName);
  const optionDirectory = path.join(labRoot, canonicalName);
  fs.mkdirSync(optionDirectory, { mode: 0o700 });
  fs.writeFileSync(path.join(optionDirectory, "ordinary-marker.txt"), "harmless source marker\n", { flag: "wx", mode: 0o600 });

  const responseLines = ["--no-recursion", "--directory=fixture-area", "ordinary-project-file.txt"];
  fs.writeFileSync(path.join(labRoot, "fixture-list"), `${responseLines.join("\n")}\n`, { flag: "wx", mode: 0o600 });
  const responseClasses = responseLines.map((line) => classifyFileListLine(line));
  const verbatimClasses = responseLines.map((line) => classifyFileListLine(line, true));
  assert(responseClasses.join(",") === "OPTION,OPTION,NAME", "GNU file-list model lost option sensitivity");
  assert(verbatimClasses.every((value) => value === "NAME"), "verbatim file-list negative control failed");

  const baselineName = "ordinary-application";
  assert(evaluatePinnedNormalizer(normalizerSource, baselineName) === baselineName, "ordinary slug baseline changed");
  assert(classifyUntrustedToken([...vulnerablePrefix, baselineName], vulnerablePrefix.length) === "OPERAND", "ordinary operand baseline failed");
  let guardedReject = false;
  try {
    rejectLeadingDash(canonicalName);
  } catch {
    guardedReject = true;
  }
  assert(guardedReject, "synthetic fixed guard accepted a leading-dash name");
  assert(rejectLeadingDash(baselineName) === baselineName, "synthetic fixed guard rejected an ordinary name");
  assert(snapshotFlatDirectory(preexistingRoot) === preexistingBefore, "pre-existing target changed after model execution");

  console.log(`[+] pinned-source hashes infra_ops=${EXPECTED_HASHES.get("scripts/infra-ops.mjs")} scheduler_compose=${EXPECTED_HASHES.get("compose.backup-scheduler.yaml")} isolation_compose=${EXPECTED_HASHES.get("compose.runtime-isolation.yaml")}`);
  console.log(`[+] candidate source_name=${canonicalName} slug=${canonicalSlug} raw_name_preserved=true source_mount=read-only`);
  console.log(`[VULNERABLE] candidate_argv untrusted_token=${canonicalName} classification=OPTION end_of_options_before_input=false`);
  console.log(`[VULNERABLE] documented_gnu_file_list line=${responseLines[0]} classification=${responseClasses[0]} verbatim_control=${verbatimClasses[0]}`);
  console.log(`[+] boundary variants ${results.map((result) => `${result.kind}=${result.vulnerable}`).join(" ")} response_style=${responseClasses[0]}`);
  console.log(`[+] negative-control fixed_argv ${results.map((result) => `${result.kind}=${result.fixed}`).join(" ")}`);
  console.log("[+] negative-control leading_dash_guard=REJECTED ordinary_name=ACCEPTED preexisting_target=REJECTED");
  console.log("[+] safety probe_child_processes=0 archive_utility_processes=0 payload_commands=0 real_backups_read=0 real_backups_written=0 services_started=0 network_attempts=0");
  console.log("[+] result=VULNERABLE_SOURCE_ARGUMENT_BOUNDARY");
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(`probe failed: ${error?.stack || error}`);
  process.exitCode = 1;
}
