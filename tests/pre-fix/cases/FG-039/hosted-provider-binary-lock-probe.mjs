#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_CONTRACT_SHA256 = "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47";
const EXPECTED_COMPOSE_WRAPPER_SHA256 = "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713";
const EXPECTED_REMOTE_DEPLOY_SHA256 = "e7460e9db36765e6078d778d8a5388d54a78ee4620ddb70f2f7a19187f937804";

const [sourceRootArgument, wrapperRootArgument, wrapperSentinelArgument, preexistingRootArgument] = process.argv.slice(2);
if (!sourceRootArgument || !wrapperRootArgument || !wrapperSentinelArgument || !preexistingRootArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned temporary root");
}

const wrapperRootPath = path.resolve(wrapperRootArgument);
const wrapperRootStat = fs.lstatSync(wrapperRootPath);
assert.equal(wrapperRootStat.isDirectory(), true, "wrapper root is not a directory");
assert.equal(wrapperRootStat.isSymbolicLink(), false, "wrapper root must not be a symbolic link");
const wrapperRoot = fs.realpathSync(wrapperRootPath);
assert.equal(wrapperRoot, wrapperRootPath, "wrapper root argument must be its physical path");

const sourceRootPath = path.resolve(sourceRootArgument);
const sourceRootStat = fs.lstatSync(sourceRootPath);
assert.equal(sourceRootStat.isDirectory(), true, "source archive is not a directory");
assert.equal(sourceRootStat.isSymbolicLink(), false, "source archive must not be a symbolic link");
const sourceRoot = fs.realpathSync(sourceRootPath);
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source archive must be the exact source child of the wrapper root");
assert.equal(path.dirname(sourceRoot), wrapperRoot, "source archive escaped the wrapper root");

const wrapperSentinelPath = path.resolve(wrapperSentinelArgument);
const wrapperSentinelStat = fs.lstatSync(wrapperSentinelPath);
assert.equal(wrapperSentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(wrapperSentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel must not be a symbolic link");
assert.equal(fs.realpathSync(wrapperSentinelPath), wrapperSentinelPath, "wrapper ownership sentinel must be its physical path");
assert.equal(path.dirname(wrapperSentinelPath), wrapperRoot, "wrapper ownership sentinel escaped the wrapper root");
const sentinelMatch = path.basename(wrapperSentinelPath).match(/^\.hosted-provider-lock-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(wrapperSentinelPath, "utf8"),
  `hosted-provider-lock:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

const contractPath = path.join(sourceRoot, "scripts", "hosted-workload-contract.mjs");
const composeWrapperPath = path.join(sourceRoot, "scripts", "compose-vps.sh");
const remoteDeployPath = path.join(sourceRoot, "scripts", "deploy-vps-remote.sh");
assert.equal(sha256File(contractPath), EXPECTED_CONTRACT_SHA256, "unexpected hosted-workload-contract.mjs revision");
assert.equal(sha256File(composeWrapperPath), EXPECTED_COMPOSE_WRAPPER_SHA256, "unexpected compose-vps.sh revision");
assert.equal(sha256File(remoteDeployPath), EXPECTED_REMOTE_DEPLOY_SHA256, "unexpected deploy-vps-remote.sh revision");

const composeWrapperSource = fs.readFileSync(composeWrapperPath, "utf8");
const remoteDeploySource = fs.readFileSync(remoteDeployPath, "utf8");
assert.match(composeWrapperSource, /compose\+=\(-f "\$workload_file"\)/);
assert.match(composeWrapperSource, /exec "\$\{compose\[@\]\}" --profile backup "\$@"/);
assert.match(remoteDeploySource, /compose-vps\.sh up -d --build --remove-orphans/);

const preexistingRootPath = path.resolve(preexistingRootArgument);
const preexistingRootStat = fs.lstatSync(preexistingRootPath);
assert.equal(preexistingRootStat.isDirectory(), true, "pre-existing target is not a directory");
assert.equal(preexistingRootStat.isSymbolicLink(), false, "pre-existing target must not be a symbolic link");
const preexistingRoot = fs.realpathSync(preexistingRootPath);
assert.equal(preexistingRoot, path.join(wrapperRoot, "preexisting"), "pre-existing target is not the exact wrapper child");
const preexistingFile = path.join(preexistingRoot, "preserve-helper");
const preexistingBefore = fs.lstatSync(preexistingFile);
const preexistingBytes = fs.readFileSync(preexistingFile);
const preexistingHash = sha256Bytes(preexistingBytes);
const preexistingEntries = fs.readdirSync(preexistingRoot).sort();
assert.throws(() => claimOwnedFixture(preexistingRoot, wrapperRoot, ownerToken), /refusing pre-existing fixture target/);
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
const preexistingAfter = fs.lstatSync(preexistingFile);
assert.equal(preexistingAfter.dev, preexistingBefore.dev, "pre-existing helper device changed");
assert.equal(preexistingAfter.ino, preexistingBefore.ino, "pre-existing helper inode changed");
assert.deepEqual(fs.readFileSync(preexistingFile), preexistingBytes);
assert.equal(sha256File(preexistingFile), preexistingHash);
console.log(`[+] negative-control preexisting_target_rejected=true helper_preserved=true sha256=${preexistingHash}`);

const fixtureRoot = path.join(wrapperRoot, `fixture-${ownerToken}`);
const fixtureOwnership = claimOwnedFixture(fixtureRoot, wrapperRoot, ownerToken);

try {
  const workloadsRoot = path.join(fixtureRoot, "workloads");
  const workloadDirectory = path.join(workloadsRoot, "probe");
  fs.mkdirSync(workloadDirectory, { recursive: true, mode: 0o700 });

  const catalogPath = path.join(workloadsRoot, "catalog.json");
  const manifestPath = path.join(workloadDirectory, "manifest.json");
  const composePath = path.join(workloadDirectory, "compose.platform.yaml");
  const environmentPath = path.join(workloadDirectory, "workload.env");
  const coreEnvironmentPath = path.join(fixtureRoot, "core.env");
  const coreComposePath = path.join(fixtureRoot, "core-compose.json");
  const helperPath = path.join(workloadDirectory, "provider-helper-v1");
  const alternateHelperPath = path.join(workloadDirectory, "provider-helper-v2");
  const helperLinkPath = path.join(workloadDirectory, "provider-helper-link");

  writeExclusiveJson(catalogPath, {
    version: 1,
    workloads: [{ manifest: "probe/manifest.json", environmentFile: "probe/workload.env" }],
  });
  writeExclusiveJson(manifestPath, {
    version: 1,
    id: "probe",
    composeFile: "compose.platform.yaml",
    services: [{ name: "probe-worker", role: "worker" }],
  });
  writeExclusive(composePath, "services:\n  probe-worker:\n    image: pinned-by-render\n");
  writeExclusive(environmentPath, "PROBE_MODE=deterministic\n");
  writeExclusive(coreEnvironmentPath, "PROJECT_HOST_SUFFIX=example.invalid\n");
  writeExclusiveJson(coreComposePath, { services: {}, networks: {} });
  writeExclusive(helperPath, "#!/bin/sh\nprintf 'provider-helper-v1\\n'\n", 0o600);
  writeExclusive(alternateHelperPath, "#!/bin/sh\nprintf 'provider-helper-v2\\n'\n", 0o600);
  fs.symlinkSync(path.basename(helperPath), helperLinkPath);

  const { resolveCatalog, validateRenderedWorkloads, verifyLockFiles } = await import(pathToFileURL(contractPath).href);
  const lock = resolveCatalog({
    catalogPath,
    workloadRoot: workloadsRoot,
    coreEnvFile: coreEnvironmentPath,
    coreFiles: [coreComposePath],
    projectName: "provider_probe",
  });
  assert.equal(lock.files.length, 6, "unexpected lock record count");
  verifyLockFiles(lock);

  const lockedPaths = new Set(lock.files.map((record) => path.resolve(record.path)));
  assert.equal(lockedPaths.has(helperPath), false, "provider helper unexpectedly entered the lock");
  assert.equal(lockedPaths.has(alternateHelperPath), false, "alternate provider helper unexpectedly entered the lock");
  assert.equal(lockedPaths.has(helperLinkPath), false, "provider helper symlink unexpectedly entered the lock");

  const digest = "a".repeat(64);
  const baseService = {
    image: `registry.example/probe/worker@sha256:${digest}`,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    pids_limit: 128,
    cpu_shares: 256,
    blkio_config: { weight: 300 },
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    cpus: 0.5,
    mem_limit: String(256 * 1024 * 1024),
    mem_reservation: String(64 * 1024 * 1024),
    healthcheck: { test: ["CMD", "node", "healthcheck.mjs"] },
    networks: { probe_bus: null },
    labels: { "com.platform.workload-id": "probe", "com.platform.workload-role": "worker" },
  };
  const core = { services: {}, networks: {} };
  const combinedFor = (providerType) => ({
    services: {
      "probe-worker": {
        ...structuredClone(baseService),
        ...(providerType === undefined ? {} : { provider: { type: providerType, options: { mode: "deterministic" } } }),
      },
    },
    networks: { probe_bus: { internal: true } },
  });

  validateRenderedWorkloads({ core, combined: combinedFor(undefined), lock });
  const mutableImage = combinedFor(undefined);
  mutableImage.services["probe-worker"].image = "registry.example/probe/worker:latest";
  assert.throws(
    () => validateRenderedWorkloads({ core, combined: mutableImage, lock }),
    /digest-pinned/,
    "negative control did not exercise the real image gate",
  );
  console.log("[+] negative-control mutable_image_rejected=true real_contract_gate_exercised=true");

  const providerVariants = [
    ["absolute", helperPath],
    ["traversal", "../probe/provider-helper-v1"],
    ["symlink", helperLinkPath],
  ];
  for (const [, providerType] of providerVariants) {
    validateRenderedWorkloads({ core, combined: combinedFor(providerType), lock });
  }
  console.log("[VULNERABLE] provider_field_accepted=true absolute=true traversal=true symlink=true");
  console.log(`[VULNERABLE] provider_helper_locked=false lock_records=${lock.files.length}`);

  const helperHashBefore = sha256File(helperPath);
  const helperStatBefore = fs.lstatSync(helperPath);
  assert.equal(helperStatBefore.isFile(), true);
  assert.equal(helperStatBefore.isSymbolicLink(), false);
  assert.equal(helperStatBefore.mode & 0o111, 0, "PoC helper must remain non-executable");
  fs.writeFileSync(helperPath, "#!/bin/sh\nprintf 'provider-helper-replaced\\n'\n", { encoding: "utf8", mode: 0o600, flag: "w" });
  const helperHashAfter = sha256File(helperPath);
  assert.notEqual(helperHashAfter, helperHashBefore, "provider helper replacement did not change bytes");
  verifyLockFiles(lock);
  validateRenderedWorkloads({ core, combined: combinedFor(helperPath), lock });
  console.log(`[VULNERABLE] mutable_replacement_survives_lock=true before=${helperHashBefore} after=${helperHashAfter}`);

  const composeBytes = fs.readFileSync(composePath);
  fs.appendFileSync(composePath, "# negative-control mutation\n");
  assert.throws(() => verifyLockFiles(lock), /Locked file changed/, "listed Compose mutation unexpectedly passed the lock");
  fs.writeFileSync(composePath, composeBytes, { mode: 0o600, flag: "w" });
  verifyLockFiles(lock);
  console.log("[+] negative-control listed_compose_mutation_rejected=true original_bytes_restored=true");

  assert.equal(fs.lstatSync(helperLinkPath).isSymbolicLink(), true);
  fs.unlinkSync(helperLinkPath);
  fs.symlinkSync(path.basename(alternateHelperPath), helperLinkPath);
  verifyLockFiles(lock);
  validateRenderedWorkloads({ core, combined: combinedFor(helperLinkPath), lock });
  console.log("[VULNERABLE] symlink_retarget_survives_lock=true");
  console.log("[+] activation-path workload_compose_reopened=true remote_compose_up=true source_assertions_only=true");
  console.log("[+] safety helper_executable=false provider_processes_started=0 compose_calls=0 docker_calls=0 services_started=0 network_attempts=0");
  console.log("[+] result=VULNERABLE");
} finally {
  cleanupOwnedFixture(fixtureOwnership, wrapperRoot);
}

assert.equal(fs.existsSync(fixtureRoot), false, "sentinel-owned fixture was not removed");
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
const preservedStat = fs.lstatSync(preexistingFile);
assert.equal(preservedStat.dev, preexistingBefore.dev);
assert.equal(preservedStat.ino, preexistingBefore.ino);
assert.equal(sha256File(preexistingFile), preexistingHash);
console.log("[+] cleanup sentinel_owned_fixture_removed=true preexisting_helper_still_present=true");

function writeExclusive(filePath, contents, mode = 0o600) {
  fs.writeFileSync(filePath, contents, { encoding: "utf8", mode, flag: "wx" });
}

function writeExclusiveJson(filePath, value) {
  writeExclusive(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

function claimOwnedFixture(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "fixture target escaped the wrapper root");
  if (fs.existsSync(targetPath)) {
    throw new Error(`refusing pre-existing fixture target: ${targetPath}`);
  }
  assert.match(path.basename(targetPath), /^fixture-[0-9a-f]{64}$/, "fixture name is not token-bound");
  fs.mkdirSync(targetPath, { recursive: false, mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true, "claimed fixture target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "claimed fixture target is a symbolic link");
  assert.equal(fs.realpathSync(targetPath), targetPath, "claimed fixture target must be its physical path");
  const sentinelPath = path.join(targetPath, `.provider-lock-probe-owner-${token}`);
  fs.writeFileSync(sentinelPath, `hosted-provider-lock:${token}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  const sentinelStat = fs.lstatSync(sentinelPath);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    sentinelPath,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
    token,
  };
}

function cleanupOwnedFixture(ownership, expectedParent) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through a target symbolic link");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  assert.equal(fs.realpathSync(ownership.targetPath), ownership.targetPath, "cleanup target is not its physical path");
  assert.equal(path.dirname(ownership.targetPath), expectedParent, "cleanup target escaped the wrapper root");

  const sentinelStat = fs.lstatSync(ownership.sentinelPath);
  assert.equal(sentinelStat.isFile(), true, "cleanup ownership sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "refusing cleanup through a sentinel symbolic link");
  assert.equal(sentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(sentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.sentinelPath, "utf8"),
    `hosted-provider-lock:${ownership.token}\n`,
    "refusing cleanup without the fixture ownership token",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}
