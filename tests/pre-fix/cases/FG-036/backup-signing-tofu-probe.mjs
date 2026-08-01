#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const EXPECTED_INFRA_OPS_SHA256 = "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b";
const [sourceRootArgument, wrapperRootArgument, wrapperSentinelArgument] = process.argv.slice(2);
if (!sourceRootArgument || !wrapperRootArgument || !wrapperSentinelArgument) {
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
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source archive must be the exact real source child of the wrapper root");
assert.equal(path.dirname(sourceRoot), wrapperRoot, "source archive escaped the wrapper root");

const wrapperSentinelPath = path.resolve(wrapperSentinelArgument);
const wrapperSentinelStat = fs.lstatSync(wrapperSentinelPath);
assert.equal(wrapperSentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(wrapperSentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel must not be a symbolic link");
assert.equal(fs.realpathSync(wrapperSentinelPath), wrapperSentinelPath, "wrapper ownership sentinel argument must be its physical path");
assert.equal(path.dirname(wrapperSentinelPath), wrapperRoot, "wrapper ownership sentinel escaped the wrapper root");
const sentinelMatch = path.basename(wrapperSentinelPath).match(/^\.backup-signing-tofu-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(wrapperSentinelPath, "utf8"),
  `backup-signing-tofu:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

const infraOps = path.join(sourceRoot, "scripts", "infra-ops.mjs");
assert.equal(sha256File(infraOps), EXPECTED_INFRA_OPS_SHA256, "unexpected infra-ops.mjs revision");

const backupsRoot = path.join(sourceRoot, "backups");
const backupsRootStat = fs.lstatSync(backupsRoot);
assert.equal(backupsRootStat.isDirectory(), true, "archive backups root is not a directory");
assert.equal(backupsRootStat.isSymbolicLink(), false, "archive backups root must not be a symbolic link");
assert.equal(fs.realpathSync(backupsRoot), backupsRoot, "archive backups root must be its physical path");

const preexistingRoot = path.join(backupsRoot, "poc-tofu-deny-preexisting");
const preexistingDump = path.join(preexistingRoot, "preserve-me.dump");
const preexistingContents = "preexisting-backup-must-survive\n";
const preexistingHash = sha256File(preexistingDump);
const preexistingEntries = fs.readdirSync(preexistingRoot).sort();
assert.equal(fs.readFileSync(preexistingDump, "utf8"), preexistingContents);
assert.throws(
  () => claimOwnedFixture(preexistingRoot, ownerToken),
  /refusing pre-existing fixture target/,
);
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
assert.equal(fs.readFileSync(preexistingDump, "utf8"), preexistingContents);
assert.equal(sha256File(preexistingDump), preexistingHash);
assert.equal(fs.existsSync(`${preexistingDump}.sha256`), false);
assert.equal(fs.existsSync(`${preexistingDump}.sig.json`), false);
console.log(`[+] negative-control preexisting_target_rejected=true backup_preserved=true sha256=${preexistingHash}`);

const fixtureRoot = path.join(sourceRoot, "backups", `poc-tofu-deny-${ownerToken}`);
const fixtureOwnership = claimOwnedFixture(fixtureRoot, ownerToken);
const fakeBin = path.join(fixtureRoot, "fake-bin");
const dumpPath = path.join(fixtureRoot, "attacker-controlled.dump");
const keyPath = path.join(fixtureRoot, "poc-signing-keys.txt");
const dockerLog = path.join(fixtureRoot, "fake-docker.log");
const signaturePath = `${dumpPath}.sig.json`;
const checksumPath = `${dumpPath}.sha256`;
const keyId = "poc-v1";
const key = "A".repeat(64);

console.log("[+] confinement source_realpath_exact_child=true wrapper_sentinel_valid=true");

try {
  fs.mkdirSync(fakeBin, { recursive: false, mode: 0o700 });
  fs.writeFileSync(
    path.join(fakeBin, "docker"),
    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${POC_DOCKER_LOG:?}\"\nexit 77\n",
    { mode: 0o700, flag: "wx" },
  );
  fs.writeFileSync(dumpPath, "not-a-postgresql-custom-dump\nattacker-controlled=1\n", { mode: 0o600, flag: "wx" });
  fs.writeFileSync(keyPath, `${keyId}=${key}\n`, { mode: 0o600, flag: "wx" });

  const commonEnvironment = {
    ...process.env,
    PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    POC_DOCKER_LOG: dockerLog,
  };

  const restoreArguments = [
    "restore-postgres",
    "--backupFile",
    dumpPath,
    "--confirmRestore",
    "--container",
    "poc-no-container",
    "--database",
    "poc_database",
    "--user",
    "postgres",
    "--backupSigningKeysFile",
    keyPath,
  ];

  const unsignedRestore = runInfra(restoreArguments, commonEnvironment);
  assert.notEqual(unsignedRestore.status, 0, "unsigned fixture unexpectedly reached restore");
  assert.match(outputOf(unsignedRestore), /Missing backup checksum sidecar/);
  assert.equal(readLog(), "", "unsigned fixture reached the Docker boundary");
  console.log("[+] negative-control unsigned artifact rejected before Docker");

  const signing = runInfra([
    "sign-existing-postgres-backups",
    "--backupRoot",
    fixtureRoot,
    "--backupSigningKeysFile",
    keyPath,
  ], commonEnvironment);
  assert.equal(signing.status, 0, outputOf(signing));
  assert.match(outputOf(signing), /signed=1 verified=0 total=1/);

  const dumpHash = sha256File(dumpPath);
  const checksum = fs.readFileSync(checksumPath, "ascii").trim().split(/\s+/, 1)[0];
  assert.equal(checksum, dumpHash);
  const sidecar = JSON.parse(fs.readFileSync(signaturePath, "utf8"));
  assert.deepEqual(
    {
      version: sidecar.version,
      algorithm: sidecar.algorithm,
      keyId: sidecar.keyId,
      artifact: sidecar.artifact,
      sha256: sidecar.sha256,
    },
    {
      version: 1,
      algorithm: "HMAC-SHA256",
      keyId,
      artifact: path.basename(dumpPath),
      sha256: dumpHash,
    },
  );
  const expectedSignature = crypto
    .createHmac("sha256", key)
    .update(`platform-postgres-backup-v1\n${path.basename(dumpPath)}\n${dumpHash}\n`)
    .digest("base64url");
  assert.equal(sidecar.signature, expectedSignature);
  assert.equal(fs.statSync(signaturePath).mode & 0o777, 0o600);
  console.log(`[VULNERABLE] arbitrary_dump_signed=true sha256=${dumpHash}`);
  console.log(`[VULNERABLE] signature_valid=true key_id=${keyId} provenance_fields=0`);

  const trustedRestore = runInfra(restoreArguments, commonEnvironment);
  assert.notEqual(trustedRestore.status, 0, "fake Docker unexpectedly reported a restore success");
  assert.match(outputOf(trustedRestore), /Copying backup into poc-no-container/);
  const dockerCalls = readLog().split("\n").filter(Boolean);
  assert.match(dockerCalls[0] ?? "", /^cp /);
  console.log("[VULNERABLE] restore_integrity_gate=passed docker_cp_reached=true pg_restore_executed=false");

  fs.appendFileSync(dumpPath, "tampered-after-signing\n");
  fs.writeFileSync(dockerLog, "", "utf8");
  const modifiedRestore = runInfra(restoreArguments, commonEnvironment);
  assert.notEqual(modifiedRestore.status, 0, "modified fixture unexpectedly reached restore");
  assert.match(outputOf(modifiedRestore), /Backup checksum mismatch/);
  assert.equal(readLog(), "", "modified fixture reached the Docker boundary");
  console.log("[+] negative-control post-sign modification rejected before Docker");
} finally {
  cleanupOwnedFixture(fixtureOwnership);
}

assert.equal(fs.existsSync(fixtureRoot), false, "sentinel-owned fixture was not removed");
assert.equal(fs.readFileSync(preexistingDump, "utf8"), preexistingContents);
assert.equal(sha256File(preexistingDump), preexistingHash);
console.log("[+] cleanup sentinel_owned_fixture_removed=true preexisting_backup_still_present=true");
console.log("[+] safety live_docker_calls=0 pg_restore_calls=0 services_started=0 network_attempts=0");
console.log("[+] result=VULNERABLE");

function runInfra(argumentsList, environment) {
  return spawnSync(process.execPath, [infraOps, ...argumentsList], {
    cwd: sourceRoot,
    env: environment,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
}

function outputOf(result) {
  if (result.error) {
    throw result.error;
  }
  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

function readLog() {
  return fs.readFileSync(dockerLog, { encoding: "utf8", flag: "a+" }).trim();
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function claimOwnedFixture(targetPath, token) {
  assert.equal(path.dirname(targetPath), backupsRoot, "fixture target escaped the archive backups root");
  if (fs.existsSync(targetPath)) {
    throw new Error(`refusing pre-existing fixture target: ${targetPath}`);
  }
  fs.mkdirSync(targetPath, { recursive: false, mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true, "claimed fixture target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "claimed fixture target is a symbolic link");
  const sentinelPath = path.join(targetPath, `.poc-owner-${token}`);
  fs.writeFileSync(sentinelPath, `backup-signing-tofu:${token}\n`, {
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

function cleanupOwnedFixture(ownership) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through a target symbolic link");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  assert.equal(fs.realpathSync(ownership.targetPath), ownership.targetPath, "cleanup target is not its physical path");
  assert.equal(path.dirname(ownership.targetPath), backupsRoot, "cleanup target escaped the archive backups root");

  const sentinelStat = fs.lstatSync(ownership.sentinelPath);
  assert.equal(sentinelStat.isFile(), true, "cleanup ownership sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "refusing cleanup through a sentinel symbolic link");
  assert.equal(sentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(sentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.sentinelPath, "utf8"),
    `backup-signing-tofu:${ownership.token}\n`,
    "refusing cleanup without the fixture ownership token",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}
