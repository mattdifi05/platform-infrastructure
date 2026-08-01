#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const EXPECTED_INFRA_OPS_SHA256 = "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b";
const REPOSITORY_CANARY = "FG037_REPOSITORY_USERINFO_CANARY";
const PASSWORD_CANARY = "FG037_PASSWORD_FILE_CANARY";
const SYNTHETIC_FAILURE = "FG037_SYNTHETIC_DOCKER_FAILURE";

const [mode, sourceArgument, runRootArgument, wrapperRootArgument, sentinelArgument] = process.argv.slice(2);
if (!mode || !sourceArgument || !runRootArgument || !wrapperRootArgument || !sentinelArgument) {
  throw new Error(
    "direct invocation denied: use run-from-git-archive.sh with its wrapper-owned temporary archive",
  );
}
assert.ok(mode === "guard" || mode === "run", "mode must be guard or run");

const wrapperRoot = exactPhysicalDirectory(wrapperRootArgument, "wrapper root");
const runRoot = exactPhysicalDirectory(runRootArgument, "run root");
assert.equal(path.dirname(runRoot), wrapperRoot, "run root must be an exact child of the wrapper root");
assert.match(path.basename(runRoot), mode === "guard" ? /^guard\.[A-Za-z0-9]+$/ : /^run\.[A-Za-z0-9]+$/);

const sourceRoot = exactPhysicalDirectory(sourceArgument, "source archive");
assert.equal(sourceRoot, path.join(runRoot, "source"), "source archive must be the exact real source child");
assert.equal(path.dirname(sourceRoot), runRoot, "source archive escaped the run root");

const sentinelPath = path.resolve(sentinelArgument);
const sentinelStat = fs.lstatSync(sentinelPath);
assert.equal(sentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(sentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel must not be a symbolic link");
assert.equal(fs.realpathSync(sentinelPath), sentinelPath, "wrapper ownership sentinel must use its physical path");
assert.equal(path.dirname(sentinelPath), wrapperRoot, "wrapper ownership sentinel escaped the wrapper root");
const sentinelMatch = path.basename(sentinelPath).match(/^\.fg037-wrapper-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(sentinelPath, "utf8"),
  `fg037-restic-argv:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

const infraOps = path.join(sourceRoot, "scripts", "infra-ops.mjs");
assert.equal(sha256File(infraOps), EXPECTED_INFRA_OPS_SHA256, "unexpected infra-ops.mjs revision");

for (const targetName of ["reports", "backups", ".tmp"]) {
  const target = path.join(sourceRoot, targetName);
  if (fs.existsSync(target)) {
    throw new Error(`refusing to mutate pre-existing target path: ${targetName}`);
  }
}

if (mode === "guard") {
  throw new Error("guard mode requires a pre-existing mutation target");
}

console.log("[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true");
console.log(`[+] source infra_ops_sha256=${EXPECTED_INFRA_OPS_SHA256}`);

const fixtureRoot = path.join(runRoot, "fixture");
const fixtureOwnership = claimOwnedDirectory(fixtureRoot, runRoot, ownerToken);

try {
  const fakeBin = path.join(fixtureRoot, "fake-bin");
  fs.mkdirSync(fakeBin, { recursive: false, mode: 0o700 });
  const dockerArgvLog = path.join(fixtureRoot, "docker-argv.json");
  const fakeDocker = path.join(fakeBin, "docker");
  fs.writeFileSync(
    fakeDocker,
    `#!/usr/bin/env node
const fs = require("node:fs");
const target = process.env.FG037_DOCKER_ARGV_LOG;
if (!target) throw new Error("missing FG037_DOCKER_ARGV_LOG");
fs.writeFileSync(target, JSON.stringify(process.argv.slice(2)) + "\\n", { encoding: "utf8", mode: 0o600, flag: "wx" });
process.stderr.write("${SYNTHETIC_FAILURE}\\n");
process.exit(77);
`,
    { encoding: "utf8", mode: 0o700, flag: "wx" },
  );

  const passwordFile = path.join(fixtureRoot, "restic-password.txt");
  fs.writeFileSync(passwordFile, `${PASSWORD_CANARY}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  const repository = `rest:https://fg037-user:${REPOSITORY_CANARY}@backup.example.invalid/repository`;

  const environment = {
    PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? "/usr/bin:/bin"}`,
    HOME: fixtureRoot,
    TMPDIR: fixtureRoot,
    LANG: "C",
    LC_ALL: "C",
    RESTIC_REPOSITORY: repository,
    RESTIC_PASSWORD_FILE: passwordFile,
    RESTIC_REQUIRE_IMMUTABLE_IMAGE: "1",
    PLATFORM_INFRA_HOST_ROOT: sourceRoot,
    PROJECT_SOURCE_HOST_ROOT: sourceRoot,
    FG037_DOCKER_ARGV_LOG: dockerArgvLog,
  };
  const result = spawnSync(process.execPath, [
    infraOps,
    "offsite-restore-drill-restic",
    "--dryRun",
    "--skipInfraHealth",
    "--families=postgres",
  ], {
    cwd: sourceRoot,
    env: environment,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.notEqual(result.status, 0, "synthetic Docker failure unexpectedly succeeded");

  const dockerArgvRecords = fs.readFileSync(dockerArgvLog, "utf8").trim().split("\n").filter(Boolean);
  assert.equal(dockerArgvRecords.length, 1, "expected exactly one fake Docker invocation");
  const dockerArgv = JSON.parse(dockerArgvRecords[0]);
  assert.ok(Array.isArray(dockerArgv), "fake Docker argv capture is not an array");
  assert.deepEqual(dockerArgv.slice(0, 2), ["run", "--rm"]);
  const repositoryArgument = `RESTIC_REPOSITORY=${repository}`;
  const repositoryIndex = dockerArgv.indexOf(repositoryArgument);
  assert.ok(repositoryIndex > 0, "repository value did not reach Docker argv");
  assert.equal(dockerArgv[repositoryIndex - 1], "-e", "repository value is not a Docker environment argument");
  assert.ok(
    dockerArgv.includes("RESTIC_PASSWORD_FILE=/restic-password/restic-password.txt"),
    "password-file path did not reach Docker argv",
  );

  const stdout = String(result.stdout ?? "");
  const stderr = String(result.stderr ?? "");
  assert.ok(stderr.includes(SYNTHETIC_FAILURE), "synthetic child failure is absent from stderr");
  assert.ok(stderr.includes(REPOSITORY_CANARY), "repository canary is absent from serialized stderr");
  assert.equal(stdout.includes(REPOSITORY_CANARY), false, "this path unexpectedly copied the canary to stdout");

  const reportDirectory = exactPhysicalDirectory(
    path.join(sourceRoot, "reports", "offsite-restore-drills"),
    "generated report directory",
  );
  const reportEntries = fs.readdirSync(reportDirectory).sort();
  const jsonReports = reportEntries.filter((name) => name.endsWith(".json"));
  const markdownReports = reportEntries.filter((name) => name.endsWith(".md"));
  assert.equal(jsonReports.length, 1, "expected one JSON failure report");
  assert.equal(markdownReports.length, 1, "expected one Markdown failure report");
  assert.equal(reportEntries.length, 2, "unexpected files appeared in the report directory");

  const jsonText = fs.readFileSync(path.join(reportDirectory, jsonReports[0]), "utf8");
  const markdownText = fs.readFileSync(path.join(reportDirectory, markdownReports[0]), "utf8");
  const reportPayload = JSON.parse(jsonText);
  assert.equal(reportPayload.status, "failed");
  assert.ok(String(reportPayload.error).includes(REPOSITORY_CANARY), "JSON report did not persist the canary");
  assert.ok(markdownText.includes(REPOSITORY_CANARY), "Markdown report did not persist the canary");

  const exposedChannels = {
    childArgv: JSON.stringify(dockerArgv),
    stderr,
    jsonReport: jsonText,
    markdownReport: markdownText,
  };
  for (const [channel, content] of Object.entries(exposedChannels)) {
    assert.ok(content.includes(REPOSITORY_CANARY), `${channel} did not contain the repository canary`);
    assert.equal(content.includes(PASSWORD_CANARY), false, `${channel} exposed the password-file contents`);
  }
  assert.equal(stdout.includes(PASSWORD_CANARY), false);

  const backupRoot = exactPhysicalDirectory(path.join(sourceRoot, "backups"), "generated backup root");
  assert.deepEqual(fs.readdirSync(backupRoot), [], "failure path unexpectedly wrote backup data");
  assert.equal(fs.existsSync(path.join(sourceRoot, ".tmp")), false, "failure path unexpectedly created restore state");

  const referenceArgv = dockerArgv.map((argument) => (
    argument === repositoryArgument
      ? "RESTIC_REPOSITORY_FILE=/run/secrets/restic-repository"
      : argument
  ));
  const referenceError = redactSecrets(stderr, [repository, REPOSITORY_CANARY]);
  assert.equal(JSON.stringify(referenceArgv).includes(REPOSITORY_CANARY), false);
  assert.equal(referenceError.includes(REPOSITORY_CANARY), false);

  console.log("[VULNERABLE] repository_canary_in_docker_child_argv=true");
  console.log("[VULNERABLE] repository_canary_in_stderr=true json_report=true markdown_report=true");
  console.log("[NEGATIVE] password_file_contents_exposed=false stdout_repository_canary=false");
  console.log("[REFERENCE] repository_file_argv_secret_free=true centralized_error_redaction=true");
  console.log("[+] safety fake_docker_calls=1 real_docker_calls=0 real_restic_executions=0 network_attempts=0");
  console.log("[+] result=VULNERABLE");
} finally {
  cleanupOwnedDirectory(fixtureOwnership);
}

assert.equal(fs.existsSync(fixtureRoot), false, "sentinel-owned fixture was not removed");
console.log("[+] cleanup sentinel_owned_fixture_removed=true");

function exactPhysicalDirectory(argument, label) {
  const resolved = path.resolve(argument);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  const physical = fs.realpathSync(resolved);
  assert.equal(physical, resolved, `${label} argument must be its exact physical path`);
  return physical;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function claimOwnedDirectory(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "fixture target escaped its wrapper-owned parent");
  if (fs.existsSync(targetPath)) {
    throw new Error(`refusing pre-existing fixture target: ${targetPath}`);
  }
  fs.mkdirSync(targetPath, { recursive: false, mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true);
  assert.equal(targetStat.isSymbolicLink(), false);
  assert.equal(fs.realpathSync(targetPath), targetPath);
  const ownershipSentinel = path.join(targetPath, `.fg037-fixture-owner-${token}`);
  fs.writeFileSync(ownershipSentinel, `fg037-fixture:${token}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  const sentinelStat = fs.lstatSync(ownershipSentinel);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    ownershipSentinel,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
    token,
  };
}

function cleanupOwnedDirectory(ownership) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through target symlink");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  const sentinelStat = fs.lstatSync(ownership.ownershipSentinel);
  assert.equal(sentinelStat.isFile(), true, "cleanup sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "cleanup sentinel is a symbolic link");
  assert.equal(sentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(sentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.ownershipSentinel, "utf8"),
    `fg037-fixture:${ownership.token}\n`,
    "cleanup sentinel content changed",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}

function redactSecrets(value, secrets) {
  let redacted = String(value);
  for (const secret of [...secrets].sort((left, right) => right.length - left.length)) {
    if (secret) redacted = redacted.replaceAll(secret, "[REDACTED]");
  }
  return redacted;
}
