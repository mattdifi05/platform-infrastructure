#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const EXPECTED_HASHES = new Map([
  [".github/workflows/enterprise-vps-evidence.yml", "312d035fea9b16017289c1c87b2222a48f292d6a93f8f725bf486227588b9f1d"],
  ["scripts/vps-evidence-request.mjs", "b5214592c3ea5cbcbc9b52142a2236708e23f20ffb95ae48d4bf9de790977e40"],
  ["scripts/vps-evidence-remote.sh", "c5a893a722addfa3da16d405caf2239a4c89228dd6f7858facc61a9b2716cb2d"],
  ["scripts/vps-host-readiness.sh", "a992bb416f7bc2175515cd91b95ba84772d586509002fbe17dd96ad88159f198"],
]);

const sourceArgument = process.argv[2];
const labArgument = process.argv[3];
if (!sourceArgument || !labArgument) {
  throw new Error(
    "usage: remote-revision-binding-probe.mjs WRAPPER_OWNED_SOURCE WRAPPER_OWNED_LAB",
  );
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
console.log("[+] wrapper-owned source and lab boundaries verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const workflowSource = fs.readFileSync(
  path.join(sourceRoot, ".github/workflows/enterprise-vps-evidence.yml"),
  "utf8",
);
const requestSource = fs.readFileSync(
  path.join(sourceRoot, "scripts/vps-evidence-request.mjs"),
  "utf8",
);
const remoteSource = fs.readFileSync(
  path.join(sourceRoot, "scripts/vps-evidence-remote.sh"),
  "utf8",
);
const readinessSource = fs.readFileSync(
  path.join(sourceRoot, "scripts/vps-host-readiness.sh"),
  "utf8",
);

assert.match(workflowSource, /node \.\/scripts\/vps-evidence-request\.mjs render/);
assert.match(
  workflowSource,
  /ssh -i ~\/\.ssh\/deploy_key[\s\S]*'bash -s' < \.tmp\/vps-evidence-remote\.sh/,
);
assert.doesNotMatch(workflowSource, /github\.sha|GITHUB_SHA|EXPECTED_(?:COMMIT|TREE)/);

for (const assignment of [
  "PLATFORM_REMOTE_DIR_B64",
  "PLATFORM_HARDENED_SSH_PORT_B64",
  "PLATFORM_RUN_BOOTSTRAP_B64",
  "PLATFORM_RUN_HARDENING_B64",
  "PLATFORM_RELOAD_SSHD_B64",
  "PLATFORM_REPLACE_DOCKER_DAEMON_CONFIG_B64",
  "PLATFORM_DEPLOY_USER_B64",
]) {
  assert.match(requestSource, new RegExp(assignment));
}
assert.doesNotMatch(
  requestSource,
  /PLATFORM_(?:EXPECTED|WORKFLOW|SOURCE)_(?:COMMIT|TREE|SHA)|GITHUB_SHA/,
);

assert.match(
  remoteSource,
  /cd -- "\$remote_dir"\ngit fetch --all --prune\ngit checkout main\ngit pull --ff-only origin main/,
);
assert.doesNotMatch(
  remoteSource,
  /checkout --detach|rev-parse HEAD|status --porcelain|EXPECTED_(?:COMMIT|TREE)/,
);
assert.match(remoteSource, /tar -czf - "\$\{tar_paths\[@\]\}" \| base64 -w0/);
assert.doesNotMatch(remoteSource, /evidence-manifest|sourceCommit|sourceTree/);
assert.doesNotMatch(readinessSource, /git rev-parse|sourceCommit|sourceTree/);

console.log(
  "[TRACE] workflow_revision_forwarded=false expected_tree_forwarded=false remote_selection=main-fast-forward archive_binding=missing",
);

const gitEnvironment = {
  PATH: process.env.PATH || "/usr/bin:/bin",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: path.join(labRoot, "empty-global-gitconfig"),
  GIT_TERMINAL_PROMPT: "0",
  GIT_ALLOW_PROTOCOL: "file",
  HOME: path.join(labRoot, "home"),
  LC_ALL: "C",
};
fs.mkdirSync(gitEnvironment.HOME);
fs.writeFileSync(gitEnvironment.GIT_CONFIG_GLOBAL, "", { mode: 0o600 });

const authorRoot = path.join(labRoot, "author");
const originRoot = path.join(labRoot, "origin.git");
const remoteRoot = path.join(labRoot, "remote");
fs.mkdirSync(authorRoot);
git(authorRoot, ["init", "-q"]);
git(authorRoot, ["branch", "-M", "main"]);
fs.writeFileSync(path.join(authorRoot, "evidence-source.txt"), "revision-A\n");
git(authorRoot, ["add", "evidence-source.txt"]);
git(authorRoot, ["commit", "-q", "-m", "workflow revision A"], commitEnvironment("2001-01-01T00:00:00Z"));
const workflowCommit = git(authorRoot, ["rev-parse", "HEAD"]);
const workflowTree = git(authorRoot, ["rev-parse", "HEAD^{tree}"]);

git(labRoot, ["clone", "-q", "--bare", authorRoot, originRoot]);
git(authorRoot, ["remote", "add", "origin", originRoot]);
git(labRoot, ["clone", "-q", originRoot, remoteRoot]);
assert.equal(path.resolve(git(remoteRoot, ["remote", "get-url", "origin"])), originRoot);

fs.writeFileSync(path.join(authorRoot, "evidence-source.txt"), "revision-B\n");
git(authorRoot, ["add", "evidence-source.txt"]);
git(authorRoot, ["commit", "-q", "-m", "mutable main B"], commitEnvironment("2001-01-02T00:00:00Z"));
const mutableMainCommit = git(authorRoot, ["rev-parse", "HEAD"]);
const mutableMainTree = git(authorRoot, ["rev-parse", "HEAD^{tree}"]);
assert.notEqual(mutableMainCommit, workflowCommit);
assert.notEqual(mutableMainTree, workflowTree);
git(authorRoot, ["push", "-q", "origin", "main"]);

git(remoteRoot, ["fetch", "--all", "--prune"]);
git(remoteRoot, ["checkout", "main"]);
git(remoteRoot, ["pull", "--ff-only", "origin", "main"]);
assert.equal(git(remoteRoot, ["rev-parse", "HEAD"]), mutableMainCommit);
assert.equal(
  fs.readFileSync(path.join(remoteRoot, "evidence-source.txt"), "utf8"),
  "revision-B\n",
);
console.log(
  "[VULNERABLE] workflow_sha=A remote_head=B evidence_revision=B workflow_matches_remote=false",
);

const mutableMain = verifyBoundWorktree(remoteRoot, workflowCommit, workflowTree);
assert.deepEqual(mutableMain, { ok: false, reason: "not-detached" });

git(remoteRoot, ["checkout", "--detach", mutableMainCommit]);
const wrongCommit = verifyBoundWorktree(remoteRoot, workflowCommit, workflowTree);
assert.deepEqual(wrongCommit, { ok: false, reason: "wrong-commit" });

git(remoteRoot, ["checkout", "--detach", workflowCommit]);
const wrongTree = verifyBoundWorktree(remoteRoot, workflowCommit, mutableMainTree);
assert.deepEqual(wrongTree, { ok: false, reason: "wrong-tree" });

fs.writeFileSync(path.join(remoteRoot, "evidence-source.txt"), "locally-dirty\n");
const dirty = verifyBoundWorktree(remoteRoot, workflowCommit, workflowTree);
assert.deepEqual(dirty, { ok: false, reason: "dirty-worktree" });

fs.writeFileSync(path.join(remoteRoot, "evidence-source.txt"), "revision-A\n");
const exact = verifyBoundWorktree(remoteRoot, workflowCommit, workflowTree);
assert.deepEqual(exact, { ok: true, reason: "exact-detached" });

console.log(
  "[CONTROL] mutable_main=rejected wrong_commit=rejected wrong_tree=rejected dirty_worktree=rejected exact_detached=accepted",
);

assert.equal(directoryDigest(sourceRoot), sourceBefore, "the source snapshot changed during the PoC");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the PoC");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the PoC");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the PoC");
console.log("[+] summary revision_mismatch_reproduced=true source_tree_unchanged=true");
console.log(
  "[+] no network, SSH, GitHub API, credential, sudo, host check, archive extraction, or live target was accessed",
);

function verifyBoundWorktree(repository, expectedCommit, expectedTree) {
  if (!/^[a-f0-9]{40}$/.test(expectedCommit)) return { ok: false, reason: "invalid-commit" };
  if (!/^[a-f0-9]{40}$/.test(expectedTree)) return { ok: false, reason: "invalid-tree" };

  const symbolic = gitResult(repository, ["symbolic-ref", "--quiet", "HEAD"]);
  if (symbolic.status === 0) return { ok: false, reason: "not-detached" };
  if (![1, 128].includes(symbolic.status)) {
    throw new Error(`unexpected symbolic-ref failure: ${symbolic.stderr.trim()}`);
  }

  const actualCommit = git(repository, ["rev-parse", "HEAD"]);
  if (actualCommit !== expectedCommit) return { ok: false, reason: "wrong-commit" };
  const actualTree = git(repository, ["rev-parse", "HEAD^{tree}"]);
  if (actualTree !== expectedTree) return { ok: false, reason: "wrong-tree" };
  const status = git(repository, ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "") return { ok: false, reason: "dirty-worktree" };
  return { ok: true, reason: "exact-detached" };
}

function commitEnvironment(timestamp) {
  return {
    GIT_AUTHOR_NAME: "Offline PoC",
    GIT_AUTHOR_EMAIL: "poc@example.invalid",
    GIT_AUTHOR_DATE: timestamp,
    GIT_COMMITTER_NAME: "Offline PoC",
    GIT_COMMITTER_EMAIL: "poc@example.invalid",
    GIT_COMMITTER_DATE: timestamp,
  };
}

function git(cwd, args, extraEnvironment = {}) {
  const result = gitResult(cwd, args, extraEnvironment);
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed (${result.status}): ${result.stderr.trim()}`,
    );
  }
  return result.stdout.trim();
}

function gitResult(cwd, args, extraEnvironment = {}) {
  const result = spawnSync(
    "git",
    ["-c", "protocol.file.allow=always", ...args],
    {
      cwd,
      encoding: "utf8",
      env: { ...gitEnvironment, ...extraEnvironment },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.error) throw result.error;
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function validateWrapperOwnedPaths(sourceInput, labInput) {
  const wrapperInput = requiredEnvironment("FG058_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG058_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG058_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg058-(?:guard|run)\.[A-Za-z0-9]+$/,
    "wrapper temporary root does not have the expected mktemp name",
  );

  const sourcePath = path.resolve(sourceInput);
  const sourceStat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(sourcePath);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned source child");

  const sentinelPath = path.resolve(sentinelInput);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside the wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg058-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg058-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG058-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  const labPath = path.resolve(labInput);
  const labStat = fs.lstatSync(labPath, { throwIfNoEntry: false });
  assert.ok(labStat?.isDirectory(), "wrapper laboratory directory is missing");
  assert.equal(labStat.isSymbolicLink(), false, "wrapper laboratory directory must not be a symlink");
  const labReal = fs.realpathSync(labPath);
  assert.equal(labReal, path.join(wrapperReal, "lab"), "lab must be the exact wrapper-owned lab child");
  assert.deepEqual(fs.readdirSync(labReal), [], "wrapper laboratory directory must start empty");

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

function sha256File(filePath) {
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
