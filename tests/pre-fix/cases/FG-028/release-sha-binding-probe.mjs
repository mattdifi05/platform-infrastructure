#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const EXPECTED_HASHES = new Map([
  [".github/workflows/enterprise-infra.yml", "1cc02a79d482c2bee65e0173c879d7cf06f74f84ee5d9a6ed6893b2907fd8650"],
  ["scripts/deploy-vps.sh", "ee572ce2164fa620c59eb63cecc5d75db02f58d9e664bf923400b5315ef75245"],
  ["scripts/deploy-vps-remote.sh", "e7460e9db36765e6078d778d8a5388d54a78ee4620ddb70f2f7a19187f937804"],
  ["SECURITY.md", "b72a0abd090dfa15832d5af3e389edeee50cf5128cbd515e7c74b6a72f4d9cb3"],
]);
const sourceRoot = path.resolve(process.argv[2] ?? "");

if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: release-sha-binding-probe.mjs /path/to/archived/source");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified exact workflow, deploy scripts, and policy source hashes");

const workflow = readSource(".github/workflows/enterprise-infra.yml");
const client = readSource("scripts/deploy-vps.sh");
const remote = readSource("scripts/deploy-vps-remote.sh");
const security = readSource("SECURITY.md");
const deployJob = workflow.slice(workflow.indexOf("  deploy-vps:"));

assert.match(workflow, /github-actions-run-evidence[\s\S]*--sha "\$\{\{ github\.sha \}\}"/);
assert.match(deployJob, /environment:\s+name: production/);
assert.match(deployJob, /concurrency:\s+group: infra-production-deploy\s+cancel-in-progress: false/);
assert.match(deployJob, /uses: actions\/checkout@/);
assert.doesNotMatch(deployJob, /DEPLOY_(?:APPROVED_)?(?:SHA|COMMIT|TREE)/);
assert.doesNotMatch(deployJob, /github\.sha/);
assert.match(client, /BRANCH="\$\{DEPLOY_BRANCH:-main\}"/);
assert.match(client, /PLATFORM_BRANCH_B64/);
assert.doesNotMatch(client, /PLATFORM_(?:APPROVED_)?(?:SHA|COMMIT|TREE)_B64/);
assert.match(remote, /git fetch --all --prune\s+git checkout "\$branch"\s+git pull --ff-only origin "\$branch"/);
assert.match(remote, /git pull --ff-only origin "\$branch"\s+sh \.\/scripts\/vps-preflight\.sh[\s\S]*compose-vps\.sh up -d --build --remove-orphans/);
assert.match(security, /Hosted manifests, Compose files, non-secret environments and migrations are\s+hash-locked\. A changed input fails closed before Compose activation\./);

const temporaryParent = process.env.RELEASE_SHA_POC_TMP || os.tmpdir();
const fixtureRoot = fs.mkdtempSync(path.join(temporaryParent, "release-sha-fixture-"));
let completed = false;

try {
  const origin = path.join(fixtureRoot, "origin.git");
  const otherOrigin = path.join(fixtureRoot, "other-origin.git");
  const seed = path.join(fixtureRoot, "seed");
  const host = path.join(fixtureRoot, "host");
  fs.mkdirSync(seed);
  runGit(fixtureRoot, ["init", "--bare", origin]);
  runGit(fixtureRoot, ["init", "--bare", otherOrigin]);
  runGit(seed, ["init"]);
  runGit(seed, ["config", "user.name", "Synthetic Release Probe"]);
  runGit(seed, ["config", "user.email", "probe@example.invalid"]);
  runGit(seed, ["checkout", "-b", "main"]);

  fs.writeFileSync(path.join(seed, "release-payload.txt"), "approved\n");
  runGit(seed, ["add", "release-payload.txt"]);
  runGit(seed, ["commit", "-m", "approved workflow commit"], {
    GIT_AUTHOR_DATE: "2030-01-01T00:00:00Z",
    GIT_COMMITTER_DATE: "2030-01-01T00:00:00Z",
  });
  const approvedSha = gitOutput(seed, ["rev-parse", "HEAD"]);
  const approvedTree = gitOutput(seed, ["rev-parse", "HEAD^{tree}"]);
  assert.match(approvedSha, /^[a-f0-9]{40}$/);
  assert.match(approvedTree, /^[a-f0-9]{40}$/);
  runGit(seed, ["remote", "add", "origin", origin]);
  runGit(seed, ["push", "-u", "origin", "main"]);
  runGit(fixtureRoot, ["clone", "--branch", "main", origin, host]);
  assert.equal(gitOutput(host, ["rev-parse", "HEAD"]), approvedSha);
  console.log(`[APPROVAL] approved_sha=${approvedSha} approved_tree=${approvedTree}`);

  fs.writeFileSync(path.join(seed, "release-payload.txt"), "post-approval\n");
  runGit(seed, ["add", "release-payload.txt"]);
  runGit(seed, ["commit", "-m", "post-approval branch update"], {
    GIT_AUTHOR_DATE: "2030-01-02T00:00:00Z",
    GIT_COMMITTER_DATE: "2030-01-02T00:00:00Z",
  });
  const movedSha = gitOutput(seed, ["rev-parse", "HEAD"]);
  const movedTree = gitOutput(seed, ["rev-parse", "HEAD^{tree}"]);
  runGit(seed, ["push", "origin", "main"]);
  runGit(seed, ["merge-base", "--is-ancestor", approvedSha, movedSha]);
  assert.notEqual(movedSha, approvedSha);
  console.log(`[BRANCH-MOVED] main_sha=${movedSha} main_tree=${movedTree} fast_forward=true`);

  // Reproduce the archived remote sequence without running preflight or Compose.
  runGit(host, ["fetch", "--all", "--prune"]);
  runGit(host, ["checkout", "main"]);
  runGit(host, ["pull", "--ff-only", "origin", "main"]);
  const vulnerableHead = gitOutput(host, ["rev-parse", "HEAD"]);
  const vulnerableTree = gitOutput(host, ["rev-parse", "HEAD^{tree}"]);
  const vulnerablePayload = fs.readFileSync(path.join(host, "release-payload.txt"), "utf8").trim();
  assert.equal(vulnerableHead, movedSha);
  assert.equal(vulnerableTree, movedTree);
  assert.notEqual(vulnerableHead, approvedSha);
  assert.equal(vulnerablePayload, "post-approval");
  console.log(
    `[VULNERABLE] protocol=fetch+checkout+pull-ff-only deployed_sha=${vulnerableHead}`
    + ` approved_match=false payload=${vulnerablePayload} activation_executed=false`,
  );

  const expectedBinding = {
    sha: approvedSha,
    tree: approvedTree,
    origin: fs.realpathSync(origin),
  };
  const movingTargetCheck = verifyReleaseBinding(host, expectedBinding);
  assert.deepEqual(movingTargetCheck, { accepted: false, reason: "commit-mismatch" });
  console.log(`[REFERENCE-MOVING-TARGET] accepted=false reason=${movingTargetCheck.reason} activation=false`);

  // A corrected handoff fetches the approved object and checks it out detached.
  runGit(host, ["checkout", "--detach", approvedSha]);
  const approvedCheck = verifyReleaseBinding(host, expectedBinding);
  assert.equal(approvedCheck.accepted, true);
  assert.equal(gitOutput(host, ["symbolic-ref", "-q", "HEAD"], { allowFailure: true }), "");
  console.log(
    `[REFERENCE-DETACHED] accepted=true head=${approvedCheck.head} tree=${approvedCheck.tree}`
    + ` detached=true activation_allowed=true`,
  );

  const wrongRepository = verifyReleaseBinding(host, { ...expectedBinding, origin: fs.realpathSync(otherOrigin) });
  assert.deepEqual(wrongRepository, { accepted: false, reason: "repository-mismatch" });
  console.log(`[REFERENCE-WRONG-REPOSITORY] accepted=false reason=${wrongRepository.reason} activation=false`);

  const wrongTree = verifyReleaseBinding(host, { ...expectedBinding, tree: "0".repeat(40) });
  assert.deepEqual(wrongTree, { accepted: false, reason: "tree-mismatch" });
  console.log(`[REFERENCE-WRONG-TREE] accepted=false reason=${wrongTree.reason} activation=false`);

  fs.appendFileSync(path.join(host, "release-payload.txt"), "dirty\n");
  const dirtyTree = verifyReleaseBinding(host, expectedBinding);
  assert.deepEqual(dirtyTree, { accepted: false, reason: "dirty-worktree" });
  console.log(`[REFERENCE-DIRTY-WORKTREE] accepted=false reason=${dirtyTree.reason} activation=false`);
  runGit(host, ["restore", "release-payload.txt"]);
  assert.equal(verifyReleaseBinding(host, expectedBinding).accepted, true);

  console.log("[+] moving head reproduced and commit/repository/tree/cleanliness reference gates verified");
  console.log("[+] no SSH, network transport, workflow, server, preflight, Compose, container, deployment, or secret was used");
  completed = true;
} finally {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
}

assert.equal(completed, true);
assert.equal(fs.existsSync(fixtureRoot), false);
console.log("[+] temporary Git repositories removed");

function verifyReleaseBinding(repository, expected) {
  assert.match(expected.sha, /^[a-f0-9]{40}$/);
  assert.match(expected.tree, /^[a-f0-9]{40}$/);
  const configuredOrigin = gitOutput(repository, ["remote", "get-url", "origin"]);
  const actualOrigin = fs.realpathSync(path.resolve(repository, configuredOrigin));
  if (actualOrigin !== expected.origin) return { accepted: false, reason: "repository-mismatch" };
  if (gitOutput(repository, ["status", "--porcelain=v1", "--untracked-files=all"]) !== "") {
    return { accepted: false, reason: "dirty-worktree" };
  }
  const head = gitOutput(repository, ["rev-parse", "HEAD"]);
  if (head !== expected.sha) return { accepted: false, reason: "commit-mismatch" };
  const tree = gitOutput(repository, ["rev-parse", "HEAD^{tree}"]);
  if (tree !== expected.tree) return { accepted: false, reason: "tree-mismatch" };
  return { accepted: true, reason: "exact-binding", head, tree };
}

function runGit(cwd, args, extraEnv = {}) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: gitEnvironment(extraEnv),
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${(result.stderr || result.stdout).trim()}`);
  }
  return result;
}

function gitOutput(cwd, args, { allowFailure = false } = {}) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", env: gitEnvironment() });
  if (result.status !== 0) {
    if (allowFailure) return "";
    throw new Error(`git ${args.join(" ")} failed: ${(result.stderr || result.stdout).trim()}`);
  }
  return result.stdout.trim();
}

function gitEnvironment(extra = {}) {
  return {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: os.devNull,
    GIT_TERMINAL_PROMPT: "0",
    ...extra,
  };
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}
