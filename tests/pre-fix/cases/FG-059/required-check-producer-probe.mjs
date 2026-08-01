#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/github-governance-policy.mjs", "af8ef2dff13e2aeda17623736cb055428527fc303b3968418f7752299b1a372b"],
  ["governance/github-branch-protection.json", "319a788bde9012153a902ddcaf74dc12b97845e3c416b4d9bb2a24d42d74352b"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["scripts/github-governance-policy.test.mjs", "2333bbbe2b28564e28489479b0cb0b3b904c34b41a276477f1042b64eb2b2833"],
  [".github/workflows/enterprise-infra.yml", "1cc02a79d482c2bee65e0173c879d7cf06f74f84ee5d9a6ed6893b2907fd8650"],
]);

const EXPECTED_APP_ID = 1001;
const UNAPPROVED_APP_ID = 9001;
const sourceArgument = process.argv[2];
if (!sourceArgument) {
  throw new Error("usage: required-check-producer-probe.mjs WRAPPER_OWNED_SOURCE");
}

const {
  sourceRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedSource(sourceArgument);
const treeBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source boundary verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const policyPath = path.join(sourceRoot, "governance/github-branch-protection.json");
const modulePath = path.join(sourceRoot, "scripts/github-governance-policy.mjs");
const infraPath = path.join(sourceRoot, "scripts/infra-ops.mjs");
const testsPath = path.join(sourceRoot, "scripts/github-governance-policy.test.mjs");
const workflowPath = path.join(sourceRoot, ".github/workflows/enterprise-infra.yml");
const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
const policySource = fs.readFileSync(modulePath, "utf8");
const infraSource = fs.readFileSync(infraPath, "utf8");
const testSource = fs.readFileSync(testsPath, "utf8");
const workflowSource = fs.readFileSync(workflowPath, "utf8");

const required = policy.required_status_checks;
assert.equal(required.strict, true);
assert.deepEqual(required.contexts, ["quality", "compose", "supply-chain", "enterprise-readiness"]);
assert.equal(Object.hasOwn(required, "checks"), false, "the vulnerable policy unexpectedly binds checks to applications");
for (const context of required.contexts) {
  assert.match(workflowSource, new RegExp(`^  ${escapeRegex(context)}:`, "m"), `workflow job ${context} is missing`);
}

assert.match(policySource, /remote\?\.required_status_checks\?\.checks\?\.map\(\(check\) => check\.context\)/);
assert.match(policySource, /function sortedStrings\(values\)[\s\S]*new Set/);
assert.doesNotMatch(
  sourceSlice(policySource, "export function branchProtectionMismatches", "export function githubEnvironmentMismatches"),
  /app_id|integration_id/,
  "the vulnerable comparator unexpectedly checks producer identity",
);
assert.match(testSource, /extra status check fails exact comparison/);
assert.doesNotMatch(testSource, /app_id|integration_id/);
const applySlice = sourceSlice(
  infraSource,
  "async function githubBranchProtection() {",
  "\n\nasync function verifyGithubBranchProtectionRemote",
);
assert.match(applySlice, /const policy = githubBranchProtectionPolicy\(\);/);
assert.match(applySlice, /await githubApi\("PUT", apiPath, policy\);/);

const moduleUrl = pathToFileURL(modulePath).href;
const {
  branchProtectionMismatches,
  assertExactBranchProtection,
} = await import(moduleUrl);

console.log(
  `[+] policy required_contexts=${required.contexts.length} producer_bindings=0 apply_payload=contexts-only`,
);

const approvedChecks = checksForProducer(EXPECTED_APP_ID);
const approved = governanceResult(remoteBranch(approvedChecks));
assert.equal(approved.accepted, true);
assert.equal(tupleMismatchCount(approvedChecks), 0);
console.log(
  `[CONTROL] approved-producer app_id=${EXPECTED_APP_ID} tuple_mismatches=0 governance_mismatches=${approved.issues.length} accepted=true`,
);

const unapprovedChecks = checksForProducer(UNAPPROVED_APP_ID);
const unapproved = governanceResult(remoteBranch(unapprovedChecks));
const unapprovedTupleMismatches = tupleMismatchCount(unapprovedChecks);
assert.equal(unapproved.accepted, true);
assert.equal(unapproved.issues.length, 0);
assert.equal(unapprovedTupleMismatches, required.contexts.length);
console.log(
  `[VULNERABLE] unapproved-producer app_id=${UNAPPROVED_APP_ID} tuple_mismatches=${unapprovedTupleMismatches} governance_mismatches=0 accepted=true`,
);

const anyProducerChecks = checksForProducer(-1);
const anyProducer = governanceResult(remoteBranch(anyProducerChecks));
const anyTupleMismatches = tupleMismatchCount(anyProducerChecks);
assert.equal(anyProducer.accepted, true);
assert.equal(anyProducer.issues.length, 0);
assert.equal(anyTupleMismatches, required.contexts.length);
console.log(
  `[VULNERABLE] any-producer app_id=-1 tuple_mismatches=${anyTupleMismatches} governance_mismatches=0 accepted=true`,
);

const duplicateChecks = [
  ...approvedChecks,
  { context: "quality", app_id: UNAPPROVED_APP_ID },
];
const duplicate = governanceResult(remoteBranch(duplicateChecks));
const duplicateTupleMismatches = tupleMismatchCount(duplicateChecks);
assert.equal(duplicate.accepted, true);
assert.equal(duplicate.issues.length, 0);
assert.equal(duplicateTupleMismatches, 1);
console.log(
  `[VULNERABLE] duplicate-context context=quality app_ids=${EXPECTED_APP_ID},${UNAPPROVED_APP_ID} tuple_mismatches=${duplicateTupleMismatches} governance_mismatches=0 accepted=true`,
);

const missingChecks = approvedChecks.filter((check) => check.context !== "enterprise-readiness");
const missing = governanceResult(remoteBranch(missingChecks));
assert.equal(missing.accepted, false);
assert.equal(missing.issues.length, 1);
assert.match(missing.issues[0], /required status checks differ/);
console.log(`[CONTROL] missing-context governance_mismatches=${missing.issues.length} rejected=true`);

const extraChecks = [...approvedChecks, { context: "unreviewed-check", app_id: EXPECTED_APP_ID }];
const extra = governanceResult(remoteBranch(extraChecks));
assert.equal(extra.accepted, false);
assert.equal(extra.issues.length, 1);
assert.match(extra.issues[0], /required status checks differ/);
console.log(`[CONTROL] extra-context governance_mismatches=${extra.issues.length} rejected=true`);

assert.equal(directoryDigest(sourceRoot), treeBefore, "the archived source changed during the read-only probe");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the probe");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the probe");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the probe");
console.log("[+] summary vulnerable=3 controls=3 source_tree_unchanged=true");
console.log("[+] no GitHub API, status/check publication, pull request, merge, credential, network, or live target was accessed");

function checksForProducer(appId) {
  return required.contexts.map((context) => ({ context, app_id: appId }));
}

function tupleMismatchCount(checks) {
  let mismatches = 0;
  for (const context of required.contexts) {
    const ids = checks.filter((check) => check.context === context).map((check) => check.app_id).sort((a, b) => a - b);
    if (ids.length !== 1 || ids[0] !== EXPECTED_APP_ID) mismatches += 1;
  }
  for (const check of checks) {
    if (!required.contexts.includes(check.context)) mismatches += 1;
  }
  return mismatches;
}

function governanceResult(remote) {
  const issues = branchProtectionMismatches(policy, remote);
  let accepted = true;
  try {
    assertExactBranchProtection(policy, remote);
  } catch {
    accepted = false;
  }
  assert.equal(accepted, issues.length === 0, "mismatch list and throwing assertion disagree");
  return { accepted, issues };
}

function remoteBranch(checks) {
  return {
    required_status_checks: {
      strict: true,
      checks,
    },
    enforce_admins: { enabled: true },
    required_pull_request_reviews: structuredClone(policy.required_pull_request_reviews),
    restrictions: null,
    required_linear_history: { enabled: true },
    allow_force_pushes: { enabled: false },
    allow_deletions: { enabled: false },
    required_conversation_resolution: { enabled: true },
    block_creations: { enabled: true },
    lock_branch: { enabled: false },
    allow_fork_syncing: { enabled: false },
  };
}

function validateWrapperOwnedSource(sourceInput) {
  const wrapperInput = requiredEnvironment("FG059_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG059_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG059_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg059-(?:guard|run)\.[A-Za-z0-9]+$/,
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
  assert.match(path.basename(sentinelReal), /^\.fg059-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg059-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG059-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  return {
    sourceRoot: sourceReal,
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

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker.trim()}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker.trim()}`);
  return source.slice(start, end);
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
