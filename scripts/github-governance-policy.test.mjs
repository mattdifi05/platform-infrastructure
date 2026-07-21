#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  applyAndVerifyBranchProtection,
  applyAndVerifyGithubEnvironment,
  assertValidGithubEnvironmentCollection,
  branchProtectionMismatches,
  githubEnvironmentMismatches,
  requiredStatusCheckMismatches,
} from "./github-governance-policy.mjs";

const branchPolicy = {
  required_status_checks: {
    strict: true,
    contexts: [],
    checks: [
      { context: "quality", app_id: 15368 },
      { context: "compose", app_id: 15368 },
    ],
  },
  enforce_admins: true,
  required_pull_request_reviews: {
    dismiss_stale_reviews: true,
    require_code_owner_reviews: true,
    require_last_push_approval: true,
    required_approving_review_count: 2,
    bypass_pull_request_allowances: { users: [], teams: [], apps: [] },
  },
  restrictions: null,
  required_linear_history: true,
  allow_force_pushes: false,
  allow_deletions: false,
  required_conversation_resolution: true,
  block_creations: true,
  lock_branch: false,
  allow_fork_syncing: false,
};

const remoteBranch = {
  required_status_checks: {
    strict: true,
    contexts: [],
    checks: [
      { context: "compose", app_id: 15368 },
      { context: "quality", app_id: 15368 },
    ],
  },
  enforce_admins: { enabled: true },
  required_pull_request_reviews: structuredClone(branchPolicy.required_pull_request_reviews),
  restrictions: null,
  required_linear_history: { enabled: true },
  allow_force_pushes: { enabled: false },
  allow_deletions: { enabled: false },
  required_conversation_resolution: { enabled: true },
  block_creations: { enabled: true },
  lock_branch: { enabled: false },
  allow_fork_syncing: { enabled: false },
};

const environmentPolicy = {
  name: "production",
  wait_timer: 15,
  prevent_self_review: true,
  require_reviewers_on_apply: true,
  reviewers: [{ type: "User", id: 95946096, login: "mattdifi05" }],
  deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
};

const remoteEnvironment = {
  protection_rules: [
    { type: "wait_timer", wait_timer: 15 },
    {
      type: "required_reviewers",
      prevent_self_review: true,
      reviewers: [{ type: "User", reviewer: { id: 95946096, login: "mattdifi05" } }],
    },
  ],
  deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
};

const tests = [];
function test(name, fn) {
  tests.push([name, fn]);
}

test("exact branch protection passes", () => {
  assert.deepEqual(branchProtectionMismatches(branchPolicy, remoteBranch), []);
});
test("missing status check fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.checks = [{ context: "quality", app_id: 15368 }];
  assert.match(branchProtectionMismatches(branchPolicy, remote).join(" "), /producer bindings/);
});
test("extra status check fails exact comparison", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.checks.push({ context: "unreviewed-check", app_id: 15368 });
  assert.match(branchProtectionMismatches(branchPolicy, remote).join(" "), /producer bindings/);
});
test("context-only policy fails closed", () => {
  assert.match(requiredStatusCheckMismatches({ contexts: ["quality"] }, remoteBranch.required_status_checks).join(" "), /context-only/);
});
test("context-only remote rule fails closed", () => {
  const remote = { strict: true, contexts: ["quality", "compose"] };
  assert.match(requiredStatusCheckMismatches(branchPolicy.required_status_checks, remote).join(" "), /context-only/);
});
test("wrong producer app id fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.checks[0].app_id = 999;
  assert.match(requiredStatusCheckMismatches(branchPolicy.required_status_checks, remote.required_status_checks).join(" "), /producer bindings/);
});
test("null producer app id fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.checks[0].app_id = null;
  assert.match(requiredStatusCheckMismatches(branchPolicy.required_status_checks, remote.required_status_checks).join(" "), /null/);
});
test("duplicate producer tuple fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.checks.push({ context: "quality", app_id: 15368 });
  assert.match(requiredStatusCheckMismatches(branchPolicy.required_status_checks, remote.required_status_checks).join(" "), /duplicate/);
});
test("string-valued producer app id fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.checks[0].app_id = "15368";
  assert.match(requiredStatusCheckMismatches(branchPolicy.required_status_checks, remote.required_status_checks).join(" "), /invalid app_id/);
});
test("same context with a different producer fails", () => {
  const policy = structuredClone(branchPolicy.required_status_checks);
  policy.checks.push({ context: "quality", app_id: 999 });
  assert.match(requiredStatusCheckMismatches(policy, policy).join(" "), /exactly once/);
});
test("non-strict status checks fail", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.strict = false;
  assert.match(branchProtectionMismatches(branchPolicy, remote).join(" "), /strict/);
});
test("admins bypass fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.enforce_admins.enabled = false;
  assert.match(branchProtectionMismatches(branchPolicy, remote).join(" "), /enforce_admins/);
});
test("review bypass allowance fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_pull_request_reviews.bypass_pull_request_allowances.users = [{ login: "bypass" }];
  assert.match(branchProtectionMismatches(branchPolicy, remote).join(" "), /bypass/);
});
test("exact production environment passes", () => {
  assert.deepEqual(githubEnvironmentMismatches(environmentPolicy, remoteEnvironment), []);
});
test("wrong reviewer identity fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules[1].reviewers[0].reviewer.id = 1;
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /reviewer identities/);
});
test("extra reviewer fails exact comparison", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules[1].reviewers.push({ type: "Team", reviewer: { id: 44, slug: "other" } });
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /reviewer identities/);
});
test("self review mismatch fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules[1].prevent_self_review = false;
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /prevent_self_review/);
});
test("deployment branch widening fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.deployment_branch_policy.protected_branches = false;
  remote.deployment_branch_policy.custom_branch_policies = true;
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /deployment_branch_policy/);
});

test("whitespace status context alias fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.checks[0].context = " compose ";
  assert.match(requiredStatusCheckMismatches(branchPolicy.required_status_checks, remote.required_status_checks).join(" "), /non-exact context/);
});
test("missing empty contexts array fails", () => {
  const remote = structuredClone(remoteBranch);
  delete remote.required_status_checks.contexts;
  assert.match(requiredStatusCheckMismatches(branchPolicy.required_status_checks, remote.required_status_checks).join(" "), /empty contexts/);
});
test("string strict flag fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_status_checks.strict = "true";
  assert.match(branchProtectionMismatches(branchPolicy, remote).join(" "), /strict/);
});
test("string review count fails", () => {
  const remote = structuredClone(remoteBranch);
  remote.required_pull_request_reviews.required_approving_review_count = "2";
  assert.match(branchProtectionMismatches(branchPolicy, remote).join(" "), /invalid type/);
});
test("string reviewer id fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules[1].reviewers[0].reviewer.id = "95946096";
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /non-integer identity/);
});
test("duplicate reviewer identity fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules[1].reviewers.push(structuredClone(remote.protection_rules[1].reviewers[0]));
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /duplicate identities/);
});
test("duplicate reviewer protection rule fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules.push(structuredClone(remote.protection_rules[1]));
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /cardinality/);
});
test("duplicate wait timer protection rule fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules.push(structuredClone(remote.protection_rules[0]));
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /at most once/);
});
test("string wait timer fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules[0].wait_timer = "15";
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /invalid type/);
});
test("string self-review flag fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules[1].prevent_self_review = "true";
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /invalid type/);
});
test("unexpected protection rule fails", () => {
  const remote = structuredClone(remoteEnvironment);
  remote.protection_rules.push({ type: "unreviewed-provider-rule" });
  assert.match(githubEnvironmentMismatches(environmentPolicy, remote).join(" "), /unexpected/);
});
test("invalid tracked branch policy is rejected before PUT", async () => {
  const expected = structuredClone(branchPolicy);
  expected.required_status_checks.checks[0].app_id = "15368";
  const calls = [];
  await assert.rejects(() => applyAndVerifyBranchProtection({
    expected,
    apply: async () => calls.push("PUT"),
    read: async () => remoteBranch,
  }), /invalid app_id/);
  assert.deepEqual(calls, []);
});
test("branch apply requires fresh exact GET before success", async () => {
  const drifted = structuredClone(remoteBranch);
  drifted.required_status_checks.checks[0].app_id = 999;
  const calls = [];
  await assert.rejects(() => applyAndVerifyBranchProtection({
    expected: branchPolicy,
    apply: async () => { calls.push("PUT"); return remoteBranch; },
    read: async () => { calls.push("GET"); return drifted; },
  }), /producer bindings differ/);
  assert.deepEqual(calls, ["PUT", "GET"]);
});
test("environment apply requires fresh exact GET before success", async () => {
  const drifted = structuredClone(remoteEnvironment);
  drifted.protection_rules[1].prevent_self_review = false;
  const calls = [];
  await assert.rejects(() => applyAndVerifyGithubEnvironment({
    expected: environmentPolicy,
    apply: async () => { calls.push("PUT"); return remoteEnvironment; },
    read: async () => { calls.push("GET"); return drifted; },
  }), /prevent_self_review/);
  assert.deepEqual(calls, ["PUT", "GET"]);
});
test("duplicate expected reviewers are rejected before PUT", async () => {
  const expected = structuredClone(environmentPolicy);
  expected.reviewers.push(structuredClone(expected.reviewers[0]));
  const calls = [];
  await assert.rejects(() => applyAndVerifyGithubEnvironment({
    expected,
    apply: async () => calls.push("PUT"),
    read: async () => remoteEnvironment,
  }), /duplicate identities/);
  assert.deepEqual(calls, []);
});
test("duplicate environment names fail collection preflight", () => {
  assert.throws(() => assertValidGithubEnvironmentCollection({
    environments: [environmentPolicy, structuredClone(environmentPolicy)],
  }), /unique/);
});

let passed = 0;
for (const [name, fn] of tests) {
  await fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}
process.stdout.write(`github governance tests passed ${passed}/${passed}\n`);
