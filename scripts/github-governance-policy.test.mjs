#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  branchProtectionMismatches,
  githubEnvironmentMismatches,
  requiredStatusCheckMismatches,
} from "./github-governance-policy.mjs";

const branchPolicy = {
  required_status_checks: {
    strict: true,
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

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
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

process.stdout.write(`github governance tests passed ${passed}/${passed}\n`);
