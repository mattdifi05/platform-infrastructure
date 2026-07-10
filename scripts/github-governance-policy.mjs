function enabled(value) {
  if (value && typeof value === "object" && "enabled" in value) {
    return Boolean(value.enabled);
  }
  return Boolean(value);
}

function sortedStrings(values) {
  return [...new Set((values ?? []).map((value) => String(value)))].sort();
}

function sameStrings(left, right) {
  return JSON.stringify(sortedStrings(left)) === JSON.stringify(sortedStrings(right));
}

function reviewerKey(reviewer) {
  const type = String(reviewer?.type ?? "");
  const nested = reviewer?.reviewer ?? reviewer;
  const id = Number(nested?.id);
  return ["User", "Team"].includes(type) && Number.isInteger(id) && id > 0 ? `${type}:${id}` : null;
}

function expectedReviewerKeys(environment) {
  return sortedStrings((environment.reviewers ?? []).map(reviewerKey).filter(Boolean));
}

function remoteReviewerKeys(rule) {
  return sortedStrings((rule?.reviewers ?? []).map(reviewerKey).filter(Boolean));
}

function allowanceNames(value, key) {
  return sortedStrings((value?.[key] ?? []).map((entry) => entry?.login ?? entry?.slug ?? entry?.name ?? entry));
}

export function branchProtectionMismatches(expected, remote) {
  const issues = [];
  const expectedChecks = expected?.required_status_checks?.contexts ?? [];
  const remoteChecks = remote?.required_status_checks?.contexts
    ?? remote?.required_status_checks?.checks?.map((check) => check.context)
    ?? [];
  if (!sameStrings(expectedChecks, remoteChecks)) {
    issues.push(`required status checks differ: expected ${sortedStrings(expectedChecks).join(",")}, got ${sortedStrings(remoteChecks).join(",")}`);
  }
  if (Boolean(remote?.required_status_checks?.strict) !== Boolean(expected?.required_status_checks?.strict)) {
    issues.push("required_status_checks.strict differs");
  }
  if (enabled(remote?.enforce_admins) !== Boolean(expected?.enforce_admins)) {
    issues.push("enforce_admins differs");
  }

  const expectedReview = expected?.required_pull_request_reviews ?? {};
  const remoteReview = remote?.required_pull_request_reviews ?? {};
  for (const key of [
    "dismiss_stale_reviews",
    "require_code_owner_reviews",
    "require_last_push_approval",
  ]) {
    if (Boolean(remoteReview[key]) !== Boolean(expectedReview[key])) {
      issues.push(`required_pull_request_reviews.${key} differs`);
    }
  }
  if (Number(remoteReview.required_approving_review_count ?? 0) !== Number(expectedReview.required_approving_review_count ?? 0)) {
    issues.push("required_pull_request_reviews.required_approving_review_count differs");
  }
  for (const key of ["users", "teams", "apps"]) {
    if (!sameStrings(
      allowanceNames(expectedReview.bypass_pull_request_allowances, key),
      allowanceNames(remoteReview.bypass_pull_request_allowances, key),
    )) {
      issues.push(`required_pull_request_reviews.bypass_pull_request_allowances.${key} differs`);
    }
  }

  for (const key of [
    "required_linear_history",
    "allow_force_pushes",
    "allow_deletions",
    "required_conversation_resolution",
    "block_creations",
    "lock_branch",
    "allow_fork_syncing",
  ]) {
    if (key in expected && enabled(remote?.[key]) !== Boolean(expected[key])) {
      issues.push(`${key} differs`);
    }
  }

  if (expected?.restrictions === null) {
    if (remote?.restrictions !== null && remote?.restrictions !== undefined) {
      issues.push("restrictions must be null");
    }
  } else if (expected?.restrictions) {
    for (const key of ["users", "teams", "apps"]) {
      if (!sameStrings(allowanceNames(expected.restrictions, key), allowanceNames(remote?.restrictions, key))) {
        issues.push(`restrictions.${key} differs`);
      }
    }
  }
  return issues;
}

export function githubEnvironmentMismatches(expected, remote) {
  const issues = [];
  const rules = Array.isArray(remote?.protection_rules) ? remote.protection_rules : [];
  const expectedWait = Number(expected.wait_timer ?? 0);
  const waitRule = rules.find((rule) => rule.type === "wait_timer");
  if (Number(waitRule?.wait_timer ?? 0) !== expectedWait) {
    issues.push(`wait_timer differs: expected ${expectedWait}`);
  }

  const reviewerRule = rules.find((rule) => rule.type === "required_reviewers");
  const expectedReviewers = expectedReviewerKeys(expected);
  const remoteReviewers = remoteReviewerKeys(reviewerRule);
  if (!sameStrings(expectedReviewers, remoteReviewers)) {
    issues.push(`reviewer identities differ: expected ${expectedReviewers.join(",") || "none"}, got ${remoteReviewers.join(",") || "none"}`);
  }
  if (expected.require_reviewers_on_apply && expectedReviewers.length === 0) {
    issues.push("policy requires reviewers but defines no exact reviewer identities");
  }
  if (expectedReviewers.length > 0 && !reviewerRule) {
    issues.push("required_reviewers protection rule is missing");
  }
  if (reviewerRule && Boolean(reviewerRule.prevent_self_review) !== Boolean(expected.prevent_self_review)) {
    issues.push("prevent_self_review differs");
  }

  const expectedBranch = expected.deployment_branch_policy;
  const remoteBranch = remote?.deployment_branch_policy;
  if (expectedBranch) {
    for (const key of ["protected_branches", "custom_branch_policies"]) {
      if (Boolean(remoteBranch?.[key]) !== Boolean(expectedBranch[key])) {
        issues.push(`deployment_branch_policy.${key} differs`);
      }
    }
  } else if (remoteBranch !== null && remoteBranch !== undefined) {
    issues.push("deployment_branch_policy must be null");
  }
  return issues;
}

export function assertExactBranchProtection(expected, remote) {
  const issues = branchProtectionMismatches(expected, remote);
  if (issues.length) {
    throw new Error(`Remote GitHub branch protection does not match exact policy: ${issues.join("; ")}`);
  }
}

export function assertExactGithubEnvironment(expected, remote) {
  const issues = githubEnvironmentMismatches(expected, remote);
  if (issues.length) {
    throw new Error(`Remote GitHub environment ${expected.name} does not match exact policy: ${issues.join("; ")}`);
  }
}
