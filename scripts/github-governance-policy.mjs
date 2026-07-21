function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function providerBoolean(value) {
  if (typeof value === "boolean") return value;
  if (isObject(value) && typeof value.enabled === "boolean") return value.enabled;
  return null;
}

function exactNonEmptyString(value) {
  return typeof value === "string" && value.length > 0 && value.trim() === value;
}

function sorted(values) {
  return [...values].sort();
}

function sameSorted(left, right) {
  return JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
}

function requiredCheckKey(check) {
  if (!isObject(check) || !exactNonEmptyString(check.context)) return null;
  if (!Number.isInteger(check.app_id) || check.app_id <= 0) return null;
  return `${check.context}\u0000${check.app_id}`;
}

function statusCheckSideIssues(statusChecks, side) {
  const issues = [];
  if (!isObject(statusChecks)) {
    issues.push(`${side} required_status_checks must be an object`);
    return issues;
  }
  if (!Array.isArray(statusChecks.contexts)) {
    issues.push(`${side} required status checks must retain an exact empty contexts array`);
  } else if (statusChecks.contexts.length !== 0) {
    issues.push(`${side} branch protection contains context-only required checks`);
  }
  if (typeof statusChecks.strict !== "boolean") {
    issues.push(`${side} required_status_checks.strict must be a boolean`);
  }
  const checks = statusChecks.checks;
  if (!Array.isArray(checks) || checks.length === 0) {
    issues.push(`${side} must define at least one producer-bound required status check`);
    return issues;
  }
  const keys = checks.map(requiredCheckKey);
  if (keys.some((key) => key === null)) {
    issues.push(`${side} required checks include a non-exact context or missing, null, wildcard or invalid app_id`);
  }
  const validKeys = keys.filter((key) => key !== null);
  if (new Set(validKeys).size !== validKeys.length) {
    issues.push(`${side} required checks contain duplicate context/app_id tuples`);
  }
  const contexts = checks
    .filter((check) => exactNonEmptyString(check?.context))
    .map((check) => check.context);
  if (new Set(contexts).size !== contexts.length) {
    issues.push(`${side} required check contexts must each appear exactly once`);
  }
  return issues;
}

export function requiredStatusCheckMismatches(expectedStatusChecks, remoteStatusChecks) {
  const issues = [
    ...statusCheckSideIssues(expectedStatusChecks, "policy"),
    ...statusCheckSideIssues(remoteStatusChecks, "remote"),
  ];
  const expectedKeys = Array.isArray(expectedStatusChecks?.checks)
    ? expectedStatusChecks.checks.map(requiredCheckKey).filter((key) => key !== null)
    : [];
  const remoteKeys = Array.isArray(remoteStatusChecks?.checks)
    ? remoteStatusChecks.checks.map(requiredCheckKey).filter((key) => key !== null)
    : [];
  if (!sameSorted(expectedKeys, remoteKeys)) {
    issues.push("required status check producer bindings differ");
  }
  return issues;
}

function strictBooleanMismatch(expected, remote, label, issues, { providerShape = false } = {}) {
  if (typeof expected !== "boolean") {
    issues.push(`policy ${label} must be a boolean`);
    return;
  }
  const remoteValue = providerShape ? providerBoolean(remote) : (typeof remote === "boolean" ? remote : null);
  if (remoteValue === null || remoteValue !== expected) issues.push(`${label} differs or has an invalid type`);
}

function allowanceName(entry, key) {
  if (typeof entry === "string") return exactNonEmptyString(entry) ? entry : null;
  if (!isObject(entry)) return null;
  const fields = key === "users" ? ["login"] : key === "teams" ? ["slug"] : ["slug", "name"];
  for (const field of fields) {
    if (exactNonEmptyString(entry[field])) return entry[field];
  }
  return null;
}

function allowanceNames(container, key, side, issues) {
  const values = container?.[key];
  if (!Array.isArray(values)) {
    issues.push(`${side} ${key} bypass allowance must be an array`);
    return [];
  }
  const names = values.map((entry) => allowanceName(entry, key));
  if (names.some((name) => name === null)) issues.push(`${side} ${key} bypass allowance contains an invalid identity`);
  const valid = names.filter((name) => name !== null);
  if (new Set(valid).size !== valid.length) issues.push(`${side} ${key} bypass allowance contains duplicates`);
  return valid;
}

export function branchProtectionMismatches(expected, remote) {
  const issues = [];
  if (!isObject(expected) || !isObject(remote)) return ["policy and remote branch protection must be objects"];
  issues.push(...requiredStatusCheckMismatches(expected.required_status_checks, remote.required_status_checks));
  strictBooleanMismatch(
    expected.required_status_checks?.strict,
    remote.required_status_checks?.strict,
    "required_status_checks.strict",
    issues,
  );
  strictBooleanMismatch(expected.enforce_admins, remote.enforce_admins, "enforce_admins", issues, { providerShape: true });

  const expectedReview = expected.required_pull_request_reviews;
  const remoteReview = remote.required_pull_request_reviews;
  if (!isObject(expectedReview) || !isObject(remoteReview)) {
    issues.push("required_pull_request_reviews must be an object");
  } else {
    for (const key of ["dismiss_stale_reviews", "require_code_owner_reviews", "require_last_push_approval"]) {
      strictBooleanMismatch(expectedReview[key], remoteReview[key], `required_pull_request_reviews.${key}`, issues);
    }
    if (!Number.isInteger(expectedReview.required_approving_review_count) || expectedReview.required_approving_review_count < 0) {
      issues.push("policy required_pull_request_reviews.required_approving_review_count must be a non-negative integer");
    }
    if (!Number.isInteger(remoteReview.required_approving_review_count)
      || remoteReview.required_approving_review_count !== expectedReview.required_approving_review_count) {
      issues.push("required_pull_request_reviews.required_approving_review_count differs or has an invalid type");
    }
    for (const key of ["users", "teams", "apps"]) {
      const expectedNames = allowanceNames(expectedReview.bypass_pull_request_allowances, key, "policy", issues);
      const remoteNames = allowanceNames(remoteReview.bypass_pull_request_allowances, key, "remote", issues);
      if (!sameSorted(expectedNames, remoteNames)) {
        issues.push(`required_pull_request_reviews.bypass_pull_request_allowances.${key} differs`);
      }
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
    strictBooleanMismatch(expected[key], remote[key], key, issues, { providerShape: true });
  }

  if (expected.restrictions === null) {
    if (remote.restrictions !== null) issues.push("restrictions must be exactly null");
  } else if (!isObject(expected.restrictions) || !isObject(remote.restrictions)) {
    issues.push("restrictions must be exact objects or null");
  } else {
    for (const key of ["users", "teams", "apps"]) {
      const expectedNames = allowanceNames(expected.restrictions, key, "policy restriction", issues);
      const remoteNames = allowanceNames(remote.restrictions, key, "remote restriction", issues);
      if (!sameSorted(expectedNames, remoteNames)) issues.push(`restrictions.${key} differs`);
    }
  }
  return issues;
}

function expectedReviewerKey(reviewer) {
  if (!isObject(reviewer) || !["User", "Team"].includes(reviewer.type)) return null;
  return Number.isInteger(reviewer.id) && reviewer.id > 0 ? `${reviewer.type}:${reviewer.id}` : null;
}

function remoteReviewerKey(reviewer) {
  if (!isObject(reviewer) || !["User", "Team"].includes(reviewer.type) || !isObject(reviewer.reviewer)) return null;
  const id = reviewer.reviewer.id;
  return Number.isInteger(id) && id > 0 ? `${reviewer.type}:${id}` : null;
}

function reviewerKeys(reviewers, keyFn, side, issues) {
  if (!Array.isArray(reviewers)) {
    issues.push(`${side} reviewers must be an array`);
    return [];
  }
  const keys = reviewers.map(keyFn);
  if (keys.some((key) => key === null)) issues.push(`${side} reviewers contain an invalid or non-integer identity`);
  const valid = keys.filter((key) => key !== null);
  if (new Set(valid).size !== valid.length) issues.push(`${side} reviewers contain duplicate identities`);
  return valid;
}

export function githubEnvironmentPolicyIssues(expected) {
  const issues = [];
  if (!isObject(expected)) return ["environment policy must be an object"];
  if (!exactNonEmptyString(expected.name) || !/^[A-Za-z0-9_.-]+$/.test(expected.name)) {
    issues.push("environment policy name must be a simple exact string");
  }
  if (!Number.isInteger(expected.wait_timer) || expected.wait_timer < 0 || expected.wait_timer > 43200) {
    issues.push("environment policy wait_timer must be an integer from 0 to 43200");
  }
  if (typeof expected.prevent_self_review !== "boolean") issues.push("environment policy prevent_self_review must be a boolean");
  if (typeof expected.require_reviewers_on_apply !== "boolean") issues.push("environment policy require_reviewers_on_apply must be a boolean");
  const reviewerKeysExpected = reviewerKeys(expected.reviewers, expectedReviewerKey, "policy", issues);
  if (expected.require_reviewers_on_apply === true && reviewerKeysExpected.length === 0) {
    issues.push("policy requires reviewers but defines no exact reviewer identities");
  }
  const branch = expected.deployment_branch_policy;
  if (!isObject(branch)) {
    issues.push("environment policy deployment_branch_policy must be an object");
  } else {
    for (const key of ["protected_branches", "custom_branch_policies"]) {
      if (typeof branch[key] !== "boolean") issues.push(`environment policy deployment_branch_policy.${key} must be a boolean`);
    }
    if (typeof branch.protected_branches === "boolean"
      && typeof branch.custom_branch_policies === "boolean"
      && branch.protected_branches === branch.custom_branch_policies) {
      issues.push("environment policy must choose exactly one branch-policy mode");
    }
  }
  return issues;
}

export function githubEnvironmentMismatches(expected, remote) {
  const issues = [...githubEnvironmentPolicyIssues(expected)];
  if (!isObject(remote)) return [...issues, "remote environment must be an object"];
  const rules = remote.protection_rules;
  if (!Array.isArray(rules)) return [...issues, "remote protection_rules must be an array"];
  const unknownRules = rules.filter((rule) => !isObject(rule) || !["wait_timer", "required_reviewers"].includes(rule.type));
  if (unknownRules.length > 0) issues.push("remote protection_rules contain an unexpected or invalid rule type");

  const waitRules = rules.filter((rule) => rule?.type === "wait_timer");
  if (waitRules.length > 1) issues.push("wait_timer protection rule must appear at most once");
  if (expected.wait_timer > 0 && waitRules.length !== 1) issues.push("wait_timer protection rule is missing or duplicated");
  if (waitRules.length === 1
    && (!Number.isInteger(waitRules[0].wait_timer) || waitRules[0].wait_timer !== expected.wait_timer)) {
    issues.push(`wait_timer differs or has an invalid type: expected ${expected.wait_timer}`);
  }

  const expectedReviewers = reviewerKeys(expected.reviewers, expectedReviewerKey, "policy", issues);
  const reviewerRules = rules.filter((rule) => rule?.type === "required_reviewers");
  const expectedReviewerRuleCount = expectedReviewers.length > 0 ? 1 : 0;
  if (reviewerRules.length !== expectedReviewerRuleCount) {
    issues.push("required_reviewers protection rule cardinality differs");
  }
  if (reviewerRules.length > 0) {
    const reviewerRule = reviewerRules[0];
    const remoteReviewers = reviewerKeys(reviewerRule.reviewers, remoteReviewerKey, "remote", issues);
    if (!sameSorted(expectedReviewers, remoteReviewers)) {
      issues.push(`reviewer identities differ: expected ${sorted(expectedReviewers).join(",") || "none"}, got ${sorted(remoteReviewers).join(",") || "none"}`);
    }
    if (typeof reviewerRule.prevent_self_review !== "boolean"
      || reviewerRule.prevent_self_review !== expected.prevent_self_review) {
      issues.push("prevent_self_review differs or has an invalid type");
    }
  }

  const expectedBranch = expected.deployment_branch_policy;
  const remoteBranch = remote.deployment_branch_policy;
  if (!isObject(remoteBranch)) {
    issues.push("deployment_branch_policy must be an object");
  } else if (isObject(expectedBranch)) {
    for (const key of ["protected_branches", "custom_branch_policies"]) {
      if (typeof remoteBranch[key] !== "boolean" || remoteBranch[key] !== expectedBranch[key]) {
        issues.push(`deployment_branch_policy.${key} differs or has an invalid type`);
      }
    }
  }
  return issues;
}

export function assertExactBranchProtection(expected, remote) {
  const issues = branchProtectionMismatches(expected, remote);
  if (issues.length) throw new Error(`Remote GitHub branch protection does not match exact policy: ${issues.join("; ")}`);
}

export function assertValidGithubEnvironmentPolicy(expected) {
  const issues = githubEnvironmentPolicyIssues(expected);
  if (issues.length) throw new Error(`GitHub environment policy is invalid: ${issues.join("; ")}`);
}

export function assertValidGithubEnvironmentCollection(policy) {
  if (!isObject(policy) || !Array.isArray(policy.environments) || policy.environments.length === 0) {
    throw new Error("GitHub environments policy must define a non-empty environments array");
  }
  const names = policy.environments.map((environment) => environment?.name);
  if (names.some((name) => !exactNonEmptyString(name)) || new Set(names).size !== names.length) {
    throw new Error("GitHub environment names must be exact and unique");
  }
  for (const environment of policy.environments) assertValidGithubEnvironmentPolicy(environment);
}

export function assertExactGithubEnvironment(expected, remote) {
  const issues = githubEnvironmentMismatches(expected, remote);
  if (issues.length) throw new Error(`Remote GitHub environment ${expected.name} does not match exact policy: ${issues.join("; ")}`);
}

export async function applyAndVerifyBranchProtection({ expected, apply, read }) {
  assertExactBranchProtection(expected, expected);
  await apply(expected);
  const remote = await read();
  assertExactBranchProtection(expected, remote);
  return remote;
}

export async function applyAndVerifyGithubEnvironment({ expected, apply, read }) {
  assertValidGithubEnvironmentPolicy(expected);
  await apply(expected);
  const remote = await read();
  assertExactGithubEnvironment(expected, remote);
  return remote;
}
