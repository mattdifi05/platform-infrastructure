#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";

const RESULT_SCHEMA = "platform.governance-documentation-closure-result/v1";
const LOCAL_STATUS = "LOCAL-SUPPORT-READY-EXTERNAL-PENDING";
const EXTERNAL_STATE = "GOVERNANCE-EXTERNAL";
const SYNTHETIC_STATE = "SYNTHETIC-TEST";
const CANONICAL_OWNERSHIP_PATH = "governance/service-asset-ownership.json";
const CANONICAL_RUNBOOKS_PATH = "governance/runbook-catalog.json";

const REQUIRED_DOMAINS = Object.freeze([
  "hardware",
  "network",
  "applications",
  "data",
  "backups",
  "secrets",
  "observability",
  "ci",
  "providers",
]);

const REQUIRED_CAPABILITIES = Object.freeze([
  "host-capacity",
  "host-recovery",
  "network-segmentation",
  "edge-routing",
  "platform-service-lifecycle",
  "hosted-workload-boundary",
  "database-storage",
  "object-storage",
  "backup",
  "restore",
  "secret-lifecycle",
  "key-recovery",
  "metrics",
  "logs",
  "alerting",
  "source-governance",
  "release-provenance",
  "dns-edge-provider",
  "identity-provider",
  "notification-provider",
]);

const REQUIRED_RUNBOOK_TYPES = Object.freeze([
  "operations",
  "incident",
  "provider",
  "rollout",
  "rollback",
  "backup",
  "restore",
  "access-recovery",
]);

const REQUIRED_DRILL_TYPES = Object.freeze([
  "rollout",
  "rollback",
  "backup",
  "restore",
  "access-recovery",
]);

const RESPONSIBILITIES = Object.freeze([
  "closure",
  "rollback",
  "preservation",
  "review",
]);

const ROLE_KEYS = Object.freeze(["primary", "substitute", "approval", "escalation"]);
const CANONICAL_ROLE_BY_KEY = Object.freeze({
  primary: "role:platform-governance-primary",
  substitute: "role:platform-governance-substitute",
  approval: "role:release-approval-authority",
  escalation: "role:incident-escalation-authority",
});
const CANONICAL_ROLE_IDS = Object.freeze(Object.values(CANONICAL_ROLE_BY_KEY));
const OWNERSHIP_EXTERNAL_CONDITIONS = Object.freeze([
  "Authenticated primary and substitute acknowledgements for every catalog asset remain GOVERNANCE-EXTERNAL and GO-blocking.",
]);
const RUNBOOK_EXTERNAL_CONDITIONS = Object.freeze([
  "Independent authenticated drills for rollout, rollback, backup, restore, and access-recovery remain GOVERNANCE-EXTERNAL and GO-blocking.",
]);
const PLACEHOLDER_PATTERN = /(?:^|[^a-z0-9])(?:todo|tbd|placeholder|unknown|unassigned|someone|fixme|n\/a)(?:$|[^a-z0-9])/i;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const SUBJECT_PATTERN = /^(?:provider|oidc|webauthn|test)-subject-sha256:[a-f0-9]{64}$/;
const RECEIPT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{7,127}$/;

class GovernanceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "GovernanceError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new GovernanceError(code, message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected, label) {
  if (!isObject(value)) fail("INVALID_OBJECT", `${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("UNEXPECTED_FIELDS", `${label} fields must be exactly: ${wanted.join(", ")}.`);
  }
}

function nonPlaceholderString(value, label, minimumLength = 1) {
  if (typeof value !== "string" || value.length < minimumLength || value.trim() !== value) {
    fail("INVALID_STRING", `${label} must be a non-empty canonical string.`);
  }
  if (PLACEHOLDER_PATTERN.test(value)) fail("PLACEHOLDER_REJECTED", `${label} contains a placeholder.`);
  return value;
}

function exactSet(actual, expected, label) {
  if (!Array.isArray(actual)) fail("INVALID_SET", `${label} must be an array.`);
  if (actual.some((value) => typeof value !== "string")) fail("INVALID_SET", `${label} contains a non-string value.`);
  const unique = new Set(actual);
  if (unique.size !== actual.length) fail("DUPLICATE_VALUE", `${label} contains duplicate values.`);
  const wanted = new Set(expected);
  if (unique.size !== wanted.size || [...unique].some((value) => !wanted.has(value))) {
    fail("COVERAGE_NOT_CLOSED", `${label} must exactly match the closed required set.`);
  }
}

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

function gitText(root, args, label) {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  if (result.status !== 0) fail("GIT_STATE_UNAVAILABLE", `${label} could not be read from Git.`);
  return result.stdout.trim();
}

function gitBytes(root, args, label) {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding: null,
    env: { PATH: process.env.PATH },
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) fail("GIT_STATE_UNAVAILABLE", `${label} could not be read from Git.`);
  return result.stdout;
}

function canonicalRelativePath(value, label) {
  nonPlaceholderString(value, label);
  if (value.includes("\\") || value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    fail("INVALID_PATH", `${label} contains a forbidden character.`);
  }
  if (path.posix.isAbsolute(value) || path.posix.normalize(value) !== value || value.startsWith("../") || value === "..") {
    fail("INVALID_PATH", `${label} must be a canonical repository-relative path.`);
  }
  return value;
}

function repositoryRoot(value) {
  const resolved = realpathSync(value);
  if (!statSync(resolved).isDirectory()) fail("INVALID_ROOT", "Repository root must be a directory.");
  const git = spawnSync("git", ["-C", resolved, "rev-parse", "--show-toplevel"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  if (git.status !== 0 || realpathSync(git.stdout.trim()) !== resolved) {
    fail("INVALID_ROOT", "Root must be the exact top level of a Git worktree.");
  }
  return resolved;
}

function repositoryContext(root) {
  const commit = gitText(root, ["rev-parse", "--verify", "HEAD^{commit}"], "Current repository commit");
  const tree = gitText(root, ["rev-parse", "--verify", "HEAD^{tree}"], "Current repository tree");
  if (!/^[a-f0-9]{40,64}$/.test(commit) || !/^[a-f0-9]{40,64}$/.test(tree)) {
    fail("INVALID_GIT_IDENTITY", "Current repository commit and tree must be exact hexadecimal object ids.");
  }
  return {
    root,
    commit,
    tree,
    authoritativePaths: new Map(),
  };
}

function assertRepositoryIdentity(context) {
  const commit = gitText(context.root, ["rev-parse", "--verify", "HEAD^{commit}"], "Current repository commit");
  const tree = gitText(context.root, ["rev-parse", "--verify", "HEAD^{tree}"], "Current repository tree");
  if (commit !== context.commit || tree !== context.tree) {
    fail("REPOSITORY_IDENTITY_CHANGED", "Repository commit or tree changed during governance validation.");
  }
}

function resolveRegularFile(root, relative, label, { tracked = true } = {}) {
  const safeRelative = canonicalRelativePath(relative, label);
  const resolved = path.resolve(root, ...safeRelative.split("/"));
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    fail("PATH_ESCAPE", `${label} escapes the repository root.`);
  }

  let cursor = root;
  for (const segment of safeRelative.split("/")) {
    cursor = path.join(cursor, segment);
    const stat = lstatSync(cursor);
    if (stat.isSymbolicLink()) fail("SYMLINK_REJECTED", `${label} must not traverse a symlink.`);
  }
  if (!lstatSync(resolved).isFile()) fail("NOT_REGULAR_FILE", `${label} must name a regular file.`);
  if (realpathSync(resolved) !== resolved) fail("PATH_ALIAS_REJECTED", `${label} must resolve to its exact path.`);

  if (tracked) {
    const result = spawnSync("git", ["-C", root, "ls-files", "--error-unmatch", "--", safeRelative], {
      encoding: "utf8",
      env: { PATH: process.env.PATH },
    });
    if (result.status !== 0) fail("UNTRACKED_ARTIFACT", `${label} must name a tracked file.`);
  }
  return resolved;
}

function resolveDirectory(root, relative, label) {
  const safeRelative = canonicalRelativePath(relative, label);
  const resolved = path.resolve(root, ...safeRelative.split("/"));
  if (resolved === root || !resolved.startsWith(`${root}${path.sep}`)) {
    fail("PATH_ESCAPE", `${label} must name a repository subdirectory.`);
  }

  let cursor = root;
  for (const segment of safeRelative.split("/")) {
    cursor = path.join(cursor, segment);
    let stat;
    try {
      stat = lstatSync(cursor);
    } catch {
      fail("MISSING_DIRECTORY", `${label} does not exist.`);
    }
    if (stat.isSymbolicLink()) fail("SYMLINK_REJECTED", `${label} must not traverse a symlink.`);
  }
  if (!lstatSync(resolved).isDirectory() || realpathSync(resolved) !== resolved) {
    fail("INVALID_RECEIPT_DIRECTORY", `${label} must be an exact real directory.`);
  }
  return resolved;
}

function resolveUntrackedRegularFile(root, relative, label) {
  const file = resolveRegularFile(root, relative, label, { tracked: false });
  const safeRelative = path.relative(root, file).split(path.sep).join("/");
  const result = spawnSync("git", ["-C", root, "ls-files", "--error-unmatch", "--", safeRelative], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  if (result.status === 0) fail("TRACKED_RECEIPT_REJECTED", `${label} must be external untracked evidence.`);
  return file;
}

function readAuthoritativeFile(context, relative, label) {
  const safeRelative = canonicalRelativePath(relative, label);
  const file = resolveRegularFile(context.root, safeRelative, label);
  const dirty = spawnSync("git", ["-C", context.root, "diff", "--quiet", "HEAD", "--", safeRelative], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  if (dirty.status !== 0) {
    fail("DIRTY_AUTHORITATIVE_PATH", `${label} must be unchanged from HEAD in both the index and worktree.`);
  }
  const headBytes = gitBytes(context.root, ["show", `HEAD:${safeRelative}`], `${label} HEAD bytes`);
  const indexBytes = gitBytes(context.root, ["show", `:${safeRelative}`], `${label} index bytes`);
  const worktreeBytes = readFileSync(file);
  if (!headBytes.equals(indexBytes) || !headBytes.equals(worktreeBytes)) {
    fail("AUTHORITATIVE_BYTES_MISMATCH", `${label} must be byte-identical in HEAD, the index, and the worktree.`);
  }
  const digest = sha256(worktreeBytes);
  const existing = context.authoritativePaths.get(safeRelative);
  if (existing && existing !== digest) {
    fail("AUTHORITATIVE_BYTES_CHANGED", `${label} changed during governance validation.`);
  }
  context.authoritativePaths.set(safeRelative, digest);
  return { file, contents: worktreeBytes, relative: safeRelative, sha256: digest };
}

function readJsonFile(context, relative, label) {
  const authoritative = readAuthoritativeFile(context, relative, label);
  let value;
  try {
    value = JSON.parse(authoritative.contents.toString("utf8"));
  } catch {
    fail("INVALID_JSON", `${label} must contain valid JSON.`);
  }
  return { ...authoritative, value };
}

function validateArtifact(context, artifact, label) {
  exactKeys(artifact, ["path", "sha256", "anchors"], label);
  if (!HASH_PATTERN.test(artifact.sha256)) fail("INVALID_HASH", `${label}.sha256 must be a lowercase SHA-256 digest.`);
  if (!Array.isArray(artifact.anchors) || artifact.anchors.length === 0) {
    fail("MISSING_ANCHOR", `${label}.anchors must contain at least one exact anchor.`);
  }
  const authoritative = readAuthoritativeFile(context, artifact.path, `${label}.path`);
  const contents = authoritative.contents;
  if (authoritative.sha256 !== artifact.sha256) fail("HASH_MISMATCH", `${label} hash does not match the tracked regular file.`);
  const text = contents.toString("utf8");
  const seen = new Set();
  for (const [index, anchor] of artifact.anchors.entries()) {
    nonPlaceholderString(anchor, `${label}.anchors[${index}]`, 4);
    if (anchor.includes("\n") || anchor.includes("\r")) fail("INVALID_ANCHOR", `${label} anchors must be single exact lines or tokens.`);
    if (seen.has(anchor)) fail("DUPLICATE_ANCHOR", `${label} contains duplicate anchors.`);
    seen.add(anchor);
    const first = text.indexOf(anchor);
    if (first === -1 || text.indexOf(anchor, first + anchor.length) !== -1) {
      fail("ANCHOR_MISMATCH", `${label} anchor must occur exactly once in the bound artifact.`);
    }
  }
  return { ...artifact };
}

function validateRoleRef(value, label) {
  if (typeof value !== "string" || !CANONICAL_ROLE_IDS.includes(value)) {
    fail("NON_CANONICAL_ROLE", `${label} must be one of the four closed canonical accountability role ids.`);
  }
  return value;
}

function validateRoleAssignments(value, roles, label) {
  exactKeys(value, ROLE_KEYS, label);
  for (const key of ROLE_KEYS) {
    validateRoleRef(value[key], `${label}.${key}`);
    if (value[key] !== CANONICAL_ROLE_BY_KEY[key]) {
      fail("NON_CANONICAL_ROLE_ASSIGNMENT", `${label}.${key} must use its exact canonical accountability role id.`);
    }
    if (!roles.has(value[key])) fail("UNKNOWN_ROLE", `${label}.${key} is not declared in the ownership role catalog.`);
  }
  if (new Set(ROLE_KEYS.map((key) => value[key])).size !== ROLE_KEYS.length) {
    fail("ROLE_SEPARATION_REQUIRED", `${label} primary, substitute, approval, and escalation roles must differ.`);
  }
}

function validateReview(value, label) {
  exactKeys(value, ["cadenceDays", "beforeRollout", "afterMaterialChange"], label);
  if (!Number.isSafeInteger(value.cadenceDays) || value.cadenceDays < 1 || value.cadenceDays > 365) {
    fail("INVALID_REVIEW_CADENCE", `${label}.cadenceDays must be between 1 and 365.`);
  }
  if (value.beforeRollout !== true || value.afterMaterialChange !== true) {
    fail("INCOMPLETE_REVIEW", `${label} must require review before rollout and after material change.`);
  }
}

function validateOwnership(context, manifest) {
  exactKeys(manifest, [
    "schema",
    "scope",
    "status",
    "gateAdmissible",
    "requiredDomains",
    "requiredCapabilities",
    "roles",
    "assets",
    "externalConditions",
  ], "ownership catalog");
  if (manifest.schema !== "platform.service-asset-ownership/v1") fail("INVALID_SCHEMA", "Ownership catalog schema is unsupported.");
  if (manifest.scope !== "platform-infrastructure") fail("INVALID_SCOPE", "Ownership catalog scope must be platform-infrastructure.");
  if (manifest.status !== LOCAL_STATUS || manifest.gateAdmissible !== false) {
    fail("FALSE_CLOSURE_CLAIM", `Ownership catalog must remain ${LOCAL_STATUS} and non-gate-admissible.`);
  }
  exactSet(manifest.requiredDomains, REQUIRED_DOMAINS, "ownership requiredDomains");
  exactSet(manifest.requiredCapabilities, REQUIRED_CAPABILITIES, "ownership requiredCapabilities");
  exactSet(manifest.externalConditions, OWNERSHIP_EXTERNAL_CONDITIONS, "ownership externalConditions");
  if (!Array.isArray(manifest.roles) || manifest.roles.length !== CANONICAL_ROLE_IDS.length) {
    fail("NON_CANONICAL_ROLE", "Ownership catalog must declare exactly the four closed canonical accountability roles.");
  }
  const roles = new Map();
  for (const [index, role] of manifest.roles.entries()) {
    const label = `ownership roles[${index}]`;
    exactKeys(role, ["id", "kind", "runtimePrincipalAllowed", "identityBinding"], label);
    validateRoleRef(role.id, `${label}.id`);
    if (roles.has(role.id)) fail("DUPLICATE_ROLE", `${label}.id is duplicated.`);
    if (role.kind !== "human-accountability-role" || role.runtimePrincipalAllowed !== false) {
      fail("RUNTIME_IDENTITY_REJECTED", `${label} must be a human accountability role and must deny runtime principals.`);
    }
    exactKeys(role.identityBinding, ["state", "authenticatedReceiptRequired"], `${label}.identityBinding`);
    if (role.identityBinding.state !== EXTERNAL_STATE || role.identityBinding.authenticatedReceiptRequired !== true) {
      fail("FALSE_ACKNOWLEDGEMENT_CLAIM", `${label} must require an authenticated external identity binding.`);
    }
    roles.set(role.id, role);
  }
  exactSet([...roles.keys()], CANONICAL_ROLE_IDS, "ownership canonical role ids");

  if (!Array.isArray(manifest.assets) || manifest.assets.length === 0) fail("MISSING_ASSETS", "Ownership catalog must contain assets.");
  const assetIds = new Set();
  const domains = [];
  const capabilities = [];
  for (const [index, asset] of manifest.assets.entries()) {
    const label = `ownership assets[${index}]`;
    exactKeys(asset, ["id", "domain", "capabilities", "artifactRefs", "roles", "acknowledgement", "lifecycle"], label);
    if (typeof asset.id !== "string" || !/^asset:[a-z][a-z0-9-]{1,79}$/.test(asset.id) || PLACEHOLDER_PATTERN.test(asset.id)) {
      fail("INVALID_ASSET_ID", `${label}.id must be canonical and non-placeholder.`);
    }
    if (assetIds.has(asset.id)) fail("DUPLICATE_ASSET", `${label}.id is duplicated.`);
    assetIds.add(asset.id);
    if (!REQUIRED_DOMAINS.includes(asset.domain)) fail("UNKNOWN_DOMAIN", `${label}.domain is outside the closed domain set.`);
    domains.push(asset.domain);
    if (!Array.isArray(asset.capabilities) || asset.capabilities.length === 0) fail("MISSING_CAPABILITY", `${label} has no capabilities.`);
    for (const capability of asset.capabilities) {
      if (!REQUIRED_CAPABILITIES.includes(capability)) fail("UNKNOWN_CAPABILITY", `${label} has an unknown capability.`);
      capabilities.push(capability);
    }
    if (!Array.isArray(asset.artifactRefs) || asset.artifactRefs.length === 0) fail("MISSING_ARTIFACT", `${label} must bind tracked artifacts.`);
    asset.artifactRefs.forEach((artifact, artifactIndex) => validateArtifact(context, artifact, `${label}.artifactRefs[${artifactIndex}]`));
    validateRoleAssignments(asset.roles, roles, `${label}.roles`);
    exactKeys(asset.acknowledgement, ["state", "authenticatedReceiptRequired"], `${label}.acknowledgement`);
    if (asset.acknowledgement.state !== EXTERNAL_STATE || asset.acknowledgement.authenticatedReceiptRequired !== true) {
      fail("FALSE_ACKNOWLEDGEMENT_CLAIM", `${label} must retain authenticated external acknowledgement.`);
    }
    exactKeys(asset.lifecycle, ["preserve", "rollback", "review"], `${label}.lifecycle`);
    nonPlaceholderString(asset.lifecycle.preserve, `${label}.lifecycle.preserve`, 24);
    nonPlaceholderString(asset.lifecycle.rollback, `${label}.lifecycle.rollback`, 24);
    validateReview(asset.lifecycle.review, `${label}.lifecycle.review`);
  }
  exactSet(domains, REQUIRED_DOMAINS, "ownership asset domain coverage");
  exactSet(capabilities, REQUIRED_CAPABILITIES, "ownership asset capability coverage");
  return { roles, assetIds, manifest };
}

function validateRunbooks(context, manifest, roles) {
  exactKeys(manifest, [
    "schema",
    "scope",
    "status",
    "gateAdmissible",
    "requiredTypes",
    "requiredIndependentDrillTypes",
    "runbooks",
    "externalConditions",
  ], "runbook catalog");
  if (manifest.schema !== "platform.runbook-catalog/v1") fail("INVALID_SCHEMA", "Runbook catalog schema is unsupported.");
  if (manifest.scope !== "platform-infrastructure") fail("INVALID_SCOPE", "Runbook catalog scope must be platform-infrastructure.");
  if (manifest.status !== LOCAL_STATUS || manifest.gateAdmissible !== false) {
    fail("FALSE_CLOSURE_CLAIM", `Runbook catalog must remain ${LOCAL_STATUS} and non-gate-admissible.`);
  }
  exactSet(manifest.requiredTypes, REQUIRED_RUNBOOK_TYPES, "runbook requiredTypes");
  exactSet(manifest.requiredIndependentDrillTypes, REQUIRED_DRILL_TYPES, "runbook requiredIndependentDrillTypes");
  exactSet(manifest.externalConditions, RUNBOOK_EXTERNAL_CONDITIONS, "runbook externalConditions");
  if (!Array.isArray(manifest.runbooks)) fail("MISSING_RUNBOOKS", "Runbook catalog must contain runbooks.");
  const ids = new Set();
  const types = [];
  const byId = new Map();
  for (const [index, runbook] of manifest.runbooks.entries()) {
    const label = `runbook entries[${index}]`;
    exactKeys(runbook, [
      "id",
      "type",
      "artifact",
      "roles",
      "preservationRequired",
      "rollbackRequired",
      "review",
      "drill",
    ], label);
    if (!REQUIRED_RUNBOOK_TYPES.includes(runbook.type) || runbook.id !== `runbook:${runbook.type}`) {
      fail("INVALID_RUNBOOK_ID", `${label} must use the exact closed runbook type and matching id.`);
    }
    if (ids.has(runbook.id)) fail("DUPLICATE_RUNBOOK", `${label}.id is duplicated.`);
    ids.add(runbook.id);
    types.push(runbook.type);
    validateArtifact(context, runbook.artifact, `${label}.artifact`);
    validateRoleAssignments(runbook.roles, roles, `${label}.roles`);
    if (runbook.preservationRequired !== true || runbook.rollbackRequired !== true) {
      fail("INCOMPLETE_RUNBOOK_SAFETY", `${label} must require preservation and rollback.`);
    }
    validateReview(runbook.review, `${label}.review`);
    exactKeys(runbook.drill, ["state", "independentOperatorRequired", "exactArtifactBindingRequired"], `${label}.drill`);
    if (runbook.drill.state !== EXTERNAL_STATE || runbook.drill.independentOperatorRequired !== true || runbook.drill.exactArtifactBindingRequired !== true) {
      fail("INCOMPLETE_DRILL_BOUNDARY", `${label} must require an independent external drill against the exact artifact.`);
    }
    byId.set(runbook.id, runbook);
  }
  exactSet(types, REQUIRED_RUNBOOK_TYPES, "runbook type coverage");
  return { byId, manifest };
}

function parseTime(value, label) {
  nonPlaceholderString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) fail("INVALID_TIME", `${label} must be an RFC 3339 UTC timestamp.`);
  const time = Date.parse(value);
  if (!Number.isFinite(time)) fail("INVALID_TIME", `${label} is not a valid timestamp.`);
  return time;
}

function validateAuthentication(value, evidenceClass, label) {
  exactKeys(value, ["method", "issuerRef", "evidenceSha256"], label);
  if (!HASH_PATTERN.test(value.evidenceSha256)) fail("INVALID_HASH", `${label}.evidenceSha256 must be a lowercase SHA-256 digest.`);
  nonPlaceholderString(value.issuerRef, `${label}.issuerRef`, 4);
  if (evidenceClass === SYNTHETIC_STATE) {
    if (value.method !== "synthetic") fail("INVALID_SYNTHETIC_AUTH", `${label}.method must be synthetic for a synthetic receipt.`);
  } else if (!new Set(["provider-signed", "oidc-mfa", "webauthn"]).has(value.method)) {
    fail("UNAUTHENTICATED_RECEIPT", `${label}.method is not an accepted authenticated external method.`);
  }
}

function validateReceiptClass(receipt, label) {
  if (![SYNTHETIC_STATE, EXTERNAL_STATE].includes(receipt.evidenceClass)) fail("INVALID_EVIDENCE_CLASS", `${label}.evidenceClass is unsupported.`);
  const synthetic = receipt.evidenceClass === SYNTHETIC_STATE;
  if (receipt.synthetic !== synthetic || receipt.gateAdmissible !== false) {
    fail("FALSE_GATE_CLAIM", `${label} must remain non-gate-admissible until an independent trusted verifier authenticates it.`);
  }
  return synthetic;
}

function validateCatalogBinding(value, expected, label) {
  exactKeys(value, ["path", "sha256"], label);
  if (!HASH_PATTERN.test(value.sha256)) fail("INVALID_HASH", `${label}.sha256 must be a lowercase SHA-256 digest.`);
  canonicalRelativePath(value.path, `${label}.path`);
  if (value.path !== expected.path || value.sha256 !== expected.sha256) {
    fail("CATALOG_BINDING_MISMATCH", `${label} must match the exact canonical catalog path and SHA-256 passed to the validator.`);
  }
}

function validateSubject(value, evidenceClass, label) {
  if (typeof value !== "string" || !SUBJECT_PATTERN.test(value)) fail("INVALID_SUBJECT_REF", `${label} must be an authenticated subject digest reference.`);
  if (evidenceClass === EXTERNAL_STATE && value.startsWith("test-")) fail("SYNTHETIC_IDENTITY_REJECTED", `${label} cannot use a test identity in external evidence.`);
}

function validateAcceptanceReceipt(catalogs, receipt) {
  exactKeys(receipt, [
    "schema",
    "receiptId",
    "evidenceClass",
    "synthetic",
    "gateAdmissible",
    "scope",
    "catalog",
    "issuedAt",
    "acknowledgements",
    "approval",
  ], "acceptance receipt");
  if (receipt.schema !== "platform.governance-acceptance-receipt/v1") fail("INVALID_SCHEMA", "Acceptance receipt schema is unsupported.");
  if (!RECEIPT_ID_PATTERN.test(receipt.receiptId) || PLACEHOLDER_PATTERN.test(receipt.receiptId)) fail("INVALID_RECEIPT_ID", "Acceptance receipt id is invalid.");
  if (receipt.scope !== "platform-infrastructure") fail("INVALID_SCOPE", "Acceptance receipt scope must be platform-infrastructure.");
  const synthetic = validateReceiptClass(receipt, "acceptance receipt");
  const issuedAt = parseTime(receipt.issuedAt, "acceptance receipt.issuedAt");
  validateCatalogBinding(receipt.catalog, catalogs.ownershipBinding, "acceptance receipt.catalog");
  const ownershipManifest = catalogs.ownership.manifest;
  const ownership = catalogs.ownership;
  if (!Array.isArray(receipt.acknowledgements)) fail("MISSING_ACKNOWLEDGEMENTS", "Acceptance receipt must contain acknowledgements.");
  const expectedPairs = new Set();
  for (const asset of ownershipManifest.assets) {
    expectedPairs.add(`${asset.id}\0${asset.roles.primary}`);
    expectedPairs.add(`${asset.id}\0${asset.roles.substitute}`);
  }
  const actualPairs = new Set();
  const subjectsByAsset = new Map();
  const subjectByRole = new Map();
  const roleBySubject = new Map();
  let latestAcknowledgement = Number.NEGATIVE_INFINITY;
  for (const [index, acknowledgement] of receipt.acknowledgements.entries()) {
    const label = `acceptance acknowledgements[${index}]`;
    exactKeys(acknowledgement, [
      "assetId",
      "roleRef",
      "authenticatedSubjectRef",
      "authentication",
      "responsibilities",
      "acknowledgedAt",
    ], label);
    if (!ownership.assetIds.has(acknowledgement.assetId)) fail("UNKNOWN_ASSET", `${label}.assetId is not in the bound catalog.`);
    validateRoleRef(acknowledgement.roleRef, `${label}.roleRef`);
    const pair = `${acknowledgement.assetId}\0${acknowledgement.roleRef}`;
    if (!expectedPairs.has(pair)) fail("WRONG_ACKNOWLEDGEMENT_ROLE", `${label} is not the primary or substitute role for the asset.`);
    if (actualPairs.has(pair)) fail("DUPLICATE_ACKNOWLEDGEMENT", `${label} duplicates an asset/role acknowledgement.`);
    actualPairs.add(pair);
    validateSubject(acknowledgement.authenticatedSubjectRef, receipt.evidenceClass, `${label}.authenticatedSubjectRef`);
    validateAuthentication(acknowledgement.authentication, receipt.evidenceClass, `${label}.authentication`);
    exactSet(acknowledgement.responsibilities, RESPONSIBILITIES, `${label}.responsibilities`);
    const acknowledgedAt = parseTime(acknowledgement.acknowledgedAt, `${label}.acknowledgedAt`);
    if (acknowledgedAt > issuedAt) fail("INVALID_RECEIPT_ORDER", `${label}.acknowledgedAt cannot postdate receipt issuance.`);
    latestAcknowledgement = Math.max(latestAcknowledgement, acknowledgedAt);
    const existingSubject = subjectByRole.get(acknowledgement.roleRef);
    if (existingSubject && existingSubject !== acknowledgement.authenticatedSubjectRef) {
      fail("ROLE_SUBJECT_MISMATCH", `${label}.roleRef must bind one consistent authenticated subject.`);
    }
    const existingRole = roleBySubject.get(acknowledgement.authenticatedSubjectRef);
    if (existingRole && existingRole !== acknowledgement.roleRef) {
      fail("ROLE_SUBJECT_COLLISION", `${label}.authenticatedSubjectRef cannot satisfy multiple accountability roles.`);
    }
    subjectByRole.set(acknowledgement.roleRef, acknowledgement.authenticatedSubjectRef);
    roleBySubject.set(acknowledgement.authenticatedSubjectRef, acknowledgement.roleRef);
    if (!subjectsByAsset.has(acknowledgement.assetId)) subjectsByAsset.set(acknowledgement.assetId, new Set());
    subjectsByAsset.get(acknowledgement.assetId).add(acknowledgement.authenticatedSubjectRef);
  }
  exactSet([...actualPairs], [...expectedPairs], "acceptance acknowledgement coverage");
  for (const [assetId, subjects] of subjectsByAsset) {
    if (subjects.size !== 2) fail("NO_SUBSTITUTE_SEPARATION", `Acceptance subjects for ${assetId} must be distinct.`);
  }
  exactKeys(receipt.approval, ["roleRef", "authenticatedSubjectRef", "authentication", "approvedAt"], "acceptance approval");
  validateRoleRef(receipt.approval.roleRef, "acceptance approval.roleRef");
  if (!ownership.roles.has(receipt.approval.roleRef) || !ownershipManifest.assets.every((asset) => asset.roles.approval === receipt.approval.roleRef)) {
    fail("WRONG_APPROVAL_ROLE", "Acceptance approval role must match every asset approval role in the closed catalog.");
  }
  validateSubject(receipt.approval.authenticatedSubjectRef, receipt.evidenceClass, "acceptance approval.authenticatedSubjectRef");
  validateAuthentication(receipt.approval.authentication, receipt.evidenceClass, "acceptance approval.authentication");
  const approvedAt = parseTime(receipt.approval.approvedAt, "acceptance approval.approvedAt");
  if (approvedAt < latestAcknowledgement || approvedAt > issuedAt) {
    fail("INVALID_RECEIPT_ORDER", "Acceptance approval must follow every acknowledgement and cannot postdate receipt issuance.");
  }
  if (roleBySubject.has(receipt.approval.authenticatedSubjectRef)) {
    fail("ROLE_SUBJECT_COLLISION", "Acceptance approval subject must be distinct from primary and substitute subjects.");
  }
  return {
    synthetic,
    receipt,
    ownership,
    primarySubjectsByRole: new Map(ownershipManifest.assets.map((asset) => {
      const matching = receipt.acknowledgements.filter((entry) => entry.assetId === asset.id && entry.roleRef === asset.roles.primary);
      return [asset.roles.primary, new Set(matching.map((entry) => entry.authenticatedSubjectRef))];
    })),
  };
}

function sameArtifact(left, right) {
  return left.path === right.path && left.sha256 === right.sha256 &&
    Array.isArray(left.anchors) && Array.isArray(right.anchors) &&
    left.anchors.length === right.anchors.length && left.anchors.every((anchor, index) => anchor === right.anchors[index]);
}

function validateDrillReceipt(catalogs, receipt) {
  exactKeys(receipt, [
    "schema",
    "receiptId",
    "evidenceClass",
    "synthetic",
    "gateAdmissible",
    "scope",
    "runbookId",
    "runbookType",
    "catalog",
    "artifact",
    "performedAt",
    "independentOperator",
    "result",
    "preservationVerified",
    "rollbackVerified",
    "evidenceSha256",
  ], "drill receipt");
  if (receipt.schema !== "platform.runbook-drill-receipt/v1") fail("INVALID_SCHEMA", "Drill receipt schema is unsupported.");
  if (!RECEIPT_ID_PATTERN.test(receipt.receiptId) || PLACEHOLDER_PATTERN.test(receipt.receiptId)) fail("INVALID_RECEIPT_ID", "Drill receipt id is invalid.");
  if (receipt.scope !== "platform-infrastructure") fail("INVALID_SCOPE", "Drill receipt scope must be platform-infrastructure.");
  const synthetic = validateReceiptClass(receipt, "drill receipt");
  parseTime(receipt.performedAt, "drill receipt.performedAt");
  validateCatalogBinding(receipt.catalog, catalogs.runbooksBinding, "drill receipt.catalog");
  const catalog = catalogs.runbooks;
  const runbook = catalog.byId.get(receipt.runbookId);
  if (!runbook || runbook.type !== receipt.runbookType) fail("UNKNOWN_RUNBOOK", "Drill receipt does not match an exact catalog runbook id and type.");
  validateArtifact(catalogs.context, receipt.artifact, "drill receipt.artifact");
  if (!sameArtifact(receipt.artifact, runbook.artifact)) fail("ARTIFACT_BINDING_MISMATCH", "Drill receipt artifact does not exactly match the runbook catalog binding.");
  exactKeys(receipt.independentOperator, ["authenticatedSubjectRef", "authentication", "independentFromPrimary"], "drill receipt.independentOperator");
  validateSubject(receipt.independentOperator.authenticatedSubjectRef, receipt.evidenceClass, "drill receipt.independentOperator.authenticatedSubjectRef");
  validateAuthentication(receipt.independentOperator.authentication, receipt.evidenceClass, "drill receipt.independentOperator.authentication");
  if (receipt.independentOperator.independentFromPrimary !== true) fail("DRILL_NOT_INDEPENDENT", "Drill receipt must attest operator independence from the primary role.");
  if (receipt.result !== "PASS" || receipt.preservationVerified !== true || receipt.rollbackVerified !== true) {
    fail("DRILL_NOT_PASSED", "Drill receipt must pass preservation and rollback verification.");
  }
  if (!HASH_PATTERN.test(receipt.evidenceSha256)) fail("INVALID_HASH", "Drill receipt evidenceSha256 must be a lowercase SHA-256 digest.");
  return { synthetic, receipt, runbook, catalog };
}

function parseOptions(argv, allowed) {
  const options = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || value.startsWith("--")) fail("INVALID_ARGUMENT", "CLI options must be --name value pairs.");
    const name = key.slice(2);
    if (!allowed.has(name)) fail("UNKNOWN_ARGUMENT", `Unknown option: --${name}.`);
    if (options.has(name)) fail("DUPLICATE_ARGUMENT", `Duplicate option: --${name}.`);
    options.set(name, value);
  }
  return options;
}

function requiredOption(options, name) {
  const value = options.get(name);
  if (!value) fail("MISSING_ARGUMENT", `Missing required option: --${name}.`);
  return value;
}

function loadCatalogs(options) {
  const root = repositoryRoot(requiredOption(options, "root"));
  const ownershipPath = requiredOption(options, "ownership");
  const runbooksPath = requiredOption(options, "runbooks");
  if (ownershipPath !== CANONICAL_OWNERSHIP_PATH || runbooksPath !== CANONICAL_RUNBOOKS_PATH) {
    fail(
      "NON_CANONICAL_CATALOG_PATH",
      `Catalog arguments must be exactly ${CANONICAL_OWNERSHIP_PATH} and ${CANONICAL_RUNBOOKS_PATH}.`,
    );
  }
  const context = repositoryContext(root);
  const ownershipFile = readJsonFile(context, ownershipPath, "ownership catalog");
  const ownership = validateOwnership(context, ownershipFile.value);
  const runbookFile = readJsonFile(context, runbooksPath, "runbook catalog");
  const runbooks = validateRunbooks(context, runbookFile.value, ownership.roles);
  assertRepositoryIdentity(context);
  return {
    root,
    context,
    ownership,
    runbooks,
    ownershipBinding: { path: ownershipPath, sha256: ownershipFile.sha256 },
    runbooksBinding: { path: runbooksPath, sha256: runbookFile.sha256 },
  };
}

function repositoryBinding(catalogs) {
  assertRepositoryIdentity(catalogs.context);
  return {
    commit: catalogs.context.commit,
    tree: catalogs.context.tree,
    authoritativePaths: [...catalogs.context.authoritativePaths]
      .map(([pathValue, digest]) => ({ path: pathValue, sha256: digest }))
      .sort((left, right) => left.path.localeCompare(right.path)),
  };
}

function catalogResult(catalogs) {
  return {
    schema: RESULT_SCHEMA,
    valid: true,
    status: LOCAL_STATUS,
    gateAdmissible: false,
    externalConditions: [
      ...OWNERSHIP_EXTERNAL_CONDITIONS,
      ...RUNBOOK_EXTERNAL_CONDITIONS,
    ],
    repositoryBinding: repositoryBinding(catalogs),
  };
}

function listReceiptFiles(root, relative, label) {
  const directory = resolveDirectory(root, relative, label);
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) {
      fail("UNEXPECTED_RECEIPT_ENTRY", `${label} contains a non-JSON or non-regular entry.`);
    }
    const receiptRelative = path.relative(root, path.join(directory, entry.name)).split(path.sep).join("/");
    resolveUntrackedRegularFile(root, receiptRelative, `${label}/${entry.name}`);
    files.push(receiptRelative);
  }
  return files.sort();
}

function readUntrackedReceipt(root, relative, label) {
  const file = resolveUntrackedRegularFile(root, relative, label);
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    fail("INVALID_JSON", `${label} must contain valid JSON.`);
  }
}

function assertFresh(timeString, cadenceDays, label) {
  const time = parseTime(timeString, label);
  const now = Date.now();
  if (time > now + 5 * 60 * 1000) fail("FUTURE_RECEIPT", `${label} is unreasonably in the future.`);
  if (now - time > cadenceDays * 24 * 60 * 60 * 1000) fail("STALE_RECEIPT", `${label} exceeds the catalog review cadence.`);
}

function gateResult(catalogs, options) {
  const acceptanceFiles = listReceiptFiles(catalogs.root, requiredOption(options, "acceptance-dir"), "acceptance receipt directory");
  const drillFiles = listReceiptFiles(catalogs.root, requiredOption(options, "drill-dir"), "drill receipt directory");
  const externalAcceptances = [];
  const externalDrills = [];
  const receiptIds = new Set();
  for (const file of acceptanceFiles) {
    const result = validateAcceptanceReceipt(catalogs, readUntrackedReceipt(catalogs.root, file, "acceptance receipt"));
    if (receiptIds.has(result.receipt.receiptId)) fail("DUPLICATE_RECEIPT_ID", "Governance receipt ids must be unique.");
    receiptIds.add(result.receipt.receiptId);
    if (!result.synthetic) externalAcceptances.push(result);
  }
  for (const file of drillFiles) {
    const result = validateDrillReceipt(catalogs, readUntrackedReceipt(catalogs.root, file, "drill receipt"));
    if (receiptIds.has(result.receipt.receiptId)) fail("DUPLICATE_RECEIPT_ID", "Governance receipt ids must be unique.");
    receiptIds.add(result.receipt.receiptId);
    if (!result.synthetic) externalDrills.push(result);
  }

  const blockers = [];
  if (externalAcceptances.length !== 1) blockers.push("Exactly one current authenticated external ownership acceptance receipt is required.");
  const acceptance = externalAcceptances.length === 1 ? externalAcceptances[0] : null;
  if (acceptance) {
    const minimumCadence = Math.min(...catalogs.ownership.manifest.assets.map((asset) => asset.lifecycle.review.cadenceDays));
    assertFresh(acceptance.receipt.issuedAt, minimumCadence, "acceptance receipt.issuedAt");
  }
  for (const type of REQUIRED_DRILL_TYPES) {
    const matching = externalDrills.filter((entry) => entry.receipt.runbookType === type);
    if (matching.length !== 1) {
      blockers.push(`Exactly one current independent external drill receipt is required for ${type}.`);
      continue;
    }
    const entry = matching[0];
    assertFresh(entry.receipt.performedAt, entry.runbook.review.cadenceDays, `drill ${type}.performedAt`);
    if (acceptance) {
      const accountableSubjects = new Set([
        ...acceptance.receipt.acknowledgements.map((acknowledgement) => acknowledgement.authenticatedSubjectRef),
        acceptance.receipt.approval.authenticatedSubjectRef,
      ]);
      if (accountableSubjects.has(entry.receipt.independentOperator.authenticatedSubjectRef)) {
        blockers.push(`Independent drill operator for ${type} matches an accepted accountability subject.`);
      }
    }
  }
  if (externalDrills.some((entry) => !REQUIRED_DRILL_TYPES.includes(entry.receipt.runbookType))) {
    blockers.push("External gate evidence contains an unrequested drill type.");
  }

  const structurallyComplete = blockers.length === 0;
  if (structurallyComplete) {
    blockers.push("An independent trusted verifier must authenticate owner/substitute acknowledgements and drill evidence outside this local validator.");
  }
  return {
    schema: RESULT_SCHEMA,
    valid: true,
    status: structurallyComplete
      ? "GOVERNANCE-EXTERNAL-VERIFICATION-PENDING"
      : "GOVERNANCE-EXTERNAL-BLOCKING",
    gateAdmissible: false,
    doesNotAuthorizeDeployment: true,
    blockers,
    repositoryBinding: repositoryBinding(catalogs),
  };
}

function main(argv) {
  const command = argv[0];
  if (command === "catalogs") {
    const options = parseOptions(argv.slice(1), new Set(["root", "ownership", "runbooks"]));
    const catalogs = loadCatalogs(options);
    return { result: catalogResult(catalogs), exitCode: 0 };
  }
  if (command === "receipt") {
    const options = parseOptions(argv.slice(1), new Set(["root", "ownership", "runbooks", "kind", "receipt"]));
    const catalogs = loadCatalogs(options);
    const root = catalogs.root;
    const kind = requiredOption(options, "kind");
    const receiptPath = requiredOption(options, "receipt");
    if (path.isAbsolute(receiptPath)) fail("INVALID_PATH", "Receipt path must be repository-relative.");
    const receipt = readUntrackedReceipt(root, receiptPath, "receipt");
    const validated = kind === "acceptance"
      ? validateAcceptanceReceipt(catalogs, receipt)
      : kind === "drill"
        ? validateDrillReceipt(catalogs, receipt)
        : fail("INVALID_RECEIPT_KIND", "Receipt kind must be acceptance or drill.");
    return {
      result: {
        schema: RESULT_SCHEMA,
        valid: true,
        status: validated.synthetic ? "SYNTHETIC-NON-GATE-ADMISSIBLE" : "GOVERNANCE-EXTERNAL-VERIFICATION-PENDING",
        gateAdmissible: false,
        doesNotAuthorizeDeployment: true,
        repositoryBinding: repositoryBinding(catalogs),
      },
      exitCode: 0,
    };
  }
  if (command === "gate") {
    const options = parseOptions(argv.slice(1), new Set([
      "root",
      "ownership",
      "runbooks",
      "acceptance-dir",
      "drill-dir",
    ]));
    const catalogs = loadCatalogs(options);
    const result = gateResult(catalogs, options);
    return { result, exitCode: 1 };
  }
  fail("INVALID_COMMAND", "Command must be catalogs, receipt, or gate.");
}

try {
  const { result, exitCode } = main(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = exitCode;
} catch (error) {
  const code = error instanceof GovernanceError ? error.code : "UNEXPECTED_ERROR";
  const message = error instanceof GovernanceError ? error.message : "Unexpected local validation failure.";
  process.stdout.write(`${JSON.stringify({
    schema: RESULT_SCHEMA,
    valid: false,
    status: "INVALID-GOVERNANCE-DOCUMENTATION",
    gateAdmissible: false,
    error: { code, message },
  })}\n`);
  process.exitCode = 1;
}
