#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_HASHES = new Map([
  ["scripts/cloudflare-access-admin.mjs", "58977b1797b81f2bd9f1567ff48b1390dbb4b4d5d8c83edbba7b7036c630ba21"],
  ["cloudflare/access-admin.example.json", "dff6bc2ef134bce187330f9cf74148ffd84cd8cb6d9c9a82b9df609566283968"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["governance/production-go-no-go.json", "b439dec1c3e5cc47d22c3f452991b5bd985464fca2fd4f7988b6222352fbc8ca"],
  ["SECURITY.md", "b72a0abd090dfa15832d5af3e389edeee50cf5128cbd515e7c74b6a72f4d9cb3"],
]);

const [mode, sourceArgument, runRootArgument, wrapperArgument, sentinelArgument] = process.argv.slice(2);
if (!mode || !sourceArgument || !runRootArgument || !wrapperArgument || !sentinelArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned archive");
}
assert.ok(mode === "guard" || mode === "run", "mode must be guard or run");

const wrapperRoot = exactPhysicalDirectory(wrapperArgument, "wrapper root");
const runRoot = exactPhysicalDirectory(runRootArgument, "run root");
assert.equal(path.dirname(runRoot), wrapperRoot, "run root must be an exact wrapper child");
assert.match(path.basename(runRoot), mode === "guard" ? /^guard\.[A-Za-z0-9]+$/ : /^run\.[A-Za-z0-9]+$/);
const sourceRoot = exactPhysicalDirectory(sourceArgument, "source archive");
assert.equal(sourceRoot, path.join(runRoot, "source"), "source archive must be the exact run-root child");

const sentinelPath = path.resolve(sentinelArgument);
const sentinelStat = fs.lstatSync(sentinelPath);
assert.equal(sentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(sentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel is a symbolic link");
assert.equal(fs.realpathSync(sentinelPath), sentinelPath, "wrapper ownership sentinel must use its physical path");
assert.equal(path.dirname(sentinelPath), wrapperRoot, "wrapper ownership sentinel escaped its root");
const sentinelMatch = path.basename(sentinelPath).match(/^\.fg062-wrapper-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(sentinelPath, "utf8"),
  `fg062-provider-mfa:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} is not the expected source`);
}

const outputRoot = path.join(runRoot, "poc-output");
if (fs.existsSync(outputRoot)) {
  throw new Error("refusing to overwrite pre-existing output target: poc-output");
}
if (mode === "guard") {
  throw new Error("guard mode requires a pre-existing output target");
}

const outputOwnership = claimOwnedDirectory(outputRoot, runRoot, ownerToken);
let receiptHash = null;

try {
  const accessSource = readSource("scripts/cloudflare-access-admin.mjs");
  const infraOpsSource = readSource("scripts/infra-ops.mjs");
  const policySource = readSource("SECURITY.md");
  const goNoGoPolicy = JSON.parse(readSource("governance/production-go-no-go.json"));

  assert.match(policySource, /Cloudflare Access or equivalent provider MFA is required for production admin\s+surfaces/);
  assert.equal(goNoGoPolicy.requireCloudflareAccessVerify, true);

  const normalizeSource = extractFunction(accessSource, "function normalizeManifest(raw, argv) {", "\n}\n\nfunction applicationPayload");
  const summarySource = extractFunction(accessSource, "function manifestSummary(manifest) {", "\n}\n\nfunction writeEvidenceReport");
  const applicationPayloadSource = extractFunction(accessSource, "function applicationPayload(app, manifest) {", "\n}\n\nfunction policyPayload");
  const policyPayloadSource = extractFunction(accessSource, "function policyPayload(app, manifest) {", "\n}\n\nasync function cloudflareRequest");
  const selectorKeysSource = extractFunction(accessSource, "function selectorKeys(selectors = []) {", "\n}\n\nfunction requireSelectorSet");
  const requireSelectorSetSource = extractFunction(accessSource, "function requireSelectorSet(remoteSelectors, expectedSelectors, label) {", "\n}\n\nfunction assertAppMatches");
  const assertAppSource = extractFunction(accessSource, "function assertAppMatches(remote, expected) {", "\n}\n\nfunction assertPolicyMatches");
  const assertPolicySource = extractFunction(accessSource, "function assertPolicyMatches(remote, expected) {", "\n}\n\nfunction dryRun");
  const verifyRemoteSource = extractFunction(accessSource, "async function verifyRemote(manifest) {", "\n}\n\nasync function main");

  assert.match(normalizeSource, /raw\.mfaEnforcedByIdentityProvider !== true/);
  assert.match(summarySource, /mfaEnforcedByIdentityProvider: true/);
  assert.match(policyPayloadSource, /require: \[\{ login_method: \{ id: manifest\.allowedIdentityProviderIds\[0\] \} \}\]/);
  assert.doesNotMatch(policyPayloadSource, /\b(?:acr|amr|mfa|authentication_context)\b/i);
  assert.doesNotMatch(assertAppSource, /\b(?:acr|amr|mfa|authentication_context)\b/i);
  assert.doesNotMatch(assertPolicySource, /\b(?:acr|amr|mfa|authentication_context)\b/i);
  assert.doesNotMatch(verifyRemoteSource, /\b(?:acr|amr|mfa|authentication_context)\b/i);

  const goNoGoSlice = sliceBetween(
    infraOpsSource,
    "const latestCloudflareAccessReport = latestJsonReport",
    "const blockingRequired = checks.filter",
  );
  assert.match(goNoGoSlice, /cloudflareApps\.every\(\(app\) => app\.result === "verified"\)/);
  assert.match(goNoGoSlice, /cloudflareAccess\.payload\.status === "passed"/);
  assert.doesNotMatch(goNoGoSlice, /providerMfa|mfaAssurance|acr|amr/);

  const rawManifest = {
    accountId: "synthetic-account",
    teamName: "synthetic-team",
    adminSessionDuration: "1h",
    mfaEnforcedByIdentityProvider: true,
    allowedIdentityProviderIds: ["synthetic-idp"],
    allowedEmails: ["researcher@example.invalid"],
    allowedEmailDomains: [],
    applications: [{
      name: "Synthetic Admin",
      domain: "admin.example.invalid",
      policyName: "Synthetic Admin allow",
      sessionDuration: "1h",
    }],
  };

  const sandbox = {
    __networkAttempts: 0,
    __providerQueries: 0,
    __accessListCalls: 0,
    __stdout: [],
    __apps: [],
    __policies: [],
    process: {
      env: { CLOUDFLARE_API_TOKEN: "offline-placeholder-not-used" },
      stdout: { write(value) { sandbox.__stdout.push(String(value)); } },
    },
    fetch() {
      sandbox.__networkAttempts += 1;
      throw new Error("network access is forbidden in this PoC");
    },
    structuredClone,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(`
function cleanArray(value) {
  return Array.isArray(value) ? value.map((item) => String(item).trim()).filter(Boolean) : [];
}
${normalizeSource}
${summarySource}
${applicationPayloadSource}
${policyPayloadSource}
${selectorKeysSource}
${requireSelectorSetSource}
${assertAppSource}
${assertPolicySource}
async function listApplications() {
  globalThis.__accessListCalls += 1;
  return structuredClone(globalThis.__apps);
}
async function listPolicies() {
  globalThis.__accessListCalls += 1;
  return structuredClone(globalThis.__policies);
}
${verifyRemoteSource}
globalThis.__api = { normalizeManifest, manifestSummary, applicationPayload, policyPayload, verifyRemote };
`, context, { filename: "extracted-cloudflare-access-admin.mjs" });

  sandbox.__raw = rawManifest;
  sandbox.__argv = { apply: false, verifyRemote: false };
  sandbox.__manifest = vm.runInContext("__api.normalizeManifest(__raw, __argv)", context);
  const normalized = plain(sandbox.__manifest);
  assert.equal(Object.hasOwn(normalized, "mfaEnforcedByIdentityProvider"), false);

  const summary = plain(vm.runInContext("__api.manifestSummary(__manifest)", context));
  assert.equal(summary.mfaEnforcedByIdentityProvider, true);
  const expectedApp = plain(vm.runInContext("__api.applicationPayload(__manifest.applications[0], __manifest)", context));
  const expectedPolicy = plain(vm.runInContext("__api.policyPayload(__manifest.applications[0], __manifest)", context));
  assert.deepEqual(expectedPolicy.require, [{ login_method: { id: "synthetic-idp" } }]);

  sandbox.__apps = [{ ...expectedApp, id: "synthetic-app-id" }];
  sandbox.__policies = [{ ...expectedPolicy, id: "synthetic-policy-id" }];
  sandbox.__providerState = { mfaEnforced: false, evidence: null };
  const weakProviderResults = plain(await vm.runInContext("__api.verifyRemote(__manifest)", context));
  assert.deepEqual(weakProviderResults.map((item) => item.result), ["verified"]);
  assert.equal(sandbox.__networkAttempts, 0);
  assert.equal(sandbox.__providerQueries, 0);

  sandbox.__providerState = { mfaEnforced: true, evidence: null };
  const strongProviderResults = plain(await vm.runInContext("__api.verifyRemote(__manifest)", context));
  assert.deepEqual(strongProviderResults, weakProviderResults);
  assert.equal(sandbox.__networkAttempts, 0);
  assert.equal(sandbox.__providerQueries, 0);

  sandbox.__rawFalse = { ...rawManifest, mfaEnforcedByIdentityProvider: false };
  assert.throws(
    () => vm.runInContext("__api.normalizeManifest(__rawFalse, __argv)", context),
    /must set mfaEnforcedByIdentityProvider: true/,
  );

  const missingReceipt = offlineAssuranceGate({ manifestAssertion: true, providerReceipt: null });
  assert.deepEqual(missingReceipt, {
    decision: "pending-provider",
    reason: "fresh authenticated provider assurance is absent",
  });
  const selfAttestedReceipt = offlineAssuranceGate({
    manifestAssertion: true,
    providerReceipt: { source: "local-manifest", mfa: true },
  });
  assert.deepEqual(selfAttestedReceipt, {
    decision: "rejected",
    reason: "local self-attestation is not provider assurance",
  });
  const unverifiedClaim = offlineAssuranceGate({
    manifestAssertion: true,
    providerReceipt: {
      source: "synthetic-provider-claim",
      issuer: "https://issuer.example.invalid",
      clientId: "synthetic-client",
      mfa: true,
    },
  });
  assert.deepEqual(unverifiedClaim, {
    decision: "pending-provider",
    reason: "offline PoC cannot authenticate provider evidence",
  });

  const generatedAt = new Date().toISOString();
  const receipt = {
    schema: "provider-mfa-assurance-poc/v1",
    generatedAt,
    input: {
      revision: REVISION,
      tree: TREE,
      archiveSha256: process.env.FG062_ARCHIVE_SHA256 ?? null,
    },
    sourceHashes: Object.fromEntries(EXPECTED_HASHES),
    sourceProof: {
      localBooleanRequired: true,
      summaryHardCodesMfaTrue: true,
      remotePolicySelector: expectedPolicy.require,
      syntheticRemoteResult: weakProviderResults,
      syntheticAccessListCalls: sandbox.__accessListCalls,
      providerQueries: sandbox.__providerQueries,
      networkAttempts: sandbox.__networkAttempts,
    },
    negativeControls: {
      localFalseRejected: true,
      selfAttestationRejected: true,
      unauthenticatedClaimNotAccepted: true,
    },
    liveProviderAssurance: "NOT-TESTED",
    finalGate: missingReceipt.decision,
    result: "VULNERABLE-SOURCE-GAP",
  };
  const receiptPath = path.join(outputRoot, "provider-mfa-assurance-receipt.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  assert.deepEqual(JSON.parse(fs.readFileSync(receiptPath, "utf8")), receipt);
  receiptHash = sha256File(receiptPath);

  console.log("[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true");
  console.log("[+] source hashes access_admin=true manifest=true go_no_go=true policy=true infra_ops=true");
  console.log("[SOURCE] manifest_boolean_required=true normalized_provider_evidence_fields=0 evidence_summary_mfa=true");
  console.log("[SOURCE] access_policy_requires_login_method_id=true access_policy_requires_mfa_context=false");
  console.log(`[VULNERABLE] synthetic_app_policy_match=verified synthetic_access_list_calls=${sandbox.__accessListCalls} provider_assurance_inputs=0 provider_assurance_queries=0`);
  console.log("[CONDITIONAL] weak_provider_path_required=true deployed_provider_state=NOT-TESTED");
  console.log("[NEGATIVE-CONTROL] local_false_rejected=true self_attestation_rejected=true unauthenticated_claim_accepted=false");
  console.log("[REFERENCE] fresh_authenticated_provider_receipt=false decision=pending-provider");
  console.log(`[RECEIPT] generated_at=${generatedAt} sha256=${receiptHash}`);
  console.log("[+] safety live_provider_calls=0 network_calls=0 real_token_reads=0 browser_flows=0 identity_logins=0 live_mutations=0 source_mutations=0");
  console.log("[+] result=VULNERABLE-SOURCE-GAP live_provider_assurance=NOT-TESTED final_gate=PENDING-PROVIDER");
} finally {
  cleanupOwnedDirectory(outputOwnership);
}

assert.match(receiptHash ?? "", /^[a-f0-9]{64}$/);
assert.equal(fs.existsSync(outputRoot), false, "sentinel-owned output was not removed");
console.log("[+] cleanup sentinel_owned_output_removed=true");

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function extractFunction(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `unable to extract ${start}`);
  assert.equal(source.indexOf(start, startIndex + start.length), -1, `ambiguous extraction for ${start}`);
  return source.slice(startIndex, endIndex + "\n}".length);
}

function sliceBetween(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `unable to slice ${start}`);
  return source.slice(startIndex, endIndex);
}

function offlineAssuranceGate({ manifestAssertion, providerReceipt }) {
  assert.equal(manifestAssertion, true, "the local manifest assertion is expected only as configuration intent");
  if (!providerReceipt) {
    return { decision: "pending-provider", reason: "fresh authenticated provider assurance is absent" };
  }
  if (providerReceipt.source === "local-manifest") {
    return { decision: "rejected", reason: "local self-attestation is not provider assurance" };
  }
  return { decision: "pending-provider", reason: "offline PoC cannot authenticate provider evidence" };
}

function exactPhysicalDirectory(argument, label) {
  const resolved = path.resolve(argument);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  const physical = fs.realpathSync(resolved);
  assert.equal(physical, resolved, `${label} argument must be its exact physical path`);
  return physical;
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function claimOwnedDirectory(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "output target escaped its expected parent");
  assert.equal(fs.existsSync(targetPath), false, "output target already exists");
  fs.mkdirSync(targetPath, { mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true);
  assert.equal(targetStat.isSymbolicLink(), false);
  assert.equal(fs.realpathSync(targetPath), targetPath);
  const ownershipSentinel = path.join(targetPath, `.fg062-output-owner-${token}`);
  fs.writeFileSync(ownershipSentinel, `fg062-output:${token}\n`, { mode: 0o600, flag: "wx" });
  const innerSentinelStat = fs.lstatSync(ownershipSentinel);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    ownershipSentinel,
    sentinelDevice: innerSentinelStat.dev,
    sentinelInode: innerSentinelStat.ino,
    token,
  };
}

function cleanupOwnedDirectory(ownership) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through target symlink");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  const cleanupSentinelStat = fs.lstatSync(ownership.ownershipSentinel);
  assert.equal(cleanupSentinelStat.isFile(), true, "cleanup sentinel is not a regular file");
  assert.equal(cleanupSentinelStat.isSymbolicLink(), false, "cleanup sentinel is a symbolic link");
  assert.equal(cleanupSentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(cleanupSentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.ownershipSentinel, "utf8"),
    `fg062-output:${ownership.token}\n`,
    "cleanup sentinel content changed",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}
