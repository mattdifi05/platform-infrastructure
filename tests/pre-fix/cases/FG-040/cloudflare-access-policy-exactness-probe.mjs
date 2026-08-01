#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const SOURCE_SHA256 = "58977b1797b81f2bd9f1567ff48b1390dbb4b4d5d8c83edbba7b7036c630ba21";
const API_BASE = "https://api.cloudflare.com/client/v4";
const SYNTHETIC_TOKEN = "poc-synthetic-token-never-sent";
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));

const sourceArgument = String(process.argv[2] || "");
const tmpArgument = String(process.env.CF_ACCESS_POC_TMP_ROOT || "");
const ownerToken = String(process.env.CF_ACCESS_POC_OWNER_TOKEN || "");
if (!sourceArgument || !tmpArgument || !ownerToken) {
  throw new Error("run this probe through run-from-git-archive.sh");
}

const tmpRoot = verifiedRealDirectory(tmpArgument, "wrapper temporary root");
const sourceRoot = verifiedRealDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(tmpRoot, "source"), "source must be the exact wrapper-owned source child");
assert.equal(ownerToken.length, 64, "invalid wrapper ownership token length");
const rootOwnerFile = path.join(tmpRoot, ".cloudflare-access-policy-poc-owner");
assertRegularFile(rootOwnerFile, "wrapper ownership sentinel");
assert.equal(fs.readFileSync(rootOwnerFile, "utf8"), ownerToken, "wrapper ownership sentinel mismatch");

const sourcePath = path.join(sourceRoot, "scripts/cloudflare-access-admin.mjs");
assertRegularFile(sourcePath, "pinned Cloudflare Access verifier");
assert.equal(sha256File(sourcePath), SOURCE_SHA256, "unexpected Cloudflare Access verifier bytes");
const vulnerableSource = fs.readFileSync(sourcePath, "utf8");

const selectorSource = sourceSlice(vulnerableSource, "function selectorKeys", "function assertAppMatches");
const policySource = sourceSlice(vulnerableSource, "function assertPolicyMatches", "function dryRun");
const verifySource = sourceSlice(vulnerableSource, "async function verifyRemote", "async function main");
assert.match(selectorSource, /return new Set\(keys\)/);
assert.match(selectorSource, /for \(const key of selectorKeys\(expectedSelectors\)\)/);
assert.doesNotMatch(selectorSource, /remote\.size\s*[!=]==?\s*expected\.size|unknown selector|unsupported selector/i);
assert.match(policySource, /requireSelectorSet\(remote\.include, expected\.include/);
assert.match(verifySource, /const policy = policies\.find\(\(item\) => item\.name === expectedPolicy\.name\)/);
assert.doesNotMatch(verifySource, /policies\.length\s*[!=]==?\s*1|every\(.*policy|for \(const policy of policies\)/s);
console.log(`[PASS] pinned verifier fingerprint revision=${REVISION} tree=${TREE} sha256=${SOURCE_SHA256}`);
console.log("[PASS] source proof subset-only selector comparison and single-name policy selection confirmed");

const fixturePath = path.join(SCRIPT_DIR, "fixtures", "synthetic-provider-cases.json");
assertRegularFile(fixturePath, "synthetic provider fixture");
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

const runtimeRoot = path.join(tmpRoot, "runtime");
const runtimeOwner = createOwnedDirectory(runtimeRoot, ownerToken);
const negativeRoot = path.join(tmpRoot, "negative-preservation");
let modulePath;
let sourceHashAfter;
let syntheticFetchCalls = 0;
const originalFetch = globalThis.fetch;
const originalToken = process.env.CLOUDFLARE_API_TOKEN;

try {
  runNegativePreservationRegression(negativeRoot, ownerToken);

  const instrumentedSource = instrumentForImport(vulnerableSource);
  modulePath = path.join(runtimeRoot, "pinned-cloudflare-access-admin.mjs");
  fs.writeFileSync(modulePath, instrumentedSource, { encoding: "utf8", flag: "wx", mode: 0o600 });
  const vulnerable = await import(`${pathToFileURL(modulePath).href}?revision=${REVISION}`);
  const manifest = vulnerable.normalizeManifest(deepClone(fixture.manifest), { verifyRemote: true });
  const expectedPolicy = vulnerable.policyPayload(manifest.applications[0], manifest);

  process.env.CLOUDFLARE_API_TOKEN = SYNTHETIC_TOKEN;

  const exact = await runTargetCase(vulnerable, manifest, fixture.cases.exact);
  syntheticFetchCalls += exact.fetchCalls;
  assert.equal(exact.result.length, 1);
  assert.equal(exact.result[0].result, "verified");
  assertExactEffectivePolicy(fixture.cases.exact, expectedPolicy);
  console.log("[CONTROL] exact_policy=true target=verified exact_oracle=accepted");

  const broadened = await runTargetCase(vulnerable, manifest, fixture.cases.broadenedSelector);
  syntheticFetchCalls += broadened.fetchCalls;
  assert.equal(broadened.result[0].result, "verified");
  assert.throws(
    () => assertExactEffectivePolicy(fixture.cases.broadenedSelector, expectedPolicy),
    /selector mismatch|unsupported selector/,
  );
  console.log("[VULNERABLE CAN-126] expected_selector_present=true duplicate=true extra_domain=true everyone=true target=verified exact_oracle=rejected");

  const sibling = await runTargetCase(vulnerable, manifest, fixture.cases.siblingBypass);
  syntheticFetchCalls += sibling.fetchCalls;
  assert.equal(sibling.result[0].result, "verified");
  assert.throws(
    () => assertExactEffectivePolicy(fixture.cases.siblingBypass, expectedPolicy),
    /expected exactly one policy/,
  );
  console.log("[VULNERABLE CAN-127] expected_policy_intact=true sibling_decision=bypass policy_count=2 target=verified exact_oracle=rejected");

  const missing = await runTargetCase(vulnerable, manifest, fixture.cases.missingExpectedSelector, { expectFailure: true });
  syntheticFetchCalls += missing.fetchCalls;
  assert.match(missing.error.message, /remote verification failed/);
  assert.match(missing.error.issues.join("\n"), /missing selector email_domain:admins\.invalid/);
  console.log("[NEGATIVE CONTROL] expected_selector_missing=true target=failed");

  sourceHashAfter = sha256File(sourcePath);
  assert.equal(sourceHashAfter, SOURCE_SHA256, "probe changed the archived vulnerable source");
  assert.equal(fs.existsSync(path.join(sourceRoot, "reports")), false, "probe unexpectedly created source reports");
  console.log(`[SAFE] provider_requests=0 synthetic_fetch_calls=${syntheticFetchCalls} source_mutations=0 live_mutations=0`);
  console.log("[+] result=VULNERABLE canonical_ids=CAN-126,CAN-127");
} finally {
  if (originalFetch === undefined) delete globalThis.fetch;
  else globalThis.fetch = originalFetch;
  if (originalToken === undefined) delete process.env.CLOUDFLARE_API_TOKEN;
  else process.env.CLOUDFLARE_API_TOKEN = originalToken;
  if (fs.existsSync(runtimeRoot)) removeOwnedDirectory(runtimeRoot, runtimeOwner, tmpRoot);
}

assert.equal(sourceHashAfter, SOURCE_SHA256);
assert.equal(fs.existsSync(runtimeRoot), false);
console.log("[+] sentinel-authorized runtime cleanup complete; wrapper root remains trap-owned");

async function runTargetCase(vulnerable, manifest, providerCase, options = {}) {
  let fetchCalls = 0;
  globalThis.fetch = async (input, request = {}) => {
    fetchCalls += 1;
    assert.equal(request.method, "GET", "the verifier unexpectedly attempted a provider mutation");
    assert.equal(request.body, undefined, "the verifier unexpectedly supplied a request body");
    assert.equal(request.headers?.Authorization, `Bearer ${SYNTHETIC_TOKEN}`);
    const url = String(input);
    const appList = `${API_BASE}/accounts/${manifest.accountId}/access/apps?per_page=1000`;
    if (url === appList) return syntheticResponse(providerCase.applications);
    const prefix = `${API_BASE}/accounts/${manifest.accountId}/access/apps/`;
    const suffix = "/policies?per_page=1000";
    if (url.startsWith(prefix) && url.endsWith(suffix)) {
      const appId = decodeURIComponent(url.slice(prefix.length, -suffix.length));
      assert.ok(Object.hasOwn(providerCase.policiesByApplication, appId), `missing synthetic policies for ${appId}`);
      return syntheticResponse(providerCase.policiesByApplication[appId]);
    }
    throw new Error(`synthetic provider rejected unexpected URL: ${url}`);
  };

  if (options.expectFailure) {
    try {
      await vulnerable.verifyRemote(manifest);
    } catch (error) {
      return { error, fetchCalls };
    }
    throw new Error("target unexpectedly accepted the negative control");
  }
  return { result: await vulnerable.verifyRemote(manifest), fetchCalls };
}

function syntheticResponse(result) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ success: true, result: deepClone(result), errors: [] }),
  };
}

function assertExactEffectivePolicy(providerCase, expectedPolicy) {
  const appId = providerCase.applications[0]?.id;
  const policies = providerCase.policiesByApplication[appId] || [];
  assert.equal(policies.length, 1, `expected exactly one policy, received ${policies.length}`);
  const remote = policies[0];
  assert.equal(remote.name, expectedPolicy.name);
  assert.equal(remote.decision, expectedPolicy.decision);
  assert.equal(Number(remote.precedence), Number(expectedPolicy.precedence));
  assert.equal(String(remote.session_duration), String(expectedPolicy.session_duration));
  for (const field of ["include", "require", "exclude"]) {
    assert.deepEqual(
      canonicalSelectorArray(remote[field] || []),
      canonicalSelectorArray(expectedPolicy[field] || []),
      `${field} selector mismatch`,
    );
  }
}

function canonicalSelectorArray(selectors) {
  return selectors.map(canonicalSelector).sort();
}

function canonicalSelector(selector) {
  const entries = Object.entries(selector || {});
  assert.equal(entries.length, 1, "selector must contain exactly one selector kind");
  const [kind, value] = entries[0];
  let scalar;
  if (kind === "email") scalar = value?.email;
  else if (kind === "email_domain") scalar = value?.domain;
  else if (kind === "login_method") scalar = value?.id;
  else throw new Error(`unsupported selector: ${kind}`);
  assert.equal(typeof scalar, "string", `malformed ${kind} selector`);
  return `${kind}:${kind === "login_method" ? scalar : scalar.toLowerCase()}`;
}

function instrumentForImport(source) {
  const trailer = /\nmain\(\)\.catch\(\(error\) => \{\n  process\.stderr\.write\(`\$\{error\.message \?\? error\}\\n`\);\n  process\.exitCode = 1;\n\}\);\s*$/;
  assert.match(source, trailer, "unexpected verifier entry-point trailer");
  return source.replace(
    trailer,
    "\nexport { normalizeManifest, policyPayload, assertPolicyMatches, verifyRemote };\n",
  );
}

function runNegativePreservationRegression(directory, token) {
  fs.mkdirSync(directory, { mode: 0o700 });
  const foreignOwner = `${token.slice(0, -1)}${token.endsWith("0") ? "1" : "0"}`;
  const ownerFile = path.join(directory, ".poc-owner");
  const preserveFile = path.join(directory, "preserve-me.txt");
  fs.writeFileSync(ownerFile, foreignOwner, { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(preserveFile, "must-survive-refused-cleanup\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  assert.throws(() => removeOwnedDirectory(directory, token, tmpRoot), /ownership sentinel mismatch/);
  assert.equal(fs.readFileSync(preserveFile, "utf8"), "must-survive-refused-cleanup\n");
  fs.writeFileSync(ownerFile, token, { encoding: "utf8", flag: "w", mode: 0o600 });
  removeOwnedDirectory(directory, token, tmpRoot);
  assert.equal(fs.existsSync(directory), false);
  console.log("[PASS] negative preservation mismatched sentinel refused deletion and preserved existing data");
}

function createOwnedDirectory(directory, token) {
  assert.equal(path.dirname(directory), tmpRoot, "owned mutation directory must be a direct child of the wrapper root");
  fs.mkdirSync(directory, { mode: 0o700 });
  const ownerFile = path.join(directory, ".poc-owner");
  fs.writeFileSync(ownerFile, token, { encoding: "utf8", flag: "wx", mode: 0o600 });
  return token;
}

function removeOwnedDirectory(directory, token, parent) {
  const parentReal = verifiedRealDirectory(parent, "cleanup parent");
  assert.equal(path.dirname(path.resolve(directory)), parentReal, "cleanup target must be a direct child of wrapper root");
  const stats = fs.lstatSync(directory, { throwIfNoEntry: false });
  assert.ok(stats?.isDirectory() && !stats.isSymbolicLink(), "cleanup target must be a real directory");
  assert.equal(fs.realpathSync(directory), path.resolve(directory), "cleanup target realpath mismatch");
  const ownerFile = path.join(directory, ".poc-owner");
  assertRegularFile(ownerFile, "cleanup ownership sentinel");
  assert.equal(fs.readFileSync(ownerFile, "utf8"), token, "ownership sentinel mismatch");
  fs.rmSync(directory, { recursive: true });
}

function verifiedRealDirectory(input, label) {
  const resolved = path.resolve(input);
  const stats = fs.lstatSync(resolved, { throwIfNoEntry: false });
  assert.ok(stats?.isDirectory() && !stats.isSymbolicLink(), `${label} must be a real directory`);
  const real = fs.realpathSync(resolved);
  assert.equal(real, resolved, `${label} realpath mismatch`);
  return real;
}

function assertRegularFile(filePath, label) {
  const stats = fs.lstatSync(filePath, { throwIfNoEntry: false });
  assert.ok(stats?.isFile() && !stats.isSymbolicLink(), `${label} must be a regular file`);
}

function sourceSlice(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `missing source slice ${start} -> ${end}`);
  return source.slice(startIndex, endIndex);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}
