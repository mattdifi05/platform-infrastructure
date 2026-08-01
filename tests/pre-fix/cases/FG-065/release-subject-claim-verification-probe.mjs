#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const CANONICAL_ID = "CAN-192";
const REPOSITORY = "approved/platform-infrastructure";
const SIGNER_WORKFLOW = `${REPOSITORY}/.github/workflows/release-attestation.yml`;
const SOURCE_REF = "refs/tags/v0.0.0-offline-poc";
const PROBE_PATH = fileURLToPath(import.meta.url);
const OWNER_SENTINEL = ".release-subject-claim-verification-runtime-owner";
const EXPECTED_HASHES = new Map([
  [".github/workflows/release-attestation.yml", "2cc23f6f3e3927768e061d9258ee8e49dd96ea0cda11096a6a92334a8929e264"],
  ["scripts/release-trust.mjs", "69a5a538a8125eb756e515812be161d97e8699d63124c935f5425d86eea7bdc0"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
]);

if (process.argv[2] === "--mock-gh") {
  mockGithubVerifier(process.argv.slice(3));
  process.exit(86);
}

const sourceArgument = String(process.argv[2] || "");
const tmpArgument = String(process.env.RELEASE_SUBJECT_POC_TMP_ROOT || "");
const ownerToken = String(process.env.RELEASE_SUBJECT_POC_OWNER_TOKEN || "");
if (!sourceArgument || !tmpArgument || !ownerToken) {
  throw new Error("run this probe through run-from-git-archive.sh");
}

const tmpRoot = verifiedRealDirectory(tmpArgument, "wrapper temporary root");
const sourceRoot = verifiedRealDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(tmpRoot, "source"), "source must be the exact wrapper-owned source child");
assert.match(ownerToken, /^[a-f0-9]{64}$/, "invalid wrapper ownership token");
const wrapperOwner = path.join(tmpRoot, ".release-subject-claim-verification-poc-owner");
assertRegularFile(wrapperOwner, "wrapper ownership sentinel");
assert.equal(fs.readFileSync(wrapperOwner, "utf8"), ownerToken, "wrapper ownership sentinel mismatch");

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  const target = path.join(sourceRoot, relativePath);
  assertRegularFile(target, `pinned source ${relativePath}`);
  assert.equal(sha256File(target), expectedHash, `${relativePath} is not the expected vulnerable source`);
}
console.log(`[PASS] exact pre-fix sources revision=${REVISION} tree=${TREE}`);

const workflowPath = path.join(sourceRoot, ".github", "workflows", "release-attestation.yml");
const releaseTrustPath = path.join(sourceRoot, "scripts", "release-trust.mjs");
const infraOpsPath = path.join(sourceRoot, "scripts", "infra-ops.mjs");
const workflowSource = fs.readFileSync(workflowPath, "utf8");
const releaseTrustSource = fs.readFileSync(releaseTrustPath, "utf8");
const infraOpsSource = fs.readFileSync(infraOpsPath, "utf8");

assert.match(workflowSource, /RELEASE_IMAGES_JSON: \$\{\{ github\.event\.inputs\.release_images_json \|\| '\{\}' \}\}/);
assert.match(workflowSource, /const digest = digestFromImageRef\(image\) \|\| entry\.digest \|\| entry\.subjectDigest;/);
assert.match(workflowSource, /const subjects = \[phpApacheSubject, \.\.\.configuredSubjects\];/);
assert.match(workflowSource, /subject-path: \.tmp\/release-attestation\/release-subjects\.json/);
const verificationStep = sliceBetween(
  workflowSource,
  "      - name: Cryptographically verify and record attestations\n",
  "      - name: Upload GitHub Sigstore release evidence\n",
  "workflow verification step",
);
assert.equal((verificationStep.match(/github-attestation-evidence\.sh/g) || []).length, 2);
assert.match(verificationStep, /--subject "oci:\/\/\$\{PHP_APACHE_IMAGE\}@\$\{PHP_APACHE_DIGEST\}"/);
assert.match(verificationStep, /--subject \.tmp\/release-attestation\/release-subjects\.json/);
assert.doesNotMatch(verificationStep, /configuredSubjects|RELEASE_IMAGES_JSON|verifyGithubReleaseImages/);
assert.match(releaseTrustSource, /export function verifyGithubReleaseImages\(\{ images, \.\.\.options \}\)/);
assert.match(releaseTrustSource, /return verifyGithubAttestation\(\{/);
assert.match(infraOpsSource, /if \(requireProvenance\) \{[\s\S]*verifyGithubReleaseImages\(\{/);
console.log("[PASS] source proof configured claims enter manifest and SBOM before two verifications limited to the built image and manifest blob");
console.log("[PASS] countercontrol source separately re-verifies release images when the deployment admission gate requires provenance");

const runtimeRoot = path.join(tmpRoot, "runtime");
const negativeRoot = path.join(tmpRoot, "negative-preservation");
let runtimeOwned = false;
let completed = false;

try {
  runNegativePreservationRegression(negativeRoot, ownerToken, tmpRoot);
  createOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
  runtimeOwned = true;

  const parserEvidence = runExactWorkflowGenerator({ runtimeRoot, workflowSource });
  assert.equal(parserEvidence.configuredCount, 5);
  assert.equal(parserEvidence.manifestIncluded, 5);
  assert.equal(parserEvidence.sbomIncluded, 5);
  console.log("[LOCAL PARSER VULNERABLE] configured_subjects=5 manifest_included=5 sbom_included=5 registry_queries=0 attestation_verifications=0");
  console.log("[LOCAL PARSER VULNERABLE] nonexistent_reserved_name=included mutable_with_fallback_digest=included wrong_repository=included platform_constraint=discarded unattested_flag=discarded");

  const releaseTrust = await import(`${pathToFileURL(releaseTrustPath).href}?poc=${crypto.randomUUID()}`);
  runSelfAssertedNegativeControl(releaseTrust);
  runVerifierExitNegativeControl({ releaseTrust, runtimeRoot });
  exerciseFixedOracle();

  for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
    assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} changed during the probe`);
  }
  assert.equal(fs.existsSync(path.join(sourceRoot, ".tmp")), false, "probe unexpectedly created archived-source temporary state");
  assert.equal(fs.existsSync(path.join(sourceRoot, "reports")), false, "probe unexpectedly created archived-source reports");
  console.log("[SAFE] network=0 provider=0 token=0 registry=0 live_mutations=0 source_mutations=0 working_tree_mutations=0");
  console.log(`[+] result=VULNERABLE canonical_id=${CANONICAL_ID}`);
  completed = true;
} finally {
  if (runtimeOwned && fs.existsSync(runtimeRoot)) {
    removeOwnedDirectory(runtimeRoot, ownerToken, tmpRoot);
  }
}

assert.equal(completed, true);
assert.equal(fs.existsSync(runtimeRoot), false);
console.log("[+] sentinel-authorized temporary cleanup complete; wrapper root remains trap-owned");

function runExactWorkflowGenerator({ runtimeRoot: root, workflowSource: source }) {
  const generatorSource = extractWorkflowGenerator(source);
  const scenarioRoot = path.join(root, "local-parser");
  const generatorPath = path.join(scenarioRoot, "exact-workflow-generator.cjs");
  const githubEnvPath = path.join(scenarioRoot, "github-env");
  const home = path.join(scenarioRoot, "home");
  const targetTmp = path.join(scenarioRoot, "tmp");
  fs.mkdirSync(path.join(scenarioRoot, ".tmp", "release-attestation"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(scenarioRoot, "reports", "release"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(targetTmp, { mode: 0o700 });
  fs.writeFileSync(generatorPath, generatorSource, { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(githubEnvPath, "", { encoding: "utf8", flag: "wx", mode: 0o600 });

  const digests = Object.fromEntries(["built", "nonexistent", "mutable", "foreign", "platform", "unattested"].map((key, index) => [key, `sha256:${String.fromCharCode(97 + index).repeat(64)}`]));
  const configured = [
    `registry.example.invalid/platform/nonexistent@${digests.nonexistent}`,
    { image: "ghcr.io/approved/platform-api:mutable", digest: digests.mutable },
    `ghcr.io/foreign/other-platform@${digests.foreign}`,
    { image: `ghcr.io/approved/platform-api@${digests.platform}`, platform: "linux/arm64" },
    { image: `ghcr.io/approved/platform-api@${digests.unattested}`, provenanceVerified: false },
  ];
  const environment = {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    HOME: home,
    TMPDIR: targetTmp,
    LANG: "C",
    LC_ALL: "C",
    NODE_OPTIONS: "",
    RELEASE_IMAGES_JSON: JSON.stringify(configured),
    PHP_APACHE_IMAGE: "ghcr.io/approved/platform-infrastructure-php-apache",
    PHP_APACHE_DIGEST: digests.built,
    PHP_APACHE_ATTESTATION_URL: "https://attestations.example.invalid/built-subject",
    RELEASE_NAME: "offline-source-pinned-poc",
    GITHUB_REPOSITORY: REPOSITORY,
    GITHUB_SHA: REVISION,
    GITHUB_REF_NAME: "v0.0.0-offline-poc",
    GITHUB_REF: SOURCE_REF,
    GITHUB_RUN_ID: "192",
    GITHUB_SERVER_URL: "https://github.example.invalid",
    GITHUB_ENV: githubEnvPath,
  };
  assertNoSensitiveEnvironment(environment);
  const result = spawnSync(process.execPath, [generatorPath], {
    cwd: scenarioRoot,
    encoding: "utf8",
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.error, undefined, `exact workflow generator failed to start: ${result.error?.message || "unknown"}`);
  assert.equal(result.status, 0, `exact workflow generator status=${result.status} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()}`);

  const manifestPath = path.join(scenarioRoot, ".tmp", "release-attestation", "release-subjects.json");
  const sbomPath = path.join(scenarioRoot, "reports", "release", "github-release-sbom-192.cdx.json");
  assertRegularFile(manifestPath, "generated local manifest");
  assertRegularFile(sbomPath, "generated local SBOM");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const sbom = JSON.parse(fs.readFileSync(sbomPath, "utf8"));
  assert.equal(manifest.subjects.length, configured.length + 1);
  assert.equal(manifest.subjects[0].digest, digests.built);
  assert.equal(manifest.subjects[0].attestationUrl, environment.PHP_APACHE_ATTESTATION_URL);

  const configuredSubjects = manifest.subjects.slice(1);
  const expectedSubjects = [
    { name: "registry.example.invalid/platform/nonexistent", digest: digests.nonexistent },
    { name: "ghcr.io/approved/platform-api:mutable", digest: digests.mutable },
    { name: "ghcr.io/foreign/other-platform", digest: digests.foreign },
    { name: "ghcr.io/approved/platform-api", digest: digests.platform },
    { name: "ghcr.io/approved/platform-api", digest: digests.unattested },
  ];
  assert.deepEqual(configuredSubjects, expectedSubjects);
  assert.ok(configuredSubjects.every((subject) => !("attestationUrl" in subject)));
  assert.ok(configuredSubjects.every((subject) => !("platform" in subject)));
  assert.ok(configuredSubjects.every((subject) => !("provenanceVerified" in subject)));

  const configuredComponents = sbom.components.slice(1);
  assert.equal(configuredComponents.length, configured.length);
  for (const expected of expectedSubjects) {
    const component = configuredComponents.find((entry) => entry.name === expected.name && entry.version === expected.digest);
    assert.ok(component, `configured subject omitted from SBOM: ${expected.name}@${expected.digest}`);
    assert.equal(component.properties.find((entry) => entry.name === "attestationUrl")?.value, "");
  }
  const manifestHash = sha256File(manifestPath);
  assert.equal(fs.readFileSync(githubEnvPath, "utf8"), `RELEASE_SUBJECTS_SHA256=${manifestHash}\n`);
  return {
    configuredCount: configured.length,
    manifestIncluded: configuredSubjects.length,
    sbomIncluded: configuredComponents.length,
  };
}

function extractWorkflowGenerator(source) {
  const block = sliceBetween(source, "          node <<'NODE'\n", "          NODE\n", "workflow Node generator");
  const lines = block.split("\n");
  for (const [index, line] of lines.entries()) {
    assert.ok(!line || line.startsWith("          "), `workflow generator line ${index + 1} is not indented as expected`);
  }
  const dedented = lines.map((line) => line ? line.slice(10) : "").join("\n");
  assert.match(dedented, /^const fs = require\("node:fs"\);/);
  assert.match(dedented, /fs\.appendFileSync\(process\.env\.GITHUB_ENV/);
  return `${dedented}\n`;
}

function runSelfAssertedNegativeControl(releaseTrust) {
  const selfAsserted = JSON.stringify([{
    statement: {
      predicateType: releaseTrust.SLSA_PROVENANCE_V1,
      subject: [{ name: "self-authored", digest: { sha256: "f".repeat(64) } }],
    },
  }]);
  assert.throws(
    () => releaseTrust.parseCryptographicallyVerifiedGithubOutput(selfAsserted, { expectedSubjectDigest: `sha256:${"f".repeat(64)}` }),
    /lacks verificationResult; self-asserted reports are not accepted/,
  );
  console.log("[NEGATIVE CONTROL self-asserted] local_json=rejected verificationResult=missing cryptographic_verification=false");
}

function runVerifierExitNegativeControl({ releaseTrust, runtimeRoot: root }) {
  const verifierRoot = path.join(root, "verifier-negative");
  const verifierPath = path.join(verifierRoot, "gh-refuse");
  const verifierLog = path.join(verifierRoot, "invocation.json");
  fs.mkdirSync(verifierRoot, { mode: 0o700 });
  writeExecutable(
    verifierPath,
    "#!/bin/sh\nexec \"$RELEASE_SUBJECT_POC_NODE\" \"$RELEASE_SUBJECT_POC_PROBE\" --mock-gh \"$@\"\n",
  );
  const saved = new Map();
  const environmentKeys = [
    "PLATFORM_RELEASE_TRUST_TEST_MODE",
    "GITHUB_CLI_BIN",
    "RELEASE_SUBJECT_POC_NODE",
    "RELEASE_SUBJECT_POC_PROBE",
    "RELEASE_SUBJECT_POC_VERIFIER_LOG",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
  ];
  for (const key of environmentKeys) {
    saved.set(key, process.env[key]);
    delete process.env[key];
  }
  try {
    process.env.PLATFORM_RELEASE_TRUST_TEST_MODE = "1";
    process.env.GITHUB_CLI_BIN = verifierPath;
    process.env.RELEASE_SUBJECT_POC_NODE = process.execPath;
    process.env.RELEASE_SUBJECT_POC_PROBE = PROBE_PATH;
    process.env.RELEASE_SUBJECT_POC_VERIFIER_LOG = verifierLog;
    assertNoSensitiveEnvironment(process.env);
    const image = `ghcr.io/approved/platform-api@sha256:${"e".repeat(64)}`;
    assert.throws(
      () => releaseTrust.verifyGithubReleaseImages({
        images: [image],
        repository: REPOSITORY,
        signerWorkflow: SIGNER_WORKFLOW,
        sourceDigest: REVISION,
        sourceRef: SOURCE_REF,
      }),
      /GitHub attestation cryptographic verification failed: synthetic offline verifier refusal/,
    );
    const invocation = JSON.parse(fs.readFileSync(verifierLog, "utf8"));
    assert.equal(invocation.sensitiveEnvironmentPresent, false);
    assert.deepEqual(invocation.args.slice(0, 3), [
      "attestation",
      "verify",
      `oci://${image}`,
    ]);
    assertArgumentPair(invocation.args, "--repo", REPOSITORY);
    assertArgumentPair(invocation.args, "--signer-workflow", SIGNER_WORKFLOW);
    assertArgumentPair(invocation.args, "--source-digest", REVISION);
    assertArgumentPair(invocation.args, "--source-ref", SOURCE_REF);
    assert.ok(invocation.args.includes("--deny-self-hosted-runners"));
    assertArgumentPair(invocation.args, "--format", "json");
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
  console.log("[NEGATIVE CONTROL verifier] exact_release_verifier=invoked mock_exit=86 result=rejected network=0 token=0");
}

function mockGithubVerifier(args) {
  const logPath = String(process.env.RELEASE_SUBJECT_POC_VERIFIER_LOG || "");
  assert.ok(logPath, "mock verifier log path is required");
  const sensitiveEnvironmentPresent = sensitiveEnvironmentKeys().some((key) => String(process.env[key] || "").length > 0);
  fs.writeFileSync(logPath, `${JSON.stringify({ args, sensitiveEnvironmentPresent }, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  process.stderr.write("synthetic offline verifier refusal\n");
}

function exerciseFixedOracle() {
  const digest = `sha256:${"a".repeat(64)}`;
  const exact = {
    image: `ghcr.io/approved/platform-api@${digest}`,
    requiredRepository: "ghcr.io/approved/platform-api",
    registryResolved: true,
    resolvedDigest: digest,
    requiredPlatform: "linux/amd64",
    resolvedPlatform: "linux/amd64",
    provenanceVerified: true,
  };
  assert.equal(fixedOracle(exact), true);
  assert.equal(fixedOracle({ ...exact, registryResolved: false }), false);
  assert.equal(fixedOracle({ ...exact, image: "ghcr.io/approved/platform-api:mutable" }), false);
  assert.equal(fixedOracle({ ...exact, image: `ghcr.io/foreign/platform-api@${digest}` }), false);
  assert.equal(fixedOracle({ ...exact, resolvedPlatform: "linux/arm64" }), false);
  assert.equal(fixedOracle({ ...exact, provenanceVerified: false }), false);
  console.log("[FIXED ORACLE] exact=accepted nonexistent=rejected mutable=rejected wrong_repository=rejected wrong_platform=rejected unattested=rejected");
}

function fixedOracle({ image, requiredRepository, registryResolved, resolvedDigest, requiredPlatform, resolvedPlatform, provenanceVerified }) {
  const match = String(image).match(/^(.+)@(sha256:[a-f0-9]{64})$/);
  if (!match) return false;
  const [, repository, claimedDigest] = match;
  return repository === requiredRepository
    && registryResolved === true
    && resolvedDigest === claimedDigest
    && resolvedPlatform === requiredPlatform
    && provenanceVerified === true;
}

function runNegativePreservationRegression(directory, ownerToken, parent) {
  assertDirectChild(directory, parent, "negative preservation directory");
  fs.mkdirSync(directory, { mode: 0o700 });
  const ownerFile = path.join(directory, OWNER_SENTINEL);
  const foreignFile = path.join(directory, "foreign-data");
  fs.writeFileSync(ownerFile, "0".repeat(64), { encoding: "utf8", flag: "wx", mode: 0o600 });
  fs.writeFileSync(foreignFile, "preserve-me\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  assert.throws(() => removeOwnedDirectory(directory, ownerToken, parent), /ownership sentinel mismatch/);
  assert.equal(fs.readFileSync(foreignFile, "utf8"), "preserve-me\n");
  fs.writeFileSync(ownerFile, ownerToken, { encoding: "utf8", flag: "w", mode: 0o600 });
  removeOwnedDirectory(directory, ownerToken, parent);
  assert.equal(fs.existsSync(directory), false);
  console.log("[PASS] negative preservation mismatched sentinel refused deletion and preserved existing data");
}

function createOwnedDirectory(directory, ownerToken, parent) {
  assertDirectChild(directory, parent, "owned runtime directory");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.writeFileSync(path.join(directory, OWNER_SENTINEL), ownerToken, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

function removeOwnedDirectory(directory, ownerToken, parent) {
  assertDirectChild(directory, parent, "cleanup directory");
  const stat = fs.lstatSync(directory);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), "cleanup target must be a real directory");
  assert.equal(fs.realpathSync(directory), directory, "cleanup target physical path mismatch");
  const ownerFile = path.join(directory, OWNER_SENTINEL);
  assertRegularFile(ownerFile, "cleanup ownership sentinel");
  assert.equal(fs.readFileSync(ownerFile, "utf8"), ownerToken, "cleanup ownership sentinel mismatch");
  fs.rmSync(directory, { recursive: true, force: false });
}

function assertDirectChild(child, parent, label) {
  assert.equal(path.dirname(child), parent, `${label} is not a direct child of its trusted parent`);
  assert.equal(path.resolve(child), child, `${label} is not absolute and normalized`);
}

function assertArgumentPair(args, flag, value) {
  const index = args.indexOf(flag);
  assert.ok(index >= 0, `missing verifier argument ${flag}`);
  assert.equal(args[index + 1], value, `unexpected verifier value for ${flag}`);
}

function assertNoSensitiveEnvironment(environment) {
  const populated = sensitiveEnvironmentKeys().filter((key) => String(environment[key] || "").length > 0);
  assert.deepEqual(populated, [], `sensitive environment unexpectedly populated: ${populated.join(",")}`);
}

function sensitiveEnvironmentKeys() {
  return [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "SIGSTORE_ID_TOKEN",
    "COSIGN_PASSWORD",
  ];
}

function sliceBetween(source, startMarker, endMarker, label) {
  const start = source.indexOf(startMarker);
  assert.ok(start >= 0, `${label} start marker missing`);
  const contentStart = start + startMarker.length;
  const end = source.indexOf(endMarker, contentStart);
  assert.ok(end >= 0, `${label} end marker missing`);
  assert.equal(source.indexOf(startMarker, contentStart), -1, `${label} start marker is ambiguous`);
  return source.slice(contentStart, end);
}

function verifiedRealDirectory(value, label) {
  const resolved = path.resolve(value);
  const stat = fs.lstatSync(resolved);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), `${label} must be a real directory`);
  assert.equal(fs.realpathSync(resolved), resolved, `${label} physical path mismatch`);
  return resolved;
}

function assertRegularFile(filePath, label) {
  const stat = fs.lstatSync(filePath);
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular non-symlink file`);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function writeExecutable(filePath, contents) {
  fs.writeFileSync(filePath, contents, { encoding: "utf8", flag: "wx", mode: 0o700 });
  fs.chmodSync(filePath, 0o700);
}
