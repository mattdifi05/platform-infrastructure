#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_SOURCE_HASHES = new Map([
  ["security/admission/cosign-digest-policy.rego", "62c6052d50c2445ef1fd9c16af6587299282de3b5bda48c87780e0dc043b863f"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["scripts/release-trust.mjs", "69a5a538a8125eb756e515812be161d97e8699d63124c935f5425d86eea7bdc0"],
  ["scripts/release-trust.test.mjs", "97edc9931d7db9e00f12f7eccd5583142ee63dbedeb44b78e81a26fabb81f890"],
  ["scripts/t16-policy.mjs", "05e9fac302958dd0e5aef855e7de8f2182143fd753132a622d761c55d7d52e3f"],
  ["governance/release-trust.json", "f4aec6aa2f5a3ff5ef089d93c12a588df8903164139fa772ab84b89ecbdff2e2"],
  ["RELEASE-TRUST-AND-WORKFLOW-SECURITY.md", "55c17a17bd920fc8381bfb65394594d16fc3711245c378d23abec61b0293f6c9"],
]);
const UNDEFINED = Symbol("rego-undefined");

function fail(message) {
  throw new Error(message);
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function snapshotTree(root) {
  const digest = crypto.createHash("sha256");

  function visit(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isDirectory()) {
      digest.update(`directory\0${relative}\0${stat.mode & 0o7777}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        visit(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    if (stat.isFile()) {
      const data = fs.readFileSync(current);
      digest.update(`file\0${relative}\0${stat.mode & 0o7777}\0${data.length}\0`);
      digest.update(data);
      digest.update("\0");
      return;
    }
    if (stat.isSymbolicLink()) {
      digest.update(`symlink\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    fail(`unsupported archived source entry: ${relative}`);
  }

  visit(root, "");
  return digest.digest("hex");
}

function verifyBoundary(sourceArgument) {
  const wrapperRootInput = process.env.FG063_WRAPPER_TEMP_ROOT;
  const sentinelInput = process.env.FG063_OWNERSHIP_SENTINEL;
  const token = process.env.FG063_OWNERSHIP_TOKEN;
  if (!wrapperRootInput || !sentinelInput || !token) {
    fail("wrapper ownership environment is required; direct invocation is refused");
  }
  if (!/^[A-Za-z0-9]+$/.test(token)) fail("ownership token has invalid syntax");

  const wrapperRoot = path.resolve(wrapperRootInput);
  const source = path.resolve(sourceArgument);
  const sentinel = path.resolve(sentinelInput);
  const rootStat = fs.lstatSync(wrapperRoot);
  const sourceStat = fs.lstatSync(source);
  const sentinelStat = fs.lstatSync(sentinel);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("wrapper root must be a real directory");
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) fail("source must be a real directory");
  if (!sentinelStat.isFile() || sentinelStat.isSymbolicLink()) fail("ownership sentinel must be a regular file");

  const realRoot = fs.realpathSync(wrapperRoot);
  const realSource = fs.realpathSync(source);
  const realSentinel = fs.realpathSync(sentinel);
  if (realSource !== path.join(realRoot, "source")) fail("source is not the wrapper-owned source child");
  if (path.dirname(realSentinel) !== realRoot) fail("ownership sentinel is outside the wrapper root");
  if (path.basename(realSentinel) !== `.fg063-owner.${token}`) {
    fail("ownership token does not match sentinel name");
  }
  if (fs.readFileSync(realSentinel, "utf8") !== `FG063-OWNER:${token}\n`) {
    fail("ownership sentinel content is invalid");
  }
  return realSource;
}

function readSource(sourceRoot, relative) {
  const file = path.join(sourceRoot, relative);
  const data = fs.readFileSync(file);
  assert.equal(sha256(data), EXPECTED_SOURCE_HASHES.get(relative), `unexpected archived source hash for ${relative}`);
  return data.toString("utf8");
}

function verifySourceShape(sourceRoot) {
  const policy = readSource(sourceRoot, "security/admission/cosign-digest-policy.rego");
  const infraOps = readSource(sourceRoot, "scripts/infra-ops.mjs");
  const releaseTrust = readSource(sourceRoot, "scripts/release-trust.mjs");
  const releaseTrustTest = readSource(sourceRoot, "scripts/release-trust.test.mjs");
  const t16Policy = readSource(sourceRoot, "scripts/t16-policy.mjs");
  const trustPolicy = JSON.parse(readSource(sourceRoot, "governance/release-trust.json"));
  const trustDocument = readSource(sourceRoot, "RELEASE-TRUST-AND-WORKFLOW-SECURITY.md");

  assert.equal([...policy.matchAll(/^deny\[msg\]\s*\{/gm)].length, 4, "unexpected Rego deny-rule count");
  assert.match(policy, /input\.metadata\.annotations\["cosign\.sigstore\.dev\/verified"\] != "true"/);
  assert.match(policy, /input\.metadata\.annotations\["slsa\.dev\/provenance"\] != "verified"/);
  assert.doesNotMatch(policy, /\bobject\.get\b|\bdata\.|verificationResult|trustedVerification|signature\s*\?|certificate/);

  assert.match(infraOps, /assertMatch\(policy, \/cosign\\\.sigstore/);
  assert.match(infraOps, /assertMatch\(policy, \/slsa\\\.dev/);
  assert.match(infraOps, /verifyGithubReleaseImages\(/);
  assert.match(infraOps, /run\("cosign", \["verify", image\]\)/);

  assert.match(releaseTrust, /spawnSync\(verifierBinary\(\), args/);
  assert.match(releaseTrust, /if \(result\.status !== 0\)/);
  assert.match(releaseTrust, /parseCryptographicallyVerifiedGithubOutput\(result\.stdout/);
  assert.match(releaseTrust, /does not cover expected subject/);
  assert.match(releaseTrustTest, /PLATFORM_RELEASE_TRUST_TEST_MODE/);
  assert.match(releaseTrustTest, /synthetic-certificate-used-only-after-fake-cli-exit-success/);
  assert.match(t16Policy, /release gate invokes cryptographic verification/);
  assert.equal(trustPolicy.accept_unsigned_local_provenance, false);
  assert.equal(trustPolicy.accept_normalized_verification_reports, false);
  assert.match(trustDocument, /invokes the image-owned `\/usr\/local\/bin\/gh attestation verify` process/);

  return {
    releaseTrustPath: path.join(sourceRoot, "scripts/release-trust.mjs"),
    policy,
  };
}

function annotationValue(input, key) {
  const annotations = input?.metadata?.annotations;
  if (!annotations || !Object.prototype.hasOwnProperty.call(annotations, key)) return UNDEFINED;
  return annotations[key];
}

function regoNotEqual(reference, expected) {
  if (reference === UNDEFINED) return false;
  return reference !== expected;
}

function simulatePinnedPolicy(input) {
  const deny = [];
  if (input?.kind === "Deployment") {
    for (const container of input?.spec?.template?.spec?.containers ?? []) {
      const image = String(container?.image ?? "");
      if (!image.includes("@sha256:")) deny.push(`container ${container?.name} image must be digest-pinned`);
      if (image.endsWith(":latest")) deny.push(`container ${container?.name} image must not use :latest`);
    }
  }
  if (regoNotEqual(annotationValue(input, "cosign.sigstore.dev/verified"), "true")) {
    deny.push("deployment must be admitted only after cosign signature verification");
  }
  if (regoNotEqual(annotationValue(input, "slsa.dev/provenance"), "verified")) {
    deny.push("deployment must include verified SLSA provenance");
  }
  return deny;
}

function deployment({ image, annotations, verificationContext } = {}) {
  const document = {
    kind: "Deployment",
    metadata: {},
    spec: {
      template: {
        spec: {
          containers: [{ name: "application", image }],
        },
      },
    },
  };
  if (annotations !== undefined) document.metadata.annotations = annotations;
  if (verificationContext !== undefined) document.trustedVerification = verificationContext;
  return document;
}

function resultLine(label, name, input, detail) {
  const deny = simulatePinnedPolicy(input);
  process.stdout.write(`${label} ${name} deny=${deny.length} admitted=${deny.length === 0} ${detail}\n`);
  return deny;
}

async function main() {
  if (process.argv.length !== 3) fail("usage: cryptographic-admission-verification-probe.mjs ARCHIVED_SOURCE");
  const sourceRoot = verifyBoundary(process.argv[2]);
  process.stdout.write("[+] wrapper-owned source boundary verified\n");
  const before = snapshotTree(sourceRoot);
  const { releaseTrustPath } = verifySourceShape(sourceRoot);
  process.stdout.write("[+] verified 7 archived source hashes and admission/release trust source shapes\n");
  process.stdout.write("[+] classified admission_policy=annotation-comparison release_policy_check=static-text\n");
  process.stdout.write("[+] classified release_attestation_path=external-cryptographic-verifier present=true invoked=false\n");

  const mutableDenials = resultLine(
    "[NEGATIVE-CONTROL]",
    "mutable-image",
    deployment({
      image: "registry.example/application:latest",
      annotations: {
        "cosign.sigstore.dev/verified": "true",
        "slsa.dev/provenance": "verified",
      },
    }),
    "simulator=source-model",
  );
  assert.equal(mutableDenials.length, 2);

  const badAnnotationDenials = resultLine(
    "[NEGATIVE-CONTROL]",
    "explicit-bad-annotations",
    deployment({
      image: `registry.example/application@sha256:${"a".repeat(64)}`,
      annotations: {
        "cosign.sigstore.dev/verified": "false",
        "slsa.dev/provenance": "unverified",
      },
    }),
    "simulator=source-model",
  );
  assert.equal(badAnnotationDenials.length, 2);

  const missingDenials = resultLine(
    "[VULNERABLE]",
    "missing-annotations",
    deployment({ image: `registry.example/application@sha256:${"b".repeat(64)}` }),
    "rego_missing_reference=undefined simulator=source-model",
  );
  assert.deepEqual(missingDenials, []);

  const forgedDenials = resultLine(
    "[VULNERABLE]",
    "self-asserted-annotations",
    deployment({
      image: `registry.example/application@sha256:${"c".repeat(64)}`,
      annotations: {
        "cosign.sigstore.dev/verified": "true",
        "slsa.dev/provenance": "verified",
      },
    }),
    "cryptographic_evidence=absent simulator=source-model",
  );
  assert.deepEqual(forgedDenials, []);

  const ignoredContextDenials = resultLine(
    "[VULNERABLE]",
    "wrong-signer-repository-digest",
    deployment({
      image: `registry.attacker.invalid/application@sha256:${"d".repeat(64)}`,
      annotations: {
        "cosign.sigstore.dev/verified": "true",
        "slsa.dev/provenance": "verified",
      },
      verificationContext: {
        verified: false,
        repository: "attacker/repository",
        signerWorkflow: "attacker/repository/.github/workflows/release.yml",
        subjectDigest: "e".repeat(64),
      },
    }),
    "verification_context=ignored simulator=source-model",
  );
  assert.deepEqual(ignoredContextDenials, []);

  const moduleUrl = `${pathToFileURL(releaseTrustPath).href}?revision=${REVISION}&tree=${TREE}`;
  const { buildGithubAttestationVerifyArgs, parseCryptographicallyVerifiedGithubOutput } = await import(moduleUrl);
  const digest = "f".repeat(64);
  const sourceDigest = "1".repeat(40);
  const repository = "owner/repository";
  const signerWorkflow = `${repository}/.github/workflows/release-attestation.yml`;
  const args = buildGithubAttestationVerifyArgs({
    subject: `oci://registry.example/application@sha256:${digest}`,
    repository,
    signerWorkflow,
    sourceDigest,
    sourceRef: "refs/heads/main",
  });
  for (const flag of ["--repo", "--signer-workflow", "--source-digest", "--signer-digest", "--source-ref", "--cert-oidc-issuer", "--predicate-type"]) {
    assert.ok(args.includes(flag), `missing cryptographic verifier binding ${flag}`);
  }
  assert.throws(() => buildGithubAttestationVerifyArgs({
    subject: `oci://registry.example/application@sha256:${digest}`,
    repository,
    signerWorkflow: "attacker/repository/.github/workflows/release.yml",
    sourceDigest,
    sourceRef: "refs/heads/main",
  }), /exact workflow path/);
  assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify({
    verified: true,
    repository,
    commitSha: sourceDigest,
  }), { expectedSubjectDigest: digest }), /non-empty result array|verificationResult/);
  process.stdout.write("[PARSER-CONTROL] legacy_verified_boolean=rejected cryptographic_verification=false\n");
  process.stdout.write("[CRYPTO-BOUNDARY] verifier_args_bound=repository,workflow,source-digest,signer-digest,ref,issuer,predicate,subject-digest executable_invoked=false\n");

  const after = snapshotTree(sourceRoot);
  assert.equal(after, before, "archived source tree changed during the probe");
  process.stdout.write("[+] summary simulated_policy_bypasses=3 total=3 cryptographic_verifications_executed=0 source_tree_unchanged=true\n");
  process.stdout.write("[+] no OPA, verifier, cosign, Docker, Kubernetes, network, credential, SSH, or live target was accessed\n");
}

main().catch((error) => {
  process.stderr.write(`error: ${error.message}\n`);
  process.exitCode = 1;
});
