#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const EXPECTED_HASHES = new Map([
  [".github/workflows/release-attestation.yml", "2cc23f6f3e3927768e061d9258ee8e49dd96ea0cda11096a6a92334a8929e264"],
  [".github/workflows/enterprise-vps-evidence.yml", "312d035fea9b16017289c1c87b2222a48f292d6a93f8f725bf486227588b9f1d"],
  [".github/workflows/enterprise-live-evidence.yml", "21525e6307d42ac4643218f4fe6fd4193bef73f90367beed06b9f73f7f6546dc"],
  [".github/workflows/enterprise-infra.yml", "1cc02a79d482c2bee65e0173c879d7cf06f74f84ee5d9a6ed6893b2907fd8650"],
  ["scripts/vps-evidence-request.mjs", "b5214592c3ea5cbcbc9b52142a2236708e23f20ffb95ae48d4bf9de790977e40"],
  ["scripts/infra-ops.sh", "9e97cba91e877c34066c57509655a55f8bf67dab632d0a1e507242fdc8fb8901"],
  ["scripts/deploy-vps.sh", "ee572ce2164fa620c59eb63cecc5d75db02f58d9e664bf923400b5315ef75245"],
  ["docker/php-apache.Dockerfile", "03fddd9ead7f79747c0be10c1ddae8b3fd64acfb99d97b3d07a11108073c1108"],
  ["governance/github-environments.json", "41321d4251cb3c5e299363f9a424d3c0e1e71777ca1e4294413dc6e61bae92f8"],
  ["governance/production-readiness.json", "3daac5be3fb1f211cc1e77a70c2a9285d76b1dcc2f0fd2834ea861ce2502f41d"],
]);

const CHECKOUT_ACTION = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0";
const SELECTED_REF = "refs/heads/researcher-controlled";
const CASES = [
  {
    id: "CAN-227",
    name: "release-attestation",
    workflow: ".github/workflows/release-attestation.yml",
    job: "github-sigstore-release-evidence",
    environment: null,
    authority: "packages+attestations+oidc",
    authorityMarkers: [
      "id-token: write",
      "attestations: write",
      "packages: write",
    ],
    controlledMarker: "file: docker/php-apache.Dockerfile",
    sinkMarkers: [
      "docker/build-push-action@",
      "actions/attest-build-provenance@",
      "push-to-registry: true",
    ],
    providerPrecondition: "write-dispatch-authority",
  },
  {
    id: "CAN-229",
    name: "vps-evidence",
    workflow: ".github/workflows/enterprise-vps-evidence.yml",
    job: "vps-host-evidence",
    environment: "production",
    authority: "production-ssh",
    authorityMarkers: [
      "DEPLOY_SSH_KEY: ${{ secrets.DEPLOY_SSH_KEY }}",
      "DEPLOY_REMOTE: ${{ vars.DEPLOY_REMOTE }}",
    ],
    controlledMarker: "node ./scripts/vps-evidence-request.mjs render",
    sinkMarkers: [
      "ssh -i ~/.ssh/deploy_key",
      "'bash -s' < .tmp/vps-evidence-remote.sh",
    ],
    providerPrecondition: "production-environment-admits-ref",
  },
  {
    id: "CAN-230",
    name: "live-evidence",
    workflow: ".github/workflows/enterprise-live-evidence.yml",
    job: "production-live-evidence",
    environment: "production",
    authority: "cloudflare-provider-token",
    authorityMarkers: [
      "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}",
      "CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}",
    ],
    controlledMarker: "sh ./scripts/infra-ops.sh cloudflare-access-admin",
    sinkMarkers: [
      "--manifest .tmp/cloudflare-access-admin.production.json",
      "--verifyRemote",
    ],
    providerPrecondition: "production-environment-admits-ref",
  },
  {
    id: "CAN-231",
    name: "production-deploy",
    workflow: ".github/workflows/enterprise-infra.yml",
    job: "deploy-vps",
    environment: "production",
    authority: "production-ssh-deploy",
    authorityMarkers: [
      "DEPLOY_SSH_KEY: ${{ secrets.DEPLOY_SSH_KEY }}",
      "DEPLOY_REMOTE: ${{ vars.DEPLOY_REMOTE }}",
    ],
    controlledMarker: "run: sh ./scripts/deploy-vps.sh",
    sinkMarkers: [
      "GIT_SSH_COMMAND: ssh -i ~/.ssh/deploy_key",
      "run: sh ./scripts/deploy-vps.sh",
    ],
    providerPrecondition: "production-environment-admits-ref",
  },
];

const sourceArgument = process.argv[2];
if (!sourceArgument) {
  throw new Error("usage: privileged-ref-trust-probe.mjs WRAPPER_OWNED_SOURCE");
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

const environmentPolicy = JSON.parse(
  fs.readFileSync(path.join(sourceRoot, "governance/github-environments.json"), "utf8"),
);
const productionPolicy = environmentPolicy.environments.find(
  (environment) => environment.name === "production",
);
assert.equal(productionPolicy?.prevent_self_review, true);
assert.equal(productionPolicy?.require_reviewers_on_apply, true);
assert.equal(productionPolicy?.deployment_branch_policy?.protected_branches, true);
assert.equal(productionPolicy?.deployment_branch_policy?.custom_branch_policies, false);
const readiness = fs.readFileSync(
  path.join(sourceRoot, "governance/production-readiness.json"),
  "utf8",
);
assert.match(
  readiness,
  /Configure GitHub production environment secrets\/variables and require approvals for the deploy job\./,
);
console.log("[+] verified tracked production policy is provider-enforced and still requires live proof");

const regression = {
  protectedMain: trustedReferencePolicy({
    eventName: "workflow_dispatch",
    ref: "refs/heads/main",
    sha: "a".repeat(40),
    protectedMainContainsSha: true,
    protectedRef: true,
  }),
  attackerBranch: trustedReferencePolicy({
    eventName: "workflow_dispatch",
    ref: SELECTED_REF,
    sha: "b".repeat(40),
    protectedMainContainsSha: false,
    protectedRef: false,
  }),
  pullRequest: trustedReferencePolicy({
    eventName: "pull_request",
    ref: "refs/pull/17/merge",
    sha: "c".repeat(40),
    protectedMainContainsSha: false,
    protectedRef: false,
  }),
  unapprovedTag: trustedReferencePolicy({
    eventName: "workflow_dispatch",
    ref: "refs/tags/v9.9.9",
    sha: "d".repeat(40),
    authorizedTag: false,
    immutableTag: false,
  }),
  approvedTag: trustedReferencePolicy({
    eventName: "workflow_dispatch",
    ref: "refs/tags/v1.2.3",
    sha: "e".repeat(40),
    authorizedTag: true,
    immutableTag: true,
    protectedMainContainsSha: true,
  }),
};
assert.equal(regression.protectedMain, true);
assert.equal(regression.attackerBranch, false);
assert.equal(regression.pullRequest, false);
assert.equal(regression.unapprovedTag, false);
assert.equal(regression.approvedTag, true);
console.log(
  "[CONTROL] trusted-ref-policy protected_main=accepted attacker_branch=rejected pull_request_ref=rejected unapproved_tag=rejected approved_release_tag=accepted",
);

let vulnerable = 0;
for (const testCase of CASES) {
  const source = fs.readFileSync(path.join(sourceRoot, testCase.workflow), "utf8");
  assert.match(source, /^  workflow_dispatch:$/m, `${testCase.workflow} is not manually dispatchable`);
  const jobAnchor = `\n  ${testCase.job}:\n`;
  const jobIndex = source.indexOf(jobAnchor);
  assert.notEqual(jobIndex, -1, `${testCase.workflow} has no ${testCase.job} job`);
  const jobSource = source.slice(jobIndex + 1);

  const checkoutIndex = jobSource.indexOf(CHECKOUT_ACTION);
  assert.notEqual(checkoutIndex, -1, `${testCase.workflow} has no expected pinned checkout`);
  const checkout = checkoutBlock(jobSource, checkoutIndex);
  assert.doesNotMatch(
    checkout,
    /^\s+ref:\s*/m,
    `${testCase.workflow} unexpectedly overrides the event ref during checkout`,
  );

  const trustedConditions = [...jobSource.matchAll(/^\s*if:\s*(.+)$/gm)]
    .map((match) => match[1])
    .filter((condition) =>
      /github\.(?:ref|ref_name|ref_protected|sha)|GITHUB_(?:REF|SHA)|merge-base|verify-tag/.test(
        condition,
      ));
  assert.deepEqual(
    trustedConditions,
    [],
    `${testCase.workflow} unexpectedly contains a trusted-ref condition`,
  );

  if (testCase.environment) {
    assert.match(
      jobSource,
      new RegExp(`^\\s+environment:\\s*\\n\\s+name:\\s+${testCase.environment}\\s*$`, "m"),
    );
  } else {
    assert.doesNotMatch(jobSource, /^\s+environment:\s*$/m);
  }

  for (const marker of [...testCase.authorityMarkers, testCase.controlledMarker]) {
    assert.notEqual(jobSource.indexOf(marker), -1, `missing ${testCase.id} marker: ${marker}`);
  }
  for (const marker of testCase.sinkMarkers) {
    const sinkIndex = jobSource.indexOf(marker);
    assert.ok(sinkIndex > checkoutIndex, `${testCase.id} sink does not follow selected-ref checkout`);
  }

  vulnerable += 1;
  console.log(
    `[VULNERABLE] ${testCase.id} ${testCase.name} selected_ref=${SELECTED_REF} precheckout_ref_gate=missing checkout=event-ref authority=${testCase.authority} provider_precondition=${testCase.providerPrecondition}`,
  );
}

assert.equal(vulnerable, CASES.length);
assert.equal(directoryDigest(sourceRoot), treeBefore, "the source snapshot changed during the read-only probe");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the probe");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the probe");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the probe");
console.log(
  `[+] summary vulnerable_source_paths=${vulnerable} provider_environment_status=not_queried source_tree_unchanged=true`,
);
console.log(
  "[+] no GitHub API, Actions runner, credential, SSH, provider, registry, Docker, network, or live target was accessed",
);

function checkoutBlock(source, checkoutIndex) {
  const nextStep = source.indexOf("\n      - ", checkoutIndex + CHECKOUT_ACTION.length);
  return source.slice(checkoutIndex, nextStep === -1 ? source.length : nextStep);
}

function trustedReferencePolicy(context) {
  if (context.eventName !== "workflow_dispatch") return false;
  if (!/^[a-f0-9]{40}$/.test(String(context.sha ?? ""))) return false;
  if (
    context.ref === "refs/heads/main" &&
    context.protectedRef === true &&
    context.protectedMainContainsSha === true
  ) {
    return true;
  }
  if (
    /^refs\/tags\/(?:v|release-)/.test(String(context.ref ?? "")) &&
    context.authorizedTag === true &&
    context.immutableTag === true &&
    context.protectedMainContainsSha === true
  ) {
    return true;
  }
  return false;
}

function validateWrapperOwnedSource(sourceInput) {
  const wrapperInput = requiredEnvironment("FG049_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG049_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG049_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg049-(?:guard|run)\.[A-Za-z0-9]+$/,
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
  assert.match(path.basename(sentinelReal), /^\.fg049-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg049-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG049-OWNER:${ownershipToken}\n`;
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
