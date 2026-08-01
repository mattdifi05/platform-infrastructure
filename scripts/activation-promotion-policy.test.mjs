#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { projectProviderRunMetadata, validateActivationPromotion } from "./activation-promotion-policy.mjs";
import { ACTIVATION_BUNDLE_ENTRY_LIMITS } from "./activation-bundle.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";

const sha = (character) => character.repeat(64);
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const jsonArtifact = (document, sourcePath) => {
  const bytes = Buffer.from(`${canonicalJson(document)}\n`);
  return { document, sourcePath, sha256: hash(bytes), sizeBytes: bytes.length };
};
const fileArtifact = (bytes, sourcePath) => ({
  sourcePath,
  sha256: hash(bytes),
  sizeBytes: bytes.length,
});

const policy = jsonArtifact({
  version: 1,
  status: "READY",
  requiredReceiptKind: "platform-activation-promotion/v1",
  selfAssertedAnnotationsAccepted: false,
  trustedRootSha256: null,
  trustedProducer: {
    repository: "owner/activation-promoter",
    workflowPath: ".github/workflows/promote.yml",
    workflowSha: "a".repeat(40),
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
    artifactName: "platform-promoted-activation",
  },
  reason: null,
}, "/fixtures/policy.json");
const trustedRoot = fileArtifact(Buffer.from("trusted root\n"), "/fixtures/trusted-root.json");
policy.document.trustedRootSha256 = trustedRoot.sha256;
policy.sha256 = hash(Buffer.from(`${canonicalJson(policy.document)}\n`));
const bundle = fileArtifact(Buffer.from("promoted activation bundle\n"), "/fixtures/activation.bundle");
const admission = fileArtifact(Buffer.from("sigstore dsse bundle\n"), "/fixtures/activation-admission.jsonl");
const runtimeIntentSha256 = sha("b");
const releaseContextSha256 = sha("c");
const deploymentReceiptSha256 = sha("d");
const requestId = `activation:${deploymentReceiptSha256}:${releaseContextSha256}`;
const dastReceipt = jsonArtifact({
  version: 1,
  kind: "platform-dast-verification/v1",
  status: "passed",
  repository: "owner/repo",
  commitSha: "b".repeat(40),
  treeSha: "c".repeat(40),
  runtimeIntentSha256,
  generatedAt: "2026-08-01T12:00:00.000Z",
  target: { url: "https://staging.example.com/", origin: "https://staging.example.com" },
  report: { name: "zap-baseline.json", sha256: sha("e"), sizeBytes: 4096 },
  consumerChallenge: {
    consumerRepository: "owner/repo",
    consumerRunId: "123456",
    consumerRunAttempt: 2,
    consumerJob: "deploy-vps",
    challengeNonce: sha("f"),
  },
}, "/fixtures/dast.json");
const providerMetadata = jsonArtifact({
  id: 789012,
  run_attempt: 3,
  repository: { full_name: "owner/activation-promoter" },
  head_repository: { full_name: "owner/activation-promoter" },
  path: ".github/workflows/promote.yml",
  head_branch: "main",
  head_sha: "a".repeat(40),
  event: "workflow_dispatch",
  status: "completed",
  conclusion: "success",
  html_url: "https://github.example/owner/activation-promoter/actions/runs/789012",
  actor: { login: "provider-bot", id: 99 },
}, "/fixtures/provider.json");
const manifestDocument = {
  schema: "platform-activation-bundle-manifest/v1",
  requestId,
  releaseContextSha256,
  runtimeIntentSha256,
  entries: Object.keys(ACTIVATION_BUNDLE_ENTRY_LIMITS).sort().map((name, index) => ({
    name,
    sha256: String(index + 1).repeat(64),
    sizeBytes: 1,
  })),
};
const bundleManifest = jsonArtifact(manifestDocument, "/fixtures/manifest.json");
const manifestSha256 = hash(Buffer.from(canonicalJson(manifestDocument)));

function receiptArtifact(mutator = null) {
  const document = {
    schema: "platform-activation-promotion/v1",
    status: "READY",
    requestId,
    releaseContextSha256,
    runtimeIntentSha256,
    dastReceiptSha256: dastReceipt.sha256,
    generatedAt: "2026-08-01T12:34:56.000Z",
    consumer: {
      repository: "owner/repo",
      runId: "123456",
      runAttempt: 2,
      job: "deploy-vps",
      challengeNonce: sha("f"),
    },
    producer: {
      repository: "owner/activation-promoter",
      workflowPath: ".github/workflows/promote.yml",
      workflowSha: "a".repeat(40),
      sourceRef: "refs/heads/main",
      event: "workflow_dispatch",
      runId: "789012",
      runAttempt: 3,
    },
    bundle: {
      schema: "platform-activation-bundle-descriptor/v1",
      sha256: bundle.sha256,
      sizeBytes: bundle.sizeBytes,
      manifestSha256,
    },
    cas: {
      schema: "platform-activation-cas-installation/v1",
      bundleObject: `sha256/${bundle.sha256}`,
      manifestObject: `sha256/${manifestSha256}`,
      installed: true,
      immutable: true,
      providerAttested: true,
    },
  };
  if (mutator) mutator(document);
  return jsonArtifact(document, "/fixtures/promotion-receipt.json");
}

const verifiedSubjects = [];
function verifyAttestation(options) {
  verifiedSubjects.push([options.subject, options.expectedSubjectDigest]);
  return {
    status: "passed",
    verified: true,
    selfHostedRunnerDenied: true,
    offlineBundleVerified: true,
    resultCount: 1,
  };
}
const base = {
  policy,
  receipt: receiptArtifact(),
  providerMetadata,
  bundle,
  bundleManifest,
  admission,
  trustedRoot,
  dastReceipt,
  repository: "owner/repo",
  consumerRunId: "123456",
  consumerRunAttempt: 2,
  providerRunId: "789012",
  providerRunAttempt: 3,
  verifyAttestation,
};
const result = validateActivationPromotion(base);
assert.equal(result.status, "READY");
assert.equal(result.bundle.sha256, bundle.sha256);
assert.equal(result.activationAdmission.sha256, admission.sha256);
assert.deepEqual(verifiedSubjects, [
  [bundle.sourcePath, bundle.sha256],
  [base.receipt.sourcePath, base.receipt.sha256],
]);
assert.deepEqual(Object.keys(projectProviderRunMetadata(providerMetadata.document)).sort(), [
  "conclusion", "event", "head_branch", "head_repository", "head_sha", "id", "path", "repository", "run_attempt", "status",
]);

for (const [label, mutate] of [
  ["self-asserted policy", (value) => { value.policy.document.selfAssertedAnnotationsAccepted = true; }],
  ["wrong provider run", (value) => { value.providerMetadata.document.id = 789013; }],
  ["missing provider repository", (value) => { delete value.providerMetadata.document.repository; }],
  ["wrong consumer", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.consumer.runId = "654321"; }); }],
  ["wrong DAST", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.dastReceiptSha256 = sha("0"); }); }],
  ["DAST runtime substitution", (value) => { value.dastReceipt = structuredClone(dastReceipt); value.dastReceipt.document.runtimeIntentSha256 = sha("0"); }],
  ["open DAST schema", (value) => { value.dastReceipt = structuredClone(dastReceipt); value.dastReceipt.document.untrusted = true; }],
  ["wrong bundle", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.bundle.sha256 = sha("0"); }); }],
  ["wrong manifest", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.bundle.manifestSha256 = sha("0"); }); }],
  ["CAS not installed", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.cas.installed = false; }); }],
  ["CAS mutable", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.cas.immutable = false; }); }],
  ["CAS object substitution", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.cas.bundleObject = `sha256/${sha("0")}`; }); }],
  ["untrusted root", (value) => { value.trustedRoot = fileArtifact(Buffer.from("other root\n"), "/fixtures/other-root.json"); }],
  ["incomplete DSSE", (value) => { value.verifyAttestation = () => ({ status: "passed", verified: false }); }],
]) {
  const candidate = { ...base, policy: structuredClone(base.policy), providerMetadata: structuredClone(base.providerMetadata) };
  mutate(candidate);
  assert.throws(() => validateActivationPromotion(candidate), undefined, label);
}

process.stdout.write("activation promotion policy tests passed 19/19\n");
