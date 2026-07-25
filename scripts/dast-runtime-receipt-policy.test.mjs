#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  activeRuntimeFingerprint,
  buildDastReceipt,
  validateDastReceipt,
  validateStagingDeploymentReceipt,
  validateStagingProbe,
} from "./dast-runtime-receipt-policy.mjs";

const repository = "owner/repo";
const commitSha = "a".repeat(40);
const treeSha = "b".repeat(40);
const artifactReceiptSha256 = "c".repeat(64);
const providerMetadataSha256 = "d".repeat(64);
const stagingReceiptSha256 = "e".repeat(64);
const generatedAt = "2026-07-25T10:00:00.000Z";
const now = "2026-07-25T10:10:00.000Z";
const target = "https://staging.example.test";
const identityPath = "/.well-known/platform-release.json";
const subjects = [{
  key: "PHP_APACHE_IMAGE",
  image: `ghcr.io/owner/platform-infrastructure-php-apache@sha256:${"1".repeat(64)}`,
  imageId: `sha256:${"2".repeat(64)}`,
}];
const policy = {
  version: 1,
  status: "READY",
  trustedVerifierChannel: "external-admission-controller/prod",
  trustedOpsImageRepository: "ghcr.io/owner/platform-infrastructure-ops",
  selfAssertedAnnotationsAccepted: false,
  requiredReceiptKind: "platform-trusted-deployment-admission/v1",
  trustedProducer: {
    repository: "owner/trusted-admission",
    workflowPath: ".github/workflows/produce-admission.yml",
    workflowSha: "4".repeat(40),
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
  },
  stagingDast: {
    status: "READY",
    canonicalTarget: target,
    releaseIdentityPath: identityPath,
    requiredStagingReceiptKind: "platform-trusted-staging-deployment/v1",
    requiredDastReceiptKind: "platform-dast-verification/v1",
    maxStagingReceiptAgeSeconds: 3600,
    maxDastReceiptAgeSeconds: 1800,
  },
};
const artifactReceipt = {
  version: 1,
  kind: "platform-release-artifact-verification/v1",
  status: "EXTERNAL-PENDING",
  artifactVerification: "passed",
  deploymentAdmission: "EXTERNAL-PENDING",
  usageScope: "artifact-verification-only",
  repository,
  commitSha,
  sourceArchiveSha256: "0".repeat(64),
  generatedAt,
  manifestSha256: "5".repeat(64),
  sbomSha256: "6".repeat(64),
  subjects: subjects.map(({ key, image }) => ({ key, image })),
  provenance: {
    verificationFingerprint: "7".repeat(64),
    manifestVerificationFingerprint: "8".repeat(64),
  },
};
const providerMetadata = {
  id: 123456,
  run_attempt: 2,
  repository: { full_name: policy.trustedProducer.repository },
  head_repository: { full_name: policy.trustedProducer.repository },
  path: policy.trustedProducer.workflowPath,
  head_sha: policy.trustedProducer.workflowSha,
  head_branch: "main",
  event: "workflow_dispatch",
  status: "completed",
  conclusion: "success",
};
const provider = {
  ...policy.trustedProducer,
  runId: "123456",
  runAttempt: 2,
};
const runtimeFingerprint = activeRuntimeFingerprint({
  repository, commitSha, treeSha, target, subjects,
});
const probe = {
  version: 1,
  kind: "platform-staging-release-identity/v1",
  status: "READY",
  repository,
  commitSha,
  treeSha,
  target,
  activeRuntime: { subjects, fingerprint: runtimeFingerprint },
};
const probeSha256 = crypto.createHash("sha256").update(`${JSON.stringify(probe)}\n`).digest("hex");
const stagingReceipt = {
  version: 1,
  kind: policy.stagingDast.requiredStagingReceiptKind,
  status: "READY",
  repository,
  commitSha,
  treeSha,
  target,
  deploymentId: "staging-deployment:12345678",
  deployedAt: generatedAt,
  artifactVerificationReceiptSha256: artifactReceiptSha256,
  activeRuntime: { subjects, fingerprint: runtimeFingerprint },
  probe: { path: identityPath, sha256: probeSha256 },
  producer: provider,
};
const expectedDastProducer = {
  repository,
  workflowPath: ".github/workflows/enterprise-infra.yml",
  workflowSha: commitSha,
  sourceRef: "refs/heads/main",
  event: "workflow_dispatch",
  runId: "7654321",
  runAttempt: 1,
  job: "dast-zap",
};
const stagingOptions = {
  policy,
  repository,
  commitSha,
  treeSha,
  artifactReceipt,
  artifactReceiptSha256,
  providerMetadata,
  providerRunId: provider.runId,
  providerRunAttempt: provider.runAttempt,
  now,
};
const stagingBinding = validateStagingDeploymentReceipt(stagingReceipt, stagingOptions);
const probeBinding = validateStagingProbe(probe, {
  stagingBinding,
  probeSha256,
});
const scan = {
  engineImage: `ghcr.io/zaproxy/zaproxy@sha256:${"9".repeat(64)}`,
  reports: {
    json: "a".repeat(64),
    html: "b".repeat(64),
    xml: "c".repeat(64),
  },
};
const dastReceipt = buildDastReceipt({
  stagingBinding,
  stagingReceiptSha256,
  providerMetadataSha256,
  probeBinding,
  scan,
  producer: expectedDastProducer,
  generatedAt,
});
const dastOptions = {
  policy,
  stagingBinding,
  stagingReceiptSha256,
  providerMetadataSha256,
  expectedProducer: expectedDastProducer,
  now,
};

test("provider-authenticated exact staging deployment and exact probe pass", () => {
  assert.equal(stagingBinding.commitSha, commitSha);
  assert.equal(stagingBinding.treeSha, treeSha);
  assert.equal(stagingBinding.target, target);
  assert.equal(stagingBinding.activeRuntime.subjects.length, 1);
  assert.equal(probeBinding.sha256, probeSha256);
});

test("wrong or stale candidate SHA/tree fails closed", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt({ ...stagingReceipt, commitSha: "f".repeat(40) }, stagingOptions),
    /repository\/commit\/tree/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt(stagingReceipt, { ...stagingOptions, treeSha: "f".repeat(40) }),
    /repository\/commit\/tree/,
  );
});

test("mutable or noncanonical DAST targets fail closed", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt({ ...stagingReceipt, target: "https://attacker.example" }, stagingOptions),
    /canonical staging target/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt(stagingReceipt, {
      ...stagingOptions,
      policy: { ...policy, stagingDast: { ...policy.stagingDast, canonicalTarget: "http://staging.example.test" } },
    }),
    /HTTPS/,
  );
});

test("wrong, missing, duplicate or additional active image subjects fail closed", () => {
  const wrongImage = [{ ...subjects[0], image: `ghcr.io/owner/platform-infrastructure-php-apache@sha256:${"f".repeat(64)}` }];
  assert.throws(
    () => validateStagingDeploymentReceipt({
      ...stagingReceipt,
      activeRuntime: {
        subjects: wrongImage,
        fingerprint: activeRuntimeFingerprint({ repository, commitSha, treeSha, target, subjects: wrongImage }),
      },
    }, stagingOptions),
    /subject set/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt({
      ...stagingReceipt,
      activeRuntime: { subjects: [], fingerprint: runtimeFingerprint },
    }, stagingOptions),
    /subject/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt({
      ...stagingReceipt,
      activeRuntime: { subjects: [...subjects, subjects[0]], fingerprint: runtimeFingerprint },
    }, stagingOptions),
    /unique/,
  );
});

test("self-authored or wrong provider producer fails closed", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt({
      ...stagingReceipt,
      producer: { ...provider, workflowPath: ".github/workflows/attacker.yml" },
    }, stagingOptions),
    /authenticated provider run/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt(stagingReceipt, {
      ...stagingOptions,
      providerMetadata: { ...providerMetadata, conclusion: "failure" },
    }),
    /successful workflow/,
  );
});

test("expired and future staging deployment receipts fail closed", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt({ ...stagingReceipt, deployedAt: "2026-07-25T08:00:00.000Z" }, stagingOptions),
    /expired/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt({ ...stagingReceipt, deployedAt: "2026-07-25T11:00:00.000Z" }, stagingOptions),
    /future/,
  );
});

test("probe bytes must fingerprint the exact provider-bound candidate", () => {
  assert.throws(
    () => validateStagingProbe({ ...probe, commitSha: "f".repeat(40) }, { stagingBinding, probeSha256 }),
    /candidate binding/,
  );
  assert.throws(
    () => validateStagingProbe(probe, { stagingBinding, probeSha256: "f".repeat(64) }),
    /probe SHA256/,
  );
  assert.throws(
    () => validateStagingProbe({
      ...probe,
      activeRuntime: { ...probe.activeRuntime, fingerprint: "f".repeat(64) },
    }, { stagingBinding, probeSha256 }),
    /runtime fingerprint/,
  );
});

test("DAST receipt binds scan, probe, staging receipt and authenticated current workflow producer", () => {
  assert.equal(validateDastReceipt(dastReceipt, dastOptions), dastReceipt);
  assert.throws(
    () => validateDastReceipt({ ...dastReceipt, stagingDeploymentReceiptSha256: "f".repeat(64) }, dastOptions),
    /staging deployment receipt/,
  );
  assert.throws(
    () => validateDastReceipt({
      ...dastReceipt,
      producer: { ...dastReceipt.producer, workflowPath: ".github/workflows/attacker.yml" },
    }, dastOptions),
    /DAST producer/,
  );
  assert.throws(
    () => validateDastReceipt({
      ...dastReceipt,
      scan: { ...dastReceipt.scan, reports: { ...dastReceipt.scan.reports, json: "f".repeat(64) } },
    }, dastOptions),
    /scan fingerprint/,
  );
});

test("stale DAST receipts cannot authorize deployment", () => {
  assert.throws(
    () => validateDastReceipt({ ...dastReceipt, generatedAt: "2026-07-25T09:00:00.000Z" }, dastOptions),
    /expired/,
  );
});

test("EXTERNAL-PENDING policy cannot mint or accept readiness", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt(stagingReceipt, {
      ...stagingOptions,
      policy: {
        ...policy,
        stagingDast: { ...policy.stagingDast, status: "EXTERNAL-PENDING", canonicalTarget: null },
      },
    }),
    /EXTERNAL-PENDING/,
  );
});

test("offline CLI creates and deploy-revalidates one exact run-bound receipt", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "platform-dast-policy-test-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const writeJson = (name, value) => {
    const pathname = path.join(directory, name);
    fs.writeFileSync(pathname, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    return pathname;
  };
  const digest = (pathname) => crypto.createHash("sha256").update(fs.readFileSync(pathname)).digest("hex");
  const artifactPath = writeJson("artifact.json", artifactReceipt);
  const providerPath = writeJson("provider.json", providerMetadata);
  const probePath = writeJson("probe.json", probe);
  const runtimeStagingReceipt = {
    ...stagingReceipt,
    artifactVerificationReceiptSha256: digest(artifactPath),
    probe: { ...stagingReceipt.probe, sha256: digest(probePath) },
  };
  const stagingPath = writeJson("staging.json", runtimeStagingReceipt);
  const policyPath = writeJson("policy.json", policy);
  const zapJson = path.join(directory, "zap.json");
  const zapHtml = path.join(directory, "zap.html");
  const zapXml = path.join(directory, "zap.xml");
  fs.writeFileSync(zapJson, "{\"site\":[]}\n");
  fs.writeFileSync(zapHtml, "<html>passed</html>\n");
  fs.writeFileSync(zapXml, "<OWASPZAPReport/>\n");
  const receiptPath = path.join(directory, "dast.json");
  const common = [
    "--policy", policyPath,
    "--artifactReceipt", artifactPath,
    "--artifactReceiptSha256", digest(artifactPath),
    "--providerMetadata", providerPath,
    "--providerMetadataSha256", digest(providerPath),
    "--stagingReceipt", stagingPath,
    "--stagingReceiptSha256", digest(stagingPath),
    "--repo", repository,
    "--commit", commitSha,
    "--tree", treeSha,
    "--providerRunId", provider.runId,
    "--providerRunAttempt", String(provider.runAttempt),
    "--workflowPath", expectedDastProducer.workflowPath,
    "--sourceRef", expectedDastProducer.sourceRef,
    "--event", expectedDastProducer.event,
    "--runId", expectedDastProducer.runId,
    "--runAttempt", String(expectedDastProducer.runAttempt),
    "--job", expectedDastProducer.job,
    "--now", generatedAt,
  ];
  const created = JSON.parse(execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    ...common,
    "--probe", probePath,
    "--zapImage", scan.engineImage,
    "--zapJson", zapJson,
    "--zapHtml", zapHtml,
    "--zapXml", zapXml,
    "--receiptOutput", receiptPath,
  ], { encoding: "utf8" }));
  assert.equal(created.status, "READY");
  assert.equal(created.dastReceiptSha256, digest(receiptPath));

  const verified = JSON.parse(execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    ...common,
    "--dastReceipt", receiptPath,
    "--dastReceiptSha256", digest(receiptPath),
  ], { encoding: "utf8" }));
  assert.equal(verified.status, "READY");
  assert.equal(verified.commitSha, commitSha);
  assert.throws(() => execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    ...common,
    "--dastReceipt", receiptPath,
    "--dastReceiptSha256", "f".repeat(64),
  ], { encoding: "utf8", stdio: "pipe" }), /Command failed/);
});

test("provider-authenticated staging evidence must be independent from the candidate repository", () => {
  const sameRepositoryPolicy = {
    ...policy,
    trustedProducer: { ...policy.trustedProducer, repository },
  };
  const sameRepositoryMetadata = {
    ...providerMetadata,
    repository: { full_name: repository },
    head_repository: { full_name: repository },
  };
  const sameRepositoryReceipt = {
    ...stagingReceipt,
    producer: { ...stagingReceipt.producer, repository },
  };
  assert.throws(
    () => validateStagingDeploymentReceipt(sameRepositoryReceipt, {
      ...stagingOptions,
      policy: sameRepositoryPolicy,
      providerMetadata: sameRepositoryMetadata,
    }),
    /independent/,
  );
});

test("one pre-scan identity blob cannot authorize a scan without a fresh post-scan observation", () => {
  assert.throws(
    () => buildDastReceipt({
      stagingBinding,
      stagingReceiptSha256,
      providerMetadataSha256,
      preProbeBinding: probeBinding,
      scan,
      scanStartedAt: "2026-07-25T10:01:00.000Z",
      scanFinishedAt: "2026-07-25T10:02:00.000Z",
      producer: expectedDastProducer,
      generatedAt,
    }),
    /post-scan/,
  );
});

test("DAST authorization must carry the provider-bound current deploy consumer challenge", () => {
  assert.deepEqual(dastReceipt.consumerChallenge, {
    consumerRepository: repository,
    consumerRunId: expectedDastProducer.runId,
    consumerRunAttempt: expectedDastProducer.runAttempt,
    consumerJob: "deploy-vps",
    challengeNonce: "0".repeat(64),
  });
});
