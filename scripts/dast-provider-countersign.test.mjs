#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  analyzeZapJsonReport,
  buildDastProviderReceipt,
  validateDastProviderReceipt,
  verifyDastProviderAttestation,
} from "./dast-runtime-receipt-policy.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const repository = "owner/platform-infrastructure";
const providerRepository = "owner/platform-admission";
const commitSha = "1".repeat(40);
const treeSha = "2".repeat(40);
const target = "https://staging.platform-infrastructure.test";
const generatedAt = "2026-07-25T10:10:00.000Z";
const scanRequestSha256 = "3".repeat(64);
const providerMetadataSha256 = "4".repeat(64);
const provider = {
  repository: providerRepository,
  workflowPath: ".github/workflows/produce-admission.yml",
  workflowSha: "5".repeat(40),
  sourceRef: "refs/heads/main",
  event: "workflow_dispatch",
  runId: "987654",
  runAttempt: 2,
};
const consumerChallenge = {
  consumerRepository: repository,
  consumerRunId: "7654321",
  consumerRunAttempt: 3,
  consumerJob: "deploy-vps",
  challengeNonce: "6".repeat(64),
};
const candidateProducer = {
  repository,
  workflowPath: ".github/workflows/enterprise-infra.yml",
  workflowSha: commitSha,
  sourceRef: "refs/heads/main",
  event: "workflow_dispatch",
  runId: consumerChallenge.consumerRunId,
  runAttempt: consumerChallenge.consumerRunAttempt,
  job: "dast-zap",
};
const semanticVerdict = {
  policy: "zap-baseline-no-risk-alerts/v1",
  status: "passed",
  siteCount: 1,
  alertCount: 0,
  highestRiskCode: 0,
};
const reportEvidence = {
  artifactName: `dast-scan-request-${consumerChallenge.consumerRunId}-${consumerChallenge.consumerRunAttempt}-${consumerChallenge.challengeNonce}`,
  engineImage: `ghcr.io/zaproxy/zaproxy@sha256:${"7".repeat(64)}`,
  files: {
    json: { path: "zap-baseline.json", sha256: "8".repeat(64), bytes: 1024 },
    html: { path: "zap-baseline.html", sha256: "9".repeat(64), bytes: 2048 },
    xml: { path: "zap-baseline.xml", sha256: "a".repeat(64), bytes: 1536 },
  },
  semanticVerdict,
};
const scanRequest = {
  version: 1,
  kind: "platform-dast-scan-request/v1",
  status: "PENDING-PROVIDER-ATTESTATION",
  repository,
  commitSha,
  treeSha,
  target,
  artifactVerificationReceiptSha256: "b".repeat(64),
  deploymentAdmissionReceiptSha256: "c".repeat(64),
  stagingDeploymentReceiptSha256: "d".repeat(64),
  stagingProviderMetadataSha256: "e".repeat(64),
  consumerChallenge,
  runtimeIntentSha256: "f".repeat(64),
  runtimeInventorySha256: "0".repeat(64),
  targetServingInventoryHash: "1".repeat(64),
  targetServingServices: ["control-center", "project-router", "traefik"],
  observations: {
    pre: {
      path: "/.well-known/platform-release.json",
      sha256: "2".repeat(64),
      observedAt: "2026-07-25T10:01:00.000Z",
    },
    scan: {
      startedAt: "2026-07-25T10:02:00.000Z",
      finishedAt: "2026-07-25T10:06:00.000Z",
    },
    post: {
      path: "/.well-known/platform-release.json",
      sha256: "2".repeat(64),
      observedAt: "2026-07-25T10:07:00.000Z",
    },
  },
  reportEvidence,
  producer: candidateProducer,
  generatedAt: "2026-07-25T10:08:00.000Z",
};
const policy = {
  version: 1,
  status: "READY",
  trustedVerifierChannel: "external-admission-controller/prod",
  selfAssertedAnnotationsAccepted: false,
  trustedProducer: {
    repository: providerRepository,
    workflowPath: provider.workflowPath,
    workflowSha: provider.workflowSha,
    sourceRef: provider.sourceRef,
    event: provider.event,
  },
  stagingDast: {
    status: "READY",
    canonicalTarget: target,
    releaseIdentityPath: "/.well-known/platform-release.json",
    requiredStagingReceiptKind: "platform-trusted-staging-deployment/v1",
    requiredDastReceiptKind: "platform-dast-verification/v1",
    maxStagingReceiptAgeSeconds: 3600,
    maxDastReceiptAgeSeconds: 1800,
  },
};
const providerMetadata = {
  id: Number(provider.runId),
  run_attempt: provider.runAttempt,
  repository: { full_name: providerRepository },
  head_repository: { full_name: providerRepository },
  path: provider.workflowPath,
  head_sha: provider.workflowSha,
  head_branch: "main",
  event: provider.event,
  status: "completed",
  conclusion: "success",
};

test("empty or risk-bearing ZAP JSON cannot mint semantic pass", () => {
  assert.throws(
    () => analyzeZapJsonReport({ "@version": "2.16.1", "@generated": generatedAt, site: [] }, { target }),
    /site/i,
  );
  assert.throws(
    () => analyzeZapJsonReport({
      "@version": "2.16.1",
      "@generated": generatedAt,
      site: [{
        "@name": target,
        "@host": new URL(target).hostname,
        "@port": "443",
        "@ssl": "true",
        alerts: [{ riskcode: "1", alert: "warning" }],
      }],
    }, { target }),
    /risk alert/i,
  );
});

test("one exact target with no risk alerts has a closed semantic verdict", () => {
  const verdict = analyzeZapJsonReport({
    "@version": "2.16.1",
    "@generated": generatedAt,
    site: [{
      "@name": target,
      "@host": new URL(target).hostname,
      "@port": "443",
      "@ssl": "true",
      alerts: [],
    }],
  }, { target });
  assert.deepEqual(verdict, semanticVerdict);
});

test("candidate request remains pending and only authenticated provider can issue passed receipt", () => {
  const receipt = buildDastProviderReceipt({
    scanRequest,
    scanRequestSha256,
    providerProducer: provider,
    providerMetadataSha256,
    generatedAt,
  });
  assert.equal(scanRequest.status, "PENDING-PROVIDER-ATTESTATION");
  assert.equal(receipt.status, "passed");
  assert.equal(receipt.scanRequestSha256, scanRequestSha256);
  assert.deepEqual(receipt.consumerChallenge, consumerChallenge);
  assert.equal(validateDastProviderReceipt(receipt, {
    policy,
    scanRequest,
    scanRequestSha256,
    providerMetadata,
    providerMetadataSha256,
    providerRunId: provider.runId,
    providerRunAttempt: provider.runAttempt,
    now: generatedAt,
  }), receipt);
});

test("cross-run, nonce, request digest and candidate-repository provider substitutions reject", () => {
  const receipt = buildDastProviderReceipt({
    scanRequest,
    scanRequestSha256,
    providerProducer: provider,
    providerMetadataSha256,
    generatedAt,
  });
  assert.throws(
    () => validateDastProviderReceipt({ ...receipt, scanRequestSha256: "9".repeat(64) }, {
      policy,
      scanRequest,
      scanRequestSha256,
      providerMetadata,
      providerMetadataSha256,
      providerRunId: provider.runId,
      providerRunAttempt: provider.runAttempt,
      now: generatedAt,
    }),
    /scan request/i,
  );
  assert.throws(
    () => validateDastProviderReceipt({
      ...receipt,
      consumerChallenge: { ...receipt.consumerChallenge, challengeNonce: "9".repeat(64) },
    }, {
      policy,
      scanRequest,
      scanRequestSha256,
      providerMetadata,
      providerMetadataSha256,
      providerRunId: provider.runId,
      providerRunAttempt: provider.runAttempt,
      now: generatedAt,
    }),
    /challenge/i,
  );
  const selfPolicy = {
    ...policy,
    trustedProducer: { ...policy.trustedProducer, repository },
  };
  const selfMetadata = {
    ...providerMetadata,
    repository: { full_name: repository },
    head_repository: { full_name: repository },
  };
  assert.throws(
    () => validateDastProviderReceipt({
      ...receipt,
      provider: { ...receipt.provider, repository },
    }, {
      policy: selfPolicy,
      scanRequest,
      scanRequestSha256,
      providerMetadata: selfMetadata,
      providerMetadataSha256,
      providerRunId: provider.runId,
      providerRunAttempt: provider.runAttempt,
      now: generatedAt,
    }),
    /independent/i,
  );
});

test("Sigstore bundle is verified against GitHub public-good roots and exact provider identity", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "platform-dast-provider-attestation-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const receiptPath = path.join(directory, "dast-provider-verification.json");
  const bundlePath = path.join(directory, "dast-provider-attestation.bundle.jsonl");
  const verifierPath = path.join(directory, "gh");
  const argsPath = path.join(directory, "args.txt");
  const receiptBytes = `${JSON.stringify(buildDastProviderReceipt({
    scanRequest,
    scanRequestSha256,
    providerProducer: provider,
    providerMetadataSha256,
    generatedAt,
  }))}\n`;
  fs.writeFileSync(receiptPath, receiptBytes);
  fs.writeFileSync(bundlePath, "{}\n");
  const receiptSha256 = sha256(receiptBytes);
  const verifiedOutput = [{
    verificationResult: {
      signature: {
        certificate: {
          rawBytes: "synthetic certificate accepted only after fake verifier success",
          sourceRepository: providerRepository,
        },
      },
      verifiedTimestamps: [{ type: "transparency-log", integratedTime: 1 }],
      statement: {
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [{
          name: path.basename(receiptPath),
          digest: { sha256: receiptSha256 },
        }],
        predicate: {},
      },
    },
  }];
  fs.writeFileSync(verifierPath, `#!/bin/sh
printf '%s\n' "$@" > "$FAKE_GH_ARGS"
printf '%s' "$FAKE_GH_OUTPUT"
`, { mode: 0o700 });
  process.env.FAKE_GH_ARGS = argsPath;
  process.env.FAKE_GH_OUTPUT = JSON.stringify(verifiedOutput);
  const verified = verifyDastProviderAttestation({
    receiptPath,
    receiptSha256,
    bundlePath,
    policy,
    verifierBinary: verifierPath,
  });
  assert.equal(verified.verified, true);
  assert.equal(verified.offlineBundleVerified, true);
  const args = fs.readFileSync(argsPath, "utf8").trim().split("\n");
  assert.ok(args.includes("--bundle"));
  assert.ok(!args.includes("--custom-trusted-root"));
  assert.ok(args.includes(`${providerRepository}/${provider.workflowPath}`));
  assert.ok(args.includes(provider.workflowSha));

  process.env.FAKE_GH_OUTPUT = JSON.stringify([{
    ...verifiedOutput[0],
    verificationResult: {
      ...verifiedOutput[0].verificationResult,
      statement: {
        ...verifiedOutput[0].verificationResult.statement,
        subject: [{
          name: path.basename(receiptPath),
          digest: { sha256: "f".repeat(64) },
        }],
      },
    },
  }]);
  assert.throws(
    () => verifyDastProviderAttestation({
      receiptPath,
      receiptSha256,
      bundlePath,
      policy,
      verifierBinary: verifierPath,
    }),
    /does not cover/i,
  );
});
