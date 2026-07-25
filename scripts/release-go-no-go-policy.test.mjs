#!/usr/bin/env node
import assert from "node:assert/strict";
import { releaseEvidenceAdmissionReady } from "./release-go-no-go-policy.mjs";

const base = {
  mode: "evidence",
  status: "passed",
  admission: { artifactVerification: "passed", deploymentAdmission: "EXTERNAL-PENDING" },
  artifacts: {
    admissionReceipt: {
      kind: "platform-release-artifact-verification/v1",
      status: "EXTERNAL-PENDING",
      sha256: "a".repeat(64),
      artifactReceiptSha256: "b".repeat(64),
      providerMetadataSha256: "c".repeat(64),
      repository: "owner/repo",
      commitSha: "d".repeat(40),
      treeSha: "e".repeat(40),
      providerRunId: "123456",
      providerRunAttempt: 2,
    },
  },
};
assert.equal(releaseEvidenceAdmissionReady(base), false, "status=passed must not override EXTERNAL-PENDING");
assert.equal(releaseEvidenceAdmissionReady({ ...base, admission: { artifactVerification: "passed", deploymentAdmission: "READY" } }), false, "artifact receipt is not a deployment receipt");
const ready = structuredClone(base);
ready.admission.deploymentAdmission = "READY";
ready.artifacts.admissionReceipt.kind = "platform-trusted-deployment-admission/v1";
ready.artifacts.admissionReceipt.status = "READY";
const verified = {
  status: "READY",
  deploymentReceiptSha256: "a".repeat(64),
  artifactReceiptSha256: "b".repeat(64),
  providerMetadataSha256: "c".repeat(64),
  repository: "owner/repo",
  commitSha: "d".repeat(40),
  treeSha: "e".repeat(40),
  providerRunId: "123456",
  providerRunAttempt: 2,
};
assert.equal(releaseEvidenceAdmissionReady(ready), false, "report shape alone must never be sufficient");
assert.equal(releaseEvidenceAdmissionReady(ready, verified), true);
delete ready.artifacts.admissionReceipt.sha256;
assert.equal(releaseEvidenceAdmissionReady(ready, verified), false, "unbound deployment receipt must fail");
ready.artifacts.admissionReceipt.sha256 = "a".repeat(64);
assert.equal(releaseEvidenceAdmissionReady(ready, { ...verified, providerRunId: "654321" }), false,
  "authenticated provider run identity must match the report");
assert.equal(releaseEvidenceAdmissionReady(ready, { ...verified, deploymentReceiptSha256: "f".repeat(64) }), false,
  "the directly verified deployment receipt bytes must match the report");
process.stdout.write("release go/no-go admission tests passed 7/7\n");
