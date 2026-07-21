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
    },
  },
};
assert.equal(releaseEvidenceAdmissionReady(base), false, "status=passed must not override EXTERNAL-PENDING");
assert.equal(releaseEvidenceAdmissionReady({ ...base, admission: { artifactVerification: "passed", deploymentAdmission: "READY" } }), false, "artifact receipt is not a deployment receipt");
const ready = structuredClone(base);
ready.admission.deploymentAdmission = "READY";
ready.artifacts.admissionReceipt.kind = "platform-trusted-deployment-admission/v1";
ready.artifacts.admissionReceipt.status = "READY";
assert.equal(releaseEvidenceAdmissionReady(ready), true);
delete ready.artifacts.admissionReceipt.sha256;
assert.equal(releaseEvidenceAdmissionReady(ready), false, "unbound deployment receipt must fail");
process.stdout.write("release go/no-go admission tests passed 4/4\n");
