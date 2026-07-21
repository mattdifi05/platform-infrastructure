#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import { assertDeploymentAdmissionConfigured } from "./deployment-admission-policy.mjs";

const policy = JSON.parse(fs.readFileSync("governance/deployment-admission.json", "utf8"));
const rego = fs.readFileSync("security/admission/cosign-digest-policy.rego", "utf8");
assert.equal(policy.status, "EXTERNAL-PENDING");
assert.equal(policy.trustedVerifierChannel, null);
assert.deepEqual(policy.trustedProducer, { repository: null, workflowPath: null, sourceRef: null, event: null });
assert.equal(policy.selfAssertedAnnotationsAccepted, false);
assert.match(rego, /EXTERNAL-PENDING/);
assert.doesNotMatch(rego, /metadata\.annotations/);
assert.throws(() => assertDeploymentAdmissionConfigured(policy), /EXTERNAL-PENDING/);
assert.throws(
  () => assertDeploymentAdmissionConfigured({ status: "READY", trustedVerifierChannel: null, selfAssertedAnnotationsAccepted: true }),
  /EXTERNAL-PENDING/,
);
assert.throws(
  () => assertDeploymentAdmissionConfigured({
    status: "READY", trustedVerifierChannel: "external/prod", selfAssertedAnnotationsAccepted: false,
    trustedProducer: { repository: null, workflowPath: null, sourceRef: null, event: null },
  }),
  /EXTERNAL-PENDING/,
);
process.stdout.write("deployment admission policy tests passed 9/9; state=EXTERNAL-PENDING\n");
