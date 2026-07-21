#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import { assertDeploymentAdmissionConfigured } from "./deployment-admission-policy.mjs";

const policy = JSON.parse(fs.readFileSync("governance/deployment-admission.json", "utf8"));
const rego = fs.readFileSync("security/admission/cosign-digest-policy.rego", "utf8");
assert.equal(policy.status, "EXTERNAL-PENDING");
assert.equal(policy.trustedVerifierChannel, null);
assert.equal(policy.selfAssertedAnnotationsAccepted, false);
assert.match(rego, /EXTERNAL-PENDING/);
assert.doesNotMatch(rego, /metadata\.annotations/);
assert.throws(() => assertDeploymentAdmissionConfigured(policy), /EXTERNAL-PENDING/);
assert.throws(
  () => assertDeploymentAdmissionConfigured({ status: "READY", trustedVerifierChannel: null, selfAssertedAnnotationsAccepted: true }),
  /EXTERNAL-PENDING/,
);
process.stdout.write("deployment admission policy tests passed 7/7; state=EXTERNAL-PENDING\n");
