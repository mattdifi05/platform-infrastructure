#!/usr/bin/env node
import assert from "node:assert/strict";
import { trustedProducerConfiguration, validateTrustedProviderRun } from "./trusted-provider-run-policy.mjs";

const policy = {
  status: "READY",
  trustedVerifierChannel: "external-admission-controller/prod",
  selfAssertedAnnotationsAccepted: false,
  trustedProducer: {
    repository: "owner/trusted-admission",
    workflowPath: ".github/workflows/produce-admission.yml",
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
  },
};
const run = {
  id: 123456,
  run_attempt: 2,
  repository: { full_name: policy.trustedProducer.repository },
  head_repository: { full_name: policy.trustedProducer.repository },
  path: policy.trustedProducer.workflowPath,
  head_branch: "main",
  head_sha: "a".repeat(40),
  event: "workflow_dispatch",
  status: "completed",
  conclusion: "success",
};
const producer = {
  ...policy.trustedProducer,
  runId: "123456",
  runAttempt: 2,
  workflowSha: "a".repeat(40),
};

assert.deepEqual(trustedProducerConfiguration(policy), policy.trustedProducer);
assert.deepEqual(validateTrustedProviderRun(run, { policy, runId: "123456", runAttempt: "2" }), producer);
assert.deepEqual(validateTrustedProviderRun(run, {
  policy, runId: "123456", runAttempt: "2", deploymentReceipt: { producer },
}), producer);
assert.throws(() => validateTrustedProviderRun({ ...run, path: ".github/workflows/attacker.yml" }, {
  policy, runId: "123456", runAttempt: "2",
}), /does not match/);
assert.throws(() => validateTrustedProviderRun({ ...run, conclusion: "failure" }, {
  policy, runId: "123456", runAttempt: "2",
}), /does not match/);
assert.throws(() => validateTrustedProviderRun(run, {
  policy, runId: "123456", runAttempt: "1",
}), /does not match/);
assert.throws(() => validateTrustedProviderRun(run, {
  policy, runId: "123456", runAttempt: "2", deploymentReceipt: { producer: { ...producer, runId: "999999" } },
}), /does not bind/);
assert.throws(() => trustedProducerConfiguration({
  status: "EXTERNAL-PENDING", trustedVerifierChannel: null, selfAssertedAnnotationsAccepted: false,
}), /EXTERNAL-PENDING/);

process.stdout.write("trusted provider run policy tests passed 8/8\n");
