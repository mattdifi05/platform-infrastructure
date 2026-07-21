#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "enterprise-infra.yml"), "utf8");

function wiringIssues(source) {
  const issues = [];
  const requireText = (text, label) => { if (!source.includes(text)) issues.push(label); };
  for (const input of [
    "trusted_admission_run_id:",
    "artifact_receipt_sha256:",
    "deployment_receipt_sha256:",
  ]) requireText(input, `missing dispatch input ${input}`);
  requireText("name: platform-trusted-deployment-admission", "trusted provider artifact name is not fixed");
  requireText("run-id: ${{ inputs.trusted_admission_run_id }}", "trusted provider run identity is not bound");
  requireText("test \"${#artifact_receipts[@]}\" -eq 1", "artifact receipt cardinality is not exact");
  requireText("test \"${#deployment_receipts[@]}\" -eq 1", "deployment receipt cardinality is not exact");
  requireText("= \"$EXPECTED_ARTIFACT_RECEIPT_SHA256\"", "artifact receipt hash is not checked after download");
  requireText("= \"$EXPECTED_DEPLOYMENT_RECEIPT_SHA256\"", "deployment receipt hash is not checked after download");
  requireText("--artifactVerificationOnly", "artifact-only cryptographic gate is absent");
  const policyCalls = source.match(/node \.\/scripts\/deployment-receipt-policy\.mjs/g) ?? [];
  if (policyCalls.length !== 2) issues.push("trusted receipt policy must run before upload and again before deploy");
  requireText("name: admitted-deployment-receipts-${{ github.run_id }}", "validated receipt handoff artifact is not run-bound");
  requireText("needs:\n      - enterprise-readiness\n      - release-admission\n      - dast-zap", "deploy DAG does not require readiness, admission and DAST");
  for (const variable of [
    "DEPLOY_ARTIFACT_RECEIPT_PATH:",
    "DEPLOY_ARTIFACT_RECEIPT_SHA256:",
    "DEPLOY_ADMISSION_RECEIPT_PATH:",
    "DEPLOY_ADMISSION_RECEIPT_SHA256:",
  ]) requireText(variable, `deploy consumer is missing ${variable}`);
  return issues;
}

assert.deepEqual(wiringIssues(workflow), []);
assert.notDeepEqual(wiringIssues(workflow.replace("DEPLOY_ADMISSION_RECEIPT_SHA256:", "REMOVED_ADMISSION_SHA:")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("name: platform-trusted-deployment-admission", "name: caller-selected-artifact")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("test \"${#deployment_receipts[@]}\" -eq 1", "test \"${#deployment_receipts[@]}\" -ge 1")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("--artifactVerificationOnly", "--skipDeploymentAdmission")), []);

process.stdout.write("trusted receipt workflow wiring tests passed 5/5; provider channel remains EXTERNAL-PENDING\n");
