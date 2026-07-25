#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "enterprise-infra.yml"), "utf8");
const producerWorkflow = fs.readFileSync(path.join(root, ".github", "workflows", "release-attestation.yml"), "utf8");

function wiringIssues(source) {
  const issues = [];
  const requireText = (text, label) => { if (!source.includes(text)) issues.push(label); };
  for (const input of [
    "trusted_admission_run_id:",
    "trusted_admission_run_attempt:",
    "release_attestation_run_attempt:",
    "artifact_receipt_sha256:",
    "deployment_receipt_sha256:",
  ]) requireText(input, `missing dispatch input ${input}`);
  requireText("name: platform-trusted-deployment-admission", "trusted provider artifact name is not fixed");
  requireText("run-id: ${{ inputs.trusted_admission_run_id }}", "trusted provider run identity is not bound");
  requireText("repository: ${{ steps.provider.outputs.repository }}", "trusted provider repository is not policy-bound");
  requireText("trusted-provider-run-policy.mjs", "trusted producer workflow/ref/run metadata is not authenticated");
  requireText('--metadataSha256 "$TRUSTED_PROVIDER_METADATA_SHA256"', "trusted producer metadata hash is not handed off");
  requireText('--providerRunId "$TRUSTED_PROVIDER_RUN_ID"', "deployment receipt is not bound to provider run ID");
  requireText('--providerRunAttempt "$TRUSTED_PROVIDER_RUN_ATTEMPT"', "deployment receipt is not bound to provider run attempt");
  requireText(".path == \".github/workflows/release-attestation.yml\"", "release producer workflow path is not authenticated");
  requireText(".head_sha == $sha", "release producer commit is not authenticated");
  requireText(".status == \"completed\" and .conclusion == \"success\"", "release producer completion is not authenticated");
  requireText("test \"${#artifact_receipts[@]}\" -eq 1", "artifact receipt cardinality is not exact");
  requireText("test \"${#deployment_receipts[@]}\" -eq 1", "deployment receipt cardinality is not exact");
  requireText("test \"${#source_archives[@]}\" -eq 1", "source archive cardinality is not exact");
  requireText("'.sourceArchiveSha256' \"${artifact_receipts[0]}\"", "artifact receipt is not bound to the selected source archive");
  requireText("'.sourceArchiveSha256' \"${deployment_receipts[0]}\"", "deployment receipt is not bound to the selected source archive");
  requireText("= \"$EXPECTED_ARTIFACT_RECEIPT_SHA256\"", "artifact receipt hash is not checked after download");
  requireText("= \"$EXPECTED_DEPLOYMENT_RECEIPT_SHA256\"", "deployment receipt hash is not checked after download");
  requireText("--artifactVerificationOnly", "artifact-only cryptographic gate is absent");
  requireText('--sourceArchive "$RELEASE_SOURCE_ARCHIVE"', "fresh artifact verification does not consume the exact source archive");
  requireText('--receiptOutput "$REVERIFIED_ARTIFACT_RECEIPT"', "fresh cryptographic output is not captured");
  requireText('sha256sum "$REVERIFIED_ARTIFACT_RECEIPT"', "fresh cryptographic output hash is not checked");
  requireText('cmp -- "$REVERIFIED_ARTIFACT_RECEIPT" "$ARTIFACT_RECEIPT"', "downloaded receipt is not byte-equal to fresh verification output");
  requireText('--artifactReceipt "$REVERIFIED_ARTIFACT_RECEIPT"', "deployment policy does not consume the fresh cryptographic output");
  requireText('--sourceArchiveSha256 "$RELEASE_SOURCE_ARCHIVE_SHA256"', "deployment policy is not bound to the exact source archive");
  requireText('exact-source-archive.tar"', "admitted handoff does not preserve the verified source archive");
  const policyCalls = source.match(/node \.\/scripts\/deployment-receipt-policy\.mjs/g) ?? [];
  if (policyCalls.length !== 2) issues.push("trusted receipt policy must run before upload and again before deploy");
  requireText("name: admitted-deployment-receipts-${{ github.run_id }}", "validated receipt handoff artifact is not run-bound");
  requireText("needs:\n      - enterprise-readiness\n      - release-admission\n      - dast-zap", "deploy DAG does not require readiness, admission and DAST");
  for (const variable of [
    "DEPLOY_ARTIFACT_RECEIPT_PATH:",
    "DEPLOY_ARTIFACT_RECEIPT_SHA256:",
    "DEPLOY_ADMISSION_RECEIPT_PATH:",
    "DEPLOY_ADMISSION_RECEIPT_SHA256:",
    "DEPLOY_TRUSTED_PROVIDER_METADATA_PATH:",
    "DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256:",
    "DEPLOY_TRUSTED_PROVIDER_RUN_ID:",
    "DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT:",
  ]) requireText(variable, `deploy consumer is missing ${variable}`);
  return issues;
}

assert.deepEqual(wiringIssues(workflow), []);
assert.notDeepEqual(wiringIssues(workflow.replace("DEPLOY_ADMISSION_RECEIPT_SHA256:", "REMOVED_ADMISSION_SHA:")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("name: platform-trusted-deployment-admission", "name: caller-selected-artifact")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("test \"${#deployment_receipts[@]}\" -eq 1", "test \"${#deployment_receipts[@]}\" -ge 1")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("test \"${#source_archives[@]}\" -eq 1", "test \"${#source_archives[@]}\" -ge 1")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("--artifactVerificationOnly", "--skipDeploymentAdmission")), []);
assert.notDeepEqual(wiringIssues(workflow.replace('--sourceArchive "$RELEASE_SOURCE_ARCHIVE"', "--sourceArchive /tmp/caller-selected.tar")), []);
assert.notDeepEqual(wiringIssues(workflow.replace('cmp -- "$REVERIFIED_ARTIFACT_RECEIPT" "$ARTIFACT_RECEIPT"', "true")), []);
assert.notDeepEqual(wiringIssues(workflow.replace("repository: ${{ steps.provider.outputs.repository }}", "repository: owner/caller-selected")), []);
assert.notDeepEqual(wiringIssues(workflow.replaceAll('--providerRunAttempt "$TRUSTED_PROVIDER_RUN_ATTEMPT"', '--providerRunAttempt "1"')), []);
assert.notDeepEqual(wiringIssues(workflow.replace("DEPLOY_TRUSTED_PROVIDER_METADATA_PATH:", "REMOVED_PROVIDER_METADATA_PATH:")), []);

const manifestAttestation = producerWorkflow.indexOf("- name: Attest release subject manifest provenance");
const finalizedReceipt = producerWorkflow.indexOf('--receiptOutput "reports/release/release-artifact-admission-${GITHUB_RUN_ID}.json"');
assert.ok(manifestAttestation >= 0 && finalizedReceipt > manifestAttestation,
  "producer must finalize the artifact receipt only after manifest attestation");
assert.doesNotMatch(
  producerWorkflow.slice(0, manifestAttestation),
  /--receipt(?:Output)?\s+"reports\/release\/release-artifact-admission-/,
  "pre-attestation generation must not mint an artifact receipt",
);

process.stdout.write("trusted receipt workflow wiring tests passed 25/25; provider channel remains EXTERNAL-PENDING\n");
