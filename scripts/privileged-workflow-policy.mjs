import fs from "node:fs";

const TRUSTED_REF_GUARD = "github.ref == 'refs/heads/main' && github.ref_protected == true";

function jobBlock(text, jobName) {
  const jobStart = text.search(new RegExp(`^  ${jobName}:`, "m"));
  if (jobStart < 0) return null;
  const followingJob = text.slice(jobStart + 1).search(/^  [A-Za-z0-9_-]+:/m);
  return followingJob < 0 ? text.slice(jobStart) : text.slice(jobStart, jobStart + 1 + followingJob);
}

function exactNeeds(jobText) {
  const match = jobText.match(/^    needs:[ \t]*\r?\n((?:^      - [A-Za-z0-9_-]+[ \t]*\r?\n)+)/m);
  return match ? [...match[1].matchAll(/^      - ([A-Za-z0-9_-]+)[ \t]*$/gm)].map((item) => item[1]) : [];
}

export function privilegedWorkflowMismatches(workflowText, { jobName, forbidTagTrigger = false } = {}) {
  const text = String(workflowText);
  const issues = [];
  const jobText = jobBlock(text, jobName);
  if (!jobText) return [`missing privileged job ${jobName}`];
  if (!jobText.includes(TRUSTED_REF_GUARD)) {
    issues.push(`${jobName} lacks the exact protected-main admission guard`);
  }
  if (!/environment:\s*\n\s+name:\s+production/.test(jobText)) {
    issues.push(`${jobName} lacks the production environment gate`);
  }
  if (!/uses:\s*actions\/checkout@[a-f0-9]{40}[\s\S]*?with:\s*\n\s+ref:\s*\$\{\{ github\.sha \}\}\s*\n\s+persist-credentials:\s*false/.test(jobText)) {
    issues.push(`${jobName} must checkout github.sha without persisted credentials`);
  }
  if (forbidTagTrigger && /^\s{2}push:/m.test(text)) {
    issues.push("privileged release workflow must not admit unverified tag triggers");
  }
  return issues;
}

export function deploymentPrerequisiteMismatches(workflowText) {
  const text = String(workflowText);
  const issues = [];
  const deploy = jobBlock(text, "deploy-vps");
  const dast = jobBlock(text, "dast-zap");
  const admission = jobBlock(text, "release-admission");
  if (!deploy || !dast || !admission) return ["deployment DAG is missing deploy-vps, dast-zap, or release-admission"];

  const needs = exactNeeds(deploy);
  const expectedNeeds = ["enterprise-readiness", "release-admission", "dast-zap"];
  if (JSON.stringify(needs) !== JSON.stringify(expectedNeeds)) {
    issues.push("deploy-vps must depend on the exact enterprise-readiness, release-admission, and dast-zap prerequisite set");
  }
  if (/if:\s*.*(?:always\(\)|!\s*cancelled\(\))/.test(deploy)) {
    issues.push("deploy-vps must preserve default fail/skip propagation from every prerequisite");
  }
  if (!dast.includes(`    if: github.event_name == 'workflow_dispatch' && ${TRUSTED_REF_GUARD}\n`)) {
    issues.push("dast-zap must use the exact protected-main manual release guard");
  }
  if (JSON.stringify(exactNeeds(dast)) !== JSON.stringify(["enterprise-readiness", "release-admission"])
    || !/environment:\s*\n\s+name:\s+staging/.test(dast)
    || !/dast-zap-baseline\.sh/.test(dast)
    || !/dast-admission-policy\.mjs/.test(dast)
    || !/dast-runtime-receipt-policy\.mjs/.test(dast)) {
    issues.push("dast-zap must consume the exact readiness and release-admission prerequisites and bind both runtime verification and activation admission receipts");
  }
  if (!/^    needs: enterprise-readiness\s*$/m.test(admission)
    || !admission.includes(TRUSTED_REF_GUARD)
    || !/(?:release-artifact-gate\.sh|node \.\/scripts\/infra-ops\.mjs release-artifact-gate)/.test(admission)) {
    issues.push("release-admission must consume readiness and enforce protected-main artifact admission");
  }
  if (/continue-on-error:\s*true/.test(`${dast}\n${admission}`)) {
    issues.push("DAST and release admission may not continue on error");
  }
  const legacyDeployCalls = text.match(/run:\s*sh \.\/scripts\/deploy-vps\.sh/g) ?? [];
  if (legacyDeployCalls.length !== 0) {
    issues.push("production mutation must not invoke the candidate checkout deploy-vps.sh directly");
  }
  const trustedOpsSinks = text.match(/^\s+"\$OPS_IMAGE_ID" deploy-vps > "\$ACTIVATION_RECEIPT"\s*$/gm) ?? [];
  if (trustedOpsSinks.length !== 1 || !/^\s+"\$OPS_IMAGE_ID" deploy-vps > "\$ACTIVATION_RECEIPT"\s*$/m.test(deploy)) {
    issues.push("production mutation must have exactly one trusted ops image deploy-vps entrypoint sink inside the gated deploy-vps job");
  }
  const productionEnvironments = text.match(/environment:\s*\n\s+name:\s+production/g) ?? [];
  if (productionEnvironments.length !== 1) {
    issues.push("enterprise-infra must expose exactly one production environment job");
  }
  return issues;
}

export function dastReceiptWiringMismatches(workflowText) {
  const text = String(workflowText);
  const issues = [];
  const release = jobBlock(text, "release-admission");
  const dast = jobBlock(text, "dast-zap");
  const deploy = jobBlock(text, "deploy-vps");
  if (!release || !dast || !deploy) return ["DAST receipt workflow jobs are missing"];

  if (JSON.stringify(exactNeeds(dast)) !== JSON.stringify(["enterprise-readiness", "release-admission"])) {
    issues.push("dast-zap lacks the exact release admission dependency");
  }
  if (!dast.includes(`    if: github.event_name == 'workflow_dispatch' && ${TRUSTED_REF_GUARD}\n`)) {
    issues.push("dast-zap lacks the protected-main producer guard");
  }
  if (
    !release.includes("staging_receipt_sha256: ${{ steps.artifacts.outputs.staging_receipt_sha256 }}")
    || !release.includes("test \"${#staging_receipts[@]}\" -eq 1")
    || !release.includes('STAGING_RECEIPT_SHA256="$(sha256sum "${staging_receipts[0]}"')
    || !release.includes('test "$(jq -er \'.runtimeIntentSha256\' "${staging_receipts[0]}")" = "$RUNTIME_INTENT_SHA256"')
    || !release.includes('install -m 600 "$STAGING_RECEIPT" "${RUNNER_TEMP}/admitted-deployment-receipts/trusted-staging-deployment.json"')
  ) {
    issues.push("release admission does not select, hash-bind, validate and hand off exactly one provider staging receipt");
  }
  const stagingValidationCalls = dast.match(/--stagingReceipt "\$STAGING_RECEIPT"/g) ?? [];
  if (
    stagingValidationCalls.length !== 4
    || !dast.includes('--stagingReceiptSha256 "$STAGING_RECEIPT_SHA256"')
    || !dast.includes('--providerMetadata "$TRUSTED_PROVIDER_METADATA"')
    || !dast.includes('--artifactReceipt "$ARTIFACT_RECEIPT"')
    || !dast.includes('--runtimeIntentSha256 "$RUNTIME_INTENT_SHA256"')
  ) {
    issues.push("dast-zap lacks exact provider-authenticated staging receipt validation");
  }
  if (
    !dast.includes('test "$DAST_TARGET" = "$CANONICAL_TARGET"')
    || !dast.includes("curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-redirs 0")
    || !dast.includes('--preProbe "$PRE_PROBE"')
    || !dast.includes('--postProbe "$POST_PROBE"')
    || !dast.includes('--scanStartedAt "$SCAN_STARTED_AT"')
    || !dast.includes('--scanFinishedAt "$SCAN_FINISHED_AT"')
  ) {
    issues.push("dast-zap does not bind the canonical target to the provider probe and scan");
  }
  if (
    !dast.includes("dast_scan_request_sha256: ${{ steps.request.outputs.dast_scan_request_sha256 }}")
    || !dast.includes("dast_report_artifact_id: ${{ steps.upload-request.outputs.artifact-id }}")
    || !dast.includes("dast_report_artifact_sha256: ${{ steps.upload-request.outputs.artifact-digest }}")
    || !dast.includes('--scanRequestOutput "$DAST_SCAN_REQUEST"')
    || dast.includes('--receiptOutput "$DAST_RECEIPT"')
    || !dast.includes("PENDING-PROVIDER-ATTESTATION")
    || !dast.includes("id: upload-request")
    || !dast.includes("path: ${{ runner.temp }}/dast-scan-request/")
    || !dast.includes("inputs[dast_report_artifact_sha256]=${DAST_REPORT_ARTIFACT_SHA256}")
    || !dast.includes("mode]=dast-countersign")
    || !dast.includes("repository: ${{ steps.dast-provider.outputs.repository }}")
    || !dast.includes('--scanRequest "$DAST_SCAN_REQUEST"')
    || !dast.includes('--reportArtifactId "$DAST_REPORT_ARTIFACT_ID"')
    || !dast.includes('--reportArtifactSha256 "$DAST_REPORT_ARTIFACT_SHA256"')
    || !dast.includes('--dastProviderMetadata "$DAST_PROVIDER_METADATA"')
    || !dast.includes('--dastAttestationBundle "$DAST_BUNDLE"')
    || !dast.includes("--attestationVerifier /usr/local/bin/gh")
    || !dast.includes("name: dast-verification-${{ github.run_id }}")
    || !dast.includes("path: ${{ runner.temp }}/dast-verification/")
    || !dast.includes("if-no-files-found: error")
  ) {
    issues.push("dast-zap lacks independent provider authorization over the exact report artifact and final handoff");
  }
  if (
    !dast.includes("--workflowPath .github/workflows/enterprise-infra.yml")
    || !dast.includes('--sourceRef "$GITHUB_REF"')
    || !dast.includes('--runId "$GITHUB_RUN_ID"')
    || !dast.includes('--runAttempt "$GITHUB_RUN_ATTEMPT"')
    || !dast.includes("--job dast-zap")
  ) {
    issues.push("DAST receipt producer identity is not bound to the current workflow run");
  }
  if (
    !deploy.includes("name: dast-verification-${{ github.run_id }}")
    || !deploy.includes("DAST_SCAN_REQUEST_SHA256: ${{ needs.dast-zap.outputs.dast_scan_request_sha256 }}")
    || !deploy.includes("DAST_REPORT_ARTIFACT_SHA256: ${{ needs.dast-zap.outputs.dast_report_artifact_sha256 }}")
    || !deploy.includes("DAST_RECEIPT_SHA256: ${{ needs.dast-zap.outputs.dast_receipt_sha256 }}")
    || !deploy.includes('--scanRequest "$DAST_SCAN_REQUEST"')
    || !deploy.includes('--reportArtifactSha256 "$DAST_REPORT_ARTIFACT_SHA256"')
    || !deploy.includes('--dastReceipt "$DAST_RECEIPT"')
    || !deploy.includes('--dastReceiptSha256 "$DAST_RECEIPT_SHA256"')
    || !deploy.includes('--dastAttestationBundle "$DAST_ATTESTATION_BUNDLE"')
    || !deploy.includes('--attestationVerifier /usr/local/bin/gh')
    || !deploy.includes("DEPLOY_DAST_REPORT_ARTIFACT_SHA256:")
    || (deploy.match(/node \.\/scripts\/dast-runtime-receipt-policy\.mjs/g) ?? []).length !== 1
  ) {
    issues.push("deploy must cryptographically revalidate the exact request, report archive and provider receipt before mutation");
  }
  if (/continue-on-error:\s*true/.test(`${release}\n${dast}\n${deploy}`)) {
    issues.push("release, DAST and deploy receipt gates may not continue on error");
  }
  return issues;
}

export function assertPrivilegedWorkflow(pathname, options) {
  const issues = privilegedWorkflowMismatches(fs.readFileSync(pathname, "utf8"), options);
  if (issues.length) throw new Error(issues.join("; "));
}
