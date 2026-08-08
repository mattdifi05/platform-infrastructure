#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  dastReceiptWiringMismatches,
  deploymentPrerequisiteMismatches,
  privilegedWorkflowMismatches,
} from "./privileged-workflow-policy.mjs";

const fixtures = [
  [".github/workflows/enterprise-infra.yml", "deploy-vps", false],
  [".github/workflows/enterprise-vps-evidence.yml", "vps-host-evidence", false],
  [".github/workflows/enterprise-live-evidence.yml", "production-live-evidence", false],
  [".github/workflows/release-attestation.yml", "github-sigstore-release-evidence", true],
];

for (const [pathname, jobName, forbidTagTrigger] of fixtures) {
  const text = fs.readFileSync(pathname, "utf8");
  assert.deepEqual(privilegedWorkflowMismatches(text, { jobName, forbidTagTrigger }), []);
  assert.match(
    privilegedWorkflowMismatches(text.replaceAll("github.ref_protected == true", "true"), { jobName, forbidTagTrigger }).join(" "),
    /protected-main/,
  );
  assert.match(
    privilegedWorkflowMismatches(text.replaceAll("persist-credentials: false", "persist-credentials: true"), { jobName, forbidTagTrigger }).join(" "),
    /persisted credentials/,
  );
}

const release = fs.readFileSync(".github/workflows/release-attestation.yml", "utf8");
assert.match(
  privilegedWorkflowMismatches(`${release}\n  push:\n    tags: ['v*']\n`, { jobName: "github-sigstore-release-evidence", forbidTagTrigger: true }).join(" "),
  /tag triggers/,
);

const deployment = fs.readFileSync(".github/workflows/enterprise-infra.yml", "utf8");
const infraOps = fs.readFileSync("scripts/infra-ops.mjs", "utf8");
assert.deepEqual(deploymentPrerequisiteMismatches(deployment), []);
assert.deepEqual(dastReceiptWiringMismatches(deployment), []);
assert.match(deploymentPrerequisiteMismatches(deployment.replace("      - dast-zap\n", "")).join(" "), /exact .* prerequisite set/);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace("      - release-admission\n", "")).join(" "),
  /runtime verification and activation admission receipts/,
);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace(
    "    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected == true\n    permissions:",
    "    if: true\n    permissions:",
  )).join(" "),
  /protected-main manual release guard/,
);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace("    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected == true\n    environment:\n      name: production", "    if: ${{ always() }}\n    environment:\n      name: production")).join(" "),
  /fail\/skip propagation/,
);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace("      - name: Run ZAP baseline against staging", "    continue-on-error: true\n      - name: Run ZAP baseline against staging")).join(" "),
  /continue on error/,
);
assert.match(
  deploymentPrerequisiteMismatches(`${deployment}\n  alternate-deploy:\n    environment:\n      name: production\n    steps:\n      - run: sh ./scripts/deploy-vps.sh\n`).join(" "),
  /must not invoke .* directly|exactly one production environment/,
);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace('            "$OPS_IMAGE_ID" deploy-vps', '            "$OPS_IMAGE_ID" inspect')).join(" "),
  /exactly one trusted ops image/,
);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace("        run: |\n          ACTIVATION_RECEIPT=", "        run: sh ./scripts/deploy-vps.sh\n          ACTIVATION_RECEIPT=")).join(" "),
  /must not invoke .* directly/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace(
    'STAGING_RECEIPT_SHA256="$(sha256sum "${staging_receipts[0]}"',
    'STAGING_RECEIPT_SHA256="caller-selected"',
  )).join(" "),
  /provider staging receipt/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("      - release-admission\n    if: github.event_name == 'workflow_dispatch' && github.ref", "    if: github.event_name == 'workflow_dispatch' && github.ref")).join(" "),
  /release admission dependency/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("--stagingReceipt \"$STAGING_RECEIPT\"", "--stagingReceipt /tmp/unbound.json")).join(" "),
  /staging receipt validation/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("--scanRequestOutput \"$DAST_SCAN_REQUEST\"", "--receiptOutput \"$DAST_RECEIPT\"")).join(" "),
  /independent provider authorization/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replaceAll("--dastReceipt \"$DAST_RECEIPT\"", "--dastReceipt /tmp/unbound.json")).join(" "),
  /independent provider authorization|cryptographically revalidate/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replaceAll("DAST_RECEIPT_SHA256: ${{ needs.dast-zap.outputs.dast_receipt_sha256 }}", "DAST_RECEIPT_SHA256: deadbeef")).join(" "),
  /cryptographically revalidate/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("test \"$DAST_TARGET\" = \"$CANONICAL_TARGET\"", "true")).join(" "),
  /canonical target/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("inputs[dast_report_artifact_sha256]=${DAST_REPORT_ARTIFACT_SHA256}", "inputs[dast_report_artifact_sha256]=caller-selected")).join(" "),
  /independent provider authorization/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("--reportArtifactSha256 \"$DAST_REPORT_ARTIFACT_SHA256\"", "--reportArtifactSha256 deadbeef")).join(" "),
  /independent provider authorization|cryptographically revalidate/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("--dastAttestationBundle \"$DAST_BUNDLE\"", "--dastAttestationBundle /tmp/unbound.bundle")).join(" "),
  /independent provider authorization/,
);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace("platform-activation-receipt/v3", "platform-activation-receipt/v2")).join(" "),
  /receipt v3/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace('--dockerActivationEnvelope "$PROMOTED/docker-runtime-activation.dsse.json"', "--legacyBundle /tmp/activation.bundle")).join(" "),
  /seven-file activation promotion v2/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace(
    '            -v "$DEPLOY_DAST_PROVIDER_RECEIPT_PATH:/run/platform-deploy/dast-provider-verification.json:ro"',
    '            -v "$DEPLOY_DAST_PROVIDER_RECEIPT_PATH:/run/platform-deploy/dast-provider-verification.json:ro" \\\n            -v "$DAST_PROVIDER_METADATA:/run/platform-deploy/dast-provider-run.json:ro"',
  )).join(" "),
  /closed receipt, authorization and manifest/,
);

const releasePolicyStep = deployment.match(
  /      - name: Release artifact and admission policy tests\n[\s\S]*?(?=\n      - name: Upload supply-chain evidence reports)/,
)?.[0] ?? "";
for (const command of [
  "node --test scripts/hosted-preparation-provider-conformance.test.mjs",
  "node scripts/dast-deploy-sink.test.mjs",
  "node scripts/t16-policy.mjs",
  "sh scripts/cloudflare-origin-lock-ufw-test.sh",
]) {
  assert.equal(
    releasePolicyStep.split(command).length - 1,
    1,
    `${command} must appear exactly once in the offline Release policy step`,
  );
}

const brokerInvocation = infraOps.match(
  /const dockerActionBrokerTestFiles = \[([\s\S]*?)\];[\s\S]*?run\(process\.execPath, \[\n\s+"--test",\n\s+"--test-concurrency=1",\n\s+\.\.\.dockerActionBrokerTestFiles,\n\s+\], \{ cwd: infraRoot \}\);/,
);
assert.ok(brokerInvocation, "testing-hygiene must run the complete broker suite serially");
assert.deepEqual(
  [...brokerInvocation[1].matchAll(/"([^"]+\.test\.mjs)"/g)].map((match) => match[1]),
  [
    "scripts/docker-action-contract.test.mjs",
    "scripts/docker-action-broker.test.mjs",
    "scripts/docker-action-client.test.mjs",
    "scripts/docker-action-worker.test.mjs",
    "scripts/docker-action-broker.boundary.test.mjs",
    "scripts/docker-action-helper-plan.test.mjs",
    "scripts/docker-action-v2-fixtures.test.mjs",
    "scripts/docker-action-activation.test.mjs",
  ],
);
assert.match(
  infraOps,
  /return \["tests", "state", "status"\]\.flatMap\(\(directory\) =>/,
  "Control Center hygiene must include package-owned tests, state, and status suites",
);

const total = fixtures.length * 3 + 1 + 29;
process.stdout.write(`privileged workflow policy tests passed ${total}/${total}\n`);
