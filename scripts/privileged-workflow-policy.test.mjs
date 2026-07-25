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
assert.deepEqual(deploymentPrerequisiteMismatches(deployment), []);
assert.deepEqual(dastReceiptWiringMismatches(deployment), []);
assert.match(deploymentPrerequisiteMismatches(deployment.replace("      - dast-zap\n", "")).join(" "), /exact .* prerequisite set/);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace("      - release-admission\n", "")).join(" "),
  /run-bound DAST receipt/,
);
assert.match(
  deploymentPrerequisiteMismatches(deployment.replace("    if: github.event_name == 'workflow_dispatch'\n    environment:\n      name: staging", "    if: false\n    environment:\n      name: staging")).join(" "),
  /unconditionally/,
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
  deploymentPrerequisiteMismatches(deployment.replace("        run: |\n          PROMOTED=", "        run: sh ./scripts/deploy-vps.sh\n          PROMOTED=")).join(" "),
  /must not invoke .* directly/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("staging_receipt_sha256:", "removed_staging_receipt_sha256:")).join(" "),
  /staging receipt input/,
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
  dastReceiptWiringMismatches(deployment.replace("name: dast-verification-${{ github.run_id }}", "name: caller-selected-dast")).join(" "),
  /run-bound DAST artifact/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("--dastReceipt \"$DAST_RECEIPT\"", "--dastReceipt /tmp/unbound.json")).join(" "),
  /deploy must revalidate/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("DAST_RECEIPT_SHA256: ${{ needs.dast-zap.outputs.dast_receipt_sha256 }}", "DAST_RECEIPT_SHA256: deadbeef")).join(" "),
  /DAST receipt hash output/,
);
assert.match(
  dastReceiptWiringMismatches(deployment.replace("test \"$DAST_TARGET\" = \"$CANONICAL_TARGET\"", "true")).join(" "),
  /canonical target/,
);

const total = fixtures.length * 3 + 1 + 17;
process.stdout.write(`privileged workflow policy tests passed ${total}/${total}\n`);
