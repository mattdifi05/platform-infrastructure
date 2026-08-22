import fs from "node:fs";
import crypto from "node:crypto";

const TRUSTED_REF_GUARD = "github.ref == 'refs/heads/main' && github.ref_protected == true";
const V1_INSTALL_ONLY_WORKFLOW_SHA256 = "c7fc3315fbf74b2e599ee31ad2d15b2224abb5a366aeb10cc832f45dbd7bc88e";
const V1_LOCAL_PRIVATE_WORKFLOW_SHA256 = "52b53e470926339dcbf80558cb438329854eccc8f9c852b71768de5dfe46f533";
const RUN_EVIDENCE_SECRET_FIXTURES = "postgres_superuser_password keycloak_db_password redis_password keycloak_admin_password nats_password minio_root_password grafana_admin_password projects_gateway_signing_keys control_center_vault_keys control_center_database_url smtp_password mariadb_root_password phpmyadmin_control_password alertmanager_webhook_token backup_signing_keys restic_password docker_action_runtime_intent_trust_key docker_action_backup_catalog docker_action_backup_job_execute docker_action_backup_prune_plan docker_action_backup_prune_apply docker_action_restore_drill_full docker_action_backup_offsite_sync docker_action_evidence_runtime_snapshot";
const RUN_EVIDENCE_ENV_OVERRIDE_KEYS = "DOMAIN PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256 ALERT_EMAIL_TO MAILER_FROM MAILER_REPLY_TO SMTP_HOST SMTP_USER";
const RUN_EVIDENCE_COMPOSE_VERSION = "5.3.1";
const RUN_EVIDENCE_COMPOSE_SHA256 = "f9ebc6ebdb19d769b793c245a736caaeb198c62587f13b25c660c13b4987f959";
const RUN_EVIDENCE_COMPOSE_ENV_LINES = [
  "DOMAIN=fixture.invalid",
  "PROJECT_SOURCE_DIR=../compose-source",
  "PHP_PROJECTS_DIR=../compose-source",
  "DOCKER_ACTION_ACTIVATION_INBOX=/srv/platform/provider-activation/inbox",
  "DOCKER_ACTION_RUNTIME_INTENT_FILE=/srv/platform/trust/runtime-intent.json",
  "DOCKER_ACTION_ACTIVE_RECEIPT_FILE=/srv/platform/trust/active-receipt.json",
  "DOCKER_ACTION_RUNTIME_INTENT_ID=intent.offline-compose-v2",
  `DOCKER_ACTION_ACTIVE_RECEIPT_SHA256=${"a".repeat(64)}`,
  `DOCKER_ACTION_COMBINED_RENDER_SHA256=${"b".repeat(64)}`,
  `PLATFORM_OPS_IMAGE=registry.example.invalid/platform/ops@sha256:${"f".repeat(64)}`,
  "PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY=registry.example.invalid/platform/backup-scheduler",
  `PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256=${"e".repeat(64)}`,
  "PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY=registry.example.invalid/platform/docker-action-broker",
  `PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256=${"c".repeat(64)}`,
  "PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_REPOSITORY=registry.example.invalid/platform/provider-activation",
  `PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_SHA256=${"d".repeat(64)}`,
  "ALERT_EMAIL_TO=qa@fixture.invalid",
  "MAILER_FROM=qa@fixture.invalid",
  "MAILER_REPLY_TO=qa@fixture.invalid",
  "SMTP_HOST=smtp.fixture.invalid",
  "SMTP_USER=qa",
];

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

export function runEvidenceWorkflowMismatches(workflowText) {
  const text = String(workflowText);
  const issues = [];
  const verify = jobBlock(text, "github-actions-run-evidence");
  if (!verify) return ["run evidence workflow is missing github-actions-run-evidence"];

  const rendererBlock = [
    "      - name: Install SHA-pinned Compose renderer",
    `          PLATFORM_TEST_DOCKER_COMPOSE_BIN: /tmp/platform-ci-docker-compose-v${RUN_EVIDENCE_COMPOSE_VERSION}`,
    `          PLATFORM_TEST_DOCKER_COMPOSE_SHA256: ${RUN_EVIDENCE_COMPOSE_SHA256}`,
    '          install -d -m 700 "$HOME/.docker/cli-plugins"',
    `            https://github.com/docker/compose/releases/download/v${RUN_EVIDENCE_COMPOSE_VERSION}/docker-compose-linux-x86_64`,
    `          printf '%s  %s\\n' "$PLATFORM_TEST_DOCKER_COMPOSE_SHA256" "$PLATFORM_TEST_DOCKER_COMPOSE_BIN" | sha256sum -c -`,
    '          install -m 700 "$PLATFORM_TEST_DOCKER_COMPOSE_BIN" "$HOME/.docker/cli-plugins/docker-compose"',
    "          compose_version=$(docker compose version --short)",
    `          test "$compose_version" = ${RUN_EVIDENCE_COMPOSE_VERSION}`,
  ];
  const rendererIndex = verify.indexOf(rendererBlock[0]);
  const verifyStepIndex = verify.indexOf("      - name: Verify completed enterprise infra run");
  const installIndex = verify.indexOf("install -m 0600 .env.vps.example .env");
  const fixtureIndex = verify.indexOf("mkdir -p ../compose-source secrets traefik/certs");
  const overrideBlock = [
    `          for key in ${RUN_EVIDENCE_ENV_OVERRIDE_KEYS}; do`,
    '            sed -i -E "/^${key}=/d" .env',
    "          done",
  ].join("\n");
  const overrideIndex = verify.indexOf(overrideBlock, installIndex);
  const envFixtureStart = verify.indexOf("          {\n", installIndex);
  const envFixtureEnd = verify.indexOf("          } >> .env", envFixtureStart);
  const envFixtureBlock = envFixtureStart >= 0 && envFixtureEnd > envFixtureStart
    ? verify.slice(envFixtureStart, envFixtureEnd + "          } >> .env".length)
    : "";
  const cleanIndex = verify.indexOf('test -z "$(git status --porcelain=v1 --untracked-files=all)"');
  const verifierIndex = verify.indexOf("node ./scripts/infra-ops.mjs github-actions-run-evidence");
  const filesystemFixture = [
    `for name in ${RUN_EVIDENCE_SECRET_FIXTURES}; do`,
    `printf 'ci-placeholder-%s-00000000000000000000000000000000\\n' "$name" > "secrets/$name.txt"`,
    "chmod 600 secrets/*.txt",
    "chmod 640 secrets/alertmanager_webhook_token.txt",
    `printf 'dummy-cert\\n' > traefik/certs/local-cert.pem`,
    `printf 'dummy-key\\n' > traefik/certs/local-key.pem`,
    "chmod 644 traefik/certs/local-cert.pem traefik/certs/local-key.pem",
  ];
  const exactEnvFixture = RUN_EVIDENCE_COMPOSE_ENV_LINES.every((line) =>
    (verify.match(new RegExp(line.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) ?? []).length === 1
      && envFixtureBlock.includes(`'${line}'`));

  if (rendererIndex < 0
      || rendererBlock.some((line) => !verify.includes(line))
      || verify.indexOf(rendererBlock[0], rendererIndex + 1) >= 0
      || !(rendererIndex < verifyStepIndex && verifyStepIndex < fixtureIndex)) {
    issues.push("run evidence must install the exact SHA-pinned Compose renderer before verification");
  }

  if (fixtureIndex < 0
      || filesystemFixture.some((line) => !verify.includes(line))
      || overrideIndex < 0
      || verify.indexOf(overrideBlock, overrideIndex + 1) >= 0
      || !exactEnvFixture
      || envFixtureBlock.length === 0) {
    issues.push("run evidence must append the exact deterministic non-secret Compose identity fixture once");
  }
  if (!(installIndex >= 0
      && fixtureIndex < installIndex
      && installIndex < overrideIndex
      && overrideIndex < envFixtureStart
      && envFixtureEnd < cleanIndex
      && cleanIndex < verifierIndex)) {
    issues.push("run evidence must materialize its Compose identity fixture before clean-check and verification");
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
    || !/dast-runtime-receipt-policy\.mjs/.test(dast)
    || !/mode\]=dast-countersign/.test(dast)) {
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
  const promotionIndex = deploy.indexOf("node ./scripts/activation-promotion-policy.mjs");
  const providerReplayIndex = deploy.lastIndexOf("node ./scripts/dast-runtime-receipt-policy.mjs");
  const sshCredentialIndex = deploy.indexOf("- name: Install SSH key");
  if (
    promotionIndex < 0
    || providerReplayIndex < 0
    || sshCredentialIndex < 0
    || promotionIndex >= sshCredentialIndex
    || providerReplayIndex >= sshCredentialIndex
  ) {
    issues.push("provider replay and activation promotion v2 must both finish before SSH credential installation");
  }
  if (
    !deploy.includes("platform-activation-receipt/v3")
    || !deploy.includes(".releaseBundleSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_RELEASE_BUNDLE_SHA256")
    || !deploy.includes(".dockerActivationEnvelopeSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SHA256")
    || !deploy.includes(".dastAuthorizationSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_DAST_ACTIVATION_AUTHORIZATION_SHA256")
    || !deploy.includes(".dastChainSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_DAST_CHAIN_SHA256")
  ) {
    issues.push("deploy-vps must validate the exact receipt v3 release, envelope, authorization and chain identities");
  }
  return issues;
}

export function v1InstallOnlyWorkflowMismatches(workflowText) {
  const text = String(workflowText);
  const issues = [];
  if (crypto.createHash("sha256").update(text, "utf8").digest("hex") !== V1_INSTALL_ONLY_WORKFLOW_SHA256) {
    issues.push("V1 install-only workflow bytes differ from the frozen candidate-specific controller");
  }
  const install = jobBlock(text, "install-v1");
  if (!install) return ["V1 install-only workflow is missing install-v1"];
  if (!/^  workflow_dispatch:\s*$/m.test(text) || /^  (?:pull_request|push|schedule|workflow_call):\s*$/m.test(text)) {
    issues.push("V1 install-only workflow must be manual-only");
  }
  if (!/^permissions:\s*\n  contents:\s*read\s*$/m.test(text)
    || /^\s{2}(?:actions|attestations|checks|deployments|id-token|packages|pull-requests|statuses):/m.test(text)) {
    issues.push("V1 install-only workflow permissions must be exactly contents read");
  }
  if (!install.includes(`    if: github.event_name == 'workflow_dispatch' && ${TRUSTED_REF_GUARD}\n`)) {
    issues.push("V1 install-only workflow lacks the exact protected-main manual guard");
  }
  if (!/environment:\s*\n\s+name:\s+production/.test(install)) {
    issues.push("V1 install-only workflow lacks the production environment gate");
  }
  if (!/concurrency:\s*\n\s+group:\s+infra-production-deploy\s*\n\s+cancel-in-progress:\s*false/.test(install)) {
    issues.push("V1 install-only workflow must serialize with full production deployment");
  }
  if (!/uses:\s*actions\/checkout@[a-f0-9]{40}[\s\S]*?with:\s*\n\s+ref:\s*\$\{\{ github\.sha \}\}\s*\n\s+persist-credentials:\s*false/.test(install)) {
    issues.push("V1 install-only workflow must checkout github.sha without persisted credentials");
  }
  if (!install.includes('test "$APPROVED_CANDIDATE_SHA" = 832bf2baec47055342af7e7f73425444381b91e0')
    || !install.includes('test "$APPROVED_CONTROLLER_SHA" = "$GITHUB_SHA"')
    || !install.includes('test "$(git rev-parse --verify \'HEAD^{commit}\')" = "$GITHUB_SHA"')
    || !install.includes('test -z "$(git status --porcelain=v1 --untracked-files=all)"')) {
    issues.push("V1 install-only workflow does not bind the frozen candidate approval and exact clean controller");
  }
  if (/^\s+needs:|continue-on-error:\s*true/m.test(install)) {
    issues.push("V1 install-only workflow must have no cross-job dependency or continue-on-error path");
  }
  const sinks = text.match(/^\s+sh \.\/scripts\/deploy-v1-install-only\.sh > "\$receipt"\s*$/gm) ?? [];
  if (sinks.length !== 1 || !/^\s+sh \.\/scripts\/deploy-v1-install-only\.sh > "\$receipt"\s*$/m.test(install)) {
    issues.push("V1 install-only workflow must contain exactly one fixed install-only sink");
  }
  if (!install.includes("node ./scripts/v1-brownfield-install-receipt.mjs verify")
    || !install.includes("--candidateCommit 832bf2baec47055342af7e7f73425444381b91e0")
    || !install.includes("--candidateTree 91cee2380809cb0691b9ac47cafa2a673d434caa")
    || !install.includes("--sourceArchiveSha256 6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007")) {
    issues.push("V1 install-only workflow does not revalidate the exact root receipt");
  }
  if (/\bdocker\b|platform-activation-broker|deploy-vps\.sh|release-admission|dast-zap|sigstore|promoter|activation-request/i.test(install)) {
    issues.push("V1 install-only workflow crosses the activation or Docker boundary");
  }
  const productionEnvironments = text.match(/environment:\s*\n\s+name:\s+production/g) ?? [];
  if (productionEnvironments.length !== 1) {
    issues.push("V1 install-only workflow must expose exactly one production environment job");
  }
  return issues;
}

export function v1LocalPrivateWorkflowMismatches(workflowText) {
  const text = String(workflowText);
  const issues = [];
  if (crypto.createHash("sha256").update(text, "utf8").digest("hex") !== V1_LOCAL_PRIVATE_WORKFLOW_SHA256) {
    issues.push("V1 LOCAL_PRIVATE workflow bytes differ from the frozen candidate-specific controller");
  }
  const activation = jobBlock(text, "activate-v1-local-private");
  if (!activation) return ["V1 LOCAL_PRIVATE workflow is missing activate-v1-local-private"];
  if (!/^  workflow_dispatch:\s*$/m.test(text) || /^  (?:pull_request|push|schedule|workflow_call):\s*$/m.test(text)) {
    issues.push("V1 LOCAL_PRIVATE workflow must be manual-only");
  }
  if (!/^permissions:\s*\n  contents:\s*read\s*$/m.test(text)
    || /^\s{2}(?:actions|attestations|checks|deployments|id-token|packages|pull-requests|statuses):/m.test(text)) {
    issues.push("V1 LOCAL_PRIVATE workflow permissions must be exactly contents read");
  }
  if (!activation.includes(`    if: github.event_name == 'workflow_dispatch' && ${TRUSTED_REF_GUARD}\n`)) {
    issues.push("V1 LOCAL_PRIVATE workflow lacks the exact protected-main manual guard");
  }
  if (!/environment:\s*\n\s+name:\s+production/.test(activation)) {
    issues.push("V1 LOCAL_PRIVATE workflow lacks the production environment gate");
  }
  if (!/concurrency:\s*\n\s+group:\s+infra-production-deploy\s*\n\s+cancel-in-progress:\s*false/.test(activation)) {
    issues.push("V1 LOCAL_PRIVATE workflow must serialize with full production deployment");
  }
  if (!/uses:\s*actions\/checkout@[a-f0-9]{40}[\s\S]*?with:\s*\n\s+ref:\s*\$\{\{ github\.sha \}\}\s*\n\s+persist-credentials:\s*false/.test(activation)) {
    issues.push("V1 LOCAL_PRIVATE workflow must checkout github.sha without persisted credentials");
  }
  if (!activation.includes('test "$APPROVED_CANDIDATE_SHA" = 832bf2baec47055342af7e7f73425444381b91e0')
    || !activation.includes('test "$APPROVED_CONTROLLER_SHA" = "$GITHUB_SHA"')
    || !activation.includes('test "$(git rev-parse --verify \'HEAD^{commit}\')" = "$GITHUB_SHA"')
    || !activation.includes('test -z "$(git status --porcelain=v1 --untracked-files=all)"')) {
    issues.push("V1 LOCAL_PRIVATE workflow does not bind the frozen candidate approval and exact clean controller");
  }
  if (/^\s+needs:|continue-on-error:\s*true/m.test(activation)) {
    issues.push("V1 LOCAL_PRIVATE workflow must have no cross-job dependency or continue-on-error path");
  }
  const sinks = text.match(/^\s+sh \.\/scripts\/deploy-v1-local-private\.sh > "\$receipt"\s*$/gm) ?? [];
  if (sinks.length !== 1 || !/^\s+sh \.\/scripts\/deploy-v1-local-private\.sh > "\$receipt"\s*$/m.test(activation)) {
    issues.push("V1 LOCAL_PRIVATE workflow must contain exactly one fixed activation sink");
  }
  if (!activation.includes("node ./scripts/v1-local-private-control-receipt.mjs verify")
    || !activation.includes("--candidateCommit 832bf2baec47055342af7e7f73425444381b91e0")
    || !activation.includes("--candidateTree 91cee2380809cb0691b9ac47cafa2a673d434caa")
    || !activation.includes("--sourceArchiveSha256 6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007")
    || !activation.includes('controller_sha256="$(sha256sum ./scripts/v1-local-private-control.py')
    || !activation.includes('unit_sha256="$(sha256sum ./systemd/platform-v1-local-private-control.service')
    || !activation.includes('--controllerSha256 "$controller_sha256"')
    || !activation.includes('--unitSha256 "$unit_sha256"')) {
    issues.push("V1 LOCAL_PRIVATE workflow does not revalidate the exact root receipt");
  }
  const artifacts = text.match(/uses:\s*actions\/upload-artifact@[a-f0-9]{40}/g) ?? [];
  if (artifacts.length !== 1
    || !activation.includes("path: ${{ runner.temp }}/v1-local-private-control-receipt.json")
    || !activation.includes("if-no-files-found: error")) {
    issues.push("V1 LOCAL_PRIVATE workflow must publish exactly one required receipt artifact");
  }
  if (/platform-activation-broker|deploy-vps\.sh|release-admission|dast-zap|sigstore|promoter|activation-request|docker-action/i.test(activation)) {
    issues.push("V1 LOCAL_PRIVATE workflow crosses the enterprise provider activation boundary");
  }
  const productionEnvironments = text.match(/environment:\s*\n\s+name:\s+production/g) ?? [];
  if (productionEnvironments.length !== 1) {
    issues.push("V1 LOCAL_PRIVATE workflow must expose exactly one production environment job");
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
    || (deploy.match(/node \.\/scripts\/dast-runtime-receipt-policy\.mjs/g) ?? []).length !== 1
  ) {
    issues.push("deploy must cryptographically revalidate the exact request, report archive and provider receipt before mutation");
  }
  const promotedNames = "release-activation.bundle release-activation-bundle-manifest.json docker-runtime-activation.dsse.json dast-activation-authorization.json activation-admission.jsonl sigstore-trusted-root.json activation-promotion-receipt.json";
  if (
    !deploy.includes("-eq 7")
    || !deploy.includes(promotedNames)
    || !deploy.includes('--releaseBundle "$PROMOTED/release-activation.bundle"')
    || !deploy.includes('--releaseBundleManifest "$PROMOTED/release-activation-bundle-manifest.json"')
    || !deploy.includes('--dockerActivationEnvelope "$PROMOTED/docker-runtime-activation.dsse.json"')
    || !deploy.includes('--dastAuthorization "$PROMOTED/dast-activation-authorization.json"')
    || !deploy.includes('--dastProviderReceipt "$DAST_RECEIPT"')
    || !deploy.includes('--dastProviderMetadata "$DAST_PROVIDER_METADATA"')
    || !deploy.includes('--dastProviderAttestationBundle "$DAST_PROVIDER_ATTESTATION_BUNDLE"')
    || !deploy.includes('test "$(wc -c < "$RESULT" | tr -d \' \')" -le 1048576')
  ) {
    issues.push("deploy must consume the exact bounded seven-file activation promotion v2 handoff");
  }
  const opsStart = deploy.indexOf("docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges");
  const opsEnd = deploy.indexOf('"$OPS_IMAGE_ID" deploy-vps > "$ACTIVATION_RECEIPT"', opsStart);
  const opsInvocation = opsStart >= 0 && opsEnd > opsStart ? deploy.slice(opsStart, opsEnd) : "";
  if (
    !opsInvocation.includes("dast-provider-verification.json:ro")
    || !opsInvocation.includes("dast-activation-authorization.json:ro")
    || !opsInvocation.includes("release-activation-bundle-manifest.json:ro")
    || /dast-scan-request|dast-provider-run|dast-provider-attestation|sigstore-trusted-root|docker-runtime-activation\.dsse|release-activation\.bundle/.test(opsInvocation)
  ) {
    issues.push("trusted ops sink must receive only the closed receipt, authorization and manifest evidence projection");
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
