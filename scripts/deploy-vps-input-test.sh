#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/deploy-vps-input-test.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
TEST_ROOT="$TMP/ops-image"
mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/governance" "$TMP/bin"
cp "$SCRIPT_DIR"/*.mjs "$SCRIPT_DIR"/*.sh "$TEST_ROOT/scripts/"
[ -f "$TEST_ROOT/scripts/docker-action-contract.mjs" ] || {
  [ -n "${DOCKER_ACTION_CONTRACT_PATH:-}" ] && [ -f "$DOCKER_ACTION_CONTRACT_PATH" ] || {
    echo "Integration blocker: authoritative docker-action-contract.mjs is absent." >&2
    exit 78
  }
  cp "$DOCKER_ACTION_CONTRACT_PATH" "$TEST_ROOT/scripts/docker-action-contract.mjs"
}
cp -R "$ROOT/vendor" "$TEST_ROOT/vendor"
chmod 0555 "$TEST_ROOT/scripts"/*.mjs "$TEST_ROOT/scripts"/*.sh

export FIXTURE_DIR="$TMP"
export FIXTURE_ROOT="$ROOT"
node --input-type=module <<'JS'
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const requestPolicy = await import(pathToFileURL(`${process.env.FIXTURE_ROOT}/scripts/activation-request.mjs`));
const receiptPolicy = await import(pathToFileURL(`${process.env.FIXTURE_ROOT}/scripts/activation-receipt-policy.mjs`));
const dockerActionContract = await import(pathToFileURL(
  process.env.DOCKER_ACTION_CONTRACT_PATH ?? `${process.env.FIXTURE_ROOT}/scripts/docker-action-contract.mjs`,
));
const dockerActionFixtures = await import(pathToFileURL(
  process.env.DOCKER_ACTION_FIXTURES_PATH ?? `${process.env.FIXTURE_ROOT}/scripts/docker-action-v2-fixtures.mjs`,
));
const bundlePolicy = await import(pathToFileURL(`${process.env.FIXTURE_ROOT}/scripts/activation-bundle.mjs`));
const runtimePolicy = await import(pathToFileURL(`${process.env.FIXTURE_ROOT}/scripts/runtime-intent-policy.mjs`));
const { buildActivationRequest, buildTrustedReleaseContext } = requestPolicy;
const { activationRequestSha256 } = receiptPolicy;
const { exactNoHostedLockBytes, validateActivationBundleManifest } = bundlePolicy;
const { canonicalJson, runtimeIntentSha256 } = runtimePolicy;

const directory = process.env.FIXTURE_DIR;
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const writeJson = (name, value) => {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  fs.writeFileSync(path.join(directory, name), bytes, { mode: 0o600 });
  return { document: value, sha256: hash(bytes) };
};
const repository = "owner/repo";
const commitSha = "a".repeat(40);
const treeSha = "b".repeat(40);
const appImage = `ghcr.io/owner/app@sha256:${"c".repeat(64)}`;
const schedulerImage = `ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:${"9".repeat(64)}`;
const schedulerImageId = `sha256:${"a".repeat(64)}`;
const opsImage = `ghcr.io/owner/platform-infrastructure-ops@sha256:${"d".repeat(64)}`;
const opsImageId = `sha256:${"e".repeat(64)}`;
const policy = {
  version: 1,
  status: "READY",
  trustedVerifierChannel: "external-admission-controller/prod",
  trustedOpsImageRepository: "ghcr.io/owner/platform-infrastructure-ops",
  requiredReceiptKind: "platform-trusted-deployment-admission/v1",
  selfAssertedAnnotationsAccepted: false,
  trustedProducer: {
    repository: "owner/trusted-admission",
    workflowPath: ".github/workflows/produce-admission.yml",
    workflowSha: "4".repeat(40),
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
  },
};
const policyArtifact = writeJson("policy.json", policy);
const artifactDocument = {
  version: 1,
  kind: "platform-release-artifact-verification/v1",
  status: "EXTERNAL-PENDING",
  artifactVerification: "passed",
  deploymentAdmission: "EXTERNAL-PENDING",
  usageScope: "artifact-verification-only",
  repository,
  commitSha,
  sourceArchiveSha256: "f".repeat(64),
  generatedAt: "2026-07-21T00:00:00.000Z",
  manifestSha256: "1".repeat(64),
  sbomSha256: "2".repeat(64),
  subjects: [
    { key: "APP_IMAGE", image: appImage },
    { key: "PLATFORM_BACKUP_SCHEDULER_IMAGE", image: schedulerImage },
  ],
  subjectVerificationReceipts: [
    { key: "APP_IMAGE", image: appImage, registry: {
      rootDigest: `sha256:${"c".repeat(64)}`, descriptorSha256: "c".repeat(64),
      platforms: [{ platform: "linux/amd64", digest: `sha256:${"1".repeat(64)}`, size: 100, imageId: `sha256:${"8".repeat(64)}`, configSize: 50, manifestArtifactSha256: "2".repeat(64) }],
    } },
    { key: "PLATFORM_BACKUP_SCHEDULER_IMAGE", image: schedulerImage, registry: {
      rootDigest: `sha256:${"9".repeat(64)}`, descriptorSha256: "9".repeat(64),
      platforms: [{ platform: "linux/amd64", digest: `sha256:${"3".repeat(64)}`, size: 100, imageId: schedulerImageId, configSize: 50, manifestArtifactSha256: "4".repeat(64) }],
    } },
  ],
  provenance: {
    verificationFingerprint: "3".repeat(64),
    manifestVerificationFingerprint: "4".repeat(64),
  },
};
const artifact = writeJson("artifact.json", artifactDocument);
const runtimeIntent = {
  version: 2,
  kind: "platform-runtime-intent/v2",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256: artifactDocument.sourceArchiveSha256,
  projectName: "platform_infra_vps",
  environmentSha256: "5".repeat(64),
  hostedWorkloadLockSha256: null,
  sourceRenderSha256: "6".repeat(64),
  combinedComposeSha256: "7".repeat(64),
  persistentVolumes: [{
    name: "enterprise_local_registry_data",
    createdAt: "2026-07-21T00:00:00.000Z",
    driver: "local",
    scope: "local",
    options: {},
    labels: {
      "platform.infrastructure.managed": "true",
      "platform.infrastructure.purpose": "local-registry",
    },
    mountpoint: "/var/lib/docker/volumes/enterprise_local_registry_data/_data",
    owner: { uid: 0, gid: 0, mode: "0755" },
  }],
  services: [
    {
      service: "app",
      image: appImage,
      admission: { kind: "artifact-subject", subjectKey: "APP_IMAGE" },
      expectedLocalImageId: `sha256:${"8".repeat(64)}`,
    },
    {
      service: "backup-scheduler",
      image: schedulerImage,
      admission: { kind: "artifact-subject", subjectKey: "PLATFORM_BACKUP_SCHEDULER_IMAGE" },
      expectedLocalImageId: schedulerImageId,
    },
  ],
  targetServingServices: ["app"],
};
const deploymentDocument = {
  version: 1,
  kind: "platform-trusted-deployment-admission/v1",
  status: "READY",
  artifactVerification: "passed",
  deploymentAdmission: "READY",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256: artifactDocument.sourceArchiveSha256,
  artifactVerificationReceiptSha256: artifact.sha256,
  manifestSha256: artifactDocument.manifestSha256,
  sbomSha256: artifactDocument.sbomSha256,
  generatedAt: "2026-07-21T00:00:00.000Z",
  decisionId: "decision:12345678",
  verifier: {
    channel: policy.trustedVerifierChannel,
    fingerprint: "9".repeat(64),
    selfAsserted: false,
    verifiedAt: "2026-07-21T00:00:00.000Z",
  },
  producer: { ...policy.trustedProducer, runId: "123456", runAttempt: 2 },
  opsRunner: {
    image: opsImage,
    imageId: opsImageId,
    verificationFingerprint: "0".repeat(64),
    providerAttested: true,
  },
  runtimeIntent,
  runtimeIntentSha256: runtimeIntentSha256(runtimeIntent),
  deploymentTarget: {
    environment: "production",
    host: "example.internal",
    projectName: "platform_infra_vps",
  },
  privilegedRuntime: {
    activationBroker: {
      path: "/usr/local/libexec/platform-activation-broker",
      version: 1,
      sha256: "a".repeat(64),
      providerAttested: true,
    },
    originFirewallHelper: {
      path: "/usr/local/libexec/platform-origin-firewall",
      version: 1,
      sha256: "b".repeat(64),
      providerAttested: true,
    },
    workloadEgressHelper: {
      path: "/usr/local/libexec/platform-workload-egress-firewall",
      version: 1,
      sha256: "c".repeat(64),
      providerAttested: true,
    },
  },
};
const deployment = writeJson("deployment.json", deploymentDocument);
const provider = writeJson("provider.json", {
  id: 123456,
  run_attempt: 2,
  repository: { full_name: policy.trustedProducer.repository },
  head_repository: { full_name: policy.trustedProducer.repository },
  path: policy.trustedProducer.workflowPath,
  head_branch: "main",
  head_sha: policy.trustedProducer.workflowSha,
  event: "workflow_dispatch",
  status: "completed",
  conclusion: "success",
});
const dast = writeJson("dast.json", {
  version: 1,
  kind: "platform-dast-verification/v1",
  status: "passed",
  repository,
  commitSha,
  treeSha,
  runtimeIntentSha256: deploymentDocument.runtimeIntentSha256,
  generatedAt: "2026-07-21T00:00:00.000Z",
  target: { url: "https://staging.example.com/", origin: "https://staging.example.com" },
  report: {
    name: "zap-baseline.json",
    sha256: "e".repeat(64),
    sizeBytes: 4096,
  },
  consumerChallenge: {
    consumerRepository: repository,
    consumerRunId: "789012",
    consumerRunAttempt: 3,
    consumerJob: "deploy-vps",
    challengeNonce: "d".repeat(64),
  },
});
const context = buildTrustedReleaseContext({
  deploymentReceipt: deploymentDocument,
  artifactReceiptSha256: artifact.sha256,
  deploymentReceiptSha256: deployment.sha256,
  providerMetadataSha256: provider.sha256,
  dastReceiptSha256: dast.sha256,
  providerRunId: "123456",
  providerRunAttempt: 2,
  providerChallenge: "d".repeat(64),
});
const releaseContextSha256 = hash(Buffer.from(canonicalJson(context)));
const requestId = `activation:${deployment.sha256}:${releaseContextSha256}`;
const entryHashes = {
  "artifact-verification.json": artifact.sha256,
  "combined-compose.json": runtimeIntent.combinedComposeSha256,
  "dast-admission.json": dast.sha256,
  "environment.env": runtimeIntent.environmentSha256,
  "exact-source-archive.tar": runtimeIntent.sourceArchiveSha256,
  "hosted-workloads.lock.json": hash(exactNoHostedLockBytes()),
  "source-compose.json": runtimeIntent.sourceRenderSha256,
  "trusted-deployment-admission.json": deployment.sha256,
  "trusted-provider-run.json": provider.sha256,
};
const manifest = {
  schema: "platform-activation-bundle-manifest/v1",
  requestId,
  releaseContextSha256,
  runtimeIntentSha256: deploymentDocument.runtimeIntentSha256,
  entries: Object.keys(entryHashes).sort().map((name) => ({ name, sha256: entryHashes[name], sizeBytes: 1 })),
};
const manifestSha256 = validateActivationBundleManifest(manifest, {
  requestId,
  releaseContextSha256,
  runtimeIntentSha256: deploymentDocument.runtimeIntentSha256,
  expectedEntryHashes: entryHashes,
}).sha256;
const manifestArtifact = writeJson("bundle-manifest.json", manifest);
const activationRequest = buildActivationRequest({
  policy: policyArtifact,
  artifactReceipt: artifact,
  artifactReceiptSha256: artifact.sha256,
  deploymentReceipt: deployment,
  deploymentReceiptSha256: deployment.sha256,
  providerMetadata: provider,
  providerMetadataSha256: provider.sha256,
  dastReceipt: dast,
  dastReceiptSha256: dast.sha256,
  bundleManifest: manifestArtifact,
  bundleDescriptor: {
    schema: "platform-activation-bundle-descriptor/v1",
    sha256: "e".repeat(64),
    sizeBytes: 4096,
    manifestSha256,
  },
  activationAdmission: {
    schema: "platform-activation-admission-descriptor/v1",
    sha256: "f".repeat(64),
    sizeBytes: 8192,
  },
  repository,
  commitSha,
  treeSha,
  targetHost: "example.internal",
  environmentSha256: runtimeIntent.environmentSha256,
  providerRunId: "123456",
  providerRunAttempt: 2,
  consumerRunId: "789012",
  consumerRunAttempt: 3,
  sshPort: 2222,
});
const activationNow = Date.now();
const activationReceipt = {
  schema: "platform-activation-receipt/v2",
  status: "ACTIVE",
  activatedAt: new Date(activationNow - 60_000).toISOString(),
  requestId: activationRequest.requestId,
  requestSha256: activationRequestSha256(activationRequest),
  releaseContextSha256: activationRequest.releaseContextSha256,
  runtimeIntentSha256: activationRequest.runtimeIntentSha256,
  bundleSha256: activationRequest.bundle.sha256,
  activationAdmissionSha256: activationRequest.activationAdmission.sha256,
  deploymentTarget: activationRequest.deploymentTarget,
  broker: activationRequest.privilegedRuntime.activationBroker,
  activeReceipt: null,
  activeReceiptSha256: null,
  operationResults: activationRequest.requestedOperations.map((name) => ({
    name,
    status: name === "rollback-on-failure" ? "not-required" : "passed",
  })),
};
const activeReceipt = dockerActionFixtures.buildRawActiveReceiptV2({ now: activationNow });
activeReceipt.activationBundleSha256 = activationRequest.bundle.sha256;
activeReceipt.releaseId = activationRequest.dockerRuntime.releaseId;
activeReceipt.candidateId = activationRequest.dockerRuntime.candidateId;
activeReceipt.targetId = activationRequest.dockerRuntime.targetId;
activeReceipt.treeSha256 = activationRequest.dockerRuntime.treeSha256;
activeReceipt.environment = activationRequest.deploymentTarget.environment;
activeReceipt.sourceRenderSha256 = activationRequest.releaseContext.sourceRenderSha256;
activeReceipt.combinedRenderSha256 = activationRequest.releaseContext.combinedRenderSha256;
activeReceipt.dastChainSha256 = activationRequest.releaseContext.receipts.dastSha256;
for (const container of Object.values(activeReceipt.resources.containers)) {
  container.labels["com.platform.runtime.candidate-id"] = activeReceipt.candidateId;
  container.labels["com.platform.runtime.source-render-sha256"] = activeReceipt.sourceRenderSha256;
}
const normalizedActiveReceipt = dockerActionContract.normalizeActiveReceipt(activeReceipt, {
  now: activationNow,
});
activationReceipt.activeReceipt = activeReceipt;
activationReceipt.activeReceiptSha256 = dockerActionContract.sha256(
  dockerActionContract.canonicalJson(normalizedActiveReceipt),
);
fs.writeFileSync(path.join(directory, "broker-receipt.json"), `${canonicalJson(activationReceipt)}\n`, { mode: 0o600 });
writeJson("fixture.json", {
  artifactSha256: artifact.sha256,
  deploymentSha256: deployment.sha256,
  providerSha256: provider.sha256,
  dastSha256: dast.sha256,
  environmentSha256: runtimeIntent.environmentSha256,
  manifestSha256,
  commitSha,
  treeSha,
});
JS

fixture() {
  node -e "const f=require(process.argv[1]);process.stdout.write(String(f[process.argv[2]]))" "$TMP/fixture.json" "$1"
}

printf '%s\n' '[example.internal]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILBajvJtpsX+LmnBbwAcOXdb9LRHK+d9WJlVKLaAklDO' > "$TMP/known-hosts"
printf '%s\n' 'test-only-private-key' > "$TMP/ssh-key"
chmod 600 "$TMP/known-hosts" "$TMP/ssh-key"
cp "$TMP/policy.json" "$TEST_ROOT/governance/deployment-admission.json"

cat > "$TMP/bin/ssh" <<'SH'
#!/usr/bin/env sh
set -eu
printf '%s\n' "$@" > "$FAKE_SSH_ARGS"
cat > "$FAKE_SSH_STDIN"
if [ "${BROKER_EXIT:-0}" -ne 0 ]; then exit "$BROKER_EXIT"; fi
cat "$FAKE_SSH_RECEIPT"
SH
chmod 0555 "$TMP/bin/ssh"

export FAKE_SSH_ARGS="$TMP/ssh-args"
export FAKE_SSH_STDIN="$TMP/ssh-stdin"

run_client() {
  env \
    PATH="$TMP/bin:$PATH" \
    PLATFORM_TRUSTED_OPS_RUNNER=1 \
    PLATFORM_OPS_CODE_ROOT="$TEST_ROOT" \
    FAKE_SSH_RECEIPT="${FAKE_SSH_RECEIPT_OVERRIDE:-$TMP/broker-receipt.json}" \
    DEPLOY_ADMISSION_POLICY_PATH="$TMP/policy.json" \
    DEPLOY_REMOTE=deploy@example.internal \
    DEPLOY_SSH_PORT=2222 \
    DEPLOY_SSH_KEY_PATH="$TMP/ssh-key" \
    DEPLOY_KNOWN_HOSTS_PATH="$TMP/known-hosts" \
    DEPLOY_REPO=owner/repo \
    DEPLOY_RELEASE_SHA="$(fixture commitSha)" \
    DEPLOY_RELEASE_TREE="$(fixture treeSha)" \
    DEPLOY_ENVIRONMENT_SHA256="$(fixture environmentSha256)" \
    DEPLOY_ARTIFACT_RECEIPT_PATH="$TMP/artifact.json" \
    DEPLOY_ARTIFACT_RECEIPT_SHA256="$(fixture artifactSha256)" \
    DEPLOY_ADMISSION_RECEIPT_PATH="$TMP/deployment.json" \
    DEPLOY_ADMISSION_RECEIPT_SHA256="$(fixture deploymentSha256)" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_PATH="$TMP/provider.json" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256="$(fixture providerSha256)" \
    DEPLOY_TRUSTED_PROVIDER_RUN_ID=123456 \
    DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT=2 \
    DEPLOY_DAST_RECEIPT_PATH="$TMP/dast.json" \
    DEPLOY_DAST_RECEIPT_SHA256="$(fixture dastSha256)" \
    DEPLOY_ACTIVATION_BUNDLE_MANIFEST_PATH="$TMP/bundle-manifest.json" \
    DEPLOY_ACTIVATION_BUNDLE_SHA256="$(printf 'e%.0s' $(seq 1 64))" \
    DEPLOY_ACTIVATION_BUNDLE_SIZE_BYTES=4096 \
    DEPLOY_ACTIVATION_BUNDLE_MANIFEST_SHA256="$(fixture manifestSha256)" \
    DEPLOY_ACTIVATION_ADMISSION_SHA256="$(printf 'f%.0s' $(seq 1 64))" \
    DEPLOY_ACTIVATION_ADMISSION_SIZE_BYTES=8192 \
    DEPLOY_CONSUMER_RUN_ID=789012 \
    DEPLOY_CONSUMER_RUN_ATTEMPT=3 \
    "$@"
}

expect_reject() {
  label=$1
  shift
  rm -f "$FAKE_SSH_ARGS" "$FAKE_SSH_STDIN"
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  [ ! -e "$FAKE_SSH_ARGS" ] || {
    echo "FAIL: $label reached SSH" >&2
    exit 1
  }
  printf 'PASS\t%s\n' "$label"
}

expect_reject untrusted-caller run_client env PLATFORM_TRUSTED_OPS_RUNNER=0 sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject remote-option run_client env DEPLOY_REMOTE=-oProxyCommand=id sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject option-like-user-f run_client env DEPLOY_REMOTE=-Ftmp@example.internal sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject option-like-user-v run_client env DEPLOY_REMOTE=-V@example.internal sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject noncanonical-uppercase-user run_client env DEPLOY_REMOTE=Deploy@example.internal sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject remote-multiple-at run_client env DEPLOY_REMOTE=deploy@example@internal sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject wrong-target-host run_client env DEPLOY_REMOTE=deploy@attacker.internal sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject short-commit run_client env DEPLOY_RELEASE_SHA=abc sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject wrong-artifact-hash run_client env DEPLOY_ARTIFACT_RECEIPT_SHA256="$(printf '0%.0s' $(seq 1 64))" sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject wrong-dast-hash run_client env DEPLOY_DAST_RECEIPT_SHA256="$(printf '0%.0s' $(seq 1 64))" sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject wrong-manifest-hash run_client env DEPLOY_ACTIVATION_BUNDLE_MANIFEST_SHA256="$(printf '0%.0s' $(seq 1 64))" sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject missing-sidecar-digest run_client env -u DEPLOY_ACTIVATION_ADMISSION_SHA256 sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject missing-cas-digest run_client env -u DEPLOY_ACTIVATION_BUNDLE_SHA256 sh "$TEST_ROOT/scripts/deploy-vps.sh"
ln -s "$TMP/ssh-key" "$TMP/ssh-key-link"
expect_reject symlink-ssh-key run_client env DEPLOY_SSH_KEY_PATH="$TMP/ssh-key-link" sh "$TEST_ROOT/scripts/deploy-vps.sh"

rm -f "$FAKE_SSH_ARGS" "$FAKE_SSH_STDIN"
run_client sh "$TEST_ROOT/scripts/deploy-vps.sh" > "$TMP/receipt"
grep -Fx 'deploy@example.internal' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx -- '--' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx '/usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'StrictHostKeyChecking=yes' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'GlobalKnownHostsFile=/dev/null' "$FAKE_SSH_ARGS" >/dev/null
node -e '
const fs=require("fs");
const request=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
if (request.schema!=="platform-activation-request/v2") process.exit(1);
if (!/^activation:[a-f0-9]{64}:[a-f0-9]{64}$/.test(request.requestId)) process.exit(1);
if (request.bundle.sha256!=="e".repeat(64)) process.exit(1);
if (Object.hasOwn(request,"artifacts")) process.exit(1);
' "$FAKE_SSH_STDIN"
[ "$(wc -c < "$FAKE_SSH_STDIN" | tr -d ' ')" -lt 1048576 ]
if grep -Eq 'base64|exact-source-archive\.tar|remote_dir|git (fetch|pull|checkout)|sh -s' "$FAKE_SSH_STDIN"; then
  echo "FAIL: small broker request contains a legacy shell/archive/checkout transport" >&2
  exit 1
fi
printf 'PASS\tfixed-broker-small-json-request\n'

jq '.bundleSha256 = ("0" * 64)' "$TMP/broker-receipt.json" > "$TMP/tampered-broker-receipt.json"
rm -f "$FAKE_SSH_ARGS" "$FAKE_SSH_STDIN"
if FAKE_SSH_RECEIPT_OVERRIDE="$TMP/tampered-broker-receipt.json" run_client sh "$TEST_ROOT/scripts/deploy-vps.sh" >/dev/null 2>&1; then
  echo "FAIL: mismatched broker receipt was accepted" >&2
  exit 1
fi
[ -s "$FAKE_SSH_STDIN" ] || {
  echo "FAIL: receipt-negative path did not reach the broker boundary" >&2
  exit 1
}
printf 'PASS\tmismatched-broker-receipt-fails-closed\n'

set +e
run_client env BROKER_EXIT=78 sh "$TEST_ROOT/scripts/deploy-vps.sh" >/dev/null 2>&1
status=$?
set -e
[ "$status" -eq 78 ] || {
  echo "FAIL: missing external broker did not remain EXTERNAL-PENDING (status $status)" >&2
  exit 1
}
printf 'PASS\tbroker-external-pending-has-no-fallback\n'

for forbidden in 'sh -s' 'git ' 'docker ' 'scp ' 'sftp ' 'cloudflare-origin-lock-ufw.sh' 'prepare-vps-runtime.sh'; do
  if grep -F "$forbidden" "$TEST_ROOT/scripts/deploy-vps.sh" >/dev/null; then
    echo "FAIL: deployment client contains forbidden candidate-side operation: $forbidden" >&2
    exit 1
  fi
done
printf 'PASS\tno-remote-checkout-staging-or-candidate-privilege\n'

printf 'deploy VPS input tests passed 18/18\n'
