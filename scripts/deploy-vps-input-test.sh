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
const dastAuthorizationPolicy = await import(pathToFileURL(
  `${process.env.FIXTURE_ROOT}/scripts/dast-activation-authorization.mjs`,
));
const runtimePolicy = await import(pathToFileURL(`${process.env.FIXTURE_ROOT}/scripts/runtime-intent-policy.mjs`));
const { buildActivationRequest, buildTrustedReleaseContext } = requestPolicy;
const { activationRequestSha256 } = receiptPolicy;
const { exactNoHostedLockBytes, validateActivationBundleManifest } = bundlePolicy;
const { dastActivationChainSha256 } = dastAuthorizationPolicy;
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
const dastProviderMetadataSha256 = "2".repeat(64);
const dastSigstoreBundleSha256 = "3".repeat(64);
const dastSigstoreSubject = `dast-provider-verification.json@sha256:${"4".repeat(64)}`;
const dastDocument = {
  version: 1,
  kind: "platform-dast-verification/v1",
  status: "passed",
  repository,
  commitSha,
  treeSha,
  runtimeIntentSha256: deploymentDocument.runtimeIntentSha256,
  generatedAt: "2026-07-21T00:00:00.000Z",
  target: "https://staging.example.com",
  scanRequestSha256: "0".repeat(64),
  runtimeInventorySha256: "8".repeat(64),
  targetServingInventoryHash: "7".repeat(64),
  reportArtifact: {
    id: "456789",
    name: "dast-scan-request-789012-3",
    archiveSha256: "6".repeat(64),
    repository,
    runId: "789012",
    runAttempt: 3,
  },
  reportEvidenceSha256: "e".repeat(64),
  provider: {
    repository: policy.trustedProducer.repository,
    workflowPath: policy.trustedProducer.workflowPath,
    workflowSha: policy.trustedProducer.workflowSha,
    sourceRef: policy.trustedProducer.sourceRef,
    event: policy.trustedProducer.event,
    runId: "987654",
    runAttempt: 2,
    job: "dast-countersign",
  },
  consumerChallenge: {
    consumerRepository: repository,
    consumerRunId: "789012",
    consumerRunAttempt: 3,
    consumerJob: "deploy-vps",
    challengeNonce: "d".repeat(64),
  },
};
const dastProviderReceipt = writeJson("dast-provider-receipt.json", dastDocument);
const dastChain = {
  schema: "platform.docker-dast-chain/v2",
  repository,
  commitSha,
  treeSha,
  target: dastDocument.target,
  runtimeIntentSha256: deploymentDocument.runtimeIntentSha256,
  runtimeInventorySha256: dastDocument.runtimeInventorySha256,
  targetServingInventoryHash: dastDocument.targetServingInventoryHash,
  consumerChallengeSha256: hash(Buffer.from(canonicalJson(dastDocument.consumerChallenge))),
  scanRequestSha256: dastDocument.scanRequestSha256,
  providerReceiptSha256: dastProviderReceipt.sha256,
  providerMetadataSha256: dastProviderMetadataSha256,
  providerRunId: dastDocument.provider.runId,
  providerRunAttempt: dastDocument.provider.runAttempt,
  reportArtifactId: dastDocument.reportArtifact.id,
  reportArtifactArchiveSha256: dastDocument.reportArtifact.archiveSha256,
  reportEvidenceSha256: dastDocument.reportEvidenceSha256,
  sigstoreBundleSha256: dastSigstoreBundleSha256,
  sigstoreSubject: dastSigstoreSubject,
  verdict: "pass",
};
const dastAuthorizationDocument = {
  schema: "platform-dast-activation-authorization/v1",
  status: "READY",
  consumerChallenge: structuredClone(dastDocument.consumerChallenge),
  chain: dastChain,
  chainSha256: dastActivationChainSha256(dastChain),
  generatedAt: "2026-07-21T00:01:00.000Z",
};
const dastAuthorization = writeJson("dast-authorization.json", dastAuthorizationDocument);
const context = buildTrustedReleaseContext({
  deploymentReceipt: deploymentDocument,
  artifactReceiptSha256: artifact.sha256,
  deploymentReceiptSha256: deployment.sha256,
  providerMetadataSha256: provider.sha256,
  dastProviderReceiptSha256: dastProviderReceipt.sha256,
  dastAuthorizationSha256: dastAuthorization.sha256,
  dastChainSha256: dastAuthorizationDocument.chainSha256,
  providerRunId: "123456",
  providerRunAttempt: 2,
  providerChallenge: "d".repeat(64),
});
const releaseContextSha256 = hash(Buffer.from(canonicalJson(context)));
const requestId = `activation:${deployment.sha256}:${releaseContextSha256}`;
const entryHashes = {
  "artifact-verification.json": artifact.sha256,
  "combined-compose.json": runtimeIntent.combinedComposeSha256,
  "dast-activation-authorization.json": dastAuthorization.sha256,
  "dast-provider-verification.json": dastProviderReceipt.sha256,
  "environment.env": runtimeIntent.environmentSha256,
  "exact-source-archive.tar": runtimeIntent.sourceArchiveSha256,
  "hosted-workloads.lock.json": hash(exactNoHostedLockBytes()),
  "source-compose.json": runtimeIntent.sourceRenderSha256,
  "trusted-deployment-admission.json": deployment.sha256,
  "trusted-provider-run.json": provider.sha256,
};
const manifest = {
  schema: "platform-activation-bundle-manifest/v2",
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
  dastProviderReceipt,
  dastProviderReceiptSha256: dastProviderReceipt.sha256,
  dastAuthorization,
  dastAuthorizationSha256: dastAuthorization.sha256,
  dastProviderMetadataSha256,
  dastSigstoreBundleSha256,
  dastSigstoreSubject,
  bundleManifest: manifestArtifact,
  releaseBundleDescriptor: {
    schema: "platform-activation-bundle-descriptor/v2",
    sha256: "e".repeat(64),
    sizeBytes: 4096,
    manifestSha256,
  },
  dockerActivationEnvelope: {
    schema: "platform-docker-runtime-activation-envelope-descriptor/v1",
    sha256: "f".repeat(64),
    sizeBytes: 8192,
    payloadType: "application/vnd.platform.docker-runtime-activation.v2+json",
    runtimeIntentId: "runtime.production",
    generation: 7,
    dastAuthorizationSha256: dastAuthorization.sha256,
    dastChainSha256: dastAuthorizationDocument.chainSha256,
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
  schema: "platform-activation-receipt/v3",
  status: "ACTIVE",
  activatedAt: new Date(activationNow - 60_000).toISOString(),
  requestId: activationRequest.requestId,
  requestSha256: activationRequestSha256(activationRequest),
  releaseContextSha256: activationRequest.releaseContextSha256,
  runtimeIntentSha256: activationRequest.runtimeIntentSha256,
  releaseBundleSha256: activationRequest.releaseBundle.sha256,
  dockerActivationEnvelopeSha256: activationRequest.dockerActivationEnvelope.sha256,
  dastAuthorizationSha256: activationRequest.releaseContext.receipts.dastAuthorizationSha256,
  dastChainSha256: activationRequest.releaseContext.dastChainSha256,
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
activeReceipt.activationBundleSha256 = activationRequest.dockerActivationEnvelope.sha256;
activeReceipt.generation = activationRequest.dockerActivationEnvelope.generation;
activeReceipt.releaseId = activationRequest.dockerRuntime.releaseId;
activeReceipt.candidateId = activationRequest.dockerRuntime.candidateId;
activeReceipt.targetId = activationRequest.dockerRuntime.targetId;
activeReceipt.treeSha256 = activationRequest.dockerRuntime.treeSha256;
activeReceipt.environment = activationRequest.deploymentTarget.environment;
activeReceipt.sourceRenderSha256 = activationRequest.releaseContext.sourceRenderSha256;
activeReceipt.combinedRenderSha256 = activationRequest.releaseContext.combinedRenderSha256;
activeReceipt.dastChainSha256 = activationRequest.releaseContext.dastChainSha256;
for (const container of Object.values(activeReceipt.resources.containers)) {
  container.labels["com.platform.runtime.candidate-id"] = activeReceipt.candidateId;
  container.labels["com.platform.runtime.source-render-sha256"] = activeReceipt.sourceRenderSha256;
}
const normalizedActiveReceipt = dockerActionContract.normalizeActiveReceipt(activeReceipt, {
  now: activationNow,
});
activationReceipt.activatedAt = activeReceipt.issuedAt;
activationReceipt.activeReceipt = activeReceipt;
activationReceipt.activeReceiptSha256 = dockerActionContract.sha256(
  dockerActionContract.canonicalJson(normalizedActiveReceipt),
);
fs.writeFileSync(path.join(directory, "broker-receipt.json"), `${canonicalJson(activationReceipt)}\n`, { mode: 0o600 });
writeJson("fixture.json", {
  artifactSha256: artifact.sha256,
  deploymentSha256: deployment.sha256,
  providerSha256: provider.sha256,
  dastProviderReceiptSha256: dastProviderReceipt.sha256,
  dastAuthorizationSha256: dastAuthorization.sha256,
  dastProviderMetadataSha256,
  dastSigstoreBundleSha256,
  dastSigstoreSubject,
  dastChainSha256: dastAuthorizationDocument.chainSha256,
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
    DEPLOY_DAST_PROVIDER_RECEIPT_PATH="$TMP/dast-provider-receipt.json" \
    DEPLOY_DAST_PROVIDER_RECEIPT_SHA256="$(fixture dastProviderReceiptSha256)" \
    DEPLOY_DAST_ACTIVATION_AUTHORIZATION_PATH="$TMP/dast-authorization.json" \
    DEPLOY_DAST_ACTIVATION_AUTHORIZATION_SHA256="$(fixture dastAuthorizationSha256)" \
    DEPLOY_DAST_PROVIDER_METADATA_SHA256="$(fixture dastProviderMetadataSha256)" \
    DEPLOY_DAST_SIGSTORE_BUNDLE_SHA256="$(fixture dastSigstoreBundleSha256)" \
    DEPLOY_DAST_SIGSTORE_SUBJECT="$(fixture dastSigstoreSubject)" \
    DEPLOY_DAST_CHAIN_SHA256="$(fixture dastChainSha256)" \
    DEPLOY_RELEASE_BUNDLE_MANIFEST_PATH="$TMP/bundle-manifest.json" \
    DEPLOY_RELEASE_BUNDLE_SHA256="$(printf 'e%.0s' $(seq 1 64))" \
    DEPLOY_RELEASE_BUNDLE_SIZE_BYTES=4096 \
    DEPLOY_RELEASE_BUNDLE_MANIFEST_SHA256="$(fixture manifestSha256)" \
    DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SHA256="$(printf 'f%.0s' $(seq 1 64))" \
    DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SIZE_BYTES=8192 \
    DEPLOY_DOCKER_ACTIVATION_ENVELOPE_PAYLOAD_TYPE=application/vnd.platform.docker-runtime-activation.v2+json \
    DEPLOY_DOCKER_ACTIVATION_RUNTIME_INTENT_ID=runtime.production \
    DEPLOY_DOCKER_ACTIVATION_GENERATION=7 \
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

expect_v1_admission_stop() {
  label=$1
  shift
  rm -f "$FAKE_SSH_ARGS" "$FAKE_SSH_STDIN"
  set +e
  "$@" >"$TMP/$label.stdout" 2>"$TMP/$label.stderr"
  status=$?
  set -e
  [ "$status" -eq 78 ] || {
    echo "FAIL: $label did not stop with EXTERNAL-PENDING status 78 (status $status)" >&2
    exit 1
  }
  grep -F 'Authoritative V1 brownfield admission is unavailable.' "$TMP/$label.stderr" >/dev/null || {
    echo "FAIL: $label did not report the authoritative V1 brownfield stop" >&2
    exit 1
  }
  grep -F 'REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE' "$TMP/$label.stderr" >/dev/null || {
    echo "FAIL: $label did not classify the local backup result as deny-only" >&2
    exit 1
  }
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
expect_reject wrong-dast-provider-receipt-hash run_client env DEPLOY_DAST_PROVIDER_RECEIPT_SHA256="$(printf '0%.0s' $(seq 1 64))" sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject wrong-dast-authorization-hash run_client env DEPLOY_DAST_ACTIVATION_AUTHORIZATION_SHA256="$(printf '0%.0s' $(seq 1 64))" sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject wrong-release-manifest-hash run_client env DEPLOY_RELEASE_BUNDLE_MANIFEST_SHA256="$(printf '0%.0s' $(seq 1 64))" sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject wrong-dast-chain-hash run_client env DEPLOY_DAST_CHAIN_SHA256="$(printf '0%.0s' $(seq 1 64))" sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject missing-envelope-digest run_client env -u DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SHA256 sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject missing-release-bundle-digest run_client env -u DEPLOY_RELEASE_BUNDLE_SHA256 sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_reject legacy-dast-receipt-only run_client env -u DEPLOY_DAST_PROVIDER_RECEIPT_PATH DEPLOY_DAST_RECEIPT_PATH="$TMP/dast-provider-receipt.json" sh "$TEST_ROOT/scripts/deploy-vps.sh"
ln -s "$TMP/ssh-key" "$TMP/ssh-key-link"
expect_reject symlink-ssh-key run_client env DEPLOY_SSH_KEY_PATH="$TMP/ssh-key-link" sh "$TEST_ROOT/scripts/deploy-vps.sh"

expect_v1_admission_stop omitted-v1-admission \
  run_client sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_v1_admission_stop self-asserted-ready-is-denied \
  run_client env \
    DEPLOY_V1_BROWNFIELD_ADMISSION_STATUS=READY \
    DEPLOY_V1_BROWNFIELD_MUTATION_AUTHORITY=true \
    sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_v1_admission_stop local-non-authoritative-backup-is-denied \
  run_client env \
    DEPLOY_V1_BROWNFIELD_ADMISSION_STATUS=REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE \
    DEPLOY_V1_BROWNFIELD_MUTATION_AUTHORITY=false \
    sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_v1_admission_stop caller-baseline-hash-cannot-bypass \
  run_client env \
    DEPLOY_V1_BROWNFIELD_ADMISSION_STATUS=READY \
    DEPLOY_V1_BROWNFIELD_BASELINE_SHA256="$(printf '0%.0s' $(seq 1 64))" \
    sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_v1_admission_stop caller-backup-hash-cannot-bypass \
  run_client env \
    DEPLOY_V1_BROWNFIELD_ADMISSION_STATUS=READY \
    DEPLOY_V1_BROWNFIELD_BACKUP_RECEIPT_SHA256="$(printf '0%.0s' $(seq 1 64))" \
    sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_v1_admission_stop caller-candidate-binding-cannot-bypass \
  run_client env \
    DEPLOY_V1_BROWNFIELD_ADMISSION_STATUS=READY \
    DEPLOY_V1_BROWNFIELD_CANDIDATE_COMMIT="$(printf '0%.0s' $(seq 1 40))" \
    DEPLOY_V1_BROWNFIELD_CANDIDATE_TREE="$(printf '1%.0s' $(seq 1 40))" \
    sh "$TEST_ROOT/scripts/deploy-vps.sh"
expect_v1_admission_stop caller-target-binding-cannot-bypass \
  run_client env \
    DEPLOY_V1_BROWNFIELD_ADMISSION_STATUS=READY \
    DEPLOY_V1_BROWNFIELD_TARGET_ROOT=/srv/caller-selected \
    DEPLOY_V1_BROWNFIELD_PROVIDER_AUTHORIZATION=self-asserted \
    DEPLOY_V1_BROWNFIELD_TARGET_AUTHORIZATION=self-asserted \
    sh "$TEST_ROOT/scripts/deploy-vps.sh"

for forbidden in 'sh -s' 'git ' 'docker ' 'scp ' 'sftp ' 'cloudflare-origin-lock-ufw.sh' 'prepare-vps-runtime.sh'; do
  if grep -F "$forbidden" "$TEST_ROOT/scripts/deploy-vps.sh" >/dev/null; then
    echo "FAIL: deployment client contains forbidden candidate-side operation: $forbidden" >&2
    exit 1
  fi
done
printf 'PASS\tno-remote-checkout-staging-or-candidate-privilege\n'

printf 'deploy VPS input tests passed 25/25\n'
