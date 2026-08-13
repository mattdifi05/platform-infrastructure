#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";

const localSink = fs.readFileSync("scripts/deploy-vps.sh", "utf8");
const remoteSink = fs.readFileSync("scripts/deploy-vps-remote.sh", "utf8");
const workflow = fs.readFileSync(".github/workflows/enterprise-infra.yml", "utf8");
const installWorkflow = fs.readFileSync(".github/workflows/v1-install-only.yml", "utf8");
const opsDockerfile = fs.readFileSync("docker/ops.Dockerfile", "utf8");

const dastJobStart = workflow.indexOf("\n  dast-zap:");
const releaseAdmissionStart = workflow.indexOf("\n  release-admission:", dastJobStart);
const deployJobStart = workflow.indexOf("\n  deploy-vps:");
assert.ok(dastJobStart >= 0 && releaseAdmissionStart > dastJobStart, "DAST job is missing");
assert.ok(deployJobStart > releaseAdmissionStart, "deploy-vps job is missing");
const dastJob = workflow.slice(dastJobStart, releaseAdmissionStart);
const deployJob = workflow.slice(deployJobStart);

let checks = 3;
function has(text, fragment, message) {
  assert.ok(text.includes(fragment), message);
  checks += 1;
}
function lacks(text, fragment, message) {
  assert.ok(!text.includes(fragment), message);
  checks += 1;
}
function matches(text, pattern, message) {
  assert.match(text, pattern, message);
  checks += 1;
}
function before(text, earlier, later, message) {
  const earlierIndex = text.indexOf(earlier);
  const laterIndex = text.indexOf(later);
  assert.ok(earlierIndex >= 0 && laterIndex > earlierIndex, message);
  checks += 1;
}

// The candidate run emits only a non-authorizing scan request. A distinct,
// authenticated provider workflow produces the raw rich DAST receipt.
for (const fragment of [
  '--scanRequestOutput "$DAST_SCAN_REQUEST"',
  "PENDING-PROVIDER-ATTESTATION",
  "id: upload-request",
  "dast_report_artifact_id: ${{ steps.upload-request.outputs.artifact-id }}",
  "dast_report_artifact_sha256: ${{ steps.upload-request.outputs.artifact-digest }}",
  '-f "inputs[mode]=dast-countersign"',
  'test "$TRUSTED_REPOSITORY" != "$GITHUB_REPOSITORY"',
  "inputs[dast_scan_request_artifact]",
  "inputs[dast_scan_request_sha256]",
  "inputs[dast_report_artifact_id]",
  "inputs[dast_report_artifact_sha256]",
  "inputs[challenge_nonce]",
  "inputs[runtime_intent_sha256]",
  'TRUSTED_RUN_METADATA="${RUNNER_TEMP}/dast-provider-run.json"',
  '--metadata "$TRUSTED_RUN_METADATA"',
  "Download independent provider DAST receipt and Sigstore bundle",
  "dast-provider-attestation.bundle.jsonl",
  "--attestationVerifier /usr/local/bin/gh",
]) has(dastJob, fragment, `DAST provider boundary is missing ${fragment}`);
lacks(dastJob, "--receiptOutput", "candidate DAST job must not self-issue an authorizing receipt");

// Promotion v2 consumes the complete provider evidence locally. Its output is
// bounded and projects only the exact authorization identities needed by the
// immutable deploy client.
for (const fragment of [
  '--releaseBundle "$PROMOTED/release-activation.bundle"',
  '--releaseBundleManifest "$PROMOTED/release-activation-bundle-manifest.json"',
  '--dockerActivationEnvelope "$PROMOTED/docker-runtime-activation.dsse.json"',
  '--dastAuthorization "$PROMOTED/dast-activation-authorization.json"',
  '--dastProviderReceipt "$DAST_RECEIPT"',
  '--dastProviderMetadata "$DAST_PROVIDER_METADATA"',
  '--dastProviderAttestationBundle "$DAST_PROVIDER_ATTESTATION_BUNDLE"',
  'test "$(wc -c < "$RESULT" | tr -d \' \')" -le 1048576',
  'test "$(jq -er \'.dastChainSha256\' "$RESULT")" = "$(jq -er \'.chainSha256\' "$PROMOTED/dast-activation-authorization.json")"',
]) has(deployJob, fragment, `promotion v2 boundary is missing ${fragment}`);
has(
  deployJob,
  "release-activation.bundle release-activation-bundle-manifest.json docker-runtime-activation.dsse.json dast-activation-authorization.json activation-admission.jsonl sigstore-trusted-root.json activation-promotion-receipt.json",
  "promoted artifact must contain the exact seven-file flat set",
);

const sshInstall = deployJob.indexOf("- name: Install SSH key");
const promotion = deployJob.indexOf("node ./scripts/activation-promotion-policy.mjs");
const providerReplay = deployJob.lastIndexOf("node ./scripts/dast-runtime-receipt-policy.mjs");
assert.ok(promotion >= 0 && providerReplay >= 0 && sshInstall > promotion && sshInstall > providerReplay,
  "provider replay and promotion must both finish before SSH credentials are installed");
checks += 1;

// The isolated ops runner receives exactly the closed local projection. Raw
// reports, provider metadata, Sigstore material, bundle and envelope stay out.
const dockerStart = deployJob.indexOf("docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges");
const dockerEnd = deployJob.indexOf('"$OPS_IMAGE_ID" deploy-vps > "$ACTIVATION_RECEIPT"', dockerStart);
assert.ok(dockerStart >= 0 && dockerEnd > dockerStart, "trusted ops invocation is missing");
checks += 1;
const opsInvocation = deployJob.slice(dockerStart, dockerEnd);
for (const mounted of [
  "/run/platform-deploy/ssh-key:ro",
  "/run/platform-deploy/known-hosts:ro",
  "/run/platform-deploy/artifact-verification.json:ro",
  "/run/platform-deploy/trusted-deployment-admission.json:ro",
  "/run/platform-deploy/trusted-provider-run.json:ro",
  "/run/platform-deploy/dast-provider-verification.json:ro",
  "/run/platform-deploy/dast-activation-authorization.json:ro",
  "/run/platform-deploy/release-activation-bundle-manifest.json:ro",
]) has(opsInvocation, mounted, `ops mount allowlist is missing ${mounted}`);
const mountCount = (opsInvocation.match(/^\s+-v\s+/gm) ?? []).length;
assert.equal(mountCount, 8, "ops runner must have exactly eight read-only mounts");
checks += 1;
assert.doesNotMatch(opsInvocation,
  /dast-scan-request|dast-provider-run|dast-provider-attestation|sigstore-trusted-root|docker-runtime-activation\.dsse|release-activation\.bundle/,
  "raw/provider/CAS material must not cross into the ops runner");
checks += 1;

// The immutable client consumes the new typed identities and rejects the old
// generic bundle/admission and raw DAST evidence vocabulary.
for (const variable of [
  "DEPLOY_DAST_PROVIDER_RECEIPT_PATH",
  "DEPLOY_DAST_PROVIDER_RECEIPT_SHA256",
  "DEPLOY_DAST_ACTIVATION_AUTHORIZATION_PATH",
  "DEPLOY_DAST_ACTIVATION_AUTHORIZATION_SHA256",
  "DEPLOY_DAST_PROVIDER_METADATA_SHA256",
  "DEPLOY_DAST_SIGSTORE_BUNDLE_SHA256",
  "DEPLOY_DAST_SIGSTORE_SUBJECT",
  "DEPLOY_DAST_CHAIN_SHA256",
  "DEPLOY_RELEASE_BUNDLE_MANIFEST_PATH",
  "DEPLOY_RELEASE_BUNDLE_SHA256",
  "DEPLOY_RELEASE_BUNDLE_SIZE_BYTES",
  "DEPLOY_RELEASE_BUNDLE_MANIFEST_SHA256",
  "DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SHA256",
  "DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SIZE_BYTES",
  "DEPLOY_DOCKER_ACTIVATION_ENVELOPE_PAYLOAD_TYPE",
  "DEPLOY_DOCKER_ACTIVATION_RUNTIME_INTENT_ID",
  "DEPLOY_DOCKER_ACTIVATION_GENERATION",
]) has(localSink, variable, `${variable} must be mandatory in the immutable client`);
for (const argument of [
  '--dastProviderReceipt "$DAST_PROVIDER_RECEIPT"',
  '--dastProviderReceiptSha256 "$DAST_PROVIDER_RECEIPT_SHA256"',
  '--dastAuthorization "$DAST_ACTIVATION_AUTHORIZATION"',
  '--dastAuthorizationSha256 "$DAST_ACTIVATION_AUTHORIZATION_SHA256"',
  '--dastProviderMetadataSha256 "$DAST_PROVIDER_METADATA_SHA256"',
  '--dastSigstoreBundleSha256 "$DAST_SIGSTORE_BUNDLE_SHA256"',
  '--dastSigstoreSubject "$DAST_SIGSTORE_SUBJECT"',
  '--releaseBundleSha256 "$RELEASE_BUNDLE_SHA256"',
  '--dockerActivationEnvelopeSha256 "$DOCKER_ACTIVATION_ENVELOPE_SHA256"',
]) has(localSink, argument, `activation request v3 producer is missing ${argument}`);
has(localSink, "node \"$SCRIPT_ROOT/activation-receipt-policy.mjs\"", "client must validate receipt v3 locally");
has(localSink, "'/usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate'", "SSH sink must be the fixed root broker only");
has(localSink, '< "$request" > "$receipt"', "only the bounded request may cross SSH stdin");
lacks(localSink, "PLATFORM_DAST_SCAN_REQUEST", "raw scan request must not cross SSH");
lacks(localSink, "PLATFORM_DAST_PROVIDER_METADATA", "DAST provider metadata must not cross SSH");
lacks(localSink, "PLATFORM_DAST_ATTESTATION_BUNDLE", "DAST Sigstore material must not cross SSH");
lacks(localSink, "git fetch", "immutable client must not fetch or checkout on the remote host");
lacks(localSink, "docker compose", "immutable client must not mutate Docker directly");
before(localSink, "node \"$SCRIPT_ROOT/activation-request.mjs\"", "ssh \"$@\" -- \"$REMOTE\"", "request v3 must be validated and emitted before SSH");
before(localSink, "ssh \"$@\" -- \"$REMOTE\"", "node \"$SCRIPT_ROOT/activation-receipt-policy.mjs\"", "receipt v3 must be validated after the broker response");

// The compatibility transport is now an install-only sink. It accepts no
// request bytes and can invoke only the fixed root-owned V1 consumer.
has(remoteSink, "CONSUMER=/usr/local/libexec/platform-v1-brownfield-install-consumer", "remote install consumer path is not fixed");
has(remoteSink, "/bin/dd if=/dev/stdin bs=1 count=1", "remote install transport does not prove stdin is empty");
has(remoteSink, '[ "$stdin_bytes" = 0 ]', "remote install transport does not reject request bytes");
has(remoteSink, 'exec "$SUDO" -n -- "$CONSUMER" install < /dev/null', "remote install transport does not use the fixed root consumer");
lacks(remoteSink, "platform-activation-broker", "install-only transport must not invoke the activation broker");
for (const forbidden of [
  "git fetch",
  "git checkout",
  "docker ",
  "compose",
  "DAST_RECEIPT",
  "ATTESTATION_BUNDLE",
  "PROVIDER_METADATA",
  "base64",
  "curl ",
]) lacks(remoteSink, forbidden, `remote shim must not contain ${forbidden}`);

assert.equal(
  (installWorkflow.match(/^\s+sh \.\/scripts\/deploy-v1-install-only\.sh > "\$receipt"\s*$/gm) ?? []).length,
  1,
  "install-only workflow must expose one exact fixed sink",
);
checks += 1;
for (const forbidden of [
  "docker ",
  "platform-activation-broker",
  "release-admission",
  "dast-zap",
  "sigstore",
  "promoter",
  "activation-request",
]) lacks(installWorkflow, forbidden, `install-only workflow must not contain ${forbidden}`);

// Workflow validates and records the four semantically distinct receipt v3
// identities; no binary bundle, envelope or DAST evidence is sent over SSH.
for (const binding of [
  "platform-activation-receipt/v3",
  ".releaseBundleSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_RELEASE_BUNDLE_SHA256",
  ".dockerActivationEnvelopeSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SHA256",
  ".dastAuthorizationSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_DAST_ACTIVATION_AUTHORIZATION_SHA256",
  ".dastChainSha256' \"$ACTIVATION_RECEIPT\")\" = \"$DEPLOY_DAST_CHAIN_SHA256",
]) has(deployJob, binding, `receipt v3 sink is missing ${binding}`);
assert.equal((workflow.match(/^\s+"\$OPS_IMAGE_ID" deploy-vps > "\$ACTIVATION_RECEIPT"\s*$/gm) ?? []).length, 1,
  "workflow must contain exactly one trusted production mutation sink");
checks += 1;
matches(remoteSink, /\/bin\/dd if=\/dev\/stdin bs=1 count=1[\s\S]*\[ "\$stdin_bytes" = 0 \]/,
  "remote install-only shim must enforce exactly empty stdin");
const executableClosure = opsDockerfile.slice(
  opsDockerfile.indexOf("&& chmod 0555"),
  opsDockerfile.indexOf("\n\nWORKDIR"),
);
for (const runtimeModule of [
  "/opt/platform-infrastructure/scripts/dast-activation-authorization.mjs",
  "/opt/platform-infrastructure/scripts/docker-action-activation.mjs",
  "/opt/platform-infrastructure/scripts/docker-action-contract.mjs",
  "/opt/platform-infrastructure/scripts/ssh-known-host-endpoint.sh",
  "/opt/platform-infrastructure/scripts/pinned-ssh-host-key.mjs",
]) has(executableClosure, runtimeModule, `ops executable closure is missing ${runtimeModule}`);

process.stdout.write(`DAST deploy sink v3 policy tests passed ${checks}/${checks}\n`);
