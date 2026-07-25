#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";

const localSink = fs.readFileSync("scripts/deploy-vps.sh", "utf8");
const remoteSink = fs.readFileSync("scripts/deploy-vps-remote.sh", "utf8");
const workflow = fs.readFileSync(".github/workflows/enterprise-infra.yml", "utf8");

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
function before(text, earlier, later, message, start = 0) {
  const earlierIndex = text.indexOf(earlier, start);
  const laterIndex = text.indexOf(later, start);
  assert.ok(earlierIndex >= start && laterIndex > earlierIndex, message);
  checks += 1;
  return { earlierIndex, laterIndex };
}

// The candidate run may emit only a non-authorizing scan request. A distinct
// independent workflow run supplies the final receipt.
has(dastJob, "--scanRequestOutput \"$DAST_SCAN_REQUEST\"", "candidate DAST job must emit a scan request");
has(dastJob, "PENDING-PROVIDER-ATTESTATION", "candidate DAST request must remain non-authorizing");
lacks(dastJob, "--receiptOutput", "candidate DAST job must not self-issue any authorizing receipt");
has(dastJob, "id: upload-request", "request and raw reports must be uploaded for provider observation");
has(dastJob, "dast_report_artifact_id: ${{ steps.upload-request.outputs.artifact-id }}",
  "DAST job must export the immutable report artifact ID");
has(dastJob, "dast_report_artifact_sha256: ${{ steps.upload-request.outputs.artifact-digest }}",
  "DAST job must export the provider-observed report archive digest");
has(dastJob, "-f \"inputs[mode]=dast-countersign\"", "independent provider must run in DAST countersign mode");
has(dastJob, "test \"$TRUSTED_REPOSITORY\" != \"$GITHUB_REPOSITORY\"",
  "candidate repository must not act as its own provider");
for (const providerInput of [
  "inputs[dast_scan_request_artifact]",
  "inputs[dast_scan_request_sha256]",
  "inputs[dast_report_artifact_id]",
  "inputs[dast_report_artifact_sha256]",
  "inputs[challenge_nonce]",
  "inputs[runtime_intent_sha256]",
]) {
  has(dastJob, providerInput, `${providerInput} must be bound into the independent provider dispatch`);
}
has(dastJob, "TRUSTED_RUN_METADATA=\"${RUNNER_TEMP}/dast-provider-run.json\"",
  "the second provider run must have separately authenticated metadata");
has(dastJob, "--metadata \"$TRUSTED_RUN_METADATA\"", "the second provider run metadata must be policy checked");
has(dastJob, "Download independent provider DAST receipt and Sigstore bundle",
  "the final provider receipt and Sigstore bundle must come from the independent run");
has(dastJob, "dast-provider-attestation.bundle.jsonl", "the Sigstore bundle must be retained in the handoff");
has(dastJob, "--attestationVerifier /usr/local/bin/gh",
  "the provider receipt must be cryptographically verified before handoff");

// Every trust input is mandatory at the deploy sink and is wired from the
// exact DAST/provider job outputs.
for (const variable of [
  "DEPLOY_DAST_SCAN_REQUEST_PATH",
  "DEPLOY_DAST_SCAN_REQUEST_SHA256",
  "DEPLOY_DAST_REPORT_ARTIFACT_ID",
  "DEPLOY_DAST_REPORT_ARTIFACT_SHA256",
  "DEPLOY_DAST_RECEIPT_PATH",
  "DEPLOY_DAST_RECEIPT_SHA256",
  "DEPLOY_DAST_PROVIDER_METADATA_PATH",
  "DEPLOY_DAST_PROVIDER_METADATA_SHA256",
  "DEPLOY_DAST_PROVIDER_RUN_ID",
  "DEPLOY_DAST_PROVIDER_RUN_ATTEMPT",
  "DEPLOY_DAST_ATTESTATION_BUNDLE_PATH",
  "DEPLOY_DAST_ATTESTATION_BUNDLE_SHA256",
  "DEPLOY_GH_VERIFIER_ARCHIVE_PATH",
]) {
  has(localSink, variable, `${variable} must be mandatory at deploy-vps.sh`);
  has(deployJob, `${variable}:`, `${variable} must be handed to deploy-vps.sh`);
}
has(localSink, "stable_dast_scan_request=\"$request_dir/dast-scan-request.json\"",
  "the scan request needs an independent stable snapshot");
has(localSink, "stable_dast_receipt=\"$request_dir/dast-verification.json\"",
  "the provider receipt needs an independent stable snapshot");
has(localSink, "[ \"$(hash_file \"$stable_dast_scan_request\")\" = \"$DAST_SCAN_REQUEST_SHA256\" ]",
  "the stable scan request digest must be checked");
has(localSink, "[ \"$(hash_file \"$stable_dast_receipt\")\" = \"$DAST_RECEIPT_SHA256\" ]",
  "the stable provider receipt digest must be checked");
has(localSink, "[ \"$(hash_file \"$stable_dast_provider_metadata\")\" = \"$DAST_PROVIDER_METADATA_SHA256\" ]",
  "the second-run metadata digest must be checked");
has(localSink, "[ \"$(hash_file \"$stable_dast_attestation_bundle\")\" = \"$DAST_ATTESTATION_BUNDLE_SHA256\" ]",
  "the Sigstore bundle digest must be checked");
matches(localSink, /GH_VERIFIER_ARCHIVE_SHA256=[a-f0-9]{64}/,
  "the local sink must checksum-pin the attestation verifier archive");
has(localSink, "--reportArtifactId \"$DAST_REPORT_ARTIFACT_ID\"",
  "the local replay must bind the exact artifact ID");
has(localSink, "--reportArtifactSha256 \"$DAST_REPORT_ARTIFACT_SHA256\"",
  "the local replay must bind the provider-observed archive digest");
has(localSink, "--dastProviderMetadata \"$stable_dast_provider_metadata\"",
  "the local replay must bind second-run metadata");
has(localSink, "--dastAttestationBundle \"$stable_dast_attestation_bundle\"",
  "the local replay must bind the Sigstore bundle");
has(localSink, "--attestationVerifier \"$stable_gh_verifier\"",
  "the local replay must use the checksum-pinned verifier");

// The complete evidence set, including the verifier, must cross the SSH
// boundary and be revalidated on the destination.
for (const transport of [
  "PLATFORM_DAST_SCAN_REQUEST_SHA256_B64",
  "PLATFORM_DAST_REPORT_ARTIFACT_ID_B64",
  "PLATFORM_DAST_REPORT_ARTIFACT_SHA256_B64",
  "PLATFORM_DAST_RECEIPT_SHA256_B64",
  "PLATFORM_DAST_PROVIDER_METADATA_SHA256_B64",
  "PLATFORM_DAST_PROVIDER_RUN_ID_B64",
  "PLATFORM_DAST_PROVIDER_RUN_ATTEMPT_B64",
  "PLATFORM_DAST_ATTESTATION_BUNDLE_SHA256_B64",
  "PLATFORM_DAST_SCAN_REQUEST_B64",
  "PLATFORM_DAST_RECEIPT_B64",
  "PLATFORM_DAST_PROVIDER_METADATA_B64",
  "PLATFORM_DAST_ATTESTATION_BUNDLE_B64",
  "PLATFORM_GH_VERIFIER_ARCHIVE_B64",
]) {
  has(localSink, transport, `${transport} must be included in the SSH request`);
  has(remoteSink, transport, `${transport} must be consumed by the remote sink`);
}
has(remoteSink, "[ \"$(hash_file \"$dast_scan_request\")\" = \"$dast_scan_request_sha256\" ]",
  "remote sink must hash the separate scan request");
has(remoteSink, "[ \"$(hash_file \"$dast_provider_metadata\")\" = \"$dast_provider_metadata_sha256\" ]",
  "remote sink must hash the second-run provider metadata");
has(remoteSink, "[ \"$(hash_file \"$dast_attestation_bundle\")\" = \"$dast_attestation_bundle_sha256\" ]",
  "remote sink must hash the Sigstore bundle");
has(remoteSink, ".reportArtifact.id == $artifactId and .reportArtifact.archiveSha256 == $artifactSha256",
  "remote schema gate must bind both report artifact ID and archive digest");
has(remoteSink, ".validatedReportEvidence == $scanRequest[0].reportEvidence",
  "remote schema gate must bind provider-observed evidence to the request");
has(remoteSink, ".semanticVerdict == .validatedReportEvidence.semanticVerdict",
  "remote schema gate must reject a self-asserted divergent semantic verdict");
has(remoteSink, ".providerValidation == {", "remote schema gate must require provider validation");
has(remoteSink, "parser:\"platform-provider-zap-report-set/v1\"",
  "remote schema gate must require the independent provider parser");
has(remoteSink, "keys == [\"html\",\"json\",\"xml\"]",
  "remote schema gate must require the complete exact report file set");
has(remoteSink, ".provider.repository != $repo and .provider.job == \"dast-countersign\"",
  "remote receipt must identify an independent second provider run");
has(remoteSink, ".status == \"completed\" and .conclusion == \"success\"",
  "remote second-run metadata must authenticate a successful completed provider run");

// Sigstore verification is explicit and offline against the transferred
// bundle, with exact workflow identity and receipt subject digest.
has(remoteSink, "\"$gh_verifier\" attestation verify \"$dast_receipt\"",
  "remote sink must cryptographically verify the final receipt");
for (const verifierArgument of [
  "--signer-workflow",
  "--source-digest",
  "--signer-digest",
  "--source-ref",
  "--cert-oidc-issuer https://token.actions.githubusercontent.com",
  "--predicate-type https://slsa.dev/provenance/v1",
  "--deny-self-hosted-runners",
  "--bundle \"$dast_attestation_bundle\"",
]) {
  has(remoteSink, verifierArgument, `${verifierArgument} must constrain remote attestation verification`);
}
has(remoteSink, ".verificationResult.signature.certificate",
  "remote sink must inspect the verified certificate");
has(remoteSink, ".verificationResult.verifiedTimestamps",
  "remote sink must require verified transparency timestamps");
has(remoteSink, ".digest.sha256 == $digest",
  "remote sink must bind the attestation subject to the exact receipt digest");

// Ordering: the complete Node policy (which invokes the pinned verifier) runs
// locally before SSH. The destination verifies the attestation before fetching
// or checking out code, then replays the full Node policy from that exact
// checkout before any production mutation.
const localPolicyOrder = before(
  localSink,
  "node \"$SCRIPT_DIR/dast-runtime-receipt-policy.mjs\"",
  "ssh \"$@\" \"$REMOTE\" 'sh -s'",
  "local DAST policy and cryptographic verification must finish before SSH",
);
before(
  localSink,
  "--attestationVerifier \"$stable_gh_verifier\"",
  "ssh \"$@\" \"$REMOTE\" 'sh -s'",
  "the pinned local verifier must be selected before SSH",
  localPolicyOrder.earlierIndex,
);
before(
  deployJob,
  "node ./scripts/dast-runtime-receipt-policy.mjs",
  "- name: Install SSH key",
  "workflow revalidation must finish before installing or using SSH credentials",
);
const remoteCryptoOrder = before(
  remoteSink,
  "\"$gh_verifier\" attestation verify \"$dast_receipt\"",
  "git fetch --no-tags origin \"$release_sha\"",
  "remote cryptographic verification must finish before git fetch",
);
before(
  remoteSink,
  ".digest.sha256 == $digest",
  "git fetch --no-tags origin \"$release_sha\"",
  "verified attestation subject binding must finish before git fetch",
  remoteCryptoOrder.earlierIndex,
);
const remoteReplayOrder = before(
  remoteSink,
  "node ./scripts/dast-runtime-receipt-policy.mjs",
  "rollback_required=1",
  "remote full policy replay must finish before the production mutation boundary",
);
before(
  remoteSink,
  "--attestationVerifier \"$gh_verifier\"",
  "rollback_required=1",
  "remote replay must use the pinned verifier before production mutation",
  remoteReplayOrder.earlierIndex,
);

process.stdout.write(`DAST deploy sink policy tests passed ${checks}/${checks}\n`);
