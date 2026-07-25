#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/deploy-vps-input-test.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
RELEASE_SHA=$(printf 'a%.0s' $(seq 1 40))
RELEASE_TREE=$(printf 'b%.0s' $(seq 1 40))
IMAGE="ghcr.io/owner/app@sha256:$(printf 'c%.0s' $(seq 1 64))"
MANIFEST_SHA=$(printf 'd%.0s' $(seq 1 64))
SBOM_SHA=$(printf 'e%.0s' $(seq 1 64))

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
printf 'exact authenticated source archive fixture\n' > "$TMP/source-archive.tar"
SOURCE_ARCHIVE_SHA=$(hash_file "$TMP/source-archive.tar")

cat > "$TMP/ssh" <<'SH'
#!/usr/bin/env sh
set -eu
known_hosts=
identity=
previous=
for argument in "$@"; do
  case "$argument" in UserKnownHostsFile=*) known_hosts=${argument#UserKnownHostsFile=} ;; esac
  [ "$previous" != -i ] || identity=$argument
  previous=$argument
done
if [ -n "${SWAP_KNOWN_HOSTS_SOURCE:-}" ]; then
  printf '%s\n' '[example.internal]:2222 ssh-ed25519 definitely-not-a-key' > "$SWAP_KNOWN_HOSTS_SOURCE"
  [ "$known_hosts" != "$SWAP_KNOWN_HOSTS_SOURCE" ]
  [ "$identity" != "$ORIGINAL_SSH_KEY_SOURCE" ]
  grep -Fx "$EXPECTED_KNOWN_HOST_RECORD" "$known_hosts" >/dev/null
  cmp "$ORIGINAL_SSH_KEY_SOURCE" "$identity" >/dev/null
fi
printf '%s\n' "$@" > "$FAKE_SSH_ARGS"
cat > "$FAKE_SSH_STDIN"
SH
cat > "$TMP/git" <<'SH'
#!/usr/bin/env sh
set -eu
case "$*" in
  *"rev-parse HEAD") printf '%s\n' "$FAKE_RELEASE_SHA" ;;
  *"rev-parse ${FAKE_RELEASE_SHA}^{tree}") printf '%s\n' "$FAKE_RELEASE_TREE" ;;
  *"status --porcelain --untracked-files=all") : ;;
  *) echo "unexpected git call: $*" >&2; exit 1 ;;
esac
SH
chmod 700 "$TMP/ssh" "$TMP/git"

cat > "$TMP/ready-policy.json" <<'EOF'
{"version":1,"status":"READY","trustedVerifierChannel":"external-admission-controller/prod","trustedOpsImageRepository":"ghcr.io/owner/platform-infrastructure-ops","requiredReceiptKind":"platform-trusted-deployment-admission/v1","selfAssertedAnnotationsAccepted":false,"trustedProducer":{"repository":"owner/trusted-admission","workflowPath":".github/workflows/produce-admission.yml","workflowSha":"4444444444444444444444444444444444444444","sourceRef":"refs/heads/main","event":"workflow_dispatch"}}
EOF
cat > "$TMP/artifact.json" <<EOF
{"version":1,"kind":"platform-release-artifact-verification/v1","status":"EXTERNAL-PENDING","artifactVerification":"passed","deploymentAdmission":"EXTERNAL-PENDING","usageScope":"artifact-verification-only","repository":"owner/repo","commitSha":"$RELEASE_SHA","sourceArchiveSha256":"$SOURCE_ARCHIVE_SHA","generatedAt":"2026-07-21T00:00:00.000Z","manifestSha256":"$MANIFEST_SHA","sbomSha256":"$SBOM_SHA","subjects":[{"key":"APP_IMAGE","image":"$IMAGE"}],"provenance":{"verificationFingerprint":"$(printf '1%.0s' $(seq 1 64))","manifestVerificationFingerprint":"$(printf '2%.0s' $(seq 1 64))"}}
EOF
ARTIFACT_SHA=$(hash_file "$TMP/artifact.json")
cat > "$TMP/admission.json" <<EOF
{"version":1,"kind":"platform-trusted-deployment-admission/v1","status":"READY","artifactVerification":"passed","deploymentAdmission":"READY","repository":"owner/repo","commitSha":"$RELEASE_SHA","treeSha":"$RELEASE_TREE","sourceArchiveSha256":"$SOURCE_ARCHIVE_SHA","artifactVerificationReceiptSha256":"$ARTIFACT_SHA","manifestSha256":"$MANIFEST_SHA","sbomSha256":"$SBOM_SHA","generatedAt":"2026-07-21T00:00:00.000Z","decisionId":"decision:12345678","verifier":{"channel":"external-admission-controller/prod","fingerprint":"$(printf '3%.0s' $(seq 1 64))","selfAsserted":false,"verifiedAt":"2026-07-21T00:00:00.000Z"},"producer":{"repository":"owner/trusted-admission","workflowPath":".github/workflows/produce-admission.yml","workflowSha":"$(printf '4%.0s' $(seq 1 40))","sourceRef":"refs/heads/main","event":"workflow_dispatch","runId":"123456","runAttempt":1},"opsRunner":{"image":"ghcr.io/owner/platform-infrastructure-ops@sha256:$(printf '5%.0s' $(seq 1 64))","imageId":"sha256:$(printf '6%.0s' $(seq 1 64))","verificationFingerprint":"$(printf '7%.0s' $(seq 1 64))","providerAttested":true}}
EOF
ADMISSION_SHA=$(hash_file "$TMP/admission.json")
cat > "$TMP/provider.json" <<'EOF'
{"id":123456,"run_attempt":1,"repository":{"full_name":"owner/trusted-admission"},"head_repository":{"full_name":"owner/trusted-admission"},"path":".github/workflows/produce-admission.yml","head_branch":"main","head_sha":"4444444444444444444444444444444444444444","event":"workflow_dispatch","status":"completed","conclusion":"success"}
EOF
PROVIDER_SHA=$(hash_file "$TMP/provider.json")
printf '%s\n' '[example.internal]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILBajvJtpsX+LmnBbwAcOXdb9LRHK+d9WJlVKLaAklDO' > "$TMP/known_hosts"
printf '%s\n' 'test-only-private-key' > "$TMP/deploy_key"
chmod 600 "$TMP/deploy_key"

# Positive-path fixtures execute an unmodified copy of the deployment scripts
# with a fixture policy in that copy. The production checkout keeps its
# repository-owned EXTERNAL-PENDING policy and exposes no policy-path override.
TEST_ROOT="$TMP/test-root"
mkdir -p "$TEST_ROOT/governance"
cp -R "$SCRIPT_DIR" "$TEST_ROOT/scripts"
cp -R "$ROOT/vendor" "$TEST_ROOT/vendor"
cp "$TMP/ready-policy.json" "$TEST_ROOT/governance/deployment-admission.json"
TEST_DEPLOY_SCRIPT="$TEST_ROOT/scripts/deploy-vps.sh"

expect_reject() {
  label=$1
  shift
  if env PATH="$TMP:$PATH" "$@" sh "$SCRIPT_DIR/deploy-vps.sh" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  printf 'PASS\t%s\n' "$label"
}

base_env() {
  env \
    PATH="$TMP:$PATH" \
    DEPLOY_REMOTE='deploy@example.internal' \
    DEPLOY_SSH_PORT=2222 \
    DEPLOY_REMOTE_DIR='/opt/platform-infrastructure' \
    DEPLOY_KNOWN_HOSTS_PATH="$TMP/known_hosts" \
    DEPLOY_SSH_KEY_PATH="$TMP/deploy_key" \
    DEPLOY_ENV_FILE='.env' \
    DEPLOY_PROJECT_NAME='platform_infra_vps' \
    DEPLOY_REPO='owner/repo' \
    DEPLOY_RELEASE_SHA="$RELEASE_SHA" \
    DEPLOY_RELEASE_TREE="$RELEASE_TREE" \
    DEPLOY_SOURCE_ARCHIVE_PATH="$TMP/source-archive.tar" \
    DEPLOY_ARTIFACT_RECEIPT_PATH="$TMP/artifact.json" \
    DEPLOY_ARTIFACT_RECEIPT_SHA256="$ARTIFACT_SHA" \
    DEPLOY_ADMISSION_RECEIPT_PATH="$TMP/admission.json" \
    DEPLOY_ADMISSION_RECEIPT_SHA256="$ADMISSION_SHA" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_PATH="$TMP/provider.json" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256="$PROVIDER_SHA" \
    DEPLOY_TRUSTED_PROVIDER_RUN_ID=123456 \
    DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT=1 \
    DEPLOY_RUN_WAF_SMOKE=1 \
    DEPLOY_RUN_INFRA_HEALTH=1 \
    DEPLOY_RUN_PRODUCTION_PREFLIGHT=1 \
    DEPLOY_RUN_PRE_GO_LIVE=1 \
    DEPLOY_RUN_GO_NO_GO=1 \
    DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT=1 \
    DEPLOY_PRE_GO_LIVE_RESTORE_DRILL=1 \
    DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN=1 \
    DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE=1 \
    FAKE_RELEASE_SHA="$RELEASE_SHA" \
    FAKE_RELEASE_TREE="$RELEASE_TREE" \
    "$@"
}

expect_base_reject() {
  label=$1
  shift
  if base_env "$@" sh "$TEST_DEPLOY_SCRIPT" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  printf 'PASS\t%s\n' "$label"
}

expect_reject deploy-user-option env DEPLOY_REMOTE='-oProxyCommand=id'
expect_reject deploy-remote-multiple-at env DEPLOY_REMOTE='deploy@example@internal'
expect_reject remote-dir-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_REMOTE_DIR='/opt/platform;id'
expect_reject env-traversal env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_ENV_FILE='../secret'
expect_reject project-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_PROJECT_NAME='prod;id'
expect_reject boolean-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_RUN_WAF_SMOKE='1;id'
expect_reject repo-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_REPO='owner/repo;id'
expect_reject short-approved-sha env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_REPO='owner/repo' DEPLOY_RELEASE_SHA=abc
expect_reject missing-receipts env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_REPO='owner/repo' DEPLOY_RELEASE_SHA="$RELEASE_SHA" DEPLOY_RELEASE_TREE="$RELEASE_TREE"
expect_base_reject wrong-artifact-hash env DEPLOY_ARTIFACT_RECEIPT_SHA256="$(printf '9%.0s' $(seq 1 64))"
expect_base_reject wrong-provider-metadata-hash env DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256="$(printf '8%.0s' $(seq 1 64))"
expect_base_reject wrong-provider-run-attempt env DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT=2
export FAKE_SSH_ARGS="$TMP/ssh-args.txt"
export FAKE_SSH_STDIN="$TMP/ssh-stdin.sh"
rm -f "$FAKE_SSH_ARGS" "$FAKE_SSH_STDIN"
expect_base_reject missing-mandatory-production-gate env -u DEPLOY_RUN_GO_NO_GO
[ ! -e "$FAKE_SSH_ARGS" ] && [ ! -e "$FAKE_SSH_STDIN" ] || { echo "FAIL: missing mandatory gate reached SSH" >&2; exit 1; }
expect_base_reject disabled-mandatory-production-gate env DEPLOY_RUN_GO_NO_GO=0
[ ! -e "$FAKE_SSH_ARGS" ] && [ ! -e "$FAKE_SSH_STDIN" ] || { echo "FAIL: disabled mandatory gate reached SSH" >&2; exit 1; }
expect_base_reject missing-dedicated-ssh-key env DEPLOY_SSH_KEY_PATH="$TMP/missing-key"
ln -s "$TMP/deploy_key" "$TMP/deploy-key-link"
expect_base_reject symlink-dedicated-ssh-key env DEPLOY_SSH_KEY_PATH="$TMP/deploy-key-link"

cp "$TMP/known_hosts" "$TMP/wrong-port-known-hosts"
sed 's/:2222/:2200/' "$TMP/wrong-port-known-hosts" > "$TMP/wrong-port-known-hosts.next"
mv "$TMP/wrong-port-known-hosts.next" "$TMP/wrong-port-known-hosts"
expect_base_reject wrong-host-port-pin env DEPLOY_KNOWN_HOSTS_PATH="$TMP/wrong-port-known-hosts"

expected_known_host_record='[example.internal]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILBajvJtpsX+LmnBbwAcOXdb9LRHK+d9WJlVKLaAklDO'
base_env env SWAP_KNOWN_HOSTS_SOURCE="$TMP/known_hosts" ORIGINAL_SSH_KEY_SOURCE="$TMP/deploy_key" EXPECTED_KNOWN_HOST_RECORD="$expected_known_host_record" sh "$TEST_DEPLOY_SCRIPT"
grep -Fx 'deploy@example.internal' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'sh -s' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'StrictHostKeyChecking=yes' "$FAKE_SSH_ARGS" >/dev/null
stable_known_hosts=$(sed -n 's/^UserKnownHostsFile=//p' "$FAKE_SSH_ARGS")
stable_identity=$(awk 'previous == "-i" { print; exit } { previous=$0 }' "$FAKE_SSH_ARGS")
[ "$stable_known_hosts" != "$TMP/known_hosts" ]
[ "$stable_identity" != "$TMP/deploy_key" ]
printf 'PASS\tssh-identity-and-host-database-use-private-snapshots\n'
grep -Fx 'GlobalKnownHostsFile=/dev/null' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'UpdateHostKeys=no' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'BatchMode=yes' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'IdentitiesOnly=yes' "$FAKE_SSH_ARGS" >/dev/null
if grep -F 'accept-new' "$FAKE_SSH_ARGS" >/dev/null; then echo "FAIL: accept-new remained enabled" >&2; exit 1; fi
if grep -F '/opt/platform-infrastructure' "$FAKE_SSH_STDIN" >/dev/null; then echo "FAIL: raw remote directory leaked into generated shell" >&2; exit 1; fi
grep -E "^PLATFORM_RELEASE_SHA_B64='[A-Za-z0-9+/=]+'$" "$FAKE_SSH_STDIN" >/dev/null
grep -E "^PLATFORM_SOURCE_ARCHIVE_SHA256_B64='[A-Za-z0-9+/=]+'$" "$FAKE_SSH_STDIN" >/dev/null
grep -F "base64 -d <<'__PLATFORM_EXACT_SOURCE_ARCHIVE__'" "$FAKE_SSH_STDIN" >/dev/null
grep -E "^PLATFORM_ADMISSION_RECEIPT_B64='[A-Za-z0-9+/=]+'$" "$FAKE_SSH_STDIN" >/dev/null
grep -E "^PLATFORM_PROVIDER_METADATA_B64='[A-Za-z0-9+/=]+'$" "$FAKE_SSH_STDIN" >/dev/null
grep -E "^PLATFORM_PROVIDER_RUN_ID_B64='[A-Za-z0-9+/=]+'$" "$FAKE_SSH_STDIN" >/dev/null
printf 'PASS\texact-release-receipts-host-port-and-encoded-request\n'

expect_reject production-policy-stays-external-pending env \
  PATH="$TMP:$PATH" DEPLOY_REMOTE='deploy@example.internal' DEPLOY_SSH_PORT=2222 DEPLOY_KNOWN_HOSTS_PATH="$TMP/known_hosts" \
  DEPLOY_REPO='owner/repo' DEPLOY_RELEASE_SHA="$RELEASE_SHA" DEPLOY_RELEASE_TREE="$RELEASE_TREE" \
  DEPLOY_ARTIFACT_RECEIPT_PATH="$TMP/artifact.json" DEPLOY_ARTIFACT_RECEIPT_SHA256="$ARTIFACT_SHA" \
  DEPLOY_ADMISSION_RECEIPT_PATH="$TMP/admission.json" DEPLOY_ADMISSION_RECEIPT_SHA256="$ADMISSION_SHA" \
  DEPLOY_TRUSTED_PROVIDER_METADATA_PATH="$TMP/provider.json" DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256="$PROVIDER_SHA" \
  DEPLOY_TRUSTED_PROVIDER_RUN_ID=123456 DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT=1 \
  FAKE_RELEASE_SHA="$RELEASE_SHA" FAKE_RELEASE_TREE="$RELEASE_TREE"

printf 'deploy VPS input tests passed 20/20\n'
