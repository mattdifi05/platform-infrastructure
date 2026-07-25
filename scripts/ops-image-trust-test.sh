#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ops-image-trust.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
FIXTURE_ROOT="$TMP/fixture-root"
FIXTURE_BIN="$TMP/bin"
mkdir -p "$FIXTURE_ROOT" "$FIXTURE_BIN"
cp -R "$ROOT/scripts" "$ROOT/governance" "$ROOT/vendor" "$FIXTURE_ROOT/"
mkdir -p "$FIXTURE_ROOT/control-center"
cp -R "$ROOT/control-center/backup" "$FIXTURE_ROOT/control-center/"
tar -cf "$TMP/fake-infra-source.tar" -C "$FIXTURE_ROOT" scripts governance

IMAGE="ghcr.io/owner/platform-infrastructure-ops@sha256:$(printf '5%.0s' $(seq 1 64))"
IMAGE_ID="sha256:$(printf '6%.0s' $(seq 1 64))"
RELEASE_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf 'f%.0s' $(seq 1 64))"
RELEASE_SHA=$(printf 'a%.0s' $(seq 1 40))
RELEASE_TREE=$(printf 'b%.0s' $(seq 1 40))
MANIFEST_SHA=$(printf 'd%.0s' $(seq 1 64))
SBOM_SHA=$(printf 'e%.0s' $(seq 1 64))
PROVIDER_RUN_ID=123456
PROVIDER_RUN_ATTEMPT=2

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
SOURCE_ARCHIVE_SHA=$(hash_file "$TMP/fake-infra-source.tar")

cat > "$FIXTURE_ROOT/governance/deployment-admission.json" <<'EOF'
{"version":1,"status":"READY","trustedVerifierChannel":"external-admission-controller/prod","trustedOpsImageRepository":"ghcr.io/owner/platform-infrastructure-ops","requiredReceiptKind":"platform-trusted-deployment-admission/v1","selfAssertedAnnotationsAccepted":false,"trustedProducer":{"repository":"owner/trusted-admission","workflowPath":".github/workflows/produce-admission.yml","workflowSha":"4444444444444444444444444444444444444444","sourceRef":"refs/heads/main","event":"workflow_dispatch"}}
EOF
cat > "$TMP/artifact.json" <<EOF
{"version":1,"kind":"platform-release-artifact-verification/v1","status":"EXTERNAL-PENDING","artifactVerification":"passed","deploymentAdmission":"EXTERNAL-PENDING","usageScope":"artifact-verification-only","repository":"owner/repo","commitSha":"$RELEASE_SHA","sourceArchiveSha256":"$SOURCE_ARCHIVE_SHA","generatedAt":"2026-07-21T00:00:00.000Z","manifestSha256":"$MANIFEST_SHA","sbomSha256":"$SBOM_SHA","subjects":[{"key":"PHP_APACHE_IMAGE","image":"$RELEASE_IMAGE"}],"provenance":{"verificationFingerprint":"$(printf '1%.0s' $(seq 1 64))","manifestVerificationFingerprint":"$(printf '2%.0s' $(seq 1 64))"}}
EOF
ARTIFACT_SHA=$(hash_file "$TMP/artifact.json")
cat > "$TMP/admission.json" <<EOF
{"version":1,"kind":"platform-trusted-deployment-admission/v1","status":"READY","artifactVerification":"passed","deploymentAdmission":"READY","repository":"owner/repo","commitSha":"$RELEASE_SHA","treeSha":"$RELEASE_TREE","sourceArchiveSha256":"$SOURCE_ARCHIVE_SHA","artifactVerificationReceiptSha256":"$ARTIFACT_SHA","manifestSha256":"$MANIFEST_SHA","sbomSha256":"$SBOM_SHA","generatedAt":"2026-07-21T00:00:00.000Z","decisionId":"decision:12345678","verifier":{"channel":"external-admission-controller/prod","fingerprint":"$(printf '3%.0s' $(seq 1 64))","selfAsserted":false,"verifiedAt":"2026-07-21T00:00:00.000Z"},"producer":{"repository":"owner/trusted-admission","workflowPath":".github/workflows/produce-admission.yml","workflowSha":"$(printf '4%.0s' $(seq 1 40))","sourceRef":"refs/heads/main","event":"workflow_dispatch","runId":"$PROVIDER_RUN_ID","runAttempt":$PROVIDER_RUN_ATTEMPT},"opsRunner":{"image":"$IMAGE","imageId":"$IMAGE_ID","verificationFingerprint":"$(printf '7%.0s' $(seq 1 64))","providerAttested":true}}
EOF
ADMISSION_SHA=$(hash_file "$TMP/admission.json")
cat > "$TMP/provider.json" <<EOF
{"id":$PROVIDER_RUN_ID,"run_attempt":$PROVIDER_RUN_ATTEMPT,"repository":{"full_name":"owner/trusted-admission"},"head_repository":{"full_name":"owner/trusted-admission"},"path":".github/workflows/produce-admission.yml","head_branch":"main","head_sha":"$(printf '4%.0s' $(seq 1 40))","event":"workflow_dispatch","status":"completed","conclusion":"success"}
EOF
PROVIDER_SHA=$(hash_file "$TMP/provider.json")

cat > "$FIXTURE_BIN/docker" <<'SH'
#!/usr/bin/env sh
set -eu
case "$1 ${2:-}" in
  "image inspect")
    if [ -n "${MUTATE_AFTER_INSPECT_PATH:-}" ]; then
      printf 'post-admission mutation sentinel\n' > "$MUTATE_AFTER_INSPECT_PATH"
      : > "$MUTATE_AFTER_INSPECT_MARKER"
    fi
    : > "$DOCKER_INSPECTED"
    printf '[{"Id":"%s","RepoDigests":["%s"]}]\n' "$FAKE_IMAGE_ID" "$FAKE_REPO_DIGEST"
    ;;
  "run --rm")
    printf '%s\n' "$@" > "$DOCKER_RUN_ARGS"
    ;;
  *) echo "unexpected docker invocation: $*" >&2; exit 99 ;;
esac
SH
cat > "$FIXTURE_BIN/git" <<'SH'
#!/usr/bin/env sh
set -eu
case "$*" in
  *"rev-parse HEAD") printf '%s\n' "$FAKE_RELEASE_SHA" ;;
  *"rev-parse ${FAKE_RELEASE_SHA}^{tree}") printf '%s\n' "$FAKE_RELEASE_TREE" ;;
  *"rev-parse --abbrev-ref HEAD") printf 'main\n' ;;
  *"ls-tree -r --name-only -z"*) printf 'scripts/infra-ops.mjs\0' ;;
  *"ls-tree -r "*) printf '100755 blob 1111111111111111111111111111111111111111\tscripts/infra-ops.mjs\n' ;;
  *"status --porcelain --untracked-files=all")
    if [ "${FAKE_DIRTY:-0}" = 1 ] || { [ -n "${MUTATE_AFTER_INSPECT_MARKER:-}" ] && [ -e "$MUTATE_AFTER_INSPECT_MARKER" ]; }; then
      printf ' M scripts/infra-ops.mjs\n'
    fi
    ;;
  *) echo "unexpected git invocation: $*" >&2; exit 99 ;;
esac
SH
cat > "$FIXTURE_BIN/cp" <<'SH'
#!/usr/bin/env sh
set -eu
if [ -n "${SIGNAL_DURING_COPY_SOURCE:-}" ] && [ "${1:-}" = "$SIGNAL_DURING_COPY_SOURCE" ]; then
  kill -TERM "$PPID"
fi
exec /bin/cp "$@"
SH
chmod 700 "$FIXTURE_BIN/docker" "$FIXTURE_BIN/git" "$FIXTURE_BIN/cp"

trust_env() {
  env \
    PATH="$FIXTURE_BIN:$PATH" \
    DOCKER_INSPECTED="$TMP/docker-inspected" \
    DOCKER_RUN_ARGS="$TMP/docker-run-args" \
    FAKE_IMAGE_ID="${TEST_FAKE_IMAGE_ID:-$IMAGE_ID}" \
    FAKE_REPO_DIGEST="$IMAGE" \
    FAKE_RELEASE_SHA="${TEST_FAKE_RELEASE_SHA:-$RELEASE_SHA}" \
    FAKE_RELEASE_TREE="$RELEASE_TREE" \
    FAKE_DIRTY="${TEST_FAKE_DIRTY:-0}" \
    MUTATE_AFTER_INSPECT_PATH="${TEST_MUTATE_AFTER_INSPECT_PATH:-}" \
    MUTATE_AFTER_INSPECT_MARKER="${TEST_MUTATE_AFTER_INSPECT_MARKER:-}" \
    SIGNAL_DURING_COPY_SOURCE="${TEST_SIGNAL_DURING_COPY_SOURCE:-}" \
    PLATFORM_OPS_DOCKER_MODE=none \
    DEPLOY_REPO=owner/repo \
    DEPLOY_RELEASE_SHA="$RELEASE_SHA" \
    DEPLOY_RELEASE_TREE="$RELEASE_TREE" \
    DEPLOY_SOURCE_ARCHIVE_PATH="${TEST_SOURCE_ARCHIVE_PATH:-$TMP/fake-infra-source.tar}" \
    DEPLOY_ARTIFACT_RECEIPT_PATH="$TMP/artifact.json" \
    DEPLOY_ARTIFACT_RECEIPT_SHA256="${TEST_ARTIFACT_SHA256:-$ARTIFACT_SHA}" \
    DEPLOY_ADMISSION_RECEIPT_PATH="${TEST_ADMISSION_PATH:-$TMP/admission.json}" \
    DEPLOY_ADMISSION_RECEIPT_SHA256="${TEST_ADMISSION_SHA256:-$ADMISSION_SHA}" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_PATH="${TEST_PROVIDER_METADATA_PATH:-$TMP/provider.json}" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256="${TEST_PROVIDER_METADATA_SHA256:-$PROVIDER_SHA}" \
    DEPLOY_TRUSTED_PROVIDER_RUN_ID="$PROVIDER_RUN_ID" \
    DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT="$PROVIDER_RUN_ATTEMPT" \
    "$@"
}

inner_env() {
  env \
    PLATFORM_INFRA_ROOT="$FIXTURE_ROOT" \
    PLATFORM_GIT_COMMIT="$RELEASE_SHA" \
    PLATFORM_GIT_BRANCH=main \
    PLATFORM_GIT_DIRTY=0 \
    PLATFORM_GIT_TREE="${TEST_INNER_TREE:-$RELEASE_TREE}" \
    PLATFORM_INFRA_SNAPSHOT_SHA256="${TEST_INNER_EXPECTED_SHA256:-$SOURCE_ARCHIVE_SHA}" \
    PLATFORM_INFRA_SNAPSHOT_VERIFIED_SHA256="${TEST_INNER_VERIFIED_SHA256:-$SOURCE_ARCHIVE_SHA}" \
    DEPLOY_REPO=owner/repo \
    DEPLOY_RELEASE_SHA="$RELEASE_SHA" \
    DEPLOY_RELEASE_TREE="$RELEASE_TREE" \
    DEPLOY_ARTIFACT_RECEIPT_PATH="$TMP/artifact.json" \
    DEPLOY_ARTIFACT_RECEIPT_SHA256="$ARTIFACT_SHA" \
    DEPLOY_ADMISSION_RECEIPT_PATH="$TMP/admission.json" \
    DEPLOY_ADMISSION_RECEIPT_SHA256="$ADMISSION_SHA" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_PATH="$TMP/provider.json" \
    DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256="$PROVIDER_SHA" \
    DEPLOY_TRUSTED_PROVIDER_RUN_ID="$PROVIDER_RUN_ID" \
    DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT="$PROVIDER_RUN_ATTEMPT" \
    "$@"
}

expect_reject_without_docker() {
  label=$1
  shift
  rm -f "$TMP/docker-inspected"
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  [ ! -e "$TMP/docker-inspected" ] || {
    echo "FAIL: $label reached Docker before trust validation" >&2
    exit 1
  }
  printf 'PASS\t%s\n' "$label"
}

result=$(trust_env sh "$FIXTURE_ROOT/scripts/ops-image-trust.sh")
[ "$(printf '%s' "$result" | jq -r '.image')" = "$IMAGE" ]
[ "$(printf '%s' "$result" | jq -r '.imageId')" = "$IMAGE_ID" ]
[ "$(printf '%s' "$result" | jq -r '.sourceArchiveSha256')" = "$SOURCE_ARCHIVE_SHA" ]
printf 'PASS\tprovider-receipt-and-local-image-positive-path\n'

inner_env node "$FIXTURE_ROOT/scripts/infra-ops.mjs" trusted-deployment-admission-check >/dev/null
printf 'PASS\timmutable-snapshot-inner-admission-positive-path\n'

TEST_INNER_VERIFIED_SHA256=$(printf '8%.0s' $(seq 1 64))
if inner_env node "$FIXTURE_ROOT/scripts/infra-ops.mjs" trusted-deployment-admission-check >/dev/null 2>&1; then
  echo "FAIL: inner admission accepted mismatched copied snapshot bytes" >&2
  exit 1
fi
unset TEST_INNER_VERIFIED_SHA256
printf 'PASS\tinner-admission-rejects-mismatched-copied-snapshot\n'

TEST_INNER_TREE=$(printf '9%.0s' $(seq 1 40))
if inner_env node "$FIXTURE_ROOT/scripts/infra-ops.mjs" trusted-deployment-admission-check >/dev/null 2>&1; then
  echo "FAIL: inner admission accepted the wrong source tree" >&2
  exit 1
fi
unset TEST_INNER_TREE
printf 'PASS\tinner-admission-rejects-wrong-tree\n'

TEST_INNER_EXPECTED_SHA256=$(printf '7%.0s' $(seq 1 64))
TEST_INNER_VERIFIED_SHA256="$TEST_INNER_EXPECTED_SHA256"
export TEST_INNER_VERIFIED_SHA256
if inner_env node "$FIXTURE_ROOT/scripts/infra-ops.mjs" trusted-deployment-admission-check >/dev/null 2>&1; then
  echo "FAIL: inner admission accepted snapshot bytes not bound by the receipt" >&2
  exit 1
fi
unset TEST_INNER_EXPECTED_SHA256 TEST_INNER_VERIFIED_SHA256
printf 'PASS\tinner-admission-rejects-receipt-unbound-snapshot\n'

TEST_ARTIFACT_SHA256=$(printf '8%.0s' $(seq 1 64))
expect_reject_without_docker wrong-artifact-hash trust_env sh "$FIXTURE_ROOT/scripts/ops-image-trust.sh"
unset TEST_ARTIFACT_SHA256
jq '.run_attempt = 1' "$TMP/provider.json" > "$TMP/provider-wrong-attempt.json"
WRONG_PROVIDER_SHA=$(hash_file "$TMP/provider-wrong-attempt.json")
if node "$FIXTURE_ROOT/scripts/trusted-provider-run-policy.mjs" \
  --policy "$FIXTURE_ROOT/governance/deployment-admission.json" \
  --metadata "$TMP/provider-wrong-attempt.json" \
  --metadataSha256 "$WRONG_PROVIDER_SHA" \
  --deploymentReceipt "$TMP/admission.json" \
  --runId "$PROVIDER_RUN_ID" \
  --runAttempt "$PROVIDER_RUN_ATTEMPT" >/dev/null 2>&1; then
  echo "FAIL: direct provider policy accepted the wrong run attempt" >&2
  exit 1
fi
TEST_PROVIDER_METADATA_PATH="$TMP/provider-wrong-attempt.json"
TEST_PROVIDER_METADATA_SHA256="$WRONG_PROVIDER_SHA"
expect_reject_without_docker wrong-provider-run-attempt trust_env sh "$FIXTURE_ROOT/scripts/ops-image-trust.sh"
unset TEST_PROVIDER_METADATA_PATH TEST_PROVIDER_METADATA_SHA256
TEST_FAKE_RELEASE_SHA=$(printf '9%.0s' $(seq 1 40))
expect_reject_without_docker wrong-local-checkout trust_env sh "$FIXTURE_ROOT/scripts/ops-image-trust.sh"
unset TEST_FAKE_RELEASE_SHA
TEST_FAKE_DIRTY=1
expect_reject_without_docker dirty-local-checkout trust_env sh "$FIXTURE_ROOT/scripts/ops-image-trust.sh"
unset TEST_FAKE_DIRTY

jq '.opsRunner.image = "ghcr.io/owner/platform-infrastructure-ops:latest"' "$TMP/admission.json" > "$TMP/admission-mutable.json"
MUTABLE_SHA=$(hash_file "$TMP/admission-mutable.json")
TEST_ADMISSION_PATH="$TMP/admission-mutable.json"
TEST_ADMISSION_SHA256="$MUTABLE_SHA"
expect_reject_without_docker mutable-ops-image trust_env sh "$FIXTURE_ROOT/scripts/ops-image-trust.sh"
unset TEST_ADMISSION_PATH TEST_ADMISSION_SHA256

rm -f "$TMP/docker-inspected"
TEST_FAKE_IMAGE_ID="sha256:$(printf '9%.0s' $(seq 1 64))"
if trust_env sh "$FIXTURE_ROOT/scripts/ops-image-trust.sh" >/dev/null 2>&1; then
  echo "FAIL: wrong local image ID was accepted" >&2
  exit 1
fi
unset TEST_FAKE_IMAGE_ID
[ -e "$TMP/docker-inspected" ]
printf 'PASS\twrong-local-image-id\n'

expect_reject_without_docker repository-policy-remains-external-pending \
  trust_env sh "$ROOT/scripts/ops-image-trust.sh"

rm -f "$TMP/docker-run-args"
trust_env sh "$FIXTURE_ROOT/scripts/infra-ops.sh" testing-hygiene
grep -Fx -- '--pull=never' "$TMP/docker-run-args" >/dev/null
grep -Fx -- "$IMAGE_ID" "$TMP/docker-run-args" >/dev/null
grep -F -- ":/run/platform-input/infra-source.tar:ro" "$TMP/docker-run-args" >/dev/null
if grep -Fx -- "$IMAGE" "$TMP/docker-run-args" >/dev/null; then
  echo "FAIL: wrapper executed the digest alias instead of the admitted local image ID" >&2
  exit 1
fi
if grep -Fx -- "$FIXTURE_ROOT:/workspace" "$TMP/docker-run-args" >/dev/null; then
  echo "FAIL: wrapper mounted the mutable checkout as its runtime root" >&2
  exit 1
fi
printf 'PASS\twrapper-executes-admitted-id-without-pull\n'

printf 'wrong source archive bytes\n' > "$TMP/wrong-infra-source.tar"
rm -f "$TMP/docker-run-args"
TEST_SOURCE_ARCHIVE_PATH="$TMP/wrong-infra-source.tar"
export TEST_SOURCE_ARCHIVE_PATH
if trust_env sh "$FIXTURE_ROOT/scripts/infra-ops.sh" testing-hygiene >/dev/null 2>&1; then
  echo "FAIL: wrapper accepted source archive bytes not bound by the receipt" >&2
  exit 1
fi
unset TEST_SOURCE_ARCHIVE_PATH
[ ! -e "$TMP/docker-run-args" ] || {
  echo "FAIL: wrong source archive bytes reached docker run" >&2
  exit 1
}
if grep -Eq 'git .*archive|git -C .* archive' "$ROOT/scripts/infra-ops.sh"; then
  echo "FAIL: wrapper reserializes the authenticated source archive through local Git" >&2
  exit 1
fi
printf 'PASS\twrapper-consumes-exact-authenticated-archive-bytes\n'

rm -f "$TMP/docker-run-args"
TEST_SIGNAL_DURING_COPY_SOURCE="$TMP/fake-infra-source.tar"
export TEST_SIGNAL_DURING_COPY_SOURCE
set +e
trust_env sh "$FIXTURE_ROOT/scripts/infra-ops.sh" testing-hygiene >/dev/null 2>&1
signal_status=$?
set -e
unset TEST_SIGNAL_DURING_COPY_SOURCE
[ "$signal_status" -eq 143 ] || {
  echo "FAIL: host wrapper did not terminate with status 143 during source snapshot copy" >&2
  exit 1
}
[ ! -e "$TMP/docker-run-args" ] || {
  echo "FAIL: host wrapper reached docker run after TERM during source snapshot copy" >&2
  exit 1
}
printf 'PASS\thost-wrapper-term-during-copy-stops-before-execution\n'

sed "s#CODE_ROOT=/opt/platform-infrastructure#CODE_ROOT=$FIXTURE_ROOT#" \
  "$ROOT/scripts/ops-image-entrypoint.sh" > "$TMP/fixture-entrypoint.sh"
chmod 700 "$TMP/fixture-entrypoint.sh"
set +e
PATH="$FIXTURE_BIN:$PATH" \
SIGNAL_DURING_COPY_SOURCE="$TMP/fake-infra-source.tar" \
PLATFORM_INFRA_ROOT="$TMP/entrypoint-runtime" \
PLATFORM_INFRA_SNAPSHOT_ARCHIVE="$TMP/fake-infra-source.tar" \
PLATFORM_INFRA_SNAPSHOT_SHA256="$SOURCE_ARCHIVE_SHA" \
  sh "$TMP/fixture-entrypoint.sh" help >/dev/null 2>&1
signal_status=$?
set -e
[ "$signal_status" -eq 143 ] || {
  echo "FAIL: image entrypoint did not terminate with status 143 during source snapshot copy" >&2
  exit 1
}
[ ! -e "$TMP/entrypoint-runtime/scripts/infra-ops.mjs" ] || {
  echo "FAIL: image entrypoint extracted or executed source after TERM during snapshot copy" >&2
  exit 1
}
printf 'PASS\timage-entrypoint-term-during-copy-stops-before-execution\n'

rm -f "$TMP/docker-run-args"
trust_env sh "$FIXTURE_ROOT/scripts/infra-ops.sh" testing-hygiene
for denied_name in GITHUB_TOKEN GH_TOKEN RESTIC_REPOSITORY RESTIC_PASSWORD_FILE AWS_SECRET_ACCESS_KEY RCLONE_CONFIG; do
  if grep -Fx -- "$denied_name" "$TMP/docker-run-args" >/dev/null; then
    echo "FAIL: repository-only command received capability environment $denied_name" >&2
    exit 1
  fi
done
rm -f "$TMP/docker-run-args"
trust_env sh "$FIXTURE_ROOT/scripts/infra-ops.sh" pre-go-live-evidence
for required_name in \
  GITHUB_TOKEN GH_TOKEN RESTIC_REPOSITORY RESTIC_PASSWORD_FILE RESTIC_IMAGE \
  RCLONE_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN \
  B2_ACCOUNT_ID B2_ACCOUNT_KEY AZURE_ACCOUNT_NAME AZURE_ACCOUNT_KEY \
  GOOGLE_PROJECT_ID GOOGLE_ACCESS_TOKEN OS_AUTH_URL OS_PASSWORD
do
  awk -v expected="$required_name" '
    previous == "-e" && $0 == expected { found = 1 }
    { previous = $0 }
    END { exit(found ? 0 : 1) }
  ' "$TMP/docker-run-args"
done
printf 'PASS\tcommand-capability-matrix-forwards-only-required-backends\n'

hostile_source="$TMP/project --entrypoint sh --label keep"
mkdir -p "$hostile_source"
rm -f "$TMP/docker-run-args"
PROJECT_SOURCE_ROOT="$hostile_source"
export PROJECT_SOURCE_ROOT
trust_env sh "$FIXTURE_ROOT/scripts/infra-ops.sh" -c 'printf "%s\n" safe-command'
unset PROJECT_SOURCE_ROOT
awk -v expected="$hostile_source:/project:ro" '
  previous == "-v" && $0 == expected { found = 1 }
  { previous = $0 }
  END { exit(found ? 0 : 1) }
' "$TMP/docker-run-args"
awk -v image="$IMAGE_ID" '
  previous == image && $0 == "-c" { found = 1 }
  { previous = $0 }
  END { exit(found ? 0 : 1) }
' "$TMP/docker-run-args"
for injected in --entrypoint sh --label keep; do
  if grep -Fx -- "$injected" "$TMP/docker-run-args" >/dev/null; then
    echo "FAIL: source mount path injected Docker argv token $injected" >&2
    exit 1
  fi
done
printf 'PASS\tsource-mount-path-is-one-atomic-docker-argument\n'

rm -f "$TMP/docker-run-args" "$TMP/post-admission-mutation"
TEST_MUTATE_AFTER_INSPECT_PATH="$FIXTURE_ROOT/scripts/infra-ops.mjs"
TEST_MUTATE_AFTER_INSPECT_MARKER="$TMP/post-admission-mutation"
export TEST_MUTATE_AFTER_INSPECT_PATH TEST_MUTATE_AFTER_INSPECT_MARKER
if trust_env sh "$FIXTURE_ROOT/scripts/infra-ops.sh" testing-hygiene >/dev/null 2>&1; then
  echo "FAIL: wrapper accepted a checkout mutation after ops image admission" >&2
  exit 1
fi
unset TEST_MUTATE_AFTER_INSPECT_PATH TEST_MUTATE_AFTER_INSPECT_MARKER
[ ! -e "$TMP/docker-run-args" ] || {
  echo "FAIL: checkout mutation after admission reached docker run" >&2
  exit 1
}
grep -Fx 'post-admission mutation sentinel' "$FIXTURE_ROOT/scripts/infra-ops.mjs" >/dev/null
printf 'PASS\tpost-admission-checkout-mutation-never-reaches-runner\n'

if grep -Eq 'docker build|platform/ops:local|OPS_FINGERPRINT_LABEL|PLATFORM_OPS_USE_HOST_NODE|SOURCE_MOUNT_ARGS|ENV_FORWARD_ARGS|NETWORK_ARGS|shellcheck disable=SC2086' "$ROOT/scripts/infra-ops.sh"; then
  echo "FAIL: mutable, self-attested, or host bypass remains in infra-ops.sh" >&2
  exit 1
fi
printf 'PASS\tno-wrapper-build-label-or-host-bypass\n'

prepare_runs=$(grep -c 'docker run --rm --pull=never' "$ROOT/scripts/prepare-hosted-workloads.sh")
prepare_ids=$(grep -c '"$OPS_IMAGE_ID" hosted-workload-contract ' "$ROOT/scripts/prepare-hosted-workloads.sh")
[ "$prepare_runs" -ge 2 ] && [ "$prepare_ids" -eq "$prepare_runs" ]
if grep -Eq 'platform/ops:local|docker build|"\$OPS_IMAGE" scripts/' "$ROOT/scripts/prepare-hosted-workloads.sh"; then
  echo "FAIL: hosted preparation retains a mutable or caller-selected execution path" >&2
  exit 1
fi
printf 'PASS\thosted-preparation-positive-path-uses-admitted-id\n'

if grep -q 'platform/ops:local' "$ROOT/compose.backup-scheduler.yaml" || grep -q '^    build:' "$ROOT/compose.backup-scheduler.yaml"; then
  echo "FAIL: backup scheduler retains a mutable default or local build" >&2
  exit 1
fi
grep -F '${PLATFORM_OPS_IMAGE:?' "$ROOT/compose.backup-scheduler.yaml" >/dev/null
grep -F '$compose.services["backup-scheduler"].image == $deployment.opsRunner.image' "$ROOT/scripts/release-compose-admission.sh" >/dev/null
printf 'PASS\tbackup-scheduler-binds-provider-admitted-ops-image\n'

live_workflow="$ROOT/.github/workflows/enterprise-live-evidence.yml"
[ "$(grep -c 'sh ./scripts/infra-ops.sh' "$live_workflow")" -eq 7 ]
if grep -q 'node ./scripts/infra-ops.mjs' "$live_workflow"; then
  echo "FAIL: privileged live-evidence workflow bypasses the admitted ops runner" >&2
  exit 1
fi
printf 'PASS\tprivileged-live-evidence-uses-admitted-runner\n'

if grep -q 'sh ./scripts/github-attestation-evidence.sh' "$ROOT/.github/workflows/release-attestation.yml"; then
  echo "FAIL: release producer routes its repository-only verifier through the privileged runner" >&2
  exit 1
fi
if grep -q 'PLATFORM_OPS_USE_HOST_NODE' "$ROOT/.github/workflows/enterprise-infra.yml"; then
  echo "FAIL: repository-only CI retains the removed host-node bypass" >&2
  exit 1
fi
if grep -q 'platform/ops:ci' "$ROOT/.github/workflows/enterprise-infra.yml"; then
  echo "FAIL: CI backup dry-run retains a mutable local ops tag" >&2
  exit 1
fi
grep -F 'docker build --iidfile "${RUNNER_TEMP}/ops-test-image-id"' "$ROOT/.github/workflows/enterprise-infra.yml" >/dev/null
printf 'PASS\trepository-only-workflows-use-direct-node\n'

grep -F 'ref: ${{ github.sha }}' "$ROOT/.github/workflows/enterprise-infra.yml" >/dev/null
grep -F 'persist-credentials: false' "$ROOT/.github/workflows/enterprise-infra.yml" >/dev/null
grep -F 'ref: ${{ github.event.workflow_run.head_sha }}' "$ROOT/.github/workflows/enterprise-infra-run-evidence.yml" >/dev/null
printf 'PASS\tdirect-node-workflows-bind-exact-checkouts\n'

printf 'ops image trust tests passed 25/25; production provider state=EXTERNAL-PENDING\n'
