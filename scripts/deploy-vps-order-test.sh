#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/deploy-vps-order-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/remote" "$TMP/bin"
REMOTE_DIR=$(CDPATH= cd -- "$TMP/remote" && pwd -P)
LOG="$TMP/order.log"
RELEASE_SHA=$(printf 'a%.0s' $(seq 1 40))
RELEASE_TREE=$(printf 'b%.0s' $(seq 1 40))
MANIFEST_SHA=$(printf 'c%.0s' $(seq 1 64))
SBOM_SHA=$(printf 'd%.0s' $(seq 1 64))
APPROVED_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf 'e%.0s' $(seq 1 64))"
OTHER_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf '9%.0s' $(seq 1 64))"
APPROVED_IMAGE_ID="sha256:$(printf 'f%.0s' $(seq 1 64))"
RUNTIME_CONTAINER_ID=$(printf '1%.0s' $(seq 1 64))

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
encode() { printf '%s' "$1" | base64 | tr -d '\r\n'; }
encode_file() { base64 < "$1" | tr -d '\r\n'; }

cat > "$TMP/artifact.json" <<EOF
{"version":1,"kind":"platform-release-artifact-verification/v1","status":"EXTERNAL-PENDING","artifactVerification":"passed","deploymentAdmission":"EXTERNAL-PENDING","usageScope":"artifact-verification-only","repository":"owner/repo","commitSha":"$RELEASE_SHA","manifestSha256":"$MANIFEST_SHA","sbomSha256":"$SBOM_SHA","subjects":[{"key":"PHP_APACHE_IMAGE","image":"$APPROVED_IMAGE"}]}
EOF
ARTIFACT_SHA=$(hash_file "$TMP/artifact.json")
cat > "$TMP/admission.json" <<EOF
{"version":1,"kind":"platform-trusted-deployment-admission/v1","status":"READY","artifactVerification":"passed","deploymentAdmission":"READY","repository":"owner/repo","commitSha":"$RELEASE_SHA","treeSha":"$RELEASE_TREE","artifactVerificationReceiptSha256":"$ARTIFACT_SHA","manifestSha256":"$MANIFEST_SHA","sbomSha256":"$SBOM_SHA","decisionId":"decision:12345678","verifier":{"channel":"external/prod","fingerprint":"$(printf 'f%.0s' $(seq 1 64))","selfAsserted":false}}
EOF
ADMISSION_SHA=$(hash_file "$TMP/admission.json")

cat > "$TMP/bin/git" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  "rev-parse --is-inside-work-tree") printf 'true\n' ;;
  "remote get-url --all origin") printf '%s\n' "$FAKE_CANONICAL_ORIGIN" ;;
  "status --porcelain --untracked-files=all") : ;;
  "fetch --no-tags origin $FAKE_RELEASE_SHA") printf 'git-fetch\n' >> "$ORDER_LOG" ;;
  "cat-file -e ${FAKE_RELEASE_SHA}^{commit}") : ;;
  "checkout --detach $FAKE_RELEASE_SHA") printf 'git-checkout\n' >> "$ORDER_LOG" ;;
  "rev-parse HEAD") printf '%s\n' "$FAKE_RELEASE_SHA" ;;
  "rev-parse ${FAKE_RELEASE_SHA}^{tree}") printf '%s\n' "$FAKE_RELEASE_TREE" ;;
  *) echo "unexpected git call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/sudo" <<'SH'
#!/bin/sh
set -eu
printf 'origin-apply\n' >> "$ORDER_LOG"
[ "${FAIL_ORIGIN_APPLY:-0}" != 1 ]
SH
cat > "$TMP/bin/sh" <<'SH'
#!/bin/sh
set -eu
case "$1" in
  ./scripts/vps-preflight.sh) printf 'preflight\n' >> "$ORDER_LOG" ;;
  ./scripts/release-compose-admission.sh)
    jq -e -s '.[0].subjects == [{"key":"PHP_APACHE_IMAGE","image":$image}] and .[1].services["php-apache"].image == $image' \
      --arg image "$FAKE_APPROVED_IMAGE" "$2" "$3" >/dev/null
    printf 'subject-bind\n' >> "$ORDER_LOG"
    ;;
  ./scripts/cloudflare-origin-lock-ufw.sh)
    printf 'origin-verify\n' >> "$ORDER_LOG"
    [ "${FAIL_ORIGIN_VERIFY:-0}" != 1 ]
    ;;
  ./scripts/vps-postdeploy.sh)
    if [ "${DEPLOY_RUN_RATE_LIMIT_EVIDENCE:-0}" = 1 ]; then
      printf 'preactivation\n' >> "$ORDER_LOG"
    else
      printf 'postactivation\n' >> "$ORDER_LOG"
    fi
    ;;
  ./scripts/prepare-vps-runtime.sh) printf 'prepare\n' >> "$ORDER_LOG" ;;
  *) echo "unexpected sh call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/bash" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  *"compose-vps.sh config --format json")
    printf 'compose-config\n' >> "$ORDER_LOG"
    printf '{"services":{"edge":{"ports":[{"published":443,"target":8443,"protocol":"tcp","host_ip":"0.0.0.0"}]},"php-apache":{"image":"%s"}},"volumes":{}}\n' "${FAKE_COMPOSE_IMAGE:-$FAKE_APPROVED_IMAGE}"
    ;;
  *) echo "unexpected bash call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/docker" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  "pull $FAKE_APPROVED_IMAGE") printf 'image-pull\n' >> "$ORDER_LOG" ;;
  "image inspect --format {{.Id}} $FAKE_APPROVED_IMAGE") printf '%s\n' "$FAKE_APPROVED_IMAGE_ID" ;;
  "compose "*" up -d --remove-orphans --no-build --pull never")
    printf '%s\n' "$*" > "$COMPOSE_UP_ARGS"
    printf 'compose-up\n' >> "$ORDER_LOG"
    ;;
  "compose "*" ps --no-trunc -q php-apache") printf '%s\n' "$FAKE_RUNTIME_CONTAINER_ID" ;;
  "inspect --format {{.Image}} $FAKE_RUNTIME_CONTAINER_ID")
    printf 'runtime-verify\n' >> "$ORDER_LOG"
    printf '%s\n' "$FAKE_APPROVED_IMAGE_ID"
    ;;
  *) echo "unexpected docker call: $*" >&2; exit 1 ;;
esac
SH
chmod 700 "$TMP/bin/git" "$TMP/bin/sudo" "$TMP/bin/sh" "$TMP/bin/bash" "$TMP/bin/docker"

run_remote() {
  env \
    PATH="$TMP/bin:$PATH" ORDER_LOG="$LOG" COMPOSE_UP_ARGS="$TMP/compose-up-args" \
    FAKE_RELEASE_SHA="$RELEASE_SHA" FAKE_RELEASE_TREE="$RELEASE_TREE" FAKE_CANONICAL_ORIGIN='https://github.com/owner/repo.git' \
    FAKE_APPROVED_IMAGE="$APPROVED_IMAGE" FAKE_APPROVED_IMAGE_ID="$APPROVED_IMAGE_ID" FAKE_RUNTIME_CONTAINER_ID="$RUNTIME_CONTAINER_ID" \
    PLATFORM_REMOTE_DIR_B64="$(encode "$REMOTE_DIR")" \
    PLATFORM_ENV_FILE_B64="$(encode '.env')" \
    PLATFORM_PROJECT_NAME_B64="$(encode 'platform_infra_vps')" \
    PLATFORM_RELEASE_SHA_B64="$(encode "$RELEASE_SHA")" \
    PLATFORM_RELEASE_TREE_B64="$(encode "$RELEASE_TREE")" \
    PLATFORM_DEPLOY_REPO_B64="$(encode 'owner/repo')" \
    PLATFORM_CANONICAL_ORIGIN_B64="$(encode 'https://github.com/owner/repo.git')" \
    PLATFORM_ARTIFACT_RECEIPT_SHA256_B64="$(encode "$ARTIFACT_SHA")" \
    PLATFORM_ADMISSION_RECEIPT_SHA256_B64="$(encode "$ADMISSION_SHA")" \
    PLATFORM_ARTIFACT_RECEIPT_B64="$(encode_file "$TMP/artifact.json")" \
    PLATFORM_ADMISSION_RECEIPT_B64="$(encode_file "$TMP/admission.json")" \
    PLATFORM_RUN_WAF_SMOKE_B64="$(encode 1)" \
    PLATFORM_RUN_INFRA_HEALTH_B64="$(encode 1)" \
    PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64="$(encode 1)" \
    PLATFORM_RUN_PRE_GO_LIVE_B64="$(encode 1)" \
    PLATFORM_RUN_GO_NO_GO_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64="$(encode 0)" \
    "$@" /bin/sh "$SCRIPT_DIR/deploy-vps-remote.sh"
}

assert_not_activated() {
  if grep -Eq '^(prepare|compose-up)$' "$LOG"; then
    echo "FAIL: runtime activation was reached after a failed preactivation gate" >&2
    exit 1
  fi
}

: > "$LOG"
if run_remote env FAKE_COMPOSE_IMAGE="$OTHER_IMAGE" >/dev/null 2>&1; then echo "FAIL: mismatched rendered release image was accepted" >&2; exit 1; fi
if grep -Eq '^(origin-apply|prepare|compose-up)$' "$LOG"; then echo "FAIL: release subject mismatch reached a mutation" >&2; exit 1; fi
printf 'PASS\tsubject-compose-mismatch-blocks-mutation\n'

: > "$LOG"
if run_remote env FAIL_ORIGIN_APPLY=1 >/dev/null 2>&1; then echo "FAIL: failed origin reconcile was accepted" >&2; exit 1; fi
assert_not_activated
printf 'PASS\torigin-reconcile-failure-blocks-activation\n'

: > "$LOG"
if run_remote env FAIL_ORIGIN_VERIFY=1 >/dev/null 2>&1; then echo "FAIL: failed origin verification was accepted" >&2; exit 1; fi
assert_not_activated
printf 'PASS\torigin-verification-failure-blocks-activation\n'

: > "$LOG"
run_remote env >/dev/null
cat > "$TMP/expected-order" <<'EOF'
git-fetch
git-checkout
preactivation
preflight
compose-config
subject-bind
image-pull
origin-apply
origin-verify
prepare
compose-up
runtime-verify
postactivation
EOF
cmp "$TMP/expected-order" "$LOG"
grep -F -- '--project-directory' "$TMP/compose-up-args" >/dev/null
grep -F -- '--profile backup' "$TMP/compose-up-args" >/dev/null
grep -F -- '--no-build' "$TMP/compose-up-args" >/dev/null
grep -F -- '--pull never' "$TMP/compose-up-args" >/dev/null
if grep -Eq '(^| )--build( |$)' "$TMP/compose-up-args"; then echo "FAIL: remote deploy still permits build-on-host" >&2; exit 1; fi
printf 'PASS\texact-gates-before-prepare-and-compose-up\n'
printf 'deploy VPS order tests passed 4/4\n'
