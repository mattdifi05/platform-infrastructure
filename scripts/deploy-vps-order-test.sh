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
OPS_CONTAINER_ID=$(printf 'a%.0s' $(seq 1 64))
PREVIOUS_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf '0%.0s' $(seq 1 64))"
PREVIOUS_IMAGE_ID="sha256:$(printf '2%.0s' $(seq 1 64))"
PREVIOUS_CONTAINER_ID=$(printf '3%.0s' $(seq 1 64))
PREVIOUS_OPS_CONTAINER_ID=$(printf 'b%.0s' $(seq 1 64))
PREVIOUS_COMMIT=$(printf '4%.0s' $(seq 1 40))
PREVIOUS_TREE=$(printf '5%.0s' $(seq 1 40))
OPS_IMAGE="ghcr.io/owner/platform-infrastructure-ops@sha256:$(printf '7%.0s' $(seq 1 64))"
OPS_IMAGE_ID="sha256:$(printf '8%.0s' $(seq 1 64))"

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
{"version":1,"kind":"platform-trusted-deployment-admission/v1","status":"READY","artifactVerification":"passed","deploymentAdmission":"READY","repository":"owner/repo","commitSha":"$RELEASE_SHA","treeSha":"$RELEASE_TREE","artifactVerificationReceiptSha256":"$ARTIFACT_SHA","manifestSha256":"$MANIFEST_SHA","sbomSha256":"$SBOM_SHA","decisionId":"decision:12345678","verifier":{"channel":"external/prod","fingerprint":"$(printf 'f%.0s' $(seq 1 64))","selfAsserted":false},"producer":{"repository":"owner/trusted-admission","workflowPath":".github/workflows/produce-admission.yml","sourceRef":"refs/heads/main","event":"workflow_dispatch","runId":"123456","runAttempt":1,"workflowSha":"$(printf '6%.0s' $(seq 1 40))"},"opsRunner":{"image":"$OPS_IMAGE","imageId":"$OPS_IMAGE_ID","verificationFingerprint":"$(printf '9%.0s' $(seq 1 64))","providerAttested":true}}
EOF
ADMISSION_SHA=$(hash_file "$TMP/admission.json")
printf '{"id":123456,"run_attempt":1,"repository":{"full_name":"owner/trusted-admission"}}\n' > "$TMP/provider.json"
PROVIDER_SHA=$(hash_file "$TMP/provider.json")

cat > "$TMP/bin/git" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  "rev-parse --is-inside-work-tree") printf 'true\n' ;;
  "remote get-url --all origin") printf '%s\n' "$FAKE_CANONICAL_ORIGIN" ;;
  "status --porcelain --untracked-files=all") : ;;
  "fetch --no-tags origin $FAKE_RELEASE_SHA") printf 'git-fetch\n' >> "$ORDER_LOG" ;;
  "cat-file -e ${FAKE_RELEASE_SHA}^{commit}") : ;;
  "checkout --detach $FAKE_RELEASE_SHA") printf '%s\n' "$FAKE_RELEASE_SHA" > "$GIT_STATE_FILE"; printf 'git-checkout\n' >> "$ORDER_LOG" ;;
  "checkout --detach $FAKE_PREVIOUS_COMMIT") printf '%s\n' "$FAKE_PREVIOUS_COMMIT" > "$GIT_STATE_FILE"; printf 'rollback-git-checkout\n' >> "$ORDER_LOG" ;;
  "rev-parse HEAD")
    if [ -f "$GIT_STATE_FILE" ]; then cat "$GIT_STATE_FILE"; else printf '%s\n' "$FAKE_PREVIOUS_COMMIT"; fi
    ;;
  "rev-parse ${FAKE_RELEASE_SHA}^{tree}") printf '%s\n' "$FAKE_RELEASE_TREE" ;;
  "rev-parse ${FAKE_PREVIOUS_COMMIT}^{tree}") printf '%s\n' "$FAKE_PREVIOUS_TREE" ;;
  *) echo "unexpected git call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/sudo" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  *rollback-compose.json*)
    printf 'rollback-origin-apply\n' >> "$ORDER_LOG"
    [ "${FAIL_ROLLBACK_ORIGIN:-0}" != 1 ]
    ;;
  *)
    printf 'origin-apply\n' >> "$ORDER_LOG"
    [ "${FAIL_ORIGIN_APPLY:-0}" != 1 ]
    ;;
esac
SH
cat > "$TMP/bin/sh" <<'SH'
#!/bin/sh
set -eu
case "$1" in
  ./scripts/vps-preflight.sh) printf 'preflight\n' >> "$ORDER_LOG" ;;
  ./scripts/release-compose-admission.sh)
    jq -e -s '.[0].subjects == [{"key":"PHP_APACHE_IMAGE","image":$image}] and .[1].services["php-apache"].image == $image' \
      --arg image "$FAKE_APPROVED_IMAGE" "$2" "$4" >/dev/null
    jq -e --arg ops "$FAKE_OPS_IMAGE" '.opsRunner.image == $ops' "$3" >/dev/null
    printf 'subject-bind\n' >> "$ORDER_LOG"
    ;;
  ./scripts/cloudflare-origin-lock-ufw.sh)
    case "$*" in
      *rollback-compose.json*) printf 'rollback-origin-verify\n' >> "$ORDER_LOG" ;;
      *)
        count=0
        [ ! -f "$VERIFY_COUNT_FILE" ] || count=$(cat "$VERIFY_COUNT_FILE")
        count=$((count + 1))
        printf '%s\n' "$count" > "$VERIFY_COUNT_FILE"
        if [ "$count" -eq 1 ]; then
          printf 'origin-verify-pre\n' >> "$ORDER_LOG"
          [ "${FAIL_ORIGIN_VERIFY:-0}" != 1 ]
        else
          printf 'origin-verify-final\n' >> "$ORDER_LOG"
          [ "${FAIL_FINAL_ORIGIN_VERIFY:-0}" != 1 ]
        fi
        ;;
    esac
    ;;
  ./scripts/vps-postdeploy.sh)
    [ -s "$DEPLOY_ARTIFACT_RECEIPT_PATH" ]
    [ -s "$DEPLOY_ADMISSION_RECEIPT_PATH" ]
    [ -s "$DEPLOY_TRUSTED_PROVIDER_METADATA_PATH" ]
    [ "$DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256" = "$FAKE_PROVIDER_SHA" ]
    [ "$DEPLOY_TRUSTED_PROVIDER_RUN_ID" = 123456 ]
    [ "$DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT" = 1 ]
    if [ "${DEPLOY_RUN_RATE_LIMIT_EVIDENCE:-0}" = 1 ]; then
      printf 'preactivation\n' >> "$ORDER_LOG"
    else
      printf 'postactivation\n' >> "$ORDER_LOG"
      [ "${FAIL_POSTACTIVATION:-0}" != 1 ]
    fi
    ;;
  ./scripts/prepare-vps-runtime.sh) printf 'prepare\n' >> "$ORDER_LOG" ;;
  *) echo "unexpected sh call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/node" <<'SH'
#!/bin/sh
set -eu
script=$1
shift
case "$script" in
  ./scripts/trusted-provider-run-policy.mjs)
    [ "$1" = --policy ] && [ "$2" = governance/deployment-admission.json ]
    [ "$3" = --metadata ] && [ -s "$4" ]
    [ "$5" = --metadataSha256 ] && [ "$6" = "$FAKE_PROVIDER_SHA" ]
    [ "$7" = --deploymentReceipt ] && [ -s "$8" ]
    [ "$9" = --runId ] && [ "${10}" = 123456 ]
    [ "${11}" = --runAttempt ] && [ "${12}" = 1 ]
    printf 'provider-run-verify\n' >> "$ORDER_LOG"
    ;;
  ./scripts/deployment-receipt-policy.mjs)
    case "$*" in
      *"--policy governance/deployment-admission.json"*"--artifactReceipt "*"--deploymentReceipt "*"--providerRunId 123456 --providerRunAttempt 1") ;;
      *) echo "unexpected deployment receipt policy args: $*" >&2; exit 1 ;;
    esac
    printf 'deployment-receipt-verify\n' >> "$ORDER_LOG"
    ;;
  *) echo "unexpected node call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/bash" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  *"compose-vps.sh config --format json")
    count=0
    [ ! -f "$CONFIG_COUNT_FILE" ] || count=$(cat "$CONFIG_COUNT_FILE")
    count=$((count + 1))
    printf '%s\n' "$count" > "$CONFIG_COUNT_FILE"
    if [ "$count" -eq 1 ]; then
      printf 'rollback-config\n' >> "$ORDER_LOG"
      image=$FAKE_PREVIOUS_IMAGE
    else
      printf 'compose-config\n' >> "$ORDER_LOG"
      image=${FAKE_COMPOSE_IMAGE:-$FAKE_APPROVED_IMAGE}
    fi
    printf '{"services":{"php-apache":{"image":"%s","ports":[{"published":443,"target":8443,"protocol":"tcp","host_ip":"0.0.0.0"}],"volumes":[{"type":"volume","source":"database","target":"/var/lib/php-data"}]},"backup-scheduler":{"image":"%s"}},"volumes":{"database":{"name":"platform_database","driver":"local"}}}\n' "$image" "$FAKE_OPS_IMAGE"
    ;;
  *) echo "unexpected bash call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/docker" <<'SH'
#!/bin/sh
set -eu
case "$*" in
  "volume inspect platform_database")
    count=0
    [ ! -f "$VOLUME_COUNT_FILE" ] || count=$(cat "$VOLUME_COUNT_FILE")
    count=$((count + 1))
    printf '%s\n' "$count" > "$VOLUME_COUNT_FILE"
    if [ "$count" -eq 1 ]; then printf 'volume-before\n' >> "$ORDER_LOG"; else printf 'volume-after\n' >> "$ORDER_LOG"; fi
    mountpoint=/var/lib/docker/volumes/platform_database/_data
    if [ "${VOLUME_DRIFT:-0}" = 1 ] && [ "$count" -gt 1 ]; then mountpoint=/var/lib/docker/volumes/replaced/_data; fi
    printf '[{"Name":"platform_database","Driver":"local","Mountpoint":"%s","Scope":"local","Options":null,"Labels":null}]\n' "$mountpoint"
    ;;
  "pull $FAKE_APPROVED_IMAGE")
    printf 'image-pull\n' >> "$ORDER_LOG"
    [ "${FAIL_PULL:-0}" != 1 ]
    ;;
  "image inspect --format {{.Id}} $FAKE_APPROVED_IMAGE")
    [ "${FAIL_IMAGE_INSPECT:-0}" != 1 ]
    printf '%s\n' "$FAKE_APPROVED_IMAGE_ID"
    ;;
  "image inspect --format {{.Id}} $FAKE_PREVIOUS_IMAGE")
    printf 'rollback-image-bind\n' >> "$ORDER_LOG"
    printf '%s\n' "$FAKE_PREVIOUS_IMAGE_ID"
    ;;
  "compose "*" up -d --remove-orphans --no-build --pull never")
    case "$*" in
      *rollback-compose.json*)
        printf 'rollback-up\n' >> "$ORDER_LOG"
        [ "${FAIL_ROLLBACK:-0}" != 1 ]
        ;;
      *)
        printf '%s\n' "$*" > "$COMPOSE_UP_ARGS"
        printf 'compose-up\n' >> "$ORDER_LOG"
        ;;
    esac
    ;;
  "compose "*" ps --no-trunc -q php-apache")
    case "$*" in
      *rollback-compose.json*) printf '%s\n' "$FAKE_PREVIOUS_CONTAINER_ID" ;;
      *) printf '%s\n' "$FAKE_RUNTIME_CONTAINER_ID" ;;
    esac
    ;;
  "compose "*rollback-compose.json*" ps --no-trunc -q backup-scheduler")
    printf '%s\n' "$FAKE_PREVIOUS_OPS_CONTAINER_ID"
    ;;
  "compose "*" ps --no-trunc -q backup-scheduler")
    printf '%s\n' "$FAKE_OPS_CONTAINER_ID"
    ;;
  "inspect --format {{.Image}} $FAKE_RUNTIME_CONTAINER_ID")
    printf 'runtime-verify\n' >> "$ORDER_LOG"
    printf '%s\n' "${FAKE_RUNTIME_IMAGE_ID:-$FAKE_APPROVED_IMAGE_ID}"
    ;;
  "inspect --format {{.Image}} $FAKE_PREVIOUS_CONTAINER_ID")
    printf 'previous-runtime-verify\n' >> "$ORDER_LOG"
    printf '%s\n' "$FAKE_PREVIOUS_IMAGE_ID"
    ;;
  "inspect --format {{.Image}} $FAKE_OPS_CONTAINER_ID")
    printf 'ops-runtime-verify\n' >> "$ORDER_LOG"
    printf '%s\n' "${FAKE_OPS_RUNTIME_IMAGE_ID:-$FAKE_OPS_IMAGE_ID}"
    ;;
  "inspect --format {{.Image}} $FAKE_PREVIOUS_OPS_CONTAINER_ID")
    printf 'previous-ops-runtime-verify\n' >> "$ORDER_LOG"
    printf '%s\n' "$FAKE_OPS_IMAGE_ID"
    ;;
  *) echo "unexpected docker call: $*" >&2; exit 1 ;;
esac
SH
cat > "$TMP/bin/timeout" <<'SH'
#!/bin/sh
set -eu
shift
exec "$@"
SH
chmod 700 "$TMP/bin/git" "$TMP/bin/sudo" "$TMP/bin/sh" "$TMP/bin/bash" "$TMP/bin/docker" "$TMP/bin/node" "$TMP/bin/timeout"

run_remote() {
  rm -f "$TMP/config-count" "$TMP/volume-count" "$TMP/verify-count" "$TMP/compose-up-args" "$TMP/git-state"
  env \
    PATH="$TMP/bin:$PATH" ORDER_LOG="$LOG" COMPOSE_UP_ARGS="$TMP/compose-up-args" CONFIG_COUNT_FILE="$TMP/config-count" VOLUME_COUNT_FILE="$TMP/volume-count" VERIFY_COUNT_FILE="$TMP/verify-count" GIT_STATE_FILE="$TMP/git-state" \
    FAKE_RELEASE_SHA="$RELEASE_SHA" FAKE_RELEASE_TREE="$RELEASE_TREE" FAKE_CANONICAL_ORIGIN='https://github.com/owner/repo.git' \
    FAKE_APPROVED_IMAGE="$APPROVED_IMAGE" FAKE_APPROVED_IMAGE_ID="$APPROVED_IMAGE_ID" FAKE_RUNTIME_CONTAINER_ID="$RUNTIME_CONTAINER_ID" \
    FAKE_OPS_IMAGE="$OPS_IMAGE" FAKE_OPS_IMAGE_ID="$OPS_IMAGE_ID" FAKE_OPS_CONTAINER_ID="$OPS_CONTAINER_ID" FAKE_PROVIDER_SHA="$PROVIDER_SHA" \
    FAKE_PREVIOUS_IMAGE="$PREVIOUS_IMAGE" FAKE_PREVIOUS_IMAGE_ID="$PREVIOUS_IMAGE_ID" FAKE_PREVIOUS_CONTAINER_ID="$PREVIOUS_CONTAINER_ID" FAKE_PREVIOUS_OPS_CONTAINER_ID="$PREVIOUS_OPS_CONTAINER_ID" \
    FAKE_PREVIOUS_COMMIT="$PREVIOUS_COMMIT" FAKE_PREVIOUS_TREE="$PREVIOUS_TREE" \
    PLATFORM_REMOTE_DIR_B64="$(encode "$REMOTE_DIR")" \
    PLATFORM_ENV_FILE_B64="$(encode '.env')" \
    PLATFORM_PROJECT_NAME_B64="$(encode 'platform_infra_vps')" \
    PLATFORM_RELEASE_SHA_B64="$(encode "$RELEASE_SHA")" \
    PLATFORM_RELEASE_TREE_B64="$(encode "$RELEASE_TREE")" \
    PLATFORM_DEPLOY_REPO_B64="$(encode 'owner/repo')" \
    PLATFORM_CANONICAL_ORIGIN_B64="$(encode 'https://github.com/owner/repo.git')" \
    PLATFORM_SSH_PORT_B64="$(encode 65002)" \
    PLATFORM_ARTIFACT_RECEIPT_SHA256_B64="$(encode "$ARTIFACT_SHA")" \
    PLATFORM_ADMISSION_RECEIPT_SHA256_B64="$(encode "$ADMISSION_SHA")" \
    PLATFORM_PROVIDER_METADATA_SHA256_B64="$(encode "$PROVIDER_SHA")" \
    PLATFORM_PROVIDER_RUN_ID_B64="$(encode 123456)" \
    PLATFORM_PROVIDER_RUN_ATTEMPT_B64="$(encode 1)" \
    PLATFORM_ARTIFACT_RECEIPT_B64="$(encode_file "$TMP/artifact.json")" \
    PLATFORM_ADMISSION_RECEIPT_B64="$(encode_file "$TMP/admission.json")" \
    PLATFORM_PROVIDER_METADATA_B64="$(encode_file "$TMP/provider.json")" \
    PLATFORM_RUN_WAF_SMOKE_B64="$(encode 1)" \
    PLATFORM_RUN_INFRA_HEALTH_B64="$(encode 1)" \
    PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64="$(encode 1)" \
    PLATFORM_RUN_PRE_GO_LIVE_B64="$(encode 1)" \
    PLATFORM_RUN_GO_NO_GO_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64="$(encode 1)" \
    PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64="$(encode 1)" \
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

for gate in \
  PLATFORM_RUN_WAF_SMOKE_B64 PLATFORM_RUN_INFRA_HEALTH_B64 PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64 \
  PLATFORM_RUN_PRE_GO_LIVE_B64 PLATFORM_RUN_GO_NO_GO_B64 PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64 \
  PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64 PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64 PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64
do
  : > "$LOG"
  if run_remote env "$gate=$(encode 0)" >/dev/null 2>&1; then echo "FAIL: disabled mandatory remote gate $gate was accepted" >&2; exit 1; fi
  if grep -Eq '^(git-fetch|origin-apply|prepare|compose-up|rollback-up)$' "$LOG"; then echo "FAIL: disabled mandatory remote gate reached checkout or mutation" >&2; exit 1; fi
done
printf 'PASS\tmandatory-remote-gates-cannot-be-skipped\n'

: > "$LOG"
if run_remote env FAIL_PULL=1 >/dev/null 2>&1; then echo "FAIL: failed exact image pull was accepted" >&2; exit 1; fi
if grep -Eq '^(origin-apply|prepare|compose-up|rollback-up)$' "$LOG"; then echo "FAIL: failed pull reached mutation or rollback" >&2; exit 1; fi
printf 'PASS\tpull-failure-blocks-mutation\n'

: > "$LOG"
if run_remote env FAIL_IMAGE_INSPECT=1 >/dev/null 2>&1; then echo "FAIL: failed exact image inspect was accepted" >&2; exit 1; fi
if grep -Eq '^(origin-apply|prepare|compose-up|rollback-up)$' "$LOG"; then echo "FAIL: failed image inspect reached mutation or rollback" >&2; exit 1; fi
printf 'PASS\timage-inspect-failure-blocks-mutation\n'

: > "$LOG"
if run_remote env FAIL_ORIGIN_APPLY=1 >/dev/null 2>&1; then echo "FAIL: failed origin reconcile was accepted" >&2; exit 1; fi
assert_not_activated
printf 'PASS\torigin-reconcile-failure-blocks-activation\n'

: > "$LOG"
if run_remote env FAIL_ORIGIN_VERIFY=1 >/dev/null 2>&1; then echo "FAIL: failed origin verification was accepted" >&2; exit 1; fi
assert_not_activated
printf 'PASS\torigin-verification-failure-blocks-activation\n'

: > "$LOG"
if run_remote env FAIL_FINAL_ORIGIN_VERIFY=1 >/dev/null 2>&1; then echo "FAIL: post-prepare origin drift was accepted" >&2; exit 1; fi
grep -Fx 'prepare' "$LOG" >/dev/null
grep -Fx 'origin-verify-final' "$LOG" >/dev/null
if grep -Fx 'compose-up' "$LOG" >/dev/null; then echo "FAIL: post-prepare origin drift reached runtime activation" >&2; exit 1; fi
printf 'PASS\tpost-prepare-origin-drift-blocks-compose\n'

: > "$LOG"
if run_remote env FAKE_RUNTIME_IMAGE_ID="$PREVIOUS_IMAGE_ID" >"$TMP/runtime-mismatch.out" 2>"$TMP/runtime-mismatch.err"; then echo "FAIL: runtime image ID mismatch was accepted" >&2; exit 1; fi
if ! grep -Fx 'rollback-up' "$LOG" >/dev/null; then
  echo "FAIL: runtime image mismatch did not reach rollback" >&2
  cat "$TMP/runtime-mismatch.err" >&2
  cat "$LOG" >&2
  exit 1
fi
grep -Fx 'volume-after' "$LOG" >/dev/null
if grep -Fx 'postactivation' "$LOG" >/dev/null; then echo "FAIL: runtime mismatch reached postactivation" >&2; exit 1; fi
printf 'PASS\truntime-image-mismatch-rolls-back\n'

: > "$LOG"
if run_remote env FAKE_OPS_RUNTIME_IMAGE_ID="$APPROVED_IMAGE_ID" >"$TMP/ops-runtime-mismatch.out" 2>"$TMP/ops-runtime-mismatch.err"; then
  echo "FAIL: backup scheduler image ID mismatch was accepted" >&2
  exit 1
fi
grep -Fx 'ops-runtime-verify' "$LOG" >/dev/null
grep -Fx 'rollback-up' "$LOG" >/dev/null
if grep -Fx 'postactivation' "$LOG" >/dev/null; then echo "FAIL: backup scheduler mismatch reached postactivation" >&2; exit 1; fi
printf 'PASS\tbackup-scheduler-image-mismatch-rolls-back\n'

: > "$LOG"
if run_remote env FAIL_POSTACTIVATION=1 >/dev/null 2>&1; then echo "FAIL: synthetic postactivation failure was accepted" >&2; exit 1; fi
grep -Fx 'rollback-up' "$LOG" >/dev/null
grep -Fx 'previous-runtime-verify' "$LOG" >/dev/null
grep -Fx 'volume-after' "$LOG" >/dev/null
printf 'PASS\tsynthetic-failure-restores-runtime-and-volume-identity\n'

: > "$LOG"
set +e
run_remote env FAIL_POSTACTIVATION=1 FAIL_ROLLBACK=1 >/dev/null 2>&1
rollback_status=$?
set -e
[ "$rollback_status" -eq 72 ] || { echo "FAIL: rollback failure did not return hard status 72 (got $rollback_status)" >&2; exit 1; }
printf 'PASS\trollback-failure-is-hard-failure\n'

: > "$LOG"
set +e
run_remote env FAIL_POSTACTIVATION=1 VOLUME_DRIFT=1 >/dev/null 2>&1
volume_drift_status=$?
set -e
[ "$volume_drift_status" -eq 72 ] || { echo "FAIL: rollback volume drift did not return hard status 72 (got $volume_drift_status)" >&2; exit 1; }
printf 'PASS\trollback-volume-identity-drift-is-hard-failure\n'

: > "$LOG"
run_remote env >/dev/null
cat > "$TMP/expected-order" <<'EOF'
rollback-config
volume-before
previous-ops-runtime-verify
previous-runtime-verify
previous-runtime-verify
rollback-image-bind
git-fetch
git-checkout
provider-run-verify
deployment-receipt-verify
preactivation
preflight
compose-config
subject-bind
image-pull
origin-apply
origin-verify-pre
prepare
origin-verify-final
compose-up
runtime-verify
ops-runtime-verify
postactivation
EOF
cmp "$TMP/expected-order" "$LOG"
grep -F -- '--project-directory' "$TMP/compose-up-args" >/dev/null
grep -F -- '--profile backup' "$TMP/compose-up-args" >/dev/null
grep -F -- '--no-build' "$TMP/compose-up-args" >/dev/null
grep -F -- '--pull never' "$TMP/compose-up-args" >/dev/null
if grep -Eq '(^| )--build( |$)' "$TMP/compose-up-args"; then echo "FAIL: remote deploy still permits build-on-host" >&2; exit 1; fi
printf 'PASS\texact-gates-before-prepare-and-compose-up\n'

grep -F 'timeout 120 sudo -n sh ./scripts/cloudflare-origin-lock-ufw.sh --apply' "$SCRIPT_DIR/deploy-vps-remote.sh" | grep -F -- '--ssh-port "$ssh_port"' >/dev/null
grep -F 'timeout 120 sh ./scripts/cloudflare-origin-lock-ufw.sh --verify' "$SCRIPT_DIR/deploy-vps-remote.sh" | grep -F -- '--ssh-port "$ssh_port"' >/dev/null
grep -F 'timeout 300 sh ./scripts/prepare-vps-runtime.sh' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -F 'timeout "$activation_timeout_seconds" docker compose' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -F 'timeout "$postactivation_timeout_seconds" sh ./scripts/vps-postdeploy.sh' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
printf 'PASS\tpost-boundary-commands-are-bounded\n'

if grep -Eq 'docker (compose .*down|volume (rm|prune)|system prune)' "$SCRIPT_DIR/deploy-vps-remote.sh"; then
  echo "FAIL: rollback contains a destructive volume/project teardown operation" >&2
  exit 1
fi
printf 'PASS\trollback-never-deletes-project-or-volumes\n'

printf 'deploy VPS order tests passed 15/15\n'
