#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/deploy-vps-order-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/bin"

cat > "$TMP/bin/sudo" <<'SH'
#!/usr/bin/env sh
set -eu
: > "$PATH_SHADOW_INVOKED"
exit 99
SH
chmod 0555 "$TMP/bin/sudo"

grep -Fx 'BROKER=/usr/local/libexec/platform-activation-broker' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -Fx 'SUDO=/usr/bin/sudo' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -Fx 'MAX_REQUEST_BYTES=1048576' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -F 'if [ "$SYSTEM_NAME" != Linux ]; then' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -F '/bin/dd if=/dev/stdin of="$request" bs=65536 count=17' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -F '[ "$size" -gt 0 ] && [ "$size" -le "$MAX_REQUEST_BYTES" ]' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
grep -Fx 'exec "$SUDO" -n "$BROKER" activate < "$request"' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
if grep -Eq 'exec[[:space:]]+sudo|/usr/bin/env[[:space:]]+sudo' "$SCRIPT_DIR/deploy-vps-remote.sh"; then
  echo "FAIL: activation sink resolves sudo through caller PATH" >&2
  exit 1
fi
printf 'PASS\texact-absolute-root-broker-sink\n'

rm -f "$TMP/path-shadow-invoked"
if env PATH="$TMP/bin:$PATH" PATH_SHADOW_INVOKED="$TMP/path-shadow-invoked" \
  sh "$SCRIPT_DIR/deploy-vps-remote.sh" attacker >/dev/null 2>&1; then
  echo "FAIL: activation sink accepted a caller-selected argument" >&2
  exit 1
fi
[ ! -e "$TMP/path-shadow-invoked" ]
printf 'PASS\tcaller-selected-arguments-rejected-before-any-sudo\n'

grep -F "ssh \"\$@\" -- \"\$REMOTE\" '/usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate'" \
  "$SCRIPT_DIR/deploy-vps.sh" >/dev/null
printf 'PASS\tssh-uses-option-terminator-and-absolute-root-broker\n'

if grep -Eq 'git (fetch|pull|checkout)|docker |compose-vps|prepare-vps-runtime|cloudflare-origin-lock|base64|PLATFORM_REMOTE_DIR|PLATFORM_SOURCE_ARCHIVE' \
  "$SCRIPT_DIR/deploy-vps-remote.sh"; then
  echo "FAIL: fixed activation sink contains a legacy remote mutation or staging path" >&2
  exit 1
fi
printf 'PASS\tlegacy-remote-mutator-is-absent\n'

request_line=$(grep -n 'node "$SCRIPT_ROOT/activation-request.mjs"' "$SCRIPT_DIR/deploy-vps.sh" | cut -d: -f1)
ssh_line=$(grep -n "ssh \"\$@\" -- \"\$REMOTE\" '/usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate'" "$SCRIPT_DIR/deploy-vps.sh" | cut -d: -f1)
receipt_line=$(grep -n 'node "$SCRIPT_ROOT/activation-receipt-policy.mjs"' "$SCRIPT_DIR/deploy-vps.sh" | cut -d: -f1)
[ "$request_line" -lt "$ssh_line" ] && [ "$ssh_line" -lt "$receipt_line" ] || {
  echo "FAIL: request, broker activation and receipt validation are not ordered" >&2
  exit 1
}
printf 'PASS\trequest-before-broker-before-receipt-validation\n'

for required in \
  DEPLOY_DAST_PROVIDER_RECEIPT_PATH \
  DEPLOY_DAST_PROVIDER_RECEIPT_SHA256 \
  DEPLOY_DAST_ACTIVATION_AUTHORIZATION_PATH \
  DEPLOY_DAST_ACTIVATION_AUTHORIZATION_SHA256 \
  DEPLOY_DAST_PROVIDER_METADATA_SHA256 \
  DEPLOY_DAST_SIGSTORE_BUNDLE_SHA256 \
  DEPLOY_DAST_SIGSTORE_SUBJECT \
  DEPLOY_DAST_CHAIN_SHA256 \
  DEPLOY_RELEASE_BUNDLE_MANIFEST_PATH \
  DEPLOY_RELEASE_BUNDLE_SHA256 \
  DEPLOY_RELEASE_BUNDLE_SIZE_BYTES \
  DEPLOY_RELEASE_BUNDLE_MANIFEST_SHA256 \
  DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SHA256 \
  DEPLOY_DOCKER_ACTIVATION_ENVELOPE_SIZE_BYTES \
  DEPLOY_DOCKER_ACTIVATION_ENVELOPE_PAYLOAD_TYPE \
  DEPLOY_DOCKER_ACTIVATION_RUNTIME_INTENT_ID \
  DEPLOY_DOCKER_ACTIVATION_GENERATION; do
  grep -F "$required" "$SCRIPT_DIR/deploy-vps.sh" >/dev/null || {
    echo "FAIL: deployment client omits v3 input $required" >&2
    exit 1
  }
done
printf 'PASS\texact-v3-release-and-docker-activation-inputs\n'

if grep -Eq 'DEPLOY_DAST_RECEIPT_(PATH|SHA256)|DEPLOY_ACTIVATION_BUNDLE_|DEPLOY_ACTIVATION_ADMISSION_|--dastReceipt([[:space:]]|$)|--activationAdmission' \
  "$SCRIPT_DIR/deploy-vps.sh"; then
  echo "FAIL: deployment client retains a legacy DAST/bundle/admission input" >&2
  exit 1
fi
printf 'PASS\tlegacy-activation-admission-is-absent\n'

grep -F '[ "${1:-}" = "deploy-vps" ]' "$SCRIPT_DIR/ops-image-entrypoint.sh" >/dev/null
grep -F 'export PLATFORM_TRUSTED_OPS_RUNNER=1' "$SCRIPT_DIR/ops-image-entrypoint.sh" >/dev/null
grep -F 'export PLATFORM_OPS_CODE_ROOT="$CODE_ROOT"' "$SCRIPT_DIR/ops-image-entrypoint.sh" >/dev/null
grep -F 'exec sh "$CODE_ROOT/scripts/deploy-vps.sh"' "$SCRIPT_DIR/ops-image-entrypoint.sh" >/dev/null
printf 'PASS\ttrusted-ops-entrypoint-is-the-deployment-runner\n'

grep -F 'activation-request.mjs' "$ROOT/docker/ops.Dockerfile" >/dev/null
grep -F 'activation-receipt-policy.mjs' "$ROOT/docker/ops.Dockerfile" >/dev/null
grep -F '/opt/platform-infrastructure/scripts/ops-image-entrypoint.sh' "$ROOT/docker/ops.Dockerfile" >/dev/null
printf 'PASS\tops-image-contains-request-and-receipt-boundary\n'

for forbidden in 'sh -s' 'scp ' 'sftp ' 'git ' 'docker ' 'prepare-vps-runtime.sh' 'cloudflare-origin-lock-ufw.sh'; do
  if grep -F "$forbidden" "$SCRIPT_DIR/deploy-vps.sh" >/dev/null; then
    echo "FAIL: deployment client contains legacy candidate-side operation: $forbidden" >&2
    exit 1
  fi
done
printf 'PASS\tdeployment-client-has-no-alternate-mutation-sink\n'

if grep -Eq 'DEPLOY_REMOTE_DIR|DEPLOY_SOURCE_ARCHIVE_PATH|DEPLOY_RUN_|PRE_GO_LIVE' "$SCRIPT_DIR/deploy-vps.sh"; then
  echo "FAIL: deployment client still consumes legacy remote-mutator inputs" >&2
  exit 1
fi
printf 'PASS\tlegacy-ordering-inputs-are-not-consumed\n'

printf 'deploy VPS broker order tests passed 11/11\n'
