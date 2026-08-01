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

grep -Fx 'exec /usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate' \
  "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
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

printf 'deploy VPS broker order tests passed 9/9\n'
