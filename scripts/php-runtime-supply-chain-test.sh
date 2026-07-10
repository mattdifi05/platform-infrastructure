#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="platform/php-apache:t15-candidate"
NEGATIVE_LOG=$(mktemp)
STDOUT_LOG=$(mktemp)
STDERR_LOG=$(mktemp)
cleanup() {
  rm -f "$NEGATIVE_LOG" "$STDOUT_LOG" "$STDERR_LOG"
  docker image rm -f "$IMAGE" platform/php-apache:t15-invalid-checksum >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker build --progress plain -f "$ROOT/docker/php-apache.Dockerfile" -t "$IMAGE" "$ROOT"

docker run --rm "$IMAGE" php -r '
if (ini_get("display_errors") !== "") exit(10);
if (ini_get("display_startup_errors") !== "") exit(11);
if (ini_get("log_errors") !== "1") exit(12);
trigger_error("T15_ERROR_LOG_PROBE", E_USER_WARNING);
echo "client-safe\n";
' > "$STDOUT_LOG" 2> "$STDERR_LOG"
grep -qx 'client-safe' "$STDOUT_LOG"
if grep -q 'T15_ERROR_LOG_PROBE' "$STDOUT_LOG"; then
  echo "PHP error leaked to standard output" >&2
  exit 1
fi
grep -q 'T15_ERROR_LOG_PROBE' "$STDERR_LOG"

if docker build --progress plain \
  --build-arg "IMAGICK_SHA256=$(printf '0%.0s' $(seq 1 64))" \
  -f "$ROOT/docker/php-apache.Dockerfile" \
  -t platform/php-apache:t15-invalid-checksum \
  "$ROOT" > "$NEGATIVE_LOG" 2>&1; then
  echo "PHP build accepted an invalid Imagick checksum" >&2
  docker image rm -f platform/php-apache:t15-invalid-checksum >/dev/null 2>&1 || true
  exit 1
fi
grep -Eq 'FAILED|did NOT match|checksum' "$NEGATIVE_LOG"

echo "PHP supply-chain test passed: valid build, hidden client error, logged server error and checksum mismatch rejection."
