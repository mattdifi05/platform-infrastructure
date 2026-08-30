#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPS_IMAGE="platform/ops:t15-candidate"
CONTROL_IMAGE="platform/control-center:t15-candidate"
cleanup() {
  docker image rm -f "$OPS_IMAGE" "$CONTROL_IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker build --quiet -f "$ROOT/docker/ops.Dockerfile" -t "$OPS_IMAGE" "$ROOT" >/dev/null
docker build --quiet -f "$ROOT/docker/control-center.Dockerfile" -t "$CONTROL_IMAGE" "$ROOT" >/dev/null
docker run --rm --entrypoint node "$OPS_IMAGE" --version
docker run --rm --entrypoint node "$CONTROL_IMAGE" -e 'import("@simplewebauthn/server").then(() => import("pg")).then(() => import("redis")).catch(() => process.exit(1))'

echo "Core image supply-chain test passed for ops and Control Center candidates."
