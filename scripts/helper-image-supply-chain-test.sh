#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="platform/restic-rclone:t15-candidate"
cleanup() {
  docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker build --quiet -f "$ROOT/docker/restic-rclone.Dockerfile" -t "$IMAGE" "$ROOT" >/dev/null
docker run --rm --entrypoint restic "$IMAGE" version
docker run --rm --entrypoint rclone "$IMAGE" version

echo "Restic/rclone helper test passed from digest-pinned base images."
