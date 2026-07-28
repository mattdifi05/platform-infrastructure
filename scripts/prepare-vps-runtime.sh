#!/usr/bin/env sh
set -eu

REGISTRY_VOLUME=${REGISTRY_VOLUME:-enterprise_local_registry_data}
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock

case "${DOCKER_HOST:-}" in ""|"$CANONICAL_DOCKER_HOST") ;; *) echo "Caller-selected DOCKER_HOST is forbidden." >&2; exit 2 ;; esac
case "${DOCKER_CONTEXT:-}" in ""|default) ;; *) echo "Caller-selected DOCKER_CONTEXT is forbidden." >&2; exit 2 ;; esac
unset DOCKER_CONTEXT
export DOCKER_HOST=$CANONICAL_DOCKER_HOST
daemon_id=$(docker --host "$CANONICAL_DOCKER_HOST" info --format '{{.ID}}') || {
  echo "Canonical local Docker daemon is unavailable." >&2
  exit 1
}
case "$daemon_id" in ''|*[!A-Za-z0-9._:-]*) echo "Canonical local Docker daemon identity is invalid." >&2; exit 1 ;; esac
assert_daemon() {
  current=$(docker --host "$CANONICAL_DOCKER_HOST" info --format '{{.ID}}') || exit 1
  [ "$current" = "$daemon_id" ] || {
    echo "Docker daemon identity changed during runtime preparation." >&2
    exit 1
  }
}

for directory in \
  "$ROOT_DIR/backups" \
  "$ROOT_DIR/reports" \
  "$ROOT_DIR/projects-portal/state"
do
  install -d -m 0700 "$directory"
done

assert_daemon
if docker --host "$CANONICAL_DOCKER_HOST" volume inspect "$REGISTRY_VOLUME" >/dev/null 2>&1; then
  assert_daemon
  echo "Runtime volume already present: $REGISTRY_VOLUME"
  exit 0
fi

docker --host "$CANONICAL_DOCKER_HOST" volume create \
  --label platform.infrastructure.managed=true \
  --label platform.infrastructure.purpose=local-registry \
  "$REGISTRY_VOLUME" >/dev/null
assert_daemon

echo "Created runtime volume: $REGISTRY_VOLUME"
