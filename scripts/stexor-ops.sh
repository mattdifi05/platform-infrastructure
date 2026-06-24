#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
if [ -n "${STEXOR_SOURCE_ROOT:-}" ]; then
  SOURCE_ROOT_RAW="$STEXOR_SOURCE_ROOT"
elif [ -n "${NODE_SOURCE_DIR:-}" ]; then
  SOURCE_ROOT_RAW="$NODE_SOURCE_DIR"
elif [ -d "$INFRA_ROOT/src_stexor" ]; then
  SOURCE_ROOT_RAW="$INFRA_ROOT/src_stexor"
else
  SOURCE_ROOT_RAW="$INFRA_ROOT/../src_stexor"
fi
if [ -d "$SOURCE_ROOT_RAW" ]; then
  SOURCE_ROOT=$(CDPATH= cd -- "$SOURCE_ROOT_RAW" && pwd)
else
  SOURCE_ROOT="$SOURCE_ROOT_RAW"
fi
OPS_IMAGE="${STEXOR_OPS_IMAGE:-stexor/ops:local}"
NODE_IMAGE="${NODE_IMAGE:-node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606}"

if [ "${STEXOR_OPS_USE_HOST_NODE:-0}" = "1" ]; then
  exec node "$SCRIPT_DIR/stexor-ops.mjs" "$@"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run Stexor ops without host Node." >&2
  exit 127
fi

if ! docker image inspect "$OPS_IMAGE" >/dev/null 2>&1; then
  docker build \
    --build-arg "NODE_IMAGE=$NODE_IMAGE" \
    -f "$INFRA_ROOT/docker/ops.Dockerfile" \
    -t "$OPS_IMAGE" \
    "$INFRA_ROOT"
fi

INFRA_CONTAINER_ROOT="${STEXOR_INFRA_CONTAINER_ROOT:-/infra}"
SOURCE_CONTAINER_ROOT="${STEXOR_SOURCE_CONTAINER_ROOT:-/src_stexor}"

case "$(uname -s 2>/dev/null || printf unknown)" in
  Linux)
    NETWORK_ARGS="${STEXOR_OPS_NETWORK_ARGS:---network host}"
    LOCAL_HOST_TARGET="${STEXOR_LOCAL_HOST_TARGET:-127.0.0.1}"
    ;;
  *)
    NETWORK_ARGS="${STEXOR_OPS_NETWORK_ARGS:-}"
    LOCAL_HOST_TARGET="${STEXOR_LOCAL_HOST_TARGET:-host-gateway}"
    ;;
esac

DOCKER_SOCKET="${STEXOR_DOCKER_SOCKET:-/var/run/docker.sock}"
if [ ! -S "$DOCKER_SOCKET" ] && [ -z "${DOCKER_HOST:-}" ]; then
  echo "Docker socket not found at $DOCKER_SOCKET. Set DOCKER_HOST or STEXOR_DOCKER_SOCKET." >&2
  exit 127
fi

SOCKET_ARGS=""
if [ -S "$DOCKER_SOCKET" ]; then
  SOCKET_ARGS="-v $DOCKER_SOCKET:/var/run/docker.sock"
fi

INFRA_VOLUME_SOURCE="${STEXOR_INFRA_VOLUME_SOURCE:-${STEXOR_INFRA_HOST_ROOT:-$INFRA_ROOT}}"
SOURCE_VOLUME_SOURCE="${STEXOR_SOURCE_VOLUME_SOURCE:-${STEXOR_SOURCE_HOST_ROOT:-$SOURCE_ROOT}}"
SOURCE_MOUNT_ARGS=""
if [ -d "$SOURCE_ROOT" ]; then
  SOURCE_MOUNT_ARGS="-v $SOURCE_VOLUME_SOURCE:$SOURCE_CONTAINER_ROOT:ro"
fi
LOCAL_HOST_ARGS=""
for host in \
  localhost.com \
  api.localhost.com \
  account.localhost.com \
  auth.localhost.com \
  projects.localhost.com \
  phpmyadmin.localhost.com \
  grafana.localhost.com \
  traefik.localhost.com \
  prometheus.localhost.com \
  alertmanager.localhost.com \
  stream.localhost.com \
  anniversary.localhost.com \
  workcalendar.localhost.com \
  fireport.localhost.com
do
  LOCAL_HOST_ARGS="$LOCAL_HOST_ARGS --add-host $host:$LOCAL_HOST_TARGET"
done

ENV_FORWARD_ARGS=""
for name in \
  BACKEND_IMAGE \
  WEB_IMAGE \
  WORKER_NOTIFICATIONS_IMAGE \
  WORKER_JOBS_IMAGE \
  BACKUP_SIGNING_KEYS_FILE \
  CLOUDFLARE_ACCOUNT_ID \
  CLOUDFLARE_API_TOKEN \
  COSIGN_KEY \
  GH_TOKEN \
  GITHUB_API_VERSION \
  GITHUB_REF_NAME \
  GITHUB_REPOSITORY \
  GITHUB_SHA \
  GITHUB_TOKEN \
  RESTIC_PASSWORD_FILE \
  RESTIC_REPOSITORY \
  STEXOR_GITHUB_REPOSITORY \
  STEXOR_REQUIRE_SOURCE_ROOT \
  STEXOR_STATIC_INFRA_ONLY
do
  ENV_FORWARD_ARGS="$ENV_FORWARD_ARGS -e $name"
done

# shellcheck disable=SC2086
exec docker run --rm \
  $SOCKET_ARGS \
  $SOURCE_MOUNT_ARGS \
  $NETWORK_ARGS \
  $LOCAL_HOST_ARGS \
  $ENV_FORWARD_ARGS \
  -e "DOCKER_HOST=${DOCKER_HOST:-}" \
  -e "NODE_IMAGE=$NODE_IMAGE" \
  -e "PLAYWRIGHT_IMAGE=${PLAYWRIGHT_IMAGE:-}" \
  -e "STEXOR_SOURCE_ROOT=$SOURCE_CONTAINER_ROOT" \
  -e "STEXOR_INFRA_CONTAINER_ROOT=$INFRA_CONTAINER_ROOT" \
  -e "STEXOR_INFRA_HOST_ROOT=$INFRA_VOLUME_SOURCE" \
  -e "STEXOR_SOURCE_HOST_ROOT=$SOURCE_VOLUME_SOURCE" \
  -e "STEXOR_OPS_CONTAINER=1" \
  -v "$INFRA_VOLUME_SOURCE:$INFRA_CONTAINER_ROOT" \
  -w "$INFRA_CONTAINER_ROOT" \
  "$OPS_IMAGE" "$@"
