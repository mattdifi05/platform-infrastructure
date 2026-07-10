#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INFRA_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
if [ -n "${PROJECT_SOURCE_ROOT:-}" ]; then
  SOURCE_ROOT_RAW="$PROJECT_SOURCE_ROOT"
elif [ -n "${PROJECT_SOURCE_DIR:-}" ]; then
  SOURCE_ROOT_RAW="$PROJECT_SOURCE_DIR"
elif [ -d "$INFRA_ROOT/project" ]; then
  SOURCE_ROOT_RAW="$INFRA_ROOT/project"
else
  SOURCE_ROOT_RAW="$INFRA_ROOT/../project"
fi
if [ -d "$SOURCE_ROOT_RAW" ]; then
  SOURCE_ROOT=$(CDPATH= cd -- "$SOURCE_ROOT_RAW" && pwd)
else
  SOURCE_ROOT="$SOURCE_ROOT_RAW"
fi
OPS_IMAGE="${PLATFORM_OPS_IMAGE:-platform/ops:local}"
NODE_IMAGE="${NODE_IMAGE:-node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606}"

if [ "${PLATFORM_OPS_USE_HOST_NODE:-0}" = "1" ]; then
  exec node "$SCRIPT_DIR/infra-ops.mjs" "$@"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run Platform ops without host Node." >&2
  exit 127
fi

if ! docker image inspect "$OPS_IMAGE" >/dev/null 2>&1; then
  docker build \
    --build-arg "NODE_IMAGE=$NODE_IMAGE" \
    -f "$INFRA_ROOT/docker/ops.Dockerfile" \
    -t "$OPS_IMAGE" \
    "$INFRA_ROOT"
fi

INFRA_CONTAINER_ROOT="${PLATFORM_INFRA_CONTAINER_ROOT:-/infra}"
SOURCE_CONTAINER_ROOT="${PROJECT_SOURCE_CONTAINER_ROOT:-/project}"
OPS_UID="${PLATFORM_OPS_UID:-$(id -u)}"
OPS_GID="${PLATFORM_OPS_GID:-$(id -g)}"
OPS_DOCKER_MODE="${PLATFORM_OPS_DOCKER_MODE:-auto}"
SOCKET_ARGS=""
EPHEMERAL_PROXY_CONTAINER=""
EPHEMERAL_PROXY_NETWORK=""
PROXY_IMAGE="${DOCKER_SOCKET_PROXY_IMAGE:-ghcr.io/tecnativa/docker-socket-proxy:v0.4.2@sha256:1f3a6f303320723d199d2316a3e82b2e2685d86c275d5e3deeaf182573b47476}"

cleanup_ephemeral_proxy() {
  if [ -n "$EPHEMERAL_PROXY_CONTAINER" ]; then
    docker rm -f "$EPHEMERAL_PROXY_CONTAINER" >/dev/null 2>&1 || true
  fi
  if [ -n "$EPHEMERAL_PROXY_NETWORK" ]; then
    docker network rm "$EPHEMERAL_PROXY_NETWORK" >/dev/null 2>&1 || true
  fi
}

start_ephemeral_proxy() {
  EPHEMERAL_PROXY_NETWORK="platform-ops-proxy-$$"
  EPHEMERAL_PROXY_CONTAINER="platform-ops-proxy-$$"
  docker network create "$EPHEMERAL_PROXY_NETWORK" >/dev/null
  docker run -d \
    --name "$EPHEMERAL_PROXY_CONTAINER" \
    --network "$EPHEMERAL_PROXY_NETWORK" \
    --network-alias docker-socket-proxy \
    --read-only \
    --tmpfs /run:rw,noexec,nosuid,nodev,size=16m \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --cpus 0.10 \
    --cpu-shares 1024 \
    --memory 128m \
    --memory-reservation 32m \
    --pids-limit 64 \
    --ulimit nofile=16384:16384 \
    --blkio-weight 700 \
    --security-opt no-new-privileges:true \
    -e ALLOW_RESTARTS=1 \
    -e ALLOW_START=1 \
    -e ALLOW_STOP=1 \
    -e AUTH=0 \
    -e BUILD=0 \
    -e COMMIT=0 \
    -e CONFIGS=0 \
    -e CONTAINERS=1 \
    -e EXEC=1 \
    -e IMAGES=1 \
    -e INFO=1 \
    -e NETWORKS=1 \
    -e POST=1 \
    -e SECRETS=0 \
    -e SERVICES=0 \
    -e SESSION=0 \
    -e SWARM=0 \
    -e SYSTEM=0 \
    -e TASKS=0 \
    -e VOLUMES=1 \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    "$PROXY_IMAGE" >/dev/null
  PROXY_CONTAINER="$EPHEMERAL_PROXY_CONTAINER"
  PROXY_NETWORK="$EPHEMERAL_PROXY_NETWORK"
}

trap cleanup_ephemeral_proxy EXIT INT TERM

case "$OPS_DOCKER_MODE" in
  auto)
    PROXY_CONTAINER="${PLATFORM_OPS_DOCKER_PROXY_CONTAINER:-enterprise-docker-socket-proxy}"
    PROXY_NETWORK="${PLATFORM_OPS_DOCKER_NETWORK:-${COMPOSE_PROJECT_NAME:-platform_infra_vps}_platform_docker_control}"
    if [ "$(docker inspect --format '{{.State.Running}}' "$PROXY_CONTAINER" 2>/dev/null || true)" != "true" ]; then
      start_ephemeral_proxy
      NETWORK_ARGS="${PLATFORM_OPS_NETWORK_ARGS:---network $PROXY_NETWORK}"
      LOCAL_HOST_TARGET="${PLATFORM_LOCAL_HOST_TARGET:-host-gateway}"
      OPS_DOCKER_HOST="${PLATFORM_OPS_DOCKER_HOST:-tcp://$PROXY_CONTAINER:2375}"
    else
      NETWORK_ARGS="${PLATFORM_OPS_NETWORK_ARGS:---network host}"
      LOCAL_HOST_TARGET="${PLATFORM_LOCAL_HOST_TARGET:-127.0.0.1}"
      OPS_DOCKER_HOST="${PLATFORM_OPS_DOCKER_HOST:-tcp://127.0.0.1:${DOCKER_SOCKET_PROXY_PORT:-2376}}"
    fi
    OPS_DOCKER_API_VERSION="${PLATFORM_OPS_DOCKER_API_VERSION:-1.51}"
    ;;
  proxy)
    PROXY_CONTAINER="${PLATFORM_OPS_DOCKER_PROXY_CONTAINER:-enterprise-docker-socket-proxy}"
    PROXY_NETWORK="${PLATFORM_OPS_DOCKER_NETWORK:-${COMPOSE_PROJECT_NAME:-platform_infra_vps}_platform_docker_control}"
    if [ "$(docker inspect --format '{{.State.Running}}' "$PROXY_CONTAINER" 2>/dev/null || true)" != "true" ]; then
      echo "Docker socket proxy is not running: $PROXY_CONTAINER. Start the hardened VPS runtime or choose an explicit trusted mode." >&2
      exit 127
    fi
    NETWORK_ARGS="${PLATFORM_OPS_NETWORK_ARGS:---network host}"
    LOCAL_HOST_TARGET="${PLATFORM_LOCAL_HOST_TARGET:-127.0.0.1}"
    OPS_DOCKER_HOST="${PLATFORM_OPS_DOCKER_HOST:-tcp://127.0.0.1:${DOCKER_SOCKET_PROXY_PORT:-2376}}"
    OPS_DOCKER_API_VERSION="${PLATFORM_OPS_DOCKER_API_VERSION:-1.51}"
    ;;
  raw)
    if [ "${PLATFORM_ALLOW_RAW_DOCKER_SOCKET:-0}" != "1" ]; then
      echo "Raw Docker socket mode requires PLATFORM_ALLOW_RAW_DOCKER_SOCKET=1 and is reserved for an approved recovery window." >&2
      exit 126
    fi
    DOCKER_SOCKET="${PLATFORM_DOCKER_SOCKET:-/var/run/docker.sock}"
    if [ ! -S "$DOCKER_SOCKET" ]; then
      echo "Docker socket not found at $DOCKER_SOCKET." >&2
      exit 127
    fi
    SOCKET_ARGS="-v $DOCKER_SOCKET:/var/run/docker.sock"
    NETWORK_ARGS="${PLATFORM_OPS_NETWORK_ARGS:---network host}"
    LOCAL_HOST_TARGET="${PLATFORM_LOCAL_HOST_TARGET:-127.0.0.1}"
    OPS_DOCKER_HOST="unix:///var/run/docker.sock"
    OPS_DOCKER_API_VERSION="${PLATFORM_OPS_DOCKER_API_VERSION:-}"
    ;;
  none)
    NETWORK_ARGS="${PLATFORM_OPS_NETWORK_ARGS:---network none}"
    LOCAL_HOST_TARGET="${PLATFORM_LOCAL_HOST_TARGET:-host-gateway}"
    OPS_DOCKER_HOST=""
    OPS_DOCKER_API_VERSION=""
    ;;
  *)
    echo "Unsupported PLATFORM_OPS_DOCKER_MODE: $OPS_DOCKER_MODE (expected auto, proxy, raw or none)." >&2
    exit 64
    ;;
esac

INFRA_VOLUME_SOURCE="${PLATFORM_INFRA_VOLUME_SOURCE:-${PLATFORM_INFRA_HOST_ROOT:-$INFRA_ROOT}}"
SOURCE_VOLUME_SOURCE="${PLATFORM_SOURCE_VOLUME_SOURCE:-${PROJECT_SOURCE_HOST_ROOT:-$SOURCE_ROOT}}"
SOURCE_MOUNT_ARGS=""
if [ -d "$SOURCE_ROOT" ]; then
  SOURCE_MOUNT_ARGS="-v $SOURCE_VOLUME_SOURCE:$SOURCE_CONTAINER_ROOT:ro"
fi

env_file_value() {
  key="$1"
  file="$INFRA_ROOT/.env"
  [ -f "$file" ] || return 0
  value=$(grep -E "^${key}=" "$file" 2>/dev/null | tail -n 1 | sed "s/^[^=]*=//; s/^['\\\"]//; s/['\\\"]$//" || true)
  printf '%s' "$value"
}

configured_domain="${DOMAIN:-$(env_file_value DOMAIN)}"
configured_admin_host="${ADMIN_HOST:-$(env_file_value ADMIN_HOST)}"
configured_control_host="${CONTROL_CENTER_HOST:-$(env_file_value CONTROL_CENTER_HOST)}"
configured_docs_host="${DOCS_HOST:-$(env_file_value DOCS_HOST)}"
if [ -n "$configured_domain" ]; then
  configured_admin_host="${configured_admin_host:-portal.$configured_domain}"
  configured_control_host="${configured_control_host:-$configured_admin_host}"
  configured_docs_host="${configured_docs_host:-docs.$configured_domain}"
fi

LOCAL_HOST_ARGS=""
LOCAL_HOSTS="localhost.com portal.localhost.com docs.localhost.com"
if [ -n "$configured_domain" ]; then
  LOCAL_HOSTS="$LOCAL_HOSTS $configured_domain $configured_admin_host $configured_control_host $configured_docs_host portal.$configured_domain docs.$configured_domain app.$configured_domain api.$configured_domain auth.$configured_domain storage.$configured_domain grafana.$configured_domain"
fi
for host in $LOCAL_HOSTS; do
  [ -n "$host" ] || continue
  LOCAL_HOST_ARGS="$LOCAL_HOST_ARGS --add-host $host:$LOCAL_HOST_TARGET"
done

NODE_CA_ARGS=""
if [ -n "${NODE_EXTRA_CA_CERTS:-}" ]; then
  NODE_CA_ARGS="-e NODE_EXTRA_CA_CERTS"
elif [ -f "$INFRA_ROOT/traefik/certs/ca.pem" ]; then
  NODE_CA_ARGS="-e NODE_EXTRA_CA_CERTS=$INFRA_CONTAINER_ROOT/traefik/certs/ca.pem"
fi

GITHUB_TOKEN_FILE="${GITHUB_TOKEN_FILE:-$INFRA_CONTAINER_ROOT/secrets/github_token.txt}"
export GITHUB_TOKEN_FILE

if [ "${BACKUP_SIGNING_KEYS_FILE:-}" = "/run/secrets/backup_signing_keys" ] && [ -f "$INFRA_ROOT/secrets/backup_signing_keys.txt" ]; then
  BACKUP_SIGNING_KEYS_FILE="$INFRA_CONTAINER_ROOT/secrets/backup_signing_keys.txt"
  export BACKUP_SIGNING_KEYS_FILE
fi

ENV_FORWARD_ARGS=""
for name in \
  BACKEND_IMAGE \
  WEB_IMAGE \
  WORKER_NOTIFICATIONS_IMAGE \
  WORKER_JOBS_IMAGE \
  BACKUP_SIGNING_KEYS_FILE \
  BACKUP_LOCAL_KEEP_LAST \
  CLOUDFLARE_ACCOUNT_ID \
  CLOUDFLARE_API_TOKEN \
  COSIGN_KEY \
  GH_TOKEN \
  GITHUB_API_VERSION \
  GITHUB_REF_NAME \
  GITHUB_REPOSITORY \
  GITHUB_SHA \
  GITHUB_TOKEN \
  GITHUB_TOKEN_FILE \
  GH_TOKEN_FILE \
  NODE_EXTRA_CA_CERTS \
  RCLONE_CONFIG \
  RESTIC_IMAGE \
  RESTIC_HOSTNAME \
  RESTIC_KEEP_LAST \
  RESTIC_MAX_REPOSITORY_BYTES \
  RESTIC_PASSWORD_FILE \
  RESTIC_REPOSITORY \
  RESTIC_REQUIRE_IMMUTABLE_IMAGE \
  APP_DB_NAME \
  KEYCLOAK_DB_NAME \
  PLATFORM_GITHUB_REPOSITORY \
  PROJECT_REQUIRE_SOURCE_ROOT \
  PLATFORM_STATIC_INFRA_ONLY
do
  ENV_FORWARD_ARGS="$ENV_FORWARD_ARGS -e $name"
done

# shellcheck disable=SC2086
set +e
docker run --rm -i \
  --user "$OPS_UID:$OPS_GID" \
  $SOCKET_ARGS \
  $SOURCE_MOUNT_ARGS \
  $NETWORK_ARGS \
  $LOCAL_HOST_ARGS \
  $ENV_FORWARD_ARGS \
  $NODE_CA_ARGS \
  -e "DOCKER_API_VERSION=$OPS_DOCKER_API_VERSION" \
  -e "DOCKER_HOST=$OPS_DOCKER_HOST" \
  -e HOME=/tmp \
  -e "NODE_IMAGE=$NODE_IMAGE" \
  -e "PLAYWRIGHT_IMAGE=${PLAYWRIGHT_IMAGE:-}" \
  -e "PROJECT_SOURCE_ROOT=$SOURCE_CONTAINER_ROOT" \
  -e "PLATFORM_INFRA_CONTAINER_ROOT=$INFRA_CONTAINER_ROOT" \
  -e "PLATFORM_INFRA_HOST_ROOT=$INFRA_VOLUME_SOURCE" \
  -e "PROJECT_SOURCE_HOST_ROOT=$SOURCE_VOLUME_SOURCE" \
  -e "PLATFORM_OPS_CONTAINER=1" \
  -v "$INFRA_VOLUME_SOURCE:$INFRA_CONTAINER_ROOT" \
  -v "$INFRA_CONTAINER_ROOT/control-center/node_modules" \
  -w "$INFRA_CONTAINER_ROOT" \
  "$OPS_IMAGE" "$@"
status=$?
set -e
cleanup_ephemeral_proxy
exit "$status"
