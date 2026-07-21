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
OPS_FINGERPRINT_LABEL=io.platform-infrastructure.ops-source-sha256
OPS_DOCKER_MODE="${PLATFORM_OPS_DOCKER_MODE:-none}"

if [ "${PLATFORM_OPS_USE_HOST_NODE:-0}" = "1" ]; then
  exec node "$SCRIPT_DIR/infra-ops.mjs" "$@"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run Platform ops without host Node." >&2
  exit 127
fi

if [ "$OPS_DOCKER_MODE" = "gateway" ]; then
  GATEWAY_CONTAINER="${PLATFORM_DOCKER_GATEWAY_CONTAINER:-enterprise-docker-operation-gateway}"
  [ "$(docker inspect --format '{{.State.Running}}' "$GATEWAY_CONTAINER" 2>/dev/null || true)" = "true" ] || {
    echo "Typed Docker operation gateway is not running: $GATEWAY_CONTAINER" >&2
    exit 127
  }
  operation="${1:-}"
  shift || true
  case "$operation" in
    backup-platform-catalog|full-restore-drill|offsite-backup-restic|prune-manifest-backups-plan|prune-manifest-backups-apply)
      [ "$#" -eq 0 ] || { echo "Typed gateway operation does not accept additional arguments." >&2; exit 64; }
      exec docker exec "$GATEWAY_CONTAINER" node /infra/scripts/docker-operation-client.mjs "$operation"
      ;;
    *)
      echo "Operation is not exposed by the typed Docker gateway: ${operation:-missing}" >&2
      exit 64
      ;;
  esac
fi

OPS_SOURCE_FINGERPRINT=$(
  {
    printf '%s\n' "$NODE_IMAGE"
    sha256sum \
      "$INFRA_ROOT/docker/ops.Dockerfile" \
      "$INFRA_ROOT/control-center/package.json" \
      "$INFRA_ROOT/control-center/package-lock.json"
  } | sha256sum | awk '{print $1}'
)
CURRENT_OPS_FINGERPRINT=$(docker image inspect --format "{{index .Config.Labels \"$OPS_FINGERPRINT_LABEL\"}}" "$OPS_IMAGE" 2>/dev/null || true)

if [ "$CURRENT_OPS_FINGERPRINT" != "$OPS_SOURCE_FINGERPRINT" ]; then
  docker build \
    --build-arg "NODE_IMAGE=$NODE_IMAGE" \
    --label "$OPS_FINGERPRINT_LABEL=$OPS_SOURCE_FINGERPRINT" \
    -f "$INFRA_ROOT/docker/ops.Dockerfile" \
    -t "$OPS_IMAGE" \
    "$INFRA_ROOT"
fi

INFRA_CONTAINER_ROOT="${PLATFORM_INFRA_CONTAINER_ROOT:-/infra}"
SOURCE_CONTAINER_ROOT="${PROJECT_SOURCE_CONTAINER_ROOT:-/project}"
OPS_UID="${PLATFORM_OPS_UID:-$(id -u)}"
OPS_GID="${PLATFORM_OPS_GID:-$(id -g)}"
OPS_GIT_COMMIT="$(git -C "$INFRA_ROOT" rev-parse HEAD 2>/dev/null || true)"
OPS_GIT_TREE="$(git -C "$INFRA_ROOT" rev-parse 'HEAD^{tree}' 2>/dev/null || true)"
OPS_GIT_BRANCH="$(git -C "$INFRA_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
OPS_GIT_REPOSITORY="${PLATFORM_GITHUB_REPOSITORY:-${GITHUB_REPOSITORY:-}}"
if [ -z "$OPS_GIT_REPOSITORY" ]; then
  OPS_GIT_REPOSITORY="$(git -C "$INFRA_ROOT" config --get remote.origin.url 2>/dev/null \
    | sed -E 's#^[A-Za-z][A-Za-z0-9+.-]*://([^/@]+@)?##; s#^[^@/]+@##; s#:#/#; s#\.git$##' || true)"
fi
OPS_GIT_TRACKED_FILES_B64="$(git -C "$INFRA_ROOT" ls-files -z 2>/dev/null | base64 | tr -d '\n' || true)"
if [ -n "$(git -C "$INFRA_ROOT" status --short 2>/dev/null || true)" ]; then
  OPS_GIT_DIRTY=1
else
  OPS_GIT_DIRTY=0
fi
SOCKET_ARGS=""

case "$OPS_DOCKER_MODE" in
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
    echo "Unsupported PLATFORM_OPS_DOCKER_MODE: $OPS_DOCKER_MODE (expected gateway, raw or none)." >&2
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
  LOCAL_HOSTS="$LOCAL_HOSTS $configured_domain $configured_admin_host $configured_control_host $configured_docs_host portal.$configured_domain docs.$configured_domain auth.$configured_domain storage.$configured_domain grafana.$configured_domain"
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
  PLATFORM_ALERT_DISPATCHER_IMAGE \
  CONTROL_CENTER_IMAGE \
  PHP_APACHE_IMAGE \
  PLATFORM_OPS_IMAGE \
  BACKUP_SIGNING_KEYS_FILE \
  BACKUP_LOCAL_KEEP_LAST \
  CLOUDFLARE_ACCOUNT_ID \
  CLOUDFLARE_API_TOKEN \
  COSIGN_KEY \
  GH_TOKEN \
  GITHUB_API_VERSION \
  GITHUB_REF \
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
  POSTGRES_BACKUP_DATABASE \
  KEYCLOAK_DB_NAME \
  PLATFORM_GITHUB_REPOSITORY \
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
  -e "PLATFORM_GIT_COMMIT=$OPS_GIT_COMMIT" \
  -e "PLATFORM_GIT_TREE=$OPS_GIT_TREE" \
  -e "PLATFORM_GIT_BRANCH=$OPS_GIT_BRANCH" \
  -e "PLATFORM_GIT_REPOSITORY=$OPS_GIT_REPOSITORY" \
  -e "PLATFORM_GIT_DIRTY=$OPS_GIT_DIRTY" \
  -e "PLATFORM_GIT_TRACKED_FILES_B64=$OPS_GIT_TRACKED_FILES_B64" \
  -e "PLATFORM_OPS_CONTAINER=1" \
  -v "$INFRA_VOLUME_SOURCE:$INFRA_CONTAINER_ROOT" \
  -v "$INFRA_CONTAINER_ROOT/control-center/node_modules" \
  -w "$INFRA_CONTAINER_ROOT" \
  "$OPS_IMAGE" "$@"
status=$?
set -e
exit "$status"
