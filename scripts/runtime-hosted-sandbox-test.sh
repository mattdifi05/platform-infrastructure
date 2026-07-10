#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE_ROOT=${T13_APP_SOURCE_ROOT:-$ROOT/../src}
CERTS_ROOT=${T13_CERTS_DIR:-$ROOT/traefik/certs}
RUN_ID="platform_t13_apps_$$"

if [ ! -d "$SOURCE_ROOT" ]; then
  echo "Hosted source root is missing. Set T13_APP_SOURCE_ROOT." >&2
  exit 66
fi
if [ ! -s "$CERTS_ROOT/localhost.fullchain.crt" ] || [ ! -s "$CERTS_ROOT/localhost.key" ]; then
  echo "Runtime certificate files are missing. Set T13_CERTS_DIR to a read-only certificate directory." >&2
  exit 66
fi

export COMPOSE_ENV_FILE=${COMPOSE_ENV_FILE:-.env.vps.example}
export COMPOSE_PROJECT_NAME=$RUN_ID
export PLATFORM_NETWORK_PREFIX=$RUN_ID
export PHP_PROJECTS_DIR=$SOURCE_ROOT
export PROJECT_SOURCE_DIR=$SOURCE_ROOT
export PLATFORM_CERTS_DIR=$CERTS_ROOT

cleanup() {
  sh "$ROOT/scripts/compose-vps.sh" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for service in \
  php-anniversary \
  php-fiplatform \
  php-matthewdifilippo \
  php-stream \
  php-workcalendar \
  node-account \
  node-ui
do
  name="${RUN_ID}-${service}"
  sh "$ROOT/scripts/compose-vps.sh" run --no-deps -d --name "$name" "$service" >/dev/null
  docker inspect "$name" | jq -e '
    .[0] as $container |
    $container.HostConfig.ReadonlyRootfs == true and
    $container.HostConfig.Memory > 0 and
    $container.HostConfig.NanoCpus > 0 and
    $container.HostConfig.PidsLimit > 0 and
    ([
      $container.Mounts[] |
      select(
        .Destination == "/var/run/docker.sock" or
        (.Destination | startswith("/mnt/host")) or
        (.Destination | startswith("/var/www/infra-docs")) or
        (.Destination | startswith("/var/www/project-state"))
      )
    ] | length == 0) and
    ([
      $container.Mounts[] |
      select(
        (.Destination | startswith("/workspace")) or
        (.Destination | startswith("/opt/platform-source/"))
      ) |
      .RW
    ] | all(. == false))
  ' >/dev/null

  case "$service" in
    php-*)
      slug=${service#php-}
      attempt=0
      until docker exec "$name" pgrep apache2 >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 20 ]; then
          docker logs "$name" 2>&1 | tail -n 50
          exit 1
        fi
        sleep 1
      done
      docker exec "$name" apache2ctl -t >/dev/null
      docker exec "$name" test -r "/var/www/projects/$slug/public"
      secret_count=$(docker exec "$name" sh -ec 'find /run/secrets -mindepth 1 -maxdepth 1 2>/dev/null | wc -l')
      [ "$secret_count" -eq 0 ]
      asset=$(docker exec "$name" sh -ec "find /var/www/projects/$slug/public -type f | awk '/\\.(css|js|png|jpg|jpeg|webp|svg|ico|woff2?)$/ { print; exit }'")
      [ -n "$asset" ]
      asset_path=${asset#*/var/www/projects/$slug/public}
      http_code=$(docker exec "$name" curl -sS -o /dev/null -w '%{http_code}' -H "Host: ${slug}.example.com" "http://127.0.0.1$asset_path")
      case "$http_code" in
        200|206|304) ;;
        *)
          echo "$service static asset returned HTTP $http_code" >&2
          exit 1
          ;;
      esac
      ;;
    node-*)
      docker exec "$name" sh -ec 'test -r /workspace/apps/web/.next/standalone/apps/web/server.js; test ! -e /var/run/docker.sock'
      attempt=0
      until docker exec "$name" node -e 'fetch("http://127.0.0.1:3000/", { redirect: "manual", signal: AbortSignal.timeout(2000) }).then((response) => process.exit(response.status < 500 ? 0 : 1)).catch(() => process.exit(1))' >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 30 ]; then
          docker logs "$name" 2>&1 | tail -n 50
          exit 1
        fi
        sleep 2
      done
      ;;
  esac
  docker rm -f "$name" >/dev/null
  echo "$service mount/runtime probe passed"
done

echo "Hosted runtime sandbox passed for seven isolated applications."
