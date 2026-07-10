#!/usr/bin/env sh
set -eu

REGISTRY_VOLUME=${REGISTRY_VOLUME:-enterprise_local_registry_data}
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for directory in \
  "$ROOT_DIR/backups" \
  "$ROOT_DIR/reports" \
  "$ROOT_DIR/projects-portal/state"
do
  install -d -m 0700 "$directory"
done

if docker volume inspect "$REGISTRY_VOLUME" >/dev/null 2>&1; then
  echo "Runtime volume already present: $REGISTRY_VOLUME"
  exit 0
fi

docker volume create \
  --label platform.infrastructure.managed=true \
  --label platform.infrastructure.purpose=local-registry \
  "$REGISTRY_VOLUME" >/dev/null

echo "Created runtime volume: $REGISTRY_VOLUME"
