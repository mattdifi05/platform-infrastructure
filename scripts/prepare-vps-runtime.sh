#!/usr/bin/env sh
set -eu

REGISTRY_VOLUME=${REGISTRY_VOLUME:-enterprise_local_registry_data}

if docker volume inspect "$REGISTRY_VOLUME" >/dev/null 2>&1; then
  echo "Runtime volume already present: $REGISTRY_VOLUME"
  exit 0
fi

docker volume create \
  --label platform.infrastructure.managed=true \
  --label platform.infrastructure.purpose=local-registry \
  "$REGISTRY_VOLUME" >/dev/null

echo "Created runtime volume: $REGISTRY_VOLUME"
