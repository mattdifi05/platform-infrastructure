#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
IMAGE="platform/t15-build-context:$$"
CONTAINER="platform-t15-build-context-$$"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

cp "$ROOT/.dockerignore" "$TMP/.dockerignore"
mkdir -p "$TMP/safe" "$TMP/secrets" "$TMP/backups" "$TMP/reports" "$TMP/.tmp" "$TMP/node_modules" "$TMP/.git" "$TMP/traefik/certs" "$TMP/projects-portal/state"
printf '%s\n' keep > "$TMP/safe/keep.txt"
for file in secrets/token.txt backups/data.dump reports/report.json .tmp/state.json node_modules/package.json .git/config traefik/certs/key.pem projects-portal/state/state.json; do
  printf '%s\n' excluded > "$TMP/$file"
done
printf '%s\n' secret > "$TMP/.env"
printf '%s\n' 'FROM scratch' 'COPY . /context' > "$TMP/Dockerfile"

docker build --quiet -t "$IMAGE" "$TMP" >/dev/null
docker create --name "$CONTAINER" "$IMAGE" /context/safe/keep.txt >/dev/null
docker export "$CONTAINER" | tar -tf - > "$TMP/export.txt"
grep -qx 'context/safe/keep.txt' "$TMP/export.txt"
for path in context/secrets/token.txt context/backups/data.dump context/reports/report.json context/.tmp/state.json context/node_modules/package.json context/.git/config context/traefik/certs/key.pem context/projects-portal/state/state.json context/.env; do
  if grep -Fx "$path" "$TMP/export.txt" >/dev/null; then
    echo "Excluded build-context path leaked: $path" >&2
    exit 1
  fi
done

echo "Build context sandbox passed: required source included and secret/state/build outputs excluded."
