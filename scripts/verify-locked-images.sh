#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOCK="$ROOT/governance/supply-chain-lock.json"

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
docker buildx version >/dev/null

count=0
jq -r '.images[]' "$LOCK" | while IFS= read -r reference; do
  case "$reference" in
    *@sha256:*) ;;
    *) echo "Unlocked image reference: $reference" >&2; exit 1 ;;
  esac
  expected="sha256:${reference##*@sha256:}"
  local_digests=$(docker image inspect "$reference" --format '{{json .RepoDigests}}' 2>/dev/null || true)
  if [ -n "$local_digests" ] && printf '%s' "$local_digests" | jq -e --arg digest "$expected" 'any(.[]; endswith("@" + $digest))' >/dev/null; then
    actual="$expected"
    source=local-content-store
  else
    actual=$(docker buildx imagetools inspect "$reference" --format '{{.Manifest.Digest}}')
    source=registry
  fi
  if [ "$actual" != "$expected" ]; then
    echo "Registry digest mismatch for ${reference%@*}: expected $expected, got $actual" >&2
    exit 1
  fi
  count=$((count + 1))
  echo "verified ${reference%@*} $actual source=$source"
done

echo "All locked image manifests are available at their exact digests."
