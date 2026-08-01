#!/bin/sh
set -eu

EXPECTED_REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
EXPECTED_TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
EXPECTED_LOCK_SHA256=f87317c017f541796f4144442a07c3c98e0b280aafb11396bd64852571390674
EXPECTED_COMPOSE_SHA256=09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713

usage() {
  echo "usage: $0 /path/to/platform-infrastructure [revision]" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
repository=$1
revision=${2:-$EXPECTED_REVISION}

[ -d "$repository" ] && git -C "$repository" rev-parse --git-dir >/dev/null 2>&1 || {
  echo "error: repository is not a Git worktree: $repository" >&2
  exit 2
}
command -v node >/dev/null 2>&1 || { echo "error: node is required" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }
command -v sha256sum >/dev/null 2>&1 || { echo "error: sha256sum is required by the archived verifier" >&2; exit 2; }

commit=$(git -C "$repository" rev-parse --verify "${revision}^{commit}")
tree=$(git -C "$repository" rev-parse --verify "${commit}^{tree}")
if [ "$commit" != "$EXPECTED_REVISION" ] || [ "$tree" != "$EXPECTED_TREE" ]; then
  echo "error: this PoC is pinned to revision $EXPECTED_REVISION (tree $EXPECTED_TREE)" >&2
  exit 2
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/hosted-lock-poc.XXXXXX")
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

snapshot=$tmp/repository
mkdir -p "$snapshot"
git -C "$repository" archive "$commit" | tar -x -C "$snapshot"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

lock_script=$snapshot/scripts/hosted-workload-lock.sh
compose_script=$snapshot/scripts/compose-vps.sh
[ "$(hash_file "$lock_script")" = "$EXPECTED_LOCK_SHA256" ] || {
  echo "error: archived lock verifier hash does not match the pinned vulnerable source" >&2
  exit 1
}
[ "$(hash_file "$compose_script")" = "$EXPECTED_COMPOSE_SHA256" ] || {
  echo "error: archived activation wrapper hash does not match the pinned vulnerable source" >&2
  exit 1
}

node "$(dirname "$0")/probe.mjs" "$snapshot" "$commit" "$tree"

