#!/bin/sh
set -eu

EXPECTED_REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
EXPECTED_TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
EXPECTED_CONTRACT_SHA256=5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47

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

commit=$(git -C "$repository" rev-parse --verify "${revision}^{commit}")
tree=$(git -C "$repository" rev-parse --verify "${commit}^{tree}")

if [ "$commit" != "$EXPECTED_REVISION" ] || [ "$tree" != "$EXPECTED_TREE" ]; then
  echo "error: this PoC is pinned to revision $EXPECTED_REVISION (tree $EXPECTED_TREE)" >&2
  exit 2
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/hosted-config-poc.XXXXXX")
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

snapshot=$tmp/repository
mkdir -p "$snapshot"
git -C "$repository" archive "$commit" | tar -x -C "$snapshot"

contract=$snapshot/scripts/hosted-workload-contract.mjs
[ -f "$contract" ] || {
  echo "error: archived contract source is missing" >&2
  exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
  contract_sha=$(sha256sum "$contract" | awk '{print $1}')
else
  contract_sha=$(shasum -a 256 "$contract" | awk '{print $1}')
fi

[ "$contract_sha" = "$EXPECTED_CONTRACT_SHA256" ] || {
  echo "error: archived contract source hash does not match the pinned vulnerable source" >&2
  exit 1
}

node "$(dirname "$0")/probe.mjs" "$snapshot" "$commit" "$tree"
