#!/bin/sh
set -eu

EXPECTED_REVISION='68cd05895b8d479ffb8167344282e7d922958bfc'
EXPECTED_TREE='70031b30316fbaecbb23249491d6ff4e364d65d5'

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 SOURCE_REPO" >&2
  exit 2
fi

SOURCE_REPO=$1
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 2; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 2; }
command -v node >/dev/null 2>&1 || { echo "node is required" >&2; exit 2; }

ACTUAL_REVISION=$(git -C "$SOURCE_REPO" rev-parse --verify 'HEAD^{commit}')
ACTUAL_TREE=$(git -C "$SOURCE_REPO" rev-parse --verify 'HEAD^{tree}')
if [ "$ACTUAL_REVISION" != "$EXPECTED_REVISION" ]; then
  echo "refusing unpinned revision: expected $EXPECTED_REVISION, got $ACTUAL_REVISION" >&2
  exit 1
fi
if [ "$ACTUAL_TREE" != "$EXPECTED_TREE" ]; then
  echo "refusing unexpected tree: expected $EXPECTED_TREE, got $ACTUAL_TREE" >&2
  exit 1
fi

ARCHIVE_ROOT=$(mktemp -d "${TMPDIR:?TMPDIR is required}/fg033-edge-evidence-authenticity.XXXXXX")
cleanup() {
  rm -rf -- "$ARCHIVE_ROOT"
}
trap cleanup EXIT HUP INT TERM

git -C "$SOURCE_REPO" archive --format=tar "$EXPECTED_REVISION" | tar -xf - -C "$ARCHIVE_ROOT"
node "$SCRIPT_DIR/edge-evidence-authenticity-probe.mjs" "$ARCHIVE_ROOT"
