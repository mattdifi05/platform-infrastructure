#!/usr/bin/env sh
set -eu

REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
SOURCE_REPO=${1:-${SOURCE_REPO:-}}

if [ -z "$SOURCE_REPO" ]; then
  printf '%s\n' "usage: $0 /path/to/platform-infrastructure" >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/release-gate-order-poc.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

actual_revision=$(git -C "$SOURCE_REPO" rev-parse --verify "$REVISION^{commit}")
actual_tree=$(git -C "$SOURCE_REPO" rev-parse "$REVISION^{tree}")
[ "$actual_revision" = "$REVISION" ] || {
  printf '%s\n' "unexpected revision: $actual_revision" >&2
  exit 1
}
[ "$actual_tree" = "$TREE" ] || {
  printf '%s\n' "unexpected tree: $actual_tree" >&2
  exit 1
}

mkdir "$TMP/source"
git -C "$SOURCE_REPO" archive --format=tar "$REVISION" | tar -xf - -C "$TMP/source"

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
RELEASE_GATE_POC_TMP="$TMP" node "$SCRIPT_DIR/release-gate-order-probe.mjs" "$TMP/source"
