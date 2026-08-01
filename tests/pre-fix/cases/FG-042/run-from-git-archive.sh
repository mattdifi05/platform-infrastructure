#!/usr/bin/env sh
set -eu

REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
SOURCE_REPO=${1:-${SOURCE_REPO:-}}

if [ -z "$SOURCE_REPO" ]; then
  printf '%s\n' "usage: $0 /path/to/platform-infrastructure" >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)
TMP_BASE=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)

umask 077
OWNER_TOKEN=$(LC_ALL=C od -An -N 32 -tx1 /dev/urandom | tr -d ' \n')
[ "${#OWNER_TOKEN}" -eq 64 ] || {
  printf '%s\n' "failed to create temporary-root ownership token" >&2
  exit 1
}

TMP=$(mktemp -d "$TMP_BASE/project-route-owner-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
case "$TMP" in
  "$TMP_BASE"/project-route-owner-poc.*) ;;
  *)
    printf '%s\n' "refusing unexpected temporary root: $TMP" >&2
    exit 1
    ;;
esac

OWNER_FILE="$TMP/.project-route-owner-poc-owner"
printf '%s' "$OWNER_TOKEN" > "$OWNER_FILE"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -d "$TMP" ] \
    && [ ! -L "$TMP" ] \
    && [ -f "$OWNER_FILE" ] \
    && [ ! -L "$OWNER_FILE" ] \
    && [ "$(cat "$OWNER_FILE")" = "$OWNER_TOKEN" ]; then
    rm -rf -- "$TMP"
  else
    printf '%s\n' "refusing temporary cleanup because ownership validation failed: $TMP" >&2
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

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
git -C "$SOURCE_REPO" archive --format=tar --output "$TMP/source.tar" "$REVISION"
tar -xf "$TMP/source.tar" -C "$TMP/source"
SOURCE_REAL=$(CDPATH= cd -- "$TMP/source" && pwd -P)
[ "$SOURCE_REAL" = "$TMP/source" ] || {
  printf '%s\n' "archived source escaped the wrapper-owned temporary root" >&2
  exit 1
}

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
printf '%s\n' '[+] safety temporary source fixtures and intercepted proxy sink only; no network, Docker, SSH, secret, or live access'
PROJECT_ROUTE_POC_TMP_ROOT="$TMP" \
PROJECT_ROUTE_POC_OWNER_TOKEN="$OWNER_TOKEN" \
node --max-old-space-size=64 "$SCRIPT_DIR/project-route-owner-binding-probe.mjs" "$SOURCE_REAL"
