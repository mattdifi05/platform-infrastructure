#!/usr/bin/env sh
set -eu
umask 077

REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
SOURCE_REPO=${1:-${SOURCE_REPO:-}}

file_identity() {
  if stat -f '%d:%i' "$1" >/dev/null 2>&1; then
    stat -f '%d:%i' "$1"
  else
    stat -c '%d:%i' "$1"
  fi
}

if [ -z "$SOURCE_REPO" ]; then
  printf '%s\n' "usage: $0 /path/to/platform-infrastructure" >&2
  exit 2
fi

SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_BASE=${TMPDIR:-/tmp}
TMP_PARENT=$(CDPATH= cd -- "$TMP_BASE" && pwd -P)
TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/fg052-release-admission-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
TMP_ID=$(file_identity "$TMP")
OWNER_TOKEN=
OWNER_SENTINEL=
OWNER_SENTINEL_ID=

cleanup() {
  status=$1
  trap - EXIT HUP INT TERM
  expected_sentinel="$TMP/.fg052-wrapper-owner-$OWNER_TOKEN"
  physical_tmp=
  actual_tmp_id=
  actual_parent_id=
  actual_sentinel_id=
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    physical_tmp=$(CDPATH= cd -- "$TMP" && pwd -P)
    actual_tmp_id=$(file_identity "$TMP" 2>/dev/null) || actual_tmp_id=
  fi
  if [ -d "$TMP_PARENT" ] && [ ! -L "$TMP_PARENT" ]; then
    actual_parent_id=$(file_identity "$TMP_PARENT" 2>/dev/null) || actual_parent_id=
  fi
  if [ -f "$OWNER_SENTINEL" ] && [ ! -L "$OWNER_SENTINEL" ]; then
    actual_sentinel_id=$(file_identity "$OWNER_SENTINEL" 2>/dev/null) || actual_sentinel_id=
  fi
  case "$TMP" in
    "$TMP_PARENT"/fg052-release-admission-poc.*) temp_name_valid=true ;;
    *) temp_name_valid=false ;;
  esac
  if [ "$temp_name_valid" = true ] \
    && [ "$physical_tmp" = "$TMP" ] \
    && [ "$actual_tmp_id" = "$TMP_ID" ] \
    && [ "$actual_parent_id" = "$TMP_PARENT_ID" ] \
    && [ -n "$OWNER_TOKEN" ] \
    && [ "$OWNER_SENTINEL" = "$expected_sentinel" ] \
    && [ -f "$OWNER_SENTINEL" ] \
    && [ ! -L "$OWNER_SENTINEL" ] \
    && [ "$actual_sentinel_id" = "$OWNER_SENTINEL_ID" ] \
    && [ "$(cat "$OWNER_SENTINEL")" = "fg052-release-admission:$OWNER_TOKEN" ]; then
    if rm -rf -- "$TMP"; then
      printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true'
    else
      printf '%s\n' '[!] failed to remove the sentinel-owned temporary archive' >&2
      status=1
    fi
  else
    printf '%s\n' "[!] refusing cleanup without exact realpath and wrapper ownership sentinel; retained $TMP" >&2
    status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

OWNER_TOKEN=$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')
OWNER_SENTINEL="$TMP/.fg052-wrapper-owner-$OWNER_TOKEN"
[ ! -e "$OWNER_SENTINEL" ] || {
  printf '%s\n' 'ownership sentinel target unexpectedly exists' >&2
  exit 1
}
printf 'fg052-release-admission:%s\n' "$OWNER_TOKEN" > "$OWNER_SENTINEL"
OWNER_SENTINEL_ID=$(file_identity "$OWNER_SENTINEL")

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

if command -v sha256sum >/dev/null 2>&1; then
  ARCHIVE_SHA256=$(sha256sum "$TMP/source.tar" | awk '{print $1}')
else
  ARCHIVE_SHA256=$(shasum -a 256 "$TMP/source.tar" | awk '{print $1}')
fi

tar -xf "$TMP/source.tar" -C "$TMP/source"
rm -- "$TMP/source.tar"

printf '[+] archived revision=%s tree=%s archive_sha256=%s\n' \
  "$REVISION" "$TREE" "$ARCHIVE_SHA256"
printf '%s\n' '[+] safety local archive, synthetic branch, fake Git, no SSH, network, Docker, credentials, or live state'

FG052_ARCHIVE_SHA256="$ARCHIVE_SHA256" \
  node --max-old-space-size=96 "$SCRIPT_DIR/release-admission-order-probe.mjs" \
    "$TMP/source" "$TMP" "$OWNER_SENTINEL"
