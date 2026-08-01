#!/usr/bin/env sh
set -eu

REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
SOURCE_REPO=${1:-${SOURCE_REPO:-}}

if [ -z "$SOURCE_REPO" ]; then
  printf '%s\n' "usage: $0 SOURCE_REPO" >&2
  exit 2
fi

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

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_PARENT="$SCRIPT_DIR/.tmp"
[ ! -L "$TMP_PARENT" ] || {
  printf '%s\n' "temporary parent must not be a symbolic link: $TMP_PARENT" >&2
  exit 1
}
TMP_PARENT_CREATED=false
if [ ! -e "$TMP_PARENT" ]; then
  mkdir "$TMP_PARENT"
  TMP_PARENT_CREATED=true
else
  [ -d "$TMP_PARENT" ] || {
    printf '%s\n' "temporary parent is not a directory: $TMP_PARENT" >&2
    exit 1
  }
fi
TMP_PARENT=$(CDPATH= cd -- "$TMP_PARENT" && pwd -P)

file_identity() {
  if stat -f '%d:%i' "$1" >/dev/null 2>&1; then
    stat -f '%d:%i' "$1"
  else
    stat -c '%d:%i' "$1"
  fi
}

TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/archive.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
TMP_ID=$(file_identity "$TMP")
[ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] || {
  printf '%s\n' "temporary root escaped its wrapper-owned parent" >&2
  exit 1
}

OWNER_TOKEN=$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')
OWNER_SENTINEL="$TMP/.project-router-volumes-from-owner-$OWNER_TOKEN"
(umask 077; printf 'project-router-volumes-from:%s\n' "$OWNER_TOKEN" > "$OWNER_SENTINEL")
OWNER_SENTINEL_ID=$(file_identity "$OWNER_SENTINEL")

cleanup() {
  rc=$1
  trap - EXIT HUP INT TERM
  expected_sentinel="$TMP/.project-router-volumes-from-owner-$OWNER_TOKEN"
  physical_tmp=
  actual_tmp_id=
  actual_parent_id=
  actual_sentinel_id=
  case "$TMP" in
    "$TMP_PARENT"/archive.*) temp_path_valid=true ;;
    *) temp_path_valid=false ;;
  esac
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
  if [ "$temp_path_valid" = true ] \
    && [ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] \
    && [ "$physical_tmp" = "$TMP" ] \
    && [ "$actual_tmp_id" = "$TMP_ID" ] \
    && [ "$actual_parent_id" = "$TMP_PARENT_ID" ] \
    && [ -n "$OWNER_TOKEN" ] \
    && [ "$OWNER_SENTINEL" = "$expected_sentinel" ] \
    && [ ! -L "$OWNER_SENTINEL" ] \
    && [ -f "$OWNER_SENTINEL" ] \
    && [ "$actual_sentinel_id" = "$OWNER_SENTINEL_ID" ] \
    && [ "$(cat "$OWNER_SENTINEL")" = "project-router-volumes-from:$OWNER_TOKEN" ]; then
    rm -rf -- "$TMP"
    printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true'
  else
    printf '%s\n' "warning: refusing cleanup without the wrapper ownership sentinel: $TMP" >&2
    rc=1
  fi
  if [ "$TMP_PARENT_CREATED" = true ] \
    && [ -d "$TMP_PARENT" ] \
    && [ ! -L "$TMP_PARENT" ] \
    && [ "$(file_identity "$TMP_PARENT" 2>/dev/null || true)" = "$TMP_PARENT_ID" ]; then
    rmdir "$TMP_PARENT" 2>/dev/null || true
  fi
  exit "$rc"
}
trap 'cleanup $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$TMP/source"
git -C "$SOURCE_REPO" archive --format=tar --output "$TMP/source.tar" "$REVISION"
tar -xf "$TMP/source.tar" -C "$TMP/source"

PREEXISTING_ROOT="$TMP/preexisting"
mkdir "$PREEXISTING_ROOT"
printf '%s\n' 'preexisting-project-router-state-must-survive' > "$PREEXISTING_ROOT/project-state.json"
PREEXISTING_HASH=$(shasum -a 256 "$PREEXISTING_ROOT/project-state.json" | awk '{print $1}')

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
printf '%s\n' '[+] safety source-only policy analysis, no Docker, Compose, container, mount, project, credential, service, or network operation'
node --max-old-space-size=96 "$SCRIPT_DIR/project-router-volumes-from-probe.mjs" \
  "$TMP/source" "$TMP" "$OWNER_SENTINEL" "$PREEXISTING_ROOT"

POSTEXISTING_HASH=$(shasum -a 256 "$PREEXISTING_ROOT/project-state.json" | awk '{print $1}')
[ "$POSTEXISTING_HASH" = "$PREEXISTING_HASH" ] || {
  printf '%s\n' 'pre-existing project-router state changed' >&2
  exit 1
}
[ ! -e "$PREEXISTING_ROOT/.project-router-volumes-from-probe-owner" ] || {
  printf '%s\n' 'pre-existing target received a probe sentinel' >&2
  exit 1
}
printf '[+] wrapper post-check preexisting_state_survived=true sha256=%s\n' "$POSTEXISTING_HASH"
