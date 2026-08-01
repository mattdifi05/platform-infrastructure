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
  printf '%s\n' "usage: $0 SOURCE_REPO" >&2
  exit 2
fi

[ -d "$SOURCE_REPO" ] && [ ! -L "$SOURCE_REPO" ] || {
  printf '%s\n' "source repository must be a real directory: $SOURCE_REPO" >&2
  exit 2
}
SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_PARENT=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/backup-tar-option-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
[ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] || {
  printf '%s\n' "temporary root escaped its wrapper-owned parent" >&2
  exit 1
}
TMP_ID=$(file_identity "$TMP")

OWNER_TOKEN=$(LC_ALL=C od -An -N 32 -tx1 /dev/urandom | tr -d ' \n')
[ "${#OWNER_TOKEN}" -eq 64 ] || {
  printf '%s\n' 'failed to create a 256-bit ownership token' >&2
  exit 1
}
OWNER_SENTINEL="$TMP/.backup-tar-option-owner-$OWNER_TOKEN"
printf 'backup-tar-option:%s\n' "$OWNER_TOKEN" > "$OWNER_SENTINEL"
OWNER_ID=$(file_identity "$OWNER_SENTINEL")

cleanup() {
  rc=$1
  trap - EXIT HUP INT TERM
  expected_sentinel="$TMP/.backup-tar-option-owner-$OWNER_TOKEN"
  temp_path_valid=false
  case "$TMP" in
    "$TMP_PARENT"/backup-tar-option-poc.*) temp_path_valid=true ;;
  esac
  current_owner_id=""
  if [ -e "$OWNER_SENTINEL" ] && [ ! -L "$OWNER_SENTINEL" ]; then
    current_owner_id=$(file_identity "$OWNER_SENTINEL" 2>/dev/null || true)
  fi
  current_tmp=""
  current_tmp_id=""
  current_parent_id=""
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    current_tmp=$(CDPATH= cd -- "$TMP" && pwd -P 2>/dev/null || true)
    current_tmp_id=$(file_identity "$TMP" 2>/dev/null || true)
  fi
  if [ -d "$TMP_PARENT" ] && [ ! -L "$TMP_PARENT" ]; then
    current_parent_id=$(file_identity "$TMP_PARENT" 2>/dev/null || true)
  fi
  if [ "$temp_path_valid" = true ] \
    && [ "$current_tmp" = "$TMP" ] \
    && [ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] \
    && [ "$current_tmp_id" = "$TMP_ID" ] \
    && [ "$current_parent_id" = "$TMP_PARENT_ID" ] \
    && [ -n "$OWNER_TOKEN" ] \
    && [ "$OWNER_SENTINEL" = "$expected_sentinel" ] \
    && [ "$current_owner_id" = "$OWNER_ID" ] \
    && [ "$(cat "$OWNER_SENTINEL")" = "backup-tar-option:$OWNER_TOKEN" ]; then
    rm -rf -- "$TMP"
    printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_device_inode_verified=true'
  else
    printf '%s\n' "warning: refusing cleanup without exact wrapper ownership proof: $TMP" >&2
    rc=1
  fi
  exit "$rc"
}
trap 'cleanup $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$TMP/source/scripts" "$TMP/git-home" "$TMP/node-home"
safe_git() {
  env -i \
    PATH="$PATH" \
    HOME="$TMP/git-home" \
    LANG=C \
    LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_TERMINAL_PROMPT=0 \
    GIT_ALLOW_PROTOCOL=file \
    git --no-replace-objects -c core.hooksPath=/dev/null -C "$SOURCE_REPO" "$@"
}

actual_revision=$(safe_git rev-parse --verify "$REVISION^{commit}")
actual_tree=$(safe_git rev-parse "$REVISION^{tree}")
[ "$actual_revision" = "$REVISION" ] || {
  printf '%s\n' "unexpected revision: $actual_revision" >&2
  exit 1
}
[ "$actual_tree" = "$TREE" ] || {
  printf '%s\n' "unexpected tree: $actual_tree" >&2
  exit 1
}

safe_git show "$REVISION:scripts/infra-ops.mjs" > "$TMP/source/scripts/infra-ops.mjs"
safe_git show "$REVISION:compose.backup-scheduler.yaml" > "$TMP/source/compose.backup-scheduler.yaml"
safe_git show "$REVISION:compose.runtime-isolation.yaml" > "$TMP/source/compose.runtime-isolation.yaml"

PREEXISTING_ROOT="$TMP/preexisting"
mkdir "$PREEXISTING_ROOT"
printf '%s\n' 'preexisting-backup-control-must-survive' > "$PREEXISTING_ROOT/control.txt"
PREEXISTING_HASH=$(shasum -a 256 "$PREEXISTING_ROOT/control.txt" | awk '{print $1}')
PREEXISTING_ID=$(file_identity "$PREEXISTING_ROOT/control.txt")
PREEXISTING_LISTING=$(find "$PREEXISTING_ROOT" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort)

printf '[+] materialized revision=%s tree=%s blobs=3\n' "$REVISION" "$TREE"
printf '%s\n' '[+] safety source-only argument analysis; no archive utility, backup path, payload command, service, or network operation'
env -i PATH="$PATH" HOME="$TMP/node-home" LANG=C LC_ALL=C NODE_OPTIONS= \
  node --max-old-space-size=96 "$SCRIPT_DIR/backup-tar-option-probe.mjs" \
  "$TMP/source" "$TMP" "$OWNER_SENTINEL" "$PREEXISTING_ROOT"

POSTEXISTING_HASH=$(shasum -a 256 "$PREEXISTING_ROOT/control.txt" | awk '{print $1}')
POSTEXISTING_ID=$(file_identity "$PREEXISTING_ROOT/control.txt")
POSTEXISTING_LISTING=$(find "$PREEXISTING_ROOT" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort)
[ "$POSTEXISTING_HASH" = "$PREEXISTING_HASH" ] || {
  printf '%s\n' 'pre-existing control bytes changed' >&2
  exit 1
}
[ "$POSTEXISTING_ID" = "$PREEXISTING_ID" ] || {
  printf '%s\n' 'pre-existing control device/inode changed' >&2
  exit 1
}
[ "$POSTEXISTING_LISTING" = "$PREEXISTING_LISTING" ] || {
  printf '%s\n' 'pre-existing control directory listing changed' >&2
  exit 1
}
[ ! -e "$PREEXISTING_ROOT/.backup-tar-option-probe-owner" ] || {
  printf '%s\n' 'pre-existing target received a probe sentinel' >&2
  exit 1
}
printf '[+] wrapper post-check preexisting_control_survived=true sha256=%s device_inode=%s\n' "$POSTEXISTING_HASH" "$POSTEXISTING_ID"
