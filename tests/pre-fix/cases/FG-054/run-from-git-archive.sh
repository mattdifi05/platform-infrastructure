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

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_PARENT=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/redis-workload-authorization-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
TMP_ID=$(file_identity "$TMP")
WRAPPER_SENTINEL=$(mktemp "$TMP/.fg054-wrapper-owner.XXXXXX")
WRAPPER_TOKEN=${WRAPPER_SENTINEL##*.}
printf 'FG054-WRAPPER:%s\n' "$WRAPPER_TOKEN" > "$WRAPPER_SENTINEL"
WRAPPER_SENTINEL_ID=$(file_identity "$WRAPPER_SENTINEL")

cleanup() {
  rc=$?
  trap - EXIT HUP INT TERM
  expected_owner="FG054-WRAPPER:$WRAPPER_TOKEN"
  actual_owner=
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
  if [ -f "$WRAPPER_SENTINEL" ] && [ ! -L "$WRAPPER_SENTINEL" ]; then
    actual_owner=$(sed -n '1p' "$WRAPPER_SENTINEL")
    actual_sentinel_id=$(file_identity "$WRAPPER_SENTINEL" 2>/dev/null) || actual_sentinel_id=
  fi
  case "$WRAPPER_SENTINEL" in
    "$TMP"/.fg054-wrapper-owner.*) sentinel_path_owned=1 ;;
    *) sentinel_path_owned=0 ;;
  esac
  case "${TMP##*/}" in
    redis-workload-authorization-poc.*) temp_name_owned=1 ;;
    *) temp_name_owned=0 ;;
  esac
  if [ -d "$TMP" ] && [ ! -L "$TMP" ] \
    && [ "$physical_tmp" = "$TMP" ] \
    && [ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] \
    && [ "$actual_tmp_id" = "$TMP_ID" ] \
    && [ "$actual_parent_id" = "$TMP_PARENT_ID" ] \
    && [ "$actual_sentinel_id" = "$WRAPPER_SENTINEL_ID" ] \
    && [ "$sentinel_path_owned" -eq 1 ] \
    && [ "$temp_name_owned" -eq 1 ] \
    && [ "$actual_owner" = "$expected_owner" ]; then
    if rm -rf -- "$TMP"; then
      printf '%s\n' '[+] sentinel-owned temporary archive removed'
    else
      printf '%s\n' '[!] failed to remove sentinel-owned temporary archive' >&2
      rc=1
    fi
  else
    printf '%s\n' '[!] refusing cleanup: wrapper ownership sentinel is missing or invalid' >&2
    rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

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

archive_revision() {
  destination=$1
  mkdir "$destination/source"
  git -C "$SOURCE_REPO" archive --format=tar "$REVISION" \
    | tar -xf - -C "$destination/source"
  [ ! -e "$destination/source/.git" ] || {
    printf '%s\n' 'archive unexpectedly contains Git metadata' >&2
    exit 1
  }
}

GUARD_ROOT=$(mktemp -d "$TMP/fg054-guard.XXXXXX")
GUARD_ROOT=$(CDPATH= cd -- "$GUARD_ROOT" && pwd -P)
GUARD_SENTINEL=$(mktemp "$GUARD_ROOT/.fg054-owner.XXXXXX")
GUARD_TOKEN=${GUARD_SENTINEL##*.}
printf 'FG054-OWNER:%s\n' "$GUARD_TOKEN" > "$GUARD_SENTINEL"
archive_revision "$GUARD_ROOT"
GUARD_BEFORE=$(git hash-object "$GUARD_ROOT/source/compose.yaml")
GUARD_LOG="$GUARD_ROOT/negative-ownership.log"
if REPORT_FG054_WRAPPER_TEMP_ROOT="$GUARD_ROOT" \
  REPORT_FG054_OWNERSHIP_SENTINEL="$GUARD_SENTINEL" \
  REPORT_FG054_OWNERSHIP_TOKEN="wrong-$GUARD_TOKEN" \
  node "$SCRIPT_DIR/redis-workload-authorization-probe.mjs" \
    "$GUARD_ROOT/source" > "$GUARD_LOG" 2>&1; then
  printf '%s\n' 'guard regression failed: wrong ownership token was accepted' >&2
  exit 1
fi
grep -q 'ownership token does not match sentinel name' "$GUARD_LOG" || {
  printf '%s\n' 'guard regression failed for an unexpected reason' >&2
  exit 1
}
GUARD_AFTER=$(git hash-object "$GUARD_ROOT/source/compose.yaml")
[ "$GUARD_BEFORE" = "$GUARD_AFTER" ] || {
  printf '%s\n' 'guard regression modified archived source' >&2
  exit 1
}

RUN_ROOT=$(mktemp -d "$TMP/fg054-run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
RUN_SENTINEL=$(mktemp "$RUN_ROOT/.fg054-owner.XXXXXX")
RUN_TOKEN=${RUN_SENTINEL##*.}
printf 'FG054-OWNER:%s\n' "$RUN_TOKEN" > "$RUN_SENTINEL"
archive_revision "$RUN_ROOT"

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
printf '%s\n' '[GUARD] wrong_ownership_token=reject archived_source_unchanged=true'
REPORT_FG054_WRAPPER_TEMP_ROOT="$RUN_ROOT" \
  REPORT_FG054_OWNERSHIP_SENTINEL="$RUN_SENTINEL" \
  REPORT_FG054_OWNERSHIP_TOKEN="$RUN_TOKEN" \
  node "$SCRIPT_DIR/redis-workload-authorization-probe.mjs" \
    "$RUN_ROOT/source"
