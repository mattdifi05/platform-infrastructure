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

if [ ! -d "$SOURCE_REPO" ] || ! git -C "$SOURCE_REPO" rev-parse --git-dir >/dev/null 2>&1; then
  printf '%s\n' "error: source is not a Git worktree: $SOURCE_REPO" >&2
  exit 2
fi

SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_PARENT=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/nats-workload-authorization-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
TMP_ID=$(file_identity "$TMP")
WRAPPER_SENTINEL=$(mktemp "$TMP/.fg055-wrapper-owner.XXXXXX")
WRAPPER_TOKEN=${WRAPPER_SENTINEL##*.}
printf 'FG055-WRAPPER:%s\n' "$WRAPPER_TOKEN" > "$WRAPPER_SENTINEL"
WRAPPER_SENTINEL_ID=$(file_identity "$WRAPPER_SENTINEL")

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  expected_owner="FG055-WRAPPER:$WRAPPER_TOKEN"
  actual_owner=
  actual_sentinel_id=
  if [ -f "$WRAPPER_SENTINEL" ] && [ ! -L "$WRAPPER_SENTINEL" ]; then
    actual_owner=$(sed -n '1p' "$WRAPPER_SENTINEL")
    actual_sentinel_id=$(file_identity "$WRAPPER_SENTINEL" 2>/dev/null) || actual_sentinel_id=
  fi
  case "$WRAPPER_SENTINEL" in
    "$TMP"/.fg055-wrapper-owner.*) sentinel_path_owned=1 ;;
    *) sentinel_path_owned=0 ;;
  esac
  temp_real=
  actual_tmp_id=
  actual_parent_id=
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    temp_real=$(CDPATH= cd -- "$TMP" && pwd -P)
    actual_tmp_id=$(file_identity "$TMP" 2>/dev/null) || actual_tmp_id=
  fi
  if [ -d "$TMP_PARENT" ] && [ ! -L "$TMP_PARENT" ]; then
    actual_parent_id=$(file_identity "$TMP_PARENT" 2>/dev/null) || actual_parent_id=
  fi
  if [ "$temp_real" = "$TMP" ] \
    && [ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] \
    && [ "$actual_tmp_id" = "$TMP_ID" ] \
    && [ "$actual_parent_id" = "$TMP_PARENT_ID" ] \
    && [ "$actual_sentinel_id" = "$WRAPPER_SENTINEL_ID" ] \
    && [ "$sentinel_path_owned" -eq 1 ] \
    && [ "$actual_owner" = "$expected_owner" ]; then
    if rm -rf -- "$TMP"; then
      printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true'
    else
      printf '%s\n' '[!] failed to remove wrapper-owned temporary archive' >&2
      status=1
    fi
  else
    printf '%s\n' "[!] refusing cleanup: wrapper ownership sentinel is missing or invalid; retained $TMP" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

actual_revision=$(git -C "$SOURCE_REPO" rev-parse --verify "$REVISION^{commit}")
actual_tree=$(git -C "$SOURCE_REPO" rev-parse --verify "$REVISION^{tree}")
[ "$actual_revision" = "$REVISION" ] || {
  printf '%s\n' "unexpected revision: $actual_revision" >&2
  exit 1
}
[ "$actual_tree" = "$TREE" ] || {
  printf '%s\n' "unexpected tree: $actual_tree" >&2
  exit 1
}

GUARD_ROOT=$(mktemp -d "$TMP/fg055-guard.XXXXXX")
GUARD_ROOT=$(CDPATH= cd -- "$GUARD_ROOT" && pwd -P)
GUARD_SENTINEL=$(mktemp "$GUARD_ROOT/.fg055-owner.XXXXXX")
GUARD_TOKEN=${GUARD_SENTINEL##*.}
printf 'FG055-OWNER:%s\n' "$GUARD_TOKEN" > "$GUARD_SENTINEL"
mkdir "$GUARD_ROOT/source"
git -C "$SOURCE_REPO" archive --format=tar --output="$GUARD_ROOT/source.tar" "$REVISION"
tar -xf "$GUARD_ROOT/source.tar" -C "$GUARD_ROOT/source"
printf '%s\n' 'pre-existing synthetic bytes must survive the rejected probe' \
  > "$GUARD_ROOT/source/preserve-me.txt"
cp "$GUARD_ROOT/source/preserve-me.txt" "$GUARD_ROOT/expected-preserve-me.txt"

GUARD_LOG="$GUARD_ROOT/negative-regression.log"
if FG055_WRAPPER_TEMP_ROOT="$GUARD_ROOT" \
  FG055_OWNERSHIP_SENTINEL="$GUARD_SENTINEL" \
  FG055_OWNERSHIP_TOKEN="X$GUARD_TOKEN" \
  node "$SCRIPT_DIR/nats-workload-authorization-probe.mjs" \
    "$GUARD_ROOT/source" > "$GUARD_LOG" 2>&1; then
  printf '%s\n' 'guard regression failed: invalid ownership was accepted' >&2
  exit 1
fi
grep -q 'ownership token does not match sentinel name' "$GUARD_LOG" || {
  printf '%s\n' 'guard regression failed for an unexpected reason' >&2
  exit 1
}
cmp -s "$GUARD_ROOT/expected-preserve-me.txt" "$GUARD_ROOT/source/preserve-me.txt" || {
  printf '%s\n' 'guard regression modified pre-existing source bytes' >&2
  exit 1
}
printf '%s\n' '[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true'

RUN_ROOT=$(mktemp -d "$TMP/fg055-run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
RUN_SENTINEL=$(mktemp "$RUN_ROOT/.fg055-owner.XXXXXX")
RUN_TOKEN=${RUN_SENTINEL##*.}
printf 'FG055-OWNER:%s\n' "$RUN_TOKEN" > "$RUN_SENTINEL"
mkdir "$RUN_ROOT/source"
git -C "$SOURCE_REPO" archive --format=tar --output="$RUN_ROOT/source.tar" "$REVISION"
tar -xf "$RUN_ROOT/source.tar" -C "$RUN_ROOT/source"

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
FG055_WRAPPER_TEMP_ROOT="$RUN_ROOT" \
  FG055_OWNERSHIP_SENTINEL="$RUN_SENTINEL" \
  FG055_OWNERSHIP_TOKEN="$RUN_TOKEN" \
  node "$SCRIPT_DIR/nats-workload-authorization-probe.mjs" \
    "$RUN_ROOT/source"
