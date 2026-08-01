#!/usr/bin/env sh
set -eu
umask 077

REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
SOURCE_REPO=${1:-${SOURCE_REPO:-}}

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
TMP=$(mktemp -d "${TMPDIR:-/tmp}/hosted-logging-policy-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
WRAPPER_SENTINEL=$(mktemp "$TMP/.fg041-wrapper-owner.XXXXXX")
WRAPPER_TOKEN=${WRAPPER_SENTINEL##*.}
printf 'FG041-WRAPPER:%s\n' "$WRAPPER_TOKEN" > "$WRAPPER_SENTINEL"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  expected_owner="FG041-WRAPPER:$WRAPPER_TOKEN"
  actual_owner=
  if [ -f "$WRAPPER_SENTINEL" ] && [ ! -L "$WRAPPER_SENTINEL" ]; then
    actual_owner=$(sed -n '1p' "$WRAPPER_SENTINEL")
  fi
  case "$WRAPPER_SENTINEL" in
    "$TMP"/.fg041-wrapper-owner.*) sentinel_path_owned=1 ;;
    *) sentinel_path_owned=0 ;;
  esac
  temp_real=
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    temp_real=$(CDPATH= cd -- "$TMP" && pwd -P)
  fi
  if [ "$temp_real" = "$TMP" ] \
    && [ "$sentinel_path_owned" -eq 1 ] \
    && [ "$actual_owner" = "$expected_owner" ]; then
    if rm -rf "$TMP"; then
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

GUARD_ROOT=$(mktemp -d "$TMP/fg041-guard.XXXXXX")
GUARD_ROOT=$(CDPATH= cd -- "$GUARD_ROOT" && pwd -P)
GUARD_SENTINEL=$(mktemp "$GUARD_ROOT/.fg041-owner.XXXXXX")
GUARD_TOKEN=${GUARD_SENTINEL##*.}
printf 'FG041-OWNER:%s\n' "$GUARD_TOKEN" > "$GUARD_SENTINEL"
mkdir "$GUARD_ROOT/source"
git -C "$SOURCE_REPO" archive --format=tar "$REVISION" \
  | tar -xf - -C "$GUARD_ROOT/source"
printf '%s\n' 'pre-existing synthetic bytes must survive the rejected probe' \
  > "$GUARD_ROOT/source/preserve-me.txt"
cp "$GUARD_ROOT/source/preserve-me.txt" "$GUARD_ROOT/expected-preserve-me.txt"

GUARD_LOG="$GUARD_ROOT/negative-regression.log"
if FG041_WRAPPER_TEMP_ROOT="$GUARD_ROOT" \
  FG041_OWNERSHIP_SENTINEL="$GUARD_SENTINEL" \
  FG041_OWNERSHIP_TOKEN="X$GUARD_TOKEN" \
  node "$SCRIPT_DIR/hosted-logging-policy-probe.mjs" \
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

RUN_ROOT=$(mktemp -d "$TMP/fg041-run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
RUN_SENTINEL=$(mktemp "$RUN_ROOT/.fg041-owner.XXXXXX")
RUN_TOKEN=${RUN_SENTINEL##*.}
printf 'FG041-OWNER:%s\n' "$RUN_TOKEN" > "$RUN_SENTINEL"
mkdir "$RUN_ROOT/source"
git -C "$SOURCE_REPO" archive --format=tar "$REVISION" \
  | tar -xf - -C "$RUN_ROOT/source"

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
FG041_WRAPPER_TEMP_ROOT="$RUN_ROOT" \
  FG041_OWNERSHIP_SENTINEL="$RUN_SENTINEL" \
  FG041_OWNERSHIP_TOKEN="$RUN_TOKEN" \
  node "$SCRIPT_DIR/hosted-logging-policy-probe.mjs" \
    "$RUN_ROOT/source"
