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

random_token() {
  LC_ALL=C od -An -N 32 -tx1 /dev/urandom | tr -d ' \n'
}

if [ -z "$SOURCE_REPO" ]; then
  printf '%s\n' "usage: $0 /path/to/platform-infrastructure" >&2
  exit 2
fi

if [ ! -d "$SOURCE_REPO" ] || [ -L "$SOURCE_REPO" ]; then
  printf '%s\n' "error: source is not a Git worktree: $SOURCE_REPO" >&2
  exit 2
fi

SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_PARENT=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
[ -d "$TMP_PARENT" ] && [ ! -L "$TMP_PARENT" ] || {
  printf '%s\n' 'error: temporary parent must be a real directory' >&2
  exit 1
}
TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/database-admin-profile-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
TMP_ID=$(file_identity "$TMP")
WRAPPER_TOKEN=$(random_token)
WRAPPER_SENTINEL="$TMP/.fg076-wrapper-owner.$WRAPPER_TOKEN"
printf 'FG076-WRAPPER:%s\n' "$WRAPPER_TOKEN" > "$WRAPPER_SENTINEL"
WRAPPER_SENTINEL_ID=$(file_identity "$WRAPPER_SENTINEL")

cleanup() {
  status_code=$?
  trap - EXIT HUP INT TERM
  expected_owner="FG076-WRAPPER:$WRAPPER_TOKEN"
  actual_owner=
  actual_sentinel_id=
  if [ -f "$WRAPPER_SENTINEL" ] && [ ! -L "$WRAPPER_SENTINEL" ]; then
    actual_owner=$(cat "$WRAPPER_SENTINEL")
    actual_sentinel_id=$(file_identity "$WRAPPER_SENTINEL" 2>/dev/null) || actual_sentinel_id=
  fi
  case "$WRAPPER_SENTINEL" in
    "$TMP"/.fg076-wrapper-owner.*) sentinel_path_owned=1 ;;
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
    && [ "$sentinel_path_owned" -eq 1 ] \
    && [ "$actual_owner" = "$expected_owner" ] \
    && [ "$actual_sentinel_id" = "$WRAPPER_SENTINEL_ID" ]; then
    if rm -rf -- "$TMP"; then
      printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true'
    else
      printf '%s\n' '[!] failed to remove wrapper-owned temporary archive' >&2
      status_code=1
    fi
  else
    printf '%s\n' "[!] refusing cleanup: wrapper ownership sentinel is missing or invalid; retained $TMP" >&2
    status_code=1
  fi
  exit "$status_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$TMP/git-home" "$TMP/node-home"
safe_git() {
  env -i PATH="$PATH" HOME="$TMP/git-home" LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=file \
    git --no-replace-objects -c core.hooksPath=/dev/null "$@"
}

SOURCE_HEAD_BEFORE=$(safe_git -C "$SOURCE_REPO" rev-parse --verify 'HEAD^{commit}')
SOURCE_TREE_BEFORE=$(safe_git -C "$SOURCE_REPO" rev-parse --verify 'HEAD^{tree}')
[ "$SOURCE_HEAD_BEFORE" = "$REVISION" ] || {
  printf '%s\n' "unexpected source HEAD: $SOURCE_HEAD_BEFORE" >&2
  exit 1
}
[ "$SOURCE_TREE_BEFORE" = "$TREE" ] || {
  printf '%s\n' "unexpected source HEAD tree: $SOURCE_TREE_BEFORE" >&2
  exit 1
}

GUARD_ROOT=$(mktemp -d "$TMP/fg076-guard.XXXXXX")
GUARD_ROOT=$(CDPATH= cd -- "$GUARD_ROOT" && pwd -P)
GUARD_TOKEN=$(random_token)
GUARD_SENTINEL="$GUARD_ROOT/.fg076-owner.$GUARD_TOKEN"
printf 'FG076-OWNER:%s\n' "$GUARD_TOKEN" > "$GUARD_SENTINEL"
mkdir "$GUARD_ROOT/source" "$GUARD_ROOT/lab"
GUARD_ARCHIVE="$GUARD_ROOT/source.tar"
safe_git -C "$SOURCE_REPO" archive --format=tar --output="$GUARD_ARCHIVE" "$REVISION"
tar -xf "$GUARD_ARCHIVE" -C "$GUARD_ROOT/source"
rm -f -- "$GUARD_ARCHIVE"
printf '%s\n' 'pre-existing synthetic bytes must survive the rejected probe' \
  > "$GUARD_ROOT/source/preserve-me.txt"
cp "$GUARD_ROOT/source/preserve-me.txt" "$GUARD_ROOT/expected-preserve-me.txt"

GUARD_LOG="$GUARD_ROOT/negative-regression.log"
if env -i PATH="$PATH" HOME="$TMP/node-home" LANG=C LC_ALL=C NODE_OPTIONS= \
  FG076_WRAPPER_TEMP_ROOT="$GUARD_ROOT" \
  FG076_OWNERSHIP_SENTINEL="$GUARD_SENTINEL" \
  FG076_OWNERSHIP_TOKEN="wrong-$GUARD_TOKEN" \
  node "$SCRIPT_DIR/database-admin-profile-probe.mjs" \
    "$GUARD_ROOT/source" "$GUARD_ROOT/lab" > "$GUARD_LOG" 2>&1; then
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
[ -z "$(find "$GUARD_ROOT/lab" -mindepth 1 -print -quit)" ] || {
  printf '%s\n' 'guard regression wrote to the laboratory before ownership validation' >&2
  exit 1
}
printf '%s\n' '[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true lab_untouched=true'

RUN_ROOT=$(mktemp -d "$TMP/fg076-run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
RUN_TOKEN=$(random_token)
RUN_SENTINEL="$RUN_ROOT/.fg076-owner.$RUN_TOKEN"
printf 'FG076-OWNER:%s\n' "$RUN_TOKEN" > "$RUN_SENTINEL"
mkdir "$RUN_ROOT/source" "$RUN_ROOT/lab"
RUN_ARCHIVE="$RUN_ROOT/source.tar"
safe_git -C "$SOURCE_REPO" archive --format=tar --output="$RUN_ARCHIVE" "$REVISION"
tar -xf "$RUN_ARCHIVE" -C "$RUN_ROOT/source"
rm -f -- "$RUN_ARCHIVE"

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
env -i PATH="$PATH" HOME="$TMP/node-home" LANG=C LC_ALL=C NODE_OPTIONS= \
  FG076_WRAPPER_TEMP_ROOT="$RUN_ROOT" \
  FG076_OWNERSHIP_SENTINEL="$RUN_SENTINEL" \
  FG076_OWNERSHIP_TOKEN="$RUN_TOKEN" \
  node "$SCRIPT_DIR/database-admin-profile-probe.mjs" \
    "$RUN_ROOT/source" "$RUN_ROOT/lab"

SOURCE_HEAD_AFTER=$(safe_git -C "$SOURCE_REPO" rev-parse --verify 'HEAD^{commit}')
SOURCE_TREE_AFTER=$(safe_git -C "$SOURCE_REPO" rev-parse --verify 'HEAD^{tree}')
[ "$SOURCE_HEAD_AFTER" = "$SOURCE_HEAD_BEFORE" ] || {
  printf '%s\n' 'source HEAD changed while the PoC ran' >&2
  exit 1
}
[ "$SOURCE_TREE_AFTER" = "$SOURCE_TREE_BEFORE" ] || {
  printf '%s\n' 'source HEAD tree changed while the PoC ran' >&2
  exit 1
}
printf '%s\n' '[+] source_repository_head_unchanged=true source_repository_tree_unchanged=true'
