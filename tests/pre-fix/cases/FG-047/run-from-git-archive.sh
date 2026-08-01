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

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/evidence-render-deployment-equivalence-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
WRAPPER_SENTINEL=$(mktemp "$TMP/.fg047-wrapper-owner.XXXXXX")
WRAPPER_TOKEN=${WRAPPER_SENTINEL##*.}
printf 'FG047-WRAPPER:%s\n' "$WRAPPER_TOKEN" > "$WRAPPER_SENTINEL"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  expected_owner="FG047-WRAPPER:$WRAPPER_TOKEN"
  actual_owner=
  if [ -f "$WRAPPER_SENTINEL" ] && [ ! -L "$WRAPPER_SENTINEL" ]; then
    actual_owner=$(sed -n '1p' "$WRAPPER_SENTINEL")
  fi
  case "$WRAPPER_SENTINEL" in
    "$TMP"/.fg047-wrapper-owner.*) sentinel_path_owned=1 ;;
    *) sentinel_path_owned=0 ;;
  esac
  case "${TMP##*/}" in
    evidence-render-deployment-equivalence-poc.*) temp_name_owned=1 ;;
    *) temp_name_owned=0 ;;
  esac
  if [ -d "$TMP" ] && [ ! -L "$TMP" ] \
    && [ "$sentinel_path_owned" -eq 1 ] \
    && [ "$temp_name_owned" -eq 1 ] \
    && [ "$actual_owner" = "$expected_owner" ]; then
    if rm -rf "$TMP"; then
      printf '%s\n' '[+] sentinel-owned temporary archive removed'
    else
      printf '%s\n' '[!] failed to remove sentinel-owned temporary archive' >&2
      status=1
    fi
  else
    printf '%s\n' '[!] refusing cleanup: wrapper ownership sentinel is missing or invalid' >&2
    status=1
  fi
  exit "$status"
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

RUN_ROOT=$(mktemp -d "$TMP/fg047-run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
RUN_SENTINEL=$(mktemp "$RUN_ROOT/.fg047-owner.XXXXXX")
RUN_TOKEN=${RUN_SENTINEL##*.}
printf 'FG047-OWNER:%s\n' "$RUN_TOKEN" > "$RUN_SENTINEL"
mkdir "$RUN_ROOT/source"
git -C "$SOURCE_REPO" archive --format=tar "$REVISION" \
  | tar -xf - -C "$RUN_ROOT/source"

[ ! -e "$RUN_ROOT/source/.git" ] || {
  printf '%s\n' 'archive unexpectedly contains Git metadata' >&2
  exit 1
}

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
REPORT_FG047_WRAPPER_TEMP_ROOT="$RUN_ROOT" \
  REPORT_FG047_OWNERSHIP_SENTINEL="$RUN_SENTINEL" \
  REPORT_FG047_OWNERSHIP_TOKEN="$RUN_TOKEN" \
  node "$SCRIPT_DIR/evidence-render-deployment-equivalence-probe.mjs" \
    "$RUN_ROOT/source"
