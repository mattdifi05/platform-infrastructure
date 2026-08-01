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

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/evidence-bundle-trust-anchor-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
WRAPPER_SENTINEL=$(mktemp "$TMP/.fg035-wrapper-owner.XXXXXX")
WRAPPER_TOKEN=${WRAPPER_SENTINEL##*.}
printf 'FG035-WRAPPER:%s\n' "$WRAPPER_TOKEN" > "$WRAPPER_SENTINEL"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  expected_owner="FG035-WRAPPER:$WRAPPER_TOKEN"
  actual_owner=
  if [ -f "$WRAPPER_SENTINEL" ] && [ ! -L "$WRAPPER_SENTINEL" ]; then
    actual_owner=$(sed -n '1p' "$WRAPPER_SENTINEL")
  fi
  case "$WRAPPER_SENTINEL" in
    "$TMP"/.fg035-wrapper-owner.*) sentinel_path_owned=1 ;;
    *) sentinel_path_owned=0 ;;
  esac
  if [ -d "$TMP" ] && [ ! -L "$TMP" ] \
    && [ "$sentinel_path_owned" -eq 1 ] \
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

GUARD_ROOT=$(mktemp -d "$TMP/fg035-guard.XXXXXX")
GUARD_ROOT=$(CDPATH= cd -- "$GUARD_ROOT" && pwd -P)
GUARD_SENTINEL=$(mktemp "$GUARD_ROOT/.fg035-owner.XXXXXX")
GUARD_TOKEN=${GUARD_SENTINEL##*.}
printf 'FG035-OWNER:%s\n' "$GUARD_TOKEN" > "$GUARD_SENTINEL"
mkdir "$GUARD_ROOT/source"
git -C "$SOURCE_REPO" archive --format=tar "$REVISION" \
  | tar -xf - -C "$GUARD_ROOT/source"
mkdir -p "$GUARD_ROOT/source/reports/preexisting"
printf '%s\n' 'pre-existing evidence must survive the rejected probe' \
  > "$GUARD_ROOT/expected-evidence.txt"
cp "$GUARD_ROOT/expected-evidence.txt" \
  "$GUARD_ROOT/source/reports/preexisting/evidence.txt"

GUARD_LOG="$GUARD_ROOT/negative-regression.log"
if REPORT_FG035_WRAPPER_TEMP_ROOT="$GUARD_ROOT" \
  REPORT_FG035_OWNERSHIP_SENTINEL="$GUARD_SENTINEL" \
  REPORT_FG035_OWNERSHIP_TOKEN="$GUARD_TOKEN" \
  node "$SCRIPT_DIR/evidence-bundle-trust-anchor-probe.mjs" \
    "$GUARD_ROOT/source" > "$GUARD_LOG" 2>&1; then
  printf '%s\n' 'guard regression failed: pre-existing reports were accepted' >&2
  exit 1
fi
grep -q 'refusing to mutate pre-existing target path: reports' "$GUARD_LOG" || {
  printf '%s\n' 'guard regression failed for an unexpected reason' >&2
  exit 1
}
cmp -s "$GUARD_ROOT/expected-evidence.txt" \
  "$GUARD_ROOT/source/reports/preexisting/evidence.txt" || {
  printf '%s\n' 'guard regression modified pre-existing evidence' >&2
  exit 1
}
[ ! -e "$GUARD_ROOT/source/.tmp" ] || {
  printf '%s\n' 'guard regression created a mutation target before rejection' >&2
  exit 1
}

RUN_ROOT=$(mktemp -d "$TMP/fg035-run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
RUN_SENTINEL=$(mktemp "$RUN_ROOT/.fg035-owner.XXXXXX")
RUN_TOKEN=${RUN_SENTINEL##*.}
printf 'FG035-OWNER:%s\n' "$RUN_TOKEN" > "$RUN_SENTINEL"
mkdir "$RUN_ROOT/source"
git -C "$SOURCE_REPO" archive --format=tar "$REVISION" \
  | tar -xf - -C "$RUN_ROOT/source"

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
printf '%s\n' '[GUARD] pre_existing_reports=true probe=reject evidence_preserved=true'
REPORT_FG035_WRAPPER_TEMP_ROOT="$RUN_ROOT" \
  REPORT_FG035_OWNERSHIP_SENTINEL="$RUN_SENTINEL" \
  REPORT_FG035_OWNERSHIP_TOKEN="$RUN_TOKEN" \
  node "$SCRIPT_DIR/evidence-bundle-trust-anchor-probe.mjs" \
    "$RUN_ROOT/source"
