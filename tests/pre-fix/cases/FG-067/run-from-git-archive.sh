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

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

source_fingerprint() {
  {
    sha256_file "$1/scripts/infra-ops.mjs"
    sha256_file "$1/compose.yaml"
  } | shasum -a 256 | awk '{print $1}'
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
TMP_BASE=${TMPDIR:-/tmp}
TMP_PARENT=$(CDPATH= cd -- "$TMP_BASE" && pwd -P)
TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/fg067-restore-boundary-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
TMP_ID=$(file_identity "$TMP")
OWNER_TOKEN=
OWNER_SENTINEL=
OWNER_SENTINEL_ID=

cleanup() {
  status=$1
  trap - EXIT HUP INT TERM
  expected_sentinel="$TMP/.fg067-wrapper-owner-$OWNER_TOKEN"
  physical_tmp=
  actual_tmp_id=
  actual_parent_id=
  actual_sentinel_id=
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    physical_tmp=$(CDPATH= cd -- "$TMP" && pwd -P 2>/dev/null || true)
    actual_tmp_id=$(file_identity "$TMP" 2>/dev/null || true)
  fi
  if [ -d "$TMP_PARENT" ] && [ ! -L "$TMP_PARENT" ]; then
    actual_parent_id=$(file_identity "$TMP_PARENT" 2>/dev/null || true)
  fi
  if [ -f "$OWNER_SENTINEL" ] && [ ! -L "$OWNER_SENTINEL" ]; then
    actual_sentinel_id=$(file_identity "$OWNER_SENTINEL" 2>/dev/null) || actual_sentinel_id=
  fi
  case "$TMP" in
    "$TMP_PARENT"/fg067-restore-boundary-poc.*) temp_name_valid=true ;;
    *) temp_name_valid=false ;;
  esac
  if [ "$temp_name_valid" = true ] \
    && [ "$physical_tmp" = "$TMP" ] \
    && [ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] \
    && [ "$actual_tmp_id" = "$TMP_ID" ] \
    && [ "$actual_parent_id" = "$TMP_PARENT_ID" ] \
    && [ -n "$OWNER_TOKEN" ] \
    && [ "$OWNER_SENTINEL" = "$expected_sentinel" ] \
    && [ -f "$OWNER_SENTINEL" ] \
    && [ ! -L "$OWNER_SENTINEL" ] \
    && [ "$actual_sentinel_id" = "$OWNER_SENTINEL_ID" ] \
    && [ "$(cat "$OWNER_SENTINEL")" = "fg067-restore-boundary:$OWNER_TOKEN" ]; then
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

OWNER_TOKEN=$(LC_ALL=C od -An -N 32 -tx1 /dev/urandom | tr -d ' \n')
[ "${#OWNER_TOKEN}" -eq 64 ] || {
  printf '%s\n' 'failed to create a 256-bit ownership token' >&2
  exit 1
}
OWNER_SENTINEL="$TMP/.fg067-wrapper-owner-$OWNER_TOKEN"
[ ! -e "$OWNER_SENTINEL" ] || {
  printf '%s\n' 'ownership sentinel target unexpectedly exists' >&2
  exit 1
}
printf 'fg067-restore-boundary:%s\n' "$OWNER_TOKEN" > "$OWNER_SENTINEL"
OWNER_SENTINEL_ID=$(file_identity "$OWNER_SENTINEL")

mkdir "$TMP/git-home" "$TMP/node-home"
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

SOURCE_ARCHIVE="$TMP/source.tar"
SOURCE_ROOT="$TMP/source"
[ ! -e "$SOURCE_ROOT" ] || {
  printf '%s\n' 'refusing pre-existing source archive target' >&2
  exit 1
}
safe_git archive --format=tar --output "$SOURCE_ARCHIVE" "$REVISION"
ARCHIVE_SHA256=$(sha256_file "$SOURCE_ARCHIVE")
mkdir "$SOURCE_ROOT"
tar -xf "$SOURCE_ARCHIVE" -C "$SOURCE_ROOT"
rm -- "$SOURCE_ARCHIVE"
SOURCE_BEFORE=$(source_fingerprint "$SOURCE_ROOT")

GUARD_ROOT=$(mktemp -d "$TMP/guard.XXXXXX")
GUARD_ROOT=$(CDPATH= cd -- "$GUARD_ROOT" && pwd -P)
mkdir "$GUARD_ROOT/poc-output"
printf '%s\n' 'pre-existing evidence must survive the rejected probe' \
  > "$GUARD_ROOT/expected-preserved.txt"
cp "$GUARD_ROOT/expected-preserved.txt" "$GUARD_ROOT/poc-output/preserve.txt"
GUARD_LOG="$GUARD_ROOT/negative-regression.log"
if env -i PATH="$PATH" HOME="$TMP/node-home" LANG=C LC_ALL=C NODE_OPTIONS= \
  FG067_ARCHIVE_SHA256="$ARCHIVE_SHA256" node "$SCRIPT_DIR/restore-drill-boundary-probe.mjs" guard \
  "$SOURCE_ROOT" "$GUARD_ROOT" "$TMP" "$OWNER_SENTINEL" \
  > "$GUARD_LOG" 2>&1; then
  printf '%s\n' 'negative preservation regression unexpectedly accepted pre-existing output' >&2
  exit 1
fi
grep -q 'refusing to overwrite pre-existing output target: poc-output' "$GUARD_LOG" || {
  printf '%s\n' 'negative preservation regression failed for an unexpected reason' >&2
  exit 1
}
cmp -s "$GUARD_ROOT/expected-preserved.txt" "$GUARD_ROOT/poc-output/preserve.txt" || {
  printf '%s\n' 'negative preservation regression modified pre-existing output' >&2
  exit 1
}
[ "$(source_fingerprint "$SOURCE_ROOT")" = "$SOURCE_BEFORE" ] || {
  printf '%s\n' 'negative preservation regression modified archived source' >&2
  exit 1
}
printf '%s\n' '[GUARD] preexisting_output_rejected=true evidence_preserved=true source_mutations=0'

RUN_ROOT=$(mktemp -d "$TMP/run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
printf '[+] archived revision=%s tree=%s archive_sha256=%s\n' "$REVISION" "$TREE" "$ARCHIVE_SHA256"
printf '%s\n' '[+] safety exact archived source, static parsing and inert metadata only; no Docker, database, restore, SQL, network, secret, or live operation'
env -i PATH="$PATH" HOME="$TMP/node-home" LANG=C LC_ALL=C NODE_OPTIONS= \
  FG067_ARCHIVE_SHA256="$ARCHIVE_SHA256" node "$SCRIPT_DIR/restore-drill-boundary-probe.mjs" run \
  "$SOURCE_ROOT" "$RUN_ROOT" "$TMP" "$OWNER_SENTINEL"

[ "$(source_fingerprint "$SOURCE_ROOT")" = "$SOURCE_BEFORE" ] || {
  printf '%s\n' 'probe modified archived source' >&2
  exit 1
}
printf '%s\n' '[+] wrapper source_fingerprint_unchanged=true source_mutations=0'
