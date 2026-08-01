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

SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_BASE=${TMPDIR:-/tmp}
TMP_PARENT=$(CDPATH= cd -- "$TMP_BASE" && pwd -P)
TMP=$(mktemp -d "$TMP_PARENT/fg043-read-capabilities-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
OWNER_TOKEN=
OWNER_SENTINEL=

cleanup() {
  status=$1
  trap - EXIT HUP INT TERM
  expected_sentinel="$TMP/.fg043-wrapper-owner-$OWNER_TOKEN"
  physical_tmp=
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    physical_tmp=$(CDPATH= cd -- "$TMP" && pwd -P)
  fi
  case "$TMP" in
    "$TMP_PARENT"/fg043-read-capabilities-poc.*) temp_name_valid=true ;;
    *) temp_name_valid=false ;;
  esac
  if [ "$temp_name_valid" = true ] \
    && [ "$physical_tmp" = "$TMP" ] \
    && [ -n "$OWNER_TOKEN" ] \
    && [ "$OWNER_SENTINEL" = "$expected_sentinel" ] \
    && [ -f "$OWNER_SENTINEL" ] \
    && [ ! -L "$OWNER_SENTINEL" ] \
    && [ "$(cat "$OWNER_SENTINEL")" = "fg043-read-capabilities:$OWNER_TOKEN" ]; then
    if rm -rf -- "$TMP"; then
      printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true'
    else
      printf '%s\n' '[!] failed to remove the sentinel-owned temporary archive' >&2
      status=1
    fi
  else
    printf '%s\n' '[!] refusing cleanup without exact realpath and wrapper ownership sentinel' >&2
    status=1
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

OWNER_TOKEN=$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')
OWNER_SENTINEL="$TMP/.fg043-wrapper-owner-$OWNER_TOKEN"
[ ! -e "$OWNER_SENTINEL" ] || {
  printf '%s\n' 'ownership sentinel target unexpectedly exists' >&2
  exit 1
}
printf 'fg043-read-capabilities:%s\n' "$OWNER_TOKEN" > "$OWNER_SENTINEL"

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
  [ ! -e "$destination/source" ] || {
    printf '%s\n' "refusing pre-existing archive target: $destination/source" >&2
    exit 1
  }
  mkdir "$destination/source"
  git -C "$SOURCE_REPO" archive --format=tar --output "$destination/source.tar" "$REVISION"
  tar -xf "$destination/source.tar" -C "$destination/source"
  rm -- "$destination/source.tar"
}

GUARD_ROOT=$(mktemp -d "$TMP/guard.XXXXXX")
GUARD_ROOT=$(CDPATH= cd -- "$GUARD_ROOT" && pwd -P)
archive_revision "$GUARD_ROOT"
mkdir "$GUARD_ROOT/poc-output"
printf '%s\n' 'pre-existing output must survive the rejected probe' \
  > "$GUARD_ROOT/expected-preserved.txt"
cp "$GUARD_ROOT/expected-preserved.txt" "$GUARD_ROOT/poc-output/preserve.txt"
GUARD_LOG="$GUARD_ROOT/negative-regression.log"
if node "$SCRIPT_DIR/control-read-capabilities-probe.mjs" guard \
  "$GUARD_ROOT/source" "$GUARD_ROOT" "$TMP" "$OWNER_SENTINEL" \
  > "$GUARD_LOG" 2>&1; then
  printf '%s\n' 'negative preservation regression unexpectedly accepted a pre-existing output target' >&2
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
printf '%s\n' '[GUARD] preexisting_output_rejected=true evidence_preserved=true source_mutations=0'

RUN_ROOT=$(mktemp -d "$TMP/run.XXXXXX")
RUN_ROOT=$(CDPATH= cd -- "$RUN_ROOT" && pwd -P)
archive_revision "$RUN_ROOT"

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
printf '%s\n' '[+] safety exact source slices, synthetic sessions, no server, identity provider, database, backup, Vault, or network'
node --max-old-space-size=96 "$SCRIPT_DIR/control-read-capabilities-probe.mjs" run \
  "$RUN_ROOT/source" "$RUN_ROOT" "$TMP" "$OWNER_SENTINEL"
