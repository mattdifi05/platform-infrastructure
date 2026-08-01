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
mkdir -p "$TMP_PARENT"
TMP_PARENT=$(CDPATH= cd -- "$TMP_PARENT" && pwd -P)
TMP=$(mktemp -d "$TMP_PARENT/archive.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
[ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] || {
  printf '%s\n' "temporary root escaped its wrapper-owned parent" >&2
  exit 1
}

OWNER_TOKEN=$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')
OWNER_SENTINEL="$TMP/.hosted-provider-lock-owner-$OWNER_TOKEN"
(umask 077; printf 'hosted-provider-lock:%s\n' "$OWNER_TOKEN" > "$OWNER_SENTINEL")

cleanup() {
  status=$1
  trap - EXIT HUP INT TERM
  expected_sentinel="$TMP/.hosted-provider-lock-owner-$OWNER_TOKEN"
  case "$TMP" in
    "$TMP_PARENT"/archive.*) temp_path_valid=true ;;
    *) temp_path_valid=false ;;
  esac
  if [ "$temp_path_valid" = true ] \
    && [ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] \
    && [ -n "$OWNER_TOKEN" ] \
    && [ "$OWNER_SENTINEL" = "$expected_sentinel" ] \
    && [ ! -L "$OWNER_SENTINEL" ] \
    && [ -f "$OWNER_SENTINEL" ] \
    && [ "$(cat "$OWNER_SENTINEL")" = "hosted-provider-lock:$OWNER_TOKEN" ]; then
    rm -rf -- "$TMP"
    printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true'
  else
    printf '%s\n' "warning: refusing cleanup without the wrapper ownership sentinel: $TMP" >&2
  fi
  rmdir "$TMP_PARENT" 2>/dev/null || true
  exit "$status"
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
printf '%s\n' 'preexisting-provider-helper-must-survive' > "$PREEXISTING_ROOT/preserve-helper"
PREEXISTING_HASH=$(shasum -a 256 "$PREEXISTING_ROOT/preserve-helper" | awk '{print $1}')

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
printf '%s\n' '[+] safety source-only contract calls, non-executable helper fixtures, no Compose, Docker, provider, service, or network execution'
node --max-old-space-size=96 "$SCRIPT_DIR/hosted-provider-binary-lock-probe.mjs" \
  "$TMP/source" "$TMP" "$OWNER_SENTINEL" "$PREEXISTING_ROOT"

POSTEXISTING_HASH=$(shasum -a 256 "$PREEXISTING_ROOT/preserve-helper" | awk '{print $1}')
[ "$POSTEXISTING_HASH" = "$PREEXISTING_HASH" ] || {
  printf '%s\n' 'pre-existing negative-control helper changed' >&2
  exit 1
}
[ ! -e "$PREEXISTING_ROOT/.provider-lock-probe-owner" ] || {
  printf '%s\n' 'pre-existing negative-control target received a probe sentinel' >&2
  exit 1
}
printf '[+] wrapper post-check preexisting_helper_survived=true sha256=%s\n' "$POSTEXISTING_HASH"
