#!/usr/bin/env sh
set -eu

REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
SOURCE_REPO=${1:-${SOURCE_REPO:-}}

if [ -z "$SOURCE_REPO" ]; then
  printf '%s\n' "usage: $0 /path/to/platform-infrastructure" >&2
  exit 2
fi

[ -d "$SOURCE_REPO" ] && [ ! -L "$SOURCE_REPO" ] || {
  printf '%s\n' "source repository must be a real directory: $SOURCE_REPO" >&2
  exit 2
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)
TMP_BASE=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
NODE_BIN=$(command -v node)

file_identity() {
  if stat -f '%d:%i' "$1" >/dev/null 2>&1; then
    stat -f '%d:%i' "$1"
  else
    stat -c '%d:%i' "$1"
  fi
}

TMP_BASE_ID=$(file_identity "$TMP_BASE")

umask 077
OWNER_TOKEN=$(LC_ALL=C od -An -N 32 -tx1 /dev/urandom | tr -d ' \n')
[ "${#OWNER_TOKEN}" -eq 64 ] || {
  printf '%s\n' "failed to create temporary-root ownership token" >&2
  exit 1
}

TMP=$(mktemp -d "$TMP_BASE/release-subject-claim-verification-poc.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
TMP_ID=$(file_identity "$TMP")
case "$TMP" in
  "$TMP_BASE"/release-subject-claim-verification-poc.*) ;;
  *)
    printf '%s\n' "refusing unexpected temporary root: $TMP" >&2
    exit 1
    ;;
esac

OWNER_FILE="$TMP/.release-subject-claim-verification-poc-owner"
printf '%s' "$OWNER_TOKEN" > "$OWNER_FILE"
OWNER_FILE_ID=$(file_identity "$OWNER_FILE")

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  physical_tmp=
  actual_tmp_id=
  actual_parent_id=
  actual_owner_id=
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    physical_tmp=$(CDPATH= cd -- "$TMP" && pwd -P)
    actual_tmp_id=$(file_identity "$TMP" 2>/dev/null) || actual_tmp_id=
  fi
  if [ -d "$TMP_BASE" ] && [ ! -L "$TMP_BASE" ]; then
    actual_parent_id=$(file_identity "$TMP_BASE" 2>/dev/null) || actual_parent_id=
  fi
  if [ -f "$OWNER_FILE" ] && [ ! -L "$OWNER_FILE" ]; then
    actual_owner_id=$(file_identity "$OWNER_FILE" 2>/dev/null) || actual_owner_id=
  fi
  if [ -d "$TMP" ] \
    && [ ! -L "$TMP" ] \
    && [ "$physical_tmp" = "$TMP" ] \
    && [ "$(dirname -- "$TMP")" = "$TMP_BASE" ] \
    && [ "$actual_tmp_id" = "$TMP_ID" ] \
    && [ "$actual_parent_id" = "$TMP_BASE_ID" ] \
    && [ -f "$OWNER_FILE" ] \
    && [ ! -L "$OWNER_FILE" ] \
    && [ "$actual_owner_id" = "$OWNER_FILE_ID" ] \
    && [ "$(cat "$OWNER_FILE")" = "$OWNER_TOKEN" ]; then
    rm -rf -- "$TMP"
  else
    printf '%s\n' "refusing temporary cleanup because ownership validation failed: $TMP" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$TMP/git-home"
safe_git() {
  env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
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

mkdir "$TMP/source" "$TMP/home" "$TMP/node-tmp"
safe_git archive --format=tar --output "$TMP/source.tar" "$REVISION"
tar -xf "$TMP/source.tar" -C "$TMP/source"
SOURCE_REAL=$(CDPATH= cd -- "$TMP/source" && pwd -P)
[ "$SOURCE_REAL" = "$TMP/source" ] || {
  printf '%s\n' "archived source escaped the wrapper-owned temporary root" >&2
  exit 1
}

printf '[+] archived revision=%s tree=%s\n' "$REVISION" "$TREE"
printf '%s\n' '[+] safety empty environment, local parser fixture, and refusing verifier only; no network, provider, token, registry, SSH, secret, or live access'
env -i \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  HOME="$TMP/home" \
  TMPDIR="$TMP/node-tmp" \
  LANG=C \
  LC_ALL=C \
  NODE_OPTIONS= \
  RELEASE_SUBJECT_POC_TMP_ROOT="$TMP" \
  RELEASE_SUBJECT_POC_OWNER_TOKEN="$OWNER_TOKEN" \
  "$NODE_BIN" --max-old-space-size=96 "$SCRIPT_DIR/release-subject-claim-verification-probe.mjs" "$SOURCE_REAL"
