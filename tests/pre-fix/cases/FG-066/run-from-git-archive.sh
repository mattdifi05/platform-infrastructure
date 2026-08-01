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
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

if [ -z "$SOURCE_REPO" ]; then
  printf '%s\n' "usage: $0 /path/to/platform-infrastructure" >&2
  exit 2
fi
[ -d "$SOURCE_REPO" ] && [ ! -L "$SOURCE_REPO" ] || {
  printf '%s\n' "source repository must be a real directory: $SOURCE_REPO" >&2
  exit 1
}
SOURCE_REPO=$(CDPATH= cd -- "$SOURCE_REPO" && pwd -P)

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
TMP_PARENT=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
TMP_PARENT_ID=$(file_identity "$TMP_PARENT")
TMP=$(mktemp -d "$TMP_PARENT/hosted-env-boundary.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
case "$TMP" in
  "$TMP_PARENT"/hosted-env-boundary.*) ;;
  *)
    printf '%s\n' "refusing unexpected temporary root: $TMP" >&2
    exit 1
    ;;
esac
[ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] || {
  printf '%s\n' "temporary root escaped its physical parent: $TMP" >&2
  exit 1
}

TMP_ID=$(file_identity "$TMP")
OWNER_TOKEN=$(LC_ALL=C od -An -N 32 -tx1 /dev/urandom | tr -d ' \n')
[ "${#OWNER_TOKEN}" -eq 64 ] || {
  printf '%s\n' "failed to create a 256-bit ownership token" >&2
  exit 1
}
OWNER_SENTINEL="$TMP/.hosted-env-boundary-wrapper-owner"
printf 'hosted-env-boundary:%s\n' "$OWNER_TOKEN" > "$OWNER_SENTINEL"
OWNER_SENTINEL_ID=$(file_identity "$OWNER_SENTINEL")

cleanup() {
  rc=$1
  trap - EXIT HUP INT TERM
  valid=true
  expected_sentinel="$TMP/.hosted-env-boundary-wrapper-owner"
  physical_tmp=
  actual_parent_id=
  case "$TMP" in "$TMP_PARENT"/hosted-env-boundary.*) ;; *) valid=false ;; esac
  [ -d "$TMP" ] && [ ! -L "$TMP" ] || valid=false
  if [ -d "$TMP" ] && [ ! -L "$TMP" ]; then
    physical_tmp=$(CDPATH= cd -- "$TMP" && pwd -P 2>/dev/null || true)
  fi
  if [ -d "$TMP_PARENT" ] && [ ! -L "$TMP_PARENT" ]; then
    actual_parent_id=$(file_identity "$TMP_PARENT" 2>/dev/null || true)
  fi
  [ "$physical_tmp" = "$TMP" ] || valid=false
  [ "$(dirname -- "$TMP")" = "$TMP_PARENT" ] || valid=false
  [ "$actual_parent_id" = "$TMP_PARENT_ID" ] || valid=false
  [ "$(file_identity "$TMP" 2>/dev/null || true)" = "$TMP_ID" ] || valid=false
  [ "$OWNER_SENTINEL" = "$expected_sentinel" ] || valid=false
  [ -f "$OWNER_SENTINEL" ] && [ ! -L "$OWNER_SENTINEL" ] || valid=false
  [ "$(file_identity "$OWNER_SENTINEL" 2>/dev/null || true)" = "$OWNER_SENTINEL_ID" ] || valid=false
  [ "$(cat "$OWNER_SENTINEL" 2>/dev/null || true)" = "hosted-env-boundary:$OWNER_TOKEN" ] || valid=false

  if [ "$valid" = true ]; then
    rm -rf -- "$TMP"
    if [ -e "$TMP" ]; then
      printf '%s\n' "cleanup failed to remove wrapper-owned temporary root: $TMP" >&2
      rc=1
    else
      printf '%s\n' '[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true'
    fi
  else
    printf '%s\n' "refusing cleanup because ownership validation failed: $TMP" >&2
    rc=1
  fi
  exit "$rc"
}
trap 'cleanup $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$TMP/git-home" "$TMP/node-home" "$TMP/source"
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

safe_git archive --format=tar --output "$TMP/source.tar" "$REVISION" -- \
  scripts/hosted-workload-contract.mjs \
  scripts/hosted-workload-contract.test.mjs \
  scripts/prepare-hosted-workloads.sh \
  scripts/compose-vps.sh
ARCHIVE_SHA256=$(sha256_file "$TMP/source.tar")
tar -xf "$TMP/source.tar" -C "$TMP/source"
SOURCE_REAL=$(CDPATH= cd -- "$TMP/source" && pwd -P)
[ "$SOURCE_REAL" = "$TMP/source" ] || {
  printf '%s\n' "archived source escaped the wrapper-owned root" >&2
  exit 1
}

printf '[+] archive revision=%s tree=%s sha256=%s\n' "$REVISION" "$TREE" "$ARCHIVE_SHA256"
printf '%s\n' '[+] safety only an exact synthetic KEY=value file inside the wrapper temp may be read; no real env discovery'
printf '%s\n' '[+] safety no Docker, Compose, network, SSH, credential, service, source mutation, or live access'

env -i \
  PATH="$PATH" \
  HOME="$TMP/node-home" \
  LANG=C \
  LC_ALL=C \
  NODE_OPTIONS= \
  node --max-old-space-size=64 "$SCRIPT_DIR/env-file-boundary-probe.mjs" \
    "$SOURCE_REAL" "$TMP" "$OWNER_SENTINEL" "$OWNER_TOKEN"
