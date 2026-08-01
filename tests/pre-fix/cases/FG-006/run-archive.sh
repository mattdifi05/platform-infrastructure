#!/bin/sh
set -eu

REVISION=68cd05895b8d479ffb8167344282e7d922958bfc
TREE=70031b30316fbaecbb23249491d6ff4e364d65d5
REPOSITORY=${1:-}

if [ -z "$REPOSITORY" ]; then
  echo "Usage: sh run-archive.sh PATH_TO_REPOSITORY" >&2
  exit 2
fi

actual_revision=$(git -C "$REPOSITORY" rev-parse "$REVISION^{commit}")
actual_tree=$(git -C "$REPOSITORY" rev-parse "$REVISION^{tree}")
if [ "$actual_revision" != "$REVISION" ] || [ "$actual_tree" != "$TREE" ]; then
  echo "The repository does not resolve the required vulnerable commit and tree." >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/oidc-internal-tls-source-model.XXXXXX")
cleanup() {
  rm -rf -- "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

git -C "$REPOSITORY" archive --format=tar "$REVISION" control-center/auth/oidc.mjs |
  tar -xf - -C "$temporary_root"

node "$script_dir/oidc-internal-tls-probe.mjs" \
  --module "$temporary_root/control-center/auth/oidc.mjs" \
  --revision "$actual_revision"
