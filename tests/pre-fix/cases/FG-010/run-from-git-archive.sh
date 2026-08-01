#!/bin/sh
set -eu

repository=${1:-}
revision=${2:-68cd05895b8d479ffb8167344282e7d922958bfc}
expect=${3:-vulnerable}

if [ -z "$repository" ]; then
  printf '%s\n' "usage: $0 REPOSITORY [REVISION] [vulnerable|fixed|either]" >&2
  exit 2
fi

case "$expect" in
  vulnerable|fixed|either) ;;
  *)
    printf '%s\n' "invalid expectation: $expect" >&2
    exit 2
    ;;
esac

repository=$(cd "$repository" && pwd -P)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/release-admission-poc.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

git -C "$repository" archive "$revision" | tar -x -C "$scratch"
mkdir -p "$scratch/.poc"
cp -R "$(dirname "$0")/fixtures/." "$scratch/.poc/"

node "$(dirname "$0")/release-admission-probe.mjs" \
  --source-root "$scratch" \
  --revision "$revision" \
  --expect "$expect"
