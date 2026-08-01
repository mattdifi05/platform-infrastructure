#!/usr/bin/env sh
set -eu

: "${REMOTE_ROOT:?REMOTE_ROOT is required}"
: "${BRANCH:?BRANCH is required}"
: "${EXPECTED_COMMIT:?EXPECTED_COMMIT is required}"
: "${EXPECTED_TREE:?EXPECTED_TREE is required}"
: "${TRUSTED_ADMISSION:?TRUSTED_ADMISSION is required}"
: "${TRACE_FILE:?TRACE_FILE is required}"

case "$REMOTE_ROOT" in /*) ;; *) exit 64 ;; esac
[ -d "$REMOTE_ROOT" ] && [ ! -L "$REMOTE_ROOT" ] || exit 64

cd -- "$REMOTE_ROOT"
git fetch --all --prune
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

actual_commit=$(git rev-parse --verify 'HEAD^{commit}')
actual_tree=$(git rev-parse 'HEAD^{tree}')
printf 'guard:identity commit=%s tree=%s\n' "$actual_commit" "$actual_tree" >> "$TRACE_FILE"

if [ "$actual_commit" != "$EXPECTED_COMMIT" ] || [ "$actual_tree" != "$EXPECTED_TREE" ]; then
  printf '%s\n' 'guard:identity-rejected' >> "$TRACE_FILE"
  exit 65
fi

"$TRUSTED_ADMISSION" --commit "$actual_commit" --tree "$actual_tree"
printf '%s\n' 'guard:admission-passed' >> "$TRACE_FILE"

sh ./scripts/vps-preflight.sh .env
sh ./scripts/prepare-vps-runtime.sh
bash ./scripts/compose-vps.sh up -d --build --remove-orphans
