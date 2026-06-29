#!/bin/sh
set -eu

workdir="${NODE_PROJECT_WORKDIR:-/workspace}"
install_command="${NODE_PROJECT_INSTALL_COMMAND:-}"
build_command="${NODE_PROJECT_BUILD_COMMAND:-}"
start_command="${NODE_PROJECT_START_COMMAND:?Set NODE_PROJECT_START_COMMAND}"
lock_name="${NODE_PROJECT_LOCK_NAME:-runtime-build}"

cd "$workdir"
mkdir -p .platform
lock_dir=".platform/${lock_name}.lock"

while ! mkdir "$lock_dir" 2>/dev/null; do
  echo "waiting for ${lock_dir}"
  sleep 2
done

cleanup() {
  rmdir "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [ -n "$install_command" ]; then
  sh -ec "$install_command"
fi

if [ -n "$build_command" ]; then
  sh -ec "$build_command"
fi

cleanup
trap - EXIT INT TERM

exec sh -ec "$start_command"
