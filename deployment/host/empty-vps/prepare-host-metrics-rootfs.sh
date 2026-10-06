#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# = 1 && $1 = --prepare ]] || {
  printf 'Usage: %s --prepare\n' "$0" >&2
  exit 64
}
[[ $(uname -s) = Linux && $(id -u) = 0 ]] || {
  echo 'Run as root on the intended Linux VPS.' >&2
  exit 1
}

rootfs=/var/lib/platform-host-metrics/rootfs
parent=${rootfs%/*}
[[ ! -L "$parent" && ! -L "$rootfs" ]] || {
  echo 'Host-metrics bind path must not be a symlink.' >&2
  exit 1
}
if [[ -e "$parent" ]]; then
  [[ -d "$parent" && $(stat -c '%u:%g:%a' "$parent") = 0:0:555 \
     && -z $(find "$parent" -mindepth 1 -maxdepth 1 ! -name rootfs -print -quit) ]] || {
    echo 'Existing host-metrics parent is not the reviewed empty root-owned directory.' >&2
    exit 1
  }
fi
if [[ -e "$rootfs" ]]; then
  [[ -d "$rootfs" && $(stat -c '%u:%g:%a' "$rootfs") = 0:0:555 \
     && -z $(find "$rootfs" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
    echo 'Existing host-metrics rootfs is not the reviewed empty root-owned directory.' >&2
    exit 1
  }
fi
install -d -o root -g root -m 0555 "$parent" "$rootfs"
[[ $(stat -c %d /) = $(stat -c %d "$rootfs") ]] || {
  echo 'Host-metrics directory must be on the root filesystem.' >&2
  exit 1
}
[[ -z $(find "$rootfs" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
  echo 'Host-metrics directory must be empty.' >&2
  exit 1
}
[[ $(stat -c '%u:%g:%a' "$rootfs") = 0:0:555 ]] || {
  echo 'Host-metrics directory permissions differ from the reviewed bind.' >&2
  exit 1
}
echo 'Empty root-filesystem metadata bind is ready.'
