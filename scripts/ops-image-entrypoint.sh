#!/usr/bin/env sh
set -eu
umask 077

CODE_ROOT=/opt/platform-infrastructure
RUNTIME_ROOT=${PLATFORM_INFRA_ROOT:-/workspace}
ARCHIVE=${PLATFORM_INFRA_SNAPSHOT_ARCHIVE:-/run/platform-input/infra-source.tar}
EXPECTED_SHA256=${PLATFORM_INFRA_SNAPSHOT_SHA256:-}

if [ "${1:-}" = "hosted-workload-contract" ]; then
  shift
  exec node "$CODE_ROOT/scripts/hosted-workload-contract.mjs" "$@"
fi
if [ "${1:-}" = "backup-scheduler" ]; then
  shift
  exec sh "$CODE_ROOT/scripts/backup-scheduler.sh" "$@"
fi

case "$EXPECTED_SHA256" in
  *[!a-f0-9]*|"") echo "Exact infrastructure snapshot SHA256 is required." >&2; exit 78 ;;
esac
[ "${#EXPECTED_SHA256}" -eq 64 ] || {
  echo "Infrastructure snapshot SHA256 must be complete." >&2
  exit 78
}
[ -f "$ARCHIVE" ] && [ -r "$ARCHIVE" ] && [ -s "$ARCHIVE" ] && [ ! -L "$ARCHIVE" ] || {
  echo "Infrastructure snapshot archive is missing, unreadable, empty, or a symlink." >&2
  exit 78
}
[ -f "$CODE_ROOT/scripts/infra-ops.mjs" ] && [ ! -L "$CODE_ROOT/scripts/infra-ops.mjs" ] || {
  echo "The admitted ops image does not contain its immutable runner." >&2
  exit 78
}

local_archive=$(mktemp "${TMPDIR:-/tmp}/platform-infra-source.XXXXXX.tar")
cleanup() {
  rm -f "$local_archive"
}
stop_on_signal() {
  status=$1
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'stop_on_signal 129' HUP
trap 'stop_on_signal 130' INT
trap 'stop_on_signal 143' TERM

# Copy once into container-owned tmpfs, then hash and extract that same stable
# file. A host-side archive change can only cause a hash mismatch, never a
# mixed verify/extract view.
cp "$ARCHIVE" "$local_archive"
chmod 400 "$local_archive"
actual_sha256=$(sha256sum "$local_archive" | awk '{print $1}')
[ "$actual_sha256" = "$EXPECTED_SHA256" ] || {
  echo "Infrastructure snapshot archive SHA256 mismatch." >&2
  exit 1
}
tar -tf "$local_archive" | awk '
  /^\/|(^|\/)\.\.(\/|$)|(^|\/)\.(\/|$)|[\r\n]/ { invalid = 1 }
  END { exit invalid ? 1 : 0 }
' || {
  echo "Infrastructure snapshot archive contains an unsafe path." >&2
  exit 1
}
if tar -tf "$local_archive" | grep -Eq '^(projects-portal/state|secrets|traefik/acme|traefik/certs)(/|$)'; then
  echo "Infrastructure snapshot archive crossed a persistent-data boundary." >&2
  exit 1
fi

mkdir -p "$RUNTIME_ROOT"
tar -xf "$local_archive" -C "$RUNTIME_ROOT"
rm -f "$local_archive"
trap - EXIT HUP INT TERM

export PLATFORM_INFRA_ROOT="$RUNTIME_ROOT"
export PLATFORM_INFRA_SNAPSHOT_VERIFIED_SHA256="$actual_sha256"
exec node "$CODE_ROOT/scripts/infra-ops.mjs" "$@"
