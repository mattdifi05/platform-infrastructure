#!/usr/bin/env sh
set -eu

# This is deliberately a minimal transport shim. The candidate checkout never
# selects release paths, installs privileged helpers, renders Compose, or
# mutates Docker. The fixed provider-installed broker authenticates the bounded
# request and derives every object from its hard-coded policy and CAS roots.

BROKER=/usr/local/libexec/platform-activation-broker
MAX_REQUEST_BYTES=1048576
SUDO=/usr/bin/sudo
SYSTEM_NAME=$(/usr/bin/uname -s)
if [ "$SYSTEM_NAME" != Linux ]; then
  BROKER=${PLATFORM_ACTIVATION_TEST_BROKER:-$BROKER}
  SUDO=${PLATFORM_ACTIVATION_TEST_SUDO:-$SUDO}
fi

[ "$#" -eq 0 ] || {
  echo "Usage: deploy-vps-remote.sh < activation-request.json" >&2
  exit 64
}

umask 077
request=$(/usr/bin/mktemp /tmp/platform-activation-request.XXXXXX)
cleanup() {
  /bin/rm -f -- "$request"
}
trap cleanup EXIT HUP INT TERM

/bin/dd if=/dev/stdin of="$request" bs=65536 count=17 2>/dev/null
size=$(/usr/bin/wc -c < "$request" | /usr/bin/tr -d '[:space:]')
case "$size" in
  ''|*[!0-9]*) echo "Activation request size is invalid." >&2; exit 64 ;;
esac
[ "$size" -gt 0 ] && [ "$size" -le "$MAX_REQUEST_BYTES" ] || {
  echo "Activation request is empty or exceeds the 1 MiB transport bound." >&2
  exit 64
}

exec "$SUDO" -n "$BROKER" activate < "$request"
