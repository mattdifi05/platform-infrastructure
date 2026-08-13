#!/usr/bin/env sh
set -eu

# This compatibility entrypoint is deliberately install-only. It accepts no
# caller-selected path, release identity, request body, Docker command, or
# activation input. The root-owned consumer carries the fixed V1 candidate and
# has only additive authority to materialize that candidate into a new path.
CONSUMER=/usr/local/libexec/platform-v1-brownfield-install-consumer
SUDO=/usr/bin/sudo
SYSTEM_NAME=$(/usr/bin/uname -s)
if [ "$SYSTEM_NAME" != Linux ]; then
  SUDO=${PLATFORM_V1_INSTALL_TEST_SUDO:-$SUDO}
fi

[ "$#" -eq 0 ] || {
  echo "Usage: deploy-vps-remote.sh" >&2
  exit 64
}

# Require EOF before crossing the privilege boundary. Reading one bounded byte
# is fail-closed: a caller that leaves stdin open can only delay its own request
# and can never reach sudo or the consumer.
stdin_bytes=$(/bin/dd if=/dev/stdin bs=1 count=1 2>/dev/null | /usr/bin/wc -c | /usr/bin/tr -d '[:space:]')
[ "$stdin_bytes" = 0 ] || {
  echo "The V1 install-only transport accepts no stdin." >&2
  exit 64
}

exec "$SUDO" -n -- "$CONSUMER" install < /dev/null
