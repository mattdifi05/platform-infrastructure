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

# Require EOF before crossing the privilege boundary. Preserve the caller's
# descriptor explicitly: reopening /dev/stdin can fail for a pipe or socket
# even while fd 0 is still open. od represents every possible input byte,
# including NUL, without placing that byte in a shell variable.
exec 3<&0
if ! stdin_octet=$(/usr/bin/od -An -tu1 -N1 <&3 2>/dev/null); then
  exec 3<&-
  echo "The V1 install-only transport could not inspect stdin." >&2
  exit 74
fi
exec 3<&-
stdin_octet=$(printf '%s' "$stdin_octet" | /usr/bin/tr -d '[:space:]')
[ -z "$stdin_octet" ] || {
  echo "The V1 install-only transport accepts no stdin." >&2
  exit 64
}

exec "$SUDO" -n -- "$CONSUMER" install < /dev/null
