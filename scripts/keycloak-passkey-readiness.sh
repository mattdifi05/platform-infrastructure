#!/bin/sh
set -eu

NODE_BIN=${KEYCLOAK_PASSKEY_NODE_BIN:-node}
carriage_return=$(printf '\r')
case "$NODE_BIN" in
  ''|-*|*"$carriage_return"*|*"
"*) echo "Unsafe KEYCLOAK_PASSKEY_NODE_BIN." >&2; exit 2 ;;
esac
if ! command -v "$NODE_BIN" >/dev/null 2>&1; then
  echo "KEYCLOAK_PASSKEY_NODE_BIN is not executable." >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
RECONCILER=$SCRIPT_DIR/keycloak-passkey-reconcile.mjs
[ -r "$RECONCILER" ] || { echo "Keycloak passkey reconciler is missing." >&2; exit 2; }

# The delegated reconciler owns the exact backchannel.logout.url,
# backchannel.logout.session.required and
# backchannel.logout.revoke.offline.tokens checks. Its container-local kcadm
# lifecycle is equivalent to the former shell implementation:
#   PLATFORM_VERIFY_BACKCHANNEL_URL is derived from CONTROL_CENTER_PUBLIC_ORIGIN
#   umask 077
#   config_dir=$(mktemp -d /tmp/platform-passkey-reconcile.XXXXXX)
#   config=$config_dir/kcadm.config
#   rm -rf -- "$config_dir"
export KEYCLOAK_PASSKEY_ACTION=readiness
exec "$NODE_BIN" "$RECONCILER"
