#!/usr/bin/env sh
set -eu
umask 077

SCRIPT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_ROOT/.." && pwd)
REMOTE=${DEPLOY_REMOTE:-}
SSH_PORT=${DEPLOY_SSH_PORT:-22}
SSH_KEY_SOURCE=${DEPLOY_SSH_KEY_PATH:-${HOME:?HOME is required}/.ssh/deploy_key}
KNOWN_HOSTS_SOURCE=${DEPLOY_SSH_KNOWN_HOSTS_PATH:-${HOME:?HOME is required}/.ssh/known_hosts}
CANDIDATE_COMMIT=832bf2baec47055342af7e7f73425444381b91e0
CANDIDATE_TREE=91cee2380809cb0691b9ac47cafa2a673d434caa
SOURCE_ARCHIVE_SHA256=6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007
CONTROLLER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-control.py"
UNIT_SOURCE="$REPOSITORY_ROOT/systemd/platform-v1-local-private-control.service"
REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control activate'
SSH=/usr/bin/ssh
SYSTEM_NAME=$(/usr/bin/uname -s)
if [ "$SYSTEM_NAME" != Linux ]; then
  SSH=${PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH:-$SSH}
fi

fail() {
  echo "$1" >&2
  exit "${2:-64}"
}

hash_file() {
  trap - EXIT HUP INT TERM
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_input_file() {
  label=$1
  filename=$2
  [ -f "$filename" ] && [ -r "$filename" ] && [ -s "$filename" ] && [ ! -L "$filename" ] \
    || fail "$label must be one readable, non-empty regular file and not a symlink."
}

[ "$#" -eq 0 ] || fail "deploy-v1-local-private.sh accepts no positional arguments."
case "$REMOTE" in *@*) ;; *) fail "DEPLOY_REMOTE must be one canonical user@host endpoint." ;; esac
REMOTE_USER=${REMOTE%@*}
REMOTE_HOST=${REMOTE#*@}
case "$REMOTE_USER" in ""|[!a-z_]*|*[!a-z0-9_-]*) fail "DEPLOY_REMOTE user is invalid." ;; esac
case "$REMOTE_HOST" in ""|[!a-z0-9]*|*[!a-z0-9.-]*|*..*|*[-.]) fail "DEPLOY_REMOTE host is invalid." ;; esac
case "$REMOTE" in *@*@*) fail "DEPLOY_REMOTE must contain exactly one separator." ;; esac
case "$SSH_PORT" in ""|*[!0-9]*) fail "DEPLOY_SSH_PORT must be numeric." ;; esac
[ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] || fail "DEPLOY_SSH_PORT is outside the accepted range."
[ -x "$SSH" ] || fail "The fixed SSH client is unavailable." 78
[ -f "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" ] && [ ! -L "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" ] \
  || fail "The exact SSH endpoint verifier is unavailable." 78
[ -f "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" ] && [ ! -L "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" ] \
  || fail "The exact SSH host-key verifier is unavailable." 78
[ -f "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" ] && [ ! -L "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" ] \
  || fail "The exact V1 LOCAL_PRIVATE receipt verifier is unavailable." 78
require_input_file "SSH private key" "$SSH_KEY_SOURCE"
require_input_file "SSH known-hosts input" "$KNOWN_HOSTS_SOURCE"
require_input_file "V1 LOCAL_PRIVATE controller source" "$CONTROLLER_SOURCE"
require_input_file "V1 LOCAL_PRIVATE systemd unit source" "$UNIT_SOURCE"

work=$(mktemp -d "${TMPDIR:-/tmp}/platform-v1-local-private-client.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ssh_key="$work/ssh-key"
known_hosts="$work/known-hosts"
receipt="$work/local-private-control-receipt.json"
controller_snapshot="$work/v1-local-private-control.py"
unit_snapshot="$work/platform-v1-local-private-control.service"
key_before=$(hash_file "$SSH_KEY_SOURCE")
known_before=$(hash_file "$KNOWN_HOSTS_SOURCE")
controller_before=$(hash_file "$CONTROLLER_SOURCE")
unit_before=$(hash_file "$UNIT_SOURCE")
cp "$SSH_KEY_SOURCE" "$ssh_key"
cp "$KNOWN_HOSTS_SOURCE" "$known_hosts"
cp "$CONTROLLER_SOURCE" "$controller_snapshot"
cp "$UNIT_SOURCE" "$unit_snapshot"
chmod 600 "$ssh_key" "$known_hosts"
chmod 400 "$controller_snapshot" "$unit_snapshot"
[ "$(hash_file "$SSH_KEY_SOURCE")" = "$key_before" ] \
  && [ "$(hash_file "$ssh_key")" = "$key_before" ] \
  || fail "SSH private key changed during stable capture." 65
[ "$(hash_file "$KNOWN_HOSTS_SOURCE")" = "$known_before" ] \
  && [ "$(hash_file "$known_hosts")" = "$known_before" ] \
  || fail "SSH known-hosts input changed during stable capture." 65
[ "$(hash_file "$CONTROLLER_SOURCE")" = "$controller_before" ] \
  && [ "$(hash_file "$controller_snapshot")" = "$controller_before" ] \
  || fail "V1 LOCAL_PRIVATE controller source changed during stable capture." 65
[ "$(hash_file "$UNIT_SOURCE")" = "$unit_before" ] \
  && [ "$(hash_file "$unit_snapshot")" = "$unit_before" ] \
  || fail "V1 LOCAL_PRIVATE systemd unit source changed during stable capture." 65
CONTROLLER_SHA256=$controller_before
UNIT_SHA256=$unit_before

sh "$SCRIPT_ROOT/ssh-known-host-endpoint.sh" "$REMOTE_HOST" "$SSH_PORT" "$known_hosts"
node "$SCRIPT_ROOT/pinned-ssh-host-key.mjs" verify \
  --remote "$REMOTE" \
  --port "$SSH_PORT" \
  --file "$known_hosts" >/dev/null || fail "Pinned SSH host trust validation failed." 65

set -- \
  -F /dev/null \
  -i "$ssh_key" \
  -p "$SSH_PORT" \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=$known_hosts" \
  -o GlobalKnownHostsFile=/dev/null \
  -o UpdateHostKeys=no \
  -o PermitLocalCommand=no \
  -o ClearAllForwardings=yes \
  -o ExitOnForwardFailure=yes

# No caller-controlled plan, candidate path, provider evidence, or command
# crosses SSH. The root-owned LOCAL_PRIVATE controller owns the fixed plan.
(
  # POSIX file-size limits use 512-byte blocks. Bound the authenticated remote
  # response before disk write; the verifier enforces the same 128 KiB ceiling.
  ulimit -f 256
  exec "$SSH" "$@" -- "$REMOTE" "$REMOTE_COMMAND" < /dev/null
) > "$receipt"
[ -f "$receipt" ] && [ ! -L "$receipt" ] && [ -s "$receipt" ] \
  || fail "The root V1 LOCAL_PRIVATE controller returned no receipt." 65
receipt_size=$(wc -c < "$receipt" | tr -d '[:space:]')
case "$receipt_size" in ""|*[!0-9]*) fail "The V1 LOCAL_PRIVATE receipt size is invalid." 65 ;; esac
[ "$receipt_size" -le 131072 ] || fail "The V1 LOCAL_PRIVATE receipt exceeds 128 KiB." 65

node "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" verify \
  --file "$receipt" \
  --candidateCommit "$CANDIDATE_COMMIT" \
  --candidateTree "$CANDIDATE_TREE" \
  --sourceArchiveSha256 "$SOURCE_ARCHIVE_SHA256" \
  --controllerSha256 "$CONTROLLER_SHA256" \
  --unitSha256 "$UNIT_SHA256" >/dev/null
cat "$receipt"
