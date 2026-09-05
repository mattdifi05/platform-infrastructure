#!/usr/bin/env sh
set -eu
umask 077

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=plan
CONFIRM=
MANIFEST=
PREVIOUS_MANIFEST=
INSTALL_DIR=/usr/local/libexec/platform-infrastructure
INSTALL_HELPER=$INSTALL_DIR/local-private-egress-firewall
CONFIG_DIR=/etc/platform-infrastructure
INSTALL_MANIFEST=$CONFIG_DIR/local-private-egress.manifest.json
UNIT_NAME=local-private-egress-firewall.service
UNIT_FILE=/etc/systemd/system/$UNIT_NAME
DOCKER_SERVICE_DROPIN_DIR=/etc/systemd/system/docker.service.d
DOCKER_SERVICE_DROPIN=$DOCKER_SERVICE_DROPIN_DIR/20-local-private-egress.conf
DOCKER_SOCKET_DROPIN_DIR=/etc/systemd/system/docker.socket.d
DOCKER_SOCKET_DROPIN=$DOCKER_SOCKET_DROPIN_DIR/20-local-private-egress.conf

usage() {
  cat <<'EOF'
Usage: local-private-egress-install.sh [--plan|--install|--verify] [--manifest ABSOLUTE_PATH] [--previous-manifest ABSOLUTE_PATH] [--confirm TOKEN]

--install copies a previously admitted root-owned manifest and the fixed helper,
installs/enables the boot unit, but intentionally does not start it or change the
live firewall. It requires --confirm INSTALL-LOCAL-PRIVATE-EGRESS. Apply the
firewall in a separately gated pre-attach step with the installed helper.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --install) MODE=install ;;
    --verify) MODE=verify ;;
    --manifest) shift; MANIFEST=${1:?Missing value for --manifest} ;;
    --previous-manifest) shift; PREVIOUS_MANIFEST=${1:?Missing value for --previous-manifest} ;;
    --confirm) shift; CONFIRM=${1:?Missing value for --confirm} ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$MODE" = plan ]; then
  cat <<EOF
Plan only; no host or firewall mutation executed.
- validate one admitted root-owned manifest with $ROOT_DIR/scripts/local-private-egress-firewall.sh
- install the helper at $INSTALL_HELPER
- install the manifest at $INSTALL_MANIFEST with mode 0600
- install fail-closed Requires/After drop-ins for docker.socket and docker.service
- install a Docker ExecStartPre re-application gate for every daemon start
- install and enable $UNIT_NAME before docker.socket and docker.service
- require an isolated nft kernel round-trip before copying any file
- do not start the unit or attach/recreate any Docker network
EOF
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "Installation and verification require root" >&2; exit 1; }
for command_name in install systemctl stat cmp find sha256sum unshare; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name command not found" >&2; exit 1; }
done

verify_installation() {
  [ -f "$INSTALL_HELPER" ] && [ ! -L "$INSTALL_HELPER" ]
  [ -f "$INSTALL_MANIFEST" ] && [ ! -L "$INSTALL_MANIFEST" ]
  [ -f "$UNIT_FILE" ] && [ ! -L "$UNIT_FILE" ]
  [ -f "$DOCKER_SERVICE_DROPIN" ] && [ ! -L "$DOCKER_SERVICE_DROPIN" ]
  [ -f "$DOCKER_SOCKET_DROPIN" ] && [ ! -L "$DOCKER_SOCKET_DROPIN" ]
  [ "$(stat -c '%u:%g:%a' "$INSTALL_HELPER")" = "0:0:755" ]
  [ "$(stat -c '%u:%g:%a' "$INSTALL_MANIFEST")" = "0:0:600" ]
  [ "$(stat -c '%u:%g:%a' "$UNIT_FILE")" = "0:0:644" ]
  [ "$(stat -c '%u:%g:%a' "$DOCKER_SERVICE_DROPIN")" = "0:0:644" ]
  [ "$(stat -c '%u:%g:%a' "$DOCKER_SOCKET_DROPIN")" = "0:0:644" ]
  cmp -s "$ROOT_DIR/scripts/local-private-egress-firewall.sh" "$INSTALL_HELPER"
  cmp -s "$ROOT_DIR/systemd/local-private-egress-firewall.service" "$UNIT_FILE"
  cmp -s "$ROOT_DIR/systemd/local-private-egress-docker.service.conf" "$DOCKER_SERVICE_DROPIN"
  cmp -s "$ROOT_DIR/systemd/local-private-egress-docker.socket.conf" "$DOCKER_SOCKET_DROPIN"
  systemctl is-enabled --quiet "$UNIT_NAME"
  "$INSTALL_HELPER" --check --manifest "$INSTALL_MANIFEST"
  echo "$UNIT_NAME root-owned installation verified; live activation remains separate."
}

ensure_root_directory() {
  directory=$1
  if [ -e "$directory" ]; then
    [ -d "$directory" ] && [ ! -L "$directory" ] \
      || { echo "Installation directory is not a real directory: $directory" >&2; exit 1; }
    [ "$(stat -c '%u' "$directory")" -eq 0 ] \
      || { echo "Installation directory is not root-owned: $directory" >&2; exit 1; }
    [ -z "$(find "$directory" -maxdepth 0 -perm /022 -print -quit)" ] \
      || { echo "Installation directory is group/world writable: $directory" >&2; exit 1; }
    return
  fi
  install -d -o root -g root -m 0755 "$directory"
}

assert_protected_directory_chain() {
  current=$1
  while :; do
    [ -d "$current" ] && [ ! -L "$current" ] \
      || { echo "Installation path is not a real directory: $current" >&2; exit 1; }
    [ "$(stat -c '%u' "$current")" -eq 0 ] \
      || { echo "Installation path is not root-owned: $current" >&2; exit 1; }
    [ -z "$(find "$current" -maxdepth 0 -perm /022 -print -quit)" ] \
      || { echo "Installation path is group/world writable: $current" >&2; exit 1; }
    [ "$current" = / ] && break
    current=$(dirname -- "$current")
  done
}

assert_new_or_exact() {
  source_file=$1
  destination_file=$2
  destination_mode=$3
  if [ -e "$destination_file" ] || [ -L "$destination_file" ]; then
    [ -f "$destination_file" ] && [ ! -L "$destination_file" ] \
      && [ "$(stat -c '%u:%g:%a' "$destination_file")" = "0:0:$destination_mode" ] \
      && cmp -s "$source_file" "$destination_file" \
      || { echo "Refusing to overwrite foreign or drifted installation file: $destination_file" >&2; exit 1; }
  fi
}

install_if_absent() {
  source_file=$1
  destination_file=$2
  destination_mode=$3
  [ -e "$destination_file" ] || install -o root -g root -m "$destination_mode" "$source_file" "$destination_file"
}

if [ "$MODE" = verify ]; then
  verify_installation
  exit 0
fi

[ "$CONFIRM" = INSTALL-LOCAL-PRIVATE-EGRESS ] \
  || { echo "--install requires --confirm INSTALL-LOCAL-PRIVATE-EGRESS" >&2; exit 1; }
case "$MANIFEST" in /*) ;; *) echo "--manifest must be absolute for --install" >&2; exit 2 ;; esac
[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || { echo "Admitted manifest is missing or symbolic" >&2; exit 1; }
if [ -n "$PREVIOUS_MANIFEST" ]; then
  case "$PREVIOUS_MANIFEST" in /*) ;; *) echo "--previous-manifest must be absolute" >&2; exit 2 ;; esac
  [ -f "$PREVIOUS_MANIFEST" ] && [ ! -L "$PREVIOUS_MANIFEST" ] \
    || { echo "Previous manifest is missing or symbolic" >&2; exit 1; }
fi

# Resolve every destination and manifest preimage before the first filesystem
# mutation, so a foreign file cannot leave a partial installation behind.
assert_new_or_exact "$ROOT_DIR/scripts/local-private-egress-firewall.sh" "$INSTALL_HELPER" 755
assert_new_or_exact "$ROOT_DIR/systemd/local-private-egress-firewall.service" "$UNIT_FILE" 644
assert_new_or_exact "$ROOT_DIR/systemd/local-private-egress-docker.service.conf" "$DOCKER_SERVICE_DROPIN" 644
assert_new_or_exact "$ROOT_DIR/systemd/local-private-egress-docker.socket.conf" "$DOCKER_SOCKET_DROPIN" 644

manifest_action=unchanged
backup_manifest=
if [ -e "$INSTALL_MANIFEST" ] || [ -L "$INSTALL_MANIFEST" ]; then
  [ -f "$INSTALL_MANIFEST" ] && [ ! -L "$INSTALL_MANIFEST" ] \
    && [ "$(stat -c '%u:%g:%a' "$INSTALL_MANIFEST")" = "0:0:600" ] \
    || { echo "Refusing a foreign installed manifest" >&2; exit 1; }
  if ! cmp -s "$MANIFEST" "$INSTALL_MANIFEST"; then
    [ -n "$PREVIOUS_MANIFEST" ] && cmp -s "$PREVIOUS_MANIFEST" "$INSTALL_MANIFEST" \
      || { echo "Installed manifest does not match --previous-manifest preimage" >&2; exit 1; }
    previous_sha=$(sha256sum "$INSTALL_MANIFEST" | awk '{print $1}')
    backup_manifest="$CONFIG_DIR/local-private-egress.manifest.previous.$previous_sha.json"
    if [ -e "$backup_manifest" ]; then
      [ -f "$backup_manifest" ] && [ ! -L "$backup_manifest" ] \
        && [ "$(stat -c '%u:%g:%a' "$backup_manifest")" = "0:0:600" ] \
        && cmp -s "$INSTALL_MANIFEST" "$backup_manifest" \
        || { echo "Manifest backup path already contains different data" >&2; exit 1; }
    fi
    manifest_action=replace
  fi
else
  [ -z "$PREVIOUS_MANIFEST" ] || { echo "--previous-manifest is invalid for a fresh installation" >&2; exit 1; }
  manifest_action=fresh
fi

# Only after every destination preimage is accepted, prove the program against
# the host kernel in an isolated namespace and check the live table preimage.
"$ROOT_DIR/scripts/local-private-egress-firewall.sh" --kernel-roundtrip --manifest "$MANIFEST"
"$ROOT_DIR/scripts/local-private-egress-firewall.sh" --check --manifest "$MANIFEST"

ensure_root_directory "$INSTALL_DIR"
ensure_root_directory "$CONFIG_DIR"
ensure_root_directory "$DOCKER_SERVICE_DROPIN_DIR"
ensure_root_directory "$DOCKER_SOCKET_DROPIN_DIR"
assert_protected_directory_chain "$INSTALL_DIR"
assert_protected_directory_chain "$CONFIG_DIR"
assert_protected_directory_chain /etc/systemd/system
assert_protected_directory_chain "$DOCKER_SERVICE_DROPIN_DIR"
assert_protected_directory_chain "$DOCKER_SOCKET_DROPIN_DIR"
install_if_absent "$ROOT_DIR/scripts/local-private-egress-firewall.sh" "$INSTALL_HELPER" 755
install_if_absent "$ROOT_DIR/systemd/local-private-egress-firewall.service" "$UNIT_FILE" 644
install_if_absent "$ROOT_DIR/systemd/local-private-egress-docker.service.conf" "$DOCKER_SERVICE_DROPIN" 644
install_if_absent "$ROOT_DIR/systemd/local-private-egress-docker.socket.conf" "$DOCKER_SOCKET_DROPIN" 644

if [ "$manifest_action" = replace ]; then
  [ -e "$backup_manifest" ] || install -o root -g root -m 0600 "$INSTALL_MANIFEST" "$backup_manifest"
  install -o root -g root -m 0600 "$MANIFEST" "$INSTALL_MANIFEST"
elif [ "$manifest_action" = fresh ]; then
  install -o root -g root -m 0600 "$MANIFEST" "$INSTALL_MANIFEST"
fi
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
verify_installation
