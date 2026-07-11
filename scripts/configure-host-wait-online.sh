#!/bin/sh
set -eu

MODE=plan
INTERFACE=wlp3s0
UNIT=systemd-networkd-wait-online.service
DROPIN_DIR=/etc/systemd/system/systemd-networkd-wait-online.service.d
DROPIN_FILE="$DROPIN_DIR/20-platform-interface.conf"

usage() {
  cat <<'EOF'
Usage: configure-host-wait-online.sh [--plan|--apply|--verify|--remove] [--interface NAME]

Configures wait-online to require only the selected host interface. It never
changes Netplan, addresses, routes, NetworkManager or systemd-networkd.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --remove) MODE=remove ;;
    --interface)
      shift
      [ "$#" -gt 0 ] || { echo "--interface requires a value" >&2; exit 2; }
      INTERFACE=$1
      ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$INTERFACE" in
  *[!A-Za-z0-9_.:-]*|'') echo "Invalid interface name" >&2; exit 2 ;;
esac

WAIT_ONLINE=/usr/lib/systemd/systemd-networkd-wait-online
[ -x "$WAIT_ONLINE" ] || WAIT_ONLINE=/lib/systemd/systemd-networkd-wait-online
[ -x "$WAIT_ONLINE" ] || { echo "systemd-networkd-wait-online not found" >&2; exit 1; }

verify() {
  ip link show dev "$INTERFACE" >/dev/null
  ip route show default dev "$INTERFACE" | grep -q '^default '
  systemctl is-active --quiet "$UNIT"
  [ "$(systemctl show "$UNIT" -p Result --value)" = "success" ]
  [ "$(systemctl show "$UNIT" -p ExecMainStatus --value)" = "0" ]
  echo "$UNIT verified on $INTERFACE; active default route unchanged."
}

if [ "$MODE" = verify ]; then
  verify
  exit 0
fi

if [ "$MODE" = plan ]; then
  cat <<EOF
Plan only; no changes made:
- interface: $INTERFACE
- drop-in: $DROPIN_FILE
- command: $WAIT_ONLINE --interface=$INTERFACE --timeout=30
- network services and Netplan are not restarted or changed
EOF
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "$MODE requires root" >&2; exit 1; }

if [ "$MODE" = remove ]; then
  rm -f "$DROPIN_FILE"
  systemctl daemon-reload
  systemctl reset-failed "$UNIT" || true
  echo "Removed $DROPIN_FILE. The generated Netplan wait-online command is restored for the next start."
  exit 0
fi

ip link show dev "$INTERFACE" >/dev/null
ip route show default dev "$INTERFACE" | grep -q '^default '
install -d -m 0755 "$DROPIN_DIR"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
cat >"$tmp" <<EOF
[Service]
ExecStart=
ExecStart=$WAIT_ONLINE --interface=$INTERFACE --timeout=30
EOF
install -m 0644 "$tmp" "$DROPIN_FILE"
systemctl daemon-reload
systemctl stop "$UNIT" || true
systemctl reset-failed "$UNIT" || true
systemctl start "$UNIT"
verify
