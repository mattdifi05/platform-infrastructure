#!/usr/bin/env sh
set -eu

APPLY=0
PORTS="${ORIGIN_LOCK_PORTS:-80 443}"

usage() {
  cat <<'EOF'
Usage: cloudflare-origin-lock-ufw.sh [--apply] [--ports "80 443"]

Allow HTTP(S) origin traffic only from Cloudflare IP ranges using UFW.
Dry-run by default. Run on the VPS after Cloudflare DNS records are proxied.

Important: remove any old generic "ufw allow 80/tcp" or "ufw allow 443/tcp"
rules after confirming Cloudflare proxying works, otherwise direct-origin
bypass remains possible.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply)
      APPLY=1
      ;;
    --ports)
      shift
      PORTS="${1:?Missing value for --ports}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

run() {
  if [ "$APPLY" -eq 1 ]; then
    echo "+ $*"
    "$@"
  else
    echo "DRY-RUN: $*"
  fi
}

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root on the VPS, for example: sudo $0 --apply" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

curl -fsSL https://www.cloudflare.com/ips-v4 -o "$tmpdir/ips-v4"
curl -fsSL https://www.cloudflare.com/ips-v6 -o "$tmpdir/ips-v6"

echo "==> Allowing Cloudflare IP ranges to origin ports: $PORTS"
for port in $PORTS; do
  while IFS= read -r cidr; do
    [ -n "$cidr" ] || continue
    run ufw allow proto tcp from "$cidr" to any port "$port" comment "cloudflare-origin-${port}"
  done < "$tmpdir/ips-v4"

  while IFS= read -r cidr; do
    [ -n "$cidr" ] || continue
    run ufw allow proto tcp from "$cidr" to any port "$port" comment "cloudflare-origin-${port}"
  done < "$tmpdir/ips-v6"
done

run ufw reload

cat <<'EOF'

Next manual check on the VPS:
  sudo ufw status numbered

If generic public 80/443 allow rules still exist, delete them only after
Cloudflare proxied DNS is working. The desired end state is SSH open to you,
and web ports open only from Cloudflare CIDRs.
EOF
