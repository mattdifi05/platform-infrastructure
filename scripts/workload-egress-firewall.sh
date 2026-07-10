#!/usr/bin/env sh
set -eu

MODE=plan
CONFIRM=""
NETWORK_PREFIX="${PLATFORM_NETWORK_PREFIX:-platform_infra_vps}"
CHAIN=PLATFORM-WORKLOAD-EGRESS
SUBNET_FILE=$(mktemp)
cleanup() {
  rm -f "$SUBNET_FILE"
}
trap cleanup EXIT HUP INT TERM

usage() {
  cat <<'EOF'
Usage: workload-egress-firewall.sh [--plan|--apply|--verify|--rollback] [--network-prefix PREFIX] [--subnet CIDR] [--confirm TOKEN]

Default mode is plan. Apply discovers the candidate application egress Docker
networks and blocks access from their IPv4 subnets to private, loopback,
link-local/metadata, CGNAT and reserved destinations through DOCKER-USER.

--subnet is accepted for plan-only sandbox evidence and is rejected by apply,
verify and rollback.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --rollback) MODE=rollback ;;
    --network-prefix)
      shift
      NETWORK_PREFIX="${1:?Missing value for --network-prefix}"
      ;;
    --subnet)
      shift
      printf '%s\n' "${1:?Missing value for --subnet}" >> "$SUBNET_FILE"
      ;;
    --confirm)
      shift
      CONFIRM="${1:?Missing value for --confirm}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

case "$NETWORK_PREFIX" in
  ''|*[!A-Za-z0-9_.-]*)
    echo "Invalid network prefix" >&2
    exit 2
    ;;
esac

BLOCKED_DESTINATIONS="
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
"

require_command() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 command not found" >&2; exit 1; }
}

discover_subnets() {
  require_command docker
  docker network ls --format '{{.Name}}' | while IFS= read -r network; do
    case "$network" in
      "${NETWORK_PREFIX}"_app_*_egress)
        docker network inspect "$network" --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' \
          | while IFS= read -r subnet; do
              case "$subnet" in
                *:*) ;;
                '') ;;
                *) printf '%s\n' "$subnet" ;;
              esac
            done
        ;;
    esac
  done >> "$SUBNET_FILE"
}

validate_subnets() {
  sort -u "$SUBNET_FILE" -o "$SUBNET_FILE"
  if [ ! -s "$SUBNET_FILE" ]; then
    echo "No workload egress subnet found for prefix $NETWORK_PREFIX" >&2
    exit 1
  fi
  while IFS= read -r subnet; do
    case "$subnet" in
      *[!0-9./]*|''|*.*.*.*.*|*//*|/*|*/)
        echo "Invalid IPv4 CIDR: $subnet" >&2
        exit 1
        ;;
    esac
  done < "$SUBNET_FILE"
}

if [ "$MODE" != plan ] && [ -s "$SUBNET_FILE" ]; then
  echo "--subnet is plan-only; apply/verify must discover real Docker network subnets" >&2
  exit 2
fi

if [ "$MODE" = rollback ]; then
  [ "$(id -u)" -eq 0 ] || { echo "--rollback requires root" >&2; exit 1; }
  [ "$CONFIRM" = "ROLLBACK-WORKLOAD-EGRESS-FIREWALL" ] || { echo "Rollback requires --confirm ROLLBACK-WORKLOAD-EGRESS-FIREWALL" >&2; exit 1; }
  require_command iptables
  while iptables -w -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; do
    iptables -w -D DOCKER-USER -j "$CHAIN"
  done
  iptables -w -F "$CHAIN" >/dev/null 2>&1 || true
  iptables -w -X "$CHAIN" >/dev/null 2>&1 || true
  echo "Workload egress firewall chain removed; verify Docker/UFW policy before restarting workloads."
  exit 0
fi

if [ ! -s "$SUBNET_FILE" ]; then
  discover_subnets
fi
validate_subnets

if [ "$MODE" = plan ]; then
  echo "Mode: plan; no firewall mutation executed."
  echo "Chain: $CHAIN via DOCKER-USER"
  while IFS= read -r subnet; do
    echo "Workload source: $subnet"
  done < "$SUBNET_FILE"
  printf '%s\n' "$BLOCKED_DESTINATIONS" | while IFS= read -r destination; do
    if [ -n "$destination" ]; then
      echo "Deny destination: $destination"
    fi
  done
  echo "Allow: remaining public IPv4 destinations; DNS remains Docker embedded DNS."
  exit 0
fi

require_command iptables
iptables -w -S DOCKER-USER >/dev/null 2>&1 || { echo "DOCKER-USER chain is unavailable; verify Docker firewall backend before rollout" >&2; exit 1; }

verify_rules() {
  iptables -w -C DOCKER-USER -j "$CHAIN" >/dev/null
  while IFS= read -r subnet; do
    printf '%s\n' "$BLOCKED_DESTINATIONS" | while IFS= read -r destination; do
      [ -n "$destination" ] || continue
      iptables -w -C "$CHAIN" -s "$subnet" -d "$destination" -j REJECT --reject-with icmp-admin-prohibited >/dev/null
    done
    iptables -w -C "$CHAIN" -s "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN >/dev/null
    iptables -w -C "$CHAIN" -s "$subnet" -j RETURN >/dev/null
  done < "$SUBNET_FILE"
}

if [ "$MODE" = verify ]; then
  verify_rules
  echo "Workload egress firewall verified for $(wc -l < "$SUBNET_FILE") subnet(s)."
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "--apply requires root" >&2; exit 1; }
[ "$CONFIRM" = "APPLY-WORKLOAD-EGRESS-FIREWALL" ] || { echo "Apply requires --confirm APPLY-WORKLOAD-EGRESS-FIREWALL" >&2; exit 1; }

iptables -w -N "$CHAIN" >/dev/null 2>&1 || true
iptables -w -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1 || iptables -w -I DOCKER-USER 1 -j "$CHAIN"
iptables -w -F "$CHAIN"
while IFS= read -r subnet; do
  printf '%s\n' "$BLOCKED_DESTINATIONS" | while IFS= read -r destination; do
    [ -n "$destination" ] || continue
    iptables -w -A "$CHAIN" -s "$subnet" -d "$destination" -j REJECT --reject-with icmp-admin-prohibited
  done
  iptables -w -A "$CHAIN" -s "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -w -A "$CHAIN" -s "$subnet" -j RETURN
done < "$SUBNET_FILE"
iptables -w -A "$CHAIN" -j RETURN

verify_rules
echo "Workload egress firewall applied and verified for $(wc -l < "$SUBNET_FILE") subnet(s)."
