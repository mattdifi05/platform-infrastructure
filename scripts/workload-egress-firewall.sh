#!/usr/bin/env sh
set -eu

MODE=plan
CONFIRM=""
NETWORK_PREFIX="${PLATFORM_NETWORK_PREFIX:-platform_infra_vps}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCK=""
PROJECT_NAME=""
CHAIN=PLATFORM-WORKLOAD-EGRESS
SUBNET_FILE=$(mktemp)
cleanup() {
  rm -f "$SUBNET_FILE"
}
trap cleanup EXIT HUP INT TERM

usage() {
  cat <<'EOF'
Usage: workload-egress-firewall.sh [--plan|--apply|--verify|--rollback] --lock ABSOLUTE_PATH --project-name NAME [--subnet CIDR] [--confirm TOKEN]

Default mode is plan. Apply reads the exact egress-network inventory from one
verified hosted workload lock and blocks its IPv4 subnets to private, loopback,
link-local/metadata, CGNAT and reserved destinations through DOCKER-USER.

--subnet is accepted only for isolated plan evidence. Apply and verify reject
caller-supplied networks/subnets and require the verified lock inventory.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --verify) MODE=verify ;;
    --rollback) MODE=rollback ;;
    --lock)
      shift
      LOCK="${1:?Missing value for --lock}"
      ;;
    --project-name)
      shift
      PROJECT_NAME="${1:?Missing value for --project-name}"
      ;;
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

load_locked_egress_subnets() {
  require_command docker
  require_command jq
  case "$LOCK" in
    /*) ;;
    *) echo "--lock must be an absolute path" >&2; exit 2 ;;
  esac
  case "$LOCK" in *[!A-Za-z0-9_./-]*|*//*|*/../*|*/..) echo "Invalid --lock path" >&2; exit 2 ;; esac
  [ -f "$LOCK" ] || { echo "Hosted workload lock does not exist: $LOCK" >&2; exit 1; }
  case "$PROJECT_NAME" in ''|*[!a-z0-9_-]* ) echo "Invalid --project-name" >&2; exit 2 ;; esac
  activation_bundle=$(sh "$SCRIPT_DIR/hosted-workload-lock.sh" "$LOCK" activation-bundle)
  printf '%s' "$activation_bundle" | jq -e --arg projectName "$PROJECT_NAME" '
    .projectName == $projectName
    and (.networkRecords | type == "array")
    and all(.networkRecords[];
      (.workloadId | type == "string")
      and (.logicalName | type == "string")
      and (.physicalName == ($projectName + "_" + .logicalName))
    )
    and all(.networkRecords[] | select(.logicalName | endswith("_egress")); .logicalName == ((.workloadId | gsub("-"; "_")) + "_egress"))
  ' >/dev/null || { echo "Hosted workload egress inventory is invalid" >&2; exit 1; }
  egress_records=$(printf '%s' "$activation_bundle" | jq -r '.networkRecords[] | select(.logicalName | endswith("_egress")) | [.logicalName, .physicalName] | @tsv')
  while IFS="$(printf '\t')" read -r logical_name physical_name; do
    [ -n "$physical_name" ] || continue
    inspection=$(docker network inspect "$physical_name") || {
      echo "Locked workload egress network is missing: $physical_name" >&2
      exit 1
    }
    printf '%s' "$inspection" | jq -e --arg physicalName "$physical_name" --arg projectName "$PROJECT_NAME" --arg logicalName "$logical_name" '
      type == "array"
      and length == 1
      and .[0].Name == $physicalName
      and .[0].EnableIPv6 == false
      and .[0].Labels["com.docker.compose.project"] == $projectName
      and .[0].Labels["com.docker.compose.network"] == $logicalName
      and (.[0].IPAM.Config | type == "array")
      and ([.[0].IPAM.Config[].Subnet | select(type == "string" and (contains(":") | not))] | length > 0)
    ' >/dev/null || { echo "Locked workload egress network identity/IPAM is invalid: $physical_name" >&2; exit 1; }
    printf '%s' "$inspection" | jq -r '.[0].IPAM.Config[].Subnet | select(type == "string" and (contains(":") | not))' >> "$SUBNET_FILE"
  done <<EOF
$egress_records
EOF
}

validate_subnets() {
  sort -u "$SUBNET_FILE" -o "$SUBNET_FILE"
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

if [ ! -s "$SUBNET_FILE" ] && [ "$MODE" != rollback ]; then
  load_locked_egress_subnets
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
  expected_rules=1
  blocked_rule_count=$(printf '%s\n' "$BLOCKED_DESTINATIONS" | awk 'NF { count += 1 } END { print count + 0 }')
  while IFS= read -r subnet; do
    printf '%s\n' "$BLOCKED_DESTINATIONS" | while IFS= read -r destination; do
      [ -n "$destination" ] || continue
      iptables -w -C "$CHAIN" -s "$subnet" -d "$destination" -j REJECT --reject-with icmp-admin-prohibited >/dev/null
    done
    iptables -w -C "$CHAIN" -s "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN >/dev/null
    iptables -w -C "$CHAIN" -s "$subnet" -j RETURN >/dev/null
    expected_rules=$((expected_rules + blocked_rule_count + 2))
  done < "$SUBNET_FILE"
  iptables -w -C "$CHAIN" -j RETURN >/dev/null
  actual_rules=$(iptables -w -S "$CHAIN" | awk '$1 == "-A" { count += 1 } END { print count + 0 }')
  [ "$actual_rules" -eq "$expected_rules" ] || { echo "Workload egress firewall has stale or unexpected rules" >&2; exit 1; }
}

if [ "$MODE" = verify ]; then
  verify_rules
  echo "Workload egress firewall verified for $(awk 'END { print NR + 0 }' "$SUBNET_FILE") subnet(s)."
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "--apply requires root" >&2; exit 1; }
[ "$CONFIRM" = "APPLY-WORKLOAD-EGRESS-FIREWALL" ] || { echo "Apply requires --confirm APPLY-WORKLOAD-EGRESS-FIREWALL" >&2; exit 1; }

iptables -w -N "$CHAIN" >/dev/null 2>&1 || true
while iptables -w -C DOCKER-USER -j "$CHAIN" >/dev/null 2>&1; do
  iptables -w -D DOCKER-USER -j "$CHAIN"
done
iptables -w -I DOCKER-USER 1 -j "$CHAIN"
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
echo "Workload egress firewall applied and verified for $(awk 'END { print NR + 0 }' "$SUBNET_FILE") subnet(s)."
