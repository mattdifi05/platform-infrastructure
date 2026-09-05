#!/usr/bin/env bash
# Real kernel/packet proof. All addresses and services exist only in temporary
# network namespaces: no host firewall, Docker network, or Internet traffic.
set -Eeuo pipefail
umask 077

script_path=$(readlink -f -- "$0")
manifest=${1:?root-owned admitted test manifest required}
helper="$(dirname "$script_path")/local-private-egress-firewall.sh"
test "$(id -u)" = 0
for command_name in unshare nsenter ip curl python3 jq nft readlink; do
  command -v "$command_name" >/dev/null
done
if test "${2:-}" != --inside; then
  exec unshare --net -- "$script_path" "$manifest" --inside
fi
test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)"
test "$(jq -r '.applications | length' "$manifest")" = 1
test "$(jq -r '.applications[0].owner' "$manifest")" = fiplatform
test "$(jq -r '.applications[0].network.bridgeName' "$manifest")" = lpe-fiplatform
test "$(jq -r '.applications[0].network.subnet' "$manifest")" = 172.31.240.0/28
test "$(ip -o link show | wc -l)" = 1

owned_pids=()
cleanup() {
  failure=$?
  trap - EXIT HUP INT TERM
  for owned_pid in "${owned_pids[@]}"; do
    kill "$owned_pid" 2>/dev/null || true
  done
  for owned_pid in "${owned_pids[@]}"; do
    wait "$owned_pid" 2>/dev/null || true
  done
  exit "$failure"
}
trap cleanup EXIT HUP INT TERM

unshare --net -- sleep 600 &
client_pid=$!
owned_pids+=("$client_pid")
unshare --net -- sleep 600 &
fixture_pid=$!
owned_pids+=("$fixture_pid")
for child_pid in "$client_pid" "$fixture_pid"; do
  ready=0
  for attempt in {1..50}; do
    if test -e "/proc/$child_pid/ns/net" && test "$(readlink "/proc/$child_pid/ns/net")" != "$(readlink /proc/self/ns/net)"; then ready=1; break; fi
    sleep .02
  done
  test "$ready" = 1
done
client() { nsenter -t "$client_pid" -n -- "$@"; }
fixture() { nsenter -t "$fixture_pid" -n -- "$@"; }

ip link set lo up
ip link add lpe-fiplatform type bridge
ip address add 172.31.240.1/28 dev lpe-fiplatform
ip -6 address add fd00:24::1/64 dev lpe-fiplatform nodad
ip link set lpe-fiplatform up
ip link add client-root type veth peer name client-ns
ip link set client-root master lpe-fiplatform
ip link set client-root up
ip link set client-ns netns "$client_pid"
client ip link set lo up
client ip link set client-ns up
client ip address add 172.31.240.2/28 dev client-ns
client ip -6 address add fd00:24::2/64 dev client-ns nodad
client ip route add default via 172.31.240.1
client ip -6 route add default via fd00:24::1

ip link add wan-root type veth peer name wan-ns
ip link set wan-ns netns "$fixture_pid"
ip address add 8.8.8.1/24 dev wan-root
ip -6 address add fd00:42::1/64 dev wan-root nodad
ip link set wan-root up
fixture ip link set lo up
fixture ip link set wan-ns up
fixture ip address add 8.8.8.2/24 dev wan-ns
fixture ip -6 address add fd00:42::2/64 dev wan-ns nodad
fixture ip route add default via 8.8.8.1
fixture ip -6 route add default via fd00:42::1
for address in 10.99.0.2 169.254.169.254 100.64.0.2; do
  fixture ip address add "$address/32" dev lo
  ip route add "$address/32" via 8.8.8.2
done
fixture ip -6 address add 2001:4860:4860::8888/128 dev lo nodad
ip -6 route add 2001:4860:4860::8888/128 via fd00:42::2
ip address add 9.9.9.9/32 dev lo
client ip address add 172.31.241.2/32 dev client-ns
ip route add 172.31.241.2/32 dev lpe-fiplatform

# Existing private path is deliberately outside the new egress interface.
ip link add compat-root type veth peer name compat-ns
ip link set compat-ns netns "$client_pid"
ip address add 172.30.200.1/24 dev compat-root
ip link set compat-root up
client ip address add 172.30.200.2/24 dev compat-ns
client ip link set compat-ns up
sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf.lpe-fiplatform.rp_filter=0

# The tiny TCP responder opens no files and emits no user or runtime data.
responder='import socket,sys
s=socket.socket(socket.AF_INET6 if sys.argv[1]=="6" else socket.AF_INET)
if sys.argv[1]=="6": s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("::" if sys.argv[1]=="6" else "0.0.0.0",8080));s.listen(32)
while True:
 c,a=s.accept();c.recv(4096);c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");c.close()'
fixture python3 -c "$responder" 4 >/dev/null 2>&1 &
owned_pids+=("$!")
fixture python3 -c "$responder" 6 >/dev/null 2>&1 &
owned_pids+=("$!")
python3 -c "$responder" 4 >/dev/null 2>&1 &
owned_pids+=("$!")

# Post-DNAT forwarding must be classified by its real private destination.
nft -f - <<'NFT'
table ip isolated_fixture_nat {
 chain prerouting {
  type nat hook prerouting priority -100; policy accept;
  ip daddr 9.8.7.6 tcp dport 8080 dnat to 10.99.0.2:8080
 }
}
NFT

probe() { client curl --silent --show-error --noproxy '*' --connect-timeout 1 --max-time 2 "$@"; }
reachable() {
  name=$1; shift
  if ! response=$(probe "$@" 2>&1) || test "$response" != OK; then
    printf 'FAIL reachable %s: %s\n' "$name" "$response" >&2
    if test "$name" = baseline-ipv6; then
      client ip -6 route show
      ip -6 route show
      fixture ip -6 route show
      fixture ss -tln
      client ping -6 -c 1 -W 1 fd00:24::1 || true
      ping -6 -c 1 -W 1 fd00:42::2 || true
      client ping -6 -c 1 -W 1 2001:4860:4860::8888 || true
    fi
    return 1
  fi
  printf 'PASS reachable %s\n' "$name"
}
blocked() {
  name=$1; shift
  if probe "$@" >/dev/null 2>&1; then
    printf 'FAIL unexpectedly reachable %s\n' "$name" >&2
    exit 1
  fi
  printf 'PASS blocked %s\n' "$name"
}

ready=0
for attempt in {1..20}; do
  # New IPv6 veth neighbours may need their initial discovery cycle. Require
  # actual end-to-end readiness in both families before scoring the controls.
  if probe http://8.8.8.2:8080 >/dev/null 2>&1 \
    && probe 'http://[2001:4860:4860::8888]:8080' >/dev/null 2>&1; then ready=1; break; fi
  sleep .02
done
test "$ready" = 1
reachable baseline-public http://8.8.8.2:8080
reachable baseline-private http://10.99.0.2:8080
reachable baseline-metadata http://169.254.169.254:8080
reachable baseline-vpn http://100.64.0.2:8080
reachable baseline-host-public http://9.9.9.9:8080
reachable baseline-host-gateway http://172.31.240.1:8080
reachable baseline-published-dnat http://9.8.7.6:8080
reachable baseline-ipv6 'http://[2001:4860:4860::8888]:8080'
reachable baseline-spoof --interface 172.31.241.2 http://8.8.8.2:8080
reachable baseline-existing-private http://172.30.200.1:8080

"$helper" --apply --manifest "$manifest" --confirm APPLY-LOCAL-PRIVATE-EGRESS
"$helper" --verify --manifest "$manifest"
reachable public-with-return-traffic http://8.8.8.2:8080
blocked private http://10.99.0.2:8080
blocked metadata http://169.254.169.254:8080
blocked vpn http://100.64.0.2:8080
blocked host-public http://9.9.9.9:8080
blocked host-gateway http://172.31.240.1:8080
blocked published-dnat http://9.8.7.6:8080
blocked ipv6 'http://[2001:4860:4860::8888]:8080'
blocked spoof --interface 172.31.241.2 http://8.8.8.2:8080
reachable existing-private-path http://172.30.200.1:8080
printf '%s\n' 'ISOLATED_KERNEL_PACKET_PROOF_PASS=1'
