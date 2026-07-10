#!/usr/bin/env sh
set -eu

NODE_IMAGE="${NODE_IMAGE:-node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606}"
SUFFIX="t12-$$-$(date -u +%s)"
INGRESS_ONE="${SUFFIX}-ingress-one"
DATA_ONE="${SUFFIX}-data-one"
EGRESS_ONE="${SUFFIX}-egress-one"
INGRESS_TWO="${SUFFIX}-ingress-two"
OBSERVABILITY="${SUFFIX}-observability"
ROUTER="${SUFFIX}-router"
APP_ONE="${SUFFIX}-app-one"
APP_TWO="${SUFFIX}-app-two"
DATABASE="${SUFFIX}-database"
METRICS="${SUFFIX}-metrics"

cleanup() {
  docker rm -f "$ROUTER" "$APP_ONE" "$APP_TWO" "$DATABASE" "$METRICS" >/dev/null 2>&1 || true
  docker network rm "$INGRESS_ONE" "$DATA_ONE" "$EGRESS_ONE" "$INGRESS_TWO" "$OBSERVABILITY" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

for network in "$INGRESS_ONE" "$DATA_ONE" "$INGRESS_TWO" "$OBSERVABILITY"; do
  docker network create --internal "$network" >/dev/null
done
docker network create "$EGRESS_ONE" >/dev/null

server_command='const http=require("node:http");const name=process.env.NAME;http.createServer((req,res)=>{res.end(name)}).listen(8080,"0.0.0.0");setInterval(()=>{},60000)'
docker run -d --name "$ROUTER" --network "$INGRESS_ONE" -e NAME=router "$NODE_IMAGE" node -e "$server_command" >/dev/null
docker run -d --name "$APP_ONE" --network "$INGRESS_ONE" -e NAME=app-one "$NODE_IMAGE" node -e "$server_command" >/dev/null
docker network connect "$DATA_ONE" "$APP_ONE"
docker network connect "$EGRESS_ONE" "$APP_ONE"
docker run -d --name "$DATABASE" --network "$DATA_ONE" -e NAME=database "$NODE_IMAGE" node -e "$server_command" >/dev/null
docker run -d --name "$APP_TWO" --network "$INGRESS_TWO" -e NAME=app-two "$NODE_IMAGE" node -e "$server_command" >/dev/null
docker run -d --name "$METRICS" --network "$OBSERVABILITY" -e NAME=metrics "$NODE_IMAGE" node -e "$server_command" >/dev/null

probe() {
  container="$1"
  target="$2"
  expected="$3"
  docker exec "$container" node -e '
    const [target, expected] = process.argv.slice(1);
    fetch(`http://${target}:8080/`, { signal: AbortSignal.timeout(1500) })
      .then(async (response) => {
        const body = await response.text();
        process.exit(response.ok && body === expected ? 0 : 1);
      })
      .catch(() => process.exit(1));
  ' "$target" "$expected"
}

deny() {
  container="$1"
  target="$2"
  if docker exec "$container" node -e '
    const target = process.argv[1];
    fetch(`http://${target}:8080/`, { signal: AbortSignal.timeout(800) })
      .then(() => process.exit(0))
      .catch(() => process.exit(1));
  ' "$target" >/dev/null 2>&1; then
    echo "Unexpected network path: $container -> $target" >&2
    exit 1
  fi
}

attempt=0
until probe "$ROUTER" "$APP_ONE" app-one >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 20 ] || { echo "sandbox services did not become ready" >&2; exit 1; }
  sleep 1
done

probe "$ROUTER" "$APP_ONE" app-one
probe "$APP_ONE" "$DATABASE" database
deny "$ROUTER" "$DATABASE"
deny "$ROUTER" "$METRICS"
deny "$APP_ONE" "$METRICS"
deny "$APP_ONE" "$APP_TWO"
deny "$APP_TWO" "$DATABASE"

router_networks=$(docker inspect "$ROUTER" --format '{{json .NetworkSettings.Networks}}' | jq 'keys | sort')
app_networks=$(docker inspect "$APP_ONE" --format '{{json .NetworkSettings.Networks}}' | jq 'keys | sort')
printf '%s' "$router_networks" | jq -e --arg ingress "$INGRESS_ONE" '. == [$ingress]' >/dev/null
printf '%s' "$app_networks" | jq -e --arg data "$DATA_ONE" --arg egress "$EGRESS_ONE" --arg ingress "$INGRESS_ONE" '. == ([$data, $egress, $ingress] | sort)' >/dev/null

firewall_plan=$(sh "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/workload-egress-firewall.sh" --plan --subnet 172.30.10.0/24)
printf '%s\n' "$firewall_plan" | grep -q 'Mode: plan; no firewall mutation executed.'
printf '%s\n' "$firewall_plan" | grep -q 'Deny destination: 169.254.0.0/16'
printf '%s\n' "$firewall_plan" | grep -q 'Deny destination: 10.0.0.0/8'
printf '%s\n' "$firewall_plan" | grep -q 'Deny destination: 192.168.0.0/16'
if sh "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/workload-egress-firewall.sh" --apply --subnet 172.30.10.0/24 >/dev/null 2>&1; then
  echo "Firewall apply unexpectedly accepted a caller-supplied subnet" >&2
  exit 1
fi

echo "Network segmentation sandbox passed: intended ingress/data paths work and cross-app/control-plane paths are denied."
