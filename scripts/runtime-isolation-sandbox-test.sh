#!/usr/bin/env sh
set -eu

NODE_IMAGE=${NODE_IMAGE:-node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606}
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUN_ID="platform-t13-sandbox-$$"
CONTROL_NETWORK="${RUN_ID}-control"
DENIED_NETWORK="${RUN_ID}-denied"
GATEWAY="${RUN_ID}-gateway"
CONTROL="${RUN_ID}-control-plane"
CPU_STRESS="${RUN_ID}-cpu"
MEMORY_STRESS="${RUN_ID}-memory"
LIVE_BEFORE=$(mktemp)
LIVE_AFTER=$(mktemp)
TOKEN_FILE=$(mktemp)
GATEWAY_TOKEN="runtime-isolation-gateway-token-0123456789abcdef"
printf '%s\n' "$GATEWAY_TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"

platform_inventory() {
  docker ps --filter label=com.docker.compose.project=platform_infra_vps --format '{{.ID}} {{.Names}}' | sort
}

cleanup() {
  docker rm -f "$MEMORY_STRESS" "$CPU_STRESS" "$CONTROL" "$GATEWAY" >/dev/null 2>&1 || true
  docker network rm "$DENIED_NETWORK" "$CONTROL_NETWORK" >/dev/null 2>&1 || true
  rm -f "$LIVE_BEFORE" "$LIVE_AFTER" "$TOKEN_FILE"
}
trap cleanup EXIT INT TERM

platform_inventory > "$LIVE_BEFORE"
docker network create --internal "$CONTROL_NETWORK" >/dev/null
docker network create --internal "$DENIED_NETWORK" >/dev/null

docker run -d \
  --name "$GATEWAY" \
  --network "$CONTROL_NETWORK" \
  --network-alias docker-operation-gateway \
  --read-only \
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cpus 0.50 \
  --cpu-shares 1024 \
  --memory 128m \
  --memory-reservation 32m \
  --pids-limit 64 \
  --ulimit nofile=16384:16384 \
  --blkio-weight 700 \
  --security-opt no-new-privileges:true \
  -e DOCKER_GATEWAY_TOKEN_FILE=/run/secrets/docker_gateway_token \
  -e PLATFORM_INFRA_ROOT=/infra \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$ROOT_DIR:/infra:ro" \
  -v "$TOKEN_FILE:/run/secrets/docker_gateway_token:ro" \
  "$NODE_IMAGE" node /infra/scripts/docker-operation-gateway.mjs >/dev/null

docker run -d \
  --name "$CONTROL" \
  --network "$CONTROL_NETWORK" \
  --network-alias control-plane \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cpus 0.50 \
  --cpu-shares 1024 \
  --memory 128m \
  --memory-reservation 32m \
  --pids-limit 64 \
  --ulimit nofile=4096:4096 \
  --blkio-weight 700 \
  --security-opt no-new-privileges:true \
  "$NODE_IMAGE" \
  node -e 'require("node:http").createServer((_,r)=>{r.end("ok")}).listen(8080,"0.0.0.0")' >/dev/null

sleep 2

docker run --rm -i --network "$CONTROL_NETWORK" -e GATEWAY_TOKEN="$GATEWAY_TOKEN" "$NODE_IMAGE" node - <<'NODE'
const endpoints = [
  ["/healthz", 200],
  ["/_ping", 404],
  ["/v1.51/version", 404],
  ["/v1.51/containers/json", 404],
  ["/v1.51/secrets", 404],
];
for (const [path, expected] of endpoints) {
  const response = await fetch(`http://docker-operation-gateway:8787${path}`);
  if (response.status !== expected) throw new Error(`${path}: expected ${expected}, received ${response.status}`);
}
const response = await fetch("http://docker-operation-gateway:8787/v1/operations", {
  method: "POST",
  headers: { Authorization: `Bearer ${process.env.GATEWAY_TOKEN}`, "Content-Type": "application/json" },
  body: JSON.stringify({ version: 1, requestId: "123e4567-e89b-42d3-a456-426614174000", issuedAt: new Date().toISOString(), operation: "container-create", parameters: {} }),
});
if (response.status !== 403) throw new Error(`forbidden operation expected 403, received ${response.status}`);
const control = await fetch("http://control-plane:8080/");
if (control.status !== 200 || await control.text() !== "ok") throw new Error("control-plane probe failed");
NODE

if docker run --rm --network "$DENIED_NETWORK" "$NODE_IMAGE" node -e 'fetch("http://docker-operation-gateway:8787/healthz",{signal:AbortSignal.timeout(1000)}).then(()=>process.exit(0)).catch(()=>process.exit(1))' >/dev/null 2>&1; then
  echo "Denied network unexpectedly reached the typed Docker gateway." >&2
  exit 1
fi

docker run -d \
  --name "$CPU_STRESS" \
  --network "$CONTROL_NETWORK" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cpus 0.25 \
  --cpu-shares 256 \
  --memory 96m \
  --memory-reservation 32m \
  --memory-swap 96m \
  --pids-limit 32 \
  --ulimit nofile=256:256 \
  --blkio-weight 300 \
  --security-opt no-new-privileges:true \
  "$NODE_IMAGE" \
  node -e 'const end=Date.now()+5000; while(Date.now()<end){Math.sqrt(Math.random())}' >/dev/null

docker inspect "$CPU_STRESS" --format '{{json .HostConfig}}' | jq -e '
  .ReadonlyRootfs == true and
  .Memory == 100663296 and
  .MemoryReservation == 33554432 and
  .NanoCpus == 250000000 and
  .CpuShares == 256 and
  .PidsLimit == 32 and
  .BlkioWeight == 300 and
  any(.Ulimits[]; .Name == "nofile" and .Soft == 256 and .Hard == 256)
' >/dev/null

if docker exec "$CPU_STRESS" sh -ec 'test ! -e /var/run/docker.sock; test ! -e /infra; test ! -e /backups; test ! -e /var/www/projects' >/dev/null 2>&1; then
  :
else
  echo "Stress workload escaped the mount allowlist." >&2
  exit 1
fi

probe=0
while [ "$probe" -lt 5 ]; do
  docker run --rm --network "$CONTROL_NETWORK" "$NODE_IMAGE" node -e 'fetch("http://control-plane:8080/",{signal:AbortSignal.timeout(1000)}).then(async r=>process.exit(r.status===200&&(await r.text())==="ok"?0:1)).catch(()=>process.exit(1))'
  probe=$((probe + 1))
done
docker wait "$CPU_STRESS" >/dev/null

docker run -d \
  --name "$MEMORY_STRESS" \
  --network "$CONTROL_NETWORK" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cpus 0.25 \
  --cpu-shares 256 \
  --memory 96m \
  --memory-reservation 32m \
  --memory-swap 96m \
  --pids-limit 32 \
  --ulimit nofile=256:256 \
  --blkio-weight 300 \
  --security-opt no-new-privileges:true \
  "$NODE_IMAGE" \
  node -e 'const blocks=[]; setInterval(()=>blocks.push(Buffer.alloc(16*1024*1024,1)),10)' >/dev/null

set +e
timeout 20 docker wait "$MEMORY_STRESS" >/dev/null
wait_status=$?
set -e
if [ "$wait_status" -ne 0 ]; then
  echo "Bounded memory stress did not terminate within 20 seconds." >&2
  exit 1
fi
if [ "$(docker inspect --format '{{.State.OOMKilled}}' "$MEMORY_STRESS")" != "true" ]; then
  echo "Memory stress was not contained by the cgroup OOM boundary." >&2
  exit 1
fi

docker run --rm --network "$CONTROL_NETWORK" "$NODE_IMAGE" node -e 'fetch("http://control-plane:8080/",{signal:AbortSignal.timeout(1000)}).then(async r=>process.exit(r.status===200&&(await r.text())==="ok"?0:1)).catch(()=>process.exit(1))'

platform_inventory > "$LIVE_AFTER"
diff -u "$LIVE_BEFORE" "$LIVE_AFTER" >/dev/null

printf '%s\n' "Runtime isolation sandbox passed: typed gateway deny boundary, read-only mount boundary, CPU/RAM/PID/FD/I/O controls, bounded OOM and control-plane continuity."
