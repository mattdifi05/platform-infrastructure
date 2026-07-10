#!/usr/bin/env sh
set -eu

NODE_IMAGE="${NODE_IMAGE:-node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606}"
TMP=$(mktemp -d)
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

cat > "$TMP/package.json" <<'JSON'
{
  "name": "daemon-isolation-fixture",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "preinstall": "node probe.mjs"
  }
}
JSON
cat > "$TMP/probe.mjs" <<'JS'
import fs from "node:fs";
import net from "node:net";

if (fs.existsSync("/var/run/docker.sock")) process.exit(20);
const socket = net.createConnection({ path: "/var/run/docker.sock" });
socket.once("connect", () => process.exit(21));
socket.once("error", () => process.exit(0));
setTimeout(() => process.exit(0), 500).unref();
JS
chmod 0755 "$TMP"
chmod 0644 "$TMP/package.json" "$TMP/probe.mjs"

docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --tmpfs /workspace:rw,exec,nosuid,nodev,size=64m \
  -v "$TMP:/fixture:ro" \
  -w /workspace \
  "$NODE_IMAGE" \
  sh -lc 'cp /fixture/package.json /fixture/probe.mjs . && npm install --ignore-scripts=false --no-audit --no-fund >/dev/null'

echo "Lifecycle sandbox passed: an install hook cannot find or connect to the Docker daemon."
