import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vpsWaf = read("compose.vps-waf.yaml");
const vpsEnv = read(".env.vps.example");
const edgeTraefik = read("traefik/traefik.edge-http.yml");
const networks = read("compose.networks.yaml");
const networkPolicy = read("scripts/network-segmentation-policy.mjs");

test("FG-053 plaintext edge traffic redirects and cannot spoof forwarded HTTPS", () => {
  const waf = serviceBlock(vpsWaf, "waf");
  const traefik = serviceBlock(vpsWaf, "traefik");
  assert.match(waf, /NGINX_ALWAYS_TLS_REDIRECT: "on"/);
  assert.match(waf, /NGINX_X_FORWARDED_PROTO: "https"/);
  assert.doesNotMatch(waf, /NGINX_(?:ALWAYS_TLS_REDIRECT|X_FORWARDED_PROTO):\s*\$\{/);
  assert.match(waf, /0\.0\.0\.0:80}:8080/);
  assert.match(waf, /0\.0\.0\.0:443}:8443/);
  assert.match(traefik, /ports: !override \[\]/);
  assert.doesNotMatch(vpsEnv, /^WAF_NGINX_ALWAYS_TLS_REDIRECT=off$/m);
  assert.doesNotMatch(edgeTraefik, /forwardedHeaders:\s*[\s\S]*insecure:\s*true/);
});

test("FG-053 only WAF and Traefik can inhabit the TLS-termination edge zone", () => {
  assert.match(serviceBlock(networks, "waf"), /networks: !override\n\s+- platform_edge/);
  assert.match(serviceBlock(networks, "traefik"), /\n\s+- platform_edge/);
  assert.match(networkPolicy, /members-platform-edge[\s\S]*\["traefik", "waf"\]/);
});

function read(name) {
  return fs.readFileSync(path.join(root, name), "utf8");
}

function serviceBlock(source, name) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing service ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n  [a-zA-Z0-9][a-zA-Z0-9_-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}
