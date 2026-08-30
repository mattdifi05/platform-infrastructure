import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const baseCompose = read("compose.yaml");
const prodCompose = read("compose.prod.yaml");
const vpsCompose = read("compose.vps.yaml");
const vpsWaf = read("compose.vps-waf.yaml");
const vpsEnv = read(".env.vps.example");
const edgeTraefik = read("traefik/traefik.edge-http.yml");
const networks = read("compose.networks.yaml");
const networkPolicy = read("scripts/network-segmentation-policy.mjs");
const middlewares = read("traefik/dynamic/middlewares.yml");
const vpsWafRules = read("waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf");
const trustedProxySnapshot = JSON.parse(read("cloudflare/trusted-proxy-cidrs.json"));

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
  assert.match(serviceBlock(networks, "waf"), /networks: !override\n\s+platform_edge:/);
  assert.match(serviceBlock(networks, "traefik"), /\n\s+platform_edge:/);
  assert.match(networkPolicy, /members-platform-edge[\s\S]*\["traefik", "waf"\]/);
});

test("FG-060 Traefik trusts forwarded identity only from the fixed WAF peer", () => {
  assert.match(edgeTraefik, /forwardedHeaders:\n\s+trustedIPs:\n\s+- "172\.30\.250\.2\/32"/);
  assert.doesNotMatch(edgeTraefik, /forwardedHeaders:\s*[\s\S]*insecure:\s*true/);
  assert.match(serviceBlock(networks, "waf"), /platform_edge:\n\s+ipv4_address: 172\.30\.250\.2/);
  assert.match(serviceBlock(networks, "traefik"), /platform_edge:\n\s+ipv4_address: 172\.30\.250\.3/);
  assert.match(networks, /platform_edge:[\s\S]*subnet: 172\.30\.250\.0\/29/);
});

test("FG-060 rate key skips only the pinned provider hops and ignores spoofed left entries", () => {
  const block = middlewareBlock(middlewares, "enterprise-rate-limit");
  assert.match(block, /sourceCriterion:\n\s+ipStrategy:\n\s+excludedIPs:/);
  assert.doesNotMatch(block, /\n\s+depth:/);
  const configured = [...block.matchAll(/^\s+- "?([^"\s]+\/\d+)"?$/gm)].map((match) => match[1]).sort();
  const expected = [...trustedProxySnapshot.ipv4, ...trustedProxySnapshot.ipv6].sort();
  assert.deepEqual(configured, expected);

  const direct = selectClientIp(["198.51.100.99", "203.0.113.7"], trustedProxySnapshot.ipv4);
  const throughCloudflareA = selectClientIp(["203.0.113.10", "198.41.128.42"], trustedProxySnapshot.ipv4);
  const throughCloudflareB = selectClientIp(["203.0.113.11", "198.41.128.43"], trustedProxySnapshot.ipv4);
  assert.equal(direct, "203.0.113.7");
  assert.equal(throughCloudflareA, "203.0.113.10");
  assert.equal(throughCloudflareB, "203.0.113.11");
  assert.notEqual(throughCloudflareA, throughCloudflareB);
});

test("OIDC authorization redirect_uri exemption is exact and target-scoped", () => {
  assert.match(vpsWafRules, /REQUEST_HEADERS:Host "@rx \(\?i\)\^auth\\\.platform-infrastructure\\\.com\$"/);
  assert.match(vpsWafRules, /id:1000107,phase:1,pass,nolog,[^\n"]*chain/);
  assert.match(vpsWafRules, /REQUEST_URI "@rx \^\/realms\/platform\/protocol\/openid-connect\/auth/);
  assert.match(vpsWafRules, /ctl:ruleRemoveTargetById=931130;ARGS:redirect_uri/);
  assert.doesNotMatch(
    vpsWafRules,
    /ctl:ruleRemoveTargetById=931130(?!;ARGS:redirect_uri)/,
    "the CRS RFI rule must not be removed broadly",
  );
});

test("FG-060 origin firewall refuses provider drift before applying trusted ranges", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "trusted-proxy-check-"));
  const ipv4Path = path.join(temp, "ips-v4");
  const ipv6Path = path.join(temp, "ips-v6");
  try {
    fs.writeFileSync(ipv4Path, `${trustedProxySnapshot.ipv4.join("\n")}\n`);
    fs.writeFileSync(ipv6Path, `${trustedProxySnapshot.ipv6.join("\n")}\n`);
    assert.equal(runTrustedProxyCheck(ipv4Path, ipv6Path).status, 0);

    fs.appendFileSync(ipv4Path, "203.0.113.0/24\n");
    const extraRange = runTrustedProxyCheck(ipv4Path, ipv6Path);
    assert.notEqual(extraRange.status, 0);
    assert.match(extraRange.stderr, /ipv4 ranges differ/);

    fs.writeFileSync(ipv4Path, `${trustedProxySnapshot.ipv4.slice(1).join("\n")}\n`);
    const missingRange = runTrustedProxyCheck(ipv4Path, ipv6Path);
    assert.notEqual(missingRange.status, 0);
    assert.match(missingRange.stderr, /ipv4 ranges differ/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("FG-060 rejects identical malformed IPv4 CIDRs in provider and snapshot", () => {
  const fixture = trustedProxyFixture({ ipv4: ["198.41.128.0/17", "999.999.999.999/24"], ipv6: ["2606:4700::/32"] });
  try {
    const result = runTrustedProxyCheck(fixture.ipv4Path, fixture.ipv6Path, fixture.snapshotPath);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /invalid.*ipv4|ipv4.*invalid/i);
  } finally {
    fixture.cleanup();
  }
});

test("FG-060 rejects identical malformed IPv6 CIDRs in provider and snapshot", () => {
  const fixture = trustedProxyFixture({ ipv4: ["198.41.128.0/17"], ipv6: ["2606:4700::/32", "2606:4700::gg/32"] });
  try {
    const result = runTrustedProxyCheck(fixture.ipv4Path, fixture.ipv6Path, fixture.snapshotPath);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /invalid.*ipv6|ipv6.*invalid/i);
  } finally {
    fixture.cleanup();
  }
});

test("FG-060 compares valid IPv6 CIDRs by canonical network semantics", () => {
  const fixture = trustedProxyFixture({
    ipv4: ["198.41.128.0/17"],
    ipv6: ["2606:4700:0000:0000:0000:0000:0000:0000/32"],
    providerIpv6: ["2606:4700::/32"],
  });
  try {
    assert.equal(runTrustedProxyCheck(fixture.ipv4Path, fixture.ipv6Path, fixture.snapshotPath).status, 0);
  } finally {
    fixture.cleanup();
  }
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

function middlewareBlock(source, name) {
  const marker = `\n    ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing middleware ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n    [a-zA-Z0-9][a-zA-Z0-9_-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

function selectClientIp(chain, trustedCidrs) {
  for (let index = chain.length - 1; index >= 0; index -= 1) {
    if (!trustedCidrs.some((cidr) => ipv4InCidr(chain[index], cidr))) return chain[index];
  }
  return "";
}

function ipv4InCidr(address, cidr) {
  if (address.includes(":") || cidr.includes(":")) return false;
  const [network, prefixText] = cidr.split("/");
  const prefix = Number(prefixText);
  const toInt = (value) => value.split(".").reduce((out, octet) => (out * 256 + Number(octet)) >>> 0, 0) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (toInt(address) & mask) === (toInt(network) & mask);
}

function runTrustedProxyCheck(ipv4Path, ipv6Path, snapshotPath = path.join(root, "cloudflare/trusted-proxy-cidrs.json")) {
  return spawnSync(
    path.join(root, "scripts/cloudflare-trusted-proxy-check.sh"),
    [snapshotPath, ipv4Path, ipv6Path],
    { encoding: "utf8" },
  );
}

function trustedProxyFixture({ ipv4, ipv6, providerIpv4 = ipv4, providerIpv6 = ipv6 }) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "trusted-proxy-cidr-"));
  const snapshotPath = path.join(temp, "snapshot.json");
  const ipv4Path = path.join(temp, "ips-v4");
  const ipv6Path = path.join(temp, "ips-v6");
  fs.writeFileSync(snapshotPath, `${JSON.stringify({ ipv4, ipv6 }, null, 2)}\n`);
  fs.writeFileSync(ipv4Path, `${providerIpv4.join("\n")}\n`);
  fs.writeFileSync(ipv6Path, `${providerIpv6.join("\n")}\n`);
  return {
    snapshotPath,
    ipv4Path,
    ipv6Path,
    cleanup: () => fs.rmSync(temp, { recursive: true, force: true }),
  };
}
