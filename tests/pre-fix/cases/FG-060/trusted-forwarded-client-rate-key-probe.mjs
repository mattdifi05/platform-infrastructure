#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const SOURCE_HASHES = new Map([
  ["traefik/dynamic/middlewares.yml", "79ae033e15398379b4fec860ff658091c9518f995a533a9ee78ee5b1e9d0a11b"],
  ["compose.vps-waf.yaml", "01635f0a117de50fd60aa95aa5b6bf42416aa0a39ffe606462e1a6a839c2f008"],
  ["compose.networks.yaml", "f6cfb3b3857c1fd85414fbd7dc29c78a5f96ca9e7d309d8849cbb3400f66d759"],
  ["compose.vps.yaml", "c8954158a542825fe276742d3b943818603c2cc764764da98fd81859de3f1415"],
  ["compose.runtime.yaml", "b7b546bbb8587b54d39a0a53d22db4f020afcc707c33338eee264c4407d30505"],
  ["traefik/dynamic/admin-routes.yml", "0c712f00c4ca5b35cc22ad66ac6bcbd7ad091f1cf82b66904b8124b8ddc1b931"],
  ["traefik/dynamic/project-routes.yml", "d3614e869d7ff64ab7ed8f54efbaea56666405d5fdcf4bef24095e1b6ee060e1"],
  ["traefik/traefik.edge-http.yml", "a36a40cfe8ad23c170d29c6e0e2f72ce0c72a99169d66b80b562436f232642ea"],
]);

class BurstProjection {
  constructor(capacity) {
    assert.ok(Number.isSafeInteger(capacity) && capacity > 0);
    this.capacity = capacity;
    this.remaining = new Map();
  }

  allow(key) {
    const remaining = this.remaining.get(key) ?? this.capacity;
    if (remaining === 0) return false;
    this.remaining.set(key, remaining - 1);
    return true;
  }
}

if (!process.argv[2]) {
  throw new Error("usage: trusted-forwarded-client-rate-key-probe.mjs /path/to/archived/source");
}

const sourceRoot = validateWrapperOwnedSource(process.argv[2]);
assert.equal(fs.existsSync(path.join(sourceRoot, ".git")), false, "source must be a Git archive without .git metadata");
for (const [relativePath, expected] of SOURCE_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected pre-fix source`);
}
console.log(`[PASS] exact pre-fix source fingerprints verified revision=${REVISION} tree=${TREE}`);

const middlewares = readSource("traefik/dynamic/middlewares.yml");
const vpsWaf = readSource("compose.vps-waf.yaml");
const networks = readSource("compose.networks.yaml");
const vpsRoutes = readSource("compose.vps.yaml");
const runtime = readSource("compose.runtime.yaml");
const adminRoutes = readSource("traefik/dynamic/admin-routes.yml");
const projectRoutes = readSource("traefik/dynamic/project-routes.yml");
const edgeStatic = readSource("traefik/traefik.edge-http.yml");

const limiter = sourceSlice(middlewares, "    enterprise-rate-limit:\n", "    enterprise-compress:\n");
assert.match(limiter, /rateLimit:\s*\n\s+average:\s*120\s*\n\s+burst:\s*60\s*\n\s+period:\s*1m/);
assert.doesNotMatch(limiter, /sourceCriterion|requestHeaderName|ipStrategy|requestHost/);
assert.match(vpsWaf, /traefik:\s*\n\s+ports:\s*!override\s*\[\]/);
assert.match(vpsWaf, /waf:[\s\S]*0\.0\.0\.0:80[\s\S]*BACKEND:\s*\$\{WAF_BACKEND:-http:\/\/traefik:80\}/);
const traefikNetworks = sourceSlice(networks, "  traefik:\n", "  waf:\n");
const wafNetworks = sourceSlice(networks, "  waf:\n", "  postgres:\n");
assert.match(traefikNetworks, /- platform_edge/);
assert.match(wafNetworks, /- platform_edge/);
assert.doesNotMatch(edgeStatic, /forwardedHeaders|trustedIPs|insecure:/);
assert.match(runtime, /admin-routes\.yml:\/etc\/traefik\/dynamic\/admin-routes\.yml:ro/);
assert.match(runtime, /project-routes\.yml:\/etc\/traefik\/dynamic\/project-routes\.yml:ro/);
assert.equal(count(vpsRoutes, "enterprise-rate-limit@file"), 3);
assert.equal(count(adminRoutes, "enterprise-rate-limit@file"), 4);
assert.equal(count(projectRoutes, "enterprise-rate-limit@file"), 1);
assert.match(projectRoutes, /HostRegexp\(`\^\[a-z0-9-\]\+\\\.platform-infrastructure\\\.com\$`\)/);
console.log("[SOURCE] rate=120/1m burst=60 source_criterion=absent default_key=remote_address");
console.log("[TOPOLOGY] public_peer=waf shared_edge_network=platform_edge affected_router_refs=8 wildcard_project_router=true");

const wafPeer = "172.31.0.2";
const clientA = requestFixture("198.51.100.10", wafPeer, "203.0.113.250");
const clientB = requestFixture("198.51.100.20", wafPeer, "203.0.113.251");
const preFixKeyA = preFixRateKey(clientA);
const preFixKeyB = preFixRateKey(clientB);
assert.equal(preFixKeyA, wafPeer);
assert.equal(preFixKeyB, wafPeer);
assert.equal(preFixKeyA, preFixKeyB);
console.log(`[PRE-FIX] client_a_key=${preFixKeyA} client_b_key=${preFixKeyB} same_bucket=true`);

const preFixBuckets = new BurstProjection(60);
assert.equal(consumeBurst(preFixBuckets, preFixKeyA, 60), 60);
assert.equal(preFixBuckets.allow(preFixKeyA), false);
assert.equal(preFixBuckets.allow(preFixKeyB), false);
console.log("[PRE-FIX-CONTROL] attacker_burst=60 attacker_next=429 independent_client_next=429");

const sanitizedA = sanitizeAtWaf(clientA);
const sanitizedB = sanitizeAtWaf(clientB);
const fixedKeyA = fixedRateKey(sanitizedA, wafPeer);
const fixedKeyB = fixedRateKey(sanitizedB, wafPeer);
assert.equal(fixedKeyA, "198.51.100.10");
assert.equal(fixedKeyB, "198.51.100.20");
assert.notEqual(fixedKeyA, fixedKeyB);
const fixedBuckets = new BurstProjection(60);
assert.equal(consumeBurst(fixedBuckets, fixedKeyA, 60), 60);
assert.equal(fixedBuckets.allow(fixedKeyA), false);
assert.equal(fixedBuckets.allow(fixedKeyB), true);
console.log(`[FIXED-CONTROL] client_a_key=${fixedKeyA} client_b_key=${fixedKeyB} independent=true attacker_next=429 client_b_next=allow`);

assert.notEqual(sanitizedA.headers["x-platform-client-ip"], clientA.inboundHeaders["x-platform-client-ip"]);
assert.equal(sanitizedA.headers["x-platform-client-ip"], clientA.publicSocketPeer);
assert.throws(
  () => fixedRateKey({ ...sanitizedA, traefikRemoteAddress: "172.31.0.99" }, wafPeer),
  /untrusted Traefik peer/,
);
assert.throws(
  () => sanitizeAtWaf({
    ...clientA,
    publicSocketPeer: "192.0.2.44",
    inboundHeaders: { "cf-connecting-ip": "198.51.100.40, 198.51.100.41" },
    trustedProviderPeers: new Set(["192.0.2.44"]),
  }),
  /invalid provider client identity/,
);
const untrustedProvider = sanitizeAtWaf({
  ...clientA,
  inboundHeaders: { "cf-connecting-ip": "198.51.100.99" },
  trustedProviderPeers: new Set(["192.0.2.44"]),
});
assert.equal(untrustedProvider.headers["x-platform-client-ip"], clientA.publicSocketPeer);
assert.equal(normalizeIp("2001:0DB8:0:0:0:0:0:1", "expanded IPv6"), "2001:db8::1");
assert.equal(normalizeIp("2001:db8::1", "compressed IPv6"), "2001:db8::1");
console.log("[NEGATIVE-IDENTITY] spoofed_header=ignored direct_to_traefik=reject malformed_provider_header=reject untrusted_provider_header=ignored");
console.log("[SAFE] source-pinned key and token-bucket projection only; no Traefik, WAF, Docker, network, SSH, credentials, or live target");

function requestFixture(publicSocketPeer, traefikRemoteAddress, spoofedIdentity) {
  return {
    publicSocketPeer,
    traefikRemoteAddress,
    inboundHeaders: { "x-platform-client-ip": spoofedIdentity },
    trustedProviderPeers: new Set(),
  };
}

function preFixRateKey(request) {
  return normalizeIp(request.traefikRemoteAddress, "Traefik remote address");
}

function sanitizeAtWaf(request) {
  const socketPeer = normalizeIp(request.publicSocketPeer, "WAF socket peer");
  let identity = socketPeer;
  if (request.trustedProviderPeers.has(socketPeer)) {
    identity = normalizeIp(request.inboundHeaders["cf-connecting-ip"], "provider client identity");
  }
  return {
    ...request,
    headers: { "x-platform-client-ip": identity },
  };
}

function fixedRateKey(request, expectedWafPeer) {
  const peer = normalizeIp(request.traefikRemoteAddress, "Traefik remote address");
  if (peer !== expectedWafPeer) throw new Error(`untrusted Traefik peer: ${peer}`);
  return normalizeIp(request.headers["x-platform-client-ip"], "WAF client identity");
}

function normalizeIp(value, label) {
  if (typeof value !== "string" || value.trim() !== value) {
    throw new Error(`invalid ${label}`);
  }
  const version = net.isIP(value);
  if (version === 4) return value.split(".").map((octet) => String(Number(octet))).join(".");
  if (version === 6) return new URL(`http://[${value}]/`).hostname.slice(1, -1).toLowerCase();
  throw new Error(`invalid ${label}`);
}

function consumeBurst(policy, key, requests) {
  let accepted = 0;
  for (let index = 0; index < requests; index += 1) {
    if (policy.allow(key)) accepted += 1;
  }
  return accepted;
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
}

function count(source, token) {
  return source.split(token).length - 1;
}

function validateWrapperOwnedSource(sourceArgument) {
  const wrapperArgument = requiredEnvironment("REPORT_FG060_WRAPPER_TEMP_ROOT");
  const sentinelArgument = requiredEnvironment("REPORT_FG060_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("REPORT_FG060_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperArgument);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(path.basename(wrapperReal), /^fg060-(?:guard|run)\.[A-Za-z0-9]+$/);

  const requestedSource = path.resolve(sourceArgument);
  const sourceStat = fs.lstatSync(requestedSource, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(requestedSource);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned archive child");

  const sentinelPath = path.resolve(sentinelArgument);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  assert.equal(path.dirname(sentinelPath), wrapperReal, "ownership sentinel must be inside wrapper root");
  assert.match(path.basename(sentinelPath), /^\.fg060-owner\.[A-Za-z0-9]+$/);
  assert.equal(path.basename(sentinelPath), `.fg060-owner.${ownershipToken}`, "ownership token does not match sentinel name");
  assert.equal(fs.readFileSync(sentinelPath, "utf8"), `FG060-OWNER:${ownershipToken}\n`, "ownership sentinel content mismatch");
  return sourceReal;
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}
