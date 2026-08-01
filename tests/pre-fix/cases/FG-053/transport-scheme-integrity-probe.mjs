#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_HASHES = new Map([
  ["README.md", "27ae730ec95e41ace8ee74e4bed8ded858d5acc69e634a3e0e9c34340bfe8d33"],
  [".env.example", "36bc8fec1a5f7a3d9f8c65e9c534c72bf8e6228630f659a4a9213801cf1eb6a3"],
  [".env.vps.example", "ed0c6b9a548321a351f022e54a22accec9eefbb76f511521d6bc6bfaae29f333"],
  ["compose.waf.yaml", "592f106ab0ff139f9246e0a104b483b7c3a82643d841f565227d95676364e28e"],
  ["compose.vps-waf.yaml", "01635f0a117de50fd60aa95aa5b6bf42416aa0a39ffe606462e1a6a839c2f008"],
  ["compose.vps.yaml", "c8954158a542825fe276742d3b943818603c2cc764764da98fd81859de3f1415"],
  ["traefik/dynamic/middlewares.yml", "79ae033e15398379b4fec860ff658091c9518f995a533a9ee78ee5b1e9d0a11b"],
  ["traefik/traefik.edge-http.yml", "a36a40cfe8ad23c170d29c6e0e2f72ce0c72a99169d66b80b562436f232642ea"],
]);

const [sourceArgument, wrapperArgument, sentinelArgument, ownerToken] = process.argv.slice(2);
if (!sourceArgument || !wrapperArgument || !sentinelArgument || !ownerToken) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh");
}

const wrapperRoot = verifiedPhysicalDirectory(wrapperArgument, "wrapper root");
const sourceRoot = verifiedPhysicalDirectory(sourceArgument, "archived source root");
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source must be the wrapper's exact source child");
assert.match(ownerToken, /^[0-9a-f]{64}$/, "invalid ownership token");

const wrapperSentinel = verifiedRegularFile(sentinelArgument, "wrapper ownership sentinel");
assert.equal(wrapperSentinel, path.join(wrapperRoot, ".transport-scheme-integrity-wrapper-owner"));
assert.equal(
  fs.readFileSync(wrapperSentinel, "utf8"),
  `transport-scheme-integrity:${ownerToken}\n`,
  "wrapper ownership sentinel mismatch",
);

const source = new Map();
for (const [relative, expectedHash] of EXPECTED_HASHES) {
  const file = verifiedContainedSourceFile(sourceRoot, relative);
  const bytes = fs.readFileSync(file);
  const actualHash = sha256(bytes);
  assert.equal(actualHash, expectedHash, `unexpected bytes for ${relative}`);
  source.set(relative, bytes.toString("utf8"));
  console.log(`[SOURCE] path=${relative} sha256=${actualHash}`);
}
console.log(`[SOURCE] revision=${REVISION} tree=${TREE} files=${source.size} provenance=git-archive`);

const readme = source.get("README.md");
const baseEnv = parseDotEnv(source.get(".env.example"));
const vpsEnv = parseDotEnv(source.get(".env.vps.example"));
const baseWaf = source.get("compose.waf.yaml");
const vpsWaf = source.get("compose.vps-waf.yaml");
const vpsCompose = source.get("compose.vps.yaml");
const middlewares = source.get("traefik/dynamic/middlewares.yml");
const edgeStatic = source.get("traefik/traefik.edge-http.yml");

assert.match(readme, /copy the values|copia i valori/i);
assert.match(readme, /-f compose\.waf\.yaml[\s\S]*-f compose\.vps-waf\.yaml/);
assert.equal(baseEnv.get("WAF_NGINX_ALWAYS_TLS_REDIRECT"), "on");
assert.equal(vpsEnv.get("WAF_NGINX_ALWAYS_TLS_REDIRECT"), "off");
assert.match(baseWaf, /NGINX_ALWAYS_TLS_REDIRECT:\s*\$\{WAF_NGINX_ALWAYS_TLS_REDIRECT:-on\}/);
assert.match(vpsWaf, /ports:\s*!override[\s\S]*\$\{WAF_HTTP_BIND:-0\.0\.0\.0:80\}:8080/);
assert.match(vpsWaf, /BACKEND:\s*\$\{WAF_BACKEND:-http:\/\/traefik:80\}/);
assert.match(vpsWaf, /NGINX_X_FORWARDED_PROTO:\s*\$\{WAF_X_FORWARDED_PROTO:-https\}/);
assert.match(edgeStatic, /entryPoints:\s*\n\s+web:\s*\n\s+address:\s*":80"/);
assert.match(vpsCompose, /enterprise-identity:[\s\S]*entryPoints:\s*\n\s+- web[\s\S]*enterprise-edge-forwarded-https@file[\s\S]*service: enterprise-identity/);
assert.match(vpsCompose, /KC_HTTP_ENABLED:\s*"true"[\s\S]*KC_PROXY_HEADERS:\s*xforwarded/);
assert.match(vpsCompose, /enterprise-identity:[\s\S]*url:\s*http:\/\/keycloak:8080/);
assert.match(middlewares, /enterprise-edge-forwarded-https:[\s\S]*X-Forwarded-Proto:\s*https[\s\S]*X-Forwarded-Port:\s*"443"/);
console.log("[PASS] activation path and downstream xforwarded trust are present in the pinned source");

const defaults = {
  WAF_HTTP_BIND: interpolationDefault(vpsWaf, "WAF_HTTP_BIND"),
  WAF_BACKEND: interpolationDefault(vpsWaf, "WAF_BACKEND"),
  WAF_NGINX_ALWAYS_TLS_REDIRECT: interpolationDefault(vpsWaf, "WAF_NGINX_ALWAYS_TLS_REDIRECT"),
  WAF_X_FORWARDED_PROTO: interpolationDefault(vpsWaf, "WAF_X_FORWARDED_PROTO"),
};
const vulnerableState = deriveState(vpsEnv, defaults, { edgeStatic, middlewares, vpsCompose });
assert.deepEqual(vulnerableState, {
  httpHost: "0.0.0.0",
  httpPort: 80,
  publicHttp: true,
  redirect: false,
  backendProtocol: "http:",
  wafForwardedProto: "https",
  traefikEntryPoint: "web:80",
  traefikForcesHttps: true,
  applicationTrustsForwarded: true,
  vulnerable: true,
});
console.log(
  "[VULNERABLE CAN-123] public_http=0.0.0.0:80 redirect=off " +
  "waf_backend=http://traefik:80 waf_forwarded_proto=https traefik_entrypoint=web:80 " +
  "traefik_forwarded_proto=https application_trust=xforwarded",
);

for (const inboundProto of [undefined, "http", "https", "attacker-value"]) {
  const trace = tracePlaintextRequest(vulnerableState, inboundProto);
  assert.equal(trace.wafDecision, "forward");
  assert.equal(trace.backendTransport, "plaintext-http");
  assert.equal(trace.backendForwardedProto, "https");
  assert.equal(trace.backendForwardedPort, "443");
  console.log(
    `[TRACE] inbound_x_forwarded_proto=${inboundProto ?? "absent"} ` +
    "waf_decision=forward backend_transport=plaintext-http backend_x_forwarded_proto=https backend_x_forwarded_port=443",
  );
}

const safeEnv = new Map(vpsEnv);
safeEnv.set("WAF_NGINX_ALWAYS_TLS_REDIRECT", "on");
const safeState = deriveState(safeEnv, defaults, { edgeStatic, middlewares, vpsCompose });
assert.equal(safeState.vulnerable, false);
assert.equal(safeState.redirect, true);
const safeTrace = tracePlaintextRequest(safeState, "https");
assert.deepEqual(safeTrace, {
  clientTransport: "plaintext-http",
  inboundForwardedProto: "https",
  wafDecision: "redirect-https",
  backendReached: false,
});
console.log("[NEGATIVE CONTROL] redirect=on spoofed_forwarded_proto=https backend_reached=false verdict=safe");

const modified = Buffer.from(fs.readFileSync(path.join(sourceRoot, ".env.vps.example")));
modified[modified.length - 1] ^= 1;
assert.throws(
  () => verifyExpectedHash(".env.vps.example", modified),
  /source hash mismatch/,
);
console.log("[NEGATIVE CONTROL] single_byte_source_change_rejected=true");

const preexisting = path.join(wrapperRoot, "preexisting-preservation-control");
fs.mkdirSync(preexisting, { mode: 0o700 });
const marker = path.join(preexisting, "preserve-me.txt");
fs.writeFileSync(marker, "preexisting-data-must-survive\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
const markerBefore = fileIdentityAndHash(marker);
assert.throws(() => removeOwnedDirectory(preexisting, wrapperRoot, ownerToken), /ownership sentinel/);
assert.deepEqual(fileIdentityAndHash(marker), markerBefore);
console.log(`[GUARD] unowned_cleanup_refused=true preexisting_sha256=${markerBefore.sha256}`);

const analysisRoot = path.join(wrapperRoot, "owned-analysis");
const analysisOwner = createOwnedDirectory(analysisRoot, wrapperRoot, ownerToken);
let receiptHash;
try {
  const receipt = {
    schema: "transport-scheme-integrity-poc/v1",
    revision: REVISION,
    tree: TREE,
    sourceSha256: Object.fromEntries(EXPECTED_HASHES),
    vulnerableState,
    negativeControl: {
      redirect: safeState.redirect,
      backendReached: safeTrace.backendReached,
    },
    safety: {
      networkAttempts: 0,
      credentialsRead: 0,
      servicesStarted: 0,
      sourceMutations: 0,
      liveMutations: 0,
    },
  };
  const receiptPath = path.join(analysisRoot, "offline-receipt.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  receiptHash = sha256(fs.readFileSync(receiptPath));
  assert.equal(JSON.parse(fs.readFileSync(receiptPath, "utf8")).vulnerableState.vulnerable, true);
  console.log(`[RECEIPT] sha256=${receiptHash} scope=wrapper-owned-temporary-root`);
} finally {
  removeOwnedDirectory(analysisRoot, wrapperRoot, analysisOwner);
}
assert.equal(fs.existsSync(analysisRoot), false, "sentinel-owned analysis directory survived cleanup");
assert.deepEqual(fileIdentityAndHash(marker), markerBefore, "pre-existing preservation marker changed");

for (const [relative, expectedHash] of EXPECTED_HASHES) {
  assert.equal(sha256(fs.readFileSync(path.join(sourceRoot, relative))), expectedHash, `source mutation detected: ${relative}`);
}
console.log("[SAFE] network_attempts=0 credentials_read=0 services_started=0 source_mutations=0 live_mutations=0");
console.log("[+] cleanup sentinel_owned_analysis_removed=true preexisting_marker_preserved=true");
console.log("[+] result=VULNERABLE canonical_id=CAN-123");

function parseDotEnv(text) {
  const result = new Map();
  for (const [offset, raw] of text.split("\n").entries()) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    assert.notEqual(separator, -1, `invalid env line ${offset + 1}`);
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    assert.match(key, /^[A-Z][A-Z0-9_]*$/, `invalid env key on line ${offset + 1}`);
    assert.equal(result.has(key), false, `duplicate env key ${key}`);
    result.set(key, value);
  }
  return result;
}

function interpolationDefault(text, variable) {
  const expression = new RegExp(`\\$\\{${variable}:-([^}]+)\\}`, "g");
  const values = [...text.matchAll(expression)].map((match) => match[1]);
  assert.equal(values.length, 1, `expected one interpolation for ${variable}`);
  return values[0];
}

function composeValue(env, defaults, key) {
  const value = env.get(key);
  return value === undefined || value === "" ? defaults[key] : value;
}

function deriveState(env, defaults, sourceText) {
  const bind = parseHostBind(composeValue(env, defaults, "WAF_HTTP_BIND"));
  const redirectValue = composeValue(env, defaults, "WAF_NGINX_ALWAYS_TLS_REDIRECT").toLowerCase();
  assert.match(redirectValue, /^(?:on|off)$/, "redirect must be explicit on/off");
  const backend = new URL(composeValue(env, defaults, "WAF_BACKEND"));
  const forwarded = composeValue(env, defaults, "WAF_X_FORWARDED_PROTO").toLowerCase();
  assert.match(forwarded, /^(?:http|https)$/, "forwarded proto must be http or https");
  const publicHttp = ["0.0.0.0", "::"].includes(bind.host) && bind.port === 80;
  const traefikEntryPoint = /entryPoints:\s*\n\s+web:\s*\n\s+address:\s*":80"/.test(sourceText.edgeStatic)
    ? "web:80"
    : "unknown";
  const traefikForcesHttps = /X-Forwarded-Proto:\s*https[\s\S]*X-Forwarded-Port:\s*"443"/.test(sourceText.middlewares);
  const applicationTrustsForwarded = /KC_PROXY_HEADERS:\s*xforwarded/.test(sourceText.vpsCompose);
  return {
    httpHost: bind.host,
    httpPort: bind.port,
    publicHttp,
    redirect: redirectValue === "on",
    backendProtocol: backend.protocol,
    wafForwardedProto: forwarded,
    traefikEntryPoint,
    traefikForcesHttps,
    applicationTrustsForwarded,
    vulnerable:
      publicHttp &&
      redirectValue === "off" &&
      backend.protocol === "http:" &&
      forwarded === "https" &&
      traefikEntryPoint === "web:80" &&
      traefikForcesHttps &&
      applicationTrustsForwarded,
  };
}

function parseHostBind(value) {
  if (/^[0-9]+$/.test(value)) {
    return { host: "0.0.0.0", port: Number(value) };
  }
  const ipv6 = value.match(/^\[([^\]]+)\]:([0-9]+)$/);
  if (ipv6) return { host: ipv6[1] === "::" ? "::" : ipv6[1], port: Number(ipv6[2]) };
  const ipv4 = value.match(/^([^:]+):([0-9]+)$/);
  assert.ok(ipv4, `unsupported host bind: ${value}`);
  return { host: ipv4[1], port: Number(ipv4[2]) };
}

function tracePlaintextRequest(state, inboundForwardedProto) {
  if (state.redirect) {
    return {
      clientTransport: "plaintext-http",
      inboundForwardedProto: inboundForwardedProto ?? null,
      wafDecision: "redirect-https",
      backendReached: false,
    };
  }
  return {
    clientTransport: "plaintext-http",
    inboundForwardedProto: inboundForwardedProto ?? null,
    wafDecision: "forward",
    backendReached: true,
    backendTransport: state.backendProtocol === "http:" ? "plaintext-http" : state.backendProtocol,
    backendForwardedProto: state.traefikForcesHttps ? "https" : state.wafForwardedProto,
    backendForwardedPort: state.traefikForcesHttps ? "443" : null,
  };
}

function verifiedPhysicalDirectory(candidate, label) {
  const resolved = path.resolve(candidate);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  assert.equal(fs.realpathSync(resolved), resolved, `${label} must be a physical path`);
  return resolved;
}

function verifiedRegularFile(candidate, label) {
  const resolved = path.resolve(candidate);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isFile(), true, `${label} is not a regular file`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  return resolved;
}

function verifiedContainedSourceFile(root, relative) {
  const candidate = path.resolve(root, relative);
  assert.equal(candidate.startsWith(`${root}${path.sep}`), true, `source path escaped archive: ${relative}`);
  verifiedRegularFile(candidate, relative);
  assert.equal(fs.realpathSync(candidate), candidate, `source file must be a physical path: ${relative}`);
  return candidate;
}

function createOwnedDirectory(directory, parent, token) {
  const resolved = path.resolve(directory);
  assert.equal(path.dirname(resolved), parent, "owned directory must be a direct wrapper child");
  assert.equal(fs.existsSync(resolved), false, "refusing pre-existing owned directory target");
  fs.mkdirSync(resolved, { mode: 0o700 });
  const sentinel = path.join(resolved, ".transport-scheme-integrity-owner");
  fs.writeFileSync(sentinel, `${token}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  return token;
}

function removeOwnedDirectory(directory, parent, token) {
  const resolved = path.resolve(directory);
  assert.equal(path.dirname(resolved), parent, "cleanup target is outside wrapper root");
  const directoryStat = fs.lstatSync(resolved);
  assert.equal(directoryStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(directoryStat.isSymbolicLink(), false, "cleanup target is a symbolic link");
  assert.equal(fs.realpathSync(resolved), resolved, "cleanup target is not a physical path");
  const sentinel = path.join(resolved, ".transport-scheme-integrity-owner");
  assert.equal(fs.existsSync(sentinel), true, "ownership sentinel is missing");
  const sentinelStat = fs.lstatSync(sentinel);
  assert.equal(sentinelStat.isFile(), true, "ownership sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel is a symbolic link");
  assert.equal(fs.readFileSync(sentinel, "utf8"), `${token}\n`, "ownership sentinel mismatch");
  fs.rmSync(resolved, { recursive: true, force: false });
  assert.equal(fs.existsSync(resolved), false, "owned directory survived cleanup");
}

function fileIdentityAndHash(file) {
  const stat = fs.lstatSync(file);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  return { device: stat.dev, inode: stat.ino, size: stat.size, sha256: sha256(fs.readFileSync(file)) };
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function verifyExpectedHash(relative, bytes) {
  const expected = EXPECTED_HASHES.get(relative);
  assert.ok(expected, `missing expected hash for ${relative}`);
  const actual = sha256(bytes);
  if (actual !== expected) throw new Error(`source hash mismatch for ${relative}`);
  return actual;
}
