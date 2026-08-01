#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const EXPECTED_HASHES = new Map([
  ["traefik/dynamic/admin-routes.yml", "0c712f00c4ca5b35cc22ad66ac6bcbd7ad091f1cf82b66904b8124b8ddc1b931"],
  ["traefik/dynamic/middlewares.yml", "79ae033e15398379b4fec860ff658091c9518f995a533a9ee78ee5b1e9d0a11b"],
  ["waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf", "d6419045ce81e4cff9199815ad08cdc34e03ad8adb6c015381cae5c3908325b0"],
  ["compose.runtime.yaml", "b7b546bbb8587b54d39a0a53d22db4f020afcc707c33338eee264c4407d30505"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["control-center/auth/oidc.mjs", "2f0c9ea5239935857caab3f233ff43cdb81a34d8ab77cfc1a7a00c2a1b7b91b1"],
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
]);

const [sourceRootArgument, wrapperRootArgument, wrapperSentinelArgument, preexistingRootArgument] = process.argv.slice(2);
if (!sourceRootArgument || !wrapperRootArgument || !wrapperSentinelArgument || !preexistingRootArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned temporary root");
}

const wrapperRootPath = path.resolve(wrapperRootArgument);
const wrapperRootStat = fs.lstatSync(wrapperRootPath);
assert.equal(wrapperRootStat.isDirectory(), true, "wrapper root is not a directory");
assert.equal(wrapperRootStat.isSymbolicLink(), false, "wrapper root must not be a symbolic link");
const wrapperRoot = fs.realpathSync(wrapperRootPath);
assert.equal(wrapperRoot, wrapperRootPath, "wrapper root must be its physical path");

const sourceRootPath = path.resolve(sourceRootArgument);
const sourceRootStat = fs.lstatSync(sourceRootPath);
assert.equal(sourceRootStat.isDirectory(), true, "source archive is not a directory");
assert.equal(sourceRootStat.isSymbolicLink(), false, "source archive must not be a symbolic link");
const sourceRoot = fs.realpathSync(sourceRootPath);
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source archive must be the exact source child");
assert.equal(path.dirname(sourceRoot), wrapperRoot, "source archive escaped the wrapper root");

const wrapperSentinelPath = path.resolve(wrapperSentinelArgument);
const wrapperSentinelStat = fs.lstatSync(wrapperSentinelPath);
assert.equal(wrapperSentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(wrapperSentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel must not be a symbolic link");
assert.equal(fs.realpathSync(wrapperSentinelPath), wrapperSentinelPath, "wrapper ownership sentinel must be its physical path");
assert.equal(path.dirname(wrapperSentinelPath), wrapperRoot, "wrapper ownership sentinel escaped the wrapper root");
const sentinelMatch = path.basename(wrapperSentinelPath).match(/^\.database-admin-owner-gate-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(wrapperSentinelPath, "utf8"),
  `database-admin-owner-gate:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  const target = path.join(sourceRoot, relativePath);
  const targetStat = fs.lstatSync(target);
  assert.equal(targetStat.isFile(), true, `${relativePath} is not a regular file`);
  assert.equal(targetStat.isSymbolicLink(), false, `${relativePath} must not be a symbolic link`);
  assert.equal(sha256File(target), expectedHash, `unexpected source revision for ${relativePath}`);
}

const preexistingRootPath = path.resolve(preexistingRootArgument);
const preexistingRootStat = fs.lstatSync(preexistingRootPath);
assert.equal(preexistingRootStat.isDirectory(), true, "pre-existing target is not a directory");
assert.equal(preexistingRootStat.isSymbolicLink(), false, "pre-existing target must not be a symbolic link");
const preexistingRoot = fs.realpathSync(preexistingRootPath);
assert.equal(preexistingRoot, path.join(wrapperRoot, "preexisting"), "pre-existing target is not the exact wrapper child");
const preexistingFile = path.join(preexistingRoot, "preserve-route.yml");
const preexistingBefore = fs.lstatSync(preexistingFile);
const preexistingBytes = fs.readFileSync(preexistingFile);
const preexistingHash = sha256Bytes(preexistingBytes);
const preexistingEntries = fs.readdirSync(preexistingRoot).sort();
assert.throws(() => claimOwnedFixture(preexistingRoot, wrapperRoot, ownerToken), /refusing pre-existing fixture target/);
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
const preexistingAfter = fs.lstatSync(preexistingFile);
assert.equal(preexistingAfter.dev, preexistingBefore.dev, "pre-existing route fixture device changed");
assert.equal(preexistingAfter.ino, preexistingBefore.ino, "pre-existing route fixture inode changed");
assert.deepEqual(fs.readFileSync(preexistingFile), preexistingBytes);
console.log(`[+] negative-control preexisting_target_rejected=true route_preserved=true sha256=${preexistingHash}`);

const fixtureRoot = path.join(wrapperRoot, `fixture-${ownerToken}`);
const fixtureOwnership = claimOwnedFixture(fixtureRoot, wrapperRoot, ownerToken);

try {
  const adminRoutesSource = readSource("traefik/dynamic/admin-routes.yml");
  const middlewaresSource = readSource("traefik/dynamic/middlewares.yml");
  const wafSource = readSource("waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf");
  const runtimeSource = readSource("compose.runtime.yaml");
  const composeWrapperSource = readSource("scripts/compose-vps.sh");
  const oidcSource = readSource("control-center/auth/oidc.mjs");
  const serverSource = readSource("control-center/server.mjs");

  assert.doesNotMatch(adminRoutesSource, /\bforwardAuth\s*:/, "admin routes unexpectedly define ForwardAuth");
  assert.doesNotMatch(middlewaresSource, /\bforwardAuth\s*:/, "middleware catalog unexpectedly defines ForwardAuth");
  assert.match(runtimeSource, /  traefik:\n    volumes:\n      - \.\/traefik\/dynamic\/admin-routes\.yml:\/etc\/traefik\/dynamic\/admin-routes\.yml:ro/);
  assert.match(runtimeSource, /  phpmyadmin:\n    profiles: !reset \[\]\n    restart: unless-stopped/);
  assert.match(runtimeSource, /  phppgadmin:\n    profiles: !reset \[\]\n    restart: unless-stopped/);
  assert.match(composeWrapperSource, /-f compose\.vps\.yaml[\s\S]*-f compose\.runtime\.yaml/);
  console.log("[+] activation admin_routes_mounted=true phpmyadmin_enabled=true phppgadmin_enabled=true runtime_overlay_after_vps=true");

  assert.match(oidcSource, /"\/actions\/phpmyadmin-login"/);
  assert.match(oidcSource, /"\/actions\/phppgadmin-login"/);
  assert.match(oidcSource, /if \(sensitive && session\.role !== "owner"\) return denied\(403/);
  assert.match(oidcSource, /this\.config\.freshAuthSeconds \* 1000/);
  assert.match(serverSource, /controlAuth\.authorize\(req, url, session\)/);
  assert.match(serverSource, /appendAudit\(\{ action: "database\.phpmyadmin\.login"/);
  assert.match(serverSource, /appendAudit\(\{ action: "database\.phppgadmin\.login"/);
  console.log("[+] intended-control sensitive_actions=true owner_required=true fresh_auth_seconds=300 audited_bridge=true");

  const routers = new Map([
    ["CAN-169", {
      name: "enterprise-phpmyadmin",
      host: "phpmyadmin.platform-infrastructure.com",
      path: "/",
      expectedService: "enterprise-phpmyadmin",
    }],
    ["CAN-170", {
      name: "enterprise-phppgadmin",
      host: "phppgadmin.platform-infrastructure.com",
      path: "/phppgadmin/",
      expectedService: "enterprise-phppgadmin",
    }],
  ]);

  const parsedRouters = new Map();
  for (const [canonicalId, definition] of routers) {
    const router = parseRouter(adminRoutesSource, definition.name);
    assert.equal(router.service, definition.expectedService, `${canonicalId} routes to the wrong service`);
    assert.equal(routeMatches(router.rule, definition.host, definition.path), true, `${canonicalId} route did not match its dedicated request`);
    assert.equal(hasOwnerAuthMiddleware(router.middlewares), false, `${canonicalId} unexpectedly has an owner gate`);
    parsedRouters.set(canonicalId, { ...definition, ...router });
    console.log(`[VULNERABLE] ${canonicalId} router=${definition.name} owner_auth_middleware=false service=${router.service}`);
  }

  const privateRanges = parseWafPrivateRanges(wafSource);
  assert.deepEqual(privateRanges, ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
  for (const privateAddress of ["127.0.0.1", "10.23.4.5", "172.20.9.8", "192.168.50.4"]) {
    assert.equal(ipMatchesAny(privateAddress, privateRanges), true, `${privateAddress} was not recognized as WAF-exempt`);
  }
  assert.equal(ipMatchesAny("198.51.100.23", privateRanges), false);
  console.log(`[+] waf private_source_exemptions=${privateRanges.join(",")} public_admin_host_status=404`);

  const identities = [
    { label: "anonymous", authenticated: false, role: "", authAgeSeconds: null, expectedControlStatus: 401 },
    { label: "viewer", authenticated: true, role: "viewer", authAgeSeconds: 0, expectedControlStatus: 403 },
    { label: "admin", authenticated: true, role: "admin", authAgeSeconds: 0, expectedControlStatus: 403 },
    { label: "stale-owner", authenticated: true, role: "owner", authAgeSeconds: 301, expectedControlStatus: 428 },
    { label: "fresh-owner", authenticated: true, role: "owner", authAgeSeconds: 0, expectedControlStatus: 200 },
  ];

  for (const [canonicalId, router] of parsedRouters) {
    for (const identity of identities) {
      const controlStatus = intendedControlStatus(identity);
      assert.equal(controlStatus, identity.expectedControlStatus, `unexpected Control Center status for ${identity.label}`);
      const direct = directRouteDecision(router, "10.23.4.5", identity, privateRanges);
      assert.deepEqual(direct, { action: "route", service: router.service }, `${canonicalId} direct route unexpectedly consulted identity`);
      console.log(`[VULNERABLE] ${canonicalId} private_identity=${identity.label} control_status=${controlStatus} direct=ROUTED_TO_NATIVE_LOGIN`);
    }
    const publicDecision = directRouteDecision(router, "198.51.100.23", identities.at(-1), privateRanges);
    assert.deepEqual(publicDecision, { action: "deny", status: 404 });
    console.log(`[+] ${canonicalId} negative-control public_source_status=404 route_reached=false`);
  }

  const fixedPolicyReceipt = {
    version: 1,
    generatedFrom: "synthetic-negative-control",
    routers: {},
  };
  for (const [canonicalId, router] of parsedRouters) {
    const fixedRouter = {
      ...router,
      middlewares: ["enterprise-db-admin-owner-auth@file", ...router.middlewares],
    };
    assert.equal(hasOwnerAuthMiddleware(fixedRouter.middlewares), true);
    fixedPolicyReceipt.routers[canonicalId] = [];
    for (const identity of identities) {
      const decision = directRouteDecision(fixedRouter, "10.23.4.5", identity, privateRanges);
      const expectedStatus = identity.expectedControlStatus;
      if (expectedStatus === 200) {
        assert.deepEqual(decision, { action: "route", service: fixedRouter.service });
      } else {
        assert.deepEqual(decision, { action: "deny", status: expectedStatus });
      }
      fixedPolicyReceipt.routers[canonicalId].push({ identity: identity.label, status: expectedStatus });
    }
  }
  const fixedReceiptPath = path.join(fixtureRoot, "synthetic-fixed-owner-policy.json");
  fs.writeFileSync(fixedReceiptPath, `${JSON.stringify(fixedPolicyReceipt, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  assert.equal(JSON.parse(fs.readFileSync(fixedReceiptPath, "utf8")).routers["CAN-169"].length, identities.length);
  console.log("[+] negative-control synthetic_forwardauth anonymous=401 viewer=403 admin=403 stale_owner=428 fresh_owner=200");
  console.log("[+] safety http_requests=0 traefik_calls=0 waf_calls=0 docker_calls=0 database_logins=0 credentials_read=0 services_started=0 network_attempts=0");
  console.log("[+] result=VULNERABLE");
} finally {
  cleanupOwnedFixture(fixtureOwnership, wrapperRoot);
}

assert.equal(fs.existsSync(fixtureRoot), false, "sentinel-owned fixture was not removed");
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
const preservedStat = fs.lstatSync(preexistingFile);
assert.equal(preservedStat.dev, preexistingBefore.dev);
assert.equal(preservedStat.ino, preexistingBefore.ino);
assert.equal(sha256File(preexistingFile), preexistingHash);
console.log("[+] cleanup sentinel_owned_fixture_removed=true preexisting_route_still_present=true");

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function parseRouter(source, name) {
  const lines = source.split("\n");
  const routersStart = lines.findIndex((line) => line === "  routers:");
  assert.notEqual(routersStart, -1, "routers section is missing");
  const routersEnd = lines.findIndex((line, index) => index > routersStart && /^  [a-zA-Z0-9_-]+:$/.test(line));
  assert.notEqual(routersEnd, -1, "routers section is unterminated");
  const routerStart = lines.findIndex((line, index) => index > routersStart && index < routersEnd && line === `    ${name}:`);
  assert.notEqual(routerStart, -1, `router ${name} is missing`);
  let routerEnd = routersEnd;
  for (let index = routerStart + 1; index < routersEnd; index += 1) {
    if (/^    [a-zA-Z0-9_-]+:$/.test(lines[index])) {
      routerEnd = index;
      break;
    }
  }
  const block = lines.slice(routerStart, routerEnd);
  const ruleLine = block.find((line) => line.startsWith("      rule: "));
  const serviceLine = block.find((line) => line.startsWith("      service: "));
  assert.ok(ruleLine, `${name} rule is missing`);
  assert.ok(serviceLine, `${name} service is missing`);
  const middlewareStart = block.findIndex((line) => line === "      middlewares:");
  assert.notEqual(middlewareStart, -1, `${name} middleware list is missing`);
  const middlewares = [];
  for (let index = middlewareStart + 1; index < block.length; index += 1) {
    const match = block[index].match(/^        - (\S+)$/);
    if (!match) break;
    middlewares.push(match[1]);
  }
  assert.ok(middlewares.length > 0, `${name} middleware list is empty`);
  return {
    rule: ruleLine.slice("      rule: ".length),
    service: serviceLine.slice("      service: ".length),
    middlewares,
  };
}

function routeMatches(rule, host, requestPath) {
  const hostMatch = rule.match(/Host\(`([^`]+)`\)/);
  if (!hostMatch || hostMatch[1].toLowerCase() !== host.toLowerCase()) return false;
  const pathMatch = rule.match(/PathPrefix\(`([^`]+)`\)/);
  return !pathMatch || requestPath.startsWith(pathMatch[1]);
}

function hasOwnerAuthMiddleware(middlewares) {
  return middlewares.includes("enterprise-db-admin-owner-auth@file");
}

function parseWafPrivateRanges(source) {
  assert.match(source, /SecRule REQUEST_HEADERS:Host "@rx \(\?i\).*phpmyadmin\|phppgadmin[\s\S]*tag:'platform-waf\/admin-surface',chain"/);
  const match = source.match(/SecRule REMOTE_ADDR "!@ipMatch ([^"]+)"/);
  assert.ok(match, "WAF private-source exception is missing");
  return match[1].split(",").map((value) => value.trim());
}

function directRouteDecision(router, remoteAddress, identity, privateRanges) {
  if (!ipMatchesAny(remoteAddress, privateRanges)) return { action: "deny", status: 404 };
  if (hasOwnerAuthMiddleware(router.middlewares)) {
    const status = intendedControlStatus(identity);
    if (status !== 200) return { action: "deny", status };
  }
  return { action: "route", service: router.service };
}

function intendedControlStatus(identity) {
  if (!identity.authenticated) return 401;
  if (identity.role !== "owner") return 403;
  if (!Number.isFinite(identity.authAgeSeconds) || identity.authAgeSeconds > 300) return 428;
  return 200;
}

function ipMatchesAny(address, ranges) {
  return ranges.some((range) => ipv4InRange(address, range));
}

function ipv4InRange(address, range) {
  assert.equal(net.isIP(address), 4, `unsupported address ${address}`);
  const [base, prefixText] = range.split("/");
  assert.equal(net.isIP(base), 4, `unsupported range ${range}`);
  const prefix = prefixText === undefined ? 32 : Number(prefixText);
  assert.ok(Number.isInteger(prefix) && prefix >= 0 && prefix <= 32, `invalid prefix ${range}`);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToInteger(address) & mask) === (ipv4ToInteger(base) & mask);
}

function ipv4ToInteger(address) {
  return address.split(".").reduce((value, octet) => ((value << 8) | Number(octet)) >>> 0, 0);
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

function claimOwnedFixture(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "fixture target escaped the wrapper root");
  if (fs.existsSync(targetPath)) {
    throw new Error(`refusing pre-existing fixture target: ${targetPath}`);
  }
  assert.match(path.basename(targetPath), /^fixture-[0-9a-f]{64}$/, "fixture name is not token-bound");
  fs.mkdirSync(targetPath, { recursive: false, mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true, "claimed fixture target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "claimed fixture target is a symbolic link");
  assert.equal(fs.realpathSync(targetPath), targetPath, "claimed fixture target must be its physical path");
  const sentinelPath = path.join(targetPath, `.database-admin-owner-gate-probe-owner-${token}`);
  fs.writeFileSync(sentinelPath, `database-admin-owner-gate:${token}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  const sentinelStat = fs.lstatSync(sentinelPath);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    sentinelPath,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
    token,
  };
}

function cleanupOwnedFixture(ownership, expectedParent) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through a target symbolic link");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  assert.equal(fs.realpathSync(ownership.targetPath), ownership.targetPath, "cleanup target is not its physical path");
  assert.equal(path.dirname(ownership.targetPath), expectedParent, "cleanup target escaped the wrapper root");

  const sentinelStat = fs.lstatSync(ownership.sentinelPath);
  assert.equal(sentinelStat.isFile(), true, "cleanup ownership sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "refusing cleanup through a sentinel symbolic link");
  assert.equal(sentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(sentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.sentinelPath, "utf8"),
    `database-admin-owner-gate:${ownership.token}\n`,
    "refusing cleanup without the fixture ownership token",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}
