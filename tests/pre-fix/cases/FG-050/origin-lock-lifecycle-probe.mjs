#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const EXPECTED_HASHES = new Map([
  ["scripts/cloudflare-origin-lock-ufw.sh", "9dd0007ab6a1ae430c40dd9df12a7bf49f9aaef66c2f45f267c2028087387dfb"],
  ["scripts/vps-hardening-ubuntu.sh", "c8edddfe1a1cb5da1499e4e35cc390b8dd14d7240a71321544709941bad62388"],
  ["scripts/vps-host-readiness.sh", "a992bb416f7bc2175515cd91b95ba84772d586509002fbe17dd96ad88159f198"],
  ["README.md", "27ae730ec95e41ace8ee74e4bed8ded858d5acc69e634a3e0e9c34340bfe8d33"],
  ["VPS-PREDEPLOY-CHECKLIST.md", "3dcd43f6a44ffca28d690573d5b03a335b4095d08ad615d62c951732b61208e9"],
  ["compose.vps-waf.yaml", "01635f0a117de50fd60aa95aa5b6bf42416aa0a39ffe606462e1a6a839c2f008"],
  ["scripts/deploy-vps-remote.sh", "e7460e9db36765e6078d778d8a5388d54a78ee4620ddb70f2f7a19187f937804"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/vps-preflight.sh", "7ef50ca582463092bbd0d2e6be5150b2c7cfe7979c931e8c74fe1988fe9eca03"],
  ["scripts/prepare-vps-runtime.sh", "e260cd2f9daa7db2f31a911ec50e9086e1ff07974ec3478e938a7456a30a2734"],
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
const sentinelMatch = path.basename(wrapperSentinelPath).match(/^\.origin-lock-lifecycle-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(wrapperSentinelPath, "utf8"),
  `origin-lock-lifecycle:${ownerToken}\n`,
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
const preexistingFile = path.join(preexistingRoot, "ufw-before.txt");
const preexistingBefore = fs.lstatSync(preexistingFile);
const preexistingBytes = fs.readFileSync(preexistingFile);
const preexistingHash = sha256Bytes(preexistingBytes);
const preexistingEntries = fs.readdirSync(preexistingRoot).sort();
assert.throws(() => claimOwnedFixture(preexistingRoot, wrapperRoot, ownerToken), /refusing pre-existing fixture target/);
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
const preexistingAfter = fs.lstatSync(preexistingFile);
assert.equal(preexistingAfter.dev, preexistingBefore.dev, "pre-existing snapshot device changed");
assert.equal(preexistingAfter.ino, preexistingBefore.ino, "pre-existing snapshot inode changed");
assert.deepEqual(fs.readFileSync(preexistingFile), preexistingBytes);
console.log(`[+] negative-control preexisting_target_rejected=true snapshot_preserved=true sha256=${preexistingHash}`);

const fixtureRoot = path.join(wrapperRoot, `fixture-${ownerToken}`);
const fixtureOwnership = claimOwnedFixture(fixtureRoot, wrapperRoot, ownerToken);

try {
  const originLockSource = readSource("scripts/cloudflare-origin-lock-ufw.sh");
  const hardeningSource = readSource("scripts/vps-hardening-ubuntu.sh");
  const readinessSource = readSource("scripts/vps-host-readiness.sh");
  const readmeSource = readSource("README.md");
  const checklistSource = readSource("VPS-PREDEPLOY-CHECKLIST.md");
  const wafComposeSource = readSource("compose.vps-waf.yaml");
  const deploySource = readSource("scripts/deploy-vps-remote.sh");
  const composeWrapperSource = readSource("scripts/compose-vps.sh");
  const preflightSource = readSource("scripts/vps-preflight.sh");
  const prepareRuntimeSource = readSource("scripts/prepare-vps-runtime.sh");

  assert.match(hardeningSource, /run ufw allow "\$\{SSH_PORT\}\/tcp"\nrun ufw allow 80\/tcp\nrun ufw allow 443\/tcp/);
  const defaultPortsMatch = originLockSource.match(/PORTS="\$\{ORIGIN_LOCK_PORTS:-([^}]+)\}"/);
  assert.ok(defaultPortsMatch, "origin-lock default ports are missing");
  assert.deepEqual(parsePorts(defaultPortsMatch[1]), [80, 443]);
  const scopedAllowCommands = [...originLockSource.matchAll(/run ufw allow proto tcp from "\$cidr" to any port "\$port"/g)];
  assert.equal(scopedAllowCommands.length, 2, "expected one IPv4 and one IPv6 scoped allow loop");
  assert.doesNotMatch(originLockSource, /run ufw (?:delete|deny|reject)/, "origin-lock source unexpectedly reconciles permissive rules");
  assert.match(originLockSource, /If generic public 80\/443 allow rules still exist, delete them only after/);

  const readmePorts = documentedPorts(readmeSource);
  const checklistPorts = documentedPorts(checklistSource);
  assert.deepEqual(readmePorts, [80]);
  assert.deepEqual(checklistPorts, [80]);

  assert.match(wafComposeSource, /\$\{WAF_HTTP_BIND:-0\.0\.0\.0:80\}:8080/);
  assert.match(wafComposeSource, /\$\{WAF_HTTPS_BIND:-0\.0\.0\.0:443\}:8443/);
  assert.match(composeWrapperSource, /-f compose\.vps-waf\.yaml/);

  const readinessUfwBlock = functionBlock(readinessSource, "check_ufw", "check_services");
  assert.match(readinessUfwBlock, /Status: active/);
  assert.match(readinessUfwBlock, /ufw-no-direct-internal-ports/);
  assert.match(readinessUfwBlock, /ufw-ssh-port-allowed/);
  assert.doesNotMatch(readinessUfwBlock, /cloudflare-origin|80\/tcp|443\/tcp|80\|443/);

  const composeStartNeedle = "bash ./scripts/compose-vps.sh up -d --build --remove-orphans";
  const composeStartIndex = deploySource.indexOf(composeStartNeedle);
  assert.notEqual(composeStartIndex, -1, "remote deploy does not contain the expected Compose activation");
  const beforeActivation = deploySource.slice(0, composeStartIndex);
  assert.match(beforeActivation, /sh \.\/scripts\/vps-preflight\.sh "\$env_file"/);
  assert.match(beforeActivation, /sh \.\/scripts\/prepare-vps-runtime\.sh/);
  assert.doesNotMatch(beforeActivation, /cloudflare-origin-lock|vps-host-readiness|\bufw\b/);
  assert.doesNotMatch(preflightSource, /cloudflare-origin-lock|vps-host-readiness|\bufw\b/);
  assert.doesNotMatch(prepareRuntimeSource, /cloudflare-origin-lock|vps-host-readiness|\bufw\b/);
  assert.ok(deploySource.indexOf("sh ./scripts/vps-postdeploy.sh", composeStartIndex) > composeStartIndex);

  console.log("[+] source hardening_generic_web_allows=80,443 origin_lock_default_ports=80,443 origin_lock_reconciliation=false");
  console.log("[+] documentation readme_ports=80 checklist_ports=80 public_waf_ports=80,443");
  console.log("[+] readiness ufw_active=true internal_port_check=true ssh_check=true generic_web_allow_check=false");

  const candidateBaseline = baselineRules();
  const defaultApplication = applyCandidateOriginLock(candidateBaseline, [80, 443]);
  const defaultExposure = exposureMatrix(defaultApplication, [80, 443]);
  assert.equal(defaultExposure.every((entry) => entry.untrustedAllowed), true);
  console.log("[VULNERABLE] CAN-121 additive_origin_lock=true generic_rules_removed=false untrusted_ipv4_80=true untrusted_ipv4_443=true untrusted_ipv6_80=true untrusted_ipv6_443=true");

  const documentedApplication = applyCandidateOriginLock(candidateBaseline, readmePorts);
  assert.equal(documentedApplication.some((rule) => rule.port === 443 && rule.source === "cloudflare"), false);
  assert.equal(isAllowed(documentedApplication, "ipv4", 443, "untrusted"), true);
  assert.equal(isAllowed(documentedApplication, "ipv6", 443, "untrusted"), true);
  console.log("[VULNERABLE] CAN-122 documented_ports=80 published_ports=80,443 cloudflare_scoped_443=false untrusted_ipv4_443=true untrusted_ipv6_443=true");

  const readinessFixture = renderUfwStatus(documentedApplication, 65002);
  const readinessDecision = candidateReadinessDecision(readinessFixture, 65002);
  assert.deepEqual(readinessDecision, { active: true, noInternalPorts: true, sshAllowed: true, passesUfwChecks: true });
  const lifecycle = candidateDeployLifecycle(deploySource);
  assert.equal(lifecycle.originVerificationBeforeActivation, false);
  assert.equal(lifecycle.activated, true);
  console.log("[VULNERABLE] CAN-149 preactivation_origin_gate=false compose_activated=true public_bind_ipv4_80=true public_bind_ipv4_443=true readiness_accepts_generic_web_rules=true");

  const fixed = fixedDeployLifecycle(candidateBaseline, [80, 443], [80, 443]);
  assert.equal(fixed.verified, true);
  assert.equal(fixed.activated, true);
  assert.equal(fixed.rules.some((rule) => rule.port === 65002 && rule.source === "any"), true);
  assert.equal(exposureMatrix(fixed.rules, [80, 443]).every((entry) => !entry.untrustedAllowed && entry.cloudflareAllowed), true);
  console.log("[+] negative-control fixed_policy verified=true activated=true ssh_recovery_preserved=true untrusted_ipv4_80=false untrusted_ipv4_443=false untrusted_ipv6_80=false untrusted_ipv6_443=false cloudflare_dual_stack=true");

  const leftoverV6 = fixedDeployLifecycle(candidateBaseline, [80, 443], [80, 443], [
    rule("ipv6", 443, "any", "injected-leftover"),
  ]);
  assert.equal(leftoverV6.verified, false);
  assert.equal(leftoverV6.activated, false);
  assert.ok(leftoverV6.violations.includes("generic-ipv6-443"));
  console.log("[+] negative-control leftover_ipv6_443 verified=false activated=false fail_closed=true");

  const omittedPort = fixedDeployLifecycle(candidateBaseline, [80], [80, 443]);
  assert.equal(omittedPort.verified, false);
  assert.equal(omittedPort.activated, false);
  assert.ok(omittedPort.violations.some((entry) => entry.endsWith("-443")));
  console.log("[+] negative-control omitted_443 verified=false activated=false fail_closed=true");

  const receipt = {
    version: 1,
    revision: "68cd05895b8d479ffb8167344282e7d922958bfc",
    tree: "70031b30316fbaecbb23249491d6ff4e364d65d5",
    canonicalFindings: ["CAN-121", "CAN-122", "CAN-149"],
    vulnerable: true,
    candidate: {
      additiveOriginLockLeavesGenericRules: true,
      documentedPorts: readmePorts,
      publishedPorts: [80, 443],
      originVerificationBeforeActivation: lifecycle.originVerificationBeforeActivation,
    },
    negativeControls: {
      fixedPolicyVerified: fixed.verified,
      sshRecoveryPreserved: fixed.rules.some((entry) => entry.port === 65002 && entry.source === "any"),
      leftoverIpv6Rejected: !leftoverV6.verified && !leftoverV6.activated,
      omittedPortRejected: !omittedPort.verified && !omittedPort.activated,
    },
    safety: {
      ufwCalls: 0,
      sudoCalls: 0,
      curlCalls: 0,
      httpRequests: 0,
      sshConnections: 0,
      dockerCalls: 0,
      composeCalls: 0,
      firewallChanges: 0,
      servicesStarted: 0,
      credentialsRead: 0,
      networkAttempts: 0,
    },
  };
  const receiptPath = path.join(fixtureRoot, "origin-lock-lifecycle-receipt.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  assert.deepEqual(JSON.parse(fs.readFileSync(receiptPath, "utf8")).canonicalFindings, ["CAN-121", "CAN-122", "CAN-149"]);
  console.log("[+] safety ufw_calls=0 sudo_calls=0 curl_calls=0 http_requests=0 ssh_connections=0 docker_calls=0 compose_calls=0 firewall_changes=0 services_started=0 credentials_read=0 network_attempts=0");
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
console.log("[+] cleanup sentinel_owned_fixture_removed=true preexisting_snapshot_still_present=true");

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function documentedPorts(source) {
  const matches = [...source.matchAll(/cloudflare-origin-lock-ufw\.sh --apply --ports "([0-9 ]+)"/g)];
  assert.ok(matches.length >= 1, "documented origin-lock command is missing");
  const unique = new Set(matches.map((match) => match[1]));
  assert.equal(unique.size, 1, "documented origin-lock commands disagree within one source");
  return parsePorts(matches[0][1]);
}

function parsePorts(value) {
  return value.trim().split(/\s+/).map((port) => Number(port));
}

function functionBlock(source, startName, nextName) {
  const start = source.indexOf(`${startName}() {`);
  const end = source.indexOf(`${nextName}() {`, start + 1);
  assert.notEqual(start, -1, `${startName} is missing`);
  assert.notEqual(end, -1, `${startName} is unterminated`);
  return source.slice(start, end);
}

function rule(family, port, source, comment) {
  return { family, port, source, comment };
}

function baselineRules() {
  return [
    rule("ipv4", 65002, "any", "ssh-recovery"),
    rule("ipv6", 65002, "any", "ssh-recovery"),
    rule("ipv4", 80, "any", "generic-web"),
    rule("ipv6", 80, "any", "generic-web"),
    rule("ipv4", 443, "any", "generic-web"),
    rule("ipv6", 443, "any", "generic-web"),
  ];
}

function applyCandidateOriginLock(inputRules, ports) {
  const rules = structuredClone(inputRules);
  for (const port of ports) {
    rules.push(rule("ipv4", port, "cloudflare", `cloudflare-origin-${port}`));
    rules.push(rule("ipv6", port, "cloudflare", `cloudflare-origin-${port}`));
  }
  return rules;
}

function isAllowed(rules, family, port, source) {
  return rules.some((entry) => entry.family === family && entry.port === port && (entry.source === "any" || entry.source === source));
}

function exposureMatrix(rules, ports) {
  const matrix = [];
  for (const family of ["ipv4", "ipv6"]) {
    for (const port of ports) {
      matrix.push({
        family,
        port,
        untrustedAllowed: isAllowed(rules, family, port, "untrusted"),
        cloudflareAllowed: isAllowed(rules, family, port, "cloudflare"),
      });
    }
  }
  return matrix;
}

function renderUfwStatus(rules, sshPort) {
  const lines = ["Status: active", "To                         Action      From"];
  for (const entry of rules) {
    const suffix = entry.family === "ipv6" ? " (v6)" : "";
    const from = entry.source === "any" ? "Anywhere" : entry.family === "ipv4" ? "203.0.113.0/24" : "2001:db8:100::/48";
    lines.push(`${entry.port}/tcp${suffix} ALLOW ${from}`);
  }
  assert.ok(rules.some((entry) => entry.port === sshPort));
  return `${lines.join("\n")}\n`;
}

function candidateReadinessDecision(status, expectedSshPort) {
  const active = /Status: active/i.test(status);
  const noInternalPorts = !/(^|\s)(3306|5432|6379|4222|8080|9000|9001|9090|9093|3000|3100)\/tcp/m.test(status);
  const sshAllowed = new RegExp(`^${expectedSshPort}\\/tcp(?:\\s|$).*ALLOW`, "m").test(status);
  return { active, noInternalPorts, sshAllowed, passesUfwChecks: active && noInternalPorts && sshAllowed };
}

function candidateDeployLifecycle(source) {
  const activation = source.indexOf("bash ./scripts/compose-vps.sh up -d --build --remove-orphans");
  assert.notEqual(activation, -1);
  const before = source.slice(0, activation);
  const originVerificationBeforeActivation = /cloudflare-origin-lock|origin-lock-verify|ufw status/.test(before);
  return { originVerificationBeforeActivation, activated: true };
}

function reconcileFixed(inputRules, originPorts) {
  const originPortSet = new Set(originPorts);
  const rules = inputRules.filter((entry) => !(originPortSet.has(entry.port) && entry.source === "any"));
  for (const port of originPorts) {
    rules.push(rule("ipv4", port, "cloudflare", `cloudflare-origin-${port}`));
    rules.push(rule("ipv6", port, "cloudflare", `cloudflare-origin-${port}`));
  }
  return rules;
}

function verifyFixedPolicy(rules, publishedPorts) {
  const violations = [];
  for (const family of ["ipv4", "ipv6"]) {
    for (const port of publishedPorts) {
      if (rules.some((entry) => entry.family === family && entry.port === port && entry.source === "any")) {
        violations.push(`generic-${family}-${port}`);
      }
      if (!rules.some((entry) => entry.family === family && entry.port === port && entry.source === "cloudflare")) {
        violations.push(`missing-cloudflare-${family}-${port}`);
      }
      if (isAllowed(rules, family, port, "untrusted")) {
        violations.push(`direct-origin-${family}-${port}`);
      }
    }
  }
  if (!rules.some((entry) => entry.port === 65002 && entry.source === "any")) {
    violations.push("ssh-recovery-missing");
  }
  return [...new Set(violations)];
}

function fixedDeployLifecycle(inputRules, configuredOriginPorts, publishedPorts, injectedRules = []) {
  const rules = reconcileFixed(inputRules, configuredOriginPorts).concat(injectedRules);
  const violations = verifyFixedPolicy(rules, publishedPorts);
  const verified = violations.length === 0;
  return { rules, violations, verified, activated: verified };
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
  const sentinelPath = path.join(targetPath, `.origin-lock-lifecycle-probe-owner-${token}`);
  fs.writeFileSync(sentinelPath, `origin-lock-lifecycle:${token}\n`, {
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
    `origin-lock-lifecycle:${ownership.token}\n`,
    "refusing cleanup without the fixture ownership token",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}
