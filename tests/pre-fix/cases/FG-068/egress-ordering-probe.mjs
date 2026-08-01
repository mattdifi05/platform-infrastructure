#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_HASHES = new Map([
  ["scripts/deploy-vps-remote.sh", "e7460e9db36765e6078d778d8a5388d54a78ee4620ddb70f2f7a19187f937804"],
  ["scripts/vps-go-live.sh", "89d824edac428b30673f855f90e7d4710fb784f100c2dab95054a417435bc258"],
  ["scripts/vps-preflight.sh", "7ef50ca582463092bbd0d2e6be5150b2c7cfe7979c931e8c74fe1988fe9eca03"],
  ["scripts/vps-postdeploy.sh", "e88fa132b375d110933e473a0dc80f10ebe06ab37eb8741ba2a8139a06da7963"],
  ["scripts/vps-host-readiness.sh", "a992bb416f7bc2175515cd91b95ba84772d586509002fbe17dd96ad88159f198"],
  ["scripts/prepare-vps-runtime.sh", "e260cd2f9daa7db2f31a911ec50e9086e1ff07974ec3478e938a7456a30a2734"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/workload-egress-firewall.sh", "813217f31244cd909ad55cbe546452afbf5e47d74efd3508e666cfcb67d79a85"],
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
]);

class GateRejection extends Error {
  constructor(reason) {
    super(reason);
    this.name = "GateRejection";
    this.reason = reason;
  }
}

class EgressStartGate {
  constructor(expectedLockDigest, expectedSubnets) {
    assert.match(expectedLockDigest, /^[a-f0-9]{64}$/);
    this.expectedLockDigest = expectedLockDigest;
    this.expectedSubnets = normalizeSubnets(expectedSubnets);
    this.staged = false;
    this.applied = false;
    this.verified = false;
    this.running = false;
    this.trace = [];
  }

  stage(lockDigestValue, subnets) {
    this.#requireLock(lockDigestValue, "stage-lock-mismatch");
    this.#requireSubnets(subnets, "stage-subnet-mismatch");
    if (this.running) throw new GateRejection("workload-already-running");
    this.staged = true;
    this.applied = false;
    this.verified = false;
    this.trace.push("stage-networks-stopped");
  }

  applyPolicy(lockDigestValue, subnets) {
    if (!this.staged) throw new GateRejection("networks-not-staged");
    this.#requireLock(lockDigestValue, "policy-lock-mismatch");
    this.#requireSubnets(subnets, "policy-subnet-mismatch");
    this.applied = true;
    this.verified = false;
    this.trace.push("apply-default-deny");
  }

  verifyPolicy(lockDigestValue, subnets) {
    if (!this.applied) throw new GateRejection("policy-not-applied");
    this.#requireLock(lockDigestValue, "verify-lock-mismatch");
    this.#requireSubnets(subnets, "verify-subnet-mismatch");
    this.verified = true;
    this.trace.push("verify-exact-policy");
  }

  start(lockDigestValue) {
    if (!this.staged) throw new GateRejection("networks-not-staged");
    this.#requireLock(lockDigestValue, "start-lock-mismatch");
    if (!this.verified) throw new GateRejection("policy-not-verified");
    this.running = true;
    this.trace.push("start-workloads");
  }

  #requireLock(actual, reason) {
    if (actual !== this.expectedLockDigest) throw new GateRejection(reason);
  }

  #requireSubnets(actual, reason) {
    if (JSON.stringify(normalizeSubnets(actual)) !== JSON.stringify(this.expectedSubnets)) {
      throw new GateRejection(reason);
    }
  }
}

const sourceArgument = process.argv[2];
const labArgument = process.argv[3];
if (!sourceArgument || !labArgument) {
  throw new Error(
    "usage: egress-ordering-probe.mjs WRAPPER_OWNED_SOURCE WRAPPER_OWNED_LAB",
  );
}

const {
  sourceRoot,
  labRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedPaths(sourceArgument, labArgument);
const sourceBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source and lab boundaries verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const remoteSource = readSource("scripts/deploy-vps-remote.sh");
const goLiveSource = readSource("scripts/vps-go-live.sh");
const preflightSource = readSource("scripts/vps-preflight.sh");
const postdeploySource = readSource("scripts/vps-postdeploy.sh");
const readinessSource = readSource("scripts/vps-host-readiness.sh");
const runtimePreparationSource = readSource("scripts/prepare-vps-runtime.sh");
const composeSource = readSource("scripts/compose-vps.sh");
const firewallSource = readSource("scripts/workload-egress-firewall.sh");
const workloadContractSource = readSource("scripts/hosted-workload-contract.mjs");

const remoteSequence = {
  preflight: lineOf(remoteSource, /^sh \.\/scripts\/vps-preflight\.sh "\$env_file"$/m),
  start: lineOf(
    remoteSource,
    /^\s*bash \.\/scripts\/compose-vps\.sh up -d --build --remove-orphans$/m,
  ),
  postdeploy: lineOf(remoteSource, /^\s*sh \.\/scripts\/vps-postdeploy\.sh "\$env_file"$/m),
};
assertOrdering(remoteSequence, "remote deployment");

const goLiveSequence = {
  preflight: lineOf(goLiveSource, /^run_step "vps-preflight" /m),
  start: lineOf(goLiveSource, /^\s*run_step "compose-up" /m),
  postdeploy: lineOf(goLiveSource, /^run_step "vps-postdeploy" /m),
};
assertOrdering(goLiveSequence, "go-live deployment");

for (const [name, source] of [
  ["remote deployment", remoteSource],
  ["go-live deployment", goLiveSource],
  ["preflight", preflightSource],
  ["postdeploy", postdeploySource],
  ["host readiness", readinessSource],
  ["runtime preparation", runtimePreparationSource],
]) {
  assert.doesNotMatch(
    source,
    /workload-egress-firewall|PLATFORM-WORKLOAD-EGRESS|DOCKER-USER/,
    `${name} unexpectedly invokes or verifies the dedicated egress gate`,
  );
}

assert.match(
  composeSource,
  /exec "\$\{compose\[@\]\}" --profile backup "\$@"/,
  "the Compose wrapper no longer forwards the requested lifecycle command",
);
assert.match(
  workloadContractSource,
  /if \(network\?\.internal === true \|\| network\?\.enable_ipv6 === true\) invalid\(`Workload egress network \$\{name\} must allow IPv4 egress with IPv6 disabled\.`\);/,
  "the hosted workload contract no longer requires an outward-routable IPv4 egress network",
);

assert.match(firewallSource, /^MODE=plan$/m);
assert.ok(
  firewallSource.includes('"${NETWORK_PREFIX}"_app_*_egress)'),
  "the firewall no longer discovers per-workload egress networks",
);
assert.match(firewallSource, /docker network ls --format/);
assert.match(firewallSource, /Mode: plan; no firewall mutation executed\./);
assert.match(firewallSource, /--apply requires root/);
assert.match(firewallSource, /APPLY-WORKLOAD-EGRESS-FIREWALL/);
assert.match(firewallSource, /iptables -w -F "\$CHAIN"/);
assert.match(firewallSource, /^verify_rules$/m);

console.log(
  `[TRACE] deploy_remote=preflight@${remoteSequence.preflight}>compose-up@${remoteSequence.start}>postdeploy@${remoteSequence.postdeploy} firewall_call=absent`,
);
console.log(
  `[TRACE] go_live=preflight@${goLiveSequence.preflight}>compose-up@${goLiveSequence.start}>postdeploy@${goLiveSequence.postdeploy} firewall_call=absent`,
);

const vulnerableTrace = simulateUngatedDeployment([
  "preflight",
  "compose-up",
  "postdeploy",
]);
assert.equal(vulnerableTrace.unsafeStartObserved, true);
assert.equal(vulnerableTrace.firewallVerifiedAtStart, false);
console.log(
  "[VULNERABLE] workload_started=true firewall_verified_at_start=false prestart_default_deny=false",
);

const lockDigest = sha256Text("verified-workload-lock-v1");
const expectedSubnets = ["172.30.10.0/24", "172.30.11.0/24"];
const wrongSubnets = ["172.30.10.0/24", "172.30.99.0/24"];

assert.equal(
  rejectedReason(() => {
    const gate = new EgressStartGate(lockDigest, expectedSubnets);
    gate.start(lockDigest);
  }),
  "networks-not-staged",
);

assert.equal(
  rejectedReason(() => {
    const gate = new EgressStartGate(lockDigest, expectedSubnets);
    gate.stage(lockDigest, expectedSubnets);
    gate.start(lockDigest);
  }),
  "policy-not-verified",
);

assert.equal(
  rejectedReason(() => {
    const gate = new EgressStartGate(lockDigest, expectedSubnets);
    gate.stage(lockDigest, expectedSubnets);
    gate.applyPolicy(lockDigest, expectedSubnets);
    gate.start(lockDigest);
  }),
  "policy-not-verified",
);

assert.equal(
  rejectedReason(() => {
    const gate = new EgressStartGate(lockDigest, expectedSubnets);
    gate.stage(lockDigest, expectedSubnets);
    gate.applyPolicy(sha256Text("stale-workload-lock"), expectedSubnets);
  }),
  "policy-lock-mismatch",
);

assert.equal(
  rejectedReason(() => {
    const gate = new EgressStartGate(lockDigest, expectedSubnets);
    gate.stage(lockDigest, expectedSubnets);
    gate.applyPolicy(lockDigest, wrongSubnets);
  }),
  "policy-subnet-mismatch",
);

const fixedGate = new EgressStartGate(lockDigest, expectedSubnets);
fixedGate.stage(lockDigest, expectedSubnets);
fixedGate.applyPolicy(lockDigest, expectedSubnets);
fixedGate.verifyPolicy(lockDigest, expectedSubnets);
fixedGate.start(lockDigest);
assert.deepEqual(fixedGate.trace, [
  "stage-networks-stopped",
  "apply-default-deny",
  "verify-exact-policy",
  "start-workloads",
]);
assert.equal(fixedGate.running, true);
console.log(
  "[CONTROL] uncreated_networks=rejected missing_policy=rejected unverified_policy=rejected stale_lock=rejected wrong_subnets=rejected exact_verified_policy=accepted",
);

const traceArtifact = {
  schemaVersion: 1,
  sourceRevision: REVISION,
  sourceTree: TREE,
  remoteSequence,
  goLiveSequence,
  vulnerable: vulnerableTrace,
  fixed: {
    lockDigest,
    expectedSubnets,
    trace: fixedGate.trace,
    running: fixedGate.running,
  },
};
const tracePath = path.join(labRoot, "ordering-trace.json");
fs.writeFileSync(tracePath, `${JSON.stringify(traceArtifact, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600,
});
const roundTrip = JSON.parse(fs.readFileSync(tracePath, "utf8"));
assert.equal(roundTrip.vulnerable.unsafeStartObserved, true);
assert.deepEqual(roundTrip.fixed.trace, fixedGate.trace);

assert.equal(directoryDigest(sourceRoot), sourceBefore, "the source snapshot changed during the PoC");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the PoC");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the PoC");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the PoC");

console.log(
  "[+] summary unsafe_order_reproduced=true fixed_gate_enforced=true source_tree_unchanged=true",
);
console.log(
  "[+] no firewall command, network socket, Docker, SSH, sudo, credential, or live target was accessed",
);

function rejectedReason(action) {
  try {
    action();
  } catch (error) {
    if (error instanceof GateRejection) return error.reason;
    throw error;
  }
  return "not-rejected";
}

function simulateUngatedDeployment(events) {
  let firewallVerified = false;
  let unsafeStartObserved = false;
  for (const event of events) {
    if (event === "firewall-verify") firewallVerified = true;
    if (event === "compose-up" && !firewallVerified) unsafeStartObserved = true;
  }
  return {
    events,
    workloadStarted: events.includes("compose-up"),
    firewallVerifiedAtStart: events.indexOf("firewall-verify") >= 0
      && events.indexOf("firewall-verify") < events.indexOf("compose-up"),
    unsafeStartObserved,
  };
}

function assertOrdering(sequence, label) {
  assert.ok(sequence.preflight < sequence.start, `${label} does not start after preflight`);
  assert.ok(sequence.start < sequence.postdeploy, `${label} does not run postdeploy after start`);
}

function lineOf(source, pattern) {
  const offset = source.search(pattern);
  assert.notEqual(offset, -1, `source pattern not found: ${pattern}`);
  return source.slice(0, offset).split("\n").length;
}

function normalizeSubnets(values) {
  assert.ok(Array.isArray(values) && values.length > 0, "subnet set must not be empty");
  const normalized = [...new Set(values.map(String))].sort();
  for (const subnet of normalized) {
    assert.match(subnet, /^[0-9]+(?:\.[0-9]+){3}\/[0-9]{1,2}$/);
  }
  return normalized;
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function validateWrapperOwnedPaths(sourceInput, labInput) {
  const wrapperInput = requiredEnvironment("FG068_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG068_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG068_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg068-(?:guard|run)\.[A-Za-z0-9]+$/,
    "wrapper temporary root does not have the expected mktemp name",
  );

  const sourcePath = path.resolve(sourceInput);
  const sourceStat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(sourcePath);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned source child");

  const sentinelPath = path.resolve(sentinelInput);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside the wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg068-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg068-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG068-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  const labPath = path.resolve(labInput);
  const labStat = fs.lstatSync(labPath, { throwIfNoEntry: false });
  assert.ok(labStat?.isDirectory(), "wrapper laboratory directory is missing");
  assert.equal(labStat.isSymbolicLink(), false, "wrapper laboratory directory must not be a symlink");
  const labReal = fs.realpathSync(labPath);
  assert.equal(labReal, path.join(wrapperReal, "lab"), "lab must be the exact wrapper-owned lab child");
  assert.deepEqual(fs.readdirSync(labReal), [], "wrapper laboratory directory must start empty");

  return {
    sourceRoot: sourceReal,
    labRoot: labReal,
    sentinelPath: sentinelReal,
    sentinelText,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
  };
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke through run-from-git-archive.sh`);
  }
  return value;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function sha256Text(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function directoryDigest(root) {
  const digest = crypto.createHash("sha256");
  walk(root, "");
  return digest.digest("hex");

  function walk(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      digest.update(`L\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    if (stat.isDirectory()) {
      digest.update(`D\0${relative}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        walk(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    assert.equal(stat.isFile(), true, `unsupported archived entry: ${relative}`);
    digest.update(`F\0${relative}\0`);
    digest.update(fs.readFileSync(current));
    digest.update("\0");
  }
}
