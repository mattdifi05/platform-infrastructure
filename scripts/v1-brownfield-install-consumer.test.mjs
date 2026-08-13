#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const consumer = path.join(import.meta.dirname, "v1-brownfield-install-consumer.py");
const python = "/usr/bin/python3";
const productionCommit = "832bf2baec47055342af7e7f73425444381b91e0";
const productionTree = "91cee2380809cb0691b9ac47cafa2a673d434caa";
const productionArchive = "6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007";
const testRootEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_ROOT";
const readyButDisabled = [
  "PROVIDER_ADMISSION",
  "DNS_PUBLICATION",
  "DAST",
  "SIGSTORE_PROMOTION",
  "DOCKER_CONTROL_PLANE",
];

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function writeFile(filename, bytes, mode = 0o600) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filename, bytes, { mode });
  fs.chmodSync(filename, mode);
}

function fixed(root, absolutePath) {
  return path.join(root, absolutePath.slice(1));
}

function git(directory, arguments_) {
  const result = spawnSync("/usr/bin/git", arguments_, {
    cwd: directory,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      HOME: "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
  });
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}

function buildArchive(root, checkout) {
  const archive = fixed(root, "/var/lib/platform-infrastructure/v1/predeploy/current/exact-source-archive.tar");
  fs.mkdirSync(path.dirname(archive), { recursive: true, mode: 0o700 });
  const result = spawnSync("/usr/bin/git", ["-c", "tar.umask=0000", "archive", "--format=tar", `--output=${archive}`, "HEAD"], {
    cwd: checkout,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      HOME: "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
  });
  assert.equal(result.status, 0, result.stderr);
  fs.chmodSync(archive, 0o600);
  return { archive, digest: sha256(fs.readFileSync(archive)) };
}

function fixture(t, { faultAfterWrites = null } = {}) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-install-consumer-test-")));
  fs.chmodSync(root, 0o700);
  t.after(() => {
    const pending = [root];
    while (pending.length) {
      const pathname = pending.pop();
      const stat = fs.lstatSync(pathname);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        fs.chmodSync(pathname, 0o700);
        for (const child of fs.readdirSync(pathname)) pending.push(path.join(pathname, child));
      }
    }
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 10 });
  });

  for (const directory of [
    "/home/platform_infrastructure/.v1-release-staging",
    "/var/lib/platform-infrastructure/v1/predeploy/current",
    "/var/lib/platform-infrastructure/v1",
    "/run/lock",
    "/srv",
  ]) {
    fs.mkdirSync(fixed(root, directory), { recursive: true, mode: 0o700 });
    fs.chmodSync(fixed(root, directory), 0o700);
  }

  const stagingParent = fixed(root, "/home/platform_infrastructure/.v1-release-staging");
  const seed = path.join(root, "seed");
  fs.mkdirSync(seed, { mode: 0o700 });
  git(seed, ["init", "--quiet"]);
  git(seed, ["config", "user.name", "V1 Fixture"]);
  git(seed, ["config", "user.email", "v1-fixture@example.invalid"]);
  writeFile(path.join(seed, "README.txt"), "pinned V1 fixture\n", 0o644);
  fs.mkdirSync(path.join(seed, "bin"), { mode: 0o755 });
  writeFile(path.join(seed, "bin", "tool"), "#!/bin/sh\nexit 0\n", 0o755);
  fs.symlinkSync("../README.txt", path.join(seed, "bin", "readme"));
  git(seed, ["add", "."]);
  git(seed, ["commit", "--quiet", "-m", "fixture"]);
  const commit = git(seed, ["rev-parse", "HEAD"]);
  const tree = git(seed, ["rev-parse", "HEAD^{tree}"]);
  const staging = path.join(stagingParent, productionCommit);
  fs.renameSync(seed, staging);

  const { archive, digest } = buildArchive(root, staging);
  const pinsPath = fixed(root, "/var/lib/platform-infrastructure/v1/predeploy/current/.install-consumer-test-pins.json");
  writeFile(pinsPath, `${stableJson({
    candidateCommit: commit,
    candidateTree: tree,
    faultAfterWrites,
    sourceArchiveSha256: digest,
  })}\n`, 0o600);

  const now = Math.floor(Date.now() / 1000);
  const rawArchiveSha256 = "a".repeat(64);
  const checkpoint = fixed(root, "/var/lib/platform-infrastructure/v1/predeploy/current/install-checkpoint.json");
  writeFile(checkpoint, `${stableJson({
    archiveListingSha256: "b".repeat(64),
    authoritative: false,
    backupCapturedUnixSeconds: now - 30,
    backupVerifiedUnixSeconds: now - 10,
    candidateCommit: commit,
    candidateTree: tree,
    logicalEvidenceSha256: "c".repeat(64),
    offHostRawArchiveSha256: rawArchiveSha256,
    rawArchiveSha256,
    restoreEvidenceSha256: "d".repeat(64),
    restoreVerified: true,
    runtimeInventorySha256: "e".repeat(64),
    runtimeRecovered: true,
    runtimeVerifiedUnixSeconds: now - 5,
    sourceArchiveSha256: digest,
  })}\n`, 0o600);

  return {
    archive,
    archiveSha256: digest,
    commit,
    checkpoint,
    finalRelease: fixed(root, `/srv/platform-infrastructure/releases/${productionCommit}-${productionArchive}`),
    pinsPath,
    receipt: fixed(root, `/var/lib/platform-infrastructure/v1/install-receipts/${productionCommit}-${productionArchive}.json`),
    root,
    staging,
    tree,
  };
}

function run(candidate, arguments_ = ["install"], environment = {}) {
  return spawnSync(python, ["-I", consumer, ...arguments_], {
    cwd: "/",
    encoding: "utf8",
    env: {
      ...process.env,
      [testRootEnvironment]: candidate.root,
      PATH: "/attacker/path",
      PYTHONPATH: "/attacker/python",
      PYTHONINSPECT: "1",
      ...environment,
    },
    input: "",
    timeout: 15_000,
  });
}

function parseOutput(result) {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /\n$/);
  const receipt = JSON.parse(result.stdout);
  assert.equal(result.stdout, `${stableJson(receipt)}\n`);
  return receipt;
}

function expectedReceiptKeys() {
  return [
    "activationAuthorized",
    "authorizationSource",
    "backupEvidenceAuthoritative",
    "candidateCommit",
    "candidateTree",
    "dataMutation",
    "dockerMutation",
    "readyButDisabled",
    "releaseRoot",
    "schema",
    "sourceArchiveSha256",
    "status",
  ];
}

test("materializes only the pinned clean source archive and emits the exact closed receipt", (t) => {
  const candidate = fixture(t);
  const receipt = parseOutput(run(candidate));
  assert.equal(receipt.status, "INSTALL_ONLY_COMPLETE");
  assert.deepEqual(Object.keys(receipt).sort(), expectedReceiptKeys());
  assert.equal(receipt.schema, "platform.v1-brownfield-install-receipt/v1");
  assert.equal(receipt.candidateCommit, candidate.commit);
  assert.equal(receipt.candidateTree, candidate.tree);
  assert.equal(receipt.sourceArchiveSha256, candidate.archiveSha256);
  assert.equal(receipt.activationAuthorized, false);
  assert.equal(receipt.authorizationSource, "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY");
  assert.equal(receipt.backupEvidenceAuthoritative, false);
  assert.equal(receipt.dockerMutation, false);
  assert.equal(receipt.dataMutation, false);
  assert.deepEqual(receipt.readyButDisabled, readyButDisabled);
  assert.equal(fs.readFileSync(path.join(candidate.finalRelease, "README.txt"), "utf8"), "pinned V1 fixture\n");
  assert.equal(fs.readlinkSync(path.join(candidate.finalRelease, "bin", "readme")), "../README.txt");
  assert.equal(fs.statSync(path.join(candidate.finalRelease, "bin", "tool")).mode & 0o777, 0o555);
  assert.equal(fs.statSync(candidate.finalRelease).mode & 0o777, 0o555);
  assert.equal(fs.readFileSync(candidate.receipt, "utf8"), `${stableJson(receipt)}\n`);
  assert.equal(fs.statSync(candidate.receipt).mode & 0o777, 0o444);
});

test("an exact second run is idempotent and reports ALREADY_INSTALLED", (t) => {
  const candidate = fixture(t);
  const first = parseOutput(run(candidate));
  const identity = fs.statSync(candidate.finalRelease);
  const second = parseOutput(run(candidate));
  assert.equal(first.status, "INSTALL_ONLY_COMPLETE");
  assert.equal(second.status, "ALREADY_INSTALLED");
  const after = fs.statSync(candidate.finalRelease);
  assert.equal(after.ino, identity.ino);
  assert.equal(after.dev, identity.dev);
  assert.equal(JSON.parse(fs.readFileSync(candidate.receipt, "utf8")).status, "INSTALL_ONLY_COMPLETE");
});

test("rejects every CLI except exact install before entering the seam", () => {
  for (const arguments_ of [[], ["--help"], ["install", "extra"]]) {
    const result = spawnSync(python, ["-I", consumer, ...arguments_], { encoding: "utf8", env: process.env });
    assert.equal(result.status, 64);
    assert.match(result.stderr, /usage/);
  }
});

test("rejects the test seam when invoked as effective UID zero", (t) => {
  if (process.geteuid() !== 0) return t.skip("requires a root test runner");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-root-seam-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.chmodSync(root, 0o700);
  const result = spawnSync(python, ["-I", consumer, "install"], {
    encoding: "utf8",
    env: { ...process.env, [testRootEnvironment]: root },
  });
  assert.equal(result.status, 77);
  assert.match(result.stderr, /test seam is forbidden/);
});

test("rejects dirty and untracked staging without creating a release", (t) => {
  const candidate = fixture(t);
  fs.writeFileSync(path.join(candidate.staging, "untracked"), "unsafe\n");
  const result = run(candidate);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /dirty or contains untracked/);
  assert.equal(fs.existsSync(candidate.finalRelease), false);
});

test("rejects wrong pinned checkout commit and tree before mutation", (t) => {
  const candidate = fixture(t);
  const pins = JSON.parse(fs.readFileSync(candidate.pinsPath, "utf8"));
  pins.candidateCommit = "a".repeat(40);
  writeFile(candidate.pinsPath, `${stableJson(pins)}\n`, 0o600);
  const checkpoint = JSON.parse(fs.readFileSync(candidate.checkpoint, "utf8"));
  checkpoint.candidateCommit = pins.candidateCommit;
  writeFile(candidate.checkpoint, `${stableJson(checkpoint)}\n`, 0o600);
  const result = run(candidate);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /HEAD differs/);
  assert.equal(fs.existsSync(candidate.finalRelease), false);
});

test("requires a fresh byte-equal off-host PRE-DEPLOY checkpoint before mutation", (t) => {
  const missing = fixture(t);
  fs.unlinkSync(missing.checkpoint);
  let result = run(missing);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /checkpoint.*missing/i);
  assert.equal(fs.existsSync(missing.finalRelease), false);

  const stale = fixture(t);
  const checkpoint = JSON.parse(fs.readFileSync(stale.checkpoint, "utf8"));
  checkpoint.backupVerifiedUnixSeconds -= 3600;
  checkpoint.backupCapturedUnixSeconds -= 3600;
  writeFile(stale.checkpoint, `${stableJson(checkpoint)}\n`, 0o600);
  result = run(stale);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /stale/);
  assert.equal(fs.existsSync(stale.finalRelease), false);

  const staleCapture = fixture(t);
  const captureCheckpoint = JSON.parse(fs.readFileSync(staleCapture.checkpoint, "utf8"));
  captureCheckpoint.backupCapturedUnixSeconds -= 3600;
  writeFile(staleCapture.checkpoint, `${stableJson(captureCheckpoint)}\n`, 0o600);
  result = run(staleCapture);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /stale/);
  assert.equal(fs.existsSync(staleCapture.finalRelease), false);

  const mismatched = fixture(t);
  const mismatch = JSON.parse(fs.readFileSync(mismatched.checkpoint, "utf8"));
  mismatch.offHostRawArchiveSha256 = "f".repeat(64);
  writeFile(mismatched.checkpoint, `${stableJson(mismatch)}\n`, 0o600);
  result = run(mismatched);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /raw and off-host archive digests differ/);
  assert.equal(fs.existsSync(mismatched.finalRelease), false);
});

test("a bounded write failure removes its private temporary release", (t) => {
  const candidate = fixture(t, { faultAfterWrites: 1 });
  const result = run(candidate);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /fault injected/);
  assert.equal(fs.existsSync(candidate.finalRelease), false);
  const releaseParent = path.dirname(candidate.finalRelease);
  assert.deepEqual(fs.existsSync(releaseParent) ? fs.readdirSync(releaseParent) : [], []);
});

test("rejects a divergent pre-existing final release", (t) => {
  const candidate = fixture(t);
  fs.mkdirSync(path.dirname(candidate.finalRelease), { recursive: true, mode: 0o700 });
  fs.mkdirSync(candidate.finalRelease, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(candidate.finalRelease, "unexpected"), "unsafe\n");
  fs.chmodSync(candidate.finalRelease, 0o555);
  const result = run(candidate);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /unexpected path|missing/);
});

test("source and test suite preserve the install-only no-Docker no-network boundary", () => {
  const source = fs.readFileSync(consumer, "utf8");
  assert.doesNotMatch(source, /\b(?:docker|podman|nerdctl)\b\s+(?:compose|run|exec|start|stop|rm|volume|network)/i);
  assert.doesNotMatch(source, /\b(?:curl|wget|ssh|scp|rsync|requests|urllib|socket)\b/);
  assert.doesNotMatch(source, /v1-brownfield-admission|platform-activation-request|replay/i);
  assert.match(source, /install-checkpoint\.json/);
  assert.match(source, /PRE-DEPLOY raw and off-host archive digests differ/);
  assert.match(source, /MAX_CHECKPOINT_AGE_SECONDS = 900/);
  assert.match(source, new RegExp(productionCommit));
  assert.match(source, new RegExp(productionTree));
  assert.match(source, new RegExp(productionArchive));
  assert.match(source, /\/usr\/bin\/git/);
  assert.doesNotMatch(source, /shell\s*=\s*True|os\.system|Popen/);
});
