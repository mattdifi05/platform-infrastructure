#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const consumer = path.join(import.meta.dirname, "v1-brownfield-install-consumer.py");
const productionSudoers = path.join(import.meta.dirname, "..", "sudoers", "platform-v1-local-private-control");
const python = "/usr/bin/python3";
const testRootEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_ROOT";
const testFaultEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_FAULT_AFTER_WRITES";
const testVisudoEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_VISUDO";
const testSystemdAnalyzeEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_SYSTEMD_ANALYZE";
const testSystemctlEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_SYSTEMCTL";
const testArtifactCrashEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_CRASH_AFTER_ARTIFACT_REPLACEMENTS";
const testArtifactRollbackCrashEnvironment = "PLATFORM_V1_INSTALL_CONSUMER_TEST_CRASH_AFTER_ARTIFACT_ROLLBACK_STEPS";
const installedConsumerPath = "/usr/local/libexec/platform-v1-brownfield-install-consumer";
const installLockPath = "/run/lock/platform-v1-brownfield-install.lock";
const transactionLockPath = "/run/lock/platform-v1-local-private-transaction.lock";
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
  fs.chmodSync(archive, 0o444);
  return { archive, digest: sha256(fs.readFileSync(archive)) };
}

function fixture(t, {
  faultAfterWrites = null,
  sudoersBytes = fs.readFileSync(productionSudoers),
} = {}) {
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
    "/etc/sudoers.d",
    "/etc/systemd/system",
    "/home/platform_infrastructure/.v1-release-staging",
    "/usr/local/libexec",
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
  writeFile(path.join(seed, "README.txt"), "checkpoint-bound V1 fixture\n", 0o644);
  fs.mkdirSync(path.join(seed, "bin"), { mode: 0o755 });
  writeFile(path.join(seed, "bin", "tool"), "#!/bin/sh\nexit 0\n", 0o755);
  fs.symlinkSync("../README.txt", path.join(seed, "bin", "readme"));
  fs.mkdirSync(path.join(seed, "scripts"), { mode: 0o755 });
  fs.mkdirSync(path.join(seed, "systemd"), { mode: 0o755 });
  fs.mkdirSync(path.join(seed, "sudoers"), { mode: 0o755 });
  writeFile(
    path.join(seed, "scripts", "v1-brownfield-install-consumer.py"),
    fs.readFileSync(consumer),
    0o755,
  );
  writeFile(
    path.join(seed, "scripts", "v1-local-private-control.py"),
    "#!/usr/bin/python3 -I\nraise SystemExit(0)\n",
    0o755,
  );
  writeFile(
    path.join(seed, "scripts", "v1-local-private-reconcile.py"),
    "#!/usr/bin/python3 -I\nraise SystemExit(0)\n",
    0o755,
  );
  writeFile(
    path.join(seed, "systemd", "platform-v1-local-private-control.service"),
    "[Unit]\nDescription=V1 test control\n[Service]\nType=simple\nExecStart=/usr/local/libexec/platform-v1-local-private-control supervise\n",
    0o644,
  );
  writeFile(
    path.join(seed, "sudoers", "platform-v1-local-private-control"),
    sudoersBytes,
    0o644,
  );
  git(seed, ["add", "."]);
  git(seed, ["commit", "--quiet", "-m", "fixture"]);
  const commit = git(seed, ["rev-parse", "HEAD"]);
  const tree = git(seed, ["rev-parse", "HEAD^{tree}"]);
  const staging = path.join(stagingParent, commit);
  fs.renameSync(seed, staging);

  const { archive, digest } = buildArchive(root, staging);

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

  const tools = path.join(root, "tools");
  fs.mkdirSync(tools, { mode: 0o700 });
  const visudo = path.join(tools, "visudo");
  const systemdAnalyze = path.join(tools, "systemd-analyze");
  const systemctl = path.join(tools, "systemctl");
  const systemctlLog = path.join(root, "systemctl.log");
  writeFile(visudo, "#!/bin/sh\n[ \"$1\" = -c ] && [ \"$2\" = -f ] && [ -f \"$3\" ]\n", 0o700);
  writeFile(systemdAnalyze, "#!/bin/sh\n[ \"$1\" = verify ] && [ -f \"$2\" ] && [ \"${2##*.}\" = service ]\n", 0o700);
  writeFile(systemctl, `#!/bin/sh\nprintf '%s\\n' "$*" >> ${JSON.stringify(systemctlLog)}\n[ "$1" = daemon-reload ]\n`, 0o700);

  const artifactTargets = [
    ["installer", "/usr/local/libexec/platform-v1-brownfield-install-consumer", 0o555],
    ["controller", "/usr/local/libexec/platform-v1-local-private-control", 0o555],
    ["reconciler", "/usr/local/libexec/platform-v1-local-private-reconcile", 0o555],
    ["unit", "/etc/systemd/system/platform-v1-local-private-control.service", 0o444],
    ["sudoers", "/etc/sudoers.d/platform-v1-local-private-control", 0o440],
  ];
  for (const [name, logical, mode] of artifactTargets) {
    writeFile(fixed(root, logical), `old-${name}\n`, mode);
  }

  return {
    archive,
    archiveSha256: digest,
    commit,
    checkpoint,
    faultAfterWrites,
    finalRelease: fixed(root, `/srv/platform-infrastructure/releases/${commit}-${digest}`),
    receipt: fixed(root, `/var/lib/platform-infrastructure/v1/install-receipts/${commit}-${digest}.json`),
    root,
    staging,
    artifactTargets,
    systemctl,
    systemctlLog,
    toolEnvironment: {
      [testVisudoEnvironment]: visudo,
      [testSystemdAnalyzeEnvironment]: systemdAnalyze,
      [testSystemctlEnvironment]: systemctl,
    },
    tree,
  };
}

function runExecutable(candidate, executable, arguments_ = ["install"], environment = {}) {
  return spawnSync(python, ["-I", executable, ...arguments_], {
    cwd: "/",
    encoding: "utf8",
    env: {
      ...process.env,
      [testRootEnvironment]: candidate.root,
      PATH: "/attacker/path",
      PYTHONPATH: "/attacker/python",
      PYTHONINSPECT: "1",
      ...(candidate.faultAfterWrites === null ? {} : { [testFaultEnvironment]: String(candidate.faultAfterWrites) }),
      ...candidate.toolEnvironment,
      ...environment,
    },
    input: "",
    timeout: 15_000,
  });
}

function run(candidate, arguments_ = ["install"], environment = {}) {
  return runExecutable(candidate, consumer, arguments_, environment);
}

function runInstalled(candidate, arguments_ = ["install"], environment = {}) {
  return runExecutable(candidate, fixed(candidate.root, installedConsumerPath), arguments_, environment);
}

function runReleaseConsumer(candidate, arguments_ = ["install"], environment = {}) {
  return runExecutable(
    candidate,
    path.join(candidate.finalRelease, "scripts", "v1-brownfield-install-consumer.py"),
    arguments_,
    environment,
  );
}

function installPriorSupportedConsumer(candidate) {
  const bytes = Buffer.concat([
    fs.readFileSync(consumer),
    Buffer.from("\n# prior-supported installed-consumer fixture\n"),
  ]);
  const target = fixed(candidate.root, installedConsumerPath);
  fs.chmodSync(target, 0o600);
  writeFile(target, bytes, 0o555);
  return bytes;
}

function snapshotArtifacts(candidate) {
  return new Map(candidate.artifactTargets.map(([, logical]) => {
    const target = fixed(candidate.root, logical);
    return [logical, {
      bytes: fs.readFileSync(target),
      mode: fs.statSync(target).mode & 0o777,
    }];
  }));
}

function assertArtifacts(candidate, expected) {
  for (const [, logical] of candidate.artifactTargets) {
    const target = fixed(candidate.root, logical);
    assert.deepEqual(fs.readFileSync(target), expected.get(logical).bytes, logical);
    assert.equal(fs.statSync(target).mode & 0o777, expected.get(logical).mode, logical);
  }
}

function advanceCandidate(candidate) {
  writeFile(path.join(candidate.staging, "README.txt"), "checkpoint-bound V1 fixture candidate B\n", 0o644);
  git(candidate.staging, ["add", "README.txt"]);
  git(candidate.staging, ["commit", "--quiet", "-m", "candidate B"]);
  const commit = git(candidate.staging, ["rev-parse", "HEAD"]);
  const tree = git(candidate.staging, ["rev-parse", "HEAD^{tree}"]);
  const staging = path.join(path.dirname(candidate.staging), commit);
  fs.renameSync(candidate.staging, staging);
  fs.chmodSync(candidate.archive, 0o600);
  fs.unlinkSync(candidate.archive);
  const { digest } = buildArchive(candidate.root, staging);
  const checkpoint = JSON.parse(fs.readFileSync(candidate.checkpoint, "utf8"));
  const now = Math.floor(Date.now() / 1000);
  Object.assign(checkpoint, {
    backupCapturedUnixSeconds: now - 30,
    backupVerifiedUnixSeconds: now - 10,
    candidateCommit: commit,
    candidateTree: tree,
    runtimeVerifiedUnixSeconds: now - 5,
    sourceArchiveSha256: digest,
  });
  writeFile(candidate.checkpoint, `${stableJson(checkpoint)}\n`, 0o600);
  return {
    ...candidate,
    archiveSha256: digest,
    commit,
    finalRelease: fixed(candidate.root, `/srv/platform-infrastructure/releases/${commit}-${digest}`),
    receipt: fixed(candidate.root, `/var/lib/platform-infrastructure/v1/install-receipts/${commit}-${digest}.json`),
    staging,
    tree,
  };
}

function useTransportCheckpoint(candidate, overrides = {}) {
  const checkpoint = {
    activationAuthorized: false,
    authoritative: false,
    backupEvidenceAuthoritative: false,
    bridgeSha256: sha256("bootstrap-bridge"),
    candidateCommit: candidate.commit,
    candidateConsumerSha256: sha256(fs.readFileSync(consumer)),
    candidateTree: candidate.tree,
    createdAtUnixSeconds: Math.floor(Date.now() / 1000),
    gitBundleSha256: sha256("git-bundle"),
    purpose: "CONTROL_PLANE_STAGING_ONLY",
    schema: "platform.v1-bootstrap-transport-checkpoint/v1",
    sourceArchiveSha256: candidate.archiveSha256,
    sourceArchiveSizeBytes: fs.statSync(candidate.archive).size,
    transportVerified: true,
    ...overrides,
  };
  writeFile(candidate.checkpoint, `${stableJson(checkpoint)}\n`, 0o600);
  return checkpoint;
}

async function holdExclusiveLock(t, filename) {
  const code = [
    "import fcntl, os, sys",
    "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)",
    "os.fchmod(fd, 0o600)",
    "fcntl.flock(fd, fcntl.LOCK_EX)",
    "print('READY', flush=True)",
    "sys.stdin.buffer.read()",
    "os.close(fd)",
  ].join("\n");
  const child = spawn(python, ["-I", "-c", code, filename], {
    cwd: "/",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const completion = new Promise((resolve) => child.once("close", (status, signal) => resolve({ signal, status })));
  await new Promise((resolve, reject) => {
    child.stdout.setEncoding("utf8");
    child.stdout.once("data", (chunk) => {
      if (chunk === "READY\n") resolve();
      else reject(new Error(`unexpected lock holder output: ${chunk}`));
    });
    child.once("error", reject);
    child.once("exit", (status, signal) => {
      if (status !== null || signal !== null) reject(new Error(`lock holder exited early: ${status}/${signal}: ${stderr}`));
    });
  });
  let released = false;
  const release = async () => {
    if (released) return;
    released = true;
    child.stdin.end();
    const result = await completion;
    assert.equal(result.signal, null, stderr);
    assert.equal(result.status, 0, stderr);
  };
  t.after(release);
  return release;
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

test("materializes only the checkpoint-bound clean source archive and emits the exact closed receipt", (t) => {
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
  assert.equal(fs.readFileSync(path.join(candidate.finalRelease, "README.txt"), "utf8"), "checkpoint-bound V1 fixture\n");
  assert.equal(fs.readlinkSync(path.join(candidate.finalRelease, "bin", "readme")), "../README.txt");
  assert.equal(fs.statSync(path.join(candidate.finalRelease, "bin", "tool")).mode & 0o777, 0o555);
  assert.equal(fs.statSync(candidate.finalRelease).mode & 0o777, 0o555);
  assert.equal(fs.readFileSync(candidate.receipt, "utf8"), `${stableJson(receipt)}\n`);
  assert.equal(fs.statSync(candidate.receipt).mode & 0o777, 0o444);
});

test("the one-time bootstrap verb accepts only a non-authoritative transport checkpoint", (t) => {
  const candidate = fixture(t);
  const checkpoint = useTransportCheckpoint(candidate);
  assert.equal(checkpoint.authoritative, false);
  assert.equal(checkpoint.backupEvidenceAuthoritative, false);
  assert.equal(checkpoint.activationAuthorized, false);
  assert.equal("restoreVerified" in checkpoint, false);
  assert.equal("runtimeRecovered" in checkpoint, false);

  let result = run(candidate, ["install"]);
  assert.equal(result.status, 64);
  assert.match(result.stderr, /exact bootstrap-install verb/);
  assert.equal(fs.existsSync(candidate.finalRelease), false);

  const installReceipt = parseOutput(run(candidate, ["bootstrap-install"]));
  assert.equal(installReceipt.status, "INSTALL_ONLY_COMPLETE");
  assert.equal(installReceipt.backupEvidenceAuthoritative, false);
  assert.equal(installReceipt.activationAuthorized, false);
  assert.equal(installReceipt.dataMutation, false);
  assert.equal(installReceipt.dockerMutation, false);

  const controlReceipt = parseOutput(run(candidate, ["install-control-artifacts"]));
  assert.equal(controlReceipt.status, "CONTROL_ARTIFACTS_INSTALLED");
  assert.equal(controlReceipt.dataMutation, false);
  assert.equal(controlReceipt.dockerMutation, false);
});

test("bootstrap transport rejects stale or authority-expanding checkpoints before release mutation", (t) => {
  for (const overrides of [
    { createdAtUnixSeconds: Math.floor(Date.now() / 1000) - 901 },
    { backupEvidenceAuthoritative: true },
    { activationAuthorized: true },
    { purpose: "CUTOVER" },
    { transportVerified: false },
  ]) {
    const candidate = fixture(t);
    useTransportCheckpoint(candidate, overrides);
    const result = run(candidate, ["bootstrap-install"]);
    assert.equal(result.status, 78);
    assert.match(result.stderr, /transport checkpoint/);
    assert.equal(fs.existsSync(candidate.finalRelease), false);
  }
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

test("installs the exact V1 control artifacts atomically without activation or Docker", (t) => {
  const candidate = fixture(t);
  parseOutput(run(candidate));
  const receipt = parseOutput(run(candidate, ["install-control-artifacts"]));
  assert.equal(receipt.status, "CONTROL_ARTIFACTS_INSTALLED");
  assert.equal(receipt.candidateCommit, candidate.commit);
  assert.equal(receipt.candidateTree, candidate.tree);
  assert.equal(receipt.sourceArchiveSha256, candidate.archiveSha256);
  assert.equal(receipt.dockerMutation, false);
  assert.equal(receipt.dataMutation, false);
  assert.equal(receipt.hostControlMutation, true);
  assert.deepEqual(receipt.artifacts.map(({ name }) => name), candidate.artifactTargets.map(([name]) => name));
  assert.deepEqual(receipt.artifacts.map(({ name }) => name), ["installer", "controller", "reconciler", "unit", "sudoers"]);
  for (const [name, logical, mode] of candidate.artifactTargets) {
    const installed = fixed(candidate.root, logical);
    const source = path.join(candidate.finalRelease, name === "installer"
      ? "scripts/v1-brownfield-install-consumer.py"
      : name === "controller"
        ? "scripts/v1-local-private-control.py"
        : name === "reconciler"
          ? "scripts/v1-local-private-reconcile.py"
          : name === "unit"
            ? "systemd/platform-v1-local-private-control.service"
            : "sudoers/platform-v1-local-private-control");
    assert.deepEqual(fs.readFileSync(installed), fs.readFileSync(source));
    assert.equal(fs.statSync(installed).mode & 0o777, mode);
  }
  assert.equal(fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction")), false);
  assert.equal(fs.readFileSync(candidate.systemctlLog, "utf8"), "daemon-reload\n");

  const second = parseOutput(run(candidate, ["install-control-artifacts"]));
  assert.equal(second.status, "ALREADY_INSTALLED");
  assert.equal(second.hostControlMutation, false);
  assert.doesNotMatch(fs.readFileSync(candidate.systemctlLog, "utf8"), /restart|start|enable/);
});

test("the closed sudoers set retains exact verify and candidate-B install authority", (t) => {
  const candidateA = fixture(t);
  parseOutput(run(candidateA));
  parseOutput(run(candidateA, ["install-control-artifacts"]));
  const installedSudoers = fs.readFileSync(
    fixed(candidateA.root, "/etc/sudoers.d/platform-v1-local-private-control"),
    "utf8",
  );
  assert.equal(installedSudoers, fs.readFileSync(productionSudoers, "utf8"));
  assert.equal(installedSudoers.trimEnd().split("\n").length, 21);
  for (const command of ["aborted-record", "runtime-authority", "validation-mode"]) {
    assert.match(installedSudoers, new RegExp(`platform-v1-local-private-control ${command}\\n`));
  }
  assert.match(installedSudoers, /platform-v1-local-private-control verify\n/);
  for (const command of ["validation-open", "validation-close"]) {
    assert.match(installedSudoers, new RegExp(`platform-v1-local-private-reconcile ${command}\\n`));
  }
  assert.match(installedSudoers, /platform-v1-brownfield-install-consumer install\n/);
  assert.match(installedSudoers, /\/usr\/bin\/cat \/var\/lib\/platform-infrastructure\/v1\/predeploy\/current\/offhost-backup-evidence\.json\n/);
  assert.match(installedSudoers, /\/usr\/bin\/cat \/var\/lib\/platform-infrastructure\/v1\/predeploy\/current\/secrets-backup-evidence\.json\n/);

  const candidateB = advanceCandidate(candidateA);
  const receipt = parseOutput(runInstalled(candidateB, ["install"]));
  assert.equal(receipt.status, "INSTALL_ONLY_COMPLETE");
  assert.equal(receipt.candidateCommit, candidateB.commit);
  assert.equal(receipt.candidateTree, candidateB.tree);
  assert.equal(receipt.sourceArchiveSha256, candidateB.archiveSha256);
  assert.equal(
    fs.readFileSync(path.join(candidateB.finalRelease, "README.txt"), "utf8"),
    "checkpoint-bound V1 fixture candidate B\n",
  );
});

test("control-artifact install takes the shared maintenance lock before its private lock", async (t) => {
  const candidate = fixture(t);
  const release = await holdExclusiveLock(t, fixed(candidate.root, transactionLockPath));

  // Additive source materialization is outside the maintenance mutation domain.
  const installReceipt = parseOutput(run(candidate, ["install"]));
  assert.equal(installReceipt.status, "INSTALL_ONLY_COMPLETE");

  const blocked = run(candidate, ["install-control-artifacts"]);
  assert.equal(blocked.status, 75);
  assert.match(blocked.stderr, /another V1 local-private maintenance transaction is active/);
  assert.equal(
    fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction")),
    false,
  );

  const source = fs.readFileSync(consumer, "utf8");
  const controlBody = source.slice(
    source.indexOf("def install_control_artifacts()"),
    source.indexOf("\ndef main("),
  );
  assert.ok(
    controlBody.indexOf("transaction_lock_descriptor = acquire_transaction_lock()")
      < controlBody.indexOf("lock_descriptor = acquire_lock()"),
  );

  await release();
  const releaseInstallLock = await holdExclusiveLock(t, fixed(candidate.root, installLockPath));
  const privateBlocked = run(candidate, ["install-control-artifacts"]);
  assert.equal(privateBlocked.status, 75);
  assert.match(privateBlocked.stderr, /another V1 install-only transaction is active/);
  // Failure on the second lock must release the first lock immediately.
  const releaseTransactionProbe = await holdExclusiveLock(
    t,
    fixed(candidate.root, transactionLockPath),
  );
  await releaseTransactionProbe();
  await releaseInstallLock();

  const receipt = parseOutput(run(candidate, ["install-control-artifacts"]));
  assert.equal(receipt.status, "CONTROL_ARTIFACTS_INSTALLED");
});

test("rejects every sudoers deviation before the first artifact write", (t) => {
  const exact = fs.readFileSync(productionSudoers, "utf8");
  const mutations = [
    exact.replace(
      "platform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-control activate",
      "platform_infrastructure ALL=(root) NOPASSWD: ALL",
    ),
    exact.replace(
      "/usr/local/libexec/platform-v1-local-private-control activate",
      "/usr/local/libexec/platform-v1-local-private-control *",
    ),
    exact.replace(
      "platform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-control verify\n",
      "",
    ),
    exact.replace(
      "/usr/local/libexec/platform-v1-brownfield-install-consumer install\n",
      "/usr/local/libexec/platform-v1-brownfield-install-consumer install *\n",
    ),
    exact.replace(
      "/usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json\n",
      "/usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/*\n",
    ),
    exact.replace(
      "platform_infrastructure ALL=(root) NOPASSWD: /usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json\n",
      "",
    ),
    exact.replace(
      "platform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-reconcile validation-open\n",
      "",
    ),
    exact.replace(
      "/usr/local/libexec/platform-v1-local-private-reconcile validation-close\n",
      "/usr/local/libexec/platform-v1-local-private-reconcile validation-close *\n",
    ),
    `${exact}@include /etc/sudoers.d/attacker\n`,
    exact.replace(
      "Defaults:platform_infrastructure env_reset\n",
      "Defaults:platform_infrastructure env_reset \\\n,authenticate\n",
    ),
    `${exact}${exact.split("\n")[2]}\n`,
  ];

  for (const sudoersBytes of mutations) {
    const candidate = fixture(t, { sudoersBytes });
    parseOutput(run(candidate));
    const preimages = new Map(candidate.artifactTargets.map(([, logical]) => {
      const target = fixed(candidate.root, logical);
      const metadata = fs.statSync(target);
      return [logical, {
        bytes: fs.readFileSync(target),
        device: metadata.dev,
        inode: metadata.ino,
        mode: metadata.mode & 0o777,
      }];
    }));

    const result = run(candidate, ["install-control-artifacts"]);
    assert.equal(result.status, 78);
    assert.match(result.stderr, /exact closed twenty-one-line grant set/);
    assert.equal(
      fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction")),
      false,
    );
    for (const [, logical] of candidate.artifactTargets) {
      const target = fixed(candidate.root, logical);
      const metadata = fs.statSync(target);
      const before = preimages.get(logical);
      assert.deepEqual(fs.readFileSync(target), before.bytes);
      assert.equal(metadata.dev, before.device);
      assert.equal(metadata.ino, before.inode);
      assert.equal(metadata.mode & 0o777, before.mode);
    }
  }
});

test("a post-write daemon-reload failure restores every exact preimage", (t) => {
  const candidate = fixture(t);
  parseOutput(run(candidate));
  const preimages = new Map(candidate.artifactTargets.map(([, logical]) => {
    const target = fixed(candidate.root, logical);
    return [logical, { bytes: fs.readFileSync(target), mode: fs.statSync(target).mode & 0o777 }];
  }));
  const reloadCount = path.join(candidate.root, "reload-count");
  writeFile(candidate.systemctl, `#!/bin/sh
[ "$1" = daemon-reload ] || exit 91
count=0
[ ! -f ${JSON.stringify(reloadCount)} ] || count=$(/bin/cat ${JSON.stringify(reloadCount)})
count=$((count + 1))
printf '%s\n' "$count" > ${JSON.stringify(reloadCount)}
[ "$count" -ne 1 ]
`, 0o700);
  const result = run(candidate, ["install-control-artifacts"]);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /systemctl daemon-reload rejected/);
  assert.equal(fs.readFileSync(reloadCount, "utf8"), "2\n");
  for (const [, logical] of candidate.artifactTargets) {
    const target = fixed(candidate.root, logical);
    assert.deepEqual(fs.readFileSync(target), preimages.get(logical).bytes);
    assert.equal(fs.statSync(target).mode & 0o777, preimages.get(logical).mode);
  }
  assert.equal(fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction")), false);
});

test("a prior-supported installed consumer recovers all five install replacement crash boundaries", (t) => {
  const candidate = fixture(t);
  parseOutput(run(candidate));
  const priorConsumer = installPriorSupportedConsumer(candidate);
  const preimages = snapshotArtifacts(candidate);
  const visudo = candidate.toolEnvironment[testVisudoEnvironment];
  const validVisudo = fs.readFileSync(visudo);

  for (let boundary = 1; boundary <= 5; boundary += 1) {
    let result = runInstalled(candidate, ["install-control-artifacts"], {
      [testArtifactCrashEnvironment]: String(boundary),
    });
    assert.equal(result.status, 86, `install boundary ${boundary}`);
    assert.equal(
      fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction/journal.json")),
      true,
    );

    writeFile(visudo, "#!/bin/sh\nexit 93\n", 0o700);
    result = runInstalled(candidate, ["install-control-artifacts"]);
    assert.equal(result.status, 78, `install recovery boundary ${boundary}`);
    assert.match(result.stderr, /visudo rejected/);
    assertArtifacts(candidate, preimages);
    assert.deepEqual(fs.readFileSync(fixed(candidate.root, installedConsumerPath)), priorConsumer);
    assert.equal(
      fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction")),
      false,
    );
    writeFile(visudo, validVisudo, 0o700);
  }
});

test("a prior-supported installed consumer recovers every rollback crash boundary", (t) => {
  const candidate = fixture(t);
  parseOutput(run(candidate));
  const priorConsumer = installPriorSupportedConsumer(candidate);
  const preimages = snapshotArtifacts(candidate);
  const visudo = candidate.toolEnvironment[testVisudoEnvironment];
  const validVisudo = fs.readFileSync(visudo);
  const reloadCount = path.join(candidate.root, "rollback-reload-count");

  for (let boundary = 1; boundary <= 6; boundary += 1) {
    fs.rmSync(reloadCount, { force: true });
    writeFile(candidate.systemctl, `#!/bin/sh
[ "$1" = daemon-reload ] || exit 91
count=0
[ ! -f ${JSON.stringify(reloadCount)} ] || count=$(/bin/cat ${JSON.stringify(reloadCount)})
count=$((count + 1))
printf '%s\n' "$count" > ${JSON.stringify(reloadCount)}
[ "$count" -ne 1 ]
`, 0o700);
    let result = runInstalled(candidate, ["install-control-artifacts"], {
      [testArtifactRollbackCrashEnvironment]: String(boundary),
    });
    assert.equal(result.status, 87, `rollback boundary ${boundary}`);
    assert.equal(
      fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction/journal.json")),
      true,
    );

    // Boundaries 5 and 6 execute after the installer preimage was restored;
    // this retry therefore proves the predecessor itself owns recovery.
    if (boundary >= 5) {
      assert.deepEqual(fs.readFileSync(fixed(candidate.root, installedConsumerPath)), priorConsumer);
    }
    writeFile(visudo, "#!/bin/sh\nexit 93\n", 0o700);
    result = runInstalled(candidate, ["install-control-artifacts"]);
    assert.equal(result.status, 78, `rollback recovery boundary ${boundary}`);
    assert.match(result.stderr, /visudo rejected/);
    assertArtifacts(candidate, preimages);
    assert.equal(
      fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction")),
      false,
    );
    writeFile(visudo, validVisudo, 0o700);
  }
});

test("the first legacy bootstrap recovers through the exact release-root current consumer", (t) => {
  const candidate = fixture(t);
  parseOutput(run(candidate));
  const preimages = snapshotArtifacts(candidate);
  const reloadCount = path.join(candidate.root, "legacy-bootstrap-reload-count");
  writeFile(candidate.systemctl, `#!/bin/sh
[ "$1" = daemon-reload ] || exit 91
count=0
[ ! -f ${JSON.stringify(reloadCount)} ] || count=$(/bin/cat ${JSON.stringify(reloadCount)})
count=$((count + 1))
printf '%s\n' "$count" > ${JSON.stringify(reloadCount)}
[ "$count" -ne 1 ]
`, 0o700);
  let result = runReleaseConsumer(candidate, ["install-control-artifacts"], {
    [testArtifactRollbackCrashEnvironment]: "5",
  });
  assert.equal(result.status, 87);
  assert.deepEqual(
    fs.readFileSync(fixed(candidate.root, installedConsumerPath)),
    preimages.get(installedConsumerPath).bytes,
  );

  writeFile(candidate.toolEnvironment[testVisudoEnvironment], "#!/bin/sh\nexit 93\n", 0o700);
  result = runReleaseConsumer(candidate, ["install-control-artifacts"]);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /visudo rejected/);
  assertArtifacts(candidate, preimages);
  assert.equal(
    fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/control-artifact-install-transaction")),
    false,
  );
});

test("rejects every CLI outside the three exact install verbs before entering the seam", () => {
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

test("rejects a checkpoint tree that differs from its clean staging checkout before mutation", (t) => {
  const candidate = fixture(t);
  const checkpoint = JSON.parse(fs.readFileSync(candidate.checkpoint, "utf8"));
  checkpoint.candidateTree = "a".repeat(40);
  writeFile(candidate.checkpoint, `${stableJson(checkpoint)}\n`, 0o600);
  const result = run(candidate);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /tree differs/);
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
  assert.doesNotMatch(source, /^(?:CANDIDATE_COMMIT|CANDIDATE_TREE|SOURCE_ARCHIVE_SHA256)\s*=/m);
  assert.match(source, /checkpoint-bound V1 archive digest/);
  assert.match(source, /\.v1-release-staging\/\{pins\.commit\}/);
  assert.match(source, /\/usr\/bin\/git/);
  assert.doesNotMatch(source, /shell\s*=\s*True|os\.system|Popen/);
});
