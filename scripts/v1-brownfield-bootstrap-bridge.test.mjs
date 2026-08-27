#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const bridge = path.join(import.meta.dirname, "v1-brownfield-bootstrap-bridge.py");
const consumer = path.join(import.meta.dirname, "v1-brownfield-install-consumer.py");
const nodeHelper = path.join(import.meta.dirname, "v1-node-runtime-prerequisite.py");
const sudoers = path.join(import.meta.dirname, "..", "sudoers", "platform-v1-local-private-control");
const python = "/usr/bin/python3";
const artifactPaths = [
  "/usr/local/libexec/platform-v1-brownfield-install-consumer",
  "/usr/local/libexec/platform-v1-local-private-control",
  "/usr/local/libexec/platform-v1-local-private-reconcile",
  "/etc/systemd/system/platform-v1-local-private-control.service",
  "/etc/sudoers.d/platform-v1-local-private-control",
];

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const stable = (value) => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object"
  ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`
  : JSON.stringify(value);
const fixed = (root, logical) => path.join(root, logical.slice(1));

function write(filename, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filename, value, { mode });
  fs.chmodSync(filename, mode);
}

function git(cwd, args) {
  const result = spawnSync("/usr/bin/git", args, {
    cwd, encoding: "utf8",
    env: { GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", HOME: "/nonexistent", LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function buildTransport(seed, root, label, options = {}) {
  const commit = git(seed, ["rev-parse", "HEAD"]);
  const tree = git(seed, ["rev-parse", "HEAD^{tree}"]);
  const checkpointUnixSeconds = options.checkpointUnixSeconds
    ?? Number.parseInt(git(seed, ["show", "-s", "--format=%ct", "HEAD"]), 10);
  assert.equal(Number.isInteger(checkpointUnixSeconds) && checkpointUnixSeconds > 0, true);
  const archive = path.join(root, `source-${label}.tar`);
  const bundle = path.join(root, `source-${label}.bundle`);
  let result = spawnSync("/usr/bin/git", ["archive", "--format=tar", `--output=${archive}`, "HEAD"], { cwd: seed, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  result = spawnSync("/usr/bin/git", ["bundle", "create", bundle, "HEAD"], { cwd: seed, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const archiveBytes = fs.readFileSync(archive);
  const bundleBytes = fs.readFileSync(bundle);
  const bridgeBytes = fs.readFileSync(bridge);
  const consumerBytes = fs.readFileSync(path.join(seed, "scripts", "v1-brownfield-install-consumer.py"));
  const checkpoint = {
    activationAuthorized: false, authoritative: false, backupEvidenceAuthoritative: false,
    bridgeSha256: sha(bridgeBytes), candidateCommit: commit, candidateConsumerSha256: sha(consumerBytes),
    candidateTree: tree, createdAtUnixSeconds: checkpointUnixSeconds, gitBundleSha256: sha(bundleBytes),
    purpose: "CONTROL_PLANE_STAGING_ONLY", schema: "platform.v1-bootstrap-transport-checkpoint/v1",
    sourceArchiveSha256: sha(archiveBytes), sourceArchiveSizeBytes: archiveBytes.length, transportVerified: true,
  };
  const checkpointBytes = Buffer.from(`${stable(checkpoint)}\n`);
  const parts = { bridge: bridgeBytes, consumer: consumerBytes, checkpoint: checkpointBytes, sanction: options.sanctionBytes ?? Buffer.from("{}"), gitBundle: bundleBytes, sourceArchive: archiveBytes };
  const manifest = {
    bridgeSha256: sha(bridgeBytes), candidateCommit: commit, candidateTree: tree,
    checkpointSha256: sha(checkpointBytes), consumerSha256: sha(consumerBytes), gitBundleSha256: sha(bundleBytes),
    lengths: Object.fromEntries(Object.entries(parts).map(([name, bytes]) => [name, bytes.length])),
    schema: "platform.v1-brownfield-bootstrap-frame/v1", sanctionSha256: sha(parts.sanction), sourceArchiveSha256: sha(archiveBytes),
  };
  const manifestBytes = Buffer.from(stable(manifest));
  const frame = Buffer.concat([
    Buffer.from(manifestBytes.length.toString(16).padStart(8, "0")), manifestBytes,
    ...["bridge", "consumer", "checkpoint", "sanction", "gitBundle", "sourceArchive"].map((name) => parts[name]),
  ]);
  return { archiveBytes, checkpointBytes, checkpointUnixSeconds, commit, consumerBytes, frame, manifest, tree };
}

function createFixture(t) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-bootstrap-bridge-test-")));
  fs.chmodSync(root, 0o700);
  t.after(() => {
    const pending = [root];
    while (pending.length) {
      const current = pending.pop();
      if (!fs.existsSync(current)) continue;
      const metadata = fs.lstatSync(current);
      if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
        fs.chmodSync(current, 0o700);
        for (const child of fs.readdirSync(current)) pending.push(path.join(current, child));
      }
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  const seed = path.join(root, "candidate");
  fs.mkdirSync(seed, { mode: 0o700 });
  git(seed, ["init", "--quiet"]);
  git(seed, ["config", "user.name", "V1 Bootstrap Fixture"]);
  git(seed, ["config", "user.email", "fixture@example.invalid"]);
  write(path.join(seed, ".gitignore"), ".env\n", 0o644);
  write(path.join(seed, "README.md"), "transport-only bootstrap fixture\n", 0o644);
  write(path.join(seed, "scripts", "v1-brownfield-bootstrap-bridge.py"), fs.readFileSync(bridge), 0o644);
  write(path.join(seed, "scripts", "v1-brownfield-install-consumer.py"), fs.readFileSync(consumer), 0o755);
  write(path.join(seed, "scripts", "v1-node-runtime-prerequisite.py"), fs.readFileSync(nodeHelper), 0o755);
  write(path.join(seed, "scripts", "v1-local-private-control.py"), "#!/usr/bin/python3 -I\nraise SystemExit(0)\n", 0o644);
  write(path.join(seed, "scripts", "v1-local-private-reconcile.py"), "#!/usr/bin/python3 -I\nraise SystemExit(0)\n", 0o644);
  write(path.join(seed, "systemd", "platform-v1-local-private-control.service"), "[Unit]\nDescription=V1 fixture\n[Service]\nType=simple\nExecStart=/usr/local/libexec/platform-v1-local-private-control supervise\n", 0o644);
  write(path.join(seed, "sudoers", "platform-v1-local-private-control"), fs.readFileSync(sudoers), 0o644);
  fs.mkdirSync(path.join(seed, "config"), { recursive: true });
  write(path.join(seed, "config", "local-private-recovery-escrow-cert.pem"), ensureSanctionTrust().certBytes, 0o644);
  git(seed, ["add", "."]);
  git(seed, ["commit", "--quiet", "-m", "fixture"]);
  const transport = buildTransport(seed, root, "a");
  const bridgeBytes = fs.readFileSync(bridge);

  const legacyConsumer = Buffer.from("test-only historical installed consumer\n");
  const legacyV1Sudoers = Buffer.from([
    "Defaults:platform_infrastructure env_reset",
    "Defaults:platform_infrastructure secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "platform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-control activate",
    "",
  ].join("\n"));
  const broadGrant = Buffer.from("platform_infrastructure ALL=(ALL) NOPASSWD:ALL\n");
  const liveEnvironment = Buffer.from("PLATFORM_MODE=LOCAL_PRIVATE\nFIXTURE_SECRET=not-printed\n");
  write(fixed(root, "/usr/local/libexec/platform-v1-brownfield-install-consumer"), legacyConsumer, 0o555);
  write(fixed(root, "/etc/sudoers.d/platform-v1-local-private-control"), legacyV1Sudoers, 0o440);
  write(fixed(root, "/etc/sudoers.d/platform_infrastructure"), broadGrant, 0o440);
  write(fixed(root, "/home/platform_infrastructure/.v1-bootstrap-upload/v1-brownfield-bootstrap-bridge.py"), bridgeBytes, 0o500);
  write(fixed(root, "/home/platform_infrastructure/platform-infrastructure/.env"), liveEnvironment, 0o600);
  for (const directory of ["/etc/systemd/system", "/run/lock", "/srv", "/var/lib/platform-infrastructure/v1"]) {
    fs.mkdirSync(fixed(root, directory), { recursive: true, mode: 0o700 });
    fs.chmodSync(fixed(root, directory), 0o700);
  }
  const tools = path.join(root, "tools");
  const visudo = path.join(tools, "visudo");
  const analyze = path.join(tools, "systemd-analyze");
  const systemctl = path.join(tools, "systemctl");
  const aptCache = path.join(tools, "apt-cache");
  const aptGet = path.join(tools, "apt-get");
  const dpkgQuery = path.join(tools, "dpkg-query");
  const nodeRuntime = fixed(root, "/usr/bin/node");
  const nodePackageState = path.join(root, "node-package-installed");
  write(visudo, "#!/bin/sh\n[ \"$1\" = -c ] && [ \"$2\" = -f ] && [ -f \"$3\" ]\n", 0o700);
  write(analyze, "#!/bin/sh\n[ \"$1\" = verify ] && [ -f \"$2\" ]\n", 0o700);
  write(systemctl, "#!/bin/sh\n[ \"$1\" = daemon-reload ]\n", 0o700);
  write(aptCache, `#!${process.execPath}\nprocess.stdout.write("Package: nodejs\\nVersion: 22.22.1+dfsg+~cs22.19.15-1ubuntu1\\nArchitecture: amd64\\n\\n");\n`, 0o700);
  write(aptGet, `#!${process.execPath}\nrequire("node:fs").writeFileSync(${JSON.stringify(nodePackageState)}, "installed\\n");\n`, 0o700);
  write(dpkgQuery, `#!${process.execPath}\nconst fs=require("node:fs"); if(fs.existsSync(${JSON.stringify(nodePackageState)})) process.stdout.write("nodejs\\tinstall ok installed\\t22.22.1+dfsg+~cs22.19.15-1ubuntu1\\tamd64\\n"); else process.exitCode=1;\n`, 0o700);
  write(nodeRuntime, `#!${process.execPath}\nprocess.stdout.write("v22.22.1\\n");\n`, 0o700);

  return {
    ...transport, bridgeBytes, broadGrant, legacyConsumer, legacyV1Sudoers, liveEnvironment, root, seed,
    environment: {
      ...process.env,
      PLATFORM_V1_BOOTSTRAP_TEST_ROOT: root,
      PLATFORM_V1_BOOTSTRAP_TEST_LEGACY_CONSUMER_SHA256: sha(legacyConsumer),
      PLATFORM_V1_INSTALL_CONSUMER_TEST_VISUDO: visudo,
      PLATFORM_V1_INSTALL_CONSUMER_TEST_SYSTEMD_ANALYZE: analyze,
      PLATFORM_V1_INSTALL_CONSUMER_TEST_SYSTEMCTL: systemctl,
      PLATFORM_V1_NODE_RUNTIME_TEST_APT_CACHE: aptCache,
      PLATFORM_V1_NODE_RUNTIME_TEST_APT_GET: aptGet,
      PLATFORM_V1_NODE_RUNTIME_TEST_DPKG_QUERY: dpkgQuery,
      PLATFORM_V1_NODE_RUNTIME_TEST_NODE: nodeRuntime,
    },
  };
}

function advanceCandidate(candidate) {
  write(path.join(candidate.seed, "README.md"), "transport-only bootstrap fixture candidate B\n", 0o644);
  write(
    path.join(candidate.seed, "scripts", "v1-brownfield-install-consumer.py"),
    Buffer.concat([fs.readFileSync(consumer), Buffer.from("\n# exact candidate B installer bytes\n")]),
    0o755,
  );
  write(path.join(candidate.seed, "scripts", "v1-local-private-control.py"), "#!/usr/bin/python3 -I\n# candidate B controller\nraise SystemExit(0)\n", 0o644);
  write(path.join(candidate.seed, "scripts", "v1-local-private-reconcile.py"), "#!/usr/bin/python3 -I\n# candidate B reconciler\nraise SystemExit(0)\n", 0o644);
  write(path.join(candidate.seed, "systemd", "platform-v1-local-private-control.service"), "[Unit]\nDescription=V1 fixture candidate B\n[Service]\nType=simple\nExecStart=/usr/local/libexec/platform-v1-local-private-control supervise\n", 0o644);
  git(candidate.seed, ["add", "."]);
  git(candidate.seed, ["commit", "--quiet", "-m", "candidate B"]);
  return { ...candidate, ...buildTransport(candidate.seed, candidate.root, "b", { checkpointUnixSeconds: candidate.checkpointUnixSeconds }) };
}

function execute(candidate) {
  return spawnSync(python, ["-I", bridge, "apply"], {
    cwd: "/", encoding: "utf8", env: candidate.environment, input: candidate.frame, maxBuffer: 1024 * 1024, timeout: 30_000,
  });
}

test("stages exact transport bytes, stable-copies .env, installs control artifacts, and preserves broad sudo", (t) => {
  const candidate = createFixture(t);
  const source = fs.readFileSync(bridge, "utf8");
  assert.match(source, /GIT_CONFIG_GLOBAL.*\/dev\/null/s);
  assert.match(source, /GIT_CONFIG_NOSYSTEM.*1/s);
  assert.match(source, /safe\.directory=/);
  const livePath = fixed(candidate.root, "/home/platform_infrastructure/platform-infrastructure/.env");
  const liveBefore = fs.statSync(livePath);
  const first = execute(candidate);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stderr, "");
  const envelope = JSON.parse(first.stdout);
  assert.equal(first.stdout, `${stable(envelope)}\n`);
  assert.equal(envelope.schema, "platform.v1-brownfield-bootstrap-result/v1");
  assert.equal(envelope.bootstrap.status, "BOOTSTRAP_CONTROL_INSTALLED");
  assert.equal(envelope.bootstrap.dataMutation, false);
  assert.equal(envelope.bootstrap.dockerMutation, false);
  assert.equal(envelope.bootstrap.stagingMutation, true);
  assert.equal(envelope.bootstrap.stagingEnvironmentSha256, sha(candidate.liveEnvironment));
  assert.equal(envelope.bootstrap.legacyBroadSudoersBeforeSha256, sha(candidate.broadGrant));
  assert.equal(envelope.bootstrap.legacyBroadSudoersAfterSha256, sha(candidate.broadGrant));
  assert.equal(envelope.controlArtifacts.status, "CONTROL_ARTIFACTS_INSTALLED");
  assert.equal(envelope.controlArtifacts.dataMutation, false);
  assert.equal(envelope.controlArtifacts.dockerMutation, false);
  assert.equal(envelope.nodeRuntime.status, "NODE_RUNTIME_READY");
  assert.equal(envelope.nodeRuntime.hostControlMutation, true);
  const nodeRuntimeBytes = Buffer.from(`${stable(envelope.nodeRuntime)}\n`);
  assert.equal(envelope.bootstrap.nodeRuntimeReceiptSha256, sha(nodeRuntimeBytes));
  assert.deepEqual(
    fs.readFileSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json")),
    nodeRuntimeBytes,
  );

  const stagingEnvironment = fixed(candidate.root, `/home/platform_infrastructure/.v1-release-staging/${candidate.commit}/.env`);
  const stagingRoot = path.dirname(stagingEnvironment);
  assert.deepEqual(fs.readFileSync(stagingEnvironment), candidate.liveEnvironment);
  assert.equal(fs.statSync(stagingEnvironment).mode & 0o777, 0o600);
  assert.equal(git(stagingRoot, ["rev-parse", "--verify", "refs/remotes/github/main^{commit}"]), candidate.commit);
  assert.deepEqual(fs.readFileSync(livePath), candidate.liveEnvironment);
  const liveAfter = fs.statSync(livePath);
  assert.equal(liveAfter.ino, liveBefore.ino);
  assert.equal(liveAfter.mtimeMs, liveBefore.mtimeMs);
  assert.deepEqual(fs.readFileSync(fixed(candidate.root, "/etc/sudoers.d/platform_infrastructure")), candidate.broadGrant);
  assert.deepEqual(fs.readFileSync(fixed(candidate.root, "/usr/local/libexec/platform-v1-brownfield-install-consumer")), candidate.consumerBytes);

  const transport = JSON.parse(fs.readFileSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/predeploy/current/install-checkpoint.json"), "utf8"));
  assert.equal(transport.schema, "platform.v1-bootstrap-transport-checkpoint/v1");
  assert.equal(transport.backupEvidenceAuthoritative, false);
  assert.equal(transport.activationAuthorized, false);
  assert.equal("restoreVerified" in transport, false);
  assert.equal("runtimeRecovered" in transport, false);

  const second = execute(candidate);
  assert.equal(second.status, 0, second.stderr);
  const secondEnvelope = JSON.parse(second.stdout);
  assert.equal(secondEnvelope.controlArtifacts.status, "ALREADY_INSTALLED");
  assert.equal(secondEnvelope.controlArtifacts.hostControlMutation, false);
  assert.equal(secondEnvelope.nodeRuntime.hostControlMutation, true);
  assert.deepEqual(secondEnvelope.nodeRuntime, envelope.nodeRuntime);
  assert.equal(secondEnvelope.bootstrap.stagingMutation, false);
  assert.deepEqual(fs.readFileSync(livePath), candidate.liveEnvironment);
  assert.deepEqual(fs.readFileSync(fixed(candidate.root, "/etc/sudoers.d/platform_infrastructure")), candidate.broadGrant);
});

test("an exact prior chain authorizes candidate B and its idempotent retry", (t) => {
  const candidateA = createFixture(t);
  const installedA = execute(candidateA);
  assert.equal(installedA.status, 0, installedA.stderr);
  const envelopeA = JSON.parse(installedA.stdout);
  assert.equal(envelopeA.bootstrap.checkpointBeforeSha256, null);
  assert.equal(envelopeA.bootstrap.sourceArchiveBeforeSha256, null);
  const candidateB = advanceCandidate(candidateA);
  assert.notEqual(candidateB.commit, candidateA.commit);
  assert.notEqual(sha(candidateB.consumerBytes), sha(candidateA.consumerBytes));

  const installedB = execute(candidateB);
  assert.equal(installedB.status, 0, installedB.stderr);
  const envelopeB = JSON.parse(installedB.stdout);
  assert.equal(envelopeB.bootstrap.candidateCommit, candidateB.commit);
  assert.equal(envelopeB.bootstrap.candidateTree, candidateB.tree);
  assert.equal(envelopeB.bootstrap.dataMutation, false);
  assert.equal(envelopeB.bootstrap.dockerMutation, false);
  assert.equal(envelopeB.controlArtifacts.status, "CONTROL_ARTIFACTS_INSTALLED");
  assert.equal(envelopeB.controlArtifacts.hostControlMutation, true);
  assert.deepEqual(
    fs.readFileSync(fixed(candidateB.root, artifactPaths[0])),
    candidateB.consumerBytes,
  );
  for (const artifact of envelopeB.controlArtifacts.artifacts) {
    const pathname = fixed(candidateB.root, artifact.path);
    assert.equal(sha(fs.readFileSync(pathname)), artifact.sha256);
    assert.equal((fs.statSync(pathname).mode & 0o777).toString(8).padStart(4, "0"), artifact.mode);
  }
  const stagingB = fixed(candidateB.root, `/home/platform_infrastructure/.v1-release-staging/${candidateB.commit}`);
  assert.equal(git(stagingB, ["rev-parse", "--verify", "refs/remotes/github/main^{commit}"]), candidateB.commit);

  const retryB = execute(candidateB);
  assert.equal(retryB.status, 0, retryB.stderr);
  const retryEnvelope = JSON.parse(retryB.stdout);
  assert.equal(retryEnvelope.controlArtifacts.status, "ALREADY_INSTALLED");
  assert.equal(retryEnvelope.controlArtifacts.hostControlMutation, false);
  assert.equal(retryEnvelope.bootstrap.dataMutation, false);
  assert.equal(retryEnvelope.bootstrap.dockerMutation, false);
  assert.deepEqual(fs.readFileSync(fixed(candidateB.root, "/etc/sudoers.d/platform_infrastructure")), candidateB.broadGrant);
});

test("rejects a self-consistent receipt/live tamper that differs from the frozen prior release", (t) => {
  const candidateA = createFixture(t);
  const installedA = execute(candidateA);
  assert.equal(installedA.status, 0, installedA.stderr);
  const candidateB = advanceCandidate(candidateA);
  const controllerPath = fixed(candidateA.root, artifactPaths[1]);
  const tamperedController = Buffer.concat([fs.readFileSync(controllerPath), Buffer.from("# tampered current controller\n")]);
  fs.chmodSync(controllerPath, 0o700);
  write(controllerPath, tamperedController, 0o555);

  const controlPath = fixed(candidateA.root, "/var/lib/platform-infrastructure/v1/bootstrap-control-artifact-receipt.json");
  const control = JSON.parse(fs.readFileSync(controlPath, "utf8"));
  control.artifacts[1].sha256 = sha(tamperedController);
  const controlBytes = Buffer.from(`${stable(control)}\n`);
  fs.chmodSync(controlPath, 0o600);
  write(controlPath, controlBytes, 0o400);
  const bridgeReceiptPath = fixed(candidateA.root, "/var/lib/platform-infrastructure/v1/bootstrap-bridge-receipt.json");
  const prior = JSON.parse(fs.readFileSync(bridgeReceiptPath, "utf8"));
  prior.controlArtifactReceiptSha256 = sha(controlBytes);
  delete prior.documentId;
  prior.documentId = sha(Buffer.from(stable(prior)));
  fs.chmodSync(bridgeReceiptPath, 0o600);
  write(bridgeReceiptPath, Buffer.from(`${stable(prior)}\n`), 0o400);

  const rejected = execute(candidateB);
  assert.equal(rejected.status, 78, rejected.stderr);
  assert.match(rejected.stderr, /current\/frozen V1 control artifact differs/);
  assert.deepEqual(fs.readFileSync(controllerPath), tamperedController);
  assert.equal(
    fs.existsSync(fixed(candidateB.root, `/srv/platform-infrastructure/releases/${candidateB.commit}-${candidateB.manifest.sourceArchiveSha256}`)),
    false,
  );
  assert.deepEqual(fs.readFileSync(fixed(candidateB.root, "/etc/sudoers.d/platform_infrastructure")), candidateB.broadGrant);
});

test("does not repair a missing github/main ref in an existing staging checkout", (t) => {
  const candidate = createFixture(t);
  const installed = execute(candidate);
  assert.equal(installed.status, 0, installed.stderr);
  const staging = fixed(candidate.root, `/home/platform_infrastructure/.v1-release-staging/${candidate.commit}`);
  git(staging, ["update-ref", "-d", "refs/remotes/github/main"]);
  const rejected = execute(candidate);
  assert.equal(rejected.status, 78, rejected.stderr);
  assert.match(rejected.stderr, /staging github\/main ref/);
  assert.equal(git(staging, ["for-each-ref", "--format=%(refname)", "refs/remotes/github/main"]), "");
});

test("candidate B crash rolls every control artifact back to candidate A before a clean retry", (t) => {
  const candidateA = createFixture(t);
  const installedA = execute(candidateA);
  assert.equal(installedA.status, 0, installedA.stderr);
  const preimages = new Map(artifactPaths.map((logical) => [logical, fs.readFileSync(fixed(candidateA.root, logical))]));
  const candidateB = advanceCandidate(candidateA);
  const cleanFrame = Buffer.from(candidateB.frame);
  candidateB.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER = "13";
  const crashed = execute(candidateB);
  assert.equal(crashed.status, 87, crashed.stderr);
  assert.deepEqual(fs.readFileSync(fixed(candidateB.root, artifactPaths[0])), candidateB.consumerBytes);

  delete candidateB.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER;
  candidateB.frame = Buffer.from(cleanFrame);
  candidateB.frame[candidateB.frame.length - 1] ^= 0xff;
  const recoveredThenRejected = execute(candidateB);
  assert.equal(recoveredThenRejected.status, 65, recoveredThenRejected.stderr);
  assert.match(recoveredThenRejected.stderr, /sourceArchive body digest/);
  for (const [logical, bytes] of preimages) assert.deepEqual(fs.readFileSync(fixed(candidateB.root, logical)), bytes, logical);
  assert.equal(fs.existsSync(fixed(candidateB.root, "/var/lib/platform-infrastructure/v1/bootstrap-transaction")), false);

  candidateB.frame = cleanFrame;
  const retried = execute(candidateB);
  assert.equal(retried.status, 0, retried.stderr);
  assert.equal(JSON.parse(retried.stdout).bootstrap.candidateCommit, candidateB.commit);
  assert.deepEqual(fs.readFileSync(fixed(candidateB.root, artifactPaths[0])), candidateB.consumerBytes);
  assert.deepEqual(fs.readFileSync(fixed(candidateB.root, "/etc/sudoers.d/platform_infrastructure")), candidateB.broadGrant);
});

test("rejects a transport checkpoint that claims backup authority before mutation", (t) => {
  const candidate = createFixture(t);
  const manifestLength = Number.parseInt(candidate.frame.subarray(0, 8).toString(), 16);
  const manifest = JSON.parse(candidate.frame.subarray(8, 8 + manifestLength).toString());
  let offset = 8 + manifestLength + manifest.lengths.bridge + manifest.lengths.consumer;
  const checkpointBytes = candidate.frame.subarray(offset, offset + manifest.lengths.checkpoint);
  const checkpoint = JSON.parse(checkpointBytes.toString());
  checkpoint.backupEvidenceAuthoritative = true;
  const changedCheckpoint = Buffer.from(`${stable(checkpoint)}\n`);
  manifest.lengths.checkpoint = changedCheckpoint.length;
  manifest.checkpointSha256 = sha(changedCheckpoint);
  const changedManifest = Buffer.from(stable(manifest));
  offset += checkpointBytes.length;
  candidate.frame = Buffer.concat([
    Buffer.from(changedManifest.length.toString(16).padStart(8, "0")), changedManifest,
    candidate.frame.subarray(8 + manifestLength, 8 + manifestLength + manifest.lengths.bridge + manifest.lengths.consumer),
    changedCheckpoint,
    candidate.frame.subarray(offset),
  ]);
  const result = execute(candidate);
  assert.equal(result.status, 65);
  assert.match(result.stderr, /transport checkpoint scope/);
  assert.equal(fs.existsSync(fixed(candidate.root, `/srv/platform-infrastructure/releases/${candidate.commit}-${manifest.sourceArchiveSha256}`)), false);
  assert.deepEqual(fs.readFileSync(fixed(candidate.root, "/etc/sudoers.d/platform_infrastructure")), candidate.broadGrant);
});

test("recovers every control artifact preimage after a hard crash following control install", (t) => {
  const candidate = createFixture(t);
  candidate.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER = "13";
  const crashed = execute(candidate);
  assert.equal(crashed.status, 87, crashed.stderr);
  assert.deepEqual(
    fs.readFileSync(fixed(candidate.root, "/usr/local/libexec/platform-v1-brownfield-install-consumer")),
    candidate.consumerBytes,
  );

  delete candidate.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER;
  const corruptFrame = Buffer.from(candidate.frame);
  corruptFrame[corruptFrame.length - 1] ^= 0xff;
  candidate.frame = corruptFrame;
  const recovery = execute(candidate);
  assert.equal(recovery.status, 65, recovery.stderr);
  assert.match(recovery.stderr, /sourceArchive body digest/);

  assert.deepEqual(
    fs.readFileSync(fixed(candidate.root, "/usr/local/libexec/platform-v1-brownfield-install-consumer")),
    candidate.legacyConsumer,
  );
  assert.deepEqual(
    fs.readFileSync(fixed(candidate.root, "/etc/sudoers.d/platform-v1-local-private-control")),
    candidate.legacyV1Sudoers,
  );
  for (const logical of [
    "/usr/local/libexec/platform-v1-local-private-control",
    "/usr/local/libexec/platform-v1-local-private-reconcile",
    "/etc/systemd/system/platform-v1-local-private-control.service",
  ]) assert.equal(fs.existsSync(fixed(candidate.root, logical)), false, `${logical} was not rolled back`);
  assert.equal(fs.existsSync(fixed(candidate.root, "/var/lib/platform-infrastructure/v1/bootstrap-transaction")), false);
  assert.deepEqual(fs.readFileSync(fixed(candidate.root, "/etc/sudoers.d/platform_infrastructure")), candidate.broadGrant);
});

test("hard-crash retry preserves the durable Node mutation receipt and completes forward", (t) => {
  const candidate = createFixture(t);
  candidate.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER = "14";
  const crashed = execute(candidate);
  assert.equal(crashed.status, 87, crashed.stderr);
  const nodeReceiptPath = fixed(candidate.root, "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json");
  const durableBefore = fs.readFileSync(nodeReceiptPath);
  const firstNodeReceipt = JSON.parse(durableBefore);
  assert.equal(firstNodeReceipt.hostControlMutation, true);

  delete candidate.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER;
  const recovered = execute(candidate);
  assert.equal(recovered.status, 0, recovered.stderr);
  const envelope = JSON.parse(recovered.stdout);
  assert.deepEqual(envelope.nodeRuntime, firstNodeReceipt);
  assert.equal(envelope.nodeRuntime.hostControlMutation, true);
  assert.equal(envelope.bootstrap.nodeRuntimeReceiptSha256, sha(durableBefore));
  assert.deepEqual(fs.readFileSync(nodeReceiptPath), durableBefore);
  assert.deepEqual(fs.readFileSync(fixed(candidate.root, "/etc/sudoers.d/platform_infrastructure")), candidate.broadGrant);
});

function stageGreenfieldPreimage(candidate, greenfieldEnv, releaseCommit) {
  const envPath = "/home/platform_infrastructure/greenfield-live/render/preimage/greenfield-deployment.env";
  const provenancePath = "/home/platform_infrastructure/greenfield-live/render/preimage/preimage-provenance.json";
  write(fixed(candidate.root, envPath), greenfieldEnv, 0o400);
  const imageIdentities = {
    PLATFORM_OPS_IMAGE: `127.0.0.1:5000/platform/ops@sha256:${"e".repeat(64)}`,
    CONTROL_CENTER_IMAGE: `127.0.0.1:5000/platform/control-center@sha256:${"f".repeat(64)}`,
    PROJECT_ROUTER_IMAGE: `127.0.0.1:5000/platform/router@sha256:${"1".repeat(64)}`,
    PLATFORM_ALERT_DISPATCHER_IMAGE: `127.0.0.1:5000/platform/alert@sha256:${"2".repeat(64)}`,
    PLATFORM_BACKUP_SCHEDULER_IMAGE_POSTGRES: `127.0.0.1:5000/platform/bs-pg@sha256:${"3".repeat(64)}`,
    PLATFORM_DOCKER_ACTION_BROKER_IMAGE_POSTGRES: `127.0.0.1:5000/platform/broker@sha256:${"4".repeat(64)}`,
    PLATFORM_PROVIDER_ACTIVATION_SIDECAR_IMAGE_POSTGRES: `127.0.0.1:5000/platform/sidecar@sha256:${"5".repeat(64)}`,
  };
  const provenance = {
    schema: "platform.v1-greenfield-preimage/v1",
    generatedAtUnixSeconds: 1800000000,
    releaseCommit,
    greenfieldEnvSha256: sha(greenfieldEnv),
    renderEnvSha256: sha(greenfieldEnv),
    preimagePath: envPath,
    preimageSha256: sha(greenfieldEnv),
    imageIdentities,
  };
  write(fixed(candidate.root, provenancePath), Buffer.from(`${stable(provenance)}\n`), 0o400);
  candidate.environment.PLATFORM_V1_LIVE_ENV = envPath;
  candidate.environment.PLATFORM_V1_REQUIRE_GREENFIELD_PREIMAGE = "1";
  candidate.environment.PLATFORM_V1_LIVE_ENV_PROVENANCE = provenancePath;
}

test("greenfield preimage selection binds the bridge to the greenfield .env and never the brownfield .env", (t) => {
  const candidate = createFixture(t);
  const greenfieldEnv = Buffer.from("PLATFORM_MODE=LOCAL_PRIVATE\nGREENFIELD_SECRET=only-in-greenfield\n");
  stageGreenfieldPreimage(candidate, greenfieldEnv, candidate.commit);
  const result = execute(candidate);
  assert.equal(result.status, 0, result.stderr);
  const envelope = JSON.parse(result.stdout);
  assert.equal(envelope.bootstrap.status, "BOOTSTRAP_CONTROL_INSTALLED");
  assert.equal(envelope.bootstrap.stagingEnvironmentSha256, sha(greenfieldEnv));
  assert.notEqual(envelope.bootstrap.stagingEnvironmentSha256, sha(candidate.liveEnvironment));
  const stagingEnv = fixed(candidate.root, `/home/platform_infrastructure/.v1-release-staging/${candidate.commit}/.env`);
  assert.deepEqual(fs.readFileSync(stagingEnv), greenfieldEnv);
  assert.deepEqual(fs.readFileSync(fixed(candidate.root, "/home/platform_infrastructure/platform-infrastructure/.env")), candidate.liveEnvironment);
});

test("greenfield preimage selection fails closed when provenance does not bind the candidate commit", (t) => {
  const candidate = createFixture(t);
  const greenfieldEnv = Buffer.from("PLATFORM_MODE=LOCAL_PRIVATE\nGREENFIELD_SECRET=only-in-greenfield\n");
  stageGreenfieldPreimage(candidate, greenfieldEnv, "0".repeat(40));
  const result = execute(candidate);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /preimage|provenance|candidate/i);
});

test("greenfield preimage selection fails closed when the preimage path equals the brownfield live environment", (t) => {
  const candidate = createFixture(t);
  candidate.environment.PLATFORM_V1_LIVE_ENV = "/home/platform_infrastructure/platform-infrastructure/.env";
  candidate.environment.PLATFORM_V1_REQUIRE_GREENFIELD_PREIMAGE = "1";
  candidate.environment.PLATFORM_V1_LIVE_ENV_PROVENANCE = "/home/platform_infrastructure/greenfield-live/render/preimage/preimage-provenance.json";
  const result = execute(candidate);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /brownfield/i);
});

const SANCTION_OPENSSL_BIN = process.env.PLATFORM_V1_TEST_SANCTION_OPENSSL || "openssl";
const sanctionTrustRoots = [];
let SANCTION_TRUST = null;
function ensureSanctionTrust() {
  if (SANCTION_TRUST) return SANCTION_TRUST;
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-sanction-trust-")));
  sanctionTrustRoots.push(root);
  const certPath = path.join(root, "cert.pem");
  const keyPath = path.join(root, "key.pem");
  const generate = (name, certOut, keyOut) => {
    const result = spawnSync(SANCTION_OPENSSL_BIN,
      ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", `/CN=${name}`, "-keyout", keyOut, "-out", certOut],
      { encoding: "buffer" });
    assert.equal(result.status, 0, result.stderr?.toString());
  };
  generate("V1 Sanction Test Root", certPath, keyPath);
  SANCTION_TRUST = { root, certPath, keyPath, certBytes: fs.readFileSync(certPath) };
  SANCTION_TRUST.sha256 = sha(SANCTION_TRUST.certBytes);
  return SANCTION_TRUST;
}
process.on("exit", () => { for (const root of sanctionTrustRoots) fs.rmSync(root, { recursive: true, force: true }); });

let FOREIGN_SIGNER = null;
function ensureForeignSigner() {
  if (FOREIGN_SIGNER) return FOREIGN_SIGNER;
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-sanction-foreign-")));
  sanctionTrustRoots.push(root);
  const certPath = path.join(root, "cert.pem");
  const keyPath = path.join(root, "key.pem");
  const result = spawnSync(SANCTION_OPENSSL_BIN,
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=V1 Foreign Signer", "-keyout", keyPath, "-out", certPath],
    { encoding: "buffer" });
  assert.equal(result.status, 0, result.stderr?.toString());
  FOREIGN_SIGNER = { certPath, keyPath };
  return FOREIGN_SIGNER;
}

function craftTransportSanction(priorBootstrap, candidateManifest, overrides = {}) {
  const trust = ensureSanctionTrust();
  const core = {
    checkpointSha256: overrides.checkpointSha256 ?? candidateManifest.checkpointSha256,
    createdAtUnixSeconds: overrides.createdAtUnixSeconds ?? Math.floor(Date.now() / 1000),
    priorCheckpointAfterSha256: overrides.priorCheckpointAfterSha256 ?? priorBootstrap.checkpointAfterSha256,
    priorReceiptDocumentId: overrides.priorReceiptDocumentId ?? priorBootstrap.documentId,
    reasonCode: "TRANSPORT_CHECKPOINT_REGENERATED_NO_PRIOR_BYTES",
    schema: "platform.v1-transport-checkpoint-sanction/v1",
  };
  const coreBuffer = Buffer.from(`${stable(core)}\n`);
  const coreFile = path.join(trust.root, `core-${sha(coreBuffer).slice(0, 12)}.bin`);
  fs.writeFileSync(coreFile, coreBuffer);
  let signatureBase64 = overrides.signatureBase64 ?? null;
  if (!signatureBase64) {
    const signatureOut = path.join(trust.root, `sig-${sha(coreBuffer).slice(0, 12)}.der`);
    const signResult = spawnSync(SANCTION_OPENSSL_BIN,
      ["cms", "-sign", "-binary", "-in", coreFile, "-signer", overrides.signerCert ?? trust.certPath, "-inkey", overrides.signerKey ?? trust.keyPath, "-outform", "DER", "-out", signatureOut],
      { encoding: "buffer" });
    assert.equal(signResult.status, 0, signResult.stderr?.toString());
    signatureBase64 = fs.readFileSync(signatureOut).toString("base64");
  }
  return Buffer.from(`${stable({ ...core, signatureBase64 })}\n`);
}

function divergeDiskCheckpoint(candidate) {
  const checkpointLogical = "/var/lib/platform-infrastructure/v1/predeploy/current/install-checkpoint.json";
  const target = fixed(candidate.root, checkpointLogical);
  const pristine = fs.readFileSync(target);
  const rogue = Buffer.from(`${stable({
    activationAuthorized: false, authoritative: false, backupEvidenceAuthoritative: false,
    bridgeSha256: candidate.manifest.bridgeSha256, candidateCommit: candidate.commit,
    candidateConsumerSha256: candidate.manifest.consumerSha256, candidateTree: candidate.manifest.candidateTree,
    createdAtUnixSeconds: candidate.checkpointUnixSeconds - 3600, gitBundleSha256: candidate.manifest.gitBundleSha256,
    purpose: "CONTROL_PLANE_STAGING_ONLY", schema: "platform.v1-bootstrap-transport-checkpoint/v1",
    sourceArchiveSha256: candidate.manifest.sourceArchiveSha256, sourceArchiveSizeBytes: candidate.archiveBytes.length,
    transportVerified: true,
  })}\n`);
  fs.chmodSync(target, 0o600);
  fs.writeFileSync(target, rogue);
  fs.chmodSync(target, 0o400);
  return { checkpointLogical, pristine, rogue };
}

function sanctionSeams(candidate) {
  const trust = ensureSanctionTrust();
  candidate.environment.PLATFORM_V1_BOOTSTRAP_TEST_SANCTION_OPENSSL = SANCTION_OPENSSL_BIN;
  candidate.environment.PLATFORM_V1_BOOTSTRAP_TEST_SANCTION_CERT_SHA256 = trust.sha256;
}

test("unchanged empty-marker flow keeps the original fail-closed guard for a diverged disk checkpoint", (t) => {
  const candidateA = createFixture(t);
  const installedA = execute(candidateA);
  assert.equal(installedA.status, 0, installedA.stderr);
  const priorBootstrap = JSON.parse(installedA.stdout).bootstrap;
  const candidateB = advanceCandidate(candidateA);
  divergeDiskCheckpoint(candidateB);
  const guardResult = execute(candidateB);
  assert.equal(guardResult.status, 78, guardResult.stderr);
  assert.match(guardResult.stderr, /current bootstrap transport preimage differs from the prior exact receipt\./);
});

test("an operator-signed transport sanction authorizes regeneration and records an auditable receipt", (t) => {
  const candidateA = createFixture(t);
  const installedA = execute(candidateA);
  assert.equal(installedA.status, 0, installedA.stderr);
  const priorBootstrap = JSON.parse(installedA.stdout).bootstrap;
  const candidateB = advanceCandidate(candidateA);
  sanctionSeams(candidateB);
  const divergence = divergeDiskCheckpoint(candidateB);
  assert.notDeepEqual(divergence.rogue, divergence.pristine);
  candidateB.frame = buildTransport(
    candidateB.seed, candidateB.root, "b-sanctioned",
    { sanctionBytes: craftTransportSanction(priorBootstrap, candidateB.manifest), checkpointUnixSeconds: candidateB.checkpointUnixSeconds },
  ).frame;
  const repaired = execute(candidateB);
  assert.equal(repaired.status, 0, repaired.stderr);
  const envelope = JSON.parse(repaired.stdout);
  assert.equal(envelope.bootstrap.transportSanction.present, true);
  assert.equal(envelope.bootstrap.transportSanction.reasonCode, "TRANSPORT_CHECKPOINT_REGENERATED_NO_PRIOR_BYTES");
  const retried = execute(candidateB);
  assert.equal(retried.status, 0, retried.stderr);
  assert.equal(JSON.parse(retried.stdout).bootstrap.transportSanction.present, false);
});

for (const variant of ["tampered-signature", "wrong-prior-digest", "wrong-frame-binding", "foreign-signer"]) {
  test(`sanction variant ${variant} fails closed without mutating state`, (t) => {
    const candidate = createFixture(t);
    const base = execute(candidate);
    assert.equal(base.status, 0, base.stderr);
    const priorBootstrap = JSON.parse(base.stdout).bootstrap;
    const activeCandidate = variant === "tampered-signature" || variant === "foreign-signer"
      ? advanceCandidate(candidate)
      : candidate;
    sanctionSeams(activeCandidate);
    divergeDiskCheckpoint(activeCandidate);
    const overrides = {};
    if (variant === "wrong-prior-digest") overrides.priorCheckpointAfterSha256 = "f".repeat(64);
    if (variant === "wrong-frame-binding") overrides.checkpointSha256 = "e".repeat(64);
    let bytes;
    if (variant === "tampered-signature") {
      bytes = craftTransportSanction(priorBootstrap, activeCandidate.manifest);
      const marker = bytes.indexOf(Buffer.from('"signatureBase64":"'));
      bytes[marker + 25] ^= 0x01;
    } else if (variant === "foreign-signer") {
      ensureForeignSigner();
      bytes = craftTransportSanction(priorBootstrap, activeCandidate.manifest, { signerCert: FOREIGN_SIGNER.certPath, signerKey: FOREIGN_SIGNER.keyPath });
    } else {
      bytes = craftTransportSanction(priorBootstrap, activeCandidate.manifest, overrides);
    }
    activeCandidate.frame = buildTransport(activeCandidate.seed, activeCandidate.root, `v-${variant}`, { sanctionBytes: bytes, checkpointUnixSeconds: activeCandidate.checkpointUnixSeconds }).frame;
    const result = execute(activeCandidate);
    assert.equal(result.status, 78, `${variant}: ${result.stderr}`);
    if (variant === "wrong-prior-digest" || variant === "wrong-frame-binding") {
      assert.match(result.stderr, /sanction binding is invalid/);
    } else {
      assert.doesNotMatch(result.stderr, /sanction binding is invalid/);
      assert.match(result.stderr, /signature rejected|trust anchor|sanction/);
    }
  });
}

function crashSeamAt(marker) {
  const source = fs.readFileSync(bridge, "utf8");
  return (source.slice(0, source.indexOf(marker)).match(/crash_point\(\)/g) || []).length;
}

test("a sanctioned-flow crash rolls back to the pristine divergent pre-state and retries cleanly", (t) => {
  const candidateA = createFixture(t);
  const installedA = execute(candidateA);
  assert.equal(installedA.status, 0, installedA.stderr);
  const priorBootstrap = JSON.parse(installedA.stdout).bootstrap;
  const candidateB = advanceCandidate(candidateA);
  sanctionSeams(candidateB);
  const divergence = divergeDiskCheckpoint(candidateB);
  candidateB.frame = buildTransport(
    candidateB.seed, candidateB.root, "b-crash",
    { sanctionBytes: craftTransportSanction(priorBootstrap, candidateB.manifest), checkpointUnixSeconds: candidateB.checkpointUnixSeconds },
  ).frame;
  candidateB.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER = String(crashSeamAt("atomic_write(INSTALL_CHECKPOINT"));
  const crashed = execute(candidateB);
  assert.equal(crashed.status, 87, crashed.stderr);
  assert.deepEqual(fs.readFileSync(fixed(candidateB.root, divergence.checkpointLogical)), divergence.rogue);
  delete candidateB.environment.PLATFORM_V1_BOOTSTRAP_TEST_CRASH_AFTER;
  const retried = execute(candidateB);
  assert.equal(retried.status, 0, retried.stderr);
});