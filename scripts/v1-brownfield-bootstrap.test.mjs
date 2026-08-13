#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const SCRIPT = path.join(import.meta.dirname, "v1-brownfield-bootstrap.sh");
const SCRIPT_EXISTS = fs.existsSync(SCRIPT);
const testIfImplemented = SCRIPT_EXISTS ? test : test.skip;
const REQUIRED_BINARIES = Object.freeze([
  ["activationBroker", "/usr/local/libexec/platform-activation-broker", "provider-activation-broker"],
  ["hostedPreparationBroker", "/usr/local/libexec/platform-hosted-preparation-broker", "provider-hosted-preparation-broker"],
  ["originFirewallHelper", "/usr/local/libexec/platform-origin-firewall", "provider-origin-firewall"],
  ["workloadEgressHelper", "/usr/local/libexec/platform-workload-egress-firewall", "provider-workload-egress-firewall"],
]);

test("V1 brownfield bootstrap implementation exists", () => {
  assert.equal(SCRIPT_EXISTS, true, `${SCRIPT} is missing`);
});

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function physical(root, logical) {
  assert.equal(path.isAbsolute(logical), true);
  return path.join(root, logical.slice(1));
}

function writeFile(root, logical, bytes, mode) {
  const target = physical(root, logical);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
  fs.writeFileSync(target, bytes, { mode });
  fs.chmodSync(target, mode);
  return target;
}

function makeFixture(t, { manifestMutation, sourceNames = {} } = {}) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-brownfield-bootstrap-test-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  for (const logical of ["/srv", "/usr/local/libexec", "/etc/platform-infrastructure", "/run/lock", "/provider/bin"]) {
    fs.mkdirSync(physical(root, logical), { recursive: true, mode: 0o755 });
    fs.chmodSync(physical(root, logical), 0o755);
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });
  writeFile(root, "/etc/platform-infrastructure/v1-bootstrap-provider-public-key.pem", publicPem, 0o444);

  const binaries = REQUIRED_BINARIES.map(([name, target, defaultSource], index) => {
    const sourceName = sourceNames[name] ?? defaultSource;
    const source = `/provider/bin/${sourceName}`;
    const bytes = Buffer.from(`#!/bin/sh\n# externally supplied ${name}\nprintf '%s\\n' '${name}/v1'\n`);
    writeFile(root, source, bytes, 0o555);
    return {
      gid: 0,
      mode: "0555",
      name,
      nlink: 1,
      path: target,
      providerAttested: true,
      sha256: sha256(bytes),
      source,
      uid: 0,
      version: index + 1,
    };
  });
  const now = Date.now();
  const manifest = {
    binaries,
    directories: [
      { gid: 0, mode: "0755", path: "/srv/platform-infrastructure", uid: 0 },
      { gid: 0, mode: "0755", path: "/srv/platform-infrastructure/releases", uid: 0 },
      { gid: 0, mode: "0755", path: "/srv/platform-infrastructure/release-states", uid: 0 },
    ],
    expiresAt: new Date(now + 60 * 60_000).toISOString(),
    generatedAt: new Date(now - 60_000).toISOString(),
    provider: {
      event: "workflow_dispatch",
      keyId: sha256(publicPem),
      repository: "independent/provider-control-plane",
      runAttempt: 1,
      runId: "123456789",
      sourceRef: "refs/heads/main",
      workflowPath: ".github/workflows/install-v1-host-brokers.yml",
      workflowSha: "a".repeat(40),
    },
    providerAttested: true,
    schema: "platform-v1-brownfield-install-manifest/v1",
    signatureAlgorithm: "openssl-dgst-sha256",
    status: "READY",
    version: 1,
  };
  manifestMutation?.(manifest);
  const manifestBytes = Buffer.from(`${canonical(manifest)}\n`);
  const manifestFile = path.join(root, "provider", "install-manifest.json");
  const signatureFile = path.join(root, "provider", "install-manifest.sig");
  fs.writeFileSync(manifestFile, manifestBytes, { mode: 0o444 });
  fs.chmodSync(manifestFile, 0o444);
  fs.writeFileSync(signatureFile, crypto.sign("sha256", manifestBytes, privateKey), { mode: 0o444 });
  fs.chmodSync(signatureFile, 0o444);

  return {
    manifest,
    manifestFile,
    resign() {
      const bytes = Buffer.from(`${canonical(manifest)}\n`);
      fs.chmodSync(manifestFile, 0o644);
      fs.chmodSync(signatureFile, 0o644);
      fs.writeFileSync(manifestFile, bytes, { mode: 0o444 });
      fs.chmodSync(manifestFile, 0o444);
      fs.writeFileSync(signatureFile, crypto.sign("sha256", bytes, privateKey), { mode: 0o444 });
      fs.chmodSync(signatureFile, 0o444);
    },
    root,
    signatureFile,
  };
}

function run(fixture, args, extraEnv = {}, { cwd } = {}) {
  return spawnSync("/bin/sh", [SCRIPT, ...args], {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      V1_BROWNFIELD_TEST_ALLOW_NON_ROOT: "1",
      V1_BROWNFIELD_TEST_ROOT: fixture.root,
      ...extraEnv,
    },
  });
}

function runAsync(fixture, args, extraEnv = {}, { cwd } = {}) {
  const child = spawn("/bin/sh", [SCRIPT, ...args], {
    cwd,
    env: {
      ...process.env,
      V1_BROWNFIELD_TEST_ALLOW_NON_ROOT: "1",
      V1_BROWNFIELD_TEST_ROOT: fixture.root,
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const completed = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status, signal) => resolve({ signal, status, stderr, stdout }));
  });
  return { child, completed };
}

async function waitForFile(filename, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(filename)) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`timed out waiting for checkpoint ${filename}`);
}

function releaseCheckpoint(directory, name) {
  fs.writeFileSync(path.join(directory, `${name}.release`), "continue\n", { mode: 0o600 });
}

function writeUnsignedManifest(filename, manifest) {
  fs.writeFileSync(filename, `${canonical(manifest)}\n`, { mode: 0o444 });
  fs.chmodSync(filename, 0o444);
}

function providerArgs(fixture, mode) {
  return [mode, "--manifest", fixture.manifestFile, "--signature", fixture.signatureFile];
}

function snapshot(root) {
  const records = [];
  const visit = (candidate, relative = ".") => {
    const details = fs.lstatSync(candidate, { bigint: true });
    const record = {
      dev: details.dev.toString(),
      ino: details.ino.toString(),
      mode: Number(details.mode & 0o777n),
      nlink: details.nlink.toString(),
      path: relative,
      size: details.size.toString(),
      type: details.isDirectory() ? "directory" : details.isFile() ? "file" : details.isSymbolicLink() ? "symlink" : "other",
    };
    if (details.isFile()) record.sha256 = sha256(fs.readFileSync(candidate));
    records.push(record);
    if (details.isDirectory()) {
      for (const name of fs.readdirSync(candidate).sort()) visit(path.join(candidate, name), path.join(relative, name));
    }
  };
  visit(root);
  return records;
}

function assertNoInstalledState(root) {
  assert.equal(fs.existsSync(physical(root, "/srv/platform-infrastructure")), false);
  for (const [, target] of REQUIRED_BINARIES) assert.equal(fs.existsSync(physical(root, target)), false, target);
}

function assertInstalledState(root) {
  for (const logical of [
    "/srv/platform-infrastructure",
    "/srv/platform-infrastructure/releases",
    "/srv/platform-infrastructure/release-states",
  ]) {
    const details = fs.lstatSync(physical(root, logical));
    assert.equal(details.isDirectory(), true, logical);
    assert.equal(details.isSymbolicLink(), false, logical);
    assert.equal(details.mode & 0o777, 0o755, logical);
  }
  for (const [, target, sourceName] of REQUIRED_BINARIES) {
    const installed = physical(root, target);
    const source = physical(root, `/provider/bin/${sourceName}`);
    const details = fs.lstatSync(installed);
    assert.equal(details.isFile(), true, target);
    assert.equal(details.isSymbolicLink(), false, target);
    assert.equal(details.nlink, 1, target);
    assert.equal(details.mode & 0o777, 0o555, target);
    assert.deepEqual(fs.readFileSync(installed), fs.readFileSync(source), target);
  }
}

testIfImplemented("static scope excludes legacy/live mutation surfaces", () => {
  const source = fs.readFileSync(SCRIPT, "utf8");
  for (const forbidden of [
    /\/home(?:\/|\b)/,
    /\bdocker(?:\s|$)/i,
    /\bcompose(?:\s|$)/i,
    /\bsystemctl\b/,
    /\bapt(?:-get)?\b/,
    /\busermod\b/,
    /docker-group/i,
    /--remove-orphans/,
    /\bprune\b/,
    /\bdown\b/,
    /rm\s+-[^\n]*r/,
  ]) assert.doesNotMatch(source, forbidden);
  assert.match(source, /platform-activation-broker\.py/);
  assert.match(source, /refus/i);
});

testIfImplemented("default plan is read-only and records provider EXTERNAL-PENDING", (t) => {
  const fixture = makeFixture(t);
  const before = snapshot(fixture.root);
  const result = run(fixture, []);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /EXTERNAL-PENDING/);
  assert.deepEqual(snapshot(fixture.root), before);
});

testIfImplemented("hostile caller PATH shims are never invoked", (t) => {
  const fixture = makeFixture(t);
  const hostileBin = path.join(fixture.root, "hostile-bin");
  const marker = path.join(fixture.root, "hostile-command-invoked");
  fs.mkdirSync(hostileBin, { mode: 0o755 });
  for (const name of ["apt-get", "docker", "id", "openssl", "python3", "rm", "sed", "systemctl", "tr", "usermod", "wc"]) {
    const shim = path.join(hostileBin, name);
    fs.writeFileSync(shim, `#!/bin/sh\nprintf invoked >> '${marker}'\nexit 99\n`, { mode: 0o755 });
  }
  const result = run(fixture, providerArgs(fixture, "--plan"), { PATH: hostileBin });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(marker), false);
});

testIfImplemented("Python and OpenSSL loader environments are sterilized before privileged parsing", (t) => {
  const fixture = makeFixture(t);
  const poisonRoot = path.join(fixture.root, "provider", "poison");
  const marker = path.join(fixture.root, "interpreter-environment-poisoned");
  fs.mkdirSync(poisonRoot, { recursive: true, mode: 0o755 });
  fs.writeFileSync(
    path.join(poisonRoot, "sitecustomize.py"),
    `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text("executed", encoding="utf-8")\n`,
    { mode: 0o644 },
  );
  const opensslConfig = path.join(poisonRoot, "openssl.cnf");
  fs.writeFileSync(
    opensslConfig,
    "openssl_conf = invalid_init\n[invalid_init]\nproviders = invalid_providers\n[invalid_providers]\nmissing = missing_provider\n[missing_provider]\nmodule = /definitely/missing/provider.so\nactivate = 1\n",
    { mode: 0o644 },
  );

  const result = run(fixture, providerArgs(fixture, "--plan"), {
    PYTHONHOME: poisonRoot,
    PYTHONPATH: poisonRoot,
    PYTHONSTARTUP: path.join(poisonRoot, "sitecustomize.py"),
    PYTHONWARNINGS: "default",
    OPENSSL_CONF: opensslConfig,
    OPENSSL_MODULES: poisonRoot,
    OPENSSL_ENGINES: poisonRoot,
  }, { cwd: poisonRoot });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(marker), false, "caller-controlled Python code ran before provider verification");
  const source = fs.readFileSync(SCRIPT, "utf8");
  assert.equal(source.startsWith("#!/bin/sh\n"), true);
  const pythonCalls = [...source.matchAll(/^\s*"\$PYTHON"([^\n]*)/gm)].map((match) => match[1]);
  assert.ok(pythonCalls.length > 0);
  assert.equal(
    pythonCalls.every((argumentsText) => /(?:^|\s)-I(?:\s|$)/.test(argumentsText)),
    true,
    "every fixed Python invocation must use isolated mode",
  );
});

testIfImplemented("verify and apply fail closed without provider artifacts", (t) => {
  const fixture = makeFixture(t);
  const before = snapshot(fixture.root);
  for (const mode of ["--verify", "--apply"]) {
    const result = run(fixture, [mode]);
    assert.notEqual(result.status, 0, `${mode} unexpectedly succeeded`);
    assert.match(result.stderr, /manifest.*signature|required/i);
  }
  assert.deepEqual(snapshot(fixture.root), before);
  assertNoInstalledState(fixture.root);
});

testIfImplemented("signed plan is read-only and reports the exact closed install set", (t) => {
  const fixture = makeFixture(t);
  const before = snapshot(fixture.root);
  const result = run(fixture, providerArgs(fixture, "--plan"));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /status=INSTALL-PLAN-READY-NON-AUTHORITATIVE/);
  assert.match(result.stdout, /trustDomain=BOOTSTRAP-INSTALL-ONLY/);
  assert.match(result.stdout, /deploymentAuthorized=false/);
  assert.match(result.stdout, /providerGates=EXTERNAL-PENDING/);
  for (const [, target] of REQUIRED_BINARIES) assert.match(result.stdout, new RegExp(target.replaceAll("/", "\\/")));
  assert.deepEqual(snapshot(fixture.root), before);
});

testIfImplemented("production apply is terminally disabled until the Phase-B root installer exists", (t) => {
  const fixture = makeFixture(t);
  const env = { ...process.env };
  delete env.V1_BROWNFIELD_TEST_ALLOW_NON_ROOT;
  delete env.V1_BROWNFIELD_TEST_ROOT;
  delete env.V1_BROWNFIELD_TEST_FAIL_AFTER_STEP;
  delete env.V1_BROWNFIELD_TEST_CHECKPOINT_DIR;
  const result = spawnSync("/bin/sh", [SCRIPT, ...providerArgs(fixture, "--apply")], {
    encoding: "utf8",
    env,
  });
  assert.equal(result.status, 78, result.stderr);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /Phase-B root installer.*required|production apply.*disabled/i);
  assertNoInstalledState(fixture.root);
});

testIfImplemented("the non-production root seam rejects root aliases and newline retargeting", (t) => {
  const fixture = makeFixture(t);
  const hostileParent = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-bootstrap-hostile-root-")));
  t.after(() => fs.rmSync(hostileParent, { recursive: true, force: true }));

  for (const hostileRoot of ["/", "/\n", `${fixture.root}\t`, `${fixture.root}|shadow`]) {
    const result = run(fixture, providerArgs(fixture, "--apply"), {
      V1_BROWNFIELD_TEST_ROOT: hostileRoot,
    });
    assert.equal(result.status, 64, result.stderr);
    assertNoInstalledState(fixture.root);
  }

  const rootAlias = path.join(hostileParent, "root-alias");
  fs.symlinkSync("/", rootAlias);
  const aliasResult = run(fixture, providerArgs(fixture, "--apply"), {
    V1_BROWNFIELD_TEST_ROOT: rootAlias,
  });
  assert.equal(aliasResult.status, 64, aliasResult.stderr);
  assertNoInstalledState(fixture.root);

  const strippedSibling = path.join(hostileParent, "retargeted-root");
  fs.cpSync(fixture.root, strippedSibling, { recursive: true });
  const ancestorAlias = path.join(hostileParent, "ancestor-alias");
  fs.symlinkSync(hostileParent, ancestorAlias);
  const ancestorResult = run(fixture, providerArgs(fixture, "--apply"), {
    V1_BROWNFIELD_TEST_ROOT: path.join(ancestorAlias, path.basename(strippedSibling)),
  });
  assert.equal(ancestorResult.status, 64, ancestorResult.stderr);
  assertNoInstalledState(strippedSibling);

  const newlineRoot = `${strippedSibling}\n`;
  fs.mkdirSync(newlineRoot, { mode: 0o700 });
  const before = snapshot(strippedSibling);
  const newlineResult = run(fixture, providerArgs(fixture, "--apply"), {
    V1_BROWNFIELD_TEST_ROOT: newlineRoot,
  });
  assert.equal(newlineResult.status, 64, newlineResult.stderr);
  assert.deepEqual(snapshot(strippedSibling), before);
  assertNoInstalledState(strippedSibling);
});

testIfImplemented("the checkpoint seam rejects newline and dot-dot retargeting", (t) => {
  const fixture = makeFixture(t);
  const checkpointSibling = path.join(fixture.root, "checkpoints");
  const newlineCheckpoint = `${checkpointSibling}\n`;
  fs.mkdirSync(checkpointSibling, { mode: 0o700 });
  fs.mkdirSync(newlineCheckpoint, { mode: 0o700 });
  const checkpointAlias = path.join(fixture.root, "checkpoint-alias");
  fs.symlinkSync(fixture.root, checkpointAlias);
  const aliasResult = run(fixture, providerArgs(fixture, "--plan"), {
    V1_BROWNFIELD_TEST_CHECKPOINT_DIR: path.join(checkpointAlias, path.basename(checkpointSibling)),
  });
  assert.equal(aliasResult.status, 64, aliasResult.stderr);
  const beforeNewline = snapshot(fixture.root);
  const newlineResult = run(fixture, providerArgs(fixture, "--plan"), {
    V1_BROWNFIELD_TEST_CHECKPOINT_DIR: newlineCheckpoint,
  });
  assert.equal(newlineResult.status, 64, newlineResult.stderr);
  assert.deepEqual(snapshot(fixture.root), beforeNewline);

  const dotDotParent = path.join(fixture.root, "checkpoint-parent");
  const dotDotNewline = path.join(dotDotParent, "..\n");
  fs.mkdirSync(dotDotNewline, { recursive: true, mode: 0o700 });
  const beforeDotDot = snapshot(fixture.root);
  const dotDotResult = run(fixture, providerArgs(fixture, "--plan"), {
    V1_BROWNFIELD_TEST_CHECKPOINT_DIR: dotDotNewline,
  });
  assert.equal(dotDotResult.status, 64, dotDotResult.stderr);
  assert.deepEqual(snapshot(fixture.root), beforeDotDot);
});

testIfImplemented("valid provider-attested apply provisions only the exact V1 host roots and binaries", (t) => {
  const fixture = makeFixture(t);
  const result = run(fixture, providerArgs(fixture, "--apply"));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /status=INSTALL-APPLIED-NON-AUTHORITATIVE/);
  assert.match(result.stdout, /trustDomain=BOOTSTRAP-INSTALL-ONLY/);
  assert.match(result.stdout, /deploymentAuthorized=false/);
  assert.match(result.stdout, /providerGates=EXTERNAL-PENDING/);
  assertInstalledState(fixture.root);
  assert.deepEqual(fs.readdirSync(physical(fixture.root, "/srv/platform-infrastructure")).sort(), ["release-states", "releases"]);
  assert.deepEqual(
    fs.readdirSync(physical(fixture.root, "/usr/local/libexec")).sort(),
    REQUIRED_BINARIES.map(([, target]) => path.basename(target)).sort(),
  );
  assert.deepEqual(fs.readdirSync(physical(fixture.root, "/run/lock")), []);
});

testIfImplemented("verify is read-only and idempotent apply preserves installed inode identity", (t) => {
  const fixture = makeFixture(t);
  const applied = run(fixture, providerArgs(fixture, "--apply"));
  assert.equal(applied.status, 0, applied.stderr);
  const protectedRoots = [
    physical(fixture.root, "/srv/platform-infrastructure"),
    physical(fixture.root, "/usr/local/libexec"),
  ];
  const before = protectedRoots.map(snapshot);
  const verified = run(fixture, providerArgs(fixture, "--verify"));
  assert.equal(verified.status, 0, verified.stderr);
  assert.deepEqual(protectedRoots.map(snapshot), before);
  const reapplied = run(fixture, providerArgs(fixture, "--apply"));
  assert.equal(reapplied.status, 0, reapplied.stderr);
  assert.deepEqual(protectedRoots.map(snapshot), before);
});

testIfImplemented("tampered, incomplete, expired, or self-asserted manifests fail before mutation", async (t) => {
  const cases = [
    ["tampered-signature", (fixture) => {
      fs.chmodSync(fixture.manifestFile, 0o644);
      fs.appendFileSync(fixture.manifestFile, " ");
      fs.chmodSync(fixture.manifestFile, 0o444);
    }],
    ["incomplete-binaries", (fixture) => { fixture.manifest.binaries.pop(); fixture.resign(); }],
    ["self-asserted", (fixture) => { fixture.manifest.providerAttested = false; fixture.resign(); }],
    ["expired", (fixture) => { fixture.manifest.expiresAt = new Date(Date.now() - 60_000).toISOString(); fixture.resign(); }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, (subtest) => {
      const fixture = makeFixture(subtest);
      mutate(fixture);
      const before = snapshot(fixture.root);
      const result = run(fixture, providerArgs(fixture, "--apply"));
      assert.notEqual(result.status, 0, `${name} unexpectedly succeeded`);
      assert.deepEqual(snapshot(fixture.root), before);
      assertNoInstalledState(fixture.root);
    });
  }
});

testIfImplemented("coordinated A-to-B-to-A swap cannot mix verified and parsed manifest bytes", async (t) => {
  const fixture = makeFixture(t);
  const checkpoints = path.join(fixture.root, "checkpoints");
  fs.mkdirSync(checkpoints, { mode: 0o700 });
  for (const name of ["after-signature", "after-parse"]) {
    fs.writeFileSync(path.join(checkpoints, `${name}.enabled`), "enabled\n", { mode: 0o600 });
  }
  const unsignedPath = path.join(fixture.root, "provider", "unsigned-manifest.json");
  const unsignedRestored = path.join(fixture.root, "provider", "unsigned-restored.json");
  const signedBackup = path.join(fixture.root, "provider", "signed-manifest.json");
  const attackerSource = "/provider/bin/unsigned-attacker-broker";
  const attackerBytes = Buffer.from("#!/bin/sh\nprintf 'unsigned attacker broker\\n'\n");
  const attackerSha256 = sha256(attackerBytes);
  writeFile(fixture.root, attackerSource, attackerBytes, 0o555);
  const unsigned = structuredClone(fixture.manifest);
  unsigned.binaries[0].sha256 = attackerSha256;
  unsigned.binaries[0].source = attackerSource;
  writeUnsignedManifest(unsignedPath, unsigned);

  const execution = runAsync(fixture, providerArgs(fixture, "--plan"), {
    V1_BROWNFIELD_TEST_CHECKPOINT_DIR: checkpoints,
  });
  t.after(() => execution.child.kill("SIGKILL"));

  await waitForFile(path.join(checkpoints, "after-signature.ready"));
  fs.renameSync(fixture.manifestFile, signedBackup);
  fs.renameSync(unsignedPath, fixture.manifestFile);
  releaseCheckpoint(checkpoints, "after-signature");

  await waitForFile(path.join(checkpoints, "after-parse.ready"));
  fs.renameSync(fixture.manifestFile, unsignedRestored);
  fs.renameSync(signedBackup, fixture.manifestFile);
  releaseCheckpoint(checkpoints, "after-parse");

  const result = await execution.completed;
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /manifest.*(?:descriptor identity|pathname).*changed/i);
  assert.doesNotMatch(result.stdout, new RegExp(attackerSha256));
  assert.doesNotMatch(result.stdout, /unsigned-attacker-broker/);
  assertNoInstalledState(fixture.root);
});

testIfImplemented("lstat and opened descriptor cannot describe different manifest objects", async (t) => {
  const fixture = makeFixture(t);
  const checkpoints = path.join(fixture.root, "checkpoints");
  fs.mkdirSync(checkpoints, { mode: 0o700 });
  fs.writeFileSync(path.join(checkpoints, "manifest-after-lstat.enabled"), "enabled\n", { mode: 0o600 });
  const replacement = path.join(fixture.root, "provider", "replacement-manifest.json");
  const original = path.join(fixture.root, "provider", "original-manifest.json");
  fs.writeFileSync(replacement, fs.readFileSync(fixture.manifestFile), { mode: 0o444 });
  fs.chmodSync(replacement, 0o444);

  const execution = runAsync(fixture, providerArgs(fixture, "--plan"), {
    V1_BROWNFIELD_TEST_CHECKPOINT_DIR: checkpoints,
  });
  t.after(() => execution.child.kill("SIGKILL"));

  await waitForFile(path.join(checkpoints, "manifest-after-lstat.ready"));
  fs.renameSync(fixture.manifestFile, original);
  fs.renameSync(replacement, fixture.manifestFile);
  releaseCheckpoint(checkpoints, "manifest-after-lstat");

  const result = await execution.completed;
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /manifest.*(?:identity|mixed|changed)/i);
  assertNoInstalledState(fixture.root);
});

testIfImplemented("activationBroker cannot be sourced from the inner state supervisor file", (t) => {
  const fixture = makeFixture(t, { sourceNames: { activationBroker: "platform-activation-broker.py" } });
  const before = snapshot(fixture.root);
  const result = run(fixture, providerArgs(fixture, "--apply"));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /platform-activation-broker\.py|outer activation broker/i);
  assert.deepEqual(snapshot(fixture.root), before);
  assertNoInstalledState(fixture.root);
});

testIfImplemented("renaming the inner state supervisor cannot turn it into the outer activation broker", (t) => {
  const fixture = makeFixture(t);
  const source = physical(fixture.root, fixture.manifest.binaries[0].source);
  fs.chmodSync(source, 0o755);
  fs.writeFileSync(source, fs.readFileSync(path.join(import.meta.dirname, "platform-activation-broker.py")));
  fs.chmodSync(source, 0o555);
  fixture.manifest.binaries[0].sha256 = sha256(fs.readFileSync(source));
  fixture.resign();
  const before = snapshot(fixture.root);
  const result = run(fixture, providerArgs(fixture, "--apply"));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /renamed copy|inner state supervisor/i);
  assert.deepEqual(snapshot(fixture.root), before);
  assertNoInstalledState(fixture.root);
});

testIfImplemented("existing divergent, symlink, hardlink, and wrong-mode targets stop fail-closed", async (t) => {
  const cases = [
    ["divergent", (fixture, target) => fs.writeFileSync(target, "legacy\n", { mode: 0o555 })],
    ["symlink", (fixture, target) => fs.symlinkSync(physical(fixture.root, "/provider/bin/provider-origin-firewall"), target)],
    ["hardlink", (fixture, target) => {
      const source = physical(fixture.root, "/provider/bin/provider-activation-broker");
      fs.linkSync(source, target);
    }],
    ["wrong-mode", (fixture, target) => {
      const source = physical(fixture.root, "/provider/bin/provider-activation-broker");
      fs.copyFileSync(source, target);
      fs.chmodSync(target, 0o755);
    }],
  ];
  for (const [name, arrange] of cases) {
    await t.test(name, (subtest) => {
      const fixture = makeFixture(subtest);
      const target = physical(fixture.root, "/usr/local/libexec/platform-activation-broker");
      arrange(fixture, target);
      const before = snapshot(fixture.root);
      const result = run(fixture, providerArgs(fixture, "--apply"));
      assert.notEqual(result.status, 0, `${name} unexpectedly succeeded`);
      assert.deepEqual(snapshot(fixture.root), before);
      assert.equal(fs.existsSync(physical(fixture.root, "/srv/platform-infrastructure")), false);
    });
  }
});

testIfImplemented("unsafe pre-existing service root identity is preserved and rejected", (t) => {
  const fixture = makeFixture(t);
  const serviceRoot = physical(fixture.root, "/srv/platform-infrastructure");
  fs.mkdirSync(serviceRoot, { mode: 0o777 });
  fs.chmodSync(serviceRoot, 0o777);
  const before = snapshot(fixture.root);
  const result = run(fixture, providerArgs(fixture, "--apply"));
  assert.notEqual(result.status, 0);
  assert.deepEqual(snapshot(fixture.root), before);
  assert.equal(fs.lstatSync(serviceRoot).mode & 0o777, 0o777);
});

testIfImplemented("injected failure rolls back only transaction-owned exact files and empty directories", (t) => {
  const fixture = makeFixture(t);
  const providerBefore = snapshot(physical(fixture.root, "/provider"));
  const trustBefore = snapshot(physical(fixture.root, "/etc/platform-infrastructure"));
  const result = run(fixture, providerArgs(fixture, "--apply"), {
    V1_BROWNFIELD_TEST_FAIL_AFTER_STEP: "5",
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /injected/i);
  assertNoInstalledState(fixture.root);
  assert.deepEqual(snapshot(physical(fixture.root, "/provider")), providerBefore);
  assert.deepEqual(snapshot(physical(fixture.root, "/etc/platform-infrastructure")), trustBefore);
  assert.deepEqual(fs.readdirSync(physical(fixture.root, "/run/lock")), []);
});
