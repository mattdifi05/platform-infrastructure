#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const productionScript = path.join(import.meta.dirname, "deploy-v1-local-private.sh");
const bundledNode = process.execPath;
const candidateCommit = "832bf2baec47055342af7e7f73425444381b91e0";
const candidateTree = "91cee2380809cb0691b9ac47cafa2a673d434caa";
const sourceArchiveSha256 = "6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007";

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const keyBlob = Buffer.concat([
  sshString("ssh-ed25519"),
  sshString(Buffer.alloc(32, 11)),
]).toString("base64");

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deploy-v1-local-private-test-"));
  const bin = path.join(root, "bin");
  const key = path.join(root, "deploy-key");
  const knownHosts = path.join(root, "known-hosts");
  const fakeSsh = path.join(root, "fixed-ssh");
  const argumentsFile = path.join(root, "ssh-arguments");
  const stdinSizeFile = path.join(root, "ssh-stdin-size");
  const fixtureScripts = path.join(root, "scripts");
  const fixtureSystemd = path.join(root, "systemd");
  const fixtureScript = path.join(fixtureScripts, "deploy-v1-local-private.sh");
  fs.mkdirSync(bin);
  fs.mkdirSync(fixtureScripts);
  fs.mkdirSync(fixtureSystemd);
  const source = fs.readFileSync(productionScript, "utf8");
  const systemProbe = "SYSTEM_NAME=$(/usr/bin/uname -s)";
  assert.equal(source.split(systemProbe).length - 1, 1, "production client must contain one exact OS test boundary");
  fs.writeFileSync(fixtureScript, source.replace(systemProbe, "SYSTEM_NAME=Darwin"), { mode: 0o700 });
  for (const dependency of [
    "ssh-known-host-endpoint.sh",
    "pinned-ssh-host-key.mjs",
  ]) fs.copyFileSync(path.join(import.meta.dirname, dependency), path.join(fixtureScripts, dependency));
  const controllerSource = path.join(fixtureScripts, "v1-local-private-control.py");
  const unitSource = path.join(fixtureSystemd, "platform-v1-local-private-control.service");
  fs.copyFileSync(path.join(import.meta.dirname, "v1-local-private-control.py"), controllerSource);
  fs.copyFileSync(path.join(import.meta.dirname, "..", "systemd", "platform-v1-local-private-control.service"), unitSource);
  const controllerSha256 = crypto.createHash("sha256").update(fs.readFileSync(controllerSource)).digest("hex");
  const unitSha256 = crypto.createHash("sha256").update(fs.readFileSync(unitSource)).digest("hex");
  fs.writeFileSync(path.join(fixtureScripts, "v1-local-private-control-receipt.mjs"), `#!/usr/bin/env node
import fs from "node:fs";
const argv = process.argv.slice(2);
const value = (flag) => argv[argv.indexOf(flag) + 1];
if (argv[0] !== "verify"
  || value("--candidateCommit") !== ${JSON.stringify(candidateCommit)}
  || value("--candidateTree") !== ${JSON.stringify(candidateTree)}
  || value("--sourceArchiveSha256") !== ${JSON.stringify(sourceArchiveSha256)}
  || value("--controllerSha256") !== ${JSON.stringify(controllerSha256)}
  || value("--unitSha256") !== ${JSON.stringify(unitSha256)}) {
  throw new Error("invalid verifier invocation");
}
const receipt = JSON.parse(fs.readFileSync(value("--file"), "utf8"));
if (receipt.schema !== "platform.v1-local-private-control-receipt/v1"
  || receipt.status !== "ACTIVE"
  || receipt.candidateCommit !== ${JSON.stringify(candidateCommit)}) {
  throw new Error("invalid LOCAL_PRIVATE receipt");
}
`, { mode: 0o700 });
  fs.writeFileSync(key, "test-only-private-key\n", { mode: 0o600 });
  fs.writeFileSync(knownHosts, `[example.internal]:2222 ssh-ed25519 ${keyBlob}\n`, { mode: 0o600 });
  fs.symlinkSync(bundledNode, path.join(bin, "node"));

  const receipt = JSON.stringify({
    candidateCommit,
    schema: "platform.v1-local-private-control-receipt/v1",
    status: "ACTIVE",
  });
  fs.writeFileSync(fakeSsh, `#!/bin/sh
: > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_ARGUMENTS"
for argument do printf '%s\\n' "$argument" >> "$PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_ARGUMENTS"; done
/usr/bin/wc -c < /dev/stdin | /usr/bin/tr -d '[:space:]' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_STDIN_SIZE"
case "\${PLATFORM_V1_LOCAL_PRIVATE_TEST_RECEIPT_MODE:-valid}" in
  invalid) printf '%s\\n' '{"schema":"attacker"}' ;;
  oversized) /usr/bin/yes x | /usr/bin/head -c 131073 ;;
  *) printf '%s\\n' '${receipt}' ;;
esac
`, { mode: 0o700 });

  const environment = {
    ...process.env,
    PATH: `${bin}:/usr/bin:/bin`,
    HOME: root,
    DEPLOY_REMOTE: "deploy_user@example.internal",
    DEPLOY_SSH_PORT: "2222",
    DEPLOY_SSH_KEY_PATH: key,
    DEPLOY_SSH_KNOWN_HOSTS_PATH: knownHosts,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH: fakeSsh,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_ARGUMENTS: argumentsFile,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_STDIN_SIZE: stdinSizeFile,
  };
  return { root, knownHosts, controllerSource, unitSource, fixtureScript, argumentsFile, stdinSizeFile, environment, receipt };
}

function execute(testFixture, args = [], environment = {}) {
  return spawnSync("/bin/sh", [testFixture.fixtureScript, ...args], {
    encoding: "utf8",
    env: { ...testFixture.environment, ...environment },
  });
}

test("pins host trust and invokes only the fixed root LOCAL_PRIVATE controller", () => {
  const current = fixture();
  try {
    const result = execute(current);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `${current.receipt}\n`);
    assert.equal(fs.readFileSync(current.stdinSizeFile, "utf8"), "0");
    const args = fs.readFileSync(current.argumentsFile, "utf8").trim().split("\n");
    assert.deepEqual(args.slice(-3), [
      "--",
      "deploy_user@example.internal",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control activate",
    ]);
    assert.ok(args.includes("BatchMode=yes"));
    assert.ok(args.includes("StrictHostKeyChecking=yes"));
    assert.ok(args.includes("ClearAllForwardings=yes"));
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects caller arguments before SSH", () => {
  const current = fixture();
  try {
    const result = execute(current, ["attacker-plan"]);
    assert.equal(result.status, 64);
    assert.match(result.stderr, /accepts no positional arguments/);
    assert.equal(fs.existsSync(current.argumentsFile), false);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects an invalid root receipt", () => {
  const current = fixture();
  try {
    const result = execute(current, [], { PLATFORM_V1_LOCAL_PRIVATE_TEST_RECEIPT_MODE: "invalid" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /invalid LOCAL_PRIVATE receipt/);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("bounds the authenticated remote response at 128 KiB", () => {
  const current = fixture();
  try {
    const result = execute(current, [], { PLATFORM_V1_LOCAL_PRIVATE_TEST_RECEIPT_MODE: "oversized" });
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects missing host trust before SSH", () => {
  const current = fixture();
  try {
    fs.rmSync(current.knownHosts);
    const result = execute(current);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /known-hosts input/);
    assert.equal(fs.existsSync(current.argumentsFile), false);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects a missing controller source before SSH", () => {
  const current = fixture();
  try {
    fs.rmSync(current.controllerSource);
    const result = execute(current);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /controller source/);
    assert.equal(fs.existsSync(current.argumentsFile), false);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("source pins the immutable candidate and transports no plan or provider input", () => {
  const source = fs.readFileSync(productionScript, "utf8");
  for (const value of [
    `CANDIDATE_COMMIT=${candidateCommit}`,
    `CANDIDATE_TREE=${candidateTree}`,
    `SOURCE_ARCHIVE_SHA256=${sourceArchiveSha256}`,
    "REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control activate'",
    'exec "$SSH" "$@" -- "$REMOTE" "$REMOTE_COMMAND" < /dev/null',
    "ulimit -f 256",
    'receipt_size=$(wc -c < "$receipt"',
    '[ "$receipt_size" -le 131072 ]',
    'node "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" verify',
    '--controllerSha256 "$CONTROLLER_SHA256"',
    '--unitSha256 "$UNIT_SHA256"',
    'CONTROLLER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-control.py"',
    'UNIT_SOURCE="$REPOSITORY_ROOT/systemd/platform-v1-local-private-control.service"',
    "SSH=/usr/bin/ssh",
    'SSH=${PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH:-$SSH}',
  ]) assert.ok(source.includes(value), `LOCAL_PRIVATE client is missing ${value}`);
  assert.doesNotMatch(source, /git (?:fetch|pull|checkout)|docker |compose|scp |sftp |sh -s|platform-activation-broker|activation-request|provider-activation/);
});
