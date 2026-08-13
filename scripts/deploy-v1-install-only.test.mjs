#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  V1_INSTALL_CANDIDATE_COMMIT,
  V1_INSTALL_CANDIDATE_TREE,
  V1_INSTALL_SOURCE_ARCHIVE_SHA256,
} from "./v1-brownfield-install-receipt.mjs";

const productionScript = path.join(import.meta.dirname, "deploy-v1-install-only.sh");
const bundledNode = process.execPath;

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const keyBlob = Buffer.concat([
  sshString("ssh-ed25519"),
  sshString(Buffer.alloc(32, 7)),
]).toString("base64");

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deploy-v1-install-only-test-"));
  const bin = path.join(root, "bin");
  const key = path.join(root, "deploy-key");
  const knownHosts = path.join(root, "known-hosts");
  const fakeSsh = path.join(root, "fixed-ssh");
  const argumentsFile = path.join(root, "ssh-arguments");
  const stdinSizeFile = path.join(root, "ssh-stdin-size");
  const fixtureScripts = path.join(root, "scripts");
  const fixtureScript = path.join(fixtureScripts, "deploy-v1-install-only.sh");
  fs.mkdirSync(bin);
  fs.mkdirSync(fixtureScripts);
  const source = fs.readFileSync(productionScript, "utf8");
  const systemProbe = "SYSTEM_NAME=$(/usr/bin/uname -s)";
  assert.equal(source.split(systemProbe).length - 1, 1, "production client must contain one exact OS test boundary");
  fs.writeFileSync(fixtureScript, source.replace(systemProbe, "SYSTEM_NAME=Darwin"), { mode: 0o700 });
  for (const dependency of [
    "ssh-known-host-endpoint.sh",
    "pinned-ssh-host-key.mjs",
    "v1-brownfield-install-receipt.mjs",
  ]) fs.copyFileSync(path.join(import.meta.dirname, dependency), path.join(fixtureScripts, dependency));
  fs.writeFileSync(key, "test-only-private-key\n", { mode: 0o600 });
  fs.writeFileSync(knownHosts, `[example.internal]:2222 ssh-ed25519 ${keyBlob}\n`, { mode: 0o600 });
  fs.symlinkSync(bundledNode, path.join(bin, "node"));

  const receipt = JSON.stringify({
    activationAuthorized: false,
    authorizationSource: "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY",
    backupEvidenceAuthoritative: false,
    candidateCommit: V1_INSTALL_CANDIDATE_COMMIT,
    candidateTree: V1_INSTALL_CANDIDATE_TREE,
    dataMutation: false,
    dockerMutation: false,
    readyButDisabled: ["PROVIDER_ADMISSION", "DNS_PUBLICATION", "DAST", "SIGSTORE_PROMOTION", "DOCKER_CONTROL_PLANE"],
    releaseRoot: `/srv/platform-infrastructure/releases/${V1_INSTALL_CANDIDATE_COMMIT}-${V1_INSTALL_SOURCE_ARCHIVE_SHA256}`,
    schema: "platform.v1-brownfield-install-receipt/v1",
    sourceArchiveSha256: V1_INSTALL_SOURCE_ARCHIVE_SHA256,
    status: "INSTALL_ONLY_COMPLETE",
  });
  fs.writeFileSync(fakeSsh, `#!/bin/sh
: > "$PLATFORM_V1_INSTALL_TEST_SSH_ARGUMENTS"
for argument do printf '%s\\n' "$argument" >> "$PLATFORM_V1_INSTALL_TEST_SSH_ARGUMENTS"; done
/usr/bin/wc -c < /dev/stdin | /usr/bin/tr -d '[:space:]' > "$PLATFORM_V1_INSTALL_TEST_SSH_STDIN_SIZE"
if [ "\${PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE:-valid}" = invalid ]; then
  printf '%s\\n' '{"schema":"attacker"}'
else
  printf '%s\\n' '${receipt}'
fi
`, { mode: 0o700 });

  const environment = {
    ...process.env,
    PATH: `${bin}:/usr/bin:/bin`,
    HOME: root,
    DEPLOY_REMOTE: "deploy_user@example.internal",
    DEPLOY_SSH_PORT: "2222",
    DEPLOY_SSH_KEY_PATH: key,
    DEPLOY_SSH_KNOWN_HOSTS_PATH: knownHosts,
    PLATFORM_V1_INSTALL_TEST_SSH: fakeSsh,
    PLATFORM_V1_INSTALL_TEST_SSH_ARGUMENTS: argumentsFile,
    PLATFORM_V1_INSTALL_TEST_SSH_STDIN_SIZE: stdinSizeFile,
  };
  return { root, key, knownHosts, fakeSsh, fixtureScript, argumentsFile, stdinSizeFile, environment, receipt };
}

function execute(testFixture, args = [], environment = {}) {
  return spawnSync("/bin/sh", [testFixture.fixtureScript, ...args], {
    encoding: "utf8",
    env: { ...testFixture.environment, ...environment },
  });
}

test("pins host trust and invokes only the fixed root install consumer", () => {
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
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-brownfield-install-consumer install",
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
    const result = execute(current, ["/tmp/attacker"]);
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
    const result = execute(current, [], { PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE: "invalid" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /missing or unexpected fields|schema/);
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

test("source contains the exact immutable V1 identity and no deployment payload transport", () => {
  const source = fs.readFileSync(productionScript, "utf8");
  for (const value of [
    `CANDIDATE_COMMIT=${V1_INSTALL_CANDIDATE_COMMIT}`,
    `CANDIDATE_TREE=${V1_INSTALL_CANDIDATE_TREE}`,
    `SOURCE_ARCHIVE_SHA256=${V1_INSTALL_SOURCE_ARCHIVE_SHA256}`,
    "REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-brownfield-install-consumer install'",
    'exec "$SSH" "$@" -- "$REMOTE" "$REMOTE_COMMAND" < /dev/null',
    "ulimit -f 128",
    "SSH=/usr/bin/ssh",
    'if [ "$SYSTEM_NAME" != Linux ]; then',
    'SSH=${PLATFORM_V1_INSTALL_TEST_SSH:-$SSH}',
  ]) assert.ok(source.includes(value), `install client is missing ${value}`);
  assert.doesNotMatch(source, /git (?:fetch|pull|checkout)|docker |compose|scp |sftp |sh -s|platform-activation-broker/);
});
