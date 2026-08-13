#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "platform-activation-transport-")));
const fakeSudo = path.join(root, "sudo");
const fakeBroker = path.join(root, "broker");
const sudoSentinel = path.join(root, "sudo-invoked");
const brokerSentinel = path.join(root, "broker-invoked");
fs.writeFileSync(fakeSudo, `#!/bin/sh
: > "$PLATFORM_ACTIVATION_TEST_SUDO_SENTINEL"
exit 97
`, { mode: 0o755 });
fs.writeFileSync(fakeBroker, `#!/bin/sh
: > "$PLATFORM_ACTIVATION_TEST_BROKER_SENTINEL"
exit 98
`, { mode: 0o755 });

const script = path.join(import.meta.dirname, "deploy-vps-remote.sh");
const environment = {
  ...process.env,
  PATH: root,
  TMPDIR: path.join(root, "hostile-tmp"),
  PLATFORM_ACTIVATION_TEST_SUDO: fakeSudo,
  PLATFORM_ACTIVATION_TEST_BROKER: fakeBroker,
  PLATFORM_ACTIVATION_TEST_SUDO_SENTINEL: sudoSentinel,
  PLATFORM_ACTIVATION_TEST_BROKER_SENTINEL: brokerSentinel,
};

const run = (input, arguments_ = [], extraEnvironment = {}) => spawnSync("/bin/sh", [script, ...arguments_], {
  encoding: null,
  input,
  env: { ...environment, ...extraEnvironment },
});

function assertTerminalStop(result, label) {
  assert.equal(result.status, 78, `${label}: expected terminal STOP 78; stderr=${result.stderr.toString()}`);
  assert.equal(result.stdout.length, 0, `${label}: STOP emitted unexpected stdout`);
  assert.match(result.stderr.toString(), /V1 brownfield existing-host path is STOP/);
  assert.equal(fs.existsSync(sudoSentinel), false, `${label}: STOP reached sudo`);
  assert.equal(fs.existsSync(brokerSentinel), false, `${label}: STOP reached the activation broker`);
}

async function runWithUnreadableStdin() {
  const child = spawn("/bin/sh", [script], {
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));

  return await new Promise((resolve, reject) => {
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.stdin.destroy();
      child.kill("SIGKILL");
    }, 1000);
    child.once("error", reject);
    child.once("close", (status, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error("remote activation shim attempted to read stdin before the terminal V1 STOP"));
        return;
      }
      resolve({
        status,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      });
    });
  });
}

try {
  // No authoritative V1 consumer binds the verified PRE-DEPLOY backup and all
  // provider gates to this target-side transport. The shim must therefore stop
  // without waiting for, consuming, or interpreting stdin.
  assertTerminalStop(await runWithUnreadableStdin(), "open stdin");

  const request = Buffer.from('{"schema":"platform-activation-request/v3"}\n');
  assertTerminalStop(run(request), "ordinary request");

  assertTerminalStop(run(request, ["--force", "attacker-path"]), "caller arguments");

  assertTerminalStop(run(request, [], {
    V1_BACKUP_GATE: "SATISFIED",
    V1_PROVIDER_GATES: "SATISFIED",
    V1_DEPLOYMENT_ADMISSION: "AUTHORIZED",
    V1_ACTIVATION_PROMOTION: "AUTHORIZED",
    CONFIRM_MUTATING_VPS: "true",
  }), "caller environment");

  const source = fs.readFileSync(script, "utf8");
  const stop = source.indexOf('echo "V1 brownfield existing-host path is STOP:');
  const exit = source.indexOf("exit 78", stop);
  for (const boundary of [
    "BROKER=/usr/local/libexec/platform-activation-broker",
    "SYSTEM_NAME=$(/usr/bin/uname -s)",
    "request=$(/usr/bin/mktemp",
    "/bin/dd if=/dev/stdin",
    'exec "$SUDO" -n "$BROKER" activate',
  ]) {
    const boundaryIndex = source.indexOf(boundary);
    assert.ok(stop >= 0 && exit > stop && boundaryIndex > exit,
      `terminal V1 STOP must precede ${boundary}`);
  }
  assert.equal(fs.existsSync(environment.TMPDIR), false, "caller TMPDIR influenced the stopped transport");
  process.stdout.write("platform activation transport tests passed 5/5\n");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
