#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "platform-v1-install-transport-")));
const fakeSudo = path.join(root, "fixed-sudo");
const pathShadowSudo = path.join(root, "path-shadow-sudo");
const pathDirectory = path.join(root, "bin");
const sudoSentinel = path.join(root, "sudo-invoked");
const sudoArguments = path.join(root, "sudo-arguments");
const pathShadowSentinel = path.join(root, "path-shadow-invoked");
fs.writeFileSync(fakeSudo, `#!/bin/sh
printf '%s\\n' "$@" > "$PLATFORM_V1_INSTALL_TEST_SUDO_ARGUMENTS"
: > "$PLATFORM_V1_INSTALL_TEST_SUDO_SENTINEL"
exit 97
`, { mode: 0o755 });
fs.writeFileSync(pathShadowSudo, `#!/bin/sh
: > "$PLATFORM_V1_INSTALL_TEST_PATH_SHADOW_SENTINEL"
exit 96
`, { mode: 0o755 });

const productionScript = path.join(import.meta.dirname, "deploy-vps-remote.sh");
const productionSource = fs.readFileSync(productionScript, "utf8");
const systemProbe = "SYSTEM_NAME=$(/usr/bin/uname -s)";
assert.equal(productionSource.split(systemProbe).length - 1, 1, "remote transport must contain one exact OS test boundary");
const script = path.join(root, "deploy-vps-remote.sh");
fs.writeFileSync(script, productionSource.replace(systemProbe, "SYSTEM_NAME=Darwin"), { mode: 0o700 });
const environment = {
  ...process.env,
  PATH: pathDirectory,
  PLATFORM_V1_INSTALL_TEST_SUDO: fakeSudo,
  PLATFORM_V1_INSTALL_TEST_SUDO_ARGUMENTS: sudoArguments,
  PLATFORM_V1_INSTALL_TEST_SUDO_SENTINEL: sudoSentinel,
  PLATFORM_V1_INSTALL_TEST_PATH_SHADOW_SENTINEL: pathShadowSentinel,
};

// The PATH shadow uses the conventional name, while the test seam remains an
// explicit absolute path. Production Linux ignores the seam entirely.
fs.mkdirSync(pathDirectory);
fs.symlinkSync(pathShadowSudo, path.join(pathDirectory, "sudo"));

const reset = () => {
  for (const file of [sudoSentinel, sudoArguments, pathShadowSentinel]) fs.rmSync(file, { force: true });
};
const run = (input, arguments_ = [], extraEnvironment = {}) => {
  reset();
  return spawnSync("/bin/sh", [script, ...arguments_], {
    encoding: null,
    input,
    env: { ...environment, ...extraEnvironment },
  });
};

async function assertOpenStdinCannotReachSudo(shell) {
  reset();
  const child = spawn(shell, [script], {
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
  });
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(fs.existsSync(sudoSentinel), false, `open stdin reached sudo before EOF under ${shell}`);
  child.stdin.end();
  const result = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status, signal) => resolve({ status, signal }));
  });
  assert.equal(result.status, 97, `EOF did not reach the fixed test sudo consumer under ${shell}`);
}

try {
  const transportShells = ["/bin/sh"];
  if (fs.existsSync("/bin/dash")
      && fs.realpathSync.native("/bin/dash") !== fs.realpathSync.native("/bin/sh")) {
    transportShells.push("/bin/dash");
  }
  for (const shell of transportShells) await assertOpenStdinCannotReachSudo(shell);

  const empty = run(Buffer.alloc(0));
  assert.equal(empty.status, 97, `empty stdin did not reach the fixed consumer: ${empty.stderr.toString()}`);
  assert.equal(fs.existsSync(sudoSentinel), true, "fixed sudo test seam was not invoked");
  assert.equal(fs.existsSync(pathShadowSentinel), false, "caller PATH selected sudo");
  assert.deepEqual(fs.readFileSync(sudoArguments, "utf8").trim().split("\n"), [
    "-n",
    "--",
    "/usr/local/libexec/platform-v1-brownfield-install-consumer",
    "install",
  ]);

  const request = run(Buffer.from('{"schema":"platform-activation-request/v3"}\n'));
  assert.equal(request.status, 64, "request bytes were accepted by the install-only transport");
  assert.match(request.stderr.toString(), /accepts no stdin/);
  assert.equal(fs.existsSync(sudoSentinel), false, "request bytes reached sudo");

  const nulByte = run(Buffer.from([0]));
  assert.equal(nulByte.status, 64, "a NUL byte was mistaken for empty stdin");
  assert.match(nulByte.stderr.toString(), /accepts no stdin/);
  assert.equal(fs.existsSync(sudoSentinel), false, "a NUL byte reached sudo");

  const argumentsResult = run(Buffer.alloc(0), ["--force", "/tmp/attacker"]);
  assert.equal(argumentsResult.status, 64, "caller arguments were accepted");
  assert.match(argumentsResult.stderr.toString(), /Usage: deploy-vps-remote\.sh/);
  assert.equal(fs.existsSync(sudoSentinel), false, "caller arguments reached sudo");

  const environmentResult = run(Buffer.alloc(0), ["attacker"], {
    PLATFORM_V1_CANDIDATE_COMMIT: "0".repeat(40),
    PLATFORM_V1_RELEASE_ROOT: "/tmp/attacker",
    V1_PROVIDER_GATES: "SATISFIED",
  });
  assert.equal(environmentResult.status, 64, "caller state selected a consumer target");
  assert.equal(fs.existsSync(sudoSentinel), false, "caller state reached sudo");

  const source = productionSource;
  for (const required of [
    "CONSUMER=/usr/local/libexec/platform-v1-brownfield-install-consumer",
    "SUDO=/usr/bin/sudo",
    "SYSTEM_NAME=$(/usr/bin/uname -s)",
    "exec 3<&0",
    "/usr/bin/od -An -tu1 -N1 <&3",
    "exec 3<&-",
    '[ -z "$stdin_octet" ]',
    'exec "$SUDO" -n -- "$CONSUMER" install < /dev/null',
  ]) assert.ok(source.includes(required), `install-only transport is missing ${required}`);
  for (const forbidden of ["git ", "docker ", "compose", "platform-activation-broker", "sourceArchive", "releaseRoot"] ) {
    assert.ok(!source.includes(forbidden), `install-only transport contains forbidden ${forbidden}`);
  }
  process.stdout.write("platform V1 install transport tests passed 7/7\n");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
