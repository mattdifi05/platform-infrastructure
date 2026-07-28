#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "platform-activation-transport-")));
const fakeSudo = path.join(root, "sudo");
const fakeBroker = path.join(root, "broker");
const brokerInput = path.join(root, "broker-input");
const brokerArguments = path.join(root, "broker-arguments");
fs.writeFileSync(fakeSudo, "#!/bin/sh\n[ \"$1\" = -n ] || exit 91\nshift\nexec \"$@\"\n", { mode: 0o755 });
fs.writeFileSync(fakeBroker, `#!/bin/sh
printf '%s\\n' "$*" > "$PLATFORM_ACTIVATION_TEST_ARGUMENTS"
/bin/cat > "$PLATFORM_ACTIVATION_TEST_INPUT"
printf '{"status":"EXTERNAL-PENDING"}\\n'
`, { mode: 0o755 });

const script = path.join(import.meta.dirname, "deploy-vps-remote.sh");
const environment = {
  ...process.env,
  PATH: root,
  TMPDIR: path.join(root, "hostile-tmp"),
  PLATFORM_ACTIVATION_TEST_SUDO: fakeSudo,
  PLATFORM_ACTIVATION_TEST_BROKER: fakeBroker,
  PLATFORM_ACTIVATION_TEST_INPUT: brokerInput,
  PLATFORM_ACTIVATION_TEST_ARGUMENTS: brokerArguments,
};
const run = (input, arguments_ = []) => spawnSync("/bin/sh", [script, ...arguments_], {
  encoding: null,
  input,
  env: environment,
});

try {
  const request = Buffer.from('{"schema":"platform-activation-request/v1"}\n');
  const accepted = run(request);
  assert.equal(accepted.status, 0, accepted.stderr.toString());
  assert.deepEqual(fs.readFileSync(brokerInput), request);
  assert.equal(fs.readFileSync(brokerArguments, "utf8"), "activate\n");

  fs.rmSync(brokerInput, { force: true });
  const extraArgument = run(request, ["attacker-path"]);
  assert.notEqual(extraArgument.status, 0);
  assert.equal(fs.existsSync(brokerInput), false);

  const empty = run(Buffer.alloc(0));
  assert.notEqual(empty.status, 0);
  assert.equal(fs.existsSync(brokerInput), false);

  const exactLimit = run(Buffer.alloc(1024 * 1024, 0x61));
  assert.equal(exactLimit.status, 0, exactLimit.stderr.toString());
  assert.equal(fs.statSync(brokerInput).size, 1024 * 1024);

  fs.rmSync(brokerInput, { force: true });
  const oversized = run(Buffer.alloc((1024 * 1024) + 1, 0x62));
  assert.notEqual(oversized.status, 0);
  assert.equal(fs.existsSync(brokerInput), false);
  assert.match(oversized.stderr.toString(), /exceeds the 1 MiB transport bound/);

  assert.equal(fs.existsSync(environment.TMPDIR), false, "caller TMPDIR influenced the fixed transport");
  process.stdout.write("platform activation transport tests passed 5/5\n");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
