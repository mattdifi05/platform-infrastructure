import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { redactSensitiveText, runCommandSync } from "./command-safety.mjs";
import { resticSecretTransport } from "./restic-secret-transport.mjs";

const credential = "synthetic-restic-password-for-test";
const repository = `rest:https://backup-user:${credential}@backup.invalid/platform?token=${credential}`;
const here = path.dirname(fileURLToPath(import.meta.url));

test("repository value stays out of Docker argv and process listings", () => {
  const transport = resticSecretTransport(repository, "/run/restic/password");
  const argv = ["docker", "run", "--rm", ...transport.dockerArgs, "restic:test", "snapshots"];
  assert.equal(argv.join(" ").includes(repository), false);
  assert.equal(argv.join(" ").includes(credential), false);
  assert.equal(transport.processEnv.RESTIC_REPOSITORY, repository);
  assert.equal(transport.processEnv.RESTIC_PASSWORD_FILE, "/run/restic/password");
});

test("infra Restic execution uses the key-only environment transport", () => {
  const source = fs.readFileSync(path.join(here, "infra-ops.mjs"), "utf8");
  assert.doesNotMatch(source, /RESTIC_REPOSITORY=\$\{repository\}/);
  assert.match(source, /resticSecretTransport\(repository,/);
  assert.match(source, /invocation\.secretTransport\.processEnv/);
  assert.match(source, /invocation\.secretTransport\.sensitiveValues/);
});

test("raw, URI, percent-encoded, and base64 repository credentials are redacted", () => {
  const payload = [repository, `https://backup-user:${credential}@backup.invalid/path`, encodeURIComponent(repository), Buffer.from(repository).toString("base64")].join("\n");
  const clean = redactSensitiveText(payload, [repository, credential]);
  assert.equal(clean.includes(repository), false);
  assert.equal(clean.includes(credential), false);
  assert.match(clean, /\[REDACTED\]/);
});

test("synthetic command failure cannot serialize the repository credential", () => {
  const script = [
    `process.stdout.write(${JSON.stringify(repository)});`,
    `process.stderr.write(${JSON.stringify(Buffer.from(repository).toString("base64"))});`,
    "process.exit(7);",
  ].join("\n");
  assert.throws(
    () => runCommandSync(process.execPath, ["-e", script, repository], { capture: true, sensitiveValues: [repository, credential] }),
    (error) => {
      assert.equal(error.message.includes(repository), false);
      assert.equal(error.message.includes(credential), false);
      assert.match(error.message, /\[REDACTED\]/);
      return true;
    },
  );
});
