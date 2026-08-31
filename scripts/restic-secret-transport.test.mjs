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
  assert.match(source, /invocation\.secretTransport\.sensitiveEnvironmentKeys/);
  assert.match(
    source,
    /hostPathForContainerMount\(passwordFile\)}:\/restic-password\/\$\{resticPasswordName\}:ro/,
    "Restic helper must receive only the exact password file, never its secret-bearing parent directory",
  );
  assert.doesNotMatch(source, /hostPathForContainerMount\(resticPasswordDir\)/);
  assert.match(
    source,
    /\[process\.env\.LOCAL_PRIVATE_BACKUP_BROKER_STATE_CONTAINER_ROOT, process\.env\.LOCAL_PRIVATE_BACKUP_BROKER_STATE_HOST_ROOT\]/,
    "Restic OAuth staging needs an exact closed container-to-host mapping outside shared platform state",
  );
  const compose = fs.readFileSync(path.join(here, "..", "compose.local-private-backup.yaml"), "utf8");
  assert.match(compose, /LOCAL_PRIVATE_BACKUP_BROKER_STATE_CONTAINER_ROOT: \/var\/lib\/platform-docker-action-broker/);
  assert.match(compose, /LOCAL_PRIVATE_BACKUP_BROKER_STATE_HOST_ROOT: \$\{LOCAL_PRIVATE_BACKUP_BROKER_STATE_DIR[^}]*\}/);
});

test("raw, URI, percent-encoded, and base64 repository credentials are redacted", () => {
  const payload = [repository, `https://backup-user:${credential}@backup.invalid/path`, encodeURIComponent(repository), Buffer.from(repository).toString("base64")].join("\n");
  const clean = redactSensitiveText(payload, [repository, credential]);
  assert.equal(clean.includes(repository), false);
  assert.equal(clean.includes(credential), false);
  assert.match(clean, /\[REDACTED\]/);
});

test("synthetic command failure cannot serialize the repository credential", () => {
  const transport = resticSecretTransport(repository, "/run/restic/password");
  const script = [
    `process.stdout.write(${JSON.stringify(`${credential}\nbackup-user`)});`,
    `process.stderr.write(${JSON.stringify(Buffer.from(repository).toString("base64"))});`,
    "process.exit(7);",
  ].join("\n");
  assert.throws(
    () => runCommandSync(process.execPath, ["-e", script, repository], {
      capture: true,
      sensitiveValues: transport.sensitiveValues,
    }),
    (error) => {
      assert.equal(error.message.includes(repository), false);
      assert.equal(error.message.includes(credential), false);
      assert.equal(error.message.includes("backup-user"), false);
      assert.match(error.message, /\[REDACTED\]/);
      return true;
    },
  );
});

test("passthrough credential environment values are discovered by key and redacted", () => {
  const inheritedCredential = "synthetic-inherited-provider-credential";
  const transport = resticSecretTransport(repository, "/run/restic/password");
  const script = `process.stderr.write(process.env.AWS_SECRET_ACCESS_KEY); process.exit(9);`;
  assert.equal(transport.sensitiveEnvironmentKeys.includes("AWS_SECRET_ACCESS_KEY"), true);
  assert.throws(
    () => runCommandSync(process.execPath, ["-e", script], {
      capture: true,
      env: { ...process.env, AWS_SECRET_ACCESS_KEY: inheritedCredential },
      sensitiveValues: transport.sensitiveValues,
      sensitiveEnvironmentKeys: transport.sensitiveEnvironmentKeys,
    }),
    (error) => {
      assert.equal(error.message.includes(inheritedCredential), false);
      assert.match(error.message, /\[REDACTED\]/);
      return true;
    },
  );
});
