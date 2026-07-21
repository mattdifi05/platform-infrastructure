import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { renderRedisAcl, writeProtectedConfig } from "./render-workload-broker-config.mjs";
import { brokerPolicySha256, expectedRedisPolicy, normalizeWorkloadBrokers } from "./workload-broker-policy.mjs";

function redisWorkload(id) {
  const services = [{ name: `${id}-worker`, role: "worker" }];
  const secrets = [`${id}-redis-password`];
  return {
    id,
    brokers: normalizeWorkloadBrokers({ redis: expectedRedisPolicy(id) }, { id, services, secrets }),
  };
}

function verifiedLock(workloads) {
  return {
    version: 2,
    validatorVersion: "hosted-contract-v2",
    state: "verified",
    workloads,
    brokerPolicySha256: brokerPolicySha256(workloads),
  };
}

test("renders deterministic Redis ACL hashes with default user off and an explicit allowlist", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "redis-acl-render-"));
  try {
    writeSecret(root, "redis_password", "platform-secret-value-1234567890");
    writeSecret(root, "alpha-app-redis-password", "alpha-secret-value-123456789012");
    writeSecret(root, "beta-app-redis-password", "beta-secret-value-1234567890123");
    const lock = verifiedLock([redisWorkload("beta-app"), redisWorkload("alpha-app")]);
    const rendered = renderRedisAcl(lock, { secretsRoot: root, platformPasswordFile: path.join(root, "redis_password") });
    const repeated = renderRedisAcl(lock, { secretsRoot: root, platformPasswordFile: path.join(root, "redis_password") });
    assert.equal(rendered.text, repeated.text);
    assert.match(rendered.text, /^user default reset off$/m);
    assert.match(rendered.text, /^user platform reset on #[a-f0-9]{64} ~\* &\* \+@all$/m);
    assert.match(rendered.text, /^user wl_alpha_app reset on #[a-f0-9]{64} ~alpha-app:\* &alpha-app:\* -@all /m);
    assert.ok(rendered.text.indexOf("wl_alpha_app") < rendered.text.indexOf("wl_beta_app"));
    assert.doesNotMatch(rendered.text, /platform-secret|alpha-secret|beta-secret/);
    for (const command of ["flushall", "flushdb", "config", "acl", "module", "script", "eval", "keys", "scan"]) {
      assert.doesNotMatch(rendered.text, new RegExp(`\\+${command}(?:\\s|$)`));
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("independent Redis credential rotation changes only that tenant ACL line", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "redis-acl-rotation-"));
  try {
    writeSecret(root, "redis_password", "platform-secret-value-1234567890");
    writeSecret(root, "alpha-app-redis-password", "alpha-secret-value-123456789012");
    writeSecret(root, "beta-app-redis-password", "beta-secret-value-1234567890123");
    const lock = verifiedLock([redisWorkload("alpha-app"), redisWorkload("beta-app")]);
    const before = renderRedisAcl(lock, { secretsRoot: root, platformPasswordFile: path.join(root, "redis_password") });
    writeSecret(root, "alpha-app-redis-password", "alpha-rotated-value-12345678901");
    const after = renderRedisAcl(lock, { secretsRoot: root, platformPasswordFile: path.join(root, "redis_password") });
    const line = (text, username) => text.split("\n").find((item) => item.startsWith(`user ${username} `));
    assert.notEqual(line(before.text, "wl_alpha_app"), line(after.text, "wl_alpha_app"));
    assert.equal(line(before.text, "wl_beta_app"), line(after.text, "wl_beta_app"));
    assert.notEqual(before.sha256, after.sha256);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("writes Redis ACL and digest with owner-only modes and rejects symlink credentials", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "redis-acl-output-"));
  try {
    const secrets = path.join(root, "secrets");
    const output = path.join(root, "output");
    fs.mkdirSync(secrets, { mode: 0o700 });
    fs.mkdirSync(output, { mode: 0o700 });
    writeSecret(secrets, "redis_password", "platform-secret-value-1234567890");
    writeSecret(secrets, "alpha-app-redis-password", "alpha-secret-value-123456789012");
    const lock = verifiedLock([redisWorkload("alpha-app")]);
    const rendered = renderRedisAcl(lock, { secretsRoot: secrets, platformPasswordFile: path.join(secrets, "redis_password") });
    const written = writeProtectedConfig(path.join(output, "users.acl"), rendered);
    assert.equal(fs.statSync(written.outputPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(written.digestPath).mode & 0o777, 0o600);
    assert.match(fs.readFileSync(written.digestPath, "utf8"), new RegExp(`^${rendered.sha256}  users\\.acl`));
    const outside = path.join(root, "outside-secret");
    fs.writeFileSync(outside, "outside-secret-value-1234567890\n");
    fs.unlinkSync(path.join(secrets, "alpha-app-redis-password"));
    fs.symlinkSync(outside, path.join(secrets, "alpha-app-redis-password"));
    assert.throws(
      () => renderRedisAcl(lock, { secretsRoot: secrets, platformPasswordFile: path.join(secrets, "redis_password") }),
      /ELOOP|symbolic link|invalid/i,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function writeSecret(root, name, value) {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(root, name), `${value}\n`, { mode: 0o600 });
}
