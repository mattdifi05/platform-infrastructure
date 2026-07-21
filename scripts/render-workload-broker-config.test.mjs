import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { renderNatsConfig, renderRedisAcl, writeProtectedConfig } from "./render-workload-broker-config.mjs";
import { brokerPolicySha256, expectedNatsPolicy, expectedRedisPolicy, normalizeWorkloadBrokers } from "./workload-broker-policy.mjs";

function redisWorkload(id) {
  const services = [{ name: `${id}-worker`, role: "worker" }];
  const secrets = [`${id}-redis-password`];
  return {
    id,
    brokers: normalizeWorkloadBrokers({ redis: expectedRedisPolicy(id) }, { id, services, secrets }),
  };
}

function natsWorkload(id, roles = ["worker"]) {
  const services = roles.map((role) => ({ name: `${id}-${role}`, role }));
  const secrets = services.map((service) => `${service.name}-nats-password`);
  return {
    id,
    brokers: normalizeWorkloadBrokers({ nats: expectedNatsPolicy(id, services) }, { id, services, secrets }),
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

test("renders deterministic NATS workload accounts with exact subject, queue and response permissions", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nats-config-render-"));
  try {
    writeSecret(root, "nats_password", "platform-nats-secret-value-1234567890");
    writeSecret(root, "alpha-app-web-nats-password", "alpha-web-secret-value-1234567890");
    writeSecret(root, "alpha-app-worker-nats-password", "alpha-worker-secret-value-1234567");
    writeSecret(root, "beta-app-worker-nats-password", "beta-worker-secret-value-12345678");
    const lock = verifiedLock([natsWorkload("beta-app"), natsWorkload("alpha-app", ["worker", "web"])]);
    const options = { secretsRoot: root, platformPasswordFile: path.join(root, "nats_password") };
    const rendered = renderNatsConfig(lock, options);
    assert.equal(rendered.text, renderNatsConfig(lock, options).text);
    assert.ok(rendered.text.indexOf("WL_ALPHA_APP") < rendered.text.indexOf("WL_BETA_APP"));
    assert.match(rendered.text, /user: "wl_alpha_app_worker"/);
    assert.match(rendered.text, /publish: \{ allow: \["workload\.alpha-app\.alpha-app-worker\.>"\], deny: \["\$JS\.>", "\$SYS\.>"\] \}/);
    assert.match(rendered.text, /subscribe: \{ allow: \["_INBOX\.>", "workload\.alpha-app\.alpha-app-worker\.> workload\.alpha-app\.alpha-app-worker"\], deny: \["\$JS\.>", "\$SYS\.>"\] \}/);
    assert.match(rendered.text, /allow_responses: \{ max: 1, expires: "2s" \}/);
    assert.doesNotMatch(rendered.text, /exports\s*[:=]|imports\s*[:=]|--user|--pass/);
    assert.equal(rendered.workloadAccounts, 2);
    assert.equal(rendered.workloadUsers, 3);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("independent NATS credential rotation changes only that service user stanza", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nats-config-rotation-"));
  try {
    writeSecret(root, "nats_password", "platform-nats-secret-value-1234567890");
    writeSecret(root, "alpha-app-web-nats-password", "alpha-web-secret-value-1234567890");
    writeSecret(root, "alpha-app-worker-nats-password", "alpha-worker-secret-value-1234567");
    const lock = verifiedLock([natsWorkload("alpha-app", ["web", "worker"])]);
    const options = { secretsRoot: root, platformPasswordFile: path.join(root, "nats_password") };
    const before = renderNatsConfig(lock, options);
    writeSecret(root, "alpha-app-worker-nats-password", "alpha-worker-rotated-value-12345");
    const after = renderNatsConfig(lock, options);
    const stanza = (text, username) => text.match(new RegExp(`user: "${username}"[\\s\\S]*?(?=\\n      \\}|\\n      \\},)`))?.[0];
    assert.equal(stanza(before.text, "wl_alpha_app_web"), stanza(after.text, "wl_alpha_app_web"));
    assert.notEqual(stanza(before.text, "wl_alpha_app_worker"), stanza(after.text, "wl_alpha_app_worker"));
    assert.notEqual(before.sha256, after.sha256);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("all-mode writes owner-only broker files and reports only digests", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "broker-config-cli-"));
  try {
    const secrets = path.join(root, "secrets");
    const redisOutput = path.join(root, "redis");
    const natsOutput = path.join(root, "nats");
    fs.mkdirSync(redisOutput, { mode: 0o700 });
    fs.mkdirSync(natsOutput, { mode: 0o700 });
    writeSecret(secrets, "redis_password", "platform-redis-secret-value-1234567");
    writeSecret(secrets, "nats_password", "platform-nats-secret-value-123456789");
    writeSecret(secrets, "alpha-app-worker-nats-password", "alpha-worker-secret-value-1234567");
    const lockPath = path.join(root, "hosted.lock.json");
    fs.writeFileSync(lockPath, JSON.stringify(verifiedLock([natsWorkload("alpha-app")])), { mode: 0o600 });
    const uid = typeof process.getuid === "function" ? process.getuid() : 0;
    const gid = typeof process.getgid === "function" ? process.getgid() : 0;
    const result = spawnSync(process.execPath, [
      path.join(path.dirname(new URL(import.meta.url).pathname), "render-workload-broker-config.mjs"),
      "all", "--lock", lockPath, "--secretsRoot", secrets,
      "--redisPlatformPasswordFile", path.join(secrets, "redis_password"),
      "--redisOutput", path.join(redisOutput, "redis-users.acl"),
      "--natsPlatformPasswordFile", path.join(secrets, "nats_password"),
      "--natsOutput", path.join(natsOutput, "nats-server.conf"),
      "--natsUid", String(uid), "--natsGid", String(gid),
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.kind, "broker-auth");
    assert.match(report.redis.sha256, /^[a-f0-9]{64}$/);
    assert.match(report.nats.sha256, /^[a-f0-9]{64}$/);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /platform-redis-secret|platform-nats-secret|alpha-worker-secret/);
    for (const filePath of [
      path.join(redisOutput, "redis-users.acl"),
      path.join(redisOutput, "redis-users.acl.sha256"),
      path.join(natsOutput, "nats-server.conf"),
      path.join(natsOutput, "nats-server.conf.sha256"),
    ]) {
      const stat = fs.statSync(filePath);
      assert.equal(stat.mode & 0o777, 0o600);
      assert.equal(stat.uid, uid);
      assert.equal(stat.gid, gid);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function writeSecret(root, name, value) {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(root, name), `${value}\n`, { mode: 0o600 });
}
