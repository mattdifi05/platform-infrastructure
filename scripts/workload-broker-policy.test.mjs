import assert from "node:assert/strict";
import test from "node:test";

import {
  assertBrokerPolicyDigest,
  brokerPolicySha256,
  expectedNatsPolicy,
  expectedRedisPolicy,
  natsPolicyAllows,
  normalizeWorkloadBrokers,
  redisPolicyAllows,
  validateGlobalBrokerOwnership,
} from "./workload-broker-policy.mjs";

const alphaServices = [
  { name: "alpha-app-web", role: "web" },
  { name: "alpha-app-worker", role: "worker" },
];
const alphaSecrets = ["alpha-app-redis-password", "alpha-app-web-nats-password", "alpha-app-worker-nats-password"];

function normalized(id = "alpha-app", services = alphaServices, secrets = alphaSecrets) {
  return normalizeWorkloadBrokers({
    redis: expectedRedisPolicy(id),
    nats: expectedNatsPolicy(id, services),
  }, { id, services, secrets });
}

test("normalizes immutable Redis and NATS identity policy and binds its digest", () => {
  const brokers = normalized();
  assert.equal(brokers.redis.username, "wl_alpha_app");
  assert.equal(brokers.redis.keyPattern, "~alpha-app:*");
  assert.equal(brokers.redis.channelPattern, "&alpha-app:*");
  assert.equal(brokers.nats.account, "WL_ALPHA_APP");
  assert.deepEqual(brokers.nats.exports, []);
  assert.deepEqual(brokers.nats.imports, []);
  assert.equal(brokers.nats.users[0].credentialSecret, "alpha-app-web-nats-password");
  const workloads = [{ id: "alpha-app", brokers }];
  const lock = { workloads, brokerPolicySha256: brokerPolicySha256(workloads) };
  assert.equal(assertBrokerPolicyDigest(lock), true);
  assert.throws(() => assertBrokerPolicyDigest({ ...lock, brokerPolicySha256: "0".repeat(64) }), /digest/);
  assert.equal(brokerPolicySha256([]), "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945");
});

test("rejects widened Redis commands, escaping prefixes, missing secrets and global credentials", () => {
  const policy = expectedRedisPolicy("alpha-app");
  assert.throws(
    () => normalizeWorkloadBrokers({ redis: { ...policy, commands: [...policy.commands, "flushall"] } }, { id: "alpha-app", services: alphaServices, secrets: alphaSecrets }),
    /bounded workload ACL/,
  );
  assert.throws(
    () => normalizeWorkloadBrokers({ redis: { ...policy, keyPattern: "~*" } }, { id: "alpha-app", services: alphaServices, secrets: alphaSecrets }),
    /bounded workload ACL/,
  );
  assert.throws(
    () => normalizeWorkloadBrokers({ redis: { ...policy, credentialSecret: "redis-password" } }, { id: "alpha-app", services: alphaServices, secrets: alphaSecrets }),
    /bounded workload ACL/,
  );
  assert.throws(
    () => normalizeWorkloadBrokers({ redis: policy }, { id: "alpha-app", services: alphaServices, secrets: [] }),
    /must be declared/,
  );
});

test("Redis policy model allows own keys and channels but denies cross-tenant, enumeration and admin commands", () => {
  const policy = normalized().redis;
  assert.equal(redisPolicyAllows(policy, { command: "get", keys: ["alpha-app:session:1"] }), true);
  assert.equal(redisPolicyAllows(policy, { command: "publish", channels: ["alpha-app:events"] }), true);
  assert.equal(redisPolicyAllows(policy, { command: "get", keys: ["beta-app:session:1"] }), false);
  assert.equal(redisPolicyAllows(policy, { command: "publish", channels: ["beta-app:events"] }), false);
  for (const command of ["keys", "scan", "flushall", "flushdb", "config", "acl", "module", "script", "eval"]) {
    assert.equal(redisPolicyAllows(policy, { command }), false, command);
  }
});

test("rejects missing or widened NATS service policies, exports and imports", () => {
  const policy = expectedNatsPolicy("alpha-app", alphaServices);
  assert.throws(
    () => normalizeWorkloadBrokers({ nats: { ...policy, users: [] } }, { id: "alpha-app", services: alphaServices, secrets: alphaSecrets }),
    /at least one/,
  );
  const widened = structuredClone(policy);
  widened.users[0].publish = [">"];
  assert.throws(
    () => normalizeWorkloadBrokers({ nats: widened }, { id: "alpha-app", services: alphaServices, secrets: alphaSecrets }),
    /bounded subject/,
  );
  assert.throws(
    () => normalizeWorkloadBrokers({ nats: { ...policy, exports: [{ subject: "workload.alpha-app.>" }] } }, { id: "alpha-app", services: alphaServices, secrets: alphaSecrets }),
    /exact-direction approval/,
  );
});

test("NATS policy model allows exact own subjects and queue but denies cross, wildcard and system subjects", () => {
  const user = normalized().nats.users.find((item) => item.service === "alpha-app-worker");
  assert.equal(natsPolicyAllows(user, { operation: "publish", subject: "workload.alpha-app.alpha-app-worker.event" }), true);
  assert.equal(natsPolicyAllows(user, { operation: "subscribe", subject: "workload.alpha-app.alpha-app-worker.event", queue: "workload.alpha-app.alpha-app-worker" }), true);
  assert.equal(natsPolicyAllows(user, { operation: "publish", subject: "workload.alpha-app.alpha-app-web.event" }), false);
  assert.equal(natsPolicyAllows(user, { operation: "publish", subject: "workload.beta-app.beta-app-worker.event" }), false);
  assert.equal(natsPolicyAllows(user, { operation: "subscribe", subject: "workload.alpha-app.alpha-app-worker.*" }), false);
  assert.equal(natsPolicyAllows(user, { operation: "subscribe", subject: "$SYS.REQ.SERVER.PING" }), false);
  assert.equal(natsPolicyAllows(user, { operation: "publish", subject: "$JS.API.STREAM.CREATE" }), false);
  assert.equal(natsPolicyAllows(user, { operation: "subscribe", subject: "workload.alpha-app.alpha-app-worker.event", queue: "foreign" }), false);
});

test("global ownership rejects reused Redis/NATS identities, secrets and overlapping prefixes", () => {
  const alpha = { id: "alpha-app", brokers: normalized() };
  const betaServices = [{ name: "beta-app-worker", role: "worker" }];
  const betaSecrets = ["beta-app-redis-password", "beta-app-worker-nats-password"];
  const beta = { id: "beta-app", brokers: normalized("beta-app", betaServices, betaSecrets) };
  assert.equal(validateGlobalBrokerOwnership([beta, alpha]), true);
  const duplicateUser = structuredClone(beta);
  duplicateUser.brokers.redis.username = alpha.brokers.redis.username;
  assert.throws(() => validateGlobalBrokerOwnership([duplicateUser, alpha]), /Redis username/);
  const duplicateSecret = structuredClone(beta);
  duplicateSecret.brokers.nats.users[0].credentialSecret = alpha.brokers.redis.credentialSecret;
  assert.throws(() => validateGlobalBrokerOwnership([duplicateSecret, alpha]), /credential secret/);
  const overlap = structuredClone(beta);
  overlap.brokers.redis.keyPrefix = alpha.brokers.redis.keyPrefix;
  assert.throws(() => validateGlobalBrokerOwnership([overlap, alpha]), /prefixes overlap/);
});
