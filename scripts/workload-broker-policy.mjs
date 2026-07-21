import crypto from "node:crypto";

const ID = /^[a-z][a-z0-9-]{1,62}$/;

export const REDIS_WORKLOAD_COMMANDS = Object.freeze([
  "decr",
  "decrby",
  "del",
  "discard",
  "exec",
  "exists",
  "expire",
  "get",
  "hdel",
  "hexists",
  "hget",
  "hincrby",
  "hmget",
  "hmset",
  "hset",
  "incr",
  "incrby",
  "llen",
  "lpop",
  "lpush",
  "lrange",
  "mget",
  "mset",
  "multi",
  "pexpire",
  "ping",
  "psubscribe",
  "pttl",
  "publish",
  "rpop",
  "rpush",
  "sadd",
  "scard",
  "sismember",
  "smembers",
  "srem",
  "subscribe",
  "ttl",
  "unwatch",
  "watch",
  "zadd",
  "zcard",
  "zrange",
  "zrangebyscore",
  "zrem",
  "zscore",
]);

export const REDIS_DENIED_COMMANDS = Object.freeze([
  "acl",
  "bgrewriteaof",
  "bgsave",
  "config",
  "debug",
  "eval",
  "evalsha",
  "flushall",
  "flushdb",
  "function",
  "keys",
  "module",
  "monitor",
  "psync",
  "replicaof",
  "restore",
  "save",
  "scan",
  "script",
  "shutdown",
  "slaveof",
  "sync",
]);

export const NATS_SYSTEM_SUBJECT_DENIES = Object.freeze(["$JS.>", "$SYS.>"]);

export function normalizeWorkloadBrokers(value, { id, services, secrets }) {
  if (value === undefined || value === null) return { redis: null, nats: null };
  exactObject(value, ["nats", "redis"], `brokers for ${id}`, { optionalKeys: true });
  return {
    redis: value.redis == null ? null : normalizeRedisPolicy(value.redis, id, secrets),
    nats: value.nats == null ? null : normalizeNatsPolicy(value.nats, id, services, secrets),
  };
}

function normalizeRedisPolicy(value, id, secrets) {
  exactObject(value, [
    "channelPattern",
    "channelPrefix",
    "commands",
    "credentialSecret",
    "deniedCommands",
    "keyPattern",
    "keyPrefix",
    "username",
  ], `Redis policy for ${id}`);
  const expected = {
    username: workloadRedisUsername(id),
    credentialSecret: `${id}-redis-password`,
    keyPrefix: `${id}:`,
    keyPattern: `~${id}:*`,
    channelPrefix: `${id}:`,
    channelPattern: `&${id}:*`,
    commands: [...REDIS_WORKLOAD_COMMANDS],
    deniedCommands: [...REDIS_DENIED_COMMANDS],
  };
  if (!same(value, expected)) invalid(`Redis policy for ${id} must match the bounded workload ACL contract.`);
  if (!secrets.includes(expected.credentialSecret)) invalid(`Redis credential ${expected.credentialSecret} must be declared as a workload secret.`);
  return withPolicyDigest(expected);
}

function normalizeNatsPolicy(value, id, services, secrets) {
  exactObject(value, ["account", "exports", "imports", "users"], `NATS policy for ${id}`);
  const expectedAccount = workloadNatsAccount(id);
  if (value.account !== expectedAccount) invalid(`NATS account for ${id} must be ${expectedAccount}.`);
  if (!Array.isArray(value.exports) || value.exports.length !== 0 || !Array.isArray(value.imports) || value.imports.length !== 0) {
    invalid(`NATS exports/imports for ${id} require a separate exact-direction approval contract.`);
  }
  if (!Array.isArray(value.users) || value.users.length === 0) invalid(`NATS policy for ${id} must declare at least one service user.`);
  const serviceByName = new Map(services.map((service) => [service.name, service]));
  const seenServices = new Set();
  const users = value.users.map((user) => {
    exactObject(user, [
      "credentialSecret",
      "denyPublish",
      "denySubscribe",
      "publish",
      "queueGroups",
      "response",
      "role",
      "service",
      "subscribe",
      "username",
    ], `NATS user for ${id}`);
    const service = serviceByName.get(String(user.service ?? ""));
    if (!service || seenServices.has(service.name)) invalid(`NATS user for ${id} must bind one unique declared service.`);
    seenServices.add(service.name);
    const expected = expectedNatsUser(id, service);
    if (!same(user, expected)) invalid(`NATS user ${service.name} must match the bounded subject, queue and response contract.`);
    if (!secrets.includes(expected.credentialSecret)) invalid(`NATS credential ${expected.credentialSecret} must be declared as a workload secret.`);
    return expected;
  }).sort((left, right) => left.service.localeCompare(right.service));
  return withPolicyDigest({ account: expectedAccount, users, exports: [], imports: [] });
}

export function expectedRedisPolicy(id) {
  return {
    username: workloadRedisUsername(id),
    credentialSecret: `${id}-redis-password`,
    keyPrefix: `${id}:`,
    keyPattern: `~${id}:*`,
    channelPrefix: `${id}:`,
    channelPattern: `&${id}:*`,
    commands: [...REDIS_WORKLOAD_COMMANDS],
    deniedCommands: [...REDIS_DENIED_COMMANDS],
  };
}

export function expectedNatsPolicy(id, services) {
  return {
    account: workloadNatsAccount(id),
    users: services.map((service) => expectedNatsUser(id, service)).sort((left, right) => left.service.localeCompare(right.service)),
    exports: [],
    imports: [],
  };
}

function expectedNatsUser(id, service) {
  const subject = `workload.${id}.${service.name}.>`;
  return {
    service: service.name,
    role: service.role,
    username: `wl_${service.name.replaceAll("-", "_")}`,
    credentialSecret: `${service.name}-nats-password`,
    publish: [subject],
    subscribe: [subject, "_INBOX.>"],
    queueGroups: [`workload.${id}.${service.name}`],
    denyPublish: [...NATS_SYSTEM_SUBJECT_DENIES],
    denySubscribe: [...NATS_SYSTEM_SUBJECT_DENIES],
    response: { maxMessages: 1, ttl: "2s" },
  };
}

export function validateGlobalBrokerOwnership(workloads) {
  const redisUsers = new Map();
  const redisPrefixes = [];
  const natsAccounts = new Map();
  const natsUsers = new Map();
  const secrets = new Map();
  for (const workload of [...workloads].sort((left, right) => left.id.localeCompare(right.id))) {
    const redis = workload.brokers?.redis;
    if (redis) {
      assertPolicyDigest(redis, `${workload.id} Redis`);
      claim(redisUsers, redis.username, workload.id, "Redis username");
      claim(secrets, redis.credentialSecret, `${workload.id}/redis`, "broker credential secret");
      for (const previous of redisPrefixes) {
        if (redis.keyPrefix.startsWith(previous.prefix) || previous.prefix.startsWith(redis.keyPrefix)) {
          invalid(`Redis key prefixes overlap between ${previous.owner} and ${workload.id}.`);
        }
      }
      redisPrefixes.push({ prefix: redis.keyPrefix, owner: workload.id });
    }
    const nats = workload.brokers?.nats;
    if (nats) {
      assertPolicyDigest(nats, `${workload.id} NATS`);
      claim(natsAccounts, nats.account, workload.id, "NATS account");
      for (const user of nats.users) {
        claim(natsUsers, user.username, `${workload.id}/${user.service}`, "NATS username");
        claim(secrets, user.credentialSecret, `${workload.id}/${user.service}`, "broker credential secret");
      }
    }
  }
  return true;
}

export function brokerPolicySha256(workloads) {
  const projection = [...workloads]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((workload) => ({ id: workload.id, brokers: workload.brokers ?? { redis: null, nats: null } }));
  return crypto.createHash("sha256").update(JSON.stringify(stable(projection))).digest("hex");
}

export function assertBrokerPolicyDigest(lock) {
  validateGlobalBrokerOwnership(lock?.workloads ?? []);
  const expected = brokerPolicySha256(lock?.workloads ?? []);
  if (lock?.brokerPolicySha256 !== expected) invalid("Hosted workload broker policy digest does not match the locked tenant policy.");
  return true;
}

export function redisPolicyAllows(policy, { command, keys = [], channels = [] }) {
  const normalizedCommand = String(command ?? "").toLowerCase();
  return policy.commands.includes(normalizedCommand)
    && keys.every((key) => String(key).startsWith(policy.keyPrefix))
    && channels.every((channel) => String(channel).startsWith(policy.channelPrefix));
}

export function natsPolicyAllows(user, { operation, subject, queue = "" }) {
  if (!subject || String(subject).split(".").some((token) => !token || token === "*" || token === ">")) return false;
  const denied = operation === "publish" ? user.denyPublish : user.denySubscribe;
  const allowed = operation === "publish" ? user.publish : user.subscribe;
  if (!new Set(["publish", "subscribe"]).has(operation) || denied.some((pattern) => subjectMatches(pattern, subject))) return false;
  if (!allowed.some((pattern) => subjectMatches(pattern, subject))) return false;
  return !queue || user.queueGroups.includes(queue);
}

function subjectMatches(pattern, subject) {
  const expected = String(pattern).split(".");
  const actual = String(subject).split(".");
  for (let index = 0; index < expected.length; index += 1) {
    if (expected[index] === ">") return index < actual.length;
    if (expected[index] === "*") {
      if (actual[index] === undefined) return false;
      continue;
    }
    if (expected[index] !== actual[index]) return false;
  }
  return expected.length === actual.length;
}

function workloadRedisUsername(id) {
  return `wl_${id.replaceAll("-", "_")}`;
}

function workloadNatsAccount(id) {
  return `WL_${id.replaceAll("-", "_").toUpperCase()}`;
}

function withPolicyDigest(value) {
  return { ...value, policySha256: crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex") };
}

function assertPolicyDigest(policy, label) {
  const { policySha256, ...fields } = policy;
  const expected = crypto.createHash("sha256").update(JSON.stringify(stable(fields))).digest("hex");
  if (policySha256 !== expected) invalid(`${label} policy digest does not match its immutable authorization fields.`);
}

function claim(registry, value, owner, label) {
  const previous = registry.get(value);
  if (previous && previous !== owner) invalid(`${label} '${value}' is reused by ${previous} and ${owner}.`);
  registry.set(value, owner);
}

function exactObject(value, keys, label, { optionalKeys = false } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (optionalKeys ? actual.some((key) => !expected.includes(key)) : JSON.stringify(actual) !== JSON.stringify(expected)) {
    invalid(`${label} must contain only the exact supported fields.`);
  }
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
}

function same(left, right) {
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}

function invalid(message) {
  throw new Error(message);
}
