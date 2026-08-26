#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { assertBrokerPolicyDigest } from "./workload-broker-policy.mjs";

const SECRET_NAME = /^[a-z][a-z0-9_-]{1,127}$/;
const MAX_LOCK_BYTES = 8 * 1024 * 1024;

export function renderRedisAcl(lock, { secretsRoot, platformPasswordFile, platformUsername = "platform" }) {
  validateLock(lock);
  const credentials = loadRedisCredentials(lock, { secretsRoot, platformPasswordFile });
  assertUniqueCredentialMaterial(credentials.entries);
  return renderRedisAclWithCredentials(lock, { platformUsername, credentials });
}

function renderRedisAclWithCredentials(lock, { platformUsername, credentials }) {
  assertPlatformUsername(platformUsername, "Redis", { denyDefault: true });
  const lines = [
    "user default reset off",
    `user ${platformUsername} reset on #${credentials.platform.digest} ~* &* +@all`,
  ];
  const workloads = [...lock.workloads].sort((left, right) => left.id.localeCompare(right.id));
  for (const workload of workloads) {
    const policy = workload.brokers?.redis;
    if (!policy) continue;
    const credential = credentials.tenants.get(policy.credentialSecret);
    if (!credential) throw new Error("Redis tenant credential was not loaded.");
    const permissions = policy.commands.map((command) => `+${command}`).join(" ");
    lines.push(`user ${policy.username} reset on #${credential.digest} ${policy.keyPattern} ${policy.channelPattern} -@all ${permissions}`);
  }
  const text = `${lines.join("\n")}\n`;
  return {
    text,
    sha256: crypto.createHash("sha256").update(text).digest("hex"),
    policySha256: lock.brokerPolicySha256,
    workloadUsers: lines.length - 2,
  };
}

export function renderNatsConfig(lock, { secretsRoot, platformPasswordFile, platformUsername = "platform" }) {
  validateLock(lock);
  const credentials = loadNatsCredentials(lock, { secretsRoot, platformPasswordFile });
  assertUniqueCredentialMaterial(credentials.entries);
  return renderNatsConfigWithCredentials(lock, { platformUsername, credentials });
}

function renderNatsConfigWithCredentials(lock, { platformUsername, credentials }) {
  assertPlatformUsername(platformUsername, "NATS");
  const lines = [
    `# broker-policy-sha256: ${lock.brokerPolicySha256}`,
    'server_name: "enterprise-nats"',
    "port: 4222",
    "http_port: 8222",
    "",
    "jetstream {",
    '  store_dir: "/data/jetstream"',
    "  max_mem_store: 1Gb",
    "  max_file_store: 10Gb",
    "}",
    "",
    "max_payload: 8Mb",
    "max_connections: 65536",
    "debug: false",
    "trace: false",
    "",
    "accounts {",
    "  PLATFORM {",
    "    jetstream: enabled",
    "    users = [",
    "      {",
    `        user: ${configString(platformUsername)}`,
    `        password: ${configString(credentials.platform.value)}`,
    "        permissions: {",
    '          publish: { allow: [">"], deny: [] }',
    '          subscribe: { allow: [">"], deny: [] }',
    "        }",
    "      }",
    "    ]",
    "  }",
  ];
  let accountCount = 0;
  let userCount = 0;
  const workloads = [...lock.workloads].sort((left, right) => left.id.localeCompare(right.id));
  for (const workload of workloads) {
    const policy = workload.brokers?.nats;
    if (!policy) continue;
    accountCount += 1;
    lines.push(`  ${policy.account} {`, "    jetstream: enabled", "    users = [");
    const users = [...policy.users].sort((left, right) => left.service.localeCompare(right.service));
    users.forEach((user, index) => {
      userCount += 1;
      const credential = credentials.tenants.get(user.credentialSecret);
      if (!credential) throw new Error("NATS tenant credential was not loaded.");
      const queueSubscriptions = user.subscribe
        .filter((subject) => subject !== "_INBOX.>")
        .flatMap((subject) => user.queueGroups.map((queue) => `${subject} ${queue}`));
      const inboxSubscriptions = user.subscribe.filter((subject) => subject === "_INBOX.>");
      lines.push(
        "      {",
        `        user: ${configString(user.username)}`,
        `        password: ${configString(credential.value)}`,
        "        permissions: {",
        `          publish: { allow: ${configArray(user.publish)}, deny: ${configArray(user.denyPublish)} }`,
        `          subscribe: { allow: ${configArray([...inboxSubscriptions, ...queueSubscriptions])}, deny: ${configArray(user.denySubscribe)} }`,
        `          allow_responses: { max: ${user.response.maxMessages}, expires: ${configString(user.response.ttl)} }`,
        "        }",
        index === users.length - 1 ? "      }" : "      },",
      );
    });
    lines.push("    ]", "  }");
  }
  lines.push("}");
  const text = `${lines.join("\n")}\n`;
  return {
    text,
    sha256: crypto.createHash("sha256").update(text).digest("hex"),
    policySha256: lock.brokerPolicySha256,
    workloadAccounts: accountCount,
    workloadUsers: userCount,
  };
}

export function renderBrokerConfigs(lock, {
  secretsRoot,
  redisPlatformPasswordFile,
  natsPlatformPasswordFile,
  redisPlatformUsername = "platform",
  natsPlatformUsername = "platform",
}) {
  validateLock(lock);
  const redisCredentials = loadRedisCredentials(lock, { secretsRoot, platformPasswordFile: redisPlatformPasswordFile });
  const natsCredentials = loadNatsCredentials(lock, { secretsRoot, platformPasswordFile: natsPlatformPasswordFile });
  assertUniqueCredentialMaterial([...redisCredentials.entries, ...natsCredentials.entries]);
  return {
    redis: renderRedisAclWithCredentials(lock, { platformUsername: redisPlatformUsername, credentials: redisCredentials }),
    nats: renderNatsConfigWithCredentials(lock, { platformUsername: natsPlatformUsername, credentials: natsCredentials }),
  };
}

export function writeProtectedConfig(outputPath, rendered, { mode = 0o600, uid = null, gid = null, io = fs } = {}) {
  const destination = path.resolve(outputPath);
  const parent = path.dirname(destination);
  const parentStat = io.lstatSync(parent, { throwIfNoEntry: false });
  if (!parentStat?.isDirectory() || parentStat.isSymbolicLink()) throw new Error("Broker config output parent must be a real directory.");
  const temporary = path.join(parent, `.${path.basename(destination)}.tmp-${process.pid}-${Date.now()}`);
  try {
    io.writeFileSync(temporary, rendered.text, { flag: "wx", mode });
    io.chmodSync(temporary, mode);
    applyOwnership(temporary, uid, gid, io);
    io.renameSync(temporary, destination);
    const digestPath = `${destination}.sha256`;
    const digestTemporary = `${temporary}.sha256`;
    io.writeFileSync(digestTemporary, `${rendered.sha256}  ${path.basename(destination)}\n`, { mode, flag: "wx" });
    io.chmodSync(digestTemporary, mode);
    applyOwnership(digestTemporary, uid, gid, io);
    io.renameSync(digestTemporary, digestPath);
    return { outputPath: destination, digestPath };
  } finally {
    io.rmSync(temporary, { force: true });
    io.rmSync(`${temporary}.sha256`, { force: true });
  }
}

function applyOwnership(filePath, uid, gid, io = fs) {
  if (uid === null && gid === null) return;
  if (!Number.isSafeInteger(uid) || uid < 0 || !Number.isSafeInteger(gid) || gid < 0) {
    throw new Error("Broker config owner must be a non-negative numeric uid and gid.");
  }
  io.chownSync(filePath, uid, gid);
}

const SUPPORTED_LOCK_CONTRACTS = Object.freeze([
  Object.freeze({ version: 2, validatorVersion: "hosted-contract-v2" }),
  Object.freeze({ version: 4, validatorVersion: "hosted-contract-v4" }),
]);

function validateLock(lock) {
  const supportedContract = SUPPORTED_LOCK_CONTRACTS.some((contract) => lock?.version === contract.version && lock?.validatorVersion === contract.validatorVersion);
  if (!supportedContract || lock.state !== "verified" || !Array.isArray(lock.workloads)) {
    throw new Error("Broker authorization requires a verified hosted workload lock.");
  }
  assertBrokerPolicyDigest(lock);
}

function assertPlatformUsername(value, broker, { denyDefault = false } = {}) {
  if (!/^[a-z][a-z0-9_-]{1,63}$/.test(String(value ?? "")) || (denyDefault && value === "default")) {
    throw new Error(`${broker} platform username is invalid.`);
  }
}

function loadRedisCredentials(lock, { secretsRoot, platformPasswordFile }) {
  const platform = credentialRecord(readSecretFile(platformPasswordFile));
  const tenants = new Map();
  const entries = [platform];
  for (const workload of [...lock.workloads].sort((left, right) => left.id.localeCompare(right.id))) {
    const policy = workload.brokers?.redis;
    if (!policy) continue;
    const credential = credentialRecord(readNamedSecret(secretsRoot, policy.credentialSecret));
    tenants.set(policy.credentialSecret, credential);
    entries.push(credential);
  }
  return { platform, tenants, entries };
}

function loadNatsCredentials(lock, { secretsRoot, platformPasswordFile }) {
  const platform = credentialRecord(readSecretFile(platformPasswordFile));
  const tenants = new Map();
  const entries = [platform];
  for (const workload of [...lock.workloads].sort((left, right) => left.id.localeCompare(right.id))) {
    const users = [...(workload.brokers?.nats?.users ?? [])].sort((left, right) => left.service.localeCompare(right.service));
    for (const user of users) {
      const credential = credentialRecord(readNamedSecret(secretsRoot, user.credentialSecret));
      tenants.set(user.credentialSecret, credential);
      entries.push(credential);
    }
  }
  return { platform, tenants, entries };
}

function credentialRecord(value) {
  assertCredentialStrength(value);
  return { value, digest: crypto.createHash("sha256").update(value).digest("hex") };
}

function assertCredentialStrength(value) {
  const characters = [...value];
  const byteLength = Buffer.byteLength(value, "utf8");
  const periodic = Array.from({ length: Math.min(16, Math.floor(characters.length / 2)) }, (_, index) => index + 1)
    .some((period) => characters.length % period === 0
      && characters.every((character, index) => character === characters[index % period]));
  if (byteLength < 32 || new Set(characters).size < 10 || periodic) {
    throw new Error("Broker credential does not meet the required strength policy.");
  }
}

function assertUniqueCredentialMaterial(credentials) {
  const seen = new Set();
  for (const credential of credentials) {
    if (seen.has(credential.digest)) throw new Error("Broker credential material is reused across principals.");
    seen.add(credential.digest);
  }
}

function readNamedSecret(root, name) {
  if (!SECRET_NAME.test(String(name ?? ""))) throw new Error("Broker credential secret name is invalid.");
  const canonicalRoot = fs.realpathSync.native(path.resolve(root));
  const candidate = path.join(canonicalRoot, name);
  if (path.dirname(candidate) !== canonicalRoot) throw new Error("Broker credential escaped its secret root.");
  return readSecretFile(candidate);
}

function readSecretFile(filePath) {
  let descriptor;
  try {
    descriptor = fs.openSync(path.resolve(filePath), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size < 16 || before.size > 4096) throw new Error("Broker credential file is invalid.");
    const first = readDescriptor(descriptor, before.size);
    const second = readDescriptor(descriptor, before.size);
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || !crypto.timingSafeEqual(first, second)) {
      throw new Error("Broker credential changed while being read.");
    }
    const value = first.toString("utf8").trim();
    if (value.length < 16 || /[\0\r\n]/.test(value)) throw new Error("Broker credential content is invalid.");
    return value;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readDescriptor(descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = fs.readSync(descriptor, bytes, offset, size - offset, offset);
    if (count === 0) break;
    offset += count;
  }
  if (offset !== size) throw new Error("Broker credential changed while being read.");
  return bytes;
}

function configString(value) {
  return JSON.stringify(String(value));
}

function configArray(values) {
  return `[${values.map(configString).join(", ")}]`;
}

function readLock(filePath) {
  let descriptor;
  try {
    descriptor = fs.openSync(path.resolve(filePath), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size < 2 || before.size > MAX_LOCK_BYTES) throw new Error("Hosted workload lock file is invalid.");
    const first = readDescriptor(descriptor, before.size);
    const second = readDescriptor(descriptor, before.size);
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || !crypto.timingSafeEqual(first, second)) {
      throw new Error("Hosted workload lock changed while being read.");
    }
    return JSON.parse(first.toString("utf8"));
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseArgs(values) {
  const out = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error("Broker config arguments must use --name value pairs.");
    out[key.slice(2)] = value;
  }
  return out;
}

function main() {
  const command = process.argv[2];
  const args = parseArgs(process.argv.slice(3));
  const lock = readLock(args.lock);
  if (command === "redis") {
    const rendered = renderRedisAcl(lock, {
      secretsRoot: args.secretsRoot,
      platformPasswordFile: args.platformPasswordFile,
      platformUsername: args.platformUsername || "platform",
    });
    writeProtectedConfig(args.output, rendered);
    process.stdout.write(`${JSON.stringify({ status: "written", kind: "redis-acl", sha256: rendered.sha256, policySha256: rendered.policySha256, workloadUsers: rendered.workloadUsers })}\n`);
    return;
  }
  if (command === "nats") {
    const rendered = renderNatsConfig(lock, {
      secretsRoot: args.secretsRoot,
      platformPasswordFile: args.platformPasswordFile,
      platformUsername: args.platformUsername || "platform",
    });
    writeProtectedConfig(args.output, rendered, ownerOptions(args));
    process.stdout.write(`${JSON.stringify({ status: "written", kind: "nats-config", sha256: rendered.sha256, policySha256: rendered.policySha256, workloadAccounts: rendered.workloadAccounts, workloadUsers: rendered.workloadUsers })}\n`);
    return;
  }
  if (command === "all") {
    const { redis, nats } = renderBrokerConfigs(lock, {
      secretsRoot: args.secretsRoot,
      redisPlatformPasswordFile: args.redisPlatformPasswordFile,
      natsPlatformPasswordFile: args.natsPlatformPasswordFile,
    });
    writeProtectedConfig(args.redisOutput, redis);
    writeProtectedConfig(args.natsOutput, nats, ownerOptions(args, "nats"));
    process.stdout.write(`${JSON.stringify({ status: "written", kind: "broker-auth", policySha256: lock.brokerPolicySha256, redis: { sha256: redis.sha256, workloadUsers: redis.workloadUsers }, nats: { sha256: nats.sha256, workloadAccounts: nats.workloadAccounts, workloadUsers: nats.workloadUsers } })}\n`);
    return;
  }
  throw new Error("Usage: render-workload-broker-config.mjs redis|nats|all --lock PATH --secretsRoot PATH ...");
}

function ownerOptions(args, prefix = "") {
  const key = (name) => prefix ? `${prefix}${name[0].toUpperCase()}${name.slice(1)}` : name;
  const uid = args[key("uid")];
  const gid = args[key("gid")];
  if (uid === undefined && gid === undefined) return {};
  if (!/^(?:0|[1-9][0-9]{0,9})$/.test(String(uid ?? "")) || !/^(?:0|[1-9][0-9]{0,9})$/.test(String(gid ?? ""))) {
    throw new Error("Broker config owner requires numeric --uid and --gid values.");
  }
  return { uid: Number(uid), gid: Number(gid) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
