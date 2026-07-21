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
  if (!/^[a-z][a-z0-9_-]{1,63}$/.test(platformUsername) || platformUsername === "default") {
    throw new Error("Redis platform username is invalid.");
  }
  const lines = [
    "user default reset off",
    `user ${platformUsername} reset on #${passwordSha256(readSecretFile(platformPasswordFile))} ~* &* +@all`,
  ];
  const workloads = [...lock.workloads].sort((left, right) => left.id.localeCompare(right.id));
  for (const workload of workloads) {
    const policy = workload.brokers?.redis;
    if (!policy) continue;
    const password = readNamedSecret(secretsRoot, policy.credentialSecret);
    const permissions = policy.commands.map((command) => `+${command}`).join(" ");
    lines.push(`user ${policy.username} reset on #${passwordSha256(password)} ${policy.keyPattern} ${policy.channelPattern} -@all ${permissions}`);
  }
  const text = `${lines.join("\n")}\n`;
  return {
    text,
    sha256: crypto.createHash("sha256").update(text).digest("hex"),
    policySha256: lock.brokerPolicySha256,
    workloadUsers: lines.length - 2,
  };
}

export function writeProtectedConfig(outputPath, rendered, { mode = 0o600 } = {}) {
  const destination = path.resolve(outputPath);
  const parent = path.dirname(destination);
  const parentStat = fs.lstatSync(parent, { throwIfNoEntry: false });
  if (!parentStat?.isDirectory() || parentStat.isSymbolicLink()) throw new Error("Broker config output parent must be a real directory.");
  const temporary = path.join(parent, `.${path.basename(destination)}.tmp-${process.pid}-${Date.now()}`);
  try {
    fs.writeFileSync(temporary, rendered.text, { flag: "wx", mode });
    fs.chmodSync(temporary, mode);
    fs.renameSync(temporary, destination);
    const digestPath = `${destination}.sha256`;
    const digestTemporary = `${temporary}.sha256`;
    fs.writeFileSync(digestTemporary, `${rendered.sha256}  ${path.basename(destination)}\n`, { mode, flag: "wx" });
    fs.chmodSync(digestTemporary, mode);
    fs.renameSync(digestTemporary, digestPath);
    return { outputPath: destination, digestPath };
  } finally {
    fs.rmSync(temporary, { force: true });
    fs.rmSync(`${temporary}.sha256`, { force: true });
  }
}

function validateLock(lock) {
  if (lock?.version !== 2 || lock?.validatorVersion !== "hosted-contract-v2" || lock?.state !== "verified" || !Array.isArray(lock.workloads)) {
    throw new Error("Broker authorization requires a verified hosted workload lock.");
  }
  assertBrokerPolicyDigest(lock);
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

function passwordSha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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
  if (command !== "redis") throw new Error("Usage: render-workload-broker-config.mjs redis --lock PATH --secretsRoot PATH --platformPasswordFile PATH --output PATH");
  const rendered = renderRedisAcl(readLock(args.lock), {
    secretsRoot: args.secretsRoot,
    platformPasswordFile: args.platformPasswordFile,
    platformUsername: args.platformUsername || "platform",
  });
  writeProtectedConfig(args.output, rendered);
  process.stdout.write(`${JSON.stringify({ status: "written", kind: "redis-acl", sha256: rendered.sha256, policySha256: rendered.policySha256, workloadUsers: rendered.workloadUsers })}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
