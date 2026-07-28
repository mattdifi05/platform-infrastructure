#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function exactStateDirectory(value) {
  const directory = path.resolve(String(value || ""));
  const stat = fs.lstatSync(directory, { throwIfNoEntry: false });
  if (!stat?.isDirectory() || stat.isSymbolicLink()) fail("Activation state directory must be a real directory.");
  if (fs.realpathSync.native(directory) !== directory) fail("Activation state directory must be canonical.");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    fail("Activation state directory must be owned by the deployment identity.");
  }
  if ((stat.mode & 0o777) !== 0o700) fail("Activation state directory must use mode 0700.");
  return directory;
}

function overlaps(left, right) {
  return left === right || left.startsWith(`${right}${path.sep}`) || right.startsWith(`${left}${path.sep}`);
}

function assertUnmounted(directory, modelPaths) {
  const stateCandidates = new Set([directory, fs.realpathSync.native(directory)]);
  for (const modelPath of modelPaths) {
    let model;
    try {
      model = JSON.parse(fs.readFileSync(modelPath, "utf8"));
    } catch {
      fail("Activation mount-overlap model is unreadable.");
    }
    for (const [serviceName, service] of Object.entries(model?.services ?? {})) {
      for (const volume of service?.volumes ?? []) {
        if (!volume || typeof volume !== "object" || volume.type !== "bind" || typeof volume.source !== "string") {
          continue;
        }
        const lexicalSource = path.resolve(volume.source);
        const sourceCandidates = new Set([lexicalSource]);
        try {
          sourceCandidates.add(fs.realpathSync.native(lexicalSource));
        } catch (error) {
          if (error?.code !== "ENOENT") fail(`Bind source cannot be resolved safely for ${serviceName}.`);
        }
        for (const stateCandidate of stateCandidates) {
          for (const sourceCandidate of sourceCandidates) {
            if (overlaps(stateCandidate, sourceCandidate)) {
              fail(`Activation state directory overlaps a container bind source for ${serviceName}.`);
            }
          }
        }
      }
    }
  }
}

function statePath(directory, name) {
  if (!new Set(["journal.json", "active.json", "activation.lock"]).has(name)) fail("Unsupported activation state object.");
  return path.join(directory, name);
}

function ensureLock(directory) {
  const target = statePath(directory, "activation.lock");
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow, 0o600);
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  const stat = fs.lstatSync(target, { bigint: true, throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
      || Number(stat.mode & 0o777n) !== 0o600
      || (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid()))) {
    fail("Activation mutex must be a single deployment-owned mode-0600 regular file.");
  }
  const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
  try {
    fs.fsyncSync(directoryDescriptor);
  } finally {
    fs.closeSync(directoryDescriptor);
  }
  process.stdout.write(`${target}\n`);
}

function stableObjectBytes(input) {
  let document;
  try {
    document = JSON.parse(input);
  } catch {
    fail("Activation state input must be valid JSON.");
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    fail("Activation state input must be a JSON object.");
  }
  return Buffer.from(`${JSON.stringify(document)}\n`);
}

function atomicWrite(directory, name, input) {
  const target = statePath(directory, name);
  const bytes = stableObjectBytes(input);
  const temporary = path.join(directory, `.${name}.${process.pid}.${crypto.randomBytes(16).toString("hex")}.tmp`);
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const descriptor = fs.openSync(
    temporary,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, target);
  const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
  try {
    fs.fsyncSync(directoryDescriptor);
  } finally {
    fs.closeSync(directoryDescriptor);
  }
}

function stableRead(directory, name, optional) {
  const target = statePath(directory, name);
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_RDONLY | noFollow);
  } catch (error) {
    if (optional && error?.code === "ENOENT") return null;
    fail(`Activation state object is unavailable: ${name}.`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n) fail(`Activation state object is not a single regular file: ${name}.`);
    if (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) {
      fail(`Activation state object has the wrong owner: ${name}.`);
    }
    if (Number(before.mode & 0o777n) !== 0o600) fail(`Activation state object has the wrong mode: ${name}.`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
      if (before[field] !== after[field]) fail(`Activation state object changed while being read: ${name}.`);
    }
    const canonical = stableObjectBytes(bytes.toString("utf8"));
    process.stdout.write(canonical);
    return canonical;
  } finally {
    fs.closeSync(descriptor);
  }
}

const [command, directoryArgument, name] = process.argv.slice(2);
if (command === "nonce") {
  process.stdout.write(`${crypto.randomBytes(32).toString("hex")}\n`);
  process.exit(0);
}
const directory = exactStateDirectory(directoryArgument);
if (command === "write") {
  atomicWrite(directory, name, fs.readFileSync(0, "utf8"));
} else if (command === "read") {
  stableRead(directory, name, false);
} else if (command === "read-optional") {
  stableRead(directory, name, true);
} else if (command === "ensure-lock") {
  ensureLock(directory);
} else if (command === "assert-unmounted") {
  if (!name) fail("At least one Compose model is required for mount-overlap validation.");
  assertUnmounted(directory, process.argv.slice(4));
} else {
  fail("Usage: platform-activation-state.mjs nonce | write|read|read-optional STATE_DIR journal.json|active.json | ensure-lock STATE_DIR | assert-unmounted STATE_DIR MODEL...");
}
