#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  ACTIONS,
  CLI_ACTIONS,
  REQUEST_SCHEMA,
  signActionRequest,
} from "./docker-action-contract.mjs";

const DEFAULT_SOCKET = "/run/platform/docker-action-broker/broker.sock";
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export function buildClientRequest(command, args, {
  runtimeIntentId,
  activeReceiptSha256,
  combinedRenderSha256,
  capabilityKey,
  now = Date.now(),
  requestId,
  nonce,
} = {}) {
  const action = CLI_ACTIONS[command];
  const contract = ACTIONS[action];
  if (!contract) throw new Error(`Unsupported Docker action command: ${command || "(empty)"}`);
  const parameters = parseParameters(action, args);
  const issuedAt = new Date(now);
  const request = {
    schema: REQUEST_SCHEMA,
    requestId: requestId ?? crypto.randomUUID(),
    nonce: nonce ?? crypto.randomBytes(32).toString("base64url"),
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 30_000).toISOString(),
    runtimeIntentId: String(runtimeIntentId ?? ""),
    activeReceiptSha256: String(activeReceiptSha256 ?? ""),
    combinedRenderSha256: String(combinedRenderSha256 ?? ""),
    capabilityId: contract.capabilityId,
    action,
    parameters,
  };
  return signActionRequest(request, capabilityKey);
}

export async function sendActionRequest(request, socketPath = DEFAULT_SOCKET) {
  const frame = Buffer.from(`${JSON.stringify(request)}\n`);
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    const chunks = [];
    let length = 0;
    socket.setTimeout(10_000, () => socket.destroy(new Error("Docker action broker response timed out")));
    socket.once("connect", () => socket.end(frame));
    socket.on("data", (chunk) => {
      length += chunk.length;
      if (length > MAX_RESPONSE_BYTES) return socket.destroy(new Error("Docker action broker response is oversized"));
      chunks.push(chunk);
    });
    socket.once("error", reject);
    socket.once("end", () => {
      try {
        const response = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        resolve(response);
      } catch {
        reject(new Error("Docker action broker response is malformed"));
      }
    });
  });
}

function parseParameters(action, args) {
  if (action !== "backup.job.execute") {
    if (args.length) throw new Error("This fixed action accepts no parameters");
    return {};
  }
  if (args.length !== 2 || args[0] !== "--jobId") throw new Error("execute-backup-job requires --jobId <UUID>");
  return { jobId: String(args[1]).toLowerCase() };
}

export function protectedCapability(file, {
  expectedUid = 0,
  expectedGid = 0,
  parentRoot = "/",
} = {}) {
  const resolved = path.resolve(file);
  assertProtectedParentChain(path.dirname(resolved), { expectedUid, expectedGid, parentRoot });
  let descriptor;
  try {
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.uid !== expectedUid || before.gid !== expectedGid
      || before.size < 32 || before.size > 4096 || (before.mode & 0o077) !== 0 || (before.mode & 0o400) === 0) {
      throw new Error("Docker action capability ownership, links, permissions or size are invalid");
    }
    const first = readDescriptor(descriptor, before.size);
    const second = readDescriptor(descriptor, before.size);
    const after = fs.fstatSync(descriptor);
    if (!["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"]
      .every((field) => before[field] === after[field])
      || first.length !== second.length || !crypto.timingSafeEqual(first, second)) {
      throw new Error("Docker action capability changed while being read");
    }
    return first;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function assertProtectedParentChain(directory, { expectedUid, expectedGid, parentRoot }) {
  let current = path.resolve(directory);
  const stop = path.resolve(parentRoot);
  const prefix = stop === path.parse(stop).root ? stop : `${stop}${path.sep}`;
  if (current !== stop && !current.startsWith(prefix)) {
    throw new Error("Docker action capability parent escaped its trusted root");
  }
  while (true) {
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedUid || stat.gid !== expectedGid
      || (stat.mode & 0o022) !== 0) {
      throw new Error("Docker action capability parent directory is unsafe");
    }
    if (current === stop) break;
    const parent = path.dirname(current);
    if (parent === current) throw new Error("Docker action capability parent did not reach its trusted root");
    current = parent;
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
  if (offset !== size) throw new Error("Docker action capability changed while being read");
  return bytes;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const action = CLI_ACTIONS[command];
  const contract = ACTIONS[action];
  if (!contract) throw new Error(`Unsupported Docker action command: ${command || "(empty)"}`);
  const capabilityKey = protectedCapability(contract.capabilityFile);
  const request = buildClientRequest(command, args, {
    runtimeIntentId: process.env.DOCKER_ACTION_RUNTIME_INTENT_ID,
    activeReceiptSha256: process.env.DOCKER_ACTION_ACTIVE_RECEIPT_SHA256,
    combinedRenderSha256: process.env.DOCKER_ACTION_COMBINED_RENDER_SHA256,
    capabilityKey,
  });
  const response = await sendActionRequest(request, process.env.DOCKER_ACTION_BROKER_SOCKET || DEFAULT_SOCKET);
  process.stdout.write(`${JSON.stringify(response)}\n`);
  if (response.statusCode !== 200 || response.status !== "completed") process.exitCode = 77;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message ?? error}\n`);
    process.exitCode = 1;
  });
}
