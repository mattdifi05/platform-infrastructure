#!/usr/bin/env node
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const supportedHostKeyAlgorithms = new Set([
  "ssh-ed25519",
  "sk-ssh-ed25519@openssh.com",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "ssh-rsa",
]);

function invalid(message) {
  throw new Error(message);
}

function exactRemote(value) {
  const clean = String(value ?? "").trim();
  const match = clean.match(/^([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,252})$/);
  if (!match || match[2].includes("..") || match[2].endsWith(".") || match[2].split(".").some((label) => label.startsWith("-") || label.endsWith("-"))) {
    invalid("DEPLOY_REMOTE must be a simple user@hostname value.");
  }
  return { user: match[1], host: match[2].toLowerCase() };
}

function exactPort(value) {
  const clean = String(value ?? "").trim();
  if (!/^[0-9]{1,5}$/.test(clean)) invalid("DEPLOY_SSH_PORT must be a numeric port.");
  const port = Number(clean);
  if (port < 1 || port > 65535) invalid("DEPLOY_SSH_PORT must be between 1 and 65535.");
  return port;
}

function readSshString(bytes, offset) {
  if (offset + 4 > bytes.length) invalid("Pinned SSH host key blob is malformed.");
  const length = bytes.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + length;
  if (end > bytes.length) invalid("Pinned SSH host key blob is malformed.");
  return { value: bytes.subarray(start, end), end };
}

function exactHostKey(value) {
  const clean = String(value ?? "").trim();
  if (!clean || /[\r\n\0]/.test(clean)) invalid("DEPLOY_SSH_HOST_KEY must contain a single pinned key.");
  const fields = clean.split(/[ \t]+/);
  if (fields.length !== 2) invalid("DEPLOY_SSH_HOST_KEY must contain only one algorithm and one base64 key blob.");
  const [algorithm, encoded] = fields;
  if (!supportedHostKeyAlgorithms.has(algorithm)) invalid("Pinned SSH host key algorithm is unsupported.");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) invalid("Pinned SSH host key base64 is invalid.");
  const bytes = Buffer.from(encoded, "base64");
  if (!bytes.length || bytes.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")) {
    invalid("Pinned SSH host key base64 is invalid.");
  }
  const embedded = readSshString(bytes, 0);
  if (embedded.value.toString("utf8") !== algorithm) invalid("Pinned SSH host key algorithm does not match its key blob.");
  if (embedded.end >= bytes.length) invalid("Pinned SSH host key blob has no key material.");
  if (algorithm === "ssh-ed25519") {
    const publicKey = readSshString(bytes, embedded.end);
    if (publicKey.value.length !== 32 || publicKey.end !== bytes.length) invalid("Pinned Ed25519 SSH host key blob is malformed.");
  }
  return { algorithm, encoded };
}

function knownHostName(host, port) {
  return port === 22 ? host : `[${host}]:${port}`;
}

export function renderPinnedKnownHost({ remote, port, hostKey }) {
  const endpoint = exactRemote(remote);
  const sshPort = exactPort(port);
  const key = exactHostKey(hostKey);
  return `${knownHostName(endpoint.host, sshPort)} ${key.algorithm} ${key.encoded}\n`;
}

export function verifyPinnedKnownHostsFile({ remote, port, file }) {
  const endpoint = exactRemote(remote);
  const sshPort = exactPort(port);
  const filePath = String(file ?? "").trim();
  if (!filePath) invalid("Pinned SSH host trust file is required.");
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    invalid("Pinned SSH host trust file is missing.");
  }
  if (!stat.isFile() || stat.isSymbolicLink()) invalid("Pinned SSH host trust must be a regular non-symlink file.");
  const mode = stat.mode & 0o777;
  if (mode !== 0o600 && mode !== 0o400) invalid("Pinned SSH host trust must use mode 0600 or 0400.");
  if (stat.size < 1 || stat.size > 16 * 1024) invalid("Pinned SSH host trust file size is invalid.");
  const content = fs.readFileSync(filePath, "utf8");
  if (/\0|\r/.test(content)) invalid("Pinned SSH host trust file is malformed.");
  const lines = content.endsWith("\n") ? content.slice(0, -1).split("\n") : content.split("\n");
  if (lines.length !== 1 || !lines[0]) invalid("Pinned SSH host trust must contain exactly one endpoint key.");
  const fields = lines[0].split(/[ \t]+/);
  if (fields.length !== 3) invalid("Pinned SSH host trust entry is malformed.");
  const expectedHost = knownHostName(endpoint.host, sshPort);
  if (fields[0].toLowerCase() !== expectedHost.toLowerCase()) invalid("Pinned SSH host trust does not match the requested endpoint.");
  const key = exactHostKey(`${fields[1]} ${fields[2]}`);
  return { host: endpoint.host, port: sshPort, algorithm: key.algorithm };
}

function options(args, allowed) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith("--") || value === undefined || value.startsWith("--")) invalid("Pinned SSH host trust options must be value-bearing.");
    const key = name.slice(2);
    if (!allowed.has(key) || Object.hasOwn(parsed, key)) invalid(`Unknown or duplicate pinned SSH host trust option: ${name}.`);
    parsed[key] = value;
  }
  for (const key of allowed) if (!Object.hasOwn(parsed, key)) invalid(`Pinned SSH host trust is missing --${key}.`);
  return parsed;
}

function main() {
  const command = process.argv[2];
  if (command === "render") {
    const parsed = options(process.argv.slice(3), new Set(["remote", "port"]));
    process.stdout.write(renderPinnedKnownHost({ ...parsed, hostKey: process.env.DEPLOY_SSH_HOST_KEY }));
    return;
  }
  if (command === "verify") {
    const parsed = options(process.argv.slice(3), new Set(["remote", "port", "file"]));
    verifyPinnedKnownHostsFile(parsed);
    process.stdout.write("Pinned SSH host trust verified.\n");
    return;
  }
  invalid("Usage: pinned-ssh-host-key.mjs render --remote USER@HOST --port PORT | verify --remote USER@HOST --port PORT --file FILE");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
