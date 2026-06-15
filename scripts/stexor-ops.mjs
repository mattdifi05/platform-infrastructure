#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const infraRoot = path.resolve(scriptDir, "..");
const sourceRoot = path.resolve(infraRoot, "..", "src");
const defaultNodeImage = "node:26-alpine@sha256:3ad34ca6292aec4a91d8ddeb9229e29d9c2f689efd0dd242860889ac71842eba";
const defaultPlaywrightImage = "mcr.microsoft.com/playwright:v1.60.0-noble";

const command = process.argv[2] ?? "help";
const argv = parseArgs(process.argv.slice(3));

function parseArgs(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i += 1) {
    const value = args[i];
    if (!value.startsWith("--")) {
      out._.push(value);
      continue;
    }
    const eq = value.indexOf("=");
    if (eq !== -1) {
      out[value.slice(2, eq)] = value.slice(eq + 1);
      continue;
    }
    const key = value.slice(2);
    const next = args[i + 1];
    if (!next || next.startsWith("--")) {
      out[key] = true;
    } else {
      out[key] = next;
      i += 1;
    }
  }
  return out;
}

function log(message = "") {
  process.stdout.write(`${message}\n`);
}

function fail(message) {
  throw new Error(message);
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\"'\"'")}'`;
}

function sqlString(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function sqlIdentifier(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

function booleanFlag(value) {
  return value === true || value === "true" || value === "1" || value === "yes";
}

function positiveInteger(value, optionName, minimum = 1) {
  const next = Number(value);
  if (!Number.isInteger(next) || next < minimum) {
    fail(`${optionName} must be an integer >= ${minimum}.`);
  }
  return next;
}

function parseCronTime(value, optionName) {
  const [hour, minute] = String(value).split(":").map(Number);
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    fail(`Use --${optionName} HH:mm.`);
  }
  return { hour, minute };
}

function run(bin, args = [], options = {}) {
  const result = spawnSync(bin, args, {
    cwd: options.cwd ?? infraRoot,
    env: { ...process.env, ...options.env },
    input: options.input,
    encoding: options.encoding ?? "utf8",
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    stdio: options.capture
      ? ["pipe", "pipe", "pipe"]
      : [options.input ? "pipe" : "inherit", "inherit", "inherit"],
  });
  if (result.error) {
    if (options.allowFailure) {
      return {
        status: 1,
        stdout: "",
        stderr: String(result.error.message ?? result.error),
      };
    }
    throw result.error;
  }
  if (result.status !== 0 && !options.allowFailure) {
    const details = [result.stderr, result.stdout].filter(Boolean).join("\n").trim();
    fail(`${bin} ${args.join(" ")} failed${details ? `:\n${details}` : ""}`);
  }
  return result;
}

function output(bin, args = [], options = {}) {
  const result = run(bin, args, { ...options, capture: true });
  return String(result.stdout ?? "").trim();
}

function runSecretManager(args, options = {}) {
  return run(process.execPath, [path.join(scriptDir, "stexor-secret-manager.mjs"), ...args], options);
}

function dockerExec(container, args, options = {}) {
  const dockerArgs = ["exec"];
  if (options.input !== undefined) {
    dockerArgs.push("-i");
  }
  dockerArgs.push(container, ...args);
  return run("docker", dockerArgs, options);
}

function dockerExecOutput(container, args, options = {}) {
  const dockerArgs = ["exec"];
  if (options.input !== undefined) {
    dockerArgs.push("-i");
  }
  dockerArgs.push(container, ...args);
  return output("docker", dockerArgs, options);
}

function postgres(container, database, user, sql, options = {}) {
  return dockerExec(container, [
    "psql",
    "-U",
    user,
    "-d",
    database,
    "-v",
    "ON_ERROR_STOP=1",
    "-c",
    sql,
  ], options);
}

function postgresOut(container, database, user, sql, options = {}) {
  return dockerExecOutput(container, [
    "psql",
    "-U",
    user,
    "-d",
    database,
    "-v",
    "ON_ERROR_STOP=1",
    "-qAt",
    "-c",
    sql,
  ], options);
}

function recordBackupRestoreRun({ container, database, user, operation, status, artifactPath = null, artifactSha256 = null, startedAt, metadata = {} }) {
  const finishedAt = new Date();
  const started = startedAt instanceof Date ? startedAt : finishedAt;
  const durationMs = Math.max(0, finishedAt.getTime() - started.getTime());
  const pathValue = artifactPath ? sqlString(artifactPath) : "null";
  const shaValue = artifactSha256 ? sqlString(artifactSha256) : "null";
  const metadataValue = sqlString(JSON.stringify(metadata));
  postgres(container, database, user, `
    create extension if not exists pgcrypto;
    create schema if not exists stexor_platform;
    create table if not exists stexor_platform.backup_restore_runs (
      id uuid primary key default gen_random_uuid(),
      operation text not null check (operation in ('backup', 'restore', 'restore_test')),
      status text not null check (status in ('started', 'success', 'failed')),
      database_name text not null,
      artifact_path text,
      artifact_sha256 text check (artifact_sha256 is null or artifact_sha256 ~ '^[a-f0-9]{64}$'),
      started_at timestamptz not null default now(),
      finished_at timestamptz,
      duration_ms integer check (duration_ms is null or duration_ms >= 0),
      metadata jsonb not null default '{}'::jsonb,
      check ((status = 'started' and finished_at is null) or (status <> 'started' and finished_at is not null)),
      check (finished_at is null or finished_at >= started_at)
    );
    insert into stexor_platform.backup_restore_runs (
      operation,
      status,
      database_name,
      artifact_path,
      artifact_sha256,
      started_at,
      finished_at,
      duration_ms,
      metadata
    )
    values (
      ${sqlString(operation)},
      ${sqlString(status)},
      ${sqlString(database)},
      ${pathValue},
      ${shaValue},
      ${sqlString(started.toISOString())}::timestamptz,
      ${sqlString(finishedAt.toISOString())}::timestamptz,
      ${durationMs},
      ${metadataValue}::jsonb
    );
  `);
}

function readText(filePath) {
  if (!fs.existsSync(filePath)) {
    fail(`Missing required file: ${filePath}`);
  }
  return fs.readFileSync(filePath, "utf8");
}

function readSourceTreeText(directory, extensions = new Set([".ts", ".tsx", ".mjs", ".css"])) {
  let text = "";
  const walk = (currentDirectory) => {
    for (const entry of fs.readdirSync(currentDirectory, { withFileTypes: true })) {
      if (["node_modules", ".next", "dist", "coverage", "vendor"].includes(entry.name)) continue;
      const fullPath = path.join(currentDirectory, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && extensions.has(path.extname(entry.name))) {
        text += `\n/* ${path.relative(directory, fullPath)} */\n${fs.readFileSync(fullPath, "utf8")}`;
      }
    }
  };
  walk(directory);
  return text;
}

function assertMatch(text, pattern, message) {
  if (!pattern.test(text)) {
    fail(message);
  }
}

function assertNoMatch(text, pattern, message) {
  if (pattern.test(text)) {
    fail(message);
  }
}

function parseEnv(filePath) {
  const env = {};
  if (!fs.existsSync(filePath)) {
    return env;
  }
  for (const rawLine of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) {
      continue;
    }
    const index = line.indexOf("=");
    const key = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim().replace(/^["']|["']$/g, "");
    env[key] = value;
  }
  return env;
}

function randomSecret(bytes = 36) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function isUsableSecret(value) {
  return Boolean(value && !/change_me|your-domain|placeholder|managed_by_local_secret_file/i.test(value));
}

function hasManagedSecret(env, key) {
  return Boolean(env[`${key}_FILE`] || env[`${key}_SECRET_REF`]);
}

function requireManagedOrRawSecret(env, key, options = {}) {
  const raw = env[key];
  if (isUsableSecret(raw)) {
    const minLength = options.minLength ?? 0;
    if (minLength > 0 && raw.length < minLength) {
      fail(`${key} must be at least ${minLength} characters.`);
    }
    return;
  }
  const fileRef = env[`${key}_FILE`];
  const managerRef = env[`${key}_SECRET_REF`];
  if (fileRef && /^\/run\/secrets\/[A-Za-z0-9_.-]+$/.test(fileRef)) {
    return;
  }
  if (managerRef && env.SECRET_MANAGER_PROVIDER) {
    return;
  }
  fail(`${key} must be provided as a strong raw value, ${key}_FILE=/run/secrets/<name>, or ${key}_SECRET_REF with SECRET_MANAGER_PROVIDER.`);
}

function latestFileByMtime(directory, predicate) {
  if (!fs.existsSync(directory)) return null;
  const files = fs.readdirSync(directory)
    .map((file) => path.join(directory, file))
    .filter((file) => fs.statSync(file).isFile() && predicate(file))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  return files[0] ?? null;
}

function resolveInside(root, target) {
  const resolvedRoot = fs.realpathSync(root);
  const resolvedTarget = fs.realpathSync(target);
  const relative = path.relative(resolvedRoot, resolvedTarget);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`Path must be inside ${resolvedRoot}: ${resolvedTarget}`);
  }
  return resolvedTarget;
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function secretId(prefix) {
  return `${prefix}${new Date().toISOString().replace(/\D/g, "").slice(0, 14)}`;
}

function readSecretFileIfExists(filePath) {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const value = fs.readFileSync(filePath, "utf8").trim();
  return value || null;
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function hmacHex(secret, value) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function parseVersionedSecretKeys(value) {
  return String(value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const separator = entry.indexOf("=");
      if (separator <= 0) return null;
      const id = entry.slice(0, separator).trim();
      const secret = entry.slice(separator + 1).trim();
      return id && secret ? { id, secret } : null;
    })
    .filter(Boolean);
}

function timingSafeEqualBuffer(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function backupSigningKeys() {
  const filePath = path.resolve(argv.backupSigningKeysFile ?? process.env.BACKUP_SIGNING_KEYS_FILE ?? path.join(infraRoot, "secrets", "backup_signing_keys.txt"));
  const value = argv.backupSigningKeys
    ?? process.env.BACKUP_SIGNING_KEYS
    ?? readSecretFileIfExists(filePath);
  const keys = parseVersionedSecretKeys(value);
  if (!keys.length) {
    fail(`Backup signing keys are required. Run local-secret-manager or set BACKUP_SIGNING_KEYS_FILE. Expected local file: ${filePath}`);
  }
  if (keys.some((key) => key.secret.length < 48)) {
    fail("Every backup signing key must be at least 48 characters.");
  }
  return keys;
}

function backupSignatureSidecarPath(filePath) {
  return `${filePath}.sig.json`;
}

function backupSignatureMessage(fileName, hash) {
  return `stexor-postgres-backup-v1\n${fileName}\n${hash}\n`;
}

function signBackupArtifact(filePath, hash = sha256File(filePath)) {
  const fileName = path.basename(filePath);
  const activeKey = backupSigningKeys()[0];
  const signature = crypto.createHmac("sha256", activeKey.secret).update(backupSignatureMessage(fileName, hash)).digest("base64url");
  const sidecar = {
    version: 1,
    algorithm: "HMAC-SHA256",
    keyId: activeKey.id,
    artifact: fileName,
    sha256: hash,
    signature,
    signedAt: new Date().toISOString(),
  };
  fs.writeFileSync(backupSignatureSidecarPath(filePath), `${JSON.stringify(sidecar, null, 2)}\n`, "utf8");
  return { hash, keyId: activeKey.id, signaturePath: backupSignatureSidecarPath(filePath) };
}

function verifyBackupArtifact(filePath) {
  const fileName = path.basename(filePath);
  const hash = sha256File(filePath);
  const shaPath = `${filePath}.sha256`;
  if (!fs.existsSync(shaPath)) {
    fail(`Missing backup checksum sidecar: ${shaPath}`);
  }
  const recordedHash = fs.readFileSync(shaPath, "utf8").trim().split(/\s+/, 1)[0];
  if (recordedHash !== hash) {
    fail(`Backup checksum mismatch for ${filePath}.`);
  }
  const signaturePath = backupSignatureSidecarPath(filePath);
  if (!fs.existsSync(signaturePath)) {
    fail(`Missing backup signature sidecar: ${signaturePath}`);
  }
  const sidecar = JSON.parse(fs.readFileSync(signaturePath, "utf8"));
  if (sidecar.version !== 1 || sidecar.algorithm !== "HMAC-SHA256" || sidecar.artifact !== fileName || sidecar.sha256 !== hash) {
    fail(`Invalid backup signature metadata for ${filePath}.`);
  }
  const keys = backupSigningKeys();
  const orderedKeys = [
    ...keys.filter((key) => key.id === sidecar.keyId),
    ...keys.filter((key) => key.id !== sidecar.keyId),
  ];
  const valid = orderedKeys.some((key) => {
    const expected = crypto.createHmac("sha256", key.secret).update(backupSignatureMessage(fileName, hash)).digest("base64url");
    return timingSafeEqualBuffer(Buffer.from(sidecar.signature), Buffer.from(expected));
  });
  if (!valid) {
    fail(`Backup signature verification failed for ${filePath}.`);
  }
  return { hash, keyId: sidecar.keyId, signaturePath };
}

function listDumpFilesRecursive(root) {
  if (!fs.existsSync(root)) {
    return [];
  }
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".dump")) {
        files.push(fullPath);
      }
    }
  };
  walk(root);
  return files.sort();
}

async function signExistingPostgresBackups() {
  const backupRoot = path.resolve(argv.backupRoot ?? path.join(infraRoot, "backups", "postgres"));
  resolveInside(path.join(infraRoot, "backups"), backupRoot);
  const dumps = listDumpFilesRecursive(backupRoot);
  let signed = 0;
  let verified = 0;
  for (const dump of dumps) {
    const hash = sha256File(dump);
    const shaPath = `${dump}.sha256`;
    if (!fs.existsSync(shaPath) || fs.readFileSync(shaPath, "utf8").trim().split(/\s+/, 1)[0] !== hash) {
      fs.writeFileSync(shaPath, `${hash}  ${path.basename(dump)}\n`, "ascii");
    }
    if (fs.existsSync(backupSignatureSidecarPath(dump)) && !booleanFlag(argv.force)) {
      verifyBackupArtifact(dump);
      verified += 1;
      continue;
    }
    signBackupArtifact(dump, hash);
    signed += 1;
  }
  log(`Backup signatures ready: signed=${signed} verified=${verified} total=${dumps.length}.`);
}

function backendSessionSigningKey() {
  const raw = dockerExecOutput("enterprise-backend", [
    "sh",
    "-c",
    [
      'if [ -s /run/secrets/session_signing_keys ]; then cat /run/secrets/session_signing_keys;',
      'elif [ -n "$SESSION_SIGNING_KEYS" ]; then printf "%s" "$SESSION_SIGNING_KEYS";',
      'elif [ -s /run/secrets/session_secret ]; then printf "current=%s" "$(cat /run/secrets/session_secret)";',
      'else printf "current=%s" "$SESSION_SECRET"; fi',
    ].join(" "),
  ]).trim();
  const keys = parseVersionedSecretKeys(raw);
  const activeKey = keys[0];
  if (!activeKey) {
    fail("Cannot read backend session signing key for integration signing.");
  }
  return activeKey;
}

function backendSecretHash(value) {
  const keys = parseVersionedSecretKeys(dockerExecOutput("enterprise-backend", [
    "sh",
    "-c",
    'if [ -s /run/secrets/hash_pepper_keys ]; then cat /run/secrets/hash_pepper_keys; else printf "%s" "$SECRET_HASH_KEYS"; fi',
  ]).trim());
  const activeKey = keys[0];
  if (activeKey) {
    return `${activeKey.id}:${hmacHex(activeKey.secret, value)}`;
  }
  const sessionSecret = dockerExecOutput("enterprise-backend", [
    "sh",
    "-c",
    'if [ -s /run/secrets/session_secret ]; then cat /run/secrets/session_secret; else printf "%s" "$SESSION_SECRET"; fi',
  ]).trim();
  return hmacHex(sessionSecret, value);
}

function newSignedCookie(signingKey, accountId, sessionId) {
  const now = Math.floor(Date.now() / 1000);
  const fingerprint = hmacHex(signingKey.secret, "session-fingerprint:unknown").slice(0, 32);
  const payload = JSON.stringify({
    accountId,
    sessionId,
    fp: fingerprint,
    iat: now,
    exp: now + 315360000,
    kid: signingKey.id,
  });
  const encoded = base64url(payload);
  const signature = crypto.createHmac("sha256", signingKey.secret).update(encoded).digest("base64url");
  return `stexor_session=${encoded}.${signature}`;
}

function redisCommand(args, options = {}) {
  const script = [
    'if [ -s /run/secrets/redis_password ]; then REDISCLI_AUTH=$(cat /run/secrets/redis_password); export REDISCLI_AUTH;',
    'elif [ -n "$REDIS_PASSWORD" ]; then REDISCLI_AUTH="$REDIS_PASSWORD"; export REDISCLI_AUTH; fi;',
    'redis-cli "$@"',
  ].join(" ");
  return dockerExec("enterprise-redis", ["sh", "-c", script, "sh", ...args], options);
}

function redisSetValue(key, value, ttlMs) {
  const script = [
    'if [ -s /run/secrets/redis_password ]; then REDISCLI_AUTH=$(cat /run/secrets/redis_password); export REDISCLI_AUTH;',
    'elif [ -n "$REDIS_PASSWORD" ]; then REDISCLI_AUTH="$REDIS_PASSWORD"; export REDISCLI_AUTH; fi;',
    'redis-cli -x set "$1" >/dev/null && redis-cli pexpire "$1" "$2" >/dev/null',
  ].join(" ");
  dockerExec("enterprise-redis", ["sh", "-c", script, "sh", key, String(ttlMs)], { input: value });
}

function redisSetPlainValue(key, value, ttlMs) {
  redisCommand(["set", key, value, "px", String(ttlMs)]);
}

function redisDelete(keys) {
  if (!keys.length) {
    return;
  }
  redisCommand(["del", ...keys], { allowFailure: true, capture: true });
}

const localTlsHostnames = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "ui.localhost.com",
  "account.localhost.com",
  "api.localhost.com",
  "auth.localhost.com",
  "minio.localhost.com",
  "grafana.localhost.com",
]);

function request(method, urlString, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const isHttps = url.protocol === "https:";
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const client = isHttps ? https : http;
    const req = client.request({
      method,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      headers: {
        ...headers,
        ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}),
      },
      rejectUnauthorized: !localTlsHostnames.has(url.hostname),
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        if (text.trim()) {
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
        }
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          text,
          json,
        });
      });
    });
    req.on("error", reject);
    if (data) {
      req.write(data);
    }
    req.end();
  });
}

function headerText(headers) {
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`)
    .join("\n")
    .toLowerCase();
}

function cookieFromHeaders(headers, name) {
  const values = headers["set-cookie"];
  const list = Array.isArray(values) ? values : values ? [values] : [];
  for (const cookie of list) {
    const match = cookie.match(new RegExp(`^${name}=([^;]+)`));
    if (match) {
      return `${name}=${match[1]}`;
    }
  }
  return null;
}

function assertStatus(response, expected, name) {
  if (response.status !== expected) {
    fail(`${name} expected HTTP ${expected}, got ${response.status}: ${response.text}`);
  }
}

function pnpmInWeb(commandLine, options = {}) {
  const bootstrap = `cd /workspace && export HOME=/tmp XDG_DATA_HOME=/tmp/xdg PNPM_HOME=/tmp/pnpm-home npm_config_cache=/tmp/npm-cache && if [ ! -f /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ]; then npm install --prefix /tmp/pnpm-run --no-save pnpm@11.6.0 >/dev/null; fi && node /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ${commandLine}`;
  return dockerExec("enterprise-web", ["sh", "-lc", bootstrap], options);
}

function pnpmInWebOutput(commandLine) {
  const bootstrap = `cd /workspace && export HOME=/tmp XDG_DATA_HOME=/tmp/xdg PNPM_HOME=/tmp/pnpm-home npm_config_cache=/tmp/npm-cache && if [ ! -f /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ]; then npm install --prefix /tmp/pnpm-run --no-save pnpm@11.6.0 >/dev/null; fi && node /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ${commandLine}`;
  return dockerExecOutput("enterprise-web", ["sh", "-lc", bootstrap]);
}

function configuredNodeImage() {
  return process.env.NODE_IMAGE || parseEnv(path.join(infraRoot, ".env")).NODE_IMAGE || defaultNodeImage;
}

function configuredPlaywrightImage() {
  return process.env.PLAYWRIGHT_IMAGE || parseEnv(path.join(infraRoot, ".env")).PLAYWRIGHT_IMAGE || defaultPlaywrightImage;
}

function runSourceWorkspaceInDocker(script, options = {}) {
  run("docker", [
    "run",
    "--rm",
    "-e",
    "CI=true",
    "-e",
    "NEXT_TELEMETRY_DISABLED=1",
    "-v",
    `${sourceRoot}:/source:ro`,
    "-v",
    `${infraRoot}:/enterprise-infrastructure:ro`,
    configuredNodeImage(),
    "sh",
    "-lc",
    script,
  ], options);
}

function sourceWorkspaceOutput(commands, options = {}) {
  return output("docker", [
    "run",
    "--rm",
    "-e",
    "CI=true",
    "-e",
    "NEXT_TELEMETRY_DISABLED=1",
    "-v",
    `${sourceRoot}:/source:ro`,
    "-v",
    `${infraRoot}:/enterprise-infrastructure:ro`,
    configuredNodeImage(),
    "sh",
    "-lc",
    sourceWorkspaceBootstrap(commands),
  ], options);
}

function sourceWorkspaceBootstrap(commands) {
  const excludes = [
    "./.artifacts",
    "./.codex-*.log",
    "./.docker-build-cache",
    "./.git",
    "./.next",
    "./*/.next",
    "./.pnpm-store",
    "./coverage",
    "./dist",
    "./*/dist",
    "./node_modules",
    "./*/node_modules",
    "./playwright-report",
    "./test-results",
  ].map((pattern) => `--exclude='${pattern}'`).join(" ");
  return [
    "set -eu",
    "mkdir -p /workspace",
    "cd /source",
    `tar ${excludes} -cf - . | tar -xf - -C /workspace`,
    "cd /workspace",
    "npm install -g pnpm@11.6.0 >/dev/null",
    commands,
  ].join(" && ");
}

async function accessReview() {
  const database = argv.database ?? "stexor_app";
  log("==> Active account roles");
  postgres("enterprise-postgres", database, "postgres", `
select
  account.email::text,
  role.role,
  role.granted_at,
  role.revoked_at
from stexor_account.account_roles role
join stexor_account.accounts account on account.id = role.account_id
where account.deleted_at is null
order by account.email, role.role;
`);
  log("==> Active sessions older than 30 days");
  postgres("enterprise-postgres", database, "postgres", `
select
  account.email::text,
  session.device,
  session.browser,
  session.last_seen_at,
  session.auth_method
from stexor_account.sessions session
join stexor_account.accounts account on account.id = session.account_id
where session.status = 'active'
  and session.last_seen_at < now() - interval '30 days'
order by session.last_seen_at asc;
`);
  log("Access review completed.");
}

async function applyPostgresMigrations() {
  const container = argv.container ?? "enterprise-postgres";
  const database = argv.database ?? "stexor_app";
  const user = argv.user ?? "postgres";
  const migrationDir = path.join(infraRoot, "postgres", "migrations");
  const files = fs.readdirSync(migrationDir)
    .filter((file) => file.endsWith(".sql"))
    .sort()
    .map((file) => path.join(migrationDir, file));

  if (!files.length) {
    log(`No migrations found in ${migrationDir}`);
    return;
  }

  postgres(container, database, user, "create schema if not exists stexor_platform; create table if not exists stexor_platform.schema_migrations (version text primary key, applied_at timestamptz not null default now(), checksum text not null default '');");

  for (const file of files) {
    const version = path.basename(file, ".sql");
    const checksum = sha256File(file);
    const existing = postgresOut(container, database, user, `select checksum from stexor_platform.schema_migrations where version = ${sqlString(version)};`);
    if (existing) {
      if (existing.trim() !== checksum) {
        fail(`Migration ${version} was already applied with a different checksum.`);
      }
      log(`Skipping ${version} (already applied)`);
      continue;
    }
    log(`Applying ${version}`);
    run("docker", ["cp", file, `${container}:/tmp/stexor-migration.sql`]);
    dockerExec(container, ["psql", "-U", user, "-d", database, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/stexor-migration.sql"]);
    postgres(container, database, user, `insert into stexor_platform.schema_migrations (version, checksum) values (${sqlString(version)}, ${sqlString(checksum)});`);
    dockerExec(container, ["rm", "-f", "/tmp/stexor-migration.sql"]);
  }

  log("PostgreSQL migrations complete.");
}

async function backupPostgres(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? "stexor_app";
  const user = options.user ?? argv.user ?? "postgres";
  const outputDir = path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "postgres"));
  const startedAt = new Date();
  fs.mkdirSync(outputDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const fileName = `${database}-${timestamp}.dump`;
  const containerPath = `/tmp/${fileName}`;
  const hostPath = path.join(outputDir, fileName);

  try {
    log(`Creating PostgreSQL backup for database '${database}'...`);
    dockerExec(container, ["pg_dump", "-U", user, "-d", database, "--format=custom", "--no-owner", "--no-acl", `--file=${containerPath}`]);
    run("docker", ["cp", `${container}:${containerPath}`, hostPath]);
    dockerExec(container, ["rm", "-f", containerPath]);

    const hash = sha256File(hostPath);
    fs.writeFileSync(`${hostPath}.sha256`, `${hash}  ${fileName}\n`, "ascii");
    const signature = signBackupArtifact(hostPath, hash);
    recordBackupRestoreRun({ container, database, user, operation: "backup", status: "success", artifactPath: hostPath, artifactSha256: hash, startedAt });
    log(`Backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, container, database, user };
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-f", containerPath], { allowFailure: true });
      recordBackupRestoreRun({ container, database, user, operation: "backup", status: "failed", artifactPath: hostPath, startedAt, metadata: { error: String(error?.message ?? error) } });
    } catch {
      // Preserve the original backup failure.
    }
    throw error;
  }
}

async function certificateExpiryCheck() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const defaultHosts = [
    env.UI_HOST ?? "ui.localhost.com",
    env.ACCOUNT_HOST ?? "account.localhost.com",
    env.API_HOST ?? "api.localhost.com",
  ].join(",");
  const hosts = (argv.hosts ?? defaultHosts).split(",").map((host) => host.trim()).filter(Boolean);
  const warnDays = Number(argv.warnDays ?? 30);
  for (const host of hosts) {
    await new Promise((resolve, reject) => {
      const socket = tls.connect({
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
      }, () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        const daysLeft = Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86400000);
        log(`${host} certificate expires in ${daysLeft} days (${new Date(cert.valid_to).toISOString()})`);
        if (daysLeft < warnDays) {
          reject(new Error(`${host} certificate expires in less than ${warnDays} days`));
        } else {
          resolve();
        }
      });
      socket.on("error", reject);
    });
  }
  log("Certificate expiry check passed.");
}

async function enterpriseCheck() {
  log("==> Workspace typecheck/build in disposable Linux container");
  runSourceWorkspaceInDocker(sourceWorkspaceBootstrap([
    "node scripts/dependency-hygiene.mjs",
    "node scripts/testing-hygiene.mjs",
    "node scripts/maintainability-hygiene.mjs",
    "node scripts/performance-hygiene.mjs",
    "pnpm install --frozen-lockfile",
    "pnpm deps:supply-chain -- --sbom-output /workspace/security/sbom/pnpm-sbom-current.cdx.json",
    "pnpm -r typecheck",
    "pnpm typecheck:e2e",
    "pnpm peers check",
    "pnpm -r --if-present test",
    "pnpm --filter ./apps/web build",
    "node scripts/performance-hygiene.mjs --built",
  ].join(" && ")));
  run("docker", ["compose", "--env-file", path.join(infraRoot, ".env"), "-p", "enterprise_local", "-f", path.join(infraRoot, "compose.yaml"), "config", "--quiet"]);
  await enterpriseHardeningAudit();
  log("Enterprise local quality gate passed.");
}

async function enterpriseHardeningAudit() {
  const projectName = argv.projectName ?? "enterprise_local";
  await staticSecurityCheck();
  await dependencyHygiene();
  await supplyChainHygiene();
  await testingHygiene();
  await faultInjectionTests();
  await maintainabilityHygiene();
  await performanceHygiene();
  log("==> Compose local config");
  run("docker", ["compose", "--env-file", ".env", "-p", projectName, "config", "--quiet"]);
  log("==> Compose build config");
  run("docker", ["compose", "--env-file", ".env", "-p", projectName, "-f", "compose.yaml", "-f", "compose.build.yaml", "config", "--quiet"]);
  if (fs.existsSync(path.join(infraRoot, "compose.secrets.yaml"))) {
    await validateLocalSecrets();
    log("==> Compose local secrets config");
    run("docker", ["compose", "--env-file", ".env", "-p", projectName, "-f", "compose.yaml", "-f", "compose.secrets.yaml", "config", "--quiet"]);
  }
  log("==> Compose prod config");
  run("docker", ["compose", "--env-file", ".env", "-p", "enterprise_prod", "-f", "compose.yaml", "-f", "compose.prod.yaml", "config", "--quiet"]);
  await applyPostgresMigrations();
  await backupRestoreDrill();
  await prunePostgresBackups({ dryRun: true });
  await securitySmoke();
  await accountIntegrationTests();
  await browserE2eTests();
  await certificateExpiryCheck();
  await loadSmoke();
  await secretScan();
  await runtimeHealthChecks();
  log("Enterprise hardening audit passed.");
}

async function browserE2eTests() {
  log("==> Browser E2E tests");
  const env = parseEnv(path.join(infraRoot, ".env"));
  const playwrightBaseUrl = env.NEXT_PUBLIC_UI_URL ?? env.UI_PUBLIC_URL ?? "https://ui.localhost.com";
  const bootstrap = [
    "set -eu",
    "if ! command -v docker >/dev/null; then apt-get update >/dev/null && apt-get install -y docker.io >/dev/null; fi",
    sourceWorkspaceBootstrap([
      "pnpm install --frozen-lockfile",
      "pnpm typecheck:e2e",
      "pnpm test:e2e",
    ].join(" && ")),
  ].join(" && ");
  run("docker", [
    "run",
    "--rm",
    "--network",
    "container:enterprise-traefik",
    "-e",
    "CI=true",
    "-e",
    "NEXT_TELEMETRY_DISABLED=1",
    "-e",
    `PLAYWRIGHT_BASE_URL=${playwrightBaseUrl}`,
    "-e",
    "PLAYWRIGHT_HTML_OPEN=never",
    "-e",
    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1",
    "-v",
    "/var/run/docker.sock:/var/run/docker.sock",
    "-v",
    `${sourceRoot}:/source:ro`,
    configuredPlaywrightImage(),
    "bash",
    "-lc",
    bootstrap,
  ]);
  log("Browser E2E tests passed.");
}

async function runtimeHealthChecks() {
  const runtimeContainers = [
    "enterprise-traefik",
    "enterprise-postgres",
    "enterprise-redis",
    "enterprise-keycloak",
    "enterprise-nats",
    "enterprise-minio",
    "enterprise-backend",
    "enterprise-web",
    "enterprise-worker-notifications",
    "enterprise-worker-jobs",
    "enterprise-prometheus",
    "enterprise-alertmanager",
    "enterprise-grafana",
    "enterprise-loki",
    "enterprise-promtail",
  ];
  log("==> Container health");
  for (const container of runtimeContainers) {
    const status = output("docker", ["inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", container]);
    if (!/^running( healthy)?$/.test(status.trim())) {
      fail(`${container} is not healthy: ${status}`);
    }
  }

  log("==> Container runtime guardrails");
  for (const container of runtimeContainers) {
    const [inspect] = JSON.parse(output("docker", ["inspect", container]));
    const hostConfig = inspect?.HostConfig ?? {};
    const securityOpt = hostConfig.SecurityOpt ?? [];
    const logConfig = hostConfig.LogConfig ?? {};
    const logOptions = logConfig.Config ?? {};
    if (hostConfig.Init !== true) {
      fail(`${container} must run with init: true.`);
    }
    if (!Number.isInteger(hostConfig.PidsLimit) || hostConfig.PidsLimit <= 0) {
      fail(`${container} must set a positive pids_limit.`);
    }
    if (!securityOpt.includes("no-new-privileges:true")) {
      fail(`${container} must set no-new-privileges.`);
    }
    if (logConfig.Type !== "json-file" || logOptions["max-size"] !== "10m" || logOptions["max-file"] !== "5") {
      fail(`${container} must use bounded json-file logging.`);
    }
    if ((inspect?.Mounts ?? []).some((mount) => mount.Destination === "/var/run/docker.sock" || mount.Source === "/var/run/docker.sock")) {
      fail(`${container} must not mount docker.sock.`);
    }
  }

  log("==> Redis runtime integration");
  const redisPing = dockerExecOutput("enterprise-redis", ["sh", "-c", 'if [ -s /run/secrets/redis_password ]; then REDISCLI_AUTH=$(cat /run/secrets/redis_password); export REDISCLI_AUTH; elif [ -n "$REDIS_PASSWORD" ]; then REDISCLI_AUTH="$REDIS_PASSWORD"; export REDISCLI_AUTH; fi; redis-cli ping']);
  if (!/PONG/.test(redisPing)) {
    fail("Redis ping failed");
  }
  const metrics = dockerExecOutput("enterprise-backend", ["wget", "-q", "-O", "-", "http://127.0.0.1:3000/metrics"]);
  if (!/redis_connection_up\{service="enterprise-backend"\} 1/.test(metrics)) {
    fail("Backend Redis metric is not up");
  }
  const alertmanagerStatus = dockerExecOutput("enterprise-alertmanager", ["wget", "-q", "-O", "-", "http://127.0.0.1:9093/-/healthy"]);
  if (!/OK/.test(alertmanagerStatus)) {
    fail("Alertmanager health endpoint is not OK.");
  }
  for (const worker of ["enterprise-worker-notifications", "enterprise-worker-jobs"]) {
    const health = dockerExecOutput(worker, ["wget", "-q", "-O", "-", "http://127.0.0.1:3000/health"]);
    if (!/"redis":"ok"/.test(health)) {
      fail(`${worker} Redis health is not ok`);
    }
  }

  log("==> Session policy coherence");
  const backendSessionTtl = dockerExecOutput("enterprise-backend", ["sh", "-c", 'printf "%s" "$SESSION_COOKIE_MAX_AGE_SECONDS"']).trim();
  if (backendSessionTtl !== "315360000") {
    fail("Backend remember-me TTL must be 315360000 seconds.");
  }
  const policySessionTtl = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select value->>'rememberMeSeconds' from stexor_account.security_policies where key = 'account_session';").trim();
  if (policySessionTtl !== "315360000") {
    fail("Database account_session policy rememberMeSeconds must be 315360000.");
  }

  log("==> App DB least privilege");
  for (const role of ["stexor_app_account_rw", "stexor_app_auth_rw", "stexor_app_audit_rw"]) {
    const roleMembership = postgresOut("enterprise-postgres", "stexor_app", "postgres", `select pg_has_role('stexor_app_user', ${sqlString(role)}, 'member');`).trim();
    if (roleMembership !== "t") {
      fail(`stexor_app_user must inherit ${role}.`);
    }
  }
  const directDelete = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_user', 'stexor_account.accounts', 'delete');").trim();
  if (directDelete !== "f") {
    fail("stexor_app_user must not have DELETE on stexor_account.accounts.");
  }
  postgresOut("enterprise-postgres", "stexor_app", "postgres", "set role stexor_app_user; select count(*) from stexor_account.accounts;");

  log("==> Row-level security");
  const rlsGapCount = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'stexor_account' and c.relkind in ('r','p') and (not c.relrowsecurity or not c.relforcerowsecurity);").trim();
  if (rlsGapCount !== "0") {
    fail("All stexor_account tables must have forced row-level security.");
  }
  const rlsPolicy = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select value->>'enabled' from stexor_account.security_policies where key = 'row_level_security';").trim();
  if (rlsPolicy !== "true") {
    fail("row_level_security policy must be recorded and enabled.");
  }

  log("==> Persistence integrity readiness");
  const migration006 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '006_persistence_integrity_readiness';").trim();
  if (migration006 !== "1") {
    fail("Persistence integrity migration 006 must be applied.");
  }
  const migration007 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '007_durable_audit_outbox';").trim();
  if (migration007 !== "1") {
    fail("Durable audit outbox migration 007 must be applied.");
  }
  const migration008 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '008_audit_account_unlink';").trim();
  if (migration008 !== "1") {
    fail("Audit account unlink migration 008 must be applied.");
  }
  const migration009 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '009_audit_outbox_dispatcher';").trim();
  if (migration009 !== "1") {
    fail("Audit outbox dispatcher migration 009 must be applied.");
  }
  const migration010 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '010_platform_runtime_least_privilege';").trim();
  if (migration010 !== "1") {
    fail("Platform runtime least-privilege migration 010 must be applied.");
  }
  const migration011 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '011_platform_runtime_role_revoke';").trim();
  if (migration011 !== "1") {
    fail("Platform runtime inherited role revoke migration 011 must be applied.");
  }
  const runtimePlatformMutation = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_user', 'stexor_platform.schema_migrations', 'insert,update,delete') or has_table_privilege('stexor_app_user', 'stexor_platform.data_retention_policies', 'insert,update,delete') or has_table_privilege('stexor_app_user', 'stexor_platform.backup_restore_runs', 'insert,update,delete');").trim();
  if (runtimePlatformMutation !== "f") {
    fail("stexor_app_user must not mutate platform migration, retention or backup/restore evidence tables.");
  }
  const retentionPolicies = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.data_retention_policies where enabled;").trim();
  if (Number.parseInt(retentionPolicies, 10) < 6) {
    fail("At least six enabled data retention policies must be present.");
  }
  const backupRestoreLog = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_platform.backup_restore_runs') is not null;").trim();
  if (backupRestoreLog !== "t") {
    fail("Backup and restore run log table must exist.");
  }
  const successfulRestoreTests = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.backup_restore_runs where operation = 'restore_test' and status = 'success';").trim();
  if (Number.parseInt(successfulRestoreTests, 10) < 1) {
    fail("At least one successful PostgreSQL restore-test drill must be recorded in stexor_platform.backup_restore_runs.");
  }
  const activeBackupSetIndex = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_account.idx_backup_code_sets_one_active') is not null;").trim();
  if (activeBackupSetIndex !== "t") {
    fail("Active backup-code uniqueness index must exist.");
  }
  const auditMutationDenied = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_events', 'update') or has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_events', 'delete');").trim();
  if (auditMutationDenied !== "f") {
    fail("Audit role must not be able to update or delete audit events.");
  }
  const auditAppendOnlyTrigger = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from pg_trigger where tgname = 'trg_audit_events_append_only' and tgenabled <> 'D';").trim();
  if (auditAppendOnlyTrigger !== "1") {
    fail("Audit append-only trigger must be enabled.");
  }
  const auditOutboxTable = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_account.audit_outbox') is not null;").trim();
  if (auditOutboxTable !== "t") {
    fail("Durable audit outbox table must exist.");
  }
  const auditOutboxPrivileges = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_outbox', 'insert') and has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_outbox', 'update') and not has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_outbox', 'delete');").trim();
  if (auditOutboxPrivileges !== "t") {
    fail("Audit role must enqueue and update audit outbox entries without delete privilege.");
  }
  const auditOutboxRetention = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.data_retention_policies where key = 'audit_outbox' and enabled;").trim();
  if (auditOutboxRetention !== "1") {
    fail("Audit outbox retention policy must be enabled.");
  }
  const auditOutboxDeadStatus = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from pg_constraint where conname = 'audit_outbox_status_known' and pg_get_constraintdef(oid) like '%dead%';").trim();
  if (auditOutboxDeadStatus !== "1") {
    fail("Audit outbox must support terminal dead-letter status.");
  }
  const auditOutboxDueIndex = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_account.idx_audit_outbox_due_dispatch') is not null;").trim();
  if (auditOutboxDueIndex !== "t") {
    fail("Audit outbox must have a due-dispatch index for worker claims.");
  }
  log("==> Dev app container hardening");
  for (const container of ["enterprise-backend", "enterprise-web", "enterprise-worker-notifications", "enterprise-worker-jobs"]) {
    const readonly = output("docker", ["inspect", "--format", "{{.HostConfig.ReadonlyRootfs}}", container]).trim().toLowerCase();
    const capDrop = output("docker", ["inspect", "--format", "{{json .HostConfig.CapDrop}}", container]);
    const securityOpt = output("docker", ["inspect", "--format", "{{json .HostConfig.SecurityOpt}}", container]);
    if (readonly !== "true") {
      fail(`${container} root filesystem must be read-only.`);
    }
    if (!/ALL/.test(capDrop)) {
      fail(`${container} must drop all Linux capabilities.`);
    }
    if (!/no-new-privileges:true/.test(securityOpt)) {
      fail(`${container} must set no-new-privileges.`);
    }
  }
}

async function generateSbom() {
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "security", "sbom"));
  fs.mkdirSync(outputDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const outputFile = path.join(outputDir, `pnpm-sbom-${timestamp}.json`);
  const json = sourceWorkspaceOutput("pnpm install --frozen-lockfile >/dev/null && pnpm list --json --prod --depth 20", { maxBuffer: 128 * 1024 * 1024 });
  fs.writeFileSync(outputFile, `${json}\n`, "utf8");
  log(`SBOM written to ${outputFile}`);
}

async function dependencyHygiene() {
  log("==> Dependency hygiene");
  run(process.execPath, ["scripts/dependency-hygiene.mjs"], { cwd: sourceRoot });
}

async function supplyChainHygiene() {
  log("==> Supply-chain SBOM/CVE/license gate");
  const result = sourceWorkspaceOutput(
    "pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store >/dev/null && pnpm deps:supply-chain -- --sbom-output /workspace/security/sbom/pnpm-sbom-current.cdx.json",
    { maxBuffer: 128 * 1024 * 1024 },
  );
  log(result);
}

async function testingHygiene() {
  log("==> Testing hygiene");
  run(process.execPath, ["scripts/testing-hygiene.mjs"], { cwd: sourceRoot });
}

async function faultInjectionTests() {
  log("==> Fault injection tests");
  const testOutput = sourceWorkspaceOutput([
    "pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store >/dev/null",
    "node --import ./scripts/register-ts-extension-loader.mjs --test apps/backend/src/db-query.test.ts apps/backend/src/runtime/redis-store.test.ts apps/backend/src/runtime/session-auth.test.ts",
  ].join(" && "), { maxBuffer: 128 * 1024 * 1024 });
  log(testOutput);

  const timeoutProbe = postgres("enterprise-postgres", "stexor_app", "postgres", "begin; set local statement_timeout = '1ms'; select pg_sleep(0.05); rollback;", {
    allowFailure: true,
    capture: true,
  });
  const timeoutOutput = `${timeoutProbe.stderr ?? ""}\n${timeoutProbe.stdout ?? ""}`;
  if (timeoutProbe.status === 0 || !/statement timeout|canceling statement/i.test(timeoutOutput)) {
    fail("PostgreSQL fault injection must prove statement_timeout cancels slow statements.");
  }
  log("PostgreSQL timeout fault injection passed.");
}

async function maintainabilityHygiene() {
  log("==> Maintainability hygiene");
  run(process.execPath, ["scripts/maintainability-hygiene.mjs"], { cwd: sourceRoot });
}

async function performanceHygiene() {
  log("==> Performance hygiene");
  run(process.execPath, ["scripts/performance-hygiene.mjs"], { cwd: sourceRoot });
}

async function initLocalSecrets() {
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
  const secretsDir = path.resolve(argv.secretsDir ?? path.join(infraRoot, "secrets"));
  const force = Boolean(argv.force);
  const sanitizeEnv = Boolean(argv.sanitizeEnv);
  fs.mkdirSync(secretsDir, { recursive: true });
  const env = parseEnv(envFile);

  const existingSecret = (name) => {
    if (force) return null;
    const value = readSecretFileIfExists(path.join(secretsDir, `${name}.txt`));
    return isUsableSecret(value) ? value : null;
  };
  const secretValue = (key, name, bytes = 36) => existingSecret(name) ?? (isUsableSecret(env[key]) ? env[key] : randomSecret(bytes));
  const versionedSecretValue = (key, name, fallbackId) => {
    const existing = existingSecret(name);
    if (existing) return existing;
    if (isUsableSecret(env[key])) return env[key];
    return `${fallbackId}=${randomSecret(48)}`;
  };
  const postgresSuper = secretValue("POSTGRES_SUPERUSER_PASSWORD", "postgres_superuser_password");
  const appDbPassword = secretValue("APP_DB_PASSWORD", "app_db_password");
  const keycloakDbPassword = secretValue("KEYCLOAK_DB_PASSWORD", "keycloak_db_password");
  const redisPassword = secretValue("REDIS_PASSWORD", "redis_password");
  const keycloakAdminPassword = secretValue("KEYCLOAK_ADMIN_PASSWORD", "keycloak_admin_password");
  const natsPassword = secretValue("NATS_PASSWORD", "nats_password");
  const minioRootPassword = secretValue("MINIO_ROOT_PASSWORD", "minio_root_password");
  const grafanaAdminPassword = secretValue("GRAFANA_ADMIN_PASSWORD", "grafana_admin_password");
  const sessionSecret = secretValue("SESSION_SECRET", "session_secret", 48);
  const sessionSigningKeys = versionedSecretValue("SESSION_SIGNING_KEYS", "session_signing_keys", secretId("s"));
  const hashPepperKeys = versionedSecretValue("SECRET_HASH_KEYS", "hash_pepper_keys", "local");
  const backupSigningKeys = versionedSecretValue("BACKUP_SIGNING_KEYS", "backup_signing_keys", secretId("b"));
  const smtpPassword = secretValue("SMTP_PASSWORD", "smtp_password");
  const googleOAuthClientSecret = secretValue("GOOGLE_OAUTH_CLIENT_SECRET", "google_oauth_client_secret");
  const appDbUser = env.APP_DB_USER || "stexor_app_user";
  const appDbName = env.APP_DB_NAME || "stexor_app";
  const natsUser = env.NATS_USER || "stexor";
  const databaseUrl = existingSecret("database_url") ?? `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(appDbPassword)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  const natsUrl = existingSecret("nats_url") ?? `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(natsPassword)}@nats:4222`;

  const writeSecretFile = (name, value) => {
    const filePath = path.join(secretsDir, `${name}.txt`);
    if (fs.existsSync(filePath) && !force) {
      return;
    }
    fs.writeFileSync(filePath, value, "utf8");
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {
      // Best effort on platforms without POSIX permissions.
    }
  };

  const secretValues = {
    postgres_superuser_password: postgresSuper,
    app_db_password: appDbPassword,
    keycloak_db_password: keycloakDbPassword,
    redis_password: redisPassword,
    keycloak_admin_password: keycloakAdminPassword,
    nats_password: natsPassword,
    minio_root_password: minioRootPassword,
    grafana_admin_password: grafanaAdminPassword,
    session_secret: sessionSecret,
    session_signing_keys: sessionSigningKeys,
    hash_pepper_keys: hashPepperKeys,
    backup_signing_keys: backupSigningKeys,
    smtp_password: smtpPassword,
    google_oauth_client_secret: googleOAuthClientSecret,
    database_url: databaseUrl,
    nats_url: natsUrl,
  };

  for (const [name, value] of Object.entries(secretValues)) {
    writeSecretFile(name, value);
  }
  runSecretManager(["init", "--secretsDir", secretsDir, "--envFile", envFile]);

  if (sanitizeEnv && fs.existsSync(envFile)) {
    const sensitive = new Set([
      "POSTGRES_SUPERUSER_PASSWORD",
      "APP_DB_PASSWORD",
      "KEYCLOAK_DB_PASSWORD",
      "REDIS_PASSWORD",
      "KEYCLOAK_ADMIN_PASSWORD",
      "NATS_PASSWORD",
      "MINIO_ROOT_PASSWORD",
      "GRAFANA_ADMIN_PASSWORD",
      "SESSION_SECRET",
      "SMTP_PASSWORD",
      "GOOGLE_OAUTH_CLIENT_SECRET",
      "GOOGLE_CLIENT_SECRET",
      "RESTIC_PASSWORD",
    ]);
    const next = fs.readFileSync(envFile, "utf8").split(/\r?\n/).map((line) => {
      const key = line.split("=", 1)[0];
      return sensitive.has(key) ? `${key}=managed_by_local_secret_file` : line;
    }).join("\n");
    fs.writeFileSync(envFile, next, "utf8");
  }

  log(`Local secrets initialized in ${secretsDir}`);
  log("Stexor Secret Manager is the canonical encrypted local secret store.");
  log("Use compose.secrets.yaml when starting the local stack.");
}

async function localSecretManager() {
  await initLocalSecrets();
  await validateLocalSecrets();
  await signExistingPostgresBackups();
  log("Local secret manager is ready: Docker secret files are materialized from the encrypted local store, and PostgreSQL backups are signed.");
}

async function secretManager() {
  const args = [...argv._];
  for (const [key, value] of Object.entries(argv)) {
    if (key === "_") continue;
    args.push(`--${key}`);
    if (value !== true) args.push(String(value));
  }
  runSecretManager(args.length ? args : ["status"]);
}

async function loadSmoke() {
  const requests = positiveInteger(argv.requests ?? 80, "requests");
  const concurrency = positiveInteger(argv.concurrency ?? 8, "concurrency");
  const maxP95Ms = Number(argv.maxP95Ms ?? 750);
  if (!argv.url && !booleanFlag(argv.edge)) {
    runInternalBackendLoadProbe({ label: "Internal backend load smoke", requests, concurrency, maxP95Ms });
    return;
  }
  const url = argv.url ?? "https://api.localhost.com/health";
  await runLoadProbe({ label: "Load smoke", url, requests, concurrency, maxP95Ms });
}

async function loadProfile() {
  const durationSeconds = positiveInteger(argv.durationSeconds ?? 60, "durationSeconds");
  const targetRps = positiveInteger(argv.targetRps ?? 8, "targetRps");
  const concurrency = positiveInteger(argv.concurrency ?? Math.max(4, Math.min(64, targetRps)), "concurrency");
  const requests = positiveInteger(argv.requests ?? durationSeconds * targetRps, "requests");
  const maxP95Ms = Number(argv.maxP95Ms ?? 1000);
  if (!argv.url && !booleanFlag(argv.edge)) {
    runInternalBackendLoadProbe({ label: "Sustained internal backend load profile", requests, concurrency, maxP95Ms });
    return;
  }
  const url = argv.url ?? "https://api.localhost.com/health";
  await runLoadProbe({ label: "Sustained load profile", url, requests, concurrency, maxP95Ms });
}

function runInternalBackendLoadProbe({ label, requests, concurrency, maxP95Ms }) {
  const script = `
const http = require("node:http");
const { performance } = require("node:perf_hooks");
const requests = ${JSON.stringify(requests)};
const concurrency = ${JSON.stringify(concurrency)};
const maxP95Ms = ${JSON.stringify(maxP95Ms)};
const latencies = [];
const errors = [];
let nextRequest = 0;
function once() {
  return new Promise((resolve) => {
    const started = performance.now();
    const req = http.request({ method: "GET", hostname: "127.0.0.1", port: 3000, path: "/health" }, (res) => {
      res.resume();
      res.on("end", () => {
        latencies.push(Math.round(performance.now() - started));
        if (res.statusCode !== 200) errors.push(String(res.statusCode));
        resolve();
      });
    });
    req.on("error", (error) => {
      errors.push(error.message);
      resolve();
    });
    req.end();
  });
}
async function worker() {
  while (nextRequest < requests) {
    nextRequest += 1;
    await once();
  }
}
Promise.all(Array.from({ length: Math.min(concurrency, requests) }, () => worker())).then(() => {
  const sorted = latencies.sort((a, b) => a - b);
  const p95Index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
  const p95 = sorted[p95Index] ?? 0;
  const avg = sorted.reduce((sum, value) => sum + value, 0) / Math.max(sorted.length, 1);
  console.log(JSON.stringify({ errors, requests, concurrency, avg, p95, maxP95Ms }));
  process.exit(errors.length || p95 > maxP95Ms ? 1 : 0);
});
`;
  const result = dockerExec("enterprise-backend", ["node", "-e", script], { capture: true, allowFailure: true });
  const text = String(result.stdout ?? "").trim();
  const parsed = text ? JSON.parse(text.split(/\r?\n/).at(-1)) : null;
  if (!parsed) {
    fail(`${label} did not return metrics.`);
  }
  if (result.status !== 0) {
    if (parsed.errors?.length) parsed.errors.slice(0, 10).forEach((error) => log(`internal backend returned ${error}`));
    fail(`${label} failed: errors=${parsed.errors?.length ?? 0} p95=${parsed.p95}ms maxP95Ms=${parsed.maxP95Ms}ms.`);
  }
  log(`${label} passed: requests=${parsed.requests} requestedConcurrency=${parsed.concurrency} avg=${parsed.avg.toFixed(2)}ms p95=${parsed.p95}ms`);
}

async function runLoadProbe({ label, url, requests, concurrency, maxP95Ms }) {
  const latencies = [];
  const errors = [];
  const syntheticClientPool = booleanFlag(argv.preserveClientIp) ? 0 : positiveInteger(argv.syntheticClients ?? 64, "syntheticClients");
  let nextRequest = 0;
  const workerCount = Math.min(concurrency, requests);
  const runOne = async () => {
    const requestIndex = nextRequest;
    nextRequest += 1;
    if (requestIndex >= requests) return;
    const started = performance.now();
    try {
      const headers = syntheticClientPool > 0 ? { "X-Forwarded-For": `198.51.100.${(requestIndex % syntheticClientPool) + 1}` } : {};
      const response = await request("GET", url, { headers });
      latencies.push(Math.round(performance.now() - started));
      if (response.status !== 200) {
        errors.push(`${url} returned ${response.status}`);
      }
    } catch (error) {
      errors.push(String(error.message ?? error));
    }
    await runOne();
  };
  await Promise.all(Array.from({ length: workerCount }, () => runOne()));
  if (errors.length) {
    errors.slice(0, 10).forEach((error) => log(error));
    fail(`${label} failed with ${errors.length} errors.`);
  }
  const sorted = latencies.sort((a, b) => a - b);
  const p95Index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
  const p95 = sorted[p95Index] ?? 0;
  const avg = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  log(`${label} passed: requests=${requests} requestedConcurrency=${concurrency} syntheticClients=${syntheticClientPool || 1} avg=${avg.toFixed(2)}ms p95=${p95}ms`);
  if (p95 > maxP95Ms) {
    fail(`${label} p95 ${p95}ms exceeded ${maxP95Ms}ms.`);
  }
}

async function offsiteBackupRestic() {
  let backupFile = argv.backupFile;
  const repository = argv.repository ?? process.env.RESTIC_REPOSITORY;
  const password = argv.password ?? process.env.RESTIC_PASSWORD;
  const tag = argv.tag ?? "stexor-postgres";
  if (!backupFile) {
    const backupRoot = path.join(infraRoot, "backups", "postgres");
    const dumps = fs.existsSync(backupRoot)
      ? fs.readdirSync(backupRoot).filter((file) => file.endsWith(".dump")).map((file) => path.join(backupRoot, file))
      : [];
    dumps.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
    backupFile = dumps[0];
    if (!backupFile) {
      fail("No PostgreSQL dump found. Run backup-postgres first.");
    }
  }
  if (!fs.existsSync(backupFile)) {
    fail(`Backup file not found: ${backupFile}`);
  }
  verifyBackupArtifact(backupFile);
  if (!repository || !password) {
    fail("Set RESTIC_REPOSITORY and RESTIC_PASSWORD before running off-site backup.");
  }
  const backupDir = path.dirname(path.resolve(backupFile));
  const backupName = path.basename(backupFile);
  const sidecars = [`${backupName}.sha256`, `${backupName}.sig.json`].filter((file) => fs.existsSync(path.join(backupDir, file)));
  run("docker", [
    "run",
    "--rm",
    "-e",
    `RESTIC_REPOSITORY=${repository}`,
    "-e",
    `RESTIC_PASSWORD=${password}`,
    "-v",
    `${backupDir}:/backup:ro`,
    "restic/restic:0.18.0",
    "backup",
    `/backup/${backupName}`,
    ...sidecars.map((file) => `/backup/${file}`),
    "--tag",
    tag,
  ]);
  log(`Off-site backup completed for ${backupFile}`);
}

async function productionPreflight() {
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
  if (!fs.existsSync(envFile)) {
    fail(`Env file not found: ${envFile}`);
  }
  const env = parseEnv(envFile);
  const requireKey = (key) => {
    if (!env[key]) {
      fail(`Missing required production env: ${key}`);
    }
    if (/change_me|your-domain|localhost/i.test(env[key])) {
      fail(`Production env ${key} still contains placeholder/local value: ${env[key]}`);
    }
  };
  [
    "TRAEFIK_ACME_EMAIL",
    "API_PUBLIC_URL",
    "ACCOUNT_PUBLIC_URL",
    "UI_PUBLIC_URL",
    "NEXT_PUBLIC_API_URL",
    "NEXT_PUBLIC_UI_URL",
    "NEXT_PUBLIC_ACCOUNT_URL",
    "NEXTAUTH_URL",
    "KEYCLOAK_ISSUER",
    "WEBAUTHN_RP_ID",
    "WEBAUTHN_ORIGINS",
    "CORS_ORIGINS",
    "SMTP_USER",
    "BACKEND_IMAGE",
    "WEB_IMAGE",
    "WORKER_NOTIFICATIONS_IMAGE",
    "WORKER_JOBS_IMAGE",
  ].forEach(requireKey);

  for (const [key, minLength] of [
    ["SESSION_SECRET", 48],
    ["SESSION_SIGNING_KEYS", 48],
    ["SECRET_HASH_KEYS", 48],
    ["BACKUP_SIGNING_KEYS", 48],
    ["POSTGRES_SUPERUSER_PASSWORD", 24],
    ["APP_DB_PASSWORD", 24],
    ["KEYCLOAK_DB_PASSWORD", 24],
    ["REDIS_PASSWORD", 24],
    ["NATS_PASSWORD", 24],
    ["MINIO_ROOT_PASSWORD", 24],
    ["GRAFANA_ADMIN_PASSWORD", 24],
    ["SMTP_PASSWORD", 16],
  ]) {
    requireManagedOrRawSecret(env, key, { minLength });
  }

  for (const imageKey of ["BACKEND_IMAGE", "WEB_IMAGE", "WORKER_NOTIFICATIONS_IMAGE", "WORKER_JOBS_IMAGE"]) {
    if (/:latest(?:@|$)/.test(env[imageKey])) {
      fail(`${imageKey} must use an immutable version tag and digest, not :latest`);
    }
    if (!/@sha256:[a-f0-9]{64}$/i.test(env[imageKey])) {
      fail(`${imageKey} must be pinned by digest.`);
    }
    if (/@sha256:0{64}$/i.test(env[imageKey])) {
      fail(`${imageKey} must use a real image digest, not the all-zero placeholder.`);
    }
  }
  if ((env.SESSION_COOKIE_SECURE ?? "true").toLowerCase() !== "true") {
    fail("SESSION_COOKIE_SECURE must be true in production.");
  }
  if (hasManagedSecret(env, "SESSION_SECRET") && !env.SECRET_MANAGER_PROVIDER) {
    fail("Managed production secrets require SECRET_MANAGER_PROVIDER.");
  }
  if (!argv.skipDns) {
    for (const host of [env.UI_HOST, env.ACCOUNT_HOST, env.API_HOST, env.AUTH_HOST].filter(Boolean)) {
      if (/localhost|your-domain/i.test(host)) {
        fail(`Production host is not public: ${host}`);
      }
      await dns.resolve4(host);
    }
  }
  log("Production preflight passed.");
}

async function haConfigCheck() {
  log("==> HA multi-node configuration check");
  const haCompose = readText(path.join(infraRoot, "compose.ha.yaml"));
  for (const service of ["backend", "web", "worker-notifications", "worker-jobs"]) {
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?container_name:\\s*!reset null`, "m"), `${service} must reset fixed container_name for replicas.`);
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?replicas:\\s*\\$\\{`, "m"), `${service} must declare configurable replicas.`);
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?failure_action:\\s*rollback`, "m"), `${service} must rollback failed rolling updates.`);
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?rollback_config:`, "m"), `${service} must define rollback_config.`);
  }
  for (const service of ["postgres", "redis", "nats", "minio"]) {
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?node\\.labels\\.stexor\\.stateful == true`, "m"), `${service} must be pinned to stateful nodes or replaced by a managed tier.`);
  }
  run("docker", [
    "compose",
    "--env-file",
    ".env",
    "-p",
    "enterprise_prod_ha",
    "-f",
    "compose.yaml",
    "-f",
    "compose.prod.yaml",
    "-f",
    "compose.ha.yaml",
    "config",
    "--quiet",
  ]);
  log("HA multi-node configuration check passed.");
}

async function managedSecretsPreflight() {
  log("==> Managed secrets / KMS preflight");
  const managedCompose = readText(path.join(infraRoot, "compose.managed-secrets.yaml"));
  for (const secretName of [
    "postgres_superuser_password",
    "app_db_password",
    "keycloak_db_password",
    "redis_password",
    "keycloak_admin_password",
    "nats_password",
    "minio_root_password",
    "grafana_admin_password",
    "session_secret",
    "session_signing_keys",
    "hash_pepper_keys",
    "backup_signing_keys",
    "smtp_password",
    "google_recaptcha_secret_key",
    "cloudflare_turnstile_secret_key",
    "google_oauth_client_secret",
    "database_url",
    "nats_url",
  ]) {
    assertMatch(managedCompose, new RegExp(`^\\s{2}${secretName}:\\s*\\r?\\n\\s+external:\\s+true`, "m"), `${secretName} must be declared as an external Docker secret.`);
  }
  for (const fileEnv of ["SESSION_SECRET_FILE", "SESSION_SIGNING_KEYS_FILE", "SECRET_HASH_KEYS_FILE", "DATABASE_URL_FILE", "SMTP_PASSWORD_FILE", "GOOGLE_RECAPTCHA_SECRET_KEY_FILE", "CLOUDFLARE_TURNSTILE_SECRET_KEY_FILE", "GOOGLE_OAUTH_CLIENT_SECRET_FILE"]) {
    assertMatch(managedCompose, new RegExp(`${fileEnv}:\\s+/run/secrets/`), `${fileEnv} must point at /run/secrets.`);
  }
  run("docker", [
    "compose",
    "--env-file",
    ".env",
    "-p",
    "enterprise_prod_managed_secrets",
    "-f",
    "compose.yaml",
    "-f",
    "compose.prod.yaml",
    "-f",
    "compose.managed-secrets.yaml",
    "config",
    "--quiet",
  ]);
  log("Managed secrets / KMS preflight passed.");
}

async function releaseArtifactGate() {
  log("==> Release artifact admission gate");
  const env = parseEnv(path.resolve(argv.envFile ?? path.join(infraRoot, ".env")));
  const images = (argv.images ? argv.images.split(",") : [
    env.BACKEND_IMAGE,
    env.WEB_IMAGE,
    env.WORKER_NOTIFICATIONS_IMAGE,
    env.WORKER_JOBS_IMAGE,
  ]).filter(Boolean);
  if (!images.length) {
    fail("No release images found. Set BACKEND_IMAGE, WEB_IMAGE, WORKER_NOTIFICATIONS_IMAGE and WORKER_JOBS_IMAGE or pass --images.");
  }
  for (const image of images) {
    if (/:latest(?:@|$)/.test(image)) {
      fail(`Mutable :latest image is not admissible: ${image}`);
    }
    if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
      fail(`Release image must be digest-pinned: ${image}`);
    }
  }

  const sbomFile = argv.sbom ?? latestFileByMtime(path.join(infraRoot, "security", "sbom"), (file) => /sbom.*\.(json|cdx\.json)$/i.test(path.basename(file)));
  if (!sbomFile || !fs.existsSync(sbomFile)) {
    fail("A release SBOM artifact is required. Run generate-sbom or pass --sbom <file>.");
  }
  JSON.parse(fs.readFileSync(sbomFile, "utf8"));

  const policy = readText(path.join(infraRoot, "security", "admission", "cosign-digest-policy.rego"));
  assertMatch(policy, /cosign\.sigstore\.dev\/verified/, "Admission policy must require cosign verification annotation.");
  assertMatch(policy, /slsa\.dev\/provenance/, "Admission policy must require SLSA provenance annotation.");

  if (booleanFlag(argv.requireProvenance)) {
    const provenance = argv.provenance;
    if (!provenance || !fs.existsSync(path.resolve(provenance))) {
      fail("SLSA provenance is required. Pass --provenance <file>.");
    }
  }
  if (booleanFlag(argv.verifyCosign)) {
    for (const image of images) {
      run("cosign", ["verify", image]);
    }
  }
  log(`Release artifact admission gate passed with SBOM ${sbomFile}.`);
}

async function drReadinessCheck() {
  log("==> DR / PITR readiness check");
  const drCompose = readText(path.join(infraRoot, "compose.dr.yaml"));
  const plan = readText(path.join(infraRoot, "ENTERPRISE-10-PLAN.md"));
  const runbook = readText(path.join(infraRoot, "RUNBOOK.md"));
  assertMatch(drCompose, /archive_mode=on/, "DR overlay must enable PostgreSQL archive_mode.");
  assertMatch(drCompose, /wal_level=replica/, "DR overlay must set wal_level=replica.");
  assertMatch(drCompose, /enterprise_postgres_wal_archive/, "DR overlay must persist WAL archives.");
  assertMatch(plan, /RPO:\s+15 minutes/i, "Enterprise plan must declare the RPO target.");
  assertMatch(plan, /RTO:\s+60 minutes/i, "Enterprise plan must declare the RTO target.");
  assertMatch(runbook, /offsite-backup-restic/, "Runbook must include encrypted off-site backup procedure.");
  assertMatch(runbook, /backup-restore-drill/, "Runbook must include scheduled restore drill procedure.");
  run("docker", [
    "compose",
    "--env-file",
    ".env",
    "-p",
    "enterprise_prod_dr",
    "-f",
    "compose.yaml",
    "-f",
    "compose.prod.yaml",
    "-f",
    "compose.dr.yaml",
    "config",
    "--quiet",
  ]);
  log("DR / PITR readiness check passed.");
}

async function securityMatrix() {
  log("==> Security test matrix");
  await testingHygiene();
  const securitySpec = readText(path.join(sourceRoot, "e2e", "security-guards.spec.ts"));
  const accountSpec = readText(path.join(sourceRoot, "e2e", "account-auth.spec.ts"));
  const opsScript = readText(path.join(infraRoot, "scripts", "stexor-ops.mjs"));
  assertMatch(securitySpec, /cross-site mutating requests are blocked/, "Security E2E must cover cross-site request blocking.");
  assertMatch(securitySpec, /require the CSRF header/, "Security E2E must cover CSRF header enforcement.");
  assertMatch(accountSpec, /loginWithBackupCodeRecovery/, "Account E2E must cover backup-code recovery login.");
  assertMatch(accountSpec, /expectBackupCodeStatus\(page, backupCode \?\? "", 400\)/, "Account E2E/integration must cover backup-code single-use blocking.");
  assertMatch(opsScript, /passkey login options for added account/, "Account integration must cover passkey requested-account isolation.");
  await securitySmoke();
  await accountIntegrationTests();
  log("Security test matrix passed.");
}

async function chaosProfile() {
  log("==> Staging chaos profile");
  if (!booleanFlag(argv.confirmChaos)) {
    fail("chaos-profile is destructive. Re-run with --confirmChaos in staging.");
  }
  const targets = ["enterprise-redis", "enterprise-nats", "enterprise-minio"];
  if (booleanFlag(argv.includePostgres)) {
    targets.push("enterprise-postgres");
  }
  const stopped = [];
  try {
    for (const container of targets) {
      log(`Stopping ${container}`);
      run("docker", ["stop", "--time", "10", container]);
      stopped.push(container);
      await new Promise((resolve) => setTimeout(resolve, 3000));
      if (container === "enterprise-redis") {
        await securitySmoke();
      }
      log(`Restarting ${container}`);
      run("docker", ["start", container]);
      stopped.pop();
      await new Promise((resolve) => setTimeout(resolve, 5000));
      await runtimeHealthChecks();
    }
    await faultInjectionTests();
    await loadProfile();
    log("Staging chaos profile passed.");
  } finally {
    for (const container of stopped.reverse()) {
      run("docker", ["start", container], { allowFailure: true, capture: true });
    }
  }
}

async function governanceCheck() {
  log("==> Governance / release control check");
  const workflow = readText(path.join(sourceRoot, ".github", "workflows", "enterprise-ci.yml"));
  const branchProtection = JSON.parse(readText(path.join(infraRoot, "governance", "github-branch-protection.json")));
  const runbook = readText(path.join(infraRoot, "RUNBOOK.md"));
  for (const job of ["quality", "compose", "supply-chain", "enterprise-readiness"]) {
    assertMatch(workflow, new RegExp(`^\\s{2}${job}:`, "m"), `Enterprise CI must define ${job} job.`);
    if (!branchProtection.required_status_checks.contexts.includes(job)) {
      fail(`Branch protection must require ${job}.`);
    }
  }
  assertMatch(runbook, /Production deploy/, "Runbook must document production deploy.");
  assertMatch(runbook, /Rollback/, "Runbook must document rollback.");
  assertMatch(runbook, /release approval/i, "Runbook must document release approval.");
  assertMatch(runbook, /audit trail/i, "Runbook must document deploy audit trail.");
  log("Governance / release control check passed.");
}

async function enterpriseTenCheck() {
  log("==> Enterprise 10 readiness gate");
  await haConfigCheck();
  await managedSecretsPreflight();
  await releaseArtifactGate();
  await drReadinessCheck();
  await governanceCheck();
  await staticSecurityCheck();
  await testingHygiene();
  await performanceHygiene();
  log("Enterprise 10 readiness gate passed.");
}

async function restorePostgres() {
  const backupFileArg = argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  if (!argv.confirmRestore) {
    fail("Restore is destructive. Re-run with --confirmRestore after verifying the backup file.");
  }
  const container = argv.container ?? "enterprise-postgres";
  const database = argv.database ?? "stexor_app";
  const user = argv.user ?? "postgres";
  const backupFile = resolveInside(path.join(infraRoot, "backups"), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const containerPath = `/tmp/${fileName}`;
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  try {
    log(`Copying backup into ${container}...`);
    run("docker", ["cp", backupFile, `${container}:${containerPath}`]);
    log(`Restoring database '${database}'. This will clean existing objects owned by the dump.`);
    dockerExec(container, ["pg_restore", "-U", user, "-d", database, "--clean", "--if-exists", "--no-owner", "--no-acl", containerPath]);
    dockerExec(container, ["rm", "-f", containerPath]);
    recordBackupRestoreRun({ container, database, user, operation: "restore", status: "success", artifactPath: backupFile, artifactSha256: hash, startedAt });
    log("Restore complete.");
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-f", containerPath], { allowFailure: true });
      recordBackupRestoreRun({ container, database, user, operation: "restore", status: "failed", artifactPath: backupFile, artifactSha256: hash, startedAt, metadata: { error: String(error?.message ?? error) } });
    } catch {
      // Preserve the original restore failure.
    }
    throw error;
  }
}

async function restoreTestPostgres(options = {}) {
  const backupFileArg = options.backupFile ?? argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? "stexor_app";
  const testDatabase = options.testDatabase ?? argv.testDatabase ?? "stexor_restore_test";
  const user = options.user ?? argv.user ?? "postgres";
  const backupFile = resolveInside(path.join(infraRoot, "backups"), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const containerPath = `/tmp/${fileName}`;
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  const testDatabaseIdentifier = sqlIdentifier(testDatabase);
  try {
    log(`Creating disposable restore-test database '${testDatabase}'...`);
    dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `drop database if exists ${testDatabaseIdentifier} with (force);`]);
    dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `create database ${testDatabaseIdentifier};`]);
    run("docker", ["cp", backupFile, `${container}:${containerPath}`]);
    dockerExec(container, ["pg_restore", "-U", user, "-d", testDatabase, "--no-owner", "--no-acl", containerPath]);
    dockerExec(container, ["rm", "-f", containerPath]);
    const tables = Number(postgresOut(container, testDatabase, user, "select count(*) from information_schema.tables where table_schema = 'stexor_account';"));
    dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `drop database if exists ${testDatabaseIdentifier} with (force);`]);
    if (tables < 10) {
      fail(`Restore test produced too few stexor_account tables: ${tables}`);
    }
    recordBackupRestoreRun({ container, database, user, operation: "restore_test", status: "success", artifactPath: backupFile, artifactSha256: hash, startedAt, metadata: { restoredTables: tables, testDatabase } });
    log(`Restore test passed with ${tables} stexor_account tables.`);
    return { backupFile, hash, tables, testDatabase, container, database, user };
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-f", containerPath], { allowFailure: true });
      dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `drop database if exists ${testDatabaseIdentifier} with (force);`], { allowFailure: true });
      recordBackupRestoreRun({ container, database, user, operation: "restore_test", status: "failed", artifactPath: backupFile, artifactSha256: hash, startedAt, metadata: { error: String(error?.message ?? error), testDatabase } });
    } catch {
      // Preserve the original restore-test failure.
    }
    throw error;
  }
}

async function backupRestoreDrill() {
  log("==> PostgreSQL backup/restore drill");
  const container = argv.container ?? "enterprise-postgres";
  const database = argv.database ?? "stexor_app";
  const user = argv.user ?? "postgres";
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "postgres", "drills"));
  const suffix = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const testDatabase = argv.testDatabase ?? `stexor_restore_test_${suffix}`;
  const backup = await backupPostgres({ container, database, user, outputDir });
  const restore = await restoreTestPostgres({ container, database, user, backupFile: backup.hostPath, testDatabase });
  const recorded = postgresOut(
    container,
    database,
    user,
    `
      select count(*)
      from stexor_platform.backup_restore_runs
      where operation = 'restore_test'
        and status = 'success'
        and artifact_sha256 = ${sqlString(backup.hash)}
        and metadata->>'testDatabase' = ${sqlString(restore.testDatabase)}
    `,
  ).trim();
  if (recorded !== "1") {
    fail("Restore drill completed but backup_restore_runs did not record the matching restore_test success.");
  }
  log(`Backup/restore drill recorded restore_test success for ${path.basename(backup.hostPath)}.`);
}

function listDumpArtifacts(directory) {
  if (!fs.existsSync(directory)) {
    return [];
  }
  return fs.readdirSync(directory)
    .filter((file) => file.endsWith(".dump"))
    .map((file) => {
      const filePath = resolveInside(directory, path.join(directory, file));
      const shaPath = `${filePath}.sha256`;
      const sigPath = backupSignatureSidecarPath(filePath);
      return {
        file,
        filePath,
        mtimeMs: fs.statSync(filePath).mtimeMs,
        shaPath: fs.existsSync(shaPath) ? resolveInside(directory, shaPath) : null,
        sigPath: fs.existsSync(sigPath) ? resolveInside(directory, sigPath) : null,
      };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
}

function pruneDumpDirectory({ directory, dryRun, label, minKeep, retentionDays }) {
  const artifacts = listDumpArtifacts(directory);
  const cutoff = Date.now() - retentionDays * 86400000;
  let removed = 0;
  for (const [index, artifact] of artifacts.entries()) {
    if (index < minKeep || artifact.mtimeMs >= cutoff) {
      continue;
    }
    const action = dryRun ? "Would delete" : "Deleting";
    log(`${action} ${label} backup artifact: ${artifact.filePath}`);
    if (artifact.shaPath) {
      log(`${action} ${label} checksum: ${artifact.shaPath}`);
    }
    if (artifact.sigPath) {
      log(`${action} ${label} signature: ${artifact.sigPath}`);
    }
    if (!dryRun) {
      fs.rmSync(artifact.filePath, { force: true });
      if (artifact.shaPath) fs.rmSync(artifact.shaPath, { force: true });
      if (artifact.sigPath) fs.rmSync(artifact.sigPath, { force: true });
    }
    removed += 1;
  }
  return { kept: artifacts.length - removed, removed, total: artifacts.length };
}

function assertRecentRestoreTest(container, database, user, maxAgeDays) {
  const count = postgresOut(
    container,
    database,
    user,
    `
      select count(*)
      from stexor_platform.backup_restore_runs
      where operation = 'restore_test'
        and status = 'success'
        and finished_at >= now() - (${positiveInteger(maxAgeDays, "--maxRestoreTestAgeDays")}::text || ' days')::interval
    `,
  ).trim();
  if (count === "0") {
    fail(`Refusing backup retention cleanup: no successful restore_test in the last ${maxAgeDays} days.`);
  }
}

async function prunePostgresBackups(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? "stexor_app";
  const user = options.user ?? argv.user ?? "postgres";
  const backupDir = path.resolve(options.backupDir ?? argv.backupDir ?? path.join(infraRoot, "backups", "postgres"));
  const drillDir = path.resolve(options.drillDir ?? argv.drillDir ?? path.join(backupDir, "drills"));
  const backupRetentionDays = positiveInteger(options.retentionDays ?? argv.retentionDays ?? 30, "--retentionDays");
  const drillRetentionDays = positiveInteger(options.drillRetentionDays ?? argv.drillRetentionDays ?? 14, "--drillRetentionDays");
  const minBackups = positiveInteger(options.minBackups ?? argv.minBackups ?? 3, "--minBackups");
  const minDrills = positiveInteger(options.minDrills ?? argv.minDrills ?? 3, "--minDrills");
  const maxRestoreTestAgeDays = positiveInteger(options.maxRestoreTestAgeDays ?? argv.maxRestoreTestAgeDays ?? 35, "--maxRestoreTestAgeDays");
  const dryRun = options.dryRun ?? booleanFlag(argv.dryRun);

  resolveInside(path.join(infraRoot, "backups"), backupDir);
  if (fs.existsSync(drillDir)) {
    resolveInside(path.join(infraRoot, "backups"), drillDir);
  }
  assertRecentRestoreTest(container, database, user, maxRestoreTestAgeDays);

  log(`==> PostgreSQL backup retention${dryRun ? " dry run" : ""}`);
  const backups = pruneDumpDirectory({ directory: backupDir, dryRun, label: "regular", minKeep: minBackups, retentionDays: backupRetentionDays });
  const drills = pruneDumpDirectory({ directory: drillDir, dryRun, label: "drill", minKeep: minDrills, retentionDays: drillRetentionDays });
  log(`Retention complete: regular ${backups.removed}/${backups.total} pruned, drill ${drills.removed}/${drills.total} pruned.`);
}

async function secretScan() {
  const roots = [
    path.resolve(argv.infraRoot ?? infraRoot),
    path.resolve(argv.sourceRoot ?? sourceRoot),
  ];
  const patterns = [
    /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/,
    /\baws_access_key_id\b/i,
    /\baws_secret_access_key\b/i,
    /\b(api|access|secret|private|client)_?(key|token|secret)\b\s*[:=]\s*['"][^'"]{16,}/i,
    /\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{8,}/i,
    /\bSMTP_PASSWORD\b\s*=.+/i,
  ];
  const ignoredDirs = new Set([
    ".git",
    "node_modules",
    ".pnpm-store",
    ".next",
    "dist",
    "coverage",
    "backups",
    "secrets",
    "certs",
    "acme",
    "sbom",
  ]);
  const hits = [];
  const scanFile = (filePath) => {
    const relativeName = path.basename(filePath);
    if (/^\.env(?:\.|$)/.test(relativeName)) {
      return;
    }
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) {
      return;
    }
    const content = fs.readFileSync(filePath);
    if (content.includes(0)) {
      return;
    }
    const text = content.toString("utf8");
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (/change_me|placeholder|example|your-domain|smtpPassword|redisPassword|dbPassword|rootPassword|WITH PASSWORD :'\w+_password'/i.test(line)) {
        return;
      }
      if (patterns.some((pattern) => pattern.test(line))) {
        hits.push(`${filePath}:${index + 1}: ${line.trim()}`);
      }
    });
  };
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ignoredDirs.has(entry.name)) {
        continue;
      }
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        scanFile(fullPath);
      }
    }
  };
  for (const root of roots) {
    if (fs.existsSync(root)) {
      walk(root);
    }
  }
  if (hits.length) {
    hits.forEach((hit) => log(hit));
    fail("Potential hardcoded secrets found. Review the hits above.");
  }
  log("Secret scan passed.");
}

async function securitySmoke() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const uiPublicUrl = env.UI_PUBLIC_URL ?? env.NEXT_PUBLIC_UI_URL ?? "https://ui.localhost.com";
  const accountPublicUrl = env.ACCOUNT_PUBLIC_URL ?? env.NEXT_PUBLIC_ACCOUNT_URL ?? "https://account.localhost.com";
  const apiPublicUrl = env.API_PUBLIC_URL ?? env.NEXT_PUBLIC_API_URL ?? "https://api.localhost.com";
  const defaultUrls = [
    `${uiPublicUrl.replace(/\/$/, "")}/`,
    `${accountPublicUrl.replace(/\/$/, "")}/`,
    `${apiPublicUrl.replace(/\/$/, "")}/health`,
  ].join(",");
  const urls = (argv.urls ?? defaultUrls).split(",").map((url) => url.trim()).filter(Boolean);
  for (const url of urls) {
    log(`Checking ${url}`);
    const response = await request("HEAD", url);
    const headers = headerText(response.headers);
    for (const required of ["strict-transport-security", "x-content-type-options", "referrer-policy", "permissions-policy"]) {
      if (!headers.includes(required)) {
        fail(`Missing ${required} on ${url}`);
      }
    }
  }

  assertStatus(await request("GET", "https://api.localhost.com/account/snapshot"), 401, "unauthenticated account snapshot");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { Origin: "https://evil.example" } }), 403, "untrusted Origin");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { "Sec-Fetch-Site": "cross-site" } }), 403, "cross-site Fetch Metadata");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" } }), 200, "same-site logout");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "cross-site" } }), 200, "trusted cross-site logout");
  log("Security smoke checks passed.");
}

async function signImages() {
  const images = (argv.images ? argv.images.split(",") : [
    process.env.BACKEND_IMAGE,
    process.env.WEB_IMAGE,
    process.env.WORKER_NOTIFICATIONS_IMAGE,
    process.env.WORKER_JOBS_IMAGE,
  ]).filter(Boolean);
  const key = argv.key ?? process.env.COSIGN_KEY;
  const hasCosign = run("cosign", ["version"], { capture: true, allowFailure: true }).status === 0;
  if (!hasCosign) {
    fail("cosign is required for image signing. Install cosign and authenticate to your registry.");
  }
  if (!key) {
    fail("Set COSIGN_KEY to a key reference or use keyless signing in CI.");
  }
  for (const image of images) {
    if (/:latest$/.test(image)) {
      fail(`Refusing to sign mutable :latest image: ${image}`);
    }
    run("cosign", ["sign", "--key", key, image]);
  }
  log("Image signing completed.");
}

async function staticSecurityCheck() {
  log("==> Static security checks");
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const composeBuild = readText(path.join(infraRoot, "compose.build.yaml"));
  const composeProd = readText(path.join(infraRoot, "compose.prod.yaml"));
  const composeSecrets = readText(path.join(infraRoot, "compose.secrets.yaml"));
  const composeHa = readText(path.join(infraRoot, "compose.ha.yaml"));
  const composeManagedSecrets = readText(path.join(infraRoot, "compose.managed-secrets.yaml"));
  const composeDr = readText(path.join(infraRoot, "compose.dr.yaml"));
  const prometheusConfig = readText(path.join(infraRoot, "prometheus", "prometheus.yml"));
  const prometheusAlerts = readText(path.join(infraRoot, "prometheus", "rules", "enterprise-alerts.yml"));
  const alertmanagerConfig = readText(path.join(infraRoot, "alertmanager", "alertmanager.yml"));
  const lokiConfig = readText(path.join(infraRoot, "loki", "config.yml"));
  const promtailConfig = readText(path.join(infraRoot, "promtail", "config.yml"));
  const backendDockerfile = readText(path.join(infraRoot, "docker", "backend.Dockerfile"));
  const webDockerfile = readText(path.join(infraRoot, "docker", "web.Dockerfile"));
  const workerDockerfile = readText(path.join(infraRoot, "docker", "worker.Dockerfile"));
  const opsScript = readText(path.join(infraRoot, "scripts", "stexor-ops.mjs"));
  const secretManagerScript = readText(path.join(infraRoot, "scripts", "stexor-secret-manager.mjs"));
  const backendConfig = readText(path.join(sourceRoot, "apps", "backend", "src", "server-config.ts"));
  const backendRedisStore = readText(path.join(sourceRoot, "apps", "backend", "src", "runtime", "redis-store.ts"));
  const backendSessionAuth = readText(path.join(sourceRoot, "apps", "backend", "src", "runtime", "session-auth.ts"));
  const observabilitySource = readText(path.join(sourceRoot, "packages", "observability", "src", "index.ts"));
  const workerJobsServer = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "server.ts"));
  const workerNotificationsServer = readText(path.join(sourceRoot, "apps", "worker-notifications", "src", "server.ts"));
  const workerJobsAuditOutbox = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "audit-outbox.ts"));
  const workerJobsAuditOutboxStore = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "audit-outbox-store.ts"));
  const workerJobsNatsSink = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "nats-audit-sink.ts"));
  const sourcePackage = readText(path.join(sourceRoot, "package.json"));
  const sourceSupplyChainGate = readText(path.join(sourceRoot, "scripts", "supply-chain-gate.mjs"));
  const sourceCiWorkflow = readText(path.join(sourceRoot, ".github", "workflows", "enterprise-ci.yml"));
  const cryptoRuntime = readText(path.join(sourceRoot, "apps", "backend", "src", "runtime", "crypto.ts"));
  const webNextConfig = readText(path.join(sourceRoot, "apps", "web", "next.config.mjs"));
  const webProxy = readText(path.join(sourceRoot, "apps", "web", "src", "proxy.ts"));
  const webAppNotFound = readText(path.join(sourceRoot, "apps", "web", "src", "app", "not-found.tsx"));
  const webGlobalError = readText(path.join(sourceRoot, "apps", "web", "src", "app", "global-error.tsx"));
  const webRememberModel = readText(path.join(sourceRoot, "apps", "web", "src", "components", "account-center", "model.ts"));
  const webSource = readSourceTreeText(path.join(sourceRoot, "apps", "web", "src"));
  const uiSource = readSourceTreeText(path.join(sourceRoot, "packages", "ui", "src"));
  const browserUiSource = `${webSource}\n${uiSource}`;
  const enterprisePlan = readText(path.join(infraRoot, "ENTERPRISE-10-PLAN.md"));
  const admissionPolicy = readText(path.join(infraRoot, "security", "admission", "cosign-digest-policy.rego"));
  const branchProtection = readText(path.join(infraRoot, "governance", "github-branch-protection.json"));

  for (const text of [compose, backendDockerfile, webDockerfile, workerDockerfile]) {
    assertMatch(text, /@sha256:[a-f0-9]{64}/, "Base/runtime images must be digest-pinned.");
  }
  assertMatch(compose, /x-default-logging:[\s\S]*max-size:\s+"10m"[\s\S]*max-file:\s+"5"/, "Compose services must define bounded json-file logging.");
  assertMatch(compose, /^name:\s+enterprise_local/m, "Compose must set a stable local project name to avoid accidental duplicate stacks.");
  assertMatch(composeBuild, /BACKEND_BUILD_IMAGE[\s\S]*WEB_BUILD_IMAGE[\s\S]*WORKER_NOTIFICATIONS_BUILD_IMAGE[\s\S]*WORKER_JOBS_BUILD_IMAGE/, "Compose build must use local build image variables.");
  assertMatch(composeBuild, /cache_from:[\s\S]*cache_to:/, "Compose build must define reusable BuildKit cache import/export.");
  assertMatch(composeBuild, /NEXT_PUBLIC_API_URL[\s\S]*NEXT_PUBLIC_ACCOUNT_URL/, "Compose build must pass public web URLs into the Next.js production build.");
  assertNoMatch(composeBuild, /\$\{(?:BACKEND_IMAGE|WEB_IMAGE|WORKER_NOTIFICATIONS_IMAGE|WORKER_JOBS_IMAGE)[:-]/, "Compose build must not reuse production release image variables.");
  assertMatch(composeHa, /failure_action:\s+rollback/, "HA overlay must rollback failed rolling updates.");
  assertMatch(composeHa, /max_replicas_per_node:\s+1/, "HA overlay must spread stateless replicas across nodes.");
  assertMatch(composeManagedSecrets, /SESSION_SECRET_FILE:\s+\/run\/secrets\/session_secret/, "Managed secret overlay must consume session secret through a file.");
  assertMatch(composeManagedSecrets, /SESSION_SIGNING_KEYS_FILE:\s+\/run\/secrets\/session_signing_keys/, "Managed secret overlay must consume session signing keys through a file.");
  assertMatch(composeManagedSecrets, /GOOGLE_RECAPTCHA_SECRET_KEY_FILE:\s+\/run\/secrets\/google_recaptcha_secret_key/, "Managed secret overlay must consume Google reCAPTCHA secret through a file.");
  assertMatch(composeManagedSecrets, /CLOUDFLARE_TURNSTILE_SECRET_KEY_FILE:\s+\/run\/secrets\/cloudflare_turnstile_secret_key/, "Managed secret overlay must consume Cloudflare Turnstile secret through a file.");
  assertMatch(composeManagedSecrets, /GOOGLE_OAUTH_CLIENT_SECRET_FILE:\s+\/run\/secrets\/google_oauth_client_secret/, "Managed secret overlay must consume Google OAuth client secret through a file.");
  assertMatch(composeManagedSecrets, /ALERTMANAGER_WEBHOOK_TOKEN_FILE:\s+\/run\/secrets\/alertmanager_webhook_token/, "Managed secret overlay must consume the Alertmanager webhook token through a file.");
  assertMatch(composeManagedSecrets, /external:\s+true/, "Managed secret overlay must use external Docker secrets.");
  assertMatch(composeSecrets, /SESSION_SIGNING_KEYS_FILE:\s+\/run\/secrets\/session_signing_keys/, "Local secret overlay must consume session signing keys through a Docker secret file.");
  assertMatch(composeSecrets, /GOOGLE_RECAPTCHA_SECRET_KEY_FILE:\s+\/run\/secrets\/google_recaptcha_secret_key/, "Local secret overlay must consume Google reCAPTCHA secret through a Docker secret file.");
  assertMatch(composeSecrets, /CLOUDFLARE_TURNSTILE_SECRET_KEY_FILE:\s+\/run\/secrets\/cloudflare_turnstile_secret_key/, "Local secret overlay must consume Cloudflare Turnstile secret through a Docker secret file.");
  assertMatch(composeSecrets, /GOOGLE_OAUTH_CLIENT_SECRET_FILE:\s+\/run\/secrets\/google_oauth_client_secret/, "Local secret overlay must consume Google OAuth client secret through a Docker secret file.");
  assertMatch(composeSecrets, /ALERTMANAGER_WEBHOOK_TOKEN_FILE:\s+\/run\/secrets\/alertmanager_webhook_token/, "Local secret overlay must consume the Alertmanager webhook token through a Docker secret file.");
  assertMatch(secretManagerScript, /manager:\s+"stexor-secret-manager"/, "Infrastructure must include the proprietary Stexor Secret Manager store format.");
  assertMatch(secretManagerScript, /AES-256-GCM/, "Stexor Secret Manager must encrypt stored secrets with authenticated encryption.");
  assertMatch(secretManagerScript, /function audit\(/, "Stexor Secret Manager must append an audit trail for secret operations.");
  assertMatch(secretManagerScript, /function materialize\(/, "Stexor Secret Manager must materialize Docker secret files for Compose.");
  assertMatch(opsScript, /runSecretManager\(\["verify"/, "Enterprise local secret validation must verify the proprietary secret manager store.");
  assertMatch(composeDr, /archive_mode=on/, "DR overlay must enable PostgreSQL WAL archiving.");
  assertMatch(composeDr, /enterprise_postgres_wal_archive/, "DR overlay must persist WAL archives.");
  assertMatch(admissionPolicy, /cosign\.sigstore\.dev\/verified/, "Admission policy must require cosign verification.");
  assertMatch(admissionPolicy, /slsa\.dev\/provenance/, "Admission policy must require SLSA provenance.");
  assertMatch(branchProtection, /enterprise-readiness/, "Governance branch protection must require enterprise-readiness.");
  assertMatch(enterprisePlan, /## 1\. HA multi-node production[\s\S]*## 8\. Governance/, "Enterprise 10 plan must cover all eight readiness domains.");
  assertMatch(compose, /image:\s+\$\{BACKEND_BUILD_IMAGE:-stexor\/backend:local\}/, "Local dev backend must run the production image shape, not a generic Node watch container.");
  assertMatch(compose, /image:\s+\$\{WEB_BUILD_IMAGE:-stexor\/web:local\}/, "Local dev web must run the production image shape, not next dev.");
  assertMatch(compose, /image:\s+\$\{WORKER_NOTIFICATIONS_BUILD_IMAGE:-stexor\/worker-notifications:local\}/, "Local dev workers must run production-shaped images.");
  assertNoMatch(compose, /--watch|next dev/, "Local dev compose must not run watch/dev servers.");
  assertNoMatch(compose, /--loader \.\/scripts\/ts-extension-loader\.mjs/, "Dev backend must not use the unsupported Node --loader flag.");
  assertNoMatch(compose, /\.\.\/src:\/workspace/, "Local dev compose must not bind-mount app source into runtime containers.");
  assertNoMatch(compose, /\$\{(?:POSTGRES_PORT|REDIS_PORT|KEYCLOAK_PORT|NATS_CLIENT_PORT|NATS_MONITORING_PORT|MINIO_API_PORT|MINIO_CONSOLE_PORT|BACKEND_PORT|WEB_PORT|PROMETHEUS_PORT|GRAFANA_PORT|LOKI_PORT)/, "Local dev compose must not expose direct service ports; route through Traefik like production.");
  assertMatch(compose, /NODE_ENV:\s+production/, "Local dev app services must run with NODE_ENV=production.");
  assertNoMatch(compose, /\/var\/run\/docker\.sock/, "Compose must not mount docker.sock into application or observability containers.");
  assertNoMatch(promtailConfig, /docker_sd_configs|unix:\/\/\/var\/run\/docker\.sock/, "Promtail must scrape container logs without docker.sock service discovery.");
  assertMatch(promtailConfig, /drop:[\s\S]*older_than:\s+168h/, "Promtail must drop stale Docker log backfill before sending to Loki.");
  assertMatch(promtailConfig, /replace:[\s\S]*authorization[\s\S]*\[REDACTED\]/, "Promtail must apply a sensitive-field redaction pipeline.");
  assertMatch(promtailConfig, /json:[\s\S]*level:\s+level[\s\S]*service:\s+service/, "Promtail must parse structured application log fields.");
  assertMatch(promtailConfig, /labels:[\s\S]*level:[\s\S]*service:/, "Promtail must promote service and level labels for Loki queries.");
  assertMatch(lokiConfig, /retention_period:\s+168h/, "Loki must enforce bounded log retention.");
  assertMatch(lokiConfig, /reject_old_samples:\s+true/, "Loki must reject stale samples.");
  assertMatch(backendDockerfile, /FROM \$\{NODE_IMAGE\} AS build/, "Backend Dockerfile must use a dedicated JavaScript build stage.");
  assertMatch(backendDockerfile, /pnpm --filter \.\/apps\/backend build/, "Backend Dockerfile must build the production JavaScript bundle.");
  assertMatch(backendDockerfile, /COPY --from=build --chown=node:node \/workspace\/apps\/backend\/dist apps\/backend\/dist/, "Backend runtime image must copy compiled dist from the build stage.");
  assertMatch(backendDockerfile, /CMD \["node", "--enable-source-maps", "dist\/server\.js"\]/, "Backend runtime image must execute compiled JavaScript with source maps.");
  assertNoMatch(backendDockerfile, /register-ts-extension-loader|ts-extension-loader|src\/server\.ts/, "Backend production image must not run TypeScript through a runtime loader.");
  assertMatch(backendDockerfile, /packages\/observability\/package\.json[\s\S]*packages\/observability packages\/observability/, "Backend Dockerfile must include the shared observability package in build and runtime stages.");
  assertMatch(workerDockerfile, /packages\/observability\/package\.json[\s\S]*packages\/observability packages\/observability/, "Worker Dockerfile must include the shared observability package.");
  for (const service of ["traefik", "postgres", "redis", "keycloak", "nats", "minio", "backend", "web", "worker-notifications", "worker-jobs", "prometheus", "alertmanager", "grafana", "loki", "promtail"]) {
    assertMatch(
      compose,
      new RegExp(`^\\s{2}${service}:.*?init:\\s+true.*?pids_limit:\\s+\\d+.*?logging:\\s+\\*default_logging`, "ms"),
      `Service ${service} must have init, pids_limit and bounded logging.`,
    );
    assertMatch(
      compose,
      new RegExp(`^\\s{2}${service}:.*?security_opt:\\s*\\r?\\n\\s+- no-new-privileges:true`, "ms"),
      `Service ${service} must set no-new-privileges.`,
    );
  }
  for (const service of ["backend", "web", "worker-notifications", "worker-jobs"]) {
    assertMatch(
      compose,
      new RegExp(`^\\s{2}${service}:.*?read_only:\\s+true.*?no-new-privileges:true.*?cap_drop:\\s*\\r?\\n\\s+- ALL`, "ms"),
      `Dev service ${service} must be read-only, no-new-privileges and cap-drop ALL.`,
    );
  }
  for (const dockerfile of [backendDockerfile, webDockerfile, workerDockerfile]) {
    assertMatch(dockerfile, /^# syntax=docker\/dockerfile:1\.7/m, "Production Dockerfiles must opt into BuildKit cache mount syntax.");
    assertMatch(dockerfile, /--mount=type=cache,target=\/pnpm\/store/, "Production Dockerfiles must cache the pnpm store during dependency install.");
    assertMatch(dockerfile, /COPY --chown=node:node/, "Production Dockerfiles must copy runtime files as the node user.");
    assertMatch(dockerfile, /USER node[\s\S]*RUN[\s\S]*pnpm install/, "Production Dockerfiles must run dependency install as the non-root node user.");
    assertMatch(dockerfile, /^HEALTHCHECK /m, "Production Dockerfiles must include an image-level healthcheck.");
  }
  assertMatch(webDockerfile, /ARG NEXT_PUBLIC_API_URL[\s\S]*NEXT_PUBLIC_ACCOUNT_URL/, "Web Dockerfile must receive public URLs as build args for production bundles.");
  assertMatch(compose, /AUDIT_OUTBOX_ENABLED:\s+\$\{AUDIT_OUTBOX_ENABLED:-true\}/, "Worker jobs must enable audit outbox dispatch by default.");
  assertMatch(compose, /AUDIT_OUTBOX_MAX_ATTEMPTS:\s+\$\{AUDIT_OUTBOX_MAX_ATTEMPTS:-8\}/, "Audit outbox worker must have bounded retry attempts.");
  assertMatch(compose, /alertmanager:[\s\S]*prom\/alertmanager:v0\.32\.2@sha256:/, "Alertmanager must run as a pinned local/prod service.");
  assertMatch(composeProd, /alertmanager:[\s\S]*ports:\s*!reset \[\]/, "Alertmanager must not expose host ports in production.");
  assertMatch(prometheusConfig, /alertmanagers:[\s\S]*alertmanager:9093/, "Prometheus must route alerts to Alertmanager.");
  assertMatch(prometheusConfig, /job_name: alertmanager[\s\S]*alertmanager:9093/, "Prometheus must scrape Alertmanager.");
  assertMatch(alertmanagerConfig, /worker-notifications:3000\/alerts\/prometheus/, "Alertmanager must deliver alerts to the notification worker.");
  assertMatch(alertmanagerConfig, /authorization:[\s\S]*type:\s+Bearer[\s\S]*credentials_file:\s+\/run\/secrets\/alertmanager_webhook_token/, "Alertmanager webhook delivery must use the shared bearer-token secret.");
  assertMatch(lokiConfig, /alertmanager_url:\s+http:\/\/alertmanager:9093/, "Loki ruler must route alerts to Alertmanager over the Docker network.");
  for (const alertName of ["AuditOutboxDeadLetters", "PostgresBackupStale", "RestoreDrillStale", "AlertmanagerDeliveryFailed"]) {
    assertMatch(prometheusAlerts, new RegExp(`alert: ${alertName}`), `Prometheus alerts must include ${alertName}.`);
  }
  assertMatch(workerNotificationsServer, /\/alerts\/prometheus/, "Notification worker must expose an Alertmanager webhook endpoint.");
  assertMatch(workerNotificationsServer, /ALERTMANAGER_WEBHOOK_TOKEN/, "Notification worker must require the Alertmanager webhook token in production.");
  assertMatch(workerNotificationsServer, /notification_alert_webhook_alerts_total/, "Notification worker must expose alert webhook metrics.");
  assertMatch(workerJobsServer, /backup_restore_last_success_age_seconds/, "Jobs worker must expose backup/restore freshness metrics.");
  assertMatch(observabilitySource, /FASTIFY_LOG_REDACTION_PATHS[\s\S]*authorization[\s\S]*set-cookie/, "Shared observability package must define sensitive Fastify redaction paths.");
  assertMatch(observabilitySource, /function redactLogValue[\s\S]*isSensitiveLogKey/, "Shared observability package must recursively redact sensitive log fields.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /FASTIFY_LOG_REDACTION_PATHS[\s\S]*LOG_REDACTION_CENSOR/, "Backend must use the shared log redaction policy.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /base:[\s\S]*service:[\s\S]*enterprise-backend/, "Backend logs must include a stable service field.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /formatters:[\s\S]*level\(label\)[\s\S]*return \{ level: label \}/, "Backend log levels must be text labels for Loki queries.");
  assertMatch(workerJobsServer, /createJsonLogger\(serviceName\)/, "Jobs worker must use the shared redacting JSON logger.");
  assertMatch(workerNotificationsServer, /createJsonLogger\(serviceName\)/, "Notifications worker must use the shared redacting JSON logger.");
  assertMatch(backendConfig, /apiDocsEnabled.*isProduction \? "false" : "true"/, "API docs must default off in production.");
  assertMatch(backendConfig, /SESSION_SIGNING_KEYS/, "Session signing key-ring support must be configured.");
  assertMatch(backendConfig, /sensitiveActionFallbackRateLimitMax/, "Sensitive action degraded rate limit budget must be configured.");
  assertMatch(backendConfig, /sessionTouchThrottleMs/, "Session touch throttling must be configurable.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /skipOnError:\s*false/, "Fastify rate-limit must fail closed instead of skipping on store errors.");
  assertMatch(backendRedisStore, /assertRequestRateAllowed/, "HTTP rate limiting must have a Redis-backed runtime guard.");
  assertMatch(backendRedisStore, /using fail-safe memory window/, "Redis rate-limit degradation must fall back to memory.");
  assertMatch(backendSessionAuth, /shouldPersistSessionTouch/, "Authenticated session touches must be throttled.");
  assertMatch(cryptoRuntime, /readPayloadKeyId/, "Session token verification must support key ids for rotation.");
  assertMatch(opsScript, /async function backupRestoreDrill/, "Ops script must provide an automated backup/restore drill.");
  assertMatch(opsScript, /function signBackupArtifact/, "Ops script must sign PostgreSQL backup artifacts.");
  assertMatch(opsScript, /function verifyBackupArtifact/, "Ops script must verify PostgreSQL backup signatures before restore.");
  assertMatch(opsScript, /verifyBackupArtifact\(backupFile\)/, "Restore paths must verify signed backup artifacts before pg_restore.");
  assertMatch(opsScript, /await backupRestoreDrill\(\)/, "Enterprise hardening audit must execute a backup/restore drill.");
  assertMatch(opsScript, /async function prunePostgresBackups/, "Ops script must provide backup artifact retention cleanup.");
  assertMatch(opsScript, /await prunePostgresBackups\(\{ dryRun: true \}\)/, "Enterprise hardening audit must dry-run backup artifact retention.");
  assertMatch(opsScript, /backup-restore-drill\.sh.*restore-drill\.log/s, "PostgreSQL cron installer must schedule restore drills.");
  assertMatch(opsScript, /prune-postgres-backups\.sh.*retention\.log/s, "PostgreSQL cron installer must schedule backup retention cleanup.");
  assertMatch(opsScript, /async function supplyChainHygiene/, "Ops script must provide a mandatory supply-chain gate.");
  assertMatch(opsScript, /await supplyChainHygiene\(\)/, "Enterprise hardening audit must execute the supply-chain gate.");
  assertMatch(opsScript, /async function faultInjectionTests/, "Ops script must provide fault-injection tests.");
  assertMatch(opsScript, /await faultInjectionTests\(\)/, "Enterprise hardening audit must execute fault-injection tests.");
  assertMatch(opsScript, /statement_timeout = '1ms'[\s\S]*pg_sleep/, "Fault-injection tests must exercise live PostgreSQL statement timeout.");
  assertMatch(opsScript, /async function loadProfile/, "Ops script must provide a sustained load profile command.");
  assertMatch(opsScript, /async function haConfigCheck/, "Ops script must provide an HA readiness gate.");
  assertMatch(opsScript, /async function managedSecretsPreflight/, "Ops script must provide a managed-secrets preflight.");
  assertMatch(opsScript, /async function releaseArtifactGate/, "Ops script must provide a release artifact admission gate.");
  assertMatch(opsScript, /async function drReadinessCheck/, "Ops script must provide a DR/PITR readiness gate.");
  assertMatch(opsScript, /async function securityMatrix/, "Ops script must provide a security test matrix gate.");
  assertMatch(opsScript, /async function chaosProfile/, "Ops script must provide an opt-in chaos profile.");
  assertMatch(opsScript, /async function governanceCheck/, "Ops script must provide a governance gate.");
  assertMatch(opsScript, /async function enterpriseTenCheck/, "Ops script must provide the combined enterprise 10 readiness gate.");
  assertMatch(opsScript, /Promise\.all\(Array\.from\(\{ length: workerCount \}/, "Load probes must issue real concurrent requests.");
  assertMatch(opsScript, /\/enterprise-infrastructure:ro/, "Disposable Linux source checks must mount infrastructure read-only for cross-repo hygiene gates.");
  assertMatch(sourcePackage, /"deps:supply-chain":\s+"node scripts\/supply-chain-gate\.mjs"/, "Root package must expose the supply-chain gate.");
  assertMatch(sourceSupplyChainGate, /"audit",\s+"--prod",\s+"--audit-level"/, "Supply-chain gate must run a production CVE audit.");
  assertMatch(sourceSupplyChainGate, /CycloneDX/, "Supply-chain gate must generate a CycloneDX SBOM.");
  assertMatch(sourceSupplyChainGate, /Denied or unknown production dependency licenses/, "Supply-chain gate must enforce a license policy.");
  assertMatch(sourceCiWorkflow, /pnpm deps:supply-chain/, "Enterprise CI must run the mandatory supply-chain gate.");
  assertMatch(sourceCiWorkflow, /pnpm-cyclonedx-sbom/, "Enterprise CI must upload the generated CycloneDX SBOM artifact.");
  assertMatch(opsScript, /operation = 'restore_test'[\s\S]*status = 'success'/, "Runtime checks must require a recorded successful restore_test run.");
  assertMatch(workerJobsServer, /AuditOutboxDispatcher/, "Worker jobs must run the durable audit outbox dispatcher.");
  assertMatch(workerJobsServer, /audit_outbox_rows/, "Worker jobs metrics must expose audit outbox lifecycle gauges.");
  assertMatch(workerJobsAuditOutboxStore, /for update skip locked/i, "Audit outbox dispatcher must use transaction-safe row claims.");
  assertMatch(workerJobsAuditOutboxStore, /status = 'dead'/, "Audit outbox dispatcher must support a dead-letter terminal state.");
  assertMatch(workerJobsNatsSink, /Idempotency-Key/, "Audit outbox delivery must publish an idempotency key.");
  assertNoMatch(webNextConfig, /Content-Security-Policy/, "Web CSP must be nonce-based middleware, not a static header.");
  if (fs.existsSync(path.join(sourceRoot, "apps", "web", "src", "middleware.ts"))) {
    fail("Web must use src/proxy.ts instead of src/middleware.ts.");
  }
  assertMatch(webProxy, /export function proxy/, "Web CSP proxy must export the Next.js proxy handler.");
  assertMatch(webProxy, /'nonce-\$\{nonce\}'/, "Web CSP must include a request nonce.");
  assertNoMatch(webProxy, /script-src[^\n`"]*unsafe-inline/, "Web script CSP must not allow unsafe-inline.");
  assertNoMatch(webProxy, /style-src[^\n`"]*unsafe-inline/, "Web style CSP must not allow unsafe-inline.");
  assertMatch(webProxy, /style-src-elem 'self' 'nonce-\$\{nonce\}'/, "Web CSP must nonce stylesheet elements.");
  assertMatch(webProxy, /style-src-attr 'none'/, "Web CSP must block style attributes.");
  assertNoMatch(browserUiSource, /style=\{/, "Browser UI source must not use React inline style props.");
  assertNoMatch(browserUiSource, /dangerouslySetInnerHTML/, "Browser UI source must not inject inline style/script blocks.");
  assertNoMatch(browserUiSource, /import\s*\{[^}]*\bmotion\b[^}]*\}\s*from\s*["']framer-motion["']/, "Browser UI source must not import Framer Motion DOM components because they write inline style attributes at runtime.");
  assertNoMatch(browserUiSource, /import\s+\*\s+as\s+motion\s+from\s*["']framer-motion["']/, "Browser UI source must not import Framer Motion DOM components because they write inline style attributes at runtime.");
  assertMatch(browserUiSource, /createDynamicCssRule/, "CSP-safe motion and scroll affordances must write dynamic geometry through stylesheet rules.");
  assertNoMatch(webSource, /container\.style\./, "Bot-protection widgets must not position themselves with CSP-blocked style attributes.");
  assertMatch(webSource, /sx-account-turnstile-container/, "Turnstile must use account-owned static CSS instead of inline styles.");
  for (const fallback of [webAppNotFound, webGlobalError]) {
    assertMatch(fallback, /SectionCard[\s\S]*className="ui-section"/, "Web fallback error surfaces must use CSP-safe UI package styles instead of Next inline styled defaults.");
  }
  assertNoMatch(webRememberModel, /JSON\.stringify\(accounts/, "Remembered accounts must not persist full profile objects in localStorage.");

  const rlsSql = readText(path.join(infraRoot, "postgres", "migrations", "005_row_level_security_hardening.sql"));
  const auditOutboxSql = readText(path.join(infraRoot, "postgres", "migrations", "007_durable_audit_outbox.sql"));
  const auditUnlinkSql = readText(path.join(infraRoot, "postgres", "migrations", "008_audit_account_unlink.sql"));
  const auditOutboxDispatcherSql = readText(path.join(infraRoot, "postgres", "migrations", "009_audit_outbox_dispatcher.sql"));
  assertMatch(rlsSql, /FORCE ROW LEVEL SECURITY/, "RLS hardening migration must force row-level security.");
  assertMatch(auditOutboxSql, /CREATE TABLE IF NOT EXISTS stexor_account\.audit_outbox/, "Audit outbox migration must create a durable queue.");
  assertMatch(auditOutboxSql, /FORCE ROW LEVEL SECURITY/, "Audit outbox must force row-level security.");
  assertMatch(auditUnlinkSql, /NEW\.account_id IS NULL/, "Audit append-only trigger must permit account_id unlink for cleanup/anonymization.");
  assertMatch(auditOutboxDispatcherSql, /'dead'/, "Audit outbox dispatcher migration must add dead-letter status.");
  assertMatch(auditOutboxDispatcherSql, /idx_audit_outbox_due_dispatch/, "Audit outbox dispatcher migration must add a due-dispatch index.");
  log("Static security checks passed.");
}

async function validateLocalSecrets() {
  const secretsDir = path.resolve(argv.secretsDir ?? path.join(infraRoot, "secrets"));
  const required = [
    "postgres_superuser_password",
    "app_db_password",
    "keycloak_db_password",
    "redis_password",
    "keycloak_admin_password",
    "nats_password",
    "minio_root_password",
    "grafana_admin_password",
    "session_secret",
    "session_signing_keys",
    "hash_pepper_keys",
    "backup_signing_keys",
    "smtp_password",
    "google_recaptcha_secret_key",
    "cloudflare_turnstile_secret_key",
    "google_oauth_client_secret",
    "database_url",
    "nats_url",
  ];
  for (const name of required) {
    const filePath = path.join(secretsDir, `${name}.txt`);
    if (!fs.existsSync(filePath)) {
      fail(`Missing local secret file: ${filePath}`);
    }
    const value = fs.readFileSync(filePath, "utf8").trim();
    if (!isUsableSecret(value)) {
      fail(`Invalid local secret value in ${filePath}`);
    }
  }
  for (const name of ["session_signing_keys", "hash_pepper_keys", "backup_signing_keys"]) {
    const keys = parseVersionedSecretKeys(fs.readFileSync(path.join(secretsDir, `${name}.txt`), "utf8"));
    if (!keys.length || keys.some((key) => key.secret.length < 48)) {
      fail(`Invalid versioned key ring in ${path.join(secretsDir, `${name}.txt`)}`);
    }
  }
  runSecretManager(["verify", "--secretsDir", secretsDir]);
  log("Local secrets validation passed.");
}

async function installPostgresBackupCron() {
  const backupAt = parseCronTime(argv.backupAt ?? argv.at ?? "03:15", "backupAt");
  const drillAt = parseCronTime(argv.drillAt ?? "04:15", "drillAt");
  const retentionAt = parseCronTime(argv.retentionAt ?? "05:15", "retentionAt");
  const drillWeekday = String(argv.drillWeekday ?? "0");
  if (!/^[0-7]$/.test(drillWeekday)) {
    fail("Use --drillWeekday 0-7, where 0/7 is Sunday.");
  }
  const cronRoot = argv.cronRoot ?? infraRoot;
  const backupLine = `${backupAt.minute} ${backupAt.hour} * * * cd ${shellQuote(cronRoot)} && sh ./scripts/backup-postgres.sh >> ./backups/postgres/backup.log 2>&1`;
  const drillLine = `${drillAt.minute} ${drillAt.hour} * * ${drillWeekday} cd ${shellQuote(cronRoot)} && sh ./scripts/backup-restore-drill.sh >> ./backups/postgres/drills/restore-drill.log 2>&1`;
  const retentionLine = `${retentionAt.minute} ${retentionAt.hour} * * * cd ${shellQuote(cronRoot)} && sh ./scripts/prune-postgres-backups.sh >> ./backups/postgres/retention.log 2>&1`;
  log("Add these lines to the production host crontab:");
  log(backupLine);
  log(drillLine);
  log(retentionLine);
}

async function accountIntegrationTests() {
  const apiBase = argv.apiBase ?? "https://api.localhost.com";
  log("==> Account integration tests");
  const signingKey = backendSessionSigningKey();

  const stamp = Date.now();
  const email = `integration+${stamp}@stexor.local`;
  const username = `integration_${stamp}`;
  const code = "184729";
  const signupChallengeId = `it_signup_${stamp}`;
  const loginChallengeId = `it_login_${stamp}`;
  const secondSignupChallengeId = `it_signup_second_${stamp}`;
  const redisPrefix = "stexor";
  let accountId = null;
  const createdAccountIds = [];

  try {
    const expiresAt = Date.now() + 8 * 60 * 1000;
    redisSetValue(`${redisPrefix}:otp:${signupChallengeId}`, JSON.stringify({
      id: signupChallengeId,
      purpose: "signup",
      destination: email,
      codeHash: backendSecretHash(code),
      expiresAt,
      attempts: 0,
    }), 480000);
    redisSetPlainValue(`${redisPrefix}:otp-verified:${signupChallengeId}`, "1", 480000);

    const register = await request("POST", `${apiBase}/account/bootstrap/register`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: {
        firstName: "Integration",
        lastName: "Test",
        email,
        username,
        dateOfBirth: "1990-01-01",
        challengeId: signupChallengeId,
        code,
      },
    });
    assertStatus(register, 200, "signup/register");
    accountId = register.json?.profile?.id;
    if (!accountId) {
      fail("signup/register did not return profile id.");
    }
    createdAccountIds.push(accountId);

    const sessionId = postgresOut("enterprise-postgres", "stexor_app", "postgres", `select s.id::text from stexor_account.sessions s join stexor_account.accounts a on a.id = s.account_id where a.external_id = ${sqlString(accountId)} and s.status = 'active' order by s.current_session desc, s.last_seen_at desc limit 1;`).trim();
    if (!sessionId) {
      fail("No active session created for integration account.");
    }
    const cookie = newSignedCookie(signingKey, accountId, sessionId);
    const authHeaders = { Cookie: cookie, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" };

    assertStatus(await request("GET", `${apiBase}/account/snapshot`, { headers: authHeaders }), 200, "snapshot");
    const accountsResponse = await request("GET", `${apiBase}/auth/accounts`, { headers: authHeaders });
    assertStatus(accountsResponse, 200, "account switcher accounts");
    const accountSwitchCookie = cookieFromHeaders(accountsResponse.headers, "stexor_account_switcher");
    if (!accountSwitchCookie) {
      fail("auth/accounts did not refresh account switch cookie.");
    }
    assertStatus(await request("POST", `${apiBase}/auth/switch-account`, {
      headers: { Cookie: `${cookie}; ${accountSwitchCookie}`, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" },
      body: { accountId },
    }), 200, "switch account");

    const profileBody = {
      username,
      firstName: "Integration",
      lastName: "Verified",
      email,
      dateOfBirth: "1990-01-01",
      language: "it-IT",
      country: "IT",
      avatarImage: null,
    };
    assertStatus(await request("PATCH", `${apiBase}/account/profile`, {
      headers: { Cookie: cookie, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "cross-site", "x-stexor-csrf": "1" },
      body: profileBody,
    }), 200, "trusted cross-site profile patch");
    assertStatus(await request("PATCH", `${apiBase}/account/profile`, {
      headers: { Cookie: cookie, Origin: "https://evil.example", "Sec-Fetch-Site": "cross-site", "x-stexor-csrf": "1" },
      body: { ...profileBody, firstName: "Blocked" },
    }), 403, "untrusted cross-site profile patch");

    const credentialId = crypto.randomBytes(16).toString("base64url");
    postgres("enterprise-postgres", "stexor_app", "postgres", `insert into stexor_account.passkeys (account_id, credential_id, public_key, counter, label, device_type, backed_up, transports) select id, ${sqlString(credentialId)}, decode(repeat('ab',32),'hex'), 0, 'Integration passkey', 'singleDevice', false, ARRAY['internal']::text[] from stexor_account.accounts where external_id = ${sqlString(accountId)} on conflict (credential_id) do nothing;`);
    const passkeyOptions = await request("POST", `${apiBase}/auth/login/passkey/options`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { email },
    });
    assertStatus(passkeyOptions, 200, "passkey login options");
    if (!passkeyOptions.json?.allowCredentials?.length) {
      fail("passkey login options did not include seeded passkey.");
    }

    const secondEmail = `integration.second+${stamp}@stexor.local`;
    const secondUsername = `int2_${stamp.toString(36)}`;
    redisSetValue(`${redisPrefix}:otp:${secondSignupChallengeId}`, JSON.stringify({
      id: secondSignupChallengeId,
      purpose: "signup",
      destination: secondEmail,
      codeHash: backendSecretHash(code),
      expiresAt,
      attempts: 0,
    }), 480000);
    redisSetPlainValue(`${redisPrefix}:otp-verified:${secondSignupChallengeId}`, "1", 480000);
    const secondRegister = await request("POST", `${apiBase}/account/bootstrap/register`, {
      headers: { Cookie: `${cookie}; ${accountSwitchCookie}`, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" },
      body: {
        firstName: "Integration",
        lastName: "Second",
        email: secondEmail,
        username: secondUsername,
        dateOfBirth: "1991-01-01",
        challengeId: secondSignupChallengeId,
        code,
      },
    });
    assertStatus(secondRegister, 200, "signup/register while another account is logged in");
    const secondAccountId = secondRegister.json?.profile?.id;
    if (!secondAccountId) {
      fail("second signup/register did not return profile id.");
    }
    createdAccountIds.push(secondAccountId);
    const secondCredentialId = crypto.randomBytes(16).toString("base64url");
    postgres("enterprise-postgres", "stexor_app", "postgres", `insert into stexor_account.passkeys (account_id, credential_id, public_key, counter, label, device_type, backed_up, transports) select id, ${sqlString(secondCredentialId)}, decode(repeat('cd',32),'hex'), 0, 'Integration second passkey', 'singleDevice', false, ARRAY['internal']::text[] from stexor_account.accounts where external_id = ${sqlString(secondAccountId)} on conflict (credential_id) do nothing;`);
    const crossAccountPasskeyOptions = await request("POST", `${apiBase}/auth/login/passkey/options`, {
      headers: { Cookie: cookie, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" },
      body: { email: secondEmail },
    });
    assertStatus(crossAccountPasskeyOptions, 200, "passkey login options for added account while current account cookie exists");
    const crossAccountCredentialIds = (crossAccountPasskeyOptions.json?.allowCredentials ?? []).map((credential) => credential.id);
    if (!crossAccountCredentialIds.includes(secondCredentialId) || crossAccountCredentialIds.includes(credentialId)) {
      fail("passkey login options for added account resolved the current account instead of the requested account.");
    }

    redisSetValue(`${redisPrefix}:otp:${loginChallengeId}`, JSON.stringify({
      id: loginChallengeId,
      purpose: "login",
      destination: email,
      codeHash: backendSecretHash(code),
      expiresAt,
      attempts: 0,
    }), 480000);
    assertStatus(await request("POST", `${apiBase}/account/bootstrap/email-otp/verify`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { challengeId: loginChallengeId, code, email },
    }), 200, "email OTP login verify");

    const backupRotate = await request("POST", `${apiBase}/account/backup-codes/rotate`, { headers: authHeaders });
    assertStatus(backupRotate, 200, "backup code rotate");
    const backupCode = backupRotate.json?.codes?.[0];
    const recoveryBackupCode = backupRotate.json?.codes?.[1];
    assertStatus(await request("POST", `${apiBase}/account/backup-codes/verify`, {
      headers: authHeaders,
      body: { code: backupCode },
    }), 200, "backup code verify");
    assertStatus(await request("POST", `${apiBase}/account/backup-codes/verify`, {
      headers: authHeaders,
      body: { code: backupCode },
    }), 400, "backup code one-time reuse block");
    assertStatus(await request("POST", `${apiBase}/auth/login/recovery/verify`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { email, method: "backup_code", code: recoveryBackupCode },
    }), 200, "backup code recovery login verify");
    assertStatus(await request("POST", `${apiBase}/auth/login/recovery/verify`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { email, method: "backup_code", code: recoveryBackupCode },
    }), 400, "backup code recovery one-time reuse block");

    const extraSessionId = crypto.randomUUID();
    postgres("enterprise-postgres", "stexor_app", "postgres", `insert into stexor_account.sessions (id, account_id, device, browser, trusted, current_session, auth_method, status, created_at, last_seen_at, expires_at) select ${sqlString(extraSessionId)}::uuid, id, 'Integration second device', 'Curl', true, false, 'integration', 'active', now(), now(), now() + interval '10 years' from stexor_account.accounts where external_id = ${sqlString(accountId)};`);
    assertStatus(await request("DELETE", `${apiBase}/account/sessions/${extraSessionId}`, { headers: authHeaders }), 200, "session revocation");
    const revokedSessionStatus = postgresOut("enterprise-postgres", "stexor_app", "postgres", `select status from stexor_account.sessions where id = ${sqlString(extraSessionId)}::uuid;`).trim();
    if (revokedSessionStatus !== "revoked") {
      fail("session revocation did not persist revoked status.");
    }
    log("Account integration tests passed.");
  } finally {
    redisDelete([
      `${redisPrefix}:otp:${signupChallengeId}`,
      `${redisPrefix}:otp-verified:${signupChallengeId}`,
      `${redisPrefix}:otp:${loginChallengeId}`,
      `${redisPrefix}:otp:${secondSignupChallengeId}`,
      `${redisPrefix}:otp-verified:${secondSignupChallengeId}`,
    ]);
    for (const id of createdAccountIds.reverse()) {
      postgres("enterprise-postgres", "stexor_app", "postgres", `delete from stexor_account.accounts where external_id = ${sqlString(id)};`, { allowFailure: true, capture: true });
    }
  }
}

function help() {
  log(`Usage: node scripts/stexor-ops.mjs <command> [--key value]

Commands:
  access-review
  account-integration-tests
  apply-postgres-migrations
  backup-restore-drill
  backup-postgres
  browser-e2e-tests
  certificate-expiry-check
  chaos-profile
  dependency-hygiene
  dr-readiness-check
  enterprise-check
  enterprise-hardening-audit
  enterprise-10-check
  fault-injection-tests
  generate-sbom
  governance-check
  ha-config-check
  init-local-secrets
  install-postgres-backup-cron
  local-secret-manager
  load-profile
  load-smoke
  maintainability-hygiene
  managed-secrets-preflight
  offsite-backup-restic
  performance-hygiene
  prune-postgres-backups
  production-preflight
  release-artifact-gate
  restore-postgres
  restore-test-postgres
  secret-scan
  secret-manager
  security-matrix
  security-smoke
  sign-existing-postgres-backups
  sign-images
  static-security-check
  supply-chain-hygiene
  testing-hygiene
  validate-local-secrets`);
}

const commands = {
  "access-review": accessReview,
  "account-integration-tests": accountIntegrationTests,
  "apply-postgres-migrations": applyPostgresMigrations,
  "backup-restore-drill": backupRestoreDrill,
  "backup-postgres": backupPostgres,
  "browser-e2e-tests": browserE2eTests,
  "certificate-expiry-check": certificateExpiryCheck,
  "chaos-profile": chaosProfile,
  "dependency-hygiene": dependencyHygiene,
  "dr-readiness-check": drReadinessCheck,
  "enterprise-check": enterpriseCheck,
  "enterprise-hardening-audit": enterpriseHardeningAudit,
  "enterprise-10-check": enterpriseTenCheck,
  "fault-injection-tests": faultInjectionTests,
  "generate-sbom": generateSbom,
  "governance-check": governanceCheck,
  "ha-config-check": haConfigCheck,
  "init-local-secrets": initLocalSecrets,
  "install-postgres-backup-cron": installPostgresBackupCron,
  "local-secret-manager": localSecretManager,
  "load-profile": loadProfile,
  "load-smoke": loadSmoke,
  "maintainability-hygiene": maintainabilityHygiene,
  "managed-secrets-preflight": managedSecretsPreflight,
  "offsite-backup-restic": offsiteBackupRestic,
  "performance-hygiene": performanceHygiene,
  "prune-postgres-backups": prunePostgresBackups,
  "production-preflight": productionPreflight,
  "release-artifact-gate": releaseArtifactGate,
  "restore-postgres": restorePostgres,
  "restore-test-postgres": restoreTestPostgres,
  "secret-scan": secretScan,
  "secret-manager": secretManager,
  "security-matrix": securityMatrix,
  "security-smoke": securitySmoke,
  "sign-existing-postgres-backups": signExistingPostgresBackups,
  "sign-images": signImages,
  "static-security-check": staticSecurityCheck,
  "supply-chain-hygiene": supplyChainHygiene,
  "testing-hygiene": testingHygiene,
  "validate-local-secrets": validateLocalSecrets,
  help,
};

try {
  if (!commands[command]) {
    help();
    fail(`Unknown command: ${command}`);
  }
  await commands[command]();
} catch (error) {
  process.stderr.write(`${error.message ?? error}\n`);
  process.exitCode = 1;
}
