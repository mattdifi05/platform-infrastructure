#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const infraRoot = path.resolve(scriptDir, "..");
const command = process.argv[2] ?? "help";
const argv = parseArgs(process.argv.slice(3));

const requiredSecrets = [
  { name: "postgres_superuser_password", env: "POSTGRES_SUPERUSER_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "app_db_password", env: "APP_DB_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "keycloak_db_password", env: "KEYCLOAK_DB_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "redis_password", env: "REDIS_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90 },
  { name: "keycloak_admin_password", env: "KEYCLOAK_ADMIN_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90 },
  { name: "nats_password", env: "NATS_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "minio_root_password", env: "MINIO_ROOT_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90 },
  { name: "grafana_admin_password", env: "GRAFANA_ADMIN_PASSWORD", kind: "raw", bytes: 36, rotationDays: 90 },
  { name: "session_secret", env: "SESSION_SECRET", kind: "raw", bytes: 48, rotationDays: 90 },
  { name: "session_signing_keys", env: "SESSION_SIGNING_KEYS", kind: "keyring", bytes: 48, keyPrefix: "s", rotationDays: 60 },
  { name: "hash_pepper_keys", env: "SECRET_HASH_KEYS", kind: "keyring", bytes: 48, keyPrefix: "h", rotationDays: 90 },
  { name: "backup_signing_keys", env: "BACKUP_SIGNING_KEYS", kind: "keyring", bytes: 48, keyPrefix: "b", rotationDays: 90 },
  { name: "alertmanager_webhook_token", env: "ALERTMANAGER_WEBHOOK_TOKEN", kind: "raw", bytes: 48, rotationDays: 90 },
  { name: "smtp_password", env: "SMTP_PASSWORD", kind: "raw", bytes: 36, minLength: 8, rotationDays: 90 },
  { name: "google_recaptcha_secret_key", env: "GOOGLE_RECAPTCHA_SECRET_KEY", kind: "raw", bytes: 36, minLength: 8, rotationDays: 90, manualRotation: true },
  { name: "cloudflare_turnstile_secret_key", env: "CLOUDFLARE_TURNSTILE_SECRET_KEY", kind: "raw", bytes: 36, minLength: 8, rotationDays: 90, manualRotation: true },
  { name: "google_oauth_client_secret", env: "GOOGLE_OAUTH_CLIENT_SECRET", kind: "raw", bytes: 36, minLength: 8, rotationDays: 90, manualRotation: true },
  { name: "database_url", kind: "derived", rotationDays: 90 },
  { name: "nats_url", kind: "derived", rotationDays: 90 },
];

const requiredByName = new Map(requiredSecrets.map((secret) => [secret.name, secret]));

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

function booleanFlag(value) {
  return value === true || value === "true" || value === "1" || value === "yes";
}

function secretsDir() {
  return path.resolve(argv.secretsDir ?? path.join(infraRoot, "secrets"));
}

function envFile() {
  return path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
}

function storePath() {
  return path.resolve(argv.store ?? path.join(secretsDir(), "stexor-secret-manager-store.json"));
}

function masterKeyPath() {
  return path.resolve(argv.masterKey ?? path.join(secretsDir(), "stexor-secret-manager-master.key"));
}

function auditLogPath() {
  return path.resolve(argv.auditLog ?? path.join(secretsDir(), "stexor-secret-manager-audit.log"));
}

function secretFilePath(name) {
  return path.join(secretsDir(), `${name}.txt`);
}

function randomSecret(bytes = 36) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function secretId(prefix) {
  return `${prefix}${new Date().toISOString().replace(/\D/g, "").slice(0, 14)}`;
}

function isUsableSecret(value) {
  return Boolean(value && !/change_me|your-domain|placeholder|managed_by_local_secret_file/i.test(value));
}

function readFileIfExists(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const value = fs.readFileSync(filePath, "utf8").trim();
  return value || null;
}

function writePrivateFile(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value, "utf8");
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Best effort on platforms without POSIX permissions.
  }
}

function parseEnv(filePath) {
  const env = {};
  if (!fs.existsSync(filePath)) return env;
  for (const rawLine of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const index = line.indexOf("=");
    const key = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim().replace(/^["']|["']$/g, "");
    env[key] = value;
  }
  return env;
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
      return /^[A-Za-z0-9_-]{1,32}$/.test(id) && secret ? { id, secret } : null;
    })
    .filter(Boolean);
}

function keyringValue(prefix, bytes = 48) {
  return `${secretId(prefix)}=${randomSecret(bytes)}`;
}

function fingerprint(value) {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function masterKey() {
  fs.mkdirSync(secretsDir(), { recursive: true });
  const existing = readFileIfExists(masterKeyPath());
  if (existing) return existing;
  const value = `smk_${randomSecret(64)}`;
  writePrivateFile(masterKeyPath(), `${value}\n`);
  return value;
}

function encryptionKey(master) {
  return crypto.createHash("sha256").update(`stexor-secret-manager-v1:${master}`).digest();
}

function encryptSecret(master, name, value) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(`stexor-secret:${name}`, "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(master), iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    algorithm: "AES-256-GCM",
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
}

function decryptSecret(master, name, encrypted) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(master), Buffer.from(encrypted.iv, "base64url"));
  decipher.setAAD(Buffer.from(`stexor-secret:${name}`, "utf8"));
  decipher.setAuthTag(Buffer.from(encrypted.tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

function readStore() {
  if (!fs.existsSync(storePath())) return null;
  return JSON.parse(fs.readFileSync(storePath(), "utf8").replace(/^\uFEFF/, ""));
}

function decryptStoreValues(store = readStore()) {
  if (!store) return {};
  if (store.manager !== "stexor-secret-manager" || store.version !== 1 || !store.secrets) {
    fail("Secret manager store has an invalid format.");
  }
  const key = masterKey();
  const values = {};
  for (const [name, record] of Object.entries(store.secrets)) {
    values[name] = decryptSecret(key, name, record.encryption);
  }
  return values;
}

function writeStore(values, previousStore = readStore()) {
  const key = masterKey();
  const now = new Date().toISOString();
  const previousRecords = previousStore?.secrets ?? {};
  const records = {};
  for (const spec of requiredSecrets) {
    const value = values[spec.name];
    if (!value) continue;
    const keyIds = spec.kind === "keyring" ? parseVersionedSecretKeys(value).map((entry) => entry.id) : undefined;
    records[spec.name] = {
      kind: spec.kind,
      owner: "platform",
      rotationDays: spec.rotationDays,
      materializeTo: `secrets/${spec.name}.txt`,
      updatedAt: previousRecords[spec.name]?.fingerprint === fingerprint(value) ? previousRecords[spec.name].updatedAt : now,
      fingerprint: fingerprint(value),
      keyIds,
      encryption: encryptSecret(key, spec.name, value),
    };
  }
  const store = {
    version: 1,
    manager: "stexor-secret-manager",
    createdAt: previousStore?.createdAt ?? now,
    updatedAt: now,
    secrets: records,
  };
  writePrivateFile(storePath(), `${JSON.stringify(store, null, 2)}\n`);
  return store;
}

function audit(action, details = {}) {
  const entry = {
    at: new Date().toISOString(),
    action,
    actor: (() => {
      try {
        return os.userInfo().username;
      } catch {
        return "unknown";
      }
    })(),
    host: os.hostname(),
    status: "success",
    ...details,
  };
  fs.mkdirSync(path.dirname(auditLogPath()), { recursive: true });
  fs.appendFileSync(auditLogPath(), `${JSON.stringify(entry)}\n`, "utf8");
}

function materializedOrEnv(spec, env) {
  const existing = readFileIfExists(secretFilePath(spec.name));
  if (spec.kind === "keyring") {
    if (isUsableSecret(existing) && parseVersionedSecretKeys(existing).every((key) => key.secret.length >= 48)) return existing;
    if (spec.env && isUsableSecret(env[spec.env]) && parseVersionedSecretKeys(env[spec.env]).every((key) => key.secret.length >= 48)) return env[spec.env];
  } else if (spec.kind === "raw") {
    const minLength = spec.minLength ?? Math.min(spec.bytes, 24);
    if (isUsableSecret(existing) && existing.length >= minLength) return existing;
    if (spec.env && isUsableSecret(env[spec.env]) && env[spec.env].length >= minLength) return env[spec.env];
  } else if (isUsableSecret(existing)) {
    return existing;
  }
  if (spec.kind === "keyring") return keyringValue(spec.keyPrefix, spec.bytes);
  if (spec.kind === "raw") return randomSecret(spec.bytes);
  return null;
}

function buildValues(existingValues = {}) {
  const env = parseEnv(envFile());
  const values = {};
  for (const spec of requiredSecrets) {
    if (existingValues[spec.name]) {
      values[spec.name] = existingValues[spec.name];
      continue;
    }
    values[spec.name] = materializedOrEnv(spec, env);
  }
  const appDbUser = env.APP_DB_USER || "stexor_app_user";
  const appDbName = env.APP_DB_NAME || "stexor_app";
  const natsUser = env.NATS_USER || "stexor";
  values.database_url ||= `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(values.app_db_password)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  values.nats_url ||= `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(values.nats_password)}@nats:4222`;
  return values;
}

function validateValues(values) {
  for (const spec of requiredSecrets) {
    const value = values[spec.name];
    if (!isUsableSecret(value)) {
      fail(`Missing or invalid secret: ${spec.name}`);
    }
    if (spec.kind === "keyring") {
      const keys = parseVersionedSecretKeys(value);
      if (!keys.length || keys.some((key) => key.secret.length < 48)) {
        fail(`Invalid keyring secret: ${spec.name}`);
      }
    } else if (spec.kind === "raw" && value.length < (spec.minLength ?? Math.min(spec.bytes, 24))) {
      fail(`Secret ${spec.name} is too short.`);
    }
  }
}

function materialize(values = decryptStoreValues()) {
  validateValues(values);
  for (const spec of requiredSecrets) {
    writePrivateFile(secretFilePath(spec.name), `${values[spec.name]}\n`);
  }
  audit("materialize", { names: requiredSecrets.map((secret) => secret.name) });
  log(`Materialized ${requiredSecrets.length} Docker secret files in ${secretsDir()}`);
}

async function init() {
  const force = booleanFlag(argv.force);
  const previousStore = force ? null : readStore();
  const previousValues = previousStore ? decryptStoreValues(previousStore) : {};
  const values = buildValues(previousValues);
  validateValues(values);
  const store = writeStore(values, previousStore);
  materialize(values);
  audit("init", {
    store: storePath(),
    names: Object.keys(store.secrets),
  });
  log(`Stexor Secret Manager initialized at ${storePath()}`);
}

async function verify() {
  const store = readStore();
  if (!store) fail(`Missing Stexor Secret Manager store: ${storePath()}`);
  const values = decryptStoreValues(store);
  validateValues(values);
  for (const spec of requiredSecrets) {
    const materialized = readFileIfExists(secretFilePath(spec.name));
    if (!materialized) fail(`Missing materialized Docker secret: ${secretFilePath(spec.name)}`);
    if (!timingSafeEqual(Buffer.from(materialized), Buffer.from(values[spec.name]))) {
      fail(`Materialized secret does not match manager store: ${spec.name}`);
    }
  }
  audit("verify", { names: requiredSecrets.map((secret) => secret.name) });
  log("Stexor Secret Manager verification passed.");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function status() {
  const store = readStore();
  if (!store) fail(`Missing Stexor Secret Manager store: ${storePath()}`);
  log(`Store: ${storePath()}`);
  log(`Updated: ${store.updatedAt}`);
  for (const spec of requiredSecrets) {
    const record = store.secrets?.[spec.name];
    if (!record) {
      log(`${spec.name}: missing`);
      continue;
    }
    const keyIds = record.keyIds?.length ? ` keyIds=${record.keyIds.join(",")}` : "";
    log(`${spec.name}: kind=${record.kind} updatedAt=${record.updatedAt} fingerprint=${record.fingerprint}${keyIds}`);
  }
}

async function rotate() {
  const name = argv.name ?? argv._[0];
  if (!name) fail("Use rotate --name <secret_name>.");
  const spec = requiredByName.get(name);
  if (!spec) fail(`Unknown secret: ${name}`);
  if (spec.manualRotation && !booleanFlag(argv.force)) {
    fail(`${name} requires coordinated service-side rotation. Re-run with --force only after updating the dependent service.`);
  }
  const store = readStore();
  if (!store) fail(`Missing Stexor Secret Manager store: ${storePath()}`);
  const values = decryptStoreValues(store);
  const keep = Number(argv.keep ?? 3);
  if (spec.kind === "keyring") {
    const previous = parseVersionedSecretKeys(values[name]);
    values[name] = [
      keyringValue(spec.keyPrefix, spec.bytes),
      ...previous.map((key) => `${key.id}=${key.secret}`),
    ].slice(0, keep).join(",");
  } else if (spec.kind === "raw") {
    values[name] = randomSecret(spec.bytes);
  } else {
    fail(`${name} is derived and cannot be rotated directly.`);
  }
  if (name === "app_db_password") {
    const env = parseEnv(envFile());
    const appDbUser = env.APP_DB_USER || "stexor_app_user";
    const appDbName = env.APP_DB_NAME || "stexor_app";
    values.database_url = `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(values.app_db_password)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  }
  if (name === "nats_password") {
    const env = parseEnv(envFile());
    const natsUser = env.NATS_USER || "stexor";
    values.nats_url = `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(values.nats_password)}@nats:4222`;
  }
  validateValues(values);
  writeStore(values, store);
  materialize(values);
  audit("rotate", { name, keep });
  log(`Rotated ${name}. Recreate dependent containers after reviewing the rollout window.`);
}

function readSecretInput(spec) {
  const valueFile = argv.valueFile ?? argv["value-file"] ?? argv.file;
  const valueEnv = argv.valueEnv ?? argv["value-env"] ?? argv.env;
  if (valueFile) {
    const value = readFileIfExists(path.resolve(valueFile));
    if (!value) fail(`Secret value file is empty or unreadable: ${valueFile}`);
    return value;
  }
  if (valueEnv) {
    const value = process.env[String(valueEnv)];
    if (!value) fail(`Environment variable ${valueEnv} is empty.`);
    return value.trim();
  }
  if (booleanFlag(argv.stdin)) {
    const value = fs.readFileSync(0, "utf8").trim();
    if (!value) fail("No secret value received on stdin.");
    return value;
  }
  if (argv.value) {
    return String(argv.value).trim();
  }
  fail(`Use set --name ${spec.name} with --value-file, --value-env, --stdin, or --value.`);
}

async function setSecret() {
  const name = argv.name ?? argv._[0];
  if (!name) fail("Use set --name <secret_name>.");
  const spec = requiredByName.get(name);
  if (!spec) fail(`Unknown secret: ${name}`);
  if (spec.kind === "derived") fail(`${name} is derived and cannot be set directly.`);

  const store = readStore();
  const values = buildValues(store ? decryptStoreValues(store) : {});
  values[name] = readSecretInput(spec);
  if (name === "app_db_password") {
    const env = parseEnv(envFile());
    const appDbUser = env.APP_DB_USER || "stexor_app_user";
    const appDbName = env.APP_DB_NAME || "stexor_app";
    values.database_url = `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(values.app_db_password)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  }
  if (name === "nats_password") {
    const env = parseEnv(envFile());
    const natsUser = env.NATS_USER || "stexor";
    values.nats_url = `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(values.nats_password)}@nats:4222`;
  }
  validateValues(values);
  writeStore(values, store);
  materialize(values);
  audit("set", { name });
  log(`Updated ${name} in Stexor Secret Manager and materialized Docker secret files.`);
}

function help() {
  log(`Usage: node scripts/stexor-secret-manager.mjs <command> [--key value]

Commands:
  init                 Create/update the encrypted store and materialize Docker secret files.
  materialize          Decrypt the store into secrets/*.txt for compose.secrets.yaml.
  rotate --name <name> Rotate a keyring or safe raw secret, then materialize.
  set --name <name>    Import or replace a secret from --value-file, --value-env, or --stdin.
  status               Print metadata and fingerprints without secret values.
  verify               Validate encrypted store and materialized Docker secret files.
`);
}

const commands = {
  help,
  init,
  materialize: async () => materialize(),
  rotate,
  set: setSecret,
  status,
  verify,
};

try {
  if (!commands[command]) {
    help();
    fail(`Unknown command: ${command}`);
  }
  await commands[command]();
} catch (error) {
  try {
    audit(command, { status: "failed", error: String(error?.message ?? error) });
  } catch {
    // Preserve the original failure.
  }
  process.stderr.write(`${error.message ?? error}\n`);
  process.exitCode = 1;
}
