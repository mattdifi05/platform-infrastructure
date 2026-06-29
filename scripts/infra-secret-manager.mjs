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
  { name: "postgres_superuser_password", kind: "opaque", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "app_db_password", kind: "opaque", bytes: 36, rotationDays: 90, manualRotation: true, fileMode: 0o640 },
  { name: "keycloak_db_password", kind: "opaque", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "redis_password", kind: "opaque", bytes: 36, rotationDays: 90 },
  { name: "keycloak_admin_password", kind: "opaque", bytes: 36, rotationDays: 90 },
  { name: "nats_password", kind: "opaque", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "minio_root_password", kind: "opaque", bytes: 36, rotationDays: 90 },
  { name: "mariadb_root_password", kind: "opaque", bytes: 36, rotationDays: 90, manualRotation: true },
  { name: "phpmyadmin_control_password", kind: "opaque", bytes: 36, rotationDays: 90 },
  { name: "grafana_admin_password", kind: "opaque", bytes: 36, rotationDays: 90 },
  { name: "session_secret", kind: "opaque", bytes: 48, rotationDays: 90 },
  { name: "session_signing_keys", kind: "keyring", bytes: 48, keyPrefix: "s", rotationDays: 60 },
  { name: "projects_gateway_signing_keys", kind: "keyring", bytes: 48, keyPrefix: "p", rotationDays: 90 },
  { name: "hash_pepper_keys", kind: "keyring", bytes: 48, keyPrefix: "h", rotationDays: 90 },
  { name: "backup_signing_keys", kind: "keyring", bytes: 48, keyPrefix: "b", rotationDays: 90 },
  { name: "alertmanager_webhook_token", kind: "opaque", bytes: 48, rotationDays: 90 },
  { name: "smtp_password", kind: "opaque", bytes: 36, minLength: 8, rotationDays: 90 },
  { name: "cloudflare_turnstile_secret_key", kind: "opaque", bytes: 36, minLength: 8, rotationDays: 90, manualRotation: true },
  { name: "database_url", kind: "derived", rotationDays: 90 },
  { name: "nats_url", kind: "derived", rotationDays: 90 },
];

const requiredByName = new Map(requiredSecrets.map((secret) => [secret.name, secret]));
const requiredSecretOrder = new Map(requiredSecrets.map((secret, index) => [secret.name, index]));
const secretNamePattern = /^[a-z][a-z0-9_]{1,80}$/;
const ownerPattern = /^[A-Za-z0-9_.:@/-]{1,80}$/;

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
  return path.resolve(argv.store ?? path.join(secretsDir(), "infra-secret-manager-store.json"));
}

function masterKeyPath() {
  return path.resolve(argv.masterKey ?? path.join(secretsDir(), "infra-secret-manager-master.key"));
}

function auditLogPath() {
  return path.resolve(argv.auditLog ?? path.join(secretsDir(), "infra-secret-manager-audit.log"));
}

function secretFilePath(name) {
  return path.join(secretsDir(), `${name}.txt`);
}

function validateSecretName(name) {
  const normalized = String(name ?? "");
  if (!secretNamePattern.test(normalized)) {
    fail("Secret name must start with a lowercase letter and contain only lowercase letters, numbers and underscores.");
  }
  return normalized;
}

function positiveInteger(value, fallback, label) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) fail(`${label} must be a positive integer.`);
  return parsed;
}

function secretOwner(value, fallback = "vault") {
  const owner = String(value ?? fallback).trim() || fallback;
  if (!ownerPattern.test(owner)) {
    fail("Secret owner may contain only letters, numbers, dot, underscore, dash, colon, slash and at sign.");
  }
  return owner;
}

function vaultSpec(name, previousRecord = {}, overrides = {}) {
  const normalized = validateSecretName(name);
  return {
    name: normalized,
    kind: "opaque",
    bytes: positiveInteger(overrides.bytes ?? previousRecord.bytes, 48, "bytes"),
    minLength: positiveInteger(overrides.minLength ?? overrides["min-length"] ?? previousRecord.minLength, 1, "minLength"),
    owner: secretOwner(overrides.owner ?? previousRecord.owner, "vault"),
    rotationDays: positiveInteger(overrides.rotationDays ?? overrides["rotation-days"] ?? previousRecord.rotationDays, 90, "rotationDays"),
    materializeTo: `secrets/${normalized}.txt`,
    vault: true,
  };
}

function secretSpec(name, previousRecords = {}, overrides = {}) {
  const normalized = validateSecretName(name);
  return requiredByName.get(normalized) ?? vaultSpec(normalized, previousRecords[normalized], overrides);
}

function orderedSecretNames(values = {}, previousRecords = {}) {
  const names = new Set([...Object.keys(previousRecords), ...Object.keys(values)]);
  for (const spec of requiredSecrets) names.add(spec.name);
  return [...names]
    .filter((name) => {
      validateSecretName(name);
      return values[name] !== undefined && values[name] !== null && String(values[name]).length > 0;
    })
    .sort((a, b) => {
      const aRequired = requiredSecretOrder.has(a);
      const bRequired = requiredSecretOrder.has(b);
      if (aRequired && bRequired) return requiredSecretOrder.get(a) - requiredSecretOrder.get(b);
      if (aRequired) return -1;
      if (bRequired) return 1;
      return a.localeCompare(b);
    });
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

function writePrivateFile(filePath, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value, "utf8");
  try {
    fs.chmodSync(filePath, mode);
  } catch {
    // Best effort on platforms without POSIX permissions.
  }
}

function parseEnv(filePath) {
  const env = {};
  if (!fs.existsSync(filePath)) return env;
  for (const sourceLine of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const line = sourceLine.trim();
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

function kmsKeyId() {
  return `kek_${new Date().toISOString().replace(/\D/g, "").slice(0, 14)}_${randomSecret(9)}`;
}

function kmsRootFingerprint(master) {
  return crypto.createHash("sha256").update(`local-bucket-kms-root:${master}`).digest("hex").slice(0, 24);
}

function normalizeKmsMetadata(previousStore) {
  const now = new Date().toISOString();
  const rootFingerprint = kmsRootFingerprint(masterKey());
  if (previousStore?.kms?.provider === "local-bucket-kms" && previousStore.kms.activeKeyId && previousStore.kms.keys?.[previousStore.kms.activeKeyId]) {
    return {
      ...previousStore.kms,
      rootFingerprint,
      keys: previousStore.kms.keys,
    };
  }
  const activeKeyId = kmsKeyId();
  return {
    provider: "local-bucket-kms",
    version: 1,
    algorithm: "HKDF-SHA256+A256GCM",
    activeKeyId,
    rootFingerprint,
    createdAt: previousStore?.createdAt ?? now,
    updatedAt: now,
    keys: {
      [activeKeyId]: {
        createdAt: now,
        status: "active",
        rootFingerprint,
      },
    },
  };
}

function masterKey() {
  fs.mkdirSync(secretsDir(), { recursive: true });
  const existing = readFileIfExists(masterKeyPath());
  if (existing) return existing;
  const value = `smk_${randomSecret(64)}`;
  writePrivateFile(masterKeyPath(), `${value}\n`);
  return value;
}

function encryptionKey(master, keyId) {
  if (!keyId) {
    return crypto.createHash("sha256").update(`infra-secret-manager-v1:${master}`).digest();
  }
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    Buffer.from(master),
    Buffer.from("local-bucket-kms-v1", "utf8"),
    Buffer.from(`secret-store:${keyId}`, "utf8"),
    32,
  ));
}

function encryptSecret(master, name, value, keyId) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(`platform-secret:${name}:kms:${keyId ?? "legacy"}`, "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(master, keyId), iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    algorithm: "AES-256-GCM",
    provider: keyId ? "local-bucket-kms" : "legacy-local-master-key",
    keyId,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
}

function decryptSecret(master, name, encrypted) {
  const keyId = encrypted.keyId;
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(master, keyId), Buffer.from(encrypted.iv, "base64url"));
  const aad = keyId ? `platform-secret:${name}:kms:${keyId}` : `platform-secret:${name}`;
  decipher.setAAD(Buffer.from(aad, "utf8"));
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
  if (store.manager !== "infra-secret-manager" || store.version !== 1 || !store.secrets) {
    fail("Secret manager store has an invalid format.");
  }
  const key = masterKey();
  const values = {};
  for (const [name, record] of Object.entries(store.secrets)) {
    validateSecretName(name);
    values[name] = decryptSecret(key, name, record.encryption);
  }
  return values;
}

function writeStore(values, previousStore = readStore(), kmsOverride = null, specOverrides = {}) {
  const key = masterKey();
  const now = new Date().toISOString();
  const kms = kmsOverride ?? normalizeKmsMetadata(previousStore);
  const previousRecords = previousStore?.secrets ?? {};
  const records = {};
  for (const name of orderedSecretNames(values, previousRecords)) {
    const spec = secretSpec(name, previousRecords, specOverrides[name]);
    const value = values[name];
    if (!value) continue;
    const previousRecord = previousRecords[name] ?? {};
    const keyIds = spec.kind === "keyring" ? parseVersionedSecretKeys(value).map((entry) => entry.id) : undefined;
    records[name] = {
      kind: spec.kind,
      owner: spec.owner ?? "platform",
      rotationDays: spec.rotationDays,
      materializeTo: spec.materializeTo ?? `secrets/${name}.txt`,
      updatedAt: previousRecord.fingerprint === fingerprint(value) ? previousRecord.updatedAt : now,
      fingerprint: fingerprint(value),
      keyIds,
      ...(spec.vault ? { minLength: spec.minLength, scope: "vault" } : { scope: "platform" }),
      encryption: encryptSecret(key, name, value, kms.activeKeyId),
    };
  }
  const store = {
    version: 1,
    manager: "infra-secret-manager",
    createdAt: previousStore?.createdAt ?? now,
    updatedAt: now,
    kms: {
      ...kms,
      updatedAt: now,
    },
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

function materializedOrGenerated(spec) {
  const existing = readFileIfExists(secretFilePath(spec.name));
  if (spec.kind === "keyring") {
    if (isUsableSecret(existing) && parseVersionedSecretKeys(existing).every((key) => key.secret.length >= 48)) return existing;
  } else if (spec.kind === "opaque") {
    const minLength = spec.minLength ?? Math.min(spec.bytes, 24);
    if (isUsableSecret(existing) && existing.length >= minLength) return existing;
  } else if (isUsableSecret(existing)) {
    return existing;
  }
  if (spec.kind === "keyring") return keyringValue(spec.keyPrefix, spec.bytes);
  if (spec.kind === "opaque") return randomSecret(spec.bytes);
  return null;
}

function buildValues(existingValues = {}) {
  const env = parseEnv(envFile());
  const values = { ...existingValues };
  for (const spec of requiredSecrets) {
    if (existingValues[spec.name]) {
      values[spec.name] = existingValues[spec.name];
      continue;
    }
    values[spec.name] = materializedOrGenerated(spec);
  }
  const appDbUser = env.APP_DB_USER || "app_user";
  const appDbName = env.APP_DB_NAME || "app_db";
  const natsUser = env.NATS_USER || "platform";
  values.database_url ||= `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(values.app_db_password)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  values.nats_url ||= `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(values.nats_password)}@nats:4222`;
  return values;
}

function validateValues(values, store = null) {
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
    } else if (spec.kind === "opaque" && value.length < (spec.minLength ?? Math.min(spec.bytes, 24))) {
      fail(`Secret ${spec.name} is too short.`);
    }
  }
  const previousRecords = store?.secrets ?? {};
  for (const [name, value] of Object.entries(values)) {
    if (requiredByName.has(name)) continue;
    const spec = secretSpec(name, previousRecords);
    if (typeof value !== "string" || value.length < spec.minLength) {
      fail(`Vault secret ${name} is missing or shorter than ${spec.minLength} byte(s).`);
    }
  }
}

function materialize(values = null, store = null) {
  const sourceStore = store ?? readStore();
  const sourceValues = values ?? decryptStoreValues(sourceStore);
  validateValues(sourceValues, sourceStore);
  const names = [];
  const previousRecords = sourceStore?.secrets ?? {};
  for (const name of orderedSecretNames(sourceValues, previousRecords)) {
    const spec = secretSpec(name, previousRecords);
    writePrivateFile(secretFilePath(name), `${sourceValues[name]}\n`, spec.fileMode || 0o600);
    names.push(name);
  }
  audit("materialize", { names });
  log(`Materialized ${names.length} Docker secret files in ${secretsDir()}`);
}

async function init() {
  const force = booleanFlag(argv.force);
  const previousStore = force ? null : readStore();
  const previousValues = previousStore ? decryptStoreValues(previousStore) : {};
  const values = buildValues(previousValues);
  validateValues(values, previousStore);
  const store = writeStore(values, previousStore);
  materialize(values, store);
  audit("init", {
    store: storePath(),
    names: Object.keys(store.secrets),
  });
  log(`Infra Secret Manager initialized at ${storePath()}`);
}

async function verify() {
  const store = readStore();
  if (!store) fail(`Missing Infra Secret Manager store: ${storePath()}`);
  const values = decryptStoreValues(store);
  validateValues(values, store);
  const names = orderedSecretNames(values, store.secrets);
  for (const name of names) {
    const materialized = readFileIfExists(secretFilePath(name));
    if (!materialized) fail(`Missing materialized Docker secret: ${secretFilePath(name)}`);
    if (!timingSafeEqual(Buffer.from(materialized), Buffer.from(values[name]))) {
      fail(`Materialized secret does not match manager store: ${name}`);
    }
  }
  audit("verify", { names });
  log("Infra Secret Manager verification passed.");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function status() {
  const store = readStore();
  if (!store) fail(`Missing Infra Secret Manager store: ${storePath()}`);
  log(`Store: ${storePath()}`);
  log(`Updated: ${store.updatedAt}`);
  const values = decryptStoreValues(store);
  const names = orderedSecretNames(values, store.secrets);
  for (const name of names) {
    const record = store.secrets?.[name];
    if (!record) {
      log(`${name}: missing`);
      continue;
    }
    const keyIds = record.keyIds?.length ? ` keyIds=${record.keyIds.join(",")}` : "";
    const scope = record.scope ?? (requiredByName.has(name) ? "platform" : "vault");
    const owner = record.owner ? ` owner=${record.owner}` : "";
    log(`${name}: scope=${scope}${owner} kind=${record.kind} updatedAt=${record.updatedAt} fingerprint=${record.fingerprint}${keyIds}`);
  }
}

async function kmsStatus() {
  const store = readStore();
  if (!store) fail(`Missing Infra Secret Manager store: ${storePath()}`);
  const kms = normalizeKmsMetadata(store);
  log(`KMS provider: ${kms.provider}`);
  log(`Algorithm: ${kms.algorithm}`);
  log(`Root fingerprint: ${kms.rootFingerprint}`);
  log(`Active key: ${kms.activeKeyId}`);
  for (const [keyId, record] of Object.entries(kms.keys)) {
    log(`${keyId}: status=${record.status} createdAt=${record.createdAt} root=${record.rootFingerprint}`);
  }
}

async function kmsRotate() {
  const store = readStore();
  if (!store) fail(`Missing Infra Secret Manager store: ${storePath()}`);
  const values = decryptStoreValues(store);
  const previousKms = normalizeKmsMetadata(store);
  const now = new Date().toISOString();
  const nextKeyId = kmsKeyId();
  const keys = { ...previousKms.keys };
  for (const [keyId, record] of Object.entries(keys)) {
    keys[keyId] = {
      ...record,
      status: keyId === previousKms.activeKeyId ? "decrypt-only" : record.status,
    };
  }
  const nextKms = {
    ...previousKms,
    activeKeyId: nextKeyId,
    rotatedAt: now,
    updatedAt: now,
    keys: {
      ...keys,
      [nextKeyId]: {
        createdAt: now,
        status: "active",
        rootFingerprint: kmsRootFingerprint(masterKey()),
      },
    },
  };
  writeStore(values, store, nextKms);
  materialize(values);
  audit("kms_rotate", { previousActiveKeyId: previousKms.activeKeyId, activeKeyId: nextKeyId });
  log(`Rotated Platform Local KMS active key to ${nextKeyId} and rewrapped ${Object.keys(values).length} secrets.`);
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
  if (!store) fail(`Missing Infra Secret Manager store: ${storePath()}`);
  const values = decryptStoreValues(store);
  const keep = Number(argv.keep ?? 3);
  if (spec.kind === "keyring") {
    const previous = parseVersionedSecretKeys(values[name]);
    values[name] = [
      keyringValue(spec.keyPrefix, spec.bytes),
      ...previous.map((key) => `${key.id}=${key.secret}`),
    ].slice(0, keep).join(",");
  } else if (spec.kind === "opaque") {
    values[name] = randomSecret(spec.bytes);
  } else {
    fail(`${name} is derived and cannot be rotated directly.`);
  }
  if (name === "app_db_password") {
    const env = parseEnv(envFile());
    const appDbUser = env.APP_DB_USER || "app_user";
    const appDbName = env.APP_DB_NAME || "app_db";
    values.database_url = `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(values.app_db_password)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  }
  if (name === "nats_password") {
    const env = parseEnv(envFile());
    const natsUser = env.NATS_USER || "platform";
    values.nats_url = `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(values.nats_password)}@nats:4222`;
  }
  validateValues(values, store);
  const nextStore = writeStore(values, store);
  materialize(values, nextStore);
  audit("rotate", { name, keep });
  log(`Rotated ${name}. Recreate dependent containers after reviewing the rollout window.`);
}

function readSecretInput(spec) {
  const valueFile = argv.valueFile ?? argv["value-file"] ?? argv.file;
  if (valueFile) {
    const value = readFileIfExists(path.resolve(valueFile));
    if (!value) fail(`Secret value file is empty or unreadable: ${valueFile}`);
    return value;
  }
  if (booleanFlag(argv.stdin)) {
    const value = fs.readFileSync(0, "utf8").trim();
    if (!value) fail("No secret value received on stdin.");
    return value;
  }
  fail(`Use set --name ${spec.name} with --value-file or --stdin.`);
}

async function setSecret() {
  const name = argv.name ?? argv._[0];
  if (!name) fail("Use set --name <secret_name>.");
  const normalized = validateSecretName(name);
  const store = readStore();
  const spec = secretSpec(normalized, store?.secrets ?? {}, {
    owner: argv.owner,
    rotationDays: argv.rotationDays ?? argv["rotation-days"],
    minLength: argv.minLength ?? argv["min-length"],
  });
  if (spec.kind === "derived" && !booleanFlag(argv.allowDerived ?? argv["allow-derived"])) {
    fail(`${normalized} is derived and cannot be set directly. Re-run with --allowDerived only to adopt an already-verified materialized value.`);
  }

  const values = buildValues(store ? decryptStoreValues(store) : {});
  values[normalized] = readSecretInput(spec);
  if (spec.vault && values[normalized].length < spec.minLength) {
    fail(`Vault secret ${normalized} is shorter than ${spec.minLength} byte(s).`);
  }
  if (normalized === "app_db_password") {
    const env = parseEnv(envFile());
    const appDbUser = env.APP_DB_USER || "app_user";
    const appDbName = env.APP_DB_NAME || "app_db";
    values.database_url = `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(values.app_db_password)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  }
  if (normalized === "nats_password") {
    const env = parseEnv(envFile());
    const natsUser = env.NATS_USER || "platform";
    values.nats_url = `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(values.nats_password)}@nats:4222`;
  }
  validateValues(values, store);
  const specOverrides = spec.vault
    ? { [normalized]: { owner: spec.owner, rotationDays: spec.rotationDays, minLength: spec.minLength } }
    : {};
  const nextStore = writeStore(values, store, null, specOverrides);
  materialize(values, nextStore);
  audit("set", { name: normalized, scope: spec.vault ? "vault" : "platform", owner: spec.owner ?? "platform", derived: spec.kind === "derived" });
  log(`Updated ${normalized} in Infra Secret Manager and materialized Docker secret files.`);
}

function help() {
  log(`Usage: node scripts/infra-secret-manager.mjs <command> [--key value]

Commands:
  init                 Create/update the encrypted store and materialize Docker secret files.
  materialize          Decrypt the store into secrets/*.txt for compose.secrets.yaml.
  kms-status           Print proprietary KMS key metadata without secret values.
  kms-rotate           Rotate the active KMS KEK and rewrap all stored secrets.
  rotate --name <name> Rotate a keyring or opaque secret, then materialize.
  set --name <name>    Import or replace a platform or vault secret from --value-file or --stdin.
                       Unknown safe names become vault secrets. Use --owner, --rotationDays and --minLength for metadata.
                       Derived platform secrets require --allowDerived.
  status               Print metadata and fingerprints without secret values.
  verify               Validate encrypted store and materialized Docker secret files.
`);
}

const commands = {
  help,
  init,
  "kms-rotate": kmsRotate,
  "kms-status": kmsStatus,
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
