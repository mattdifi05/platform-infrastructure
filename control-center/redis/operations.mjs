import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createClient, RESP_TYPES } from "redis";

export const REDIS_BACKUP_SCHEMA = "platform.redis-backup/v1";
export const REDIS_CACHE_SCHEMA = "platform.control-center-cache/v1";

const DEFAULT_MAX_KEYS = 10_000;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_CACHE_MAX_BYTES = 4 * 1024 * 1024;

export class RedisOperationsError extends Error {
  constructor(message, code = "redis_operation_failed") {
    super(message);
    this.name = "RedisOperationsError";
    this.code = code;
  }
}

export function createRedisOperations({
  enabled = false,
  host = "redis",
  port = 6379,
  username = "platform",
  passwordFile = "",
  database = 0,
  workloadLockFile = "",
  connectTimeoutMs = 1200,
  operationTimeoutMs = 15_000,
  backupPauseMs = 10_000,
  maxBackupKeys = DEFAULT_MAX_KEYS,
  maxBackupBytes = DEFAULT_MAX_BYTES,
  cachePrefix = "control-center:cache:v1",
  cacheMaxBytes = DEFAULT_CACHE_MAX_BYTES,
  clientFactory = createClient,
} = {}) {
  const configuration = {
    enabled: enabled === true,
    host: String(host || "redis").trim() || "redis",
    port: boundedInteger(port, 1, 65535, 6379),
    username: String(username || "platform").trim() || "platform",
    passwordFile: String(passwordFile || "").trim(),
    database: boundedInteger(database, 0, 63, 0),
    workloadLockFile: String(workloadLockFile || "").trim(),
    connectTimeoutMs: boundedInteger(connectTimeoutMs, 250, 10_000, 1200),
    operationTimeoutMs: boundedInteger(operationTimeoutMs, 1000, 120_000, 15_000),
    backupPauseMs: boundedInteger(backupPauseMs, 1000, 30_000, 10_000),
    maxBackupKeys: boundedInteger(maxBackupKeys, 1, 100_000, DEFAULT_MAX_KEYS),
    maxBackupBytes: boundedInteger(maxBackupBytes, 1024, 512 * 1024 * 1024, DEFAULT_MAX_BYTES),
    cachePrefix: validCachePrefix(cachePrefix),
    cacheMaxBytes: boundedInteger(cacheMaxBytes, 1024, 32 * 1024 * 1024, DEFAULT_CACHE_MAX_BYTES),
  };
  let sharedClient = null;
  let connectPending = null;

  async function connectedClient(label) {
    if (sharedClient?.isOpen) return sharedClient;
    if (connectPending) return connectPending;
    const password = readRedisPassword(configuration.passwordFile);
    const rawClient = clientFactory({
      socket: {
        host: configuration.host,
        port: configuration.port,
        connectTimeout: configuration.connectTimeoutMs,
        reconnectStrategy: false,
      },
      username: configuration.username,
      password,
      database: configuration.database,
      name: "platform-control-center",
      disableClientInfo: false,
    });
    rawClient.on?.("error", () => {});
    const client = typeof rawClient.withTypeMapping === "function"
      ? rawClient.withTypeMapping({ [RESP_TYPES.BLOB_STRING]: Buffer })
      : rawClient;
    sharedClient = client;
    const pending = deadline(client.connect(), configuration.connectTimeoutMs + 500, `${label}: connessione scaduta.`)
      .then(() => client);
    connectPending = pending;
    try {
      return await pending;
    } catch (error) {
      if (sharedClient === client) sharedClient = null;
      await closeRedisClient(client);
      throw error;
    } finally {
      if (connectPending === pending) connectPending = null;
    }
  }

  async function withClient(label, operation) {
    if (!configuration.enabled) throw new RedisOperationsError("Connessione Redis live non abilitata.", "redis_live_disabled");
    let client;
    try {
      client = await connectedClient(label);
      return await deadline(operation(client), configuration.operationTimeoutMs, `${label}: operazione scaduta.`);
    } catch (error) {
      if (!(error instanceof RedisOperationsError) || error.code === "redis_timeout" || error.code === "redis_connection_failed") {
        if (sharedClient === client) sharedClient = null;
        await closeRedisClient(client);
      }
      if (error instanceof RedisOperationsError) throw error;
      throw new RedisOperationsError(`${label} non riuscita.`, "redis_connection_failed");
    }
  }

  async function cacheGetJson(name) {
    if (!cacheAvailable(configuration)) return null;
    try {
      const payload = await withClient("Lettura cache Redis", (client) => client.get(cacheKey(configuration, name)));
      if (payload == null) return null;
      const bytes = redisBuffer(payload);
      if (bytes.length > configuration.cacheMaxBytes) return null;
      const envelope = JSON.parse(bytes.toString("utf8"));
      return envelope?.schema === REDIS_CACHE_SCHEMA && Object.hasOwn(envelope, "value") ? envelope.value : null;
    } catch {
      return null;
    }
  }

  async function cacheSetJson(name, value, ttlMs) {
    if (!cacheAvailable(configuration)) return false;
    try {
      const payload = Buffer.from(JSON.stringify({ schema: REDIS_CACHE_SCHEMA, value }), "utf8");
      if (payload.length > configuration.cacheMaxBytes) return false;
      const ttl = boundedInteger(ttlMs, 250, 24 * 60 * 60 * 1000, 15_000);
      await withClient("Scrittura cache Redis", (client) => client.set(cacheKey(configuration, name), payload, { PX: ttl }));
      return true;
    } catch {
      return false;
    }
  }

  async function cacheDelete(name) {
    if (!cacheAvailable(configuration)) return false;
    try {
      await withClient("Invalidazione cache Redis", (client) => client.del(cacheKey(configuration, name)));
      return true;
    } catch {
      return false;
    }
  }

  async function cacheCounter(name) {
    if (!cacheAvailable(configuration)) return null;
    try {
      const value = await withClient("Lettura versione cache Redis", (client) => client.get(cacheKey(configuration, name)));
      if (value == null) return 0;
      const number = Number(redisText(value));
      return Number.isSafeInteger(number) && number >= 0 ? number : null;
    } catch {
      return null;
    }
  }

  async function cacheIncrement(name, ttlMs = 30 * 24 * 60 * 60 * 1000) {
    if (!cacheAvailable(configuration)) return null;
    try {
      const key = cacheKey(configuration, name);
      const value = await withClient("Aggiornamento versione cache Redis", async (client) => {
        const next = await client.incr(key);
        await client.pExpire(key, boundedInteger(ttlMs, 60_000, 90 * 24 * 60 * 60 * 1000, 30 * 24 * 60 * 60 * 1000));
        return next;
      });
      const number = Number(value);
      return Number.isSafeInteger(number) && number >= 0 ? number : null;
    } catch {
      return null;
    }
  }

  async function close() {
    const client = sharedClient;
    sharedClient = null;
    connectPending = null;
    await closeRedisClient(client);
  }

  async function snapshot() {
    const workloads = readRedisWorkloadBindings(configuration.workloadLockFile);
    if (!configuration.enabled) return unavailableSnapshot("Connessione live disabilitata.", workloads);
    if (!configuration.passwordFile || !existsSync(configuration.passwordFile)) {
      return unavailableSnapshot("Docker Secret Redis non disponibile al Control Center.", workloads);
    }
    try {
      return await withClient("Lettura Redis", async (client) => {
        const sections = await Promise.all(["server", "clients", "memory", "stats", "persistence", "keyspace"]
          .map((section) => client.info(section)));
        const info = parseRedisInfo(sections.map(redisText).join("\n"));
        const [dbSize, aclReply] = await Promise.all([
          client.dbSize(),
          client.sendCommand(["ACL", "USERS"]),
        ]);
        const hits = redisNumber(info.keyspace_hits);
        const misses = redisNumber(info.keyspace_misses);
        const requests = hits + misses;
        return {
          available: true,
          status: redisNumber(info.loading) === 0 ? "healthy" : "loading",
          message: "Istanza Redis raggiungibile.",
          host: configuration.host,
          port: configuration.port,
          database: configuration.database,
          version: redisText(info.redis_version),
          capturedAt: new Date().toISOString(),
          uptimeSeconds: redisNumber(info.uptime_in_seconds),
          clients: redisNumber(info.connected_clients),
          keyCount: redisInteger(dbSize),
          memory: {
            usedBytes: redisNumber(info.used_memory),
            peakBytes: redisNumber(info.used_memory_peak),
            maxBytes: redisNumber(info.maxmemory),
          },
          stats: {
            commands: redisNumber(info.total_commands_processed),
            connections: redisNumber(info.total_connections_received),
            hits,
            misses,
            hitRate: requests > 0 ? (hits / requests) * 100 : null,
            evictedKeys: redisNumber(info.evicted_keys),
            expiredKeys: redisNumber(info.expired_keys),
          },
          persistence: {
            aofEnabled: redisNumber(info.aof_enabled) === 1,
            aofRewriteInProgress: redisNumber(info.aof_rewrite_in_progress) === 1,
            aofLastStatus: redisText(info.aof_last_bgrewrite_status || "unknown"),
            rdbSaveInProgress: redisNumber(info.rdb_bgsave_in_progress) === 1,
            rdbLastStatus: redisText(info.rdb_last_bgsave_status || "unknown"),
            rdbLastSaveAt: epochDate(info.rdb_last_save_time),
          },
          aclUsers: redisArray(aclReply).map(redisText).filter(Boolean).sort(),
          workloads,
        };
      });
    } catch (error) {
      return unavailableSnapshot(error instanceof RedisOperationsError ? error.message : "Redis non raggiungibile.", workloads);
    }
  }

  async function captureBackup() {
    return withClient("Backup Redis", async (client) => {
      const createdAt = new Date();
      const entries = [];
      const seen = new Set();
      let totalBytes = 0;
      let cursor = "0";
      let paused = false;
      try {
        await client.sendCommand(["CLIENT", "PAUSE", String(configuration.backupPauseMs), "WRITE"]);
        paused = true;
        do {
          const reply = await client.scan(cursor, { COUNT: 500 });
          cursor = redisText(reply?.cursor ?? reply?.[0] ?? "0");
          const keys = reply?.keys ?? reply?.[1] ?? [];
          for (const keyValue of keys) {
            const key = redisBuffer(keyValue);
            if (isCacheKey(configuration, key)) continue;
            const identity = key.toString("base64");
            if (seen.has(identity)) continue;
            seen.add(identity);
            if (seen.size > configuration.maxBackupKeys) {
              throw new RedisOperationsError("Backup Redis oltre il limite massimo di chiavi.", "redis_backup_too_large");
            }
            const [dumpValue, ttlValue] = await Promise.all([client.dump(key), client.pTTL(key)]);
            if (dumpValue == null) continue;
            const dump = redisBuffer(dumpValue);
            totalBytes += key.length + dump.length;
            if (totalBytes > configuration.maxBackupBytes) {
              throw new RedisOperationsError("Backup Redis oltre il limite massimo di dimensione.", "redis_backup_too_large");
            }
            const ttlMs = redisInteger(ttlValue);
            entries.push({
              key: key.toString("base64"),
              dump: dump.toString("base64"),
              expiresAt: ttlMs >= 0 ? new Date(Date.now() + ttlMs).toISOString() : null,
            });
          }
        } while (cursor !== "0");
      } finally {
        if (paused) {
          try { await client.sendCommand(["CLIENT", "UNPAUSE"]); } catch { /* Redis auto-unpauses at the bounded timeout. */ }
        }
      }
      return validateRedisBackupDocument({
        schema: REDIS_BACKUP_SCHEMA,
        id: `redis-${createdAt.toISOString().replace(/\D/g, "").slice(0, 14)}-${randomBytes(4).toString("hex")}`,
        createdAt: createdAt.toISOString(),
        database: configuration.database,
        keyCount: entries.length,
        payloadBytes: totalBytes,
        entries,
      }, configuration);
    });
  }

  async function restoreBackup(input) {
    const backup = validateRedisBackupDocument(input, configuration);
    return withClient("Restore Redis", async (client) => {
      const restoredEntries = backup.entries
        .map((entry) => ({
          key: Buffer.from(entry.key, "base64"),
          dump: Buffer.from(entry.dump, "base64"),
          ttlMs: entry.expiresAt == null ? 0 : Date.parse(entry.expiresAt) - Date.now(),
        }))
        .filter((entry) => entry.ttlMs === 0 || entry.ttlMs > 0);
      const validationKeys = [];
      try {
        for (let index = 0; index < restoredEntries.length; index += 1) {
          const validationKey = Buffer.from(`__control_center_restore_check:${randomBytes(16).toString("hex")}:${index}`);
          validationKeys.push(validationKey);
          await client.restore(validationKey, 60_000, restoredEntries[index].dump);
        }
      } finally {
        if (validationKeys.length) {
          try { await client.del(validationKeys); } catch { /* Validation keys expire automatically. */ }
        }
      }
      const transaction = client.multi();
      transaction.flushDb();
      for (const entry of restoredEntries) transaction.restore(entry.key, entry.ttlMs, entry.dump);
      const results = await transaction.exec();
      if (Array.isArray(results) && results.some((result) => result instanceof Error)) {
        throw new RedisOperationsError("Restore Redis incompleto.", "redis_restore_failed");
      }
      return {
        restoredKeys: restoredEntries.length,
        expiredKeysSkipped: backup.entries.length - restoredEntries.length,
        database: configuration.database,
      };
    });
  }

  return Object.freeze({
    cacheCounter,
    cacheDelete,
    cacheGetJson,
    cacheIncrement,
    cacheSetJson,
    captureBackup,
    close,
    configuration: Object.freeze({ ...configuration, passwordFile: configuration.passwordFile ? "configured" : "" }),
    restoreBackup,
    snapshot,
  });
}

export function parseRedisInfo(value) {
  const info = {};
  for (const rawLine of String(value || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    info[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return info;
}

export function validateRedisBackupDocument(input, limits = {}) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const maxKeys = boundedInteger(limits.maxBackupKeys, 1, 100_000, DEFAULT_MAX_KEYS);
  const maxBytes = boundedInteger(limits.maxBackupBytes, 1024, 512 * 1024 * 1024, DEFAULT_MAX_BYTES);
  if (source.schema !== REDIS_BACKUP_SCHEMA) throw new RedisOperationsError("Schema backup Redis non valido.", "redis_backup_invalid");
  if (!/^redis-\d{14}-[a-f0-9]{8}$/.test(String(source.id || ""))) throw new RedisOperationsError("Identità backup Redis non valida.", "redis_backup_invalid");
  const createdAt = new Date(source.createdAt);
  if (!Number.isFinite(createdAt.getTime())) throw new RedisOperationsError("Data backup Redis non valida.", "redis_backup_invalid");
  const database = boundedInteger(source.database, 0, 63, -1);
  if (database < 0) throw new RedisOperationsError("Database Redis non valido.", "redis_backup_invalid");
  if (!Array.isArray(source.entries) || source.entries.length > maxKeys) throw new RedisOperationsError("Elenco backup Redis non valido.", "redis_backup_invalid");
  const entries = [];
  const keys = new Set();
  let payloadBytes = 0;
  for (const entry of source.entries) {
    if (!entry || typeof entry !== "object" || !validBase64(entry.key) || !validBase64(entry.dump)) {
      throw new RedisOperationsError("Contenuto backup Redis non valido.", "redis_backup_invalid");
    }
    const key = Buffer.from(entry.key, "base64");
    const dump = Buffer.from(entry.dump, "base64");
    if (!key.length || key.length > 1024 * 1024 || !dump.length) throw new RedisOperationsError("Elemento backup Redis non valido.", "redis_backup_invalid");
    const identity = key.toString("base64");
    if (keys.has(identity)) throw new RedisOperationsError("Chiave duplicata nel backup Redis.", "redis_backup_invalid");
    keys.add(identity);
    const expiresAt = entry.expiresAt == null ? null : new Date(entry.expiresAt);
    if (expiresAt && !Number.isFinite(expiresAt.getTime())) throw new RedisOperationsError("Scadenza backup Redis non valida.", "redis_backup_invalid");
    payloadBytes += key.length + dump.length;
    if (payloadBytes > maxBytes) throw new RedisOperationsError("Backup Redis oltre il limite massimo di dimensione.", "redis_backup_too_large");
    entries.push({ key: identity, dump: dump.toString("base64"), expiresAt: expiresAt ? expiresAt.toISOString() : null });
  }
  if (Number(source.keyCount) !== entries.length || Number(source.payloadBytes) !== payloadBytes) {
    throw new RedisOperationsError("Conteggi backup Redis non coerenti.", "redis_backup_invalid");
  }
  return Object.freeze({
    schema: REDIS_BACKUP_SCHEMA,
    id: String(source.id),
    createdAt: createdAt.toISOString(),
    database,
    keyCount: entries.length,
    payloadBytes,
    entries: Object.freeze(entries.map(Object.freeze)),
  });
}

export function readRedisWorkloadBindings(filePath) {
  if (!filePath || !existsSync(filePath)) return [];
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8"));
    if (!Array.isArray(parsed.workloads)) return [];
    return parsed.workloads.flatMap((workload) => {
      const policy = workload?.brokers?.redis;
      if (!policy || typeof policy !== "object") return [];
      const id = String(workload.id || "").trim();
      const username = String(policy.username || "").trim();
      const keyPrefix = String(policy.keyPrefix || "").trim();
      if (!/^[a-z][a-z0-9-]{1,62}$/.test(id) || !username || !keyPrefix) return [];
      return [{ id, username, keyPrefix, commandCount: Array.isArray(policy.commands) ? policy.commands.length : 0 }];
    }).sort((a, b) => a.id.localeCompare(b.id));
  } catch {
    return [];
  }
}

function unavailableSnapshot(message, workloads) {
  return {
    available: false,
    status: "unavailable",
    message,
    host: "",
    port: 0,
    database: 0,
    version: "",
    capturedAt: new Date().toISOString(),
    uptimeSeconds: 0,
    clients: 0,
    keyCount: 0,
    memory: { usedBytes: 0, peakBytes: 0, maxBytes: 0 },
    stats: { commands: 0, connections: 0, hits: 0, misses: 0, hitRate: null, evictedKeys: 0, expiredKeys: 0 },
    persistence: { aofEnabled: false, aofRewriteInProgress: false, aofLastStatus: "unknown", rdbSaveInProgress: false, rdbLastStatus: "unknown", rdbLastSaveAt: null },
    aclUsers: [],
    workloads,
  };
}

function readRedisPassword(filePath) {
  if (!filePath || !existsSync(filePath)) throw new RedisOperationsError("Docker Secret Redis non leggibile.", "redis_secret_unavailable");
  try {
    const password = readFileSync(filePath, "utf8").replace(/\r?\n$/, "");
    if (!password || password.length > 4096 || /[\0\r\n]/.test(password)) throw new Error("invalid secret");
    return password;
  } catch {
    throw new RedisOperationsError("Docker Secret Redis non leggibile.", "redis_secret_unavailable");
  }
}

function cacheAvailable(configuration) {
  return configuration.enabled && Boolean(configuration.passwordFile) && existsSync(configuration.passwordFile);
}

function validCachePrefix(value) {
  const prefix = String(value || "").trim();
  return /^[a-z][a-z0-9:_-]{2,95}$/.test(prefix) ? prefix : "control-center:cache:v1";
}

function cacheKey(configuration, name) {
  const suffix = String(name || "").trim();
  if (!/^[a-z0-9][a-z0-9:_-]{0,190}$/.test(suffix)) {
    throw new RedisOperationsError("Identità cache Redis non valida.", "redis_cache_key_invalid");
  }
  return `${configuration.cachePrefix}:${suffix}`;
}

function isCacheKey(configuration, key) {
  const prefix = Buffer.from(`${configuration.cachePrefix}:`, "utf8");
  return key.length >= prefix.length && key.subarray(0, prefix.length).equals(prefix);
}

async function closeRedisClient(client) {
  if (!client) return;
  try {
    if (client.isOpen && typeof client.close === "function") await client.close();
    else if (client.isOpen && typeof client.quit === "function") await client.quit();
    else if (typeof client.destroy === "function") client.destroy();
  } catch {
    try { client.destroy?.(); } catch { /* Ignore cleanup failures. */ }
  }
}

function deadline(promise, timeoutMs, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new RedisOperationsError(message, "redis_timeout")), timeoutMs); }),
  ]).finally(() => clearTimeout(timer));
}

function validBase64(value) {
  const text = String(value || "");
  return text.length > 0 && text.length <= 128 * 1024 * 1024 && text.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(text);
}

function redisArray(value) {
  return Array.isArray(value) ? value : [];
}

function redisBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return Buffer.from(String(value ?? ""));
}

function redisText(value) {
  return redisBuffer(value).toString("utf8").replace(/\r$/, "");
}

function redisNumber(value) {
  const number = Number(redisText(value));
  return Number.isFinite(number) ? number : 0;
}

function redisInteger(value) {
  if (typeof value === "bigint") return Number(value);
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : Math.trunc(redisNumber(value));
}

function epochDate(value) {
  const seconds = redisNumber(value);
  return seconds > 0 ? new Date(seconds * 1000).toISOString() : null;
}

function boundedInteger(value, minimum, maximum, fallback) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}
