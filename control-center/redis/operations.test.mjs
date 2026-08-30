import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  REDIS_BACKUP_SCHEMA,
  RedisOperationsError,
  createRedisOperations,
  parseRedisInfo,
  readRedisWorkloadBindings,
  validateRedisBackupDocument,
} from "./operations.mjs";

function fixtureDocument(entries) {
  const payloadBytes = entries.reduce((sum, entry) => sum
    + Buffer.from(entry.key, "base64").length
    + Buffer.from(entry.dump, "base64").length, 0);
  return {
    schema: REDIS_BACKUP_SCHEMA,
    id: "redis-20300102030405-deadbeef",
    createdAt: "2030-01-02T03:04:05.000Z",
    database: 0,
    keyCount: entries.length,
    payloadBytes,
    entries,
  };
}

function keyEntry(key, dump, expiresAt = null) {
  return {
    key: Buffer.from(key).toString("base64"),
    dump: Buffer.from(dump).toString("base64"),
    expiresAt,
  };
}

function passwordFixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), "control-center-redis-"));
  const file = path.join(root, "redis-password");
  writeFileSync(file, "not-a-real-password\n", { mode: 0o600 });
  t.after(() => rmSync(root, { force: true, recursive: true }));
  return file;
}

function clientFixture(overrides = {}) {
  const client = {
    isOpen: false,
    on() {},
    withTypeMapping() { return this; },
    async connect() { this.isOpen = true; },
    async close() { this.isOpen = false; },
    ...overrides,
  };
  return client;
}

test("parseRedisInfo ignores headings and preserves values after the first colon", () => {
  assert.deepEqual(parseRedisInfo("# Server\r\nredis_version:8.6.4\r\nrole:master:local\r\n"), {
    redis_version: "8.6.4",
    role: "master:local",
  });
});

test("readRedisWorkloadBindings exposes bindings but never policy secrets", (t) => {
  const root = mkdtempSync(path.join(tmpdir(), "control-center-redis-lock-"));
  const file = path.join(root, "lock.json");
  t.after(() => rmSync(root, { force: true, recursive: true }));
  writeFileSync(file, JSON.stringify({
    workloads: [
      { id: "stexor-account", brokers: { redis: { username: "app_account", keyPrefix: "account:", commands: ["GET", "SET"], password: "must-not-leak" } } },
      { id: "invalid id", brokers: { redis: { username: "ignored", keyPrefix: "ignored:" } } },
    ],
  }));
  const result = readRedisWorkloadBindings(file);
  assert.deepEqual(result, [{ id: "stexor-account", username: "app_account", keyPrefix: "account:", commandCount: 2 }]);
  assert.equal(JSON.stringify(result).includes("must-not-leak"), false);
});

test("validateRedisBackupDocument rejects duplicate keys and inconsistent counts", () => {
  const entry = keyEntry("session:1", "redis-dump");
  assert.throws(() => validateRedisBackupDocument(fixtureDocument([entry, entry])), RedisOperationsError);
  assert.throws(() => validateRedisBackupDocument({ ...fixtureDocument([entry]), keyCount: 2 }), RedisOperationsError);
  assert.equal(validateRedisBackupDocument(fixtureDocument([entry])).keyCount, 1);
});

test("snapshot returns live aggregate metrics without scanning keys", async (t) => {
  const passwordFile = passwordFixture(t);
  const calls = [];
  const client = clientFixture({
    async info(section) {
      calls.push(["info", section]);
      return [
        "redis_version:8.6.4",
        "loading:0",
        "uptime_in_seconds:3600",
        "connected_clients:4",
        "used_memory:1000",
        "used_memory_peak:1200",
        "maxmemory:0",
        "total_commands_processed:99",
        "total_connections_received:8",
        "keyspace_hits:9",
        "keyspace_misses:1",
        "evicted_keys:0",
        "expired_keys:7",
        "aof_enabled:1",
        "aof_rewrite_in_progress:0",
        "aof_last_bgrewrite_status:ok",
        "rdb_bgsave_in_progress:0",
        "rdb_last_bgsave_status:ok",
        "rdb_last_save_time:1893456000",
      ].join("\r\n");
    },
    async dbSize() { return 3; },
    async sendCommand(command) {
      assert.deepEqual(command, ["ACL", "USERS"]);
      return ["platform", "default"];
    },
    async scan() { throw new Error("snapshot must not inspect key names"); },
  });
  const operations = createRedisOperations({ enabled: true, passwordFile, clientFactory: () => client });
  const snapshot = await operations.snapshot();
  assert.equal(snapshot.available, true);
  assert.equal(snapshot.version, "8.6.4");
  assert.equal(snapshot.keyCount, 3);
  assert.equal(snapshot.stats.hitRate, 90);
  assert.deepEqual(snapshot.aclUsers, ["default", "platform"]);
  assert.equal(JSON.stringify(snapshot).includes("session:"), false);
  assert.equal(calls.filter(([name]) => name === "info").length, 6);
});

test("captureBackup pauses writes and preserves binary DUMP plus absolute expiry", async (t) => {
  const passwordFile = passwordFixture(t);
  const commands = [];
  let scans = 0;
  const dump = Buffer.from([0, 255, 10, 42, 9]);
  const client = clientFixture({
    async sendCommand(command) { commands.push(command); return "OK"; },
    async scan() {
      scans += 1;
      return { cursor: "0", keys: [Buffer.from("session:1")] };
    },
    async dump(key) { assert.deepEqual(key, Buffer.from("session:1")); return dump; },
    async pTTL() { return 60_000; },
  });
  const operations = createRedisOperations({ enabled: true, passwordFile, clientFactory: () => client });
  const backup = await operations.captureBackup();
  assert.equal(scans, 1);
  assert.deepEqual(commands[0].slice(0, 2), ["CLIENT", "PAUSE"]);
  assert.deepEqual(commands.at(-1), ["CLIENT", "UNPAUSE"]);
  assert.equal(backup.entries[0].dump, dump.toString("base64"));
  assert.ok(Date.parse(backup.entries[0].expiresAt) > Date.now());
});

test("cache reuses one Redis connection and stores only bounded expiring JSON", async (t) => {
  const passwordFile = passwordFixture(t);
  const values = new Map();
  const expiries = [];
  let connections = 0;
  const client = clientFixture({
    async connect() { connections += 1; this.isOpen = true; },
    async get(key) { return values.get(String(key)) ?? null; },
    async set(key, value, options) {
      assert.ok(Number(options?.PX) >= 250);
      values.set(String(key), Buffer.from(value));
      expiries.push([String(key), Number(options.PX)]);
      return "OK";
    },
    async del(key) { return values.delete(String(key)) ? 1 : 0; },
    async incr(key) {
      const next = Number(values.get(String(key)) || 0) + 1;
      values.set(String(key), Buffer.from(String(next)));
      return next;
    },
    async pExpire(key, ttl) { expiries.push([String(key), ttl]); return true; },
  });
  const operations = createRedisOperations({ enabled: true, passwordFile, clientFactory: () => client });
  t.after(() => operations.close());

  assert.equal(await operations.cacheGetJson("context:missing"), null);
  assert.equal(await operations.cacheSetJson("context:abc", { ok: true }, 5_000), true);
  assert.deepEqual(await operations.cacheGetJson("context:abc"), { ok: true });
  assert.equal(await operations.cacheCounter("portal:generation"), 0);
  assert.equal(await operations.cacheIncrement("portal:generation"), 1);
  assert.equal(await operations.cacheCounter("portal:generation"), 1);
  assert.equal(await operations.cacheDelete("context:abc"), true);
  assert.equal(connections, 1);
  assert.ok(expiries.every(([, ttl]) => ttl > 0));
  assert.equal([...values.keys()].every((key) => key.startsWith("control-center:cache:v1:")), true);
});

test("captureBackup excludes Control Center cache entries", async (t) => {
  const passwordFile = passwordFixture(t);
  const dumped = [];
  const client = clientFixture({
    async sendCommand() { return "OK"; },
    async scan() {
      return {
        cursor: "0",
        keys: [Buffer.from("control-center:cache:v1:context:abc"), Buffer.from("workers:jobs:heartbeat")],
      };
    },
    async dump(key) { dumped.push(key.toString()); return Buffer.from("dump"); },
    async pTTL() { return 30_000; },
  });
  const operations = createRedisOperations({ enabled: true, passwordFile, clientFactory: () => client });
  t.after(() => operations.close());
  const backup = await operations.captureBackup();
  assert.deepEqual(dumped, ["workers:jobs:heartbeat"]);
  assert.equal(backup.keyCount, 1);
});

test("restore validates payloads, replaces the database atomically and skips expired keys", async (t) => {
  const passwordFile = passwordFixture(t);
  const validationRestores = [];
  const transactionCalls = [];
  const transaction = {
    flushDb() { transactionCalls.push(["flushDb"]); return this; },
    restore(key, ttl, dump) { transactionCalls.push(["restore", key.toString(), ttl, dump.toString()]); return this; },
    async exec() { transactionCalls.push(["exec"]); return []; },
  };
  const client = clientFixture({
    async restore(key, ttl, dump) { validationRestores.push([key.toString(), ttl, dump.toString()]); return "OK"; },
    async del(keys) { assert.equal(keys.length, 2); return keys.length; },
    multi() { return transaction; },
  });
  const operations = createRedisOperations({ enabled: true, passwordFile, clientFactory: () => client });
  const backup = fixtureDocument([
    keyEntry("persistent", "dump-a"),
    keyEntry("future", "dump-b", new Date(Date.now() + 120_000).toISOString()),
    keyEntry("expired", "dump-c", new Date(Date.now() - 1_000).toISOString()),
  ]);
  const restored = await operations.restoreBackup(backup);
  assert.equal(validationRestores.length, 2);
  assert.equal(transactionCalls.filter(([name]) => name === "flushDb").length, 1);
  assert.deepEqual(transactionCalls.filter(([name]) => name === "restore").map(([, key]) => key), ["persistent", "future"]);
  assert.equal(transactionCalls.at(-1)[0], "exec");
  assert.deepEqual(restored, { restoredKeys: 2, expiredKeysSkipped: 1, database: 0 });
});
