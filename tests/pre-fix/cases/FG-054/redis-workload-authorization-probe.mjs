#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const SOURCE_HASHES = new Map([
  ["compose.yaml", "ed630eee1be8350142493307c2647aa98ce67324c93c127a9370a19a24a9d6c7"],
  ["compose.secrets.yaml", "52897c0e6f650f360b673fff67a1dac1fe312f8c9ec8843890686ad62b4a6c60"],
  ["compose.networks.yaml", "f6cfb3b3857c1fd85414fbd7dc29c78a5f96ca9e7d309d8849cbb3400f66d759"],
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
]);

if (!process.argv[2]) {
  throw new Error("usage: redis-workload-authorization-probe.mjs /path/to/archived/source");
}

const sourceRoot = validateWrapperOwnedSource(process.argv[2]);
assert.equal(fs.existsSync(path.join(sourceRoot, ".git")), false, "source must be a Git archive without .git metadata");
for (const [relativePath, expected] of SOURCE_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected pre-fix source`);
}
console.log(`[PASS] exact pre-fix source fingerprints verified revision=${REVISION} tree=${TREE}`);

const compose = fs.readFileSync(path.join(sourceRoot, "compose.yaml"), "utf8");
const composeSecrets = fs.readFileSync(path.join(sourceRoot, "compose.secrets.yaml"), "utf8");
const composeNetworks = fs.readFileSync(path.join(sourceRoot, "compose.networks.yaml"), "utf8");
const contractSource = fs.readFileSync(path.join(sourceRoot, "scripts", "hosted-workload-contract.mjs"), "utf8");
const redisService = sourceSlice(compose, "  redis:\n", "  keycloak:\n");
const redisSecretOverlay = sourceSlice(composeSecrets, "  redis:\n", "  keycloak:\n");
const redisNetworkOverlay = sourceSlice(composeNetworks, "  redis:\n", "  keycloak:\n");

assert.match(redisService, /REDIS_PASSWORD_FILE:\s*\/run\/secrets\/redis_password/);
assert.match(redisService, /redis-server --appendonly yes --requirepass "\$\$\{REDIS_PASSWORD\}"/);
assert.match(redisSecretOverlay, /secrets:\s*\n\s*- redis_password/);
assert.match(redisNetworkOverlay, /networks:\s*!override\s*\n\s*- platform_cache/);
assert.doesNotMatch(`${redisService}\n${redisSecretOverlay}`, /--aclfile|ACL\s+SETUSER|user\s+default\s+off/i);
assert.match(contractSource, /const PLATFORM_DEPENDENCIES = new Set\(\[[\s\S]*"redis"/);
assert.match(contractSource, /\["redis", new Set\(\["cache"\]\)\]/);
assert.doesNotMatch(contractSource, /redisAcl|redisUsername|redisKeyPattern|redisCommandAllowlist/);
console.log("[SOURCE] redis_auth=requirepass user=default global_secret=redis_password aclfile=absent");
console.log("[SOURCE] hosted_contract redis_dependency=allowed cache_network_extension=allowed workload_acl_binding=absent");

const contractModule = await import(pathToFileURL(path.join(sourceRoot, "scripts", "hosted-workload-contract.mjs")));
const { core, combined, lock } = twoWorkloadFixture();
const accepted = contractModule.validateRenderedWorkloads({
  core: structuredClone(core),
  combined: structuredClone(combined),
  lock: structuredClone(lock),
});
assert.deepEqual(accepted.routes, []);
assert.deepEqual(Object.keys(combined.services.redis.networks).sort(), ["alpha_cache", "beta_cache", "platform_cache"]);
console.log("[CONTRACT] workloads=2 redis_services=1 dedicated_cache_networks=2 result=accepted");

const crossNetwork = structuredClone(combined);
crossNetwork.services["alpha-api"].networks = { beta_cache: null };
assert.throws(
  () => contractModule.validateRenderedWorkloads({ core, combined: crossNetwork, lock }),
  /alpha-api uses unauthorized network beta_cache/,
);
const undeclaredSecret = structuredClone(combined);
undeclaredSecret.services["alpha-api"].secrets = ["beta-cache-auth"];
assert.throws(
  () => contractModule.validateRenderedWorkloads({ core, combined: undeclaredSecret, lock }),
  /alpha-api uses undeclared secret beta-cache-auth/,
);
console.log("[NEGATIVE-CONTRACT] cross_workload_network=reject undeclared_secret=reject");

function twoWorkloadFixture() {
  const redis = {
    image: `redis@sha256:${"a".repeat(64)}`,
    command: ["redis-server", "--requirepass", "fixture-secret-reference"],
    networks: { platform_cache: null },
  };
  const core = {
    services: { redis },
    networks: { platform_cache: { internal: true } },
  };
  const combined = structuredClone(core);
  combined.services.redis.networks.alpha_cache = null;
  combined.services.redis.networks.beta_cache = null;
  combined.services["alpha-api"] = workloadService("alpha", "alpha-cache-auth");
  combined.services["beta-api"] = workloadService("beta", "beta-cache-auth");
  combined.networks.alpha_cache = { internal: true };
  combined.networks.beta_cache = { internal: true };
  combined.secrets = {
    "alpha-cache-auth": { external: true },
    "beta-cache-auth": { external: true },
  };
  const lock = {
    workloads: [
      {
        id: "alpha",
        secrets: ["alpha-cache-auth"],
        services: [{ name: "alpha-api", role: "api", routes: [] }],
      },
      {
        id: "beta",
        secrets: ["beta-cache-auth"],
        services: [{ name: "beta-api", role: "api", routes: [] }],
      },
    ],
  };
  return { core, combined, lock };
}

function workloadService(workloadId, secretName) {
  return {
    image: `example/${workloadId}@sha256:${"b".repeat(64)}`,
    init: true,
    restart: "unless-stopped",
    read_only: true,
    user: "10001:10001",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    cap_add: [],
    healthcheck: { test: ["CMD", "true"] },
    cpus: 0.25,
    mem_limit: 128 * 1024 * 1024,
    mem_reservation: 64 * 1024 * 1024,
    pids_limit: 64,
    cpu_shares: 128,
    blkio_config: { weight: 100 },
    ulimits: { nofile: { soft: 1024, hard: 2048 } },
    environment: {
      [`${workloadId.toUpperCase()}_CACHE_AUTH_FILE`]: `/run/secrets/${secretName}`,
    },
    secrets: [secretName],
    volumes: [],
    networks: { [`${workloadId}_cache`]: null },
    depends_on: { redis: { condition: "service_healthy" } },
    labels: {
      "com.platform.workload-id": workloadId,
      "com.platform.workload-role": "api",
    },
  };
}

class AuthorizationModel {
  constructor(users) {
    this.users = users;
    this.values = new Map();
  }

  login(username, password) {
    const policy = this.users[username];
    if (!policy || policy.password !== password) throw new Error("WRONGPASS invalid username-password pair");
    const authorize = (command, key = null) => {
      const normalized = command.toUpperCase();
      if (policy.commands !== "*" && !policy.commands.has(normalized)) throw new Error(`NOPERM command ${normalized}`);
      if (key !== null && !policy.keyPrefixes.some((prefix) => String(key).startsWith(prefix))) {
        throw new Error(`NOPERM key ${key}`);
      }
    };
    return {
      set: (key, value) => {
        authorize("SET", key);
        this.values.set(key, value);
        return "OK";
      },
      get: (key) => {
        authorize("GET", key);
        return this.values.get(key) ?? null;
      },
      del: (key) => {
        authorize("DEL", key);
        return this.values.delete(key) ? 1 : 0;
      },
      keys: (pattern) => {
        authorize("KEYS", pattern);
        if (pattern !== "*") throw new Error("model supports only KEYS *");
        return [...this.values.keys()];
      },
      flushall: () => {
        authorize("FLUSHALL");
        this.values.clear();
        return "OK";
      },
    };
  }
}

const sharedCredential = "offline-fixture-shared-credential";
const preFix = new AuthorizationModel({
  default: {
    password: sharedCredential,
    commands: "*",
    keyPrefixes: [""],
  },
});
const alphaLegacy = preFix.login("default", sharedCredential);
const betaLegacy = preFix.login("default", sharedCredential);
alphaLegacy.set("alpha:session:1", "alpha-session");
betaLegacy.set("beta:session:1", "beta-session");
assert.equal(alphaLegacy.get("beta:session:1"), "beta-session");
assert.deepEqual(alphaLegacy.keys("*").sort(), ["alpha:session:1", "beta:session:1"]);
alphaLegacy.flushall();
assert.deepEqual(betaLegacy.keys("*"), []);
console.log("[PRE-FIX] shared_auth=true cross_workload_read=allow keyspace_enumeration=allow flushall=allow");

const fixed = new AuthorizationModel({
  alpha: {
    password: "offline-fixture-alpha-only",
    commands: new Set(["GET", "SET", "DEL", "EXPIRE", "TTL", "PTTL"]),
    keyPrefixes: ["alpha:"],
  },
  beta: {
    password: "offline-fixture-beta-only",
    commands: new Set(["GET", "SET", "DEL", "EXPIRE", "TTL", "PTTL"]),
    keyPrefixes: ["beta:"],
  },
});
const alphaFixed = fixed.login("alpha", "offline-fixture-alpha-only");
const betaFixed = fixed.login("beta", "offline-fixture-beta-only");
alphaFixed.set("alpha:session:1", "alpha-session");
betaFixed.set("beta:session:1", "beta-session");
assert.equal(alphaFixed.get("alpha:session:1"), "alpha-session");
assert.equal(betaFixed.get("beta:session:1"), "beta-session");
assert.throws(() => alphaFixed.get("beta:session:1"), /NOPERM key/);
assert.throws(() => betaFixed.get("alpha:session:1"), /NOPERM key/);
assert.throws(() => alphaFixed.flushall(), /NOPERM command/);
assert.throws(() => alphaFixed.keys("*"), /NOPERM command/);
assert.throws(() => fixed.login("alpha", sharedCredential), /WRONGPASS/);
console.log("[FIXED-CONTROL] own_prefix=allow cross_workload=deny admin_command=deny keyspace_command=deny shared_password=deny");
console.log("[SAFE] source-pinned policy projection only; no Redis server, Docker, network, SSH, credentials, or live target");

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
}

function validateWrapperOwnedSource(sourceArgument) {
  const wrapperArgument = requiredEnvironment("REPORT_FG054_WRAPPER_TEMP_ROOT");
  const sentinelArgument = requiredEnvironment("REPORT_FG054_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("REPORT_FG054_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperArgument);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(path.basename(wrapperReal), /^fg054-(?:guard|run)\.[A-Za-z0-9]+$/);

  const requestedSource = path.resolve(sourceArgument);
  const sourceStat = fs.lstatSync(requestedSource, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(requestedSource);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned archive child");

  const sentinelPath = path.resolve(sentinelArgument);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg054-owner\.[A-Za-z0-9]+$/);
  const sentinelToken = path.basename(sentinelReal).slice(".fg054-owner.".length);
  assert.equal(ownershipToken, sentinelToken, "ownership token does not match sentinel name");
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), `FG054-OWNER:${ownershipToken}\n`);
  return sourceReal;
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke this probe through run-from-git-archive.sh`);
  }
  return value;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}
