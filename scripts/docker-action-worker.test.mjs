import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import * as broker from "./docker-action-broker.mjs";
import {
  createBackupJobDocument,
  parseBackupJobDocument,
} from "../control-center/backup/contracts.mjs";
import {
  EXPECTED_ACTION_PHASES,
  EXPECTED_PHASE_PROFILES,
  MAX_PHASE_OUTPUT_BYTES_V2,
  buildFixtureNetworkInspect,
  buildFixturePhaseOutputV2,
  buildFixtureSignedActionRequestV2,
  buildFixtureTrustedContextV2,
  buildFixtureVolumeInspect,
  buildRawActiveReceiptV2,
  canonicalFixtureJson,
  fixtureSha256,
} from "./docker-action-v2-fixtures.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const workerPath = path.join(scriptDir, "docker-action-worker.mjs");
const workerRuntimeGuardPath = path.join(
  scriptDir,
  "docker-action-worker-runtime-guard.mjs",
);
const WORKER_CONTAINER_PATH =
  "/opt/platform-docker-worker/docker-action-worker.mjs";
const WORKER_RUNTIME_GUARD_CONTAINER_PATH =
  "/opt/platform-docker-worker/docker-action-worker-runtime-guard.mjs";
const EXPECTED_WORKER_ENTRYPOINT = Object.freeze([
  "node",
  "--import",
  WORKER_RUNTIME_GUARD_CONTAINER_PATH,
  WORKER_CONTAINER_PATH,
]);
const EXPECTED_BROKER_IMAGE_ENTRYPOINT = Object.freeze([
  "node",
  "/opt/platform-docker-broker/docker-action-broker.mjs",
]);
const EXPECTED_NODE_IMAGE_REFERENCE =
  "node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606";
const EXPECTED_DOCKERFILE_FRONTEND_REFERENCE =
  "docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e";
const FIXED_ADAPTER_SOURCE_DIRECTORY = "scripts/docker-action-adapters";
const SUPPLY_CHAIN_LOCK_PATH = path.join(
  path.resolve(scriptDir, ".."),
  "governance",
  "supply-chain-lock.json",
);
const EXPECTED_COMMAND_BY_ACTION_PHASE = Object.freeze({
  "backup.catalog\0catalog.capture": "backup-catalog",
  "backup.job.execute\0job.backup.capture": "backup-job",
  "backup.job.execute\0job.restore.verify": "restore-job",
  "backup.prune.apply\0prune.apply": "backup-prune-apply",
  "backup.prune.plan\0prune.plan": "backup-prune-plan",
  "restore.drill.full\0restore.capture": "backup-catalog",
  "restore.drill.full\0restore.verify": "restore-drill-full",
  "backup.offsite.sync\0offsite.sync": "backup-offsite-sync",
});
const GLOBAL_REACHABILITY_SNAPSHOT_SOURCE = String.raw`
function globalReachabilityShape() {
  const sentinel = Symbol.for("platform.worker.socketless-guard-count");
  const skippedGlobalNames = new Set();
  const skippedProcessNames = new Set(["stdin", "stdout", "stderr"]);
  const keyLabel = (key) => typeof key === "symbol"
    ? "symbol:" + (Symbol.keyFor(key) ?? "") + ":" + (key.description ?? "")
    : "string:" + key;
  const functionLabel = (value) => {
    if (typeof value !== "function") return typeof value;
    try {
      return "function:"
        + JSON.stringify(String(value.name))
        + ":"
        + JSON.stringify(Function.prototype.toString.call(value));
    } catch {
      return "function:<uninspectable>";
    }
  };
  const descriptorLabel = (descriptor) => {
    if (Object.hasOwn(descriptor, "value")) {
      return "data:" + (
        typeof descriptor.value === "function"
          ? functionLabel(descriptor.value)
          : typeof descriptor.value
      );
    }
    return "accessor:get=" + functionLabel(descriptor.get)
      + ":set=" + functionLabel(descriptor.set);
  };
  const rows = [];
  const cryptoDescriptor =
    Object.getOwnPropertyDescriptor(globalThis, "crypto");
  if (!cryptoDescriptor || typeof cryptoDescriptor.get !== "function") {
    throw new Error("global reachability snapshot requires the crypto accessor");
  }
  const firstCryptoAccessorValue = Reflect.get(globalThis, "crypto");
  const secondCryptoAccessorValue = Reflect.get(globalThis, "crypto");
  if (
    firstCryptoAccessorValue === null
    || (
      typeof firstCryptoAccessorValue !== "object"
      && typeof firstCryptoAccessorValue !== "function"
    )
    || !Object.is(firstCryptoAccessorValue, secondCryptoAccessorValue)
  ) {
    throw new Error(
      "global reachability snapshot requires one stable crypto accessor value",
    );
  }
  const queue = [[
    firstCryptoAccessorValue,
    0,
    "accessor-root:string:crypto",
    false,
  ]];
  rows.push(
    "0|accessor-root:string:crypto|"
      + (
        typeof firstCryptoAccessorValue === "function"
          ? functionLabel(firstCryptoAccessorValue)
          : typeof firstCryptoAccessorValue
      ),
  );
  const rootKeys = Reflect.ownKeys(globalThis)
    .sort((left, right) => keyLabel(left).localeCompare(keyLabel(right)));
  for (const key of rootKeys) {
    if (key === sentinel) continue;
    if (typeof key === "string" && skippedGlobalNames.has(key)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
    if (!descriptor) continue;
    const rootLabel = keyLabel(key);
    rows.push("0|" + rootLabel + "|" + descriptorLabel(descriptor));
    if (Object.hasOwn(descriptor, "value")) {
      queue.push([descriptor.value, 0, rootLabel, key === "process"]);
    }
  }
  const seen = new WeakSet();
  let scanCount = 0;
  while (queue.length > 0) {
    const [value, depth, parentLabel, processRoot] = queue.shift();
    if (
      value === null
      || (typeof value !== "object" && typeof value !== "function")
      || seen.has(value)
    ) {
      continue;
    }
    if (scanCount >= 32768) {
      throw new Error("global reachability snapshot exceeded its object bound");
    }
    seen.add(value);
    scanCount += 1;
    let descriptors;
    try {
      descriptors = Object.getOwnPropertyDescriptors(value);
    } catch {
      rows.push(String(depth + 1) + "|" + parentLabel + "|<uninspectable>");
      continue;
    }
    const nestedKeys = Reflect.ownKeys(descriptors)
      .sort((left, right) => keyLabel(left).localeCompare(keyLabel(right)));
    for (const nestedKey of nestedKeys) {
      if (value === globalThis) {
        if (nestedKey === sentinel) continue;
        if (
          typeof nestedKey === "string"
          && skippedGlobalNames.has(nestedKey)
        ) {
          continue;
        }
      }
      if (
        processRoot
        && typeof nestedKey === "string"
        && skippedProcessNames.has(nestedKey)
      ) {
        continue;
      }
      const nestedLabel = parentLabel + ">" + keyLabel(nestedKey);
      const nestedDescriptor = descriptors[nestedKey];
      rows.push(
        String(depth + 1)
          + "|"
          + nestedLabel
          + "|"
          + descriptorLabel(nestedDescriptor),
      );
      if (Object.hasOwn(nestedDescriptor, "value")) {
        queue.push([
          nestedDescriptor.value,
          depth + 1,
          nestedLabel,
          processRoot,
        ]);
      }
    }
    let prototype;
    try {
      prototype = Object.getPrototypeOf(value);
    } catch {
      throw new Error("global reachability snapshot encountered an uninspectable prototype");
    }
    rows.push(
      String(depth + 1)
        + "|"
        + parentLabel
        + ">[[Prototype]]|"
        + (
          typeof prototype === "function"
            ? functionLabel(prototype)
            : typeof prototype
        ),
    );
    queue.push([
      prototype,
      depth + 1,
      parentLabel + ">[[Prototype]]",
      processRoot,
    ]);
  }
  rows.push("scan-count|" + scanCount);
  return rows.sort();
}
`;

const GLOBAL_REACHABILITY_IDENTITY_SOURCE = String.raw`
function captureGlobalReachabilityIdentities() {
  const sentinel = Symbol.for("platform.worker.socketless-guard-count");
  const cryptoDescriptor =
    Object.getOwnPropertyDescriptor(globalThis, "crypto");
  if (!cryptoDescriptor || typeof cryptoDescriptor.get !== "function") {
    throw new Error("global identity snapshot requires the crypto accessor");
  }
  const firstCryptoAccessorValue = Reflect.get(globalThis, "crypto");
  const secondCryptoAccessorValue = Reflect.get(globalThis, "crypto");
  if (
    firstCryptoAccessorValue === null
    || (
      typeof firstCryptoAccessorValue !== "object"
      && typeof firstCryptoAccessorValue !== "function"
    )
    || !Object.is(firstCryptoAccessorValue, secondCryptoAccessorValue)
  ) {
    throw new Error(
      "global identity snapshot requires one stable crypto accessor value",
    );
  }
  const queue = [globalThis, firstCryptoAccessorValue];
  const seen = new WeakSet();
  const owners = [];
  let scanCount = 0;
  while (queue.length > 0) {
    const owner = queue.shift();
    if (
      owner === null
      || (typeof owner !== "object" && typeof owner !== "function")
      || seen.has(owner)
    ) {
      continue;
    }
    if (scanCount >= 32768) {
      throw new Error("global identity snapshot exceeded its object bound");
    }
    seen.add(owner);
    scanCount += 1;
    let descriptors;
    try {
      descriptors = Object.getOwnPropertyDescriptors(owner);
    } catch {
      throw new Error("global identity snapshot encountered an uninspectable owner");
    }
    const keys = Reflect.ownKeys(descriptors)
      .filter((key) => owner !== globalThis || key !== sentinel);
    let prototype;
    try {
      prototype = Object.getPrototypeOf(owner);
    } catch {
      throw new Error("global identity snapshot encountered an uninspectable prototype");
    }
    owners.push({
      descriptors: new Map(keys.map((key) => [key, descriptors[key]])),
      keys,
      owner,
      prototype,
    });
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (Object.hasOwn(descriptor, "value")) {
        queue.push(descriptor.value);
      }
    }
    queue.push(prototype);
  }
  return { owners, scanCount };
}

function assertGlobalReachabilityIdentitiesUnchanged(snapshot) {
  for (const expected of snapshot.owners) {
    let descriptors;
    try {
      descriptors = Object.getOwnPropertyDescriptors(expected.owner);
    } catch {
      throw new Error("global reachability identity owner became uninspectable");
    }
    let prototype;
    try {
      prototype = Object.getPrototypeOf(expected.owner);
    } catch {
      throw new Error("global reachability identity prototype became uninspectable");
    }
    if (prototype !== expected.prototype) {
      throw new Error("global reachability identity prototype changed");
    }
    const currentKeys = Reflect.ownKeys(descriptors)
      .filter((key) =>
        expected.owner !== globalThis
        || key !== Symbol.for("platform.worker.socketless-guard-count"));
    if (
      currentKeys.length !== expected.keys.length
      || currentKeys.some((key) => !expected.keys.includes(key))
    ) {
      throw new Error("global reachability identity key set changed");
    }
    for (const key of expected.keys) {
      const before = expected.descriptors.get(key);
      const after = descriptors[key];
      if (
        !after
        || before.configurable !== after.configurable
        || before.enumerable !== after.enumerable
        || (
          Object.hasOwn(before, "value")
          !== Object.hasOwn(after, "value")
        )
        || (
          Object.hasOwn(before, "value")
          && (
            before.writable !== after.writable
            || !Object.is(before.value, after.value)
          )
        )
        || (
          !Object.hasOwn(before, "value")
          && (
            before.get !== after.get
            || before.set !== after.set
          )
        )
      ) {
        throw new Error(
          "global reachability identity changed at "
            + (typeof key === "symbol" ? String(key) : key),
        );
      }
    }
  }
}
`;

let cachedPlainGlobalReachabilityShape;

function plainGlobalReachabilityShape() {
  if (cachedPlainGlobalReachabilityShape) {
    return cachedPlainGlobalReachabilityShape;
  }
  const observed = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `${GLOBAL_REACHABILITY_SNAPSHOT_SOURCE}
await import("node:child_process");
const baselineModule = await import("node:module");
baselineModule.registerHooks({
  resolve(specifier, context, nextResolve) {
    return nextResolve(specifier, context);
  },
});
function baselineBlocked(label) {
  return () => {
    throw new Error("socketless runtime guard blocked " + label);
  };
}
const BaselineOriginalFunction = globalThis.Function;
const BaselineFunctionPrototype = BaselineOriginalFunction.prototype;
const BaselineAsyncFunctionPrototype =
  Object.getPrototypeOf(async function () {});
const BaselineGeneratorFunctionPrototype =
  Object.getPrototypeOf(function* () {});
const BaselineAsyncGeneratorFunctionPrototype =
  Object.getPrototypeOf(async function* () {});
const baselineConstructorIntrinsics = [
  ["Function", BaselineFunctionPrototype.constructor, BaselineFunctionPrototype],
  [
    "AsyncFunction",
    BaselineAsyncFunctionPrototype.constructor,
    BaselineAsyncFunctionPrototype,
  ],
  [
    "GeneratorFunction",
    BaselineGeneratorFunctionPrototype.constructor,
    BaselineGeneratorFunctionPrototype,
  ],
  [
    "AsyncGeneratorFunction",
    BaselineAsyncGeneratorFunctionPrototype.constructor,
    BaselineAsyncGeneratorFunctionPrototype,
  ],
];
const baselineGuardedConstructors = new Map();
for (const [name, intrinsic, prototype] of baselineConstructorIntrinsics) {
  const guarded = new Proxy(intrinsic, {
    apply: baselineBlocked(name),
    construct: baselineBlocked(name),
  });
  Object.defineProperty(prototype, "constructor", {
    configurable: true,
    value: guarded,
    writable: true,
  });
  baselineGuardedConstructors.set(name, guarded);
}
Object.defineProperty(globalThis, "Function", {
  configurable: true,
  value: baselineGuardedConstructors.get("Function"),
  writable: true,
});
for (const name of ["eval", "fetch", "WebSocket", "EventSource"]) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value: baselineBlocked(name),
    writable: true,
  });
}
for (const name of [
  "getBuiltinModule",
  "binding",
  "_linkedBinding",
  "dlopen",
  "execve",
  "_getActiveHandles",
  "_getActiveRequests",
]) {
  Object.defineProperty(process, name, {
    configurable: true,
    value: baselineBlocked("process." + name),
    writable: true,
  });
}
baselineModule.syncBuiltinESMExports();
void globalThis.fetch;
const baselineCrypto = await import("node:crypto");
const baselineRows = globalReachabilityShape();
process.stdout.write(JSON.stringify({
  digest: baselineCrypto
    .createHash("sha256")
    .update(JSON.stringify(baselineRows))
    .digest("hex"),
  rowCount: baselineRows.length,
}));`,
    ],
    {
      encoding: "utf8",
      env: {
        HOME: os.tmpdir(),
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
  assert.deepEqual(
    {
      signal: observed.signal,
      status: observed.status,
      stderr: observed.stderr,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
    },
    "plain Node global reachability baseline failed",
  );
  cachedPlainGlobalReachabilityShape = Object.freeze(
    JSON.parse(observed.stdout),
  );
  return cachedPlainGlobalReachabilityShape;
}

function assertNoGlobalDeregistrationHandleSource() {
  const baseline = JSON.stringify(plainGlobalReachabilityShape());
  return `
${GLOBAL_REACHABILITY_SNAPSHOT_SOURCE}
if (typeof exactGlobalReachabilityIdentitySnapshot !== "undefined") {
  assertGlobalReachabilityIdentitiesUnchanged(
    exactGlobalReachabilityIdentitySnapshot,
  );
}
const expectedGlobalReachabilityShape = ${baseline};
const reachabilityCrypto = await import("node:crypto");
const observedGlobalReachabilityRows = globalReachabilityShape();
const observedGlobalReachabilityShape = {
  digest: reachabilityCrypto
    .createHash("sha256")
    .update(JSON.stringify(observedGlobalReachabilityRows))
    .digest("hex"),
  rowCount: observedGlobalReachabilityRows.length,
};
if (
  JSON.stringify(observedGlobalReachabilityShape)
  !== JSON.stringify(expectedGlobalReachabilityShape)
) {
  throw new Error(
    "global reachability shape changed outside the exact guard allowlist: expected="
      + JSON.stringify(expectedGlobalReachabilityShape)
      + " observed="
      + JSON.stringify(observedGlobalReachabilityShape),
  );
}
const handleCryptoDescriptor =
  Object.getOwnPropertyDescriptor(globalThis, "crypto");
if (!handleCryptoDescriptor || typeof handleCryptoDescriptor.get !== "function") {
  throw new Error("global reachability handle scan requires the crypto accessor");
}
const firstHandleCryptoValue = Reflect.get(globalThis, "crypto");
const secondHandleCryptoValue = Reflect.get(globalThis, "crypto");
if (
  firstHandleCryptoValue === null
  || (
    typeof firstHandleCryptoValue !== "object"
    && typeof firstHandleCryptoValue !== "function"
  )
  || !Object.is(firstHandleCryptoValue, secondHandleCryptoValue)
) {
  throw new Error(
    "global reachability handle scan requires one stable crypto accessor value",
  );
}
const handleQueue = [[firstHandleCryptoValue, 0], ...Reflect.ownKeys(globalThis).flatMap((key) => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
  return descriptor && Object.hasOwn(descriptor, "value")
    ? [[descriptor.value, 0]]
    : [];
})];
const handleSeen = new WeakSet();
let handleLeak = false;
let handleScanCount = 0;
const functionFingerprint = (value) => {
  if (typeof value !== "function") return "";
  try {
    return String(value.name) + String.fromCharCode(10)
      + Function.prototype.toString.call(value);
  } catch {
    return "";
  }
};
while (handleQueue.length > 0 && handleScanCount < 32768) {
  const [value, depth] = handleQueue.shift();
  if (
    value === null
    || (typeof value !== "object" && typeof value !== "function")
    || handleSeen.has(value)
  ) {
    continue;
  }
  handleSeen.add(value);
  handleScanCount += 1;
  if (/deregister/i.test(functionFingerprint(value))) {
    handleLeak = true;
    break;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const deregister = descriptors.deregister;
  if (
    deregister
    && (
      (Object.hasOwn(deregister, "value") && typeof deregister.value === "function")
      || typeof deregister.get === "function"
    )
  ) {
    handleLeak = true;
    break;
  }
  if (
    Object.values(descriptors).some((descriptor) =>
      /deregister/i.test(functionFingerprint(descriptor.get))
      || /deregister/i.test(functionFingerprint(descriptor.set)))
  ) {
    handleLeak = true;
    break;
  }
  for (const descriptor of Object.values(descriptors)) {
    if (Object.hasOwn(descriptor, "value")) {
      handleQueue.push([descriptor.value, depth + 1]);
    }
  }
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    throw new Error("global reachability handle scan encountered an uninspectable prototype");
  }
  handleQueue.push([prototype, depth + 1]);
}
if (handleLeak) throw new Error("resolution handle leaked through global reachability");
if (handleQueue.length > 0) {
  throw new Error("global reachability handle scan exceeded its object bound");
}
`;
}

function assertRuntimeGuardRejectsDirectNetworkImport(
  runGuardedSource,
  label = "runtime guard",
) {
  const rejected = runGuardedSource('await import("node:net");');
  assert.notEqual(
    rejected.status,
    0,
    `${label} admitted direct node:net module resolution`,
  );
  assert.match(
    rejected.stderr,
    /socketless runtime guard blocked module resolution: node:net/i,
    `${label} rejected node:net outside its registered resolver boundary`,
  );
}

function assertRuntimeGuardLexicalHandleDiscipline(source, label) {
  assert.equal(
    String(source),
    socketlessRuntimeGuardSource(),
    `${label} must match the exact canonical socketless runtime-guard source`,
  );
  assert.equal(
    (String(source).match(/\bregisterHooks\s*\(/g) ?? []).length,
    1,
    `${label} must register exactly one resolution hook`,
  );
  assert.match(
    source,
    /\bconst\s+resolutionHookRegistration\s*=\s*registerHooks\s*\(\s*\{/,
    `${label} must retain the one hook handle in the exact lexical binding`,
  );
  assert.equal(
    (String(source).match(/\bresolutionHookRegistration\b/g) ?? []).length,
    2,
    `${label} may reference its lexical hook handle only for binding and validation`,
  );
  assert.doesNotMatch(
    source,
    /platform\.worker\.socketless-resolution-hook/,
    `${label} exposes a deregistration handle through a global symbol`,
  );
  for (const [capability, pattern] of [
    [
      "ChildProcess constructor export",
      /\bchildProcess\.ChildProcess\s*=\s*undefined\s*;/,
    ],
    [
      "ChildProcess internal fork export",
      /\bchildProcess\._forkChild\s*=\s*undefined\s*;/,
    ],
    [
      "Module prototype compiler",
      /\bmoduleBuiltin\.prototype\._compile\s*=\s*blocked\("module\._compile"\)\s*;/,
    ],
    [
      "Module prototype loader",
      /\bmoduleBuiltin\.prototype\.load\s*=\s*blocked\("module\.load"\)\s*;/,
    ],
    [
      "Module main loader",
      /\bmoduleBuiltin\.runMain\s*=\s*blocked\("module\.runMain"\)\s*;/,
    ],
    [
      "Module extension registry",
      /\bmoduleBuiltin\._extensions\s*=\s*Object\.freeze\(Object\.create\(null\)\)\s*;/,
    ],
    [
      "Module preload loader",
      /\bmoduleBuiltin\._preloadModules\s*=\s*blocked\("module\._preloadModules"\)\s*;/,
    ],
    [
      "builtin export resynchronizer",
      /\bmoduleBuiltin\.syncBuiltinESMExports\s*=\s*undefined\s*;/,
    ],
  ]) {
    assert.match(
      source,
      pattern,
      `${label} exposes the original ${capability}`,
    );
  }
}

function runRuntimeGuardGlobalIdentityBoundary(guardPath, root) {
  const guardUrl = pathToFileURL(guardPath).href;
  return spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `${GLOBAL_REACHABILITY_IDENTITY_SOURCE}
await import("node:child_process");
const observedModuleNamespace = await import("node:module");
const observedModuleBuiltin = observedModuleNamespace.default;
const originalObservedRegisterHooks = observedModuleBuiltin.registerHooks;
let observedRegisterHooksCallCount = 0;
observedModuleBuiltin.registerHooks = function (...args) {
  observedRegisterHooksCallCount += 1;
  return Reflect.apply(originalObservedRegisterHooks, observedModuleBuiltin, args);
};
observedModuleNamespace.syncBuiltinESMExports();
const OriginalFunction = globalThis.Function;
const allowedOwnersAndKeys = [
  [globalThis, "Function"],
  [globalThis, "eval"],
  [globalThis, "fetch"],
  [globalThis, "WebSocket"],
  [globalThis, "EventSource"],
  [OriginalFunction.prototype, "constructor"],
  [Object.getPrototypeOf(async function () {}), "constructor"],
  [Object.getPrototypeOf(function* () {}), "constructor"],
  [Object.getPrototypeOf(async function* () {}), "constructor"],
  [process, "getBuiltinModule"],
  [process, "binding"],
  [process, "_linkedBinding"],
  [process, "dlopen"],
  [process, "execve"],
  [process, "_getActiveHandles"],
  [process, "_getActiveRequests"],
  [process, "stdin"],
  [process, "stdout"],
  [process, "stderr"],
].map(([owner, key]) => ({
  descriptor: Object.getOwnPropertyDescriptor(owner, key),
  key,
  owner,
}));
const exactGlobalReachabilityIdentitySnapshot =
  captureGlobalReachabilityIdentities();
await import(${JSON.stringify(guardUrl)});
if (observedRegisterHooksCallCount !== 1) {
  throw new Error(
    "runtime guard registered "
      + observedRegisterHooksCallCount
      + " resolution hooks",
  );
}
for (const { descriptor, key, owner } of allowedOwnersAndKeys) {
  if (descriptor) {
    Object.defineProperty(owner, key, descriptor);
  } else {
    delete owner[key];
  }
}
delete globalThis[Symbol.for("platform.worker.socketless-guard-count")];
assertGlobalReachabilityIdentitiesUnchanged(
  exactGlobalReachabilityIdentitySnapshot,
);
process.stdout.write("identity-ok" + String.fromCharCode(10));`,
    ],
    {
      encoding: "utf8",
      env: {
        HOME: root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
}

// Test-only deterministic key material. These bytes are not deployment secrets.
const MANIFEST_TEST_KEY = Buffer.alloc(48, 0x4d);
const ARTIFACT_TEST_KEY = Buffer.alloc(48, 0x41);
const PRUNE_TEST_KEY = Buffer.alloc(48, 0x50);
const PRUNE_PLAN_DIGEST_DOMAIN =
  "platform.backup-prune-sealed-plan-digest/v1\0";
const PRUNE_PLAN_MAC_DOMAIN =
  "platform.backup-prune-sealed-plan-mac/v1\0";
const BACKUP_JOB_ID = "0123456789abcdef";
const BACKUP_JOB_CREATED_AT = "2026-07-28T11:59:00.000Z";
const REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const REQUEST_INDEX = 426614174000;
const SNAPSHOT_CONTAINER_PATH = "/run/platform/claimed-job/job.json";
const MAX_WORKER_ENV_ENTRY_BYTES = 32 * 1024;
const MAX_WORKER_ENV_TOTAL_BYTES = 64 * 1024;
const MAX_FIXED_ADAPTER_SOURCE_BYTES = 128 * 1024;
const EXPECTED_FIXED_ADAPTERS = Object.freeze({
  "backup-catalog": Object.freeze({
    api: "spawn",
    executable: "/opt/platform-docker-worker/bin/backup-catalog",
    argv: Object.freeze([]),
    shell: false,
  }),
  "backup-job": Object.freeze({
    api: "spawn",
    executable: "/opt/platform-docker-worker/bin/backup-job",
    argv: Object.freeze([]),
    shell: false,
  }),
  "backup-offsite-sync": Object.freeze({
    api: "spawn",
    executable: "/opt/platform-docker-worker/bin/backup-offsite-sync",
    argv: Object.freeze([]),
    shell: false,
  }),
  "backup-prune-apply": Object.freeze({
    api: "spawn",
    executable: "/opt/platform-docker-worker/bin/backup-prune-apply",
    argv: Object.freeze([]),
    shell: false,
  }),
  "backup-prune-plan": Object.freeze({
    api: "spawn",
    executable: "/opt/platform-docker-worker/bin/backup-prune-plan",
    argv: Object.freeze([]),
    shell: false,
  }),
  "restore-drill-full": Object.freeze({
    api: "spawn",
    executable: "/opt/platform-docker-worker/bin/restore-drill-full",
    argv: Object.freeze([]),
    shell: false,
  }),
  "restore-job": Object.freeze({
    api: "spawn",
    executable: "/opt/platform-docker-worker/bin/restore-job",
    argv: Object.freeze([]),
    shell: false,
  }),
});
function expectedFixedAdapterSource(command) {
  return `#!/usr/local/bin/node
import "../docker-action-worker-runtime-guard.mjs";

const { runFixedToolEntry } = await import("../docker-action-worker.mjs");
await runFixedToolEntry(${JSON.stringify(command)});
`;
}

const EXPECTED_FIXED_ADAPTER_SOURCE_TEXT = Object.freeze(
  Object.fromEntries(
    Object.keys(EXPECTED_FIXED_ADAPTERS).map((command) => [
      command,
      expectedFixedAdapterSource(command),
    ]),
  ),
);
const ALLOWED_WORKER_BUILTINS = new Set([
  "node:buffer",
  "node:child_process",
  "node:crypto",
  "node:events",
  "node:fs",
  "node:module",
  "node:path",
  "node:stream",
  "node:url",
  "node:util",
]);
const WORKER_TRUSTED_CONTEXT = buildFixtureTrustedContextV2().trusted;
const BACKUP_JOB_DOCUMENT = Object.freeze({
  ...createBackupJobDocument({
    id: BACKUP_JOB_ID,
    operation: "backup",
    scope: { kind: "platform", id: "platform" },
    resources: [{
      id: "source:platform",
      externalId: "platform",
      kind: "source",
      name: "platform",
      projectId: "platform",
      sourceDirectory: "platform",
    }],
    requestedBy: "scheduler-test",
    environment: "production",
    createdAt: BACKUP_JOB_CREATED_AT,
  }),
  status: "running",
  startedAt: BACKUP_JOB_CREATED_AT,
  resultSummary: "Claimed by the scheduler.",
});
parseBackupJobDocument(BACKUP_JOB_DOCUMENT);
const BACKUP_JOB_BYTES = Buffer.from(`${JSON.stringify(BACKUP_JOB_DOCUMENT, null, 2)}\n`);
const BACKUP_JOB_SHA256 = fixtureSha256(BACKUP_JOB_BYTES);
const BACKUP_SIGNED_REQUEST = buildFixtureSignedActionRequestV2(
  "backup.job.execute",
  backupJobParameters("backup"),
  {
    index: REQUEST_INDEX,
    trustedContext: WORKER_TRUSTED_CONTEXT,
  },
);
assert.equal(BACKUP_SIGNED_REQUEST.requestId, REQUEST_ID);
const REQUEST_SHA256 = signedRequestSha256(BACKUP_SIGNED_REQUEST);
const RESTORE_JOB_ID = "job-0123456789abcdef";
const RESTORE_JOB_DOCUMENT = Object.freeze({
  ...createBackupJobDocument({
    id: RESTORE_JOB_ID,
    operation: "restore-drill",
    scope: { kind: "platform", id: "platform" },
    resources: [{
      id: "source:platform",
      externalId: "platform",
      kind: "source",
      name: "platform",
      projectId: "platform",
      sourceDirectory: "platform",
    }],
    requestedBy: "scheduler-test",
    environment: "production",
    createdAt: BACKUP_JOB_CREATED_AT,
    sourceManifestPath: "manifests/restore-source.json",
  }),
  status: "running",
  startedAt: BACKUP_JOB_CREATED_AT,
  resultSummary: "Claimed by the scheduler.",
});
parseBackupJobDocument(RESTORE_JOB_DOCUMENT);
const RESTORE_JOB_BYTES = Buffer.from(`${JSON.stringify(RESTORE_JOB_DOCUMENT, null, 2)}\n`);
const RESTORE_JOB_SHA256 = fixtureSha256(RESTORE_JOB_BYTES);

const importedWorker = await importWorkerWithoutCliSideEffects();
const worker = importedWorker.namespace;
const exactWorkerBodyBaselineReady = hasExactWorkerBodyBaseline();

test("worker module is import-safe and exposes the complete fixed pure API", () => {
  const requiredFunctions = [
    "applyPruneTransition",
    "dispatchWorkerCommand",
    "loadClaimedJobSnapshot",
    "normalizeWorkerResult",
    "planPruneTransition",
    "readProtectedFile",
    "reverseCleanupOrder",
    "runFixedToolEntry",
    "runWorkerCli",
    "transitionOffsiteAttempt",
    "transitionRestorePhase",
    "verifyManifestEnvelope",
  ];
  assert.deepEqual({
    exitCode: importedWorker.exitCode,
    missingFunctions: requiredFunctions.filter((name) => typeof worker[name] !== "function"),
    stderr: importedWorker.stderr,
    validMaximumStdoutBytes: Number.isSafeInteger(worker.MAX_WORKER_STDOUT_BYTES)
      && worker.MAX_WORKER_STDOUT_BYTES >= 512
      && worker.MAX_WORKER_STDOUT_BYTES <= 4096,
  }, {
    exitCode: undefined,
    missingFunctions: [],
    stderr: "",
    validMaximumStdoutBytes: true,
  });
});

workerTest("fixed dispatcher admits exact commands and never derives shell argv from caller input", [
  "dispatchWorkerCommand",
], async () => {
  const dispatchWorkerCommand = requireWorkerFunction("dispatchWorkerCommand");
  const calls = [];
  const adapter = Object.freeze({
    runFixedTool: async (invocation) => {
      calls.push(structuredClone(invocation));
      return fixtureToolOutput(invocation.command, invocation.parameters);
    },
  });
  const commands = [
    ["backup-catalog", "backup", {}],
    ["backup-job", "backup", backupJobParameters("backup")],
    ["restore-job", "restore", backupJobParameters("restore-drill")],
    ["backup-prune-plan", "retention", {}],
    ["backup-prune-apply", "retention", {}],
    ["restore-drill-full", "restore", {}],
    ["backup-offsite-sync", "offsite", {}],
  ];

  for (const [command, profile, parameters] of commands) {
    const result = await dispatchWorkerCommand(command, parameters, adapter);
    const invocation = calls.at(-1);
    assert.deepEqual(
      Object.keys(invocation).sort(),
      ["argv", "command", "parameters", "profile", "shell"],
      `${command} fixed invocation schema`,
    );
    assert.equal(invocation.command, command);
    assert.equal(invocation.profile, profile);
    assert.equal(invocation.shell, false);
    assert.deepEqual(invocation.parameters, parameters);
    assert.ok(Array.isArray(invocation.argv) && invocation.argv.length >= 1);
    assert.equal(invocation.argv[0], command, `${command} must dispatch only its fixed executable identity`);
    assert.equal(
      invocation.argv.some((entry) => ["/bin/sh", "/bin/bash", "sh", "bash", "-c"].includes(entry)),
      false,
      `${command} must not cross a shell`,
    );
    assert.deepEqual(result, fixtureToolOutput(command, parameters));
  }

  const admittedCalls = calls.length;
  for (const [command, parameters] of [
    ["sh", {}],
    ["restore-full", {}],
    ["restore-drill-full", { argv: ["sh", "-c", "id"] }],
    ["backup-prune-plan", { command: "id" }],
    ["backup-offsite-sync", { shell: true }],
    ["backup-job", { ...backupJobParameters("backup"), executable: "/bin/sh" }],
  ]) {
    await assert.rejects(
      () => dispatchWorkerCommand(command, parameters, adapter),
      /unsupported|command|parameter|schema|shell|argv/i,
      `${command} must not widen the fixed dispatcher`,
    );
  }
  assert.equal(calls.length, admittedCalls, "rejected caller commands must never reach the tool adapter");
});

workerTest("CLI entrypoint delegates one fixed command and emits one bounded normalized document", [
  "runWorkerCli",
], async () => {
  const runWorkerCli = requireWorkerFunction("runWorkerCli");
  const toolCalls = [];
  let stdout = "";
  let stderr = "";
  const cliIdentity = {
    action: "restore.drill.full",
    phaseId: "restore.verify",
    requestId: REQUEST_ID,
  };
  const expectedRawResult = rawWorkerResult({
    ...cliIdentity,
    command: "restore-drill-full",
    job: null,
  });
  const result = await runWorkerCli(
    [process.execPath, workerPath, "restore-drill-full"],
    {
      writeStdout: (chunk) => { stdout += String(chunk); },
      writeStderr: (chunk) => { stderr += String(chunk); },
    },
    {
      env: workerCliEnvironment(cliIdentity),
      runFixedTool: async (invocation) => {
        toolCalls.push(structuredClone(invocation));
        return fixtureToolOutput(invocation.command, invocation.parameters);
      },
    },
  );
  assert.equal(result, 0);
  assert.equal(stderr, "");
  assert.equal(toolCalls.length, 1);
  assert.equal(toolCalls[0].command, "restore-drill-full");
  assert.equal(toolCalls[0].profile, "restore");
  assert.equal(toolCalls[0].shell, false);
  assert.equal(stdout, `${JSON.stringify(expectedRawResult)}\n`);

  await assert.rejects(
    () => runWorkerCli(
      [process.execPath, workerPath, "restore-drill-full", "--shell", "sh"],
      { writeStdout: () => {}, writeStderr: () => {} },
      {
        env: workerCliEnvironment(cliIdentity),
        runFixedTool: async () => assert.fail("hostile CLI input reached the tool adapter"),
      },
    ),
    /argument|command|parameter|unsupported/i,
  );
});

workerTest("CLI backup and restore jobs consume one exact protected snapshot before fixed dispatch", [
  "loadClaimedJobSnapshot",
  "runWorkerCli",
], async (t) => {
  const runWorkerCli = requireWorkerFunction("runWorkerCli");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-cli-jobs-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.chmodSync(root, 0o700);
  const uid = process.getuid?.() ?? fs.statSync(root).uid;
  const gid = process.getgid?.() ?? fs.statSync(root).gid;
  const cases = [
    {
      action: "backup.job.execute",
      bytes: BACKUP_JOB_BYTES,
      command: "backup-job",
      document: BACKUP_JOB_DOCUMENT,
      job: backupJobParameters("backup"),
      phaseId: "job.backup.capture",
    },
    {
      action: "backup.job.execute",
      bytes: RESTORE_JOB_BYTES,
      command: "restore-job",
      document: RESTORE_JOB_DOCUMENT,
      job: {
        jobFileName: `${RESTORE_JOB_ID}.json`,
        jobId: RESTORE_JOB_ID,
        jobOperation: "restore-drill",
        jobSha256: RESTORE_JOB_SHA256,
      },
      phaseId: "job.restore.verify",
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.command, async () => {
      const snapshotPath = path.join(root, `${fixture.command}.json`);
      fs.writeFileSync(snapshotPath, fixture.bytes, { mode: 0o400 });
      fs.chmodSync(snapshotPath, 0o400);
      const toolCalls = [];
      let stdout = "";
      let stderr = "";
      const identity = {
        action: fixture.action,
        job: fixture.job,
        phaseId: fixture.phaseId,
        requestId: REQUEST_ID,
      };
      const expected = rawWorkerResult({
        ...identity,
        command: fixture.command,
      });
      const exitCode = await runWorkerCli(
        [process.execPath, workerPath, fixture.command],
        {
          writeStdout: (chunk) => { stdout += String(chunk); },
          writeStderr: (chunk) => { stderr += String(chunk); },
        },
        {
          claimedJobPolicy: {
            expectedGid: gid,
            expectedMode: 0o400,
            expectedUid: uid,
            maximumBytes: 128 * 1024,
            parentRoot: root,
          },
          env: workerCliEnvironment({
            ...identity,
            snapshotPath,
          }),
          runFixedTool: async (invocation) => {
            toolCalls.push(structuredClone(invocation));
            assert.deepEqual(
              invocation.parameters,
              fixture.job,
              `${fixture.command} dispatcher lost the byte-bound claimed-job identity`,
            );
            return fixtureToolOutput(invocation.command, invocation.parameters);
          },
        },
      );

      assert.equal(exitCode, 0);
      assert.equal(stderr, "");
      assert.equal(stdout, `${JSON.stringify(expected)}\n`);
      assert.deepEqual(fs.readFileSync(snapshotPath), fixture.bytes);
      assert.equal(fs.statSync(snapshotPath).mode & 0o777, 0o400);
      assert.equal(toolCalls.length, 1, `${fixture.command} dispatched more than once`);
      assert.equal(toolCalls[0].command, fixture.command);
      assert.equal(toolCalls[0].shell, false);

      const rejectedTarget = `${snapshotPath}.target`;
      const assertRejectedBeforeDispatch = async (label, prepare, pattern) => {
        fs.rmSync(snapshotPath, { force: true });
        fs.rmSync(rejectedTarget, { force: true });
        prepare(rejectedTarget);
        let rejectedToolCalls = 0;
        await assert.rejects(
          () => runWorkerCli(
            [process.execPath, workerPath, fixture.command],
            { writeStdout: () => {}, writeStderr: () => {} },
            {
              claimedJobPolicy: {
                expectedGid: gid,
                expectedMode: 0o400,
                expectedUid: uid,
                maximumBytes: 128 * 1024,
                parentRoot: root,
              },
              env: workerCliEnvironment({
                ...identity,
                snapshotPath,
              }),
              runFixedTool: async () => {
                rejectedToolCalls += 1;
                return assert.fail(`${label} reached the fixed tool adapter`);
              },
            },
          ),
          pattern,
          `${fixture.command}/${label} did not fail at the protected snapshot boundary`,
        );
        assert.equal(
          rejectedToolCalls,
          0,
          `${fixture.command}/${label} dispatched a tool before snapshot admission`,
        );
      };

      await assertRejectedBeforeDispatch(
        "missing snapshot",
        () => {},
        /ENOENT|missing|open|file|snapshot/i,
      );
      await assertRejectedBeforeDispatch(
        "symlink snapshot",
        (target) => {
          fs.writeFileSync(target, fixture.bytes, { mode: 0o400 });
          fs.chmodSync(target, 0o400);
          fs.symlinkSync(target, snapshotPath);
        },
        /symlink|follow|regular|file|link/i,
      );
      await assertRejectedBeforeDispatch(
        "world-readable snapshot",
        () => {
          fs.writeFileSync(snapshotPath, fixture.bytes, { mode: 0o644 });
          fs.chmodSync(snapshotPath, 0o644);
        },
        /mode|permission|ownership/i,
      );
      await assertRejectedBeforeDispatch(
        "valid same-size digest substitution",
        () => {
          fs.writeFileSync(
            snapshotPath,
            validSameSizeClaimedJobTamper(fixture.document, fixture.bytes),
            { mode: 0o400 },
          );
          fs.chmodSync(snapshotPath, 0o400);
        },
        /digest|sha256/i,
      );
    });
  }
});

workerTest("protected-file reader enforces leaf and ancestor identity, mode, links and byte bounds", [
  "readProtectedFile",
], (t) => {
  const readProtectedFile = requireWorkerFunction("readProtectedFile");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-protected-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.chmodSync(root, 0o700);
  const uid = process.getuid?.() ?? fs.statSync(root).uid;
  const gid = process.getgid?.() ?? fs.statSync(root).gid;
  const file = path.join(root, "manifest.json");
  fs.writeFileSync(file, "{\"safe\":true}\n", { mode: 0o600 });
  const policy = protectedFilePolicy(root, uid, gid);

  assert.equal(Buffer.from(readProtectedFile(file, policy)).toString("utf8"), "{\"safe\":true}\n");

  const symlink = path.join(root, "manifest-link.json");
  fs.symlinkSync(file, symlink);
  assert.throws(() => readProtectedFile(symlink, policy), /symlink|follow|regular|file|link/i);

  const hardlink = path.join(root, "manifest-hardlink.json");
  fs.linkSync(file, hardlink);
  assert.throws(() => readProtectedFile(file, policy), /hardlink|link/i);
  fs.unlinkSync(hardlink);

  fs.chmodSync(file, 0o640);
  assert.throws(() => readProtectedFile(file, policy), /mode|permission/i);
  fs.chmodSync(file, 0o600);

  assert.throws(
    () => readProtectedFile(file, { ...policy, expectedUid: uid + 1 }),
    /owner|uid/i,
    "the same inode under a substituted owner attestation must fail",
  );
  assert.throws(
    () => readProtectedFile(file, { ...policy, expectedGid: gid + 1 }),
    /group|gid|owner/i,
    "the same inode under a substituted group attestation must fail",
  );

  fs.chmodSync(file, 0o400);
  assert.throws(
    () => readProtectedFile(file, policy),
    /mode|permission/i,
    "a private but non-exact leaf mode must fail",
  );
  fs.chmodSync(file, 0o600);

  const oversized = path.join(root, "oversized.json");
  fs.writeFileSync(oversized, Buffer.alloc(65, 0x61), { mode: 0o600 });
  assert.throws(
    () => readProtectedFile(oversized, { ...policy, maximumBytes: 64 }),
    /byte|size|oversized|maximum/i,
  );

  const unsafeParent = path.join(root, "unsafe-parent");
  fs.mkdirSync(unsafeParent, { mode: 0o700 });
  const unsafeChild = path.join(unsafeParent, "child.json");
  fs.writeFileSync(unsafeChild, "{}\n", { mode: 0o600 });
  fs.chmodSync(unsafeParent, 0o777);
  assert.throws(
    () => readProtectedFile(unsafeChild, policy),
    /ancestor|parent|directory|permission|mode/i,
  );

  const safeParent = path.join(root, "safe-parent");
  fs.mkdirSync(safeParent, { mode: 0o700 });
  const safeChild = path.join(safeParent, "child.json");
  fs.writeFileSync(safeChild, "{}\n", { mode: 0o600 });
  const parentAlias = path.join(root, "parent-alias");
  fs.symlinkSync(safeParent, parentAlias);
  assert.throws(
    () => readProtectedFile(path.join(parentAlias, "child.json"), policy),
    /ancestor|parent|symlink|canonical|realpath|directory/i,
  );

  const exactParent = path.join(root, "exact-parent");
  fs.mkdirSync(exactParent, { mode: 0o700 });
  const exactChild = path.join(exactParent, "child.json");
  fs.writeFileSync(exactChild, "{}\n", { mode: 0o600 });
  fs.chmodSync(exactParent, 0o500);
  assert.throws(
    () => readProtectedFile(exactChild, policy),
    /ancestor|parent|directory|permission|mode/i,
    "a private but non-exact ancestor mode must fail",
  );
  fs.chmodSync(exactParent, 0o700);

  for (const [label, targetPath, field, value] of [
    ["ancestor UID", exactParent, "uid", uid + 1],
    ["ancestor GID", exactParent, "gid", gid + 1],
    ["ancestor mode", exactParent, "mode", fs.statSync(exactParent).mode ^ 0o100],
  ]) {
    assert.throws(
      () => readProtectedFile(
        exactChild,
        policy,
        {
          io: statMutationIo(exactChild, {
            family: "path",
            field,
            targetPath,
            value,
          }),
        },
      ),
      /ancestor|parent|directory|owner|uid|gid|group|permission|mode|identity/i,
      `protected reader ignored isolated ${label} substitution`,
    );
  }

  assert.throws(
    () => readProtectedFile(
      file,
      policy,
      {
        io: statMutationIo(file, {
          family: "fstat",
          field: "isFile",
          targetPath: file,
          value: false,
        }),
      },
    ),
    /regular|file|identity|stat/i,
    "protected reader admitted a non-regular descriptor",
  );
  assert.throws(
    () => readProtectedFile(
      file,
      policy,
      {
        io: statMutationIo(file, {
          family: "fstat",
          field: "ino",
          targetPath: file,
          value: fs.lstatSync(file).ino + 1,
        }),
      },
    ),
    /identity|inode|ino|changed|race|stat/i,
    "protected reader ignored leaf lstat/fstat divergence",
  );
});

workerTest("protected-file reader rejects a same-size content swap even when descriptor stats appear stable", [
  "readProtectedFile",
], (t) => {
  const readProtectedFile = requireWorkerFunction("readProtectedFile");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-stable-read-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.chmodSync(root, 0o700);
  const uid = process.getuid?.() ?? fs.statSync(root).uid;
  const gid = process.getgid?.() ?? fs.statSync(root).gid;
  const file = path.join(root, "claimed-job.json");
  const original = Buffer.from('{"job":"original"}\n');
  const substituted = Buffer.from('{"job":"attacker"}\n');
  assert.equal(original.length, substituted.length, "race fixture must preserve byte length");
  fs.writeFileSync(file, original, { mode: 0o600 });

  const racing = sameSizeRaceIo(file, substituted);
  assert.throws(
    () => readProtectedFile(
      file,
      protectedFilePolicy(root, uid, gid),
      { io: racing.io },
    ),
    /changed|race|stable|substitution|content/i,
  );
  assert.deepEqual(
    {
      completedPassesBeforeSubstitution:
        racing.evidence.completedPassesBeforeSubstitution,
      substitutions: racing.evidence.substitutions,
    },
    { completedPassesBeforeSubstitution: 1, substitutions: 1 },
    "race fixture did not substitute exactly after the first complete descriptor pass",
  );
});

workerTest("worker loads the protected claimed-job file and binds its exact metadata and digest", [
  "loadClaimedJobSnapshot",
], (t) => {
  const loadClaimedJobSnapshot = requireWorkerFunction("loadClaimedJobSnapshot");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-load-claimed-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.chmodSync(root, 0o700);
  const uid = process.getuid?.() ?? fs.statSync(root).uid;
  const gid = process.getgid?.() ?? fs.statSync(root).gid;
  const file = path.join(root, "job.json");
  fs.writeFileSync(file, BACKUP_JOB_BYTES, { mode: 0o400 });
  fs.chmodSync(file, 0o400);
  const job = {
    jobFileName: `${BACKUP_JOB_ID}.json`,
    jobId: BACKUP_JOB_ID,
    jobOperation: "backup",
    jobSha256: BACKUP_JOB_SHA256,
  };
  const input = {
    env: workerCliEnvironment({
      action: "backup.job.execute",
      job,
      phaseId: "job.backup.capture",
      requestId: REQUEST_ID,
    }),
    policy: {
      expectedGid: gid,
      expectedMode: 0o400,
      expectedUid: uid,
      maximumBytes: 128 * 1024,
      parentRoot: root,
    },
    snapshotPath: file,
  };
  const stableReadObservation = observeDescriptorStableReadIo(file);
  const loaded = loadClaimedJobSnapshot(input, { io: stableReadObservation.io });
  assertStableReadEvidence(stableReadObservation.evidence);
  assert.deepEqual(loaded, {
    document: BACKUP_JOB_DOCUMENT,
    jobFileName: job.jobFileName,
    jobId: job.jobId,
    jobOperation: job.jobOperation,
    jobSha256: job.jobSha256,
    sourceId: "jobs.running",
  });

  const sameSizeTamper = validSameSizeClaimedJobTamper(
    BACKUP_JOB_DOCUMENT,
    BACKUP_JOB_BYTES,
  );
  for (const [label, env] of [
    ["job filename", {
      ...input.env,
      PLATFORM_CLAIMED_JOB_FILE_NAME: `${RESTORE_JOB_ID}.json`,
    }],
    ["job ID", {
      ...input.env,
      PLATFORM_CLAIMED_JOB_ID: RESTORE_JOB_ID,
    }],
    ["job operation", {
      ...input.env,
      PLATFORM_CLAIMED_JOB_OPERATION: "restore-drill",
    }],
    ["source ID", {
      ...input.env,
      PLATFORM_CLAIMED_JOB_SOURCE_ID: "jobs.attacker",
    }],
  ]) {
    assert.throws(
      () => loadClaimedJobSnapshot({ ...input, env }),
      /identity|filename|job|operation|source|parameter|metadata/i,
      `${label} substitution crossed claimed-job identity admission`,
    );
  }

  const racing = sameSizeRaceIo(file, sameSizeTamper);
  assert.throws(
    () => loadClaimedJobSnapshot(input, { io: racing.io }),
    /changed|race|stable|substitution|content/i,
    "claimed-job loading bypassed the descriptor-stable read boundary",
  );
  assert.deepEqual(
    {
      completedPassesBeforeSubstitution:
        racing.evidence.completedPassesBeforeSubstitution,
      substitutions: racing.evidence.substitutions,
    },
    { completedPassesBeforeSubstitution: 1, substitutions: 1 },
    "claimed-job race did not substitute exactly after the first complete descriptor pass",
  );
  fs.chmodSync(file, 0o600);
  fs.writeFileSync(file, BACKUP_JOB_BYTES);
  fs.chmodSync(file, 0o400);

  fs.chmodSync(file, 0o600);
  fs.writeFileSync(file, sameSizeTamper);
  fs.chmodSync(file, 0o400);
  assert.throws(
    () => loadClaimedJobSnapshot(input),
    /digest|sha256/i,
    "a contract-valid same-size substitution must reach the exact digest boundary",
  );
});

brokerTest("broker stable-reads the exact claimed queue document into an immutable worker snapshot", [
  "readClaimedJobSnapshot",
], (t) => {
  const readClaimedJobSnapshot = requireBrokerFunction("readClaimedJobSnapshot");
  const receipt = buildRawActiveReceiptV2();
  const canonicalSource = receipt.resources.claimedJobSources["jobs.running"];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-claimed-job-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.chmodSync(root, 0o700);
  const uid = process.getuid?.() ?? fs.statSync(root).uid;
  const gid = process.getgid?.() ?? fs.statSync(root).gid;
  const jobFile = path.join(root, `${BACKUP_JOB_ID}.json`);
  fs.writeFileSync(jobFile, BACKUP_JOB_BYTES, { mode: 0o600 });
  const parameters = backupJobParameters("backup");
  const source = { ...canonicalSource, brokerRoot: root };
  const input = {
    sourceId: "jobs.running",
    source,
    parameters,
    policy: {
      expectedUid: uid,
      expectedGid: gid,
      expectedMode: 0o600,
      maximumBytes: canonicalSource.maximumBytes,
      parentRoot: root,
    },
  };

  const snapshot = readClaimedJobSnapshot(input);
  assert.deepEqual(Object.keys(snapshot).sort(), [
    "bytes",
    "jobFileName",
    "jobId",
    "jobOperation",
    "jobSha256",
    "sourceId",
  ]);
  assert.equal(Buffer.isBuffer(snapshot.bytes), true);
  assert.deepEqual(snapshot.bytes, BACKUP_JOB_BYTES);
  assert.equal(snapshot.jobFileName, parameters.jobFileName);
  assert.equal(snapshot.jobId, parameters.jobId);
  assert.equal(snapshot.jobOperation, parameters.jobOperation);
  assert.equal(snapshot.jobSha256, parameters.jobSha256);
  assert.equal(snapshot.sourceId, "jobs.running");
  assert.ok(snapshot.bytes.length <= canonicalSource.maximumBytes);

  const sameSizeTamper = validSameSizeClaimedJobTamper(
    BACKUP_JOB_DOCUMENT,
    BACKUP_JOB_BYTES,
  );
  fs.writeFileSync(jobFile, sameSizeTamper);
  fs.chmodSync(jobFile, 0o600);
  assert.throws(
    () => readClaimedJobSnapshot(input),
    /digest|sha256/i,
    "the broker reader must reject a valid same-size document only at the digest boundary",
  );

  fs.writeFileSync(jobFile, BACKUP_JOB_BYTES);
  fs.chmodSync(jobFile, 0o600);
  assert.throws(
    () => readClaimedJobSnapshot({
      ...input,
      parameters: { ...parameters, jobFileName: `nested/${parameters.jobFileName}` },
    }),
    /filename|path|claimed|job|traversal/i,
  );
});

brokerTest("semantic executor stable-reads once, seals once, then binds the immutable job file into the worker body", [
  "createSemanticActionExecutor",
  "readClaimedJobSnapshot",
], async (t) => {
  const createSemanticActionExecutor = requireBrokerFunction("createSemanticActionExecutor");
  const readClaimedJobSnapshot = requireBrokerFunction("readClaimedJobSnapshot");
  const trusted = WORKER_TRUSTED_CONTEXT;
  const receipt = trusted.receipt;
  const request = BACKUP_SIGNED_REQUEST;
  const requestSha256 = signedRequestSha256(request);
  const source = receipt.resources.claimedJobSources["jobs.running"];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-read-once-"));
  const queueRoot = path.join(root, "queue");
  const brokerStateMountpoint = path.join(root, "broker-state");
  fs.mkdirSync(queueRoot, { mode: 0o700 });
  fs.mkdirSync(brokerStateMountpoint, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const uid = process.getuid?.() ?? fs.statSync(root).uid;
  const gid = process.getgid?.() ?? fs.statSync(root).gid;
  const sourceFile = path.join(queueRoot, `${BACKUP_JOB_ID}.json`);
  fs.writeFileSync(sourceFile, BACKUP_JOB_BYTES, { mode: 0o600 });
  fs.chmodSync(sourceFile, 0o600);

  let providerCalls = 0;
  let sealCalls = 0;
  let sourceBufferAfterSeal;
  let sealedHostPath;
  let sealedSnapshot;
  let createdBody;
  const transportCalls = [];
  const stableReadObservation = observeDescriptorStableReadIo(sourceFile);
  const phase = receipt.resources.phaseProfiles["job.backup.capture"];
  const expectedJobIdentity = {
    jobFileName: `${BACKUP_JOB_ID}.json`,
    jobId: BACKUP_JOB_ID,
    jobOperation: "backup",
    jobSha256: BACKUP_JOB_SHA256,
  };
  const rawResult = rawWorkerResult({
    action: "backup.job.execute",
    command: phase.command,
    job: expectedJobIdentity,
    phaseId: phase.phaseId,
    requestId: request.requestId,
  });
  const transport = semanticWorkerTransport({
    brokerStateMountpoint,
    expectedPhaseCase: () => ({
      action: "backup.job.execute",
      parameters: expectedJobIdentity,
      phaseId: "job.backup.capture",
      request,
      snapshot: sealedSnapshot,
    }),
    onCreateBody: (body) => {
      assert.ok(sealedSnapshot, "worker create occurred before the claimed job was sealed");
      assertExactWorkerBody({
        observedBody: body,
        phaseCase: {
          action: "backup.job.execute",
          parameters: expectedJobIdentity,
          phaseId: "job.backup.capture",
          request,
          snapshot: sealedSnapshot,
        },
        trusted,
      });
      createdBody = structuredClone(body);
    },
    rawWorkerResult: rawResult,
    receipt,
    calls: transportCalls,
    trusted,
  });
  const snapshotFileStore = {
    seal(snapshot, {
      request: admittedRequest,
      requestId,
      requestSha256: admittedRequestSha256,
      source: admittedSource,
      volumeInspect,
    } = {}) {
      sealCalls += 1;
      assert.deepEqual(admittedRequest, request);
      assert.equal(requestId, request.requestId);
      assert.equal(admittedRequestSha256, requestSha256);
      assert.deepEqual(admittedSource, source);
      assert.deepEqual(volumeInspect, {
        ...buildFixtureVolumeInspect(receipt, "broker.state"),
        Mountpoint: brokerStateMountpoint,
      });
      assert.equal(
        transportCalls.some(
          ({ method, name }) => method === "inspectVolume"
            && name === receipt.resources.volumes["broker.state"].engineName,
        ),
        true,
        "broker.state must be exact-inspected before snapshot materialization",
      );
      const sealedBytes = Buffer.from(snapshot.bytes);
      assert.equal(fixtureSha256(sealedBytes), snapshot.jobSha256);
      const directory = path.join(
        brokerStateMountpoint,
        source.snapshotVolumeSubpath,
        requestSha256,
      );
      fs.mkdirSync(directory, { mode: 0o700, recursive: true });
      sealedHostPath = path.join(directory, "job.json");
      fs.writeFileSync(sealedHostPath, sealedBytes, {
        flag: "wx",
        mode: 0o400,
      });
      fs.chmodSync(sealedHostPath, 0o400);
      snapshot.bytes.fill(0x78);
      sourceBufferAfterSeal = Buffer.from(snapshot.bytes);
      sealedSnapshot = Object.freeze({
        containerPath: source.snapshotContainerPath,
        hostPath: sealedHostPath,
        jobFileName: snapshot.jobFileName,
        jobId: snapshot.jobId,
        jobOperation: snapshot.jobOperation,
        jobSha256: snapshot.jobSha256,
        requestSha256,
        snapshotVolumeId: source.snapshotVolumeId,
        snapshotVolumeMountpoint: brokerStateMountpoint,
        snapshotVolumeName: receipt.resources.volumes[source.snapshotVolumeId].engineName,
        snapshotVolumeSubpath: source.snapshotVolumeSubpath,
        sourceId: snapshot.sourceId,
      });
      return sealedSnapshot;
    },
  };
  const executor = createSemanticActionExecutor({
    cleanupTimeoutMs: 100,
    claimedJobSnapshotProvider: async ({ parameters, sourceId }) => {
      providerCalls += 1;
      assert.equal(sourceId, "jobs.running");
      const snapshot = readClaimedJobSnapshot({
        parameters,
        policy: {
          expectedUid: uid,
          expectedGid: gid,
          expectedMode: 0o600,
          maximumBytes: source.maximumBytes,
          parentRoot: queueRoot,
        },
        source: { ...source, brokerRoot: queueRoot },
        sourceId,
      }, { io: stableReadObservation.io });
      assert.equal(Buffer.isBuffer(snapshot.bytes), true);
      return snapshot;
    },
    randomBytes: () => Buffer.alloc(12, 0x31),
    snapshotFileStore,
    transport,
  });
  const leaseEvents = [];
  const result = await executor.execute("backup.job.execute", {
    lease: {
      preserve: () => leaseEvents.push({ event: "preserve" }),
      recordEvent: (event) => leaseEvents.push(structuredClone(event)),
      recordWorker: (event) => leaseEvents.push({ event: "worker", ...structuredClone(event) }),
      release: () => leaseEvents.push({ event: "release" }),
    },
    parameters: backupJobParameters("backup"),
    request: structuredClone(request),
    requestId: request.requestId,
    requestSha256,
    signal: new AbortController().signal,
    trusted,
  });

  assert.equal(providerCalls, 1, "the queue consumer must capture one descriptor-stable snapshot");
  assert.equal(sealCalls, 1, "the broker must materialize one immutable snapshot file");
  assertStableReadEvidence(stableReadObservation.evidence);
  assert.equal(
    sourceBufferAfterSeal.length,
    BACKUP_JOB_BYTES.length,
    "post-capture mutation must preserve the admitted byte length",
  );
  assert.deepEqual(
    sourceBufferAfterSeal,
    Buffer.alloc(BACKUP_JOB_BYTES.length, 0x78),
    "post-capture mutation proof did not mutate the provider-owned buffer",
  );
  assert.deepEqual(
    fs.readFileSync(sealedHostPath),
    BACKUP_JOB_BYTES,
    "the broker-owned sealed file changed with the provider buffer",
  );
  assert.equal(fs.statSync(sealedHostPath).mode & 0o777, 0o400);
  const env = environmentMap(createdBody.Env);
  assert.equal(env.PLATFORM_CLAIMED_JOB_PATH, SNAPSHOT_CONTAINER_PATH);
  assert.equal(env.PLATFORM_CLAIMED_JOB_SHA256, BACKUP_JOB_SHA256);
  assert.equal(env.PLATFORM_DOCKER_REQUEST_ID, request.requestId);
  assert.equal(Object.hasOwn(env, "PLATFORM_CLAIMED_JOB_BASE64"), false);
  assert.equal(
    createdBody.HostConfig.Binds.includes(`${sealedHostPath}:${SNAPSHOT_CONTAINER_PATH}:ro`),
    true,
  );
  assert.equal(
    createdBody.HostConfig.Binds.some((bind) => bind === `${brokerStateMountpoint}:${SNAPSHOT_CONTAINER_PATH}:ro`),
    false,
    "the broker-state directory/volume itself must never be exposed to the worker",
  );
  assert.equal(
    transportCalls.filter(({ method }) => method === "createWorker").length,
    1,
    "the consumer seam did not reach worker creation exactly once",
  );
  assert.deepEqual(result, {
    schema: "platform.docker-action.result/v2",
    action: "backup.job.execute",
    job: expectedJobIdentity,
    phases: [{
      output: rawResult.output,
      outputSchema: phase.outputSchema,
      outputSha256: fixtureSha256(canonicalFixtureJson(rawResult.output)),
      phaseId: "job.backup.capture",
      status: "completed",
    }],
    status: "completed",
  });
});

test("workerCreateBody emits one exact phase-scoped body for every canonical phase", async (t) => {
  const trusted = WORKER_TRUSTED_CONTEXT;
  const cases = phaseActionCases(trusted);
  await Promise.all(cases.map((phaseCase) => t.test(
    `${phaseCase.action}/${phaseCase.phaseId}`,
    () => assertExactWorkerBody({ phaseCase, trusted }),
  )));
});

bodyMatrixTest("workerCreateBody never collapses operation phases into an action-wide authority union", () => {
  const trusted = WORKER_TRUSTED_CONTEXT;
  const cases = phaseActionCases(trusted);
  const backupCase = cases.find(({ phaseId }) => phaseId === "job.backup.capture");
  const restoreCase = cases.find(({ phaseId }) => phaseId === "job.restore.verify");
  const backupBody = broker.workerCreateBody({
    action: backupCase.action,
    claimedJobSnapshot: backupCase.snapshot,
    parameters: backupCase.parameters,
    phaseId: backupCase.phaseId,
    request: backupCase.request,
    requestId: backupCase.request.requestId,
    requestSha256: signedRequestSha256(backupCase.request),
    trusted,
  });
  const restoreBody = broker.workerCreateBody({
    action: restoreCase.action,
    claimedJobSnapshot: restoreCase.snapshot,
    parameters: restoreCase.parameters,
    phaseId: restoreCase.phaseId,
    request: restoreCase.request,
    requestId: restoreCase.request.requestId,
    requestSha256: signedRequestSha256(restoreCase.request),
    trusted,
  });
  const backupSerialized = canonicalFixtureJson(backupBody);
  const restoreSerialized = canonicalFixtureJson(restoreBody);

  assert.doesNotMatch(backupSerialized, /manifest-verification|restore-scratch|restore\.verify|platform_egress/);
  assert.doesNotMatch(restoreSerialized, /manifest-signing|project-sources|project-state|platform_db_admin|platform_storage/);
  assert.equal(backupBody.Labels["com.platform.docker-phase"], "job.backup.capture");
  assert.equal(restoreBody.Labels["com.platform.docker-phase"], "job.restore.verify");
  assert.notEqual(backupBody.Image, restoreBody.Image);

  const captureCase = cases.find(({ phaseId }) => phaseId === "restore.capture");
  const verifyCase = cases.find(({ phaseId }) => phaseId === "restore.verify");
  const capture = workerBodyForCase(captureCase, trusted);
  const verify = workerBodyForCase(verifyCase, trusted);
  assert.deepEqual(capture.Cmd, ["backup-catalog"]);
  assert.deepEqual(verify.Cmd, ["restore-drill-full"]);
  assert.notEqual(
    capture.Labels["com.platform.docker-phase-sha256"],
    verify.Labels["com.platform.docker-phase-sha256"],
  );
});

bodyMatrixTest("workerCreateBody bounds AUTHORITY_BASE64 and keeps the largest admissible environment below the aggregate limit", () => {
  const oversizedEntryReceipt = receiptWithAuthorityEntryAtLeast(
    MAX_WORKER_ENV_ENTRY_BYTES + 1,
  );
  const oversizedEntryTrusted = buildFixtureTrustedContextV2({
    rawReceipt: oversizedEntryReceipt,
  }).trusted;
  const oversizedEntryCase = phaseActionCases(oversizedEntryTrusted)
    .find(({ phaseId }) => phaseId === "job.backup.capture");
  const oversizedAuthority = expectedPhaseAuthority(
    oversizedEntryTrusted.receipt,
    oversizedEntryCase.action,
    oversizedEntryCase.phaseId,
  );
  const oversizedAuthorityEntry = authorityEnvironmentEntry(oversizedAuthority);
  assert.ok(
    environmentEntryBytes(oversizedAuthorityEntry) > MAX_WORKER_ENV_ENTRY_BYTES,
    "hostile authority fixture did not exceed the per-entry byte limit",
  );
  assert.ok(
    environmentEntryBytes(oversizedAuthorityEntry) < MAX_WORKER_ENV_TOTAL_BYTES,
    "per-entry hostile fixture must remain below the aggregate limit",
  );
  assert.throws(
    () => workerBodyForCase(oversizedEntryCase, oversizedEntryTrusted),
    /AUTHORITY_BASE64|environment.?entry|32768|oversized/i,
    "oversized authority crossed workerCreateBody without a per-entry rejection",
  );

  const nearLimitReceipt = receiptWithAuthorityEntryAtLeast(
    MAX_WORKER_ENV_ENTRY_BYTES - 512,
  );
  const nearLimitTrusted = buildFixtureTrustedContextV2({
    rawReceipt: nearLimitReceipt,
  }).trusted;
  const nearLimitCase = phaseActionCases(nearLimitTrusted)
    .find(({ phaseId }) => phaseId === "job.backup.capture");
  const phase = nearLimitTrusted.receipt.resources.phaseProfiles[nearLimitCase.phaseId];
  const authority = expectedPhaseAuthority(
    nearLimitTrusted.receipt,
    nearLimitCase.action,
    nearLimitCase.phaseId,
  );
  const expectedEnvironment = expectedWorkerEnvironment({
    action: nearLimitCase.action,
    authority,
    claimedJobSnapshot: nearLimitCase.snapshot,
    phase,
    phaseId: nearLimitCase.phaseId,
    requestId: nearLimitCase.request.requestId,
  });
  const nearLimitEntries = Object.entries(expectedEnvironment)
    .map(([name, value]) => `${name}=${value}`);
  const nearLimitSizes = nearLimitEntries.map(environmentEntryBytes);
  assert.ok(
    nearLimitSizes.every((size) => size <= MAX_WORKER_ENV_ENTRY_BYTES),
    "largest admissible fixture exceeded the per-entry limit",
  );
  assert.ok(
    nearLimitSizes.reduce((sum, size) => sum + size, 0) <= MAX_WORKER_ENV_TOTAL_BYTES,
    "largest admissible fixture exceeded the complete Env byte limit",
  );
  const nearLimitBody = workerBodyForCase(nearLimitCase, nearLimitTrusted);
  assert.deepEqual(nearLimitBody.Env, nearLimitEntries);
});

test("RED v2: the real broker-created worker body binds the production runtime guard", () => {
  const phaseCase = phaseActionCases(WORKER_TRUSTED_CONTEXT)
    .find(({ phaseId }) => phaseId === "prune.plan");
  assert.ok(phaseCase, "runtime-guard consumer RED lacks the prune.plan fixture");
  let legacyFallbackUsed = false;
  let body;
  try {
    body = workerBodyForCase(phaseCase, WORKER_TRUSTED_CONTEXT);
  } catch (error) {
    assert.match(error?.message ?? "", /worker policy mismatch/i);
    legacyFallbackUsed = true;
    body = broker.workerCreateBody({
      action: "backup.prune.plan",
      command: "backup-prune-plan",
      hostPath: "/srv/platform/backups",
      imageRef: "sha256:".concat("1".repeat(64)),
      intentId: "intent-runtime-guard-red",
      mountAttestation: {
        access: "ro",
        containerPath: "/data/backups",
        device: "1",
        hostPath: "/srv/platform/backups",
        inode: "2",
        kind: "directory",
        mode: "0700",
        ownerGid: 0,
        ownerUid: 0,
        symlinkFree: true,
      },
      receiptDigest: "2".repeat(64),
    });
  }
  assert.deepEqual(body.Entrypoint, EXPECTED_WORKER_ENTRYPOINT);
  assert.equal(
    legacyFallbackUsed,
    false,
    "runtime-guard body passed only through the obsolete worker policy surface",
  );
  assert.equal(
    body.Env.some((entry) => String(entry).startsWith("NODE_OPTIONS=")),
    false,
    "worker body may bind its guard only through the immutable Entrypoint",
  );
});

test("Dockerfile staging oracle excludes artifacts copied only by an unused build stage", (t) => {
  const repositoryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "docker-worker-final-stage-oracle-"),
  );
  t.after(() => fs.rmSync(repositoryRoot, { force: true, recursive: true }));
  const scriptsDirectory = path.join(repositoryRoot, "scripts");
  fs.mkdirSync(scriptsDirectory, { mode: 0o700 });
  fs.writeFileSync(
    path.join(scriptsDirectory, "decoy-guard.mjs"),
    "throw new Error('unused stage');\n",
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(scriptsDirectory, "docker-action-worker.mjs"),
    "process.stdout.write('final stage');\n",
    { mode: 0o600 },
  );
  const dockerfile = path.join(repositoryRoot, "Dockerfile");
  fs.writeFileSync(
    dockerfile,
    [
      "FROM node:fixture AS unused",
      `COPY scripts/decoy-guard.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
      "FROM node:fixture AS final",
      `COPY scripts/docker-action-worker.mjs ${WORKER_CONTAINER_PATH}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  const staged = stageDockerWorkerImageLayout(
    t,
    "docker-worker-final-stage-oracle-stage-",
    { dockerfile, repositoryRoot },
  );
  assert.equal(
    fs.existsSync(path.join(
      staged.root,
      WORKER_RUNTIME_GUARD_CONTAINER_PATH.replace(/^\/+/, ""),
    )),
    false,
    "staging oracle merged an unused Docker build stage into the final image",
  );
});

test("runtime-guard package oracle rejects every final-stage mutation of its immutable execution boundary", () => {
  const exactCopy =
    `COPY --chown=0:0 --chmod=0555 scripts/docker-action-worker-runtime-guard.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`;
  const entrypoint =
    `ENTRYPOINT ${JSON.stringify(EXPECTED_BROKER_IMAGE_ENTRYPOINT)}`;
  const control = ["FROM node:fixture", exactCopy, entrypoint, ""].join("\n");
  assert.doesNotThrow(() => assertFixtureFinalRuntimeGuardLayer(control));
  const canonicalProductionDockerfile = [
    `# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}`,
    ...canonicalProductionDockerfileInstructions(),
    "",
  ].join("\n");
  assert.doesNotThrow(
    () => assertFinalRuntimeGuardLayer(canonicalProductionDockerfile),
    "canonical production image manifest rejected its own exact instruction set",
  );
  for (const [label, instruction] of [
    [
      "non-root chown",
      `RUN chown 1000:1000 ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
    ],
    [
      "writable chmod",
      `RUN chmod 0777 ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
    ],
    [
      "replacement COPY",
      `COPY scripts/decoy.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
    ],
    [
      "replacement ADD",
      `ADD scripts/decoy.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
    ],
    [
      "runtime-obscuring VOLUME",
      "VOLUME /opt/platform-docker-worker",
    ],
    [
      "post-copy WORKDIR",
      "WORKDIR /opt/platform-docker-worker",
    ],
    [
      "deferred ONBUILD mutation",
      "ONBUILD RUN node /tmp/preload.mjs",
    ],
    [
      "NODE_OPTIONS preload",
      "ENV NODE_OPTIONS=--import=/tmp/preload.mjs",
    ],
    [
      "replacement entrypoint",
      'ENTRYPOINT ["node","/tmp/preload.mjs"]',
    ],
    [
      "worker entrypoint as the image default",
      `ENTRYPOINT ${JSON.stringify(EXPECTED_WORKER_ENTRYPOINT)}`,
    ],
    [
      "inherited command",
      'CMD ["node","/tmp/preload.mjs"]',
    ],
    [
      "executable healthcheck",
      "HEALTHCHECK CMD node /tmp/preload.mjs",
    ],
  ]) {
    assert.throws(
      () => assertFixtureFinalRuntimeGuardLayer(
        control.replace(entrypoint, `${instruction}\n${entrypoint}`),
      ),
      /canonical immutable image manifest/i,
      `runtime-guard package oracle admitted ${label}`,
    );
  }
  for (const [label, instruction] of [
    [
      "relocated NODE_OPTIONS preload",
      "ENV NODE_OPTIONS=--import=/tmp/preload.mjs",
    ],
    [
      "relocated deferred ONBUILD mutation",
      "ONBUILD RUN node /tmp/preload.mjs",
    ],
    [
      "relocated replacement entrypoint",
      'ENTRYPOINT ["node","/tmp/preload.mjs"]',
    ],
    [
      "relocated inherited command",
      'CMD ["node","/tmp/preload.mjs"]',
    ],
    [
      "relocated executable healthcheck",
      "HEALTHCHECK CMD node /tmp/preload.mjs",
    ],
  ]) {
    assert.throws(
      () => assertFixtureFinalRuntimeGuardLayer(
        control.replace(exactCopy, `${instruction}\n${exactCopy}`),
      ),
      /canonical immutable image manifest/i,
      `runtime-guard package oracle admitted ${label} before its guard COPY`,
    );
  }
  for (const [label, instruction] of [
    [
      "pre-guard Node interpreter replacement",
      "COPY scripts/evil-node /usr/local/bin/node",
    ],
    [
      "pre-guard Node wrapper installation",
      "RUN mv /usr/local/bin/node /usr/local/bin/node-real && install /tmp/evil-node /usr/local/bin/node",
    ],
    [
      "duplicate admitted-looking worker COPY",
      `COPY scripts/docker-action-worker.mjs ${WORKER_CONTAINER_PATH}`,
    ],
  ]) {
    assert.throws(
      () => assertFixtureFinalRuntimeGuardLayer(
        control.replace(exactCopy, `${instruction}\n${exactCopy}`),
      ),
      /canonical immutable image manifest/i,
      `runtime-guard package oracle admitted ${label}`,
    );
  }
  const heredocStageSpoof = [
    "FROM node:fixture",
    "ENV NODE_OPTIONS=--import=/tmp/preload.mjs",
    "COPY <<EOF /tmp/decoy",
    "FROM decoy",
    "EOF",
    exactCopy,
    entrypoint,
    "",
  ].join("\n");
  assert.throws(
    () => assertFixtureFinalRuntimeGuardLayer(heredocStageSpoof),
    /heredoc syntax is forbidden/i,
    "runtime-guard package oracle admitted a heredoc stage-boundary spoof",
  );
  const parserEscapeSpoof = [
    "# escape=`",
    "FROM node:fixture",
    "ARG SWALLOW=ignored`",
    exactCopy,
    entrypoint,
    "",
  ].join("\n");
  assert.throws(
    () => assertFixtureFinalRuntimeGuardLayer(parserEscapeSpoof),
    /parser directive/i,
    "runtime-guard package oracle admitted a parser-escape stage spoof",
  );
  const buildArgumentBaseImageSpoof = [
    `ARG NODE_IMAGE=${EXPECTED_NODE_IMAGE_REFERENCE}`,
    "FROM ${NODE_IMAGE}",
    exactCopy,
    entrypoint,
    "",
  ].join("\n");
  assert.throws(
    () => assertFixtureFinalRuntimeGuardLayer(buildArgumentBaseImageSpoof),
    /canonical immutable image manifest/i,
    "runtime-guard package oracle admitted an overrideable base-image build argument",
  );
  for (const [label, mutated, pattern] of [
    [
      "missing pinned frontend",
      canonicalProductionDockerfile
        .replace(`# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}\n`, ""),
      /first physical line|exact digest-pinned/i,
    ],
    [
      "altered frontend digest",
      canonicalProductionDockerfile.replace(
        EXPECTED_DOCKERFILE_FRONTEND_REFERENCE,
        EXPECTED_DOCKERFILE_FRONTEND_REFERENCE.replace(/.$/, "0"),
      ),
      /parser directive|exact digest-pinned/i,
    ],
    [
      "unpinned frontend tag",
      canonicalProductionDockerfile.replace(
        EXPECTED_DOCKERFILE_FRONTEND_REFERENCE,
        "docker/dockerfile:1.7",
      ),
      /parser directive|exact digest-pinned/i,
    ],
    [
      "misplaced frontend directive",
      canonicalProductionDockerfile.replace(
        `# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}\n`,
        `\n# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}\n`,
      ),
      /first physical line/i,
    ],
    [
      "duplicate frontend directive",
      canonicalProductionDockerfile.replace(
        `# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}\n`,
        `# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}\n# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}\n`,
      ),
      /exactly one Dockerfile frontend/i,
    ],
    [
      "dangling continuation",
      `${canonicalProductionDockerfile.trimEnd()} \\\n`,
      /ended inside a continued instruction/i,
    ],
    [
      "continuation trailing whitespace",
      canonicalProductionDockerfile.replace(
        "WORKDIR /opt/platform-docker-broker",
        "WORKDIR /opt/platform-docker-broker\\ ",
      ),
      /continuation escape must be the final physical byte/i,
    ],
  ]) {
    assert.throws(
      () => assertFinalRuntimeGuardLayer(mutated),
      pattern,
      `production image oracle admitted ${label}`,
    );
  }
});

test("global reachability oracle rejects renamed callable, accessor and nested deregistration capabilities", () => {
  const setup = `
import childProcess from "node:child_process";
import moduleBuiltin, { syncBuiltinESMExports } from "node:module";
const registration = moduleBuiltin.registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "node:net") {
      throw new Error("self-mutant resolver blocked node:net");
    }
    return nextResolve(specifier, context);
  },
});
function blocked(label) {
  return () => {
    throw new Error("socketless runtime guard blocked " + label);
  };
}
const OriginalFunction = globalThis.Function;
const FunctionPrototype = OriginalFunction.prototype;
const AsyncFunctionPrototype = Object.getPrototypeOf(async function () {});
const GeneratorFunctionPrototype = Object.getPrototypeOf(function* () {});
const AsyncGeneratorFunctionPrototype =
  Object.getPrototypeOf(async function* () {});
const constructorIntrinsics = [
  ["Function", FunctionPrototype.constructor, FunctionPrototype],
  [
    "AsyncFunction",
    AsyncFunctionPrototype.constructor,
    AsyncFunctionPrototype,
  ],
  [
    "GeneratorFunction",
    GeneratorFunctionPrototype.constructor,
    GeneratorFunctionPrototype,
  ],
  [
    "AsyncGeneratorFunction",
    AsyncGeneratorFunctionPrototype.constructor,
    AsyncGeneratorFunctionPrototype,
  ],
];
const guardedConstructors = new Map();
for (const [name, intrinsic, prototype] of constructorIntrinsics) {
  const guarded = new Proxy(intrinsic, {
    apply: blocked(name),
    construct: blocked(name),
  });
  Object.defineProperty(prototype, "constructor", {
    configurable: true,
    value: guarded,
    writable: true,
  });
  guardedConstructors.set(name, guarded);
}
Object.defineProperty(globalThis, "Function", {
  configurable: true,
  value: guardedConstructors.get("Function"),
  writable: true,
});
for (const name of ["eval", "fetch", "WebSocket", "EventSource"]) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value: blocked(name),
    writable: true,
  });
}
for (const name of ["getBuiltinModule", "binding", "_linkedBinding", "dlopen"]) {
  Object.defineProperty(process, name, {
    configurable: true,
    value: blocked("process." + name),
    writable: true,
  });
}
void childProcess;
syncBuiltinESMExports();
`;
  const oracle = assertNoGlobalDeregistrationHandleSource();
  const identityBaseline = `
${GLOBAL_REACHABILITY_IDENTITY_SOURCE}
const exactGlobalReachabilityIdentitySnapshot =
  captureGlobalReachabilityIdentities();
`;
  const run = (source) => spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", source],
    {
      encoding: "utf8",
      env: {
        HOME: os.tmpdir(),
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
  const positive = run(`${setup}
${identityBaseline}
${oracle}
process.stdout.write("oracle-ok" + String.fromCharCode(10));`);
  assert.deepEqual(
    {
      signal: positive.signal,
      status: positive.status,
      stderr: positive.stderr,
      stdout: positive.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "oracle-ok\n",
    },
    "global reachability oracle rejected its exact lexical-handle control",
  );

  for (const [label, expose, deregister] of [
    [
      "renamed bound callable",
      'const leakedKey = Symbol("renamed-callable"); globalThis[leakedKey] = registration.deregister.bind(registration);',
      "globalThis[leakedKey]();",
    ],
    [
      "renamed accessor",
      'const leakedKey = Symbol("renamed-accessor"); Object.defineProperty(globalThis, leakedKey, { configurable: true, get() { return registration; } });',
      "globalThis[leakedKey].deregister();",
    ],
    [
      "two nested wrappers",
      'const leakedKey = Symbol("renamed-nested"); globalThis[leakedKey] = { first: { second: registration } };',
      "globalThis[leakedKey].first.second.deregister();",
    ],
    [
      "existing configurable accessor",
      'const leakedKey = "crypto"; const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, leakedKey); if (!originalDescriptor?.configurable || typeof originalDescriptor.get !== "function") throw new Error("missing accessor control"); Object.defineProperty(globalThis, leakedKey, { configurable: originalDescriptor.configurable, enumerable: originalDescriptor.enumerable, get() { return registration; }, set: originalDescriptor.set });',
      "globalThis[leakedKey].deregister();",
    ],
    [
      "existing data-function slot",
      'const leakedKey = "fetch"; const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, leakedKey); const leakedCallable = registration.deregister.bind(registration); Object.defineProperty(leakedCallable, "name", { configurable: true, value: "run" }); Object.defineProperty(globalThis, leakedKey, { configurable: originalDescriptor.configurable, enumerable: originalDescriptor.enumerable, value: leakedCallable, writable: originalDescriptor.writable });',
      "globalThis[leakedKey]();",
    ],
    [
      "existing nested data-function slot",
      'const leakedOwner = globalThis.console.Console.prototype; const leakedKey = "log"; const originalDescriptor = Object.getOwnPropertyDescriptor(leakedOwner, leakedKey); if (!originalDescriptor || typeof originalDescriptor.value !== "function") throw new Error("missing nested function control"); const leakedCallable = registration.deregister.bind(registration); Object.defineProperty(leakedCallable, "name", { configurable: true, value: "log" }); Object.defineProperty(leakedOwner, leakedKey, { configurable: originalDescriptor.configurable, enumerable: originalDescriptor.enumerable, value: leakedCallable, writable: originalDescriptor.writable });',
      "globalThis.console.Console.prototype.log();",
    ],
    [
      "existing opaque bound-function slot",
      'const leakedOwner = globalThis.console; const leakedKey = "log"; const originalDescriptor = Object.getOwnPropertyDescriptor(leakedOwner, leakedKey); if (!originalDescriptor || typeof originalDescriptor.value !== "function") throw new Error("missing opaque function control"); const leakedCallable = registration.deregister.bind(registration); Object.defineProperty(leakedCallable, "name", { configurable: true, value: "log" }); Object.defineProperty(leakedOwner, leakedKey, { configurable: originalDescriptor.configurable, enumerable: originalDescriptor.enumerable, value: leakedCallable, writable: originalDescriptor.writable });',
      "globalThis.console.log();",
    ],
  ]) {
    const vulnerabilityControl = run(`${setup}
${expose}
${deregister}
await import("node:net");
process.stdout.write("bypass-ok" + String.fromCharCode(10));`);
    assert.deepEqual(
      {
        signal: vulnerabilityControl.signal,
        status: vulnerabilityControl.status,
        stderr: vulnerabilityControl.stderr,
        stdout: vulnerabilityControl.stdout,
      },
      {
        signal: null,
        status: 0,
        stderr: "",
        stdout: "bypass-ok\n",
      },
      `${label} is not a real resolver deregistration capability`,
    );
    const rejected = run(`${setup}
${identityBaseline}
${expose}
${oracle}
${deregister}
await import("node:net");`);
    assert.notEqual(rejected.status, 0, `${label} escaped the global oracle`);
    assert.match(
      rejected.stderr,
      /global reachability (?:shape|identity).*changed|resolution handle leaked through global reachability/i,
      `${label} failed outside the global reachability oracle`,
    );
  }

  const capExpose = `
const originalConsole = globalThis.console;
const expandedConsoleEntries = Object.create(null);
for (let index = 0; index < 40000; index += 1) {
  expandedConsoleEntries["k" + index] =
    index === 39999 ? registration : Object.create(null);
}
let consoleOwnKeysCalls = 0;
globalThis.console = new Proxy(originalConsole, {
  get(target, key, receiver) {
    if (Object.hasOwn(expandedConsoleEntries, key)) {
      return expandedConsoleEntries[key];
    }
    return Reflect.get(target, key, receiver);
  },
  getOwnPropertyDescriptor(target, key) {
    if (Object.hasOwn(expandedConsoleEntries, key)) {
      return {
        configurable: true,
        enumerable: true,
        value: expandedConsoleEntries[key],
        writable: true,
      };
    }
    return Reflect.getOwnPropertyDescriptor(target, key);
  },
  ownKeys(target) {
    consoleOwnKeysCalls += 1;
    return consoleOwnKeysCalls === 1
      ? Reflect.ownKeys(target)
      : [...Reflect.ownKeys(target), ...Object.keys(expandedConsoleEntries)];
  },
});
`;
  const capVulnerabilityControl = run(`${setup}
${capExpose}
globalThis.console.k39999.deregister();
await import("node:net");
process.stdout.write("cap-bypass-ok" + String.fromCharCode(10));`);
  assert.deepEqual(
    {
      signal: capVulnerabilityControl.signal,
      status: capVulnerabilityControl.status,
      stderr: capVulnerabilityControl.stderr,
      stdout: capVulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "cap-bypass-ok\n",
    },
    "stateful cap mutant is not a real resolver deregistration capability",
  );
  const capRejected = run(`${setup}
${capExpose}
${oracle}`);
  assert.notEqual(capRejected.status, 0, "stateful cap mutant escaped the oracle");
  assert.match(
    capRejected.stderr,
    /global reachability handle scan exceeded its object bound/i,
    "stateful cap mutant failed outside the fail-closed object bound",
  );

  const deepExpose = `
const originalConsole = globalThis.console;
let deepRegistration = registration;
for (let depth = 0; depth < 12; depth += 1) {
  deepRegistration = { next: deepRegistration };
}
let consoleOwnKeysCalls = 0;
globalThis.console = new Proxy(originalConsole, {
  get(target, key, receiver) {
    if (key === "hidden") return deepRegistration;
    return Reflect.get(target, key, receiver);
  },
  getOwnPropertyDescriptor(target, key) {
    if (key === "hidden") {
      return {
        configurable: true,
        enumerable: true,
        value: deepRegistration,
        writable: true,
      };
    }
    return Reflect.getOwnPropertyDescriptor(target, key);
  },
  ownKeys(target) {
    consoleOwnKeysCalls += 1;
    return consoleOwnKeysCalls === 1
      ? Reflect.ownKeys(target)
      : [...Reflect.ownKeys(target), "hidden"];
  },
});
`;
  const deepVulnerabilityControl = run(`${setup}
${deepExpose}
let leakedRegistration = globalThis.console.hidden;
for (let depth = 0; depth < 12; depth += 1) {
  leakedRegistration = leakedRegistration.next;
}
leakedRegistration.deregister();
await import("node:net");
process.stdout.write("deep-bypass-ok" + String.fromCharCode(10));`);
  assert.deepEqual(
    {
      signal: deepVulnerabilityControl.signal,
      status: deepVulnerabilityControl.status,
      stderr: deepVulnerabilityControl.stderr,
      stdout: deepVulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "deep-bypass-ok\n",
    },
    "stateful deep mutant is not a real resolver deregistration capability",
  );
  const deepRejected = run(`${setup}
${deepExpose}
${oracle}`);
  assert.notEqual(deepRejected.status, 0, "stateful deep mutant escaped the oracle");
  assert.match(
    deepRejected.stderr,
    /resolution handle leaked through global reachability/i,
    "stateful deep mutant failed outside the unbounded reachability walk",
  );
});

test("runtime-guard resolver oracle kills a registered no-op hook", (t) => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "docker-worker-noop-resolver-mutant-"),
  );
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const guardPath = path.join(root, "runtime-guard-noop-mutant.mjs");
  const exactResolveHeader =
    "  resolve(specifier, context, nextResolve) {\n";
  const source = socketlessRuntimeGuardSource();
  assertRuntimeGuardLexicalHandleDiscipline(
    source,
    "test-local runtime guard control",
  );
  const mutant = source.replace(
    exactResolveHeader,
    `${exactResolveHeader}    return nextResolve(specifier, context);\n`,
  );
  assert.notEqual(mutant, source, "no-op resolver mutant was not activated");
  fs.writeFileSync(guardPath, mutant, { mode: 0o600 });
  const runMutant = (snippet) => spawnSync(
    process.execPath,
    [
      "--import",
      pathToFileURL(guardPath).href,
      "--input-type=module",
      "--eval",
      snippet,
    ],
    {
      encoding: "utf8",
      env: {
        HOME: root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
  const vulnerabilityControl = runMutant(
    'await import("node:net"); process.stdout.write("noop-bypass\\n");',
  );
  assert.deepEqual(
    {
      signal: vulnerabilityControl.signal,
      status: vulnerabilityControl.status,
      stderr: vulnerabilityControl.stderr,
      stdout: vulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "noop-bypass\n",
    },
    "registered no-op hook is not a live direct-import bypass",
  );
  assert.throws(
    () => assertRuntimeGuardRejectsDirectNetworkImport(
      runMutant,
      "registered no-op hook mutant",
    ),
    /admitted direct node:net module resolution/i,
    "direct-import behavior oracle did not kill the no-op resolver mutant",
  );

  const exactHandleValidation =
    'if (typeof resolutionHookRegistration?.deregister !== "function") {';
  const leakMutant = source.replace(
    exactHandleValidation,
    `const leakedConsoleDeregister =
  resolutionHookRegistration.deregister.bind(resolutionHookRegistration);
Object.defineProperty(leakedConsoleDeregister, "name", {
  configurable: true,
  value: "log",
});
globalThis.console.log = leakedConsoleDeregister;
${exactHandleValidation}`,
  );
  assert.notEqual(leakMutant, source, "lexical-handle leak mutant was not activated");
  assert.throws(
    () => assertRuntimeGuardLexicalHandleDiscipline(
      leakMutant,
      "lexical-handle leak mutant",
    ),
    /exact canonical socketless runtime-guard source/i,
    "lexical source oracle admitted an opaque bound-handle leak",
  );
  const leakPath = path.join(root, "runtime-guard-handle-leak-mutant.mjs");
  fs.writeFileSync(leakPath, leakMutant, { mode: 0o600 });
  const leakedGuard = (snippet) => spawnSync(
    process.execPath,
    [
      "--import",
      pathToFileURL(leakPath).href,
      "--input-type=module",
      "--eval",
      snippet,
    ],
    {
      encoding: "utf8",
      env: {
        HOME: root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
  const leakVulnerabilityControl = leakedGuard(
    'globalThis.console.log(); await import("node:net"); process.stdout.write("leak-bypass\\n");',
  );
  assert.deepEqual(
    {
      signal: leakVulnerabilityControl.signal,
      status: leakVulnerabilityControl.status,
      stderr: leakVulnerabilityControl.stderr,
      stdout: leakVulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "leak-bypass\n",
    },
    "opaque bound-handle leak mutant is not a real resolver bypass",
  );
  const identityRejected = runRuntimeGuardGlobalIdentityBoundary(
    leakPath,
    root,
  );
  assert.notEqual(
    identityRejected.status,
    0,
    "same-process identity boundary admitted the opaque bound-handle leak",
  );
  assert.match(
    identityRejected.stderr,
    /global reachability identity changed at log/i,
    "opaque bound-handle leak failed outside the same-process identity boundary",
  );

  const exactRegisterHooksBlock =
    'moduleBuiltin.registerHooks = blocked("module.registerHooks");';
  const computedSecondRegistrationMutant = source.replace(
    exactRegisterHooksBlock,
    `void moduleBuiltin[["register", "Hooks"].join("")].call(moduleBuiltin, {
  resolve(specifier, context, nextResolve) {
    return nextResolve(specifier, context);
  },
});
${exactRegisterHooksBlock}`,
  );
  assert.notEqual(
    computedSecondRegistrationMutant,
    source,
    "computed second-registerHooks mutant was not activated",
  );
  assert.throws(
    () => assertRuntimeGuardLexicalHandleDiscipline(
      computedSecondRegistrationMutant,
      "computed second-registerHooks mutant",
    ),
    /exact canonical socketless runtime-guard source/i,
    "canonical source oracle admitted a computed second hook registration",
  );
  const computedSecondRegistrationPath = path.join(
    root,
    "runtime-guard-computed-second-registration-mutant.mjs",
  );
  fs.writeFileSync(
    computedSecondRegistrationPath,
    computedSecondRegistrationMutant,
    { mode: 0o600 },
  );
  const computedSecondRegistrationRejected =
    runRuntimeGuardGlobalIdentityBoundary(
      computedSecondRegistrationPath,
      root,
    );
  assert.notEqual(
    computedSecondRegistrationRejected.status,
    0,
    "dynamic hook-count boundary admitted a computed second registration",
  );
  assert.match(
    computedSecondRegistrationRejected.stderr,
    /runtime guard registered 2 resolution hooks/i,
    "computed second registration failed outside the real registerHooks boundary",
  );

  const exactRegisterHooksBinding =
    "const registerHooks = moduleBuiltin.registerHooks?.bind(moduleBuiltin);";
  const cryptoAccessorLeakMutant = source.replace(
    exactRegisterHooksBinding,
    `const registerHooks = (...args) => {
  const registration =
    moduleBuiltin[["register", "Hooks"].join("")].apply(moduleBuiltin, args);
  globalThis.crypto[
    Symbol.for(["worker", "resolution", "handle"].join("."))
  ] = registration;
  return registration;
};`,
  );
  assert.notEqual(
    cryptoAccessorLeakMutant,
    source,
    "crypto-accessor handle-leak mutant was not activated",
  );
  assert.throws(
    () => assertRuntimeGuardLexicalHandleDiscipline(
      cryptoAccessorLeakMutant,
      "crypto-accessor handle-leak mutant",
    ),
    /exact canonical socketless runtime-guard source/i,
    "canonical source oracle admitted a crypto-accessor handle leak",
  );
  const cryptoAccessorLeakPath = path.join(
    root,
    "runtime-guard-crypto-accessor-leak-mutant.mjs",
  );
  fs.writeFileSync(cryptoAccessorLeakPath, cryptoAccessorLeakMutant, {
    mode: 0o600,
  });
  const cryptoAccessorLeakControl = spawnSync(
    process.execPath,
    [
      "--import",
      pathToFileURL(cryptoAccessorLeakPath).href,
      "--input-type=module",
      "--eval",
      `globalThis.crypto[
  Symbol.for(["worker", "resolution", "handle"].join("."))
].deregister();
await import("node:net");
process.stdout.write("crypto-accessor-bypass" + String.fromCharCode(10));`,
    ],
    {
      encoding: "utf8",
      env: {
        HOME: root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
  assert.deepEqual(
    {
      signal: cryptoAccessorLeakControl.signal,
      status: cryptoAccessorLeakControl.status,
      stderr: cryptoAccessorLeakControl.stderr,
      stdout: cryptoAccessorLeakControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "crypto-accessor-bypass\n",
    },
    "crypto-accessor mutant is not a real resolver deregistration capability",
  );
  const cryptoAccessorLeakRejected = runRuntimeGuardGlobalIdentityBoundary(
    cryptoAccessorLeakPath,
    root,
  );
  assert.notEqual(
    cryptoAccessorLeakRejected.status,
    0,
    "same-process identity boundary admitted a crypto-accessor handle leak",
  );
  assert.match(
    cryptoAccessorLeakRejected.stderr,
    /global reachability identity key set changed/i,
    "crypto-accessor handle leak failed outside its materialized identity root",
  );
});

test("RED v2: the production runtime guard is root-owned, Dockerfile-bound and executed by the exact worker entrypoint", (t) => {
  assert.equal(
    fs.existsSync(workerRuntimeGuardPath),
    true,
    "production worker runtime guard source is missing",
  );
  const dockerfile = path.join(
    path.resolve(scriptDir, ".."),
    "docker",
    "docker-action-broker.Dockerfile",
  );
  const dockerfileSource = fs.readFileSync(dockerfile, "utf8");
  assertFinalRuntimeGuardLayer(dockerfileSource);
  assert.match(
    dockerfileSource,
    new RegExp(
      `^COPY --chown=0:0 --chmod=0555 scripts/docker-action-worker-runtime-guard\\.mjs ${escapeRegExp(WORKER_RUNTIME_GUARD_CONTAINER_PATH)}$`,
      "m",
    ),
    "Dockerfile lacks the one exact root-owned immutable runtime-guard COPY",
  );
  const staged = stageDockerWorkerImageLayout(t, "docker-worker-runtime-guard-stage-");
  const stagedGuardPath = path.join(
    staged.root,
    WORKER_RUNTIME_GUARD_CONTAINER_PATH.replace(/^\/+/, ""),
  );
  assert.equal(fs.existsSync(stagedGuardPath), true);
  const stagedGuardStat = fs.lstatSync(stagedGuardPath);
  assert.equal(stagedGuardStat.isFile(), true);
  assert.equal(stagedGuardStat.isSymbolicLink(), false);
  assert.equal(stagedGuardStat.mode & 0o777, 0o555);
  const guardSource = fs.readFileSync(stagedGuardPath, "utf8");
  assertRuntimeGuardLexicalHandleDiscipline(
    guardSource,
    "production runtime guard",
  );
  const identityBoundary = runRuntimeGuardGlobalIdentityBoundary(
    stagedGuardPath,
    staged.root,
  );
  assert.deepEqual(
    {
      signal: identityBoundary.signal,
      status: identityBoundary.status,
      stderr: identityBoundary.stderr,
      stdout: identityBoundary.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "identity-ok\n",
    },
    "production guard changed a global-reachable identity outside its exact allowlist",
  );

  const exactEntrypoint = EXPECTED_WORKER_ENTRYPOINT.map((argument, index) => {
    if (index === 0) return process.execPath;
    if (!argument.startsWith("/")) return argument;
    return path.join(staged.root, argument.replace(/^\/+/, ""));
  });
  assert.deepEqual(exactEntrypoint.slice(1, 3), ["--import", stagedGuardPath]);
  assert.equal(exactEntrypoint.at(-1), staged.workerPath);
  const runExactEntrypoint = (source) => {
    fs.chmodSync(staged.workerPath, 0o700);
    fs.writeFileSync(staged.workerPath, `${source}\n`, { mode: 0o700 });
    fs.chmodSync(staged.workerPath, 0o555);
    return spawnSync(exactEntrypoint[0], exactEntrypoint.slice(1), {
      cwd: path.dirname(staged.workerPath),
      encoding: "utf8",
      env: {
        HOME: staged.root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    });
  };

  const positive = runExactEntrypoint(
    `${assertNoGlobalDeregistrationHandleSource()}
if (globalThis[Symbol.for("platform.worker.socketless-guard-count")] !== 1) throw new Error("guard sentinel");
await import("node:fs");
await import("node:path");
process.stdout.write("guard-ok" + String.fromCharCode(10));`,
  );
  assert.deepEqual(
    {
      signal: positive.signal,
      status: positive.status,
      stderr: positive.stderr,
      stdout: positive.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "guard-ok\n",
    },
  );

  assertRuntimeGuardRejectsDirectNetworkImport(
    runExactEntrypoint,
    "production runtime guard",
  );

  for (const [name, snippet] of [
    [
      "Function",
      'globalThis[Symbol.for("platform.worker.socketless-resolution-hook")]?.deregister?.(); const load = (() => {}).constructor(\'return import("node:" + "net")\'); await load();',
    ],
    [
      "AsyncFunction",
      'const load = (async () => {}).constructor(\'return import("node:" + "net")\'); await load();',
    ],
    [
      "GeneratorFunction",
      'const load = (function* () {}).constructor(\'yield import("node:" + "net")\'); await load().next();',
    ],
    [
      "AsyncGeneratorFunction",
      'const load = (async function* () {}).constructor(\'yield import("node:" + "net")\'); await load().next();',
    ],
  ]) {
    const rejected = runExactEntrypoint(snippet);
    assert.notEqual(rejected.status, 0, `${name} reconstruction was admitted`);
    assert.match(
      rejected.stderr,
      new RegExp(`socketless runtime guard blocked ${name}(?:\\n|\\b)`),
      `${name} was blocked only by a later resolver boundary`,
    );
  }
});

test("worker source is socketless while its fixed subprocess adapter remains testable", (t) => {
  const source = fs.readFileSync(workerPath, "utf8");
  assertSocketlessWorkerSource(source, "real worker source");
  for (const [label, hostileSource] of [
    ["bare net import", 'import net from "net";'],
    ["comment-obfuscated static import", 'import net from/*x*/"node:net";'],
    ["bare undici import", 'import { request } from "undici";'],
    ["HTTP/2 import", 'import http2 from "node:http2";'],
    ["dynamic network import", 'const net = await import("node:" + "net");'],
    ["getBuiltinModule", 'process.getBuiltinModule("node:net");'],
    ["constructed getBuiltinModule", 'process["get" + "BuiltinModule"]("node:net");'],
    [
      "createRequire",
      'import { createRequire } from "node:module"; createRequire(import.meta.url)("node:net");',
    ],
    [
      "Module._load",
      'import Module from "node:module"; Module._load("node:net");',
    ],
    [
      "computed Module._load",
      'import Module from "node:module"; Module["_" + "load"]("node:net");',
    ],
    [
      "base64 Module._load",
      'import Module from "node:module"; Module[Buffer.from("X2xvYWQ=", "base64").toString()]("node:net");',
    ],
    [
      "reflected Module._load",
      'import Module from "node:module"; Reflect.get(Module, "_load")("node:net");',
    ],
    ["eval", 'eval("process.getBuiltinModule(\\"node:net\\")");'],
    ["Function constructor", 'Function("return fetch(\\"http://engine\\")")();'],
    [
      "prototype constructor reconstruction",
      '(() => {})["con" + "structor"]("return im" + "port(\\"node:\\" + \\"net\\")")();',
    ],
    [
      "joined constructor and import aliases",
      'const key = ["con", "structor"].join(""); const word = ["im", "port"].join(""); const body = ["return ", word, "(\\"node:\\" + \\"net\\")"].join(""); await (() => {})[key](body)();',
    ],
    [
      "reverse-order joined import and constructor aliases",
      'const word = ["im", "port"].join(""); const key = ["con", "structor"].join(""); const body = ["return ", word, "(\\"node:\\" + \\"net\\")"].join(""); await (() => {})[key](body)();',
    ],
    [
      "indirect joined constructor alias",
      'function buildKey() { return ["con", "structor"].join(""); } const word = ["im", "port"].join(""); await (() => {})[buildKey()]("return " + word + "(\\"node:\\" + \\"net\\")")();',
    ],
    ["global fetch", 'await fetch("http://engine/containers/json");'],
    ["WebSocket", 'new WebSocket("ws://engine/events");'],
    [
      "child process network tool",
      'import { spawn } from "node:child_process"; spawn("/usr/bin/curl", ["http://engine"]);',
    ],
    [
      "computed network command through a shell",
      'import { spawn } from "node:child_process"; const command = String.fromCharCode(99,117,114,108,32,104,116,116,112,58,47,47,101,110,103,105,110,101); spawn("/bin/sh", ["-c", command], { shell: false });',
    ],
    [
      "environment interpreter wrapper",
      'import { spawn } from "node:child_process"; spawn("/usr/bin/env", ["node", "-e", "process.exit(0)"], { shell: false });',
    ],
    [
      "computed process execve",
      'process[["exec", "ve"].join("")]("/usr/bin/printf", ["printf", "admitted"], process.env);',
    ],
    [
      "computed process stdout Socket connect",
      'const stream = process[["std", "out"].join("")]; new stream[["con", "structor"].join("")]()[["con", "nect"].join("")](65535, "127.0.0.1");',
    ],
    [
      "computed child stdout Socket connect",
      'const child = {}; child.stdout = process.stdout; new child.stdout[["con", "structor"].join("")]()[["con", "nect"].join("")](65535, "127.0.0.1");',
    ],
    ["joined Docker socket", 'const socket = ["/var/run/", "docker", ".sock"].join("");'],
    ["templated Docker socket", 'const socket = `/var/run/${"docker"}${".sock"}`;'],
    ["unicode Docker socket", 'const socket = "docker\\u002esock";'],
  ]) {
    assert.throws(
      () => assertSocketlessWorkerSource(hostileSource, label),
      /socketless|network|Docker|Engine|dynamic|fetch/i,
      `socketless scanner missed ${label}`,
    );
  }

  const staged = stageDockerWorkerImageLayout(t, "docker-worker-oracle-stage-");
  assert.equal(
    fs.readFileSync(staged.workerPath, "utf8"),
    source,
    "Dockerfile-exact staging changed the worker fixture",
  );
  assert.deepEqual(
    assertSocketlessWorkerImportGraph(staged.workerPath),
    ["docker-action-worker.mjs"],
    "worker import graph escaped its one staged entrypoint",
  );
  const hostileGraphRoot = path.join(staged.root, "hostile-worker-graph");
  fs.mkdirSync(hostileGraphRoot, { mode: 0o700 });
  const hostileGraphEntry = path.join(hostileGraphRoot, "entry.mjs");
  const hostileGraphNested = path.join(hostileGraphRoot, "nested.mjs");
  fs.writeFileSync(hostileGraphEntry, 'import "./nested.mjs";\n', { mode: 0o600 });
  fs.writeFileSync(hostileGraphNested, 'import "node:net";\n', { mode: 0o600 });
  assert.throws(
    () => assertSocketlessWorkerImportGraph(hostileGraphEntry),
    /allowlist|socketless|builtin|network/i,
    "socketless graph scanner ignored a nested forbidden builtin",
  );
  fs.writeFileSync(hostileGraphEntry, 'import "../escaped.mjs";\n', { mode: 0o600 });
  assert.throws(
    () => assertSocketlessWorkerImportGraph(hostileGraphEntry),
    /escaped|root|graph|local/i,
    "socketless graph scanner ignored a local import escaping its root",
  );
  const hookPath = path.join(staged.root, "fixed-adapter-hook-check.mjs");
  fs.writeFileSync(
    hookPath,
    fixedAdapterHookSource(path.join(staged.root, "unused-trace.jsonl")),
    { mode: 0o600 },
  );
  const hookCheck = spawnSync(process.execPath, ["--check", hookPath], {
    encoding: "utf8",
  });
  assert.deepEqual(
    {
      signal: hookCheck.signal,
      status: hookCheck.status,
      stderr: hookCheck.stderr,
      stdout: hookCheck.stdout,
    },
    { signal: null, status: 0, stderr: "", stdout: "" },
    "fixed-adapter preload oracle is not syntactically valid",
  );

  const guardPath = path.join(staged.root, "socketless-runtime-guard.mjs");
  const guardSource = socketlessRuntimeGuardSource();
  assertRuntimeGuardLexicalHandleDiscipline(
    guardSource,
    "test-local socketless runtime guard",
  );
  fs.writeFileSync(guardPath, guardSource, { mode: 0o600 });
  const guardCheck = spawnSync(process.execPath, ["--check", guardPath], {
    encoding: "utf8",
  });
  assert.deepEqual(
    { signal: guardCheck.signal, status: guardCheck.status, stderr: guardCheck.stderr },
    { signal: null, status: 0, stderr: "" },
    "socketless runtime guard is not syntactically valid",
  );
  const identityBoundary = runRuntimeGuardGlobalIdentityBoundary(
    guardPath,
    staged.root,
  );
  assert.deepEqual(
    {
      signal: identityBoundary.signal,
      status: identityBoundary.status,
      stderr: identityBoundary.stderr,
      stdout: identityBoundary.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "identity-ok\n",
    },
    "test-local guard changed a global-reachable identity outside its allowlist",
  );
  const guardUrl = pathToFileURL(guardPath).href;
  const positiveGuard = spawnSync(
    process.execPath,
    [
      "--import",
      guardUrl,
      "--input-type=module",
      "--eval",
      `${assertNoGlobalDeregistrationHandleSource()}
if (globalThis[Symbol.for("platform.worker.socketless-guard-count")] !== 1) throw new Error("guard sentinel");
await import("node:fs");
await import("node:path");
process.stdout.write("guard-ok" + String.fromCharCode(10));`,
    ],
    { encoding: "utf8", env: { HOME: staged.root, LANG: "C.UTF-8" } },
  );
  assert.deepEqual(
    {
      signal: positiveGuard.signal,
      status: positiveGuard.status,
      stderr: positiveGuard.stderr,
      stdout: positiveGuard.stdout,
    },
    { signal: null, status: 0, stderr: "", stdout: "guard-ok\n" },
    "socketless runtime guard broke the admitted builtin control",
  );
  for (const [label, snippet, expectedError = /socketless runtime guard/i] of [
    [
      "direct node:net import",
      'await import("node:net");',
      /socketless runtime guard blocked module resolution: node:net/i,
    ],
    [
      "comment-obfuscated static import",
      'import net from/*x*/"node:net"; void net;',
    ],
    ["getBuiltinModule", 'process.getBuiltinModule("node:net");'],
    [
      "createRequire",
      'const { createRequire } = await import("node:module"); createRequire(import.meta.url)("node:net");',
    ],
    [
      "Module._load",
      'const Module = (await import("node:module")).default; Module._load("node:net");',
    ],
    [
      "computed Module._load",
      'const Module = (await import("node:module")).default; Module["_" + "load"]("node:net");',
    ],
    [
      "base64 Module._load",
      'const Module = (await import("node:module")).default; Module[Buffer.from("X2xvYWQ=", "base64").toString()]("node:net");',
    ],
    [
      "reflected Module._load",
      'const Module = (await import("node:module")).default; Reflect.get(Module, "_load")("node:net");',
    ],
    [
      "Module.prototype.require",
      'const Module = (await import("node:module")).default; Module.prototype.require.call({}, "node:net");',
    ],
    [
      "computed Module.prototype._compile",
      'const Module = (await import("node:module")).default; const instance = new Module("mutant"); instance[["_", "compile"].join("")]("void 0", "mutant.cjs");',
      /socketless runtime guard blocked module\._compile/i,
    ],
    [
      "computed Module.prototype.load",
      'const Module = (await import("node:module")).default; const instance = new Module("mutant"); instance[["lo", "ad"].join("")]("/tmp/mutant.cjs");',
      /socketless runtime guard blocked module\.load/i,
    ],
    [
      "computed Module.runMain",
      'const Module = (await import("node:module")).default; Module[["run", "Main"].join("")]();',
      /socketless runtime guard blocked module\.runMain/i,
    ],
    [
      "reflected Module._extensions",
      'const Module = (await import("node:module")).default; Reflect.get(Module, ["_", "extensions"].join(""))[".js"]({}, "/tmp/mutant.cjs");',
      /not a function|undefined/i,
    ],
    [
      "computed Module._preloadModules",
      'const Module = (await import("node:module")).default; Module[["_", "preload", "Modules"].join("")](["/tmp/mutant.cjs"]);',
      /socketless runtime guard blocked module\._preloadModules/i,
    ],
    [
      "computed Module.syncBuiltinESMExports",
      'const Module = (await import("node:module")).default; Module[["sync", "Builtin", "ESM", "Exports"].join("")]();',
      /not a function|undefined/i,
    ],
    [
      "named syncBuiltinESMExports export",
      'const namespace = await import("node:module"); namespace.syncBuiltinESMExports();',
      /not a function|undefined/i,
    ],
    [
      "registerHooks replacement",
      'const Module = (await import("node:module")).default; Module.registerHooks({ resolve() { return { url: "node:net" }; } });',
    ],
    ["eval", 'eval("1 + 1");'],
    ["Function", 'Function("return 1")();'],
    [
      "leaked handle plus Function prototype constructor",
      'globalThis[Symbol.for("platform.worker.socketless-resolution-hook")]?.deregister?.(); const load = (() => {}).constructor(\'return import("node:" + "net")\'); await load();',
      /socketless runtime guard blocked Function(?:\n|\b)/,
    ],
    [
      "AsyncFunction prototype constructor",
      'const load = (async () => {}).constructor(\'return import("node:" + "net")\'); await load();',
      /socketless runtime guard blocked AsyncFunction(?:\n|\b)/,
    ],
    [
      "GeneratorFunction prototype constructor",
      'const load = (function* () {}).constructor(\'yield import("node:" + "net")\'); await load().next();',
      /socketless runtime guard blocked GeneratorFunction(?:\n|\b)/,
    ],
    [
      "AsyncGeneratorFunction prototype constructor",
      'const load = (async function* () {}).constructor(\'yield import("node:" + "net")\'); await load().next();',
      /socketless runtime guard blocked AsyncGeneratorFunction(?:\n|\b)/,
    ],
    ["fetch", 'await fetch("http://engine");'],
    [
      "child-process curl",
      'const { spawnSync } = await import("node:child_process"); spawnSync("/usr/bin/curl", []);',
    ],
    [
      "ChildProcess native handle spawn",
      `const childProcess = (await import("node:child_process")).default;
       const child = new childProcess.ChildProcess();
       child._handle.spawn(
         "/usr/bin/printf",
         ["printf", "native-handle-admitted"],
         undefined,
         [],
         [
           { type: "inherit", fd: 0 },
           { type: "inherit", fd: 1 },
           { type: "inherit", fd: 2 },
         ],
         0,
         undefined,
         undefined,
       );`,
      /not a constructor|undefined/i,
    ],
    [
      "computed ChildProcess native handle spawn",
      `const childProcess = (await import("node:child_process")).default;
       const Constructor = childProcess[["Child", "Process"].join("")];
       const child = new Constructor();
       child[["_", "handle"].join("")][["sp", "awn"].join("")](
         "/usr/bin/printf",
         ["printf", "computed-native-handle-admitted"],
         undefined,
         [],
         [
           { type: "inherit", fd: 0 },
           { type: "inherit", fd: 1 },
           { type: "inherit", fd: 2 },
         ],
         0,
         undefined,
         undefined,
       );`,
      /not a constructor|undefined/i,
    ],
    [
      "named ChildProcess export",
      'const { ChildProcess } = await import("node:child_process"); new ChildProcess();',
      /not a constructor|undefined/i,
    ],
    [
      "computed internal fork export",
      'const childProcess = (await import("node:child_process")).default; childProcess[["_fork", "Child"].join("")]();',
      /not a function|undefined/i,
    ],
    [
      "shell indirection",
      'const { spawn } = await import("node:child_process"); spawn("/bin/sh", ["-c", "printf admitted"], { env: process.env, shell: false, stdio: ["ignore", "pipe", "pipe"] });',
      /socketless runtime guard rejected non-exact fixed adapter spawn/i,
    ],
    [
      "environment wrapper",
      'const { spawn } = await import("node:child_process"); spawn("/usr/bin/env", ["/opt/platform-docker-worker/bin/backup-catalog"], { env: process.env, shell: false, stdio: ["ignore", "pipe", "pipe"] });',
      /socketless runtime guard rejected non-exact fixed adapter spawn/i,
    ],
    [
      "interpreter indirection",
      'const { spawn } = await import("node:child_process"); spawn("/usr/local/bin/node", ["-e", "process.exit(0)"], { env: process.env, shell: false, stdio: ["ignore", "pipe", "pipe"] });',
      /socketless runtime guard rejected non-exact fixed adapter spawn/i,
    ],
    [
      "adapter argv widening",
      'const { spawn } = await import("node:child_process"); spawn("/opt/platform-docker-worker/bin/backup-catalog", ["attacker"], { env: process.env, shell: false, stdio: ["ignore", "pipe", "pipe"] });',
      /socketless runtime guard rejected non-exact fixed adapter spawn/i,
    ],
    [
      "adapter shell widening",
      'const { spawn } = await import("node:child_process"); spawn("/opt/platform-docker-worker/bin/backup-catalog", [], { env: process.env, shell: true, stdio: ["ignore", "pipe", "pipe"] });',
      /socketless runtime guard rejected non-exact fixed adapter spawn/i,
    ],
    [
      "adapter environment widening",
      'const { spawn } = await import("node:child_process"); spawn("/opt/platform-docker-worker/bin/backup-catalog", [], { env: { ...process.env, NODE_OPTIONS: "--import=/tmp/attacker.mjs" }, shell: false, stdio: ["ignore", "pipe", "pipe"] });',
      /socketless runtime guard rejected non-exact fixed adapter spawn/i,
    ],
    [
      "safe-looking executable through wrong API",
      'const { execFile } = await import("node:child_process"); execFile("/opt/platform-docker-worker/bin/backup-catalog", []);',
      /socketless runtime guard blocked non-admitted child_process API: execFile/i,
    ],
  ]) {
    const guarded = spawnSync(
      process.execPath,
      ["--import", guardUrl, "--input-type=module", "--eval", snippet],
      {
        encoding: "utf8",
        env: { HOME: staged.root, LANG: "C.UTF-8" },
      },
    );
    assert.notEqual(guarded.status, 0, `socketless runtime guard admitted ${label}`);
    assert.match(
      guarded.stderr,
      expectedError,
      `${label} failed outside the socketless runtime guard`,
    );
  }
});

test("runtime guard owns spawn inputs, phase identity and every child-visible capability", (t) => {
  const fixtureCommandByActionPhase = {};
  for (const [action, profile] of Object.entries(EXPECTED_ACTION_PHASES)) {
    const phaseIds = [
      ...profile.phaseIds,
      ...Object.values(profile.operationPhaseIds).flat(),
    ];
    for (const phaseId of phaseIds) {
      fixtureCommandByActionPhase[`${action}\0${phaseId}`] =
        EXPECTED_PHASE_PROFILES[phaseId].command;
    }
  }
  assert.deepEqual(
    EXPECTED_COMMAND_BY_ACTION_PHASE,
    fixtureCommandByActionPhase,
    "runtime guard action/phase mapping does not cover the exact eight fixture identities",
  );
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "docker-worker-owned-spawn-guard-"),
  );
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const tracePath = path.join(root, "owned-spawn-trace.json");
  const hookPath = path.join(root, "owned-spawn-hook.mjs");
  const guardPath = path.join(root, "owned-spawn-guard.mjs");
  fs.writeFileSync(
    hookPath,
    `
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { PassThrough } from "node:stream";

const tracePath = ${JSON.stringify(tracePath)};
childProcess.ChildProcess.prototype.spawn = function (options) {
  this.pid = 4242;
  this.stdin = null;
  this.stdout = new PassThrough();
  this.stderr = new PassThrough();
  this.kill = () => true;
  const environmentDescriptors =
    Object.getOwnPropertyDescriptors(options.env);
  const optionDescriptors =
    Object.getOwnPropertyDescriptors(options);
  const stdioDescriptors =
    Object.getOwnPropertyDescriptors(options.stdio);
  fs.writeFileSync(tracePath, JSON.stringify({
    args: [...options.args],
    envFrozen: Object.isFrozen(options.env),
    envKeys: Reflect.ownKeys(options.env).sort(),
    envOwnData: Reflect.ownKeys(environmentDescriptors).every((key) =>
      Object.hasOwn(environmentDescriptors[key], "value")
      && environmentDescriptors[key].configurable === false
      && environmentDescriptors[key].enumerable === true
      && environmentDescriptors[key].writable === false),
    envSameAsProcess: options.env === process.env,
    executable: options.file,
    optionKeys: Reflect.ownKeys(options).sort(),
    optionsOwnData: Reflect.ownKeys(optionDescriptors).every((key) =>
      Object.hasOwn(optionDescriptors[key], "value")
      && typeof optionDescriptors[key].get !== "function"
      && typeof optionDescriptors[key].set !== "function"),
    shell: options.shell,
    stdio: [...options.stdio],
    stdioFrozen: Object.isFrozen(options.stdio),
    stdioOwnData: ["0", "1", "2"].every((key) =>
      Object.hasOwn(stdioDescriptors[key], "value")
      && stdioDescriptors[key].configurable === false
      && stdioDescriptors[key].enumerable === true
      && stdioDescriptors[key].writable === false),
  }));
  queueMicrotask(() => {
    this.stdout.end("owned-child-output\\n");
    this.stderr.end();
    this.emit("exit", 0, null);
    this.emit("close", 0, null);
  });
};
syncBuiltinESMExports();
`,
    { mode: 0o600 },
  );
  fs.writeFileSync(guardPath, socketlessRuntimeGuardSource(), { mode: 0o600 });
  const runGuarded = (source, environment = {}) => spawnSync(
    process.execPath,
    [
      "--import",
      pathToFileURL(hookPath).href,
      "--import",
      pathToFileURL(guardPath).href,
      "--input-type=module",
      "--eval",
      source,
    ],
    {
      encoding: "utf8",
      env: {
        HOME: root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
        PLATFORM_DOCKER_ACTION: "backup.catalog",
        PLATFORM_DOCKER_PHASE_ID: "catalog.capture",
        ...environment,
      },
      maxBuffer: 32 * 1024,
    },
  );
  const exactExecutable =
    EXPECTED_FIXED_ADAPTERS["backup-catalog"].executable;
  const admitted = runGuarded(`
    import childProcess from "node:child_process";
    const childProcessNamespace = await import("node:child_process");
    const moduleNamespace = await import("node:module");
    if (
      childProcess.ChildProcess !== undefined
      || childProcessNamespace.ChildProcess !== undefined
      || childProcess._forkChild !== undefined
      || childProcessNamespace._forkChild !== undefined
      || moduleNamespace.default.syncBuiltinESMExports !== undefined
      || moduleNamespace.syncBuiltinESMExports !== undefined
      || moduleNamespace.Module !== moduleNamespace.default
      || moduleNamespace.runMain !== moduleNamespace.default.runMain
      || moduleNamespace._extensions !== moduleNamespace.default._extensions
      || moduleNamespace._preloadModules
        !== moduleNamespace.default._preloadModules
      || Object.getPrototypeOf(moduleNamespace.default._extensions) !== null
      || Reflect.ownKeys(moduleNamespace.default._extensions).length !== 0
      || !Object.isFrozen(moduleNamespace.default._extensions)
    ) {
      throw new Error("original constructor or builtin export authority escaped");
    }
    const callerArgv = [];
    const callerOptions = {
      env: process.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    };
    const child = childProcess.spawn(
      ${JSON.stringify(exactExecutable)},
      callerArgv,
      callerOptions,
    );
    if (child === null || typeof child !== "object") {
      throw new Error("guard returned no safe child facade");
    }
    if (
      typeof process.stdout.constructor?.prototype?.connect === "function"
      || typeof process.stderr.constructor?.prototype?.connect === "function"
      || typeof child.stdout.constructor?.prototype?.connect === "function"
      || typeof child.stderr.constructor?.prototype?.connect === "function"
      || child.stdout._handle !== undefined
      || child.stderr._handle !== undefined
      || typeof child.constructor?.prototype?.spawn === "function"
    ) {
      throw new Error("raw stream or ChildProcess capability escaped the guard");
    }
    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.on("close", () => process.stdout.write("guard-owned-ok\\n"));
  `);
  assert.deepEqual(
    {
      signal: admitted.signal,
      status: admitted.status,
      stderr: admitted.stderr,
      stdout: admitted.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "owned-child-output\nguard-owned-ok\n",
    },
    "exact worker-style spawn did not cross the real guard-owned invocation",
  );
  const trace = JSON.parse(fs.readFileSync(tracePath, "utf8"));
  assert.deepEqual(trace, {
    args: [exactExecutable],
    envFrozen: true,
    envKeys: [
      "HOME",
      "LANG",
      "NODE_ENV",
      "PLATFORM_DOCKER_ACTION",
      "PLATFORM_DOCKER_PHASE_ID",
    ],
    envOwnData: true,
    envSameAsProcess: false,
    executable: exactExecutable,
    optionKeys: [
      "args",
      "cwd",
      "detached",
      "env",
      "envPairs",
      "file",
      "shell",
      "stdio",
      "windowsHide",
      "windowsVerbatimArguments",
    ],
    optionsOwnData: true,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    stdioFrozen: true,
    stdioOwnData: true,
  });

  for (const [label, source, pattern] of [
    [
      "argv Proxy",
      `import childProcess from "node:child_process";
       childProcess.spawn(${JSON.stringify(exactExecutable)}, new Proxy([], {}), {
         env: process.env, shell: false, stdio: ["ignore", "pipe", "pipe"],
       });`,
      /non-exact fixed adapter spawn/i,
    ],
    [
      "options Proxy",
      `import childProcess from "node:child_process";
       childProcess.spawn(${JSON.stringify(exactExecutable)}, [], new Proxy({
         env: process.env, shell: false, stdio: ["ignore", "pipe", "pipe"],
       }, {}));`,
      /non-exact fixed adapter spawn/i,
    ],
    [
      "options accessor",
      `import childProcess from "node:child_process";
       const options = {};
       Object.defineProperties(options, {
         env: { configurable: true, enumerable: true, get() { return process.env; } },
         shell: { configurable: true, enumerable: true, value: false, writable: true },
         stdio: {
           configurable: true,
           enumerable: true,
           value: ["ignore", "pipe", "pipe"],
           writable: true,
         },
       });
       childProcess.spawn(${JSON.stringify(exactExecutable)}, [], options);`,
      /non-exact fixed adapter spawn/i,
    ],
    [
      "stateful stdio Proxy",
      `import childProcess from "node:child_process";
       const stdio = new Proxy(["ignore", "pipe", "pipe"], {
         get(target, key, receiver) {
           return Reflect.get(target, key, receiver);
         },
       });
       childProcess.spawn(${JSON.stringify(exactExecutable)}, [], {
         env: process.env, shell: false, stdio,
       });`,
      /non-exact fixed adapter spawn/i,
    ],
    [
      "omitted env and stdio",
      `import childProcess from "node:child_process";
       childProcess.spawn(${JSON.stringify(exactExecutable)}, [], { shell: false });`,
      /non-exact fixed adapter spawn/i,
    ],
    [
      "cross-phase executable",
      `import childProcess from "node:child_process";
       childProcess.spawn(
         ${JSON.stringify(EXPECTED_FIXED_ADAPTERS["backup-job"].executable)},
         [],
         { env: process.env, shell: false, stdio: ["ignore", "pipe", "pipe"] },
       );`,
      /non-exact fixed adapter spawn/i,
    ],
    [
      "ChildProcess prototype spawn",
      `import childProcess from "node:child_process";
       new childProcess.ChildProcess().spawn({
         args: ["printf", "prototype-admitted"],
         detached: false,
         envPairs: [],
         file: "/usr/bin/printf",
         stdio: ["ignore", "pipe", "pipe"],
         windowsHide: false,
         windowsVerbatimArguments: false,
       });`,
      /blocked ChildProcess\.prototype\.spawn|not a constructor|undefined/i,
    ],
    [
      "computed process execve",
      `process[["exec", "ve"].join("")](
         "/usr/bin/printf",
         ["printf", "execve-admitted"],
         process.env,
       );`,
      /blocked process\.execve/i,
    ],
  ]) {
    fs.rmSync(tracePath, { force: true });
    const rejected = runGuarded(source);
    assert.notEqual(rejected.status, 0, `runtime guard admitted ${label}`);
    assert.equal(rejected.stdout, "", `${label} reached child output`);
    assert.match(rejected.stderr, pattern, `${label} failed outside the real guard`);
    assert.equal(
      fs.existsSync(tracePath),
      false,
      `${label} reached the pre-guard spawn sink`,
    );
  }

  const prototypeVulnerabilityControl = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import childProcess from "node:child_process";
       const child = new childProcess.ChildProcess();
       child.spawn({
         args: ["printf", "prototype-spawn-vulnerable\\\\n"],
         detached: false,
         envPairs: [],
         file: "/usr/bin/printf",
         stdio: ["ignore", "pipe", "pipe"],
         windowsHide: false,
         windowsVerbatimArguments: false,
       });
       child.stdout.on("data", (chunk) => process.stdout.write(chunk));`,
    ],
    { encoding: "utf8" },
  );
  assert.deepEqual(
    {
      signal: prototypeVulnerabilityControl.signal,
      status: prototypeVulnerabilityControl.status,
      stderr: prototypeVulnerabilityControl.stderr,
      stdout: prototypeVulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "prototype-spawn-vulnerable\n",
    },
    "ChildProcess.prototype.spawn mutant is not a live child-process bypass",
  );

  const nativeHandleVulnerabilityControl = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const childProcess = (await import("node:child_process")).default;
       const Constructor = childProcess[["Child", "Process"].join("")];
       const child = new Constructor();
       const nativeHandle = child[["_", "handle"].join("")];
       const result = nativeHandle[["sp", "awn"].join("")](
         "/usr/bin/printf",
         ["printf", "native-handle-vulnerable\\\\n"],
         undefined,
         [],
         [
           { type: "inherit", fd: 0 },
           { type: "inherit", fd: 1 },
           { type: "inherit", fd: 2 },
         ],
         0,
         undefined,
         undefined,
       );
       if (result !== 0) throw new Error("native spawn failed: " + result);`,
    ],
    { encoding: "utf8" },
  );
  assert.deepEqual(
    {
      signal: nativeHandleVulnerabilityControl.signal,
      status: nativeHandleVulnerabilityControl.status,
      stderr: nativeHandleVulnerabilityControl.stderr,
      stdout: nativeHandleVulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "native-handle-vulnerable\n",
    },
    "computed ChildProcess constructor->_handle.spawn mutant is not a live bypass",
  );

  const moduleCapabilityPaths = Object.fromEntries(
    ["load", "extension", "preload", "runmain"].map((label) => {
      const file = path.join(root, `module-${label}-vulnerability.cjs`);
      fs.writeFileSync(
        file,
        `process.stdout.write(${JSON.stringify(`module-${label}-vulnerable\n`)});\n`,
        { mode: 0o600 },
      );
      return [label, file];
    }),
  );
  const moduleCapabilityVulnerabilityControl = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const Module = (await import("node:module")).default;
       const compileModule = new Module("module-compile-vulnerability");
       compileModule[["_", "compile"].join("")](
         "process.stdout.write('module-compile-vulnerable\\\\n')",
         "module-compile-vulnerability.cjs",
       );
       const loadPath = ${JSON.stringify(moduleCapabilityPaths.load)};
       const loadModule = new Module(loadPath);
       loadModule[["lo", "ad"].join("")](loadPath);
       const extensionPath = ${JSON.stringify(moduleCapabilityPaths.extension)};
       const extensionModule = new Module(extensionPath);
       extensionModule.filename = extensionPath;
       extensionModule.paths = Module._nodeModulePaths(
         ${JSON.stringify(root)},
       );
       Reflect.get(Module, ["_", "extensions"].join(""))[".js"](
         extensionModule,
         extensionPath,
       );
       Module[["_", "preload", "Modules"].join("")]([
         ${JSON.stringify(moduleCapabilityPaths.preload)},
       ]);
       process.argv[1] = ${JSON.stringify(moduleCapabilityPaths.runmain)};
       Module[["run", "Main"].join("")]();`,
    ],
    { encoding: "utf8" },
  );
  assert.deepEqual(
    {
      signal: moduleCapabilityVulnerabilityControl.signal,
      status: moduleCapabilityVulnerabilityControl.status,
      stderr: moduleCapabilityVulnerabilityControl.stderr,
      stdout: moduleCapabilityVulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: [
        "module-compile-vulnerable",
        "module-load-vulnerable",
        "module-extension-vulnerable",
        "module-preload-vulnerable",
        "module-runmain-vulnerable",
        "",
      ].join("\n"),
    },
    "computed legacy Module loader mutants are not live execution capabilities",
  );

  const toctouVulnerabilityControl = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import { spawn } from "node:child_process";
       let environmentReads = 0;
       const options = new Proxy({
         shell: false,
         stdio: ["ignore", "pipe", "pipe"],
       }, {
         get(target, key, receiver) {
           if (key === "env") {
             environmentReads += 1;
             return environmentReads === 1
               ? process.env
               : { ...process.env, PLATFORM_TOCTOU_INJECTED: "yes" };
           }
           return Reflect.get(target, key, receiver);
         },
         ownKeys(target) {
           return ["env", ...Reflect.ownKeys(target)];
         },
         getOwnPropertyDescriptor(target, key) {
           if (key === "env") {
             return {
               configurable: true,
               enumerable: true,
               value: process.env,
               writable: true,
             };
           }
           return Reflect.getOwnPropertyDescriptor(target, key);
         },
       });
       function vulnerableForward(executable, argv, candidate) {
         if (candidate.env !== process.env || candidate.shell !== false) {
           throw new Error("unexpected vulnerability-control shape");
         }
         return spawn(executable, argv, candidate);
       }
       const child = vulnerableForward(
         process.execPath,
         ["--input-type=module", "--eval",
          "process.stdout.write(process.env.PLATFORM_TOCTOU_INJECTED ?? 'missing')"],
         options,
       );
       child.stdout.on("data", (chunk) => process.stdout.write(chunk));`,
    ],
    { encoding: "utf8" },
  );
  assert.deepEqual(
    {
      signal: toctouVulnerabilityControl.signal,
      status: toctouVulnerabilityControl.status,
      stderr: toctouVulnerabilityControl.stderr,
      stdout: toctouVulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: "yes",
    },
    "stateful options Proxy is not a live validate-then-forward mutation",
  );
});

test("exact fixed adapter starts its own guard before the first worker import", (t) => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "docker-worker-real-adapter-guard-"),
  );
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin, { mode: 0o700 });
  const adapterPath = path.join(bin, "backup-catalog.mjs");
  const guardPath = path.join(root, "docker-action-worker-runtime-guard.mjs");
  const workerFixturePath = path.join(root, "docker-action-worker.mjs");
  const exactAdapterSource = EXPECTED_FIXED_ADAPTER_SOURCE_TEXT["backup-catalog"];
  fs.writeFileSync(adapterPath, exactAdapterSource, { mode: 0o555 });
  fs.chmodSync(adapterPath, 0o555);
  fs.writeFileSync(guardPath, socketlessRuntimeGuardSource(), { mode: 0o555 });
  fs.chmodSync(guardPath, 0o555);
  const environment = {
    HOME: root,
    LANG: "C.UTF-8",
    NODE_ENV: "production",
  };
  const runAdapter = () => spawnSync(
    process.execPath,
    [adapterPath],
    {
      cwd: root,
      encoding: "utf8",
      env: environment,
      maxBuffer: 32 * 1024,
    },
  );

  fs.writeFileSync(
    workerFixturePath,
    `export async function runFixedToolEntry(command) {
  const guardCount =
    globalThis[Symbol.for("platform.worker.socketless-guard-count")] ?? 0;
  process.stdout.write(JSON.stringify({ command, guardCount }) + "\\n");
}
`,
    { mode: 0o555 },
  );
  fs.chmodSync(workerFixturePath, 0o555);
  const positive = runAdapter();
  assert.deepEqual(
    {
      signal: positive.signal,
      status: positive.status,
      stderr: positive.stderr,
      stdout: positive.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: '{"command":"backup-catalog","guardCount":1}\n',
    },
    "the real adapter process did not execute exactly one guard before its worker import",
  );

  const reconstructedNetworkModule = [
    110, 111, 100, 101, 58, 110, 101, 116,
  ];
  fs.chmodSync(workerFixturePath, 0o755);
  fs.writeFileSync(
    workerFixturePath,
    `export async function runFixedToolEntry() {
  const dynamicConstructor = globalThis[["Func", "tion"].join("")];
  const load = dynamicConstructor(
    "return im" + "port(String.fromCharCode(${
      reconstructedNetworkModule.join(",")
    }))",
  );
  await load();
  process.stdout.write(
    JSON.stringify({
      guardCount:
        globalThis[Symbol.for("platform.worker.socketless-guard-count")] ?? 0,
      networkImport: "admitted",
    }) + "\\n",
  );
}
`,
    { mode: 0o555 },
  );
  fs.chmodSync(workerFixturePath, 0o555);
  const guarded = runAdapter();
  assert.notEqual(
    guarded.status,
    0,
    "the real adapter child admitted reconstructed dynamic network authority",
  );
  assert.equal(
    guarded.stdout,
    "",
    "the guarded adapter child reached output after reconstructed network authority",
  );
  assert.match(
    guarded.stderr,
    /socketless runtime guard blocked Function(?:\n|\b)/i,
    "the adapter child failed outside its own runtime guard",
  );

  const missingGuardSource = exactAdapterSource.replace(
    'import "../docker-action-worker-runtime-guard.mjs";\n\n',
    "",
  );
  assert.notEqual(
    missingGuardSource,
    exactAdapterSource,
    "missing-child-guard mutant was not activated",
  );
  fs.chmodSync(adapterPath, 0o755);
  fs.writeFileSync(adapterPath, missingGuardSource, { mode: 0o555 });
  fs.chmodSync(adapterPath, 0o555);
  const vulnerabilityControl = runAdapter();
  assert.deepEqual(
    {
      signal: vulnerabilityControl.signal,
      status: vulnerabilityControl.status,
      stderr: vulnerabilityControl.stderr,
      stdout: vulnerabilityControl.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: '{"guardCount":0,"networkImport":"admitted"}\n',
    },
    "missing-child-guard mutant is not a live adapter-process network bypass",
  );
  assert.equal(
    EXPECTED_FIXED_ADAPTER_SOURCE_TEXT["backup-catalog"],
    exactAdapterSource,
    "canonical adapter source changed during the child-process oracle",
  );
});

test("descriptor-stable read oracle requires exactly two complete positional passes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-read-oracle-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const file = path.join(root, "snapshot.bin");
  const bytes = Buffer.from("descriptor-stable-read-oracle\n");
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  const observed = observeDescriptorStableReadIo(file);
  observed.io.lstatSync(file);
  const descriptor = observed.io.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  observed.io.fstatSync(descriptor);
  const split = Math.floor(bytes.length / 2);
  for (let pass = 0; pass < 2; pass += 1) {
    const buffer = Buffer.alloc(bytes.length);
    assert.equal(observed.io.readSync(descriptor, buffer, 0, split, 0), split);
    assert.equal(
      observed.io.readSync(
        descriptor,
        buffer,
        split,
        bytes.length - split,
        split,
      ),
      bytes.length - split,
    );
    assert.deepEqual(buffer, bytes);
  }
  observed.io.fstatSync(descriptor);
  observed.io.closeSync(descriptor);
  assertStableReadEvidence(observed.evidence);

  const hostileEvidence = [
    {
      label: "zero-count dummy read",
      mutate(evidence) {
        evidence.readSyncCalls[0].returnedCount = 0;
      },
      pattern: /positive bounded progress/i,
    },
    {
      label: "partial restart",
      mutate(evidence) {
        evidence.readSyncCalls.splice(1, 0, {
          ...evidence.readSyncCalls[0],
          order: evidence.readSyncCalls[0].order + 0.5,
        });
      },
      pattern: /restarted at position zero before completing/i,
    },
    {
      label: "third complete pass",
      mutate(evidence) {
        const nextOrder = evidence.readSyncCalls.at(-1).order + 1;
        evidence.readSyncCalls.push(
          ...evidence.readSyncCalls.slice(0, 2).map((call, index) => ({
            ...call,
            order: nextOrder + index,
          })),
        );
      },
      pattern: /exactly two complete descriptor passes/i,
    },
    {
      label: "descriptor substitution",
      mutate(evidence) {
        evidence.readSyncCalls.at(-1).descriptor += 1;
      },
      pattern: /changed descriptors/i,
    },
  ];
  for (const { label, mutate, pattern } of hostileEvidence) {
    const evidence = structuredClone(observed.evidence);
    mutate(evidence);
    assert.throws(
      () => assertStableReadEvidence(evidence),
      pattern,
      `stable-read oracle admitted ${label}`,
    );
  }
  for (const field of Object.keys(observed.evidence.expectedIdentity)) {
    const evidence = structuredClone(observed.evidence);
    evidence.fstatEvents.at(-1).identity[field] = differentStatIdentityValue(
      evidence.fstatEvents.at(-1).identity[field],
    );
    assert.throws(
      () => assertStableReadEvidence(evidence),
      /fstat identity changed across descriptor reads/i,
      `stable-read oracle ignored post-read fstat ${field}`,
    );
  }
  const divergentLeaf = structuredClone(observed.evidence);
  divergentLeaf.leafLstatEvents[0].identity.ino = differentStatIdentityValue(
    divergentLeaf.leafLstatEvents[0].identity.ino,
  );
  assert.throws(
    () => assertStableReadEvidence(divergentLeaf),
    /leaf lstat identity changed/i,
    "stable-read oracle ignored leaf lstat/fstat divergence",
  );

  fs.chmodSync(file, 0o400);
  const substituted = Buffer.from(bytes);
  substituted[0] ^= 0x20;
  const racing = sameSizeRaceIo(file, substituted);
  const racingDescriptor = racing.io.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  racing.io.fstatSync(racingDescriptor);
  const firstPass = Buffer.alloc(bytes.length);
  assert.equal(racing.io.readSync(racingDescriptor, firstPass, 0, split, 0), split);
  assert.equal(racing.evidence.substitutions, 0, "race fired before pass one completed");
  assert.equal(
    racing.io.readSync(
      racingDescriptor,
      firstPass,
      split,
      bytes.length - split,
      split,
    ),
    bytes.length - split,
  );
  assert.deepEqual(firstPass, bytes);
  assert.deepEqual(
    {
      completedPassesBeforeSubstitution:
        racing.evidence.completedPassesBeforeSubstitution,
      substitutions: racing.evidence.substitutions,
    },
    { completedPassesBeforeSubstitution: 1, substitutions: 1 },
  );
  const secondPass = Buffer.alloc(bytes.length);
  assert.equal(
    racing.io.readSync(racingDescriptor, secondPass, 0, bytes.length, 0),
    bytes.length,
  );
  assert.deepEqual(secondPass, substituted);
  racing.io.closeSync(racingDescriptor);
  assert.equal(fs.statSync(file).mode & 0o777, 0o400, "race fixture changed snapshot mode");
});

test("Dockerfile image identities bind exact supply-chain lock keys", () => {
  const lock = JSON.parse(fs.readFileSync(SUPPLY_CHAIN_LOCK_PATH, "utf8"));
  assert.doesNotThrow(() => assertExactDockerfileSupplyChainLock(lock));
  for (const [label, mutate] of [
    [
      "swapped Node and frontend values",
      (candidate) => {
        const frontend = candidate.images["dockerfile-frontend"];
        candidate.images["dockerfile-frontend"] = candidate.images.node;
        candidate.images.node = frontend;
      },
    ],
    [
      "frontend rebound to another admitted lock member",
      (candidate) => {
        candidate.images["dockerfile-frontend"] = candidate.images.node;
      },
    ],
    [
      "missing exact frontend key",
      (candidate) => {
        candidate.images.frontend = candidate.images["dockerfile-frontend"];
        delete candidate.images["dockerfile-frontend"];
      },
    ],
    [
      "missing exact Node key",
      (candidate) => {
        candidate.images["node-runtime"] = candidate.images.node;
        delete candidate.images.node;
      },
    ],
  ]) {
    const mutant = structuredClone(lock);
    mutate(mutant);
    assert.throws(
      () => assertExactDockerfileSupplyChainLock(mutant),
      /exact (?:dockerfile-frontend|node) lock key|disjoint/i,
      `supply-chain key oracle admitted ${label}`,
    );
  }
});

test("Dockerignore semantics preserve every exact Dockerfile COPY source", () => {
  const repositoryRoot = path.resolve(scriptDir, "..");
  const dockerfilePath = path.join(
    repositoryRoot,
    "docker",
    "docker-action-broker.Dockerfile",
  );
  const { source: dockerignoreSource } =
    effectiveDockerignoreForDockerfile(repositoryRoot, dockerfilePath);
  const canonicalDockerfile = [
    `# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}`,
    ...canonicalProductionDockerfileInstructions(),
    "",
  ].join("\n");
  const canonicalSources = canonicalProductionDockerfileInstructions()
    .map(parseDockerCopyInstruction)
    .filter(Boolean)
    .flatMap(({ sources }) => sources)
    .sort();
  assert.deepEqual(
    assertDockerCopySourcesIncludedByDockerignore(
      canonicalDockerfile,
      dockerignoreSource,
    ),
    canonicalSources,
    "repository .dockerignore removed a production COPY dependency",
  );
  const fixtureDockerfile = [
    "FROM node:fixture",
    `COPY scripts/docker-action-worker.mjs ${WORKER_CONTAINER_PATH}`,
    "",
  ].join("\n");
  for (const [label, hostileDockerignore] of [
    [
      "exact worker exclusion",
      "scripts/docker-action-worker.mjs\n",
    ],
    [
      "excluded parent directory",
      "scripts/\n",
    ],
    [
      "single-segment glob",
      "scripts/*.mjs\n",
    ],
    [
      "recursive basename glob",
      "**/docker-action-worker.mjs\n",
    ],
    [
      "file negation beneath a still-excluded parent",
      "*\n!scripts/docker-action-worker.mjs\n",
    ],
    [
      "late re-exclusion after a valid negation",
      [
        "scripts/*.mjs",
        "!scripts/docker-action-worker.mjs",
        "scripts/docker-action-worker.mjs",
        "",
      ].join("\n"),
    ],
  ]) {
    assert.throws(
      () => assertDockerCopySourcesIncludedByDockerignore(
        fixtureDockerfile,
        hostileDockerignore,
      ),
      /Dockerignore excludes an exact Dockerfile COPY source/i,
      `Dockerignore closure admitted ${label}`,
    );
  }
  assert.deepEqual(
    assertDockerCopySourcesIncludedByDockerignore(
      fixtureDockerfile,
      [
        "scripts/*.mjs",
        "!scripts/docker-action-worker.mjs",
        "",
      ].join("\n"),
    ),
    ["scripts/docker-action-worker.mjs"],
    "Dockerignore closure did not honor an exact late file negation",
  );
  assert.deepEqual(
    assertDockerCopySourcesIncludedByDockerignore(
      fixtureDockerfile,
      [
        "scripts/",
        "!scripts/",
        "!scripts/docker-action-worker.mjs",
        "",
      ].join("\n"),
    ),
    ["scripts/docker-action-worker.mjs"],
    "Dockerignore closure did not honor explicit parent and leaf negations",
  );
});

test("Dockerignore uses Dockerfile-specific precedence and filepath.Clean identities", (t) => {
  const repositoryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "docker-worker-dockerignore-precedence-"),
  );
  t.after(() => fs.rmSync(repositoryRoot, { force: true, recursive: true }));
  const dockerDirectory = path.join(repositoryRoot, "docker");
  const dockerfilePath = path.join(dockerDirectory, "fixture.Dockerfile");
  const rootDockerignorePath = path.join(repositoryRoot, ".dockerignore");
  const dockerfileDockerignorePath = `${dockerfilePath}.dockerignore`;
  fs.mkdirSync(dockerDirectory, { mode: 0o700, recursive: true });
  fs.writeFileSync(dockerfilePath, "FROM node:fixture\n", { mode: 0o600 });
  fs.writeFileSync(rootDockerignorePath, "./scripts/../scripts/\n", {
    mode: 0o600,
  });
  const fixtureDockerfile = [
    "FROM node:fixture",
    `COPY ./scripts/./docker-action-worker.mjs ${WORKER_CONTAINER_PATH}`,
    "",
  ].join("\n");

  const rootFallback = effectiveDockerignoreForDockerfile(
    repositoryRoot,
    dockerfilePath,
  );
  assert.equal(rootFallback.path, rootDockerignorePath);
  assert.throws(
    () => assertDockerCopySourcesIncludedByDockerignore(
      fixtureDockerfile,
      rootFallback.source,
    ),
    /Dockerignore excludes an exact Dockerfile COPY source/i,
    "root Dockerignore fallback ignored filepath.Clean parent exclusion",
  );

  fs.writeFileSync(
    dockerfileDockerignorePath,
    "scripts/*.tmp\n",
    { mode: 0o600 },
  );
  const dockerfileSpecific = effectiveDockerignoreForDockerfile(
    repositoryRoot,
    dockerfilePath,
  );
  assert.equal(
    dockerfileSpecific.path,
    dockerfileDockerignorePath,
    "Dockerfile-specific Dockerignore did not take precedence over the root file",
  );
  assert.deepEqual(
    assertDockerCopySourcesIncludedByDockerignore(
      fixtureDockerfile,
      dockerfileSpecific.source,
    ),
    ["scripts/docker-action-worker.mjs"],
    "root Dockerignore leaked into Dockerfile-specific precedence",
  );

  for (const [label, dockerignoreSource] of [
    [
      "cleaned parent remains excluded under a leaf-only negation",
      [
        "*",
        "!./scripts/../scripts/docker-action-worker.mjs",
        "",
      ].join("\n"),
    ],
    [
      "last cleaned rule re-excludes a previously admitted leaf",
      [
        "./scripts/../scripts/*.mjs",
        "!./scripts/./docker-action-worker.mjs",
        "./scripts/../scripts/docker-action-worker.mjs",
        "",
      ].join("\n"),
    ],
  ]) {
    assert.throws(
      () => assertDockerCopySourcesIncludedByDockerignore(
        fixtureDockerfile,
        dockerignoreSource,
      ),
      /Dockerignore excludes an exact Dockerfile COPY source/i,
      `Dockerignore filepath.Clean oracle admitted ${label}`,
    );
  }
  assert.deepEqual(
    assertDockerCopySourcesIncludedByDockerignore(
      fixtureDockerfile,
      [
        "*",
        "!./scripts/../scripts/",
        "!./scripts/./docker-action-worker.mjs",
        "",
      ].join("\n"),
    ),
    ["scripts/docker-action-worker.mjs"],
    "cleaned parent and leaf negations did not restore the exact COPY identity",
  );
});

test("Dockerfile stage packages all seven exact root-owned fixed adapter targets", (t) => {
  const staged = stageDockerWorkerImageLayout(t, "docker-worker-adapter-package-stage-");
  const commands = Object.keys(EXPECTED_FIXED_ADAPTERS).sort();
  assert.deepEqual(
    commands,
    [...new Set(Object.values(EXPECTED_PHASE_PROFILES).map(({ command }) => command))].sort(),
    "fixed adapter oracle does not cover the exact seven phase commands",
  );
  assert.deepEqual(
    Object.keys(EXPECTED_FIXED_ADAPTER_SOURCE_TEXT).sort(),
    commands,
    "fixed adapter source oracle does not cover the exact seven phase commands",
  );
  const dockerfileSource = fs.readFileSync(staged.dockerfile, "utf8");
  for (const [command, expected] of Object.entries(EXPECTED_FIXED_ADAPTERS)) {
    assert.deepEqual(Object.keys(expected).sort(), ["api", "argv", "executable", "shell"]);
    assert.equal(expected.api, "spawn", `${command} must use the one admitted subprocess API`);
    assert.deepEqual(expected.argv, [], `${command} must not carry caller identity in argv`);
    assert.equal(expected.shell, false, `${command} must explicitly disable shell execution`);
    assert.match(
      expected.executable,
      new RegExp(`^/opt/platform-docker-worker/bin/${escapeRegExp(command)}$`),
    );
    assert.doesNotMatch(
      expected.executable,
      /(?:^|\/)(?:env|sh|bash|dash|zsh|node|python|perl|ruby|curl|wget|nc|ncat|socat|ssh)$/,
      `${command} collapsed to an interpreter, wrapper, shell, or network tool`,
    );
  }
  for (const [label, invocation] of [
    ["shell with token smuggling", {
      api: "spawn",
      executable: "/bin/sh",
      argv: ["-c", "id", "backup-catalog"],
      shell: false,
    }],
    ["environment wrapper", {
      api: "spawn",
      executable: "/usr/bin/env",
      argv: [EXPECTED_FIXED_ADAPTERS["backup-catalog"].executable],
      shell: false,
    }],
    ["network tool", {
      api: "spawn",
      executable: "/usr/bin/curl",
      argv: ["backup-catalog"],
      shell: false,
    }],
    ["wrong child API", {
      ...EXPECTED_FIXED_ADAPTERS["backup-catalog"],
      api: "execFile",
    }],
    ["caller argv", {
      ...EXPECTED_FIXED_ADAPTERS["backup-catalog"],
      argv: ["attacker"],
    }],
    ["implicit shell", {
      ...EXPECTED_FIXED_ADAPTERS["backup-catalog"],
      shell: true,
    }],
  ]) {
    assert.throws(
      () => assertFixedAdapterInvocation(invocation, "backup-catalog"),
      /exact code-owned adapter identity/i,
      `fixed adapter oracle admitted ${label}`,
    );
  }
  const assessment = fixedAdapterPackageAssessment({
    dockerfileSource,
    repositoryRoot: path.resolve(scriptDir, ".."),
    stagedRoot: staged.root,
  });
  assert.deepEqual(
    {
      auditedCommands: assessment.auditedCommands,
      issues: assessment.issues,
    },
    {
      auditedCommands: commands,
      issues: [],
    },
    "Dockerfile final stage is missing the seven repository-bound root:root 0555 adapter COPY contracts",
  );
});

test("fixed adapter package oracle rejects post-COPY mutations and non-canonical source semantics", (t) => {
  const repositoryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "docker-worker-adapter-oracle-repository-"),
  );
  t.after(() => fs.rmSync(repositoryRoot, { force: true, recursive: true }));
  const dockerfile = path.join(repositoryRoot, "Dockerfile");
  const sourceDirectory = path.join(repositoryRoot, "adapters");
  fs.mkdirSync(sourceDirectory, { mode: 0o700, recursive: true });
  fs.mkdirSync(path.join(repositoryRoot, "scripts"), { mode: 0o700, recursive: true });
  fs.writeFileSync(
    path.join(repositoryRoot, "scripts", "docker-action-worker.mjs"),
    "export async function runFixedToolEntry(command) { return command; }\n",
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(
      repositoryRoot,
      "scripts",
      "docker-action-worker-runtime-guard.mjs",
    ),
    "export {};\n",
    { mode: 0o600 },
  );
  const commands = Object.keys(EXPECTED_FIXED_ADAPTERS).sort();
  const sourceByCommand = Object.fromEntries(commands.map((command) => [
    command,
    `adapters/${command}.mjs`,
  ]));
  for (const [command, source] of Object.entries(sourceByCommand)) {
    fs.writeFileSync(
      path.join(repositoryRoot, source),
      EXPECTED_FIXED_ADAPTER_SOURCE_TEXT[command],
      { mode: 0o600 },
    );
  }
  const adapterCopies = commands.map((command) => (
    `COPY --chown=0:0 --chmod=0555 ${sourceByCommand[command]} ${EXPECTED_FIXED_ADAPTERS[command].executable}`
  ));
  const validDockerfileSource = [
    "FROM node:fixture",
    "COPY scripts/docker-action-worker.mjs /opt/platform-docker-worker/docker-action-worker.mjs",
    ...adapterCopies,
    `COPY --chown=0:0 --chmod=0555 scripts/docker-action-worker-runtime-guard.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
    `ENTRYPOINT ${JSON.stringify(EXPECTED_WORKER_ENTRYPOINT)}`,
    "",
  ].join("\n");
  fs.writeFileSync(dockerfile, validDockerfileSource, { mode: 0o600 });
  const staged = stageDockerWorkerImageLayout(
    t,
    "docker-worker-adapter-oracle-stage-",
    { dockerfile, repositoryRoot },
  );
  const valid = fixedAdapterPackageAssessment({
    dockerfileSource: validDockerfileSource,
    repositoryRoot,
    stagedRoot: staged.root,
  });
  assert.deepEqual(valid, {
    auditedCommands: commands,
    issues: [],
  });

  for (const [label, suffix, pattern] of [
    [
      "later chmod 0777",
      "\nRUN chmod 0777 /opt/platform-docker-worker/bin/backup-catalog\n",
      /filesystem-mutating instruction after the adapter COPY block/i,
    ],
    [
      "later chown 65532",
      "\nRUN chown 65532:65532 /opt/platform-docker-worker/bin/backup-catalog\n",
      /filesystem-mutating instruction after the adapter COPY block/i,
    ],
    [
      "dead branch chmod",
      "\nRUN false && chmod 0555 /opt/platform-docker-worker/bin/backup-catalog\n",
      /filesystem-mutating instruction after the adapter COPY block/i,
    ],
  ]) {
    const mutated = fixedAdapterPackageAssessment({
      dockerfileSource: `${validDockerfileSource}${suffix}`,
      repositoryRoot,
      stagedRoot: staged.root,
    });
    assert.match(
      mutated.issues.join("\n"),
      pattern,
      `ordered package oracle admitted ${label}`,
    );
  }

  const firstCommand = commands[0];
  const firstSource = path.join(repositoryRoot, sourceByCommand[firstCommand]);
  const admittedSource = fs.readFileSync(firstSource);
  fs.rmSync(firstSource);
  fs.symlinkSync(path.join(repositoryRoot, sourceByCommand[commands[1]]), firstSource);
  assert.match(
    fixedAdapterPackageAssessment({
      dockerfileSource: validDockerfileSource,
      repositoryRoot,
      stagedRoot: staged.root,
    }).issues.join("\n"),
    /source.*regular.*non-symlink/i,
    "package oracle admitted a symlinked repository source",
  );
  fs.rmSync(firstSource);
  fs.writeFileSync(firstSource, admittedSource, { mode: 0o600 });

  const firstTarget = stagedContainerPath(
    staged.root,
    EXPECTED_FIXED_ADAPTERS[firstCommand].executable,
  );
  const admittedTarget = fs.readFileSync(firstTarget);
  fs.chmodSync(firstTarget, 0o755);
  fs.appendFileSync(firstTarget, "tampered\n");
  fs.chmodSync(firstTarget, 0o555);
  assert.match(
    fixedAdapterPackageAssessment({
      dockerfileSource: validDockerfileSource,
      repositoryRoot,
      stagedRoot: staged.root,
    }).issues.join("\n"),
    /target bytes diverge/i,
    "package oracle admitted staged bytes different from the repository source",
  );
  fs.chmodSync(firstTarget, 0o755);
  fs.writeFileSync(firstTarget, admittedTarget, { mode: 0o555 });
  fs.chmodSync(firstTarget, 0o555);

  for (const [label, hostileSource] of [
    [
      "wrong literal command identity",
      EXPECTED_FIXED_ADAPTER_SOURCE_TEXT[firstCommand].replace(
        `"${firstCommand}"`,
        '"backup-job"',
      ),
    ],
    [
      "socketless forged output",
      `#!/usr/local/bin/node
import { runFixedToolEntry } from "../docker-action-worker.mjs";

void runFixedToolEntry;
process.stdout.write('{"status":"completed"}\\n');
`,
    ],
  ]) {
    fs.writeFileSync(firstSource, hostileSource, { mode: 0o600 });
    fs.chmodSync(firstTarget, 0o755);
    fs.writeFileSync(firstTarget, hostileSource, { mode: 0o555 });
    fs.chmodSync(firstTarget, 0o555);
    assert.match(
      fixedAdapterPackageAssessment({
        dockerfileSource: validDockerfileSource,
        repositoryRoot,
        stagedRoot: staged.root,
      }).issues.join("\n"),
      /source bytes do not match the exact adapter contract/i,
      `package oracle admitted ${label}`,
    );
  }
});

test("dummy fixed-adapter preload rejects every non-exact process identity before output", (t) => {
  const staged = stageDockerWorkerImageLayout(t, "docker-worker-adapter-hook-stage-");
  const command = "backup-catalog";
  const phaseId = "catalog.capture";
  const expected = EXPECTED_FIXED_ADAPTERS[command];
  const stagedTarget = stagedContainerPath(staged.root, expected.executable);
  fs.mkdirSync(path.dirname(stagedTarget), { mode: 0o700, recursive: true });
  fs.writeFileSync(
    stagedTarget,
    EXPECTED_FIXED_ADAPTER_SOURCE_TEXT[command],
    { mode: 0o555 },
  );
  fs.chmodSync(stagedTarget, 0o555);
  const expectedEnvironment = {
    HOME: staged.root,
    LANG: "C.UTF-8",
    PLATFORM_DOCKER_ACTION: "backup.catalog",
    PLATFORM_DOCKER_PHASE_ID: phaseId,
  };
  const expectedOutput = buildFixturePhaseOutputV2(
    "backup.catalog",
    phaseId,
    {},
  );
  const tracePath = path.join(staged.root, "adapter-hook-self-test.jsonl");
  const hookPath = path.join(staged.root, "adapter-hook-self-test.mjs");
  const guardPath = path.join(staged.root, "adapter-hook-runtime-guard.mjs");
  fs.writeFileSync(
    hookPath,
    fixedAdapterHookSource(tracePath, {
      expectedCommandByPhase: { [phaseId]: command },
      expectedEnvironmentByPhase: { [phaseId]: expectedEnvironment },
      expectedOutputByPhase: { [phaseId]: expectedOutput },
      stagedRoot: staged.root,
    }),
    { mode: 0o600 },
  );
  fs.writeFileSync(guardPath, socketlessRuntimeGuardSource(), { mode: 0o600 });
  const preloadArguments = [
    "--import",
    pathToFileURL(hookPath).href,
    "--import",
    pathToFileURL(guardPath).href,
    "--input-type=module",
    "--eval",
  ];
  const runProbe = (source) => spawnSync(
    process.execPath,
    [...preloadArguments, source],
    {
      encoding: "utf8",
      env: expectedEnvironment,
      maxBuffer: 32 * 1024,
    },
  );
  const admitted = runProbe(`
    import childProcess from "node:child_process";
    const child = childProcess.spawn(
      ${JSON.stringify(expected.executable)},
      [],
      {
        env: process.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    child.on("close", (code) => { process.exitCode = code; });
  `);
  assert.deepEqual(
    {
      signal: admitted.signal,
      status: admitted.status,
      stderr: admitted.stderr,
      stdout: admitted.stdout,
    },
    {
      signal: null,
      status: 0,
      stderr: "",
      stdout: `${JSON.stringify(expectedOutput)}\n`,
    },
  );
  const [trace] = readJsonLines(tracePath);
  assertFixedAdapterInvocation(trace, command);
  assert.deepEqual(trace.environment, expectedEnvironment);
  assert.deepEqual(trace.processEnvironment, expectedEnvironment);
  assert.equal(trace.preloadCount, 1);
  assert.equal(trace.socketlessGuardCount, 1);

  for (const [label, source, pattern] of [
    [
      "shell token smuggling",
      `import childProcess from "node:child_process";
       childProcess.spawn("/bin/sh", ["-c", "id", ${JSON.stringify(command)}], { shell: false });`,
      /non-exact fixed adapter spawn|exact code-owned identity/i,
    ],
    [
      "environment wrapper",
      `import childProcess from "node:child_process";
       childProcess.spawn("/usr/bin/env", [${JSON.stringify(expected.executable)}], { shell: false });`,
      /non-exact fixed adapter spawn|exact code-owned identity/i,
    ],
    [
      "network tool",
      `import childProcess from "node:child_process";
       childProcess.spawn("/usr/bin/curl", [${JSON.stringify(command)}], { shell: false });`,
      /non-exact fixed adapter spawn|exact code-owned identity/i,
    ],
    [
      "caller argv",
      `import childProcess from "node:child_process";
       childProcess.spawn(${JSON.stringify(expected.executable)}, ["attacker"], { shell: false });`,
      /non-exact fixed adapter spawn|exact code-owned identity/i,
    ],
    [
      "wrong API",
      `import childProcess from "node:child_process";
       childProcess.execFile(${JSON.stringify(expected.executable)}, [], { shell: false });`,
      /non-admitted child_process API/i,
    ],
  ]) {
    const rejected = runProbe(source);
    assert.notEqual(rejected.status, 0, `adapter preload admitted ${label}`);
    assert.equal(rejected.stdout, "", `${label} received forged adapter output`);
    assert.match(rejected.stderr, pattern, `${label} failed outside the exact adapter guard`);
    assert.equal(
      readJsonLines(tracePath).length,
      1,
      `${label} was traced as an admitted fixed adapter invocation`,
    );
  }

  fs.chmodSync(stagedTarget, 0o755);
  fs.writeFileSync(
    stagedTarget,
    EXPECTED_FIXED_ADAPTER_SOURCE_TEXT[command].replace(
      `"${command}"`,
      '"backup-job"',
    ),
  );
  fs.chmodSync(stagedTarget, 0o555);
  const wrongAdapter = runProbe(`
    import childProcess from "node:child_process";
    const child = childProcess.spawn(
      ${JSON.stringify(expected.executable)},
      [],
      {
        env: process.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  `);
  assert.notEqual(wrongAdapter.status, 0, "preload admitted a socketless wrong adapter body");
  assert.equal(wrongAdapter.stdout, "", "wrong adapter body received synthesized output");
  assert.match(
    wrongAdapter.stderr,
    /source bytes diverged from the exact adapter contract/i,
  );
  assert.equal(readJsonLines(tracePath).length, 1);
});

workerTest("Dockerfile-exact staged worker layout closes import and CLI dependencies", [
  "runWorkerCli",
], (t) => {
  const staged = stageDockerWorkerImageLayout(t, "docker-worker-dependency-stage-");
  const importProbe = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(staged.workerPath).href)});`,
    ],
    {
      cwd: staged.root,
      encoding: "utf8",
      env: {
        HOME: staged.root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
  assert.deepEqual(
    {
      signal: importProbe.signal,
      status: importProbe.status,
      stderr: importProbe.stderr,
      stdout: importProbe.stdout,
    },
    { signal: null, status: 0, stderr: "", stdout: "" },
    "worker import failed from the exact Dockerfile COPY closure",
  );

  const cliProbe = spawnSync(
    process.execPath,
    [staged.workerPath, "__dependency-closure-probe__"],
    {
      cwd: staged.root,
      encoding: "utf8",
      env: {
        HOME: staged.root,
        LANG: "C.UTF-8",
        NODE_ENV: "production",
      },
    },
  );
  assert.equal(cliProbe.signal, null);
  assert.notEqual(cliProbe.status, 0, "invalid staged CLI probe unexpectedly succeeded");
  assert.doesNotMatch(
    `${cliProbe.stderr}\n${cliProbe.stdout}`,
    /ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND|Cannot find (?:module|package)/i,
    "worker CLI dependency graph is absent from the Dockerfile-exact stage",
  );
  assert.match(
    cliProbe.stderr,
    /argument|command|environment|unsupported|worker action/i,
    "staged CLI did not reach the worker's own fail-closed argument boundary",
  );
});

test("real worker main executes all eight phases through one code-owned socketless adapter", (t) => {
  const requiredFunctions = [
    "loadClaimedJobSnapshot",
    "normalizeWorkerResult",
    "runFixedToolEntry",
    "runWorkerCli",
  ];
  assert.deepEqual(
    {
      exactWorkerBodyBaselineReady,
      missingFunctions: requiredFunctions.filter(
        (functionName) => typeof worker[functionName] !== "function",
      ),
    },
    {
      exactWorkerBodyBaselineReady: true,
      missingFunctions: [],
    },
    "true-main prerequisites must fail actively and may not collapse into a TODO gate",
  );
  const staged = stageDockerWorkerImageLayout(t, "docker-worker-main-stage-");
  const snapshotPath = path.join(staged.root, "claimed-job", "job.json");
  fs.mkdirSync(path.dirname(snapshotPath), { mode: 0o700, recursive: true });
  fs.chmodSync(path.dirname(snapshotPath), 0o700);

  const rawReceipt = buildRawActiveReceiptV2();
  rawReceipt.resources.claimedJobSources["jobs.running"].snapshotContainerPath = snapshotPath;
  const trusted = buildFixtureTrustedContextV2({ rawReceipt }).trusted;
  assert.notEqual(
    trusted.receiptDigest,
    WORKER_TRUSTED_CONTEXT.receiptDigest,
    "true-main matrix did not bind a custom trusted receipt",
  );
  assert.equal(
    trusted.receipt.resources.claimedJobSources["jobs.running"].snapshotContainerPath,
    snapshotPath,
  );
  const cases = phaseActionCases(trusted);
  assert.equal(cases.length, 8, "real-main matrix must cover every canonical phase");
  const expectedEnvironmentByPhase = Object.fromEntries(cases.map((phaseCase) => {
    const expectedBody = expectedWorkerBodyDocument(phaseCase, trusted);
    return [phaseCase.phaseId, environmentMap(expectedBody.Env)];
  }));
  const expectedCommandByPhase = Object.fromEntries(cases.map((phaseCase) => [
    phaseCase.phaseId,
    EXPECTED_PHASE_PROFILES[phaseCase.phaseId].command,
  ]));
  const expectedOutputByPhase = Object.fromEntries(cases.map((phaseCase) => [
    phaseCase.phaseId,
    buildFixturePhaseOutputV2(
      phaseCase.action,
      phaseCase.phaseId,
      phaseCase.parameters,
    ),
  ]));
  const hookPath = path.join(staged.root, "fixed-adapter-hook.mjs");
  const tracePath = path.join(staged.root, "fixed-adapter-trace.jsonl");
  fs.writeFileSync(
    hookPath,
    fixedAdapterHookSource(tracePath, {
      expectedCommandByPhase,
      expectedEnvironmentByPhase,
      expectedOutputByPhase,
      stagedRoot: staged.root,
    }),
    { mode: 0o600 },
  );
  const hookUrl = pathToFileURL(hookPath).href;
  const runtimeGuardPath = path.join(
    staged.root,
    WORKER_RUNTIME_GUARD_CONTAINER_PATH.replace(/^\/+/, ""),
  );
  assert.equal(
    fs.readFileSync(runtimeGuardPath, "utf8"),
    fs.readFileSync(workerRuntimeGuardPath, "utf8"),
    "real-main matrix did not consume the Dockerfile-staged production guard",
  );
  const instrumentedLocalEntrypoint = (body, preloadUrl) => {
    assert.deepEqual(body.Entrypoint, EXPECTED_WORKER_ENTRYPOINT);
    const localized = body.Entrypoint.map((argument, index) => {
      if (index === 0) return process.execPath;
      if (!argument.startsWith("/")) return argument;
      return path.join(staged.root, argument.replace(/^\/+/, ""));
    });
    return [
      localized[0],
      [
        "--import",
        preloadUrl,
        ...localized.slice(1, -1),
        localized.at(-1),
        ...body.Cmd,
      ],
    ];
  };
  let traceCount = 0;

  for (const phaseCase of cases) {
    fs.rmSync(snapshotPath, { force: true });
    if (phaseCase.snapshot) {
      const bytes = phaseCase.parameters.jobOperation === "backup"
        ? BACKUP_JOB_BYTES
        : RESTORE_JOB_BYTES;
      fs.writeFileSync(snapshotPath, bytes, { mode: 0o400 });
      fs.chmodSync(snapshotPath, 0o400);
    }
    const body = workerBodyForCase(phaseCase, trusted);
    const expectedBody = expectedWorkerBodyDocument(phaseCase, trusted);
    assertExactWorkerBody({ observedBody: body, phaseCase, trusted });
    assert.deepEqual(
      body,
      expectedBody,
      `${phaseCase.action}/${phaseCase.phaseId} diverged from the independent body oracle`,
    );
    assert.equal(
      body.Labels["com.platform.active-receipt-sha256"],
      trusted.receiptDigest,
      `${phaseCase.phaseId} did not bind the custom trusted receipt`,
    );
    const exactEnvironment = environmentMap(expectedBody.Env);
    assert.equal(Object.hasOwn(exactEnvironment, "NODE_OPTIONS"), false);
    if (phaseCase.snapshot) {
      assert.equal(exactEnvironment.PLATFORM_CLAIMED_JOB_PATH, snapshotPath);
    } else {
      assert.equal(Object.hasOwn(exactEnvironment, "PLATFORM_CLAIMED_JOB_PATH"), false);
    }
    const [workerExecutable, workerArgv] = instrumentedLocalEntrypoint(
      body,
      hookUrl,
    );
    const result = spawnSync(
      workerExecutable,
      workerArgv,
      {
        cwd: path.dirname(staged.workerPath),
        encoding: "utf8",
        env: exactEnvironment,
        maxBuffer: 32 * 1024,
      },
    );
    assert.deepEqual(
      { signal: result.signal, status: result.status, stderr: result.stderr },
      { signal: null, status: 0, stderr: "" },
      `${phaseCase.action}/${phaseCase.phaseId} real main failed`,
    );
    const expected = rawWorkerResult({
      action: phaseCase.action,
      command: expectedBody.Cmd[0],
      job: phaseCase.snapshot ? claimedJobParameters(phaseCase.snapshot) : null,
      phaseId: phaseCase.phaseId,
      requestId: phaseCase.request.requestId,
    });
    assert.equal(result.stdout, `${JSON.stringify(expected)}\n`);
    assert.ok(
      Buffer.byteLength(result.stdout.trimEnd()) <= MAX_PHASE_OUTPUT_BYTES_V2,
      `${phaseCase.phaseId} main output exceeded the worker stdout contract`,
    );

    const traces = readJsonLines(tracePath);
    assert.equal(
      traces.length,
      traceCount + 1,
      `${phaseCase.phaseId} did not invoke exactly one fixed adapter process`,
    );
    traceCount = traces.length;
    const trace = traces.at(-1);
    assert.deepEqual(
      trace.environment,
      Object.fromEntries(Object.entries(exactEnvironment).sort(([left], [right]) => left.localeCompare(right))),
      `${phaseCase.phaseId} adapter did not inherit the exact broker body environment`,
    );
    assert.deepEqual(
      trace.processEnvironment,
      Object.fromEntries(Object.entries(exactEnvironment).sort(([left], [right]) => left.localeCompare(right))),
      `${phaseCase.phaseId} preload observed a widened worker process environment`,
    );
    assert.equal(trace.preloadCount, 1, `${phaseCase.phaseId} preload did not execute exactly once`);
    assert.equal(
      trace.socketlessGuardCount,
      1,
      `${phaseCase.phaseId} socketless runtime guard did not execute exactly once`,
    );
    assert.deepEqual(
      {
        api: trace.api,
        argv: trace.argv,
        executable: trace.executable,
        shell: trace.shell,
      },
      EXPECTED_FIXED_ADAPTERS[expectedBody.Cmd[0]],
      `${phaseCase.phaseId} escaped the exact fixed adapter identity`,
    );
    const callerValues = new Set([
      ...Object.values(exactEnvironment),
      phaseCase.parameters.jobFileName,
      phaseCase.parameters.jobId,
      phaseCase.parameters.jobOperation,
      phaseCase.parameters.jobSha256,
    ].filter((value) => typeof value === "string" && value.length > 0));
    assert.equal(
      [trace.executable, ...trace.argv].some(
        (entry) => [...callerValues].some((value) => String(entry).includes(value)),
      ),
      false,
      `${phaseCase.phaseId} projected caller-controlled identity into adapter executable/argv`,
    );
    assertFixedAdapterInvocation(trace, expectedBody.Cmd[0]);
  }
  assert.equal(traceCount, 8, "real main matrix did not execute all eight phase adapters");

  const hostileCase = cases.find(({ phaseId }) => phaseId === "restore.verify");
  const hostileBody = workerBodyForCase(hostileCase, trusted);
  const hostileExpectedBody = expectedWorkerBodyDocument(hostileCase, trusted);
  assert.deepEqual(hostileBody, hostileExpectedBody);
  const hostileEnvironment = environmentMap(hostileExpectedBody.Env);
  for (const [label, hookOptions, pattern] of [
    [
      "oversized adapter output",
      { oversizedOutput: true },
      /output|oversized|length|byte|schema/i,
    ],
    [
      "non-zero adapter exit",
      { exitStatus: 17 },
      /adapter|command|exit|failed|status|tool/i,
    ],
  ]) {
    const suffix = label.replaceAll(" ", "-");
    const hostileHookPath = path.join(staged.root, `${suffix}-hook.mjs`);
    const hostileTracePath = path.join(staged.root, `${suffix}-trace.jsonl`);
    fs.writeFileSync(
      hostileHookPath,
      fixedAdapterHookSource(hostileTracePath, {
        ...hookOptions,
        expectedCommandByPhase,
        expectedEnvironmentByPhase,
        expectedOutputByPhase,
        stagedRoot: staged.root,
      }),
      { mode: 0o600 },
    );
    const [hostileExecutable, hostileArgv] = instrumentedLocalEntrypoint(
      hostileBody,
      pathToFileURL(hostileHookPath).href,
    );
    const rejected = spawnSync(
      hostileExecutable,
      hostileArgv,
      {
        cwd: path.dirname(staged.workerPath),
        encoding: "utf8",
        env: hostileEnvironment,
        maxBuffer: 32 * 1024,
      },
    );
    assert.equal(rejected.signal, null, `${label} killed the real worker main`);
    assert.equal(rejected.status, 78, `${label} did not produce the fixed worker failure exit`);
    assert.equal(rejected.stdout, "", `${label} emitted an admitted result`);
    assert.match(rejected.stderr, pattern, `${label} failed at an unrelated boundary`);
    assert.equal(readJsonLines(hostileTracePath).length, 1, `${label} did not reach one adapter`);
  }
});

test("manifest fixture oracle independently canonicalizes digests and separates HMAC domains", () => {
  const fixture = signedManifestEnvelope();
  const artifactPath = "postgres/worker-test.dump";
  const sidecar = fixture.sidecars[artifactPath];
  const digest = testManifestDigest(fixture.unsigned);
  assert.equal(digest, fixture.manifest.signature.digest);
  assert.equal(testManifestDigest(fixture.manifest), digest);
  assert.equal(
    testManifestDigest(reverseObjectKeyOrder(fixture.unsigned)),
    digest,
    "manifest digest must be independent of object insertion order",
  );
  assert.notEqual(
    testCryptoSha256(JSON.stringify(fixture.unsigned)),
    digest,
    "manifest fixture accidentally collapsed to insertion-order JSON hashing",
  );
  assert.equal(
    testCryptoSha256(fixture.artifactBytes),
    fixture.manifest.artifacts[0].sha256,
  );
  assert.equal(
    testHmacBase64Url(
      MANIFEST_TEST_KEY,
      `platform-backup-manifest-v1\n${fixture.unsigned.id}\n${digest}\n`,
    ),
    fixture.manifest.signature.value,
  );
  assert.equal(
    testHmacBase64Url(
      ARTIFACT_TEST_KEY,
      `platform-postgres-backup-v1\n${path.basename(artifactPath)}\n${sidecar.sha256}\n`,
    ),
    sidecar.signature,
  );
  assert.notEqual(
    testHmacBase64Url(
      MANIFEST_TEST_KEY,
      `platform-backup-manifest-v1\n${fixture.unsigned.id}\n${digest}\n`,
    ),
    testHmacBase64Url(
      MANIFEST_TEST_KEY,
      `platform-postgres-backup-v1\n${path.basename(artifactPath)}\n${sidecar.sha256}\n`,
    ),
    "manifest and artifact HMAC messages collapsed across domains",
  );

  for (const [label, mutate] of [
    ["manifest ID", (value) => { value.id = "manifest-worker-evil"; }],
    ["nested resource", (value) => { value.resources[0].name = "postgres-evil"; }],
    ["artifact path", (value) => { value.artifacts[0].path = "postgres/evil-test.dump"; }],
    ["coverage", (value) => { value.coverage.requiredResourceIds = ["database:mariadb"]; }],
    ["timestamp", (value) => { value.createdAt = "2026-07-26T12:00:01.000Z"; }],
  ]) {
    const mutated = structuredClone(fixture.unsigned);
    mutate(mutated);
    assert.notEqual(
      testManifestDigest(mutated),
      digest,
      `independent manifest digest collapsed ${label}`,
    );
  }
  const artifactTamper = Buffer.from(fixture.artifactBytes);
  artifactTamper[0] ^= 0x20;
  assert.equal(artifactTamper.length, fixture.artifactBytes.length);
  assert.notEqual(
    testCryptoSha256(artifactTamper),
    sidecar.sha256,
    "independent artifact digest collapsed a same-size byte mutation",
  );
});

workerTest("real manifest and sidecar files are bound by digest, key ID and domain-separated HMAC", [
  "readProtectedFile",
  "verifyManifestEnvelope",
], (t) => {
  const readProtectedFile = requireWorkerFunction("readProtectedFile");
  const verifyManifestEnvelope = requireWorkerFunction("verifyManifestEnvelope");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-worker-manifest-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.chmodSync(root, 0o700);
  const uid = process.getuid?.() ?? fs.statSync(root).uid;
  const gid = process.getgid?.() ?? fs.statSync(root).gid;
  const policy = protectedFilePolicy(root, uid, gid);
  const fixture = signedManifestEnvelope();
  const manifestFile = path.join(root, "manifest.json");
  const sidecarFile = path.join(root, "artifact.sig.json");
  const artifactFile = path.join(root, "worker-test.dump");
  writeProtectedJson(manifestFile, fixture.manifest);
  writeProtectedJson(sidecarFile, fixture.sidecars["postgres/worker-test.dump"]);
  fs.writeFileSync(artifactFile, fixture.artifactBytes, { mode: 0o600 });

  const loadEnvelope = () => ({
    manifest: JSON.parse(Buffer.from(readProtectedFile(manifestFile, policy)).toString("utf8")),
    sidecars: {
      "postgres/worker-test.dump": JSON.parse(
        Buffer.from(readProtectedFile(sidecarFile, policy)).toString("utf8"),
      ),
    },
  });
  const loadOptions = () => ({
    ...manifestVerificationOptions(),
    artifactBytes: {
      "postgres/worker-test.dump": Buffer.from(readProtectedFile(artifactFile, policy)),
    },
  });
  const options = loadOptions();
  const verified = verifyManifestEnvelope(loadEnvelope(), options);
  assert.equal(verified.manifestDigest, fixture.manifest.signature.digest);
  assert.equal(verified.artifactCount, 1);
  assert.equal(
    testCryptoSha256(options.artifactBytes["postgres/worker-test.dump"]),
    fixture.manifest.artifacts[0].sha256,
  );

  writeProtectedJson(manifestFile, {
    ...fixture.manifest,
    resources: [{
      ...fixture.manifest.resources[0],
      name: "postgres-evil",
    }],
  });
  assert.throws(
    () => verifyManifestEnvelope(loadEnvelope(), loadOptions()),
    /manifest|digest|sha256|authentication|signature/i,
    "nested manifest mutation collapsed under the admitted digest",
  );
  writeProtectedJson(manifestFile, fixture.manifest);

  writeProtectedJson(manifestFile, {
    ...fixture.manifest,
    signature: {
      ...fixture.manifest.signature,
      value: fixture.sidecars["postgres/worker-test.dump"].signature,
    },
  });
  assert.throws(
    () => verifyManifestEnvelope(loadEnvelope(), loadOptions()),
    /manifest|HMAC|authentication|signature/i,
    "artifact-domain HMAC authenticated a manifest-domain message",
  );
  writeProtectedJson(manifestFile, fixture.manifest);

  writeProtectedJson(sidecarFile, {
    ...fixture.sidecars["postgres/worker-test.dump"],
    signature: fixture.manifest.signature.value,
  });
  assert.throws(
    () => verifyManifestEnvelope(loadEnvelope(), loadOptions()),
    /sidecar|artifact|HMAC|authentication|signature/i,
    "manifest-domain HMAC authenticated an artifact-domain message",
  );
  writeProtectedJson(sidecarFile, fixture.sidecars["postgres/worker-test.dump"]);

  fs.writeFileSync(artifactFile, Buffer.from("worker test attacker\n"));
  fs.chmodSync(artifactFile, 0o600);
  assert.equal(
    fs.statSync(artifactFile).size,
    fixture.artifactBytes.length,
    "artifact substitution fixture must preserve the recorded byte length",
  );
  assert.throws(
    () => verifyManifestEnvelope(loadEnvelope(), loadOptions()),
    /artifact|bytes|digest|sha256|signature/i,
  );
  fs.writeFileSync(artifactFile, fixture.artifactBytes);
  fs.chmodSync(artifactFile, 0o600);

  writeProtectedJson(sidecarFile, {
    ...fixture.sidecars["postgres/worker-test.dump"],
    sha256: "8".repeat(64),
  });
  assert.throws(
    () => verifyManifestEnvelope(loadEnvelope(), loadOptions()),
    /sidecar|artifact|digest|sha256|signature/i,
  );

  writeProtectedJson(sidecarFile, fixture.sidecars["postgres/worker-test.dump"]);
  writeProtectedJson(manifestFile, {
    ...fixture.manifest,
    signature: {
      ...fixture.manifest.signature,
      value: Buffer.alloc(32, 0x58).toString("base64url"),
    },
  });
  assert.throws(
    () => verifyManifestEnvelope(loadEnvelope(), loadOptions()),
    /manifest|HMAC|authentication|signature/i,
  );

  writeProtectedJson(manifestFile, {
    ...fixture.manifest,
    signature: { ...fixture.manifest.signature, keyId: "manifest-test-unknown" },
  });
  assert.throws(
    () => verifyManifestEnvelope(loadEnvelope(), loadOptions()),
    /key.?id|key|signature/i,
  );
});

workerTest("worker result normalization binds request, action, phase and the complete claimed-job identity", [
  "normalizeWorkerResult",
], () => {
  const normalizeWorkerResult = requireWorkerFunction("normalizeWorkerResult");
  assert.equal(
    Number.isSafeInteger(worker.MAX_WORKER_STDOUT_BYTES),
    true,
    "docker-action-worker must export an integer MAX_WORKER_STDOUT_BYTES",
  );
  assert.equal(MAX_PHASE_OUTPUT_BYTES_V2, 4096);
  assert.equal(worker.MAX_WORKER_STDOUT_BYTES, MAX_PHASE_OUTPUT_BYTES_V2);

  const identity = {
    action: "backup.job.execute",
    job: {
      jobFileName: `${BACKUP_JOB_ID}.json`,
      jobId: BACKUP_JOB_ID,
      jobOperation: "backup",
      jobSha256: BACKUP_JOB_SHA256,
    },
    outputSchema: "platform.backup-job-result/v1",
    phaseId: "job.backup.capture",
    requestId: REQUEST_ID,
  };
  const candidate = rawWorkerResult({
    action: identity.action,
    command: "backup-job",
    job: identity.job,
    phaseId: identity.phaseId,
    requestId: identity.requestId,
  });
  const normalized = normalizeWorkerResult("backup-job", candidate, identity);
  assert.deepEqual(normalized, candidate);
  assert.ok(Buffer.byteLength(JSON.stringify(normalized)) <= worker.MAX_WORKER_STDOUT_BYTES);

  for (const [label, substituted] of [
    ["request", { ...candidate, requestId: "123e4567-e89b-42d3-a456-426614174999" }],
    ["action", { ...candidate, action: "backup.prune.apply" }],
    ["phase", { ...candidate, phaseId: "job.restore.verify" }],
    ["command", { ...candidate, command: "restore-job" }],
    ["job operation", {
      ...candidate,
      job: { ...candidate.job, jobOperation: "restore-drill" },
    }],
    ["job filename", {
      ...candidate,
      job: { ...candidate.job, jobFileName: `${RESTORE_JOB_ID}.json` },
    }],
    ["job ID", {
      ...candidate,
      job: { ...candidate.job, jobId: RESTORE_JOB_ID },
    }],
    ["job digest", {
      ...candidate,
      job: { ...candidate.job, jobSha256: "7".repeat(64) },
    }],
    ["unmodeled job source", {
      ...candidate,
      job: { ...candidate.job, sourceId: "jobs.running" },
    }],
    ["output schema", {
      ...candidate,
      output: { ...candidate.output, schema: "platform.restore-drill/v1" },
    }],
    ["detail array", {
      ...candidate,
      output: { ...candidate.output, details: { artifactPaths: ["postgres/worker-test.dump"] } },
    }],
    ["artifact array", {
      ...candidate,
      output: { ...candidate.output, artifacts: [{ path: "postgres/worker-test.dump" }] },
    }],
    ["artifact digest", {
      ...candidate,
      output: { ...candidate.output, artifactSetSha256: "not-a-digest" },
    }],
    ["oversized evidence", {
      ...candidate,
      output: {
        ...candidate.output,
        evidenceSha256: "a".repeat(worker.MAX_WORKER_STDOUT_BYTES + 1),
      },
    }],
  ]) {
    assert.throws(
      () => normalizeWorkerResult("backup-job", substituted, identity),
      /unsupported|array|detail|field|schema|digest|sha256|oversized|length|identity|request|action|phase|command|job|operation/i,
      `${label} substitution must not cross worker result admission`,
    );
  }
});

test("prune seal oracle independently binds canonical digest, key and MAC domains", () => {
  const plan = {
    schema: "platform.backup-prune-sealed-plan/v1",
    planId: "prune-plan-worker-test",
    artifactCount: 2,
    artifactSetSha256: "a".repeat(64),
    candidatePaths: [
      "postgres/expired-one.dump",
      "manifests/manifest-expired.json",
    ],
  };
  const key = { keyId: "prune-test-v1", key: PRUNE_TEST_KEY };
  const seal = testPrunePlanSeal(plan, key);
  assert.deepEqual(seal, {
    algorithm: "HMAC-SHA256",
    digest: "18f546d44c38efab8b4a502aff8017916f96518b8bdc0f1ad8f9482e8450cc76",
    keyId: "prune-test-v1",
    value: "jCGw3PRX5vSGcQcj_EVm_49ngC4Wo2Sb9ecuVknEXBo",
  });
  assert.deepEqual(
    testPrunePlanSeal(reverseObjectKeyOrder(plan), key),
    seal,
    "prune seal changed under recursive object-key reordering",
  );
  assert.equal(
    testPrunePlanDigest({ ...structuredClone(plan), seal }),
    seal.digest,
    "prune canonicalizer did not omit the one exact top-level seal field",
  );
  for (const [label, mutant] of [
    [
      "legacy signature alias",
      {
        ...structuredClone(plan),
        signature: structuredClone(seal),
      },
    ],
    [
      "seal alias",
      {
        ...structuredClone(plan),
        authenticatedSeal: structuredClone(seal),
      },
    ],
    [
      "schema drift",
      {
        ...structuredClone(plan),
        schema: "platform.backup-prune-sealed-plan/v2",
      },
    ],
  ]) {
    assert.throws(
      () => testPrunePlanDigest(mutant),
      /exact prune plan schema|schema identity/i,
      `prune canonicalizer admitted ${label}`,
    );
  }
  for (const [label, mutant] of [
    [
      "same-size nested candidate substitution",
      {
        ...structuredClone(plan),
        candidatePaths: [
          "postgres/expired-two.dump",
          "manifests/manifest-expired.json",
        ],
      },
    ],
    [
      "same-size artifact-set substitution",
      {
        ...structuredClone(plan),
        artifactSetSha256: `${"a".repeat(63)}b`,
      },
    ],
    [
      "nested candidate order substitution",
      {
        ...structuredClone(plan),
        candidatePaths: [...plan.candidatePaths].reverse(),
      },
    ],
  ]) {
    assert.equal(
      JSON.stringify(mutant).length,
      JSON.stringify(plan).length,
      `${label} is not a same-size causality mutant`,
    );
    assert.notEqual(
      testPrunePlanDigest(mutant),
      seal.digest,
      `prune digest oracle admitted ${label}`,
    );
    assert.notEqual(
      testPrunePlanMac(mutant, key),
      seal.value,
      `prune MAC oracle admitted ${label}`,
    );
  }
  const wrongKey = { keyId: key.keyId, key: Buffer.alloc(48, 0x51) };
  const wrongKeyId = { keyId: "prune-test-v2", key: key.key };
  assert.equal(testPrunePlanDigest(plan), seal.digest);
  assert.notEqual(testPrunePlanMac(plan, wrongKey), seal.value);
  assert.notEqual(testPrunePlanMac(plan, wrongKeyId), seal.value);
  assert.notEqual(
    testHmacBase64Url(
      key.key,
      `${PRUNE_PLAN_DIGEST_DOMAIN}${key.keyId}\0${plan.planId}\0${seal.digest}\0`,
    ),
    seal.value,
    "prune MAC oracle collapsed its explicit MAC and digest domains",
  );
});

workerTest("prune state requires a sealed plan, quarantine barrier and exact committed digest", [
  "applyPruneTransition",
  "planPruneTransition",
], () => {
  const planPruneTransition = requireWorkerFunction("planPruneTransition");
  const applyPruneTransition = requireWorkerFunction("applyPruneTransition");
  const plan = {
    schema: "platform.backup-prune-sealed-plan/v1",
    planId: "prune-plan-worker-test",
    artifactCount: 2,
    artifactSetSha256: "a".repeat(64),
    candidatePaths: [
      "postgres/expired-one.dump",
      "manifests/manifest-expired.json",
    ],
  };
  const sealKey = { keyId: "prune-test-v1", key: PRUNE_TEST_KEY };
  assert.throws(
    () => planPruneTransition(
      { phase: "empty" },
      {
        type: "seal",
        plan: {
          ...structuredClone(plan),
          signature: testPrunePlanSeal(plan, sealKey),
        },
      },
      sealKey,
    ),
    /field|schema|signature|seal|unsupported/i,
    "prune transition admitted a legacy signature alias outside the exact plan schema",
  );
  const sealed = planPruneTransition({ phase: "empty" }, { type: "seal", plan }, sealKey);
  assert.equal(sealed.phase, "sealed");
  assert.deepEqual(
    Object.keys(sealed.plan.seal).sort(),
    ["algorithm", "digest", "keyId", "value"],
    "sealed prune plan must expose one exact authenticated seal",
  );
  assert.deepEqual(
    sealed.plan.seal,
    testPrunePlanSeal(plan, sealKey),
    "prune transition accepted a self-derived digest or MAC",
  );
  const reorderedSealed = planPruneTransition(
    { phase: "empty" },
    { type: "seal", plan: reverseObjectKeyOrder(plan) },
    sealKey,
  );
  assert.deepEqual(
    reorderedSealed.plan.seal,
    sealed.plan.seal,
    "prune transition seal depends on object insertion order",
  );
  const sameSizeNestedMutation = {
    ...structuredClone(plan),
    candidatePaths: [
      "postgres/expired-two.dump",
      "manifests/manifest-expired.json",
    ],
  };
  assert.equal(
    JSON.stringify(sameSizeNestedMutation).length,
    JSON.stringify(plan).length,
    "prune product causality mutant is not same-size",
  );
  const mutationSealed = planPruneTransition(
    { phase: "empty" },
    { type: "seal", plan: sameSizeNestedMutation },
    sealKey,
  );
  assert.deepEqual(
    mutationSealed.plan.seal,
    testPrunePlanSeal(sameSizeNestedMutation, sealKey),
    "prune transition did not authenticate the nested mutation independently",
  );
  assert.notEqual(mutationSealed.plan.seal.digest, sealed.plan.seal.digest);
  assert.notEqual(mutationSealed.plan.seal.value, sealed.plan.seal.value);

  assert.throws(
    () => applyPruneTransition(sealed, {
      type: "commit-delete",
      planDigest: sealed.plan.seal.digest,
      quarantineDigest: "c".repeat(64),
    }, { keys: { [sealKey.keyId]: sealKey.key } }),
    /quarantine|phase|barrier|transition/i,
  );
  for (const [label, keys] of [
    [
      "wrong key bytes",
      { [sealKey.keyId]: Buffer.alloc(PRUNE_TEST_KEY.length, 0x51) },
    ],
    ["unknown key id", {}],
    ["wrong known key id", { "prune-test-v2": PRUNE_TEST_KEY }],
  ]) {
    assert.throws(
      () => applyPruneTransition(sealed, {
        type: "quarantine",
        planDigest: sealed.plan.seal.digest,
        quarantineDigest: "c".repeat(64),
        artifactCount: plan.artifactCount,
      }, { keys }),
      /key|HMAC|MAC|seal|signature|authenticated|unknown/i,
      `prune transition admitted ${label}`,
    );
  }
  const retainedSealPlanMutants = [
    [
      "same-size candidatePaths substitution",
      [
        "postgres/expired-two.dump",
        "manifests/manifest-expired.json",
      ],
    ],
    [
      "candidatePaths reordering",
      [...plan.candidatePaths].reverse(),
    ],
  ];
  for (const [label, candidatePaths] of retainedSealPlanMutants) {
    const tamperedSealed = structuredClone(sealed);
    tamperedSealed.plan.candidatePaths = candidatePaths;
    assert.equal(
      JSON.stringify(tamperedSealed.plan).length,
      JSON.stringify(sealed.plan).length,
      `${label} changed the sealed plan byte length`,
    );
    assert.deepEqual(
      tamperedSealed.plan.seal,
      sealed.plan.seal,
      `${label} did not retain the original authenticated seal`,
    );
    assert.throws(
      () => applyPruneTransition(tamperedSealed, {
        type: "quarantine",
        planDigest: sealed.plan.seal.digest,
        quarantineDigest: "c".repeat(64),
        artifactCount: plan.artifactCount,
      }, { keys: { [sealKey.keyId]: sealKey.key } }),
      /digest|HMAC|MAC|seal|signature|authenticated|substitution|candidate/i,
      `quarantine consumer did not recalculate the plan after ${label}`,
    );
  }
  const signatureAliasSealed = structuredClone(sealed);
  signatureAliasSealed.plan.signature = structuredClone(sealed.plan.seal);
  assert.throws(
    () => applyPruneTransition(signatureAliasSealed, {
      type: "quarantine",
      planDigest: sealed.plan.seal.digest,
      quarantineDigest: "c".repeat(64),
      artifactCount: plan.artifactCount,
    }, { keys: { [sealKey.keyId]: sealKey.key } }),
    /field|schema|signature|seal|unsupported/i,
    "quarantine consumer admitted a signature alias outside the exact plan schema",
  );
  const quarantined = applyPruneTransition(sealed, {
    type: "quarantine",
    planDigest: sealed.plan.seal.digest,
    quarantineDigest: "c".repeat(64),
    artifactCount: plan.artifactCount,
  }, { keys: { [sealKey.keyId]: sealKey.key } });
  assert.equal(quarantined.phase, "quarantined");
  assert.equal(quarantined.deletionCommitted, false);
  for (const [label, candidatePaths] of retainedSealPlanMutants) {
    const tamperedQuarantined = structuredClone(quarantined);
    tamperedQuarantined.plan.candidatePaths = candidatePaths;
    assert.equal(
      JSON.stringify(tamperedQuarantined.plan).length,
      JSON.stringify(quarantined.plan).length,
      `${label} changed the quarantined plan byte length`,
    );
    assert.deepEqual(
      tamperedQuarantined.plan.seal,
      quarantined.plan.seal,
      `${label} did not retain the quarantined authenticated seal`,
    );
    assert.throws(
      () => applyPruneTransition(tamperedQuarantined, {
        type: "commit-delete",
        planDigest: sealed.plan.seal.digest,
        quarantineDigest: quarantined.quarantineDigest,
      }, { keys: { [sealKey.keyId]: sealKey.key } }),
      /digest|HMAC|MAC|seal|signature|authenticated|substitution|candidate/i,
      `commit consumer did not recalculate the plan after ${label}`,
    );
  }
  assert.throws(
    () => applyPruneTransition(quarantined, {
      type: "commit-delete",
      planDigest: "d".repeat(64),
      quarantineDigest: quarantined.quarantineDigest,
    }, { keys: { [sealKey.keyId]: sealKey.key } }),
    /digest|sealed|substitution/i,
  );
  const applied = applyPruneTransition(quarantined, {
    type: "commit-delete",
    planDigest: sealed.plan.seal.digest,
    quarantineDigest: quarantined.quarantineDigest,
  }, { keys: { [sealKey.keyId]: sealKey.key } });
  assert.equal(applied.phase, "applied");
  assert.equal(applied.deletionCommitted, true);
});

workerTest("restore state enforces prepare, restore, verify, barrier and reverse cleanup", [
  "reverseCleanupOrder",
  "transitionRestorePhase",
], () => {
  const transitionRestorePhase = requireWorkerFunction("transitionRestorePhase");
  const reverseCleanupOrder = requireWorkerFunction("reverseCleanupOrder");
  const digest = "e".repeat(64);
  const created = {
    phase: "created",
    cleanupStack: ["postgres", "mariadb", "minio"],
    verifiedArtifactSetSha256: digest,
  };
  assert.throws(
    () => transitionRestorePhase(created, { type: "barrier-passed" }),
    /phase|prepare|transition|barrier/i,
  );
  const prepared = transitionRestorePhase(created, { type: "prepare-complete" });
  const restored = transitionRestorePhase(prepared, { type: "restore-complete" });
  const verified = transitionRestorePhase(restored, {
    type: "verify-complete",
    restoredArtifactSetSha256: digest,
  });
  assert.equal(verified.phase, "verified");
  assert.throws(
    () => transitionRestorePhase(verified, {
      type: "barrier-passed",
      restoredArtifactSetSha256: "f".repeat(64),
    }),
    /barrier|digest|artifact|substitution/i,
  );
  const barrier = transitionRestorePhase(verified, {
    type: "barrier-passed",
    restoredArtifactSetSha256: digest,
  });
  assert.equal(barrier.phase, "barrier-passed");
  assert.deepEqual(reverseCleanupOrder(barrier.cleanupStack), ["minio", "mariadb", "postgres"]);
  assert.throws(
    () => transitionRestorePhase(barrier, { type: "shell", command: "true" }),
    /unsupported|transition|event/i,
  );
});

workerTest("offsite state binds idempotency and preserves remote-unknown ambiguity", [
  "transitionOffsiteAttempt",
], () => {
  const transitionOffsiteAttempt = requireWorkerFunction("transitionOffsiteAttempt");
  const manifestDigest = "1".repeat(64);
  const idempotencyKey = testCryptoSha256(`platform-offsite-sync-v1\n${manifestDigest}\n`);
  const begin = { type: "begin", idempotencyKey, manifestDigest };
  const idle = {
    phase: "idle",
    idempotencyKey: null,
    manifestDigest: null,
    snapshotId: null,
  };
  assert.throws(
    () => transitionOffsiteAttempt(idle, { ...begin, idempotencyKey: "2".repeat(64) }),
    /idempotency|manifest|digest/i,
  );
  const inFlight = transitionOffsiteAttempt(idle, begin);
  const complete = transitionOffsiteAttempt(inFlight, {
    type: "commit",
    idempotencyKey,
    manifestDigest,
    snapshotId: "3".repeat(64),
  });
  assert.equal(complete.phase, "complete");
  assert.deepEqual(transitionOffsiteAttempt(complete, begin), complete);

  const remoteUnknown = transitionOffsiteAttempt(inFlight, {
    type: "transport-unknown",
    idempotencyKey,
    manifestDigest,
  });
  assert.equal(remoteUnknown.phase, "remote-unknown");
  assert.equal(remoteUnknown.retryAllowed, false);
  assert.throws(
    () => transitionOffsiteAttempt(remoteUnknown, begin),
    /remote-unknown|reconcile|retry/i,
  );
});

function phaseActionCases(trusted = WORKER_TRUSTED_CONTEXT) {
  const definitions = [
    { action: "backup.catalog", parameters: {}, phaseId: "catalog.capture", requestOffset: 2 },
    {
      action: "backup.job.execute",
      parameters: backupJobParameters("backup"),
      phaseId: "job.backup.capture",
      requestOffset: 0,
    },
    {
      action: "backup.job.execute",
      parameters: {
        jobFileName: `${RESTORE_JOB_ID}.json`,
        jobId: RESTORE_JOB_ID,
        jobOperation: "restore-drill",
        jobSha256: RESTORE_JOB_SHA256,
      },
      phaseId: "job.restore.verify",
      requestOffset: 1,
    },
    { action: "backup.prune.plan", parameters: {}, phaseId: "prune.plan", requestOffset: 3 },
    { action: "backup.prune.apply", parameters: {}, phaseId: "prune.apply", requestOffset: 4 },
    { action: "restore.drill.full", parameters: {}, phaseId: "restore.capture", requestOffset: 5 },
    { action: "restore.drill.full", parameters: {}, phaseId: "restore.verify", requestOffset: 6 },
    { action: "backup.offsite.sync", parameters: {}, phaseId: "offsite.sync", requestOffset: 7 },
  ];
  const cases = definitions.map((definition) => {
    const request = buildFixtureSignedActionRequestV2(
      definition.action,
      definition.parameters,
      {
        index: REQUEST_INDEX + definition.requestOffset,
        trustedContext: trusted,
      },
    );
    const snapshot = definition.action === "backup.job.execute"
      ? sealedClaimedJobSnapshot({
          ...definition.parameters,
          receipt: trusted.receipt,
          request,
        })
      : undefined;
    return {
      action: definition.action,
      parameters: structuredClone(definition.parameters),
      phaseId: definition.phaseId,
      request,
      ...(snapshot ? { snapshot } : {}),
    };
  });
  assert.deepEqual(
    cases.map(({ phaseId }) => phaseId).sort(),
    Object.keys(EXPECTED_PHASE_PROFILES).sort(),
    "worker body matrix must cover every canonical phase exactly once",
  );
  for (const { action, phaseId, snapshot } of cases) {
    const plan = EXPECTED_ACTION_PHASES[action];
    const admitted = plan.phaseIds.includes(phaseId)
      || Object.values(plan.operationPhaseIds).some((phaseIds) => phaseIds.includes(phaseId));
    assert.equal(admitted, true, `${phaseId} is not owned by ${action}`);
    assert.equal(
      Boolean(snapshot),
      action === "backup.job.execute",
      `${phaseId} claimed-job snapshot ownership`,
    );
  }
  return cases;
}

function assertExactWorkerBody({ observedBody, phaseCase, trusted }) {
  const {
    action,
    parameters,
    phaseId,
    request,
    snapshot: claimedJobSnapshot,
  } = phaseCase;
  const requestSha256 = signedRequestSha256(request);
  const receipt = trusted.receipt;
  const phase = receipt.resources.phaseProfiles[phaseId];
  const actionProfile = receipt.resources.actionProfiles[action];
  const authority = expectedPhaseAuthority(receipt, action, phaseId);
  assert.equal(request.action, action);
  assert.deepEqual(request.parameters, parameters);
  assert.equal(request.runtimeIntentId, trusted.intent.intentId);
  assert.equal(request.activeReceiptSha256, trusted.receiptDigest);
  assert.match(request.mac, /^[a-f0-9]{64}$/);
  if (claimedJobSnapshot) assert.equal(claimedJobSnapshot.requestSha256, requestSha256);
  const body = observedBody ?? workerBodyForCase(phaseCase, trusted);
  const env = environmentMap(body.Env);
  const expectedNetworkNames = phase.networkIds.map(
    (networkId) => receipt.resources.networks[networkId].engineName,
  );

  assert.deepEqual(Object.keys(body).sort(), [
    "AttachStderr",
    "AttachStdin",
    "AttachStdout",
    "Cmd",
    "Entrypoint",
    "Env",
    "HostConfig",
    "Image",
    "Labels",
    "NetworkDisabled",
    "NetworkingConfig",
    "OpenStdin",
    "StdinOnce",
    "Tty",
    "User",
    "WorkingDir",
  ]);
  assert.equal(body.Image, phase.workerImageRef, `${phaseId} image`);
  assert.deepEqual(body.Entrypoint, EXPECTED_WORKER_ENTRYPOINT);
  assert.deepEqual(body.Cmd, [phase.command], `${phaseId} fixed command`);
  assert.equal(body.User, "0:0", `${phaseId} must traverse root-owned 0700/0400 inputs`);
  assert.equal(body.WorkingDir, "/opt/platform-docker-worker");
  assert.equal(body.AttachStdin, false);
  assert.equal(body.AttachStdout, false);
  assert.equal(body.AttachStderr, false);
  assert.equal(body.OpenStdin, false);
  assert.equal(body.StdinOnce, false);
  assert.equal(body.Tty, false);
  assert.deepEqual(body.Labels, {
    "com.platform.active-receipt-sha256": trusted.receiptDigest,
    "com.platform.docker-action": action,
    "com.platform.docker-action-profile": actionProfile.profileId,
    "com.platform.docker-action-profile-sha256": actionProfile.profileSha256,
    "com.platform.docker-phase": phaseId,
    "com.platform.docker-phase-sha256": phase.phaseSha256,
    "com.platform.runtime-intent": trusted.intent.intentId,
  });
  assert.deepEqual(
    body.HostConfig,
    expectedWorkerHostConfig(receipt, phase, claimedJobSnapshot),
    `${phaseId} HostConfig must contain exactly the admitted namespace, bind, volume and limit surface`,
  );
  assert.equal(body.NetworkDisabled, expectedNetworkNames.length === 0);
  assert.deepEqual(body.NetworkingConfig, {
    EndpointsConfig: Object.fromEntries(expectedNetworkNames.map((name) => [name, { Aliases: [] }])),
  });

  assert.equal(env.HOME, "/tmp");
  assert.equal(env.LANG, "C.UTF-8");
  assert.equal(env.NODE_ENV, "production");
  assert.equal(env.PLATFORM_DOCKER_ACTION, action);
  assert.equal(env.PLATFORM_DOCKER_PHASE_ID, phaseId);
  assert.equal(env.PLATFORM_DOCKER_REQUEST_ID, request.requestId);
  assert.equal(
    env.PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64,
    Buffer.from(canonicalFixtureJson(authority)).toString("base64url"),
  );
  assert.equal(
    env.PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256,
    fixtureSha256(canonicalFixtureJson(authority)),
  );

  const claimedKeys = [
    "PLATFORM_CLAIMED_JOB_FILE_NAME",
    "PLATFORM_CLAIMED_JOB_ID",
    "PLATFORM_CLAIMED_JOB_OPERATION",
    "PLATFORM_CLAIMED_JOB_PATH",
    "PLATFORM_CLAIMED_JOB_SHA256",
    "PLATFORM_CLAIMED_JOB_SOURCE_ID",
  ];
  assert.equal(
    Object.hasOwn(env, "PLATFORM_CLAIMED_JOB_BASE64"),
    false,
    `${phaseId} must not encode a claimed job in execve environment bytes`,
  );
  if (claimedJobSnapshot) {
    const expectedSnapshotContainerPath =
      receipt.resources.claimedJobSources[claimedJobSnapshot.sourceId].snapshotContainerPath;
    assert.equal(env.PLATFORM_CLAIMED_JOB_PATH, expectedSnapshotContainerPath);
    assert.equal(env.PLATFORM_CLAIMED_JOB_FILE_NAME, claimedJobSnapshot.jobFileName);
    assert.equal(env.PLATFORM_CLAIMED_JOB_ID, claimedJobSnapshot.jobId);
    assert.equal(env.PLATFORM_CLAIMED_JOB_OPERATION, claimedJobSnapshot.jobOperation);
    assert.equal(env.PLATFORM_CLAIMED_JOB_SHA256, claimedJobSnapshot.jobSha256);
    assert.equal(env.PLATFORM_CLAIMED_JOB_SOURCE_ID, claimedJobSnapshot.sourceId);
    assert.equal(
      body.HostConfig.Binds.filter(
        (bind) => bind.endsWith(`:${expectedSnapshotContainerPath}:ro`),
      ).length,
      1,
      `${phaseId} must bind exactly one sealed snapshot file`,
    );
    for (const [label, substitutedSnapshot] of [
      ["host path", {
        ...claimedJobSnapshot,
        hostPath: `/tmp/attacker/${claimedJobSnapshot.jobFileName}`,
      }],
      ["container path", {
        ...claimedJobSnapshot,
        containerPath: "/run/platform/claimed-job/attacker.json",
      }],
      ["request digest", {
        ...claimedJobSnapshot,
        requestSha256: requestSha256 === "f".repeat(64)
          ? "e".repeat(64)
          : "f".repeat(64),
      }],
      ["state volume ID", {
        ...claimedJobSnapshot,
        snapshotVolumeId: "jobs.queue",
      }],
      ["state volume name", {
        ...claimedJobSnapshot,
        snapshotVolumeName: receipt.resources.volumes["jobs.queue"].engineName,
      }],
      ["state volume mountpoint", {
        ...claimedJobSnapshot,
        snapshotVolumeMountpoint: "/tmp/attacker-volume",
      }],
      ["state volume subpath", {
        ...claimedJobSnapshot,
        snapshotVolumeSubpath: "attacker",
      }],
      ["source ID", {
        ...claimedJobSnapshot,
        sourceId: "jobs.attacker",
      }],
      ["job filename", {
        ...claimedJobSnapshot,
        jobFileName: `attacker-${claimedJobSnapshot.jobFileName}`,
      }],
      ["job ID", {
        ...claimedJobSnapshot,
        jobId: claimedJobSnapshot.jobId === BACKUP_JOB_ID ? RESTORE_JOB_ID : BACKUP_JOB_ID,
      }],
      ["job operation", {
        ...claimedJobSnapshot,
        jobOperation: claimedJobSnapshot.jobOperation === "backup" ? "restore-drill" : "backup",
      }],
      ["job digest", {
        ...claimedJobSnapshot,
        jobSha256: "7".repeat(64),
      }],
    ]) {
      assert.throws(
        () => broker.workerCreateBody({
          action,
          claimedJobSnapshot: substitutedSnapshot,
          parameters,
          phaseId,
          request,
          requestId: request.requestId,
          requestSha256,
          trusted,
        }),
        /broker.?state|mountpoint|snapshot|host.?path|authority|descendant|container|request|volume|source|job|filename|operation|digest|sha256|parameter/i,
        `${phaseId} accepted substituted claimed-job ${label}`,
      );
    }
  } else {
    for (const key of claimedKeys) assert.equal(Object.hasOwn(env, key), false, `${phaseId}/${key}`);
    assert.equal(
      body.HostConfig.Binds.some((bind) => Object.values(
        receipt.resources.claimedJobSources,
      ).some(({ snapshotContainerPath }) => bind.includes(snapshotContainerPath))),
      false,
      `${phaseId} must not receive a claimed-job snapshot`,
    );
  }

  if (phase.writableSubpathIds.includes("backup.quarantine")) {
    assert.equal(env.PLATFORM_BACKUP_QUARANTINE_RELATIVE_PATH, ".quarantine");
    assert.equal(
      receipt.resources.writableSubpaths["backup.quarantine"].device,
      receipt.resources.mounts["backup.root.rw"].device,
    );
    assert.equal(
      body.HostConfig.Mounts.some(({ Source }) => Source?.includes("quarantine")),
      false,
      "quarantine must stay on the admitted backup filesystem",
    );
  }
  const expectedEnvironment = expectedWorkerEnvironment({
    action,
    authority,
    claimedJobSnapshot,
    phase,
    phaseId,
    requestId: request.requestId,
  });
  assert.deepEqual(
    env,
    expectedEnvironment,
    `${phaseId} worker environment namespace must be exact`,
  );
  assert.deepEqual(
    body.Env,
    Object.entries(expectedEnvironment).map(([name, value]) => `${name}=${value}`),
    `${phaseId} worker environment order must be deterministic`,
  );
  assertWorkerEnvironmentBounds(body.Env, phaseId);
  const serialized = canonicalFixtureJson(body);
  assert.doesNotMatch(serialized, /(?:^|[/:])docker\.sock(?:$|["/:])/);
  assert.doesNotMatch(serialized, /DOCKER_HOST/);
  assert.doesNotMatch(serialized, /jobs\.queue|\/run\/platform\/backup-jobs/);
  assert.doesNotMatch(serialized, /\/run\/secrets\/docker_action_/);
}

function workerBodyForCase(phaseCase, trusted) {
  return broker.workerCreateBody({
    action: phaseCase.action,
    claimedJobSnapshot: phaseCase.snapshot,
    parameters: phaseCase.parameters,
    phaseId: phaseCase.phaseId,
    request: phaseCase.request,
    requestId: phaseCase.request.requestId,
    requestSha256: signedRequestSha256(phaseCase.request),
    trusted,
  });
}

function expectedWorkerEnvironment({
  action,
  authority,
  claimedJobSnapshot,
  phase,
  phaseId,
  requestId,
}) {
  const result = {
    HOME: "/tmp",
    LANG: "C.UTF-8",
    NODE_ENV: "production",
    PLATFORM_DOCKER_ACTION: action,
    PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64:
      Buffer.from(canonicalFixtureJson(authority)).toString("base64url"),
    PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256:
      fixtureSha256(canonicalFixtureJson(authority)),
    PLATFORM_DOCKER_PHASE_ID: phaseId,
    PLATFORM_DOCKER_REQUEST_ID: requestId,
  };
  if (claimedJobSnapshot) {
    Object.assign(result, {
      PLATFORM_CLAIMED_JOB_FILE_NAME: claimedJobSnapshot.jobFileName,
      PLATFORM_CLAIMED_JOB_ID: claimedJobSnapshot.jobId,
      PLATFORM_CLAIMED_JOB_OPERATION: claimedJobSnapshot.jobOperation,
      PLATFORM_CLAIMED_JOB_PATH: claimedJobSnapshot.containerPath,
      PLATFORM_CLAIMED_JOB_SHA256: claimedJobSnapshot.jobSha256,
      PLATFORM_CLAIMED_JOB_SOURCE_ID: claimedJobSnapshot.sourceId,
    });
  }
  if (phase.writableSubpathIds.includes("backup.quarantine")) {
    result.PLATFORM_BACKUP_QUARANTINE_RELATIVE_PATH = ".quarantine";
  }
  return result;
}

function expectedWorkerHostConfig(receipt, phase, claimedJobSnapshot) {
  const networkNames = phase.networkIds.map(
    (networkId) => receipt.resources.networks[networkId].engineName,
  );
  const binds = phase.mountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return `${mount.canonicalPath}:${mount.containerPath}:${mount.access}`;
  });
  if (claimedJobSnapshot) {
    binds.push(
      `${claimedJobSnapshot.hostPath}:${claimedJobSnapshot.containerPath}:ro`,
    );
  }
  return {
    Annotations: null,
    AutoRemove: false,
    Binds: binds,
    BlkioDeviceReadBps: null,
    BlkioDeviceReadIOps: null,
    BlkioDeviceWriteBps: null,
    BlkioDeviceWriteIOps: null,
    BlkioWeight: 0,
    BlkioWeightDevice: null,
    CapAdd: [],
    CapDrop: ["ALL"],
    Cgroup: "",
    CgroupnsMode: "private",
    CgroupParent: "",
    ConsoleSize: [0, 0],
    CpuCount: 0,
    CpuPercent: 0,
    CpuPeriod: 0,
    CpuQuota: 0,
    CpuRealtimePeriod: 0,
    CpuRealtimeRuntime: 0,
    CpuShares: 0,
    CpusetCpus: "",
    CpusetMems: "",
    DeviceCgroupRules: [],
    Devices: [],
    DeviceRequests: [],
    DiskQuota: 0,
    Dns: [],
    DnsOptions: [],
    DnsSearch: [],
    ExtraHosts: [],
    GroupAdd: [],
    IOMaximumBandwidth: 0,
    IOMaximumIOps: 0,
    Init: false,
    IpcMode: "private",
    Isolation: "",
    KernelMemory: 0,
    KernelMemoryTCP: 0,
    Links: [],
    LogConfig: { Type: "json-file", Config: { "max-file": "1", "max-size": "1m" } },
    MaskedPaths: [
      "/proc/acpi",
      "/proc/asound",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/proc/scsi",
      "/sys/devices/virtual/powercap",
      "/sys/firmware",
    ],
    Memory: 134217728,
    MemoryReservation: 0,
    MemorySwap: 134217728,
    MemorySwappiness: null,
    Mounts: expectedNamedVolumeMounts(receipt, phase),
    NanoCpus: 250000000,
    NetworkMode: networkNames[0] ?? "none",
    OomKillDisable: false,
    OomScoreAdj: 0,
    PidMode: "",
    PidsLimit: 96,
    PortBindings: {},
    Privileged: false,
    PublishAllPorts: false,
    ReadonlyPaths: [
      "/proc/asound",
      "/proc/acpi",
      "/proc/interrupts",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/proc/scsi",
      "/sys/firmware",
    ],
    ReadonlyRootfs: true,
    RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
    Runtime: "runc",
    SecurityOpt: ["no-new-privileges:true"],
    ShmSize: 67108864,
    StorageOpt: {},
    Sysctls: {},
    Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=32m,mode=700" },
    Ulimits: [{ Name: "nofile", Soft: 1024, Hard: 1024 }],
    UsernsMode: "",
    UTSMode: "",
    VolumeDriver: "",
    VolumesFrom: [],
  };
}

function sealedClaimedJobSnapshot({
  jobFileName,
  jobId,
  jobOperation,
  jobSha256,
  receipt = WORKER_TRUSTED_CONTEXT.receipt,
  request = BACKUP_SIGNED_REQUEST,
}) {
  const requestSha256 = signedRequestSha256(request);
  const source = receipt.resources.claimedJobSources["jobs.running"];
  const snapshotVolumeId = source.snapshotVolumeId;
  const snapshotVolumeName = receipt.resources.volumes[snapshotVolumeId].engineName;
  const snapshotVolumeMountpoint = `/var/lib/docker/volumes/${snapshotVolumeName}/_data`;
  return Object.freeze({
    containerPath: source.snapshotContainerPath,
    hostPath: `${snapshotVolumeMountpoint}/${source.snapshotVolumeSubpath}/${requestSha256}/job.json`,
    jobFileName,
    jobId,
    jobOperation,
    jobSha256,
    requestSha256,
    snapshotVolumeId,
    snapshotVolumeMountpoint,
    snapshotVolumeName,
    snapshotVolumeSubpath: source.snapshotVolumeSubpath,
    sourceId: "jobs.running",
  });
}

function claimedJobParameters(snapshot) {
  return {
    jobFileName: snapshot.jobFileName,
    jobId: snapshot.jobId,
    jobOperation: snapshot.jobOperation,
    jobSha256: snapshot.jobSha256,
  };
}

function expectedPhaseAuthority(receipt, action, phaseId) {
  const phase = receipt.resources.phaseProfiles[phaseId];
  const workerSecretSets = Object.fromEntries(
    phase.workerSecretSetIds.map((id) => [id, structuredClone(receipt.resources.workerSecretSets[id])]),
  );
  const volumeIds = [
    ...phase.workerSecretSetIds.map((id) => receipt.resources.workerSecretSets[id].volumeId),
    ...phase.scratchVolumeIds,
  ];
  return {
    schema: "platform.docker-worker.phase-authority/v2",
    action,
    actionProfile: structuredClone(receipt.resources.actionProfiles[action]),
    phaseProfile: structuredClone(phase),
    resources: {
      mounts: Object.fromEntries(
        phase.mountIds.map((id) => [id, structuredClone(receipt.resources.mounts[id])]),
      ),
      networks: Object.fromEntries(
        phase.networkIds.map((id) => [id, structuredClone(receipt.resources.networks[id])]),
      ),
      volumes: Object.fromEntries(
        [...new Set(volumeIds)].map((id) => [id, structuredClone(receipt.resources.volumes[id])]),
      ),
      workerSecretSets,
      writableSubpaths: Object.fromEntries(
        phase.writableSubpathIds.map(
          (id) => [id, structuredClone(receipt.resources.writableSubpaths[id])],
        ),
      ),
    },
  };
}

function expectedNamedVolumeMounts(receipt, phase) {
  const secretMounts = phase.workerSecretSetIds.map((secretSetId) => {
    const secretSet = receipt.resources.workerSecretSets[secretSetId];
    const volume = receipt.resources.volumes[secretSet.volumeId];
    return {
      Type: "volume",
      Source: volume.engineName,
      Target: secretSet.containerRoot,
      ReadOnly: true,
      VolumeOptions: { NoCopy: true },
    };
  });
  const scratchMounts = phase.scratchVolumeIds.map((volumeId) => {
    const volume = receipt.resources.volumes[volumeId];
    return {
      Type: "volume",
      Source: volume.engineName,
      Target: volume.containerPath,
      ReadOnly: false,
      VolumeOptions: { NoCopy: true },
    };
  });
  return [...secretMounts, ...scratchMounts];
}

function environmentMap(values) {
  assert.ok(Array.isArray(values), "worker Env must be an array");
  const result = {};
  for (const entry of values) {
    const delimiter = String(entry).indexOf("=");
    assert.ok(delimiter > 0, `worker environment entry is malformed: ${entry}`);
    const name = entry.slice(0, delimiter);
    assert.equal(Object.hasOwn(result, name), false, `duplicate worker environment key: ${name}`);
    result[name] = entry.slice(delimiter + 1);
  }
  return result;
}

function assertFixedAdapterInvocation(invocation, command) {
  const expected = EXPECTED_FIXED_ADAPTERS[command];
  assert.ok(expected, `fixed adapter oracle has no command: ${command}`);
  assert.deepEqual(
    {
      api: invocation.api,
      argv: invocation.argv,
      executable: invocation.executable,
      shell: invocation.shell,
    },
    expected,
    `${command} did not use its one exact code-owned adapter identity`,
  );
  assert.equal(path.isAbsolute(invocation.executable), true);
  assert.deepEqual(invocation.argv, []);
  assert.equal(
    [path.basename(invocation.executable), ...invocation.argv].some(
      (token) => [
        "-c",
        "bash",
        "curl",
        "dash",
        "env",
        "nc",
        "ncat",
        "node",
        "perl",
        "python",
        "ruby",
        "sh",
        "socat",
        "ssh",
        "wget",
        "zsh",
      ].includes(token),
    ),
    false,
    `${command} crossed a shell, interpreter, wrapper, or network-tool boundary`,
  );
}

function assertSocketlessWorkerSource(source, label) {
  const decoded = stripStaticJavaScriptComments(
    expandStaticBase64Literals(decodeStaticJavaScriptEscapes(String(source))),
  );
  assert.doesNotMatch(
    decoded,
    /(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*)["'](?:node:)?(?:net|http|https|http2|tls|dgram|dns|undici)["']/,
    `${label} violates the socketless network-module boundary`,
  );
  assert.doesNotMatch(
    decoded,
    /\bimport\s*\(/,
    `${label} violates the socketless dynamic-import boundary`,
  );
  assert.doesNotMatch(
    decoded,
    /\b(?:eval|fetch|WebSocket|EventSource)\s*\(|(?:\bnew\s+)?\bFunction\s*\(|(?:\.\s*constructor|\[\s*["']constructor["']\s*\])\s*\(/,
    `${label} violates the socketless dynamic-code or global-network boundary`,
  );
  assert.doesNotMatch(
    decoded,
    /\b(?:createRequire|getBuiltinModule|_linkedBinding|binding|dlopen|registerHooks?|_load|_resolveFilename)\b/,
    `${label} violates the socketless runtime-loader boundary`,
  );
  assert.doesNotMatch(
    decoded,
    /\brequire\s*\(/,
    `${label} violates the socketless CommonJS-loader boundary`,
  );
  const folded = decoded
    .toLowerCase()
    .replace(/[\s"'`+\[\](){},;$\\]/g, "");
  assert.doesNotMatch(
    folded,
    /docker\.sock|docker_host|\/containers\/(?:create|[^/]*\/start)|\/images\/create|getbuiltinmodule|createrequire|module(?:builtin)?\.?_load|module(?:builtin)?prototype\.?require/,
    `${label} reconstructs forbidden Docker Engine authority`,
  );
  assert.equal(
    /constructor/.test(folded)
      && /(?:import|fetch|websocket|eventsource)/.test(folded),
    false,
    `${label} reconstructs a dynamic constructor and forbidden loader in any order`,
  );
  assert.doesNotMatch(
    folded,
    /(?:spawn|exec|fork)[a-z]*.*\/(?:curl|wget|nc|ncat|socat|ssh)/,
    `${label} invokes a forbidden child_process network tool`,
  );
  assert.doesNotMatch(
    folded,
    /process[^a-z0-9]*execve/,
    `${label} violates the socketless native execve boundary`,
  );
  assert.equal(
    /(?:process|child)[\s\S]*(?:stdin|stdout|stderr)/.test(folded)
      && /constructor/.test(folded)
      && /connect/.test(folded),
    false,
    `${label} reaches a stream-derived network capability`,
  );
  if (/(?:spawn|exec|fork)/.test(folded)) {
    assert.doesNotMatch(
      folded,
      /\/(?:bin\/(?:bash|dash|sh|zsh)|usr\/bin\/env|usr\/local\/bin\/node)/,
      `${label} violates the socketless shell, interpreter, or environment-wrapper boundary`,
    );
  }
  for (const specifier of staticModuleSpecifiers(decoded)) {
    if (specifier.startsWith("node:")) {
      assert.equal(
        ALLOWED_WORKER_BUILTINS.has(specifier),
        true,
        `${label} imports a builtin outside the socketless allowlist: ${specifier}`,
      );
      continue;
    }
    assert.equal(
      specifier.startsWith("./") || specifier.startsWith("../"),
      true,
      `${label} imports a bare or remote module outside the socketless allowlist: ${specifier}`,
    );
  }
}

function assertSocketlessWorkerImportGraph(
  entryFile,
  graphRoot = path.dirname(path.resolve(entryFile)),
) {
  graphRoot = path.resolve(graphRoot);
  const queue = [path.resolve(entryFile)];
  const visited = new Set();
  while (queue.length > 0) {
    const file = queue.shift();
    if (visited.has(file)) continue;
    assert.equal(
      file === graphRoot || file.startsWith(`${graphRoot}${path.sep}`),
      true,
      `socketless worker import escaped its local graph root: ${file}`,
    );
    const stat = fs.lstatSync(file);
    assert.equal(
      stat.isFile() && !stat.isSymbolicLink(),
      true,
      `socketless worker import is not one regular staged file: ${file}`,
    );
    const source = fs.readFileSync(file, "utf8");
    assertSocketlessWorkerSource(source, path.relative(graphRoot, file) || path.basename(file));
    visited.add(file);
    for (const specifier of staticModuleSpecifiers(source)) {
      if (specifier.startsWith("node:")) continue;
      const imported = path.resolve(path.dirname(file), specifier);
      assert.equal(
        imported.startsWith(`${graphRoot}${path.sep}`),
        true,
        `socketless worker local import escaped its graph root: ${specifier}`,
      );
      assert.equal(
        fs.existsSync(imported),
        true,
        `socketless worker local import is absent from the staged closure: ${specifier}`,
      );
      queue.push(imported);
    }
  }
  return [...visited]
    .map((file) => path.relative(graphRoot, file) || path.basename(file))
    .sort();
}

function staticModuleSpecifiers(source) {
  const specifiers = [];
  const normalized = stripStaticJavaScriptComments(
    expandStaticBase64Literals(decodeStaticJavaScriptEscapes(String(source))),
  );
  const patterns = [
    /\bimport\s*["']([^"']+)["']/g,
    /\b(?:import|export)\b[\s\S]{0,500}?\bfrom\s*["']([^"']+)["']/g,
  ];
  for (const pattern of patterns) {
    for (const match of normalized.matchAll(pattern)) specifiers.push(match[1]);
  }
  return [...new Set(specifiers)];
}

function decodeStaticJavaScriptEscapes(source) {
  return String(source)
    .replace(
      /\\u\{([0-9a-f]{1,6})\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/gi,
      (_match, codePoint, shortUnicode, hexadecimal) => String.fromCodePoint(
        Number.parseInt(codePoint ?? shortUnicode ?? hexadecimal, 16),
      ),
    );
}

function expandStaticBase64Literals(source) {
  const decode = (_match, _prefix, quote, encoded) => {
    try {
      const bytes = Buffer.from(encoded, "base64");
      if (bytes.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")) {
        return _match;
      }
      return JSON.stringify(bytes.toString("utf8"));
    } catch {
      return _match;
    }
  };
  return String(source)
    .replace(
      /((?:globalThis\.)?Buffer\s*\.\s*from\s*\(\s*)(["'])([A-Za-z0-9+/]+={0,2})\2\s*,\s*["']base64["']\s*\)(?:\s*\.\s*toString\s*\(\s*(?:["']utf-?8["'])?\s*\))?/gi,
      (match, prefix, quote, encoded) => decode(match, prefix, quote, encoded),
    )
    .replace(
      /\batob\s*\(\s*(["'])([A-Za-z0-9+/]+={0,2})\1\s*\)/gi,
      (match, quote, encoded) => decode(match, "", quote, encoded),
    );
}

function stripStaticJavaScriptComments(source) {
  const input = String(source);
  let output = "";
  let quote = null;
  let escaped = false;
  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    const next = input[index + 1];
    if (quote) {
      output += character;
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === '"' || character === "`") {
      quote = character;
      output += character;
      continue;
    }
    if (character === "/" && next === "*") {
      output += "  ";
      index += 2;
      while (index < input.length) {
        if (input[index] === "*" && input[index + 1] === "/") {
          output += "  ";
          index += 1;
          break;
        }
        output += input[index] === "\n" ? "\n" : " ";
        index += 1;
      }
      continue;
    }
    if (character === "/" && next === "/") {
      output += "  ";
      index += 2;
      while (index < input.length && input[index] !== "\n") {
        output += " ";
        index += 1;
      }
      if (index < input.length) output += "\n";
      continue;
    }
    output += character;
  }
  return output;
}

function expectedWorkerBodyDocument(phaseCase, trusted) {
  const receipt = trusted.receipt;
  const phase = receipt.resources.phaseProfiles[phaseCase.phaseId];
  const actionProfile = receipt.resources.actionProfiles[phaseCase.action];
  const authority = expectedPhaseAuthority(receipt, phaseCase.action, phaseCase.phaseId);
  const networkNames = phase.networkIds.map(
    (networkId) => receipt.resources.networks[networkId].engineName,
  );
  const environment = expectedWorkerEnvironment({
    action: phaseCase.action,
    authority,
    claimedJobSnapshot: phaseCase.snapshot,
    phase,
    phaseId: phaseCase.phaseId,
    requestId: phaseCase.request.requestId,
  });
  return {
    AttachStderr: false,
    AttachStdin: false,
    AttachStdout: false,
    Cmd: [phase.command],
    Entrypoint: [...EXPECTED_WORKER_ENTRYPOINT],
    Env: Object.entries(environment).map(([name, value]) => `${name}=${value}`),
    HostConfig: expectedWorkerHostConfig(receipt, phase, phaseCase.snapshot),
    Image: phase.workerImageRef,
    Labels: {
      "com.platform.active-receipt-sha256": trusted.receiptDigest,
      "com.platform.docker-action": phaseCase.action,
      "com.platform.docker-action-profile": actionProfile.profileId,
      "com.platform.docker-action-profile-sha256": actionProfile.profileSha256,
      "com.platform.docker-phase": phaseCase.phaseId,
      "com.platform.docker-phase-sha256": phase.phaseSha256,
      "com.platform.runtime-intent": trusted.intent.intentId,
    },
    NetworkDisabled: networkNames.length === 0,
    NetworkingConfig: {
      EndpointsConfig: Object.fromEntries(networkNames.map((name) => [name, { Aliases: [] }])),
    },
    OpenStdin: false,
    StdinOnce: false,
    Tty: false,
    User: "0:0",
    WorkingDir: "/opt/platform-docker-worker",
  };
}

function expectedWorkerInspectMounts(receipt, phase, claimedJobSnapshot) {
  const bindMounts = phase.mountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return {
      Destination: mount.containerPath,
      Mode: mount.access,
      Name: "",
      RW: mount.access === "rw",
      Source: mount.canonicalPath,
      Type: "bind",
    };
  });
  if (claimedJobSnapshot) {
    bindMounts.push({
      Destination: claimedJobSnapshot.containerPath,
      Mode: "ro",
      Name: "",
      RW: false,
      Source: claimedJobSnapshot.hostPath,
      Type: "bind",
    });
  }
  const volumeMounts = expectedNamedVolumeMounts(receipt, phase).map((mount) => ({
    Destination: mount.Target,
    Driver: "local",
    Mode: mount.ReadOnly ? "ro" : "rw",
    Name: mount.Source,
    RW: mount.ReadOnly !== true,
    Source: `/var/lib/docker/volumes/${mount.Source}/_data`,
    Type: "volume",
  }));
  return [...bindMounts, ...volumeMounts];
}

function semanticWorkerTransport({
  brokerStateMountpoint,
  calls,
  expectedPhaseCase,
  inspectMutation,
  onCreateBody,
  rawWorkerResult: result,
  receipt,
  trusted,
}) {
  let createdName;
  const workerId = "a".repeat(64);
  return Object.freeze({
    async inspectVolume(name) {
      calls.push({ method: "inspectVolume", name });
      const logicalId = Object.keys(receipt.resources.volumes).find(
        (id) => receipt.resources.volumes[id].engineName === name,
      );
      assert.ok(logicalId, `unexpected volume inspection: ${name}`);
      const inspect = buildFixtureVolumeInspect(receipt, logicalId);
      if (logicalId === "broker.state") inspect.Mountpoint = brokerStateMountpoint;
      return inspect;
    },
    async inspectNetwork(id) {
      calls.push({ method: "inspectNetwork", id });
      const logicalId = Object.keys(receipt.resources.networks).find((candidate) => {
        const network = receipt.resources.networks[candidate];
        return candidate === id || network.engineId === id || network.engineName === id;
      });
      assert.ok(logicalId, `unexpected network inspection: ${id}`);
      return buildFixtureNetworkInspect(receipt, logicalId);
    },
    async createWorker(name, body) {
      calls.push({ method: "createWorker", name });
      createdName = name;
      onCreateBody(body);
      return { Id: workerId };
    },
    async inspectContainer(id) {
      calls.push({ method: "inspectContainer", id });
      assert.equal(id, workerId);
      assert.ok(createdName, "worker inspect occurred before create");
      const phaseCase = expectedPhaseCase();
      const phase = receipt.resources.phaseProfiles[phaseCase.phaseId];
      const expectedBody = expectedWorkerBodyDocument(phaseCase, trusted);
      const config = {
        AttachStderr: expectedBody.AttachStderr,
        AttachStdin: expectedBody.AttachStdin,
        AttachStdout: expectedBody.AttachStdout,
        Cmd: structuredClone(expectedBody.Cmd),
        Entrypoint: structuredClone(expectedBody.Entrypoint),
        Env: structuredClone(expectedBody.Env),
        ExposedPorts: {},
        Healthcheck: null,
        Image: expectedBody.Image,
        Labels: structuredClone(expectedBody.Labels),
        NetworkDisabled: expectedBody.NetworkDisabled,
        OnBuild: [],
        OpenStdin: expectedBody.OpenStdin,
        StdinOnce: expectedBody.StdinOnce,
        Tty: expectedBody.Tty,
        User: expectedBody.User,
        Volumes: {},
        WorkingDir: expectedBody.WorkingDir,
      };
      const networks = Object.fromEntries(
        phase.networkIds.map((logicalId) => {
          const network = receipt.resources.networks[logicalId];
          return [network.engineName, {
            Aliases: [],
            EndpointID: fixtureSha256(`fixture:endpoint:${logicalId}`),
            NetworkID: network.engineId,
          }];
        }),
      );
      const inspect = {
        Config: config,
        HostConfig: expectedWorkerHostConfig(receipt, phase, phaseCase.snapshot),
        Id: workerId,
        Image: phase.workerImageId,
        Mounts: expectedWorkerInspectMounts(receipt, phase, phaseCase.snapshot),
        Name: `/${createdName}`,
        NetworkSettings: { Networks: networks },
      };
      return inspectMutation
        ? inspectMutation(structuredClone(inspect), phaseCase)
        : inspect;
    },
    async startContainer(id) {
      calls.push({ method: "startContainer", id });
      assert.equal(id, workerId);
    },
    async waitContainer(id) {
      calls.push({ method: "waitContainer", id });
      assert.equal(id, workerId);
      return { StatusCode: 0 };
    },
    async logsContainer(id) {
      calls.push({ method: "logsContainer", id });
      assert.equal(id, workerId);
      return dockerStdoutFrame(`${JSON.stringify(result)}\n`);
    },
    async deleteContainer(id) {
      calls.push({ method: "deleteContainer", id });
      assert.equal(id, workerId);
    },
    async inspectContainerForRecovery(name) {
      calls.push({ method: "inspectContainerForRecovery", name });
      return null;
    },
  });
}

function rawWorkerResult({
  action,
  command,
  job,
  phaseId,
  requestId,
}) {
  return {
    schema: "platform.docker-worker.result/v2",
    requestId,
    action,
    phaseId,
    command,
    job: job
      ? {
          jobFileName: job.jobFileName,
          jobId: job.jobId,
          jobOperation: job.jobOperation,
          jobSha256: job.jobSha256,
        }
      : null,
    status: "completed",
    output: buildFixturePhaseOutputV2(action, phaseId, job ?? {}),
  };
}

function workerCliEnvironment({
  action,
  job = null,
  phaseId,
  requestId,
  snapshotPath = SNAPSHOT_CONTAINER_PATH,
}) {
  const env = {
    PLATFORM_DOCKER_ACTION: action,
    PLATFORM_DOCKER_PHASE_ID: phaseId,
    PLATFORM_DOCKER_REQUEST_ID: requestId,
  };
  if (job) {
    Object.assign(env, {
      PLATFORM_CLAIMED_JOB_FILE_NAME: job.jobFileName,
      PLATFORM_CLAIMED_JOB_ID: job.jobId,
      PLATFORM_CLAIMED_JOB_OPERATION: job.jobOperation,
      PLATFORM_CLAIMED_JOB_PATH: snapshotPath,
      PLATFORM_CLAIMED_JOB_SHA256: job.jobSha256,
      PLATFORM_CLAIMED_JOB_SOURCE_ID: "jobs.running",
    });
  }
  return env;
}

function dockerStdoutFrame(text) {
  const payload = Buffer.from(text);
  const header = Buffer.alloc(8);
  header[0] = 1;
  header.writeUInt32BE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

async function importWorkerWithoutCliSideEffects() {
  const savedArgv = process.argv;
  const savedExitCode = process.exitCode;
  const savedStderrWrite = process.stderr.write;
  let capturedStderr = "";
  try {
    process.argv = [process.execPath, "docker-action-worker-unit-import"];
    process.exitCode = undefined;
    process.stderr.write = (chunk, ...args) => {
      capturedStderr += String(chunk);
      const callback = args.find((entry) => typeof entry === "function");
      if (callback) callback();
      return true;
    };
    const namespace = await import(`${pathToFileURL(workerPath).href}?worker-contract-red=2`);
    return { namespace, stderr: capturedStderr, exitCode: process.exitCode };
  } finally {
    process.argv = savedArgv;
    process.stderr.write = savedStderrWrite;
    process.exitCode = savedExitCode;
  }
}

function requireWorkerFunction(name) {
  assert.equal(
    typeof worker[name],
    "function",
    `docker-action-worker pure API is missing export: ${name}`,
  );
  return worker[name];
}

function requireBrokerFunction(name) {
  assert.equal(
    typeof broker[name],
    "function",
    `docker-action-broker pure API is missing export: ${name}`,
  );
  return broker[name];
}

function workerTest(name, requiredFunctions, body) {
  const missing = requiredFunctions.filter((functionName) => typeof worker[functionName] !== "function");
  if (missing.length > 0) {
    test(name, {
      todo: `blocked by worker pure-API boundary: ${missing.join(", ")}`,
    });
    return;
  }
  test(name, body);
}

function brokerTest(name, requiredFunctions, body) {
  const missing = requiredFunctions.filter((functionName) => typeof broker[functionName] !== "function");
  if (missing.length > 0) {
    test(name, {
      todo: `blocked by broker consumer boundary: ${missing.join(", ")}`,
    });
    return;
  }
  test(name, body);
}

function bodyMatrixTest(name, body) {
  if (!exactWorkerBodyBaselineReady) {
    test(name, {
      todo: "blocked until all eight exact workerCreateBody phase baselines pass",
    });
    return;
  }
  test(name, body);
}

function hasExactWorkerBodyBaseline() {
  const trusted = WORKER_TRUSTED_CONTEXT;
  try {
    for (const phaseCase of phaseActionCases(trusted)) {
      assertExactWorkerBody({ phaseCase, trusted });
    }
    return true;
  } catch {
    return false;
  }
}

function backupJobParameters(jobOperation) {
  return {
    jobFileName: `${BACKUP_JOB_ID}.json`,
    jobId: BACKUP_JOB_ID,
    jobOperation,
    jobSha256: jobOperation === "backup" ? BACKUP_JOB_SHA256 : "7".repeat(64),
  };
}

function signedRequestSha256(request) {
  return fixtureSha256(canonicalFixtureJson(request));
}

function validSameSizeClaimedJobTamper(document, admittedBytes) {
  const tamperedDocument = {
    ...structuredClone(document),
    requestedBy: document.requestedBy === "scheduler-test"
      ? "scheduler-evil"
      : "scheduler-test",
  };
  parseBackupJobDocument(tamperedDocument);
  const tamperedBytes = Buffer.from(`${JSON.stringify(tamperedDocument, null, 2)}\n`);
  assert.equal(
    tamperedBytes.length,
    admittedBytes.length,
    "digest tamper fixture must preserve exact byte length",
  );
  assert.notEqual(
    fixtureSha256(tamperedBytes),
    fixtureSha256(admittedBytes),
    "digest tamper fixture must change the admitted bytes",
  );
  return tamperedBytes;
}

function observeDescriptorStableReadIo(file) {
  const expectedPath = path.resolve(file);
  const expectedIdentity = fileStatIdentity(fs.lstatSync(file));
  const leafDescriptors = new Set();
  let eventOrder = 0;
  const evidence = {
    descriptorReadFileCalls: 0,
    expectedIdentity,
    fstatEvents: [],
    leafCloseEvents: [],
    leafLstatEvents: [],
    leafOpenEvents: [],
    pathReadCalls: 0,
    readSyncCalls: [],
  };
  const io = new Proxy(fs, {
    get(target, property) {
      if (property === "lstatSync") {
        return (candidate, ...args) => {
          const stat = target.lstatSync(candidate, ...args);
          if (path.resolve(String(candidate)) === expectedPath) {
            evidence.leafLstatEvents.push({
              identity: fileStatIdentity(stat),
              order: eventOrder += 1,
            });
          }
          return stat;
        };
      }
      if (property === "openSync") {
        return (candidate, flags, ...args) => {
          const descriptor = target.openSync(candidate, flags, ...args);
          if (path.resolve(String(candidate)) === expectedPath) {
            leafDescriptors.add(descriptor);
            evidence.leafOpenEvents.push({
              descriptor,
              flags,
              order: eventOrder += 1,
            });
          }
          return descriptor;
        };
      }
      if (property === "fstatSync") {
        return (descriptor, ...args) => {
          const stat = target.fstatSync(descriptor, ...args);
          if (leafDescriptors.has(descriptor)) {
            evidence.fstatEvents.push({
              descriptor,
              identity: fileStatIdentity(stat),
              order: eventOrder += 1,
            });
          }
          return stat;
        };
      }
      if (property === "readFileSync") {
        return (candidate, ...args) => {
          if (typeof candidate === "number" && leafDescriptors.has(candidate)) {
            evidence.descriptorReadFileCalls += 1;
          } else if (typeof candidate !== "number"
            && path.resolve(String(candidate)) === expectedPath) {
            evidence.pathReadCalls += 1;
          }
          return target.readFileSync(candidate, ...args);
        };
      }
      if (property === "readSync") {
        return (descriptor, buffer, offset, length, position) => {
          const returnedCount = target.readSync(
            descriptor,
            buffer,
            offset,
            length,
            position,
          );
          if (leafDescriptors.has(descriptor)) {
            evidence.readSyncCalls.push({
              bufferLength: buffer?.byteLength,
              bufferOffset: offset,
              descriptor,
              order: eventOrder += 1,
              position,
              requestedLength: length,
              returnedCount,
            });
          }
          return returnedCount;
        };
      }
      if (property === "closeSync") {
        return (descriptor) => {
          const result = target.closeSync(descriptor);
          if (leafDescriptors.delete(descriptor)) {
            evidence.leafCloseEvents.push({
              descriptor,
              order: eventOrder += 1,
            });
          }
          return result;
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { evidence, io };
}

function assertStableReadEvidence(evidence) {
  assert.equal(
    evidence.leafOpenEvents.length,
    1,
    "claimed-job leaf must be opened exactly once for one descriptor-stable read",
  );
  const [{ descriptor: leafDescriptor, flags: leafFlags }] = evidence.leafOpenEvents;
  assert.equal(
    Number.isInteger(leafFlags)
      && (leafFlags & fs.constants.O_NOFOLLOW) === fs.constants.O_NOFOLLOW,
    true,
    "claimed-job leaf open did not observe O_NOFOLLOW",
  );
  assert.deepEqual(
    evidence.leafCloseEvents.map(({ descriptor }) => descriptor),
    [leafDescriptor],
    "claimed-job consumer did not close the one admitted leaf descriptor exactly once",
  );
  assert.ok(
    Number.isSafeInteger(evidence.expectedIdentity.size)
      && evidence.expectedIdentity.size > 0,
    "claimed-job stable-read fixture has an invalid byte size",
  );
  assert.ok(
    evidence.leafLstatEvents.length >= 1,
    "claimed-job consumer did not lstat the leaf before descriptor admission",
  );
  assert.equal(
    evidence.leafLstatEvents.every(
      ({ identity }) => sameFileIdentity(identity, evidence.expectedIdentity),
    ),
    true,
    "claimed-job leaf lstat identity changed before descriptor admission",
  );
  assert.equal(
    evidence.leafLstatEvents.some(
      ({ order }) => order < evidence.leafOpenEvents[0].order,
    ),
    true,
    "claimed-job consumer did not lstat the leaf before opening it",
  );
  assert.equal(
    evidence.descriptorReadFileCalls,
    0,
    "claimed-job consumer used offset-dependent readFileSync on the descriptor",
  );
  assert.equal(evidence.pathReadCalls, 0, "claimed-job bytes were re-opened by pathname");
  assert.ok(evidence.readSyncCalls.length >= 2, "claimed-job consumer did not read two passes");
  assert.equal(
    evidence.readSyncCalls.every(({ descriptor }) => descriptor === leafDescriptor),
    true,
    "claimed-job consumer changed descriptors between stable-read passes",
  );

  const passes = [];
  let activePass = null;
  for (const call of evidence.readSyncCalls) {
    assert.ok(
      Number.isSafeInteger(call.bufferLength) && call.bufferLength > 0,
      "claimed-job readSync used an invalid buffer",
    );
    assert.ok(
      Number.isSafeInteger(call.bufferOffset) && call.bufferOffset >= 0,
      "claimed-job readSync used an invalid buffer offset",
    );
    assert.ok(
      Number.isSafeInteger(call.requestedLength) && call.requestedLength > 0,
      "claimed-job readSync issued a zero-length or invalid request",
    );
    assert.ok(
      call.bufferOffset + call.requestedLength <= call.bufferLength,
      "claimed-job readSync request escaped its destination buffer",
    );
    assert.ok(
      Number.isSafeInteger(call.position) && call.position >= 0,
      "claimed-job consumer did not use an explicit positional readSync",
    );
    assert.ok(
      Number.isSafeInteger(call.returnedCount)
        && call.returnedCount > 0
        && call.returnedCount <= call.requestedLength,
      "claimed-job readSync made no positive bounded progress",
    );
    assert.ok(
      call.requestedLength <= evidence.expectedIdentity.size - call.position,
      "claimed-job readSync requested bytes beyond the admitted stat size",
    );

    if (call.position === 0) {
      if (activePass) {
        assert.equal(
          activePass.returnedBytes,
          evidence.expectedIdentity.size,
          "claimed-job consumer restarted at position zero before completing a pass",
        );
      }
      activePass = { calls: 0, returnedBytes: 0 };
      passes.push(activePass);
    }
    assert.ok(activePass, "claimed-job descriptor read did not start at position zero");
    assert.equal(
      call.position,
      activePass.returnedBytes,
      "claimed-job descriptor pass was not contiguous",
    );
    activePass.calls += 1;
    activePass.returnedBytes += call.returnedCount;
    assert.ok(
      activePass.returnedBytes <= evidence.expectedIdentity.size,
      "claimed-job descriptor pass exceeded the admitted stat size",
    );
  }
  assert.equal(
    passes.length,
    2,
    "claimed-job consumer must perform exactly two complete descriptor passes",
  );
  for (const [index, pass] of passes.entries()) {
    assert.ok(pass.calls >= 1, `claimed-job descriptor pass ${index + 1} was empty`);
    assert.equal(
      pass.returnedBytes,
      evidence.expectedIdentity.size,
      `claimed-job descriptor pass ${index + 1} did not cover the complete stat size`,
    );
  }

  assert.ok(
    evidence.fstatEvents.length >= 2,
    "claimed-job consumer did not fstat before and after reading",
  );
  assert.equal(
    evidence.fstatEvents.every(
      ({ descriptor }) => descriptor === leafDescriptor,
    ),
    true,
    "claimed-job fstat observations changed descriptor identity",
  );
  const firstReadOrder = evidence.readSyncCalls[0].order;
  const lastReadOrder = evidence.readSyncCalls.at(-1).order;
  const preReadFstat = evidence.fstatEvents
    .filter(({ order }) => order < firstReadOrder)
    .at(-1);
  const postReadFstat = evidence.fstatEvents
    .find(({ order }) => order > lastReadOrder);
  assert.ok(preReadFstat, "claimed-job consumer omitted the pre-read fstat");
  assert.ok(postReadFstat, "claimed-job consumer omitted the post-read fstat");
  assert.deepEqual(
    preReadFstat.identity,
    evidence.expectedIdentity,
    "claimed-job leaf lstat and pre-read fstat identities diverged",
  );
  assert.deepEqual(
    postReadFstat.identity,
    preReadFstat.identity,
    "claimed-job fstat identity changed across descriptor reads",
  );
  assert.ok(
    evidence.leafCloseEvents[0].order > lastReadOrder,
    "claimed-job descriptor closed before both complete passes finished",
  );
}

function fileStatIdentity(stat) {
  return {
    ctimeMs: stat.ctimeMs,
    dev: stat.dev,
    gid: stat.gid,
    ino: stat.ino,
    isFile: stat.isFile(),
    mode: stat.mode,
    mtimeMs: stat.mtimeMs,
    nlink: stat.nlink,
    size: stat.size,
    uid: stat.uid,
  };
}

function sameFileIdentity(left, right) {
  return Object.keys(right).every((field) => Object.is(left[field], right[field]));
}

function differentStatIdentityValue(value) {
  if (typeof value === "boolean") return !value;
  if (typeof value === "bigint") return value + 1n;
  if (typeof value === "number") return value + 1;
  throw new TypeError("unsupported stat identity fixture field");
}

function statMutationIo(file, {
  family,
  field,
  targetPath,
  value,
}) {
  const expectedLeaf = path.resolve(file);
  const expectedTarget = path.resolve(targetPath);
  const leafDescriptors = new Set();
  const mutateStat = (stat) => new Proxy(stat, {
    get(target, property) {
      if (property === field) {
        return field === "isFile" ? () => Boolean(value) : value;
      }
      const member = Reflect.get(target, property);
      return typeof member === "function" ? member.bind(target) : member;
    },
  });
  return new Proxy(fs, {
    get(target, property) {
      if (property === "openSync") {
        return (candidate, flags, ...args) => {
          const descriptor = target.openSync(candidate, flags, ...args);
          if (path.resolve(String(candidate)) === expectedLeaf) {
            leafDescriptors.add(descriptor);
          }
          return descriptor;
        };
      }
      if (property === "closeSync") {
        return (descriptor) => {
          const result = target.closeSync(descriptor);
          leafDescriptors.delete(descriptor);
          return result;
        };
      }
      if (property === "fstatSync") {
        return (descriptor, ...args) => {
          const stat = target.fstatSync(descriptor, ...args);
          return family === "fstat" && leafDescriptors.has(descriptor)
            ? mutateStat(stat)
            : stat;
        };
      }
      if (property === "lstatSync" || property === "statSync") {
        return (candidate, ...args) => {
          const stat = target[property](candidate, ...args);
          return family === "path"
              && path.resolve(String(candidate)) === expectedTarget
            ? mutateStat(stat)
            : stat;
        };
      }
      const member = Reflect.get(target, property);
      return typeof member === "function" ? member.bind(target) : member;
    },
  });
}

function environmentEntryBytes(entry) {
  return Buffer.byteLength(String(entry)) + 1;
}

function assertWorkerEnvironmentBounds(entries, label) {
  const sizes = entries.map(environmentEntryBytes);
  assert.ok(
    sizes.every((size) => size <= MAX_WORKER_ENV_ENTRY_BYTES),
    `${label} exceeds the ${MAX_WORKER_ENV_ENTRY_BYTES}-byte per-entry Env limit`,
  );
  assert.ok(
    sizes.reduce((sum, size) => sum + size, 0) <= MAX_WORKER_ENV_TOTAL_BYTES,
    `${label} exceeds the ${MAX_WORKER_ENV_TOTAL_BYTES}-byte aggregate Env limit`,
  );
  const authorityEntries = entries.filter(
    (entry) => String(entry).startsWith("PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64="),
  );
  assert.equal(authorityEntries.length, 1, `${label} must carry one authority entry`);
  assert.ok(
    environmentEntryBytes(authorityEntries[0]) <= MAX_WORKER_ENV_ENTRY_BYTES,
    `${label} authority exceeds the per-entry Env limit`,
  );
}

function authorityEnvironmentEntry(authority) {
  return `PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64=${Buffer.from(
    canonicalFixtureJson(authority),
  ).toString("base64url")}`;
}

function receiptWithAuthorityEntryAtLeast(minimumEntryBytes) {
  const receipt = buildRawActiveReceiptV2();
  const phaseId = "job.backup.capture";
  const phase = receipt.resources.phaseProfiles[phaseId];
  const secretSet = receipt.resources.workerSecretSets[phase.workerSecretSetIds[0]];
  const template = secretSet.files.key;
  let index = 0;
  while (environmentEntryBytes(authorityEnvironmentEntry(
    expectedPhaseAuthority(receipt, "backup.job.execute", phaseId),
  )) < minimumEntryBytes) {
    const suffix = String(index).padStart(4, "0");
    secretSet.files[`extra-${suffix}`] = {
      ...structuredClone(template),
      inode: 10_000 + index,
      relativePath: `extra-${suffix}.key`,
      sha256: fixtureSha256(`hostile-authority-file:${suffix}`),
    };
    index += 1;
    assert.ok(index < 2_000, "failed to construct a bounded hostile authority fixture");
  }
  return receipt;
}

function sameSizeRaceIo(file, substitutedBytes) {
  const expectedPath = path.resolve(file);
  const originalStat = fs.statSync(file);
  const originalMode = originalStat.mode & 0o777;
  assert.equal(
    substitutedBytes.length,
    originalStat.size,
    "race substitution must preserve the admitted stat size",
  );
  const evidence = {
    completedPassesBeforeSubstitution: null,
    firstPassBytes: 0,
    substitutions: 0,
  };
  let leafDescriptor;
  const stableStat = originalStat;
  let substituted = false;
  const substitute = () => {
    if (substituted) return;
    substituted = true;
    evidence.completedPassesBeforeSubstitution = 1;
    evidence.substitutions += 1;
    fs.chmodSync(file, originalMode | 0o200);
    try {
      fs.writeFileSync(file, substitutedBytes);
    } finally {
      fs.chmodSync(file, originalMode);
    }
  };
  const observeFirstPassProgress = (descriptor, position, returnedCount) => {
    if (substituted || descriptor !== leafDescriptor) return;
    if (!Number.isSafeInteger(position)
      || !Number.isSafeInteger(returnedCount)
      || returnedCount <= 0
      || position !== evidence.firstPassBytes) {
      return;
    }
    evidence.firstPassBytes += returnedCount;
    if (evidence.firstPassBytes === originalStat.size) substitute();
  };
  const io = new Proxy(fs, {
    get(target, property) {
      if (property === "openSync") {
        return (candidate, flags, ...args) => {
          const descriptor = target.openSync(candidate, flags, ...args);
          if (path.resolve(String(candidate)) === expectedPath) leafDescriptor = descriptor;
          return descriptor;
        };
      }
      if (property === "fstatSync") {
        return (descriptor, ...args) => {
          if (descriptor !== leafDescriptor) return target.fstatSync(descriptor, ...args);
          return stableStat;
        };
      }
      if (property === "readFileSync") {
        return (descriptor, ...args) => {
          const value = target.readFileSync(descriptor, ...args);
          if (descriptor === leafDescriptor) {
            const returnedCount = Buffer.isBuffer(value)
              ? value.length
              : Buffer.byteLength(String(value));
            observeFirstPassProgress(descriptor, 0, returnedCount);
          }
          return value;
        };
      }
      if (property === "readSync") {
        return (descriptor, buffer, offset, length, position) => {
          const count = target.readSync(descriptor, buffer, offset, length, position);
          observeFirstPassProgress(descriptor, position, count);
          return count;
        };
      }
      if (property === "closeSync") {
        return (descriptor) => {
          const result = target.closeSync(descriptor);
          if (descriptor === leafDescriptor) leafDescriptor = undefined;
          return result;
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { evidence, io };
}

function protectedFilePolicy(parentRoot, expectedUid, expectedGid) {
  return {
    expectedUid,
    expectedGid,
    expectedMode: 0o600,
    maximumBytes: 2 * 1024 * 1024,
    parentRoot,
  };
}

function stagedContainerPath(root, containerPath) {
  assert.equal(path.isAbsolute(containerPath), true, "staged container path must be absolute");
  const stagedPath = path.resolve(root, containerPath.replace(/^\/+/, ""));
  assert.equal(
    stagedPath.startsWith(`${path.resolve(root)}${path.sep}`),
    true,
    "staged container path escaped its image root",
  );
  return stagedPath;
}

function dockerfileLogicalLines(source) {
  const physicalSource = String(source);
  const physicalLines = physicalSource.split(/\r?\n/);
  const parserDirectiveIndexes = [];
  for (const [index, rawLine] of physicalLines.entries()) {
    if (/^\s*#\s*(?:check|escape|syntax)\s*=/i.test(rawLine)) {
      parserDirectiveIndexes.push(index);
      assert.equal(
        rawLine,
        `# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}`,
        "Dockerfile parser directive is not the exact digest-pinned frontend",
      );
      assert.equal(
        index,
        0,
        "Dockerfile frontend must be the first physical line",
      );
    }
  }
  assert.ok(
    parserDirectiveIndexes.length <= 1,
    "Dockerfile may contain exactly one Dockerfile frontend directive",
  );
  const logicalLines = [];
  let pending = "";
  for (const rawLine of physicalLines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    assert.doesNotMatch(
      line,
      /<</,
      "Dockerfile heredoc syntax is forbidden by the exact image manifest",
    );
    assert.doesNotMatch(
      rawLine,
      /\\[ \t]+$/,
      "Dockerfile continuation escape must be the final physical byte",
    );
    pending += `${pending ? " " : ""}${line.replace(/\\$/, "").trim()}`;
    if (line.endsWith("\\")) continue;
    logicalLines.push(pending);
    pending = "";
  }
  assert.equal(pending, "", "Dockerfile ended inside a continued instruction");
  return logicalLines;
}

function assertExactDockerfileFrontendDirective(dockerfileSource) {
  const physicalLines = String(dockerfileSource).split(/\r?\n/);
  assert.equal(
    physicalLines[0],
    `# syntax=${EXPECTED_DOCKERFILE_FRONTEND_REFERENCE}`,
    "Dockerfile frontend must be the first physical line and exact digest-pinned identity",
  );
  assert.equal(
    physicalLines.filter(
      (line) => /^\s*#\s*(?:check|escape|syntax)\s*=/i.test(line),
    ).length,
    1,
    "Dockerfile must contain exactly one Dockerfile frontend directive",
  );
}

function assertExactDockerfileSupplyChainLock(lock) {
  assert.equal(
    lock !== null
      && typeof lock === "object"
      && lock.images !== null
      && typeof lock.images === "object"
      && !Array.isArray(lock.images),
    true,
    "supply-chain lock must expose one images record",
  );
  assert.equal(
    lock.images["dockerfile-frontend"],
    EXPECTED_DOCKERFILE_FRONTEND_REFERENCE,
    "Dockerfile frontend must bind the exact dockerfile-frontend lock key",
  );
  assert.equal(
    lock.images.node,
    EXPECTED_NODE_IMAGE_REFERENCE,
    "Dockerfile base image must bind the exact node lock key",
  );
  assert.notEqual(
    lock.images["dockerfile-frontend"],
    lock.images.node,
    "Dockerfile frontend and Node base image lock identities must stay disjoint",
  );
}

function dockerIgnoreRules(source) {
  const rules = [];
  for (const rawLine of String(source).split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || line === "." || line.startsWith("#")) continue;
    if (line.startsWith("\\#")) line = line.slice(1);
    let negated = false;
    if (line.startsWith("\\!")) {
      line = line.slice(1);
    } else if (line.startsWith("!")) {
      negated = true;
      line = line.slice(1);
    }
    line = line.replaceAll("\\", "/");
    line = line.replace(/^\/+|\/+$/g, "");
    line = path.posix.normalize(line);
    if (!line || line === ".") continue;
    assert.equal(
      !line.startsWith("/")
        && line !== ".."
        && !line.startsWith("../")
        && line.split("/").every((component) => component !== ".."),
      true,
      "Dockerignore pattern may not escape its build context",
    );
    rules.push({
      hasSlash: line.includes("/"),
      negated,
      pattern: line,
    });
  }
  return rules;
}

function dockerIgnoreRuleMatches(rule, candidate) {
  if (rule.hasSlash) {
    return path.matchesGlob(candidate, rule.pattern);
  }
  return path.matchesGlob(path.posix.basename(candidate), rule.pattern);
}

function dockerBuildContextPathIdentity(relativePath) {
  const raw = String(relativePath).replaceAll("\\", "/");
  assert.equal(
    raw.length > 0 && !raw.startsWith("/"),
    true,
    `Docker build-context path is not one bounded relative identity: ${relativePath}`,
  );
  const normalized = path.posix.normalize(raw);
  assert.equal(
    normalized.length > 0
      && normalized !== "."
      && normalized !== ".."
      && !normalized.startsWith("../")
      && normalized.split("/").every(
        (component) => component.length > 0 && component !== "." && component !== "..",
      ),
    true,
    `Docker build-context path is not one bounded relative identity: ${relativePath}`,
  );
  return normalized;
}

function dockerBuildContextPathIsIncluded(relativePath, dockerignoreSource) {
  const normalized = dockerBuildContextPathIdentity(relativePath);
  const components = normalized.split("/");
  const prefixes = components.map((_, index) => ({
    ignored: false,
    path: components.slice(0, index + 1).join("/"),
  }));
  for (const rule of dockerIgnoreRules(dockerignoreSource)) {
    for (const prefix of prefixes) {
      if (dockerIgnoreRuleMatches(rule, prefix.path)) {
        prefix.ignored = !rule.negated;
      }
    }
  }
  return prefixes.every(({ ignored }) => !ignored);
}

function assertDockerCopySourcesIncludedByDockerignore(
  dockerfileSource,
  dockerignoreSource,
) {
  const sources = [];
  for (const instruction of dockerfileLogicalLines(dockerfileSource)) {
    const copy = parseDockerCopyInstruction(instruction);
    if (!copy) continue;
    assert.equal(
      copy.flags.some((flag) => flag.startsWith("--from=")),
      false,
      "Dockerignore closure does not admit cross-stage COPY sources",
    );
    for (const source of copy.sources) {
      assert.doesNotMatch(
        source,
        /[*?[\]{}]/,
        `Dockerfile COPY source must be one exact path: ${source}`,
      );
      assert.equal(
        dockerBuildContextPathIsIncluded(source, dockerignoreSource),
        true,
        `Dockerignore excludes an exact Dockerfile COPY source: ${source}`,
      );
      sources.push(dockerBuildContextPathIdentity(source));
    }
  }
  assert.ok(sources.length > 0, "Dockerfile has no exact COPY source closure");
  return sources.sort();
}

function effectiveDockerignoreForDockerfile(repositoryRoot, dockerfilePath) {
  const root = path.resolve(repositoryRoot);
  const dockerfile = path.resolve(dockerfilePath);
  assert.equal(
    dockerfile.startsWith(`${root}${path.sep}`),
    true,
    "Dockerfile-specific Dockerignore lookup escaped the repository root",
  );
  const dockerfileSpecificPath = `${dockerfile}.dockerignore`;
  const rootPath = path.join(root, ".dockerignore");
  const selectedPath = fs.existsSync(dockerfileSpecificPath)
    ? dockerfileSpecificPath
    : rootPath;
  return {
    path: selectedPath,
    source: fs.existsSync(selectedPath)
      ? fs.readFileSync(selectedPath, "utf8")
      : "",
  };
}

function canonicalProductionDockerfileInstructions() {
  const adapterCopies = Object.keys(EXPECTED_FIXED_ADAPTERS)
    .sort()
    .map((command) =>
      `COPY --chown=0:0 --chmod=0555 ${FIXED_ADAPTER_SOURCE_DIRECTORY}/${command}.mjs ${EXPECTED_FIXED_ADAPTERS[command].executable}`);
  return [
    `FROM ${EXPECTED_NODE_IMAGE_REFERENCE}`,
    "WORKDIR /opt/platform-docker-broker",
    "COPY scripts/docker-action-contract.mjs /opt/platform-docker-broker/docker-action-contract.mjs",
    "COPY scripts/docker-action-activation.mjs /opt/platform-docker-broker/docker-action-activation.mjs",
    "COPY scripts/docker-action-broker.mjs /opt/platform-docker-broker/docker-action-broker.mjs",
    `COPY scripts/docker-action-worker.mjs ${WORKER_CONTAINER_PATH}`,
    "COPY policy/docker-action-activation-policy.json /opt/platform-docker-broker/docker-action-activation-policy.json",
    "RUN chmod 0555 /opt/platform-docker-broker/docker-action-contract.mjs /opt/platform-docker-broker/docker-action-activation.mjs /opt/platform-docker-broker/docker-action-broker.mjs /opt/platform-docker-worker/docker-action-worker.mjs && chmod 0400 /opt/platform-docker-broker/docker-action-activation-policy.json && chown -R root:root /opt/platform-docker-broker /opt/platform-docker-worker",
    ...adapterCopies,
    `COPY --chown=0:0 --chmod=0555 scripts/docker-action-worker-runtime-guard.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
    `ENTRYPOINT ${JSON.stringify(EXPECTED_BROKER_IMAGE_ENTRYPOINT)}`,
  ];
}

function assertFinalRuntimeGuardLayer(dockerfileSource) {
  assertExactDockerfileFrontendDirective(dockerfileSource);
  const allLogicalLines = dockerfileLogicalLines(dockerfileSource);
  assert.equal(
    canonicalProductionDockerfileInstructions().length === allLogicalLines.length
      && canonicalProductionDockerfileInstructions().every(
        (instruction, index) => instruction === allLogicalLines[index],
      ),
    true,
    "Dockerfile does not match the one exact canonical immutable production image manifest",
  );
}

function assertFixtureFinalRuntimeGuardLayer(dockerfileSource) {
  const allLogicalLines = dockerfileLogicalLines(dockerfileSource);
  const exactFixtureManifest = [
    "FROM node:fixture",
    `COPY --chown=0:0 --chmod=0555 scripts/docker-action-worker-runtime-guard.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`,
    `ENTRYPOINT ${JSON.stringify(EXPECTED_BROKER_IMAGE_ENTRYPOINT)}`,
  ];
  assert.equal(
    exactFixtureManifest.length === allLogicalLines.length
      && exactFixtureManifest.every(
        (instruction, index) => instruction === allLogicalLines[index],
      ),
    true,
    "Dockerfile does not match the exact fixture-only canonical immutable image manifest",
  );
}

function dockerfileInstructionRecords(source) {
  return dockerfileLogicalLines(source).map((instruction, index) => ({
    index,
    instruction,
    keyword: instruction.match(/^([A-Z]+)/i)?.[1]?.toUpperCase() ?? "",
  }));
}

function parseDockerCopyInstruction(instruction) {
  const match = String(instruction).match(/^COPY\s+(.+)$/i);
  if (!match) return null;
  const tokens = match[1].split(/\s+/).filter(Boolean);
  const flags = [];
  while (tokens[0]?.startsWith("--")) flags.push(tokens.shift());
  if (tokens.length < 2) return { destination: null, flags, sources: [] };
  return {
    destination: tokens.at(-1),
    flags,
    sources: tokens.slice(0, -1),
  };
}

function fixedAdapterPackageAssessment({
  dockerfileSource,
  repositoryRoot,
  stagedRoot,
}) {
  const records = dockerfileInstructionRecords(dockerfileSource);
  const issues = [];
  const auditedCommands = [];
  const finalFromIndex = records.findLastIndex(({ keyword }) => keyword === "FROM");
  if (finalFromIndex < 0) {
    return {
      auditedCommands,
      issues: ["Dockerfile has no final image stage"],
    };
  }
  const finalStage = records.filter(({ index }) => index > finalFromIndex);
  const admittedCopyIndexes = new Set();
  const adapterCopyIndexes = [];
  const requiredFlags = ["--chown=0:0", "--chmod=0555"].sort();
  const exactGuardCopy =
    `COPY --chown=0:0 --chmod=0555 scripts/docker-action-worker-runtime-guard.mjs ${WORKER_RUNTIME_GUARD_CONTAINER_PATH}`;
  const exactGuardCopies = finalStage.filter(
    ({ instruction }) => instruction === exactGuardCopy,
  );
  if (exactGuardCopies.length === 1) {
    admittedCopyIndexes.add(exactGuardCopies[0].index);
  }

  for (const [command, expected] of Object.entries(EXPECTED_FIXED_ADAPTERS)) {
    const issueCount = issues.length;
    const candidates = finalStage
      .map((record) => ({ ...record, copy: parseDockerCopyInstruction(record.instruction) }))
      .filter(({ copy }) => copy?.destination === expected.executable);
    if (candidates.length !== 1) {
      issues.push(
        `${command}: requires exactly one final-stage per-target COPY to ${expected.executable}`,
      );
      continue;
    }
    const candidate = candidates[0];
    adapterCopyIndexes.push(candidate.index);
    if (
      candidate.copy.sources.length !== 1
      || !exactStringArray(candidate.copy.flags.slice().sort(), requiredFlags)
    ) {
      issues.push(
        `${command}: final COPY must be exactly one source with --chown=0:0 --chmod=0555`,
      );
      continue;
    }
    admittedCopyIndexes.add(candidate.index);
    const [source] = candidate.copy.sources;
    if (
      path.isAbsolute(source)
      || /[*?[\]{}]/.test(source)
      || source.startsWith("../")
    ) {
      issues.push(`${command}: repository source path is not one bounded relative path`);
      continue;
    }
    const sourcePath = path.resolve(repositoryRoot, source);
    if (
      sourcePath === path.resolve(repositoryRoot)
      || !sourcePath.startsWith(`${path.resolve(repositoryRoot)}${path.sep}`)
      || !fs.existsSync(sourcePath)
      || hasSymlinkPathComponent(repositoryRoot, sourcePath)
    ) {
      issues.push(`${command}: repository source must exist inside the root as a regular non-symlink`);
      continue;
    }
    const sourceStat = fs.lstatSync(sourcePath);
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) {
      issues.push(`${command}: repository source must be one regular non-symlink file`);
      continue;
    }
    const sourceBytes = fs.readFileSync(sourcePath);
    if (
      sourceBytes.length < 1
      || sourceBytes.length > MAX_FIXED_ADAPTER_SOURCE_BYTES
      || !Buffer.from(sourceBytes.toString("utf8"), "utf8").equals(sourceBytes)
      || sourceBytes.includes(0)
    ) {
      issues.push(`${command}: repository source bytes are empty, oversized, binary, or non-UTF-8`);
      continue;
    }
    const expectedSourceBytes = Buffer.from(
      EXPECTED_FIXED_ADAPTER_SOURCE_TEXT[command],
      "utf8",
    );
    if (!sourceBytes.equals(expectedSourceBytes)) {
      issues.push(`${command}: repository source bytes do not match the exact adapter contract`);
      continue;
    }
    const stagedTarget = stagedContainerPath(stagedRoot, expected.executable);
    if (!fs.existsSync(stagedTarget)) {
      issues.push(`${command}: staged target is missing`);
      continue;
    }
    const stagedStat = fs.lstatSync(stagedTarget);
    if (!stagedStat.isFile() || stagedStat.isSymbolicLink()) {
      issues.push(`${command}: staged target must be one regular non-symlink file`);
      continue;
    }
    if ((stagedStat.mode & 0o777) !== 0o555) {
      issues.push(`${command}: staged target does not simulate final mode 0555`);
      continue;
    }
    const stagedBytes = fs.readFileSync(stagedTarget);
    if (
      stagedBytes.length !== sourceBytes.length
      || testCryptoSha256(stagedBytes) !== testCryptoSha256(sourceBytes)
      || !stagedBytes.equals(sourceBytes)
    ) {
      issues.push(`${command}: staged target bytes diverge from the repository source`);
      continue;
    }
    if (issues.length === issueCount) auditedCommands.push(command);
  }

  if (adapterCopyIndexes.length > 0) {
    const firstAdapterCopyIndex = Math.min(...adapterCopyIndexes);
    const filesystemMutatingKeywords = new Set([
      "ADD",
      "COPY",
      "ONBUILD",
      "RUN",
      "VOLUME",
      "WORKDIR",
    ]);
    for (const record of finalStage) {
      if (
        record.index > firstAdapterCopyIndex
        && filesystemMutatingKeywords.has(record.keyword)
        && !admittedCopyIndexes.has(record.index)
      ) {
        issues.push(
          `Dockerfile has a filesystem-mutating instruction after the adapter COPY block: ${record.instruction}`,
        );
      }
    }
  }
  return {
    auditedCommands: auditedCommands.sort(),
    issues: [...new Set(issues)].sort(),
  };
}

function exactStringArray(left, right) {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function hasSymlinkPathComponent(root, file) {
  const relative = path.relative(path.resolve(root), path.resolve(file));
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return true;
  let cursor = path.resolve(root);
  for (const component of relative.split(path.sep)) {
    cursor = path.join(cursor, component);
    if (fs.lstatSync(cursor).isSymbolicLink()) return true;
  }
  return false;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stageDockerWorkerImageLayout(t, prefix, {
  repositoryRoot = path.resolve(scriptDir, ".."),
  dockerignore,
  dockerfile = path.join(path.resolve(scriptDir, ".."), "docker", "docker-action-broker.Dockerfile"),
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const dockerfileSource = fs.readFileSync(dockerfile, "utf8");
  const dockerignoreSource = dockerignore === undefined
    ? effectiveDockerignoreForDockerfile(repositoryRoot, dockerfile).source
    : (
      fs.existsSync(dockerignore)
        ? fs.readFileSync(dockerignore, "utf8")
        : ""
    );
  assertDockerCopySourcesIncludedByDockerignore(
    dockerfileSource,
    dockerignoreSource,
  );
  const allLogicalLines = dockerfileLogicalLines(dockerfileSource);
  const finalFromIndex = allLogicalLines.findLastIndex(
    (instruction) => /^FROM(?:\s|$)/i.test(instruction),
  );
  assert.ok(finalFromIndex >= 0, "Dockerfile stage has no final FROM instruction");
  const logicalLines = allLogicalLines.slice(finalFromIndex);
  let copyCount = 0;
  for (const instruction of logicalLines) {
    const match = instruction.match(/^COPY\s+(.+)$/i);
    if (!match) continue;
    const tokens = match[1].split(/\s+/).filter(Boolean);
    assert.equal(
      tokens.some((token) => token.startsWith("--from=")),
      false,
      "dependency closure cannot materialize a COPY --from stage",
    );
    const paths = tokens.filter((token) => !token.startsWith("--"));
    assert.ok(paths.length >= 2, `malformed Dockerfile COPY: ${instruction}`);
    const destination = paths.at(-1);
    const sources = paths.slice(0, -1);
    for (const source of sources) {
      assert.doesNotMatch(source, /[*?[\]{}]/, `unbounded Dockerfile COPY source: ${source}`);
      const sourcePath = path.resolve(repositoryRoot, source);
      const repositoryPrefix = `${repositoryRoot}${path.sep}`;
      assert.ok(
        sourcePath.startsWith(repositoryPrefix),
        `Dockerfile COPY escaped the repository root: ${source}`,
      );
      assert.equal(fs.existsSync(sourcePath), true, `Dockerfile COPY source is missing: ${source}`);
      const destinationPath = path.join(
        root,
        destination.replace(/^\/+/, ""),
        sources.length > 1 || destination.endsWith("/") ? path.basename(source) : "",
      );
      fs.mkdirSync(path.dirname(destinationPath), { mode: 0o700, recursive: true });
      fs.cpSync(sourcePath, destinationPath, {
        errorOnExist: true,
        force: false,
        preserveTimestamps: true,
        recursive: fs.statSync(sourcePath).isDirectory(),
      });
      const modeFlag = tokens.find((token) => token.startsWith("--chmod="));
      if (modeFlag) {
        const mode = Number.parseInt(modeFlag.slice("--chmod=".length), 8);
        assert.equal(Number.isInteger(mode), true, `invalid Dockerfile COPY mode: ${modeFlag}`);
        fs.chmodSync(destinationPath, mode);
      }
      copyCount += 1;
    }
  }
  assert.ok(copyCount >= 1, "Dockerfile stage did not materialize any COPY instruction");
  const stagedWorkerPath = path.join(
    root,
    "opt",
    "platform-docker-worker",
    "docker-action-worker.mjs",
  );
  assert.equal(fs.existsSync(stagedWorkerPath), true, "Dockerfile stage omitted the worker entrypoint");
  return { dockerfile, root, workerPath: stagedWorkerPath };
}

function socketlessRuntimeGuardSource() {
  return `
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import moduleBuiltin from "node:module";
import { PassThrough } from "node:stream";
import { types as utilTypes } from "node:util";

const ALLOWED_BUILTINS = new Set(${JSON.stringify([...ALLOWED_WORKER_BUILTINS].sort())});
const EXPECTED_COMMAND_BY_ACTION_PHASE = Object.freeze(
  ${JSON.stringify(EXPECTED_COMMAND_BY_ACTION_PHASE)},
);
const EXPECTED_EXECUTABLE_BY_COMMAND = Object.freeze(
  ${JSON.stringify(Object.fromEntries(
    Object.entries(EXPECTED_FIXED_ADAPTERS).map(
      ([command, { executable }]) => [command, executable],
    ),
  ))},
);

if (process.platform === "darwin" && Object.hasOwn(process.env, "__CF_USER_TEXT_ENCODING")) {
  if (!/^0x[0-9a-f]+:0x[0-9a-f]+:0x[0-9a-f]+$/i.test(process.env.__CF_USER_TEXT_ENCODING)) {
    throw new Error("socketless runtime guard rejected malformed Darwin launcher metadata");
  }
  delete process.env.__CF_USER_TEXT_ENCODING;
}

const SENTINEL = Symbol.for("platform.worker.socketless-guard-count");
globalThis[SENTINEL] = (globalThis[SENTINEL] ?? 0) + 1;

function blocked(label) {
  return () => {
    throw new Error("socketless runtime guard blocked " + label);
  };
}

const syncBuiltinExports =
  moduleBuiltin.syncBuiltinESMExports.bind(moduleBuiltin);
const registerHooks = moduleBuiltin.registerHooks?.bind(moduleBuiltin);
if (typeof registerHooks !== "function") {
  throw new Error("socketless runtime guard requires module.registerHooks");
}
const resolutionHookRegistration = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (String(specifier).startsWith("node:")) {
      if (!ALLOWED_BUILTINS.has(String(specifier))) {
        throw new Error("socketless runtime guard blocked module resolution: " + specifier);
      }
      return nextResolve(specifier, context);
    }
    if (
      String(specifier).startsWith("./")
      || String(specifier).startsWith("../")
      || String(specifier).startsWith("file:")
    ) {
      return nextResolve(specifier, context);
    }
    throw new Error("socketless runtime guard blocked bare or remote module resolution: " + specifier);
  },
});
if (typeof resolutionHookRegistration?.deregister !== "function") {
  throw new Error("socketless runtime guard did not retain its lexical resolution hook");
}

const OriginalFunction = globalThis.Function;
const FunctionPrototype = OriginalFunction.prototype;
const AsyncFunctionPrototype = Object.getPrototypeOf(async function () {});
const GeneratorFunctionPrototype = Object.getPrototypeOf(function* () {});
const AsyncGeneratorFunctionPrototype = Object.getPrototypeOf(async function* () {});
const constructorIntrinsics = [
  ["Function", FunctionPrototype.constructor, FunctionPrototype],
  ["AsyncFunction", AsyncFunctionPrototype.constructor, AsyncFunctionPrototype],
  ["GeneratorFunction", GeneratorFunctionPrototype.constructor, GeneratorFunctionPrototype],
  [
    "AsyncGeneratorFunction",
    AsyncGeneratorFunctionPrototype.constructor,
    AsyncGeneratorFunctionPrototype,
  ],
];
const guardedConstructors = new Map();
for (const [name, intrinsic, prototype] of constructorIntrinsics) {
  const guarded = new Proxy(intrinsic, {
    apply: blocked(name),
    construct: blocked(name),
  });
  Object.defineProperty(prototype, "constructor", {
    configurable: true,
    value: guarded,
    writable: true,
  });
  guardedConstructors.set(name, guarded);
}
for (const name of ["eval", "fetch", "WebSocket", "EventSource"]) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value: blocked(name),
    writable: true,
  });
}
Object.defineProperty(globalThis, "Function", {
  configurable: true,
  value: guardedConstructors.get("Function"),
  writable: true,
});
for (const name of [
  "getBuiltinModule",
  "binding",
  "_linkedBinding",
  "dlopen",
  "execve",
  "_getActiveHandles",
  "_getActiveRequests",
]) {
  Object.defineProperty(process, name, {
    configurable: true,
    value: blocked("process." + name),
    writable: true,
  });
}
moduleBuiltin.createRequire = blocked("module.createRequire");
moduleBuiltin._load = blocked("module._load");
moduleBuiltin.runMain = blocked("module.runMain");
moduleBuiltin._preloadModules = blocked("module._preloadModules");
moduleBuiltin._extensions = Object.freeze(Object.create(null));
moduleBuiltin.prototype._compile = blocked("module._compile");
moduleBuiltin.prototype.load = blocked("module.load");
moduleBuiltin.prototype.require = blocked("module.require");
moduleBuiltin.register = blocked("module.register");
moduleBuiltin.registerHooks = blocked("module.registerHooks");

const rawStdout = process.stdout;
const rawStderr = process.stderr;
function safeWritableFacade(rawStream, label) {
  const facade = Object.create(null);
  Object.defineProperties(facade, {
    isTTY: {
      enumerable: true,
      value: rawStream?.isTTY === true,
    },
    write: {
      enumerable: true,
      value: (...arguments_) => {
        if (!rawStream || typeof rawStream.write !== "function") {
          throw new Error("socketless runtime guard has no " + label + " writer");
        }
        return Reflect.apply(rawStream.write, rawStream, arguments_);
      },
    },
  });
  return Object.freeze(facade);
}
const safeStdin = Object.create(null);
Object.defineProperties(safeStdin, {
  isTTY: { enumerable: true, value: false },
  read: { enumerable: true, value: blocked("process.stdin.read") },
});
Object.freeze(safeStdin);
for (const [name, value] of [
  ["stdin", safeStdin],
  ["stdout", safeWritableFacade(rawStdout, "stdout")],
  ["stderr", safeWritableFacade(rawStderr, "stderr")],
]) {
  Object.defineProperty(process, name, {
    configurable: true,
    enumerable: true,
    value,
    writable: false,
  });
}

const guardedEnvironmentEntries = Object.entries(process.env)
  .sort(([left], [right]) => left.localeCompare(right));
const guardedProcessEnvironment = JSON.stringify(
  Object.fromEntries(guardedEnvironmentEntries),
);
const guardOwnedEnvironment = Object.freeze(
  Object.fromEntries(guardedEnvironmentEntries),
);
const guardOwnedArgv = Object.freeze([]);
const guardOwnedStdio = Object.freeze(["ignore", "pipe", "pipe"]);
const guardOwnedOptions = Object.freeze({
  env: guardOwnedEnvironment,
  shell: false,
  stdio: guardOwnedStdio,
});

function hasExactDataDescriptor(descriptor, value) {
  return descriptor !== undefined
    && Object.hasOwn(descriptor, "value")
    && descriptor.configurable === true
    && descriptor.enumerable === true
    && descriptor.writable === true
    && Object.is(descriptor.value, value);
}

function hasExactEmptyArrayShape(value) {
  if (
    !Array.isArray(value)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || JSON.stringify(Reflect.ownKeys(value)) !== JSON.stringify(["length"])
  ) {
    return false;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, "length");
  return descriptor !== undefined
    && Object.hasOwn(descriptor, "value")
    && descriptor.configurable === false
    && descriptor.enumerable === false
    && descriptor.writable === true
    && descriptor.value === 0;
}

function hasExactStdioShape(value) {
  if (
    !Array.isArray(value)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || JSON.stringify(Reflect.ownKeys(value))
      !== JSON.stringify(["0", "1", "2", "length"])
  ) {
    return false;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return hasExactDataDescriptor(descriptors["0"], "ignore")
    && hasExactDataDescriptor(descriptors["1"], "pipe")
    && hasExactDataDescriptor(descriptors["2"], "pipe")
    && descriptors.length?.configurable === false
    && descriptors.length?.enumerable === false
    && descriptors.length?.writable === true
    && descriptors.length?.value === 3;
}

function hasExactOptionsShape(value) {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || JSON.stringify(Reflect.ownKeys(value).sort())
      !== JSON.stringify(["env", "shell", "stdio"])
  ) {
    return false;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return hasExactDataDescriptor(descriptors.env, process.env)
    && hasExactDataDescriptor(descriptors.shell, false)
    && hasExactDataDescriptor(descriptors.stdio, descriptors.stdio?.value)
    && hasExactStdioShape(descriptors.stdio.value);
}

const originalSpawn = childProcess.spawn.bind(childProcess);
const OriginalChildProcess = childProcess.ChildProcess;
const ChildProcessPrototype = OriginalChildProcess.prototype;
const originalPrototypeSpawnDescriptor =
  Object.getOwnPropertyDescriptor(ChildProcessPrototype, "spawn");
if (
  !originalPrototypeSpawnDescriptor
  || typeof originalPrototypeSpawnDescriptor.value !== "function"
) {
  throw new Error("socketless runtime guard requires ChildProcess.prototype.spawn");
}
let prototypeSpawnPermit = false;
const guardedPrototypeSpawnDescriptor = {
  ...originalPrototypeSpawnDescriptor,
  value: function (...arguments_) {
    if (!prototypeSpawnPermit) {
      throw new Error(
        "socketless runtime guard blocked ChildProcess.prototype.spawn",
      );
    }
    prototypeSpawnPermit = false;
    return Reflect.apply(
      originalPrototypeSpawnDescriptor.value,
      this,
      arguments_,
    );
  },
};
Object.defineProperty(
  ChildProcessPrototype,
  "spawn",
  guardedPrototypeSpawnDescriptor,
);
childProcess.ChildProcess = undefined;
childProcess._forkChild = undefined;
for (const api of [
  "exec",
  "execFile",
  "execFileSync",
  "execSync",
  "fork",
  "spawnSync",
]) {
  childProcess[api] = blocked("non-admitted child_process API: " + api);
}
let admittedSpawnCount = 0;

function spawnWithGuardOwnedInputs(executable) {
  if (prototypeSpawnPermit) {
    throw new Error("socketless runtime guard detected a nested spawn permit");
  }
  prototypeSpawnPermit = true;
  try {
    const child = originalSpawn(
      executable,
      guardOwnedArgv,
      guardOwnedOptions,
    );
    if (prototypeSpawnPermit) {
      throw new Error(
        "socketless runtime guard spawn did not cross its lexical prototype permit",
      );
    }
    return child;
  } finally {
    prototypeSpawnPermit = false;
  }
}

function safeReadableFacade(rawStream, label) {
  if (
    rawStream === null
    || typeof rawStream !== "object"
    || typeof rawStream.on !== "function"
  ) {
    throw new Error("socketless runtime guard received no " + label + " stream");
  }
  const safeStream = new PassThrough();
  rawStream.on("data", (chunk) => safeStream.write(chunk));
  rawStream.on("end", () => safeStream.end());
  rawStream.on("error", (error) => safeStream.destroy(error));
  return safeStream;
}

function safeChildFacade(rawChild) {
  if (
    rawChild === null
    || typeof rawChild !== "object"
    || typeof rawChild.on !== "function"
  ) {
    throw new Error("socketless runtime guard received no child process");
  }
  const safeChild = new EventEmitter();
  safeChild.stdin = null;
  safeChild.stdout = safeReadableFacade(rawChild.stdout, "stdout");
  safeChild.stderr = safeReadableFacade(rawChild.stderr, "stderr");
  safeChild.pid = Number.isSafeInteger(rawChild.pid) ? rawChild.pid : undefined;
  safeChild.kill = (signal = "SIGTERM") => {
    if (signal !== "SIGTERM" && signal !== "SIGKILL") {
      throw new Error("socketless runtime guard rejected child signal");
    }
    if (typeof rawChild.kill !== "function") return false;
    return Reflect.apply(rawChild.kill, rawChild, [signal]);
  };
  for (const event of ["close", "disconnect", "error", "exit"]) {
    rawChild.on(event, (...arguments_) => safeChild.emit(event, ...arguments_));
  }
  return safeChild;
}

childProcess.spawn = (executable, argv, options) => {
  const currentProcessEnvironment = JSON.stringify(
    Object.fromEntries(
      Object.entries(process.env).sort(([left], [right]) => left.localeCompare(right)),
    ),
  );
  const action = process.env.PLATFORM_DOCKER_ACTION;
  const phaseId = process.env.PLATFORM_DOCKER_PHASE_ID;
  const command = EXPECTED_COMMAND_BY_ACTION_PHASE[action + "\\0" + phaseId];
  const expectedExecutable = EXPECTED_EXECUTABLE_BY_COMMAND[command];
  if (
    typeof executable !== "string"
    || typeof command !== "string"
    || executable !== expectedExecutable
    || !hasExactEmptyArrayShape(argv)
    || !hasExactOptionsShape(options)
    || Object.hasOwn(process.env, "NODE_OPTIONS")
    || currentProcessEnvironment !== guardedProcessEnvironment
    || admittedSpawnCount !== 0
  ) {
    throw new Error(
      "socketless runtime guard rejected non-exact fixed adapter spawn",
    );
  }
  admittedSpawnCount += 1;
  return safeChildFacade(spawnWithGuardOwnedInputs(executable));
};
syncBuiltinExports();
moduleBuiltin.syncBuiltinESMExports = undefined;
syncBuiltinExports();
`;
}

function fixedAdapterHookSource(tracePath, {
  expectedCommandByPhase = {},
  expectedEnvironmentByPhase = {},
  expectedOutputByPhase = {},
  exitStatus = 0,
  oversizedOutput = false,
  stagedRoot = "",
} = {}) {
  return `
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { PassThrough } from "node:stream";
import { types as utilTypes } from "node:util";

const TRACE_PATH = ${JSON.stringify(tracePath)};
const EXPECTED_ADAPTERS = ${JSON.stringify(EXPECTED_FIXED_ADAPTERS)};
const EXPECTED_ADAPTER_SOURCE_TEXT = ${JSON.stringify(EXPECTED_FIXED_ADAPTER_SOURCE_TEXT)};
const EXPECTED_COMMAND_BY_PHASE = ${JSON.stringify(expectedCommandByPhase)};
const EXPECTED_ENVIRONMENT_BY_PHASE = ${JSON.stringify(expectedEnvironmentByPhase)};
const EXPECTED_OUTPUT_BY_PHASE = ${JSON.stringify(expectedOutputByPhase)};
const EXIT_STATUS = ${JSON.stringify(exitStatus)};
const OVERSIZED_OUTPUT = ${JSON.stringify(oversizedOutput)};
const STAGED_ROOT = ${JSON.stringify(stagedRoot)};
const PRELOAD_SENTINEL = Symbol.for("platform.worker.fixed-adapter-preload-count");
globalThis[PRELOAD_SENTINEL] = (globalThis[PRELOAD_SENTINEL] ?? 0) + 1;
const PRELOAD_COUNT = globalThis[PRELOAD_SENTINEL];

function sortedEnvironment(value) {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function exactJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function expectedPhaseContext() {
  const socketlessGuardCount =
    globalThis[Symbol.for("platform.worker.socketless-guard-count")] ?? 0;
  if (socketlessGuardCount !== 1) {
    throw new Error("socketless runtime guard was not loaded exactly once");
  }
  const phaseId = process.env.PLATFORM_DOCKER_PHASE_ID;
  const expectedEnvironment = EXPECTED_ENVIRONMENT_BY_PHASE[phaseId];
  const command = EXPECTED_COMMAND_BY_PHASE[phaseId];
  const output = EXPECTED_OUTPUT_BY_PHASE[phaseId];
  if (!expectedEnvironment || !command || !output) {
    throw new Error("test preload received an unsupported phase context");
  }
  const processEnvironment = sortedEnvironment(process.env);
  if (Object.hasOwn(processEnvironment, "NODE_OPTIONS")) {
    throw new Error("worker process environment contains forbidden NODE_OPTIONS");
  }
  if (!exactJson(processEnvironment, sortedEnvironment(expectedEnvironment))) {
    throw new Error("worker process environment diverged from the independent body oracle");
  }
  return {
    command,
    expectedEnvironment,
    output,
    phaseId,
    processEnvironment,
    socketlessGuardCount,
  };
}

function exactFrozenDataDescriptor(descriptor, value) {
  return descriptor !== undefined
    && Object.hasOwn(descriptor, "value")
    && descriptor.configurable === false
    && descriptor.enumerable === true
    && descriptor.writable === false
    && Object.is(descriptor.value, value);
}

function assertGuardOwnedInvocationShape(options, context, expected) {
  if (
    options === null
    || typeof options !== "object"
    || utilTypes.isProxy(options)
    || JSON.stringify(Reflect.ownKeys(options).sort())
      !== JSON.stringify([
        "args",
        "cwd",
        "detached",
        "env",
        "envPairs",
        "file",
        "shell",
        "stdio",
        "windowsHide",
        "windowsVerbatimArguments",
      ])
  ) {
    throw new Error("fixed adapter did not receive the exact normalized spawn record");
  }
  const optionDescriptors = Object.getOwnPropertyDescriptors(options);
  if (
    Reflect.ownKeys(optionDescriptors).some((key) =>
      !Object.hasOwn(optionDescriptors[key], "value")
      || typeof optionDescriptors[key].get === "function"
      || typeof optionDescriptors[key].set === "function")
  ) {
    throw new Error("fixed adapter normalized options contain an accessor field");
  }
  if (
    options.cwd !== undefined
    || options.detached !== false
    || options.file !== expected.executable
    || options.shell !== false
    || options.windowsHide !== false
    || options.windowsVerbatimArguments !== false
    || !Array.isArray(options.args)
    || utilTypes.isProxy(options.args)
    || !exactJson(options.args, [expected.executable])
  ) {
    throw new Error("fixed adapter normalized process identity diverged");
  }
  const environment = optionDescriptors.env.value;
  if (
    environment === process.env
    || environment === null
    || typeof environment !== "object"
    || utilTypes.isProxy(environment)
    || Object.getPrototypeOf(environment) !== Object.prototype
    || !Object.isFrozen(environment)
  ) {
    throw new Error("fixed adapter environment is not one guard-owned snapshot");
  }
  const environmentDescriptors = Object.getOwnPropertyDescriptors(environment);
  if (
    Reflect.ownKeys(environmentDescriptors).some((key) =>
      !exactFrozenDataDescriptor(
        environmentDescriptors[key],
        environmentDescriptors[key]?.value,
      ))
    || !exactJson(
      sortedEnvironment(environment),
      sortedEnvironment(context.expectedEnvironment),
    )
  ) {
    throw new Error("fixed adapter environment diverged from the worker process environment");
  }
  const stdio = optionDescriptors.stdio.value;
  const stdioDescriptors = Object.getOwnPropertyDescriptors(stdio);
  if (
    !Array.isArray(stdio)
    || utilTypes.isProxy(stdio)
    || Object.getPrototypeOf(stdio) !== Array.prototype
    || !Object.isFrozen(stdio)
    || JSON.stringify(Reflect.ownKeys(stdio))
      !== JSON.stringify(["0", "1", "2", "length"])
    || !exactFrozenDataDescriptor(stdioDescriptors["0"], "ignore")
    || !exactFrozenDataDescriptor(stdioDescriptors["1"], "pipe")
    || !exactFrozenDataDescriptor(stdioDescriptors["2"], "pipe")
    || stdioDescriptors.length?.value !== 3
    || stdioDescriptors.length?.writable !== false
  ) {
    throw new Error("fixed adapter stdio is not the exact guard-owned tuple");
  }
  const expectedEnvironmentPairs = Object.entries(context.expectedEnvironment)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => name + "=" + value);
  if (
    !Array.isArray(options.envPairs)
    || utilTypes.isProxy(options.envPairs)
    || !exactJson(options.envPairs, expectedEnvironmentPairs)
  ) {
    throw new Error("fixed adapter normalized environment pairs diverged");
  }
  return environment;
}

function encodedOutput(output) {
  output = JSON.parse(JSON.stringify(output));
  if (OVERSIZED_OUTPUT) output.unmodeledOversizedEvidence = "a".repeat(8192);
  return Buffer.from(JSON.stringify(output) + "\\n");
}

function assertExactInvocation(options) {
  const context = expectedPhaseContext();
  const expected = EXPECTED_ADAPTERS[context.command];
  if (!expected) throw new Error("fixed adapter command has no exact oracle");
  const effectiveEnvironment = assertGuardOwnedInvocationShape(
    options,
    context,
    expected,
  );
  const actual = {
    api: "spawn",
    executable: options.file,
    argv: options.args.slice(1),
    shell: options.shell,
  };
  if (!exactJson(actual, expected)) {
    throw new Error("fixed adapter invocation diverged from its exact code-owned identity");
  }
  const stagedExecutable = path.resolve(
    STAGED_ROOT,
    expected.executable.replace(/^\\/+/, ""),
  );
  if (!stagedExecutable.startsWith(path.resolve(STAGED_ROOT) + path.sep)) {
    throw new Error("fixed adapter staged target escaped the image root");
  }
  const stat = fs.lstatSync(stagedExecutable);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o555) {
    throw new Error("fixed adapter staged target is not one regular file");
  }
  if (
    fs.readFileSync(stagedExecutable, "utf8")
    !== EXPECTED_ADAPTER_SOURCE_TEXT[context.command]
  ) {
    throw new Error("fixed adapter source bytes diverged from the exact adapter contract");
  }
  return {
    actual,
    context,
    effectiveEnvironment: sortedEnvironment(effectiveEnvironment),
  };
}

function record(validated) {
  fs.appendFileSync(TRACE_PATH, JSON.stringify({
    ...validated.actual,
    environment: validated.effectiveEnvironment,
    phaseId: validated.context.phaseId,
    preloadCount: PRELOAD_COUNT,
    processEnvironment: validated.context.processEnvironment,
    socketlessGuardCount: validated.context.socketlessGuardCount,
  }) + "\\n");
}

function asynchronousChild(child, stdout) {
  child.pid = 4242;
  child.stdin = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  queueMicrotask(() => {
    child.stdout.end(stdout);
    child.stderr.end();
    child.emit("exit", EXIT_STATUS, null);
    child.emit("close", EXIT_STATUS, null);
  });
}

childProcess.ChildProcess.prototype.spawn = function (options) {
  const validated = assertExactInvocation(options);
  record(validated);
  asynchronousChild(this, encodedOutput(validated.context.output));
};

for (const api of ["exec", "execFile", "execFileSync", "execSync", "fork", "spawnSync"]) {
  childProcess[api] = () => {
    throw new Error("worker crossed a non-admitted child_process API: " + api);
  };
}

syncBuiltinESMExports();
`;
}

function readJsonLines(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, "utf8");
  return text
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function writeProtectedJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function signedManifestEnvelope() {
  const artifactPath = "postgres/worker-test.dump";
  const artifactBytes = Buffer.from("worker test artifact\n");
  const artifactSha256 = testCryptoSha256(artifactBytes);
  const unsigned = {
    schema: "platform.backup-manifest/v1",
    id: "manifest-worker-test",
    jobId: "job-worker-test",
    operation: "backup",
    scope: { kind: "platform", id: "platform" },
    resources: [{
      id: "database:postgres",
      externalId: "postgres",
      kind: "database",
      projectId: "platform",
      name: "postgres",
      engine: "postgres",
    }],
    artifacts: [{
      id: "artifact-worker-test",
      resourceId: "database:postgres",
      path: artifactPath,
      sha256: artifactSha256,
      sizeBytes: 21,
      signatureKeyId: "artifact-test-v1",
    }],
    coverage: {
      requiredResourceIds: ["database:postgres"],
      artifactResourceIds: ["database:postgres"],
      missingResourceIds: [],
      complete: true,
    },
    createdAt: "2026-07-26T12:00:00.000Z",
  };
  const digest = testManifestDigest(unsigned);
  const manifestMac = testHmacBase64Url(
    MANIFEST_TEST_KEY,
    `platform-backup-manifest-v1\n${unsigned.id}\n${digest}\n`,
  );
  const artifactName = path.basename(artifactPath);
  const artifactMac = testHmacBase64Url(
    ARTIFACT_TEST_KEY,
    `platform-postgres-backup-v1\n${artifactName}\n${artifactSha256}\n`,
  );
  return {
    artifactBytes,
    manifest: {
      ...unsigned,
      signature: {
        algorithm: "HMAC-SHA256",
        keyId: "manifest-test-v1",
        digest,
        value: manifestMac,
      },
    },
    sidecars: {
      [artifactPath]: {
        version: 1,
        algorithm: "HMAC-SHA256",
        keyId: "artifact-test-v1",
        artifact: artifactName,
        sha256: artifactSha256,
        signature: artifactMac,
      },
    },
    unsigned,
  };
}

function testCryptoSha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function testHmacBase64Url(key, value) {
  return crypto.createHmac("sha256", key).update(value).digest("base64url");
}

function testManifestDigest(document) {
  return testCryptoSha256(JSON.stringify(testCanonicalBackupValue(document)));
}

function testPrunePlanUnsignedValue(plan) {
  assert.equal(
    plan !== null
      && typeof plan === "object"
      && !Array.isArray(plan)
      && Object.getPrototypeOf(plan) === Object.prototype,
    true,
    "exact prune plan schema requires one plain object",
  );
  const expectedKeys = [
    "artifactCount",
    "artifactSetSha256",
    "candidatePaths",
    "planId",
    "schema",
    ...(Object.hasOwn(plan, "seal") ? ["seal"] : []),
  ].sort();
  assert.deepEqual(
    Reflect.ownKeys(plan).sort(),
    expectedKeys,
    "exact prune plan schema contains an unsupported field",
  );
  assert.equal(
    plan.schema,
    "platform.backup-prune-sealed-plan/v1",
    "exact prune plan schema identity changed",
  );
  return testCanonicalPrunePlanValue(
    Object.fromEntries(
      Object.entries(plan).filter(([key]) => key !== "seal"),
    ),
  );
}

function testPrunePlanDigest(plan) {
  const canonical = JSON.stringify(testPrunePlanUnsignedValue(plan));
  return testCryptoSha256(`${PRUNE_PLAN_DIGEST_DOMAIN}${canonical}`);
}

function testPrunePlanMac(plan, { keyId, key }, digest = testPrunePlanDigest(plan)) {
  return testHmacBase64Url(
    key,
    `${PRUNE_PLAN_MAC_DOMAIN}${keyId}\0${plan.planId}\0${digest}\0`,
  );
}

function testPrunePlanSeal(plan, key) {
  const digest = testPrunePlanDigest(plan);
  return {
    algorithm: "HMAC-SHA256",
    digest,
    keyId: key.keyId,
    value: testPrunePlanMac(plan, key, digest),
  };
}

function testCanonicalPrunePlanValue(value) {
  if (Array.isArray(value)) return value.map(testCanonicalPrunePlanValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, testCanonicalPrunePlanValue(value[key])]),
    );
  }
  return value;
}

function testCanonicalBackupValue(value) {
  if (Array.isArray(value)) return value.map(testCanonicalBackupValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .filter((key) => key !== "signature")
        .sort()
        .map((key) => [key, testCanonicalBackupValue(value[key])]),
    );
  }
  return value;
}

function reverseObjectKeyOrder(value) {
  if (Array.isArray(value)) return value.map(reverseObjectKeyOrder);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .reverse()
        .map((key) => [key, reverseObjectKeyOrder(value[key])]),
    );
  }
  return value;
}

function manifestVerificationOptions() {
  return {
    manifestKeys: { "manifest-test-v1": MANIFEST_TEST_KEY },
    artifactKeys: { "artifact-test-v1": ARTIFACT_TEST_KEY },
  };
}

function fixtureToolOutput(command, parameters) {
  const binding = {
    "backup-catalog": ["backup.catalog", "catalog.capture"],
    "backup-job": ["backup.job.execute", "job.backup.capture"],
    "backup-offsite-sync": ["backup.offsite.sync", "offsite.sync"],
    "backup-prune-apply": ["backup.prune.apply", "prune.apply"],
    "backup-prune-plan": ["backup.prune.plan", "prune.plan"],
    "restore-drill-full": ["restore.drill.full", "restore.verify"],
    "restore-job": ["backup.job.execute", "job.restore.verify"],
  }[command];
  assert.ok(binding, `test fixture has no fixed command binding for ${command}`);
  return buildFixturePhaseOutputV2(binding[0], binding[1], parameters);
}
