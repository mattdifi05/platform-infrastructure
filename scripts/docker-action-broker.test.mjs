import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import testRunner from "node:test";
import { inspect } from "node:util";

import {
  createBackupJobDocument,
  parseBackupJobDocument,
} from "../control-center/backup/contracts.mjs";
import * as broker from "./docker-action-broker.mjs";
import {
  EXPECTED_ACTION_PHASES,
  EXPECTED_PHASE_PROFILES,
  FIXTURE_NOW,
  SCHEDULER_ACTION_NAMES,
  buildFixtureActionResultV2,
  buildFixtureNetworkInspect,
  buildFixturePhaseOutputV2,
  buildFixtureSignedActionRequestV2,
  buildFixtureTrustedContextV2,
  buildFixtureVolumeInspect,
  buildRawActiveReceiptV2,
  canonicalFixtureJson,
  fixtureCapabilityKey,
  fixtureSha256,
} from "./docker-action-v2-fixtures.mjs";

const NOW = FIXTURE_NOW;
const SNAPSHOT_CONTAINER_PATH = "/run/platform/claimed-job/job.json";
const WORKER_ID = "2".repeat(64);
const RESTORE_WORKER_ID = "3".repeat(64);
const REQUEST_SCHEMA_V2 = "platform.docker-action.request/v2";
const RESULT_SCHEMA_V2 = "platform.docker-action.result/v2";
const WORKER_RESULT_SCHEMA_V2 = "platform.docker-worker.result/v2";
const LEASE_SCHEMA_V2 = "platform.docker-action.lease/v2";
const JOURNAL_ENTRY_SCHEMA_V2 = "platform.docker-action.lease-journal-entry/v2";
const BROKER_MODULE_URL = new URL("./docker-action-broker.mjs", import.meta.url).href;
let requestSequence = 1000;
const HAS_SEMANTIC_EXECUTOR = typeof broker.createSemanticActionExecutor === "function";
const HAS_CLAIMED_JOB_READER = typeof broker.readClaimedJobSnapshot === "function";
const HAS_SNAPSHOT_STORE = typeof broker.createSnapshotFileStore === "function";
const HAS_RESPONSE_ENCODER = typeof broker.encodeActionResponseFrame === "function";
const HAS_RAW_FRAME_E2E_APIS = HAS_SEMANTIC_EXECUTOR
  && HAS_CLAIMED_JOB_READER
  && HAS_SNAPSHOT_STORE
  && HAS_RESPONSE_ENCODER
  && ["PersistentReplayStore", "createBrokerCore"]
    .every((name) => typeof broker[name] === "function");

testRunner("RED v2: broker exports one already-admitted semantic executor API", () => {
  assert.equal(
    typeof broker.createSemanticActionExecutor,
    "function",
    "docker-action-broker must export createSemanticActionExecutor",
  );
  const executor = broker.createSemanticActionExecutor({
    snapshotFileStore: {},
    transport: {},
  });
  assert.equal(typeof executor?.execute, "function");
  assert.equal(typeof executor?.executePhase, "function");
  assert.equal(typeof executor?.recoverLease, "function");
});

function test(name, callback) {
  if (HAS_SEMANTIC_EXECUTOR) return testRunner(name, callback);
  return testRunner(
    name,
    { todo: "blocked only by the active createSemanticActionExecutor API RED" },
    () => {},
  );
}

testRunner("RED v2: broker exports the descriptor-stable claimed-job reader", () => {
  assert.equal(
    typeof broker.readClaimedJobSnapshot,
    "function",
    "docker-action-broker must export readClaimedJobSnapshot",
  );
});

function readerTest(name, callback) {
  if (HAS_CLAIMED_JOB_READER) return testRunner(name, callback);
  return testRunner(
    name,
    { todo: "blocked only by the active readClaimedJobSnapshot export RED" },
    () => {},
  );
}

testRunner("RED v2: broker exports the root-owned immutable snapshot file store", () => {
  assert.equal(
    typeof broker.createSnapshotFileStore,
    "function",
    "docker-action-broker must export createSnapshotFileStore",
  );
});

function snapshotTest(name, callback) {
  if (HAS_SNAPSHOT_STORE) return testRunner(name, callback);
  return testRunner(
    name,
    { todo: "blocked only by the active createSnapshotFileStore export RED" },
    () => {},
  );
}

testRunner("RED v2: broker exports the canonical response frame encoder independently", () => {
  assert.equal(
    typeof broker.encodeActionResponseFrame,
    "function",
    "docker-action-broker must export encodeActionResponseFrame without depending on semantic executor availability",
  );
});

testRunner(
  "RED v2: response encoder directly emits recursive canonical JSON and exactly one LF without a socket",
  () => {
    assert.equal(
      typeof broker.encodeActionResponseFrame,
      "function",
      "behavioral response-encoder RED requires the direct encoder export",
    );
    const result = {
      status: "completed",
      phases: [{
        status: "completed",
        phaseId: "catalog.capture",
        outputSha256: "3".repeat(64),
        outputSchema: "platform.docker-worker.catalog-capture-output/v2",
        output: {
          schema: "platform.docker-worker.catalog-capture-output/v2",
          catalog: {
            zeta: ["last", { zeta: 2, alpha: 1 }],
            alpha: { zeta: false, alpha: true },
          },
        },
      }],
      job: null,
      action: "backup.catalog",
      schema: RESULT_SCHEMA_V2,
    };
    const bodyWithoutMac = {
      statusCode: 200,
      status: "completed",
      schema: "platform.docker-action.response/v2",
      resultSha256: fixtureSha256(canonicalFixtureJson(result)),
      result,
      requestSha256: "2".repeat(64),
      requestId: "123e4567-e89b-42d3-a456-426614174091",
      errorCode: null,
      action: "backup.catalog",
    };
    const capabilityKey = fixtureCapabilityKey(bodyWithoutMac.action);
    const body = {
      ...bodyWithoutMac,
      mac: crypto
        .createHmac("sha256", capabilityKey)
        .update(`${bodyWithoutMac.schema}\0`)
        .update(canonicalFixtureJson(bodyWithoutMac))
        .digest("hex"),
    };
    const expected = Buffer.from(`${canonicalFixtureJson(body)}\n`);
    assert.notDeepEqual(
      Buffer.from(`${JSON.stringify(body)}\n`),
      expected,
      "response fixture no longer distinguishes recursive canonical encoding from JSON.stringify",
    );
    const encoded = broker.encodeActionResponseFrame(body);
    assert.equal(
      typeof encoded === "string" || Buffer.isBuffer(encoded),
      true,
      "response encoder returned an unbounded byte container",
    );
    const encodedBytes = Buffer.isBuffer(encoded)
      ? encoded
      : Buffer.from(encoded);

    assert.deepEqual(
      encodedBytes,
      expected,
      "encoder did not recursively canonicalize the complete response body",
    );
    assert.deepEqual(
      JSON.parse(encodedBytes.subarray(0, -1).toString("utf8")),
      body,
      "direct encoder changed the admitted response value",
    );
    assert.equal(encodedBytes.at(-1), 0x0a, "response frame lacks its terminal LF");
    assert.equal(
      encodedBytes.subarray(0, -1).includes(0x0a),
      false,
      "response frame contains an interior LF",
    );
    assert.equal(
      encodedBytes.includes(0x0d),
      false,
      "response frame widened LF framing to CRLF",
    );
  },
);

function rawFrameE2eTest(name, callback) {
  if (HAS_RAW_FRAME_E2E_APIS) return testRunner(name, callback);
  const missing = [
    ["PersistentReplayStore", typeof broker.PersistentReplayStore],
    ["createBrokerCore", typeof broker.createBrokerCore],
    ["createSemanticActionExecutor", typeof broker.createSemanticActionExecutor],
    ["createSnapshotFileStore", typeof broker.createSnapshotFileStore],
    ["encodeActionResponseFrame", typeof broker.encodeActionResponseFrame],
    ["readClaimedJobSnapshot", typeof broker.readClaimedJobSnapshot],
  ]
    .filter(([, type]) => type !== "function")
    .map(([name]) => name)
    .join(", ");
  return testRunner(
    name,
    { todo: `blocked by missing raw-frame E2E prerequisite API(s): ${missing}` },
    () => {},
  );
}

for (const reorderKind of ["top-level", "recursive-parameters"]) {
  testRunner(
    `RED v2: core rejects ${reorderKind} noncanonical signed wire before every provider`,
    async () => {
      const phase = findPhase("job.backup.capture");
      const { trusted } = buildFixtureTrustedContextV2({
        allowedActions: [phase.action],
        now: NOW,
      });
      const request = buildFixtureSignedActionRequestV2(
        phase.action,
        phase.parameters,
        {
          index: reorderKind === "top-level" ? 2591 : 2592,
          now: NOW,
          trustedContext: trusted,
        },
      );
      const frame = reorderKind === "top-level"
        ? Buffer.from(JSON.stringify(
          Object.fromEntries(Object.entries(request).reverse()),
        ))
        : Buffer.from(`{${
          Object.keys(request)
            .sort()
            .map((key) => `${JSON.stringify(key)}:${
              key === "parameters"
                ? JSON.stringify(Object.fromEntries(
                  Object.entries(request.parameters).reverse(),
                ))
                : canonicalFixtureJson(request[key])
            }`)
            .join(",")
        }}`);
      assert.deepEqual(JSON.parse(frame.toString("utf8")), request);
      assert.notDeepEqual(frame, Buffer.from(canonicalFixtureJson(request)));

      const calls = {
        capability: 0,
        engine: 0,
        replay: 0,
        trust: 0,
      };
      const replayStore = {
        acquire() {
          calls.replay += 1;
          return {
            lineage: {},
            preserve() {},
            release() {},
          };
        },
        admitActivation() {
          calls.replay += 1;
        },
        admitTrustedContext() {
          calls.replay += 1;
        },
        consume() {
          calls.replay += 1;
        },
      };
      const core = broker.createBrokerCore({
        capabilityProvider: async () => {
          calls.capability += 1;
          return fixtureCapabilityKey(request.action);
        },
        engine: {
          async execute() {
            calls.engine += 1;
            return {};
          },
        },
        now: () => NOW,
        operationTimeoutMs: 1_000,
        replayStore,
        trustedContextProvider: async () => {
          calls.trust += 1;
          return trusted;
        },
      });
      let failure;
      try {
        await core.handle(frame);
      } catch (error) {
        failure = error;
      }
      assert.deepEqual(
        calls,
        {
          capability: 0,
          engine: 0,
          replay: 0,
          trust: 0,
        },
        `${reorderKind} wire crossed a trust, capability, replay or Engine boundary`,
      );
      assert.match(
        failure?.message ?? "",
        /canonical|wire|encoding|frame/i,
        `${reorderKind} wire was not rejected as noncanonical`,
      );
    },
  );
}

testRunner(
  "RED v2: broker core rejects coherently signed action affixes as noncanonical identities",
  async (t) => {
    const phase = findPhase("job.backup.capture");
    const { trusted } = buildFixtureTrustedContextV2({
      allowedActions: [phase.action],
      now: NOW,
    });
    const canonicalRequest = buildFixtureSignedActionRequestV2(
      phase.action,
      phase.parameters,
      {
        index: 2593,
        now: NOW,
        trustedContext: trusted,
      },
    );
    const capabilityKey = fixtureCapabilityKey(phase.action);

    for (const hostileAction of [
      `${phase.action}.nested`,
      `nested.${phase.action}`,
      `${phase.action}-api`,
    ]) {
      await t.test(hostileAction, async () => {
        const unsigned = {
          ...Object.fromEntries(
            Object.entries(canonicalRequest).filter(([key]) => key !== "mac"),
          ),
          action: hostileAction,
        };
        const hostileRequest = {
          ...unsigned,
          mac: crypto
            .createHmac("sha256", capabilityKey)
            .update(`${REQUEST_SCHEMA_V2}\0`)
            .update(canonicalFixtureJson(unsigned))
            .digest("hex"),
        };
        const calls = {
          capability: 0,
          engine: 0,
          replay: 0,
          trust: 0,
        };
        const core = broker.createBrokerCore({
          capabilityProvider: async () => {
            calls.capability += 1;
            return capabilityKey;
          },
          engine: {
            async execute() {
              calls.engine += 1;
              return {};
            },
          },
          now: () => NOW,
          operationTimeoutMs: 1_000,
          replayStore: {
            acquire() {
              calls.replay += 1;
              throw new Error("unknown action acquired a lease");
            },
            admitActivation() {
              calls.replay += 1;
            },
            admitTrustedContext() {
              calls.replay += 1;
            },
            consume() {
              calls.replay += 1;
            },
          },
          trustedContextProvider: async () => {
            calls.trust += 1;
            return trusted;
          },
        });

        await assert.rejects(
          () => core.handle(Buffer.from(canonicalFixtureJson(hostileRequest))),
          /action|authorized|exact|identity/i,
          `${hostileAction} was treated as ${phase.action}`,
        );
        assert.equal(calls.capability, 0);
        assert.equal(calls.engine, 0);
        assert.equal(calls.replay, 0);
        assert.equal(
          calls.trust <= 1,
          true,
          "unknown action repeated the trusted-context lookup",
        );
      });
    }
  },
);

testRunner(
  "RED v2: default socketless broker traverses backup.job.execute through one root-owned snapshot store",
  async () => {
    const assemblySource = Function.prototype.toString.call(
      broker.createDockerActionBroker,
    );
    const assemblySignature = assemblySource.slice(
      0,
      assemblySource.indexOf("} = {})") + "} = {})".length,
    );
    for (const seam of [
      "claimedJobSnapshotProvider",
      "replayStore",
      "semanticExecutorOptions",
      "serverFactory",
      "snapshotFileStoreFactory",
      "transport",
    ]) {
      assert.match(
        assemblySignature,
        new RegExp(`\\b${seam}\\b`),
        `default broker assembly lacks the offline-observable ${seam} seam`,
      );
    }

    async function runAssembly({ injectSnapshotStore = false } = {}) {
      const phase = findPhase("job.backup.capture");
      const { trusted } = buildFixtureTrustedContextV2({
        allowedActions: [phase.action],
        now: NOW,
      });
      const request = buildFixtureSignedActionRequestV2(
        phase.action,
        phase.parameters,
        {
          index: injectSnapshotStore ? 2595 : 2594,
          now: NOW,
          trustedContext: trusted,
        },
      );
      const defaultStore = snapshotStoreFixture({});
      const injectedStore = snapshotStoreFixture({});
      const trace = {
        acceptConnection: null,
        connectionEnd: [],
        defaultStore,
        factoryOptions: [],
        injectedStore,
        providerCalls: 0,
        request,
        serverEvents: [],
        timeoutMs: [],
      };
      const transport = new OracleEngineTransport({
        phases: [phase],
        rawResults: [rawWorkerResult(phase, request.requestId)],
        request,
        requestId: request.requestId,
        trusted,
      });
      const replayStore = Object.freeze({
        acquire(candidateRequest, candidateTrusted) {
          assert.deepEqual(candidateRequest, request);
          return recordingLease(candidateRequest, candidateTrusted);
        },
        admitActivation() {},
        admitTrustedContext() {},
        consume() {},
        async recover() {
          throw new Error("socketless request harness must not invoke recovery");
        },
      });
      const serverFactory = (...args) => {
        assert.equal(args.length, 1, "serverFactory received ambient options");
        assert.equal(typeof args[0], "function");
        trace.acceptConnection = args[0];
        return {
          listening: false,
          on(event, listener) {
            assert.equal(typeof listener, "function");
            trace.serverEvents.push(event);
            return this;
          },
        };
      };
      const semanticExecutorOptions = Object.freeze({
        cleanupTimeoutMs: 100,
        randomBytes: () => Buffer.alloc(12, 0x31),
        ...(injectSnapshotStore
          ? { snapshotFileStore: injectedStore }
          : {}),
      });
      const semanticOptionsBefore = Reflect.ownKeys(semanticExecutorOptions);
      const server = broker.createDockerActionBroker({
        capabilityProvider: async (action) => {
          assert.equal(action, request.action);
          return fixtureCapabilityKey(action);
        },
        claimedJobSnapshotProvider: async ({ parameters, sourceId }) => {
          trace.providerCalls += 1;
          assert.equal(sourceId, "jobs.running");
          assert.deepEqual(parameters, request.parameters);
          return {
            ...phase.claimedJob,
            bytes: Buffer.from(phase.claimedJob.bytes),
            sourceId,
          };
        },
        now: () => NOW,
        operationTimeoutMs: 1_000,
        replayStore,
        semanticExecutorOptions,
        serverFactory,
        snapshotFileStoreFactory(options) {
          trace.factoryOptions.push(structuredClone(options));
          return defaultStore;
        },
        socketPath: "/in-memory/never-listened.sock",
        stateDir: "/in-memory/unused-state",
        transport,
        trustedContextProvider: async () => trusted,
      });
      assert.deepEqual(
        Reflect.ownKeys(semanticExecutorOptions),
        semanticOptionsBefore,
        "assembly mutated caller-owned semantic options",
      );
      assert.equal(server.listening, false);
      assert.equal(typeof trace.acceptConnection, "function");

      const connectionHandlers = new Map();
      const connection = {
        destroy() {
          assert.fail("socketless connection was destroyed");
        },
        end(frame) {
          assert.equal(
            typeof frame === "string" || Buffer.isBuffer(frame),
            true,
            "connection received an unbounded frame container",
          );
          trace.connectionEnd.push(Buffer.isBuffer(frame)
            ? Buffer.from(frame)
            : Buffer.from(frame, "utf8"));
          return this;
        },
        on(event, listener) {
          assert.equal(["data", "error"].includes(event), true);
          assert.equal(typeof listener, "function");
          connectionHandlers.set(event, listener);
          return this;
        },
        setTimeout(milliseconds, listener) {
          trace.timeoutMs.push(milliseconds);
          assert.equal(typeof listener, "function");
          connectionHandlers.set("timeout", listener);
          return this;
        },
      };
      trace.acceptConnection(connection);
      assert.deepEqual([...connectionHandlers.keys()].sort(), [
        "data",
        "error",
        "timeout",
      ]);
      await connectionHandlers.get("data")(
        Buffer.from(`${canonicalFixtureJson(request)}\n`),
      );
      assert.deepEqual(trace.timeoutMs, [5_000]);
      assert.equal(trace.connectionEnd.length, 1);
      const responseFrame = trace.connectionEnd[0];
      assert.equal(responseFrame.at(-1), 0x0a);
      assert.equal(responseFrame.subarray(0, -1).includes(0x0a), false);
      const response = JSON.parse(
        responseFrame.subarray(0, -1).toString("utf8"),
      );
      assert.equal(response.schema, "platform.docker-action.response/v2");
      assert.equal(response.status, "completed");
      assert.equal(response.action, request.action);
      assert.equal(response.requestId, request.requestId);
      assert.equal(
        response.requestSha256,
        fixtureSha256(canonicalFixtureJson(request)),
      );
      assert.deepEqual(
        responseFrame,
        Buffer.from(`${canonicalFixtureJson(response)}\n`),
      );
      return trace;
    }

    function assertDefaultRootTrace(trace) {
      assert.deepEqual(
        trace.factoryOptions,
        [{ expectedGid: 0, expectedUid: 0 }],
        "default root-owned store factory options were bypassed",
      );
      assert.equal(
        trace.defaultStore.calls.length,
        1,
        "default root-owned store did not receive exactly one seal",
      );
      assert.equal(
        trace.defaultStore.cleanupCalls.length,
        1,
        "default root-owned store did not receive exactly one cleanup",
      );
      assert.equal(
        trace.injectedStore.calls.length,
        0,
        "an injected store masqueraded as the default root-owned store",
      );
      assert.equal(trace.providerCalls, 1);
      const authority = trace.defaultStore.calls[0].authority;
      assert.deepEqual(
        authority.request,
        trace.request,
        "default seal did not receive the exact complete signed request",
      );
      assert.equal(
        authority.requestSha256,
        fixtureSha256(canonicalFixtureJson(authority.request)),
        "default seal lost the complete canonical signed-request digest",
      );
    }

    const defaultTrace = await runAssembly();
    assertDefaultRootTrace(defaultTrace);
    const injectedTrace = await runAssembly({ injectSnapshotStore: true });
    assert.equal(injectedTrace.factoryOptions.length, 0);
    assert.equal(injectedTrace.defaultStore.calls.length, 0);
    assert.equal(injectedTrace.injectedStore.calls.length, 1);
    assert.throws(
      () => assertDefaultRootTrace(injectedTrace),
      /default root-owned|masqueraded/,
      "default-store oracle admitted an explicitly injected-store mutant",
    );
  },
);

testRunner("broker security-oracle self-mutants reject every previously accepted bypass", async (t) => {
  await t.test("snapshot decoy fd plus pathname/reopen write", () => {
    const file = "/oracle/snapshot/job.json";
    const leafIdentity = {
      ctimeNs: "1000000001",
      dev: 1,
      gid: 0,
      ino: 2,
      isFile: true,
      mode: 0o100400,
      mtimeNs: "1000000000",
      nlink: 1,
      size: 4,
      uid: 0,
    };
    const finalLeafStat = {
      ...leafIdentity,
      isFile: () => true,
    };
    const oracleOptions = {
      expectedBytes: 4,
      file,
      finalDirectoryInventory: ["job.json"],
      finalLeafStat,
    };
    const safeFlags = fs.constants.O_WRONLY
      | fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW;
    const positive = [
      { type: "open", file, flags: safeFlags, mode: 0o400, descriptor: 10 },
      {
        type: "write",
        file,
        descriptor: 10,
        pathnameWrite: false,
        bytes: 4,
      },
      { type: "fsync", file, descriptor: 10, ...leafIdentity },
      { type: "close", file, descriptor: 10 },
    ];
    assert.doesNotThrow(() => assertSnapshotLeafSealHistory(positive, oracleOptions));
    const decoy = [
      positive[0],
      { type: "close", file, descriptor: 10 },
      { type: "open", file, flags: fs.constants.O_WRONLY, mode: 0o400, descriptor: 11 },
      {
        type: "write",
        file,
        descriptor: 11,
        pathnameWrite: true,
        bytes: 4,
      },
      { type: "fsync", file, descriptor: 11, ...leafIdentity },
      { type: "close", file, descriptor: 11 },
    ];
    assert.throws(
      () => assertSnapshotLeafSealHistory(decoy, oracleOptions),
      /exactly one|descriptor|pathname|reopen/i,
    );
  });

  await t.test("snapshot pre-fsync rename-to-orphan plus symlink-back", () => {
    const file = "/oracle/snapshot/job.json";
    const orphan = "/oracle/snapshot/orphan.json";
    const identity = {
      ctimeNs: "2000000001",
      dev: 1,
      gid: 0,
      ino: 3,
      isFile: true,
      mode: 0o100400,
      mtimeNs: "2000000000",
      nlink: 1,
      size: 4,
      uid: 0,
    };
    const safeFlags = fs.constants.O_WRONLY
      | fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW;
    const base = [
      { type: "open", file, flags: safeFlags, mode: 0o400, descriptor: 20 },
      {
        type: "write",
        file,
        descriptor: 20,
        pathnameWrite: false,
        bytes: 4,
      },
      { type: "fsync", file, descriptor: 20, ...identity },
      { type: "close", file, descriptor: 20 },
    ];
    const finalLeafStat = { ...identity, isFile: () => true };
    assert.doesNotThrow(() => assertSnapshotLeafSealHistory(base, {
      expectedBytes: 4,
      file,
      finalDirectoryInventory: ["job.json"],
      finalLeafStat,
    }));
    const substituted = [
      ...base.slice(0, 2),
      { type: "rename", from: file, to: orphan },
      { type: "symlink", target: orphan, to: file },
      ...base.slice(2),
    ];
    assert.throws(
      () => assertSnapshotLeafSealHistory(substituted, {
        expectedBytes: 4,
        file,
        finalDirectoryInventory: ["job.json", "orphan.json"],
        finalLeafStat,
      }),
      /between exclusive open and fsync|mutated|substituted/i,
    );
    const requestDirectory = path.dirname(file);
    const orphanDirectory = "/oracle/orphan-request";
    const parentSubstituted = [
      ...base.slice(0, 2),
      { type: "rename", from: requestDirectory, to: orphanDirectory },
      { type: "symlink", target: orphanDirectory, to: requestDirectory },
      ...base.slice(2),
    ];
    assert.throws(
      () => assertSnapshotLeafSealHistory(parentSubstituted, {
        expectedBytes: 4,
        file,
        finalDirectoryInventory: ["job.json"],
        finalLeafStat,
      }),
      /between exclusive open and fsync|mutated|substituted/i,
    );
    assert.throws(
      () => assertSnapshotLeafSealHistory(base, {
        expectedBytes: 4,
        file,
        finalDirectoryInventory: ["job.json", "orphan.json"],
        finalLeafStat,
      }),
      /orphan|inventory/i,
    );
  });

  await t.test("raw-fs ancestor substitutions cannot evade any pinned directory identity", () => {
    const cases = [
      {
        id: "mountpoint",
        label: "mutant Engine Mountpoint",
        select: ({ mountpoint }) => mountpoint,
      },
      {
        id: "claimed-jobs",
        label: "mutant claimed-jobs directory",
        select: ({ claimedJobs }) => claimedJobs,
      },
      {
        id: "request-directory",
        label: "mutant request snapshot directory",
        select: ({ requestDirectory }) => requestDirectory,
      },
    ];
    const run = (attackCase = null, mutationKind = "symlink-back") => {
      const root = fs.realpathSync(tempDir(t));
      const mountpoint = path.join(
        root,
        `mount-${attackCase?.id ?? "positive"}`,
      );
      const claimedJobs = path.join(mountpoint, "claimed-jobs");
      const requestDirectory = path.join(claimedJobs, "request");
      const leaf = path.join(requestDirectory, "job.json");
      const attackedPath = attackCase?.select({
        claimedJobs,
        mountpoint,
        requestDirectory,
      }) ?? null;
      const orphan = attackCase === null
        ? null
        : path.join(root, `external-orphan-${attackCase.id}`);
      let hookCount = 0;
      fs.mkdirSync(mountpoint, { mode: 0o700 });
      let attackResult = null;
      const { audit, io } = filesystemHistoryProbe({
        onEvent(event) {
          if (attackCase !== null
            && event.type === "fsync" && event.file === leaf) {
            hookCount += 1;
            if (attackResult !== null) return;
            attackResult = spawnSync(
              process.execPath,
              ["--input-type=module", "--eval", String.raw`
                import fs from "node:fs";
                import path from "node:path";
                if (process.env.MUTATION_KIND === "mtime-and-ctime-change") {
                  const exactTime = new Date("2000-01-01T00:00:00.000Z");
                  fs.utimesSync(process.env.ATTACKED_PATH, exactTime, exactTime);
                } else if (process.env.MUTATION_KIND === "ctime-change") {
                  fs.chmodSync(process.env.ATTACKED_PATH, 0o700);
                } else {
                  fs.renameSync(process.env.ATTACKED_PATH, process.env.ORPHAN);
                  if (process.env.MUTATION_KIND === "symlink-back") {
                    fs.symlinkSync(process.env.ORPHAN, process.env.ATTACKED_PATH);
                  } else {
                    const replacementLeaf = path.join(
                      process.env.ATTACKED_PATH,
                      process.env.RELATIVE_LEAF,
                    );
                    const orphanLeaf = path.join(
                      process.env.ORPHAN,
                      process.env.RELATIVE_LEAF,
                    );
                    fs.mkdirSync(path.dirname(replacementLeaf), {
                      mode: 0o700,
                      recursive: true,
                    });
                    fs.renameSync(orphanLeaf, replacementLeaf);
                    fs.copyFileSync(replacementLeaf, orphanLeaf, fs.constants.COPYFILE_EXCL);
                    fs.chmodSync(replacementLeaf, 0o400);
                    fs.chmodSync(orphanLeaf, 0o400);
                  }
                }
                process.stdout.write(JSON.stringify({
                  processId: process.pid,
                  realpath: fs.realpathSync(process.env.ATTACKED_PATH),
                  symlink: fs.lstatSync(process.env.ATTACKED_PATH).isSymbolicLink(),
                }));
              `],
              {
                encoding: "utf8",
                env: {
                  ...process.env,
                  ATTACKED_PATH: attackedPath,
                  MUTATION_KIND: mutationKind,
                  ORPHAN: orphan,
                  RELATIVE_LEAF: path.relative(attackedPath, leaf),
                },
                timeout: 15_000,
              },
            );
          }
        },
      });
      const flags = fs.constants.O_RDONLY
        | fs.constants.O_DIRECTORY
        | fs.constants.O_NOFOLLOW;
      const pin = (directory) => {
        const descriptor = io.openSync(directory, flags);
        io.fstatSync(descriptor, { bigint: true });
        return { descriptor, directory };
      };
      const pins = [pin(mountpoint)];
      io.mkdirSync(claimedJobs, { mode: 0o700 });
      io.fsyncSync(pins[0].descriptor);
      pins.push(pin(claimedJobs));
      io.mkdirSync(requestDirectory, { mode: 0o700 });
      io.fsyncSync(pins[1].descriptor);
      pins.push(pin(requestDirectory));
      const leafDescriptor = io.openSync(
        leaf,
        fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_NOFOLLOW,
        0o400,
      );
      io.writeFileSync(leafDescriptor, Buffer.from("sealed\n"));
      for (const { descriptor } of pins) {
        io.fstatSync(descriptor, { bigint: true });
      }
      io.fsyncSync(leafDescriptor);
      const leafFsyncIndex = audit.events.length - 1;
      io.closeSync(leafDescriptor);
      if (attackCase !== null) {
        assert.equal(hookCount, 1, `${attackCase.id} hook count is not exact`);
        assert.equal(
          attackResult?.status,
          0,
          `external ancestry mutant child failed: ${
            attackResult?.stderr || attackResult?.error?.message || ""
          }`,
        );
        const proof = JSON.parse(attackResult.stdout);
        assert.notEqual(proof.processId, process.pid);
        assert.equal(proof.symlink, mutationKind === "symlink-back");
        assert.equal(
          proof.realpath,
          mutationKind === "symlink-back" ? orphan : attackedPath,
        );
        assert.equal(
          fs.lstatSync(attackedPath).isSymbolicLink(),
          mutationKind === "symlink-back",
        );
        assert.equal(
          fs.realpathSync(attackedPath),
          mutationKind === "symlink-back" ? orphan : attackedPath,
        );
        if (
          mutationKind === "mtime-and-ctime-change"
          || mutationKind === "ctime-change"
        ) {
          assert.equal(fs.lstatSync(attackedPath).mode & 0o777, 0o700);
        } else if (mutationKind === "directory-replacement") {
          assert.equal(fs.lstatSync(attackedPath).mode & 0o777, 0o700);
        }
        assert.equal(
          audit.events.some(({ type }) => type === "rename" || type === "symlink"),
          false,
          "external-process ancestry mutant unexpectedly passed through injected io",
        );
      } else {
        assert.equal(hookCount, 0);
        assert.equal(attackResult, null);
      }
      io.fsyncSync(pins[2].descriptor);
      for (const { descriptor, directory } of pins) {
        io.fstatSync(descriptor, { bigint: true });
        io.lstatSync(directory, { bigint: true });
        io.realpathSync(directory);
        io.readdirSync(directory);
        io.closeSync(descriptor);
      }
      const options = {
        directories: [
          {
            directory: mountpoint,
            expectedInventory: ["claimed-jobs"],
            label: "mutant Engine Mountpoint",
          },
          {
            directory: claimedJobs,
            expectedInventory: ["request"],
            label: "mutant claimed-jobs directory",
          },
          {
            directory: requestDirectory,
            expectedInventory: ["job.json"],
            label: "mutant request snapshot directory",
          },
        ],
        historyEnd: audit.events.length,
        leaf,
        leafFsyncIndex,
      };
      return { events: audit.events, options };
    };
    const positive = run();
    assert.doesNotThrow(
      () => assertPinnedSnapshotAncestryHistory(positive.events, positive.options),
    );
    for (const [attackIndex, attackCase] of cases.entries()) {
      for (const mutationKind of [
        "symlink-back",
        "directory-replacement",
        "mtime-and-ctime-change",
        "ctime-change",
      ]) {
        const mutant = run(attackCase, mutationKind);
        if (
          mutationKind === "mtime-and-ctime-change"
          || mutationKind === "ctime-change"
        ) {
          const timestampField = mutationKind === "mtime-and-ctime-change"
            ? "mtimeNs"
            : "ctimeNs";
          const exactError =
            `${attackCase.label} pinned descriptor settled ${timestampField} changed`;
          let timestampEvents = mutant.events;
          if (mutationKind === "mtime-and-ctime-change") {
            timestampEvents = structuredClone(mutant.events);
            const attackedDirectory =
              mutant.options.directories[attackIndex].directory;
            const pin = timestampEvents.find(
              (event) => event.type === "open"
                && event.file === attackedDirectory,
            );
            const settled = timestampEvents
              .filter((event, index) => index < mutant.options.leafFsyncIndex
                && event.type === "fstat"
                && event.file === attackedDirectory
                && event.descriptor === pin.descriptor)
              .at(-1);
            const rawPost = timestampEvents.find(
              (event, index) => index > mutant.options.leafFsyncIndex
                && event.type === "fstat"
                && event.file === attackedDirectory
                && event.descriptor === pin.descriptor,
            );
            assert.notEqual(
              rawPost.ctimeNs,
              settled.ctimeNs,
              "raw mtime control did not co-change ctime before seam isolation",
            );
            let overrides = 0;
            for (const [index, event] of timestampEvents.entries()) {
              if (
                index > mutant.options.leafFsyncIndex
                && event.file === attackedDirectory
                && (event.type === "fstat" || event.type === "lstat")
              ) {
                event.ctimeNs = settled.ctimeNs;
                overrides += 1;
              }
            }
            assert.equal(overrides, 2, "mtime-only trace seam is not exact");
          }
          assert.throws(
            () => assertSettledPinnedDirectoryTimestampStable(
              timestampEvents,
              mutant.options,
              attackIndex,
              timestampField,
            ),
            (error) => error?.message?.split("\n", 1)[0] === exactError,
          );
        } else {
          assert.throws(
            () => assertPinnedSnapshotAncestryHistory(mutant.events, mutant.options),
            new RegExp(
              `${attackCase.label} pathname no longer resolves to the pinned directory`,
              "i",
            ),
          );
        }
      }
    }

    const root = fs.realpathSync(tempDir(t));
    const authorityParent = path.join(root, "authority");
    const orphanAuthorityParent = path.join(root, "authority-orphan");
    const mountpoint = path.join(authorityParent, "broker-state");
    const claimedJobs = path.join(mountpoint, "claimed-jobs");
    const requestDirectory = path.join(claimedJobs, "request");
    const leaf = path.join(requestDirectory, "job.json");
    fs.mkdirSync(authorityParent, { mode: 0o700 });
    fs.mkdirSync(mountpoint, { mode: 0o700 });
    let attackResult = null;
    let hookCount = 0;
    const { audit, io } = filesystemHistoryProbe({
      onEvent(event) {
        if (event.type !== "fsync" || event.file !== leaf) return;
        hookCount += 1;
        if (attackResult !== null) return;
        attackResult = spawnSync(
          process.execPath,
          ["--input-type=module", "--eval", String.raw`
            import fs from "node:fs";
            fs.renameSync(
              process.env.AUTHORITY_PARENT,
              process.env.ORPHAN_AUTHORITY_PARENT,
            );
            fs.symlinkSync(
              process.env.ORPHAN_AUTHORITY_PARENT,
              process.env.AUTHORITY_PARENT,
            );
            const mountIdentity = fs.lstatSync(
              process.env.MOUNTPOINT,
              { bigint: true },
            );
            process.stdout.write(JSON.stringify({
              authorityIsSymlink: fs.lstatSync(
                process.env.AUTHORITY_PARENT,
              ).isSymbolicLink(),
              mountDev: String(mountIdentity.dev),
              mountDirectory: mountIdentity.isDirectory(),
              mountIno: String(mountIdentity.ino),
              processId: process.pid,
              realpath: fs.realpathSync(process.env.MOUNTPOINT),
            }));
          `],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              AUTHORITY_PARENT: authorityParent,
              MOUNTPOINT: mountpoint,
              ORPHAN_AUTHORITY_PARENT: orphanAuthorityParent,
            },
            timeout: 15_000,
          },
        );
      },
    });
    const flags = fs.constants.O_RDONLY
      | fs.constants.O_DIRECTORY
      | fs.constants.O_NOFOLLOW;
    const pin = (directory) => {
      const descriptor = io.openSync(directory, flags);
      io.fstatSync(descriptor, { bigint: true });
      return { descriptor, directory };
    };
    const pins = [pin(mountpoint)];
    io.mkdirSync(claimedJobs, { mode: 0o700 });
    io.fsyncSync(pins[0].descriptor);
    pins.push(pin(claimedJobs));
    io.mkdirSync(requestDirectory, { mode: 0o700 });
    io.fsyncSync(pins[1].descriptor);
    pins.push(pin(requestDirectory));
    const leafDescriptor = io.openSync(
      leaf,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o400,
    );
    io.writeFileSync(leafDescriptor, Buffer.from("sealed\n"));
    for (const { descriptor } of pins) {
      io.fstatSync(descriptor, { bigint: true });
    }
    io.fsyncSync(leafDescriptor);
    const leafFsyncIndex = audit.events.length - 1;
    io.closeSync(leafDescriptor);
    assert.equal(hookCount, 1);
    assert.equal(
      attackResult?.status,
      0,
      `ancestor-above-mount mutant failed: ${
        attackResult?.stderr || attackResult?.error?.message || ""
      }`,
    );
    const attackProof = JSON.parse(attackResult.stdout);
    assert.equal(Number.isInteger(attackProof.processId), true);
    assert.ok(attackProof.processId > 0);
    assert.notEqual(attackProof.processId, process.pid);
    assert.equal(attackProof.authorityIsSymlink, true);
    assert.equal(attackProof.mountDirectory, true);
    assert.match(attackProof.mountDev, /^\d+$/);
    assert.match(attackProof.mountIno, /^\d+$/);
    assert.equal(
      attackProof.realpath,
      path.join(orphanAuthorityParent, "broker-state"),
    );
    io.fsyncSync(pins[2].descriptor);
    for (const { descriptor, directory } of pins) {
      io.fstatSync(descriptor, { bigint: true });
      io.lstatSync(directory, { bigint: true });
      io.realpathSync(directory);
      io.readdirSync(directory);
      io.closeSync(descriptor);
    }
    assert.equal(audit.descriptors.size, 0);
    assert.equal(
      audit.events.some(({ type }) => type === "rename" || type === "symlink"),
      false,
      "external ancestor mutant unexpectedly passed through injected io",
    );
    const mountOpen = audit.events.find(
      (event) => event.type === "open" && event.file === mountpoint,
    );
    const mountSettled = audit.events
      .filter((event) => event.type === "fstat"
        && event.file === mountpoint
        && event.descriptor === mountOpen.descriptor)
      .at(-2);
    const mountPost = audit.events
      .filter((event) => event.type === "fstat"
        && event.file === mountpoint
        && event.descriptor === mountOpen.descriptor)
      .at(-1);
    const mountPath = audit.events.findLast(
      (event) => event.type === "lstat" && event.file === mountpoint,
    );
    assert.deepEqual(
      {
        dev: mountPost.dev,
        ino: mountPost.ino,
        mtimeNs: mountPost.mtimeNs,
      },
      {
        dev: mountSettled.dev,
        ino: mountSettled.ino,
        mtimeNs: mountSettled.mtimeNs,
      },
      "ancestor-above-mount mutant altered the pinned mountpoint",
    );
    assert.deepEqual(
      {
        dev: mountPath.dev,
        ino: mountPath.ino,
        mtimeNs: mountPath.mtimeNs,
      },
      {
        dev: mountPost.dev,
        ino: mountPost.ino,
        mtimeNs: mountPost.mtimeNs,
      },
      "ancestor-above-mount mutant altered the mountpoint pathname identity",
    );
    assert.throws(
      () => assertPinnedSnapshotAncestryHistory(audit.events, {
        directories: [
          {
            directory: mountpoint,
            expectedInventory: ["claimed-jobs"],
            label: "mutant Engine Mountpoint",
          },
          {
            directory: claimedJobs,
            expectedInventory: ["request"],
            label: "mutant claimed-jobs directory",
          },
          {
            directory: requestDirectory,
            expectedInventory: ["job.json"],
            label: "mutant request snapshot directory",
          },
        ],
        leaf,
        leafFsyncIndex,
      }),
      (error) => error?.message?.split("\n", 1)[0]
        === "mutant Engine Mountpoint post-fsync realpath escaped its exact authority path",
    );
  });

  await t.test("journal and lease-head temp reject pre-fsync pathname substitution", () => {
    for (const [label, file, descriptor] of [
      ["journal entry", "/oracle/journal/0000000000000000.json", 30],
      ["lease head temp", "/oracle/replay/active.lock.tmp", 31],
    ]) {
      const orphan = `${file}.orphan`;
      const positive = [
        { type: "open", file, descriptor },
        {
          type: "write",
          file,
          descriptor,
          pathnameWrite: false,
          bytes: 4,
        },
        { type: "fsync", file, descriptor },
      ];
      assert.doesNotThrow(() => assertOnlyDescriptorWritesBeforeFsync(positive, {
        descriptor,
        file,
        fsyncIndex: 2,
        label,
        openIndex: 0,
      }));
      const substituted = [
        ...positive.slice(0, 2),
        { type: "rename", from: file, to: orphan },
        { type: "symlink", target: orphan, to: file },
        positive[2],
      ];
      assert.throws(
        () => assertOnlyDescriptorWritesBeforeFsync(substituted, {
          descriptor,
          file,
          fsyncIndex: 4,
          label,
          openIndex: 0,
        }),
        /between exclusive open and fsync|mutated|substituted/i,
      );
    }
  });

  await t.test("journal consumer reaches both entry and lease-head mutation windows", () => {
    const root = tempDir(t);
    const leaseId = "a".repeat(64);
    const directory = path.join(root, "journal", leaseId);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const file = path.join(directory, "0000000000000000.json");
    const entryBytes = Buffer.from("journal\n");
    fs.writeFileSync(file, entryBytes, { mode: 0o400 });
    fs.chmodSync(file, 0o400);
    const activePath = path.join(root, "active.lock");
    const activeBytes = Buffer.from(`${JSON.stringify({
      journalEntryCount: 1,
      schema: LEASE_SCHEMA_V2,
    })}\n`);
    fs.writeFileSync(activePath, activeBytes, { mode: 0o400 });
    fs.chmodSync(activePath, 0o400);
    const entryIdentity = filesystemStatIdentity(
      fs.lstatSync(file, { bigint: true }),
    );
    const headIdentity = filesystemStatIdentity(
      fs.lstatSync(activePath, { bigint: true }),
    );
    const flags = fs.constants.O_WRONLY
      | fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW;
    const headTemp = path.join(root, "active.lock.self-mutant.tmp");
    const positive = [
      {
        type: "open",
        file,
        flags,
        mode: 0o400,
        descriptor: 40,
        mutatesPath: true,
      },
      {
        type: "write",
        file,
        descriptor: 40,
        pathnameWrite: false,
        bytes: entryBytes.length,
      },
      { type: "fsync", file, descriptor: 40, ...entryIdentity },
      { type: "close", file, descriptor: 40 },
      { type: "fsync", file: directory, descriptor: 41 },
      {
        type: "open",
        file: headTemp,
        flags,
        mode: 0o400,
        descriptor: 42,
        mutatesPath: true,
      },
      {
        type: "write",
        file: headTemp,
        descriptor: 42,
        pathnameWrite: false,
        bytes: activeBytes.length,
      },
      { type: "fsync", file: headTemp, descriptor: 42, ...headIdentity },
      { type: "close", file: headTemp, descriptor: 42 },
      {
        type: "rename",
        from: headTemp,
        to: activePath,
        sourceIdentity: headIdentity,
        sourceSize: headIdentity.size,
        destinationIdentity: headIdentity,
      },
      { type: "fsync", file: root, descriptor: 43 },
    ];
    assert.doesNotThrow(() => assertJournalAppendFsyncOrder(
      root,
      directory,
      [file],
      { events: positive },
      "positive journal consumer",
    ));
    const entrySubstituted = [
      ...positive.slice(0, 2),
      { type: "rename", from: file, to: `${file}.orphan` },
      { type: "symlink", target: `${file}.orphan`, to: file },
      ...positive.slice(2),
    ];
    assert.throws(
      () => assertJournalAppendFsyncOrder(
        root,
        directory,
        [file],
        { events: entrySubstituted },
        "mutant journal entry consumer",
      ),
      /between exclusive open and fsync|mutated|substituted/i,
    );
    const headFsyncIndex = positive.findIndex(
      (event) => event.type === "fsync" && event.file === headTemp,
    );
    const headSubstituted = [
      ...positive.slice(0, headFsyncIndex),
      { type: "rename", from: headTemp, to: `${headTemp}.orphan` },
      { type: "symlink", target: `${headTemp}.orphan`, to: headTemp },
      ...positive.slice(headFsyncIndex),
    ];
    assert.throws(
      () => assertJournalAppendFsyncOrder(
        root,
        directory,
        [file],
        { events: headSubstituted },
        "mutant lease-head consumer",
      ),
      /between exclusive open and fsync|mutated|substituted/i,
    );
  });

  await t.test("filesystem probe fails closed for every uninstrumented write family", async () => {
    const root = tempDir(t);
    const file = path.join(root, "protected.json");
    const original = Buffer.from("sealed\n");
    fs.writeFileSync(file, original, { mode: 0o400 });
    const { audit, io } = filesystemHistoryProbe();
    assert.throws(
      () => io.appendFileSync(file, "attacker"),
      /refuses uninstrumented mutating fs API.*appendFileSync/i,
    );
    const descriptor = fs.openSync(file, fs.constants.O_RDONLY);
    try {
      assert.throws(
        () => io.writevSync(descriptor, [Buffer.from("attacker")]),
        /refuses uninstrumented mutating fs API.*writevSync/i,
      );
    } finally {
      fs.closeSync(descriptor);
    }
    assert.throws(
      () => io.createWriteStream(file),
      /refuses uninstrumented mutating fs API.*createWriteStream/i,
    );
    assert.throws(
      () => io.writeFile(file, "attacker", () => {}),
      /refuses uninstrumented mutating fs API.*writeFile/i,
    );
    await assert.rejects(
      () => io.promises.writeFile(file, "attacker"),
      /refuses uninstrumented mutating fs API.*promises\.writeFile/i,
    );
    await assert.rejects(
      () => io.promises.open(file, "w"),
      /refuses uninstrumented mutating fs API.*promises\.open/i,
    );
    assert.deepEqual(fs.readFileSync(file), original);
    assert.deepEqual(audit.events, []);
  });

  await t.test("filesystem probe audits sync, callback and promise read-only authority", async () => {
    const root = tempDir(t);
    const file = path.join(root, "read-only.json");
    fs.writeFileSync(file, "sealed\n", { mode: 0o400 });
    const { audit, io } = filesystemHistoryProbe();
    assert.equal(io.existsSync(file), true);
    await new Promise((resolve, reject) => {
      io.readFile(file, (error, bytes) => {
        if (error) {
          reject(error);
          return;
        }
        try {
          assert.deepEqual(bytes, Buffer.from("sealed\n"));
          resolve();
        } catch (assertionError) {
          reject(assertionError);
        }
      });
    });
    assert.deepEqual(await io.promises.readFile(file), Buffer.from("sealed\n"));
    assert.deepEqual(
      audit.events.map(({ api, file: observedFile, type }) => ({
        api,
        file: observedFile,
        type,
      })),
      [
        { api: "fs.existsSync", file, type: "read-only" },
        { api: "fs.readFile", file, type: "read-only" },
        { api: "fs.promises.readFile", file, type: "read-only" },
      ],
      "every read-only surface must enter the same audit transcript",
    );
  });

  await t.test("raw-fs same-fd same-size post-fsync rewrites fail on nanosecond identity", () => {
    const rewriteSameBytes = (event) => {
      const before = { ctimeNs: event.ctimeNs, mtimeNs: event.mtimeNs };
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
      const bytes = fs.readFileSync(event.file);
      assert.equal(
        fs.writeSync(event.descriptor, bytes, 0, bytes.length, 0),
        bytes.length,
      );
      fs.fsyncSync(event.descriptor);
      const after = filesystemStatIdentity(
        fs.fstatSync(event.descriptor, { bigint: true }),
      );
      assert.equal(
        after.ctimeNs !== before.ctimeNs || after.mtimeNs !== before.mtimeNs,
        true,
        "raw-fs rewrite fixture did not change nanosecond identity",
      );
    };

    {
      const root = fs.realpathSync(tempDir(t));
      const requestDirectory = path.join(root, "snapshot-request");
      const file = path.join(requestDirectory, "job.json");
      fs.mkdirSync(requestDirectory, { mode: 0o700 });
      let mutated = false;
      const { audit, io } = filesystemHistoryProbe({
        onEvent(event) {
          if (!mutated && event.type === "fsync" && event.file === file) {
            mutated = true;
            rewriteSameBytes(event);
          }
        },
      });
      const bytes = Buffer.from("sealed-snapshot\n");
      const descriptor = io.openSync(
        file,
        fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_NOFOLLOW,
        0o400,
      );
      io.writeFileSync(descriptor, bytes);
      io.fsyncSync(descriptor);
      io.closeSync(descriptor);
      assert.equal(mutated, true);
      assert.deepEqual(fs.readFileSync(file), bytes);
      assert.throws(
        () => assertSnapshotLeafSealHistory(audit.events, {
          expectedBytes: bytes.length,
          file,
        }),
        /snapshot leaf final path identity differs from the descriptor fsynced inode/i,
      );
    }

    const journalRun = (rewriteTarget) => {
      const root = fs.realpathSync(tempDir(t));
      const leaseId = "b".repeat(64);
      const directory = path.join(root, "journal", leaseId);
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      const file = path.join(directory, "0000000000000000.json");
      const activePath = path.join(root, "active.lock");
      const headFile = path.join(root, "active.lock.nanosecond.tmp");
      const entryBytes = Buffer.from("journal-entry\n");
      const headBytes = Buffer.from(`${JSON.stringify({
        journalEntryCount: 1,
        schema: LEASE_SCHEMA_V2,
      })}\n`);
      let mutated = false;
      const { audit, io } = filesystemHistoryProbe({
        onEvent(event) {
          if (!mutated && event.type === "fsync" && (
            (rewriteTarget === "journal" && event.file === file)
            || (rewriteTarget === "head" && event.file === headFile)
          )) {
            mutated = true;
            rewriteSameBytes(event);
          }
        },
      });
      const safeFlags = fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW;
      const entryDescriptor = io.openSync(file, safeFlags, 0o400);
      io.writeFileSync(entryDescriptor, entryBytes);
      io.fsyncSync(entryDescriptor);
      io.closeSync(entryDescriptor);
      const journalDirectoryDescriptor = io.openSync(
        directory,
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
      );
      io.fsyncSync(journalDirectoryDescriptor);
      io.closeSync(journalDirectoryDescriptor);
      const headDescriptor = io.openSync(headFile, safeFlags, 0o400);
      io.writeFileSync(headDescriptor, headBytes);
      io.fsyncSync(headDescriptor);
      io.closeSync(headDescriptor);
      io.renameSync(headFile, activePath);
      const rootDescriptor = io.openSync(
        root,
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
      );
      io.fsyncSync(rootDescriptor);
      io.closeSync(rootDescriptor);
      assert.deepEqual(fs.readFileSync(file), entryBytes);
      assert.deepEqual(fs.readFileSync(activePath), headBytes);
      return {
        assertHistory: () => assertJournalAppendFsyncOrder(
          root,
          directory,
          [file],
          audit,
          `${rewriteTarget ?? "positive"} nanosecond journal`,
        ),
        mutated,
      };
    };
    const positive = journalRun(null);
    assert.equal(positive.mutated, false);
    assert.doesNotThrow(positive.assertHistory);
    for (const [target, expectedFailure] of [
      [
        "journal",
        /journal nanosecond journal journal entry final path identity differs/i,
      ],
      [
        "head",
        /head nanosecond journal lease head temp before rename final path identity differs/i,
      ],
    ]) {
      const mutant = journalRun(target);
      assert.equal(mutant.mutated, true);
      assert.throws(mutant.assertHistory, expectedFailure);
    }
  });

  await t.test("claimed reader third incomplete pass", () => {
    const completed = [
      { descriptor: 12, initialPosition: 0, pass: 0 },
      { descriptor: 12, initialPosition: 0, pass: 1 },
    ];
    assert.doesNotThrow(() => assertExactlyTwoDescriptorReadPasses({
      completedReadPasses: completed,
      startedReadPasses: structuredClone(completed),
    }));
    assert.throws(
      () => assertExactlyTwoDescriptorReadPasses({
        completedReadPasses: completed,
        startedReadPasses: [
          ...structuredClone(completed),
          { descriptor: 12, initialPosition: 0, pass: 2 },
        ],
      }),
      /start exactly two|incomplete|substituted/i,
    );
  });

  await t.test("journal post-fsync rewrite", () => {
    const file = "/oracle/journal/0001.json";
    const positive = [{ type: "fsync", file }, { type: "close", file }];
    assert.doesNotThrow(
      () => assertPathImmutableAfter(positive, file, 0, positive.length, "positive"),
    );
    const rewritten = [
      ...positive,
      {
        type: "write",
        file,
        descriptor: 14,
        pathnameWrite: false,
        bytes: 1,
      },
    ];
    assert.throws(
      () => assertPathImmutableAfter(rewritten, file, 0, rewritten.length, "mutant"),
      /mutated.*durability/i,
    );
  });

  await t.test("journal extra attacker field", () => {
    const base = {
      action: "backup.prune.apply",
      event: "action-completed",
      leaseId: "a".repeat(64),
      previousEntrySha256: "0".repeat(64),
      recordedAt: new Date(NOW).toISOString(),
      requestId: "123e4567-e89b-42d3-a456-426614174000",
      requestSha256: "1".repeat(64),
      resultSha256: "2".repeat(64),
      schema: JOURNAL_ENTRY_SCHEMA_V2,
      sequence: 0,
    };
    assert.doesNotThrow(() => assertExactJournalEventKeys(
      base,
      { requestSha256: base.requestSha256, resultSha256: base.resultSha256 },
      "positive",
    ));
    assert.throws(
      () => assertExactJournalEventKeys(
        { ...base, attackerHostPath: "/host/secret" },
        { requestSha256: base.requestSha256, resultSha256: base.resultSha256 },
        "mutant",
      ),
      /exact canonical fields/i,
    );
  });

  await t.test("lease unlink before durable head root-fsync", () => {
    const activePath = "/oracle/replay/active.lock";
    const root = path.dirname(activePath);
    const positive = [
      { type: "rename", from: `${activePath}.tmp`, to: activePath },
      { type: "fsync", file: root },
      { type: "unlink", file: activePath },
      { type: "fsync", file: root },
    ];
    assert.doesNotThrow(() => assertActiveUnlinkFsyncOrder(
      positive,
      activePath,
      1,
      "positive",
    ));
    const earlyUnlink = [
      { type: "rename", from: `${activePath}.tmp`, to: activePath },
      { type: "unlink", file: activePath },
      { type: "fsync", file: root },
    ];
    assert.throws(
      () => assertActiveUnlinkFsyncOrder(
        earlyUnlink,
        activePath,
        2,
        "mutant",
      ),
      /after.*durable head|before.*head/i,
    );
  });

  await t.test("recovery early delete before second inspect", () => {
    const expectedInspects = ["worker-second", "worker-first"];
    const expectedDeletes = [RESTORE_WORKER_ID, WORKER_ID];
    const positive = [
      { method: "inspectContainerForRecovery", name: "worker-second" },
      { method: "inspectContainerForRecovery", name: "worker-first" },
      { method: "deleteContainer", id: RESTORE_WORKER_ID },
      { method: "deleteContainer", id: WORKER_ID },
    ];
    assert.doesNotThrow(() => assertInspectAllBeforeDeleteAll(
      positive,
      expectedInspects,
      expectedDeletes,
      "positive",
    ));
    const earlyDelete = [
      positive[0],
      positive[2],
      positive[1],
      positive[3],
    ];
    assert.throws(
      () => assertInspectAllBeforeDeleteAll(
        earlyDelete,
        expectedInspects,
        expectedDeletes,
        "mutant",
      ),
      /entire.*before deletion/i,
    );
  });

  await t.test("preserved lock overwrite", () => {
    const root = "/oracle/replay";
    assert.doesNotThrow(() => assertNoStateMutationEvents([
      {
        type: "open",
        file: path.join(root, "active.lock"),
        flags: fs.constants.O_RDONLY,
      },
    ], root, "positive"));
    assert.throws(
      () => assertNoStateMutationEvents([{
        type: "write",
        file: path.join(root, "active.lock"),
        descriptor: 15,
        pathnameWrite: false,
        bytes: 128,
      }], root, "mutant"),
      /mutated.*replay tree/i,
    );
  });

  await t.test("timestamp facade kills coarse, Date and reflective raw-target survivors", () => {
    const rawStat = {
      atime: new Date(9009),
      atimeMs: 9009n,
      atimeNs: 9_009_999_999n,
      ctime: new Date(8008),
      ctimeMs: 8008n,
      ctimeNs: 8_008_999_999n,
      dev: 1n,
      ino: 2n,
      isDirectory: () => true,
      mode: 0o40700n,
      mtime: new Date(7007),
      mtimeMs: 7007n,
      mtimeNs: 7_007_999_999n,
    };
    const settled = Object.freeze({
      atime: new Date(1001),
      atimeMs: 1001n,
      atimeNs: 1_001_000_001n,
      ctime: new Date(2002),
      ctimeMs: 2002n,
      ctimeNs: 2_002_000_001n,
      mtime: new Date(3003),
      mtimeMs: 3003n,
      mtimeNs: 3_003_000_001n,
    });
    const mtimeOnly = createTimestampIdentityFacade(rawStat, {
      mutationKind: "mtime-and-ctime-change",
      settled,
    });
    assert.equal(mtimeOnly.facade.mtimeNs, rawStat.mtimeNs);
    assert.equal(mtimeOnly.facade.mtimeMs, settled.mtimeMs);
    assert.equal(mtimeOnly.facade.mtime.getTime(), settled.mtime.getTime());
    assert.equal(mtimeOnly.facade.ctimeNs, settled.ctimeNs);
    assert.equal(mtimeOnly.facade.atimeNs, settled.atimeNs);
    assert.equal(
      mtimeOnly.facade.mtimeMs !== settled.mtimeMs,
      false,
      "coarse-only mtime mutant still observes a change",
    );
    assert.equal(
      mtimeOnly.facade.mtime.getTime() !== settled.mtime.getTime(),
      false,
      "Date-only mtime mutant still observes a change",
    );
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(mtimeOnly.reads).filter(([, count]) => count > 0),
      ),
      {
        atimeNs: 1,
        ctimeNs: 1,
        mtime: 2,
        mtimeMs: 2,
        mtimeNs: 1,
      },
      "timestamp facade did not track the exact aliases consumed by the oracle",
    );
    const reflected = inspect(mtimeOnly.facade, {
      getters: true,
      showHidden: true,
      showProxy: true,
    });
    assert.doesNotMatch(
      reflected,
      /9009999999|8008999999|7007n/,
      "reflection exposed a masked raw timestamp alias",
    );
    assert.doesNotMatch(
      reflected,
      /^Proxy\s*\[/,
      "timestamp facade retained an inspectable Proxy target",
    );

    const ctimeOnly = createTimestampIdentityFacade(rawStat, {
      mutationKind: "ctime-change",
      settled,
    });
    assert.equal(ctimeOnly.facade.ctimeNs, rawStat.ctimeNs);
    assert.equal(ctimeOnly.facade.ctimeMs, settled.ctimeMs);
    assert.equal(ctimeOnly.facade.ctime.getTime(), settled.ctime.getTime());
    assert.equal(ctimeOnly.facade.mtimeNs, rawStat.mtimeNs);
  });
});

const BACKUP_JOB_ID = "0123456789abcdef";
const RESTORE_JOB_ID = "job-0123456789abcdef";
const JOB_CREATED_AT = "2026-07-28T11:59:00.000Z";

const BACKUP_JOB_DOCUMENT = claimedJobDocument({
  id: BACKUP_JOB_ID,
  operation: "backup",
});
const RESTORE_JOB_DOCUMENT = claimedJobDocument({
  id: RESTORE_JOB_ID,
  operation: "restore-drill",
  sourceManifestPath: "manifests/restore-source.json",
});
const BACKUP_JOB_BYTES = Buffer.from(`${JSON.stringify(BACKUP_JOB_DOCUMENT, null, 2)}\n`);
const RESTORE_JOB_BYTES = Buffer.from(`${JSON.stringify(RESTORE_JOB_DOCUMENT, null, 2)}\n`);

const PHASE_CASES = Object.freeze([
  phaseCase("backup.catalog", "catalog.capture"),
  phaseCase("backup.job.execute", "job.backup.capture", claimedJob({
    bytes: BACKUP_JOB_BYTES,
    jobFileName: `${BACKUP_JOB_ID}.json`,
    jobId: BACKUP_JOB_ID,
    jobOperation: "backup",
  })),
  phaseCase("backup.job.execute", "job.restore.verify", claimedJob({
    bytes: RESTORE_JOB_BYTES,
    jobFileName: `${RESTORE_JOB_ID}.json`,
    jobId: RESTORE_JOB_ID,
    jobOperation: "restore-drill",
  })),
  phaseCase("backup.prune.plan", "prune.plan"),
  phaseCase("backup.prune.apply", "prune.apply"),
  phaseCase("restore.drill.full", "restore.capture"),
  phaseCase("restore.drill.full", "restore.verify"),
  phaseCase("backup.offsite.sync", "offsite.sync"),
]);

assert.deepEqual(
  PHASE_CASES.map(({ phaseId }) => phaseId).sort(),
  Object.keys(EXPECTED_PHASE_PROFILES).sort(),
  "the broker RED must register every canonical phase exactly once",
);

/*
 * This is intentionally an already-admitted semantic seam. Admission/MAC tests
 * live in docker-action-contract.test.mjs and docker-action-broker.boundary.test.mjs.
 * Reaching Docker policy, worker inspection, journaling and recovery must not
 * depend on the legacy ACTIONS[action].modeled switch.
 */
for (const phase of PHASE_CASES) {
  test(`v2 admitted executor reaches the exact ${phase.phaseId} Engine boundary`, async (t) => {
    const fixture = semanticFixture(t, phase);
    const result = await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);

    assert.deepEqual(result, expectedActionResult(phase, fixture.rawResult));
    assert.equal(fixture.transport.startedIds.length, 1);
    assert.equal(fixture.transport.deletedIds.length, 1);
    assert.equal(fixture.transport.created.length, 1);
    assert.deepEqual(fixture.context.request, fixture.request);
    assert.equal(fixture.context.requestSha256, fixture.requestSha256);
    assert.deepEqual(fixture.context.lease.lineage.request, fixture.request);
    assert.equal(fixture.context.lease.lineage.requestSha256, fixture.requestSha256);
    assertExactBody(
      fixture.transport.created[0].body,
      phase,
      fixture.trusted,
      fixture.sealedSnapshot,
      fixture.context.requestId,
    );
    assertPreflightBeforeCreate(fixture.transport, phase, fixture.trusted.receipt);
    if (phase.claimedJob) {
      assert.equal(fixture.providerCalls(), 1, `${phase.phaseId} must stable-read exactly once`);
      assert.equal(fixture.snapshotStore.calls.length, 1, `${phase.phaseId} must seal exactly once`);
    } else {
      assert.equal(fixture.providerCalls(), 0, `${phase.phaseId} may not read the private queue`);
      assert.equal(fixture.snapshotStore.calls.length, 0, `${phase.phaseId} may not materialize a job`);
    }
  });
}

const HOST_CONFIG_WIDENING_FIELDS = Object.freeze(
  Object.keys(expectedWorkerHostConfig(
    directTrustedContext().receipt,
    findPhase("job.backup.capture"),
    null,
  )).sort(),
);

const INSPECT_MOUNT_WIDENING_FIELDS = Object.freeze([
  "Destination",
  "Driver",
  "Mode",
  "Name",
  "Propagation",
  "RW",
  "Source",
  "Type",
]);

const INSPECT_WIDENINGS = Object.freeze([
  widening("container-id", (inspect) => ({ ...inspect, Id: "9".repeat(64) })),
  widening("container-name", (inspect) => ({ ...inspect, Name: "/attacker-worker" })),
  widening("resolved-image", (inspect) => ({ ...inspect, Image: `sha256:${"9".repeat(64)}` })),
  widening("config-image", (inspect) => ({
    ...inspect,
    Config: { ...inspect.Config, Image: "attacker/image:latest" },
  })),
  widening("env.action", (inspect) => mutateEnvToDifferent(
    inspect,
    "PLATFORM_DOCKER_ACTION",
    "backup.prune.apply",
    "backup.catalog",
  )),
  widening("env.phase", (inspect) => mutateEnvToDifferent(
    inspect,
    "PLATFORM_DOCKER_PHASE_ID",
    "restore.verify",
    "catalog.capture",
  )),
  widening("env.request", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_DOCKER_REQUEST_ID",
    "123e4567-e89b-42d3-a456-426614174999",
  )),
  widening("env.authority-base64", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64",
    Buffer.from('{"attacker":true}').toString("base64url"),
  )),
  widening("env.authority-sha256", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256",
    "9".repeat(64),
  )),
  widening("env.claimed-file-name", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_CLAIMED_JOB_FILE_NAME",
    "attacker.json",
  )),
  widening("env.claimed-id", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_CLAIMED_JOB_ID",
    "attacker-job",
  )),
  widening("env.claimed-operation", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_CLAIMED_JOB_OPERATION",
    "attacker-operation",
  )),
  widening("env.claimed-path", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_CLAIMED_JOB_PATH",
    "/host/attacker",
  )),
  widening("env.claimed-sha256", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_CLAIMED_JOB_SHA256",
    "9".repeat(64),
  )),
  widening("env.claimed-source", (inspect) => mutateEnv(
    inspect,
    "PLATFORM_CLAIMED_JOB_SOURCE_ID",
    "attacker.source",
  )),
  widening("env-missing", removeInspectEnvEntry),
  widening("env-extra", (inspect) => ({
    ...inspect,
    Config: {
      ...inspect.Config,
      Env: [...inspect.Config.Env, "ATTACKER_EXTRA=1"],
    },
  })),
  widening("env-duplicate", duplicateInspectEnvEntry),
  widening("env-reordered", (inspect) => ({
    ...inspect,
    Config: {
      ...inspect.Config,
      Env: [...inspect.Config.Env].reverse(),
    },
  })),
  widening("entrypoint", (inspect) => ({ ...inspect, Config: { ...inspect.Config, Entrypoint: ["sh"] } })),
  widening("cmd", (inspect) => ({ ...inspect, Config: { ...inspect.Config, Cmd: ["sh", "-c", "id"] } })),
  widening("user", (inspect) => ({ ...inspect, Config: { ...inspect.Config, User: "65532:65532" } })),
  widening("working-dir", (inspect) => ({ ...inspect, Config: { ...inspect.Config, WorkingDir: "/tmp" } })),
  widening("labels", (inspect) => {
    const labels = { ...inspect.Config.Labels };
    delete labels["com.platform.docker-phase-sha256"];
    return { ...inspect, Config: { ...inspect.Config, Labels: labels } };
  }),
  widening("config-volumes", (inspect) => mutateInspectConfig(
    inspect,
    "Volumes",
    { "/attacker": {} },
  )),
  widening("config-exposed-ports", (inspect) => mutateInspectConfig(
    inspect,
    "ExposedPorts",
    { "2375/tcp": {} },
  )),
  widening("config-healthcheck", (inspect) => mutateInspectConfig(
    inspect,
    "Healthcheck",
    { Test: ["CMD-SHELL", "id"] },
  )),
  widening("config-onbuild", (inspect) => mutateInspectConfig(
    inspect,
    "OnBuild",
    ["RUN id"],
  )),
  ...HOST_CONFIG_WIDENING_FIELDS.map((field) => widening(
    `hostconfig.${field}`,
    (inspect) => mutateInspectHostConfig(inspect, field),
  )),
  ...INSPECT_MOUNT_WIDENING_FIELDS.map((field) => widening(
    `mount.${field}`,
    (inspect) => mutateInspectMount(inspect, field),
  )),
  widening("snapshot-bind-source", (inspect) => mutateSnapshotBind(
    inspect,
    { Source: "/host/attacker/job.json" },
  )),
  widening("snapshot-bind-destination", (inspect) => mutateSnapshotBind(
    inspect,
    { Destination: "/run/platform/attacker/job.json" },
  )),
  widening("snapshot-bind-read-write", (inspect) => mutateSnapshotBind(
    inspect,
    { Mode: "rw", RW: true },
  )),
  widening("network-id", (inspect) => {
    const entries = Object.entries(inspect.NetworkSettings.Networks);
    if (entries.length === 0) {
      return {
        ...inspect,
        HostConfig: { ...inspect.HostConfig, NetworkMode: "attacker" },
        NetworkSettings: {
          Networks: { attacker: { Aliases: [], NetworkID: "9".repeat(64) } },
        },
      };
    }
    const [name, endpoint] = entries[0];
    return {
      ...inspect,
      NetworkSettings: {
        Networks: {
          ...inspect.NetworkSettings.Networks,
          [name]: { ...endpoint, NetworkID: "9".repeat(64) },
        },
      },
    };
  }),
  widening("network-alias", (inspect) => {
    const entries = Object.entries(inspect.NetworkSettings.Networks);
    if (entries.length === 0) {
      return {
        ...inspect,
        NetworkSettings: {
          Networks: { attacker: { Aliases: ["docker-action-broker"], NetworkID: "9".repeat(64) } },
        },
      };
    }
    const [name, endpoint] = entries[0];
    return {
      ...inspect,
      NetworkSettings: {
        Networks: {
          ...inspect.NetworkSettings.Networks,
          [name]: { ...endpoint, Aliases: ["docker-action-broker"] },
        },
      },
    };
  }),
]);

for (const phase of PHASE_CASES) {
  test(`v2 ${phase.phaseId} independently rejects the complete inspect widening matrix`, async (t) => {
    for (const wideningCase of INSPECT_WIDENINGS) {
      await t.test(wideningCase.id, async (t) => {
        const baseline = semanticFixture(t, phase);
        await baseline.executor.executePhase(phase.action, phase.phaseId, baseline.context);
        assert.deepEqual(baseline.transport.startedIds, [WORKER_ID], "positive control did not start");

        const widened = semanticFixture(t, phase, { inspectMutation: wideningCase.mutate });
        await assert.rejects(
          () => widened.executor.executePhase(phase.action, phase.phaseId, widened.context),
          /inspect|exact|mismatch|forbidden|worker|authority|network|mount/i,
        );
        assert.equal(widened.transport.created.length, 1, "mutation did not reach create");
        assert.deepEqual(widened.transport.startedIds, [], "widened worker started");
        assert.deepEqual(widened.transport.deletedIds, [WORKER_ID], "widened worker was not deleted");
      });
    }
  });
}

for (const phase of PHASE_CASES) {
  test(`v2 ${phase.phaseId} independently binds every result identity and bounded output`, async (t) => {
    for (const [id, mutate] of [
      ["request", (value) => ({ ...value, requestId: "123e4567-e89b-42d3-a456-426614174999" })],
      ["action", (value) => ({ ...value, action: "backup.prune.apply" })],
      ["action-nested-id", (value) => ({
        ...value,
        action: `${value.action}.nested`,
      })],
      ["action-shared-prefix-id", (value) => ({
        ...value,
        action: `${value.action}-api`,
      })],
      ["phase", (value) => ({ ...value, phaseId: "restore.verify" })],
      ["phase-nested-id", (value) => ({
        ...value,
        phaseId: `${value.phaseId}.nested`,
      })],
      ["phase-shared-prefix-id", (value) => ({
        ...value,
        phaseId: `${value.phaseId}-api`,
      })],
      ["output-schema", (value) => ({
        ...value,
        output: { ...value.output, schema: "platform.unmodeled/v1" },
      })],
      ["output-array", (value) => ({
        ...value,
        output: { ...value.output, artifacts: [{ path: "/secret" }] },
      })],
    ]) {
      await t.test(id, async (t) => {
        const baseline = semanticFixture(t, phase);
        const expected = await baseline.executor.executePhase(phase.action, phase.phaseId, baseline.context);
        assert.deepEqual(expected, expectedActionResult(phase, baseline.rawResult));

        const hostile = semanticFixture(t, phase, { resultMutation: mutate });
        await assert.rejects(
          () => hostile.executor.executePhase(phase.action, phase.phaseId, hostile.context),
          /result|request|action|phase|schema|array|unsupported|identity/i,
        );
      });
    }
  });
}

for (const phase of PHASE_CASES.filter(({ claimedJob }) => claimedJob)) {
  test(`v2 ${phase.phaseId} independently rejects every result job substitution`, async (t) => {
    for (const [id, mutate] of [
      ["job-file", (job) => ({ ...job, jobFileName: "substituted.json" })],
      ["job-id", (job) => ({ ...job, jobId: "substituted" })],
      ["job-id-nested", (job) => ({ ...job, jobId: `${job.jobId}-nested` })],
      ["job-id-shared-prefix", (job) => ({ ...job, jobId: `${job.jobId}0` })],
      ["job-operation", (job) => ({
        ...job,
        jobOperation: job.jobOperation === "backup" ? "restore-drill" : "backup",
      })],
      ["job-digest", (job) => ({ ...job, jobSha256: "9".repeat(64) })],
    ]) {
      await t.test(id, async (t) => {
        const baseline = semanticFixture(t, phase);
        await baseline.executor.executePhase(phase.action, phase.phaseId, baseline.context);
        assert.deepEqual(baseline.transport.startedIds, [WORKER_ID]);

        const hostile = semanticFixture(t, phase, {
          resultMutation: (value) => ({ ...value, job: mutate(value.job) }),
        });
        await assert.rejects(
          () => hostile.executor.executePhase(phase.action, phase.phaseId, hostile.context),
          /job|operation|digest|identity|result/i,
        );
      });
    }
  });
}

for (const phase of PHASE_CASES.filter(({ claimedJob }) => claimedJob)) {
  test(`v2 ${phase.phaseId} rejects coherent nested job identities across job and output`, async (t) => {
    for (const suffix of ["-nested", "0"]) {
      await t.test(`suffix-${JSON.stringify(suffix)}`, async (t) => {
        const hostileJobId = `${phase.claimedJob.jobId}${suffix}`;
        const hostile = semanticFixture(t, phase, {
          resultMutation: (value) => ({
            ...value,
            job: {
              ...value.job,
              jobId: hostileJobId,
            },
            output: {
              ...value.output,
              jobId: hostileJobId,
            },
          }),
        });
        await assert.rejects(
          () => hostile.executor.executePhase(
            phase.action,
            phase.phaseId,
            hostile.context,
          ),
          /job|digest|identity|result|exact/i,
        );
        assert.equal(
          hostile.transport.rawResults[0]?.job?.jobId ?? hostileJobId,
          hostileJobId,
          "coherent nested-ID mutant did not reach the worker-result boundary",
        );
      });
    }
  });
}

test("v2 job capture is read once, sealed once, immutable, file-bound and never environment-encoded", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "job.backup.capture");
  let providerBuffer;
  const fixture = semanticFixture(t, phase, {
    afterSeal(bytes) {
      providerBuffer = bytes;
      bytes.fill(0x78);
    },
  });
  await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);

  assert.equal(fixture.providerCalls(), 1);
  assert.equal(fixture.snapshotStore.calls.length, 1);
  assert.deepEqual(fixture.snapshotStore.calls[0].authority.request, fixture.request);
  assert.equal(
    fixture.snapshotStore.calls[0].authority.requestSha256,
    fixture.requestSha256,
  );
  assert.notEqual(fixture.requestSha256, fixtureSha256(fixture.request.requestId));
  assert.equal(fixture.sealedSnapshot.requestSha256, fixture.requestSha256);
  assert.match(fixture.sealedSnapshot.hostPath, new RegExp(`/${fixture.requestSha256}/job\\.json$`));
  assert.deepEqual(providerBuffer, Buffer.alloc(BACKUP_JOB_BYTES.length, 0x78));
  assert.deepEqual(fixture.snapshotStore.calls[0].sealedBytes, BACKUP_JOB_BYTES);
  const body = fixture.transport.created[0].body;
  const env = environmentMap(body.Env);
  assert.equal(env.PLATFORM_CLAIMED_JOB_PATH, SNAPSHOT_CONTAINER_PATH);
  assert.equal(env.PLATFORM_CLAIMED_JOB_FILE_NAME, `${BACKUP_JOB_ID}.json`);
  assert.equal(env.PLATFORM_CLAIMED_JOB_ID, BACKUP_JOB_ID);
  assert.equal(env.PLATFORM_CLAIMED_JOB_OPERATION, "backup");
  assert.equal(env.PLATFORM_CLAIMED_JOB_SHA256, fixtureSha256(BACKUP_JOB_BYTES));
  assert.equal(env.PLATFORM_CLAIMED_JOB_SOURCE_ID, "jobs.running");
  assert.equal(Object.hasOwn(env, "PLATFORM_CLAIMED_JOB_BASE64"), false);
  assert.equal(
    body.HostConfig.Binds.filter((bind) => bind.endsWith(`:${SNAPSHOT_CONTAINER_PATH}:ro`)).length,
    1,
  );
  assert.doesNotMatch(canonicalFixtureJson(body), /jobs\.queue|backup-jobs\/running|docker\.sock|DOCKER_HOST/);
});

test("v2 sealed snapshot is cleaned exactly once after success and after pre-start rejection", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "job.backup.capture");
  const success = semanticFixture(t, phase);
  await success.executor.executePhase(phase.action, phase.phaseId, success.context);
  assert.deepEqual(success.snapshotStore.cleanupCalls, [success.sealedSnapshot]);

  const rejected = semanticFixture(t, phase, {
    inspectMutation: (inspect) => ({
      ...inspect,
      Config: { ...inspect.Config, Cmd: ["sh", "-c", "id"] },
    }),
  });
  await assert.rejects(
    () => rejected.executor.executePhase(phase.action, phase.phaseId, rejected.context),
  );
  assert.deepEqual(rejected.snapshotStore.cleanupCalls, [rejected.sealedSnapshot]);
  assert.deepEqual(rejected.transport.startedIds, []);
});

test("v2 uncertain snapshot cleanup preserves the lease instead of permitting replay", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "job.backup.capture");
  const fixture = semanticFixture(t, phase, {
    cleanupError: new Error("snapshot cleanup could not be proven"),
  });
  let failure;
  try {
    await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);
  } catch (error) {
    failure = error;
  }
  assert.match(failure?.message ?? "", /snapshot|cleanup/i);
  assert.equal(failure?.preserveLease, true);
  assert.equal(fixture.snapshotStore.cleanupCalls.length, 1);
});

snapshotTest("v2 snapshot store uses O_EXCL 0400 fsync under the exact Engine Mountpoint and cleans only its request leaf", async (t) => {
  assert.equal(
    typeof broker.createSnapshotFileStore,
    "function",
    "docker-action-broker must export createSnapshotFileStore",
  );
  const root = tempDir(t);
  const mountpoint = path.join(root, "broker-state");
  fs.mkdirSync(mountpoint, { mode: 0o700 });
  const uid = fs.statSync(mountpoint).uid;
  const gid = fs.statSync(mountpoint).gid;
  const history = filesystemHistoryProbe();
  const { audit, io } = history;
  const receipt = buildRawActiveReceiptV2();
  const source = receipt.resources.claimedJobSources["jobs.running"];
  const volumeInspect = {
    ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
    Mountpoint: mountpoint,
  };
  const store = broker.createSnapshotFileStore({
    expectedGid: gid,
    expectedUid: uid,
    io,
  });
  const snapshot = {
    ...findPhase("job.backup.capture").claimedJob,
    bytes: Buffer.from(BACKUP_JOB_BYTES),
  };
  const trusted = directTrustedContext();
  const request = admittedRequest(
    "backup.job.execute",
    findPhase("job.backup.capture").parameters,
    trusted,
    2001,
  );
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  assert.notEqual(
    requestSha256,
    fixtureSha256(request.requestId),
    "snapshot lineage must never collapse to sha256(requestId)",
  );
  const sealed = await store.seal(snapshot, {
    request,
    requestId: request.requestId,
    requestSha256,
    source,
    volumeInspect,
  });
  const sealHistoryEnd = audit.events.length;
  const leafSeal = assertSnapshotLeafSealHistory(audit.events, {
    expectedBytes: BACKUP_JOB_BYTES.length,
    file: sealed.hostPath,
    historyEnd: sealHistoryEnd,
  });
  const expectedDirectory = path.join(
    mountpoint,
    source.snapshotVolumeSubpath,
    requestSha256,
  );
  const claimedJobsDirectory = path.dirname(expectedDirectory);
  assert.equal(sealed.hostPath, path.join(expectedDirectory, "job.json"));
  assert.equal(sealed.containerPath, SNAPSHOT_CONTAINER_PATH);
  assertPinnedSnapshotAncestryHistory(audit.events, {
    directories: [
      {
        directory: mountpoint,
        expectedInventory: [path.basename(claimedJobsDirectory)],
        label: "Engine Mountpoint",
      },
      {
        directory: claimedJobsDirectory,
        expectedInventory: [path.basename(expectedDirectory)],
        label: "claimed-jobs directory",
      },
      {
        directory: expectedDirectory,
        expectedInventory: ["job.json"],
        label: "request snapshot directory",
      },
    ],
    historyEnd: sealHistoryEnd,
    leaf: sealed.hostPath,
    leafFsyncIndex: leafSeal.fsyncIndex,
  });
  assert.deepEqual(fs.readFileSync(sealed.hostPath), BACKUP_JOB_BYTES);
  assert.equal(fs.statSync(claimedJobsDirectory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(expectedDirectory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(sealed.hostPath).mode & 0o777, 0o400);
  const snapshotOpen = audit.opens.find(({ file }) => file === sealed.hostPath);
  assert.ok(snapshotOpen, "snapshot leaf was not descriptor-opened");
  assert.equal(
    snapshotOpen.flags & (
      fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW
    ),
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
  );
  assert.equal(snapshotOpen.mode, 0o400);
  let durabilityCursor = historyIndex(
    audit.events,
    -1,
    ({ file, type }) => type === "mkdir" && file === claimedJobsDirectory,
    "claimed-jobs directory creation was not observed",
  );
  durabilityCursor = historyIndex(
    audit.events,
    durabilityCursor,
    ({ file, type }) => type === "fsync" && file === mountpoint,
    "the Engine Mountpoint was not fsynced after claimed-jobs creation",
  );
  durabilityCursor = historyIndex(
    audit.events,
    durabilityCursor,
    ({ file, type }) => type === "mkdir" && file === expectedDirectory,
    "request snapshot directory creation was not observed",
  );
  durabilityCursor = historyIndex(
    audit.events,
    durabilityCursor,
    ({ file, type }) => type === "fsync" && file === claimedJobsDirectory,
    "claimed-jobs was not fsynced after request directory creation",
  );
  durabilityCursor = historyIndex(
    audit.events,
    durabilityCursor,
    ({ file, type }) => type === "open" && file === sealed.hostPath,
    "snapshot leaf open was not observed after its durable directory creation",
  );
  const leafWriteIndex = historyIndex(
    audit.events,
    durabilityCursor,
    ({ file, type }) => type === "write" && file === sealed.hostPath,
    "snapshot bytes were not written through the opened leaf",
  );
  const leafFsyncIndex = historyIndex(
    audit.events,
    leafWriteIndex,
    ({ file, type }) => type === "fsync" && file === sealed.hostPath,
    "snapshot leaf was fsynced before its bytes were written",
  );
  const bytesWrittenBeforeFsync = audit.events
    .slice(durabilityCursor + 1, leafFsyncIndex)
    .filter(({ file, type }) => type === "write" && file === sealed.hostPath)
    .reduce((sum, { bytes }) => sum + bytes, 0);
  assert.equal(
    bytesWrittenBeforeFsync,
    BACKUP_JOB_BYTES.length,
    "snapshot leaf fsync did not follow one complete file write",
  );
  const requestDirectoryFsync = historyIndex(
    audit.events,
    leafSeal.closeIndex,
    ({ file, type }) => type === "fsync" && file === expectedDirectory,
    "snapshot request directory was not fsynced after the durable leaf close",
  );
  assert.equal(
    audit.events
      .slice(leafFsyncIndex + 1, sealHistoryEnd)
      .some(({ file, type }) => type === "write" && file === sealed.hostPath),
    false,
    "snapshot leaf was modified after its only durable fsync",
  );
  assert.ok(requestDirectoryFsync < sealHistoryEnd);
  snapshot.bytes.fill(0x78);
  assert.deepEqual(fs.readFileSync(sealed.hostPath), BACKUP_JOB_BYTES);
  const collisionBefore = captureTreeSnapshot(expectedDirectory);
  const collisionHistoryStart = audit.events.length;
  await assert.rejects(
    async () => store.seal({
      ...snapshot,
      bytes: Buffer.from(BACKUP_JOB_BYTES),
    }, {
      request,
      requestId: request.requestId,
      requestSha256,
      source,
      volumeInspect,
    }),
    /exist|exclusive|snapshot|replay/i,
  );
  assert.deepEqual(
    captureTreeSnapshot(expectedDirectory),
    collisionBefore,
    "existing snapshot collision changed bytes, inode, metadata or inventory",
  );
  assertNoStateMutationEvents(
    audit.events.slice(collisionHistoryStart),
    expectedDirectory,
    "existing snapshot collision",
  );
  const siblingRequestSha256 = requestSha256 === "a".repeat(64)
    ? "b".repeat(64)
    : "a".repeat(64);
  const siblingDirectory = path.join(claimedJobsDirectory, siblingRequestSha256);
  const siblingFile = path.join(siblingDirectory, "job.json");
  fs.mkdirSync(siblingDirectory, { mode: 0o700 });
  fs.writeFileSync(siblingFile, "survivor\n", { mode: 0o400 });
  fs.chmodSync(siblingFile, 0o400);
  const siblingBefore = fs.statSync(siblingFile);
  const siblingTreeBefore = captureTreeSnapshot(siblingDirectory);
  const cleanupStart = audit.events.length;
  await store.cleanup(sealed);
  assert.equal(fs.existsSync(sealed.hostPath), false);
  assert.equal(fs.existsSync(expectedDirectory), false);
  assert.equal(fs.existsSync(mountpoint), true);
  assert.equal(fs.existsSync(claimedJobsDirectory), true);
  assert.equal(fs.readFileSync(siblingFile, "utf8"), "survivor\n");
  const siblingAfter = fs.statSync(siblingFile);
  assert.deepEqual(
    captureTreeSnapshot(siblingDirectory),
    siblingTreeBefore,
    "snapshot cleanup renamed or transiently replaced the sibling subtree",
  );
  assert.deepEqual(
    Object.fromEntries(
      ["dev", "ino", "mode", "uid", "gid", "nlink", "size"]
        .map((field) => [field, siblingAfter[field]]),
    ),
    Object.fromEntries(
      ["dev", "ino", "mode", "uid", "gid", "nlink", "size"]
        .map((field) => [field, siblingBefore[field]]),
    ),
    "snapshot cleanup changed a sibling request artifact",
  );
  const cleanupEvents = audit.events.slice(cleanupStart);
  assertSnapshotCleanupHistory(audit.events, {
    historyStart: cleanupStart,
    sealed,
  });
  assert.deepEqual(
    cleanupEvents
      .filter(isMutatingIoEvent)
      .map(({ file, from, to, type }) => ({ file, from, to, type })),
    [
      {
        file: sealed.hostPath,
        from: undefined,
        to: undefined,
        type: "unlink",
      },
      {
        file: expectedDirectory,
        from: undefined,
        to: undefined,
        type: "rmdir",
      },
    ],
    "snapshot cleanup wrote, renamed or escaped its exact request leaf/directory",
  );
  const unlinkIndex = historyIndex(
    audit.events,
    cleanupStart - 1,
    ({ file, type }) => type === "unlink" && file === sealed.hostPath,
    "snapshot cleanup did not unlink the exact leaf",
  );
  const requestDirectoryCleanupFsync = historyIndex(
    audit.events,
    unlinkIndex,
    ({ file, type }) => type === "fsync" && file === expectedDirectory,
    "snapshot cleanup did not fsync the request directory after leaf unlink",
  );
  const rmdirIndex = historyIndex(
    audit.events,
    requestDirectoryCleanupFsync,
    ({ file, type }) => type === "rmdir" && file === expectedDirectory,
    "snapshot cleanup removed the request directory before its unlink was durable",
  );
  historyIndex(
    audit.events,
    rmdirIndex,
    ({ file, type }) => type === "fsync" && file === claimedJobsDirectory,
    "snapshot cleanup did not fsync claimed-jobs after unlink/rmdir",
  );
});

testRunner(
  "RED v2: fresh-process first-import trap forbids cached fs authority outside snapshot io",
  (t) => {
    const root = tempDir(t);
    const mountpoint = path.join(root, "broker-state");
    fs.mkdirSync(mountpoint, { mode: 0o700 });
    const mountStat = fs.statSync(mountpoint);
    const receipt = buildRawActiveReceiptV2();
    const source = receipt.resources.claimedJobSources["jobs.running"];
    const volumeInspect = {
      ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
      Mountpoint: mountpoint,
    };
    const phase = findPhase("job.backup.capture");
    const trusted = directTrustedContext();
    const request = admittedRequest(
      phase.action,
      phase.parameters,
      trusted,
      2099,
    );
    const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
    const { bytes, ...snapshotMetadata } = phase.claimedJob;
    const payloadPath = path.join(root, "first-import-payload.json");
    fs.writeFileSync(
      payloadPath,
      `${JSON.stringify({
        authority: {
          request,
          requestId: request.requestId,
          requestSha256,
          source,
          volumeInspect,
        },
        expectedGid: mountStat.gid,
        expectedUid: mountStat.uid,
        snapshot: {
          ...snapshotMetadata,
          bytesBase64: Buffer.from(bytes).toString("base64"),
        },
      })}\n`,
      { mode: 0o600 },
    );

    const childSource = String.raw`
import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import fs from "node:fs";
import Module, {
  registerHooks as rawRegisterHooks,
  syncBuiltinESMExports as importedSyncBuiltinESMExports,
} from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { types as utilTypes } from "node:util";

function assertNoPreload(argv, nodeOptions) {
  assert.equal(
    nodeOptions,
    undefined,
    "fresh-process boundary forbids NODE_OPTIONS preload authority",
  );
  assert.deepEqual(
    argv.slice(0, 2),
    ["--input-type=module", "--eval"],
    "fresh-process boundary requires the exact eval entrypoint",
  );
  assert.equal(argv.length, 3, "fresh-process boundary admits no extra execArgv");
  assert.equal(
    argv.some((value) =>
      value === "--require"
      || value === "-r"
      || value.startsWith("--require=")
      || value === "--import"
      || value.startsWith("--import=")),
    false,
    "fresh-process boundary admits no --require/--import helper",
  );
}

assertNoPreload(process.execArgv, process.env.NODE_OPTIONS);
assert.throws(
  () => assertNoPreload(
    ["--input-type=module", "--eval", "source", "--import=attacker.mjs"],
    undefined,
  ),
  /extra execArgv|preload|require|import/i,
  "preloaded-helper mutant did not reach the exact execArgv boundary",
);

const payload = JSON.parse(
  fs.readFileSync(process.env.SNAPSHOT_TRAP_PAYLOAD, "utf8"),
);
const payloadPath = path.resolve(process.env.SNAPSHOT_TRAP_PAYLOAD);
const brokerUrl = process.env.BROKER_MODULE_URL;
const productionGraph = new Set([
  brokerUrl,
  new URL("./docker-action-activation.mjs", brokerUrl).href,
  new URL("./docker-action-contract.mjs", brokerUrl).href,
]);
const productionPaths = new Set(
  [...productionGraph].map((url) => path.resolve(fileURLToPath(url))),
);
const productionBuiltins = new Set([
  "node:crypto",
  "node:fs",
  "node:http",
  "node:net",
  "node:path",
  "node:url",
]);
const originalOwners = [fs, fs.promises].map((owner) => ({
  owner,
  ownerName: owner === fs ? "fs" : "fs.promises",
  descriptors: Object.getOwnPropertyDescriptors(owner),
}));
const rawFs = Object.create(null);
for (const key of Reflect.ownKeys(fs)) {
  if (key === "promises") continue;
  const value = Reflect.get(fs, key);
  rawFs[key] = typeof value === "function" ? value.bind(fs) : value;
}
rawFs.promises = Object.create(null);
for (const key of Reflect.ownKeys(fs.promises)) {
  const value = Reflect.get(fs.promises, key);
  rawFs.promises[key] =
    typeof value === "function" ? value.bind(fs.promises) : value;
}

const loaderScope = new AsyncLocalStorage();
const snapshotScope = new AsyncLocalStorage();
const loaderToken = Object.freeze(Object.create(null));
const snapshotTokenBrand = new WeakSet();
const directAttempts = [];
const loaderAudit = [];
const loaderDescriptors = new Map();
const loaderRejects = [];
const loaderResolves = [];
const loaderLoads = [];
const snapshotAudit = [];
const snapshotCallValidationRejects = [];
const snapshotDescriptors = new Map();
let loaderActive = true;
let snapshotCallSequence = 0;
let snapshotPhase = "seal";
let snapshotRevoked = false;
const loaderApiNames = new Set([
  "closeSync",
  "fstatSync",
  "lstatSync",
  "openSync",
  "readFileSync",
  "readSync",
  "realpathSync",
  "statSync",
]);

function exactLoaderPath(value) {
  if (value instanceof URL && value.protocol === "file:") {
    return path.resolve(fileURLToPath(value));
  }
  return path.resolve(String(value));
}

function exactSnapshotPath(value, label) {
  assert.equal(
    typeof value,
    "string",
    label + " pathname must be a primitive string",
  );
  assert.doesNotMatch(value, /\0/, label + " pathname contains NUL");
  return path.resolve(value);
}

function assertLoaderPath(name, args) {
  if (name === "readSync" || name === "closeSync" || name === "fstatSync") {
    const descriptorPath = loaderDescriptors.get(args[0]);
    assert.equal(
      productionPaths.has(descriptorPath),
      true,
      "loader reused an untracked or out-of-graph descriptor",
    );
    return descriptorPath;
  }
  const resolved = exactLoaderPath(args[0]);
  assert.equal(
    productionPaths.has(resolved),
    true,
    "loader attempted filesystem I/O outside the exact production graph",
  );
  return resolved;
}

function invokeLoaderOriginal(ownerName, owner, name, original, args) {
  const qualifiedName = ownerName + "." + String(name);
  assert.equal(loaderActive, true, "loader token survived graph closure");
  assert.equal(ownerName, "fs", "loader token reached promise filesystem I/O");
  assert.equal(
    loaderApiNames.has(String(name)),
    true,
    "loader token widened to " + qualifiedName,
  );
  const file = assertLoaderPath(String(name), args);
  const result = Reflect.apply(original, owner, args);
  if (name === "openSync") loaderDescriptors.set(result, file);
  if (name === "closeSync") loaderDescriptors.delete(args[0]);
  loaderAudit.push({
    api: qualifiedName,
    descriptor:
      name === "openSync"
        ? result
        : Number.isInteger(args[0])
          ? args[0]
          : null,
    file,
  });
  return result;
}

function snapshotPathFor(name, args) {
  if ([
    "closeSync",
    "fstatSync",
    "fsyncSync",
    "readFileSync",
    "writeFileSync",
    "writeSync",
  ].includes(name)) {
    return snapshotDescriptors.get(args[0]) ?? null;
  }
  return typeof args[0] === "string"
    ? path.resolve(args[0])
    : null;
}

function cloneExactOptions(value, expected, label) {
  assert.equal(
    value !== null
      && typeof value === "object"
      && !utilTypes.isProxy(value)
      && Object.getPrototypeOf(value) === Object.prototype,
    true,
    label + " options must be one non-Proxy plain object",
  );
  const descriptors = Object.getOwnPropertyDescriptors(value);
  assert.equal(
    Reflect.ownKeys(descriptors).every((key) => typeof key === "string"),
    true,
    label + " options forbid symbol keys",
  );
  assert.deepEqual(
    Reflect.ownKeys(descriptors).sort(),
    Object.keys(expected).sort(),
    label + " options keys are not exact",
  );
  const clone = {};
  for (const [key, expectedValue] of Object.entries(expected)) {
    const descriptor = descriptors[key];
    assert.equal(
      Object.hasOwn(descriptor, "value"),
      true,
      label + " options forbid accessors",
    );
    assert.equal(
      descriptor.value,
      expectedValue,
      label + " option " + key + " is not exact",
    );
    clone[key] = expectedValue;
  }
  return Object.freeze(clone);
}

function assertExactArity(name, args, arities) {
  assert.equal(
    arities.includes(args.length),
    true,
    name + " argument count is not exact",
  );
}

function trackedDescriptor(value, name) {
  assert.equal(
    Number.isInteger(value) && snapshotDescriptors.has(value),
    true,
    name + " requires one tracked descriptor",
  );
  return value;
}

function normalizeSnapshotArguments(name, callerArgs) {
  assert.equal(
    Array.isArray(callerArgs) && !utilTypes.isProxy(callerArgs),
    true,
    name + " arguments must be an unproxied argument list",
  );
  if (["closeSync", "fsyncSync"].includes(name)) {
    assertExactArity(name, callerArgs, [1]);
    return Object.freeze([trackedDescriptor(callerArgs[0], name)]);
  }
  if (name === "fstatSync") {
    assertExactArity(name, callerArgs, [2]);
    return Object.freeze([
      trackedDescriptor(callerArgs[0], name),
      cloneExactOptions(callerArgs[1], { bigint: true }, name),
    ]);
  }
  if (["existsSync", "realpathSync", "rmdirSync", "unlinkSync"].includes(name)) {
    assertExactArity(name, callerArgs, [1]);
    return Object.freeze([
      exactSnapshotPath(callerArgs[0], name),
    ]);
  }
  if (["lstatSync", "statSync"].includes(name)) {
    assertExactArity(name, callerArgs, [2]);
    assert.equal(
      !utilTypes.isProxy(callerArgs[1]),
      true,
      name + " options forbid Proxy objects",
    );
    const descriptors = Object.getOwnPropertyDescriptors(callerArgs[1] ?? {});
    const expected = {
      bigint: true,
      ...(Object.hasOwn(descriptors, "throwIfNoEntry")
        ? { throwIfNoEntry: false }
        : {}),
    };
    return Object.freeze([
      exactSnapshotPath(callerArgs[0], name),
      cloneExactOptions(callerArgs[1], expected, name),
    ]);
  }
  if (name === "mkdirSync") {
    assertExactArity(name, callerArgs, [2]);
    const options = typeof callerArgs[1] === "number"
      ? callerArgs[1]
      : cloneExactOptions(callerArgs[1], { mode: 0o700 }, name);
    assert.equal(
      typeof options === "number" ? options : options.mode,
      0o700,
      "mkdirSync mode must be exactly 0700",
    );
    return Object.freeze([
      exactSnapshotPath(callerArgs[0], name),
      options,
    ]);
  }
  if (name === "openSync") {
    assertExactArity(name, callerArgs, [2, 3]);
    assert.equal(
      typeof callerArgs[1],
      "number",
      "openSync flags must be a primitive number",
    );
    if (callerArgs.length === 3) {
      assert.equal(
        typeof callerArgs[2],
        "number",
        "openSync mode must be a primitive number",
      );
    }
    return Object.freeze([
      exactSnapshotPath(callerArgs[0], name),
      callerArgs[1],
      ...(callerArgs.length === 3 ? [callerArgs[2]] : []),
    ]);
  }
  if (name === "readFileSync") {
    assertExactArity(name, callerArgs, [1]);
    return Object.freeze([trackedDescriptor(callerArgs[0], name)]);
  }
  if (name === "readdirSync") {
    assertExactArity(name, callerArgs, [1, 2]);
    const file = exactSnapshotPath(callerArgs[0], name);
    if (callerArgs.length === 1) return Object.freeze([file]);
    assert.equal(
      !utilTypes.isProxy(callerArgs[1]),
      true,
      "readdirSync options forbid Proxy objects",
    );
    const descriptors = Object.getOwnPropertyDescriptors(callerArgs[1] ?? {});
    const expected = {};
    for (const key of Reflect.ownKeys(descriptors)) {
      if (key === "encoding") expected.encoding = "utf8";
      else if (key === "recursive") expected.recursive = false;
      else if (key === "withFileTypes") expected.withFileTypes = false;
      else assert.fail("readdirSync options keys are not exact");
    }
    return Object.freeze([
      file,
      cloneExactOptions(callerArgs[1], expected, name),
    ]);
  }
  if (name === "writeFileSync") {
    assertExactArity(name, callerArgs, [2]);
    trackedDescriptor(callerArgs[0], name);
    assert.equal(
      Buffer.isBuffer(callerArgs[1]) && !utilTypes.isProxy(callerArgs[1]),
      true,
      "writeFileSync bytes must be one unproxied Buffer",
    );
    return Object.freeze([
      callerArgs[0],
      Buffer.from(callerArgs[1]),
    ]);
  }
  if (name === "writeSync") {
    assertExactArity(name, callerArgs, [2, 5]);
    trackedDescriptor(callerArgs[0], name);
    assert.equal(
      Buffer.isBuffer(callerArgs[1]) && !utilTypes.isProxy(callerArgs[1]),
      true,
      "writeSync bytes must be one unproxied Buffer",
    );
    const bytes = Buffer.from(callerArgs[1]);
    if (callerArgs.length === 2) {
      return Object.freeze([callerArgs[0], bytes, 0, bytes.length, null]);
    }
    for (const [label, value] of [
      ["offset", callerArgs[2]],
      ["length", callerArgs[3]],
    ]) {
      assert.equal(Number.isInteger(value) && value >= 0, true, "writeSync " + label);
    }
    assert.equal(
      callerArgs[4] === null
        || (Number.isInteger(callerArgs[4]) && callerArgs[4] >= 0),
      true,
      "writeSync position is invalid",
    );
    return Object.freeze([
      callerArgs[0],
      bytes,
      callerArgs[2],
      callerArgs[3],
      callerArgs[4],
    ]);
  }
  throw new Error("SNAPSHOT_IO_METHOD_FORBIDDEN:" + name);
}

const mountpoint = exactSnapshotPath(
  payload.authority.volumeInspect.Mountpoint,
  "Engine Mountpoint",
);
const claimedJobsDirectory = path.join(
  mountpoint,
  payload.authority.source.snapshotVolumeSubpath,
);
const requestDirectory = path.join(
  claimedJobsDirectory,
  payload.authority.requestSha256,
);
const snapshotLeaf = path.join(requestDirectory, "job.json");
const snapshotPaths = new Set([
  mountpoint,
  claimedJobsDirectory,
  requestDirectory,
  snapshotLeaf,
]);
const snapshotMethodsByPhase = Object.freeze({
  cleanup: new Set([
    "closeSync",
    "existsSync",
    "fstatSync",
    "fsyncSync",
    "lstatSync",
    "openSync",
    "readdirSync",
    "realpathSync",
    "rmdirSync",
    "statSync",
    "unlinkSync",
  ]),
  seal: new Set([
    "closeSync",
    "existsSync",
    "fstatSync",
    "fsyncSync",
    "lstatSync",
    "mkdirSync",
    "openSync",
    "readFileSync",
    "readdirSync",
    "realpathSync",
    "statSync",
    "writeFileSync",
    "writeSync",
  ]),
});

function assertSnapshotOperation(name, args) {
  if (snapshotRevoked) throw new Error("SNAPSHOT_IO_REVOKED");
  if (!snapshotMethodsByPhase[snapshotPhase]?.has(name)) {
    throw new Error("SNAPSHOT_IO_PHASE_FORBIDDEN:" + snapshotPhase + ":" + name);
  }
  const file = snapshotPathFor(name, args);
  if (!snapshotPaths.has(file)) {
    throw new Error("SNAPSHOT_IO_PATH_FORBIDDEN:" + String(file));
  }
  if (name === "lstatSync" || name === "statSync") {
    const keys = Object.keys(args[1]).sort();
    assert.equal(
      keys.every((key) => ["bigint", "throwIfNoEntry"].includes(key)),
      true,
    );
    assert.equal(args[1].bigint, true);
    assert.equal(
      Object.hasOwn(args[1], "throwIfNoEntry")
        ? args[1].throwIfNoEntry === false
        : true,
      true,
    );
  }
  if (name === "fstatSync") {
    assert.deepEqual(args[1], { bigint: true });
  }
  if (name === "mkdirSync") {
    assert.equal(
      file === claimedJobsDirectory || file === requestDirectory,
      true,
      "snapshot io may create only its two exact directories",
    );
    const mode = typeof args[1] === "number" ? args[1] : args[1]?.mode;
    assert.equal(mode, 0o700, "snapshot directory mode must be 0700");
    if (typeof args[1] === "object") {
      assert.deepEqual(args[1], { mode: 0o700 });
    }
  }
  if (name === "openSync") {
    assert.equal(typeof args[1], "number", "snapshot open flags must be numeric");
    if (file === snapshotLeaf) {
      if (snapshotPhase !== "seal") {
        throw new Error(
          "SNAPSHOT_IO_PHASE_FORBIDDEN:" + snapshotPhase + ":openSync",
        );
      }
      const exactCreateFlags = rawFs.constants.O_WRONLY
        | rawFs.constants.O_CREAT
        | rawFs.constants.O_EXCL
        | (rawFs.constants.O_NOFOLLOW ?? 0);
      assert.equal(args[1], exactCreateFlags, "snapshot leaf flags are widened");
      assert.equal(args[2], 0o400, "snapshot leaf mode must be 0400");
    } else {
      const exactDirectoryFlags = rawFs.constants.O_RDONLY
        | (rawFs.constants.O_DIRECTORY ?? 0)
        | (rawFs.constants.O_NOFOLLOW ?? 0);
      assert.equal(
        args[1],
        exactDirectoryFlags,
        "snapshot directory flags are widened",
      );
      assert.equal(args[2], undefined);
    }
  }
  if (name === "writeFileSync" || name === "writeSync") {
    assert.equal(file, snapshotLeaf, "snapshot writes require the exact leaf fd");
    assert.equal(Number.isInteger(args[0]), true, "pathname write is forbidden");
    assert.equal(snapshotPhase, "seal");
  }
  if (name === "unlinkSync") {
    assert.equal(file, snapshotLeaf, "cleanup may unlink only the snapshot leaf");
  }
  if (name === "rmdirSync") {
    assert.equal(
      file,
      requestDirectory,
      "cleanup may remove only its exact request directory",
    );
  }
  if ([
    "closeSync",
    "fstatSync",
    "fsyncSync",
    "writeFileSync",
    "writeSync",
  ].includes(name)) {
    assert.equal(
      snapshotDescriptors.has(args[0]),
      true,
      "snapshot io used an untracked descriptor",
    );
  }
  return file;
}

function invokeSnapshotOriginal(ownerName, owner, name, original, args) {
  assert.equal(ownerName, "fs", "snapshot token reached promise filesystem I/O");
  const call = snapshotScope.getStore();
  if (!snapshotTokenBrand.has(call) || call.active !== true) {
    throw new Error("SNAPSHOT_IO_TOKEN_REVOKED:" + String(name));
  }
  assert.equal(call.method, name, "snapshot token crossed into a different method");
  assert.equal(call.phase, snapshotPhase, "snapshot token crossed phase boundary");
  assert.equal(
    args.length,
    call.args.length,
    "snapshot guard-owned argument count changed",
  );
  assert.equal(
    args.every((value, index) => Object.is(value, call.args[index])),
    true,
    "snapshot call forwarded a caller-owned object or substituted argument",
  );
  const event = {
    api: ownerName + "." + String(name),
    descriptor: Number.isInteger(args[0]) ? args[0] : null,
    error: null,
    flags: name === "openSync" ? args[1] : null,
    file: snapshotPathFor(String(name), args),
    method: String(name),
    mode: name === "openSync" ? args[2] ?? null : null,
    optionKeys:
      args[1] !== null
        && typeof args[1] === "object"
        && !Buffer.isBuffer(args[1])
        ? Object.keys(args[1]).sort()
        : [],
    phase: snapshotPhase,
    rejected: false,
    sequence: snapshotAudit.length,
  };
  snapshotAudit.push(event);
  try {
    const file = assertSnapshotOperation(String(name), args);
    const result = Reflect.apply(original, owner, args);
    if (name === "openSync") {
      snapshotDescriptors.set(result, file);
      event.descriptor = result;
    }
    if (name === "closeSync") snapshotDescriptors.delete(args[0]);
    if (name === "readdirSync") {
      assert.equal(
        Array.isArray(result)
          && result.every((entry) => typeof entry === "string"),
        true,
        "snapshot readdir exposed a raw Dir or Dirent capability",
      );
    }
    assert.equal(
      result !== null
        && typeof result === "object"
        && typeof result.then === "function",
      false,
      "sync snapshot io returned an asynchronous capability",
    );
    return result;
  } catch (error) {
    event.rejected = true;
    event.error = error?.message ?? String(error);
    throw error;
  }
}

function invokeTrapped(ownerName, owner, name, original, args) {
  if (loaderScope.getStore() === loaderToken) {
    return invokeLoaderOriginal(ownerName, owner, name, original, args);
  }
  if (snapshotTokenBrand.has(snapshotScope.getStore())) {
    return invokeSnapshotOriginal(ownerName, owner, name, original, args);
  }
  const qualifiedName = ownerName + "." + String(name);
  directAttempts.push(qualifiedName);
  throw new Error("DIRECT_FS_FORBIDDEN:" + qualifiedName);
}

for (const { descriptors, owner, ownerName } of originalOwners) {
  for (const name of Reflect.ownKeys(descriptors)) {
    const descriptor = descriptors[name];
    if (
      !Object.hasOwn(descriptor, "value")
      || typeof descriptor.value !== "function"
      || descriptor.configurable !== true
    ) {
      continue;
    }
    const original = descriptor.value;
    Object.defineProperty(owner, name, {
      ...descriptor,
      value: (...args) =>
        invokeTrapped(ownerName, owner, String(name), original, args),
    });
  }
}

const blockedModuleAttempts = [];
const blockedProcessAttempts = [];
function blockedModuleApi(name) {
  return (..._args) => {
    blockedModuleAttempts.push(name);
    throw new Error("MODULE_AUTHORITY_FORBIDDEN:" + name);
  };
}
function blockedProcessApi(name) {
  return (..._args) => {
    blockedProcessAttempts.push(name);
    throw new Error("PROCESS_AUTHORITY_FORBIDDEN:" + name);
  };
}

const hookHandle = rawRegisterHooks({
  resolve(specifier, context, nextResolve) {
    return loaderScope.run(loaderToken, () => {
      if (
        /^(?:data|file):/.test(specifier)
        && !productionGraph.has(specifier)
      ) {
        loaderRejects.push("resolve:" + specifier);
        throw new Error("LOADER_GRAPH_FORBIDDEN:" + specifier);
      }
      const resolved = nextResolve(specifier, context);
      const parentUrl = context.parentURL ?? null;
      if (resolved.url.startsWith("node:")) {
        if (
          !productionBuiltins.has(resolved.url)
          || !productionGraph.has(parentUrl)
        ) {
          loaderRejects.push("resolve:" + resolved.url);
          throw new Error("LOADER_GRAPH_FORBIDDEN:" + resolved.url);
        }
      } else if (!productionGraph.has(resolved.url)) {
        loaderRejects.push("resolve:" + resolved.url);
        throw new Error("LOADER_GRAPH_FORBIDDEN:" + resolved.url);
      } else if (
        resolved.url !== brokerUrl
        && !productionGraph.has(parentUrl)
      ) {
        loaderRejects.push("parent:" + String(parentUrl));
        throw new Error("LOADER_PARENT_FORBIDDEN:" + String(parentUrl));
      }
      loaderResolves.push({
        parentUrl,
        specifier,
        url: resolved.url,
      });
      return resolved;
    });
  },
  load(url, context, nextLoad) {
    return loaderScope.run(loaderToken, () => {
      if (
        !productionGraph.has(url)
        && !productionBuiltins.has(url)
      ) {
        loaderRejects.push("load:" + url);
        throw new Error("LOADER_GRAPH_FORBIDDEN:" + url);
      }
      const loaded = nextLoad(url, context);
      if (productionGraph.has(url)) {
        assert.equal(loaded.format, "module");
        loaderLoads.push(url);
      }
      return loaded;
    });
  },
});

const rawSyncBuiltinESMExports = importedSyncBuiltinESMExports;
for (const name of [
  "_findPath",
  "_load",
  "_preloadModules",
  "_resolveFilename",
  "createRequire",
  "register",
  "registerHooks",
  "runMain",
]) {
  Object.defineProperty(Module, name, {
    ...Object.getOwnPropertyDescriptor(Module, name),
    configurable: false,
    value: blockedModuleApi(name),
    writable: false,
  });
}
for (const name of ["_compile", "load", "require"]) {
  Object.defineProperty(Module.prototype, name, {
    ...Object.getOwnPropertyDescriptor(Module.prototype, name),
    configurable: false,
    value: blockedModuleApi("prototype." + name),
    writable: false,
  });
}
for (const extension of [".js", ".json", ".node"]) {
  Object.defineProperty(Module._extensions, extension, {
    ...Object.getOwnPropertyDescriptor(Module._extensions, extension),
    configurable: false,
    value: blockedModuleApi("extension:" + extension),
    writable: false,
  });
}
Object.freeze(Module._extensions);
rawSyncBuiltinESMExports();
Object.defineProperty(Module, "syncBuiltinESMExports", {
  ...Object.getOwnPropertyDescriptor(Module, "syncBuiltinESMExports"),
  configurable: false,
  value: blockedModuleApi("syncBuiltinESMExports"),
  writable: false,
});
rawSyncBuiltinESMExports();

for (const name of [
  "_linkedBinding",
  "binding",
  "dlopen",
  "execve",
  "getBuiltinModule",
  "loadEnvFile",
]) {
  Object.defineProperty(process, name, {
    ...Object.getOwnPropertyDescriptor(process, name),
    configurable: false,
    value: blockedProcessApi(name),
    writable: false,
  });
}
const lockedProcessReport = process.report;
Object.defineProperty(lockedProcessReport, "writeReport", {
  ...Object.getOwnPropertyDescriptor(lockedProcessReport, "writeReport"),
  configurable: false,
  value: blockedProcessApi("report.writeReport"),
  writable: false,
});
Object.defineProperty(process, "report", {
  configurable: false,
  enumerable: true,
  value: lockedProcessReport,
  writable: false,
});
for (const [owner, name] of [
  ...[
    "_findPath",
    "_load",
    "_preloadModules",
    "_resolveFilename",
    "createRequire",
    "register",
    "registerHooks",
    "runMain",
    "syncBuiltinESMExports",
  ].map((name) => [Module, name]),
  ...["_compile", "load", "require"]
    .map((name) => [Module.prototype, name]),
  ...[".js", ".json", ".node"]
    .map((name) => [Module._extensions, name]),
  ...[
    "_linkedBinding",
    "binding",
    "dlopen",
    "execve",
    "getBuiltinModule",
    "loadEnvFile",
  ].map((name) => [process, name]),
  [lockedProcessReport, "writeReport"],
  [process, "report"],
]) {
  const descriptor = Object.getOwnPropertyDescriptor(owner, name);
  assert.equal(descriptor.configurable, false, name + " blocker is configurable");
  if (Object.hasOwn(descriptor, "writable")) {
    assert.equal(descriptor.writable, false, name + " blocker is writable");
  }
}
assert.equal(
  Reflect.defineProperty(Module, "registerHooks", {
    value: () => {},
  }),
  false,
  "Module blocker could be replaced",
);
assert.equal(
  Reflect.defineProperty(process, "execve", {
    value: () => {},
  }),
  false,
  "process blocker could be replaced",
);
assert.equal(
  Reflect.defineProperty(process, "report", {
    value: {},
  }),
  false,
  "process.report pin could be replaced",
);

const broker = await import(brokerUrl);
await assert.rejects(
  () => import(pathToFileURL(payloadPath).href, { with: { type: "json" } }),
  /LOADER_GRAPH_FORBIDDEN/,
  "unexpected JSON import escaped the exact production graph",
);
await assert.rejects(
  () => import("data:text/javascript,export default 'lazy-loader-mutant'"),
  /LOADER_GRAPH_FORBIDDEN/,
  "lazy data-module import escaped the still-active production graph hook",
);
assert.equal(
  loaderDescriptors.size,
  0,
  "Node ESM loader retained a descriptor after initial production graph load",
);
assert.deepEqual(
  [...new Set(loaderLoads)].sort(),
  [...productionGraph].sort(),
  "first import did not load the exact three-file production graph",
);
assert.equal(
  loaderResolves.every(({ parentUrl, url }) =>
    productionGraph.has(url)
      ? url === brokerUrl || productionGraph.has(parentUrl)
      : productionBuiltins.has(url) && productionGraph.has(parentUrl)),
  true,
  "production graph contains an unbound parent/child resolution",
);
assert.equal(
  loaderAudit.every(({ api, file }) =>
    loaderApiNames.has(api.slice("fs.".length))
    && productionPaths.has(file)),
  true,
  "loader token widened beyond its exact method/path graph",
);

const target = mountpoint;
const cachedNamedLstat = fs.lstatSync;
const cachedReflectedLstat = Reflect.get(fs, ["lstat", "Sync"].join(""));
const directMutants = [
  ["cached named lstatSync", () => cachedNamedLstat(target, { bigint: true })],
  ["cached reflected lstatSync", () =>
    cachedReflectedLstat(target, { bigint: true })],
  ["truncate", () => fs.truncateSync(payloadPath, 0)],
  ["callback read", () => fs.readFile(target, () => {})],
  ["callback raw Dir", () => fs.opendir(target, () => {})],
  ["raw Dir", () => fs.opendirSync(target)],
  ["promise raw Dir", () => fs.promises.opendir(target)],
  ["openAsBlob", () => fs.openAsBlob(target)],
  ["watch", () => fs.watch(target, () => {})],
  ["module registerHooks", () => Module.registerHooks({})],
  ["module register", () => Module.register("data:text/javascript,")],
  ["module createRequire", () => Module.createRequire(import.meta.url)],
  ["module _findPath", () => Module._findPath("node:fs", [])],
  ["module _load", () => Module._load("node:fs")],
  ["module _preloadModules", () => Module._preloadModules([])],
  ["module _resolveFilename", () => Module._resolveFilename("node:fs", null)],
  ["module runMain", () => Module.runMain()],
  ["module prototype _compile", () =>
    Module.prototype._compile.call({}, "module.exports = 1", payloadPath)],
  ["module prototype load", () =>
    Module.prototype.load.call({}, payloadPath)],
  ["module require", () => Module.prototype.require.call({}, "node:fs")],
  ["module extension js", () => Module._extensions[".js"]({}, payloadPath)],
  ["module extension json", () => Module._extensions[".json"]({}, payloadPath)],
  ["module extension node", () => Module._extensions[".node"]({}, payloadPath)],
  ["module syncBuiltinESMExports", () => Module.syncBuiltinESMExports()],
  ["process binding", () => process.binding("fs")],
  ["process linked binding", () => process._linkedBinding("fs")],
  ["process dlopen", () => process.dlopen({}, "/tmp/never.node")],
  ["process execve", () =>
    process.execve(payloadPath + ".nonexistent-executable", [], {})],
  ["process getBuiltinModule", () => process.getBuiltinModule("fs")],
  ["process loadEnvFile", () => process.loadEnvFile(payloadPath)],
  ["process report writeReport", () => process.report.writeReport(payloadPath)],
];
for (const [label, run] of directMutants) {
  assert.throws(
    run,
    /DIRECT_FS_FORBIDDEN|MODULE_AUTHORITY_FORBIDDEN|PROCESS_AUTHORITY_FORBIDDEN/,
    label + " escaped the fresh-process authority boundary",
  );
}
assert.throws(
  () => fs.promises.open(target, "r"),
  /DIRECT_FS_FORBIDDEN:fs\.promises\.open/,
  "FileHandle mutant escaped the fresh-process authority boundary",
);

const sourceUrlMutant = Function(
  "candidate",
  "cached",
  "return cached(candidate, { bigint: true });\n//# sourceURL="
    + brokerUrl,
);
assert.throws(
  () => sourceUrlMutant(target, cachedNamedLstat),
  /DIRECT_FS_FORBIDDEN:fs\.lstatSync/,
  "sourceURL mutant forged loader authority",
);
const originalPrepareStackTrace = Error.prepareStackTrace;
try {
  Error.prepareStackTrace = () =>
    "getSourceSync node:internal/modules/esm/load";
  assert.throws(
    () => cachedNamedLstat(target, { bigint: true }),
    /DIRECT_FS_FORBIDDEN:fs\.lstatSync/,
    "prepareStackTrace mutant forged loader authority",
  );
} finally {
  Error.prepareStackTrace = originalPrepareStackTrace;
}

const SNAPSHOT_IO_METHODS = Object.freeze([
  "closeSync",
  "existsSync",
  "fstatSync",
  "fsyncSync",
  "lstatSync",
  "mkdirSync",
  "openSync",
  "readFileSync",
  "readdirSync",
  "realpathSync",
  "rmdirSync",
  "statSync",
  "unlinkSync",
  "writeFileSync",
  "writeSync",
]);
const ioDescriptors = {
  constants: {
    enumerable: true,
    value: Object.freeze({ ...rawFs.constants }),
    writable: false,
  },
};
function runSnapshotIo(name, callerArgs) {
  let guardArgs;
  try {
    guardArgs = normalizeSnapshotArguments(name, callerArgs);
  } catch (error) {
    snapshotCallValidationRejects.push(Object.freeze({
      error: error?.message ?? String(error),
      method: name,
      phase: snapshotPhase,
    }));
    throw error;
  }
  const call = Object.seal({
    active: true,
    args: guardArgs,
    id: ++snapshotCallSequence,
    method: name,
    phase: snapshotPhase,
  });
  snapshotTokenBrand.add(call);
  try {
    const result = snapshotScope.run(
      call,
      () => fs[name](...guardArgs),
    );
    assert.equal(
      result !== null
        && typeof result === "object"
        && typeof result.then === "function",
      false,
      "snapshot io call escaped asynchronously",
    );
    return result;
  } finally {
    call.active = false;
  }
}
for (const name of SNAPSHOT_IO_METHODS) {
  assert.equal(
    typeof rawFs[name],
    "function",
    "missing raw snapshot io method: " + name,
  );
  ioDescriptors[name] = {
    enumerable: true,
    value: (...args) => runSnapshotIo(name, args),
    writable: false,
  };
}
const io = Object.freeze(Object.create(null, ioDescriptors));
assert.equal(Object.getPrototypeOf(io), null);
assert.equal(Object.isFrozen(io), true);
assert.equal(Object.hasOwn(io, "promises"), false);
assert.equal(Object.hasOwn(io, "readFile"), false);
assert.equal(Object.hasOwn(io, "opendir"), false);
assert.equal(Object.hasOwn(io, "opendirSync"), false);
assert.equal(Object.hasOwn(io, "watch"), false);
assert.equal(
  io.lstatSync(target, { bigint: true }).isDirectory(),
  true,
  "strict injected io positive control did not reach the real filesystem",
);
assert.deepEqual(
  io.readdirSync(target),
  [],
  "snapshot readdir positive control did not return exact primitive names",
);
const directoryFlags = rawFs.constants.O_RDONLY
  | (rawFs.constants.O_DIRECTORY ?? 0)
  | (rawFs.constants.O_NOFOLLOW ?? 0);
const targetDescriptor = io.openSync(target, directoryFlags);
assert.equal(
  io.fstatSync(targetDescriptor, { bigint: true }).isDirectory(),
  true,
  "tracked descriptor fstat positive control failed",
);
assert.throws(
  () => io.fstatSync(targetDescriptor, { bigint: false }),
  /option bigint is not exact/,
  "fstat bigint mutant escaped exact option validation",
);
io.closeSync(targetDescriptor);
assert.throws(
  () => io.lstatSync(payloadPath, { bigint: true }),
  /SNAPSHOT_IO_PATH_FORBIDDEN/,
  "snapshot io read an unrelated path",
);
assert.throws(
  () => io.lstatSync(Buffer.from(target), { bigint: true }),
  /primitive string/,
  "Buffer pathname escaped primitive-string validation",
);
let toPrimitiveCalls = 0;
const coerciblePath = {
  [Symbol.toPrimitive]() {
    toPrimitiveCalls += 1;
    return target;
  },
};
assert.throws(
  () => io.lstatSync(coerciblePath, { bigint: true }),
  /primitive string/,
  "Symbol.toPrimitive pathname escaped primitive-string validation",
);
assert.equal(toPrimitiveCalls, 0, "pathname policy invoked attacker coercion");
let proxyOptionReads = 0;
const proxyOptions = new Proxy({ bigint: true }, {
  get(targetValue, property, receiver) {
    proxyOptionReads += 1;
    return Reflect.get(targetValue, property, receiver);
  },
});
assert.throws(
  () => io.lstatSync(target, proxyOptions),
  /Proxy/,
  "Proxy options escaped exact data-descriptor validation",
);
assert.equal(proxyOptionReads, 0, "snapshot policy read Proxy-controlled options");
let accessorReads = 0;
const accessorOptions = {};
Object.defineProperty(accessorOptions, "bigint", {
  enumerable: true,
  get() {
    accessorReads += 1;
    return true;
  },
});
assert.throws(
  () => io.lstatSync(target, accessorOptions),
  /forbid accessors/,
  "accessor options escaped exact data-descriptor validation",
);
assert.equal(accessorReads, 0, "snapshot policy invoked an options getter");
assert.throws(
  () => io.readFileSync(snapshotLeaf, { flag: "w+" }),
  /argument count|tracked descriptor|no options/,
  "readFileSync w+ mutant escaped descriptor-only read policy",
);
assert.throws(
  () => io.readdirSync(target, { recursive: true }),
  /option recursive is not exact/,
  "recursive readdir mutant escaped exact option validation",
);
assert.throws(
  () => io.readdirSync(target, { withFileTypes: true }),
  /option withFileTypes is not exact/,
  "raw Dirent readdir mutant escaped exact option validation",
);
assert.throws(
  () => io.openSync(
    snapshotLeaf,
    rawFs.constants.O_RDWR
      | rawFs.constants.O_CREAT
      | rawFs.constants.O_EXCL
      | (rawFs.constants.O_NOFOLLOW ?? 0),
    0o400,
  ),
  /flags are widened/,
  "snapshot io accepted widened leaf flags",
);
assert.throws(
  () => io.fsyncSync(987654),
  /tracked descriptor/,
  "snapshot io accepted a substituted descriptor",
);
snapshotPhase = "cleanup";
assert.throws(
  () => io.openSync(
    snapshotLeaf,
    rawFs.constants.O_WRONLY
      | rawFs.constants.O_CREAT
      | rawFs.constants.O_EXCL
      | (rawFs.constants.O_NOFOLLOW ?? 0),
    0o400,
  ),
  /PHASE_FORBIDDEN/,
  "cleanup phase accepted a seal-only open",
);
snapshotPhase = "seal";
snapshotRevoked = true;
assert.throws(
  () => io.existsSync(target),
  /SNAPSHOT_IO_REVOKED/,
  "revoked snapshot io retained read authority",
);
snapshotRevoked = false;

const escapedCall = Object.seal({
  active: true,
  args: Object.freeze([target]),
  id: ++snapshotCallSequence,
  method: "existsSync",
  phase: snapshotPhase,
});
snapshotTokenBrand.add(escapedCall);
const asyncEscape = snapshotScope.run(escapedCall, async () => {
  await Promise.resolve();
  return fs.existsSync(target);
});
escapedCall.active = false;
await assert.rejects(
  asyncEscape,
  /SNAPSHOT_IO_TOKEN_REVOKED/,
  "AsyncLocalStorage continuation reused a revoked per-call token",
);

const transcriptKeys = [
  "api",
  "descriptor",
  "error",
  "file",
  "flags",
  "method",
  "mode",
  "optionKeys",
  "phase",
  "rejected",
  "sequence",
];
for (const [index, event] of snapshotAudit.entries()) {
  assert.deepEqual(
    Object.keys(event).sort(),
    transcriptKeys,
    "snapshot transcript event shape is not exact",
  );
  assert.equal(event.sequence, index, "snapshot transcript sequence has a gap");
  assert.equal(event.api, "fs." + event.method);
  assert.equal(
    snapshotPaths.has(event.file)
      || (event.rejected === true && event.file === payloadPath),
    true,
    "snapshot transcript contains an unknown pathname",
  );
  assert.equal(
    snapshotMethodsByPhase[event.phase]?.has(event.method),
    true,
    "snapshot transcript crossed its phase/method matrix",
  );
  assert.equal(
    event.descriptor === null || Number.isInteger(event.descriptor),
    true,
    "snapshot transcript descriptor is not exact",
  );
  if (event.method !== "openSync") {
    assert.equal(event.flags, null);
    assert.equal(event.mode, null);
  }
  assert.equal(
    Array.isArray(event.optionKeys)
      && event.optionKeys.every((key) => typeof key === "string"),
    true,
    "snapshot transcript option keys are not primitive strings",
  );
}
assert.equal(
  snapshotCallValidationRejects.length,
  9,
  "one or more argument/option/path mutants missed the call validator",
);
const mutantCount =
  directMutants.length
  + 23;
assert.equal(
  snapshotAudit.some(({ api, rejected }) =>
    api === "fs.lstatSync" && rejected === false),
  true,
  "read-only snapshot io was not audited",
);
assert.equal(
  snapshotAudit.filter(({ rejected }) => rejected).length,
  4,
  "snapshot capability mutants did not all reach the central policy",
);
assert.equal(
  directAttempts.includes("fs.truncateSync"),
  true,
  "destructive truncation mutant did not reach the direct-fs boundary",
);
assert.equal(
  blockedModuleAttempts.length,
  15,
  "module authority mutants did not reach every blocked API",
);
assert.equal(
  blockedProcessAttempts.length,
  7,
  "native process authority mutants did not reach every blocked API",
);
directAttempts.length = 0;
blockedModuleAttempts.length = 0;
blockedProcessAttempts.length = 0;
if (process.env.SNAPSHOT_TRAP_SELF_TEST === "1") {
  snapshotRevoked = true;
  await assert.rejects(
    () => import("data:text/javascript,export default 'post-revoke-mutant'"),
    /LOADER_GRAPH_FORBIDDEN/,
    "lazy loader escaped before self-oracle revocation",
  );
  hookHandle.deregister();
  loaderActive = false;
  process.stdout.write(JSON.stringify({
    directAttempts,
    loaderFiles: [...new Set(loaderLoads)].sort(),
    loaderIoCount: loaderAudit.length,
    loaderRejectCount: loaderRejects.length,
    mutantCount,
    processId: process.pid,
    snapshotAuditCount: snapshotAudit.length,
    snapshotCallValidationRejectCount: snapshotCallValidationRejects.length,
    stage: "first-import-oracle-ready",
  }) + "\n");
  process.exit(0);
}

assert.equal(
  typeof broker.createSnapshotFileStore,
  "function",
  "fresh first-import consumer requires createSnapshotFileStore",
);
const store = broker.createSnapshotFileStore({
  expectedGid: payload.expectedGid,
  expectedUid: payload.expectedUid,
  io,
});
const { bytesBase64, ...metadata } = payload.snapshot;
snapshotPhase = "seal";
const sealed = await store.seal(
  {
    ...metadata,
    bytes: Buffer.from(bytesBase64, "base64"),
  },
  payload.authority,
);
assert.equal(
  rawFs.readFileSync(sealed.hostPath).equals(
    Buffer.from(bytesBase64, "base64"),
  ),
  true,
  "fresh first-import snapshot bytes diverged",
);
await assert.rejects(
  () => import("data:text/javascript,export default 'during-store-mutant'"),
  /LOADER_GRAPH_FORBIDDEN/,
  "lazy loader escaped while the snapshot store remained live",
);
snapshotPhase = "cleanup";
await store.cleanup(sealed);
snapshotRevoked = true;
assert.throws(
  () => io.existsSync(target),
  /SNAPSHOT_IO_REVOKED/,
  "snapshot capability remained usable after cleanup",
);
await assert.rejects(
  () => import("data:text/javascript,export default 'post-cleanup-mutant'"),
  /LOADER_GRAPH_FORBIDDEN/,
  "lazy loader escaped before capability revocation and hook teardown",
);
assert.equal(loaderActive, true, "loader hook was removed before cleanup/revocation");
hookHandle.deregister();
loaderActive = false;
assert.deepEqual(
  directAttempts,
  [],
  "snapshot store used fs authority outside its strict injected io",
);
process.stdout.write(JSON.stringify({
  directAttempts,
  loaderFiles: [...new Set(loaderLoads)].sort(),
  loaderIoCount: loaderAudit.length,
  loaderRejectCount: loaderRejects.length,
  mutantCount,
  processId: process.pid,
  snapshotAuditCount: snapshotAudit.length,
  snapshotCallValidationRejectCount: snapshotCallValidationRejects.length,
}) + "\n");
`;

    const runChild = (selfTest) => spawnSync(
      process.execPath,
      ["--input-type=module", "--eval", childSource],
      {
        encoding: "utf8",
        env: {
          BROKER_MODULE_URL,
          HOME: root,
          LANG: "C.UTF-8",
          NODE_ENV: "production",
          SNAPSHOT_TRAP_PAYLOAD: payloadPath,
          SNAPSHOT_TRAP_SELF_TEST: selfTest ? "1" : "0",
        },
        timeout: 20_000,
      },
    );
    const oracleChild = runChild(true);
    assert.equal(
      oracleChild.status,
      0,
      `fresh first-import self-oracle failed: ${
        oracleChild.stderr || oracleChild.error?.message || ""
      }`,
    );
    const oracleProof = JSON.parse(oracleChild.stdout);
    assert.notEqual(oracleProof.processId, process.pid);
    assert.equal(oracleProof.stage, "first-import-oracle-ready");
    assert.equal(oracleProof.mutantCount, 54);
    assert.deepEqual(oracleProof.directAttempts, []);
    assert.deepEqual(oracleProof.loaderFiles, [
      new URL("./docker-action-activation.mjs", BROKER_MODULE_URL).href,
      BROKER_MODULE_URL,
      new URL("./docker-action-contract.mjs", BROKER_MODULE_URL).href,
    ].sort());
    assert.equal(Number.isInteger(oracleProof.loaderIoCount), true);
    assert.equal(oracleProof.loaderRejectCount, 3);
    assert.equal(oracleProof.snapshotAuditCount >= 6, true);
    assert.equal(oracleProof.snapshotCallValidationRejectCount, 9);

    const child = runChild(false);
    assert.equal(
      child.status,
      0,
      `fresh first-import snapshot consumer failed: ${
        child.stderr || child.error?.message || child.stdout || ""
      }`,
    );
    const proof = JSON.parse(child.stdout);
    assert.notEqual(proof.processId, process.pid);
    assert.equal(proof.mutantCount, 54);
    assert.deepEqual(proof.directAttempts, []);
    assert.deepEqual(proof.loaderFiles, oracleProof.loaderFiles);
    assert.equal(Number.isInteger(proof.loaderIoCount), true);
    assert.equal(proof.loaderRejectCount, 4);
    assert.equal(proof.snapshotAuditCount > oracleProof.snapshotAuditCount, true);
    assert.equal(proof.snapshotCallValidationRejectCount, 9);
  },
);

for (const [attackIndex, attackCase] of [
  {
    expectedError:
      "Engine Mountpoint pathname no longer resolves to the pinned directory",
    id: "engine-mountpoint",
    label: "Engine Mountpoint",
    selectTarget: ({ mountpoint }) => mountpoint,
    targetIndex: 0,
  },
  {
    expectedError:
      "claimed-jobs directory pathname no longer resolves to the pinned directory",
    id: "claimed-jobs-directory",
    label: "claimed-jobs directory",
    selectTarget: ({ claimedJobs }) => claimedJobs,
    targetIndex: 1,
  },
  {
    expectedError:
      "request snapshot directory pathname no longer resolves to the pinned directory",
    id: "request-snapshot-directory",
    label: "request snapshot directory",
    selectTarget: ({ requestDirectory }) => requestDirectory,
    targetIndex: 2,
  },
].flatMap((attackCase) => [
  {
    ...attackCase,
    mutationKind: "symlink-back",
  },
  {
    ...attackCase,
    mutationKind: "directory-replacement",
  },
  {
    ...attackCase,
    expectedError:
      `${attackCase.label} pinned directory settled mtimeNs changed`,
    mutationKind: "mtime-and-ctime-change",
  },
  {
    ...attackCase,
    expectedError:
      `${attackCase.label} pinned directory settled ctimeNs changed`,
    mutationKind: "ctime-change",
  },
]).entries()) {
  testRunner(
    `RED v2: real snapshot store rejects external-process ${attackCase.mutationKind} substitution of its ${attackCase.label}`,
    async (t) => {
      assert.equal(
        typeof broker.createSnapshotFileStore,
        "function",
        `${attackCase.id} real-consumer ancestry RED requires createSnapshotFileStore`,
      );
      const root = fs.realpathSync(tempDir(t));
      const mountpoint = path.join(root, "broker-state");
      fs.mkdirSync(mountpoint, { mode: 0o700 });
      const mountStat = fs.statSync(mountpoint);
      const receipt = buildRawActiveReceiptV2();
      const source = receipt.resources.claimedJobSources["jobs.running"];
      const volumeInspect = {
        ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
        Mountpoint: mountpoint,
      };
      const phase = findPhase("job.backup.capture");
      const trusted = directTrustedContext();
      const request = admittedRequest(
        phase.action,
        phase.parameters,
        trusted,
        2003 + attackIndex,
      );
      const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
      const claimedJobs = path.join(mountpoint, source.snapshotVolumeSubpath);
      const requestDirectory = path.join(claimedJobs, requestSha256);
      const expectedLeaf = path.join(requestDirectory, "job.json");
      const attackTarget = attackCase.selectTarget({
        claimedJobs,
        mountpoint,
        requestDirectory,
      });
      const orphan = path.join(root, `${attackCase.id}-external-orphan`);
      let attackResult = null;
      let hookCount = 0;
      let injectionEventIndex = -1;
      let exactSettledTimestampAliases = null;
      const timestampIsolationObservations = [];
      const { audit, io: recordedIo } = filesystemHistoryProbe({
        onEvent(event) {
          if (event.type !== "fsync" || event.file !== expectedLeaf) return;
          hookCount += 1;
          if (attackResult !== null) return;
          injectionEventIndex = audit.events.length - 1;
          attackResult = spawnSync(
            process.execPath,
            ["--input-type=module", "--eval", String.raw`
              import fs from "node:fs";
              import path from "node:path";
              const beforeTargetIdentity = fs.lstatSync(
                process.env.ATTACK_TARGET,
                { bigint: true },
              );
              const metadataOnly =
                process.env.MUTATION_KIND === "mtime-and-ctime-change"
                || process.env.MUTATION_KIND === "ctime-change";
              let replacementLeaf = null;
              if (metadataOnly) {
                Atomics.wait(
                  new Int32Array(new SharedArrayBuffer(4)),
                  0,
                  0,
                  12,
                );
              }
              if (process.env.MUTATION_KIND === "mtime-and-ctime-change") {
                const exactTime = new Date("2000-01-01T00:00:00.000Z");
                fs.utimesSync(
                  process.env.ATTACK_TARGET,
                  exactTime,
                  exactTime,
                );
              } else if (process.env.MUTATION_KIND === "ctime-change") {
                const originalMode = Number(beforeTargetIdentity.mode & 0o777n);
                fs.chmodSync(process.env.ATTACK_TARGET, originalMode ^ 0o010);
                fs.chmodSync(process.env.ATTACK_TARGET, originalMode);
              } else {
                fs.renameSync(process.env.ATTACK_TARGET, process.env.ORPHAN);
                if (process.env.MUTATION_KIND === "symlink-back") {
                  fs.symlinkSync(process.env.ORPHAN, process.env.ATTACK_TARGET);
                } else if (process.env.MUTATION_KIND === "directory-replacement") {
                  replacementLeaf = path.join(
                    process.env.ATTACK_TARGET,
                    process.env.RELATIVE_LEAF,
                  );
                  const orphanLeaf = path.join(
                    process.env.ORPHAN,
                    process.env.RELATIVE_LEAF,
                  );
                  fs.mkdirSync(path.dirname(replacementLeaf), {
                    mode: 0o700,
                    recursive: true,
                  });
                  fs.renameSync(orphanLeaf, replacementLeaf);
                  fs.copyFileSync(
                    replacementLeaf,
                    orphanLeaf,
                    fs.constants.COPYFILE_EXCL,
                  );
                  fs.chmodSync(replacementLeaf, 0o400);
                  fs.chmodSync(orphanLeaf, 0o400);
                } else {
                  throw new Error("unsupported ancestry mutation");
                }
              }
              const orphanIdentity = metadataOnly
                ? null
                : fs.lstatSync(process.env.ORPHAN, { bigint: true });
              const targetIdentity = fs.lstatSync(
                process.env.ATTACK_TARGET,
                { bigint: true },
              );
              const claimedLeaf = path.join(
                process.env.ATTACK_TARGET,
                process.env.RELATIVE_LEAF,
              );
              const claimedLeafIdentity = fs.lstatSync(
                claimedLeaf,
                { bigint: true },
              );
              const replacementLeafIdentity = replacementLeaf === null
                ? null
                : fs.lstatSync(replacementLeaf, { bigint: true });
              const orphanLeafIdentity =
                metadataOnly
                  ? null
                  : fs.lstatSync(
                    path.join(process.env.ORPHAN, process.env.RELATIVE_LEAF),
                    { bigint: true },
                  );
              process.stdout.write(JSON.stringify({
                beforeTargetAtimeNs: String(beforeTargetIdentity.atimeNs),
                beforeTargetAtimeMs: String(beforeTargetIdentity.atimeMs),
                beforeTargetAtimeEpochMs: String(
                  beforeTargetIdentity.atime.getTime(),
                ),
                beforeTargetCtimeNs: String(beforeTargetIdentity.ctimeNs),
                beforeTargetCtimeMs: String(beforeTargetIdentity.ctimeMs),
                beforeTargetCtimeEpochMs: String(
                  beforeTargetIdentity.ctime.getTime(),
                ),
                beforeTargetDev: String(beforeTargetIdentity.dev),
                beforeTargetIno: String(beforeTargetIdentity.ino),
                beforeTargetMtimeNs: String(beforeTargetIdentity.mtimeNs),
                beforeTargetMtimeMs: String(beforeTargetIdentity.mtimeMs),
                beforeTargetMtimeEpochMs: String(
                  beforeTargetIdentity.mtime.getTime(),
                ),
                claimedLeafDev: String(claimedLeafIdentity.dev),
                claimedLeafIno: String(claimedLeafIdentity.ino),
                claimedLeafIsFile: claimedLeafIdentity.isFile(),
                mutationKind: process.env.MUTATION_KIND,
                orphan: orphanIdentity === null ? null : process.env.ORPHAN,
                orphanDev: orphanIdentity === null
                  ? null
                  : String(orphanIdentity.dev),
                orphanIno: orphanIdentity === null
                  ? null
                  : String(orphanIdentity.ino),
                orphanLeafDev: orphanLeafIdentity === null
                  ? null
                  : String(orphanLeafIdentity.dev),
                orphanLeafIno: orphanLeafIdentity === null
                  ? null
                  : String(orphanLeafIdentity.ino),
                processId: process.pid,
                realpath: fs.realpathSync(process.env.ATTACK_TARGET),
                replacementLeafIsFile: replacementLeaf === null
                  ? null
                  : replacementLeafIdentity.isFile(),
                replacementLeafDev: replacementLeafIdentity === null
                  ? null
                  : String(replacementLeafIdentity.dev),
                replacementLeafIno: replacementLeafIdentity === null
                  ? null
                  : String(replacementLeafIdentity.ino),
                symlink: targetIdentity.isSymbolicLink(),
                target: process.env.ATTACK_TARGET,
                targetAtimeNs: String(targetIdentity.atimeNs),
                targetAtimeMs: String(targetIdentity.atimeMs),
                targetAtimeEpochMs: String(targetIdentity.atime.getTime()),
                targetDev: String(targetIdentity.dev),
                targetDirectory: targetIdentity.isDirectory(),
                targetIno: String(targetIdentity.ino),
                targetCtimeNs: String(targetIdentity.ctimeNs),
                targetCtimeMs: String(targetIdentity.ctimeMs),
                targetCtimeEpochMs: String(targetIdentity.ctime.getTime()),
                targetMtimeNs: String(targetIdentity.mtimeNs),
                targetMtimeMs: String(targetIdentity.mtimeMs),
                targetMtimeEpochMs: String(targetIdentity.mtime.getTime()),
              }));
            `],
            {
              encoding: "utf8",
              env: {
                ...process.env,
                ATTACK_TARGET: attackTarget,
                MUTATION_KIND: attackCase.mutationKind,
                ORPHAN: orphan,
                RELATIVE_LEAF: path.relative(attackTarget, expectedLeaf),
              },
              timeout: 15_000,
            },
          );
          if (metadataOnly && attackResult.status === 0) {
            const proof = JSON.parse(attackResult.stdout);
            exactSettledTimestampAliases = Object.freeze({
              atime: new Date(Number(proof.beforeTargetAtimeEpochMs)),
              atimeMs: BigInt(proof.beforeTargetAtimeMs),
              atimeNs: BigInt(proof.beforeTargetAtimeNs),
              ctime: new Date(Number(proof.beforeTargetCtimeEpochMs)),
              ctimeMs: BigInt(proof.beforeTargetCtimeMs),
              ctimeNs: BigInt(proof.beforeTargetCtimeNs),
              mtime: new Date(Number(proof.beforeTargetMtimeEpochMs)),
              mtimeMs: BigInt(proof.beforeTargetMtimeMs),
              mtimeNs: BigInt(proof.beforeTargetMtimeNs),
            });
          }
        },
      });
      const io = new Proxy(recordedIo, {
        get(target, property) {
          if (property === "fstatSync") {
            return (descriptor, options) => {
              const stat = target.fstatSync(descriptor, options);
              if (
                (
                  attackCase.mutationKind === "mtime-and-ctime-change"
                  || attackCase.mutationKind === "ctime-change"
                )
                && injectionEventIndex >= 0
                && exactSettledTimestampAliases !== null
                && audit.descriptors.get(descriptor) === attackTarget
              ) {
                const event = audit.events.at(-1);
                assert.equal(event.type, "fstat");
                assert.equal(event.file, attackTarget);
                const observation = createTimestampIdentityFacade(stat, {
                  mutationKind: attackCase.mutationKind,
                  settled: exactSettledTimestampAliases,
                });
                if (attackCase.mutationKind === "mtime-and-ctime-change") {
                  event.ctimeNs = String(exactSettledTimestampAliases.ctimeNs);
                }
                timestampIsolationObservations.push(Object.freeze({
                  ...observation,
                  operation: "fstat",
                }));
                return observation.facade;
              }
              return stat;
            };
          }
          if (property === "lstatSync") {
            return (candidate, options) => {
              const stat = target.lstatSync(candidate, options);
              if (
                (
                  attackCase.mutationKind === "mtime-and-ctime-change"
                  || attackCase.mutationKind === "ctime-change"
                )
                && injectionEventIndex >= 0
                && exactSettledTimestampAliases !== null
                && path.resolve(String(candidate)) === attackTarget
              ) {
                const event = audit.events.at(-1);
                assert.equal(event.type, "lstat");
                assert.equal(event.file, attackTarget);
                const observation = createTimestampIdentityFacade(stat, {
                  mutationKind: attackCase.mutationKind,
                  settled: exactSettledTimestampAliases,
                });
                if (attackCase.mutationKind === "mtime-and-ctime-change") {
                  event.ctimeNs = String(exactSettledTimestampAliases.ctimeNs);
                }
                timestampIsolationObservations.push(Object.freeze({
                  ...observation,
                  operation: "lstat",
                }));
                return observation.facade;
              }
              return stat;
            };
          }
          const member = Reflect.get(target, property);
          return typeof member === "function" ? member.bind(target) : member;
        },
      });
      let failure;
      const store = broker.createSnapshotFileStore({
        expectedGid: mountStat.gid,
        expectedUid: mountStat.uid,
        io,
      });
      await assert.rejects(async () => {
        try {
          await store.seal({
            ...phase.claimedJob,
            bytes: Buffer.from(phase.claimedJob.bytes),
          }, {
            request,
            requestId: request.requestId,
            requestSha256,
            source,
            volumeInspect,
          });
        } catch (error) {
          failure = error;
          throw error;
        }
      });

      assert.equal(hookCount, 1, `${attackCase.label} attack hook count`);
      assert.equal(
        attackResult?.status,
        0,
        `external ancestry child did not complete: ${
          attackResult?.stderr || attackResult?.error?.message || ""
        }`,
      );
      const attackProof = JSON.parse(attackResult.stdout);
      const timestampIsolated =
        attackCase.mutationKind === "mtime-and-ctime-change"
        || attackCase.mutationKind === "ctime-change";
      assert.deepEqual(
        timestampIsolationObservations.map(({ operation }) => operation),
        timestampIsolated ? ["fstat", "lstat"] : [],
        "timestamp-isolation seam did not reach the exact attacked consumer reads",
      );
      assert.equal(Number.isInteger(attackProof.processId), true);
      assert.ok(attackProof.processId > 0);
      assert.notEqual(attackProof.processId, process.pid);
      assert.equal(attackProof.target, attackTarget);
      assert.equal(attackProof.mutationKind, attackCase.mutationKind);
      const metadataOnly =
        attackCase.mutationKind === "mtime-and-ctime-change"
        || attackCase.mutationKind === "ctime-change";
      for (const field of [
        "beforeTargetAtimeNs",
        "beforeTargetAtimeMs",
        "beforeTargetAtimeEpochMs",
        "beforeTargetCtimeNs",
        "beforeTargetCtimeMs",
        "beforeTargetCtimeEpochMs",
        "beforeTargetDev",
        "beforeTargetIno",
        "beforeTargetMtimeNs",
        "beforeTargetMtimeMs",
        "beforeTargetMtimeEpochMs",
        "claimedLeafDev",
        "claimedLeafIno",
        "targetDev",
        "targetIno",
        "targetAtimeNs",
        "targetAtimeMs",
        "targetAtimeEpochMs",
        "targetCtimeNs",
        "targetCtimeMs",
        "targetCtimeEpochMs",
        "targetMtimeNs",
        "targetMtimeMs",
        "targetMtimeEpochMs",
      ]) {
        assert.match(attackProof[field], /^\d+$/, `${field} is not exact`);
      }
      assert.equal(attackProof.claimedLeafIsFile, true);
      if (metadataOnly) {
        assert.equal(attackProof.orphan, null);
        assert.equal(attackProof.orphanDev, null);
        assert.equal(attackProof.orphanIno, null);
        assert.equal(attackProof.orphanLeafDev, null);
        assert.equal(attackProof.orphanLeafIno, null);
        assert.equal(attackProof.beforeTargetDev, attackProof.targetDev);
        assert.equal(attackProof.beforeTargetIno, attackProof.targetIno);
        if (attackCase.mutationKind === "mtime-and-ctime-change") {
          assert.notEqual(
            attackProof.beforeTargetAtimeNs,
            attackProof.targetAtimeNs,
            "mtime child did not provide the raw atimeNs co-change control",
          );
          assert.notEqual(
            attackProof.beforeTargetAtimeMs,
            attackProof.targetAtimeMs,
            "mtime child did not provide the raw atimeMs co-change control",
          );
          assert.notEqual(
            attackProof.beforeTargetAtimeEpochMs,
            attackProof.targetAtimeEpochMs,
            "mtime child did not provide the raw atime Date co-change control",
          );
          assert.notEqual(
            attackProof.beforeTargetMtimeNs,
            attackProof.targetMtimeNs,
            "mtime-and-ctime child did not alter settled directory mtime",
          );
          assert.notEqual(
            attackProof.beforeTargetMtimeMs,
            attackProof.targetMtimeMs,
            "mtime-and-ctime child did not alter coarse directory mtime",
          );
          assert.notEqual(
            attackProof.beforeTargetMtimeEpochMs,
            attackProof.targetMtimeEpochMs,
            "mtime-and-ctime child did not alter Date directory mtime",
          );
          assert.notEqual(
            attackProof.beforeTargetCtimeNs,
            attackProof.targetCtimeNs,
            "mtime-and-ctime child did not alter raw directory ctime",
          );
          assert.notEqual(
            attackProof.beforeTargetCtimeMs,
            attackProof.targetCtimeMs,
            "mtime-and-ctime child did not alter raw coarse directory ctime",
          );
          assert.notEqual(
            attackProof.beforeTargetCtimeEpochMs,
            attackProof.targetCtimeEpochMs,
            "mtime-and-ctime child did not alter raw Date directory ctime",
          );
        } else {
          assert.equal(
            attackProof.beforeTargetAtimeNs,
            attackProof.targetAtimeNs,
            "ctime-change child unexpectedly altered directory atimeNs",
          );
          assert.equal(
            attackProof.beforeTargetAtimeMs,
            attackProof.targetAtimeMs,
            "ctime-change child unexpectedly altered directory atimeMs",
          );
          assert.equal(
            attackProof.beforeTargetAtimeEpochMs,
            attackProof.targetAtimeEpochMs,
            "ctime-change child unexpectedly altered directory atime Date",
          );
          assert.equal(
            attackProof.beforeTargetMtimeNs,
            attackProof.targetMtimeNs,
            "ctime-change child unexpectedly altered directory mtime",
          );
          assert.equal(
            attackProof.beforeTargetMtimeMs,
            attackProof.targetMtimeMs,
            "ctime-change child unexpectedly altered coarse directory mtime",
          );
          assert.equal(
            attackProof.beforeTargetMtimeEpochMs,
            attackProof.targetMtimeEpochMs,
            "ctime-change child unexpectedly altered Date directory mtime",
          );
          assert.notEqual(
            attackProof.beforeTargetCtimeNs,
            attackProof.targetCtimeNs,
            "ctime-change child did not alter settled directory ctime",
          );
          assert.notEqual(
            attackProof.beforeTargetCtimeMs,
            attackProof.targetCtimeMs,
            "ctime-change child did not alter raw coarse directory ctime",
          );
          assert.notEqual(
            attackProof.beforeTargetCtimeEpochMs,
            attackProof.targetCtimeEpochMs,
            "ctime-change child did not alter raw Date directory ctime",
          );
        }
        const expectedTimestampView = {
          atimeEpochMs:
            attackCase.mutationKind === "mtime-and-ctime-change"
              ? attackProof.beforeTargetAtimeEpochMs
              : attackProof.targetAtimeEpochMs,
          atimeMs:
            attackCase.mutationKind === "mtime-and-ctime-change"
              ? attackProof.beforeTargetAtimeMs
              : attackProof.targetAtimeMs,
          atimeNs:
            attackCase.mutationKind === "mtime-and-ctime-change"
              ? attackProof.beforeTargetAtimeNs
              : attackProof.targetAtimeNs,
          ctimeEpochMs: attackProof.beforeTargetCtimeEpochMs,
          ctimeMs: attackProof.beforeTargetCtimeMs,
          ctimeNs:
            attackCase.mutationKind === "mtime-and-ctime-change"
              ? attackProof.beforeTargetCtimeNs
              : attackProof.targetCtimeNs,
          mtimeEpochMs:
            attackCase.mutationKind === "mtime-and-ctime-change"
              ? attackProof.beforeTargetMtimeEpochMs
              : attackProof.targetMtimeEpochMs,
          mtimeMs:
            attackCase.mutationKind === "mtime-and-ctime-change"
              ? attackProof.beforeTargetMtimeMs
              : attackProof.targetMtimeMs,
          mtimeNs: attackProof.targetMtimeNs,
        };
        const expectedRawTimestampView = {
          atimeEpochMs: attackProof.targetAtimeEpochMs,
          atimeMs: attackProof.targetAtimeMs,
          atimeNs: attackProof.targetAtimeNs,
          ctimeEpochMs: attackProof.targetCtimeEpochMs,
          ctimeMs: attackProof.targetCtimeMs,
          ctimeNs: attackProof.targetCtimeNs,
          mtimeEpochMs: attackProof.targetMtimeEpochMs,
          mtimeMs: attackProof.targetMtimeMs,
          mtimeNs: attackProof.targetMtimeNs,
        };
        assert.deepEqual(
          timestampIsolationObservations.map(
            ({ exposed, operation, raw }) => ({ exposed, operation, raw }),
          ),
          [
            {
              exposed: expectedTimestampView,
              operation: "fstat",
              raw: expectedRawTimestampView,
            },
            {
              exposed: expectedTimestampView,
              operation: "lstat",
              raw: expectedRawTimestampView,
            },
          ],
          "timestamp facade did not expose one exact causal alias set to each consumer read",
        );
        for (const observation of timestampIsolationObservations) {
          assert.ok(
            observation.reads.ctimeNs >= 1,
            `${observation.operation} consumer did not read exact ctimeNs`,
          );
          assert.ok(
            observation.reads.mtimeNs >= 1,
            `${observation.operation} consumer did not read exact mtimeNs`,
          );
          for (const field of [
            "atime",
            "atimeMs",
            "atimeNs",
            "ctime",
            "ctimeMs",
            "mtime",
            "mtimeMs",
          ]) {
            assert.equal(
              observation.reads[field],
              0,
              `${observation.operation} consumer read non-causal timestamp alias ${field}`,
            );
          }
        }
      } else {
        assert.deepEqual(timestampIsolationObservations, []);
        assert.equal(attackProof.orphan, orphan);
        assert.match(attackProof.orphanDev, /^\d+$/);
        assert.match(attackProof.orphanIno, /^\d+$/);
        for (const field of ["orphanLeafDev", "orphanLeafIno"]) {
          assert.match(attackProof[field], /^\d+$/, `${field} is not exact`);
        }
      }
      assert.equal(
        attackProof.symlink,
        attackCase.mutationKind === "symlink-back",
      );
      assert.equal(
        attackProof.targetDirectory,
        attackCase.mutationKind !== "symlink-back",
      );
      assert.equal(
        attackProof.replacementLeafIsFile,
        attackCase.mutationKind === "directory-replacement" ? true : null,
      );
      for (const field of ["replacementLeafDev", "replacementLeafIno"]) {
        if (attackCase.mutationKind === "directory-replacement") {
          assert.match(attackProof[field], /^\d+$/, `${field} is not exact`);
        } else {
          assert.equal(attackProof[field], null);
        }
      }
      if (attackCase.mutationKind === "directory-replacement") {
        assert.notDeepEqual(
          {
            dev: attackProof.orphanLeafDev,
            ino: attackProof.orphanLeafIno,
          },
          {
            dev: attackProof.replacementLeafDev,
            ino: attackProof.replacementLeafIno,
          },
          "directory-replacement mutant reused one leaf inode at both names",
        );
      }
      const expectedRealpath = attackCase.mutationKind === "symlink-back"
        ? orphan
        : attackTarget;
      assert.equal(attackProof.realpath, expectedRealpath);
      assert.equal(
        fs.lstatSync(attackTarget, { bigint: true }).isSymbolicLink(),
        attackCase.mutationKind === "symlink-back",
      );
      assert.equal(fs.realpathSync(attackTarget), expectedRealpath);
      assert.deepEqual(fs.readdirSync(mountpoint), ["claimed-jobs"]);
      assert.deepEqual(fs.readdirSync(claimedJobs), [requestSha256]);
      assert.deepEqual(fs.readdirSync(requestDirectory), ["job.json"]);
      const finalClaimedLeaf = fs.lstatSync(expectedLeaf, { bigint: true });
      assert.equal(finalClaimedLeaf.isFile(), true);
      assert.equal(String(finalClaimedLeaf.dev), attackProof.claimedLeafDev);
      assert.equal(String(finalClaimedLeaf.ino), attackProof.claimedLeafIno);
      assert.equal(
        fs.existsSync(orphan),
        !metadataOnly,
        "metadata-only mutation unexpectedly created an orphan ancestry",
      );
      assert.equal(
        audit.events.filter(({ type }) => type === "rename" || type === "symlink").length,
        0,
        "external child mutation leaked into injected-io history",
      );
      assertExternalSnapshotAncestryAttackHistory({
        attackProof,
        attackTarget,
        audit,
        directories: [mountpoint, claimedJobs, requestDirectory],
        injectionEventIndex,
        leaf: expectedLeaf,
        mutationKind: attackCase.mutationKind,
        orphan,
        targetIndex: attackCase.targetIndex,
      });
      assert.equal(failure?.message, attackCase.expectedError);
      assert.equal(failure?.preserveLease, true);
    },
  );
}

testRunner(
  "RED v2: real snapshot store rejects an ancestor-above-mount symlink-back whose mountpoint pathname identity still matches its pin",
  async (t) => {
    assert.equal(
      typeof broker.createSnapshotFileStore,
      "function",
      "ancestor-above-mount real-consumer RED requires createSnapshotFileStore",
    );
    const root = fs.realpathSync(tempDir(t));
    const authorityParent = path.join(root, "authority");
    const orphanAuthorityParent = path.join(root, "authority-orphan");
    const mountpoint = path.join(authorityParent, "broker-state");
    fs.mkdirSync(authorityParent, { mode: 0o700 });
    fs.mkdirSync(mountpoint, { mode: 0o700 });
    const mountStat = fs.statSync(mountpoint);
    const receipt = buildRawActiveReceiptV2();
    const source = receipt.resources.claimedJobSources["jobs.running"];
    const volumeInspect = {
      ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
      Mountpoint: mountpoint,
    };
    const phase = findPhase("job.backup.capture");
    const trusted = directTrustedContext();
    const request = admittedRequest(
      phase.action,
      phase.parameters,
      trusted,
      2012,
    );
    const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
    const claimedJobs = path.join(mountpoint, source.snapshotVolumeSubpath);
    const requestDirectory = path.join(claimedJobs, requestSha256);
    const expectedLeaf = path.join(requestDirectory, "job.json");
    const escapedMountpoint = path.join(orphanAuthorityParent, "broker-state");
    let attackResult = null;
    let hookCount = 0;
    let injectionEventIndex = -1;
    const { audit, io } = filesystemHistoryProbe({
      onEvent(event) {
        if (event.type !== "fsync" || event.file !== expectedLeaf) return;
        hookCount += 1;
        if (attackResult !== null) return;
        injectionEventIndex = audit.events.length - 1;
        attackResult = spawnSync(
          process.execPath,
          ["--input-type=module", "--eval", String.raw`
            import fs from "node:fs";
            const beforeMount = fs.lstatSync(
              process.env.MOUNTPOINT,
              { bigint: true },
            );
            fs.renameSync(
              process.env.AUTHORITY_PARENT,
              process.env.ORPHAN_AUTHORITY_PARENT,
            );
            fs.symlinkSync(
              process.env.ORPHAN_AUTHORITY_PARENT,
              process.env.AUTHORITY_PARENT,
            );
            const afterMount = fs.lstatSync(
              process.env.MOUNTPOINT,
              { bigint: true },
            );
            const leaf = fs.lstatSync(process.env.LEAF, { bigint: true });
            process.stdout.write(JSON.stringify({
              afterMountDev: String(afterMount.dev),
              afterMountIno: String(afterMount.ino),
              afterMountMtimeNs: String(afterMount.mtimeNs),
              authorityIsSymlink: fs.lstatSync(
                process.env.AUTHORITY_PARENT,
              ).isSymbolicLink(),
              beforeMountDev: String(beforeMount.dev),
              beforeMountIno: String(beforeMount.ino),
              beforeMountMtimeNs: String(beforeMount.mtimeNs),
              leafDev: String(leaf.dev),
              leafIno: String(leaf.ino),
              leafIsFile: leaf.isFile(),
              mountDirectory: afterMount.isDirectory(),
              processId: process.pid,
              realpath: fs.realpathSync(process.env.MOUNTPOINT),
            }));
          `],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              AUTHORITY_PARENT: authorityParent,
              LEAF: expectedLeaf,
              MOUNTPOINT: mountpoint,
              ORPHAN_AUTHORITY_PARENT: orphanAuthorityParent,
            },
            timeout: 15_000,
          },
        );
      },
    });
    const store = broker.createSnapshotFileStore({
      expectedGid: mountStat.gid,
      expectedUid: mountStat.uid,
      io,
    });
    let failure;
    await assert.rejects(async () => {
      try {
        await store.seal({
          ...phase.claimedJob,
          bytes: Buffer.from(phase.claimedJob.bytes),
        }, {
          request,
          requestId: request.requestId,
          requestSha256,
          source,
          volumeInspect,
        });
      } catch (error) {
        failure = error;
        throw error;
      }
    });

    assert.equal(hookCount, 1, "ancestor-above-mount attack hook count");
    assert.equal(
      attackResult?.status,
      0,
      `ancestor-above-mount child did not complete: ${
        attackResult?.stderr || attackResult?.error?.message || ""
      }`,
    );
    const attackProof = JSON.parse(attackResult.stdout);
    assert.equal(Number.isInteger(attackProof.processId), true);
    assert.ok(attackProof.processId > 0);
    assert.notEqual(attackProof.processId, process.pid);
    for (const field of [
      "afterMountDev",
      "afterMountIno",
      "afterMountMtimeNs",
      "beforeMountDev",
      "beforeMountIno",
      "beforeMountMtimeNs",
      "leafDev",
      "leafIno",
    ]) {
      assert.match(attackProof[field], /^\d+$/, `${field} is not exact`);
    }
    assert.equal(attackProof.authorityIsSymlink, true);
    assert.equal(attackProof.mountDirectory, true);
    assert.equal(attackProof.leafIsFile, true);
    assert.deepEqual(
      {
        dev: attackProof.afterMountDev,
        ino: attackProof.afterMountIno,
        mtimeNs: attackProof.afterMountMtimeNs,
      },
      {
        dev: attackProof.beforeMountDev,
        ino: attackProof.beforeMountIno,
        mtimeNs: attackProof.beforeMountMtimeNs,
      },
      "ancestor substitution changed the mountpoint pathname identity",
    );
    assert.equal(attackProof.realpath, escapedMountpoint);
    assert.equal(fs.lstatSync(authorityParent).isSymbolicLink(), true);
    assert.equal(fs.realpathSync(mountpoint), escapedMountpoint);
    assert.deepEqual(fs.readdirSync(mountpoint), ["claimed-jobs"]);
    assert.deepEqual(fs.readdirSync(claimedJobs), [requestSha256]);
    assert.deepEqual(fs.readdirSync(requestDirectory), ["job.json"]);
    const finalLeaf = fs.lstatSync(expectedLeaf, { bigint: true });
    assert.equal(finalLeaf.isFile(), true);
    assert.equal(String(finalLeaf.dev), attackProof.leafDev);
    assert.equal(String(finalLeaf.ino), attackProof.leafIno);
    assert.equal(
      audit.events.filter(({ type }) => type === "rename" || type === "symlink").length,
      0,
      "external ancestor mutation leaked into injected-io history",
    );
    assertExternalSnapshotAncestorRealpathEscapeHistory({
      audit,
      directories: [mountpoint, claimedJobs, requestDirectory],
      escapedMountpoint,
      injectionEventIndex,
      leaf: expectedLeaf,
      attackProof,
    });
    assert.equal(
      failure?.message,
      "Engine Mountpoint realpath no longer resolves to its canonical authority",
    );
    assert.equal(failure?.preserveLease, true);
  },
);

snapshotTest("v2 snapshot seal and cleanup survive an exact cross-process A-to-B boundary using persisted bytes only", async (t) => {
  const root = tempDir(t);
  const mountpoint = path.join(root, "broker-state");
  fs.mkdirSync(mountpoint, { mode: 0o700 });
  const mountStat = fs.statSync(mountpoint);
  const receipt = buildRawActiveReceiptV2();
  const source = receipt.resources.claimedJobSources["jobs.running"];
  const volumeInspect = {
    ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
    Mountpoint: mountpoint,
  };
  const phase = findPhase("job.backup.capture");
  const trusted = directTrustedContext();
  const request = admittedRequest(
    phase.action,
    phase.parameters,
    trusted,
    2002,
  );
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const payloadPath = path.join(root, "child-seal-input.json");
  const sealedPath = path.join(root, "child-sealed-output.json");
  const cleanupProofPath = path.join(root, "child-cleanup-proof.json");
  const {
    bytes: snapshotBytes,
    ...snapshotMetadata
  } = phase.claimedJob;
  fs.writeFileSync(payloadPath, `${JSON.stringify({
    authority: {
      request,
      requestId: request.requestId,
      requestSha256,
      source,
      volumeInspect,
    },
    expectedGid: mountStat.gid,
    expectedUid: mountStat.uid,
    snapshot: {
      ...snapshotMetadata,
      bytesBase64: Buffer.from(snapshotBytes).toString("base64"),
    },
  })}\n`, { mode: 0o600 });

  const childSource = String.raw`
    import fs from "node:fs";
    import path from "node:path";
    const broker = await import(process.env.BROKER_MODULE_URL);
    const payloadPath = process.env.BROKER_CHILD_PAYLOAD;
    const sealedPath = process.env.BROKER_CHILD_SEALED;
    const mode = process.env.BROKER_CHILD_MODE;
    const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
    const store = broker.createSnapshotFileStore({
      expectedGid: payload.expectedGid,
      expectedUid: payload.expectedUid,
    });
    if (mode === "seal") {
      const { bytesBase64, ...metadata } = payload.snapshot;
      const sealed = await store.seal(
        { ...metadata, bytes: Buffer.from(bytesBase64, "base64") },
        payload.authority,
      );
      const descriptor = fs.openSync(
        sealedPath,
        fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_NOFOLLOW,
        0o600,
      );
      try {
        fs.writeFileSync(
          descriptor,
          Buffer.from(JSON.stringify({ processId: process.pid, sealed }) + "\n"),
        );
        fs.fsyncSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
      const parent = fs.openSync(path.dirname(sealedPath), fs.constants.O_RDONLY);
      try {
        fs.fsyncSync(parent);
      } finally {
        fs.closeSync(parent);
      }
    } else if (mode === "cleanup") {
      const { sealed } = JSON.parse(fs.readFileSync(sealedPath, "utf8"));
      await store.cleanup(sealed);
      fs.writeFileSync(
        process.env.BROKER_CHILD_CLEANUP_PROOF,
        JSON.stringify({ processId: process.pid }) + "\n",
        { flag: "wx", mode: 0o600 },
      );
    } else {
      throw new Error("unknown child mode");
    }
  `;
  const childEnvironment = {
    ...process.env,
    BROKER_CHILD_PAYLOAD: payloadPath,
    BROKER_CHILD_SEALED: sealedPath,
    BROKER_CHILD_CLEANUP_PROOF: cleanupProofPath,
    BROKER_MODULE_URL,
  };
  const processA = spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", childSource],
    {
      encoding: "utf8",
      env: { ...childEnvironment, BROKER_CHILD_MODE: "seal" },
      timeout: 15_000,
    },
  );
  assert.equal(
    processA.status,
    0,
    `snapshot seal child A failed: ${processA.stderr || processA.error?.message || ""}`,
  );
  const processAProof = JSON.parse(fs.readFileSync(sealedPath, "utf8"));
  const persistedSealed = processAProof.sealed;
  assert.notEqual(processAProof.processId, process.pid);
  assert.equal(fs.existsSync(persistedSealed.hostPath), true);
  assert.deepEqual(fs.readFileSync(persistedSealed.hostPath), snapshotBytes);

  const processB = spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", childSource],
    {
      encoding: "utf8",
      env: { ...childEnvironment, BROKER_CHILD_MODE: "cleanup" },
      timeout: 15_000,
    },
  );
  assert.equal(
    processB.status,
    0,
    `snapshot cleanup child B failed: ${processB.stderr || processB.error?.message || ""}`,
  );
  const processBProof = JSON.parse(fs.readFileSync(cleanupProofPath, "utf8"));
  assert.notEqual(processBProof.processId, process.pid);
  assert.notEqual(processBProof.processId, processAProof.processId);
  assert.equal(fs.existsSync(persistedSealed.hostPath), false);
  assert.equal(fs.existsSync(path.dirname(persistedSealed.hostPath)), false);
});

const SEMANTIC_RECOVERY_CHILD_SOURCE = String.raw`
  import assert from "node:assert/strict";
  import fs from "node:fs";
  import path from "node:path";

  const broker = await import(process.env.BROKER_MODULE_URL);
  const inputPath = process.env.BROKER_SEMANTIC_RECOVERY_INPUT;
  const receiptPath = process.env.BROKER_SEMANTIC_RECOVERY_RECEIPT;
  const input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  const activePath = path.join(input.replayRoot, "active.lock");
  const calls = [];
  const lifecycle = [];
  const inspectedWorkerIds = new Set();

  function readEngineState() {
    const state = JSON.parse(fs.readFileSync(input.engineStatePath, "utf8"));
    assert.equal(state.schema, "platform.docker-action.recovery-engine-state/v1");
    assert.equal(Array.isArray(state.workers), true);
    return state;
  }

  function writeEngineState(state) {
    const temporary = input.engineStatePath + ".tmp-" + process.pid;
    const descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      fs.writeFileSync(descriptor, Buffer.from(JSON.stringify(state) + "\n"));
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    fs.renameSync(temporary, input.engineStatePath);
    const directory = fs.openSync(path.dirname(input.engineStatePath), fs.constants.O_RDONLY);
    try {
      fs.fsyncSync(directory);
    } finally {
      fs.closeSync(directory);
    }
  }

  assert.equal(typeof broker.PersistentReplayStore, "function");
  assert.equal(typeof broker.createSemanticActionExecutor, "function");
  assert.equal(typeof broker.createSnapshotFileStore, "function");
  assert.equal(fs.existsSync(activePath), true, "child B did not receive the persisted lease");
  assert.equal(
    fs.existsSync(input.sealed.hostPath),
    true,
    "child B did not receive the persisted sealed snapshot",
  );

  const replayIo = new Proxy(fs, {
    get(target, property) {
      if (property === "unlinkSync") {
        return (file, ...args) => {
          const resolved = path.resolve(String(file));
          const result = fs.unlinkSync(file, ...args);
          if (resolved === activePath) lifecycle.push("lease-unlinked");
          return result;
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const realSnapshotStore = broker.createSnapshotFileStore({
    expectedGid: input.expectedGid,
    expectedUid: input.expectedUid,
  });
  const snapshotFileStore = {
    seal() {
      throw new Error("recovery child must not seal a new snapshot");
    },
    async cleanup(candidate) {
      assert.deepEqual(candidate, input.sealed);
      const result = await realSnapshotStore.cleanup(candidate);
      lifecycle.push("snapshot-cleaned");
      return result;
    },
  };
  const transport = {
    async inspectContainerForRecovery(name) {
      calls.push({ method: "inspectContainerForRecovery", name });
      lifecycle.push("worker-inspected");
      assert.equal(name, input.resourceName);
      const state = readEngineState();
      const worker = state.workers.find((candidate) => candidate.name === name);
      assert.ok(worker, "recovery inspect did not find the persisted worker");
      inspectedWorkerIds.add(worker.id);
      return structuredClone(worker.inspect);
    },
    async deleteContainer(id) {
      assert.equal(id, input.workerId);
      assert.equal(
        inspectedWorkerIds.has(id),
        true,
        "recovery deleted a worker before its persisted inspect",
      );
      const state = readEngineState();
      assert.equal(
        state.workers.filter((candidate) => candidate.id === id).length,
        1,
        "recovery delete did not bind one exact persisted worker",
      );
      writeEngineState({
        ...state,
        workers: state.workers.filter((candidate) => candidate.id !== id),
      });
      calls.push({ id, method: "deleteContainer" });
      lifecycle.push("worker-deleted");
    },
  };
  const executor = broker.createSemanticActionExecutor({
    snapshotFileStore,
    transport,
  });
  assert.equal(typeof executor?.recoverLease, "function");
  const replayStore = new broker.PersistentReplayStore(input.replayRoot, {
    bootId: input.recoveryBootId,
    expectedGid: input.expectedGid,
    expectedUid: input.expectedUid,
    io: replayIo,
    now: () => input.now,
  });
  const recoveryResult = await replayStore.recover(executor);
  const journalNames = fs.readdirSync(input.journalDirectory).sort();
  const journalEntries = journalNames.map((name) => JSON.parse(
    fs.readFileSync(path.join(input.journalDirectory, name), "utf8"),
  ));
  const receipt = {
    calls,
    finalState: {
      activeLockExists: fs.existsSync(activePath),
      engineWorkerCount: readEngineState().workers.length,
      requestDirectoryExists: fs.existsSync(path.dirname(input.sealed.hostPath)),
      snapshotExists: fs.existsSync(input.sealed.hostPath),
    },
    journalEntries,
    lifecycle,
    processId: process.pid,
    recoveryResult,
    schema: "platform.docker-action.semantic-recovery-test-receipt/v1",
  };
  const descriptor = fs.openSync(
    receiptPath,
    fs.constants.O_WRONLY
      | fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, Buffer.from(JSON.stringify(receipt) + "\n"));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  const receiptDirectory = fs.openSync(path.dirname(receiptPath), fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(receiptDirectory);
  } finally {
    fs.closeSync(receiptDirectory);
  }
`;

function assertSemanticRecoveryProcessReceipt(receipt, {
  expectedJournalEvents,
  parentProcessId = process.pid,
  resourceName,
  workerId,
}) {
  assert.deepEqual(Object.keys(receipt).sort(), [
    "calls",
    "finalState",
    "journalEntries",
    "lifecycle",
    "processId",
    "recoveryResult",
    "schema",
  ]);
  assert.equal(
    receipt.schema,
    "platform.docker-action.semantic-recovery-test-receipt/v1",
  );
  assert.equal(Number.isSafeInteger(receipt.processId), true);
  assert.notEqual(receipt.processId, parentProcessId);
  assert.deepEqual(receipt.calls, [
    { method: "inspectContainerForRecovery", name: resourceName },
    { id: workerId, method: "deleteContainer" },
  ]);
  assert.deepEqual(receipt.lifecycle, [
    "worker-inspected",
    "worker-deleted",
    "snapshot-cleaned",
    "lease-unlinked",
  ]);
  assert.deepEqual(receipt.finalState, {
    activeLockExists: false,
    engineWorkerCount: 0,
    requestDirectoryExists: false,
    snapshotExists: false,
  });
  assert.equal(receipt.recoveryResult?.status, "recovered");
  assert.equal(receipt.recoveryResult?.resourceName, resourceName);
  assert.deepEqual(
    receipt.journalEntries.map(({ event }) => event),
    expectedJournalEvents,
  );
}

testRunner("broker cross-process semantic recovery harness is syntax-valid and self-mutant fail-closed", async (t) => {
  const syntax = spawnSync(
    process.execPath,
    ["--input-type=module", "--check", "-"],
    {
      encoding: "utf8",
      input: SEMANTIC_RECOVERY_CHILD_SOURCE,
      timeout: 15_000,
    },
  );
  assert.equal(
    syntax.status,
    0,
    `semantic recovery child harness has invalid syntax: ${syntax.stderr}`,
  );
  const resourceName = "platform-action-job-backup-process-boundary";
  const workerId = WORKER_ID;
  const expectedJournalEvents = [
    "snapshot-materialized",
    "worker-recorded",
    "worker-deleted",
    "snapshot-cleaned",
  ];
  const positive = {
    calls: [
      { method: "inspectContainerForRecovery", name: resourceName },
      { id: workerId, method: "deleteContainer" },
    ],
    finalState: {
      activeLockExists: false,
      engineWorkerCount: 0,
      requestDirectoryExists: false,
      snapshotExists: false,
    },
    journalEntries: expectedJournalEvents.map((event) => ({ event })),
    lifecycle: [
      "worker-inspected",
      "worker-deleted",
      "snapshot-cleaned",
      "lease-unlinked",
    ],
    processId: process.pid + 1,
    recoveryResult: { resourceName, status: "recovered" },
    schema: "platform.docker-action.semantic-recovery-test-receipt/v1",
  };
  const options = { expectedJournalEvents, resourceName, workerId };
  assert.doesNotThrow(() => assertSemanticRecoveryProcessReceipt(positive, options));
  for (const [id, mutate] of [
    ["same-process", (value) => ({ ...value, processId: process.pid })],
    ["delete-before-inspect", (value) => ({
      ...value,
      calls: [...value.calls].reverse(),
    })],
    ["cleanup-before-delete", (value) => ({
      ...value,
      lifecycle: [
        "worker-inspected",
        "snapshot-cleaned",
        "worker-deleted",
        "lease-unlinked",
      ],
    })],
    ["snapshot-survives", (value) => ({
      ...value,
      finalState: { ...value.finalState, snapshotExists: true },
    })],
    ["lease-survives", (value) => ({
      ...value,
      finalState: { ...value.finalState, activeLockExists: true },
    })],
    ["worker-survives", (value) => ({
      ...value,
      finalState: { ...value.finalState, engineWorkerCount: 1 },
    })],
    ["journal-truncated", (value) => ({
      ...value,
      journalEntries: value.journalEntries.slice(0, -1),
    })],
    ["receipt-extension", (value) => ({ ...value, inheritedClosure: true })],
  ]) {
    await t.test(id, () => {
      assert.throws(
        () => assertSemanticRecoveryProcessReceipt(mutate(structuredClone(positive)), options),
      );
    });
  }
});

snapshotTest("v2 snapshot store independently rejects each path-authority substitution after a positive control", async (t) => {
  assert.equal(typeof broker.createSnapshotFileStore, "function");
  for (const [id, hostile] of [
    ["symlink-mountpoint", ({ alias, inspect, snapshot, source }) => ({
      inspect: { ...inspect, Mountpoint: alias },
      snapshot,
      source,
    })],
    ["symlink-claimed-jobs", ({ attacker, inspect, real, snapshot, source }) => {
      const claimedJobs = path.join(real, source.snapshotVolumeSubpath);
      fs.rmSync(claimedJobs, { force: true, recursive: true });
      fs.symlinkSync(attacker, claimedJobs);
      return { inspect, snapshot, source };
    }],
    ["symlink-request-directory", ({
      attacker,
      hostileSha256,
      inspect,
      real,
      snapshot,
      source,
    }) => {
      const claimedJobs = path.join(real, source.snapshotVolumeSubpath);
      fs.mkdirSync(claimedJobs, { mode: 0o700, recursive: true });
      fs.symlinkSync(attacker, path.join(claimedJobs, hostileSha256));
      return { inspect, snapshot, source };
    }],
    ["symlink-leaf-collision", ({
      attacker,
      hostileSha256,
      inspect,
      real,
      snapshot,
      source,
    }) => {
      const requestDirectory = path.join(
        real,
        source.snapshotVolumeSubpath,
        hostileSha256,
      );
      fs.mkdirSync(requestDirectory, { mode: 0o700, recursive: true });
      fs.symlinkSync(
        path.join(attacker, "sentinel.txt"),
        path.join(requestDirectory, "job.json"),
      );
      return { inspect, snapshot, source };
    }],
    ["traversal-subpath", ({ inspect, snapshot, source }) => ({
      inspect,
      snapshot,
      source: { ...source, snapshotVolumeSubpath: "../attacker" },
    })],
    ["caller-host-path", ({ inspect, snapshot, source }) => ({
      inspect,
      snapshot: { ...snapshot, hostPath: "/tmp/attacker/job.json" },
      source,
    })],
    ["request-digest", ({ inspect, snapshot, source }) => ({
      inspect,
      requestSha256: "9".repeat(64),
      snapshot,
      source,
    })],
  ]) {
    await t.test(id, async (t) => {
      const root = tempDir(t);
      const real = path.join(root, "real-state");
      const alias = path.join(root, "state-alias");
      const attacker = path.join(root, "attacker");
      fs.mkdirSync(real, { mode: 0o700 });
      fs.mkdirSync(attacker, { mode: 0o700 });
      const attackerSentinel = path.join(attacker, "sentinel.txt");
      fs.writeFileSync(attackerSentinel, "outside-survivor\n", { mode: 0o600 });
      fs.symlinkSync(real, alias);
      const stat = fs.statSync(real);
      const receipt = buildRawActiveReceiptV2();
      const source = receipt.resources.claimedJobSources["jobs.running"];
      const inspect = {
        ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
        Mountpoint: real,
      };
      const pathHistory = filesystemHistoryProbe();
      const store = broker.createSnapshotFileStore({
        expectedGid: stat.gid,
        expectedUid: stat.uid,
        io: pathHistory.io,
      });
      const snapshot = {
        ...findPhase("job.backup.capture").claimedJob,
        bytes: Buffer.from(BACKUP_JOB_BYTES),
      };
      const trusted = directTrustedContext();
      const positiveRequest = admittedRequest(
        "backup.job.execute",
        findPhase("job.backup.capture").parameters,
        trusted,
      );
      const positiveSha256 = fixtureSha256(canonicalFixtureJson(positiveRequest));
      const sealed = await store.seal(snapshot, {
        request: positiveRequest,
        requestId: positiveRequest.requestId,
        requestSha256: positiveSha256,
        source,
        volumeInspect: inspect,
      });
      assert.equal(fs.existsSync(sealed.hostPath), true, `${id} positive control did not seal`);
      await store.cleanup(sealed);
      const hostileHistoryStart = pathHistory.audit.events.length;

      const hostileRequest = admittedRequest(
        "backup.job.execute",
        findPhase("job.backup.capture").parameters,
        trusted,
      );
      const hostileSha256 = fixtureSha256(canonicalFixtureJson(hostileRequest));
      const candidate = hostile({
        alias,
        attacker,
        hostileSha256,
        inspect,
        real,
        snapshot,
        source,
      });
      const realBeforeHostileSeal = captureTreeSnapshot(real);
      const attackerBeforeHostileSeal = captureTreeSnapshot(attacker);
      await assert.rejects(
        async () => store.seal(candidate.snapshot, {
          request: hostileRequest,
          requestId: hostileRequest.requestId,
          requestSha256: candidate.requestSha256 ?? hostileSha256,
          source: candidate.source,
          volumeInspect: candidate.inspect,
        }),
        /symlink|canonical|exist|exclusive|mountpoint|host.?path|subpath|traversal|unsupported|digest|lineage|request/i,
      );
      assert.equal(
        pathHistory.audit.events
          .slice(hostileHistoryStart)
          .some(({ type }) => type === "write"),
        false,
        `${id} wrote snapshot bytes before rejecting hostile path authority`,
      );
      assertNoStateMutationEvents(
        pathHistory.audit.events.slice(hostileHistoryStart),
        root,
        `${id} hostile path authority`,
      );
      assert.deepEqual(
        captureTreeSnapshot(real),
        realBeforeHostileSeal,
        `${id} changed trusted-tree bytes, inode, metadata or inventory`,
      );
      assert.deepEqual(
        captureTreeSnapshot(attacker),
        attackerBeforeHostileSeal,
        `${id} changed attacker-tree bytes, inode, metadata or inventory`,
      );
      assert.deepEqual(
        fs.readdirSync(attacker),
        ["sentinel.txt"],
        `${id} wrote through an untrusted intermediate symlink`,
      );
      assert.equal(fs.readFileSync(attackerSentinel, "utf8"), "outside-survivor\n");
    });
  }
});

snapshotTest("v2 snapshot store independently enforces private owner/mode ancestry", async (t) => {
  for (const [id, hostile] of [
    ["uid-policy", ({ gid, uid }) => ({
      storeOptions: { expectedGid: gid, expectedUid: uid + 1 },
    })],
    ["gid-policy", ({ gid, uid }) => ({
      storeOptions: { expectedGid: gid + 1, expectedUid: uid },
    })],
    ["mountpoint-mode", ({ gid, mountpoint, uid }) => {
      fs.chmodSync(mountpoint, 0o770);
      return { storeOptions: { expectedGid: gid, expectedUid: uid } };
    }],
    ["claimed-jobs-mode", ({ gid, mountpoint, source, uid }) => {
      fs.chmodSync(path.join(mountpoint, source.snapshotVolumeSubpath), 0o750);
      return { storeOptions: { expectedGid: gid, expectedUid: uid } };
    }],
    ["ancestor-mode", ({ gid, mountpoint, root, uid }) => {
      const unsafeParent = path.join(root, "unsafe-parent");
      fs.mkdirSync(unsafeParent, { mode: 0o700 });
      fs.renameSync(mountpoint, path.join(unsafeParent, "broker-state"));
      fs.chmodSync(unsafeParent, 0o770);
      return {
        mountpoint: path.join(unsafeParent, "broker-state"),
        storeOptions: { expectedGid: gid, expectedUid: uid },
      };
    }],
  ]) {
    await t.test(id, async (t) => {
      const root = tempDir(t);
      let mountpoint = path.join(root, "broker-state");
      fs.mkdirSync(mountpoint, { mode: 0o700 });
      const stat = fs.statSync(mountpoint);
      const receipt = buildRawActiveReceiptV2();
      const source = receipt.resources.claimedJobSources["jobs.running"];
      const volumeInspect = {
        ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
        Mountpoint: mountpoint,
      };
      const snapshot = {
        ...findPhase("job.backup.capture").claimedJob,
        bytes: Buffer.from(BACKUP_JOB_BYTES),
      };
      const trusted = directTrustedContext();
      const positiveRequest = admittedRequest(
        "backup.job.execute",
        findPhase("job.backup.capture").parameters,
        trusted,
      );
      const positiveStore = broker.createSnapshotFileStore({
        expectedGid: stat.gid,
        expectedUid: stat.uid,
      });
      const positive = await positiveStore.seal(snapshot, {
        request: positiveRequest,
        requestId: positiveRequest.requestId,
        requestSha256: fixtureSha256(canonicalFixtureJson(positiveRequest)),
        source,
        volumeInspect,
      });
      assert.equal(fs.existsSync(positive.hostPath), true, `${id} positive control did not seal`);
      await positiveStore.cleanup(positive);

      const candidate = hostile({
        gid: stat.gid,
        mountpoint,
        root,
        source,
        uid: stat.uid,
      });
      mountpoint = candidate.mountpoint ?? mountpoint;
      const hostileRequest = admittedRequest(
        "backup.job.execute",
        findPhase("job.backup.capture").parameters,
        trusted,
      );
      const hostileSha256 = fixtureSha256(canonicalFixtureJson(hostileRequest));
      const hostileDirectory = path.join(
        mountpoint,
        source.snapshotVolumeSubpath,
        hostileSha256,
      );
      const hostileHistory = filesystemHistoryProbe();
      const hostileStore = broker.createSnapshotFileStore({
        ...candidate.storeOptions,
        io: hostileHistory.io,
      });
      await assert.rejects(
        async () => hostileStore.seal(snapshot, {
          request: hostileRequest,
          requestId: hostileRequest.requestId,
          requestSha256: hostileSha256,
          source,
          volumeInspect: { ...volumeInspect, Mountpoint: mountpoint },
        }),
        /ancestor|directory|gid|mode|owner|permission|private|root|safe|uid/i,
      );
      assert.equal(fs.existsSync(hostileDirectory), false);
      assert.equal(
        hostileHistory.audit.events.some(({ type }) => type === "write"),
        false,
        `${id} wrote snapshot state before rejecting the private-owner policy`,
      );
    });
  }
});

snapshotTest("v2 snapshot store isolates owner, mode and hardlink checks to each exact ancestry node", async (t) => {
  for (const [nodeId, nodePath] of [
    ["ancestor", ({ root }) => root],
    ["mountpoint", ({ mountpoint }) => mountpoint],
    ["claimed-jobs", ({ claimedJobs }) => claimedJobs],
    ["request-directory", ({ requestDirectory }) => requestDirectory],
    ["leaf", ({ leaf }) => leaf],
  ]) {
    for (const [mutationId, mutationFor] of [
      ["uid", ({ uid }) => ({ uid: uid + 1 })],
      ["gid", ({ gid }) => ({ gid: gid + 1 })],
      ["mode", ({ isLeaf }) => ({ permissions: isLeaf ? 0o600 : 0o750 })],
      ...(nodeId === "leaf"
        ? [["hardlink", () => ({ nlink: 2 })]]
        : []),
    ]) {
      await t.test(`${nodeId}-${mutationId}`, async (t) => {
        const root = tempDir(t);
        const mountpoint = path.join(root, "broker-state");
        fs.mkdirSync(mountpoint, { mode: 0o700 });
        const claimedJobs = path.join(mountpoint, "claimed-jobs");
        fs.mkdirSync(claimedJobs, { mode: 0o700 });
        const stat = fs.statSync(mountpoint);
        const receipt = buildRawActiveReceiptV2();
        const source = receipt.resources.claimedJobSources["jobs.running"];
        const trusted = directTrustedContext();
        const request = admittedRequest(
          "backup.job.execute",
          findPhase("job.backup.capture").parameters,
          trusted,
        );
        const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
        const requestDirectory = path.join(claimedJobs, requestSha256);
        const leaf = path.join(requestDirectory, "job.json");
        const paths = { claimedJobs, leaf, mountpoint, requestDirectory, root };
        const target = nodePath(paths);
        const history = filesystemHistoryProbe();
        const mutation = mutationFor({
          gid: stat.gid,
          isLeaf: nodeId === "leaf",
          uid: stat.uid,
        });
        const store = broker.createSnapshotFileStore({
          expectedGid: stat.gid,
          expectedUid: stat.uid,
          io: pathStatMutationIo(history.io, {
            mutations: new Map([[target, mutation]]),
          }),
        });
        await assert.rejects(
          async () => store.seal({
            ...findPhase("job.backup.capture").claimedJob,
            bytes: Buffer.from(BACKUP_JOB_BYTES),
          }, {
            request,
            requestId: request.requestId,
            requestSha256,
            source,
            volumeInspect: {
              ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
              Mountpoint: mountpoint,
            },
          }),
          /ancestor|directory|gid|hard.?link|integrity|link|mode|owner|permission|private|root|safe|uid/i,
        );
        assert.equal(
          fs.existsSync(requestDirectory),
          false,
          `${nodeId}-${mutationId} left a partial snapshot tree`,
        );
        assert.equal(
          history.audit.events.some(
            (event) => event.type === "write" && event.file === leaf,
          ),
          false,
          `${nodeId}-${mutationId} wrote bytes before completing exact-node attestation`,
        );
      });
    }
  }
});

snapshotTest("v2 snapshot store default ownership is exactly root 0:0", async (t) => {
  const root = tempDir(t);
  const mountpoint = path.join(root, "broker-state");
  fs.mkdirSync(mountpoint, { mode: 0o700 });
  const receipt = buildRawActiveReceiptV2();
  const source = receipt.resources.claimedJobSources["jobs.running"];
  const volumeInspect = {
    ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
    Mountpoint: mountpoint,
  };
  const snapshot = {
    ...findPhase("job.backup.capture").claimedJob,
    bytes: Buffer.from(BACKUP_JOB_BYTES),
  };
  const trusted = directTrustedContext();
  const rootHistory = filesystemHistoryProbe();
  const rootStore = broker.createSnapshotFileStore({
    io: statIdentityIo(rootHistory.io, { gid: 0, uid: 0 }),
  });
  const positiveRequest = admittedRequest(
    "backup.job.execute",
    findPhase("job.backup.capture").parameters,
    trusted,
  );
  const sealed = await rootStore.seal(snapshot, {
    request: positiveRequest,
    requestId: positiveRequest.requestId,
    requestSha256: fixtureSha256(canonicalFixtureJson(positiveRequest)),
    source,
    volumeInspect,
  });
  assert.equal(fs.existsSync(sealed.hostPath), true);
  await rootStore.cleanup(sealed);

  const nonRootHistory = filesystemHistoryProbe();
  const nonRootStore = broker.createSnapshotFileStore({
    io: statIdentityIo(nonRootHistory.io, { gid: 1, uid: 1 }),
  });
  const hostileRequest = admittedRequest(
    "backup.job.execute",
    findPhase("job.backup.capture").parameters,
    trusted,
  );
  const hostileSha256 = fixtureSha256(canonicalFixtureJson(hostileRequest));
  await assert.rejects(
    async () => nonRootStore.seal(snapshot, {
      request: hostileRequest,
      requestId: hostileRequest.requestId,
      requestSha256: hostileSha256,
      source,
      volumeInspect,
    }),
    /gid|owner|root|uid/i,
  );
  assert.equal(
    fs.existsSync(path.join(
      mountpoint,
      source.snapshotVolumeSubpath,
      hostileSha256,
    )),
    false,
  );
  assert.equal(
    nonRootHistory.audit.events.some(({ type }) => type === "write"),
    false,
  );
});

snapshotTest("v2 snapshot store default root policy independently attests every ancestry node", async (t) => {
  for (const [nodeId, nodePath] of [
    ["ancestor", ({ root }) => root],
    ["mountpoint", ({ mountpoint }) => mountpoint],
    ["claimed-jobs", ({ claimedJobs }) => claimedJobs],
    ["request-directory", ({ requestDirectory }) => requestDirectory],
    ["leaf", ({ leaf }) => leaf],
  ]) {
    await t.test(nodeId, async (t) => {
      const root = tempDir(t);
      const mountpoint = path.join(root, "broker-state");
      fs.mkdirSync(mountpoint, { mode: 0o700 });
      const claimedJobs = path.join(mountpoint, "claimed-jobs");
      fs.mkdirSync(claimedJobs, { mode: 0o700 });
      const receipt = buildRawActiveReceiptV2();
      const source = receipt.resources.claimedJobSources["jobs.running"];
      const trusted = directTrustedContext();
      const request = admittedRequest(
        "backup.job.execute",
        findPhase("job.backup.capture").parameters,
        trusted,
      );
      const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
      const requestDirectory = path.join(claimedJobs, requestSha256);
      const leaf = path.join(requestDirectory, "job.json");
      const paths = { claimedJobs, leaf, mountpoint, requestDirectory, root };
      const history = filesystemHistoryProbe();
      const store = broker.createSnapshotFileStore({
        io: pathStatMutationIo(history.io, {
          defaultGid: 0,
          defaultUid: 0,
          mutations: new Map([[nodePath(paths), { gid: 1, uid: 1 }]]),
        }),
      });
      await assert.rejects(
        async () => store.seal({
          ...findPhase("job.backup.capture").claimedJob,
          bytes: Buffer.from(BACKUP_JOB_BYTES),
        }, {
          request,
          requestId: request.requestId,
          requestSha256,
          source,
          volumeInspect: {
            ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
            Mountpoint: mountpoint,
          },
        }),
        /gid|owner|root|uid/i,
      );
      assert.equal(fs.existsSync(requestDirectory), false);
      assert.equal(
        history.audit.events.some(
          (event) => event.type === "write" && event.file === leaf,
        ),
        false,
      );
    });
  }
});

snapshotTest("v2 snapshot cleanup refuses a hard-linked leaf without deleting either name", async (t) => {
  const root = tempDir(t);
  const mountpoint = path.join(root, "broker-state");
  fs.mkdirSync(mountpoint, { mode: 0o700 });
  const stat = fs.statSync(mountpoint);
  const receipt = buildRawActiveReceiptV2();
  const source = receipt.resources.claimedJobSources["jobs.running"];
  const store = broker.createSnapshotFileStore({
    expectedGid: stat.gid,
    expectedUid: stat.uid,
  });
  const trusted = directTrustedContext();
  const request = admittedRequest(
    "backup.job.execute",
    findPhase("job.backup.capture").parameters,
    trusted,
  );
  const sealed = await store.seal({
    ...findPhase("job.backup.capture").claimedJob,
    bytes: Buffer.from(BACKUP_JOB_BYTES),
  }, {
    request,
    requestId: request.requestId,
    requestSha256: fixtureSha256(canonicalFixtureJson(request)),
    source,
    volumeInspect: {
      ...buildFixtureVolumeInspect(receipt, source.snapshotVolumeId),
      Mountpoint: mountpoint,
    },
  });
  const alias = path.join(path.dirname(sealed.hostPath), "job-hardlink.json");
  fs.linkSync(sealed.hostPath, alias);
  await assert.rejects(
    async () => store.cleanup(sealed),
    /hard.?link|link|snapshot|integrity|nlink/i,
  );
  assert.equal(fs.existsSync(sealed.hostPath), true);
  assert.equal(fs.existsSync(alias), true);
});

readerTest("v2 claimed-job reader uses O_NOFOLLOW, two descriptor reads and stable pre/post fstat", (t) => {
  const fixture = claimedReaderFixture(t);
  const probe = claimedReaderIoProbe(fixture.file);
  const snapshot = broker.readClaimedJobSnapshot(fixture.input, { io: probe.io });
  assert.deepEqual(snapshot.bytes, BACKUP_JOB_BYTES);
  assert.equal(snapshot.jobSha256, fixture.parameters.jobSha256);
  const leafOpens = probe.audit.opens.filter(({ file }) => file === fixture.file);
  assert.equal(leafOpens.length, 1);
  assert.equal(
    leafOpens[0].flags & fs.constants.O_NOFOLLOW,
    fs.constants.O_NOFOLLOW,
  );
  assert.equal(leafOpens[0].file, fixture.file);
  assertExactlyTwoDescriptorReadPasses(probe.audit);
  assert.deepEqual(
    probe.audit.completedReadPasses.map(({ bytes, initialPosition }) => ({
      bytes,
      initialPosition,
    })),
    [
      { bytes: BACKUP_JOB_BYTES.length, initialPosition: 0 },
      { bytes: BACKUP_JOB_BYTES.length, initialPosition: 0 },
    ],
    "each descriptor pass must restart explicitly at position zero and consume the complete file",
  );
  assert.equal(
    new Set(probe.audit.completedReadPasses.map(({ descriptor }) => descriptor)).size,
    1,
    "both complete reads must use the same already-open descriptor",
  );
  assert.equal(
    probe.audit.descriptorReadFileCalls,
    0,
    "the oracle must not require readFileSync(fd), whose second call begins at EOF",
  );
  assert.equal(probe.audit.pathReadFileCalls, 0, "claimed-job bytes were reopened by pathname");
  assert.ok(probe.audit.fstats.length >= 2, "claimed job requires pre/post descriptor metadata");
  assert.equal(new Set(probe.audit.fstats).size, 1, "pre/post fstat must use the same descriptor");
  const firstPassIndex = probe.audit.events.findIndex(
    ({ pass, type }) => type === "read-pass-complete" && pass === 0,
  );
  const secondPassIndex = probe.audit.events.findIndex(
    ({ pass, type }) => type === "read-pass-complete" && pass === 1,
  );
  const preFstatIndex = probe.audit.events.findIndex(({ type }) => type === "fstat");
  assert.ok(
    preFstatIndex >= 0 && preFstatIndex < firstPassIndex,
    "claimed-job reader did not fstat the leaf before its first pass",
  );
  assert.ok(firstPassIndex >= 0 && secondPassIndex > firstPassIndex);
  assert.ok(
    probe.audit.events.findIndex(
      ({ type }, index) => index > secondPassIndex && type === "fstat",
    ) > secondPassIndex,
    "claimed-job reader did not fstat the same leaf after its second pass",
  );
});

readerTest("v2 claimed-job reader rejects a same-size content race between descriptor reads", (t) => {
  const baseline = claimedReaderFixture(t);
  const positive = claimedReaderIoProbe(baseline.file);
  assert.deepEqual(
    broker.readClaimedJobSnapshot(baseline.input, { io: positive.io }).bytes,
    BACKUP_JOB_BYTES,
  );

  const hostile = claimedReaderFixture(t);
  const substitutedDocument = {
    ...BACKUP_JOB_DOCUMENT,
    resultSummary: BACKUP_JOB_DOCUMENT.resultSummary.replace("scheduler", "schedulEr"),
  };
  parseBackupJobDocument(substitutedDocument);
  const substituted = Buffer.from(`${JSON.stringify(substitutedDocument, null, 2)}\n`);
  assert.equal(substituted.length, BACKUP_JOB_BYTES.length);
  const racing = claimedReaderIoProbe(hostile.file, {
    afterFirstDescriptorRead() {
      fs.writeFileSync(hostile.file, substituted);
      fs.chmodSync(hostile.file, 0o600);
    },
    freezeMetadata: true,
  });
  assert.throws(
    () => broker.readClaimedJobSnapshot({
      ...hostile.input,
      parameters: {
        ...hostile.input.parameters,
        jobSha256: fixtureSha256(substituted),
      },
    }, { io: racing.io }),
    /changed|race|stable|substitution|content/i,
  );
  assertExactlyTwoDescriptorReadPasses(racing.audit, "same-size race reader");
  assert.equal(racing.audit.raceInjectedAfterPass, 1);
});

readerTest("v2 claimed-job reader rejects descriptor metadata changes even when bytes and length match", (t) => {
  const baseline = claimedReaderFixture(t);
  assert.deepEqual(
    broker.readClaimedJobSnapshot(
      baseline.input,
      { io: claimedReaderIoProbe(baseline.file).io },
    ).bytes,
    BACKUP_JOB_BYTES,
  );

  const hostile = claimedReaderFixture(t);
  const racing = claimedReaderIoProbe(hostile.file, { metadataRace: true });
  assert.throws(
    () => broker.readClaimedJobSnapshot(hostile.input, { io: racing.io }),
    /metadata|changed|race|stable|inode|descriptor/i,
  );
  assert.ok(racing.audit.fstats.length >= 2);
});

readerTest("v2 claimed-job reader independently enforces queue owner/mode/link policy", async (t) => {
  for (const [id, mutate] of [
    ["uid-policy", ({ input, uid }) => ({
      ...input,
      policy: { ...input.policy, expectedUid: uid + 1 },
    })],
    ["gid-policy", ({ gid, input }) => ({
      ...input,
      policy: { ...input.policy, expectedGid: gid + 1 },
    })],
    ["leaf-mode", ({ file, input }) => {
      fs.chmodSync(file, 0o640);
      return input;
    }],
    ["leaf-hardlink", ({ file, input, root }) => {
      fs.linkSync(file, path.join(root, "job-hardlink.json"));
      return input;
    }],
    ["ancestor-mode", ({ input, queueRoot }) => {
      fs.chmodSync(queueRoot, 0o770);
      return input;
    }],
  ]) {
    await t.test(id, (st) => {
      const fixture = claimedReaderFixture(st);
      const stat = fs.statSync(path.dirname(fixture.file));
      assert.deepEqual(
        broker.readClaimedJobSnapshot(
          fixture.input,
          { io: claimedReaderIoProbe(fixture.file).io },
        ).bytes,
        BACKUP_JOB_BYTES,
        `${id} positive control did not read the claimed job`,
      );
      const hostileInput = mutate({
        file: fixture.file,
        gid: stat.gid,
        input: fixture.input,
        queueRoot: path.dirname(fixture.file),
        root: path.dirname(path.dirname(fixture.file)),
        uid: stat.uid,
      });
      assert.throws(
        () => broker.readClaimedJobSnapshot(
          hostileInput,
          { io: claimedReaderIoProbe(fixture.file).io },
        ),
        /ancestor|directory|gid|hard.?link|link|mode|owner|permission|policy|root|safe|uid/i,
      );
    });
  }
});

readerTest("v2 claimed-job reader default ownership is exactly root 0:0", (t) => {
  const rootFixture = claimedReaderFixture(t);
  const rootPolicy = { ...rootFixture.input.policy };
  delete rootPolicy.expectedUid;
  delete rootPolicy.expectedGid;
  const rootProbe = claimedReaderIoProbe(rootFixture.file);
  assert.deepEqual(
    broker.readClaimedJobSnapshot(
      { ...rootFixture.input, policy: rootPolicy },
      { io: statIdentityIo(rootProbe.io, { gid: 0, uid: 0 }) },
    ).bytes,
    BACKUP_JOB_BYTES,
    "default root policy rejected an input independently attested as 0:0",
  );

  const nonRootFixture = claimedReaderFixture(t);
  const nonRootPolicy = { ...nonRootFixture.input.policy };
  delete nonRootPolicy.expectedUid;
  delete nonRootPolicy.expectedGid;
  const nonRootProbe = claimedReaderIoProbe(nonRootFixture.file);
  assert.throws(
    () => broker.readClaimedJobSnapshot(
      { ...nonRootFixture.input, policy: nonRootPolicy },
      { io: statIdentityIo(nonRootProbe.io, { gid: 1, uid: 1 }) },
    ),
    /gid|owner|root|uid/i,
  );
});

for (const [id, mutate] of [
  ["name", (value) => ({ ...value, Name: "attacker-state" })],
  ["labels", (value) => ({ ...value, Labels: { ...value.Labels, attacker: "true" } })],
  ["options", (value) => ({ ...value, Options: { type: "nfs" } })],
  ["relative-mountpoint", (value) => ({ ...value, Mountpoint: "claimed-jobs" })],
  ["traversal-mountpoint", (value) => ({ ...value, Mountpoint: "/var/lib/docker/volumes/state/_data/../attacker" })],
  ["nul-mountpoint", (value) => ({ ...value, Mountpoint: "/var/lib/docker/volumes/state/_data\u0000x" })],
]) {
  test(`v2 broker.state ${id} substitution fails before snapshot seal and worker create`, async (t) => {
    const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "job.backup.capture");
    const baseline = semanticFixture(t, phase);
    await baseline.executor.executePhase(phase.action, phase.phaseId, baseline.context);
    assert.equal(baseline.snapshotStore.calls.length, 1);
    assert.equal(baseline.transport.created.length, 1);

    const hostile = semanticFixture(t, phase, {
      volumeMutation: (inspect, logicalId) => logicalId === "broker.state" ? mutate(inspect) : inspect,
    });
    await assert.rejects(
      () => hostile.executor.executePhase(phase.action, phase.phaseId, hostile.context),
      /volume|mountpoint|canonical|absolute|NUL|inspect|state/i,
    );
    assert.equal(hostile.snapshotStore.calls.length, 0);
    assert.equal(hostile.transport.created.length, 0);
  });
}

for (const phase of PHASE_CASES) {
  test(`v2 ${phase.phaseId} independently rejects every preflight identity substitution`, async (t) => {
    for (const resourceKind of ["network", "volume"]) {
      const required = requiredPreflightIds(phase, directTrustedContext().receipt)[resourceKind];
      for (const targetLogicalId of required) {
        await t.test(`${resourceKind}.${targetLogicalId}`, async (t) => {
          const baseline = semanticFixture(t, phase);
          await baseline.executor.executePhase(phase.action, phase.phaseId, baseline.context);
          assert.equal(baseline.transport.created.length, 1);
          assertExactPreflightInspectInventory(
            baseline.transport,
            phase,
            baseline.trusted.receipt,
          );

          let mutationCalls = 0;
          const option = resourceKind === "network"
            ? {
                networkMutation: (inspect, logicalId) => {
                  if (logicalId !== targetLogicalId) return inspect;
                  mutationCalls += 1;
                  return { ...inspect, Id: "9".repeat(64) };
                },
              }
            : {
                volumeMutation: (inspect, logicalId) => {
                  if (logicalId !== targetLogicalId) return inspect;
                  mutationCalls += 1;
                  return { ...inspect, Name: "attacker-volume" };
                },
              };
          const hostile = semanticFixture(t, phase, option);
          await assert.rejects(
            () => hostile.executor.executePhase(phase.action, phase.phaseId, hostile.context),
            /network|volume|inspect|identity|exact/i,
          );
          assert.equal(mutationCalls, 1, "target resource mutation was not reached exactly once");
          assertExactPreflightInspectInventory(
            hostile.transport,
            phase,
            hostile.trusted.receipt,
          );
          assert.equal(hostile.providerCalls(), 0);
          assert.deepEqual(hostile.snapshotStore.calls, []);
          assert.deepEqual(hostile.snapshotStore.cleanupCalls, []);
          assert.equal(hostile.transport.created.length, 0);
        });
      }
    }
  });
}

for (const flow of actionFlows()) {
  test(`v2 full action ${flow.id} aggregates exact phase outputs`, async (t) => {
    const fixture = actionFixture(t, flow);
    const result = await fixture.executor.execute(flow.action, fixture.context);
    assert.deepEqual(result, expectedFlowResult(flow, fixture.rawResults));
    assert.deepEqual(
      fixture.transport.created.map(({ phase }) => phase.phaseId),
      flow.phases.map(({ phaseId }) => phaseId),
    );
  });
}

for (const flow of actionFlows()) {
  test(`v2 ${flow.id} independently rejects caller Docker policy fields with zero Engine calls`, async (t) => {
    for (const [field, value] of [
      ["workerImage", "attacker/image:latest"],
      ["argv", ["sh", "-c", "id"]],
      ["mounts", ["/:/host:rw"]],
      ["networkId", "platform_egress"],
      ["capAdd", ["SYS_ADMIN"]],
      ["repository", "s3:https://attacker.invalid/bucket"],
      ["keepCompleteManifests", 0],
    ]) {
      await t.test(field, async (t) => {
        const baseline = actionFixture(t, flow);
        await baseline.executor.execute(flow.action, baseline.context);
        assert.ok(baseline.transport.calls.length > 0, "positive semantic boundary was not reached");

        const hostile = actionFixture(t, flow);
        hostile.context.parameters = {
          ...structuredClone(flow.parameters),
          [field]: value,
        };
        await assert.rejects(
          () => hostile.executor.execute(flow.action, hostile.context),
          /parameter|unsupported|schema|caller|authority|action/i,
        );
        assert.deepEqual(hostile.transport.calls, []);
      });
    }
  });
}

test("v2 restore capture failure prevents creation of restore.verify", async (t) => {
  const flow = actionFlows().find(({ id }) => id === "restore-full");
  const fixture = actionFixture(t, flow, {
    workerStatus: { "restore.capture": 17 },
  });
  await assert.rejects(
    () => fixture.executor.execute(flow.action, fixture.context),
    /worker|status|capture|failed/i,
  );
  assert.deepEqual(
    fixture.transport.created.map(({ phase }) => phase.phaseId),
    ["restore.capture"],
  );
});

test("v2 restore phase two is created only after a durable phase-one journal barrier", async (t) => {
  const flow = actionFlows().find(({ id }) => id === "restore-full");
  const root = tempDir(t);
  const ioProbe = durableIoProbe();
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48), { io: ioProbe.io });
  store.admitTrustedContext(trusted);
  const request = admittedRequest(flow.action, {}, trusted);
  const lease = store.acquire(request, trusted);
  const fixture = actionFixture(t, flow, {
    trusted,
    lease,
    onCreate(phase) {
      if (phase.phaseId !== "restore.verify") return;
      assertDurableBarrier(root, "restore.capture", request);
      assertBarrierFsyncOrder(root, "restore.capture", ioProbe.audit);
    },
  });
  await fixture.executor.execute(flow.action, fixture.context);
  lease.preserve();
  assertJournalChain(root, request);
});

for (const mutation of [
  journalMutation("tamper", ({ entries }) => {
    const entry = entries[Math.min(1, entries.length - 1)];
    const value = readJson(entry);
    value.action = "backup.prune.apply";
    writeJson(entry, value);
  }),
  journalMutation("truncate", ({ entries }) => fs.truncateSync(entries.at(-1), 7)),
  journalMutation("delete", ({ entries }) => fs.unlinkSync(entries[Math.floor(entries.length / 2)])),
  journalMutation("insert", ({ directory }) => {
    writeJson(path.join(directory, "0000000000009999.json"), {
      schema: JOURNAL_ENTRY_SCHEMA_V2,
      sequence: 9999,
      previousEntrySha256: "0".repeat(64),
      event: "worker-recorded",
    });
  }),
  journalMutation("reorder", ({ entries }) => {
    const first = fs.readFileSync(entries[0]);
    const second = fs.readFileSync(entries[1]);
    fs.writeFileSync(entries[0], second);
    fs.writeFileSync(entries[1], first);
  }),
  journalMutation("duplicate", ({ entries, directory }) => {
    fs.copyFileSync(entries[0], path.join(directory, "0000000000009998.json"));
  }),
  journalMutation("head", ({ root }) => {
    const active = readJson(path.join(root, "active.lock"));
    active.journalHeadSha256 = "9".repeat(64);
    writeJson(path.join(root, "active.lock"), active);
  }),
  journalMutation("restart-identity", ({ root }) => {
    const active = readJson(path.join(root, "active.lock"));
    active.leaseId = "9".repeat(64);
    writeJson(path.join(root, "active.lock"), active);
  }),
]) {
  test(`v2 restart rejects lease journal ${mutation.id} and preserves the lock`, async (t) => {
    const baseline = await preservedJournalFixture(t);
    assertJournalChain(baseline.root, baseline.request);
    mutation.apply(journalFiles(baseline.root));

    const recoveryTransport = new OracleEngineTransport({
      trusted: baseline.trusted,
      phases: [],
      request: baseline.request,
      requestId: baseline.request.requestId,
      rawResults: [],
    });
    const recovery = createSemanticExecutor({ transport: recoveryTransport });
    const preservedTree = captureTreeSnapshot(baseline.root);
    const recoveryIo = durableIoProbe();
    const restarted = createReplayStore(
      baseline.root,
      "b".repeat(48),
      { io: recoveryIo.io },
    );
    await assert.rejects(
      () => restarted.recover(recovery),
      /journal|chain|sequence|head|duplicate|corrupt|integrity|entry/i,
    );
    assert.equal(fs.existsSync(path.join(baseline.root, "active.lock")), true);
    assert.deepEqual(recoveryTransport.calls, []);
    assert.deepEqual(captureTreeSnapshot(baseline.root), preservedTree);
    assertNoStateMutationEvents(
      recoveryIo.audit.events,
      baseline.root,
      `${mutation.id} corrupt-journal restart`,
    );
  });
}

test("v2 journal sequence/head bind exactly and post-terminal appends are rejected", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "job.backup.capture");
  const root = tempDir(t);
  const ioProbe = durableIoProbe();
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48), { io: ioProbe.io });
  store.admitTrustedContext(trusted);
  const request = admittedRequest(phase.action, phase.parameters, trusted);
  const lease = store.acquire(request, trusted);
  const fixture = semanticFixture(t, phase, { trusted, lease, request });
  await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);
  lease.preserve();
  const entries = assertJournalChain(root, request);
  assertExactRealExecutionJournal(entries, {
    phase,
    rawResult: fixture.rawResult,
    request,
    resourceName: fixture.transport.created[0].name,
    sealed: fixture.sealedSnapshot,
    trusted,
    workerId: WORKER_ID,
  });
  assert.equal(entries.at(-1).event, "action-completed");
  const journal = journalFiles(root);
  assertJournalAppendFsyncOrder(
    root,
    journal.directory,
    journal.entries,
    ioProbe.audit,
    "complete claimed-job execution",
  );
  assert.throws(
    () => lease.recordEvent({ event: "worker-recorded", phaseId: phase.phaseId }),
    /terminal|closed|completed|append/i,
  );
});

test("v2 lease release follows a durable action-completed append and fsyncs the surviving state parent", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "prune.apply");
  const root = tempDir(t);
  const ioProbe = durableIoProbe();
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48), { io: ioProbe.io });
  store.admitTrustedContext(trusted);
  const request = admittedRequest(phase.action, {}, trusted);
  const lease = store.acquire(request, trusted);
  const fixture = semanticFixture(t, phase, { trusted, lease, request });
  await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);

  const journal = journalFiles(root);
  const entries = assertJournalChain(root, request);
  assert.equal(entries.at(-1).event, "action-completed");
  assertJournalAppendFsyncOrder(
    root,
    journal.directory,
    [journal.entries.at(-1)],
    ioProbe.audit,
    "action-completed",
  );
  const releaseStart = ioProbe.audit.events.length;
  lease.release();
  assert.equal(fs.existsSync(path.join(root, "active.lock")), false);
  assertLeaseRemovalFsync(root, ioProbe.audit, releaseStart, "lease release");
});

test("v2 recovery exact-inspects every live worker before reverse-order deletion", async (t) => {
  const root = tempDir(t);
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48));
  store.admitTrustedContext(trusted);
  const request = admittedRequest("restore.drill.full", {}, trusted);
  const lease = store.acquire(request, trusted);
  const phases = [
    PHASE_CASES.find(({ phaseId }) => phaseId === "restore.capture"),
    PHASE_CASES.find(({ phaseId }) => phaseId === "restore.verify"),
  ];
  for (const [index, phase] of phases.entries()) {
    const name = `platform-action-${phase.phaseId.replaceAll(".", "-")}-${index}`;
    lease.recordWorker({
      action: phase.action,
      phaseId: phase.phaseId,
      resourceName: name,
      phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
      receiptDigest: trusted.receiptDigest,
    });
    lease.recordEvent({
      event: "worker-created",
      phaseId: phase.phaseId,
      resourceName: name,
      workerId: index === 0 ? WORKER_ID : RESTORE_WORKER_ID,
    });
  }
  lease.preserve();

  const lifecycle = [];
  const recoveryIo = durableIoProbe({
    onEvent(event) {
      if (event.type === "unlink" && event.file === path.join(root, "active.lock")) {
        lifecycle.push("lease-unlinked");
      }
    },
  });
  const transport = new OracleEngineTransport({
    trusted,
    phases,
    request,
    requestId: request.requestId,
    rawResults: phases.map((phase) => rawWorkerResult(phase, request.requestId)),
    recoveryOnly: true,
    onDelete: (id) => lifecycle.push(`worker-deleted:${id}`),
  });
  transport.seedRecoveryWorkers([
    { id: WORKER_ID, name: "platform-action-restore-capture-0", phase: phases[0] },
    { id: RESTORE_WORKER_ID, name: "platform-action-restore-verify-1", phase: phases[1] },
  ]);
  const executor = createSemanticExecutor({ transport });
  const restarted = createReplayStore(root, "b".repeat(48), { io: recoveryIo.io });
  await restarted.recover(executor);
  assertInspectAllBeforeDeleteAll(
    transport.calls,
    [
      "platform-action-restore-verify-1",
      "platform-action-restore-capture-0",
    ],
    [RESTORE_WORKER_ID, WORKER_ID],
    "two-worker recovery",
  );
  assert.deepEqual(lifecycle, [
    `worker-deleted:${RESTORE_WORKER_ID}`,
    `worker-deleted:${WORKER_ID}`,
    "lease-unlinked",
  ]);
  assert.equal(fs.existsSync(path.join(root, "active.lock")), false);
  assertLeaseRemovalFsync(root, recoveryIo.audit, 0, "worker recovery");
});

test("v2 multi-worker recovery preserves the exact tree when the second reverse inspect is hostile", async (t) => {
  for (const { id, mutate } of [
    ...INSPECT_WIDENINGS,
    widening("missing-inspect", () => null),
  ]) {
    await t.test(id, async (t) => {
      const root = tempDir(t);
      const trusted = directTrustedContext();
      const request = admittedRequest("restore.drill.full", {}, trusted);
      const phases = [findPhase("restore.capture"), findPhase("restore.verify")];
      const resourceNames = [
        "platform-action-restore-capture-batch",
        "platform-action-restore-verify-batch",
      ];
      const workerIds = [WORKER_ID, RESTORE_WORKER_ID];
      const store = createReplayStore(root, "a".repeat(48));
      store.admitTrustedContext(trusted);
      const lease = store.acquire(request, trusted);
      for (const [index, phase] of phases.entries()) {
        lease.recordWorker({
          action: phase.action,
          phaseId: phase.phaseId,
          phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
          receiptDigest: trusted.receiptDigest,
          requestSha256: fixtureSha256(canonicalFixtureJson(request)),
          resourceName: resourceNames[index],
        });
        lease.recordEvent({
          event: "worker-created",
          phaseId: phase.phaseId,
          resourceName: resourceNames[index],
          workerId: workerIds[index],
        });
      }
      lease.preserve();

      const transport = new OracleEngineTransport({
        inspectMutation: mutate,
        inspectMutationPhaseId: "restore.capture",
        phases,
        rawResults: phases.map((phase) => rawWorkerResult(phase, request.requestId)),
        recoveryOnly: true,
        request,
        requestId: request.requestId,
        trusted,
      });
      transport.seedRecoveryWorkers(phases.map((phase, index) => ({
        id: workerIds[index],
        name: resourceNames[index],
        phase,
      })));
      const recoveryIo = durableIoProbe();
      const preservedTree = captureTreeSnapshot(root);
      const recoveryStart = 0;
      const restarted = createReplayStore(root, "b".repeat(48), { io: recoveryIo.io });
      await assert.rejects(
        () => restarted.recover(createSemanticExecutor({ transport })),
        /absent|authority|forbidden|identity|image|inspect|exact|mismatch|missing|mount|name|network|recovery|worker/i,
      );
      assertInspectAllBeforeDeleteAll(
        transport.calls,
        [resourceNames[1], resourceNames[0]],
        [],
        `${id} batch recovery`,
      );
      assert.deepEqual(transport.deletedIds, []);
      assert.deepEqual(
        captureTreeSnapshot(root),
        preservedTree,
        `${id} changed lock bytes, inode, metadata or replay inventory`,
      );
      assertNoStateMutationEvents(
        recoveryIo.audit.events.slice(recoveryStart),
        root,
        `${id} batch recovery`,
      );
      assert.equal(fs.existsSync(path.join(root, "active.lock")), true);
    });
  }
});

test("v2 recovery independently rejects the complete inspect widening matrix or missing inspect", async (t) => {
  for (const { id, inspectMutation, seedWorker } of [
    ...INSPECT_WIDENINGS.map(({ id, mutate }) => ({
      id,
      inspectMutation: mutate,
      seedWorker: true,
    })),
    { id: "missing-inspect", inspectMutation: null, seedWorker: false },
  ]) {
    await t.test(id, async (t) => {
      const root = tempDir(t);
      const trusted = directTrustedContext();
      const phase = findPhase("prune.apply");
      const request = admittedRequest(phase.action, phase.parameters, trusted);
      const store = createReplayStore(root, "a".repeat(48));
      store.admitTrustedContext(trusted);
      const lease = store.acquire(request, trusted);
      const resourceName = `platform-action-prune-apply-recovery-${id}`;
      lease.recordWorker({
        action: phase.action,
        phaseId: phase.phaseId,
        phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
        receiptDigest: trusted.receiptDigest,
        requestSha256: fixtureSha256(canonicalFixtureJson(request)),
        resourceName,
      });
      lease.recordEvent({
        event: "worker-created",
        phaseId: phase.phaseId,
        resourceName,
        workerId: WORKER_ID,
      });
      lease.preserve();

      const transport = new OracleEngineTransport({
        inspectMutation,
        phases: [phase],
        rawResults: [rawWorkerResult(phase, request.requestId)],
        recoveryOnly: true,
        request,
        requestId: request.requestId,
        trusted,
      });
      if (seedWorker) {
        transport.seedRecoveryWorkers([{ id: WORKER_ID, name: resourceName, phase }]);
      }
      const recoveryIo = durableIoProbe();
      const executor = createSemanticExecutor({ transport });
      const preservedTree = captureTreeSnapshot(root);
      const recoveryStart = 0;
      const restarted = createReplayStore(root, "b".repeat(48), { io: recoveryIo.io });
      await assert.rejects(
        () => restarted.recover(executor),
        /absent|authority|forbidden|identity|image|inspect|exact|mismatch|missing|mount|name|network|recovery|worker/i,
      );
      assert.deepEqual(transport.deletedIds, []);
      assertInspectAllBeforeDeleteAll(
        transport.calls,
        [resourceName],
        [],
        `${id} prune recovery`,
      );
      assert.deepEqual(
        captureTreeSnapshot(root),
        preservedTree,
        `${id} changed the preserved prune lock/replay tree`,
      );
      assertNoStateMutationEvents(
        recoveryIo.audit.events.slice(recoveryStart),
        root,
        `${id} prune recovery`,
      );
      assert.equal(fs.existsSync(path.join(root, "active.lock")), true);
    });
  }
});

test("v2 recovery carries claimed-job lineage, exact-inspects its worker and cleans its sealed snapshot", async (t) => {
  const root = tempDir(t);
  const trusted = directTrustedContext();
  const phase = findPhase("job.backup.capture");
  const request = admittedRequest(phase.action, phase.parameters, trusted);
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const sealed = sealedSnapshot(phase.claimedJob, request);
  const store = createReplayStore(root, "a".repeat(48));
  store.admitTrustedContext(trusted);
  const lease = store.acquire(request, trusted);
  lease.recordEvent({
    event: "snapshot-materialized",
    phaseId: phase.phaseId,
    requestSha256,
    snapshot: sealed,
  });
  const resourceName = "platform-action-job-backup-recovery";
  lease.recordWorker({
    action: phase.action,
    phaseId: phase.phaseId,
    phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
    receiptDigest: trusted.receiptDigest,
    requestSha256,
    resourceName,
    snapshot: sealed,
  });
  lease.recordEvent({
    event: "worker-created",
    phaseId: phase.phaseId,
    resourceName,
    workerId: WORKER_ID,
  });
  lease.preserve();

  const lifecycle = [];
  const recoveryIo = durableIoProbe({
    onEvent(event) {
      if (event.type === "unlink" && event.file === path.join(root, "active.lock")) {
        lifecycle.push("lease-unlinked");
      }
    },
  });
  const snapshotFileStore = snapshotStoreFixture({
    onCleanup: () => lifecycle.push("snapshot-cleaned"),
  });
  const transport = new OracleEngineTransport({
    phases: [phase],
    rawResults: [rawWorkerResult(phase, request.requestId)],
    recoveryOnly: true,
    request,
    requestId: request.requestId,
    trusted,
    onDelete: () => lifecycle.push("worker-deleted"),
  });
  transport.seedRecoveryWorkers([{
    id: WORKER_ID,
    name: resourceName,
    phase,
    sealed,
  }]);
  const executor = createSemanticExecutor({ snapshotFileStore, transport });
  const restarted = createReplayStore(root, "b".repeat(48), { io: recoveryIo.io });
  await restarted.recover(executor);
  assertInspectAllBeforeDeleteAll(
    transport.calls,
    [resourceName],
    [WORKER_ID],
    "claimed-job recovery",
  );
  assert.deepEqual(snapshotFileStore.cleanupCalls, [sealed]);
  assert.deepEqual(lifecycle, ["worker-deleted", "snapshot-cleaned", "lease-unlinked"]);
  assert.equal(fs.existsSync(path.join(root, "active.lock")), false);
  assertLeaseRemovalFsync(root, recoveryIo.audit, 0, "claimed-job recovery");
});

test("v2 claimed-job recovery rejects the complete inspect widening matrix without cleanup or deletion", async (t) => {
  for (const { id, mutate, seedWorker = true } of [
    ...INSPECT_WIDENINGS,
    { id: "missing-inspect", mutate: null, seedWorker: false },
  ]) {
    await t.test(id, async (t) => {
      const root = tempDir(t);
      const trusted = directTrustedContext();
      const phase = findPhase("job.backup.capture");
      const request = admittedRequest(phase.action, phase.parameters, trusted);
      const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
      const sealed = sealedSnapshot(phase.claimedJob, request);
      const resourceName = "platform-action-job-backup-hostile-recovery";
      const store = createReplayStore(root, "a".repeat(48));
      store.admitTrustedContext(trusted);
      const lease = store.acquire(request, trusted);
      lease.recordEvent({
        event: "snapshot-materialized",
        phaseId: phase.phaseId,
        requestSha256,
        snapshot: sealed,
      });
      lease.recordWorker({
        action: phase.action,
        phaseId: phase.phaseId,
        phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
        receiptDigest: trusted.receiptDigest,
        requestSha256,
        resourceName,
        snapshot: sealed,
      });
      lease.recordEvent({
        event: "worker-created",
        phaseId: phase.phaseId,
        resourceName,
        workerId: WORKER_ID,
      });
      lease.preserve();

      const snapshotFileStore = snapshotStoreFixture();
      const transport = new OracleEngineTransport({
        inspectMutation: mutate,
        phases: [phase],
        rawResults: [rawWorkerResult(phase, request.requestId)],
        recoveryOnly: true,
        request,
        requestId: request.requestId,
        trusted,
      });
      if (seedWorker) {
        transport.seedRecoveryWorkers([{
          id: WORKER_ID,
          name: resourceName,
          phase,
          sealed,
        }]);
      }
      const recoveryIo = durableIoProbe();
      const preservedTree = captureTreeSnapshot(root);
      const recoveryStart = 0;
      const restarted = createReplayStore(root, "b".repeat(48), { io: recoveryIo.io });
      await assert.rejects(
        () => restarted.recover(createSemanticExecutor({
          snapshotFileStore,
          transport,
        })),
        /absent|authority|forbidden|identity|image|inspect|exact|mismatch|missing|mount|name|network|recovery|worker/i,
      );
      assertInspectAllBeforeDeleteAll(
        transport.calls,
        [resourceName],
        [],
        `${id} claimed-job recovery`,
      );
      assert.deepEqual(transport.deletedIds, []);
      assert.deepEqual(snapshotFileStore.cleanupCalls, []);
      assert.deepEqual(
        captureTreeSnapshot(root),
        preservedTree,
        `${id} changed the claimed-job lock/replay tree`,
      );
      assertNoStateMutationEvents(
        recoveryIo.audit.events.slice(recoveryStart),
        root,
        `${id} claimed-job recovery`,
      );
      assert.equal(fs.existsSync(path.join(root, "active.lock")), true);
    });
  }
});

testRunner("RED v2: real executor crash checkpoints and after-create recovery execute in a fresh process B", async (t) => {
  assert.deepEqual(
    {
      createSemanticActionExecutor: typeof broker.createSemanticActionExecutor,
      createSnapshotFileStore: typeof broker.createSnapshotFileStore,
    },
    {
      createSemanticActionExecutor: "function",
      createSnapshotFileStore: "function",
    },
    "process-B semantic recovery requires both exact production APIs",
  );
  for (const scenario of [
    {
      id: "after-seal",
      preRecoveryEvents: [],
      postRecoveryEvents: ["snapshot-cleaned"],
      workerCreated: false,
    },
    {
      id: "after-create",
      preRecoveryEvents: [
        "snapshot-materialized",
        "worker-recorded",
      ],
      postRecoveryEvents: [
        "snapshot-materialized",
        "worker-recorded",
        "worker-deleted",
        "snapshot-cleaned",
      ],
      workerCreated: true,
    },
  ]) {
    await t.test(scenario.id, async (t) => {
      const root = tempDir(t);
      const replayRoot = path.join(root, "replay");
      const mountpoint = path.join(root, "broker-state");
      fs.mkdirSync(mountpoint, { mode: 0o700 });
      const mountStat = fs.statSync(mountpoint);
      const lifecycle = [];
      const replayHistory = durableIoProbe({
        onEvent(event) {
          if (event.type === "unlink"
            && event.file === path.join(replayRoot, "active.lock")) {
            lifecycle.push("lease-unlinked");
          }
        },
      });
      const snapshotHistory = filesystemHistoryProbe();
      const realSnapshotStore = broker.createSnapshotFileStore({
        expectedGid: mountStat.gid,
        expectedUid: mountStat.uid,
        io: snapshotHistory.io,
      });
      const phase = findPhase("job.backup.capture");
      const trusted = directTrustedContext();
      const request = admittedRequest(phase.action, phase.parameters, trusted);
      const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
      const store = createReplayStore(
        replayRoot,
        "a".repeat(48),
        { io: replayHistory.io },
      );
      store.admitTrustedContext(trusted);
      const persistentLease = store.acquire(request, trusted);
      const crashError = Object.assign(
        new Error(`simulated abrupt process crash ${scenario.id}`),
        { simulatedProcessCrash: true },
      );
      let sealed;
      const crashSnapshotStore = {
        async seal(...args) {
          sealed = await realSnapshotStore.seal(...args);
          if (scenario.id === "after-seal") throw crashError;
          return sealed;
        },
        cleanup() {
          throw crashError;
        },
      };
      const liveTransport = new OracleEngineTransport({
        deleteError: crashError,
        phases: [phase],
        rawResults: [rawWorkerResult(phase, request.requestId)],
        request,
        requestId: request.requestId,
        sealedSnapshotProvider: () => sealed,
        trusted,
        onCreate: scenario.id === "after-create"
          ? () => {
              throw crashError;
            }
          : undefined,
        volumeMutation(inspect, logicalId) {
          return logicalId === "broker.state"
            ? { ...inspect, Mountpoint: mountpoint }
            : inspect;
        },
      });
      const executor = createSemanticExecutor({
        cleanupTimeoutMs: 100,
        claimedJobSnapshotProvider: async ({ parameters, sourceId }) => {
          assert.deepEqual(parameters, request.parameters);
          assert.equal(sourceId, "jobs.running");
          return {
            ...phase.claimedJob,
            bytes: Buffer.from(phase.claimedJob.bytes),
            sourceId,
          };
        },
        randomBytes: () => Buffer.alloc(12, 1),
        snapshotFileStore: crashSnapshotStore,
        transport: liveTransport,
      });
      await assert.rejects(
        () => executor.executePhase(phase.action, phase.phaseId, {
          lease: persistentLease,
          parameters: structuredClone(request.parameters),
          request: structuredClone(request),
          requestId: request.requestId,
          requestSha256,
          signal: new AbortController().signal,
          trusted,
        }),
        /abrupt|crash|cleanup|simulated/i,
      );
      persistentLease.preserve();
      assert.ok(sealed, `${scenario.id} did not complete the real snapshot seal`);
      assert.equal(fs.existsSync(sealed.hostPath), true);
      assert.equal(fs.existsSync(path.join(replayRoot, "active.lock")), true);
      assert.equal(liveTransport.created.length, scenario.workerCreated ? 1 : 0);
      assert.deepEqual(liveTransport.deletedIds, []);
      const resourceName = scenario.workerCreated
        ? liveTransport.created[0].name
        : null;
      const snapshotMaterializedEntry = {
        event: "snapshot-materialized",
        phaseId: phase.phaseId,
        requestSha256,
        snapshot: sealed,
      };
      const workerRecordedEntry = scenario.workerCreated
        ? {
            action: phase.action,
            event: "worker-recorded",
            phaseId: phase.phaseId,
            phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
            receiptDigest: trusted.receiptDigest,
            requestSha256,
            resourceName,
            snapshot: sealed,
          }
        : null;
      const preRecoveryExpected = scenario.workerCreated
        ? [snapshotMaterializedEntry, workerRecordedEntry]
        : [];
      const preRecoveryJournal = journalFiles(replayRoot);
      const preRecoveryEntries = assertJournalChain(replayRoot, request);
      assertExactJournalEntries(
        preRecoveryEntries,
        preRecoveryExpected,
        `${scenario.id} did not stop at the exact real journal checkpoint`,
      );
      if (preRecoveryJournal.entries.length > 0) {
        assertJournalAppendFsyncOrder(
          replayRoot,
          preRecoveryJournal.directory,
          preRecoveryJournal.entries,
          replayHistory.audit,
          `${scenario.id} pre-recovery journal`,
        );
      }
      if (scenario.id === "after-create") {
        assert.ok(resourceName);
        const replayStat = fs.statSync(replayRoot);
        assert.equal(replayStat.uid, mountStat.uid);
        assert.equal(replayStat.gid, mountStat.gid);
        const recoveryInputPath = path.join(root, "semantic-recovery-input.json");
        const recoveryReceiptPath = path.join(root, "semantic-recovery-receipt.json");
        const engineStatePath = path.join(root, "semantic-recovery-engine-state.json");
        const engineState = {
          schema: "platform.docker-action.recovery-engine-state/v1",
          workers: [{
            id: WORKER_ID,
            inspect: oracleWorkerInspect({
              id: WORKER_ID,
              name: resourceName,
              phase,
              requestId: request.requestId,
              sealed,
              trusted,
            }),
            name: resourceName,
          }],
        };
        writeDurableTestJson(engineStatePath, engineState);
        assert.deepEqual(
          readJson(engineStatePath),
          engineState,
          "after-create Engine state JSON did not round-trip exactly",
        );
        writeDurableTestJson(recoveryInputPath, {
          engineStatePath,
          expectedGid: mountStat.gid,
          expectedUid: mountStat.uid,
          journalDirectory: preRecoveryJournal.directory,
          now: NOW,
          recoveryBootId: "b".repeat(48),
          replayRoot,
          resourceName,
          sealed,
          workerId: WORKER_ID,
        });
        const recoveryChild = spawnSync(
          process.execPath,
          ["--input-type=module", "--eval", SEMANTIC_RECOVERY_CHILD_SOURCE],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              BROKER_MODULE_URL,
              BROKER_SEMANTIC_RECOVERY_INPUT: recoveryInputPath,
              BROKER_SEMANTIC_RECOVERY_RECEIPT: recoveryReceiptPath,
            },
            timeout: 15_000,
          },
        );
        assert.equal(
          recoveryChild.status,
          0,
          `after-create semantic recovery child B failed: ${
            recoveryChild.stderr || recoveryChild.error?.message || ""
          }`,
        );
        const receipt = readJson(recoveryReceiptPath);
        assertSemanticRecoveryProcessReceipt(receipt, {
          expectedJournalEvents: scenario.postRecoveryEvents,
          resourceName,
          workerId: WORKER_ID,
        });
        assert.equal(fs.existsSync(path.join(replayRoot, "active.lock")), false);
        assert.equal(fs.existsSync(sealed.hostPath), false);
        assert.equal(fs.existsSync(path.dirname(sealed.hostPath)), false);
        assert.deepEqual(readJson(engineStatePath), {
          schema: engineState.schema,
          workers: [],
        });
        const recoveredJournal = assertJournalDirectoryChain(
          preRecoveryJournal.directory,
          request,
        );
        const postRecoveryExpected = [
          ...preRecoveryExpected,
          {
            event: "worker-deleted",
            phaseId: phase.phaseId,
            resourceName,
            workerId: WORKER_ID,
          },
          {
            event: "snapshot-cleaned",
            phaseId: phase.phaseId,
            requestSha256,
            snapshot: sealed,
          },
        ];
        assertExactJournalEntries(
          receipt.journalEntries,
          postRecoveryExpected,
          "after-create child B persisted receipt journal",
        );
        assertExactJournalEntries(
          recoveredJournal.values,
          postRecoveryExpected,
          "after-create child B final on-disk journal",
        );
        return;
      }

      const snapshotCleanupStart = snapshotHistory.audit.events.length;
      const recoveryRealSnapshotStore = broker.createSnapshotFileStore({
        expectedGid: mountStat.gid,
        expectedUid: mountStat.uid,
        io: snapshotHistory.io,
      });
      const recoverySnapshotStore = {
        seal() {
          throw new Error("recovery must not create a new snapshot");
        },
        cleanup(candidate) {
          assert.deepEqual(candidate, sealed);
          const result = recoveryRealSnapshotStore.cleanup(candidate);
          lifecycle.push("snapshot-cleaned");
          return result;
        },
      };
      const recoveryTransport = new OracleEngineTransport({
        phases: [phase],
        rawResults: [rawWorkerResult(phase, request.requestId)],
        recoveryOnly: true,
        request,
        requestId: request.requestId,
        trusted,
        onDelete: (id) => lifecycle.push(`worker-deleted:${id}`),
      });
      if (scenario.workerCreated) {
        recoveryTransport.seedRecoveryWorkers([{
          id: WORKER_ID,
          name: resourceName,
          phase,
          sealed,
        }]);
      }
      const recoveryStart = replayHistory.audit.events.length;
      const restarted = createReplayStore(
        replayRoot,
        "b".repeat(48),
        { io: replayHistory.io },
      );
      await restarted.recover(createSemanticExecutor({
        snapshotFileStore: recoverySnapshotStore,
        transport: recoveryTransport,
      }));
      assert.equal(fs.existsSync(path.join(replayRoot, "active.lock")), false);
      assert.equal(fs.existsSync(sealed.hostPath), false);
      assertSnapshotCleanupHistory(snapshotHistory.audit.events, {
        historyStart: snapshotCleanupStart,
        label: `${scenario.id} recovery snapshot cleanup`,
        sealed,
      });
      assertInspectAllBeforeDeleteAll(
        recoveryTransport.calls,
        scenario.workerCreated ? [resourceName] : [],
        scenario.workerCreated ? [WORKER_ID] : [],
        `${scenario.id} real recovery`,
      );
      assert.deepEqual(
        lifecycle,
        scenario.workerCreated
          ? [`worker-deleted:${WORKER_ID}`, "snapshot-cleaned", "lease-unlinked"]
          : ["snapshot-cleaned", "lease-unlinked"],
      );
      const recoveredJournal = assertJournalDirectoryChain(
        preRecoveryJournal.directory,
        request,
      );
      const postRecoveryExpected = [
        ...preRecoveryExpected,
        ...(scenario.workerCreated
          ? [{
              event: "worker-deleted",
              phaseId: phase.phaseId,
              resourceName,
              workerId: WORKER_ID,
            }]
          : []),
        {
          event: "snapshot-cleaned",
          phaseId: phase.phaseId,
          requestSha256,
          snapshot: sealed,
        },
      ];
      assertExactJournalEntries(
        recoveredJournal.values,
        postRecoveryExpected,
        `${scenario.id} recovery did not append the exact cleanup journal`,
      );
      assertJournalAppendFsyncOrder(
        replayRoot,
        preRecoveryJournal.directory,
        recoveredJournal.entries,
        replayHistory.audit,
        `${scenario.id} recovered journal`,
        { allowActiveUnlink: true },
      );
      assertLeaseRemovalFsync(
        replayRoot,
        replayHistory.audit,
        recoveryStart,
        `${scenario.id} real recovery`,
      );
    });
  }
});

test("v2 offsite remote-unknown is terminal, preserves the lease and forbids automatic replay", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "offsite.sync");
  const root = tempDir(t);
  const ioProbe = durableIoProbe();
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48), { io: ioProbe.io });
  store.admitTrustedContext(trusted);
  const request = admittedRequest(phase.action, {}, trusted);
  const lease = store.acquire(request, trusted);
  const fixture = semanticFixture(t, phase, {
    trusted,
    lease,
    request,
    logsError: Object.assign(
      new Error("remote side effect completed but terminal receipt is unknown"),
      { remoteEffectUnknown: true },
    ),
  });
  let failure;
  try {
    await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);
  } catch (error) {
    failure = error;
  }
  assert.equal(failure?.remoteEffectUnknown, true);
  assert.equal(failure?.preserveLease, true);
  lease.preserve();
  const entries = assertJournalChain(root, request);
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const resourceName = fixture.transport.created[0].name;
  assertExactJournalEntries(
    entries,
    [
      {
        action: phase.action,
        event: "worker-recorded",
        phaseId: phase.phaseId,
        phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
        receiptDigest: trusted.receiptDigest,
        requestSha256,
        resourceName,
      },
      {
        event: "worker-created",
        phaseId: phase.phaseId,
        resourceName,
        workerId: WORKER_ID,
      },
      {
        event: "worker-deleted",
        phaseId: phase.phaseId,
        resourceName,
        workerId: WORKER_ID,
      },
      {
        event: "remote-effect-unknown",
        phaseId: phase.phaseId,
        resourceName,
        workerId: WORKER_ID,
      },
    ],
    "remote-effect-unknown exact journal",
  );
  assert.equal(entries.at(-1).event, "remote-effect-unknown");
  const journal = journalFiles(root);
  assertJournalAppendFsyncOrder(
    root,
    journal.directory,
    journal.entries,
    ioProbe.audit,
    "remote-effect-unknown",
  );
  assert.throws(
    () => store.acquire(admittedRequest(phase.action, {}, trusted), trusted),
    /another|remote|reconcile/i,
  );
  assert.equal(fixture.transport.created.length, 1);
  const recoveryTransport = new OracleEngineTransport({
    phases: [],
    rawResults: [],
    recoveryOnly: true,
    request,
    requestId: request.requestId,
    trusted,
  });
  const preservedBeforeRestart = captureTreeSnapshot(root);
  const recoveryIo = durableIoProbe();
  const recoveryStart = 0;
  const restarted = createReplayStore(root, "b".repeat(48), { io: recoveryIo.io });
  await assert.rejects(
    () => restarted.recover(createSemanticExecutor({ transport: recoveryTransport })),
    /remote|unknown|reconcile|terminal/i,
  );
  assert.deepEqual(recoveryTransport.calls, []);
  assert.equal(fs.existsSync(path.join(root, "active.lock")), true);
  assert.deepEqual(
    captureTreeSnapshot(root),
    preservedBeforeRestart,
    "remote-unknown restart changed the preserved lock/replay tree",
  );
  assertNoStateMutationEvents(
    recoveryIo.audit.events.slice(recoveryStart),
    root,
    "remote-unknown restart",
  );
});

rawFrameE2eTest("v2 raw signed frame preserves one full-request digest through core, lease, snapshot, journal and response", async (t) => {
  assert.equal(typeof broker.readClaimedJobSnapshot, "function");
  assert.equal(typeof broker.createSnapshotFileStore, "function");
  assert.equal(typeof broker.encodeActionResponseFrame, "function");
  const root = tempDir(t);
  const queueRoot = path.join(root, "queue");
  const brokerStateMountpoint = path.join(root, "broker-state");
  const replayRoot = path.join(root, "replay-state");
  fs.mkdirSync(queueRoot, { mode: 0o700 });
  fs.mkdirSync(brokerStateMountpoint, { mode: 0o700 });
  const stat = fs.statSync(root);
  const phase = findPhase("job.backup.capture");
  const { trusted } = buildFixtureTrustedContextV2({
    allowedActions: [phase.action],
    now: NOW,
  });
  const request = buildFixtureSignedActionRequestV2(
    phase.action,
    phase.parameters,
    {
      index: 2601,
      now: NOW,
      trustedContext: trusted,
    },
  );
  const canonicalRequestBytes = Buffer.from(canonicalFixtureJson(request));
  const rawFrame = Buffer.from(canonicalFixtureJson(request));
  const topLevelReorderedFrame = Buffer.from(JSON.stringify(
    Object.fromEntries(Object.entries(request).reverse()),
  ));
  const recursivelyReorderedParameters = Object.fromEntries(
    Object.entries(request.parameters).reverse(),
  );
  const nestedReorderedFrame = Buffer.from(`{${
    Object.keys(request)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${
        key === "parameters"
          ? JSON.stringify(recursivelyReorderedParameters)
          : canonicalFixtureJson(request[key])
      }`)
      .join(",")
  }}`);
  const requestSha256 = crypto
    .createHash("sha256")
    .update(canonicalRequestBytes)
    .digest("hex");
  assert.deepEqual(
    rawFrame,
    canonicalRequestBytes,
    "successful raw-frame control must be the exact canonical signed request wire",
  );
  for (const [label, hostileFrame] of [
    ["top-level", topLevelReorderedFrame],
    ["recursive parameters", nestedReorderedFrame],
  ]) {
    assert.deepEqual(
      JSON.parse(hostileFrame.toString("utf8")),
      request,
      `${label} reorder must preserve the same validly MACed request object`,
    );
    assert.notDeepEqual(
      hostileFrame,
      canonicalRequestBytes,
      `${label} reorder mutant accidentally remained canonical`,
    );
  }
  assert.equal(
    Object.keys(request.parameters).length >= 2,
    true,
    "recursive parameter-order mutant requires a nontrivial nested object",
  );
  const unsignedRequest = Object.fromEntries(
    Object.entries(request).filter(([key]) => key !== "mac"),
  );
  assert.notEqual(requestSha256, fixtureSha256(request.requestId));
  assert.notEqual(requestSha256, fixtureSha256(canonicalFixtureJson(unsignedRequest)));
  const queueFile = path.join(queueRoot, request.parameters.jobFileName);
  fs.writeFileSync(queueFile, BACKUP_JOB_BYTES, { mode: 0o600 });
  fs.chmodSync(queueFile, 0o600);

  let providerCalls = 0;
  let sealedSnapshotValue;
  const observed = {
    acquire: [],
    boundary: {
      capability: 0,
      engine: 0,
      replay: 0,
      trust: 0,
    },
    journalAtRelease: [],
    semantic: [],
    snapshot: [],
  };
  const snapshotHistory = filesystemHistoryProbe();
  const realSnapshotStore = broker.createSnapshotFileStore({
    expectedGid: stat.gid,
    expectedUid: stat.uid,
    io: snapshotHistory.io,
  });
  const snapshotFileStore = {
    async seal(snapshot, authority) {
      observed.snapshot.push({
        request: structuredClone(authority.request),
        requestId: authority.requestId,
        requestSha256: authority.requestSha256,
      });
      assert.deepEqual(authority.request, request);
      assert.equal(authority.requestId, request.requestId);
      assert.equal(authority.requestSha256, requestSha256);
      sealedSnapshotValue = await realSnapshotStore.seal(snapshot, authority);
      assert.match(sealedSnapshotValue.hostPath, new RegExp(`/${requestSha256}/job\\.json$`));
      return sealedSnapshotValue;
    },
    cleanup(sealed) {
      return realSnapshotStore.cleanup(sealed);
    },
  };
  const transport = new OracleEngineTransport({
    phases: [phase],
    rawResults: [rawWorkerResult(phase, request.requestId)],
    request,
    requestId: request.requestId,
    trusted,
    sealedSnapshotProvider: () => sealedSnapshotValue,
    volumeMutation(inspect, logicalId) {
      return logicalId === "broker.state"
        ? { ...inspect, Mountpoint: brokerStateMountpoint }
        : inspect;
    },
  });
  const semantic = broker.createSemanticActionExecutor({
    cleanupTimeoutMs: 100,
    claimedJobSnapshotProvider: async ({ parameters, sourceId }) => {
      providerCalls += 1;
      assert.equal(sourceId, "jobs.running");
      assert.deepEqual(parameters, request.parameters);
      const source = trusted.receipt.resources.claimedJobSources[sourceId];
      return broker.readClaimedJobSnapshot({
        parameters,
        policy: {
          expectedGid: stat.gid,
          expectedMode: 0o600,
          expectedUid: stat.uid,
          maximumBytes: source.maximumBytes,
          parentRoot: queueRoot,
        },
        source: { ...source, brokerRoot: queueRoot },
        sourceId,
      }, { io: claimedReaderIoProbe(queueFile).io });
    },
    randomBytes: () => Buffer.alloc(12, 0x32),
    snapshotFileStore,
    transport,
  });
  const engine = {
    recoverLease: semantic.recoverLease,
    async execute(action, context) {
      observed.boundary.engine += 1;
      observed.semantic.push({
        action,
        request: structuredClone(context.request),
        requestId: context.requestId,
        requestSha256: context.requestSha256,
      });
      assert.deepEqual(context.request, request);
      assert.equal(context.requestId, request.requestId);
      assert.equal(context.requestSha256, requestSha256);
      assert.deepEqual(context.lease.lineage.request, request);
      assert.equal(context.lease.lineage.requestSha256, requestSha256);
      return semantic.execute(action, context);
    },
  };

  const persistentReplayStore = createReplayStore(replayRoot, "a".repeat(48));
  let released = false;
  const replayStore = {
    admitActivation() {
      observed.boundary.replay += 1;
    },
    admitTrustedContext(...args) {
      observed.boundary.replay += 1;
      return persistentReplayStore.admitTrustedContext(...args);
    },
    consume(...args) {
      observed.boundary.replay += 1;
      return persistentReplayStore.consume(...args);
    },
    acquire(candidateRequest, candidateTrusted) {
      observed.boundary.replay += 1;
      observed.acquire.push({
        request: structuredClone(candidateRequest),
        requestSha256: fixtureSha256(canonicalFixtureJson(candidateRequest)),
      });
      assert.deepEqual(candidateRequest, request);
      assert.equal(observed.acquire.at(-1).requestSha256, requestSha256);
      const lease = persistentReplayStore.acquire(candidateRequest, candidateTrusted);
      const wrapped = {
        lineage: lease.lineage,
        preserve: () => lease.preserve(),
        recordEvent: (event) => lease.recordEvent(event),
        recordWorker: (event) => lease.recordWorker(event),
        release() {
          if (released) return;
          const active = readJson(path.join(replayRoot, "active.lock"));
          assert.deepEqual(active.request, request);
          assert.equal(active.requestSha256, requestSha256);
          observed.journalAtRelease = assertJournalChain(replayRoot, request);
          assert.ok(observed.journalAtRelease.length > 0);
          assert.equal(observed.journalAtRelease.at(-1).event, "action-completed");
          assert.equal(
            observed.journalAtRelease.every(
              (entry) => entry.requestSha256 === requestSha256,
            ),
            true,
          );
          released = true;
          return lease.release();
        },
      };
      assert.deepEqual(wrapped.lineage.request, request);
      assert.equal(wrapped.lineage.requestSha256, requestSha256);
      return Object.freeze(wrapped);
    },
  };
  const capabilityKey = fixtureCapabilityKey(request.action);
  const core = broker.createBrokerCore({
    capabilityProvider: async (action) => {
      observed.boundary.capability += 1;
      assert.equal(action, request.action);
      return capabilityKey;
    },
    engine,
    now: () => NOW,
    operationTimeoutMs: 1_000,
    replayStore,
    trustedContextProvider: async () => {
      observed.boundary.trust += 1;
      return trusted;
    },
  });
  for (const [label, hostileFrame] of [
    ["top-level", topLevelReorderedFrame],
    ["recursive parameters", nestedReorderedFrame],
  ]) {
    await assert.rejects(
      () => core.handle(hostileFrame),
      /canonical|wire|encoding|frame/i,
      `${label} noncanonical wire was admitted`,
    );
    assert.deepEqual(
      observed.boundary,
      {
        capability: 0,
        engine: 0,
        replay: 0,
        trust: 0,
      },
      `${label} noncanonical wire crossed a trust, capability, replay or Engine boundary`,
    );
    assert.equal(providerCalls, 0);
    assert.deepEqual(observed.acquire, []);
    assert.deepEqual(observed.semantic, []);
    assert.deepEqual(observed.snapshot, []);
  }

  for (const nestedAction of [
    `${request.action}.nested`,
    `nested.${request.action}`,
    `${request.action}-api`,
  ]) {
    const unsignedNestedActionRequest = {
      ...unsignedRequest,
      action: nestedAction,
    };
    const nestedActionRequest = {
      ...unsignedNestedActionRequest,
      mac: crypto
        .createHmac("sha256", capabilityKey)
        .update(`${REQUEST_SCHEMA_V2}\0`)
        .update(canonicalFixtureJson(unsignedNestedActionRequest))
        .digest("hex"),
    };
    await assert.rejects(
      () => core.handle(Buffer.from(canonicalFixtureJson(nestedActionRequest))),
      /action|authorized|exact|identity/i,
      `${nestedAction} was treated as the canonical action identity`,
    );
    assert.equal(
      observed.boundary.capability,
      0,
      "unknown nested action reached a capability provider via prefix matching",
    );
    assert.equal(observed.boundary.replay, 0);
    assert.equal(observed.boundary.engine, 0);
  }
  observed.boundary.trust = 0;

  const wire = await core.handle(rawFrame);
  assert.deepEqual(observed.boundary, {
    capability: 1,
    engine: 1,
    replay: 4,
    trust: 1,
  });
  assert.equal(providerCalls, 1);
  assert.equal(observed.acquire.length, 1);
  assert.equal(observed.semantic.length, 1);
  assert.equal(observed.snapshot.length, 1);
  assert.equal(released, true);
  assert.equal(fs.existsSync(path.join(replayRoot, "active.lock")), false);
  assert.ok(sealedSnapshotValue);
  assert.equal(fs.existsSync(sealedSnapshotValue.hostPath), false);
  assert.equal(wire.statusCode, 200);
  assert.deepEqual(Object.keys(wire.body).sort(), [
    "action",
    "errorCode",
    "mac",
    "requestId",
    "requestSha256",
    "result",
    "resultSha256",
    "schema",
    "status",
    "statusCode",
  ]);
  assert.equal(wire.body.schema, "platform.docker-action.response/v2");
  assert.equal(wire.body.status, "completed");
  assert.equal(wire.body.statusCode, 200);
  assert.equal(wire.body.errorCode, null);
  assert.equal(wire.body.action, request.action);
  assert.equal(wire.body.requestId, request.requestId);
  assert.equal(wire.body.requestSha256, requestSha256);
  assert.equal(
    wire.body.resultSha256,
    fixtureSha256(canonicalFixtureJson(wire.body.result)),
  );
  const unsignedResponse = Object.fromEntries(
    Object.entries(wire.body).filter(([key]) => key !== "mac"),
  );
  const expectedResponseMac = crypto
    .createHmac("sha256", capabilityKey)
    .update(`${wire.body.schema}\0`)
    .update(canonicalFixtureJson(unsignedResponse))
    .digest("hex");
  assert.equal(
    wire.body.mac,
    expectedResponseMac,
    "response MAC must authenticate the exact canonical unsigned response",
  );
  const encoded = broker.encodeActionResponseFrame(wire.body);
  const encodedBytes = Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded);
  assert.deepEqual(encodedBytes, Buffer.from(`${canonicalFixtureJson(wire.body)}\n`));
  assert.equal(encodedBytes.at(-1), 0x0a);
  assert.equal(encodedBytes.subarray(0, -1).includes(0x0a), false);
});

function semanticFixture(t, phase, options = {}) {
  const trusted = options.trusted ?? directTrustedContext();
  const request = options.request ?? admittedRequest(
    phase.action,
    phase.parameters,
    trusted,
    options.requestIndex,
  );
  const requestId = request.requestId;
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const snapshotStore = snapshotStoreFixture(options);
  let providerCalls = 0;
  const rawResult = rawWorkerResult(phase, requestId);
  const mutatedResult = options.resultMutation
    ? options.resultMutation(structuredClone(rawResult))
    : rawResult;
  const transport = new OracleEngineTransport({
    trusted,
    phases: [phase],
    request,
    requestId,
    rawResults: [mutatedResult],
    inspectMutation: options.inspectMutation,
    networkMutation: options.networkMutation,
    volumeMutation: options.volumeMutation,
    logsError: options.logsError,
    onCreate: options.onCreate,
  });
  const executor = createSemanticExecutor({
    cleanupTimeoutMs: 100,
    claimedJobSnapshotProvider: async ({ parameters, sourceId }) => {
      providerCalls += 1;
      assert.equal(sourceId, "jobs.running");
      assert.deepEqual(parameters, phase.parameters);
      return {
        ...phase.claimedJob,
        bytes: Buffer.from(phase.claimedJob.bytes),
        sourceId,
      };
    },
    randomBytes: () => Buffer.alloc(12, 1),
    snapshotFileStore: snapshotStore,
    transport,
  });
  const context = {
    lease: options.lease ?? recordingLease(request, trusted),
    parameters: structuredClone(phase.parameters),
    request: structuredClone(request),
    requestId,
    requestSha256,
    signal: new AbortController().signal,
    trusted,
  };
  return {
    context,
    executor,
    providerCalls: () => providerCalls,
    rawResult,
    request,
    requestSha256,
    sealedSnapshot: phase.claimedJob ? sealedSnapshot(phase.claimedJob, request) : null,
    snapshotStore,
    transport,
    trusted,
  };
}

function actionFixture(t, flow, options = {}) {
  const trusted = options.trusted ?? directTrustedContext();
  const request = options.request ?? admittedRequest(
    flow.action,
    flow.parameters,
    trusted,
    options.requestIndex,
  );
  const requestId = request.requestId;
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const snapshotStore = snapshotStoreFixture(options);
  const rawResults = flow.phases.map((phase) => rawWorkerResult(phase, requestId));
  const transport = new OracleEngineTransport({
    trusted,
    phases: flow.phases,
    request,
    requestId,
    rawResults,
    onCreate: options.onCreate,
    workerStatus: options.workerStatus,
  });
  const executor = createSemanticExecutor({
    cleanupTimeoutMs: 100,
    claimedJobSnapshotProvider: async ({ sourceId }) => {
      const phase = flow.phases.find(({ claimedJob }) => claimedJob);
      assert.ok(phase);
      return { ...phase.claimedJob, bytes: Buffer.from(phase.claimedJob.bytes), sourceId };
    },
    randomBytes: () => Buffer.alloc(12, 1),
    snapshotFileStore: snapshotStore,
    transport,
  });
  return {
    context: {
      lease: options.lease ?? recordingLease(request, trusted),
      parameters: structuredClone(flow.parameters),
      request: structuredClone(request),
      requestId,
      requestSha256,
      signal: new AbortController().signal,
      trusted,
    },
    executor,
    rawResults,
    request,
    requestSha256,
    snapshotStore,
    transport,
    trusted,
  };
}

function createSemanticExecutor(options) {
  assert.equal(
    typeof broker.createSemanticActionExecutor,
    "function",
    "docker-action-broker must export the already-admitted createSemanticActionExecutor seam",
  );
  const executor = broker.createSemanticActionExecutor(options);
  assert.equal(typeof executor?.execute, "function", "semantic executor execute API");
  assert.equal(typeof executor?.executePhase, "function", "semantic executor independently reachable phase API");
  assert.equal(typeof executor?.recoverLease, "function", "semantic executor recovery API");
  return executor;
}

class OracleEngineTransport {
  constructor({
    trusted,
    phases,
    request,
    requestId,
    rawResults,
    inspectMutation,
    inspectMutationPhaseId,
    networkMutation,
    volumeMutation,
    logsError,
    deleteError,
    onCreate,
    onDelete,
    sealedSnapshotProvider,
    workerStatus,
    recoveryOnly = false,
  }) {
    this.trusted = trusted;
    this.phases = phases;
    this.request = request;
    this.requestId = requestId;
    this.rawResults = rawResults;
    this.inspectMutation = inspectMutation;
    this.inspectMutationPhaseId = inspectMutationPhaseId;
    this.networkMutation = networkMutation;
    this.volumeMutation = volumeMutation;
    this.logsError = logsError;
    this.deleteError = deleteError;
    this.onCreate = onCreate;
    this.onDelete = onDelete;
    this.sealedSnapshotProvider = sealedSnapshotProvider;
    this.workerStatus = workerStatus ?? {};
    this.recoveryOnly = recoveryOnly;
    this.calls = [];
    this.created = [];
    this.startedIds = [];
    this.deletedIds = [];
    this.recoveryWorkers = [];
  }

  async inspectNetwork(id) {
    this.calls.push({ method: "inspectNetwork", id });
    const entry = Object.entries(this.trusted.receipt.resources.networks)
      .find(([, value]) => value.engineId === id);
    if (!entry) throw new Error(`oracle has no admitted network for ${id}`);
    const inspect = buildFixtureNetworkInspect(this.trusted.receipt, entry[0]);
    return this.networkMutation
      ? this.networkMutation(structuredClone(inspect), entry[0])
      : inspect;
  }

  async inspectVolume(name) {
    this.calls.push({ method: "inspectVolume", name });
    const entry = Object.entries(this.trusted.receipt.resources.volumes)
      .find(([, value]) => value.engineName === name);
    if (!entry) throw new Error(`oracle has no admitted volume for ${name}`);
    const inspect = buildFixtureVolumeInspect(this.trusted.receipt, entry[0]);
    return this.volumeMutation
      ? this.volumeMutation(structuredClone(inspect), entry[0])
      : inspect;
  }

  async createWorker(name, body) {
    assert.equal(this.recoveryOnly, false, "recovery attempted to create a worker");
    const phase = this.phases[this.created.length];
    assert.ok(phase, "executor created an unplanned phase");
    const id = this.created.length === 0 ? WORKER_ID : RESTORE_WORKER_ID;
    this.calls.push({ method: "createWorker", name, body: structuredClone(body), id });
    this.created.push({ body: structuredClone(body), id, name, phase });
    this.onCreate?.(phase, body);
    return { Id: id };
  }

  async inspectContainer(id) {
    this.calls.push({ method: "inspectContainer", id });
    const created = this.created.find((value) => value.id === id);
    assert.ok(created, `oracle has no created worker ${id}`);
    const sealed = created.phase.claimedJob
      ? this.sealedSnapshotProvider?.(created.phase)
        ?? sealedSnapshot(created.phase.claimedJob, this.request)
      : null;
    const inspect = oracleWorkerInspect({
      id,
      name: created.name,
      phase: created.phase,
      requestId: this.requestId,
      sealed,
      trusted: this.trusted,
    });
    if (!this.inspectMutation
      || (this.inspectMutationPhaseId
        && this.inspectMutationPhaseId !== created.phase.phaseId)) {
      return inspect;
    }
    const mutated = this.inspectMutation(structuredClone(inspect), created.phase);
    assert.notDeepEqual(
      mutated,
      inspect,
      `inspect mutation ${created.phase.phaseId} did not change the Engine response`,
    );
    return mutated;
  }

  async startContainer(id) {
    this.calls.push({ method: "startContainer", id });
    this.startedIds.push(id);
  }

  async waitContainer(id) {
    this.calls.push({ method: "waitContainer", id });
    const created = this.created.find((value) => value.id === id);
    return { StatusCode: this.workerStatus[created?.phase?.phaseId] ?? 0 };
  }

  async logsContainer(id) {
    this.calls.push({ method: "logsContainer", id });
    if (this.logsError) throw this.logsError;
    const index = this.created.findIndex((value) => value.id === id);
    return dockerFrame(`${JSON.stringify(this.rawResults[index])}\n`);
  }

  async deleteContainer(id) {
    this.calls.push({ method: "deleteContainer", id });
    if (this.deleteError) throw this.deleteError;
    this.deletedIds.push(id);
    this.onDelete?.(id);
  }

  async inspectContainerForRecovery(name) {
    this.calls.push({ method: "inspectContainerForRecovery", name });
    const worker = this.recoveryWorkers.find((value) => value.name === name);
    if (!worker) return null;
    const inspect = oracleWorkerInspect({
      id: worker.id,
      name: worker.name,
      phase: worker.phase,
      requestId: this.requestId,
      sealed: worker.sealed ?? null,
      trusted: this.trusted,
    });
    if (!this.inspectMutation
      || (this.inspectMutationPhaseId
        && this.inspectMutationPhaseId !== worker.phase.phaseId)) {
      return inspect;
    }
    const mutated = this.inspectMutation(structuredClone(inspect), worker.phase);
    assert.notDeepEqual(
      mutated,
      inspect,
      `recovery inspect mutation ${worker.phase.phaseId} did not change the Engine response`,
    );
    return mutated;
  }

  seedRecoveryWorkers(workers) {
    this.recoveryWorkers = workers.map((value) => ({ ...value }));
  }
}

function oracleWorkerInspect({ id, name, phase, requestId, sealed, trusted }) {
  const body = expectedWorkerBody(phase, trusted, sealed, requestId);
  const networkNames = phaseProfile(trusted.receipt, phase).networkIds.map(
    (logicalId) => trusted.receipt.resources.networks[logicalId].engineName,
  );
  return {
    Id: id,
    Name: `/${name}`,
    Image: phaseProfile(trusted.receipt, phase).workerImageId,
    Config: {
      Image: body.Image,
      Entrypoint: body.Entrypoint,
      Cmd: body.Cmd,
      Env: body.Env,
      User: body.User,
      WorkingDir: body.WorkingDir,
      NetworkDisabled: body.NetworkDisabled,
      AttachStdin: false,
      AttachStdout: false,
      AttachStderr: false,
      OpenStdin: false,
      StdinOnce: false,
      Tty: false,
      Labels: body.Labels,
    },
    HostConfig: expectedWorkerHostConfig(trusted.receipt, phase, sealed),
    Mounts: expectedInspectMounts(trusted.receipt, phase, sealed),
    NetworkSettings: {
      Networks: Object.fromEntries(networkNames.map((networkName) => {
        const network = Object.values(trusted.receipt.resources.networks)
          .find((value) => value.engineName === networkName);
        return [networkName, { Aliases: [], NetworkID: network.engineId }];
      })),
    },
  };
}

function expectedWorkerBody(phaseCaseValue, trusted, sealed, requestId) {
  const phase = phaseProfile(trusted.receipt, phaseCaseValue);
  const actionProfile = trusted.receipt.resources.actionProfiles[phaseCaseValue.action];
  const networkNames = phase.networkIds.map(
    (logicalId) => trusted.receipt.resources.networks[logicalId].engineName,
  );
  const authority = expectedPhaseAuthority(trusted.receipt, phaseCaseValue.action, phase.phaseId);
  const env = [
    "HOME=/tmp",
    "LANG=C.UTF-8",
    "NODE_ENV=production",
    `PLATFORM_DOCKER_ACTION=${phaseCaseValue.action}`,
    `PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64=${Buffer.from(canonicalFixtureJson(authority)).toString("base64url")}`,
    `PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256=${fixtureSha256(canonicalFixtureJson(authority))}`,
    `PLATFORM_DOCKER_PHASE_ID=${phase.phaseId}`,
    `PLATFORM_DOCKER_REQUEST_ID=${requestId}`,
  ];
  if (sealed) {
    env.push(
      `PLATFORM_CLAIMED_JOB_FILE_NAME=${sealed.jobFileName}`,
      `PLATFORM_CLAIMED_JOB_ID=${sealed.jobId}`,
      `PLATFORM_CLAIMED_JOB_OPERATION=${sealed.jobOperation}`,
      `PLATFORM_CLAIMED_JOB_PATH=${sealed.containerPath}`,
      `PLATFORM_CLAIMED_JOB_SHA256=${sealed.jobSha256}`,
      `PLATFORM_CLAIMED_JOB_SOURCE_ID=${sealed.sourceId}`,
    );
  }
  if (phase.writableSubpathIds.includes("backup.quarantine")) {
    env.push("PLATFORM_BACKUP_QUARANTINE_RELATIVE_PATH=.quarantine");
  }
  return {
    Image: phase.workerImageRef,
    Entrypoint: [
      "node",
      "--import",
      "/opt/platform-docker-worker/docker-action-worker-runtime-guard.mjs",
      "/opt/platform-docker-worker/docker-action-worker.mjs",
    ],
    Cmd: [phase.command],
    Env: env,
    User: "0:0",
    WorkingDir: "/opt/platform-docker-worker",
    NetworkDisabled: networkNames.length === 0,
    AttachStdin: false,
    AttachStdout: false,
    AttachStderr: false,
    OpenStdin: false,
    StdinOnce: false,
    Tty: false,
    Labels: {
      "com.platform.active-receipt-sha256": trusted.receiptDigest,
      "com.platform.docker-action": phaseCaseValue.action,
      "com.platform.docker-action-profile": actionProfile.profileId,
      "com.platform.docker-action-profile-sha256": actionProfile.profileSha256,
      "com.platform.docker-phase": phase.phaseId,
      "com.platform.docker-phase-sha256": phase.phaseSha256,
      "com.platform.runtime-intent": trusted.intent.intentId,
    },
    HostConfig: expectedWorkerHostConfig(trusted.receipt, phaseCaseValue, sealed),
    NetworkingConfig: {
      EndpointsConfig: Object.fromEntries(networkNames.map((name) => [name, { Aliases: [] }])),
    },
  };
}

function expectedWorkerHostConfig(receipt, phaseCaseValue, sealed) {
  const phase = phaseProfile(receipt, phaseCaseValue);
  const networkNames = phase.networkIds.map((id) => receipt.resources.networks[id].engineName);
  const binds = phase.mountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return `${mount.canonicalPath}:${mount.containerPath}:${mount.access}`;
  });
  if (sealed) binds.push(`${sealed.hostPath}:${sealed.containerPath}:ro`);
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
      "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
      "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
      "/proc/sched_debug", "/proc/scsi", "/sys/devices/virtual/powercap",
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
      "/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore",
      "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
      "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware",
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

function expectedInspectMounts(receipt, phaseCaseValue, sealed) {
  const phase = phaseProfile(receipt, phaseCaseValue);
  const binds = phase.mountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return {
      Type: "bind",
      Source: mount.canonicalPath,
      Destination: mount.containerPath,
      Mode: mount.access,
      RW: mount.access !== "ro",
      Propagation: "rprivate",
    };
  });
  if (sealed) {
    binds.push({
      Type: "bind",
      Source: sealed.hostPath,
      Destination: sealed.containerPath,
      Mode: "ro",
      RW: false,
      Propagation: "rprivate",
    });
  }
  const volumes = expectedNamedVolumeMounts(receipt, phase).map((mount) => ({
    Type: "volume",
    Name: mount.Source,
    Source: `/var/lib/docker/volumes/${mount.Source}/_data`,
    Destination: mount.Target,
    Driver: "local",
    Mode: "",
    RW: mount.ReadOnly !== true,
    Propagation: "",
  }));
  return [...binds, ...volumes];
}

function expectedNamedVolumeMounts(receipt, phase) {
  return [
    ...phase.workerSecretSetIds.map((secretSetId) => {
      const secretSet = receipt.resources.workerSecretSets[secretSetId];
      return {
        Type: "volume",
        Source: receipt.resources.volumes[secretSet.volumeId].engineName,
        Target: secretSet.containerRoot,
        ReadOnly: true,
        VolumeOptions: { NoCopy: true },
      };
    }),
    ...phase.scratchVolumeIds.map((volumeId) => ({
      Type: "volume",
      Source: receipt.resources.volumes[volumeId].engineName,
      Target: receipt.resources.volumes[volumeId].containerPath,
      ReadOnly: false,
      VolumeOptions: { NoCopy: true },
    })),
  ];
}

function assertExactBody(actual, phase, trusted, sealed, requestId) {
  assert.deepEqual(actual, expectedWorkerBody(phase, trusted, sealed, requestId));
  const serialized = canonicalFixtureJson(actual);
  assert.doesNotMatch(serialized, /docker\.sock|DOCKER_HOST|\/run\/secrets\/docker_action_/);
  assert.doesNotMatch(serialized, /PLATFORM_CLAIMED_JOB_BASE64/);
}

function rawWorkerResult(phaseCaseValue, requestId) {
  const phase = EXPECTED_PHASE_PROFILES[phaseCaseValue.phaseId];
  const output = buildFixturePhaseOutputV2(
    phaseCaseValue.action,
    phaseCaseValue.phaseId,
    phaseCaseValue.parameters,
  );
  return {
    schema: WORKER_RESULT_SCHEMA_V2,
    requestId,
    action: phaseCaseValue.action,
    phaseId: phaseCaseValue.phaseId,
    command: phase.command,
    job: phaseCaseValue.claimedJob
      ? {
          jobFileName: phaseCaseValue.claimedJob.jobFileName,
          jobId: phaseCaseValue.claimedJob.jobId,
          jobOperation: phaseCaseValue.claimedJob.jobOperation,
          jobSha256: phaseCaseValue.claimedJob.jobSha256,
        }
      : null,
    status: "completed",
    output,
  };
}

function expectedActionResult(phase, rawResult) {
  return {
    schema: RESULT_SCHEMA_V2,
    action: phase.action,
    job: rawResult.job,
    phases: [{
      output: rawResult.output,
      outputSchema: EXPECTED_PHASE_PROFILES[phase.phaseId].outputSchema,
      outputSha256: fixtureSha256(canonicalFixtureJson(rawResult.output)),
      phaseId: phase.phaseId,
      status: "completed",
    }],
    status: "completed",
  };
}

function expectedFlowResult(flow, rawResults) {
  return buildFixtureActionResultV2(flow.action, flow.parameters, {
    outputByPhaseId: Object.fromEntries(
      rawResults.map((rawResult, index) => [
        flow.phases[index].phaseId,
        rawResult.output,
      ]),
    ),
  });
}

function snapshotStoreFixture(options) {
  const calls = [];
  const cleanupCalls = [];
  return {
    calls,
    cleanupCalls,
    seal(snapshot, {
      request,
      requestId,
      requestSha256,
      source,
      volumeInspect,
    } = {}) {
      const sealedBytes = Buffer.from(snapshot.bytes);
      assert.equal(fixtureSha256(sealedBytes), snapshot.jobSha256);
      assert.deepEqual(request, admittedRequestShape(request));
      assert.equal(requestId, request.requestId);
      assert.equal(
        requestSha256,
        fixtureSha256(canonicalFixtureJson(request)),
        "snapshot lineage must hash the full canonical signed request",
      );
      assert.equal(source?.snapshotVolumeId, "broker.state");
      assert.equal(source?.snapshotVolumeSubpath, "claimed-jobs");
      assert.equal(source?.snapshotContainerPath, SNAPSHOT_CONTAINER_PATH);
      assert.equal(
        volumeInspect?.Name,
        "platform_infra_vps_docker_action_broker_state",
        "snapshot store must consume the exact-inspected broker.state volume",
      );
      assert.equal(path.isAbsolute(volumeInspect?.Mountpoint ?? ""), true);
      assert.equal(path.normalize(volumeInspect.Mountpoint), volumeInspect.Mountpoint);
      assert.doesNotMatch(volumeInspect.Mountpoint, /\0/);
      const result = Object.freeze({
        containerPath: source.snapshotContainerPath,
        hostPath: `${volumeInspect.Mountpoint}/${source.snapshotVolumeSubpath}/${requestSha256}/job.json`,
        jobFileName: snapshot.jobFileName,
        jobId: snapshot.jobId,
        jobOperation: snapshot.jobOperation,
        jobSha256: snapshot.jobSha256,
        requestSha256,
        snapshotVolumeId: source.snapshotVolumeId,
        snapshotVolumeMountpoint: volumeInspect.Mountpoint,
        snapshotVolumeName: volumeInspect.Name,
        snapshotVolumeSubpath: source.snapshotVolumeSubpath,
        sourceId: snapshot.sourceId,
      });
      calls.push({
        authority: structuredClone({
          request,
          requestId,
          requestSha256,
          source,
          volumeInspect,
        }),
        result,
        sealedBytes,
      });
      options.afterSeal?.(snapshot.bytes);
      return result;
    },
    cleanup(sealed) {
      cleanupCalls.push(structuredClone(sealed));
      if (options.cleanupError) throw options.cleanupError;
      options.onCleanup?.(structuredClone(sealed));
    },
  };
}

function sealedSnapshot(snapshot, request) {
  const receipt = buildRawActiveReceiptV2();
  const source = receipt.resources.claimedJobSources["jobs.running"];
  const volume = receipt.resources.volumes[source.snapshotVolumeId];
  const mountpoint = `/var/lib/docker/volumes/${volume.engineName}/_data`;
  admittedRequestShape(request);
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  return Object.freeze({
    containerPath: source.snapshotContainerPath,
    hostPath: `${mountpoint}/${source.snapshotVolumeSubpath}/${requestSha256}/job.json`,
    jobFileName: snapshot.jobFileName,
    jobId: snapshot.jobId,
    jobOperation: snapshot.jobOperation,
    jobSha256: snapshot.jobSha256,
    requestSha256,
    snapshotVolumeId: source.snapshotVolumeId,
    snapshotVolumeMountpoint: mountpoint,
    snapshotVolumeName: volume.engineName,
    snapshotVolumeSubpath: source.snapshotVolumeSubpath,
    sourceId: "jobs.running",
  });
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
        phase.writableSubpathIds.map((id) => [id, structuredClone(receipt.resources.writableSubpaths[id])]),
      ),
    },
  };
}

function directTrustedContext() {
  const receipt = buildRawActiveReceiptV2({ now: NOW });
  return Object.freeze({
    intent: Object.freeze({
      schema: "platform.docker-runtime-intent/v1",
      intentId: "intent.release-v2",
      allowedActions: [...SCHEDULER_ACTION_NAMES],
      generation: receipt.generation,
    }),
    receipt: Object.freeze(receipt),
    receiptDigest: fixtureSha256(canonicalFixtureJson(receipt)),
  });
}

function phaseCase(action, phaseId, job = null) {
  const expected = EXPECTED_ACTION_PHASES[action];
  const admitted = expected.phaseIds.includes(phaseId)
    || Object.values(expected.operationPhaseIds).some((ids) => ids.includes(phaseId));
  assert.equal(admitted, true, `${phaseId} is not owned by ${action}`);
  return Object.freeze({
    action,
    claimedJob: job,
    id: phaseId.replaceAll(".", "-"),
    parameters: job
      ? {
          jobFileName: job.jobFileName,
          jobId: job.jobId,
          jobOperation: job.jobOperation,
          jobSha256: job.jobSha256,
        }
      : Object.freeze({}),
    phaseId,
  });
}

function claimedJob({ bytes, jobFileName, jobId, jobOperation }) {
  return Object.freeze({
    bytes: Buffer.from(bytes),
    jobFileName,
    jobId,
    jobOperation,
    jobSha256: fixtureSha256(bytes),
    sourceId: "jobs.running",
  });
}

function claimedJobDocument({ id, operation, sourceManifestPath }) {
  const value = {
    ...createBackupJobDocument({
      id,
      operation,
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
      createdAt: JOB_CREATED_AT,
      ...(sourceManifestPath ? { sourceManifestPath } : {}),
    }),
    status: "running",
    startedAt: JOB_CREATED_AT,
    resultSummary: "Claimed by the scheduler.",
  };
  parseBackupJobDocument(value);
  return Object.freeze(value);
}

function actionFlows() {
  return [
    { id: "catalog", action: "backup.catalog", parameters: {}, phases: [findPhase("catalog.capture")] },
    { id: "job-backup", action: "backup.job.execute", parameters: findPhase("job.backup.capture").parameters, phases: [findPhase("job.backup.capture")] },
    { id: "job-restore", action: "backup.job.execute", parameters: findPhase("job.restore.verify").parameters, phases: [findPhase("job.restore.verify")] },
    { id: "prune-plan", action: "backup.prune.plan", parameters: {}, phases: [findPhase("prune.plan")] },
    { id: "prune-apply", action: "backup.prune.apply", parameters: {}, phases: [findPhase("prune.apply")] },
    { id: "restore-full", action: "restore.drill.full", parameters: {}, phases: [findPhase("restore.capture"), findPhase("restore.verify")] },
    { id: "offsite", action: "backup.offsite.sync", parameters: {}, phases: [findPhase("offsite.sync")] },
  ];
}

function findPhase(phaseId) {
  return PHASE_CASES.find((value) => value.phaseId === phaseId);
}

function phaseProfile(receipt, phaseCaseValue) {
  return receipt.resources.phaseProfiles[phaseCaseValue.phaseId];
}

function requiredPreflightIds(phaseCaseValue, receipt) {
  const phase = phaseProfile(receipt, phaseCaseValue);
  const volume = [
    ...phase.workerSecretSetIds.map((id) => receipt.resources.workerSecretSets[id].volumeId),
    ...phase.scratchVolumeIds,
  ];
  if (phaseCaseValue.claimedJob) {
    const source = receipt.resources.claimedJobSources["jobs.running"];
    volume.unshift("jobs.queue", source.snapshotVolumeId);
  }
  return { network: [...phase.networkIds], volume: [...new Set(volume)] };
}

function assertPreflightBeforeCreate(transport, phase, receipt) {
  const createIndex = transport.calls.findIndex(({ method }) => method === "createWorker");
  assert.ok(createIndex >= 0);
  assertExactPreflightInspectInventory(transport, phase, receipt);
  const required = requiredPreflightIds(phase, receipt);
  for (const logicalId of required.network) {
    const id = receipt.resources.networks[logicalId].engineId;
    const index = transport.calls.findIndex((call) => call.method === "inspectNetwork" && call.id === id);
    assert.ok(index >= 0 && index < createIndex, `${phase.phaseId} network ${logicalId} was not preflighted`);
  }
  for (const logicalId of required.volume) {
    const name = receipt.resources.volumes[logicalId].engineName;
    const index = transport.calls.findIndex((call) => call.method === "inspectVolume" && call.name === name);
    assert.ok(index >= 0 && index < createIndex, `${phase.phaseId} volume ${logicalId} was not preflighted`);
  }
}

function assertExactPreflightInspectInventory(transport, phase, receipt) {
  const required = requiredPreflightIds(phase, receipt);
  const expected = [
    ...required.network.map(
      (logicalId) => ["inspectNetwork", receipt.resources.networks[logicalId].engineId],
    ),
    ...required.volume.map(
      (logicalId) => ["inspectVolume", receipt.resources.volumes[logicalId].engineName],
    ),
  ].sort(([methodA, valueA], [methodB, valueB]) => (
    methodA.localeCompare(methodB) || valueA.localeCompare(valueB)
  ));
  const observed = transport.calls
    .filter(({ method }) => method === "inspectNetwork" || method === "inspectVolume")
    .map(({ id, method, name }) => [method, id ?? name])
    .sort(([methodA, valueA], [methodB, valueB]) => (
      methodA.localeCompare(methodB) || valueA.localeCompare(valueB)
    ));
  assert.deepEqual(
    observed,
    expected,
    `${phase.phaseId} must inspect every required logical resource exactly once`,
  );
}

function recordingLease(request, trusted) {
  const events = [];
  admittedRequestShape(request);
  const lineage = Object.freeze({
    action: request.action,
    intentId: trusted.intent.intentId,
    receiptDigest: trusted.receiptDigest,
    request: structuredClone(request),
    requestId: request.requestId,
    requestSha256: fixtureSha256(canonicalFixtureJson(request)),
  });
  return {
    events,
    lineage,
    recordEvent(event) { events.push(structuredClone(event)); },
    recordWorker(event) { events.push({ event: "worker-recorded", ...structuredClone(event) }); },
    preserve() { events.push({ event: "lease-preserved" }); },
    release() { events.push({ event: "lease-released" }); },
  };
}

function admittedRequest(action, parameters, trusted = directTrustedContext(), index) {
  const request = buildFixtureSignedActionRequestV2(action, parameters, {
    index: index ?? (requestSequence += 1),
    now: NOW,
    trustedContext: trusted,
  });
  assert.equal(request.schema, REQUEST_SCHEMA_V2);
  assert.match(request.mac, /^[a-f0-9]{64}$/);
  return Object.freeze(request);
}

function admittedRequestShape(request) {
  assert.deepEqual(Object.keys(request ?? {}).sort(), [
    "action",
    "activeReceiptSha256",
    "capabilityId",
    "combinedRenderSha256",
    "expiresAt",
    "issuedAt",
    "mac",
    "nonce",
    "parameters",
    "requestId",
    "runtimeIntentId",
    "schema",
  ]);
  assert.equal(request?.schema, REQUEST_SCHEMA_V2);
  assert.match(request?.requestId ?? "", /^[0-9a-f-]{36}$/);
  assert.match(request?.nonce ?? "", /^[A-Za-z0-9_-]{43}$/);
  assert.match(request?.mac ?? "", /^[a-f0-9]{64}$/);
  assert.equal(typeof request?.action, "string");
  assert.equal(typeof request?.parameters, "object");
  return request;
}

function createReplayStore(root, bootId, { io = fs } = {}) {
  return new broker.PersistentReplayStore(root, {
    now: () => NOW,
    bootId,
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
    io,
  });
}

async function preservedJournalFixture(t) {
  const phase = findPhase("prune.apply");
  const root = tempDir(t);
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48));
  store.admitTrustedContext(trusted);
  const request = admittedRequest(phase.action, {}, trusted);
  const lease = store.acquire(request, trusted);
  const fixture = semanticFixture(t, phase, { trusted, lease, request });
  await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);
  lease.preserve();
  return { fixture, lease, request, root, store, trusted };
}

function journalFiles(root) {
  const active = readJson(path.join(root, "active.lock"));
  assert.equal(active.schema, LEASE_SCHEMA_V2);
  const directory = path.join(root, "journal", active.leaseId);
  const entries = fs.readdirSync(directory).sort().map((name) => path.join(directory, name));
  return { active, directory, entries, root };
}

function assertJournalChain(root, expectedRequest) {
  const { active, directory } = journalFiles(root);
  const request = expectedRequest ?? active.request;
  admittedRequestShape(request);
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  assert.deepEqual(active.request, request);
  assert.equal(active.requestId, request.requestId);
  assert.equal(active.requestSha256, requestSha256);
  assert.equal(active.action, request.action);
  const { head, values } = assertJournalDirectoryChain(directory, request);
  assert.equal(active.journalEntryCount, values.length);
  assert.equal(active.journalHeadSha256, head);
  return values;
}

function assertJournalDirectoryChain(directory, request) {
  admittedRequestShape(request);
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const entries = fs.readdirSync(directory)
    .sort()
    .map((name) => path.join(directory, name));
  let previous = "0".repeat(64);
  const leaseId = path.basename(directory);
  const values = entries.map((file, index) => {
    const value = readJson(file);
    assert.equal(value.schema, JOURNAL_ENTRY_SCHEMA_V2);
    assert.equal(value.leaseId, leaseId);
    assert.equal(value.recordedAt, new Date(NOW).toISOString());
    assert.equal(value.sequence, index);
    assert.equal(value.previousEntrySha256, previous);
    assert.equal(value.requestId, request.requestId);
    assert.equal(value.requestSha256, requestSha256);
    assert.equal(value.action, request.action);
    previous = fixtureSha256(canonicalFixtureJson(value));
    return value;
  });
  return { entries, head: previous, values };
}

function assertExactJournalEventKeys(entry, expectedFields, label) {
  const expectedKeys = [...new Set([
    "action",
    "event",
    "leaseId",
    "previousEntrySha256",
    "recordedAt",
    "requestId",
    "requestSha256",
    "schema",
    "sequence",
    ...Object.keys(expectedFields),
  ])].sort();
  assert.deepEqual(
    Object.keys(entry).sort(),
    expectedKeys,
    `${label} must contain only its exact canonical fields`,
  );
}

function assertExactJournalEntries(entries, expectedEntries, label) {
  assert.equal(
    entries.length,
    expectedEntries.length,
    `${label}: journal entry count is not exact`,
  );
  for (const [index, expected] of expectedEntries.entries()) {
    const entry = entries[index];
    assert.equal(entry.event, expected.event, `${label}: event ${index} is not exact`);
    assertExactJournalEventKeys(entry, expected, `${label}: ${expected.event}`);
    for (const [field, value] of Object.entries(expected)) {
      assert.deepEqual(
        entry[field],
        value,
        `${label}: ${expected.event}.${field} is not exact`,
      );
    }
  }
}

function assertExactRealExecutionJournal(entries, {
  phase,
  rawResult,
  request,
  resourceName,
  sealed,
  trusted,
  workerId,
}) {
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  const expectedResourceName = `platform-action-${phase.phaseId.replaceAll(".", "-")}-${"01".repeat(12)}`;
  assert.equal(
    resourceName,
    expectedResourceName,
    "real executor used a noncanonical or caller-derived worker resource name",
  );
  assert.deepEqual(
    entries.map(({ event }) => event),
    [
      "snapshot-materialized",
      "worker-recorded",
      "worker-created",
      "worker-result-recorded",
      "worker-deleted",
      "snapshot-cleaned",
      "action-completed",
    ],
    "real claimed-job execution journal sequence is not exact",
  );
  const expectedByEvent = {
    "snapshot-materialized": {
      phaseId: phase.phaseId,
      requestSha256,
      snapshot: sealed,
    },
    "worker-recorded": {
      action: phase.action,
      phaseId: phase.phaseId,
      phaseProfileSha256: trusted.receipt.resources.phaseProfiles[phase.phaseId].phaseSha256,
      receiptDigest: trusted.receiptDigest,
      requestSha256,
      resourceName,
      snapshot: sealed,
    },
    "worker-created": {
      phaseId: phase.phaseId,
      resourceName,
      workerId,
    },
    "worker-result-recorded": {
      phaseId: phase.phaseId,
      resourceName,
      workerId,
      workerResultSha256: fixtureSha256(canonicalFixtureJson(rawResult)),
    },
    "worker-deleted": {
      phaseId: phase.phaseId,
      resourceName,
      workerId,
    },
    "snapshot-cleaned": {
      phaseId: phase.phaseId,
      requestSha256,
      snapshot: sealed,
    },
    "action-completed": {
      requestSha256,
      resultSha256: fixtureSha256(canonicalFixtureJson(
        expectedActionResult(phase, rawResult),
      )),
    },
  };
  for (const entry of entries) {
    const expected = expectedByEvent[entry.event];
    assert.ok(expected, `unexpected journal event ${entry.event}`);
    assertExactJournalEventKeys(entry, expected, entry.event);
    for (const [field, value] of Object.entries(expected)) {
      assert.equal(
        Object.hasOwn(entry, field),
        true,
        `${entry.event} is missing exact field ${field}`,
      );
      assert.deepEqual(entry[field], value, `${entry.event}.${field} is not exact`);
    }
  }
}

function assertDurableBarrier(root, phaseId, request) {
  const entries = assertJournalChain(root, request);
  assert.equal(
    entries.some((entry) => entry.event === "worker-result-recorded" && entry.phaseId === phaseId),
    true,
    `${phaseId} result barrier is not durable`,
  );
  assert.equal(
    entries.some((entry) => entry.event === "worker-deleted" && entry.phaseId === phaseId),
    true,
    `${phaseId} cleanup barrier is not durable`,
  );
}

function journalMutation(id, apply) {
  return Object.freeze({ id, apply });
}

function widening(id, mutate) {
  return Object.freeze({ id, mutate });
}

function mutateEnv(inspect, key, value) {
  const env = environmentMap(inspect.Config.Env);
  env[key] = value;
  return {
    ...inspect,
    Config: {
      ...inspect.Config,
      Env: Object.entries(env).map(([name, content]) => `${name}=${content}`),
    },
  };
}

function mutateEnvToDifferent(inspect, key, preferred, alternate) {
  const current = environmentMap(inspect.Config.Env)[key];
  return mutateEnv(inspect, key, current === preferred ? alternate : preferred);
}

function removeInspectEnvEntry(inspect) {
  assert.ok(inspect.Config.Env.length > 0, "inspect Env removal requires a positive control");
  return {
    ...inspect,
    Config: {
      ...inspect.Config,
      Env: inspect.Config.Env.slice(1),
    },
  };
}

function duplicateInspectEnvEntry(inspect) {
  assert.ok(inspect.Config.Env.length > 0, "inspect Env duplication requires a positive control");
  return {
    ...inspect,
    Config: {
      ...inspect.Config,
      Env: [...inspect.Config.Env, inspect.Config.Env[0]],
    },
  };
}

function mutateInspectConfig(inspect, field, value) {
  return {
    ...inspect,
    Config: {
      ...inspect.Config,
      [field]: structuredClone(value),
    },
  };
}

function differentExactValue(value) {
  if (value === null) return { attacker: true };
  if (value === undefined) return "attacker";
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") return value + 1;
  if (typeof value === "string") return `${value}-attacker`;
  if (Array.isArray(value)) return [...structuredClone(value), "__attacker__"];
  return { ...structuredClone(value), __attacker__: true };
}

function mutateInspectHostConfig(inspect, field) {
  assert.equal(
    Object.hasOwn(inspect.HostConfig, field),
    true,
    `HostConfig positive control is missing ${field}`,
  );
  return {
    ...inspect,
    HostConfig: {
      ...inspect.HostConfig,
      [field]: differentExactValue(inspect.HostConfig[field]),
    },
  };
}

function mutateInspectMount(inspect, field) {
  const mounts = inspect.Mounts.length > 0
    ? structuredClone(inspect.Mounts)
    : [{
        Type: "bind",
        Source: "/var/lib/platform/positive",
        Destination: "/run/platform/positive",
        Mode: "ro",
        RW: false,
        Propagation: "rprivate",
      }];
  mounts[0] = {
    ...mounts[0],
    [field]: differentExactValue(mounts[0][field]),
  };
  return { ...inspect, Mounts: mounts };
}

function mutateSnapshotBind(inspect, mutation) {
  const mounts = structuredClone(inspect.Mounts);
  let index = mounts.findIndex(
    ({ Destination }) => Destination === SNAPSHOT_CONTAINER_PATH,
  );
  if (index < 0) {
    mounts.push({
      Type: "bind",
      Source: "/var/lib/platform/unexpected/job.json",
      Destination: SNAPSHOT_CONTAINER_PATH,
      Mode: "ro",
      RW: false,
      Propagation: "rprivate",
    });
    index = mounts.length - 1;
  }
  mounts[index] = { ...mounts[index], ...structuredClone(mutation) };
  return { ...inspect, Mounts: mounts };
}

function environmentMap(values) {
  const result = {};
  for (const entry of values) {
    const delimiter = entry.indexOf("=");
    assert.ok(delimiter > 0, `malformed env: ${entry}`);
    const key = entry.slice(0, delimiter);
    assert.equal(Object.hasOwn(result, key), false, `duplicate env: ${key}`);
    result[key] = entry.slice(delimiter + 1);
  }
  return result;
}

function dockerFrame(text) {
  const payload = Buffer.from(text);
  const header = Buffer.alloc(8);
  header[0] = 1;
  header.writeUInt32BE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${canonicalFixtureJson(value)}\n`);
}

function claimedReaderFixture(t) {
  const root = tempDir(t);
  const queueRoot = path.join(root, "running");
  fs.mkdirSync(queueRoot, { mode: 0o700 });
  const file = path.join(queueRoot, `${BACKUP_JOB_ID}.json`);
  fs.writeFileSync(file, BACKUP_JOB_BYTES, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  const stat = fs.statSync(queueRoot);
  const receipt = buildRawActiveReceiptV2();
  const canonicalSource = receipt.resources.claimedJobSources["jobs.running"];
  const parameters = structuredClone(findPhase("job.backup.capture").parameters);
  return {
    file,
    parameters,
    input: {
      parameters,
      policy: {
        expectedGid: stat.gid,
        expectedMode: 0o600,
        expectedUid: stat.uid,
        maximumBytes: canonicalSource.maximumBytes,
        parentRoot: queueRoot,
      },
      source: { ...canonicalSource, brokerRoot: queueRoot },
      sourceId: "jobs.running",
    },
  };
}

function claimedReaderIoProbe(file, {
  afterFirstDescriptorRead,
  freezeMetadata = false,
  metadataRace = false,
} = {}) {
  const resolvedFile = path.resolve(file);
  const expectedBytes = fs.statSync(resolvedFile).size;
  const audit = {
    completedReadPasses: [],
    descriptorReadFileCalls: 0,
    events: [],
    fstats: [],
    opens: [],
    pathReadFileCalls: 0,
    raceInjectedAfterPass: null,
    readSyncCalls: [],
    startedReadPasses: [],
  };
  let baselineStat;
  let currentPass = null;
  let leafDescriptor;
  let postMetadata = false;
  const io = new Proxy(fs, {
    get(target, property) {
      if (property === "openSync") {
        return (candidate, flags, mode) => {
          const descriptor = fs.openSync(candidate, flags, mode);
          const resolved = path.resolve(String(candidate));
          audit.opens.push({
            descriptor,
            file: resolved,
            flags,
            mode,
          });
          if (resolved === resolvedFile) leafDescriptor = descriptor;
          return descriptor;
        };
      }
      if (property === "readFileSync") {
        return (descriptor, ...args) => {
          const value = fs.readFileSync(descriptor, ...args);
          if (typeof descriptor === "number") {
            audit.descriptorReadFileCalls += 1;
          } else {
            audit.pathReadFileCalls += 1;
          }
          return value;
        };
      }
      if (property === "readSync") {
        return (descriptor, buffer, offsetOrOptions, length, position) => {
          const options = offsetOrOptions && typeof offsetOrOptions === "object"
            ? offsetOrOptions
            : {
                offset: offsetOrOptions,
                length,
                position,
              };
          const performRead = () => (
            offsetOrOptions && typeof offsetOrOptions === "object"
              ? fs.readSync(descriptor, buffer, offsetOrOptions)
              : fs.readSync(descriptor, buffer, offsetOrOptions, length, position)
          );
          const explicitPosition = options.position;
          if (descriptor !== leafDescriptor) {
            return performRead();
          }
          assert.equal(
            Number.isInteger(explicitPosition) && explicitPosition >= 0,
            true,
            "claimed-job descriptor reads must use an explicit non-negative position",
          );
          if (currentPass?.complete && explicitPosition === expectedBytes) {
            const count = performRead();
            audit.readSyncCalls.push({
              bytes: count,
              descriptor,
              pass: currentPass.index,
              position: explicitPosition,
            });
            assert.equal(count, 0, "a positioned EOF probe returned unexpected bytes");
            return count;
          }
          if (!currentPass || currentPass.complete) {
            assert.equal(
              explicitPosition,
              0,
              "each complete claimed-job descriptor pass must restart at position zero",
            );
            currentPass = {
              bytes: 0,
              complete: false,
              descriptor,
              index: audit.completedReadPasses.length,
              initialPosition: explicitPosition,
              nextPosition: 0,
            };
            audit.startedReadPasses.push({
              descriptor,
              initialPosition: explicitPosition,
              pass: currentPass.index,
            });
            audit.events.push({
              type: "read-pass-start",
              descriptor,
              pass: currentPass.index,
              position: explicitPosition,
            });
          }
          assert.equal(
            explicitPosition,
            currentPass.nextPosition,
            "claimed-job descriptor pass skipped or repeated a byte range",
          );
          const count = performRead();
          audit.readSyncCalls.push({
            bytes: count,
            descriptor,
            pass: currentPass.index,
            position: explicitPosition,
          });
          currentPass.bytes += count;
          currentPass.nextPosition += count;
          assert.ok(
            currentPass.bytes <= expectedBytes,
            "claimed-job descriptor pass exceeded the attested file size",
          );
          if (currentPass.bytes === expectedBytes && !currentPass.complete) {
            currentPass.complete = true;
            audit.completedReadPasses.push({
              bytes: currentPass.bytes,
              descriptor,
              initialPosition: currentPass.initialPosition,
              pass: currentPass.index,
            });
            audit.events.push({
              type: "read-pass-complete",
              bytes: currentPass.bytes,
              descriptor,
              pass: currentPass.index,
            });
            if (currentPass.index === 0) {
              audit.raceInjectedAfterPass = 1;
              afterFirstDescriptorRead?.();
              audit.events.push({
                type: "first-pass-hook-complete",
                descriptor,
                pass: currentPass.index,
              });
              postMetadata = true;
            }
          }
          return count;
        };
      }
      if (property === "fstatSync") {
        return (descriptor, ...args) => {
          const value = fs.fstatSync(descriptor, ...args);
          if (descriptor !== leafDescriptor) return value;
          audit.fstats.push(descriptor);
          audit.events.push({ type: "fstat", descriptor });
          baselineStat ??= value;
          if (freezeMetadata) return baselineStat;
          if (!metadataRace || !postMetadata || audit.fstats.length < 2) return value;
          return new Proxy(value, {
            get(targetStat, key) {
              if (key === "ino") return targetStat.ino + 1;
              if (key === "mtimeMs") return targetStat.mtimeMs + 1;
              if (key === "ctimeMs") return targetStat.ctimeMs + 1;
              return Reflect.get(targetStat, key);
            },
          });
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { audit, io };
}

function statIdentityIo(io, { uid, gid }) {
  const withIdentity = (stat) => {
    if (!stat || typeof stat !== "object") return stat;
    return new Proxy(stat, {
      get(target, property) {
        if (property === "uid") return uid;
        if (property === "gid") return gid;
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  return new Proxy(io, {
    get(target, property) {
      if (["fstatSync", "lstatSync", "statSync"].includes(property)) {
        return (...args) => withIdentity(Reflect.get(target, property)(...args));
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function pathStatMutationIo(io, {
  defaultGid,
  defaultUid,
  mutations = new Map(),
} = {}) {
  const descriptors = new Map();
  const normalizeMutations = new Map(
    [...mutations.entries()].map(([candidate, mutation]) => [
      path.resolve(candidate),
      mutation,
    ]),
  );
  const transform = (stat, candidate) => {
    if (!stat || typeof stat !== "object") return stat;
    const mutation = normalizeMutations.get(candidate) ?? {};
    return new Proxy(stat, {
      get(target, property) {
        if (property === "uid" && mutation.uid !== undefined) return mutation.uid;
        if (property === "uid" && defaultUid !== undefined) return defaultUid;
        if (property === "gid" && mutation.gid !== undefined) return mutation.gid;
        if (property === "gid" && defaultGid !== undefined) return defaultGid;
        if (property === "mode" && mutation.permissions !== undefined) {
          return (target.mode & ~0o777) | mutation.permissions;
        }
        if (property === "nlink" && mutation.nlink !== undefined) return mutation.nlink;
        if (property === "isFile" && mutation.kind) {
          return () => mutation.kind === "file";
        }
        if (property === "isDirectory" && mutation.kind) {
          return () => mutation.kind === "directory";
        }
        if (property === "isSymbolicLink" && mutation.kind) {
          return () => mutation.kind === "symlink";
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  return new Proxy(io, {
    get(target, property) {
      if (property === "openSync") {
        return (candidate, ...args) => {
          const descriptor = Reflect.get(target, property)(candidate, ...args);
          descriptors.set(descriptor, path.resolve(String(candidate)));
          return descriptor;
        };
      }
      if (property === "closeSync") {
        return (descriptor, ...args) => {
          const result = Reflect.get(target, property)(descriptor, ...args);
          descriptors.delete(descriptor);
          return result;
        };
      }
      if (property === "fstatSync") {
        return (descriptor, ...args) => transform(
          Reflect.get(target, property)(descriptor, ...args),
          descriptors.get(descriptor),
        );
      }
      if (property === "lstatSync" || property === "statSync") {
        return (candidate, ...args) => transform(
          Reflect.get(target, property)(candidate, ...args),
          path.resolve(String(candidate)),
        );
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

const UNINSTRUMENTED_MUTATING_FS_APIS = new Set([
  "appendFile",
  "appendFileSync",
  "chmod",
  "chown",
  "copyFile",
  "cp",
  "cpSync",
  "createWriteStream",
  "fchmod",
  "fchmodSync",
  "fchown",
  "fchownSync",
  "fdatasync",
  "fdatasyncSync",
  "ftruncate",
  "futimes",
  "futimesSync",
  "link",
  "lchmod",
  "lchown",
  "lchownSync",
  "lutimes",
  "mkdir",
  "mkdtemp",
  "mkdtempSync",
  "open",
  "openAsBlob",
  "rename",
  "rm",
  "rmdir",
  "symlink",
  "truncate",
  "unlink",
  "utimes",
  "write",
  "writeFile",
  "writev",
  "writevSync",
]);

const PROVEN_READ_ONLY_FS_APIS = new Set([
  "access",
  "accessSync",
  "exists",
  "existsSync",
  "fstat",
  "fstatSync",
  "lstat",
  "lstatSync",
  "opendir",
  "opendirSync",
  "read",
  "readFile",
  "readFileSync",
  "readdir",
  "readdirSync",
  "readlink",
  "readlinkSync",
  "readSync",
  "readv",
  "readvSync",
  "realpath",
  "realpathSync",
  "stat",
  "statfs",
  "statfsSync",
  "statSync",
]);

const PROVEN_READ_ONLY_PROMISE_FS_APIS = new Set([
  "access",
  "lstat",
  "opendir",
  "readFile",
  "readdir",
  "readlink",
  "realpath",
  "stat",
  "statfs",
]);

const EXACT_TIMESTAMP_ALIAS_FIELDS = Object.freeze([
  "atime",
  "atimeMs",
  "atimeNs",
  "ctime",
  "ctimeMs",
  "ctimeNs",
  "mtime",
  "mtimeMs",
  "mtimeNs",
]);

function timestampAliasValues(stat) {
  return Object.freeze({
    atime: new Date(stat.atime.getTime()),
    atimeMs: stat.atimeMs,
    atimeNs: stat.atimeNs,
    ctime: new Date(stat.ctime.getTime()),
    ctimeMs: stat.ctimeMs,
    ctimeNs: stat.ctimeNs,
    mtime: new Date(stat.mtime.getTime()),
    mtimeMs: stat.mtimeMs,
    mtimeNs: stat.mtimeNs,
  });
}

function serializedTimestampAliasValues(values) {
  return Object.freeze({
    atimeEpochMs: String(values.atime.getTime()),
    atimeMs: String(values.atimeMs),
    atimeNs: String(values.atimeNs),
    ctimeEpochMs: String(values.ctime.getTime()),
    ctimeMs: String(values.ctimeMs),
    ctimeNs: String(values.ctimeNs),
    mtimeEpochMs: String(values.mtime.getTime()),
    mtimeMs: String(values.mtimeMs),
    mtimeNs: String(values.mtimeNs),
  });
}

function createTimestampIdentityFacade(stat, {
  mutationKind,
  settled,
}) {
  const raw = timestampAliasValues(stat);
  const exposed = { ...raw };
  if (mutationKind === "mtime-and-ctime-change") {
    for (const field of [
      "atime",
      "atimeMs",
      "atimeNs",
      "ctime",
      "ctimeMs",
      "ctimeNs",
      "mtime",
      "mtimeMs",
    ]) {
      exposed[field] = settled[field];
    }
  } else if (mutationKind === "ctime-change") {
    exposed.ctime = settled.ctime;
    exposed.ctimeMs = settled.ctimeMs;
  } else {
    throw new Error("timestamp identity facade requires one exact mutation kind");
  }
  const descriptors = Object.getOwnPropertyDescriptors(stat);
  for (const field of EXACT_TIMESTAMP_ALIAS_FIELDS) delete descriptors[field];
  const reads = Object.fromEntries(
    EXACT_TIMESTAMP_ALIAS_FIELDS.map((field) => [field, 0]),
  );
  const facade = Object.create(Object.getPrototypeOf(stat), descriptors);
  for (const field of EXACT_TIMESTAMP_ALIAS_FIELDS) {
    Object.defineProperty(facade, field, {
      configurable: false,
      enumerable: true,
      get() {
        reads[field] += 1;
        const value = exposed[field];
        return value instanceof Date ? new Date(value.getTime()) : value;
      },
    });
  }
  Object.freeze(facade);
  return Object.freeze({
    exposed: serializedTimestampAliasValues(exposed),
    facade,
    raw: serializedTimestampAliasValues(raw),
    reads,
  });
}

function filesystemStatIdentity(stat) {
  const scalar = (value) => typeof value === "bigint" ? Number(value) : value;
  const nanoseconds = (field) => {
    const exact = stat[`${field}Ns`];
    assert.equal(
      typeof exact,
      "bigint",
      `stat.${field}Ns requires a bigint stat identity`,
    );
    return String(exact);
  };
  return {
    ctimeNs: nanoseconds("ctime"),
    dev: String(stat.dev),
    gid: scalar(stat.gid),
    ino: String(stat.ino),
    isDirectory: stat.isDirectory(),
    isFile: stat.isFile(),
    isSymlink: stat.isSymbolicLink(),
    mode: scalar(stat.mode),
    mtimeNs: nanoseconds("mtime"),
    nlink: scalar(stat.nlink),
    size: scalar(stat.size),
    uid: scalar(stat.uid),
  };
}

function uninstrumentedMutationError(api) {
  return new Error(
    `filesystemHistoryProbe refuses uninstrumented mutating fs API: ${api}`,
  );
}

function filesystemHistoryProbe({ onEvent = () => {} } = {}) {
  const audit = { descriptors: new Map(), events: [], opens: [] };
  const rawFs = Object.create(null);
  for (const key of Reflect.ownKeys(fs)) {
    if (key === "promises") continue;
    const value = Reflect.get(fs, key);
    rawFs[key] = typeof value === "function" ? value.bind(fs) : value;
  }
  rawFs.promises = Object.create(null);
  for (const key of Reflect.ownKeys(fs.promises)) {
    const value = Reflect.get(fs.promises, key);
    rawFs.promises[key] =
      typeof value === "function" ? value.bind(fs.promises) : value;
  }
  const rawFstatSync = rawFs.fstatSync;
  const rawLstatSync = rawFs.lstatSync;
  const record = (event) => {
    audit.events.push(event);
    onEvent(structuredClone(event));
  };
  const resolvedFile = (value) => (
    typeof value === "number"
      ? audit.descriptors.get(value) ?? `fd:${value}`
      : path.resolve(String(value))
  );
  const io = new Proxy(rawFs, {
    get(target, property) {
      if (property === "openSync") {
        return (file, flags, mode) => {
          const descriptor = rawFs.openSync(file, flags, mode);
          const resolved = path.resolve(String(file));
          audit.descriptors.set(descriptor, resolved);
          const mutatesPath = typeof flags === "number"
            ? (flags & (rawFs.constants.O_CREAT | rawFs.constants.O_TRUNC)) !== 0
            : !["r", "rs", "sr"].includes(String(flags));
          const event = {
            type: "open",
            file: resolved,
            flags,
            mode,
            descriptor,
            mutatesPath,
          };
          record(event);
          audit.opens.push(event);
          return descriptor;
        };
      }
      if (property === "fstatSync") {
        return (descriptor, options) => {
          const result = rawFstatSync(descriptor, options);
          record({
            type: "fstat",
            bigint: options?.bigint === true,
            file: resolvedFile(descriptor),
            descriptor,
            ...filesystemStatIdentity(result),
          });
          return result;
        };
      }
      if (property === "lstatSync") {
        return (file, options) => {
          const resolved = path.resolve(String(file));
          const result = rawLstatSync(file, options);
          record({
            type: "lstat",
            bigint: options?.bigint === true,
            file: resolved,
            ...filesystemStatIdentity(result),
          });
          return result;
        };
      }
      if (property === "realpathSync") {
        return (file, options) => {
          const resolvedInput = path.resolve(String(file));
          const result = rawFs.realpathSync(file, options);
          record({
            type: "realpath",
            file: resolvedInput,
            resolved: path.resolve(String(result)),
          });
          return result;
        };
      }
      if (property === "readdirSync") {
        return (directory, options) => {
          const result = rawFs.readdirSync(directory, options);
          record({
            type: "readdir",
            file: path.resolve(String(directory)),
            inventory: result.map((entry) => (
              typeof entry === "string" || Buffer.isBuffer(entry)
                ? String(entry)
                : entry.name
            )).sort(),
          });
          return result;
        };
      }
      if (property === "mkdirSync") {
        return (directory, options) => {
          const existed = rawFs.existsSync(directory);
          const result = rawFs.mkdirSync(directory, options);
          record({
            type: "mkdir",
            file: path.resolve(String(directory)),
            created: !existed,
            options: structuredClone(options ?? null),
          });
          return result;
        };
      }
      if (property === "writeFileSync") {
        return (file, data, options) => {
          const result = rawFs.writeFileSync(file, data, options);
          record({
            type: "write",
            file: resolvedFile(file),
            descriptor: typeof file === "number" ? file : null,
            bytes: Buffer.byteLength(
              Buffer.isBuffer(data) || ArrayBuffer.isView(data)
                ? Buffer.from(data.buffer, data.byteOffset, data.byteLength)
                : String(data),
            ),
            method: "writeFileSync",
            pathnameWrite: typeof file !== "number",
          });
          return result;
        };
      }
      if (property === "writeSync") {
        return (descriptor, ...args) => {
          const count = rawFs.writeSync(descriptor, ...args);
          record({
            type: "write",
            file: resolvedFile(descriptor),
            descriptor,
            bytes: count,
            method: "writeSync",
            pathnameWrite: false,
          });
          return count;
        };
      }
      if (property === "fsyncSync") {
        return (descriptor) => {
          const result = rawFs.fsyncSync(descriptor);
          const stat = rawFstatSync(descriptor, { bigint: true });
          record({
            type: "fsync",
            file: resolvedFile(descriptor),
            descriptor,
            ...filesystemStatIdentity(stat),
          });
          return result;
        };
      }
      if (property === "closeSync") {
        return (descriptor) => {
          const file = resolvedFile(descriptor);
          const result = rawFs.closeSync(descriptor);
          record({
            type: "close",
            file,
            descriptor,
          });
          audit.descriptors.delete(descriptor);
          return result;
        };
      }
      if (property === "truncateSync") {
        return (file, length) => {
          const result = rawFs.truncateSync(file, length);
          record({
            type: "truncate",
            file: path.resolve(String(file)),
            length: length ?? 0,
            pathnameWrite: true,
          });
          return result;
        };
      }
      if (property === "ftruncateSync") {
        return (descriptor, length) => {
          const result = rawFs.ftruncateSync(descriptor, length);
          record({
            type: "truncate",
            file: resolvedFile(descriptor),
            descriptor,
            length: length ?? 0,
            pathnameWrite: false,
          });
          return result;
        };
      }
      if (property === "unlinkSync") {
        return (file) => {
          const result = rawFs.unlinkSync(file);
          record({ type: "unlink", file: path.resolve(String(file)) });
          return result;
        };
      }
      if (property === "rmdirSync") {
        return (directory, options) => {
          const result = rawFs.rmdirSync(directory, options);
          record({
            type: "rmdir",
            file: path.resolve(String(directory)),
            options: structuredClone(options ?? null),
          });
          return result;
        };
      }
      if (property === "rmSync") {
        return (file, options) => {
          const result = rawFs.rmSync(file, options);
          record({
            type: "rm",
            file: path.resolve(String(file)),
            options: structuredClone(options ?? null),
          });
          return result;
        };
      }
      if (property === "renameSync") {
        return (from, to) => {
          const resolvedFrom = path.resolve(String(from));
          const resolvedTo = path.resolve(String(to));
          const sourceIdentity = filesystemStatIdentity(
            rawLstatSync(from, { bigint: true }),
          );
          const result = rawFs.renameSync(from, to);
          const destinationIdentity = filesystemStatIdentity(
            rawLstatSync(to, { bigint: true }),
          );
          record({
            type: "rename",
            from: resolvedFrom,
            to: resolvedTo,
            sourceIdentity,
            sourceSize: sourceIdentity.size,
            destinationIdentity,
          });
          return result;
        };
      }
      if (property === "copyFileSync") {
        return (from, to, mode) => {
          const result = rawFs.copyFileSync(from, to, mode);
          record({
            type: "copy",
            from: path.resolve(String(from)),
            to: path.resolve(String(to)),
            mode: mode ?? 0,
          });
          return result;
        };
      }
      if (property === "linkSync") {
        return (existing, created) => {
          const result = rawFs.linkSync(existing, created);
          record({
            type: "link",
            from: path.resolve(String(existing)),
            to: path.resolve(String(created)),
          });
          return result;
        };
      }
      if (property === "symlinkSync") {
        return (targetValue, created, type) => {
          const result = rawFs.symlinkSync(targetValue, created, type);
          record({
            type: "symlink",
            target: String(targetValue),
            to: path.resolve(String(created)),
          });
          return result;
        };
      }
      if (property === "chmodSync" || property === "chownSync") {
        return (file, ...args) => {
          const result = Reflect.get(rawFs, property)(file, ...args);
          record({
            type: property === "chmodSync" ? "chmod" : "chown",
            file: path.resolve(String(file)),
            args: [...args],
          });
          return result;
        };
      }
      if (property === "utimesSync" || property === "lutimesSync") {
        return (file, ...args) => {
          const result = Reflect.get(rawFs, property)(file, ...args);
          record({
            type: "utimes",
            file: path.resolve(String(file)),
            args: args.map((value) => String(value)),
          });
          return result;
        };
      }
      if (property === "promises") {
        return new Proxy(rawFs.promises, {
          get(promisesTarget, promisesProperty) {
            if (UNINSTRUMENTED_MUTATING_FS_APIS.has(promisesProperty)) {
              return async () => {
                throw uninstrumentedMutationError(`promises.${String(promisesProperty)}`);
              };
            }
            const value = Reflect.get(promisesTarget, promisesProperty);
            if (typeof value !== "function") return value;
            if (PROVEN_READ_ONLY_PROMISE_FS_APIS.has(promisesProperty)) {
              return (...args) => {
                record({
                  api: `fs.promises.${String(promisesProperty)}`,
                  descriptor: typeof args[0] === "number" ? args[0] : null,
                  file: args.length > 0 ? resolvedFile(args[0]) : null,
                  type: "read-only",
                });
                return Reflect.apply(value, promisesTarget, args);
              };
            }
            return async () => {
              throw uninstrumentedMutationError(`promises.${String(promisesProperty)}`);
            };
          },
        });
      }
      if (UNINSTRUMENTED_MUTATING_FS_APIS.has(property)) {
        return (..._args) => {
          throw uninstrumentedMutationError(String(property));
        };
      }
      const value = Reflect.get(target, property);
      if (typeof value !== "function") return value;
      if (PROVEN_READ_ONLY_FS_APIS.has(property)) {
        return (...args) => {
          record({
            api: `fs.${String(property)}`,
            descriptor: typeof args[0] === "number" ? args[0] : null,
            file: args.length > 0 ? resolvedFile(args[0]) : null,
            type: "read-only",
          });
          return Reflect.apply(value, target, args);
        };
      }
      return (..._args) => {
        throw uninstrumentedMutationError(String(property));
      };
    },
  });
  return { audit, io };
}

function durableIoProbe(options) {
  return filesystemHistoryProbe(options);
}

function historyIndex(events, after, predicate, message) {
  const index = events.findIndex(
    (event, eventIndex) => eventIndex > after && predicate(event),
  );
  assert.ok(index > after, message);
  return index;
}

const MUTATING_IO_EVENT_TYPES = new Set([
  "chmod",
  "chown",
  "copy",
  "link",
  "mkdir",
  "rename",
  "rm",
  "rmdir",
  "symlink",
  "truncate",
  "unlink",
  "utimes",
  "write",
]);

function isMutatingIoEvent(event) {
  return (MUTATING_IO_EVENT_TYPES.has(event.type)
    || (event.type === "open" && event.mutatesPath === true))
    && !(event.type === "mkdir" && event.created === false);
}

function pathIsSameOrAncestor(candidatePath, targetPath) {
  if (typeof candidatePath !== "string") return false;
  const relative = path.relative(candidatePath, targetPath);
  return relative === ""
    || (relative !== ".."
      && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative));
}

function eventCanReplacePathIdentity(event, targetPath) {
  return [event.file, event.from, event.to]
    .some((candidatePath) => pathIsSameOrAncestor(candidatePath, targetPath));
}

function assertPathImmutableAfter(events, targetPath, afterIndex, endIndex, label) {
  assert.equal(
    events
      .slice(afterIndex + 1, endIndex)
      .some((event) => isMutatingIoEvent(event)
        && eventCanReplacePathIdentity(event, targetPath)),
    false,
    `${label} mutated ${targetPath} after its durability point`,
  );
}

function assertOnlyDescriptorWritesBeforeFsync(events, {
  descriptor,
  file,
  fsyncIndex,
  label,
  openIndex,
}) {
  const forbidden = events
    .slice(openIndex + 1, fsyncIndex)
    .map((event, relativeIndex) => ({
      event,
      index: openIndex + 1 + relativeIndex,
    }))
    .filter(({ event }) => isMutatingIoEvent(event)
      && eventCanReplacePathIdentity(event, file)
      && !(event.type === "write"
        && event.file === file
        && event.descriptor === descriptor
        && event.pathnameWrite === false));
  assert.deepEqual(
    forbidden,
    [],
    `${label} mutated or substituted ${file} between exclusive open and fsync`,
  );
}

function normalizedFilesystemIdentity(value) {
  return Object.fromEntries(
    [
      "ctimeNs",
      "dev",
      "gid",
      "ino",
      "mode",
      "mtimeNs",
      "nlink",
      "size",
      "uid",
      "isFile",
    ]
      .map((field) => [
        field,
        field === "isFile" && typeof value[field] === "function"
          ? value[field]()
          : field === "ctimeNs" || field === "mtimeNs"
            ? String(value[field])
            : field === "dev" || field === "ino"
              ? String(value[field])
            : typeof value[field] === "bigint"
              ? Number(value[field])
              : value[field],
      ]),
  );
}

function assertFsyncMatchesFinalRegularLeaf(fsyncEvent, finalStat, label) {
  const fsyncIdentity = normalizedFilesystemIdentity(fsyncEvent);
  const finalIdentity = normalizedFilesystemIdentity(finalStat);
  assert.equal(fsyncIdentity.isFile, true, `${label} fsync target was not a regular file`);
  assert.equal(finalIdentity.isFile, true, `${label} final path was not a regular file`);
  assert.match(fsyncIdentity.mtimeNs, /^\d+$/, `${label} fsync mtime is not exact`);
  assert.match(fsyncIdentity.ctimeNs, /^\d+$/, `${label} fsync ctime is not exact`);
  assert.equal(fsyncIdentity.nlink, 1, `${label} fsync target had a second hard link`);
  assert.equal(finalIdentity.nlink, 1, `${label} final path had a second hard link`);
  assert.deepEqual(
    fsyncIdentity,
    finalIdentity,
    `${label} final path identity differs from the descriptor fsynced inode`,
  );
}

function assertRenamePreservesRegularLeafIdentity(sourceIdentity, destinationIdentity, label) {
  const withoutRenameCtime = (value) => {
    const identity = normalizedFilesystemIdentity(value);
    delete identity.ctimeNs;
    return identity;
  };
  assert.deepEqual(
    withoutRenameCtime(destinationIdentity),
    withoutRenameCtime(sourceIdentity),
    `${label} rename substituted or modified the durable inode`,
  );
}

function assertExactDirectoryInventory(directory, expectedNames, label) {
  assert.deepEqual(
    fs.readdirSync(directory).sort(),
    [...expectedNames].sort(),
    `${label} contains an orphan, alias, temp or unexpected inventory entry`,
  );
}

function normalizedDirectoryIdentity(value) {
  return Object.fromEntries(
    [
      "dev",
      "gid",
      "ino",
      "isDirectory",
      "isSymlink",
      "mode",
      "nlink",
      "uid",
    ].map((field) => [
      field,
      typeof value[field] === "function"
        ? value[field]()
        : field === "dev" || field === "ino"
          ? String(value[field])
        : typeof value[field] === "bigint"
          ? Number(value[field])
          : value[field],
    ]),
  );
}

function assertExternalSnapshotAncestryAttackHistory({
  attackProof,
  attackTarget,
  audit,
  directories,
  injectionEventIndex,
  leaf,
  mutationKind,
  orphan,
  targetIndex,
}) {
  const { events } = audit;
  const metadataOnly = mutationKind === "mtime-and-ctime-change"
    || mutationKind === "ctime-change";
  assert.equal(directories.length, 3, "external ancestry RED requires three pins");
  assert.equal(directories[targetIndex], attackTarget);
  assert.equal(
    !metadataOnly
      && directories.some((directory) => pathIsSameOrAncestor(directory, orphan)),
    false,
    "external ancestry orphan entered an observed directory inventory",
  );
  assert.ok(injectionEventIndex >= 0, "external ancestry attack was not injected");
  assert.equal(events[injectionEventIndex]?.type, "fsync");
  assert.equal(events[injectionEventIndex]?.file, leaf);

  const assertExactIdentityStrings = (event, label) => {
    for (const field of ["dev", "ino", "ctimeNs", "mtimeNs"]) {
      assert.match(
        event?.[field] ?? "",
        /^\d+$/,
        `${label}.${field} is not an exact decimal string`,
      );
    }
  };
  const injectedLeafFsync = events[injectionEventIndex];
  assertExactIdentityStrings(injectedLeafFsync, "injected leaf fsync");
  assert.equal(injectedLeafFsync.dev, attackProof.claimedLeafDev);
  assert.equal(injectedLeafFsync.ino, attackProof.claimedLeafIno);
  if (mutationKind === "directory-replacement") {
    assert.notDeepEqual(
      {
        dev: injectedLeafFsync.dev,
        ino: injectedLeafFsync.ino,
      },
      {
        dev: attackProof.orphanLeafDev,
        ino: attackProof.orphanLeafIno,
      },
      "replacement ancestry did not keep the fsynced inode at the claimed leaf",
    );
  } else if (mutationKind === "symlink-back") {
    assert.equal(injectedLeafFsync.dev, attackProof.orphanLeafDev);
    assert.equal(injectedLeafFsync.ino, attackProof.orphanLeafIno);
  }
  const requiredFlags = fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
  const forbiddenFlags = fs.constants.O_WRONLY
    | fs.constants.O_RDWR
    | fs.constants.O_CREAT
    | fs.constants.O_TRUNC
    | fs.constants.O_APPEND;
  const pinRecords = directories.map((directory, directoryIndex) => {
    const opens = events
      .map((event, index) => ({ event, index }))
      .filter(({ event }) => event.type === "open" && event.file === directory);
    assert.equal(opens.length, 1, `${directory} must have one exact pin`);
    const [open] = opens;
    assert.equal(
      open.event.flags & requiredFlags,
      requiredFlags,
      `${directory} pin lacks O_DIRECTORY|O_NOFOLLOW`,
    );
    assert.equal(
      open.event.flags & forbiddenFlags,
      0,
      `${directory} pin is not O_RDONLY`,
    );
    const descendantBoundaries = events
      .map((event, index) => ({ event, index }))
      .filter(({ event }) => directoryIndex < directories.length - 1
        ? event.type === "mkdir"
          && event.file === directories[directoryIndex + 1]
          && event.created === true
        : event.type === "open" && event.file === leaf);
    assert.equal(
      descendantBoundaries.length,
      1,
      `${directory} lacks one exact descendant boundary`,
    );
    const descendantBoundary = descendantBoundaries[0].index;
    const initialFstats = events
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => index > open.index
        && index < descendantBoundary
        && event.type === "fstat"
        && event.file === directory
        && event.descriptor === open.event.descriptor
        && event.bigint === true);
    assert.equal(initialFstats.length, 1, `${directory} lacks one exact initial fstat`);
    assertExactIdentityStrings(initialFstats[0].event, `${directory} initial fstat`);
    const settledFstats = events
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => index > descendantBoundary
        && index < injectionEventIndex
        && event.type === "fstat"
        && event.file === directory
        && event.descriptor === open.event.descriptor
        && event.bigint === true);
    assert.equal(settledFstats.length, 1, `${directory} lacks one exact settled fstat`);
    assertExactIdentityStrings(settledFstats[0].event, `${directory} settled fstat`);
    assert.ok(
      open.index < initialFstats[0].index
        && initialFstats[0].index < descendantBoundary
        && descendantBoundary < settledFstats[0].index
        && descendantBoundary < injectionEventIndex,
      `${directory} was not pinned before its exact descendant boundary`,
    );
    return {
      closeIndexes: events
        .map((event, index) => ({ event, index }))
        .filter(({ event }) => event.type === "close"
          && event.file === directory
          && event.descriptor === open.event.descriptor)
        .map(({ index }) => index),
      descriptor: open.event.descriptor,
      descendantBoundary,
      initialFstatIndex: initialFstats[0].index,
      openIndex: open.index,
      settledFstatIndex: settledFstats[0].index,
    };
  });
  assert.equal(
    new Set(pinRecords.map(({ descriptor }) => descriptor)).size,
    directories.length,
    "snapshot ancestry reused a directory descriptor as a decoy pin",
  );

  const exactDirectoryFsyncBetween = (record, after, before, label) => {
    const fsyncs = events
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => index > after
        && index < before
        && event.type === "fsync"
        && event.file === directories[record]
        && event.descriptor === pinRecords[record].descriptor);
    assert.equal(fsyncs.length, 1, `${label} lacks one exact pinned fsync`);
    return fsyncs[0].index;
  };
  const mountFsyncIndex = exactDirectoryFsyncBetween(
    0,
    pinRecords[0].descendantBoundary,
    pinRecords[1].openIndex,
    "Engine Mountpoint",
  );
  const claimedJobsFsyncIndex = exactDirectoryFsyncBetween(
    1,
    pinRecords[1].descendantBoundary,
    pinRecords[2].openIndex,
    "claimed-jobs directory",
  );
  assert.ok(
    pinRecords[0].openIndex
      < pinRecords[0].initialFstatIndex
      && pinRecords[0].initialFstatIndex
        < pinRecords[0].descendantBoundary
      && pinRecords[0].descendantBoundary
        < mountFsyncIndex
      && mountFsyncIndex
        < pinRecords[1].openIndex
      && pinRecords[1].openIndex
        < pinRecords[1].initialFstatIndex
      && pinRecords[1].initialFstatIndex
        < pinRecords[1].descendantBoundary
      && pinRecords[1].descendantBoundary
        < claimedJobsFsyncIndex
      && claimedJobsFsyncIndex
        < pinRecords[2].openIndex
      && pinRecords[2].openIndex
        < pinRecords[2].initialFstatIndex
      && pinRecords[2].initialFstatIndex
        < pinRecords[2].descendantBoundary
      && pinRecords[2].descendantBoundary
        < pinRecords[0].settledFstatIndex
      && pinRecords[0].settledFstatIndex
        < pinRecords[1].settledFstatIndex
      && pinRecords[1].settledFstatIndex
        < pinRecords[2].settledFstatIndex
      && pinRecords[2].settledFstatIndex
        < injectionEventIndex,
    "snapshot ancestry pin/create/fsync order is not exact",
  );

  const attackedPin = pinRecords[targetIndex];
  const attackedPostFstats = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index > injectionEventIndex
      && event.type === "fstat"
      && event.file === attackTarget
      && event.descriptor === attackedPin.descriptor
      && event.bigint === true);
  assert.equal(
    attackedPostFstats.length,
    1,
    "attacked pin lacks one exact post-attack descriptor fstat",
  );
  const [attackedPostFstat] = attackedPostFstats;
  assertExactIdentityStrings(attackedPostFstat.event, "attacked post-attack fstat");
  const attackedSettledFstat = events[attackedPin.settledFstatIndex];
  assert.equal(attackedPostFstat.event.dev, attackedSettledFstat.dev);
  assert.equal(attackedPostFstat.event.ino, attackedSettledFstat.ino);
  if (metadataOnly) {
    assert.deepEqual(
      {
        ctimeNs: attackedSettledFstat.ctimeNs,
        dev: attackedSettledFstat.dev,
        ino: attackedSettledFstat.ino,
        mtimeNs: attackedSettledFstat.mtimeNs,
      },
      {
        ctimeNs: attackProof.beforeTargetCtimeNs,
        dev: attackProof.beforeTargetDev,
        ino: attackProof.beforeTargetIno,
        mtimeNs: attackProof.beforeTargetMtimeNs,
      },
      "timestamp child did not attack the exact settled pinned identity",
    );
    if (mutationKind === "mtime-and-ctime-change") {
      assert.notEqual(
        attackedPostFstat.event.mtimeNs,
        attackedSettledFstat.mtimeNs,
        "mtime-and-ctime change did not alter the settled pinned descriptor mtime",
      );
      assert.equal(
        attackedPostFstat.event.ctimeNs,
        attackedSettledFstat.ctimeNs,
        "mtime-only seam did not preserve the settled pinned descriptor ctime",
      );
      assert.notEqual(
        attackProof.targetCtimeNs,
        attackProof.beforeTargetCtimeNs,
        "raw mtime mutation did not provide the required ctime-cochange control",
      );
    } else {
      assert.equal(
        attackedPostFstat.event.mtimeNs,
        attackedSettledFstat.mtimeNs,
        "ctime-change unexpectedly altered the settled pinned descriptor mtime",
      );
      assert.notEqual(
        attackedPostFstat.event.ctimeNs,
        attackedSettledFstat.ctimeNs,
        "ctime-change did not alter the settled pinned descriptor ctime",
      );
      assert.equal(attackedPostFstat.event.ctimeNs, attackProof.targetCtimeNs);
    }
    assert.equal(attackedPostFstat.event.mtimeNs, attackProof.targetMtimeNs);
    assert.equal(attackedPostFstat.event.dev, attackProof.targetDev);
    assert.equal(attackedPostFstat.event.ino, attackProof.targetIno);
  } else {
    assert.deepEqual(
      {
        dev: attackedSettledFstat.dev,
        ino: attackedSettledFstat.ino,
      },
      {
        dev: attackProof.beforeTargetDev,
        ino: attackProof.beforeTargetIno,
      },
      "external child did not substitute the exact settled pinned inode",
    );
    assert.equal(attackedPostFstat.event.dev, attackProof.orphanDev);
    assert.equal(attackedPostFstat.event.ino, attackProof.orphanIno);
  }
  const attackedLstats = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index > injectionEventIndex
      && event.type === "lstat"
      && event.file === attackTarget
      && event.bigint === true
      && event.isSymlink === (mutationKind === "symlink-back")
      && event.isDirectory === (mutationKind !== "symlink-back"));
  assert.equal(
    attackedLstats.length,
    1,
    "SUT did not consume one exact post-attack bigint lstat of the attacked pathname",
  );
  const [attackedLstat] = attackedLstats;
  assertExactIdentityStrings(attackedLstat.event, "attacked pathname lstat");
  assert.equal(attackedLstat.event.dev, attackProof.targetDev);
  assert.equal(attackedLstat.event.ino, attackProof.targetIno);
  if (metadataOnly) {
    assert.deepEqual(
      {
        ctimeNs: attackedLstat.event.ctimeNs,
        dev: attackedLstat.event.dev,
        ino: attackedLstat.event.ino,
        mtimeNs: attackedLstat.event.mtimeNs,
      },
      {
        ctimeNs: attackedPostFstat.event.ctimeNs,
        dev: attackedPostFstat.event.dev,
        ino: attackedPostFstat.event.ino,
        mtimeNs: attackedPostFstat.event.mtimeNs,
      },
      "timestamp-only mutation unexpectedly substituted the attacked pathname",
    );
  } else {
    assert.notDeepEqual(
      {
        dev: attackedLstat.event.dev,
        ino: attackedLstat.event.ino,
      },
      {
        dev: attackedPostFstat.event.dev,
        ino: attackedPostFstat.event.ino,
      },
      "external ancestry mutant did not replace the pinned pathname identity",
    );
  }
  const expectedRealpath = mutationKind === "symlink-back"
    ? orphan
    : attackTarget;
  const attackedRealpaths = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index > injectionEventIndex
      && event.type === "realpath"
      && event.file === attackTarget
      && event.resolved === expectedRealpath);
  assert.equal(
    attackedRealpaths.length,
    1,
    "SUT did not consume one exact external realpath of the attacked pathname",
  );
  const [attackedRealpath] = attackedRealpaths;
  assert.ok(
    attackedPostFstat.index < attackedLstat.index
      && attackedLstat.index < attackedRealpath.index,
    "SUT did not consume fstat then lstat then realpath after injection",
  );

  for (const { closeIndexes, descriptor } of pinRecords) {
    assert.equal(
      closeIndexes.length,
      1,
      `pinned descriptor ${descriptor} was not closed exactly once`,
    );
    assert.ok(
      closeIndexes[0] > attackedRealpath.index,
      `pinned descriptor ${descriptor} closed before causal revalidation`,
    );
  }
  assert.equal(audit.descriptors.size, 0, "snapshot rejection leaked a descriptor");
  assert.deepEqual(
    events
      .slice(injectionEventIndex + 1)
      .filter(isMutatingIoEvent)
      .map(({ file, from, to, type }) => ({ file, from, to, type })),
    [],
    "snapshot rejection mutated a pathname after authority loss",
  );
  assert.equal(pathIsSameOrAncestor(attackTarget, leaf), true);
  const relocatedLeaf = metadataOnly
    ? leaf
    : path.join(orphan, path.relative(attackTarget, leaf));
  assert.equal(
    fs.lstatSync(relocatedLeaf, { bigint: true }).isFile(),
    true,
    metadataOnly
      ? "durable snapshot leaf disappeared during metadata-only mutation"
      : "durable snapshot leaf disappeared from the externally renamed ancestry",
  );
}

function assertExternalSnapshotAncestorRealpathEscapeHistory({
  attackProof,
  audit,
  directories,
  escapedMountpoint,
  injectionEventIndex,
  leaf,
}) {
  const { events } = audit;
  assert.equal(directories.length, 3, "realpath escape RED requires three pins");
  assert.ok(injectionEventIndex >= 0, "realpath escape attack was not injected");
  assert.equal(events[injectionEventIndex]?.type, "fsync");
  assert.equal(events[injectionEventIndex]?.file, leaf);
  const assertExactIdentityStrings = (event, label) => {
    for (const field of ["dev", "ino", "ctimeNs", "mtimeNs"]) {
      assert.match(
        event?.[field] ?? "",
        /^\d+$/,
        `${label}.${field} is not an exact decimal string`,
      );
    }
  };
  const leafFsync = events[injectionEventIndex];
  assertExactIdentityStrings(leafFsync, "ancestor escape leaf fsync");
  assert.equal(leafFsync.dev, attackProof.leafDev);
  assert.equal(leafFsync.ino, attackProof.leafIno);

  const requiredFlags = fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
  const forbiddenFlags = fs.constants.O_WRONLY
    | fs.constants.O_RDWR
    | fs.constants.O_CREAT
    | fs.constants.O_TRUNC
    | fs.constants.O_APPEND;
  const pinRecords = directories.map((directory, directoryIndex) => {
    const opens = events
      .map((event, index) => ({ event, index }))
      .filter(({ event }) => event.type === "open" && event.file === directory);
    assert.equal(opens.length, 1, `${directory} must have one exact pin`);
    const [open] = opens;
    assert.equal(open.event.flags & requiredFlags, requiredFlags);
    assert.equal(open.event.flags & forbiddenFlags, 0);
    const descendantBoundaries = events
      .map((event, index) => ({ event, index }))
      .filter(({ event }) => directoryIndex < directories.length - 1
        ? event.type === "mkdir"
          && event.file === directories[directoryIndex + 1]
          && event.created === true
        : event.type === "open" && event.file === leaf);
    assert.equal(
      descendantBoundaries.length,
      1,
      `${directory} lacks one exact descendant boundary`,
    );
    const descendantBoundary = descendantBoundaries[0].index;
    const initialFstats = events
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => index > open.index
        && index < descendantBoundary
        && event.type === "fstat"
        && event.file === directory
        && event.descriptor === open.event.descriptor
        && event.bigint === true);
    assert.equal(initialFstats.length, 1, `${directory} lacks one initial fstat`);
    assertExactIdentityStrings(initialFstats[0].event, `${directory} initial fstat`);
    const settledFstats = events
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => index > descendantBoundary
        && index < injectionEventIndex
        && event.type === "fstat"
        && event.file === directory
        && event.descriptor === open.event.descriptor
        && event.bigint === true);
    assert.equal(settledFstats.length, 1, `${directory} lacks one settled fstat`);
    assertExactIdentityStrings(settledFstats[0].event, `${directory} settled fstat`);
    return {
      closeIndexes: events
        .map((event, index) => ({ event, index }))
        .filter(({ event }) => event.type === "close"
          && event.file === directory
          && event.descriptor === open.event.descriptor)
        .map(({ index }) => index),
      descendantBoundary,
      descriptor: open.event.descriptor,
      initialFstatIndex: initialFstats[0].index,
      openIndex: open.index,
      settledFstatIndex: settledFstats[0].index,
    };
  });
  assert.equal(
    new Set(pinRecords.map(({ descriptor }) => descriptor)).size,
    3,
    "realpath escape RED reused a pin descriptor",
  );
  const directoryFsyncIndex = (directoryIndex, after, before) => {
    const matches = events
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => index > after
        && index < before
        && event.type === "fsync"
        && event.file === directories[directoryIndex]
        && event.descriptor === pinRecords[directoryIndex].descriptor);
    assert.equal(
      matches.length,
      1,
      `${directories[directoryIndex]} lacks one causal pinned fsync`,
    );
    return matches[0].index;
  };
  const mountFsyncIndex = directoryFsyncIndex(
    0,
    pinRecords[0].descendantBoundary,
    pinRecords[1].openIndex,
  );
  const claimedJobsFsyncIndex = directoryFsyncIndex(
    1,
    pinRecords[1].descendantBoundary,
    pinRecords[2].openIndex,
  );
  assert.ok(
    pinRecords[0].openIndex
      < pinRecords[0].initialFstatIndex
      && pinRecords[0].initialFstatIndex
        < pinRecords[0].descendantBoundary
      && pinRecords[0].descendantBoundary
        < mountFsyncIndex
      && mountFsyncIndex
        < pinRecords[1].openIndex
      && pinRecords[1].openIndex
        < pinRecords[1].initialFstatIndex
      && pinRecords[1].initialFstatIndex
        < pinRecords[1].descendantBoundary
      && pinRecords[1].descendantBoundary
        < claimedJobsFsyncIndex
      && claimedJobsFsyncIndex
        < pinRecords[2].openIndex
      && pinRecords[2].openIndex
        < pinRecords[2].initialFstatIndex
      && pinRecords[2].initialFstatIndex
        < pinRecords[2].descendantBoundary
      && pinRecords[2].descendantBoundary
        < pinRecords[0].settledFstatIndex
      && pinRecords[0].settledFstatIndex
        < pinRecords[1].settledFstatIndex
      && pinRecords[1].settledFstatIndex
        < pinRecords[2].settledFstatIndex
      && pinRecords[2].settledFstatIndex
        < injectionEventIndex,
    "realpath escape pin/create/fsync/settled order is not exact",
  );

  const mountRecord = pinRecords[0];
  const mountPostFstats = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index > injectionEventIndex
      && event.type === "fstat"
      && event.file === directories[0]
      && event.descriptor === mountRecord.descriptor
      && event.bigint === true);
  assert.equal(mountPostFstats.length, 1, "mount pin lacks one post-attack fstat");
  const [mountPostFstat] = mountPostFstats;
  assertExactIdentityStrings(mountPostFstat.event, "mount post-attack fstat");
  const mountLstats = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index > injectionEventIndex
      && event.type === "lstat"
      && event.file === directories[0]
      && event.bigint === true
      && event.isDirectory === true
      && event.isSymlink === false);
  assert.equal(
    mountLstats.length,
    1,
    "SUT did not consume one exact unchanged mountpoint lstat",
  );
  const [mountLstat] = mountLstats;
  assertExactIdentityStrings(mountLstat.event, "mount pathname lstat");
  const mountRealpaths = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index > injectionEventIndex
      && event.type === "realpath"
      && event.file === directories[0]
      && event.resolved === escapedMountpoint);
  assert.equal(
    mountRealpaths.length,
    1,
    "SUT did not consume the escaped mountpoint realpath result",
  );
  const [mountRealpath] = mountRealpaths;
  assert.ok(
    mountPostFstat.index < mountLstat.index
      && mountLstat.index < mountRealpath.index,
    "SUT did not consume mount fstat then lstat then realpath after injection",
  );
  const settledMount = events[mountRecord.settledFstatIndex];
  const stableIdentity = (event) => ({
    dev: event.dev,
    ino: event.ino,
    mtimeNs: event.mtimeNs,
  });
  assert.deepEqual(
    stableIdentity(mountPostFstat.event),
    stableIdentity(settledMount),
    "ancestor escape changed the settled mount pin",
  );
  assert.deepEqual(
    stableIdentity(mountLstat.event),
    stableIdentity(mountPostFstat.event),
    "ancestor escape changed the mountpoint pathname identity",
  );
  assert.deepEqual(
    stableIdentity(mountLstat.event),
    {
      dev: attackProof.afterMountDev,
      ino: attackProof.afterMountIno,
      mtimeNs: attackProof.afterMountMtimeNs,
    },
    "SUT mountpoint identity differs from the raw child proof",
  );
  assert.notEqual(
    mountRealpath.event.resolved,
    directories[0],
    "ancestor escape did not change the canonical mountpoint authority",
  );

  for (const { closeIndexes, descriptor } of pinRecords) {
    assert.equal(
      closeIndexes.length,
      1,
      `pinned descriptor ${descriptor} was not closed exactly once`,
    );
    assert.ok(
      closeIndexes[0] > mountRealpath.index,
      `pinned descriptor ${descriptor} closed before causal realpath rejection`,
    );
  }
  assert.equal(audit.descriptors.size, 0, "realpath rejection leaked a descriptor");
  assert.deepEqual(
    events
      .slice(injectionEventIndex + 1)
      .filter(isMutatingIoEvent)
      .map(({ file, from, to, type }) => ({ file, from, to, type })),
    [],
    "realpath rejection mutated a pathname after authority loss",
  );
}

function assertSettledPinnedDirectoryTimestampStable(
  events,
  {
    directories,
    leafFsyncIndex,
  },
  targetIndex,
  timestampField,
) {
  const { directory, label } = directories[targetIndex];
  const opens = events.filter(
    (event) => event.type === "open" && event.file === directory,
  );
  assert.equal(opens.length, 1, `${label} lacks one exact pin`);
  const [open] = opens;
  const preFstats = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index < leafFsyncIndex
      && event.type === "fstat"
      && event.file === directory
      && event.descriptor === open.descriptor
      && event.bigint === true);
  assert.equal(preFstats.length, 2, `${label} lacks its initial and settled fstats`);
  const settled = preFstats.at(-1).event;
  const postFstats = events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index > leafFsyncIndex
      && event.type === "fstat"
      && event.file === directory
      && event.descriptor === open.descriptor
      && event.bigint === true);
  assert.equal(postFstats.length, 1, `${label} lacks one post-attack fstat`);
  const post = postFstats[0].event;
  assert.ok(
    timestampField === "ctimeNs" || timestampField === "mtimeNs",
    "settled timestamp oracle requires ctimeNs or mtimeNs",
  );
  assert.match(settled[timestampField], /^\d+$/);
  assert.match(post[timestampField], /^\d+$/);
  assert.equal(
    post[timestampField],
    settled[timestampField],
    `${label} pinned descriptor settled ${timestampField} changed`,
  );
}

function assertPinnedSnapshotAncestryHistory(events, {
  directories,
  historyEnd = events.length,
  leaf,
  leafFsyncIndex,
}) {
  const history = events.slice(0, historyEnd);
  const requiredFlags = fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
  const forbiddenWriteFlags = fs.constants.O_WRONLY
    | fs.constants.O_RDWR
    | fs.constants.O_CREAT
    | fs.constants.O_TRUNC
    | fs.constants.O_APPEND;
  assert.equal(directories.length, 3, "snapshot ancestry must pin exactly three directories");
  for (const [directoryIndex, {
    directory,
    expectedInventory,
    label,
  }] of directories.entries()) {
    const opens = history
      .map((event, index) => ({ event, index }))
      .filter(({ event }) => event.type === "open" && event.file === directory);
    assert.equal(opens.length, 1, `${label} must use one pinned directory descriptor`);
    const [open] = opens;
    assert.equal(
      open.event.flags & requiredFlags,
      requiredFlags,
      `${label} pin lacks O_DIRECTORY|O_NOFOLLOW`,
    );
    assert.equal(
      open.event.flags & forbiddenWriteFlags,
      0,
      `${label} pin is not O_RDONLY`,
    );
    const initialFstat = history.findIndex((event, index) => index > open.index
      && index < leafFsyncIndex
      && event.type === "fstat"
      && event.file === directory
      && event.descriptor === open.event.descriptor
      && event.bigint === true);
    assert.ok(
      initialFstat > open.index,
      `${label} lacks an exact pre-fsync bigint fstat`,
    );
    const descendantBoundary = directoryIndex < directories.length - 1
      ? history.findIndex((event) => event.type === "mkdir"
        && event.file === directories[directoryIndex + 1].directory
        && event.created === true)
      : history.findIndex((event) => event.type === "open"
        && event.file === leaf);
    assert.ok(
      descendantBoundary > initialFstat && descendantBoundary < leafFsyncIndex,
      `${label} was not pinned and fstat-attested before its descendant was created/opened`,
    );
    const settledFstats = history
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => index > descendantBoundary
        && index < leafFsyncIndex
        && event.type === "fstat"
        && event.file === directory
        && event.descriptor === open.event.descriptor
        && event.bigint === true);
    assert.equal(
      settledFstats.length,
      1,
      `${label} lacks one settled pre-attack bigint fstat`,
    );
    const [settledFstat] = settledFstats;
    const postFstat = historyIndex(
      history,
      leafFsyncIndex,
      (event) => event.type === "fstat"
        && event.file === directory
        && event.descriptor === open.event.descriptor
        && event.bigint === true,
      `${label} lacks an exact post-fsync bigint fstat`,
    );
    const postLstat = historyIndex(
      history,
      leafFsyncIndex,
      (event) => event.type === "lstat"
        && event.file === directory
        && event.bigint === true,
      `${label} lacks an exact post-fsync bigint lstat`,
    );
    const postRealpath = historyIndex(
      history,
      leafFsyncIndex,
      (event) => event.type === "realpath" && event.file === directory,
      `${label} lacks a post-fsync realpath`,
    );
    const postInventory = historyIndex(
      history,
      leafFsyncIndex,
      (event) => event.type === "readdir" && event.file === directory,
      `${label} lacks a post-fsync exact inventory read`,
    );
    const close = historyIndex(
      history,
      Math.max(postFstat, postLstat, postRealpath, postInventory),
      (event) => event.type === "close"
        && event.file === directory
        && event.descriptor === open.event.descriptor,
      `${label} pin was closed before post-fsync revalidation`,
    );
    const initialIdentity = normalizedDirectoryIdentity(history[initialFstat]);
    const settledIdentity = normalizedDirectoryIdentity(settledFstat.event);
    const postIdentity = normalizedDirectoryIdentity(history[postFstat]);
    const pathIdentity = normalizedDirectoryIdentity(history[postLstat]);
    assert.equal(initialIdentity.isDirectory, true, `${label} pin is not a directory`);
    assert.equal(initialIdentity.isSymlink, false, `${label} pin resolved a symlink`);
    assert.deepEqual(
      postIdentity,
      settledIdentity,
      `${label} pinned descriptor identity changed`,
    );
    assert.deepEqual(
      pathIdentity,
      postIdentity,
      `${label} pathname no longer resolves to the pinned directory`,
    );
    assert.equal(
      history[postRealpath].resolved,
      directory,
      `${label} post-fsync realpath escaped its exact authority path`,
    );
    assert.deepEqual(
      history[postInventory].inventory,
      [...expectedInventory].sort(),
      `${label} post-fsync inventory is not exact`,
    );
    const directoryFsyncs = history.filter(
      (event) => event.type === "fsync" && event.file === directory,
    );
    assert.ok(directoryFsyncs.length > 0, `${label} was never fsynced`);
    assert.equal(
      directoryFsyncs.every(
        (event) => event.descriptor === open.event.descriptor,
      ),
      true,
      `${label} fsync escaped its pinned descriptor`,
    );
    assert.ok(close < historyEnd);
  }
}

function assertSnapshotLeafSealHistory(events, {
  expectedDirectoryInventory = ["job.json"],
  expectedBytes,
  file,
  finalDirectoryInventory,
  finalLeafStat,
  historyEnd = events.length,
  label = "snapshot leaf",
}) {
  const history = events.slice(0, historyEnd);
  const opens = history.filter((event) => event.type === "open" && event.file === file);
  assert.equal(opens.length, 1, `${label} must have exactly one successful open`);
  const [open] = opens;
  assert.equal(
    open.flags & (
      fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW
    ),
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
    `${label} was not safely opened`,
  );
  assert.equal(open.mode, 0o400, `${label} open mode must be 0400`);
  const openIndex = history.indexOf(open);
  const writes = history
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.type === "write" && event.file === file);
  assert.ok(writes.length > 0, `${label} has no descriptor write`);
  assert.equal(
    writes.every(({ event, index }) => index > openIndex
      && event.descriptor === open.descriptor
      && event.pathnameWrite === false),
    true,
    `${label} write escaped the one safely-opened descriptor`,
  );
  const fsyncs = history
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.type === "fsync" && event.file === file);
  assert.equal(fsyncs.length, 1, `${label} must fsync its one descriptor exactly once`);
  const [leafFsync] = fsyncs;
  assert.equal(
    leafFsync.event.descriptor,
    open.descriptor,
    `${label} fsync used a decoy or reopened descriptor`,
  );
  assert.equal(
    writes
      .filter(({ index }) => index < leafFsync.index)
      .reduce((sum, { event }) => sum + event.bytes, 0),
    expectedBytes,
    `${label} was not completely written before fsync`,
  );
  assert.equal(
    leafFsync.event.size,
    expectedBytes,
    `${label} fsynced inode length does not equal the exact snapshot bytes`,
  );
  assert.equal(
    writes.some(({ index }) => index > leafFsync.index),
    false,
    `${label} was rewritten after fsync`,
  );
  assertOnlyDescriptorWritesBeforeFsync(history, {
    descriptor: open.descriptor,
    file,
    fsyncIndex: leafFsync.index,
    label,
    openIndex,
  });
  const closes = history
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.type === "close"
      && event.file === file
      && event.descriptor === open.descriptor);
  assert.equal(closes.length, 1, `${label} must close its one descriptor exactly once`);
  assert.ok(
    closes[0].index > leafFsync.index,
    `${label} descriptor closed before its fsync`,
  );
  assertPathImmutableAfter(
    history,
    file,
    leafFsync.index,
    history.length,
    label,
  );
  const finalStat = finalLeafStat ?? fs.lstatSync(file, { bigint: true });
  assertFsyncMatchesFinalRegularLeaf(leafFsync.event, finalStat, label);
  assert.equal(finalStat.mode & 0o777, 0o400, `${label} final mode must be 0400`);
  if (finalDirectoryInventory === undefined) {
    assertExactDirectoryInventory(
      path.dirname(file),
      expectedDirectoryInventory,
      `${label} request directory`,
    );
  } else {
    assert.deepEqual(
      [...finalDirectoryInventory].sort(),
      [...expectedDirectoryInventory].sort(),
      `${label} synthetic request directory inventory is not exact`,
    );
  }
  return {
    closeIndex: closes[0].index,
    descriptor: open.descriptor,
    fsyncIndex: leafFsync.index,
    openIndex,
  };
}

function assertSnapshotCleanupHistory(events, {
  historyStart,
  sealed,
  label = "snapshot cleanup",
}) {
  const requestDirectory = path.dirname(sealed.hostPath);
  const claimedJobsDirectory = path.dirname(requestDirectory);
  const mutations = events
    .slice(historyStart)
    .filter(isMutatingIoEvent)
    .map(({ file, from, to, type }) => ({ file, from, to, type }));
  assert.deepEqual(
    mutations,
    [
      {
        file: sealed.hostPath,
        from: undefined,
        to: undefined,
        type: "unlink",
      },
      {
        file: requestDirectory,
        from: undefined,
        to: undefined,
        type: "rmdir",
      },
    ],
    `${label} performed an unexpected write, rename or destructive operation`,
  );
  const unlinkIndex = historyIndex(
    events,
    historyStart - 1,
    ({ file, type }) => type === "unlink" && file === sealed.hostPath,
    `${label} did not unlink the exact leaf`,
  );
  const requestFsync = historyIndex(
    events,
    unlinkIndex,
    ({ file, type }) => type === "fsync" && file === requestDirectory,
    `${label} did not fsync the request directory after leaf unlink`,
  );
  const rmdirIndex = historyIndex(
    events,
    requestFsync,
    ({ file, type }) => type === "rmdir" && file === requestDirectory,
    `${label} removed the request directory before its unlink was durable`,
  );
  return historyIndex(
    events,
    rmdirIndex,
    ({ file, type }) => type === "fsync" && file === claimedJobsDirectory,
    `${label} did not fsync claimed-jobs after request-directory removal`,
  );
}

function assertExactlyTwoDescriptorReadPasses(audit, label = "claimed-job reader") {
  assert.equal(
    audit.startedReadPasses.length,
    2,
    `${label} must start exactly two descriptor passes`,
  );
  assert.equal(
    audit.completedReadPasses.length,
    2,
    `${label} must complete exactly two descriptor passes`,
  );
  assert.deepEqual(
    audit.startedReadPasses.map(({ descriptor, initialPosition, pass }) => ({
      descriptor,
      initialPosition,
      pass,
    })),
    audit.completedReadPasses.map(({ descriptor, initialPosition, pass }) => ({
      descriptor,
      initialPosition,
      pass,
    })),
    `${label} started an incomplete or substituted descriptor pass`,
  );
}

function assertInspectAllBeforeDeleteAll(calls, expectedInspects, expectedDeletes, label) {
  assert.deepEqual(
    calls
      .filter(({ method }) => method === "inspectContainerForRecovery"
        || method === "deleteContainer")
      .map(({ id, method, name }) => [method, name ?? id]),
    [
      ...expectedInspects.map((name) => ["inspectContainerForRecovery", name]),
      ...expectedDeletes.map((id) => ["deleteContainer", id]),
    ],
    `${label} did not attest the entire reverse-order worker set before deletion`,
  );
}

function stableStatFingerprint(stat) {
  return Object.fromEntries([
    "dev",
    "ino",
    "mode",
    "nlink",
    "uid",
    "gid",
    "rdev",
    "size",
    "blksize",
    "blocks",
    "mtimeNs",
    "ctimeNs",
    "birthtimeNs",
  ].map((field) => [field, stat[field]]));
}

function captureTreeSnapshot(root) {
  const resolvedRoot = path.resolve(root);
  const entries = [];
  const visit = (candidate) => {
    const stat = fs.lstatSync(candidate, { bigint: true });
    const relative = path.relative(resolvedRoot, candidate) || ".";
    const entry = {
      path: relative,
      stat: stableStatFingerprint(stat),
      type: stat.isDirectory()
        ? "directory"
        : stat.isFile()
          ? "file"
          : stat.isSymbolicLink()
            ? "symlink"
            : "other",
    };
    if (stat.isFile()) {
      entry.bytes = fs.readFileSync(candidate).toString("base64");
    } else if (stat.isSymbolicLink()) {
      entry.target = fs.readlinkSync(candidate);
    }
    entries.push(entry);
    if (stat.isDirectory()) {
      for (const name of fs.readdirSync(candidate).sort()) {
        visit(path.join(candidate, name));
      }
    }
  };
  visit(resolvedRoot);
  return entries;
}

function assertNoStateMutationEvents(events, root, label) {
  const resolvedRoot = path.resolve(root);
  const writeFlags = fs.constants.O_WRONLY
    | fs.constants.O_RDWR
    | fs.constants.O_CREAT
    | fs.constants.O_TRUNC
    | fs.constants.O_APPEND;
  const inside = (candidate) => typeof candidate === "string"
    && (candidate === resolvedRoot || candidate.startsWith(`${resolvedRoot}${path.sep}`));
  const hostile = events.filter((event) => (
    event.type === "open"
      ? inside(event.file) && (event.flags & writeFlags) !== 0
      : isMutatingIoEvent(event)
        && [event.file, event.from, event.to].some(inside)
  ));
  assert.deepEqual(hostile, [], `${label} mutated the preserved replay tree`);
}

function assertActiveUnlinkFsyncOrder(events, activePath, lastHeadRootFsync, label) {
  const unlinks = events
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.type === "unlink" && event.file === activePath);
  assert.equal(unlinks.length, 1, `${label} must unlink active.lock exactly once`);
  const [unlink] = unlinks;
  assert.ok(
    unlink.index > lastHeadRootFsync,
    `${label} unlinked active.lock before the final durable head root-fsync`,
  );
  const removalRootFsync = historyIndex(
    events,
    unlink.index,
    (event) => event.type === "fsync" && event.file === path.dirname(activePath),
    `${label} did not fsync the state root after active.lock unlink`,
  );
  return { removalRootFsync, unlinkIndex: unlink.index };
}

function assertLeaseRemovalFsync(root, audit, startIndex, label) {
  const activePath = path.join(root, "active.lock");
  const destructive = audit.events
    .map((event, index) => ({ event, index }))
    .filter(({ event, index }) => index >= startIndex
      && ["rm", "rmdir", "unlink"].includes(event.type));
  assert.equal(
    destructive.some(({ event }) => event.type === "rm"),
    false,
    `${label} used opaque recursive removal instead of exact unlink/rmdir`,
  );
  const activeUnlinks = destructive.filter(
    ({ event }) => event.type === "unlink" && event.file === activePath,
  );
  assert.equal(activeUnlinks.length, 1, `${label} must unlink active.lock exactly once`);
  for (const { event, index } of destructive) {
    historyIndex(
      audit.events,
      index,
      (candidate) => candidate.type === "fsync"
        && candidate.file === path.dirname(event.file),
      `${label} did not fsync ${path.dirname(event.file)} after ${event.type}(${event.file})`,
    );
  }
}

function assertBarrierFsyncOrder(root, phaseId, audit) {
  const { directory, entries } = journalFiles(root);
  const barrierFiles = entries.filter((file) => {
    const entry = readJson(file);
    return entry.phaseId === phaseId
      && ["worker-result-recorded", "worker-deleted"].includes(entry.event);
  });
  assert.equal(barrierFiles.length, 2, `${phaseId} requires result and cleanup barrier entries`);
  assertJournalAppendFsyncOrder(root, directory, barrierFiles, audit, phaseId);
}

function assertJournalAppendFsyncOrder(
  root,
  directory,
  files,
  audit,
  label,
  { allowActiveUnlink = false } = {},
) {
  let cursor = -1;
  let scopeStart = null;
  const historyEnd = audit.events.length;
  const activePath = path.join(root, "active.lock");
  const active = fs.existsSync(activePath) ? readJson(activePath) : null;
  const expectedJournalInventory = active
    ? Array.from(
        { length: active.journalEntryCount },
        (_, index) => `${String(index).padStart(16, "0")}.json`,
      )
    : files.map((file) => path.basename(file));
  assertExactDirectoryInventory(
    directory,
    expectedJournalInventory,
    `${label} journal directory`,
  );
  for (const name of expectedJournalInventory) {
    const stat = fs.lstatSync(path.join(directory, name));
    assert.equal(stat.isFile(), true, `${label} journal inventory leaf is not regular: ${name}`);
    assert.equal(stat.nlink, 1, `${label} journal inventory leaf is hard-linked: ${name}`);
  }
  const headTemps = new Set();
  const headRenameIndexes = new Set();
  let lastInstalledHeadIdentity = null;
  for (const file of files) {
    const openIndex = historyIndex(
      audit.events,
      cursor,
      (event) => event.type === "open"
        && event.file === file
        && (event.flags & (
          fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_NOFOLLOW
        )) === (
          fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_NOFOLLOW
        ),
      `${label} journal entry was not opened exclusively: ${file}`,
    );
    scopeStart ??= openIndex;
    const entryOpen = audit.events[openIndex];
    assert.equal(
      audit.events
        .slice(0, historyEnd)
        .filter((event) => event.type === "open" && event.file === file)
        .length,
      1,
      `${label} journal entry was reopened: ${file}`,
    );
    const entryWrites = audit.events
      .slice(openIndex + 1, historyEnd)
      .map((event, relativeIndex) => ({ event, index: openIndex + 1 + relativeIndex }))
      .filter(({ event }) => event.type === "write" && event.file === file);
    assert.ok(entryWrites.length > 0, `${label} journal entry has no write: ${file}`);
    assert.equal(
      entryWrites.every(({ event }) => event.descriptor === entryOpen.descriptor
        && event.pathnameWrite === false),
      true,
      `${label} journal entry write escaped its exclusive descriptor: ${file}`,
    );
    const entryFsync = historyIndex(
      audit.events,
      openIndex,
      (event) => event.type === "fsync"
        && event.file === file
        && event.descriptor === entryOpen.descriptor,
      `${label} journal entry was fsynced before its write: ${file}`,
    );
    assert.equal(
      entryWrites
        .filter(({ index }) => index < entryFsync)
        .reduce((sum, { event }) => sum + event.bytes, 0),
      audit.events[entryFsync].size,
      `${label} journal entry was not completely written before fsync: ${file}`,
    );
    assertOnlyDescriptorWritesBeforeFsync(audit.events, {
      descriptor: entryOpen.descriptor,
      file,
      fsyncIndex: entryFsync,
      label: `${label} journal entry`,
      openIndex,
    });
    assertFsyncMatchesFinalRegularLeaf(
      audit.events[entryFsync],
      fs.lstatSync(file, { bigint: true }),
      `${label} journal entry`,
    );
    const entryClose = historyIndex(
      audit.events,
      entryFsync,
      (event) => event.type === "close"
        && event.file === file
        && event.descriptor === entryOpen.descriptor,
      `${label} journal entry descriptor was not closed after fsync: ${file}`,
    );
    const directoryFsync = historyIndex(
      audit.events,
      entryClose,
      (event) => event.type === "fsync" && event.file === directory,
      `${label} journal directory was not fsynced for entry: ${file}`,
    );
    assertPathImmutableAfter(
      audit.events,
      file,
      entryFsync,
      historyEnd,
      `${label} journal entry`,
    );
    const headOpen = historyIndex(
      audit.events,
      directoryFsync,
      (event) => event.type === "open"
        && event.file !== activePath
        && path.dirname(event.file) === root
        && path.basename(event.file).includes("active.lock")
        && (event.flags & (
          fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_NOFOLLOW
        )) === (
          fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_NOFOLLOW
        ),
      `${label} lease head temp was not exclusively opened after journal durability: ${file}`,
    );
    const headOpenEvent = audit.events[headOpen];
    const headFile = headOpenEvent.file;
    assert.equal(
      headTemps.has(headFile),
      false,
      `${label} reused a prior lease head temp: ${headFile}`,
    );
    headTemps.add(headFile);
    const headWrites = audit.events
      .slice(headOpen + 1, historyEnd)
      .map((event, relativeIndex) => ({ event, index: headOpen + 1 + relativeIndex }))
      .filter(({ event }) => event.type === "write" && event.file === headFile);
    assert.ok(headWrites.length > 0, `${label} lease head temp has no write: ${headFile}`);
    assert.equal(
      headWrites.every(({ event }) => event.descriptor === headOpenEvent.descriptor
        && event.pathnameWrite === false),
      true,
      `${label} lease head temp write escaped its exclusive descriptor`,
    );
    const headFsync = historyIndex(
      audit.events,
      headOpen,
      (event) => event.type === "fsync"
        && event.file === headFile
        && event.descriptor === headOpenEvent.descriptor,
      `${label} lease head temp was fsynced before its write: ${headFile}`,
    );
    assert.equal(
      headWrites
        .filter(({ index }) => index < headFsync)
        .reduce((sum, { event }) => sum + event.bytes, 0),
      audit.events[headFsync].size,
      `${label} lease head temp was not completely written before fsync`,
    );
    assertOnlyDescriptorWritesBeforeFsync(audit.events, {
      descriptor: headOpenEvent.descriptor,
      file: headFile,
      fsyncIndex: headFsync,
      label: `${label} lease head temp`,
      openIndex: headOpen,
    });
    const headClose = historyIndex(
      audit.events,
      headFsync,
      (event) => event.type === "close"
        && event.file === headFile
        && event.descriptor === headOpenEvent.descriptor,
      `${label} lease head temp descriptor was not closed after fsync`,
    );
    const headRename = historyIndex(
      audit.events,
      headClose,
      (event) => event.type === "rename"
        && event.from === headFile
        && event.to === activePath,
      `${label} lease head was not atomically installed from its fsynced temp`,
    );
    headRenameIndexes.add(headRename);
    assert.equal(
      audit.events[headRename].sourceSize,
      audit.events[headFsync].size,
      `${label} renamed an incomplete or substituted lease head temp`,
    );
    assertFsyncMatchesFinalRegularLeaf(
      audit.events[headFsync],
      audit.events[headRename].sourceIdentity,
      `${label} lease head temp before rename`,
    );
    assertRenamePreservesRegularLeafIdentity(
      audit.events[headRename].sourceIdentity,
      audit.events[headRename].destinationIdentity,
      `${label} installed lease head`,
    );
    lastInstalledHeadIdentity = audit.events[headRename].destinationIdentity;
    const forbiddenTempMutation = audit.events
      .slice(headFsync + 1, historyEnd)
      .map((event, relativeIndex) => ({ event, index: headFsync + 1 + relativeIndex }))
      .filter(({ event, index }) => isMutatingIoEvent(event)
        && eventCanReplacePathIdentity(event, headFile)
        && !(index === headRename
          && event.type === "rename"
          && event.from === headFile
          && event.to === activePath));
    assert.deepEqual(
      forbiddenTempMutation,
      [],
      `${label} lease head temp changed after its durable fsync`,
    );
    cursor = historyIndex(
      audit.events,
      headRename,
      (event) => event.type === "fsync" && event.file === root,
      `${label} broker state directory was not fsynced after head install`,
    );
  }
  const activeMutations = audit.events
    .slice(scopeStart ?? 0, historyEnd)
    .map((event, relativeIndex) => ({
      event,
      index: (scopeStart ?? 0) + relativeIndex,
    }))
    .filter(({ event }) => isMutatingIoEvent(event)
      && eventCanReplacePathIdentity(event, activePath));
  const activeUnlink = allowActiveUnlink
    ? assertActiveUnlinkFsyncOrder(
        audit.events,
        activePath,
        cursor,
        label,
      )
    : null;
  assert.equal(
    activeMutations.every(({ event, index }) => (
      headRenameIndexes.has(index)
        && event.type === "rename"
        && event.to === activePath
    ) || (
      allowActiveUnlink
        && index === activeUnlink.unlinkIndex
        && event.type === "unlink"
        && event.file === activePath
    )),
    true,
    `${label} mutated or rekeyed active.lock outside an expected durable-head rename`,
  );
  const activeAliases = fs.readdirSync(root)
    .filter((name) => name.includes("active.lock"))
    .sort();
  assert.deepEqual(
    activeAliases,
    fs.existsSync(activePath) ? ["active.lock"] : [],
    `${label} left an orphan, alias or temp lease head`,
  );
  const includesFinalHead = files.length > 0
    && path.basename(files.at(-1)) === expectedJournalInventory.at(-1);
  if (active && includesFinalHead) {
    assertFsyncMatchesFinalRegularLeaf(
      lastInstalledHeadIdentity,
      fs.lstatSync(activePath, { bigint: true }),
      `${label} final active lease head`,
    );
  }
  return cursor;
}

function writeDurableTestJson(file, value) {
  const descriptor = fs.openSync(
    file,
    fs.constants.O_WRONLY
      | fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, Buffer.from(`${JSON.stringify(value)}\n`));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  const directory = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(directory);
  } finally {
    fs.closeSync(directory);
  }
}

function tempDir(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-broker-v2-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
