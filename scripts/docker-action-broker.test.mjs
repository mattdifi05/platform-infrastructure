import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import testRunner from "node:test";

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

if (HAS_SEMANTIC_EXECUTOR) {
  testRunner("RED v2: broker exports the descriptor-stable claimed-job reader", () => {
    assert.equal(
      typeof broker.readClaimedJobSnapshot,
      "function",
      "docker-action-broker must export readClaimedJobSnapshot",
    );
  });
} else {
  testRunner(
    "RED v2: broker exports the descriptor-stable claimed-job reader",
    { todo: "blocked only by the active createSemanticActionExecutor API RED" },
    () => {},
  );
}

function readerTest(name, callback) {
  if (HAS_SEMANTIC_EXECUTOR && HAS_CLAIMED_JOB_READER) {
    return testRunner(name, callback);
  }
  const reason = HAS_SEMANTIC_EXECUTOR
    ? "blocked only by the active readClaimedJobSnapshot export RED"
    : "blocked only by the active createSemanticActionExecutor API RED";
  return testRunner(name, { todo: reason }, () => {});
}

if (HAS_SEMANTIC_EXECUTOR) {
  testRunner("RED v2: broker exports the root-owned immutable snapshot file store", () => {
    assert.equal(
      typeof broker.createSnapshotFileStore,
      "function",
      "docker-action-broker must export createSnapshotFileStore",
    );
  });
} else {
  testRunner(
    "RED v2: broker exports the root-owned immutable snapshot file store",
    { todo: "blocked only by the active createSemanticActionExecutor API RED" },
    () => {},
  );
}

function snapshotTest(name, callback) {
  if (HAS_SEMANTIC_EXECUTOR && HAS_SNAPSHOT_STORE) {
    return testRunner(name, callback);
  }
  const reason = HAS_SEMANTIC_EXECUTOR
    ? "blocked only by the active createSnapshotFileStore export RED"
    : "blocked only by the active createSemanticActionExecutor API RED";
  return testRunner(name, { todo: reason }, () => {});
}

if (HAS_SEMANTIC_EXECUTOR) {
  testRunner("RED v2: broker exports the canonical response frame encoder", () => {
    assert.equal(
      typeof broker.encodeActionResponseFrame,
      "function",
      "docker-action-broker must export encodeActionResponseFrame",
    );
  });
} else {
  testRunner(
    "RED v2: broker exports the canonical response frame encoder",
    { todo: "blocked only by the active createSemanticActionExecutor API RED" },
    () => {},
  );
}

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

const INSPECT_WIDENINGS = Object.freeze([
  widening("container-id", (inspect) => ({ ...inspect, Id: "9".repeat(64) })),
  widening("container-name", (inspect) => ({ ...inspect, Name: "/attacker-worker" })),
  widening("resolved-image", (inspect) => ({ ...inspect, Image: `sha256:${"9".repeat(64)}` })),
  widening("config-image", (inspect) => ({
    ...inspect,
    Config: { ...inspect.Config, Image: "attacker/image:latest" },
  })),
  widening("env.snapshot-path", (inspect) => mutateEnv(inspect, "PLATFORM_CLAIMED_JOB_PATH", "/host/attacker")),
  widening("env.snapshot-metadata", (inspect) => mutateEnv(inspect, "PLATFORM_CLAIMED_JOB_SHA256", "9".repeat(64))),
  widening("entrypoint", (inspect) => ({ ...inspect, Config: { ...inspect.Config, Entrypoint: ["sh"] } })),
  widening("cmd", (inspect) => ({ ...inspect, Config: { ...inspect.Config, Cmd: ["sh", "-c", "id"] } })),
  widening("user", (inspect) => ({ ...inspect, Config: { ...inspect.Config, User: "65532:65532" } })),
  widening("working-dir", (inspect) => ({ ...inspect, Config: { ...inspect.Config, WorkingDir: "/tmp" } })),
  widening("labels", (inspect) => {
    const labels = { ...inspect.Config.Labels };
    delete labels["com.platform.docker-phase-sha256"];
    return { ...inspect, Config: { ...inspect.Config, Labels: labels } };
  }),
  widening("readonly-rootfs", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, ReadonlyRootfs: false },
  })),
  widening("security-opt", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, SecurityOpt: [] },
  })),
  widening("namespace-cgroup", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, CgroupnsMode: "host" },
  })),
  widening("namespace-pid", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, PidMode: "host" },
  })),
  widening("namespace-ipc", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, IpcMode: "host" },
  })),
  widening("namespace-user", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, UsernsMode: "host" },
  })),
  widening("namespace-uts", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, UTSMode: "host" },
  })),
  widening("privileged", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, Privileged: true },
  })),
  widening("capability", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, CapAdd: ["SYS_ADMIN"] },
  })),
  widening("bind", (inspect) => ({
    ...inspect,
    HostConfig: { ...inspect.HostConfig, Binds: ["/:/host:rw"] },
    Mounts: [{ Type: "bind", Source: "/", Destination: "/host", RW: true }],
  })),
  widening("named-volume", (inspect) => ({
    ...inspect,
    Mounts: inspect.Mounts.length === 0
      ? [{
          Type: "volume",
          Name: "attacker",
          Source: "/var/lib/docker/volumes/attacker/_data",
          Destination: "/run/attacker",
          Driver: "local",
          Mode: "",
          RW: true,
          Propagation: "",
        }]
      : inspect.Mounts.map((mount, index) => (
          index === inspect.Mounts.length - 1
            ? { ...mount, Name: "attacker", Source: "/var/lib/docker/volumes/attacker/_data" }
            : mount
        )),
  })),
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
      ["phase", (value) => ({ ...value, phaseId: "restore.verify" })],
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
  const expectedDirectory = path.join(
    mountpoint,
    source.snapshotVolumeSubpath,
    requestSha256,
  );
  const claimedJobsDirectory = path.dirname(expectedDirectory);
  assert.equal(sealed.hostPath, path.join(expectedDirectory, "job.json"));
  assert.equal(sealed.containerPath, SNAPSHOT_CONTAINER_PATH);
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
    leafFsyncIndex,
    ({ file, type }) => type === "fsync" && file === expectedDirectory,
    "snapshot request directory was not fsynced after the durable leaf write",
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
  const siblingRequestSha256 = requestSha256 === "a".repeat(64)
    ? "b".repeat(64)
    : "a".repeat(64);
  const siblingDirectory = path.join(claimedJobsDirectory, siblingRequestSha256);
  const siblingFile = path.join(siblingDirectory, "job.json");
  fs.mkdirSync(siblingDirectory, { mode: 0o700 });
  fs.writeFileSync(siblingFile, "survivor\n", { mode: 0o400 });
  fs.chmodSync(siblingFile, 0o400);
  const siblingBefore = fs.statSync(siblingFile);
  const cleanupStart = audit.events.length;
  await store.cleanup(sealed);
  assert.equal(fs.existsSync(sealed.hostPath), false);
  assert.equal(fs.existsSync(expectedDirectory), false);
  assert.equal(fs.existsSync(mountpoint), true);
  assert.equal(fs.existsSync(claimedJobsDirectory), true);
  assert.equal(fs.readFileSync(siblingFile, "utf8"), "survivor\n");
  const siblingAfter = fs.statSync(siblingFile);
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
  assert.deepEqual(
    cleanupEvents
      .filter(({ type }) => type === "unlink" || type === "rmdir" || type === "rm")
      .map(({ file, type }) => ({ file, type })),
    [
      { file: sealed.hostPath, type: "unlink" },
      { file: expectedDirectory, type: "rmdir" },
    ],
    "snapshot cleanup escaped its exact request leaf/directory or used recursive removal",
  );
  const unlinkIndex = historyIndex(
    audit.events,
    cleanupStart - 1,
    ({ file, type }) => type === "unlink" && file === sealed.hostPath,
    "snapshot cleanup did not unlink the exact leaf",
  );
  const rmdirIndex = historyIndex(
    audit.events,
    unlinkIndex,
    ({ file, type }) => type === "rmdir" && file === expectedDirectory,
    "snapshot cleanup did not remove the empty request directory after its leaf",
  );
  historyIndex(
    audit.events,
    rmdirIndex,
    ({ file, type }) => type === "fsync" && file === claimedJobsDirectory,
    "snapshot cleanup did not fsync claimed-jobs after unlink/rmdir",
  );
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
  assert.equal(
    probe.audit.completedReadPasses.length,
    2,
    "claimed job must be read in two complete positioned passes",
  );
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
  assert.equal(racing.audit.completedReadPasses.length, 2);
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
      if (required.length === 0) continue;
      await t.test(resourceKind, async (t) => {
        const baseline = semanticFixture(t, phase);
        await baseline.executor.executePhase(phase.action, phase.phaseId, baseline.context);
        assert.equal(baseline.transport.created.length, 1);

        const option = resourceKind === "network"
          ? { networkMutation: (inspect) => ({ ...inspect, Id: "9".repeat(64) }) }
          : { volumeMutation: (inspect) => ({ ...inspect, Name: "attacker-volume" }) };
        const hostile = semanticFixture(t, phase, option);
        await assert.rejects(
          () => hostile.executor.executePhase(phase.action, phase.phaseId, hostile.context),
          /network|volume|inspect|identity|exact/i,
        );
        assert.equal(hostile.transport.created.length, 0);
      });
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
    const restarted = createReplayStore(baseline.root, "b".repeat(48));
    await assert.rejects(
      () => restarted.recover(recovery),
      /journal|chain|sequence|head|duplicate|corrupt|integrity|entry/i,
    );
    assert.equal(fs.existsSync(path.join(baseline.root, "active.lock")), true);
    assert.deepEqual(recoveryTransport.calls, []);
  });
}

test("v2 journal sequence/head bind exactly and post-terminal appends are rejected", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "prune.apply");
  const root = tempDir(t);
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48));
  store.admitTrustedContext(trusted);
  const request = admittedRequest(phase.action, {}, trusted);
  const lease = store.acquire(request, trusted);
  const fixture = semanticFixture(t, phase, { trusted, lease, request });
  await fixture.executor.executePhase(phase.action, phase.phaseId, fixture.context);
  lease.preserve();
  const entries = assertJournalChain(root, request);
  assert.equal(entries.at(-1).event, "action-completed");
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
  assert.deepEqual(
    transport.calls
      .filter(({ method }) => method === "inspectContainerForRecovery" || method === "deleteContainer")
      .map(({ method, id, name }) => [method, name ?? id]),
    [
      ["inspectContainerForRecovery", "platform-action-restore-verify-1"],
      ["deleteContainer", RESTORE_WORKER_ID],
      ["inspectContainerForRecovery", "platform-action-restore-capture-0"],
      ["deleteContainer", WORKER_ID],
    ],
  );
  assert.deepEqual(lifecycle, [
    `worker-deleted:${RESTORE_WORKER_ID}`,
    `worker-deleted:${WORKER_ID}`,
    "lease-unlinked",
  ]);
  assert.equal(fs.existsSync(path.join(root, "active.lock")), false);
  assertLeaseRemovalFsync(root, recoveryIo.audit, 0, "worker recovery");
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
      const restarted = createReplayStore(root, "b".repeat(48), { io: recoveryIo.io });
      await assert.rejects(
        () => restarted.recover(executor),
        /absent|authority|forbidden|identity|image|inspect|exact|mismatch|missing|mount|name|network|recovery|worker/i,
      );
      assert.deepEqual(transport.deletedIds, []);
      assert.deepEqual(
        transport.calls.map(({ method }) => method),
        ["inspectContainerForRecovery"],
      );
      assert.deepEqual(
        recoveryIo.audit.events.filter(
          ({ type }) => type === "unlink" || type === "rmdir" || type === "rm",
        ),
        [],
        `${id} performed destructive recovery IO after an unproven inspect`,
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
  assert.deepEqual(
    transport.calls
      .filter(({ method }) => method === "inspectContainerForRecovery" || method === "deleteContainer")
      .map(({ method }) => method),
    ["inspectContainerForRecovery", "deleteContainer"],
  );
  assert.deepEqual(snapshotFileStore.cleanupCalls, [sealed]);
  assert.deepEqual(lifecycle, ["worker-deleted", "snapshot-cleaned", "lease-unlinked"]);
  assert.equal(fs.existsSync(path.join(root, "active.lock")), false);
  assertLeaseRemovalFsync(root, recoveryIo.audit, 0, "claimed-job recovery");
});

test("v2 offsite remote-unknown is terminal, preserves the lease and forbids automatic replay", async (t) => {
  const phase = PHASE_CASES.find(({ phaseId }) => phaseId === "offsite.sync");
  const root = tempDir(t);
  const trusted = directTrustedContext();
  const store = createReplayStore(root, "a".repeat(48));
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
  assert.equal(entries.at(-1).event, "remote-effect-unknown");
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
  const restarted = createReplayStore(root, "b".repeat(48));
  await assert.rejects(
    () => restarted.recover(createSemanticExecutor({ transport: recoveryTransport })),
    /remote|unknown|reconcile|terminal/i,
  );
  assert.deepEqual(recoveryTransport.calls, []);
  assert.equal(fs.existsSync(path.join(root, "active.lock")), true);
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
  const rawFrame = Buffer.from(JSON.stringify(
    Object.fromEntries(Object.entries(request).reverse()),
  ));
  const requestSha256 = crypto
    .createHash("sha256")
    .update(canonicalRequestBytes)
    .digest("hex");
  assert.notEqual(
    crypto.createHash("sha256").update(rawFrame).digest("hex"),
    requestSha256,
    "the raw-frame fixture must distinguish byte hashing from canonical request hashing",
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
    admitActivation() {},
    admitTrustedContext: (...args) => persistentReplayStore.admitTrustedContext(...args),
    consume: (...args) => persistentReplayStore.consume(...args),
    acquire(candidateRequest, candidateTrusted) {
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
      assert.equal(action, request.action);
      return capabilityKey;
    },
    engine,
    now: () => NOW,
    operationTimeoutMs: 1_000,
    replayStore,
    trustedContextProvider: async () => trusted,
  });
  const wire = await core.handle(rawFrame);
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
    networkMutation,
    volumeMutation,
    logsError,
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
    this.networkMutation = networkMutation;
    this.volumeMutation = volumeMutation;
    this.logsError = logsError;
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
    return this.inspectMutation ? this.inspectMutation(structuredClone(inspect), created.phase) : inspect;
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
    return this.inspectMutation
      ? this.inspectMutation(structuredClone(inspect), worker.phase)
      : inspect;
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
    Entrypoint: ["node", "/opt/platform-docker-worker/docker-action-worker.mjs"],
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
  const { active, entries } = journalFiles(root);
  const request = expectedRequest ?? active.request;
  admittedRequestShape(request);
  const requestSha256 = fixtureSha256(canonicalFixtureJson(request));
  assert.deepEqual(active.request, request);
  assert.equal(active.requestId, request.requestId);
  assert.equal(active.requestSha256, requestSha256);
  assert.equal(active.action, request.action);
  let previous = "0".repeat(64);
  const values = entries.map((file, index) => {
    const value = readJson(file);
    assert.equal(value.schema, JOURNAL_ENTRY_SCHEMA_V2);
    assert.equal(value.sequence, index);
    assert.equal(value.previousEntrySha256, previous);
    assert.equal(value.requestId, request.requestId);
    assert.equal(value.requestSha256, requestSha256);
    assert.equal(value.action, request.action);
    previous = fixtureSha256(canonicalFixtureJson(value));
    return value;
  });
  assert.equal(active.journalEntryCount, values.length);
  assert.equal(active.journalHeadSha256, previous);
  return values;
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

function filesystemHistoryProbe({ onEvent = () => {} } = {}) {
  const audit = { descriptors: new Map(), events: [], opens: [] };
  const record = (event) => {
    audit.events.push(event);
    onEvent(structuredClone(event));
  };
  const resolvedFile = (value) => (
    typeof value === "number"
      ? audit.descriptors.get(value) ?? `fd:${value}`
      : path.resolve(String(value))
  );
  const io = new Proxy(fs, {
    get(target, property) {
      if (property === "openSync") {
        return (file, flags, mode) => {
          const descriptor = fs.openSync(file, flags, mode);
          const resolved = path.resolve(String(file));
          audit.descriptors.set(descriptor, resolved);
          const event = { type: "open", file: resolved, flags, mode, descriptor };
          record(event);
          audit.opens.push(event);
          return descriptor;
        };
      }
      if (property === "mkdirSync") {
        return (directory, options) => {
          const result = fs.mkdirSync(directory, options);
          record({
            type: "mkdir",
            file: path.resolve(String(directory)),
            options: structuredClone(options ?? null),
          });
          return result;
        };
      }
      if (property === "writeFileSync") {
        return (file, data, options) => {
          const result = fs.writeFileSync(file, data, options);
          record({
            type: "write",
            file: resolvedFile(file),
            bytes: Buffer.byteLength(
              Buffer.isBuffer(data) || ArrayBuffer.isView(data)
                ? Buffer.from(data.buffer, data.byteOffset, data.byteLength)
                : String(data),
            ),
            method: "writeFileSync",
          });
          return result;
        };
      }
      if (property === "writeSync") {
        return (descriptor, ...args) => {
          const count = fs.writeSync(descriptor, ...args);
          record({
            type: "write",
            file: resolvedFile(descriptor),
            bytes: count,
            method: "writeSync",
          });
          return count;
        };
      }
      if (property === "fsyncSync") {
        return (descriptor) => {
          const result = fs.fsyncSync(descriptor);
          record({
            type: "fsync",
            file: resolvedFile(descriptor),
          });
          return result;
        };
      }
      if (property === "closeSync") {
        return (descriptor) => {
          const file = resolvedFile(descriptor);
          const result = fs.closeSync(descriptor);
          record({
            type: "close",
            file,
          });
          audit.descriptors.delete(descriptor);
          return result;
        };
      }
      if (property === "unlinkSync") {
        return (file) => {
          const result = fs.unlinkSync(file);
          record({ type: "unlink", file: path.resolve(String(file)) });
          return result;
        };
      }
      if (property === "rmdirSync") {
        return (directory, options) => {
          const result = fs.rmdirSync(directory, options);
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
          const result = fs.rmSync(file, options);
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
          const result = fs.renameSync(from, to);
          record({
            type: "rename",
            from: path.resolve(String(from)),
            to: path.resolve(String(to)),
          });
          return result;
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
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

function assertJournalAppendFsyncOrder(root, directory, files, audit, label) {
  let cursor = -1;
  for (const file of files) {
    const openIndex = historyIndex(
      audit.events,
      cursor,
      (event) => event.type === "open"
        && event.file === file
        && (event.flags & fs.constants.O_EXCL) === fs.constants.O_EXCL,
      `${label} journal entry was not opened exclusively: ${file}`,
    );
    const writeIndex = historyIndex(
      audit.events,
      openIndex,
      (event) => event.type === "write" && event.file === file && event.bytes > 0,
      `${label} journal entry was not written after its exclusive open: ${file}`,
    );
    const entryFsync = historyIndex(
      audit.events,
      writeIndex,
      (event) => event.type === "fsync" && event.file === file,
      `${label} journal entry was fsynced before its write: ${file}`,
    );
    assert.equal(
      audit.events
        .slice(openIndex + 1, entryFsync)
        .filter((event) => event.type === "write" && event.file === file)
        .reduce((sum, event) => sum + event.bytes, 0),
      fs.statSync(file).size,
      `${label} journal entry was not completely written before fsync: ${file}`,
    );
    const directoryFsync = historyIndex(
      audit.events,
      entryFsync,
      (event) => event.type === "fsync" && event.file === directory,
      `${label} journal directory was not fsynced for entry: ${file}`,
    );
    assert.equal(
      audit.events
        .slice(entryFsync + 1, directoryFsync)
        .some((event) => event.type === "write" && event.file === file),
      false,
      `${label} journal entry changed after its durable fsync: ${file}`,
    );
    const headWrite = historyIndex(
      audit.events,
      directoryFsync,
      (event) => event.type === "write"
        && event.file !== path.join(root, "active.lock")
        && path.basename(event.file).includes("active.lock")
        && event.bytes > 0,
      `${label} lease head temp was not written after journal durability: ${file}`,
    );
    const headFile = audit.events[headWrite].file;
    const headFsync = historyIndex(
      audit.events,
      headWrite,
      (event) => event.type === "fsync" && event.file === headFile,
      `${label} lease head temp was fsynced before its write: ${headFile}`,
    );
    const headRename = historyIndex(
      audit.events,
      headFsync,
      (event) => event.type === "rename"
        && event.from === headFile
        && event.to === path.join(root, "active.lock"),
      `${label} lease head was not atomically installed from its fsynced temp`,
    );
    assert.equal(
      audit.events
        .slice(headFsync + 1, headRename)
        .some((event) => event.type === "write" && event.file === headFile),
      false,
      `${label} lease head temp changed after its durable fsync`,
    );
    cursor = historyIndex(
      audit.events,
      headRename,
      (event) => event.type === "fsync" && event.file === root,
      `${label} broker state directory was not fsynced after head install`,
    );
  }
  return cursor;
}

function tempDir(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-broker-v2-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
