import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createBackupJobDocument,
  parseBackupJobDocument,
} from "../control-center/backup/contracts.mjs";
import * as broker from "./docker-action-broker.mjs";
import * as contract from "./docker-action-contract.mjs";
import {
  ACTIVE_RECEIPT_SCHEMA_V2,
  EVIDENCE_ACTION_NAMES,
  EXPECTED_ACTION_BINDINGS,
  FIXTURE_NOW,
  FIXTURE_TRUST_KEY,
  REQUEST_SCHEMA_V2,
  SCHEDULER_ACTION_NAMES,
  buildFixtureSignedActionRequestV2,
  buildFixtureNetworkInspect,
  buildFixtureVolumeInspect,
  buildRawActiveReceiptV2,
  canonicalFixtureJson,
  expectedClaimedJobSourceId,
  fixtureCapabilityKey,
  fixtureSha256,
} from "./docker-action-v2-fixtures.mjs";

const {
  ACTIONS,
  ACTIVE_RECEIPT_SCHEMA,
  REQUEST_SCHEMA,
  RUNTIME_INTENT_SCHEMA,
  canonicalJson,
  normalizeActiveReceipt,
  normalizeTrustedContext,
  sha256,
  signActionRequest,
  signRuntimeIntent,
} = contract;
const {
  PersistentReplayStore,
  createBrokerCore,
  createFixedDockerEngine,
  parseWorkerOutput,
  readProtectedFile,
  workerCreateBody,
} = broker;

const NOW = FIXTURE_NOW;
const SCHEDULER_ACTIONS = SCHEDULER_ACTION_NAMES;
const ALL_ACTIONS = Object.freeze([...SCHEDULER_ACTION_NAMES, ...EVIDENCE_ACTION_NAMES]);
const CAPABILITIES = Object.freeze(Object.fromEntries(
  ALL_ACTIONS.map((action) => [action, fixtureCapabilityKey(action)]),
));
const TRUST_KEY = FIXTURE_TRUST_KEY;
const ENGINE_ID = "1".repeat(64);
const WORKER_ID = "2".repeat(64);
const IMAGE_ID = `sha256:${"3".repeat(64)}`;
const WORKER_IMAGE_ID = `sha256:${"4".repeat(64)}`;
const IMAGE_REF = `registry.example/platform/postgres@sha256:${"5".repeat(64)}`;
const WORKER_IMAGE_REF = `registry.example/platform/docker-action-broker@sha256:${"6".repeat(64)}`;
const BACKUP_JOB_ID = "0123456789abcdef";
const BACKUP_JOB_CREATED_AT = "2026-07-28T11:59:00.000Z";
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
let v2RequestSequence = 0;
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
const WORKER_FLOWS = Object.freeze([
  Object.freeze({
    id: "backup-catalog",
    action: "backup.catalog",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-catalog", phaseId: "catalog.capture" }),
    ]),
  }),
  Object.freeze({
    id: "backup-job",
    action: "backup.job.execute",
    parameters: Object.freeze({
      jobFileName: `${BACKUP_JOB_ID}.json`,
      jobId: BACKUP_JOB_ID,
      jobOperation: "backup",
      jobSha256: BACKUP_JOB_SHA256,
    }),
    phases: Object.freeze([
      Object.freeze({ command: "backup-job", phaseId: "job.backup.capture" }),
    ]),
  }),
  Object.freeze({
    id: "restore-job",
    action: "backup.job.execute",
    parameters: Object.freeze({
      jobFileName: `${RESTORE_JOB_ID}.json`,
      jobId: RESTORE_JOB_ID,
      jobOperation: "restore-drill",
      jobSha256: RESTORE_JOB_SHA256,
    }),
    phases: Object.freeze([
      Object.freeze({ command: "restore-job", phaseId: "job.restore.verify" }),
    ]),
  }),
  Object.freeze({
    id: "backup-prune-plan",
    action: "backup.prune.plan",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-prune-plan", phaseId: "prune.plan" }),
    ]),
  }),
  Object.freeze({
    id: "backup-prune-apply",
    action: "backup.prune.apply",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-prune-apply", phaseId: "prune.apply" }),
    ]),
  }),
  Object.freeze({
    id: "restore-full",
    action: "restore.drill.full",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-catalog", phaseId: "restore.capture" }),
      Object.freeze({ command: "restore-drill-full", phaseId: "restore.verify" }),
    ]),
  }),
  Object.freeze({
    id: "backup-offsite-sync",
    action: "backup.offsite.sync",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-offsite-sync", phaseId: "offsite.sync" }),
    ]),
  }),
]);

test("hostile requests cause zero fake Engine calls before complete admission", async (t) => {
  const fixture = coreFixture(t);
  const valid = requestFor(fixture.trusted, "evidence.runtime.snapshot");
  const hostile = [
    Buffer.from("{"),
    Buffer.alloc(16 * 1024 + 1, 0x61),
    encode({ ...valid, mac: "0".repeat(64) }),
    encode({ ...valid, requestId: "not-a-uuid" }),
    encode({ ...valid, capabilityId: ACTIONS["backup.prune.plan"].capabilityId }),
    encode({ ...valid, action: "container.create", capabilityId: "container.create.v1" }),
    encode({ ...valid, action: "container.exec", capabilityId: "container.exec.v1" }),
    encode({ ...valid, action: "container.start", capabilityId: "container.start.v1" }),
    encode({ ...valid, action: "volume.create", capabilityId: "volume.create.v1" }),
    encode({ ...valid, action: "network.create", capabilityId: "network.create.v1" }),
    encode(signActionRequest({ ...withoutMac(valid), parameters: { privileged: true } }, CAPABILITIES["evidence.runtime.snapshot"])),
    encode(signActionRequest({ ...withoutMac(valid), parameters: { binds: ["/:/host"] } }, CAPABILITIES["evidence.runtime.snapshot"])),
    encode(signActionRequest({ ...withoutMac(valid), parameters: { devices: ["/dev/sda"] } }, CAPABILITIES["evidence.runtime.snapshot"])),
    encode(signActionRequest({ ...withoutMac(valid), parameters: { networkMode: "host" } }, CAPABILITIES["evidence.runtime.snapshot"])),
    encode(signActionRequest({ ...withoutMac(valid), parameters: { argv: ["sh", "-c", "id"] } }, CAPABILITIES["evidence.runtime.snapshot"])),
  ];
  for (const frame of hostile) await assert.rejects(() => fixture.core.handle(frame));
  assert.deepEqual(fixture.transport.calls, []);
});

test("runtime evidence resolves exact receipt identities and rejects substituted state", async (t) => {
  const fixture = coreFixture(t);
  const request = requestFor(fixture.trusted, "evidence.runtime.snapshot");
  const response = await fixture.core.handle(encode(request));
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.result.resources["platform.postgres"].containerId, ENGINE_ID);
  assert.deepEqual(fixture.transport.calls.map(({ method }) => method), ["inspectContainer"]);

  const substituted = coreFixture(t, { inspectMutation: (inspect) => ({ ...inspect, Id: "9".repeat(64) }) });
  await assert.rejects(() => substituted.core.handle(encode(requestFor(substituted.trusted, "evidence.runtime.snapshot"))), /does not match/);
  assert.deepEqual(substituted.transport.calls.map(({ method }) => method), ["inspectContainer"]);

  for (const mutate of [
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, GroupAdd: ["998"] } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, DeviceCgroupRules: ["a *:* rwm"] } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, Runtime: "kata" } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, UTSMode: "host" } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, PortBindings: { "5432/tcp": [{ HostPort: "5432" }] } } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, PublishAllPorts: true } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, ExtraHosts: ["metadata:169.254.169.254"] } }),
    (inspect) => ({ ...inspect, Config: { ...inspect.Config, Env: [...inspect.Config.Env, "INJECTED=1"] } }),
    (inspect) => ({ ...inspect, NetworkSettings: { Networks: { platform_db: {}, attacker: {} } } }),
  ]) {
    const widened = coreFixture(t, { inspectMutation: mutate });
    await assert.rejects(
      () => widened.core.handle(encode(requestFor(widened.trusted, "evidence.runtime.snapshot"))),
      /does not match|forbidden|omitted/,
    );
    assert.deepEqual(widened.transport.calls.map(({ method }) => method), ["inspectContainer"]);
  }
});

test("fixed worker create-inspect-start-wait-logs-delete is exact and returns semantic output", async (t) => {
  const fixture = coreFixture(t);
  const response = await fixture.core.handle(encode(requestFor(fixture.trusted, "backup.prune.plan")));
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.result.schema, "platform.backup-prune-plan/v1");
  assert.equal(response.body.result.mutationPerformed, false);
  assert.deepEqual(fixture.transport.calls.map(({ method }) => method), [
    "createWorker",
    "inspectContainer",
    "startContainer",
    "waitContainer",
    "logsContainer",
    "deleteContainer",
  ]);
  const create = fixture.transport.calls[0];
  assert.equal(create.body.Image, WORKER_IMAGE_REF);
  assert.equal(create.body.User, "65532:65532");
  assert.equal(create.body.NetworkDisabled, true);
  assert.deepEqual(create.body.Cmd, ["backup-prune-plan"]);
  assert.deepEqual(create.body.HostConfig.Binds, ["/srv/platform/backups:/data/backups:ro"]);
  assert.equal(create.body.HostConfig.Privileged, false);
  assert.equal(create.body.HostConfig.NetworkMode, "none");
  assert.deepEqual(create.body.HostConfig.CapAdd, []);
  assert.deepEqual(create.body.HostConfig.Devices, []);
});

test("post-create widening is deleted before start", async (t) => {
  for (const mutate of [
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, Privileged: true } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, Binds: ["/:/host:rw"] } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, Devices: [{ PathOnHost: "/dev/sda" }] } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, NetworkMode: "host" } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, PidMode: "host" } }),
    (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, CgroupnsMode: "host" } }),
    (inspect) => ({ ...inspect, Config: { ...inspect.Config, Cmd: ["sh"] } }),
    (inspect) => ({ ...inspect, Image: `sha256:${"9".repeat(64)}` }),
  ]) {
    const fixture = coreFixture(t, { inspectMutation: mutate });
    await assert.rejects(() => fixture.core.handle(encode(requestFor(fixture.trusted, "backup.prune.plan"))));
    assert.deepEqual(fixture.transport.calls.map(({ method }) => method), ["createWorker", "inspectContainer", "deleteContainer"]);
  }
});

test("replay, cross-action confused deputy and concurrency fail closed", async (t) => {
  const fixture = coreFixture(t);
  const first = requestFor(fixture.trusted, "evidence.runtime.snapshot");
  await fixture.core.handle(encode(first));
  await assert.rejects(() => fixture.core.handle(encode(first)), /replay/);

  const crossed = signActionRequest({
    ...withoutMac(requestFor(fixture.trusted, "evidence.runtime.snapshot")),
    capabilityId: ACTIONS["backup.prune.plan"].capabilityId,
  }, CAPABILITIES["backup.prune.plan"]);
  await assert.rejects(() => fixture.core.handle(encode(crossed)), /bound/);

  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const concurrent = coreFixture(t, { executeOverride: () => pending });
  const running = concurrent.core.handle(encode(requestFor(concurrent.trusted, "evidence.runtime.snapshot")));
  while (!concurrent.executeStarted()) await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(
    () => concurrent.core.handle(encode(requestFor(concurrent.trusted, "backup.prune.plan"))),
    /another Docker action/,
  );
  release({ ok: true });
  await running;
});

test("mount substitution and cleanup failure never run an unverified worker and preserve recovery lease", async (t) => {
  const changed = coreFixture(t, {
    inspectMutation: (inspect) => inspect?.Mounts
      ? { ...inspect, Mounts: [{ ...inspect.Mounts[0], Source: "/srv/platform/substituted" }] }
      : inspect,
  });
  await assert.rejects(() => changed.core.handle(encode(requestFor(changed.trusted, "backup.prune.plan"))), /mounts do not match/);
  assert.deepEqual(changed.transport.calls.map(({ method }) => method), ["createWorker", "inspectContainer", "deleteContainer"]);

  const stuck = coreFixture(t, { deleteNeverReturns: true, cleanupTimeoutMs: 20 });
  await assert.rejects(() => stuck.core.handle(encode(requestFor(stuck.trusted, "backup.prune.plan"))), /cleanup timed out/);
  await assert.rejects(
    () => stuck.core.handle(encode(requestFor(stuck.trusted, "evidence.runtime.snapshot"))),
    /another Docker action/,
  );
});

test("persistent generation, crash recovery and ledger flood are bounded", async (t) => {
  const root = tempDir(t);
  const owner = { expectedUid: process.getuid(), expectedGid: process.getgid() };
  const trusted = trustedFixture({ generation: 2 });
  const store = new PersistentReplayStore(root, { now: () => NOW, bootId: "a".repeat(48), ...owner });
  store.admitTrustedContext(trusted);
  const rollback = trustedFixture({ generation: trusted.intent.generation - 1 });
  assert.throws(() => store.admitTrustedContext(rollback), /rollback/);
  const substituted = trustedFixture({ generation: 2, intentId: "intent.substituted" });
  assert.throws(() => store.admitTrustedContext(substituted), /substitution/);

  const request = admittedRequestShape("backup.prune.plan");
  const lease = store.acquire(request, trusted);
  const body = workerCreateBody({
    action: "backup.prune.plan",
    command: "backup-prune-plan",
    imageRef: WORKER_IMAGE_REF,
    hostPath: "/srv/platform/backups",
    intentId: trusted.intent.intentId,
    receiptDigest: trusted.receiptDigest,
    mountAttestation: trusted.receipt.resources.mounts["backup.root"],
  });
  lease.recordWorker({ resourceName: "platform-action-prune-plan-recovery", body, imageId: WORKER_IMAGE_ID, hostPath: "/srv/platform/backups" });
  lease.preserve();

  const recovered = new PersistentReplayStore(root, { now: () => NOW, bootId: "b".repeat(48), ...owner });
  let recoveredRecord;
  await recovered.recover({ recoverLease: async (record) => { recoveredRecord = record; } });
  assert.equal(recoveredRecord.resourceName, "platform-action-prune-plan-recovery");
  assert.equal(fs.existsSync(path.join(root, "active.lock")), false);

  const replay = path.join(root, "replay");
  for (let index = 0; index <= 4096; index += 1) {
    fs.writeFileSync(path.join(replay, index.toString(16).padStart(64, "0")), `${JSON.stringify({ expiresAt: new Date(NOW + 60_000).toISOString() })}\n`, { mode: 0o600 });
  }
  assert.throws(() => recovered.purgeExpired(), /bound exceeded/);
});

test("provider activation journal is one-shot and rejects replay, gaps and ABA", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-activation-journal-"));
  fs.chmodSync(root, 0o700);
  try {
    const owner = { expectedUid: process.getuid(), expectedGid: process.getgid() };
    const store = new PersistentReplayStore(root, { now: () => NOW, ...owner });
    const first = trustedFixture();
    store.admitActivation(first.activation, first);
    store.admitActivation(first.activation, first);

    const replayedIdentity = trustedFixture({
      generation: 2,
      activationBundleSha256: "7".repeat(64),
      previousActiveSha256: first.activation.envelopeSha256,
      activationRequestId: first.activation.requestId,
      activationNonce: first.activation.nonce,
    });
    assert.throws(() => store.admitActivation(replayedIdentity.activation, replayedIdentity), /replay/);

    const gap = trustedFixture({
      generation: 3,
      activationBundleSha256: "8".repeat(64),
      previousActiveSha256: first.activation.envelopeSha256,
    });
    assert.throws(() => store.admitActivation(gap.activation, gap), /rollback, gap or ABA/);

    const second = trustedFixture({
      generation: 2,
      activationBundleSha256: "9".repeat(64),
      previousActiveSha256: first.activation.envelopeSha256,
    });
    store.admitActivation(second.activation, second);
    const aba = trustedFixture({
      generation: 3,
      activationBundleSha256: first.activation.envelopeSha256,
      previousActiveSha256: second.activation.envelopeSha256,
    });
    assert.throws(() => store.admitActivation(aba.activation, aba), /rollback, gap or ABA|substituted|ABA replay/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("protected input rejects symlinks, hardlinks and non-root ownership", (t) => {
  const root = tempDir(t);
  const source = path.join(root, "source");
  fs.writeFileSync(source, "x".repeat(48), { mode: 0o400 });
  const link = path.join(root, "link");
  fs.symlinkSync(source, link);
  assert.throws(() => readProtectedFile(link), /parent directory is unsafe|ELOOP|ownership/);
  const hard = path.join(root, "hard");
  fs.linkSync(source, hard);
  assert.throws(() => readProtectedFile(source, 4096, {
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
    parentRoot: root,
  }), /links/);
});

test("worker parser rejects malformed, multi-document and oversized output", () => {
  const valid = workerResult();
  assert.equal(parseWorkerOutput(frame(JSON.stringify(valid) + "\n"), "backup-prune-plan").schema, valid.schema);
  assert.throws(() => parseWorkerOutput(Buffer.from("{}\n"), "backup-prune-plan"), /frame/);
  assert.throws(() => parseWorkerOutput(frame("{}\n{}\n"), "backup-prune-plan"), /exactly one/);
  assert.throws(() => parseWorkerOutput(frame(`${"x".repeat(65 * 1024)}\n`), "backup-prune-plan"), /length|oversized/);
});

test("future-dated runtime intent and active receipt fail closed", () => {
  assert.throws(
    () => trustedFixture({ receiptIssuedAt: NOW + 31_000 }),
    /not yet valid/,
  );
  assert.throws(
    () => trustedFixture({ intentIssuedAt: NOW + 31_000 }),
    /not yet valid/,
  );
});

test("source render is bound to the final model and the self-referential legacy label is rejected", () => {
  assert.throws(
    () => trustedFixture({ sourceRenderLabel: "0".repeat(64) }),
    /candidate or source render label/,
  );
  assert.throws(
    () => trustedFixture({ legacyRenderLabel: true }),
    /unsupported or missing fields/,
  );
});

test("direct semantic Engine executes every phase from exact receipt authority", async (t) => {
  for (const flow of WORKER_FLOWS) {
    await t.test(flow.id, async (t) => {
      const fixture = semanticEngineFixture(t, flow);
      const result = await fixture.engine.execute(flow.action, fixture.context);
      assert.ok(result && typeof result === "object", `${flow.id} must return one bounded semantic result`);

      const creates = fixture.transport.calls.filter(({ method }) => method === "createWorker");
      assert.equal(creates.length, flow.phases.length);
      for (let index = 0; index < flow.phases.length; index += 1) {
        assertExactPhaseBody(
          creates[index].body,
          flow.phases[index],
          flow.action,
          fixture.trusted.receipt,
        );
      }

      const expectedNetworkEngineIds = uniqueInOrder(flow.phases.flatMap(({ phaseId }) => {
        const phase = fixture.trusted.receipt.resources.phaseProfiles[phaseId];
        return phase.networkIds.map(
          (logicalId) => fixture.trusted.receipt.resources.networks[logicalId].engineId,
        );
      }));
      assert.deepEqual(
        fixture.transport.calls
          .filter(({ method }) => method === "inspectNetwork")
          .map(({ id }) => id),
        expectedNetworkEngineIds,
        `${flow.id} must inspect exact Engine network IDs`,
      );

      const phaseVolumeNames = flow.phases.flatMap(({ phaseId }) => {
        const phase = fixture.trusted.receipt.resources.phaseProfiles[phaseId];
        const secretVolumeIds = phase.workerSecretSetIds.map(
          (secretSetId) => fixture.trusted.receipt.resources.workerSecretSets[secretSetId].volumeId,
        );
        return [...secretVolumeIds, ...phase.scratchVolumeIds].map(
          (volumeId) => fixture.trusted.receipt.resources.volumes[volumeId].engineName,
        );
      });
      const queueVolumeNames = flow.action === "backup.job.execute"
        ? [fixture.trusted.receipt.resources.volumes["jobs.queue"].engineName]
        : [];
      assert.deepEqual(
        fixture.transport.calls
          .filter(({ method }) => method === "inspectVolume")
          .map(({ name }) => name),
        uniqueInOrder([...queueVolumeNames, ...phaseVolumeNames]),
        `${flow.id} must inspect exact Engine volume names`,
      );

      const firstCreate = fixture.transport.calls.findIndex(({ method }) => method === "createWorker");
      for (const [index, call] of fixture.transport.calls.entries()) {
        if (call.method === "inspectNetwork" || call.method === "inspectVolume") {
          assert.ok(index < firstCreate, `${flow.id} inspected ${call.method} after worker creation`);
        }
      }
      assert.equal(
        fixture.transport.calls.some(({ method }) => method === "startContainer"),
        true,
        `${flow.id} positive control never reached Engine start`,
      );
    });
  }
});

test("direct semantic Engine deletes an independently widened worker before that worker starts", async (t) => {
  const widenings = [
    ["image", (inspect) => ({ ...inspect, Image: `sha256:${"9".repeat(64)}` })],
    ["user", (inspect) => ({ ...inspect, Config: { ...inspect.Config, User: "65532:65532" } })],
    ["argv", (inspect) => ({ ...inspect, Config: { ...inspect.Config, Cmd: ["sh", "-c", "id"] } })],
    ["lineage-label", (inspect) => {
      const labels = { ...inspect.Config.Labels };
      delete labels["com.platform.docker-phase-sha256"];
      return { ...inspect, Config: { ...inspect.Config, Labels: labels } };
    }],
    ["bind", (inspect) => ({
      ...inspect,
      HostConfig: { ...inspect.HostConfig, Binds: ["/:/host:rw"] },
      Mounts: [{ Source: "/", Destination: "/host", RW: true }],
    })],
    ["named-volume", (inspect) => {
      const mounts = inspect.Mounts.map((mount, index) => (
        index === inspect.Mounts.length - 1
          ? { ...mount, Name: "attacker-volume", Source: "/var/lib/docker/volumes/attacker-volume/_data" }
          : mount
      ));
      return { ...inspect, Mounts: mounts };
    }],
    ["scratch-access", (inspect) => {
      let changed = false;
      const mounts = inspect.Mounts.map((mount) => {
        if (mount.Destination !== "/run/platform/restore-scratch") return mount;
        changed = true;
        return { ...mount, RW: false };
      });
      if (!changed) {
        mounts.push({
          Type: "volume",
          Name: "attacker-scratch",
          Source: "/var/lib/docker/volumes/attacker-scratch/_data",
          Destination: "/run/platform/restore-scratch",
          Driver: "local",
          Mode: "",
          RW: true,
          Propagation: "",
        });
      }
      return { ...inspect, Mounts: mounts };
    }],
    ["network-alias", (inspect) => {
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
    }],
    ["network-id", (inspect) => {
      const entries = Object.entries(inspect.NetworkSettings.Networks);
      if (entries.length === 0) {
        return {
          ...inspect,
          HostConfig: { ...inspect.HostConfig, NetworkMode: "attacker" },
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
    }],
    ["namespace", (inspect) => ({
      ...inspect,
      HostConfig: { ...inspect.HostConfig, CgroupnsMode: "host" },
    })],
  ];

  for (const flow of WORKER_FLOWS) {
    for (const [id, mutate] of widenings) {
      await t.test(`${flow.id}-${id}`, async (t) => {
        const fixture = semanticEngineFixture(t, flow, { inspectMutation: mutate });
        await assert.rejects(() => fixture.engine.execute(flow.action, fixture.context));
        const creates = fixture.transport.calls.filter(({ method }) => method === "createWorker");
        assert.ok(creates.length >= 1, `${flow.id}/${id} never reached the intended worker boundary`);
        const lastWorkerId = creates.at(-1).id;
        assert.equal(
          fixture.transport.calls.some(
            (call) => call.method === "startContainer" && call.id === lastWorkerId,
          ),
          false,
          `${flow.id}/${id} started the widened worker`,
        );
        assert.equal(
          fixture.transport.calls.some(
            (call) => call.method === "deleteContainer" && call.id === lastWorkerId,
          ),
          true,
          `${flow.id}/${id} did not delete the widened worker`,
        );
      });
    }
  }
});

test("network and volume substitutions fail before any worker is created", async (t) => {
  for (const flow of WORKER_FLOWS) {
    const receipt = schedulerTrustedFixture().receipt;
    const phaseIds = flow.phases.map(({ phaseId }) => phaseId);
    const hasNetworks = phaseIds.some(
      (phaseId) => receipt.resources.phaseProfiles[phaseId].networkIds.length > 0,
    );
    const hasVolumes = flow.action === "backup.job.execute" || phaseIds.some((phaseId) => {
      const phase = receipt.resources.phaseProfiles[phaseId];
      return phase.workerSecretSetIds.length > 0 || phase.scratchVolumeIds.length > 0;
    });
    if (hasNetworks) {
      await t.test(`${flow.id}-network`, async (t) => {
        const baseline = semanticEngineFixture(t, flow);
        await baseline.engine.execute(flow.action, baseline.context);
        assert.equal(
          baseline.transport.calls.some(({ method }) => method === "startContainer"),
          true,
          `${flow.id} network mutation lacks a real positive control`,
        );
        const fixture = semanticEngineFixture(t, flow, {
          networkInspectMutation: (inspect) => ({ ...inspect, Id: "9".repeat(64) }),
        });
        await assert.rejects(() => fixture.engine.execute(flow.action, fixture.context));
        assert.equal(
          fixture.transport.calls.some(({ method }) => method === "createWorker"),
          false,
        );
      });
    }
    if (hasVolumes) {
      await t.test(`${flow.id}-volume`, async (t) => {
        const baseline = semanticEngineFixture(t, flow);
        await baseline.engine.execute(flow.action, baseline.context);
        assert.equal(
          baseline.transport.calls.some(({ method }) => method === "startContainer"),
          true,
          `${flow.id} volume mutation lacks a real positive control`,
        );
        const fixture = semanticEngineFixture(t, flow, {
          volumeInspectMutation: (inspect) => ({ ...inspect, Name: "attacker-volume" }),
        });
        await assert.rejects(() => fixture.engine.execute(flow.action, fixture.context));
        assert.equal(
          fixture.transport.calls.some(({ method }) => method === "createWorker"),
          false,
        );
      });
    }
  }
});

test("all six scheduler actions use exact socketless semantic worker profiles", async (t) => {
  for (const flow of WORKER_FLOWS) {
    await t.test(flow.id, async (t) => {
      const fixture = coreFixture(t, {
        trusted: schedulerTrustedFixture(),
        expectedPhaseIds: flow.phases.map(({ phaseId }) => phaseId),
        claimedJobBytes: flow.id === "restore-job" ? RESTORE_JOB_BYTES : BACKUP_JOB_BYTES,
      });
      const response = await fixture.core.handle(
        encode(requestFor(fixture.trusted, flow.action, flow.parameters)),
      );
      assert.equal(response.statusCode, 200, `${flow.id} must complete through the real broker core`);
      assert.equal(response.body.action, flow.action);
      assert.equal(response.body.status, "completed");
      assert.ok(response.body.result && typeof response.body.result === "object");
      const creates = fixture.transport.calls.filter(({ method }) => method === "createWorker");
      assert.equal(
        creates.length,
        flow.phases.length,
        `${flow.id} must create ${flow.phases.length} fixed worker phase(s)`,
      );
      for (let index = 0; index < flow.phases.length; index += 1) {
        assertExactPhaseBody(
          creates[index].body,
          flow.phases[index],
          flow.action,
          fixture.trusted.receipt,
        );
      }
    });
  }
});

test("caller mutations of image argv mount network capability repository or retention cause zero Engine calls", async (t) => {
  const mutations = Object.freeze([
    Object.freeze({ workerImage: "attacker/image:latest" }),
    Object.freeze({ argv: ["sh", "-c", "id"] }),
    Object.freeze({ mounts: ["/:/host:rw"] }),
    Object.freeze({ networkId: "platform_egress" }),
    Object.freeze({ capAdd: ["SYS_ADMIN"] }),
    Object.freeze({ repository: "s3:https://attacker.invalid/bucket" }),
    Object.freeze({ keepCompleteManifests: 0 }),
  ]);
  for (const flow of uniqueActionFlows()) {
    await t.test(flow.id, async (t) => {
      const baseline = coreFixture(t, {
        trusted: schedulerTrustedFixture(),
        expectedPhaseIds: flow.phases.map(({ phaseId }) => phaseId),
        claimedJobBytes: flow.id === "restore-job" ? RESTORE_JOB_BYTES : BACKUP_JOB_BYTES,
      });
      const baselineResponse = await baseline.core.handle(
        encode(requestFor(baseline.trusted, flow.action, flow.parameters)),
      );
      assert.equal(
        baselineResponse.statusCode,
        200,
        `${flow.id} baseline must reach the real semantic consumer before mutation rejection is credited`,
      );
      assert.ok(
        baseline.transport.calls.length > 0,
        `${flow.id} baseline did not reach the independent Engine double`,
      );

      for (const mutation of mutations) {
        const key = Object.keys(mutation)[0];
        await t.test(key, async (t) => {
          const fixture = coreFixture(t, {
            trusted: schedulerTrustedFixture(),
            expectedPhaseIds: flow.phases.map(({ phaseId }) => phaseId),
            claimedJobBytes: flow.id === "restore-job" ? RESTORE_JOB_BYTES : BACKUP_JOB_BYTES,
          });
          const request = requestFor(fixture.trusted, flow.action, { ...flow.parameters, ...mutation });
          await assert.rejects(
            () => fixture.core.handle(encode(request)),
            undefined,
            `${flow.id} must reject caller-controlled ${key}`,
          );
          assert.deepEqual(fixture.transport.calls, [], `${flow.id}/${key} reached the Engine before exact admission`);
        });
      }
    });
  }
});

test("every semantic profile is exact-inspected and deleted before start when Docker widens it", async (t) => {
  const widenings = Object.freeze([
    Object.freeze({
      id: "image",
      mutate: (inspect) => ({ ...inspect, Image: `sha256:${"9".repeat(64)}` }),
    }),
    Object.freeze({
      id: "argv",
      mutate: (inspect) => ({ ...inspect, Config: { ...inspect.Config, Cmd: ["sh", "-c", "id"] } }),
    }),
    Object.freeze({
      id: "mount",
      mutate: (inspect) => ({ ...inspect, Mounts: [{ Source: "/", Destination: "/host", RW: true }] }),
    }),
    Object.freeze({
      id: "network",
      mutate: (inspect) => ({
        ...inspect,
        HostConfig: { ...inspect.HostConfig, NetworkMode: "platform_egress" },
        NetworkSettings: { Networks: { platform_egress: {} } },
      }),
    }),
    Object.freeze({
      id: "capability",
      mutate: (inspect) => ({ ...inspect, HostConfig: { ...inspect.HostConfig, CapAdd: ["SYS_ADMIN"] } }),
    }),
    Object.freeze({
      id: "network-alias",
      mutate: (inspect) => ({
        ...inspect,
        NetworkSettings: {
          Networks: {
            ...inspect.NetworkSettings.Networks,
            platform_storage: { Aliases: ["docker-action-broker"] },
          },
        },
      }),
    }),
    Object.freeze({
      id: "parent-bind",
      mutate: (inspect) => ({
        ...inspect,
        HostConfig: { ...inspect.HostConfig, Binds: ["/var/run:/host-run:ro"] },
      }),
    }),
  ]);
  for (const flow of WORKER_FLOWS) {
    for (const widening of widenings) {
      await t.test(`${flow.id}-${widening.id}`, async (t) => {
        const fixture = coreFixture(t, {
          trusted: schedulerTrustedFixture(),
          inspectMutation: widening.mutate,
        });
        await assert.rejects(
          () => fixture.core.handle(encode(requestFor(fixture.trusted, flow.action, flow.parameters))),
        );
        assert.deepEqual(
          fixture.transport.calls.map(({ method }) => method),
          ["createWorker", "inspectContainer", "deleteContainer"],
          `${flow.id}/${widening.id} must create, exact-inspect and delete before any start`,
        );
      });
    }
  }
});

test("action-driven restore writes an append-only hash-chained lease journal", async (t) => {
  const root = tempDir(t);
  const trusted = schedulerTrustedFixture();
  const store = new PersistentReplayStore(root, {
    now: () => NOW,
    bootId: "a".repeat(48),
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
  });
  store.admitTrustedContext(trusted);
  const flow = WORKER_FLOWS.find(({ id }) => id === "restore-full");
  const fixture = semanticEngineFixture(t, flow);
  const lease = store.acquire(admittedRequestShape(flow.action), trusted);
  const result = await fixture.engine.execute(flow.action, {
    ...fixture.context,
    lease,
    trusted,
  });
  assert.equal(result.schema, "platform.restore-drill/v1");
  lease.preserve();

  const active = JSON.parse(fs.readFileSync(path.join(root, "active.lock"), "utf8"));
  assert.equal(active.schema, "platform.docker-action.lease/v2", "multi-phase work requires lease/v2");
  assert.match(active.leaseId, /^[a-f0-9]{64}$/, "lease/v2 requires a stable exact lease identity");
  const entries = readLeaseJournal(root, active.leaseId);
  const workers = entries.filter(({ event }) => event === "worker-recorded");
  assert.deepEqual(
    workers.map(({ phaseId }) => phaseId),
    ["restore.capture", "restore.verify"],
    "journal entries must come from the two real action phases",
  );
  let previousEntrySha256 = "0".repeat(64);
  for (const entry of entries) {
    assert.equal(entry.schema, "platform.docker-action.lease-journal-entry/v2");
    assert.equal(entry.previousEntrySha256, previousEntrySha256, `journal chain broke at sequence ${entry.sequence}`);
    previousEntrySha256 = sha256(canonicalJson(entry));
  }
});

test("action-driven crash recovery exact-inspects and deletes the last live phase worker", async (t) => {
  const root = tempDir(t);
  const trusted = schedulerTrustedFixture();
  const owner = { expectedUid: process.getuid(), expectedGid: process.getgid() };
  const store = new PersistentReplayStore(root, { now: () => NOW, bootId: "a".repeat(48), ...owner });
  store.admitTrustedContext(trusted);
  const flow = WORKER_FLOWS.find(({ id }) => id === "restore-full");
  const fixture = semanticEngineFixture(t, flow, {
    cleanupTimeoutMs: 20,
    deleteNeverReturnsPhaseId: "restore.verify",
    startFailurePhaseId: "restore.verify",
  });
  const lease = store.acquire(admittedRequestShape(flow.action), trusted);
  let actionError;
  try {
    await fixture.engine.execute(flow.action, {
      ...fixture.context,
      lease,
      trusted,
    });
  } catch (error) {
    actionError = error;
  }
  assert.ok(actionError, "crash fixture did not interrupt the restore verification phase");
  assert.equal(actionError.preserveLease, true, "uncertain cleanup must preserve the durable lease");
  lease.preserve();
  const liveWorkers = fixture.transport.createdWorkers.map((worker) => structuredClone(worker));
  assert.equal(liveWorkers.length, 1, "only the interrupted verification worker may remain live");
  assert.equal(liveWorkers[0].expectedPhaseId, "restore.verify");

  const transport = new FakeEngineTransport({
    trusted,
    recoveryWorkers: liveWorkers,
  });
  const engine = createFixedDockerEngine({ transport, cleanupTimeoutMs: 100 });
  const recovered = new PersistentReplayStore(root, { now: () => NOW, bootId: "b".repeat(48), ...owner });
  await recovered.recover(engine);
  assert.deepEqual(
    transport.calls.filter(({ method }) => method === "deleteContainer").map(({ id }) => id),
    [liveWorkers[0].id],
    "recovery must delete the exact journal-bound live worker",
  );
  assert.equal(fs.existsSync(path.join(root, "active.lock")), false);
});

test("action-driven prune apply journals worker identity, bounded result digest and terminal cleanup", async (t) => {
  const root = tempDir(t);
  const trusted = schedulerTrustedFixture();
  const store = new PersistentReplayStore(root, {
    now: () => NOW,
    bootId: "a".repeat(48),
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
  });
  store.admitTrustedContext(trusted);
  const flow = WORKER_FLOWS.find(({ id }) => id === "backup-prune-apply");
  const fixture = semanticEngineFixture(t, flow);
  const lease = store.acquire(admittedRequestShape(flow.action), trusted);
  const result = await fixture.engine.execute(flow.action, {
    ...fixture.context,
    lease,
    trusted,
  });
  assert.equal(result.schema, "platform.backup-prune-apply/v1");
  assert.equal(result.mutationPerformed, true);
  lease.preserve();
  const active = JSON.parse(fs.readFileSync(path.join(root, "active.lock"), "utf8"));
  assert.equal(active.schema, "platform.docker-action.lease/v2");
  const entries = readLeaseJournal(root, active.leaseId);
  const events = entries.map(({ event }) => event);
  assert.deepEqual(
    events.filter((event) => [
      "worker-recorded",
      "worker-result-recorded",
      "worker-deleted",
      "action-completed",
    ].includes(event)),
    ["worker-recorded", "worker-result-recorded", "worker-deleted", "action-completed"],
  );
  const resultEntry = entries.find(({ event }) => event === "worker-result-recorded");
  assert.equal(resultEntry.phaseId, "prune.apply");
  assert.equal(resultEntry.resultSha256, fixtureSha256(canonicalFixtureJson(result)));
});

test("full restore never starts restore phase when the catalog barrier fails", async (t) => {
  const flow = WORKER_FLOWS.find(({ id }) => id === "restore-full");
  const fixture = semanticEngineFixture(t, flow, {
    workerStatusCodes: { "backup-catalog": 17 },
  });
  await assert.rejects(
    () => fixture.engine.execute(flow.action, fixture.context),
  );
  assert.deepEqual(
    fixture.transport.calls.filter(({ method }) => method === "createWorker").map(({ body }) => body.Cmd),
    [["backup-catalog"]],
    "restore-full must not be created until the catalog phase has a durable successful barrier",
  );
});

test("offsite remote-unknown preserves the lease and is never replayed automatically", async (t) => {
  const flow = WORKER_FLOWS.find(({ id }) => id === "backup-offsite-sync");
  const trusted = schedulerTrustedFixture();
  const root = tempDir(t);
  const store = new PersistentReplayStore(root, {
    now: () => NOW,
    bootId: "a".repeat(48),
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
  });
  store.admitTrustedContext(trusted);
  const fixture = semanticEngineFixture(t, flow, {
    logsFailurePhaseId: "offsite.sync",
  });
  const lease = store.acquire(admittedRequestShape(flow.action), trusted);
  let remoteError;
  try {
    await fixture.engine.execute(flow.action, {
      ...fixture.context,
      lease,
      trusted,
    });
  } catch (error) {
    remoteError = error;
  }
  assert.match(remoteError?.message ?? "", /remote|unknown|terminal|receipt/i);
  assert.equal(remoteError?.remoteEffectUnknown, true);
  assert.equal(remoteError?.preserveLease, true);
  lease.preserve();
  const leasePreserved = fs.existsSync(path.join(root, "active.lock"));
  const firstCreateCount = fixture.transport.calls.filter(({ method }) => method === "createWorker").length;
  assert.equal(firstCreateCount, 1, "offsite uncertainty fixture did not reach the real worker");
  assert.throws(
    () => store.acquire(admittedRequestShape(flow.action), trusted),
    /another Docker action|remote|reconcile/i,
  );
  assert.equal(
    fixture.transport.calls.filter(({ method }) => method === "createWorker").length,
    firstCreateCount,
    "remote-unknown must block automatic offsite replay",
  );
  assert.equal(leasePreserved, true, "remote-unknown must preserve the durable recovery lease");
});

function semanticEngineFixture(t, flow, options = {}) {
  const trusted = schedulerTrustedFixture();
  const claimedJobBytes = flow.id === "restore-job" ? RESTORE_JOB_BYTES : BACKUP_JOB_BYTES;
  const transport = new FakeEngineTransport({
    trusted,
    expectedPhaseIds: flow.phases.map(({ phaseId }) => phaseId),
    workerStatusCodes: options.workerStatusCodes,
    inspectMutation: options.inspectMutation,
    networkInspectMutation: options.networkInspectMutation,
    volumeInspectMutation: options.volumeInspectMutation,
    startFailurePhaseId: options.startFailurePhaseId,
    deleteNeverReturnsPhaseId: options.deleteNeverReturnsPhaseId,
    logsFailurePhaseId: options.logsFailurePhaseId,
  });
  const leaseEvents = [];
  const lease = Object.freeze({
    recordEvent(event) {
      leaseEvents.push(structuredClone(event));
    },
    recordWorker(event) {
      leaseEvents.push(structuredClone({ event: "worker-recorded", ...event }));
    },
    preserve() {
      leaseEvents.push({ event: "lease-preserved" });
    },
    release() {
      leaseEvents.push({ event: "lease-released" });
    },
  });
  const engine = createFixedDockerEngine({
    transport,
    randomBytes: () => Buffer.alloc(12, 1),
    cleanupTimeoutMs: options.cleanupTimeoutMs ?? 100,
    claimedJobSnapshotProvider: async ({ parameters, sourceId }) => {
      assert.equal(flow.action, "backup.job.execute", "non-job action requested the private queue");
      assert.equal(sourceId, expectedClaimedJobSourceId(flow.action));
      const bytes = Buffer.from(claimedJobBytes);
      assert.equal(parameters.jobSha256, fixtureSha256(bytes));
      return Object.freeze({
        bytes,
        jobFileName: parameters.jobFileName,
        jobId: parameters.jobId,
        jobOperation: parameters.jobOperation,
        jobSha256: parameters.jobSha256,
        sourceId,
      });
    },
  });
  return {
    context: {
      lease,
      parameters: structuredClone(flow.parameters),
      signal: new AbortController().signal,
      trusted,
    },
    engine,
    leaseEvents,
    transport,
    trusted,
  };
}

function coreFixture(t, options = {}) {
  const root = tempDir(t);
  const trusted = options.trusted ?? trustedFixture();
  const transport = new FakeEngineTransport({ trusted, ...options });
  let started = false;
  const fixed = createFixedDockerEngine({
    transport,
    randomBytes: () => Buffer.alloc(12, 1),
    cleanupTimeoutMs: options.cleanupTimeoutMs ?? 100,
    claimedJobSnapshotProvider: async ({ parameters, sourceId }) => {
      const bytes = Buffer.from(options.claimedJobBytes ?? BACKUP_JOB_BYTES);
      return Object.freeze({
        bytes,
        jobFileName: parameters.jobFileName,
        jobId: parameters.jobId,
        jobOperation: parameters.jobOperation,
        jobSha256: fixtureSha256(bytes),
        sourceId,
      });
    },
  });
  const engine = options.executeOverride
    ? {
        execute: async (...args) => {
          started = true;
          return options.executeOverride(...args);
        },
        recoverLease: fixed.recoverLease,
      }
    : {
        ...fixed,
        execute: async (...args) => {
          started = true;
          return fixed.execute(...args);
        },
      };
  const store = new PersistentReplayStore(root, {
    now: () => NOW,
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
  });
  const core = createBrokerCore({
    trustedContextProvider: async () => trusted,
    capabilityProvider: async (action) => CAPABILITIES[action],
    engine,
    replayStore: store,
    now: () => NOW,
    operationTimeoutMs: 500,
  });
  return { core, engine, root, transport, trusted, executeStarted: () => started };
}

function uniqueInOrder(values) {
  return [...new Set(values)];
}

class FakeEngineTransport {
  constructor(options) {
    this.options = options;
    this.calls = [];
    this.created = null;
    this.createdWorkers = [];
    this.recoveryWorkers = [...(options.recoveryWorkers ?? [])];
  }

  async inspectContainer(id) {
    this.calls.push({ method: "inspectContainer", id });
    if (id === "enterprise-postgres") {
      const expected = this.options.trusted.receipt.resources.containers["platform.postgres"];
      const parts = runtimeInspectParts(expected.labels);
      const inspect = {
        Id: expected.containerId,
        Name: `/${expected.name}`,
        Image: expected.imageId,
        ...parts,
        State: { Status: expected.expectedState, Health: { Status: expected.expectedHealth } },
      };
      return this.options.inspectMutation ? this.options.inspectMutation(inspect) : inspect;
    }
    const created = this.createdWorkers.find((candidate) => candidate.id === id) ?? this.created;
    const inspect = workerInspect(created, id, this.options.trusted);
    return this.options.inspectMutation ? this.options.inspectMutation(inspect) : inspect;
  }

  async inspectNetwork(id) {
    this.calls.push({ method: "inspectNetwork", id });
    const entry = Object.entries(this.options.trusted.receipt.resources.networks ?? {})
      .find(([, network]) => network.engineId === id);
    if (!entry) throw new Error(`fake Engine has no admitted network for ${id}`);
    const inspect = buildFixtureNetworkInspect(this.options.trusted.receipt, entry[0]);
    return this.options.networkInspectMutation
      ? this.options.networkInspectMutation(structuredClone(inspect), entry[0])
      : inspect;
  }

  async inspectVolume(name) {
    this.calls.push({ method: "inspectVolume", name });
    const entry = Object.entries(this.options.trusted.receipt.resources.volumes ?? {})
      .find(([, volume]) => volume.engineName === name);
    if (!entry) throw new Error(`fake Engine has no admitted volume for ${name}`);
    const inspect = buildFixtureVolumeInspect(this.options.trusted.receipt, entry[0]);
    return this.options.volumeInspectMutation
      ? this.options.volumeInspectMutation(structuredClone(inspect), entry[0])
      : inspect;
  }

  async inspectContainerForRecovery(name) {
    this.calls.push({ method: "inspectContainerForRecovery", name });
    const created = this.recoveryWorkers.find((candidate) => candidate.name === name)
      ?? this.createdWorkers.find((candidate) => candidate.name === name)
      ?? (this.created?.name === name ? this.created : null);
    return created ? workerInspect(created, created.id ?? WORKER_ID, this.options.trusted) : null;
  }

  async createWorker(name, body) {
    const expectedPhaseId = this.options.expectedPhaseIds?.[this.createdWorkers.length] ?? null;
    const id = this.createdWorkers.length === 0
      ? WORKER_ID
      : (this.createdWorkers.length + 2).toString(16).repeat(64).slice(0, 64);
    this.calls.push({ method: "createWorker", name, body, id });
    this.created = { id, name, body, expectedPhaseId };
    this.createdWorkers.push(this.created);
    return { Id: id };
  }

  async startContainer(id) {
    this.calls.push({ method: "startContainer", id });
    const created = this.createdWorkers.find((candidate) => candidate.id === id);
    if (created?.expectedPhaseId === this.options.startFailurePhaseId) {
      throw new Error(`fake Engine start failure for ${created.expectedPhaseId}`);
    }
  }

  async waitContainer(id) {
    this.calls.push({ method: "waitContainer", id });
    const created = this.createdWorkers.find((candidate) => candidate.id === id);
    const command = expectedWorkerCommand(created, this.options.trusted);
    return { StatusCode: this.options.workerStatusCodes?.[command] ?? 0 };
  }

  async logsContainer(id) {
    this.calls.push({ method: "logsContainer", id });
    const created = this.createdWorkers.find((candidate) => candidate.id === id);
    if (created?.expectedPhaseId === this.options.logsFailurePhaseId) {
      const error = new Error("remote side effect completed but terminal receipt is unknown");
      error.remoteEffectUnknown = true;
      throw error;
    }
    const command = expectedWorkerCommand(created, this.options.trusted);
    return frame(`${JSON.stringify(workerResult(command))}\n`);
  }

  async deleteContainer(id) {
    this.calls.push({ method: "deleteContainer", id });
    const created = this.createdWorkers.find((candidate) => candidate.id === id);
    if (this.options.deleteNeverReturns
      || created?.expectedPhaseId === this.options.deleteNeverReturnsPhaseId) {
      return new Promise(() => {});
    }
    this.createdWorkers = this.createdWorkers.filter((candidate) => candidate.id !== id);
    this.recoveryWorkers = this.recoveryWorkers.filter((candidate) => candidate.id !== id);
    if (this.created?.id === id || (this.created?.id === undefined && id === WORKER_ID)) this.created = null;
  }
}

function workerInspect(created, id, trusted) {
  if (!created) throw new Error(`fake Engine has no worker for ${id}`);
  const { name, body, expectedPhaseId } = created;
  const bindMounts = (body.HostConfig?.Binds ?? []).map((bind) => {
    const [source, destination, access = "rw"] = bind.split(":");
    return { Source: source, Destination: destination, RW: access !== "ro" };
  });
  const namedMounts = (body.HostConfig?.Mounts ?? []).map((mount) => ({
    Type: mount.Type,
    Name: mount.Source,
    Source: `/var/lib/docker/volumes/${mount.Source}/_data`,
    Destination: mount.Target,
    Driver: "local",
    Mode: "",
    RW: mount.ReadOnly !== true,
    Propagation: "",
  }));
  const networks = Object.fromEntries(
    Object.keys(body.NetworkingConfig?.EndpointsConfig ?? {}).map((networkName) => {
      const network = Object.values(trusted.receipt.resources.networks ?? {})
        .find((candidate) => candidate.engineName === networkName);
      return [networkName, {
        Aliases: [],
        NetworkID: network?.engineId,
      }];
    }),
  );
  const imageId = expectedPhaseId
    ? trusted.receipt.resources.phaseProfiles[expectedPhaseId]?.workerImageId
    : WORKER_IMAGE_ID;
  return {
    Id: id,
    Name: `/${name}`,
    Image: imageId,
    Config: {
      Image: body.Image,
      Entrypoint: body.Entrypoint,
      Cmd: body.Cmd,
      Env: body.Env,
      User: body.User,
      WorkingDir: body.WorkingDir,
      NetworkDisabled: body.NetworkDisabled,
      AttachStdin: body.AttachStdin,
      AttachStdout: body.AttachStdout,
      AttachStderr: body.AttachStderr,
      OpenStdin: body.OpenStdin,
      StdinOnce: body.StdinOnce,
      Tty: body.Tty,
      Labels: body.Labels,
    },
    HostConfig: body.HostConfig,
    Mounts: [...bindMounts, ...namedMounts],
    NetworkSettings: { Networks: networks },
  };
}

function expectedWorkerCommand(created, trusted) {
  if (!created?.expectedPhaseId) return created?.body?.Cmd?.[0];
  const phase = trusted.receipt.resources.phaseProfiles[created.expectedPhaseId];
  if (!phase) throw new Error(`fake Engine phase is not admitted: ${created.expectedPhaseId}`);
  return phase.command;
}

function runtimeInspectParts(labels) {
  return {
    Config: {
      Cmd: ["postgres"],
      Entrypoint: ["docker-entrypoint.sh"],
      Env: ["LANG=C.UTF-8"],
      Image: IMAGE_REF,
      Labels: labels,
      User: "999:999",
      WorkingDir: "",
    },
    HostConfig: {
      Binds: [],
      CapAdd: [],
      CapDrop: ["ALL"],
      CgroupnsMode: "private",
      DeviceCgroupRules: [],
      Devices: [],
      DeviceRequests: [],
      ExtraHosts: [],
      GroupAdd: [],
      IpcMode: "private",
      Links: [],
      NetworkMode: "platform_db",
      PidMode: "",
      PortBindings: {},
      Privileged: false,
      PublishAllPorts: false,
      ReadonlyRootfs: true,
      Runtime: "runc",
      SecurityOpt: ["no-new-privileges:true"],
      UsernsMode: "",
      UTSMode: "",
      VolumesFrom: [],
    },
    Mounts: [],
    NetworkSettings: {
      Networks: {
        platform_db: {
          Aliases: ["enterprise-postgres"],
          EndpointID: "8".repeat(64),
          Gateway: "172.20.0.1",
          IPAddress: "172.20.0.2",
          IPPrefixLen: 24,
          NetworkID: "9".repeat(64),
        },
      },
    },
  };
}

function trustedFixture(overrides = {}) {
  const generation = overrides.generation ?? 1;
  const activationBundleSha256 = overrides.activationBundleSha256 ?? "f".repeat(64);
  const previousActiveSha256 = overrides.previousActiveSha256 ?? "0".repeat(64);
  const candidateId = overrides.candidateId ?? "candidate.v1";
  const environment = overrides.environment ?? "production";
  const targetId = overrides.targetId ?? "platform.primary";
  const intentId = overrides.intentId ?? "intent.v1";
  const dastChainSha256 = overrides.dastChainSha256 ?? "7".repeat(64);
  const labels = {
    "com.platform.runtime.candidate-id": candidateId,
    "com.platform.runtime.commit": "a".repeat(40),
    "com.platform.runtime.deployment-id": "deployment.v1",
    "com.platform.runtime.source-render-sha256": overrides.sourceRenderLabel ?? "b".repeat(64),
    "com.platform.runtime.tree": "c".repeat(40),
    "com.platform.runtime.workload-lock-sha256": "d".repeat(64),
  };
  if (overrides.legacyRenderLabel) {
    labels["com.platform.runtime.render-sha256"] = labels["com.platform.runtime.source-render-sha256"];
    delete labels["com.platform.runtime.source-render-sha256"];
  }
  const inspectParts = runtimeInspectParts(labels);
  const authority = {
    binds: [],
    capAdd: [],
    capDrop: ["ALL"],
    cgroupnsMode: "private",
    configSha256: sha256(canonicalJson(inspectParts.Config)),
    deviceCgroupRules: [],
    devices: [],
    deviceRequests: [],
    extraHosts: [],
    groupAdd: [],
    hostConfigSha256: sha256(canonicalJson(inspectParts.HostConfig)),
    ipcMode: "private",
    links: [],
    mounts: [],
    networkMode: "platform_db",
    networkSettingsSha256: sha256(canonicalJson(inspectParts.NetworkSettings)),
    networks: ["platform_db"],
    pidMode: "",
    portBindings: {},
    privileged: false,
    publishAllPorts: false,
    readonlyRootfs: true,
    runtime: "runc",
    securityOpt: ["no-new-privileges:true"],
    user: "999:999",
    usernsMode: "",
    utsMode: "",
    volumesFrom: [],
  };
  const rawReceipt = {
    schema: ACTIVE_RECEIPT_SCHEMA,
    activationBundleSha256,
    candidateId,
    environment,
    generation,
    receiptId: "receipt.v1",
    releaseId: "release.v1",
    issuedAt: new Date(overrides.receiptIssuedAt ?? NOW - 60_000).toISOString(),
    expiresAt: new Date(NOW + 60 * 60_000).toISOString(),
    treeSha256: "a".repeat(64),
    sourceRenderSha256: "b".repeat(64),
    combinedRenderSha256: "e".repeat(64),
    dastChainSha256,
    targetId,
    resources: {
      workerImage: { imageRef: WORKER_IMAGE_REF, imageId: WORKER_IMAGE_ID },
      backupResources: {
        "source:app1": { externalId: "app1", kind: "source", name: "app1", projectId: "app1", sourceDirectory: "app1" },
      },
      containers: {
        "platform.postgres": {
          authority,
          containerId: ENGINE_ID,
          name: "enterprise-postgres",
          imageRef: IMAGE_REF,
          imageId: IMAGE_ID,
          labels,
          expectedState: "running",
          expectedHealth: "healthy",
        },
      },
      mounts: {
        "backup.root": {
          access: "ro",
          canonicalPath: "/srv/platform/backups",
          containerPath: "/data/backups",
          device: 42,
          inode: 4242,
          kind: "directory",
          mode: 0o755,
          ownerGid: 0,
          ownerUid: 0,
          symlinkFree: true,
        },
      },
    },
  };
  const receipt = normalizeActiveReceipt(rawReceipt, { now: NOW });
  const intent = signRuntimeIntent({
    schema: RUNTIME_INTENT_SCHEMA,
    activationBundleSha256,
    candidateId,
    environment,
    generation,
    intentId,
    releaseId: "release.v1",
    issuedAt: new Date(overrides.intentIssuedAt ?? NOW - 30_000).toISOString(),
    expiresAt: new Date(NOW + 30 * 60_000).toISOString(),
    activeReceiptSha256: sha256(canonicalJson(receipt)),
    combinedRenderSha256: receipt.combinedRenderSha256,
    dastChainSha256,
    allowedActions: ["backup.prune.plan", "evidence.runtime.snapshot"],
    targetId,
  }, TRUST_KEY);
  const trusted = normalizeTrustedContext(intent, rawReceipt, TRUST_KEY, { now: NOW });
  return Object.freeze({
    ...trusted,
    activation: Object.freeze({
      activationId: overrides.activationId ?? `activation.${generation}`,
      candidateId,
      combinedRenderSha256: receipt.combinedRenderSha256,
      dastChainSha256,
      envelopeSha256: activationBundleSha256,
      environment,
      generation,
      nonce: overrides.activationNonce ?? Buffer.alloc(32, generation).toString("base64url"),
      previousActiveSha256,
      releaseId: receipt.releaseId,
      requestId: overrides.activationRequestId ?? `123e4567-e89b-42d3-a456-${String(generation).padStart(12, "0")}`,
      runtimeIntentId: intentId,
      sourceRenderSha256: receipt.sourceRenderSha256,
      targetId,
    }),
  });
}

function schedulerTrustedFixture() {
  const receipt = buildRawActiveReceiptV2({ now: NOW });
  receipt.generation = 1;
  const receiptDigest = fixtureSha256(canonicalFixtureJson(receipt));
  const intent = signRuntimeIntent({
    schema: RUNTIME_INTENT_SCHEMA,
    activeReceiptSha256: receiptDigest,
    activationBundleSha256: receipt.activationBundleSha256,
    allowedActions: [...SCHEDULER_ACTIONS],
    candidateId: receipt.candidateId,
    combinedRenderSha256: receipt.combinedRenderSha256,
    dastChainSha256: receipt.dastChainSha256,
    environment: receipt.environment,
    expiresAt: new Date(NOW + 30 * 60_000).toISOString(),
    generation: receipt.generation,
    intentId: "intent.release-v2",
    issuedAt: new Date(NOW - 30_000).toISOString(),
    releaseId: receipt.releaseId,
    targetId: receipt.targetId,
  }, TRUST_KEY);
  return Object.freeze({
    intent: Object.freeze(intent),
    receipt: Object.freeze(receipt),
    receiptDigest,
    activation: Object.freeze({
      activationId: "activation.1",
      candidateId: receipt.candidateId,
      combinedRenderSha256: receipt.combinedRenderSha256,
      dastChainSha256: receipt.dastChainSha256,
      envelopeSha256: receipt.activationBundleSha256,
      environment: receipt.environment,
      generation: receipt.generation,
      nonce: Buffer.alloc(32, 1).toString("base64url"),
      previousActiveSha256: "0".repeat(64),
      releaseId: receipt.releaseId,
      requestId: "123e4567-e89b-42d3-a456-000000000001",
      runtimeIntentId: intent.intentId,
      sourceRenderSha256: receipt.sourceRenderSha256,
      targetId: receipt.targetId,
    }),
  });
}

function requestFor(trusted, action, parameters = {}) {
  if (trusted.receipt.schema === ACTIVE_RECEIPT_SCHEMA_V2) {
    const request = buildFixtureSignedActionRequestV2(action, parameters, {
      index: v2RequestSequence += 1,
      now: NOW,
      trustedContext: trusted,
    });
    assert.equal(request.schema, REQUEST_SCHEMA_V2);
    assert.equal(request.capabilityId, EXPECTED_ACTION_BINDINGS[action].capabilityId);
    return request;
  }
  const unsigned = {
    schema: REQUEST_SCHEMA,
    requestId: crypto.randomUUID(),
    nonce: crypto.randomBytes(32).toString("base64url"),
    issuedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 30_000).toISOString(),
    runtimeIntentId: trusted.intent.intentId,
    activeReceiptSha256: trusted.receiptDigest,
    combinedRenderSha256: trusted.receipt.combinedRenderSha256,
    capabilityId: ACTIONS[action].capabilityId,
    action,
    parameters,
  };
  return signActionRequest(unsigned, CAPABILITIES[action]);
}

function admittedRequestShape(action) {
  return { requestId: crypto.randomUUID(), nonce: crypto.randomBytes(32).toString("base64url"), action };
}

function workerResult(command = "backup-prune-plan") {
  if (command === "backup-catalog") {
    return {
      schema: "platform.backup-catalog/v1",
      status: "passed",
      evidenceSha256: "a".repeat(64),
      mutationPerformed: true,
    };
  }
  if (command === "backup-job" || command === "restore-job") {
    return {
      schema: "platform.backup-job-result/v1",
      jobId: BACKUP_JOB_ID,
      jobOperation: command === "backup-job" ? "backup" : "restore-drill",
      status: "passed",
      evidenceSha256: "b".repeat(64),
      mutationPerformed: true,
    };
  }
  if (command === "backup-prune-apply") {
    return {
      schema: "platform.backup-prune-apply/v1",
      status: "passed",
      evidenceSha256: "c".repeat(64),
      mutationPerformed: true,
    };
  }
  if (command === "restore-drill-full") {
    return {
      schema: "platform.restore-drill/v1",
      status: "passed",
      evidenceSha256: "d".repeat(64),
      mutationPerformed: true,
    };
  }
  if (command === "backup-offsite-sync") {
    return {
      schema: "platform.offsite-backup-receipt/v1",
      status: "passed",
      evidenceSha256: "e".repeat(64),
      mutationPerformed: true,
      repositoryOffsite: true,
    };
  }
  return {
    schema: "platform.backup-prune-plan/v1",
    mode: "plan",
    keepCompleteManifests: 42,
    completeManifestCount: 2,
    retainedManifestIds: ["manifest:one"],
    expiredManifestIds: ["manifest:two"],
    mutationPerformed: false,
  };
}

function uniqueActionFlows() {
  const identities = new Set();
  return WORKER_FLOWS.filter(({ action, parameters }) => {
    const identity = `${action}\0${parameters.jobOperation ?? ""}`;
    if (identities.has(identity)) return false;
    identities.add(identity);
    return true;
  });
}

function assertExactPhaseBody(body, phaseCase, action, receipt) {
  const phase = receipt.resources.phaseProfiles[phaseCase.phaseId];
  const actionProfile = receipt.resources.actionProfiles[action];
  assert.ok(phase, `${phaseCase.phaseId} is absent from the receipt`);
  assert.equal(phase.command, phaseCase.command, `${phaseCase.phaseId} fixture command`);
  assert.equal(body.Image, phase.workerImageRef, `${phase.command} image must be release-pinned`);
  assert.deepEqual(body.Cmd, [phase.command], `${phase.command} argv must be fixed`);
  assert.equal(body.User, "0:0", `${phase.command} worker user must traverse the root-owned 0700 backup root`);
  assert.deepEqual(body.Labels, {
    "com.platform.active-receipt-sha256": fixtureSha256(canonicalFixtureJson(receipt)),
    "com.platform.docker-action": action,
    "com.platform.docker-action-profile": actionProfile.profileId,
    "com.platform.docker-action-profile-sha256": actionProfile.profileSha256,
    "com.platform.docker-phase": phaseCase.phaseId,
    "com.platform.docker-phase-sha256": phase.phaseSha256,
    "com.platform.runtime-intent": "intent.release-v2",
  });
  assert.equal(body.HostConfig?.Privileged, false);
  assert.equal(body.HostConfig?.ReadonlyRootfs, true);
  assert.deepEqual(body.HostConfig?.CapAdd, []);
  assert.deepEqual(body.HostConfig?.CapDrop, ["ALL"]);
  assert.deepEqual(body.HostConfig?.Devices, []);
  assert.deepEqual(body.HostConfig?.DeviceRequests, []);
  assert.deepEqual(
    body.HostConfig?.Binds,
    phase.mountIds.map((mountId) => {
      const mount = receipt.resources.mounts[mountId];
      return `${mount.canonicalPath}:${mount.containerPath}:${mount.access}`;
    }),
    `${phase.command} bind authority must exactly match its receipt-attested backup access`,
  );
  const expectedVolumeMounts = [
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
  assert.deepEqual(body.HostConfig?.Mounts, expectedVolumeMounts);
  const networkNames = phase.networkIds.map(
    (networkId) => receipt.resources.networks[networkId].engineName,
  );
  const expectedNetworkMode = networkNames[0] ?? "none";
  assert.equal(body.HostConfig?.NetworkMode, expectedNetworkMode, `${phase.command} NetworkMode must be exact`);
  assert.equal(body.NetworkDisabled, networkNames.length === 0);
  assert.deepEqual(
    body.NetworkingConfig?.EndpointsConfig,
    Object.fromEntries(networkNames.map((name) => [name, { Aliases: [] }])),
    `${phase.command} network membership must match the receipt exactly`,
  );
  if (phaseCase.phaseId === "offsite.sync") {
    assert.deepEqual(phase.networkIds, ["platform_egress"]);
  } else {
    assert.equal(phase.networkIds.includes("platform_egress"), false, `${phase.command} gained external egress`);
  }
  const serialized = canonicalJson(body);
  assert.doesNotMatch(serialized, /docker\.sock|DOCKER_HOST|jobs\.queue|\/run\/platform\/backup-jobs/);
  assert.doesNotMatch(serialized, /\/run\/secrets\/docker_action_/);
}

function readLeaseJournal(root, leaseId) {
  const directory = path.join(root, "journal", leaseId);
  assert.equal(fs.existsSync(directory), true, `lease journal directory is missing for ${leaseId}`);
  return fs.readdirSync(directory)
    .sort()
    .map((name) => JSON.parse(fs.readFileSync(path.join(directory, name), "utf8")));
}

function frame(text) {
  const payload = Buffer.from(text);
  const header = Buffer.alloc(8);
  header[0] = 1;
  header.writeUInt32BE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

function encode(value) {
  return Buffer.from(JSON.stringify(value));
}

function withoutMac(value) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== "mac"));
}

function tempDir(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-action-broker-test-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
