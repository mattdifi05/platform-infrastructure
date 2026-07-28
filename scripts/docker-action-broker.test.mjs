import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
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
} from "./docker-action-contract.mjs";
import {
  PersistentReplayStore,
  createBrokerCore,
  createFixedDockerEngine,
  parseWorkerOutput,
  readProtectedFile,
  workerCreateBody,
} from "./docker-action-broker.mjs";

const NOW = Date.parse("2026-07-26T12:00:00.000Z");
const CAPABILITIES = Object.freeze({
  "backup.catalog": Buffer.from("c".repeat(48)),
  "backup.job.execute": Buffer.from("j".repeat(48)),
  "backup.prune.plan": Buffer.from("p".repeat(48)),
  "backup.prune.apply": Buffer.from("a".repeat(48)),
  "restore.drill.full": Buffer.from("r".repeat(48)),
  "backup.offsite.sync": Buffer.from("o".repeat(48)),
  "evidence.runtime.snapshot": Buffer.from("e".repeat(48)),
});
const TRUST_KEY = Buffer.from("t".repeat(48));
const ENGINE_ID = "1".repeat(64);
const WORKER_ID = "2".repeat(64);
const IMAGE_ID = `sha256:${"3".repeat(64)}`;
const WORKER_IMAGE_ID = `sha256:${"4".repeat(64)}`;
const IMAGE_REF = `registry.example/platform/postgres@sha256:${"5".repeat(64)}`;
const WORKER_IMAGE_REF = `registry.example/platform/docker-action-broker@sha256:${"6".repeat(64)}`;
const BACKUP_JOB_ID = "0123456789abcdef";
const BACKUP_JOB_SHA256 = "7".repeat(64);
const SCHEDULER_ACTIONS = Object.freeze([
  "backup.catalog",
  "backup.job.execute",
  "backup.prune.plan",
  "backup.prune.apply",
  "restore.drill.full",
  "backup.offsite.sync",
]);
const INTERNAL_WORKER_NETWORKS = Object.freeze(["platform_db_admin", "platform_storage"]);
const WORKER_FLOWS = Object.freeze([
  Object.freeze({
    id: "backup-catalog",
    action: "backup.catalog",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-catalog", profile: "backup", networks: INTERNAL_WORKER_NETWORKS }),
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
      Object.freeze({ command: "backup-job", profile: "backup", networks: INTERNAL_WORKER_NETWORKS }),
    ]),
  }),
  Object.freeze({
    id: "restore-job",
    action: "backup.job.execute",
    parameters: Object.freeze({
      jobFileName: `${BACKUP_JOB_ID}.json`,
      jobId: BACKUP_JOB_ID,
      jobOperation: "restore-drill",
      jobSha256: BACKUP_JOB_SHA256,
    }),
    phases: Object.freeze([
      Object.freeze({ command: "restore-job", profile: "restore", networks: INTERNAL_WORKER_NETWORKS }),
    ]),
  }),
  Object.freeze({
    id: "backup-prune-plan",
    action: "backup.prune.plan",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-prune-plan", profile: "retention", networks: Object.freeze([]) }),
    ]),
  }),
  Object.freeze({
    id: "backup-prune-apply",
    action: "backup.prune.apply",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-prune-apply", profile: "retention", networks: Object.freeze([]) }),
    ]),
  }),
  Object.freeze({
    id: "restore-full",
    action: "restore.drill.full",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-catalog", profile: "backup", networks: INTERNAL_WORKER_NETWORKS }),
      Object.freeze({ command: "restore-full", profile: "restore", networks: INTERNAL_WORKER_NETWORKS }),
    ]),
  }),
  Object.freeze({
    id: "backup-offsite-sync",
    action: "backup.offsite.sync",
    parameters: Object.freeze({}),
    phases: Object.freeze([
      Object.freeze({ command: "backup-offsite-sync", profile: "offsite", networks: Object.freeze(["platform_egress"]) }),
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

test("all six scheduler actions use exact socketless semantic worker profiles", async (t) => {
  for (const flow of WORKER_FLOWS) {
    await t.test(flow.id, async (t) => {
      const fixture = coreFixture(t, { trusted: schedulerTrustedFixture() });
      let brokerFailure;
      try {
        await fixture.core.handle(encode(requestFor(fixture.trusted, flow.action, flow.parameters)));
      } catch (error) {
        brokerFailure = error;
      }
      const creates = fixture.transport.calls.filter(({ method }) => method === "createWorker");
      assert.equal(
        creates.length,
        flow.phases.length,
        `${flow.id} must create ${flow.phases.length} fixed worker phase(s); broker error=${brokerFailure?.message ?? "none"}`,
      );
      for (let index = 0; index < flow.phases.length; index += 1) {
        assertExactPhaseBody(creates[index].body, flow.phases[index], flow.action);
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
    for (const mutation of mutations) {
      const key = Object.keys(mutation)[0];
      await t.test(`${flow.id}-${key}`, async (t) => {
        const fixture = coreFixture(t, { trusted: schedulerTrustedFixture() });
        const request = requestFor(fixture.trusted, flow.action, { ...flow.parameters, ...mutation });
        await assert.rejects(
          () => fixture.core.handle(encode(request)),
          undefined,
          `${flow.id} must reject caller-controlled ${key}`,
        );
        assert.deepEqual(fixture.transport.calls, [], `${flow.id}/${key} reached the Engine before exact admission`);
      });
    }
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

test("lease v2 retains multiple workers in an append-only hash-chained journal", (t) => {
  const root = tempDir(t);
  const trusted = schedulerTrustedFixture();
  const store = new PersistentReplayStore(root, {
    now: () => NOW,
    bootId: "a".repeat(48),
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
  });
  store.admitTrustedContext(trusted);
  const lease = store.acquire(admittedRequestShape("restore.drill.full"), trusted);
  const body = workerCreateBodyForFixture(trusted);
  lease.recordWorker({
    phaseId: "catalog",
    resourceName: "platform-action-restore-catalog",
    body,
    imageId: WORKER_IMAGE_ID,
    hostPath: "/srv/platform/backups",
  });
  lease.recordWorker({
    phaseId: "restore",
    resourceName: "platform-action-restore-full",
    body,
    imageId: WORKER_IMAGE_ID,
    hostPath: "/srv/platform/backups",
  });
  lease.preserve();

  const active = JSON.parse(fs.readFileSync(path.join(root, "active.lock"), "utf8"));
  assert.equal(active.schema, "platform.docker-action.lease/v2", "multi-phase work requires lease/v2");
  assert.match(active.leaseId, /^[a-f0-9]{64}$/, "lease/v2 requires a stable exact lease identity");
  const entries = readLeaseJournal(root, active.leaseId);
  const workers = entries.filter(({ event }) => event === "worker-recorded");
  assert.deepEqual(
    workers.map(({ phaseId, resource }) => [phaseId, resource.logicalId]),
    [["catalog", "platform-action-restore-catalog"], ["restore", "platform-action-restore-full"]],
  );
  let previousEntrySha256 = "0".repeat(64);
  for (const entry of entries) {
    assert.equal(entry.schema, "platform.docker-action.lease-journal-entry/v2");
    assert.equal(entry.previousEntrySha256, previousEntrySha256, `journal chain broke at sequence ${entry.sequence}`);
    previousEntrySha256 = sha256(canonicalJson(entry));
  }
});

test("crash recovery exact-inspects and cleans multiple workers in reverse creation order", async (t) => {
  const root = tempDir(t);
  const trusted = schedulerTrustedFixture();
  const owner = { expectedUid: process.getuid(), expectedGid: process.getgid() };
  const firstBody = workerCreateBodyForFixture(trusted);
  const secondBody = workerCreateBodyForFixture(trusted);
  const store = new PersistentReplayStore(root, { now: () => NOW, bootId: "a".repeat(48), ...owner });
  store.admitTrustedContext(trusted);
  const lease = store.acquire(admittedRequestShape("restore.drill.full"), trusted);
  lease.recordWorker({
    phaseId: "catalog",
    resourceName: "platform-action-restore-catalog",
    body: firstBody,
    imageId: WORKER_IMAGE_ID,
    hostPath: "/srv/platform/backups",
  });
  lease.recordWorker({
    phaseId: "restore",
    resourceName: "platform-action-restore-full",
    body: secondBody,
    imageId: WORKER_IMAGE_ID,
    hostPath: "/srv/platform/backups",
  });
  lease.preserve();

  const transport = new FakeEngineTransport({
    trusted,
    recoveryWorkers: [
      { id: WORKER_ID, name: "platform-action-restore-catalog", body: firstBody },
      { id: "8".repeat(64), name: "platform-action-restore-full", body: secondBody },
    ],
  });
  const engine = createFixedDockerEngine({ transport, cleanupTimeoutMs: 100 });
  const recovered = new PersistentReplayStore(root, { now: () => NOW, bootId: "b".repeat(48), ...owner });
  await recovered.recover(engine);
  assert.deepEqual(
    transport.calls.filter(({ method }) => method === "deleteContainer").map(({ id }) => id),
    ["8".repeat(64), WORKER_ID],
    "recovery must clean every exact-inspected worker in reverse creation order",
  );
});

test("prune apply journals sealed plan, quarantine, verification and terminal deletion barriers", (t) => {
  const root = tempDir(t);
  const trusted = schedulerTrustedFixture();
  const store = new PersistentReplayStore(root, {
    now: () => NOW,
    bootId: "a".repeat(48),
    expectedUid: process.getuid(),
    expectedGid: process.getgid(),
  });
  store.admitTrustedContext(trusted);
  const lease = store.acquire(admittedRequestShape("backup.prune.apply"), trusted);
  const body = workerCreateBodyForFixture(trusted);
  for (const [phaseId, event] of [
    ["plan-sealed", "prune-plan-sealed"],
    ["quarantine", "prune-quarantine-created"],
    ["verification", "prune-quarantine-verified"],
    ["terminal-delete", "prune-final-delete"],
  ]) {
    lease.recordWorker({
      phaseId,
      event,
      resourceName: `platform-action-prune-${phaseId}`,
      body,
      imageId: WORKER_IMAGE_ID,
      hostPath: "/srv/platform/backups",
      resultSha256: sha256(`${phaseId}\n`),
    });
  }
  lease.preserve();
  const active = JSON.parse(fs.readFileSync(path.join(root, "active.lock"), "utf8"));
  assert.equal(active.schema, "platform.docker-action.lease/v2", "prune barriers require lease/v2");
  const events = readLeaseJournal(root, active.leaseId).map(({ event }) => event);
  assert.deepEqual(events.slice(-4), [
    "prune-plan-sealed",
    "prune-quarantine-created",
    "prune-quarantine-verified",
    "prune-final-delete",
  ]);
});

test("full restore never starts restore phase when the catalog barrier fails", async (t) => {
  const fixture = coreFixture(t, {
    trusted: schedulerTrustedFixture(),
    workerStatusCodes: { "backup-catalog": 17 },
  });
  await assert.rejects(
    () => fixture.core.handle(encode(requestFor(fixture.trusted, "restore.drill.full", {}))),
  );
  assert.deepEqual(
    fixture.transport.calls.filter(({ method }) => method === "createWorker").map(({ body }) => body.Cmd),
    [["backup-catalog"]],
    "restore-full must not be created until the catalog phase has a durable successful barrier",
  );
});

test("offsite remote-unknown preserves the lease and is never replayed automatically", async (t) => {
  let remoteAttempts = 0;
  const fixture = coreFixture(t, {
    trusted: schedulerTrustedFixture(),
    executeOverride: async (action) => {
      assert.equal(action, "backup.offsite.sync");
      remoteAttempts += 1;
      const error = new Error("remote side effect completed but terminal receipt is unknown");
      error.remoteEffectUnknown = true;
      throw error;
    },
  });
  await assert.rejects(
    () => fixture.core.handle(encode(requestFor(fixture.trusted, "backup.offsite.sync", {}))),
  );
  const leasePreserved = fs.existsSync(path.join(fixture.root, "active.lock"));
  await assert.rejects(
    () => fixture.core.handle(encode(requestFor(fixture.trusted, "backup.offsite.sync", {}))),
  );
  assert.equal(remoteAttempts, 1, "remote-unknown must block automatic offsite replay");
  assert.equal(leasePreserved, true, "remote-unknown must preserve the durable recovery lease");
});

function coreFixture(t, options = {}) {
  const root = tempDir(t);
  const trusted = options.trusted ?? trustedFixture();
  const transport = new FakeEngineTransport({ trusted, ...options });
  let started = false;
  const fixed = createFixedDockerEngine({
    transport,
    randomBytes: () => Buffer.alloc(12, 1),
    cleanupTimeoutMs: options.cleanupTimeoutMs ?? 100,
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
    const inspect = workerInspect(created, id);
    return this.options.inspectMutation ? this.options.inspectMutation(inspect) : inspect;
  }

  async inspectContainerForRecovery(name) {
    this.calls.push({ method: "inspectContainerForRecovery", name });
    const created = this.recoveryWorkers.find((candidate) => candidate.name === name)
      ?? this.createdWorkers.find((candidate) => candidate.name === name)
      ?? (this.created?.name === name ? this.created : null);
    return created ? workerInspect(created, created.id ?? WORKER_ID) : null;
  }

  async createWorker(name, body) {
    this.calls.push({ method: "createWorker", name, body });
    const id = this.createdWorkers.length === 0
      ? WORKER_ID
      : (this.createdWorkers.length + 2).toString(16).repeat(64).slice(0, 64);
    this.created = { id, name, body };
    this.createdWorkers.push(this.created);
    return { Id: id };
  }

  async startContainer(id) {
    this.calls.push({ method: "startContainer", id });
  }

  async waitContainer(id) {
    this.calls.push({ method: "waitContainer", id });
    const created = this.createdWorkers.find((candidate) => candidate.id === id);
    const command = created?.body?.Cmd?.[0];
    return { StatusCode: this.options.workerStatusCodes?.[command] ?? 0 };
  }

  async logsContainer(id) {
    this.calls.push({ method: "logsContainer", id });
    const created = this.createdWorkers.find((candidate) => candidate.id === id);
    return frame(`${JSON.stringify(workerResult(created?.body?.Cmd?.[0]))}\n`);
  }

  async deleteContainer(id) {
    this.calls.push({ method: "deleteContainer", id });
    if (this.options.deleteNeverReturns) return new Promise(() => {});
    this.createdWorkers = this.createdWorkers.filter((candidate) => candidate.id !== id);
    this.recoveryWorkers = this.recoveryWorkers.filter((candidate) => candidate.id !== id);
    if (this.created?.id === id || (this.created?.id === undefined && id === WORKER_ID)) this.created = null;
  }
}

function workerInspect(created, id) {
  if (!created) throw new Error(`fake Engine has no worker for ${id}`);
  const { name, body } = created;
  const mounts = (body.HostConfig?.Binds ?? []).map((bind) => {
    const [source, destination, access = "rw"] = bind.split(":");
    return { Source: source, Destination: destination, RW: access !== "ro" };
  });
  const networks = Object.fromEntries(
    Object.keys(body.NetworkingConfig?.EndpointsConfig ?? {}).map((name) => [name, {}]),
  );
  return {
    Id: id,
    Name: `/${name}`,
    Image: WORKER_IMAGE_ID,
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
    Mounts: mounts,
    NetworkSettings: { Networks: networks },
  };
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
  const base = trustedFixture();
  const actionProfiles = Object.fromEntries(SCHEDULER_ACTIONS.map((action) => {
    const networks = action === "backup.offsite.sync"
      ? ["platform_egress"]
      : action === "backup.prune.plan" || action === "backup.prune.apply"
        ? []
        : [...INTERNAL_WORKER_NETWORKS];
    const mountIds = action === "backup.catalog" || action === "backup.prune.apply"
      ? ["backup.root.rw"]
      : action === "backup.job.execute" || action === "restore.drill.full"
        ? ["backup.root", "backup.root.rw"]
        : ["backup.root"];
    const unsignedProfile = {
      jobOperations: action === "backup.job.execute" ? ["backup", "restore-drill"] : [],
      mountIds,
      networkIds: networks,
      profileId: `scheduler.${action}.v2`,
      quarantineVolumeIds: action === "backup.prune.apply" ? ["prune.quarantine"] : [],
      scratchVolumeIds: action === "restore.drill.full" ? ["restore.scratch"] : [],
      secretFileIds: action === "backup.offsite.sync" ? ["offsite.repository"] : [],
      workerImageId: WORKER_IMAGE_ID,
      workerImageRef: WORKER_IMAGE_REF,
    };
    return [action, Object.freeze({
      ...unsignedProfile,
      profileSha256: sha256(canonicalJson(unsignedProfile)),
    })];
  }));
  const receipt = Object.freeze({
    ...base.receipt,
    schema: "platform.docker-action.active-receipt/v2",
    resources: Object.freeze({
      ...base.receipt.resources,
      actionProfiles: Object.freeze(actionProfiles),
      mounts: Object.freeze({
        ...base.receipt.resources.mounts,
        "backup.root.rw": Object.freeze({
          ...base.receipt.resources.mounts["backup.root"],
          access: "rw",
        }),
      }),
      networks: Object.freeze({
        platform_db_admin: Object.freeze({
          driver: "bridge",
          externalEgress: false,
          internal: true,
          name: "platform_db_admin",
          networkId: "a".repeat(64),
          optionsSha256: "1".repeat(64),
        }),
        platform_storage: Object.freeze({
          driver: "bridge",
          externalEgress: false,
          internal: true,
          name: "platform_storage",
          networkId: "b".repeat(64),
          optionsSha256: "2".repeat(64),
        }),
        platform_egress: Object.freeze({
          driver: "bridge",
          externalEgress: true,
          internal: false,
          name: "platform_egress",
          networkId: "c".repeat(64),
          optionsSha256: "3".repeat(64),
        }),
      }),
      secretFiles: Object.freeze({
        "offsite.repository": Object.freeze({
          canonicalPath: "/run/secrets/offsite_repository",
          device: 42,
          inode: 5001,
          mode: 0o400,
          ownerGid: 0,
          ownerUid: 0,
          sha256: "d".repeat(64),
          symlinkFree: true,
        }),
      }),
      volumes: Object.freeze({
        "prune.quarantine": Object.freeze({
          driver: "local",
          labelsSha256: "4".repeat(64),
          name: "platform_prune_quarantine",
          optionsSha256: "5".repeat(64),
        }),
        "restore.scratch": Object.freeze({
          driver: "local",
          labelsSha256: "6".repeat(64),
          name: "platform_restore_scratch",
          optionsSha256: "7".repeat(64),
        }),
      }),
    }),
  });
  const receiptDigest = sha256(canonicalJson(receipt));
  const intent = Object.freeze({
    ...base.intent,
    activeReceiptSha256: receiptDigest,
    allowedActions: Object.freeze([...SCHEDULER_ACTIONS]),
  });
  return Object.freeze({ ...base, intent, receipt, receiptDigest });
}

function requestFor(trusted, action, parameters = {}) {
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
  if (command === "restore-full") {
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
  const actions = new Set();
  return WORKER_FLOWS.filter(({ action }) => {
    if (actions.has(action)) return false;
    actions.add(action);
    return true;
  });
}

function expectedBackupAccess(command) {
  if (["backup-catalog", "backup-job", "backup-prune-apply"].includes(command)) return "rw";
  return "ro";
}

function expectedWorkerBinds(command) {
  const binds = [`/srv/platform/backups:/data/backups:${expectedBackupAccess(command)}`];
  if (command === "backup-offsite-sync") {
    binds.push("/run/secrets/offsite_repository:/run/secrets/offsite_repository:ro");
  }
  return binds;
}

function assertExactPhaseBody(body, phase, action) {
  assert.equal(body.Image, WORKER_IMAGE_REF, `${phase.command} image must be release-pinned`);
  assert.deepEqual(body.Cmd, [phase.command], `${phase.command} argv must be fixed`);
  assert.equal(body.User, "0:0", `${phase.command} worker user must traverse the root-owned 0700 backup root`);
  assert.equal(body.Labels?.["com.platform.docker-action"], action);
  assert.equal(body.Labels?.["com.platform.docker-action-profile"], phase.profile);
  assert.equal(body.HostConfig?.Privileged, false);
  assert.equal(body.HostConfig?.ReadonlyRootfs, true);
  assert.deepEqual(body.HostConfig?.CapAdd, []);
  assert.deepEqual(body.HostConfig?.CapDrop, ["ALL"]);
  assert.deepEqual(body.HostConfig?.Devices, []);
  assert.deepEqual(body.HostConfig?.DeviceRequests, []);
  assert.deepEqual(
    body.HostConfig?.Binds,
    expectedWorkerBinds(phase.command),
    `${phase.command} bind authority must exactly match its receipt-attested backup access`,
  );
  const expectedNetworkMode = phase.networks.length === 0 ? "none" : phase.networks[0];
  assert.equal(body.HostConfig?.NetworkMode, expectedNetworkMode, `${phase.command} NetworkMode must be exact`);
  assert.equal(body.NetworkDisabled, phase.networks.length === 0);
  assert.deepEqual(
    Object.keys(body.NetworkingConfig?.EndpointsConfig ?? {}).sort(),
    [...phase.networks].sort(),
    `${phase.command} network membership must match the receipt exactly`,
  );
  for (const endpoint of Object.values(body.NetworkingConfig?.EndpointsConfig ?? {})) {
    assert.deepEqual(endpoint, {}, `${phase.command} must not request a Docker network alias`);
  }
  if (phase.profile === "offsite") {
    assert.deepEqual(phase.networks, ["platform_egress"]);
  } else {
    assert.equal(phase.networks.includes("platform_egress"), false, `${phase.command} gained external egress`);
  }
  const serialized = canonicalJson(body);
  assert.doesNotMatch(serialized, /docker\.sock|DOCKER_HOST|\/var\/run:|\/run:/);
}

function readLeaseJournal(root, leaseId) {
  const directory = path.join(root, "journal", leaseId);
  assert.equal(fs.existsSync(directory), true, `lease journal directory is missing for ${leaseId}`);
  return fs.readdirSync(directory)
    .sort()
    .map((name) => JSON.parse(fs.readFileSync(path.join(directory, name), "utf8")));
}

function workerCreateBodyForFixture(trusted) {
  return workerCreateBody({
    action: "backup.prune.plan",
    command: "backup-prune-plan",
    imageRef: WORKER_IMAGE_REF,
    hostPath: "/srv/platform/backups",
    intentId: trusted.intent.intentId,
    receiptDigest: trusted.receiptDigest,
    mountAttestation: trusted.receipt.resources.mounts["backup.root"],
  });
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
