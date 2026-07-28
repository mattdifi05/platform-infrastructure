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
  "backup.prune.plan": Buffer.from("p".repeat(48)),
  "evidence.runtime.snapshot": Buffer.from("e".repeat(48)),
});
const TRUST_KEY = Buffer.from("t".repeat(48));
const ENGINE_ID = "1".repeat(64);
const WORKER_ID = "2".repeat(64);
const IMAGE_ID = `sha256:${"3".repeat(64)}`;
const WORKER_IMAGE_ID = `sha256:${"4".repeat(64)}`;
const IMAGE_REF = `registry.example/platform/postgres@sha256:${"5".repeat(64)}`;
const WORKER_IMAGE_REF = `registry.example/platform/docker-action-broker@sha256:${"6".repeat(64)}`;

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

function coreFixture(t, options = {}) {
  const root = tempDir(t);
  const trusted = trustedFixture();
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
  return { core, engine, transport, trusted, executeStarted: () => started };
}

class FakeEngineTransport {
  constructor(options) {
    this.options = options;
    this.calls = [];
    this.created = null;
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
    const inspect = workerInspect(this.created, id);
    return this.options.inspectMutation ? this.options.inspectMutation(inspect) : inspect;
  }

  async inspectContainerForRecovery() {
    this.calls.push({ method: "inspectContainerForRecovery" });
    return this.created ? workerInspect(this.created, WORKER_ID) : null;
  }

  async createWorker(name, body) {
    this.calls.push({ method: "createWorker", name, body });
    this.created = { name, body };
    return { Id: WORKER_ID };
  }

  async startContainer(id) {
    this.calls.push({ method: "startContainer", id });
  }

  async waitContainer(id) {
    this.calls.push({ method: "waitContainer", id });
    return { StatusCode: 0 };
  }

  async logsContainer(id) {
    this.calls.push({ method: "logsContainer", id });
    return frame(`${JSON.stringify(workerResult())}\n`);
  }

  async deleteContainer(id) {
    this.calls.push({ method: "deleteContainer", id });
    if (this.options.deleteNeverReturns) return new Promise(() => {});
    this.created = null;
  }
}

function workerInspect(created, id) {
  const { name, body } = created;
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
    Mounts: [{ Source: "/srv/platform/backups", Destination: "/data/backups", RW: false }],
    NetworkSettings: { Networks: {} },
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

function requestFor(trusted, action) {
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
    parameters: {},
  };
  return signActionRequest(unsigned, CAPABILITIES[action]);
}

function admittedRequestShape(action) {
  return { requestId: crypto.randomUUID(), nonce: crypto.randomBytes(32).toString("base64url"), action };
}

function workerResult() {
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
