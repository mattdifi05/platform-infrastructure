import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  sha256,
} from "./docker-action-contract.mjs";
import * as broker from "./docker-action-broker.mjs";
import {
  backupDocumentDigest,
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

// Test-only deterministic key material. These bytes are not deployment secrets.
const MANIFEST_TEST_KEY = Buffer.alloc(48, 0x4d);
const ARTIFACT_TEST_KEY = Buffer.alloc(48, 0x41);
const PRUNE_TEST_KEY = Buffer.alloc(48, 0x50);
const BACKUP_JOB_ID = "0123456789abcdef";
const BACKUP_JOB_CREATED_AT = "2026-07-28T11:59:00.000Z";
const REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const REQUEST_INDEX = 426614174000;
const SNAPSHOT_CONTAINER_PATH = "/run/platform/claimed-job/job.json";
const MAX_WORKER_ENV_ENTRY_BYTES = 32 * 1024;
const MAX_WORKER_ENV_TOTAL_BYTES = 64 * 1024;
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
      job: backupJobParameters("backup"),
      phaseId: "job.backup.capture",
    },
    {
      action: "backup.job.execute",
      bytes: RESTORE_JOB_BYTES,
      command: "restore-job",
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

  const racingIo = sameSizeRaceIo(file, substituted);
  assert.throws(
    () => readProtectedFile(
      file,
      protectedFilePolicy(root, uid, gid),
      { io: racingIo },
    ),
    /changed|race|stable|substitution|content/i,
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
  const loaded = loadClaimedJobSnapshot(input);
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

test("worker source is socketless while its fixed subprocess adapter remains testable", () => {
  const source = fs.readFileSync(workerPath, "utf8");
  assert.doesNotMatch(source, /from\s+["']node:(?:net|http|https|tls|dgram|dns)["']/);
  assert.doesNotMatch(source, /require\(["'](?:net|http|https|tls|dgram|dns)["']\)/);
  assert.doesNotMatch(source, /docker\.sock|DOCKER_HOST|\/containers\/(?:create|[^"']*\/start)|\/images\/create/);
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
    sha256(options.artifactBytes["postgres/worker-test.dump"]),
    fixture.manifest.artifacts[0].sha256,
  );

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
  const sealed = planPruneTransition({ phase: "empty" }, { type: "seal", plan }, sealKey);
  assert.equal(sealed.phase, "sealed");
  assert.equal(sealed.plan.seal.algorithm, "HMAC-SHA256");
  assert.equal(sealed.plan.seal.keyId, sealKey.keyId);
  assert.match(sealed.plan.seal.digest, /^[a-f0-9]{64}$/);

  assert.throws(
    () => applyPruneTransition(sealed, {
      type: "commit-delete",
      planDigest: sealed.plan.seal.digest,
      quarantineDigest: "c".repeat(64),
    }, { keys: { [sealKey.keyId]: sealKey.key } }),
    /quarantine|phase|barrier|transition/i,
  );
  const quarantined = applyPruneTransition(sealed, {
    type: "quarantine",
    planDigest: sealed.plan.seal.digest,
    quarantineDigest: "c".repeat(64),
    artifactCount: plan.artifactCount,
  }, { keys: { [sealKey.keyId]: sealKey.key } });
  assert.equal(quarantined.phase, "quarantined");
  assert.equal(quarantined.deletionCommitted, false);
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
  const idempotencyKey = sha256(`platform-offsite-sync-v1\n${manifestDigest}\n`);
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
  assert.deepEqual(body.Entrypoint, ["node", "/opt/platform-docker-worker/docker-action-worker.mjs"]);
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
    assert.equal(env.PLATFORM_CLAIMED_JOB_PATH, SNAPSHOT_CONTAINER_PATH);
    assert.equal(env.PLATFORM_CLAIMED_JOB_FILE_NAME, claimedJobSnapshot.jobFileName);
    assert.equal(env.PLATFORM_CLAIMED_JOB_ID, claimedJobSnapshot.jobId);
    assert.equal(env.PLATFORM_CLAIMED_JOB_OPERATION, claimedJobSnapshot.jobOperation);
    assert.equal(env.PLATFORM_CLAIMED_JOB_SHA256, claimedJobSnapshot.jobSha256);
    assert.equal(env.PLATFORM_CLAIMED_JOB_SOURCE_ID, claimedJobSnapshot.sourceId);
    assert.equal(
      body.HostConfig.Binds.filter((bind) => bind.endsWith(`:${SNAPSHOT_CONTAINER_PATH}:ro`)).length,
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
      body.HostConfig.Binds.some((bind) => bind.includes(SNAPSHOT_CONTAINER_PATH)),
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
    Entrypoint: ["node", "/opt/platform-docker-worker/docker-action-worker.mjs"],
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
  const leafDescriptors = new Set();
  const evidence = {
    descriptorReadStarts: 0,
    fstatCalls: 0,
    leafOpenFlags: [],
    pathReadCalls: 0,
  };
  const io = new Proxy(fs, {
    get(target, property) {
      if (property === "openSync") {
        return (candidate, flags, ...args) => {
          const descriptor = target.openSync(candidate, flags, ...args);
          if (path.resolve(String(candidate)) === expectedPath) {
            evidence.leafOpenFlags.push(flags);
            leafDescriptors.add(descriptor);
          }
          return descriptor;
        };
      }
      if (property === "fstatSync") {
        return (descriptor, ...args) => {
          if (leafDescriptors.has(descriptor)) evidence.fstatCalls += 1;
          return target.fstatSync(descriptor, ...args);
        };
      }
      if (property === "readFileSync") {
        return (candidate, ...args) => {
          if (typeof candidate === "number" && leafDescriptors.has(candidate)) {
            evidence.descriptorReadStarts += 1;
          } else if (typeof candidate !== "number"
            && path.resolve(String(candidate)) === expectedPath) {
            evidence.pathReadCalls += 1;
          }
          return target.readFileSync(candidate, ...args);
        };
      }
      if (property === "readSync") {
        return (descriptor, buffer, offset, length, position) => {
          if (leafDescriptors.has(descriptor) && position === 0) {
            evidence.descriptorReadStarts += 1;
          }
          return target.readSync(descriptor, buffer, offset, length, position);
        };
      }
      if (property === "closeSync") {
        return (descriptor) => {
          const result = target.closeSync(descriptor);
          leafDescriptors.delete(descriptor);
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
  assert.ok(evidence.leafOpenFlags.length >= 1, "claimed-job leaf was not descriptor-opened");
  assert.equal(
    evidence.leafOpenFlags.every(
      (flags) => Number.isInteger(flags)
        && (flags & fs.constants.O_NOFOLLOW) === fs.constants.O_NOFOLLOW,
    ),
    true,
    "claimed-job leaf open did not observe O_NOFOLLOW",
  );
  assert.ok(
    evidence.descriptorReadStarts >= 2,
    "claimed-job consumer did not perform two independent descriptor reads",
  );
  assert.ok(evidence.fstatCalls >= 2, "claimed-job consumer did not fstat before and after reading");
  assert.equal(evidence.pathReadCalls, 0, "claimed-job bytes were re-opened by pathname");
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
  let stableStat;
  let bytesRead = 0;
  let substituted = false;
  const substitute = () => {
    if (substituted) return;
    substituted = true;
    fs.writeFileSync(file, substitutedBytes);
    fs.chmodSync(file, 0o600);
  };
  return new Proxy(fs, {
    get(target, property) {
      if (property === "fstatSync") {
        return (descriptor) => {
          stableStat ??= target.fstatSync(descriptor);
          return stableStat;
        };
      }
      if (property === "readFileSync") {
        return (descriptor, ...args) => {
          const value = target.readFileSync(descriptor, ...args);
          if (typeof descriptor === "number") substitute();
          return value;
        };
      }
      if (property === "readSync") {
        return (descriptor, buffer, offset, length, position) => {
          const count = target.readSync(descriptor, buffer, offset, length, position);
          bytesRead += count;
          if (bytesRead >= substitutedBytes.length) substitute();
          return count;
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
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

function writeProtectedJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function signedManifestEnvelope() {
  const artifactPath = "postgres/worker-test.dump";
  const artifactBytes = Buffer.from("worker test artifact\n");
  const artifactSha256 = sha256(artifactBytes);
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
  const digest = backupDocumentDigest(unsigned);
  const manifestMac = crypto.createHmac("sha256", MANIFEST_TEST_KEY)
    .update(`platform-backup-manifest-v1\n${unsigned.id}\n${digest}\n`)
    .digest("base64url");
  const artifactName = path.basename(artifactPath);
  const artifactMac = crypto.createHmac("sha256", ARTIFACT_TEST_KEY)
    .update(`platform-postgres-backup-v1\n${artifactName}\n${artifactSha256}\n`)
    .digest("base64url");
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
  };
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
