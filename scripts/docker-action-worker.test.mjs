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

test("worker module is import-safe and does not execute its CLI during unit tests", () => {
  assert.equal(importedWorker.stderr, "", "importing the worker must not emit CLI stderr");
  assert.equal(importedWorker.exitCode, undefined, "importing the worker must not set a process exit code");
});

test("fixed dispatcher admits exact commands and never derives shell argv from caller input", async () => {
  const dispatchWorkerCommand = requireWorkerFunction("dispatchWorkerCommand");
  const calls = [];
  const adapter = Object.freeze({
    runFixedTool: async (invocation) => {
      calls.push(structuredClone(invocation));
      return boundedWorkerSummary(invocation.command);
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
    assert.deepEqual(result, boundedWorkerSummary(command));
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

test("CLI entrypoint delegates one fixed command and emits one bounded normalized document", async () => {
  const runWorkerCli = requireWorkerFunction("runWorkerCli");
  const toolCalls = [];
  let stdout = "";
  let stderr = "";
  const result = await runWorkerCli(
    [process.execPath, workerPath, "restore-drill-full"],
    {
      writeStdout: (chunk) => { stdout += String(chunk); },
      writeStderr: (chunk) => { stderr += String(chunk); },
    },
    {
      runFixedTool: async (invocation) => {
        toolCalls.push(structuredClone(invocation));
        return boundedWorkerSummary(invocation.command);
      },
    },
  );
  assert.equal(result, 0);
  assert.equal(stderr, "");
  assert.equal(toolCalls.length, 1);
  assert.equal(toolCalls[0].command, "restore-drill-full");
  assert.equal(toolCalls[0].profile, "restore");
  assert.equal(toolCalls[0].shell, false);
  assert.equal(stdout, `${JSON.stringify(boundedWorkerSummary("restore-drill-full"))}\n`);

  await assert.rejects(
    () => runWorkerCli(
      [process.execPath, workerPath, "restore-drill-full", "--shell", "sh"],
      { writeStdout: () => {}, writeStderr: () => {} },
      { runFixedTool: async () => assert.fail("hostile CLI input reached the tool adapter") },
    ),
    /argument|command|parameter|unsupported/i,
  );
});

test("protected-file reader enforces leaf and ancestor identity, mode, links and byte bounds", (t) => {
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

test("protected-file reader rejects a same-size content swap even when descriptor stats appear stable", (t) => {
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

test("broker stable-reads the exact claimed queue document into an immutable worker snapshot", (t) => {
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

  const sameSizeTamper = Buffer.from(BACKUP_JOB_BYTES);
  sameSizeTamper[sameSizeTamper.length - 1] = 0x20;
  fs.writeFileSync(jobFile, sameSizeTamper);
  fs.chmodSync(jobFile, 0o600);
  assert.throws(
    () => readClaimedJobSnapshot(input),
    /digest|sha256|claimed|job|substitution/i,
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

test("workerCreateBody emits exact phase-scoped receipt authority for every canonical phase", () => {
  const receipt = buildRawActiveReceiptV2();
  const trusted = {
    intent: { intentId: "intent.release-v2" },
    receipt,
    receiptDigest: fixtureSha256(canonicalFixtureJson(receipt)),
  };

  for (const { action, phaseId, snapshot } of phaseActionCases()) {
    const sourceBytes = snapshot ? Buffer.from(snapshot.bytes) : null;
    const claimedJobSnapshot = snapshot ? { ...snapshot, bytes: sourceBytes } : undefined;
    const body = broker.workerCreateBody({
      action,
      phaseId,
      trusted,
      claimedJobSnapshot,
    });
    const phase = receipt.resources.phaseProfiles[phaseId];
    const actionProfile = receipt.resources.actionProfiles[action];
    const authority = expectedPhaseAuthority(receipt, action, phaseId);
    const env = environmentMap(body.Env);

    assert.equal(body.Image, phase.workerImageRef, `${phaseId} image`);
    assert.deepEqual(body.Entrypoint, ["node", "/opt/platform-docker-worker/docker-action-worker.mjs"]);
    assert.deepEqual(body.Cmd, [phase.command], `${phaseId} fixed command`);
    assert.equal(body.User, "0:0", `${phaseId} must traverse root-owned 0700 inputs`);
    assert.equal(body.WorkingDir, "/opt/platform-docker-worker");
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
      body.HostConfig.Binds,
      phase.mountIds.map((mountId) => {
        const mount = receipt.resources.mounts[mountId];
        return `${mount.canonicalPath}:${mount.containerPath}:${mount.access}`;
      }),
      `${phaseId} host binds`,
    );
    assert.deepEqual(
      body.HostConfig.Mounts,
      expectedNamedVolumeMounts(receipt, phase),
      `${phaseId} named-volume inputs and scratch`,
    );
    assert.equal(body.HostConfig.Privileged, false);
    assert.equal(body.HostConfig.ReadonlyRootfs, true);
    assert.deepEqual(body.HostConfig.CapAdd, []);
    assert.deepEqual(body.HostConfig.CapDrop, ["ALL"]);
    assert.deepEqual(body.HostConfig.Devices, []);
    assert.deepEqual(body.HostConfig.DeviceRequests, []);
    assert.deepEqual(body.HostConfig.DeviceCgroupRules, []);
    assert.deepEqual(body.HostConfig.GroupAdd, []);
    assert.deepEqual(body.HostConfig.Links, []);
    assert.deepEqual(body.HostConfig.VolumesFrom, []);
    assert.deepEqual(body.HostConfig.PortBindings, {});
    assert.equal(body.HostConfig.PublishAllPorts, false);
    assert.equal(body.HostConfig.CgroupnsMode, "private");
    assert.equal(body.HostConfig.IpcMode, "private");
    assert.notEqual(body.HostConfig.PidMode, "host");
    assert.notEqual(body.HostConfig.UsernsMode, "host");
    assert.notEqual(body.HostConfig.UTSMode, "host");
    assert.equal(body.HostConfig.SecurityOpt.includes("no-new-privileges:true"), true);
    assert.match(body.HostConfig.Tmpfs["/tmp"], /noexec/);
    assert.match(body.HostConfig.Tmpfs["/tmp"], /nosuid/);
    assert.match(body.HostConfig.Tmpfs["/tmp"], /nodev/);

    const expectedNetworkNames = phase.networkIds.map(
      (networkId) => receipt.resources.networks[networkId].engineName,
    );
    assert.equal(body.NetworkDisabled, expectedNetworkNames.length === 0);
    assert.equal(body.HostConfig.NetworkMode, expectedNetworkNames[0] ?? "none");
    assert.deepEqual(
      body.NetworkingConfig.EndpointsConfig,
      Object.fromEntries(expectedNetworkNames.map((name) => [name, { Aliases: [] }])),
    );

    assert.equal(env.HOME, "/tmp");
    assert.equal(env.LANG, "C.UTF-8");
    assert.equal(env.NODE_ENV, "production");
    assert.equal(
      env.PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64,
      Buffer.from(canonicalFixtureJson(authority)).toString("base64url"),
    );
    assert.equal(
      env.PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256,
      fixtureSha256(canonicalFixtureJson(authority)),
    );

    const claimedKeys = [
      "PLATFORM_CLAIMED_JOB_BASE64",
      "PLATFORM_CLAIMED_JOB_FILE_NAME",
      "PLATFORM_CLAIMED_JOB_ID",
      "PLATFORM_CLAIMED_JOB_OPERATION",
      "PLATFORM_CLAIMED_JOB_SHA256",
      "PLATFORM_CLAIMED_JOB_SOURCE_ID",
    ];
    if (snapshot) {
      const immutableBytes = Buffer.from(snapshot.bytes);
      sourceBytes.fill(0x78);
      assert.equal(env.PLATFORM_CLAIMED_JOB_BASE64, immutableBytes.toString("base64url"));
      assert.equal(env.PLATFORM_CLAIMED_JOB_FILE_NAME, snapshot.jobFileName);
      assert.equal(env.PLATFORM_CLAIMED_JOB_ID, snapshot.jobId);
      assert.equal(env.PLATFORM_CLAIMED_JOB_OPERATION, snapshot.jobOperation);
      assert.equal(env.PLATFORM_CLAIMED_JOB_SHA256, snapshot.jobSha256);
      assert.equal(env.PLATFORM_CLAIMED_JOB_SOURCE_ID, snapshot.sourceId);
    } else {
      for (const key of claimedKeys) assert.equal(Object.hasOwn(env, key), false, `${phaseId}/${key}`);
    }

    const serialized = canonicalFixtureJson(body);
    assert.doesNotMatch(serialized, /(?:^|[/:])docker\.sock(?:$|["/:])/);
    assert.doesNotMatch(serialized, /DOCKER_HOST/);
    assert.doesNotMatch(serialized, /jobs\.queue|\/run\/platform\/backup-jobs/);
    assert.doesNotMatch(serialized, /\/run\/secrets\/docker_action_/);
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
  }
});

test("workerCreateBody never collapses operation phases into an action-wide authority union", () => {
  const receipt = buildRawActiveReceiptV2();
  const trusted = {
    intent: { intentId: "intent.release-v2" },
    receipt,
    receiptDigest: fixtureSha256(canonicalFixtureJson(receipt)),
  };
  const backupCase = phaseActionCases().find(({ phaseId }) => phaseId === "job.backup.capture");
  const restoreCase = phaseActionCases().find(({ phaseId }) => phaseId === "job.restore.verify");
  const backupBody = broker.workerCreateBody({
    action: backupCase.action,
    phaseId: backupCase.phaseId,
    trusted,
    claimedJobSnapshot: backupCase.snapshot,
  });
  const restoreBody = broker.workerCreateBody({
    action: restoreCase.action,
    phaseId: restoreCase.phaseId,
    trusted,
    claimedJobSnapshot: restoreCase.snapshot,
  });
  const backupSerialized = canonicalFixtureJson(backupBody);
  const restoreSerialized = canonicalFixtureJson(restoreBody);

  assert.doesNotMatch(backupSerialized, /manifest-verification|restore-scratch|restore\.verify|platform_egress/);
  assert.doesNotMatch(restoreSerialized, /manifest-signing|project-sources|project-state|platform_db_admin|platform_storage/);
  assert.equal(backupBody.Labels["com.platform.docker-phase"], "job.backup.capture");
  assert.equal(restoreBody.Labels["com.platform.docker-phase"], "job.restore.verify");
  assert.notEqual(backupBody.Image, restoreBody.Image);

  const capture = broker.workerCreateBody({
    action: "restore.drill.full",
    phaseId: "restore.capture",
    trusted,
  });
  const verify = broker.workerCreateBody({
    action: "restore.drill.full",
    phaseId: "restore.verify",
    trusted,
  });
  assert.deepEqual(capture.Cmd, ["backup-catalog"]);
  assert.deepEqual(verify.Cmd, ["restore-drill-full"]);
  assert.notEqual(
    capture.Labels["com.platform.docker-phase-sha256"],
    verify.Labels["com.platform.docker-phase-sha256"],
  );
});

test("worker source is socketless while its fixed subprocess adapter remains testable", () => {
  const source = fs.readFileSync(workerPath, "utf8");
  assert.doesNotMatch(source, /from\s+["']node:(?:net|http|https|tls|dgram|dns)["']/);
  assert.doesNotMatch(source, /require\(["'](?:net|http|https|tls|dgram|dns)["']\)/);
  assert.doesNotMatch(source, /docker\.sock|DOCKER_HOST|\/containers\/(?:create|[^"']*\/start)|\/images\/create/);
});

test("real manifest and sidecar files are bound by digest, key ID and domain-separated HMAC", (t) => {
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

test("worker result normalization is bounded and recursively excludes detail arrays", () => {
  const normalizeWorkerResult = requireWorkerFunction("normalizeWorkerResult");
  assert.equal(
    Number.isSafeInteger(worker.MAX_WORKER_STDOUT_BYTES),
    true,
    "docker-action-worker must export an integer MAX_WORKER_STDOUT_BYTES",
  );
  assert.ok(worker.MAX_WORKER_STDOUT_BYTES >= 512 && worker.MAX_WORKER_STDOUT_BYTES <= 4096);

  const summary = boundedWorkerSummary("backup-prune-plan");
  const normalized = normalizeWorkerResult("backup-prune-plan", summary);
  assert.deepEqual(normalized, summary);
  assert.ok(Buffer.byteLength(JSON.stringify(normalized)) <= worker.MAX_WORKER_STDOUT_BYTES);

  for (const candidate of [
    { ...summary, retainedManifestIds: ["manifest-retained"] },
    { ...summary, details: { artifactPaths: ["postgres/worker-test.dump"] } },
    { ...summary, artifacts: [{ path: "postgres/worker-test.dump" }] },
    { ...summary, artifactSetSha256: "not-a-digest" },
    { ...summary, evidenceSha256: "a".repeat(worker.MAX_WORKER_STDOUT_BYTES + 1) },
  ]) {
    assert.throws(
      () => normalizeWorkerResult("backup-prune-plan", candidate),
      /unsupported|array|detail|field|schema|digest|sha256|oversized|length/i,
    );
  }
});

test("prune state requires a sealed plan, quarantine barrier and exact committed digest", () => {
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

test("restore state enforces prepare, restore, verify, barrier and reverse cleanup", () => {
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

test("offsite state binds idempotency and preserves remote-unknown ambiguity", () => {
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

function phaseActionCases() {
  const backupSnapshot = {
    bytes: Buffer.from(BACKUP_JOB_BYTES),
    jobFileName: `${BACKUP_JOB_ID}.json`,
    jobId: BACKUP_JOB_ID,
    jobOperation: "backup",
    jobSha256: BACKUP_JOB_SHA256,
    sourceId: "jobs.running",
  };
  const restoreSnapshot = {
    bytes: Buffer.from(RESTORE_JOB_BYTES),
    jobFileName: `${RESTORE_JOB_ID}.json`,
    jobId: RESTORE_JOB_ID,
    jobOperation: "restore-drill",
    jobSha256: RESTORE_JOB_SHA256,
    sourceId: "jobs.running",
  };
  const cases = [
    { action: "backup.catalog", phaseId: "catalog.capture" },
    { action: "backup.job.execute", phaseId: "job.backup.capture", snapshot: backupSnapshot },
    { action: "backup.job.execute", phaseId: "job.restore.verify", snapshot: restoreSnapshot },
    { action: "backup.prune.plan", phaseId: "prune.plan" },
    { action: "backup.prune.apply", phaseId: "prune.apply" },
    { action: "restore.drill.full", phaseId: "restore.capture" },
    { action: "restore.drill.full", phaseId: "restore.verify" },
    { action: "backup.offsite.sync", phaseId: "offsite.sync" },
  ];
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

function backupJobParameters(jobOperation) {
  return {
    jobFileName: `${BACKUP_JOB_ID}.json`,
    jobId: BACKUP_JOB_ID,
    jobOperation,
    jobSha256: jobOperation === "backup" ? BACKUP_JOB_SHA256 : "7".repeat(64),
  };
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

function boundedWorkerSummary(command) {
  return {
    schema: "platform.docker-worker.result/v2",
    command,
    status: "completed",
    artifactCount: 9,
    artifactSetSha256: "6".repeat(64),
    evidenceSha256: "5".repeat(64),
    mutationPerformed: command !== "backup-prune-plan",
  };
}
