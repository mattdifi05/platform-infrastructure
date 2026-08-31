import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  backupDocumentDigest,
  createBackupJobDocument,
  createBackupManifestDocument,
} from "../control-center/backup/contracts.mjs";
import {
  buildUnsignedRequest,
  canonicalJson,
  normalizeActionResponse,
  sha256,
  signActionRequest,
} from "./docker-action-contract.mjs";
import { readClaimedBackupJob } from "./docker-action-client.mjs";
import {
  acquireOperation,
  admitGeneration,
  consumeReplay,
  createLocalPrivateBackupBroker,
  reconcileCompletedOffsiteOperation,
  reconcileInterruptedOffsiteRestoreProof,
  runFixedOperation,
  validateRcloneTokenRefresh,
} from "./local-private-docker-action-broker.mjs";
import {
  validateRestoreContainerInspection,
  verifyRestoredOffsiteSet,
} from "./local-private-offsite-restore-drill.mjs";

function temporaryDirectory(prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(directory, 0o700);
  return directory;
}

function writePrivate(file, contents) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(file), 0o700);
  fs.writeFileSync(file, contents, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function token(access, refresh, expiry = "2026-09-01T12:00:00.123456789Z") {
  return {
    access_token: access,
    token_type: "Bearer",
    refresh_token: refresh,
    expiry,
  };
}

function rcloneConfig(value, type = "onedrive") {
  return `[platform-onedrive]\ntype = ${type}\ntoken = ${JSON.stringify(value)}\ndrive_id = fixed-drive-id\ndrive_type = business\n`;
}

function executionTrust(overrides = {}) {
  return {
    receiptDigest: "1".repeat(64),
    renderBinding: { egressNetwork: "platform_infra_greenfield_platform_egress" },
    receipt: {
      generation: 4,
      releaseCommitSha1: "2".repeat(40),
      treeSha256: "3".repeat(64),
      resources: {
        offsite: {
          repository: "rclone:platform-onedrive:platform-infrastructure/restic",
          resticImageId: `sha256:${"4".repeat(64)}`,
          restore: {
            manifestDigest: "5".repeat(64),
            manifestId: "manifest-scheduled-platform-20260831-154830-867cad",
            receiptFileName: "offsite-backup-20260831160759-cba697.json",
            receiptFileSha256: "6".repeat(64),
            snapshotId: "7".repeat(64),
          },
        },
      },
    },
    ...overrides,
  };
}

function restoreReconciliationTrust(capabilityKey, { rcloneConfig = "/run/platform/critical/rclone/rclone.conf" } = {}) {
  const document = { schema: "test.local-private-admission/v1", value: "restore-proof" };
  const receiptDigest = "1".repeat(64);
  const combinedRenderSha256 = "2".repeat(64);
  return {
    capabilityFiles: { "restore.offsite.proof": "/run/secrets/docker_action_restore_offsite_proof" },
    document,
    intent: {
      allowedActions: ["restore.offsite.proof"],
      generation: 8,
      intentId: "local-private-backup-dell-restore-proof",
    },
    offsiteFiles: {
      rcloneConfig,
      resticPassword: "/run/platform/critical/restic_password.txt",
    },
    receiptDigest,
    renderBinding: { egressNetwork: "platform_infra_greenfield_platform_egress" },
    receipt: {
      combinedRenderSha256,
      generation: 8,
      releaseCommitSha1: "3".repeat(40),
      treeSha256: "4".repeat(64),
      resources: {
        capabilityFiles: {
          "capability.restore.offsite.proof": {
            brokerPath: "/run/secrets/docker_action_restore_offsite_proof",
            sha256: sha256(capabilityKey),
          },
        },
        offsite: {
          repository: "rclone:platform-onedrive:platform-infrastructure/restic",
          resticImageId: `sha256:${"5".repeat(64)}`,
          restore: {
            manifestDigest: "6".repeat(64),
            manifestId: "manifest-scheduled-platform-20260831-154830-867cad",
            receiptFileName: "offsite-backup-20260831160759-cba697.json",
            receiptFileSha256: "7".repeat(64),
            snapshotId: "8".repeat(64),
          },
        },
      },
    },
  };
}

test("LOCAL_PRIVATE rclone refresh permits only the platform-onedrive OAuth token value", () => {
  const before = Buffer.from(rcloneConfig(token("a".repeat(32), "b".repeat(32))));
  const after = Buffer.from(rcloneConfig(token(
    "c".repeat(32),
    "d".repeat(32),
    "2026-09-01T13:00:00.123456789Z",
  )));
  assert.deepEqual(validateRcloneTokenRefresh(before, after), after);

  const withOptionalLifetime = token(
    "c".repeat(32),
    "d".repeat(32),
    "2026-09-01T13:00:00.123456789Z",
  );
  withOptionalLifetime.expires_in = 3599;
  const refreshedWithOptionalLifetime = Buffer.from(rcloneConfig(withOptionalLifetime));
  assert.deepEqual(
    validateRcloneTokenRefresh(before, refreshedWithOptionalLifetime),
    refreshedWithOptionalLifetime,
  );
  assert.deepEqual(
    validateRcloneTokenRefresh(refreshedWithOptionalLifetime, after),
    after,
    "expires_in is optional refresh metadata and may be removed by rclone",
  );

  assert.throws(
    () => validateRcloneTokenRefresh(before, Buffer.from(rcloneConfig(token("c".repeat(32), "d".repeat(32)), "s3"))),
    /outside the OAuth token/,
  );
  const changedTokenType = token("c".repeat(32), "d".repeat(32));
  changedTokenType.token_type = "Attacker";
  assert.throws(
    () => validateRcloneTokenRefresh(before, Buffer.from(rcloneConfig(changedTokenType))),
    /immutable OAuth field/,
  );
  const widened = { ...token("c".repeat(32), "d".repeat(32)), endpoint: "https://attacker.invalid" };
  assert.throws(
    () => validateRcloneTokenRefresh(before, Buffer.from(rcloneConfig(widened))),
    /token schema/,
  );
  for (const expiresIn of ["3599", -1, 1.5]) {
    const invalidLifetime = { ...token("c".repeat(32), "d".repeat(32)), expires_in: expiresIn };
    assert.throws(
      () => validateRcloneTokenRefresh(before, Buffer.from(rcloneConfig(invalidLifetime))),
      /expires_in is invalid/,
    );
  }
});

test("LOCAL_PRIVATE admission generations, replay ledger and terminal receipts fail closed", () => {
  const root = temporaryDirectory("local-private-broker-state-");
  try {
    const firstDocument = { payload: "first" };
    const first = {
      document: firstDocument,
      intent: { generation: 1 },
      receipt: { previousAdmissionSha256: "0".repeat(64) },
    };
    admitGeneration(root, first);
    admitGeneration(root, first);

    const second = {
      document: { payload: "second" },
      intent: { generation: 2 },
      receipt: { previousAdmissionSha256: sha256(canonicalJson(firstDocument)) },
    };
    admitGeneration(root, second);
    assert.throws(() => admitGeneration(root, first), /rollback, gap or substitution/);

    const replayRequest = { requestId: "11111111-1111-4111-8111-111111111111", nonce: "n".repeat(43) };
    consumeReplay(root, replayRequest, Date.now());
    assert.throws(
      () => consumeReplay(root, replayRequest, Date.now()),
      (error) => error?.errorCode === "REQUEST_REPLAY_REJECTED",
    );

    const operationRequest = {
      action: "backup.catalog",
      nonce: "m".repeat(43),
      requestId: "22222222-2222-4222-8222-222222222222",
    };
    const operation = acquireOperation(root, operationRequest);
    operation.recordTerminal({ status: "completed", statusCode: 200 });
    operation.release();
    assert.equal(fs.existsSync(path.join(root, "active-operation.json")), false);
    const receipts = fs.readdirSync(path.join(root, "terminal"));
    assert.equal(receipts.length, 1);
    const receipt = JSON.parse(fs.readFileSync(path.join(root, "terminal", receipts[0]), "utf8"));
    assert.equal(receipt.schema, "platform.local-private-broker-terminal/v1");
    assert.equal(receipt.requestId, operationRequest.requestId);
    assert.deepEqual(receipt.request, operationRequest);
    assert.equal(receipt.response.status, "completed");

    const unresolved = acquireOperation(root, {
      action: "backup.catalog",
      nonce: "q".repeat(43),
      requestId: "33333333-3333-4333-8333-333333333333",
    });
    assert.throws(() => unresolved.release(), /no durable terminal receipt/);
    assert.equal(fs.existsSync(path.join(root, "active-operation.json")), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE UDS returns an async terminal response after the client half-closes its request side", async () => {
  const root = temporaryDirectory("local-private-broker-uds-");
  const socketPath = path.join(root, "broker.sock");
  let terminalRecorded = false;
  let released = false;
  const response = { schema: "test.response/v1", status: "completed" };
  const server = createLocalPrivateBackupBroker({
    requestHandler: async (frame) => {
      assert.equal(frame.toString("utf8"), canonicalJson({ action: "backup.catalog" }));
      await new Promise((resolve) => setTimeout(resolve, 25));
      return {
        body: response,
        operation: {
          recordTerminal(value) {
            assert.deepEqual(value, response);
            terminalRecorded = true;
          },
          release() {
            assert.equal(terminalRecorded, true);
            released = true;
          },
        },
      };
    },
  });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });
    const received = await new Promise((resolve, reject) => {
      const socket = net.createConnection({ path: socketPath });
      const chunks = [];
      socket.once("connect", () => socket.end(`${canonicalJson({ action: "backup.catalog" })}\n`));
      socket.on("data", (chunk) => chunks.push(chunk));
      socket.once("error", reject);
      socket.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    assert.equal(received, `${canonicalJson(response)}\n`);
    assert.equal(terminalRecorded, true);
    assert.equal(released, true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE broker dispatches backup jobs but rejects a valid restore job before spawning infra-ops", async () => {
  const root = temporaryDirectory("local-private-broker-job-");
  const jobsRoot = path.join(root, "jobs");
  const running = path.join(jobsRoot, "running");
  const capture = path.join(root, "spawned.txt");
  const infraOps = path.join(root, "fake-infra-ops.mjs");
  const now = "2026-08-31T12:00:00.000Z";
  writePrivate(infraOps, `import fs from "node:fs";\nfs.appendFileSync(${JSON.stringify(capture)}, JSON.stringify({ args: process.argv.slice(2), action: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_ACTION, authority: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_AUTHORITY_SHA256, command: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_COMMAND, jobSha256: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_JOB_SHA256, schema: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA }) + "\\n");\n`);
  try {
    for (const [id, operation] of [
      ["backup-job-0123456789abcdef", "backup"],
      ["restore-job-0123456789abcdef", "restore-drill"],
    ]) {
      const queued = createBackupJobDocument({
        id,
        operation,
        scope: { kind: "platform", id: "platform" },
        resources: [{
          externalId: "control-state",
          kind: "platform-state",
          name: "control-state",
        }],
        requestedBy: "owner@example.test",
        environment: "production",
        createdAt: now,
        ...(operation === "restore-drill" ? { sourceManifestPath: "manifests/isolated.json" } : {}),
      });
      const document = {
        ...queued,
        status: "running",
        updatedAt: now,
        startedAt: now,
        resultSummary: "Job claimed within the scheduler concurrency budget.",
        logPath: `/var/log/platform/manual-backup-${id}.log`,
      };
      writePrivate(path.join(running, `${id}.json`), `${JSON.stringify(document, null, 2)}\n`);
    }

    const policy = {
      expectedGid: process.getgid(),
      expectedUid: process.getuid(),
      maximumBytes: 128 * 1024,
      trustedRoot: running,
    };
    const backupParameters = await readClaimedBackupJob("backup-job-0123456789abcdef.json", policy);
    const backupResult = await runFixedOperation("backup.job.execute", backupParameters, {
      infraOps,
      jobsRoot,
      requestSha256: "5".repeat(64),
      signal: new AbortController().signal,
      stateDir: root,
      trusted: executionTrust(),
    });
    assert.equal(backupResult.status, "completed");
    const spawned = JSON.parse(fs.readFileSync(capture, "utf8"));
    assert.equal(spawned.args[0], "execute-backup-job");
    assert.equal(spawned.action, "backup.job.execute");
    assert.equal(spawned.authority, "1".repeat(64));
    assert.equal(spawned.command, "execute-backup-job");
    assert.equal(spawned.jobSha256, backupParameters.jobSha256);
    assert.equal(spawned.schema, "platform.local-private-backup-invocation/v1");

    fs.rmSync(capture, { force: true });
    const restoreParameters = await readClaimedBackupJob("restore-job-0123456789abcdef.json", policy);
    await assert.rejects(
      runFixedOperation("backup.job.execute", restoreParameters, {
        infraOps,
        jobsRoot,
        requestSha256: "6".repeat(64),
        signal: new AbortController().signal,
        stateDir: root,
        trusted: executionTrust(),
      }),
      (error) => error?.errorCode === "RESTORE_JOB_NOT_ALLOWED",
    );
    assert.equal(fs.existsSync(capture), false, "restore rejection must happen before infra-ops spawn");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE offsite dispatch uses copy-on-write and atomically persists only a valid token refresh", async () => {
  const root = temporaryDirectory("local-private-broker-offsite-");
  const stateDir = path.join(root, "state");
  const configFile = path.join(root, "critical", "rclone", "rclone.conf");
  const passwordFile = path.join(root, "critical", "restic_password.txt");
  const capture = path.join(root, "offsite.json");
  const infraOps = path.join(root, "fake-offsite.mjs");
  const original = rcloneConfig(token("a".repeat(32), "b".repeat(32)));
  const refreshed = rcloneConfig(token("c".repeat(32), "d".repeat(32), "2026-09-01T13:00:00.123456789Z"));
  writePrivate(configFile, original);
  writePrivate(passwordFile, `${"p".repeat(64)}\n`);
  writePrivate(infraOps, `
import fs from "node:fs";
fs.writeFileSync(process.env.RCLONE_CONFIG, ${JSON.stringify(refreshed)}, { mode: 0o600 });
fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({
  action: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_ACTION,
  authority: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_AUTHORITY_SHA256,
  egress: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_EGRESS_NETWORK,
  operation: process.argv[2],
  repository: process.env.RESTIC_REPOSITORY,
  schema: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA,
  writable: process.env.RCLONE_CONFIG_WRITABLE,
}));
`);
  const trusted = executionTrust({
    offsiteFiles: { rcloneConfig: configFile, resticPassword: passwordFile },
    receipt: {
      generation: 4,
      releaseCommitSha1: "2".repeat(40),
      treeSha256: "3".repeat(64),
      resources: {
        offsite: {
          repository: "rclone:platform-onedrive:platform-infrastructure/restic",
          resticImageId: `sha256:${"3".repeat(64)}`,
          restore: executionTrust().receipt.resources.offsite.restore,
        },
      },
    },
  });
  try {
    const result = await runFixedOperation("backup.offsite.sync", {}, {
      infraOps,
      jobsRoot: path.join(root, "jobs"),
      requestSha256: "7".repeat(64),
      signal: new AbortController().signal,
      stateDir,
      trusted,
    });
    assert.equal(result.status, "completed");
    assert.equal(fs.readFileSync(configFile, "utf8"), refreshed);
    const observed = JSON.parse(fs.readFileSync(capture, "utf8"));
    assert.deepEqual(observed, {
      action: "backup.offsite.sync",
      authority: "1".repeat(64),
      egress: "platform_infra_greenfield_platform_egress",
      operation: "offsite-backup-restic",
      repository: "rclone:platform-onedrive:platform-infrastructure/restic",
      schema: "platform.local-private-backup-invocation/v1",
      writable: "1",
    });
    assert.notEqual(path.resolve(configFile), path.resolve(path.join(stateDir, "rclone-refresh", "rclone.conf")));
    assert.deepEqual(fs.readdirSync(path.join(stateDir, "rclone-refresh")), []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE off-site restore proof dispatch is fixed, read-only and returns one honest phase", async () => {
  const root = temporaryDirectory("local-private-broker-restore-");
  const capture = path.join(root, "restore-environment.json");
  const restoreDrill = path.join(root, "fake-restore.mjs");
  const stateDir = path.join(root, "state");
  const configFile = path.join(root, "critical", "rclone", "rclone.conf");
  const trusted = executionTrust({
    offsiteFiles: {
      rcloneConfig: configFile,
      resticPassword: "/run/platform/critical/restic_password.txt",
    },
  });
  const restore = trusted.receipt.resources.offsite.restore;
  writePrivate(configFile, rcloneConfig(token("a".repeat(32), "b".repeat(32))));
  writePrivate(restoreDrill, `
import fs from "node:fs";
fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({
  action: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_ACTION,
  command: process.env.PLATFORM_LOCAL_PRIVATE_BACKUP_COMMAND,
  config: process.env.RCLONE_CONFIG,
  manifestDigest: process.env.LOCAL_PRIVATE_RESTORE_MANIFEST_DIGEST,
  manifestId: process.env.LOCAL_PRIVATE_RESTORE_MANIFEST_ID,
  receiptFile: process.env.LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_NAME,
  receiptSha256: process.env.LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_SHA256,
  snapshotId: process.env.LOCAL_PRIVATE_RESTORE_SNAPSHOT_ID,
  writable: process.env.RCLONE_CONFIG_WRITABLE ?? null,
}));
const summary = {
  artifactCount: 20,
  artifactSignaturesVerified: true,
  exactSetVerified: true,
  manifestDigest: process.env.LOCAL_PRIVATE_RESTORE_MANIFEST_DIGEST,
  manifestId: process.env.LOCAL_PRIVATE_RESTORE_MANIFEST_ID,
  manifestSignatureVerified: true,
  receiptFile: process.env.LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_NAME,
  receiptFileSha256: process.env.LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_SHA256,
  resourceCount: 20,
  restorePayloadRemoved: true,
  restoredBytes: 1024,
  schema: "platform.offsite-restore-proof/v1",
  snapshotId: process.env.LOCAL_PRIVATE_RESTORE_SNAPSHOT_ID,
  status: "passed",
};
process.stdout.write(JSON.stringify(summary));
`);
  try {
    const result = await runFixedOperation("restore.offsite.proof", {}, {
      infraOps: path.join(root, "must-not-run.mjs"),
      jobsRoot: path.join(root, "jobs"),
      requestSha256: "8".repeat(64),
      restoreProof: restoreDrill,
      signal: new AbortController().signal,
      stateDir,
      trusted,
    });
    assert.equal(result.status, "completed");
    assert.deepEqual(result.phases.map((phase) => [phase.phaseId, phase.outputSchema]), [
      ["offsite.restore", "platform.offsite-restore-proof/v1"],
    ]);
    assert.equal(result.phases[0].output.exactSetVerified, true);
    assert.equal(result.phases[0].output.artifactSignaturesVerified, true);
    assert.equal(result.phases[0].output.restorePayloadRemoved, true);
    const observed = JSON.parse(fs.readFileSync(capture, "utf8"));
    assert.deepEqual(observed, {
      action: "restore.offsite.proof",
      command: "restore-offsite-proof",
      config: path.join(stateDir, "rclone-refresh", "rclone.conf"),
      manifestDigest: restore.manifestDigest,
      manifestId: restore.manifestId,
      receiptFile: restore.receiptFileName,
      receiptSha256: restore.receiptFileSha256,
      snapshotId: restore.snapshotId,
      writable: "1",
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE off-site restore proof verifies the exact set and every artifact HMAC", () => {
  const root = temporaryDirectory("local-private-restore-proof-");
  const restoreRoot = path.join(root, "restore");
  const signingKeyFile = path.join(root, "backup_signing_keys.txt");
  const signingSecret = "s".repeat(64);
  const manifestId = "manifest-scheduled-platform-20260831-154830-867cad";
  const snapshotId = "7".repeat(64);
  const artifactPath = "applications/stexor/stexor-source-20260831-154905.tar.gz";
  const artifactFile = path.join(restoreRoot, "backups", artifactPath);
  const artifactBytes = Buffer.from("verified isolated off-site restore artifact\n");
  const artifactSha256 = sha256(artifactBytes);
  const resource = {
    externalId: "stexor",
    kind: "source",
    name: "stexor",
    projectId: "stexor",
    sourceDirectory: "stexor",
  };
  const job = createBackupJobDocument({
    id: "scheduled-platform-20260831-154830-867cad",
    operation: "backup",
    scope: { kind: "platform", id: "platform" },
    resources: [resource],
    requestedBy: "scheduler",
    environment: "production",
    createdAt: "2026-08-31T15:48:30.000Z",
  });
  const unsigned = createBackupManifestDocument({
    id: manifestId,
    job,
    artifacts: [{
      id: "artifact-stexor",
      path: artifactPath,
      resourceId: "source:stexor",
      sha256: artifactSha256,
      signatureKeyId: "test-key",
      sizeBytes: artifactBytes.length,
    }],
    createdAt: "2026-08-31T15:49:06.486Z",
  });
  const manifestDigest = backupDocumentDigest(unsigned);
  const manifest = {
    ...unsigned,
    signature: {
      algorithm: "HMAC-SHA256",
      digest: manifestDigest,
      keyId: "test-key",
      value: crypto.createHmac("sha256", signingSecret)
        .update(`platform-backup-manifest-v1\n${manifestId}\n${manifestDigest}\n`)
        .digest("base64url"),
    },
  };
  const manifestPath = `/backups/manifests/${manifestId}.json`;
  const sidecar = {
    algorithm: "HMAC-SHA256",
    artifact: path.basename(artifactFile),
    keyId: "test-key",
    sha256: artifactSha256,
    signature: crypto.createHmac("sha256", signingSecret)
      .update(`platform-postgres-backup-v1\n${path.basename(artifactFile)}\n${artifactSha256}\n`)
      .digest("base64url"),
    signedAt: "2026-08-31T15:49:05.000Z",
    version: 1,
  };
  const snapshotPaths = [manifestPath, `/backups/${artifactPath}`, `/backups/${artifactPath}.sha256`, `/backups/${artifactPath}.sig.json`];
  const snapshotTags = [
    `platform-manifest-id=${manifestId}`,
    `platform-manifest-digest=${manifestDigest}`,
  ];
  const priorReceipt = {
    artifactCount: 1,
    credentialsExposed: false,
    manifestDigest,
    manifestId,
    repositoryOffsite: true,
    resourceIds: ["source:stexor"],
    schema: "platform.offsite-backup-receipt/v1",
    snapshotId,
    status: "passed",
  };
  const expected = { manifestDigest, manifestId, snapshotId };
  try {
    writePrivate(signingKeyFile, `test-key=${signingSecret}\n`);
    writePrivate(path.join(restoreRoot, manifestPath), `${JSON.stringify(manifest)}\n`);
    writePrivate(artifactFile, artifactBytes);
    writePrivate(`${artifactFile}.sha256`, `${artifactSha256}  ${path.basename(artifactFile)}\n`);
    writePrivate(`${artifactFile}.sig.json`, `${JSON.stringify(sidecar)}\n`);
    const verified = verifyRestoredOffsiteSet({
      backupSigningKeyFile: signingKeyFile,
      expected,
      priorReceipt,
      restoreRoot,
      snapshot: { id: snapshotId, paths: snapshotPaths, tags: snapshotTags },
    });
    assert.equal(verified.artifactCount, 1);
    assert.equal(verified.resourceCount, 1);
    writePrivate(`${artifactFile}.sig.json`, `${JSON.stringify({ ...sidecar, signature: "A".repeat(43) })}\n`);
    assert.throws(() => verifyRestoredOffsiteSet({
      backupSigningKeyFile: signingKeyFile,
      expected,
      priorReceipt,
      restoreRoot,
      snapshot: { id: snapshotId, paths: snapshotPaths, tags: snapshotTags },
    }), /artifact HMAC verification failed/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE reconciliation commits one proven offsite refresh without rerunning the remote operation", () => {
  const root = temporaryDirectory("local-private-broker-reconcile-");
  const stateDir = path.join(root, "state");
  const reportsRoot = path.join(root, "data", "reports", "offsite-backups");
  const backupsRoot = path.join(root, "data", "backups");
  const configFile = path.join(root, "critical", "rclone", "rclone.conf");
  const signingKeyFile = path.join(root, "critical", "backup_signing_keys.txt");
  const reportFileName = "offsite-backup-20260831160759-cba697.json";
  const manifestId = "manifest-scheduled-platform-20260831-154830-867cad";
  const snapshotId = "4".repeat(64);
  const admissionSha256 = "5".repeat(64);
  const capabilityKey = Buffer.from("c".repeat(64));
  const signingSecret = "s".repeat(64);
  const candidateDocument = { payload: "candidate-admission" };
  const candidateAdmissionSha256 = sha256(canonicalJson(candidateDocument));
  const activeRequest = signActionRequest({
    action: "backup.offsite.sync",
    activeReceiptSha256: admissionSha256,
    capabilityId: "backup.offsite.sync.v2",
    combinedRenderSha256: "a".repeat(64),
    expiresAt: "2026-08-31T15:52:49.398Z",
    issuedAt: "2026-08-31T15:52:19.398Z",
    nonce: "u".repeat(43),
    parameters: {},
    requestId: "34cea6a1-d78b-4f85-a7f4-bcbd6611def9",
    runtimeIntentId: "local-private-backup-generation-6",
    schema: "platform.docker-action.request/v2",
  }, capabilityKey);
  const activeRequestSha256 = sha256(canonicalJson(activeRequest));
  const active = {
    action: "backup.offsite.sync",
    admittedAt: "2026-08-31T15:52:19.398Z",
    request: activeRequest,
    requestId: activeRequest.requestId,
    requestSha256: activeRequestSha256,
    schema: "platform.local-private-broker-active-operation/v2",
    terminalFile: `terminal/${activeRequestSha256}.json`,
  };
  const original = Buffer.from(rcloneConfig(token("a".repeat(32), "b".repeat(32))));
  const refreshedToken = token("c".repeat(32), "d".repeat(32), "2026-09-01T13:00:00.123456789Z");
  refreshedToken.expires_in = 3599;
  const refreshed = Buffer.from(rcloneConfig(refreshedToken));
  try {
    writePrivate(path.join(stateDir, "active-operation.json"), `${canonicalJson(active)}\n`);
    writePrivate(path.join(stateDir, "active-admission.json"), `${canonicalJson({ admissionSha256, generation: 6 })}\n`);
    writePrivate(path.join(stateDir, "rclone-refresh", "rclone.conf"), refreshed);
    writePrivate(configFile, original);
    writePrivate(signingKeyFile, `test-key=${signingSecret}\n`);

    const resource = {
      externalId: "stexor",
      kind: "source",
      name: "stexor",
      projectId: "stexor",
      sourceDirectory: "stexor",
    };
    const job = createBackupJobDocument({
      id: "scheduled-platform-20260831-154830-867cad",
      operation: "backup",
      scope: { kind: "platform", id: "platform" },
      resources: [resource],
      requestedBy: "scheduler",
      environment: "production",
      createdAt: "2026-08-31T15:48:30.000Z",
    });
    const unsignedManifest = createBackupManifestDocument({
      id: manifestId,
      job,
      artifacts: [{
        id: "artifact-stexor",
        path: "sources/stexor.tar.zst",
        resourceId: "source:stexor",
        sha256: "9".repeat(64),
        signatureKeyId: "test-key",
        sizeBytes: 4096,
      }],
      createdAt: "2026-08-31T15:49:06.486Z",
    });
    const manifestDigest = backupDocumentDigest(unsignedManifest);
    const manifest = {
      ...unsignedManifest,
      signature: {
        algorithm: "HMAC-SHA256",
        digest: manifestDigest,
        keyId: "test-key",
        value: crypto.createHmac("sha256", signingSecret)
          .update(`platform-backup-manifest-v1\n${manifestId}\n${manifestDigest}\n`)
          .digest("base64url"),
      },
    };
    writePrivate(path.join(backupsRoot, "manifests", `${manifestId}.json`), `${JSON.stringify(manifest, null, 2)}\n`);
    const receipt = {
      artifactCount: 1,
      credentialsExposed: false,
      durationMs: 940102,
      evidenceContext: { schema: "platform.evidence-report-context/v1" },
      finishedAt: "2026-08-31T16:07:59.770Z",
      generatedAt: "2026-08-31T16:07:59.770Z",
      hostname: "platform-infrastructure",
      manifestDigest,
      manifestId,
      manifestPath: `manifests/${manifestId}.json`,
      repositoryHost: null,
      repositoryMaxBytes: 2500000000000,
      repositoryOffsite: true,
      repositorySizeBytes: 8793217059,
      repositoryType: "rclone",
      resourceIds: ["source:stexor"],
      schema: "platform.offsite-backup-receipt/v1",
      snapshotId,
      startedAt: "2026-08-31T15:52:19.668Z",
      status: "passed",
      tag: "platform-backups",
    };
    writePrivate(path.join(reportsRoot, reportFileName), `${JSON.stringify(receipt, null, 2)}\n`);

    const options = {
      backupsRoot,
      capabilityKey,
      expectedManifestDigest: manifestDigest,
      expectedOriginalRcloneSha256: sha256(original),
      expectedSnapshotId: snapshotId,
      now: Date.parse("2026-08-31T16:10:00.000Z"),
      rcloneConfigFile: configFile,
      receiptFileName: reportFileName,
      reportsRoot,
      signingKeyFile,
      stateDir,
      trusted: {
        document: candidateDocument,
        intent: { activationBundleSha256: candidateAdmissionSha256, generation: 7 },
        receipt: { previousAdmissionSha256: admissionSha256 },
      },
    };
    assert.throws(
      () => reconcileCompletedOffsiteOperation({
        ...options,
        expectedOriginalRcloneSha256: "0".repeat(64),
      }),
      /operator-confirmed pre-operation digest/,
    );
    assert.deepEqual(fs.readFileSync(configFile), original);
    assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), true);
    assert.equal(fs.existsSync(path.join(stateDir, "rclone-refresh", "rclone.conf")), true);
    assert.equal(fs.existsSync(path.join(stateDir, "terminal")), false);

    const result = reconcileCompletedOffsiteOperation(options);
    assert.equal(result.status, "reconciled");
    assert.deepEqual(fs.readFileSync(configFile), refreshed);
    assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), false);
    assert.deepEqual(
      JSON.parse(fs.readFileSync(path.join(stateDir, "active-admission.json"), "utf8")),
      { admissionSha256: candidateAdmissionSha256, generation: 7 },
    );
    assert.equal(fs.existsSync(path.join(stateDir, "rclone-refresh", "rclone.conf")), false);
    assert.equal(fs.readdirSync(path.join(stateDir, "terminal")).length, 1);
    assert.equal(fs.readdirSync(path.join(stateDir, "reconciliation")).length, 1);

    const terminalFile = path.join(stateDir, active.terminalFile);
    writePrivate(configFile, original);
    writePrivate(path.join(stateDir, "rclone-refresh", "rclone.conf"), refreshed);
    fs.rmSync(terminalFile);
    writePrivate(path.join(stateDir, "active-operation.json"), `${canonicalJson(active)}\n`);
    const resumedAfterAdmissionAdvance = reconcileCompletedOffsiteOperation(options);
    assert.equal(resumedAfterAdmissionAdvance.status, "reconciled");
    assert.deepEqual(fs.readFileSync(configFile), refreshed);
    assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), false);
    assert.equal(fs.existsSync(path.join(stateDir, "rclone-refresh", "rclone.conf")), false);
    assert.equal(fs.existsSync(terminalFile), true);

    writePrivate(path.join(stateDir, "active-operation.json"), `${canonicalJson(active)}\n`);
    const retried = reconcileCompletedOffsiteOperation(options);
    assert.equal(retried.status, "reconciled");
    assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), false);
    assert.equal(fs.readdirSync(path.join(stateDir, "terminal")).length, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE interrupted off-site restore reconciliation is authenticated, signed and idempotent", async () => {
  const root = temporaryDirectory("local-private-restore-reconcile-");
  const stateDir = path.join(root, "state");
  const capabilityKey = Buffer.from("r".repeat(64));
  const rcloneConfigFile = path.join(root, "critical", "rclone.conf");
  const trusted = restoreReconciliationTrust(capabilityKey, { rcloneConfig: rcloneConfigFile });
  const issuedAt = Date.now();
  const request = signActionRequest(buildUnsignedRequest("restore.offsite.proof", {}, trusted, {
    now: issuedAt,
    nonce: "q".repeat(43),
    requestId: "34cea6a1-d78b-4f85-a7f4-bcbd6611def9",
  }), capabilityKey);
  try {
    const originalRclone = Buffer.from(rcloneConfig(token("a".repeat(32), "b".repeat(32))));
    const refreshedRclone = Buffer.from(rcloneConfig(token(
      "c".repeat(32),
      "d".repeat(32),
      "2026-09-01T13:00:00.123456789Z",
    )));
    writePrivate(rcloneConfigFile, originalRclone);
    writePrivate(path.join(stateDir, "rclone-refresh", "rclone.conf"), refreshedRclone);
    writePrivate(path.join(stateDir, "active-admission.json"), `${canonicalJson({
      admissionSha256: sha256(canonicalJson(trusted.document)),
      generation: trusted.intent.generation,
    })}\n`);
    acquireOperation(stateDir, request);
    let cleanupCalls = 0;
    await assert.rejects(() => reconcileInterruptedOffsiteRestoreProof({
      capabilityKey,
      cleanup: async () => {
        cleanupCalls += 1;
        throw new Error("injected cleanup interruption");
      },
      dataRoot: path.join(root, "data"),
      now: issuedAt + 1_000,
      stateDir,
      trusted,
    }), /injected cleanup interruption/);
    const journalPath = path.join(stateDir, "reconciliation", `${sha256(canonicalJson(request))}.json`);
    const journalBytes = fs.readFileSync(journalPath);
    const journal = JSON.parse(journalBytes);
    assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), true);
    assert.equal(fs.existsSync(path.join(stateDir, journal.active.terminalFile)), false);

    // Simulate a crash after durable terminal write but before active-lock release.
    writePrivate(path.join(stateDir, journal.active.terminalFile), `${canonicalJson(journal.terminal)}\n`);
    const result = await reconcileInterruptedOffsiteRestoreProof({
      capabilityKey,
      cleanup: async ({ requestSha256 }) => {
        cleanupCalls += 1;
        assert.equal(requestSha256, sha256(canonicalJson(request)));
      },
      dataRoot: path.join(root, "data"),
      now: issuedAt + 2_000,
      stateDir,
      trusted,
    });
    assert.equal(result.status, "reconciled");
    assert.equal(cleanupCalls, 2);
    assert.deepEqual(fs.readFileSync(journalPath), journalBytes);
    assert.deepEqual(fs.readFileSync(rcloneConfigFile), refreshedRclone);
    assert.equal(fs.existsSync(path.join(stateDir, "rclone-refresh", "rclone.conf")), false);
    const refreshJournal = JSON.parse(fs.readFileSync(
      path.join(stateDir, "reconciliation", `${sha256(canonicalJson(request))}.rclone.json`),
      "utf8",
    ));
    assert.equal(refreshJournal.rclone.mode, "refreshed");
    assert.equal(refreshJournal.rclone.beforeSha256, sha256(originalRclone));
    assert.equal(refreshJournal.rclone.afterSha256, sha256(refreshedRclone));
    assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), false);
    const terminal = JSON.parse(fs.readFileSync(path.join(stateDir, journal.active.terminalFile), "utf8"));
    const response = normalizeActionResponse(terminal.response, request, capabilityKey);
    assert.equal(response.status, "rejected");
    assert.equal(response.statusCode, 503);
    assert.equal(response.errorCode, "OFFSITE_RESTORE_PROOF_INTERRUPTED");
    assert.deepEqual(terminal.request, request);

    // Simulate a crash after COW commit and terminal persistence, before lock unlink.
    writePrivate(path.join(stateDir, "active-operation.json"), `${canonicalJson(journal.active)}\n`);
    const resumed = await reconcileInterruptedOffsiteRestoreProof({
      capabilityKey,
      cleanup: async () => {},
      dataRoot: path.join(root, "data"),
      now: issuedAt + 3_000,
      stateDir,
      trusted,
    });
    assert.equal(resumed.status, "reconciled");
    assert.deepEqual(fs.readFileSync(rcloneConfigFile), refreshedRclone);
    assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("LOCAL_PRIVATE interrupted restore reconciliation rejects request and admission substitution before cleanup", async () => {
  const capabilityKey = Buffer.from("r".repeat(64));
  const trusted = restoreReconciliationTrust(capabilityKey);
  for (const mutation of ["mac", "admission"]) {
    const root = temporaryDirectory(`local-private-restore-reconcile-${mutation}-`);
    const stateDir = path.join(root, "state");
    const issuedAt = Date.now();
    const request = signActionRequest(buildUnsignedRequest("restore.offsite.proof", {}, trusted, {
      now: issuedAt,
      nonce: "s".repeat(43),
      requestId: "34cea6a1-d78b-4f85-a7f4-bcbd6611def9",
    }), capabilityKey);
    try {
      writePrivate(path.join(stateDir, "active-admission.json"), `${canonicalJson({
        admissionSha256: mutation === "admission" ? "0".repeat(64) : sha256(canonicalJson(trusted.document)),
        generation: trusted.intent.generation,
      })}\n`);
      acquireOperation(stateDir, request);
      if (mutation === "mac") {
        const activeFile = path.join(stateDir, "active-operation.json");
        const active = JSON.parse(fs.readFileSync(activeFile, "utf8"));
        active.request.mac = "0".repeat(64);
        active.requestSha256 = sha256(canonicalJson(active.request));
        active.terminalFile = `terminal/${active.requestSha256}.json`;
        fs.writeFileSync(activeFile, `${canonicalJson(active)}\n`, { mode: 0o600 });
      }
      let cleanupCalled = false;
      await assert.rejects(() => reconcileInterruptedOffsiteRestoreProof({
        capabilityKey,
        cleanup: async () => { cleanupCalled = true; },
        dataRoot: path.join(root, "data"),
        now: issuedAt + 1_000,
        stateDir,
        trusted,
      }), mutation === "mac" ? /request authentication failed/ : /admission differs/);
      assert.equal(cleanupCalled, false);
      assert.equal(fs.existsSync(path.join(stateDir, "active-operation.json")), true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});

test("LOCAL_PRIVATE restore helper cleanup validates complete Docker inspection identity before removal", () => {
  const trusted = executionTrust();
  const invocation = {
    action: "restore.offsite.proof",
    command: "restore-offsite-proof",
    egressNetwork: trusted.renderBinding.egressNetwork,
    receipt: trusted.receipt,
    requestSha256: "9".repeat(64),
    roots: {
      brokerStateHost: "/srv/platform/control-center/docker-action-broker",
      dataHost: "/srv/platform/control-center/data",
      secretsHost: "/srv/platform/critical",
    },
  };
  const binding = {
    id: "a".repeat(64),
    name: `gf-restic-restore-${invocation.requestSha256.slice(0, 12)}`,
    role: "restore",
  };
  const inspection = {
    Id: binding.id,
    Name: `/${binding.name}`,
    Config: {
      Cmd: ["--no-lock", "restore", trusted.receipt.resources.offsite.restore.snapshotId, "--target", "/restore"],
      Entrypoint: ["/usr/bin/restic"],
      Env: [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/tmp",
        "XDG_CACHE_HOME=/tmp/.cache",
        `RESTIC_REPOSITORY=${trusted.receipt.resources.offsite.repository}`,
        "RESTIC_PASSWORD_FILE=/restic-password/restic_password.txt",
        "RCLONE_CONFIG=/rclone-config/rclone.conf",
      ],
      Image: trusted.receipt.resources.offsite.resticImageId,
      Labels: {
        "com.platform.local-private.offsite-restore-request-sha256": invocation.requestSha256,
        "com.platform.local-private.offsite-restore-role": "restore",
      },
      User: "1000:1000",
    },
    HostConfig: {
      CapDrop: ["ALL"],
      LogConfig: { Type: "none" },
      NetworkMode: invocation.egressNetwork,
      PidsLimit: 128,
      ReadonlyRootfs: true,
      SecurityOpt: ["no-new-privileges:true"],
      Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=256m,mode=1777" },
    },
    Mounts: [
      { Destination: "/rclone-config", Mode: "", RW: true, Source: `${invocation.roots.brokerStateHost}/rclone-refresh`, Type: "bind" },
      { Destination: "/restic-password/restic_password.txt", Mode: "", RW: false, Source: `${invocation.roots.secretsHost}/restic_password.txt`, Type: "bind" },
      { Destination: "/restore", Mode: "", RW: true, Source: `${invocation.roots.dataHost}/.offsite-restore-proof/${invocation.requestSha256}`, Type: "bind" },
    ],
    NetworkSettings: { Networks: { [invocation.egressNetwork]: {} } },
  };
  assert.deepEqual(validateRestoreContainerInspection(invocation, binding, inspection), binding);
  for (const mutate of [
    (value) => { value.Config.Image = `sha256:${"b".repeat(64)}`; },
    (value) => { value.Config.Labels["com.platform.local-private.offsite-restore-role"] = "snapshots"; },
    (value) => { value.Config.User = "0:0"; },
    (value) => { value.Config.Cmd[2] = "latest"; },
    (value) => { value.HostConfig.NetworkMode = "bridge"; },
    (value) => { value.Mounts[2].Source = "/"; },
  ]) {
    const changed = structuredClone(inspection);
    mutate(changed);
    assert.throws(() => validateRestoreContainerInspection(invocation, binding, changed), /identity differs/);
  }
});
