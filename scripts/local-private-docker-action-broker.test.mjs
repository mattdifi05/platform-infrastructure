import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createBackupJobDocument } from "../control-center/backup/contracts.mjs";
import { canonicalJson, sha256 } from "./docker-action-contract.mjs";
import { readClaimedBackupJob } from "./docker-action-client.mjs";
import {
  acquireOperation,
  admitGeneration,
  consumeReplay,
  createLocalPrivateBackupBroker,
  runFixedOperation,
  validateRcloneTokenRefresh,
} from "./local-private-docker-action-broker.mjs";

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

test("LOCAL_PRIVATE rclone refresh permits only the platform-onedrive OAuth token value", () => {
  const before = Buffer.from(rcloneConfig(token("a".repeat(32), "b".repeat(32))));
  const after = Buffer.from(rcloneConfig(token(
    "c".repeat(32),
    "d".repeat(32),
    "2026-09-01T13:00:00.123456789Z",
  )));
  assert.deepEqual(validateRcloneTokenRefresh(before, after), after);

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
    assert.deepEqual(receipt.request, { action: "backup.catalog", parameters: {} });
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
  writePrivate(infraOps, `import fs from "node:fs";\nfs.appendFileSync(${JSON.stringify(capture)}, process.argv.slice(2).join(" ") + "\\n");\n`);
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
      signal: new AbortController().signal,
      stateDir: root,
      trusted: {},
    });
    assert.equal(backupResult.status, "completed");
    assert.match(fs.readFileSync(capture, "utf8"), /^execute-backup-job --jobFile /);

    fs.rmSync(capture, { force: true });
    const restoreParameters = await readClaimedBackupJob("restore-job-0123456789abcdef.json", policy);
    await assert.rejects(
      runFixedOperation("backup.job.execute", restoreParameters, {
        infraOps,
        jobsRoot,
        signal: new AbortController().signal,
        stateDir: root,
        trusted: {},
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
  operation: process.argv[2],
  repository: process.env.RESTIC_REPOSITORY,
  writable: process.env.RCLONE_CONFIG_WRITABLE,
}));
`);
  const trusted = {
    offsiteFiles: { rcloneConfig: configFile, resticPassword: passwordFile },
    receipt: {
      resources: {
        offsite: {
          repository: "rclone:platform-onedrive:platform-infrastructure/restic",
          resticImageId: `sha256:${"3".repeat(64)}`,
        },
      },
    },
  };
  try {
    const result = await runFixedOperation("backup.offsite.sync", {}, {
      infraOps,
      jobsRoot: path.join(root, "jobs"),
      signal: new AbortController().signal,
      stateDir,
      trusted,
    });
    assert.equal(result.status, "completed");
    assert.equal(fs.readFileSync(configFile, "utf8"), refreshed);
    const observed = JSON.parse(fs.readFileSync(capture, "utf8"));
    assert.deepEqual(observed, {
      operation: "offsite-backup-restic",
      repository: "rclone:platform-onedrive:platform-infrastructure/restic",
      writable: "1",
    });
    assert.notEqual(path.resolve(configFile), path.resolve(path.join(stateDir, "rclone-refresh", "rclone.conf")));
    assert.deepEqual(fs.readdirSync(path.join(stateDir, "rclone-refresh")), []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
