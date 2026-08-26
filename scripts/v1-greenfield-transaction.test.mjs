#!/usr/bin/env node
// V1 GREENFIELD TRANSACTION STATE MACHINE tests: drives the pure-Python
// orchestrator through child_process against temp journals only.  The fake
// step executor makes the delegation contract observable without Docker,
// SSH, network, or any real greenfield mutation.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const script = path.join(import.meta.dirname, "v1-greenfield-transaction.py");
const python = "python3";

const ENV_JOURNAL = "PLATFORM_GREENFIELD_TRANSACTION_JOURNAL";
const ENV_EXECUTOR = "PLATFORM_GREENFIELD_STEP_EXECUTOR";
const ENV_COMMIT = "PLATFORM_RUNTIME_CANDIDATE_COMMIT";
const ENV_TREE = "PLATFORM_RUNTIME_CANDIDATE_TREE";
const ENV_FULL_RUN = "PLATFORM_GREENFIELD_ALLOW_FULL_RUN";
const ENV_EXECUTOR_CONFIG = "PLATFORM_TEST_GREENFIELD_EXECUTOR_CONFIG";
const OWN_ENV_KEYS = [
  ENV_JOURNAL,
  ENV_EXECUTOR,
  ENV_COMMIT,
  ENV_TREE,
  ENV_FULL_RUN,
  ENV_EXECUTOR_CONFIG,
];

const RECEIPT_SCHEMA = "platform.v1-greenfield-transaction.receipt/v1";
const GENESIS = "0".repeat(64);
const ALL_STATES = [
  "PREPARE",
  "BACKUP_PRE",
  "BUILD",
  "CREATE_GREENFIELD_RESOURCES",
  "RESTORE",
  "VERIFY",
  "START_ISOLATED",
  "FUNCTIONAL_VERIFY",
  "READY_FOR_FINAL_SYNC",
  "QUIESCE_WRITERS",
  "FINAL_CAPTURE",
  "FINAL_RESTORE",
  "VERIFY_DELTA",
  "POST",
  "CUTOVER",
  "OBSERVE",
  "SEAL",
  "GO",
];
const COMMIT_A = "a".repeat(40);
const TREE_A = "b".repeat(40);
const COMMIT_B = "c".repeat(40);
const TREE_B = "d".repeat(40);

function stableCanonical(value) {
  if (Array.isArray(value)) return `[${value.map(stableCanonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableCanonical(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function fileContentDigest(pathname) {
  const bytes = fs.readFileSync(pathname);
  return crypto.createHash("sha256").update(bytes.subarray(0, bytes.length - 1)).digest("hex");
}

const pythonProbe = spawnSync(python, ["-c", "print('ok')"], { encoding: "utf8" });
const pythonReady = pythonProbe.status === 0;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-greenfield-tx-"));
  t.after(() => {
    try {
      const pidFile = path.join(root, "executor.pid");
      if (fs.existsSync(pidFile)) {
        process.kill(Number(fs.readFileSync(pidFile, "utf8")), "SIGKILL");
      }
    } catch {}
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 10 });
  });
  const journalDir = path.join(root, "transaction");
  const journal = path.join(journalDir, "journal.jsonl");
  const executorPath = path.join(root, "step-executor.cjs");
  const executorBody = `#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { raw += chunk; });
process.stdin.on("end", () => {
  const request = JSON.parse(raw);
  const configPath = process.env[${JSON.stringify(ENV_EXECUTOR_CONFIG)}];
  const config = configPath ? JSON.parse(fs.readFileSync(configPath, "utf8")) : {};
  if (config.pidFile) {
    try { fs.writeFileSync(config.pidFile, String(process.pid)); } catch {}
  }
  const failStates = config.failStates || {};
  if (Object.prototype.hasOwnProperty.call(failStates, request.state)) {
    process.stderr.write("injected failure for " + request.state + "\\n");
    process.exit(failStates[request.state]);
  }
  const sleepStates = config.sleepStates || [];
  if (sleepStates.includes(request.state)) {
    setTimeout(() => process.exit(0), 120000);
    return;
  }
  process.stdout.write(JSON.stringify({ outputs: {
    note: request.state + "-ok",
    observedProject: String(request.context.project),
    observedAttempt: String(request.context.attempt),
    observedCommand: String(request.context.command),
  } }) + "\\n");
});
`;
  fs.writeFileSync(executorPath, executorBody, { mode: 0o755 });
  fs.chmodSync(executorPath, 0o755);
  const configPath = path.join(root, "executor-config.json");
  fs.writeFileSync(configPath, JSON.stringify({}));
  return { root, journalDir, journal, executorPath, configPath };
}

function writeConfig(fixture_, config) {
  fs.writeFileSync(fixture_.configPath, JSON.stringify(config));
}

function baseEnvironment() {
  const environment = { ...process.env };
  for (const key of OWN_ENV_KEYS) delete environment[key];
  return environment;
}

function transactionEnvironment(fixture_, extra = {}) {
  return {
    ...baseEnvironment(),
    [ENV_JOURNAL]: fixture_.journal,
    [ENV_COMMIT]: COMMIT_A,
    [ENV_TREE]: TREE_A,
    [ENV_EXECUTOR]: fixture_.executorPath,
    [ENV_EXECUTOR_CONFIG]: fixture_.configPath,
    ...extra,
  };
}

function runTransaction(fixture_, arguments_, extraEnvironment = {}) {
  return spawnSync(python, [script, ...arguments_], {
    encoding: "utf8",
    env: transactionEnvironment(fixture_, extraEnvironment),
    timeout: 120000,
  });
}

function runWithoutExecutor(fixture_, arguments_) {
  const environment = transactionEnvironment(fixture_);
  delete environment[ENV_EXECUTOR];
  delete environment[ENV_EXECUTOR_CONFIG];
  return spawnSync(python, [script, ...arguments_], {
    encoding: "utf8",
    env: environment,
    timeout: 120000,
  });
}

function journalRecords(journalPath) {
  return fs
    .readFileSync(journalPath, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line));
}

function readJson(pathname) {
  return JSON.parse(fs.readFileSync(pathname, "utf8"));
}

function statusOf(fixture_) {
  const result = runTransaction(fixture_, ["status"]);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function receiptPath(fixture_, state) {
  return path.join(fixture_.journalDir, `${state}-receipt.json`);
}

function assertReceiptShape(fixture_, state, { attempt = null } = {}) {
  const receipt = readJson(receiptPath(fixture_, state));
  assert.equal(receipt.schema, RECEIPT_SCHEMA, state);
  assert.equal(receipt.state, state, state);
  assert.equal(receipt.executor, "delegated", state);
  assert.match(receipt.runId, /^[0-9a-f]{32}$/, state);
  assert.match(receipt.startedUtc, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, state);
  assert.match(receipt.finishedUtc, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, state);
  assert.equal(receipt.authority.candidateCommit, COMMIT_A, state);
  assert.equal(receipt.authority.candidateTree, TREE_A, state);
  assert.equal(receipt.outputs.observedProject, "platform_infra_greenfield", state);
  if (attempt !== null) assert.equal(receipt.outputs.attempt, String(attempt), state);
  return receipt;
}

function assertVerified(fixture_) {
  const result = runTransaction(fixture_, ["verify-journal"]);
  assert.equal(result.status, 0, result.stderr);
  const verdict = JSON.parse(result.stdout);
  assert.equal(verdict.ok, true);
  return verdict;
}

async function waitForJournalRecord(journalPath, predicate, label) {
  for (let round = 0; round < 240; round += 1) {
    try {
      const records = journalRecords(journalPath);
      if (records.some(predicate)) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timed out waiting for journal record: ${label}`);
}

if (!pythonReady) {
  console.log(
    "SKIP: python3 is not available on PATH; v1-greenfield-transaction tests cannot run.",
  );
  test(
    "python3 availability for v1-greenfield-transaction",
    { skip: "python3 is missing" },
    () => {},
  );
} else {
  test("happy path delegates through READY_FOR_FINAL_SYNC with a verifiable hash chain", (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, [
      "run",
      "--from",
      "PREPARE",
      "--stop-after",
      "READY_FOR_FINAL_SYNC",
    ]);
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(result.stdout);
    assert.equal(summary.stopAfter, "READY_FOR_FINAL_SYNC");
    assert.equal(summary.pointOfNoReturnCrossed, false);

    result = runTransaction(fx, ["status"]);
    assert.equal(result.status, 0, result.stderr);
    const status = JSON.parse(result.stdout);
    assert.equal(status.exists, true);
    assert.deepEqual(status.receivedStates, ALL_STATES.slice(0, 9));
    assert.equal(status.receivedCount, 9);
    assert.equal(status.pointOfNoReturnCrossed, false);
    assert.equal(status.sealed, false);
    assert.equal(status.dangling, null);
    assert.equal(status.project, "platform_infra_greenfield");
    assert.equal(status.authority.topology, "PARALLEL");
    assert.equal(status.authority.candidateCommit, COMMIT_A);
    assert.equal(status.authority.candidateTree, TREE_A);

    for (const state of ALL_STATES.slice(0, 9)) {
      assertReceiptShape(fx, state, { attempt: 1 });
    }

    const records = journalRecords(fx.journal);
    assert.equal(records.length, 18);
    assert.equal(records[0].prevRecordSha256, GENESIS);
    for (let index = 0; index < 9; index += 1) {
      const entered = records[index * 2];
      const receipted = records[index * 2 + 1];
      assert.equal(entered.state, ALL_STATES[index]);
      assert.equal(entered.status, "ENTERED");
      assert.equal(entered.receiptSha256, null);
      assert.equal(receipted.state, ALL_STATES[index]);
      assert.equal(receipted.status, "RECEIPTED");
      assert.match(receipted.receiptSha256, /^[a-f0-9]{64}$/);
      if (index > 0) {
        assert.equal(entered.prevRecordSha256, sha256Hex(stableCanonical(records[index * 2 - 1])));
      }
    }
    assertVerified(fx);
  });

  test("default stop-after stays safely at FUNCTIONAL_VERIFY before any PONR risk", (t) => {
    const fx = fixture(t);
    const result = runTransaction(fx, ["run"]);
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(result.stdout);
    assert.equal(summary.stopAfter, "FUNCTIONAL_VERIFY");
    assert.equal(summary.executed.length, 8);
    const status = statusOf(fx);
    assert.equal(status.receivedCount, 8);
    assert.equal(status.pointOfNoReturnCrossed, false);
    assertVerified(fx);
  });

  test("post-PONR rollback exits 86 with cutover evidence and reconcile exits 89 sealed", (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, ["run", "--stop-after", "READY_FOR_FINAL_SYNC"]);
    assert.equal(result.status, 0, result.stderr);
    result = runTransaction(fx, ["run", "--stop-after", "GO"], { [ENV_FULL_RUN]: "1" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).sealed, true);

    result = runTransaction(fx, ["rollback"]);
    assert.equal(result.status, 86, result.stderr);
    assert.match(result.stderr, /point of no return/i);
    assert.match(result.stderr, /cutoverReceiptSha256=([a-f0-9]{64})/);
    assert.match(result.stderr, /reconcile/);

    result = runTransaction(fx, ["run"]);
    assert.equal(result.status, 89, result.stderr);
    assert.match(result.stderr, /sealed/i);
    result = runTransaction(fx, ["reconcile"]);
    assert.equal(result.status, 89, result.stderr);

    const records = journalRecords(fx.journal);
    const last = records[records.length - 1];
    assert.equal(last.state, "JOURNAL_SEALED");
    assert.equal(last.status, "SEALED");
    assert.ok(readJson(receiptPath(fx, "GO")));
    assertVerified(fx);
  });

  test("pre-PONR rollback succeeds, marks ROLLED_BACK, and blocks forward runs with 85", (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, ["run", "--stop-after", "RESTORE"]);
    assert.equal(result.status, 0, result.stderr);

    result = runTransaction(fx, ["rollback"]);
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(result.stdout);
    assert.equal(summary.rolledBack, true);
    assert.deepEqual(summary.completedStates, ALL_STATES.slice(0, 5));

    const rollbackReceipt = readJson(receiptPath(fx, "ROLLBACK"));
    assert.equal(rollbackReceipt.schema, RECEIPT_SCHEMA);
    assert.equal(rollbackReceipt.state, "ROLLBACK");
    assert.equal(rollbackReceipt.executor, "delegated");
    assert.equal(
      rollbackReceipt.outputs.completedStates,
      ALL_STATES.slice(0, 5).join(","),
    );

    const records = journalRecords(fx.journal);
    const last = records[records.length - 1];
    assert.equal(last.state, "ROLLBACK");
    assert.equal(last.status, "ROLLED_BACK");
    assert.equal(last.receiptSha256, fileContentDigest(receiptPath(fx, "ROLLBACK")));
    assertVerified(fx);

    result = runTransaction(fx, ["run"]);
    assert.equal(result.status, 85, result.stderr);
    assert.match(result.stderr, /ROLLED_BACK/);
    result = runTransaction(fx, ["rollback"]);
    assert.equal(result.status, 85, result.stderr);

    const status = statusOf(fx);
    assert.equal(status.terminalStatus, "ROLLED_BACK");
    assert.equal(status.rolledBack, true);
  });

  test("a hard-crash ENTERED funnels through reconcile with an incremented attempt", async (t) => {
    const fx = fixture(t);
    writeConfig(fx, { sleepStates: ["FINAL_CAPTURE"] });

    const child = spawn(python, [script, "run", "--stop-after", "FINAL_CAPTURE"], {
      env: transactionEnvironment(fx),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let crashStderr = "";
    child.stderr.on("data", (chunk) => {
      crashStderr += chunk;
    });
    await waitForJournalRecord(
      fx.journal,
      (record) => record.state === "FINAL_CAPTURE" && record.status === "ENTERED",
      "FINAL_CAPTURE ENTERED",
    );
    child.kill("SIGKILL");
    const exit = await new Promise((resolve) => {
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    assert.equal(exit.signal, "SIGKILL", crashStderr);
    try {
      process.kill(Number(fs.readFileSync(path.join(fx.root, "executor.pid"), "utf8")), "SIGKILL");
    } catch {}

    const records = journalRecords(fx.journal);
    assert.equal(records[records.length - 1].state, "FINAL_CAPTURE");
    assert.equal(records[records.length - 1].status, "ENTERED");
    assert.equal(fs.existsSync(receiptPath(fx, "FINAL_CAPTURE")), false);

    let result = runTransaction(fx, ["run", "--stop-after", "FINAL_CAPTURE"]);
    assert.equal(result.status, 87, result.stderr);
    assert.match(result.stderr, /FINAL_CAPTURE/);
    assert.match(result.stderr, /reconcile/);
    assert.equal(journalRecords(fx.journal).length, records.length);

    writeConfig(fx, {});
    result = runTransaction(fx, ["reconcile", "--stop-after", "FINAL_CAPTURE"]);
    assert.equal(result.status, 0, result.stderr);
    assertReceiptShape(fx, "FINAL_CAPTURE", { attempt: 2 });
    const status = statusOf(fx);
    assert.equal(status.receivedCount, 11);
    assert.equal(status.dangling, null);

    result = runTransaction(fx, ["run", "--stop-after", "VERIFY_DELTA"]);
    assert.equal(result.status, 0, result.stderr);
    assertVerified(fx);
  });

  test("a crashed CUTOVER recovers only forward via reconcile and never backward", (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, ["run", "--stop-after", "POST"]);
    assert.equal(result.status, 0, result.stderr);

    writeConfig(fx, { failStates: { CUTOVER: 1 } });
    result = runTransaction(fx, ["run", "--stop-after", "GO"], { [ENV_FULL_RUN]: "1" });
    assert.equal(result.status, 78, result.stderr);
    assert.match(result.stderr, /CUTOVER/);
    let status = statusOf(fx);
    assert.equal(status.pointOfNoReturnCrossed, false);
    assert.deepEqual(status.dangling, { state: "CUTOVER", kind: "FAILED" });
    const failedRecords = journalRecords(fx.journal).filter(
      (record) => record.state === "CUTOVER" && record.status === "FAILED",
    );
    assert.equal(failedRecords.length, 1);

    result = runTransaction(fx, ["run", "--stop-after", "GO"], { [ENV_FULL_RUN]: "1" });
    assert.equal(result.status, 87, `non-idempotent CUTOVER retry must require reconcile: ${result.stderr}`);
    assert.match(result.stderr, /CUTOVER/);
    assert.match(result.stderr, /reconcile/);

    result = runTransaction(fx, ["reconcile"]);
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /point of no return/i);

    writeConfig(fx, {});
    result = runTransaction(fx, ["reconcile"], { [ENV_FULL_RUN]: "1" });
    assert.equal(result.status, 0, result.stderr);
    assertReceiptShape(fx, "CUTOVER", { attempt: 2 });

    status = statusOf(fx);
    assert.equal(status.sealed, true);
    assert.equal(status.pointOfNoReturnCrossed, true);
    assert.equal(status.receivedCount, 18);

    result = runTransaction(fx, ["rollback"]);
    assert.equal(result.status, 86, result.stderr);
    assertVerified(fx);
  });

  test("resuming with different candidate authority is refused as authority drift (88)", (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, ["run", "--stop-after", "BUILD"]);
    assert.equal(result.status, 0, result.stderr);

    result = runTransaction(fx, ["run", "--stop-after", "BUILD"], {
      [ENV_COMMIT]: COMMIT_B,
      [ENV_TREE]: TREE_B,
    });
    assert.equal(result.status, 88, result.stderr);
    assert.match(result.stderr, /authority drift/i);
    assert.ok(result.stderr.includes(COMMIT_B));

    result = runTransaction(fx, ["rollback"], {
      [ENV_COMMIT]: COMMIT_B,
      [ENV_TREE]: TREE_B,
    });
    assert.equal(result.status, 88, result.stderr);

    assertVerified(fx);
    const status = statusOf(fx);
    assert.equal(status.authority.candidateCommit, COMMIT_A);
  });

  test("tampered middle journal records fail verification with exit 79 everywhere", (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, ["run", "--stop-after", "VERIFY"]);
    assert.equal(result.status, 0, result.stderr);

    const lines = fs.readFileSync(fx.journal, "utf8").split("\n");
    assert.ok(lines[4].includes(`"seq":5`));
    const tampered = lines[4].replace(`"seq":5`, `"seq":6`);
    assert.notEqual(tampered, lines[4]);
    fs.writeFileSync(fx.journal, lines.map((line, index) => (index === 4 ? tampered : line)).join("\n"));

    result = runTransaction(fx, ["verify-journal"]);
    assert.equal(result.status, 79, result.stderr);
    assert.match(result.stderr, /chain|broken/i);
    result = runTransaction(fx, ["status"]);
    assert.equal(result.status, 79, result.stderr);
    result = runTransaction(fx, ["run"]);
    assert.equal(result.status, 79, result.stderr);
    result = runTransaction(fx, ["rollback"]);
    assert.equal(result.status, 79, result.stderr);
  });

  test("crossing the point of no return requires explicit PLATFORM_GREENFIELD_ALLOW_FULL_RUN=1", (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, ["run", "--stop-after", "GO"]);
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /point of no return/i);
    assert.match(result.stderr, /PLATFORM_GREENFIELD_ALLOW_FULL_RUN/);
    assert.equal(fs.existsSync(fx.journal), false);

    result = runTransaction(fx, ["run", "--stop-after", "CUTOVER"]);
    assert.equal(result.status, 64, result.stderr);
    assert.equal(fs.existsSync(fx.journal), false);

    result = runTransaction(fx, ["run", "--stop-after", "POST"]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(statusOf(fx).receivedCount, 14);

    result = runTransaction(fx, ["run", "--stop-after", "GO"], { [ENV_FULL_RUN]: "yes" });
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /exactly "1"/);

    result = runTransaction(fx, ["run", "--stop-after", "GO"], { [ENV_FULL_RUN]: "1" });
    assert.equal(result.status, 0, result.stderr);
    const status = statusOf(fx);
    assert.equal(status.sealed, true);
    assert.equal(status.receivedCount, 18);
    assertVerified(fx);
  });

  test("missing step executor fails closed with exit 78 before any journal mutation", (t) => {
    const fx = fixture(t);
    let result = runWithoutExecutor(fx, ["run"]);
    assert.equal(result.status, 78, result.stderr);
    assert.match(result.stderr, /fail-closed|executor/i);
    assert.equal(fs.existsSync(fx.journal), false);

    result = runWithoutExecutor(fx, ["rollback"]);
    assert.equal(result.status, 85, `empty journal has nothing to roll back: ${result.stderr}`);
    assert.match(result.stderr, /rollback incapable/);

    result = runTransaction(fx, ["status"]);
    assert.equal(result.status, 0, result.stderr);
    const status = JSON.parse(result.stdout);
    assert.equal(status.exists, false);
    assert.equal(status.receivedCount, 0);
    assert.equal(status.chainHead, GENESIS);

    result = runTransaction(fx, ["verify-journal"]);
    assert.equal(result.status, 79, result.stderr);
    assert.match(result.stderr, /does not exist/);
  });

  test("usage errors exit 64 for unknown commands and malformed state arguments", (t) => {
    const fx = fixture(t);
    for (const arguments_ of [
      [],
      ["frobnicate"],
      ["run", "--stop-after", "NOPE"],
      ["run", "--from", "GO"],
      ["run", "--from", "POST", "--stop-after", "BUILD"],
      ["run", "--wat"],
      ["status", "extra"],
      ["verify-journal", "--deep"],
    ]) {
      const result = runTransaction(fx, arguments_);
      assert.equal(result.status, 64, `${arguments_.join(" ")}: ${result.stderr}`);
      assert.match(result.stderr, /usage/i, arguments_.join(" "));
    }
    assert.equal(fs.existsSync(fx.journal), false);
  });

  test("journal tail truncation and record reordering fail verification via the anchor", async (t) => {
    const fx = fixture(t);
    let result = runTransaction(fx, [
      "run", "--from", "PREPARE", "--stop-after", "VERIFY",
    ]);
    assert.equal(result.status, 0, result.stderr);

    const original = fs.readFileSync(fx.journal, "utf8");
    const anchorPath = path.join(fx.journalDir, "chain-head.json");

    // Truncation: drop the last record; the prefix alone revalidates, so only
    // the out-of-band anchor exposes the loss.
    const lines = original.split("\n").filter((line) => line !== "");
    fs.writeFileSync(fx.journal, `${lines.slice(0, -1).join("\n")}\n`);
    result = runTransaction(fx, ["verify-journal"]);
    assert.equal(result.status, 79, result.stderr);
    assert.match(result.stderr, /chain anchor|diverges/);

    // Reordering: swap two adjacent records; seq/prev chain plus the anchor
    // must both refuse it.
    writeConfig(fx, {});
    const reordered = [...lines];
    [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
    fs.writeFileSync(fx.journal, `${reordered.join("\n")}\n`);
    result = runTransaction(fx, ["verify-journal"]);
    assert.equal(result.status, 79, result.stderr);

    // Missing anchor entirely is corrupt even when records look consistent.
    fs.writeFileSync(fx.journal, original);
    fs.rmSync(anchorPath, { force: true });
    result = runTransaction(fx, ["verify-journal"]);
    assert.equal(result.status, 79, result.stderr);
    assert.match(result.stderr, /anchor is missing/);
  });

  test("a virgin journal cannot start a cutover-capable run mid-chain", (t) => {
    const fx = fixture(t);
    const result = runTransaction(fx, [
      "run", "--from", "FINAL_CAPTURE", "--stop-after", "GO",
    ], { [ENV_FULL_RUN]: "1" });
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /virgin journal cannot start a cutover-capable run/);
    assert.equal(fs.existsSync(fx.journal), false);

    // The same mid-chain start stays legal when the horizon stays pre-PONR.
    const safe = runTransaction(fx, [
      "run", "--from", "RESTORE", "--stop-after", "FUNCTIONAL_VERIFY",
    ]);
    assert.equal(safe.status, 0, safe.stderr);
  });

  test("executor outputs carrying credential-shaped material are refused", (t) => {
    const fx = fixture(t);
    const leakyExecutor = path.join(fx.root, "leaky-executor.mjs");
    fs.writeFileSync(leakyExecutor, `#!/usr/bin/env node
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { raw += chunk; });
process.stdin.on("end", () => {
  process.stdout.write(JSON.stringify({ outputs: { note: "-----BEGIN RSA PRIVATE KEY-----" } }) + "\\n");
});
`, { mode: 0o755 });
    const environment = transactionEnvironment(fx);
    environment[ENV_EXECUTOR] = leakyExecutor;
    const result = spawnSync(python, [script, "run", "--stop-after", "PREPARE"], {
      encoding: "utf8",
      timeout: 60_000,
      env: environment,
    });
    assert.equal(result.status, 78, result.stderr);
    assert.match(result.stderr, /secret materialization/);
    // The ENTERED→FAILED attempt pair for PREPARE is durable, but no receipt
    // may exist and the failed attempt must block any blind `run` retry.
    const status = JSON.parse(runTransaction(fx, ["status"]).stdout);
    assert.equal(status.receivedCount, 0);
    assert.deepEqual(status.dangling, { state: "PREPARE", kind: "FAILED" });
  });
}
