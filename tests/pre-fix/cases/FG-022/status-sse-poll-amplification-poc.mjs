#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

function fail(message) {
  process.stderr.write("[FAIL] " + message + "\n");
  process.exit(1);
}

function pass(message) {
  process.stdout.write("[PASS] " + message + "\n");
}

function parseArgs(argv) {
  let sourceRoot = "";
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--source-root" && argv[index + 1]) {
      sourceRoot = argv[++index];
      continue;
    }
    fail("usage: node status-sse-poll-amplification-poc.mjs --source-root PATH");
  }
  if (!sourceRoot) fail("--source-root is required");
  return path.resolve(sourceRoot);
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function extractBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, "missing source marker: " + startMarker);
  assert.ok(end > start, "missing source marker: " + endMarker);
  return source.slice(start, end).trim();
}

function buildHistory(count, runId) {
  const records = [];
  for (let sequence = 1; sequence <= count; sequence += 1) {
    records.push(JSON.stringify({
      id: "event-" + sequence,
      runId,
      sequence,
      type: "check-completed",
      checkId: "check-" + (sequence % 25),
      status: "passed",
      payload: "x".repeat(96),
    }));
  }
  return records.join("\n") + "\n";
}

function printMetric(label, metric) {
  process.stdout.write(
    "[METRIC] " + label +
      " history=" + metric.historySize +
      " clients=" + metric.clients +
      " polls=" + metric.polls +
      " store_reads=" + metric.storeReads +
      " parsed_records=" + metric.parsedRecords +
      " bytes_reprocessed=" + metric.bytesReprocessed +
      " emitted_events=" + metric.emittedEvents +
      " false_writes=" + metric.falseWrites +
      "\n",
  );
}

const sourceRoot = parseArgs(process.argv.slice(2));
const expectedHashes = new Map([
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["control-center/state/file-store.mjs", "6b9528773dbefba6d75707394fe630eb00a59057e88a330bf5b7a98225899415"],
  ["control-center/state/file-store.test.mjs", "5036e15482297f353533ad3ca9876e8c3d714a361082f97d6d406187e46bd234"],
  ["control-center/state/catalog.mjs", "206b1185cb16c87c59ddbff8bcdcd5a7bd1f64c60c8b75c0fbedba0dc334d643"],
  ["control-center/auth/oidc.mjs", "2f0c9ea5239935857caab3f233ff43cdb81a34d8ab77cfc1a7a00c2a1b7b91b1"],
  ["traefik/dynamic/middlewares.yml", "79ae033e15398379b4fec860ff658091c9518f995a533a9ee78ee5b1e9d0a11b"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
  ["compose.vps.yaml", "c8954158a542825fe276742d3b943818603c2cc764764da98fd81859de3f1415"],
]);

let temporaryRoot = "";
try {
  for (const [relativePath, expectedHash] of expectedHashes) {
    assert.equal(
      sha256(path.join(sourceRoot, relativePath)),
      expectedHash,
      relativePath + " does not match the exact pre-fix source",
    );
  }
  pass("exact pre-fix source fingerprints verified");

  const fileStoreTests = spawnSync(
    process.execPath,
    [
      "--test",
      path.join(sourceRoot, "control-center/state/file-store.test.mjs"),
    ],
    {
      cwd: sourceRoot,
      encoding: "utf8",
      env: {
        HOME: process.env.HOME || "",
        PATH: process.env.PATH || "",
        TMPDIR: process.env.TMPDIR || os.tmpdir(),
        NODE_NO_WARNINGS: "1",
      },
    },
  );
  assert.equal(
    fileStoreTests.status,
    0,
    "file-store tests failed:\n" +
      (fileStoreTests.stderr || fileStoreTests.stdout || "no output"),
  );
  assert.match(fileStoreTests.stdout, /pass 4/);
  pass("repository file-store tests pass 4/4");

  const serverPath = path.join(sourceRoot, "control-center/server.mjs");
  const fileStorePath = path.join(
    sourceRoot,
    "control-center/state/file-store.mjs",
  );
  const serverText = fs.readFileSync(serverPath, "utf8");
  const fileStoreText = fs.readFileSync(fileStorePath, "utf8");
  const catalogText = fs.readFileSync(
    path.join(sourceRoot, "control-center/state/catalog.mjs"),
    "utf8",
  );
  const authText = fs.readFileSync(
    path.join(sourceRoot, "control-center/auth/oidc.mjs"),
    "utf8",
  );
  const middlewareText = fs.readFileSync(
    path.join(sourceRoot, "traefik/dynamic/middlewares.yml"),
    "utf8",
  );
  const composeVpsText = fs.readFileSync(
    path.join(sourceRoot, "compose.vps.yaml"),
    "utf8",
  );
  const runtimeIsolationText = fs.readFileSync(
    path.join(sourceRoot, "compose.runtime-isolation.yaml"),
    "utf8",
  );

  assert.ok(
    serverText.includes(
      "route(parts, \"control\", \"status\", \"events\", \"stream\")",
    ),
  );
  assert.ok(
    serverText.includes(
      "readStatusRunEvents(2000, runId).filter",
    ),
  );
  assert.ok(
    serverText.includes(
      "setTimeout(resolve, 150)",
    ),
  );
  assert.ok(fileStoreText.includes("const raw = readRaw(definition.path);"));
  assert.ok(fileStoreText.includes("const hash = digest(raw);"));
  assert.ok(fileStoreText.includes("parseJsonLines(raw, strict)"));
  assert.ok(
    fileStoreText.includes("raw.split(/\\r?\\n/).filter(Boolean)"),
  );
  assert.ok(
    catalogText.includes(
      "statusRunEvents: jsonl(env.PROJECT_STATUS_RUN_EVENTS_FILE",
    ),
  );
  assert.ok(
    authText.includes(
      "if (mutating && ![\"owner\", \"admin\"].includes(session.role))",
    ),
  );
  const sensitivePathSource = extractBetween(
    authText,
    "function isSensitivePath",
    "function normalizeSessionRow",
  );
  assert.doesNotMatch(sensitivePathSource, /status|events|stream/);
  assert.ok(middlewareText.includes("average: 120"));
  assert.ok(middlewareText.includes("burst: 60"));
  assert.match(
    composeVpsText,
    /enterprise-portal:[\s\S]*?middlewares:[\s\S]*?enterprise-rate-limit@file/,
  );
  assert.match(
    runtimeIsolationText,
    /control-center:[\s\S]*?cpus: 1\.00[\s\S]*?mem_limit: 512m/,
  );
  pass("route, poll loop, full-file parser, viewer GET, and rate-limit controls verified");

  const readStatusSource = extractBetween(
    serverText,
    "function readStatusRunEvents",
    "async function streamStatusRunEvents",
  );
  const streamStatusSource = extractBetween(
    serverText,
    "async function streamStatusRunEvents",
    "function objectState",
  );
  const recentEventsSource = extractBetween(
    serverText,
    "function recentStateEvents",
    "function readApplicationsState",
  );
  const normalizeRunIdSource = extractBetween(
    serverText,
    "function normalizeStatusRunId",
    "function statusRunTargetLabel",
  );
  const streamHarnessSource = [
    readStatusSource,
    streamStatusSource,
    recentEventsSource,
    normalizeRunIdSource,
    "globalThis.__streamStatusRunEvents = streamStatusRunEvents;",
  ].join("\n\n");
  assert.doesNotMatch(streamStatusSource, /drain|concurrent|principal.*stream/i);
  pass("exact unexported SSE functions extracted without importing the listening server");

  const fileStoreModule = await import(pathToFileURL(fileStorePath).href);
  temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "status-sse-amplification-"),
  );
  let scenarioNumber = 0;

  async function runScenario({
    historySize,
    clients,
    polls,
    requestedRunId,
    writeReturn = true,
  }) {
    scenarioNumber += 1;
    const eventPath = path.join(
      temporaryRoot,
      "status-run-events-" + scenarioNumber + ".jsonl",
    );
    const storedRunId = "status-poc00001";
    fs.writeFileSync(eventPath, buildHistory(historySize, storedRunId), {
      mode: 0o600,
    });
    const sourceBytes = fs.statSync(eventPath).size;
    const metric = {
      historySize,
      clients,
      polls,
      storeReads: 0,
      parsedRecords: 0,
      sourceBytes,
      bytesReprocessed: 0,
      emittedEvents: 0,
      emittedBytes: 0,
      falseWrites: 0,
      endedStreams: 0,
    };
    const store = fileStoreModule.createFileStateStore({
      datasets: {
        statusRunEvents: {
          path: eventPath,
          kind: "jsonl",
          defaultValue: [],
          validate(value) {
            metric.parsedRecords += 1;
            assert.ok(value && typeof value === "object" && !Array.isArray(value));
          },
        },
      },
    });
    const controlState = {
      read(name, options) {
        metric.storeReads += 1;
        return store.read(name, options);
      },
    };

    const streams = Array.from({ length: clients }, () => {
      const clock = { value: 0 };
      let closeHandler = () => {};
      let sleepCount = 0;
      class FakeDate extends Date {
        static now() {
          return clock.value;
        }
      }
      const req = {
        once(event, callback) {
          assert.equal(event, "close");
          closeHandler = callback;
        },
      };
      const res = {
        writeHead(status, headers) {
          assert.equal(status, 200);
          assert.equal(headers["content-type"], "text/event-stream; charset=utf-8");
        },
        flushHeaders() {},
        write(chunk) {
          metric.emittedEvents += 1;
          metric.emittedBytes += Buffer.byteLength(String(chunk));
          if (!writeReturn) metric.falseWrites += 1;
          return writeReturn;
        },
        end() {
          metric.endedStreams += 1;
        },
      };
      const context = vm.createContext({
        Buffer,
        controlState,
        Date: FakeDate,
        setTimeout(resolve, delay) {
          assert.equal(delay, 150);
          sleepCount += 1;
          clock.value += delay;
          if (sleepCount >= polls) closeHandler();
          queueMicrotask(resolve);
        },
        ValidationError: class ValidationError extends Error {},
      });
      vm.runInContext(streamHarnessSource, context, {
        filename: "exact-status-sse-functions.mjs",
      });
      return context.__streamStatusRunEvents(req, res, requestedRunId);
    });

    await Promise.all(streams);
    metric.bytesReprocessed = metric.sourceBytes * metric.storeReads;
    return metric;
  }

  const baseline = await runScenario({
    historySize: 2000,
    clients: 1,
    polls: 6,
    requestedRunId: "status-never0001",
  });
  const largeHistory = await runScenario({
    historySize: 12000,
    clients: 1,
    polls: 6,
    requestedRunId: "status-never0001",
  });
  const concurrent = await runScenario({
    historySize: 12000,
    clients: 16,
    polls: 6,
    requestedRunId: "status-never0001",
  });
  const backpressure = await runScenario({
    historySize: 2000,
    clients: 1,
    polls: 2,
    requestedRunId: "status-poc00001",
    writeReturn: false,
  });

  assert.equal(baseline.storeReads, 6);
  assert.equal(baseline.parsedRecords, 2000 * 6);
  assert.equal(baseline.emittedEvents, 0);
  assert.equal(largeHistory.storeReads, 6);
  assert.equal(largeHistory.parsedRecords, 12000 * 6);
  assert.equal(largeHistory.emittedEvents, 0);
  assert.equal(concurrent.storeReads, 16 * 6);
  assert.equal(concurrent.parsedRecords, 12000 * 16 * 6);
  assert.equal(concurrent.emittedEvents, 0);
  assert.equal(
    largeHistory.parsedRecords / baseline.parsedRecords,
    6,
  );
  assert.equal(
    concurrent.parsedRecords / largeHistory.parsedRecords,
    16,
  );
  assert.equal(backpressure.storeReads, 2);
  assert.equal(backpressure.emittedEvents, 2000);
  assert.equal(backpressure.falseWrites, 2000);

  printMetric("baseline", baseline);
  printMetric("large_history", largeHistory);
  printMetric("concurrent", concurrent);
  printMetric("backpressure", backpressure);
  pass("sixfold history growth causes sixfold parsing at the same poll count");
  pass("16 concurrent SSE streams cause 16-fold full-file parsing");
  pass("a valid nonexistent run ID holds streams with zero event output");
  pass("mock response backpressure is ignored and the next full poll still runs");

  const nominalPollsPerStream = Math.floor((6 * 60 * 1000) / 150);
  const nominalParsedRecords =
    12000 * 16 * nominalPollsPerStream;
  process.stdout.write(
    "[DERIVED] nominal_six_minute_polls_per_stream=" +
      nominalPollsPerStream +
      " nominal_parsed_records=" +
      nominalParsedRecords +
      "\n",
  );
  process.stdout.write(
    "[SAFE] exact SSE functions, mock req/res, fake clock, and temporary JSONL only; no listener, socket, network, or live-state access\n",
  );
} catch (error) {
  process.stderr.write("[FAIL] " + (error.stack || error.message) + "\n");
  process.exitCode = 1;
} finally {
  if (temporaryRoot) {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
