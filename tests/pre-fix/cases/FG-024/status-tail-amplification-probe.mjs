#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["control-center/state/file-store.mjs", "6b9528773dbefba6d75707394fe630eb00a59057e88a330bf5b7a98225899415"],
]);

const PREFIX_RECORDS = 50_000;
const REQUESTED_LIMIT = 1;
const TARGET_RUN_ID = "synthetic-status-run";
const sourceRoot = path.resolve(process.argv[2] ?? "");

if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: status-tail-amplification-probe.mjs /path/to/archived/source");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  const actual = sha256File(path.join(sourceRoot, relativePath));
  assert.equal(actual, expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified exact server and file-store source hashes");

const serverPath = path.join(sourceRoot, "control-center/server.mjs");
const fileStorePath = path.join(sourceRoot, "control-center/state/file-store.mjs");
const serverSource = fs.readFileSync(serverPath, "utf8");
const fileStoreSource = fs.readFileSync(fileStorePath, "utf8");

assert.match(serverSource, /const limit = clampNumber\(Number\(url\.searchParams\.get\("limit"\)/);
assert.match(serverSource, /return json\(res, \{ events: readStatusRunEvents\(limit, runId\) \}\);/);
assert.match(fileStoreSource, /const raw = readRaw\(definition\.path\);\s+const hash = digest\(raw\);/);
assert.match(fileStoreSource, /\? parseJsonLines\(raw, strict\)/);
assert.match(fileStoreSource, /for \(const record of value\) definition\.validate\?\.\(record\);/);
assert.match(fileStoreSource, /return readFileSync\(filePath, "utf8"\)/);
assert.match(fileStoreSource, /for \(const line of raw\.split\(\/\\r\?\\n\/\)\.filter\(Boolean\)\)/);

const helperSource = [
  extractFunction(serverSource, "recentStateEvents"),
  extractFunction(serverSource, "readStatusRunEvents"),
].join("\n\n");

const { createFileStateStore } = await import(pathToFileURL(fileStorePath).href);
const temporaryParent = process.env.STATUS_TAIL_POC_TMP || os.tmpdir();
const fixtureRoot = fs.mkdtempSync(path.join(temporaryParent, "status-tail-fixture-"));
const fixturePath = path.join(fixtureRoot, "status-run-events.jsonl");

let completed = false;
try {
  const tailRecords = Array.from({ length: 4 }, (_, index) => ({
    runId: TARGET_RUN_ID,
    sequence: index + 1,
    type: index === 3 ? "run-completed" : "check-completed",
    detail: "synthetic-tail-record",
  }));
  const tailText = `${tailRecords.map((record) => JSON.stringify(record)).join("\n")}\n`;
  fs.writeFileSync(fixturePath, tailText, { encoding: "utf8", mode: 0o600 });

  let validatedRecords = 0;
  const controlState = createFileStateStore({
    datasets: {
      statusRunEvents: {
        kind: "jsonl",
        path: fixturePath,
        defaultValue: [],
        validate(record) {
          assert.equal(typeof record, "object");
          assert.ok(record !== null && !Array.isArray(record));
          validatedRecords += 1;
        },
      },
    },
  });

  const { readStatusRunEvents } = vm.runInNewContext(
    `${helperSource}\n({ readStatusRunEvents });`,
    { controlState },
    { filename: "archived-status-event-helpers.mjs" },
  );

  function measure(label) {
    validatedRecords = 0;
    const beforeHeap = process.memoryUsage().heapUsed;
    const beforeCpu = process.resourceUsage();
    const startedAt = performance.now();
    const events = readStatusRunEvents(REQUESTED_LIMIT, TARGET_RUN_ID);
    const wallMs = performance.now() - startedAt;
    const afterCpu = process.resourceUsage();
    const afterHeap = process.memoryUsage().heapUsed;
    const cpuMs = (
      afterCpu.userCPUTime - beforeCpu.userCPUTime
      + afterCpu.systemCPUTime - beforeCpu.systemCPUTime
    ) / 1000;
    const measurement = {
      label,
      inputBytes: fs.statSync(fixturePath).size,
      validatedRecords,
      returnedRecords: events.length,
      returnedSequence: events[0]?.sequence,
      wallMs,
      cpuMs,
      heapDeltaBytes: afterHeap - beforeHeap,
    };
    console.log(
      `[${label}] input_bytes=${measurement.inputBytes} parsed_and_validated_records=${measurement.validatedRecords}`
      + ` requested_limit=${REQUESTED_LIMIT} returned_records=${measurement.returnedRecords}`
      + ` wall_ms=${measurement.wallMs.toFixed(3)} cpu_ms=${measurement.cpuMs.toFixed(3)}`
      + ` heap_delta_bytes=${measurement.heapDeltaBytes}`,
    );
    return measurement;
  }

  const baseline = measure("BASELINE");
  assert.equal(baseline.validatedRecords, tailRecords.length);
  assert.equal(baseline.returnedRecords, REQUESTED_LIMIT);
  assert.equal(baseline.returnedSequence, tailRecords.at(-1).sequence);

  prependSyntheticHistory(fixturePath, tailText, PREFIX_RECORDS);
  const amplified = measure("OVERSIZED_HISTORY");
  const totalRecords = PREFIX_RECORDS + tailRecords.length;

  assert.ok(amplified.inputBytes > 16 * 1024 * 1024, "fixture should exceed 16 MiB");
  assert.equal(amplified.validatedRecords, totalRecords);
  assert.equal(amplified.returnedRecords, REQUESTED_LIMIT);
  assert.equal(amplified.returnedSequence, tailRecords.at(-1).sequence);
  assert.equal(amplified.validatedRecords / amplified.returnedRecords, totalRecords);
  assert.ok(amplified.inputBytes > baseline.inputBytes * 10_000);

  console.log(
    `[ORDER] full_file_bytes_hashed=${amplified.inputBytes} all_records_parsed_before_slice=${amplified.validatedRecords}`
    + ` output_records=${amplified.returnedRecords} work_to_output_ratio=${totalRecords}:1`,
  );
  console.log("[+] finding reproduced with synthetic data; no HTTP, listener, socket, network, container, service state, or secret was used");
  completed = true;
} finally {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
}

assert.equal(completed, true);
assert.equal(fs.existsSync(fixtureRoot), false);
console.log("[+] temporary fixture removed");

function prependSyntheticHistory(filePath, tailText, count) {
  const fd = fs.openSync(filePath, "w", 0o600);
  const payload = "x".repeat(384);
  const batchSize = 500;
  try {
    for (let start = 0; start < count; start += batchSize) {
      const end = Math.min(start + batchSize, count);
      let chunk = "";
      for (let index = start; index < end; index += 1) {
        chunk += `${JSON.stringify({
          runId: `synthetic-old-run-${String(index).padStart(5, "0")}`,
          sequence: index + 1,
          type: "check-completed",
          detail: payload,
        })}\n`;
      }
      fs.writeSync(fd, chunk, undefined, "utf8");
    }
    fs.writeSync(fd, tailText, undefined, "utf8");
  } finally {
    fs.closeSync(fd);
  }
}

function extractFunction(source, name) {
  const pattern = new RegExp(`function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\}`);
  const match = source.match(pattern);
  assert.ok(match, `missing ${name} in archived server source`);
  return match[0];
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}
