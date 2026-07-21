import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createFileStateStore, StateConflictError, StateValidationError } from "./file-store.mjs";

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "control-state-store-"));
  const store = createFileStateStore({ datasets: {
    settings: { path: path.join(root, "settings.json"), defaultValue: {} },
    audit: { path: path.join(root, "audit.jsonl"), kind: "jsonl", defaultValue: [], validate: (value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("audit record required");
    } },
  } });
  return { root, store };
}

test("atomic JSON writes use private files and reject stale tokens", () => {
  const { root, store } = fixture();
  try {
    const initial = store.read("settings", { strict: true });
    const first = store.write("settings", { theme: "light" }, { expectedToken: initial.token });
    assert.equal(first.value.theme, "light");
    assert.equal(statSync(path.join(root, "settings.json")).mode & 0o777, 0o600);
    assert.throws(() => store.write("settings", { theme: "dark" }, { expectedToken: initial.token }), StateConflictError);
    assert.deepEqual(JSON.parse(readFileSync(path.join(root, "settings.json"), "utf8")), { theme: "light" });
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("JSONL append is durable and strict reads reject malformed state", () => {
  const { root, store } = fixture();
  try {
    store.append("audit", { id: "one" });
    store.append("audit", { id: "two" });
    assert.deepEqual(store.read("audit", { strict: true }).value.map((item) => item.id), ["one", "two"]);
    writeFileSync(path.join(root, "audit.jsonl"), "{broken\n");
    assert.throws(() => store.read("audit", { strict: true }), StateValidationError);
    assert.deepEqual(store.read("audit").value, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("JSONL tail applies byte and record ceilings before parsing", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "control-state-tail-"));
  const auditPath = path.join(root, "audit.jsonl");
  let validations = 0;
  const store = createFileStateStore({ datasets: {
    audit: {
      path: auditPath,
      kind: "jsonl",
      defaultValue: [],
      validate: (value) => {
        validations += 1;
        if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("audit record required");
      },
    },
  } });
  try {
    writeFileSync(auditPath, [
      "x".repeat(4096),
      "{malformed-but-not-selected}",
      JSON.stringify({ id: "one" }),
      JSON.stringify({ id: "two" }),
      JSON.stringify({ id: "three" }),
      "",
    ].join("\n"));
    const tail = store.readTail("audit", {
      strict: true,
      maxRecords: 2,
      maxBytes: 256,
      maxRecordBytes: 128,
    });
    assert.deepEqual(tail.value.map((item) => item.id), ["two", "three"]);
    assert.equal(tail.bytesRead, 256);
    assert.equal(tail.parsedRecords, 2);
    assert.equal(validations, 2);
    assert.equal(tail.truncated, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("JSONL tail rejects an oversized or malformed selected record before validation", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "control-state-tail-invalid-"));
  const auditPath = path.join(root, "audit.jsonl");
  let validations = 0;
  const store = createFileStateStore({ datasets: {
    audit: {
      path: auditPath,
      kind: "jsonl",
      defaultValue: [],
      validate: () => { validations += 1; },
    },
  } });
  try {
    writeFileSync(auditPath, `${JSON.stringify({ id: "large", value: "x".repeat(512) })}\n`);
    assert.throws(() => store.readTail("audit", {
      strict: true,
      maxRecords: 1,
      maxBytes: 1024,
      maxRecordBytes: 64,
    }), /record exceeds 64 bytes/);
    assert.equal(validations, 0);

    writeFileSync(auditPath, "{malformed}\n");
    assert.throws(() => store.readTail("audit", {
      strict: true,
      maxRecords: 1,
      maxBytes: 1024,
      maxRecordBytes: 128,
    }), StateValidationError);
    assert.equal(validations, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("retained JSONL append bounds stored records and bytes while preserving the newest events", () => {
  const { root, store } = fixture();
  try {
    for (let index = 0; index < 20; index += 1) {
      store.appendRetained("audit", { id: `event-${index}`, payload: "x".repeat(180) }, {
        maxRecords: 5,
        maxBytes: 1024,
        maxRecordBytes: 256,
      });
    }
    const records = store.read("audit", { strict: true }).value;
    assert.equal(records.length <= 5, true);
    assert.equal(records.at(-1).id, "event-19");
    assert.equal(statSync(path.join(root, "audit.jsonl")).size <= 1024, true);
    const metadata = JSON.parse(readFileSync(path.join(root, "audit.jsonl.state-meta.json"), "utf8"));
    assert.equal(metadata.recordCount, records.length);
    assert.deepEqual(metadata.retention, { maxRecords: 5, maxBytes: 1024, maxRecordBytes: 256 });
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("retained JSONL append rejects same-size drift before extending a trusted generation", () => {
  const { root, store } = fixture();
  try {
    const options = { maxRecords: 5, maxBytes: 1024, maxRecordBytes: 256 };
    store.appendRetained("audit", { id: "trusted" }, options);
    const filePath = path.join(root, "audit.jsonl");
    const raw = readFileSync(filePath, "utf8");
    writeFileSync(filePath, raw.replace("trusted", "altered"));
    assert.equal(Buffer.byteLength(readFileSync(filePath)), Buffer.byteLength(raw));
    assert.throws(() => store.appendRetained("audit", { id: "next" }, options), /changed outside the state store/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("snapshot import is plan-only by default and returns rollback evidence", () => {
  const { root, store } = fixture();
  try {
    store.write("settings", { value: "before" });
    store.append("audit", { id: "before" });
    const snapshot = store.exportSnapshot();
    store.write("settings", { value: "after" });
    const plan = store.importSnapshot(snapshot);
    assert.equal(plan.status, "planned");
    assert.equal(store.read("settings", { strict: true }).value.value, "after");
    assert.throws(() => store.importSnapshot(snapshot, { apply: true }), StateValidationError);
    const applied = store.importSnapshot(snapshot, { apply: true, confirm: "IMPORT-CONTROL-CENTER-STATE" });
    assert.equal(applied.status, "applied");
    assert.equal(applied.rollback.datasets.settings.value.value, "after");
    assert.equal(store.read("settings", { strict: true }).value.value, "before");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("tampered snapshot and duplicate dataset metadata fail closed", () => {
  const { root, store } = fixture();
  try {
    const snapshot = store.exportSnapshot();
    snapshot.datasets.settings.value = { tampered: true };
    assert.throws(() => store.planImport(snapshot), StateValidationError);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
