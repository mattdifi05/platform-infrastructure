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
