import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { createFileStateStore } from "./file-store.mjs";
import { applyStateImport, exportStateSnapshot, planStateImport } from "./migration.mjs";

test("state migration exports privately, plans safely, applies with rollback and restores", () => {
  const root = mkdtempSync(path.join(tmpdir(), "control-state-migration-"));
  try {
    const source = storeAt(path.join(root, "source"));
    source.write("projects", { projects: { alpha: { enabled: true } } });
    source.append("events", { id: "event-1", status: "passed" });
    const snapshotPath = path.join(root, "snapshot.json");
    const exported = exportStateSnapshot(source, snapshotPath);
    assert.equal(exported.datasetCount, 2);
    assert.equal(statSync(snapshotPath).mode & 0o777, 0o600);

    const target = storeAt(path.join(root, "target"));
    target.write("projects", { projects: { previous: { enabled: false } } });
    const plan = planStateImport(target, snapshotPath);
    assert.equal(plan.status, "planned");
    assert.equal(plan.changedCount, 2);
    assert.deepEqual(target.read("projects", { strict: true }).value, { projects: { previous: { enabled: false } } });

    const rollbackPath = path.join(root, "rollback.json");
    assert.throws(() => applyStateImport(target, snapshotPath, { rollbackPath }), /explicit confirmation/);
    const applied = applyStateImport(target, snapshotPath, { confirm: "IMPORT-CONTROL-CENTER-STATE", rollbackPath });
    assert.equal(applied.status, "applied");
    assert.equal(statSync(rollbackPath).mode & 0o777, 0o600);
    assert.deepEqual(target.read("projects", { strict: true }).value, source.read("projects", { strict: true }).value);

    const restoreSnapshot = JSON.parse(readFileSync(rollbackPath, "utf8"));
    const restorePath = path.join(root, "restore.json");
    writeFileSync(restorePath, `${JSON.stringify(restoreSnapshot)}\n`, { mode: 0o600 });
    applyStateImport(target, restorePath, {
      confirm: "IMPORT-CONTROL-CENTER-STATE",
      rollbackPath: path.join(root, "post-apply-rollback.json"),
    });
    assert.deepEqual(target.read("projects", { strict: true }).value, { projects: { previous: { enabled: false } } });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function storeAt(root) {
  return createFileStateStore({
    datasets: {
      projects: { path: path.join(root, "projects.json"), defaultValue: { projects: {} } },
      events: { path: path.join(root, "events.jsonl"), kind: "jsonl", defaultValue: [] },
    },
  });
}
