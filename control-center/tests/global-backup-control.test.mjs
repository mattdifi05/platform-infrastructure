import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { normalizeBackupControl, withBackupControl } from "../backup/global-control.mjs";
import { createBackupJobDocument, parseBackupJobDocument } from "../backup/contracts.mjs";
import { admitBackupJob, claimNextBackupJob, finishBackupJob } from "../backup/queue-admission.mjs";
import { resolveAuthorizationCapability } from "../auth/route-capabilities.mjs";

const resources = [{ id: "platform-state:unit", externalId: "unit", kind: "platform-state", projectId: "platform", name: "unit" }];
const state = { available: true, enabled: false, revision: "a".repeat(64), updatedAt: "2026-10-14T12:00:00Z", requestId: "" };
const controlJob = overrides => createBackupJobDocument({ id: "backup-control-unit-job-0001", operation: "backup-control", scope: { kind: "platform", id: "platform" }, resources, requestedBy: "unit-owner", environment: "test", backupEnabled: true, expectedControlRevision: state.revision, ...overrides });

test("root readback preserves legacy enrollment, defaults clean installations off, and gates capture separately from restore enrollment", () => {
  assert.deepEqual(normalizeBackupControl(null), { available: false, enabled: false, revision: "", updatedAt: "", requestId: "" });
  assert.equal(withBackupControl({ enabled: true }).enabled, true);
  assert.equal(withBackupControl({ enabled: true }).backupControl.available, false);
  const off = withBackupControl({ enabled: false, enrollmentEnabled: true, backupControl: state, productionRestoreEnabled: true });
  assert.equal(off.enabled, false);
  assert.equal(off.enrollmentEnabled, true);
  assert.equal(off.productionRestoreEnabled, true);
  assert.deepEqual(off.backupControl, state);
  for (const invalid of [{ ...state, enabled: "false" }, { ...state, revision: "" }, { ...state, requestId: "../foreign" }, { ...state, updatedAt: "bad-date" }]) assert.throws(() => normalizeBackupControl({ backupControl: invalid }));
});

test("control jobs preserve exact booleans and root revision and never become capture manifests", () => {
  for (const enabled of [false, true]) {
    const parsed = parseBackupJobDocument(controlJob({ backupEnabled: enabled }));
    assert.equal(parsed.backupEnabled, enabled);
    assert.equal(parsed.expectedControlRevision, state.revision);
  }
  for (const invalid of [{ backupEnabled: "false" }, { expectedControlRevision: "" }, { scope: { kind: "application", id: "unit" } }, { resources: [{ id: "source:unit", externalId: "unit", kind: "source", projectId: "unit", name: "unit" }] }]) assert.throws(() => controlJob(invalid));
});

test("the existing admitted queue persists and consumes control requests through the fresh owner route without allowing capture routes to forge controls", t => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "global-backup-control-queue-"));
  t.after(() => rmSync(dir, { force: true, recursive: true }));
  const jobsDir = path.join(dir, "jobs");
  const job = controlJob();
  assert.throws(() => admitBackupJob({ jobsDir, operation: resolveAuthorizationCapability("POST", "/control/backups/run"), principal: job.requestedBy, job }), /cannot create this backup job/);
  const operation = resolveAuthorizationCapability("POST", "/control/v1/backups/control");
  assert.equal(operation.capability, "owner:fresh");
  assert.equal(resolveAuthorizationCapability("GET", "/control/backups/control").capability, "viewer");
  const accepted = admitBackupJob({ jobsDir, operation, principal: job.requestedBy, job });
  assert.equal(accepted.job.backupEnabled, true);
  const claimed = claimNextBackupJob({ jobsDir });
  assert.equal(claimed.job.expectedControlRevision, state.revision);
  assert.equal(claimed.job.operation, "backup-control");
  const finished = finishBackupJob({ jobsDir, jobId: job.id, status: "done", summary: "Root state persisted", exitCode: 0 });
  assert.equal(finished.job.backupEnabled, true);
});
