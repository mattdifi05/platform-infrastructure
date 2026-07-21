import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createBackupJobDocument } from "../../backup/contracts.mjs";
import { admitBackupJob } from "../../backup/queue-admission.mjs";

const [jobsDir, readyDir, barrierPath, suffix] = process.argv.slice(2);
const principal = "owner-race@example.test";
const operation = Object.freeze({
  method: "POST",
  operationId: "backup.run",
  capability: "owner:fresh",
  canonicalPath: "/control/backups/run",
  classified: true,
  control: true,
  parameters: Object.freeze({}),
});
const job = createBackupJobDocument({
  id: `race-job-${suffix}`,
  operation: "backup",
  scope: { kind: "platform", id: "platform" },
  resources: [{
    id: "platform-state:catalog",
    externalId: "catalog",
    kind: "platform-state",
    projectId: "platform",
    name: "catalog",
  }],
  requestedBy: principal,
  environment: "test",
  createdAt: "2026-07-21T20:00:00.000Z",
});

mkdirSync(readyDir, { recursive: true });
writeFileSync(path.join(readyDir, `${process.pid}.ready`), "ready\n", { flag: "wx" });
const waitArray = new Int32Array(new SharedArrayBuffer(4));
while (!existsSync(barrierPath)) Atomics.wait(waitArray, 0, 0, 5);

try {
  const result = admitBackupJob({
    jobsDir,
    operation,
    principal,
    job,
    now: Date.parse("2026-07-21T20:00:00.000Z"),
    policy: {
      maxOutstanding: 8,
      maxPerPrincipal: 8,
      principalWindowMs: 60_000,
      maxConcurrency: 1,
      lockTimeoutMs: 5000,
    },
  });
  process.stdout.write(`${JSON.stringify({ admitted: result.admitted, id: job.id })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ admitted: false, code: error.code || error.name, id: job.id })}\n`);
}
