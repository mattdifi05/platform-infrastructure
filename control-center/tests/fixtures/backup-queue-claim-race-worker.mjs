import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { claimNextBackupJob } from "../../backup/queue-admission.mjs";

const [jobsDir, logDir, readyDir, barrierPath] = process.argv.slice(2);
mkdirSync(readyDir, { recursive: true });
writeFileSync(path.join(readyDir, `${process.pid}.ready`), "ready\n", { flag: "wx" });
const waitArray = new Int32Array(new SharedArrayBuffer(4));
while (!existsSync(barrierPath)) Atomics.wait(waitArray, 0, 0, 5);

try {
  const result = claimNextBackupJob({
    jobsDir,
    logDir,
    policy: {
      maxOutstanding: 8,
      maxPerPrincipal: 8,
      principalWindowMs: 60_000,
      maxConcurrency: 1,
      lockTimeoutMs: 5000,
    },
    now: Date.parse("2026-07-21T20:00:10.000Z"),
  });
  process.stdout.write(`${JSON.stringify({ claimed: result.claimed, reason: result.reason || "", id: result.job?.id || "" })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ claimed: false, code: error.code || error.name })}\n`);
}
