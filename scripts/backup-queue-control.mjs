#!/usr/bin/env node
import {
  BackupQueueAdmissionError,
  acquireBackupSchedulerLease,
  backupQueuePolicyFromEnvironment,
  claimNextBackupJob,
  finishBackupJob,
  pruneBackupQueue,
  releaseBackupSchedulerLease,
} from "../control-center/backup/queue-admission.mjs";

const [command, ...argv] = process.argv.slice(2);
const options = parseOptions(argv);
const jobsDir = requiredOption(options, "jobsDir");
const logDir = String(options.logDir || "");
const policy = backupQueuePolicyFromEnvironment(process.env);

try {
  if (command === "claim") {
    const result = claimNextBackupJob({ jobsDir, logDir, policy });
    if (result.claimed) process.stdout.write(`${result.runningPath}\n`);
  } else if (command === "finish") {
    finishBackupJob({
      jobsDir,
      logDir,
      jobId: requiredOption(options, "jobId"),
      status: requiredOption(options, "status"),
      summary: requiredOption(options, "summary"),
      exitCode: options.exitCode ?? null,
      policy,
    });
  } else if (command === "prune") {
    const result = pruneBackupQueue({ jobsDir, logDir, policy });
    process.stdout.write(`${JSON.stringify({ removed: result.length })}\n`);
  } else if (command === "acquire-lease") {
    const result = acquireBackupSchedulerLease({ jobsDir, logDir, kind: requiredOption(options, "kind"), policy });
    if (!result.acquired) {
      process.stderr.write(`backup queue ${result.reason}: global scheduler concurrency is exhausted\n`);
      process.exitCode = 75;
    } else {
      process.stdout.write(`${result.handle}\n`);
    }
  } else if (command === "release-lease") {
    releaseBackupSchedulerLease({ jobsDir, handle: requiredOption(options, "handle"), policy });
  } else {
    throw new Error("Usage: backup-queue-control.mjs <claim|finish|prune|acquire-lease|release-lease> --jobsDir PATH [--logDir PATH]");
  }
} catch (error) {
  if (error instanceof BackupQueueAdmissionError) {
    process.stderr.write(`backup queue ${error.code}: ${error.message}\n`);
    process.exitCode = error.status === 422 ? 64 : 75;
  } else {
    process.stderr.write(`${error?.message || error}\n`);
    process.exitCode = 64;
  }
}

function parseOptions(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const item = args[index];
    if (!item.startsWith("--") || item.length < 3) throw new Error(`Invalid option: ${item}`);
    const key = item.slice(2);
    if (key in parsed) throw new Error(`Duplicate option: --${key}`);
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`Missing value for --${key}`);
    parsed[key] = value;
    index += 1;
  }
  return parsed;
}

function requiredOption(options, name) {
  const value = String(options[name] || "").trim();
  if (!value) throw new Error(`Missing required option: --${name}`);
  return value;
}
