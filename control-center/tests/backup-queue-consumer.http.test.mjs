import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer as createNetServer } from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseBackupJobDocument } from "../backup/contracts.mjs";

const infraRoot = path.resolve(import.meta.dirname, "..", "..");

test("real HTTP backup producers share the bounded admission consumer", async (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "fg069-http-consumer-"));
  const stateDir = path.join(root, "state");
  const projectsDir = path.join(root, "projects");
  const backupsDir = path.join(root, "backups");
  const reportsDir = path.join(root, "reports");
  const jobsDir = path.join(stateDir, "backup-jobs");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(projectsDir, { recursive: true, mode: 0o700 });
  mkdirSync(backupsDir, { recursive: true, mode: 0o700 });
  mkdirSync(reportsDir, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(stateDir, "vault.key"), `test-v1=${"a".repeat(64)}\n`, { mode: 0o600 });
  writeFileSync(path.join(stateDir, "secret-vault.json"), '{"version":2,"items":{}}\n', { mode: 0o600 });
  writeFileSync(path.join(stateDir, "databases.json"), `${JSON.stringify({
    "db-one": database("db-one", "app-one", "postgres"),
    "db-two": database("db-two", "app-two", "mariadb"),
    "db-three": database("db-three", "app-three", "postgres"),
  })}\n`, { mode: 0o600 });

  const port = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_AUTH_MODE: "test-disabled",
      CONTROL_CENTER_DATABASE_LIVE_APPLY: "false",
      CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "false",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      CONTROL_CENTER_BACKUP_ROOT: backupsDir,
      CONTROL_CENTER_REPORTS_ROOT: reportsDir,
      PROJECTS_ROOT: projectsDir,
      ...isolatedStateEnv(stateDir),
      BACKUP_QUEUE_MAX_OUTSTANDING: "3",
      BACKUP_QUEUE_MAX_PER_PRINCIPAL: "8",
      BACKUP_QUEUE_RATE_WINDOW_SECONDS: "900",
      BACKUP_QUEUE_MAX_CONCURRENCY: "1",
      BACKUP_QUEUE_TERMINAL_MAX_PER_STATUS: "8",
      BACKUP_QUEUE_TERMINAL_MAX_AGE_DAYS: "30",
      BACKUP_QUEUE_LEDGER_MAX_ENTRIES: "32",
      BACKUP_QUEUE_MAX_SCAN_ENTRIES: "64",
      BACKUP_QUEUE_LOCK_TIMEOUT_MS: "2000",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  t.after(async () => {
    await stopChild(child);
    rmSync(root, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHealth(`${baseUrl}/__health`, child);

  const modernDatabase = await post(baseUrl, "/control/databases/db-one/backup");
  assert.equal(modernDatabase.status, 202);
  assert.equal((await modernDatabase.json()).job.requestedBy, "test-owner");

  const legacyDatabase = await post(baseUrl, "/actions/database-command", {
    action: "backup",
    id: "db-two",
  });
  assert.equal(legacyDatabase.status, 202);
  assert.equal((await legacyDatabase.json()).job.requestedBy, "test-owner");

  const modernCatalog = await post(baseUrl, "/control/backups/run", { scope: "all" });
  assert.equal(modernCatalog.status, 202);
  assert.equal((await modernCatalog.json()).job.requestedBy, "test-owner");

  const queueFiles = readdirSync(path.join(jobsDir, "queued"))
    .filter((name) => name.endsWith(".json"))
    .sort();
  assert.equal(queueFiles.length, 3);
  const jobs = queueFiles.map((name) => parseBackupJobDocument(
    JSON.parse(readFileSync(path.join(jobsDir, "queued", name), "utf8")),
  ));
  assert.ok(jobs.every((job) => job.requestedBy === "test-owner"));

  const ledger = JSON.parse(readFileSync(path.join(jobsDir, ".admission-ledger.json"), "utf8"));
  assert.deepEqual(
    ledger.events.map((event) => event.routeOperationId),
    ["database.backup", "legacy.database", "backup.run"],
  );

  const duplicateAlias = await post(baseUrl, "/control/v1/databases/db-one/backup");
  assert.equal(duplicateAlias.status, 409);
  assert.deepEqual(Object.keys(await duplicateAlias.clone().json()).sort(), ["error", "message"]);
  assert.equal((await duplicateAlias.json()).error, "duplicate_active");
  assert.equal(readdirSync(path.join(jobsDir, "queued")).filter((name) => name.endsWith(".json")).length, 3);

  const full = await post(baseUrl, "/control/databases/db-three/backup");
  assert.equal(full.status, 503);
  const fullPayload = await full.json();
  assert.deepEqual(Object.keys(fullPayload).sort(), ["error", "message"]);
  assert.equal(fullPayload.error, "queue_full");
  assert.equal(readdirSync(path.join(jobsDir, "queued")).filter((name) => name.endsWith(".json")).length, 3);
  assert.equal(stderr, "");
});

function database(id, projectId, engine) {
  return {
    id,
    projectId,
    engine,
    name: id.replaceAll("-", "_"),
    ownerRole: `${projectId.replaceAll("-", "_")}_app`,
    status: "declared",
    linkedApps: [projectId],
  };
}

function isolatedStateEnv(stateRoot) {
  return {
    PROJECT_STATE_FILE: path.join(stateRoot, "projects.json"),
    PROJECT_AUDIT_FILE: path.join(stateRoot, "audit.jsonl"),
    PROJECT_OPERATIONS_FILE: path.join(stateRoot, "operations.jsonl"),
    PROJECT_APPLICATIONS_FILE: path.join(stateRoot, "applications.json"),
    PROJECT_DOMAINS_FILE: path.join(stateRoot, "domains.json"),
    PROJECT_DATABASES_FILE: path.join(stateRoot, "databases.json"),
    PROJECT_DATABASE_PRINCIPALS_FILE: path.join(stateRoot, "database-principals.json"),
    PROJECT_DATABASE_DESTRUCTIVE_OPERATIONS_FILE: path.join(stateRoot, "database-destructive-operations.json"),
    PROJECT_STORAGE_BUCKETS_FILE: path.join(stateRoot, "storage-buckets.json"),
    PROJECT_SENSITIVE_MATERIALS_FILE: path.join(stateRoot, "sensitive-materials.json"),
    PROJECT_VAULT_FILE: path.join(stateRoot, "secret-vault.json"),
    CONTROL_CENTER_VAULT_KEY_FILE: path.join(stateRoot, "vault.key"),
    CONTROL_CENTER_EXISTING_SECRETS_DIR: path.join(stateRoot, "existing-secrets"),
    PROJECT_WORKER_JOBS_FILE: path.join(stateRoot, "worker-jobs.json"),
    PROJECT_IDENTITY_ACCESS_FILE: path.join(stateRoot, "identity-access.json"),
    PROJECT_DEPLOYMENTS_FILE: path.join(stateRoot, "deployments.jsonl"),
    PROJECT_BACKUP_RECORDS_FILE: path.join(stateRoot, "backups.jsonl"),
    PROJECT_BACKUP_JOBS_DIR: path.join(stateRoot, "backup-jobs"),
    PROJECT_RESOURCE_LIMITS_FILE: path.join(stateRoot, "resource-limits.json"),
    PROJECT_SECURITY_POLICIES_FILE: path.join(stateRoot, "security-policies.json"),
    PROJECT_ALERTS_FILE: path.join(stateRoot, "alerts.json"),
    PROJECT_NOTIFICATION_CHANNELS_FILE: path.join(stateRoot, "notification-channels.json"),
    PROJECT_PROVIDER_CONNECTIONS_FILE: path.join(stateRoot, "provider-connections.json"),
    PROJECT_SETTINGS_FILE: path.join(stateRoot, "settings.json"),
    PROJECT_WEBSPACES_FILE: path.join(stateRoot, "webspaces.json"),
    PROJECT_STATUS_RUNS_FILE: path.join(stateRoot, "status-runs.jsonl"),
    PROJECT_STATUS_RUN_EVENTS_FILE: path.join(stateRoot, "status-run-events.jsonl"),
    CONTROL_CENTER_STATUS_STEP_DELAY_MS: "0",
  };
}

function post(baseUrl, pathname, payload = {}) {
  return fetch(`${baseUrl}${pathname}`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(payload),
    redirect: "manual",
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

async function waitForHealth(url, child) {
  const started = Date.now();
  while (Date.now() - started < 10_000) {
    if (child.exitCode !== null) throw new Error(`Control Center exited early with code ${child.exitCode}.`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Retry while the child binds its local test socket.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Timed out waiting for Control Center health endpoint.");
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}
