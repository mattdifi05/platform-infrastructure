import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, renameSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:net";

test("global backup control HTTP requires fresh owner and CSRF, keeps OFF until root confirmation, and gates manual captures", async t => {
  const root = mkdtempSync(path.join(os.tmpdir(), "global-backup-control-http-"));
  const stateDir = path.join(root, "state");
  const publicDir = path.join(root, "public");
  mkdirSync(stateDir); mkdirSync(publicDir); mkdirSync(path.join(root, "projects"));
  const catalogFile = path.join(publicDir, "catalog.json");
  const resources = [{ id: "platform-state:unit", externalId: "unit", kind: "platform-state", projectId: "platform", name: "unit" }];
  let control = { available: true, enabled: false, revision: "a".repeat(64), updatedAt: new Date().toISOString(), requestId: "" };
  function publish() {
    writeFileSync(catalogFile, JSON.stringify({ schema: "platform.vps-backup-catalog/v1", host: "unit-host", resources, points: [], enabled: control.enabled, enrollmentEnabled: true, queueActive: true, productionRestoreEnabled: true, backupControl: control }), { mode: 0o640 });
  }
  publish();
  writeFileSync(path.join(stateDir, "vault.key"), `test-v1=${"a".repeat(64)}\n`, { mode: 0o600 });
  writeFileSync(path.join(stateDir, "databases.json"), JSON.stringify({ "unit-db": { id: "unit-db", name: "unit_db", engine: "postgres", projectId: "platform" } }));
  const ownershipShim = path.join(root, "catalog-owner-fixture.mjs");
  // The non-root test process models only this root-owned public catalog file.
  // Existing catalog tests separately reject real unprotected ownership/modes.
  writeFileSync(ownershipShim, `import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; const catalogFile = process.env.CONTROL_CENTER_TEST_BACKUP_CATALOG_FILE; const original = fs.lstatSync; fs.lstatSync = function(file, ...args) { const stat = original(file, ...args); return String(file) === catalogFile ? Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, { uid: 0 }) : stat; }; syncBuiltinESMExports();`);
  const reservation = createServer();
  await new Promise(resolve => reservation.listen(0, "127.0.0.1", resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const origin = `https://127.0.0.1:${port}`, base = `http://127.0.0.1:${port}`;
  const sessions = ["viewer", "admin", "owner", "stale-owner"].map(label => ({ label, token: `backup-control-${label}`, csrf: `backup-control-csrf-${label}`, role: label === "stale-owner" ? "owner" : label, ageSeconds: label === "stale-owner" ? 301 : 0 }));
  const child = spawn(process.execPath, ["--import", ownershipShim, "control-center/server.mjs"], {
    cwd: path.resolve(import.meta.dirname, "../.."),
    env: { ...process.env, NODE_ENV: "test", CONTROL_CENTER_ENV: "test", CONTROL_CENTER_BIND_HOST: "127.0.0.1", CONTROL_CENTER_PORT: String(port), CONTROL_CENTER_AUTH_MODE: "app-passkey", CONTROL_CENTER_AUTH_STORE: "memory", CONTROL_CENTER_PUBLIC_ORIGIN: origin, CONTROL_CENTER_AUTH_RP_ID: "127.0.0.1", CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "disabled", CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "127.0.0.0/8", CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12", CONTROL_CENTER_TEST_SESSION_FIXTURES: JSON.stringify(sessions), CONTROL_CENTER_TEST_BACKUP_CATALOG_FILE: catalogFile, CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "false", CONTROL_CENTER_DATABASE_LIVE_APPLY: "false", CONTROL_CENTER_VPS_BACKUP_CATALOG_ROOT: publicDir, CONTROL_CENTER_HOST_EXTENSION_FILE: undefined, PROJECTS_ROOT: path.join(root, "projects"), CONTROL_CENTER_REPORTS_ROOT: path.join(root, "reports"), CONTROL_CENTER_BACKUP_ROOT: path.join(root, "backups"), ...isolatedStateEnv(stateDir) },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = ""; child.stderr.on("data", chunk => { stderr += chunk; });
  t.after(async () => { child.kill("SIGTERM"); await new Promise(resolve => child.exitCode !== null ? resolve() : child.once("exit", resolve)); rmSync(root, { force: true, recursive: true }); });
  let healthy = false;
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw Error(`Server exited: ${stderr}`);
    try { if ((await fetch(`${base}/__health`)).ok) { healthy = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(healthy, true, stderr);
  function request(method, route, label, payload, csrf = true) {
    const item = sessions.find(item => item.label === label);
    const headers = { accept: "application/json", "content-type": "application/json" };
    if (item) headers.cookie = `__Host-platform_cc_session=${item.token}; __Host-platform_cc_csrf=${item.csrf}`;
    if (method === "POST" && csrf) Object.assign(headers, { origin, "sec-fetch-site": "same-origin", "x-csrf-token": item?.csrf || "invalid" });
    return fetch(`${base}${route}`, { method, headers, ...(payload ? { body: JSON.stringify(payload) } : {}) });
  }
  const endpoint = "/control/backups/control";
  const payload = { enabled: true, expectedRevision: control.revision };
  const before = readFileSync(catalogFile, "utf8");
  assert.equal((await request("POST", endpoint, null, payload)).status, 401);
  for (const role of ["viewer", "admin"]) assert.equal((await request("POST", endpoint, role, payload)).status, 403);
  assert.equal((await request("POST", endpoint, "stale-owner", payload)).status, 428);
  assert.equal((await request("POST", endpoint, "owner", payload, false)).status, 403);
  assert.equal(readFileSync(catalogFile, "utf8"), before);
  const initial = await (await request("GET", endpoint, "viewer")).json();
  assert.equal(initial.control.enabled, false);
  assert.equal(initial.control.available, true);
  assert.equal((await request("POST", "/control/backups/run", "owner", { scope: "all" })).status, 422);
  assert.equal((await request("POST", "/control/databases/unit-db/backup", "owner", {})).status, 409);
  assert.equal((await request("POST", endpoint, "owner", { ...payload, expectedRevision: "b".repeat(64) })).status, 409);
  assert.equal((await request("POST", endpoint, "owner", { ...payload, enabled: "true" })).status, 409);
  const response = await request("POST", "/control/v1/backups/control", "owner", payload);
  assert.equal(response.status, 202);
  const accepted = await response.json();
  assert.equal(accepted.control.enabled, false, "accepted request is not effective-state proof");
  const id = accepted.request.id;
  const jobFile = path.join(stateDir, "backup-jobs", "queued", `${id}.json`);
  const job = JSON.parse(readFileSync(jobFile, "utf8"));
  assert.equal(job.operation, "backup-control");
  assert.equal(job.backupEnabled, true);
  assert.equal(job.expectedControlRevision, control.revision);
  assert.equal(JSON.parse(readFileSync(catalogFile, "utf8")).backupControl.enabled, false);
  const pending = await (await request("GET", endpoint, "viewer")).json();
  assert.equal(pending.control.enabled, false);
  assert.equal(pending.request.status, "queued");
  // Model the root consumer's atomic state publication and terminal queue receipt.
  control = { ...control, enabled: true, revision: "b".repeat(64), updatedAt: new Date().toISOString(), requestId: id }; publish();
  mkdirSync(path.join(stateDir, "backup-jobs", "done"), { recursive: true });
  writeFileSync(jobFile, JSON.stringify({ ...job, status: "done", finishedAt: new Date().toISOString() }));
  renameSync(jobFile, path.join(stateDir, "backup-jobs", "done", `${id}.json`));
  const confirmed = await (await request("GET", `${endpoint}?requestId=${id}`, "viewer")).json();
  assert.equal(confirmed.control.enabled, true);
  assert.equal(confirmed.control.requestId, id);
  assert.equal(confirmed.request.status, "done");
  const settings = await (await request("GET", "/?section=settings", "viewer")).text();
  assert.match(settings, /<h1 id="control-page-title">Impostazioni<\/h1>/);
  assert.match(settings, /data-host-metrics/);
  assert.match(settings, /data-global-backup-control/);
  const applications = await (await request("GET", "/?section=projects", "viewer")).text();
  assert.doesNotMatch(applications, /data-global-backup-control/);
  const off = await request("POST", endpoint, "owner", { enabled: false, expectedRevision: control.revision });
  assert.equal(off.status, 202);
  assert.equal((await off.json()).control.enabled, true, "OFF stays pending until protected root readback");
  writeFileSync(path.join(stateDir, "projects.json"), "invalid project context fixture");
  const hostOnly = await request("GET", "/control/resources/host", "viewer");
  assert.equal(hostOnly.status, 200, "host sampler must not build project context");
  const metrics = await hostOnly.json();
  assert.equal(metrics.scope, "host");
  assert.equal(metrics.source, "prometheus-node-exporter");
  assert.equal(metrics.disk.available, false, "container filesystem fallback must never become VPS disk data");
  assert.equal(metrics.disk.totalBytes, null);

});

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
    PROJECT_HOSTING_JOBS_FILE: path.join(stateRoot, "hosting-jobs.json"),
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
