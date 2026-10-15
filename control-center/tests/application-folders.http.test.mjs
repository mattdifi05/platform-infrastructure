import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:net";

test("real HTTP folder operations enforce auth and CSRF and render isolated catalog groups", async t => {
  const root = mkdtempSync(path.join(os.tmpdir(), "application-folders-http-"));
  const stateDir = path.join(root, "state");
  mkdirSync(stateDir);
  mkdirSync(path.join(root, "projects"));
  const staleFolderId = "folder-00000000-0000-0000-0000-000000000001";
  const initial = { projects: {
    alpha: { declaredProject: true, displayName: "Alpha app", host: "alpha.example.test", runtime: "node" },
    beta: { declaredProject: true, displayName: "Beta app", host: "beta.example.test", runtime: "php" },
  }, subdomains: { retained: true }, extra: "preserved", applicationFolders: { folders: { [staleFolderId]: { name: "Temporaneamente assente" } }, memberships: { "project:absent": staleFolderId }, extra: "retained-folder-metadata" } };
  writeFileSync(path.join(stateDir, "projects.json"), JSON.stringify(initial));
  writeFileSync(path.join(stateDir, "vault.key"), `test-v1=${"a".repeat(64)}\n`, { mode: 0o600 });
  const reservation = createServer();
  await new Promise(resolve => reservation.listen(0, "127.0.0.1", resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const origin = `https://127.0.0.1:${port}`;
  const base = `http://127.0.0.1:${port}`;
  const sessions = ["viewer", "admin", "owner"].map(role => ({ token: `folder-test-${role}`, csrf: `folder-csrf-${role}`, role, ageSeconds: 0 }));
  const child = spawn(process.execPath, ["control-center/server.mjs"], {
    cwd: path.resolve(import.meta.dirname, "../.."),
    env: { ...process.env, NODE_ENV: "test", CONTROL_CENTER_ENV: "test", CONTROL_CENTER_BIND_HOST: "127.0.0.1", CONTROL_CENTER_PORT: String(port), CONTROL_CENTER_AUTH_MODE: "app-passkey", CONTROL_CENTER_AUTH_STORE: "memory", CONTROL_CENTER_PUBLIC_ORIGIN: origin, CONTROL_CENTER_AUTH_RP_ID: "127.0.0.1", CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "disabled", CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "127.0.0.0/8", CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12", CONTROL_CENTER_TEST_SESSION_FIXTURES: JSON.stringify(sessions), CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "false", CONTROL_CENTER_DATABASE_LIVE_APPLY: "false", CONTROL_CENTER_VPS_BACKUP_CATALOG_ROOT: "", CONTROL_CENTER_HOST_EXTENSION_FILE: undefined, PROJECTS_ROOT: path.join(root, "projects"), CONTROL_CENTER_REPORTS_ROOT: path.join(root, "reports"), CONTROL_CENTER_BACKUP_ROOT: path.join(root, "backups"), ...isolatedStateEnv(stateDir) },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", chunk => { stderr += chunk; });
  t.after(async () => {
    child.kill("SIGTERM");
    await new Promise(resolve => child.exitCode !== null ? resolve() : child.once("exit", resolve));
    rmSync(root, { force: true, recursive: true });
  });
  let healthy = false;
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw Error(`Server exited: ${stderr}`);
    try { if ((await fetch(`${base}/__health`)).ok) { healthy = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(healthy, true, stderr);
  function request(method, route, role, payload, csrf = true) {
    const item = sessions.find(item => item.role === role);
    const headers = { accept: "application/json", "content-type": "application/json" };
    if (item) headers.cookie = `__Host-platform_cc_session=${item.token}; __Host-platform_cc_csrf=${item.csrf}`;
    if (method === "POST" && csrf) Object.assign(headers, { origin, "sec-fetch-site": "same-origin", "x-csrf-token": item?.csrf || "invalid" });
    return fetch(`${base}${route}`, { method, headers, ...(payload ? { body: JSON.stringify(payload) } : {}) });
  }
  function assertDeleteControl(html, folderId, disabled) {
    const form = html.match(new RegExp(`<form[^>]*action="/control/project-folders/${folderId}/delete"[^>]*>([\\s\\S]*?)</form>`));
    assert.ok(form, `Delete form must be rendered for ${folderId}`);
    const button = form[1].match(/<button\b[^>]*>/)?.[0];
    assert.ok(button, "Delete control must be a button");
    assert.equal(/\bdisabled(?:\s|>|=)/.test(button), disabled);
    assert.match(form[1], disabled ? /sposta prima tutte le applicazioni/ : /vuota e può essere eliminata/);
  }
  const routes = ["/control/project-folders", "/control/project-folders/membership", "/control/project-folders/missing/rename", "/control/project-folders/missing/delete"];
  const before = readFileSync(path.join(stateDir, "projects.json"), "utf8");
  for (const route of [...routes, ...routes.map(route => route.replace("/control/", "/control/v1/"))]) {
    const anon = await request("POST", route, null, {});
    assert.equal(anon.status, 401, await anon.text());
    assert.equal((await request("POST", route, "viewer", {})).status, 403);
    assert.equal((await request("POST", route, "owner", {}, false)).status, 403);
  }
  assert.equal(readFileSync(path.join(stateDir, "projects.json"), "utf8"), before);
  const create = await request("POST", routes[0], "admin", { name: "Clienti" });
  assert.equal(create.status, 200);
  const { folderId } = await create.json();
  assert.equal((await request("POST", routes[1], "owner", { applicationKey: "project:alpha", folderId })).status, 200);
  assert.equal((await request("POST", routes[1], "owner", { applicationKey: "project:unknown", folderId })).status, 422);
  const catalog = await (await request("GET", routes[0], "viewer")).json();
  assert.equal(catalog.memberships["project:alpha"], folderId);
  assert.equal(catalog.memberships["project:beta"], "");
  assert.equal(catalog.folders.find(folder => folder.id === folderId).canDelete, false);
  assert.equal(catalog.folders.find(folder => folder.id === staleFolderId).canDelete, false);
  assert.equal(Object.hasOwn(catalog.memberships, "project:absent"), false);
  for (const prefix of ["/control", "/control/v1"]) for (const occupiedId of [folderId, staleFolderId]) {
    const beforeDelete = readFileSync(path.join(stateDir, "projects.json"), "utf8");
    const rejected = await request("POST", `${prefix}/project-folders/${occupiedId}/delete`, "owner", {});
    assert.equal(rejected.status, 422);
    assert.match(await rejected.text(), /contiene applicazioni/);
    assert.equal(readFileSync(path.join(stateDir, "projects.json"), "utf8"), beforeDelete);
  }
  const filtered = await (await request("GET", `/?section=projects&folder=${folderId}`, "owner")).text();
  assert.match(filtered, /id="project-alpha"/);
  assert.match(filtered, /data-application-search-input/);
  assert.match(filtered, /data-app-folder-group/);
  assert.match(filtered, /Gestisci cartella Clienti/);
  assertDeleteControl(filtered, folderId, true);
  const allFolders = await (await request("GET", "/?section=projects", "owner")).text();
  assertDeleteControl(allFolders, staleFolderId, true);
  assert.match(filtered, /class="ops-nav-main ops-nav-direct active" href="\/\?section=projects" aria-current="page"/);
  assert.doesNotMatch(filtered, /ops-nav-panel-projects|ops-nav-subitem/);
  assert.ok(filtered.indexOf('class="ops-logout-form"') < filtered.indexOf('class="ops-layout"'));
  assert.match(filtered, /aria-label="Esci"/);
  assert.doesNotMatch(filtered, /id="project-beta"/);
  const unfiled = await (await request("GET", "/?section=projects&folder=unfiled", "owner")).text();
  assert.match(unfiled, /id="project-beta"/);
  assert.doesNotMatch(unfiled, /id="project-alpha"/);
  assert.equal((await request("POST", `/control/v1/project-folders/${folderId}/rename`, "admin", { name: "Lavoro" })).status, 200);
  const renamed = JSON.parse(readFileSync(path.join(stateDir, "projects.json"), "utf8"));
  assert.equal(renamed.applicationFolders.folders[folderId].name, "Lavoro");
  assert.equal(renamed.applicationFolders.memberships["project:alpha"], folderId);
  const renamedCatalog = await (await request("GET", "/control/v1/project-folders", "viewer")).json();
  assert.deepEqual(renamedCatalog.folders.find(folder => folder.id === folderId), { id: folderId, name: "Lavoro", canDelete: false });
  assert.equal((await request("POST", `/control/v1/project-folders/membership`, "admin", { applicationKey: "project:alpha", folderId: "" })).status, 200);
  const emptyCatalog = await (await request("GET", routes[0], "viewer")).json();
  assert.equal(emptyCatalog.folders.find(folder => folder.id === folderId).canDelete, true);
  assert.equal((await request("POST", `/control/project-folders/${folderId}/delete`, "owner", {})).status, 200);
  const emptyCreate = await request("POST", "/control/v1/project-folders", "admin", { name: "Vuota" });
  assert.equal(emptyCreate.status, 200);
  const { folderId: emptyId } = await emptyCreate.json();
  const withEmptyFolder = await (await request("GET", "/?section=projects", "owner")).text();
  assert.match(withEmptyFolder, /data-app-folder-group aria-label="Vuota"/);
  assertDeleteControl(withEmptyFolder, emptyId, false);
  assert.equal((await request("POST", `/control/v1/project-folders/${emptyId}/delete`, "admin", {})).status, 200);
  const after = JSON.parse(readFileSync(path.join(stateDir, "projects.json"), "utf8"));
  assert.deepEqual(after.projects, initial.projects);
  assert.deepEqual(after.subdomains, initial.subdomains);
  assert.equal(after.extra, initial.extra);
  assert.deepEqual(after.applicationFolders, initial.applicationFolders);
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
