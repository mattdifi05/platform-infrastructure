import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer as createNetServer } from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
const infraRoot = path.resolve(import.meta.dirname, "..", "..");
// Keep the child clock on an exact second so 300 seconds is a true inclusive
// boundary, while staying close to the real clock used by Date construction.
const fixedNow = Math.floor(Date.now() / 1000) * 1000;
let publicOrigin = "";
let publicHost = "";

const sensitiveTargets = Object.freeze([
  ["GET", "/control/overview"],
  ["GET", "/control/advanced/backup-restore"],
  ["POST", "/control/vault/secrets/example/reveal"],
  ["POST", "/control/vault/secrets"],
  ["POST", "/control/vault/import-existing"],
  ["POST", "/control/vault/secrets/example/delete"],
  ["POST", "/control/databases"],
  ["POST", "/control/backups/files/delete"],
  ["POST", "/control/backups/run"],
  ["POST", "/control/databases/example/backup"],
  ["GET", "/control/backups/summary"],
  ["GET", "/control/backups/records"],
  ["GET", "/control/backups/jobs"],
  ["GET", "/control/backups/files"],
  ["GET", "/control/backups/preview"],
  ["GET", "/control/vault"],
]);

test("real HTTP authorization denies before payload/context/sinks and preserves CSRF and freshness", async (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "control-capabilities-http-"));
  const stateDir = path.join(root, "state");
  const projectsDir = path.join(root, "projects");
  const backupsDir = path.join(root, "backups");
  const reportsDir = path.join(root, "reports");
  const clockModule = path.join(root, "fixed-clock.mjs");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(projectsDir, { recursive: true, mode: 0o700 });
  mkdirSync(backupsDir, { recursive: true, mode: 0o700 });
  mkdirSync(path.join(backupsDir, "postgres"), { recursive: true, mode: 0o700 });
  mkdirSync(reportsDir, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(stateDir, "vault.key"), `test-v1=${"a".repeat(64)}\n`, { mode: 0o600 });
  writeFileSync(path.join(stateDir, "secret-vault.json"), '{"version":2,"items":{}}\n', { mode: 0o600 });
  writeFileSync(path.join(backupsDir, "postgres", "fg043-canary.dump"), "non-secret backup canary\n", { mode: 0o600 });
  writeFileSync(clockModule, `Date.now = () => ${fixedNow};\n`, { mode: 0o600 });
  const sessionFixtures = [
    fixture("viewer", "viewer", 0),
    fixture("admin", "admin", 0),
    fixture("owner", "owner", 0),
    fixture("owner-299", "owner", 299),
    fixture("owner-300", "owner", 300),
    fixture("owner-301", "owner", 301),
    fixture("owner-future", "owner", -1),
  ];

  const port = await freePort();
  publicOrigin = `https://127.0.0.1:${port}`;
  publicHost = `127.0.0.1:${port}`;
  const child = spawn(process.execPath, ["--import", clockModule, path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_AUTH_MODE: "app-passkey",
      CONTROL_CENTER_AUTH_STORE: "memory",
      CONTROL_CENTER_PUBLIC_ORIGIN: publicOrigin,
      CONTROL_CENTER_AUTH_RP_ID: "127.0.0.1",
      CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "disabled",
      CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "127.0.0.0/8",
      CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12",
      CONTROL_CENTER_TEST_SESSION_FIXTURES: JSON.stringify(sessionFixtures),
      CONTROL_CENTER_LOGIN_MAX_ATTEMPTS: "50",
      CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "false",
      CONTROL_CENTER_DATABASE_LIVE_APPLY: "false",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      CONTROL_CENTER_BACKUP_ROOT: backupsDir,
      CONTROL_CENTER_REPORTS_ROOT: reportsDir,
      PROJECTS_ROOT: projectsDir,
      ...isolatedStateEnv(stateDir),
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
  const disabledRegistration = await fetch(`${baseUrl}/auth/passkey/register/options`, {
    method: "POST",
    headers: {
      accept: "application/json",
      host: publicHost,
      origin: publicOrigin,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
    },
    body: "{}",
    redirect: "manual",
  });
  assert.equal(disabledRegistration.status, 404, "disabled first configuration must not expose passkey enrollment");
  const identities = {
    viewer: identity(sessionFixtures[0]),
    admin: identity(sessionFixtures[1]),
    owner: identity(sessionFixtures[2]),
    owner299: identity(sessionFixtures[3]),
    owner300: identity(sessionFixtures[4]),
    owner301: identity(sessionFixtures[5]),
    ownerFuture: identity(sessionFixtures[6]),
  };

  const restoreStateAfterDenied = installContextTripwire(path.join(stateDir, "projects.json"));
  const beforeDenied = digestTree(root, new Set(["fixed-clock.mjs"]));
  for (const [method, pathname] of sensitiveTargets) {
    for (const alias of [pathname, versioned(pathname)]) {
      assert.equal((await request(baseUrl, method, alias)).status, 401, `anonymous ${method} ${alias}`);
      assert.equal((await request(baseUrl, method, alias, identities.viewer, { oversized: method === "POST" })).status, 403, `viewer ${method} ${alias}`);
      assert.equal((await request(baseUrl, method, alias, identities.admin, { oversized: method === "POST" })).status, 403, `admin ${method} ${alias}`);
      const stale = await request(baseUrl, method, alias, identities.owner301, { validCsrf: method === "POST" });
      assert.equal(stale.status, 428, `stale owner ${method} ${alias}`);
      assert.equal((await stale.json()).error, "admin_reauthentication_required");
    }
  }
  for (const pathname of [
    "/CONTROL/vault",
    "/Control/vault",
    "/c%6fntrol/vault",
    "/c%256fntrol/vault",
    "/control%2Fvault",
    "/control%252Fvault",
    "/control%5Cvault",
    "/control%255Cvault",
    "/CONTROL/backups/files",
    "/c%6fntrol/backups/preview",
    "/control%2Fbackups/summary",
    "/control%252Fbackups/records",
    ...["/vault", "/backups/files"].flatMap((suffix) =>
      [3, 4, 32].map((layers) => nestedEncodedControlPath(suffix, layers))),
    nestedEncodedControlPath("/%FF/vault", 3),
    nestedEncodedControlPath("/%ZZ/backups/files", 4),
  ]) {
    for (const identity of [identities.viewer, identities.owner]) {
      const response = await request(baseUrl, "GET", pathname, identity);
      assert.equal(response.status, 403, `control-like path must deny before context: ${pathname}`);
      assert.equal((await response.json()).error, "endpoint_capability_denied", pathname);
    }
  }
  for (const pathname of ["/?section=secrets"]) {
    assert.equal((await request(baseUrl, "GET", pathname)).status, 401, `anonymous UI ${pathname}`);
    assert.equal((await request(baseUrl, "GET", pathname, identities.viewer)).status, 403, `viewer UI ${pathname}`);
    assert.equal((await request(baseUrl, "GET", pathname, identities.admin)).status, 403, `admin UI ${pathname}`);
    const stale = await request(baseUrl, "GET", pathname, identities.owner301);
    assert.equal(stale.status, 428, `stale owner UI ${pathname}`);
    assert.equal((await stale.json()).error, "admin_reauthentication_required");
  }
  const staleBrowserPage = await fetch(`${baseUrl}/?section=secrets`, {
    headers: { accept: "text/html", host: publicHost, cookie: identities.owner301.cookie },
    redirect: "manual",
  });
  assert.equal(staleBrowserPage.status, 303);
  assert.equal(staleBrowserPage.headers.get("location"), "/auth/login?returnTo=%2F%3Fsection%3Dsecrets");
  const staleBrowserMutation = await fetch(`${baseUrl}/actions/vault-command`, {
    method: "POST",
    headers: {
      accept: "text/html",
      host: publicHost,
      cookie: identities.owner301.cookie,
      origin: publicOrigin,
      "sec-fetch-site": "same-origin",
      "content-type": "application/x-www-form-urlencoded",
      "x-csrf-token": identities.owner301.csrf,
    },
    body: new URLSearchParams({ action: "reveal", _csrf: identities.owner301.csrf }),
    redirect: "manual",
  });
  assert.equal(staleBrowserMutation.status, 303);
  assert.equal(staleBrowserMutation.headers.get("location"), "/auth/login");
  for (const [method, pathname] of [
    ["HEAD", "/"],
    ["OPTIONS", "/index.html"],
    ["POST", "/?section=vault"],
    ["PUT", "/index.html?section=projects"],
  ]) {
    const response = await request(baseUrl, method, pathname, identities.owner, {
      validCsrf: method === "POST",
      oversized: method === "POST",
    });
    assert.equal(response.status, 403, `${method} HTML shell`);
    if (method !== "HEAD") assert.equal((await response.json()).error, "endpoint_capability_denied");
  }
  assert.equal(digestTree(root, new Set(["fixed-clock.mjs"])), beforeDenied, "denied requests must leave all state and sink fixtures byte-identical");
  restoreStateAfterDenied();

  assert.equal((await request(baseUrl, "GET", "/?section=vault", identities.owner)).status, 200, "fresh owner reaches Vault UI");
  assert.equal((await request(baseUrl, "GET", "/index.html?section=projects", identities.owner300)).status, 200, "300-second owner reaches HTML shell");

  for (const [method, pathname] of sensitiveTargets) {
    for (const alias of [pathname, versioned(pathname)]) {
      const response = await request(baseUrl, method, alias, identities.owner, { validCsrf: method === "POST" });
      const body = await response.clone().text();
      assert.ok(![401, 403, 404, 428, 500].includes(response.status), `fresh owner reaches handler: ${method} ${alias} -> ${response.status}: ${body}`);
    }
  }
  for (const pathname of ["/control/overview", "/control/v1/advanced/backup-restore"]) {
    const response = await request(baseUrl, "GET", pathname, identities.owner);
    assert.equal(response.status, 200, pathname);
    assert.match(JSON.stringify(await response.json()), /fg043-canary\.dump/, `fresh owner sees canary through ${pathname}`);
  }

  const boundaryPath = "/control/vault/secrets/missing/reveal";
  for (const [identity, expected] of [[identities.owner299, "handler"], [identities.owner300, "handler"], [identities.owner301, 428]]) {
    const response = await request(baseUrl, "POST", boundaryPath, identity, { validCsrf: true });
    if (expected === "handler") assert.ok(![401, 403, 404, 428, 500].includes(response.status), `freshness boundary -> ${response.status}`);
    else assert.equal(response.status, expected);
  }

  const futureAuth = await request(baseUrl, "GET", "/control/vault", identities.ownerFuture);
  assert.equal(futureAuth.status, 428);
  assert.equal((await futureAuth.json()).error, "admin_reauthentication_required");

  for (const [options, error] of [
    [{ validCsrf: true, origin: "https://attacker.example.test" }, "csrf_origin_rejected"],
    [{ validCsrf: true, omitFetchSite: true }, "csrf_fetch_site_rejected"],
    [{ validCsrf: true, fetchSite: "cross-site" }, "csrf_fetch_site_rejected"],
    [{ invalidCsrf: true }, "csrf_token_rejected"],
  ]) {
    const invalidCsrf = await request(baseUrl, "POST", boundaryPath, identities.owner299, options);
    assert.equal(invalidCsrf.status, 403, error);
    assert.equal((await invalidCsrf.json()).error, error);
  }

  const restoreStateAfterUnknown = installContextTripwire(path.join(stateDir, "projects.json"));
  const beforeUnknown = digestTree(root, new Set(["fixed-clock.mjs"]));
  for (const [method, pathname] of [
    ["GET", "/control/not-cataloged"],
    ["POST", "/control/not-cataloged"],
    ["GET", "/control/v1/backups/files/extra"],
    ["GET", "/control//vault"],
    ["GET", "/control/vault/"],
    ["HEAD", "/control/vault"],
    ["OPTIONS", "/control/backups/files"],
  ]) {
    const response = await request(baseUrl, method, pathname, identities.owner, {
      validCsrf: method === "POST",
      oversized: method === "POST",
    });
    assert.equal(response.status, 403, `${method} ${pathname}`);
    if (method !== "HEAD") assert.equal((await response.json()).error, "endpoint_capability_denied");
  }
  assert.equal(
    digestTree(root, new Set(["fixed-clock.mjs"])),
    beforeUnknown,
    "unclassified methods and paths must be denied before context or sink access",
  );
  restoreStateAfterUnknown();

  assert.equal(stderr, "");
});

function fixture(label, role, ageSeconds) {
  return {
    token: `test-session-token-${label}`,
    csrf: `test-session-csrf-${label}`,
    role,
    ageSeconds,
  };
}

function identity(item) {
  return {
    cookie: `__Host-platform_cc_session=${item.token}; __Host-platform_cc_csrf=${item.csrf}`,
    csrf: item.csrf,
  };
}

function request(baseUrl, method, pathname, identity = null, options = {}) {
  const headers = { accept: "application/json", host: publicHost };
  if (identity) headers.cookie = identity.cookie;
  let body;
  if (method === "POST") {
    headers["content-type"] = "application/x-www-form-urlencoded";
    if (options.validCsrf || options.invalidCsrf) {
      headers.origin = options.origin || publicOrigin;
      if (!options.omitFetchSite) headers["sec-fetch-site"] = options.fetchSite || "same-origin";
      headers["x-csrf-token"] = options.invalidCsrf ? "invalid-csrf-token" : identity.csrf;
    }
    body = options.oversized
      ? `padding=${"x".repeat(70 * 1024)}`
      : new URLSearchParams({ _csrf: options.invalidCsrf ? "invalid-csrf-token" : identity?.csrf || "" });
  }
  return fetch(`${baseUrl}${pathname}`, { method, headers, body, redirect: "manual" });
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

function digestTree(root, ignoredNames = new Set()) {
  const hash = createHash("sha256");
  const visit = (directory) => {
    for (const name of readdirSync(directory).sort()) {
      if (ignoredNames.has(name)) continue;
      const filename = path.join(directory, name);
      const relative = path.relative(root, filename);
      const stat = statSync(filename);
      hash.update(`${relative}\0${stat.isDirectory() ? "d" : "f"}\0`);
      if (stat.isDirectory()) visit(filename);
      else hash.update(readFileSync(filename));
    }
  };
  visit(root);
  return hash.digest("hex");
}

function installContextTripwire(filename) {
  const previous = existsSync(filename) ? readFileSync(filename) : null;
  writeFileSync(filename, "{malformed-context-tripwire", { mode: 0o600 });
  return () => {
    if (previous) writeFileSync(filename, previous, { mode: 0o600 });
    else rmSync(filename, { force: true });
  };
}

function versioned(pathname) {
  return pathname.replace(/^\/control(?=\/|$)/, "/control/v1");
}

function nestedEncodedControlPath(suffix, layers) {
  return `/c%${"25".repeat(layers - 1)}6fntrol${suffix}`;
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
