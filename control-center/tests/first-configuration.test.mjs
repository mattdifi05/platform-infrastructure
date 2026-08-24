import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  createFirstConfiguration,
  FIRST_CONFIGURATION_STATES,
  FirstConfigurationError,
} from "../first-configuration/index.mjs";
import { readFirstConfigurationConfig } from "../first-configuration/config.mjs";
import { FirstConfigurationKeycloakError } from "../first-configuration/keycloak.mjs";
import { MemoryFirstConfigurationStore } from "../first-configuration/store.mjs";

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), "control-center-first-configuration-"));
  const bootstrapFile = path.join(root, "bootstrap.txt");
  const databaseFile = path.join(root, "database.txt");
  const clientSecretFile = path.join(root, "keycloak-client.txt");
  const bootstrapCode = "b".repeat(64);
  writeFileSync(bootstrapFile, `${bootstrapCode}\n`, { mode: 0o600 });
  writeFileSync(databaseFile, "postgresql://control:test@postgres/control\n", { mode: 0o600 });
  writeFileSync(clientSecretFile, `${"s".repeat(48)}\n`, { mode: 0o600 });
  const env = {
    CONTROL_CENTER_ENV: "local",
    CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "required",
    CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.example.test",
    CONTROL_CENTER_OIDC_ISSUER: "https://auth.example.test/realms/platform",
    CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
    CONTROL_CENTER_OIDC_CLIENT_ID: "platform-control-center",
    CONTROL_CENTER_AUTH_DATABASE_URL_FILE: databaseFile,
    CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE: bootstrapFile,
    CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE: clientSecretFile,
    CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME: "matthew",
    CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL: "matthew@example.test",
    CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "192.168.0.0/16",
    CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12",
  };
  return { root, env, bootstrapCode };
}

function request({ address = "192.168.1.24", cookie = "", mutation = true, forwarded = "" } = {}) {
  return {
    socket: { remoteAddress: address },
    headers: {
      host: "portal.example.test",
      cookie,
      ...(mutation ? { origin: "https://portal.example.test", "sec-fetch-site": "same-origin" } : {}),
      ...(forwarded ? { "x-forwarded-for": forwarded } : {}),
    },
  };
}

function cookieHeader(setCookies) {
  return setCookies.map((value) => value.split(";", 1)[0]).join("; ");
}

test("guided first configuration is resumable, peer-bound and closes after passkey relogin", async () => {
  const files = fixture();
  const store = new MemoryFirstConfigurationStore();
  const keycloak = {
    passkeyCount: 0,
    disabled: false,
    cutover: false,
    firstLoginCompleted: false,
    sessionsRevoked: false,
    async prepareAdministrator({ username, email }) {
      return { subject: "user-123", username, email, temporaryPassword: "temporary-secret" };
    },
    async rotateBootstrapPassword() { return "rotated-secret"; },
    async credentialSummary() {
      return { passkeyCount: this.passkeyCount, passkeys: Array.from({ length: this.passkeyCount }, (_, index) => ({ id: `credential-${index}` })) };
    },
    async applyPasskeyOnlyCutover() {
      assert.equal(this.passkeyCount, 2);
      this.cutover = true;
      return { passkeyCount: 2 };
    },
    async completeFirstPasskeyLogin() {
      assert.equal(this.cutover, true);
      this.firstLoginCompleted = true;
      this.sessionsRevoked = true;
    },
    async disableBootstrapClient() {
      this.disabled = true;
      return { disabled: true, alreadyDisabled: false, verifiedByResponse: true };
    },
  };
  try {
    const setup = await createFirstConfiguration({ env: files.env, store, keycloak });
    assert.equal((await setup.status()).state, FIRST_CONFIGURATION_STATES.REQUIRED);

    await assert.rejects(
      setup.consumeBootstrap(request({ address: "203.0.113.4" }), files.bootstrapCode),
      (error) => error instanceof FirstConfigurationError && error.code === "first_configuration_network_rejected",
    );

    const bootstrap = await setup.consumeBootstrap(request(), files.bootstrapCode);
    let cookie = cookieHeader(bootstrap.cookies);
    const resumed = await setup.consumeBootstrap(request(), files.bootstrapCode);
    const resumedCookie = cookieHeader(resumed.cookies);
    assert.equal((await setup.authenticate(request({ cookie, mutation: false }))).ok, false);
    cookie = resumedCookie;

    const identity = await setup.authenticate(request({ cookie, mutation: false }));
    assert.equal(identity.ok, true);
    assert.ok(identity.csrfToken);
    assert.equal((await setup.validateMutation(request({ cookie }), identity, identity.csrfToken)).ok, true);

    await assert.rejects(
      setup.confirmAdministrator(identity, { username: "other", email: "matthew@example.test" }),
      (error) => error.code === "first_configuration_identity_rejected",
    );
    const prepared = await setup.confirmAdministrator(identity, { username: "matthew", email: "matthew@example.test" });
    assert.equal(prepared.temporaryPassword, "temporary-secret");
    assert.equal(prepared.state.state, FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED);

    keycloak.passkeyCount = 2;
    const inventory = await setup.refreshPasskeys(identity);
    assert.equal(inventory.state.state, FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED);
    assert.equal(inventory.state.passkeyCount, 2);
    await assert.rejects(
      setup.confirmPasskeyIndependence(identity, { firstTested: true, secondTested: true, independent: false }),
      (error) => error.code === "first_configuration_passkey_confirmation_required",
    );
    const ready = await setup.confirmPasskeyIndependence(identity, { firstTested: true, secondTested: true, independent: true });
    assert.equal(ready.state, FIRST_CONFIGURATION_STATES.PASSKEYS_READY);

    const cutover = await setup.applyPasskeyCutover(identity);
    assert.equal(cutover.state, FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED);
    assert.equal(keycloak.cutover, true);

    await assert.rejects(
      setup.notePasskeyLogin("different-subject"),
      (error) => error.code === "first_configuration_subject_rejected",
    );

    const firstLogin = await setup.notePasskeyLogin("user-123");
    assert.equal(firstLogin.state.state, FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED);
    assert.equal(keycloak.firstLoginCompleted, true);
    assert.equal(keycloak.sessionsRevoked, true);
    const logout = await setup.recordLogoutVerification(identity, "user-123");
    assert.equal(logout.state, FIRST_CONFIGURATION_STATES.RELOGIN_REQUIRED);
    const secondLogin = await setup.notePasskeyLogin("user-123");
    assert.equal(secondLogin.completed, true);
    assert.equal(keycloak.disabled, true);
    assert.equal((await setup.status()).state, FIRST_CONFIGURATION_STATES.COMPLETE);
    assert.equal((await setup.authenticate(request({ cookie, mutation: false }))).code, "first_configuration_closed");
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("FINALIZING remains fail-closed after an interrupted disable and completes on an idempotent retry", async () => {
  const files = fixture();
  const store = new MemoryFirstConfigurationStore();
  let attempts = 0;
  const keycloak = {
    disabled: false,
    async disableBootstrapClient({ allowAlreadyDisabled }) {
      assert.equal(allowAlreadyDisabled, true);
      attempts += 1;
      if (attempts === 1) {
        this.disabled = true;
        throw new FirstConfigurationKeycloakError(
          "Keycloak response was interrupted after disabling the bootstrap client.",
          503,
          "first_configuration_identity_unavailable",
        );
      }
      assert.equal(this.disabled, true);
      return { disabled: true, alreadyDisabled: true, verifiedByReadback: true };
    },
  };
  try {
    const setup = await createFirstConfiguration({ env: files.env, store, keycloak });
    store.state.adminSubject = "user-123";
    store.state.adminUsername = "matthew";
    store.state.adminEmail = "matthew@example.test";
    store.state.state = FIRST_CONFIGURATION_STATES.FINALIZING;
    const identity = { ok: true };

    await assert.rejects(
      setup.retryFinalization(identity),
      (error) => error instanceof FirstConfigurationError && error.code === "first_configuration_identity_unavailable",
    );
    assert.equal((await setup.status()).state, FIRST_CONFIGURATION_STATES.FINALIZING);

    const completed = await setup.retryFinalization(identity);
    assert.equal(completed.completed, true);
    assert.equal(completed.state.state, FIRST_CONFIGURATION_STATES.COMPLETE);
    assert.equal(attempts, 2);
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("FINALIZING rejects an unverified bootstrap-disable result", async () => {
  const files = fixture();
  const store = new MemoryFirstConfigurationStore();
  const keycloak = {
    async disableBootstrapClient() {
      return { disabled: true, alreadyDisabled: true };
    },
  };
  try {
    const setup = await createFirstConfiguration({ env: files.env, store, keycloak });
    store.state.adminSubject = "user-123";
    store.state.adminUsername = "matthew";
    store.state.adminEmail = "matthew@example.test";
    store.state.state = FIRST_CONFIGURATION_STATES.FINALIZING;

    await assert.rejects(
      setup.retryFinalization({ ok: true }),
      (error) => error instanceof FirstConfigurationError &&
        error.code === "first_configuration_bootstrap_disable_unverified",
    );
    assert.equal((await setup.status()).state, FIRST_CONFIGURATION_STATES.FINALIZING);
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("callback hook stays LOGIN_REQUIRED until session revocation succeeds, then guides a real re-login", async () => {
  const files = fixture();
  const store = new MemoryFirstConfigurationStore();
  let cleanupAttempts = 0;
  const keycloak = {
    async completeFirstPasskeyLogin() {
      cleanupAttempts += 1;
      if (cleanupAttempts === 1) {
        throw new FirstConfigurationKeycloakError(
          "Keycloak did not confirm revocation of the administrator sessions.",
          503,
          "first_configuration_identity_unavailable",
        );
      }
      return { passkeyCount: 2 };
    },
    async disableBootstrapClient() {
      return { disabled: true, alreadyDisabled: false, verifiedByResponse: true };
    },
  };
  try {
    const setup = await createFirstConfiguration({ env: files.env, store, keycloak });
    store.state.adminSubject = "user-123";
    store.state.adminUsername = "matthew";
    store.state.adminEmail = "matthew@example.test";
    store.state.passkeyCount = 2;
    store.state.state = FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED;

    await assert.rejects(
      setup.notePasskeyLogin("user-123"),
      (error) => error instanceof FirstConfigurationError &&
        error.code === "first_configuration_identity_unavailable",
    );
    assert.equal((await setup.status()).state, FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED);

    const accepted = await setup.notePasskeyLogin("user-123");
    assert.equal(accepted.state.state, FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED);
    const logout = await setup.recordLogoutVerification({ ok: true }, "user-123");
    assert.equal(logout.state, FIRST_CONFIGURATION_STATES.RELOGIN_REQUIRED);
    const relogin = await setup.notePasskeyLogin("user-123");
    assert.equal(relogin.completed, true);
    assert.equal(relogin.state.state, FIRST_CONFIGURATION_STATES.COMPLETE);
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("trusted proxy resolution uses the right-most untrusted LAN client", async () => {
  const files = fixture();
  const store = new MemoryFirstConfigurationStore();
  try {
    const setup = await createFirstConfiguration({
      env: files.env,
      store,
      keycloak: {},
    });
    const accepted = request({ address: "172.20.0.10", forwarded: "203.0.113.8, 192.168.1.44" });
    const result = await setup.consumeBootstrap(accepted, files.bootstrapCode);
    assert.equal(result.state.state, FIRST_CONFIGURATION_STATES.REQUIRED);
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("deployment-owned bootstrap rotation revokes prior setup sessions while incomplete", async () => {
  const files = fixture();
  const store = new MemoryFirstConfigurationStore();
  try {
    const first = await createFirstConfiguration({ env: files.env, store, keycloak: {} });
    const session = await first.consumeBootstrap(request(), files.bootstrapCode);
    const previousCookie = cookieHeader(session.cookies);
    const replacementCode = "r".repeat(64);
    writeFileSync(files.env.CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE, `${replacementCode}\n`, { mode: 0o600 });
    const rotated = await createFirstConfiguration({ env: files.env, store, keycloak: {} });
    assert.equal((await rotated.authenticate(request({ cookie: previousCookie, mutation: false }))).ok, false);
    await assert.rejects(rotated.consumeBootstrap(request(), files.bootstrapCode), /invalid or expired/);
    assert.equal((await rotated.consumeBootstrap(request(), replacementCode)).state.state, FIRST_CONFIGURATION_STATES.REQUIRED);
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("required first configuration rejects non-LOCAL_PRIVATE environments", () => {
  const files = fixture();
  try {
    assert.throws(
      () => readFirstConfigurationConfig({ ...files.env, CONTROL_CENTER_ENV: "production" }),
      /restricted to the LOCAL_PRIVATE environment/,
    );
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("First Configuration pins the owner and passkey-flow contract while deriving the exact RP", () => {
  const files = fixture();
  try {
    const config = readFirstConfigurationConfig({
      ...files.env,
      CONTROL_CENTER_OIDC_REQUIRED_ACR: "urn:platform:loa:passkey",
    });
    assert.equal(config.identityOrigin, "https://auth.example.test");
    assert.equal(config.rpId, "auth.example.test");
    assert.equal(config.requiredAcr, "urn:platform:loa:passkey");
    assert.throws(
      () => readFirstConfigurationConfig({ ...files.env, CONTROL_CENTER_OIDC_OWNER_ROLE: "admin" }),
      /must be exactly owner/,
    );
    assert.throws(
      () => readFirstConfigurationConfig({
        ...files.env,
        CONTROL_CENTER_FIRST_CONFIGURATION_PASSKEY_FLOW: "foreign-flow",
      }),
      /must be exactly platform-passkey-browser/,
    );
  } finally {
    rmSync(files.root, { recursive: true, force: true });
  }
});

test("Control Center serves the guided entry and consumes the bootstrap code over the exact local origin", async () => {
  const files = fixture();
  const port = await unusedPort();
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: path.resolve(import.meta.dirname, ".."),
    env: {
      ...process.env,
      ...files.env,
      NODE_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_AUTH_MODE: "test-disabled",
      CONTROL_CENTER_FIRST_CONFIGURATION_STORE: "memory",
      CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "127.0.0.0/8",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  const base = `http://127.0.0.1:${port}`;
  const headers = { host: "portal.example.test" };
  try {
    await waitForServer(`${base}/__health`, headers, child);
    const health = await fetch(`${base}/__health`, { headers });
    assert.deepEqual(await health.json(), { ok: true, service: "control-center", firstConfiguration: FIRST_CONFIGURATION_STATES.REQUIRED });

    const root = await fetch(`${base}/`, { headers, redirect: "manual" });
    assert.equal(root.status, 303);
    assert.equal(root.headers.get("location"), "/first-configuration");

    const lockedApi = await rawHttp(`${base}/control/v1/projects`, { headers });
    assert.equal(lockedApi.status, 423);
    assert.equal(JSON.parse(lockedApi.body).error, "first_configuration_incomplete");

    const lockedMutation = await rawHttp(`${base}/actions/toggle-project`, { method: "POST", headers });
    assert.equal(lockedMutation.status, 423);

    const entry = await rawHttp(`${base}/first-configuration`, { headers });
    assert.equal(entry.status, 200);
    assert.match(entry.body, /Codice temporaneo di configurazione/);
    assert.match(entry.headers["cache-control"] || "", /no-store/);

    const bootstrapBody = new URLSearchParams({ bootstrapCode: files.bootstrapCode }).toString();
    const bootstrap = await rawHttp(`${base}/first-configuration/bootstrap`, {
      method: "POST",
      headers: {
        ...headers,
        origin: "https://portal.example.test",
        "sec-fetch-site": "same-origin",
        "content-type": "application/x-www-form-urlencoded",
        "content-length": Buffer.byteLength(bootstrapBody),
      },
      body: bootstrapBody,
    });
    assert.equal(bootstrap.status, 303);
    for (const setCookie of bootstrap.headers["set-cookie"]) {
      assert.match(setCookie, /; Path=\//);
    }
    const cookies = bootstrap.headers["set-cookie"].map((value) => value.split(";", 1)[0]).join("; ");
    assert.match(cookies, /__Host-platform_cc_first_configuration=/);

    const guided = await rawHttp(`${base}/first-configuration`, { headers: { ...headers, cookie: cookies } });
    assert.equal(guided.status, 200);
    const guidedHtml = guided.body;
    assert.match(guidedHtml, /Conferma l’amministratore/);
    assert.match(guidedHtml, /FIRST_CONFIGURATION_REQUIRED/);
  } finally {
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("exit", resolve));
    rmSync(files.root, { recursive: true, force: true });
  }
  assert.equal(stderr, "");
});

async function unusedPort() {
  const server = createNetServer();
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForServer(url, headers, child) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Control Center exited before readiness: ${child.exitCode}`);
    try {
      const response = await fetch(url, { headers });
      if (response.ok) return;
    } catch { /* Retry while the child binds the socket. */ }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("Control Center did not become ready.");
}

function rawHttp(url, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const request = httpRequest(url, { method, headers }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.once("error", reject);
    if (body) request.write(body);
    request.end();
  });
}
