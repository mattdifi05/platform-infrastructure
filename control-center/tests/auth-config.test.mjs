import assert from "node:assert/strict";
import test from "node:test";
import {
  AuthConfigurationError,
  createControlCenterAuth,
  MemoryAuthStore,
  providerScopeAdvisoryLockKey,
  readAuthConfig,
} from "../auth/oidc.mjs";

test("test-disabled auth is restricted to test processes on loopback", () => {
  const accepted = readAuthConfig({
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "local",
    CONTROL_CENTER_BIND_HOST: "127.0.0.1",
    CONTROL_CENTER_AUTH_MODE: "test-disabled",
  });
  assert.equal(accepted.mode, "test-disabled");

  assert.throws(() => readAuthConfig({
    NODE_ENV: "test",
    CONTROL_CENTER_BIND_HOST: "0.0.0.0",
    CONTROL_CENTER_AUTH_MODE: "test-disabled",
  }), AuthConfigurationError);
  assert.throws(() => readAuthConfig({
    NODE_ENV: "production",
    CONTROL_CENTER_BIND_HOST: "127.0.0.1",
    CONTROL_CENTER_AUTH_MODE: "test-disabled",
  }), AuthConfigurationError);
});

test("OIDC passkey auth rejects all local password verifier settings", () => {
  const env = completeOidcEnv();
  assert.throws(() => readAuthConfig({
    ...env,
    CONTROL_CENTER_ADMIN_PASSWORD_SHA256: "not-a-valid-fallback",
  }), /Local password authentication is not supported/);
  assert.throws(() => readAuthConfig({
    ...env,
    CONTROL_CENTER_OIDC_CLIENT_SECRET: "must-not-be-used",
  }), /public-client PKCE/);
});

test("OIDC authorization endpoint must stay under the exact issuer", () => {
  assert.throws(() => readAuthConfig({
    ...completeOidcEnv(),
    CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: "https://attacker.example.test/authorize",
  }), /exact configured OIDC issuer/);
});

test("production OIDC token and JWKS endpoints require issuer-bound HTTPS", () => {
  const issuer = "https://identity.example.test/realms/platform";
  const production = {
    ...completeOidcEnv(),
    CONTROL_CENTER_ENV: "production",
    CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: `${issuer}/protocol/openid-connect/token`,
    CONTROL_CENTER_OIDC_JWKS_URI: `${issuer}/protocol/openid-connect/certs`,
  };
  const accepted = readAuthConfig(production);
  assert.equal(accepted.tokenEndpoint, `${issuer}/protocol/openid-connect/token`);
  assert.equal(accepted.jwksUri, `${issuer}/protocol/openid-connect/certs`);
  assert.throws(() => readAuthConfig({
    ...production,
    NODE_TLS_REJECT_UNAUTHORIZED: "0",
  }), /OIDC TLS certificate verification must remain enabled/);
  assert.throws(() => readAuthConfig({
    ...production,
    CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: "http://keycloak:8080/realms/platform/protocol/openid-connect/token",
  }), /CONTROL_CENTER_OIDC_TOKEN_ENDPOINT must use HTTPS under the exact configured OIDC issuer/);
  assert.throws(() => readAuthConfig({
    ...production,
    CONTROL_CENTER_OIDC_JWKS_URI: "http://keycloak:8080/realms/platform/protocol/openid-connect/certs",
  }), /CONTROL_CENTER_OIDC_JWKS_URI must use HTTPS under the exact configured OIDC issuer/);
  assert.throws(() => readAuthConfig({
    ...production,
    CONTROL_CENTER_OIDC_JWKS_URI: "https://attacker.example.test/realms/platform/protocol/openid-connect/certs",
  }), /CONTROL_CENTER_OIDC_JWKS_URI must use HTTPS under the exact configured OIDC issuer/);
  assert.throws(() => readAuthConfig({
    ...production,
    CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: "https://identity.example.test/realms/platform-lookalike/token",
  }), /CONTROL_CENTER_OIDC_TOKEN_ENDPOINT must use HTTPS under the exact configured OIDC issuer/);
  for (const tokenEndpoint of [
    "//identity.example.test/realms/platform/protocol/openid-connect/token",
    "https://identity.example.test@attacker.example.test/realms/platform/protocol/openid-connect/token",
    "https://identity.example.test:444/realms/platform/protocol/openid-connect/token",
    "https://identity.example.test/realms/other/protocol/openid-connect/token",
  ]) {
    assert.throws(() => readAuthConfig({
      ...production,
      CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: tokenEndpoint,
    }), /CONTROL_CENTER_OIDC_TOKEN_ENDPOINT/);
  }
});

test("database admin ForwardAuth endpoint requires a fresh owner session", async () => {
  const auth = await createControlCenterAuth({ env: completeOidcEnv() });
  const request = { method: "GET" };
  const target = new URL("https://portal.example.test/control/internal/database-admin-authorize");
  const now = Date.now();
  const session = (role, authTime) => ({ ok: true, role, identity: { authTime } });
  try {
    assert.equal(auth.authorize(request, target, { ok: false, status: 401 }).status, 401);
    assert.equal(auth.authorize(request, target, session("viewer", new Date(now).toISOString())).status, 403);
    assert.equal(auth.authorize(request, target, session("admin", new Date(now).toISOString())).status, 403);
    assert.equal(auth.authorize(request, target, session("owner", new Date(now - 301_000).toISOString())).status, 428);
    assert.equal(auth.authorize(request, target, session("owner", "malformed")).status, 428);
    assert.equal(auth.authorize(request, target, session("owner", new Date(now + 60_000).toISOString())).status, 428);
    assert.equal(auth.authorize(request, target, session("owner", new Date(now).toISOString())).ok, true);
  } finally {
    await auth.close();
  }
});

test("memory auth store consumes transactions once and revokes sessions", async () => {
  const store = new MemoryAuthStore();
  const transaction = {
    stateHash: "state-hash",
    nonceHash: "nonce-hash",
    codeVerifier: "a".repeat(64),
    expiresAt: new Date(Date.now() + 60_000),
  };
  await store.createTransaction(transaction);
  assert.equal((await store.consumeTransaction(transaction.stateHash)).nonceHash, transaction.nonceHash);
  assert.equal(await store.consumeTransaction(transaction.stateHash), null);

  await store.createSession({
    tokenHash: "session-hash",
    subject: "owner",
    role: "owner",
    roles: ["owner"],
    acr: "urn:platform:loa:passkey",
    amr: ["webauthn"],
    authTime: new Date(),
    expiresAt: new Date(Date.now() + 60_000),
  });
  assert.equal((await store.getSession("session-hash", 60)).role, "owner");
  await store.revokeSession("session-hash");
  assert.equal(await store.getSession("session-hash", 60), null);
});

test("provider scope advisory keys are PostgreSQL-text-safe and preserve tuple boundaries", () => {
  const key = providerScopeAdvisoryLockKey("issuer\0segment", "subject", "owner\0segment");
  assert.equal(key.includes("\0"), false);
  assert.deepEqual(JSON.parse(key), ["issuer\0segment", "subject", "owner\0segment"]);
  assert.notEqual(
    providerScopeAdvisoryLockKey("issuer", "subject\0owner", "value"),
    providerScopeAdvisoryLockKey("issuer\0subject", "owner", "value"),
  );
});

test("memory auth store revokes by issuer sid and subject with replay protection", async () => {
  const store = new MemoryAuthStore();
  const issuer = "https://identity.example.test/realms/platform";
  const subject = "owner-subject";
  const authTime = new Date(Date.now() - 60_000);
  const expiresAt = new Date(Date.now() + 10 * 60_000);
  const session = (tokenHash, sessionId) => ({
    tokenHash,
    csrfHash: "f".repeat(64),
    policyVersion: "1",
    subject,
    role: "owner",
    roles: ["owner"],
    acr: "urn:platform:loa:passkey",
    amr: ["webauthn"],
    authTime,
    issuer,
    sessionId,
    expiresAt,
  });
  await store.createSession(session("a".repeat(64), "sid-a"));
  await store.createSession(session("b".repeat(64), "sid-b"));
  const issuedAt = new Date();
  const receiptExpiry = new Date(Date.now() + 20 * 60_000);
  const sidResult = await store.consumeProviderRevocation({
    issuer,
    eventType: "http://schemas.openid.net/event/backchannel-logout",
    jtiHash: "1".repeat(64),
    issuedAt,
    expiresAt: receiptExpiry,
    sid: "sid-a",
    subject,
  });
  assert.deepEqual(sidResult, { replayed: false, revoked: 1 });
  assert.equal(await store.getSession("a".repeat(64), 60), null);
  assert.equal((await store.getSession("b".repeat(64), 60)).sessionId, "sid-b");
  assert.deepEqual(await store.consumeProviderRevocation({
    issuer,
    eventType: "http://schemas.openid.net/event/backchannel-logout",
    jtiHash: "1".repeat(64),
    issuedAt,
    expiresAt: receiptExpiry,
    sid: "sid-a",
    subject,
  }), { replayed: true, revoked: 0 });
  const subjectResult = await store.consumeProviderRevocation({
    issuer,
    eventType: "urn:platform-infrastructure:event:account-disabled",
    jtiHash: "2".repeat(64),
    issuedAt,
    expiresAt: receiptExpiry,
    sid: "",
    subject,
  });
  assert.deepEqual(subjectResult, { replayed: false, revoked: 1 });
  assert.equal(await store.getSession("b".repeat(64), 60), null);
  await assert.rejects(
    store.createSession(session("c".repeat(64), "sid-c")),
    /was revoked/,
  );
});

function completeOidcEnv() {
  return {
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "test",
    CONTROL_CENTER_BIND_HOST: "127.0.0.1",
    CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
    CONTROL_CENTER_AUTH_STORE: "memory",
    CONTROL_CENTER_OIDC_ISSUER: "https://identity.example.test/realms/platform",
    CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: "https://identity.example.test/realms/platform/protocol/openid-connect/auth",
    CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: "http://127.0.0.1/token",
    CONTROL_CENTER_OIDC_JWKS_URI: "http://127.0.0.1/jwks",
    CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
    CONTROL_CENTER_OIDC_CLIENT_ID: "platform-control-center",
    CONTROL_CENTER_OIDC_REQUIRED_ACR: "urn:platform:loa:passkey",
  };
}
