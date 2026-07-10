import assert from "node:assert/strict";
import test from "node:test";
import {
  AuthConfigurationError,
  MemoryAuthStore,
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
  }), /must belong to the configured issuer/);
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

function completeOidcEnv() {
  return {
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "production",
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
