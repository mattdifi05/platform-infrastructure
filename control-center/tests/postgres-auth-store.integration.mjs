import assert from "node:assert/strict";
import { PostgresAuthStore } from "../auth/oidc.mjs";

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) throw new Error("TEST_DATABASE_URL is required.");

const store = new PostgresAuthStore(databaseUrl);
try {
  await store.ready();
  const transaction = {
    stateHash: "a".repeat(64),
    nonceHash: "b".repeat(64),
    codeVerifier: "c".repeat(64),
    expiresAt: new Date(Date.now() + 60_000),
  };
  await store.createTransaction(transaction);
  assert.equal((await store.consumeTransaction(transaction.stateHash)).nonceHash, transaction.nonceHash);
  assert.equal(await store.consumeTransaction(transaction.stateHash), null);

  const session = {
    tokenHash: "d".repeat(64),
    subject: "test-owner",
    email: "owner@example.test",
    displayName: "Test Owner",
    role: "owner",
    roles: ["owner"],
    acr: "urn:platform:loa:passkey",
    amr: ["webauthn"],
    authTime: new Date(),
    issuer: "https://identity.example.test/realms/platform",
    sessionId: "test-session",
    keyId: "test-key",
    expiresAt: new Date(Date.now() + 60_000),
  };
  await store.createSession(session);
  assert.equal((await store.getSession(session.tokenHash, 60)).role, "owner");
  await store.revokeSession(session.tokenHash);
  assert.equal(await store.getSession(session.tokenHash, 60), null);
  process.stdout.write("POSTGRES_AUTH_STORE_OK\n");
} finally {
  await store.close();
}
