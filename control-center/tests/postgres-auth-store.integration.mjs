import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import pg from "pg";
import { PostgresAppPasskeyStore } from "../auth/app-passkey.mjs";

const { Pool } = pg;
const databaseUrl = process.env.TEST_DATABASE_URL;

if (!databaseUrl) {
  process.stdout.write("POSTGRES_APP_PASSKEY_STORE_NOT_RUN: TEST_DATABASE_URL is not set\n");
} else if (process.env.TEST_DATABASE_DISPOSABLE !== "1") {
  throw new Error("TEST_DATABASE_DISPOSABLE=1 is required because this test recreates control_auth.");
} else {
  const admin = new Pool({ connectionString: databaseUrl });
  let store;
  try {
    await admin.query("drop schema if exists control_auth cascade");
    await admin.query("drop role if exists control_center_runtime");
    await admin.query("create role control_center_runtime login password 'app-passkey-integration-runtime'");
    const migration = readFileSync(new URL("../migrations/001_app_passkey.sql", import.meta.url), "utf8");
    await admin.query(migration);
    await admin.query(migration);

    const legacy = await admin.query(
      `select to_regclass('control_auth.oidc_transactions') as transactions,
              to_regclass('control_auth.provider_event_tokens') as events,
              to_regclass('control_auth.first_configuration') as first_configuration`,
    );
    assert.deepEqual(legacy.rows[0], {
      transactions: null,
      events: null,
      first_configuration: null,
    });

    store = new PostgresAppPasskeyStore(withCredentials(
      databaseUrl,
      "control_center_runtime",
      "app-passkey-integration-runtime",
    ));
    await store.ready();

    const session = sessionRecord("1");
    await store.createSession(session);
    const loaded = await store.getSession(session.tokenHash, 3600);
    assert.equal(loaded.subject, session.subject);
    assert.equal(loaded.role, "owner");
    assert.equal(loaded.policyVersion, session.policyVersion);
    assert.equal(loaded.issuer, session.issuer);
    assert.equal(loaded.sessionId, "");
    await store.revokeSession(session.tokenHash);
    assert.equal(await store.getSession(session.tokenHash, 3600), null);

    const throttleKey = hex(2);
    assert.equal((await store.registerLoginAttempt(throttleKey, 2, 60, 60)).allowed, true);
    assert.equal((await store.registerLoginAttempt(throttleKey, 2, 60, 60)).allowed, true);
    assert.equal((await store.registerLoginAttempt(throttleKey, 2, 60, 60)).allowed, false);
    await store.clearLoginThrottle(throttleKey);
    assert.equal((await store.registerLoginAttempt(throttleKey, 2, 60, 60)).allowed, true);

    const challenge = {
      challengeHash: hex(3),
      challenge: "challenge_value_1234567890",
      flow: "authentication",
      userId: "app-admin:integration",
      peerHash: hex(4),
      expiresAt: new Date(Date.now() + 60_000),
    };
    await store.createWebAuthnChallenge(challenge);
    assert.equal((await store.consumeWebAuthnChallenge(challenge)).challenge, challenge.challenge);
    assert.equal(await store.consumeWebAuthnChallenge(challenge), null);

    const passkey = {
      id: "integration_credential_1",
      userId: "app-admin:integration",
      webauthnUserId: hex(5),
      publicKey: Buffer.from([1, 2, 3, 4]),
      counter: 0,
      transports: ["internal"],
      deviceType: "singleDevice",
      backedUp: false,
      expiresAt: new Date(Date.now() + 86_400_000),
    };
    assert.equal(await store.createPasskey(passkey), true);
    assert.equal(await store.createPasskey(passkey), false);
    assert.equal(await store.createPasskey({ ...passkey, id: "integration_credential_2" }), false);
    assert.equal((await store.listPasskeys(passkey.userId))[0].id, passkey.id);
    assert.equal(await store.updatePasskeyCounter({
      credentialId: passkey.id,
      userId: passkey.userId,
      counter: 2,
      deviceType: "multiDevice",
      backedUp: true,
    }), true);
    assert.equal(await store.updatePasskeyCounter({
      credentialId: passkey.id,
      userId: passkey.userId,
      counter: 1,
    }), false);
    const updated = (await store.listPasskeys(passkey.userId))[0];
    assert.equal(updated.counter, 2);
    assert.equal(updated.deviceType, "multiDevice");
    assert.equal(updated.backedUp, true);

    process.stdout.write("POSTGRES_APP_PASSKEY_STORE_OK\n");
  } finally {
    await store?.close();
    await admin.end();
  }
}

function withCredentials(connectionString, username, password) {
  const url = new URL(connectionString);
  url.username = username;
  url.password = password;
  return url.toString();
}

function hex(value) {
  return Number(value).toString(16).padStart(64, "0");
}

function sessionRecord(seed) {
  return {
    tokenHash: hex(seed),
    csrfHash: hex(Number(seed) + 20),
    policyVersion: "test-policy-v1",
    subject: "app-admin:integration",
    email: "admin@example.test",
    displayName: "Integration Admin",
    role: "owner",
    roles: ["owner"],
    acr: "app-passkey",
    amr: ["webauthn"],
    authTime: new Date(),
    issuer: "https://portal.example.test",
    sessionId: "",
    keyId: "",
    expiresAt: new Date(Date.now() + 86_400_000),
  };
}
