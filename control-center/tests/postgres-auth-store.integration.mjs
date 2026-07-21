import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import pg from "pg";
import { PostgresAuthStore } from "../auth/oidc.mjs";

const { Pool } = pg;
const databaseUrl = process.env.TEST_DATABASE_URL;
const issuer = "https://identity.example.test/realms/platform";
const otherIssuer = "https://other-identity.example.test/realms/platform";
const subject = "test-owner";
const adminPool = databaseUrl
  ? new Pool({ connectionString: withApplicationName(databaseUrl, "oidc-backchannel-admin") })
  : null;
const stores = [];
let hashCounter = 0;

if (!databaseUrl) {
  process.stdout.write("POSTGRES_AUTH_STORE_PROVIDER_REVOCATION_NOT_RUN: TEST_DATABASE_URL is not set\n");
} else if (process.env.TEST_DATABASE_DISPOSABLE !== "1") {
  throw new Error("TEST_DATABASE_DISPOSABLE=1 is required because this test recreates control_auth.");
} else try {
  await adminPool.query("drop schema if exists control_auth cascade");
  for (const migration of [
    "../migrations/001_auth_sessions.sql",
    "../migrations/002_session_security.sql",
    "../migrations/003_oidc_provider_revocation.sql",
  ]) {
    await adminPool.query(readFileSync(new URL(migration, import.meta.url), "utf8"));
  }

  const store = authStore("oidc-backchannel-base");
  await store.ready();
  const transaction = {
    stateHash: nextHash(),
    nonceHash: nextHash(),
    codeVerifier: "c".repeat(64),
    throttleKeyHash: nextHash(),
    expiresAt: new Date(Date.now() + 60_000),
  };
  await store.createTransaction(transaction);
  assert.equal((await store.consumeTransaction(transaction.stateHash)).nonceHash, transaction.nonceHash);
  assert.equal(await store.consumeTransaction(transaction.stateHash), null);

  const authenticationTime = new Date(Date.now() - 60_000);
  const sidA = session({ issuer, subject, sessionId: "sid-a", authTime: authenticationTime });
  const sidB = session({ issuer, subject, sessionId: "sid-b", authTime: authenticationTime });
  const otherIssuerSession = session({ issuer: otherIssuer, subject, sessionId: "sid-a", authTime: authenticationTime });
  await store.createSession(sidA);
  await store.createSession(sidB);
  await store.createSession(otherIssuerSession);

  const sidEventAt = new Date();
  const sidReceiptExpiry = new Date(Date.now() + 20 * 60_000);
  assert.deepEqual(await store.consumeProviderRevocation({
    issuer,
    eventType: "http://schemas.openid.net/event/backchannel-logout",
    jtiHash: nextHash(),
    issuedAt: sidEventAt,
    expiresAt: sidReceiptExpiry,
    sid: "sid-a",
    subject,
  }), { replayed: false, revoked: 1 });
  assert.equal(await store.getSession(sidA.tokenHash, 600), null);
  assert.equal((await store.getSession(sidB.tokenHash, 600)).sessionId, "sid-b");
  assert.equal((await store.getSession(otherIssuerSession.tokenHash, 600)).issuer, otherIssuer);

  const replayJti = nextHash();
  assert.deepEqual(await store.consumeProviderRevocation({
    issuer,
    eventType: "http://schemas.openid.net/event/backchannel-logout",
    jtiHash: replayJti,
    issuedAt: sidEventAt,
    expiresAt: sidReceiptExpiry,
    sid: "sid-missing",
    subject,
  }), { replayed: false, revoked: 0 });
  assert.deepEqual(await store.consumeProviderRevocation({
    issuer,
    eventType: "http://schemas.openid.net/event/backchannel-logout",
    jtiHash: replayJti,
    issuedAt: sidEventAt,
    expiresAt: sidReceiptExpiry,
    sid: "sid-b",
    subject,
  }), { replayed: true, revoked: 0 });
  assert.notEqual(await store.getSession(sidB.tokenHash, 600), null);

  const subjectEventAt = new Date(Date.now() - 2_000);
  assert.deepEqual(await store.consumeProviderRevocation({
    issuer,
    eventType: "urn:platform-infrastructure:event:authorization-changed",
    jtiHash: nextHash(),
    issuedAt: subjectEventAt,
    expiresAt: sidReceiptExpiry,
    sid: "",
    subject,
  }), { replayed: false, revoked: 1 });
  assert.equal(await store.getSession(sidB.tokenHash, 600), null);
  assert.notEqual(await store.getSession(otherIssuerSession.tokenHash, 600), null);

  const staleAfterSubjectLogout = session({
    issuer,
    subject,
    sessionId: "sid-stale-after-subject-logout",
    authTime: new Date(subjectEventAt.getTime() - 1_000),
  });
  await assert.rejects(store.createSession(staleAfterSubjectLogout), /was revoked/);
  const freshAfterSubjectLogout = session({
    issuer,
    subject,
    sessionId: "sid-fresh-after-subject-logout",
    authTime: new Date(subjectEventAt.getTime() + 1_000),
  });
  await store.createSession(freshAfterSubjectLogout);
  assert.notEqual(await store.getSession(freshAfterSubjectLogout.tokenHash, 600), null);

  for (const scopeType of ["sid", "subject"]) {
    await exerciseConcurrentCreateBeforeRevocation(store, scopeType);
    await exerciseConcurrentRevocationBeforeCreate(store, scopeType);
  }

  const throttleHash = nextHash();
  assert.equal((await store.registerLoginAttempt(throttleHash, 2, 60, 60)).allowed, true);
  assert.equal((await store.registerLoginAttempt(throttleHash, 2, 60, 60)).allowed, true);
  assert.equal((await store.registerLoginAttempt(throttleHash, 2, 60, 60)).allowed, false);
  await store.clearLoginThrottle(throttleHash);
  assert.equal((await store.registerLoginAttempt(throttleHash, 2, 60, 60)).allowed, true);
  process.stdout.write("POSTGRES_AUTH_STORE_PROVIDER_REVOCATION_OK\n");
} finally {
  await Promise.allSettled(stores.map((store) => store.close()));
  try {
    await adminPool.query("drop schema if exists control_auth cascade");
  } finally {
    await adminPool.end();
  }
}

async function exerciseConcurrentCreateBeforeRevocation(readStore, scopeType) {
  const raceSubject = `race-create-first-${scopeType}`;
  const raceSid = `sid-race-create-first-${scopeType}`;
  const raceSession = session({
    issuer,
    subject: raceSubject,
    sessionId: raceSid,
    authTime: new Date(Date.now() - 60_000),
  });
  const createStore = authStore(`oidc-race-create-first-${scopeType}`);
  const revocationStore = authStore(`oidc-race-revoke-second-${scopeType}`);
  const scopeValue = scopeType === "sid" ? raceSid : raceSubject;
  const scopeKey = `${issuer}\0${scopeType}\0${scopeValue}`;
  const blocker = await adminPool.connect();
  let createPromise;
  let revocationPromise;
  try {
    await blocker.query("select pg_advisory_lock(hashtextextended($1, 0))", [scopeKey]);
    createPromise = createStore.createSession(raceSession);
    await waitForLock(`oidc-race-create-first-${scopeType}`);
    revocationPromise = revocationStore.consumeProviderRevocation({
      issuer,
      eventType: scopeType === "sid"
        ? "http://schemas.openid.net/event/backchannel-logout"
        : "urn:platform-infrastructure:event:authorization-changed",
      jtiHash: nextHash(),
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 20 * 60_000),
      sid: scopeType === "sid" ? raceSid : "",
      subject: raceSubject,
    });
    await waitForLock(`oidc-race-revoke-second-${scopeType}`);
  } finally {
    await blocker.query("select pg_advisory_unlock(hashtextextended($1, 0))", [scopeKey]);
    blocker.release();
  }
  assert.equal((await Promise.allSettled([createPromise, revocationPromise])).every((item) => item.status === "fulfilled"), true);
  assert.equal(await readStore.getSession(raceSession.tokenHash, 600), null);
}

async function exerciseConcurrentRevocationBeforeCreate(readStore, scopeType) {
  const raceSubject = `race-revoke-first-${scopeType}`;
  const raceSid = `sid-race-revoke-first-${scopeType}`;
  const raceSession = session({
    issuer,
    subject: raceSubject,
    sessionId: raceSid,
    authTime: new Date(Date.now() - 60_000),
  });
  const createStore = authStore(`oidc-race-create-second-${scopeType}`);
  const revocationStore = authStore(`oidc-race-revoke-first-${scopeType}`);
  const scopeValue = scopeType === "sid" ? raceSid : raceSubject;
  const scopeKey = `${issuer}\0${scopeType}\0${scopeValue}`;
  const blocker = await adminPool.connect();
  let createPromise;
  let revocationPromise;
  try {
    await blocker.query("select pg_advisory_lock(hashtextextended($1, 0))", [scopeKey]);
    revocationPromise = revocationStore.consumeProviderRevocation({
      issuer,
      eventType: scopeType === "sid"
        ? "http://schemas.openid.net/event/backchannel-logout"
        : "urn:platform-infrastructure:event:account-disabled",
      jtiHash: nextHash(),
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 20 * 60_000),
      sid: scopeType === "sid" ? raceSid : "",
      subject: raceSubject,
    });
    await waitForLock(`oidc-race-revoke-first-${scopeType}`);
    createPromise = createStore.createSession(raceSession);
    await waitForLock(`oidc-race-create-second-${scopeType}`);
  } finally {
    await blocker.query("select pg_advisory_unlock(hashtextextended($1, 0))", [scopeKey]);
    blocker.release();
  }
  const [revocationResult, createResult] = await Promise.allSettled([revocationPromise, createPromise]);
  assert.equal(revocationResult.status, "fulfilled");
  assert.equal(createResult.status, "rejected");
  assert.match(String(createResult.reason?.message || createResult.reason), /was revoked/);
  assert.equal(await readStore.getSession(raceSession.tokenHash, 600), null);
}

async function waitForLock(applicationName) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await adminPool.query(
      `select 1 from pg_stat_activity
       where datname=current_database() and application_name=$1 and wait_event_type='Lock'
       limit 1`,
      [applicationName],
    );
    if (result.rowCount === 1) return;
    await delay(25);
  }
  throw new Error(`Timed out waiting for PostgreSQL advisory lock: ${applicationName}`);
}

function authStore(applicationName) {
  const store = new PostgresAuthStore(withApplicationName(databaseUrl, applicationName));
  stores.push(store);
  return store;
}

function withApplicationName(connectionString, applicationName) {
  const url = new URL(connectionString);
  url.searchParams.set("application_name", applicationName);
  return url.toString();
}

function nextHash() {
  hashCounter += 1;
  return hashCounter.toString(16).padStart(64, "0");
}

function session({ issuer: sessionIssuer, subject: sessionSubject, sessionId, authTime }) {
  return {
    tokenHash: nextHash(),
    csrfHash: nextHash(),
    policyVersion: "test-policy-v1",
    subject: sessionSubject,
    email: `${sessionSubject}@example.test`,
    displayName: sessionSubject,
    role: "owner",
    roles: ["owner"],
    acr: "urn:platform:loa:passkey",
    amr: ["webauthn"],
    authTime,
    issuer: sessionIssuer,
    sessionId,
    keyId: "test-key",
    expiresAt: new Date(Date.now() + 10 * 60_000),
  };
}
