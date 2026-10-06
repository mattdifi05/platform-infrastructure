import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";

import {
  AuthConfigurationError,
  AuthRequestError,
  createControlCenterAuth,
  readAuthConfig,
} from "../auth/app-passkey.mjs";
import { createFirstConfiguration, FIRST_CONFIGURATION_STATES } from "../first-configuration/index.mjs";
import { DATABASE_ADMIN_AUTHORIZATION_PATH } from "../auth/database-admin-gate.mjs";

const ORIGIN = "https://portal.platform-infrastructure.com";
const HOST = "portal.platform-infrastructure.com";

function env(overrides = {}) {
  return {
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "local_private",
    CONTROL_CENTER_AUTH_MODE: "app-passkey",
    CONTROL_CENTER_AUTH_STORE: "memory",
    CONTROL_CENTER_PUBLIC_ORIGIN: ORIGIN,
    CONTROL_CENTER_AUTH_RP_ID: HOST,
    CONTROL_CENTER_AUTH_RP_NAME: "Platform Control Center",
    CONTROL_CENTER_FIRST_CONFIGURATION_MODE: "required",
    CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME: "admin",
    CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL: "admin@example.com",
    CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "192.168.0.0/16",
    CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12",
    ...overrides,
  };
}

function request({ host = HOST, origin = ORIGIN, address = "192.168.1.24", mutation = true } = {}) {
  return {
    method: "POST",
    socket: { remoteAddress: address },
    headers: {
      host,
      ...(mutation ? { origin, "sec-fetch-site": "same-origin" } : {}),
    },
  };
}

test("app-passkey config is standalone with an exact origin, durable credential and one-day session", () => {
  const config = readAuthConfig(env());
  assert.equal(config.mode, "app-passkey");
  assert.equal(config.publicOrigin, ORIGIN);
  assert.equal(config.publicHost, HOST);
  assert.equal(config.rpId, HOST);
  assert.equal(config.passkeyTtlSeconds, 315_360_000);
  assert.equal(config.sessionMaxAgeSeconds, 86_400);
  assert.equal(config.challengeTtlSeconds, 300);
});

test("app-passkey config has no external identity-provider material", () => {
  const config = readAuthConfig(env());
  for (const key of ["issuer", "clientId", "authorizationEndpoint", "tokenEndpoint"]) {
    assert.equal(Object.hasOwn(config, key), false, key);
  }
  assert.throws(
    () => readAuthConfig(env({ CONTROL_CENTER_PUBLIC_ORIGIN: "http://portal.platform-infrastructure.com" })),
    AuthConfigurationError,
  );
});

test("mutation validation caches form payload for the authorized handler", async () => {
  const auth = await createControlCenterAuth({ env: env() });
  try {
    const req = Readable.from(["action=backup&scope=application&projectId=stream"]);
    req.method = "POST";
    req.socket = { remoteAddress: "192.168.1.24" };
    req.headers = {
      host: HOST,
      origin: ORIGIN,
      "sec-fetch-site": "same-origin",
      "content-type": "application/x-www-form-urlencoded",
      "x-csrf-token": "csrf-token",
    };
    const result = await auth.validateMutation(req, new URL(`${ORIGIN}/actions/backup-command`), {
      ok: true,
      identity: { csrfToken: "csrf-token" },
    });
    assert.equal(result.ok, true);
    assert.deepEqual(req.controlCenterPayload, {
      action: "backup",
      scope: "application",
      projectId: "stream",
    });
  } finally {
    await auth.close();
  }
});

test("database admin ForwardAuth accepts the exact public host only from a trusted proxy", async () => {
  const auth = await createControlCenterAuth({ env: env() });
  try {
    const forwardedRequest = request({ host: "control-center:8080", address: "172.20.0.10", mutation: false });
    forwardedRequest.method = "GET";
    forwardedRequest.url = DATABASE_ADMIN_AUTHORIZATION_PATH;
    forwardedRequest.headers["x-forwarded-host"] = HOST;
    forwardedRequest.headers["x-forwarded-for"] = "192.168.1.24";
    assert.equal(auth.assertRequest(forwardedRequest).clientAddress, "192.168.1.24");

    for (const overrides of [
      { address: "192.168.1.24" },
      { url: "/control/internal/another-endpoint" },
      { forwardedHost: "phpmyadmin.platform-infrastructure.com" },
      { forwardedHost: `${HOST},attacker.example` },
    ]) {
      const rejected = request({ host: "control-center:8080", address: overrides.address || "172.20.0.10", mutation: false });
      rejected.method = "GET";
      rejected.url = overrides.url || DATABASE_ADMIN_AUTHORIZATION_PATH;
      rejected.headers["x-forwarded-host"] = overrides.forwardedHost || HOST;
      rejected.headers["x-forwarded-for"] = "192.168.1.24";
      assert.throws(
        () => auth.assertRequest(rejected),
        (error) => error instanceof AuthRequestError && error.status === 421,
      );
    }
  } finally {
    await auth.close();
  }
});

test("first configuration accepts one exact IPv6 client through trusted proxies without trusting a spoofed address", async () => {
  const client = "2001:db8:56f5:b90c:8c01:7ee3:a3c9:2a";
  const auth = await createControlCenterAuth({ env: env({
    CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: `${client}/128`,
    CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS:
      "172.23.0.2/32,172.22.0.2/32,172.30.250.2/32,172.30.250.1/32,127.0.0.0/8",
  }) });
  try {
    const req = request({ address: "172.23.0.2", mutation: false });
    req.url = "/first-configuration";
    req.headers["x-forwarded-for"] = `2001:db8::bad, ${client}, 127.0.0.1, 172.30.250.1, 172.30.250.2`;
    assert.equal(auth.assertRequest(req).clientAddress, client);

    req.headers["x-forwarded-for"] = "2001:db8::bad, 127.0.0.1, 172.30.250.1, 172.30.250.2";
    assert.throws(() => auth.assertRequest(req), (error) => error instanceof AuthRequestError && error.status === 403);
  } finally {
    await auth.close();
  }
});

test("first enrollment needs a private short-lived token and reviewed IPv6 CIDR even when the address rotates", async (t) => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "cc-first-enrollment-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const tokenFile = path.join(directory, "token.json");
  const token = "ab".repeat(32);
  const tokenSha256 = createHash("sha256").update(token).digest("hex");
  const issuedAt = new Date(Date.now() - 30_000).toISOString();
  const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
  writeFileSync(tokenFile, JSON.stringify({ tokenSha256, issuedAt, expiresAt }), { mode: 0o600 });
  const configured = env({
    CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "2001:db8:abcd:55::/64",
    CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_FILE: tokenFile,
  });
  const auth = await createControlCenterAuth({ env: configured });
  try {
    const firstAddress = request({ address: "2001:db8:abcd:55::1" });
    const rotatedAddress = request({ address: "2001:db8:abcd:55::2" });
    const outsideCidr = request({ address: "2001:db8:abcd:56::1" });
    for (const supplied of [undefined, "cd".repeat(32)]) {
      await assert.rejects(auth.beginPasskeyRegistration(firstAddress, supplied),
        (error) => error instanceof AuthRequestError && error.status === 403);
    }
    await assert.rejects(auth.beginPasskeyRegistration(outsideCidr, token),
      (error) => error instanceof AuthRequestError && error.status === 403);
    assert.equal(
      auth.assertRequest(firstAddress, { firstEnrollment: true }).peerHash,
      auth.assertRequest(rotatedAddress, { firstEnrollment: true }).peerHash,
    );
    const options = await auth.beginPasskeyRegistration(firstAddress, token);
    assert.match(options.challenge, /^[A-Za-z0-9_-]{43}$/);
    await assert.rejects(auth.completePasskeyRegistration(rotatedAddress, {
      bootstrapToken: "cd".repeat(32), challenge: options.challenge,
    }), (error) => error instanceof AuthRequestError && error.status === 403);
    await assert.rejects(auth.completePasskeyRegistration(rotatedAddress, {
      bootstrapToken: token, challenge: options.challenge, credential: { type: "not-public-key" },
    }), (error) => error instanceof AuthRequestError && error.status === 400);
    await auth.store.createPasskey({
      id: "existing-passkey", userId: auth.config.adminSubject, webauthnUserId: auth.config.webauthnUserId,
      publicKey: new Uint8Array([1]), counter: 0, transports: [], deviceType: "singleDevice",
      backedUp: false, createdAt: new Date(), expiresAt: new Date(Date.now() + 86_400_000),
    });
    await assert.rejects(auth.beginPasskeyRegistration(firstAddress),
      (error) => error instanceof AuthRequestError && error.status === 409);
    await assert.rejects(auth.completePasskeyRegistration(rotatedAddress, {}),
      (error) => error instanceof AuthRequestError && error.status === 409);
  } finally {
    await auth.close();
  }
  writeFileSync(tokenFile, JSON.stringify({ tokenSha256,
    issuedAt: new Date(Date.now() - 6 * 60_000).toISOString(),
    expiresAt: new Date(Date.now() - 60_000).toISOString() }), { mode: 0o600 });
  const expired = await createControlCenterAuth({ env: configured });
  try {
    await assert.rejects(expired.beginPasskeyRegistration(request({ address: "2001:db8:abcd:55::3" }), token),
      (error) => error instanceof AuthRequestError && error.status === 403);
  } finally {
    await expired.close();
  }
  chmodSync(tokenFile, 0o644);
  assert.throws(() => readAuthConfig(configured), AuthConfigurationError);
});

test("registration and login options are generated for the exact portal origin", async () => {
  const auth = await createControlCenterAuth({ env: env() });
  try {
    const options = await auth.beginPasskeyRegistration(request());
    assert.equal(options.rp.id, HOST);
    assert.equal(options.rp.name, "Platform Control Center");
    assert.equal(options.user.name, "admin");
    assert.match(options.challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.match(options.user.id, /^[A-Za-z0-9_-]{43}$/);

    const peerHash = options.challenge && auth.store.webauthnChallenges.get(options.challenge
      ? [...auth.store.webauthnChallenges.keys()][0]
      : "")?.peerHash;
    assert.ok(peerHash);
    const consumed = await auth.store.consumeWebAuthnChallenge({
      challengeHash: [...auth.store.webauthnChallenges.keys()][0],
      challenge: options.challenge,
      flow: "registration",
      userId: auth.config.adminSubject,
      peerHash,
    });
    assert.equal(consumed.challenge, options.challenge);
    assert.equal(await auth.store.consumeWebAuthnChallenge({
      challengeHash: [...auth.store.webauthnChallenges.keys()][0] || "missing",
      challenge: options.challenge,
      flow: "registration",
      userId: auth.config.adminSubject,
      peerHash,
    }), null);

    await assert.rejects(
      auth.beginPasskeyRegistration(request({ origin: "https://evil.example" })),
      (error) => error instanceof AuthRequestError && error.status === 403,
    );
    await assert.rejects(
      auth.beginPasskeyRegistration(request({ host: "auth.platform-infrastructure.com" })),
      (error) => error instanceof AuthRequestError && error.status === 421,
    );
  } finally {
    await auth.close();
  }
});

test("one passkey completes direct first configuration and duplicate credentials never overwrite", async () => {
  const auth = await createControlCenterAuth({ env: env() });
  try {
    const setup = await createFirstConfiguration({ env: env(), auth });
    assert.equal(setup.direct, true);
    assert.equal((await setup.status()).state, FIRST_CONFIGURATION_STATES.REQUIRED);

    const credential = {
      id: "credential-one",
      userId: auth.config.adminSubject,
      webauthnUserId: auth.config.webauthnUserId,
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      transports: ["internal"],
      deviceType: "singleDevice",
      backedUp: false,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 86_400_000),
    };
    assert.equal(await auth.store.createPasskey(credential), true);
    assert.equal(await auth.store.createPasskey({ ...credential, publicKey: new Uint8Array([9, 9, 9]) }), false);
    assert.equal(await auth.store.createPasskey({ ...credential, id: "credential-two" }), false);
    assert.deepEqual([...auth.store.passkeys.get(credential.id).publicKey], [1, 2, 3]);
    const state = await setup.status();
    assert.equal(state.state, FIRST_CONFIGURATION_STATES.COMPLETE);
    assert.equal(state.complete, true);
    assert.equal(state.passkeyCount, 1);

    const loginOptions = await auth.beginLogin(request());
    assert.equal(loginOptions.rpId, HOST);
    assert.equal((await auth.authenticate(request({ host: "auth.platform-infrastructure.com", mutation: false }))).status, 421);
    const changedAddress = request({ address: "203.0.113.10" });
    assert.equal((await auth.authenticate(changedAddress)).status, 401);
    changedAddress.headers["x-forwarded-for"] = "192.168.1.24";
    assert.equal(auth.assertRequest(changedAddress).clientAddress, "203.0.113.10");
    assert.equal((await auth.beginLogin(changedAddress)).rpId, HOST);
    const session = await auth.createSessionResult();
    changedAddress.headers.cookie = session.cookies.map((cookie) => cookie.split(";", 1)[0]).join("; ");
    const authenticated = await auth.authenticate(changedAddress);
    assert.equal(authenticated.ok, true);
    const changedAddressMutation = Readable.from([]);
    changedAddressMutation.method = "POST";
    changedAddressMutation.socket = changedAddress.socket;
    changedAddressMutation.headers = { ...changedAddress.headers };
    const mutationUrl = new URL(`${ORIGIN}/actions/backup-command`);
    assert.equal((await auth.validateMutation(changedAddressMutation, mutationUrl, authenticated)).error, "csrf_token_rejected");
    changedAddressMutation.headers["x-csrf-token"] = authenticated.identity.csrfToken;
    assert.equal((await auth.validateMutation(changedAddressMutation, mutationUrl, authenticated)).ok, true);
    const wrongOrigin = request({ address: "203.0.113.10", origin: "https://evil.example" });
    await assert.rejects(auth.beginLogin(wrongOrigin), (error) => error instanceof AuthRequestError && error.status === 403);
    await assert.rejects(auth.beginPasskeyRegistration(changedAddress), (error) => error instanceof AuthRequestError && error.status === 403);
    await assert.rejects(
      auth.completeLogin(request(), {
        challenge: loginOptions.challenge,
        credential: { type: "not-public-key" },
      }),
      (error) => error instanceof AuthRequestError && error.status === 400,
    );
  } finally {
    await auth.close();
  }
});
