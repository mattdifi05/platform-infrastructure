import assert from "node:assert/strict";
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
    assert.equal((await auth.authenticate(request({ address: "203.0.113.10", mutation: false }))).status, 403);
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
