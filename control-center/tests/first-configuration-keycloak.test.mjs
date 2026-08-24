import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  KeycloakFirstConfigurationAdapter,
} from "../first-configuration/keycloak.mjs";

const ADMIN_BASE_URL = "https://auth.example.test/admin/realms/platform";
const TOKEN_ENDPOINT = "https://auth.example.test/realms/platform/protocol/openid-connect/token";
const PASSKEY_FLOW = "platform-passkey-browser";
const PASSWORDLESS_ACTION = "webauthn-register-passwordless";
const FIXTURE_SERVICE_TOKEN = ["bounded", "test", "service", "token"].join("-");

test("passkey cutover performs the browser binding as its only write and retains the password", async (t) => {
  const harness = createHarness(t);

  const result = await harness.adapter.applyPasskeyOnlyCutover({
    subject: "admin-1",
    username: "owner@example.test",
    independenceConfirmed: true,
  });

  assert.equal(result.passkeyCount, 2);
  assert.equal(harness.state.realm.browserFlow, PASSKEY_FLOW);
  assert.deepEqual(harness.state.writes, [{
    method: "PUT",
    path: "",
    query: "",
    body: { browserFlow: PASSKEY_FLOW },
  }]);
  assert.equal(harness.state.credentials.some((credential) => credential.type === "password"), true);
});

test("post-bind drift causes only the bounded browser-flow rollback", async (t) => {
  const harness = createHarness(t, { postBindDrift: true });

  await assert.rejects(
    harness.adapter.applyPasskeyOnlyCutover({
      subject: "admin-1",
      username: "owner@example.test",
      independenceConfirmed: true,
    }),
    (error) => {
      assert.equal(error.code, "first_configuration_passkey_contract_not_ready");
      assert.match(error.message, /client\.webOrigins/);
      return true;
    },
  );

  assert.equal(harness.state.realm.browserFlow, "browser");
  assert.deepEqual(harness.state.writes, [
    { method: "PUT", path: "", query: "", body: { browserFlow: PASSKEY_FLOW } },
    { method: "PUT", path: "", query: "", body: { browserFlow: "browser" } },
  ]);
  assert.equal(harness.state.credentials.some((credential) => credential.type === "password"), true);
});

test("an unexpected existing browser flow is rejected without mutation", async (t) => {
  const harness = createHarness(t, { browserFlow: "foreign-browser-flow" });

  await assert.rejects(
    harness.adapter.applyPasskeyOnlyCutover({
      subject: "admin-1",
      username: "owner@example.test",
      independenceConfirmed: true,
    }),
    (error) => {
      assert.equal(error.code, "first_configuration_passkey_contract_not_ready");
      return true;
    },
  );

  assert.deepEqual(harness.state.writes, []);
  assert.equal(harness.state.realm.browserFlow, "foreign-browser-flow");
});

test("retrying an already-bound cutover is idempotent", async (t) => {
  const harness = createHarness(t, { browserFlow: PASSKEY_FLOW });

  const result = await harness.adapter.applyPasskeyOnlyCutover({
    subject: "admin-1",
    username: "owner@example.test",
    independenceConfirmed: true,
  });

  assert.equal(result.passkeyCount, 2);
  assert.deepEqual(harness.state.writes, []);
});

test("first passkey-login completion removes passwords, revokes every admin session and retries idempotently", async (t) => {
  const harness = createHarness(t, {
    browserFlow: PASSKEY_FLOW,
    requiredActions: [PASSWORDLESS_ACTION, "VERIFY_PROFILE"],
    activeSessions: ["session-one", "session-two"],
  });

  const first = await harness.adapter.completeFirstPasskeyLogin({ subject: "admin-1" });

  assert.equal(first.passkeyCount, 2);
  assert.equal(harness.state.credentials.some((credential) => credential.type === "password"), false);
  assert.deepEqual(harness.state.user.requiredActions, ["VERIFY_PROFILE"]);
  assert.deepEqual(harness.state.activeSessions, []);
  assert.deepEqual(harness.state.writes, [
    {
      method: "DELETE",
      path: "/users/admin-1/credentials/password-1",
      query: "",
      body: undefined,
    },
    {
      method: "PUT",
      path: "/users/admin-1",
      query: "",
      body: {
        id: "admin-1",
        username: "owner@example.test",
        enabled: true,
        requiredActions: ["VERIFY_PROFILE"],
      },
    },
    {
      method: "POST",
      path: "/users/admin-1/logout",
      query: "",
      body: undefined,
    },
  ]);

  harness.state.writes.length = 0;
  const retry = await harness.adapter.completeFirstPasskeyLogin({ subject: "admin-1" });
  assert.equal(retry.passkeyCount, 2);
  assert.deepEqual(harness.state.writes, [{
    method: "POST",
    path: "/users/admin-1/logout",
    query: "",
    body: undefined,
  }]);
  assert.deepEqual(harness.state.activeSessions, []);
  assert.deepEqual(harness.state.user.requiredActions, ["VERIFY_PROFILE"]);
});

test("session revocation failure blocks first-login completion and a retry resumes after cleanup", async (t) => {
  const harness = createHarness(t, {
    browserFlow: PASSKEY_FLOW,
    activeSessions: ["session-one", "session-two"],
    logoutFailureOnce: true,
  });

  await assert.rejects(
    harness.adapter.completeFirstPasskeyLogin({ subject: "admin-1" }),
    (error) => {
      assert.equal(error.code, "first_configuration_identity_unavailable");
      return true;
    },
  );
  assert.equal(harness.state.credentials.some((credential) => credential.type === "password"), false);
  assert.deepEqual(harness.state.activeSessions, ["session-one", "session-two"]);

  const retry = await harness.adapter.completeFirstPasskeyLogin({ subject: "admin-1" });
  assert.equal(retry.passkeyCount, 2);
  assert.deepEqual(harness.state.activeSessions, []);
});

test("bootstrap-client disable reads the exact client, requires a terminal receipt and gates already-disabled retry", async (t) => {
  const harness = createHarness(t);

  const result = await harness.adapter.disableBootstrapClient();
  assert.deepEqual(result, { disabled: true, alreadyDisabled: false, verifiedByResponse: true });
  assert.equal(harness.state.bootstrapClient.enabled, false);
  assert.equal(harness.state.bootstrapClient.serviceAccountsEnabled, false);
  assert.equal(harness.state.bootstrapClientReadbacks, 1);
  assert.deepEqual(harness.state.writes, [{
    method: "PUT",
    path: "/clients/bootstrap-client-uuid",
    query: "",
    body: {
      id: "bootstrap-client-uuid",
      clientId: "platform-first-configuration",
      enabled: false,
      serviceAccountsEnabled: false,
    },
  }]);

  const retryHarness = createHarness(t, { bootstrapDisabled: true });
  await assert.rejects(
    retryHarness.adapter.disableBootstrapClient(),
    (error) => {
      assert.equal(error.code, "first_configuration_bootstrap_client_already_disabled");
      return true;
    },
  );
  assert.deepEqual(retryHarness.state.writes, []);

  const retry = await retryHarness.adapter.disableBootstrapClient({ allowAlreadyDisabled: true });
  assert.deepEqual(retry, { disabled: true, alreadyDisabled: true, verifiedByReadback: true });
  assert.deepEqual(retryHarness.state.writes, []);
});

test("invalid_client never proves bootstrap disable, including after an Admin REST retry", async (t) => {
  const staleSecret = createHarness(t, {
    adminUnauthorizedOnce: true,
    tokenSequence: [null, { status: 401, payload: { error: "invalid_client" } }],
  });
  await assert.rejects(
    staleSecret.adapter.disableBootstrapClient({ allowAlreadyDisabled: true }),
    (error) => {
      assert.equal(error.code, "first_configuration_keycloak_invalid_client");
      return true;
    },
  );
  assert.equal(staleSecret.state.bootstrapClient.enabled, true);
  assert.equal(staleSecret.state.tokenRequests, 2);
  assert.deepEqual(staleSecret.state.writes, []);

  const wrongSecret = createHarness(t, {
    tokenFailure: { status: 400, payload: { error: "invalid_client" } },
  });
  await assert.rejects(
    wrongSecret.adapter.disableBootstrapClient({ allowAlreadyDisabled: true }),
    (error) => {
      assert.equal(error.code, "first_configuration_keycloak_invalid_client");
      return true;
    },
  );
  assert.equal(wrongSecret.state.bootstrapClient.enabled, true);
  assert.deepEqual(wrongSecret.state.writes, []);

  const differentFailure = createHarness(t, {
    tokenFailure: { status: 401, payload: { error: "unauthorized_client" } },
  });
  await assert.rejects(
    differentFailure.adapter.disableBootstrapClient({ allowAlreadyDisabled: true }),
    (error) => {
      assert.equal(error.code, "first_configuration_identity_unavailable");
      return true;
    },
  );
  assert.deepEqual(differentFailure.state.writes, []);
});

test("a lost disable response completes only after authenticated disabled read-back", async (t) => {
  const harness = createHarness(t, { bootstrapDisableResponseLostOnce: true });

  await assert.rejects(
    harness.adapter.disableBootstrapClient({ allowAlreadyDisabled: true }),
    /lost bootstrap disable response/,
  );
  assert.equal(harness.state.bootstrapClient.enabled, false);

  const retry = await harness.adapter.disableBootstrapClient({ allowAlreadyDisabled: true });
  assert.deepEqual(retry, {
    disabled: true,
    alreadyDisabled: true,
    verifiedByReadback: true,
  });
  assert.equal(harness.state.bootstrapClientReadbacks, 2);
});

function createHarness(t, options = {}) {
  const root = mkdtempSync(path.join(tmpdir(), "first-configuration-keycloak-"));
  const secretFile = path.join(root, "client-secret");
  writeFileSync(secretFile, "test-only-keycloak-secret-00000001\n", { mode: 0o600 });
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const state = createState(options);
  const config = {
    adminBaseUrl: ADMIN_BASE_URL,
    tokenEndpoint: TOKEN_ENDPOINT,
    keycloakClientSecretFile: secretFile,
    clientId: "platform-first-configuration",
    controlCenterClientId: "platform-control-center",
    identityOrigin: "https://auth.example.test",
    publicOrigin: "https://portal.example.test",
    rpId: "auth.example.test",
    requiredAcr: "urn:platform:loa:passkey",
    minimumPasskeys: 2,
    adminUsername: "owner@example.test",
    ownerRole: "owner",
  };
  return {
    state,
    adapter: new KeycloakFirstConfigurationAdapter(config, { fetchImpl: createFetch(state, config) }),
  };
}

function createState(options) {
  const browserFlow = options.browserFlow || "browser";
  const bootstrapDisabled = options.bootstrapDisabled === true;
  return {
    tokenFailure: options.tokenFailure || null,
    tokenSequence: Array.isArray(options.tokenSequence) ? [...options.tokenSequence] : null,
    adminUnauthorizedOnce: options.adminUnauthorizedOnce === true,
    bootstrapDisableResponseLostOnce: options.bootstrapDisableResponseLostOnce === true,
    logoutFailureOnce: options.logoutFailureOnce === true,
    tokenRequests: 0,
    postBindDrift: options.postBindDrift === true,
    writes: [],
    bootstrapClientReadbacks: 0,
    activeSessions: Array.isArray(options.activeSessions) ? [...options.activeSessions] : [],
    realm: {
      realm: "platform",
      enabled: true,
      browserFlow,
      bruteForceProtected: true,
      resetPasswordAllowed: false,
      rememberMe: false,
      webAuthnPolicyRpId: "auth.example.test",
      webAuthnPolicyExtraOrigins: ["https://auth.example.test"],
      webAuthnPolicyUserVerificationRequirement: "required",
      webAuthnPolicyAvoidSameAuthenticatorRegister: true,
      webAuthnPolicyPasswordlessRpId: "auth.example.test",
      webAuthnPolicyPasswordlessExtraOrigins: ["https://auth.example.test"],
      webAuthnPolicyPasswordlessRequireResidentKey: "Yes",
      webAuthnPolicyPasswordlessUserVerificationRequirement: "required",
      webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: true,
      attributes: { "acr.loa.map": JSON.stringify({ "urn:platform:loa:passkey": 1 }) },
    },
    controlClient: {
      id: "control-client-uuid",
      clientId: "platform-control-center",
      enabled: true,
      protocol: "openid-connect",
      publicClient: true,
      bearerOnly: false,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      implicitFlowEnabled: false,
      serviceAccountsEnabled: false,
      fullScopeAllowed: true,
      authenticationFlowBindingOverrides: {},
      redirectUris: ["https://portal.example.test/auth/callback"],
      webOrigins: ["https://portal.example.test"],
      attributes: {
        "pkce.code.challenge.method": "S256",
        "backchannel.logout.url": "https://portal.example.test/auth/backchannel-logout",
        "backchannel.logout.session.required": "true",
        "backchannel.logout.revoke.offline.tokens": "true",
      },
      protocolMappers: [
        {
          name: "amr",
          protocol: "openid-connect",
          protocolMapper: "oidc-amr-mapper",
          config: { "id.token.claim": "true", "access.token.claim": "true" },
        },
        {
          name: "platform-realm-roles",
          protocol: "openid-connect",
          protocolMapper: "oidc-usermodel-realm-role-mapper",
          config: {
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "realm_access.roles",
            multivalued: "true",
          },
        },
        {
          name: "platform-auth-time",
          protocol: "openid-connect",
          protocolMapper: "oidc-usersessionmodel-note-mapper",
          config: {
            "user.session.note": "AUTH_TIME",
            "id.token.claim": "true",
            "claim.name": "auth_time",
            "jsonType.label": "long",
          },
        },
      ],
    },
    bootstrapClient: {
      id: "bootstrap-client-uuid",
      clientId: "platform-first-configuration",
      enabled: !bootstrapDisabled,
      serviceAccountsEnabled: !bootstrapDisabled,
    },
    user: {
      id: "admin-1",
      username: "owner@example.test",
      enabled: true,
      requiredActions: options.requiredActions || [PASSWORDLESS_ACTION],
    },
    credentials: [
      { id: "passkey-1", type: "webauthn-passwordless", userLabel: "Laptop", createdDate: 1_700_000_000_000 },
      { id: "passkey-2", type: "webauthn-passwordless", userLabel: "Phone", createdDate: 1_700_000_001_000 },
      { id: "password-1", type: "password" },
    ],
    adminRoles: [{ id: "owner-role-id", name: "owner" }],
  };
}

function createFetch(state, config) {
  return async (input, init = {}) => {
    const target = new URL(String(input));
    const method = String(init.method || "GET").toUpperCase();
    if (target.href === config.tokenEndpoint) {
      state.tokenRequests += 1;
      const sequencedFailure = state.tokenSequence?.[state.tokenRequests - 1];
      const tokenFailure = sequencedFailure || state.tokenFailure;
      if (tokenFailure) return jsonResponse(tokenFailure.status, tokenFailure.payload);
      return jsonResponse(200, { access_token: FIXTURE_SERVICE_TOKEN, expires_in: 300 });
    }
    if (!target.href.startsWith(`${config.adminBaseUrl}`)) return jsonResponse(404, { error: "outside_fixture" });
    assert.equal(init.headers?.authorization, `Bearer ${FIXTURE_SERVICE_TOKEN}`);
    if (state.adminUnauthorizedOnce) {
      state.adminUnauthorizedOnce = false;
      return jsonResponse(401, { error: "invalid_token" });
    }
    const pathname = target.pathname.slice(new URL(config.adminBaseUrl).pathname.length);
    const query = target.search.slice(1);
    const body = init.body === undefined ? undefined : JSON.parse(String(init.body));
    if (method !== "GET") state.writes.push({ method, path: pathname, query, body });

    if (pathname === "") {
      if (method === "GET") return jsonResponse(200, state.realm);
      if (method === "PUT") {
        state.realm = { ...state.realm, ...body };
        if (body.browserFlow === PASSKEY_FLOW && state.postBindDrift) {
          state.controlClient.webOrigins = ["https://drift.example.test"];
        }
        return emptyResponse(204);
      }
    }

    if (pathname === "/clients" && method === "GET") {
      const clientId = target.searchParams.get("clientId");
      if (clientId === state.controlClient.clientId) return jsonResponse(200, [state.controlClient]);
      if (clientId === state.bootstrapClient.clientId) return jsonResponse(200, [state.bootstrapClient]);
      return jsonResponse(200, []);
    }
    if (pathname === "/clients/control-client-uuid" && method === "GET") {
      return jsonResponse(200, state.controlClient);
    }
    if (pathname === "/clients/bootstrap-client-uuid") {
      if (method === "GET") {
        state.bootstrapClientReadbacks += 1;
        return jsonResponse(200, state.bootstrapClient);
      }
      if (method === "PUT") {
        state.bootstrapClient = { ...state.bootstrapClient, ...body };
        if (state.bootstrapDisableResponseLostOnce) {
          state.bootstrapDisableResponseLostOnce = false;
          throw new TypeError("lost bootstrap disable response");
        }
        return emptyResponse(204);
      }
    }
    if (pathname === "/clients/control-client-uuid/default-client-scopes" && method === "GET") {
      return jsonResponse(200, [{ id: "acr-scope-id", name: "acr", protocol: "openid-connect" }]);
    }
    if (pathname === "/client-scopes/acr-scope-id/protocol-mappers/models" && method === "GET") {
      return jsonResponse(200, [{
        name: "acr",
        protocol: "openid-connect",
        protocolMapper: "oidc-acr-mapper",
        config: { "id.token.claim": "true" },
      }]);
    }
    if (pathname === "/client-scopes/acr-scope-id/scope-mappings" && method === "GET") {
      return jsonResponse(200, { realmMappings: [], clientMappings: {} });
    }

    if (pathname === "/authentication/flows" && method === "GET") {
      return jsonResponse(200, [{
        id: "passkey-flow-id",
        alias: PASSKEY_FLOW,
        providerId: "basic-flow",
        builtIn: false,
        topLevel: true,
      }]);
    }
    if (pathname === `/authentication/flows/${PASSKEY_FLOW}/executions` && method === "GET") {
      return jsonResponse(200, [{
        id: "loa-subflow-execution-id",
        level: 0,
        authenticationFlow: true,
        displayName: "platform-passkey-loa",
        requirement: "CONDITIONAL",
        priority: 10,
        index: 0,
        flowId: "loa-flow-id",
      }]);
    }
    if (pathname === "/authentication/flows/loa-flow-id" && method === "GET") {
      return jsonResponse(200, {
        id: "loa-flow-id",
        alias: "platform-passkey-loa",
        providerId: "basic-flow",
        builtIn: false,
        topLevel: false,
      });
    }
    if (pathname === "/authentication/flows/platform-passkey-loa/executions" && method === "GET") {
      return jsonResponse(200, [
        {
          id: "loa-condition-execution-id",
          level: 0,
          providerId: "conditional-level-of-authentication",
          requirement: "REQUIRED",
          priority: 10,
          index: 0,
          authenticationConfig: "loa-condition-config-id",
        },
        {
          id: "webauthn-execution-id",
          level: 0,
          providerId: "webauthn-authenticator-passwordless",
          requirement: "REQUIRED",
          priority: 20,
          index: 1,
          authenticationConfig: "webauthn-config-id",
        },
      ]);
    }
    if (pathname === "/authentication/config/loa-condition-config-id" && method === "GET") {
      return jsonResponse(200, {
        id: "loa-condition-config-id",
        alias: "platform-passkey-loa-1",
        config: { "loa-condition-level": "1", "loa-max-age": "0" },
      });
    }
    if (pathname === "/authentication/config/webauthn-config-id" && method === "GET") {
      return jsonResponse(200, {
        id: "webauthn-config-id",
        alias: "platform-passkey-amr-webauthn",
        config: { "default.reference.value": "webauthn", "default.reference.maxAge": "300" },
      });
    }
    if (pathname === "/authentication/required-actions" && method === "GET") {
      return jsonResponse(200, [{
        alias: PASSWORDLESS_ACTION,
        providerId: PASSWORDLESS_ACTION,
        enabled: true,
      }]);
    }
    if (pathname === "/roles" && method === "GET") {
      return jsonResponse(200, [
        { id: "owner-role-id", name: "owner" },
        { id: "admin-role-id", name: "admin" },
        { id: "viewer-role-id", name: "viewer" },
      ]);
    }

    if (pathname === "/users/admin-1") {
      if (method === "GET") return jsonResponse(200, state.user);
      if (method === "PUT") {
        state.user = { ...state.user, ...body };
        return emptyResponse(204);
      }
    }
    if (pathname === "/users/admin-1/credentials" && method === "GET") {
      return jsonResponse(200, state.credentials);
    }
    if (pathname.startsWith("/users/admin-1/credentials/") && method === "DELETE") {
      const credentialId = decodeURIComponent(pathname.split("/").at(-1));
      const before = state.credentials.length;
      state.credentials = state.credentials.filter((credential) => credential.id !== credentialId);
      return emptyResponse(before === state.credentials.length ? 404 : 204);
    }
    if (pathname === "/users/admin-1/role-mappings/realm" && method === "GET") {
      return jsonResponse(200, state.adminRoles);
    }
    if (pathname === "/users/admin-1/logout" && method === "POST") {
      if (state.logoutFailureOnce) {
        state.logoutFailureOnce = false;
        return jsonResponse(500, { error: "temporary_logout_failure" });
      }
      state.activeSessions = [];
      return emptyResponse(204);
    }

    return jsonResponse(404, { error: "fixture_route_missing", method, pathname, query });
  };
}

function jsonResponse(status, payload) {
  const text = JSON.stringify(payload);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (name) => name.toLowerCase() === "content-length" ? String(Buffer.byteLength(text)) : null },
    async text() { return text; },
  };
}

function emptyResponse(status) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => "0" },
    async text() { return ""; },
  };
}
