import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  evaluateKeycloakPasskeyReadiness,
  keycloakPasskeyStructuralDrift,
} from "../control-center/auth/keycloak-passkey-contract.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const reconciler = path.join(repositoryRoot, "scripts", "keycloak-passkey-reconcile.mjs");
const readiness = path.join(repositoryRoot, "scripts", "keycloak-passkey-readiness.sh");
const importPath = path.join(repositoryRoot, "keycloak", "import", "platform-realm.json");
const templatePath = path.join(repositoryRoot, "keycloak", "templates", "platform-realm.example.json");

const contractOptions = Object.freeze({
  identityOrigin: "https://auth.platform-infrastructure.com",
  publicOrigin: "https://portal.platform-infrastructure.com",
  rpId: "auth.platform-infrastructure.com",
  clientId: "platform-control-center",
  requiredAcr: "urn:platform:loa:passkey",
});

function validContractSnapshot({ binding = "staged", administrator = false } = {}) {
  return {
    realm: {
      enabled: true,
      browserFlow: binding === "cutover" ? "platform-passkey-browser" : "browser",
      bruteForceProtected: true,
      resetPasswordAllowed: false,
      rememberMe: false,
      webAuthnPolicyRpId: contractOptions.rpId,
      webAuthnPolicyExtraOrigins: [contractOptions.identityOrigin],
      webAuthnPolicyUserVerificationRequirement: "required",
      webAuthnPolicyAvoidSameAuthenticatorRegister: true,
      webAuthnPolicyPasswordlessRpId: contractOptions.rpId,
      webAuthnPolicyPasswordlessExtraOrigins: [contractOptions.identityOrigin],
      webAuthnPolicyPasswordlessRequireResidentKey: "Yes",
      webAuthnPolicyPasswordlessUserVerificationRequirement: "required",
      webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: true,
      attributes: { "acr.loa.map": JSON.stringify({ [contractOptions.requiredAcr]: 1 }) },
    },
    clients: [{
      id: "client-uuid",
      clientId: contractOptions.clientId,
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
      redirectUris: [`${contractOptions.publicOrigin}/auth/callback`],
      webOrigins: [contractOptions.publicOrigin],
      attributes: {
        "pkce.code.challenge.method": "S256",
        "backchannel.logout.url": `${contractOptions.publicOrigin}/auth/backchannel-logout`,
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
      ],
    }],
    flows: [{
      id: "flow-id",
      alias: "platform-passkey-browser",
      providerId: "basic-flow",
      builtIn: false,
      topLevel: true,
    }],
    topExecutions: [{
      id: "subflow-execution-id",
      level: 0,
      index: 0,
      priority: 10,
      authenticationFlow: true,
      displayName: "platform-passkey-loa",
      flowId: "subflow-id",
      requirement: "CONDITIONAL",
    }],
    subflow: {
      id: "subflow-id",
      alias: "platform-passkey-loa",
      providerId: "basic-flow",
      builtIn: false,
      topLevel: false,
    },
    subExecutions: [
      {
        id: "loa-execution-id",
        level: 0,
        index: 0,
        priority: 10,
        authenticationFlow: false,
        providerId: "conditional-level-of-authentication",
        requirement: "REQUIRED",
        authenticationConfig: "loa-config-id",
      },
      {
        id: "webauthn-execution-id",
        level: 0,
        index: 1,
        priority: 20,
        authenticationFlow: false,
        providerId: "webauthn-authenticator-passwordless",
        requirement: "REQUIRED",
        authenticationConfig: "amr-config-id",
      },
    ],
    configs: {
      "loa-config-id": {
        alias: "platform-passkey-loa-1",
        config: { "loa-condition-level": "1", "loa-max-age": "0" },
      },
      "amr-config-id": {
        alias: "platform-passkey-amr-webauthn",
        config: { "default.reference.value": "webauthn", "default.reference.maxAge": "300" },
      },
    },
    acrScope: { id: "acr-scope-id", name: "acr", protocol: "openid-connect" },
    acrScopeMappers: [{
      protocol: "openid-connect",
      protocolMapper: "oidc-acr-mapper",
      config: { "id.token.claim": "true" },
    }],
    acrScopeMappings: {},
    basicScope: { id: "basic-scope-id", name: "basic", protocol: "openid-connect" },
    basicScopeMappers: [{
      id: "auth-time-mapper-id",
      name: "auth_time",
      protocol: "openid-connect",
      protocolMapper: "oidc-usersessionmodel-note-mapper",
      config: {
        "user.session.note": "AUTH_TIME",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "claim.name": "auth_time",
        "jsonType.label": "long",
      },
    }],
    basicScopeMappings: {},
    requiredActions: [{
      alias: "webauthn-register-passwordless",
      providerId: "webauthn-register-passwordless",
      enabled: true,
    }],
    roles: [{ name: "owner" }, { name: "admin" }, { name: "viewer" }],
    ...(administrator ? {
      administrator: {
        user: { id: "admin-subject", username: "owner", enabled: true, requiredActions: [] },
        credentials: [
          { id: "passkey-one", type: "webauthn-passwordless" },
          { id: "passkey-two", type: "webauthn-passwordless" },
        ],
        realmRoles: [{ name: "owner" }],
      },
    } : {}),
  };
}

const managedEnv = [
  "CONTROL_CENTER_ADMIN_USERS",
  "CONTROL_CENTER_ADMIN_SUBJECT",
  "CONTROL_CENTER_MIN_PASSKEYS",
  "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID",
  "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE",
  "CONTROL_CENTER_OIDC_CLIENT_ID",
  "CONTROL_CENTER_OIDC_ISSUER",
  "CONTROL_CENTER_OIDC_REDIRECT_URI",
  "CONTROL_CENTER_OIDC_REQUIRED_ACR",
  "CONTROL_CENTER_OIDC_REQUIRED_AMR",
  "CONTROL_CENTER_PUBLIC_ORIGIN",
  "KEYCLOAK_CONTAINER",
  "KEYCLOAK_IDENTITY_ORIGIN",
  "KEYCLOAK_PASSKEY_ACTION",
  "KEYCLOAK_PASSKEY_CONFIRM",
  "KEYCLOAK_PASSKEY_EXPECT_BINDING",
  "KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED",
  "KEYCLOAK_PASSKEY_NODE_BIN",
  "KEYCLOAK_PASSKEY_READINESS_PHASE",
  "KEYCLOAK_PASSKEY_RP_ID",
  "KEYCLOAK_PASSKEY_VALIDATE_ONLY",
  "KEYCLOAK_REALM",
];

function cleanEnv(extra = {}) {
  const env = { ...process.env };
  for (const key of managedEnv) delete env[key];
  return { ...env, ...extra };
}

function runReconciler(extra = {}) {
  return spawnSync(process.execPath, [reconciler], {
    cwd: repositoryRoot,
    env: cleanEnv({
      KEYCLOAK_IDENTITY_ORIGIN: "https://auth.platform-infrastructure.com",
      CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.platform-infrastructure.com",
      CONTROL_CENTER_OIDC_ISSUER: "https://auth.platform-infrastructure.com/realms/platform",
      CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.platform-infrastructure.com/auth/callback",
      CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
      KEYCLOAK_PASSKEY_VALIDATE_ONLY: "true",
      ...extra,
    }),
    encoding: "utf8",
  });
}

test("first-boot realm is enrollable and stages the Keycloak 26.6.3 passkey contract", () => {
  const importSource = readFileSync(importPath, "utf8");
  const templateSource = readFileSync(templatePath, "utf8");
  assert.equal(templateSource, importSource);

  const realm = JSON.parse(importSource);
  assert.equal(realm.browserFlow, "browser");
  assert.equal(realm.webAuthnPolicyRpId, "auth.localhost.com");
  assert.deepEqual(realm.webAuthnPolicyExtraOrigins, ["https://auth.localhost.com"]);
  assert.equal(realm.webAuthnPolicyPasswordlessRpId, "auth.localhost.com");
  assert.deepEqual(realm.webAuthnPolicyPasswordlessExtraOrigins, ["https://auth.localhost.com"]);
  assert.deepEqual(JSON.parse(realm.attributes["acr.loa.map"]), {
    "urn:platform:loa:passkey": 1,
  });

  const top = realm.authenticationFlows.filter((flow) => flow.alias === "platform-passkey-browser");
  assert.equal(top.length, 1);
  assert.equal(top[0].topLevel, true);
  assert.deepEqual(top[0].authenticationExecutions, [{
    authenticatorFlow: true,
    requirement: "CONDITIONAL",
    priority: 10,
    flowAlias: "platform-passkey-loa",
    userSetupAllowed: false,
  }]);

  const loa = realm.authenticationFlows.filter((flow) => flow.alias === "platform-passkey-loa");
  assert.equal(loa.length, 1);
  assert.equal(loa[0].topLevel, false);
  assert.deepEqual(loa[0].authenticationExecutions.map((entry) => ({
    authenticator: entry.authenticator,
    authenticatorFlow: entry.authenticatorFlow,
    requirement: entry.requirement,
    priority: entry.priority,
    config: entry.authenticatorConfig,
  })), [
    {
      authenticator: "conditional-level-of-authentication",
      authenticatorFlow: false,
      requirement: "REQUIRED",
      priority: 10,
      config: "platform-passkey-loa-1",
    },
    {
      authenticator: "webauthn-authenticator-passwordless",
      authenticatorFlow: false,
      requirement: "REQUIRED",
      priority: 20,
      config: "platform-passkey-amr-webauthn",
    },
  ]);

  const configs = new Map(realm.authenticatorConfig.map((entry) => [entry.alias, entry.config]));
  assert.deepEqual(configs.get("platform-passkey-loa-1"), {
    "loa-condition-level": "1",
    "loa-max-age": "0",
  });
  assert.deepEqual(configs.get("platform-passkey-amr-webauthn"), {
    "default.reference.value": "webauthn",
    "default.reference.maxAge": "300",
  });

  const clients = realm.clients.filter((client) => client.clientId === "platform-control-center");
  assert.equal(clients.length, 1);
  const client = clients[0];
  assert.equal(client.fullScopeAllowed, true);
  assert.equal(client.bearerOnly, false);
  assert.deepEqual(client.authenticationFlowBindingOverrides, {});
  assert.equal(client.defaultClientScopes.includes("basic"), true);
  assert.equal(client.defaultClientScopes.includes("acr"), true);
  assert.deepEqual(client.redirectUris, ["https://portal.localhost.com/auth/callback"]);
  assert.deepEqual(client.webOrigins, ["https://portal.localhost.com"]);
  assert.equal(client.attributes["pkce.code.challenge.method"], "S256");
  assert.equal(client.attributes["backchannel.logout.url"], "https://portal.localhost.com/auth/backchannel-logout");
  assert.equal(client.attributes["backchannel.logout.session.required"], "true");
  assert.equal(client.attributes["backchannel.logout.revoke.offline.tokens"], "true");
  assert.equal(client.protocolMappers.filter((mapper) => mapper.protocolMapper === "oidc-amr-mapper").length, 1);
  const roleMappers = client.protocolMappers.filter((mapper) => mapper.protocolMapper === "oidc-usermodel-realm-role-mapper");
  assert.equal(roleMappers.length, 1);
  assert.equal(roleMappers[0].name, "platform-realm-roles");
  assert.equal(roleMappers[0].config["id.token.claim"], "true");
  assert.equal(roleMappers[0].config["claim.name"], "realm_access.roles");
});

test("pure readiness accepts staged structure before the administrator exists", () => {
  const result = evaluateKeycloakPasskeyReadiness(validContractSnapshot(), {
    ...contractOptions,
    phase: "staged",
  });
  assert.deepEqual(result, {
    ready: true,
    phase: "staged",
    passkeyCount: 0,
    drift: [],
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.drift), true);
});

test("pure enrollment readiness gates one exact owner on two distinct passkeys and persisted confirmation", () => {
  const missingAdministrator = evaluateKeycloakPasskeyReadiness(validContractSnapshot(), {
    ...contractOptions,
    phase: "enrollment",
    adminSubject: "admin-subject",
    adminUsername: "owner",
    minimumPasskeys: 2,
    independenceConfirmed: false,
  });
  assert.equal(missingAdministrator.ready, false);
  assert.deepEqual(missingAdministrator.drift, [
    "administrator.enabled",
    "administrator.ownerRole",
    "administrator.passkeyIndependence",
    "administrator.passkeys",
    "administrator.subject",
    "administrator.username",
  ]);

  const enrolled = evaluateKeycloakPasskeyReadiness(validContractSnapshot({ administrator: true }), {
    ...contractOptions,
    phase: "enrollment",
    adminSubject: "admin-subject",
    adminUsername: "owner",
    minimumPasskeys: 2,
    independenceConfirmed: true,
  });
  assert.equal(enrolled.ready, true);
  assert.equal(enrolled.passkeyCount, 2);
  assert.deepEqual(enrolled.drift, []);

  const duplicateCredential = validContractSnapshot({ administrator: true });
  duplicateCredential.administrator.credentials[1].id = "passkey-one";
  const duplicateResult = evaluateKeycloakPasskeyReadiness(duplicateCredential, {
    ...contractOptions,
    phase: "enrollment",
    adminSubject: "admin-subject",
    adminUsername: "owner",
    minimumPasskeys: 2,
    independenceConfirmed: true,
  });
  assert.equal(duplicateResult.passkeyCount, 1);
  assert.deepEqual(duplicateResult.drift, ["administrator.passkeys"]);
});

test("pure cutover readiness requires the verified passkey browser binding", () => {
  const options = {
    ...contractOptions,
    phase: "cutover",
    adminSubject: "admin-subject",
    adminUsername: "owner",
    minimumPasskeys: 2,
    independenceConfirmed: true,
  };
  const stillStaged = evaluateKeycloakPasskeyReadiness(validContractSnapshot({ administrator: true }), options);
  assert.equal(stillStaged.ready, false);
  assert.deepEqual(stillStaged.drift, ["realm.browserFlow"]);

  const cutover = evaluateKeycloakPasskeyReadiness(
    validContractSnapshot({ binding: "cutover", administrator: true }),
    options,
  );
  assert.equal(cutover.ready, true);
  assert.equal(cutover.passkeyCount, 2);
});

test("pure structural validator fails closed on ACR type, realm-role mapper and flow topology drift", () => {
  const snapshot = validContractSnapshot();
  snapshot.realm.attributes["acr.loa.map"] = JSON.stringify({ [contractOptions.requiredAcr]: "1" });
  snapshot.clients[0].protocolMappers = snapshot.clients[0].protocolMappers
    .filter((mapper) => mapper.protocolMapper !== "oidc-usermodel-realm-role-mapper");
  snapshot.basicScopeMappers[0].config["id.token.claim"] = "false";
  snapshot.subExecutions[1].priority = 10;
  const drift = keycloakPasskeyStructuralDrift(snapshot, { ...contractOptions, binding: "staged" });
  assert.deepEqual(drift, [
    "client.authTimeSource",
    "client.realmRoleMapper",
    "flow.webauthn",
    "realm.acr.loa.map",
  ]);
});

test("pure structural validator accepts a client-local auth_time fallback without a shared basic scope", () => {
  const snapshot = validContractSnapshot();
  snapshot.basicScope = null;
  snapshot.basicScopeMappers = [];
  snapshot.clients[0].protocolMappers.push({
    id: "client-auth-time-id",
    name: "platform-auth-time",
    protocol: "openid-connect",
    protocolMapper: "oidc-usersessionmodel-note-mapper",
    config: {
      "user.session.note": "AUTH_TIME",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "claim.name": "auth_time",
      "jsonType.label": "long",
    },
  });
  assert.deepEqual(
    keycloakPasskeyStructuralDrift(snapshot, { ...contractOptions, binding: "staged" }),
    [],
  );
});

test("pure structural validator rejects extra ACR-to-LoA mappings", () => {
  const snapshot = validContractSnapshot();
  snapshot.realm.attributes["acr.loa.map"] = JSON.stringify({
    [contractOptions.requiredAcr]: 1,
    "urn:unrelated:loa": 2,
  });
  assert.deepEqual(
    keycloakPasskeyStructuralDrift(snapshot, { ...contractOptions, binding: "staged" }),
    ["realm.acr.loa.map"],
  );
});

test("pure structural validator rejects non-OIDC ACR, AMR and realm-role mapper shapes", () => {
  const snapshot = validContractSnapshot();
  snapshot.acrScope.protocol = "saml";
  snapshot.acrScopeMappers[0].protocol = "saml";
  snapshot.clients[0].protocolMappers[0].protocol = "saml";
  snapshot.clients[0].protocolMappers[1].protocol = "saml";
  assert.deepEqual(
    keycloakPasskeyStructuralDrift(snapshot, { ...contractOptions, binding: "staged" }),
    ["client.acrScope", "client.amrMapper", "client.protocolMapperSurface", "client.realmRoleMapper"],
  );
});

test("foreign role-emitting client mapper is outside the exact allowlist and blocks readiness", () => {
  const snapshot = validContractSnapshot();
  snapshot.clients[0].protocolMappers.push({
    id: "foreign-role-mapper",
    name: "foreign-client-roles",
    protocol: "openid-connect",
    protocolMapper: "oidc-usermodel-client-role-mapper",
    config: {
      "id.token.claim": "true",
      "access.token.claim": "true",
      "claim.name": "resource_access.foreign.roles",
      multivalued: "true",
    },
  });

  const result = evaluateKeycloakPasskeyReadiness(snapshot, {
    ...contractOptions,
    phase: "staged",
  });
  assert.equal(result.ready, false);
  assert.deepEqual(result.drift, ["client.protocolMapperSurface"]);

  const source = readFileSync(reconciler, "utf8");
  assert.match(source, /assertExactClientProtocolMapperAllowlist\(mappers\)/);
  assert.match(source, /protocol mapper outside the exact managed allowlist/);
});

test("pure structural validator rejects role-gated shared ACR and basic client scopes", () => {
  const snapshot = validContractSnapshot();
  snapshot.acrScopeMappings = { realmMappings: [{ id: "role-a", name: "foreign" }] };
  snapshot.basicScopeMappings = {
    clientMappings: { foreign: { id: "client-a", client: "foreign", mappings: [{ id: "role-b", name: "foreign" }] } },
  };
  assert.deepEqual(
    keycloakPasskeyStructuralDrift(snapshot, { ...contractOptions, binding: "staged" }),
    ["client.acrScope", "client.authTimeSource"],
  );
});

test("pure readiness rejects a disabled realm and client flow override without gating pre-login required actions", () => {
  const snapshot = validContractSnapshot({ administrator: true });
  snapshot.realm.enabled = false;
  snapshot.clients[0].authenticationFlowBindingOverrides = { browser: "foreign-flow-id" };
  snapshot.administrator.user.requiredActions = ["webauthn-register-passwordless"];
  const result = evaluateKeycloakPasskeyReadiness(snapshot, {
    ...contractOptions,
    phase: "enrollment",
    adminSubject: "admin-subject",
    adminUsername: "owner",
    minimumPasskeys: 2,
    independenceConfirmed: true,
  });
  assert.deepEqual(result.drift, [
    "client.authenticationFlowBindingOverrides",
    "realm.enabled",
  ]);
});

test("validate-only derives the exact real RP, callback and back-channel URLs without Docker", () => {
  const result = runReconciler();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /identity_origin=https:\/\/auth\.platform-infrastructure\.com/);
  assert.match(result.stdout, /rp_id=auth\.platform-infrastructure\.com/);
  assert.match(result.stdout, /callback=https:\/\/portal\.platform-infrastructure\.com\/auth\/callback/);
  assert.match(result.stdout, /backchannel=https:\/\/portal\.platform-infrastructure\.com\/auth\/backchannel-logout/);
  assert.match(result.stdout, /expected_binding=staged status=validated-only/);
});

test("origin, RP ID and ACR inputs fail closed before Docker", () => {
  for (const [extra, expected] of [
    [{ KEYCLOAK_IDENTITY_ORIGIN: "http://auth.platform-infrastructure.com" }, /origin-only HTTPS URL/],
    [{ KEYCLOAK_IDENTITY_ORIGIN: "https://192.168.1.164" }, /origin-only HTTPS URL/],
    [{ KEYCLOAK_IDENTITY_ORIGIN: "https://auth.platform-infrastructure.com/path" }, /origin-only HTTPS URL/],
    [{ CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.platform-infrastructure.com/callback" }, /origin-only HTTPS URL/],
    [{ KEYCLOAK_PASSKEY_RP_ID: "platform-infrastructure.com" }, /must exactly match/],
    [{ CONTROL_CENTER_OIDC_REQUIRED_ACR: "bad acr" }, /unsupported characters/],
    [{ CONTROL_CENTER_OIDC_ISSUER: "https://wrong.example/realms/platform" }, /must be exactly/],
    [{ CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.platform-infrastructure.com/other" }, /must be exactly/],
    [{ CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn,otp" }, /must be exactly webauthn/],
  ]) {
    const result = runReconciler(extra);
    assert.equal(result.status, 2, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, expected);
  }
});

test("every mutating action requires its exact confirmation before Docker", () => {
  for (const [action, confirmation] of [
    ["apply-staged", "RECONCILE-PLATFORM-PASSKEY-STAGED"],
    ["bind", "BIND-PLATFORM-PASSKEY-BROWSER"],
    ["rollback-browser", "ROLLBACK-PLATFORM-BROWSER-FLOW"],
  ]) {
    const result = runReconciler({
      KEYCLOAK_PASSKEY_ACTION: action,
      KEYCLOAK_PASSKEY_VALIDATE_ONLY: "false",
    });
    assert.equal(result.status, 2, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, new RegExp(`KEYCLOAK_PASSKEY_CONFIRM=${confirmation}`));
    assert.doesNotMatch(result.stderr, /Docker invocation/);
  }
});

test("bind validates the full enrollment gate before creating a kcadm session", () => {
  const result = runReconciler({
    KEYCLOAK_PASSKEY_ACTION: "bind",
    KEYCLOAK_PASSKEY_VALIDATE_ONLY: "false",
    KEYCLOAK_PASSKEY_CONFIRM: "BIND-PLATFORM-PASSKEY-BROWSER",
    KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED: "true",
    CONTROL_CENTER_ADMIN_USERS: "owner",
    CONTROL_CENTER_ADMIN_SUBJECT: "00000000-0000-4000-8000-000000000001",
    CONTROL_CENTER_MIN_PASSKEYS: "1",
  });
  assert.equal(result.status, 2, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /CONTROL_CENTER_MIN_PASSKEYS must be an integer from 2 to 20/);
  assert.doesNotMatch(result.stderr, /Docker invocation/);

  const missingSubject = runReconciler({
    KEYCLOAK_PASSKEY_ACTION: "bind",
    KEYCLOAK_PASSKEY_VALIDATE_ONLY: "false",
    KEYCLOAK_PASSKEY_CONFIRM: "BIND-PLATFORM-PASSKEY-BROWSER",
    KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED: "true",
    CONTROL_CENTER_ADMIN_USERS: "owner",
    CONTROL_CENTER_MIN_PASSKEYS: "2",
  });
  assert.equal(missingSubject.status, 2, `${missingSubject.stdout}${missingSubject.stderr}`);
  assert.match(missingSubject.stderr, /admin subject is unsafe/);
  assert.doesNotMatch(missingSubject.stderr, /Docker invocation/);
});

test("staged readiness validates inputs without passkeys while later phases require explicit independence", () => {
  const staged = spawnSync("sh", [readiness], {
    cwd: repositoryRoot,
    env: cleanEnv({
      KEYCLOAK_IDENTITY_ORIGIN: "https://auth.platform-infrastructure.com",
      CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.platform-infrastructure.com",
      KEYCLOAK_PASSKEY_READINESS_PHASE: "staged",
      KEYCLOAK_PASSKEY_VALIDATE_ONLY: "true",
      KEYCLOAK_PASSKEY_NODE_BIN: process.execPath,
    }),
    encoding: "utf8",
  });
  assert.equal(staged.status, 0, staged.stderr);
  assert.match(staged.stdout, /readiness_phase=staged live_contract=not-inspected status=validated-only/);
  assert.doesNotMatch(staged.stdout + staged.stderr, /passkeys=/);

  for (const phase of ["enrollment", "cutover"]) {
    const result = spawnSync("sh", [readiness], {
      cwd: repositoryRoot,
      env: cleanEnv({
        KEYCLOAK_IDENTITY_ORIGIN: "https://auth.platform-infrastructure.com",
        CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.platform-infrastructure.com",
        CONTROL_CENTER_OIDC_ISSUER: "https://auth.platform-infrastructure.com/realms/platform",
        CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.platform-infrastructure.com/auth/callback",
        CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
        KEYCLOAK_PASSKEY_READINESS_PHASE: phase,
        KEYCLOAK_PASSKEY_VALIDATE_ONLY: "false",
        KEYCLOAK_PASSKEY_NODE_BIN: process.execPath,
        CONTROL_CENTER_ADMIN_USERS: "owner",
        CONTROL_CENTER_ADMIN_SUBJECT: "00000000-0000-4000-8000-000000000001",
      }),
      encoding: "utf8",
    });
    assert.equal(result.status, 2, `${phase}: ${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED=true/);
    assert.doesNotMatch(result.stderr, /Docker invocation/);
  }

  const enrollmentWithoutPersistedSubject = spawnSync("sh", [readiness], {
    cwd: repositoryRoot,
    env: cleanEnv({
      KEYCLOAK_IDENTITY_ORIGIN: "https://auth.platform-infrastructure.com",
      CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.platform-infrastructure.com",
      CONTROL_CENTER_OIDC_ISSUER: "https://auth.platform-infrastructure.com/realms/platform",
      CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.platform-infrastructure.com/auth/callback",
      CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
      KEYCLOAK_PASSKEY_READINESS_PHASE: "enrollment",
      KEYCLOAK_PASSKEY_VALIDATE_ONLY: "false",
      KEYCLOAK_PASSKEY_NODE_BIN: process.execPath,
      KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED: "true",
      CONTROL_CENTER_ADMIN_USERS: "owner",
    }),
    encoding: "utf8",
  });
  assert.equal(enrollmentWithoutPersistedSubject.status, 2);
  assert.match(enrollmentWithoutPersistedSubject.stderr, /admin subject is unsafe/);
  assert.doesNotMatch(enrollmentWithoutPersistedSubject.stderr, /Docker invocation/);
});

test("staged apply and rollback keep browser-flow mutation in separate confirmed branches", () => {
  const source = readFileSync(reconciler, "utf8");
  assert.match(source, /PLATFORM_KCADM_CONFIG=\$\{configDir\}\/kcadm\.config/);
  assert.match(source, /default-client-scopes\/\$\{acrScope\.id\}`, \{ query: \["-n"\] \}/);
  const stagedStart = source.indexOf('} else if (action === "apply-staged") {');
  const bindStart = source.indexOf('} else if (action === "bind") {', stagedStart);
  assert.ok(stagedStart >= 0 && bindStart > stagedStart);
  const stagedBranch = source.slice(stagedStart, bindStart);
  assert.doesNotMatch(stagedBranch, /updateBrowserFlow\(/);
  assert.match(stagedBranch, /before\.browserFlow !== "browser"/);

  const rollbackStart = source.indexOf('if (action === "rollback-browser") {');
  assert.ok(rollbackStart >= 0 && stagedStart > rollbackStart);
  const rollbackBranch = source.slice(rollbackStart, stagedStart);
  assert.match(rollbackBranch, /updateBrowserFlow\("browser"\)/);
  assert.match(rollbackBranch, /Refusing to replace unexpected browser flow/);
  assert.match(source, /function updateBrowserFlow\(browserFlow\) \{\s*kcadm\("update", `realms\/\$\{realmName\}`, \{ realmScoped: false, body: \{ browserFlow \} \}\);\s*\}/);

  const bindEnd = source.indexOf("} else {", bindStart);
  assert.ok(bindEnd > bindStart);
  const bindBranch = source.slice(bindStart, bindEnd);
  assert.match(bindBranch, /staged\.realm\.browserFlow === FLOW \? "cutover" : "staged"/);
  assert.match(bindBranch, /const changed = staged\.realm\.browserFlow === "browser"/);
  assert.match(bindBranch, /if \(changed\) updateBrowserFlow\(FLOW\)/);
  assert.match(bindBranch, /evaluateReadiness\(cutover, "cutover"\)/);
  assert.match(bindBranch, /if \(changed\) rollbackFailedBind\(error\)/);
  assert.match(source, /evaluateKeycloakPasskeyReadiness\(contract/);
  assert.match(source, /authenticationFlowInventory\(flows\)/);
  assert.match(source, /authenticationFlowBindingOverrides: clearedFlowBindingOverrides\(client\.authenticationFlowBindingOverrides\)/);
  assert.match(source, /refusing a realm-global repair/);
  assert.match(source, /function startCleanupWatchdog\(\)/);
  assert.match(source, /trap 'cleanup; exit 0' HUP INT TERM/);
  assert.match(source, /while kill -0 "\$parent_pid"/);
  assert.match(source, /'rm -rf -- "\$1"; test ! -e "\$1"'/);
  assert.doesNotMatch(source, /kcadm\("create", "client-scopes"/);
  assert.doesNotMatch(source, /kcadm\("update", `client-scopes\/\$\{scope\.id\}\/protocol-mappers/);
});

test("mocked bind rolls back only browserFlow when post-bind readiness fails", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "platform-passkey-docker-"));
  const dockerPath = path.join(directory, "docker");
  const fixturePath = path.join(directory, "fixture.json");
  const statePath = path.join(directory, "state.json");
  const logPath = path.join(directory, "updates.jsonl");
  const secretPath = path.join(directory, "first-configuration-client-secret");
  const firstConfigurationSecret = "mock-first-configuration-secret-0001";
  const fixture = validContractSnapshot({ administrator: true });
  writeFileSync(fixturePath, JSON.stringify(fixture), { mode: 0o600 });
  writeFileSync(statePath, JSON.stringify({ browserFlow: "browser" }), { mode: 0o600 });
  writeFileSync(logPath, "", { mode: 0o600 });
  writeFileSync(secretPath, firstConfigurationSecret, { mode: 0o600 });
  writeFileSync(dockerPath, `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
const fixture = JSON.parse(fs.readFileSync(process.env.FAKE_KEYCLOAK_FIXTURE, "utf8"));
const firstConfigurationSecret = process.env.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE
  ? fs.readFileSync(process.env.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE, "utf8").trim()
  : "";
const readState = () => JSON.parse(fs.readFileSync(process.env.FAKE_KEYCLOAK_STATE, "utf8"));
const writeState = (state) => fs.writeFileSync(process.env.FAKE_KEYCLOAK_STATE, JSON.stringify(state));
const output = (value) => process.stdout.write(JSON.stringify(value));
if (args[0] === "inspect") process.exit(0);
if (args[0] !== "exec") process.exit(91);
if (args.includes("sh") && args.includes("-ec")) {
  const script = args.at(-1);
  if (script.includes("mktemp -d")) process.stdout.write("/tmp/platform-passkey-reconcile.mock123");
  process.exit(0);
}
if (args.includes("rm") && args.includes("-rf")) process.exit(0);
const kcadm = args.indexOf("/opt/keycloak/bin/kcadm.sh");
if (kcadm < 0) process.exit(92);
const command = args[kcadm + 1];
const endpoint = args[kcadm + 2];
if (command === "update" && endpoint === "realms/platform") {
  const body = JSON.parse(fs.readFileSync(0, "utf8"));
  const state = readState();
  if (Object.hasOwn(body, "browserFlow")) state.browserFlow = body.browserFlow;
  writeState(state);
  fs.appendFileSync(process.env.FAKE_KEYCLOAK_LOG, JSON.stringify({ endpoint, body }) + "\\n");
  process.exit(0);
}
if (command !== "get") process.exit(93);
const state = readState();
const client = structuredClone(fixture.clients[0]);
const firstConfigurationClient = {
  id: "first-configuration-client-uuid",
  clientId: "platform-first-configuration",
  enabled: true,
  protocol: "openid-connect",
  clientAuthenticatorType: "client-secret",
  publicClient: false,
  bearerOnly: false,
  standardFlowEnabled: false,
  directAccessGrantsEnabled: false,
  implicitFlowEnabled: false,
  serviceAccountsEnabled: true,
  fullScopeAllowed: false,
  redirectUris: [],
  webOrigins: [],
  authenticationFlowBindingOverrides: {},
  protocolMappers: [],
};
if (process.env.FAKE_FIRST_CONFIGURATION_DISABLED === "true") {
  firstConfigurationClient.enabled = false;
  firstConfigurationClient.serviceAccountsEnabled = false;
}
const realmManagementClient = { id: "realm-management-uuid", clientId: "realm-management" };
const managementRoles = ["manage-clients", "manage-realm", "manage-users"].map((name) => ({ id: "role-" + name, name }));
const rolesScope = { id: "roles-scope-id", name: "roles", protocol: "openid-connect" };
const rolesScopeMappers = [{
  id: "client-roles-mapper-id",
  name: "client roles",
  protocol: "openid-connect",
  protocolMapper: "oidc-usermodel-client-role-mapper",
  config: {
    "access.token.claim": "true",
    "claim.name": "resource_access.\${client_id}.roles",
    multivalued: "true",
    "jsonType.label": "String",
  },
}];
if (state.browserFlow === "platform-passkey-browser" && process.env.FAKE_POST_BIND_DRIFT === "true") {
  client.webOrigins = ["https://drift.invalid"];
}
if (endpoint === "clients") {
  const queryIndex = args.indexOf("-q");
  const query = queryIndex >= 0 ? args[queryIndex + 1] : "";
  const queriedClientId = query.startsWith("clientId=") ? query.slice("clientId=".length) : "";
  const summaries = {
    [client.clientId]: [{ id: client.id, clientId: client.clientId }],
    [firstConfigurationClient.clientId]: [{ id: firstConfigurationClient.id, clientId: firstConfigurationClient.clientId }],
    [realmManagementClient.clientId]: [realmManagementClient],
  };
  output(summaries[queriedClientId] || []);
  process.exit(0);
}
const responses = {
  "realms/platform": { ...fixture.realm, browserFlow: state.browserFlow },
  ["clients/" + client.id]: client,
  ["clients/" + firstConfigurationClient.id]: firstConfigurationClient,
  ["clients/" + firstConfigurationClient.id + "/client-secret"]: { value: firstConfigurationSecret },
  ["clients/" + firstConfigurationClient.id + "/default-client-scopes"]: [rolesScope],
  ["clients/" + firstConfigurationClient.id + "/optional-client-scopes"]: [],
  ["clients/" + firstConfigurationClient.id + "/service-account-user"]: {
    id: "first-configuration-service-account",
    enabled: true,
    serviceAccountClientId: firstConfigurationClient.clientId,
  },
  ["clients/" + realmManagementClient.id]: realmManagementClient,
  ["users/first-configuration-service-account/role-mappings/clients/" + realmManagementClient.id]: managementRoles,
  ["clients/" + firstConfigurationClient.id + "/scope-mappings/clients/" + realmManagementClient.id]: managementRoles,
  ["client-scopes/" + rolesScope.id + "/protocol-mappers/models"]: rolesScopeMappers,
  ["client-scopes/" + rolesScope.id + "/scope-mappings"]: {},
  "authentication/flows": fixture.flows,
  "authentication/flows/platform-passkey-browser/executions": fixture.topExecutions,
  "authentication/flows/subflow-id": fixture.subflow,
  "authentication/flows/platform-passkey-loa/executions": fixture.subExecutions,
  "authentication/config/loa-config-id": fixture.configs["loa-config-id"],
  "authentication/config/amr-config-id": fixture.configs["amr-config-id"],
  ["clients/" + client.id + "/default-client-scopes"]: [fixture.acrScope, fixture.basicScope],
  "client-scopes/acr-scope-id/protocol-mappers/models": fixture.acrScopeMappers,
  "client-scopes/acr-scope-id/scope-mappings": fixture.acrScopeMappings,
  "client-scopes/basic-scope-id/protocol-mappers/models": fixture.basicScopeMappers,
  "client-scopes/basic-scope-id/scope-mappings": fixture.basicScopeMappings,
  "authentication/required-actions": fixture.requiredActions,
  "roles": fixture.roles,
  "users/admin-subject": fixture.administrator.user,
  "users/admin-subject/credentials": fixture.administrator.credentials,
  "users/admin-subject/role-mappings/realm": fixture.administrator.realmRoles,
};
if (!Object.hasOwn(responses, endpoint)) process.exit(94);
output(responses[endpoint]);
`, { mode: 0o700 });
  chmodSync(dockerPath, 0o700);

  try {
    const result = spawnSync(process.execPath, [reconciler], {
      cwd: repositoryRoot,
      env: cleanEnv({
        PATH: `${directory}:${process.env.PATH || ""}`,
        FAKE_KEYCLOAK_FIXTURE: fixturePath,
        FAKE_KEYCLOAK_STATE: statePath,
        FAKE_KEYCLOAK_LOG: logPath,
        FAKE_POST_BIND_DRIFT: "true",
        KEYCLOAK_IDENTITY_ORIGIN: contractOptions.identityOrigin,
        CONTROL_CENTER_PUBLIC_ORIGIN: contractOptions.publicOrigin,
        CONTROL_CENTER_OIDC_ISSUER: `${contractOptions.identityOrigin}/realms/platform`,
        CONTROL_CENTER_OIDC_REDIRECT_URI: `${contractOptions.publicOrigin}/auth/callback`,
        CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
        CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE: secretPath,
        KEYCLOAK_PASSKEY_ACTION: "bind",
        KEYCLOAK_PASSKEY_CONFIRM: "BIND-PLATFORM-PASSKEY-BROWSER",
        KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED: "true",
        CONTROL_CENTER_ADMIN_USERS: "owner",
        CONTROL_CENTER_ADMIN_SUBJECT: "admin-subject",
        CONTROL_CENTER_MIN_PASSKEYS: "2",
      }),
      encoding: "utf8",
    });
    assert.equal(result.status, 1, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Passkey browser binding did not verify: client\.webOrigins/);
    assert.equal(JSON.parse(readFileSync(statePath, "utf8")).browserFlow, "browser");
    const updates = readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
    assert.deepEqual(updates, [
      { endpoint: "realms/platform", body: { browserFlow: "platform-passkey-browser" } },
      { endpoint: "realms/platform", body: { browserFlow: "browser" } },
    ]);

    writeFileSync(statePath, JSON.stringify({ browserFlow: "platform-passkey-browser" }), { mode: 0o600 });
    const terminal = spawnSync(process.execPath, [reconciler], {
      cwd: repositoryRoot,
      env: cleanEnv({
        PATH: `${directory}:${process.env.PATH || ""}`,
        FAKE_KEYCLOAK_FIXTURE: fixturePath,
        FAKE_KEYCLOAK_STATE: statePath,
        FAKE_KEYCLOAK_LOG: logPath,
        FAKE_FIRST_CONFIGURATION_DISABLED: "true",
        KEYCLOAK_IDENTITY_ORIGIN: contractOptions.identityOrigin,
        CONTROL_CENTER_PUBLIC_ORIGIN: contractOptions.publicOrigin,
        CONTROL_CENTER_OIDC_ISSUER: `${contractOptions.identityOrigin}/realms/platform`,
        CONTROL_CENTER_OIDC_REDIRECT_URI: `${contractOptions.publicOrigin}/auth/callback`,
        CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
        KEYCLOAK_PASSKEY_ACTION: "plan",
        KEYCLOAK_PASSKEY_EXPECT_BINDING: "cutover",
      }),
      encoding: "utf8",
    });
    assert.equal(terminal.status, 0, `${terminal.stdout}${terminal.stderr}`);
    assert.match(terminal.stdout, /expected_binding=cutover action=none status=ready/);
    assert.doesNotMatch(terminal.stdout + terminal.stderr, /secret/);

    const terminalReadiness = spawnSync(process.execPath, [reconciler], {
      cwd: repositoryRoot,
      env: cleanEnv({
        PATH: `${directory}:${process.env.PATH || ""}`,
        FAKE_KEYCLOAK_FIXTURE: fixturePath,
        FAKE_KEYCLOAK_STATE: statePath,
        FAKE_KEYCLOAK_LOG: logPath,
        FAKE_FIRST_CONFIGURATION_DISABLED: "true",
        KEYCLOAK_IDENTITY_ORIGIN: contractOptions.identityOrigin,
        CONTROL_CENTER_PUBLIC_ORIGIN: contractOptions.publicOrigin,
        CONTROL_CENTER_OIDC_ISSUER: `${contractOptions.identityOrigin}/realms/platform`,
        CONTROL_CENTER_OIDC_REDIRECT_URI: `${contractOptions.publicOrigin}/auth/callback`,
        CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
        KEYCLOAK_PASSKEY_ACTION: "readiness",
        KEYCLOAK_PASSKEY_READINESS_PHASE: "cutover",
        KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED: "true",
        CONTROL_CENTER_ADMIN_USERS: "owner",
        CONTROL_CENTER_ADMIN_SUBJECT: "admin-subject",
        CONTROL_CENTER_MIN_PASSKEYS: "2",
      }),
      encoding: "utf8",
    });
    assert.equal(terminalReadiness.status, 0, `${terminalReadiness.stdout}${terminalReadiness.stderr}`);
    assert.match(terminalReadiness.stdout, /readiness_phase=cutover status=ready/);
    assert.doesNotMatch(terminalReadiness.stdout + terminalReadiness.stderr, /secret/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
