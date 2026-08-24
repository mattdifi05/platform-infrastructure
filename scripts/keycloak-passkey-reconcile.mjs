#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import {
  evaluateKeycloakPasskeyReadiness,
  KEYCLOAK_PASSKEY_CONTRACT,
  keycloakPasskeyStructuralDrift,
} from "../control-center/auth/keycloak-passkey-contract.mjs";

const {
  browserFlow: FLOW,
  loaFlow: LOA_FLOW,
  loaConfigAlias: LOA_CONFIG_ALIAS,
  amrConfigAlias: AMR_CONFIG_ALIAS,
  roleMapperName: ROLE_MAPPER_NAME,
  authTimeMapperName: AUTH_TIME_MAPPER_NAME,
  requiredRoles: REQUIRED_ROLES,
} = KEYCLOAK_PASSKEY_CONTRACT;
const ACTION_CONFIRMATIONS = Object.freeze({
  "apply-staged": "RECONCILE-PLATFORM-PASSKEY-STAGED",
  bind: "BIND-PLATFORM-PASSKEY-BROWSER",
  "rollback-browser": "ROLLBACK-PLATFORM-BROWSER-FLOW",
});
const FIRST_CONFIGURATION_ADMIN_ROLES = Object.freeze(["manage-clients", "manage-realm", "manage-users"]);
const FIRST_CONFIGURATION_CLIENT_ROLE_CLAIM = "resource_access.${client_id}.roles";

const env = process.env;
const container = safeIdentifier(env.KEYCLOAK_CONTAINER || "enterprise-keycloak", "Keycloak container", /^[A-Za-z0-9_.:-]+$/);
const realmName = safeIdentifier(env.KEYCLOAK_REALM || "platform", "Keycloak realm", /^[A-Za-z0-9._:-]+$/);
const clientId = safeIdentifier(env.CONTROL_CENTER_OIDC_CLIENT_ID || "platform-control-center", "OIDC client", /^[A-Za-z0-9._:-]+$/);
const firstConfigurationClientId = safeIdentifier(
  env.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID || "platform-first-configuration",
  "first-configuration OIDC client",
  /^[A-Za-z0-9._:-]+$/,
);
const action = String(env.KEYCLOAK_PASSKEY_ACTION || "plan").trim();
const validateOnly = exactBoolean(env.KEYCLOAK_PASSKEY_VALIDATE_ONLY || "false", "KEYCLOAK_PASSKEY_VALIDATE_ONLY");
const readinessPhase = String(env.KEYCLOAK_PASSKEY_READINESS_PHASE || "cutover").trim();
const expectedBinding = String(env.KEYCLOAK_PASSKEY_EXPECT_BINDING ||
  (action === "readiness" && readinessPhase === "cutover" ? "cutover" : "staged")).trim();
const firstConfigurationClientState = action === "apply-staged" || action === "bind" || expectedBinding === "staged"
  ? "active"
  : "disabled";

if (!["plan", "readiness", "apply-staged", "bind", "rollback-browser"].includes(action)) {
  fail("KEYCLOAK_PASSKEY_ACTION must be plan, readiness, apply-staged, bind or rollback-browser.", 2);
}
if (!["staged", "cutover"].includes(expectedBinding)) {
  fail("KEYCLOAK_PASSKEY_EXPECT_BINDING must be staged or cutover.", 2);
}
if (action in ACTION_CONFIRMATIONS && String(env.KEYCLOAK_PASSKEY_CONFIRM || "") !== ACTION_CONFIRMATIONS[action]) {
  fail(`Action ${action} requires KEYCLOAK_PASSKEY_CONFIRM=${ACTION_CONFIRMATIONS[action]}.`, 2);
}
if (action === "readiness" && !["staged", "enrollment", "cutover"].includes(readinessPhase)) {
  fail("KEYCLOAK_PASSKEY_READINESS_PHASE must be staged, enrollment or cutover.", 2);
}

let identityOrigin = "";
let portalOrigin = "";
let rpId = "";
let callback = "";
let backchannel = "";
let requiredAcr = "";
let expectedIssuer = "";
let bindAdminUsers = [];
let bindAdminSubject = "";
let minimumPasskeys = 2;
let firstConfigurationClientSecret = "";
if (action !== "rollback-browser") {
  identityOrigin = normalizeOrigin(env.KEYCLOAK_IDENTITY_ORIGIN, "KEYCLOAK_IDENTITY_ORIGIN");
  portalOrigin = normalizeOrigin(env.CONTROL_CENTER_PUBLIC_ORIGIN, "CONTROL_CENTER_PUBLIC_ORIGIN");
  const identityUrl = new URL(identityOrigin);
  rpId = String(env.KEYCLOAK_PASSKEY_RP_ID || identityUrl.hostname).trim().toLowerCase();
  if (!isDnsName(rpId) || rpId !== identityUrl.hostname.toLowerCase()) {
    fail("KEYCLOAK_PASSKEY_RP_ID must exactly match the DNS hostname in KEYCLOAK_IDENTITY_ORIGIN.", 2);
  }
  requiredAcr = String(env.CONTROL_CENTER_OIDC_REQUIRED_ACR || "urn:platform:loa:passkey").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}$/.test(requiredAcr)) {
    fail("CONTROL_CENTER_OIDC_REQUIRED_ACR contains unsupported characters.", 2);
  }
  callback = `${portalOrigin}/auth/callback`;
  backchannel = `${portalOrigin}/auth/backchannel-logout`;
  expectedIssuer = `${identityOrigin}/realms/${realmName}`;
  assertRuntimeOidcContract({ requireExplicit: enrollmentGateForAction(action, readinessPhase) });
}

const enrollmentGateRequired = action === "bind" || (action === "readiness" && readinessPhase !== "staged");
if (enrollmentGateRequired) {
  if (String(env.KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED || "") !== "true") {
    fail("Enrollment/cutover readiness requires KEYCLOAK_PASSKEY_INDEPENDENCE_CONFIRMED=true after testing two independent authenticators.", 2);
  }
  bindAdminUsers = parseAdminUsers(true);
  bindAdminSubject = safeIdentifier(env.CONTROL_CENTER_ADMIN_SUBJECT, "admin subject", /^[A-Za-z0-9._:-]+$/);
  minimumPasskeys = parseMinimumPasskeys();
}

if (validateOnly) {
  if (action !== "plan" && !(action === "readiness" && readinessPhase === "staged")) {
    fail("Validate-only mode is available only for plan or staged readiness.", 2);
  }
  process.stdout.write(
    `realm=${realmName} client=${clientId} identity_origin=${identityOrigin} rp_id=${rpId} ` +
    `callback=${callback} backchannel=${backchannel} expected_binding=${expectedBinding} ` +
    `${action === "readiness" ? `readiness_phase=${readinessPhase} live_contract=not-inspected ` : ""}status=validated-only\n`,
  );
  process.exit(0);
}

if (action !== "rollback-browser" && firstConfigurationClientState === "active") {
  try {
    firstConfigurationClientSecret = readFirstConfigurationClientSecret(
      env.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE,
    );
  } catch (error) {
    fail(safeError(error), 2);
  }
}

let configDir = "";
let cleanupWatchdog = null;
try {
  docker(["inspect", "--", container], { quiet: true });
  configDir = docker([
    "exec", container, "sh", "-ec",
    "umask 077; dir=$(mktemp -d /tmp/platform-passkey-reconcile.XXXXXX); printf %s \"$dir\"",
  ]).trim();
  if (!/^\/tmp\/platform-passkey-reconcile\.[A-Za-z0-9]+$/.test(configDir)) {
    throw new Error("Keycloak did not return a safe temporary configuration directory.");
  }
  cleanupWatchdog = startCleanupWatchdog();
  loginKcadm();

  if (action === "rollback-browser") {
    const before = kcadmJson("get", `realms/${realmName}`, { realmScoped: false });
    if (before.browserFlow !== "browser" && before.browserFlow !== FLOW) {
      throw new Error(`Refusing to replace unexpected browser flow ${String(before.browserFlow || "<empty>")}.`);
    }
    if (before.browserFlow === FLOW) updateBrowserFlow("browser");
    const realm = kcadmJson("get", `realms/${realmName}`, { realmScoped: false });
    if (realm.browserFlow !== "browser") throw new Error("Browser-flow rollback did not verify.");
    process.stdout.write(`realm=${realmName} browser_flow=browser action=rollback-browser status=ready\n`);
  } else if (action === "apply-staged") {
    const before = kcadmJson("get", `realms/${realmName}`, { realmScoped: false });
    if (before.browserFlow !== "browser") {
      throw new Error("Staged apply never changes browserFlow; use the separately confirmed rollback-browser action first.");
    }
    applyStagedContract();
    const verification = collectContract();
    const drift = contractDrift(verification, "staged");
    if (drift.length) throw new Error(`Staged reconciliation did not verify: ${drift.join(",")}`);
    process.stdout.write(
      `realm=${realmName} client=${clientId} browser_flow=browser action=apply-staged status=ready\n`,
    );
  } else if (action === "bind") {
    const staged = {
      ...collectContract(),
      administrator: collectAdministrator(),
    };
    const currentBinding = staged.realm.browserFlow === FLOW ? "cutover" : "staged";
    if (staged.realm.browserFlow !== "browser" && staged.realm.browserFlow !== FLOW) {
      throw new Error(`Refusing to replace unexpected browser flow ${String(staged.realm.browserFlow || "<empty>")}.`);
    }
    const beforeBinding = evaluateReadiness(staged, currentBinding === "cutover" ? "cutover" : "enrollment");
    if (!beforeBinding.ready) {
      throw new Error(`Passkey contract is not ready for binding: ${beforeBinding.drift.join(",")}`);
    }
    const changed = staged.realm.browserFlow === "browser";
    let cutoverReadiness;
    try {
      if (changed) updateBrowserFlow(FLOW);
      const cutover = {
        ...collectContract(),
        administrator: collectAdministrator(),
      };
      cutoverReadiness = evaluateReadiness(cutover, "cutover");
      if (!cutoverReadiness.ready) {
        throw new Error(`Passkey browser binding did not verify: ${cutoverReadiness.drift.join(",")}`);
      }
    } catch (error) {
      if (changed) rollbackFailedBind(error);
      throw error;
    }
    process.stdout.write(`admin=${bindAdminUsers[0]} passkeys=${cutoverReadiness.passkeyCount} status=ready\n`);
    process.stdout.write(
      `realm=${realmName} client=${clientId} browser_flow=${FLOW} browser_flow_changed=${changed} action=bind status=ready\n`,
    );
  } else if (action === "readiness") {
    const contract = collectContract();
    if (readinessPhase !== "staged") contract.administrator = collectAdministrator();
    const readiness = evaluateReadiness(contract, readinessPhase);
    if (!readiness.ready) {
      process.stdout.write(
        `realm=${realmName} client=${clientId} readiness_phase=${readinessPhase} ` +
        `drift=${readiness.drift.join(",")} status=drift\n`,
      );
      process.exitCode = 1;
    } else {
      if (readinessPhase !== "staged") {
        process.stdout.write(`admin=${bindAdminUsers[0]} passkeys=${readiness.passkeyCount} status=ready\n`);
      }
      process.stdout.write(
        `realm=${realmName} client=${clientId} readiness_phase=${readinessPhase} status=ready\n`,
      );
    }
  } else {
    const contract = collectContract();
    const drift = contractDrift(contract, expectedBinding);
    if (drift.length) {
      process.stdout.write(
        `realm=${realmName} client=${clientId} expected_binding=${expectedBinding} ` +
        `drift=${drift.join(",")} action=update-required status=drift\n`,
      );
      process.exitCode = 1;
    } else {
      process.stdout.write(
        `realm=${realmName} client=${clientId} expected_binding=${expectedBinding} action=none status=ready\n`,
      );
    }
  }
} catch (error) {
  process.stderr.write(`Keycloak passkey reconciliation failed: ${safeError(error)}\n`);
  process.exitCode = 1;
} finally {
  try {
    cleanupConfigDir();
  } catch {
    process.stderr.write("Warning: unable to remove the temporary in-container kcadm directory.\n");
    if (!process.exitCode) process.exitCode = 1;
  }
}

function applyStagedContract() {
  preflightStagedContract();
  ensureRoles();
  ensurePasskeyFlow();
  ensureClient();
  ensureFirstConfigurationClient();
  ensureRequiredAction();

  const realm = kcadmJson("get", `realms/${realmName}`, { realmScoped: false });
  const acrMap = parseAcrMap(realm.attributes?.["acr.loa.map"]);
  const extraAcrMappings = Object.keys(acrMap).filter((acr) => acr !== requiredAcr);
  if (extraAcrMappings.length) {
    throw new Error("Refusing to delete unrelated ACR-to-LoA mappings from the realm.");
  }
  const attributes = {
    ...(realm.attributes || {}),
    "acr.loa.map": JSON.stringify({ [requiredAcr]: 1 }),
  };
  kcadm("update", `realms/${realmName}`, {
    realmScoped: false,
    body: {
      enabled: true,
      bruteForceProtected: true,
      resetPasswordAllowed: false,
      rememberMe: false,
      webAuthnPolicyRpId: rpId,
      webAuthnPolicyExtraOrigins: [identityOrigin],
      webAuthnPolicyUserVerificationRequirement: "required",
      webAuthnPolicyAvoidSameAuthenticatorRegister: true,
      webAuthnPolicyPasswordlessRpId: rpId,
      webAuthnPolicyPasswordlessExtraOrigins: [identityOrigin],
      webAuthnPolicyPasswordlessRequireResidentKey: "Yes",
      webAuthnPolicyPasswordlessUserVerificationRequirement: "required",
      webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: true,
      attributes,
    },
  });
}

function preflightStagedContract() {
  const realm = kcadmJson("get", `realms/${realmName}`, { realmScoped: false });
  const acrMap = parseAcrMap(realm.attributes?.["acr.loa.map"]);
  if (Object.keys(acrMap).some((acr) => acr !== requiredAcr)) {
    throw new Error("Realm acr.loa.map contains unrelated mappings; refusing an unbounded replacement.");
  }

  const flows = kcadmJson("get", "authentication/flows");
  const inventory = authenticationFlowInventory(flows);
  const managedFlowOccurrences = inventory.filter((entry) => entry.flow.alias === FLOW);
  if (managedFlowOccurrences.length > 1 || managedFlowOccurrences.some((entry) => entry.parentAlias !== null)) {
    throw new Error(`Authentication flow alias ${FLOW} collides outside the managed top-level flow.`);
  }
  const loaFlowOccurrences = inventory.filter((entry) => entry.flow.alias === LOA_FLOW);
  if (loaFlowOccurrences.length > 1 || loaFlowOccurrences.some((entry) => entry.parentAlias !== FLOW)) {
    throw new Error(`Authentication flow alias ${LOA_FLOW} collides outside ${FLOW}.`);
  }
  const ownedAuthenticatorConfigs = new Map();
  const matches = flows.filter((flow) => flow.alias === FLOW);
  if (matches.length > 1) throw new Error(`Authentication flow ${FLOW} is duplicated.`);
  if (matches.length === 1) {
    assertTopFlowShape(matches[0]);
    const top = directExecutions(kcadmJson("get", `authentication/flows/${FLOW}/executions`));
    assertTopExecutionSafety(top);
    const subflows = top.filter((execution) => execution.authenticationFlow === true && execution.displayName === LOA_FLOW);
    if (subflows.length > 1) throw new Error(`Authentication subflow ${LOA_FLOW} is duplicated.`);
    if (subflows.length === 1) {
      assertSubflowShape(subflows[0]);
      const nested = directExecutions(kcadmJson("get", `authentication/flows/${LOA_FLOW}/executions`));
      assertNestedExecutionSafety(nested);
      const condition = nested.find((execution) => execution.providerId === "conditional-level-of-authentication");
      const webauthn = nested.find((execution) => execution.providerId === "webauthn-authenticator-passwordless");
      if (condition) {
        assertManagedExecutionConfig(condition, LOA_CONFIG_ALIAS);
        if (condition.authenticationConfig) {
          ownedAuthenticatorConfigs.set(LOA_CONFIG_ALIAS, {
            configId: condition.authenticationConfig,
            executionId: condition.id,
          });
        }
      }
      if (webauthn) {
        assertManagedExecutionConfig(webauthn, AMR_CONFIG_ALIAS);
        if (webauthn.authenticationConfig) {
          ownedAuthenticatorConfigs.set(AMR_CONFIG_ALIAS, {
            configId: webauthn.authenticationConfig,
            executionId: webauthn.id,
          });
        }
      }
    }
  }
  assertAuthenticatorConfigAliasOwnership(ownedAuthenticatorConfigs, inventory);

  const clients = exactClients();
  if (clients.length > 1) throw new Error(`OIDC client ${clientId} is duplicated.`);
  if (clients.length === 1) {
    const client = clients[0];
    if (client.protocol !== "openid-connect") throw new Error(`Existing client ${clientId} is not an OIDC client.`);
    const mappers = Array.isArray(client.protocolMappers) ? client.protocolMappers : [];
    assertExactClientProtocolMapperAllowlist(mappers);
    const amrMappers = mappers.filter((mapper) => mapper.protocolMapper === "oidc-amr-mapper");
    if (amrMappers.length > 1 || amrMappers.some((mapper) => mapper.name !== "amr" || mapper.protocol !== "openid-connect") ||
        mappers.some((mapper) => mapper.name === "amr" && mapper.protocolMapper !== "oidc-amr-mapper")) {
      throw new Error("The Control Center client has an unmanaged or duplicate AMR mapper.");
    }
    const roleMappers = mappers.filter((mapper) => mapper.protocolMapper === "oidc-usermodel-realm-role-mapper");
    if (roleMappers.length > 1 || roleMappers.some((mapper) =>
      mapper.name !== ROLE_MAPPER_NAME || mapper.protocol !== "openid-connect"
    ) ||
        mappers.some((mapper) => mapper.name === ROLE_MAPPER_NAME && mapper.protocolMapper !== "oidc-usermodel-realm-role-mapper")) {
      throw new Error("The Control Center client has an unmanaged or duplicate realm-role mapper.");
    }
    assertClientAuthTimeSafety(client);
  }

  const firstConfigurationClients = exactFirstConfigurationClients();
  if (firstConfigurationClients.length > 1) {
    throw new Error(`OIDC client ${firstConfigurationClientId} is duplicated.`);
  }
  if (firstConfigurationClients.length === 1) {
    const bootstrapClient = firstConfigurationClients[0];
    if (bootstrapClient.protocol !== "openid-connect" || bootstrapClient.publicClient === true ||
        (Array.isArray(bootstrapClient.protocolMappers) && bootstrapClient.protocolMappers.length !== 0)) {
      throw new Error("The existing first-configuration client has an unsafe or unmanaged shape.");
    }
  }
  const realmManagementClients = exactNamedClients("realm-management");
  const realmManagementClient = one(realmManagementClients, "realm-management client");
  for (const roleName of FIRST_CONFIGURATION_ADMIN_ROLES) {
    kcadmJson("get", `clients/${realmManagementClient.id}/roles/${roleName}`);
  }

  const clientScopes = kcadmJson("get", "client-scopes");
  const acrScope = one(
    clientScopes.filter((scope) => scope.name === "acr" && scope.protocol === "openid-connect"),
    "OIDC default acr client scope",
  );
  const acrMappers = kcadmJson("get", `client-scopes/${acrScope.id}/protocol-mappers/models`)
    .filter((mapper) => mapper.protocolMapper === "oidc-acr-mapper");
  if (acrMappers.length !== 1 || acrMappers[0].protocol !== "openid-connect" ||
      acrMappers[0].config?.["id.token.claim"] !== "true") {
    throw new Error("The default acr client scope does not have one enabled ID-token ACR mapper.");
  }
  assertNoClientScopeRoleMappings(acrScope, "acr");
  const rolesScope = one(
    clientScopes.filter((scope) => scope.name === "roles" && scope.protocol === "openid-connect"),
    "OIDC roles client scope",
  );
  assertFirstConfigurationRolesScope(rolesScope);
  const actions = kcadmJson("get", "authentication/required-actions");
  const enrollmentActions = actions.filter((entry) =>
    entry.alias === "webauthn-register-passwordless" || entry.providerId === "webauthn-register-passwordless"
  );
  const requiredAction = one(enrollmentActions, "webauthn-register-passwordless required action");
  if (requiredAction.alias !== "webauthn-register-passwordless" || requiredAction.providerId !== "webauthn-register-passwordless") {
    throw new Error("The passwordless WebAuthn required action has an unexpected identity.");
  }
}

function assertAuthenticatorConfigAliasOwnership(ownedConfigs, inventory) {
  const exportedRealm = kcadmJson(
    "create",
    "partial-export?exportClients=false&exportGroupsAndRoles=false",
    { query: ["-o"] },
  );
  const configs = Array.isArray(exportedRealm?.authenticatorConfig) ? exportedRealm.authenticatorConfig : [];
  const references = inventory.flatMap((entry) =>
    (entry.executions || [])
      .filter((execution) => execution.authenticationConfig)
      .map((execution) => ({
        configId: execution.authenticationConfig,
        executionId: execution.id,
        flowAlias: entry.flow.alias,
      }))
  );
  for (const alias of [LOA_CONFIG_ALIAS, AMR_CONFIG_ALIAS]) {
    const matches = configs.filter((config) => config?.alias === alias);
    const owner = ownedConfigs.get(alias);
    const ownerReferences = owner ? references.filter((entry) => entry.configId === owner.configId) : [];
    if (matches.length > 1 || (matches.length === 1 && !owner) ||
        (owner && (matches.length !== 1 || ownerReferences.length !== 1 || ownerReferences[0].executionId !== owner.executionId))) {
      throw new Error(`Authenticator configuration alias ${alias} is owned by a foreign or orphan configuration.`);
    }
  }
}

function authenticationFlowInventory(topLevelFlows) {
  const queue = (Array.isArray(topLevelFlows) ? topLevelFlows : [])
    .map((flow) => ({ flow, parentAlias: null }));
  const expanded = new Set();
  const inventory = [];
  while (queue.length) {
    const entry = queue.shift();
    const flow = entry?.flow;
    if (!flow || !flow.id || !/^[A-Za-z0-9._:-]+$/.test(flow.id) || typeof flow.alias !== "string" || !flow.alias) {
      throw new Error("Keycloak returned an unsafe authentication-flow identity during preflight.");
    }
    if (inventory.length > 256) throw new Error("Authentication-flow inventory exceeded the bounded preflight limit.");
    if (expanded.has(flow.id)) {
      inventory.push({ ...entry, executions: [] });
      continue;
    }
    expanded.add(flow.id);
    const executions = directExecutions(kcadmJson(
      "get",
      `authentication/flows/${encodeURIComponent(flow.alias)}/executions`,
    ));
    inventory.push({ ...entry, executions });
    for (const execution of executions.filter((candidate) => candidate.authenticationFlow === true)) {
      if (!execution.flowId || !/^[A-Za-z0-9._:-]+$/.test(execution.flowId)) {
        throw new Error(`Authentication flow ${flow.alias} exposes an unsafe child-flow ID.`);
      }
      const child = kcadmJson("get", `authentication/flows/${execution.flowId}`);
      queue.push({ flow: child, parentAlias: flow.alias });
    }
  }
  return inventory;
}

function ensureRoles() {
  const roles = kcadmJson("get", "roles");
  for (const name of REQUIRED_ROLES) {
    if (!roles.some((role) => role.name === name)) {
      kcadm("create", "roles", { body: { name } });
    }
  }
}

function ensurePasskeyFlow() {
  let flows = kcadmJson("get", "authentication/flows");
  let matches = flows.filter((flow) => flow.alias === FLOW);
  if (matches.length > 1) throw new Error(`Authentication flow ${FLOW} is duplicated.`);
  if (!matches.length) {
    kcadm("create", "authentication/flows", {
      body: {
        alias: FLOW,
        description: "Platform administrator passkey-only browser flow.",
        providerId: "basic-flow",
        topLevel: true,
        builtIn: false,
      },
    });
    flows = kcadmJson("get", "authentication/flows");
    matches = flows.filter((flow) => flow.alias === FLOW);
  }
  const flow = one(matches, `authentication flow ${FLOW}`);
  assertTopFlowShape(flow);

  let top = directExecutions(kcadmJson("get", `authentication/flows/${FLOW}/executions`));
  assertTopExecutionSafety(top);

  let subflow = top.filter((execution) => execution.authenticationFlow === true && execution.displayName === LOA_FLOW);
  if (subflow.length > 1) throw new Error(`Authentication subflow ${LOA_FLOW} is duplicated.`);
  if (!subflow.length) {
    kcadm("create", `authentication/flows/${FLOW}/executions/flow`, {
      body: {
        alias: LOA_FLOW,
        type: "basic-flow",
        provider: "basic-flow",
        priority: 10,
        description: "Reach passkey LoA 1 with a verified passwordless WebAuthn assertion.",
      },
    });
    top = directExecutions(kcadmJson("get", `authentication/flows/${FLOW}/executions`));
    subflow = top.filter((execution) => execution.authenticationFlow === true && execution.displayName === LOA_FLOW);
  }
  const subflowExecution = one(subflow, `authentication subflow ${LOA_FLOW}`);
  assertSubflowShape(subflowExecution);
  setExecutionRequirement(FLOW, subflowExecution, "CONDITIONAL", 10);

  let nested = directExecutions(kcadmJson("get", `authentication/flows/${LOA_FLOW}/executions`));
  assertNestedExecutionSafety(nested);
  let condition = nested.filter((execution) => execution.providerId === "conditional-level-of-authentication");
  let webauthn = nested.filter((execution) => execution.providerId === "webauthn-authenticator-passwordless");
  if (condition.length > 1 || webauthn.length > 1) throw new Error(`Authentication subflow ${LOA_FLOW} contains duplicate executions.`);
  if (!condition.length) {
    kcadm("create", `authentication/flows/${LOA_FLOW}/executions/execution`, {
      body: { provider: "conditional-level-of-authentication", priority: 10 },
    });
  }
  if (!webauthn.length) {
    kcadm("create", `authentication/flows/${LOA_FLOW}/executions/execution`, {
      body: { provider: "webauthn-authenticator-passwordless", priority: 20 },
    });
  }
  nested = directExecutions(kcadmJson("get", `authentication/flows/${LOA_FLOW}/executions`));
  condition = nested.filter((execution) => execution.providerId === "conditional-level-of-authentication");
  webauthn = nested.filter((execution) => execution.providerId === "webauthn-authenticator-passwordless");
  const conditionExecution = one(condition, "LoA condition execution");
  const webauthnExecution = one(webauthn, "WebAuthn passwordless execution");
  assertManagedExecutionConfig(conditionExecution, LOA_CONFIG_ALIAS);
  assertManagedExecutionConfig(webauthnExecution, AMR_CONFIG_ALIAS);
  setExecutionRequirement(LOA_FLOW, conditionExecution, "REQUIRED", 10);
  setExecutionRequirement(LOA_FLOW, webauthnExecution, "REQUIRED", 20);
  ensureExecutionConfig(conditionExecution, LOA_CONFIG_ALIAS, {
    "loa-condition-level": "1",
    "loa-max-age": "0",
  });
  ensureExecutionConfig(webauthnExecution, AMR_CONFIG_ALIAS, {
    "default.reference.value": "webauthn",
    "default.reference.maxAge": "300",
  });

  for (const legacy of managedLegacyExecutions(top)) {
    kcadm("delete", `authentication/executions/${legacy.id}`);
  }
}

function assertTopFlowShape(flow) {
  if (flow.providerId !== "basic-flow" || flow.builtIn !== false || flow.topLevel !== true) {
    throw new Error(`Existing authentication flow ${FLOW} has an unsafe shape.`);
  }
}

function assertTopExecutionSafety(top) {
  const unknown = top.filter((execution) =>
    !(execution.authenticationFlow === true && execution.displayName === LOA_FLOW) &&
    execution.providerId !== "webauthn-authenticator-passwordless"
  );
  if (unknown.length) throw new Error(`Authentication flow ${FLOW} contains unmanaged top-level executions.`);
  const legacy = top.filter((execution) =>
    execution.authenticationFlow !== true && execution.providerId === "webauthn-authenticator-passwordless"
  );
  if (legacy.length > 1 || legacy.some((execution) => !isManagedLegacyExecution(execution))) {
    throw new Error(`Authentication flow ${FLOW} contains duplicate or customized legacy WebAuthn executions.`);
  }
}

function isManagedLegacyExecution(execution) {
  return execution.requirement === "REQUIRED" && !execution.authenticationConfig;
}

function managedLegacyExecutions(top) {
  const legacy = top.filter((execution) =>
    execution.authenticationFlow !== true && execution.providerId === "webauthn-authenticator-passwordless"
  );
  if (legacy.length > 1 || legacy.some((execution) => !isManagedLegacyExecution(execution))) {
    throw new Error(`Authentication flow ${FLOW} contains duplicate or customized legacy WebAuthn executions.`);
  }
  return legacy;
}

function assertSubflowShape(execution) {
  if (!execution.flowId || !/^[A-Za-z0-9._:-]+$/.test(execution.flowId)) {
    throw new Error(`Authentication subflow ${LOA_FLOW} does not expose a safe flow ID.`);
  }
  const flow = kcadmJson("get", `authentication/flows/${execution.flowId}`);
  if (flow.alias !== LOA_FLOW || flow.providerId !== "basic-flow" || flow.topLevel !== false || flow.builtIn !== false) {
    throw new Error(`Authentication subflow ${LOA_FLOW} has an unsafe shape.`);
  }
  return flow;
}

function assertNestedExecutionSafety(nested) {
  const managedProviders = new Set(["conditional-level-of-authentication", "webauthn-authenticator-passwordless"]);
  if (nested.some((execution) => execution.authenticationFlow || !managedProviders.has(execution.providerId))) {
    throw new Error(`Authentication subflow ${LOA_FLOW} contains unmanaged executions.`);
  }
  const condition = nested.filter((execution) => execution.providerId === "conditional-level-of-authentication");
  const webauthn = nested.filter((execution) => execution.providerId === "webauthn-authenticator-passwordless");
  if (condition.length > 1 || webauthn.length > 1) {
    throw new Error(`Authentication subflow ${LOA_FLOW} contains duplicate executions.`);
  }
}

function assertManagedExecutionConfig(execution, expectedAlias) {
  if (!execution.authenticationConfig) return;
  const config = kcadmJson("get", `authentication/config/${execution.authenticationConfig}`);
  if (config.alias !== expectedAlias) {
    throw new Error(`Execution ${execution.providerId} references an unmanaged authenticator configuration.`);
  }
}

function ensureExecutionConfig(execution, alias, config) {
  if (execution.authenticationConfig) {
    kcadm("update", `authentication/config/${execution.authenticationConfig}`, { body: { alias, config } });
  } else {
    kcadm("create", `authentication/executions/${execution.id}/config`, { body: { alias, config } });
  }
}

function setExecutionRequirement(flowAlias, execution, requirement, priority) {
  if (execution.requirement === requirement && Number(execution.priority) === priority) return;
  kcadm("update", `authentication/flows/${flowAlias}/executions`, {
    body: {
      id: execution.id,
      requirement,
      priority,
      authenticationFlow: Boolean(execution.authenticationFlow),
      flowId: execution.flowId || undefined,
      displayName: execution.displayName || undefined,
      description: execution.description || "",
    },
  });
}

function ensureClient() {
  let clients = exactClients();
  if (clients.length > 1) throw new Error(`OIDC client ${clientId} is duplicated.`);
  if (!clients.length) {
    kcadm("create", "clients", {
      body: {
        clientId,
        name: "Platform Control Center",
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
        redirectUris: [callback],
        webOrigins: [portalOrigin],
        attributes: desiredClientAttributes({}),
      },
    });
    clients = exactClients();
  }
  const client = one(clients, `OIDC client ${clientId}`);
  kcadm("update", `clients/${client.id}`, {
    body: {
      ...client,
      enabled: true,
      protocol: "openid-connect",
      publicClient: true,
      bearerOnly: false,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      implicitFlowEnabled: false,
      serviceAccountsEnabled: false,
      fullScopeAllowed: true,
      authenticationFlowBindingOverrides: clearedFlowBindingOverrides(client.authenticationFlowBindingOverrides),
      redirectUris: [callback],
      webOrigins: [portalOrigin],
      attributes: desiredClientAttributes(client.attributes || {}),
    },
  });

  const refreshed = one(exactClients(), `OIDC client ${clientId}`);
  const mappers = Array.isArray(refreshed.protocolMappers) ? refreshed.protocolMappers : [];
  ensureClientMapper(refreshed.id, mappers, {
    name: "amr",
    protocol: "openid-connect",
    protocolMapper: "oidc-amr-mapper",
    consentRequired: false,
    config: { "id.token.claim": "true", "access.token.claim": "true" },
  });
  ensureClientMapper(refreshed.id, mappers, {
    name: ROLE_MAPPER_NAME,
    protocol: "openid-connect",
    protocolMapper: "oidc-usermodel-realm-role-mapper",
    consentRequired: false,
    config: {
      "id.token.claim": "true",
      "access.token.claim": "true",
      "claim.name": "realm_access.roles",
      "jsonType.label": "String",
      multivalued: "true",
      "user.attribute": "foo",
    },
  });
  ensureAcrScope(refreshed.id);
  ensureClientAuthTimeSource(refreshed.id, mappers);
}

function ensureFirstConfigurationClient() {
  let clients = exactFirstConfigurationClients();
  if (clients.length > 1) throw new Error(`OIDC client ${firstConfigurationClientId} is duplicated.`);
  const desiredBase = {
    clientId: firstConfigurationClientId,
    name: "Platform First Configuration",
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
  if (!clients.length) {
    kcadm("create", "clients", {
      body: { ...desiredBase, secret: firstConfigurationClientSecret, defaultClientScopes: ["roles"] },
    });
    clients = exactFirstConfigurationClients();
  }
  const client = one(clients, `OIDC client ${firstConfigurationClientId}`);
  kcadm("update", `clients/${client.id}`, {
    body: {
      ...client,
      ...desiredBase,
      secret: firstConfigurationClientSecret,
      authenticationFlowBindingOverrides: clearedFlowBindingOverrides(client.authenticationFlowBindingOverrides),
    },
  });
  const refreshed = one(exactFirstConfigurationClients(), `OIDC client ${firstConfigurationClientId}`);
  reconcileFirstConfigurationScopes(refreshed.id);
  reconcileFirstConfigurationAdminRoles(refreshed.id);
}

function reconcileFirstConfigurationScopes(clientUuid) {
  const globalScopes = kcadmJson("get", "client-scopes");
  const rolesScope = one(
    globalScopes.filter((scope) => scope.name === "roles" && scope.protocol === "openid-connect"),
    "OIDC roles client scope",
  );
  assertFirstConfigurationRolesScope(rolesScope);
  const defaults = kcadmJson("get", `clients/${clientUuid}/default-client-scopes`);
  for (const scope of defaults.filter((entry) => entry.id !== rolesScope.id)) {
    kcadm("delete", `clients/${clientUuid}/default-client-scopes/${safeResourceId(scope.id, "default client scope")}`);
  }
  if (!defaults.some((scope) => scope.id === rolesScope.id)) {
    kcadm("update", `clients/${clientUuid}/default-client-scopes/${rolesScope.id}`, { query: ["-n"] });
  }
  const optional = kcadmJson("get", `clients/${clientUuid}/optional-client-scopes`);
  for (const scope of optional) {
    kcadm("delete", `clients/${clientUuid}/optional-client-scopes/${safeResourceId(scope.id, "optional client scope")}`);
  }
}

function assertFirstConfigurationRolesScope(scope) {
  const scopeId = safeResourceId(scope?.id, "roles client scope");
  const mappers = kcadmJson("get", `client-scopes/${scopeId}/protocol-mappers/models`);
  const clientRoleMappers = mappers.filter((mapper) => mapper?.protocolMapper === "oidc-usermodel-client-role-mapper");
  if (clientRoleMappers.length !== 1 || !isExactFirstConfigurationClientRoleMapper(clientRoleMappers[0])) {
    throw new Error(
      "The shared roles client scope lacks the exact OIDC client-role access-token mapper; refusing a realm-global repair.",
    );
  }
  assertNoClientScopeRoleMappings(scope, "roles");
}

function isExactFirstConfigurationClientRoleMapper(mapper) {
  return mapper?.protocol === "openid-connect" &&
    mapper?.protocolMapper === "oidc-usermodel-client-role-mapper" &&
    mapper?.config?.["access.token.claim"] === "true" &&
    mapper?.config?.["claim.name"] === FIRST_CONFIGURATION_CLIENT_ROLE_CLAIM &&
    mapper?.config?.multivalued === "true" &&
    mapper?.config?.["jsonType.label"] === "String";
}

function reconcileFirstConfigurationAdminRoles(clientUuid) {
  const realmManagementClient = one(exactNamedClients("realm-management"), "realm-management client");
  const desiredRoles = FIRST_CONFIGURATION_ADMIN_ROLES.map((roleName) =>
    kcadmJson("get", `clients/${realmManagementClient.id}/roles/${roleName}`)
  );
  const serviceAccount = kcadmJson("get", `clients/${clientUuid}/service-account-user`);
  const serviceAccountId = safeResourceId(serviceAccount.id, "first-configuration service account");
  reconcileRoleMapping(
    `users/${serviceAccountId}/role-mappings/clients/${realmManagementClient.id}`,
    desiredRoles,
  );
  reconcileRoleMapping(
    `clients/${clientUuid}/scope-mappings/clients/${realmManagementClient.id}`,
    desiredRoles,
  );
}

function reconcileRoleMapping(endpoint, desiredRoles) {
  const desiredNames = new Set(desiredRoles.map((role) => role.name));
  const current = kcadmJson("get", endpoint);
  const extras = current.filter((role) => !desiredNames.has(role.name));
  const currentNames = new Set(current.map((role) => role.name));
  const missing = desiredRoles.filter((role) => !currentNames.has(role.name));
  if (extras.length) kcadm("delete", endpoint, { body: extras });
  if (missing.length) kcadm("create", endpoint, { body: missing });
}

function ensureClientMapper(clientUuid, existingMappers, body) {
  const providerMatches = existingMappers.filter((mapper) => mapper.protocolMapper === body.protocolMapper);
  if (providerMatches.length > 1 || providerMatches.some((mapper) => mapper.name !== body.name) ||
      existingMappers.some((mapper) => mapper.name === body.name && mapper.protocolMapper !== body.protocolMapper)) {
    throw new Error(`The Control Center client has an unmanaged or duplicate ${body.name} mapper.`);
  }
  if (providerMatches.length === 1) {
    if (!providerMatches[0].id || !/^[A-Za-z0-9._:-]+$/.test(providerMatches[0].id)) {
      throw new Error(`The Control Center ${body.name} mapper returned an unsafe ID.`);
    }
    kcadm("update", `clients/${clientUuid}/protocol-mappers/models/${providerMatches[0].id}`, { body });
  } else {
    kcadm("create", `clients/${clientUuid}/protocol-mappers/models`, { body });
  }
}

function assertExactClientProtocolMapperAllowlist(mappers) {
  if (mappers.some((mapper) => !isAllowedDirectClientMapper(mapper))) {
    throw new Error("The Control Center client has a protocol mapper outside the exact managed allowlist.");
  }
}

function isAllowedDirectClientMapper(mapper) {
  return mapper?.protocol === "openid-connect" && (
    (mapper?.name === "amr" && mapper?.protocolMapper === "oidc-amr-mapper") ||
    (mapper?.name === ROLE_MAPPER_NAME && mapper?.protocolMapper === "oidc-usermodel-realm-role-mapper") ||
    (mapper?.name === AUTH_TIME_MAPPER_NAME && mapper?.protocolMapper === "oidc-usersessionmodel-note-mapper")
  );
}

function desiredClientAttributes(existing) {
  return {
    ...existing,
    "pkce.code.challenge.method": "S256",
    "backchannel.logout.url": backchannel,
    "backchannel.logout.session.required": "true",
    "backchannel.logout.revoke.offline.tokens": "true",
  };
}

function clearedFlowBindingOverrides(existing) {
  if (!existing || typeof existing !== "object" || Array.isArray(existing)) return {};
  return Object.fromEntries(Object.keys(existing).map((key) => [key, ""]));
}

function ensureAcrScope(clientUuid) {
  const scopes = kcadmJson("get", "client-scopes");
  const acrScopes = scopes.filter((scope) => scope.name === "acr" && scope.protocol === "openid-connect");
  const acrScope = one(acrScopes, "OIDC default acr client scope");
  const mappers = kcadmJson("get", `client-scopes/${acrScope.id}/protocol-mappers/models`)
    .filter((mapper) => mapper.protocolMapper === "oidc-acr-mapper");
  if (mappers.length !== 1 || mappers[0].protocol !== "openid-connect" ||
      mappers[0].config?.["id.token.claim"] !== "true") {
    throw new Error("The default acr client scope does not have one enabled ID-token ACR mapper.");
  }
  assertNoClientScopeRoleMappings(acrScope, "acr");
  const defaults = kcadmJson("get", `clients/${clientUuid}/default-client-scopes`);
  if (!defaults.some((scope) => scope.id === acrScope.id || scope.name === "acr")) {
    kcadm("update", `clients/${clientUuid}/default-client-scopes/${acrScope.id}`, { query: ["-n"] });
  }
}

function assertClientAuthTimeSafety(client) {
  const candidates = (Array.isArray(client.protocolMappers) ? client.protocolMappers : [])
    .filter(isAuthTimeMapperCandidate);
  if (candidates.length > 1 || candidates.some((mapper) =>
    mapper.name !== AUTH_TIME_MAPPER_NAME || mapper.protocol !== "openid-connect" ||
    mapper.protocolMapper !== "oidc-usersessionmodel-note-mapper"
  )) {
    throw new Error("The Control Center client has an unmanaged or duplicate auth_time mapper.");
  }
  inspectAssignedBasicAuthTime(client.id);
}

function ensureClientAuthTimeSource(clientUuid, existingMappers) {
  const candidates = existingMappers.filter(isAuthTimeMapperCandidate);
  if (candidates.length > 1 || candidates.some((mapper) =>
    mapper.name !== AUTH_TIME_MAPPER_NAME || mapper.protocol !== "openid-connect" ||
    mapper.protocolMapper !== "oidc-usersessionmodel-note-mapper"
  )) {
    throw new Error("The Control Center client has an unmanaged or duplicate auth_time mapper.");
  }
  if (candidates.length === 1) {
    const mapper = candidates[0];
    if (!mapper.id || !/^[A-Za-z0-9._:-]+$/.test(mapper.id)) {
      throw new Error("The Control Center auth_time mapper returned an unsafe ID.");
    }
    kcadm("update", `clients/${clientUuid}/protocol-mappers/models/${mapper.id}`, {
      body: authTimeMapperBody(),
    });
    return;
  }
  if (inspectAssignedBasicAuthTime(clientUuid)) return;
  kcadm("create", `clients/${clientUuid}/protocol-mappers/models`, { body: authTimeMapperBody() });
}

function inspectAssignedBasicAuthTime(clientUuid) {
  const defaults = kcadmJson("get", `clients/${clientUuid}/default-client-scopes`);
  const basicScopes = defaults.filter((scope) => scope.name === "basic");
  if (basicScopes.length > 1) throw new Error("The Control Center client has duplicate basic scope assignments.");
  if (!basicScopes.length) return false;
  const scope = basicScopes[0];
  if (scope.protocol !== "openid-connect" || !scope.id || !/^[A-Za-z0-9._:-]+$/.test(scope.id)) {
    throw new Error("The assigned basic client scope is not a safe OIDC scope.");
  }
  assertNoClientScopeRoleMappings(scope, "basic");
  const candidates = kcadmJson("get", `client-scopes/${scope.id}/protocol-mappers/models`)
    .filter(isAuthTimeMapperCandidate);
  if (candidates.length > 1) throw new Error("The assigned basic scope has duplicate auth_time mappers.");
  if (!candidates.length) return false;
  if (candidates[0].name !== "auth_time" || !isExactAuthTimeMapper(candidates[0])) {
    throw new Error("The assigned shared basic scope has an unsafe auth_time mapper; refusing a realm-global repair.");
  }
  return true;
}

function assertNoClientScopeRoleMappings(scope, label) {
  const scopeId = safeResourceId(scope?.id, `${label} client scope`);
  const mappings = kcadmJson("get", `client-scopes/${scopeId}/scope-mappings`);
  if (!hasNoClientScopeRoleMappings(mappings)) {
    throw new Error(`The shared ${label} client scope has role scope mappings; refusing a realm-global repair.`);
  }
}

function hasNoClientScopeRoleMappings(mappings) {
  if (!mappings || typeof mappings !== "object" || Array.isArray(mappings)) return false;
  if (Object.hasOwn(mappings, "realmMappings") && !Array.isArray(mappings.realmMappings)) return false;
  if (Object.hasOwn(mappings, "clientMappings") &&
      (!mappings.clientMappings || typeof mappings.clientMappings !== "object" || Array.isArray(mappings.clientMappings))) {
    return false;
  }
  return (mappings.realmMappings || []).length === 0 &&
    Object.keys(mappings.clientMappings || {}).length === 0;
}

function authTimeMapperBody() {
  return {
    name: AUTH_TIME_MAPPER_NAME,
    protocol: "openid-connect",
    protocolMapper: "oidc-usersessionmodel-note-mapper",
    consentRequired: false,
    config: {
      "user.session.note": "AUTH_TIME",
      "introspection.token.claim": "true",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "claim.name": "auth_time",
      "jsonType.label": "long",
    },
  };
}

function isAuthTimeMapperCandidate(mapper) {
  return mapper?.name === "auth_time" || mapper?.config?.["claim.name"] === "auth_time" ||
    mapper?.config?.["user.session.note"] === "AUTH_TIME";
}

function isExactAuthTimeMapper(mapper) {
  return mapper?.protocol === "openid-connect" && mapper?.protocolMapper === "oidc-usersessionmodel-note-mapper" &&
    mapper?.config?.["user.session.note"] === "AUTH_TIME" && mapper?.config?.["id.token.claim"] === "true" &&
    mapper?.config?.["claim.name"] === "auth_time" && mapper?.config?.["jsonType.label"] === "long";
}

function ensureRequiredAction() {
  const actions = kcadmJson("get", "authentication/required-actions");
  const matches = actions.filter((entry) =>
    entry.alias === "webauthn-register-passwordless" || entry.providerId === "webauthn-register-passwordless"
  );
  const requiredAction = one(matches, "webauthn-register-passwordless required action");
  if (requiredAction.enabled !== true) {
    kcadm("update", `authentication/required-actions/${requiredAction.alias}`, {
      body: { ...requiredAction, enabled: true },
    });
  }
}

function updateBrowserFlow(browserFlow) {
  kcadm("update", `realms/${realmName}`, { realmScoped: false, body: { browserFlow } });
}

function collectContract() {
  const realm = kcadmJson("get", `realms/${realmName}`, { realmScoped: false });
  const clients = exactClients();
  const flows = kcadmJson("get", "authentication/flows").filter((flow) => flow.alias === FLOW);
  const topExecutions = flows.length === 1
    ? kcadmJson("get", `authentication/flows/${FLOW}/executions`)
    : [];
  const subflowExecution = directExecutions(topExecutions).find((entry) =>
    entry.authenticationFlow === true && entry.displayName === LOA_FLOW
  ) || null;
  const subflow = subflowExecution?.flowId && /^[A-Za-z0-9._:-]+$/.test(subflowExecution.flowId)
    ? kcadmJson("get", `authentication/flows/${subflowExecution.flowId}`)
    : null;
  const subExecutions = subflowExecution
    ? kcadmJson("get", `authentication/flows/${LOA_FLOW}/executions`)
    : [];
  const configs = new Map();
  for (const execution of [...topExecutions, ...subExecutions]) {
    if (execution.authenticationConfig && !configs.has(execution.authenticationConfig)) {
      configs.set(
        execution.authenticationConfig,
        kcadmJson("get", `authentication/config/${execution.authenticationConfig}`),
      );
    }
  }
  let acrScope = null;
  let acrScopeMappers = [];
  let acrScopeMappings = null;
  let basicScope = null;
  let basicScopeMappers = [];
  let basicScopeMappings = null;
  let defaultScopes = [];
  if (clients.length === 1) {
    defaultScopes = kcadmJson("get", `clients/${clients[0].id}/default-client-scopes`);
    acrScope = defaultScopes.find((scope) => scope.name === "acr") || null;
    if (acrScope) {
      acrScopeMappers = kcadmJson("get", `client-scopes/${acrScope.id}/protocol-mappers/models`);
      acrScopeMappings = kcadmJson("get", `client-scopes/${acrScope.id}/scope-mappings`);
    }
    basicScope = defaultScopes.find((scope) => scope.name === "basic") || null;
    if (basicScope) {
      basicScopeMappers = kcadmJson("get", `client-scopes/${basicScope.id}/protocol-mappers/models`);
      basicScopeMappings = kcadmJson("get", `client-scopes/${basicScope.id}/scope-mappings`);
    }
  }
  const requiredActions = kcadmJson("get", "authentication/required-actions");
  const roles = kcadmJson("get", "roles");
  const firstConfiguration = collectFirstConfigurationClientContract();
  return {
    realm,
    clients,
    flows,
    topExecutions,
    subflow,
    subExecutions,
    configs,
    acrScope,
    acrScopeMappers,
    acrScopeMappings,
    basicScope,
    basicScopeMappers,
    basicScopeMappings,
    requiredActions,
    roles,
    firstConfiguration,
  };
}

function contractDrift(contract, binding) {
  return uniqueSorted([
    ...keycloakPasskeyStructuralDrift(contract, {
      binding,
      identityOrigin,
      publicOrigin: portalOrigin,
      rpId,
      clientId,
      requiredAcr,
    }),
    ...firstConfigurationClientDrift(contract.firstConfiguration, firstConfigurationClientState),
  ]);
}

function collectFirstConfigurationClientContract() {
  const clients = exactFirstConfigurationClients();
  const contract = {
    clients,
    secretMatches: false,
    serviceAccount: null,
    serviceRoles: [],
    scopeRoles: [],
    defaultScopes: [],
    optionalScopes: [],
    rolesScope: null,
    rolesScopeMappers: [],
    rolesScopeMappings: null,
  };
  if (clients.length !== 1) return contract;
  const client = clients[0];
  contract.defaultScopes = kcadmJson("get", `clients/${client.id}/default-client-scopes`);
  contract.optionalScopes = kcadmJson("get", `clients/${client.id}/optional-client-scopes`);
  contract.rolesScope = contract.defaultScopes.find((scope) =>
    scope?.name === "roles" && scope?.protocol === "openid-connect"
  ) || null;
  if (contract.rolesScope) {
    const rolesScopeId = safeResourceId(contract.rolesScope.id, "roles client scope");
    contract.rolesScopeMappers = kcadmJson("get", `client-scopes/${rolesScopeId}/protocol-mappers/models`);
    contract.rolesScopeMappings = kcadmJson("get", `client-scopes/${rolesScopeId}/scope-mappings`);
  }
  if (firstConfigurationClientState === "disabled") return contract;
  const secret = kcadmJson("get", `clients/${client.id}/client-secret`);
  contract.secretMatches = safeSecretEqual(secret?.value, firstConfigurationClientSecret);
  if (client.serviceAccountsEnabled !== true) return contract;
  contract.serviceAccount = kcadmJson("get", `clients/${client.id}/service-account-user`);
  const serviceAccountId = safeResourceId(contract.serviceAccount?.id, "first-configuration service account");
  const realmManagementClients = exactNamedClients("realm-management");
  if (realmManagementClients.length !== 1) return contract;
  const realmManagementId = realmManagementClients[0].id;
  contract.serviceRoles = kcadmJson("get", `users/${serviceAccountId}/role-mappings/clients/${realmManagementId}`);
  contract.scopeRoles = kcadmJson("get", `clients/${client.id}/scope-mappings/clients/${realmManagementId}`);
  return contract;
}

function firstConfigurationClientDrift(value, expectedState) {
  const drift = [];
  const contract = value && typeof value === "object" ? value : {};
  const clients = Array.isArray(contract.clients) ? contract.clients : [];
  if (clients.length !== 1 || clients[0]?.clientId !== firstConfigurationClientId) {
    drift.push("firstConfiguration.client.unique");
    return drift;
  }
  const client = clients[0];
  if (client.protocol !== "openid-connect" || client.clientAuthenticatorType !== "client-secret" ||
      client.publicClient !== false || client.bearerOnly !== false) drift.push("firstConfiguration.client.confidential");
  if (client.standardFlowEnabled !== false || client.directAccessGrantsEnabled !== false ||
      client.implicitFlowEnabled !== false || client.fullScopeAllowed !== false) {
    drift.push("firstConfiguration.client.flows");
  }
  if (!sameStrings(client.redirectUris, []) || !sameStrings(client.webOrigins, []) ||
      Object.keys(client.authenticationFlowBindingOverrides || {}).length !== 0 ||
      (Array.isArray(client.protocolMappers) ? client.protocolMappers.length : 0) !== 0) {
    drift.push("firstConfiguration.client.surface");
  }
  if (expectedState === "active") {
    if (client.enabled !== true || client.serviceAccountsEnabled !== true) drift.push("firstConfiguration.client.lifecycle");
    if (contract.secretMatches !== true) drift.push("firstConfiguration.client.secret");
    if (contract.serviceAccount?.enabled !== true || contract.serviceAccount?.serviceAccountClientId !== firstConfigurationClientId) {
      drift.push("firstConfiguration.serviceAccount");
    }
    if (!sameRoleNames(contract.serviceRoles, FIRST_CONFIGURATION_ADMIN_ROLES)) {
      drift.push("firstConfiguration.serviceRoles");
    }
    if (!sameRoleNames(contract.scopeRoles, FIRST_CONFIGURATION_ADMIN_ROLES)) {
      drift.push("firstConfiguration.scopeRoles");
    }
    const clientRoleMappers = (Array.isArray(contract.rolesScopeMappers) ? contract.rolesScopeMappers : [])
      .filter((mapper) => mapper?.protocolMapper === "oidc-usermodel-client-role-mapper");
    if (!contract.rolesScope || clientRoleMappers.length !== 1 ||
        !isExactFirstConfigurationClientRoleMapper(clientRoleMappers[0]) ||
        !hasNoClientScopeRoleMappings(contract.rolesScopeMappings)) {
      drift.push("firstConfiguration.rolesScope");
    }
  } else if (expectedState === "disabled") {
    if (client.enabled !== false || client.serviceAccountsEnabled !== false) drift.push("firstConfiguration.client.lifecycle");
  } else {
    throw new TypeError("first-configuration client state must be active or disabled.");
  }
  if (!sameStrings((contract.defaultScopes || []).map((scope) => scope.name).sort(), ["roles"]) ||
      !sameStrings((contract.optionalScopes || []).map((scope) => scope.name).sort(), [])) {
    drift.push("firstConfiguration.client.scopes");
  }
  return uniqueSorted(drift);
}

function evaluateReadiness(contract, phase) {
  const base = evaluateKeycloakPasskeyReadiness(contract, {
    phase,
    identityOrigin,
    publicOrigin: portalOrigin,
    rpId,
    clientId,
    requiredAcr,
    adminSubject: bindAdminSubject,
    adminUsername: bindAdminUsers[0],
    minimumPasskeys,
    independenceConfirmed: true,
  });
  const drift = uniqueSorted([
    ...base.drift,
    ...firstConfigurationClientDrift(contract.firstConfiguration, firstConfigurationClientState),
  ]);
  return Object.freeze({ ...base, ready: drift.length === 0, drift: Object.freeze(drift) });
}

function collectAdministrator() {
  const user = kcadmJson("get", `users/${bindAdminSubject}`);
  return {
    user,
    credentials: user?.id ? kcadmJson("get", `users/${user.id}/credentials`) : [],
    realmRoles: user?.id ? kcadmJson("get", `users/${user.id}/role-mappings/realm`) : [],
  };
}

function rollbackFailedBind(originalError) {
  try {
    updateBrowserFlow("browser");
    const realm = kcadmJson("get", `realms/${realmName}`, { realmScoped: false });
    if (realm.browserFlow !== "browser") throw new Error("browserFlow read-back is not browser");
  } catch (rollbackError) {
    throw new Error(
      `Passkey browser binding failed (${safeError(originalError)}); automatic browserFlow rollback also failed (${safeError(rollbackError)}).`,
    );
  }
}

function exactClients() {
  const summaries = kcadmJson("get", "clients", { query: ["-q", `clientId=${clientId}`] })
    .filter((client) => client.clientId === clientId);
  return summaries.map((client) => {
    if (!client.id || !/^[A-Za-z0-9._:-]+$/.test(client.id)) {
      throw new Error(`OIDC client ${clientId} returned an unsafe ID.`);
    }
    return kcadmJson("get", `clients/${client.id}`);
  });
}

function exactFirstConfigurationClients() {
  return exactNamedClients(firstConfigurationClientId);
}

function exactNamedClients(expectedClientId) {
  const summaries = kcadmJson("get", "clients", { query: ["-q", `clientId=${expectedClientId}`] })
    .filter((client) => client.clientId === expectedClientId);
  return summaries.map((client) => {
    const id = safeResourceId(client.id, `OIDC client ${expectedClientId}`);
    return kcadmJson("get", `clients/${id}`);
  });
}

function loginKcadm() {
  docker([
    "exec", "-e", `PLATFORM_KCADM_CONFIG=${configDir}/kcadm.config`, container, "sh", "-ec",
    `umask 077
admin_password=$(cat "$KC_BOOTSTRAP_ADMIN_PASSWORD_FILE")
/opt/keycloak/bin/kcadm.sh config credentials --config "$PLATFORM_KCADM_CONFIG" --server http://127.0.0.1:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$admin_password" >/dev/null
unset admin_password`,
  ], { quiet: true });
}

function kcadmJson(command, endpoint, options = {}) {
  const output = kcadm(command, endpoint, options);
  try {
    return JSON.parse(output || "null");
  } catch {
    throw new Error(`Keycloak returned invalid JSON for ${command} ${endpoint}.`);
  }
}

function kcadm(command, endpoint, { realmScoped = true, body = undefined, query = [] } = {}) {
  const args = ["exec"];
  if (body !== undefined) args.push("-i");
  args.push(container, "/opt/keycloak/bin/kcadm.sh", command, endpoint, "--config", `${configDir}/kcadm.config`);
  if (realmScoped) args.push("-r", realmName);
  args.push(...query);
  if (body !== undefined && body !== null) args.push("-f", "-");
  return docker(args, { input: body === undefined || body === null ? undefined : JSON.stringify(body) });
}

function docker(args, { input = undefined, quiet = false } = {}) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    input,
    maxBuffer: 16 * 1024 * 1024,
    stdio: input === undefined ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"],
  });
  if (result.error) throw new Error(`Docker invocation failed: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "").trim().slice(-1200);
    throw new Error(detail ? `Docker/Keycloak command failed: ${detail}` : "Docker/Keycloak command failed.");
  }
  if (!quiet && result.stderr) process.stderr.write(redactSensitive(result.stderr));
  return String(result.stdout || "");
}

function cleanupConfigDir() {
  if (!configDir) return;
  const directory = configDir;
  docker([
    "exec", container, "sh", "-ec",
    'rm -rf -- "$1"; test ! -e "$1"', "sh", directory,
  ], { quiet: true });
  configDir = "";
  stopCleanupWatchdog();
}

function startCleanupWatchdog() {
  const watchdog = spawn("sh", [
    "-ec",
    `parent_pid=$1
container_name=$2
directory=$3
cleanup() {
  docker exec "$container_name" sh -ec 'rm -rf -- "$1"; test ! -e "$1"' sh "$directory" >/dev/null 2>&1 || true
}
trap 'cleanup; exit 0' HUP INT TERM
while kill -0 "$parent_pid" 2>/dev/null; do sleep 1; done
cleanup`,
    "sh", String(process.pid), container, configDir,
  ], { stdio: "ignore" });
  watchdog.on("error", () => {});
  watchdog.unref();
  return watchdog;
}

function stopCleanupWatchdog() {
  if (!cleanupWatchdog) return;
  if (cleanupWatchdog.exitCode === null && cleanupWatchdog.signalCode === null) cleanupWatchdog.kill("SIGTERM");
  cleanupWatchdog = null;
}

function directExecutions(executions) {
  return (Array.isArray(executions) ? executions : []).filter((entry) => Number(entry.level || 0) === 0);
}

function readFirstConfigurationClientSecret(filename) {
  const path = String(filename || "");
  if (!path || /[\r\n\0]/.test(path)) {
    throw new Error("CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE is required and unsafe.");
  }
  let value;
  try {
    value = readFileSync(path, "utf8").trim();
  } catch {
    throw new Error("Unable to read the first-configuration Keycloak client secret file.");
  }
  if (value.length < 24 || value.length > 4096 || /[\r\n\0]/.test(value)) {
    throw new Error("The first-configuration Keycloak client secret file is invalid.");
  }
  return value;
}

function safeSecretEqual(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function safeResourceId(value, label) {
  const text = String(value || "");
  if (!text || !/^[A-Za-z0-9._:-]+$/.test(text) || text.startsWith("-")) {
    throw new Error(`${label} returned an unsafe ID.`);
  }
  return text;
}

function sameStrings(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length &&
    actual.every((value, index) => value === expected[index]);
}

function sameRoleNames(actual, expected) {
  const names = (Array.isArray(actual) ? actual : []).map((role) => role?.name).filter(Boolean).sort();
  return sameStrings(names, [...expected].sort());
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function parseAcrMap(raw) {
  if (raw === undefined || raw === null || raw === "") return {};
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch {
    throw new Error("Realm acr.loa.map is not valid JSON.");
  }
  if (!parsed || Array.isArray(parsed) || Object.getPrototypeOf(parsed) !== Object.prototype) {
    throw new Error("Realm acr.loa.map must be a JSON object.");
  }
  return parsed;
}

function one(values, label) {
  if (!Array.isArray(values) || values.length !== 1) throw new Error(`Expected exactly one ${label}.`);
  return values[0];
}

function parseAdminUsers(required) {
  const users = String(env.CONTROL_CENTER_ADMIN_USERS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (required && users.length !== 1) fail("CONTROL_CENTER_ADMIN_USERS must list exactly the configured administrator.", 2);
  if (new Set(users).size !== users.length) fail("CONTROL_CENTER_ADMIN_USERS contains duplicate usernames.", 2);
  for (const username of users) safeIdentifier(username, "admin username", /^[A-Za-z0-9@._+-]+$/);
  return users;
}

function parseMinimumPasskeys() {
  const value = Number(env.CONTROL_CENTER_MIN_PASSKEYS || 2);
  if (!Number.isInteger(value) || value < 2 || value > 20) {
    fail("CONTROL_CENTER_MIN_PASSKEYS must be an integer from 2 to 20.", 2);
  }
  return value;
}

function normalizeOrigin(value, name) {
  const raw = String(value || "");
  if (!raw || raw.trim() !== raw || /[\r\n]/.test(raw)) fail(`${name} must be an origin-only HTTPS URL with a DNS hostname.`, 2);
  let url;
  try {
    url = new URL(raw);
  } catch {
    fail(`${name} must be an origin-only HTTPS URL with a DNS hostname.`, 2);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || !isDnsName(url.hostname)) {
    fail(`${name} must be an origin-only HTTPS URL with a DNS hostname.`, 2);
  }
  const port = url.port && url.port !== "443" ? `:${url.port}` : "";
  return `https://${url.hostname.toLowerCase()}${port}`;
}

function enrollmentGateForAction(currentAction, phase) {
  return currentAction === "bind" || (currentAction === "readiness" && phase !== "staged");
}

function assertRuntimeOidcContract({ requireExplicit }) {
  const issuer = String(env.CONTROL_CENTER_OIDC_ISSUER || "");
  const redirectUri = String(env.CONTROL_CENTER_OIDC_REDIRECT_URI || "");
  const requiredAmr = String(env.CONTROL_CENTER_OIDC_REQUIRED_AMR || "");
  if (requireExplicit && (!issuer || !redirectUri || !requiredAmr)) {
    fail(
      "Enrollment/cutover requires explicit CONTROL_CENTER_OIDC_ISSUER, CONTROL_CENTER_OIDC_REDIRECT_URI and CONTROL_CENTER_OIDC_REQUIRED_AMR.",
      2,
    );
  }
  if (issuer && issuer !== expectedIssuer) {
    fail(`CONTROL_CENTER_OIDC_ISSUER must be exactly ${expectedIssuer}.`, 2);
  }
  if (redirectUri && redirectUri !== callback) {
    fail(`CONTROL_CENTER_OIDC_REDIRECT_URI must be exactly ${callback}.`, 2);
  }
  if (requiredAmr) {
    const values = requiredAmr.split(",").map((value) => value.trim()).filter(Boolean);
    if (values.length !== 1 || values[0] !== "webauthn") {
      fail("CONTROL_CENTER_OIDC_REQUIRED_AMR must be exactly webauthn for passkey-only cutover.", 2);
    }
  }
}

function isDnsName(value) {
  return isIP(value) === 0 && /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(value);
}

function safeIdentifier(value, label, pattern) {
  const text = String(value || "");
  if (!text || !pattern.test(text) || text.startsWith("-")) fail(`${label} is unsafe.`, 2);
  return text;
}

function exactBoolean(value, name) {
  if (value === "true") return true;
  if (value === "false") return false;
  fail(`${name} must be exactly true or false.`, 2);
}

function safeError(error) {
  return redactSensitive(error instanceof Error ? error.message : error).replace(/[\r\n]+/g, " ").slice(0, 1600);
}

function redactSensitive(value) {
  let text = String(value || "");
  if (firstConfigurationClientSecret) {
    text = text.split(firstConfigurationClientSecret).join("[REDACTED]");
  }
  return text;
}

function fail(message, code = 1) {
  process.stderr.write(`${message}\n`);
  process.exit(code);
}
