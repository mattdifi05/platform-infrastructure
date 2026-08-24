export const KEYCLOAK_PASSKEY_CONTRACT = Object.freeze({
  browserFlow: "platform-passkey-browser",
  loaFlow: "platform-passkey-loa",
  loaConfigAlias: "platform-passkey-loa-1",
  amrConfigAlias: "platform-passkey-amr-webauthn",
  roleMapperName: "platform-realm-roles",
  authTimeMapperName: "platform-auth-time",
  requiredRoles: Object.freeze(["owner", "admin", "viewer"]),
});

export function keycloakPasskeyStructuralDrift(snapshot, options) {
  const expected = normalizeOptions(options);
  const drift = [];
  const realm = object(snapshot?.realm);
  const expectedBrowserFlow = expected.binding === "cutover"
    ? KEYCLOAK_PASSKEY_CONTRACT.browserFlow
    : "browser";
  if (realm.enabled !== true) drift.push("realm.enabled");
  if (realm.browserFlow !== expectedBrowserFlow) drift.push("realm.browserFlow");
  if (realm.bruteForceProtected !== true) drift.push("realm.bruteForceProtected");
  if (realm.resetPasswordAllowed !== false) drift.push("realm.resetPasswordAllowed");
  if (realm.rememberMe !== false) drift.push("realm.rememberMe");
  if (realm.webAuthnPolicyRpId !== expected.rpId) drift.push("realm.webAuthnPolicyRpId");
  if (!sameStrings(realm.webAuthnPolicyExtraOrigins, [expected.identityOrigin])) drift.push("realm.webAuthnPolicyExtraOrigins");
  if (realm.webAuthnPolicyUserVerificationRequirement !== "required") drift.push("realm.webAuthnPolicyUserVerificationRequirement");
  if (realm.webAuthnPolicyAvoidSameAuthenticatorRegister !== true) drift.push("realm.webAuthnPolicyAvoidSameAuthenticatorRegister");
  if (realm.webAuthnPolicyPasswordlessRpId !== expected.rpId) drift.push("realm.webAuthnPolicyPasswordlessRpId");
  if (!sameStrings(realm.webAuthnPolicyPasswordlessExtraOrigins, [expected.identityOrigin])) drift.push("realm.webAuthnPolicyPasswordlessExtraOrigins");
  if (realm.webAuthnPolicyPasswordlessRequireResidentKey !== "Yes") drift.push("realm.webAuthnPolicyPasswordlessRequireResidentKey");
  if (realm.webAuthnPolicyPasswordlessUserVerificationRequirement !== "required") drift.push("realm.webAuthnPolicyPasswordlessUserVerificationRequirement");
  if (realm.webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister !== true) drift.push("realm.webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister");
  if (!hasExactAcrMap(realm.attributes?.["acr.loa.map"], expected.requiredAcr)) drift.push("realm.acr.loa.map");

  const clients = array(snapshot?.clients);
  if (clients.length !== 1 || clients[0]?.clientId !== expected.clientId) {
    drift.push("client.unique");
  } else {
    const client = object(clients[0]);
    if (client.enabled !== true || client.protocol !== "openid-connect" || client.publicClient !== true ||
        client.bearerOnly !== false) drift.push("client.public");
    if (client.standardFlowEnabled !== true || client.directAccessGrantsEnabled !== false || client.implicitFlowEnabled !== false ||
        client.serviceAccountsEnabled !== false || client.fullScopeAllowed !== true) drift.push("client.flows");
    if (Object.keys(object(client.authenticationFlowBindingOverrides)).length !== 0) {
      drift.push("client.authenticationFlowBindingOverrides");
    }
    if (!sameStrings(client.redirectUris, [`${expected.publicOrigin}/auth/callback`])) drift.push("client.redirectUris");
    if (!sameStrings(client.webOrigins, [expected.publicOrigin])) drift.push("client.webOrigins");
    const attributes = object(client.attributes);
    if (attributes["pkce.code.challenge.method"] !== "S256") drift.push("client.pkce");
    if (attributes["backchannel.logout.url"] !== `${expected.publicOrigin}/auth/backchannel-logout`) drift.push("client.backchannel.url");
    if (attributes["backchannel.logout.session.required"] !== "true") drift.push("client.backchannel.session");
    if (attributes["backchannel.logout.revoke.offline.tokens"] !== "true") drift.push("client.backchannel.offline");
    const mappers = array(client.protocolMappers);
    const amrMappers = mappers.filter((mapper) => mapper?.protocolMapper === "oidc-amr-mapper");
    if (amrMappers.length !== 1 || amrMappers[0]?.name !== "amr" ||
        amrMappers[0]?.protocol !== "openid-connect" ||
        amrMappers[0]?.config?.["id.token.claim"] !== "true" || amrMappers[0]?.config?.["access.token.claim"] !== "true") {
      drift.push("client.amrMapper");
    }
    const roleMappers = mappers.filter((mapper) => mapper?.protocolMapper === "oidc-usermodel-realm-role-mapper");
    if (roleMappers.length !== 1 || roleMappers[0]?.name !== KEYCLOAK_PASSKEY_CONTRACT.roleMapperName ||
        roleMappers[0]?.protocol !== "openid-connect" ||
        roleMappers[0]?.config?.["id.token.claim"] !== "true" || roleMappers[0]?.config?.["access.token.claim"] !== "true" ||
        roleMappers[0]?.config?.["claim.name"] !== "realm_access.roles" ||
        roleMappers[0]?.config?.multivalued !== "true") drift.push("client.realmRoleMapper");
    const directAuthTimeMappers = mappers.filter(isAuthTimeMapperCandidate);
    if (directAuthTimeMappers.length > 1 || directAuthTimeMappers.some((mapper) =>
      mapper?.name !== KEYCLOAK_PASSKEY_CONTRACT.authTimeMapperName || !isExactAuthTimeMapper(mapper)
    )) drift.push("client.authTimeSource");
    if (mappers.some((mapper) => !isAllowedDirectClientMapper(mapper))) {
      drift.push("client.protocolMapperSurface");
    }
  }

  const acrMappers = array(snapshot?.acrScopeMappers).filter((mapper) => mapper?.protocolMapper === "oidc-acr-mapper");
  if (!snapshot?.acrScope || snapshot.acrScope?.protocol !== "openid-connect" || acrMappers.length !== 1 ||
      acrMappers[0]?.protocol !== "openid-connect" || acrMappers[0]?.config?.["id.token.claim"] !== "true" ||
      !hasNoScopeMappings(snapshot?.acrScopeMappings)) {
    drift.push("client.acrScope");
  }
  const clientMappers = clients.length === 1 ? array(clients[0]?.protocolMappers) : [];
  const directAuthTimeMappers = clientMappers.filter(isAuthTimeMapperCandidate);
  const directAuthTimeReady = directAuthTimeMappers.length === 1 &&
    directAuthTimeMappers[0]?.name === KEYCLOAK_PASSKEY_CONTRACT.authTimeMapperName &&
    isExactAuthTimeMapper(directAuthTimeMappers[0]);
  const basicScope = object(snapshot?.basicScope);
  const authTimeMappers = array(snapshot?.basicScopeMappers).filter(isAuthTimeMapperCandidate);
  const basicAuthTimeReady = basicScope.name === "basic" && basicScope.protocol === "openid-connect" &&
    authTimeMappers.length === 1 && authTimeMappers[0]?.name === "auth_time" &&
    isExactAuthTimeMapper(authTimeMappers[0]) && hasNoScopeMappings(snapshot?.basicScopeMappings);
  if (basicScope.name === "basic" && authTimeMappers.length > 0 && !basicAuthTimeReady) {
    drift.push("client.authTimeSource");
  }
  if (!directAuthTimeReady && !basicAuthTimeReady) drift.push("client.authTimeSource");

  const flows = array(snapshot?.flows);
  if (flows.length !== 1 || flows[0]?.alias !== KEYCLOAK_PASSKEY_CONTRACT.browserFlow ||
      flows[0]?.providerId !== "basic-flow" || flows[0]?.builtIn !== false || flows[0]?.topLevel !== true) {
    drift.push("flow.unique");
  } else {
    const directTop = directExecutions(snapshot?.topExecutions);
    const subflows = directTop.filter((entry) =>
      entry?.authenticationFlow === true && entry?.displayName === KEYCLOAK_PASSKEY_CONTRACT.loaFlow
    );
    if (directTop.length !== 1 || subflows.length !== 1 || subflows[0]?.requirement !== "CONDITIONAL" ||
        Number(subflows[0]?.priority) !== 10 || Number(subflows[0]?.index) !== 0) drift.push("flow.loaSubflow");
    const subflow = object(snapshot?.subflow);
    if (subflow.alias !== KEYCLOAK_PASSKEY_CONTRACT.loaFlow || subflow.providerId !== "basic-flow" ||
        subflow.builtIn !== false || subflow.topLevel !== false) drift.push("flow.loaSubflowShape");
    const nested = directExecutions(snapshot?.subExecutions);
    const condition = nested.filter((entry) => entry?.providerId === "conditional-level-of-authentication");
    const webauthn = nested.filter((entry) => entry?.providerId === "webauthn-authenticator-passwordless");
    if (nested.length !== 2 || condition.length !== 1 || condition[0]?.requirement !== "REQUIRED" ||
        Number(condition[0]?.priority) !== 10 || Number(condition[0]?.index) !== 0) drift.push("flow.loaCondition");
    if (nested.length !== 2 || webauthn.length !== 1 || webauthn[0]?.requirement !== "REQUIRED" ||
        Number(webauthn[0]?.priority) !== 20 || Number(webauthn[0]?.index) !== 1) drift.push("flow.webauthn");
    if (condition.length === 1) {
      const config = configFor(snapshot?.configs, condition[0]?.authenticationConfig);
      if (config?.alias !== KEYCLOAK_PASSKEY_CONTRACT.loaConfigAlias || config?.config?.["loa-condition-level"] !== "1" ||
          config?.config?.["loa-max-age"] !== "0") drift.push("flow.loaConfig");
    }
    if (webauthn.length === 1) {
      const config = configFor(snapshot?.configs, webauthn[0]?.authenticationConfig);
      if (config?.alias !== KEYCLOAK_PASSKEY_CONTRACT.amrConfigAlias || config?.config?.["default.reference.value"] !== "webauthn" ||
          config?.config?.["default.reference.maxAge"] !== "300") drift.push("flow.amrReference");
    }
    if (array(snapshot?.topExecutions).some((entry) =>
      ["auth-username-password", "auth-username-password-form", "auth-otp-form", "recovery-authn-code-form"].includes(entry?.providerId)
    )) drift.push("flow.fallbackExecution");
  }

  const enrollmentActions = array(snapshot?.requiredActions).filter((entry) =>
    entry?.alias === "webauthn-register-passwordless" || entry?.providerId === "webauthn-register-passwordless"
  );
  if (enrollmentActions.length !== 1 || enrollmentActions[0]?.alias !== "webauthn-register-passwordless" ||
      enrollmentActions[0]?.providerId !== "webauthn-register-passwordless" || enrollmentActions[0]?.enabled !== true) {
    drift.push("requiredAction.webauthnPasswordless");
  }
  for (const role of KEYCLOAK_PASSKEY_CONTRACT.requiredRoles) {
    if (!array(snapshot?.roles).some((entry) => entry?.name === role)) drift.push(`roles.${role}`);
  }
  return uniqueSorted(drift);
}

export function evaluateKeycloakPasskeyReadiness(snapshot, options) {
  const phase = String(options?.phase || "");
  if (!new Set(["staged", "enrollment", "cutover"]).has(phase)) {
    throw new TypeError("Keycloak passkey readiness phase must be staged, enrollment or cutover.");
  }
  const binding = phase === "cutover" ? "cutover" : "staged";
  const drift = keycloakPasskeyStructuralDrift(snapshot, { ...options, binding });
  let passkeyCount = 0;
  if (phase !== "staged") {
    const minimumPasskeys = Number(options?.minimumPasskeys ?? 2);
    if (!Number.isInteger(minimumPasskeys) || minimumPasskeys < 2 || minimumPasskeys > 20) {
      throw new TypeError("minimumPasskeys must be an integer from 2 to 20.");
    }
    const administrator = object(snapshot?.administrator);
    const user = object(administrator.user);
    if (!options?.adminSubject || user.id !== options.adminSubject) drift.push("administrator.subject");
    if (!options?.adminUsername || user.username !== options.adminUsername) drift.push("administrator.username");
    if (user.enabled !== true) drift.push("administrator.enabled");
    const credentials = array(administrator.credentials);
    const credentialIds = credentials
      .filter((credential) => credential?.type === "webauthn-passwordless" && typeof credential?.id === "string" && credential.id)
      .map((credential) => credential.id);
    passkeyCount = new Set(credentialIds).size;
    if (passkeyCount < minimumPasskeys) drift.push("administrator.passkeys");
    if (!array(administrator.realmRoles).some((role) => role?.name === "owner")) drift.push("administrator.ownerRole");
    if (options?.independenceConfirmed !== true) drift.push("administrator.passkeyIndependence");
  }
  const normalizedDrift = uniqueSorted(drift);
  return Object.freeze({
    ready: normalizedDrift.length === 0,
    phase,
    passkeyCount,
    drift: Object.freeze(normalizedDrift),
  });
}

function normalizeOptions(options) {
  const binding = String(options?.binding || "");
  if (binding !== "staged" && binding !== "cutover") throw new TypeError("binding must be staged or cutover.");
  const identityOrigin = exactOrigin(options?.identityOrigin, "identityOrigin");
  const publicOrigin = exactOrigin(options?.publicOrigin, "publicOrigin");
  const rpId = String(options?.rpId || "");
  if (rpId !== new URL(identityOrigin).hostname) throw new TypeError("rpId must exactly match identityOrigin hostname.");
  const clientId = nonEmpty(options?.clientId, "clientId");
  const requiredAcr = nonEmpty(options?.requiredAcr, "requiredAcr");
  return { binding, identityOrigin, publicOrigin, rpId, clientId, requiredAcr };
}

function exactOrigin(value, label) {
  let parsed;
  try { parsed = new URL(String(value || "")); } catch { throw new TypeError(`${label} must be an HTTPS origin.`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new TypeError(`${label} must be an HTTPS origin.`);
  }
  const port = parsed.port && parsed.port !== "443" ? `:${parsed.port}` : "";
  return `https://${parsed.hostname.toLowerCase()}${port}`;
}

function nonEmpty(value, label) {
  const text = String(value || "");
  if (!text) throw new TypeError(`${label} is required.`);
  return text;
}

function hasExactAcrMap(raw, requiredAcr) {
  try {
    const parsed = JSON.parse(String(raw || ""));
    return parsed && !Array.isArray(parsed) && Object.keys(parsed).length === 1 && parsed[requiredAcr] === 1;
  } catch {
    return false;
  }
}

function configFor(configs, id) {
  if (!id) return null;
  if (configs instanceof Map) return configs.get(id) || null;
  return object(configs)[id] || null;
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

function isAllowedDirectClientMapper(mapper) {
  return mapper?.protocol === "openid-connect" && (
    (mapper?.name === "amr" && mapper?.protocolMapper === "oidc-amr-mapper") ||
    (mapper?.name === KEYCLOAK_PASSKEY_CONTRACT.roleMapperName &&
      mapper?.protocolMapper === "oidc-usermodel-realm-role-mapper") ||
    (mapper?.name === KEYCLOAK_PASSKEY_CONTRACT.authTimeMapperName &&
      mapper?.protocolMapper === "oidc-usersessionmodel-note-mapper")
  );
}

function directExecutions(executions) {
  return array(executions).filter((entry) => Number(entry?.level || 0) === 0);
}

function sameStrings(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function hasNoScopeMappings(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (Object.hasOwn(value, "realmMappings") && !Array.isArray(value.realmMappings)) return false;
  if (Object.hasOwn(value, "clientMappings") &&
      (!value.clientMappings || typeof value.clientMappings !== "object" || Array.isArray(value.clientMappings))) return false;
  const realmMappings = value.realmMappings || [];
  const clientMappings = value.clientMappings || {};
  return realmMappings.length === 0 && Object.keys(clientMappings).length === 0;
}

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function array(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}
