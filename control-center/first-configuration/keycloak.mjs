import { randomBytes } from "node:crypto";
import {
  evaluateKeycloakPasskeyReadiness,
  KEYCLOAK_PASSKEY_CONTRACT,
} from "../auth/keycloak-passkey-contract.mjs";
import { readSecret } from "./config.mjs";

const REQUIRED_ACTION = "webauthn-register-passwordless";

export class FirstConfigurationKeycloakError extends Error {
  constructor(message, status = 502, code = "first_configuration_identity_unavailable") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export class KeycloakFirstConfigurationAdapter {
  constructor(config, { fetchImpl = fetch } = {}) {
    this.config = config;
    this.fetch = fetchImpl;
    this.cachedToken = null;
  }

  async prepareAdministrator({ username, email }) {
    let user = await this.findExactUser(username);
    if (!user) {
      await this.adminRequest("/users", {
        method: "POST",
        body: {
          username,
          email,
          enabled: true,
          emailVerified: true,
          requiredActions: [REQUIRED_ACTION],
        },
        expectedStatuses: [201, 204],
      });
      user = await this.findExactUser(username);
      if (!user) throw new FirstConfigurationKeycloakError("Keycloak did not materialize the configured administrator.");
    }
    if (String(user.email || "").trim().toLowerCase() && String(user.email).trim().toLowerCase() !== email.toLowerCase()) {
      throw new FirstConfigurationKeycloakError("The existing administrator email does not match the configured bootstrap identity.", 409, "first_configuration_identity_mismatch");
    }

    const subject = boundedId(user.id, "administrator subject");
    const requiredActions = new Set(Array.isArray(user.requiredActions) ? user.requiredActions.map(String) : []);
    requiredActions.add(REQUIRED_ACTION);
    await this.adminRequest(`/users/${encodeURIComponent(subject)}`, {
      method: "PUT",
      body: {
        ...user,
        username,
        email,
        enabled: true,
        emailVerified: true,
        requiredActions: [...requiredActions],
      },
      expectedStatuses: [204],
    });
    await this.ensureRealmRole(subject, this.config.ownerRole);
    const temporaryPassword = await this.rotateBootstrapPassword(subject);
    return { subject, username, email, temporaryPassword };
  }

  async rotateBootstrapPassword(subject) {
    const password = randomBytes(32).toString("base64url");
    await this.adminRequest(`/users/${encodeURIComponent(boundedId(subject, "administrator subject"))}/reset-password`, {
      method: "PUT",
      body: { type: "password", value: password, temporary: false },
      expectedStatuses: [204],
    });
    return password;
  }

  async credentialSummary(subject) {
    const credentials = await this.adminRequest(`/users/${encodeURIComponent(boundedId(subject, "administrator subject"))}/credentials`);
    if (!Array.isArray(credentials)) throw new FirstConfigurationKeycloakError("Keycloak returned an invalid credential inventory.");
    const passwordless = uniqueCredentials(credentials.filter((credential) => credential?.type === "webauthn-passwordless"));
    return {
      passkeyCount: passwordless.length,
      passkeys: passwordless.map((credential) => ({
        id: boundedOptionalText(credential.id, 256),
        label: boundedOptionalText(credential.userLabel, 256),
        createdAt: Number.isSafeInteger(Number(credential.createdDate)) ? new Date(Number(credential.createdDate)).toISOString() : "",
      })),
      passwordCredentialIds: credentials
        .filter((credential) => credential?.type === "password")
        .map((credential) => boundedId(credential.id, "password credential")),
    };
  }

  async applyPasskeyOnlyCutover({ subject, username, independenceConfirmed }) {
    const safeSubject = boundedId(subject, "administrator subject");
    const safeUsername = boundedUsername(username, "administrator username");
    if (independenceConfirmed !== true) {
      throw new FirstConfigurationKeycloakError(
        "Independent passkey confirmation is required before cutover.",
        409,
        "first_configuration_passkey_confirmation_required",
      );
    }
    const initialRealm = await this.adminRequest("");
    const browserFlow = String(initialRealm?.browserFlow || "");
    if (browserFlow !== "browser" && browserFlow !== KEYCLOAK_PASSKEY_CONTRACT.browserFlow) {
      throw new FirstConfigurationKeycloakError(
        "Keycloak has an unexpected browser authentication flow.",
        409,
        "first_configuration_passkey_contract_not_ready",
      );
    }
    let before;
    try {
      before = await this.collectPasskeySnapshot({ subject: safeSubject, realm: initialRealm });
    } catch (error) {
      if (browserFlow === KEYCLOAK_PASSKEY_CONTRACT.browserFlow) await this.rollbackBrowserFlow(error);
      throw error;
    }
    const initialPhase = browserFlow === KEYCLOAK_PASSKEY_CONTRACT.browserFlow ? "cutover" : "enrollment";
    try {
      this.requirePasskeyReadiness(before, {
        phase: initialPhase,
        subject: safeSubject,
        username: safeUsername,
        independenceConfirmed,
      });
    } catch (error) {
      if (initialPhase === "cutover") await this.rollbackBrowserFlow(error);
      throw error;
    }
    if (initialPhase === "cutover") {
      try {
        return await this.credentialSummary(safeSubject);
      } catch (error) {
        await this.rollbackBrowserFlow(error);
        throw error;
      }
    }

    let bindingAttempted = false;
    try {
      bindingAttempted = true;
      await this.adminRequest("", {
        method: "PUT",
        body: { browserFlow: KEYCLOAK_PASSKEY_CONTRACT.browserFlow },
        expectedStatuses: [204],
      });
      const after = await this.collectPasskeySnapshot({ subject: safeSubject });
      this.requirePasskeyReadiness(after, {
        phase: "cutover",
        subject: safeSubject,
        username: safeUsername,
        independenceConfirmed,
      });
      return await this.credentialSummary(safeSubject);
    } catch (error) {
      if (bindingAttempted) await this.rollbackBrowserFlow(error);
      throw error;
    }
  }

  async completeFirstPasskeyLogin({ subject }) {
    const safeSubject = boundedId(subject, "administrator subject");
    const before = await this.collectPasskeySnapshot({ subject: safeSubject });
    this.requirePasskeyReadiness(before, {
      phase: "cutover",
      subject: safeSubject,
      username: this.config.adminUsername,
      independenceConfirmed: true,
    });

    for (const credential of before.administrator.credentials) {
      if (credential?.type !== "password") continue;
      const credentialId = boundedId(credential.id, "password credential");
      await this.adminRequest(
        `/users/${encodeURIComponent(safeSubject)}/credentials/${encodeURIComponent(credentialId)}`,
        { method: "DELETE", expectedStatuses: [204, 404] },
      );
    }
    const user = await this.getUser(safeSubject);
    const requiredActions = Array.isArray(user.requiredActions) ? user.requiredActions.map(String) : [];
    const remainingActions = requiredActions.filter((action) => action !== REQUIRED_ACTION);
    if (remainingActions.length !== requiredActions.length) {
      await this.adminRequest(`/users/${encodeURIComponent(safeSubject)}`, {
        method: "PUT",
        body: { ...user, requiredActions: remainingActions },
        expectedStatuses: [204],
      });
    }

    const verified = await this.collectPasskeySnapshot({ subject: safeSubject });
    this.requirePasskeyReadiness(verified, {
      phase: "cutover",
      subject: safeSubject,
      username: this.config.adminUsername,
      independenceConfirmed: true,
    });
    if (verified.administrator.credentials.some((credential) => credential?.type === "password") ||
        (verified.administrator.user.requiredActions || []).includes(REQUIRED_ACTION)) {
      throw new FirstConfigurationKeycloakError("The first passkey login cleanup did not verify exactly.");
    }
    const summary = await this.credentialSummary(safeSubject);
    await this.adminRequest(`/users/${encodeURIComponent(safeSubject)}/logout`, {
      method: "POST",
      expectedStatuses: [204],
    });
    return summary;
  }

  async disableBootstrapClient({ allowAlreadyDisabled = false } = {}) {
    let clients;
    try {
      clients = await this.adminRequest(`/clients?clientId=${encodeURIComponent(this.config.clientId)}&max=2`);
    } catch (error) {
      if (error?.code === "first_configuration_keycloak_admin_unauthorized") {
        clients = await this.adminRequest(`/clients?clientId=${encodeURIComponent(this.config.clientId)}&max=2`);
      } else {
        throw error;
      }
    }
    const summary = exactClient(clients, this.config.clientId, "temporary first-configuration client");
    const clientId = boundedId(summary.id, "first-configuration client");
    const client = await this.adminRequest(`/clients/${encodeURIComponent(clientId)}`);
    if (client?.clientId !== this.config.clientId) {
      throw new FirstConfigurationKeycloakError("The temporary first-configuration client read-back changed identity.");
    }
    if (client.enabled === false && client.serviceAccountsEnabled === false) {
      if (allowAlreadyDisabled !== true) {
        throw new FirstConfigurationKeycloakError(
          "The temporary first-configuration client is already disabled.",
          409,
          "first_configuration_bootstrap_client_already_disabled",
        );
      }
      this.cachedToken = null;
      return { disabled: true, alreadyDisabled: true, verifiedByReadback: true };
    }
    await this.adminRequest(`/clients/${encodeURIComponent(clientId)}`, {
      method: "PUT",
      body: { ...client, enabled: false, serviceAccountsEnabled: false },
      expectedStatuses: [204],
    });
    // Keycloak may invalidate Admin REST bearer tokens as soon as their client
    // is disabled, so the authenticated 204 response is the terminal receipt.
    // OAuth invalid_client is never evidence of the client's lifecycle state.
    this.cachedToken = null;
    return { disabled: true, alreadyDisabled: false, verifiedByResponse: true };
  }

  async collectPasskeySnapshot({ subject, realm: suppliedRealm } = {}) {
    const realm = suppliedRealm || await this.adminRequest("");
    const clientSummaries = await this.adminRequest(
      `/clients?clientId=${encodeURIComponent(this.config.controlCenterClientId)}&max=2`,
    );
    const clientSummary = exactClient(clientSummaries, this.config.controlCenterClientId, "Control Center OIDC client");
    const client = await this.adminRequest(
      `/clients/${encodeURIComponent(boundedId(clientSummary.id, "Control Center client"))}`,
    );
    const flows = await this.adminRequest("/authentication/flows");
    if (!Array.isArray(flows)) throw new FirstConfigurationKeycloakError("Keycloak returned an invalid authentication-flow inventory.");
    const managedFlows = flows.filter((flow) => flow?.alias === KEYCLOAK_PASSKEY_CONTRACT.browserFlow);
    const topExecutions = managedFlows.length === 1
      ? await this.adminRequest(`/authentication/flows/${encodeURIComponent(KEYCLOAK_PASSKEY_CONTRACT.browserFlow)}/executions`)
      : [];
    const directTop = Array.isArray(topExecutions)
      ? topExecutions.filter((entry) => Number(entry?.level || 0) === 0)
      : [];
    const subflowExecution = directTop.find((entry) =>
      entry?.authenticationFlow === true && entry?.displayName === KEYCLOAK_PASSKEY_CONTRACT.loaFlow
    ) || null;
    const subflowId = subflowExecution?.flowId
      ? boundedId(subflowExecution.flowId, "passkey LoA subflow")
      : "";
    const subflow = subflowId
      ? await this.adminRequest(`/authentication/flows/${encodeURIComponent(subflowId)}`)
      : null;
    const subExecutions = subflowExecution
      ? await this.adminRequest(`/authentication/flows/${encodeURIComponent(KEYCLOAK_PASSKEY_CONTRACT.loaFlow)}/executions`)
      : [];
    const configs = new Map();
    for (const execution of [...directTop, ...(Array.isArray(subExecutions) ? subExecutions : [])]) {
      if (!execution?.authenticationConfig || configs.has(execution.authenticationConfig)) continue;
      const configId = boundedId(execution.authenticationConfig, "authenticator configuration");
      configs.set(configId, await this.adminRequest(`/authentication/config/${encodeURIComponent(configId)}`));
    }

    const defaultScopes = await this.adminRequest(
      `/clients/${encodeURIComponent(boundedId(client.id, "Control Center client"))}/default-client-scopes`,
    );
    if (!Array.isArray(defaultScopes)) throw new FirstConfigurationKeycloakError("Keycloak returned an invalid client-scope inventory.");
    const acrScope = exactOptionalScope(defaultScopes, "acr");
    const basicScope = exactOptionalScope(defaultScopes, "basic");
    const acrScopeMappers = acrScope
      ? await this.adminRequest(`/client-scopes/${encodeURIComponent(boundedId(acrScope.id, "ACR client scope"))}/protocol-mappers/models`)
      : [];
    const acrScopeMappings = acrScope
      ? await this.adminRequest(`/client-scopes/${encodeURIComponent(boundedId(acrScope.id, "ACR client scope"))}/scope-mappings`)
      : null;
    const basicScopeMappers = basicScope
      ? await this.adminRequest(`/client-scopes/${encodeURIComponent(boundedId(basicScope.id, "basic client scope"))}/protocol-mappers/models`)
      : [];
    const basicScopeMappings = basicScope
      ? await this.adminRequest(`/client-scopes/${encodeURIComponent(boundedId(basicScope.id, "basic client scope"))}/scope-mappings`)
      : null;

    const snapshot = {
      realm,
      clients: [client],
      flows: managedFlows,
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
      requiredActions: await this.adminRequest("/authentication/required-actions"),
      roles: await this.adminRequest("/roles"),
    };
    if (subject) {
      const safeSubject = boundedId(subject, "administrator subject");
      snapshot.administrator = {
        user: await this.getUser(safeSubject),
        credentials: await this.adminRequest(`/users/${encodeURIComponent(safeSubject)}/credentials`),
        realmRoles: await this.adminRequest(`/users/${encodeURIComponent(safeSubject)}/role-mappings/realm`),
      };
    }
    return snapshot;
  }

  requirePasskeyReadiness(snapshot, { phase, subject, username, independenceConfirmed }) {
    const result = evaluateKeycloakPasskeyReadiness(snapshot, {
      phase,
      identityOrigin: this.config.identityOrigin,
      publicOrigin: this.config.publicOrigin,
      rpId: this.config.rpId,
      clientId: this.config.controlCenterClientId,
      requiredAcr: this.config.requiredAcr,
      adminSubject: subject,
      adminUsername: username,
      minimumPasskeys: this.config.minimumPasskeys,
      independenceConfirmed,
    });
    if (!result.ready) {
      throw new FirstConfigurationKeycloakError(
        `Keycloak passkey readiness failed: ${result.drift.join(",")}.`,
        409,
        "first_configuration_passkey_contract_not_ready",
      );
    }
    return result;
  }

  async rollbackBrowserFlow(originalError) {
    try {
      await this.adminRequest("", {
        method: "PUT",
        body: { browserFlow: "browser" },
        expectedStatuses: [204],
      });
      const realm = await this.adminRequest("");
      if (realm?.browserFlow !== "browser") throw new Error("browserFlow read-back is not browser");
    } catch (rollbackError) {
      throw new FirstConfigurationKeycloakError(
        `Passkey browser binding failed (${safeMessage(originalError)}); browserFlow rollback also failed (${safeMessage(rollbackError)}).`,
      );
    }
  }

  async findExactUser(username) {
    const users = await this.adminRequest(`/users?username=${encodeURIComponent(username)}&exact=true&max=2`);
    if (!Array.isArray(users)) throw new FirstConfigurationKeycloakError("Keycloak returned an invalid user inventory.");
    const exact = users.filter((user) => user?.username === username);
    if (exact.length > 1) throw new FirstConfigurationKeycloakError("The configured administrator is duplicated.", 409, "first_configuration_identity_duplicated");
    return exact[0] || null;
  }

  async getUser(subject) {
    return this.adminRequest(`/users/${encodeURIComponent(boundedId(subject, "administrator subject"))}`);
  }

  async ensureRealmRole(subject, roleName) {
    const role = await this.adminRequest(`/roles/${encodeURIComponent(roleName)}`);
    const mappings = await this.adminRequest(`/users/${encodeURIComponent(subject)}/role-mappings/realm`);
    if (!Array.isArray(mappings)) throw new FirstConfigurationKeycloakError("Keycloak returned an invalid role mapping.");
    if (mappings.some((item) => item?.name === roleName)) return;
    await this.adminRequest(`/users/${encodeURIComponent(subject)}/role-mappings/realm`, {
      method: "POST",
      body: [role],
      expectedStatuses: [204],
    });
  }

  async adminRequest(pathname, { method = "GET", body, expectedStatuses = [200] } = {}) {
    const token = await this.serviceToken();
    const target = new URL(`${this.config.adminBaseUrl}${pathname}`);
    const response = await this.fetch(target, {
      method,
      redirect: "error",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!expectedStatuses.includes(response.status)) {
      if (response.status === 401) {
        this.cachedToken = null;
        throw new FirstConfigurationKeycloakError(
          "Keycloak rejected the first-configuration Admin REST bearer.",
          503,
          "first_configuration_keycloak_admin_unauthorized",
        );
      }
      throw new FirstConfigurationKeycloakError(`Keycloak rejected a bounded first-configuration operation (${response.status}).`);
    }
    if (response.status === 204 || response.status === 201 || method === "DELETE") return null;
    return boundedJson(response);
  }

  async serviceToken() {
    const now = Date.now();
    if (this.cachedToken?.expiresAt > now + 5_000) return this.cachedToken.value;
    const secret = readSecret(this.config.keycloakClientSecretFile, "first-configuration Keycloak client secret", 24);
    const response = await this.fetch(this.config.tokenEndpoint, {
      method: "POST",
      redirect: "error",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: this.config.clientId, client_secret: secret }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) {
      let payload;
      try { payload = await boundedJson(response); } catch {
        throw new FirstConfigurationKeycloakError("The temporary Keycloak first-configuration client is unavailable.");
      }
      if ((response.status === 400 || response.status === 401) && payload?.error === "invalid_client") {
        throw new FirstConfigurationKeycloakError(
          "The temporary Keycloak first-configuration client no longer accepts credentials.",
          503,
          "first_configuration_keycloak_invalid_client",
        );
      }
      throw new FirstConfigurationKeycloakError("The temporary Keycloak first-configuration client is unavailable.");
    }
    const payload = await boundedJson(response);
    const value = typeof payload.access_token === "string" ? payload.access_token : "";
    const expiresIn = Number(payload.expires_in || 0);
    if (!value || value.length > 16384 || !Number.isFinite(expiresIn) || expiresIn < 10 || expiresIn > 3600) {
      throw new FirstConfigurationKeycloakError("Keycloak returned an invalid first-configuration token.");
    }
    this.cachedToken = { value, expiresAt: now + expiresIn * 1000 };
    return value;
  }
}

async function boundedJson(response) {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > 1024 * 1024) throw new FirstConfigurationKeycloakError("Keycloak response exceeded the first-configuration limit.");
  const text = await response.text();
  if (Buffer.byteLength(text) > 1024 * 1024) throw new FirstConfigurationKeycloakError("Keycloak response exceeded the first-configuration limit.");
  try { return JSON.parse(text || "null"); } catch { throw new FirstConfigurationKeycloakError("Keycloak returned malformed JSON."); }
}

function boundedId(value, label) {
  const text = String(value || "").trim();
  if (!/^[A-Za-z0-9._:-]{1,256}$/.test(text)) throw new FirstConfigurationKeycloakError(`Keycloak returned an invalid ${label}.`);
  return text;
}

function boundedOptionalText(value, maximum) {
  const text = String(value || "").trim();
  return text.length <= maximum && !/[\r\n\0]/.test(text) ? text : "";
}

function boundedUsername(value, label) {
  const text = String(value || "").trim();
  if (!/^[A-Za-z0-9@._+-]{1,128}$/.test(text)) {
    throw new FirstConfigurationKeycloakError(`Keycloak returned an invalid ${label}.`);
  }
  return text;
}

function exactClient(value, clientId, label) {
  if (!Array.isArray(value)) throw new FirstConfigurationKeycloakError(`Keycloak returned an invalid ${label} inventory.`);
  const exact = value.filter((client) => client?.clientId === clientId);
  if (exact.length !== 1) throw new FirstConfigurationKeycloakError(`The ${label} is missing or duplicated.`);
  return exact[0];
}

function exactOptionalScope(scopes, name) {
  const exact = scopes.filter((scope) => scope?.name === name);
  if (exact.length > 1) throw new FirstConfigurationKeycloakError(`The assigned ${name} client scope is duplicated.`);
  return exact[0] || null;
}

function uniqueCredentials(credentials) {
  const unique = new Map();
  for (const credential of credentials) {
    const id = boundedId(credential?.id, "passkey credential");
    if (!unique.has(id)) unique.set(id, credential);
  }
  return [...unique.values()];
}

function safeMessage(error) {
  return String(error instanceof Error ? error.message : error).replace(/[\r\n]+/g, " ").slice(0, 800);
}
