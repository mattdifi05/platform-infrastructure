import { randomBytes } from "node:crypto";
import {
  assertFirstConfigurationRequest,
  FirstConfigurationError,
  readFirstConfigurationConfig,
  safeEqual,
  sha256,
} from "./config.mjs";
import { FirstConfigurationKeycloakError, KeycloakFirstConfigurationAdapter } from "./keycloak.mjs";
import {
  FIRST_CONFIGURATION_STATES,
  MemoryFirstConfigurationStore,
  PostgresFirstConfigurationStore,
} from "./store.mjs";

const SESSION_COOKIE = "__Host-platform_cc_first_configuration";
const CSRF_COOKIE = "__Host-platform_cc_first_configuration_csrf";

export { FIRST_CONFIGURATION_STATES, FirstConfigurationError };

export async function createFirstConfiguration({
  env = process.env,
  store,
  keycloak,
  oidc,
  fetchImpl = fetch,
  now = () => Date.now(),
} = {}) {
  const authMode = String(env.CONTROL_CENTER_AUTH_MODE || "").trim().toLowerCase();
  if (authMode === "app-passkey") {
    const mode = String(env.CONTROL_CENTER_FIRST_CONFIGURATION_MODE || "disabled").trim().toLowerCase();
    if (mode === "disabled") return new DisabledFirstConfiguration();
    if (mode !== "required") throw new FirstConfigurationError("CONTROL_CENTER_FIRST_CONFIGURATION_MODE must be required or disabled.", 500, "first_configuration_config_invalid");
    if (!oidc || oidc.mode !== "app-passkey") throw new FirstConfigurationError("Application passkey authentication is unavailable.", 503, "first_configuration_app_passkey_unavailable");
    return new DirectFirstConfiguration({ auth: oidc });
  }
  const config = readFirstConfigurationConfig(env);
  if (!config.enabled) return new DisabledFirstConfiguration();

  const stateStore = store || (config.store === "memory"
    ? new MemoryFirstConfigurationStore()
    : new PostgresFirstConfigurationStore(config.databaseUrl));
  const bootstrapTokenExpiresAt = new Date(now() + config.bootstrapTokenLifetimeSeconds * 1000);
  await stateStore.ready({
    bootstrapTokenHash: config.bootstrapTokenHash,
    bootstrapTokenExpiresAt,
  });
  config.bootstrapToken = undefined;

  return new FirstConfiguration({
    config,
    store: stateStore,
    keycloak: keycloak || new KeycloakFirstConfigurationAdapter(config, { fetchImpl }),
    now,
  });
}

class FirstConfiguration {
  constructor({ config, store, keycloak, now }) {
    this.enabled = true;
    this.config = config;
    this.store = store;
    this.keycloak = keycloak;
    this.now = now;
  }

  async status() {
    const state = await this.store.getState();
    if (!state) throw new FirstConfigurationError("First-configuration state is unavailable.", 503, "first_configuration_state_unavailable");
    return publicState(state, this.config);
  }

  async consumeBootstrap(req, rawToken) {
    const request = assertFirstConfigurationRequest(this.config, req, { mutation: true });
    const token = String(rawToken || "").trim();
    if (token.length < 43 || token.length > 4096 || /[\r\n\0]/.test(token)) {
      throw new FirstConfigurationError("The bootstrap code is invalid.", 401, "first_configuration_bootstrap_rejected");
    }
    const rawSessionToken = opaqueToken(64);
    const rawCsrfToken = opaqueToken(32);
    const expiresAt = new Date(this.now() + this.config.sessionMaxAgeSeconds * 1000);
    const state = await this.store.consumeBootstrapToken({
      bootstrapTokenHash: sha256(token),
      sessionTokenHash: sha256(rawSessionToken),
      csrfHash: sha256(rawCsrfToken),
      peerHash: request.peerHash,
      expiresAt,
    });
    if (!state) throw new FirstConfigurationError("The bootstrap code is invalid or expired.", 401, "first_configuration_bootstrap_rejected");
    return {
      state: publicState(state, this.config),
      cookies: [sessionCookie(rawSessionToken, expiresAt), csrfCookie(rawCsrfToken, expiresAt)],
    };
  }

  async authenticate(req) {
    let request;
    try { request = assertFirstConfigurationRequest(this.config, req); } catch (error) { return denied(error); }
    const state = await this.store.getState();
    if (!state || state.state === FIRST_CONFIGURATION_STATES.COMPLETE) {
      return { ok: false, status: 410, code: "first_configuration_closed", message: "Prima Configurazione is complete." };
    }
    const cookies = parseCookie(req.headers.cookie || "");
    const rawToken = cookies[SESSION_COOKIE] || "";
    if (!rawToken) return { ok: false, status: 401, code: "first_configuration_auth_required", message: "Prima Configurazione authentication required." };
    const session = await this.store.getSession(sha256(rawToken), request.peerHash, this.config.sessionIdleSeconds);
    if (!session) return { ok: false, status: 401, code: "first_configuration_auth_required", message: "Prima Configurazione authentication required." };
    const rawCsrf = cookies[CSRF_COOKIE] || "";
    const csrfValid = rawCsrf && safeEqual(sha256(rawCsrf), session.csrfHash);
    return {
      ok: true,
      status: 200,
      sessionTokenHash: sha256(rawToken),
      csrfToken: csrfValid ? rawCsrf : "",
      state: publicState(state, this.config),
    };
  }

  async validateMutation(req, identity, providedCsrf = "") {
    if (!identity?.ok) return identity;
    try { assertFirstConfigurationRequest(this.config, req, { mutation: true }); } catch (error) { return denied(error); }
    const provided = String(providedCsrf || req.headers["x-csrf-token"] || "");
    if (!provided || !identity.csrfToken || !safeEqual(provided, identity.csrfToken)) {
      return { ok: false, status: 403, code: "first_configuration_csrf_rejected", message: "Prima Configurazione CSRF validation failed." };
    }
    return identity;
  }

  async confirmAdministrator(identity, { username, email }) {
    requireIdentity(identity);
    const normalizedUsername = String(username || "").trim();
    const normalizedEmail = String(email || "").trim().toLowerCase();
    if (!safeEqual(normalizedUsername, this.config.adminUsername) || !safeEqual(normalizedEmail, this.config.adminEmail)) {
      throw new FirstConfigurationError("The administrator identity does not match the configured bootstrap owner.", 403, "first_configuration_identity_rejected");
    }
    const prepared = await keycloakOperation(() => this.keycloak.prepareAdministrator({ username: normalizedUsername, email: normalizedEmail }));
    const state = await this.store.recordAdministrator(prepared);
    return { state: publicState(state, this.config), temporaryPassword: prepared.temporaryPassword };
  }

  async rotateBootstrapPassword(identity) {
    requireIdentity(identity);
    const state = await this.store.getState();
    requireAdministratorState(state);
    const temporaryPassword = await keycloakOperation(() => this.keycloak.rotateBootstrapPassword(state.adminSubject));
    return { state: publicState(state, this.config), temporaryPassword };
  }

  async refreshPasskeys(identity) {
    requireIdentity(identity);
    const state = await this.store.getState();
    requireAdministratorState(state);
    const summary = await keycloakOperation(() => this.keycloak.credentialSummary(state.adminSubject));
    const updated = await this.store.recordPasskeyCount({ subject: state.adminSubject, count: summary.passkeyCount });
    return { state: publicState(updated, this.config), passkeys: summary.passkeys };
  }

  async confirmPasskeyIndependence(identity, confirmation) {
    requireIdentity(identity);
    if (confirmation?.firstTested !== true || confirmation?.secondTested !== true || confirmation?.independent !== true) {
      throw new FirstConfigurationError("Confirm both tested, independent passkeys before cutover.", 409, "first_configuration_passkey_confirmation_required");
    }
    const state = await this.store.getState();
    requireAdministratorState(state);
    const updated = await this.store.confirmPasskeyIndependence({ subject: state.adminSubject });
    return publicState(updated, this.config);
  }

  async applyPasskeyCutover(identity) {
    requireIdentity(identity);
    const state = await this.store.getState();
    if (state?.state !== FIRST_CONFIGURATION_STATES.PASSKEYS_READY || !state.passkeyIndependenceConfirmedAt) {
      throw new FirstConfigurationError("Passkey readiness and independence confirmation are required before cutover.", 409, "first_configuration_cutover_not_ready");
    }
    const summary = await keycloakOperation(() => this.keycloak.applyPasskeyOnlyCutover({
      subject: state.adminSubject,
      username: state.adminUsername,
      independenceConfirmed: Boolean(state.passkeyIndependenceConfirmedAt),
    }));
    const updated = await this.store.recordCutover({ subject: state.adminSubject, count: summary.passkeyCount });
    return publicState(updated, this.config);
  }

  async notePasskeyLogin(subject) {
    const state = await this.store.getState();
    if (!state) throw new FirstConfigurationError("First-configuration state is unavailable.", 503, "first_configuration_state_unavailable");
    if (state.state === FIRST_CONFIGURATION_STATES.COMPLETE) {
      return { accepted: true, changed: false, completed: true, state: publicState(state, this.config) };
    }
    if (!subject || !state.adminSubject || state.adminSubject !== subject) {
      throw new FirstConfigurationError("The passkey identity does not match the configured bootstrap owner.", 403, "first_configuration_subject_rejected");
    }
    if (state.state === FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED) {
      await keycloakOperation(() => this.keycloak.completeFirstPasskeyLogin({ subject }));
      const updated = await this.store.recordPasskeyLogin({ subject });
      return { accepted: true, changed: true, state: publicState(updated, this.config) };
    }
    if (state.state === FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED) {
      return { accepted: true, changed: false, state: publicState(state, this.config) };
    }
    if (state.state === FIRST_CONFIGURATION_STATES.RELOGIN_REQUIRED) {
      await this.store.recordFinalizing({ subject });
      return this.finishFinalization(subject);
    }
    if (state.state === FIRST_CONFIGURATION_STATES.FINALIZING) {
      return this.finishFinalization(subject);
    }
    throw new FirstConfigurationError("Passkey login is not available in the current setup state.", 409, "first_configuration_login_not_ready");
  }

  async retryFinalization(identity) {
    requireIdentity(identity);
    const state = await this.store.getState();
    if (!state?.adminSubject || state.state !== FIRST_CONFIGURATION_STATES.FINALIZING) {
      throw new FirstConfigurationError("First Configuration finalization is not pending.", 409, "first_configuration_finalization_not_pending");
    }
    return this.finishFinalization(state.adminSubject);
  }

  async finishFinalization(subject) {
    const receipt = await keycloakOperation(() => this.keycloak.disableBootstrapClient({ allowAlreadyDisabled: true }));
    if (!isPositiveBootstrapDisableReceipt(receipt)) {
      throw new FirstConfigurationError(
        "The temporary first-configuration client disable did not return a positive authenticated receipt.",
        503,
        "first_configuration_bootstrap_disable_unverified",
      );
    }
    const updated = await this.store.recordComplete({ subject });
    return { accepted: true, changed: true, completed: true, state: publicState(updated, this.config) };
  }

  async recordLogoutVerification(identity, oidcSubject) {
    requireIdentity(identity);
    const state = await this.store.getState();
    if (!state || state.adminSubject !== oidcSubject || state.state !== FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED) {
      throw new FirstConfigurationError("A verified owner passkey session is required.", 409, "first_configuration_logout_not_ready");
    }
    const updated = await this.store.recordLogoutVerification({ subject: oidcSubject });
    return publicState(updated, this.config);
  }

  async logoutBootstrap(req) {
    const token = parseCookie(req.headers.cookie || "")[SESSION_COOKIE] || "";
    if (token) await this.store.revokeSession(sha256(token));
    return clearCookies();
  }

  async close() { await this.store.close(); }
}

/**
 * Application-owned onboarding. The first visit is intentionally a single
 * WebAuthn registration action: there is no bootstrap code, Keycloak handoff,
 * impersonation cookie, or external identity-origin callback.
 */
class DirectFirstConfiguration {
  constructor({ auth }) {
    this.enabled = true;
    this.direct = true;
    this.auth = auth;
    this.config = auth.config;
  }

  async status() {
    const passkeys = await this.auth.store.listPasskeys(this.config.adminSubject);
    const passkeyCount = passkeys.length;
    const complete = passkeyCount >= 1;
    return {
      state: complete ? FIRST_CONFIGURATION_STATES.COMPLETE : FIRST_CONFIGURATION_STATES.REQUIRED,
      complete,
      adminSubject: this.config.adminSubject,
      adminUsername: this.config.adminUsername,
      adminEmail: this.config.adminEmail,
      passkeyCount,
      minimumPasskeys: 1,
      passkeys: passkeys.map((item) => ({ id: item.id, createdAt: item.createdAt, expiresAt: item.expiresAt })),
      publicOrigin: this.config.publicOrigin,
      identityOrigin: this.config.publicOrigin,
      rpId: this.config.rpId,
    };
  }

  async authenticate(req) {
    const state = await this.status();
    if (state.complete) {
      const session = await this.auth.authenticate(req);
      return session.ok ? { ...session, state } : {
        ok: false,
        status: 401,
        code: "first_configuration_auth_required",
        message: "Control Center passkey authentication required.",
      };
    }
    return {
      ok: false,
      status: 401,
      code: "first_configuration_auth_required",
      message: "Register the Control Center passkey to continue.",
      state,
    };
  }

  async notePasskeyLogin() { return this.status(); }
  async validateMutation(_req, identity) { return identity; }
  async close() {}
}

class DisabledFirstConfiguration {
  constructor() { this.enabled = false; }
  async status() { return { enabled: false, state: "DISABLED" }; }
  async notePasskeyLogin() { return { accepted: true, changed: false, completed: true, state: null }; }
  async close() {}
}

function publicState(state, config) {
  return {
    enabled: true,
    state: state.state,
    adminUsername: state.adminUsername || config.adminUsername,
    adminEmail: state.adminEmail || config.adminEmail,
    passkeyCount: state.passkeyCount,
    minimumPasskeys: config.minimumPasskeys,
    passkeyIndependenceConfirmed: Boolean(state.passkeyIndependenceConfirmedAt),
    cutoverApplied: Boolean(state.cutoverAt),
    passkeyLoginVerified: Boolean(state.passkeyLoginVerifiedAt),
    logoutVerified: Boolean(state.logoutVerifiedAt),
    complete: state.state === FIRST_CONFIGURATION_STATES.COMPLETE,
    accountUrl: config.accountUrl,
  };
}

function requireIdentity(identity) {
  if (!identity?.ok) throw new FirstConfigurationError("Prima Configurazione authentication required.", 401, "first_configuration_auth_required");
}

function requireAdministratorState(state) {
  if (!state?.adminSubject || ![
    FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED,
    FIRST_CONFIGURATION_STATES.PASSKEYS_READY,
  ].includes(state.state)) {
    throw new FirstConfigurationError("Confirm the administrator before passkey enrollment.", 409, "first_configuration_identity_required");
  }
}

function denied(error) {
  if (error instanceof FirstConfigurationError) {
    return { ok: false, status: error.status, code: error.code, message: error.message };
  }
  return { ok: false, status: 403, code: "first_configuration_rejected", message: "Prima Configurazione request rejected." };
}

async function keycloakOperation(operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof FirstConfigurationKeycloakError) {
      throw new FirstConfigurationError(error.message, error.status, error.code);
    }
    throw error;
  }
}

function opaqueToken(bytes) { return randomBytes(bytes).toString("base64url"); }

function isPositiveBootstrapDisableReceipt(receipt) {
  if (receipt?.disabled !== true) return false;
  return receipt.verifiedByResponse === true ||
    (receipt.alreadyDisabled === true && receipt.verifiedByReadback === true);
}

function sessionCookie(token, expiresAt) {
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function csrfCookie(token, expiresAt) {
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
  return `${CSRF_COOKIE}=${token}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Strict`;
}

function clearCookies() {
  return [
    `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
    `${CSRF_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Strict`,
  ];
}

function parseCookie(header) {
  const values = {};
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    try { values[decodeURIComponent(part.slice(0, index).trim())] = decodeURIComponent(part.slice(index + 1).trim()); } catch { /* Ignore malformed cookies. */ }
  }
  return values;
}
