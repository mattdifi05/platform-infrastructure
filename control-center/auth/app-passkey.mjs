import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { resolveAuthorizationCapability, } from "./route-capabilities.mjs";
import { DATABASE_ADMIN_AUTHORIZATION_PATH } from "./database-admin-gate.mjs";
import { cidrListContains, resolveClientAddress } from "../first-configuration/config.mjs";
import { AuthRequestError, MemoryAuthStore, PostgresAuthStore } from "./oidc.mjs";

const SESSION_COOKIE = "__Host-platform_cc_session";
const CSRF_COOKIE = "__Host-platform_cc_csrf";

/**
 * Control Center authentication owned by the application itself.
 *
 * There is deliberately no redirect, issuer, client secret, Keycloak session,
 * or provider callback in this class. WebAuthn assertions are verified here
 * and the credential public key/counter are stored in PostgreSQL.
 */
export class AppPasskeyAuth {
  constructor(config, store) {
    this.config = config;
    this.store = store;
    this.enabled = true;
    this.mode = "app-passkey";
  }

  assertRequest(req, { mutation = false } = {}) {
    const host = appPasskeyRequestHost(this.config, req);
    if (!host || !safeEqualText(host, this.config.publicHost)) {
      throw new AuthRequestError("The exact Control Center host is required.", 421);
    }
    const clientAddress = resolveClientAddress(this.config, req);
    if (!clientAddress || !cidrListContains(this.config.allowedCidrs, clientAddress)) {
      throw new AuthRequestError("Passkey authentication is available only from the management LAN.", 403);
    }
    if (mutation) {
      if (!safeEqualText(String(req?.headers?.origin || ""), this.config.publicOrigin)) {
        throw new AuthRequestError("Exact request origin is required.", 403);
      }
      if (String(req?.headers?.["sec-fetch-site"] || "").trim().toLowerCase() !== "same-origin") {
        throw new AuthRequestError("Same-origin Fetch Metadata is required.", 403);
      }
    }
    return {
      clientAddress,
      peerHash: sha256(`app-passkey-peer\0${clientAddress}`),
    };
  }

  async beginPasskeyRegistration(req) {
    const request = this.assertRequest(req, { mutation: true });
    const existing = await this.store.listPasskeys(this.config.adminSubject);
    if (existing.length > 0) {
      throw new AuthRequestError("A Control Center passkey is already registered. Authenticate to manage it.", 409);
    }
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userName: this.config.adminUsername,
      userDisplayName: this.config.adminDisplayName,
      userID: Buffer.from(this.config.webauthnUserId, "hex"),
      timeout: 60_000,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      excludeCredentials: existing.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
    });
    await this.store.createWebAuthnChallenge({
      challenge: options.challenge,
      challengeHash: sha256(options.challenge),
      flow: "registration",
      userId: this.config.adminSubject,
      peerHash: request.peerHash,
      expiresAt: new Date(Date.now() + this.config.challengeTtlSeconds * 1000),
    });
    return options;
  }

  async completePasskeyRegistration(req, payload) {
    const request = this.assertRequest(req, { mutation: true });
    const challenge = boundedChallenge(payload?.challenge);
    const credential = normalizeCredential(payload?.credential || payload, "registration");
    const consumed = await this.store.consumeWebAuthnChallenge({
      challengeHash: sha256(challenge),
      challenge,
      flow: "registration",
      userId: this.config.adminSubject,
      peerHash: request.peerHash,
    });
    if (!consumed) throw new AuthRequestError("The passkey registration challenge is invalid or expired.", 401);

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin: this.config.publicOrigin,
        expectedRPID: this.config.rpId,
        requireUserPresence: true,
        requireUserVerification: true,
      });
    } catch {
      throw new AuthRequestError("The passkey registration assertion is invalid.", 401);
    }
    if (!verification.verified || !verification.registrationInfo?.credential?.id ||
        !verification.registrationInfo.credential.publicKey) {
      throw new AuthRequestError("The passkey registration assertion was not verified.", 401);
    }

    const info = verification.registrationInfo;
    const stored = await this.store.listPasskeys(this.config.adminSubject);
    if (stored.length > 0) {
      throw new AuthRequestError("A Control Center passkey is already registered.", 409);
    }
    const credentialInfo = info.credential;
    const created = await this.store.createPasskey({
      id: credentialInfo.id,
      userId: this.config.adminSubject,
      webauthnUserId: this.config.webauthnUserId,
      publicKey: Buffer.from(credentialInfo.publicKey),
      counter: credentialInfo.counter,
      transports: credentialInfo.transports || credential.response.transports || [],
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.passkeyTtlSeconds * 1000),
    });
    if (!created) throw new AuthRequestError("A Control Center passkey is already registered.", 409);
    return this.createSessionResult();
  }

  async beginLogin(req) {
    const request = this.assertRequest(req, { mutation: true });
    const throttleKeyHash = sha256(`app-passkey-login\0${request.peerHash}`);
    const permit = await this.store.registerLoginAttempt(
      throttleKeyHash,
      this.config.loginMaxAttempts,
      this.config.loginWindowSeconds,
      this.config.loginLockSeconds,
    );
    if (!permit.allowed) {
      throw new AuthRequestError("Too many authentication attempts. Retry later.", 429);
    }
    const credentials = await this.store.listPasskeys(this.config.adminSubject);
    if (credentials.length === 0) {
      throw new AuthRequestError("No Control Center passkey is registered yet.", 409);
    }
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpId,
      allowCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
      userVerification: "required",
      timeout: 60_000,
    });
    await this.store.createWebAuthnChallenge({
      challenge: options.challenge,
      challengeHash: sha256(options.challenge),
      flow: "authentication",
      userId: this.config.adminSubject,
      peerHash: request.peerHash,
      expiresAt: new Date(Date.now() + this.config.challengeTtlSeconds * 1000),
    });
    return options;
  }

  async completeLogin(req, payload) {
    const request = this.assertRequest(req, { mutation: true });
    const challenge = boundedChallenge(payload?.challenge);
    const credential = normalizeCredential(payload?.credential || payload, "authentication");
    const consumed = await this.store.consumeWebAuthnChallenge({
      challengeHash: sha256(challenge),
      challenge,
      flow: "authentication",
      userId: this.config.adminSubject,
      peerHash: request.peerHash,
    });
    if (!consumed) throw new AuthRequestError("The passkey authentication challenge is invalid or expired.", 401);

    const credentials = await this.store.listPasskeys(this.config.adminSubject);
    const current = credentials.find((candidate) => candidate.id === credential.id);
    if (!current) throw new AuthRequestError("The supplied passkey is not registered for this Control Center.", 401);
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin: this.config.publicOrigin,
        expectedRPID: this.config.rpId,
        requireUserVerification: true,
        credential: {
          id: current.id,
          publicKey: current.publicKey,
          counter: current.counter,
          transports: current.transports,
        },
      });
    } catch {
      throw new AuthRequestError("The passkey authentication assertion is invalid.", 401);
    }
    if (!verification.verified || !verification.authenticationInfo) {
      throw new AuthRequestError("The passkey authentication assertion was not verified.", 401);
    }
    const info = verification.authenticationInfo;
    const updated = await this.store.updatePasskeyCounter({
      credentialId: current.id,
      userId: this.config.adminSubject,
      counter: info.newCounter,
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
    });
    if (!updated) throw new AuthRequestError("The passkey counter is stale; authenticate again.", 401);
    await this.store.clearLoginThrottle(sha256(`app-passkey-login\0${request.peerHash}`));
    return this.createSessionResult();
  }

  createSessionResult() {
    const rawSessionToken = opaqueToken(64);
    const rawCsrfToken = opaqueToken(32);
    const authTime = new Date();
    const expiresAt = new Date(Date.now() + this.config.sessionMaxAgeSeconds * 1000);
    const item = {
      tokenHash: sha256(rawSessionToken),
      csrfHash: sha256(rawCsrfToken),
      policyVersion: this.config.sessionPolicyVersion,
      subject: this.config.adminSubject,
      email: this.config.adminEmail,
      displayName: this.config.adminDisplayName,
      role: "owner",
      roles: ["owner"],
      acr: "app-passkey",
      amr: ["webauthn"],
      authTime,
      issuer: this.config.publicOrigin,
      sessionId: "",
      keyId: "",
      expiresAt,
    };
    return this.store.createSession(item).then(() => ({
      cookies: [sessionCookie(rawSessionToken, expiresAt), csrfCookie(rawCsrfToken, expiresAt)],
      role: "owner",
      subject: this.config.adminSubject,
      sessionTokenHash: item.tokenHash,
    }));
  }

  async authenticate(req) {
    try {
      this.assertRequest(req);
    } catch (error) {
      return denied(error.status || 403, error.message || "Admin authentication required.", { error: "admin_request_rejected" });
    }
    const cookies = parseCookie(req?.headers?.cookie || "");
    const token = cookies[SESSION_COOKIE] || "";
    if (!token) return denied(401, "Admin authentication required.");
    const session = await this.store.getSession(sha256(token), this.config.sessionIdleSeconds);
    if (!session || session.policyVersion !== this.config.sessionPolicyVersion || session.subject !== this.config.adminSubject) {
      return denied(401, "Admin authentication required.");
    }
    const csrfToken = cookies[CSRF_COOKIE] || "";
    const csrfCookieValid = csrfToken && safeEqualText(sha256(csrfToken), session.csrfHash);
    return {
      ok: true,
      status: 200,
      message: "",
      role: session.role,
      identity: { ...session, csrfToken: csrfCookieValid ? csrfToken : "" },
    };
  }

  authorize(req, url, session) {
    if (!session?.ok) return session;
    const method = String(req?.method || "GET").toUpperCase();
    const operation = req.controlCenterOperation || resolveAuthorizationCapability(method, url.pathname);
    if (operation.capability === "deny") return denied(403, "Endpoint capability is not declared.", { error: "endpoint_capability_denied" });
    if (operation.capability === "owner:fresh") {
      if (session.role !== "owner") return denied(403, "Platform owner authorization required.");
      const authTime = new Date(session.identity?.authTime).getTime();
      if (!Number.isFinite(authTime) || authTime > Date.now() || Date.now() - authTime > this.config.freshAuthSeconds * 1000) {
        return denied(428, "A recent passkey authentication is required.", { error: "admin_reauthentication_required", reauthUrl: "/auth/login" });
      }
    }
    if (operation.capability === "admin" && !["owner", "admin"].includes(session.role)) return denied(403, "Administrative authorization required.");
    if (operation.capability === "viewer" && !["owner", "admin", "viewer"].includes(session.role)) return denied(403, "Control Center authorization required.");
    return session;
  }

  async validateMutation(req, _url, session) {
    const method = String(req?.method || "GET").toUpperCase();
    if (["GET", "HEAD", "OPTIONS"].includes(method)) return session;
    try {
      this.assertRequest(req, { mutation: true });
    } catch (error) {
      return denied(error.status || 403, error.message || "Request rejected.", { error: "admin_request_rejected" });
    }
    if (String(req?.headers?.origin || "") !== this.config.publicOrigin) return denied(403, "Exact request origin is required.", { error: "csrf_origin_rejected" });
    if (String(req?.headers?.["sec-fetch-site"] || "").toLowerCase() !== "same-origin") return denied(403, "Same-origin Fetch Metadata is required.", { error: "csrf_fetch_site_rejected" });
    const payload = await readRequestPayload(req);
    const provided = String(req?.headers?.["x-csrf-token"] || payload._csrf || "");
    const expected = String(session?.identity?.csrfToken || "");
    if (!provided || !expected || !safeEqualText(provided, expected)) return denied(403, "CSRF validation failed.", { error: "csrf_token_rejected" });
    return session;
  }

  async logout(req) {
    const token = parseCookie(req?.headers?.cookie || "")[SESSION_COOKIE] || "";
    if (token) await this.store.revokeSession(sha256(token));
    return clearSessionCookies();
  }

  async providerSecurityEvent() { throw new AuthRequestError("Provider security events are unavailable for app-passkey authentication.", 404); }
  async backchannelLogout() { throw new AuthRequestError("OIDC back-channel logout is unavailable for app-passkey authentication.", 404); }
  async discardLogin(login) {
    const tokenHash = String(login?.sessionTokenHash || "");
    if (/^[0-9a-f]{64}$/.test(tokenHash)) await this.store.revokeSession(tokenHash);
  }
  async close() { await this.store.close(); }
}

export async function createAppPasskeyAuth(config) {
  const store = config.store === "memory" ? new MemoryAuthStore() : new PostgresAuthStore(config.databaseUrl);
  await store.ready({ requirePasskeys: true });
  return new AppPasskeyAuth(config, store);
}

function normalizeCredential(value, flow) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new AuthRequestError(`The ${flow} credential payload is invalid.`, 400);
  if (value.type !== "public-key") throw new AuthRequestError(`The ${flow} credential type is invalid.`, 400);
  const id = boundedCredentialId(value.id);
  const rawId = boundedCredentialId(value.rawId || value.id);
  const response = value.response;
  if (!response || typeof response !== "object" || Array.isArray(response)) throw new AuthRequestError(`The ${flow} credential response is invalid.`, 400);
  const required = flow === "registration"
    ? ["clientDataJSON", "attestationObject"]
    : ["clientDataJSON", "authenticatorData", "signature"];
  for (const key of required) if (!boundedBase64url(response[key])) throw new AuthRequestError(`The ${flow} credential response is incomplete.`, 400);
  if (response.userHandle !== undefined && response.userHandle !== null && !boundedBase64url(response.userHandle)) {
    throw new AuthRequestError("The passkey user handle is invalid.", 400);
  }
  return {
    id,
    rawId,
    response: {
      ...response,
      clientDataJSON: String(response.clientDataJSON),
      ...(flow === "registration"
        ? { attestationObject: String(response.attestationObject) }
        : {
          authenticatorData: String(response.authenticatorData),
          signature: String(response.signature),
          ...(response.userHandle ? { userHandle: String(response.userHandle) } : {}),
        }),
    },
    type: "public-key",
    clientExtensionResults: value.clientExtensionResults && typeof value.clientExtensionResults === "object"
      ? value.clientExtensionResults
      : {},
    ...(value.authenticatorAttachment ? { authenticatorAttachment: String(value.authenticatorAttachment) } : {}),
  };
}

function boundedCredentialId(value) {
  const id = String(value || "");
  if (!boundedBase64url(id) || id.length > 1024) throw new AuthRequestError("The passkey credential id is invalid.", 400);
  return id;
}

function boundedChallenge(value) {
  const challenge = String(value || "");
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(challenge)) throw new AuthRequestError("The passkey challenge is invalid.", 400);
  return challenge;
}

function boundedBase64url(value) {
  const text = String(value || "");
  return text.length >= 1 && text.length <= 4096 && /^[A-Za-z0-9_-]+$/.test(text);
}

async function readRequestPayload(req) {
  if (req.controlCenterPayload && typeof req.controlCenterPayload === "object") return req.controlCenterPayload;
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 256 * 1024) throw new AuthRequestError("Request payload is too large.", 413);
  }
  const type = String(req?.headers?.["content-type"] || "").toLowerCase();
  if (type.includes("application/json")) {
    try {
      const parsed = JSON.parse(body || "{}");
      req.controlCenterPayload = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      req.controlCenterPayload = {};
    }
  } else {
    req.controlCenterPayload = Object.fromEntries(new URLSearchParams(body).entries());
  }
  return req.controlCenterPayload;
}

function denied(status, message, extra = {}) { return { ok: false, status, message, ...extra }; }
function appPasskeyRequestHost(config, req) {
  const directHost = String(req?.headers?.host || "").trim().toLowerCase();
  if (safeEqualText(directHost, config.publicHost)) return directHost;
  const method = String(req?.method || "GET").trim().toUpperCase();
  const pathname = String(req?.url || "").split("?", 1)[0];
  const peerAddress = String(req?.socket?.remoteAddress || "").trim();
  if (!["GET", "HEAD"].includes(method)
      || pathname !== DATABASE_ADMIN_AUTHORIZATION_PATH
      || !cidrListContains(config.trustedProxyCidrs, peerAddress)) return directHost;
  const forwardedValues = Array.isArray(req?.headers?.["x-forwarded-host"])
    ? req.headers["x-forwarded-host"]
    : [req?.headers?.["x-forwarded-host"]];
  if (forwardedValues.length !== 1) return directHost;
  const forwardedHost = String(forwardedValues[0] || "").trim().toLowerCase();
  if (!forwardedHost || forwardedHost.includes(",") || /[\r\n]/.test(forwardedHost)) return directHost;
  return safeEqualText(forwardedHost, config.publicHost) ? forwardedHost : directHost;
}
function opaqueToken(bytes = 32) { return randomBytes(bytes).toString("base64url"); }
function sha256(value) { return createHash("sha256").update(String(value)).digest("hex"); }
function safeEqualText(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}
function parseCookie(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    try { out[decodeURIComponent(part.slice(0, index).trim())] = decodeURIComponent(part.slice(index + 1).trim()); } catch {}
  }
  return out;
}
function sessionCookie(token, expiresAt) {
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}
function csrfCookie(token, expiresAt) {
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
  return `${CSRF_COOKIE}=${token}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Strict`;
}
function clearSessionCookies() {
  return [
    `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    `${CSRF_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Strict`,
  ];
}
