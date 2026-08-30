import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { isIP } from "node:net";
import pg from "pg";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { resolveAuthorizationCapability } from "./route-capabilities.mjs";
import { DATABASE_ADMIN_AUTHORIZATION_PATH } from "./database-admin-gate.mjs";

const { Pool } = pg;

const SESSION_COOKIE = "__Host-platform_cc_session";
const CSRF_COOKIE = "__Host-platform_cc_csrf";

export class AuthConfigurationError extends Error {}

export class AuthRequestError extends Error {
  constructor(message, status = 401) {
    super(message);
    this.status = status;
  }
}

export async function createControlCenterAuth({ env = process.env } = {}) {
  const config = readAuthConfig(env);
  if (config.mode === "test-disabled") return new TestDisabledAuth(config);
  const store = config.store === "memory"
    ? new MemoryAppPasskeyStore()
    : new PostgresAppPasskeyStore(config.databaseUrl);
  await store.ready();
  await seedTestSessions(store, config, env);
  return new AppPasskeyAuth(config, store);
}

export function readAuthConfig(env = process.env) {
  const environment = String(env.CONTROL_CENTER_ENV || "local").trim().toLowerCase();
  const nodeEnvironment = String(env.NODE_ENV || "production").trim().toLowerCase();
  const bindHost = String(env.CONTROL_CENTER_BIND_HOST || "0.0.0.0").trim();
  const mode = String(env.CONTROL_CENTER_AUTH_MODE || "").trim().toLowerCase();
  if (mode === "test-disabled") {
    if (nodeEnvironment !== "test" || !isLoopback(bindHost)) {
      throw new AuthConfigurationError("test-disabled authentication requires NODE_ENV=test and a loopback bind address.");
    }
    return { mode, environment, bindHost };
  }
  if (mode !== "app-passkey") {
    throw new AuthConfigurationError("CONTROL_CENTER_AUTH_MODE must be app-passkey.");
  }
  if (String(env.NODE_TLS_REJECT_UNAUTHORIZED || "").trim() === "0") {
    throw new AuthConfigurationError("TLS certificate verification must remain enabled.");
  }

  const store = String(env.CONTROL_CENTER_AUTH_STORE || "postgres").trim().toLowerCase();
  if (!['postgres', 'memory'].includes(store)) {
    throw new AuthConfigurationError("CONTROL_CENTER_AUTH_STORE must be postgres or memory.");
  }
  if (store === "memory" && nodeEnvironment !== "test") {
    throw new AuthConfigurationError("The in-memory app-passkey store is restricted to NODE_ENV=test.");
  }

  const publicOrigin = exactHttpsOrigin(env.CONTROL_CENTER_PUBLIC_ORIGIN, "CONTROL_CENTER_PUBLIC_ORIGIN");
  const publicUrl = new URL(publicOrigin);
  const publicHost = publicUrl.host.toLowerCase();
  const rpId = String(env.CONTROL_CENTER_AUTH_RP_ID || publicUrl.hostname).trim().toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(rpId) ||
      (publicUrl.hostname.toLowerCase() !== rpId && !publicUrl.hostname.toLowerCase().endsWith(`.${rpId}`))) {
    throw new AuthConfigurationError("CONTROL_CENTER_AUTH_RP_ID must be the exact Control Center hostname or a parent suffix.");
  }

  const adminUsername = requiredText(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME || "admin",
    "CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME",
  );
  const adminEmail = requiredText(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL || "admin@example.com",
    "CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL",
  );
  const adminSubject = `app-admin:${sha256(`${publicOrigin}\0${adminUsername}`).slice(0, 48)}`;
  return {
    mode,
    environment,
    nodeEnvironment,
    bindHost,
    publicOrigin,
    publicHost,
    rpId,
    rpName: requiredText(env.CONTROL_CENTER_AUTH_RP_NAME || "Platform Control Center", "CONTROL_CENTER_AUTH_RP_NAME"),
    adminUsername,
    adminEmail,
    adminDisplayName: String(env.CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_DISPLAY_NAME || adminUsername).trim() || adminUsername,
    adminSubject,
    webauthnUserId: sha256(`webauthn-user\0${adminSubject}`),
    sessionMaxAgeSeconds: boundedInteger(env.CONTROL_CENTER_SESSION_MAX_AGE_SECONDS, 86400, 3600, 7 * 86400),
    sessionIdleSeconds: boundedInteger(env.CONTROL_CENTER_SESSION_IDLE_SECONDS, 86400, 300, 7 * 86400),
    passkeyTtlSeconds: boundedInteger(env.CONTROL_CENTER_PASSKEY_TTL_SECONDS, 10 * 365 * 86400, 86400, 20 * 365 * 86400),
    challengeTtlSeconds: boundedInteger(env.CONTROL_CENTER_PASSKEY_CHALLENGE_TTL_SECONDS, 300, 60, 86400),
    freshAuthSeconds: boundedInteger(env.CONTROL_CENTER_FRESH_AUTH_SECONDS, 300, 60, 900),
    loginMaxAttempts: boundedInteger(env.CONTROL_CENTER_LOGIN_MAX_ATTEMPTS, 20, 2, 100),
    loginWindowSeconds: boundedInteger(env.CONTROL_CENTER_LOGIN_WINDOW_SECONDS, 60, 10, 600),
    loginLockSeconds: boundedInteger(env.CONTROL_CENTER_LOGIN_LOCK_SECONDS, 60, 10, 3600),
    sessionPolicyVersion: requiredText(env.CONTROL_CENTER_SESSION_POLICY_VERSION || "1", "CONTROL_CENTER_SESSION_POLICY_VERSION"),
    allowedCidrs: parseCidrs(env.CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS || "192.168.1.0/24,127.0.0.0/8,::1/128"),
    trustedProxyCidrs: parseCidrs(env.CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS || "172.16.0.0/12,127.0.0.0/8,::1/128"),
    store,
    databaseUrl: store === "postgres" ? readDatabaseUrl(env.CONTROL_CENTER_AUTH_DATABASE_URL_FILE) : "",
  };
}

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
      const code = error?.message === "Exact request origin is required."
        ? "csrf_origin_rejected"
        : error?.message === "Same-origin Fetch Metadata is required."
          ? "csrf_fetch_site_rejected"
          : "admin_request_rejected";
      return denied(error.status || 403, error.message || "Request rejected.", { error: code });
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

  async close() { await this.store.close(); }
}

export async function createAppPasskeyAuth(config) {
  const store = config.store === "memory"
    ? new MemoryAppPasskeyStore()
    : new PostgresAppPasskeyStore(config.databaseUrl);
  await store.ready();
  return new AppPasskeyAuth(config, store);
}

class TestDisabledAuth {
  constructor(config) {
    this.config = config;
    this.enabled = false;
    this.mode = config.mode;
  }
  async authenticate() {
    return { ok: true, status: 200, message: "", role: "owner", identity: { subject: "test-owner", role: "owner" } };
  }
  authorize(_req, _url, session) { return session; }
  async validateMutation(_req, _url, session) { return session; }
  async close() {}
}

export class PostgresAppPasskeyStore {
  constructor(connectionString) {
    this.pool = new Pool({ connectionString, max: 5, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000 });
  }

  async ready() {
    const result = await this.pool.query(
      `select to_regclass('control_auth.sessions') as sessions,
              to_regclass('control_auth.login_throttle') as throttle,
              to_regclass('control_auth.passkeys') as passkeys,
              to_regclass('control_auth.webauthn_challenges') as webauthn_challenges,
              exists(select 1 from information_schema.columns
                     where table_schema='control_auth' and table_name='sessions' and column_name='csrf_hash') as csrf_ready,
              exists(select 1 from information_schema.columns
                     where table_schema='control_auth' and table_name='sessions' and column_name='policy_version') as policy_ready`,
    );
    const row = result.rows[0] || {};
    if (!row.sessions || !row.throttle || !row.passkeys || !row.webauthn_challenges || !row.csrf_ready || !row.policy_ready) {
      throw new AuthConfigurationError("Control Center app-passkey migration is not applied.");
    }
  }

  async createSession(item) {
    await this.pool.query(
      `insert into control_auth.sessions
       (token_hash,csrf_hash,policy_version,subject,email,display_name,role,roles,acr,amr,auth_time,issuer,oidc_session_id,signing_key_id,expires_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [
        item.tokenHash,
        item.csrfHash,
        item.policyVersion,
        item.subject,
        item.email,
        item.displayName,
        item.role,
        item.roles,
        item.acr,
        item.amr,
        item.authTime,
        item.issuer,
        item.sessionId || "",
        item.keyId || "",
        item.expiresAt,
      ],
    );
  }

  async getSession(tokenHash, idleSeconds) {
    const result = await this.pool.query(
      `update control_auth.sessions
       set last_seen_at=now()
       where token_hash=$1 and revoked_at is null and expires_at > now()
         and last_seen_at > now() - ($2::text || ' seconds')::interval
       returning subject,email,display_name,role,roles,acr,amr,auth_time,issuer,oidc_session_id,csrf_hash,policy_version,created_at,last_seen_at,expires_at`,
      [tokenHash, idleSeconds],
    );
    return normalizeSessionRow(result.rows[0]);
  }

  async revokeSession(tokenHash) {
    await this.pool.query("update control_auth.sessions set revoked_at=now() where token_hash=$1 and revoked_at is null", [tokenHash]);
  }

  async registerLoginAttempt(keyHash, maxAttempts, windowSeconds, lockSeconds) {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const current = (await client.query(
        "select * from control_auth.login_throttle where key_hash=$1 for update",
        [keyHash],
      )).rows[0];
      const now = Date.now();
      const lockedUntil = current?.locked_until ? new Date(current.locked_until).getTime() : 0;
      if (lockedUntil > now) {
        await client.query("commit");
        return { allowed: false, retryAfterSeconds: Math.ceil((lockedUntil - now) / 1000) };
      }
      const windowStarted = current?.window_started_at ? new Date(current.window_started_at).getTime() : 0;
      const reset = !windowStarted || windowStarted <= now - windowSeconds * 1000;
      const attempts = reset ? 1 : Number(current.attempts || 0) + 1;
      const nextLockedUntil = attempts > maxAttempts ? new Date(now + lockSeconds * 1000) : null;
      await client.query(
        `insert into control_auth.login_throttle (key_hash,window_started_at,attempts,locked_until,updated_at)
         values ($1,$2,$3,$4,now())
         on conflict (key_hash) do update
         set window_started_at=excluded.window_started_at,attempts=excluded.attempts,
             locked_until=excluded.locked_until,updated_at=now()`,
        [keyHash, new Date(reset ? now : windowStarted), attempts, nextLockedUntil],
      );
      await client.query("commit");
      return { allowed: attempts <= maxAttempts, retryAfterSeconds: nextLockedUntil ? lockSeconds : 0 };
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally {
      client.release();
    }
  }

  async clearLoginThrottle(keyHash) {
    await this.pool.query("delete from control_auth.login_throttle where key_hash=$1", [keyHash]);
  }

  async createWebAuthnChallenge(item) {
    await this.pool.query("delete from control_auth.webauthn_challenges where expires_at <= now()");
    await this.pool.query(
      `insert into control_auth.webauthn_challenges
       (challenge_hash,challenge,flow,user_id,peer_hash,expires_at)
       values ($1,$2,$3,$4,$5,$6)
       on conflict (challenge_hash) do update
       set challenge=excluded.challenge,flow=excluded.flow,user_id=excluded.user_id,
           peer_hash=excluded.peer_hash,created_at=now(),expires_at=excluded.expires_at`,
      [item.challengeHash, item.challenge, item.flow, item.userId, item.peerHash, item.expiresAt],
    );
  }

  async consumeWebAuthnChallenge({ challengeHash, challenge, flow, userId, peerHash }) {
    const result = await this.pool.query(
      `delete from control_auth.webauthn_challenges
       where challenge_hash=$1 and challenge=$2 and flow=$3 and user_id=$4 and peer_hash=$5 and expires_at > now()
       returning challenge,flow,user_id,peer_hash,expires_at`,
      [challengeHash, challenge, flow, userId, peerHash],
    );
    const row = result.rows[0];
    return row ? {
      challenge: row.challenge,
      flow: row.flow,
      userId: row.user_id,
      peerHash: row.peer_hash,
      expiresAt: row.expires_at,
    } : null;
  }

  async listPasskeys(userId) {
    await this.pool.query("delete from control_auth.passkeys where expires_at <= now()");
    const result = await this.pool.query(
      `select credential_id,user_id,webauthn_user_id,public_key,counter,transports,device_type,backed_up,
              created_at,expires_at,last_used_at,updated_at
       from control_auth.passkeys where user_id=$1 and expires_at > now() order by created_at asc`,
      [userId],
    );
    return result.rows.map(normalizePasskeyRow);
  }

  async createPasskey(item) {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      await client.query("select pg_advisory_xact_lock(hashtextextended($1, 0))", [item.userId]);
      await client.query("delete from control_auth.passkeys where user_id=$1 and expires_at <= now()", [item.userId]);
      const result = await client.query(
        `insert into control_auth.passkeys
         (credential_id,user_id,webauthn_user_id,public_key,counter,transports,device_type,backed_up,expires_at)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9
         where not exists (select 1 from control_auth.passkeys where user_id=$2 and expires_at > now())
         on conflict (credential_id) do nothing`,
        [item.id, item.userId, item.webauthnUserId, item.publicKey, item.counter, item.transports || [], item.deviceType, item.backedUp, item.expiresAt],
      );
      await client.query("commit");
      return result.rowCount === 1;
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally {
      client.release();
    }
  }

  async updatePasskeyCounter({ credentialId, userId, counter, deviceType, backedUp }) {
    const result = await this.pool.query(
      `update control_auth.passkeys
       set counter=$1,device_type=coalesce($2,device_type),backed_up=coalesce($3,backed_up),last_used_at=now(),updated_at=now()
       where credential_id=$4 and user_id=$5 and expires_at > now() and counter <= $1
       returning credential_id`,
      [counter, deviceType || null, backedUp === undefined ? null : Boolean(backedUp), credentialId, userId],
    );
    return result.rowCount === 1;
  }

  async close() { await this.pool.end(); }
}

export class MemoryAppPasskeyStore {
  constructor() {
    this.sessions = new Map();
    this.loginThrottle = new Map();
    this.passkeys = new Map();
    this.webauthnChallenges = new Map();
  }
  async ready() {}
  async createSession(item) {
    this.sessions.set(item.tokenHash, {
      ...structuredClone(item),
      createdAt: new Date(),
      lastSeenAt: new Date(),
      revokedAt: null,
    });
  }
  async getSession(tokenHash, idleSeconds) {
    const item = this.sessions.get(tokenHash);
    const now = Date.now();
    if (!item || item.revokedAt || item.expiresAt.getTime() <= now || item.lastSeenAt.getTime() <= now - idleSeconds * 1000) return null;
    item.lastSeenAt = new Date();
    return structuredClone(item);
  }
  async revokeSession(tokenHash) {
    const item = this.sessions.get(tokenHash);
    if (item) item.revokedAt = new Date();
  }
  async registerLoginAttempt(keyHash, maxAttempts, windowSeconds, lockSeconds) {
    const now = Date.now();
    const current = this.loginThrottle.get(keyHash);
    if (current?.lockedUntil > now) {
      return { allowed: false, retryAfterSeconds: Math.ceil((current.lockedUntil - now) / 1000) };
    }
    const reset = !current || current.windowStarted <= now - windowSeconds * 1000;
    const attempts = reset ? 1 : current.attempts + 1;
    const lockedUntil = attempts > maxAttempts ? now + lockSeconds * 1000 : 0;
    this.loginThrottle.set(keyHash, { windowStarted: reset ? now : current.windowStarted, attempts, lockedUntil });
    return { allowed: attempts <= maxAttempts, retryAfterSeconds: lockedUntil ? lockSeconds : 0 };
  }
  async clearLoginThrottle(keyHash) { this.loginThrottle.delete(keyHash); }
  async createWebAuthnChallenge(item) {
    const now = Date.now();
    for (const [key, value] of this.webauthnChallenges) {
      if (value.expiresAt.getTime() <= now) this.webauthnChallenges.delete(key);
    }
    this.webauthnChallenges.set(item.challengeHash, {
      ...structuredClone(item),
      expiresAt: new Date(item.expiresAt),
    });
  }
  async consumeWebAuthnChallenge({ challengeHash, challenge, flow, userId, peerHash }) {
    const item = this.webauthnChallenges.get(challengeHash);
    this.webauthnChallenges.delete(challengeHash);
    if (!item || item.challenge !== challenge || item.flow !== flow || item.userId !== userId ||
        item.peerHash !== peerHash || item.expiresAt.getTime() <= Date.now()) return null;
    return structuredClone(item);
  }
  async listPasskeys(userId) {
    const now = Date.now();
    for (const [key, value] of this.passkeys) {
      if (value.expiresAt.getTime() <= now) this.passkeys.delete(key);
    }
    return [...this.passkeys.values()]
      .filter((item) => item.userId === userId && item.expiresAt.getTime() > now)
      .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime())
      .map((item) => structuredClone(item));
  }
  async createPasskey(item) {
    const now = Date.now();
    for (const [key, value] of this.passkeys) {
      if (value.expiresAt.getTime() <= now) this.passkeys.delete(key);
      else if (value.userId === item.userId) return false;
    }
    if (this.passkeys.has(item.id)) return false;
    this.passkeys.set(item.id, {
      ...structuredClone(item),
      publicKey: new Uint8Array(item.publicKey),
      createdAt: new Date(item.createdAt || Date.now()),
      expiresAt: new Date(item.expiresAt),
    });
    return true;
  }
  async updatePasskeyCounter({ credentialId, userId, counter, deviceType, backedUp }) {
    const item = this.passkeys.get(credentialId);
    if (!item || item.userId !== userId || item.expiresAt.getTime() <= Date.now() || item.counter > counter) return false;
    item.counter = counter;
    if (deviceType) item.deviceType = deviceType;
    if (backedUp !== undefined) item.backedUp = Boolean(backedUp);
    item.lastUsedAt = new Date();
    item.updatedAt = new Date();
    return true;
  }
  async close() {}
}

async function seedTestSessions(store, config, env) {
  const raw = String(env.CONTROL_CENTER_TEST_SESSION_FIXTURES || "").trim();
  if (!raw) return;
  if (config.nodeEnvironment !== "test" || config.store !== "memory" || !isLoopback(config.bindHost)) {
    throw new AuthConfigurationError("CONTROL_CENTER_TEST_SESSION_FIXTURES is restricted to loopback memory tests.");
  }
  let fixtures;
  try {
    fixtures = JSON.parse(raw);
  } catch {
    throw new AuthConfigurationError("CONTROL_CENTER_TEST_SESSION_FIXTURES must be valid JSON.");
  }
  if (!Array.isArray(fixtures) || fixtures.length > 32) {
    throw new AuthConfigurationError("CONTROL_CENTER_TEST_SESSION_FIXTURES must contain at most 32 sessions.");
  }
  for (const fixture of fixtures) {
    const token = requiredFixtureToken(fixture?.token, "token");
    const csrf = requiredFixtureToken(fixture?.csrf, "csrf");
    const role = String(fixture?.role || "");
    if (!["viewer", "admin", "owner"].includes(role)) {
      throw new AuthConfigurationError("Test session roles must be viewer, admin, or owner.");
    }
    const ageSeconds = Number(fixture?.ageSeconds || 0);
    if (!Number.isFinite(ageSeconds) || Math.abs(ageSeconds) > 86400) {
      throw new AuthConfigurationError("Test session ageSeconds is invalid.");
    }
    const authTime = new Date(Date.now() - ageSeconds * 1000);
    await store.createSession({
      tokenHash: sha256(token),
      csrfHash: sha256(csrf),
      policyVersion: config.sessionPolicyVersion,
      subject: config.adminSubject,
      email: config.adminEmail,
      displayName: config.adminDisplayName,
      role,
      roles: [role],
      acr: "app-passkey",
      amr: ["webauthn"],
      authTime,
      issuer: config.publicOrigin,
      sessionId: "",
      keyId: "",
      expiresAt: new Date(Date.now() + config.sessionMaxAgeSeconds * 1000),
    });
  }
}

function requiredFixtureToken(value, label) {
  const token = String(value || "");
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(token)) {
    throw new AuthConfigurationError(`Test session ${label} is invalid.`);
  }
  return token;
}

function normalizeSessionRow(row) {
  if (!row) return null;
  return {
    subject: row.subject,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    roles: row.roles || [],
    acr: row.acr,
    amr: row.amr || [],
    authTime: row.auth_time,
    issuer: row.issuer,
    sessionId: row.oidc_session_id,
    csrfHash: row.csrf_hash,
    policyVersion: row.policy_version,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
  };
}

function normalizePasskeyRow(row) {
  return {
    id: row.credential_id,
    userId: row.user_id,
    webauthnUserId: row.webauthn_user_id,
    publicKey: row.public_key,
    counter: Number(row.counter || 0),
    transports: Array.isArray(row.transports) ? row.transports : [],
    deviceType: row.device_type || "singleDevice",
    backedUp: row.backed_up === true,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastUsedAt: row.last_used_at,
    updatedAt: row.updated_at,
  };
}

function readDatabaseUrl(filename) {
  const target = String(filename || "").trim();
  if (!target || !existsSync(target)) {
    throw new AuthConfigurationError("CONTROL_CENTER_AUTH_DATABASE_URL_FILE is required and must exist.");
  }
  const value = readFileSync(target, "utf8").trim();
  if (!/^postgres(?:ql)?:\/\//i.test(value)) {
    throw new AuthConfigurationError("Control Center auth database URL must use PostgreSQL.");
  }
  return value;
}

function exactHttpsOrigin(value, name) {
  const text = requiredText(value, name);
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new AuthConfigurationError(`${name} must be an absolute HTTPS origin.`);
  }
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
    throw new AuthConfigurationError(`${name} must be an exact HTTPS origin without path, query, fragment, or credentials.`);
  }
  return url.origin;
}

function requiredText(value, name) {
  const text = String(value || "").trim();
  if (!text) throw new AuthConfigurationError(`${name} is required.`);
  return text;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value || fallback), 10);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new AuthConfigurationError(`Authentication timeout must be between ${minimum} and ${maximum} seconds.`);
  }
  return parsed;
}

function isLoopback(host) {
  return ["127.0.0.1", "::1", "localhost"].includes(String(host).toLowerCase());
}

function parseCidrs(value) {
  const cidrs = String(value || "").split(",").map((item) => item.trim()).filter(Boolean).map(parseCidr);
  if (cidrs.length === 0 || cidrs.length > 32) {
    throw new AuthConfigurationError("Control Center CIDR lists cannot be empty or exceed 32 entries.");
  }
  return cidrs;
}

function parseCidr(value) {
  const [rawAddress, rawPrefix, ...extra] = String(value).split("/");
  const address = normalizeIp(rawAddress);
  const family = isIP(address);
  if (extra.length || !family) throw new AuthConfigurationError(`Invalid CIDR: ${value}`);
  const maximum = family === 4 ? 32 : 128;
  const prefix = rawPrefix === undefined ? maximum : Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maximum) {
    throw new AuthConfigurationError(`Invalid CIDR: ${value}`);
  }
  if (family === 6 && !(address === "::1" && prefix === 128)) {
    throw new AuthConfigurationError("Only the ::1/128 IPv6 management CIDR is supported.");
  }
  return { address, family, prefix };
}

function resolveClientAddress(config, req) {
  let current = normalizeIp(req?.socket?.remoteAddress || "");
  if (!current) return "";
  if (!cidrListContains(config.trustedProxyCidrs, current)) return current;
  const forwarded = String(req?.headers?.["x-forwarded-for"] || "")
    .split(",")
    .map((value) => normalizeIp(value.trim()))
    .filter(Boolean);
  if (forwarded.length === 0 || forwarded.length > 8) return "";
  for (let index = forwarded.length - 1; index >= 0; index -= 1) {
    if (!cidrListContains(config.trustedProxyCidrs, current)) break;
    current = forwarded[index];
  }
  return current;
}

function cidrListContains(cidrs, address) {
  return cidrs.some((cidr) => cidrContains(cidr, address));
}

function cidrContains(cidr, rawAddress) {
  const address = normalizeIp(rawAddress);
  if (cidr.family !== isIP(address)) return false;
  if (cidr.family === 6) return address === cidr.address;
  const mask = cidr.prefix === 0 ? 0 : (0xffffffff << (32 - cidr.prefix)) >>> 0;
  return (ipv4Number(address) & mask) === (ipv4Number(cidr.address) & mask);
}

function ipv4Number(value) {
  return value.split(".").reduce((total, part) => ((total << 8) | Number(part)) >>> 0, 0);
}

function normalizeIp(value) {
  let address = String(value || "").trim().toLowerCase();
  if (address.startsWith("[")) address = address.replace(/^\[|\]$/g, "");
  if (address.startsWith("::ffff:")) address = address.slice(7);
  return isIP(address) ? address : "";
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
