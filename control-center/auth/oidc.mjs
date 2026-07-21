import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRemoteJWKSet, jwtVerify } from "jose";
import pg from "pg";
import { resolveAuthorizationCapability } from "./route-capabilities.mjs";

const { Pool } = pg;
const SESSION_COOKIE = "__Host-platform_cc_session";
const CSRF_COOKIE = "__Host-platform_cc_csrf";
const DEFAULT_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;
const DEFAULT_SESSION_IDLE_SECONDS = 30 * 60;
const DEFAULT_TRANSACTION_TTL_SECONDS = 5 * 60;

export async function createControlCenterAuth({ env = process.env } = {}) {
  const config = readAuthConfig(env);
  if (config.mode === "test-disabled") {
    return new TestDisabledAuth(config);
  }

  const store = config.store === "memory"
    ? new MemoryAuthStore()
    : new PostgresAuthStore(config.databaseUrl);
  await store.ready();
  return new OidcPasskeyAuth(config, store);
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
  if (mode !== "oidc-passkey") {
    throw new AuthConfigurationError("CONTROL_CENTER_AUTH_MODE must be oidc-passkey.");
  }
  if (env.CONTROL_CENTER_ADMIN_PASSWORD_SHA256 || env.CONTROL_CENTER_ADMIN_PASSWORD_FILE) {
    throw new AuthConfigurationError("Local password authentication is not supported.");
  }
  if (env.CONTROL_CENTER_OIDC_CLIENT_SECRET || env.CONTROL_CENTER_OIDC_CLIENT_SECRET_FILE) {
    throw new AuthConfigurationError("The Control Center OIDC client must use public-client PKCE without a client secret.");
  }

  if (String(env.NODE_TLS_REJECT_UNAUTHORIZED || "").trim() === "0") {
    throw new AuthConfigurationError("OIDC TLS certificate verification must remain enabled.");
  }

  const issuer = requiredIssuerUrl(env.CONTROL_CENTER_OIDC_ISSUER, "CONTROL_CENTER_OIDC_ISSUER");
  const authorizationEndpoint = requiredIssuerEndpoint(
    env.CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT,
    "CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT",
    issuer,
  );
  const allowInsecureTestEndpoint = nodeEnvironment === "test" && environment === "test" && isLoopback(bindHost);
  const tokenEndpoint = requiredIssuerEndpoint(
    env.CONTROL_CENTER_OIDC_TOKEN_ENDPOINT,
    "CONTROL_CENTER_OIDC_TOKEN_ENDPOINT",
    issuer,
    { allowInsecureTestEndpoint },
  );
  const jwksUri = requiredIssuerEndpoint(
    env.CONTROL_CENTER_OIDC_JWKS_URI,
    "CONTROL_CENTER_OIDC_JWKS_URI",
    issuer,
    { allowInsecureTestEndpoint },
  );
  const redirectUri = requiredHttpsUrl(env.CONTROL_CENTER_OIDC_REDIRECT_URI, "CONTROL_CENTER_OIDC_REDIRECT_URI");
  const clientId = requiredText(env.CONTROL_CENTER_OIDC_CLIENT_ID, "CONTROL_CENTER_OIDC_CLIENT_ID");
  const requiredAcr = requiredText(env.CONTROL_CENTER_OIDC_REQUIRED_ACR, "CONTROL_CENTER_OIDC_REQUIRED_ACR");
  const requiredAmr = csv(env.CONTROL_CENTER_OIDC_REQUIRED_AMR || "");
  const store = String(env.CONTROL_CENTER_AUTH_STORE || "postgres").trim().toLowerCase();
  if (!['postgres', 'memory'].includes(store)) {
    throw new AuthConfigurationError("CONTROL_CENTER_AUTH_STORE must be postgres.");
  }
  if (store === "memory" && nodeEnvironment !== "test") {
    throw new AuthConfigurationError("The in-memory auth store is restricted to NODE_ENV=test.");
  }

  const databaseUrl = store === "postgres" ? readDatabaseUrl(env.CONTROL_CENTER_AUTH_DATABASE_URL_FILE) : "";
  return {
    mode,
    environment,
    bindHost,
    issuer: trimTrailingSlash(issuer),
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    redirectUri,
    clientId,
    requiredAcr,
    requiredAmr,
    ownerRole: String(env.CONTROL_CENTER_OIDC_OWNER_ROLE || "owner").trim(),
    adminRole: String(env.CONTROL_CENTER_OIDC_ADMIN_ROLE || "admin").trim(),
    viewerRole: String(env.CONTROL_CENTER_OIDC_VIEWER_ROLE || "viewer").trim(),
    sessionMaxAgeSeconds: boundedInteger(env.CONTROL_CENTER_SESSION_MAX_AGE_SECONDS, DEFAULT_SESSION_MAX_AGE_SECONDS, 300, 86400),
    sessionIdleSeconds: boundedInteger(env.CONTROL_CENTER_SESSION_IDLE_SECONDS, DEFAULT_SESSION_IDLE_SECONDS, 60, 43200),
    transactionTtlSeconds: boundedInteger(env.CONTROL_CENTER_OIDC_TRANSACTION_TTL_SECONDS, DEFAULT_TRANSACTION_TTL_SECONDS, 60, 900),
    freshAuthSeconds: boundedInteger(env.CONTROL_CENTER_FRESH_AUTH_SECONDS, 300, 60, 900),
    loginMaxAttempts: boundedInteger(env.CONTROL_CENTER_LOGIN_MAX_ATTEMPTS, 20, 2, 100),
    loginWindowSeconds: boundedInteger(env.CONTROL_CENTER_LOGIN_WINDOW_SECONDS, 60, 10, 600),
    loginLockSeconds: boundedInteger(env.CONTROL_CENTER_LOGIN_LOCK_SECONDS, 60, 10, 3600),
    sessionPolicyVersion: requiredText(env.CONTROL_CENTER_SESSION_POLICY_VERSION || "1", "CONTROL_CENTER_SESSION_POLICY_VERSION"),
    publicOrigin: originOf(requiredHttpsUrl(env.CONTROL_CENTER_PUBLIC_ORIGIN || redirectUri, "CONTROL_CENTER_PUBLIC_ORIGIN")),
    store,
    databaseUrl,
  };
}

class OidcPasskeyAuth {
  constructor(config, store) {
    this.config = config;
    this.store = store;
    this.enabled = true;
    this.mode = config.mode;
    this.jwks = createRemoteJWKSet(new URL(config.jwksUri), {
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
      timeoutDuration: 5_000,
    });
  }

  async beginLogin(req) {
    const throttleKeyHash = sha256(immediatePeer(req));
    const permit = await this.store.registerLoginAttempt(
      throttleKeyHash,
      this.config.loginMaxAttempts,
      this.config.loginWindowSeconds,
      this.config.loginLockSeconds,
    );
    if (!permit.allowed) {
      throw new AuthRequestError("Too many authentication attempts. Retry later.", 429);
    }
    const state = opaqueToken();
    const nonce = opaqueToken();
    const codeVerifier = opaqueToken(64);
    const codeChallenge = base64urlSha256(codeVerifier);
    await this.store.createTransaction({
      stateHash: sha256(state),
      nonceHash: sha256(nonce),
      codeVerifier,
      throttleKeyHash,
      expiresAt: new Date(Date.now() + this.config.transactionTtlSeconds * 1000),
    });

    const target = new URL(this.config.authorizationEndpoint);
    target.searchParams.set("client_id", this.config.clientId);
    target.searchParams.set("redirect_uri", this.config.redirectUri);
    target.searchParams.set("response_type", "code");
    target.searchParams.set("scope", "openid profile email");
    target.searchParams.set("state", state);
    target.searchParams.set("nonce", nonce);
    target.searchParams.set("code_challenge", codeChallenge);
    target.searchParams.set("code_challenge_method", "S256");
    target.searchParams.set("acr_values", this.config.requiredAcr);
    target.searchParams.set("prompt", "login");
    return target.toString();
  }

  async completeLogin(url) {
    if (url.searchParams.get("error")) {
      throw new AuthRequestError("Identity provider authentication was rejected.", 401);
    }
    const code = String(url.searchParams.get("code") || "");
    const state = String(url.searchParams.get("state") || "");
    if (!code || !state) throw new AuthRequestError("OIDC callback is incomplete.", 400);

    const transaction = await this.store.consumeTransaction(sha256(state));
    if (!transaction || transaction.expiresAt.getTime() <= Date.now()) {
      throw new AuthRequestError("OIDC transaction is invalid or expired.", 401);
    }

    const response = await fetch(this.config.tokenEndpoint, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: this.config.clientId,
        code,
        redirect_uri: this.config.redirectUri,
        code_verifier: transaction.codeVerifier,
      }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) throw new AuthRequestError("OIDC token exchange failed.", 401);
    const tokens = await response.json();
    const idToken = typeof tokens.id_token === "string" ? tokens.id_token : "";
    if (!idToken) throw new AuthRequestError("OIDC response did not contain an ID token.", 401);

    const { payload, protectedHeader } = await jwtVerify(idToken, this.jwks, {
      issuer: this.config.issuer,
      audience: this.config.clientId,
      algorithms: ["RS256", "ES256"],
      clockTolerance: 5,
      maxTokenAge: "10 minutes",
    });
    if (!safeEqualText(String(payload.nonce || ""), transaction.nonceHash, true)) {
      throw new AuthRequestError("OIDC nonce validation failed.", 401);
    }
    if (String(payload.acr || "") !== this.config.requiredAcr) {
      throw new AuthRequestError("A verified passkey authentication level is required.", 403);
    }
    const amr = Array.isArray(payload.amr) ? payload.amr.map(String) : [];
    if (this.config.requiredAmr.some((method) => !amr.includes(method))) {
      throw new AuthRequestError("The identity provider did not attest the required passkey method.", 403);
    }
    if (!Number.isFinite(Number(payload.auth_time))) {
      throw new AuthRequestError("The identity provider did not provide authentication time.", 403);
    }
    const authTimeMs = Number(payload.auth_time) * 1000;
    if (authTimeMs > Date.now() + 5_000 || authTimeMs < Date.now() - 10 * 60_000) {
      throw new AuthRequestError("A recent passkey authentication is required.", 403);
    }

    const roles = tokenRoles(payload, this.config.clientId);
    const role = highestRole(roles, this.config);
    if (!role) throw new AuthRequestError("The authenticated identity has no Control Center role.", 403);

    const now = Date.now();
    const tokenExpiryMs = Number(payload.exp) * 1000;
    const expiresAt = new Date(Math.min(now + this.config.sessionMaxAgeSeconds * 1000, tokenExpiryMs));
    const rawSessionToken = opaqueToken(64);
    const rawCsrfToken = opaqueToken(32);
    await this.store.createSession({
      tokenHash: sha256(rawSessionToken),
      csrfHash: sha256(rawCsrfToken),
      policyVersion: this.config.sessionPolicyVersion,
      subject: requiredClaim(payload.sub, "sub"),
      email: String(payload.email || ""),
      displayName: String(payload.name || payload.preferred_username || payload.email || payload.sub),
      role,
      roles: [...roles],
      acr: String(payload.acr),
      amr,
      authTime: new Date(authTimeMs),
      issuer: String(payload.iss),
      sessionId: String(payload.sid || ""),
      keyId: String(protectedHeader.kid || ""),
      expiresAt,
    });
    if (transaction.throttleKeyHash) await this.store.clearLoginThrottle(transaction.throttleKeyHash);
    return {
      cookies: [sessionCookie(rawSessionToken, expiresAt), csrfCookie(rawCsrfToken, expiresAt)],
      role,
      subject: String(payload.sub),
    };
  }

  async authenticate(req) {
    const cookies = parseCookie(req.headers.cookie || "");
    const token = cookies[SESSION_COOKIE] || "";
    if (!token) return denied(401, "Admin authentication required.");
    const session = await this.store.getSession(sha256(token), this.config.sessionIdleSeconds);
    if (!session || session.policyVersion !== this.config.sessionPolicyVersion) {
      return denied(401, "Admin authentication required.");
    }
    const csrfToken = cookies[CSRF_COOKIE] || "";
    const csrfCookieValid = csrfToken && safeEqualText(csrfToken, session.csrfHash, true);
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
    const method = String(req.method || "GET").toUpperCase();
    const operation = req.controlCenterOperation || resolveAuthorizationCapability(method, url.pathname);
    if (operation.capability === "deny") {
      return denied(403, "Endpoint capability is not declared.", { error: "endpoint_capability_denied" });
    }
    if (operation.capability === "owner:fresh") {
      if (session.role !== "owner") return denied(403, "Platform owner authorization required.");
      const now = Date.now();
      const authTime = new Date(session.identity?.authTime).getTime();
      if (!Number.isFinite(authTime) || authTime > now || now - authTime > this.config.freshAuthSeconds * 1000) {
        return denied(428, "A recent passkey authentication is required.", { error: "admin_reauthentication_required", reauthUrl: "/auth/login" });
      }
    }
    if (operation.capability === "admin" && !["owner", "admin"].includes(session.role)) {
      return denied(403, "Administrative authorization required.");
    }
    if (operation.capability === "viewer" && !["owner", "admin", "viewer"].includes(session.role)) {
      return denied(403, "Control Center authorization required.");
    }
    return session;
  }

  async validateMutation(req, url, session) {
    const method = String(req.method || "GET").toUpperCase();
    if (["GET", "HEAD", "OPTIONS"].includes(method)) return session;
    if (String(req.headers.origin || "") !== this.config.publicOrigin) {
      return denied(403, "Exact request origin is required.", { error: "csrf_origin_rejected" });
    }
    if (String(req.headers["sec-fetch-site"] || "").toLowerCase() !== "same-origin") {
      return denied(403, "Same-origin Fetch Metadata is required.", { error: "csrf_fetch_site_rejected" });
    }
    const payload = await readRequestPayload(req);
    const provided = String(req.headers["x-csrf-token"] || payload._csrf || "");
    const expected = String(session.identity?.csrfToken || "");
    if (!provided || !expected || !safeEqualText(provided, expected)) {
      return denied(403, "CSRF validation failed.", { error: "csrf_token_rejected" });
    }
    return session;
  }

  async logout(req) {
    const token = parseCookie(req.headers.cookie || "")[SESSION_COOKIE] || "";
    if (token) await this.store.revokeSession(sha256(token));
    return clearSessionCookies();
  }

  async close() {
    await this.store.close();
  }
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

export class PostgresAuthStore {
  constructor(connectionString) {
    this.pool = new Pool({ connectionString, max: 5, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000 });
  }
  async ready() {
    const result = await this.pool.query(
      `select to_regclass('control_auth.oidc_transactions') as transactions,
              to_regclass('control_auth.sessions') as sessions,
              to_regclass('control_auth.login_throttle') as throttle,
              exists(select 1 from information_schema.columns where table_schema='control_auth' and table_name='sessions' and column_name='csrf_hash') as csrf_ready`,
    );
    if (!result.rows[0]?.transactions || !result.rows[0]?.sessions || !result.rows[0]?.throttle || !result.rows[0]?.csrf_ready) {
      throw new AuthConfigurationError("Control Center auth migrations are not applied.");
    }
  }
  async createTransaction(item) {
    await this.pool.query("delete from control_auth.oidc_transactions where expires_at <= now()");
    await this.pool.query(
      "insert into control_auth.oidc_transactions (state_hash, nonce_hash, code_verifier, throttle_key_hash, expires_at) values ($1,$2,$3,$4,$5)",
      [item.stateHash, item.nonceHash, item.codeVerifier, item.throttleKeyHash || null, item.expiresAt],
    );
  }
  async consumeTransaction(stateHash) {
    const result = await this.pool.query(
      "delete from control_auth.oidc_transactions where state_hash=$1 returning nonce_hash, code_verifier, throttle_key_hash, expires_at",
      [stateHash],
    );
    const row = result.rows[0];
    return row ? { nonceHash: row.nonce_hash, codeVerifier: row.code_verifier, throttleKeyHash: row.throttle_key_hash, expiresAt: row.expires_at } : null;
  }
  async createSession(item) {
    await this.pool.query(
      `insert into control_auth.sessions
       (token_hash, csrf_hash, policy_version, subject, email, display_name, role, roles, acr, amr, auth_time, issuer, oidc_session_id, signing_key_id, expires_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [item.tokenHash, item.csrfHash, item.policyVersion, item.subject, item.email, item.displayName, item.role, item.roles, item.acr, item.amr, item.authTime, item.issuer, item.sessionId, item.keyId, item.expiresAt],
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
      const current = (await client.query("select * from control_auth.login_throttle where key_hash=$1 for update", [keyHash])).rows[0];
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
         on conflict (key_hash) do update set window_started_at=excluded.window_started_at,attempts=excluded.attempts,locked_until=excluded.locked_until,updated_at=now()`,
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
  async close() { await this.pool.end(); }
}

export class MemoryAuthStore {
  constructor() {
    this.transactions = new Map();
    this.sessions = new Map();
    this.loginThrottle = new Map();
  }
  async ready() {}
  async createTransaction(item) {
    this.transactions.set(item.stateHash, structuredClone(item));
  }
  async consumeTransaction(stateHash) {
    const item = this.transactions.get(stateHash) || null;
    this.transactions.delete(stateHash);
    return item;
  }
  async createSession(item) {
    this.sessions.set(item.tokenHash, { ...structuredClone(item), createdAt: new Date(), lastSeenAt: new Date(), revokedAt: null });
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
  async close() {}
}

export class AuthConfigurationError extends Error {}
export class AuthRequestError extends Error {
  constructor(message, status = 401) {
    super(message);
    this.status = status;
  }
}

function readDatabaseUrl(filename) {
  const target = String(filename || "").trim();
  if (!target || !existsSync(target)) throw new AuthConfigurationError("CONTROL_CENTER_AUTH_DATABASE_URL_FILE is required and must exist.");
  const value = readFileSync(target, "utf8").trim();
  if (!/^postgres(?:ql)?:\/\//i.test(value)) throw new AuthConfigurationError("Control Center auth database URL must use PostgreSQL.");
  return value;
}

function tokenRoles(payload, clientId) {
  const roles = new Set();
  for (const role of payload.realm_access?.roles || []) roles.add(String(role));
  for (const role of payload.resource_access?.[clientId]?.roles || []) roles.add(String(role));
  return roles;
}

function highestRole(roles, config) {
  if (roles.has(config.ownerRole)) return "owner";
  if (roles.has(config.adminRole)) return "admin";
  if (roles.has(config.viewerRole)) return "viewer";
  return "";
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

function parseCookie(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try { out[decodeURIComponent(name)] = decodeURIComponent(value); } catch { /* Ignore malformed cookies. */ }
  }
  return out;
}

function opaqueToken(bytes = 32) { return randomBytes(bytes).toString("base64url"); }
function sha256(value) { return createHash("sha256").update(String(value)).digest("hex"); }
function base64urlSha256(value) { return createHash("sha256").update(String(value)).digest("base64url"); }
function csv(value) { return String(value || "").split(",").map((item) => item.trim()).filter(Boolean); }
function trimTrailingSlash(value) { return String(value).replace(/\/+$/, ""); }
function denied(status, message, extra = {}) { return { ok: false, status, message, role: "", identity: null, ...extra }; }
function isLoopback(host) { return ["127.0.0.1", "::1", "localhost"].includes(String(host).toLowerCase()); }
function originOf(value) { return new URL(value).origin; }

function immediatePeer(req) {
  return String(req?.socket?.remoteAddress || "unknown-peer").trim().toLowerCase();
}

async function readRequestPayload(req) {
  if (req.controlCenterPayload && typeof req.controlCenterPayload === "object") return req.controlCenterPayload;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) throw new AuthRequestError("Request body is too large.", 413);
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  const type = String(req.headers["content-type"] || "").toLowerCase();
  if (type.includes("application/json")) {
    try {
      const parsed = JSON.parse(raw || "{}");
      req.controlCenterPayload = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      throw new AuthRequestError("Invalid JSON payload.", 400);
    }
  } else {
    req.controlCenterPayload = Object.fromEntries(new URLSearchParams(raw));
  }
  return req.controlCenterPayload;
}

function requiredText(value, name) {
  const text = String(value || "").trim();
  if (!text) throw new AuthConfigurationError(`${name} is required.`);
  return text;
}

function requiredUrl(value, name) {
  const text = requiredText(value, name);
  let url;
  try { url = new URL(text); } catch { throw new AuthConfigurationError(`${name} must be an absolute URL.`); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new AuthConfigurationError(`${name} must use HTTP or HTTPS.`);
  return url.toString();
}

function requiredHttpsUrl(value, name) {
  const text = requiredUrl(value, name);
  if (new URL(text).protocol !== "https:") throw new AuthConfigurationError(`${name} must use HTTPS.`);
  return text;
}

function requiredIssuerUrl(value, name) {
  const text = requiredHttpsUrl(value, name);
  const url = new URL(text);
  if (url.username || url.password || url.search || url.hash) {
    throw new AuthConfigurationError(`${name} must not contain userinfo, query parameters, or a fragment.`);
  }
  return trimTrailingSlash(url.toString());
}

function requiredIssuerEndpoint(value, name, issuer, { allowInsecureTestEndpoint = false } = {}) {
  const text = requiredUrl(value, name);
  const endpoint = new URL(text);
  const issuerUrl = new URL(issuer);
  if (endpoint.username || endpoint.password || endpoint.hash) {
    throw new AuthConfigurationError(`${name} must not contain userinfo or a fragment.`);
  }
  if (allowInsecureTestEndpoint && endpoint.protocol === "http:" && isLoopback(endpoint.hostname)) {
    return endpoint.toString();
  }
  const issuerPath = `${trimTrailingSlash(issuerUrl.pathname)}/`;
  if (endpoint.protocol !== "https:" || endpoint.origin !== issuerUrl.origin || !endpoint.pathname.startsWith(issuerPath)) {
    throw new AuthConfigurationError(`${name} must use HTTPS under the exact configured OIDC issuer.`);
  }
  return endpoint.toString();
}

function requiredClaim(value, name) {
  const text = String(value || "").trim();
  if (!text) throw new AuthRequestError(`OIDC ${name} claim is required.`, 401);
  return text;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value || fallback), 10);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new AuthConfigurationError(`Authentication timeout must be between ${minimum} and ${maximum} seconds.`);
  }
  return parsed;
}

function safeEqualText(left, rightHash, compareHash = false) {
  const leftValue = compareHash ? sha256(left) : String(left);
  const rightValue = String(rightHash);
  const leftBuffer = Buffer.from(leftValue);
  const rightBuffer = Buffer.from(rightValue);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
