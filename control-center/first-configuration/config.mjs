import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { isIP } from "node:net";

const DEFAULT_ALLOWED_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128";
const DEFAULT_TRUSTED_PROXY_CIDRS = "172.16.0.0/12,127.0.0.0/8,::1/128";

export class FirstConfigurationError extends Error {
  constructor(message, status = 400, code = "first_configuration_rejected") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export class FirstConfigurationConfigError extends Error {}

export function readFirstConfigurationConfig(env = process.env) {
  const mode = String(env.CONTROL_CENTER_FIRST_CONFIGURATION_MODE || "disabled").trim().toLowerCase();
  if (mode === "disabled") return { mode, enabled: false };
  if (mode !== "required") {
    throw new FirstConfigurationConfigError("CONTROL_CENTER_FIRST_CONFIGURATION_MODE must be required or disabled.");
  }

  const environment = String(env.CONTROL_CENTER_ENV || "local").trim().toLowerCase();
  const nodeEnvironment = String(env.NODE_ENV || "production").trim().toLowerCase();
  if (!["local", "local_private", "local-private"].includes(environment)) {
    throw new FirstConfigurationConfigError("First configuration is restricted to the LOCAL_PRIVATE environment.");
  }

  const publicOrigin = exactHttpsOrigin(env.CONTROL_CENTER_PUBLIC_ORIGIN, "CONTROL_CENTER_PUBLIC_ORIGIN");
  const issuer = exactIssuer(env.CONTROL_CENTER_OIDC_ISSUER, "CONTROL_CENTER_OIDC_ISSUER");
  const realm = requiredIdentifier(env.CONTROL_CENTER_FIRST_CONFIGURATION_REALM || issuer.pathname.split("/").filter(Boolean).at(-1), "CONTROL_CENTER_FIRST_CONFIGURATION_REALM");
  const tokenEndpoint = exactIssuerEndpoint(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_ENDPOINT || `${issuer.href.replace(/\/$/, "")}/protocol/openid-connect/token`,
    issuer,
    "CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_ENDPOINT",
  );
  const adminBaseUrl = exactAdminBase(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_BASE_URL || `${issuer.origin}/admin/realms/${encodeURIComponent(realm)}`,
    issuer.origin,
    realm,
  );
  const accountUrl = exactAccountUrl(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_ACCOUNT_URL || `${issuer.origin}/realms/${encodeURIComponent(realm)}/account/`,
    issuer.origin,
    realm,
  );

  const bootstrapTokenFile = requiredExistingFile(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE,
    "CONTROL_CENTER_FIRST_CONFIGURATION_BOOTSTRAP_TOKEN_FILE",
  );
  const bootstrapToken = readSecret(bootstrapTokenFile, "first-configuration bootstrap token", 43);
  const databaseUrl = readDatabaseUrl(requiredExistingFile(
    env.CONTROL_CENTER_AUTH_DATABASE_URL_FILE,
    "CONTROL_CENTER_AUTH_DATABASE_URL_FILE",
  ));
  const store = String(env.CONTROL_CENTER_FIRST_CONFIGURATION_STORE || "postgres").trim().toLowerCase();
  if (!['postgres', 'memory'].includes(store) || (store === "memory" && nodeEnvironment !== "test")) {
    throw new FirstConfigurationConfigError("CONTROL_CENTER_FIRST_CONFIGURATION_STORE must be postgres; memory is test-only.");
  }
  const keycloakClientSecretFile = requiredExistingFile(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE,
    "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_SECRET_FILE",
  );
  readSecret(keycloakClientSecretFile, "first-configuration Keycloak client secret", 24);

  const adminUsername = requiredUsername(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME,
    "CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_USERNAME",
  );
  const adminEmail = requiredEmail(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL,
    "CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_EMAIL",
  );
  const ownerRole = requiredIdentifier(env.CONTROL_CENTER_OIDC_OWNER_ROLE || "owner", "CONTROL_CENTER_OIDC_OWNER_ROLE");
  if (ownerRole !== "owner") {
    throw new FirstConfigurationConfigError("CONTROL_CENTER_OIDC_OWNER_ROLE must be exactly owner for First Configuration.");
  }
  const passkeyFlow = requiredIdentifier(
    env.CONTROL_CENTER_FIRST_CONFIGURATION_PASSKEY_FLOW || "platform-passkey-browser",
    "CONTROL_CENTER_FIRST_CONFIGURATION_PASSKEY_FLOW",
  );
  if (passkeyFlow !== "platform-passkey-browser") {
    throw new FirstConfigurationConfigError(
      "CONTROL_CENTER_FIRST_CONFIGURATION_PASSKEY_FLOW must be exactly platform-passkey-browser.",
    );
  }

  return {
    mode,
    enabled: true,
    environment,
    publicOrigin: publicOrigin.origin,
    publicHost: publicOrigin.host.toLowerCase(),
    issuer: issuer.href.replace(/\/$/, ""),
    identityOrigin: issuer.origin,
    rpId: issuer.hostname.toLowerCase(),
    realm,
    tokenEndpoint: tokenEndpoint.href,
    adminBaseUrl: adminBaseUrl.href.replace(/\/$/, ""),
    accountUrl: accountUrl.href,
    clientId: requiredIdentifier(
      env.CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID || "platform-first-configuration",
      "CONTROL_CENTER_FIRST_CONFIGURATION_KEYCLOAK_CLIENT_ID",
    ),
    keycloakClientSecretFile,
    bootstrapToken,
    bootstrapTokenHash: sha256(bootstrapToken),
    bootstrapTokenLifetimeSeconds: boundedInteger(
      env.CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_LIFETIME_SECONDS,
      7 * 24 * 60 * 60,
      15 * 60,
      30 * 24 * 60 * 60,
    ),
    sessionMaxAgeSeconds: boundedInteger(
      env.CONTROL_CENTER_FIRST_CONFIGURATION_SESSION_MAX_AGE_SECONDS,
      2 * 60 * 60,
      10 * 60,
      8 * 60 * 60,
    ),
    sessionIdleSeconds: boundedInteger(
      env.CONTROL_CENTER_FIRST_CONFIGURATION_SESSION_IDLE_SECONDS,
      30 * 60,
      5 * 60,
      2 * 60 * 60,
    ),
    allowedCidrs: parseCidrs(env.CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS || DEFAULT_ALLOWED_CIDRS),
    trustedProxyCidrs: parseCidrs(env.CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS || DEFAULT_TRUSTED_PROXY_CIDRS),
    databaseUrl,
    store,
    adminUsername,
    adminEmail,
    ownerRole,
    controlCenterClientId: requiredIdentifier(env.CONTROL_CENTER_OIDC_CLIENT_ID || "platform-control-center", "CONTROL_CENTER_OIDC_CLIENT_ID"),
    controlCenterRedirectUri: exactHttpsUrl(env.CONTROL_CENTER_OIDC_REDIRECT_URI, "CONTROL_CENTER_OIDC_REDIRECT_URI").href,
    requiredAcr: requiredIdentifier(
      env.CONTROL_CENTER_OIDC_REQUIRED_ACR || "urn:platform:loa:passkey",
      "CONTROL_CENTER_OIDC_REQUIRED_ACR",
    ),
    backchannelLogoutUrl: `${publicOrigin.origin}/auth/backchannel-logout`,
    passkeyFlow,
    minimumPasskeys: boundedInteger(env.CONTROL_CENTER_MIN_PASSKEYS, 2, 2, 2),
  };
}

export function assertFirstConfigurationRequest(config, req, { mutation = false } = {}) {
  const host = String(req?.headers?.host || "").trim().toLowerCase();
  if (!host || !safeEqual(host, config.publicHost)) {
    throw new FirstConfigurationError("The exact Control Center host is required.", 421, "first_configuration_host_rejected");
  }
  const clientAddress = resolveClientAddress(config, req);
  if (!clientAddress || !cidrListContains(config.allowedCidrs, clientAddress)) {
    throw new FirstConfigurationError("First configuration is available only from the management LAN.", 403, "first_configuration_network_rejected");
  }
  if (mutation) {
    if (!safeEqual(String(req.headers.origin || ""), config.publicOrigin)) {
      throw new FirstConfigurationError("Exact request origin is required.", 403, "first_configuration_origin_rejected");
    }
    if (String(req.headers["sec-fetch-site"] || "").trim().toLowerCase() !== "same-origin") {
      throw new FirstConfigurationError("Same-origin Fetch Metadata is required.", 403, "first_configuration_fetch_site_rejected");
    }
  }
  return { clientAddress, peerHash: sha256(`first-configuration-peer\0${clientAddress}`) };
}

export function resolveClientAddress(config, req) {
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

export function cidrListContains(cidrs, address) {
  return cidrs.some((cidr) => cidrContains(cidr, address));
}

export function readSecret(filename, label, minimumLength = 1) {
  const value = readFileSync(filename, "utf8").trim();
  if (value.length < minimumLength || value.length > 4096 || /[\r\n\0]/.test(value)) {
    throw new FirstConfigurationConfigError(`The ${label} file is invalid.`);
  }
  return value;
}

export function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function parseCidrs(value) {
  const cidrs = String(value || "").split(",").map((item) => item.trim()).filter(Boolean).map(parseCidr);
  if (cidrs.length === 0 || cidrs.length > 32) throw new FirstConfigurationConfigError("First-configuration CIDR lists cannot be empty.");
  return cidrs;
}

function parseCidr(value) {
  const [rawAddress, rawPrefix, ...extra] = String(value).split("/");
  if (extra.length) throw new FirstConfigurationConfigError(`Invalid CIDR: ${value}`);
  const address = normalizeIp(rawAddress);
  const family = isIP(address);
  if (!family) throw new FirstConfigurationConfigError(`Invalid CIDR: ${value}`);
  const max = family === 4 ? 32 : 128;
  const prefix = rawPrefix === undefined ? max : Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) throw new FirstConfigurationConfigError(`Invalid CIDR: ${value}`);
  if (family === 6 && !(address === "::1" && prefix === 128)) {
    throw new FirstConfigurationConfigError("Only the ::1/128 IPv6 management CIDR is supported.");
  }
  return { address, family, prefix };
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

function exactHttpsOrigin(value, name) {
  const target = exactHttpsUrl(value, name);
  if (target.pathname !== "/" || target.search || target.hash || target.username || target.password) {
    throw new FirstConfigurationConfigError(`${name} must be an HTTPS origin without path, query or credentials.`);
  }
  return target;
}

function exactHttpsUrl(value, name) {
  let target;
  try { target = new URL(requiredText(value, name)); } catch { throw new FirstConfigurationConfigError(`${name} must be a valid HTTPS URL.`); }
  if (target.protocol !== "https:" || isIP(target.hostname) || !target.hostname.includes(".")) {
    throw new FirstConfigurationConfigError(`${name} must use HTTPS with a DNS hostname.`);
  }
  return target;
}

function exactIssuer(value, name) {
  const target = exactHttpsUrl(value, name);
  if (target.search || target.hash || target.username || target.password || !/^\/realms\/[A-Za-z0-9._-]+\/?$/.test(target.pathname)) {
    throw new FirstConfigurationConfigError(`${name} must identify one exact HTTPS realm issuer.`);
  }
  return target;
}

function exactIssuerEndpoint(value, issuer, name) {
  const target = exactHttpsUrl(value, name);
  const issuerPrefix = `${issuer.pathname.replace(/\/$/, "")}/`;
  if (target.origin !== issuer.origin || !target.pathname.startsWith(issuerPrefix) || target.search || target.hash) {
    throw new FirstConfigurationConfigError(`${name} must remain under the exact configured issuer.`);
  }
  return target;
}

function exactAdminBase(value, origin, realm) {
  const target = exactHttpsUrl(value, "CONTROL_CENTER_FIRST_CONFIGURATION_ADMIN_BASE_URL");
  if (target.origin !== origin || target.pathname.replace(/\/$/, "") !== `/admin/realms/${realm}` || target.search || target.hash) {
    throw new FirstConfigurationConfigError("The Keycloak admin base URL must target the exact configured realm.");
  }
  return target;
}

function exactAccountUrl(value, origin, realm) {
  const target = exactHttpsUrl(value, "CONTROL_CENTER_FIRST_CONFIGURATION_ACCOUNT_URL");
  if (target.origin !== origin || !target.pathname.startsWith(`/realms/${realm}/account`) || target.search || target.username || target.password) {
    throw new FirstConfigurationConfigError("The Keycloak account URL must target the exact configured realm.");
  }
  return target;
}

function requiredExistingFile(value, name) {
  const filename = requiredText(value, name);
  if (!filename.startsWith("/") || !existsSync(filename)) throw new FirstConfigurationConfigError(`${name} must be an existing absolute file.`);
  return filename;
}

function readDatabaseUrl(filename) {
  const value = readFileSync(filename, "utf8").trim();
  if (!/^postgres(?:ql)?:\/\//i.test(value) || /[\r\n\0]/.test(value)) {
    throw new FirstConfigurationConfigError("Control Center first-configuration storage requires PostgreSQL.");
  }
  return value;
}

function requiredIdentifier(value, name) {
  const text = requiredText(value, name);
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(text)) throw new FirstConfigurationConfigError(`${name} is invalid.`);
  return text;
}

function requiredUsername(value, name) {
  const text = requiredText(value, name);
  if (!/^[A-Za-z0-9@._+-]{1,128}$/.test(text)) throw new FirstConfigurationConfigError(`${name} is invalid.`);
  return text;
}

function requiredEmail(value, name) {
  const text = requiredText(value, name).toLowerCase();
  if (text.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) throw new FirstConfigurationConfigError(`${name} is invalid.`);
  return text;
}

function requiredText(value, name) {
  const text = String(value || "").trim();
  if (!text || text.length > 4096 || /[\r\n\0]/.test(text)) throw new FirstConfigurationConfigError(`${name} is required.`);
  return text;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = value === undefined || value === "" ? fallback : Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new FirstConfigurationConfigError(`First-configuration numeric value must be between ${minimum} and ${maximum}.`);
  }
  return number;
}
