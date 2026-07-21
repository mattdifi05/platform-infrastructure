export const DATABASE_ADMIN_AUTHORIZATION_PATH = "/control/internal/database-admin-authorize";

const ALLOWED_METHODS = new Set(["GET", "HEAD", "POST"]);
const ALLOWED_PATH_PREFIXES = ["/phpmyadmin", "/phppgadmin"];

export function authorizeDatabaseAdminForwardTarget(headers, { expectedHost }) {
  const host = normalizedSingleHeader(headers?.["x-forwarded-host"]);
  const method = normalizedSingleHeader(headers?.["x-forwarded-method"]).toUpperCase();
  const uri = normalizedSingleHeader(headers?.["x-forwarded-uri"]);
  const requiredHost = normalizeHost(expectedHost);

  if (!requiredHost || normalizeHost(host) !== requiredHost) return denied("forwarded host");
  if (!ALLOWED_METHODS.has(method)) return denied("forwarded method");
  const targetPath = databaseAdminPath(uri);
  if (!targetPath) return denied("forwarded URI");
  return { ok: true, status: 204, method, host: requiredHost, path: targetPath };
}

function databaseAdminPath(uri) {
  if (!uri || uri.length > 4096 || !uri.startsWith("/") || /[\\\u0000-\u001f\u007f#]/.test(uri)) return "";
  const rawPath = uri.split("?", 1)[0];
  let decoded;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return "";
  }
  if (decoded.split("/").some((segment) => segment === "." || segment === "..")) return "";
  if (!ALLOWED_PATH_PREFIXES.some((prefix) => decoded === prefix || decoded.startsWith(`${prefix}/`))) return "";
  return decoded;
}

function normalizedSingleHeader(value) {
  const values = Array.isArray(value) ? value : [value];
  if (values.length !== 1) return "";
  const normalized = String(values[0] || "").trim();
  if (!normalized || normalized.includes(",") || /[\r\n]/.test(normalized)) return "";
  return normalized;
}

function normalizeHost(value) {
  const host = String(value || "").trim().toLowerCase().replace(/:\d+$/, "");
  return /^[a-z0-9.-]{1,253}$/.test(host) ? host : "";
}

function denied(field) {
  return { ok: false, status: 403, error: "database_admin_target_rejected", message: `Database admin ${field} is invalid.` };
}
