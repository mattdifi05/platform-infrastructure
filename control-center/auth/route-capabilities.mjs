const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

const parameter = (name) => Object.freeze({ parameter: name });
const route = (method, operationId, capability, ...segments) => Object.freeze({
  method,
  operationId,
  capability,
  segments: Object.freeze(segments),
});
const viewer = (operationId, ...segments) => route("GET", operationId, "viewer", ...segments);
const admin = (operationId, ...segments) => route("POST", operationId, "admin", ...segments);
const ownerFresh = (method, operationId, ...segments) => route(method, operationId, "owner:fresh", ...segments);

// This is the complete Control API contract. Authorization and dispatch both
// consume the operation resolved from this catalog; adding a handler therefore
// requires an explicit capability decision here first.
const CONTROL_ROUTES = Object.freeze([
  ownerFresh("GET", "overview.read", "control", "overview"),
  viewer("status.events.stream", "control", "status", "events", "stream"),
  viewer("status.events.read", "control", "status", "events"),
  viewer("status.read", "control", "status"),
  viewer("go-no-go.read", "control", "go-no-go"),

  viewer("projects.list", "control", "projects"),
  admin("projects.create", "control", "projects"),
  viewer("projects.files.read", "control", "projects", parameter("projectId"), "files"),
  viewer("projects.read", "control", "projects", parameter("projectId")),
  admin("projects.update", "control", "projects", parameter("projectId"), "update"),
  admin("projects.archive.plan", "control", "projects", parameter("projectId"), "archive", "plan"),
  admin("projects.archive.apply", "control", "projects", parameter("projectId"), "archive", "apply"),
  admin("projects.delete.plan", "control", "projects", parameter("projectId"), "delete", "plan"),
  admin("projects.delete.apply", "control", "projects", parameter("projectId"), "delete", "apply"),

  viewer("applications.list", "control", "applications"),
  admin("applications.create", "control", "applications"),
  admin("applications.lifecycle", "control", "applications", parameter("applicationId"), parameter("action")),

  viewer("domains.list", "control", "domains"),
  admin("domains.create", "control", "domains"),
  viewer("network.read", "control", "network"),
  admin("subdomains.plan", "control", "subdomains", "plan"),
  admin("subdomains.apply", "control", "subdomains", "apply"),
  admin("subdomains.remove.plan", "control", "subdomains", parameter("subdomainId"), "remove", "plan"),
  admin("subdomains.remove.apply", "control", "subdomains", parameter("subdomainId"), "remove", "apply"),
  admin("subdomains.verify", "control", "subdomains", parameter("subdomainId"), "verify"),

  viewer("webspaces.list", "control", "webspaces"),
  admin("webspaces.create", "control", "webspaces"),
  admin("webspaces.quota", "control", "webspaces", parameter("webspaceId"), "quota"),

  viewer("databases.list", "control", "databases"),
  ownerFresh("POST", "database.create", "control", "databases"),
  ownerFresh("POST", "database.backup", "control", "databases", parameter("databaseId"), "backup"),
  admin("database.restore.plan", "control", "databases", parameter("databaseId"), "restore", "plan"),

  viewer("storage.read", "control", "storage"),
  admin("storage.bucket.create", "control", "storage", "buckets"),
  admin("storage.bucket.policy", "control", "storage", "buckets", parameter("bucketId"), "policy"),
  admin("storage.bucket.lifecycle", "control", "storage", "buckets", parameter("bucketId"), "lifecycle"),
  admin("storage.bucket.access-key", "control", "storage", "buckets", parameter("bucketId"), "access-key"),
  admin("storage.bucket.backup", "control", "storage", "buckets", parameter("bucketId"), "backup"),
  admin("storage.bucket.restore.plan", "control", "storage", "buckets", parameter("bucketId"), "restore", "plan"),

  viewer("secrets.inventory.read", "control", "secrets"),
  admin("secrets.material.create", "control", "secrets", "materials"),
  admin("secrets.material.rotation", "control", "secrets", "materials", parameter("materialId"), "rotation"),
  admin("secrets.material.usage", "control", "secrets", "materials", parameter("materialId"), "usage"),
  admin("secrets.material.access", "control", "secrets", "materials", parameter("materialId"), "access"),

  ownerFresh("GET", "vault.inventory.read", "control", "vault"),
  ownerFresh("POST", "vault.secret.store", "control", "vault", "secrets"),
  ownerFresh("POST", "vault.import-existing", "control", "vault", "import-existing"),
  ownerFresh("POST", "vault.secret.reveal", "control", "vault", "secrets", parameter("vaultItemId"), "reveal"),
  ownerFresh("POST", "vault.secret.delete", "control", "vault", "secrets", parameter("vaultItemId"), "delete"),

  viewer("workers-jobs.read", "control", "workers-jobs"),
  admin("workers-jobs.worker.create", "control", "workers-jobs", "workers"),
  admin("workers-jobs.queue.create", "control", "workers-jobs", "queues"),
  admin("workers-jobs.job.create", "control", "workers-jobs", "jobs"),
  admin("workers-jobs.job.retry", "control", "workers-jobs", "jobs", parameter("jobId"), "retry"),
  admin("workers-jobs.schedule.create", "control", "workers-jobs", "schedules"),
  admin("workers-jobs.schedule.status", "control", "workers-jobs", "schedules", parameter("scheduleId"), "status"),

  viewer("identity.read", "control", "identity"),
  admin("identity.admin-user.plan", "control", "identity", "admin-users"),
  admin("identity.team.plan", "control", "identity", "teams"),
  admin("identity.role.plan", "control", "identity", "roles"),
  admin("identity.session-policy.plan", "control", "identity", "sessions"),
  admin("identity.access-review.plan", "control", "identity", "access-reviews"),

  viewer("resources.summary.read", "control", "resources", "summary"),
  admin("resources.limits.plan", "control", "resources", "limits"),
  viewer("monitoring.read", "control", "monitoring"),
  viewer("security.summary.read", "control", "security", "summary"),
  admin("security.policy.plan", "control", "security", "policy"),
  viewer("logs.summary.read", "control", "logs", "summary"),
  viewer("alerts.list", "control", "alerts"),
  admin("alerts.record", "control", "alerts", "record"),
  admin("alerts.resolve", "control", "alerts", parameter("alertId"), "resolve"),
  admin("notifications.channel.plan", "control", "notifications", "channel"),
  viewer("provider-connections.list", "control", "provider-connections"),
  admin("provider-connections.update", "control", "provider-connections", parameter("providerId")),

  viewer("settings.read", "control", "settings"),
  viewer("ui-package.read", "control", "ui-package"),
  viewer("readiness.read", "control", "readiness"),
  admin("settings.local.plan", "control", "settings", "local"),

  ownerFresh("GET", "backup.summary.read", "control", "backups", "summary"),
  ownerFresh("GET", "backup.records.read", "control", "backups", "records"),
  ownerFresh("GET", "backup.jobs.read", "control", "backups", "jobs"),
  ownerFresh("GET", "backup.files.list", "control", "backups", "files"),
  ownerFresh("GET", "backup.file.preview", "control", "backups", "preview"),
  ownerFresh("POST", "backup.run", "control", "backups", "run"),
  ownerFresh("POST", "backup.file.delete", "control", "backups", "files", "delete"),
  admin("restore.plan", "control", "restore", "plan"),

  viewer("deployments.list", "control", "deployments"),
  viewer("advanced.read", "control", "advanced"),
  ownerFresh("GET", "advanced.section.read", "control", "advanced", parameter("sectionId")),
  viewer("adapters.list", "control", "adapters"),
  viewer("adapters.read", "control", "adapters", parameter("adapterId")),
  admin("adapters.plan", "control", "adapters", parameter("adapterId"), "plan"),
  admin("adapters.verify", "control", "adapters", parameter("adapterId"), "verify"),
  admin("adapters.apply.reject", "control", "adapters", parameter("adapterId"), "apply"),
  viewer("operations.list", "control", "operations"),
  viewer("operations.read", "control", "operations", parameter("operationId")),
  viewer("audit.read", "control", "audit"),
]);

const LEGACY_SENSITIVE_ROUTES = Object.freeze([
  // The HTML shell builds one monolithic operational context containing Vault
  // and backup metadata, so it must cross the same fresh-owner boundary before
  // any context reads occur.
  ownerFresh("GET", "ui.control-center"),
  ownerFresh("GET", "ui.control-center.index", "index.html"),
  ownerFresh("POST", "legacy.vault", "actions", "vault-command"),
  ownerFresh("POST", "legacy.database", "actions", "database-command"),
  ownerFresh("POST", "legacy.database-admin-login", "actions", "database-admin-login"),
  ownerFresh("GET", "legacy.phpmyadmin-login", "actions", "phpmyadmin-login"),
  ownerFresh("GET", "legacy.phppgadmin-login", "actions", "phppgadmin-login"),
  ownerFresh("POST", "legacy.backup", "actions", "backup-command"),
  ownerFresh("POST", "legacy.identity", "actions", "identity-command"),
  ownerFresh("POST", "legacy.settings", "actions", "settings-command"),
]);

export function normalizeControlApiParts(parts) {
  const routeParts = Array.from(parts || [], (part) => String(part));
  if (routeParts[0] === "control" && routeParts[1] === "v1") {
    return ["control", ...routeParts.slice(2)];
  }
  return routeParts;
}

export function isControlApiPath(pathname) {
  const value = String(pathname || "");
  return value === "/control" || value.startsWith("/control/");
}

export function listControlRouteDefinitions() {
  return CONTROL_ROUTES.map((definition) => ({
    method: definition.method,
    operationId: definition.operationId,
    capability: definition.capability,
    template: `/${definition.segments.map((segment) => isParameter(segment) ? `:${segment.parameter}` : segment).join("/")}`,
  }));
}

export function resolveAuthorizationCapability(method, pathname) {
  const verb = String(method || "GET").toUpperCase();
  const pathValue = String(pathname || "");
  const controlPath = isControlApiPath(pathValue);
  const parsed = parsePath(pathValue);

  if (!parsed.ok) {
    return controlPath
      ? deniedOperation(verb, pathValue)
      : defaultOperation(verb, pathValue);
  }

  const parts = normalizeControlApiParts(parsed.parts);
  const definitions = parts[0] === "control" ? CONTROL_ROUTES : LEGACY_SENSITIVE_ROUTES;
  for (const definition of definitions) {
    if (definition.method !== verb) continue;
    const parameters = matchRoute(parts, definition.segments);
    if (parameters) {
      return Object.freeze({
        method: verb,
        operationId: definition.operationId,
        capability: definition.capability,
        canonicalPath: canonicalPath(parts),
        classified: true,
        control: parts[0] === "control",
        parameters,
      });
    }
  }

  return parts[0] === "control" || isProtectedUiPath(parts)
    ? deniedOperation(verb, canonicalPath(parts), parts[0] === "control")
    : defaultOperation(verb, canonicalPath(parts));
}

function parsePath(pathname) {
  if (!pathname.startsWith("/") || (pathname.length > 1 && pathname.endsWith("/")) || pathname.includes("//")) {
    return { ok: false, parts: [] };
  }
  return { ok: true, parts: pathname === "/" ? [] : pathname.slice(1).split("/") };
}

function matchRoute(actual, expected) {
  if (actual.length !== expected.length) return null;
  const parameters = {};
  for (let index = 0; index < expected.length; index += 1) {
    const expectedSegment = expected[index];
    if (isParameter(expectedSegment)) {
      if (!actual[index]) return null;
      parameters[expectedSegment.parameter] = actual[index];
    } else if (actual[index] !== expectedSegment) {
      return null;
    }
  }
  return Object.freeze(parameters);
}

function isParameter(segment) {
  return Boolean(segment && typeof segment === "object" && typeof segment.parameter === "string");
}

function isProtectedUiPath(parts) {
  return parts.length === 0 || (parts.length === 1 && parts[0] === "index.html");
}

function deniedOperation(method, pathname, control = true) {
  return Object.freeze({
    method,
    operationId: "control.denied",
    capability: "deny",
    canonicalPath: pathname || "/",
    classified: false,
    control,
    parameters: Object.freeze({}),
  });
}

function defaultOperation(method, pathname) {
  const mutating = !READ_METHODS.has(method);
  return Object.freeze({
    method,
    operationId: mutating ? "default.mutation" : "default.read",
    capability: mutating ? "admin" : "viewer",
    canonicalPath: pathname || "/",
    classified: false,
    control: false,
    parameters: Object.freeze({}),
  });
}

function canonicalPath(parts) {
  return parts.length ? `/${parts.join("/")}` : "/";
}
