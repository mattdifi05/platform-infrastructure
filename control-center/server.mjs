import { createServer } from "node:http";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, appendFileSync } from "node:fs";
import path from "node:path";

const port = Number(process.env.CONTROL_CENTER_PORT || 8080);
const projectsRoot = process.env.PROJECTS_ROOT || "/var/www/projects";
const docsRoot = process.env.CONTROL_CENTER_DOCS_ROOT || "/var/www/infra-docs";
const stateFile = process.env.PROJECT_STATE_FILE || "/var/www/project-state/projects.json";
const auditFile = process.env.PROJECT_AUDIT_FILE || "/var/www/project-state/audit.jsonl";
const operationsFile = process.env.PROJECT_OPERATIONS_FILE || "/var/www/project-state/operations.jsonl";
const applicationsFile = process.env.PROJECT_APPLICATIONS_FILE || "/var/www/project-state/applications.json";
const domainsFile = process.env.PROJECT_DOMAINS_FILE || "/var/www/project-state/domains.json";
const databasesFile = process.env.PROJECT_DATABASES_FILE || "/var/www/project-state/databases.json";
const deploymentsFile = process.env.PROJECT_DEPLOYMENTS_FILE || "/var/www/project-state/deployments.jsonl";
const backupRecordsFile = process.env.PROJECT_BACKUP_RECORDS_FILE || "/var/www/project-state/backups.jsonl";
const resourceLimitsFile = process.env.PROJECT_RESOURCE_LIMITS_FILE || "/var/www/project-state/resource-limits.json";
const securityPoliciesFile = process.env.PROJECT_SECURITY_POLICIES_FILE || "/var/www/project-state/security-policies.json";
const alertsFile = process.env.PROJECT_ALERTS_FILE || "/var/www/project-state/alerts.json";
const notificationChannelsFile = process.env.PROJECT_NOTIFICATION_CHANNELS_FILE || "/var/www/project-state/notification-channels.json";
const providerConnectionsFile = process.env.PROJECT_PROVIDER_CONNECTIONS_FILE || "/var/www/project-state/provider-connections.json";
const settingsFile = process.env.PROJECT_SETTINGS_FILE || "/var/www/project-state/settings.json";
const webspacesFile = process.env.PROJECT_WEBSPACES_FILE || "/var/www/project-state/webspaces.json";
const sessionKeysFile = process.env.CONTROL_CENTER_SESSION_KEYS_FILE || "";
const adminPasswordFile = process.env.CONTROL_CENTER_ADMIN_PASSWORD_FILE || "";
const adminPasswordSha256 = String(process.env.CONTROL_CENTER_ADMIN_PASSWORD_SHA256 || "").trim().toLowerCase();
const authRequired = parseBoolean(process.env.CONTROL_CENTER_AUTH_REQUIRED || "") || Boolean(adminPasswordSha256 || adminPasswordFile);
const environment = normalizeEnvironment(process.env.CONTROL_CENTER_ENV || "local");
const projectsHost = normalizeHost(process.env.PROJECTS_HOST || "projects.localhost.com");
const hostSuffix = normalizeHostSuffix(process.env.PROJECT_HOST_SUFFIX || ".localhost.com");
const nodeHosts = parsePairs(process.env.NODE_PROJECT_HOSTS || "");

const docs = {
  "Start Here": [
    ["README.md", "Overview and local usage"],
    ["RUNBOOK.md", "Operations runbook"],
    ["VPS-PREDEPLOY-CHECKLIST.md", "VPS pre-deploy checklist"],
  ],
  "Security And Readiness": [
    ["SECURITY.md", "Security model"],
    ["THREAT-MODEL.md", "Threat model"],
    ["ENTERPRISE-MATURITY.md", "Enterprise maturity matrix"],
    ["READINESS-REPORT.md", "Readiness report"],
    ["FINAL-READINESS-AUDIT.md", "Final audit notes"],
  ],
  "Cloud And Edge": [
    ["cloudflare/README.md", "Cloudflare setup"],
    ["cloudflare/LIVE-CHANGES.md", "Cloudflare live change log"],
  ],
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `https://${req.headers.host || projectsHost}`);
    if (url.pathname === "/__health") {
      json(res, { ok: true, service: "control-center" });
      return;
    }

    if (url.pathname === "/login" && req.method === "POST") {
      await handleLogin(req, res);
      return;
    }

    if (url.pathname === "/logout") {
      clearSession(res);
      redirect(res, "/");
      return;
    }

    const session = authenticateRequest(req);
    if (authRequired && !session.ok) {
      if (url.pathname.startsWith("/control/") || req.method !== "GET") {
        json(res, { error: "admin_auth_required", message: session.message }, session.status);
        return;
      }
      html(res, renderLogin(session.message), session.status);
      return;
    }

    const state = readState();
    const projects = discoverProjects(state);
    const context = buildContext({ projects, state });

    if (url.pathname.startsWith("/control/")) {
      await handleApi(req, res, url, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/toggle-project") {
      await handleToggleProject(req, res, projects);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/project-command") {
      await handleProjectCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/application-command") {
      await handleApplicationCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/subdomain-command") {
      await handleSubdomainCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/webspace-command") {
      await handleWebspaceCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/database-command") {
      await handleDatabaseCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/backup-command") {
      await handleBackupCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/resource-command") {
      await handleResourceCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/security-command") {
      await handleSecurityCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/alert-command") {
      await handleAlertCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/settings-command") {
      await handleSettingsCommand(req, res, context);
      return;
    }

    if (url.pathname !== "/" && url.pathname !== "/index.html") {
      notFound(res);
      return;
    }

    html(res, renderControlCenter(context, url.searchParams));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    json(res, { error: "control_center_error", message: sanitizeMessage(message) }, 500);
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`control-center listening on ${port}`);
});

async function handleLogin(req, res) {
  const payload = await readPayload(req);
  const password = String(payload.password || "");
  if (!authVerifierConfigured()) {
    json(res, { error: "admin_auth_not_configured", message: "Admin authentication is required but no password verifier is configured." }, 503);
    return;
  }
  if (!verifyAdminPassword(password)) {
    appendAudit({
      action: "admin.login.failed",
      target: "control-center",
      environment,
      risk: "medium",
      result: "failed",
      dryRun: false,
      summary: "Admin login rejected.",
    });
    if (wantsJson(req)) {
      json(res, { error: "admin_auth_failed", message: "Invalid admin password." }, 401);
      return;
    }
    html(res, renderLogin("Invalid admin password."), 401);
    return;
  }

  appendAudit({
    action: "admin.login.success",
    target: "control-center",
    environment,
    risk: "low",
    result: "success",
    dryRun: false,
    summary: "Admin session created.",
  });
  setSession(res);
  redirect(res, "/");
}

async function handleApi(req, res, url, context) {
  const method = (req.method || "GET").toUpperCase();
  const parts = url.pathname.split("/").filter(Boolean);
  const payload = await readPayload(req);

  try {
    if (method === "GET" && route(parts, "control", "overview")) return json(res, context.overview);
    if (method === "GET" && route(parts, "control", "projects")) return json(res, { projects: context.projects });
    if (method === "POST" && route(parts, "control", "projects")) return json(res, planProjectCreate(payload, context), 202);
    if (method === "GET" && parts.length === 3 && route(parts.slice(0, 2), "control", "projects")) return json(res, findById(context.projects, parts[2], "Project"));
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "projects", "update")) {
      return json(res, planOrApplyProjectUpdate(parts[2], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "projects", "archive", "plan")) {
      return json(res, planProjectArchive(parts[2], context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "projects", "archive", "apply")) {
      return json(res, applyProjectArchive(parts[2], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "projects", "delete", "plan")) {
      return json(res, planProjectDelete(parts[2], context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "projects", "delete", "apply")) {
      return json(res, applyProjectDelete(parts[2], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "applications")) return json(res, { applications: context.applications });
    if (method === "POST" && route(parts, "control", "applications")) return json(res, planApplicationCreate(payload, context), 202);
    if (method === "POST" && parts.length === 4 && route(parts.slice(0, 2), "control", "applications")) {
      return json(res, planApplicationLifecycle(parts[2], parts[3], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "domains")) return json(res, { domains: context.domains, subdomains: context.subdomains });
    if (method === "POST" && route(parts, "control", "domains")) return json(res, planDomainCreate(payload, context), 202);
    if (method === "POST" && route(parts, "control", "subdomains", "plan")) return json(res, planSubdomain(payload, context), 202);
    if (method === "POST" && route(parts, "control", "subdomains", "apply")) return json(res, applySubdomain(payload, context), 202);
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "subdomains", "remove", "plan")) {
      return json(res, planSubdomainRemoval(parts[2], context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "subdomains", "remove", "apply")) {
      return json(res, applySubdomainRemoval(parts[2], payload, context), 202);
    }
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "subdomains", "verify")) {
      return json(res, verifySubdomain(parts[2], context), 202);
    }

    if (method === "GET" && route(parts, "control", "webspaces")) return json(res, { webspaces: context.webspaces });
    if (method === "POST" && route(parts, "control", "webspaces")) return json(res, planWebspaceCreate(payload, context), 202);
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "webspaces", "quota")) {
      return json(res, planWebspaceQuota(parts[2], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "databases")) return json(res, { databases: context.databases, engines: context.databaseEngines });
    if (method === "POST" && route(parts, "control", "databases")) return json(res, planDatabaseCreate(payload, context), 202);
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "databases", "backup")) {
      return json(res, planDatabaseBackup(parts[2], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "databases", "restore", "plan")) {
      return json(res, planDatabaseRestore(parts[2], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "resources", "summary")) return json(res, context.resources);
    if (method === "POST" && route(parts, "control", "resources", "limits")) return json(res, planResourceLimitUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "security", "summary")) return json(res, context.security);
    if (method === "POST" && route(parts, "control", "security", "policy")) return json(res, planSecurityPolicyUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "logs", "summary")) return json(res, context.logsAlerts);
    if (method === "GET" && route(parts, "control", "alerts")) return json(res, { alerts: context.alertRecords, notificationChannels: context.notificationChannels });
    if (method === "POST" && route(parts, "control", "alerts", "record")) return json(res, planAlertRecord(payload, context), 202);
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "alerts", "resolve")) {
      return json(res, planAlertResolution(parts[2], payload, context), 202);
    }
    if (method === "POST" && route(parts, "control", "notifications", "channel")) return json(res, planNotificationChannelUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "provider-connections")) return json(res, { providerConnections: context.providerConnections });
    if (method === "POST" && parts.length === 3 && route(parts.slice(0, 2), "control", "provider-connections")) {
      return json(res, planProviderConnectionUpdate(parts[2], payload, context), 202);
    }
    if (method === "GET" && route(parts, "control", "settings")) return json(res, context.settings);
    if (method === "POST" && route(parts, "control", "settings", "local")) return json(res, planSettingsUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "backups", "summary")) return json(res, context.backups);
    if (method === "GET" && route(parts, "control", "backups", "records")) return json(res, { records: context.backupRecords });
    if (method === "POST" && route(parts, "control", "backups", "run")) return json(res, planBackupRun(payload, context), 202);
    if (method === "POST" && route(parts, "control", "restore", "plan")) return json(res, planRestore(payload, context), 202);

    if (method === "GET" && route(parts, "control", "deployments")) return json(res, { deployments: context.deployments });
    if (method === "GET" && route(parts, "control", "advanced")) return json(res, advancedControlOverview(context));
    if (method === "GET" && parts.length === 3 && route(parts.slice(0, 2), "control", "advanced")) return json(res, advancedControlSection(parts[2], context));
    if (method === "GET" && route(parts, "control", "adapters")) return json(res, { adapters: adapterRegistry(context) });
    if (method === "GET" && parts.length === 3 && route(parts.slice(0, 2), "control", "adapters")) return json(res, findAdapter(parts[2], context));
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "adapters", "plan")) {
      return json(res, planAdapterAction(parts[2], payload, context), 202);
    }
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "adapters", "verify")) {
      return json(res, planAdapterVerify(parts[2], payload, context), 202);
    }
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "adapters", "apply")) {
      return json(res, rejectAdapterApply(parts[2], payload, context), 409);
    }
    if (method === "GET" && route(parts, "control", "operations")) return json(res, { operations: context.operations });
    if (method === "GET" && parts.length === 3 && route(parts.slice(0, 2), "control", "operations")) return json(res, findById(context.operations, parts[2], "Operation"));
    if (method === "GET" && route(parts, "control", "audit")) return json(res, { audit: context.audit });
  } catch (error) {
    if (error instanceof ValidationError) return json(res, { error: "validation_failed", message: error.message }, 422);
    if (error instanceof RejectedOperationError) return json(res, { error: "operation_rejected", message: error.message }, 409);
    throw error;
  }

  notFound(res);
}

async function handleToggleProject(req, res, projects) {
  const payload = await readPayload(req);
  const slug = slugify(payload.slug || "");
  const project = projects.find((item) => item.slug === slug);
  if (!project) {
    json(res, { error: "not_found", message: "Project not found." }, 404);
    return;
  }
  const enabled = String(payload.enabled || "") === "1";
  if (enabled && project.filesystemExists === false) {
    json(res, { error: "operation_rejected", message: "Project routing cannot be enabled until source files are mounted under the projects directory." }, 409);
    return;
  }
  const state = readState();
  state.projects[slug] = { ...(state.projects[slug] || {}), enabled, archivedAt: enabled ? null : state.projects[slug]?.archivedAt || null, updatedAt: new Date().toISOString() };
  writeState(state);
  appendAudit({
    action: enabled ? "project.enable" : "project.disable",
    target: slug,
    environment,
    risk: enabled ? "low" : "medium",
    result: "success",
    dryRun: false,
    summary: enabled ? "Project routing enabled locally." : "Project routing disabled locally.",
  });
  redirect(res, `/?section=projects#project-${encodeURIComponent(slug)}`);
}

async function handleProjectCommand(req, res, context) {
  const payload = await readPayload(req);
  const id = slugify(payload.id || payload.slug || payload.projectId || "");
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "create") operation = planProjectCreate(payload, context);
    else if (action === "archive") operation = applyProjectArchive(id, payload, context);
    else if (action === "delete") operation = applyProjectDelete(id, payload, context);
    else if (action === "update") operation = planOrApplyProjectUpdate(id, payload, context);
    else throw new ValidationError("Unsupported project action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, "/?section=projects");
}

async function handleApplicationCommand(req, res, context) {
  const payload = await readPayload(req);
  const id = slugify(payload.id || payload.applicationId || "");
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "create") operation = planApplicationCreate(payload, context);
    else operation = planApplicationLifecycle(id, action, payload, context);
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, `/?section=applications&project=${encodeURIComponent(operation.projectId || "")}#app-${encodeURIComponent(id)}`);
}

async function handleSubdomainCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "create-domain") operation = planDomainCreate(payload, context);
    else if (action === "apply-local") operation = applySubdomain({ ...payload, environment: "local", confirm: "APPLY-LOCAL" }, context);
    else if (action === "verify") operation = verifySubdomain(payload.id || payload.subdomainId || "", context);
    else if (action === "remove") operation = applySubdomainRemoval(payload.id || payload.subdomainId || "", payload, context);
    else throw new ValidationError("Unsupported subdomain action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, "/?section=domains");
}

async function handleWebspaceCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "create") operation = planWebspaceCreate(payload, context);
    else if (action === "quota") operation = planWebspaceQuota(payload.id || payload.webspaceId || "", payload, context);
    else throw new ValidationError("Unsupported webspace action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, `/?section=webspaces#webspace-${encodeURIComponent(operation.details?.webspaceId || operation.details?.id || "")}`);
}

async function handleDatabaseCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "create") operation = planDatabaseCreate(payload, context);
    else if (action === "backup") operation = planDatabaseBackup(payload.id || payload.databaseId || "", payload, context);
    else if (action === "restore") operation = planDatabaseRestore(payload.id || payload.databaseId || "", payload, context);
    else throw new ValidationError("Unsupported database action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, `/?mode=advanced&section=databases#database-${encodeURIComponent(operation.details?.databaseId || operation.database?.id || "")}`);
}

async function handleBackupCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "backup") operation = planBackupRun(payload, context);
    else if (action === "restore") operation = planRestore(payload, context);
    else throw new ValidationError("Unsupported backup action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, "/?section=backups");
}

async function handleResourceCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "limits") operation = planResourceLimitUpdate(payload, context);
    else throw new ValidationError("Unsupported resource action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, `/?section=resources#resources-${encodeURIComponent(operation.details?.projectId || operation.resourceLimit?.projectId || "")}`);
}

async function handleSecurityCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "policy") operation = planSecurityPolicyUpdate(payload, context);
    else throw new ValidationError("Unsupported security action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, `/?section=security#security-${encodeURIComponent(operation.details?.scope || operation.securityPolicy?.scope || "global")}`);
}

async function handleAlertCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "record") operation = planAlertRecord(payload, context);
    else if (action === "resolve") operation = planAlertResolution(payload.id || payload.alertId || "", payload, context);
    else if (action === "channel") operation = planNotificationChannelUpdate(payload, context);
    else throw new ValidationError("Unsupported alert action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, `/?section=logs#alert-${encodeURIComponent(operation.details?.alertId || operation.alert?.id || operation.notificationChannel?.channel || "")}`);
}

async function handleSettingsCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "update") operation = planSettingsUpdate(payload, context);
    else if (action === "provider-connection") operation = planProviderConnectionUpdate(payload.id || payload.providerId || "", payload, context);
    else throw new ValidationError("Unsupported settings action.");
  } catch (error) {
    if (error instanceof ValidationError) {
      json(res, { error: "validation_failed", message: error.message }, 422);
      return;
    }
    if (error instanceof RejectedOperationError) {
      json(res, { error: "operation_rejected", message: error.message }, 409);
      return;
    }
    throw error;
  }
  if (wantsJson(req)) {
    json(res, operation, 202);
    return;
  }
  redirect(res, "/?section=settings#settings-local");
}

function buildContext({ projects, state }) {
  const storedApplications = readApplicationsState();
  const storedDomains = readDomainsState();
  const discoveredApplications = projects.map((project) => applicationRecord({
    id: project.slug,
    projectId: project.slug,
    name: project.name,
    runtime: project.runtime,
    kind: project.runtime === "node" ? "frontend" : "php",
    host: project.host,
    status: project.enabled ? "online" : "offline",
    healthcheck: `https://${project.host}/`,
    source: "project-discovery",
    filesystemTouched: false,
    dockerTouched: false,
  }));
  const discoveredApplicationIds = new Set(discoveredApplications.map((app) => app.id));
  const applications = [
    ...discoveredApplications.map((app) => applicationRecord({ ...app, ...(storedApplications[app.id] || {}) })),
    ...Object.values(storedApplications)
      .filter((app) => app && !app.deletedAt && !discoveredApplicationIds.has(app.id))
      .map((app) => applicationRecord(app)),
  ];
  const subdomains = [
    ...projects.map((project) => ({
      id: slugify(project.host),
      projectId: project.slug,
      applicationId: project.slug,
      environment,
      hostname: project.host,
      baseDomain: hostSuffix.replace(/^\./, ""),
      type: project.runtime === "node" ? "frontend" : "custom",
      visibility: "public",
      protection: "none",
      tlsStatus: environment === "local" ? "local-certificate" : "requires-verify",
      dnsStatus: environment === "local" ? "local-resolver-or-hosts" : "requires-cloudflare-verify",
      healthStatus: project.enabled ? "routable" : "disabled",
      status: project.enabled ? "active" : "disabled",
      createdBy: "control-center-discovery",
      deletedAt: null,
    })),
    ...Object.values(state.subdomains || {}).filter((item) => item && !item.deletedAt),
  ];
  const storedWebspaces = readWebspacesState();
  const defaultWebspaces = projects.map((project) => ({
    id: project.slug,
    projectId: project.slug,
    name: project.slug,
    environment: "local",
    basePath: `webspaces/${project.slug}`,
    quotaBytes: 0,
    usedBytes: 0,
    mounts: ["public", "private", "uploads", "backups", "config"],
    linkedApps: [project.slug],
    status: project.enabled ? "active" : "disabled",
    source: "project-discovery",
  }));
  const defaultIds = new Set(defaultWebspaces.map((space) => space.id));
  const storedActiveWebspaces = Object.values(storedWebspaces).filter((space) => space && !space.deletedAt);
  const webspaces = [
    ...defaultWebspaces.map((space) => ({ ...space, ...(storedWebspaces[space.id] || {}) })),
    ...storedActiveWebspaces.filter((space) => !defaultIds.has(space.id)),
  ];
  const databaseEngines = [
    { id: "mariadb", name: "MariaDB", status: "configured", service: "mariadb", liveAdapter: "DatabaseAdapter", productionEvidence: false },
    { id: "postgres", name: "PostgreSQL", status: "configured", service: "postgres", liveAdapter: "DatabaseAdapter", productionEvidence: false },
  ];
  const databases = Object.values(readDatabasesState())
    .filter((database) => database && !database.deletedAt)
    .map((database) => databaseRecord(database))
    .sort((a, b) => `${a.projectId}:${a.engine}:${a.name}`.localeCompare(`${b.projectId}:${b.engine}:${b.name}`));
  const deployments = readDeployments();
  const backupRecords = readBackupRecords();
  const storedResourceLimits = readResourceLimitsState();
  const storedSecurityPolicies = readSecurityPoliciesState();
  const storedAlerts = readAlertsState();
  const storedNotificationChannels = readNotificationChannelsState();
  const storedProviderConnections = readProviderConnectionsState();
  const storedSettings = readSettingsState();
  const audit = readAudit();
  const operations = readOperations();
  const activeProjects = projects.filter((project) => project.enabled && project.status === "active").length;
  const archivedProjects = projects.filter((project) => project.status === "archived").length;
  const onlineApps = applications.filter((app) => app.status === "online").length;
  const resources = {
    mode: environment,
    source: "local-control-plane",
    cpu: { status: "configured", summary: "Container metrics are available through Grafana/Prometheus." },
    memory: { status: "configured", summary: "Memory trend is delegated to Prometheus/cAdvisor." },
    disk: { status: "local-estimate", webspacesBytes: webspaces.reduce((sum, item) => sum + item.usedBytes, 0) },
    containersByProject: applications.map((app) => ({
      projectId: app.projectId,
      applicationId: app.id,
      runtime: app.runtime,
      status: app.status,
    })),
    projectLimits: projects.map((project) => resourceLimitRecord({ projectId: project.slug, ...(storedResourceLimits[project.slug] || {}) })),
    trend: "delegated-to-prometheus-and-cadvisor",
  };
  const defaultSecurityPolicy = securityPolicyRecord({
    scope: "global",
    wafMode: "configured",
    rateLimitTier: "configured",
    adminProtection: authRequired ? "required" : "local-only",
    securityHeaders: "configured",
    cloudflareAccess: environment === "production" ? "requires-verify-remote" : "plan-only-local",
    passkeyAdminAuth: "available-through-stexor-account-app",
    status: "discovered",
    source: "control-center-default",
  });
  const securityPolicies = [
    securityPolicyRecord({ ...defaultSecurityPolicy, ...(storedSecurityPolicies.global || {}) }),
    ...Object.values(storedSecurityPolicies)
      .filter((policy) => policy && policy.scope !== "global")
      .map((policy) => securityPolicyRecord(policy)),
  ];
  const globalSecurityPolicy = securityPolicies[0];
  const recentSecurityAudit = audit.filter((event) => /security|admin|auth|waf|rate|cloudflare/i.test(event.action || "")).slice(0, 8);
  const security = {
    waf: globalSecurityPolicy.wafMode,
    rateLimit: globalSecurityPolicy.rateLimitTier,
    cloudflareAccess: globalSecurityPolicy.cloudflareAccess,
    adminProtection: globalSecurityPolicy.adminProtection,
    securityHeaders: globalSecurityPolicy.securityHeaders,
    passkeyAdminAuth: globalSecurityPolicy.passkeyAdminAuth,
    policies: securityPolicies,
    recentAuditEvents: recentSecurityAudit,
  };
  const backups = {
    mode: environment,
    manualBackup: "plan-only-from-control-center",
    restoreDrill: "available-through-infra-ops",
    offsite: process.env.BACKUP_SCHEDULER_ENABLE_OFFSITE === "true" ? "configured" : "not-configured",
    rpoRto: "reported-by-production-go-no-go-evidence",
    latest: backupRecords.slice(0, 5),
  };
  const alertRecords = Object.values(storedAlerts)
    .filter((alert) => alert && !alert.deletedAt)
    .map((alert) => alertRecord(alert))
    .sort((a, b) => String(b.updatedAt || b.createdAt).localeCompare(String(a.updatedAt || a.createdAt)));
  const notificationChannels = defaultNotificationChannels().map((channel) => notificationChannelRecord({
    ...channel,
    ...(storedNotificationChannels[channel.channel] || {}),
  }));
  const openAlerts = alertRecords.filter((alert) => ["open", "firing"].includes(alert.status));
  const providerConnections = defaultProviderConnections(notificationChannels).map((connection) => providerConnectionRecord({
    ...connection,
    ...(storedProviderConnections[connection.id] || {}),
  }));
  const providerById = new Map(providerConnections.map((connection) => [connection.id, connection]));
  const logsAlerts = {
    mode: environment,
    source: "local-control-plane",
    openAlerts,
    recentErrors: recentErrorRecords(audit, operations),
    notificationChannels,
    detailedLogs: "Use authenticated Grafana/Loki dashboards or Docker logs from the operator shell.",
    alertRouting: "Prometheus routes to internal Alertmanager, then to worker-notifications with secret-backed delivery.",
    rawConsoles: "Prometheus, Alertmanager and Traefik raw consoles are intentionally not linked from Projects.",
  };
  const settings = settingsRecord({
    preferredMode: "simple",
    environmentMode: environment,
    baseDomain: hostSuffix.replace(/^\./, ""),
    cloudflareConnectionStatus: providerById.get("cloudflare")?.status || globalSecurityPolicy.cloudflareAccess,
    githubConnectionStatus: providerById.get("github")?.status || "dry-run",
    smtpAlertStatus: providerById.get("smtp")?.status || notificationChannels.find((channel) => channel.channel === "email")?.status || "not-configured",
    productionGuard: environment === "production" ? "requires-verify-remote" : "local-evidence-only",
    source: "control-center-default",
    ...storedSettings,
  });
  const defaultDomain = domainRecord({
    id: "local",
    environment: "local",
    baseDomain: hostSuffix.replace(/^\./, ""),
    dnsStatus: "local-hosts-or-resolver",
    tlsStatus: "local-certificate",
    cloudflareStatus: "not-used-in-local-mode",
    source: "control-center-default",
  });
  const domains = [
    domainRecord({ ...defaultDomain, ...(storedDomains[defaultDomain.id] || {}) }),
    ...Object.values(storedDomains)
      .filter((domain) => domain && !domain.deletedAt && domain.id !== defaultDomain.id)
      .map((domain) => domainRecord(domain)),
  ];
  const overview = {
    title: "Stexor Control Center",
    environment,
    modeEvidence: environment === "production" ? "production evidence requires verifyRemote" : "local evidence only",
    projects: { total: projects.length, active: activeProjects, archived: archivedProjects },
    applications: { total: applications.length, online: onlineApps, offline: applications.length - onlineApps },
    resources,
    subdomains: { total: subdomains.length, active: subdomains.filter((item) => item.status === "active").length },
    databases: { total: databases.length, declared: databases.filter((item) => item.status === "declared").length },
    alerts: { open: openAlerts.length, source: "Control Center local alert metadata and Alertmanager evidence tooling" },
    deployments: { latest: deployments.slice(0, 5) },
    backups,
  };
  return {
    overview,
    projects,
    applications,
    domains,
    subdomains,
    webspaces,
    databases,
    databaseEngines,
    resources,
    security,
    backups,
    logsAlerts,
    settings,
    alertRecords,
    notificationChannels,
    providerConnections,
    backupRecords,
    deployments,
    operations,
    audit,
    docsAvailable: countAvailableDocs(),
    environment,
    advancedServices: advancedServices(),
  };
}

function adapterRegistry(context) {
  const adapters = [
    {
      id: "cloudflare",
      name: "CloudflareAdapter",
      category: "edge",
      status: context.environment === "production" ? "requires-private-material-and-verifyRemote" : "local-plan-only",
      capabilities: ["dns records", "proxied status", "Access policies", "WAF rules", "cache rules", "verify remote"],
      advancedSections: ["network", "cloudflare", "security-advanced", "go-no-go"],
      privateMaterialRefs: ["Cloudflare API material file", "Cloudflare zone metadata"],
    },
    {
      id: "traefik",
      name: "TraefikAdapter",
      category: "network",
      status: "read-only-route-evidence",
      capabilities: ["routers", "middleware", "TLS", "redirects", "route tests"],
      advancedSections: ["infrastructure", "network"],
      privateMaterialRefs: [],
    },
    {
      id: "docker",
      name: "DockerAdapter",
      category: "runtime",
      status: "planned-apply-adapter",
      capabilities: ["start", "stop", "restart", "healthcheck", "resource limits"],
      advancedSections: ["infrastructure", "workers-jobs", "deployments", "monitoring"],
      privateMaterialRefs: ["Docker socket mounted only in ops runner"],
    },
    {
      id: "github",
      name: "GitHubAdapter",
      category: "governance",
      status: "evidence-through-actions",
      capabilities: ["workflow status", "branch protection", "environments", "deploy approvals", "release evidence"],
      advancedSections: ["cicd-github", "deployments", "release-evidence"],
      privateMaterialRefs: ["GitHub app connection"],
    },
    {
      id: "prometheus",
      name: "PrometheusAdapter",
      category: "observability",
      status: "read-only-evidence",
      capabilities: ["metrics", "latency", "error rate", "container resources"],
      advancedSections: ["monitoring", "resources"],
      privateMaterialRefs: [],
    },
    {
      id: "loki",
      name: "LokiAdapter",
      category: "observability",
      status: "planned-query-adapter",
      capabilities: ["log query", "project filters", "request id", "non-sensitive export"],
      advancedSections: ["logs-advanced", "monitoring"],
      privateMaterialRefs: [],
    },
    {
      id: "alertmanager",
      name: "AlertmanagerAdapter",
      category: "observability",
      status: "read-only-evidence",
      capabilities: ["alert rules", "routing", "delivery evidence", "failure evidence"],
      advancedSections: ["alerts-advanced", "monitoring"],
      privateMaterialRefs: ["notification delivery material files"],
    },
    {
      id: "backup",
      name: "BackupAdapter",
      category: "resilience",
      status: "plan-only-from-control-center",
      capabilities: ["manual backup", "automatic backup", "retention", "off-site status"],
      advancedSections: ["backup-restore", "disaster-recovery"],
      privateMaterialRefs: ["backup repository material files"],
    },
    {
      id: "restore",
      name: "RestoreAdapter",
      category: "resilience",
      status: "plan-only-from-control-center",
      capabilities: ["single service restore", "full restore drill", "off-site restore drill", "restore p95"],
      advancedSections: ["backup-restore", "disaster-recovery"],
      privateMaterialRefs: ["backup repository material files"],
    },
    {
      id: "minio",
      name: "MinioAdapter",
      category: "storage",
      status: "planned-adapter",
      capabilities: ["buckets", "quota", "access policy", "lifecycle", "bucket restore"],
      advancedSections: ["storage"],
      privateMaterialRefs: ["MinIO access material file"],
    },
    {
      id: "database",
      name: "DatabaseAdapter",
      category: "data",
      status: "planned-adapter",
      capabilities: ["create database", "backup DB", "restore DB", "connection status", "users and permissions"],
      advancedSections: ["databases", "backup-restore", "disaster-recovery"],
      privateMaterialRefs: ["database admin material files"],
    },
    {
      id: "security",
      name: "SecurityAdapter",
      category: "security",
      status: "local-policy-evidence",
      capabilities: ["WAF", "rate limit", "CSP", "CORS", "headers", "admin route protection"],
      advancedSections: ["security-advanced", "identity"],
      privateMaterialRefs: [],
    },
    {
      id: "go-no-go",
      name: "GoNoGoAdapter",
      category: "release-control",
      status: "evidence-through-ops-runner",
      capabilities: ["production gate", "blocker report", "JSON report", "Markdown report", "evidence bundle"],
      advancedSections: ["go-no-go", "release-evidence", "disaster-recovery"],
      privateMaterialRefs: [],
    },
  ];
  return adapters.map((adapter) => adapterRecord(adapter, context));
}

function adapterRecord(adapter, context) {
  return sanitizeEvent({
    ...adapter,
    environment: context.environment,
    modeEvidence: context.overview.modeEvidence,
    planEndpoint: `/control/adapters/${adapter.id}/plan`,
    verifyEndpoint: `/control/adapters/${adapter.id}/verify`,
    applyEndpoint: `/control/adapters/${adapter.id}/apply`,
    dryRunDefault: true,
    providerTouched: false,
    liveProviderTouched: false,
    dockerTouched: false,
    destructiveActionExecuted: false,
    productionEvidence: false,
    guardrails: {
      clientCannotExecuteShell: true,
      applyRequiresBackendImplementation: true,
      applyRequiresStrongConfirmation: true,
      verifyAfterApplyRequired: true,
      productionRequiresVerifyRemote: true,
      sensitiveValuesExposed: false,
    },
    evidence: {
      auditEvents: context.audit.filter((event) => String(event.action || "").includes(adapter.id)).length,
      operations: context.operations.filter((operation) => String(operation.type || "").includes(adapter.id)).length,
    },
  });
}

function adaptersForSection(section, context) {
  return adapterRegistry(context).filter((adapter) => adapter.advancedSections.includes(section));
}

function findAdapter(id, context) {
  const cleanId = sanitizeIdentifier(id);
  const adapter = adapterRegistry(context).find((item) => item.id === cleanId);
  if (!adapter) throw new ValidationError("Adapter not found.");
  return adapter;
}

function planAdapterAction(id, payload, context) {
  const adapter = findAdapter(id, context);
  const action = sanitizeIdentifier(payload.action || "inspect") || "inspect";
  appendAudit({
    action: `adapter.${adapter.id}.${action}.plan`,
    target: adapter.id,
    environment: context.environment,
    risk: adapter.id === "cloudflare" || adapter.id === "docker" ? "medium" : "low",
    result: "planned",
    dryRun: true,
    summary: "Adapter action plan generated; no live provider, Docker or destructive action executed.",
  });
  return operationPlan(`adapter.${adapter.id}.${action}.plan`, context.environment, true, [
    "validate adapter",
    "validate requested action",
    "select backend adapter",
    "prepare dry-run execution plan",
    "require explicit apply implementation before mutation",
    "write audit event",
  ], {
    adapterId: adapter.id,
    adapterName: adapter.name,
    action,
    confirmationRequired: `ADAPTER-APPLY:${adapter.id}:${action}`,
    providerTouched: false,
    liveProviderTouched: false,
    dockerTouched: false,
    destructiveActionExecuted: false,
    productionEvidence: false,
  });
}

function planAdapterVerify(id, payload, context) {
  const adapter = findAdapter(id, context);
  const scope = sanitizeIdentifier(payload.scope || "default") || "default";
  appendAudit({
    action: `adapter.${adapter.id}.verify.plan`,
    target: adapter.id,
    environment: context.environment,
    risk: "low",
    result: "planned",
    dryRun: true,
    summary: "Adapter verification plan generated; remote checks are not executed from this foundation.",
  });
  return operationPlan(`adapter.${adapter.id}.verify.plan`, context.environment, true, [
    "validate adapter",
    "collect local evidence references",
    "prepare remote verification checklist",
    "mark production evidence false until verifyRemote passes",
    "write audit event",
  ], {
    adapterId: adapter.id,
    adapterName: adapter.name,
    scope,
    verifyRemoteRequired: context.environment === "production",
    providerTouched: false,
    liveProviderTouched: false,
    dockerTouched: false,
    productionEvidence: false,
  });
}

function rejectAdapterApply(id, payload, context) {
  const adapter = findAdapter(id, context);
  const action = sanitizeIdentifier(payload.action || "apply") || "apply";
  appendAudit({
    action: `adapter.${adapter.id}.${action}.apply.rejected`,
    target: adapter.id,
    environment: context.environment,
    risk: "high",
    result: "rejected",
    dryRun: true,
    summary: "Adapter apply rejected because no live backend apply implementation is enabled.",
  });
  throw new RejectedOperationError(`Adapter apply is disabled for ${adapter.name}; add an explicit backend implementation, strong confirmation and verifyRemote before enabling mutations.`);
}

function advancedControlOverview(context) {
  const sections = navigationForMode("advanced").map((item) => ({
    id: item.id,
    label: item.label,
    endpoint: `/control/advanced/${item.id}`,
    capabilityCount: advancedItems(item.id).length,
    adapterStatus: advancedAdapterStatus(item.id),
    dryRunDefault: true,
    providerTouched: false,
    productionEvidence: false,
  }));
  return sanitizeEvent({
    title: "Stexor Control Center Advanced API",
    environment: context.environment,
    modeEvidence: context.overview.modeEvidence,
    endpointPrefix: "/control/advanced",
    dryRunDefault: true,
    providerTouched: false,
    liveProviderTouched: false,
    productionEvidence: false,
    adapterEndpoint: "/control/adapters",
    adapterCount: adapterRegistry(context).length,
    sections,
  });
}

function advancedControlSection(section, context) {
  const cleanSection = sanitizeIdentifier(section);
  const navItem = navigationForMode("advanced").find((item) => item.id === cleanSection);
  if (!navItem) throw new ValidationError("Advanced section not found.");
  return sanitizeEvent({
    id: navItem.id,
    label: navItem.label,
    environment: context.environment,
    modeEvidence: context.overview.modeEvidence,
    adapterStatus: advancedAdapterStatus(navItem.id),
    capabilities: advancedItems(navItem.id),
    dryRunDefault: true,
    providerTouched: false,
    liveProviderTouched: false,
    dockerTouched: false,
    destructiveActionExecuted: false,
    productionEvidence: false,
    guardrails: {
      applyRequiresExplicitAdapter: true,
      productionRequiresVerifyRemote: true,
      localEvidenceIsProductionEvidence: false,
      sensitiveValuesExposed: false,
    },
    evidencePath: {
      auditEvents: context.audit.length,
      operations: context.operations.length,
      deployments: context.deployments.length,
      backupRecords: context.backupRecords.length,
      openAlerts: context.logsAlerts.openAlerts.length,
    },
    adapters: adaptersForSection(navItem.id, context).map((adapter) => ({
      id: adapter.id,
      name: adapter.name,
      status: adapter.status,
      planEndpoint: adapter.planEndpoint,
      verifyEndpoint: adapter.verifyEndpoint,
      productionEvidence: adapter.productionEvidence,
    })),
    data: advancedSectionData(navItem.id, context),
  });
}

function advancedAdapterStatus(section) {
  const readOnlySections = new Set(["infrastructure", "deployments", "monitoring", "logs-advanced", "alerts-advanced", "backup-restore", "security-advanced", "audit"]);
  return readOnlySections.has(section) ? "read-only-evidence" : "planned-adapter";
}

function advancedSectionData(section, context) {
  switch (section) {
    case "infrastructure":
      return {
        services: context.advancedServices,
        configuredServices: context.advancedServices.filter((service) => service.status === "configured").length,
      };
    case "network":
      return {
        domains: context.domains,
        subdomains: context.subdomains,
        routeTest: "plan-only through existing local Traefik wildcard routing",
        originLockStatus: context.environment === "production" ? "requires-verify-remote" : "not-required-local",
      };
    case "databases":
      return {
        engines: context.databaseEngines,
        databases: context.databases,
        operations: ["create database", "backup DB", "restore DB", "users and permissions"],
        slowQueries: "planned read-only adapter",
        connectionStatus: "metadata-only until DatabaseAdapter verify is enabled",
      };
    case "storage":
      return {
        webspaces: context.webspaces,
        buckets: [{ name: "MinIO", status: "planned adapter", policy: "metadata-only", valueExposed: false }],
      };
    case "workers-jobs":
      return {
        workers: context.applications.filter((app) => app.runtime === "worker"),
        failedJobs: context.operations.filter((operation) => /worker|job/i.test(operation.type || "") && operation.status === "failed"),
        scheduler: "containerized scheduler adapter planned",
        retryControls: "planned adapter",
      };
    case "deployments":
      return {
        deployments: context.deployments,
        latest: context.deployments.slice(0, 5),
        productionApproval: "required before production apply",
      };
    case "cicd-github":
      return {
        githubConnectionStatus: context.providerConnections.find((connection) => connection.id === "github")?.status || context.settings.githubConnectionStatus,
        branchProtection: "planned adapter",
        environments: "planned adapter",
        variablesVerification: "planned adapter with no values exposed",
        workflowStatus: "reported by GitHub Actions evidence",
        deployApprovals: "required for production",
      };
    case "cloudflare":
      return {
        connectionStatus: context.providerConnections.find((connection) => connection.id === "cloudflare")?.status || context.settings.cloudflareConnectionStatus,
        providerConnection: context.providerConnections.find((connection) => connection.id === "cloudflare") || null,
        dnsRecords: context.subdomains.map((item) => ({ hostname: item.hostname, status: item.status, environment: item.environment, proxied: context.environment === "production" ? "requires-verify-remote" : "not-used-local" })),
        accessPolicies: "planned adapter",
        wafRules: context.security.waf,
        cacheRules: "planned adapter",
        apply: "blocked without explicit adapter, confirmation and provider secrets",
        verifyRemote: "required before production evidence",
      };
    case "monitoring":
      return {
        resources: context.resources,
        openAlerts: context.logsAlerts.openAlerts,
        metrics: ["Prometheus", "cAdvisor", "node-exporter", "latency", "error rate"],
      };
    case "logs-advanced":
      return {
        recentErrors: context.logsAlerts.recentErrors,
        query: { backend: "Loki planned adapter", filters: ["project", "application", "container", "request id", "user id", "level"] },
        export: "non-sensitive export only",
      };
    case "alerts-advanced":
      return {
        alerts: context.alertRecords,
        notificationChannels: context.notificationChannels,
        deliveryEvidence: "verified through infra-ops evidence before production",
        escalation: "planned adapter",
      };
    case "backup-restore":
      return {
        backups: context.backups,
        records: context.backupRecords,
        retention: "configured by backup scheduler evidence",
      };
    case "disaster-recovery":
      return {
        rpoRto: context.backups.rpoRto,
        offsite: context.backups.offsite,
        latestBackup: context.backupRecords[0] || null,
        walArchive: "planned adapter",
        restoreP95: "reported by DR evidence",
        offsiteRestoreEvidence: "required before production go/no-go",
      };
    case "release-evidence":
      return {
        deployments: context.deployments,
        requirements: ["SBOM", "digest-pinned images", "provenance", "signature", "previous-images.json", "rollback validation"],
        localEvidenceOnly: context.environment !== "production",
      };
    case "go-no-go":
      return {
        environment: context.environment,
        blockers: context.environment === "production" ? ["verifyRemote evidence required"] : ["local evidence only is not production evidence"],
        reports: ["JSON", "Markdown", "evidence bundle"],
      };
    case "security-advanced":
      return {
        security: context.security,
        controls: advancedItems("security-advanced"),
        adminRouteProtection: context.security.adminProtection,
      };
    case "identity":
      return {
        adminAuthRequired: authRequired,
        adminVerifierConfigured: authVerifierConfigured(),
        sessionPolicy: "HttpOnly; Secure; SameSite=Lax",
        passkeyAdminAuth: context.security.passkeyAdminAuth,
        adminUsers: "identity adapter planned",
      };
    case "secrets":
      return {
        stores: [
          { name: "Docker secrets", status: "configured by compose secret files", valueExposed: false },
          { name: "Control Center session keys", status: sessionKeysFile ? "configured by secret file" : "not configured", valueExposed: false },
          { name: "Admin password verifier", status: authVerifierConfigured() ? "configured verifier only" : "not configured", valueExposed: false },
          { name: "Alert delivery secrets", status: context.notificationChannels.some((channel) => channel.status === "configured") ? "partially configured" : "metadata only", valueExposed: false },
        ],
        providerConnections: context.providerConnections.map((connection) => ({ id: connection.id, privateMaterialConfigured: connection.privateMaterialConfigured, credentialValueExposed: connection.credentialValueExposed })),
        rotation: "tracked through infra-ops secret evidence",
        usageMap: "planned adapter",
      };
    case "audit":
      return {
        events: context.audit,
        appendOnly: true,
        fields: ["actor", "project", "environment", "action", "result", "timestamp", "risk", "request id"],
      };
    case "billing":
      return {
        vpsPlanMetadata: "operator supplied",
        resourceBudget: context.resources.projectLimits,
        cloudflarePlan: "operator supplied",
        backupStorage: context.backups.offsite,
        costReview: "planned adapter",
      };
    default:
      return { status: "planned adapter" };
  }
}

function discoverProjects(state) {
  if (!existsSync(projectsRoot)) return [];
  const projects = [];
  const seen = new Set();
  for (const entry of readdirSync(projectsRoot, { withFileTypes: true })) {
    if (entry.name === "." || entry.name === "..") continue;
    const slug = slugify(entry.name);
    if (!slug || seen.has(slug) || ["public", "node-modules", "vendor"].includes(slug)) continue;
    const projectPath = path.join(projectsRoot, entry.name);
    if (!safeIsDirectory(projectPath)) continue;
    const metadata = state.projects?.[slug] || {};
    if (metadata.deletedAt) continue;
    const isPhp = isPhpProject(projectPath);
    const isNode = existsSync(path.join(projectPath, "package.json"));
    if (!isPhp && !isNode) continue;
    const type = isPhp ? "PHP" : "Node";
    const host = type === "Node" && nodeHosts.has(slug) ? nodeHosts.get(slug) : `${slug}${hostSuffix}`;
    const archived = Boolean(metadata.archivedAt);
    const enabled = metadata.enabled !== false && !archived;
    projects.push({
      id: slug,
      slug,
      name: metadata.displayName || humanName(entry.name),
      type,
      runtime: type.toLowerCase(),
      host,
      href: `https://${host}/`,
      enabled,
      status: archived ? "archived" : enabled ? "active" : "disabled",
      archivedAt: metadata.archivedAt || null,
      updatedAt: metadata.updatedAt || null,
      source: "project-discovery",
      filesystemExists: true,
      filesystemTouched: false,
      databaseTouched: false,
      summary: archived ? "Archived in local Control Center state" : type === "PHP" ? "Apache/PHP local host" : "Node routed service",
    });
    seen.add(slug);
  }
  for (const [key, metadata] of Object.entries(state.projects || {})) {
    const slug = slugify(key);
    if (!slug || seen.has(slug) || metadata?.deletedAt || metadata?.declaredProject !== true) continue;
    const runtime = ["node", "php"].includes(metadata.runtime) ? metadata.runtime : "node";
    const type = runtime === "php" ? "PHP" : "Node";
    const archived = Boolean(metadata.archivedAt);
    const enabled = metadata.enabled === true && !archived;
    const host = normalizeHost(metadata.host || `${slug}${hostSuffix}`);
    projects.push({
      id: slug,
      slug,
      name: metadata.displayName || humanName(slug),
      type,
      runtime,
      host,
      href: `https://${host}/`,
      enabled,
      status: archived ? "archived" : enabled ? "active" : "declared",
      archivedAt: metadata.archivedAt || null,
      updatedAt: metadata.updatedAt || metadata.createdAt || null,
      source: "control-center-state",
      filesystemExists: false,
      filesystemTouched: false,
      databaseTouched: false,
      summary: archived ? "Archived in local Control Center state" : "Declared in Control Center state; add source files or link applications before enabling routing.",
    });
    seen.add(slug);
  }
  projects.sort((a, b) => {
    const typeOrder = { PHP: 0, Node: 1 };
    return (typeOrder[a.type] - typeOrder[b.type]) || a.name.localeCompare(b.name);
  });
  return projects;
}

function renderControlCenter(context, params) {
  const mode = params.get("mode") === "advanced" ? "advanced" : "simple";
  const nav = navigationForMode(mode);
  const requestedSection = params.get("section") || (mode === "advanced" ? "infrastructure" : "overview");
  const section = nav.some((item) => item.id === requestedSection) ? requestedSection : nav[0].id;
  const selectedProject = context.projects.some((project) => project.slug === params.get("project")) ? params.get("project") : "";
  const scoped = (items) => selectedProject ? items.filter((item) => (item.projectId || item.slug) === selectedProject) : items;
  const title = nav.find((item) => item.id === section)?.label || "Overview";

  let body = "";
  if (mode === "simple") {
    if (section === "overview") body = renderOverview(context);
    else if (section === "projects") body = renderProjects(scoped(context.projects));
    else if (section === "applications") body = renderApplications(scoped(context.applications), context.projects, context.webspaces);
    else if (section === "domains") body = renderDomains(context.domains, scoped(context.subdomains), context.projects);
    else if (section === "webspaces") body = renderWebspaces(scoped(context.webspaces), context.projects);
    else if (section === "resources") body = renderResources(context.resources, context.projects);
    else if (section === "security") body = renderSecurity(context.security);
    else if (section === "backups") body = renderBackups(context.backups, context.backupRecords);
    else if (section === "logs") body = renderLogsAlerts(context.logsAlerts);
    else body = renderSettings(context);
  } else {
    if (section === "audit") body = renderAudit(context.audit, "Audit Log");
    else if (section === "network") body = renderDomains(context.domains, scoped(context.subdomains), context.projects);
    else if (section === "infrastructure") body = renderInfrastructure(context.advancedServices);
    else if (section === "databases") body = renderDatabases(scoped(context.databases), context.databaseEngines, context.projects);
    else if (section === "deployments") body = renderDeployments(scoped(context.deployments));
    else if (section === "logs-advanced") body = renderAdvancedPanel(title, section, context, "Loki query and export surfaces stay metadata-only here.");
    else if (section === "alerts-advanced") body = renderAdvancedPanel(title, section, context, "Alert delivery evidence is verified through the ops runner before production use.");
    else if (section === "security-advanced") body = renderAdvancedPanel(title, section, context, "Security controls stay behind explicit adapters and confirmation gates.");
    else if (section === "backup-restore") body = renderBackups(context.backups, context.backupRecords);
    else body = renderAdvancedPanel(title, section, context);
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stexor Control Center</title>
${styleTag()}
</head>
<body>
<main class="control-shell">
  <aside class="sidebar">
    <div class="brand"><span class="brand-mark">SX</span><div><strong>Stexor</strong><small>Control Center</small></div></div>
    <nav aria-label="Control navigation">
      ${nav.map((item) => `<a class="${section === item.id ? "active" : ""}" href="/?mode=${mode}&section=${item.id}"><span>${escapeHtml(item.short)}</span>${escapeHtml(item.label)}</a>`).join("")}
    </nav>
    <div class="mode-card">
      <small>Mode</small>
      <div class="segmented">
        <a class="${mode === "simple" ? "selected" : ""}" href="/?mode=simple&section=overview">Simple</a>
        <a class="${mode === "advanced" ? "selected" : ""}" href="/?mode=advanced&section=infrastructure">Advanced</a>
      </div>
    </div>
  </aside>
  <section class="workspace">
    <header class="topbar">
      <div><p class="eyebrow">${escapeHtml(environment.toUpperCase())} MODE</p><h1>${escapeHtml(title)}</h1></div>
      <div class="top-actions">
        <span class="pill ${environment === "production" ? "danger" : "info"}">${escapeHtml(context.overview.modeEvidence)}</span>
        ${authRequired ? '<a class="button" href="/logout">Logout</a>' : ""}
        <form method="get" class="switcher">
          <input type="hidden" name="mode" value="${escapeHtml(mode)}">
          <input type="hidden" name="section" value="${escapeHtml(section)}">
          <select name="project" onchange="this.form.submit()" aria-label="Project switcher">
            <option value="">All projects</option>
            ${context.projects.map((project) => `<option value="${escapeHtml(project.slug)}" ${selectedProject === project.slug ? "selected" : ""}>${escapeHtml(project.name)}</option>`).join("")}
          </select>
        </form>
      </div>
    </header>
    ${body}
  </section>
</main>
</body>
</html>`;
}

function renderLogin(message) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stexor Control Center Sign In</title>
${styleTag()}
</head>
<body>
<main class="login-shell">
  <section class="login-panel">
    <span class="brand-mark">SX</span>
    <p class="eyebrow">${escapeHtml(environment.toUpperCase())} MODE</p>
    <h1>Admin Sign In</h1>
    <p class="login-copy">${escapeHtml(message || "Admin authentication required.")}</p>
    <form method="post" action="/login" class="login-form">
      <label for="password">Admin password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button class="button open" type="submit">Sign in</button>
    </form>
  </section>
</main>
</body>
</html>`;
}

function renderOverview(context) {
  return `<section class="metric-grid">
    <div class="metric"><span>${context.overview.projects.active}</span><small>active projects</small></div>
    <div class="metric"><span>${context.overview.applications.online}</span><small>online apps</small></div>
    <div class="metric"><span>${context.overview.subdomains.active}</span><small>active subdomains</small></div>
    <div class="metric"><span>${context.overview.alerts.open}</span><small>open alerts</small></div>
  </section>
  <section class="grid two">
    <div class="panel"><div class="panel-head"><span>OPS</span><div><h2>Daily operations</h2><p>Safe local controls and dry-run production planning.</p></div></div>
      <div class="cards">
        <a class="card compact" href="/?section=projects"><strong>Projects</strong><span>Create/edit/archive/delete planning and routing state.</span></a>
        <a class="card compact" href="/?section=applications"><strong>Applications</strong><span>Node, PHP, static, API and worker inventory.</span></a>
        <a class="card compact" href="/?section=domains"><strong>Domains</strong><span>Local subdomain planning and production dry-runs.</span></a>
        <a class="card compact" href="/?section=backups"><strong>Backups</strong><span>Manual backup and restore drill planning.</span></a>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><span>SEC</span><div><h2>Safety posture</h2><p>No live provider calls from this panel by default.</p></div></div>
      <ul class="status-list">
        <li><strong>Cloudflare</strong><span>plan-only until explicit apply and verifyRemote</span></li>
        <li><strong>Secrets</strong><span>never serialized to the client</span></li>
        <li><strong>Audit</strong><span>every Control Center action writes local audit</span></li>
        <li><strong>Production</strong><span>local evidence is never production evidence</span></li>
      </ul>
    </div>
  </section>`;
}

function renderProjects(projects) {
  return `<section class="panel"><div class="panel-head"><span>PRJ</span><div><h2>Projects</h2><p>Routing toggle is local and audited. Create/archive/delete are API planned.</p></div></div>
  <form class="inline-confirm project-create-form" method="post" action="/actions/project-command">
    <input type="hidden" name="action" value="create">
    <input name="slug" placeholder="project-slug" aria-label="Project slug">
    <input name="displayName" placeholder="Display name" aria-label="Project display name">
    <select name="runtime" aria-label="Default project runtime"><option value="node">Node.js</option><option value="php">PHP</option></select>
    <input name="host" placeholder="project.localhost.com" aria-label="Project host">
    <input type="hidden" name="confirm" value="CREATE-PROJECT">
    <button class="button enable" type="submit">Create project</button>
  </form>
  <div class="cards project-cards">${projects.map(renderProjectCard).join("") || empty("No projects", "No mounted projects found.")}</div></section>`;
}

function renderProjectCard(project) {
  const canRoute = project.filesystemExists !== false;
  return `<div id="project-${escapeHtml(project.slug)}" class="card project-card ${project.enabled ? "" : "is-off"}">
    <div class="card-title"><strong>${escapeHtml(project.name)}</strong><em>${escapeHtml(project.type)}</em></div>
    <span class="host">${escapeHtml(project.host)}</span>
    <span>${escapeHtml(project.summary)}</span>
    ${project.archivedAt ? `<span>Archived at ${escapeHtml(project.archivedAt)}</span>` : ""}
    ${canRoute ? "" : "<span>Routing waits for mounted source files.</span>"}
    <div class="project-actions">
      <span class="state ${project.enabled ? "on" : "off"}">${escapeHtml(humanName(project.status))}</span>
      ${project.enabled && canRoute ? `<a class="button open" href="${escapeHtml(project.href)}">Open</a>` : `<span class="button muted">Open</span>`}
      ${canRoute ? `<form method="post" action="/actions/toggle-project">
        <input type="hidden" name="slug" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="enabled" value="${project.enabled ? "0" : "1"}">
        <button class="button ${project.enabled ? "danger" : "enable"}" type="submit">${project.enabled ? "Disable" : "Enable"}</button>
      </form>` : '<span class="button muted">Enable</span>'}
      <form class="inline-confirm" method="post" action="/actions/project-command">
        <input type="hidden" name="slug" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="action" value="archive">
        <input name="confirm" value="" placeholder="ARCHIVE-PROJECT" aria-label="Archive confirmation for ${escapeHtml(project.slug)}">
        <button class="button danger" type="submit">Archive</button>
      </form>
      <form class="inline-confirm" method="post" action="/actions/project-command">
        <input type="hidden" name="slug" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="action" value="delete">
        <input name="confirm" value="" placeholder="DELETE-PROJECT:${escapeHtml(project.slug)}" aria-label="Delete confirmation for ${escapeHtml(project.slug)}">
        <button class="button danger" type="submit">Soft delete</button>
      </form>
    </div>
  </div>`;
}

function renderApplications(applications, projects, webspaces) {
  return `<section class="panel"><div class="panel-head"><span>APP</span><div><h2>Applications</h2><p>Create app records and lifecycle plans without touching Docker or project files from the browser.</p></div></div>
  <form method="post" action="/actions/application-command" class="inline-confirm app-create-form">
    <select name="projectId" aria-label="Project for application">${projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("")}</select>
    <input name="name" placeholder="app name" aria-label="Application name">
    <select name="runtime" aria-label="Runtime"><option value="node">Node.js</option><option value="php">PHP</option><option value="static">static site</option><option value="api">API backend</option><option value="worker">worker</option></select>
    <select name="webspaceId" aria-label="Linked web space"><option value="">no web space</option>${webspaces.map((space) => `<option value="${escapeHtml(space.id)}">${escapeHtml(space.projectId)}/${escapeHtml(space.name)}</option>`).join("")}</select>
    <input name="repositoryUrl" placeholder="git repo or folder ref" aria-label="Repository or folder reference">
    <input type="hidden" name="action" value="create">
    <input type="hidden" name="confirm" value="CREATE-APPLICATION">
    <button class="button enable" type="submit">Create app</button>
  </form>
  <div class="cards app-cards">${applications.map(renderApplicationCard).join("") || empty("No applications", "No Node, PHP, static, API or worker applications were discovered.")}</div></section>`;
}

function renderApplicationCard(app) {
  const actions = ["start", "stop", "restart", "deploy", "rollback"];
  return `<div id="app-${escapeHtml(app.id)}" class="card app-card">
    <div class="card-title"><strong>${escapeHtml(app.name)}</strong><em>${escapeHtml(app.runtime)}</em></div>
    <span class="host">${escapeHtml(app.host)}</span>
    <span>Healthcheck: ${escapeHtml(app.healthcheck)}</span>
    <span>${escapeHtml(app.source || "control-center-state")} / webspace ${escapeHtml(app.webspaceId || "not-linked")}</span>
    <div class="project-actions app-actions">
      <span class="state ${app.status === "online" ? "on" : "off"}">${escapeHtml(app.status)}</span>
      ${actions.map((action) => `<form method="post" action="/actions/application-command">
        <input type="hidden" name="id" value="${escapeHtml(app.id)}">
        <input type="hidden" name="action" value="${escapeHtml(action)}">
        <button class="button ${action === "stop" || action === "rollback" ? "danger" : action === "deploy" ? "enable" : ""}" type="submit">${escapeHtml(humanName(action))}</button>
      </form>`).join("")}
    </div>
  </div>`;
}

function renderDomains(domains, subdomains, projects) {
  return `<section class="grid two"><div class="panel"><div class="panel-head"><span>DNS</span><div><h2>Domains</h2><p>Local DNS is simulated; production domains remain metadata-only until Cloudflare verifyRemote passes.</p></div></div>
    <form method="post" action="/actions/subdomain-command" class="inline-confirm">
      <input type="hidden" name="action" value="create-domain">
      <input name="baseDomain" placeholder="example.com" aria-label="Base domain">
      <select name="environment" aria-label="Domain environment"><option value="local">local</option><option value="staging">staging</option><option value="production">production</option></select>
      <select name="visibility" aria-label="Domain visibility"><option value="public">public</option><option value="admin">admin</option><option value="private">private</option></select>
      <input name="providerConnectionId" placeholder="cloudflare" aria-label="Provider connection id">
      <input type="hidden" name="confirm" value="CREATE-DOMAIN">
      <button class="button enable" type="submit">Add domain</button>
    </form>
    <div class="cards">${domains.map(renderDomainCard).join("")}</div></div>
  <div class="panel"><div class="panel-head"><span>SUB</span><div><h2>Subdomains</h2><p>Local apply writes routing state only; production remains dry-run until explicit provider adapters verify remote evidence.</p></div></div>
    <form method="post" action="/actions/subdomain-command" class="inline-confirm">
      <select name="projectId" aria-label="Project for subdomain">${projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("")}</select>
      <input name="hostname" placeholder="preview.localhost.com" aria-label="Local hostname">
      <select name="visibility" aria-label="Visibility"><option value="public">public</option><option value="admin">admin</option><option value="private">private</option></select>
      <select name="protection" aria-label="Protection"><option value="none">none</option><option value="passkey">passkey</option><option value="cloudflare-access">cloudflare-access</option></select>
      <input type="hidden" name="action" value="apply-local">
      <button class="button enable" type="submit">Add local</button>
    </form>
    <div class="cards">${subdomains.map(renderSubdomainCard).join("") || empty("No subdomains", "Create a local subdomain to test routing without Cloudflare.")}</div></div></section>`;
}

function renderDomainCard(domain) {
  return `<div id="domain-${escapeHtml(domain.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(domain.baseDomain)}</strong><em>${escapeHtml(domain.environment)}</em></div>
    <span>DNS ${escapeHtml(domain.dnsStatus)} / TLS ${escapeHtml(domain.tlsStatus)}</span>
    <span>Cloudflare ${escapeHtml(domain.cloudflareStatus)} / provider ${escapeHtml(domain.providerConnectionId || "none")}</span>
    <span>${escapeHtml(domain.source || "control-center-state")} / production evidence ${domain.productionEvidence ? "yes" : "no"}</span>
  </div>`;
}

function renderSubdomainCard(item) {
  const removable = item.createdBy !== "control-center-discovery";
  return `<div id="subdomain-${escapeHtml(item.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(item.hostname)}</strong><em>${escapeHtml(item.visibility || "public")}</em></div>
    <span>${escapeHtml(item.type)} / ${escapeHtml(item.protection)} / ${escapeHtml(item.healthStatus)}</span>
    <span>DNS ${escapeHtml(item.dnsStatus || "unknown")} / TLS ${escapeHtml(item.tlsStatus || "unknown")}</span>
    <div class="project-actions">
      <form method="post" action="/actions/subdomain-command">
        <input type="hidden" name="id" value="${escapeHtml(item.id)}">
        <input type="hidden" name="action" value="verify">
        <button class="button" type="submit">Verify</button>
      </form>
      ${removable ? `<form method="post" action="/actions/subdomain-command" class="inline-confirm">
        <input type="hidden" name="id" value="${escapeHtml(item.id)}">
        <input type="hidden" name="action" value="remove">
        <input name="confirm" placeholder="REMOVE-SUBDOMAIN" aria-label="Remove confirmation for ${escapeHtml(item.hostname)}">
        <button class="button danger" type="submit">Remove</button>
      </form>` : `<span class="button muted">Discovered route</span>`}
    </div>
  </div>`;
}

function renderWebspaces(webspaces, projects) {
  return `<section class="panel"><div class="panel-head"><span>WEB</span><div><h2>Web Spaces</h2><p>Declarative folders only; secrets are excluded by policy.</p></div></div>
  <form method="post" action="/actions/webspace-command" class="inline-confirm">
    <select name="projectId" aria-label="Project for web space">${projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("")}</select>
    <input name="name" placeholder="space name" aria-label="Web space name">
    <input name="quotaBytes" placeholder="quota bytes" inputmode="numeric" aria-label="Quota bytes">
    <input type="hidden" name="action" value="create">
    <input type="hidden" name="confirm" value="CREATE-WEBSPACE">
    <button class="button enable" type="submit">Create space</button>
  </form>
  <div class="cards">${webspaces.map(renderWebspaceCard).join("") || empty("No web spaces", "Create a project web space to declare public/private/uploads/backups/config folders.")}</div></section>`;
}

function renderWebspaceCard(space) {
  return `<div id="webspace-${escapeHtml(space.id)}" class="card">
    <div class="card-title"><strong>${escapeHtml(space.name)}</strong><em>${escapeHtml(space.status)}</em></div>
    <span>${escapeHtml(space.basePath)}</span>
    <span>${bytesLabel(space.usedBytes)} used / quota ${bytesLabel(space.quotaBytes)}</span>
    <span>Folders: ${escapeHtml((space.mounts || []).join(", "))}</span>
    <form method="post" action="/actions/webspace-command" class="inline-confirm">
      <input type="hidden" name="id" value="${escapeHtml(space.id)}">
      <input type="hidden" name="action" value="quota">
      <input name="quotaBytes" value="${space.quotaBytes || 0}" inputmode="numeric" aria-label="Quota bytes for ${escapeHtml(space.id)}">
      <input type="hidden" name="confirm" value="UPDATE-QUOTA">
      <button class="button" type="submit">Set quota</button>
    </form>
  </div>`;
}

function renderResources(resources, projects) {
  const limits = resources.projectLimits || [];
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>RES</span><div><h2>Resources</h2><p>CPU, RAM and disk quota metadata per project. Runtime enforcement stays behind Docker adapters.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>CPU</strong><span>${escapeHtml(resources.cpu.status)} / ${escapeHtml(resources.cpu.summary)}</span></div>
        <div class="card compact"><strong>RAM</strong><span>${escapeHtml(resources.memory.status)} / ${escapeHtml(resources.memory.summary)}</span></div>
        <div class="card compact"><strong>Disk</strong><span>${escapeHtml(resources.disk.status)} / web spaces ${bytesLabel(resources.disk.webspacesBytes)}</span></div>
        <div class="card compact"><strong>Trend</strong><span>${escapeHtml(resources.trend)}</span></div>
      </div>
      <form method="post" action="/actions/resource-command" class="inline-confirm resource-form">
        <input type="hidden" name="action" value="limits">
        <select name="projectId" aria-label="Project for resource limits">${projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("")}</select>
        <input name="cpuMillicores" value="0" inputmode="numeric" aria-label="CPU millicores">
        <input name="memoryMb" value="0" inputmode="numeric" aria-label="Memory MB">
        <input name="diskMb" value="0" inputmode="numeric" aria-label="Disk MB">
        <input type="hidden" name="confirm" value="UPDATE-RESOURCE-LIMITS">
        <button class="button enable" type="submit">Set limits</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>QTA</span><div><h2>Quota per project</h2><p>Zero means unbounded metadata. No live container mutation is executed here.</p></div></div>
      <div class="cards">${limits.map(renderResourceLimitCard).join("") || empty("No resource limits", "Mount projects to create per-project resource cards.")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>RUN</span><div><h2>Containers</h2><p>Discovered application runtime state per project.</p></div></div>
      <div class="cards">${resources.containersByProject.map((item) => `<div class="card compact"><strong>${escapeHtml(item.projectId)}</strong><span>${escapeHtml(item.runtime)} / ${escapeHtml(item.status)}</span></div>`).join("") || empty("No containers", "No project applications were discovered.")}</div>
    </div>
  </section>`;
}

function renderResourceLimitCard(limit) {
  return `<div id="resources-${escapeHtml(limit.projectId)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(limit.projectId)}</strong><em>${escapeHtml(limit.status)}</em></div>
    <span>CPU ${limit.cpuMillicores}m / RAM ${limit.memoryMb} MB / Disk ${limit.diskMb} MB</span>
    <span>${escapeHtml(limit.updatedAt ? `updated ${limit.updatedAt}` : "no local quota metadata yet")}</span>
  </div>`;
}

function renderSecurity(security) {
  const policies = security.policies || [];
  const globalPolicy = policies.find((policy) => policy.scope === "global") || securityPolicyRecord({ scope: "global" });
  const selectOptions = (name, selected, values, label) => `<select name="${escapeHtml(name)}" aria-label="${escapeHtml(label)}">${values.map((value) => `<option value="${escapeHtml(value)}" ${selected === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}</select>`;
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>SEC</span><div><h2>Security</h2><p>Security posture is managed as local policy metadata unless a verified production adapter applies it.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>WAF</strong><span>${escapeHtml(security.waf)}</span></div>
        <div class="card compact"><strong>Rate limit</strong><span>${escapeHtml(security.rateLimit)}</span></div>
        <div class="card compact"><strong>Cloudflare Access</strong><span>${escapeHtml(security.cloudflareAccess)}</span></div>
        <div class="card compact"><strong>Admin Protection</strong><span>${escapeHtml(security.adminProtection)}</span></div>
        <div class="card compact"><strong>Security Headers</strong><span>${escapeHtml(security.securityHeaders)}</span></div>
        <div class="card compact"><strong>Passkey/Admin Auth</strong><span>${escapeHtml(security.passkeyAdminAuth)}</span></div>
      </div>
      <form method="post" action="/actions/security-command" class="inline-confirm security-form">
        <input type="hidden" name="action" value="policy">
        <input name="scope" value="${escapeHtml(globalPolicy.scope)}" aria-label="Security policy scope">
        ${selectOptions("wafMode", globalPolicy.wafMode, ["configured", "monitor", "blocking", "disabled"], "WAF mode")}
        ${selectOptions("rateLimitTier", globalPolicy.rateLimitTier, ["configured", "standard", "strict", "disabled"], "Rate limit tier")}
        ${selectOptions("adminProtection", globalPolicy.adminProtection, ["local-only", "required", "cloudflare-access", "vpn-required"], "Admin protection")}
        ${selectOptions("securityHeaders", globalPolicy.securityHeaders, ["configured", "strict", "report-only", "disabled"], "Security headers")}
        ${selectOptions("cloudflareAccess", globalPolicy.cloudflareAccess, ["plan-only-local", "requires-verify-remote", "configured"], "Cloudflare Access status")}
        ${selectOptions("passkeyAdminAuth", globalPolicy.passkeyAdminAuth, ["available-through-stexor-account-app", "required", "not-configured"], "Passkey admin auth")}
        <input type="hidden" name="confirm" value="UPDATE-SECURITY-POLICY">
        <button class="button enable" type="submit">Update policy</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>POL</span><div><h2>Policy Records</h2><p>Provider changes stay plan-only until explicit production adapters verify remote evidence.</p></div></div>
      <div class="cards">${policies.map(renderSecurityPolicyCard).join("") || empty("No security policies", "Update the global policy to create local metadata.")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>AUD</span><div><h2>Recent Security Audit</h2><p>Filtered Control Center security, auth and admin events.</p></div></div>
      ${security.recentAuditEvents?.length ? `<div class="cards">${security.recentAuditEvents.map((event) => `<div class="card compact"><strong>${escapeHtml(event.action || "event")}</strong><span>${escapeHtml(`${event.timestamp || ""} / ${event.result || "unknown"}`)}</span></div>`).join("")}</div>` : empty("No security events", "Security policy and admin auth events will appear here after activity.")}
    </div>
  </section>`;
}

function renderSecurityPolicyCard(policy) {
  return `<div id="security-${escapeHtml(policy.scope)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(policy.scope)}</strong><em>${escapeHtml(policy.status)}</em></div>
    <span>WAF ${escapeHtml(policy.wafMode)} / Rate ${escapeHtml(policy.rateLimitTier)} / Admin ${escapeHtml(policy.adminProtection)}</span>
    <span>Headers ${escapeHtml(policy.securityHeaders)} / Access ${escapeHtml(policy.cloudflareAccess)} / Auth ${escapeHtml(policy.passkeyAdminAuth)}</span>
    <span>${escapeHtml(policy.updatedAt ? `updated ${policy.updatedAt}` : policy.source || "control-center-default")}</span>
  </div>`;
}

function renderSettings(context) {
  const settings = context.settings || settingsRecord();
  const optionList = (name, selected, values, label) => `<select name="${escapeHtml(name)}" aria-label="${escapeHtml(label)}">${values.map((value) => `<option value="${escapeHtml(value)}" ${selected === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}</select>`;
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>SET</span><div><h2>Settings</h2><p>Local preferences and connection statuses. Tokens stay in Docker secrets and provider changes stay behind explicit adapters.</p></div></div>
      <ul class="status-list">
        <li><strong>Environment</strong><span>${escapeHtml(settings.environmentMode)}</span></li>
        <li><strong>Base domain</strong><span>${escapeHtml(settings.baseDomain)}</span></li>
        <li><strong>Cloudflare connection</strong><span>${escapeHtml(settings.cloudflareConnectionStatus)}</span></li>
        <li><strong>GitHub connection</strong><span>${escapeHtml(settings.githubConnectionStatus)}</span></li>
        <li><strong>SMTP/alert status</strong><span>${escapeHtml(settings.smtpAlertStatus)}</span></li>
        <li><strong>Default mode</strong><span>${escapeHtml(settings.preferredMode)}</span></li>
      </ul>
      <form id="settings-local" method="post" action="/actions/settings-command" class="inline-confirm settings-form">
        <input type="hidden" name="action" value="update">
        ${optionList("preferredMode", settings.preferredMode, ["simple", "advanced"], "Default mode preference")}
        ${optionList("environmentMode", settings.environmentMode, ["local", "staging", "production"], "Environment mode")}
        <input name="baseDomain" value="${escapeHtml(settings.baseDomain)}" aria-label="Base domain">
        ${optionList("cloudflareConnectionStatus", settings.cloudflareConnectionStatus, ["not-configured", "plan-only-local", "requires-verify-remote", "configured"], "Cloudflare connection status")}
        ${optionList("githubConnectionStatus", settings.githubConnectionStatus, ["not-configured", "dry-run", "requires-verify", "configured"], "GitHub connection status")}
        ${optionList("smtpAlertStatus", settings.smtpAlertStatus, ["not-configured", "requires-secret-file", "configured", "disabled", "verified-production"], "SMTP alert status")}
        <input type="hidden" name="confirm" value="UPDATE-SETTINGS">
        <button class="button enable" type="submit">Update settings</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>SAFE</span><div><h2>Production Guard</h2><p>Changing this metadata does not mutate Compose, DNS, Cloudflare, GitHub or SMTP.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Runtime env</strong><span>${escapeHtml(environment)}</span></div>
        <div class="card compact"><strong>Preference source</strong><span>${escapeHtml(settings.source)}</span></div>
        <div class="card compact"><strong>Production guard</strong><span>${escapeHtml(settings.productionGuard)}</span></div>
        <div class="card compact"><strong>Provider touched</strong><span>${settings.providerTouched ? "yes" : "no"}</span></div>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><span>CON</span><div><h2>Provider Connections</h2><p>Connection metadata only. Tokens and provider credentials stay in Docker secrets or private ops material.</p></div></div>
      <div class="cards">${(context.providerConnections || []).map(renderProviderConnectionCard).join("")}</div>
      <form method="post" action="/actions/settings-command" class="inline-confirm settings-form">
        <input type="hidden" name="action" value="provider-connection">
        <select name="id" aria-label="Provider connection">${(context.providerConnections || []).map((connection) => `<option value="${escapeHtml(connection.id)}">${escapeHtml(connection.name)}</option>`).join("")}</select>
        ${optionList("status", "metadata-only", ["not-configured", "metadata-only", "requires-secret-file", "requires-verify-remote", "configured", "verified-production"], "Provider connection status")}
        <input name="accountLabel" placeholder="account or zone label" aria-label="Account or zone label">
        <input name="scope" placeholder="scope" aria-label="Provider scope">
        <input type="hidden" name="confirm" value="UPDATE-PROVIDER-CONNECTION">
        <button class="button enable" type="submit">Update connection</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>DOC</span><div><h2>Documentation</h2><p>${context.docsAvailable} local docs</p></div></div>${renderDocs()}</div>
  </section>`;
}

function renderProviderConnectionCard(connection) {
  return `<div id="provider-${escapeHtml(connection.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(connection.name)}</strong><em>${escapeHtml(connection.status)}</em></div>
    <span>${escapeHtml(connection.provider)} / ${escapeHtml(connection.environment)} / ${escapeHtml(connection.scope || "global")}</span>
    <span>${escapeHtml(connection.accountLabel || "no account label")} / material ${escapeHtml(connection.privateMaterialConfigured ? "configured" : "not configured")}</span>
    <span>verified ${escapeHtml(connection.lastVerifiedAt || "never")} / production evidence ${connection.productionEvidence ? "yes" : "no"}</span>
  </div>`;
}

function renderDocs() {
  return Object.entries(docs).map(([group, items]) => `<h3>${escapeHtml(group)}</h3><div class="cards">${items.map(([docPath, description]) => {
    const exists = existsSync(safeDocPath(docPath));
    return `<a class="card compact ${exists ? "" : "disabled"}" href="#"><strong>${escapeHtml(path.basename(docPath))}</strong><span>${escapeHtml(description)}</span></a>`;
  }).join("")}</div>`).join("");
}

function renderInfrastructure(services) {
  return `<section class="panel"><div class="panel-head"><span>INF</span><div><h2>Infrastructure</h2><p>Enterprise service map. Mutations stay behind backend adapters and confirmation.</p></div></div><div class="cards">${services.map((service) => `<div class="card compact"><strong>${escapeHtml(service.name)}</strong><span>${escapeHtml(service.role)} / ${escapeHtml(service.status)}</span></div>`).join("")}</div></section>`;
}

function renderDeployments(deployments) {
  return `<section class="panel"><div class="panel-head"><span>DEP</span><div><h2>Deployments</h2><p>Local deployment records are plan evidence only until production verifyRemote passes.</p></div></div>${deployments.length ? `<div class="cards">${deployments.slice(0, 24).map((deployment) => `<div class="card compact"><strong>${escapeHtml(`${deployment.action} / ${deployment.applicationId}`)}</strong><span>${escapeHtml(`${deployment.createdAt} / ${deployment.status} / ${deployment.environment}`)}</span><span>${escapeHtml(`branch ${deployment.branch} / commit ${deployment.commit}`)}</span></div>`).join("")}</div>` : empty("No deployments", "Deploy and rollback plans will appear here after you run them from Applications.")}</section>`;
}

function renderDatabases(databases, engines, projects) {
  const projectOptions = projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("");
  const engineOptions = engines.map((engine) => `<option value="${escapeHtml(engine.id)}">${escapeHtml(engine.name)}</option>`).join("");
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>DB</span><div><h2>Databases</h2><p>Database inventory and plans are metadata-only until a live DatabaseAdapter is explicitly enabled.</p></div></div>
      <div class="cards">
        ${engines.map((engine) => `<div class="card compact"><strong>${escapeHtml(engine.name)}</strong><span>${escapeHtml(engine.service)} / ${escapeHtml(engine.status)} / production evidence ${engine.productionEvidence ? "yes" : "no"}</span></div>`).join("")}
      </div>
      <form method="post" action="/actions/database-command" class="inline-confirm database-form">
        <input type="hidden" name="action" value="create">
        <select name="projectId" aria-label="Database project">${projectOptions}</select>
        <select name="engine" aria-label="Database engine">${engineOptions}</select>
        <input name="name" value="app_db" aria-label="Database name">
        <input name="ownerRole" value="app_user" aria-label="Owner role">
        <input type="hidden" name="confirm" value="CREATE-DATABASE">
        <button class="button enable" type="submit">Declare database</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>INV</span><div><h2>Database Inventory</h2><p>Create/backup/restore controls write audited plans and never expose credentials.</p></div></div>
      ${databases.length ? `<div class="cards">${databases.map(renderDatabaseCard).join("")}</div>` : empty("No databases declared", "Declare a project database to track backup and restore plans from the Control Center.")}
    </div>
  </section>`;
}

function renderDatabaseCard(database) {
  return `<div id="database-${escapeHtml(database.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(database.name)}</strong><em>${escapeHtml(database.engine)}</em></div>
    <span>${escapeHtml(database.projectId)} / ${escapeHtml(database.status)} / ${escapeHtml(database.connectionStatus)}</span>
    <span>size ${escapeHtml(String(database.sizeBytes))} bytes / slow queries ${escapeHtml(database.slowQueries)}</span>
    <form method="post" action="/actions/database-command" class="inline-confirm">
      <input type="hidden" name="action" value="backup">
      <input type="hidden" name="id" value="${escapeHtml(database.id)}">
      <button class="button enable" type="submit">Plan backup</button>
    </form>
    <form method="post" action="/actions/database-command" class="inline-confirm">
      <input type="hidden" name="action" value="restore">
      <input type="hidden" name="id" value="${escapeHtml(database.id)}">
      <input name="backupRef" value="latest" aria-label="Backup reference">
      <button class="button danger" type="submit">Plan restore</button>
    </form>
  </div>`;
}

function renderBackups(summary, records) {
  const latest = records.slice(0, 24);
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>BKP</span><div><h2>Backups</h2><p>Manual backup and restore drill controls create safe local operation plans.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Manual backup</strong><span>${escapeHtml(summary.manualBackup)}</span></div>
        <div class="card compact"><strong>Restore drill</strong><span>${escapeHtml(summary.restoreDrill)}</span></div>
        <div class="card compact"><strong>Off-site</strong><span>${escapeHtml(summary.offsite)}</span></div>
        <div class="card compact"><strong>RPO/RTO</strong><span>${escapeHtml(summary.rpoRto)}</span></div>
      </div>
      <form method="post" action="/actions/backup-command" class="inline-confirm backup-form">
        <input type="hidden" name="action" value="backup">
        <input name="scope" value="all" aria-label="Backup scope">
        <button class="button enable" type="submit">Plan manual backup</button>
      </form>
      <form method="post" action="/actions/backup-command" class="inline-confirm backup-form">
        <input type="hidden" name="action" value="restore">
        <input name="scope" value="all" aria-label="Restore scope">
        <input name="backupRef" value="latest" aria-label="Backup reference">
        <button class="button danger" type="submit">Plan restore drill</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>HIS</span><div><h2>Backup History</h2><p>Local records are plan evidence, not production restore proof.</p></div></div>
      ${latest.length ? `<div class="cards">${latest.map(renderBackupRecord).join("")}</div>` : empty("No backup records", "Plan a manual backup or restore drill to create a local audit record.")}
    </div>
  </section>`;
}

function renderBackupRecord(record) {
  return `<div id="backup-${escapeHtml(record.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(humanName(record.action))}</strong><em>${escapeHtml(record.status)}</em></div>
    <span>${escapeHtml(record.scope)} / ${escapeHtml(record.environment)} / ${record.dryRun ? "dry-run" : "accepted"}</span>
    <span>${escapeHtml(record.createdAt)} / off-site ${escapeHtml(record.offsite)}</span>
    <span>${escapeHtml(record.resultSummary)}</span>
  </div>`;
}

function renderLogsAlerts(logsAlerts) {
  const openAlerts = logsAlerts.openAlerts || [];
  const recentErrors = logsAlerts.recentErrors || [];
  const channels = logsAlerts.notificationChannels || [];
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>LOG</span><div><h2>Logs / Alerts</h2><p>Minimal operational view. Raw internal consoles stay off the public Projects surface.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Open alerts</strong><span>${openAlerts.length} active local records</span></div>
        <div class="card compact"><strong>Recent errors</strong><span>${recentErrors.length} failed operations or audit events</span></div>
        <div class="card compact"><strong>Detailed logs</strong><span>${escapeHtml(logsAlerts.detailedLogs)}</span></div>
        <div class="card compact"><strong>Alert routing</strong><span>${escapeHtml(logsAlerts.alertRouting)}</span></div>
      </div>
      <form method="post" action="/actions/alert-command" class="inline-confirm alert-form">
        <input type="hidden" name="action" value="record">
        <input name="service" value="platform" aria-label="Alert service">
        <select name="severity" aria-label="Alert severity"><option value="info">info</option><option value="warning" selected>warning</option><option value="critical">critical</option></select>
        <input name="summary" value="note" aria-label="Alert summary">
        <input type="hidden" name="confirm" value="RECORD-ALERT">
        <button class="button enable" type="submit">Record alert</button>
      </form>
      <form method="post" action="/actions/alert-command" class="inline-confirm alert-form">
        <input type="hidden" name="action" value="channel">
        <select name="channel" aria-label="Notification channel"><option value="email">email</option><option value="discord">discord</option><option value="telegram">telegram</option></select>
        <select name="status" aria-label="Notification status"><option value="not-configured">not-configured</option><option value="requires-secret-file">requires-secret-file</option><option value="configured">configured</option><option value="disabled">disabled</option><option value="verified-production">verified-production</option></select>
        <select name="deliveryMode" aria-label="Delivery mode"><option value="local-metadata">local-metadata</option><option value="secret-file">secret-file</option><option value="provider-verified">provider-verified</option></select>
        <input type="hidden" name="confirm" value="UPDATE-NOTIFICATION-CHANNEL">
        <button class="button" type="submit">Update channel</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>ALT</span><div><h2>Open Alerts</h2><p>${escapeHtml(logsAlerts.rawConsoles)}</p></div></div>
      ${openAlerts.length ? `<div class="cards">${openAlerts.map(renderAlertCard).join("")}</div>` : empty("No open alerts", "Record a local alert or run alert evidence tooling to create operational context.")}
    </div>
    <div class="panel"><div class="panel-head"><span>MET</span><div><h2>Notification Channels</h2><p>Email, Discord and Telegram status without exposing webhook or token values.</p></div></div>
      <div class="cards">${channels.map(renderNotificationChannelCard).join("")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>ERR</span><div><h2>Recent Errors</h2><p>Sanitized failed operations and audit failures.</p></div></div>
      ${recentErrors.length ? `<div class="cards">${recentErrors.map((item) => `<div class="card compact"><strong>${escapeHtml(item.source)}</strong><span>${escapeHtml(`${item.timestamp} / ${item.name}`)}</span><span>${escapeHtml(item.summary)}</span></div>`).join("")}</div>` : empty("No recent errors", "No failed Control Center operations or audited failures were found.")}
    </div>
  </section>`;
}

function renderAlertCard(alert) {
  return `<div id="alert-${escapeHtml(alert.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(alert.service)}</strong><em>${escapeHtml(alert.severity)}</em></div>
    <span>${escapeHtml(alert.summary)}</span>
    <span>${escapeHtml(alert.status)} / ${escapeHtml(alert.createdAt || "local metadata")}</span>
    <form method="post" action="/actions/alert-command" class="inline-confirm">
      <input type="hidden" name="action" value="resolve">
      <input type="hidden" name="id" value="${escapeHtml(alert.id)}">
      <input type="hidden" name="confirm" value="RESOLVE-ALERT">
      <button class="button" type="submit">Resolve</button>
    </form>
  </div>`;
}

function renderNotificationChannelCard(channel) {
  return `<div id="channel-${escapeHtml(channel.channel)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(humanName(channel.channel))}</strong><em>${escapeHtml(channel.status)}</em></div>
    <span>${escapeHtml(channel.deliveryMode)} / ${escapeHtml(channel.source)}</span>
    <span>${escapeHtml(channel.updatedAt ? `updated ${channel.updatedAt}` : "no local override")}</span>
  </div>`;
}

function renderAdvancedPanel(title, section, context, note = "Advanced control is dry-run/plan by default in this foundation.") {
  const items = advancedItems(section);
  const statusCards = [
    ["Environment", context.environment],
    ["Evidence mode", context.overview.modeEvidence],
    ["Provider apply", "requires explicit adapter and confirmation"],
    ["Production proof", "requires verifyRemote before evidence is accepted"],
  ];
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>ADV</span><div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(note)}</p></div></div>
      <div class="cards">${items.map((item) => `<div class="card compact"><strong>${escapeHtml(item)}</strong><span>planned adapter surface</span></div>`).join("")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>GATE</span><div><h2>Execution Guardrails</h2><p>No live provider, Docker or destructive operation is executed from this skeleton.</p></div></div>
      <div class="cards">${statusCards.map(([name, value]) => `<div class="card compact"><strong>${escapeHtml(name)}</strong><span>${escapeHtml(value)}</span></div>`).join("")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>EVD</span><div><h2>Evidence Path</h2><p>Use containerized infra-ops commands for live proof, then surface sanitized summaries here.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Audit</strong><span>${context.audit.length} recent Control Center events available.</span></div>
        <div class="card compact"><strong>Operations</strong><span>${context.operations.length} local operation records available.</span></div>
        <div class="card compact"><strong>Deployments</strong><span>${context.deployments.length} deployment records available.</span></div>
        <div class="card compact"><strong>Alerts</strong><span>${context.logsAlerts.openAlerts.length} open local alert records.</span></div>
      </div>
    </div>
  </section>`;
}

function renderPlanOnlyPanel(title, items) {
  return `<section class="panel"><div class="panel-head"><span>ADV</span><div><h2>${escapeHtml(title)}</h2><p>Advanced control is dry-run/plan by default in this foundation.</p></div></div><div class="cards">${items.map((item) => `<div class="card compact"><strong>${escapeHtml(item)}</strong><span>planned adapter surface</span></div>`).join("")}</div></section>`;
}

function renderJsonPanel(title, data) {
  return `<section class="panel"><div class="panel-head"><span>SUM</span><div><h2>${escapeHtml(title)}</h2><p>Sanitized local summary.</p></div></div><pre class="json-block">${escapeHtml(JSON.stringify(data, null, 2))}</pre></section>`;
}

function renderAudit(audit, title) {
  return `<section class="panel"><div class="panel-head"><span>AUD</span><div><h2>${escapeHtml(title)}</h2><p>Control Center events are append-only JSON lines in local state.</p></div></div>${audit.length ? `<div class="cards">${audit.slice(0, 12).map((event) => `<div class="card compact"><strong>${escapeHtml(event.action || "event")}</strong><span>${escapeHtml(`${event.timestamp || ""} / ${event.result || "unknown"}`)}</span></div>`).join("")}</div>` : empty("No events", "No Control Center action has been audited yet.")}</section>`;
}

function planProjectCreate(payload, context) {
  const slug = slugify(payload.slug || payload.name || "");
  validateSlug(slug);
  if (context.projects.some((project) => project.slug === slug)) throw new ValidationError("Project already exists.");
  const displayName = sanitizeDisplayName(payload.displayName || payload.name || humanName(slug));
  const runtime = choice(String(payload.runtime || "node").toLowerCase(), ["node", "php"], "runtime");
  const host = normalizeHost(payload.host || `${slug}${hostSuffix}`);
  validateHostname(host, context.environment);
  const details = {
    projectId: slug,
    displayName,
    runtime,
    type: runtime === "php" ? "PHP" : "Node",
    host,
    source: "control-center-state",
    filesystemExists: false,
    filesystemTouched: false,
    dockerTouched: false,
    databaseTouched: false,
    providerTouched: false,
    productionEvidence: false,
  };
  if (payload.confirm === "CREATE-PROJECT") {
    const state = readState();
    state.projects[slug] = {
      ...(state.projects[slug] || {}),
      declaredProject: true,
      displayName,
      runtime,
      host,
      enabled: false,
      source: "control-center-state",
      filesystemExists: false,
      filesystemTouched: false,
      dockerTouched: false,
      databaseTouched: false,
      providerTouched: false,
      productionEvidence: false,
      createdAt: state.projects[slug]?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    writeState(state);
    appendAudit({ action: "project.create.apply", target: slug, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Project metadata declared locally; no filesystem, database, Docker or provider changes applied." });
    const operation = operationPlan("project.create.local", context.environment, false, ["validate slug", "create local project metadata", "leave filesystem untouched", "leave Docker and providers unchanged", "write audit event"], details);
    return { ...operation, project: { id: slug, slug, name: displayName, status: "declared", enabled: false, ...details } };
  }
  appendAudit({ action: "project.create.plan", target: slug, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Project creation plan generated; no filesystem changes applied." });
  return operationPlan("project.create", context.environment, true, ["validate slug", "prepare project metadata", "require apply confirmation", "leave filesystem untouched", "write audit event"], { ...details, confirmationRequired: "CREATE-PROJECT" });
}

function planOrApplyProjectUpdate(id, payload, context) {
  const project = findById(context.projects, id, "Project");
  const displayName = sanitizeDisplayName(payload.displayName || payload.name || project.name);
  const details = { projectId: project.slug, displayName };
  if (payload.confirm !== "UPDATE-PROJECT") {
    appendAudit({ action: "project.update.plan", target: project.slug, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Project metadata update plan generated." });
    return operationPlan("project.update", context.environment, true, ["validate project", "validate metadata", "prepare local state update", "write audit event"], details);
  }
  const state = readState();
  state.projects[project.slug] = {
    ...(state.projects[project.slug] || {}),
    displayName,
    updatedAt: new Date().toISOString(),
  };
  writeState(state);
  appendAudit({ action: "project.update.apply", target: project.slug, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Project display metadata updated in local Control Center state." });
  return operationPlan("project.update.local", context.environment, false, ["validate project", "update local project metadata", "write audit event"], details);
}

function planProjectArchive(id, context) {
  const project = findById(context.projects, id, "Project");
  appendAudit({ action: "project.archive.plan", target: project.slug, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Project archive plan generated; no filesystem changes applied." });
  return operationPlan("project.archive", context.environment, true, ["validate project", "disable local routing", "mark project archived", "preserve filesystem and audit trail", "write audit event"], { projectId: project.slug, confirmationRequired: "ARCHIVE-PROJECT" });
}

function applyProjectArchive(id, payload, context) {
  const project = findById(context.projects, id, "Project");
  if (payload.confirm !== "ARCHIVE-PROJECT") throw new RejectedOperationError("Project archive requires confirm=ARCHIVE-PROJECT.");
  const state = readState();
  state.projects[project.slug] = {
    ...(state.projects[project.slug] || {}),
    enabled: false,
    archivedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  writeState(state);
  appendAudit({ action: "project.archive.apply", target: project.slug, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Project archived in local Control Center state; project files were not deleted." });
  return operationPlan("project.archive.local", context.environment, false, ["validate confirmation", "disable local routing", "mark project archived", "preserve filesystem", "write audit event"], { projectId: project.slug, filesystemTouched: false });
}

function planProjectDelete(id, context) {
  const project = findById(context.projects, id, "Project");
  appendAudit({ action: "project.delete.plan", target: project.slug, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Project delete plan generated; local foundation only supports soft delete from inventory." });
  return operationPlan("project.delete", context.environment, true, ["validate project", "require strong confirmation", "soft delete from Control Center inventory", "preserve filesystem and databases", "write audit event"], { projectId: project.slug, confirmationRequired: `DELETE-PROJECT:${project.slug}`, filesystemTouched: false });
}

function applyProjectDelete(id, payload, context) {
  const project = findById(context.projects, id, "Project");
  const expected = `DELETE-PROJECT:${project.slug}`;
  if (payload.confirm !== expected) throw new RejectedOperationError(`Project soft delete requires confirm=${expected}.`);
  const state = readState();
  state.projects[project.slug] = {
    ...(state.projects[project.slug] || {}),
    enabled: false,
    deletedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  writeState(state);
  appendAudit({ action: "project.delete.apply", target: project.slug, environment: context.environment, risk: "high", result: "success", dryRun: false, summary: "Project soft deleted from local Control Center inventory; project files and databases were not deleted." });
  return operationPlan("project.delete.local", context.environment, false, ["validate strong confirmation", "soft delete local inventory entry", "disable local routing", "preserve filesystem and databases", "write audit event"], { projectId: project.slug, filesystemTouched: false, databaseTouched: false });
}

function planApplicationCreate(payload, context) {
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const runtime = choice(String(payload.runtime || ""), ["node", "php", "static", "api", "worker"], "runtime");
  const name = slugify(payload.name || payload.id || runtime);
  validateSlug(name);
  const id = sanitizeIdentifier(payload.id || `${projectId}-${name}`);
  validateSlug(id);
  if (context.applications.some((app) => app.id === id)) throw new ValidationError("Application already exists.");
  const webspaceId = slugify(payload.webspaceId || "");
  if (webspaceId) {
    const space = findById(context.webspaces, webspaceId, "Webspace");
    if (space.projectId !== projectId) throw new ValidationError("Application webspace must belong to the selected project.");
  }
  const host = normalizeHost(payload.host || `${id}${hostSuffix}`);
  validateHostname(host, context.environment);
  const details = applicationRecord({
    id,
    projectId,
    name: sanitizeDisplayName(payload.displayName || humanName(payload.name || name)),
    runtime,
    kind: applicationKind(runtime, payload.kind),
    host,
    status: "declared",
    healthcheck: `https://${host}/`,
    repositoryUrl: sanitizeOptionalRef(payload.repositoryUrl || payload.repository || payload.sourceRef || ""),
    webspaceId,
    source: "control-center-state",
  });
  if (payload.confirm === "CREATE-APPLICATION") {
    const state = readApplicationsState();
    state[id] = { ...(state[id] || {}), ...details, createdAt: state[id]?.createdAt || new Date().toISOString(), updatedAt: new Date().toISOString() };
    writeApplicationsState(state);
    appendAudit({ action: "application.create.apply", target: id, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Application metadata declared locally; no files, containers or providers were changed." });
    const operation = operationPlan("application.create.local", context.environment, false, ["validate project", "validate runtime", "link repository or webspace metadata", "create healthcheck metadata", "write audit event"], { ...details, filesystemTouched: false, dockerTouched: false, providerTouched: false, productionEvidence: false });
    return { ...operation, application: state[id] };
  }
  appendAudit({ action: "application.create.plan", target: id, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Application creation plan generated." });
  return operationPlan("application.create", context.environment, true, ["validate project", "validate runtime", "link repository or webspace metadata", "create healthcheck metadata", "prepare route plan", "write audit event"], { ...details, filesystemTouched: false, dockerTouched: false, providerTouched: false, productionEvidence: false, confirmationRequired: "CREATE-APPLICATION" });
}

function planApplicationLifecycle(id, action, payload, context) {
  if (!["start", "stop", "restart", "deploy", "rollback"].includes(action)) throw new ValidationError("Unsupported lifecycle action.");
  const app = findById(context.applications, id, "Application");
  if (action === "deploy" || action === "rollback") return planApplicationDeployment(app, action, payload, context);
  appendAudit({ action: `application.${action}.plan`, target: sanitizeIdentifier(id), environment: context.environment, risk: action === "stop" ? "medium" : "low", result: "planned", dryRun: true, summary: "Lifecycle action planned; no container command executed." });
  return operationPlan(`application.${action}`, context.environment, true, ["validate application", "check current health", "prepare Docker adapter command", "require confirmation for apply", "write audit event"], { projectId: app.projectId, applicationId: app.id });
}

function planApplicationDeployment(app, action, payload, context) {
  const deploymentId = rid();
  const branch = sanitizeRef(payload.branch || "local");
  const commit = sanitizeRef(payload.commit || "unresolved-local");
  const rollbackTarget = sanitizeRef(payload.rollbackTarget || "previous-approved-release");
  const risk = action === "rollback" ? "high" : "medium";
  appendAudit({ action: `application.${action}.plan`, target: app.id, environment: context.environment, risk, result: "planned", dryRun: true, summary: `${humanName(action)} plan generated; no image build, container update or provider call executed.` });
  const operation = operationPlan(`application.${action}`, context.environment, true, deploymentSteps(action), {
    projectId: app.projectId,
    applicationId: app.id,
    deploymentId,
    branch,
    commit,
    rollbackTarget,
    productionEvidence: false,
  });
  const deployment = sanitizeEvent({
    id: deploymentId,
    operationId: operation.id,
    projectId: app.projectId,
    applicationId: app.id,
    environment: context.environment,
    action,
    status: "planned",
    branch,
    commit,
    imageDigest: "not-built",
    sbom: "required-before-production",
    provenance: "required-before-production",
    rollbackTarget,
    productionApproval: "required-for-production",
    releaseEvidence: "local-plan-only",
    dryRun: true,
    createdAt: new Date().toISOString(),
  });
  appendDeployment(deployment);
  return { ...operation, deployment };
}

function planDomainCreate(payload, context) {
  const targetEnv = normalizeEnvironment(payload.environment || context.environment);
  const baseDomain = validateBaseDomain(payload.baseDomain || "");
  if (targetEnv === "production" && /(?:^|\.)localhost(?:\.com)?$/i.test(baseDomain)) {
    throw new ValidationError("Production domain metadata requires a real domain, not localhost.");
  }
  const id = sanitizeIdentifier(payload.id || `${targetEnv}-${baseDomain.replace(/\./g, "-")}`);
  validateSlug(id);
  if (context.domains.some((domain) => domain.id === id || domain.baseDomain === baseDomain)) throw new ValidationError("Domain already exists.");
  const visibility = choice(payload.visibility || "public", ["public", "admin", "private"], "visibility");
  const providerConnectionId = sanitizeIdentifier(payload.providerConnectionId || (targetEnv === "production" ? "cloudflare" : ""));
  if (providerConnectionId) findById(context.providerConnections, providerConnectionId, "Provider connection");
  const details = domainRecord({
    id,
    environment: targetEnv,
    baseDomain,
    visibility,
    providerConnectionId,
    dnsStatus: targetEnv === "local" ? "local-hosts-or-resolver" : "requires-verify-remote",
    tlsStatus: targetEnv === "local" ? "local-certificate" : "requires-https-verify",
    cloudflareStatus: providerConnectionId === "cloudflare" ? "metadata-only-requires-verify" : "not-linked",
    source: "control-center-state",
  });
  if (payload.confirm === "CREATE-DOMAIN") {
    const state = readDomainsState();
    state[id] = { ...(state[id] || {}), ...details, createdAt: state[id]?.createdAt || new Date().toISOString(), updatedAt: new Date().toISOString() };
    writeDomainsState(state);
    appendAudit({ action: "domain.create.apply", target: baseDomain, environment: targetEnv, risk: targetEnv === "production" ? "medium" : "low", result: "success", dryRun: false, summary: "Domain metadata declared locally; no DNS, TLS, Traefik or Cloudflare changes applied." });
    const operation = operationPlan("domain.create.local", targetEnv, false, ["validate domain", "validate provider metadata", "record local domain metadata", "leave DNS/TLS/providers unchanged", "write audit event"], { ...state[id], dnsTouched: false, tlsTouched: false, traefikTouched: false, providerTouched: false, productionEvidence: false });
    return { ...operation, domain: state[id] };
  }
  appendAudit({ action: "domain.create.plan", target: baseDomain, environment: targetEnv, risk: targetEnv === "production" ? "medium" : "low", result: "planned", dryRun: true, summary: "Domain metadata creation plan generated." });
  return operationPlan("domain.create", targetEnv, true, ["validate domain", "validate provider metadata", "prepare local domain metadata", "require apply confirmation", "write audit event"], { ...details, dnsTouched: false, tlsTouched: false, traefikTouched: false, providerTouched: false, productionEvidence: false, confirmationRequired: "CREATE-DOMAIN" });
}

function planSubdomain(payload, context) {
  const targetEnv = normalizeEnvironment(payload.environment || context.environment);
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const hostname = subdomainHostname(payload, targetEnv);
  validateHostname(hostname, targetEnv);
  const visibility = choice(payload.visibility || "public", ["public", "admin", "private"], "visibility");
  const protection = choice(payload.protection || "none", ["none", "passkey", "cloudflare-access"], "protection");
  appendAudit({ action: "subdomain.plan", target: hostname, environment: targetEnv, risk: targetEnv === "production" ? "high" : "low", result: "planned", dryRun: true, summary: "Subdomain plan generated without live provider calls." });
  const steps = targetEnv === "production"
    ? ["validate hostname", "prepare Cloudflare DNS record", "prepare Traefik route", "prepare TLS/proxy settings", "prepare Access/WAF policy", "verifyRemote after apply"]
    : ["validate hostname", "use local wildcard route", "link project/app", "mark TLS as local certificate", "write audit event"];
  return operationPlan("subdomain.plan", targetEnv, true, steps, { hostname, projectId, visibility, protection, productionEvidence: false });
}

function applySubdomain(payload, context) {
  const plan = planSubdomain(payload, context);
  if (plan.environment === "production") {
    if (payload.confirm !== "APPLY-PRODUCTION") throw new RejectedOperationError("Production apply requires confirm=APPLY-PRODUCTION and verified provider secrets.");
    throw new RejectedOperationError("Production apply is disabled in local Control Center foundation; use the backend Cloudflare adapter with verifyRemote.");
  }
  if (payload.confirm !== "APPLY-LOCAL") throw new RejectedOperationError("Local apply requires confirm=APPLY-LOCAL.");
  const state = readState();
  const id = slugify(plan.details.hostname);
  state.subdomains[id] = {
    id,
    projectId: plan.details.projectId,
    applicationId: payload.applicationId || plan.details.projectId,
    environment: "local",
    hostname: plan.details.hostname,
    visibility: plan.details.visibility,
    protection: plan.details.protection,
    status: "active",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  writeState(state);
  appendAudit({ action: "subdomain.apply.local", target: plan.details.hostname, environment: "local", risk: "medium", result: "success", dryRun: false, summary: "Local subdomain state recorded; routing uses existing wildcard Traefik rule." });
  return operationPlan("subdomain.apply.local", "local", false, ["record local subdomain state", "use existing wildcard Traefik route", "write audit event"], {
    subdomainId: id,
    hostname: plan.details.hostname,
    projectId: plan.details.projectId,
    visibility: plan.details.visibility,
    protection: plan.details.protection,
    productionEvidence: false,
  });
}

function planSubdomainRemoval(id, context) {
  const item = findById(context.subdomains, id, "Subdomain");
  appendAudit({ action: "subdomain.remove.plan", target: item.hostname, environment: item.environment, risk: "high", result: "planned", dryRun: true, summary: "Subdomain removal plan generated." });
  return operationPlan("subdomain.remove", item.environment, true, ["soft delete subdomain", "disable route", "remove Cloudflare DNS only after explicit confirmation", "write audit event"], { subdomainId: id, hostname: item.hostname });
}

function applySubdomainRemoval(id, payload, context) {
  const item = findById(context.subdomains, id, "Subdomain");
  if (payload.confirm !== "REMOVE-SUBDOMAIN") throw new RejectedOperationError("Subdomain removal requires confirm=REMOVE-SUBDOMAIN.");
  const state = readState();
  state.subdomains[item.id] = { ...item, status: "disabled", deletedAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  writeState(state);
  appendAudit({ action: "subdomain.remove.apply", target: item.hostname, environment: item.environment, risk: "high", result: "success", dryRun: false, summary: "Subdomain soft deleted locally." });
  return operationPlan("subdomain.remove", item.environment, false, ["soft delete local subdomain state"], { subdomainId: id });
}

function verifySubdomain(id, context) {
  const item = findById(context.subdomains, id, "Subdomain");
  appendAudit({ action: "subdomain.verify.plan", target: item.hostname, environment: item.environment, risk: "low", result: "planned", dryRun: true, summary: "Verification plan generated; no external DNS request made." });
  return operationPlan("subdomain.verify", item.environment, true, ["check DNS status", "check TLS status", "check route status", "check app health status"], { hostname: item.hostname, productionEvidence: false });
}

function planWebspaceCreate(payload, context) {
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const name = slugify(payload.name || projectId);
  validateSlug(name);
  const id = webspaceId(projectId, name);
  const basePath = validateWebspacePath(payload.basePath || `webspaces/${projectId}/${name}`);
  const quotaBytes = parseQuotaBytes(payload.quotaBytes || 0);
  const details = webspaceRecord({ id, projectId, name, basePath, quotaBytes });
  if (payload.confirm === "CREATE-WEBSPACE") {
    const state = readWebspacesState();
    state[id] = { ...(state[id] || {}), ...details, updatedAt: new Date().toISOString(), createdAt: state[id]?.createdAt || new Date().toISOString() };
    writeWebspacesState(state);
    appendAudit({ action: "webspace.create.apply", target: `${projectId}/${name}`, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Webspace metadata created locally; no host filesystem changes applied." });
    const operation = operationPlan("webspace.create.local", context.environment, false, ["validate project", "validate path traversal protection", "declare public/private/uploads/backups/config folders", "apply quota metadata", "write audit event"], { ...details, filesystemTouched: false });
    return { ...operation, webspace: state[id] };
  }
  appendAudit({ action: "webspace.create.plan", target: `${projectId}/${name}`, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Webspace creation plan generated." });
  return operationPlan("webspace.create", context.environment, true, ["validate project", "validate path traversal protection", "declare public/private/uploads/backups/config folders", "apply quota metadata", "write audit event"], { ...details, filesystemTouched: false, confirmationRequired: "CREATE-WEBSPACE" });
}

function planWebspaceQuota(id, payload, context) {
  const space = findById(context.webspaces, id, "Webspace");
  const quotaBytes = parseQuotaBytes(payload.quotaBytes || 0);
  if (payload.confirm === "UPDATE-QUOTA") {
    const state = readWebspacesState();
    state[space.id] = {
      ...webspaceRecord(space),
      ...(state[space.id] || {}),
      quotaBytes,
      updatedAt: new Date().toISOString(),
      createdAt: state[space.id]?.createdAt || space.createdAt || new Date().toISOString(),
    };
    writeWebspacesState(state);
    appendAudit({ action: "webspace.quota.apply", target: sanitizeIdentifier(id), environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Webspace quota metadata updated locally." });
    const operation = operationPlan("webspace.quota.local", context.environment, false, ["validate quota", "update local quota metadata", "write audit event"], { webspaceId: space.id, projectId: space.projectId, quotaBytes, filesystemTouched: false });
    return { ...operation, webspace: state[space.id] };
  }
  appendAudit({ action: "webspace.quota.plan", target: sanitizeIdentifier(id), environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Quota update plan generated." });
  return operationPlan("webspace.quota", context.environment, true, ["validate quota", "prepare quota metadata update", "write audit event"], { webspaceId: space.id, projectId: space.projectId, quotaBytes, confirmationRequired: "UPDATE-QUOTA" });
}

function planDatabaseCreate(payload, context) {
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const engine = choice(String(payload.engine || "mariadb").toLowerCase(), ["mariadb", "postgres"], "database engine");
  const name = validateDatabaseName(payload.name || `${projectId}_${engine}`);
  const ownerRole = validateDatabaseName(payload.ownerRole || `${projectId}_app`);
  const id = databaseId(projectId, engine, name);
  const details = databaseRecord({ id, projectId, engine, name, ownerRole });
  if (payload.confirm === "CREATE-DATABASE") {
    const state = readDatabasesState();
    state[id] = {
      ...(state[id] || {}),
      ...details,
      status: "declared",
      updatedAt: new Date().toISOString(),
      createdAt: state[id]?.createdAt || new Date().toISOString(),
    };
    writeDatabasesState(state);
    appendAudit({ action: "database.create.apply", target: `${projectId}/${name}`, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Database metadata declared locally; no live database mutation executed." });
    const operation = operationPlan("database.create.local", context.environment, false, ["validate project", "validate database name", "declare engine and owner role", "leave MariaDB/PostgreSQL unchanged", "write audit event"], { ...state[id], databaseTouched: false, credentialsExposed: false, productionEvidence: false });
    return { ...operation, database: state[id] };
  }
  appendAudit({ action: "database.create.plan", target: `${projectId}/${name}`, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Database creation plan generated; no live database mutation executed." });
  return operationPlan("database.create", context.environment, true, ["validate project", "validate database name", "prepare local metadata", "require apply confirmation", "write audit event"], { ...details, databaseTouched: false, credentialsExposed: false, productionEvidence: false, confirmationRequired: "CREATE-DATABASE" });
}

function planDatabaseBackup(id, payload, context) {
  const database = findById(context.databases, id, "Database");
  const scope = `database:${database.id}`;
  appendAudit({ action: "database.backup.plan", target: database.id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Database backup plan generated; no dump command executed from the web panel." });
  const operation = operationPlan("database.backup", context.environment, true, ["validate database record", "select database engine", "invoke DatabaseAdapter dump in ops runner", "verify backup artifact", "write evidence"], {
    databaseId: database.id,
    projectId: database.projectId,
    engine: database.engine,
    scope,
    databaseTouched: false,
    credentialsExposed: false,
    productionEvidence: false,
  });
  return { ...operation, database };
}

function planDatabaseRestore(id, payload, context) {
  const database = findById(context.databases, id, "Database");
  const backupRef = sanitizeRef(payload.backupRef || payload.backupId || "latest");
  appendAudit({ action: "database.restore.plan", target: database.id, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Database restore drill plan generated; no live data changed." });
  const operation = operationPlan("database.restore.plan", context.environment, true, ["validate database record", "validate backup reference", "create disposable restore target", "run restore drill through DatabaseAdapter", "generate evidence"], {
    databaseId: database.id,
    projectId: database.projectId,
    engine: database.engine,
    backupRef,
    databaseTouched: false,
    dataChanged: false,
    credentialsExposed: false,
    productionEvidence: false,
  });
  return { ...operation, database };
}

function planResourceLimitUpdate(payload, context) {
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const details = resourceLimitRecord({
    projectId,
    cpuMillicores: parseResourceLimitNumber(payload.cpuMillicores || 0, "CPU millicores", 128000),
    memoryMb: parseResourceLimitNumber(payload.memoryMb || 0, "Memory MB", 1048576),
    diskMb: parseResourceLimitNumber(payload.diskMb || 0, "Disk MB", 1073741824),
  });
  if (payload.confirm === "UPDATE-RESOURCE-LIMITS") {
    const state = readResourceLimitsState();
    state[projectId] = { ...(state[projectId] || {}), ...details, status: "configured", updatedAt: new Date().toISOString(), createdAt: state[projectId]?.createdAt || new Date().toISOString() };
    writeResourceLimitsState(state);
    appendAudit({ action: "resources.limits.apply", target: projectId, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Resource quota metadata updated locally; no live container mutation executed." });
    const operation = operationPlan("resources.limits.local", context.environment, false, ["validate project", "validate resource limits", "update local quota metadata", "leave Docker runtime unchanged", "write audit event"], { ...state[projectId], dockerTouched: false });
    return { ...operation, resourceLimit: state[projectId] };
  }
  appendAudit({ action: "resources.limits.plan", target: projectId, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Resource quota metadata update plan generated." });
  return operationPlan("resources.limits", context.environment, true, ["validate project", "validate resource limits", "prepare quota metadata update", "require apply confirmation", "write audit event"], { ...details, dockerTouched: false, confirmationRequired: "UPDATE-RESOURCE-LIMITS" });
}

function planSecurityPolicyUpdate(payload, context) {
  const scope = sanitizeIdentifier(payload.scope || "global") || "global";
  if (scope !== "global") findById(context.projects, scope, "Project");
  const details = securityPolicyRecord({
    scope,
    wafMode: choice(String(payload.wafMode || "configured"), ["configured", "monitor", "blocking", "disabled"], "WAF mode"),
    rateLimitTier: choice(String(payload.rateLimitTier || "configured"), ["configured", "standard", "strict", "disabled"], "rate limit tier"),
    adminProtection: choice(String(payload.adminProtection || "local-only"), ["local-only", "required", "cloudflare-access", "vpn-required"], "admin protection"),
    securityHeaders: choice(String(payload.securityHeaders || "configured"), ["configured", "strict", "report-only", "disabled"], "security headers"),
    cloudflareAccess: choice(String(payload.cloudflareAccess || "plan-only-local"), ["plan-only-local", "requires-verify-remote", "configured"], "Cloudflare Access status"),
    passkeyAdminAuth: choice(String(payload.passkeyAdminAuth || "available-through-stexor-account-app"), ["available-through-stexor-account-app", "required", "not-configured"], "passkey admin auth"),
    status: "configured",
    source: "control-center-state",
  });
  if (payload.confirm === "UPDATE-SECURITY-POLICY") {
    const state = readSecurityPoliciesState();
    state[scope] = {
      ...(state[scope] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state[scope]?.createdAt || new Date().toISOString(),
    };
    writeSecurityPoliciesState(state);
    appendAudit({ action: "security.policy.apply", target: scope, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Security policy metadata updated locally; no provider or firewall mutation executed." });
    const operation = operationPlan("security.policy.local", context.environment, false, ["validate scope", "validate security posture fields", "update local policy metadata", "leave providers and firewall unchanged", "write audit event"], { ...state[scope], providerTouched: false, productionEvidence: false });
    return { ...operation, securityPolicy: state[scope] };
  }
  appendAudit({ action: "security.policy.plan", target: scope, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Security policy update plan generated; no provider or firewall mutation executed." });
  return operationPlan("security.policy", context.environment, true, ["validate scope", "validate security posture fields", "prepare local policy update", "require apply confirmation", "write audit event"], { ...details, providerTouched: false, productionEvidence: false, confirmationRequired: "UPDATE-SECURITY-POLICY" });
}

function planAlertRecord(payload, context) {
  const service = sanitizeIdentifier(payload.service || "platform") || "platform";
  const severity = choice(String(payload.severity || "warning"), ["info", "warning", "critical"], "alert severity");
  const summary = sanitizeMessage(payload.summary || "Local control alert").replace(/\s+/g, " ").trim().slice(0, 180) || "Local control alert";
  const details = alertRecord({
    id: payload.id ? sanitizeIdentifier(payload.id) : rid(),
    service,
    severity,
    status: "open",
    summary,
    source: "control-center-local",
  });
  if (payload.confirm === "RECORD-ALERT") {
    const state = readAlertsState();
    state[details.id] = {
      ...(state[details.id] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state[details.id]?.createdAt || new Date().toISOString(),
    };
    writeAlertsState(state);
    appendAudit({ action: "alert.record.apply", target: service, environment: context.environment, risk: severity === "critical" ? "high" : "medium", result: "success", dryRun: false, summary: "Local alert metadata recorded; no notification delivery attempted." });
    const operation = operationPlan("alert.record.local", context.environment, false, ["validate alert metadata", "record local alert state", "leave notification delivery unchanged", "write audit event"], { alertId: details.id, service, severity, status: "open", deliveryAttempted: false, productionEvidence: false });
    return { ...operation, alert: state[details.id] };
  }
  appendAudit({ action: "alert.record.plan", target: service, environment: context.environment, risk: severity === "critical" ? "high" : "medium", result: "planned", dryRun: true, summary: "Local alert record plan generated." });
  return operationPlan("alert.record", context.environment, true, ["validate alert metadata", "prepare local alert state", "require apply confirmation", "write audit event"], { ...details, deliveryAttempted: false, productionEvidence: false, confirmationRequired: "RECORD-ALERT" });
}

function planAlertResolution(id, payload, context) {
  const alertId = sanitizeIdentifier(id || "");
  if (!alertId) throw new ValidationError("Alert id is required.");
  const state = readAlertsState();
  const alert = state[alertId];
  if (!alert) throw new ValidationError("Alert not found.");
  if (payload.confirm === "RESOLVE-ALERT") {
    state[alertId] = { ...alertRecord(alert), status: "resolved", resolvedAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    writeAlertsState(state);
    appendAudit({ action: "alert.resolve.apply", target: alertId, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Local alert marked resolved." });
    const operation = operationPlan("alert.resolve.local", context.environment, false, ["validate alert", "mark local alert resolved", "write audit event"], { alertId, service: state[alertId].service, status: "resolved", deliveryAttempted: false, productionEvidence: false });
    return { ...operation, alert: state[alertId] };
  }
  appendAudit({ action: "alert.resolve.plan", target: alertId, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Alert resolution plan generated." });
  return operationPlan("alert.resolve", context.environment, true, ["validate alert", "prepare local resolution", "require apply confirmation", "write audit event"], { alertId, service: alert.service, status: alert.status, confirmationRequired: "RESOLVE-ALERT" });
}

function planNotificationChannelUpdate(payload, context) {
  const channel = choice(String(payload.channel || ""), ["email", "discord", "telegram"], "notification channel");
  const status = choice(String(payload.status || "not-configured"), ["not-configured", "configured", "disabled", "requires-secret-file", "verified-production"], "notification channel status");
  const deliveryMode = choice(String(payload.deliveryMode || "local-metadata"), ["local-metadata", "secret-file", "provider-verified"], "notification delivery mode");
  const details = notificationChannelRecord({ channel, status, deliveryMode, source: "control-center-state" });
  if (payload.confirm === "UPDATE-NOTIFICATION-CHANNEL") {
    const state = readNotificationChannelsState();
    state[channel] = {
      ...(state[channel] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state[channel]?.createdAt || new Date().toISOString(),
    };
    writeNotificationChannelsState(state);
    appendAudit({ action: "alerts.channel.apply", target: channel, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Notification channel metadata updated locally; no test message sent." });
    const operation = operationPlan("alerts.channel.local", context.environment, false, ["validate channel", "update local notification metadata", "leave provider delivery unchanged", "write audit event"], { ...state[channel], deliveryAttempted: false, productionEvidence: false });
    return { ...operation, notificationChannel: state[channel] };
  }
  appendAudit({ action: "alerts.channel.plan", target: channel, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Notification channel update plan generated." });
  return operationPlan("alerts.channel", context.environment, true, ["validate channel", "prepare local notification metadata", "require apply confirmation", "write audit event"], { ...details, deliveryAttempted: false, productionEvidence: false, confirmationRequired: "UPDATE-NOTIFICATION-CHANNEL" });
}

function planSettingsUpdate(payload, context) {
  const details = settingsRecord({
    preferredMode: choice(String(payload.preferredMode || "simple"), ["simple", "advanced"], "default mode preference"),
    environmentMode: choice(String(payload.environmentMode || context.environment), ["local", "staging", "production"], "environment mode"),
    baseDomain: validateBaseDomain(payload.baseDomain || hostSuffix.replace(/^\./, "")),
    cloudflareConnectionStatus: choice(String(payload.cloudflareConnectionStatus || "plan-only-local"), ["not-configured", "plan-only-local", "requires-verify-remote", "configured"], "Cloudflare connection status"),
    githubConnectionStatus: choice(String(payload.githubConnectionStatus || "dry-run"), ["not-configured", "dry-run", "requires-verify", "configured"], "GitHub connection status"),
    smtpAlertStatus: choice(String(payload.smtpAlertStatus || "not-configured"), ["not-configured", "requires-secret-file", "configured", "disabled", "verified-production"], "SMTP alert status"),
    productionGuard: String(payload.environmentMode || context.environment) === "production" ? "requires-verify-remote" : "local-evidence-only",
    source: "control-center-state",
  });
  if (payload.confirm === "UPDATE-SETTINGS") {
    const current = readSettingsState();
    const next = {
      ...current,
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: current.createdAt || new Date().toISOString(),
    };
    writeSettingsState(next);
    appendAudit({ action: "settings.update.apply", target: "control-center", environment: context.environment, risk: details.environmentMode === "production" ? "medium" : "low", result: "success", dryRun: false, summary: "Control Center settings metadata updated locally; no runtime or provider configuration changed." });
    const operation = operationPlan("settings.update.local", context.environment, false, ["validate settings", "update local settings metadata", "leave runtime environment unchanged", "leave providers unchanged", "write audit event"], { ...next, runtimeEnvironmentChanged: false, providerTouched: false, productionEvidence: false });
    return { ...operation, settings: next };
  }
  appendAudit({ action: "settings.update.plan", target: "control-center", environment: context.environment, risk: details.environmentMode === "production" ? "medium" : "low", result: "planned", dryRun: true, summary: "Control Center settings update plan generated." });
  return operationPlan("settings.update", context.environment, true, ["validate settings", "prepare local settings metadata", "require apply confirmation", "write audit event"], { ...details, runtimeEnvironmentChanged: false, providerTouched: false, productionEvidence: false, confirmationRequired: "UPDATE-SETTINGS" });
}

function planProviderConnectionUpdate(id, payload, context) {
  const current = findById(context.providerConnections, id, "Provider connection");
  const status = choice(String(payload.status || current.status || "metadata-only"), ["not-configured", "metadata-only", "requires-secret-file", "requires-verify-remote", "configured", "verified-production"], "provider connection status");
  const details = providerConnectionRecord({
    ...current,
    status,
    accountLabel: sanitizeOptionalRef(payload.accountLabel || current.accountLabel || ""),
    scope: sanitizeOptionalRef(payload.scope || current.scope || "global") || "global",
    privateMaterialConfigured: parseBoolean(payload.privateMaterialConfigured || "") || current.privateMaterialConfigured || ["requires-verify-remote", "configured", "verified-production"].includes(status),
    verificationStatus: status === "verified-production" ? "verified" : status === "requires-verify-remote" ? "requires-verify-remote" : "not-verified",
    lastVerifiedAt: status === "verified-production" ? (current.lastVerifiedAt || new Date().toISOString()) : current.lastVerifiedAt || null,
    source: "control-center-state",
    updatedAt: new Date().toISOString(),
  });
  if (payload.confirm === "UPDATE-PROVIDER-CONNECTION") {
    const state = readProviderConnectionsState();
    state[current.id] = {
      ...(state[current.id] || {}),
      ...details,
      createdAt: state[current.id]?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    writeProviderConnectionsState(state);
    appendAudit({ action: "provider.connection.apply", target: current.id, environment: context.environment, risk: status === "verified-production" ? "medium" : "low", result: "success", dryRun: false, summary: "Provider connection metadata updated locally; no provider API call or secret write occurred." });
    const operation = operationPlan("provider.connection.local", context.environment, false, ["validate provider", "sanitize metadata", "update local connection metadata", "leave provider credentials unchanged", "write audit event"], { ...state[current.id], providerTouched: false, liveProviderTouched: false, productionEvidence: false });
    return { ...operation, providerConnection: state[current.id] };
  }
  appendAudit({ action: "provider.connection.plan", target: current.id, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Provider connection metadata update plan generated." });
  return operationPlan("provider.connection", context.environment, true, ["validate provider", "sanitize metadata", "prepare local connection metadata", "require apply confirmation", "write audit event"], { ...details, providerTouched: false, liveProviderTouched: false, productionEvidence: false, confirmationRequired: "UPDATE-PROVIDER-CONNECTION" });
}

function planBackupRun(payload, context) {
  const scope = sanitizeIdentifier(payload.scope || "all") || "all";
  appendAudit({ action: "backup.run.plan", target: scope, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Manual backup plan generated." });
  const operation = operationPlan("backup.run", context.environment, true, ["select scope", "invoke backup adapter", "verify artifact", "write evidence"], { scope, productionEvidence: false });
  const backup = backupRecord({
    operationId: operation.id,
    action: "backup",
    scope,
    environment: context.environment,
    status: "planned",
    dryRun: true,
    resultSummary: "Manual backup plan generated. No backup command executed from the web panel.",
  });
  appendBackupRecord(backup);
  return { ...operation, backup };
}

function planRestore(payload, context) {
  const scope = sanitizeIdentifier(payload.scope || "all") || "all";
  const backupRef = sanitizeRef(payload.backupRef || payload.backupId || "latest");
  appendAudit({ action: "restore.plan", target: scope, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Restore plan generated; no data changed." });
  const operation = operationPlan("restore.plan", context.environment, true, ["validate backup artifact", "create disposable restore target", "run restore drill", "generate evidence"], { scope, backupRef, productionEvidence: false, dataChanged: false });
  const backup = backupRecord({
    operationId: operation.id,
    action: "restore-drill",
    scope,
    environment: context.environment,
    status: "planned",
    dryRun: true,
    backupRef,
    resultSummary: "Restore drill plan generated. No live data was changed.",
  });
  appendBackupRecord(backup);
  return { ...operation, backup };
}

function operationPlan(type, targetEnv, dryRun, steps, details = {}) {
  const now = new Date().toISOString();
  const operationId = rid();
  const cleanDetails = sanitizeOperationDetails(details);
  const operation = sanitizeEvent({
    id: operationId,
    operationId,
    type,
    status: dryRun ? "planned" : "accepted",
    projectId: cleanDetails.projectId || cleanDetails.project || cleanDetails.applicationId || cleanDetails.webspaceId || cleanDetails.subdomainId || "",
    environment: targetEnv,
    requestedBy: "local-admin",
    dryRun,
    startedAt: now,
    finishedAt: now,
    resultSummary: dryRun ? "Plan generated. No external provider or destructive action executed." : "Local operation accepted.",
    reportPath: null,
    errorCode: null,
    errorMessage: null,
    steps: steps.map((name) => ({
      id: rid(),
      operationId,
      name,
      status: dryRun ? "planned" : "accepted",
      startedAt: now,
      finishedAt: now,
      output: "sanitized",
    })),
    details: cleanDetails,
  });
  appendOperation(operation);
  return operation;
}

function readState() {
  try {
    const parsed = JSON.parse(readFileSync(stateFile, "utf8"));
    return {
      ...parsed,
      projects: typeof parsed.projects === "object" && parsed.projects ? parsed.projects : {},
      subdomains: typeof parsed.subdomains === "object" && parsed.subdomains ? parsed.subdomains : {},
    };
  } catch {
    return { projects: {}, subdomains: {} };
  }
}

function writeState(state) {
  mkdirSync(path.dirname(stateFile), { recursive: true });
  writeFileSync(stateFile, `${JSON.stringify(state, null, 2)}\n`);
}

function appendAudit(event) {
  mkdirSync(path.dirname(auditFile), { recursive: true });
  const record = sanitizeEvent({
    id: rid(),
    timestamp: new Date().toISOString(),
    actor: "local-admin",
    requestId: rid(),
    ...event,
  });
  appendFileSync(auditFile, `${JSON.stringify(record)}\n`);
}

function readAudit() {
  try {
    return readFileSync(auditFile, "utf8").split(/\r?\n/).filter(Boolean).reverse().slice(0, 100).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

function appendOperation(operation) {
  mkdirSync(path.dirname(operationsFile), { recursive: true });
  appendFileSync(operationsFile, `${JSON.stringify(sanitizeEvent(operation))}\n`);
}

function readOperations() {
  try {
    return readFileSync(operationsFile, "utf8").split(/\r?\n/).filter(Boolean).reverse().slice(0, 100).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

function readApplicationsState() {
  try {
    const parsed = JSON.parse(readFileSync(applicationsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeApplicationsState(state) {
  mkdirSync(path.dirname(applicationsFile), { recursive: true });
  writeFileSync(applicationsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readDomainsState() {
  try {
    const parsed = JSON.parse(readFileSync(domainsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeDomainsState(state) {
  mkdirSync(path.dirname(domainsFile), { recursive: true });
  writeFileSync(domainsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readWebspacesState() {
  try {
    const parsed = JSON.parse(readFileSync(webspacesFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeWebspacesState(state) {
  mkdirSync(path.dirname(webspacesFile), { recursive: true });
  writeFileSync(webspacesFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readDatabasesState() {
  try {
    const parsed = JSON.parse(readFileSync(databasesFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeDatabasesState(state) {
  mkdirSync(path.dirname(databasesFile), { recursive: true });
  writeFileSync(databasesFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readResourceLimitsState() {
  try {
    const parsed = JSON.parse(readFileSync(resourceLimitsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeResourceLimitsState(state) {
  mkdirSync(path.dirname(resourceLimitsFile), { recursive: true });
  writeFileSync(resourceLimitsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readSecurityPoliciesState() {
  try {
    const parsed = JSON.parse(readFileSync(securityPoliciesFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeSecurityPoliciesState(state) {
  mkdirSync(path.dirname(securityPoliciesFile), { recursive: true });
  writeFileSync(securityPoliciesFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readAlertsState() {
  try {
    const parsed = JSON.parse(readFileSync(alertsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeAlertsState(state) {
  mkdirSync(path.dirname(alertsFile), { recursive: true });
  writeFileSync(alertsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readNotificationChannelsState() {
  try {
    const parsed = JSON.parse(readFileSync(notificationChannelsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeNotificationChannelsState(state) {
  mkdirSync(path.dirname(notificationChannelsFile), { recursive: true });
  writeFileSync(notificationChannelsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readProviderConnectionsState() {
  try {
    const parsed = JSON.parse(readFileSync(providerConnectionsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeProviderConnectionsState(state) {
  mkdirSync(path.dirname(providerConnectionsFile), { recursive: true });
  writeFileSync(providerConnectionsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readSettingsState() {
  try {
    const parsed = JSON.parse(readFileSync(settingsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeSettingsState(state) {
  mkdirSync(path.dirname(settingsFile), { recursive: true });
  writeFileSync(settingsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function appendDeployment(deployment) {
  mkdirSync(path.dirname(deploymentsFile), { recursive: true });
  appendFileSync(deploymentsFile, `${JSON.stringify(sanitizeEvent(deployment))}\n`);
}

function readDeployments() {
  try {
    return readFileSync(deploymentsFile, "utf8").split(/\r?\n/).filter(Boolean).reverse().slice(0, 100).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

function backupRecord({ operationId, action, scope, environment: targetEnv, status, dryRun, backupRef = "", resultSummary }) {
  return sanitizeEvent({
    id: rid(),
    operationId,
    action,
    scope,
    environment: targetEnv,
    status,
    dryRun,
    backupRef,
    artifactPath: null,
    offsite: process.env.BACKUP_SCHEDULER_ENABLE_OFFSITE === "true" ? "configured" : "not-configured",
    rpo: "reported-by-dr-evidence",
    rto: "reported-by-dr-evidence",
    restoreDrill: action === "restore-drill" ? "planned" : "not-run",
    productionEvidence: false,
    resultSummary,
    createdAt: new Date().toISOString(),
  });
}

function appendBackupRecord(record) {
  mkdirSync(path.dirname(backupRecordsFile), { recursive: true });
  appendFileSync(backupRecordsFile, `${JSON.stringify(sanitizeEvent(record))}\n`);
}

function readBackupRecords() {
  try {
    return readFileSync(backupRecordsFile, "utf8").split(/\r?\n/).filter(Boolean).reverse().slice(0, 100).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

async function readPayload(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  const type = String(req.headers["content-type"] || "").toLowerCase();
  if (type.includes("application/json")) {
    try {
      const parsed = JSON.parse(raw || "{}");
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      throw new ValidationError("Invalid JSON payload.");
    }
  }
  const params = new URLSearchParams(raw);
  return Object.fromEntries(params.entries());
}

function authenticateRequest(req) {
  if (!authRequired) return { ok: true, status: 200, message: "" };
  if (!authVerifierConfigured()) {
    return { ok: false, status: 503, message: "Admin authentication is required but no password verifier is configured." };
  }
  const token = parseCookie(req.headers.cookie || "").sxcc_session || "";
  if (!verifySession(token)) {
    return { ok: false, status: 401, message: "Admin authentication required." };
  }
  return { ok: true, status: 200, message: "" };
}

function authVerifierConfigured() {
  return Boolean(adminPasswordSha256 || (adminPasswordFile && existsSync(adminPasswordFile)));
}

function verifyAdminPassword(password) {
  if (!password) return false;
  if (adminPasswordSha256) {
    return safeEqualHex(sha256(password), adminPasswordSha256);
  }
  if (adminPasswordFile && existsSync(adminPasswordFile)) {
    const expected = readFileSync(adminPasswordFile, "utf8").trim();
    return safeEqualText(password, expected);
  }
  return false;
}

function setSession(res) {
  const expiresAt = Date.now() + (8 * 60 * 60 * 1000);
  const nonce = rid();
  const body = `${expiresAt}.${nonce}`;
  const signature = signSessionBody(body);
  const token = `v1.${body}.${signature}`;
  res.setHeader("set-cookie", `sxcc_session=${token}; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax`);
}

function clearSession(res) {
  res.setHeader("set-cookie", "sxcc_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
}

function verifySession(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return false;
  const expiresAt = Number(parts[1]);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return false;
  const body = `${parts[1]}.${parts[2]}`;
  return sessionKeys().some((key) => safeEqualHex(signSessionBody(body, key), parts[3]));
}

function signSessionBody(body, explicitKey = "") {
  const key = explicitKey || sessionKeys()[0] || "";
  if (!key) return "";
  return createHmac("sha256", key).update(body).digest("hex");
}

function sessionKeys() {
  const raw = sessionKeysFile && existsSync(sessionKeysFile) ? readFileSync(sessionKeysFile, "utf8") : "";
  return raw.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
}

function parseCookie(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    out[decodeURIComponent(part.slice(0, separator).trim())] = decodeURIComponent(part.slice(separator + 1).trim());
  }
  return out;
}

function wantsJson(req) {
  return String(req.headers.accept || "").includes("application/json") || String(req.headers["content-type"] || "").includes("application/json");
}

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function safeEqualHex(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function safeEqualText(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function isPhpProject(projectPath) {
  if (existsSync(path.join(projectPath, "composer.json"))) return true;
  if (existsSync(path.join(projectPath, "public", "index.php"))) return true;
  if (existsSync(path.join(projectPath, "index.php"))) return true;
  try {
    return readdirSync(path.join(projectPath, "public")).some((name) => name.endsWith(".php"));
  } catch {
    return false;
  }
}

function validateSlug(value) {
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) throw new ValidationError("Invalid slug.");
}

function validateHostname(hostname, targetEnv) {
  if (!hostname || hostname.length > 253 || hostname.includes("..")) throw new ValidationError("Invalid hostname.");
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/.test(hostname)) throw new ValidationError("Invalid hostname.");
  if (targetEnv === "production" && hostname.includes("localhost")) throw new ValidationError("Production hostname must use a real domain.");
  if (targetEnv === "local" && !hostname.endsWith(hostSuffix)) throw new ValidationError("Local hostname must use the configured local suffix.");
}

function validateWebspacePath(value) {
  const input = String(value || "");
  const normalized = input.replaceAll("\\", "/").replace(/^\/+|\/+$/g, "");
  if (!normalized || normalized.includes("..") || input.startsWith("/") || /^[A-Za-z]:/.test(input)) throw new ValidationError("Invalid webspace path.");
  if (!/^[a-zA-Z0-9._/-]+$/.test(normalized)) throw new ValidationError("Invalid webspace path.");
  return normalized;
}

function validateDatabaseName(value) {
  const name = String(value || "").trim().toLowerCase();
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(name)) throw new ValidationError("Invalid database identifier.");
  return name;
}

function parseQuotaBytes(value) {
  const quotaBytes = Number(value || 0);
  if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 0) throw new ValidationError("Quota must be zero or a positive safe integer.");
  return quotaBytes;
}

function parseResourceLimitNumber(value, label, max) {
  const next = Number(value || 0);
  if (!Number.isSafeInteger(next) || next < 0 || next > max) throw new ValidationError(`${label} must be zero or a positive safe integer within policy.`);
  return next;
}

function validateBaseDomain(value) {
  const domain = normalizeHost(value || "");
  if (!domain || domain.includes("/") || domain.includes("_") || domain.includes("..") || domain.length > 253) throw new ValidationError("Invalid base domain.");
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/.test(domain)) throw new ValidationError("Invalid base domain.");
  return domain;
}

function webspaceId(projectId, name) {
  return name === projectId ? projectId : `${projectId}-${name}`;
}

function databaseId(projectId, engine, name) {
  return sanitizeIdentifier(`${projectId}-${engine}-${name.replace(/_/g, "-")}`);
}

function domainRecord({
  id = "",
  environment: targetEnv = "local",
  baseDomain = hostSuffix.replace(/^\./, ""),
  visibility = "public",
  providerConnectionId = "",
  dnsStatus = "local-hosts-or-resolver",
  tlsStatus = "local-certificate",
  cloudflareStatus = "not-used-in-local-mode",
  source = "control-center-state",
  providerTouched = false,
  productionEvidence = false,
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanEnv = normalizeEnvironment(targetEnv);
  const cleanBaseDomain = validateBaseDomain(baseDomain || hostSuffix.replace(/^\./, ""));
  const cleanId = sanitizeIdentifier(id || `${cleanEnv}-${cleanBaseDomain.replace(/\./g, "-")}`) || rid();
  return sanitizeEvent({
    id: cleanId,
    environment: cleanEnv,
    baseDomain: cleanBaseDomain,
    visibility: choice(visibility || "public", ["public", "admin", "private"], "visibility"),
    providerConnectionId: sanitizeIdentifier(providerConnectionId),
    dnsStatus,
    tlsStatus,
    cloudflareStatus,
    source,
    dnsTouched: false,
    tlsTouched: false,
    traefikTouched: false,
    providerTouched,
    productionEvidence,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function webspaceRecord({ id, projectId, name, basePath, quotaBytes = 0, usedBytes = 0, linkedApps = null, status = "active", createdAt = null, updatedAt = null }) {
  return sanitizeEvent({
    id,
    projectId,
    name,
    environment: "local",
    basePath,
    quotaBytes,
    usedBytes,
    mounts: ["public", "private", "uploads", "backups", "config"],
    linkedApps: linkedApps || [projectId],
    status,
    source: "control-center-state",
    createdAt,
    updatedAt,
  });
}

function resourceLimitRecord({ projectId, cpuMillicores = 0, memoryMb = 0, diskMb = 0, status = "", createdAt = null, updatedAt = null }) {
  return sanitizeEvent({
    id: projectId,
    projectId,
    environment: "local",
    cpuMillicores: Number(cpuMillicores || 0),
    memoryMb: Number(memoryMb || 0),
    diskMb: Number(diskMb || 0),
    status: status || (Number(cpuMillicores || 0) || Number(memoryMb || 0) || Number(diskMb || 0) ? "configured" : "not-set"),
    source: "control-center-state",
    dockerTouched: false,
    createdAt,
    updatedAt,
  });
}

function databaseRecord({
  id = "",
  projectId = "",
  engine = "mariadb",
  name = "",
  ownerRole = "",
  status = "declared",
  connectionStatus = "metadata-only",
  sizeBytes = 0,
  slowQueries = "planned-adapter",
  users = [],
  permissions = [],
  backupPolicy = "manual-plan-only",
  restoreStatus = "restore-drill-plan-only",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId);
  const cleanEngine = choice(String(engine || "mariadb").toLowerCase(), ["mariadb", "postgres"], "database engine");
  const fallbackProject = cleanProjectId || "platform";
  const cleanName = validateDatabaseName(name || `${fallbackProject}_${cleanEngine}`);
  const cleanOwnerRole = validateDatabaseName(ownerRole || `${fallbackProject}_app`);
  return sanitizeEvent({
    id: sanitizeIdentifier(id || databaseId(cleanProjectId, cleanEngine, cleanName)),
    projectId: cleanProjectId,
    engine: cleanEngine,
    name: cleanName,
    ownerRole: cleanOwnerRole,
    environment: "local",
    status,
    connectionStatus,
    sizeBytes: Number.isSafeInteger(Number(sizeBytes)) && Number(sizeBytes) >= 0 ? Number(sizeBytes) : 0,
    slowQueries,
    users: Array.isArray(users) ? users.map((user) => sanitizeOptionalRef(user)).filter(Boolean).slice(0, 20) : [],
    permissions: Array.isArray(permissions) ? permissions.map((permission) => sanitizeOptionalRef(permission)).filter(Boolean).slice(0, 20) : [],
    backupPolicy,
    restoreStatus,
    source,
    databaseTouched: false,
    credentialsExposed: false,
    providerTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function applicationRecord({
  id = "",
  projectId = "",
  name = "",
  runtime = "node",
  kind = "",
  host = "",
  status = "declared",
  healthcheck = "",
  repositoryUrl = "",
  webspaceId = "",
  source = "control-center-state",
  filesystemTouched = false,
  dockerTouched = false,
  providerTouched = false,
  productionEvidence = false,
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId);
  const cleanRuntime = ["node", "php", "static", "api", "worker"].includes(runtime) ? runtime : "node";
  const cleanId = sanitizeIdentifier(id || `${cleanProjectId}-${cleanRuntime}`) || rid();
  const cleanHost = normalizeHost(host || `${cleanId}${hostSuffix}`);
  return sanitizeEvent({
    id: cleanId,
    projectId: cleanProjectId,
    name: sanitizeMessage(name || humanName(cleanId)).replace(/\s+/g, " ").trim().slice(0, 80),
    runtime: cleanRuntime,
    kind: kind || applicationKind(cleanRuntime),
    host: cleanHost,
    status,
    healthcheck: healthcheck || `https://${cleanHost}/`,
    repositoryUrl,
    webspaceId: sanitizeIdentifier(webspaceId),
    source,
    filesystemTouched,
    dockerTouched,
    providerTouched,
    productionEvidence,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function applicationKind(runtime, requested = "") {
  const normalized = String(requested || "").toLowerCase().trim();
  if (["frontend", "php", "static", "api", "worker"].includes(normalized)) return normalized;
  if (runtime === "php") return "php";
  if (runtime === "static") return "static";
  if (runtime === "api") return "api";
  if (runtime === "worker") return "worker";
  return "frontend";
}

function securityPolicyRecord({
  scope = "global",
  wafMode = "configured",
  rateLimitTier = "configured",
  adminProtection = "local-only",
  securityHeaders = "configured",
  cloudflareAccess = "plan-only-local",
  passkeyAdminAuth = "available-through-stexor-account-app",
  status = "configured",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
} = {}) {
  const cleanScope = sanitizeIdentifier(scope || "global") || "global";
  return sanitizeEvent({
    id: cleanScope,
    scope: cleanScope,
    environment: "local",
    wafMode,
    rateLimitTier,
    adminProtection,
    securityHeaders,
    cloudflareAccess,
    passkeyAdminAuth,
    status,
    source,
    providerTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
  });
}

function alertRecord({
  id = "",
  service = "platform",
  severity = "warning",
  status = "open",
  summary = "Local control alert",
  source = "control-center-local",
  createdAt = null,
  updatedAt = null,
  resolvedAt = null,
  deletedAt = null,
} = {}) {
  const alertId = sanitizeIdentifier(id || rid()) || rid();
  return sanitizeEvent({
    id: alertId,
    service: sanitizeIdentifier(service || "platform") || "platform",
    environment: "local",
    severity,
    status,
    summary: sanitizeMessage(summary).replace(/\s+/g, " ").trim().slice(0, 180) || "Local control alert",
    source,
    deliveryAttempted: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    resolvedAt,
    deletedAt,
  });
}

function notificationChannelRecord({
  channel = "email",
  status = "not-configured",
  deliveryMode = "local-metadata",
  source = "control-center-default",
  createdAt = null,
  updatedAt = null,
} = {}) {
  return sanitizeEvent({
    id: channel,
    channel,
    environment: "local",
    status,
    deliveryMode,
    source,
    plainValueExposed: false,
    deliveryAttempted: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
  });
}

function defaultProviderConnections(notificationChannels = []) {
  const emailStatus = notificationChannels.find((channel) => channel.channel === "email")?.status || "not-configured";
  return [
    providerConnectionRecord({
      id: "cloudflare",
      provider: "cloudflare",
      name: "Cloudflare",
      status: environment === "production" ? "requires-verify-remote" : "metadata-only",
      scope: hostSuffix.replace(/^\./, ""),
      source: "control-center-default",
    }),
    providerConnectionRecord({
      id: "github",
      provider: "github",
      name: "GitHub",
      status: "metadata-only",
      scope: "repository-governance",
      source: "control-center-default",
    }),
    providerConnectionRecord({
      id: "smtp",
      provider: "smtp",
      name: "SMTP Alerts",
      status: emailStatus,
      scope: "alert-delivery",
      privateMaterialConfigured: emailStatus === "configured",
      source: "notification-channel-metadata",
    }),
    providerConnectionRecord({
      id: "hostinger",
      provider: "hostinger",
      name: "Hostinger VPS",
      status: "metadata-only",
      scope: "vps-go-live",
      source: "control-center-default",
    }),
    providerConnectionRecord({
      id: "restic",
      provider: "restic",
      name: "Restic Off-site Backups",
      status: process.env.BACKUP_SCHEDULER_ENABLE_OFFSITE === "true" ? "configured" : "not-configured",
      scope: "off-site-backup",
      privateMaterialConfigured: process.env.BACKUP_SCHEDULER_ENABLE_OFFSITE === "true",
      source: "backup-scheduler-metadata",
    }),
  ];
}

function providerConnectionRecord({
  id = "",
  provider = "",
  name = "",
  status = "metadata-only",
  accountLabel = "",
  scope = "global",
  privateMaterialConfigured = false,
  verificationStatus = "not-verified",
  lastVerifiedAt = null,
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
} = {}) {
  const cleanProvider = choiceProvider(provider || id || "provider");
  const cleanId = sanitizeIdentifier(id || cleanProvider);
  return sanitizeEvent({
    id: cleanId,
    provider: cleanProvider,
    name: sanitizeMessage(name || humanName(cleanProvider)).replace(/\s+/g, " ").trim().slice(0, 80),
    environment,
    status,
    accountLabel: sanitizeOptionalRef(accountLabel),
    scope: sanitizeOptionalRef(scope) || "global",
    privateMaterialConfigured: Boolean(privateMaterialConfigured),
    credentialValueExposed: false,
    providerTouched: false,
    liveProviderTouched: false,
    productionEvidence: false,
    verificationStatus,
    lastVerifiedAt,
    source,
    createdAt,
    updatedAt,
  });
}

function settingsRecord({
  preferredMode = "simple",
  environmentMode = "local",
  baseDomain = hostSuffix.replace(/^\./, ""),
  cloudflareConnectionStatus = "plan-only-local",
  githubConnectionStatus = "dry-run",
  smtpAlertStatus = "not-configured",
  productionGuard = "local-evidence-only",
  source = "control-center-state",
  providerTouched = false,
  productionEvidence = false,
  runtimeEnvironmentChanged = false,
  createdAt = null,
  updatedAt = null,
} = {}) {
  return sanitizeEvent({
    id: "local",
    preferredMode,
    environmentMode,
    baseDomain,
    cloudflareConnectionStatus,
    githubConnectionStatus,
    smtpAlertStatus,
    productionGuard,
    source,
    providerTouched,
    productionEvidence,
    runtimeEnvironmentChanged,
    createdAt,
    updatedAt,
  });
}

function defaultNotificationChannels() {
  return [
    notificationChannelRecord({
      channel: "email",
      status: process.env.ALERT_EMAIL_TO && process.env.SMTP_HOST && process.env.SMTP_USER ? "configured" : "requires-secret-file",
      deliveryMode: "secret-file",
      source: "compose-env-secret-file",
    }),
    notificationChannelRecord({
      channel: "discord",
      status: process.env.ALERT_DISCORD_WEBHOOK_URL_FILE ? "configured" : "not-configured",
      deliveryMode: "secret-file",
      source: "compose-env-secret-file",
    }),
    notificationChannelRecord({
      channel: "telegram",
      status: process.env.ALERT_TELEGRAM_BOT_TOKEN_FILE && process.env.ALERT_TELEGRAM_CHAT_ID ? "configured" : "not-configured",
      deliveryMode: "secret-file",
      source: "compose-env-secret-file",
    }),
  ];
}

function recentErrorRecords(audit, operations) {
  const fromOperations = operations
    .filter((operation) => operation.status === "failed" || operation.errorCode || operation.errorMessage)
    .map((operation) => ({
      id: operation.id,
      source: "operation",
      timestamp: operation.finishedAt || operation.startedAt || "",
      name: operation.type || "operation",
      summary: operation.errorMessage || operation.resultSummary || "Operation failed.",
    }));
  const fromAudit = audit
    .filter((event) => event.result === "failed")
    .map((event) => ({
      id: event.id,
      source: "audit",
      timestamp: event.timestamp || "",
      name: event.action || "audit event",
      summary: event.summary || "Audited action failed.",
    }));
  return [...fromOperations, ...fromAudit]
    .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))
    .slice(0, 12)
    .map((item) => sanitizeEvent(item));
}

function subdomainHostname(payload, targetEnv) {
  const explicit = normalizeHost(payload.hostname || "");
  if (explicit) return explicit;
  const label = slugify(payload.subdomain || "");
  validateSlug(label);
  const baseDomain = normalizeHost(payload.baseDomain || hostSuffix.replace(/^\./, ""));
  return `${label}.${baseDomain}`;
}

function findById(items, id, label) {
  const slug = slugify(id);
  const found = items.find((item) => item.id === id || item.id === slug || item.slug === slug || slugify(item.hostname || "") === slug);
  if (!found) throw new ValidationError(`${label} not found.`);
  return found;
}

function route(parts, ...expected) {
  return parts.length === expected.length && expected.every((part, index) => parts[index] === part);
}

function choice(value, allowed, label) {
  if (!allowed.includes(value)) throw new ValidationError(`Invalid ${label}.`);
  return value;
}

function choiceProvider(value) {
  return choice(String(value || "").toLowerCase().trim(), ["cloudflare", "github", "smtp", "hostinger", "restic"], "provider");
}

function parsePairs(value) {
  const pairs = new Map();
  for (const item of String(value).split(",")) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    const separatorIndex = trimmed.includes("=") ? trimmed.indexOf("=") : trimmed.indexOf(":");
    if (separatorIndex <= 0) continue;
    const key = slugify(trimmed.slice(0, separatorIndex));
    const val = trimmed.slice(separatorIndex + 1).trim();
    if (key && val) pairs.set(key, val);
  }
  return pairs;
}

function normalizeEnvironment(value) {
  const normalized = String(value || "").toLowerCase().trim();
  return ["local", "staging", "production"].includes(normalized) ? normalized : "local";
}

function parseBoolean(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").toLowerCase().trim());
}

function normalizeHost(value) {
  return String(value || "").toLowerCase().trim().replace(/:\d+$/, "");
}

function normalizeHostSuffix(value) {
  const normalized = normalizeHost(value);
  return normalized.startsWith(".") ? normalized : `.${normalized}`;
}

function slugify(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
}

function sanitizeIdentifier(value) {
  return slugify(value).slice(0, 80);
}

function sanitizeDisplayName(value) {
  const next = sanitizeMessage(value).replace(/\s+/g, " ").trim().slice(0, 80);
  if (!next) throw new ValidationError("Project display name is required.");
  return next;
}

function sanitizeRef(value) {
  return String(value || "").trim().replace(/[^a-zA-Z0-9._/@:-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120) || "unknown";
}

function sanitizeOptionalRef(value) {
  const raw = String(value || "").trim();
  return raw ? sanitizeRef(raw) : "";
}

function sanitizeMessage(message) {
  return String(message || "").replace(/\b(token|secret|password|authorization|cookie)=([^\s]+)/gi, "$1=[redacted]");
}

function sanitizeEvent(event) {
  return sanitizeValue(event);
}

function sanitizeOperationDetails(details) {
  return sanitizeValue(details && typeof details === "object" ? details : {});
}

function sanitizeValue(value, keyName = "") {
  if (/(secret|token|password|authorization|cookie)/i.test(keyName)) return "[redacted]";
  if (typeof value === "string") return sanitizeMessage(value);
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item));
  if (value && typeof value === "object") {
    const clean = {};
    for (const [key, childValue] of Object.entries(value)) clean[key] = sanitizeValue(childValue, key);
    return clean;
  }
  return value;
}

function safeIsDirectory(value) {
  try {
    return statSync(value).isDirectory();
  } catch {
    return false;
  }
}

function safeDocPath(docPath) {
  const normalized = String(docPath || "").replaceAll("\\", "/");
  if (normalized.includes("..")) return path.join(docsRoot, "__invalid__");
  return path.join(docsRoot, normalized);
}

function countAvailableDocs() {
  return Object.values(docs).flat().filter(([docPath]) => existsSync(safeDocPath(docPath))).length;
}

function humanName(value) {
  return String(value).replace(/[-_]+/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
}

function bytesLabel(bytes) {
  if (!bytes) return "unlimited";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(bytes);
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${Math.round(value * 10) / 10} ${units[index]}`;
}

function rid() {
  return randomBytes(8).toString("hex");
}

function empty(title, message) {
  return `<div class="empty"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(message)}</p></div>`;
}

function advancedServices() {
  return [
    ["Traefik", "reverse proxy"], ["WAF", "ModSecurity CRS"], ["MariaDB", "local PHP database"], ["PostgreSQL", "platform database"],
    ["Redis", "cache/session support"], ["NATS", "messaging"], ["Keycloak", "identity provider"], ["MinIO", "object storage"],
    ["Prometheus", "metrics"], ["Loki", "logs"], ["Alertmanager", "alert routing"], ["Grafana", "observability UI"],
    ["backup scheduler", "scheduled backup orchestration"], ["workers", "jobs and notifications"], ["node-exporter", "host metrics"], ["cAdvisor", "container metrics"],
  ].map(([name, role]) => ({ name, role, status: name === "backup scheduler" ? "planned adapter" : "configured" }));
}

function deploymentSteps(action) {
  if (action === "rollback") {
    return ["validate application", "select rollback target", "verify previous image digest", "prepare Compose override", "require production approval before apply", "write deployment evidence"];
  }
  return ["validate application", "resolve branch and commit", "prepare image build plan", "require SBOM and provenance", "prepare healthcheck", "write deployment evidence"];
}

function navigationForMode(mode) {
  if (mode === "advanced") {
    return [
      ["infrastructure", "Infrastructure", "INF"], ["network", "Network", "NET"], ["databases", "Databases", "DB"], ["storage", "Storage", "S3"],
      ["workers-jobs", "Workers & Jobs", "JOB"], ["deployments", "Deployments", "DEP"], ["cicd-github", "CI/CD & GitHub Governance", "CI"],
      ["cloudflare", "Cloudflare", "CF"], ["monitoring", "Monitoring", "MON"], ["logs-advanced", "Logs Advanced", "LOG"], ["alerts-advanced", "Alerts Advanced", "ALT"],
      ["backup-restore", "Backup & Restore", "BKP"], ["disaster-recovery", "Disaster Recovery", "DR"], ["release-evidence", "Release Evidence", "EVD"],
      ["go-no-go", "Production Go/No-Go", "GO"], ["security-advanced", "Security Advanced", "SEC"], ["identity", "Identity & Access", "IAM"],
      ["secrets", "Secrets", "KEY"], ["audit", "Audit Log", "AUD"], ["billing", "Billing / Plans", "BIL"],
    ].map(([id, label, short]) => ({ id, label, short }));
  }
  return [
    ["overview", "Overview", "OVR"], ["projects", "Projects", "PRJ"], ["applications", "Applications", "APP"], ["domains", "Domains & Subdomains", "DNS"],
    ["webspaces", "Web Spaces", "WEB"], ["resources", "Resources", "RES"], ["security", "Security", "SEC"], ["backups", "Backups", "BKP"],
    ["logs", "Logs / Alerts", "LOG"], ["settings", "Settings", "SET"],
  ].map(([id, label, short]) => ({ id, label, short }));
}

function advancedItems(section) {
  const map = {
    databases: ["MariaDB", "PostgreSQL", "backup DB", "restore DB", "users and permissions"],
    storage: ["MinIO buckets", "quota", "access key policy", "lifecycle", "bucket restore"],
    "workers-jobs": ["worker status", "queues", "failed jobs", "retry controls", "containerized scheduler"],
    deployments: ["deploy history", "image digest", "SBOM", "provenance", "rollback target"],
    "cicd-github": ["branch protection", "environments", "secrets/vars verification", "workflow status", "deploy approvals"],
    cloudflare: ["DNS records", "Access policies", "WAF rules", "Cache rules", "Remote verification"],
    monitoring: ["Prometheus", "cAdvisor", "node-exporter", "latency", "error rate"],
    "logs-advanced": ["query Loki", "project/app/container filters", "request id", "user id", "non-sensitive export"],
    "alerts-advanced": ["alert rules", "channels", "delivery evidence", "failure evidence", "escalation"],
    "disaster-recovery": ["DR evidence", "RTO/RPO", "backup freshness", "restore p95", "WAL archive", "off-site restore evidence"],
    "release-evidence": ["SBOM", "digest-pinned images", "provenance", "signature", "previous-images.json", "rollback validation"],
    "go-no-go": ["production-go-no-go", "evidence bundle", "live blockers", "JSON/Markdown reports"],
    "security-advanced": ["WAF", "rate limit", "brute force", "CSP", "CORS", "headers", "secret scan", "vulnerability scan", "Cloudflare Access", "admin route protection"],
    identity: ["users", "teams", "roles", "passkeys", "sessions", "login audit"],
    secrets: ["Docker secrets", "KMS metadata", "rotation", "usage map", "no plaintext values"],
    billing: ["VPS plan metadata", "resource budget", "Cloudflare plan", "backup storage", "cost review"],
  };
  return map[section] || ["dry-run adapter", "apply confirmation", "verify evidence"];
}

function json(res, payload, status = 200) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-stexor-control-center-runtime": "node" });
  res.end(`${JSON.stringify(payload, null, 2)}\n`);
}

function html(res, content, status = 200) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-stexor-control-center-runtime": "node" });
  res.end(content);
}

function redirect(res, location) {
  res.writeHead(303, { location, "cache-control": "no-store", "x-stexor-control-center-runtime": "node" });
  res.end();
}

function notFound(res) {
  json(res, { error: "not_found", message: "Control endpoint not found." }, 404);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;",
  }[char]));
}

function styleTag() {
  return `<style>
.inline-confirm select{width:190px;min-height:34px;padding:0 10px;border:1px solid var(--line);border-radius:8px;background:#090f15;color:var(--text);font-size:12px}
:root{color-scheme:dark;--bg:#0b1117;--panel:#121a23;--panel-2:#172231;--text:#eef5ff;--muted:#9eb0c5;--line:#263547;--accent:#76e4c5;--accent-2:#8fb7ff;--danger:#ff8b8b;--warn:#f6d66f;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text)}a{color:inherit;text-decoration:none}button,input,select{font:inherit}.control-shell{display:grid;grid-template-columns:280px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;padding:18px;border-right:1px solid var(--line);background:#090f15;overflow:auto}.brand{display:flex;gap:12px;align-items:center;padding-bottom:18px;border-bottom:1px solid var(--line)}.brand-mark{display:grid;place-items:center;width:42px;height:42px;border:1px solid var(--accent);border-radius:8px;color:var(--accent);font-weight:900}.brand strong,.brand small{display:block}.brand small{color:var(--muted)}nav{display:grid;gap:8px;margin-top:18px}nav a{display:flex;align-items:center;gap:10px;min-height:40px;padding:8px 10px;border:1px solid transparent;border-radius:8px;color:var(--muted);font-weight:800}nav a span{display:inline-grid;place-items:center;min-width:38px;min-height:26px;border:1px solid var(--line);border-radius:7px;color:var(--accent-2);font-size:11px}nav a.active,nav a:hover{color:var(--text);background:var(--panel);border-color:var(--line)}.mode-card{margin-top:18px;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}.mode-card small{color:var(--muted)}.segmented{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px}.segmented a{display:grid;place-items:center;min-height:34px;border:1px solid var(--line);border-radius:8px;color:var(--muted);font-weight:850}.segmented a.selected{color:var(--accent);border-color:var(--accent)}.workspace{width:min(1240px,calc(100% - 32px));margin:0 auto;padding:28px 0 48px}.topbar{display:flex;justify-content:space-between;align-items:end;gap:18px;padding-bottom:22px;border-bottom:1px solid var(--line)}.eyebrow{margin:0 0 8px;color:var(--accent);font-size:13px;font-weight:850;letter-spacing:0}h1{margin:0;font-size:48px;line-height:1;letter-spacing:0}h2{margin:0;font-size:22px}h3{margin:18px 0 10px;color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:0}.top-actions{display:flex;align-items:center;justify-content:end;gap:10px;flex-wrap:wrap}.switcher select{min-height:38px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text);padding:0 10px}.pill,.state{display:inline-flex;align-items:center;min-height:30px;padding:0 10px;border:1px solid var(--line);border-radius:999px;font-size:12px;font-weight:850;color:var(--muted)}.pill.info,.state.on{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 55%,var(--line))}.pill.danger,.state.off{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 55%,var(--line))}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin-top:22px}.metric{min-height:96px;padding:16px;background:var(--panel);border:1px solid var(--line);border-radius:8px}.metric span{display:block;font-size:34px;font-weight:900;color:var(--accent-2)}.metric small{color:var(--muted)}.grid{display:grid;gap:16px;margin-top:22px}.grid.two{grid-template-columns:minmax(0,1.15fr) minmax(320px,.85fr)}.panel{margin-top:22px;padding:18px;background:var(--panel);border:1px solid var(--line);border-radius:8px}.grid .panel{margin-top:0}.panel-head{display:flex;gap:12px;align-items:center;margin-bottom:16px}.panel-head>span{display:inline-grid;place-items:center;width:42px;height:42px;border:1px solid var(--accent);border-radius:8px;color:var(--accent);font-size:12px;font-weight:900}.panel-head p{margin:4px 0 0;color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}.card{min-height:96px;padding:14px;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;transition:transform .18s ease,border-color .18s ease,background .18s ease}a.card:hover,.project-card:hover{transform:translateY(-2px);border-color:var(--accent);background:#1a2838}.card strong{display:block;font-size:15px}.card span{display:block;margin-top:8px;color:var(--muted);font-size:13px;line-height:1.45}.card.compact{min-height:78px}.project-cards{margin-top:16px}.project-card{min-height:164px;display:flex;flex-direction:column;gap:4px}.project-card.is-off{opacity:.76}.card-title{display:flex;align-items:start;justify-content:space-between;gap:10px}.card-title em{padding:4px 8px;border:1px solid var(--line);border-radius:999px;color:var(--accent);font-size:11px;font-style:normal;font-weight:850}.card .host{color:var(--accent-2);font-weight:850;overflow-wrap:anywhere}.project-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:auto;padding-top:12px}.button{display:inline-flex;align-items:center;justify-content:center;min-height:34px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:#101820;color:var(--text);font-size:13px;font-weight:850;cursor:pointer}.button.open,.button.enable{border-color:color-mix(in srgb,var(--accent) 60%,var(--line));color:var(--accent)}.button.danger{border-color:color-mix(in srgb,var(--danger) 60%,var(--line));color:var(--danger)}.button.muted{color:var(--muted);cursor:not-allowed;opacity:.55}.status-list{display:grid;gap:10px;padding:0;margin:0;list-style:none}.status-list li{display:flex;justify-content:space-between;gap:16px;padding:12px;background:var(--panel-2);border:1px solid var(--line);border-radius:8px}.status-list span{color:var(--muted);text-align:right}.json-block,pre{overflow:auto;white-space:pre-wrap;margin:0;color:#dce8f7;line-height:1.55;font-size:14px}.empty{padding:18px;background:#101820;border:1px dashed var(--line);border-radius:8px;color:var(--muted)}.disabled{opacity:.45;pointer-events:none}.login-shell{display:grid;place-items:center;min-height:100vh;padding:24px}.login-panel{width:min(460px,100%);padding:24px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}.login-panel h1{font-size:38px}.login-copy{color:var(--muted);line-height:1.55}.login-form{display:grid;gap:12px;margin-top:20px}.login-form label{color:var(--muted);font-size:13px;font-weight:850}.login-form input{min-height:42px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:#090f15;color:var(--text)}.inline-confirm{display:flex;align-items:center;gap:6px;flex-wrap:wrap}.inline-confirm input{width:190px;min-height:34px;padding:0 10px;border:1px solid var(--line);border-radius:8px;background:#090f15;color:var(--text);font-size:12px}@media(max-width:980px){.control-shell{display:block}.sidebar{position:static;height:auto}.workspace{width:min(100% - 24px,1240px)}.topbar,.grid.two{display:block}.metric-grid{grid-template-columns:repeat(2,1fr)}h1{font-size:36px}.top-actions{justify-content:start;margin-top:14px}}
</style>`;
}

class ValidationError extends Error {}
class RejectedOperationError extends Error {}
