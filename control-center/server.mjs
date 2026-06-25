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
const deploymentsFile = process.env.PROJECT_DEPLOYMENTS_FILE || "/var/www/project-state/deployments.jsonl";
const backupRecordsFile = process.env.PROJECT_BACKUP_RECORDS_FILE || "/var/www/project-state/backups.jsonl";
const resourceLimitsFile = process.env.PROJECT_RESOURCE_LIMITS_FILE || "/var/www/project-state/resource-limits.json";
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

    if (req.method === "POST" && url.pathname === "/actions/backup-command") {
      await handleBackupCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/resource-command") {
      await handleResourceCommand(req, res, context);
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

    if (method === "GET" && route(parts, "control", "resources", "summary")) return json(res, context.resources);
    if (method === "POST" && route(parts, "control", "resources", "limits")) return json(res, planResourceLimitUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "security", "summary")) return json(res, context.security);
    if (method === "GET" && route(parts, "control", "backups", "summary")) return json(res, context.backups);
    if (method === "GET" && route(parts, "control", "backups", "records")) return json(res, { records: context.backupRecords });
    if (method === "POST" && route(parts, "control", "backups", "run")) return json(res, planBackupRun(payload, context), 202);
    if (method === "POST" && route(parts, "control", "restore", "plan")) return json(res, planRestore(payload, context), 202);

    if (method === "GET" && route(parts, "control", "deployments")) return json(res, { deployments: context.deployments });
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
  if (!projects.some((project) => project.slug === slug)) {
    json(res, { error: "not_found", message: "Project not found." }, 404);
    return;
  }
  const enabled = String(payload.enabled || "") === "1";
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
    if (action === "archive") operation = applyProjectArchive(id, payload, context);
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
    operation = planApplicationLifecycle(id, action, payload, context);
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
    if (action === "apply-local") operation = applySubdomain({ ...payload, environment: "local", confirm: "APPLY-LOCAL" }, context);
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

function buildContext({ projects, state }) {
  const applications = projects.map((project) => ({
    id: project.slug,
    projectId: project.slug,
    name: project.name,
    runtime: project.runtime,
    kind: project.runtime === "node" ? "frontend" : "php",
    host: project.host,
    status: project.enabled ? "online" : "offline",
    healthcheck: `https://${project.host}/`,
  }));
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
  const deployments = readDeployments();
  const backupRecords = readBackupRecords();
  const storedResourceLimits = readResourceLimitsState();
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
  const security = {
    waf: "configured",
    rateLimit: "configured",
    cloudflareAccess: environment === "production" ? "requires-verify-remote" : "plan-only-local",
    adminProtection: process.env.CONTROL_CENTER_REQUIRE_ADMIN === "1" ? "required" : "local-only",
    securityHeaders: "configured",
    passkeyAdminAuth: "available-through-stexor-account-app",
    recentAuditEvents: audit.slice(0, 8),
  };
  const backups = {
    mode: environment,
    manualBackup: "plan-only-from-control-center",
    restoreDrill: "available-through-infra-ops",
    offsite: process.env.BACKUP_SCHEDULER_ENABLE_OFFSITE === "true" ? "configured" : "not-configured",
    rpoRto: "reported-by-production-go-no-go-evidence",
    latest: backupRecords.slice(0, 5),
  };
  const domains = [{
    id: "local",
    environment: "local",
    baseDomain: hostSuffix.replace(/^\./, ""),
    dnsStatus: "local-hosts-or-resolver",
    tlsStatus: "local-certificate",
    cloudflareStatus: "not-used-in-local-mode",
  }];
  const overview = {
    title: "Stexor Control Center",
    environment,
    modeEvidence: environment === "production" ? "production evidence requires verifyRemote" : "local evidence only",
    projects: { total: projects.length, active: activeProjects, archived: archivedProjects },
    applications: { total: applications.length, online: onlineApps, offline: applications.length - onlineApps },
    resources,
    subdomains: { total: subdomains.length, active: subdomains.filter((item) => item.status === "active").length },
    alerts: { open: 0, source: "Alertmanager summary link" },
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
    resources,
    security,
    backups,
    backupRecords,
    deployments,
    operations,
    audit,
    docsAvailable: countAvailableDocs(),
    environment,
    advancedServices: advancedServices(),
  };
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
      summary: archived ? "Archived in local Control Center state" : type === "PHP" ? "Apache/PHP local host" : "Node routed service",
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
    else if (section === "applications") body = renderApplications(scoped(context.applications));
    else if (section === "domains") body = renderDomains(context.domains, scoped(context.subdomains), context.projects);
    else if (section === "webspaces") body = renderWebspaces(scoped(context.webspaces), context.projects);
    else if (section === "resources") body = renderResources(context.resources, context.projects);
    else if (section === "security") body = renderJsonPanel("Security", context.security);
    else if (section === "backups") body = renderBackups(context.backups, context.backupRecords);
    else if (section === "logs") body = renderAudit(context.audit, "Logs / Alerts minimal");
    else body = renderSettings(context);
  } else {
    if (section === "audit") body = renderAudit(context.audit, "Audit Log");
    else if (section === "network") body = renderDomains(context.domains, scoped(context.subdomains), context.projects);
    else if (section === "infrastructure") body = renderInfrastructure(context.advancedServices);
    else if (section === "deployments") body = renderDeployments(scoped(context.deployments));
    else if (section === "backup-restore") body = renderBackups(context.backups, context.backupRecords);
    else body = renderPlanOnlyPanel(title, advancedItems(section));
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
  <div class="cards project-cards">${projects.map(renderProjectCard).join("") || empty("No projects", "No mounted projects found.")}</div></section>`;
}

function renderProjectCard(project) {
  return `<div id="project-${escapeHtml(project.slug)}" class="card project-card ${project.enabled ? "" : "is-off"}">
    <div class="card-title"><strong>${escapeHtml(project.name)}</strong><em>${escapeHtml(project.type)}</em></div>
    <span class="host">${escapeHtml(project.host)}</span>
    <span>${escapeHtml(project.summary)}</span>
    ${project.archivedAt ? `<span>Archived at ${escapeHtml(project.archivedAt)}</span>` : ""}
    <div class="project-actions">
      <span class="state ${project.enabled ? "on" : "off"}">${escapeHtml(humanName(project.status))}</span>
      ${project.enabled ? `<a class="button open" href="${escapeHtml(project.href)}">Open</a>` : `<span class="button muted">Open</span>`}
      <form method="post" action="/actions/toggle-project">
        <input type="hidden" name="slug" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="enabled" value="${project.enabled ? "0" : "1"}">
        <button class="button ${project.enabled ? "danger" : "enable"}" type="submit">${project.enabled ? "Disable" : "Enable"}</button>
      </form>
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

function renderApplications(applications) {
  return `<section class="panel"><div class="panel-head"><span>APP</span><div><h2>Applications</h2><p>Start, stop, restart, deploy and rollback create safe dry-run operation plans.</p></div></div><div class="cards app-cards">${applications.map(renderApplicationCard).join("") || empty("No applications", "No Node, PHP, static, API or worker applications were discovered.")}</div></section>`;
}

function renderApplicationCard(app) {
  const actions = ["start", "stop", "restart", "deploy", "rollback"];
  return `<div id="app-${escapeHtml(app.id)}" class="card app-card">
    <div class="card-title"><strong>${escapeHtml(app.name)}</strong><em>${escapeHtml(app.runtime)}</em></div>
    <span class="host">${escapeHtml(app.host)}</span>
    <span>Healthcheck: ${escapeHtml(app.healthcheck)}</span>
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
  return `<section class="grid two"><div class="panel"><div class="panel-head"><span>DNS</span><div><h2>Domains</h2><p>Local DNS is simulated; production requires Cloudflare dry-run/apply/verify.</p></div></div><div class="cards">${domains.map((domain) => `<div class="card compact"><strong>${escapeHtml(domain.baseDomain)}</strong><span>${escapeHtml(domain.environment)} / ${escapeHtml(domain.tlsStatus)}</span><span>${escapeHtml(domain.cloudflareStatus)}</span></div>`).join("")}</div></div>
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

function renderSettings(context) {
  return `<section class="grid two"><div class="panel"><div class="panel-head"><span>SET</span><div><h2>Settings</h2><p>Connections are status-only here; tokens stay in Docker secrets.</p></div></div><ul class="status-list">
    <li><strong>Environment</strong><span>${escapeHtml(context.environment)}</span></li>
    <li><strong>Base domain</strong><span>${escapeHtml(hostSuffix.replace(/^\./, ""))}</span></li>
    <li><strong>Cloudflare</strong><span>${escapeHtml(context.security.cloudflareAccess)}</span></li>
    <li><strong>GitHub</strong><span>governance dry-run through infra ops</span></li>
    <li><strong>SMTP alerts</strong><span>configured through secret-backed environment</span></li>
  </ul></div><div class="panel"><div class="panel-head"><span>DOC</span><div><h2>Documentation</h2><p>${context.docsAvailable} local docs</p></div></div>${renderDocs()}</div></section>`;
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
  appendAudit({ action: "project.create.plan", target: slug, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Project creation plan generated; no filesystem changes applied." });
  return operationPlan("project.create", context.environment, true, ["validate slug", "create project metadata", "create optional webspace", "link applications/domains/databases", "write audit event"], { projectId: slug });
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
  const runtime = String(payload.runtime || "");
  if (!["node", "php", "static", "api", "worker"].includes(runtime)) throw new ValidationError("Unsupported application runtime.");
  appendAudit({ action: "application.create.plan", target: sanitizeIdentifier(payload.projectId || "unknown"), environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Application creation plan generated." });
  return operationPlan("application.create", context.environment, true, ["validate runtime", "link repository or webspace", "create healthcheck", "prepare route plan", "write audit event"], { runtime });
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

function webspaceId(projectId, name) {
  return name === projectId ? projectId : `${projectId}-${name}`;
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
      ["deployments", "Deployments", "DEP"], ["cloudflare", "Cloudflare", "CF"], ["monitoring", "Monitoring", "MON"], ["backup-restore", "Backup & Restore", "BKP"],
      ["go-no-go", "Production Go/No-Go", "GO"], ["identity", "Identity & Access", "IAM"], ["secrets", "Secrets", "SEC"], ["audit", "Audit Log", "AUD"],
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
    deployments: ["deploy history", "image digest", "SBOM", "provenance", "rollback target"],
    cloudflare: ["DNS records", "Access policies", "WAF rules", "Cache rules", "Remote verification"],
    monitoring: ["Prometheus", "cAdvisor", "node-exporter", "latency", "error rate"],
    "go-no-go": ["production-go-no-go", "evidence bundle", "live blockers", "JSON/Markdown reports"],
    identity: ["users", "teams", "roles", "passkeys", "sessions", "login audit"],
    secrets: ["Docker secrets", "KMS metadata", "rotation", "usage map", "no plaintext values"],
  };
  return map[section] || ["dry-run adapter", "apply confirmation", "verify evidence"];
}

function json(res, payload, status = 200) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(`${JSON.stringify(payload, null, 2)}\n`);
}

function html(res, content, status = 200) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  res.end(content);
}

function redirect(res, location) {
  res.writeHead(303, { location, "cache-control": "no-store" });
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
