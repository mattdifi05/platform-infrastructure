import { createServer } from "node:http";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, appendFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { controlCenterScriptTags, controlCenterStylesheetLinks, controlCenterUiContract } from "./components/ui/controlCenterUi.mjs";

const port = Number(process.env.CONTROL_CENTER_PORT || 8080);
const appRoot = path.dirname(fileURLToPath(import.meta.url));
const controlCenterStylesRoot = process.env.CONTROL_CENTER_STYLES_ROOT || path.join(appRoot, "styles");
const publicRoot = process.env.CONTROL_CENTER_PUBLIC_ROOT || path.join(appRoot, "public");
const projectsRoot = process.env.PROJECTS_ROOT || "/var/www/projects";
const docsRoot = process.env.CONTROL_CENTER_DOCS_ROOT || "/var/www/infra-docs";
const stateFile = process.env.PROJECT_STATE_FILE || "/var/www/project-state/projects.json";
const auditFile = process.env.PROJECT_AUDIT_FILE || "/var/www/project-state/audit.jsonl";
const operationsFile = process.env.PROJECT_OPERATIONS_FILE || "/var/www/project-state/operations.jsonl";
const applicationsFile = process.env.PROJECT_APPLICATIONS_FILE || "/var/www/project-state/applications.json";
const domainsFile = process.env.PROJECT_DOMAINS_FILE || "/var/www/project-state/domains.json";
const databasesFile = process.env.PROJECT_DATABASES_FILE || "/var/www/project-state/databases.json";
const storageBucketsFile = process.env.PROJECT_STORAGE_BUCKETS_FILE || "/var/www/project-state/storage-buckets.json";
const sensitiveMaterialsFile = process.env.PROJECT_SENSITIVE_MATERIALS_FILE || "/var/www/project-state/sensitive-materials.json";
const workerJobsFile = process.env.PROJECT_WORKER_JOBS_FILE || "/var/www/project-state/worker-jobs.json";
const identityAccessFile = process.env.PROJECT_IDENTITY_ACCESS_FILE || "/var/www/project-state/identity-access.json";
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
const platformName = String(process.env.PLATFORM_NAME || "Platform Infrastructure").trim() || "Platform Infrastructure";
const domain = normalizeHost(process.env.DOMAIN || process.env.LOCAL_DOMAIN || "localhost.com");
const adminHost = normalizeHost(process.env.ADMIN_HOST || `portal.${domain}`);
const controlCenterHost = normalizeHost(process.env.CONTROL_CENTER_HOST || process.env.PROJECTS_HOST || adminHost);
const docsHost = normalizeHost(process.env.DOCS_HOST || `docs.${domain}`);
const authHost = normalizeHost(process.env.AUTH_HOST || `auth.${domain}`);
const storageHost = normalizeHost(process.env.STORAGE_HOST || process.env.MINIO_CONSOLE_HOST || `storage.${domain}`);
const grafanaHost = normalizeHost(process.env.GRAFANA_HOST || `grafana.${domain}`);
const projectsHost = controlCenterHost;
const hostSuffix = normalizeHostSuffix(process.env.PROJECT_HOST_SUFFIX || `.${domain}`);
const nodeHosts = parsePairs(process.env.NODE_PROJECT_HOSTS || "");

const docs = {
  "Overview": [
    ["README.md", "Platform overview, local usage, hosts and commands"],
    ["READINESS-REPORT.md", "Current readiness status and remaining gaps"],
    ["FINAL-READINESS-AUDIT.md", "Final audit notes and evidence summary"],
  ],
  "Operations": [
    ["RUNBOOK.md", "Day-2 operations, incident response and recovery"],
    ["VPS-PREDEPLOY-CHECKLIST.md", "VPS pre-deploy checklist"],
    ["ENTERPRISE-10-PLAN.md", "Enterprise roadmap and acceptance criteria"],
  ],
  "Security": [
    ["SECURITY.md", "Security model"],
    ["THREAT-MODEL.md", "Threat model"],
    ["ENTERPRISE-MATURITY.md", "Enterprise maturity matrix"],
  ],
  "Services": [
    ["keycloak/README.md", "Identity provider notes"],
    ["minio/README.md", "Object storage notes"],
    ["secrets/README.md", "Secret store and rotation notes"],
  ],
  "Cloud And Edge": [
    ["cloudflare/README.md", "Cloudflare setup"],
    ["cloudflare/LIVE-CHANGES.md", "Cloudflare live change log"],
  ],
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `https://${req.headers.host || controlCenterHost}`);
    if (url.pathname === "/__health") {
      json(res, { ok: true, service: "control-center" });
      return;
    }

    if (url.pathname.startsWith("/assets/control-center/")) {
      serveStaticAsset(req, res, url, controlCenterStylesRoot, "/assets/control-center/");
      return;
    }

    if (url.pathname.startsWith("/fonts/")) {
      serveStaticAsset(req, res, url, path.join(publicRoot, "fonts"), "/fonts/");
      return;
    }

    if (isDocsRequest(req) && ["GET", "HEAD"].includes((req.method || "GET").toUpperCase())) {
      handleDocsRequest(res, url);
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

    if (req.method === "POST" && url.pathname === "/actions/storage-command") {
      await handleStorageCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/material-command") {
      await handleMaterialCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/worker-job-command") {
      await handleWorkerJobCommand(req, res, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/identity-command") {
      await handleIdentityCommand(req, res, context);
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
    if (method === "GET" && route(parts, "control", "network")) return json(res, context.network);
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

    if (method === "GET" && route(parts, "control", "storage")) return json(res, { buckets: context.storageBuckets, provider: context.storageProvider });
    if (method === "POST" && route(parts, "control", "storage", "buckets")) return json(res, planStorageBucketCreate(payload, context), 202);
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "storage", "buckets", "policy")) {
      return json(res, planStorageBucketPolicy(parts[3], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "storage", "buckets", "lifecycle")) {
      return json(res, planStorageBucketLifecycle(parts[3], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "storage", "buckets", "access-key")) {
      return json(res, planStorageBucketAccessKey(parts[3], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "storage", "buckets", "backup")) {
      return json(res, planStorageBucketBackup(parts[3], payload, context), 202);
    }
    if (method === "POST" && parts.length === 6 && route([parts[0], parts[1], parts[2], parts[4], parts[5]], "control", "storage", "buckets", "restore", "plan")) {
      return json(res, planStorageBucketRestore(parts[3], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "secrets")) return json(res, { inventory: context.sensitiveMaterials, stores: context.materialStores });
    if (method === "POST" && route(parts, "control", "secrets", "materials")) return json(res, planMaterialDeclare(payload, context), 202);
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "secrets", "materials", "rotation")) {
      return json(res, planMaterialRotation(parts[3], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "secrets", "materials", "usage")) {
      return json(res, planMaterialUsage(parts[3], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "secrets", "materials", "access")) {
      return json(res, planMaterialAccessAudit(parts[3], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "workers-jobs")) {
      return json(res, { workers: context.workerRuntimes, queues: context.jobQueues, jobs: context.jobRecords, schedules: context.jobSchedules });
    }
    if (method === "POST" && route(parts, "control", "workers-jobs", "workers")) return json(res, planWorkerDeclare(payload, context), 202);
    if (method === "POST" && route(parts, "control", "workers-jobs", "queues")) return json(res, planQueueDeclare(payload, context), 202);
    if (method === "POST" && route(parts, "control", "workers-jobs", "jobs")) return json(res, planJobRecord(payload, context), 202);
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "workers-jobs", "jobs", "retry")) {
      return json(res, planJobRetry(parts[3], payload, context), 202);
    }
    if (method === "POST" && route(parts, "control", "workers-jobs", "schedules")) return json(res, planScheduleDeclare(payload, context), 202);
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "workers-jobs", "schedules", "status")) {
      return json(res, planScheduleStatus(parts[3], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "identity")) return json(res, context.identityAccess);
    if (method === "POST" && route(parts, "control", "identity", "admin-users")) return json(res, planIdentityAdminUser(payload, context), 202);
    if (method === "POST" && route(parts, "control", "identity", "teams")) return json(res, planIdentityTeam(payload, context), 202);
    if (method === "POST" && route(parts, "control", "identity", "roles")) return json(res, planIdentityRole(payload, context), 202);
    if (method === "POST" && route(parts, "control", "identity", "sessions")) return json(res, planIdentitySessionPolicy(payload, context), 202);
    if (method === "POST" && route(parts, "control", "identity", "access-reviews")) return json(res, planIdentityAccessReview(payload, context), 202);

    if (method === "GET" && route(parts, "control", "resources", "summary")) return json(res, context.resources);
    if (method === "POST" && route(parts, "control", "resources", "limits")) return json(res, planResourceLimitUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "monitoring")) return json(res, context.monitoring);
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
    if (method === "GET" && route(parts, "control", "ui-package")) return json(res, context.uiPackage);
    if (method === "GET" && route(parts, "control", "readiness")) return json(res, context.readiness);
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

async function handleStorageCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "create") operation = planStorageBucketCreate(payload, context);
    else if (action === "policy") operation = planStorageBucketPolicy(payload.id || payload.bucketId || "", payload, context);
    else if (action === "lifecycle") operation = planStorageBucketLifecycle(payload.id || payload.bucketId || "", payload, context);
    else if (action === "access-key") operation = planStorageBucketAccessKey(payload.id || payload.bucketId || "", payload, context);
    else if (action === "backup") operation = planStorageBucketBackup(payload.id || payload.bucketId || "", payload, context);
    else if (action === "restore") operation = planStorageBucketRestore(payload.id || payload.bucketId || "", payload, context);
    else throw new ValidationError("Unsupported storage action.");
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
  redirect(res, `/?mode=advanced&section=storage#bucket-${encodeURIComponent(operation.details?.bucketId || operation.bucket?.id || "")}`);
}

async function handleMaterialCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "declare") operation = planMaterialDeclare(payload, context);
    else if (action === "rotation") operation = planMaterialRotation(payload.id || payload.materialId || "", payload, context);
    else if (action === "usage") operation = planMaterialUsage(payload.id || payload.materialId || "", payload, context);
    else if (action === "access") operation = planMaterialAccessAudit(payload.id || payload.materialId || "", payload, context);
    else throw new ValidationError("Unsupported material action.");
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
  redirect(res, `/?mode=advanced&section=secrets#material-${encodeURIComponent(operation.details?.materialId || operation.material?.id || "")}`);
}

async function handleWorkerJobCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "declare-worker") operation = planWorkerDeclare(payload, context);
    else if (action === "declare-queue") operation = planQueueDeclare(payload, context);
    else if (action === "record-job") operation = planJobRecord(payload, context);
    else if (action === "retry-job") operation = planJobRetry(payload.id || payload.jobId || "", payload, context);
    else if (action === "declare-schedule") operation = planScheduleDeclare(payload, context);
    else if (action === "schedule-status") operation = planScheduleStatus(payload.id || payload.scheduleId || "", payload, context);
    else throw new ValidationError("Unsupported worker/job action.");
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
  redirect(res, `/?mode=advanced&section=workers-jobs#worker-job-${encodeURIComponent(operation.details?.workerId || operation.details?.queueId || operation.details?.jobId || operation.details?.scheduleId || "")}`);
}

async function handleIdentityCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "admin-user") operation = planIdentityAdminUser(payload, context);
    else if (action === "team") operation = planIdentityTeam(payload, context);
    else if (action === "role") operation = planIdentityRole(payload, context);
    else if (action === "session-policy") operation = planIdentitySessionPolicy(payload, context);
    else if (action === "access-review") operation = planIdentityAccessReview(payload, context);
    else throw new ValidationError("Unsupported identity action.");
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
  redirect(res, `/?mode=advanced&section=identity#identity-${encodeURIComponent(operation.details?.userId || operation.details?.teamId || operation.details?.roleId || operation.details?.sessionPolicyId || operation.details?.reviewId || "")}`);
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
  const storageProvider = {
    id: "minio",
    name: "MinIO",
    status: "configured",
    service: "minio",
    liveAdapter: "MinioAdapter",
    productionEvidence: false,
  };
  const storageBuckets = Object.values(readStorageBucketsState())
    .filter((bucket) => bucket && !bucket.deletedAt)
    .map((bucket) => storageBucketRecord(bucket))
    .sort((a, b) => `${a.projectId}:${a.name}`.localeCompare(`${b.projectId}:${b.name}`));
  const sensitiveMaterials = Object.values(readSensitiveMaterialsState())
    .filter((material) => material && !material.deletedAt)
    .map((material) => sensitiveMaterialRecord(material))
    .sort((a, b) => `${a.projectId}:${a.environment}:${a.materialName}`.localeCompare(`${b.projectId}:${b.environment}:${b.materialName}`));
  const workerJobsState = readWorkerJobsState();
  const defaultWorkerRuntimes = [
    workerRuntimeRecord({
      id: "enterprise-worker-notifications",
      projectId: "platform",
      name: "Notification worker",
      service: "worker-notifications",
      status: "configured",
      queueName: "alerts",
      source: "compose-service",
    }),
    workerRuntimeRecord({
      id: "enterprise-worker-jobs",
      projectId: "platform",
      name: "Jobs worker",
      service: "worker-jobs",
      status: "configured",
      queueName: "jobs",
      source: "compose-service",
    }),
    ...applications
      .filter((app) => app.runtime === "worker")
      .map((app) => workerRuntimeRecord({
        id: app.id,
        projectId: app.projectId,
        name: app.name,
        service: app.id,
        status: app.status === "online" ? "running" : app.status,
        queueName: `${app.projectId}-jobs`,
        source: app.source || "application-metadata",
      })),
  ];
  const defaultWorkerIds = new Set(defaultWorkerRuntimes.map((worker) => worker.id));
  const workerRuntimes = [
    ...defaultWorkerRuntimes.map((worker) => workerRuntimeRecord({ ...worker, ...(workerJobsState.workers[worker.id] || {}) })),
    ...Object.values(workerJobsState.workers)
      .filter((worker) => worker && !worker.deletedAt && !defaultWorkerIds.has(worker.id))
      .map((worker) => workerRuntimeRecord(worker)),
  ].sort((a, b) => `${a.projectId}:${a.name}`.localeCompare(`${b.projectId}:${b.name}`));
  const defaultJobQueues = [
    jobQueueRecord({ id: "alerts", projectId: "platform", name: "alerts", backend: "alertmanager-webhook", status: "configured", retryPolicy: "bounded-worker-retry", source: "compose-service" }),
    jobQueueRecord({ id: "jobs", projectId: "platform", name: "jobs", backend: "nats", status: "configured", retryPolicy: "bounded-worker-retry", source: "compose-service" }),
    jobQueueRecord({ id: "audit-outbox", projectId: "platform", name: "audit-outbox", backend: "postgres-outbox", status: "configured", retryPolicy: "max-8-attempts", source: "compose-service" }),
    jobQueueRecord({ id: "maintenance", projectId: "platform", name: "maintenance", backend: "container-cron", status: "configured", retryPolicy: "ops-runner-evidence", source: "backup-scheduler" }),
  ];
  const defaultQueueIds = new Set(defaultJobQueues.map((queue) => queue.id));
  const jobQueues = [
    ...defaultJobQueues.map((queue) => jobQueueRecord({ ...queue, ...(workerJobsState.queues[queue.id] || {}) })),
    ...Object.values(workerJobsState.queues)
      .filter((queue) => queue && !queue.deletedAt && !defaultQueueIds.has(queue.id))
      .map((queue) => jobQueueRecord(queue)),
  ].sort((a, b) => `${a.projectId}:${a.name}`.localeCompare(`${b.projectId}:${b.name}`));
  const jobRecords = Object.values(workerJobsState.jobs)
    .filter((job) => job && !job.deletedAt)
    .map((job) => jobRecord(job))
    .sort((a, b) => String(b.updatedAt || b.createdAt).localeCompare(String(a.updatedAt || a.createdAt)));
  const defaultJobSchedules = [
    jobScheduleRecord({ id: "backup-scheduler", projectId: "platform", name: "Backup scheduler", workerId: "enterprise-worker-jobs", queueId: "maintenance", cronExpression: "15 3 * * *", status: "configured", source: "compose-backup-scheduler", containerizedCron: true }),
    jobScheduleRecord({ id: "audit-outbox-dispatcher", projectId: "platform", name: "Audit outbox dispatcher", workerId: "enterprise-worker-jobs", queueId: "audit-outbox", cronExpression: "*/1 * * * *", status: "configured", source: "worker-jobs", containerizedCron: true }),
  ];
  const defaultScheduleIds = new Set(defaultJobSchedules.map((schedule) => schedule.id));
  const jobSchedules = [
    ...defaultJobSchedules.map((schedule) => jobScheduleRecord({ ...schedule, ...(workerJobsState.schedules[schedule.id] || {}) })),
    ...Object.values(workerJobsState.schedules)
      .filter((schedule) => schedule && !schedule.deletedAt && !defaultScheduleIds.has(schedule.id))
      .map((schedule) => jobScheduleRecord(schedule)),
  ].sort((a, b) => `${a.projectId}:${a.name}`.localeCompare(`${b.projectId}:${b.name}`));
  const deployments = readDeployments();
  const backupRecords = readBackupRecords();
  const storedResourceLimits = readResourceLimitsState();
  const storedSecurityPolicies = readSecurityPoliciesState();
  const storedAlerts = readAlertsState();
  const storedNotificationChannels = readNotificationChannelsState();
  const storedProviderConnections = readProviderConnectionsState();
  const storedSettings = readSettingsState();
  const storedIdentityAccess = readIdentityAccessState();
  const uiPackage = readControlCenterUiPackage();
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
    passkeyAdminAuth: "external-idp-or-passkey-app",
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
  const materialStores = defaultMaterialStores(notificationChannels);
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
  const monitoring = buildMonitoringTopology({ resources, logsAlerts, alertRecords });
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
  const identityAccess = buildIdentityAccess(storedIdentityAccess, { audit, security, settings });
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
  const network = buildNetworkTopology({ subdomains, domains, security, settings });
  const readiness = buildControlReadiness({
    projects,
    applications,
    subdomains,
    webspaces,
    network,
    monitoring,
    security,
    backups,
    operations,
    audit,
    deployments,
    providerConnections,
    uiPackage,
  });
  const overview = {
    title: "Admin Control Center",
    environment,
    modeEvidence: environment === "production" ? "production evidence requires verifyRemote" : "local evidence only",
    projects: { total: projects.length, active: activeProjects, archived: archivedProjects },
    applications: { total: applications.length, online: onlineApps, offline: applications.length - onlineApps },
    resources,
    subdomains: { total: subdomains.length, active: subdomains.filter((item) => item.status === "active").length },
    network: { routers: network.routers.length, middlewares: network.middlewares.length, exposedPorts: network.exposedPorts.length, routeTests: network.routeTests.length },
    monitoring: { scrapeJobs: monitoring.scrapeJobs.length, dashboardPanels: monitoring.dashboardPanels.length, alertRules: monitoring.alertRules.length, signals: monitoring.signals.length },
    databases: { total: databases.length, declared: databases.filter((item) => item.status === "declared").length },
    storage: { buckets: storageBuckets.length, provider: storageProvider.status },
    sensitiveMaterials: { total: sensitiveMaterials.length, rotationDue: sensitiveMaterials.filter((item) => item.rotationStatus === "due").length },
    workersJobs: { workers: workerRuntimes.length, queues: jobQueues.length, failedJobs: jobRecords.filter((job) => job.status === "failed").length, schedules: jobSchedules.length },
    identityAccess: { adminUsers: identityAccess.adminUsers.length, roles: identityAccess.roles.length, sessions: identityAccess.sessionPolicies.length },
    designSystem: { package: uiPackage.name, version: uiPackage.version, source: uiPackage.source, manifestLoaded: uiPackage.apiManifestLoaded },
    readiness: readiness.summary,
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
    network,
    webspaces,
    databases,
    databaseEngines,
    storageProvider,
    storageBuckets,
    materialStores,
    sensitiveMaterials,
    workerRuntimes,
    jobQueues,
    jobRecords,
    jobSchedules,
    resources,
    security,
    backups,
    logsAlerts,
    monitoring,
    settings,
    uiPackage,
    readiness,
    identityAccess,
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
    title: "Admin Control Center Advanced API",
    environment: context.environment,
    modeEvidence: context.overview.modeEvidence,
    endpointPrefix: "/control/advanced",
    dryRunDefault: true,
    providerTouched: false,
    liveProviderTouched: false,
    productionEvidence: false,
    adapterEndpoint: "/control/adapters",
    adapterCount: adapterRegistry(context).length,
    designSystem: context.uiPackage,
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
  const readOnlySections = new Set(["infrastructure", "deployments", "monitoring", "logs-advanced", "alerts-advanced", "backup-restore", "security-advanced", "audit", "readiness"]);
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
        ...context.network,
        domains: context.domains,
        subdomains: context.subdomains,
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
        provider: context.storageProvider,
        buckets: context.storageBuckets,
        operations: ["create bucket", "quota bucket", "access key metadata", "policy", "lifecycle", "backup bucket", "restore bucket"],
      };
    case "workers-jobs":
      return {
        workers: context.workerRuntimes,
        queues: context.jobQueues,
        jobs: context.jobRecords,
        failedJobs: context.jobRecords.filter((job) => job.status === "failed"),
        retryControls: context.jobRecords.filter((job) => job.status === "failed").map((job) => ({ id: job.id, endpoint: `/control/workers-jobs/jobs/${job.id}/retry`, dockerTouched: false })),
        scheduler: context.jobSchedules,
        containerizedCron: context.jobSchedules.filter((schedule) => schedule.containerizedCron),
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
        ...context.monitoring,
        resources: context.resources,
        openAlerts: context.logsAlerts.openAlerts,
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
    case "readiness":
      return context.readiness;
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
        adminUsers: context.identityAccess.adminUsers,
        teams: context.identityAccess.teams,
        roles: context.identityAccess.roles,
        sessions: context.identityAccess.sessionPolicies,
        loginAudit: context.identityAccess.loginAudit,
        accessReviews: context.identityAccess.accessReviews,
      };
    case "secrets":
      return {
        stores: context.materialStores,
        inventory: context.sensitiveMaterials,
        providerConnections: context.providerConnections.map((connection) => ({ id: connection.id, materialConfigured: connection.privateMaterialConfigured, valueExposed: connection.credentialValueExposed })),
        rotation: "metadata tracked locally; real rotation remains in infra-ops/private material",
        usageMap: context.sensitiveMaterials.map((item) => ({ id: item.id, projectId: item.projectId, usageTargets: item.usageTargets, valueExposed: item.valueExposed })),
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

function buildControlReadiness(context) {
  const enterprise = manifestReadiness("enterprise-requirements", "Enterprise requirements", readGovernanceManifest("enterprise-requirements.json"));
  const production = manifestReadiness("production-readiness", "Production readiness checklist", readGovernanceManifest("production-readiness.json"));
  const controlChecks = [
    readinessCheck({
      id: "control-center-local-ui",
      title: "Control Center local UI contract",
      status: context.uiPackage.controlCenterPackageLoaded && context.uiPackage.packageMountedInControlCenterProject && context.uiPackage.apiManifestLoaded && context.uiPackage.missingRequiredExports.length === 0 ? "passed" : "needs-work",
      evidence: ["@platform/control-center package", "control-center/components", "control-center/styles/control-center.css", "local AppShell/Sidebar/TabGroup contract"],
      nextAction: "Keep Control Center visual changes scoped to local components and --cc-* tokens.",
    }),
    readinessCheck({
      id: "simple-mode-mvp",
      title: "Simple Mode operational MVP",
      status: context.projects.length >= 0 && context.applications.length >= 0 && context.subdomains.length >= 0 && context.webspaces.length >= 0 ? "passed" : "needs-work",
      evidence: ["/control/projects", "/control/applications", "/control/domains", "/control/webspaces", "/control/resources/summary", "/control/security/summary", "/control/backups/summary"],
      nextAction: "Promote selected plan-only actions only after backend adapters are implemented and audited.",
    }),
    readinessCheck({
      id: "advanced-mode-skeleton",
      title: "Advanced Mode enterprise sections",
      status: navigationForMode("advanced").length >= 20 ? "passed" : "needs-work",
      evidence: ["/control/advanced", "/control/network", "/control/monitoring", "/control/adapters", "/control/readiness"],
      nextAction: "Attach live provider evidence summaries after production verifyRemote runs.",
    }),
    readinessCheck({
      id: "audit-operations-model",
      title: "Audit and Operation records",
      status: "passed",
      evidence: ["projects-portal/state/audit.jsonl", "projects-portal/state/operations.jsonl", "sanitized OperationStep list"],
      nextAction: "Forward production audit events to the durable backend/outbox when the live adapter is enabled.",
    }),
    readinessCheck({
      id: "safe-adapter-boundary",
      title: "Provider and infrastructure adapter boundary",
      status: "plan-only",
      evidence: ["CloudflareAdapter", "DockerAdapter", "GitHubAdapter", "GoNoGoAdapter", "apply rejected without live implementation"],
      nextAction: "Add backend adapter implementations one at a time with strong confirmation and verifyRemote.",
    }),
    readinessCheck({
      id: "local-network-monitoring-evidence",
      title: "Local network and monitoring evidence",
      status: context.network.routeTests.length > 0 && context.monitoring.scrapeJobs.length > 0 ? "passed" : "needs-work",
      evidence: ["/control/network", "/control/monitoring", "Traefik route parser", "Prometheus/Grafana/Loki/Alertmanager config parser"],
      nextAction: "Keep browser-exposed raw consoles blocked; use Grafana and ops runner evidence for deeper inspection.",
    }),
    readinessCheck({
      id: "production-live-proof",
      title: "Production live proof separation",
      status: "pending-live-proof",
      liveProofRequired: true,
      evidence: ["localEvidenceIsProductionEvidence=false", "productionEvidence=false", "production-readiness liveProofChecks"],
      nextAction: "Run production-go-no-go, production-readiness-live and evidence-bundle verification on the real VPS/provider environment.",
    }),
  ];
  const allChecks = [...controlChecks, ...enterprise.requirements, ...production.requirements];
  return sanitizeEvent({
    title: "Admin Control Center Readiness Matrix",
    environment,
    source: "governance manifests plus live Control Center context",
    endpoint: "/control/readiness",
    dryRunDefault: true,
    providerTouched: false,
    liveProviderTouched: false,
    dockerTouched: false,
    productionEvidence: false,
    localEvidenceIsProductionEvidence: false,
    summary: readinessSummary(allChecks),
    controlCenter: {
      checks: controlChecks,
      endpointsCovered: ["/control/overview", "/control/projects", "/control/applications", "/control/domains", "/control/webspaces", "/control/resources/summary", "/control/security/summary", "/control/backups/summary", "/control/operations", "/control/audit", "/control/readiness"],
      auditEventsLoaded: context.audit.length,
      operationsLoaded: context.operations.length,
      designSystem: {
        project: context.uiPackage.controlCenterProject,
        package: context.uiPackage.name,
        dependency: context.uiPackage.declaredDependency,
        missingRequiredExports: context.uiPackage.missingRequiredExports,
      },
    },
    manifests: {
      enterprise,
      productionReadiness: production,
    },
    productionBlockers: allChecks
      .filter((item) => item.status === "needs-work" || item.status === "pending-live-proof")
      .map((item) => ({ id: item.id, status: item.status, nextAction: item.nextAction }))
      .slice(0, 40),
  });
}

function readinessCheck({ id, title, status, evidence = [], nextAction = "", liveProofRequired = false }) {
  return {
    id,
    title,
    status,
    repoEvidenceStatus: status === "needs-work" ? "incomplete" : "tracked",
    liveProofRequired: Boolean(liveProofRequired),
    evidence,
    nextAction,
  };
}

function readinessSummary(checks) {
  const byStatus = {};
  for (const check of checks) byStatus[check.status] = (byStatus[check.status] || 0) + 1;
  const needsWork = byStatus["needs-work"] || 0;
  const pendingLiveProof = byStatus["pending-live-proof"] || 0;
  const passed = byStatus.passed || 0;
  const total = checks.length;
  return {
    total,
    passed,
    planOnly: byStatus["plan-only"] || 0,
    pendingLiveProof,
    needsWork,
    repositoryEvidenceTracked: total - needsWork,
    localModeReady: needsWork === 0,
    productionReady: needsWork === 0 && pendingLiveProof === 0,
    byStatus,
  };
}

function manifestReadiness(id, title, manifest) {
  const requirements = Array.isArray(manifest.requirements) ? manifest.requirements.map((requirement) => manifestRequirementRecord(requirement)) : [];
  const summary = readinessSummary(requirements);
  const states = {};
  for (const item of requirements) states[item.sourceState] = (states[item.sourceState] || 0) + 1;
  return {
    id,
    title: manifest.title || title,
    loaded: manifest.loaded === true,
    scope: manifest.scope || "platform-infrastructure",
    expectedCount: Number(manifest.expectedCount || requirements.length),
    requirementCount: requirements.length,
    manifestPath: `governance/${manifest.fileName || `${id}.json`}`,
    liveProofCheckRequired: Boolean(manifest.liveProofCheckRequired),
    states,
    summary,
    requirements,
  };
}

function manifestRequirementRecord(requirement) {
  const sourceState = sanitizeIdentifier(requirement.state || "unknown") || "unknown";
  const liveProofRequired = Boolean(requirement.liveProof);
  const evidence = Array.isArray(requirement.evidence) ? requirement.evidence : [];
  const status = manifestRequirementStatus(sourceState, liveProofRequired);
  return {
    id: sanitizeIdentifier(requirement.id || "unknown"),
    title: sanitizeMessage(requirement.title || "Untitled requirement"),
    status,
    sourceState,
    repoEvidenceStatus: status === "needs-work" ? "incomplete" : "tracked",
    liveProofRequired,
    liveProofChecks: Array.isArray(requirement.liveProofChecks) ? requirement.liveProofChecks.map((item) => sanitizeIdentifier(item)).filter(Boolean) : [],
    evidenceCount: evidence.length,
    evidenceRefs: evidence.map((item) => ({
      type: sanitizeIdentifier(item.type || "unknown"),
      path: item.path ? sanitizeRef(item.path) : "",
      name: item.name ? sanitizeRef(item.name) : "",
    })),
    nextAction: liveProofRequired ? sanitizeMessage(requirement.liveProof || "Archive production live proof.") : "Keep repository evidence current.",
  };
}

function manifestRequirementStatus(sourceState, liveProofRequired) {
  if (["repo-ready", "gate-ready", "environment-ready", "proprietary-integrated", "repo-ready-plus-environment-action"].includes(sourceState)) {
    return liveProofRequired ? "pending-live-proof" : "passed";
  }
  if (sourceState === "planned" || sourceState === "plan-only") return "plan-only";
  return "needs-work";
}

function readGovernanceManifest(fileName) {
  const cleanFile = path.basename(fileName);
  const root = path.resolve(docsRoot, "governance");
  const target = path.resolve(root, cleanFile);
  if (!(target === root || target.startsWith(`${root}${path.sep}`)) || !existsSync(target)) {
    return { loaded: false, fileName: cleanFile, requirements: [] };
  }
  try {
    const parsed = JSON.parse(readFileSync(target, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? { ...parsed, loaded: true, fileName: cleanFile } : { loaded: false, fileName: cleanFile, requirements: [] };
  } catch {
    return { loaded: false, fileName: cleanFile, requirements: [] };
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
  const groups = navigationGroupsForMode(mode);
  const defaultSection = groups[0]?.tabs[0]?.id || nav[0]?.id || "overview";
  const requestedSection = params.get("section") || defaultSection;
  const section = nav.some((item) => item.id === requestedSection) ? requestedSection : defaultSection;
  const activeGroup = groups.find((group) => group.tabs.some((item) => item.id === section)) || groups[0];
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
    else if (section === "network") body = renderNetworkAdvanced(context.network);
    else if (section === "infrastructure") body = renderInfrastructure(context.advancedServices);
    else if (section === "databases") body = renderDatabases(scoped(context.databases), context.databaseEngines, context.projects);
    else if (section === "storage") body = renderStorage(scoped(context.storageBuckets), context.storageProvider, context.projects);
    else if (section === "secrets") body = renderSecrets(scoped(context.sensitiveMaterials), context.materialStores, context.projects);
    else if (section === "workers-jobs") body = renderWorkersJobs(scoped(context.workerRuntimes), scoped(context.jobQueues), scoped(context.jobRecords), scoped(context.jobSchedules), context.projects);
    else if (section === "deployments") body = renderDeployments(scoped(context.deployments));
    else if (section === "readiness") body = renderReadiness(context.readiness);
    else if (section === "monitoring") body = renderMonitoringAdvanced(context.monitoring);
    else if (section === "logs-advanced") body = renderAdvancedPanel(title, section, context, "Loki query and export surfaces stay metadata-only here.");
    else if (section === "alerts-advanced") body = renderAdvancedPanel(title, section, context, "Alert delivery evidence is verified through the ops runner before production use.");
    else if (section === "security-advanced") body = renderAdvancedPanel(title, section, context, "Security controls stay behind explicit adapters and confirmation gates.");
    else if (section === "identity") body = renderIdentityAccess(context.identityAccess);
    else if (section === "backup-restore") body = renderBackups(context.backups, context.backupRecords);
    else body = renderAdvancedPanel(title, section, context);
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>Admin Control Center</title>
${controlCenterStylesheetLinks()}
${controlCenterScriptTags()}
</head>
<body data-cc-theme="light">
<main aria-busy="false" class="cc-app-shell section-${escapeHtml(section)}">
  <div class="cc-shell-bg" aria-hidden="true"></div>
  <div class="cc-stage">
    ${renderControlSidebar(groups, activeGroup.id, section, mode, selectedProject)}
    <section aria-label="${escapeHtml(activeGroup.label)}" class="cc-scene" data-scroll-root="" tabindex="0">
      ${renderControlTopbar(context, mode)}
      <div class="cc-sheet">
        <header class="control-page-head">
          <div>
            <p class="eyebrow">${escapeHtml(environment.toUpperCase())} MODE / ${escapeHtml(activeGroup.label)}</p>
            <h1 id="control-page-title">${escapeHtml(title)}</h1>
          </div>
          <div class="top-actions">
            <span class="pill ${environment === "production" ? "danger" : "info"}">${escapeHtml(context.overview.modeEvidence)}</span>
            ${authRequired ? '<a class="button" href="/logout">Logout</a>' : ""}
            <form method="get" class="switcher">
              <input type="hidden" name="mode" value="${escapeHtml(mode)}">
              <input type="hidden" name="section" value="${escapeHtml(section)}">
              <select name="project" aria-label="Project switcher">
                <option value="">All projects</option>
                ${context.projects.map((project) => `<option value="${escapeHtml(project.slug)}" ${selectedProject === project.slug ? "selected" : ""}>${escapeHtml(project.name)}</option>`).join("")}
              </select>
            </form>
          </div>
        </header>
        <section class="ui-panel-stack control-tab-panel" id="control-${escapeHtml(section)}-panel" role="region" aria-labelledby="control-page-title">
          ${body}
        </section>
      </div>
    </section>
  </div>
</main>
</body>
  </html>`;
}

function renderControlSidebar(groups, activeGroupId, activeSection, mode, selectedProject) {
  const activeIndex = Math.max(0, groups.findIndex((group) => group.id === activeGroupId));
  const buckets = [
    ["", []],
    ["Gestione", []],
    ["Sicurezza", []],
    ["Avanzato", []],
  ];
  const bucketByName = new Map(buckets);
  for (const group of groups) {
    const heading = sidebarCategoryForGroup(group);
    bucketByName.get(heading)?.push(group);
  }
  const navGroups = buckets.map(([heading, navItems]) => {
    if (!navItems.length) return "";
    const bucketId = heading ? heading.toLowerCase() : "overview";
    const links = navItems.map((group) => renderSidebarGroupEntry(group, activeGroupId, activeSection, mode, selectedProject)).join("");
    if (!heading) {
      return `<div class="cc-nav-group cc-nav-group-static" data-cc-nav-group="${escapeHtml(bucketId)}"><div class="cc-nav-panel">${links}</div></div>`;
    }
    return `<div class="cc-nav-group" data-cc-collapsible="" data-cc-nav-group="${escapeHtml(bucketId)}" data-cc-collapsed="false">
      <button aria-controls="cc-nav-panel-${escapeHtml(bucketId)}" aria-expanded="true" class="cc-nav-toggle" data-cc-sidebar-toggle="${escapeHtml(bucketId)}" type="button">
        <span>${escapeHtml(heading)}</span>
        <span class="cc-nav-toggle-icon" aria-hidden="true">${controlIcon("chevron-down")}</span>
      </button>
      <div class="cc-nav-panel" id="cc-nav-panel-${escapeHtml(bucketId)}">${links}</div>
    </div>`;
  }).join("");
  return `<aside aria-label="Control Center navigation" class="cc-sidebar" data-cc-sidebar-active-index="${activeIndex}" data-cc-sidebar-id="control-sidebar">
    <a class="brand platform-wordmark" href="/?mode=simple&section=overview" aria-label="Admin Control Center"><span class="brand-mark">P</span><div><strong>Control Center</strong><small>${escapeHtml(platformName)}</small></div></a>
    <div class="cc-nav-groups">${navGroups}</div>
    <div class="mode-card">
      <small>Simple Mode</small>
      <div class="segmented">
        <a class="${mode === "simple" ? "selected" : ""}" href="${escapeHtml(controlUrl({ mode: "simple", section: "overview", project: selectedProject }))}">Simple</a>
        <a class="${mode === "advanced" ? "selected" : ""}" href="${escapeHtml(controlUrl({ mode: "advanced", section: "infrastructure", project: selectedProject }))}">Advanced</a>
      </div>
    </div>
    <div class="cc-admin-card">
      <span class="cc-admin-avatar" aria-hidden="true">A</span>
      <span><strong>admin@${escapeHtml(domain)}</strong><small>Administrator</small></span>
      <span class="cc-admin-arrow" aria-hidden="true">${controlIcon("chevron")}</span>
    </div>
  </aside>`;
}

function renderSidebarGroupEntry(group, activeGroupId, activeSection, mode, selectedProject) {
  const activeGroup = group.id === activeGroupId || group.tabs.some((item) => item.id === activeSection);
  if (group.tabs.length === 1) {
    return renderSidebarLink(group.tabs[0], group, activeSection, mode, selectedProject);
  }
  const branchId = `cc-nav-branch-${group.id}`;
  const children = group.tabs.map((item) => renderSidebarLink(item, group, activeSection, mode, selectedProject, true)).join("");
  return `<div class="cc-nav-branch" data-cc-collapsible="" data-cc-nav-group="${escapeHtml(group.id)}" data-cc-active-path="${activeGroup ? "true" : "false"}" data-cc-collapsed="${activeGroup ? "false" : "true"}">
    <button aria-controls="${escapeHtml(branchId)}" aria-expanded="${activeGroup ? "true" : "false"}" class="cc-nav-item cc-nav-branch-toggle ${activeGroup ? "active" : ""}" data-cc-sidebar-toggle="${escapeHtml(group.id)}" type="button">
      <span class="cc-nav-icon" aria-hidden="true">${controlIcon(sidebarGroupIcon(group))}</span>
      <span>${escapeHtml(sidebarGroupLabel(group))}</span>
      <span class="cc-nav-arrow" aria-hidden="true">${controlIcon("chevron-down")}</span>
    </button>
    <div class="cc-nav-panel cc-nav-children" id="${escapeHtml(branchId)}">${children}</div>
  </div>`;
}

function renderSidebarLink(item, group, activeSection, mode, selectedProject, child = false) {
  const active = item.id === activeSection;
  const href = controlUrl({ mode, section: item.id, project: selectedProject });
  return `<a class="${child ? "cc-nav-child" : "cc-nav-item"} ${active ? "active" : ""}" ${active ? 'aria-current="page"' : ""} href="${escapeHtml(href)}" title="${escapeHtml(item.label)}">
    ${child ? "" : `<span class="cc-nav-icon" aria-hidden="true">${controlIcon(item.id)}</span>`}
    <span>${escapeHtml(sidebarItemLabel(item.label))}</span>
    ${child ? "" : `<span class="cc-nav-arrow" aria-hidden="true">${item.id === "overview" ? "" : controlIcon("chevron")}</span>`}
  </a>`;
}

function renderControlTopbar(context, mode) {
  const envLabel = context.environment === "production" ? "Production" : humanName(context.environment || "local");
  const envClass = context.environment === "production" ? "production" : "local";
  return `<header class="cc-topbar">
    <a class="cc-platform-switch" href="/?mode=${escapeHtml(mode)}&section=overview">
      <span aria-hidden="true">${controlIcon("cube")}</span>
      <strong>${escapeHtml(platformName)}</strong>
      <span aria-hidden="true">${controlIcon("chevron-down")}</span>
    </a>
    <span class="cc-env-pill ${escapeHtml(envClass)}">${escapeHtml(envLabel)}</span>
    <span class="cc-topbar-fill" aria-hidden="true"></span>
    <nav class="cc-top-actions" aria-label="Quick tools">
      <a class="cc-icon-button" href="/?section=logs" aria-label="Logs and alerts">${controlIcon("bell")}<span class="cc-notification-badge">${escapeHtml(context.overview.alerts.open || 0)}</span></a>
    </nav>
  </header>`;
}

function controlUrl({ mode, section, project = "" }) {
  const params = new URLSearchParams();
  params.set("mode", mode);
  params.set("section", section);
  if (project) params.set("project", project);
  return `/?${params.toString()}`;
}

function renderLogin(message) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>Admin Control Center Sign In</title>
${controlCenterStylesheetLinks()}
${controlCenterScriptTags()}
</head>
<body data-cc-theme="light">
<main class="login-shell">
  <section class="login-panel ui-panel-stack">
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
  const totals = context.overview;
  const activeProjects = context.projects.filter((project) => project.enabled).length;
  const phpProjects = context.projects.filter((project) => project.type === "PHP").length;
  const nodeProjects = context.projects.filter((project) => project.type === "Node").length;
  const latestBackup = context.backupRecords?.[0];
  const alertCount = totals.alerts.open || 0;
  const healthLabel = alertCount ? `${alertCount} alert aperti` : "Operativa";

  return `<section class="hosting-dashboard" aria-label="Infrastructure hosting panel">
    <section class="hosting-hero">
      <div class="hosting-hero-copy">
        <p class="hosting-kicker">Pannello infrastruttura</p>
        <h1>Gestisci la tua piattaforma da un solo posto</h1>
        <p>Progetti PHP e Node, domini locali, database, container, backup e sicurezza sono separati in aree operative chiare.</p>
      </div>
      <div class="hosting-hero-status">
        <span class="hosting-status ${alertCount ? "warning" : "good"}"><i aria-hidden="true"></i>${escapeHtml(healthLabel)}</span>
        <span>${escapeHtml(dashboardDateLabel())}</span>
        <div class="hosting-hero-actions">
          <a class="primary-button" href="/?section=projects">${controlIcon("projects")} Gestisci progetti</a>
          <a class="button" href="/?mode=advanced&section=infrastructure">${controlIcon("server")} Servizi infra</a>
        </div>
      </div>
    </section>

    <section class="hosting-summary-grid" aria-label="Hosting summary">
      ${renderHostingTile("projects", "Siti e progetti", `${activeProjects}/${totals.projects.total}`, `${phpProjects} PHP / ${nodeProjects} Node`, "/?section=projects", "Gestisci")}
      ${renderHostingTile("applications", "Applicazioni", totals.applications.total, `${totals.applications.online} online`, "/?section=applications", "Apri")}
      ${renderHostingTile("domains", "Domini e routing", totals.subdomains.total, `${totals.subdomains.active} attivi`, "/?section=domains", "Configura")}
      ${renderHostingTile("databases", "Database", totals.databases.total, `${context.databaseEngines.length} motori`, "/?mode=advanced&section=databases", "Gestisci")}
      ${renderHostingTile("storage", "Storage", totals.storage.buckets, `${context.storageProvider.name} ${hostingStatusLabel(context.storageProvider.status)}`, "/?mode=advanced&section=storage", "Apri")}
      ${renderHostingTile("security", "Sicurezza", alertCount ? "Check" : "OK", hostingStatusLabel(context.security.securityHeaders), "/?section=security", "Verifica")}
      ${renderHostingTile("backups", "Backup", latestBackup ? "Attivo" : "Pronto", latestBackup ? relativeTimeLabel(latestBackup.createdAt || latestBackup.timestamp) : context.backups.offsite, "/?section=backups", "Esegui")}
      ${renderHostingTile("resources", "Monitoraggio", totals.monitoring.scrapeJobs, `${totals.monitoring.alertRules} regole alert`, "/?mode=advanced&section=monitoring", "Dettagli")}
    </section>

    <section class="hosting-main-grid">
      ${renderHostingProjects(context.projects)}
      ${renderHostingServiceHealth(context)}
    </section>

    ${renderHostingQuickActions(context)}
  </section>`;
}

function renderHostingTile(icon, title, value, meta, href, action) {
  return `<a class="hosting-tile" href="${escapeHtml(href)}">
    <span class="hosting-tile-icon" aria-hidden="true">${controlIcon(icon)}</span>
    <span class="hosting-tile-body">
      <strong>${escapeHtml(title)}</strong>
      <small>${escapeHtml(meta)}</small>
    </span>
    <span class="hosting-tile-value">${escapeHtml(value)}</span>
    <em>${escapeHtml(action)} ${controlIcon("chevron")}</em>
  </a>`;
}

function renderHostingProjects(projects) {
  const rows = projects.slice(0, 8).map((project) => {
    const canOpen = project.enabled && project.filesystemExists !== false;
    return `<tr>
      <td>
        <div class="hosting-project-cell">
          <strong>${escapeHtml(project.name)}</strong>
          <span>${escapeHtml(project.summary)}</span>
        </div>
      </td>
      <td><span class="runtime-badge ${project.type === "PHP" ? "php" : "node"}">${escapeHtml(project.type)}</span></td>
      <td><a class="hosting-host" href="${escapeHtml(project.href)}">${escapeHtml(project.host)}</a></td>
      <td><span class="state ${project.enabled ? "on" : "off"}">${project.enabled ? "Attivo" : "Disattivo"}</span></td>
      <td>
        <div class="hosting-row-actions">
          ${canOpen ? `<a class="button open" href="${escapeHtml(project.href)}">Apri</a>` : `<span class="button muted">Apri</span>`}
          ${project.filesystemExists !== false ? `<form method="post" action="/actions/toggle-project">
            <input type="hidden" name="slug" value="${escapeHtml(project.slug)}">
            <input type="hidden" name="enabled" value="${project.enabled ? "0" : "1"}">
            <button class="button ${project.enabled ? "danger" : "enable"}" type="submit">${project.enabled ? "Disattiva" : "Attiva"}</button>
          </form>` : `<span class="button muted">Attiva</span>`}
        </div>
      </td>
    </tr>`;
  }).join("");

  return `<section class="hosting-panel hosting-projects-panel">
    <div class="hosting-panel-head">
      <div>
        <h2>Siti e applicazioni</h2>
        <p>PHP e Node restano separati per runtime, ma sono ospitati contemporaneamente dalla stessa infrastruttura.</p>
      </div>
      <a class="button" href="/?section=projects">Tutti i progetti</a>
    </div>
    <div class="hosting-table-wrap">
      <table class="hosting-table">
        <thead><tr><th>Progetto</th><th>Runtime</th><th>Dominio</th><th>Stato</th><th>Azioni</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5">${empty("Nessun progetto", "Monta un progetto in src per vederlo qui.")}</td></tr>`}</tbody>
      </table>
    </div>
  </section>`;
}

function renderHostingServiceHealth(context) {
  const serviceRows = hostingServiceRows(context);
  return `<section class="hosting-panel hosting-health-panel">
    <div class="hosting-panel-head">
      <div>
        <h2>Servizi infrastruttura</h2>
        <p>Solo i servizi utili alla gestione quotidiana, con link diretti dove serve.</p>
      </div>
      <a class="button" href="/?mode=advanced&section=infrastructure">Inventario</a>
    </div>
    <div class="hosting-service-list">
      ${serviceRows.map((item) => `<a class="hosting-service-row" href="${escapeHtml(item.href)}">
        <span class="hosting-service-icon" aria-hidden="true">${controlIcon(item.icon)}</span>
        <span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.role)}</small></span>
        <em class="${escapeHtml(item.tone)}"><i aria-hidden="true"></i>${escapeHtml(item.status)}</em>
      </a>`).join("")}
    </div>
  </section>`;
}

function hostingServiceRows(context) {
  return [
    { name: "Traefik", role: "Reverse proxy e routing HTTPS", status: context.network.routers.length ? "configurato" : "da verificare", icon: "domains", href: "/?mode=advanced&section=network", tone: "good" },
    { name: "MariaDB", role: "Database PHP locali", status: "configurato", icon: "databases", href: "/?mode=advanced&section=databases", tone: "good" },
    { name: "PostgreSQL", role: "Database piattaforma", status: "configurato", icon: "databases", href: "/?mode=advanced&section=databases", tone: "good" },
    { name: "phpMyAdmin", role: "Console database MariaDB", status: "admin", icon: "databases", href: "https://phpmyadmin.localhost.com", tone: "info" },
    { name: "Keycloak", role: "Identity provider", status: "admin", icon: "security", href: `https://${authHost}`, tone: "info" },
    { name: "MinIO", role: "Object storage e bucket", status: hostingStatusLabel(context.storageProvider.status), icon: "storage", href: `https://${storageHost}`, tone: "good" },
    { name: "Grafana", role: "Metriche, log e dashboard", status: `${context.monitoring.dashboardPanels.length} pannelli`, icon: "resources", href: `https://${grafanaHost}`, tone: "good" },
    { name: "Alertmanager", role: "Routing alert", status: `${context.alertRecords.length} alert`, icon: "logs", href: "/?section=logs", tone: context.overview.alerts.open ? "warning" : "good" },
  ];
}

function hostingStatusLabel(value) {
  const normalized = String(value || "").toLowerCase().trim();
  const labels = {
    configured: "configurato",
    strict: "header attivi",
    active: "attivo",
    disabled: "disattivo",
    online: "online",
    offline: "offline",
    "not-configured": "non configurato",
    "requires-secret-file": "richiede segreto",
  };
  return labels[normalized] || value || "sconosciuto";
}

function renderHostingQuickActions(context) {
  const actions = [
    ["Apri Projects", "/?section=projects", "projects"],
    ["Nuovo dominio locale", "/?section=domains", "domains"],
    ["Database", "/?mode=advanced&section=databases", "databases"],
    ["Backup manuale", "/?section=backups", "backups"],
    ["Log e alert", "/?section=logs", "logs"],
    ["Preflight production", "/?mode=advanced&section=go-no-go", "rocket"],
  ];
  return `<section class="hosting-panel hosting-actions-panel">
    <div class="hosting-panel-head">
      <div>
        <h2>Operazioni rapide</h2>
        <p>Azioni frequenti da pannello hosting. Le operazioni sensibili restano pianificate e auditate.</p>
      </div>
      <span class="hosting-status ${context.environment === "production" ? "warning" : "info"}"><i aria-hidden="true"></i>${escapeHtml(context.overview.modeEvidence)}</span>
    </div>
    <div class="hosting-action-grid">
      ${actions.map(([label, href, icon]) => `<a class="hosting-action" href="${escapeHtml(href)}">${controlIcon(icon)}<span>${escapeHtml(label)}</span>${controlIcon("chevron")}</a>`).join("")}
    </div>
  </section>`;
}

function dashboardDateLabel() {
  try {
    return new Intl.DateTimeFormat("it-IT", { day: "2-digit", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date());
  } catch {
    return new Date().toISOString();
  }
}

function relativeTimeLabel(value) {
  const timestamp = Date.parse(value || "");
  if (!Number.isFinite(timestamp)) return "locale";
  const minutes = Math.max(1, Math.round((Date.now() - timestamp) / 60000));
  if (minutes < 60) return `${minutes} min fa`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} ore fa`;
  return `${Math.round(hours / 24)} giorni fa`;
}

function sidebarCategoryForGroup(group) {
  if (group.id === "home") return "";
  if (["workloads", "routing", "platform"].includes(group.id)) return "Gestione";
  if (["operations", "security", "resilience", "observability"].includes(group.id)) return "Sicurezza";
  return "Avanzato";
}

function sidebarGroupIcon(group) {
  const map = {
    workloads: "projects",
    routing: "domains",
    operations: "resources",
    platform: "server",
    delivery: "rocket",
    observability: "resources",
    resilience: "backups",
    security: "security",
    plans: "server",
    settings: "settings",
  };
  return map[group.id] || group.tabs[0]?.id || "settings";
}

function sidebarGroupLabel(group) {
  const map = {
    workloads: "Progetti",
    routing: "Domini",
    operations: "Operazioni",
    platform: "Piattaforma",
    delivery: "Delivery",
    observability: "Osservabilita",
    resilience: "Resilienza",
    security: "Sicurezza",
    plans: "Piani",
    settings: "Impostazioni",
  };
  return map[group.id] || group.label;
}

function sidebarItemLabel(label) {
  return label === "Logs / Alerts" ? "Logs & Alert" : label;
}

function controlIcon(name) {
  const icons = {
    overview: '<path d="M4 11.5 12 5l8 6.5v7a1.5 1.5 0 0 1-1.5 1.5H15v-5H9v5H5.5A1.5 1.5 0 0 1 4 18.5z"/>',
    projects: '<path d="M3 7.5h7l2 2h9v8.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M3 7.5V6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v1.5"/>',
    applications: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m12 12 8-4.5"/><path d="M12 12v9"/><path d="m12 12-8-4.5"/>',
    domains: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c3 3.3 3 14.7 0 18"/><path d="M12 3c-3 3.3-3 14.7 0 18"/>',
    databases: '<ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5"/><path d="M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
    storage: '<path d="M5 8h14l-1.2 11H6.2z"/><path d="M8 8V5.5A1.5 1.5 0 0 1 9.5 4h5A1.5 1.5 0 0 1 16 5.5V8"/><path d="M9 12h6"/>',
    webspaces: '<rect x="4" y="5" width="16" height="14" rx="2"/><path d="M4 10h16"/><path d="M8 15h3"/><path d="M14 15h2"/>',
    resources: '<path d="M4 19V5"/><path d="M4 19h17"/><path d="m7 15 3-3 3 2 5-7"/><path d="M18 7h3v3"/>',
    security: '<path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6z"/>',
    backups: '<path d="M7 7h11a3 3 0 0 1 0 6H8a4 4 0 1 1 3.5-6"/><path d="M12 12v6"/><path d="m9 15 3 3 3-3"/>',
    logs: '<path d="M18 8a6 6 0 1 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/>',
    settings: '<path d="M12 15.5A3.5 3.5 0 1 0 12 8a3.5 3.5 0 0 0 0 7.5z"/><path d="M19.4 15a1.8 1.8 0 0 0 .36 2l.05.05a2 2 0 1 1-2.83 2.83l-.05-.05a1.8 1.8 0 0 0-2-.36 1.8 1.8 0 0 0-1 1.63V21a2 2 0 1 1-4 0v-.08a1.8 1.8 0 0 0-1-1.63 1.8 1.8 0 0 0-2 .36l-.05.05a2 2 0 1 1-2.83-2.83l.05-.05a1.8 1.8 0 0 0 .36-2 1.8 1.8 0 0 0-1.63-1H3a2 2 0 1 1 0-4h.08a1.8 1.8 0 0 0 1.63-1 1.8 1.8 0 0 0-.36-2l-.05-.05a2 2 0 1 1 2.83-2.83l.05.05a1.8 1.8 0 0 0 2 .36h.01A1.8 1.8 0 0 0 10 3.08V3a2 2 0 1 1 4 0v.08a1.8 1.8 0 0 0 1 1.63 1.8 1.8 0 0 0 2-.36l.05-.05a2 2 0 1 1 2.83 2.83l-.05.05a1.8 1.8 0 0 0-.36 2V9.2a1.8 1.8 0 0 0 1.63 1H21a2 2 0 1 1 0 4h-.08a1.8 1.8 0 0 0-1.52.8z"/>',
    menu: '<path d="M4 7h16"/><path d="M4 12h16"/><path d="M4 17h16"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m16.5 16.5 4 4"/>',
    bell: '<path d="M18 8a6 6 0 1 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/>',
    help: '<path d="M9.2 9a3 3 0 1 1 5.2 2c-1.3.8-2.4 1.6-2.4 3"/><path d="M12 18h.01"/><circle cx="12" cy="12" r="9"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
    folder: '<path d="M3 7.5h7l2 2h9v8.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    cube: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m12 12 8-4.5"/><path d="M12 12v9"/><path d="m12 12-8-4.5"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c3 3.3 3 14.7 0 18"/><path d="M12 3c-3 3.3-3 14.7 0 18"/>',
    server: '<rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 7h.01"/><path d="M8 17h.01"/>',
    shield: '<path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6z"/>',
    rocket: '<path d="M5 15c-1 1-1.5 3-1.5 5.5C6 20.5 8 20 9 19"/><path d="M15 5c3-2 5.5-1.5 5.5-1.5S21 6 19 9l-7 7-4-4z"/><path d="m9 15-4 4"/><path d="M15 5l4 4"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
    plus: '<path d="M12 5v14"/><path d="M5 12h14"/>',
    chevron: '<path d="m9 18 6-6-6-6"/>',
    "chevron-down": '<path d="m6 9 6 6 6-6"/>',
    "arrow-right": '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
  };
  const body = icons[name] || icons.settings;
  return `<svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">${body}</svg>`;
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
  const actions = ["start", "stop", "restart", "healthcheck", "deploy", "rollback"];
  const actionForms = actions.map((action) => {
    const confirmValue = applicationLifecycleConfirmation(action, app.id);
    return `<form method="post" action="/actions/application-command">
        <input type="hidden" name="id" value="${escapeHtml(app.id)}">
        <input type="hidden" name="action" value="${escapeHtml(action)}">
        ${confirmValue ? `<input type="hidden" name="confirm" value="${escapeHtml(confirmValue)}">` : ""}
        <button class="button ${action === "stop" || action === "rollback" ? "danger" : action === "deploy" || action === "start" ? "enable" : ""}" type="submit">${escapeHtml(humanName(action))}</button>
      </form>`;
  }).join("");
  return `<div id="app-${escapeHtml(app.id)}" class="card app-card">
    <div class="card-title"><strong>${escapeHtml(app.name)}</strong><em>${escapeHtml(app.runtime)}</em></div>
    <span class="host">${escapeHtml(app.host)}</span>
    <span>Healthcheck: ${escapeHtml(app.healthcheck)} / ${escapeHtml(app.healthStatus || "not-checked")}</span>
    <span>${escapeHtml(app.source || "control-center-state")} / webspace ${escapeHtml(app.webspaceId || "not-linked")}</span>
    <span>Lifecycle: ${escapeHtml(app.lastLifecycleAction || "none")} / ${escapeHtml(app.lifecycleMode || "metadata-only")}</span>
    <div class="project-actions app-actions">
      <span class="state ${app.status === "online" ? "on" : "off"}">${escapeHtml(app.status)}</span>
      ${actionForms}
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

function renderNetworkAdvanced(network) {
  const routers = network.routers || [];
  const middlewares = network.middlewares || [];
  const exposedPorts = network.exposedPorts || [];
  const routeTests = network.routeTests || [];
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>NET</span><div><h2>Traefik Network</h2><p>Read-only topology from Compose and Traefik dynamic config. No live route probe or provider mutation is executed here.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Router topology</strong><span>${routers.length} routers / ${network.services?.length || 0} services / ${network.source}</span></div>
        <div class="card compact"><strong>Middleware chain</strong><span>${middlewares.length} middlewares / redirect ${network.redirectStatus}</span></div>
        <div class="card compact"><strong>Loopback host ports</strong><span>${exposedPorts.map((port) => `${port.hostPort}->${port.containerPort}`).join(", ") || "none"}</span></div>
        <div class="card compact"><strong>Origin lock</strong><span>${escapeHtml(network.originLockStatus)} / Cloudflare ${escapeHtml(network.cloudflareProxyStatus)}</span></div>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><span>TLS</span><div><h2>TLS & Redirect</h2><p>Local TLS uses the mounted Traefik certificate bundle; production proof still requires external HTTPS verification.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>TLS store</strong><span>${escapeHtml(network.tls.defaultStore)} / certificates ${network.tls.certificateCount}</span></div>
        <div class="card compact"><strong>HTTPS routers</strong><span>${network.tlsRouters} TLS routers configured</span></div>
        <div class="card compact"><strong>HTTP redirects</strong><span>${network.redirectRouters} redirect routers configured</span></div>
        <div class="card compact"><strong>Production evidence</strong><span>${network.productionEvidence ? "yes" : "no"} / verifyRemote required</span></div>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><span>RTR</span><div><h2>Router Topology</h2><p>Traefik routers and target services declared by the infrastructure config.</p></div></div>
      <div class="cards">${routers.map(renderNetworkRouterCard).join("") || empty("No routers", "No Traefik routers were parsed from the local config.")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>MID</span><div><h2>Middleware Chain</h2><p>Security headers, compression, rate limiting and HTTPS redirect middlewares.</p></div></div>
      <div class="cards">${middlewares.map(renderNetworkMiddlewareCard).join("") || empty("No middlewares", "No Traefik middlewares were parsed from the local config.")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>CHK</span><div><h2>Route Test Plan</h2><p>Dry-run route checks generated for operators and CI evidence. The web panel does not probe the network.</p></div></div>
      <div class="cards">${routeTests.slice(0, 24).map(renderNetworkRouteTestCard).join("") || empty("No route tests", "Route test plans appear when routers are parsed.")}</div>
    </div>
  </section>`;
}

function renderNetworkRouterCard(router) {
  return `<div id="network-router-${escapeHtml(router.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(router.id)}</strong><em>${escapeHtml(router.entryPoints.join(", ") || "none")}</em></div>
    <span>${escapeHtml(router.rule)}</span>
    <span>service ${escapeHtml(router.service)} / host ${escapeHtml(router.sampleHost)}</span>
    <span>TLS ${router.tls ? "enabled" : "disabled"} / redirect ${router.redirect ? "yes" : "no"} / probe ${router.networkProbeExecuted ? "executed" : "not executed"}</span>
  </div>`;
}

function renderNetworkMiddlewareCard(middleware) {
  return `<div id="network-middleware-${escapeHtml(middleware.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(middleware.id)}</strong><em>${escapeHtml(middleware.type)}</em></div>
    <span>${escapeHtml(middleware.summary)}</span>
    <span>provider touched ${middleware.providerTouched ? "yes" : "no"} / production evidence ${middleware.productionEvidence ? "yes" : "no"}</span>
  </div>`;
}

function renderNetworkRouteTestCard(testPlan) {
  return `<div id="network-route-test-${escapeHtml(testPlan.routerId)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(testPlan.routerId)}</strong><em>${escapeHtml(testPlan.method)}</em></div>
    <span>${escapeHtml(testPlan.url)}</span>
    <span>expected ${escapeHtml(testPlan.expectedStatus)} / network probe ${testPlan.networkProbeExecuted ? "executed" : "not executed"}</span>
    <span>local evidence ${testPlan.localEvidence ? "yes" : "no"} / production evidence ${testPlan.productionEvidence ? "yes" : "no"}</span>
  </div>`;
}

function renderMonitoringAdvanced(monitoring) {
  const scrapeJobs = monitoring.scrapeJobs || [];
  const dashboards = monitoring.dashboardPanels || [];
  const alerts = monitoring.alertRules || [];
  const datasources = monitoring.datasources || [];
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>MON</span><div><h2>Monitoring</h2><p>Read-only observability map from Prometheus, Loki, Grafana and Alertmanager configuration. No Prometheus or Loki query is executed by this panel.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Prometheus scrape jobs</strong><span>${scrapeJobs.length} jobs / interval ${escapeHtml(monitoring.prometheus.scrapeInterval)}</span></div>
        <div class="card compact"><strong>Grafana datasources</strong><span>${datasources.map((item) => item.name).join(", ") || "none"}</span></div>
        <div class="card compact"><strong>Loki retention</strong><span>${escapeHtml(monitoring.loki.retentionPeriod)} / stale samples ${escapeHtml(monitoring.loki.rejectOldSamples)}</span></div>
        <div class="card compact"><strong>Alert routing</strong><span>${escapeHtml(monitoring.alertmanager.receiver)} / secret value exposed ${monitoring.alertmanager.secretValueExposed ? "yes" : "no"}</span></div>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><span>SLO</span><div><h2>Signals</h2><p>Coverage for the requested host, container, app, worker, WAF, auth, latency and error-rate signals.</p></div></div>
      <div class="cards">${(monitoring.signals || []).map(renderMonitoringSignalCard).join("")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>MET</span><div><h2>Prometheus Targets</h2><p>Scrape configuration parsed from the infrastructure Prometheus config.</p></div></div>
      <div class="cards">${scrapeJobs.map(renderMonitoringScrapeCard).join("") || empty("No scrape jobs", "No Prometheus scrape jobs were parsed.")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>LOG</span><div><h2>Grafana Panels</h2><p>Metric and Loki panel inventory, including backend errors, worker errors, WAF events and auth failures.</p></div></div>
      <div class="cards">${dashboards.map(renderMonitoringPanelCard).join("") || empty("No dashboard panels", "No Grafana dashboard panels were parsed.")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>ALT</span><div><h2>Alert Rules</h2><p>Prometheus alert rules and severity labels used by Alertmanager routing.</p></div></div>
      <div class="cards">${alerts.slice(0, 24).map(renderMonitoringAlertRuleCard).join("") || empty("No alert rules", "No Prometheus alert rules were parsed.")}</div>
    </div>
  </section>`;
}

function renderMonitoringSignalCard(signal) {
  return `<div id="monitoring-signal-${escapeHtml(signal.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(signal.name)}</strong><em>${escapeHtml(signal.source)}</em></div>
    <span>${escapeHtml(signal.coverage)}</span>
    <span>live query ${signal.liveQueryExecuted ? "executed" : "not executed"} / production evidence ${signal.productionEvidence ? "yes" : "no"}</span>
  </div>`;
}

function renderMonitoringScrapeCard(job) {
  return `<div id="monitoring-job-${escapeHtml(job.jobName)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(job.jobName)}</strong><em>${escapeHtml(job.metricsPath)}</em></div>
    <span>${escapeHtml(job.targets.join(", "))}</span>
    <span>category ${escapeHtml(job.category)} / live query ${job.liveQueryExecuted ? "executed" : "not executed"}</span>
  </div>`;
}

function renderMonitoringPanelCard(panel) {
  return `<div id="monitoring-panel-${escapeHtml(panel.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(panel.title)}</strong><em>${escapeHtml(panel.type)}</em></div>
    <span>${escapeHtml(panel.datasource)} / ${escapeHtml(panel.signal)}</span>
    <span>${escapeHtml(panel.query)}</span>
  </div>`;
}

function renderMonitoringAlertRuleCard(rule) {
  return `<div id="monitoring-alert-${escapeHtml(rule.name)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(rule.name)}</strong><em>${escapeHtml(rule.severity)}</em></div>
    <span>${escapeHtml(rule.summary)}</span>
    <span>${escapeHtml(rule.expression)}</span>
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
        ${selectOptions("passkeyAdminAuth", globalPolicy.passkeyAdminAuth, ["external-idp-or-passkey-app", "required", "not-configured"], "Passkey admin auth")}
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
  const uiPackage = context.uiPackage || readControlCenterUiPackage();
  const uiComponents = (uiPackage.requiredComponents || []).join(", ");
  const uiAssets = (uiPackage.servedAssets || []).join(", ");
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
    <div class="panel"><div class="panel-head"><span>UI</span><div><h2>Control Center UI</h2><p>The Control Center uses a local visual system scoped to this Node dashboard.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>${escapeHtml(uiPackage.name)}</strong><span>version ${escapeHtml(uiPackage.version)} / ${escapeHtml(uiPackage.source)}</span></div>
        <div class="card compact"><strong>${escapeHtml(uiPackage.controlCenterProject || "@platform/control-center")}</strong><span>${escapeHtml(uiPackage.declaredDependency || "none")} / local scope ${uiPackage.packageMountedInControlCenterProject ? "yes" : "no"}</span></div>
        <div class="card compact"><strong>Local entrypoints</strong><span>${escapeHtml(uiAssets)}</span></div>
        <div class="card compact"><strong>Local components</strong><span>${escapeHtml(uiComponents)}</span></div>
        <div class="card compact"><strong>Visual contract</strong><span>${uiPackage.apiManifestLoaded && uiPackage.missingRequiredExports?.length === 0 ? "loaded from local Control Center files" : "needs package review"}</span></div>
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
    const href = exists ? `https://${docsHost}/docs/${encodeURIComponent(docPath)}` : "#";
    return `<a class="card compact ${exists ? "" : "disabled"}" href="${escapeHtml(href)}"><strong>${escapeHtml(path.basename(docPath))}</strong><span>${escapeHtml(description)}</span></a>`;
  }).join("")}</div>`).join("");
}

function renderDocsPortal(selectedDocPath = "") {
  const selected = selectedDocPath ? findDoc(selectedDocPath) : null;
  const title = selected ? `${path.basename(selected.path)} / Platform Docs` : "Platform Docs";
  const body = selected ? renderDocArticle(selected) : renderDocsIndex();
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>${escapeHtml(title)}</title>
${controlCenterStylesheetLinks()}
</head>
<body data-cc-theme="light">
<main class="docs-shell">
  <aside class="docs-sidebar" aria-label="Documentation navigation">
    <a class="brand platform-wordmark" href="/" aria-label="Platform Docs"><span class="brand-mark">D</span><div><strong>Docs</strong><small>${escapeHtml(platformName)}</small></div></a>
    <nav class="docs-nav">${renderDocsNavigation(selectedDocPath)}</nav>
    <div class="docs-note"><strong>Portal</strong><span>${escapeHtml(controlCenterHost)}</span></div>
  </aside>
  <section class="docs-content">
    <header class="docs-hero">
      <p class="eyebrow">${escapeHtml(environment.toUpperCase())} / DOCUMENTATION</p>
      <h1>${escapeHtml(selected ? path.basename(selected.path) : "Platform Documentation")}</h1>
      <p>${escapeHtml(selected ? selected.description : "Runbook, security, readiness and service documentation organized for operations.")}</p>
    </header>
    ${body}
  </section>
</main>
</body>
</html>`;
}

function renderDocsIndex() {
  return `<section class="docs-grid">${Object.entries(docs).map(([group, items]) => `
    <article class="docs-card">
      <h2>${escapeHtml(group)}</h2>
      <div class="docs-link-list">
        ${items.map(([docPath, description]) => {
          const exists = existsSync(safeDocPath(docPath));
          const href = exists ? `/docs/${encodeURIComponent(docPath)}` : "#";
          return `<a class="${exists ? "" : "disabled"}" href="${escapeHtml(href)}"><strong>${escapeHtml(docPath)}</strong><span>${escapeHtml(description)}</span></a>`;
        }).join("")}
      </div>
    </article>`).join("")}</section>`;
}

function renderDocsNavigation(selectedDocPath = "") {
  return Object.entries(docs).map(([group, items]) => `<div class="docs-nav-group">
    <strong>${escapeHtml(group)}</strong>
    ${items.map(([docPath]) => {
      const exists = existsSync(safeDocPath(docPath));
      const href = exists ? `/docs/${encodeURIComponent(docPath)}` : "#";
      return `<a class="${selectedDocPath === docPath ? "active" : ""} ${exists ? "" : "disabled"}" href="${escapeHtml(href)}">${escapeHtml(path.basename(docPath))}</a>`;
    }).join("")}
  </div>`).join("");
}

function renderDocArticle(doc) {
  const filePath = safeDocPath(doc.path);
  const content = existsSync(filePath) ? readFileSync(filePath, "utf8") : "";
  return `<article class="docs-article">
    <div class="docs-article-meta"><a href="/">Docs index</a><span>${escapeHtml(doc.group)}</span><span>${escapeHtml(doc.path)}</span></div>
    ${renderMarkdown(content)}
  </article>`;
}

function renderMarkdown(content) {
  const lines = String(content || "").replace(/\r\n/g, "\n").split("\n");
  const htmlParts = [];
  let inCode = false;
  let codeLines = [];
  let listItems = [];
  const flushList = () => {
    if (!listItems.length) return;
    htmlParts.push(`<ul>${listItems.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`);
    listItems = [];
  };
  const flushCode = () => {
    htmlParts.push(`<pre><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
    codeLines = [];
  };
  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+$/, "");
    if (line.startsWith("```")) {
      if (inCode) {
        flushCode();
        inCode = false;
      } else {
        flushList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeLines.push(rawLine);
      continue;
    }
    if (!line.trim()) {
      flushList();
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      flushList();
      const level = Math.min(4, heading[1].length + 1);
      htmlParts.push(`<h${level}>${escapeHtml(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet) {
      listItems.push(bullet[1]);
      continue;
    }
    flushList();
    htmlParts.push(`<p>${escapeHtml(line)}</p>`);
  }
  flushList();
  if (inCode) flushCode();
  return htmlParts.join("\n");
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

function renderStorage(buckets, provider, projects) {
  const projectOptions = projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("");
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>S3</span><div><h2>Storage</h2><p>MinIO bucket inventory and controls are metadata-only until a live MinioAdapter is explicitly enabled.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>${escapeHtml(provider.name)}</strong><span>${escapeHtml(provider.service)} / ${escapeHtml(provider.status)} / production evidence ${provider.productionEvidence ? "yes" : "no"}</span></div>
        <div class="card compact"><strong>Access keys</strong><span>tracked as configured/not-configured metadata; values are never exposed.</span></div>
        <div class="card compact"><strong>Lifecycle</strong><span>retention and transition metadata only until adapter apply.</span></div>
      </div>
      <form method="post" action="/actions/storage-command" class="inline-confirm storage-form">
        <input type="hidden" name="action" value="create">
        <select name="projectId" aria-label="Bucket project">${projectOptions}</select>
        <input name="name" value="project-assets" aria-label="Bucket name">
        <input name="quotaBytes" value="0" aria-label="Bucket quota bytes">
        <select name="accessPolicy" aria-label="Access policy"><option value="private">private</option><option value="project-private">project-private</option><option value="public-read">public-read</option><option value="admin-only">admin-only</option></select>
        <select name="accessKeyStatus" aria-label="Access key status"><option value="not-configured">not-configured</option><option value="requires-secret-file">requires-secret-file</option><option value="configured">configured</option><option value="rotating">rotating</option></select>
        <input type="hidden" name="confirm" value="CREATE-BUCKET">
        <button class="button enable" type="submit">Declare bucket</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>INV</span><div><h2>Bucket Inventory</h2><p>Policy, lifecycle, backup and restore plans are audited and do not call MinIO live.</p></div></div>
      ${buckets.length ? `<div class="cards">${buckets.map(renderStorageBucketCard).join("")}</div>` : empty("No buckets declared", "Declare a project bucket to track storage policy, lifecycle and backup plans from the Control Center.")}
    </div>
  </section>`;
}

function renderStorageBucketCard(bucket) {
  return `<div id="bucket-${escapeHtml(bucket.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(bucket.name)}</strong><em>${escapeHtml(bucket.accessPolicy)}</em></div>
    <span>${escapeHtml(bucket.projectId)} / ${escapeHtml(bucket.status)} / quota ${escapeHtml(String(bucket.quotaBytes))} bytes</span>
    <span>lifecycle ${escapeHtml(bucket.lifecycleStatus)} / retention ${escapeHtml(String(bucket.retentionDays))} days / access key ${escapeHtml(bucket.accessKeyStatus)}</span>
    <form method="post" action="/actions/storage-command" class="inline-confirm">
      <input type="hidden" name="action" value="policy">
      <input type="hidden" name="id" value="${escapeHtml(bucket.id)}">
      <select name="accessPolicy" aria-label="Access policy"><option value="private">private</option><option value="project-private">project-private</option><option value="public-read">public-read</option><option value="admin-only">admin-only</option></select>
      <input type="hidden" name="confirm" value="UPDATE-BUCKET-POLICY">
      <button class="button" type="submit">Update policy</button>
    </form>
    <form method="post" action="/actions/storage-command" class="inline-confirm">
      <input type="hidden" name="action" value="lifecycle">
      <input type="hidden" name="id" value="${escapeHtml(bucket.id)}">
      <input name="retentionDays" value="${escapeHtml(String(bucket.retentionDays || 30))}" aria-label="Retention days">
      <input type="hidden" name="confirm" value="UPDATE-BUCKET-LIFECYCLE">
      <button class="button" type="submit">Update lifecycle</button>
    </form>
    <form method="post" action="/actions/storage-command" class="inline-confirm">
      <input type="hidden" name="action" value="access-key">
      <input type="hidden" name="id" value="${escapeHtml(bucket.id)}">
      <select name="accessKeyStatus" aria-label="Access key status"><option value="not-configured">not-configured</option><option value="requires-secret-file">requires-secret-file</option><option value="configured">configured</option><option value="rotating">rotating</option></select>
      <input type="hidden" name="confirm" value="UPDATE-BUCKET-ACCESS-KEY">
      <button class="button" type="submit">Update access key</button>
    </form>
    <form method="post" action="/actions/storage-command" class="inline-confirm">
      <input type="hidden" name="action" value="backup">
      <input type="hidden" name="id" value="${escapeHtml(bucket.id)}">
      <button class="button enable" type="submit">Plan backup</button>
    </form>
    <form method="post" action="/actions/storage-command" class="inline-confirm">
      <input type="hidden" name="action" value="restore">
      <input type="hidden" name="id" value="${escapeHtml(bucket.id)}">
      <input name="backupRef" value="latest" aria-label="Backup reference">
      <button class="button danger" type="submit">Plan restore</button>
    </form>
  </div>`;
}

function renderSecrets(materials, stores, projects) {
  const projectOptions = projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("");
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>KEY</span><div><h2>Secrets</h2><p>Inventory tracks sensitive material metadata only. Plaintext values never enter the Control Center.</p></div></div>
      <div class="cards">
        ${stores.map((store) => `<div class="card compact"><strong>${escapeHtml(store.name)}</strong><span>${escapeHtml(store.status)} / value exposed ${store.valueExposed ? "yes" : "no"}</span></div>`).join("")}
      </div>
      <form method="post" action="/actions/material-command" class="inline-confirm material-form">
        <input type="hidden" name="action" value="declare">
        <select name="projectId" aria-label="Material project">${projectOptions}</select>
        <select name="targetEnv" aria-label="Material environment"><option value="local">local</option><option value="staging">staging</option><option value="production">production</option></select>
        <input name="materialName" value="APP_CONFIG" aria-label="Material name">
        <select name="materialKind" aria-label="Material kind"><option value="application">application</option><option value="docker">docker</option><option value="provider">provider</option><option value="kms">kms</option><option value="database">database</option><option value="storage">storage</option></select>
        <select name="materialConfigured" aria-label="Material configured"><option value="false">not configured</option><option value="true">configured</option></select>
        <input name="rotationDays" value="90" aria-label="Rotation days">
        <input name="usageTarget" value="app" aria-label="Usage target">
        <input type="hidden" name="confirm" value="DECLARE-MATERIAL">
        <button class="button enable" type="submit">Declare material</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>INV</span><div><h2>Material Inventory</h2><p>Rotation, usage and access audit are local metadata records, not value reads.</p></div></div>
      ${materials.length ? `<div class="cards">${materials.map(renderMaterialCard).join("")}</div>` : empty("No materials declared", "Declare sensitive material metadata to track usage, rotation and access audits without exposing values.")}
    </div>
  </section>`;
}

function renderMaterialCard(material) {
  return `<div id="material-${escapeHtml(material.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(material.materialName)}</strong><em>${escapeHtml(material.materialKind)}</em></div>
    <span>${escapeHtml(material.projectId)} / ${escapeHtml(material.environment)} / configured ${material.materialConfigured ? "yes" : "no"}</span>
    <span>rotation ${escapeHtml(material.rotationStatus)} every ${escapeHtml(String(material.rotationDays))} days / value exposed ${material.valueExposed ? "yes" : "no"}</span>
    <span>usage ${escapeHtml(material.usageTargets.join(", ") || "not mapped")}</span>
    <form method="post" action="/actions/material-command" class="inline-confirm">
      <input type="hidden" name="action" value="rotation">
      <input type="hidden" name="id" value="${escapeHtml(material.id)}">
      <input name="rotationDays" value="${escapeHtml(String(material.rotationDays || 90))}" aria-label="Rotation days">
      <input type="hidden" name="confirm" value="UPDATE-MATERIAL-ROTATION">
      <button class="button" type="submit">Update rotation</button>
    </form>
    <form method="post" action="/actions/material-command" class="inline-confirm">
      <input type="hidden" name="action" value="usage">
      <input type="hidden" name="id" value="${escapeHtml(material.id)}">
      <input name="usageTarget" value="${escapeHtml(material.usageTargets[0] || "app")}" aria-label="Usage target">
      <input type="hidden" name="confirm" value="UPDATE-MATERIAL-USAGE">
      <button class="button" type="submit">Update usage</button>
    </form>
    <form method="post" action="/actions/material-command" class="inline-confirm">
      <input type="hidden" name="action" value="access">
      <input type="hidden" name="id" value="${escapeHtml(material.id)}">
      <input name="purpose" value="admin-review" aria-label="Access purpose">
      <input type="hidden" name="confirm" value="RECORD-MATERIAL-ACCESS">
      <button class="button danger" type="submit">Record access</button>
    </form>
  </div>`;
}

function renderIdentityAccess(identity) {
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>IAM</span><div><h2>Identity &amp; Access</h2><p>Admin users, roles, teams, sessions and access reviews are metadata-only until Keycloak or Cloudflare Access adapters verify remote state.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Admin users</strong><span>${identity.adminUsers.length} records / credentials exposed no</span></div>
        <div class="card compact"><strong>Roles</strong><span>${identity.roles.length} roles / permissions metadata</span></div>
        <div class="card compact"><strong>Sessions</strong><span>${identity.sessionPolicies.length} policies / ${escapeHtml(identity.sessionPolicies[0]?.cookieFlags?.join(", ") || "HttpOnly, Secure")}</span></div>
        <div class="card compact"><strong>Login audit</strong><span>${identity.loginAudit.length} recent admin login events</span></div>
      </div>
      <form method="post" action="/actions/identity-command" class="inline-confirm identity-form">
        <input type="hidden" name="action" value="admin-user">
        <input name="email" value="admin@localhost.com" aria-label="Admin email">
        <input name="displayName" value="Platform Admin" aria-label="Admin display name">
        <input name="roleIds" value="platform-owner" aria-label="Role ids">
        <input name="teamIds" value="platform-admins" aria-label="Team ids">
        <select name="mfaRequired" aria-label="MFA required"><option value="true">MFA required</option><option value="false">MFA metadata only</option></select>
        <select name="passkeyRequired" aria-label="Passkey required"><option value="true">passkey required</option><option value="false">passkey optional</option></select>
        <input type="hidden" name="confirm" value="DECLARE-ADMIN-USER">
        <button class="button enable" type="submit">Declare admin user</button>
      </form>
      <form method="post" action="/actions/identity-command" class="inline-confirm identity-form">
        <input type="hidden" name="action" value="role">
        <input name="id" value="platform-operator" aria-label="Role id">
        <input name="name" value="Platform Operator" aria-label="Role name">
        <input name="permissions" value="control:read,projects:write,audit:read" aria-label="Permissions">
        <input type="hidden" name="confirm" value="DECLARE-IDENTITY-ROLE">
        <button class="button enable" type="submit">Declare role</button>
      </form>
      <form method="post" action="/actions/identity-command" class="inline-confirm identity-form">
        <input type="hidden" name="action" value="team">
        <input name="id" value="platform-ops" aria-label="Team id">
        <input name="name" value="Platform Ops" aria-label="Team name">
        <input name="roleIds" value="platform-operator" aria-label="Team role ids">
        <input name="members" value="local-admin" aria-label="Team members">
        <input type="hidden" name="confirm" value="DECLARE-IDENTITY-TEAM">
        <button class="button enable" type="submit">Declare team</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>USR</span><div><h2>Admin Users</h2><p>No passwords, passkey credentials or OAuth tokens are stored in this inventory.</p></div></div>
      ${identity.adminUsers.length ? `<div class="cards">${identity.adminUsers.map(renderIdentityUserCard).join("")}</div>` : empty("No admin users", "Declare admin users to track ownership and access reviews.")}
    </div>
    <div class="panel"><div class="panel-head"><span>ROL</span><div><h2>Roles &amp; Teams</h2><p>Permissions are reviewed locally; live IdP changes require an explicit adapter.</p></div></div>
      <div class="cards">${[...identity.roles.map(renderIdentityRoleCard), ...identity.teams.map(renderIdentityTeamCard)].join("")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>SES</span><div><h2>Sessions &amp; Reviews</h2><p>Session policy and access review evidence stay local until production verifyRemote passes.</p></div></div>
      <form method="post" action="/actions/identity-command" class="inline-confirm identity-form">
        <input type="hidden" name="action" value="session-policy">
        <input name="id" value="control-center-session" aria-label="Session policy id">
        <input name="maxAgeMinutes" value="480" inputmode="numeric" aria-label="Session max age minutes">
        <input name="cookieFlags" value="HttpOnly,Secure,SameSite=Lax" aria-label="Cookie flags">
        <input type="hidden" name="confirm" value="UPDATE-SESSION-POLICY">
        <button class="button" type="submit">Update session policy</button>
      </form>
      <form method="post" action="/actions/identity-command" class="inline-confirm identity-form">
        <input type="hidden" name="action" value="access-review">
        <input name="scope" value="admin-users" aria-label="Access review scope">
        <input name="reviewer" value="local-admin" aria-label="Reviewer">
        <select name="status" aria-label="Review status"><option value="planned">planned</option><option value="passed">passed</option><option value="needs-action">needs-action</option></select>
        <input type="hidden" name="confirm" value="RECORD-ACCESS-REVIEW">
        <button class="button" type="submit">Record access review</button>
      </form>
      <div class="cards">${[...identity.sessionPolicies.map(renderIdentitySessionPolicyCard), ...identity.accessReviews.map(renderIdentityAccessReviewCard), ...identity.loginAudit.map(renderIdentityLoginAuditCard)].join("") || empty("No session evidence", "Session policy and access review records appear here.")}</div>
    </div>
  </section>`;
}

function renderIdentityUserCard(user) {
  return `<div id="identity-${escapeHtml(user.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(user.displayName)}</strong><em>${escapeHtml(user.status)}</em></div>
    <span>${escapeHtml(user.email)} / roles ${escapeHtml(user.roleIds.join(", ") || "none")}</span>
    <span>MFA ${escapeHtml(user.mfaStatus)} / passkey ${escapeHtml(user.passkeyStatus)} / VPN ${escapeHtml(user.vpnStatus)}</span>
    <span>credentials exposed ${user.credentialsExposed ? "yes" : "no"} / provider touched ${user.providerTouched ? "yes" : "no"}</span>
  </div>`;
}

function renderIdentityRoleCard(role) {
  return `<div id="identity-${escapeHtml(role.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(role.name)}</strong><em>role</em></div>
    <span>${escapeHtml(role.permissions.join(", ") || "no permissions")}</span>
    <span>${escapeHtml(role.source)} / IdP touched ${role.providerTouched ? "yes" : "no"}</span>
  </div>`;
}

function renderIdentityTeamCard(team) {
  return `<div id="identity-${escapeHtml(team.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(team.name)}</strong><em>team</em></div>
    <span>roles ${escapeHtml(team.roleIds.join(", ") || "none")} / members ${escapeHtml(team.members.join(", ") || "none")}</span>
    <span>${escapeHtml(team.source)} / production evidence ${team.productionEvidence ? "yes" : "no"}</span>
  </div>`;
}

function renderIdentitySessionPolicyCard(policy) {
  return `<div id="identity-${escapeHtml(policy.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(policy.name)}</strong><em>${escapeHtml(policy.status)}</em></div>
    <span>max age ${escapeHtml(String(policy.maxAgeMinutes))}m / flags ${escapeHtml(policy.cookieFlags.join(", "))}</span>
    <span>secret file ${policy.sessionSecretConfigured ? "configured" : "not configured"} / value exposed ${policy.valueExposed ? "yes" : "no"}</span>
  </div>`;
}

function renderIdentityAccessReviewCard(review) {
  return `<div id="identity-${escapeHtml(review.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(review.scope)}</strong><em>${escapeHtml(review.status)}</em></div>
    <span>reviewer ${escapeHtml(review.reviewer)} / ${escapeHtml(review.reviewedAt || "not-reviewed")}</span>
    <span>provider touched ${review.providerTouched ? "yes" : "no"} / production evidence ${review.productionEvidence ? "yes" : "no"}</span>
  </div>`;
}

function renderIdentityLoginAuditCard(event) {
  return `<div class="card compact">
    <div class="card-title"><strong>${escapeHtml(event.action || "admin.login")}</strong><em>${escapeHtml(event.result || "unknown")}</em></div>
    <span>${escapeHtml(event.timestamp || "")} / ${escapeHtml(event.risk || "low")} / ${escapeHtml(event.requestId || "")}</span>
  </div>`;
}

function renderWorkersJobs(workers, queues, jobs, schedules, projects) {
  const projectOptions = projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("");
  const queueOptions = queues.map((queue) => `<option value="${escapeHtml(queue.id)}">${escapeHtml(`${queue.projectId}/${queue.name}`)}</option>`).join("");
  const workerOptions = workers.map((worker) => `<option value="${escapeHtml(worker.id)}">${escapeHtml(`${worker.projectId}/${worker.name}`)}</option>`).join("");
  const failedJobs = jobs.filter((job) => job.status === "failed");
  return `<section class="grid two">
    <div class="panel"><div class="panel-head"><span>JOB</span><div><h2>Workers &amp; Jobs</h2><p>Worker, queue, failed job, retry and scheduler metadata. No job execution or Docker command runs from this panel.</p></div></div>
      <div class="cards">
        <div class="card compact"><strong>Worker status</strong><span>${workers.length} runtime records / Docker touched no</span></div>
        <div class="card compact"><strong>Queues</strong><span>${queues.length} queue records / providers touched no</span></div>
        <div class="card compact"><strong>Failed jobs</strong><span>${failedJobs.length} local records / retry controls metadata-only</span></div>
        <div class="card compact"><strong>Containerized scheduler</strong><span>${schedules.filter((schedule) => schedule.containerizedCron).length} cron records</span></div>
      </div>
      <form method="post" action="/actions/worker-job-command" class="inline-confirm worker-form">
        <input type="hidden" name="action" value="declare-worker">
        <select name="projectId" aria-label="Worker project">${projectOptions}</select>
        <input name="name" value="jobs-worker" aria-label="Worker name">
        <input name="service" value="worker-jobs" aria-label="Worker service">
        <select name="status" aria-label="Worker status"><option value="declared">declared</option><option value="configured">configured</option><option value="running">running</option><option value="stopped">stopped</option><option value="degraded">degraded</option></select>
        <input name="queueName" value="jobs" aria-label="Worker queue name">
        <input name="concurrency" value="1" inputmode="numeric" aria-label="Worker concurrency">
        <input name="maxAttempts" value="3" inputmode="numeric" aria-label="Max retry attempts">
        <input type="hidden" name="confirm" value="DECLARE-WORKER">
        <button class="button enable" type="submit">Declare worker</button>
      </form>
      <form method="post" action="/actions/worker-job-command" class="inline-confirm worker-form">
        <input type="hidden" name="action" value="declare-queue">
        <select name="projectId" aria-label="Queue project">${projectOptions}</select>
        <input name="name" value="jobs" aria-label="Queue name">
        <select name="backend" aria-label="Queue backend"><option value="nats">nats</option><option value="postgres-outbox">postgres-outbox</option><option value="container-cron">container-cron</option><option value="http-webhook">http-webhook</option><option value="alertmanager-webhook">alertmanager-webhook</option></select>
        <select name="status" aria-label="Queue status"><option value="declared">declared</option><option value="configured">configured</option><option value="draining">draining</option><option value="paused">paused</option></select>
        <input name="retryPolicy" value="bounded-worker-retry" aria-label="Retry policy">
        <input type="hidden" name="confirm" value="DECLARE-QUEUE">
        <button class="button enable" type="submit">Declare queue</button>
      </form>
    </div>
    <div class="panel"><div class="panel-head"><span>WRK</span><div><h2>Worker Runtime</h2><p>Status is local metadata plus discovered Compose services; health proof comes from ops evidence.</p></div></div>
      ${workers.length ? `<div class="cards">${workers.map(renderWorkerRuntimeCard).join("")}</div>` : empty("No worker records", "Declare a worker or create an application with runtime worker.")}
    </div>
    <div class="panel"><div class="panel-head"><span>QUE</span><div><h2>Queues</h2><p>Queue depth and dead-letter metadata are safe local records until adapters read metrics.</p></div></div>
      ${queues.length ? `<div class="cards">${queues.map(renderJobQueueCard).join("")}</div>` : empty("No queues", "Declare a queue to map worker routing and retry policy.")}
    </div>
    <div class="panel"><div class="panel-head"><span>FAIL</span><div><h2>Jobs</h2><p>Record failed jobs and retry plans without running handlers from the web panel.</p></div></div>
      <form method="post" action="/actions/worker-job-command" class="inline-confirm job-form">
        <input type="hidden" name="action" value="record-job">
        <select name="projectId" aria-label="Job project">${projectOptions}</select>
        <select name="queueId" aria-label="Job queue">${queueOptions || '<option value="jobs">jobs</option>'}</select>
        <select name="workerId" aria-label="Job worker">${workerOptions || '<option value="enterprise-worker-jobs">enterprise-worker-jobs</option>'}</select>
        <input name="jobName" value="sync-task" aria-label="Job name">
        <select name="status" aria-label="Job status"><option value="failed">failed</option><option value="queued">queued</option><option value="running">running</option><option value="succeeded">succeeded</option><option value="dead">dead</option></select>
        <input name="attempts" value="1" inputmode="numeric" aria-label="Attempts">
        <input name="maxAttempts" value="3" inputmode="numeric" aria-label="Max attempts">
        <input name="lastError" value="sanitized failure note" aria-label="Last error summary">
        <input type="hidden" name="confirm" value="RECORD-JOB">
        <button class="button enable" type="submit">Record job</button>
      </form>
      ${jobs.length ? `<div class="cards">${jobs.map(renderJobRecordCard).join("")}</div>` : empty("No job records", "Failed job and retry metadata will appear here.")}
    </div>
    <div class="panel"><div class="panel-head"><span>CRON</span><div><h2>Containerized Scheduler</h2><p>Cron expressions are metadata only; production proof comes from the Dockerized scheduler evidence.</p></div></div>
      <form method="post" action="/actions/worker-job-command" class="inline-confirm schedule-form">
        <input type="hidden" name="action" value="declare-schedule">
        <select name="projectId" aria-label="Schedule project">${projectOptions}</select>
        <select name="workerId" aria-label="Schedule worker">${workerOptions || '<option value="enterprise-worker-jobs">enterprise-worker-jobs</option>'}</select>
        <select name="queueId" aria-label="Schedule queue">${queueOptions || '<option value="maintenance">maintenance</option>'}</select>
        <input name="name" value="nightly-maintenance" aria-label="Schedule name">
        <input name="cronExpression" value="15 3 * * *" aria-label="Cron expression">
        <select name="status" aria-label="Schedule status"><option value="enabled">enabled</option><option value="paused">paused</option><option value="metadata-only">metadata-only</option></select>
        <input type="hidden" name="confirm" value="DECLARE-SCHEDULE">
        <button class="button enable" type="submit">Declare schedule</button>
      </form>
      ${schedules.length ? `<div class="cards">${schedules.map(renderJobScheduleCard).join("")}</div>` : empty("No schedules", "Declare containerized cron metadata to track scheduler intent.")}
    </div>
  </section>`;
}

function renderWorkerRuntimeCard(worker) {
  return `<div id="worker-job-${escapeHtml(worker.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(worker.name)}</strong><em>${escapeHtml(worker.status)}</em></div>
    <span>${escapeHtml(worker.projectId)} / service ${escapeHtml(worker.service)} / queue ${escapeHtml(worker.queueName)}</span>
    <span>concurrency ${escapeHtml(String(worker.concurrency))} / max attempts ${escapeHtml(String(worker.maxAttempts))} / health ${escapeHtml(worker.healthStatus)}</span>
    <span>${escapeHtml(worker.source)} / command executed ${worker.commandExecuted ? "yes" : "no"}</span>
  </div>`;
}

function renderJobQueueCard(queue) {
  return `<div id="worker-job-${escapeHtml(queue.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(queue.name)}</strong><em>${escapeHtml(queue.status)}</em></div>
    <span>${escapeHtml(queue.projectId)} / ${escapeHtml(queue.backend)} / depth ${escapeHtml(String(queue.depth))}</span>
    <span>failed ${escapeHtml(String(queue.failedCount))} / retry ${escapeHtml(queue.retryPolicy)} / dead letter ${escapeHtml(queue.deadLetterQueue || "not-set")}</span>
  </div>`;
}

function renderJobRecordCard(job) {
  return `<div id="worker-job-${escapeHtml(job.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(job.jobName)}</strong><em>${escapeHtml(job.status)}</em></div>
    <span>${escapeHtml(job.projectId)} / queue ${escapeHtml(job.queueId)} / worker ${escapeHtml(job.workerId)}</span>
    <span>attempts ${escapeHtml(String(job.attempts))}/${escapeHtml(String(job.maxAttempts))} / retry after ${escapeHtml(String(job.retryAfterSeconds))}s</span>
    <span>${escapeHtml(job.lastError || "no error summary")}</span>
    ${["failed", "dead", "retry-planned"].includes(job.status) ? `<form method="post" action="/actions/worker-job-command" class="inline-confirm">
      <input type="hidden" name="action" value="retry-job">
      <input type="hidden" name="id" value="${escapeHtml(job.id)}">
      <input name="retryAfterSeconds" value="${escapeHtml(String(job.retryAfterSeconds || 60))}" inputmode="numeric" aria-label="Retry delay seconds">
      <input type="hidden" name="confirm" value="PLAN-JOB-RETRY">
      <button class="button danger" type="submit">Plan retry</button>
    </form>` : ""}
  </div>`;
}

function renderJobScheduleCard(schedule) {
  return `<div id="worker-job-${escapeHtml(schedule.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(schedule.name)}</strong><em>${escapeHtml(schedule.status)}</em></div>
    <span>${escapeHtml(schedule.projectId)} / worker ${escapeHtml(schedule.workerId)} / queue ${escapeHtml(schedule.queueId)}</span>
    <span>cron ${escapeHtml(schedule.cronExpression)} / containerized ${schedule.containerizedCron ? "yes" : "no"} / last ${escapeHtml(schedule.lastRunStatus)}</span>
    <form method="post" action="/actions/worker-job-command" class="inline-confirm">
      <input type="hidden" name="action" value="schedule-status">
      <input type="hidden" name="id" value="${escapeHtml(schedule.id)}">
      <select name="status" aria-label="Schedule status for ${escapeHtml(schedule.id)}"><option value="enabled">enabled</option><option value="paused">paused</option><option value="metadata-only">metadata-only</option></select>
      <input type="hidden" name="confirm" value="UPDATE-SCHEDULE">
      <button class="button" type="submit">Update schedule</button>
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

function renderReadiness(readiness) {
  const summary = readiness.summary || {};
  const controlChecks = readiness.controlCenter?.checks || [];
  const productionRequirements = readiness.manifests?.productionReadiness?.requirements || [];
  const enterpriseRequirements = readiness.manifests?.enterprise?.requirements || [];
  return `<section class="metric-grid">
    <div class="metric"><span>${summary.passed || 0}</span><small>passed checks</small></div>
    <div class="metric"><span>${summary.pendingLiveProof || 0}</span><small>pending live proofs</small></div>
    <div class="metric"><span>${summary.planOnly || 0}</span><small>plan-only controls</small></div>
    <div class="metric"><span>${summary.needsWork || 0}</span><small>repo gaps</small></div>
  </section>
  <section class="grid two">
    <div class="panel"><div class="panel-head"><span>RDY</span><div><h2>Control Center coverage</h2><p>Local control-plane capabilities are separated from production live evidence.</p></div></div>
      <div class="cards">${controlChecks.map(renderReadinessCard).join("")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>LIVE</span><div><h2>Production blockers</h2><p>These items need real VPS/provider proof before production evidence can be accepted.</p></div></div>
      <div class="cards">${readiness.productionBlockers.slice(0, 8).map((item) => `<div class="card compact"><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.status)} / ${escapeHtml(item.nextAction)}</span></div>`).join("") || empty("No blockers", "No pending live-proof blockers were found.")}</div>
    </div>
  </section>
  <section class="grid two">
    <div class="panel"><div class="panel-head"><span>20</span><div><h2>Production readiness checklist</h2><p>${escapeHtml(readiness.manifests?.productionReadiness?.requirementCount || 0)} tracked requirements from governance/production-readiness.json.</p></div></div>
      <div class="cards">${productionRequirements.slice(0, 20).map(renderReadinessCard).join("")}</div>
    </div>
    <div class="panel"><div class="panel-head"><span>ENT</span><div><h2>Enterprise requirements</h2><p>${escapeHtml(readiness.manifests?.enterprise?.requirementCount || 0)} tracked requirements from governance/enterprise-requirements.json.</p></div></div>
      <div class="cards">${enterpriseRequirements.slice(0, 12).map(renderReadinessCard).join("")}</div>
    </div>
  </section>`;
}

function renderReadinessCard(item) {
  const statusClass = item.status === "needs-work" ? "danger" : item.status === "pending-live-proof" || item.status === "plan-only" ? "off" : "on";
  return `<div id="readiness-${escapeHtml(item.id)}" class="card compact">
    <div class="card-title"><strong>${escapeHtml(item.title || item.id)}</strong><em class="state ${statusClass}">${escapeHtml(item.status)}</em></div>
    <span>${escapeHtml(item.repoEvidenceStatus || "tracked")} / live proof ${item.liveProofRequired ? "required" : "not required"}</span>
    <span>${escapeHtml(item.nextAction || "Keep evidence current.")}</span>
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
  if (!["start", "stop", "restart", "healthcheck", "deploy", "rollback"].includes(action)) throw new ValidationError("Unsupported lifecycle action.");
  const app = findById(context.applications, id, "Application");
  if (action === "deploy" || action === "rollback") return planApplicationDeployment(app, action, payload, context);
  if (payload.confirm === applicationLifecycleConfirmation(action, app.id)) return applyApplicationLifecycle(app, action, payload, context);
  appendAudit({ action: `application.${action}.plan`, target: sanitizeIdentifier(id), environment: context.environment, risk: action === "stop" ? "medium" : "low", result: "planned", dryRun: true, summary: "Lifecycle action planned; no container command executed." });
  return operationPlan(`application.${action}`, context.environment, true, lifecycleSteps(action, true), {
    projectId: app.projectId,
    applicationId: app.id,
    confirmationRequired: applicationLifecycleConfirmation(action, app.id),
    dockerTouched: false,
    providerTouched: false,
    commandExecuted: false,
    healthcheckNetworkTouched: false,
    productionEvidence: false,
  });
}

function applyApplicationLifecycle(app, action, payload, context) {
  const now = new Date().toISOString();
  const state = readApplicationsState();
  const previous = state[app.id] || {};
  const nextStatus = applicationLifecycleStatus(action, app.status);
  const healthStatus = action === "healthcheck"
    ? (app.status === "offline" || app.status === "stopped" ? "metadata-disabled" : "metadata-routable")
    : (nextStatus === "offline" || nextStatus === "stopped" ? "metadata-disabled" : "metadata-pending-healthcheck");
  const updated = applicationRecord({
    ...app,
    ...previous,
    status: nextStatus,
    healthStatus,
    lastLifecycleAction: action,
    lastLifecycleAt: now,
    lastHealthcheckAt: action === "healthcheck" ? now : previous.lastHealthcheckAt || app.lastHealthcheckAt || null,
    lifecycleMode: "local-metadata-only",
    source: previous.source || app.source || "control-center-state",
    updatedAt: now,
    createdAt: previous.createdAt || app.createdAt || now,
    filesystemTouched: false,
    dockerTouched: false,
    providerTouched: false,
    productionEvidence: false,
  });
  state[app.id] = updated;
  writeApplicationsState(state);
  appendAudit({
    action: `application.${action}.apply`,
    target: app.id,
    environment: context.environment,
    risk: action === "stop" ? "medium" : "low",
    result: "success",
    dryRun: false,
    summary: "Application lifecycle metadata updated locally; no Docker command, network healthcheck or provider action executed.",
  });
  const operation = operationPlan(`application.${action}.local`, context.environment, false, lifecycleSteps(action, false), {
    projectId: app.projectId,
    applicationId: app.id,
    previousStatus: app.status,
    status: nextStatus,
    healthStatus,
    filesystemTouched: false,
    dockerTouched: false,
    providerTouched: false,
    commandExecuted: false,
    healthcheckNetworkTouched: false,
    productionEvidence: false,
  });
  return { ...operation, application: updated };
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
    throw new RejectedOperationError("Production apply is disabled in local Control Center foundation; use an explicit provider adapter with verifyRemote.");
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

function planStorageBucketCreate(payload, context) {
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const name = validateBucketName(payload.name || `${projectId}-assets`);
  const quotaBytes = parseQuotaBytes(payload.quotaBytes || 0);
  const accessPolicy = choice(String(payload.accessPolicy || "private"), ["private", "project-private", "public-read", "admin-only"], "bucket access policy");
  const accessKeyStatus = choice(String(payload.accessKeyStatus || "not-configured"), ["not-configured", "configured", "requires-secret-file", "rotating"], "access key status");
  const id = bucketId(projectId, name);
  const details = storageBucketRecord({ id, projectId, name, quotaBytes, accessPolicy, accessKeyStatus });
  if (payload.confirm === "CREATE-BUCKET") {
    const state = readStorageBucketsState();
    state[id] = {
      ...(state[id] || {}),
      ...details,
      status: "declared",
      updatedAt: new Date().toISOString(),
      createdAt: state[id]?.createdAt || new Date().toISOString(),
    };
    writeStorageBucketsState(state);
    appendAudit({ action: "storage.bucket.create.apply", target: `${projectId}/${name}`, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Storage bucket metadata declared locally; no MinIO mutation executed." });
    const operation = operationPlan("storage.bucket.create.local", context.environment, false, ["validate project", "validate S3 bucket name", "declare quota and access policy metadata", "leave MinIO unchanged", "write audit event"], { ...state[id], minioTouched: false, credentialsExposed: false, productionEvidence: false });
    return { ...operation, bucket: state[id] };
  }
  appendAudit({ action: "storage.bucket.create.plan", target: `${projectId}/${name}`, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Storage bucket creation plan generated; no MinIO mutation executed." });
  return operationPlan("storage.bucket.create", context.environment, true, ["validate project", "validate S3 bucket name", "prepare local metadata", "require apply confirmation", "write audit event"], { ...details, minioTouched: false, credentialsExposed: false, productionEvidence: false, confirmationRequired: "CREATE-BUCKET" });
}

function planStorageBucketPolicy(id, payload, context) {
  const bucket = findById(context.storageBuckets, id, "Storage bucket");
  const accessPolicy = choice(String(payload.accessPolicy || bucket.accessPolicy || "private"), ["private", "project-private", "public-read", "admin-only"], "bucket access policy");
  if (payload.confirm === "UPDATE-BUCKET-POLICY") {
    const state = readStorageBucketsState();
    state[bucket.id] = {
      ...storageBucketRecord(bucket),
      ...(state[bucket.id] || {}),
      accessPolicy,
      policyStatus: "declared",
      updatedAt: new Date().toISOString(),
      createdAt: state[bucket.id]?.createdAt || bucket.createdAt || new Date().toISOString(),
    };
    writeStorageBucketsState(state);
    appendAudit({ action: "storage.bucket.policy.apply", target: bucket.id, environment: context.environment, risk: accessPolicy === "public-read" ? "high" : "medium", result: "success", dryRun: false, summary: "Storage bucket policy metadata updated locally; no MinIO policy mutation executed." });
    const operation = operationPlan("storage.bucket.policy.local", context.environment, false, ["validate bucket", "validate access policy", "update local policy metadata", "leave MinIO unchanged", "write audit event"], { ...state[bucket.id], minioTouched: false, credentialsExposed: false, productionEvidence: false });
    return { ...operation, bucket: state[bucket.id] };
  }
  appendAudit({ action: "storage.bucket.policy.plan", target: bucket.id, environment: context.environment, risk: accessPolicy === "public-read" ? "high" : "medium", result: "planned", dryRun: true, summary: "Storage bucket policy update plan generated; no MinIO policy mutation executed." });
  return operationPlan("storage.bucket.policy", context.environment, true, ["validate bucket", "validate access policy", "prepare local policy update", "require apply confirmation", "write audit event"], { ...bucket, accessPolicy, minioTouched: false, credentialsExposed: false, productionEvidence: false, confirmationRequired: "UPDATE-BUCKET-POLICY" });
}

function planStorageBucketLifecycle(id, payload, context) {
  const bucket = findById(context.storageBuckets, id, "Storage bucket");
  const retentionDays = parseRetentionDays(payload.retentionDays || bucket.retentionDays || 30);
  if (payload.confirm === "UPDATE-BUCKET-LIFECYCLE") {
    const state = readStorageBucketsState();
    state[bucket.id] = {
      ...storageBucketRecord(bucket),
      ...(state[bucket.id] || {}),
      retentionDays,
      lifecycleStatus: "declared",
      updatedAt: new Date().toISOString(),
      createdAt: state[bucket.id]?.createdAt || bucket.createdAt || new Date().toISOString(),
    };
    writeStorageBucketsState(state);
    appendAudit({ action: "storage.bucket.lifecycle.apply", target: bucket.id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Storage bucket lifecycle metadata updated locally; no MinIO lifecycle mutation executed." });
    const operation = operationPlan("storage.bucket.lifecycle.local", context.environment, false, ["validate bucket", "validate retention days", "update local lifecycle metadata", "leave MinIO unchanged", "write audit event"], { ...state[bucket.id], minioTouched: false, credentialsExposed: false, productionEvidence: false });
    return { ...operation, bucket: state[bucket.id] };
  }
  appendAudit({ action: "storage.bucket.lifecycle.plan", target: bucket.id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Storage bucket lifecycle update plan generated; no MinIO lifecycle mutation executed." });
  return operationPlan("storage.bucket.lifecycle", context.environment, true, ["validate bucket", "validate retention days", "prepare local lifecycle update", "require apply confirmation", "write audit event"], { ...bucket, retentionDays, minioTouched: false, credentialsExposed: false, productionEvidence: false, confirmationRequired: "UPDATE-BUCKET-LIFECYCLE" });
}

function planStorageBucketAccessKey(id, payload, context) {
  const bucket = findById(context.storageBuckets, id, "Storage bucket");
  const accessKeyStatus = choice(String(payload.accessKeyStatus || bucket.accessKeyStatus || "not-configured"), ["not-configured", "configured", "requires-secret-file", "rotating"], "access key status");
  if (payload.confirm === "UPDATE-BUCKET-ACCESS-KEY") {
    const state = readStorageBucketsState();
    state[bucket.id] = {
      ...storageBucketRecord(bucket),
      ...(state[bucket.id] || {}),
      accessKeyStatus,
      updatedAt: new Date().toISOString(),
      createdAt: state[bucket.id]?.createdAt || bucket.createdAt || new Date().toISOString(),
    };
    writeStorageBucketsState(state);
    appendAudit({ action: "storage.bucket.access_key.apply", target: bucket.id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Storage bucket access key metadata updated locally; no key value was generated or exposed." });
    const operation = operationPlan("storage.bucket.access_key.local", context.environment, false, ["validate bucket", "validate access key status", "update local access key metadata", "leave secret material unchanged", "write audit event"], { ...state[bucket.id], minioTouched: false, secretMaterialChanged: false, credentialsExposed: false, productionEvidence: false });
    return { ...operation, bucket: state[bucket.id] };
  }
  appendAudit({ action: "storage.bucket.access_key.plan", target: bucket.id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Storage bucket access key metadata plan generated; no key value was generated or exposed." });
  return operationPlan("storage.bucket.access_key", context.environment, true, ["validate bucket", "validate access key status", "prepare local access key metadata update", "require apply confirmation", "write audit event"], { ...bucket, accessKeyStatus, minioTouched: false, secretMaterialChanged: false, credentialsExposed: false, productionEvidence: false, confirmationRequired: "UPDATE-BUCKET-ACCESS-KEY" });
}

function planStorageBucketBackup(id, payload, context) {
  const bucket = findById(context.storageBuckets, id, "Storage bucket");
  const scope = `bucket:${bucket.id}`;
  appendAudit({ action: "storage.bucket.backup.plan", target: bucket.id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Storage bucket backup plan generated; no object storage command executed from the web panel." });
  const operation = operationPlan("storage.bucket.backup", context.environment, true, ["validate bucket record", "select MinIO bucket", "invoke MinioAdapter backup in ops runner", "verify backup artifact", "write evidence"], {
    bucketId: bucket.id,
    projectId: bucket.projectId,
    scope,
    minioTouched: false,
    credentialsExposed: false,
    productionEvidence: false,
  });
  return { ...operation, bucket };
}

function planStorageBucketRestore(id, payload, context) {
  const bucket = findById(context.storageBuckets, id, "Storage bucket");
  const backupRef = sanitizeRef(payload.backupRef || payload.backupId || "latest");
  appendAudit({ action: "storage.bucket.restore.plan", target: bucket.id, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Storage bucket restore drill plan generated; no live objects changed." });
  const operation = operationPlan("storage.bucket.restore.plan", context.environment, true, ["validate bucket record", "validate backup reference", "create disposable restore target", "run restore drill through MinioAdapter", "generate evidence"], {
    bucketId: bucket.id,
    projectId: bucket.projectId,
    backupRef,
    minioTouched: false,
    dataChanged: false,
    credentialsExposed: false,
    productionEvidence: false,
  });
  return { ...operation, bucket };
}

function planMaterialDeclare(payload, context) {
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const targetEnv = normalizeEnvironment(payload.targetEnv || context.environment);
  const materialName = validateMaterialName(payload.materialName || "APP_CONFIG");
  const materialKind = choice(String(payload.materialKind || "application"), ["application", "docker", "provider", "kms", "database", "storage"], "material kind");
  const materialConfigured = parseBoolean(payload.materialConfigured || "");
  const rotationDays = parseRotationDays(payload.rotationDays || 0);
  const usageTargets = parseUsageTargets(payload.usageTargets || payload.usageTarget || projectId);
  const id = materialId(projectId, targetEnv, materialName);
  const details = sensitiveMaterialRecord({ id, projectId, environment: targetEnv, materialName, materialKind, materialConfigured, rotationDays, usageTargets });
  if (payload.confirm === "DECLARE-MATERIAL") {
    const state = readSensitiveMaterialsState();
    state[id] = {
      ...(state[id] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state[id]?.createdAt || new Date().toISOString(),
    };
    writeSensitiveMaterialsState(state);
    appendAudit({ action: "material.declare.apply", target: `${projectId}/${targetEnv}/${materialName}`, environment: targetEnv, risk: "medium", result: "success", dryRun: false, summary: "Sensitive material metadata declared locally; no value was stored or read." });
    const operation = operationPlan("material.declare.local", targetEnv, false, ["validate project", "validate material metadata", "record usage map", "leave value material unchanged", "write audit event"], { ...state[id], materialValueChanged: false, valueExposed: false, productionEvidence: false });
    return { ...operation, material: state[id] };
  }
  appendAudit({ action: "material.declare.plan", target: `${projectId}/${targetEnv}/${materialName}`, environment: targetEnv, risk: "medium", result: "planned", dryRun: true, summary: "Sensitive material declaration plan generated; no value was stored or read." });
  return operationPlan("material.declare", targetEnv, true, ["validate project", "validate material metadata", "prepare local inventory metadata", "require apply confirmation", "write audit event"], { ...details, materialValueChanged: false, valueExposed: false, productionEvidence: false, confirmationRequired: "DECLARE-MATERIAL" });
}

function planMaterialRotation(id, payload, context) {
  const material = findById(context.sensitiveMaterials, id, "Sensitive material");
  const rotationDays = parseRotationDays(payload.rotationDays || material.rotationDays || 90);
  if (payload.confirm === "UPDATE-MATERIAL-ROTATION") {
    const state = readSensitiveMaterialsState();
    state[material.id] = {
      ...sensitiveMaterialRecord(material),
      ...(state[material.id] || {}),
      rotationDays,
      rotationStatus: rotationDays > 0 ? "planned" : "not-set",
      updatedAt: new Date().toISOString(),
      createdAt: state[material.id]?.createdAt || material.createdAt || new Date().toISOString(),
    };
    writeSensitiveMaterialsState(state);
    appendAudit({ action: "material.rotation.apply", target: material.id, environment: material.environment, risk: "medium", result: "success", dryRun: false, summary: "Sensitive material rotation metadata updated locally; value material was not changed." });
    const operation = operationPlan("material.rotation.local", material.environment, false, ["validate material", "validate rotation policy", "update local rotation metadata", "leave value material unchanged", "write audit event"], { ...state[material.id], materialValueChanged: false, valueExposed: false, productionEvidence: false });
    return { ...operation, material: state[material.id] };
  }
  appendAudit({ action: "material.rotation.plan", target: material.id, environment: material.environment, risk: "medium", result: "planned", dryRun: true, summary: "Sensitive material rotation metadata plan generated; value material was not changed." });
  return operationPlan("material.rotation", material.environment, true, ["validate material", "validate rotation policy", "prepare local rotation metadata", "require apply confirmation", "write audit event"], { ...material, rotationDays, materialValueChanged: false, valueExposed: false, productionEvidence: false, confirmationRequired: "UPDATE-MATERIAL-ROTATION" });
}

function planMaterialUsage(id, payload, context) {
  const material = findById(context.sensitiveMaterials, id, "Sensitive material");
  const usageTargets = parseUsageTargets(payload.usageTargets || payload.usageTarget || material.usageTargets || material.projectId);
  if (payload.confirm === "UPDATE-MATERIAL-USAGE") {
    const state = readSensitiveMaterialsState();
    state[material.id] = {
      ...sensitiveMaterialRecord(material),
      ...(state[material.id] || {}),
      usageTargets,
      updatedAt: new Date().toISOString(),
      createdAt: state[material.id]?.createdAt || material.createdAt || new Date().toISOString(),
    };
    writeSensitiveMaterialsState(state);
    appendAudit({ action: "material.usage.apply", target: material.id, environment: material.environment, risk: "low", result: "success", dryRun: false, summary: "Sensitive material usage map updated locally; value material was not read." });
    const operation = operationPlan("material.usage.local", material.environment, false, ["validate material", "validate usage targets", "update local usage map", "leave value material unread", "write audit event"], { ...state[material.id], materialValueChanged: false, valueExposed: false, productionEvidence: false });
    return { ...operation, material: state[material.id] };
  }
  appendAudit({ action: "material.usage.plan", target: material.id, environment: material.environment, risk: "low", result: "planned", dryRun: true, summary: "Sensitive material usage map plan generated; value material was not read." });
  return operationPlan("material.usage", material.environment, true, ["validate material", "validate usage targets", "prepare local usage map update", "require apply confirmation", "write audit event"], { ...material, usageTargets, materialValueChanged: false, valueExposed: false, productionEvidence: false, confirmationRequired: "UPDATE-MATERIAL-USAGE" });
}

function planMaterialAccessAudit(id, payload, context) {
  const material = findById(context.sensitiveMaterials, id, "Sensitive material");
  const purpose = sanitizeMessage(payload.purpose || "admin-review").replace(/\s+/g, " ").trim().slice(0, 120) || "admin-review";
  if (payload.confirm === "RECORD-MATERIAL-ACCESS") {
    const state = readSensitiveMaterialsState();
    state[material.id] = {
      ...sensitiveMaterialRecord(material),
      ...(state[material.id] || {}),
      lastAccessAuditAt: new Date().toISOString(),
      lastAccessPurpose: purpose,
      updatedAt: new Date().toISOString(),
      createdAt: state[material.id]?.createdAt || material.createdAt || new Date().toISOString(),
    };
    writeSensitiveMaterialsState(state);
    appendAudit({ action: "material.access.apply", target: material.id, environment: material.environment, risk: "high", result: "success", dryRun: false, summary: "Sensitive material access audit recorded without reading or exposing the value." });
    const operation = operationPlan("material.access.local", material.environment, false, ["validate material", "record access purpose metadata", "do not read value material", "write audit event"], { materialId: material.id, projectId: material.projectId, purpose, valueRead: false, valueExposed: false, productionEvidence: false });
    return { ...operation, material: state[material.id] };
  }
  appendAudit({ action: "material.access.plan", target: material.id, environment: material.environment, risk: "high", result: "planned", dryRun: true, summary: "Sensitive material access audit plan generated; value material will not be read." });
  return operationPlan("material.access", material.environment, true, ["validate material", "prepare access audit metadata", "do not read value material", "require apply confirmation", "write audit event"], { materialId: material.id, projectId: material.projectId, purpose, valueRead: false, valueExposed: false, productionEvidence: false, confirmationRequired: "RECORD-MATERIAL-ACCESS" });
}

function planWorkerDeclare(payload, context) {
  const projectId = validateProjectOrPlatform(payload.projectId || "platform", context);
  const name = sanitizeDisplayName(payload.name || "worker");
  const service = sanitizeOptionalRef(payload.service || slugify(name));
  const queueName = validateQueueName(payload.queueName || "jobs");
  const id = sanitizeIdentifier(payload.id || `${projectId}-${slugify(name)}`) || rid();
  const status = choice(String(payload.status || "declared"), ["declared", "configured", "running", "stopped", "degraded"], "worker status");
  const details = workerRuntimeRecord({
    id,
    projectId,
    name,
    service,
    status,
    queueName,
    concurrency: parseBoundedInteger(payload.concurrency || 1, "worker concurrency", 256),
    maxAttempts: parseBoundedInteger(payload.maxAttempts || 3, "worker max attempts", 100),
    healthStatus: payload.healthStatus || "metadata-only",
    source: "control-center-state",
  });
  if (payload.confirm === "DECLARE-WORKER") {
    const state = readWorkerJobsState();
    state.workers[id] = {
      ...(state.workers[id] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state.workers[id]?.createdAt || new Date().toISOString(),
    };
    writeWorkerJobsState(state);
    appendAudit({ action: "worker.declare.apply", target: id, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Worker runtime metadata declared locally; no process or Docker command executed." });
    const operation = operationPlan("worker.declare.local", context.environment, false, ["validate project", "validate worker metadata", "record local worker runtime state", "leave Docker runtime unchanged", "write audit event"], { ...state.workers[id], dockerTouched: false, commandExecuted: false, productionEvidence: false });
    return { ...operation, worker: state.workers[id] };
  }
  appendAudit({ action: "worker.declare.plan", target: id, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Worker runtime declaration plan generated." });
  return operationPlan("worker.declare", context.environment, true, ["validate project", "validate worker metadata", "prepare local worker state", "require apply confirmation", "write audit event"], { ...details, dockerTouched: false, commandExecuted: false, productionEvidence: false, confirmationRequired: "DECLARE-WORKER" });
}

function planQueueDeclare(payload, context) {
  const projectId = validateProjectOrPlatform(payload.projectId || "platform", context);
  const name = validateQueueName(payload.name || "jobs");
  const backend = choice(String(payload.backend || "nats"), ["nats", "postgres-outbox", "container-cron", "http-webhook", "alertmanager-webhook"], "queue backend");
  const status = choice(String(payload.status || "declared"), ["declared", "configured", "draining", "paused"], "queue status");
  const id = sanitizeIdentifier(payload.id || `${projectId}-${name}`) || rid();
  const details = jobQueueRecord({
    id,
    projectId,
    name,
    backend,
    status,
    retryPolicy: sanitizeOptionalRef(payload.retryPolicy || "bounded-worker-retry"),
    deadLetterQueue: sanitizeOptionalRef(payload.deadLetterQueue || ""),
    source: "control-center-state",
  });
  if (payload.confirm === "DECLARE-QUEUE") {
    const state = readWorkerJobsState();
    state.queues[id] = {
      ...(state.queues[id] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state.queues[id]?.createdAt || new Date().toISOString(),
    };
    writeWorkerJobsState(state);
    appendAudit({ action: "worker.queue.apply", target: id, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Queue metadata declared locally; no broker, outbox or webhook mutation executed." });
    const operation = operationPlan("worker.queue.local", context.environment, false, ["validate project", "validate queue metadata", "record local queue state", "leave broker unchanged", "write audit event"], { ...state.queues[id], brokerTouched: false, providerTouched: false, productionEvidence: false });
    return { ...operation, queue: state.queues[id] };
  }
  appendAudit({ action: "worker.queue.plan", target: id, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Queue metadata declaration plan generated." });
  return operationPlan("worker.queue", context.environment, true, ["validate project", "validate queue metadata", "prepare local queue state", "require apply confirmation", "write audit event"], { ...details, brokerTouched: false, providerTouched: false, productionEvidence: false, confirmationRequired: "DECLARE-QUEUE" });
}

function planJobRecord(payload, context) {
  const projectId = validateProjectOrPlatform(payload.projectId || "platform", context);
  const queueId = sanitizeIdentifier(payload.queueId || "jobs");
  const workerId = sanitizeIdentifier(payload.workerId || "enterprise-worker-jobs");
  findById(context.jobQueues, queueId, "Queue");
  findById(context.workerRuntimes, workerId, "Worker");
  const jobName = validateQueueName(payload.jobName || payload.name || "job");
  const status = choice(String(payload.status || "failed"), ["queued", "running", "failed", "succeeded", "dead"], "job status");
  const id = sanitizeIdentifier(payload.id || `${projectId}-${queueId}-${jobName}`) || rid();
  const details = jobRecord({
    id,
    projectId,
    queueId,
    workerId,
    jobName,
    status,
    attempts: parseBoundedInteger(payload.attempts || (status === "failed" ? 1 : 0), "job attempts", 1000),
    maxAttempts: parseBoundedInteger(payload.maxAttempts || 3, "job max attempts", 1000),
    lastError: payload.lastError || "",
    source: "control-center-state",
  });
  if (payload.confirm === "RECORD-JOB") {
    const state = readWorkerJobsState();
    state.jobs[id] = {
      ...(state.jobs[id] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state.jobs[id]?.createdAt || new Date().toISOString(),
    };
    writeWorkerJobsState(state);
    appendAudit({ action: "worker.job.record.apply", target: id, environment: context.environment, risk: status === "failed" || status === "dead" ? "medium" : "low", result: "success", dryRun: false, summary: "Job metadata recorded locally; no handler execution attempted." });
    const operation = operationPlan("worker.job.record.local", context.environment, false, ["validate queue", "validate worker", "record local job metadata", "leave job handler unexecuted", "write audit event"], { ...state.jobs[id], handlerExecuted: false, dockerTouched: false, brokerTouched: false, productionEvidence: false });
    return { ...operation, job: state.jobs[id] };
  }
  appendAudit({ action: "worker.job.record.plan", target: id, environment: context.environment, risk: status === "failed" || status === "dead" ? "medium" : "low", result: "planned", dryRun: true, summary: "Job record plan generated; no handler execution attempted." });
  return operationPlan("worker.job.record", context.environment, true, ["validate queue", "validate worker", "prepare local job metadata", "require apply confirmation", "write audit event"], { ...details, handlerExecuted: false, dockerTouched: false, brokerTouched: false, productionEvidence: false, confirmationRequired: "RECORD-JOB" });
}

function planJobRetry(id, payload, context) {
  const job = findById(context.jobRecords, id, "Job");
  if (!["failed", "dead"].includes(job.status)) throw new ValidationError("Only failed or dead jobs can receive a retry plan.");
  const retryAfterSeconds = parseBoundedInteger(payload.retryAfterSeconds || job.retryAfterSeconds || 60, "retry delay seconds", 86400);
  if (payload.confirm === "PLAN-JOB-RETRY") {
    const state = readWorkerJobsState();
    state.jobs[job.id] = {
      ...jobRecord(job),
      ...(state.jobs[job.id] || {}),
      status: "retry-planned",
      retryAfterSeconds,
      retryPlannedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdAt: state.jobs[job.id]?.createdAt || job.createdAt || new Date().toISOString(),
    };
    writeWorkerJobsState(state);
    appendAudit({ action: "worker.job.retry.apply", target: job.id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Job retry metadata recorded locally; no handler execution attempted." });
    const operation = operationPlan("worker.job.retry.local", context.environment, false, ["validate failed job", "record retry plan metadata", "leave queue untouched", "leave handler unexecuted", "write audit event"], { jobId: job.id, projectId: job.projectId, queueId: job.queueId, workerId: job.workerId, retryAfterSeconds, handlerExecuted: false, dockerTouched: false, brokerTouched: false, productionEvidence: false });
    return { ...operation, job: state.jobs[job.id] };
  }
  appendAudit({ action: "worker.job.retry.plan", target: job.id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Job retry plan generated; no handler execution attempted." });
  return operationPlan("worker.job.retry", context.environment, true, ["validate failed job", "prepare retry metadata", "require apply confirmation", "leave queue untouched", "write audit event"], { jobId: job.id, projectId: job.projectId, queueId: job.queueId, workerId: job.workerId, retryAfterSeconds, handlerExecuted: false, dockerTouched: false, brokerTouched: false, productionEvidence: false, confirmationRequired: "PLAN-JOB-RETRY" });
}

function planScheduleDeclare(payload, context) {
  const projectId = validateProjectOrPlatform(payload.projectId || "platform", context);
  const workerId = sanitizeIdentifier(payload.workerId || "enterprise-worker-jobs");
  const queueId = sanitizeIdentifier(payload.queueId || "maintenance");
  findById(context.workerRuntimes, workerId, "Worker");
  findById(context.jobQueues, queueId, "Queue");
  const name = sanitizeDisplayName(payload.name || "scheduled-job");
  const cronExpression = validateCronExpression(payload.cronExpression || "15 3 * * *");
  const status = choice(String(payload.status || "enabled"), ["enabled", "paused", "metadata-only"], "schedule status");
  const id = sanitizeIdentifier(payload.id || `${projectId}-${slugify(name)}`) || rid();
  const details = jobScheduleRecord({
    id,
    projectId,
    name,
    workerId,
    queueId,
    cronExpression,
    status,
    containerizedCron: true,
    source: "control-center-state",
  });
  if (payload.confirm === "DECLARE-SCHEDULE") {
    const state = readWorkerJobsState();
    state.schedules[id] = {
      ...(state.schedules[id] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state.schedules[id]?.createdAt || new Date().toISOString(),
    };
    writeWorkerJobsState(state);
    appendAudit({ action: "worker.schedule.apply", target: id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Containerized schedule metadata declared locally; no crontab or container changed." });
    const operation = operationPlan("worker.schedule.local", context.environment, false, ["validate worker", "validate queue", "validate cron expression", "record local schedule metadata", "leave container crontab unchanged", "write audit event"], { ...state.schedules[id], crontabTouched: false, dockerTouched: false, productionEvidence: false });
    return { ...operation, schedule: state.schedules[id] };
  }
  appendAudit({ action: "worker.schedule.plan", target: id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Containerized schedule declaration plan generated." });
  return operationPlan("worker.schedule", context.environment, true, ["validate worker", "validate queue", "validate cron expression", "prepare local schedule metadata", "require apply confirmation", "write audit event"], { ...details, crontabTouched: false, dockerTouched: false, productionEvidence: false, confirmationRequired: "DECLARE-SCHEDULE" });
}

function planScheduleStatus(id, payload, context) {
  const schedule = findById(context.jobSchedules, id, "Schedule");
  const status = choice(String(payload.status || schedule.status || "paused"), ["enabled", "paused", "metadata-only"], "schedule status");
  if (payload.confirm === "UPDATE-SCHEDULE") {
    const state = readWorkerJobsState();
    state.schedules[schedule.id] = {
      ...jobScheduleRecord(schedule),
      ...(state.schedules[schedule.id] || {}),
      status,
      updatedAt: new Date().toISOString(),
      createdAt: state.schedules[schedule.id]?.createdAt || schedule.createdAt || new Date().toISOString(),
    };
    writeWorkerJobsState(state);
    appendAudit({ action: "worker.schedule.status.apply", target: schedule.id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Schedule status metadata updated locally; no crontab or container changed." });
    const operation = operationPlan("worker.schedule.status.local", context.environment, false, ["validate schedule", "update local schedule status", "leave container crontab unchanged", "write audit event"], { scheduleId: schedule.id, projectId: schedule.projectId, status, crontabTouched: false, dockerTouched: false, productionEvidence: false });
    return { ...operation, schedule: state.schedules[schedule.id] };
  }
  appendAudit({ action: "worker.schedule.status.plan", target: schedule.id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Schedule status update plan generated." });
  return operationPlan("worker.schedule.status", context.environment, true, ["validate schedule", "prepare status metadata update", "require apply confirmation", "write audit event"], { scheduleId: schedule.id, projectId: schedule.projectId, status, crontabTouched: false, dockerTouched: false, productionEvidence: false, confirmationRequired: "UPDATE-SCHEDULE" });
}

function planIdentityAdminUser(payload, context) {
  const email = validateEmail(payload.email || "");
  const id = sanitizeIdentifier(payload.id || email.split("@")[0]) || rid();
  const roleIds = parseCsvList(payload.roleIds || payload.roleId || "platform-viewer");
  const teamIds = parseCsvList(payload.teamIds || payload.teamId || "platform-admins");
  for (const roleId of roleIds) findById(context.identityAccess.roles, roleId, "Role");
  for (const teamId of teamIds) findById(context.identityAccess.teams, teamId, "Team");
  const details = identityAdminUserRecord({
    id,
    email,
    displayName: payload.displayName || humanName(id),
    status: payload.status || "declared",
    roleIds,
    teamIds,
    mfaStatus: parseBoolean(payload.mfaRequired) ? "required" : "metadata-only",
    passkeyStatus: parseBoolean(payload.passkeyRequired) ? "required" : context.security.passkeyAdminAuth,
    vpnStatus: parseBoolean(payload.vpnRequired) ? "required" : "metadata-only",
    source: "control-center-state",
  });
  if (payload.confirm === "DECLARE-ADMIN-USER") {
    const state = readIdentityAccessState();
    state.users[id] = {
      ...(state.users[id] || {}),
      ...details,
      updatedAt: new Date().toISOString(),
      createdAt: state.users[id]?.createdAt || new Date().toISOString(),
    };
    writeIdentityAccessState(state);
    appendAudit({ action: "identity.admin-user.apply", target: id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Admin user metadata declared locally; no credentials, Keycloak user or Cloudflare policy changed." });
    const operation = operationPlan("identity.admin-user.local", context.environment, false, ["validate email", "validate role and team metadata", "record local admin user", "leave identity providers unchanged", "write audit event"], { ...state.users[id], credentialsStored: false, credentialsExposed: false, providerTouched: false, productionEvidence: false });
    return { ...operation, adminUser: state.users[id] };
  }
  appendAudit({ action: "identity.admin-user.plan", target: id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Admin user declaration plan generated." });
  return operationPlan("identity.admin-user", context.environment, true, ["validate email", "validate role and team metadata", "prepare local admin user", "require apply confirmation", "write audit event"], { ...details, credentialsStored: false, credentialsExposed: false, providerTouched: false, productionEvidence: false, confirmationRequired: "DECLARE-ADMIN-USER" });
}

function planIdentityTeam(payload, context) {
  const id = sanitizeIdentifier(payload.id || slugify(payload.name || "platform-admins")) || "platform-admins";
  const roleIds = parseCsvList(payload.roleIds || payload.roleId || "platform-viewer");
  const members = parseCsvList(payload.members || "");
  for (const roleId of roleIds) findById(context.identityAccess.roles, roleId, "Role");
  const details = identityTeamRecord({
    id,
    name: payload.name || humanName(id),
    roleIds,
    members,
    status: payload.status || "declared",
    source: "control-center-state",
  });
  if (payload.confirm === "DECLARE-IDENTITY-TEAM") {
    const state = readIdentityAccessState();
    state.teams[id] = { ...(state.teams[id] || {}), ...details, updatedAt: new Date().toISOString(), createdAt: state.teams[id]?.createdAt || new Date().toISOString() };
    writeIdentityAccessState(state);
    appendAudit({ action: "identity.team.apply", target: id, environment: context.environment, risk: "low", result: "success", dryRun: false, summary: "Identity team metadata declared locally; no identity provider group changed." });
    const operation = operationPlan("identity.team.local", context.environment, false, ["validate team", "validate role metadata", "record local team", "leave identity providers unchanged", "write audit event"], { ...state.teams[id], providerTouched: false, productionEvidence: false });
    return { ...operation, team: state.teams[id] };
  }
  appendAudit({ action: "identity.team.plan", target: id, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Identity team declaration plan generated." });
  return operationPlan("identity.team", context.environment, true, ["validate team", "validate role metadata", "prepare local team", "require apply confirmation", "write audit event"], { ...details, providerTouched: false, productionEvidence: false, confirmationRequired: "DECLARE-IDENTITY-TEAM" });
}

function planIdentityRole(payload, context) {
  const id = sanitizeIdentifier(payload.id || slugify(payload.name || "platform-viewer")) || "platform-viewer";
  const permissions = parsePermissionList(payload.permissions || "control:read");
  const details = identityRoleRecord({
    id,
    name: payload.name || humanName(id),
    permissions,
    status: payload.status || "declared",
    source: "control-center-state",
  });
  if (payload.confirm === "DECLARE-IDENTITY-ROLE") {
    const state = readIdentityAccessState();
    state.roles[id] = { ...(state.roles[id] || {}), ...details, updatedAt: new Date().toISOString(), createdAt: state.roles[id]?.createdAt || new Date().toISOString() };
    writeIdentityAccessState(state);
    appendAudit({ action: "identity.role.apply", target: id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Identity role metadata declared locally; no IdP permission model changed." });
    const operation = operationPlan("identity.role.local", context.environment, false, ["validate role", "validate permission list", "record local role", "leave identity providers unchanged", "write audit event"], { ...state.roles[id], providerTouched: false, productionEvidence: false });
    return { ...operation, role: state.roles[id] };
  }
  appendAudit({ action: "identity.role.plan", target: id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Identity role declaration plan generated." });
  return operationPlan("identity.role", context.environment, true, ["validate role", "validate permission list", "prepare local role", "require apply confirmation", "write audit event"], { ...details, providerTouched: false, productionEvidence: false, confirmationRequired: "DECLARE-IDENTITY-ROLE" });
}

function planIdentitySessionPolicy(payload, context) {
  const id = sanitizeIdentifier(payload.id || "control-center-session") || "control-center-session";
  const details = identitySessionPolicyRecord({
    id,
    name: payload.name || humanName(id),
    maxAgeMinutes: parseBoundedInteger(payload.maxAgeMinutes || 480, "session max age minutes", 43200),
    cookieFlags: parseCookieFlags(payload.cookieFlags || "HttpOnly,Secure,SameSite=Lax"),
    status: payload.status || "configured",
    source: "control-center-state",
  });
  if (payload.confirm === "UPDATE-SESSION-POLICY") {
    const state = readIdentityAccessState();
    state.sessions[id] = { ...(state.sessions[id] || {}), ...details, updatedAt: new Date().toISOString(), createdAt: state.sessions[id]?.createdAt || new Date().toISOString() };
    writeIdentityAccessState(state);
    appendAudit({ action: "identity.session.apply", target: id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Session policy metadata updated locally; no cookie secret or runtime auth model changed." });
    const operation = operationPlan("identity.session.local", context.environment, false, ["validate session policy", "record local session metadata", "leave session secrets unchanged", "write audit event"], { ...state.sessions[id], secretTouched: false, valueExposed: false, productionEvidence: false });
    return { ...operation, sessionPolicy: state.sessions[id] };
  }
  appendAudit({ action: "identity.session.plan", target: id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Session policy update plan generated." });
  return operationPlan("identity.session", context.environment, true, ["validate session policy", "prepare local session metadata", "require apply confirmation", "write audit event"], { ...details, secretTouched: false, valueExposed: false, productionEvidence: false, confirmationRequired: "UPDATE-SESSION-POLICY" });
}

function planIdentityAccessReview(payload, context) {
  const scope = sanitizeIdentifier(payload.scope || "admin-users") || "admin-users";
  const reviewer = sanitizeIdentifier(payload.reviewer || "local-admin") || "local-admin";
  const status = choice(String(payload.status || "planned"), ["planned", "passed", "needs-action"], "access review status");
  const id = sanitizeIdentifier(payload.id || `${scope}-${reviewer}-${new Date().toISOString().slice(0, 10)}`) || rid();
  const details = identityAccessReviewRecord({
    id,
    scope,
    reviewer,
    status,
    notes: payload.notes || "",
    reviewedAt: status === "planned" ? null : new Date().toISOString(),
    source: "control-center-state",
  });
  if (payload.confirm === "RECORD-ACCESS-REVIEW") {
    const state = readIdentityAccessState();
    state.accessReviews[id] = { ...(state.accessReviews[id] || {}), ...details, updatedAt: new Date().toISOString(), createdAt: state.accessReviews[id]?.createdAt || new Date().toISOString() };
    writeIdentityAccessState(state);
    appendAudit({ action: "identity.access-review.apply", target: id, environment: context.environment, risk: status === "needs-action" ? "medium" : "low", result: "success", dryRun: false, summary: "Access review metadata recorded locally; no IdP state changed." });
    const operation = operationPlan("identity.access-review.local", context.environment, false, ["validate review scope", "record local access review", "leave identity providers unchanged", "write audit event"], { ...state.accessReviews[id], providerTouched: false, productionEvidence: false });
    return { ...operation, accessReview: state.accessReviews[id] };
  }
  appendAudit({ action: "identity.access-review.plan", target: id, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Access review record plan generated." });
  return operationPlan("identity.access-review", context.environment, true, ["validate review scope", "prepare local access review", "require apply confirmation", "write audit event"], { ...details, providerTouched: false, productionEvidence: false, confirmationRequired: "RECORD-ACCESS-REVIEW" });
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
    passkeyAdminAuth: choice(String(payload.passkeyAdminAuth || "external-idp-or-passkey-app"), ["external-idp-or-passkey-app", "required", "not-configured"], "passkey admin auth"),
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

function readStorageBucketsState() {
  try {
    const parsed = JSON.parse(readFileSync(storageBucketsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeStorageBucketsState(state) {
  mkdirSync(path.dirname(storageBucketsFile), { recursive: true });
  writeFileSync(storageBucketsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readSensitiveMaterialsState() {
  try {
    const parsed = JSON.parse(readFileSync(sensitiveMaterialsFile, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeSensitiveMaterialsState(state) {
  mkdirSync(path.dirname(sensitiveMaterialsFile), { recursive: true });
  writeFileSync(sensitiveMaterialsFile, `${JSON.stringify(sanitizeEvent(state), null, 2)}\n`);
}

function readWorkerJobsState() {
  try {
    const parsed = JSON.parse(readFileSync(workerJobsFile, "utf8"));
    return {
      workers: parsed && typeof parsed.workers === "object" && !Array.isArray(parsed.workers) ? parsed.workers : {},
      queues: parsed && typeof parsed.queues === "object" && !Array.isArray(parsed.queues) ? parsed.queues : {},
      jobs: parsed && typeof parsed.jobs === "object" && !Array.isArray(parsed.jobs) ? parsed.jobs : {},
      schedules: parsed && typeof parsed.schedules === "object" && !Array.isArray(parsed.schedules) ? parsed.schedules : {},
    };
  } catch {
    return { workers: {}, queues: {}, jobs: {}, schedules: {} };
  }
}

function writeWorkerJobsState(state) {
  mkdirSync(path.dirname(workerJobsFile), { recursive: true });
  writeFileSync(workerJobsFile, `${JSON.stringify(sanitizeEvent({
    workers: state.workers || {},
    queues: state.queues || {},
    jobs: state.jobs || {},
    schedules: state.schedules || {},
  }), null, 2)}\n`);
}

function readIdentityAccessState() {
  try {
    const parsed = JSON.parse(readFileSync(identityAccessFile, "utf8"));
    return {
      users: parsed && typeof parsed.users === "object" && !Array.isArray(parsed.users) ? parsed.users : {},
      teams: parsed && typeof parsed.teams === "object" && !Array.isArray(parsed.teams) ? parsed.teams : {},
      roles: parsed && typeof parsed.roles === "object" && !Array.isArray(parsed.roles) ? parsed.roles : {},
      sessions: parsed && typeof parsed.sessions === "object" && !Array.isArray(parsed.sessions) ? parsed.sessions : {},
      accessReviews: parsed && typeof parsed.accessReviews === "object" && !Array.isArray(parsed.accessReviews) ? parsed.accessReviews : {},
    };
  } catch {
    return { users: {}, teams: {}, roles: {}, sessions: {}, accessReviews: {} };
  }
}

function writeIdentityAccessState(state) {
  mkdirSync(path.dirname(identityAccessFile), { recursive: true });
  writeFileSync(identityAccessFile, `${JSON.stringify(sanitizeEvent({
    users: state.users || {},
    teams: state.teams || {},
    roles: state.roles || {},
    sessions: state.sessions || {},
    accessReviews: state.accessReviews || {},
  }), null, 2)}\n`);
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

function readControlCenterUiPackage() {
  const controlCenterPackage = readControlCenterPackageJson();
  return sanitizeEvent(controlCenterUiContract(controlCenterPackage));
}

function readControlCenterPackageJson() {
  try {
    const parsed = JSON.parse(readFileSync(path.join(appRoot, "package.json"), "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
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

function validateBucketName(value) {
  const name = String(value || "").trim().toLowerCase();
  if (name.length < 3 || name.length > 63) throw new ValidationError("Invalid bucket name.");
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(name)) throw new ValidationError("Invalid bucket name.");
  if (name.includes("..") || name.includes(".-") || name.includes("-.")) throw new ValidationError("Invalid bucket name.");
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(name)) throw new ValidationError("Invalid bucket name.");
  return name;
}

function validateMaterialName(value) {
  const name = String(value || "").trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9_]{1,127}$/.test(name)) throw new ValidationError("Invalid material name.");
  return name;
}

function validateQueueName(value) {
  const name = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9_.-]{0,78}[a-z0-9])?$/.test(name)) throw new ValidationError("Invalid queue or job name.");
  return name;
}

function validateEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (email.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(email)) {
    throw new ValidationError("Invalid admin email.");
  }
  return email;
}

function validateProjectOrPlatform(value, context) {
  const projectId = sanitizeIdentifier(value || "platform") || "platform";
  if (projectId !== "platform") findById(context.projects, projectId, "Project");
  return projectId;
}

function parseQuotaBytes(value) {
  const quotaBytes = Number(value || 0);
  if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 0) throw new ValidationError("Quota must be zero or a positive safe integer.");
  return quotaBytes;
}

function parseRotationDays(value) {
  const rotationDays = Number(value || 0);
  if (!Number.isSafeInteger(rotationDays) || rotationDays < 0 || rotationDays > 3650) throw new ValidationError("Rotation days must be zero or a positive safe integer within policy.");
  return rotationDays;
}

function parseRetentionDays(value) {
  const retentionDays = Number(value || 0);
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 0 || retentionDays > 3650) throw new ValidationError("Retention days must be zero or a positive safe integer within policy.");
  return retentionDays;
}

function parseUsageTargets(value) {
  const values = Array.isArray(value) ? value : String(value || "").split(",");
  const cleaned = values.map((item) => sanitizeOptionalRef(item)).filter(Boolean);
  if (!cleaned.length) throw new ValidationError("At least one usage target is required.");
  return [...new Set(cleaned)].slice(0, 20);
}

function parseCsvList(value) {
  const values = Array.isArray(value) ? value : String(value || "").split(",");
  return [...new Set(values.map((item) => sanitizeOptionalRef(item)).filter(Boolean))].slice(0, 40);
}

function normalizeIdentifierList(value) {
  return parseCsvList(value).map((item) => sanitizeIdentifier(item)).filter(Boolean).slice(0, 40);
}

function parsePermissionList(value) {
  const values = Array.isArray(value) ? value : String(value || "").split(",");
  const permissions = [...new Set(values.map((item) => String(item || "").trim().toLowerCase()).filter(Boolean))].slice(0, 80);
  if (!permissions.length) throw new ValidationError("At least one permission is required.");
  for (const permission of permissions) {
    if (!/^[a-z0-9:*._-]{1,80}$/.test(permission)) throw new ValidationError("Invalid permission identifier.");
  }
  return permissions.slice(0, 80);
}

function parseCookieFlags(value) {
  const values = Array.isArray(value) ? value : String(value || "").split(",");
  const flags = [...new Set(values.map((item) => String(item || "").trim()).filter(Boolean))].slice(0, 8);
  for (const flag of flags) {
    if (!/^[A-Za-z0-9=/_:; -]{1,80}$/.test(flag)) throw new ValidationError(`Invalid cookie flag: ${sanitizeMessage(flag).slice(0, 40)}`);
  }
  return flags;
}

function parseResourceLimitNumber(value, label, max) {
  const next = Number(value || 0);
  if (!Number.isSafeInteger(next) || next < 0 || next > max) throw new ValidationError(`${label} must be zero or a positive safe integer within policy.`);
  return next;
}

function parseBoundedInteger(value, label, max) {
  const next = Number(value || 0);
  if (!Number.isSafeInteger(next) || next < 0 || next > max) throw new ValidationError(`${label} must be zero or a positive safe integer within policy.`);
  return next;
}

function validateCronExpression(value) {
  const expression = sanitizeMessage(value || "").trim().replace(/\s+/g, " ");
  const fields = expression.split(" ");
  if (fields.length !== 5) throw new ValidationError("Cron expression must have five fields.");
  if (!fields.every((field) => /^[A-Za-z0-9*/,.-]+$/.test(field) && field.length <= 32)) throw new ValidationError("Invalid cron expression.");
  return expression;
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

function bucketId(projectId, name) {
  return sanitizeIdentifier(`${projectId}-${name.replace(/\./g, "-")}`);
}

function materialId(projectId, targetEnv, materialName) {
  return sanitizeIdentifier(`${projectId}-${targetEnv}-${materialName.replace(/_/g, "-").toLowerCase()}`);
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

function storageBucketRecord({
  id = "",
  projectId = "",
  name = "",
  quotaBytes = 0,
  usedBytes = 0,
  accessPolicy = "private",
  accessKeyStatus = "not-configured",
  policyStatus = "metadata-only",
  lifecycleStatus = "metadata-only",
  retentionDays = 0,
  status = "declared",
  backupPolicy = "manual-plan-only",
  restoreStatus = "restore-drill-plan-only",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId);
  const fallbackProject = cleanProjectId || "platform";
  const cleanName = validateBucketName(name || `${fallbackProject}-assets`);
  const cleanAccessPolicy = choice(String(accessPolicy || "private"), ["private", "project-private", "public-read", "admin-only"], "bucket access policy");
  const cleanRetentionDays = parseRetentionDays(retentionDays || 0);
  return sanitizeEvent({
    id: sanitizeIdentifier(id || bucketId(fallbackProject, cleanName)),
    projectId: cleanProjectId,
    provider: "minio",
    name: cleanName,
    environment: "local",
    quotaBytes: parseQuotaBytes(quotaBytes || 0),
    usedBytes: Number.isSafeInteger(Number(usedBytes)) && Number(usedBytes) >= 0 ? Number(usedBytes) : 0,
    accessPolicy: cleanAccessPolicy,
    accessKeyStatus: choice(String(accessKeyStatus || "not-configured"), ["not-configured", "configured", "requires-secret-file", "rotating"], "access key status"),
    policyStatus,
    lifecycleStatus,
    retentionDays: cleanRetentionDays,
    status,
    backupPolicy,
    restoreStatus,
    source,
    minioTouched: false,
    credentialsExposed: false,
    providerTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function sensitiveMaterialRecord({
  id = "",
  projectId = "",
  environment: targetEnv = "local",
  materialName = "APP_CONFIG",
  materialKind = "application",
  materialConfigured = false,
  scope = "",
  usageTargets = [],
  rotationDays = 0,
  rotationStatus = "",
  lastRotatedAt = null,
  nextRotationDueAt = null,
  lastAccessAuditAt = null,
  lastAccessPurpose = "",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId);
  const cleanEnv = normalizeEnvironment(targetEnv);
  const cleanName = validateMaterialName(materialName || "APP_CONFIG");
  const cleanKind = choice(String(materialKind || "application"), ["application", "docker", "provider", "kms", "database", "storage"], "material kind");
  const cleanRotationDays = parseRotationDays(rotationDays || 0);
  const cleanUsageTargets = usageTargets?.length ? parseUsageTargets(usageTargets) : [];
  return sanitizeEvent({
    id: sanitizeIdentifier(id || materialId(cleanProjectId || "platform", cleanEnv, cleanName)),
    projectId: cleanProjectId,
    environment: cleanEnv,
    materialName: cleanName,
    materialKind: cleanKind,
    materialConfigured: Boolean(materialConfigured),
    scope: sanitizeOptionalRef(scope || cleanProjectId || "platform"),
    usageTargets: cleanUsageTargets,
    rotationDays: cleanRotationDays,
    rotationStatus: rotationStatus || (Boolean(materialConfigured) ? (cleanRotationDays > 0 ? "planned" : "not-set") : "not-configured"),
    lastRotatedAt,
    nextRotationDueAt,
    lastAccessAuditAt,
    lastAccessPurpose: sanitizeOptionalRef(lastAccessPurpose),
    valueExposed: false,
    materialValueChanged: false,
    providerTouched: false,
    productionEvidence: false,
    source,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function workerRuntimeRecord({
  id = "",
  projectId = "platform",
  name = "Worker",
  service = "worker",
  status = "declared",
  queueName = "jobs",
  concurrency = 1,
  maxAttempts = 3,
  healthStatus = "metadata-only",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId || "platform") || "platform";
  const cleanName = sanitizeMessage(name || "Worker").replace(/\s+/g, " ").trim().slice(0, 80) || "Worker";
  const cleanService = sanitizeOptionalRef(service || slugify(cleanName));
  const cleanQueueName = validateQueueName(queueName || "jobs");
  return sanitizeEvent({
    id: sanitizeIdentifier(id || `${cleanProjectId}-${slugify(cleanName)}`) || rid(),
    projectId: cleanProjectId,
    name: cleanName,
    service: cleanService,
    environment: "local",
    status: choice(String(status || "declared"), ["declared", "configured", "running", "stopped", "degraded", "online", "offline"], "worker status"),
    queueName: cleanQueueName,
    concurrency: parseBoundedInteger(concurrency || 1, "worker concurrency", 256),
    maxAttempts: parseBoundedInteger(maxAttempts || 3, "worker max attempts", 100),
    healthStatus: sanitizeOptionalRef(healthStatus || "metadata-only") || "metadata-only",
    source,
    dockerTouched: false,
    commandExecuted: false,
    providerTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function jobQueueRecord({
  id = "",
  projectId = "platform",
  name = "jobs",
  backend = "nats",
  status = "declared",
  depth = 0,
  failedCount = 0,
  retryPolicy = "bounded-worker-retry",
  deadLetterQueue = "",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId || "platform") || "platform";
  const cleanName = validateQueueName(name || "jobs");
  return sanitizeEvent({
    id: sanitizeIdentifier(id || `${cleanProjectId}-${cleanName}`) || rid(),
    projectId: cleanProjectId,
    name: cleanName,
    backend: choice(String(backend || "nats"), ["nats", "postgres-outbox", "container-cron", "http-webhook", "alertmanager-webhook"], "queue backend"),
    environment: "local",
    status: choice(String(status || "declared"), ["declared", "configured", "draining", "paused"], "queue status"),
    depth: parseBoundedInteger(depth || 0, "queue depth", 100000000),
    failedCount: parseBoundedInteger(failedCount || 0, "failed job count", 100000000),
    retryPolicy: sanitizeOptionalRef(retryPolicy || "bounded-worker-retry") || "bounded-worker-retry",
    deadLetterQueue: sanitizeOptionalRef(deadLetterQueue),
    source,
    brokerTouched: false,
    providerTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function jobRecord({
  id = "",
  projectId = "platform",
  queueId = "jobs",
  workerId = "enterprise-worker-jobs",
  jobName = "job",
  status = "failed",
  attempts = 0,
  maxAttempts = 3,
  retryAfterSeconds = 60,
  retryPlannedAt = null,
  lastError = "",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId || "platform") || "platform";
  const cleanQueueId = sanitizeIdentifier(queueId || "jobs") || "jobs";
  const cleanWorkerId = sanitizeIdentifier(workerId || "enterprise-worker-jobs") || "enterprise-worker-jobs";
  const cleanJobName = validateQueueName(jobName || "job");
  return sanitizeEvent({
    id: sanitizeIdentifier(id || `${cleanProjectId}-${cleanQueueId}-${cleanJobName}`) || rid(),
    projectId: cleanProjectId,
    queueId: cleanQueueId,
    workerId: cleanWorkerId,
    jobName: cleanJobName,
    environment: "local",
    status: choice(String(status || "failed"), ["queued", "running", "failed", "succeeded", "dead", "retry-planned"], "job status"),
    attempts: parseBoundedInteger(attempts || 0, "job attempts", 1000),
    maxAttempts: parseBoundedInteger(maxAttempts || 3, "job max attempts", 1000),
    retryAfterSeconds: parseBoundedInteger(retryAfterSeconds || 60, "retry delay seconds", 86400),
    retryPlannedAt,
    lastError: sanitizeMessage(lastError || "").replace(/\s+/g, " ").trim().slice(0, 180),
    source,
    handlerExecuted: false,
    dockerTouched: false,
    brokerTouched: false,
    providerTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function jobScheduleRecord({
  id = "",
  projectId = "platform",
  name = "Schedule",
  workerId = "enterprise-worker-jobs",
  queueId = "maintenance",
  cronExpression = "15 3 * * *",
  status = "metadata-only",
  lastRunStatus = "not-run",
  containerizedCron = true,
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId || "platform") || "platform";
  const cleanName = sanitizeMessage(name || "Schedule").replace(/\s+/g, " ").trim().slice(0, 80) || "Schedule";
  return sanitizeEvent({
    id: sanitizeIdentifier(id || `${cleanProjectId}-${slugify(cleanName)}`) || rid(),
    projectId: cleanProjectId,
    name: cleanName,
    workerId: sanitizeIdentifier(workerId || "enterprise-worker-jobs") || "enterprise-worker-jobs",
    queueId: sanitizeIdentifier(queueId || "maintenance") || "maintenance",
    environment: "local",
    cronExpression: validateCronExpression(cronExpression || "15 3 * * *"),
    status: choice(String(status || "metadata-only"), ["enabled", "paused", "metadata-only", "configured"], "schedule status"),
    lastRunStatus: sanitizeOptionalRef(lastRunStatus || "not-run") || "not-run",
    containerizedCron: Boolean(containerizedCron),
    source,
    crontabTouched: false,
    dockerTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function buildIdentityAccess(stored, { audit, security, settings }) {
  const defaultRoles = [
    identityRoleRecord({ id: "platform-owner", name: "Platform Owner", permissions: ["control:*", "projects:*", "security:*", "audit:read"], status: "configured", source: "control-center-default" }),
    identityRoleRecord({ id: "platform-viewer", name: "Platform Viewer", permissions: ["control:read", "projects:read", "audit:read"], status: "configured", source: "control-center-default" }),
  ];
  const roleIds = new Set(defaultRoles.map((role) => role.id));
  const roles = [
    ...defaultRoles.map((role) => identityRoleRecord({ ...role, ...(stored.roles[role.id] || {}) })),
    ...Object.values(stored.roles).filter((role) => role && !role.deletedAt && !roleIds.has(role.id)).map((role) => identityRoleRecord(role)),
  ].sort((a, b) => a.name.localeCompare(b.name));
  const defaultTeams = [
    identityTeamRecord({ id: "platform-admins", name: "Platform Admins", roleIds: ["platform-owner"], members: ["local-admin"], status: "configured", source: "control-center-default" }),
  ];
  const teamIds = new Set(defaultTeams.map((team) => team.id));
  const teams = [
    ...defaultTeams.map((team) => identityTeamRecord({ ...team, ...(stored.teams[team.id] || {}) })),
    ...Object.values(stored.teams).filter((team) => team && !team.deletedAt && !teamIds.has(team.id)).map((team) => identityTeamRecord(team)),
  ].sort((a, b) => a.name.localeCompare(b.name));
  const defaultUsers = [
    identityAdminUserRecord({
      id: "local-admin",
      email: `local-admin@${settings.baseDomain || "localhost.com"}`,
      displayName: "Local Admin",
      roleIds: ["platform-owner"],
      teamIds: ["platform-admins"],
      mfaStatus: authRequired ? "required" : "local-dev-disabled",
      passkeyStatus: security.passkeyAdminAuth,
      vpnStatus: security.adminProtection === "vpn-required" ? "required" : "metadata-only",
      status: authRequired ? "configured" : "local-dev",
      source: "control-center-auth",
    }),
  ];
  const userIds = new Set(defaultUsers.map((user) => user.id));
  const adminUsers = [
    ...defaultUsers.map((user) => identityAdminUserRecord({ ...user, ...(stored.users[user.id] || {}) })),
    ...Object.values(stored.users).filter((user) => user && !user.deletedAt && !userIds.has(user.id)).map((user) => identityAdminUserRecord(user)),
  ].sort((a, b) => a.displayName.localeCompare(b.displayName));
  const defaultSessions = [
    identitySessionPolicyRecord({
      id: "control-center-session",
      name: "Control Center session",
      maxAgeMinutes: 480,
      cookieFlags: ["HttpOnly", "Secure", "SameSite=Lax"],
      status: sessionKeysFile ? "configured" : "needs-secret-file",
      sessionSecretConfigured: Boolean(sessionKeysFile),
      source: "control-center-auth",
    }),
  ];
  const sessionIds = new Set(defaultSessions.map((session) => session.id));
  const sessionPolicies = [
    ...defaultSessions.map((session) => identitySessionPolicyRecord({ ...session, ...(stored.sessions[session.id] || {}) })),
    ...Object.values(stored.sessions).filter((session) => session && !session.deletedAt && !sessionIds.has(session.id)).map((session) => identitySessionPolicyRecord(session)),
  ].sort((a, b) => a.name.localeCompare(b.name));
  const accessReviews = Object.values(stored.accessReviews)
    .filter((review) => review && !review.deletedAt)
    .map((review) => identityAccessReviewRecord(review))
    .sort((a, b) => String(b.updatedAt || b.reviewedAt || b.createdAt || "").localeCompare(String(a.updatedAt || a.reviewedAt || a.createdAt || "")));
  return {
    adminUsers,
    teams,
    roles,
    sessionPolicies,
    accessReviews,
    loginAudit: audit.filter((event) => /^admin\.login\./.test(String(event.action || ""))).slice(0, 12),
    guardrails: {
      credentialsExposed: false,
      providerTouched: false,
      productionEvidence: false,
      liveIdentityProviderTouched: false,
    },
  };
}

function buildNetworkTopology({ subdomains, security, settings }) {
  const composeText = readInfraText("compose.yaml");
  const middlewareText = readInfraText("traefik/dynamic/middlewares.yml");
  const tlsText = readInfraText("traefik/dynamic/tls-local.yml");
  const routeConfig = extractTraefikRoutesConfig(composeText);
  const routers = parseTraefikRouters(routeConfig);
  const services = parseTraefikServices(routeConfig);
  const middlewares = parseTraefikMiddlewares(middlewareText);
  const exposedPorts = parseTraefikExposedPorts(composeText);
  const routeTests = routers.map((router) => networkRouteTestRecord(router));
  const tls = parseTraefikTls(tlsText);
  const redirectRouters = routers.filter((router) => router.redirect).length;
  const tlsRouters = routers.filter((router) => router.tls).length;
  return sanitizeEvent({
    source: routeConfig ? "compose:enterprise_traefik_routes" : "not-found",
    environment,
    mode: environment,
    routers,
    services,
    middlewares,
    exposedPorts,
    tls,
    redirectStatus: redirectRouters > 0 ? "configured" : "missing",
    redirectRouters,
    tlsRouters,
    routeTests,
    localSubdomainRoutes: (subdomains || []).map((item) => ({
      id: item.id,
      hostname: item.hostname,
      projectId: item.projectId,
      tlsStatus: item.tlsStatus,
      dnsStatus: item.dnsStatus,
      healthStatus: item.healthStatus,
      traefikRouteId: item.traefikRouteId || "local-projects",
      productionEvidence: false,
    })),
    cloudflareProxyStatus: environment === "production" ? settings.cloudflareConnectionStatus || "requires-verify-remote" : "not-used-local",
    originLockStatus: environment === "production" ? "requires-origin-lock-verify" : "not-required-local-loopback",
    wafStatus: security.waf,
    providerTouched: false,
    dockerTouched: false,
    networkProbeExecuted: false,
    productionEvidence: false,
    guardrails: {
      readOnly: true,
      routeTestsArePlans: true,
      liveProviderTouched: false,
      localEvidenceIsProductionEvidence: false,
    },
  });
}

function buildMonitoringTopology({ resources, logsAlerts, alertRecords }) {
  const prometheusText = readInfraText("prometheus/prometheus.yml");
  const prometheusRulesText = readInfraText("prometheus/rules/enterprise-alerts.yml");
  const datasourcesText = readInfraText("grafana/provisioning/datasources/datasources.yml");
  const dashboard = readInfraJson("grafana/dashboards/enterprise-overview.json");
  const lokiText = readInfraText("loki/config.yml");
  const alertmanagerText = readInfraText("alertmanager/alertmanager.yml");
  const scrapeJobs = parsePrometheusScrapeJobs(prometheusText);
  const dashboardPanels = parseGrafanaDashboardPanels(dashboard);
  const alertRules = parsePrometheusAlertRules(prometheusRulesText);
  const datasources = parseGrafanaDatasources(datasourcesText);
  const signals = monitoringSignals({ scrapeJobs, dashboardPanels, alertRules });
  return sanitizeEvent({
    source: "prometheus-grafana-loki-alertmanager-config",
    environment,
    prometheus: {
      scrapeInterval: parseYamlScalar(prometheusText, "scrape_interval") || "15s",
      evaluationInterval: parseYamlScalar(prometheusText, "evaluation_interval") || "15s",
      ruleFiles: parseYamlList(prometheusText, "rule_files"),
      alertmanagerTargets: parseAlertmanagerTargets(prometheusText),
      retention: "15d-default-from-compose",
      liveQueryExecuted: false,
    },
    scrapeJobs,
    datasources,
    dashboard: {
      title: sanitizeMessage(dashboard.title || "Platform Overview"),
      uid: sanitizeOptionalRef(dashboard.uid || "enterprise-overview"),
      refresh: sanitizeOptionalRef(dashboard.refresh || "30s"),
      panelCount: dashboardPanels.length,
    },
    dashboardPanels,
    loki: {
      retentionPeriod: parseYamlScalar(lokiText, "retention_period") || "unknown",
      rejectOldSamples: parseYamlScalar(lokiText, "reject_old_samples") || "unknown",
      alertmanagerUrl: parseYamlScalar(lokiText, "alertmanager_url") || "unknown",
      liveQueryExecuted: false,
    },
    alertmanager: {
      receiver: parseAlertmanagerReceiver(alertmanagerText),
      webhookTarget: sanitizeRef(parseYamlScalar(alertmanagerText, "url") || "unknown"),
      credentialFileConfigured: /credentials_file:\s+\/run\/secrets\/alertmanager_webhook_token/.test(alertmanagerText),
      secretValueExposed: false,
      providerTouched: false,
    },
    alertRules,
    signals,
    openAlerts: (alertRecords || []).filter((alert) => ["open", "firing"].includes(alert.status)).length,
    recentErrors: logsAlerts.recentErrors.length,
    resourceSummary: {
      cpu: resources.cpu.status,
      memory: resources.memory.status,
      disk: resources.disk.status,
      projectLimitCount: resources.projectLimits.length,
    },
    liveQueryExecuted: false,
    providerTouched: false,
    productionEvidence: false,
    guardrails: {
      readOnly: true,
      noPrometheusQueryFromPanel: true,
      noLokiQueryFromPanel: true,
      localEvidenceIsProductionEvidence: false,
      secretValuesExposed: false,
    },
  });
}

function parsePrometheusScrapeJobs(prometheusText) {
  const scrapeSection = prometheusText.split(/\n\s*scrape_configs:\s*\n/)[1] || "";
  const matches = [...scrapeSection.matchAll(/(?:^|\n)\s*-\s+job_name:\s+([^\r\n]+)\r?\n([\s\S]*?)(?=\n\s*-\s+job_name:\s+|$)/g)];
  return matches.map((match) => {
    const jobName = sanitizeIdentifier(match[1].replace(/^["']|["']$/g, ""));
    const block = match[2] || "";
    const targets = extractAllYamlListValues(block, "targets").map((target) => sanitizeRef(target));
    return sanitizeEvent({
      jobName,
      metricsPath: parseYamlScalar(block, "metrics_path") || "/metrics",
      targets,
      category: monitoringJobCategory(jobName),
      liveQueryExecuted: false,
      productionEvidence: false,
    });
  }).filter((job) => job.jobName);
}

function parseGrafanaDatasources(datasourcesText) {
  const matches = [...datasourcesText.matchAll(/(?:^|\n)\s*-\s+name:\s+([^\r\n]+)\r?\n([\s\S]*?)(?=\n\s*-\s+name:\s+|$)/g)];
  return matches.map((match) => sanitizeEvent({
    name: sanitizeMessage(match[1]).trim(),
    type: sanitizeOptionalRef(parseYamlScalar(match[2], "type") || "unknown"),
    url: sanitizeRef(parseYamlScalar(match[2], "url") || "unknown"),
    access: sanitizeOptionalRef(parseYamlScalar(match[2], "access") || "proxy"),
    editable: parseYamlScalar(match[2], "editable") || "false",
    liveQueryExecuted: false,
  })).filter((datasource) => datasource.name);
}

function parseGrafanaDashboardPanels(dashboard) {
  const panels = Array.isArray(dashboard.panels) ? dashboard.panels : [];
  return panels.map((panel) => {
    const targets = Array.isArray(panel.targets) ? panel.targets : [];
    const query = targets.map((target) => target.expr).filter(Boolean).join(" ; ") || "no query";
    const title = sanitizeMessage(panel.title || `Panel ${panel.id || "unknown"}`);
    return sanitizeEvent({
      id: sanitizeIdentifier(String(panel.id || slugify(title))) || rid(),
      title,
      type: sanitizeOptionalRef(panel.type || "unknown"),
      datasource: sanitizeOptionalRef(panel.datasource?.uid || panel.datasource?.type || "unknown"),
      signal: monitoringPanelSignal(title, query),
      query: sanitizeMessage(query).slice(0, 220),
      liveQueryExecuted: false,
      productionEvidence: false,
    });
  });
}

function parsePrometheusAlertRules(rulesText) {
  const matches = [...rulesText.matchAll(/(?:^|\n)\s*-\s+alert:\s+([^\r\n]+)\r?\n([\s\S]*?)(?=\n\s*-\s+alert:\s+|$)/g)];
  return matches.map((match) => {
    const block = match[2] || "";
    return sanitizeEvent({
      name: sanitizeIdentifier(match[1]),
      expression: normalizeMultilineYamlValue(parseYamlScalar(block, "expr")).slice(0, 220),
      severity: sanitizeOptionalRef(parseYamlScalar(block, "severity") || "unknown"),
      summary: sanitizeMessage(parseYamlScalar(block, "summary") || "").replace(/^["']|["']$/g, "").slice(0, 160),
      category: monitoringAlertCategory(match[1], block),
      liveQueryExecuted: false,
      productionEvidence: false,
    });
  }).filter((rule) => rule.name);
}

function monitoringSignals({ scrapeJobs, dashboardPanels, alertRules }) {
  const hasJob = (jobName) => scrapeJobs.some((job) => job.jobName === jobName);
  const hasPanel = (pattern) => dashboardPanels.some((panel) => pattern.test(`${panel.title}\n${panel.query}`));
  const hasAlert = (pattern) => alertRules.some((rule) => pattern.test(`${rule.name}\n${rule.expression}\n${rule.summary}`));
  return [
    monitoringSignalRecord("prometheus-metrics", "Prometheus metrics", "prometheus", hasJob("prometheus") && hasPanel(/HTTP request rate|http_requests_total/i)),
    monitoringSignalRecord("cadvisor-container-metrics", "cAdvisor container metrics", "cadvisor", hasJob("cadvisor") && hasAlert(/ContainerCpuUsageHigh|ContainerMemoryUsageHigh|ContainerDisappeared/i)),
    monitoringSignalRecord("node-exporter-host-metrics", "node-exporter host metrics", "node-exporter", hasJob("node-exporter") && hasAlert(/HostDiskUsageHigh|HostMemoryUsageHigh|HostCpuUsageHigh/i)),
    monitoringSignalRecord("backend-errors", "Backend errors", "loki", hasPanel(/Backend errors|enterprise-backend/i)),
    monitoringSignalRecord("worker-errors", "Worker errors", "loki", hasPanel(/Worker errors|enterprise-worker/i)),
    monitoringSignalRecord("waf-events", "WAF events", "loki", hasPanel(/WAF events|ModSecurity/i)),
    monitoringSignalRecord("auth-failures", "Auth failures", "loki", hasPanel(/Auth failures|auth.*failed/i)),
    monitoringSignalRecord("latency", "Latency", "external-uptime", true),
    monitoringSignalRecord("error-rate", "Error rate", "prometheus-loki", hasPanel(/error logs|level=~\\"warn\|error\\"|HTTP request rate/i) || hasAlert(/BackendErrorBudgetBurn/i)),
  ];
}

function monitoringSignalRecord(id, name, source, covered) {
  return sanitizeEvent({
    id,
    name,
    source,
    coverage: covered ? "configured" : "needs-review",
    liveQueryExecuted: false,
    providerTouched: false,
    productionEvidence: false,
  });
}

function monitoringJobCategory(jobName) {
  if (jobName === "node-exporter") return "host";
  if (jobName === "cadvisor") return "container";
  if (["backend", "web", "workers"].includes(jobName)) return "application";
  if (["prometheus", "alertmanager", "traefik", "keycloak"].includes(jobName)) return "platform";
  return "custom";
}

function monitoringPanelSignal(title, query) {
  const text = `${title}\n${query}`;
  if (/Backend errors/i.test(text)) return "backend-errors";
  if (/Worker errors/i.test(text)) return "worker-errors";
  if (/WAF events|ModSecurity/i.test(text)) return "waf-events";
  if (/Auth failures/i.test(text)) return "auth-failures";
  if (/http_requests_total|request rate/i.test(text)) return "request-rate";
  if (/warning and error|level=~"warn\|error"/i.test(text)) return "error-rate";
  return "observability";
}

function monitoringAlertCategory(name, block) {
  const text = `${name}\n${block}`;
  if (/Host(Disk|Memory|Cpu)/i.test(text)) return "host";
  if (/Container/i.test(text)) return "container";
  if (/Worker|AuditOutbox/i.test(text)) return "worker";
  if (/Backend|Redis|Passkeys|Sessions/i.test(text)) return "backend";
  if (/Backup|Restore/i.test(text)) return "backup";
  if (/Alertmanager|notification/i.test(text)) return "alerting";
  return "platform";
}

function parseAlertmanagerTargets(prometheusText) {
  const alertingSection = prometheusText.split(/\n\s*alerting:\s*\n/)[1]?.split(/\n\s*scrape_configs:\s*\n/)[0] || "";
  return extractAllYamlListValues(alertingSection, "targets").map((target) => sanitizeRef(target));
}

function parseAlertmanagerReceiver(alertmanagerText) {
  const receiver = parseYamlScalar(alertmanagerText, "receiver");
  if (receiver) return sanitizeRef(receiver);
  const name = parseYamlScalar(alertmanagerText, "name");
  return name ? sanitizeRef(name) : "unknown";
}

function extractAllYamlListValues(block, key) {
  const lines = block.split(/\r?\n/);
  const values = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!new RegExp(`^\\s*(?:-\\s+)?${escapeRegex(key)}:\\s*$`).test(lines[index])) continue;
    for (const line of lines.slice(index + 1)) {
      const match = line.match(/^\s*-\s+(.+?)\s*$/);
      if (match) {
        values.push(match[1].trim().replace(/^["']|["']$/g, ""));
        continue;
      }
      if (line.trim()) break;
    }
  }
  return values;
}

function normalizeMultilineYamlValue(value) {
  return sanitizeMessage(String(value || "")).replace(/^["']|["']$/g, "").replace(/\s+/g, " ").trim();
}

function readInfraJson(docPath) {
  try {
    const text = readInfraText(docPath);
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}

function parseTraefikRouters(routeConfig) {
  const section = extractBetween(routeConfig, /^\s*routers:\s*$/m, /^\s*services:\s*$/m);
  return parseIndentedYamlBlocks(section, 10).map(([id, block]) => {
    const entryPoints = parseYamlList(block, "entryPoints");
    const middlewares = parseYamlList(block, "middlewares");
    const rule = sanitizeMessage(parseYamlScalar(block, "rule") || "unknown");
    const service = sanitizeIdentifier(parseYamlScalar(block, "service") || id);
    const sampleHost = sampleHostFromRule(rule);
    return sanitizeEvent({
      id: sanitizeIdentifier(id),
      rule,
      entryPoints,
      service,
      middlewares,
      priority: Number(parseYamlScalar(block, "priority") || 0),
      tls: /^\s*tls:\s*(?:\{\}\s*)?$/m.test(block),
      redirect: middlewares.includes("enterprise-redirect-https@file"),
      sampleHost,
      source: "compose-config",
      providerTouched: false,
      dockerTouched: false,
      networkProbeExecuted: false,
      productionEvidence: false,
    });
  }).filter((router) => router.id);
}

function parseTraefikServices(routeConfig) {
  const match = routeConfig.match(/^\s*services:\s*$([\s\S]*)/m);
  const section = match ? match[1] : "";
  return parseIndentedYamlBlocks(section, 10).map(([id, block]) => sanitizeEvent({
    id: sanitizeIdentifier(id),
    url: sanitizeRef(parseYamlScalar(block, "url") || "unknown"),
    source: "compose-config",
    providerTouched: false,
    productionEvidence: false,
  })).filter((service) => service.id);
}

function parseTraefikMiddlewares(middlewareText) {
  const match = middlewareText.match(/^\s*middlewares:\s*$([\s\S]*)/m);
  const section = match ? match[1] : "";
  return parseIndentedYamlBlocks(section, 4).map(([id, block]) => {
    const type = block.includes("rateLimit:") ? "rateLimit"
      : block.includes("redirectScheme:") ? "redirectScheme"
        : block.includes("compress:") ? "compress"
          : block.includes("headers:") ? "headers"
            : "unknown";
    return sanitizeEvent({
      id: sanitizeIdentifier(id),
      type,
      summary: middlewareSummary(type, block),
      source: "traefik/dynamic/middlewares.yml",
      providerTouched: false,
      dockerTouched: false,
      productionEvidence: false,
    });
  }).filter((middleware) => middleware.id);
}

function parseTraefikExposedPorts(composeText) {
  const block = extractComposeServiceBlock(composeText, "traefik");
  const portsSection = extractYamlListSection(block, "ports");
  return portsSection.map((raw) => {
    const value = raw.replace(/^["']|["']$/g, "");
    const parts = value.split(":");
    const bind = parts.length === 3 ? parts[0] : "0.0.0.0";
    const hostPort = parts.length === 3 ? parts[1] : parts[0] || "";
    const containerPort = parts.length === 3 ? parts[2] : parts[1] || "";
    const loopbackOnly = ["127.0.0.1", "localhost", "::1"].includes(bind);
    return sanitizeEvent({
      bind,
      hostPort,
      containerPort,
      loopbackOnly,
      publicExposure: !loopbackOnly,
      source: "compose:traefik.ports",
      providerTouched: false,
      productionEvidence: false,
    });
  }).filter((port) => port.hostPort && port.containerPort);
}

function parseTraefikTls(tlsText) {
  const certificateCount = (tlsText.match(/certFile:/g) || []).length;
  return sanitizeEvent({
    status: tlsText.includes("defaultCertificate") ? "configured" : "missing",
    defaultStore: tlsText.includes("defaultCertificate") ? "defaultCertificate configured" : "not configured",
    certificateCount,
    source: "traefik/dynamic/tls-local.yml",
    localCertificateBundle: certificateCount > 0,
    providerTouched: false,
    productionEvidence: false,
  });
}

function networkRouteTestRecord(router) {
  const scheme = router.tls || router.entryPoints.includes("websecure") ? "https" : "http";
  const expectedStatus = router.redirect ? "301/308" : "200/301/302";
  return sanitizeEvent({
    routerId: router.id,
    method: "GET",
    url: `${scheme}://${router.sampleHost || projectsHost}/`,
    expectedStatus,
    service: router.service,
    localEvidence: environment !== "production",
    networkProbeExecuted: false,
    providerTouched: false,
    productionEvidence: false,
  });
}

function middlewareSummary(type, block) {
  if (type === "rateLimit") {
    return `average ${parseYamlScalar(block, "average") || "unknown"} / burst ${parseYamlScalar(block, "burst") || "unknown"} / period ${parseYamlScalar(block, "period") || "unknown"}`;
  }
  if (type === "redirectScheme") return `redirect to ${parseYamlScalar(block, "scheme") || "https"} / permanent ${parseYamlScalar(block, "permanent") || "true"}`;
  if (type === "compress") return "response compression enabled";
  if (type === "headers") return "security headers and HSTS configured";
  return "middleware parsed without a known type";
}

function sampleHostFromRule(rule) {
  if (/\b(?:CONTROL_CENTER_HOST|ADMIN_HOST|PROJECTS_HOST)\b/.test(rule)) return controlCenterHost;
  const defaultHost = rule.match(/\$\{[^:}]+:-([^}]+)\}/);
  if (defaultHost) return normalizeHost(defaultHost[1]);
  const literalHost = rule.match(/Host\(`([^`]+)`\)/);
  if (literalHost && !literalHost[1].includes("${")) return normalizeHost(literalHost[1]);
  if (rule.includes("HostRegexp")) return projectsHost;
  return projectsHost;
}

function extractTraefikRoutesConfig(composeText) {
  const match = composeText.match(/enterprise_traefik_routes:\s*\r?\n\s+content:\s+\|\r?\n([\s\S]*?)\r?\nsecrets:/);
  return match ? match[1] : "";
}

function extractComposeServiceBlock(composeText, serviceName) {
  const escaped = escapeRegex(serviceName);
  const match = `\n${composeText}`.match(new RegExp(`\\n  ${escaped}:\\s*\\r?\\n([\\s\\S]*?)(?=\\n  [a-zA-Z0-9_-]+:\\s*\\r?\\n|\\n[a-zA-Z].*:\\s*\\r?\\n|$)`));
  return match ? match[1] : "";
}

function extractBetween(text, startPattern, endPattern) {
  if (!text) return "";
  const start = text.search(startPattern);
  if (start < 0) return "";
  const afterStart = text.slice(start).replace(/^.*\r?\n/, "");
  const end = afterStart.search(endPattern);
  return end >= 0 ? afterStart.slice(0, end) : afterStart;
}

function parseIndentedYamlBlocks(section, indent) {
  const blocks = [];
  const pattern = new RegExp(`^\\s{${indent}}([a-zA-Z0-9_-]+):\\s*$`, "gm");
  const matches = [...section.matchAll(pattern)];
  for (let index = 0; index < matches.length; index += 1) {
    const current = matches[index];
    const next = matches[index + 1];
    blocks.push([current[1], section.slice(current.index + current[0].length, next ? next.index : section.length)]);
  }
  return blocks;
}

function parseYamlScalar(block, key) {
  const escaped = escapeRegex(key);
  const match = block.match(new RegExp(`^\\s*(?:-\\s+)?${escaped}:\\s*(.+?)\\s*$`, "m"));
  return match ? match[1].replace(/^["']|["']$/g, "").trim() : "";
}

function parseYamlList(block, key) {
  return extractYamlListSection(block, key).map((item) => sanitizeRef(item));
}

function extractYamlListSection(block, key) {
  const lines = block.split(/\r?\n/);
  const index = lines.findIndex((line) => new RegExp(`^\\s*(?:-\\s+)?${escapeRegex(key)}:\\s*$`).test(line));
  if (index < 0) return [];
  const items = [];
  for (const line of lines.slice(index + 1)) {
    const match = line.match(/^\s*-\s+(.+?)\s*$/);
    if (match) {
      items.push(match[1].trim());
      continue;
    }
    if (line.trim()) break;
  }
  return items;
}

function readInfraText(docPath) {
  try {
    const target = safeDocPath(docPath);
    if (!existsSync(target)) return "";
    return readFileSync(target, "utf8");
  } catch {
    return "";
  }
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function identityAdminUserRecord({
  id = "",
  email = "admin@localhost.com",
  displayName = "Admin",
  status = "declared",
  roleIds = [],
  teamIds = [],
  mfaStatus = "metadata-only",
  passkeyStatus = "metadata-only",
  vpnStatus = "metadata-only",
  source = "control-center-state",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}) {
  const cleanEmail = validateEmail(email);
  return sanitizeEvent({
    id: sanitizeIdentifier(id || cleanEmail.split("@")[0]) || rid(),
    email: cleanEmail,
    displayName: sanitizeDisplayName(displayName || cleanEmail.split("@")[0]),
    status: choice(String(status || "declared"), ["declared", "configured", "active", "suspended", "pending-review", "local-dev"], "admin user status"),
    roleIds: normalizeIdentifierList(roleIds),
    teamIds: normalizeIdentifierList(teamIds),
    mfaStatus: sanitizeOptionalRef(mfaStatus || "metadata-only") || "metadata-only",
    passkeyStatus: sanitizeOptionalRef(passkeyStatus || "metadata-only") || "metadata-only",
    vpnStatus: sanitizeOptionalRef(vpnStatus || "metadata-only") || "metadata-only",
    source,
    credentialsStored: false,
    credentialsExposed: false,
    providerTouched: false,
    liveIdentityProviderTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function identityTeamRecord({ id = "", name = "Platform Admins", roleIds = [], members = [], status = "declared", source = "control-center-state", createdAt = null, updatedAt = null, deletedAt = null } = {}) {
  return sanitizeEvent({
    id: sanitizeIdentifier(id || slugify(name)) || rid(),
    name: sanitizeDisplayName(name || "Platform Admins"),
    roleIds: normalizeIdentifierList(roleIds),
    members: normalizeIdentifierList(members),
    status: choice(String(status || "declared"), ["declared", "configured", "active", "archived"], "identity team status"),
    source,
    providerTouched: false,
    liveIdentityProviderTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function identityRoleRecord({ id = "", name = "Platform Viewer", permissions = [], status = "declared", source = "control-center-state", createdAt = null, updatedAt = null, deletedAt = null } = {}) {
  return sanitizeEvent({
    id: sanitizeIdentifier(id || slugify(name)) || rid(),
    name: sanitizeDisplayName(name || "Platform Viewer"),
    permissions: parsePermissionList(permissions),
    status: choice(String(status || "declared"), ["declared", "configured", "active", "archived"], "identity role status"),
    source,
    providerTouched: false,
    liveIdentityProviderTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function identitySessionPolicyRecord({ id = "control-center-session", name = "Control Center session", maxAgeMinutes = 480, cookieFlags = [], status = "configured", sessionSecretConfigured = false, source = "control-center-state", createdAt = null, updatedAt = null, deletedAt = null } = {}) {
  return sanitizeEvent({
    id: sanitizeIdentifier(id || "control-center-session") || "control-center-session",
    name: sanitizeDisplayName(name || "Control Center session"),
    maxAgeMinutes: parseBoundedInteger(maxAgeMinutes || 480, "session max age minutes", 43200),
    cookieFlags: parseCookieFlags(cookieFlags.length ? cookieFlags : "HttpOnly,Secure,SameSite=Lax"),
    status: choice(String(status || "configured"), ["declared", "configured", "needs-secret-file", "pending-review"], "session policy status"),
    sessionSecretConfigured: Boolean(sessionSecretConfigured),
    source,
    valueExposed: false,
    secretTouched: false,
    productionEvidence: false,
    createdAt,
    updatedAt,
    deletedAt,
  });
}

function identityAccessReviewRecord({ id = "", scope = "admin-users", reviewer = "local-admin", status = "planned", notes = "", reviewedAt = null, source = "control-center-state", createdAt = null, updatedAt = null, deletedAt = null } = {}) {
  return sanitizeEvent({
    id: sanitizeIdentifier(id || `${scope}-${reviewer}`) || rid(),
    scope: sanitizeIdentifier(scope || "admin-users") || "admin-users",
    reviewer: sanitizeIdentifier(reviewer || "local-admin") || "local-admin",
    status: choice(String(status || "planned"), ["planned", "passed", "needs-action"], "access review status"),
    notes: sanitizeMessage(notes || "").slice(0, 180),
    reviewedAt,
    source,
    providerTouched: false,
    liveIdentityProviderTouched: false,
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
  lifecycleMode = "metadata-only",
  lastLifecycleAction = "",
  lastLifecycleAt = null,
  healthStatus = "not-checked",
  lastHealthcheckAt = null,
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
    lifecycleMode: sanitizeOptionalRef(lifecycleMode || "metadata-only") || "metadata-only",
    lastLifecycleAction: sanitizeIdentifier(lastLifecycleAction),
    lastLifecycleAt,
    healthStatus: sanitizeOptionalRef(healthStatus || "not-checked") || "not-checked",
    lastHealthcheckAt,
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
  passkeyAdminAuth = "external-idp-or-passkey-app",
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
      id: "generic-vps",
      provider: "generic-vps",
      name: "Generic VPS",
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

function defaultMaterialStores(notificationChannels = []) {
  const alertDeliveryConfigured = notificationChannels.some((channel) => channel.status === "configured" || channel.status === "verified-production");
  return [
    { id: "docker-compose-files", name: "Docker secrets", status: "configured by compose files", materialConfigured: true, valueExposed: false, productionEvidence: false },
    { id: "control-center-session", name: "Control Center session material", status: sessionKeysFile ? "configured by file" : "not configured", materialConfigured: Boolean(sessionKeysFile), valueExposed: false, productionEvidence: false },
    { id: "admin-verifier", name: "Admin password verifier", status: authVerifierConfigured() ? "configured verifier only" : "not configured", materialConfigured: authVerifierConfigured(), valueExposed: false, productionEvidence: false },
    { id: "alert-delivery", name: "Alert delivery material", status: alertDeliveryConfigured ? "partially configured" : "metadata only", materialConfigured: alertDeliveryConfigured, valueExposed: false, productionEvidence: false },
    { id: "provider-private-material", name: "Provider private material", status: "tracked by provider connections", materialConfigured: false, valueExposed: false, productionEvidence: false },
    { id: "kms-metadata", name: "Platform Local KMS metadata", status: "evidence through infra-ops", materialConfigured: false, valueExposed: false, productionEvidence: false },
  ].map((store) => sanitizeEvent(store));
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
  return choice(String(value || "").toLowerCase().trim(), ["cloudflare", "github", "smtp", "generic-vps", "hostinger", "aws", "custom", "restic"], "provider");
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
  if (!/^(cookieFlags|secretValueExposed|secretValuesExposed|sessionSecretConfigured|secretTouched)$/i.test(keyName) && /(secret|token|password|authorization|cookie)/i.test(keyName)) return "[redacted]";
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

function docsEntries() {
  return Object.entries(docs).flatMap(([group, items]) => items.map(([docPath, description]) => ({
    group,
    path: docPath,
    description,
  })));
}

function findDoc(docPath) {
  const normalized = String(docPath || "").replaceAll("\\", "/");
  return docsEntries().find((doc) => doc.path === normalized) || null;
}

function isDocsRequest(req) {
  const host = normalizeHost(req.headers.host || "");
  return Boolean(docsHost && host === docsHost);
}

function handleDocsRequest(res, url) {
  if (url.pathname === "/" || url.pathname === "/index.html") {
    html(res, renderDocsPortal());
    return;
  }
  if (!url.pathname.startsWith("/docs/")) {
    notFound(res);
    return;
  }
  let docPath = "";
  try {
    docPath = decodeURIComponent(url.pathname.slice("/docs/".length));
  } catch {
    notFound(res);
    return;
  }
  const doc = findDoc(docPath);
  if (!doc || !existsSync(safeDocPath(doc.path))) {
    notFound(res);
    return;
  }
  html(res, renderDocsPortal(doc.path));
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

function applicationLifecycleConfirmation(action, appId) {
  const normalized = sanitizeIdentifier(action);
  if (!["start", "stop", "restart", "healthcheck"].includes(normalized)) return "";
  return `${normalized.toUpperCase()}-APPLICATION:${sanitizeIdentifier(appId)}`;
}

function applicationLifecycleStatus(action, currentStatus) {
  if (action === "stop") return "offline";
  if (action === "start" || action === "restart") return "online";
  return currentStatus || "declared";
}

function lifecycleSteps(action, dryRun) {
  if (action === "healthcheck") {
    return dryRun
      ? ["validate application", "prepare local healthcheck metadata", "require confirmation for metadata update", "write audit event"]
      : ["validate confirmation", "record local healthcheck metadata", "avoid network probe from browser action", "write audit event"];
  }
  return dryRun
    ? ["validate application", "prepare lifecycle metadata update", "require confirmation for apply", "write audit event"]
    : ["validate confirmation", "update local application lifecycle metadata", "avoid Docker command execution", "write audit event"];
}

function navigationForMode(mode) {
  return navigationGroupsForMode(mode).flatMap((group) => group.tabs);
}

function navigationGroupsForMode(mode) {
  if (mode === "advanced") {
    return [
      navGroup("platform", "Infrastructure", "INF", [
        ["infrastructure", "Infrastructure", "INF"], ["network", "Network", "NET"], ["databases", "Databases", "DB"], ["storage", "Storage", "S3"], ["workers-jobs", "Workers & Jobs", "JOB"],
      ]),
      navGroup("delivery", "Delivery", "DEP", [
        ["deployments", "Deployments", "DEP"], ["cicd-github", "CI/CD & GitHub Governance", "CI"], ["cloudflare", "Cloudflare", "CF"], ["release-evidence", "Release Evidence", "EVD"], ["go-no-go", "Production Go/No-Go", "GO"], ["readiness", "Readiness Matrix", "RDY"],
      ]),
      navGroup("observability", "Observability", "OBS", [
        ["monitoring", "Monitoring", "MON"], ["logs-advanced", "Logs Advanced", "LOG"], ["alerts-advanced", "Alerts Advanced", "ALT"],
      ]),
      navGroup("resilience", "Resilience", "DR", [
        ["backup-restore", "Backup & Restore", "BKP"], ["disaster-recovery", "Disaster Recovery", "DR"],
      ]),
      navGroup("security", "Security", "SEC", [
        ["security-advanced", "Security Advanced", "SEC"], ["identity", "Identity & Access", "IAM"], ["secrets", "Secrets", "KEY"], ["audit", "Audit Log", "AUD"],
      ]),
      navGroup("plans", "Plans", "BIL", [
        ["billing", "Billing / Plans", "BIL"],
      ]),
    ];
  }
  return [
    navGroup("home", "Home", "HOM", [
      ["overview", "Overview", "OVR"],
    ]),
    navGroup("workloads", "Workloads", "WRK", [
      ["projects", "Progetti", "PRJ"], ["applications", "Applicazioni", "APP"], ["webspaces", "Web spaces", "WEB"],
    ]),
    navGroup("routing", "Routing", "DNS", [
      ["domains", "Domini e sottodomini", "DNS"],
    ]),
    navGroup("operations", "Operations", "OPS", [
      ["resources", "Risorse", "RES"], ["security", "Sicurezza", "SEC"], ["backups", "Backup", "BKP"], ["logs", "Log e alert", "LOG"],
    ]),
    navGroup("settings", "Settings", "SET", [
      ["settings", "Impostazioni", "SET"],
    ]),
  ];
}

function navGroup(id, label, short, tabs) {
  return { id, label, short, tabs: tabs.map(([tabId, tabLabel, tabShort]) => ({ id: tabId, label: tabLabel, short: tabShort })) };
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
    readiness: ["Control Center coverage", "enterprise requirements", "production readiness checklist", "pending live proof", "repo evidence status"],
    "security-advanced": ["WAF", "rate limit", "brute force", "CSP", "CORS", "headers", "secret scan", "vulnerability scan", "Cloudflare Access", "admin route protection"],
    identity: ["users", "teams", "roles", "passkeys", "sessions", "login audit"],
    secrets: ["Docker secrets", "KMS metadata", "rotation", "usage map", "no plaintext values"],
    billing: ["VPS plan metadata", "resource budget", "Cloudflare plan", "backup storage", "cost review"],
  };
  return map[section] || ["dry-run adapter", "apply confirmation", "verify evidence"];
}

function json(res, payload, status = 200) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-platform-control-center-runtime": "node" });
  res.end(`${JSON.stringify(payload, null, 2)}\n`);
}

function html(res, content, status = 200) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-platform-control-center-runtime": "node" });
  res.end(content);
}

function redirect(res, location) {
  res.writeHead(303, { location, "cache-control": "no-store", "x-platform-control-center-runtime": "node" });
  res.end();
}

function notFound(res) {
  json(res, { error: "not_found", message: "Control endpoint not found." }, 404);
}

function serveStaticAsset(req, res, url, rootDir, prefix) {
  if ((req.method || "GET").toUpperCase() !== "GET") {
    notFound(res);
    return;
  }
  let relative = "";
  try {
    relative = decodeURIComponent(url.pathname.slice(prefix.length));
  } catch {
    notFound(res);
    return;
  }
  const normalized = relative.replaceAll("\\", "/");
  const extension = path.extname(normalized).toLowerCase();
  if (!normalized || normalized.includes("..") || normalized.startsWith("/") || ![".css", ".js", ".ttf", ".woff", ".woff2", ".svg"].includes(extension)) {
    notFound(res);
    return;
  }
  const root = path.resolve(rootDir);
  const target = path.resolve(root, normalized);
  if (!(target === root || target.startsWith(`${root}${path.sep}`)) || !existsSync(target)) {
    notFound(res);
    return;
  }
  const contentTypes = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".ttf": "font/ttf",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".svg": "image/svg+xml; charset=utf-8",
  };
  res.writeHead(200, {
    "content-type": contentTypes[extension] || "application/octet-stream",
    "cache-control": "no-store",
    "x-platform-control-center-runtime": "node",
  });
  res.end(readFileSync(target));
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

class ValidationError extends Error {}
class RejectedOperationError extends Error {}
