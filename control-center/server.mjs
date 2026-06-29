import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync, statfsSync, writeFileSync, appendFileSync } from "node:fs";
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
const dockerStatsFile = process.env.PROJECT_DOCKER_STATS_FILE || "/var/www/project-state/docker-stats.json";
const statusRunsFile = process.env.PROJECT_STATUS_RUNS_FILE || "/var/www/project-state/status-runs.jsonl";
const sessionKeysFile = process.env.CONTROL_CENTER_SESSION_KEYS_FILE || "";
const adminPasswordFile = process.env.CONTROL_CENTER_ADMIN_PASSWORD_FILE || "";
const postgresAppPasswordFile = process.env.CONTROL_CENTER_POSTGRES_APP_PASSWORD_FILE || "";
const adminPasswordSha256 = String(process.env.CONTROL_CENTER_ADMIN_PASSWORD_SHA256 || "").trim().toLowerCase();
const authRequired = parseBoolean(process.env.CONTROL_CENTER_AUTH_REQUIRED || "") || Boolean(adminPasswordSha256 || adminPasswordFile);
const environment = normalizeEnvironment(process.env.CONTROL_CENTER_ENV || "local");
const platformName = String(process.env.PLATFORM_NAME || "Platform Infrastructure").trim() || "Platform Infrastructure";
const domain = normalizeHost(process.env.DOMAIN || process.env.LOCAL_DOMAIN || "localhost.com");
const adminHost = normalizeHost(process.env.ADMIN_HOST || `portal.${domain}`);
const controlCenterHost = normalizeHost(process.env.CONTROL_CENTER_HOST || process.env.PROJECTS_HOST || adminHost);
const docsHost = normalizeHost(process.env.DOCS_HOST || `docs.${domain}`);
const projectsHost = controlCenterHost;
const hostSuffix = normalizeHostSuffix(process.env.PROJECT_HOST_SUFFIX || `.${domain}`);
const nodeHosts = parsePairs(process.env.NODE_PROJECT_HOSTS || "");
const discoverHostedProjects = parseBoolean(process.env.CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS || "");
const prometheusUrl = String(process.env.CONTROL_CENTER_PROMETHEUS_URL || "http://prometheus:9090").trim();
const resourceProbeTimeoutMs = clampNumber(Number(process.env.CONTROL_CENTER_RESOURCE_PROBE_TIMEOUT_MS || 900), 250, 5000);
const resourceMetricsTtlMs = clampNumber(Number(process.env.CONTROL_CENTER_RESOURCE_METRICS_TTL_MS || 10000), 1000, 60000);
const resourceProbeFailureCooldownMs = clampNumber(Number(process.env.CONTROL_CENTER_RESOURCE_PROBE_FAILURE_COOLDOWN_MS || 15000), 1000, 120000);
const resourceMetricsCache = { value: null, expiresAt: 0, failedUntil: 0 };
const projectDiskUsageTtlMs = clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_TTL_MS || 30000), 1000, 300000);
const projectDiskUsageCache = new Map();
const phpMyAdminInternalUrl = String(process.env.CONTROL_CENTER_PHPMYADMIN_INTERNAL_URL || "http://phpmyadmin:80").replace(/\/$/, "");
const phpPgAdminInternalUrl = String(process.env.CONTROL_CENTER_PHPPGADMIN_INTERNAL_URL || "http://phppgadmin:80").replace(/\/$/, "");
const postgresHost = normalizeHost(process.env.CONTROL_CENTER_POSTGRES_HOST || "postgres");
const postgresPort = clampNumber(Number(process.env.CONTROL_CENTER_POSTGRES_PORT || 5432), 1, 65535);
const postgresAppUser = sanitizeDatabasePrincipal(process.env.CONTROL_CENTER_POSTGRES_APP_USER || process.env.APP_DB_USER || "app_user") || "app_user";
const appStressProfiles = String(process.env.CONTROL_CENTER_APP_STRESS_PROFILES || "100,250,500,1000").trim();
const appStressDurationSeconds = clampNumber(Number(process.env.CONTROL_CENTER_APP_STRESS_DURATION_SECONDS || 60), 5, 3600);
const appStressPerUserRps = Number(process.env.CONTROL_CENTER_APP_STRESS_PER_USER_RPS || 0.5);
const appStressMaxConcurrency = clampNumber(Number(process.env.CONTROL_CENTER_APP_STRESS_MAX_CONCURRENCY || 1000), 1, 10000);
const appStressMaxP95Ms = clampNumber(Number(process.env.CONTROL_CENTER_APP_STRESS_MAX_P95_MS || 2500), 100, 60000);
const statusWafUrl = String(process.env.CONTROL_CENTER_STATUS_WAF_URL || "https://waf:8443").replace(/\/$/, "");
const statusProbeTimeoutMs = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_PROBE_TIMEOUT_MS || 4000), 500, 15000);
const statusProbeTlsVerify = parseBoolean(process.env.CONTROL_CENTER_STATUS_TLS_VERIFY || "");

const docs = {
  "Overview": [
    ["DOCUMENTATION-INDEX.md", "Documentation map and source-of-truth order"],
    ["README.md", "Platform overview, local usage, hosts and commands"],
    ["INFRASTRUCTURE-DEEP-DIVE.md", "Complete infrastructure architecture and operations map"],
    ["READINESS-REPORT.md", "Current readiness status and remaining gaps"],
    ["FINAL-READINESS-AUDIT.md", "Final audit notes and evidence summary"],
  ],
  "Operations": [
    ["CURRENT-OPERATING-MODEL.md", "Current reference server, compose profile and migration checklist"],
    ["RUNBOOK.md", "Day-2 operations, incident response and recovery"],
    ["VPS-PREDEPLOY-CHECKLIST.md", "VPS pre-deploy checklist"],
    ["ENTERPRISE-10-PLAN.md", "Enterprise roadmap and acceptance criteria"],
    ["PLATFORM-APPLICATION-SEPARATION-AUDIT.md", "Platform/application boundary and hosted workload rules"],
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
      appendAudit({
        action: "admin.logout.success",
        target: "control-center",
        environment,
        risk: "low",
        result: "success",
        dryRun: false,
        summary: "Admin session cleared.",
      });
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
    const context = await buildContext({ projects, state });

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

    if (req.method === "POST" && url.pathname === "/actions/database-admin-login") {
      await handleDatabaseAdminLogin(req, res, context);
      return;
    }

    if (req.method === "GET" && url.pathname === "/actions/phpmyadmin-login") {
      await handlePhpMyAdminLogin(req, res, url, context);
      return;
    }

    if (req.method === "GET" && url.pathname === "/actions/phppgadmin-login") {
      await handlePhpPgAdminLogin(req, res, url, context);
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

    if (req.method === "POST" && url.pathname === "/actions/status-check") {
      await handleStatusCheck(req, res, context);
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
    appendAudit({
      action: "admin.login.unavailable",
      target: "control-center",
      environment,
      risk: "low",
      result: "skipped",
      dryRun: true,
      summary: "Admin login attempted while local password authentication is not configured.",
    });
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
    if (method === "GET" && route(parts, "control", "status")) return json(res, { goNoGo: context.goNoGo, readiness: context.readiness, statusRun: context.statusRun });
    if (method === "GET" && route(parts, "control", "go-no-go")) return json(res, context.goNoGo);
    if (method === "GET" && route(parts, "control", "projects")) return json(res, { projects: context.projects });
    if (method === "POST" && route(parts, "control", "projects")) return json(res, planProjectCreate(payload, context), 202);
    if (method === "GET" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "projects", "files")) {
      return json(res, readProjectFiles(parts[2], url.searchParams.get("path") || "", context));
    }
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

    if (method === "GET" && route(parts, "control", "resources", "summary")) return json(res, resourceControlPayload(context));
    if (method === "POST" && route(parts, "control", "resources", "limits")) return json(res, planResourceLimitUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "monitoring")) {
      appendAudit({
        action: "admin.monitoring.access",
        target: "monitoring",
        environment: context.environment,
        risk: "low",
        result: "success",
        dryRun: true,
        summary: "Monitoring topology viewed from Control Center.",
      });
      return json(res, context.monitoring);
    }
    if (method === "GET" && route(parts, "control", "security", "summary")) return json(res, context.security);
    if (method === "POST" && route(parts, "control", "security", "policy")) return json(res, planSecurityPolicyUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "logs", "summary")) return json(res, context.logsAlerts);
    if (method === "GET" && route(parts, "control", "alerts")) return json(res, { alerts: context.alertRecords, notificationChannels: context.notificationChannels });
    if (method === "POST" && route(parts, "control", "alerts", "record")) return json(res, planAlertRecord(payload, context), 202);
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "alerts", "resolve")) {
      return json(res, planAlertResolution(parts[2], payload, context), 202);
    }
    if (method === "POST" && route(parts, "control", "notifications", "channel")) return json(res, planNotificationChannelUpdate(payload, context), 202);
    if (method === "GET" && route(parts, "control", "provider-connections")) {
      appendAudit({
        action: "admin.providers.access",
        target: "provider-connections",
        environment: context.environment,
        risk: "low",
        result: "success",
        dryRun: true,
        summary: "Provider connection metadata viewed from Control Center.",
      });
      return json(res, { providerConnections: context.providerConnections });
    }
    if (method === "POST" && parts.length === 3 && route(parts.slice(0, 2), "control", "provider-connections")) {
      return json(res, planProviderConnectionUpdate(parts[2], payload, context), 202);
    }
    if (method === "GET" && route(parts, "control", "settings")) return json(res, context.settings);
    if (method === "GET" && route(parts, "control", "ui-package")) return json(res, context.uiPackage);
    if (method === "GET" && route(parts, "control", "readiness")) {
      appendAudit({
        action: "admin.readiness.access",
        target: "readiness",
        environment: context.environment,
        risk: "low",
        result: "success",
        dryRun: true,
        summary: "Readiness matrix viewed from Control Center.",
      });
      return json(res, context.readiness);
    }
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

async function handleStatusCheck(req, res, context) {
  const run = await runStatusVerification(context);
  appendStatusRun(run);
  appendAudit({
    action: "status.verify.run",
    target: "platform-infrastructure",
    environment: context.environment,
    risk: "low",
    result: run.status === "passed" ? "success" : run.status === "failed" ? "failed" : "warning",
    dryRun: false,
    summary: `Read-only status verification executed: ${run.summary.passed} passed, ${run.summary.failed} failed, ${run.summary.pending} pending.`,
  });
  if (wantsJson(req)) {
    json(res, run, 202);
    return;
  }
  redirect(res, "/?section=status#status-run");
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
  redirect(res, `/?section=databases#database-${encodeURIComponent(operation.details?.databaseId || operation.database?.id || "")}`);
}

async function handleDatabaseAdminLogin(req, res, context) {
  const payload = await readPayload(req);
  await openPhpMyAdminDatabase(res, context, payload);
}

async function handlePhpMyAdminLogin(req, res, url, context) {
  await openPhpMyAdminDatabase(res, context, {
    id: url.searchParams.get("databaseId") || url.searchParams.get("id") || "",
    confirm: url.searchParams.get("confirm") || "",
  });
}

async function openPhpMyAdminDatabase(res, context, payload) {
  try {
    const database = findById(context.databases, payload.id || payload.databaseId || "", "Database");
    if (database.engine !== "mariadb") throw new ValidationError("phpMyAdmin is available only for MariaDB databases.");
    const confirmation = `OPEN-PHPMYADMIN:${database.id}`;
    if (payload.confirm !== confirmation) throw new ValidationError("Missing phpMyAdmin confirmation token.");
    const project = resolveContextProject(context, database.projectId);
    const credential = resolveMariaDbCredential(database, project);
    if (!credential) {
      appendAudit({ action: "database.phpmyadmin.login", target: database.id, environment: context.environment, risk: "medium", result: "rejected", dryRun: true, summary: "phpMyAdmin app-scoped login rejected because no per-app database credential was found." });
      renderTransientMessage(res, 409, "Accesso phpMyAdmin non configurato", `Non ho trovato credenziali MariaDB limitate per ${databaseDisplayName(database)}. Configura DB_USER/DB_PASSWORD dell'app o metadata adminUser/adminPasswordFile.`);
      return;
    }
    const login = await phpMyAdminLogin(database, credential);
    if (!login.ok) {
      appendAudit({ action: "database.phpmyadmin.login", target: database.id, environment: context.environment, risk: "medium", result: "failed", dryRun: true, summary: "phpMyAdmin app-scoped login failed without exposing credentials." });
      renderTransientMessage(res, 502, "Login phpMyAdmin fallito", "phpMyAdmin non ha accettato la credenziale limitata dell'app. Controlla utente DB e grants.");
      return;
    }
    appendAudit({ action: "database.phpmyadmin.login", target: database.id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "phpMyAdmin app-scoped session started; credential value not exposed." });
    const location = phpMyAdminDatabaseLocation(database.name, login.token);
    renderPhpMyAdminBridge(res, location, databaseDisplayName(database), [
      ...expiredPhpMyAdminCookies(),
      ...login.cookies,
    ]);
  } catch (error) {
    if (error instanceof ValidationError || error instanceof RejectedOperationError) {
      renderTransientMessage(res, error instanceof ValidationError ? 422 : 409, "Azione non valida", error.message);
      return;
    }
    throw error;
  }
}

async function handlePhpPgAdminLogin(req, res, url, context) {
  const databaseId = String(url.searchParams.get("databaseId") || "").trim();
  const confirm = String(url.searchParams.get("confirm") || "");
  try {
    const database = databaseId ? findById(context.databases, databaseId, "Database") : null;
    if (!database || database.engine !== "postgres") throw new ValidationError("phpPgAdmin e disponibile solo per database PostgreSQL.");
    const confirmation = `OPEN-PHPPGADMIN:${database.id}`;
    if (confirm !== confirmation) throw new ValidationError("Missing phpPgAdmin confirmation token.");
    const project = resolveContextProject(context, database.projectId);
    const credential = resolvePostgresCredential(database, project);
    if (!credential) {
      appendAudit({ action: "database.phppgadmin.login", target: database.id, environment: context.environment, risk: "medium", result: "rejected", dryRun: true, summary: "phpPgAdmin app-scoped login rejected because no PostgreSQL credential was found." });
      renderTransientMessage(res, 409, "Accesso phpPgAdmin non configurato", `Non ho trovato credenziali PostgreSQL limitate per ${databaseDisplayName(database)}. Configura adminPasswordFile oppure CONTROL_CENTER_POSTGRES_APP_PASSWORD_FILE.`);
      return;
    }
    const login = await phpPgAdminLogin(database, credential);
    if (!login.ok) {
      appendAudit({ action: "database.phppgadmin.login", target: database.id, environment: context.environment, risk: "medium", result: "failed", dryRun: true, summary: "phpPgAdmin app-scoped login failed without exposing credentials." });
      renderTransientMessage(res, 502, "Login phpPgAdmin fallito", "phpPgAdmin non ha accettato la credenziale limitata PostgreSQL. Controlla utente DB e grants.");
      return;
    }
    appendAudit({ action: "database.phppgadmin.login", target: database.id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "phpPgAdmin app-scoped PostgreSQL session started; credential value not exposed." });
    renderPhpPgAdminBridge(res, login.location, databaseDisplayName(database), [
      ...expiredPhpPgAdminCookies(),
      ...login.cookies,
    ]);
  } catch (error) {
    if (error instanceof ValidationError || error instanceof RejectedOperationError) {
      renderTransientMessage(res, error instanceof ValidationError ? 422 : 409, "Azione non valida", error.message);
      return;
    }
    throw error;
  }
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
    else if (action === "stress-test") operation = planApplicationStressTest(payload, context);
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

async function buildContext({ projects, state }) {
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
  const databaseNameHints = discoverProjectDatabaseHints(projects);
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
  const liveResources = await collectLiveResourceUsage({ projects, applications, webspaces });
  const resources = {
    mode: environment,
    source: liveResources.source,
    capturedAt: liveResources.capturedAt,
    totals: liveResources.totals,
    cpu: { status: liveResources.totals.cpu.available ? cpuPercentLabel(liveResources.totals.cpu.usedPercent) : "non disponibile", summary: liveResources.totals.cpu.available ? `${coresLabel(liveResources.totals.cpu.cores)} disponibili, misurati da Prometheus` : liveResources.totals.cpu.message },
    memory: { status: liveResources.totals.memory.available ? `${usageBytesLabel(liveResources.totals.memory.usedBytes)} / ${usageBytesLabel(liveResources.totals.memory.totalBytes)}` : "non disponibile", summary: liveResources.totals.memory.available ? `${percentLabel(liveResources.totals.memory.usedPercent)} RAM usata` : liveResources.totals.memory.message },
    disk: { status: liveResources.totals.disk.available ? `${usageBytesLabel(liveResources.totals.disk.usedBytes)} / ${usageBytesLabel(liveResources.totals.disk.totalBytes)}` : "non disponibile", webspacesBytes: webspaces.reduce((sum, item) => sum + item.usedBytes, 0), ...liveResources.totals.disk },
    containersByProject: liveResources.containersByProject,
    projectUsage: liveResources.projectUsage,
    containerMetricsAvailable: liveResources.containerMetricsAvailable,
    projectLimits: projects.map((project) => resourceLimitRecord({ projectId: project.slug, ...(storedResourceLimits[project.slug] || {}) })),
    trend: liveResources.containerMetricsAvailable ? "container metrics disponibili" : "metriche container non disponibili: CPU/RAM per applicazione non attribuibili con precisione",
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
  const goNoGo = readLatestGoNoGoReport();
  const statusRun = readLatestStatusRun();
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
    goNoGo: {
      status: goNoGo.status,
      generatedAt: goNoGo.generatedAt,
      passed: goNoGo.summary.passed,
      failed: goNoGo.summary.failed,
      pending: goNoGo.summary.pendingLiveProof + goNoGo.summary.pendingProvider,
      blockers: goNoGo.blockers.length,
    },
    statusRun: statusRun ? {
      status: statusRun.status,
      generatedAt: statusRun.generatedAt,
      passed: statusRun.summary?.passed || 0,
      failed: statusRun.summary?.failed || 0,
      pending: statusRun.summary?.pending || 0,
    } : null,
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
    databaseNameHints,
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
    goNoGo,
    statusRun,
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
  const enterpriseLiveProofReport = readLatestEnterpriseRequirementsReport();
  const enterprise = manifestReadiness("enterprise-requirements", "Enterprise requirements", readGovernanceManifest("enterprise-requirements.json"), enterpriseLiveProofReport);
  const productionLiveProofReport = readLatestProductionReadinessReport();
  const production = manifestReadiness("production-readiness", "Production readiness checklist", readGovernanceManifest("production-readiness.json"), productionLiveProofReport);
  const controlChecks = [
    readinessCheck({
      id: "control-center-local-ui",
      title: "Control Center local UI contract",
      status: context.uiPackage.controlCenterPackageLoaded && context.uiPackage.packageMountedInControlCenterProject && context.uiPackage.apiManifestLoaded && context.uiPackage.missingRequiredExports.length === 0 ? "passed" : "needs-work",
      evidence: ["@platform/control-center package", "control-center/components", "control-center/styles/control-center.css", "local operations shell contract"],
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
      enterpriseLive: enterpriseLiveProofReport,
      productionReadiness: production,
      productionReadinessLive: productionLiveProofReport,
    },
    productionBlockers: allChecks
      .filter((item) => item.status === "needs-work" || item.status === "pending-live-proof")
      .map((item) => ({ id: item.id, status: item.status, nextAction: item.nextAction }))
      .slice(0, 40),
  });
}

async function runStatusVerification(context) {
  const startedAt = new Date().toISOString();
  const startedMs = Date.now();
  const checks = [];
  const add = (check) => checks.push(statusRunCheck(check));

  add(await statusHttpCheck({
    id: "portal-through-waf",
    title: "Portal attraverso WAF",
    category: "routing",
    source: "Test reale",
    url: `${statusWafUrl}/`,
    headers: statusProbeHeaders(),
    okStatuses: [200],
    bodyIncludes: "Admin Control Center",
    okDetail: "La richiesta passa da WAF/Traefik e renderizza il Portal.",
    failAction: "Verifica WAF, Traefik e host portal prima di dichiarare lo stato online.",
  }));

  add(await statusHttpCheck({
    id: "waf-sensitive-file-block",
    title: "WAF blocca file sensibili",
    category: "security",
    source: "Test reale",
    url: `${statusWafUrl}/.env`,
    headers: statusProbeHeaders(),
    okStatuses: [403, 404, 406],
    okDetail: "La route pubblica non espone file .env.",
    failAction: "Blocca subito l'esposizione di file sensibili su WAF/Traefik.",
  }));

  const goNoGo = context.goNoGo || {};
  add({
    id: "go-no-go-report-readable",
    title: "Report go/no-go leggibile",
    category: "evidence",
    source: "Report",
    status: goNoGo.reportPath ? "passed" : "pending-live-proof",
    detail: goNoGo.reportPath ? `Report caricato: ${goNoGo.reportPath}` : "Nessun report production-go-no-go trovato.",
    nextAction: goNoGo.reportPath ? "Mantieni il report aggiornato dopo ogni cambio infrastruttura." : "Esegui il go/no-go completo dal server e conserva il report.",
  });

  add({
    id: "go-no-go-verdict",
    title: "Decisione produzione",
    category: "evidence",
    source: "Report",
    status: goNoGo.status === "go" ? "passed" : goNoGo.reportPath ? "no-go" : "pending-live-proof",
    detail: goNoGo.status === "go"
      ? "Il report più recente dice GO LIVE."
      : `Il report più recente dice ${String(goNoGo.status || "unknown").toUpperCase()} con ${Number(goNoGo.summary?.blockingRequired || goNoGo.blockers?.length || 0)} blocchi.`,
    nextAction: goNoGo.status === "go" ? "Procedi solo con backup e rollback pronti." : "Chiudi i requisiti aperti, poi rilancia il controllo.",
  });

  const readinessTotal = Number(context.readiness?.summary?.total || 0);
  add({
    id: "readiness-matrix-readable",
    title: "Matrice readiness caricata",
    category: "evidence",
    source: "Report",
    status: readinessTotal > 0 ? "passed" : "needs-work",
    detail: readinessTotal > 0 ? `${readinessTotal} controlli readiness letti dai manifest.` : "Nessun controllo readiness disponibile.",
    nextAction: readinessTotal > 0 ? "Mantieni governance/production-readiness.json e enterprise-requirements.json coerenti." : "Ripristina i manifest governance prima del prossimo go live.",
  });

  const summary = statusRunSummary(checks);
  return sanitizeEvent({
    id: `status-${startedMs.toString(36)}`,
    generatedAt: startedAt,
    finishedAt: new Date().toISOString(),
    durationMs: Date.now() - startedMs,
    status: summary.failed ? "failed" : summary.pending ? "warning" : "passed",
    scope: "platform-infrastructure",
    destructive: false,
    providerTouched: false,
    dockerTouched: false,
    summary,
    checks,
  });
}

function statusProbeHeaders(extra = {}) {
  return {
    Host: controlCenterHost,
    "X-Forwarded-Host": controlCenterHost,
    "X-Forwarded-Proto": "https",
    "User-Agent": "platform-control-center-status/1.0",
    ...extra,
  };
}

async function statusHttpCheck({ id, title, category, source, url, headers = {}, okStatuses = [200], bodyIncludes = "", okDetail = "", failAction = "" }) {
  const startedMs = Date.now();
  try {
    const response = await statusHttpRequest(url, headers);
    const durationMs = Date.now() - startedMs;
    const bodyOk = !bodyIncludes || response.body.includes(bodyIncludes);
    const statusOk = okStatuses.includes(response.status);
    return statusRunCheck({
      id,
      title,
      category,
      source,
      status: statusOk && bodyOk ? "passed" : "failed",
      detail: statusOk && bodyOk
        ? `${okDetail} HTTP ${response.status}, ${durationMs} ms.`
        : `Risposta inattesa: HTTP ${response.status}, body=${bodyOk ? "ok" : "non valido"}, ${durationMs} ms.`,
      nextAction: statusOk && bodyOk ? "Nessuna azione immediata." : failAction,
    });
  } catch (error) {
    return statusRunCheck({
      id,
      title,
      category,
      source,
      status: "failed",
      detail: sanitizeMessage(error?.message || String(error)),
      nextAction: failAction || "Controlla rete interna e route prima di rilanciare il test.",
    });
  }
}

function statusHttpRequest(urlString, headers = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(urlString);
    const isHttps = target.protocol === "https:";
    if (target.protocol !== "http:" && !isHttps) {
      reject(new Error("Status probe supports only internal HTTP/HTTPS targets."));
      return;
    }
    const requestPath = `${target.pathname || "/"}${target.search || ""}`;
    const requestFn = isHttps ? httpsRequest : httpRequest;
    const req = requestFn({
      method: "GET",
      hostname: target.hostname,
      port: target.port || (isHttps ? 443 : 80),
      path: requestPath,
      headers,
      rejectUnauthorized: isHttps ? statusProbeTlsVerify : undefined,
      timeout: statusProbeTimeoutMs,
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("timeout", () => req.destroy(new Error(`Status probe timed out for ${target.hostname}${requestPath}.`)));
    req.on("error", reject);
    req.end();
  });
}

function statusRunCheck({ id, title, category = "general", source = "Test reale", status = "failed", detail = "", nextAction = "", required = true }) {
  return {
    id: sanitizeIdentifier(id || title || "status-check") || "status-check",
    title: sanitizeMessage(title || humanName(id || "status-check")),
    category: sanitizeIdentifier(category || "general") || "general",
    source: sanitizeMessage(source || "Test reale"),
    required: required !== false,
    status: sanitizeIdentifier(status || "failed") || "failed",
    detail: sanitizeMessage(detail || ""),
    nextAction: sanitizeMessage(nextAction || ""),
  };
}

function statusRunSummary(checks) {
  const passed = checks.filter((check) => check.status === "passed").length;
  const failed = checks.filter((check) => ["failed", "needs-work"].includes(check.status)).length;
  const pending = checks.filter((check) => ["authorization-required", "pending-live-proof", "pending-provider", "plan-only"].includes(check.status)).length;
  return {
    total: checks.length,
    passed,
    failed,
    pending,
  };
}

const documentedStatusTitles = {
  "audit-log-evidence": "Evidence audit log",
  "alert-evidence": "Evidence alert reali",
  "backup-keycloak": "Backup Keycloak",
  "backup-mariadb": "Backup MariaDB",
  "backup-minio": "Backup MinIO",
  "backup-postgres": "Backup PostgreSQL",
  "backup-restore-drill": "Restore drill PostgreSQL",
  "backup-restore-drill-keycloak": "Restore drill Keycloak",
  "backup-restore-drill-mariadb": "Restore drill MariaDB",
  "backup-restore-drill-minio": "Restore drill MinIO",
  "backup-restore-drill-secret-manager-metadata": "Restore drill metadata secrets",
  "backup-secret-manager-metadata": "Backup metadata secrets",
  "certificate-expiry-check": "Scadenza certificati",
  "chaos-profile": "Profilo chaos",
  "cloudflare-access-admin": "Cloudflare Access admin",
  "cloudflare-from-zero": "Cloudflare from zero",
  "cloudflare-origin-lock-ufw": "Origin lock UFW Cloudflare",
  "compose-healthcheck-coverage": "Healthcheck Compose completi",
  "control-center-tests": "Test codice Portal",
  "dast-zap-baseline": "DAST ZAP baseline",
  "dependency-hygiene": "Igiene dipendenze",
  "deploy-vps": "Deploy VPS",
  "dr-evidence": "Evidence disaster recovery",
  "dr-readiness-check": "Readiness disaster recovery",
  "enterprise-10-check": "Enterprise 10 check",
  "enterprise-check": "Enterprise check",
  "enterprise-hardening-audit": "Audit hardening enterprise",
  "enterprise-requirements-check": "Requisiti enterprise",
  "evidence-bundle": "Bundle evidence",
  "evidence-bundle-verify": "Verifica bundle evidence",
  "external-uptime-check": "Uptime esterno",
  "failure-tests": "Failure test",
  "fault-injection-tests": "Fault injection",
  "full-restore-drill": "Restore drill completo",
  "generate-sbom": "Generazione SBOM",
  "github-actions-config": "Config GitHub Actions",
  "github-actions-run-evidence": "Evidence run GitHub Actions",
  "github-attestation-evidence": "Evidence attestazione GitHub",
  "github-branch-protection": "Branch protection GitHub",
  "github-environments": "Environment GitHub",
  "governance-check": "Governance check",
  "ha-config-check": "Configurazione alta disponibilita",
  "infra-health": "Salute infrastruttura",
  "infra-secret-manager-init": "Secret Manager init",
  "infra-secret-manager-rotate": "Secret Manager rotazione",
  "infra-secret-manager-verify": "Secret Manager verify",
  "init-local-secrets": "Inizializzazione secrets locali",
  "install-mariadb-backup-cron": "Cron backup MariaDB",
  "install-offsite-backup-cron": "Cron backup off-site",
  "install-postgres-backup-cron": "Cron backup PostgreSQL",
  "linux-portability-check": "Portabilita Linux",
  "load-benchmark": "Benchmark pubblico 50/100/500",
  "load-profile": "Profilo carico locale",
  "load-smoke": "Smoke test carico",
  "local-secret-manager": "Secret manager locale",
  "maintainability-hygiene": "Igiene manutenibilita",
  "managed-secrets-preflight": "Preflight managed secrets",
  "offsite-backup-restic": "Backup off-site Restic",
  "offsite-restore-drill-restic": "Restore off-site Restic",
  "performance-hygiene": "Igiene performance",
  "platform-admin-audit": "Audit admin piattaforma",
  "pre-go-live-evidence": "Evidence pre go-live",
  "production-go-no-go": "Production go/no-go",
  "production-preflight": "Preflight produzione",
  "production-readiness-live": "Readiness produzione live",
  "project-router-tests": "Test project-router",
  "prune-postgres-backups": "Pulizia backup PostgreSQL",
  "rate-limit-evidence": "Evidence rate limit",
  "release-artifact-gate": "Gate artefatti release",
  "release-evidence": "Evidence release",
  "repo-coverage-check": "Copertura repository",
  "restore-postgres": "Restore PostgreSQL",
  "restore-test-keycloak": "Restore test Keycloak",
  "restore-test-mariadb": "Restore test MariaDB",
  "restore-test-minio": "Restore test MinIO",
  "restore-test-postgres": "Restore test PostgreSQL",
  "restore-test-secret-manager-metadata": "Restore test metadata secrets",
  "retention-evidence": "Evidence retention log/metriche",
  "rollback-release": "Rollback release",
  "secret-manager": "Secret manager",
  "secret-rotation-evidence": "Evidence rotazione secrets",
  "secret-scan": "Secret scan",
  "security-matrix": "Matrice sicurezza",
  "security-smoke": "Security smoke",
  "sign-existing-postgres-backups": "Firma backup PostgreSQL esistenti",
  "sign-images": "Firma immagini",
  "static-security-check": "Static security check",
  "supply-chain-hygiene": "Supply chain hygiene",
  "testing-hygiene": "Igiene test",
  "validate-local-secrets": "Validazione secrets locali",
  "vps-bootstrap-ubuntu": "Bootstrap Ubuntu VPS",
  "vps-go-live": "Orchestrazione VPS go-live",
  "vps-hardening-ubuntu": "Hardening Ubuntu VPS",
  "vps-host-readiness": "Readiness host VPS",
  "vps-postdeploy": "Post-deploy VPS",
  "vps-preflight": "Preflight VPS",
  "waf-smoke": "WAF smoke",
};

const documentedStatusGoNoGoLinks = {
  "alert-evidence": "real-alert-delivery",
  "cloudflare-access-admin": "cloudflare-access-admin-verified",
  "compose-healthcheck-coverage": "healthcheck-coverage",
  "dr-evidence": "disaster-recovery-rpo-rto-offsite",
  "external-uptime-check": "external-uptime-provider",
  "full-restore-drill": "disaster-recovery-rpo-rto-offsite",
  "github-actions-run-evidence": "github-actions-run-success",
  "infra-health": "infra-health-runtime",
  "load-benchmark": "public-load-benchmark",
  "offsite-backup-restic": "disaster-recovery-rpo-rto-offsite",
  "offsite-restore-drill-restic": "disaster-recovery-rpo-rto-offsite",
  "platform-admin-audit": "platform-admin-audit-evidence",
  "pre-go-live-evidence": "pre-go-live-evidence-complete",
  "release-artifact-gate": "release-evidence-and-rollback",
  "release-evidence": "release-evidence-and-rollback",
  "retention-evidence": "retention-evidence",
  "rollback-release": "release-evidence-and-rollback",
  "secret-rotation-evidence": "secret-rotation-evidence",
  "vps-bootstrap-ubuntu": "vps-bootstrap-applied",
  "vps-hardening-ubuntu": "vps-hardening-applied",
  "vps-host-readiness": "vps-host-readiness",
};

const documentedStatusEvidenceSpecs = {
  "audit-log-evidence": { directory: "audit-logs", prefix: "audit-log-evidence-", maxAgeHours: 168, pass: "summary-failed-zero" },
  "backup-keycloak": { directory: "backups", prefix: "keycloak-backup-", maxAgeHours: 72, pass: "backup-success" },
  "backup-mariadb": { directory: "backups", prefix: "mariadb-backup-", maxAgeHours: 72, pass: "backup-success" },
  "backup-minio": { directory: "backups", prefix: "minio-backup-", maxAgeHours: 72, pass: "backup-success" },
  "backup-postgres": { directory: "backups", prefix: "postgres-backup-", maxAgeHours: 72, pass: "backup-success" },
  "backup-restore-drill": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "postgres" },
  "backup-restore-drill-keycloak": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "keycloak" },
  "backup-restore-drill-mariadb": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "mariadb" },
  "backup-restore-drill-minio": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "minio" },
  "backup-restore-drill-secret-manager-metadata": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "secret-manager-metadata" },
  "backup-secret-manager-metadata": { directory: "backups", prefix: "secret-manager-backup-", maxAgeHours: 72, pass: "backup-success" },
  "certificate-expiry-check": { directory: "local-checks", prefix: "certificate-expiry-check-", maxAgeHours: 168, pass: "local-check-passed", command: "certificate-expiry-check" },
  "chaos-profile": { directory: "chaos", prefix: "chaos-profile-", maxAgeHours: 168, pass: "status-passed" },
  "compose-healthcheck-coverage": { directory: "healthchecks", prefix: "healthcheck-coverage-", maxAgeHours: 168, pass: "healthcheck-coverage" },
  "control-center-tests": { directory: "local-checks", prefix: "control-center-tests-", maxAgeHours: 168, pass: "local-check-passed", command: "control-center-tests" },
  "dependency-hygiene": { directory: "local-checks", prefix: "dependency-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "dependency-hygiene" },
  "dr-readiness-check": { directory: "dr", prefix: "dr-evidence-", maxAgeHours: 168, pass: "status-passed-or-warning" },
  "evidence-bundle": { directory: "local-checks", prefix: "evidence-bundle-", maxAgeHours: 168, pass: "local-check-passed", command: "evidence-bundle" },
  "evidence-bundle-verify": { directory: "evidence-bundle-verify", prefix: "evidence-bundle-verify-", maxAgeHours: 168, pass: "status-passed" },
  "enterprise-check": { directory: "local-checks", prefix: "enterprise-check-", maxAgeHours: 168, pass: "local-check-passed", command: "enterprise-check" },
  "enterprise-hardening-audit": { directory: "local-checks", prefix: "enterprise-hardening-audit-", maxAgeHours: 168, pass: "local-check-passed", command: "enterprise-hardening-audit" },
  "enterprise-requirements-check": { directory: "enterprise-requirements", prefix: "enterprise-requirements-", maxAgeHours: 168, pass: "repo-report-passed" },
  "enterprise-10-check": { directory: "enterprise-requirements", prefix: "enterprise-requirements-", maxAgeHours: 168, pass: "repo-report-passed" },
  "full-restore-drill": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "status-success" },
  "failure-tests": { directory: "failure-tests", prefix: "failure-tests-", maxAgeHours: 168, pass: "failure-tests" },
  "fault-injection-tests": { directory: "fault-injection", prefix: "fault-injection-tests-", maxAgeHours: 168, pass: "status-passed" },
  "generate-sbom": { directory: "local-checks", prefix: "generate-sbom-", maxAgeHours: 168, pass: "local-check-passed", command: "generate-sbom" },
  "governance-check": { directory: "local-checks", prefix: "governance-check-", maxAgeHours: 168, pass: "local-check-passed", command: "governance-check" },
  "ha-config-check": { directory: "local-checks", prefix: "ha-config-check-", maxAgeHours: 168, pass: "local-check-passed", command: "ha-config-check" },
  "infra-health": { directory: "local-checks", prefix: "infra-health-", maxAgeHours: 24, pass: "local-check-passed", command: "infra-health" },
  "infra-secret-manager-init": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "infra-secret-manager-rotate": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "infra-secret-manager-verify": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "init-local-secrets": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "linux-portability-check": { directory: "linux-portability", prefix: "linux-portability-", maxAgeHours: 168, pass: "status-passed" },
  "load-profile": { directory: "local-checks", prefix: "load-profile-", maxAgeHours: 168, pass: "local-check-passed", command: "load-profile" },
  "load-smoke": { directory: "load", prefix: "load-smoke-", maxAgeHours: 168, pass: "status-passed" },
  "maintainability-hygiene": { directory: "local-checks", prefix: "maintainability-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "maintainability-hygiene" },
  "managed-secrets-preflight": { directory: "local-checks", prefix: "managed-secrets-preflight-", maxAgeHours: 168, pass: "local-check-passed", command: "managed-secrets-preflight" },
  "performance-hygiene": { directory: "local-checks", prefix: "performance-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "performance-hygiene" },
  "platform-admin-audit": { directory: "platform-admin-audit", prefix: "platform-admin-audit-", maxAgeHours: 168, pass: "platform-admin-audit" },
  "local-secret-manager": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "project-router-tests": { directory: "local-checks", prefix: "project-router-tests-", maxAgeHours: 168, pass: "local-check-passed", command: "project-router-tests" },
  "production-readiness-live": { directory: "production-readiness", prefix: "production-readiness-", maxAgeHours: 168, pass: "repo-report-passed" },
  "rate-limit-evidence": { directory: "rate-limits", prefix: "rate-limit-evidence-", maxAgeHours: 168, pass: "summary-failed-zero" },
  "release-artifact-gate": { directory: "local-checks", prefix: "release-artifact-gate-", maxAgeHours: 168, pass: "local-check-passed", command: "release-artifact-gate" },
  "repo-coverage-check": { directory: "repo-coverage", prefix: "repo-coverage-", maxAgeHours: 168, pass: "status-passed" },
  "retention-evidence": { directory: "retention", prefix: "retention-evidence-", maxAgeHours: 168, pass: "summary-failed-zero" },
  "prune-postgres-backups": { directory: "postgres-backup-prune", prefix: "prune-postgres-backups-", maxAgeHours: 168, pass: "postgres-backup-prune" },
  "restore-postgres": { directory: "postgres-restore", prefix: "restore-postgres-", maxAgeHours: 168, pass: "status-passed" },
  "restore-test-keycloak": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "keycloak" },
  "restore-test-mariadb": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "mariadb" },
  "restore-test-minio": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "minio" },
  "restore-test-postgres": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "postgres" },
  "restore-test-secret-manager-metadata": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "full-restore-step", step: "secret-manager-metadata" },
  "rollback-release": { directory: "rollback", prefix: "rollback-plan-", maxAgeHours: 168, pass: "rollback-plan" },
  "secret-rotation-evidence": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "secret-manager": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "secret-scan": { directory: "local-checks", prefix: "secret-scan-", maxAgeHours: 168, pass: "local-check-passed", command: "secret-scan" },
  "security-matrix": { directory: "local-checks", prefix: "security-matrix-", maxAgeHours: 168, pass: "local-check-passed", command: "security-matrix" },
  "security-smoke": { directory: "local-checks", prefix: "security-smoke-", maxAgeHours: 168, pass: "local-check-passed", command: "security-smoke" },
  "static-security-check": { directory: "local-checks", prefix: "static-security-check-", maxAgeHours: 168, pass: "local-check-passed", command: "static-security-check" },
  "supply-chain-hygiene": { directory: "local-checks", prefix: "supply-chain-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "supply-chain-hygiene" },
  "testing-hygiene": { directory: "local-checks", prefix: "testing-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "testing-hygiene" },
  "validate-local-secrets": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "sign-existing-postgres-backups": { directory: "postgres-backup-signatures", prefix: "postgres-backup-signatures-", maxAgeHours: 168, pass: "postgres-backup-signatures" },
  "vps-go-live": { directory: "vps-go-live", prefix: "vps-go-live-", maxAgeHours: 168, pass: "vps-go-live-live" },
  "vps-postdeploy": { directory: "local-checks", prefix: "vps-postdeploy-", maxAgeHours: 168, pass: "local-check-passed", command: "vps-postdeploy" },
  "vps-preflight": { directory: "local-checks", prefix: "vps-preflight-", maxAgeHours: 168, pass: "local-check-passed", command: "vps-preflight" },
  "waf-smoke": { directory: "local-checks", prefix: "waf-smoke-", maxAgeHours: 168, pass: "local-check-passed", command: "waf-smoke" },
};

const documentedStatusGroups = [
  {
    category: "local-policy",
    source: "Documentazione infra-ops",
    status: "plan-only",
    required: false,
    detail: "Test documentato e sicuro da pianificare: non viene eseguito automaticamente dal Portal.",
    nextAction: "Eseguilo dal server Ubuntu quando vuoi aggiornare l'evidence; poi rilancia go/no-go se e' un requisito.",
    commands: [
      "audit-log-evidence",
      "certificate-expiry-check",
      "compose-healthcheck-coverage",
      "control-center-tests",
      "dependency-hygiene",
      "dr-readiness-check",
      "enterprise-check",
      "enterprise-hardening-audit",
      "enterprise-requirements-check",
      "enterprise-10-check",
      "generate-sbom",
      "governance-check",
      "ha-config-check",
      "infra-health",
      "linux-portability-check",
      "maintainability-hygiene",
      "managed-secrets-preflight",
      "performance-hygiene",
      "platform-admin-audit",
      "project-router-tests",
      "rate-limit-evidence",
      "repo-coverage-check",
      "retention-evidence",
      "secret-scan",
      "security-matrix",
      "security-smoke",
      "static-security-check",
      "supply-chain-hygiene",
      "testing-hygiene",
      "waf-smoke",
    ],
  },
  {
    category: "secret-protected",
    source: "Checklist secrets",
    status: "pending-live-proof",
    required: true,
    detail: "Test locale protetto: puo' leggere, generare, validare o ruotare materiale sensibile. Non viene eseguito automaticamente dal Portal.",
    nextAction: "Eseguilo solo con autorizzazione esplicita sui secrets e senza stampare valori; poi archivia il report non-secret.",
    commands: [
      "infra-secret-manager-init",
      "infra-secret-manager-verify",
      "infra-secret-manager-rotate",
      "init-local-secrets",
      "local-secret-manager",
      "secret-manager",
      "validate-local-secrets",
    ],
  },
  {
    category: "runtime-evidence",
    source: "Documentazione runtime",
    status: "pending-live-proof",
    required: true,
    detail: "Serve una prova eseguita sul runtime Ubuntu/VPS corretto, non solo la presenza del comando nel repository.",
    nextAction: "Esegui il comando nella finestra operativa corretta, conserva il report e rilancia production-go-no-go.",
    commands: [
      "alert-evidence",
      "backup-keycloak",
      "backup-mariadb",
      "backup-minio",
      "backup-postgres",
      "backup-secret-manager-metadata",
      "dr-evidence",
      "evidence-bundle",
      "evidence-bundle-verify",
      "load-benchmark",
      "load-profile",
      "load-smoke",
      "pre-go-live-evidence",
      "production-go-no-go",
      "production-preflight",
      "production-readiness-live",
      "release-artifact-gate",
      "release-evidence",
      "secret-rotation-evidence",
      "vps-bootstrap-ubuntu",
      "vps-hardening-ubuntu",
      "vps-host-readiness",
      "vps-postdeploy",
      "vps-preflight",
    ],
  },
  {
    category: "protected-runtime",
    source: "Checklist operativa",
    status: "pending-live-proof",
    required: true,
    detail: "Test documentato ma protetto: puo' fermare servizi, usare backup o validare rollback. Non parte dal bottone Stato.",
    nextAction: "Eseguilo solo con backup, finestra di manutenzione e conferma operativa; archivia il report fuori Git.",
    commands: [
      "backup-restore-drill",
      "backup-restore-drill-keycloak",
      "backup-restore-drill-mariadb",
      "backup-restore-drill-minio",
      "backup-restore-drill-secret-manager-metadata",
      "chaos-profile",
      "deploy-vps",
      "failure-tests",
      "fault-injection-tests",
      "full-restore-drill",
      "prune-postgres-backups",
      "restore-postgres",
      "restore-test-keycloak",
      "restore-test-mariadb",
      "restore-test-minio",
      "restore-test-postgres",
      "restore-test-secret-manager-metadata",
      "rollback-release",
      "sign-existing-postgres-backups",
      "vps-go-live",
    ],
  },
  {
    category: "provider",
    source: "Provider esterno",
    status: "pending-provider",
    required: true,
    detail: "Richiede dominio, Cloudflare, GitHub, registry o monitor esterni configurati e verificati davvero.",
    nextAction: "Completa il provider live, esegui la verifica remota indicata e conserva il report non-secret.",
    commands: [
      "cloudflare-access-admin",
      "cloudflare-from-zero",
      "cloudflare-origin-lock-ufw",
      "dast-zap-baseline",
      "external-uptime-check",
      "github-actions-config",
      "github-actions-run-evidence",
      "github-attestation-evidence",
      "github-branch-protection",
      "github-environments",
      "install-mariadb-backup-cron",
      "install-offsite-backup-cron",
      "install-postgres-backup-cron",
      "offsite-backup-restic",
      "offsite-restore-drill-restic",
      "sign-images",
    ],
  },
];

function documentedStatusChecks(context) {
  const checks = [];
  const seen = new Set();
  const push = (check) => {
    const id = sanitizeIdentifier(check.id || "");
    if (!id || seen.has(id)) return;
    seen.add(id);
    checks.push(statusRunCheck({ ...check, id }));
  };

  for (const group of documentedStatusGroups) {
    for (const command of group.commands) {
      push(resolveDocumentedStatusCheck({
        id: command,
        title: documentedStatusTitles[command] || humanName(command),
        category: group.category,
        source: group.source,
        status: group.status,
        detail: group.detail,
        nextAction: group.nextAction,
        required: group.required,
        command,
      }, context));
    }
  }

  for (const check of documentedManifestStatusChecks(context, "enterprise", context.readiness?.manifests?.enterprise)) push(check);
  for (const check of documentedManifestStatusChecks(context, "production-readiness", context.readiness?.manifests?.productionReadiness)) push(check);

  return checks;
}

function resolveDocumentedStatusCheck(base, context) {
  const evidence = readDocumentedStatusEvidence(base.command);
  if (evidence) {
    return {
      ...base,
      source: `${base.source} / report`,
      status: evidence.status,
      detail: evidence.detail,
      nextAction: evidence.status === "passed"
        ? "Report reale valido: mantienilo aggiornato dopo modifiche infrastrutturali."
        : evidence.nextAction,
      required: base.required,
    };
  }

  const goNoGoName = documentedStatusGoNoGoLinks[base.command] || base.command;
  const goNoGoCheck = (context.goNoGo?.checks || []).find((check) => check.name === goNoGoName);
  if (goNoGoCheck) {
    const displayCheck = goNoGoDisplayCheck(goNoGoCheck, base.category);
    const passed = displayCheck.status === "passed";
    return {
      ...base,
      source: `${base.source} / go-no-go`,
      status: displayCheck.status,
      detail: passed
        ? (displayCheck.detail || `Evidence valida nel report go/no-go per ${goNoGoName}.`)
        : simpleBlockerReason(displayCheck),
      nextAction: passed ? "Mantieni il report aggiornato dopo ogni modifica." : simpleBlockerAction(displayCheck),
      required: displayCheck.required,
    };
  }

  if (base.command === "production-go-no-go") {
    const report = context.goNoGo || {};
    const passed = report.status === "go";
    const hasReport = Boolean(report.reportPath);
    return {
      ...base,
      status: passed ? "passed" : hasReport ? "no-go" : "pending-live-proof",
      detail: report.reportPath
        ? `Ultimo report ${report.status || "unknown"}: ${report.reportPath}.`
        : "Manca il report production-go-no-go.",
      nextAction: passed ? "Conserva il report come evidence di release." : "Esegui production-go-no-go sul server e chiudi i blocchi richiesti.",
      required: true,
    };
  }

  const readinessMatch = findReadinessRequirementForCommand(context, base.command);
  if (readinessMatch) {
    const requirementAction = documentedReadinessAction(readinessMatch.requirement);
    const rawStatus = readinessMatch.requirement.status || base.status;
    const status = classifiedEvidenceStatus(rawStatus, [
      base.command,
      base.source,
      readinessMatch.manifestTitle,
      readinessMatch.requirement.title,
      readinessMatch.requirement.liveProofStatus,
      ...(readinessMatch.requirement.liveProofChecks || []),
      requirementAction,
    ].join(" "), base.category);
    return {
      ...base,
      source: `${base.source} / ${readinessMatch.manifestTitle}`,
      status,
      detail: `Checklist: ${readinessMatch.requirement.title}. Stato repo: ${readinessMatch.requirement.sourceState}; evidence: ${readinessMatch.requirement.evidenceCount}.`,
      nextAction: requirementAction || base.nextAction,
      required: readinessMatch.requirement.liveProofRequired || base.required,
    };
  }

  return {
    ...base,
    status: classifiedEvidenceStatus(base.status, [
      base.command,
      base.source,
      base.detail,
      base.nextAction,
    ].join(" "), base.category),
  };
}

function readDocumentedStatusEvidence(command) {
  const spec = documentedStatusEvidenceSpecs[command];
  if (!spec) return null;
  const report = latestDocumentedReport(spec.directory, spec.prefix);
  if (!report) return null;
  const age = reportAgeDetail(report.payload, spec.maxAgeHours);
  const passed = age.fresh && documentedEvidencePassed(report.payload, spec);
  const failed = !passed && documentedEvidenceExplicitlyFailed(report.payload, spec);
  return {
    status: passed ? "passed" : failed ? "failed" : "pending-live-proof",
    detail: passed
      ? `Report reale valido: ${report.reportPath}; ${age.detail}.`
      : failed
        ? `Report presente ma non superato: ${report.reportPath}; status=${report.payload?.status || "unknown"}.`
        : `Report presente ma non fresco: ${report.reportPath}; ${age.detail}.`,
    nextAction: failed
      ? "Correggi il controllo fallito e rigenera il report senza forzare falsi positivi."
      : `Rilancia il comando per generare evidence fresca entro ${spec.maxAgeHours}h.`,
    reportPath: report.reportPath,
  };
}

function documentedEvidenceExplicitlyFailed(payload, spec) {
  const status = String(payload?.status || "").toLowerCase();
  if (["failed", "failure", "error"].includes(status)) return true;
  if (["planned", "plan", "dry-run", "skipped", "pending"].includes(status)) return false;
  if (["passed", "success", "go"].includes(status)) return !documentedEvidencePassed(payload, spec);
  return false;
}

function latestDocumentedReport(directoryName, prefix) {
  const root = path.resolve(docsRoot);
  const directory = path.resolve(root, "reports", path.basename(directoryName));
  if (!directory.startsWith(`${root}${path.sep}`) || !existsSync(directory)) return null;
  try {
    const cleanPrefix = String(prefix || "").replace(/[^a-z0-9-]/gi, "");
    const fileName = readdirSync(directory)
      .filter((name) => name.startsWith(cleanPrefix) && name.endsWith(".json"))
      .sort()
      .at(-1);
    if (!fileName) return null;
    const target = path.resolve(directory, fileName);
    if (!target.startsWith(`${directory}${path.sep}`)) return null;
    const payload = JSON.parse(readFileSync(target, "utf8"));
    return {
      payload: payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {},
      reportPath: `reports/${path.basename(directoryName)}/${fileName}`,
    };
  } catch {
    return null;
  }
}

function documentedEvidencePassed(payload, spec) {
  const status = String(payload?.status || "").toLowerCase();
  switch (spec.pass) {
    case "backup-success":
      return status === "success" && Boolean(payload.artifactSha256 || payload.artifactPath);
    case "healthcheck-coverage":
      return status === "passed" && Number(payload.summary?.missingHealthchecks || 0) === 0;
    case "full-restore-step":
      return status === "success"
        && Array.isArray(payload.steps)
        && payload.steps.some((step) => step?.name === spec.step && step.status === "success");
    case "failure-tests":
      return status === "passed"
        && Array.isArray(payload.targets)
        && payload.targets.length > 0
        && payload.targets.every((target) => target?.detected === true && target?.recovered === true);
    case "local-check-passed":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && (!spec.command || payload.command === spec.command);
    case "platform-admin-audit":
      return status === "passed"
        && payload.mode === "runtime"
        && payload.scope === "platform-infrastructure"
        && Number(payload.summary?.failedChecks || 0) === 0
        && Number(payload.summary?.sensitiveKeyFindings || 0) === 0;
    case "repo-report-passed":
      return status === "passed" && String(payload.repoStatus || "passed") === "passed" && Number(payload.failedCount || 0) === 0;
    case "secret-rotation":
      return status === "passed"
        && payload.mode === "evidence"
        && String(payload.verify?.status || "") === "passed"
        && Number(payload.summary?.failedSecrets || 0) === 0
        && Number(payload.summary?.expiredSecrets || 0) === 0
        && Number(payload.summary?.missingMaterializedFiles || 0) === 0;
    case "postgres-backup-prune":
      return status === "passed"
        && ["apply", "dry-run"].includes(String(payload.mode || ""))
        && Number(payload.summary?.regular?.total || 0) >= Number(payload.summary?.regular?.kept || 0)
        && Number(payload.summary?.drills?.total || 0) >= Number(payload.summary?.drills?.kept || 0);
    case "postgres-backup-signatures":
      return status === "passed"
        && Number(payload.summary?.total || 0) > 0
        && Number(payload.summary?.signed || 0) + Number(payload.summary?.verified || 0) >= Number(payload.summary?.total || 0);
    case "rollback-plan":
      return ["passed", ""].includes(status)
        && ["dry-run", "apply"].includes(String(payload.mode || ""))
        && payload.composeValidation?.status === "passed";
    case "status-passed":
      return status === "passed";
    case "status-passed-or-warning":
      return ["passed", "warning"].includes(status);
    case "status-success":
      return status === "success";
    case "summary-failed-zero":
      return status === "passed" && Number(payload.summary?.failed || payload.summary?.failedChecks || 0) === 0;
    case "vps-go-live-live":
      return status === "passed" && payload.mode === "live";
    default:
      return false;
  }
}

function reportAgeDetail(payload, maxAgeHours) {
  const generatedAt = payload?.generatedAt || payload?.finishedAt || payload?.startedAt || "";
  const generatedMs = Date.parse(generatedAt);
  if (!Number.isFinite(generatedMs)) {
    return { fresh: false, detail: "timestamp report mancante o non valido" };
  }
  const ageHours = Math.max(0, (Date.now() - generatedMs) / 36e5);
  return {
    fresh: ageHours <= Number(maxAgeHours || 24),
    detail: `eta' ${ageHours.toFixed(1)}h, massimo ${Number(maxAgeHours || 24)}h`,
  };
}

function documentedManifestStatusChecks(context, prefix, manifest) {
  if (!manifest?.requirements?.length) return [];
  return manifest.requirements.map((requirement) => {
    const linkedGoNoGo = (requirement.liveProofChecks || [])
      .map((name) => (context.goNoGo?.checks || []).find((check) => check.name === name))
      .find(Boolean);
    const displayGoNoGo = linkedGoNoGo ? goNoGoDisplayCheck(linkedGoNoGo, prefix) : null;
    const rawStatus = displayGoNoGo?.status || requirement.status;
    const requirementAction = documentedReadinessAction(requirement);
    const status = classifiedEvidenceStatus(rawStatus, [
      prefix,
      manifest.title || "Governance",
      requirement.id,
      requirement.title,
      requirement.liveProofStatus,
      ...(requirement.liveProofChecks || []),
      displayGoNoGo?.detail || "",
      displayGoNoGo ? simpleBlockerReason(displayGoNoGo) : "",
      displayGoNoGo ? simpleBlockerAction(displayGoNoGo) : "",
      requirementAction,
    ].join(" "), prefix);
    const passed = status === "passed";
    return {
      id: `${prefix}-${requirement.id}`,
      title: requirement.title,
      category: prefix,
      source: manifest.title || "Governance",
      status,
      detail: displayGoNoGo
        ? (passed ? (displayGoNoGo.detail || "Requirement coperto dal report go/no-go.") : simpleBlockerReason(displayGoNoGo))
        : `Manifest governance: ${requirement.sourceState}; evidence repo: ${requirement.evidenceCount}; live proof: ${requirement.liveProofStatus}.`,
      nextAction: displayGoNoGo
        ? (passed ? "Mantieni il report aggiornato dopo ogni modifica." : simpleBlockerAction(displayGoNoGo))
        : requirementAction,
      required: requirement.liveProofRequired !== false,
    };
  });
}

function documentedReadinessAction(requirement) {
  if (!requirement) return "";
  const checks = Array.isArray(requirement.liveProofChecks) && requirement.liveProofChecks.length
    ? ` Gate collegati: ${requirement.liveProofChecks.join(", ")}.`
    : "";
  if (requirement.liveProofRequired) {
    return `Completa la prova live o provider per "${requirement.title}" e archivia il report non-secret.${checks}`;
  }
  return `Esegui la verifica documentata per "${requirement.title}" e conserva l'evidence aggiornata.${checks}`;
}

function findReadinessRequirementForCommand(context, command) {
  const manifests = [
    context.readiness?.manifests?.productionReadiness,
    context.readiness?.manifests?.enterprise,
  ].filter(Boolean);
  for (const manifest of manifests) {
    const requirement = (manifest.requirements || []).find((item) => (
      (item.evidenceRefs || []).some((ref) => ref.name === command || ref.path === `scripts/${command}.sh`)
    ));
    if (requirement) return { manifestTitle: manifest.title || manifest.id || "Governance", requirement };
  }
  return null;
}

function readLatestProductionReadinessReport() {
  return readLatestLiveProofReport("production-readiness", "production-readiness-", "production-readiness-live", "Production Readiness Live Proof");
}

function readLatestEnterpriseRequirementsReport() {
  return readLatestLiveProofReport("enterprise-requirements", "enterprise-requirements-", "enterprise-requirements-live", "Enterprise Requirements Live Proof");
}

function readLatestGoNoGoReport() {
  const root = path.resolve(docsRoot);
  const dir = path.resolve(root, "reports", "go-no-go");
  const fallback = {
    status: "unknown",
    generatedAt: "",
    reportPath: "",
    summary: { total: 1, required: 1, passed: 0, failed: 0, pendingLiveProof: 1, pendingProvider: 0, blockingRequired: 1, failedRequired: 0, pendingRequired: 1 },
    blockers: [{
      name: "production-go-no-go-report",
      required: true,
      status: "pending-live-proof",
      blocker: "No production go/no-go report was found.",
      detail: "Run sh ./scripts/production-go-no-go.sh before evaluating go-live.",
      reportPath: "",
      generatedAt: "",
    }],
    checks: [],
  };
  if (!dir.startsWith(`${root}${path.sep}`) || !existsSync(dir)) return fallback;
  try {
    const fileName = readdirSync(dir)
      .filter((name) => /^production-go-no-go-\d+\.json$/.test(name))
      .sort()
      .at(-1);
    if (!fileName) return fallback;
    const parsed = JSON.parse(readFileSync(path.join(dir, fileName), "utf8"));
    const checks = Array.isArray(parsed.checks) ? parsed.checks.map(goNoGoCheckRecord).filter(Boolean) : [];
    return sanitizeEvent({
      status: sanitizeIdentifier(parsed.status || "unknown") || "unknown",
      generatedAt: sanitizeMessage(parsed.generatedAt || ""),
      reportPath: `reports/go-no-go/${fileName}`,
      markdownPath: `reports/go-no-go/${fileName.replace(/\.json$/, ".md")}`,
      summary: {
        total: Number(parsed.summary?.total || checks.length || 0),
        required: Number(parsed.summary?.required || checks.filter((check) => check.required).length || 0),
        passed: Number(parsed.summary?.passed || checks.filter((check) => check.status === "passed").length || 0),
        failed: Number(parsed.summary?.failed || checks.filter((check) => check.status === "failed").length || 0),
        pendingLiveProof: Number(parsed.summary?.pendingLiveProof || checks.filter((check) => check.status === "pending-live-proof").length || 0),
        pendingProvider: Number(parsed.summary?.pendingProvider || checks.filter((check) => check.status === "pending-provider").length || 0),
        blockingRequired: Number(parsed.summary?.blockingRequired || checks.filter((check) => check.required && check.status !== "passed").length || 0),
        failedRequired: Number(parsed.summary?.failedRequired || 0),
        pendingRequired: Number(parsed.summary?.pendingRequired || 0),
      },
      blockers: checks.filter((check) => check.required && check.status !== "passed"),
      checks,
    });
  } catch {
    return fallback;
  }
}

function goNoGoCheckRecord(check) {
  if (!check || typeof check !== "object") return null;
  return {
    name: sanitizeIdentifier(check.name || "unknown") || "unknown",
    required: check.required !== false,
    status: sanitizeIdentifier(check.status || "unknown") || "unknown",
    blocker: sanitizeOptionalRef(check.blocker || ""),
    detail: sanitizeMessage(check.detail || ""),
    reportPath: check.reportPath ? readinessReportRef(check.reportPath) : "",
    generatedAt: sanitizeMessage(check.generatedAt || ""),
  };
}

function readLatestLiveProofReport(reportDirectory, reportPrefix, reportId, reportTitle) {
  const root = path.resolve(docsRoot);
  const cleanDirectory = path.basename(reportDirectory);
  const cleanPrefix = String(reportPrefix || "").replace(/[^a-z0-9-]/gi, "");
  const dir = path.resolve(root, "reports", cleanDirectory);
  if (!(dir === root || dir.startsWith(`${root}${path.sep}`)) || !existsSync(dir)) return null;
  try {
    const pattern = new RegExp(`^${cleanPrefix}\\d+\\.json$`);
    const files = readdirSync(dir)
      .filter((name) => pattern.test(name))
      .sort();
    const fileName = files[files.length - 1];
    if (!fileName) return null;
    const target = path.resolve(dir, fileName);
    if (!(target === dir || target.startsWith(`${dir}${path.sep}`))) return null;
    const parsed = JSON.parse(readFileSync(target, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return readinessLiveReportRecord(parsed, cleanDirectory, fileName, reportId, reportTitle);
  } catch {
    return null;
  }
}

function readinessLiveReportRecord(report, reportDirectory, fileName, reportId, reportTitle) {
  const requirements = (Array.isArray(report.requirements) ? report.requirements : [])
    .map(readinessLiveRequirementRecord)
    .filter(Boolean);
  return {
    id: sanitizeIdentifier(reportId || "live-proof-report"),
    title: sanitizeMessage(reportTitle || "Live Proof Report"),
    status: sanitizeIdentifier(report.status || "unknown"),
    repoStatus: sanitizeIdentifier(report.repoStatus || "unknown"),
    liveProofStatus: sanitizeIdentifier(report.liveProofStatus || "unknown"),
    generatedAt: sanitizeMessage(report.generatedAt || ""),
    reportPath: `reports/${path.basename(reportDirectory)}/${path.basename(fileName)}`,
    markdownPath: `reports/${path.basename(reportDirectory)}/${path.basename(fileName).replace(/\.json$/, ".md")}`,
    passedCount: Number(report.passedCount || 0),
    failedCount: Number(report.failedCount || 0),
    requirements,
  };
}

function readinessLiveRequirementRecord(row) {
  if (!row || typeof row !== "object") return null;
  const id = sanitizeIdentifier(row.id || "unknown");
  if (!id) return null;
  const evidence = row.liveProofEvidence && typeof row.liveProofEvidence === "object" ? row.liveProofEvidence : {};
  return {
    id,
    status: sanitizeIdentifier(row.status || "unknown"),
    repoEvidenceStatus: sanitizeIdentifier(row.repoEvidenceStatus || "unknown"),
    liveProofStatus: sanitizeIdentifier(row.liveProofStatus || "unknown"),
    detail: sanitizeMessage(evidence.detail || ""),
    reportPath: evidence.reportPath ? readinessReportRef(evidence.reportPath) : "",
    checks: Array.isArray(evidence.checks) ? evidence.checks.map((check) => ({
      name: sanitizeIdentifier(check?.name || "unknown"),
      status: sanitizeIdentifier(check?.status || "unknown"),
      reportPath: check?.reportPath ? readinessReportRef(check.reportPath) : "",
    })) : [],
  };
}

function readinessReportRef(reportPath) {
  const value = String(reportPath || "");
  if (value.startsWith("/infra/")) return sanitizeRef(value.slice("/infra/".length));
  const root = path.resolve(docsRoot);
  const resolved = path.resolve(value);
  if (resolved.startsWith(`${root}${path.sep}`)) return sanitizeRef(path.relative(root, resolved));
  return sanitizeRef(value);
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

function manifestReadiness(id, title, manifest, liveProofReport = null) {
  const liveProofById = new Map((liveProofReport?.requirements || []).map((row) => [row.id, row]));
  const requirements = Array.isArray(manifest.requirements)
    ? manifest.requirements.map((requirement) => manifestRequirementRecord(requirement, liveProofById.get(sanitizeIdentifier(requirement.id || "unknown"))))
    : [];
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
    liveProofReport: liveProofReport ? {
      status: liveProofReport.status,
      liveProofStatus: liveProofReport.liveProofStatus,
      generatedAt: liveProofReport.generatedAt,
      reportPath: liveProofReport.reportPath,
      passedCount: liveProofReport.passedCount,
      failedCount: liveProofReport.failedCount,
    } : null,
    states,
    summary,
    requirements,
  };
}

function manifestRequirementRecord(requirement, liveProofRow = null) {
  const sourceState = sanitizeIdentifier(requirement.state || "unknown") || "unknown";
  const liveProofRequired = Boolean(requirement.liveProof);
  const evidence = Array.isArray(requirement.evidence) ? requirement.evidence : [];
  const liveProofStatus = sanitizeIdentifier(liveProofRow?.liveProofStatus || "");
  let status = manifestRequirementStatus(sourceState, liveProofRequired);
  let repoEvidenceStatus = status === "needs-work" ? "incomplete" : "tracked";
  let nextAction = liveProofRequired ? sanitizeMessage(requirement.liveProof || "Archive production live proof.") : "Keep repository evidence current.";
  if (liveProofRequired && liveProofRow) {
    repoEvidenceStatus = liveProofRow.repoEvidenceStatus || repoEvidenceStatus;
    if (liveProofStatus === "passed") {
      status = "passed";
      nextAction = liveProofRow.detail ? `Live proof passed: ${liveProofRow.detail}` : "Live proof passed by production readiness evidence.";
    } else if (liveProofStatus === "failed") {
      status = "pending-live-proof";
      nextAction = liveProofRow.detail || nextAction;
    }
  }
  return {
    id: sanitizeIdentifier(requirement.id || "unknown"),
    title: sanitizeMessage(requirement.title || "Untitled requirement"),
    status,
    sourceState,
    repoEvidenceStatus,
    liveProofRequired,
    liveProofStatus: liveProofStatus || (liveProofRequired ? "pending-external-evidence" : "not-required"),
    liveProofReportPath: liveProofRow?.reportPath || "",
    liveProofChecks: Array.isArray(requirement.liveProofChecks) ? requirement.liveProofChecks.map((item) => sanitizeIdentifier(item)).filter(Boolean) : [],
    evidenceCount: evidence.length,
    evidenceRefs: evidence.map((item) => ({
      type: sanitizeIdentifier(item.type || "unknown"),
      path: item.path ? sanitizeRef(item.path) : "",
      name: item.name ? sanitizeRef(item.name) : "",
    })),
    nextAction: sanitizeMessage(nextAction),
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
  const projects = [];
  const seen = new Set();
  const seenRealPaths = new Set();
  const rootRealPath = existsSync(projectsRoot) ? safeRealpath(projectsRoot) : "";
  if (discoverHostedProjects && existsSync(projectsRoot)) {
    for (const entry of readdirSync(projectsRoot, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.name === "." || entry.name === "..") continue;
      const directorySlug = slugify(entry.name);
      if (!directorySlug || seen.has(directorySlug) || ["public", "node-modules", "vendor"].includes(directorySlug)) continue;
      const projectPath = path.join(projectsRoot, entry.name);
      if (!safeIsDirectory(projectPath)) continue;
      const realProjectPath = safeRealpath(projectPath);
      if (rootRealPath && !(realProjectPath === rootRealPath || realProjectPath.startsWith(`${rootRealPath}${path.sep}`))) continue;
      if (seenRealPaths.has(realProjectPath)) continue;
      const manifest = readProjectManifest(projectPath);
      const isPhp = isPhpProject(projectPath);
      const isNode = existsSync(path.join(projectPath, "package.json"));
      const isStatic = isStaticProject(projectPath);
      if (!isPhp && !isNode && !isStatic) continue;
      const manifestProjects = manifestProjectEntries(manifest);
      const projectEntries = manifestProjects.length ? manifestProjects : [{}];
      const baseAlias = projectEntries.length === 1 ? directorySlug : "";
      for (const manifestProject of projectEntries) {
        const slug = slugify(manifestProject?.slug || directorySlug);
        if (!slug || seen.has(slug) || ["public", "node-modules", "vendor"].includes(slug)) continue;
        const metadata = state.projects?.[slug] || state.projects?.[directorySlug] || {};
        if (metadata.deletedAt) continue;
        const manifestRuntime = normalizeProjectRuntime(manifestProject?.type || manifest.type || "");
        const runtime = manifestRuntime || (isPhp ? "php" : isNode ? "node" : "static");
        const type = projectRuntimeLabel(runtime);
        const explicitHost = normalizeHost(typeof manifestProject?.host === "string" ? manifestProject.host : "");
        const host = explicitHost || (runtime === "node" && nodeHosts.has(slug) ? nodeHosts.get(slug) : `${slug}${hostSuffix}`);
        const archived = Boolean(metadata.archivedAt);
        const enabled = metadata.enabled !== false && !archived;
        const aliases = projectAliases(slug, directorySlug, manifestProject, baseAlias);
        projects.push({
          id: slug,
          slug,
          aliases,
          name: metadata.displayName || manifestProject?.name || humanName(slug),
          type,
          runtime,
          description: sanitizeOptionalDescription(metadata.description || manifestProject?.summary || manifestProject?.description || ""),
          host,
          href: `https://${host}/`,
          enabled,
          status: archived ? "archived" : enabled ? "active" : "disabled",
          archivedAt: metadata.archivedAt || null,
          updatedAt: metadata.updatedAt || null,
          source: "project-discovery",
          filesystemExists: true,
          filesAvailable: true,
          relativePath: relativeProjectPathFromRealpath(realProjectPath, rootRealPath) || entry.name,
          filesystemTouched: false,
          databaseTouched: false,
          summary: archived ? "Archived in local Control Center state" : metadata.description || manifestProject?.summary || (runtime === "php" ? "Apache/PHP local host" : runtime === "static" ? "Static site" : "Node routed service"),
        });
        seen.add(slug);
        for (const alias of aliases) seen.add(alias);
      }
      seenRealPaths.add(realProjectPath);
    }
  }
  for (const [key, metadata] of Object.entries(state.projects || {})) {
    const slug = slugify(key);
    if (!slug || seen.has(slug) || metadata?.deletedAt || metadata?.declaredProject !== true) continue;
    const runtime = ["node", "php", "static"].includes(metadata.runtime) ? metadata.runtime : "node";
    const type = projectRuntimeLabel(runtime);
    const archived = Boolean(metadata.archivedAt);
    const enabled = metadata.enabled === true && !archived;
    const host = normalizeHost(metadata.host || `${slug}${hostSuffix}`);
    projects.push({
      id: slug,
      slug,
      name: metadata.displayName || humanName(slug),
      type,
      runtime,
      description: sanitizeOptionalDescription(metadata.description || ""),
      host,
      href: `https://${host}/`,
      enabled,
      status: archived ? "archived" : enabled ? "active" : "declared",
      archivedAt: metadata.archivedAt || null,
      updatedAt: metadata.updatedAt || metadata.createdAt || null,
      source: "control-center-state",
      filesystemExists: false,
      filesAvailable: false,
      relativePath: "",
      filesystemTouched: false,
      databaseTouched: false,
      summary: archived ? "Archived in local Control Center state" : metadata.description || "Declared in Control Center state; add source files or link applications before enabling routing.",
    });
    seen.add(slug);
  }
  projects.sort((a, b) => {
    const typeOrder = { php: 0, node: 1, static: 2 };
    return ((typeOrder[a.runtime] ?? 9) - (typeOrder[b.runtime] ?? 9)) || a.name.localeCompare(b.name);
  });
  return projects;
}

function readProjectManifest(projectPath) {
  const target = path.join(projectPath, ".platform", "project.json");
  if (!existsSync(target)) return {};
  try {
    const stat = statSync(target);
    if (!stat.isFile() || stat.size > 200000) return {};
    const parsed = JSON.parse(readFileSync(target, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function manifestProjectEntries(manifest) {
  const projects = Array.isArray(manifest.projects) ? manifest.projects : [];
  return projects.filter((item) => item && typeof item === "object" && !Array.isArray(item) && (item.slug || item.name || item.type));
}

function normalizeProjectRuntime(value) {
  const next = String(value || "").toLowerCase().trim();
  if (next === "php" || next === "node" || next === "static") return next;
  return "";
}

function projectAliases(slug, directorySlug, manifestProject, baseAlias = directorySlug) {
  const aliases = [
    baseAlias,
    ...(Array.isArray(manifestProject?.aliases) ? manifestProject.aliases : []),
  ].map((item) => slugify(item)).filter((item) => item && item !== slug);
  return [...new Set(aliases)].slice(0, 20);
}

function relativeProjectPathFromRealpath(realProjectPath, rootRealPath) {
  if (!rootRealPath || !(realProjectPath === rootRealPath || realProjectPath.startsWith(`${rootRealPath}${path.sep}`))) return "";
  return path.relative(rootRealPath, realProjectPath).replaceAll(path.sep, "/");
}

function discoverProjectDatabaseHints(projects) {
  const hints = {};
  for (const project of projects) {
    const names = readProjectDatabaseHints(project);
    if (names.length) hints[project.slug] = names;
  }
  return hints;
}

function readProjectDatabaseHints(project) {
  if (!project.filesAvailable || !project.relativePath) return [];
  const candidateFiles = [
    ".env",
    ".env.local",
    ".env.production",
    "private/.env",
    "config/config.php",
    "config/database.php",
    "config/database.json",
    ".platform/project.json",
  ];
  const names = new Set();
  let root = "";
  try {
    root = resolveProjectRoot(project);
  } catch {
    return [];
  }
  for (const relative of candidateFiles) {
    const target = path.resolve(root, relative);
    if (!(target === root || target.startsWith(`${root}${path.sep}`)) || !existsSync(target)) continue;
    try {
      const stat = statSync(target);
      if (!stat.isFile() || stat.size > 200000) continue;
      for (const name of extractDatabaseNames(readFileSync(target, "utf8"))) names.add(name);
    } catch {
      // Ignore unreadable optional app config files.
    }
  }
  return [...names].sort();
}

function extractDatabaseNames(text) {
  const names = new Set();
  const patterns = [
    /(?:^|\n)\s*(?:export\s+)?(?:DB_NAME|DB_DATABASE|DATABASE_NAME|MYSQL_DATABASE|MARIADB_DATABASE|POSTGRES_DB)\s*=\s*["']?([A-Za-z][A-Za-z0-9_]{0,62})/gi,
    /["'](?:db|database|mysql|mariadb|postgres)["']\s*=>[\s\S]{0,400}?["']name["']\s*=>\s*["']([A-Za-z][A-Za-z0-9_]{0,62})["']/gi,
    /"database"\s*:\s*"([A-Za-z][A-Za-z0-9_]{0,62})"/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      try {
        names.add(validateDatabaseName(match[1]));
      } catch {
        // Ignore non-database values.
      }
    }
  }
  return [...names];
}

function readProjectFiles(id, requestedPath, context) {
  const project = findById(context.projects, id, "Project");
  if (!project.filesAvailable || !project.relativePath) {
    return sanitizeEvent({
      projectId: project.slug,
      available: false,
      path: "",
      parentPath: "",
      entries: [],
      message: "Project source files are not mounted.",
    });
  }
  const projectRoot = resolveProjectRoot(project);
  const relativePath = safeRelativeProjectPath(requestedPath || "");
  const target = path.resolve(projectRoot, relativePath);
  if (!(target === projectRoot || target.startsWith(`${projectRoot}${path.sep}`))) {
    throw new ValidationError("Invalid project file path.");
  }
  if (!existsSync(target)) {
    throw new ValidationError("Project file path not found.");
  }
  assertNoProjectPathSymlink(projectRoot, relativePath);
  const targetStat = lstatSync(target);
  if (targetStat.isSymbolicLink()) {
    throw new ValidationError("Symbolic links are not browsed from the Control Center.");
  }
  if (!targetStat.isDirectory()) {
    return sanitizeEvent({
      projectId: project.slug,
      available: true,
      path: relativePath,
      parentPath: parentRelativePath(relativePath),
      entries: [fileEntryRecord(target, path.basename(target), relativePath)],
      message: "",
    });
  }
  const entries = readdirSync(target, { withFileTypes: true })
    .filter((entry) => !hiddenProjectFile(entry.name))
    .slice(0, 250)
    .map((entry) => fileEntryRecord(path.join(target, entry.name), entry.name, joinRelativePath(relativePath, entry.name)))
    .filter(Boolean)
    .sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === "directory" ? -1 : 1));
  return sanitizeEvent({
    projectId: project.slug,
    available: true,
    path: relativePath,
    parentPath: parentRelativePath(relativePath),
    entries,
    message: "",
  });
}

function resolveProjectRoot(project) {
  const root = path.resolve(projectsRoot);
  const relativePath = safeRelativeProjectPath(project.relativePath || project.slug);
  const target = path.resolve(root, relativePath);
  if (!(target === root || target.startsWith(`${root}${path.sep}`))) {
    throw new ValidationError("Invalid project root.");
  }
  if (!existsSync(target)) {
    throw new ValidationError("Project root not found.");
  }
  const rootRealPath = safeRealpath(root);
  const targetRealPath = safeRealpath(target);
  if (!(targetRealPath === rootRealPath || targetRealPath.startsWith(`${rootRealPath}${path.sep}`))) {
    throw new ValidationError("Project root leaves the projects directory.");
  }
  return targetRealPath;
}

function safeRelativeProjectPath(value) {
  const normalized = String(value || "").replaceAll("\\", "/").replace(/^\/+|\/+$/g, "");
  if (!normalized) return "";
  if (normalized.includes("..") || /^[A-Za-z]:/.test(normalized)) throw new ValidationError("Invalid project file path.");
  if (!/^[A-Za-z0-9._/@ -]+$/.test(normalized)) throw new ValidationError("Invalid project file path.");
  return normalized;
}

function safeRealpath(value) {
  try {
    return realpathSync(value);
  } catch {
    throw new ValidationError("Project file path not found.");
  }
}

function assertNoProjectPathSymlink(projectRoot, relativePath) {
  const parts = safeRelativeProjectPath(relativePath).split("/").filter(Boolean);
  let current = projectRoot;
  for (const part of parts) {
    current = path.join(current, part);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) {
      throw new ValidationError("Symbolic links are not browsed from the Control Center.");
    }
  }
}

function joinRelativePath(base, name) {
  return [base, name].filter(Boolean).join("/");
}

function parentRelativePath(value) {
  const normalized = safeRelativeProjectPath(value);
  if (!normalized) return "";
  const parent = path.posix.dirname(normalized.replaceAll("\\", "/"));
  return parent === "." ? "" : parent;
}

function hiddenProjectFile(name) {
  return [".git", "node_modules", "vendor", ".next", "dist", "build", ".turbo", ".cache", ".env", ".env.local", ".env.production"].includes(name);
}

function fileEntryRecord(filePath, name, relativePath) {
  try {
    const stat = lstatSync(filePath);
    const isSymlink = stat.isSymbolicLink();
    return {
      name: sanitizeRef(name),
      path: sanitizeRef(relativePath),
      type: isSymlink ? "symlink" : stat.isDirectory() ? "directory" : "file",
      sizeBytes: stat.isDirectory() || isSymlink ? 0 : stat.size,
      sizeLabel: stat.isDirectory() ? "" : bytesLabel(stat.size),
      modifiedAt: stat.mtime.toISOString(),
      browsable: stat.isDirectory() && !isSymlink,
    };
  } catch {
    return null;
  }
}

function renderControlCenter(context, params) {
  const sections = operationsPortalSections();
  const requestedSection = params.get("section") || "status";
  const section = sections.some((item) => item.id === requestedSection) ? requestedSection : "status";
  const selectedProject = context.projects.some((project) => project.slug === params.get("project")) ? params.get("project") : context.projects[0]?.slug || "";
  const currentProject = context.projects.find((project) => project.slug === selectedProject) || null;
  const title = sections.find((item) => item.id === section)?.label || "Status";
  const body = renderOperationsSection(section, context, params, currentProject);

  return `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>Admin Control Center</title>
${controlCenterStylesheetLinks()}
${controlCenterScriptTags()}
</head>
<body data-cc-theme="light">
<main aria-busy="false" class="cc-app-shell ops-shell section-${escapeHtml(section)}">
  <div class="ops-layout">
    <aside class="ops-topbar ops-sidebar" aria-label="Menu principale">
      <a class="ops-brand" href="/?section=status" aria-label="Platform operations"><span class="ops-brand-mark">P</span><strong>Platform</strong></a>
      <span class="ops-status-pill ${context.goNoGo.status === "go" ? "go" : "no-go"}">${context.goNoGo.status === "go" ? "GO LIVE" : "NO GO LIVE"}</span>
      <nav class="ops-nav" aria-label="Sezioni portal">
        ${sections.filter((item) => !item.hidden).map((item) => `<a class="${item.id === section ? "active" : ""}" ${item.id === section ? 'aria-current="page"' : ""} href="/?section=${escapeHtml(item.id)}">${controlIcon(item.icon)}<span>${escapeHtml(item.label)}</span></a>`).join("")}
      </nav>
      ${authRequired ? '<a class="ops-icon-link" href="/logout" aria-label="Logout">Logout</a>' : ""}
    </aside>
    <section class="ops-page" aria-labelledby="control-page-title">
      <div class="ops-page-head">
        <div>
          <h1 id="control-page-title">${escapeHtml(title)}</h1>
          <span>${escapeHtml(operationPageHint(section, context))}</span>
        </div>
      </div>
      ${body}
    </section>
  </div>
</main>
</body>
  </html>`;
}

function operationsPortalSections() {
  return [
    { id: "status", label: "Stato", icon: "overview" },
    { id: "projects", label: "Applicazioni", icon: "projects" },
    { id: "files", label: "File", icon: "file", hidden: true },
    { id: "databases", label: "Database", icon: "databases", hidden: true },
    { id: "activity", label: "Attività", icon: "logs" },
    { id: "resources", label: "Risorse", icon: "resources" },
  ];
}

function operationPageHint(section, context) {
  const hints = {
    status: context.goNoGo.status === "go" ? "La piattaforma ha superato i controlli obbligatori." : "Qui vedi solo cosa blocca la messa online.",
    projects: "Aggiungi, ferma, avvia e archivia applicazioni senza cancellare file o database.",
    files: "Inventario file applicazione in sola lettura.",
    databases: "Database collegati alle applicazioni e azioni metadata.",
    activity: "Errori, avvisi, problemi e operazioni recenti.",
    resources: "Uso reale risorse, limiti e runtime applicazioni.",
  };
  return hints[section] || "";
}

function renderOperationsSection(section, context, params, currentProject) {
  if (section === "projects") return renderOpsProjects(context);
  if (section === "files") return renderOpsFiles(context, params, currentProject);
  if (section === "databases") return renderOpsDatabases(context, currentProject);
  if (section === "activity") return renderOpsActivity(context);
  if (section === "resources") return renderOpsResources(context);
  return renderOpsStatus(context);
}

function renderOpsStatus(context) {
  const report = context.goNoGo;
  const isGo = report.status === "go";
  const status = isGo ? "GO LIVE" : "NO GO LIVE";
  const rows = opsStatusRows(context);
  const passedRows = rows.filter((row) => row.status === "passed");
  const missingRows = rows.filter((row) => ["authorization-required", "pending-live-proof", "pending-provider"].includes(row.status));
  const fixRows = rows.filter((row) => ["failed", "needs-work", "plan-only"].includes(row.status));
  const notPassedRows = rows.filter((row) => row.status !== "passed");
  const lastRun = context.statusRun;
  const nextStep = isGo
    ? "Mantieni il report salvato come prova di rilascio e verifica che non siano cambiate configurazioni, DNS o provider."
    : notPassedRows.length
      ? "Controlla le righe aperte, chiudi i requisiti e rilancia i test."
      : "Genera un nuovo report di produzione per avere una decisione aggiornata.";
  return `<section class="ops-section">
    <div class="ops-command-band" id="status-run">
      <div>
        <strong>Verifica stato adesso</strong>
        <span>${escapeHtml(nextStep)}</span>
      </div>
      <form method="post" action="/actions/status-check">
        <button class="ops-button primary" type="submit">${controlIcon("play")} Avvia test reali</button>
      </form>
    </div>
    ${renderStatusRunSummary(lastRun)}
    <div class="ops-panel" data-status-tabs>
      <div class="ops-panel-head ops-status-tabs-head">
        <div>
          <h2>Controlli go live</h2>
          <p>Mostra solo platform-infrastructure: test reali del Portal, report go/no-go e prove produzione.</p>
        </div>
        <span class="ops-badge ${isGo ? "good" : "bad"}">${escapeHtml(status)}</span>
      </div>
      <div class="ops-status-tabs" role="tablist" aria-label="Filtro controlli stato">
        ${renderStatusTabButton("all", "Controlli", rows.length, true)}
        ${renderStatusTabButton("ok", "OK", passedRows.length)}
        ${renderStatusTabButton("fix", "Da sistemare", fixRows.length)}
        ${renderStatusTabButton("missing", "Prove mancanti", missingRows.length)}
      </div>
      <div class="ops-status-panel active" id="status-tab-all" role="tabpanel" data-status-panel="all">
        ${renderStatusAllPanel(passedRows, notPassedRows)}
      </div>
      <div class="ops-status-panel" id="status-tab-ok" role="tabpanel" data-status-panel="ok" hidden>
        ${renderStatusRowsTable(passedRows, "Tutto OK", "Nessun controllo superato ancora disponibile.")}
      </div>
      <div class="ops-status-panel" id="status-tab-fix" role="tabpanel" data-status-panel="fix" hidden>
        ${renderStatusRowsTable(fixRows, "Niente da sistemare", "Non ci sono controlli falliti o solo pianificati.")}
      </div>
      <div class="ops-status-panel" id="status-tab-missing" role="tabpanel" data-status-panel="missing" hidden>
        ${renderStatusRowsTable(missingRows, "Nessuna prova mancante", "Non risultano prove live o provider mancanti.")}
      </div>
    </div>
  </section>`;
}

function renderOpsProjects(context) {
  const resourcesByProject = projectResourceRowsByProject(context);
  const activeProjects = context.projects.filter((project) => project.enabled && !project.archivedAt).length;
  const projectsWithDatabases = context.projects.filter((project) => projectDatabases(context, project).length > 0).length;
  const dedicatedRuntimeCount = context.resources.containersByProject.filter((item) => item.attribution === "container-dedicato" || item.attribution === "docker-stats").length;
  const runtimeGroups = [
    { id: "php", label: "PHP Apache" },
    { id: "node", label: "Node/Next" },
    { id: "static", label: "Static" },
  ];
  const groupedRuntimeIds = new Set(runtimeGroups.map((group) => group.id));
  const groupedSections = runtimeGroups
    .map((group) => renderOpsProjectGroup({
      ...group,
      projects: context.projects.filter((project) => project.runtime === group.id),
      context,
      resourcesByProject,
    }))
    .join("");
  const otherProjects = context.projects.filter((project) => !groupedRuntimeIds.has(project.runtime));
  const otherSection = otherProjects.length ? renderOpsProjectGroup({
    id: "other",
    label: "Altro",
    projects: otherProjects,
    context,
    resourcesByProject,
  }) : "";
  return `<section class="ops-section">
    <div class="ops-metrics">
      ${renderOpsMetric("Applicazioni", context.projects.length, `${activeProjects} online`, activeProjects === context.projects.length ? "good" : "warn")}
      ${renderOpsMetric("Con database", projectsWithDatabases, "Mostrate nella vista database", projectsWithDatabases ? "info" : "warn")}
      ${renderOpsMetric("Runtime dedicati", `${dedicatedRuntimeCount}/${context.applications.length}`, context.resources.containerMetricsAvailable ? "Misurati da cAdvisor" : "Metriche container non disponibili", dedicatedRuntimeCount ? "good" : "warn")}
      ${renderOpsMetric("Host", context.subdomains.length, "Routing applicazioni dichiarato", "info")}
    </div>
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>Aggiungi applicazione</h2>
          <p>Scegli tipo, nome e descrizione. Slug, host e metadata tecnici vengono generati automaticamente.</p>
        </div>
      </div>
      <form class="ops-form" method="post" action="/actions/project-command">
        <input type="hidden" name="action" value="create">
        <select name="runtime" aria-label="Tipo applicazione"><option value="php">PHP Apache</option><option value="node">Node/Next</option><option value="static">Static</option></select>
        <input name="displayName" placeholder="Nome applicazione" aria-label="Nome applicazione">
        <input name="description" placeholder="Descrizione breve" aria-label="Descrizione applicazione">
        <input type="hidden" name="confirm" value="CREATE-PROJECT">
        <button class="ops-button primary" type="submit">${controlIcon("plus")} Aggiungi applicazione</button>
      </form>
    </div>
    <div class="ops-project-board">
      ${groupedSections}${otherSection || ""}
      ${context.projects.length ? "" : `<div class="ops-panel">${empty("Nessuna applicazione", "Monta o dichiara una applicazione per gestirla dal portal.")}</div>`}
    </div>
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>Archivia applicazione</h2>
          <p>Archivia i metadata e disabilita il routing; non elimina file, database o volumi.</p>
        </div>
      </div>
      <form class="ops-form" method="post" action="/actions/project-command">
        <input type="hidden" name="action" value="archive">
        <select name="slug" aria-label="Applicazione da archiviare">${context.projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("")}</select>
        <input name="confirm" placeholder="ARCHIVE-PROJECT" aria-label="Conferma archiviazione">
        <button class="ops-button danger" type="submit">${controlIcon("archive")} Archivia</button>
      </form>
    </div>
  </section>`;
}

function renderOpsProjectGroup({ id, label, projects, context, resourcesByProject }) {
  if (!projects.length) return "";
  const online = projects.filter((project) => project.enabled && !project.archivedAt).length;
  return `<div class="ops-project-group ${escapeHtml(id)}">
    <div class="ops-project-group-head">
      <div>
        <h2>${escapeHtml(label)}</h2>
        <span>${escapeHtml(String(projects.length))} applicazioni, ${escapeHtml(String(online))} online</span>
      </div>
      <span class="ops-runtime ${escapeHtml(id)}">${escapeHtml(label)}</span>
    </div>
    <div class="ops-project-grid">
      ${projects.map((project) => renderOpsProjectCard(project, context, resourcesByProject.get(project.slug))).join("")}
    </div>
  </div>`;
}

function renderOpsProjectCard(project, context, resourceSummary) {
  const databases = projectDatabases(context, project);
  const storage = projectStorage(context, project);
  const summary = resourceSummary || projectResourceSummary(context, project);
  const state = projectOpsState(project);
  const hasFiles = project.filesystemExists !== false;
  const canRoute = hasFiles && !project.archivedAt;
  const databaseLinks = databases.length
    ? databases.map((database) => `<a class="ops-mini-link" href="/?section=databases#database-${escapeHtml(database.id)}">${escapeHtml(databaseDisplayName(database))}</a>`).join("")
    : '<span class="ops-muted">Nessun database</span>';
  const storageLinks = [
    ...storage.webspaces.map((space) => `<span class="ops-mini-link">webspace: ${escapeHtml(space.name)}</span>`),
    ...storage.buckets.map((bucket) => `<span class="ops-mini-link">bucket: ${escapeHtml(bucket.name)}</span>`),
  ].join("");
  return `<article class="ops-app-card" id="project-${escapeHtml(project.slug)}">
    <div class="ops-app-card-head">
      <div class="ops-app-title">
        <h3>${escapeHtml(project.name)}</h3>
        <span>${escapeHtml(project.slug)}${project.description ? ` / ${escapeHtml(project.description)}` : ""}</span>
      </div>
      <span class="ops-state ${statusClass(state.status)}">${escapeHtml(state.label)}</span>
    </div>
    <div class="ops-app-meta">
      <div>
        <span>Host</span>
        ${project.enabled ? `<a href="${escapeHtml(project.href)}">${escapeHtml(project.host)}</a>` : `<strong>${escapeHtml(project.host)}</strong>`}
      </div>
      <div>
        <span>Runtime</span>
        <strong>${escapeHtml(dedicatedRuntimeName(project))}</strong>
      </div>
      <div>
        <span>Stato</span>
        <strong>${escapeHtml(state.detail)}</strong>
      </div>
    </div>
    <div class="ops-app-resource-grid" aria-label="Risorse ${escapeHtml(project.name)}">
      <span><strong>CPU</strong><em>${escapeHtml(summary.cpu)}</em></span>
      <span><strong>RAM</strong><em>${escapeHtml(summary.memory)}</em></span>
      <span><strong>Disco</strong><em>${escapeHtml(summary.disk)}</em></span>
      <span><strong>Fonte</strong><em>${escapeHtml(summary.measuredFrom)}</em></span>
    </div>
    <div class="ops-app-inventory">
      <div>
        <strong>Database</strong>
        <div class="ops-chip-list">${databaseLinks}</div>
      </div>
      <div>
        <strong>Storage</strong>
        <div class="ops-chip-list">${storageLinks || '<span class="ops-muted">Nessuno storage</span>'}</div>
      </div>
      <div>
        <strong>Limiti</strong>
        <span>${escapeHtml(summary.limits)}</span>
      </div>
    </div>
    <div class="ops-app-actions">
      ${project.enabled ? `<a class="ops-button" href="${escapeHtml(project.href)}">${controlIcon("external")} Apri</a>` : ""}
      ${hasFiles ? `<a class="ops-button" href="/?section=files&project=${escapeHtml(project.slug)}">${controlIcon("file")} File</a>` : `<span class="ops-button disabled">${controlIcon("file")} File</span>`}
      ${databases.length ? `<a class="ops-button" href="/?section=databases#app-${escapeHtml(project.slug)}">${controlIcon("databases")} Database</a>` : `<span class="ops-button disabled">${controlIcon("databases")} Database</span>`}
      <form method="post" action="/actions/resource-command">
        <input type="hidden" name="action" value="stress-test">
        <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="confirm" value="RUN-STRESS:${escapeHtml(project.slug)}">
        <button class="ops-button" type="submit">${controlIcon("resources")} Stress max</button>
      </form>
      ${canRoute ? `<form method="post" action="/actions/toggle-project">
        <input type="hidden" name="slug" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="enabled" value="${project.enabled ? "0" : "1"}">
        <button class="ops-button ${project.enabled ? "danger" : "primary"}" type="submit">${controlIcon(project.enabled ? "pause" : "play")} ${project.enabled ? "Ferma" : "Avvia"}</button>
      </form>` : `<span class="ops-button disabled">${controlIcon("pause")} Non avviabile</span>`}
    </div>
  </article>`;
}

function projectOpsState(project) {
  if (project.archivedAt || project.status === "archived") return { status: "archived", label: "Archiviata", detail: "Fuori dal routing" };
  if (project.filesystemExists === false) return { status: "offline", label: "File mancanti", detail: "Sorgenti non montati" };
  if (project.enabled) return { status: "online", label: "Online", detail: "Raggiungibile dal router" };
  return { status: "offline", label: "Fermata", detail: "Routing disabilitato" };
}

function projectResourceRowsByProject(context) {
  return new Map(context.projects.map((project) => [project.slug, projectResourceSummary(context, project)]));
}

function projectResourceSummary(context, project) {
  const usage = context.resources.projectUsage.find((item) => item.projectId === project.slug) || {};
  const containers = context.resources.containersByProject.filter((item) => item.projectId === project.slug || item.applicationId === project.slug);
  const measuredContainers = containers.filter((item) => item.attribution === "container-dedicato" || item.attribution === "docker-stats");
  const cpuCores = measuredContainers.length ? measuredContainers.reduce((sum, item) => sum + Number(item.cpuCores || 0), 0) : null;
  const memoryBytes = measuredContainers.length ? measuredContainers.reduce((sum, item) => sum + Number(item.memoryBytes || 0), 0) : null;
  const hostCores = Number(context.resources.totals?.cpu?.cores || 0);
  const limit = context.resources.projectLimits.find((item) => item.projectId === project.slug) || resourceLimitRecord({ projectId: project.slug });
  return {
    cpu: measuredContainers.length ? measuredCpuLabel(measuredContainers, hostCores) : usage.cpuMessage || "Metriche container non disponibili",
    memory: memoryBytes != null ? usageBytesLabel(memoryBytes) : usage.memoryMessage || "Metriche container non disponibili",
    disk: usage.diskAvailable ? `${usageBytesLabel(usage.diskBytes)} (${Number(usage.files || 0)} file)` : "Non disponibile",
    containers: containers.length ? containers.map((item) => `${item.container}:${item.status}`).join(", ") : `${dedicatedRuntimeName(project)} atteso`,
    measuredFrom: measuredContainers.length ? (measuredContainers.some((item) => item.attribution === "docker-stats") ? "docker stats + filesystem" : "Prometheus/cAdvisor + filesystem") : "filesystem + container atteso",
    limits: `${limit.cpuMillicores || 0}m CPU / ${limit.memoryMb || 0} MB RAM / ${limit.diskMb || 0} MB disk`,
  };
}

function renderOpsFiles(context, params, currentProject) {
  if (!currentProject) {
    return `<section class="ops-section"><div class="ops-panel">${empty("Nessuna applicazione selezionata", "Aggiungi o monta una applicazione per vedere i file.")}</div></section>`;
  }
  let snapshot;
  try {
    snapshot = readProjectFiles(currentProject.slug, params.get("path") || "", context);
  } catch (error) {
    snapshot = { available: false, path: "", parentPath: "", entries: [], message: error instanceof ValidationError ? error.message : "File applicazione non disponibili." };
  }
  const projectOptions = context.projects.map((project) => `<option value="${escapeHtml(project.slug)}" ${project.slug === currentProject.slug ? "selected" : ""}>${escapeHtml(project.name)}</option>`).join("");
  const entries = snapshot.entries.map((entry) => `<tr>
    <td><strong>${entry.browsable ? `<a href="/?section=files&project=${escapeHtml(currentProject.slug)}&path=${encodeURIComponent(entry.path)}">${escapeHtml(entry.name)}</a>` : escapeHtml(entry.name)}</strong><span>${escapeHtml(entry.path)}</span></td>
    <td><span class="ops-state ${statusClass(entry.type)}">${escapeHtml(entry.type)}</span></td>
    <td>${escapeHtml(entry.sizeLabel || "")}</td>
    <td>${escapeHtml(entry.modifiedAt || "")}</td>
    <td>${entry.browsable ? `<a class="ops-icon-button" href="/?section=files&project=${escapeHtml(currentProject.slug)}&path=${encodeURIComponent(entry.path)}" aria-label="Apri ${escapeHtml(entry.name)}">${controlIcon("folder")}</a>` : '<span class="ops-muted">Sola lettura</span>'}</td>
  </tr>`).join("");
  const parentHref = snapshot.parentPath || snapshot.path ? `/?section=files&project=${escapeHtml(currentProject.slug)}&path=${encodeURIComponent(snapshot.parentPath || "")}` : "";
  return `<section class="ops-section">
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>File applicazione</h2>
          <p>Elenco in sola lettura. Secret, dipendenze, build output e symlink non vengono aperti.</p>
        </div>
        <form class="switcher ops-switcher" method="get" action="/">
          <input type="hidden" name="section" value="files">
          <select name="project" aria-label="Applicazione">${projectOptions}</select>
        </form>
      </div>
      <div class="ops-file-toolbar">
        <span><strong>${escapeHtml(currentProject.name)}</strong> / ${escapeHtml(snapshot.path || ".")}</span>
        ${parentHref ? `<a class="ops-button" href="${parentHref}">${controlIcon("arrow-left")} Su</a>` : ""}
      </div>
      ${snapshot.available ? `<div class="ops-table-wrap">
        <table class="ops-table">
          <thead><tr><th>Nome</th><th>Tipo</th><th>Dimensione</th><th>Modificato</th><th>Azione</th></tr></thead>
          <tbody>${entries || `<tr><td colspan="5">${empty("Cartella vuota", "Nessun elemento navigabile trovato in questo path.")}</td></tr>`}</tbody>
        </table>
      </div>` : empty("File non disponibili", snapshot.message || "I sorgenti applicazione non sono montati.")}
    </div>
  </section>`;
}

function renderOpsDatabases(context) {
  const projectInventories = context.projects.map((project) => ({
    project,
    databases: projectDatabases(context, project),
    storage: projectStorage(context, project),
  }));
  const databaseInventories = projectInventories.filter((item) => item.databases.length > 0);
  const linkedDatabaseIds = new Set(projectInventories.flatMap((item) => item.databases.map((database) => database.id)));
  const unlinkedDatabases = context.databases.filter((database) => !linkedDatabaseIds.has(database.id));
  const projectOptions = databaseInventories.map(({ project }) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("");
  const appsWithDatabases = databaseInventories.length;
  const linkedStorageCount = projectInventories.reduce((total, item) => total + item.storage.webspaces.length + item.storage.buckets.length, 0);
  const engineSummary = context.databaseEngines.map((engine) => engine.name).join(" / ") || "Nessun motore";
  const rows = databaseInventories.map(renderProjectDatabaseRow).join("");
  const unlinkedRow = unlinkedDatabases.length ? `<tr id="app-unlinked">
    <td><strong>Metadata non collegati</strong><span>Record senza applicazione valida</span></td>
    <td>${renderDatabaseList(unlinkedDatabases)}</td>
    <td>${renderDatabaseEngineList(unlinkedDatabases)}</td>
    <td>${renderDatabaseStatusList(unlinkedDatabases)}</td>
    <td><span class="ops-muted">Nessuno storage</span></td>
    <td>${renderDatabaseBackupList(unlinkedDatabases)}</td>
    <td>${renderDatabaseActions(unlinkedDatabases)}</td>
  </tr>` : "";
  const bodyRows = `${rows}${unlinkedRow}` || `<tr><td colspan="7">${empty("Nessun database collegato", "Quando una applicazione avrà metadata database, comparirà qui.")}</td></tr>`;
  return `<section class="ops-section">
    <div class="ops-metrics">
      ${renderOpsMetric("Applicazioni con DB", appsWithDatabases, `su ${context.projects.length} applicazioni`, appsWithDatabases ? "info" : "warn")}
      ${renderOpsMetric("Database", context.databases.length, engineSummary, "info")}
      ${renderOpsMetric("Storage", linkedStorageCount, "Webspace e bucket collegati", "info")}
      ${renderOpsMetric("Credenziali", "Nascoste", "Nessun valore esposto nel portal", "good")}
    </div>
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>Aggiungi metadata database</h2>
          <p>Dichiara solo inventario; MariaDB/PostgreSQL non vengono modificati dal browser.</p>
        </div>
      </div>
      <form class="ops-form" method="post" action="/actions/database-command">
        <input type="hidden" name="action" value="create">
        <select name="projectId" aria-label="Applicazione">${projectOptions}</select>
        <select name="engine" aria-label="Motore"><option value="mariadb">MariaDB</option><option value="postgres">PostgreSQL</option></select>
        <input name="name" placeholder="database_name" aria-label="Nome database">
        <input name="ownerRole" placeholder="owner_role" aria-label="Owner role">
        <input type="hidden" name="confirm" value="CREATE-DATABASE">
        <button class="ops-button primary" type="submit">${controlIcon("plus")} Aggiungi database</button>
      </form>
    </div>
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>Database per applicazione</h2>
          <p>Vista unica di tutti i metadata: nome visibile, nome fisico, motore, storage e piani operativi.</p>
        </div>
      </div>
      <div class="ops-table-wrap">
        <table class="ops-table">
          <thead><tr><th>Applicazione</th><th>Database</th><th>Motore / owner</th><th>Stato</th><th>Storage</th><th>Backup / restore</th><th>Azioni</th></tr></thead>
          <tbody>${bodyRows}</tbody>
        </table>
      </div>
    </div>
  </section>`;
}

function renderProjectDatabaseRow({ project, databases, storage }) {
  const status = project.archivedAt ? "archived" : project.enabled ? "active" : project.status;
  return `<tr id="app-${escapeHtml(project.slug)}">
    <td><strong>${escapeHtml(project.name)}</strong><span>${escapeHtml(project.slug)} / ${escapeHtml(humanName(status))}</span></td>
    <td>${renderDatabaseList(databases)}</td>
    <td>${renderDatabaseEngineList(databases)}</td>
    <td>${renderDatabaseStatusList(databases)}</td>
    <td>${renderStorageList(storage)}</td>
    <td>${renderDatabaseBackupList(databases)}</td>
    <td>${renderDatabaseActions(databases)}</td>
  </tr>`;
}

function renderDatabaseList(databases) {
  if (!databases.length) return '<span class="ops-muted">Nessun database collegato</span>';
  return `<div class="ops-db-list">${databases.map((database) => {
    const displayName = databaseDisplayName(database);
    const physicalName = displayName === database.name ? database.id : `${database.name} / ${database.id}`;
    return `<div class="ops-db-item" id="database-${escapeHtml(database.id)}"><strong>${escapeHtml(displayName)}</strong><span>${escapeHtml(physicalName)}</span></div>`;
  }).join("")}</div>`;
}

function renderDatabaseEngineList(databases) {
  if (!databases.length) return '<span class="ops-muted">Non configurato</span>';
  return `<div class="ops-stack-list">${databases.map((database) => `<div class="ops-stack-line">
    <span class="ops-runtime ${database.engine === "mariadb" ? "php" : "node"}">${escapeHtml(database.engine)}</span>
    <span>${escapeHtml(database.ownerRole)}</span>
  </div>`).join("")}</div>`;
}

function renderDatabaseStatusList(databases) {
  if (!databases.length) return '<span class="ops-state warn">mancante</span>';
  return `<div class="ops-stack-list">${databases.map((database) => `<div class="ops-stack-line">
    <span class="ops-state ${statusClass(database.status)}">${escapeHtml(database.status)}</span>
    <span>${escapeHtml(bytesLabel(database.sizeBytes))}</span>
  </div>`).join("")}</div>`;
}

function renderDatabaseBackupList(databases) {
  if (!databases.length) return '<span class="ops-muted">Nessun piano</span>';
  return `<div class="ops-stack-list">${databases.map((database) => `<div class="ops-stack-line"><span>${escapeHtml(database.backupPolicy)}</span><span>${escapeHtml(database.restoreStatus)}</span></div>`).join("")}</div>`;
}

function renderDatabaseActions(databases) {
  if (!databases.length) return '<span class="ops-muted">Nessuna azione</span>';
  return `<div class="ops-db-actions">${databases.map((database) => {
    const admin = databaseAdminTool(database);
    const phpMyAdminConfirm = `OPEN-PHPMYADMIN:${database.id}`;
    const phpPgAdminConfirm = `OPEN-PHPPGADMIN:${database.id}`;
    const phpMyAdminHref = `/actions/phpmyadmin-login?databaseId=${encodeURIComponent(database.id)}&confirm=${encodeURIComponent(phpMyAdminConfirm)}`;
    const phpPgAdminHref = `/actions/phppgadmin-login?databaseId=${encodeURIComponent(database.id)}&confirm=${encodeURIComponent(phpPgAdminConfirm)}`;
    return `<div class="ops-row-actions">
    ${database.engine === "mariadb" ? `<a class="ops-icon-button" href="${escapeHtml(phpMyAdminHref)}" target="_blank" rel="noreferrer" aria-label="Apri ${escapeHtml(databaseDisplayName(database))} in phpMyAdmin con accesso limitato">${controlIcon("external")}</a>` : `<a class="ops-icon-button" href="${escapeHtml(phpPgAdminHref)}" target="_blank" rel="noreferrer" aria-label="Apri ${escapeHtml(databaseDisplayName(database))} in ${escapeHtml(admin.label)} con accesso limitato">${controlIcon("external")}</a>`}
    <form method="post" action="/actions/database-command">
      <input type="hidden" name="id" value="${escapeHtml(database.id)}">
      <input type="hidden" name="action" value="backup">
      <button class="ops-icon-button" type="submit" aria-label="Plan backup for ${escapeHtml(databaseDisplayName(database))}">${controlIcon("backups")}</button>
    </form>
    <form method="post" action="/actions/database-command">
      <input type="hidden" name="id" value="${escapeHtml(database.id)}">
      <input type="hidden" name="action" value="restore">
      <input type="hidden" name="backupRef" value="latest">
      <button class="ops-icon-button" type="submit" aria-label="Plan restore drill for ${escapeHtml(databaseDisplayName(database))}">${controlIcon("refresh")}</button>
    </form>
  </div>`;
  }).join("")}</div>`;
}

function databaseAdminTool(database) {
  if (database.engine === "postgres") {
    return {
      label: "phpPgAdmin",
      href: `https://${controlCenterHost}/actions/phppgadmin-login?databaseId=${encodeURIComponent(database.id)}&confirm=${encodeURIComponent(`OPEN-PHPPGADMIN:${database.id}`)}`,
    };
  }
  return {
    label: "phpMyAdmin",
    href: `https://${controlCenterHost}${phpMyAdminDatabaseLocation(database.name)}`,
  };
}

function resolveMariaDbCredential(database, project) {
  const metadataUser = sanitizeDatabasePrincipal(database.adminUser || database.ownerRole || "");
  const metadataPassword = readCredentialPasswordFile(database.adminPasswordFile || database.passwordFile || "", project);
  if (metadataUser && metadataPassword) return { user: metadataUser, password: metadataPassword, source: "database-metadata" };
  const projectCredential = readProjectMariaDbCredential(database, project);
  if (projectCredential) return projectCredential;
  const phpCredential = readProjectPhpMariaDbCredential(database, project);
  if (phpCredential) return phpCredential;
  return null;
}

function resolvePostgresCredential(database, project) {
  const metadataUser = sanitizeDatabasePrincipal(database.adminUser || database.ownerRole || "");
  const metadataPassword = readCredentialPasswordFile(database.adminPasswordFile || database.passwordFile || "", project);
  if (metadataUser && metadataPassword) return { user: metadataUser, password: metadataPassword, source: "database-metadata" };
  const appPassword = readPostgresAppPassword();
  if (appPassword && (!metadataUser || metadataUser === postgresAppUser)) {
    return { user: metadataUser || postgresAppUser, password: appPassword, source: "postgres-app-secret" };
  }
  return null;
}

function readPostgresAppPassword() {
  if (!postgresAppPasswordFile || !existsSync(postgresAppPasswordFile)) return "";
  try {
    return readFileSync(postgresAppPasswordFile, "utf8").trim();
  } catch {
    return "";
  }
}

function readProjectMariaDbCredential(database, project) {
  if (!project || !project.filesAvailable) return null;
  let root = "";
  try {
    root = resolveProjectRoot(project);
  } catch {
    return null;
  }
  for (const fileName of [".env", ".env.local", ".env.production", "private/.env"]) {
    const filePath = path.join(root, fileName);
    if (!existsSync(filePath)) continue;
    let env = {};
    try {
      env = parseEnvText(readFileSync(filePath, "utf8"));
    } catch {
      continue;
    }
    const dbName = firstEnvValue(env, ["DB_DATABASE", "DB_NAME", "DATABASE_NAME", "MYSQL_DATABASE", "MARIADB_DATABASE"]);
    if (dbName && dbName !== database.name) continue;
    const user = sanitizeDatabasePrincipal(firstEnvValue(env, ["PHPMYADMIN_USER", "PMA_USER", "DB_USERNAME", "DB_USER", "DATABASE_USER", "MYSQL_USER", "MARIADB_USER"]) || database.ownerRole || "");
    const password = firstEnvValue(env, ["PHPMYADMIN_PASSWORD", "PMA_PASSWORD", "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD", "DATABASE_PASS", "MYSQL_PASSWORD", "MYSQL_PASS", "MARIADB_PASSWORD", "MARIADB_PASS"]);
    if (user && password) return { user, password, source: `project-env:${fileName}` };
  }
  return null;
}

function readProjectPhpMariaDbCredential(database, project) {
  if (!project || !project.filesAvailable) return null;
  let root = "";
  try {
    root = resolveProjectRoot(project);
  } catch {
    return null;
  }
  for (const fileName of ["private/config/database.php", "config/config.php", "config/database.php", "private/config/app.php"]) {
    const filePath = path.join(root, fileName);
    if (!existsSync(filePath)) continue;
    let text = "";
    try {
      text = readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    const dbName = firstPhpConfigValue(text, ["database", "dbname", "db_name", "DB_DATABASE", "DB_NAME", "DATABASE_NAME"]);
    if (dbName && dbName !== database.name) continue;
    const user = sanitizeDatabasePrincipal(firstPhpConfigValue(text, ["username", "user", "db_user", "DB_USERNAME", "DB_USER", "DATABASE_USER"]) || database.ownerRole || "");
    const password = firstPhpConfigValue(text, ["password", "pass", "db_pass", "db_password", "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD", "DATABASE_PASS"]);
    if (user && password) return { user, password, source: `project-php-config:${fileName}` };
  }
  return null;
}

function firstPhpConfigValue(text, keys) {
  for (const key of keys) {
    for (const pattern of phpConfigValuePatterns(key)) {
      const match = String(text || "").match(pattern);
      if (match && match[1] !== "") return match[1];
    }
  }
  return "";
}

function phpConfigValuePatterns(key) {
  const escaped = escapeRegExp(key);
  return [
    new RegExp(`['"]${escaped}['"]\\s*=>\\s*getenv\\([^)]*\\)\\s*\\?:\\s*['"]([^'"]*)['"]`, "i"),
    new RegExp(`['"]${escaped}['"]\\s*=>\\s*\\$_ENV\\[[^\\]]+\\]\\s*\\?\\?\\s*['"]([^'"]*)['"]`, "i"),
    new RegExp(`['"]${escaped}['"]\\s*=>\\s*['"]([^'"]*)['"]`, "i"),
    new RegExp(`\\$${escaped}\\s*=\\s*['"]([^'"]*)['"]`, "i"),
    new RegExp(`define\\(\\s*['"]${escaped}['"]\\s*,\\s*['"]([^'"]*)['"]\\s*\\)`, "i"),
    new RegExp(`const\\s+${escaped}\\s*=\\s*['"]([^'"]*)['"]`, "i"),
  ];
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function readCredentialPasswordFile(filePath, project) {
  const value = String(filePath || "").trim();
  if (!value) return "";
  const allowedRoots = ["/run/secrets", "/var/www/project-state"];
  if (project) {
    try {
      allowedRoots.push(resolveProjectRoot(project));
    } catch {
      // Ignore unavailable project roots.
    }
  }
  const resolved = path.resolve(value);
  if (!allowedRoots.some((root) => resolved === root || resolved.startsWith(`${root}${path.sep}`))) return "";
  try {
    return readFileSync(resolved, "utf8").trim();
  } catch {
    return "";
  }
}

function parseEnvText(text) {
  const result = {};
  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const index = trimmed.indexOf("=");
    const key = trimmed.slice(0, index).trim();
    if (!/^[A-Z0-9_]+$/i.test(key)) continue;
    let value = trimmed.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

function firstEnvValue(env, keys) {
  for (const key of keys) {
    const value = env[key];
    if (value != null && String(value).trim() !== "") return String(value).trim();
  }
  return "";
}

function sanitizeDatabasePrincipal(value) {
  const user = String(value || "").trim();
  if (!/^[A-Za-z0-9_.$-]{1,80}$/.test(user)) return "";
  if (user.toLowerCase() === "root") return "";
  return user;
}

async function phpMyAdminLogin(database, credential) {
  const target = phpMyAdminDatabaseLocation(database.name).replace(/^\/phpmyadmin\//, "");
  const start = await phpMyAdminInternalRequest("GET", "/index.php?route=/");
  const startCookies = mergeSetCookieHeaders(start.cookies.map(rewritePhpMyAdminCookie).filter(Boolean));
  const token = htmlInputValue(start.body, "token");
  const setSession = htmlInputValue(start.body, "set_session");
  const body = new URLSearchParams({
    ...(token ? { token } : {}),
    ...(setSession ? { set_session: setSession } : {}),
    pma_username: credential.user,
    pma_password: credential.password,
    server: "1",
    target,
  }).toString();
  const login = await phpMyAdminInternalRequest("POST", "/index.php?route=/", body, {
    "content-type": "application/x-www-form-urlencoded",
    ...(startCookies.length ? { cookie: cookieHeaderFromSetCookies(startCookies) } : {}),
  });
  const cookies = mergeSetCookieHeaders([
    ...startCookies,
    ...login.cookies.map(rewritePhpMyAdminCookie).filter(Boolean),
  ]);
  if (!cookies.length) return { ok: false, cookies: [] };
  const cookieHeader = cookieHeaderFromSetCookies(cookies);
  const verify = await phpMyAdminInternalRequest("GET", `/index.php?route=/database/structure&server=1&db=${encodeURIComponent(database.name)}`, "", {
    cookie: cookieHeader,
  });
  const loggedIn = phpMyAdminAuthCookiePresent(cookies) && phpMyAdminSessionLooksAuthenticated(verify);
  return { ok: loggedIn, cookies, token: phpMyAdminPageToken(verify.body) };
}

function phpMyAdminSessionLooksAuthenticated(response) {
  if (!response || response.status < 200 || response.status >= 400) return false;
  const body = String(response.body || "");
  if (/name=["']pma_username["']|name=["']pma_password["']/i.test(body)) return false;
  if (/Access denied for user|Cannot log in to the MySQL server|mysqli::real_connect|Login without a password is forbidden/i.test(body)) return false;
  return /phpMyAdmin|pma_navigation|server_databases|database\/structure/i.test(body);
}

function phpMyAdminAuthCookiePresent(cookies) {
  return cookies.some((cookie) => /^(__Secure-)?pmaAuth-\d+(_https)?=/i.test(String(cookie || "")));
}

function phpMyAdminPageToken(htmlText) {
  const inputToken = htmlInputValue(htmlText, "token");
  if (inputToken) return inputToken;
  const body = String(htmlText || "");
  const patterns = [
    /\btoken["']?\s*:\s*["']([^"']+)["']/i,
    /\btoken=([a-f0-9]{16,})/i,
  ];
  for (const pattern of patterns) {
    const match = body.match(pattern);
    if (match) return decodeURIComponent(match[1]);
  }
  return "";
}

async function phpPgAdminLogin(database, credential) {
  const server = phpPgAdminServerId();
  const loginPath = `/phppgadmin/redirect.php?subject=server&server=${encodeURIComponent(server)}`;
  const start = await phpPgAdminInternalRequest("GET", loginPath);
  const startCookies = mergeSetCookieHeaders(start.cookies.map(rewritePhpPgAdminCookie).filter(Boolean));
  const passwordField = htmlPasswordInputName(start.body);
  if (!passwordField) return { ok: false, cookies: startCookies, location: phpPgAdminDatabaseLocation(database.name) };
  const body = new URLSearchParams({
    subject: "server",
    server,
    loginServer: server,
    loginUsername: credential.user,
    [passwordField]: credential.password,
    loginSubmit: "Login",
  }).toString();
  const login = await phpPgAdminInternalRequest("POST", "/phppgadmin/redirect.php", body, {
    "content-type": "application/x-www-form-urlencoded",
    ...(startCookies.length ? { cookie: cookieHeaderFromSetCookies(startCookies) } : {}),
  });
  const cookies = mergeSetCookieHeaders([
    ...startCookies,
    ...login.cookies.map(rewritePhpPgAdminCookie).filter(Boolean),
  ]);
  if (!cookies.length) return { ok: false, cookies: [], location: phpPgAdminDatabaseLocation(database.name) };
  const verify = await phpPgAdminInternalRequest("GET", phpPgAdminDatabaseLocation(database.name), "", {
    cookie: cookieHeaderFromSetCookies(cookies),
  });
  const loggedIn = phpPgAdminSessionLooksAuthenticated(verify, database.name);
  return {
    ok: loggedIn,
    cookies,
    location: phpPgAdminDatabaseLocation(database.name),
  };
}

function phpPgAdminSessionLooksAuthenticated(response, databaseName) {
  if (!response || response.status < 200 || response.status >= 400) return false;
  const body = String(response.body || "");
  if (/name=["']loginUsername["']|name=["']loginPassword_/i.test(body)) return false;
  if (/Login failed|Incorrect password|could not connect|FATAL:|password authentication failed/i.test(body)) return false;
  return /phpPgAdmin/i.test(body)
    && body.includes(databaseName)
    && /You are logged in as user|Schemas|SQL History|Logout/i.test(body);
}

function phpPgAdminServerId() {
  return `${postgresHost}:${postgresPort}:allow`;
}

function phpPgAdminDatabaseLocation(databaseName) {
  const params = new URLSearchParams({
    subject: "database",
    server: phpPgAdminServerId(),
    database: String(databaseName || ""),
  });
  return `/phppgadmin/redirect.php?${params.toString()}`;
}

function htmlPasswordInputName(htmlText) {
  const inputPattern = /<input\b[^>]*>/gi;
  let match;
  while ((match = inputPattern.exec(String(htmlText || ""))) !== null) {
    const input = match[0];
    if (!/\btype=(["'])password\1/i.test(input)) continue;
    const name = input.match(/\bname=(["'])(.*?)\1/i);
    return name ? decodeHtmlAttribute(name[2]) : "";
  }
  return "";
}

function htmlInputValue(htmlText, inputName) {
  const name = String(inputName || "");
  if (!name) return "";
  const inputPattern = /<input\b[^>]*>/gi;
  const namePattern = new RegExp(`\\bname=(["'])${escapeRegExp(name)}\\1`, "i");
  let match;
  while ((match = inputPattern.exec(String(htmlText || ""))) !== null) {
    const input = match[0];
    if (!namePattern.test(input)) continue;
    const value = input.match(/\bvalue=(["'])(.*?)\1/i);
    return value ? decodeHtmlAttribute(value[2]) : "";
  }
  return "";
}

function decodeHtmlAttribute(value) {
  return String(value || "")
    .replace(/&quot;/g, "\"")
    .replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function cookieHeaderFromSetCookies(cookies) {
  return cookies.map((cookie) => cookie.split(";")[0]).filter(Boolean).join("; ");
}

function mergeSetCookieHeaders(cookies) {
  const byName = new Map();
  for (const cookie of cookies) {
    const name = String(cookie || "").split("=", 1)[0].trim();
    if (!name) continue;
    byName.set(name, cookie);
  }
  return [...byName.values()];
}

function phpMyAdminInternalRequest(method, requestPath, body = "", extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const base = new URL(phpMyAdminInternalUrl);
    if (base.protocol !== "http:") {
      reject(new Error("Only http phpMyAdmin internal URLs are supported."));
      return;
    }
    const payload = body ? Buffer.from(body) : null;
    const req = httpRequest({
      method,
      hostname: base.hostname,
      port: base.port || 80,
      path: requestPath,
      headers: {
        host: controlCenterHost,
        "x-forwarded-host": controlCenterHost,
        "x-forwarded-proto": "https",
        "x-forwarded-prefix": "/phpmyadmin",
        ...(payload ? { "content-length": payload.length } : {}),
        ...extraHeaders,
      },
      timeout: 10000,
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        cookies: rawHeaderValues(response.rawHeaders, "set-cookie"),
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("timeout", () => req.destroy(new Error("phpMyAdmin login timed out.")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function phpPgAdminInternalRequest(method, requestPath, body = "", extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const base = new URL(phpPgAdminInternalUrl);
    if (base.protocol !== "http:") {
      reject(new Error("Only http phpPgAdmin internal URLs are supported."));
      return;
    }
    const payload = body ? Buffer.from(body) : null;
    const req = httpRequest({
      method,
      hostname: base.hostname,
      port: base.port || 80,
      path: requestPath,
      headers: {
        host: controlCenterHost,
        "x-forwarded-host": controlCenterHost,
        "x-forwarded-proto": "https",
        "x-forwarded-prefix": "/phppgadmin",
        ...(payload ? { "content-length": payload.length } : {}),
        ...extraHeaders,
      },
      timeout: 10000,
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        cookies: rawHeaderValues(response.rawHeaders, "set-cookie"),
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("timeout", () => req.destroy(new Error("phpPgAdmin login timed out.")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function rawHeaderValues(rawHeaders, name) {
  const values = [];
  const wanted = String(name).toLowerCase();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (String(rawHeaders[index]).toLowerCase() === wanted) values.push(String(rawHeaders[index + 1] || ""));
  }
  return values;
}

function rewritePhpMyAdminCookie(cookie) {
  let next = String(cookie || "").replace(/;\s*Domain=[^;]*/i, "");
  if (/;\s*Path=/i.test(next)) next = next.replace(/;\s*Path=[^;]*/i, "; Path=/phpmyadmin");
  else next += "; Path=/phpmyadmin";
  if (!/;\s*HttpOnly/i.test(next)) next += "; HttpOnly";
  if (!/;\s*SameSite=/i.test(next)) next += "; SameSite=Lax";
  return next;
}

function rewritePhpPgAdminCookie(cookie) {
  let next = String(cookie || "").replace(/;\s*Domain=[^;]*/i, "");
  if (/;\s*Path=/i.test(next)) next = next.replace(/;\s*Path=[^;]*/i, "; Path=/phppgadmin");
  else next += "; Path=/phppgadmin";
  if (!/;\s*HttpOnly/i.test(next)) next += "; HttpOnly";
  if (!/;\s*Secure/i.test(next)) next += "; Secure";
  if (!/;\s*SameSite=/i.test(next)) next += "; SameSite=Lax";
  return next;
}

function phpMyAdminDatabaseLocation(databaseName, token = "") {
  const params = new URLSearchParams({
    route: "/database/structure",
    server: "1",
    db: String(databaseName || ""),
  });
  if (token) params.set("token", token);
  return `/phpmyadmin/index.php?${params.toString()}`;
}

function renderPhpMyAdminBridge(res, location, label, cookies) {
  const safeLocation = String(location || "/phpmyadmin/");
  const safeLabel = String(label || "database");
  res.writeHead(200, {
    "cache-control": "no-store",
    "content-type": "text/html; charset=utf-8",
    "set-cookie": cookies,
  });
  res.end(`<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <title>Apertura phpMyAdmin</title>
</head>
<body>
  <p>Apertura phpMyAdmin per ${escapeHtml(safeLabel)}...</p>
  <p><a href="${escapeHtml(safeLocation)}">Apri manualmente</a></p>
  <script>
    try {
      var pattern = /phpmyadmin|pma_|pma-|navigation|server|database/i;
      for (var index = localStorage.length - 1; index >= 0; index -= 1) {
        var key = localStorage.key(index) || "";
        if (pattern.test(key)) localStorage.removeItem(key);
      }
      sessionStorage.clear();
    } catch (error) {}
    location.replace(${JSON.stringify(safeLocation)});
  </script>
</body>
</html>`);
}

function renderPhpPgAdminBridge(res, location, label, cookies) {
  const safeLocation = String(location || "/phppgadmin/");
  const safeLabel = String(label || "database");
  res.writeHead(200, {
    "cache-control": "no-store",
    "content-type": "text/html; charset=utf-8",
    "set-cookie": cookies,
  });
  res.end(`<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <title>Apertura phpPgAdmin</title>
</head>
<body>
  <p>Apertura phpPgAdmin per ${escapeHtml(safeLabel)}...</p>
  <p><a href="${escapeHtml(safeLocation)}">Apri manualmente</a></p>
  <script>
    try {
      var pattern = /phppgadmin|ppa_/i;
      for (var index = localStorage.length - 1; index >= 0; index -= 1) {
        var key = localStorage.key(index) || "";
        if (pattern.test(key)) localStorage.removeItem(key);
      }
      sessionStorage.clear();
    } catch (error) {}
    location.replace(${JSON.stringify(safeLocation)});
  </script>
</body>
</html>`);
}

function expiredPhpMyAdminCookies() {
  const names = [
    "__Secure-phpMyAdmin_https",
    "__Secure-pmaUser-1_https",
    "__Secure-pmaAuth-1_https",
  ];
  const paths = ["/", "/phpmyadmin", "/phpmyadmin/"];
  return names.flatMap((name) => paths.map((pathName) => `${name}=; Max-Age=0; Path=${pathName}; Secure; SameSite=Lax`));
}

function expiredPhpPgAdminCookies() {
  const names = ["PPA_ID"];
  const paths = ["/", "/phppgadmin", "/phppgadmin/"];
  return names.flatMap((name) => paths.map((pathName) => `${name}=; Max-Age=0; Path=${pathName}; Secure; SameSite=Lax`));
}

function renderStorageList(storage) {
  const links = [
    ...storage.webspaces.map((space) => `<span class="ops-mini-link">webspace: ${escapeHtml(space.name)}</span>`),
    ...storage.buckets.map((bucket) => `<span class="ops-mini-link">bucket: ${escapeHtml(bucket.name)}</span>`),
  ];
  return links.length ? `<div class="ops-chip-list">${links.join("")}</div>` : '<span class="ops-muted">Nessuno storage</span>';
}

function renderOpsActivity(context) {
  const problems = activityProblems(context);
  const errors = problems.filter((item) => item.severity === "error");
  const warnings = problems.filter((item) => item.severity === "warning");
  const pending = problems.filter((item) => item.severity === "pending");
  const rows = problems.map((item) => `<tr>
    <td><span class="ops-state ${statusClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
    <td><strong>${escapeHtml(item.source)}</strong><span>${escapeHtml(item.name)}</span></td>
    <td>${escapeHtml(item.summary)}</td>
    <td>${escapeHtml(item.timestamp || "")}</td>
    <td>${item.href ? `<a class="ops-button" href="${escapeHtml(item.href)}">${controlIcon("arrow-right")} Open</a>` : '<span class="ops-muted">No action</span>'}</td>
  </tr>`).join("");
  return `<section class="ops-section">
    <div class="ops-metrics">
      ${renderOpsMetric("Errori", errors.length, "Elementi falliti o critici", errors.length ? "bad" : "good")}
      ${renderOpsMetric("Avvisi", warnings.length, "Avvisi aperti", warnings.length ? "warn" : "good")}
      ${renderOpsMetric("In attesa", pending.length, "Prove o provider da completare", pending.length ? "warn" : "good")}
      ${renderOpsMetric("Alert aperti", context.logsAlerts.openAlerts.length, "Record alert", context.logsAlerts.openAlerts.length ? "warn" : "good")}
    </div>
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>Errori, avvisi e problemi</h2>
          <p>I problemi operativi arrivano da go/no-go, alert, job, audit e log operazioni.</p>
        </div>
      </div>
      <div class="ops-table-wrap">
        <table class="ops-table">
          <thead><tr><th>Gravità</th><th>Fonte</th><th>Problema</th><th>Ora</th><th>Azione</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="5">${empty("Nessun problema attivo", "Non sono stati trovati blocchi go/no-go, alert, job falliti o operazioni fallite.")}</td></tr>`}</tbody>
        </table>
      </div>
    </div>
  </section>`;
}

function renderOpsResources(context) {
  const totals = context.resources.totals;
  const rows = resourceUsageRows(context).map((item) => `<tr data-resource-row="${escapeHtml(item.applicationId)}">
    <td><strong>${escapeHtml(item.applicationName)}</strong><span>${escapeHtml(item.applicationId)}</span></td>
    <td><strong>${escapeHtml(item.projectName)}</strong><span>${escapeHtml(item.projectId)}</span></td>
    <td>${escapeHtml(item.runtime)}</td>
    <td data-resource-cell="status"><span class="ops-state ${statusClass(item.status)}">${escapeHtml(item.status)}</span></td>
    <td data-resource-cell="cpu">${escapeHtml(item.cpu)}</td>
    <td data-resource-cell="memory">${escapeHtml(item.memory)}</td>
    <td data-resource-cell="disk">${escapeHtml(item.disk)}</td>
    <td data-resource-cell="containers">${escapeHtml(item.containers)}</td>
    <td data-resource-cell="measuredFrom">${escapeHtml(item.measuredFrom)}</td>
    <td data-resource-cell="limits">${escapeHtml(item.limits)}</td>
  </tr>`).join("");
  return `<section class="ops-section" data-resource-live data-resource-live-url="/control/resources/summary" data-resource-refresh-ms="1000">
    <div class="ops-metrics">
      ${renderOpsMetric("CPU totale", context.resources.cpu.status, context.resources.cpu.summary, totals.cpu.available ? "info" : "warn", { resourceCard: "cpu" })}
      ${renderOpsMetric("RAM totale", context.resources.memory.status, context.resources.memory.summary, totals.memory.available ? "info" : "warn", { resourceCard: "memory" })}
      ${renderOpsMetric("Disco totale", context.resources.disk.status, totals.disk.available ? `${percentLabel(totals.disk.usedPercent)} usato` : totals.disk.message, totals.disk.available ? "info" : "warn", { resourceCard: "disk" })}
      ${renderOpsMetric("Applicazioni", context.applications.length, context.resources.trend, context.resources.containerMetricsAvailable ? "good" : "warn", { resourceCard: "applications" })}
    </div>
    <div class="ops-resource-summary">
      <div data-resource-summary="cpu">
        <span>CPU host</span>
        <strong>${escapeHtml(context.resources.cpu.status)}</strong>
        <em>${escapeHtml(totals.cpu.available ? `${coresLabel(totals.cpu.cores)} disponibili` : totals.cpu.message || "non disponibile")}</em>
      </div>
      <div data-resource-summary="memory">
        <span>RAM host</span>
        <strong>${escapeHtml(context.resources.memory.status)}</strong>
        <em>${escapeHtml(context.resources.memory.summary)}</em>
      </div>
      <div data-resource-summary="disk">
        <span>Disco host</span>
        <strong>${escapeHtml(context.resources.disk.status)}</strong>
        <em>${escapeHtml(totals.disk.available ? `${percentLabel(totals.disk.usedPercent)} usato` : totals.disk.message || "non disponibile")}</em>
      </div>
      <div data-resource-summary="source">
        <span>Fonte metriche</span>
        <strong>${escapeHtml(context.resources.source)}</strong>
        <em>${escapeHtml(context.resources.capturedAt)}</em>
      </div>
    </div>
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>Imposta limiti applicazione</h2>
          <p>Aggiorna solo metadata Control Center; i limiti runtime Docker richiedono un adapter ops esplicito.</p>
        </div>
      </div>
      <form method="post" action="/actions/resource-command" class="ops-form">
        <input type="hidden" name="action" value="limits">
        <select name="projectId" aria-label="Applicazione">${context.projects.map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("")}</select>
        <input name="cpuMillicores" value="0" inputmode="numeric" aria-label="CPU millicores">
        <input name="memoryMb" value="0" inputmode="numeric" aria-label="Memory MB">
        <input name="diskMb" value="0" inputmode="numeric" aria-label="Disk MB">
        <input type="hidden" name="confirm" value="UPDATE-RESOURCE-LIMITS">
        <button class="ops-button primary" type="submit">${controlIcon("resources")} Salva limiti</button>
      </form>
    </div>
    <div class="ops-panel">
      <div class="ops-panel-head">
        <div>
          <h2>Uso risorse</h2>
          <p>Totali da Prometheus/node-exporter. Per applicazione: CPU/RAM solo se attribuibili a container dedicati; disco sempre dalla cartella reale.</p>
        </div>
        <span class="ops-badge" data-resource-captured-at>${escapeHtml(context.resources.capturedAt)}</span>
      </div>
      <div class="ops-table-wrap">
        <table class="ops-table">
          <thead><tr><th>Applicazione</th><th>Progetto</th><th>Runtime</th><th>Stato</th><th>CPU</th><th>RAM</th><th>Disco app</th><th>Container</th><th>Fonte</th><th>Limiti</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="10">${empty("Nessuna riga risorse", "Nessun metadata applicazione disponibile.")}</td></tr>`}</tbody>
        </table>
      </div>
    </div>
  </section>`;
}

function renderOpsMetric(label, value, detail, tone = "info", options = {}) {
  const attrs = options.resourceCard ? ` data-resource-card="${escapeHtml(options.resourceCard)}"` : "";
  return `<div class="ops-metric ${escapeHtml(tone)}"${attrs}>
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(String(value))}</strong>
    <small>${escapeHtml(String(detail || ""))}</small>
  </div>`;
}

function renderStatusRunSummary(run) {
  if (!run) {
    return `<div class="ops-status-run empty-run">
      <strong>Nessun test reale eseguito dal Portal</strong>
      <span>Premi “Avvia test reali” per verificare WAF, report e prove attuali.</span>
    </div>`;
  }
  return `<div class="ops-status-run ${statusClass(run.status)}">
    <div>
      <strong>Ultimo test reale</strong>
      <span>${escapeHtml(`${run.generatedAt || "n.d."} / durata ${Number(run.durationMs || 0)} ms`)}</span>
    </div>
    <span class="ops-status-run-state">${escapeHtml(friendlyGoNoGoStatus(run.status))}</span>
  </div>`;
}

function opsStatusRows(context) {
  const rows = [];
  const seen = new Set();
  const push = (row) => {
    const key = row.technicalId || row.id;
    if (seen.has(key)) return;
    seen.add(key);
    rows.push(row);
  };
  for (const check of context.statusRun?.checks || []) {
    if (isControlCenterOnlyStatusCheck(check.id)) continue;
    push(statusTableRow({
      id: `run:${check.id}`,
      control: statusRunControlTitle(check),
      technicalId: check.id,
      source: check.source || "Test reale",
      status: check.status,
      reason: check.detail || "",
      action: check.status === "passed" ? "Nessuna azione immediata." : check.nextAction,
      required: check.required,
    }));
  }
  for (const check of context.goNoGo?.checks || []) {
    const displayCheck = goNoGoDisplayCheck(check);
    const passed = displayCheck.status === "passed";
    push(statusTableRow({
      id: `go-no-go:${displayCheck.name}`,
      control: friendlyCheckName(displayCheck.name),
      technicalId: displayCheck.name,
      source: "Go live",
      status: displayCheck.status,
      reason: passed ? (displayCheck.detail || "Controllo superato nel report go/no-go.") : simpleBlockerReason(displayCheck),
      action: passed ? "Mantieni il report come evidence e rilancia dopo ogni modifica." : simpleBlockerAction(displayCheck),
      required: displayCheck.required,
      reportPath: displayCheck.reportPath || "",
    }));
  }
  for (const check of documentedStatusChecks(context)) {
    if (isControlCenterOnlyStatusCheck(check.id)) continue;
    push(statusTableRow({
      id: `documented:${check.id}`,
      control: statusRunControlTitle(check),
      technicalId: check.id,
      source: check.source || "Documentazione",
      status: check.status,
      reason: check.detail || "",
      action: check.status === "passed" ? "Nessuna azione immediata." : check.nextAction,
      required: check.required,
    }));
  }
  return rows;
}

function isControlCenterOnlyStatusCheck(id) {
  return new Set([
    "control-center-health",
    "control-center-assets",
  ]).has(String(id || ""));
}

function statusRunControlTitle(check) {
  if (check?.id === "go-no-go-verdict") return "Decisione produzione";
  return check?.title || friendlyCheckName(check?.id);
}

function statusTableRow({ id, control, technicalId, source, status, reason, action, required = true, reportPath = "" }) {
  return sanitizeEvent({
    id,
    control,
    technicalId,
    source,
    status,
    reason,
    action,
    required,
    reportPath,
  });
}

function renderStatusTabButton(id, label, count, selected = false) {
  return `<button class="ops-status-tab ${selected ? "active" : ""}" type="button" role="tab" data-status-tab="${escapeHtml(id)}" aria-controls="status-tab-${escapeHtml(id)}" aria-selected="${selected ? "true" : "false"}">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(String(count))}</strong>
  </button>`;
}

function renderStatusAllPanel(passedRows, notPassedRows) {
  return `<div class="ops-status-split">
    <div class="ops-status-column">
      <div class="ops-status-column-head"><strong>Passati</strong><span>${escapeHtml(String(passedRows.length))}</span></div>
      ${renderStatusRowsTable(passedRows, "Nessun controllo passato", "Avvia i test reali o genera un report go/no-go.")}
    </div>
    <div class="ops-status-column">
      <div class="ops-status-column-head"><strong>Non passati</strong><span>${escapeHtml(String(notPassedRows.length))}</span></div>
      ${renderStatusRowsTable(notPassedRows, "Nessun controllo aperto", "Non risultano blocchi nel set corrente.")}
    </div>
  </div>`;
}

function renderStatusRowsTable(rows, emptyTitle, emptyMessage) {
  if (!rows.length) return empty(emptyTitle, emptyMessage);
  const body = rows.map((row) => `<tr>
    <td><strong>${escapeHtml(row.control)}</strong><span>${escapeHtml(row.technicalId)}</span></td>
    <td><span class="ops-state ${statusClass(row.status)}">${escapeHtml(friendlyGoNoGoStatus(row.status))}</span></td>
    <td>${escapeHtml(row.reason || "n.d.")}</td>
    <td>${escapeHtml(row.action || "Nessuna azione indicata.")}${row.reportPath ? `<span>${escapeHtml(row.reportPath)}</span>` : ""}</td>
    <td>${escapeHtml(row.source)}</td>
  </tr>`).join("");
  return `<div class="ops-table-wrap">
    <table class="ops-table ops-status-table">
      <thead><tr><th>Controllo</th><th>Stato</th><th>Motivo</th><th>Cosa fare</th><th>Fonte</th></tr></thead>
      <tbody>${body}</tbody>
    </table>
  </div>`;
}

function renderOpsBlockersTable(blockers) {
  const rows = blockers.map((check) => {
    const displayCheck = goNoGoDisplayCheck(check);
    return `<tr>
    <td><strong>${escapeHtml(friendlyCheckName(displayCheck.name))}</strong><span>${escapeHtml(displayCheck.name)}</span></td>
    <td><span class="ops-state ${statusClass(displayCheck.status)}">${escapeHtml(friendlyGoNoGoStatus(displayCheck.status))}</span></td>
    <td>${escapeHtml(simpleBlockerReason(displayCheck))}</td>
    <td>${escapeHtml(simpleBlockerAction(displayCheck))}</td>
  </tr>`;
  }).join("");
  return `<div class="ops-table-wrap">
    <table class="ops-table">
      <thead><tr><th>Controllo</th><th>Stato</th><th>Motivo</th><th>Cosa fare</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function friendlyCheckName(name) {
  const value = String(name || "").toLowerCase();
  if (value.includes("go-no-go")) return "Report go live";
  if (value.includes("preflight")) return "Preflight server";
  if (value.includes("github")) return "GitHub Actions";
  if (value.includes("cloudflare")) return "Cloudflare";
  if (value.includes("secret")) return "Secrets e rotazione";
  if (value.includes("restore")) return "Restore e recupero";
  if (value.includes("backup")) return "Backup";
  if (value.includes("waf")) return "WAF e protezione web";
  if (value.includes("tls") || value.includes("https")) return "HTTPS e certificati";
  if (value.includes("monitor")) return "Monitoraggio";
  if (value.includes("release")) return "Release evidence";
  if (value.includes("readiness")) return "Readiness";
  return humanName(name);
}

function friendlyGoNoGoStatus(status) {
  switch (String(status || "")) {
    case "authorization-required":
      return "Richiede autorizzazione";
    case "passed":
      return "Superato";
    case "success":
      return "Riuscito";
    case "warning":
      return "Attenzione";
    case "failed":
      return "Fallito";
    case "pending-live-proof":
      return "Manca prova live";
    case "pending-provider":
      return "Manca provider";
    case "needs-work":
      return "Da sistemare";
    case "plan-only":
      return "Solo pianificato";
    case "go":
      return "GO LIVE";
    case "no-go":
      return "NO GO LIVE";
    default:
      return humanName(status || "unknown");
  }
}

function goNoGoDisplayCheck(check, fallbackCategory = "") {
  return {
    ...check,
    status: goNoGoDisplayStatus(check, fallbackCategory),
  };
}

function externalProviderEvidenceText(text) {
  const clean = String(text || "").toLowerCase();
  return [
    "cloudflare",
    "github",
    "github-actions",
    "github action",
    "github-",
    "external-uptime",
    "provider",
    "verifyremote",
    "offsite",
    "off-site",
    "restic",
    "sigstore",
    "attestation",
    "slsa",
    "cosign",
    "provenance",
    "private registry",
    "registry",
    "public edge",
    "edge/cdn",
    "cdn",
    "public target",
    "public-target",
    "dominio pubblico",
    "monitor esterno",
    "domain",
    "dns",
    "tls",
    "https",
  ].some((needle) => clean.includes(needle));
}

function protectedEvidenceText(text) {
  const clean = String(text || "").toLowerCase();
  return [
    "alert-evidence",
    "backup-",
    "backup/",
    "backupfailures=",
    "chaos",
    "deploy-vps",
    "emailrequired",
    "failure-tests",
    "fault-injection",
    "infra-secret-manager",
    "migration",
    "migrations",
    "prune-postgres-backups",
    "real-alert-delivery",
    "restore drill",
    "restore test",
    "rotate",
    "secret",
    "vps-go-live",
  ].some((needle) => clean.includes(needle));
}

function classifiedEvidenceStatus(status, text, fallbackCategory = "") {
  const cleanStatus = sanitizeIdentifier(status || "unknown") || "unknown";
  if (["passed", "success", "go"].includes(cleanStatus)) return cleanStatus;
  const category = String(fallbackCategory || "").toLowerCase();
  if (category === "secret-protected" || category === "protected-runtime") return "authorization-required";
  if (category === "provider" || externalProviderEvidenceText(text)) return "pending-provider";
  if (protectedEvidenceText(text)) return "authorization-required";
  return cleanStatus;
}

function goNoGoDisplayStatus(check, fallbackCategory = "") {
  const status = sanitizeIdentifier(check?.status || "unknown") || "unknown";
  const category = String(fallbackCategory || "").toLowerCase();
  const text = `${check?.name || ""} ${check?.blocker || ""} ${check?.detail || ""}`.toLowerCase();
  const classified = classifiedEvidenceStatus(status, text, category);
  if (status !== "failed") return classified;
  if (classified === "pending-provider") return classified;
  if (classified === "authorization-required") return classified;
  const missingOrStaleEvidence = [
    "latest report is",
    "missing report",
    "missing evidence",
    "missing passing",
    "missing public",
    "external-live-proof",
    "public-edge-benchmark",
    "max ",
  ].some((needle) => text.includes(needle));
  if (missingOrStaleEvidence) return "pending-live-proof";
  return status;
}

function simpleBlockerReason(check) {
  const status = String(check.status || "");
  const text = `${check.name || ""} ${check.blocker || ""} ${check.detail || ""}`.toLowerCase();
  if (text.includes("production-go-no-go-report") || text.includes("no production go/no-go report")) {
    return "Manca il report principale: senza quello il portale non può confermare il go live.";
  }
  if (text.includes("external-uptime") || text.includes("domain") || text.includes("dns") || text.includes("tls") || text.includes("https")) {
    return "Manca una prova esterna che dominio, DNS e HTTPS siano raggiungibili come richiesto.";
  }
  if (text.includes("cloudflare")) return "Cloudflare non è ancora provato come configurato e funzionante per la produzione.";
  if (text.includes("github") || text.includes("pre-go-live") || text.includes("release")) {
    return "Manca una prova recente della pipeline o dell'evidence di rilascio richiesta.";
  }
  if (text.includes("load") || text.includes("benchmark")) {
    return "Manca una prova recente che il dominio pubblico regga il carico minimo richiesto.";
  }
  if (text.includes("restore") || text.includes("disaster-recovery") || text.includes("rpo") || text.includes("rto")) {
    return "Non c'è ancora prova sufficiente che backup e ripristino funzionino davvero.";
  }
  if (text.includes("backup")) return "Il sistema non ha abbastanza prova recente sui backup richiesti.";
  if (text.includes("secret")) return "La gestione o rotazione dei secrets non è ancora provata per produzione.";
  if (status === "authorization-required") {
    return "Serve autorizzazione operativa prima di eseguire questa prova: può leggere secrets, usare backup, inviare alert, fermare servizi o validare rollback.";
  }
  if (status === "pending-live-proof") {
    return "La prova esiste solo come configurazione o controllo locale; serve una verifica sull'ambiente reale.";
  }
  if (status === "pending-provider") {
    return "Serve confermare un servizio esterno collegato.";
  }
  if (status === "failed") return "Il controllo obbligatorio è fallito.";
  return check.blocker || check.detail || "Manca una prova obbligatoria per la produzione.";
}

function simpleBlockerAction(check) {
  const status = String(check.status || "");
  const text = `${check.name || ""} ${check.blocker || ""} ${check.detail || ""} ${check.nextAction || ""}`.toLowerCase();
  const evidence = check.reportPath ? " La prova tecnica esiste già nel report collegato." : " Salva poi il nuovo report come prova tecnica.";
  if (text.includes("production-go-no-go-report") || text.includes("no production go/no-go report")) {
    return "Requisito go live: esegui il controllo completo e salva il report.";
  }
  if (text.includes("external-uptime") || text.includes("domain") || text.includes("dns") || text.includes("tls") || text.includes("https")) {
    return `Requisito dominio: verifica DNS, HTTPS e monitor esterno sul dominio pubblico.${evidence}`;
  }
  if (text.includes("cloudflare")) {
    return `Requisito Cloudflare: verifica Access, DNS/WAF o proxy Cloudflare sull'ambiente reale.${evidence}`;
  }
  if (text.includes("github") || text.includes("pre-go-live")) {
    return `Requisito GitHub: fai passare la workflow di verifica richiesta e conserva l'evidence del run.${evidence}`;
  }
  if (text.includes("release")) {
    return `Requisito GitHub/release: genera evidence di release e rollback prima del go live.${evidence}`;
  }
  if (text.includes("load") || text.includes("benchmark")) {
    return `Requisito performance: esegui il benchmark pubblico sul dominio reale e aggiorna il report.${evidence}`;
  }
  if (text.includes("restore") || text.includes("disaster-recovery") || text.includes("rpo") || text.includes("rto")) {
    return `Requisito backup/restore: esegui un restore drill controllato, includendo off-site/RPO/RTO se richiesto.${evidence}`;
  }
  if (text.includes("backup")) return `Requisito backup: esegui o verifica il backup richiesto e aggiorna il report.${evidence}`;
  if (text.includes("secret")) return "Requisito secrets: completa verifica o rotazione senza stampare valori sensibili.";
  if (status === "authorization-required") return "Autorizza esplicitamente la finestra operativa e lo scope, poi esegui la prova protetta con report non-secret e rollback pronto.";
  if (status === "pending-live-proof") return `Requisito prova live: rilancia la verifica sull'ambiente server reale.${evidence}`;
  if (status === "pending-provider") return `Requisito provider: collega o verifica il servizio esterno richiesto.${evidence}`;
  if (check.nextAction) return `Requisito operativo: ${check.nextAction}`;
  return "Requisito operativo: correggi il problema e rilancia il controllo completo.";
}

function projectDatabases(context, projectOrId) {
  const project = resolveContextProject(context, projectOrId);
  if (!project) return [];
  const seen = new Set();
  return context.databases.filter((database) => {
    if (!databaseMatchesProject(context, database, project)) return false;
    if (seen.has(database.id)) return false;
    seen.add(database.id);
    return true;
  });
}

function projectStorage(context, projectOrId) {
  const project = resolveContextProject(context, projectOrId);
  if (!project) return { webspaces: [], buckets: [] };
  const identities = projectIdentitySet(project);
  const linked = (item) => identities.has(item.projectId) || (Array.isArray(item.linkedApps) && item.linkedApps.some((app) => identities.has(app)));
  return {
    webspaces: context.webspaces.filter(linked),
    buckets: context.storageBuckets.filter(linked),
  };
}

function resolveContextProject(context, projectOrId) {
  if (projectOrId && typeof projectOrId === "object") return projectOrId;
  const id = sanitizeIdentifier(projectOrId);
  return context.projects.find((project) => project.slug === id || project.id === id || projectIdentitySet(project).has(id)) || null;
}

function databaseMatchesProject(context, database, project) {
  const identities = projectIdentitySet(project);
  if (identities.has(database.projectId)) return true;
  if (databaseLinkedApps(database).some((app) => identities.has(app))) return true;
  if (database.projectId && !identities.has(database.projectId)) return false;
  const hints = new Set(context.databaseNameHints?.[project.slug] || []);
  if (hints.has(database.name)) return true;
  const databaseToken = resourceToken(database.name);
  const projectTokens = [project.slug, project.name, ...(Array.isArray(project.aliases) ? project.aliases : [])]
    .map((value) => resourceToken(value))
    .filter((value) => value && value.length >= 4);
  return projectTokens.some((token) => databaseToken === token || databaseToken.startsWith(`${token}_`) || databaseToken.endsWith(`_${token}`));
}

function projectIdentitySet(project) {
  return new Set([project.slug, project.id, ...(Array.isArray(project.aliases) ? project.aliases : [])].map((item) => sanitizeIdentifier(item)).filter(Boolean));
}

function databaseLinkedApps(database) {
  return Array.isArray(database.linkedApps) ? database.linkedApps.map((item) => sanitizeIdentifier(item)).filter(Boolean) : [];
}

function databaseDisplayName(database) {
  return sanitizeOptionalDescription(database.displayName || "") || database.name;
}

function activityProblems(context) {
  const problems = [];
  for (const check of context.goNoGo.blockers || []) {
    problems.push({
      severity: check.status === "failed" || check.status === "needs-work" ? "error" : "pending",
      source: "go-no-go",
      name: check.name,
      summary: check.blocker || check.detail || "Required production evidence is missing.",
      timestamp: check.generatedAt || context.goNoGo.generatedAt || "",
      href: "/?section=status",
    });
  }
  for (const alert of context.logsAlerts.openAlerts || []) {
    const severity = /critical|error/i.test(alert.severity) ? "error" : "warning";
    problems.push({
      severity,
      source: `alert:${alert.service}`,
      name: alert.id,
      summary: alert.summary,
      timestamp: alert.updatedAt || alert.createdAt || "",
      href: "/?section=activity",
    });
  }
  for (const error of context.logsAlerts.recentErrors || []) {
    problems.push({
      severity: "error",
      source: error.source || "operation",
      name: error.name || "failure",
      summary: error.summary || "Failed operation or audit event.",
      timestamp: error.timestamp || "",
      href: "/?section=activity",
    });
  }
  for (const job of context.jobRecords.filter((item) => item.status === "failed").slice(0, 20)) {
    problems.push({
      severity: "error",
      source: `job:${job.projectId}`,
      name: job.name || job.id,
      summary: job.lastError || "Job failed.",
      timestamp: job.updatedAt || job.createdAt || "",
      href: "/?section=activity",
    });
  }
  for (const item of context.readiness.productionBlockers || []) {
    if (problems.some((problem) => problem.name === item.id)) continue;
    problems.push({
      severity: item.status === "needs-work" ? "error" : "pending",
      source: "readiness",
      name: item.id,
      summary: item.nextAction || item.status,
      timestamp: "",
      href: "/?section=status",
    });
  }
  return problems.slice(0, 80);
}

function resourceUsageRows(context) {
  return context.applications.map((app) => {
    const project = context.projects.find((item) => item.slug === app.projectId) || context.projects.find((item) => item.slug === app.id) || null;
    const projectId = project?.slug || app.projectId || app.id;
    const limit = context.resources.projectLimits.find((item) => item.projectId === projectId) || resourceLimitRecord({ projectId });
    const usage = context.resources.projectUsage.find((item) => item.projectId === projectId) || {};
    const containers = context.resources.containersByProject.filter((item) => item.applicationId === app.id || (app.id === projectId && item.projectId === projectId));
    const measuredContainers = containers.filter((item) => item.attribution === "container-dedicato" || item.attribution === "docker-stats");
    const cpuCores = measuredContainers.length ? measuredContainers.reduce((sum, item) => sum + Number(item.cpuCores || 0), 0) : null;
    const memoryBytes = measuredContainers.length ? measuredContainers.reduce((sum, item) => sum + Number(item.memoryBytes || 0), 0) : null;
    const hostCores = Number(context.resources.totals?.cpu?.cores || 0);
    return {
      applicationId: app.id,
      applicationName: app.name,
      projectId,
      projectName: project?.name || humanName(projectId),
      runtime: app.runtime,
      status: app.status,
      cpu: measuredContainers.length ? measuredCpuLabel(measuredContainers, hostCores) : "Metriche container non disponibili",
      memory: memoryBytes != null ? usageBytesLabel(memoryBytes) : "Metriche container non disponibili",
      disk: usage.diskAvailable ? usageBytesLabel(usage.diskBytes) : "Non disponibile",
      containers: containers.length ? containers.map((item) => `${item.container}:${item.status}`).join(", ") : `${project ? dedicatedRuntimeName(project) : app.id} atteso`,
      measuredFrom: measuredContainers.length ? (measuredContainers.some((item) => item.attribution === "docker-stats") ? "docker stats + filesystem" : "Prometheus/cAdvisor + filesystem") : "filesystem + container dedicato atteso",
      limits: `${limit.cpuMillicores || 0}m / ${limit.memoryMb || 0} MB / ${limit.diskMb || 0} MB`,
    };
  });
}

function resourceControlPayload(context) {
  const totals = context.resources.totals;
  return {
    ...context.resources,
    cards: {
      cpu: {
        status: context.resources.cpu.status,
        summary: context.resources.cpu.summary,
        tone: totals.cpu.available ? "info" : "warn",
      },
      memory: {
        status: context.resources.memory.status,
        summary: context.resources.memory.summary,
        tone: totals.memory.available ? "info" : "warn",
      },
      disk: {
        status: context.resources.disk.status,
        summary: totals.disk.available ? `${percentLabel(totals.disk.usedPercent)} usato` : totals.disk.message,
        tone: totals.disk.available ? "info" : "warn",
      },
      applications: {
        status: context.applications.length,
        summary: context.resources.trend,
        tone: context.resources.containerMetricsAvailable ? "good" : "warn",
      },
    },
    summaries: {
      cpu: {
        status: context.resources.cpu.status,
        detail: totals.cpu.available ? `${coresLabel(totals.cpu.cores)} disponibili` : totals.cpu.message || "non disponibile",
      },
      memory: {
        status: context.resources.memory.status,
        detail: context.resources.memory.summary,
      },
      disk: {
        status: context.resources.disk.status,
        detail: totals.disk.available ? `${percentLabel(totals.disk.usedPercent)} usato` : totals.disk.message || "non disponibile",
      },
      source: {
        status: context.resources.source,
        detail: context.resources.capturedAt,
      },
    },
    rows: resourceUsageRows(context),
  };
}

function measuredCpuLabel(containers, hostCores = 0) {
  const dockerPercent = sumContainerCpuPercent(containers);
  const cpuCores = containers.reduce((sum, item) => sum + Number(item.cpuCores || 0), 0);
  if (dockerPercent != null) return `${cpuPercentLabel(dockerPercent)} (${preciseCoresLabel(cpuCores)})`;
  return `${preciseCoresLabel(cpuCores)} (${percentLabel(hostCores ? (cpuCores / hostCores) * 100 : null)} host)`;
}

function sumContainerCpuPercent(containers) {
  const values = containers
    .map((item) => Number(item.cpuPercent))
    .filter((value) => Number.isFinite(value));
  if (!values.length) return null;
  return values.reduce((sum, value) => sum + value, 0);
}

function cpuPercentLabel(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "n.d.";
  if (number === 0) return "0.000%";
  if (Math.abs(number) < 0.001) return "<0.001%";
  return `${number.toFixed(3)}%`;
}

function preciseCoresLabel(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "n.d.";
  if (number === 0) return "idle nel campione";
  if (number > 0 && number < 0.001) return "<0.001 core stimati";
  if (number === 1) return "1.000 core stimati";
  return `${number.toFixed(3)} core stimati`;
}

function readDockerStatsSnapshot() {
  if (!existsSync(dockerStatsFile)) return { available: false, capturedAt: "", containers: [] };
  try {
    const parsed = JSON.parse(readFileSync(dockerStatsFile, "utf8"));
    const rawContainers = Array.isArray(parsed.containers) ? parsed.containers : [];
    const containers = rawContainers.map(dockerStatsContainerRecord).filter(Boolean);
    return {
      available: containers.length > 0,
      capturedAt: sanitizeMessage(parsed.capturedAt || ""),
      containers,
    };
  } catch {
    return { available: false, capturedAt: "", containers: [] };
  }
}

function dockerStatsContainerRecord(item) {
  if (!item || typeof item !== "object") return null;
  const name = sanitizeRef(item.name || item.container || item.Name || item.Container || "");
  if (!name || name === "unknown") return null;
  const cpuPercent = parseDockerPercent(item.cpuPercent || item.CPUPerc || item.cpu || "");
  const memoryBytes = parseDockerMemoryUsage(item.memoryUsage || item.MemUsage || item.memory || "");
  return {
    name,
    cpuCores: cpuPercent != null ? cpuPercent / 100 : null,
    cpuPercent,
    memoryBytes,
  };
}

function parseDockerPercent(value) {
  const number = Number(String(value || "").replace("%", "").trim());
  return Number.isFinite(number) ? number : null;
}

function parseDockerMemoryUsage(value) {
  const first = String(value || "").split("/")[0]?.trim() || "";
  return parseDockerSize(first);
}

function parseDockerSize(value) {
  const match = String(value || "").trim().match(/^([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?i?b)$/i);
  if (!match) return null;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount)) return null;
  const unit = match[2].toLowerCase();
  const multipliers = {
    b: 1,
    kb: 1000,
    mb: 1000 ** 2,
    gb: 1000 ** 3,
    tb: 1000 ** 4,
    pb: 1000 ** 5,
    kib: 1024,
    mib: 1024 ** 2,
    gib: 1024 ** 3,
    tib: 1024 ** 4,
    pib: 1024 ** 5,
  };
  return Math.round(amount * (multipliers[unit] || 1));
}

function matchDockerStatsContainers(app, project, containers) {
  const exact = [app.id, app.id === project.slug ? dedicatedRuntimeName(project) : ""]
    .map((value) => resourceToken(value))
    .filter(Boolean);
  const fallback = app.id === project.slug
    ? [project.slug, project.name, ...(Array.isArray(project.aliases) ? project.aliases : [])]
      .map((value) => resourceToken(value))
      .filter((value) => value && value.length >= 4)
    : [];
  return containers.filter((container) => {
    const haystack = resourceToken(container.name);
    return exact.some((needle) => haystack === needle) || fallback.some((needle) => haystack === needle || haystack.includes(needle));
  });
}

async function collectLiveResourceUsage({ projects, applications, webspaces }) {
  const capturedAt = new Date().toISOString();
  const prometheus = await readPrometheusResourceSnapshot();
  const dockerStats = readDockerStatsSnapshot();
  const projectDisks = new Map(projects.map((project) => [project.slug, readProjectDiskUsage(project)]));
  const containersByProject = applications.flatMap((app) => {
    const project = projects.find((item) => item.slug === app.projectId) || projects.find((item) => item.slug === app.id);
    const exactContainers = project ? matchApplicationContainers(app, project, prometheus.containers) : [];
    if (exactContainers.length) {
      return exactContainers.map((container) => ({
        projectId: app.projectId,
        applicationId: app.id,
        runtime: app.runtime,
        status: app.status,
        container: container.name,
        cpuCores: container.cpuCores,
        cpuPercent: null,
        memoryBytes: container.memoryBytes,
        attribution: "container-dedicato",
      }));
    }
    const dockerContainers = project ? matchDockerStatsContainers(app, project, dockerStats.containers) : [];
    if (dockerContainers.length) {
      return dockerContainers.map((container) => ({
        projectId: app.projectId,
        applicationId: app.id,
        runtime: app.runtime,
        status: app.status,
        container: container.name,
        cpuCores: container.cpuCores,
        cpuPercent: container.cpuPercent,
        memoryBytes: container.memoryBytes,
        attribution: "docker-stats",
      }));
    }
    return [{
      projectId: app.projectId,
      applicationId: app.id,
      runtime: app.runtime,
      status: app.status,
      container: project ? dedicatedRuntimeName(project) : "container dedicato atteso",
      cpuCores: null,
      memoryBytes: null,
      attribution: "container-dedicato-atteso",
    }];
  });
  const projectUsage = projects.map((project) => {
    const projectApps = applications.filter((app) => app.projectId === project.slug || app.id === project.slug);
    const exactContainers = projectApps.flatMap((app) => {
      const prometheusMatches = matchApplicationContainers(app, project, prometheus.containers);
      return prometheusMatches.length ? prometheusMatches : matchDockerStatsContainers(app, project, dockerStats.containers);
    });
    const disk = projectDisks.get(project.slug) || { available: false, bytes: 0, files: 0, directories: 0 };
    const cpuCores = exactContainers.length ? exactContainers.reduce((sum, item) => sum + Number(item.cpuCores || 0), 0) : null;
    const memoryBytes = exactContainers.length ? exactContainers.reduce((sum, item) => sum + Number(item.memoryBytes || 0), 0) : null;
    const cpuPercent = cpuCores != null && prometheus.cpu.cores ? (cpuCores / prometheus.cpu.cores) * 100 : null;
    return sanitizeEvent({
      projectId: project.slug,
      projectName: project.name,
      status: project.status,
      runtime: project.runtime,
      diskAvailable: disk.available,
      diskBytes: disk.bytes,
      files: disk.files,
      directories: disk.directories,
      cpuCores,
      cpuPercent: sumContainerCpuPercent(exactContainers) ?? cpuPercent,
      memoryBytes,
      cpuMessage: exactContainers.length ? "" : "Metriche container non disponibili",
      memoryMessage: exactContainers.length ? "" : "Metriche container non disponibili",
      containersLabel: exactContainers.length ? exactContainers.map((item) => item.name).join(", ") : `${dedicatedRuntimeName(project)} atteso`,
      measuredFrom: exactContainers.length ? `${dockerStats.containers.length ? "docker stats" : "Prometheus/cAdvisor"} + filesystem` : "filesystem + container dedicato atteso",
      applications: projectApps.map((app) => app.id),
    });
  });
  const webspaceBytes = webspaces.reduce((sum, item) => sum + Number(item.usedBytes || 0), 0);
  const containerMetricsAvailable = prometheus.containers.length > 0 || dockerStats.containers.length > 0;
  return sanitizeEvent({
    source: dockerStats.containers.length ? `docker-stats-file (${dockerStats.capturedAt || "no timestamp"})` : prometheus.available ? (prometheus.containers.length > 0 ? "prometheus-node-exporter-cadvisor" : "prometheus-node-exporter") : "local-filesystem",
    capturedAt: dockerStats.capturedAt || capturedAt,
    containerMetricsAvailable,
    totals: {
      cpu: prometheus.cpu,
      memory: prometheus.memory,
      disk: prometheus.disk.available ? prometheus.disk : readLocalFilesystemSnapshot(projectsRoot),
      webspacesBytes: webspaceBytes,
    },
    containersByProject,
    projectUsage,
  });
}

async function readPrometheusResourceSnapshot() {
  const now = Date.now();
  if (resourceMetricsCache.value && resourceMetricsCache.expiresAt > now) return resourceMetricsCache.value;
  if (resourceMetricsCache.failedUntil > now) return unavailableResourceSnapshot("Prometheus non disponibile o non raggiungibile.");
  if (!prometheusUrl) return unavailableResourceSnapshot("Prometheus non configurato.");

  const queries = {
    cpuPercent: '100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[2m])))',
    cpuCores: 'count(count by (cpu) (node_cpu_seconds_total{mode="idle"}))',
    memoryTotal: "node_memory_MemTotal_bytes",
    memoryAvailable: "node_memory_MemAvailable_bytes",
    diskSize: 'node_filesystem_size_bytes{fstype!~"tmpfs|fuse.*|overlay|squashfs",mountpoint=~"/|/srv/platform-nvme"}',
    diskAvailable: 'node_filesystem_avail_bytes{fstype!~"tmpfs|fuse.*|overlay|squashfs",mountpoint=~"/|/srv/platform-nvme"}',
    containerCpuByName: 'sum by (name) (rate(container_cpu_usage_seconds_total{name!="",id!="/"}[2m]))',
    containerMemoryByName: 'max by (name) (container_memory_working_set_bytes{name!="",id!="/"})',
    containerCpuByContainer: 'sum by (container) (rate(container_cpu_usage_seconds_total{container!="",id!="/"}[2m]))',
    containerMemoryByContainer: 'max by (container) (container_memory_working_set_bytes{container!="",id!="/"})',
  };
  const entries = await Promise.all(Object.entries(queries).map(async ([key, query]) => {
    try {
      return [key, await prometheusQuery(query)];
    } catch {
      return [key, []];
    }
  }));
  const results = Object.fromEntries(entries);
  const memoryTotal = firstPrometheusValue(results.memoryTotal);
  const memoryAvailable = firstPrometheusValue(results.memoryAvailable);
  const snapshot = sanitizeEvent({
    available: [results.cpuPercent, results.cpuCores, results.memoryTotal, results.memoryAvailable, results.diskSize].some((items) => items.length > 0),
    cpu: {
      available: results.cpuPercent.length > 0 || results.cpuCores.length > 0,
      usedPercent: firstPrometheusValue(results.cpuPercent),
      cores: firstPrometheusValue(results.cpuCores),
      message: results.cpuPercent.length ? "" : "Metriche CPU non disponibili da Prometheus.",
    },
    memory: {
      available: Number.isFinite(memoryTotal) && Number.isFinite(memoryAvailable),
      totalBytes: memoryTotal || 0,
      availableBytes: memoryAvailable || 0,
      usedBytes: Number.isFinite(memoryTotal) && Number.isFinite(memoryAvailable) ? Math.max(0, memoryTotal - memoryAvailable) : 0,
      usedPercent: Number.isFinite(memoryTotal) && memoryTotal > 0 ? ((memoryTotal - memoryAvailable) / memoryTotal) * 100 : null,
      message: Number.isFinite(memoryTotal) ? "" : "Metriche RAM non disponibili da Prometheus.",
    },
    disk: buildPrometheusDiskSnapshot(results.diskSize, results.diskAvailable),
    containers: mergePrometheusContainerMetrics(
      [...results.containerCpuByName, ...results.containerCpuByContainer],
      [...results.containerMemoryByName, ...results.containerMemoryByContainer],
    ),
  });
  if (!snapshot.available) {
    resourceMetricsCache.failedUntil = now + resourceProbeFailureCooldownMs;
    return unavailableResourceSnapshot("Prometheus non ha restituito metriche host.");
  }
  resourceMetricsCache.value = snapshot;
  resourceMetricsCache.expiresAt = now + resourceMetricsTtlMs;
  return snapshot;
}

async function prometheusQuery(query) {
  const endpoint = new URL("/api/v1/query", prometheusUrl.endsWith("/") ? prometheusUrl : `${prometheusUrl}/`);
  endpoint.searchParams.set("query", query);
  const response = await fetch(endpoint, { signal: AbortSignal.timeout(resourceProbeTimeoutMs) });
  if (!response.ok) throw new Error(`Prometheus returned ${response.status}`);
  const payload = await response.json();
  if (payload.status !== "success") throw new Error("Prometheus query failed.");
  return Array.isArray(payload.data?.result) ? payload.data.result : [];
}

function unavailableResourceSnapshot(message) {
  return {
    available: false,
    cpu: { available: false, usedPercent: null, cores: null, message },
    memory: { available: false, totalBytes: 0, availableBytes: 0, usedBytes: 0, usedPercent: null, message },
    disk: readLocalFilesystemSnapshot(projectsRoot),
    containers: [],
  };
}

function buildPrometheusDiskSnapshot(sizeRows, availableRows) {
  const availableByMount = new Map(availableRows.map((row) => [row.metric?.mountpoint || "", firstPrometheusValue([row])]));
  const rows = [];
  const seenDevices = new Set();
  for (const row of sizeRows) {
    const mountpoint = row.metric?.mountpoint || "";
    const device = row.metric?.device || mountpoint;
    if (!mountpoint || seenDevices.has(device)) continue;
    const totalBytes = firstPrometheusValue([row]);
    const availableBytes = availableByMount.get(mountpoint);
    if (!Number.isFinite(totalBytes) || !Number.isFinite(availableBytes)) continue;
    seenDevices.add(device);
    rows.push({
      mountpoint,
      device,
      totalBytes,
      availableBytes,
      usedBytes: Math.max(0, totalBytes - availableBytes),
      usedPercent: totalBytes > 0 ? ((totalBytes - availableBytes) / totalBytes) * 100 : null,
    });
  }
  const totalBytes = rows.reduce((sum, row) => sum + row.totalBytes, 0);
  const availableBytes = rows.reduce((sum, row) => sum + row.availableBytes, 0);
  return sanitizeEvent({
    available: rows.length > 0,
    totalBytes,
    availableBytes,
    usedBytes: Math.max(0, totalBytes - availableBytes),
    usedPercent: totalBytes > 0 ? ((totalBytes - availableBytes) / totalBytes) * 100 : null,
    mounts: rows,
    message: rows.length ? "" : "Metriche disco non disponibili da Prometheus.",
  });
}

function mergePrometheusContainerMetrics(cpuRows, memoryRows) {
  const byName = new Map();
  for (const row of cpuRows) {
    const name = prometheusContainerName(row.metric || {});
    if (!name) continue;
    const current = byName.get(name) || { name, cpuCores: 0, memoryBytes: 0 };
    const value = firstPrometheusValue([row]);
    if (Number.isFinite(value)) current.cpuCores = Math.max(current.cpuCores || 0, value);
    byName.set(name, current);
  }
  for (const row of memoryRows) {
    const name = prometheusContainerName(row.metric || {});
    if (!name) continue;
    const current = byName.get(name) || { name, cpuCores: 0, memoryBytes: 0 };
    const value = firstPrometheusValue([row]);
    if (Number.isFinite(value)) current.memoryBytes = Math.max(current.memoryBytes || 0, value);
    byName.set(name, current);
  }
  return [...byName.values()].filter((item) => item.cpuCores || item.memoryBytes);
}

function prometheusContainerName(metric) {
  return sanitizeIdentifier(metric.name || metric.container || metric.container_name || metric.container_label_com_docker_compose_service || "");
}

function firstPrometheusValue(rows) {
  const row = rows.find((item) => Array.isArray(item.value) && item.value.length >= 2);
  const value = Number(row?.value?.[1]);
  return Number.isFinite(value) ? value : null;
}

function readLocalFilesystemSnapshot(targetPath) {
  try {
    const stats = statfsSync(existsSync(targetPath) ? targetPath : ".");
    const totalBytes = Number(stats.blocks || 0) * Number(stats.bsize || 0);
    const availableBytes = Number(stats.bavail || 0) * Number(stats.bsize || 0);
    return sanitizeEvent({
      available: totalBytes > 0,
      totalBytes,
      availableBytes,
      usedBytes: Math.max(0, totalBytes - availableBytes),
      usedPercent: totalBytes > 0 ? ((totalBytes - availableBytes) / totalBytes) * 100 : null,
      mounts: [{ mountpoint: targetPath, device: "local-filesystem", totalBytes, availableBytes, usedBytes: Math.max(0, totalBytes - availableBytes) }],
      message: totalBytes > 0 ? "" : "Filesystem non disponibile.",
    });
  } catch {
    return { available: false, totalBytes: 0, availableBytes: 0, usedBytes: 0, usedPercent: null, mounts: [], message: "Filesystem non disponibile." };
  }
}

function readProjectDiskUsage(project) {
  if (!project.filesAvailable || !project.relativePath) return { available: false, bytes: 0, files: 0, directories: 0 };
  try {
    const root = resolveProjectRoot(project);
    const key = `${project.slug}:${root}`;
    const cached = projectDiskUsageCache.get(key);
    const now = Date.now();
    if (cached && cached.expiresAt > now) return cached.value;
    const value = directoryUsage(root);
    projectDiskUsageCache.set(key, { value, expiresAt: now + projectDiskUsageTtlMs });
    return value;
  } catch {
    return { available: false, bytes: 0, files: 0, directories: 0 };
  }
}

function directoryUsage(root) {
  const stack = [root];
  let bytes = 0;
  let files = 0;
  let directories = 0;
  while (stack.length) {
    const current = stack.pop();
    let stat;
    try {
      stat = lstatSync(current);
    } catch {
      continue;
    }
    bytes += Number(stat.size || 0);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      directories += 1;
      let entries = [];
      try {
        entries = readdirSync(current);
      } catch {
        entries = [];
      }
      for (const entry of entries) stack.push(path.join(current, entry));
    } else {
      files += 1;
    }
  }
  return { available: true, bytes, files, directories };
}

function matchApplicationContainers(app, project, containers) {
  const needles = [app.id, app.name, project.slug, project.host]
    .map((value) => resourceToken(value))
    .filter(Boolean);
  return containers.filter((container) => {
    const haystack = resourceToken(container.name);
    return needles.some((needle) => haystack === needle || (needle.length >= 4 && haystack.includes(needle)));
  });
}

function dedicatedRuntimeName(project) {
  const prefix = project.runtime === "static" ? "static" : project.runtime === "node" ? "node" : "php";
  return `${prefix}-${project.slug}`;
}

function resourceToken(value) {
  return sanitizeIdentifier(String(value || "").toLowerCase().replace(/https?:\/\//, "").replace(/\..*$/, ""));
}

function statusClass(status) {
  const clean = String(status || "").toLowerCase();
  if (["go", "good", "active", "online", "running", "configured", "declared", "file", "directory", "passed", "success"].includes(clean)) return "good";
  if (["warning", "warn", "pending", "pending-live-proof", "pending-provider", "plan-only", "degraded", "local-estimate", "symlink"].includes(clean)) return "warn";
  if (["error", "failed", "critical", "needs-work", "disabled", "offline", "archived", "bad", "no-go"].includes(clean)) return "bad";
  return "info";
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
        <h2>Superfici pubbliche</h2>
        <p>Solo portal e docs sono pubblicati; i servizi operativi restano interni.</p>
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
    { name: "Portal", role: "Control Center Node", status: context.network.routers.some((router) => router.id === "enterprise-portal") ? "pubblico" : "da verificare", icon: "domains", href: `https://${controlCenterHost}`, tone: "good" },
    { name: "Docs", role: "Documentazione operativa", status: context.network.routers.some((router) => router.id === "enterprise-docs") ? "pubblico" : "da verificare", icon: "logs", href: `https://${docsHost}`, tone: "good" },
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
  // Font Awesome Free solid icon paths, embedded inline to keep the portal self-hosted.
  const icons = {
    overview: [576, 512, '<path d="M575.8 255.5c0 18-15 32.1-32 32.1h-32l.7 160.2c.2 35.5-28.5 64.3-64 64.3H128.1c-35.3 0-64-28.7-64-64V287.6H32c-18 0-32-14-32-32.1c0-9 3.8-17.3 10.4-23.4L266.4 8c14.4-12.7 36-12.7 50.5 0l248.5 224.1c6.6 6.1 10.4 14.4 10.4 23.4z"/>'],
    projects: [512, 512, '<path d="M64 480h384c35.3 0 64-28.7 64-64V160c0-35.3-28.7-64-64-64H288.8c-10.1 0-19.6-4.7-25.6-12.8L243.2 56C232.1 41.2 214.7 32 196.2 32H64C28.7 32 0 60.7 0 96v320c0 35.3 28.7 64 64 64z"/>'],
    applications: [512, 512, '<path d="M234.5 5.7c13.9-7.6 30.9-7.6 44.8 0l192 104.7c15.4 8.4 24.7 24.5 24.7 41.9v207.4c0 17.4-9.3 33.5-24.7 41.9l-192 104.7c-13.9 7.6-30.9 7.6-44.8 0l-192-104.7C27.1 393.2 17.8 377.1 17.8 359.7V152.3c0-17.4 9.3-33.5 24.7-41.9l192-104.7zM256 53.3L72.5 153.4 256 253.5l183.5-100.1L256 53.3zM464 194.9 280 295.3v157l184-100.3V194.9zM232 452.3v-157L48 194.9V352l184 100.3z"/>'],
    domains: [512, 512, '<path d="M352 256c0 22.2-1.2 43.6-3.3 64H163.3c-2.2-20.4-3.3-41.8-3.3-64s1.2-43.6 3.3-64h185.4c2.1 20.4 3.3 41.8 3.3 64zm28.8-64h123.1c5.3 20.5 8.1 41.9 8.1 64s-2.8 43.5-8.1 64H380.8c2.1-20.6 3.2-42 3.2-64s-1.1-43.4-3.2-64zm112.6-32H376.7c-10-63.9-29.8-117.4-55.3-151.6c78.3 20.7 142 77.5 172 151.6zm-149.1 0H167.7c6.1-36.4 15.5-68.6 27-94.7c10.5-23.6 22.2-40.7 33.5-51.5C239.4 3.2 248.7 0 256 0s16.6 3.2 27.8 13.8c11.3 10.8 23 27.9 33.5 51.5c11.5 26.1 20.9 58.3 27 94.7zm-209 0H18.6c30-74.1 93.7-130.9 172-151.6c-25.5 34.2-45.3 87.7-55.3 151.6zM8.1 192h123.1c-2.1 20.6-3.2 42-3.2 64s1.1 43.4 3.2 64H8.1C2.8 299.5 0 278.1 0 256s2.8-43.5 8.1-64zm159.6 160h176.6c-6.1 36.4-15.5 68.6-27 94.7c-10.5 23.6-22.2 40.7-33.5 51.5C272.6 508.8 263.3 512 256 512s-16.6-3.2-27.8-13.8c-11.3-10.8-23-27.9-33.5-51.5c-11.5-26.1-20.9-58.3-27-94.7zm-32.4 0c10 63.9 29.8 117.4 55.3 151.6c-78.3-20.7-142-77.5-172-151.6h116.7zm358.1 0c-30 74.1-93.7 130.9-172 151.6c25.5-34.2 45.3-87.7 55.3-151.6h116.7z"/>'],
    databases: [448, 512, '<path d="M448 80v48c0 44.2-100.3 80-224 80S0 172.2 0 128V80C0 35.8 100.3 0 224 0s224 35.8 224 80zM393.2 214.7c20.8-7.4 39.9-16.9 54.8-28.6V288c0 44.2-100.3 80-224 80S0 332.2 0 288V186.1c14.9 11.8 34 21.2 54.8 28.6C99.7 230.7 159.5 240 224 240s124.3-9.3 169.2-25.3zM0 346.1c14.9 11.8 34 21.2 54.8 28.6C99.7 390.7 159.5 400 224 400s124.3-9.3 169.2-25.3c20.8-7.4 39.9-16.9 54.8-28.6V432c0 44.2-100.3 80-224 80S0 476.2 0 432v-85.9z"/>'],
    storage: [512, 512, '<path d="M32 32C14.3 32 0 46.3 0 64v368c0 26.5 21.5 48 48 48h416c26.5 0 48-21.5 48-48V64c0-17.7-14.3-32-32-32H32zm64 352a32 32 0 1 1 0 64 32 32 0 1 1 0-64zm96 32a32 32 0 1 1-64 0 32 32 0 1 1 64 0zm-64-224h256c17.7 0 32 14.3 32 32s-14.3 32-32 32H128c-17.7 0-32-14.3-32-32s14.3-32 32-32z"/>'],
    webspaces: [512, 512, '<path d="M64 64C28.7 64 0 92.7 0 128v256c0 35.3 28.7 64 64 64h384c35.3 0 64-28.7 64-64V128c0-35.3-28.7-64-64-64H64zm0 64h384v64H64v-64zm0 128h112v128H64V256zm176 0h208v128H240V256z"/>'],
    resources: [512, 512, '<path d="M64 64c0-17.7-14.3-32-32-32S0 46.3 0 64v336c0 44.2 35.8 80 80 80h400c17.7 0 32-14.3 32-32s-14.3-32-32-32H80c-8.8 0-16-7.2-16-16V64zm406.6 86.6c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L320 210.7l-57.4-57.4c-12.5-12.5-32.8-12.5-45.3 0l-112 112c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0l89.4-89.3 57.4 57.4c12.5 12.5 32.8 12.5 45.3 0l128-128z"/>'],
    security: [512, 512, '<path d="M256 0c4.6 0 9.2 1 13.4 2.9l188.3 79.9c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.6 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.6 2.9C246.8 1 251.4 0 256 0zm0 66.8v378c138-66.8 175.1-214.7 176-303.4L256 66.8z"/>'],
    backups: [640, 512, '<path d="M144 480C64.5 480 0 415.5 0 336c0-62.8 40.2-116.2 96.2-135.9C97.4 125.6 158.2 64 232 64c54.8 0 102.6 30.1 128 74.6C373.6 132 388.9 128 405.3 128C464.8 128 512 177.1 512 236.6c0 4.1-.2 8.2-.7 12.2C584.9 260.3 640 323.9 640 400c0 44.2-35.8 80-80 80H144zm209-207c-9.4-9.4-24.6-9.4-33.9 0l-55 55V184c0-13.3-10.7-24-24-24s-24 10.7-24 24v144l-55-55c-9.4-9.4-24.6-9.4-33.9 0s-9.4 24.6 0 33.9l96 96c9.4 9.4 24.6 9.4 33.9 0l96-96c9.3-9.3 9.3-24.5-.1-33.9z"/>'],
    logs: [448, 512, '<path d="M224 0c-17.7 0-32 14.3-32 32v17.9C119.5 61.4 64 124.2 64 200v33.4c0 45.4-15.5 89.5-43.8 124.9L5.3 377c-5.8 7.2-6.9 17.1-2.9 25.4S14.8 416 24 416h400c9.2 0 17.6-5.3 21.6-13.6s2.9-18.2-2.9-25.4l-14.9-18.6C399.5 322.9 384 278.8 384 233.4V200c0-75.8-55.5-138.6-128-150.1V32c0-17.7-14.3-32-32-32zm0 512c35.3 0 64-28.7 64-64H160c0 35.3 28.7 64 64 64z"/>'],
    settings: [512, 512, '<path d="M495.9 166.6c3.2 8.7.5 18.4-6.4 24.6l-43.3 39.4c1.1 8.3 1.7 16.8 1.7 25.4s-.6 17.1-1.7 25.4l43.3 39.4c6.9 6.2 9.6 15.9 6.4 24.6c-4.4 11.9-9.7 23.3-15.8 34.3l-4.7 8.1c-6.6 11-14 21.4-22.1 31.2c-5.9 7.2-15.7 9.6-24.5 6.8l-55.7-17.7c-13.4 10.3-28.2 18.9-44 25.4l-12.5 57.1c-2 9.1-9 16.3-18.2 17.8c-13.8 2.3-27.9 3.5-42.4 3.5s-28.6-1.2-42.4-3.5c-9.2-1.5-16.2-8.7-18.2-17.8l-12.5-57.1c-15.8-6.5-30.6-15.1-44-25.4L83.1 425.9c-8.8 2.8-18.6.3-24.5-6.8c-8.1-9.8-15.5-20.2-22.1-31.2l-4.7-8.1c-6.1-11-11.4-22.4-15.8-34.3c-3.2-8.7-.5-18.4 6.4-24.6l43.3-39.4C64.6 273.1 64 264.6 64 256s.6-17.1 1.7-25.4L22.4 191.2c-6.9-6.2-9.6-15.9-6.4-24.6c4.4-11.9 9.7-23.3 15.8-34.3l4.7-8.1c6.6-11 14-21.4 22.1-31.2c5.9-7.2 15.7-9.6 24.5-6.8l55.7 17.7c13.4-10.3 28.2-18.9 44-25.4l12.5-57.1c2-9.1 9-16.3 18.2-17.8C227.4 1.2 241.5 0 256 0s28.6 1.2 42.4 3.5c9.2 1.5 16.2 8.7 18.2 17.8l12.5 57.1c15.8 6.5 30.6 15.1 44 25.4l55.7-17.7c8.8-2.8 18.6-.3 24.5 6.8c8.1 9.8 15.5 20.2 22.1 31.2l4.7 8.1c6.1 11 11.4 22.4 15.8 34.3zM256 336a80 80 0 1 0 0-160 80 80 0 1 0 0 160z"/>'],
    file: [384, 512, '<path d="M64 0C28.7 0 0 28.7 0 64v384c0 35.3 28.7 64 64 64h256c35.3 0 64-28.7 64-64V160H256c-17.7 0-32-14.3-32-32V0H64zm192 0v128h128L256 0zM112 256h160c8.8 0 16 7.2 16 16s-7.2 16-16 16H112c-8.8 0-16-7.2-16-16s7.2-16 16-16zm0 64h160c8.8 0 16 7.2 16 16s-7.2 16-16 16H112c-8.8 0-16-7.2-16-16s7.2-16 16-16zm0 64h160c8.8 0 16 7.2 16 16s-7.2 16-16 16H112c-8.8 0-16-7.2-16-16s7.2-16 16-16z"/>'],
    copy: [448, 512, '<path d="M208 0H332.1c12.7 0 24.9 5.1 33.9 14.1L433.9 82c9 9 14.1 21.2 14.1 33.9V336c0 26.5-21.5 48-48 48H208c-26.5 0-48-21.5-48-48V48c0-26.5 21.5-48 48-48zM48 128h80v64H64v256h192v-32h64v48c0 26.5-21.5 48-48 48H48c-26.5 0-48-21.5-48-48V176c0-26.5 21.5-48 48-48z"/>'],
    refresh: [512, 512, '<path d="M105.1 202.6c7.7-21.8 20.2-42.3 37.8-59.9c62.5-62.5 163.8-62.5 226.3 0L386.7 160H336c-17.7 0-32 14.3-32 32s14.3 32 32 32H464c17.7 0 32-14.3 32-32V64c0-17.7-14.3-32-32-32s-32 14.3-32 32v51.2L414.4 97.6c-87.5-87.5-229.3-87.5-316.8 0c-24.7 24.7-42.3 53.9-52.8 84.9c-5.7 16.8 3.3 34.9 20 40.6s34.9-3.3 40.3-20.5zM39 289.3c-5 1.5-9 4.4-12.1 8.4c-4.7 6.1-6.1 14.1-3.7 21.4c7.1 21.5 18.7 42.1 34.4 60.4c87.5 87.5 229.3 87.5 316.8 0c24.7-24.7 42.3-53.9 52.8-84.9c5.7-16.8-3.3-34.9-20-40.6s-34.9 3.3-40.6 20c-7.7 21.8-20.2 42.3-37.8 59.9c-62.5 62.5-163.8 62.5-226.3 0L85.3 352H136c17.7 0 32-14.3 32-32s-14.3-32-32-32H40c-.3 0-.7 0-1 .1z"/>'],
    play: [384, 512, '<path d="M73 39c-14.8-9.1-33.4-9.4-48.5-.9S0 62.6 0 80v352c0 17.4 9.4 33.4 24.5 41.9s33.7 8.1 48.5-.9l288-176c14.3-8.7 23-24.2 23-41s-8.7-32.2-23-41L73 39z"/>'],
    pause: [320, 512, '<path d="M48 64C21.5 64 0 85.5 0 112v288c0 26.5 21.5 48 48 48h32c26.5 0 48-21.5 48-48V112c0-26.5-21.5-48-48-48H48zm192 0c-26.5 0-48 21.5-48 48v288c0 26.5 21.5 48 48 48h32c26.5 0 48-21.5 48-48V112c0-26.5-21.5-48-48-48h-32z"/>'],
    archive: [512, 512, '<path d="M32 32C14.3 32 0 46.3 0 64v96c0 17.7 14.3 32 32 32h448c17.7 0 32-14.3 32-32V64c0-17.7-14.3-32-32-32H32zm32 192v224c0 17.7 14.3 32 32 32h320c17.7 0 32-14.3 32-32V224H64zm128 64h128c17.7 0 32 14.3 32 32s-14.3 32-32 32H192c-17.7 0-32-14.3-32-32s14.3-32 32-32z"/>'],
    external: [512, 512, '<path d="M320 0c-17.7 0-32 14.3-32 32s14.3 32 32 32h82.7L201.4 265.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L448 109.3V192c0 17.7 14.3 32 32 32s32-14.3 32-32V32c0-17.7-14.3-32-32-32H320zM80 32C35.8 32 0 67.8 0 112v320c0 44.2 35.8 80 80 80h320c44.2 0 80-35.8 80-80V320c0-17.7-14.3-32-32-32s-32 14.3-32 32v112c0 8.8-7.2 16-16 16H80c-8.8 0-16-7.2-16-16V112c0-8.8 7.2-16 16-16h112c17.7 0 32-14.3 32-32s-14.3-32-32-32H80z"/>'],
    "arrow-left": [448, 512, '<path d="M9.4 233.4c-12.5 12.5-12.5 32.8 0 45.3l160 160c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3L109.3 288H416c17.7 0 32-14.3 32-32s-14.3-32-32-32H109.3L214.6 118.6c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0l-160 160z"/>'],
    menu: [448, 512, '<path d="M0 96C0 78.3 14.3 64 32 64h384c17.7 0 32 14.3 32 32s-14.3 32-32 32H32C14.3 128 0 113.7 0 96zm0 160c0-17.7 14.3-32 32-32h384c17.7 0 32 14.3 32 32s-14.3 32-32 32H32c-17.7 0-32-14.3-32-32zm448 160c0 17.7-14.3 32-32 32H32c-17.7 0-32-14.3-32-32s14.3-32 32-32h384c17.7 0 32 14.3 32 32z"/>'],
    search: [512, 512, '<path d="M416 208c0 45.9-14.9 88.3-40 122.7l126.6 126.7c12.5 12.5 12.5 32.8 0 45.3s-32.8 12.5-45.3 0L330.7 376C296.3 401.1 253.9 416 208 416C93.1 416 0 322.9 0 208S93.1 0 208 0s208 93.1 208 208zM208 352a144 144 0 1 0 0-288 144 144 0 1 0 0 288z"/>'],
    bell: [448, 512, '<path d="M224 0c-17.7 0-32 14.3-32 32v17.9C119.5 61.4 64 124.2 64 200v33.4c0 45.4-15.5 89.5-43.8 124.9L5.3 377c-5.8 7.2-6.9 17.1-2.9 25.4S14.8 416 24 416h400c9.2 0 17.6-5.3 21.6-13.6s2.9-18.2-2.9-25.4l-14.9-18.6C399.5 322.9 384 278.8 384 233.4V200c0-75.8-55.5-138.6-128-150.1V32c0-17.7-14.3-32-32-32zm0 512c35.3 0 64-28.7 64-64H160c0 35.3 28.7 64 64 64z"/>'],
    help: [512, 512, '<path d="M256 512A256 256 0 1 0 256 0a256 256 0 1 0 0 512zm0-384c-26.5 0-48 21.5-48 48c0 17.7-14.3 32-32 32s-32-14.3-32-32c0-61.9 50.1-112 112-112s112 50.1 112 112c0 39.8-20.8 74.8-52.1 94.6c-17.9 11.3-27.9 25.6-27.9 45.4v4c0 17.7-14.3 32-32 32s-32-14.3-32-32v-4c0-42.4 23.8-78.7 57.6-100.1c13.9-8.8 22.4-23.8 22.4-40.9c0-26.5-21.5-48-48-48zm0 320a40 40 0 1 1 0-80 40 40 0 1 1 0 80z"/>'],
    sun: [512, 512, '<path d="M361.5 1.2c5 2.1 8.6 6.6 9.6 11.9L391 121l107.9 19.8c5.3 1 9.8 4.6 11.9 9.6s1.5 10.7-1.6 15.2L446.9 256l62.3 90.3c3.1 4.5 3.7 10.2 1.6 15.2s-6.6 8.6-11.9 9.6L391 391 371.1 498.9c-1 5.3-4.6 9.8-9.6 11.9s-10.7 1.5-15.2-1.6L256 446.9l-90.3 62.3c-4.5 3.1-10.2 3.7-15.2 1.6s-8.6-6.6-9.6-11.9L121 391 13.1 371.1c-5.3-1-9.8-4.6-11.9-9.6s-1.5-10.7 1.6-15.2L65.1 256 2.8 165.7c-3.1-4.5-3.7-10.2-1.6-15.2s6.6-8.6 11.9-9.6L121 121 140.9 13.1c1-5.3 4.6-9.8 9.6-11.9s10.7-1.5 15.2 1.6L256 65.1 346.3 2.8c4.5-3.1 10.2-3.7 15.2-1.6zM256 352a96 96 0 1 0 0-192 96 96 0 1 0 0 192z"/>'],
    folder: [512, 512, '<path d="M64 480h384c35.3 0 64-28.7 64-64V160c0-35.3-28.7-64-64-64H288.8c-10.1 0-19.6-4.7-25.6-12.8L243.2 56C232.1 41.2 214.7 32 196.2 32H64C28.7 32 0 60.7 0 96v320c0 35.3 28.7 64 64 64z"/>'],
    cube: [512, 512, '<path d="M234.5 5.7c13.9-7.6 30.9-7.6 44.8 0l192 104.7c15.4 8.4 24.7 24.5 24.7 41.9v207.4c0 17.4-9.3 33.5-24.7 41.9l-192 104.7c-13.9 7.6-30.9 7.6-44.8 0l-192-104.7C27.1 393.2 17.8 377.1 17.8 359.7V152.3c0-17.4 9.3-33.5 24.7-41.9l192-104.7z"/>'],
    globe: [512, 512, '<path d="M352 256c0 22.2-1.2 43.6-3.3 64H163.3c-2.2-20.4-3.3-41.8-3.3-64s1.2-43.6 3.3-64h185.4c2.1 20.4 3.3 41.8 3.3 64zm151.9-64c5.3 20.5 8.1 41.9 8.1 64s-2.8 43.5-8.1 64H380.8c2.1-20.6 3.2-42 3.2-64s-1.1-43.4-3.2-64h123.1zM493.4 160H376.7c-10-63.9-29.8-117.4-55.3-151.6c78.3 20.7 142 77.5 172 151.6zM344.3 160H167.7c6.1-36.4 15.5-68.6 27-94.7C216 17.4 239.5 0 256 0s40 17.4 61.3 65.3c11.5 26.1 20.9 58.3 27 94.7zM135.3 160H18.6c30-74.1 93.7-130.9 172-151.6c-25.5 34.2-45.3 87.7-55.3 151.6zM8.1 192h123.1c-2.1 20.6-3.2 42-3.2 64s1.1 43.4 3.2 64H8.1C2.8 299.5 0 278.1 0 256s2.8-43.5 8.1-64zm159.6 160h176.6c-6.1 36.4-15.5 68.6-27 94.7C296 494.6 272.5 512 256 512s-40-17.4-61.3-65.3c-11.5-26.1-20.9-58.3-27-94.7zm-32.4 0c10 63.9 29.8 117.4 55.3 151.6c-78.3-20.7-142-77.5-172-151.6h116.7zm358.1 0c-30 74.1-93.7 130.9-172 151.6c25.5-34.2 45.3-87.7 55.3-151.6h116.7z"/>'],
    server: [512, 512, '<path d="M64 32C28.7 32 0 60.7 0 96v64c0 35.3 28.7 64 64 64h384c35.3 0 64-28.7 64-64V96c0-35.3-28.7-64-64-64H64zm280 72a24 24 0 1 1 0 48 24 24 0 1 1 0-48zm64 0a24 24 0 1 1 0 48 24 24 0 1 1 0-48zM64 288c-35.3 0-64 28.7-64 64v64c0 35.3 28.7 64 64 64h384c35.3 0 64-28.7 64-64v-64c0-35.3-28.7-64-64-64H64zm280 72a24 24 0 1 1 0 48 24 24 0 1 1 0-48zm64 0a24 24 0 1 1 0 48 24 24 0 1 1 0-48z"/>'],
    shield: [512, 512, '<path d="M256 0c4.6 0 9.2 1 13.4 2.9l188.3 79.9c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.6 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.6 2.9C246.8 1 251.4 0 256 0z"/>'],
    rocket: [512, 512, '<path d="M156.6 384.9L125.7 354c-8.5-8.5-11.5-20.8-7.7-32.2c17.2-51.6 45.8-98.9 84.2-137.3L320 66.7C372.7 14 443.3-7.9 511.9 2.4c10.1 68.6-11.8 139.2-64.5 191.9L329.6 312.1c-38.4 38.4-85.7 67-137.3 84.2c-11.4 3.8-23.7.8-32.2-7.7l-3.5-3.7zM384 168a40 40 0 1 0 0-80 40 40 0 1 0 0 80zM112 416c0 53-43 96-96 96c0-53 43-96 96-96z"/>'],
    user: [448, 512, '<path d="M224 256A128 128 0 1 0 224 0a128 128 0 1 0 0 256zm-45.7 48C79.8 304 0 383.8 0 482.3C0 498.7 13.3 512 29.7 512h388.6c16.4 0 29.7-13.3 29.7-29.7C448 383.8 368.2 304 269.7 304h-91.4z"/>'],
    plus: [448, 512, '<path d="M256 80c0-17.7-14.3-32-32-32s-32 14.3-32 32v144H48c-17.7 0-32 14.3-32 32s14.3 32 32 32h144v144c0 17.7 14.3 32 32 32s32-14.3 32-32V288h144c17.7 0 32-14.3 32-32s-14.3-32-32-32H256V80z"/>'],
    chevron: [320, 512, '<path d="M310.6 233.4c12.5 12.5 12.5 32.8 0 45.3l-192 192c-12.5 12.5-32.8 12.5-45.3 0s-12.5-32.8 0-45.3L242.7 256 73.4 86.6c-12.5-12.5-12.5-32.8 0-45.3s32.8-12.5 45.3 0l192 192z"/>'],
    "chevron-down": [512, 512, '<path d="M233.4 406.6c12.5 12.5 32.8 12.5 45.3 0l192-192c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L256 338.7 86.6 169.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3l192 192z"/>'],
    "arrow-right": [448, 512, '<path d="M438.6 278.6c12.5-12.5 12.5-32.8 0-45.3l-160-160c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L338.7 224H32c-17.7 0-32 14.3-32 32s14.3 32 32 32h306.7L233.4 393.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0l160-160z"/>'],
  };
  const [width, height, body] = icons[name] || icons.settings;
  return `<svg class="fa-icon" viewBox="0 0 ${width} ${height}" focusable="false" aria-hidden="true">${body}</svg>`;
}

function renderProjects(projects) {
  return `<section class="panel"><div class="panel-head"><span>PRJ</span><div><h2>Projects</h2><p>Routing toggle is local and audited. Create/archive/delete are API planned.</p></div></div>
  <form class="inline-confirm project-create-form" method="post" action="/actions/project-command">
    <input type="hidden" name="action" value="create">
    <input name="slug" placeholder="project-slug" aria-label="Project slug">
    <input name="displayName" placeholder="Display name" aria-label="Project display name">
    <select name="runtime" aria-label="Default project runtime"><option value="php">PHP Apache</option><option value="node">Node/Next</option><option value="static">Static</option></select>
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
    <select name="runtime" aria-label="Runtime"><option value="php">PHP Apache</option><option value="node">Node/Next</option><option value="static">Static</option></select>
    <select name="webspaceId" aria-label="Linked web space"><option value="">no web space</option>${webspaces.map((space) => `<option value="${escapeHtml(space.id)}">${escapeHtml(space.projectId)}/${escapeHtml(space.name)}</option>`).join("")}</select>
    <input name="repositoryUrl" placeholder="git repo or folder ref" aria-label="Repository or folder reference">
    <input type="hidden" name="action" value="create">
    <input type="hidden" name="confirm" value="CREATE-APPLICATION">
    <button class="button enable" type="submit">Create app</button>
  </form>
  <div class="cards app-cards">${applications.map(renderApplicationCard).join("") || empty("No applications attached.", "Attach applications later through external manifests or local metadata.")}</div></section>`;
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
  const slug = slugify(payload.slug || payload.displayName || payload.name || "");
  validateSlug(slug);
  if (context.projects.some((project) => project.slug === slug)) throw new ValidationError("Project already exists.");
  const displayName = sanitizeDisplayName(payload.displayName || payload.name || humanName(slug));
  const description = sanitizeOptionalDescription(payload.description || payload.summary || "");
  const runtime = choice(String(payload.runtime || "node").toLowerCase(), ["php", "node", "static"], "runtime");
  const host = normalizeHost(payload.host || `${slug}${hostSuffix}`);
  validateHostname(host, context.environment);
  const details = {
    projectId: slug,
    displayName,
    description,
    runtime,
    type: projectRuntimeLabel(runtime),
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
      description,
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
    return { ...operation, project: { id: slug, slug, name: displayName, description, status: "declared", enabled: false, ...details } };
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
  const displayName = sanitizeOptionalDescription(payload.displayName || "");
  const details = databaseRecord({ id, projectId, engine, name, displayName, ownerRole });
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

function planApplicationStressTest(payload, context) {
  const projectId = slugify(payload.projectId || payload.slug || "");
  validateSlug(projectId);
  const project = findById(context.projects, projectId, "Project");
  const confirmation = `RUN-STRESS:${project.slug}`;
  const url = project.enabled ? project.href : `https://${project.host}/`;
  const profiles = sanitizeStressProfiles(payload.profiles || appStressProfiles);
  const durationSeconds = parseResourceLimitNumber(payload.durationSeconds || appStressDurationSeconds, "Duration seconds", 3600);
  const maxConcurrency = parseResourceLimitNumber(payload.maxConcurrency || appStressMaxConcurrency, "Max concurrency", 10000);
  const maxP95Ms = parseResourceLimitNumber(payload.maxP95Ms || appStressMaxP95Ms, "Max P95 ms", 60000);
  const perUserRps = Number(payload.perUserRps || appStressPerUserRps);
  if (durationSeconds < 1 || maxConcurrency < 1 || maxP95Ms < 1) throw new ValidationError("Stress parameters must be positive.");
  if (!Number.isFinite(perUserRps) || perUserRps <= 0 || perUserRps > 10) throw new ValidationError("Per-user RPS must be between 0 and 10.");
  const command = [
    "sh",
    "./scripts/app-stress-test.sh",
    "--app", shellArg(project.slug),
    "--url", shellArg(url),
    "--profiles", shellArg(profiles),
    "--durationSeconds", String(durationSeconds),
    "--perUserRps", String(perUserRps),
    "--maxConcurrency", String(maxConcurrency),
    "--maxP95Ms", String(maxP95Ms),
    "--confirm-max-load",
  ].join(" ");
  const details = {
    projectId: project.slug,
    application: project.name,
    url,
    profiles,
    durationSeconds,
    perUserRps,
    maxConcurrency,
    maxP95Ms,
    command,
    impact: "high-load",
    confirmationRequired: confirmation,
    executedFromPortal: false,
    reportPattern: "reports/load/load-benchmark-*.json",
  };
  if (payload.confirm !== confirmation) {
    appendAudit({ action: "resources.stress.plan", target: project.slug, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Per-app stress test plan generated; no traffic sent." });
    return operationPlan("resources.stress", context.environment, true, ["validate application", "build max-load command", "require exact confirmation", "send no traffic from Control Center", "write audit event"], details);
  }
  appendAudit({ action: "resources.stress.prepare", target: project.slug, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Max-load stress test command prepared; execution remains manual from server shell." });
  return operationPlan("resources.stress.command", context.environment, true, ["validate application", "prepare max-load command", "require server shell execution", "capture reports/load evidence", "watch resources during run"], { ...details, confirmationRequired: "" });
}

function sanitizeStressProfiles(value) {
  const profiles = String(value || "")
    .split(",")
    .map((item) => Number(item.trim()))
    .filter((number) => Number.isInteger(number) && number > 0 && number <= 10000);
  if (!profiles.length) throw new ValidationError("Stress profiles must contain at least one positive integer.");
  return profiles.join(",");
}

function shellArg(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
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

function appendStatusRun(run) {
  mkdirSync(path.dirname(statusRunsFile), { recursive: true });
  appendFileSync(statusRunsFile, `${JSON.stringify(sanitizeEvent(run))}\n`);
}

function readStatusRuns(limit = 20) {
  try {
    return readFileSync(statusRunsFile, "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .reverse()
      .slice(0, limit)
      .map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

function readLatestStatusRun() {
  return readStatusRuns(1)[0] || null;
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

function isStaticProject(projectPath) {
  if (existsSync(path.join(projectPath, "public", "index.html"))) return true;
  if (existsSync(path.join(projectPath, "index.html"))) return true;
  return false;
}

function projectRuntimeLabel(runtime) {
  if (runtime === "php") return "PHP Apache";
  if (runtime === "static") return "Static";
  return "Node/Next";
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
  displayName = "",
  ownerRole = "",
  status = "declared",
  connectionStatus = "metadata-only",
  sizeBytes = 0,
  slowQueries = "planned-adapter",
  users = [],
  permissions = [],
  linkedApps = [],
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
    displayName: sanitizeOptionalDescription(displayName || ""),
    ownerRole: cleanOwnerRole,
    environment: "local",
    status,
    connectionStatus,
    sizeBytes: Number.isSafeInteger(Number(sizeBytes)) && Number(sizeBytes) >= 0 ? Number(sizeBytes) : 0,
    slowQueries,
    users: Array.isArray(users) ? users.map((user) => sanitizeOptionalRef(user)).filter(Boolean).slice(0, 20) : [],
    permissions: Array.isArray(permissions) ? permissions.map((permission) => sanitizeOptionalRef(permission)).filter(Boolean).slice(0, 20) : [],
    linkedApps: Array.isArray(linkedApps) ? [...new Set(linkedApps.map((item) => sanitizeIdentifier(item)).filter(Boolean))].slice(0, 20) : [],
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

function sanitizeOptionalDescription(value) {
  return sanitizeMessage(value).replace(/\s+/g, " ").trim().slice(0, 160);
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

function usageBytesLabel(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value)) return "n.d.";
  if (value <= 0) return "0 B";
  return bytesLabel(value);
}

function percentLabel(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "n.d.";
  const precision = Math.abs(number) < 10 ? 1 : 0;
  return `${number.toFixed(precision)}%`;
}

function coresLabel(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "n.d.";
  if (number === 1) return "1 core";
  return `${Math.round(number * 100) / 100} core`;
}

function clampNumber(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.min(max, Math.max(min, number));
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
      ["projects", "Applicazioni", "APP"], ["applications", "Componenti app", "CMP"], ["webspaces", "Web spaces", "WEB"],
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
    identity: ["admin users", "teams", "roles", "sessions", "access reviews", "login audit"],
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

function renderTransientMessage(res, status, title, message) {
  html(res, `<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  ${controlCenterStylesheetLinks()}
</head>
<body class="login-body">
  <main class="login-shell">
    <section class="login-copy">
      <span>Platform</span>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
      <a class="ops-button" href="/?section=projects">Torna al portal</a>
    </section>
  </main>
</body>
</html>`, status);
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
